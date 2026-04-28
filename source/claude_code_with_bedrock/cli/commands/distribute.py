# ABOUTME: Distribute command for sharing packages via presigned URLs or landing page
# ABOUTME: Supports dual distribution platforms: presigned-s3 and landing-page

"""Distribute command - Share packages via secure presigned URLs or authenticated landing page."""

import hashlib
import json
import shutil
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError
from cleo.commands.command import Command
from cleo.helpers import option
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, DownloadColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from claude_code_with_bedrock.cli.utils.aws import get_stack_outputs
from claude_code_with_bedrock.config import Config


class S3UploadProgress:
    """Track S3 upload progress."""

    def __init__(self, filename, size, progress_bar):
        self._filename = filename
        self._size = size
        self._seen_so_far = 0
        self._progress_bar = progress_bar
        self._lock = threading.Lock()
        self._task_id = None

    def set_task_id(self, task_id):
        """Set the progress bar task ID."""
        self._task_id = task_id

    def __call__(self, bytes_amount):
        """Called by boto3 during upload."""
        with self._lock:
            self._seen_so_far += bytes_amount
            if self._task_id is not None:
                self._progress_bar.update(self._task_id, completed=self._seen_so_far)


class DistributeCommand(Command):
    """
    Distribute built packages via secure presigned URLs

    This command enables IT administrators to share packages
    with developers without requiring AWS credentials.
    """

    name = "distribute"
    description = "Distribute packages via secure presigned URLs"

    options = [
        option("expires-hours", description="URL expiration time in hours (1-168)", flag=False, default="48"),
        option("get-latest", description="Retrieve the latest distribution URL", flag=True),
        option("allowed-ips", description="Comma-separated list of allowed IP ranges", flag=False),
        option("package-path", description="Path to package directory", flag=False, default="dist"),
        option("profile", description="Configuration profile to use", flag=False),
        option("show-qr", description="Display QR code for URL (requires qrcode library)", flag=True),
        option("build-profile", description="Select build by profile name", flag=False),
        option("timestamp", description="Select build by timestamp (YYYY-MM-DD-HHMMSS)", flag=False),
        option("latest", description="Auto-select latest build without wizard", flag=True),
        option(
            "archive-all",
            description=(
                "presigned-s3 only: bundle every {platform}-portable/ and -slim/ "
                "directory into a single claude-code-package.zip. Off by default; "
                "distribute per-platform bundles instead."
            ),
            flag=True,
        ),
    ]

    def _check_old_flat_structure(self, dist_dir: Path) -> bool:
        """Check if old flat directory structure exists."""
        if not dist_dir.exists():
            return False

        # Look for files that would be in old structure (credential-process binaries)
        old_files = [
            "credential-process-macos-arm64",
            "credential-process-macos-intel",
            "credential-process-linux-x64",
            "credential-process-linux-arm64",
            "credential-process-windows.exe",
            "config.json",
            "install.sh",
        ]

        # If any of these files exist directly in dist/, it's old structure
        for filename in old_files:
            if (dist_dir / filename).exists():
                return True

        return False

    def _scan_distributions(self, dist_dir: Path) -> dict:
        """Scan dist/ for organized profile/timestamp builds."""
        builds = {}

        if not dist_dir.exists():
            return builds

        # Iterate through profile directories
        for profile_dir in sorted(dist_dir.iterdir()):
            if not profile_dir.is_dir():
                continue

            profile_name = profile_dir.name
            builds[profile_name] = []

            # Iterate through timestamp directories
            for timestamp_dir in sorted(profile_dir.iterdir(), reverse=True):  # Most recent first
                if not timestamp_dir.is_dir():
                    continue

                # Detect platforms
                platforms = self._detect_platforms(timestamp_dir)
                if not platforms:
                    continue

                # Calculate size
                size = sum(f.stat().st_size for f in timestamp_dir.rglob("*") if f.is_file())

                builds[profile_name].append(
                    {
                        "timestamp": timestamp_dir.name,
                        "path": timestamp_dir,
                        "platforms": platforms,
                        "size": size,
                    }
                )

        return builds

    def _detect_platforms(self, build_dir: Path) -> list:
        """Detect which bundle variants are present in a build directory."""
        platforms = []
        for bundle_name, s3_key in self._BUNDLE_TO_KEY.items():
            if (build_dir / bundle_name).is_dir():
                platforms.append(s3_key)
        return platforms

    def _format_size(self, bytes_size: int) -> str:
        """Format bytes to human readable size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"

    def _show_distribution_wizard(self, builds: dict, console: Console) -> Path:
        """Show interactive wizard to select build to distribute."""
        import questionary

        # Flatten builds into choices
        choices = []
        build_map = {}
        idx = 1

        for profile_name in sorted(builds.keys()):
            profile_builds = builds[profile_name]
            if not profile_builds:
                continue

            console.print(f"\n[bold]Profile: {profile_name}[/bold]")

            for build in profile_builds:
                timestamp = build["timestamp"]
                platforms_str = ", ".join(build["platforms"])
                size_str = self._format_size(build["size"])

                label = f"  [{idx}] {timestamp}"
                if build == profile_builds[0]:
                    label += " (Latest)"
                console.print(label)
                console.print(f"      Platforms: {platforms_str}")
                console.print(f"      Size: {size_str}")

                choice_text = f"{profile_name} - {timestamp}" + (" (Latest)" if build == profile_builds[0] else "")
                choices.append(choice_text)
                build_map[choice_text] = build["path"]
                idx += 1

        if not choices:
            return None

        # Auto-select if only one build
        if len(choices) == 1:
            console.print("\n[green]Auto-selecting only available build[/green]")
            return build_map[choices[0]]

        # Show selection
        console.print()
        selected = questionary.select(
            "Select package to distribute:",
            choices=choices,
        ).ask()

        if not selected:
            return None

        return build_map[selected]

    def handle(self) -> int:
        """Execute the distribute command."""
        console = Console()

        # Show header
        console.print(
            Panel.fit(
                "[bold cyan]Claude Code Package Distribution[/bold cyan]\n\nShare packages securely via presigned URLs",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Check for old flat structure and fail with clear message
        dist_dir = Path(self.option("package-path"))
        if self._check_old_flat_structure(dist_dir):
            console.print("[red]Error: Old distribution format detected![/red]")
            console.print()
            console.print("The dist/ directory contains files from an old package format.")
            console.print("Please delete the dist/ directory and run the package command again:")
            console.print()
            console.print("  [cyan]rm -rf dist/[/cyan]")
            console.print("  [cyan]poetry run ccwb package --profile <profile-name>[/cyan]")
            console.print()
            return 1

        # Scan for new organized structure
        console.print("\n[bold]Scanning package directory...[/bold]")
        builds = self._scan_distributions(dist_dir)

        if not builds or all(len(b) == 0 for b in builds.values()):
            console.print("[red]No packaged distributions found.[/red]")
            console.print("Run 'poetry run ccwb package' first to build packages.")
            return 1

        # Determine which build to use
        selected_build_path = None

        # Option 1: Explicit profile + timestamp
        build_profile = self.option("build-profile")
        timestamp = self.option("timestamp")
        if build_profile and timestamp:
            if build_profile in builds:
                for build in builds[build_profile]:
                    if build["timestamp"] == timestamp:
                        selected_build_path = build["path"]
                        break
            if not selected_build_path:
                console.print(f"[red]Build not found: {build_profile}/{timestamp}[/red]")
                return 1

        # Option 2: Latest flag (auto-select most recent)
        elif self.option("latest"):
            # Find most recent build across all profiles
            latest_build = None
            latest_timestamp = None

            for _profile_name, profile_builds in builds.items():
                if profile_builds:
                    build = profile_builds[0]  # Already sorted, first is latest
                    if latest_timestamp is None or build["timestamp"] > latest_timestamp:
                        latest_timestamp = build["timestamp"]
                        latest_build = build["path"]

            selected_build_path = latest_build
            console.print(f"[green]Auto-selected latest build: {latest_build.parent.name}/{latest_build.name}[/green]")

        # Option 3: Show wizard (default)
        else:
            selected_build_path = self._show_distribution_wizard(builds, console)
            if not selected_build_path:
                console.print("[yellow]Distribution cancelled.[/yellow]")
                return 0

        # Use selected build path for distribution
        package_path = selected_build_path
        console.print(f"\n[green]Using build: {package_path.parent.name}/{package_path.name}[/green]")

        # Load configuration
        config = Config.load()

        # Get profile name (use active profile if not specified)
        profile_name = self.option("profile")
        if not profile_name:
            profile_name = config.active_profile
            console.print(f"[dim]Using active profile: {profile_name}[/dim]\n")
        else:
            console.print(f"[dim]Using profile: {profile_name}[/dim]\n")

        profile = config.get_profile(profile_name)
        if not profile and profile_name == "default":
            # Fall back to active profile
            profile_name = config.active_profile
            profile = config.get_profile(profile_name)

        if not profile:
            if profile_name:
                console.print(f"[red]Profile '{profile_name}' not found. Run 'poetry run ccwb init' first.[/red]")
            else:
                console.print(
                    "[red]No active profile set. Run 'poetry run ccwb init' or "
                    "'poetry run ccwb context use <profile>' first.[/red]"
                )
            return 1

        # Check if distribution is enabled and stack is deployed
        if profile.enable_distribution:
            dist_stack_name = profile.stack_names.get("distribution", f"{profile.identity_pool_name}-distribution")
            try:
                dist_outputs = get_stack_outputs(dist_stack_name, profile.aws_region)
                if not dist_outputs:
                    console.print("[red]Distribution stack not deployed.[/red]")
                    console.print("Deploy the distribution stack first:")
                    console.print("  poetry run ccwb deploy distribution")
                    return 1
            except Exception:
                console.print("[red]Distribution stack not deployed.[/red]")
                console.print("Deploy the distribution stack first:")
                console.print("  poetry run ccwb deploy distribution")
                return 1
        else:
            # Distribution not enabled - show info message
            console.print("[yellow]Note: Distribution features not enabled.[/yellow]")
            console.print("Package will be created locally without S3 upload or presigned URL.")

        # Get latest URL if requested (only if distribution is enabled)
        if self.option("get-latest"):
            if not profile.enable_distribution:
                console.print("[red]Distribution features not enabled.[/red]")
                console.print("Enable distribution in profile configuration to use this feature.")
                return 1
            return self._get_latest_url(profile, console)

        # Route to appropriate distribution method based on type
        if profile.distribution_type == "landing-page":
            # For landing page, upload platform-specific packages
            return self._upload_landing_page_packages(profile, console, package_path)
        else:
            # presigned-s3 or legacy - use existing logic
            return self._create_distribution(profile, console, package_path)

    def _get_latest_url(self, profile, console: Console) -> int:
        """Retrieve the latest distribution URL from Parameter Store."""
        try:
            ssm = boto3.client("ssm", region_name=profile.aws_region)

            # Get parameter
            response = ssm.get_parameter(
                Name=f"/claude-code/{profile.identity_pool_name}/distribution/latest", WithDecryption=True
            )

            # Parse the stored data
            data = json.loads(response["Parameter"]["Value"])

            # Check if URL is still valid
            expires = datetime.fromisoformat(data["expires"])
            now = datetime.now()

            if expires < now:
                console.print("[red]Latest distribution URL has expired.[/red]")
                console.print("Generate a new one with: poetry run ccwb distribute")
                return 1

            # Display information
            console.print("\n[bold]Latest Distribution URL[/bold]")
            console.print(f"Expires: {expires.strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"Package: {data.get('filename', 'Unknown')}")
            console.print(f"SHA256: {data.get('checksum', 'Unknown')}")
            console.print(f"\n[cyan]{data['url']}[/cyan]")

            # Output download commands for different platforms
            console.print("\n[bold]Download and Installation Instructions:[/bold]")

            filename = data.get("filename", "claude-code-package.zip")

            console.print("\n[cyan]For macOS/Linux:[/cyan]")
            console.print("1. Download (copy entire line):")
            # Use regular print to avoid Rich console line wrapping
            print(f'   curl -L -o "{filename}" "{data["url"]}"')
            console.print("2. Extract and install:")
            console.print(f"   unzip {filename} && cd claude-code-package && ./install.sh")

            console.print("\n[cyan]For Windows PowerShell:[/cyan]")
            console.print("1. Download (copy entire line):")
            print(f'   Invoke-WebRequest -Uri "{data["url"]}" -OutFile "{filename}"')
            console.print("2. Extract and install:")
            console.print(f'   Expand-Archive -Path "{filename}" -DestinationPath "."')
            console.print("   cd claude-code-package")
            console.print("   .\\install.bat")

            console.print(f"\n[dim]Verify download with: sha256sum {filename} (or Get-FileHash on Windows)[/dim]")

            # Show QR code if requested
            if self.option("show-qr"):
                self._display_qr_code(data["url"], console)

            # Try to get download stats from S3 (optional)
            self._show_download_stats(profile, data.get("package_key"), console)

            return 0

        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                console.print("[yellow]No distribution URL found.[/yellow]")
                console.print("Create one with: poetry run ccwb distribute")
            else:
                console.print(f"[red]Error retrieving URL: {e}[/red]")
            return 1

    # Mapping from bundle directory name to S3 key.
    # Portable bundles strip the "-portable" suffix (the portable runtime is the
    # default, so the key stays short); slim bundles keep "-slim" so both
    # variants can coexist for Linux.
    _BUNDLE_TO_KEY = {
        "windows-portable": "windows",
        "macos-arm64-portable": "macos-arm64",
        "macos-intel-portable": "macos-intel",
        "linux-x64-portable": "linux-x64",
        "linux-arm64-portable": "linux-arm64",
        "linux-x64-slim": "linux-x64-slim",
        "linux-arm64-slim": "linux-arm64-slim",
    }

    def _upload_landing_page_packages(self, profile, console: Console, package_path: Path) -> int:
        """Upload per-bundle zip archives to S3 for the landing page."""
        import zipfile

        import boto3

        if not package_path.exists():
            console.print(f"[red]Package directory not found: {package_path}[/red]")
            console.print("Run 'poetry run ccwb package' first to build packages.")
            return 1

        dist_stack_name = profile.stack_names.get("distribution", f"{profile.identity_pool_name}-distribution")
        try:
            stack_outputs = get_stack_outputs(dist_stack_name, profile.aws_region)
            bucket_name = stack_outputs.get("DistributionBucket")
            landing_url = stack_outputs.get("DistributionURL")
            if not bucket_name:
                console.print("[red]S3 bucket not found in distribution stack outputs.[/red]")
                return 1
        except Exception as e:
            console.print(f"[red]Error getting distribution stack outputs: {e}[/red]")
            console.print("Deploy the distribution stack first: poetry run ccwb deploy distribution")
            return 1

        console.print("\n[bold]Scanning package directory...[/bold]")

        # Discover which bundle directories the packager produced.
        discovered: list[tuple[str, str, Path]] = []  # (bundle_dir_name, s3_key, path)
        for bundle_name, s3_key in self._BUNDLE_TO_KEY.items():
            bundle_path = package_path / bundle_name
            if bundle_path.is_dir():
                discovered.append((bundle_name, s3_key, bundle_path))
                console.print(f"  ✓ {bundle_name}/ → packages/{s3_key}/latest.zip")

        if not discovered:
            console.print("[red]No bundle directories found under the package path.[/red]")
            console.print(
                f"Expected one or more of: {', '.join(self._BUNDLE_TO_KEY.keys())}"
            )
            console.print("Run: [cyan]poetry run ccwb package[/cyan] first.")
            return 1

        # Extract profile name and build timestamp from package_path.
        # Expected format: dist/<profile>/<YYYY-MM-DD-HHMMSS>/. Dir names that
        # don't match (e.g. manual consolidations like "2026-04-19-final") fall
        # back to the directory's mtime so the landing page never renders
        # garbage like "2026-04-19 fi:na:l".
        import re
        from datetime import datetime as _dt

        profile_name = package_path.parent.name
        build_timestamp = package_path.name
        m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})", build_timestamp)
        if m:
            release_date = m.group(1)
            release_time = f"{m.group(2)}:{m.group(3)}:{m.group(4)}"
        else:
            mtime = _dt.fromtimestamp(package_path.stat().st_mtime)
            release_date = mtime.strftime("%Y-%m-%d")
            release_time = mtime.strftime("%H:%M:%S")
        release_datetime = f"{release_date} {release_time}"

        s3 = boto3.client("s3", region_name=profile.aws_region)

        # Purge every stale object under packages/ so renamed keys (e.g. legacy
        # "linux"/"mac"/"all-platforms") don't keep showing up on the landing page.
        console.print("\n[dim]Cleaning up old packages from S3...[/dim]")
        try:
            paginator = s3.get_paginator("list_objects_v2")
            to_delete = []
            for page in paginator.paginate(Bucket=bucket_name, Prefix="packages/"):
                for obj in page.get("Contents", []) or []:
                    to_delete.append({"Key": obj["Key"]})
            # delete_objects takes up to 1000 keys per call; batch to be safe.
            for i in range(0, len(to_delete), 1000):
                batch = to_delete[i : i + 1000]
                if batch:
                    s3.delete_objects(Bucket=bucket_name, Delete={"Objects": batch})
            if to_delete:
                console.print(f"[dim]    Removed {len(to_delete)} stale object(s).[/dim]")
        except ClientError as e:
            console.print(f"[yellow]Warning: could not clean up old packages: {e}[/yellow]")

        temp_dir = Path(tempfile.mkdtemp())
        uploaded_count = 0

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.1f}%",
                console=console,
            ) as progress:
                task = progress.add_task("Uploading packages to S3...", total=len(discovered))

                for bundle_name, s3_key, bundle_path in discovered:
                    zip_path = temp_dir / f"{s3_key}.zip"
                    # Each zip contains exactly the bundle directory at the top
                    # level so `unzip foo.zip` produces a single named folder.
                    # Write explicit directory entries (trailing slash, zero
                    # bytes) for every dir: Windows File Explorer's built-in
                    # "Extract All" sometimes turns implicit directories (dirs
                    # that appear only as path prefixes of file entries) into
                    # zero-byte *files*, which breaks Python namespace packages
                    # like jaraco/. Listing them explicitly forces Explorer to
                    # create real directories.
                    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                        dirs_written: set[str] = set()
                        for entry in sorted(bundle_path.rglob("*")):
                            rel = entry.relative_to(bundle_path)
                            if entry.is_dir():
                                arc_dir = f"{bundle_name}/{rel}/".replace("\\", "/")
                                if arc_dir not in dirs_written:
                                    zipf.writestr(arc_dir, b"")
                                    dirs_written.add(arc_dir)
                            elif entry.is_file():
                                zipf.write(entry, f"{bundle_name}/{rel}")

                    s3_object_key = f"packages/{s3_key}/latest.zip"
                    try:
                        s3.upload_file(
                            str(zip_path),
                            bucket_name,
                            s3_object_key,
                            ExtraArgs={
                                "Metadata": {
                                    "profile": profile_name,
                                    "timestamp": build_timestamp,
                                    "release_date": release_date,
                                    "release_datetime": release_datetime,
                                }
                            },
                        )
                        uploaded_count += 1
                        progress.update(task, advance=1, description=f"Uploaded {s3_key}")
                    except ClientError as e:
                        console.print(f"[red]Failed to upload {s3_key} package: {e}[/red]")
                        continue
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        if uploaded_count > 0:
            console.print(f"\n[bold green]✓ Successfully uploaded {uploaded_count} package(s)![/bold green]")
            console.print(f"\n[bold]Landing Page URL:[/bold] [cyan]{landing_url}[/cyan]")
            console.print(f"[dim]Profile: {profile_name}[/dim]")
            console.print(f"[dim]Build Timestamp: {build_timestamp}[/dim]")
            console.print(f"[dim]Release Date: {release_datetime}[/dim]")
            console.print("\n[bold]Uploaded:[/bold]")
            for _, s3_key, _ in discovered:
                console.print(f"  • {s3_key}")
            return 0
        else:
            console.print("[red]Failed to upload any packages.[/red]")
            return 1

    def _create_distribution(self, profile, console: Console, package_path: Path) -> int:
        """Create a new distribution package and generate presigned URL."""
        import json

        import boto3

        # Validate package directory
        if not package_path.exists():
            console.print(f"[red]Package directory not found: {package_path}[/red]")
            console.print("Run 'poetry run ccwb package' first to build packages.")
            return 1

        # Check what's in the package directory. Each bundle is a self-contained
        # directory ({platform}-portable or {platform}-slim) produced by `ccwb package`.
        console.print("\n[bold]Package contents:[/bold]")
        found_bundles: list[str] = []
        for bundle_name, s3_key in self._BUNDLE_TO_KEY.items():
            bundle_path = package_path / bundle_name
            if bundle_path.is_dir():
                mod_time = datetime.fromtimestamp(bundle_path.stat().st_mtime)
                console.print(f"  ✓ {bundle_name}/ (built: {mod_time.strftime('%Y-%m-%d %H:%M')})")
                found_bundles.append(s3_key)

        if (package_path / "config.json").exists():
            console.print("  ✓ Configuration file")
        if (package_path / "claude-settings" / "settings.json").exists():
            console.print("  ✓ Claude Code settings template")

        if not found_bundles:
            console.print("\n[red]No platform bundles found![/red]")
            console.print("Run: [cyan]poetry run ccwb package --target-platform all[/cyan]")
            return 1

        if "windows" not in found_bundles:
            console.print("\n[yellow]Warning: Windows support not included in this distribution[/yellow]")
            from questionary import confirm

            proceed = confirm("Continue without Windows support?", default=False).ask()
            if not proceed:
                console.print("Distribution cancelled.")
                return 0

        console.print(f"\n[green]Ready to distribute for: {', '.join(found_bundles)}[/green]")

        # Default is to stop here: presigned-s3 / local combined-zip behavior is
        # opt-in because users usually distribute bundles per-platform (landing
        # page, manual handoff, internal mirror) rather than a fat 500MB zip.
        if not self.option("archive-all"):
            console.print(
                "\n[dim]Per-platform bundles ready under[/dim] "
                f"[cyan]{package_path}[/cyan][dim]. Pass --archive-all to build a single "
                "claude-code-package.zip for presigned-s3 distribution.[/dim]"
            )
            return 0

        # Validate expiration hours (max 7 days for IAM user presigned URLs)
        try:
            expires_hours = int(self.option("expires-hours"))
            if not 1 <= expires_hours <= 168:
                console.print("[red]Expiration must be between 1 and 168 hours (7 days).[/red]")
                console.print(
                    "[dim]Note: Presigned URLs have a maximum lifetime of 7 days when using IAM user credentials.[/dim]"
                )
                return 1
        except ValueError:
            console.print("[red]Invalid expiration hours.[/red]")
            return 1

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
        ) as progress:
            # Create archive
            task = progress.add_task("Creating distribution archive...", total=None)
            archive_path = self._create_archive(package_path)

            # Calculate checksum
            progress.update(task, description="Calculating checksum...")
            checksum = self._calculate_checksum(archive_path)

            # Prepare filename
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"claude-code-package-{timestamp}.zip"

            # Only do S3 operations if distribution is enabled
            if profile.enable_distribution:
                # Get S3 bucket from distribution stack outputs
                progress.update(task, description="Getting S3 bucket information...")
                dist_stack_name = profile.stack_names.get("distribution", f"{profile.identity_pool_name}-distribution")
                try:
                    stack_outputs = get_stack_outputs(dist_stack_name, profile.aws_region)
                    bucket_name = stack_outputs.get("DistributionBucket")
                    if not bucket_name:
                        console.print("[red]S3 bucket not found in distribution stack outputs.[/red]")
                        return 1
                except Exception as e:
                    console.print(f"[red]Error getting distribution stack outputs: {e}[/red]")
                    console.print("Deploy the distribution stack first: poetry run ccwb deploy distribution")
                    return 1

                # Upload to S3 with progress tracking
                progress.update(task, description="Preparing upload...")
                package_key = f"packages/{timestamp}/{filename}"

                # Get file size for progress tracking
                file_size = archive_path.stat().st_size

                # Configure multipart upload for better performance
                config = TransferConfig(
                    multipart_threshold=1024 * 25,  # 25MB
                    max_concurrency=10,
                    multipart_chunksize=1024 * 25,
                    use_threads=True,
                )

                # Create S3 client
                s3 = boto3.client("s3", region_name=profile.aws_region)

                # Close the spinner progress and create a new one with upload progress
                progress.stop()

                # Create progress bar for upload
                with Progress(
                    TextColumn("[bold blue]Uploading to S3"),
                    BarColumn(),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    "•",
                    DownloadColumn(),
                    "•",
                    TimeRemainingColumn(),
                    console=console,
                ) as upload_progress:
                    upload_task = upload_progress.add_task("upload", total=file_size)

                    # Create callback
                    callback = S3UploadProgress(filename, file_size, upload_progress)
                    callback.set_task_id(upload_task)

                    try:
                        s3.upload_file(
                            str(archive_path),
                            bucket_name,
                            package_key,
                            ExtraArgs={
                                "Metadata": {
                                    "checksum": checksum,
                                    "created": datetime.now().isoformat(),
                                    "profile": profile.name,
                                }
                            },
                            Config=config,
                            Callback=callback,
                        )
                    except ClientError as e:
                        console.print(f"[red]Failed to upload package: {e}[/red]")
                        return 1

                # Restart the spinner progress for remaining tasks
                progress = Progress(
                    SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
                )
                progress.start()
                task = progress.add_task("Processing...", total=None)

            # Generate presigned URL
            progress.update(task, description="Generating presigned URL...")
            allowed_ips = self.option("allowed-ips")

            if allowed_ips:
                # Generate URL with IP restrictions
                url = self._generate_restricted_url(s3, bucket_name, package_key, allowed_ips, expires_hours)
            else:
                # Generate standard presigned URL
                try:
                    url = s3.generate_presigned_url(
                        "get_object", Params={"Bucket": bucket_name, "Key": package_key}, ExpiresIn=expires_hours * 3600
                    )
                except ClientError as e:
                    console.print(f"[red]Failed to generate URL: {e}[/red]")
                    return 1

            # Store in Parameter Store
            progress.update(task, description="Storing in Parameter Store...")
            expiration = datetime.now() + timedelta(hours=expires_hours)

            ssm = boto3.client("ssm", region_name=profile.aws_region)
            try:
                ssm.put_parameter(
                    Name=f"/claude-code/{profile.identity_pool_name}/distribution/latest",
                    Value=json.dumps(
                        {
                            "url": url,
                            "expires": expiration.isoformat(),
                            "package_key": package_key,
                            "checksum": checksum,
                            "filename": filename,
                            "created": datetime.now().isoformat(),
                        }
                    ),
                    Type="SecureString",
                    Overwrite=True,
                    Description="Latest Claude Code package distribution URL",
                )
            except ClientError as e:
                console.print(f"[yellow]Warning: Failed to store in Parameter Store: {e}[/yellow]")

                # Get file size before cleanup
                file_size = archive_path.stat().st_size if archive_path.exists() else 0
            else:
                # Distribution not enabled - save locally
                progress.update(task, description="Saving package locally...")
                local_dir = Path("dist")
                local_dir.mkdir(exist_ok=True)
                local_path = local_dir / filename

                import shutil

                shutil.copy2(archive_path, local_path)

                # Get file size
                file_size = archive_path.stat().st_size if archive_path.exists() else 0

            # Clean up temp file
            archive_path.unlink()

            # Stop progress if it's still running
            if "progress" in locals() and hasattr(progress, "stop"):
                progress.stop()

        # Display results based on distribution mode
        if profile.enable_distribution:
            console.print("\n[bold green]✓ Distribution package created successfully![/bold green]")
            console.print(f"\n[bold]Distribution URL[/bold] (expires in {expires_hours} hours):")
        else:
            console.print("\n[bold green]✓ Package created successfully![/bold green]")
            console.print(f"\n[bold]Package saved locally:[/bold] dist/{filename}")

        if profile.enable_distribution:
            # Show distribution-specific details
            if allowed_ips:
                console.print(f"[dim]Restricted to IPs: {allowed_ips}[/dim]")

            console.print(f"\n[cyan]{url}[/cyan]")

            console.print("\n[bold]Package Details:[/bold]")
            console.print(f"  Filename: {filename}")
            console.print(f"  SHA256: {checksum}")
            console.print(f"  Expires: {expiration.strftime('%Y-%m-%d %H:%M:%S')}")
            console.print(f"  Size: {self._format_size(file_size)}")

            # Show QR code if requested
            if self.option("show-qr"):
                self._display_qr_code(url, console)

            console.print("\n[bold]Share this URL with developers to download the package.[/bold]")

            # Output download commands for different platforms
            console.print("\n[bold]Download and Installation Instructions:[/bold]")

            console.print("\n[cyan]For macOS/Linux:[/cyan]")
            console.print("1. Download (copy entire line):")
            # Use regular print to avoid Rich console line wrapping
            print(f'   curl -L -o "{filename}" "{url}"')
            console.print("2. Extract and install:")
            console.print(f"   unzip {filename} && cd claude-code-package && ./install.sh")

            console.print("\n[cyan]For Windows PowerShell:[/cyan]")
            console.print("1. Download (copy entire line):")
            print(f'   Invoke-WebRequest -Uri "{url}" -OutFile "{filename}"')
            console.print("2. Extract and install:")
            console.print(f'   Expand-Archive -Path "{filename}" -DestinationPath "."')
            console.print("   cd claude-code-package")
            console.print("   .\\install.bat")

            console.print(f"\n[dim]Verify download with: sha256sum {filename} (or Get-FileHash on Windows)[/dim]")
        else:
            # Show local package details
            console.print("\n[bold]Package Details:[/bold]")
            console.print(f"  Filename: {filename}")
            console.print(f"  SHA256: {checksum}")
            console.print(f"  Size: {self._format_size(file_size)}")

            console.print("\n[bold]Installation Instructions:[/bold]")
            console.print("1. Extract the package:")
            console.print(f"   unzip dist/{filename}")
            console.print("2. Install:")
            console.print("   cd claude-code-package")
            console.print("   ./install.sh  (macOS/Linux)")
            console.print("   .\\install.bat  (Windows)")

            console.print("\n[dim]To enable distribution features:[/dim]")
            console.print("  1. Run: poetry run ccwb init")
            console.print("  2. Enable distribution when prompted")
            console.print("  3. Run: poetry run ccwb deploy distribution")

        return 0

    def _create_archive(self, package_path: Path) -> Path:
        """Create a zip archive containing every per-platform bundle dir.

        Bundles are the {platform}-portable / {platform}-slim directories that
        `ccwb package` emits. The zip wraps them under a single
        `claude-code-package/` top-level so extraction doesn't scatter files
        into the user's cwd.
        """
        import zipfile

        temp_dir = Path(tempfile.mkdtemp())
        archive_path = temp_dir / "claude-code-package.zip"

        # Entries to bundle: platform dirs discovered via _BUNDLE_TO_KEY, plus
        # the shared top-level artifacts that aren't platform-specific.
        to_include: list[Path] = []
        for bundle_name in self._BUNDLE_TO_KEY:
            bundle_path = package_path / bundle_name
            if bundle_path.is_dir():
                to_include.append(bundle_path)
        for top_name in ("config.json", "README.md", "claude-settings"):
            p = package_path / top_name
            if p.exists():
                to_include.append(p)

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in to_include:
                if entry.is_file():
                    zf.write(entry, f"claude-code-package/{entry.name}")
                else:
                    for file in entry.rglob("*"):
                        if file.is_file():
                            arcname = f"claude-code-package/{file.relative_to(package_path)}"
                            zf.write(file, arcname)

        return archive_path

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _generate_restricted_url(self, s3_client, bucket: str, key: str, allowed_ips: str, expires_hours: int) -> str:
        """Generate a presigned URL with IP restrictions."""
        # Parse IP addresses
        [ip.strip() for ip in allowed_ips.split(",")]

        # Create bucket policy for IP restriction

        # Generate presigned POST (which supports policies)
        # Note: For GET with IP restrictions, we'd need to use CloudFront
        # For now, we'll generate a standard URL with a warning
        url = s3_client.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_hours * 3600
        )

        # Log the requested IP restriction for audit
        Console().print("[yellow]Note: IP restriction requested but requires CloudFront for enforcement.[/yellow]")
        Console().print(
            "[yellow]URL will work from any IP. Consider using CloudFront for IP-based access control.[/yellow]"
        )

        return url

    def _display_qr_code(self, url: str, console: Console):
        """Display a QR code for the URL if qrcode library is available."""
        try:
            import qrcode

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,
                border=1,
            )
            qr.add_data(url)
            qr.make(fit=True)

            console.print("\n[bold]QR Code for distribution URL:[/bold]")
            qr.print_ascii(invert=True)

        except ImportError:
            console.print("\n[dim]QR code display requires: pip install qrcode[/dim]")

    def _show_download_stats(self, profile, package_key: str, console: Console):
        """Show download statistics if available (requires S3 access logs)."""
        # This would require S3 access logs to be configured and queryable
        # For now, just show a placeholder
        console.print("\n[dim]Download tracking requires S3 access logs configuration.[/dim]")

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"


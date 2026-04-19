# ABOUTME: Package command for building distribution packages
# ABOUTME: Creates ready-to-distribute packages with embedded configuration

"""Package command - Build distribution packages."""

import json
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path

import questionary
from cleo.commands.command import Command
from cleo.helpers import option
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from claude_code_with_bedrock.cli.utils.aws import get_stack_outputs
from claude_code_with_bedrock.cli.utils.display import display_configuration_info
from claude_code_with_bedrock.config import Config
from claude_code_with_bedrock.models import (
    get_source_region_for_profile,
)

# Windows install scripts. ASCII-only: PowerShell 5.x parses .ps1 as Windows-1252
# by default, so non-ASCII chars produce confusing "string is missing the
# terminator" errors on lines far from the actual bad byte.
_WINDOWS_INSTALL_PS1 = r"""#Requires -Version 5.0
<#
.SYNOPSIS
  Install Claude Code with Amazon Bedrock (portable Python build) on Windows.

.DESCRIPTION
  Copies payload to %USERPROFILE%\claude-code-with-bedrock\, substitutes the
  credential-process path placeholder in claude-settings\settings.json, and
  merges the result into %USERPROFILE%\.claude\settings.json. Existing
  settings.json is backed up with a timestamp suffix before merge.
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "$env:USERPROFILE\claude-code-with-bedrock",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

# 1. Locate payload
$payload = @('python', 'credential_provider', 'credential-process.cmd', 'config.json')
foreach ($item in $payload) {
    if (-not (Test-Path (Join-Path $ScriptDir $item))) {
        throw "Missing payload item: $item (run install.ps1 from inside extracted package)"
    }
}
$templatePath = Join-Path $ScriptDir 'claude-settings\settings.json'
if (-not (Test-Path $templatePath)) {
    throw "Missing claude-settings\settings.json template."
}

# 2. Install files
Write-Step "Installing to $InstallPath"
if ((Test-Path $InstallPath) -and -not $Force) {
    $resp = Read-Host "Install path exists. Overwrite contents? [y/N]"
    if ($resp -notmatch '^[yY]') { throw "Aborted by user." }
}
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
foreach ($item in $payload) {
    $src = Join-Path $ScriptDir $item
    $dst = Join-Path $InstallPath $item
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse -Force $src $dst
}
Write-Ok "Files copied."

# 3. Substitute placeholder in settings template.
$credCmd = Join-Path $InstallPath 'credential-process.cmd'
$templateText = Get-Content -Raw $templatePath
$credCmdJson = $credCmd -replace '\\', '\\'
$templateText = $templateText -replace '__CREDENTIAL_PROCESS_PATH__', $credCmdJson

$templateObj = $templateText | ConvertFrom-Json

# Drop otelHeadersHelper if template still has the placeholder (no otel-helper in package).
if ($templateObj.PSObject.Properties.Name -contains 'otelHeadersHelper' -and
    $templateObj.otelHeadersHelper -match '__OTEL_HELPER_PATH__') {
    $templateObj.PSObject.Properties.Remove('otelHeadersHelper')
    Write-Warn2 "otel-helper not bundled - dropping otelHeadersHelper."
}

# 4. Merge into ~\.claude\settings.json. Template values win for the keys we
#    set (awsAuthRefresh and env.*); user's other keys are preserved.
$claudeDir = Join-Path $env:USERPROFILE '.claude'
$settingsPath = Join-Path $claudeDir 'settings.json'
New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null

if (Test-Path $settingsPath) {
    $backup = "$settingsPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $settingsPath $backup
    Write-Ok "Backed up existing settings.json -> $backup"
    $existing = Get-Content -Raw $settingsPath | ConvertFrom-Json
} else {
    $existing = [PSCustomObject]@{}
}

$merged = [ordered]@{}
foreach ($p in $existing.PSObject.Properties) { $merged[$p.Name] = $p.Value }

foreach ($p in $templateObj.PSObject.Properties) {
    if ($p.Name -eq 'env') {
        $envMerged = [ordered]@{}
        if ($merged.Contains('env')) {
            foreach ($ep in $merged['env'].PSObject.Properties) { $envMerged[$ep.Name] = $ep.Value }
        }
        foreach ($ep in $p.Value.PSObject.Properties) { $envMerged[$ep.Name] = $ep.Value }
        $merged['env'] = [PSCustomObject]$envMerged
    } else {
        $merged[$p.Name] = $p.Value
    }
}

$json = [PSCustomObject]$merged | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($settingsPath, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Ok "Updated $settingsPath"

Write-Host ""
Write-Step "Done."
Write-Host "   Install path: $InstallPath"
Write-Host ""
Write-Host "Next: run 'claude' in a new shell to trigger first login."
"""

_WINDOWS_INSTALL_BAT = (
    "@echo off\r\n"
    "REM Double-click entry point. Delegates to install.ps1.\r\n"
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*\r\n'
    "if errorlevel 1 (\r\n"
    "    echo.\r\n"
    "    echo Installation failed.\r\n"
    "    pause\r\n"
    "    exit /b 1\r\n"
    ")\r\n"
    "echo.\r\n"
    "pause\r\n"
)


class PackageCommand(Command):
    """
    Build distribution packages for your organization

    package
        {--target-platform=macos : Target platform (macos, linux, all)}
    """

    name = "package"
    description = "Build distribution packages with embedded configuration"

    options = [
        option(
            "target-platform", description="Target platform for binary (macos, linux, all)", flag=False, default="all"
        ),
        option(
            "profile", description="Configuration profile to use (defaults to active profile)", flag=False, default=None
        ),
        option("build-verbose", description="Enable verbose logging for build processes", flag=True),
        option(
            "slim",
            description="Linux only: build a ~25MB bundle using system Python 3.9+ instead of shipping PBS",
            flag=True,
        ),
    ]

    def handle(self) -> int:
        """Execute the package command."""
        import platform
        import subprocess

        console = Console()

        # Load configuration first
        config = Config.load()
        # Use specified profile or default to active profile, or fall back to "ClaudeCode"
        profile_name = self.option("profile") or config.active_profile or "ClaudeCode"
        profile = config.get_profile(profile_name)

        if not profile:
            console.print("[red]No deployment found. Run 'poetry run ccwb init' first.[/red]")
            return 1

        # Interactive prompts if not provided via CLI
        slim = bool(self.option("slim"))
        target_platform = self.option("target-platform")
        if target_platform == "all":  # Default value, prompt user
            # Build list of available platform choices
            # Note: "macos" is omitted because it's just a smart alias for the current architecture
            # Users should explicitly choose macos-arm64 or macos-intel for clarity
            platform_choices = [
                "macos-arm64",
                "macos-intel",
                "linux-x64",
                "linux-arm64",
                "windows",
            ]

            # Use checkbox for multiple selection (require at least one)
            selected_platforms = questionary.checkbox(
                "Which platform(s) do you want to build for? (Use space to select, enter to confirm)",
                choices=platform_choices,
                validate=lambda x: len(x) > 0 or "You must select at least one platform",
            ).ask()

            # Use the selected platforms (guaranteed to have at least one due to validation)
            target_platform = selected_platforms if len(selected_platforms) > 1 else selected_platforms[0]

        # Prompt for co-authorship preference (default to No - opt-in approach)
        include_coauthored_by = questionary.confirm(
            "Include 'Co-Authored-By: Claude' in git commits?",
            default=False,
        ).ask()

        # Validate platform
        valid_platforms = ["macos", "macos-arm64", "macos-intel", "linux", "linux-x64", "linux-arm64", "windows", "all"]
        if isinstance(target_platform, list):
            for platform_name in target_platform:
                if platform_name not in valid_platforms:
                    console.print(
                        f"[red]Invalid platform: {platform_name}. Valid options: {', '.join(valid_platforms)}[/red]"
                    )
                    return 1
        elif target_platform not in valid_platforms:
            console.print(
                f"[red]Invalid platform: {target_platform}. Valid options: {', '.join(valid_platforms)}[/red]"
            )
            return 1

        # Get actual Identity Pool ID or Role ARN from stack outputs
        console.print("[yellow]Fetching deployment information...[/yellow]")
        stack_outputs = get_stack_outputs(
            profile.stack_names.get("auth", f"{profile.identity_pool_name}-stack"), profile.aws_region
        )

        if not stack_outputs:
            console.print("[red]Could not fetch stack outputs. Is the stack deployed?[/red]")
            return 1

        # Check federation type and get appropriate identifier
        federation_type = stack_outputs.get("FederationType", profile.federation_type)
        identity_pool_id = None
        federated_role_arn = None

        if federation_type == "direct":
            # Try DirectSTSRoleArn first (both old and new templates have this for direct mode)
            # Then fallback to FederatedRoleArn (new templates)
            federated_role_arn = stack_outputs.get("DirectSTSRoleArn")
            if not federated_role_arn or federated_role_arn == "N/A":
                federated_role_arn = stack_outputs.get("FederatedRoleArn")
            if not federated_role_arn or federated_role_arn == "N/A":
                console.print("[red]Direct STS Role ARN not found in stack outputs.[/red]")
                return 1
        else:
            identity_pool_id = stack_outputs.get("IdentityPoolId")
            if not identity_pool_id:
                console.print("[red]Identity Pool ID not found in stack outputs.[/red]")
                return 1

        # Welcome
        console.print(
            Panel.fit(
                "[bold cyan]Package Builder[/bold cyan]\n\n"
                f"Creating distribution package for {profile.provider_domain}",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Create timestamped output directory under profile name
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        output_dir = Path("./dist") / profile_name / timestamp

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create embedded configuration based on federation type
        embedded_config = {
            "provider_domain": profile.provider_domain,
            "client_id": profile.client_id,
            "region": profile.aws_region,
            "allowed_bedrock_regions": profile.allowed_bedrock_regions,
            "package_timestamp": timestamp,
            "package_version": "1.0.0",
            "federation_type": federation_type,
        }

        # Add federation-specific configuration
        if federation_type == "direct":
            embedded_config["federated_role_arn"] = federated_role_arn
            embedded_config["max_session_duration"] = profile.max_session_duration
        else:
            embedded_config["identity_pool_id"] = identity_pool_id

        # Show what will be packaged using shared display utility
        display_configuration_info(profile, identity_pool_id or federated_role_arn, format_type="simple")

        console.print("\n[bold]Building package...[/bold]")

        # Portable Python bundles cross-build from any host (no PyInstaller/Docker).
        if isinstance(target_platform, list):
            platforms_to_build = []
            for platform_choice in target_platform:
                if platform_choice == "all":
                    platforms_to_build.extend(
                        ["macos-arm64", "macos-intel", "linux-x64", "linux-arm64", "windows"]
                    )
                elif platform_choice not in platforms_to_build:
                    platforms_to_build.append(platform_choice)
        elif target_platform == "all":
            platforms_to_build = ["macos-arm64", "macos-intel", "linux-x64", "linux-arm64", "windows"]
        else:
            platforms_to_build = [target_platform]

        built_executables = []

        console.print()
        if slim:
            non_linux = [p for p in platforms_to_build if not p.startswith("linux")]
            if non_linux:
                console.print(
                    f"[red]--slim is Linux-only; got non-Linux targets: {', '.join(non_linux)}.[/red]"
                )
                return 1

        for platform_name in platforms_to_build:
            variant = " (slim)" if slim else ""
            console.print(f"[cyan]Building credential process for {platform_name}{variant}...[/cyan]")
            try:
                executable_path = self._build_executable(output_dir, platform_name, slim=slim)
                built_executables.append((platform_name, executable_path))
            except Exception as e:
                console.print(f"[yellow]Warning: Could not build credential process for {platform_name}: {e}[/yellow]")

        # OTEL helper is bundled as Python source inside each portable bundle (no
        # separate compiled binary), so the per-platform hash dict is empty now.
        otel_helper_hashes: dict[str, str] = {}

        if not built_executables:
            console.print("\n[red]Error: No binaries were successfully built.[/red]")
            console.print("Please check the error messages above.")
            return 1

        console.print("\n[cyan]Creating configuration...[/cyan]")
        federation_identifier = federated_role_arn if federation_type == "direct" else identity_pool_id
        self._create_config(
            output_dir,
            profile,
            federation_identifier,
            federation_type,
            profile_name,
            otel_helper_hashes=otel_helper_hashes,
        )

        console.print("[cyan]Creating documentation...[/cyan]")
        self._create_documentation(output_dir, profile, timestamp)

        console.print("[cyan]Creating Claude Code settings...[/cyan]")
        self._create_claude_settings(output_dir, profile, include_coauthored_by, profile_name)

        # Copy config.json + claude-settings/ into each bundle so the bundled
        # installer (install.ps1 / install.sh) finds them via its own directory.
        if any(p == "windows" for p, _ in built_executables):
            self._finalize_windows_portable(output_dir)
        for platform_name, _ in built_executables:
            if platform_name in self.POSIX_PYTHON_URLS:
                self._finalize_posix_portable(
                    output_dir, platform_name, profile.monitoring_enabled, slim=slim
                )

        # Summary
        console.print("\n[green]✓ Package created successfully![/green]")
        console.print(f"\nOutput directory: [cyan]{output_dir}[/cyan]")
        console.print("\nPackage contents:")

        suffix = "-slim" if slim else "-portable"
        for platform_name, _ in built_executables:
            if platform_name == "windows":
                console.print("  • windows-portable/ - Portable Python distribution for Windows")
            elif slim:
                console.print(f"  • {platform_name}{suffix}/ - Slim bundle for {platform_name} (system Python 3.9+)")
            else:
                console.print(
                    f"  • {platform_name}{suffix}/ - Portable Python distribution for {platform_name}"
                )

        console.print("  • config.json - Configuration")
        if (output_dir / "windows-portable" / "install.bat").exists():
            console.print("  • windows-portable/install.bat - Installation script for Windows")
        for platform_name, _ in built_executables:
            if platform_name in self.POSIX_PYTHON_URLS:
                console.print(f"  • {platform_name}{suffix}/install.sh - Installation script")
        console.print("  • README.md - Installation instructions")
        if profile.monitoring_enabled and (output_dir / "claude-settings" / "settings.json").exists():
            console.print("  • claude-settings/settings.json - Claude Code telemetry settings")

        console.print("\n[bold]Distribution steps:[/bold]")
        console.print("1. Send users the appropriate {platform}-portable/ bundle")
        console.print("2. Users run: ./install.sh (or install.bat on Windows)")
        console.print("3. Authentication is configured automatically")

        # Show next steps
        console.print("\n[bold]Next steps:[/bold]")

        # Only show distribute command if distribution is enabled
        if profile.enable_distribution:
            console.print("To create a distribution package: [cyan]poetry run ccwb distribute[/cyan]")
        else:
            console.print("Share the dist folder with your users for installation")

        return 0

    def _build_executable(self, output_dir: Path, target_platform: str, slim: bool = False) -> Path:
        """Build executable for target platform using portable Python bundles.

        slim=True switches Linux targets to a ~25MB bundle that relies on the
        user's system Python 3.9+ instead of shipping python-build-standalone.
        Non-Linux targets raise when slim=True.
        """
        import platform

        current_machine = platform.machine().lower()

        if target_platform == "windows":
            if slim:
                raise ValueError("--slim is Linux-only; Windows and macOS always ship portable Python.")
            return self._build_windows_portable_python(output_dir)

        # Smart aliases: "macos"/"linux" resolve to the current architecture.
        if target_platform == "macos":
            target_platform = "macos-arm64" if current_machine == "arm64" else "macos-intel"
        elif target_platform == "linux":
            target_platform = "linux-arm64" if current_machine in ("aarch64", "arm64") else "linux-x64"

        if slim:
            if not target_platform.startswith("linux"):
                raise ValueError("--slim is Linux-only; Windows and macOS always ship portable Python.")
            return self._build_linux_slim(output_dir, target_platform)

        if target_platform in self.POSIX_PYTHON_URLS:
            return self._build_posix_portable_python(output_dir, target_platform)

        raise ValueError(f"Unsupported target platform: {target_platform}")

    # Portable Python distribution (python-build-standalone, install_only variant).
    # Pinned for reproducibility; bump all entries together when updating Python.
    _PBS_RELEASE = "20260414"
    _PBS_VERSION = "3.12.13"
    WINDOWS_PYTHON_URL = (
        f"https://github.com/astral-sh/python-build-standalone/releases/download/"
        f"{_PBS_RELEASE}/cpython-{_PBS_VERSION}%2B{_PBS_RELEASE}-x86_64-pc-windows-msvc-install_only.tar.gz"
    )
    # pywin32-ctypes is keyring's Windows backend dependency, gated on
    # `sys_platform=="win32"`. pip evaluates env-markers on the HOST
    # interpreter (macOS/Linux here), not on --platform=win_amd64, so the
    # marker evaluates false and pywin32-ctypes silently drops. Pin it.
    WINDOWS_PYTHON_DEPS = ["boto3", "keyring", "pyjwt", "requests", "pywin32-ctypes"]

    # POSIX portable Python tarballs. install.sh bundles each extract into
    # {platform}-portable/python/ with a POSIX layout (bin/python3, lib/, etc.).
    _PBS_URL_FMT = (
        "https://github.com/astral-sh/python-build-standalone/releases/download/"
        f"{_PBS_RELEASE}/cpython-{_PBS_VERSION}%2B{_PBS_RELEASE}-{{triple}}-install_only.tar.gz"
    )
    POSIX_PYTHON_URLS = {
        "macos-arm64": _PBS_URL_FMT.format(triple="aarch64-apple-darwin"),
        "macos-intel": _PBS_URL_FMT.format(triple="x86_64-apple-darwin"),
        "linux-x64": _PBS_URL_FMT.format(triple="x86_64-unknown-linux-gnu"),
        "linux-arm64": _PBS_URL_FMT.format(triple="aarch64-unknown-linux-gnu"),
    }
    # pip --platform tag per bundle (must match the target's manylinux / macOS tag).
    POSIX_PIP_PLATFORMS = {
        "macos-arm64": ["macosx_11_0_arm64"],
        "macos-intel": ["macosx_10_12_x86_64"],
        "linux-x64": ["manylinux_2_17_x86_64", "manylinux2014_x86_64"],
        "linux-arm64": ["manylinux_2_17_aarch64", "manylinux2014_aarch64"],
    }
    POSIX_PYTHON_DEPS = ["boto3", "keyring", "pyjwt", "requests"]

    def _build_windows_portable_python(self, output_dir: Path) -> Path:
        """Assemble a Windows distribution using portable Python + vendored deps.

        Produces output_dir/windows-portable/ containing:
          python/               - python-build-standalone runtime with deps in site-packages
          credential_provider/  - source .py files
          credential-process.cmd - entry wrapper
          install.ps1           - PowerShell installer (merges ~/.claude/settings.json)
          install.bat           - double-click entry that invokes install.ps1

        Returns the path to credential-process.cmd so the caller can treat it
        as the "built executable" for downstream bookkeeping.
        """
        import shutil
        import tarfile
        import urllib.request

        console = Console()

        portable_dir = output_dir / "windows-portable"
        portable_dir.mkdir(parents=True, exist_ok=True)

        # 1. Fetch (or reuse cached) python-build-standalone tarball.
        cache_dir = Path.home() / ".ccwb" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        tarball_name = self.WINDOWS_PYTHON_URL.rsplit("/", 1)[-1]
        tarball_path = cache_dir / tarball_name
        if not tarball_path.exists():
            console.print(f"[dim]Downloading portable Python: {tarball_name}[/dim]")
            urllib.request.urlretrieve(self.WINDOWS_PYTHON_URL, tarball_path)
        else:
            console.print(f"[dim]Using cached portable Python: {tarball_path}[/dim]")

        # 2. Extract into portable_dir/python/. Tarball's top-level dir is "python".
        python_dir = portable_dir / "python"
        if python_dir.exists():
            shutil.rmtree(python_dir)
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(portable_dir)

        # 3. Strip .pdb debug symbols (cuts ~80MB).
        for pdb in python_dir.rglob("*.pdb"):
            pdb.unlink()

        # 3b. Prune runtime bloat we never use in a headless credential-process.
        # Removes ~50MB and ~2000 files; extract time on Windows is dominated by
        # file count, so this is the main lever (not size).
        #   * tcl/, Lib/tkinter, Lib/idlelib + _tkinter/tcl DLLs  — no GUI
        #   * Lib/ensurepip — we vendor wheels at build time
        #   * every __pycache__/ — regenerated lazily on first import
        self._prune_windows_runtime(python_dir)

        # 4. Install vendored Windows wheels into python/Lib/site-packages.
        site_packages = python_dir / "Lib" / "site-packages"
        console.print("[dim]Installing vendored Windows wheels (boto3, keyring, pyjwt, requests)...[/dim]")
        pip_cmd = [
            "python3",
            "-m",
            "pip",
            "install",
            "--target",
            str(site_packages),
            "--platform",
            "win_amd64",
            "--python-version",
            "3.12",
            "--only-binary=:all:",
            "--implementation",
            "cp",
            "--quiet",
            *self.WINDOWS_PYTHON_DEPS,
        ]
        result = subprocess.run(pip_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"pip install for Windows wheels failed:\n{result.stderr}")

        # 4b. Remove pip itself and its dist-info — we only needed it to install
        # deps, credential-process never calls pip. Also remove __pycache__ dirs
        # that pip just created.
        for name in list((python_dir / "Lib" / "site-packages").iterdir()):
            if name.name == "pip" or name.name.startswith("pip-"):
                if name.is_dir():
                    shutil.rmtree(name)
                else:
                    name.unlink()
        for cache in python_dir.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)

        # 5. Copy credential_provider source (strip __pycache__).
        src_cp = Path(__file__).parent.parent.parent.parent / "credential_provider"
        dst_cp = portable_dir / "credential_provider"
        if dst_cp.exists():
            shutil.rmtree(dst_cp)
        shutil.copytree(src_cp, dst_cp, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

        # 6. Write wrapper and installer scripts (all ASCII for PS 5.x compat).
        (portable_dir / "credential-process.cmd").write_text(
            "@echo off\r\n"
            '"%~dp0python\\python.exe" "%~dp0credential_provider\\__main__.py" %*\r\n',
            encoding="ascii",
        )
        (portable_dir / "install.ps1").write_text(_WINDOWS_INSTALL_PS1, encoding="ascii")
        (portable_dir / "install.bat").write_text(_WINDOWS_INSTALL_BAT, encoding="ascii")

        console.print("[green]OK Windows portable package assembled[/green]")
        return portable_dir / "credential-process.cmd"

    def _prune_windows_runtime(self, python_dir: Path) -> None:
        """Remove PBS runtime components that credential-process never imports."""
        import shutil as _sh

        for rel in ("tcl", "Lib/tkinter", "Lib/idlelib", "Lib/ensurepip"):
            p = python_dir / rel
            if p.exists():
                _sh.rmtree(p)
        for dll_name in ("_tkinter.pyd", "tcl86t.dll", "tk86t.dll"):
            p = python_dir / "DLLs" / dll_name
            if p.exists():
                p.unlink()
        for cache in python_dir.rglob("__pycache__"):
            _sh.rmtree(cache, ignore_errors=True)

    # POSIX installer script. Bundled into each {platform}-portable/; merges
    # claude-settings/settings.json into ~/.claude/settings.json and registers
    # the credential-process wrapper in ~/.aws/config for every profile.
    _POSIX_INSTALL_SH = r"""#!/bin/bash
# Install Claude Code with Amazon Bedrock (portable Python build) on macOS/Linux.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$HOME/claude-code-with-bedrock"

echo "==> Installing to $INSTALL_DIR"

# 1. Payload check
for item in python credential_provider credential-process config.json; do
    if [ ! -e "$SCRIPT_DIR/$item" ]; then
        echo "Missing payload item: $item (run install.sh from inside extracted package)" >&2
        exit 1
    fi
done

# 2. Copy files
mkdir -p "$INSTALL_DIR"
for item in python credential_provider credential-process config.json; do
    rm -rf "$INSTALL_DIR/$item"
    cp -R "$SCRIPT_DIR/$item" "$INSTALL_DIR/$item"
done
chmod +x "$INSTALL_DIR/credential-process"
chmod +x "$INSTALL_DIR/python/bin/python3" 2>/dev/null || true

# macOS: strip quarantine attribute so Gatekeeper doesn't prompt on every launch.
if [ "$(uname -s)" = "Darwin" ]; then
    xattr -dr com.apple.quarantine "$INSTALL_DIR" 2>/dev/null || true
fi

echo "    Files copied."

# 3. Merge Claude Code settings template
TEMPLATE="$SCRIPT_DIR/claude-settings/settings.json"
if [ -f "$TEMPLATE" ]; then
    echo "==> Merging Claude Code settings"
    mkdir -p "$HOME/.claude"
    SETTINGS="$HOME/.claude/settings.json"
    if [ -f "$SETTINGS" ]; then
        BACKUP="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
        cp "$SETTINGS" "$BACKUP"
        echo "    Backed up existing settings.json -> $BACKUP"
    fi
    CRED_PATH="$INSTALL_DIR/credential-process"
    OTEL_PATH="$INSTALL_DIR/otel-helper"
    "$INSTALL_DIR/python/bin/python3" - "$TEMPLATE" "$SETTINGS" "$CRED_PATH" "$OTEL_PATH" <<'PY'
import json, sys, os
tpl_path, out_path, cred_path, otel_path = sys.argv[1:5]
with open(tpl_path) as f:
    raw = f.read()
raw = raw.replace("__CREDENTIAL_PROCESS_PATH__", cred_path)
raw = raw.replace("__OTEL_HELPER_PATH__", otel_path)
tpl = json.loads(raw)
if tpl.get("otelHeadersHelper") == otel_path and not os.path.exists(otel_path):
    # OTEL helper not bundled; drop the key rather than point at a missing file.
    tpl.pop("otelHeadersHelper", None)
try:
    with open(out_path) as f:
        existing = json.load(f)
except (FileNotFoundError, ValueError):
    existing = {}
merged = dict(existing)
for key, value in tpl.items():
    if key == "env" and isinstance(existing.get("env"), dict) and isinstance(value, dict):
        merged["env"] = {**existing["env"], **value}
    else:
        merged[key] = value
with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
PY
    echo "    Updated $SETTINGS"
fi

# 4. Install OTEL helper if bundled
if [ -f "$SCRIPT_DIR/otel_helper/__main__.py" ]; then
    echo "==> Installing OTEL helper"
    rm -rf "$INSTALL_DIR/otel_helper"
    cp -R "$SCRIPT_DIR/otel_helper" "$INSTALL_DIR/otel_helper"
    cat > "$INSTALL_DIR/otel-helper" <<EOF
#!/bin/bash
exec "$INSTALL_DIR/python/bin/python3" "$INSTALL_DIR/otel_helper/__main__.py" "\$@"
EOF
    chmod +x "$INSTALL_DIR/otel-helper"
fi

# 5. Register AWS profiles from config.json
echo "==> Configuring AWS profiles"
mkdir -p "$HOME/.aws"
[ -f "$HOME/.aws/config" ] && cp "$HOME/.aws/config" "$HOME/.aws/config.bak"
"$INSTALL_DIR/python/bin/python3" - "$INSTALL_DIR/config.json" "$INSTALL_DIR/credential-process" <<'PY'
import configparser, json, os, sys
cfg_path, cred_path = sys.argv[1:3]
with open(cfg_path) as f:
    profiles = json.load(f)
aws_cfg = os.path.expanduser("~/.aws/config")
c = configparser.RawConfigParser()
c.read(aws_cfg)
for name, data in profiles.items():
    section = f"profile {name}"
    if not c.has_section(section):
        c.add_section(section)
    c.set(section, "credential_process", f"{cred_path} --profile {name}")
    c.set(section, "region", data.get("aws_region", ""))
with open(aws_cfg, "w") as f:
    c.write(f)
print("    Registered profiles:", ", ".join(profiles))
PY

echo ""
echo "==> Done."
echo "    Install path: $INSTALL_DIR"
echo ""
echo "Next: run 'claude' in a new shell to trigger first login."
"""

    def _build_posix_portable_python(self, output_dir: Path, target_platform: str) -> Path:
        """Assemble a macOS/Linux distribution using portable Python + vendored deps.

        Produces output_dir/{target_platform}-portable/ with the same shape as
        the Windows bundle: python/ runtime, credential_provider/ source,
        credential-process wrapper, and install.sh. Returns the path to the
        credential-process wrapper.
        """
        import shutil
        import tarfile
        import urllib.request

        console = Console()

        url = self.POSIX_PYTHON_URLS[target_platform]
        pip_platforms = self.POSIX_PIP_PLATFORMS[target_platform]
        portable_dir = output_dir / f"{target_platform}-portable"
        portable_dir.mkdir(parents=True, exist_ok=True)

        # 1. Fetch (or reuse cached) tarball. python-build-standalone uses URL-encoded "+".
        cache_dir = Path.home() / ".ccwb" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        tarball_name = url.rsplit("/", 1)[-1]
        tarball_path = cache_dir / tarball_name
        if not tarball_path.exists():
            console.print(f"[dim]Downloading portable Python: {tarball_name}[/dim]")
            urllib.request.urlretrieve(url, tarball_path)
        else:
            console.print(f"[dim]Using cached portable Python: {tarball_path}[/dim]")

        # 2. Extract into portable_dir/python/. Tarball top-level dir is "python".
        #    Skip share/terminfo/ entries: ncurses ships case-conflicting names
        #    (e.g. N/ncr... vs n/ncr...) that collide on macOS's case-insensitive
        #    APFS via symlinks, and the credential-process doesn't need terminfo.
        python_dir = portable_dir / "python"
        if python_dir.exists():
            shutil.rmtree(python_dir)

        def _not_terminfo(member: tarfile.TarInfo, _dest_path: str) -> tarfile.TarInfo | None:
            if "share/terminfo" in member.name:
                return None
            return member

        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(portable_dir, filter=_not_terminfo)

        # 3. Linux-only: strip debug_info. PBS ships Linux ELFs unstripped
        #    (libpython alone is ~200MB of debug symbols); macOS dylibs are
        #    already stripped upstream. Needs GNU strip since BSD strip doesn't
        #    grok ELF; on macOS we use Homebrew binutils.
        if target_platform.startswith("linux"):
            self._strip_linux_elves(python_dir)

        # 4. Install vendored wheels into the bundle's site-packages.
        site_packages = python_dir / "lib" / f"python{self._PBS_VERSION.rsplit('.', 1)[0]}" / "site-packages"
        if not site_packages.exists():
            # python-build-standalone sometimes nests under lib/pythonX.Y/; fall back by probing.
            candidates = list((python_dir / "lib").glob("python3.*/site-packages"))
            if not candidates:
                raise RuntimeError(f"Could not locate site-packages under {python_dir / 'lib'}")
            site_packages = candidates[0]

        console.print(
            f"[dim]Installing vendored wheels for {target_platform} "
            f"({', '.join(self.POSIX_PYTHON_DEPS)})...[/dim]"
        )
        pip_cmd = [
            "python3",
            "-m",
            "pip",
            "install",
            "--target",
            str(site_packages),
            "--python-version",
            self._PBS_VERSION.rsplit(".", 1)[0],
            "--only-binary=:all:",
            "--implementation",
            "cp",
            "--quiet",
        ]
        for tag in pip_platforms:
            pip_cmd.extend(["--platform", tag])
        pip_cmd.extend(self.POSIX_PYTHON_DEPS)
        result = subprocess.run(pip_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"pip install for {target_platform} wheels failed:\n{result.stderr}")

        # 5. Copy credential_provider source (strip __pycache__).
        src_cp = Path(__file__).parent.parent.parent.parent / "credential_provider"
        dst_cp = portable_dir / "credential_provider"
        if dst_cp.exists():
            shutil.rmtree(dst_cp)
        shutil.copytree(src_cp, dst_cp, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

        # 6. Write shell wrapper + install.sh. Wrapper uses $(dirname) so it works
        #    from any location once installed.
        wrapper = portable_dir / "credential-process"
        wrapper.write_text(
            "#!/bin/bash\n"
            'DIR="$(cd "$(dirname "$0")" && pwd)"\n'
            'exec "$DIR/python/bin/python3" "$DIR/credential_provider/__main__.py" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        install_sh = portable_dir / "install.sh"
        install_sh.write_text(self._POSIX_INSTALL_SH, encoding="utf-8")
        install_sh.chmod(0o755)

        console.print(f"[green]OK {target_platform} portable package assembled[/green]")
        return wrapper

    def _strip_linux_elves(self, python_dir: Path) -> None:
        """Strip debug_info from PBS Linux ELFs (libpython, python3.X, *.so).

        Needs GNU strip: BSD strip (/usr/bin/strip on macOS) can't parse ELF.
        On macOS we look for Homebrew binutils; on Linux the system strip works.
        If no suitable strip is found, we warn and leave debug symbols in place.
        """
        import shutil as _shutil

        strip_bin = None
        for candidate in (
            "/opt/homebrew/opt/binutils/bin/strip",  # macOS arm64 Homebrew
            "/usr/local/opt/binutils/bin/strip",  # macOS intel Homebrew
        ):
            if Path(candidate).exists():
                strip_bin = candidate
                break
        if strip_bin is None:
            strip_bin = _shutil.which("strip")
        if strip_bin is None:
            Console().print(
                "[yellow]Warning: strip not found; Linux bundle will include debug symbols "
                "(~3x larger). Install GNU binutils for smaller bundles.[/yellow]"
            )
            return

        # python-build-standalone ELFs: the interpreter, libpython, and every
        # C extension under lib-dynload/ and site-packages/. strip is idempotent
        # so over-including is harmless; under-including leaves bloat behind.
        targets = [
            python_dir / "bin" / f"python{self._PBS_VERSION.rsplit('.', 1)[0]}",
        ]
        targets.extend(python_dir.rglob("*.so"))
        targets.extend(python_dir.rglob("*.so.*"))
        for target in targets:
            if not target.is_file() or target.is_symlink():
                continue
            subprocess.run(
                [strip_bin, "--strip-unneeded", str(target)],
                capture_output=True,
                text=True,
            )

    # Floor Python version for the slim bundle. Chosen to cover Amazon Linux
    # 2023 (3.9), RHEL 9 (3.9), Debian 11 (3.9), Ubuntu 22.04 (3.10), and
    # every distro newer than those. credential_provider has `from __future__
    # import annotations` so its `X | None` annotations stay 3.9-safe.
    _SLIM_PYTHON_VERSION = "3.9"
    SLIM_PIP_PLATFORMS = {
        "linux-x64": ["manylinux_2_17_x86_64", "manylinux2014_x86_64"],
        "linux-arm64": ["manylinux_2_17_aarch64", "manylinux2014_aarch64"],
    }
    # pip --python-version picks wheels for the target, but env-markers still
    # evaluate against the *host* interpreter. Running from py3.12+, pip skips
    # deps gated on `python_version < "3.x"`, so fallback imports quietly
    # disappear. Pin each one explicitly:
    #   - backports.tarfile, importlib_metadata: keyring's py<3.12 fallbacks
    #   - typing_extensions: pyjwt imports `typing_extensions.Never` on py<3.11
    # We skip `cryptography` because credential_provider only uses
    # jwt.decode(..., options={"verify_signature": False}).
    SLIM_PYTHON_DEPS = [
        "boto3",
        "keyring",
        "pyjwt",
        "requests",
        "backports.tarfile",
        "importlib_metadata",
        "typing_extensions",
    ]

    # Slim installer. Discovers a system python3 (>= 3.9), verifies it, then
    # writes a wrapper that execs `python3 -m credential_provider` with
    # PYTHONPATH pointing at the vendored site-packages.
    _SLIM_INSTALL_SH = r"""#!/bin/bash
# Install Claude Code with Amazon Bedrock (slim bundle, uses system Python 3.9+).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$HOME/claude-code-with-bedrock"

echo "==> Installing to $INSTALL_DIR"

# 1. Payload check
for item in site-packages credential_provider credential-process config.json; do
    if [ ! -e "$SCRIPT_DIR/$item" ]; then
        echo "Missing payload item: $item (run install.sh from inside extracted package)" >&2
        exit 1
    fi
done

# 2. Find a system Python >= 3.9
find_python() {
    for candidate in python3 python3.12 python3.11 python3.10 python3.9; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}
PYTHON_BIN="$(find_python)" || {
    echo "" >&2
    echo "ERROR: No Python 3.9+ found on PATH." >&2
    echo "  Install python3 from your package manager, or use the portable bundle instead." >&2
    exit 1
}
echo "    Using: $PYTHON_BIN ($("$PYTHON_BIN" --version 2>&1))"

# 3. Copy files
mkdir -p "$INSTALL_DIR"
for item in site-packages credential_provider credential-process config.json; do
    rm -rf "$INSTALL_DIR/$item"
    cp -R "$SCRIPT_DIR/$item" "$INSTALL_DIR/$item"
done

# Rewrite the credential-process wrapper to bake in the discovered python3
# path and the install dir, so it's relocatable-by-copy within this host.
cat > "$INSTALL_DIR/credential-process" <<EOF
#!/bin/bash
DIR="$INSTALL_DIR"
export PYTHONPATH="\$DIR/site-packages\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$PYTHON_BIN" "\$DIR/credential_provider/__main__.py" "\$@"
EOF
chmod +x "$INSTALL_DIR/credential-process"
echo "    Files copied."

# 4. Merge Claude Code settings template
TEMPLATE="$SCRIPT_DIR/claude-settings/settings.json"
if [ -f "$TEMPLATE" ]; then
    echo "==> Merging Claude Code settings"
    mkdir -p "$HOME/.claude"
    SETTINGS="$HOME/.claude/settings.json"
    if [ -f "$SETTINGS" ]; then
        BACKUP="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
        cp "$SETTINGS" "$BACKUP"
        echo "    Backed up existing settings.json -> $BACKUP"
    fi
    CRED_PATH="$INSTALL_DIR/credential-process"
    OTEL_PATH="$INSTALL_DIR/otel-helper"
    "$PYTHON_BIN" - "$TEMPLATE" "$SETTINGS" "$CRED_PATH" "$OTEL_PATH" <<'PY'
import json, sys, os
tpl_path, out_path, cred_path, otel_path = sys.argv[1:5]
with open(tpl_path) as f:
    raw = f.read()
raw = raw.replace("__CREDENTIAL_PROCESS_PATH__", cred_path)
raw = raw.replace("__OTEL_HELPER_PATH__", otel_path)
tpl = json.loads(raw)
if tpl.get("otelHeadersHelper") == otel_path and not os.path.exists(otel_path):
    tpl.pop("otelHeadersHelper", None)
try:
    with open(out_path) as f:
        existing = json.load(f)
except (FileNotFoundError, ValueError):
    existing = {}
merged = dict(existing)
for key, value in tpl.items():
    if key == "env" and isinstance(existing.get("env"), dict) and isinstance(value, dict):
        merged["env"] = {**existing["env"], **value}
    else:
        merged[key] = value
with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
PY
    echo "    Updated $SETTINGS"
fi

# 5. Install OTEL helper if bundled
if [ -f "$SCRIPT_DIR/otel_helper/__main__.py" ]; then
    echo "==> Installing OTEL helper"
    rm -rf "$INSTALL_DIR/otel_helper"
    cp -R "$SCRIPT_DIR/otel_helper" "$INSTALL_DIR/otel_helper"
    cat > "$INSTALL_DIR/otel-helper" <<EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR/site-packages\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$PYTHON_BIN" "$INSTALL_DIR/otel_helper/__main__.py" "\$@"
EOF
    chmod +x "$INSTALL_DIR/otel-helper"
fi

# 6. Register AWS profiles from config.json
echo "==> Configuring AWS profiles"
mkdir -p "$HOME/.aws"
[ -f "$HOME/.aws/config" ] && cp "$HOME/.aws/config" "$HOME/.aws/config.bak"
"$PYTHON_BIN" - "$INSTALL_DIR/config.json" "$INSTALL_DIR/credential-process" <<'PY'
import configparser, json, os, sys
cfg_path, cred_path = sys.argv[1:3]
with open(cfg_path) as f:
    profiles = json.load(f)
aws_cfg = os.path.expanduser("~/.aws/config")
c = configparser.RawConfigParser()
c.read(aws_cfg)
for name, data in profiles.items():
    section = f"profile {name}"
    if not c.has_section(section):
        c.add_section(section)
    c.set(section, "credential_process", f"{cred_path} --profile {name}")
    c.set(section, "region", data.get("aws_region", ""))
with open(aws_cfg, "w") as f:
    c.write(f)
print("    Registered profiles:", ", ".join(profiles))
PY

echo ""
echo "==> Done."
echo "    Install path: $INSTALL_DIR"
echo ""
echo "Next: run 'claude' in a new shell to trigger first login."
"""

    def _build_linux_slim(self, output_dir: Path, target_platform: str) -> Path:
        """Assemble a ~25MB Linux bundle that reuses the user's system Python 3.9+.

        Produces output_dir/{target_platform}-slim/ containing:
          site-packages/        - vendored wheels (boto3, keyring, pyjwt, requests)
          credential_provider/  - source .py files
          credential-process    - shell wrapper (patched by install.sh)
          install.sh            - discovers python3 >=3.9 and wires things up

        Returns the path to the credential-process wrapper.
        """
        import shutil

        console = Console()

        if target_platform not in self.SLIM_PIP_PLATFORMS:
            raise ValueError(f"--slim does not support {target_platform} (Linux only).")

        slim_dir = output_dir / f"{target_platform}-slim"
        slim_dir.mkdir(parents=True, exist_ok=True)

        site_packages = slim_dir / "site-packages"
        if site_packages.exists():
            shutil.rmtree(site_packages)
        site_packages.mkdir()

        # 1. Install vendored wheels targeting Python 3.9 + manylinux tags.
        #    --python-version=3.9 gets us the abi3 wheel where available, so the
        #    same bundle runs on 3.10/3.11/3.12 too.
        console.print(
            f"[dim]Installing vendored wheels for {target_platform} slim "
            f"({', '.join(self.SLIM_PYTHON_DEPS)}, py{self._SLIM_PYTHON_VERSION}+)...[/dim]"
        )
        pip_cmd = [
            "python3",
            "-m",
            "pip",
            "install",
            "--target",
            str(site_packages),
            "--python-version",
            self._SLIM_PYTHON_VERSION,
            "--only-binary=:all:",
            "--implementation",
            "cp",
            "--quiet",
        ]
        for tag in self.SLIM_PIP_PLATFORMS[target_platform]:
            pip_cmd.extend(["--platform", tag])
        pip_cmd.extend(self.SLIM_PYTHON_DEPS)
        result = subprocess.run(pip_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"pip install for {target_platform} slim wheels failed:\n{result.stderr}")

        # 2. Drop extras we don't need. *.dist-info/ stays (keyring reads entry
        #    points from it), but we can trim __pycache__ and the pip/setuptools
        #    vendor trees that --target sometimes drags in.
        for cache in site_packages.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        for drop in ("pip", "pip-*.dist-info", "setuptools", "setuptools-*.dist-info", "_distutils_hack"):
            for match in site_packages.glob(drop):
                if match.is_dir():
                    shutil.rmtree(match, ignore_errors=True)
                else:
                    match.unlink(missing_ok=True)

        # 3. Copy credential_provider source (strip __pycache__).
        src_cp = Path(__file__).parent.parent.parent.parent / "credential_provider"
        dst_cp = slim_dir / "credential_provider"
        if dst_cp.exists():
            shutil.rmtree(dst_cp)
        shutil.copytree(src_cp, dst_cp, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

        # 4. Placeholder wrapper. install.sh rewrites this to bake in the
        #    discovered python3 path; the staged copy here is just a sentinel
        #    so the payload check in install.sh finds all expected items.
        wrapper = slim_dir / "credential-process"
        wrapper.write_text(
            "#!/bin/bash\n"
            '# Rewritten by install.sh with the discovered system python3.\n'
            'echo "run install.sh first to wire this bundle to your system Python." >&2\n'
            'exit 1\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        install_sh = slim_dir / "install.sh"
        install_sh.write_text(self._SLIM_INSTALL_SH, encoding="utf-8")
        install_sh.chmod(0o755)

        console.print(f"[green]OK {target_platform} slim package assembled[/green]")
        return wrapper

    def _finalize_posix_portable(
        self, output_dir: Path, target_platform: str, include_otel: bool, slim: bool = False
    ) -> None:
        """Copy config.json, claude-settings/, and optional otel_helper/ into the
        {platform}-portable/ (or -slim/) bundle so install.sh finds them beside itself.
        """
        import shutil

        suffix = "-slim" if slim else "-portable"
        portable_dir = output_dir / f"{target_platform}{suffix}"
        if not portable_dir.exists():
            return

        config_src = output_dir / "config.json"
        if config_src.exists():
            shutil.copy2(config_src, portable_dir / "config.json")

        settings_src = output_dir / "claude-settings" / "settings.json"
        if settings_src.exists():
            settings_dst_dir = portable_dir / "claude-settings"
            settings_dst_dir.mkdir(exist_ok=True)
            shutil.copy2(settings_src, settings_dst_dir / "settings.json")

        if include_otel:
            src_oh = Path(__file__).parent.parent.parent.parent / "otel_helper"
            dst_oh = portable_dir / "otel_helper"
            if src_oh.exists():
                if dst_oh.exists():
                    shutil.rmtree(dst_oh)
                shutil.copytree(src_oh, dst_oh, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sh"))

    def _finalize_windows_portable(self, output_dir: Path) -> None:
        """Copy config.json and claude-settings/ into windows-portable/ so the
        installer can find them via %~dp0. Called after _create_config() and
        _create_claude_settings() have run.
        """
        import shutil

        portable_dir = output_dir / "windows-portable"
        if not portable_dir.exists():
            return

        config_src = output_dir / "config.json"
        if config_src.exists():
            shutil.copy2(config_src, portable_dir / "config.json")

        settings_src = output_dir / "claude-settings" / "settings.json"
        if settings_src.exists():
            settings_dst_dir = portable_dir / "claude-settings"
            settings_dst_dir.mkdir(exist_ok=True)
            shutil.copy2(settings_src, settings_dst_dir / "settings.json")

    def _create_config(
        self,
        output_dir: Path,
        profile,
        federation_identifier: str,
        federation_type: str = "cognito",
        profile_name: str = "ClaudeCode",
        otel_helper_hashes: dict | None = None,
    ) -> Path:
        """Create the configuration file.

        Args:
            output_dir: Directory to write config.json to
            profile: Profile object with configuration
            federation_identifier: Identity pool ID or role ARN
            federation_type: "cognito" or "direct"
            profile_name: Name to use as key in config.json (defaults to "ClaudeCode" for backward compatibility)
            otel_helper_hashes: Per-platform SHA256 hashes, e.g. {"macos-arm64": "abc...", "windows": "def..."}
        """
        profile_data = {
            "provider_domain": profile.provider_domain,
            "client_id": profile.client_id,
            "aws_region": profile.aws_region,
            "provider_type": profile.provider_type or self._detect_provider_type(profile.provider_domain),
            "credential_storage": profile.credential_storage,
            "cross_region_profile": profile.cross_region_profile or "us",
        }

        # Include client_secret if configured (for confidential OIDC clients)
        if profile.client_secret:
            profile_data["client_secret"] = profile.client_secret

        config = {profile_name: profile_data}

        # Add the appropriate federation field based on type
        if federation_type == "direct":
            config[profile_name]["federated_role_arn"] = federation_identifier
            config[profile_name]["federation_type"] = "direct"
            config[profile_name]["max_session_duration"] = profile.max_session_duration
        else:
            config[profile_name]["identity_pool_id"] = federation_identifier
            config[profile_name]["federation_type"] = "cognito"

        # Add cognito_user_pool_id if it's a Cognito provider
        if profile.provider_type == "cognito" and profile.cognito_user_pool_id:
            config[profile_name]["cognito_user_pool_id"] = profile.cognito_user_pool_id

        # Add selected_model if available
        if hasattr(profile, "selected_model") and profile.selected_model:
            config[profile_name]["selected_model"] = profile.selected_model

        # Add TVM endpoint if quota monitoring is enabled
        if hasattr(profile, 'tvm_endpoint') and profile.tvm_endpoint:
            config[profile_name]["tvm_endpoint"] = profile.tvm_endpoint
        if hasattr(profile, 'tvm_request_timeout') and profile.tvm_request_timeout:
            config[profile_name]["tvm_request_timeout"] = profile.tvm_request_timeout

        # Add otel-helper hashes for integrity verification (per-platform)
        if otel_helper_hashes:
            config[profile_name]["otel_helper_hashes"] = otel_helper_hashes

        config_path = output_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        return config_path

    def _get_bedrock_region_for_profile(self, profile) -> str:
        """Get the correct AWS region for Bedrock API calls based on user-selected source region."""
        return get_source_region_for_profile(profile)

    def _detect_provider_type(self, domain: str) -> str:
        """Auto-detect provider type from domain."""
        from urllib.parse import urlparse

        if not domain:
            return "oidc"

        # Handle both full URLs and domain-only inputs
        url_to_parse = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"

        try:
            parsed = urlparse(url_to_parse)
            hostname = parsed.hostname

            if not hostname:
                return "oidc"

            hostname_lower = hostname.lower()

            # Check for exact domain match or subdomain match
            # Using endswith with leading dot prevents bypass attacks
            if hostname_lower.endswith(".okta.com") or hostname_lower == "okta.com":
                return "okta"
            elif hostname_lower.endswith(".auth0.com") or hostname_lower == "auth0.com":
                return "auth0"
            elif hostname_lower.endswith(".microsoftonline.com") or hostname_lower == "microsoftonline.com":
                return "azure"
            elif hostname_lower.endswith(".windows.net") or hostname_lower == "windows.net":
                return "azure"
            elif hostname_lower.endswith(".amazoncognito.com") or hostname_lower == "amazoncognito.com":
                return "cognito"
            else:
                return "oidc"  # Default to generic OIDC
        except Exception:
            return "oidc"  # Default to generic OIDC on parsing error

    def _create_documentation(self, output_dir: Path, profile, timestamp: str):
        """Create user documentation."""
        readme_content = f"""# Claude Code Authentication Setup

## Quick Start

### macOS/Linux

1. Extract the package:
   ```bash
   unzip claude-code-package-*.zip
   cd claude-code-package
   ```

2. Run the installer:
   ```bash
   ./install.sh
   ```

3. Use the AWS profile:
   ```bash
   export AWS_PROFILE=ClaudeCode
   aws sts get-caller-identity
   ```

### Windows

#### Step 1: Download the Package
```powershell
# Use the Invoke-WebRequest command provided by your IT administrator
Invoke-WebRequest -Uri "URL_PROVIDED" -OutFile "claude-code-package.zip"
```

#### Step 2: Extract the Package

**Option A: Using Windows Explorer**
1. Right-click on `claude-code-package.zip`
2. Select "Extract All..."
3. Choose a destination folder
4. Click "Extract"

**Option B: Using PowerShell**
```powershell
# Extract to current directory
Expand-Archive -Path "claude-code-package.zip" -DestinationPath "claude-code-package"

# Navigate to the extracted folder
cd claude-code-package
```

**Option C: Using Command Prompt**
```cmd
# If you have tar available (Windows 10 1803+)
tar -xf claude-code-package.zip

# Or use PowerShell from Command Prompt
powershell -command "Expand-Archive -Path 'claude-code-package.zip' -DestinationPath 'claude-code-package'"

cd claude-code-package
```

#### Step 3: Run the Installer
```cmd
install.bat
```

The installer will:
- Check for AWS CLI installation
- Copy authentication tools to `%USERPROFILE%\\claude-code-with-bedrock`
- Configure the AWS profile "ClaudeCode"
- Test the authentication

#### Step 4: Use Claude Code
```cmd
# Set the AWS profile
set AWS_PROFILE=ClaudeCode

# Verify authentication works
aws sts get-caller-identity

# Your browser will open automatically for authentication if needed
```

For PowerShell users:
```powershell
$env:AWS_PROFILE = "ClaudeCode"
aws sts get-caller-identity
```

## What This Does

- Installs the Claude Code authentication tools
- Configures your AWS CLI to use {profile.provider_domain} for authentication
- Sets up automatic credential refresh via your browser

## Requirements

- Python 3.8 or later
- AWS CLI v2
- pip3

## Troubleshooting

### macOS Keychain Access Popup
On first use, macOS will ask for permission to access the keychain. This is normal and required for \
secure credential storage. Click "Always Allow" to avoid repeated prompts.

### Authentication Issues
If you encounter issues with authentication:
- Ensure you're assigned to the Claude Code application in your identity provider
- Check that port 8400 is available for the callback
- Contact your IT administrator for help

### Authentication Behavior

The system handles authentication automatically:
- Your browser will open when authentication is needed
- Credentials are cached securely to avoid repeated logins
- Bad credentials are automatically cleared and re-authenticated

To manually clear cached credentials (if needed):
```bash
~/claude-code-with-bedrock/credential-process --clear-cache
```

This will force re-authentication on your next AWS command.

### Browser doesn't open
Check that you're not in an SSH session. The browser needs to open on your local machine.

## Support

Contact your IT administrator for help.

Configuration Details:
- Organization: {profile.provider_domain}
- Region: {profile.aws_region}
- Package Version: {timestamp}"""

        # Add analytics information if enabled
        if profile.monitoring_enabled and getattr(profile, "analytics_enabled", True):
            analytics_section = f"""

## Analytics Dashboard

Your organization has enabled advanced analytics for Claude Code usage. You can access detailed metrics \
and reports through AWS Athena.

To view analytics:
1. Open the AWS Console in region {profile.aws_region}
2. Navigate to Athena
3. Select the analytics workgroup and database
4. Run pre-built queries or create custom reports

Available metrics include:
- Token usage by user
- Cost allocation
- Model usage patterns
- Activity trends
"""
            readme_content += analytics_section

        readme_content += "\n" ""

        with open(output_dir / "README.md", "w") as f:
            f.write(readme_content)

    def _create_claude_settings(
        self, output_dir: Path, profile, include_coauthored_by: bool = True, profile_name: str = "ClaudeCode"
    ):
        """Create Claude Code settings.json with Bedrock and optional monitoring configuration."""
        console = Console()

        try:
            # Create claude-settings directory (visible, not hidden)
            claude_dir = output_dir / "claude-settings"
            claude_dir.mkdir(exist_ok=True)

            # Start with basic settings required for Bedrock
            settings = {
                "env": {
                    # Set AWS_REGION based on cross-region profile for correct Bedrock endpoint
                    "AWS_REGION": self._get_bedrock_region_for_profile(profile),
                    "CLAUDE_CODE_USE_BEDROCK": "1",
                    # AWS_PROFILE is used by both AWS SDK and otel-helper
                    "AWS_PROFILE": profile_name,
                }
            }

            # Add includeCoAuthoredBy setting if user wants to disable it (Claude Code defaults to true)
            # Only add the field if the user wants it disabled
            if not include_coauthored_by:
                settings["includeCoAuthoredBy"] = False

            # Add awsAuthRefresh for session-based credential storage
            if profile.credential_storage == "session":
                settings["awsAuthRefresh"] = f"__CREDENTIAL_PROCESS_PATH__ --profile {profile_name}"

            # Add selected model as environment variable if available
            if hasattr(profile, "selected_model") and profile.selected_model:
                settings["env"]["ANTHROPIC_MODEL"] = profile.selected_model

                # Determine and set small/fast model based on selected model family
                if "opus" in profile.selected_model:
                    # For Opus, use Haiku as small/fast model
                    model_id = profile.selected_model
                    prefix = model_id.split(".anthropic")[0]  # Get us/eu/apac prefix
                    settings["env"]["ANTHROPIC_SMALL_FAST_MODEL"] = f"{prefix}.anthropic.claude-3-5-haiku-20241022-v1:0"
                else:
                    # For other models, use same model as small/fast (or could use Haiku)
                    settings["env"]["ANTHROPIC_SMALL_FAST_MODEL"] = profile.selected_model

            # If monitoring is enabled, add telemetry configuration
            if profile.monitoring_enabled:
                # Get monitoring stack outputs
                monitoring_stack = profile.stack_names.get("monitoring", f"{profile.identity_pool_name}-otel-collector")
                cmd = [
                    "aws",
                    "cloudformation",
                    "describe-stacks",
                    "--stack-name",
                    monitoring_stack,
                    "--region",
                    profile.aws_region,
                    "--query",
                    "Stacks[0].Outputs",
                    "--output",
                    "json",
                ]

                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    outputs = json.loads(result.stdout)
                    endpoint = None

                    for output in outputs:
                        if output["OutputKey"] == "CollectorEndpoint":
                            endpoint = output["OutputValue"]
                            break

                    if endpoint:
                        # Add monitoring configuration
                        settings["env"].update(
                            {
                                "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
                                "OTEL_METRICS_EXPORTER": "otlp",
                                "OTEL_LOGS_EXPORTER": "otlp",
                                "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
                                "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
                                # Add basic OTEL resource attributes for multi-team support
                                "OTEL_RESOURCE_ATTRIBUTES": "department=engineering,team.id=default, \
                                cost_center=default,organization=default",
                            }
                        )

                        # Add the helper executable for generating OTEL headers with user attributes
                        # Use a placeholder that will be replaced by the installer script based on platform
                        settings["otelHeadersHelper"] = "__OTEL_HELPER_PATH__"

                        is_https = endpoint.startswith("https://")
                        console.print(f"[dim]Added monitoring with {'HTTPS' if is_https else 'HTTP'} endpoint[/dim]")
                        if not is_https:
                            console.print(
                                "[dim]WARNING: Using HTTP endpoint - consider enabling HTTPS for production[/dim]"
                            )
                    else:
                        console.print("[yellow]Warning: No monitoring endpoint found in stack outputs[/yellow]")
                else:
                    console.print("[yellow]Warning: Could not fetch monitoring stack outputs[/yellow]")

            # Save settings.json
            settings_path = claude_dir / "settings.json"
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)

            console.print("[dim]Created Claude Code settings for Bedrock configuration[/dim]")

        except Exception as e:
            console.print(f"[yellow]Warning: Could not create Claude Code settings: {e}[/yellow]")

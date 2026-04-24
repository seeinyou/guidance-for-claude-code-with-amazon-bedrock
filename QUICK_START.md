# Quick Start Guide

Complete deployment walkthrough for IT administrators deploying Claude Code with Amazon Bedrock.

**Time Required:** 2-3 hours for initial deployment
**Skill Level:** AWS administrator with IAM/CloudFormation experience

---

## Prerequisites

### Software Requirements

- Python 3.10-3.13
- Poetry (dependency management)
- AWS CLI v2
- Git

### AWS Requirements

- AWS account with appropriate IAM permissions to create:
  - CloudFormation stacks
  - IAM OIDC Providers or Cognito Identity Pools
  - IAM roles and policies
  - API Gateway, Lambda, SQS, DynamoDB, S3 (cost management stack)
  - (Optional) Amazon Elastic Container Service (Amazon ECS) tasks and Amazon CloudWatch dashboards
  - (Optional) Amazon Athena, AWS Glue, AWS Lambda, and Amazon Data Firehose resources
- Amazon Bedrock activated in target regions
- Bedrock Model Invocation Logging is enabled by the `quota` stack via a custom resource (creates an S3 bucket if one is not already configured)

### OIDC Provider Requirements

- Existing OIDC identity provider (Okta, Azure AD, Auth0, etc.)
- Ability to create OIDC applications
- Redirect URI support for `http://localhost:8400/callback`

### Supported AWS Regions

The guidance can be deployed in any AWS region that supports:

- IAM OIDC Providers or Amazon Cognito Identity Pools
- Amazon Bedrock
- API Gateway + Lambda + SQS + DynamoDB + S3 (cost management stack)
- (Optional) Amazon Elastic Container Service (Amazon ECS) tasks and Amazon CloudWatch dashboards
- (Optional) Amazon Athena, AWS Glue, AWS Lambda, and Amazon Data Firehose resources

### Cross-Region Inference

Claude Code uses Amazon Bedrock's cross-region inference for optimal performance and availability. During setup, you can:

- Select your preferred Claude model (Opus, Sonnet, Haiku)
- Choose a cross-region profile (US, Europe, APAC) for optimal regional routing
- Select a specific source region within your profile for model inference

This automatically routes requests across multiple AWS regions to ensure the best response times and highest availability. Modern Claude models (3.7+) require cross-region inference for access.

---

## Deployment Steps

### Step 1: Clone Repository and Install Dependencies

```bash
# Clone the repository
git clone https://github.com/aws-solutions-library-samples/guidance-for-claude-code-with-amazon-bedrock
cd guidance-for-claude-code-with-amazon-bedrock/source

# Install dependencies
poetry install
```

### Step 2: Initialize Configuration

Run the interactive setup wizard:

```bash
poetry run ccwb init
```

The wizard will guide you through:

- OIDC provider configuration (domain, client ID)
- AWS region selection for infrastructure
- Amazon Bedrock cross-region inference configuration
- Credential storage method (keyring or session files)
- Optional monitoring setup with VPC configuration

#### Understanding Profiles (v2.0+)

**What are profiles?** Profiles let you manage multiple deployments from one machine (different AWS accounts, regions, or organizations).

**Common use cases:**
- Production vs development accounts
- US vs EU regional deployments
- Multiple customer/tenant deployments

**Profile commands:**
- `ccwb context list` - See all profiles
- `ccwb context use <name>` - Switch between profiles
- `ccwb context show` - View active profile details

See [CLI Reference](assets/docs/CLI_REFERENCE.md) for complete command list.

**Upgrading from v1.x:** Profile configuration automatically migrates from `source/.ccwb-config/` to `~/.ccwb/` on first run. Your profile names and active profile are preserved. A timestamped backup is created automatically.

### Step 3: Deploy Infrastructure

Deploy the AWS CloudFormation stacks:

```bash
poetry run ccwb deploy
```

This creates the following AWS resources:

**Authentication Infrastructure:**

- IAM OIDC Provider or Amazon Cognito Identity Pool for OIDC federation
- IAM trust relationship for federated access
- IAM role with policies for:
  - Bedrock model invocation in specified regions
  - CloudWatch metrics (if monitoring enabled)

**Optional Monitoring Infrastructure:**

- VPC and networking resources (or integration with existing VPC)
- ECS Fargate cluster running OpenTelemetry collector
- Application Load Balancer for OTLP ingestion
- CloudWatch Log Groups and Metrics
- CloudWatch Dashboard with comprehensive usage analytics
- DynamoDB table for metrics aggregation and storage
- Lambda functions for custom dashboard widgets
- Kinesis Data Firehose for streaming metrics to S3 (if analytics enabled)
- Amazon Athena for SQL analytics on collected metrics (if analytics enabled)
- S3 bucket for long-term metrics storage (if analytics enabled)

### Step 4: Create Distribution Package

Build the package for end users. Each bundle is a portable Python install
(no end-user compiler, no Python dependency) produced from
[python-build-standalone](https://github.com/astral-sh/python-build-standalone).
Linux additionally has a **slim** variant that uses the user's system
Python 3.9+ for a ~30 MB download.

```bash
# Build every supported platform in one shot (default). Fully non-interactive.
poetry run ccwb package

# Pick a subset interactively (checkbox prompt)
poetry run ccwb package --pick

# Or build a single platform
poetry run ccwb package --target-platform=windows
poetry run ccwb package --target-platform=macos-arm64
poetry run ccwb package --target-platform=macos-intel
poetry run ccwb package --target-platform=linux-x64
poetry run ccwb package --target-platform=linux-arm64

# Linux slim variants (require system Python >= 3.9 on target machines)
poetry run ccwb package --target-platform=linux-x64 --slim
poetry run ccwb package --target-platform=linux-arm64 --slim

# Drop the otel_helper/ payload to shrink the bundle (OTLP still works, but
# CloudWatch metrics lose per-user attributes like email / team / cost_center)
poetry run ccwb package --target-platform=macos-arm64 --no-otel-helper

# Include 'Co-Authored-By: Claude' footer in end users' git commits.
# Default is off; the flag opts in. In non-interactive shells (CI, pipes)
# the prompt is skipped and this flag is the only way to turn it on.
poetry run ccwb package --co-authored-by

# Upload to landing page / presigned S3 (whichever was selected in init)
poetry run ccwb distribute
```

**Build requirements on the host:**

- Any macOS or Linux dev machine can cross-build Windows, macOS, and
  Linux bundles — no CodeBuild, no Nuitka, no PyInstaller.
- Linux builds require **Docker** for the ELF strip step. The build runs
  `eu-strip` from elfutils in a `debian:12-slim` container; the host
  architecture does not matter (the container targets `linux/amd64` or
  `linux/arm64` as needed).
- macOS builds have no special requirement.

The `dist/<profile>/<timestamp>/` folder contains one subdirectory per
bundle:

- `windows-portable/`
- `macos-arm64-portable/`
- `macos-intel-portable/`
- `linux-x64-portable/` / `linux-arm64-portable/`
- `linux-x64-slim/` / `linux-arm64-slim/`

Each bundle contains:

- Embedded Python interpreter (portable variants) or an installer that
  reuses the user's Python (slim variants)
- `credential_provider/` and (optional) `otel_helper/` source modules
- `config.json` — OIDC provider, TVM endpoint, model selection, quota
  interval, OTEL helper SHA256, etc.
- `claude-settings/settings.json` — merged into the user's
  `~/.claude/settings.json` at install time
- `install.sh` (Unix) or `install.bat` + `install.ps1` (Windows)

`ccwb distribute` uploads each bundle as its own S3 object under
`packages/<key>/latest.zip` (keys: `windows`, `macos-arm64`, `macos-intel`,
`linux-x64`, `linux-arm64`, `linux-x64-slim`, `linux-arm64-slim`). Zips
include explicit directory entries so Windows File Explorer's built-in
"Extract All" reconstructs the layout correctly.

### Step 5: Test the Setup

Verify everything works correctly:

```bash
poetry run ccwb test
```

This will:

- Simulate the end-user installation process
- Test OIDC authentication
- Verify AWS credential retrieval
- Check Amazon Bedrock access
- (Optional) Test actual API calls with `--api` flag

### Step 6: Distribute Packages to Users

You have three options for sharing packages with users. The distribution method is configured during `ccwb init` (Step 2).

#### Option 1: Manual Sharing

No additional infrastructure required. Share the built packages directly:

```bash
# Navigate to dist directory
cd dist

# Create a zip file of all packages
zip -r claude-code-packages.zip .

# Share via email or internal file sharing
# Users extract and run install.sh (Unix) or install.bat (Windows)
```

**Best for:** Any size team, no automation required

#### Option 2: Presigned S3 URLs

Automated distribution via time-limited S3 URLs:

```bash
poetry run ccwb distribute
```

Generates presigned URLs (default 48-hour expiry) that you share with users via email or messaging.

**Best for:** Automated distribution without authentication requirements

**Setup:** Select "presigned-s3" distribution type during `ccwb init` (Step 2)

#### Option 3: Authenticated Landing Page

Self-service portal with IdP authentication:

```bash
# Deploy landing page infrastructure (if not done during Step 3)
poetry run ccwb deploy distribution

# Upload packages to landing page
poetry run ccwb distribute
```

Users visit your landing page URL, authenticate with SSO, and download packages for their platform.

**Best for:** Self-service portal with compliance and audit requirements

**Setup:** Select "landing-page" distribution type during `ccwb init` (Step 2), then deploy distribution infrastructure

See [Distribution Comparison](assets/docs/distribution/comparison.md) for detailed feature comparison and setup guides.

---

## Platform Builds

### Build Requirements

All platforms share the same build path: download a python-build-standalone
tarball for the target, assemble a bundle directory, drop in the project
sources + wheels, and write `install.sh` / `install.bat`.

- **Windows**: PBS `install_only` build for `x86_64-pc-windows-msvc` —
  cross-extracts on macOS/Linux, no Windows build host needed.
- **macOS**: PBS `aarch64-apple-darwin` or `x86_64-apple-darwin` — builds
  locally on either Apple Silicon or Intel hosts.
- **Linux (portable)**: PBS `x86_64-unknown-linux-gnu` or
  `aarch64-unknown-linux-gnu`. ELF strip runs in Docker using `eu-strip`
  from elfutils — GNU `strip` corrupts PBS binaries.
- **Linux (slim)**: A minimal bundle that relies on the user's system
  Python ≥ 3.9. The installer bootstraps a user-local virtualenv with the
  vendored wheels. Verified on Ubuntu 22.04, Debian 11, Amazon Linux 2023;
  Ubuntu 20.04 fails cleanly with a version check error.

---

## Cleanup

You are responsible for the costs of AWS services while running this guidance. If you decide that you no longer need the guidance, please ensure that infrastructure resources are removed.

```bash
poetry run ccwb destroy
```

---

## Troubleshooting

### Authentication Issues

Force re-authentication:

```bash
~/claude-code-with-bedrock/credential-process --clear-cache
```

### Build Failures

- `docker not found` / daemon not running — start Docker Desktop (Linux
  host strip step requires it).
- `allocated section '.dynstr' not in segment` — you're using GNU `strip`
  instead of `eu-strip`; the Docker-based strip avoids this. See
  [Cost Management](docs/cost-management.md) if you hit related ELF
  issues on first run.
- Slim bundle failing on target — user's Python is < 3.9; use the portable
  bundle instead.

### Stack Deployment Issues

View stack status:

```bash
poetry run ccwb status
```

For detailed troubleshooting, see [Deployment Guide](assets/docs/DEPLOYMENT.md).

---

## Next Steps

- [Architecture Deep Dive](assets/docs/ARCHITECTURE.md) - Technical architecture details
- [Cost Management](docs/cost-management.md) - TVM, Bedrock usage pipeline, PROFILE records
- [Admin Guide](docs/admin-guide.md) - Quota policy reference and admin panel walkthrough
- [Enable Monitoring](assets/docs/MONITORING.md) - Setup OpenTelemetry monitoring
- [Setup Analytics](assets/docs/ANALYTICS.md) - Configure S3 data lake and Athena queries
- [CLI Reference](assets/docs/CLI_REFERENCE.md) - Complete command reference

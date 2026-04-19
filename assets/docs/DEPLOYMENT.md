# Enterprise Deployment Guide

This guide walks IT administrators through deploying Claude Code authentication across your organization, transforming your existing identity provider into a gateway for secure Amazon Bedrock access.

> **Prerequisites**: See the [main README](../../README.md#prerequisites) for detailed requirements. You'll need AWS administrative access, an OIDC identity provider, and Python with Poetry installed.

## The Deployment Process

Deploying Claude Code authentication involves four key phases: configuring your identity provider, deploying AWS infrastructure, creating distribution packages, and supporting your users. Each phase builds on the previous one, creating a complete authentication solution that's transparent to end users.

## Phase 1: Configuring Your Identity Provider

The journey begins in your organization's identity provider console. Whether you're using Okta, Azure AD, or Auth0, you'll create a new application that serves as the authentication gateway for Claude Code.

Log into your provider's admin console and navigate to the application creation section. You're creating what's known as a "Native Application" in OIDC terms - this tells the provider that users will authenticate from their local machines rather than a web server. Name it something clear like "Claude Code Authentication" or "Amazon Bedrock CLI Access" so users recognize it during login.

The critical configuration involves setting up the OAuth2 flow with specific parameters. Enable "Authorization Code" and "Refresh Token" grant types, which allow secure authentication and token renewal. The redirect URI must be exactly `http://localhost:8400/callback` - this is where the authentication process returns after users log in. Request the standard OIDC scopes: `openid`, `profile`, and `email`. Most importantly, enable PKCE (Proof Key for Code Exchange), which provides security without requiring client secrets.

> **Provider-Specific Guides**: For detailed instructions specific to your identity provider, see our guides for [Okta](providers/okta-setup.md), [Azure AD](providers/microsoft-entra-id-setup.md), or [Auth0](providers/auth0-setup.md).

Next, determine who should have access. The cleanest approach is creating a dedicated group like "Claude Code Users" and assigning it to the application. This gives you centralized control over access - simply add users to the group to grant access, or remove them to revoke it. Apply any additional policies your organization requires, such as MFA or device trust requirements.

Before moving on, note two critical values from your application configuration: the provider domain (like `company.okta.com` or `login.microsoftonline.com/{tenant-id}/v2.0`) and the Client ID. You'll need these for the AWS infrastructure deployment.

## Phase 2: Deploying AWS Infrastructure

With your identity provider configured, it's time to deploy the AWS infrastructure that bridges your organization's authentication to Amazon Bedrock. Start by cloning the repository and installing the deployment tools:

```bash
git clone https://github.com/aws-solutions-library-samples/guidance-for-claude-code-with-amazon-bedrock
cd guidance-for-claude-code-with-amazon-bedrock/source
poetry install
```

The `ccwb` (Claude Code with Bedrock) CLI tool guides you through deployment with an interactive wizard. Run `poetry run ccwb init` to begin. The wizard walks you through each configuration decision, starting with your OIDC provider details - enter the domain and Client ID you noted earlier.

The wizard asks you to choose an authentication method. You can select either Direct IAM federation or Cognito Identity Pool based on your organization's requirements. Both methods provide secure OIDC federation to AWS credentials.

Next, you'll select your Claude model and configure regional access. Choose from available Claude models (Opus, Sonnet, Haiku) and select a cross-region inference profile (US, Europe, or APAC) for optimal performance. The wizard will then prompt you to select a source region within your chosen profile for model inference. Finally, choose where to deploy the authentication infrastructure (typically your primary AWS region) and configure optional monitoring setup, which provides usage analytics and cost tracking through OpenTelemetry.

Once configuration is complete, deploy the infrastructure with:

```bash
poetry run ccwb deploy
```

This single command orchestrates the creation of multiple AWS resources. Depending on your chosen authentication method, it creates either an IAM OIDC Provider or a Cognito Identity Pool to establish the trust relationship with your identity provider. IAM roles and policies grant precisely scoped Bedrock access. If you enabled monitoring, it also deploys an ECS Fargate cluster running OpenTelemetry collector, complete with CloudWatch dashboards.

> **Deployment Options**: For more control, see the [CLI Reference](CLI_REFERENCE.md) for deploying specific stacks or using dry-run mode.

## Phase 3: Creating Distribution Packages

With infrastructure deployed, you're ready to create the package that end users will install.

### Multi-Platform Build Support

Claude Code supports building for all major platforms:

```bash
# Interactive: pick platform(s) from the checkbox prompt
poetry run ccwb package

# Build for specific platforms
poetry run ccwb package --target-platform=windows
poetry run ccwb package --target-platform=macos-arm64
poetry run ccwb package --target-platform=macos-intel
poetry run ccwb package --target-platform=linux-x64
poetry run ccwb package --target-platform=linux-arm64

# Linux slim variants (require Python >= 3.9 on the target machine)
poetry run ccwb package --target-platform=linux-x64 --slim
poetry run ccwb package --target-platform=linux-arm64 --slim
```

**Build method:** all variants use [python-build-standalone](https://github.com/astral-sh/python-build-standalone).

- **Windows / macOS / Linux portable**: the PBS tarball for the target is downloaded, the interpreter and project sources are placed into `<platform>-portable/`, and pinned wheels are installed into the bundle's `site-packages`.
- **Linux strip step**: `eu-strip` runs inside `debian:12-slim` via Docker (host may be macOS or Linux; container platform is auto-selected). GNU `strip` corrupts PBS binaries and must not be used.
- **Linux slim**: no interpreter is shipped. The installer creates a user-local virtualenv from system Python ≥ 3.9 and installs the vendored wheels. Verified on Ubuntu 22.04, Debian 11, Amazon Linux 2023.

The resulting `dist/<profile>/<timestamp>/` folder contains one bundle directory per platform. Each bundle has:

- The embedded Python interpreter (portable) or a bootstrap script (slim)
- `credential_provider/` and optional `otel_helper/` sources
- `config.json` with OIDC provider, TVM endpoint, model selection, OTEL helper hash, etc.
- `claude-settings/settings.json` (merged into `~/.claude/settings.json` at install time)
- `install.sh` (Unix) or `install.bat` + `install.ps1` (Windows)

> No CodeBuild, no Nuitka, no PyInstaller — all packaging runs on a macOS or Linux workstation with Docker available.

## Phase 4: Testing Your Deployment

Before distributing to users, thoroughly test the package to ensure everything works as expected. The CLI provides a comprehensive test command that simulates exactly what end users will experience:

```bash
poetry run ccwb test
```

This test runs through the complete user journey. It executes the installer in a temporary directory, configures the AWS profile, triggers the authentication flow, and verifies access to Amazon Bedrock. Watch as it opens a browser window for authentication - this is exactly what your users will see.

For more thorough validation, add the `--api` flag to make actual Bedrock API calls:

```bash
poetry run ccwb test --api
```

## Phase 5: Distributing to Your Users

With a tested package in hand, you're ready for the final phase: getting the authentication system to your users. Claude Code offers two distribution methods:

### Option 1: Secure URL Distribution

Generate a presigned URL for easy, secure distribution without requiring AWS credentials:

```bash
# Create distribution with 48-hour expiration
poetry run ccwb distribute

# Or specify custom expiration (up to 7 days)
poetry run ccwb distribute --expires-hours=72
```

The command uploads your package to S3 and generates a secure, time-limited URL. Share this URL with developers via email, Slack, or your internal wiki. Users download and run the installer - no AWS credentials required.

### Option 2: Manual Distribution

Share the `dist/` folder through your normal software distribution channels - perhaps a shared drive, internal website, or artifact repository.

**Installation by Platform:**

- **Windows**: Users run `install.bat`
- **macOS/Linux**: Users run `./install.sh`

Regardless of distribution method, the user experience remains simple. They receive the package, run the installer for their platform, and they're done. The installer:

- Detects their operating system and architecture
- Installs the appropriate binary
- Configures their AWS profile
- Sets up the credential process
- Handles all the complex authentication machinery invisibly

When they run Claude Code with `AWS_PROFILE=ClaudeCode`, authentication happens automatically in the background. On first use, users will see a browser window open for authentication with your organization's identity provider.

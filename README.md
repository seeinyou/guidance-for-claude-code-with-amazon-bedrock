# Guidance for Claude Code with Amazon Bedrock

This guidance provides enterprise deployment patterns for Claude Code with Amazon Bedrock using existing identity providers. Integrates with your IdP (Okta, Azure AD, Auth0, Cognito User Pools) for centralized access control, audit trails, and usage monitoring across your organization.

## Key Features

### For Organizations

- **Enterprise IdP Integration**: Leverage existing OIDC identity providers (Okta, Azure AD, Auth0, etc.)
- **Centralized Access Control**: Manage Claude Code access through your identity provider
- **No API Key Management**: Eliminate the need to distribute or rotate long-lived credentials
- **Server-Side Cost Controls**: Token Vending Machine issues short-lived Bedrock credentials with synchronous, fail-closed quota enforcement (see [Cost Management](docs/cost-management.md))
- **Usage Monitoring**: CloudWatch dashboards plus a Bedrock invocation-log pipeline that feeds per-user usage and cost into the admin panel
- **Multi-Region Support**: Configure which AWS regions users can access Bedrock in
- **Multi-Partition Support**: Deploy to AWS Commercial or AWS GovCloud (US) regions
- **Multi-Platform Support**: Windows, macOS (ARM & Intel), and Linux (x64 & ARM64) distributions

### For End Users

- **Seamless Authentication**: Log in with corporate credentials
- **Automatic Credential Refresh**: No manual token management required
- **AWS CLI/SDK Integration**: Works with any AWS tool or SDK
- **Multi-Profile Support**: Manage multiple authentication profiles
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Prerequisites](#prerequisites)
4. [AWS Partition Support](#aws-partition-support)
5. [What Gets Deployed](#what-gets-deployed)
6. [Monitoring and Operations](#monitoring-and-operations)
7. [Additional Resources](#additional-resources)

## Quick Start

This guidance integrates Claude Code with your existing OIDC identity provider (Okta, Azure AD, Auth0, or Cognito User Pools) to provide federated access to Amazon Bedrock.

### What You Need

**Existing Identity Provider:**
You must have an active OIDC provider with the ability to create application registrations. The guidance federates this IdP with AWS IAM to issue temporary credentials for Bedrock access.

**AWS Environment:**

- AWS account with IAM and CloudFormation permissions
- Amazon Bedrock activated in target regions
- Python 3.10+ development environment for deployment

### What Gets Deployed

The deployment creates:

- IAM OIDC Provider or Cognito Identity Pool for federation
- IAM roles with scoped Bedrock access policies
- Token Vending Machine (TVM) Lambda + Bedrock usage pipeline for server-side quota enforcement and per-user cost tracking
- Self-service landing page + admin panel (ALB + Lambda)
- Platform-specific installation packages (Windows, macOS, Linux portable + Linux slim)
- Optional: OpenTelemetry monitoring infrastructure

**Deployment time:** 2-3 hours for initial setup including IdP configuration.

See [QUICK_START.md](QUICK_START.md) for complete step-by-step deployment instructions.

## Architecture Overview

This guidance uses Direct IAM OIDC federation as the recommended authentication pattern. This provides temporary AWS credentials with complete user attribution for audit trails and usage monitoring.

**Alternative:** Cognito Identity Pool is also supported for legacy IdP integrations. See [Deployment Guide](assets/docs/DEPLOYMENT.md) for comparison.

### Authentication Flow (Direct IAM Federation)

![Architecture Diagram](assets/images/credential-flow-direct-diagram.png)

1. **User initiates authentication**: User requests access to Amazon Bedrock through Claude Code
2. **OIDC authentication**: User authenticates with their OIDC provider and receives an ID token
3. **Token submission to IAM**: Application sends the OIDC ID token to Amazon Cognito
4. **IAM returns credentials**: AWS IAM validates and returns temporary AWS credentials
5. **Access Amazon Bedrock**: Application uses the temporary credentials to call Amazon Bedrock
6. **Bedrock response**: Amazon Bedrock processes the request and returns the response

## Prerequisites

### For Deployment (IT Administrators)

**Software Requirements:**

- Python 3.10-3.13
- Poetry (dependency management)
- AWS CLI v2
- Git

**AWS Requirements:**

- AWS account with appropriate IAM permissions to create:
  - CloudFormation stacks
  - IAM OIDC Providers or Cognito Identity Pools
  - IAM roles and policies
  - (Optional) Amazon Elastic Container Service (Amazon ECS) tasks and Amazon CloudWatch dashboards
  - (Optional) Amazon Athena, AWS Glue, AWS Lambda, and Amazon Data Firehose resources
- Amazon Bedrock activated in target regions
- Bedrock Model Invocation Logging is enabled automatically by the `quota` stack when cost management is used

**OIDC Provider Requirements:**

- Existing OIDC identity provider (Okta, Azure AD, Auth0, etc.)
- Ability to create OIDC applications
- Redirect URI support for `http://localhost:8400/callback`

### For End Users

**Software Requirements:**

- AWS CLI v2 (for credential process integration)
- Claude Code installed
- Web browser for SSO authentication

**No AWS account required** - users authenticate through your organization's identity provider and receive temporary credentials automatically.

**No Python, Poetry, or Git required** - users receive pre-built installation packages from IT administrators.

### Supported AWS Regions

The guidance can be deployed in any AWS region that supports:

- IAM OIDC Providers or Amazon Cognito Identity Pools
- Amazon Bedrock
- (Optional) Amazon Elastic Container Service (Amazon ECS) tasks and Amazon CloudWatch dashboards
- (Optional) Amazon Athena, AWS Glue, AWS Lambda, and Amazon Data Firehose resources

Both AWS Commercial and AWS GovCloud (US) partitions are supported. See [AWS Partition Support](#aws-partition-support) for details.

### Cross-Region Inference

Claude Code uses Amazon Bedrock's cross-region inference for optimal performance and availability. During setup, you can:

- Select your preferred Claude model (Opus, Sonnet, Haiku)
- Choose a cross-region profile (US, Europe, APAC) for optimal regional routing
- Select a specific source region within your profile for model inference

This automatically routes requests across multiple AWS regions to ensure the best response times and highest availability. Modern Claude models (3.7+) require cross-region inference for access.

### Platform Support

Packages ship as portable Python bundles built from [python-build-standalone](https://github.com/astral-sh/python-build-standalone). The user gets a top-level directory with an embedded interpreter and wheels — no system Python, compiler, or SDK required. For Linux there is also a **slim** variant that reuses the user's existing Python 3.9+ for a ~30 MB download.

| Platform | Architecture          | Variant                 | Installer    | Approx. size |
| -------- | --------------------- | ----------------------- | ------------ | ------------ |
| Windows  | x64                   | Portable                | install.bat  | ~35 MB       |
| macOS    | ARM64 (Apple Silicon) | Portable                | install.sh   | ~90 MB       |
| macOS    | Intel (x86_64)        | Portable                | install.sh   | ~85 MB       |
| Linux    | x64                   | Portable                | install.sh   | ~130 MB      |
| Linux    | x64                   | Slim (system Python)    | install.sh   | ~29 MB       |
| Linux    | ARM64                 | Portable                | install.sh   | ~112 MB      |
| Linux    | ARM64                 | Slim (system Python)    | install.sh   | ~30 MB       |

**Build requirements:**

- macOS/Linux portable bundles build on the host directly (no Docker needed on Linux).
- Linux ELF strip uses Docker with `eu-strip` (elfutils) — required to safely shrink PBS binaries without breaking the dynamic-symbol section.
- Windows portable bundles are produced by cross-extracting PBS on macOS/Linux; no Windows CI or CodeBuild is used.

See [QUICK_START.md](QUICK_START.md#platform-builds) for build commands and caveats.

## AWS Partition Support

This guidance supports deployment across multiple AWS partitions with a single, unified codebase. The same CloudFormation templates and deployment process work seamlessly in both AWS Commercial and AWS GovCloud (US) regions.

### Supported Partitions

| Partition | Regions | Use Cases |
|-----------|---------|-----------|
| **AWS Commercial** (`aws`) | All regions where Bedrock is available | Standard commercial workloads |
| **AWS GovCloud (US)** (`aws-us-gov`) | us-gov-west-1, us-gov-east-1 | US government agencies, contractors, and regulated workloads |

### How It Works

The guidance automatically detects the AWS partition at deployment time and configures resources appropriately:

**Resource ARNs:**
- CloudFormation uses the `${AWS::Partition}` pseudo-parameter
- Automatically resolves to `aws` or `aws-us-gov`
- Example: `arn:${AWS::Partition}:bedrock:*::foundation-model/*`

**Service Principals:**
- Cognito Identity service principals are partition-specific
- Commercial: `cognito-identity.amazonaws.com`
- GovCloud West: `cognito-identity-us-gov.amazonaws.com`
- GovCloud East: `cognito-identity.us-gov-east-1.amazonaws.com`
- IAM role trust policies automatically use the correct principal based on region

**S3 Endpoints:**
- Commercial: `s3.region.amazonaws.com`
- GovCloud: `s3.region.amazonaws.com`

### Deploying to AWS GovCloud

Follow the same [Quick Start](#quick-start) instructions with your GovCloud credentials active. During `ccwb init`, select a GovCloud region (us-gov-west-1 or us-gov-east-1) and the wizard will automatically configure GovCloud-compatible models and endpoints.

**GovCloud-Specific Considerations:**

1. **Credentials:** GovCloud requires separate AWS credentials from commercial accounts
2. **Model IDs:** GovCloud uses region-prefixed model IDs (e.g., `us-gov.anthropic.*`)
3. **FIPS Endpoints:** Cognito hosted UI uses `{prefix}.auth-fips.{region}.amazoncognito.com`
4. **Managed Login:** Branding must be created for each Cognito app client

### Validation

After deployment, verify the correct partition configuration:

```bash
# Check IAM role ARN uses correct partition
aws iam get-role \
  --role-name BedrockCognitoFederatedRole \
  --region <region> \
  --query 'Role.Arn'

# Expected ARN formats:
# Commercial: arn:aws:iam::ACCOUNT:role/BedrockCognitoFederatedRole
# GovCloud: arn:aws-us-gov:iam::ACCOUNT:role/BedrockCognitoFederatedRole
```

### Backward Compatibility

✅ **All changes are fully backward compatible**

- Existing commercial deployments continue to work without modification
- CloudFormation updates can be applied to existing stacks
- No changes to user-facing functionality
- No data migration required

## What Gets Deployed

### Authentication Infrastructure

The `ccwb deploy` command creates:

**IAM Resources:**

- IAM OIDC Provider (for Direct IAM federation) or Cognito Identity Pool (for legacy IdP)
- IAM role with trust relationship for federated access
- IAM policies scoped to:
  - Bedrock model invocation in configured regions
  - CloudWatch metric publishing (if monitoring enabled)

**Cost Management Infrastructure (`quota` stack):**

- TVM Lambda (`POST /tvm`) that validates JWT, checks quotas fail-closed, and returns short-lived Bedrock credentials
- `BedrockUserRole` — Bedrock-scoped role assumed by the TVM on behalf of users
- Bedrock Model Invocation Logging custom resource + S3 → SQS → Lambda pipeline (`bedrock_usage_stream` + `bedrock_usage_reconciler`)
- CloudWatch alarms on stream errors, DLQ depth, and DynamoDB throttling

See [Cost Management](docs/cost-management.md) for the full architecture.

**User Distribution Packages:**

- Portable Python bundles (Windows, macOS ARM64/Intel, Linux x64/ARM64)
- Linux slim bundles that reuse system Python 3.9+
- Install scripts that configure the AWS CLI `credential_process` and Claude Code settings
- Pre-configured settings (OIDC provider, TVM endpoint, model selection, monitoring endpoints)

### Distribution Options (Optional)

After building packages, you can share them with users in three ways:

| Method                | Best For               | Authentication                 |
| --------------------- | ---------------------- | ------------------------------ |
| **Manual Sharing**    | Any size team          | None                           |
| **Presigned S3 URLs** | Automated distribution | None                           |
| **Landing Page**      | Self-service portal    | IdP (Okta/Azure/Auth0/Cognito) |

**Manual Sharing:** Zip the `dist/` folder and share via email or internal file sharing. No additional infrastructure required.

**Presigned URLs:** Generate time-limited S3 URLs for direct downloads. Automated but requires S3 bucket setup.

**Landing Page:** Self-service portal with IdP authentication, OS detection, and per-OS grouped cards. Linux shows a single card per architecture with side-by-side Portable/Slim download buttons. Groups with no available packages are omitted automatically.

See [Distribution Comparison](assets/docs/distribution/comparison.md) for detailed setup guides.

### Monitoring Infrastructure (Optional)

Enable usage visibility with OpenTelemetry monitoring stack:

**Components:**

- VPC and networking resources (or use existing VPC)
- ECS Fargate cluster running OpenTelemetry collector
- Application Load Balancer for metric ingestion
- CloudWatch dashboards with real-time usage metrics
- DynamoDB for metrics aggregation

**Optional Analytics Add-On:**

- Kinesis Data Firehose streaming metrics to S3
- S3 data lake for long-term storage
- Amazon Athena for SQL queries on historical data
- AWS Glue Data Catalog for schema management

See [QUICK_START.md](QUICK_START.md) for step-by-step deployment instructions.

## Monitoring and Operations

Optional OpenTelemetry monitoring provides comprehensive usage visibility for cost attribution, capacity planning, and productivity insights.

### Available Metrics

**Token Economics:**

- Input/output/cache token consumption by user, model, and type
- Prompt caching effectiveness (hit rates, token savings)
- Cost attribution by user, team, or department

**Code Activity:**

- Lines of code written vs accepted (productivity signal)
- File operations breakdown (edits, searches, reads)
- Programming language distribution

**Operational Health:**

- Active users and top consumers
- Usage patterns (hourly/daily heatmaps)
- Authentication and API error rates

### Infrastructure

The monitoring stack (deployed with `ccwb deploy monitoring`) includes:

- ECS Fargate running OpenTelemetry collector
- Application Load Balancer for metric ingestion
- CloudWatch dashboards for real-time visualization
- Optional: S3 data lake + Athena for historical analysis

See [Monitoring Guide](assets/docs/MONITORING.md) for setup details and dashboard examples.
See [Analytics Guide](assets/docs/ANALYTICS.md) for SQL queries on historical data.

## Additional Resources

### Getting Started

- [Quick Start Guide](QUICK_START.md) - Step-by-step deployment walkthrough
- [CLI Reference](assets/docs/CLI_REFERENCE.md) - Complete command reference for the `ccwb` tool

### Architecture & Deployment

- [Architecture Guide](assets/docs/ARCHITECTURE.md) - System architecture and design decisions
- [Cost Management](docs/cost-management.md) - TVM, Bedrock usage pipeline, and PROFILE records
- [Deployment Guide](assets/docs/DEPLOYMENT.md) - Advanced deployment options
- [Distribution Comparison](assets/docs/distribution/comparison.md) - Presigned URLs vs Landing Page
- [Local Testing Guide](assets/docs/LOCAL_TESTING.md) - Testing before deployment

### Operations

- [Admin Guide](docs/admin-guide.md) - Quota policies, pricing, admin panel, troubleshooting
- [User Guide](docs/user-guide.md) - End-user install, quota UX, Docker environment
- [Monitoring Guide](assets/docs/MONITORING.md) - OpenTelemetry setup and dashboards
- [Analytics Guide](assets/docs/ANALYTICS.md) - S3 data lake and Athena SQL queries

### Identity Provider Setup

- [Okta](assets/docs/providers/okta-setup.md)
- [Microsoft Entra ID (Azure AD)](assets/docs/providers/microsoft-entra-id-setup.md)
- [Auth0](assets/docs/providers/auth0-setup.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

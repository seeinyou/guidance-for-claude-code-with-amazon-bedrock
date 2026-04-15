# Migration Runbook: `feat/cost-management-hardening` → Production

> **Audience**: Claude Code agent deploying this branch to an existing environment.
> **From**: `main` branch (OTEL-only quota system, client-side quota check)
> **To**: `feat/cost-management-hardening` (TVM + Bedrock usage pipeline + admin hardening)

---

## TL;DR — Deployment Sequence

```
1. Pre-flight checks
2. Deploy quota stack          (ccwb deploy quota — adds TVM, stream, reconciler, logging config)
3. Deploy distribution stack   (ccwb deploy distribution — updated admin panel with Bedrock usage reads)
4. Deploy Cognito User Pool    (deploy-cognito.sh — refresh token validity 12h)
5. Deploy auth stack           (ccwb deploy auth — TVMEnabled=false, no change to permissions)
6. Build & distribute new client package (credential-process now calls TVM)
7. Verify end-to-end           (TVM issuance, usage tracking, admin panel)
8. Flip TVMEnabled=true        (removes direct Bedrock permissions from auth role)
9. Monitor & validate
```

**Critical rule**: Steps 2–6 are additive (no breakage). Step 8 is the point of no return for auth role permissions. Do NOT flip TVMEnabled until step 7 passes.

### Stack → Lambda Mapping

| `ccwb deploy` command | Template | Lambda functions deployed |
|---|---|---|
| `ccwb deploy quota` | `quota-monitoring.yaml` | `tvm`, `quota_monitor`, `quota_check`, `bedrock_usage_stream`, `bedrock_usage_reconciler`, `bedrock_logging_config` |
| `ccwb deploy distribution` | `landing-page-distribution.yaml` | `landing_page_admin` (admin panel UI + API) |
| `ccwb deploy dashboard` | `claude-code-dashboard.yaml` | `metrics_aggregator` |
| `ccwb deploy auth` | `bedrock-auth-{provider}.yaml` | (no Lambda — IAM roles + policies only) |
| `deploy-cognito.sh` | `cognito-user-pool-setup.yaml` | (no Lambda — Cognito User Pool + App Client settings) |

---

## 0. What Changed (Summary)

| Area | Before (main) | After (this branch) |
|------|--------------|---------------------|
| **Bedrock credentials** | Auth role has direct `bedrock:InvokeModel*` | TVM Lambda issues short-lived STS credentials via `BedrockUserRole` |
| **Quota enforcement** | Client-side `_check_quota()` calls `/check` API | TVM Lambda checks quota server-side before issuing credentials (fail-closed) |
| **Usage data source** | OTEL pipeline only (`MONTH#YYYY-MM`) | Bedrock invocation logs (`MONTH#YYYY-MM#BEDROCK` + `DAY#YYYY-MM-DD#BEDROCK`). All consumers migrated |
| **Credential refresh** | Re-auth via browser on id_token expiry | Silent refresh via Cognito refresh_token (12h validity) |
| **otel-helper** | No integrity check | SHA256 hash verified, status reported to TVM via `X-OTEL-Helper-Status` header |
| **User registry** | None (derived from usage records) | `USER#{email} SK=PROFILE` records with `status`, `first_activated`, `last_seen` |
| **User disable** | Not possible | Admin sets `PROFILE.status=disabled` → TVM denies all credentials |
| **Admin panel** | Users tab shows OTEL usage only | Shows PROFILE records, status badges, disable/enable buttons, pricing management |
| **Config fields** | `quota_api_endpoint`, `quota_fail_mode` | `tvm_endpoint`, `tvm_request_timeout` (old fields removed) |

### New CloudFormation Resources (quota-monitoring.yaml)

| Resource | Type | Purpose |
|----------|------|---------|
| `TVMFunction` | Lambda | Token Vending Machine — credential issuance |
| `TVMLambdaRole` + `TVMAssumeRolePolicy` | IAM | TVM execution role + sts:AssumeRole permission |
| `BedrockUserRole` | IAM Role | Bedrock-scoped role assumed by TVM for users |
| `TVMRoute` + `TVMIntegration` + `TVMLambdaPermission` | API GW | `POST /tvm` route on existing HTTP API |
| `BedrockLoggingConfigFunction` + `BedrockLoggingConfig` | Lambda + Custom Resource | Enables Bedrock Model Invocation Logging |
| `BedrockLogQueue` + `BedrockLogDLQ` + `BedrockLogQueuePolicy` | SQS | S3 event → SQS for log processing |
| `BedrockUsageStreamFunction` + `BedrockUsageStreamRole` | Lambda | Real-time log → DynamoDB usage records |
| `BedrockUsageStreamEventSource` | EventSourceMapping | SQS → stream Lambda |
| `BedrockUsageReconcilerFunction` + `BedrockUsageReconcilerRole` | Lambda | 30-min catchup for missed events + DLQ drain |
| `ReconcilerScheduleRule` + `ReconcilerSchedulePermission` | EventBridge | Triggers reconciler every 30 minutes |
| `StreamLambdaErrorAlarm`, `ReconcilerLambdaErrorAlarm`, `DynamoDBThrottleAlarm` | CloudWatch Alarm | Pipeline health monitoring |
| `QuotaAlertSubscription` | SNS Subscription | Email alerts (conditional on `AlertEmail` param) |

### New Lambda Functions (new directories)

| Directory | Handler | Trigger |
|-----------|---------|---------|
| `lambda-functions/tvm/index.py` | `lambda_handler` | API Gateway `POST /tvm` |
| `lambda-functions/bedrock_logging_config/index.py` | `handler` | CloudFormation Custom Resource |
| `lambda-functions/bedrock_usage_stream/index.py` | `lambda_handler` | SQS (S3 event notifications) |
| `lambda-functions/bedrock_usage_reconciler/index.py` | `lambda_handler` | EventBridge (every 30 min) |
| `lambda-functions/layer/python/bedrock_usage_utils.py` | (shared module) | Imported by stream + reconciler |

### Modified Files

| File | Key Changes |
|------|-------------|
| `credential_provider/__main__.py` | `_call_tvm()`, `_check_otel_helper_integrity()`, `_try_refresh_token()`, `_save_refresh_token()`; removed `_check_quota()`, `_should_recheck_quota()` |
| `config.py` | Added `tvm_endpoint`, `tvm_request_timeout`, `otel_helper_hash`; removed `quota_api_endpoint`, `quota_fail_mode` |
| `cli/commands/package.py` | Computes SHA256 of otel-helper, writes `otel_helper_hash` to config.json |
| `cli/commands/test.py` | Added `_test_tvm_endpoint()` test method |
| `cognito-user-pool-setup.yaml` | `RefreshTokenValidity: 720` (minutes = 12 hours) |
| `cognito-identity-pool.yaml` | Added `TVMEnabled` param, `TVMDisabled` condition, conditional Invoke permissions |
| `bedrock-auth-{cognito-pool,okta,azure,auth0}.yaml` | Same TVMEnabled pattern as above |
| `landing_page_admin/index.py` | PROFILE-based user listing, disable/enable APIs, pricing management tab, **reads `#BEDROCK` records** (deploy via `ccwb deploy distribution`) |
| `quota_monitor/index.py` | Added `check_reconciler_heartbeat()`, **reads `#BEDROCK` + `DAY#` + `PROFILE`** (deploy via `ccwb deploy quota`) |
| `quota-monitoring.yaml` | +471 lines: all new resources listed above |

---

## 1. Pre-flight Checks

Run these before any deployment. Failures here must be resolved first.

### 1.1 Existing Stack Status

```bash
# Check all existing stacks are in a stable state
aws cloudformation describe-stacks \
  --query 'Stacks[?contains(StackName,`<identity-pool-name>`)].{Name:StackName,Status:StackStatus}' \
  --output table
```

All stacks should be `CREATE_COMPLETE` or `UPDATE_COMPLETE`. If any are `*_IN_PROGRESS` or `*_FAILED`, resolve first.

### 1.2 Current Auth Stack Parameters

Record these — you'll need them to verify nothing changed during step 5:

```bash
# For whichever auth stack is in use (cognito-pool, okta, azure, auth0)
aws cloudformation describe-stacks --stack-name <auth-stack-name> \
  --query 'Stacks[0].Parameters' --output table
```

### 1.3 Bedrock Model Invocation Logging Status

The custom resource will enable this automatically, but check beforehand:

```bash
aws bedrock get-model-invocation-logging-configuration \
  --query 'loggingConfig.s3Config' --output json
```

- If already enabled: the custom resource will detect this and skip (no overwrite).
- If not enabled: the custom resource will create an S3 bucket and enable logging.

### 1.4 Verify Cognito User Pool Client Settings

Refresh token support requires `ALLOW_REFRESH_TOKEN_AUTH` on the App Client:

```bash
aws cognito-idp describe-user-pool-client \
  --user-pool-id <pool-id> --client-id <client-id> \
  --query 'UserPoolClient.{ExplicitAuthFlows:ExplicitAuthFlows,RefreshTokenValidity:TokenValidityUnits.RefreshToken}'
```

`ExplicitAuthFlows` should include `ALLOW_REFRESH_TOKEN_AUTH`. If not, the Cognito User Pool Setup stack update (step 4) will add it.

### 1.5 Code Prerequisites

```bash
# Verify AWS CLI is installed (required for cloudformation package)
which aws && aws --version

# Verify S3 bucket stack exists (required for Lambda packaging)
aws cloudformation describe-stacks --stack-name <identity-pool-name>-s3bucket \
  --query 'Stacks[0].Outputs[?OutputKey==`CfnArtifactsBucket`].OutputValue' --output text

# Verify dashboard stack exists (required for MetricsTableArn)
aws cloudformation describe-stacks --stack-name <identity-pool-name>-dashboard \
  --query 'Stacks[0].Outputs[?OutputKey==`MetricsTableArn`].OutputValue' --output text
```

---

## 2. Deploy Quota Stack

This is the biggest change — adds TVM, Bedrock logging, usage pipeline, and alarms.

```bash
cd source/
poetry run ccwb deploy quota
```

### What Happens

1. `aws cloudformation package` uploads Lambda code to S3
2. Creates: TVM Lambda, BedrockUserRole, `/tvm` API Gateway route, Bedrock logging config, SQS queue + DLQ, stream Lambda, reconciler Lambda, EventBridge schedule, CloudWatch alarms, SNS subscription
3. The `BedrockLoggingConfig` custom resource runs and enables Bedrock Model Invocation Logging (if not already enabled), creates S3→SQS notification

### Verify After Deploy

```bash
# 1. TVM endpoint is accessible (should return 401 — no JWT)
QUOTA_API=$(aws cloudformation describe-stacks --stack-name <quota-stack> \
  --query 'Stacks[0].Outputs[?OutputKey==`QuotaCheckApiEndpoint`].OutputValue' --output text)
curl -s -o /dev/null -w '%{http_code}' -X POST "${QUOTA_API}/tvm"
# Expected: 401

# 2. Bedrock logging is enabled
aws bedrock get-model-invocation-logging-configuration \
  --query 'loggingConfig.s3Config.s3BucketName' --output text
# Expected: a bucket name (created or pre-existing)

# 3. BedrockUserRole exists
aws iam get-role --role-name BedrockUserRole \
  --query 'Role.RoleName' --output text
# Expected: BedrockUserRole

# 4. SQS queue exists
aws sqs get-queue-url --queue-name claude-code-bedrock-log-queue
# Expected: queue URL

# 5. EventBridge rule is enabled
aws events describe-rule --name claude-code-reconciler-schedule \
  --query 'State' --output text
# Expected: ENABLED

# 6. CloudWatch alarms exist
aws cloudwatch describe-alarms \
  --alarm-names claude-code-bedrock-stream-errors claude-code-reconciler-errors claude-code-dynamodb-throttled \
  --query 'MetricAlarms[].AlarmName'
```

---

## 3. Deploy Distribution Stack

The `landing_page_admin` Lambda (admin panel) is in the `distribution` stack, **not** `quota`. This must be deployed separately to pick up the Bedrock usage migration (reads `#BEDROCK` records instead of OTEL).

```bash
cd source/
poetry run ccwb deploy distribution
```

### Verify After Deploy

Open the admin panel URL and verify:
- Users tab loads (shows PROFILE records with status badges)
- For `@amazon.com` admins: clicking a user row shows usage detail card

---

## 4. Deploy Cognito User Pool Setup (Refresh Token)

`cognito-user-pool-setup.yaml` is deployed via a **separate script**, not `ccwb deploy auth`. This sets `RefreshTokenValidity` to 720 minutes (12 hours) on the CLI App Client.

```bash
cd deployment/scripts/
bash deploy-cognito.sh
```

Existing sessions are unaffected — new tokens will use the updated validity.

> **Note**: `ccwb deploy auth` deploys `bedrock-auth-{provider}.yaml` (IAM roles/policies). It does NOT touch the Cognito User Pool App Client settings.

---

## 5. Deploy Auth Stack (TVMEnabled=false)

Update the auth stack with the new `TVMEnabled` parameter but keep it `false` (the default). This adds the parameter and condition to the template without changing any permissions.

```bash
cd source/
poetry run ccwb deploy auth
```

### Verify After Deploy

```bash
# Auth role still has Bedrock permissions
aws iam list-attached-role-policies --role-name <auth-role-name> \
  --query 'AttachedPolicies[].PolicyName'

# Check the policy document still contains AllowBedrockInvoke*
POLICY_ARN=$(aws cloudformation describe-stacks --stack-name <auth-stack> \
  --query 'Stacks[0].Outputs[?OutputKey==`BedrockPolicyArn`].OutputValue' --output text)
aws iam get-policy-version --policy-arn $POLICY_ARN \
  --version-id $(aws iam get-policy --policy-arn $POLICY_ARN --query 'Policy.DefaultVersionId' --output text) \
  --query 'PolicyVersion.Document.Statement[].Sid'
# Expected: should include AllowBedrockInvokeRegional, AllowBedrockInvokeGlobal, etc.
```

---

## 6. Build & Distribute New Client Package

The new credential-process calls TVM instead of the old `/check` endpoint.

### 6.1 Verify Config Profile

`tvm_endpoint` is automatically populated by `ccwb deploy quota` (step 2) from CloudFormation stack outputs. Verify it's set:

```bash
poetry run ccwb status
# Should show tvm_endpoint with the API Gateway URL
```

If `tvm_endpoint` is missing (e.g., deploy was interrupted), re-run `poetry run ccwb deploy quota`.

Old fields `quota_api_endpoint` and `quota_fail_mode` are ignored by the new client and will be excluded from the package automatically.

### 6.2 Build Package

```bash
poetry run ccwb package
```

This will:
1. Build credential-provider binaries (with new TVM code)
2. Build otel-helper binaries
3. Compute SHA256 hash of otel-helper → writes `otel_helper_hash` to config.json
4. Produce distributable zip

### 6.3 Distribute

Distribute the new package to users via your existing mechanism (S3 presigned URL, landing page, etc.).

### Verify

```bash
# Test the new credential-process against TVM
poetry run ccwb test
```

The test should show:
- Authentication: OK
- TVM endpoint: OK (new test)
- Bedrock access: OK

---

## 7. End-to-End Verification

Before flipping `TVMEnabled=true` (step 8), verify all new components work together.

### 7.1 TVM Credential Issuance

```bash
# Run ccwb test — the new _test_tvm_endpoint() method validates:
# - TVM returns credentials with AccessKeyId, SecretAccessKey, SessionToken, Expiration
# - Credentials can access Bedrock
poetry run ccwb test
```

### 7.2 Bedrock Usage Tracking

Make a Bedrock API call via Claude Code, then wait ~2 minutes for the pipeline:

```bash
# Check if Bedrock invocation logs appeared in S3
BUCKET=$(aws bedrock get-model-invocation-logging-configuration \
  --query 'loggingConfig.s3Config.s3BucketName' --output text)
aws s3 ls s3://${BUCKET}/bedrock-raw/ --recursive | tail -5

# Check SQS queue (should be ~0 messages in flight if stream processed them)
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name claude-code-bedrock-log-queue --output text) \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible

# Check DynamoDB for MONTH#YYYY-MM#BEDROCK records
aws dynamodb query --table-name UserQuotaMetrics \
  --key-condition-expression 'pk = :pk AND begins_with(sk, :sk)' \
  --expression-attribute-values '{":pk":{"S":"USER#<user-email>"},":sk":{"S":"MONTH#"}}' \
  --query 'Items[].{sk:sk.S,tokens:total_tokens.N,cost:estimated_cost.N}'

# Check ORG aggregate
aws dynamodb get-item --table-name UserQuotaMetrics \
  --key '{"pk":{"S":"ORG#global"},"sk":{"S":"MONTH#2026-04#BEDROCK"}}' \
  --query 'Item.{tokens:total_tokens.N,cost:estimated_cost.N}'
```

### 7.3 Reconciler Health

```bash
# Check heartbeat (written every 30 min)
aws dynamodb get-item --table-name UserQuotaMetrics \
  --key '{"pk":{"S":"SYSTEM#reconciler"},"sk":{"S":"HEARTBEAT"}}' \
  --query 'Item.{last_run:last_run.S,s3:records_processed.N,dlq:dlq_processed.N}'
```

### 7.4 User Profile Created

```bash
# TVM should have created a PROFILE record for the test user
aws dynamodb get-item --table-name UserQuotaMetrics \
  --key '{"pk":{"S":"USER#<user-email>"},"sk":{"S":"PROFILE"}}' \
  --query 'Item.{status:status.S,first_activated:first_activated.S,last_seen:last_seen.S}'
```

### 7.5 Admin Panel

Open the admin panel URL and verify:
- Users tab shows PROFILE records with status badges
- Disable/Enable buttons work
- Pricing tab shows BedrockPricing records
- A disabled user cannot get TVM credentials

### 7.6 Refresh Token

```bash
# Clear cached credentials to force re-auth
poetry run ccwb test --clear-cache  # or manually delete cached files

# Authenticate once (browser flow)
# Wait for id_token to expire (~60 min for Cognito default)
# Next credential request should silently refresh via refresh_token (no browser)
```

---

## 8. Flip TVMEnabled=true

**This is the critical step.** After flipping, the auth role loses direct Bedrock permissions. Users MUST have the new client (step 6) that calls TVM.

### Prerequisites Checklist

- [ ] Step 2: Quota stack deployed, TVM responding
- [ ] Step 3: Distribution stack deployed (admin panel reads Bedrock records)
- [ ] Step 4: Cognito User Pool updated (refresh token 12h)
- [ ] Step 5: Auth stack deployed with TVMEnabled parameter (still false)
- [ ] Step 6: New client package built and distributed to ALL users
- [ ] Step 7.1: TVM credential issuance verified
- [ ] Step 7.2: Bedrock usage records appearing in DynamoDB
- [ ] Step 7.4: PROFILE records being created
- [ ] All users have updated to the new client package

### Deploy

Update the auth stack with `TVMEnabled=true`. This requires passing the parameter override to CloudFormation:

```bash
# For the auth template in use (cognito-pool, okta, azure, auth0, or cognito-identity-pool):
aws cloudformation deploy \
  --template-file deployment/infrastructure/<auth-template>.yaml \
  --stack-name <auth-stack-name> \
  --parameter-overrides TVMEnabled=true \
  --capabilities CAPABILITY_IAM \
  --no-execute-changeset  # REVIEW FIRST

# Review the changeset, then execute:
aws cloudformation deploy \
  --template-file deployment/infrastructure/<auth-template>.yaml \
  --stack-name <auth-stack-name> \
  --parameter-overrides TVMEnabled=true \
  --capabilities CAPABILITY_IAM
```

### Verify

```bash
# Auth role policy should NO LONGER have AllowBedrockInvokeRegional / AllowBedrockInvokeGlobal
POLICY_ARN=$(aws cloudformation describe-stacks --stack-name <auth-stack> \
  --query 'Stacks[0].Outputs[?OutputKey==`BedrockPolicyArn`].OutputValue' --output text)
aws iam get-policy-version --policy-arn $POLICY_ARN \
  --version-id $(aws iam get-policy --policy-arn $POLICY_ARN --query 'Policy.DefaultVersionId' --output text) \
  --query 'PolicyVersion.Document.Statement[].Sid'
# Expected: AllowBedrockListRegional, AllowBedrockListGlobal (NO AllowBedrockInvoke*)

# Bedrock access still works (via TVM-issued credentials)
poetry run ccwb test
```

---

## 9. Post-Migration Monitoring

### First 24 Hours

| Check | Command / Location | Expected |
|-------|-------------------|----------|
| TVM errors | CloudWatch Logs: `/aws/lambda/claude-code-tvm` | No 5xx errors |
| Stream errors | CloudWatch Alarm: `claude-code-bedrock-stream-errors` | OK (not alarming) |
| Reconciler errors | CloudWatch Alarm: `claude-code-reconciler-errors` | OK |
| DynamoDB throttles | CloudWatch Alarm: `claude-code-dynamodb-throttled` | OK |
| Reconciler heartbeat | DynamoDB `SYSTEM#reconciler HEARTBEAT` | `last_run` within 35 min |
| DLQ depth | SQS `claude-code-bedrock-log-dlq` | ~0 messages |
| Usage accuracy | Compare `MONTH#YYYY-MM#BEDROCK` vs `MONTH#YYYY-MM` records | Bedrock records should be >= OTEL (OTEL may miss events) |
| User complaints | Slack / email | No auth failures |

### CloudWatch Queries

```
# TVM error rate (last 1h)
fields @timestamp, @message
| filter @logStream like /claude-code-tvm/
| filter @message like /ERROR/
| stats count() by bin(5m)

# Credential issuance latency
fields @timestamp, @duration
| filter @logStream like /claude-code-tvm/
| stats avg(@duration), max(@duration), p99(@duration) by bin(5m)
```

---

## Rollback Plan

### Scenario A: TVM Not Working (Before Step 8)

No impact — auth role still has direct Bedrock permissions. Users with old client continue working. Fix TVM and retry.

### Scenario B: Rollback After Step 8 (TVMEnabled=true)

```bash
# Revert auth role to include Bedrock permissions
aws cloudformation deploy \
  --template-file deployment/infrastructure/<auth-template>.yaml \
  --stack-name <auth-stack-name> \
  --parameter-overrides TVMEnabled=false \
  --capabilities CAPABILITY_IAM
```

This restores `AllowBedrockInvokeRegional` + `AllowBedrockInvokeGlobal` to the auth role. Users with both old and new clients will work.

### Scenario C: Full Rollback to Main

1. Set `TVMEnabled=false` on auth stack (step B above)
2. Redeploy quota stack from `main` branch (removes TVM resources)
3. Redistribute old client package
4. Users re-auth via browser (refresh tokens from new client are irrelevant)

**Data impact**: `MONTH#YYYY-MM#BEDROCK` and `DAY#YYYY-MM-DD#BEDROCK` records remain in DynamoDB but are not read by main-branch code. `PROFILE` records also remain inert. No data loss.

---

## Known Gaps & Caveats

### Config Field Migration

Old `config.json` profiles will have `quota_api_endpoint` and `quota_fail_mode`. The new credential-process ignores these fields (no crash), but they should be cleaned up. `tvm_endpoint` is automatically populated during `ccwb deploy quota` (from CloudFormation outputs), embedded into `config.json` by `ccwb package`, and distributed to users via `install.sh`/`install.bat`. No manual config editing is needed as long as you follow the deploy → package → install sequence.

### Cognito-Only Scope

Refresh token flow (`_try_refresh_token()`) only works with Cognito User Pools. For Okta/Azure/Auth0 providers:
- Refresh tokens are NOT implemented
- Users will re-auth via browser when id_token expires
- TVM still works — only silent refresh is unavailable

### OTEL Pipeline (Legacy)

All consumers have been migrated to read Bedrock records (`MONTH#YYYY-MM#BEDROCK`, `DAY#YYYY-MM-DD#BEDROCK`):

| Consumer | Record Types Read |
|----------|------------------|
| TVM Lambda | `MONTH#YYYY-MM#BEDROCK` (quota enforcement) |
| `quota_monitor` | `MONTH#YYYY-MM#BEDROCK` + `DAY#YYYY-MM-DD#BEDROCK` + `PROFILE` |
| `landing_page_admin` | `MONTH#YYYY-MM#BEDROCK` + `DAY#YYYY-MM-DD#BEDROCK` + `PROFILE` |
| `ccwb quota usage` | `MONTH#YYYY-MM#BEDROCK` + `DAY#YYYY-MM-DD#BEDROCK` + `PROFILE` |
| `ccwb test` | `MONTH#YYYY-MM#BEDROCK` + `DAY#YYYY-MM-DD#BEDROCK` |

The OTEL pipeline (`metrics_aggregator` → `MONTH#YYYY-MM`) still writes records but has **no active readers**. It can be disabled in a follow-up by setting `WRITE_OTEL_QUOTA_RECORDS=false` or removing the metrics_aggregator Lambda. Existing `MONTH#YYYY-MM` records remain in DynamoDB but are inert.

### Pricing Table

Ensure `BedrockPricing` DynamoDB table has entries for models in use. Without pricing data, the stream/reconciler fall back to hardcoded most-expensive pricing (Opus-class: $15/$75 per 1M tokens). Seed with:

```bash
poetry run ccwb quota set-pricing --defaults
```

### UTC+8 Timezone Boundaries

All daily/monthly boundaries use UTC+8 (matching `quota_check` and `quota_monitor`). The `EFFECTIVE_TZ = timezone(timedelta(hours=8))` is defined in `bedrock_usage_utils.py` and used by stream/reconciler for deriving `MONTH#YYYY-MM` and `DAY#YYYY-MM-DD` partition keys from log timestamps.

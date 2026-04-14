# Tasks: Cost Management Hardening

## Phase 1: Client-side Hardening + TVM + Refresh Token

- [ ] 1.1 Create TVM Lambda and update credential-process to use it
  - [ ] 1.1.1 Create `deployment/infrastructure/lambda-functions/tvm/index.py` — TVM Lambda handler: extract email from API Gateway JWT Authorizer claims via `event.requestContext.authorizer.jwt.claims["email"]` (Cognito only — other IdPs out of scope), call `_upsert_profile(email)`, check `PROFILE.status`, resolve quota policy, call `get_user_usage(email)` to read `MONTH#YYYY-MM#BEDROCK` usage (single source), compute adaptive session duration via `_compute_session_duration(usage, policy)`, call `sts:AssumeRole` with session policy (`aws:EpochTime` condition for effective duration) and override `Expiration` in response; parse and log `X-OTEL-Helper-Status` header, optionally enforce via `REQUIRE_OTEL_HELPER` env var
  - [ ] 1.1.2 Add `_upsert_profile(email)` to TVM Lambda — upsert `USER#{email} SK=PROFILE` with `first_activated` (if_not_exists), `last_seen`, `status` (defaults to "active"), `sub`; no IDENTITY# records needed
  - [ ] 1.1.3 Add `_compute_session_duration(usage, policy)` and `_assume_role_for_user(email, effective_seconds)` to TVM Lambda — `_compute_session_duration` maps quota ratio to effective duration (< 80% → 900s, 80-90% → 300s, 90-95% → 120s, >= 95% → 60s); `_assume_role_for_user` sanitizes email for RoleSessionName (max 64 chars total, `[\w+=,.@-]` only, prefix "ccwb-"), builds session policy with `aws:EpochTime` condition set to `now + effective_seconds`, calls `sts.assume_role(DurationSeconds=max(900, effective_seconds), Policy=session_policy)`, overrides `Expiration` in returned credentials to `now + effective_seconds`
  - [ ] 1.1.4 Update `deployment/infrastructure/quota-monitoring.yaml` — add TVM Lambda function, TVM Lambda execution role (sts:AssumeRole on BedrockUserRole, dynamodb:GetItem/PutItem/UpdateItem), BedrockUserRole (trusted by TVM execution role, grants bedrock:InvokeModel*); add `/tvm` POST route + Lambda integration on the existing HTTP API Gateway (reuse JWT Authorizer from quota_check); configure route-level throttling (e.g., 100 req/s burst); add `BEDROCK_USER_ROLE_ARN`, `TVM_SESSION_DURATION` (default 900) environment variables
  - [ ] 1.1.5 Update `source/credential_provider/__main__.py` — replace `_check_quota()` + direct Bedrock credential flow with `_call_tvm(id_token, otel_helper_status)` that sends an HTTP POST to `tvm_endpoint` (API Gateway `/tvm` route) with `Authorization: Bearer {id_token}` and `X-OTEL-Helper-Status` headers; no SigV4 signing or bootstrap credentials needed; receives Bedrock credentials from TVM response
  - [ ] 1.1.6 Update `source/claude_code_with_bedrock/config.py` — replace `quota_api_endpoint` with `tvm_endpoint`; add `tvm_request_timeout` (default 5s); remove `quota_fail_mode` field entirely (TVM is naturally fail-closed)
  - [ ] 1.1.7 Remove `_should_recheck_quota()`, `_get_last_quota_check_time()`, `_save_quota_check_timestamp()` methods from `source/credential_provider/__main__.py` — no longer needed since every credential issuance goes through TVM Lambda
  - [ ] 1.1.8 Refactor `run()` in `source/credential_provider/__main__.py` — in the cached-credentials path, when Bedrock credentials expire, call TVM Lambda to get new credentials (which inherently checks quota); if no valid id_token is available (both id_token and refresh_token expired), clear cached credentials and fall through to browser auth
  - [ ] 1.1.9 Remove direct Bedrock permissions from Cognito Identity Pool auth role in `deployment/infrastructure/bedrock-auth-*.yaml` or `cognito-*.yaml` — auth role no longer needs Bedrock or Lambda permissions since TVM is accessed via API Gateway with JWT auth (not IAM auth). **⚠️ MUST be executed last in Phase 1** — requires TVM Lambda deployed (1.1.4), client updated (1.1.5-1.1.8), and end-to-end verification complete before removing direct Bedrock access

- [ ] 1.2 Implement otel-helper SHA256 hash verification
  - [ ] 1.2.1 Add `_check_otel_helper_integrity()` method to `source/credential_provider/__main__.py` — compute SHA256 of otel-helper binary, compare to `config["otel_helper_hash"]`, return status string (`"valid"`, `"missing"`, `"hash-mismatch"`, `"not-configured"`); print warning to stderr for non-valid statuses but do NOT exit — status is reported to TVM Lambda for enforcement
  - [ ] 1.2.2 Call `_check_otel_helper_integrity()` in `run()` early and store the returned status for passing to `_call_tvm()`
  - [ ] 1.2.3 Update `source/claude_code_with_bedrock/cli/commands/package.py` — after building otel-helper, compute SHA256 and write `otel_helper_hash` to the profile object in `config.json`; modify `_create_config()` to accept and include `otel_helper_hash` parameter

- [ ] 1.3 Add X-OTEL-Helper-Status header to TVM request
  - [ ] 1.3.1 Update `_call_tvm()` in `source/credential_provider/__main__.py` to accept `otel_helper_status` parameter and add `X-OTEL-Helper-Status` header to the TVM Lambda request with the actual status value (`"valid"`, `"missing"`, `"hash-mismatch"`, `"not-configured"`)
  - [ ] 1.3.2 Pass the status from `_check_otel_helper_integrity()` to `_call_tvm()` in all call sites in `run()`

- [ ] 1.4 Implement refresh token support for silent credential refresh
  - [ ] 1.4.1 Update Cognito App Client (CLI) in `deployment/infrastructure/cognito-user-pool-setup.yaml` — set `RefreshTokenValidity` to 720 (minutes, i.e. 12 hours); note: `bedrock-auth-cognito-pool.yaml` only references existing User Pool/Client IDs as parameters and cannot modify App Client settings
  - [ ] 1.4.2 Update `authenticate_oidc()` in `source/credential_provider/__main__.py` — currently returns `tokens["id_token"], id_token_claims` and discards `refresh_token`; modify to also save `refresh_token` from the token response to dedicated storage (task 1.4.5) before returning; note: Cognito App Client already has `AllowedOAuthFlows: code` + `AllowedOAuthScopes: openid` + `ALLOW_REFRESH_TOKEN_AUTH` which are required for refresh_token to be returned; other IdP providers (Okta, Azure AD, etc.) are out of scope — only Cognito refresh_token flow is implemented
  - [ ] 1.4.3 Add `_try_refresh_token()` method — POST to `{cognito_domain}/oauth2/token` with `grant_type=refresh_token`, return new id_token or None
  - [ ] 1.4.4 Refactor `_try_silent_refresh()` — keep existing return signature `Tuple[credentials, id_token, token_claims]`; after trying cached id_token (existing behavior), add fallback to call `_try_refresh_token()` when id_token is expired; when a valid id_token is obtained, call `_call_tvm()` to get Bedrock credentials
  - [ ] 1.4.5 Add refresh_token to dedicated storage (similar to monitoring token) — save via keyring or session file (e.g., `{profile}-refresh-token.json`), NOT in `save_credentials()` which stores AWS credentials
  - [ ] 1.4.6 Update `clear_cached_credentials()` in `source/credential_provider/__main__.py` — add cleanup of refresh_token from keyring (`{profile}-refresh-token`) and session file (`{profile}-refresh-token.json`), matching the existing pattern for monitoring token cleanup

---

## Phase 2: Bedrock Logging Config

- [ ] 2.1 Add bedrock_logging_config Custom Resource Lambda
  - [ ] 2.1.1 Create `deployment/infrastructure/lambda-functions/bedrock_logging_config/index.py` — CloudFormation Custom Resource handler: on Create/Update, call `bedrock.get_model_invocation_logging_configuration()`; if already enabled, record existing S3 bucket and return success (skip); if not enabled, create S3 bucket via `s3.create_bucket()`, call `bedrock.put_model_invocation_logging_configuration()` to enable logging to that bucket, return bucket name
  - [ ] 2.1.2 Update `deployment/infrastructure/quota-monitoring.yaml` — add Custom Resource, IAM role for bedrock_logging_config Lambda (needs `bedrock:GetModelInvocationLoggingConfiguration`, `bedrock:PutModelInvocationLoggingConfiguration`, `s3:CreateBucket`, `s3:PutBucketPolicy` permissions)

---

## Phase 3: Bedrock Usage Tracking + Admin UI

- [ ] 3.1 Create bedrock_usage_stream Lambda
  - [ ] 3.1.1 Create `deployment/infrastructure/lambda-functions/bedrock_usage_stream/index.py` — SQS batch handler: parse S3 object keys from event, read Bedrock invocation log JSON (see design doc "Bedrock Invocation Log Schema Reference" for verified field paths); **after parsing each S3 object, immediately write processed marker `PK=PROCESSED#{sha256(s3_key)[:16]}` with TTL=48h** (before email check — ensures non-TVM logs are also marked so reconciler skips them); extract `identity.arn` for email (from RoleSessionName, e.g., `assumed-role/BedrockUserRole/ccwb-user@example.com` -> `user@example.com`) — if email cannot be parsed, log warning and skip (marker already written); extract `timestamp` (top-level), `modelId` (full ARN — extract short model ID via last path segment for pricing lookup), `input.inputTokenCount`, `output.outputTokenCount`, `input.cacheReadInputTokenCount`, `input.cacheWriteInputTokenCount`; **convert log `timestamp` (UTC) to UTC+8** to derive `MONTH#YYYY-MM` partition and `daily_date` (do NOT use Lambda wall clock — critical for delayed/DLQ/reconciler events); atomically ADD tokens/cost to `USER#{email} MONTH#YYYY-MM#BEDROCK` (monthly totals via ADD; daily totals via three-step conditional update — Step 1: ADD with `ConditionExpression="daily_date = :d OR attribute_not_exists(daily_date)"`; Step 2 on ConditionalCheckFailed: SET daily fields + date with `ConditionExpression="daily_date <> :d"`; Step 3 on second ConditionalCheckFailed: ADD all — another instance already rolled over); also atomically ADD monthly totals to `ORG#global MONTH#YYYY-MM#BEDROCK` for org-level quota checks; return `batchItemFailures` for partial failures
  - [ ] 3.1.2 Update `deployment/infrastructure/quota-monitoring.yaml` — add SQS Queue, DLQ, SQS Queue Policy (allow S3 bucket), S3 Bucket NotificationConfiguration for `s3:ObjectCreated:*` -> SQS (**note**: if S3 bucket is pre-existing, cannot use CloudFormation `NotificationConfiguration` — must configure via `bedrock_logging_config` Custom Resource Lambda or AWS CLI to avoid overwriting existing notifications), Lambda function, Lambda SQS Event Source Mapping (BatchSize=100, MaximumBatchingWindowInSeconds=60, ReportBatchItemFailures), and IAM role with `s3:GetObject` and DynamoDB permissions

- [ ] 3.2 Create bedrock_usage_reconciler Lambda
  - [ ]* 3.2.1 Create `deployment/infrastructure/lambda-functions/bedrock_usage_reconciler/index.py` — EventBridge-triggered handler: list S3 objects in last 35-minute window, **batch-check `PROCESSED#{sha256(s3_key)[:16]}` markers in DynamoDB (BatchGetItem) to skip already-processed objects without reading S3**, process remaining objects (same logic as stream Lambda — extract email from `identity.arn` RoleSessionName, parse `input.inputTokenCount`/`output.outputTokenCount`/cache tokens, extract short model ID from `modelId` ARN, **derive month/date from log timestamp UTC→UTC+8**, update both user and ORG aggregate records, **write processed marker with TTL=48h**), drain DLQ (up to 100 messages), write heartbeat to `SYSTEM#reconciler`
  - [ ]* 3.2.2 Update `deployment/infrastructure/quota-monitoring.yaml` — add EventBridge schedule (every 30min), reconciler Lambda function and IAM role, SNS topic for alerts

- [ ] 3.3 Verify TVM Lambda usage reads from Bedrock records
  - [ ] 3.3.1 Verify `get_user_usage()` in TVM Lambda (`deployment/infrastructure/lambda-functions/tvm/index.py`) — reads `MONTH#YYYY-MM#BEDROCK` record only (single source of truth from Bedrock invocation logs); returns zero-filled dict if record missing
  - [ ] 3.3.2 Verify org-level quota check in TVM Lambda — reads `ORG#global MONTH#YYYY-MM#BEDROCK` aggregate record maintained by stream Lambda (O(1) point read, no user scan)

- [ ] 3.4 Add pricing configuration support
  - [ ] 3.4.1 Add pricing lookup to stream Lambda and reconciler — query `BedrockPricing` table by `model_id` (no prefix), fall back to `DEFAULT_PRICING_JSON` env var, fall back to most expensive model price
  - [ ] 3.4.2 Update `deployment/infrastructure/quota-monitoring.yaml` — add `DEFAULT_PRICING_JSON` environment variable to stream and reconciler Lambda definitions

- [ ] 3.5 Update admin panel for user management
  - [ ] 3.5.1 Update `api_list_users()` in `deployment/infrastructure/lambda-functions/landing_page_admin/index.py` — query `SK=PROFILE` records instead of `MONTH#` records; include `status`, `first_activated`, `last_seen` fields; support `?status=active|disabled|all` filter
  - [ ] 3.5.2 Add `api_disable_user()` and `api_enable_user()` handlers — `disable` sets `PROFILE.status = "disabled"` via DynamoDB UpdateItem; TVM Lambda will deny all subsequent credential requests for this user; `enable` sets `PROFILE.status = "active"`
  - [ ] 3.5.3 Update Users tab UI in `landing_page_admin/index.py` — add Status badge column, First Activated column, Last Seen column, Disable/Enable action buttons with confirmation dialog, status filter dropdown
  - [ ] 3.5.4 Add pricing management UI to admin panel — list `BedrockPricing` table records, allow inline editing of per-token prices, call update API on save

---

## Phase 4: Alerting + Monitoring

- [ ] 4.1 Add pipeline health monitoring CloudWatch Alarms
  - [ ] 4.1.1 Update `deployment/infrastructure/quota-monitoring.yaml` — add CloudWatch Alarm for stream Lambda `Errors > 0` for 5 minutes -> SNS
  - [ ]* 4.1.2 Update `deployment/infrastructure/quota-monitoring.yaml` — add CloudWatch Alarm for reconciler Lambda errors -> SNS
  - [ ] 4.1.3 Update `deployment/infrastructure/quota-monitoring.yaml` — add CloudWatch Alarm for DynamoDB `ThrottledRequests` -> SNS
  - [ ]* 4.1.4 Update `quota_monitor` Lambda — check `SYSTEM#reconciler last_run`; if older than 45 minutes, publish SNS heartbeat alert

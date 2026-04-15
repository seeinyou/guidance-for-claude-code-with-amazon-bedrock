# Requirements: Cost Management Hardening

**Scope**: Cognito User Pool is the sole supported identity provider. Other IdP integrations (Okta, Azure AD, etc.) are out of scope for this iteration.

## Phase 1: Client-side Hardening + TVM + Refresh Token

### 1. otel-helper SHA256 Hash Verification

**User Story:** As a system administrator, I want the credential-process to verify the otel-helper binary's integrity and report the result to the server, so that the server can enforce helper presence and detect tampering.

**Acceptance Criteria:**

1. GIVEN `otel_helper_hash` is configured in `config.json`, WHEN credential-process starts, THEN it computes the SHA256 hash of the otel-helper binary and records the integrity status (`"valid"`, `"missing"`, `"hash-mismatch"`) before proceeding.
2. GIVEN the otel-helper binary is missing, WHEN credential-process runs, THEN it records the status as `"missing"`, prints a warning to stderr, and continues execution (the status is sent to the TVM Lambda via the `X-OTEL-Helper-Status` header for server-side enforcement).
3. GIVEN the otel-helper binary hash does not match `otel_helper_hash`, WHEN credential-process runs, THEN it records the status as `"hash-mismatch"`, prints a warning to stderr, and continues execution (the status is sent to the TVM Lambda for server-side enforcement).
4. GIVEN `otel_helper_hash` is not present in `config.json`, WHEN credential-process runs, THEN it records the status as `"not-configured"`, prints a warning to stderr, and continues execution.
5. GIVEN the `package` command is run, WHEN it builds the otel-helper binary, THEN it computes the SHA256 hash and writes it to the profile object in `config.json` as `otel_helper_hash` (inside the profile's nested object, e.g., `{"profile_name": {"otel_helper_hash": "..."}}`).
6. GIVEN the otel-helper binary path, WHEN on Windows, THEN the path is `~/claude-code-with-bedrock/otel-helper.exe`; on macOS/Linux it is `~/claude-code-with-bedrock/otel-helper`.
7. GIVEN the server has `REQUIRE_OTEL_HELPER` set to `"true"`, WHEN the `X-OTEL-Helper-Status` header value is not `"valid"`, THEN the TVM Lambda denies credential issuance — this is the primary enforcement mechanism.

### 2. Mandatory Credential Issuance via TVM Lambda

**User Story:** As a system administrator, I want every credential-process invocation to obtain Bedrock credentials exclusively through the TVM Lambda, so that quota enforcement is inherently applied on every credential issuance with no possibility of client-side bypass.

**Acceptance Criteria:**

1. GIVEN credential-process is invoked and `tvm_endpoint` is configured, THEN it sends an HTTP POST to the TVM API Gateway endpoint (`/tvm` route on the existing HTTP API Gateway) with `Authorization: Bearer {id_token}` header and `X-OTEL-Helper-Status` header. The API Gateway JWT Authorizer validates the Cognito id_token before forwarding to the TVM Lambda. The TVM Lambda extracts email from validated token claims, checks quota, and issues Bedrock credentials (via its own `sts:AssumeRole`) in a single request. No bootstrap credentials or SigV4 signing needed — the id_token serves as both authentication and identity.
2. GIVEN the TVM Lambda is unreachable (HTTP timeout or error), WHEN credential-process is invoked, THEN no Bedrock credentials are issued (naturally fail-closed). There is no `quota_fail_mode` configuration — the architecture is inherently fail-closed because credentials can only come from the TVM Lambda.
3. GIVEN cached Bedrock credentials have expired, WHEN credential-process is invoked, THEN it must call the TVM Lambda again to obtain new credentials. Every credential issuance passes through quota enforcement. The effective session duration is adaptive based on quota proximity (see AC6-AC8).
4. GIVEN the TVM Lambda requires a valid id_token, WHEN the cached id_token is expired, THEN credential-process uses the refresh_token to obtain a new id_token before calling the TVM Lambda (see Requirement 4).
5. GIVEN both id_token and refresh_token are expired, WHEN credential-process is invoked, THEN it clears cached credentials and falls through to browser authentication (which then calls the TVM Lambda).
6. GIVEN the TVM Lambda issues credentials, THEN it computes an effective session duration based on the highest quota utilization ratio across all dimensions (monthly cost, monthly tokens, daily cost, daily tokens): `< 80%` → 900s (default), `80-90%` → 300s, `90-95%` → 120s, `>= 95%` → 60s.
7. GIVEN the effective session duration is shorter than 900s (STS minimum), WHEN the TVM Lambda calls `sts:AssumeRole`, THEN it attaches a session policy with `aws:EpochTime` condition set to `now + effective_seconds`, so that Bedrock API calls are denied server-side after the effective window — even if the client caches the STS credentials.
8. GIVEN the TVM Lambda returns credentials to the client, THEN the `Expiration` field is set to `now + effective_seconds` (not the STS credential's actual expiration), so that the AWS SDK re-invokes credential-process at the correct time.

### 3. X-OTEL-Helper-Status Header in TVM Request

**User Story:** As a system administrator, I want the TVM request to include the otel-helper integrity status, so that the server can log and optionally enforce helper presence.

**Acceptance Criteria:**

1. GIVEN credential-process calls the TVM Lambda, THEN the request includes an `X-OTEL-Helper-Status` header with one of: `"valid"`, `"missing"`, `"hash-mismatch"`, `"not-configured"`.
2. GIVEN `otel_helper_hash` is configured and hash matches, THEN the header value is `"valid"`.
3. GIVEN `otel_helper_hash` is configured and binary is missing, THEN the header value is `"missing"`.
4. GIVEN `otel_helper_hash` is configured and hash does not match, THEN the header value is `"hash-mismatch"`.
5. GIVEN `otel_helper_hash` is not present in `config.json`, THEN the header value is `"not-configured"`.
6. GIVEN the TVM Lambda receives the `X-OTEL-Helper-Status` header, THEN it logs the value.
7. GIVEN `REQUIRE_OTEL_HELPER` environment variable is set to `"true"` on the TVM Lambda, WHEN the header value is not `"valid"`, THEN the TVM Lambda returns denied and does not issue Bedrock credentials.

### 4. Refresh Token Support for Silent Credential Refresh

**User Story:** As an end user, I want my credentials to refresh silently for up to 12 hours without browser popups, so that I only need to log in once per workday.

**Acceptance Criteria:**

1. GIVEN a successful OIDC authentication, WHEN the token response includes a `refresh_token`, THEN credential-process saves it alongside the id_token.
2. GIVEN the id_token is expired but the refresh_token is valid, WHEN credential-process needs to call the TVM Lambda, THEN it calls `POST {cognito_domain}/oauth2/token` with `grant_type=refresh_token` and obtains a new id_token without browser interaction, then uses the new id_token to call the TVM Lambda.
3. GIVEN the refresh_token is stored, THEN it is saved in a dedicated storage location (similar to monitoring token storage) — in the OS keyring on Windows/macOS or a session file with restricted permissions on Linux — separate from AWS credential storage.
4. GIVEN both id_token and refresh_token are expired, WHEN credential-process runs, THEN it clears cached credentials and falls through to the browser authentication flow.
5. GIVEN the Cognito User Pool App Client, THEN `RefreshTokenValidity` is set to 720 minutes (12 hours).
6. GIVEN the existing `_try_silent_refresh()` method (which currently only tries cached id_token), THEN it is refactored to also attempt refresh_token exchange when the id_token is expired, then call the TVM Lambda with the new id_token to obtain Bedrock credentials, returning `Tuple[credentials, id_token, token_claims]` to match the existing return signature.

### 5. User Profile Registration via TVM Lambda

**User Story:** As a system, I want the TVM Lambda to register and maintain user profiles during credential issuance, so that user status can be tracked and enforced without requiring separate identity mapping records.

**Acceptance Criteria:**

1. GIVEN a credential-process invocation calls the TVM Lambda with a valid id_token, WHEN the TVM Lambda validates the JWT, THEN it extracts the user's email directly from the token claims — no external identity headers are needed.
2. GIVEN the TVM Lambda has extracted the email from the JWT, THEN it creates or updates `USER#{email} SK=PROFILE` with `first_activated` (using DynamoDB `if_not_exists` — never overwritten), `last_seen` (always updated), `status` (defaults to `"active"` on creation), `sub` (from JWT claims).
3. GIVEN the TVM Lambda is called multiple times for the same email, THEN `first_activated` remains unchanged after the first call.
4. GIVEN the TVM Lambda processes a request, THEN it reads `USER#{email} SK=PROFILE` and checks `status` before resolving quota policy and issuing credentials.
5. GIVEN `PROFILE.status = "disabled"`, WHEN the TVM Lambda is called, THEN it returns an error (no Bedrock credentials issued). The TVM is the sole credential issuer, so no additional token revocation is needed.
6. GIVEN a user is disabled via the admin panel, WHEN the disable API is called, THEN the server sets `PROFILE.status = "disabled"`. The TVM Lambda will deny all subsequent credential requests for this user.

---

## Phase 2: Bedrock Logging Config

### 6. Bedrock Model Invocation Logging for New Deployments

**User Story:** As a system administrator deploying a new instance, I want Bedrock Model Invocation Logging to be automatically enabled if not already configured, so that server-side usage tracking works without manual steps.

**Acceptance Criteria:**

1. GIVEN a new deployment via CloudFormation, WHEN the stack is created, THEN a Custom Resource Lambda (`bedrock_logging_config`) calls `bedrock.get_model_invocation_logging_configuration()` to check the current logging status.
2. GIVEN Bedrock logging is already enabled, WHEN the Lambda checks, THEN it records the existing S3 bucket name in the CloudFormation outputs and skips configuration (no-op).
3. GIVEN Bedrock logging is NOT enabled, WHEN the Lambda runs, THEN it creates an S3 bucket (named via CloudFormation parameter or auto-generated), calls `bedrock.put_model_invocation_logging_configuration()` to enable logging to that bucket, and returns the bucket name in outputs.
4. GIVEN the Custom Resource Lambda, WHEN invoked on stack Update, THEN it re-checks logging status and only acts if logging is not enabled.
5. GIVEN the Custom Resource Lambda, WHEN invoked on stack Delete, THEN it handles cleanup gracefully without error (does NOT disable logging or delete the bucket).
6. GIVEN `quota-monitoring.yaml`, THEN it includes the S3 bucket resource (with `DeletionPolicy: Retain`), Custom Resource, and IAM role for the bedrock_logging_config Lambda.

---

## Phase 3: Bedrock Usage Tracking + Admin UI

### 7. S3 Event -> SQS -> bedrock_usage_stream Lambda

**User Story:** As a system administrator, I want Bedrock usage to be tracked in near-real-time from invocation logs, so that quota enforcement reflects actual usage even when the OTEL pipeline is unavailable.

**Acceptance Criteria:**

1. GIVEN a Bedrock invocation log file written to S3, WHEN an `s3:ObjectCreated:*` event fires, THEN an SQS message is sent to the `BedrockLogQueue`.
2. GIVEN the SQS queue, THEN it has a visibility timeout of 300 seconds, message retention of 24 hours, and a DLQ with `maxReceiveCount: 3`.
3. GIVEN the DLQ, THEN it retains messages for 14 days.
4. GIVEN the Lambda SQS Event Source Mapping, THEN `BatchSize` is 100 and `MaximumBatchingWindowInSeconds` is 60.
5. GIVEN the Lambda SQS Event Source Mapping, THEN `FunctionResponseTypes` includes `ReportBatchItemFailures`.
6. GIVEN a batch of SQS messages, WHEN the stream Lambda processes them, THEN it reads each S3 object, parses the Bedrock invocation log JSON, and extracts top-level `timestamp`, `modelId` (full ARN — extract short model ID via last path segment for pricing lookup), nested token counts `input.inputTokenCount`, `output.outputTokenCount`, `input.cacheReadInputTokenCount`, `input.cacheWriteInputTokenCount`, and `identity.arn` (IAM principal). See design doc "Bedrock Invocation Log Schema Reference" for the verified JSON structure.
7. GIVEN a parsed invocation log, WHEN the stream Lambda extracts the email from the RoleSessionName in `identity.arn` (e.g., `arn:aws:sts::...:assumed-role/BedrockUserRole/ccwb-user@example.com` -> `user@example.com`), THEN it converts the log's `timestamp` (UTC) to UTC+8, and uses the converted timestamp to determine both `MONTH#YYYY-MM` and `DAY#YYYY-MM-DD` partitions. It atomically adds tokens and calculated cost to two independent DynamoDB records: `USER#{email} SK=MONTH#YYYY-MM#BEDROCK` (monthly aggregate) and `USER#{email} SK=DAY#YYYY-MM-DD#BEDROCK` (daily record). Both records use unconditional ADD — no ConditionExpression, no rollover logic. Each day is an independent record, safe under concurrency and any event ordering (ADD is commutative). **Important**: the month and date MUST be derived from the invocation log's timestamp (converted to UTC+8), NOT from Lambda's wall clock — this ensures correct attribution when processing delayed/DLQ/reconciler events.
8. GIVEN a parsed invocation log, WHEN the email cannot be extracted from `identity.arn` (non-matching pattern), THEN the stream Lambda logs a warning and skips the record.
9. GIVEN a processing failure for one message in a batch, THEN only that message's ID is returned in `batchItemFailures` — other messages are not retried.
10. GIVEN the SQS Queue Policy, THEN it allows the Bedrock log S3 bucket to send messages via `sqs:SendMessage`.
11. GIVEN the stream Lambda has read and parsed an S3 object (regardless of whether the email was extractable from the ARN), THEN it writes a processed marker `PK=PROCESSED#{sha256(s3_key)[:16]}` with a TTL of 48 hours to DynamoDB. This allows the reconciler to skip already-processed objects — including non-TVM invocation logs — without re-reading them from S3.

### 8. bedrock_usage_reconciler Lambda

**User Story:** As a system administrator, I want a periodic reconciler to catch any missed Bedrock usage events, so that usage data is complete even if the stream Lambda fails.

**Acceptance Criteria:**

1. GIVEN an EventBridge schedule, THEN the reconciler Lambda runs every 30 minutes.
2. GIVEN the reconciler runs, THEN it lists S3 objects in the last 35-minute window using the Bedrock log key prefix.
3. GIVEN an S3 object listed by the reconciler, WHEN it checks DynamoDB for `PK=PROCESSED#{sha256(s3_key)[:16]}` and the record exists, THEN the reconciler skips the object without reading it from S3. WHEN the record does not exist, THEN the reconciler processes it identically to the stream Lambda (extracting email from ARN RoleSessionName) and writes the same processed marker with 48-hour TTL.
4. GIVEN the DLQ contains messages, WHEN the reconciler runs, THEN it drains and reprocesses up to 100 DLQ messages.
5. GIVEN a successful reconciler run, THEN it writes `PK=SYSTEM#reconciler` with `last_run` timestamp.
6. GIVEN the reconciler Lambda, THEN its timeout is set to 5 minutes.

### 9. TVM Lambda Bedrock Usage Enforcement

**User Story:** As a system, I want quota enforcement to use Bedrock invocation log data as the single source of truth for usage tracking, so that quota limits are enforced based on actual AWS-recorded usage that cannot be tampered with client-side.

**Acceptance Criteria:**

1. GIVEN `get_user_usage(email)` is called in the TVM Lambda, THEN it reads the `MONTH#YYYY-MM#BEDROCK` record for the user (single source — Bedrock invocation logs only).
2. GIVEN the record exists, THEN the returned dict contains all usage fields from the Bedrock invocation log pipeline.
3. GIVEN the record does not exist, THEN all fields return zero (new user or no usage this month).
4. GIVEN org-level quota checks, THEN the stream Lambda atomically maintains `ORG#global MONTH#YYYY-MM#BEDROCK` via ADD operations alongside per-user updates. The TVM Lambda reads this single record for org-level checks — O(1), no user scan needed.
5. GIVEN `get_user_usage()` results in quota exceeded (any dimension: monthly/daily tokens or cost), WHEN the TVM Lambda denies the request, THEN it returns an error with the exceeded dimension. No additional token revocation is needed — the TVM will continue to deny on every subsequent credential request until usage resets.

### 10. Pricing Configuration

**User Story:** As a system administrator, I want to configure model pricing in DynamoDB, so that Bedrock usage cost calculations are accurate and updatable without redeployment.

**Acceptance Criteria:**

1. GIVEN a Bedrock invocation log, WHEN calculating cost, THEN the stream Lambda and reconciler look up the `model_id` in the existing `BedrockPricing` DynamoDB table (key: `model_id`, no prefix).
2. GIVEN no DynamoDB pricing record for a model, THEN the Lambda falls back to the `DEFAULT_PRICING_JSON` environment variable.
3. GIVEN no pricing in either DynamoDB or environment variable for a model, THEN the Lambda uses the most expensive known model's pricing as fallback.
4. GIVEN `quota-monitoring.yaml`, THEN it includes the `DEFAULT_PRICING_JSON` environment variable on both stream and reconciler Lambdas.

### 11. Admin Panel User Management

**User Story:** As a system administrator, I want to view all users (including historically inactive ones), see their status, and disable/enable access, so that I can manage user access independently of quota policies.

**Acceptance Criteria:**

1. GIVEN the admin panel Users tab, WHEN listing users, THEN it reads from `USER#{email} SK=PROFILE` records (not `MONTH#` records).
2. GIVEN the user list, THEN it includes columns: email, `status` (active/disabled badge), `first_activated`, `last_seen`.
3. GIVEN a user with `status = "active"`, THEN the UI shows a `Disable` button (red/warning color).
4. GIVEN a user with `status = "disabled"`, THEN the UI shows an `Enable` button (green) and the row is visually grayed out.
5. GIVEN clicking Disable or Enable, THEN a confirmation dialog is shown before the API call is made.
6. GIVEN `POST /admin/user/disable {email}`, THEN it sets `USER#{email} PROFILE.status = "disabled"`. After disable, the TVM Lambda will deny all subsequent credential requests for this user.
7. GIVEN `POST /admin/user/enable {email}`, THEN it sets `USER#{email} PROFILE.status = "active"`.
8. GIVEN a successful disable/enable operation, THEN the user list refreshes and shows the updated status.
9. GIVEN the user list, THEN it supports filtering by status: All / Active / Disabled.
10. GIVEN the admin panel, THEN it includes a pricing management UI showing all `BedrockPricing` table records with the ability to update them.

---

## Phase 4: Alerting + Monitoring

### 12. Pipeline Health Monitoring

**User Story:** As a system administrator, I want CloudWatch alarms for the Bedrock usage tracking pipeline, so that I am alerted if the pipeline fails.

**Acceptance Criteria:**

1. GIVEN the stream Lambda has errors, WHEN `Errors > 0` for 5 consecutive minutes, THEN a CloudWatch Alarm triggers and sends an SNS notification.
2. GIVEN the reconciler heartbeat (`PK=SYSTEM#reconciler last_run`), WHEN `quota_monitor` checks it and finds it older than 45 minutes, THEN it publishes an SNS alert.
3. GIVEN DynamoDB `ThrottledRequests` metric exceeds threshold, THEN a CloudWatch Alarm triggers and sends an SNS notification.
4. GIVEN `quota-monitoring.yaml`, THEN it includes CloudWatch Alarms for stream Lambda errors, reconciler errors, and DynamoDB throttling.

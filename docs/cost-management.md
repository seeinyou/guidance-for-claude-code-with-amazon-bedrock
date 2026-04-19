# Cost Management Architecture

This document describes the server-side cost management pipeline introduced
on the `experiment/no-packaging-tools` branch. It replaces the client-side
quota check model with a Token Vending Machine (TVM) and a Bedrock
invocation-log pipeline that feed the admin panel.

See [admin-guide.md](admin-guide.md) for operator-facing policy
management; see [user-guide.md](user-guide.md) for the end-user
experience.

## Components

```
credential-process ──(id_token)──► TVM Lambda ──► STS ──► BedrockUserRole
                                      │
                                      ├─ quota check (synchronous, fail-closed)
                                      └─ user PROFILE / status check

Bedrock InvokeModel ──► Model Invocation Logging ──► S3 ──► SQS
                                                              │
                                                              ▼
                                                     bedrock_usage_stream
                                                              │
                                                              ▼
                                                    UserQuotaMetrics
                                                     (MONTH#…#BEDROCK,
                                                      DAY#…#BEDROCK)
                                                              ▲
                                                              │
                                          bedrock_usage_reconciler (30 min)
```

### Token Vending Machine (`tvm` Lambda)

`POST /tvm` is the only path the client uses to obtain AWS credentials. It:

- Validates the IdP `id_token` (Cognito JWT verification).
- Looks up `USER#{email} SK=PROFILE`; denies if `status=disabled`.
- Calls the quota check synchronously; denies on any over-limit dimension.
- Calls STS `AssumeRoleWithWebIdentity` against `BedrockUserRole` (Bedrock-
  scoped) and returns short-lived credentials to the client.

The auth role for interactive users no longer has `bedrock:InvokeModel*`
permissions — all Bedrock access flows through the TVM-issued role.

### Bedrock usage pipeline

Bedrock's native Model Invocation Logging publishes every call to S3. An S3
event notification fans out through SQS into two Lambdas:

- `bedrock_usage_stream` — processes each log record as it arrives, writes
  `USER#{email} SK=MONTH#YYYY-MM#BEDROCK` and `DAY#YYYY-MM-DD#BEDROCK`
  items to `UserQuotaMetrics`.
- `bedrock_usage_reconciler` — EventBridge-triggered every 30 minutes,
  scans the last window for missed/late events, and drains the DLQ.

Alarms (`StreamLambdaErrorAlarm`, `ReconcilerLambdaErrorAlarm`,
`DynamoDBThrottleAlarm`) watch the pipeline health; the quota monitor
Lambda also checks a reconciler heartbeat.

### User PROFILE records

Every active user gets a `USER#{email} SK=PROFILE` item with:

- `status` — `active` or `disabled`
- `first_activated`, `last_seen`
- per-month `first_seen_month` for admin UI

The admin panel uses PROFILE for the Users tab; disable/enable is a simple
`status` flip on this record and takes effect on the next TVM call.

## Config changes

`config.json` fields used by the credential process:

| Field | Purpose |
|------|---------|
| `tvm_endpoint` | `POST` target for credential issuance |
| `tvm_request_timeout` | TVM request timeout in seconds (default 10) |
| `otel_helper_hash` | SHA256 of the packaged `otel-helper` — integrity check, reported to TVM via `X-OTEL-Helper-Status` header |
| `quota_check_interval` | How often to re-check quota on cached credentials (minutes) |

Removed in this branch: `quota_api_endpoint`, `quota_fail_mode` (the old
client-side `/check` path).

## Client refresh flow

- The credential process stores the Cognito `refresh_token` in the OS
  keyring (or session file, per profile config).
- Cognito User Pool `RefreshTokenValidity` is 12h (720 minutes). On
  `id_token` expiry the client attempts a silent refresh; only a hard
  refresh-token failure prompts the browser flow again.
- Refresh token is wiped on `--clear-cache`.

## Stack → Lambda mapping

| `ccwb deploy` | Template | Lambdas |
|---|---|---|
| `quota` | `quota-monitoring.yaml` | `tvm`, `quota_monitor`, `quota_check`, `bedrock_usage_stream`, `bedrock_usage_reconciler`, `bedrock_logging_config` |
| `distribution` | `landing-page-distribution.yaml` | `landing_page_admin` |
| `dashboard` | `claude-code-dashboard.yaml` | `metrics_aggregator` |
| `auth` | `bedrock-auth-{provider}.yaml` | (IAM only) |

## Admin panel changes

- Users tab reads `USER#…#PROFILE` + `#BEDROCK` usage records (not OTEL).
- Status badges (active / disabled / over-quota) derived from PROFILE +
  current usage.
- Disable/enable user buttons call the admin API, which flips PROFILE
  status. The next TVM call sees the new status.
- Pricing tab still manages `BedrockPricing` entries; cost columns in the
  Users tab use the same table.

## Operational notes

- **Fail-closed**: if TVM cannot reach DynamoDB for the quota or PROFILE
  check, the request is denied. This is intentional — the client has no
  fallback Bedrock permissions.
- **Logging prefix**: Bedrock log objects must match the prefix the stream
  Lambda watches. See `docs/wps-bedrock-logging-prefix-mismatch.md` for the
  one known gotcha when an existing log config is reused.
- **Timezone**: all day/month rollovers use UTC+8 (consistent with the
  quota check logic in `admin-guide.md`).
- **otel-helper integrity**: if the hash does not match, the client emits
  `X-OTEL-Helper-Status: mismatch` but does not fail; TVM logs the event
  for the admin panel. A missing hash field (old clients) reports
  `not-configured` and is treated as benign.

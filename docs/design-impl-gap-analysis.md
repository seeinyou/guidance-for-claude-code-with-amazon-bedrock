# Cost Management Hardening — Design vs Implementation Gap Analysis

**Date:** 2026-04-14 (verified)
**Branch:** `feat/cost-management-hardening`
**Spec:** `.kiro/specs/cost-management-hardening/`
**Plan:** `docs/superpowers/plans/2026-04-14-cost-management-hardening.md`

---

## Summary

Each item below has been individually verified against the source code.

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 1 (was 3) | C3 fixed; C1/C2 downgraded to LOW |
| MEDIUM   | 2 (was 3) | M2 fixed |
| LOW      | 5 (was 3) | C1/C2 reclassified here |
| FALSE POSITIVE | 2 | |
| **Remaining open gaps** | **8** | **0 critical after fix** |

Components verified (with manual code inspection): TVM Lambda, credential-process, bedrock_usage_stream, bedrock_usage_reconciler, bedrock_logging_config, quota-monitoring.yaml (CloudFormation), landing_page_admin, config.py, cognito-user-pool-setup.yaml, package.py.

---

## CRITICAL Issues

### ~~C1/C2. Missing `DEFAULT_PRICING_JSON` env var~~ — DOWNGRADED TO LOW

**Reclassified:** LOW — the DDB pricing table's `DEFAULT` row (fallback step 3 in the lookup chain) catches all unknown models before the env var (step 4) is ever reached. The env var is dead code path in practice. See L4/L5 below.

---

### ~~C3. Missing route-level throttling on `/tvm` POST route~~ — FIXED

**Fixed:** Added `DefaultRouteSettings` with `ThrottlingBurstLimit: 50` and `ThrottlingRateLimit: 20` to `QuotaCheckStage` in `quota-monitoring.yaml`. Stage-level throttling protects both `/tvm` and `/check` routes.

---

## MEDIUM Issues

### M1. S3 bucket for Bedrock logging created via API, not CloudFormation — no DeletionPolicy: Retain

**Verified:** YES — confirmed gap.

**Spec (Req 6, AC6):** `quota-monitoring.yaml` should include the S3 bucket resource with `DeletionPolicy: Retain`.

**Implementation:** `bedrock_logging_config/index.py:150` creates the bucket via `s3_client.create_bucket()`. No `AWS::S3::Bucket` resource exists in the CloudFormation template (confirmed: zero matches for `AWS::S3::Bucket` or `DeletionPolicy.*Retain` in the file).

**Impact:** The bucket survives stack deletion (since CFN doesn't know about it), but this is accidental — no lifecycle policy, versioning, or intentional retention. Downgraded from CRITICAL because the practical risk is low (CFN can't delete what it doesn't manage), but it diverges from the spec's intent of explicit retention.

---

### ~~M2. Admin panel `api_upsert_pricing()` vs spec's `api_update_pricing()`~~ — FIXED

**Fixed:** Renamed `api_upsert_pricing` → `api_update_pricing` in `landing_page_admin/index.py` (function definition at line 754 and router call at line 179).

---

### M3. Reconciler `records_processed` counts only S3 records, not combined S3 + DLQ

**Verified:** YES — confirmed gap.

**Spec (Req 8, AC5):** Heartbeat should include `records_processed: int`.

**Implementation:** `bedrock_usage_reconciler/index.py:113` writes `records_processed = s3_count` and separately `dlq_processed = dlq_count` (line 114).

**Impact:** Monitoring systems checking `records_processed` miss DLQ activity. The spec implies a single combined counter.

---

## LOW Issues

### L1. TVM Lambda has extra JWT fallback decode from Authorization header

**Verified:** YES — confirmed deviation.

**Spec:** Extract email from `event.requestContext.authorizer.jwt.claims["email"]` only.

**Implementation:** `tvm/index.py:85-99` adds a fallback that decodes the JWT from the Authorization header when claims are missing.

**Impact:** None — strictly more robust than spec requires. Defensive coding.

---

### L2. Reconciler heartbeat has extra `sk: "HEARTBEAT"` and `dlq_processed` fields

**Verified:** YES — confirmed deviation.

**Spec data model:** `PK=SYSTEM#reconciler (no SK)` with `last_run` and `records_processed` only.

**Implementation:** `bedrock_usage_reconciler/index.py:111` adds `sk: "HEARTBEAT"` sort key. Line 114 adds `dlq_processed` field.

**Impact:** Consumers (e.g., `quota_monitor` Lambda checking reconciler health) must know to query with `sk="HEARTBEAT"`. Extra fields are harmless.

---

### L3. Credential-process retains `get_aws_credentials()` family of methods

**Verified:** YES — confirmed dead code for TVM flow.

**Spec:** Remove direct Bedrock credential flow from `run()`.

**Implementation:** `credential_provider/__main__.py` still has `get_aws_credentials()` (line 1199), `get_aws_credentials_direct()` (line 1212), `get_aws_credentials_cognito()` (line 1332). None are called from `run()`. Only caller is `authenticate_for_monitoring()` at line 1624 (separate monitoring auth flow).

**Impact:** Dead code for the main credential flow. Retained for monitoring auth path — removal needs to verify monitoring still works.

---

### L4. Missing `DEFAULT_PRICING_JSON` env var on bedrock_usage_stream Lambda (reclassified from C1)

**Verified:** YES — env var not set in CloudFormation.

**Why LOW:** The pricing lookup chain is: DDB exact match → DDB partial match → DDB `DEFAULT` row → env var → hardcoded most-expensive. The DDB `DEFAULT` row (step 3) catches all unknown models, so the env var (step 4) is never reached in practice. The code plumbing exists (`index.py:41`) but the CFN template doesn't wire it. No operational impact.

---

### L5. Missing `DEFAULT_PRICING_JSON` env var on bedrock_usage_reconciler Lambda (reclassified from C2)

Same as L4, for the reconciler Lambda (`index.py:43`).

---

## FALSE POSITIVES (Rejected by Manual Verification)

### ~~C5. Missing S3 → SQS notification wiring~~ — FALSE POSITIVE

**Agent reported:** S3 → SQS notifications not wired in CloudFormation.

**Manual verification:** `bedrock_logging_config/index.py:196-244` implements `_configure_s3_event_notification()` which calls `s3_client.put_bucket_notification_configuration()`. This is invoked at line 72 (existing bucket) and line 112 (new bucket). The `SQSQueueArn` is passed from the CloudFormation Custom Resource properties (line 70, 110).

**Verdict:** Notification wiring is handled inside the Lambda, not in the CFN template — this is the correct approach for a pre-existing bucket. Not a gap.

---

### ~~C6. Org-level quota check separate from resolve_policy()~~ — FALSE POSITIVE

**Agent reported:** Org-level policy not integrated into `resolve_quota_for_user()` precedence chain.

**Manual verification:** `tvm/index.py:133-140` calls `check_org_limits()` BEFORE `resolve_quota_for_user()` at line 143. The design pseudocode (lines 447-449) shows the same flow: check org → resolve user policy → check user usage. The implementation matches the spec's execution order exactly. Separation into a distinct function is a structural choice, not a functional gap.

**Verdict:** Functionally correct and matches the spec's intended execution order. Not a gap.

---

## Fully Compliant Components

| Component | File | Verdict |
|-----------|------|---------|
| credential-process core flow | `source/credential_provider/__main__.py` | All 8 design requirements met |
| bedrock_usage_stream Lambda | `lambda-functions/bedrock_usage_stream/index.py` | All 17 requirements met |
| bedrock_logging_config Lambda | `lambda-functions/bedrock_logging_config/index.py` | All 5 requirements met (incl. S3 notification) |
| Config dataclass | `source/claude_code_with_bedrock/config.py` | All 5 fields correct |
| Cognito User Pool setup | `cognito-user-pool-setup.yaml` | `RefreshTokenValidity: 1440` present |
| Package command | `cli/commands/package.py` | SHA256 hash + config write correct |
| TVM adaptive session duration | `lambda-functions/tvm/index.py` | All 4 tiers + two-layer enforcement correct |
| TVM profile upsert | `lambda-functions/tvm/index.py` | `if_not_exists` + status check correct |
| TVM RoleSessionName sanitization | `lambda-functions/tvm/index.py` | 64-char limit + charset enforcement correct |
| TVM org-level quota check | `lambda-functions/tvm/index.py` | Correct execution order in handler flow |
| TVM OTEL helper enforcement | `lambda-functions/tvm/index.py` | Header parsing + REQUIRE_OTEL_HELPER correct |

---

## Recommended Action Priority

1. ~~**C3**~~ — FIXED: API Gateway throttling added (20 req/s, 50 burst).
2. ~~**C1/C2**~~ — Downgraded to LOW: DDB `DEFAULT` row covers the gap.
3. ~~**M2**~~ — FIXED: Renamed `api_upsert_pricing` → `api_update_pricing`.
4. **M1** — Open: Document the S3 bucket retention strategy or import bucket into CFN.
5. **M3** — Open: Reconciler heartbeat — combine `records_processed` or update spec to document the split.
6. **L1-L5** — Informational only, no action needed.

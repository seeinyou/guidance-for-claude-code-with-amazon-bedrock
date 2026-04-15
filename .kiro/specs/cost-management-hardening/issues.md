# Code Review Issues: Bedrock Log Processing Lambdas

## BUG 1 + BUG 2: RESOLVED -- replaced three-step conditional daily update with DAY# records

**Original bugs:**
1. (Critical) `daily_date` never initialized -- daily quotas accumulated forever, never reset
2. (Medium) Out-of-order events clobbered daily counters via backward rollover

**Resolution:** Eliminated the entire three-step conditional update pattern. Daily usage is now stored in independent `DAY#YYYY-MM-DD#BEDROCK` records (one per user per day). Both MONTH# and DAY# records use unconditional `ADD` -- no ConditionExpression, no rollover logic. Event ordering and concurrency are irrelevant since ADD is commutative.

**Changed files:**
- `deployment/infrastructure/lambda-functions/bedrock_usage_stream/index.py` -- `_update_user_usage()` rewritten
- `deployment/infrastructure/lambda-functions/bedrock_usage_reconciler/index.py` -- `_update_user_usage()` rewritten
- `deployment/infrastructure/lambda-functions/tvm/index.py` -- `get_user_usage()` now reads `DAY#{today}#BEDROCK` for daily totals
- `.kiro/specs/cost-management-hardening/design.md` -- data model, pseudocode, correctness properties updated

---

## Issue 3: RESOLVED -- reconciler now uses hour-level S3 prefixes

**Original:** `_build_s3_prefixes()` returned only a broad prefix covering all regions and dates, causing full-bucket ListObjectsV2 pagination that could exceed the 5-minute Lambda timeout.

**Fix:** `_build_s3_prefixes()` now builds hour-level prefixes: `{prefix}AWSLogs/{account}/BedrockModelInvocationLogs/{region}/{YYYY}/{MM}/{DD}/{HH}/`. A 35-minute window spans at most 2 distinct hours. Uses `AWS_REGION` for the entry region (cross-region inference logs still use the entry region in the S3 key).

---

## Issue 4: RESOLVED -- added aws:SourceAccount to SQS Queue Policy

**Original:** `BedrockLogQueuePolicy` allowed any S3 bucket to send messages -- no source restriction.

**Fix:** Added `Condition: StringEquals: aws:SourceAccount: !Ref AWS::AccountId` to the SQS queue policy in `quota-monitoring.yaml`. Only S3 buckets in the same account can now send messages.

---

## Issue 5: ACCEPTED RISK -- Pricing cache stale on warm Lambda

Pricing cache loads once per cold start and never refreshes. Accepted because:
- Pricing changes are infrequent; `ccwb deploy quota` redeploys Lambda (triggers cold start)
- Stream Lambda instances are recycled under low traffic
- Reconciler runs every 30 min with short-lived instances
- Adding TTL refresh adds DynamoDB scan overhead for a near-zero probability issue

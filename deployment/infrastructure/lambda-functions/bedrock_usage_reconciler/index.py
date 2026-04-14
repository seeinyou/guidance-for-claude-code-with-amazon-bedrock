# ABOUTME: EventBridge-triggered Lambda that runs every 30 minutes to reconcile
# ABOUTME: missed Bedrock usage events by scanning S3 logs and reprocessing the DLQ.
# ABOUTME: Shares core logic (pricing, ARN parsing, usage updates) with bedrock_usage_stream.

import gzip
import hashlib
import json
import logging
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Effective timezone for daily/monthly boundaries (UTC+8, matching quota_check)
# ---------------------------------------------------------------------------
EFFECTIVE_TZ = timezone(timedelta(hours=8))

# ---------------------------------------------------------------------------
# AWS clients (reused across warm invocations)
# ---------------------------------------------------------------------------
s3_client = boto3.client("s3")
sqs_client = boto3.client("sqs")
dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
PRICING_TABLE = os.environ.get("PRICING_TABLE", "BedrockPricing")
DEFAULT_PRICING_JSON = os.environ.get("DEFAULT_PRICING_JSON", "")
BEDROCK_LOG_BUCKET = os.environ.get("BEDROCK_LOG_BUCKET", "")
BEDROCK_LOG_PREFIX = os.environ.get("BEDROCK_LOG_PREFIX", "bedrock-raw/")
DLQ_URL = os.environ.get("DLQ_URL", "")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")

quota_table = dynamodb.Table(QUOTA_TABLE)
pricing_table = dynamodb.Table(PRICING_TABLE)

# ---------------------------------------------------------------------------
# Hardcoded most-expensive fallback pricing (Opus-class model as of 2026-04)
# Used only when both the pricing table and DEFAULT_PRICING_JSON are unavailable.
# ---------------------------------------------------------------------------
MOST_EXPENSIVE_PRICING = {
    "input_per_1m": Decimal("15"),
    "output_per_1m": Decimal("75"),
    "cache_read_per_1m": Decimal("1.875"),
    "cache_write_per_1m": Decimal("18.75"),
}

# In-memory pricing cache (refreshed once per cold start / invocation cycle)
_pricing_cache: dict[str, dict] = {}
_pricing_cache_loaded = False

# ---------------------------------------------------------------------------
# ARN parsing patterns
# ---------------------------------------------------------------------------
# Matches: arn:aws:sts::<account>:assumed-role/<role>/ccwb-<email>
_IDENTITY_RE = re.compile(
    r"^arn:aws:sts::\d+:assumed-role/[^/]+/ccwb-(.+)$"
)

# ---------------------------------------------------------------------------
# Processed marker TTL: 48 hours
# ---------------------------------------------------------------------------
PROCESSED_TTL_SECONDS = 172800


# ===================================================================
# Lambda entry point
# ===================================================================

def lambda_handler(event, context):
    """
    EventBridge-triggered reconciler that:
    1. Scans S3 for missed Bedrock invocation logs in the last 35 minutes
    2. Reprocesses messages from the DLQ
    3. Writes a heartbeat record for monitoring
    """
    s3_count = 0
    dlq_count = 0

    try:
        s3_count = reconcile_s3_window(minutes=35)
    except Exception:
        logger.exception("Failed during S3 reconciliation")

    try:
        dlq_count = process_dlq(max_messages=100)
    except Exception:
        logger.exception("Failed during DLQ processing")

    # Write heartbeat
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        quota_table.put_item(
            Item={
                "pk": "SYSTEM#reconciler",
                "sk": "HEARTBEAT",
                "last_run": now_iso,
                "records_processed": s3_count,
                "dlq_processed": dlq_count,
            }
        )
    except Exception:
        logger.exception("Failed to write heartbeat")

    logger.info(
        "Reconciler complete: s3_records=%d, dlq_records=%d",
        s3_count, dlq_count,
    )

    return {
        "records_processed": s3_count,
        "dlq_processed": dlq_count,
    }


# ===================================================================
# S3 window reconciliation
# ===================================================================

def reconcile_s3_window(minutes: int = 35) -> int:
    """
    List S3 objects in the last `minutes` window and process any that
    lack a PROCESSED marker in DynamoDB.
    """
    if not BEDROCK_LOG_BUCKET:
        logger.warning("BEDROCK_LOG_BUCKET not set, skipping S3 reconciliation")
        return 0

    now_utc = datetime.now(timezone.utc)
    window_start = now_utc - timedelta(minutes=minutes)

    # Collect all S3 key prefixes that cover the time window.
    # Bedrock log keys are partitioned by hour:
    #   {BEDROCK_LOG_PREFIX}AWSLogs/{account}/BedrockModelInvocationLogs/{region}/{year}/{month}/{day}/{hour}/
    # We enumerate each distinct hour between window_start and now_utc.
    prefixes = _build_s3_prefixes(window_start, now_utc)
    if not prefixes:
        logger.info("No S3 prefixes to scan")
        return 0

    # List all S3 keys under the prefixes
    all_keys = []
    for prefix in prefixes:
        all_keys.extend(_list_s3_keys(BEDROCK_LOG_BUCKET, prefix, window_start))

    if not all_keys:
        logger.info("No S3 objects found in reconciliation window")
        return 0

    logger.info("Found %d S3 keys in reconciliation window", len(all_keys))

    # Check which keys already have processed markers (in batches of 100)
    unprocessed_keys = _filter_unprocessed_keys(all_keys)

    if not unprocessed_keys:
        logger.info("All S3 keys already processed")
        return 0

    logger.info("Processing %d unprocessed S3 keys", len(unprocessed_keys))

    # Process each unprocessed key
    processed_count = 0
    for s3_key in unprocessed_keys:
        try:
            _process_s3_key(BEDROCK_LOG_BUCKET, s3_key)
            processed_count += 1
        except Exception:
            logger.exception("Failed to process S3 key: %s", s3_key)

    return processed_count


def _build_s3_prefixes(window_start: datetime, window_end: datetime) -> list[str]:
    """
    Build a list of S3 key prefixes covering every hour between
    window_start and window_end.

    Bedrock invocation log path format:
        {BEDROCK_LOG_PREFIX}AWSLogs/{account_id}/BedrockModelInvocationLogs/{region}/{YYYY}/{MM}/{DD}/{HH}/

    Since the region segment sits between the account ID and the date path,
    and we may serve multiple regions, we cannot include the date in the
    prefix without knowing all regions.  Instead we build one prefix per
    distinct day observed in the window and rely on ``_list_s3_keys`` to
    filter by ``LastModified`` timestamp.

    When the window straddles a day boundary (UTC) we emit prefixes for
    both days so the S3 listing covers the full range.
    """
    if not AWS_ACCOUNT_ID:
        logger.warning("AWS_ACCOUNT_ID not set, cannot build S3 prefixes")
        return []

    base = (
        f"{BEDROCK_LOG_PREFIX}AWSLogs/{AWS_ACCOUNT_ID}/"
        f"BedrockModelInvocationLogs/"
    )

    # Collect the distinct UTC dates spanned by the window so we can
    # optionally narrow the listing when a single-day optimisation is
    # feasible.  For now, return just the base prefix — S3 ListObjectsV2
    # is efficient enough for a 35-minute window and the LastModified
    # filter in _list_s3_keys removes stale objects.
    return [base]


def _list_s3_keys(bucket: str, prefix: str, after: datetime) -> list[str]:
    """
    List all S3 object keys under the given prefix that were last modified
    after the specified timestamp.
    """
    keys = []
    continuation_token = None

    while True:
        kwargs = {
            "Bucket": bucket,
            "Prefix": prefix,
            "MaxKeys": 1000,
        }
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token

        try:
            response = s3_client.list_objects_v2(**kwargs)
        except ClientError:
            logger.exception("Failed to list S3 objects under %s", prefix)
            break

        for obj in response.get("Contents", []):
            last_modified = obj.get("LastModified")
            if last_modified and last_modified >= after:
                keys.append(obj["Key"])

        if not response.get("IsTruncated"):
            break
        continuation_token = response.get("NextContinuationToken")

    return keys


def _filter_unprocessed_keys(all_keys: list[str]) -> list[str]:
    """
    Check DynamoDB for PROCESSED markers in batches of up to 100 keys.
    Returns keys that do NOT have a processed marker.
    """
    unprocessed = []

    for i in range(0, len(all_keys), 100):
        batch = all_keys[i : i + 100]
        key_hash_map = {}
        for s3_key in batch:
            key_hash = hashlib.sha256(s3_key.encode("utf-8")).hexdigest()[:16]
            key_hash_map[f"PROCESSED#{key_hash}"] = s3_key

        # BatchGetItem requires the raw DynamoDB client with typed keys
        request_keys = [
            {"pk": {"S": pk}, "sk": {"S": "MARKER"}}
            for pk in key_hash_map.keys()
        ]

        # BatchGetItem has a limit of 100 items per request
        found_pks = set()
        try:
            response = dynamodb_client.batch_get_item(
                RequestItems={
                    QUOTA_TABLE: {
                        "Keys": request_keys,
                        "ProjectionExpression": "pk",
                    }
                }
            )
            for item in response.get("Responses", {}).get(QUOTA_TABLE, []):
                found_pks.add(item["pk"]["S"])

            # Handle unprocessed keys (DynamoDB throttling)
            unprocessed_ddb = response.get("UnprocessedKeys", {}).get(QUOTA_TABLE, {})
            while unprocessed_ddb:
                response = dynamodb_client.batch_get_item(
                    RequestItems={QUOTA_TABLE: unprocessed_ddb}
                )
                for item in response.get("Responses", {}).get(QUOTA_TABLE, []):
                    found_pks.add(item["pk"]["S"])
                unprocessed_ddb = response.get("UnprocessedKeys", {}).get(QUOTA_TABLE, {})

        except ClientError:
            logger.exception("Failed BatchGetItem for processed markers")
            # On failure, treat all as unprocessed (safe: idempotent processing)
            unprocessed.extend(batch)
            continue

        for pk, s3_key in key_hash_map.items():
            if pk not in found_pks:
                unprocessed.append(s3_key)

    return unprocessed


def _process_s3_key(bucket: str, s3_key: str) -> None:
    """
    Read a single Bedrock invocation log from S3, write a processed marker,
    extract user identity and token counts, calculate cost, and update
    DynamoDB usage records. Identical logic to the stream Lambda.
    """
    # Skip raw body files in data/ subfolder
    if "/data/" in s3_key:
        logger.info("Skipping body file (data/ subfolder): %s", s3_key)
        _write_processed_marker(s3_key)
        return

    # ------------------------------------------------------------------
    # 1. Read S3 object (may be gzip-compressed)
    # ------------------------------------------------------------------
    response = s3_client.get_object(Bucket=bucket, Key=s3_key)
    raw_bytes = response["Body"].read()

    try:
        data = gzip.decompress(raw_bytes)
    except (gzip.BadGzipFile, OSError):
        # Not gzip -- treat as plain text
        data = raw_bytes

    # Parse JSON — file may contain a single JSON object or JSONL (one per line)
    text = data.decode("utf-8", errors="replace").strip()
    try:
        log_entries = [json.loads(text)]
    except json.JSONDecodeError:
        log_entries = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    log_entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping unparseable line in %s: %s", s3_key, line[:100])

    if not log_entries:
        logger.warning("No parseable JSON in s3://%s/%s", bucket, s3_key)
        _write_processed_marker(s3_key)
        return

    # Write processed marker BEFORE any further checks
    _write_processed_marker(s3_key)

    # Process each log entry
    for log_entry in log_entries:
        _process_single_reconciler_entry(log_entry, s3_key, bucket)


def _process_single_reconciler_entry(log_entry: dict, s3_key: str, bucket: str) -> None:
    """Process a single Bedrock invocation log entry (reconciler path)."""
    identity_arn = log_entry.get("identity", {}).get("arn", "")
    email = extract_email_from_arn(identity_arn)
    if email is None:
        logger.warning(
            "Identity ARN does not match ccwb pattern, skipping: %s (s3://%s/%s)",
            identity_arn, bucket, s3_key,
        )
        return

    timestamp_str = log_entry.get("timestamp", "")
    model_id_arn = log_entry.get("modelId", "")

    input_section = log_entry.get("input", {})
    output_section = log_entry.get("output", {})

    input_tokens = input_section.get("inputTokenCount", 0)
    cache_read_tokens = input_section.get("cacheReadInputTokenCount", 0)
    cache_write_tokens = input_section.get("cacheWriteInputTokenCount", 0)
    output_tokens = output_section.get("outputTokenCount", 0)
    total_tokens = input_tokens + output_tokens + cache_read_tokens + cache_write_tokens

    try:
        event_utc = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        logger.warning("Invalid timestamp '%s', falling back to now(UTC)", timestamp_str)
        event_utc = datetime.now(timezone.utc)

    event_local = event_utc.astimezone(EFFECTIVE_TZ)
    month_key = event_local.strftime("%Y-%m")
    date_key = event_local.strftime("%Y-%m-%d")

    model_id = extract_model_id_from_arn(model_id_arn)
    pricing = get_pricing(model_id)

    cost = (
        Decimal(str(input_tokens)) * pricing["input_per_1m"]
        + Decimal(str(output_tokens)) * pricing["output_per_1m"]
        + Decimal(str(cache_read_tokens)) * pricing["cache_read_per_1m"]
        + Decimal(str(cache_write_tokens)) * pricing["cache_write_per_1m"]
    ) / Decimal("1000000")
    cost = cost.quantize(Decimal("0.000001"))

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    _update_user_usage(
        email=email,
        month_key=month_key,
        date_key=date_key,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
        total_tokens=total_tokens,
        cost=cost,
        now_iso=now_iso,
    )

    _update_org_aggregate(month_key, total_tokens, cost)

    logger.info(
        "Reconciled %s: user=%s model=%s tokens=%d cost=$%s",
        s3_key, email, model_id, total_tokens, cost,
    )


# ===================================================================
# DLQ processing
# ===================================================================

def process_dlq(max_messages: int = 100) -> int:
    """
    Receive messages from the SQS DLQ, process each as an S3 event
    notification, and delete successfully processed messages.
    """
    if not DLQ_URL:
        logger.warning("DLQ_URL not set, skipping DLQ processing")
        return 0

    processed_count = 0
    messages_received = 0

    while messages_received < max_messages:
        batch_size = min(10, max_messages - messages_received)

        try:
            response = sqs_client.receive_message(
                QueueUrl=DLQ_URL,
                MaxNumberOfMessages=batch_size,
                WaitTimeSeconds=1,
                VisibilityTimeout=300,
            )
        except ClientError:
            logger.exception("Failed to receive messages from DLQ")
            break

        messages = response.get("Messages", [])
        if not messages:
            break

        messages_received += len(messages)

        for message in messages:
            receipt_handle = message["ReceiptHandle"]
            message_id = message.get("MessageId", "unknown")

            try:
                body = json.loads(message["Body"])
                s3_records = body.get("Records", [])

                for s3_record in s3_records:
                    bucket = s3_record["s3"]["bucket"]["name"]
                    s3_key = s3_record["s3"]["object"]["key"]
                    s3_key = urllib.parse.unquote_plus(s3_key)
                    _process_s3_key(bucket, s3_key)

                # Delete successfully processed message
                sqs_client.delete_message(
                    QueueUrl=DLQ_URL,
                    ReceiptHandle=receipt_handle,
                )
                processed_count += 1

            except Exception:
                logger.exception(
                    "Failed to process DLQ message %s", message_id
                )
                # Leave message in DLQ for retry

    logger.info("DLQ processing complete: %d messages processed", processed_count)
    return processed_count


# ===================================================================
# Helper: processed marker
# ===================================================================

def _write_processed_marker(s3_key: str) -> None:
    """Write an idempotency marker so reconcilers skip already-processed files."""
    key_hash = hashlib.sha256(s3_key.encode("utf-8")).hexdigest()[:16]
    ttl = int(time.time()) + PROCESSED_TTL_SECONDS
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    try:
        quota_table.put_item(
            Item={
                "pk": f"PROCESSED#{key_hash}",
                "sk": "MARKER",
                "s3_key": s3_key,
                "processed_at": now_iso,
                "ttl": ttl,
            }
        )
    except Exception:
        logger.exception("Failed to write processed marker for %s", s3_key)
        raise


# ===================================================================
# Helper: ARN parsing
# ===================================================================

def extract_email_from_arn(identity_arn: str) -> str | None:
    """
    Extract email from an STS assumed-role ARN with ccwb- prefix.

    Expected format:
        arn:aws:sts::<account>:assumed-role/<role>/ccwb-<email>

    Returns the email portion, or None if the pattern does not match.
    """
    match = _IDENTITY_RE.match(identity_arn or "")
    if match:
        return match.group(1)
    return None


def extract_model_id_from_arn(model_id_arn: str) -> str:
    """
    Extract the short model identifier from a Bedrock model ARN.

    For ARNs like:
        arn:aws:bedrock:us-east-1:...:inference-profile/global.anthropic.claude-opus-4-6-v1
    returns:
        global.anthropic.claude-opus-4-6-v1

    If the input is not an ARN, returns it as-is.
    """
    if not model_id_arn or not model_id_arn.startswith("arn:"):
        return model_id_arn or ""

    # ARN format: arn:partition:service:region:account:resource-type/resource-id
    # The model ID is the last path segment after the final "/"
    parts = model_id_arn.split("/")
    if len(parts) >= 2:
        return parts[-1]

    return model_id_arn


# ===================================================================
# Helper: pricing lookup
# ===================================================================

def get_pricing(model_id: str) -> dict:
    """
    Look up per-token pricing for a model.

    Lookup order:
    1. Exact match in BedrockPricing DynamoDB table
    2. Partial match (model_id contained in or containing a cached key)
    3. DEFAULT_PRICING_JSON environment variable
    4. Hardcoded most-expensive pricing (fail-safe)
    """
    global _pricing_cache, _pricing_cache_loaded

    # Lazy-load the full pricing table once per cold start
    if not _pricing_cache_loaded:
        _load_pricing_cache()
        _pricing_cache_loaded = True

    # Exact match
    if model_id in _pricing_cache:
        return _pricing_cache[model_id]

    # Partial / substring match (handles cross-region prefixes, version suffixes)
    for cached_id, cached_pricing in _pricing_cache.items():
        if cached_id == "DEFAULT":
            continue
        if cached_id in model_id or model_id in cached_id:
            return cached_pricing

    # DEFAULT entry from pricing table
    if "DEFAULT" in _pricing_cache:
        return _pricing_cache["DEFAULT"]

    # Env var fallback
    if DEFAULT_PRICING_JSON:
        try:
            parsed = json.loads(DEFAULT_PRICING_JSON)
            return {
                "input_per_1m": Decimal(str(parsed.get("input_per_1m", "0"))),
                "output_per_1m": Decimal(str(parsed.get("output_per_1m", "0"))),
                "cache_read_per_1m": Decimal(str(parsed.get("cache_read_per_1m", "0"))),
                "cache_write_per_1m": Decimal(str(parsed.get("cache_write_per_1m", "0"))),
            }
        except (json.JSONDecodeError, InvalidOperation):
            logger.exception("Failed to parse DEFAULT_PRICING_JSON")

    # Last resort: most expensive known pricing
    logger.warning("No pricing found for model '%s', using most-expensive fallback", model_id)
    return MOST_EXPENSIVE_PRICING


def _load_pricing_cache() -> None:
    """Scan the BedrockPricing table and populate the in-memory cache."""
    global _pricing_cache
    _pricing_cache = {}

    try:
        response = pricing_table.scan()
        while True:
            for item in response.get("Items", []):
                mid = item.get("model_id")
                if mid:
                    _pricing_cache[mid] = {
                        "input_per_1m": Decimal(str(item.get("input_per_1m", "0"))),
                        "output_per_1m": Decimal(str(item.get("output_per_1m", "0"))),
                        "cache_read_per_1m": Decimal(str(item.get("cache_read_per_1m", "0"))),
                        "cache_write_per_1m": Decimal(str(item.get("cache_write_per_1m", "0"))),
                    }
            if "LastEvaluatedKey" not in response:
                break
            response = pricing_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])

        logger.info("Loaded pricing for %d models", len(_pricing_cache))
    except Exception:
        logger.exception("Failed to load pricing cache from DynamoDB")


# ===================================================================
# Helper: DynamoDB user usage update (three-step conditional)
# ===================================================================

def _update_user_usage(
    *,
    email: str,
    month_key: str,
    date_key: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
    total_tokens: int,
    cost: Decimal,
    now_iso: str,
) -> None:
    """
    Update the per-user monthly usage record using a three-step conditional
    write pattern for atomic daily reset:

    Step 1: ADD monthly + daily, conditioned on same day or new record.
    Step 2 (if Step 1 fails): SET daily to new values + ADD monthly,
            conditioned on different day (we are the one rolling over).
    Step 3 (if Step 2 fails): ADD everything (another invocation already
            rolled over the daily counters).
    """
    pk = f"USER#{email}"
    sk = f"MONTH#{month_key}#BEDROCK"

    token_values = {
        ":input": Decimal(str(input_tokens)),
        ":output": Decimal(str(output_tokens)),
        ":cache_read": Decimal(str(cache_read_tokens)),
        ":cache_write": Decimal(str(cache_write_tokens)),
        ":total": Decimal(str(total_tokens)),
        ":cost": cost,
        ":daily_total": Decimal(str(total_tokens)),
        ":daily_cost": cost,
        ":date": date_key,
        ":now": now_iso,
    }

    # --- Step 1: same day or brand-new record ---
    try:
        quota_table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression=(
                "ADD input_tokens :input, output_tokens :output, "
                "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
                "total_tokens :total, estimated_cost :cost, "
                "daily_tokens :daily_total, daily_cost :daily_cost "
                "SET last_updated = :now"
            ),
            ConditionExpression="daily_date = :date OR attribute_not_exists(daily_date)",
            ExpressionAttributeValues=token_values,
        )
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise

    # --- Step 2: we perform the daily rollover ---
    try:
        quota_table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression=(
                "ADD input_tokens :input, output_tokens :output, "
                "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
                "total_tokens :total, estimated_cost :cost "
                "SET daily_tokens = :daily_total, daily_cost = :daily_cost, "
                "daily_date = :date, last_updated = :now"
            ),
            ConditionExpression="daily_date <> :date",
            ExpressionAttributeValues=token_values,
        )
        logger.info("Daily rollover for %s on %s", email, date_key)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise

    # --- Step 3: another invocation already rolled over, just ADD ---
    quota_table.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression=(
            "ADD input_tokens :input, output_tokens :output, "
            "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
            "total_tokens :total, estimated_cost :cost, "
            "daily_tokens :daily_total, daily_cost :daily_cost "
            "SET last_updated = :now"
        ),
        ExpressionAttributeValues=token_values,
    )


# ===================================================================
# Helper: DynamoDB org aggregate update
# ===================================================================

def _update_org_aggregate(month_key: str, total_tokens: int, cost: Decimal) -> None:
    """Atomically increment org-wide monthly totals."""
    try:
        quota_table.update_item(
            Key={"pk": "ORG#global", "sk": f"MONTH#{month_key}#BEDROCK"},
            UpdateExpression=(
                "ADD total_tokens :tokens, estimated_cost :cost"
            ),
            ExpressionAttributeValues={
                ":tokens": Decimal(str(total_tokens)),
                ":cost": cost,
            },
        )
    except Exception:
        logger.exception("Failed to update org aggregate for %s", month_key)

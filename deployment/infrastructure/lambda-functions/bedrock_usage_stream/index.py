# ABOUTME: SQS-triggered Lambda that processes Bedrock Model Invocation Log files from S3
# ABOUTME: Extracts token usage and cost per user, updates DynamoDB quota records
# ABOUTME: Uses ReportBatchItemFailures for partial SQS batch failure handling

import json
import gzip
import hashlib
import logging
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation

import boto3

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
dynamodb = boto3.resource("dynamodb")

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
PRICING_TABLE = os.environ.get("PRICING_TABLE", "BedrockPricing")
DEFAULT_PRICING_JSON = os.environ.get("DEFAULT_PRICING_JSON", "")

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
    Process a batch of SQS messages, each wrapping an S3 event notification
    for a Bedrock invocation log file.

    Returns batchItemFailures for any messages that could not be processed,
    allowing SQS to retry only the failed messages.
    """
    failed_message_ids: list[str] = []

    for record in event.get("Records", []):
        message_id = record.get("messageId", "unknown")
        try:
            _process_sqs_record(record)
        except Exception:
            logger.exception("Failed to process SQS message %s", message_id)
            failed_message_ids.append(message_id)

    return {
        "batchItemFailures": [
            {"itemIdentifier": mid} for mid in failed_message_ids
        ]
    }


def _process_sqs_record(record: dict) -> None:
    """Parse S3 event from SQS body and process each S3 object."""
    body = json.loads(record["body"])

    # S3 event notifications wrap records in a "Records" list
    s3_records = body.get("Records", [])
    for s3_record in s3_records:
        bucket = s3_record["s3"]["bucket"]["name"]
        # S3 keys in event notifications are URL-encoded
        s3_key = s3_record["s3"]["object"]["key"]
        s3_key = urllib.parse.unquote_plus(s3_key)

        process_invocation_log(bucket, s3_key)


# ===================================================================
# Core processing
# ===================================================================

def process_invocation_log(bucket: str, s3_key: str) -> None:
    """
    Read a single Bedrock invocation log from S3, write a processed marker,
    extract user identity and token counts, calculate cost, and update
    DynamoDB usage records.
    """
    # Skip raw body files in data/ subfolder — they contain request/response
    # payloads, not the metadata records with token counts and identity ARN
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

    # Parse JSON — file may contain a single JSON object or multiple
    # newline-delimited JSON objects (JSONL format)
    text = data.decode("utf-8", errors="replace").strip()
    try:
        log_entries = [json.loads(text)]
    except json.JSONDecodeError:
        # JSONL: one JSON object per line
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

    # ------------------------------------------------------------------
    # 2. Write processed marker BEFORE any further checks
    # ------------------------------------------------------------------
    _write_processed_marker(s3_key)

    # ------------------------------------------------------------------
    # 3. Process each log entry in the file
    # ------------------------------------------------------------------
    for log_entry in log_entries:
        _process_single_entry(log_entry, s3_key, bucket)


def _process_single_entry(log_entry: dict, s3_key: str, bucket: str) -> None:
    """Process a single Bedrock invocation log entry."""
    # Extract email from identity ARN (identity may be a dict or list)
    identity = log_entry.get("identity", {})
    if isinstance(identity, list):
        identity = identity[0] if identity else {}
    identity_arn = identity.get("arn", "") if isinstance(identity, dict) else ""
    email = extract_email_from_arn(identity_arn)
    if email is None:
        logger.warning(
            "Identity ARN does not match ccwb pattern, skipping: %s (s3://%s/%s)",
            identity_arn, bucket, s3_key,
        )
        return

    # Extract fields
    timestamp_str = log_entry.get("timestamp", "")
    model_id_arn = log_entry.get("modelId", "")

    input_section = log_entry.get("input", {})
    output_section = log_entry.get("output", {})

    input_tokens = input_section.get("inputTokenCount", 0)
    cache_read_tokens = input_section.get("cacheReadInputTokenCount", 0)
    cache_write_tokens = input_section.get("cacheWriteInputTokenCount", 0)
    output_tokens = output_section.get("outputTokenCount", 0)

    total_tokens = input_tokens + output_tokens + cache_read_tokens + cache_write_tokens

    # Convert timestamp to UTC+8 for partitioning
    try:
        event_utc = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        logger.warning("Invalid timestamp '%s', falling back to now(UTC)", timestamp_str)
        event_utc = datetime.now(timezone.utc)

    event_local = event_utc.astimezone(EFFECTIVE_TZ)
    month_key = event_local.strftime("%Y-%m")
    date_key = event_local.strftime("%Y-%m-%d")

    # Extract short model ID and look up pricing
    model_id = extract_model_id_from_arn(model_id_arn)
    pricing = get_pricing(model_id)

    # Calculate cost
    cost = (
        Decimal(str(input_tokens)) * pricing["input_per_1m"]
        + Decimal(str(output_tokens)) * pricing["output_per_1m"]
        + Decimal(str(cache_read_tokens)) * pricing["cache_read_per_1m"]
        + Decimal(str(cache_write_tokens)) * pricing["cache_write_per_1m"]
    ) / Decimal("1000000")
    cost = cost.quantize(Decimal("0.000001"))

    # Update per-user record with three-step conditional daily reset
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

    # Update org aggregate
    _update_org_aggregate(month_key, total_tokens, cost)

    logger.info(
        "Processed %s: user=%s model=%s tokens=%d cost=$%s",
        s3_key, email, model_id, total_tokens, cost,
    )


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
# Helper: DynamoDB user usage updates
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
    Update per-user usage with two independent records:

    1. MONTH#YYYY-MM#BEDROCK — monthly aggregate (ADD only, no conditions)
    2. DAY#YYYY-MM-DD#BEDROCK — daily record (ADD only, no conditions)

    Both writes are unconditional ADD operations, so they are safe under
    concurrency and event ordering does not matter.  Each day's record is
    independent — no rollover logic needed.
    """
    pk = f"USER#{email}"
    month_sk = f"MONTH#{month_key}#BEDROCK"
    day_sk = f"DAY#{date_key}#BEDROCK"

    token_values = {
        ":input": Decimal(str(input_tokens)),
        ":output": Decimal(str(output_tokens)),
        ":cache_read": Decimal(str(cache_read_tokens)),
        ":cache_write": Decimal(str(cache_write_tokens)),
        ":total": Decimal(str(total_tokens)),
        ":cost": cost,
        ":now": now_iso,
    }

    # --- Monthly aggregate ---
    quota_table.update_item(
        Key={"pk": pk, "sk": month_sk},
        UpdateExpression=(
            "ADD input_tokens :input, output_tokens :output, "
            "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
            "total_tokens :total, estimated_cost :cost "
            "SET last_updated = :now"
        ),
        ExpressionAttributeValues=token_values,
    )

    # --- Daily record ---
    quota_table.update_item(
        Key={"pk": pk, "sk": day_sk},
        UpdateExpression=(
            "ADD input_tokens :input, output_tokens :output, "
            "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
            "total_tokens :total, estimated_cost :cost "
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

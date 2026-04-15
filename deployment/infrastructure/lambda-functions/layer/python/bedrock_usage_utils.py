# ABOUTME: Shared utilities for Bedrock usage tracking (stream + reconciler Lambdas)
# ABOUTME: Handles ARN parsing, pricing lookup, DynamoDB usage updates, processed markers

import gzip
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation

logger = logging.getLogger()

# ---------------------------------------------------------------------------
# Effective timezone for daily/monthly boundaries (UTC+8, matching quota_check)
# ---------------------------------------------------------------------------
EFFECTIVE_TZ = timezone(timedelta(hours=8))

# ---------------------------------------------------------------------------
# Processed marker TTL: 48 hours
# ---------------------------------------------------------------------------
PROCESSED_TTL_SECONDS = 172800

# ---------------------------------------------------------------------------
# ARN parsing patterns
# ---------------------------------------------------------------------------
# Matches: arn:aws:sts::<account>:assumed-role/<role>/ccwb-<email>
_IDENTITY_RE = re.compile(
    r"^arn:aws:sts::\d+:assumed-role/[^/]+/ccwb-(.+)$"
)

# ---------------------------------------------------------------------------
# Hardcoded most-expensive fallback pricing (Opus-class model as of 2026-04)
# Used only when both the pricing table and DEFAULT_PRICING_JSON are unavailable.
# ---------------------------------------------------------------------------
MOST_EXPENSIVE_PRICING = {
    "input_per_1m": Decimal("15"),
    "output_per_1m": Decimal("75"),
    "cache_read_per_1m": Decimal("1.875"),
    "cache_write_per_1m": Decimal("18.75"),
    "cache_write_1h_per_1m": Decimal("30"),
}


# ===================================================================
# ARN parsing
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
# Pricing lookup
# ===================================================================

class PricingCache:
    """
    In-memory pricing cache that loads from DynamoDB once per cold start.
    """

    def __init__(self):
        self._cache: dict[str, dict] = {}
        self._loaded = False

    def get_pricing(self, model_id: str, pricing_table, default_pricing_json: str = "") -> dict:
        """
        Look up per-token pricing for a model.

        Lookup order:
        1. Exact match in BedrockPricing DynamoDB table
        2. Partial match (model_id contained in or containing a cached key)
        3. DEFAULT_PRICING_JSON environment variable
        4. Hardcoded most-expensive pricing (fail-safe)
        """
        # Lazy-load the full pricing table once per cold start
        if not self._loaded:
            self._load(pricing_table)
            self._loaded = True

        # Exact match
        if model_id in self._cache:
            return self._cache[model_id]

        # Partial / substring match (handles cross-region prefixes, version suffixes)
        for cached_id, cached_pricing in self._cache.items():
            if cached_id == "DEFAULT":
                continue
            if cached_id in model_id or model_id in cached_id:
                return cached_pricing

        # DEFAULT entry from pricing table
        if "DEFAULT" in self._cache:
            return self._cache["DEFAULT"]

        # Env var fallback
        if default_pricing_json:
            try:
                parsed = json.loads(default_pricing_json)
                return {
                    "input_per_1m": Decimal(str(parsed.get("input_per_1m", "0"))),
                    "output_per_1m": Decimal(str(parsed.get("output_per_1m", "0"))),
                    "cache_read_per_1m": Decimal(str(parsed.get("cache_read_per_1m", "0"))),
                    "cache_write_per_1m": Decimal(str(parsed.get("cache_write_per_1m", "0"))),
                    "cache_write_1h_per_1m": Decimal(str(parsed.get("cache_write_1h_per_1m", "0"))),
                }
            except (json.JSONDecodeError, InvalidOperation):
                logger.exception("Failed to parse DEFAULT_PRICING_JSON")

        # Last resort: most expensive known pricing
        logger.warning("No pricing found for model '%s', using most-expensive fallback", model_id)
        return MOST_EXPENSIVE_PRICING

    def _load(self, pricing_table) -> None:
        """Scan the BedrockPricing table and populate the in-memory cache."""
        self._cache = {}
        try:
            response = pricing_table.scan()
            while True:
                for item in response.get("Items", []):
                    mid = item.get("model_id")
                    if mid:
                        self._cache[mid] = {
                            "input_per_1m": Decimal(str(item.get("input_per_1m", "0"))),
                            "output_per_1m": Decimal(str(item.get("output_per_1m", "0"))),
                            "cache_read_per_1m": Decimal(str(item.get("cache_read_per_1m", "0"))),
                            "cache_write_per_1m": Decimal(str(item.get("cache_write_per_1m", "0"))),
                            "cache_write_1h_per_1m": Decimal(str(item.get("cache_write_1h_per_1m", "0"))),
                        }
                if "LastEvaluatedKey" not in response:
                    break
                response = pricing_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            logger.info("Loaded pricing for %d models", len(self._cache))
        except Exception:
            logger.exception("Failed to load pricing cache from DynamoDB")


# ===================================================================
# Cost calculation
# ===================================================================

def calculate_cost(
    pricing: dict,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
    cache_write_5m_tokens: int = 0,
    cache_write_1h_tokens: int = 0,
) -> Decimal:
    """Calculate the cost of a Bedrock invocation given token counts and pricing.

    When cache_write_5m_tokens/cache_write_1h_tokens are provided (from the
    response body ``cache_creation`` breakdown), they are priced at their
    respective rates.  Otherwise the total ``cache_write_tokens`` is priced
    at the default (5-minute) rate for backward compatibility.
    """
    cache_write_1h_rate = pricing.get("cache_write_1h_per_1m", Decimal("0"))

    if (cache_write_5m_tokens or cache_write_1h_tokens) and cache_write_1h_rate:
        cache_write_cost = (
            Decimal(str(cache_write_5m_tokens)) * pricing["cache_write_per_1m"]
            + Decimal(str(cache_write_1h_tokens)) * cache_write_1h_rate
        )
    else:
        # Fallback: price all cache writes at the default (5-min) rate
        cache_write_cost = Decimal(str(cache_write_tokens)) * pricing["cache_write_per_1m"]

    cost = (
        Decimal(str(input_tokens)) * pricing["input_per_1m"]
        + Decimal(str(output_tokens)) * pricing["output_per_1m"]
        + Decimal(str(cache_read_tokens)) * pricing["cache_read_per_1m"]
        + cache_write_cost
    ) / Decimal("1000000")
    return cost.quantize(Decimal("0.000001"))


# ===================================================================
# S3 log parsing
# ===================================================================

def read_and_parse_s3_log(s3_client, bucket: str, s3_key: str) -> list[dict]:
    """
    Read a single S3 object, decompress if gzipped, parse as JSON or JSONL.
    Returns a list of parsed log entry dicts (may be empty).
    """
    response = s3_client.get_object(Bucket=bucket, Key=s3_key)
    raw_bytes = response["Body"].read()

    try:
        data = gzip.decompress(raw_bytes)
    except (gzip.BadGzipFile, OSError):
        data = raw_bytes

    text = data.decode("utf-8", errors="replace").strip()
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping unparseable line in %s: %s", s3_key, line[:100])
        return entries


# ===================================================================
# S3 output body parsing (for large responses)
# ===================================================================

def _parse_s3_uri(s3_uri: str) -> tuple[str, str] | None:
    """Parse an s3://bucket/key URI into (bucket, key). Returns None if invalid."""
    if not s3_uri or not s3_uri.startswith("s3://"):
        return None
    path = s3_uri[5:]
    slash = path.find("/")
    if slash <= 0:
        return None
    return path[:slash], path[slash + 1:]


def _extract_cache_creation_from_s3(s3_client, s3_uri: str) -> dict:
    """
    Fetch the output body from S3 and extract cache_creation breakdown.

    Returns {"ephemeral_5m_input_tokens": N, "ephemeral_1h_input_tokens": N}
    or empty dict on any failure.
    """
    parsed = _parse_s3_uri(s3_uri)
    if not parsed:
        return {}

    bucket, key = parsed
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        raw_bytes = response["Body"].read()
        try:
            data = gzip.decompress(raw_bytes)
        except (gzip.BadGzipFile, OSError):
            data = raw_bytes
        text = data.decode("utf-8", errors="replace").strip()

        # The output body is a JSON array of streaming chunks
        body = json.loads(text)
        chunks = body if isinstance(body, list) else [body]
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            usage = chunk.get("message", {}).get("usage", {})
            cache_creation = usage.get("cache_creation", {})
            if cache_creation:
                return cache_creation
    except Exception:
        logger.warning("Failed to read cache_creation from %s", s3_uri, exc_info=True)
    return {}


# ===================================================================
# Log entry processing
# ===================================================================

def parse_log_entry(log_entry: dict, s3_client=None) -> dict | None:
    """
    Parse a single Bedrock invocation log entry into a structured dict.

    Returns None if the email cannot be extracted from the identity ARN
    (i.e. not a TVM-issued invocation).

    Returned dict keys:
        email, month_key, date_key, model_id, input_tokens, output_tokens,
        cache_read_tokens, cache_write_tokens, cache_write_5m_tokens,
        cache_write_1h_tokens, total_tokens
    """
    # Extract email from identity ARN
    identity = log_entry.get("identity", {})
    if isinstance(identity, list):
        identity = identity[0] if identity else {}
    identity_arn = identity.get("arn", "") if isinstance(identity, dict) else ""
    email = extract_email_from_arn(identity_arn)
    if email is None:
        return None

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

    # Extract 5m/1h cache write breakdown from response body.
    # Inline: output.outputBodyJson[0].message.usage.cache_creation
    # Large responses: outputBodyJson is absent, body stored at output.outputBodyS3Path
    cache_write_5m_tokens = 0
    cache_write_1h_tokens = 0
    cache_creation = {}

    output_body_json = output_section.get("outputBodyJson", [])
    if isinstance(output_body_json, list):
        for chunk in output_body_json:
            if not isinstance(chunk, dict):
                continue
            usage = chunk.get("message", {}).get("usage", {})
            cache_creation = usage.get("cache_creation", {})
            if cache_creation:
                break

    # Fallback: fetch from S3 when body was offloaded (~5% of requests)
    if not cache_creation and cache_write_tokens and s3_client:
        s3_path = output_section.get("outputBodyS3Path", "")
        if s3_path:
            cache_creation = _extract_cache_creation_from_s3(s3_client, s3_path)

    if cache_creation:
        cache_write_5m_tokens = cache_creation.get("ephemeral_5m_input_tokens", 0)
        cache_write_1h_tokens = cache_creation.get("ephemeral_1h_input_tokens", 0)

    # Convert timestamp to UTC+8 for partitioning
    try:
        event_utc = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        logger.warning("Invalid timestamp '%s', falling back to now(UTC)", timestamp_str)
        event_utc = datetime.now(timezone.utc)

    event_local = event_utc.astimezone(EFFECTIVE_TZ)

    return {
        "email": email,
        "identity_arn": identity_arn,
        "month_key": event_local.strftime("%Y-%m"),
        "date_key": event_local.strftime("%Y-%m-%d"),
        "model_id": extract_model_id_from_arn(model_id_arn),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_tokens": cache_read_tokens,
        "cache_write_tokens": cache_write_tokens,
        "cache_write_5m_tokens": cache_write_5m_tokens,
        "cache_write_1h_tokens": cache_write_1h_tokens,
        "total_tokens": total_tokens,
    }


# ===================================================================
# DynamoDB: processed marker
# ===================================================================

def write_processed_marker(quota_table, s3_key: str) -> None:
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


def compute_marker_hash(s3_key: str) -> str:
    """Compute the hash used for PROCESSED# marker PK."""
    return hashlib.sha256(s3_key.encode("utf-8")).hexdigest()[:16]


def check_processed_marker(quota_table, s3_key: str) -> bool:
    """Return True if a PROCESSED marker already exists for this S3 key."""
    key_hash = compute_marker_hash(s3_key)
    try:
        resp = quota_table.get_item(
            Key={"pk": f"PROCESSED#{key_hash}", "sk": "MARKER"},
            ProjectionExpression="pk",
        )
        return "Item" in resp
    except Exception:
        logger.exception("Failed to check processed marker for %s", s3_key)
        return False  # On failure, assume unprocessed (safe: idempotent reprocessing)


# ===================================================================
# DynamoDB: user usage updates
# ===================================================================

def update_user_usage(
    quota_table,
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
    cache_write_5m_tokens: int = 0,
    cache_write_1h_tokens: int = 0,
) -> None:
    """
    Update per-user usage with two independent records:

    1. MONTH#YYYY-MM#BEDROCK -- monthly aggregate (ADD only, no conditions)
    2. DAY#YYYY-MM-DD#BEDROCK -- daily record (ADD only, no conditions)

    Both writes are unconditional ADD operations, so they are safe under
    concurrency and event ordering does not matter.  Each day's record is
    independent -- no rollover logic needed.
    """
    pk = f"USER#{email}"
    month_sk = f"MONTH#{month_key}#BEDROCK"
    day_sk = f"DAY#{date_key}#BEDROCK"

    token_values = {
        ":input": Decimal(str(input_tokens)),
        ":output": Decimal(str(output_tokens)),
        ":cache_read": Decimal(str(cache_read_tokens)),
        ":cache_write": Decimal(str(cache_write_tokens)),
        ":cache_write_5m": Decimal(str(cache_write_5m_tokens)),
        ":cache_write_1h": Decimal(str(cache_write_1h_tokens)),
        ":total": Decimal(str(total_tokens)),
        ":cost": cost,
        ":now": now_iso,
    }

    update_expr = (
        "ADD input_tokens :input, output_tokens :output, "
        "cache_read_tokens :cache_read, cache_write_tokens :cache_write, "
        "cache_write_5m_tokens :cache_write_5m, cache_write_1h_tokens :cache_write_1h, "
        "total_tokens :total, estimated_cost :cost "
        "SET last_updated = :now"
    )

    # --- Monthly aggregate ---
    quota_table.update_item(
        Key={"pk": pk, "sk": month_sk},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=token_values,
    )

    # --- Daily record ---
    quota_table.update_item(
        Key={"pk": pk, "sk": day_sk},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=token_values,
    )


def update_org_aggregate(quota_table, month_key: str, total_tokens: int, cost: Decimal) -> None:
    """Atomically increment org-wide monthly totals."""
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        quota_table.update_item(
            Key={"pk": "ORG#global", "sk": f"MONTH#{month_key}#BEDROCK"},
            UpdateExpression=(
                "ADD total_tokens :tokens, estimated_cost :cost "
                "SET last_updated = :now"
            ),
            ExpressionAttributeValues={
                ":tokens": Decimal(str(total_tokens)),
                ":cost": cost,
                ":now": now_iso,
            },
        )
    except Exception:
        logger.exception("Failed to update org aggregate for %s", month_key)

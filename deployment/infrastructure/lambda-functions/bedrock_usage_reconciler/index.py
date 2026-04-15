# ABOUTME: EventBridge-triggered Lambda that runs every 30 minutes to reconcile
# ABOUTME: missed Bedrock usage events by scanning S3 logs and reprocessing the DLQ.
# ABOUTME: Shares core logic (pricing, ARN parsing, usage updates) with bedrock_usage_stream
# ABOUTME: via the bedrock_usage_utils layer module.

import json
import logging
import os
import urllib.parse
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from bedrock_usage_utils import (
    PricingCache,
    calculate_cost,
    check_processed_marker,
    compute_marker_hash,
    parse_log_entry,
    read_and_parse_s3_log,
    update_org_aggregate,
    update_user_usage,
    write_processed_marker,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

# In-memory pricing cache (refreshed once per cold start)
_pricing_cache = PricingCache()


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
    Build hour-level S3 key prefixes covering the time window.

    Bedrock invocation log path format:
        {BEDROCK_LOG_PREFIX}AWSLogs/{account_id}/BedrockModelInvocationLogs/{region}/{YYYY}/{MM}/{DD}/{HH}/

    The region in the S3 key is the deployment/entry region (where the
    Bedrock API call is made), which equals AWS_REGION (the Lambda's
    own region). Cross-region inference routes to other regions for
    execution, but the log key always uses the entry region.

    A 35-minute window spans at most 2 distinct hours. We enumerate
    each hour and build a precise prefix, avoiding a full bucket scan.
    """
    if not AWS_ACCOUNT_ID:
        logger.warning("AWS_ACCOUNT_ID not set, cannot build S3 prefixes")
        return []

    region = os.environ.get("AWS_REGION", "us-east-1")

    base = (
        f"{BEDROCK_LOG_PREFIX}AWSLogs/{AWS_ACCOUNT_ID}/"
        f"BedrockModelInvocationLogs/{region}/"
    )

    # Enumerate each distinct hour between window_start and window_end
    prefixes = []
    current = window_start.replace(minute=0, second=0, microsecond=0)
    while current <= window_end:
        prefix = base + current.strftime("%Y/%m/%d/%H/")
        prefixes.append(prefix)
        current += timedelta(hours=1)

    logger.info("Built %d hour-level S3 prefixes for reconciliation", len(prefixes))
    return prefixes


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
            key_hash = compute_marker_hash(s3_key)
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
    # Guard: skip if already processed (prevents double-counting on DLQ retry)
    if check_processed_marker(quota_table, s3_key):
        logger.info("Already processed (marker exists), skipping: %s", s3_key)
        return

    # Skip raw body files in data/ subfolder
    if "/data/" in s3_key:
        logger.info("Skipping body file (data/ subfolder): %s", s3_key)
        write_processed_marker(quota_table, s3_key)
        return

    # 1. Read and parse S3 object
    log_entries = read_and_parse_s3_log(s3_client, bucket, s3_key)

    if not log_entries:
        logger.warning("No parseable JSON in s3://%s/%s", bucket, s3_key)
        write_processed_marker(quota_table, s3_key)
        return

    # Write processed marker BEFORE any further checks
    write_processed_marker(quota_table, s3_key)

    # Process each log entry
    for log_entry in log_entries:
        _process_single_entry(log_entry, s3_key, bucket)


def _process_single_entry(log_entry: dict, s3_key: str, bucket: str) -> None:
    """Process a single Bedrock invocation log entry (reconciler path)."""
    parsed = parse_log_entry(log_entry, s3_client=s3_client)
    if parsed is None:
        identity = log_entry.get("identity", {})
        if isinstance(identity, list):
            identity = identity[0] if identity else {}
        identity_arn = identity.get("arn", "") if isinstance(identity, dict) else ""
        logger.warning(
            "Identity ARN does not match ccwb pattern, skipping: %s (s3://%s/%s)",
            identity_arn, bucket, s3_key,
        )
        return

    pricing = _pricing_cache.get_pricing(parsed["model_id"], pricing_table, DEFAULT_PRICING_JSON)
    cost = calculate_cost(
        pricing,
        parsed["input_tokens"],
        parsed["output_tokens"],
        parsed["cache_read_tokens"],
        parsed["cache_write_tokens"],
        cache_write_5m_tokens=parsed["cache_write_5m_tokens"],
        cache_write_1h_tokens=parsed["cache_write_1h_tokens"],
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    update_user_usage(
        quota_table,
        email=parsed["email"],
        month_key=parsed["month_key"],
        date_key=parsed["date_key"],
        input_tokens=parsed["input_tokens"],
        output_tokens=parsed["output_tokens"],
        cache_read_tokens=parsed["cache_read_tokens"],
        cache_write_tokens=parsed["cache_write_tokens"],
        total_tokens=parsed["total_tokens"],
        cost=cost,
        now_iso=now_iso,
        cache_write_5m_tokens=parsed["cache_write_5m_tokens"],
        cache_write_1h_tokens=parsed["cache_write_1h_tokens"],
    )

    update_org_aggregate(quota_table, parsed["month_key"], parsed["total_tokens"], cost)

    logger.info(
        "Reconciled %s: user=%s model=%s tokens=%d (input=%d output=%d cache_read=%d cache_write=%d [5m=%d 1h=%d]) cost=$%s",
        s3_key, parsed["email"], parsed["model_id"], parsed["total_tokens"],
        parsed["input_tokens"], parsed["output_tokens"],
        parsed["cache_read_tokens"], parsed["cache_write_tokens"],
        parsed["cache_write_5m_tokens"], parsed["cache_write_1h_tokens"], cost,
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

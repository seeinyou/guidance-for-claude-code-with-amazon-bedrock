# ABOUTME: SQS-triggered Lambda that processes Bedrock Model Invocation Log files from S3
# ABOUTME: Extracts token usage and cost per user, updates DynamoDB quota records
# ABOUTME: Uses ReportBatchItemFailures for partial SQS batch failure handling

import json
import logging
import os
import urllib.parse
from datetime import datetime, timezone

import boto3

from bedrock_usage_utils import (
    PricingCache,
    calculate_cost,
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
dynamodb = boto3.resource("dynamodb")

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
PRICING_TABLE = os.environ.get("PRICING_TABLE", "BedrockPricing")
DEFAULT_PRICING_JSON = os.environ.get("DEFAULT_PRICING_JSON", "")

quota_table = dynamodb.Table(QUOTA_TABLE)
pricing_table = dynamodb.Table(PRICING_TABLE)

# In-memory pricing cache (refreshed once per cold start)
_pricing_cache = PricingCache()


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
        write_processed_marker(quota_table, s3_key)
        return

    # 1. Read and parse S3 object
    log_entries = read_and_parse_s3_log(s3_client, bucket, s3_key)

    if not log_entries:
        logger.warning("No parseable JSON in s3://%s/%s", bucket, s3_key)
        write_processed_marker(quota_table, s3_key)
        return

    # 2. Write processed marker BEFORE any further checks
    write_processed_marker(quota_table, s3_key)

    # 3. Process each log entry in the file
    for log_entry in log_entries:
        _process_single_entry(log_entry, s3_key, bucket)


def _process_single_entry(log_entry: dict, s3_key: str, bucket: str) -> None:
    """Process a single Bedrock invocation log entry."""
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

    # Look up pricing and calculate cost
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

    # Update per-user usage: MONTH# and DAY# records (unconditional ADD)
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

    # Update org aggregate
    update_org_aggregate(quota_table, parsed["month_key"], parsed["total_tokens"], cost)

    logger.info(
        "Processed %s: user=%s model=%s tokens=%d (input=%d output=%d cache_read=%d cache_write=%d [5m=%d 1h=%d]) cost=$%s",
        s3_key, parsed["email"], parsed["model_id"], parsed["total_tokens"],
        parsed["input_tokens"], parsed["output_tokens"],
        parsed["cache_read_tokens"], parsed["cache_write_tokens"],
        parsed["cache_write_5m_tokens"], parsed["cache_write_1h_tokens"], cost,
    )

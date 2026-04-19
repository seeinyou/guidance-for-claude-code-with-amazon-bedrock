# ABOUTME: CloudFormation Custom Resource Lambda that enables Bedrock Model Invocation Logging
# ABOUTME: Creates/configures an S3 bucket and activates logging on Create/Update; no-ops on Delete

import json
import boto3
import os
import traceback
from urllib.request import Request, urlopen

# Initialize clients
bedrock_client = boto3.client("bedrock")
s3_client = boto3.client("s3")
sts_client = boto3.client("sts")


def handler(event, context):
    """
    CloudFormation Custom Resource handler for Bedrock Model Invocation Logging.

    On Create/Update: ensures Bedrock invocation logging is enabled, creating
    an S3 bucket and bucket policy if needed.
    On Delete: returns SUCCESS without disabling logging or deleting the bucket.
    """
    request_type = event.get("RequestType", "")
    print(f"Received {request_type} request")
    print(f"Event: {json.dumps(event, default=str)}")

    try:
        if request_type in ("Create", "Update"):
            response_data = handle_create_update(event)
        elif request_type == "Delete":
            print("Delete request - skipping cleanup (logging and bucket retained)")
            response_data = {"Message": "Delete is a no-op; logging and bucket retained"}
        else:
            raise ValueError(f"Unsupported RequestType: {request_type}")

        send_cfn_response(event, context, "SUCCESS", response_data)

    except Exception as e:
        print(f"Error handling {request_type} request: {str(e)}")
        traceback.print_exc()
        send_cfn_response(
            event,
            context,
            "FAILED",
            {"Error": str(e)},
            reason=f"Exception: {str(e)}",
        )


DEFAULT_LOG_PREFIX = "bedrock-raw/"


def handle_create_update(event):
    """
    Check if Bedrock invocation logging is already enabled. If not, set it up
    with an S3 bucket and bucket policy, then enable logging.

    If logging is already enabled, respect the existing bucket and keyPrefix
    — the S3 -> SQS notification and reconciler MUST use the same prefix that
    Bedrock actually writes to, otherwise log events never trigger processing.

    Returns response data dict with the bucket name and log prefix used.
    """
    # 1. Check current logging configuration
    print("Checking current Bedrock model invocation logging configuration...")
    current_config = bedrock_client.get_model_invocation_logging_configuration()
    logging_config = current_config.get("loggingConfig", {})
    s3_config = logging_config.get("s3Config", {})

    properties = event.get("ResourceProperties", {})

    existing_bucket = s3_config.get("bucketName")
    if existing_bucket:
        # Respect whatever prefix Bedrock is already writing to.  Normalize so
        # empty string becomes ""/no prefix, and non-empty always ends with "/".
        raw_prefix = s3_config.get("keyPrefix", "") or ""
        log_prefix = (raw_prefix.rstrip("/") + "/") if raw_prefix else ""
        print(
            f"Logging already enabled with bucket: {existing_bucket}, "
            f"keyPrefix: {log_prefix!r}"
        )
        # Still configure S3 event notification (idempotent) — use the
        # EXISTING prefix, not the default.
        sqs_queue_arn = properties.get("SQSQueueArn")
        if sqs_queue_arn:
            _configure_s3_event_notification(existing_bucket, sqs_queue_arn, log_prefix)
        return {
            "BucketName": existing_bucket,
            "LogPrefix": log_prefix,
            "Message": "Logging already enabled",
        }

    # 2. Logging not enabled - determine bucket name
    bucket_name = properties.get("BedrockLogBucketName")

    if not bucket_name:
        account_id = sts_client.get_caller_identity()["Account"]
        region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        bucket_name = f"bedrock-invocation-logs-{account_id}-{region}"

    print(f"Will use S3 bucket: {bucket_name}")

    # 3. Create bucket if it doesn't exist
    ensure_bucket_exists(bucket_name)

    # 4. Apply bucket policy for Bedrock service access
    put_bedrock_bucket_policy(bucket_name, DEFAULT_LOG_PREFIX)

    # 5. Enable Bedrock model invocation logging
    print("Enabling Bedrock model invocation logging...")
    bedrock_client.put_model_invocation_logging_configuration(
        loggingConfig={
            "s3Config": {
                "bucketName": bucket_name,
                "keyPrefix": DEFAULT_LOG_PREFIX,
            },
            "textDataDeliveryEnabled": True,
            "imageDataDeliveryEnabled": False,
            "embeddingDataDeliveryEnabled": False,
        }
    )
    print(f"Successfully enabled Bedrock logging to s3://{bucket_name}/{DEFAULT_LOG_PREFIX}")

    # 6. Configure S3 event notification to SQS (for usage stream Lambda)
    sqs_queue_arn = properties.get("SQSQueueArn")
    if sqs_queue_arn:
        _configure_s3_event_notification(bucket_name, sqs_queue_arn, DEFAULT_LOG_PREFIX)

    return {
        "BucketName": bucket_name,
        "LogPrefix": DEFAULT_LOG_PREFIX,
        "Message": "Logging enabled successfully",
    }


def ensure_bucket_exists(bucket_name):
    """
    Create the S3 bucket if it doesn't already exist.
    Handles BucketAlreadyOwnedByYou gracefully.
    """
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

    try:
        s3_client.head_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} already exists")
        return
    except s3_client.exceptions.ClientError as e:
        error_code = int(e.response["Error"].get("Code", 0))
        if error_code == 404:
            print(f"Bucket {bucket_name} does not exist, creating...")
        elif error_code == 403:
            # Bucket exists but we don't have access - this is a problem
            raise RuntimeError(
                f"Bucket {bucket_name} exists but this account does not have access"
            ) from e
        else:
            raise

    try:
        create_kwargs = {"Bucket": bucket_name}
        # us-east-1 does not accept a LocationConstraint
        if region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": region,
            }
        s3_client.create_bucket(**create_kwargs)
        print(f"Created bucket {bucket_name}")
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        print(f"Bucket {bucket_name} already owned by this account")
    except s3_client.exceptions.BucketAlreadyExists:
        raise RuntimeError(
            f"Bucket {bucket_name} already exists and is owned by another account"
        )


def put_bedrock_bucket_policy(bucket_name, log_prefix):
    """
    Apply a bucket policy that allows the Bedrock service to write invocation
    logs under ``log_prefix``.  The prefix must match the keyPrefix configured
    on Bedrock model invocation logging, otherwise PutObject will be denied.
    """
    account_id = sts_client.get_caller_identity()["Account"]
    resource_prefix = log_prefix.rstrip("/") + "/" if log_prefix else ""

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBedrockLogging",
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com",
                },
                "Action": [
                    "s3:PutObject",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/{resource_prefix}*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                    },
                },
            },
        ],
    }

    print(f"Applying bucket policy to {bucket_name} for Bedrock logging")
    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(bucket_policy),
    )
    print("Bucket policy applied successfully")


def _configure_s3_event_notification(bucket_name, sqs_queue_arn, log_prefix_base):
    """
    Configure S3 event notification on the Bedrock log bucket to send
    ObjectCreated events to the SQS queue for the usage stream Lambda.

    ``log_prefix_base`` is the Bedrock S3 keyPrefix (e.g. "bedrock-raw/" or
    "bedrock-logs/") — MUST match what Bedrock actually writes to, otherwise
    events never fire.

    Replaces any existing queue configuration for the same SQS queue so the
    prefix stays in sync if it changes (e.g. when Bedrock logging was already
    configured with a different prefix before this stack was deployed).
    Merges with other unrelated notifications to avoid overwriting them.
    """
    account_id = sts_client.get_caller_identity()["Account"]
    log_prefix = f"{log_prefix_base}AWSLogs/{account_id}/BedrockModelInvocationLogs/"

    print(f"Configuring S3 event notification: s3://{bucket_name}/{log_prefix}* -> {sqs_queue_arn}")

    try:
        # Get existing notification configuration to avoid overwriting
        existing = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        # Remove ResponseMetadata which isn't part of the config
        existing.pop("ResponseMetadata", None)

        # Drop any previous configuration pointing at OUR SQS queue so we can
        # replace it with the (possibly updated) prefix.  Leave configurations
        # for other queues/topics/Lambdas untouched.
        queue_configs = [
            qc for qc in existing.get("QueueConfigurations", [])
            if qc.get("QueueArn") != sqs_queue_arn
        ]

        # Add our notification with the current prefix
        queue_configs.append({
            "QueueArn": sqs_queue_arn,
            "Events": ["s3:ObjectCreated:*"],
            "Filter": {
                "Key": {
                    "FilterRules": [
                        {"Name": "prefix", "Value": log_prefix},
                    ]
                }
            },
        })
        existing["QueueConfigurations"] = queue_configs

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=existing,
        )
        print("S3 event notification configured successfully")
    except Exception as e:
        # Non-fatal — admin can configure manually
        print(f"Warning: Could not configure S3 event notification: {e}")
        print("You may need to configure S3 -> SQS notification manually")
        traceback.print_exc()


def send_cfn_response(event, context, status, data, reason=None):
    """
    Send a response to the CloudFormation pre-signed URL.

    This is the standard cfnresponse pattern using urllib to PUT a JSON payload
    back to the CloudFormation wait condition URL.
    """
    response_url = event.get("ResponseURL")
    if not response_url:
        print("No ResponseURL found - skipping CFN response (likely a direct invocation)")
        return

    physical_resource_id = event.get("PhysicalResourceId", context.log_stream_name)

    response_body = {
        "Status": status,
        "Reason": reason or f"See CloudWatch Log Stream: {context.log_stream_name}",
        "PhysicalResourceId": physical_resource_id,
        "StackId": event.get("StackId", ""),
        "RequestId": event.get("RequestId", ""),
        "LogicalResourceId": event.get("LogicalResourceId", ""),
        "NoEcho": False,
        "Data": data or {},
    }

    json_body = json.dumps(response_body).encode("utf-8")

    print(f"Sending {status} response to CloudFormation")
    print(f"Response body: {json.dumps(response_body, default=str)}")

    try:
        request = Request(
            response_url,
            data=json_body,
            headers={
                "Content-Type": "",
                "Content-Length": str(len(json_body)),
            },
            method="PUT",
        )
        with urlopen(request) as response:
            print(f"CloudFormation response sent: HTTP {response.status}")
    except Exception as e:
        print(f"Error sending CloudFormation response: {str(e)}")
        traceback.print_exc()
        raise

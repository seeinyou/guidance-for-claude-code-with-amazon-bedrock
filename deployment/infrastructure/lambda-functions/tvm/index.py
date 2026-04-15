# ABOUTME: Token Vending Machine (TVM) Lambda — sole path to Bedrock credentials.
# ABOUTME: Exposed as POST /tvm on HTTP API Gateway with Cognito JWT Authorizer.
# ABOUTME: Enforces quota checks, adaptive session duration, and user profile tracking
# ABOUTME: before issuing time-scoped STS credentials for bedrock:InvokeModel*.

import json
import re
import base64
import time
import boto3
import os
import traceback
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from boto3.dynamodb.conditions import Key

# ---------------------------------------------------------------------------
# Effective timezone for daily / monthly quota boundaries (UTC+8)
# ---------------------------------------------------------------------------
EFFECTIVE_TZ = timezone(timedelta(hours=8))

# ---------------------------------------------------------------------------
# AWS clients
# ---------------------------------------------------------------------------
dynamodb = boto3.resource("dynamodb")
sts_client = boto3.client("sts")

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
POLICIES_TABLE = os.environ.get("POLICIES_TABLE", "QuotaPolicies")
PRICING_TABLE = os.environ.get("PRICING_TABLE", "BedrockPricing")
BEDROCK_USER_ROLE_ARN = os.environ.get("BEDROCK_USER_ROLE_ARN", "")
TVM_SESSION_DURATION = int(os.environ.get("TVM_SESSION_DURATION", "900"))
REQUIRE_OTEL_HELPER = os.environ.get("REQUIRE_OTEL_HELPER", "false").lower() == "true"
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

# ---------------------------------------------------------------------------
# DynamoDB table handles
# ---------------------------------------------------------------------------
quota_table = dynamodb.Table(QUOTA_TABLE)
policies_table = dynamodb.Table(POLICIES_TABLE)


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------
class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles DynamoDB Decimal types."""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def _json(obj: dict) -> str:
    return json.dumps(obj, cls=DecimalEncoder)


# ===================================================================
#  HANDLER
# ===================================================================

def lambda_handler(event, context):
    """
    Token Vending Machine entry-point.

    Authentication is handled by the API Gateway JWT Authorizer (Cognito).
    This function:
      1. Extracts and validates the caller identity
      2. Upserts the user profile
      3. Enforces org-wide and per-user quota limits
      4. Issues time-scoped Bedrock credentials via STS AssumeRole
    """
    try:
        # -- 1. Extract email from JWT claims --------------------------------
        authorizer_ctx = event.get("requestContext", {}).get("authorizer", {})
        jwt_claims = authorizer_ctx.get("jwt", {}).get("claims", {})
        email = jwt_claims.get("email")

        # Fallback: decode JWT from Authorization header (token already
        # validated by API GW — we only need the claims payload).
        if not email:
            auth_header = (event.get("headers") or {}).get("authorization", "")
            if auth_header.startswith("Bearer "):
                try:
                    token = auth_header[7:]
                    payload_b64 = token.split(".")[1]
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += "=" * padding
                    jwt_claims = json.loads(base64.b64decode(payload_b64))
                    email = jwt_claims.get("email")
                    if email:
                        print(f"[TVM] Email from Authorization header fallback: {email}")
                except Exception as fb_err:
                    print(f"[TVM] Fallback JWT decode failed: {fb_err}")

        if not email:
            print(f"[TVM] JWT missing email claim. Available claims: {list(jwt_claims.keys())}")
            return _error(403, "missing_email", "JWT token does not contain an email claim")

        groups = extract_groups_from_claims(jwt_claims)
        print(f"[TVM] Request from {email}, groups={groups}")

        # -- 2. OTEL helper status check -------------------------------------
        headers = event.get("headers") or {}
        otel_status = headers.get("x-otel-helper-status", "")
        print(f"[TVM] X-OTEL-Helper-Status: {otel_status!r}")

        if REQUIRE_OTEL_HELPER and otel_status != "valid":
            return _error(
                403,
                "otel_helper_required",
                "OTEL helper is required but status is not valid. "
                "Please ensure otel-helper is running.",
            )

        # -- 3. Upsert user profile ------------------------------------------
        _upsert_profile(email, jwt_claims)

        # -- 4. Check profile status (disabled?) ------------------------------
        profile = _get_profile(email)
        if profile and profile.get("status") == "disabled":
            return _error(
                403,
                "user_disabled",
                "Your account has been disabled. Contact your administrator.",
            )

        # -- 5. Org-wide limits -----------------------------------------------
        org_block = check_org_limits()
        if org_block:
            return _error(
                429,
                org_block["reason"],
                org_block["message"],
            )

        # -- 6. Resolve effective quota policy --------------------------------
        policy = resolve_quota_for_user(email, groups)

        # -- 7. Get current usage ---------------------------------------------
        usage = get_user_usage(email)

        # -- 8. Check all quota dimensions ------------------------------------
        if policy is not None:
            block = _check_quota_limits(usage, policy)
            if block:
                return _error(429, block["reason"], block["message"])

        # -- 9. Compute adaptive session duration -----------------------------
        max_duration, effective_seconds = _compute_session_duration(usage, policy)

        # -- 10. Assume role and return credentials ---------------------------
        credentials = _assume_role_for_user(email, effective_seconds)

        return _success(200, {
            "credentials": credentials,
            "session_duration": effective_seconds,
            "message": "Credentials issued successfully",
        })

    except Exception as exc:
        print(f"[TVM] Unhandled error: {exc}")
        traceback.print_exc()
        return _error(500, "internal_error", f"Internal error: {exc}")


# ===================================================================
#  RESPONSE BUILDERS
# ===================================================================

def _success(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": _cors_headers(),
        "body": _json(body),
    }


def _error(status_code: int, reason: str, message: str) -> dict:
    return {
        "statusCode": status_code,
        "headers": _cors_headers(),
        "body": _json({
            "error": reason,
            "reason": reason,
            "message": message,
        }),
    }


def _cors_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-OTEL-Helper-Status",
    }


# ===================================================================
#  USER PROFILE
# ===================================================================

def _upsert_profile(email: str, claims: dict) -> None:
    """
    Create-or-update the user profile record.

    Sets ``first_activated`` only on first call (if_not_exists), and
    refreshes ``last_seen`` on every invocation.  ``status`` defaults to
    ``active`` on first creation but is never overwritten afterwards.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    sub = claims.get("sub", "")

    try:
        quota_table.update_item(
            Key={"pk": f"USER#{email}", "sk": "PROFILE"},
            UpdateExpression=(
                "SET first_activated = if_not_exists(first_activated, :now), "
                "last_seen = :now, "
                "#st = if_not_exists(#st, :active), "
                "#sub = :sub"
            ),
            ExpressionAttributeNames={
                "#st": "status",
                "#sub": "sub",
            },
            ExpressionAttributeValues={
                ":now": now_iso,
                ":active": "active",
                ":sub": sub,
            },
        )
    except Exception as exc:
        print(f"[TVM] Error upserting profile for {email}: {exc}")


def _get_profile(email: str) -> dict | None:
    """Read the user profile record."""
    try:
        resp = quota_table.get_item(Key={"pk": f"USER#{email}", "sk": "PROFILE"})
        return resp.get("Item")
    except Exception as exc:
        print(f"[TVM] Error reading profile for {email}: {exc}")
        return None


# ===================================================================
#  USAGE
# ===================================================================

def get_user_usage(email: str) -> dict:
    """
    Get usage for the current month and current day (UTC+8 boundaries).

    Reads two records:
      - ``MONTH#YYYY-MM#BEDROCK`` for monthly totals
      - ``DAY#YYYY-MM-DD#BEDROCK`` for today's daily totals

    Both are authoritative — written by the stream / reconciler Lambdas
    from Bedrock invocation logs.
    """
    now = datetime.now(EFFECTIVE_TZ)
    month = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    pk = f"USER#{email}"

    zero = {
        "total_tokens": 0,
        "daily_tokens": 0,
        "daily_date": current_date,
        "estimated_cost": 0.0,
        "daily_cost": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }

    try:
        # Monthly totals
        month_resp = quota_table.get_item(
            Key={"pk": pk, "sk": f"MONTH#{month}#BEDROCK"}
        )
        month_item = month_resp.get("Item")

        # Daily totals — separate record, no rollover logic needed
        day_resp = quota_table.get_item(
            Key={"pk": pk, "sk": f"DAY#{current_date}#BEDROCK"}
        )
        day_item = day_resp.get("Item")

        if not month_item and not day_item:
            return zero

        return {
            "total_tokens": float((month_item or {}).get("total_tokens", 0)),
            "estimated_cost": float((month_item or {}).get("estimated_cost", 0)),
            "input_tokens": float((month_item or {}).get("input_tokens", 0)),
            "output_tokens": float((month_item or {}).get("output_tokens", 0)),
            "cache_read_tokens": float((month_item or {}).get("cache_read_tokens", 0)),
            "cache_write_tokens": float((month_item or {}).get("cache_write_tokens", 0)),
            "daily_tokens": float((day_item or {}).get("total_tokens", 0)),
            "daily_cost": float((day_item or {}).get("estimated_cost", 0)),
            "daily_date": current_date,
        }
    except Exception as exc:
        print(f"[TVM] Error reading usage for {email}: {exc}")
        return zero


# ===================================================================
#  QUOTA POLICY RESOLUTION
# ===================================================================

def extract_groups_from_claims(claims: dict) -> list:
    """
    Extract group memberships from JWT claims.

    Supports:
      - ``groups`` — standard claim (array or comma-separated string)
      - ``cognito:groups`` — Amazon Cognito groups claim
      - ``custom:department`` — custom department claim (as ``department:<value>``)
    """
    groups = []

    for key in ("groups", "cognito:groups"):
        val = claims.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            groups.extend(val)
        elif isinstance(val, str):
            groups.extend(g.strip() for g in val.split(",") if g.strip())

    dept = claims.get("custom:department")
    if dept:
        groups.append(f"department:{dept}")

    return list(set(groups))


def resolve_quota_for_user(email: str, groups: list) -> dict | None:
    """
    Resolve the effective quota policy for a user.

    Precedence (highest to lowest):
      1. org-level policy (checked separately in ``check_org_limits``)
      2. user-specific policy
      3. group policy (most restrictive if multiple)
      4. default policy
      5. None  (unlimited)
    """
    # 1. User-specific
    user_policy = _get_policy("user", email)
    if user_policy and user_policy.get("enabled", True):
        return user_policy

    # 2. Group policies — pick most restrictive
    if groups:
        group_policies = []
        for group in groups:
            gp = _get_policy("group", group)
            if gp and gp.get("enabled", True):
                group_policies.append(gp)
        if group_policies:
            return min(group_policies, key=_policy_restrictiveness)

    # 3. Default
    default_policy = _get_policy("default", "default")
    if default_policy and default_policy.get("enabled", True):
        return default_policy

    # 4. No policy — unlimited
    return None


def _policy_restrictiveness(p: dict) -> tuple:
    """Sort key: lower tuple = more restrictive."""
    return (
        p.get("monthly_token_limit") or float("inf"),
        p.get("monthly_cost_limit") or float("inf"),
        p.get("daily_token_limit") or float("inf"),
        p.get("daily_cost_limit") or float("inf"),
    )


def _get_policy(policy_type: str, identifier: str) -> dict | None:
    """Read a single policy record from DynamoDB."""
    pk = f"POLICY#{policy_type}#{identifier}"
    try:
        resp = policies_table.get_item(Key={"pk": pk, "sk": "CURRENT"})
        item = resp.get("Item")
        if not item:
            return None
        return {
            "policy_type": item.get("policy_type"),
            "identifier": item.get("identifier"),
            "monthly_token_limit": int(item.get("monthly_token_limit", 0)),
            "daily_token_limit": int(item["daily_token_limit"]) if item.get("daily_token_limit") else None,
            "monthly_cost_limit": float(item["monthly_cost_limit"]) if item.get("monthly_cost_limit") else None,
            "daily_cost_limit": float(item["daily_cost_limit"]) if item.get("daily_cost_limit") else None,
            "enforcement_mode": item.get("enforcement_mode", "alert"),
            "enabled": item.get("enabled", True),
        }
    except Exception as exc:
        print(f"[TVM] Error reading policy {policy_type}:{identifier}: {exc}")
        return None


# ===================================================================
#  ORG-WIDE LIMITS  (cached for 60 s across warm invocations)
# ===================================================================

_org_policy_cache = None
_org_policy_cache_time = 0
_ORG_CACHE_TTL = 60  # seconds


def _get_org_policy() -> dict | None:
    global _org_policy_cache, _org_policy_cache_time
    now = time.time()
    if _org_policy_cache is not None and (now - _org_policy_cache_time) < _ORG_CACHE_TTL:
        return _org_policy_cache
    _org_policy_cache = _get_policy("org", "global")
    _org_policy_cache_time = now
    return _org_policy_cache


def _get_org_usage() -> dict:
    now = datetime.now(EFFECTIVE_TZ)
    sk = f"MONTH#{now.strftime('%Y-%m')}#BEDROCK"
    try:
        resp = quota_table.get_item(Key={"pk": "ORG#global", "sk": sk})
        item = resp.get("Item")
        if not item:
            return {"total_tokens": 0, "estimated_cost": 0.0}
        return {
            "total_tokens": float(item.get("total_tokens", 0)),
            "estimated_cost": float(item.get("estimated_cost", 0)),
        }
    except Exception as exc:
        print(f"[TVM] Error reading org usage: {exc}")
        return {"total_tokens": 0, "estimated_cost": 0.0}


def check_org_limits() -> dict | None:
    """
    Return a block dict if org-wide limits are exceeded, otherwise None.
    """
    org_policy = _get_org_policy()
    if not org_policy or not org_policy.get("enabled", True):
        return None
    if org_policy.get("enforcement_mode", "alert") != "block":
        return None

    org_usage = _get_org_usage()
    total_tokens = org_usage.get("total_tokens", 0)
    estimated_cost = org_usage.get("estimated_cost", 0)

    monthly_limit = org_policy.get("monthly_token_limit", 0)
    monthly_cost_limit = org_policy.get("monthly_cost_limit")

    if monthly_limit > 0 and total_tokens >= monthly_limit:
        return {
            "reason": "org_monthly_tokens_exceeded",
            "message": (
                f"Organization monthly token quota exceeded: "
                f"{int(total_tokens):,} / {int(monthly_limit):,} tokens. "
                "All users are blocked. Contact your administrator."
            ),
        }

    if monthly_cost_limit and monthly_cost_limit > 0 and estimated_cost >= monthly_cost_limit:
        return {
            "reason": "org_monthly_cost_exceeded",
            "message": (
                f"Organization monthly cost quota exceeded: "
                f"${estimated_cost:,.2f} / ${monthly_cost_limit:,.2f}. "
                "All users are blocked. Contact your administrator."
            ),
        }

    return None


# ===================================================================
#  QUOTA LIMIT CHECKS
# ===================================================================

def _check_quota_limits(usage: dict, policy: dict) -> dict | None:
    """
    Check all four quota dimensions.  Returns a block dict on the first
    exceeded limit, or None if everything is within bounds.

    Only enforced when ``enforcement_mode`` is ``block``.
    """
    if policy.get("enforcement_mode", "alert") != "block":
        return None

    monthly_tokens = usage.get("total_tokens", 0)
    daily_tokens = usage.get("daily_tokens", 0)
    estimated_cost = usage.get("estimated_cost", 0)
    daily_cost = usage.get("daily_cost", 0)

    monthly_limit = policy.get("monthly_token_limit", 0)
    daily_limit = policy.get("daily_token_limit")
    monthly_cost_limit = policy.get("monthly_cost_limit")
    daily_cost_limit = policy.get("daily_cost_limit")

    if monthly_limit > 0 and monthly_tokens >= monthly_limit:
        return {
            "reason": "monthly_tokens_exceeded",
            "message": (
                f"Monthly token quota exceeded: {int(monthly_tokens):,} / "
                f"{int(monthly_limit):,} tokens "
                f"({monthly_tokens / monthly_limit * 100:.1f}%). "
                "Contact your administrator."
            ),
        }

    if monthly_cost_limit and monthly_cost_limit > 0 and estimated_cost >= monthly_cost_limit:
        return {
            "reason": "monthly_cost_exceeded",
            "message": (
                f"Monthly cost quota exceeded: ${estimated_cost:,.2f} / "
                f"${monthly_cost_limit:,.2f} "
                f"({estimated_cost / monthly_cost_limit * 100:.1f}%). "
                "Contact your administrator."
            ),
        }

    if daily_limit and daily_limit > 0 and daily_tokens >= daily_limit:
        return {
            "reason": "daily_tokens_exceeded",
            "message": (
                f"Daily token quota exceeded: {int(daily_tokens):,} / "
                f"{int(daily_limit):,} tokens "
                f"({daily_tokens / daily_limit * 100:.1f}%). "
                "Resets at midnight (UTC+8)."
            ),
        }

    if daily_cost_limit and daily_cost_limit > 0 and daily_cost >= daily_cost_limit:
        return {
            "reason": "daily_cost_exceeded",
            "message": (
                f"Daily cost quota exceeded: ${daily_cost:,.2f} / "
                f"${daily_cost_limit:,.2f} "
                f"({daily_cost / daily_cost_limit * 100:.1f}%). "
                "Resets at midnight (UTC+8)."
            ),
        }

    return None


# ===================================================================
#  ADAPTIVE SESSION DURATION
# ===================================================================

def _compute_session_duration(usage: dict, policy: dict | None) -> tuple[int, int]:
    """
    Compute an adaptive STS session duration based on how close the user
    is to their quota limits.

    Returns:
        ``(max_duration, effective_seconds)``
        where ``max_duration = max(900, effective_seconds)`` (STS minimum).
    """
    if policy is None:
        # No policy — unlimited; use configured default
        return (max(900, TVM_SESSION_DURATION), TVM_SESSION_DURATION)

    # Gather usage / limit pairs for every configured dimension
    dimensions = []

    monthly_limit = policy.get("monthly_token_limit", 0)
    if monthly_limit and monthly_limit > 0:
        dimensions.append(usage.get("total_tokens", 0) / monthly_limit)

    monthly_cost_limit = policy.get("monthly_cost_limit")
    if monthly_cost_limit and monthly_cost_limit > 0:
        dimensions.append(usage.get("estimated_cost", 0) / monthly_cost_limit)

    daily_limit = policy.get("daily_token_limit")
    if daily_limit and daily_limit > 0:
        dimensions.append(usage.get("daily_tokens", 0) / daily_limit)

    daily_cost_limit = policy.get("daily_cost_limit")
    if daily_cost_limit and daily_cost_limit > 0:
        dimensions.append(usage.get("daily_cost", 0) / daily_cost_limit)

    if not dimensions:
        # All limits are zero / unset — treat as unlimited
        return (max(900, TVM_SESSION_DURATION), TVM_SESSION_DURATION)

    max_ratio = max(dimensions)

    # Map ratio to session duration
    if max_ratio < 0.80:
        effective = 900
    elif max_ratio < 0.90:
        effective = 300
    elif max_ratio < 0.95:
        effective = 120
    else:
        effective = 60

    return (max(900, effective), effective)


# ===================================================================
#  STS ASSUME ROLE
# ===================================================================

def _assume_role_for_user(email: str, effective_seconds: int) -> dict:
    """
    Assume the Bedrock user role with a time-scoped inline session policy.

    The session policy restricts ``bedrock:InvokeModel*`` to expire at
    ``now + effective_seconds`` via an ``aws:EpochTime`` condition, even
    though the STS token itself may live longer (STS minimum is 900 s).

    Returns a credential dict compatible with the AWS credential_process
    contract (Version 1).
    """
    now_epoch = int(time.time())
    expiration_epoch = now_epoch + effective_seconds

    # Sanitize email for RoleSessionName (max 64 chars, limited charset)
    sanitized = re.sub(r"[^\w+=,.@-]", "-", email)[:59]
    session_name = f"ccwb-{sanitized}"

    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock:InvokeModel*",
                "Resource": "*",
                "Condition": {
                    "NumericLessThan": {
                        "aws:EpochTime": expiration_epoch,
                    }
                },
            }
        ],
    }

    sts_duration = max(900, effective_seconds)

    resp = sts_client.assume_role(
        RoleArn=BEDROCK_USER_ROLE_ARN,
        RoleSessionName=session_name,
        DurationSeconds=sts_duration,
        Policy=json.dumps(session_policy),
    )

    creds = resp["Credentials"]

    # Override Expiration to reflect the *effective* (shorter) window
    effective_expiration = datetime.fromtimestamp(
        expiration_epoch, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "Version": 1,
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
        "Expiration": effective_expiration,
    }

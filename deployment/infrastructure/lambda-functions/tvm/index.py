# ABOUTME: Token Vending Machine (TVM) Lambda — sole path to Bedrock credentials.
# ABOUTME: Exposed as POST /tvm on HTTP API Gateway with Cognito JWT Authorizer.
# ABOUTME: Enforces quota checks, adaptive session duration, and user profile tracking
# ABOUTME: before issuing time-scoped STS credentials for bedrock:InvokeModel*.

import json
import re

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
# When true, shorten session duration and attach a time-scoped inline session
# policy (aws:EpochTime) as the user approaches their quota. Disabled by
# default because the inline policy makes credentials appear invalid before
# the next 15-minute refresh, which surprises clients. With it off, hard
# quota blocks still apply at token-issuance time.
TVM_ADAPTIVE_ENFORCEMENT = os.environ.get("TVM_ADAPTIVE_ENFORCEMENT", "false").lower() == "true"
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
        try:
            _upsert_profile(email, jwt_claims, groups)
        except Exception as exc:
            print(f"[TVM] Profile upsert failed, denying request: {exc}")
            return _error(500, "internal_error", "Unable to verify user profile. Please try again.")

        # -- 4. Check profile status (disabled?) ------------------------------
        profile = _get_profile(email)
        if profile is None:
            print(f"[TVM] Profile read failed after upsert, denying request for {email}")
            return _error(500, "internal_error", "Unable to verify user profile. Please try again.")
        if profile.get("status") == "disabled":
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

        # -- 8. Check for active unblock override -----------------------------
        unblock_remaining = _get_unblock_remaining(email)
        is_unblocked = unblock_remaining is not None
        if is_unblocked:
            print(f"[TVM] User {email} is temporarily unblocked — {unblock_remaining}s remaining, skipping quota enforcement")

        # -- 9. Check all quota dimensions ------------------------------------
        if policy is not None and not is_unblocked:
            block = _check_quota_limits(usage, policy)
            if block:
                return _error(429, block["reason"], block["message"])

        # -- 10. Compute session duration -------------------------------------
        if TVM_ADAPTIVE_ENFORCEMENT:
            _, effective_seconds = _compute_session_duration(usage, policy)
        else:
            effective_seconds = TVM_SESSION_DURATION

        # Cap to unblock remaining time (min 60s, max 900s)
        if is_unblocked and unblock_remaining < effective_seconds:
            effective_seconds = max(60, min(unblock_remaining, 900))
            print(f"[TVM] Capped session to {effective_seconds}s (unblock expiry)")

        # -- 11. Assume role and return credentials ---------------------------
        credentials = _assume_role_for_user(
            email, effective_seconds, scoped=TVM_ADAPTIVE_ENFORCEMENT
        )

        return _success(200, {
            "credentials": credentials,
            "session_duration": effective_seconds,
            "message": "Credentials issued successfully",
        })

    except Exception as exc:
        print(f"[TVM] Unhandled error: {exc}")
        traceback.print_exc()
        return _error(500, "internal_error", "An internal error occurred. Please try again or contact your administrator.")


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

def _upsert_profile(email: str, claims: dict, groups: list | None = None) -> None:
    """
    Create-or-update the user profile record.

    Sets ``first_activated`` only on first call (if_not_exists), and
    refreshes ``last_seen`` on every invocation.  ``status`` defaults to
    ``active`` on first creation but is never overwritten afterwards.
    ``groups`` is overwritten on every call to keep it current.
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
                "#sub = :sub, "
                "#groups = :groups"
            ),
            ExpressionAttributeNames={
                "#st": "status",
                "#sub": "sub",
                "#groups": "groups",
            },
            ExpressionAttributeValues={
                ":now": now_iso,
                ":active": "active",
                ":sub": sub,
                ":groups": groups or [],
            },
        )
    except Exception as exc:
        print(f"[TVM] Error upserting profile for {email}: {exc}")
        raise


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
#  ORG-WIDE LIMITS
# ===================================================================


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
    org_policy = _get_policy("org", "global")
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
#  UNBLOCK CHECK
# ===================================================================

def _get_unblock_remaining(email: str) -> int | None:
    """Return remaining seconds on an active unblock override, or None."""
    try:
        resp = quota_table.get_item(
            Key={"pk": f"USER#{email}", "sk": "UNBLOCK#CURRENT"}
        )
        item = resp.get("Item")
        if not item:
            return None

        expires_at = item.get("expires_at")
        if not expires_at:
            # No expiry recorded — treat as indefinitely unblocked
            return 900

        expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        remaining = int((expires_dt - datetime.now(timezone.utc)).total_seconds())
        if remaining <= 0:
            return None

        return remaining
    except Exception as exc:
        print(f"[TVM] Error checking unblock status for {email}: {exc}")
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
            "usage": int(monthly_tokens),
            "limit": int(monthly_limit),
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
            "usage": round(float(estimated_cost), 2),
            "limit": round(float(monthly_cost_limit), 2),
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
            "usage": int(daily_tokens),
            "limit": int(daily_limit),
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
            "usage": round(float(daily_cost), 2),
            "limit": round(float(daily_cost_limit), 2),
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

    Uses two strategies and takes the shorter result:

    1. **Ratio-based** — percentage of limit consumed (existing logic).
    2. **Remaining-based** — absolute cost remaining across all cost
       dimensions.  Because the usage pipeline is asynchronous (minutes
       of lag), small-quota users can blow past their limit in a single
       long session.  Capping by absolute remaining compensates for this.

    Returns:
        ``(max_duration, effective_seconds)``
        where ``max_duration = max(900, effective_seconds)`` (STS minimum).
    """
    if policy is None:
        # No policy — unlimited; use configured default
        return (max(900, TVM_SESSION_DURATION), TVM_SESSION_DURATION)

    # ------------------------------------------------------------------
    # Strategy 1: ratio-based (percentage of limit consumed)
    # ------------------------------------------------------------------
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

    if max_ratio < 0.80:
        ratio_effective = 900
    elif max_ratio < 0.90:
        ratio_effective = 300
    elif max_ratio < 0.95:
        ratio_effective = 120
    else:
        ratio_effective = 60

    # ------------------------------------------------------------------
    # Strategy 2: absolute cost remaining
    # ------------------------------------------------------------------
    remaining_effective = 900

    cost_remaining = []
    if monthly_cost_limit and monthly_cost_limit > 0:
        cost_remaining.append(monthly_cost_limit - usage.get("estimated_cost", 0))
    if daily_cost_limit and daily_cost_limit > 0:
        cost_remaining.append(daily_cost_limit - usage.get("daily_cost", 0))

    if cost_remaining:
        min_remaining = min(cost_remaining)
        if min_remaining < 5:
            remaining_effective = 60
        elif min_remaining < 10:
            remaining_effective = 300

    # ------------------------------------------------------------------
    # Final: take the shorter of both strategies
    # ------------------------------------------------------------------
    effective = min(ratio_effective, remaining_effective)

    return (max(900, effective), effective)


# ===================================================================
#  STS ASSUME ROLE
# ===================================================================

def _assume_role_for_user(email: str, effective_seconds: int, scoped: bool = False) -> dict:
    """
    Assume the Bedrock user role and return credentials.

    When ``scoped`` is True (adaptive enforcement mode), attach an inline
    session policy that restricts ``bedrock:InvokeModel*`` to expire at
    ``now + effective_seconds`` via an ``aws:EpochTime`` condition, and
    override the returned ``Expiration`` to reflect that shorter window.

    When ``scoped`` is False (default), no inline session policy is attached
    and the native STS ``Expiration`` is returned, so credentials stay valid
    for the full STS duration and the client's normal 15-minute refresh
    cycle is not disrupted.

    Returns a credential dict compatible with the AWS credential_process
    contract (Version 1).
    """
    # Sanitize email for RoleSessionName (max 64 chars, limited charset)
    sanitized = re.sub(r"[^\w+=,.@-]", "-", email)[:59]
    session_name = f"ccwb-{sanitized}"

    sts_duration = max(900, effective_seconds)
    expiration_epoch = int(time.time()) + effective_seconds

    assume_kwargs = {
        "RoleArn": BEDROCK_USER_ROLE_ARN,
        "RoleSessionName": session_name,
        "DurationSeconds": sts_duration,
    }

    if scoped:
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
        assume_kwargs["Policy"] = json.dumps(session_policy)

    resp = sts_client.assume_role(**assume_kwargs)
    creds = resp["Credentials"]

    if scoped:
        expiration = datetime.fromtimestamp(
            expiration_epoch, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        sts_expiration = creds["Expiration"]
        expiration = (
            sts_expiration.strftime("%Y-%m-%dT%H:%M:%SZ")
            if isinstance(sts_expiration, datetime)
            else sts_expiration
        )

    return {
        "Version": 1,
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
        "Expiration": expiration,
    }

# ABOUTME: Lambda function for real-time quota checking before credential issuance
# ABOUTME: Returns allowed/blocked status based on user quota policy and current usage
# ABOUTME: Requires JWT authentication - extracts user identity from API Gateway JWT Authorizer claims

import json
import boto3
import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr

# Effective timezone for daily/monthly quota boundaries (UTC+8)
EFFECTIVE_TZ = timezone(timedelta(hours=8))

# Initialize clients
dynamodb = boto3.resource("dynamodb")

# Configuration from environment
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
POLICIES_TABLE = os.environ.get("POLICIES_TABLE", "QuotaPolicies")
# Security: Control fail behavior when email claim is missing or errors occur
# Default to "block" (fail-closed) for security; set to "open" to allow on failures
MISSING_EMAIL_ENFORCEMENT = os.environ.get("MISSING_EMAIL_ENFORCEMENT", "block")
ERROR_HANDLING_MODE = os.environ.get("ERROR_HANDLING_MODE", "fail_closed")

# DynamoDB tables
quota_table = dynamodb.Table(QUOTA_TABLE)
policies_table = dynamodb.Table(POLICIES_TABLE)


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def lambda_handler(event, context):
    """
    Real-time quota check for credential issuance.

    Authentication:
        JWT token required in Authorization header. API Gateway JWT Authorizer
        validates the token and passes claims to Lambda via requestContext.

    Returns:
        JSON response with allowed status and usage details
    """
    try:
        # Extract validated claims from API Gateway JWT Authorizer
        # The JWT Authorizer validates the token and passes claims to Lambda via requestContext.
        authorizer_context = event.get("requestContext", {}).get("authorizer", {})
        jwt_claims = authorizer_context.get("jwt", {}).get("claims", {})

        # Email from validated JWT claims (secure - no parameter tampering possible)
        email = jwt_claims.get("email")

        # Fallback: if API Gateway didn't pass claims (e.g. payload format mismatch),
        # decode the JWT from the Authorization header directly. The token has already
        # been validated by the API Gateway JWT Authorizer, so signature verification
        # is not required here — we only need the claims.
        if not email:
            auth_header = event.get("headers", {}).get("authorization", "")
            if auth_header.startswith("Bearer "):
                try:
                    import base64
                    token = auth_header[7:]
                    payload_b64 = token.split(".")[1]
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += "=" * padding
                    fallback_claims = json.loads(base64.b64decode(payload_b64))
                    email = fallback_claims.get("email")
                    if email:
                        print(f"Extracted email from Authorization header fallback: {email}")
                        jwt_claims = fallback_claims
                except Exception as fb_err:
                    print(f"Fallback JWT decode failed: {fb_err}")

        # Extract groups from various possible JWT claims
        groups = extract_groups_from_claims(jwt_claims)

        if not email:
            # JWT is valid but missing email claim
            # Security: Default to fail-closed (block) unless explicitly configured to allow
            print(f"JWT missing email claim. Available claims: {list(jwt_claims.keys())}")
            allow_missing_email = MISSING_EMAIL_ENFORCEMENT != "block"
            return build_response(200, {
                "error": "No email claim in JWT token",
                "allowed": allow_missing_email,
                "reason": "missing_email_claim",
                "message": "JWT token does not contain email claim" + (" - quota check skipped" if allow_missing_email else " - access denied for security")
            })

        # 0. Check org-wide limits first (blocks ALL users if exceeded)
        org_block = check_org_limits()
        if org_block:
            return build_response(200, org_block)

        # 1. Resolve the effective quota policy for this user
        policy = resolve_quota_for_user(email, groups)

        if policy is None:
            # No policy = unlimited (quota monitoring disabled)
            return build_response(200, {
                "allowed": True,
                "reason": "no_policy",
                "enforcement_mode": None,
                "usage": None,
                "policy": None,
                "unblock_status": None,
                "message": "No quota policy configured - unlimited access"
            })

        # 2. Check for active unblock override
        unblock_status = get_unblock_status(email)
        if unblock_status and unblock_status.get("is_unblocked"):
            return build_response(200, {
                "allowed": True,
                "reason": "unblocked",
                "enforcement_mode": policy.get("enforcement_mode", "alert"),
                "usage": get_user_usage_summary(email, policy),
                "policy": {
                    "type": policy.get("policy_type"),
                    "identifier": policy.get("identifier")
                },
                "unblock_status": unblock_status,
                "message": f"Access granted - temporarily unblocked until {unblock_status.get('expires_at')}"
            })

        # 3. Get current usage
        usage = get_user_usage(email)
        usage_summary = build_usage_summary(usage, policy)

        # 4. Check if enforcement mode is "block"
        enforcement_mode = policy.get("enforcement_mode", "alert")

        if enforcement_mode != "block":
            # Alert-only mode - always allow
            return build_response(200, {
                "allowed": True,
                "reason": "within_quota",
                "enforcement_mode": enforcement_mode,
                "usage": usage_summary,
                "policy": {
                    "type": policy.get("policy_type"),
                    "identifier": policy.get("identifier")
                },
                "unblock_status": {"is_unblocked": False},
                "message": "Access granted - enforcement mode is alert-only"
            })

        # 5. Check limits (monthly, daily — tokens and cost)
        monthly_tokens = usage.get("total_tokens", 0)
        daily_tokens = usage.get("daily_tokens", 0)
        estimated_cost = usage.get("estimated_cost", 0)
        daily_cost = usage.get("daily_cost", 0)

        monthly_limit = policy.get("monthly_token_limit", 0)
        daily_limit = policy.get("daily_token_limit")
        monthly_cost_limit = policy.get("monthly_cost_limit")
        daily_cost_limit = policy.get("daily_cost_limit")

        policy_ref = {
            "type": policy.get("policy_type"),
            "identifier": policy.get("identifier")
        }

        # Check monthly token limit
        if monthly_limit > 0 and monthly_tokens >= monthly_limit:
            return build_response(200, {
                "allowed": False,
                "reason": "monthly_exceeded",
                "enforcement_mode": enforcement_mode,
                "usage": usage_summary,
                "policy": policy_ref,
                "unblock_status": {"is_unblocked": False},
                "message": f"Monthly quota exceeded: {int(monthly_tokens):,} / {int(monthly_limit):,} tokens ({monthly_tokens/monthly_limit*100:.1f}%). Contact your administrator for assistance."
            })

        # Check monthly cost limit
        if monthly_cost_limit and monthly_cost_limit > 0 and estimated_cost >= monthly_cost_limit:
            return build_response(200, {
                "allowed": False,
                "reason": "monthly_cost_exceeded",
                "enforcement_mode": enforcement_mode,
                "usage": usage_summary,
                "policy": policy_ref,
                "unblock_status": {"is_unblocked": False},
                "message": f"Monthly cost quota exceeded: ${estimated_cost:,.2f} / ${monthly_cost_limit:,.2f} ({estimated_cost/monthly_cost_limit*100:.1f}%). Contact your administrator for assistance."
            })

        # Check daily token limit (if configured)
        if daily_limit and daily_limit > 0 and daily_tokens >= daily_limit:
            return build_response(200, {
                "allowed": False,
                "reason": "daily_exceeded",
                "enforcement_mode": enforcement_mode,
                "usage": usage_summary,
                "policy": policy_ref,
                "unblock_status": {"is_unblocked": False},
                "message": f"Daily quota exceeded: {int(daily_tokens):,} / {int(daily_limit):,} tokens ({daily_tokens/daily_limit*100:.1f}%). Quota resets at midnight (UTC+8)."
            })

        # Check daily cost limit
        if daily_cost_limit and daily_cost_limit > 0 and daily_cost >= daily_cost_limit:
            return build_response(200, {
                "allowed": False,
                "reason": "daily_cost_exceeded",
                "enforcement_mode": enforcement_mode,
                "usage": usage_summary,
                "policy": policy_ref,
                "unblock_status": {"is_unblocked": False},
                "message": f"Daily cost quota exceeded: ${daily_cost:,.2f} / ${daily_cost_limit:,.2f} ({daily_cost/daily_cost_limit*100:.1f}%). Quota resets at midnight (UTC+8)."
            })

        # All checks passed - access allowed
        return build_response(200, {
            "allowed": True,
            "reason": "within_quota",
            "enforcement_mode": enforcement_mode,
            "usage": usage_summary,
            "policy": {
                "type": policy.get("policy_type"),
                "identifier": policy.get("identifier")
            },
            "unblock_status": {"is_unblocked": False},
            "message": "Access granted - within quota limits"
        })

    except Exception as e:
        print(f"Error during quota check: {str(e)}")
        import traceback
        traceback.print_exc()

        # Security: Honor error handling mode - default to fail-closed for security
        allow_on_error = ERROR_HANDLING_MODE != "fail_closed"
        return build_response(200, {
            "allowed": allow_on_error,
            "reason": "check_failed",
            "enforcement_mode": None,
            "usage": None,
            "policy": None,
            "unblock_status": None,
            "message": f"Quota check failed ({ERROR_HANDLING_MODE}): {str(e)}"
        })


def build_response(status_code: int, body: dict) -> dict:
    """Build API Gateway response with CORS headers."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        },
        "body": json.dumps(body, cls=DecimalEncoder)
    }


def extract_groups_from_claims(claims: dict) -> list:
    """
    Extract group memberships from JWT token claims.

    Supports multiple claim formats:
    - groups: Standard groups claim (array or comma-separated string)
    - cognito:groups: Amazon Cognito groups claim
    - custom:department: Custom department claim (treated as a group)

    Args:
        claims: JWT claims dictionary from API Gateway JWT Authorizer

    Returns:
        List of group names
    """
    groups = []

    # Standard groups claim
    if "groups" in claims:
        claim_groups = claims["groups"]
        if isinstance(claim_groups, list):
            groups.extend(claim_groups)
        elif isinstance(claim_groups, str):
            # Could be comma-separated or single value
            groups.extend([g.strip() for g in claim_groups.split(",") if g.strip()])

    # Cognito groups claim
    if "cognito:groups" in claims:
        claim_groups = claims["cognito:groups"]
        if isinstance(claim_groups, list):
            groups.extend(claim_groups)
        elif isinstance(claim_groups, str):
            groups.extend([g.strip() for g in claim_groups.split(",") if g.strip()])

    # Custom department claim (treated as a group for policy matching)
    if "custom:department" in claims:
        department = claims["custom:department"]
        if department:
            groups.append(f"department:{department}")

    return list(set(groups))  # Remove duplicates


def resolve_quota_for_user(email: str, groups: list) -> dict | None:
    """
    Resolve the effective quota policy for a user.
    Precedence: user-specific > group (most restrictive) > default

    Returns:
        Policy dict or None if no policy applies (unlimited).
    """
    # 1. Check for user-specific policy
    user_policy = get_policy("user", email)
    if user_policy and user_policy.get("enabled", True):
        return user_policy

    # 2. Check for group policies (apply most restrictive)
    if groups:
        group_policies = []
        for group in groups:
            group_policy = get_policy("group", group)
            if group_policy and group_policy.get("enabled", True):
                group_policies.append(group_policy)

        if group_policies:
            # Most restrictive = lowest limits across token AND cost dimensions
            # Compare by: monthly_token_limit, monthly_cost_limit, daily_token_limit, daily_cost_limit
            def _policy_restrictiveness(p):
                return (
                    p.get("monthly_token_limit") or float("inf"),
                    p.get("monthly_cost_limit") or float("inf"),
                    p.get("daily_token_limit") or float("inf"),
                    p.get("daily_cost_limit") or float("inf"),
                )
            return min(group_policies, key=_policy_restrictiveness)

    # 3. Fall back to default policy
    default_policy = get_policy("default", "default")
    if default_policy and default_policy.get("enabled", True):
        return default_policy

    # 4. No policy = unlimited
    return None


def get_policy(policy_type: str, identifier: str) -> dict | None:
    """Get a policy from DynamoDB."""
    pk = f"POLICY#{policy_type}#{identifier}"

    try:
        response = policies_table.get_item(Key={"pk": pk, "sk": "CURRENT"})
        item = response.get("Item")

        if not item:
            return None

        return {
            "policy_type": item.get("policy_type"),
            "identifier": item.get("identifier"),
            "monthly_token_limit": int(item.get("monthly_token_limit", 0)),
            "daily_token_limit": int(item.get("daily_token_limit", 0)) if item.get("daily_token_limit") else None,
            "monthly_cost_limit": float(item["monthly_cost_limit"]) if item.get("monthly_cost_limit") else None,
            "daily_cost_limit": float(item["daily_cost_limit"]) if item.get("daily_cost_limit") else None,
            "warning_threshold_80": int(item.get("warning_threshold_80", 0)),
            "warning_threshold_90": int(item.get("warning_threshold_90", 0)),
            "enforcement_mode": item.get("enforcement_mode", "alert"),
            "enabled": item.get("enabled", True),
        }
    except Exception as e:
        print(f"Error getting policy {policy_type}:{identifier}: {e}")
        return None


def get_unblock_status(email: str) -> dict:
    """Check if user has an active unblock override."""
    pk = f"USER#{email}"
    sk = "UNBLOCK#CURRENT"

    try:
        response = quota_table.get_item(Key={"pk": pk, "sk": sk})
        item = response.get("Item")

        if not item:
            return {"is_unblocked": False}

        # Check if unblock has expired
        expires_at = item.get("expires_at")
        if expires_at:
            expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_dt:
                return {"is_unblocked": False, "expired": True}

        return {
            "is_unblocked": True,
            "expires_at": expires_at,
            "unblocked_by": item.get("unblocked_by"),
            "unblocked_at": item.get("unblocked_at"),
            "reason": item.get("reason"),
            "duration_type": item.get("duration_type")
        }
    except Exception as e:
        print(f"Error checking unblock status for {email}: {e}")
        return {"is_unblocked": False, "error": str(e)}


def get_user_usage(email: str) -> dict:
    """Get current usage for a user in the current month (UTC+8 boundaries)."""
    now = datetime.now(EFFECTIVE_TZ)
    month_prefix = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    pk = f"USER#{email}"
    sk = f"MONTH#{month_prefix}"

    try:
        response = quota_table.get_item(Key={"pk": pk, "sk": sk})
        item = response.get("Item")

        if not item:
            return {
                "total_tokens": 0,
                "daily_tokens": 0,
                "daily_date": current_date,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_tokens": 0,
                "estimated_cost": 0.0,
                "daily_cost": 0.0,
            }

        # Check if daily tokens need to be reset (different day)
        daily_date = item.get("daily_date")
        daily_tokens = float(item.get("daily_tokens", 0))
        daily_cost = float(item.get("daily_cost", 0))

        if daily_date != current_date:
            # Day has changed, daily tokens and cost should be 0 for the new day
            daily_tokens = 0
            daily_cost = 0.0

        return {
            "total_tokens": float(item.get("total_tokens", 0)),
            "daily_tokens": daily_tokens,
            "daily_date": daily_date,
            "input_tokens": float(item.get("input_tokens", 0)),
            "output_tokens": float(item.get("output_tokens", 0)),
            "cache_tokens": float(item.get("cache_tokens", 0)),
            "estimated_cost": float(item.get("estimated_cost", 0)),
            "daily_cost": daily_cost,
        }
    except Exception as e:
        print(f"Error getting usage for {email}: {e}")
        return {
            "total_tokens": 0,
            "daily_tokens": 0,
            "daily_date": current_date,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_tokens": 0,
            "estimated_cost": 0.0,
            "daily_cost": 0.0,
        }


def build_usage_summary(usage: dict, policy: dict) -> dict:
    """Build usage summary with percentages including cost data."""
    monthly_tokens = usage.get("total_tokens", 0)
    daily_tokens = usage.get("daily_tokens", 0)
    estimated_cost = usage.get("estimated_cost", 0)
    daily_cost = usage.get("daily_cost", 0)

    monthly_limit = policy.get("monthly_token_limit", 0)
    daily_limit = policy.get("daily_token_limit")
    monthly_cost_limit = policy.get("monthly_cost_limit")
    daily_cost_limit = policy.get("daily_cost_limit")

    summary = {
        "monthly_tokens": int(monthly_tokens),
        "monthly_limit": monthly_limit,
        "monthly_percent": round(monthly_tokens / monthly_limit * 100, 1) if monthly_limit > 0 else 0,
        "daily_tokens": int(daily_tokens),
        "estimated_cost": round(estimated_cost, 2),
        "daily_cost": round(daily_cost, 2),
    }

    if daily_limit:
        summary["daily_limit"] = daily_limit
        summary["daily_percent"] = round(daily_tokens / daily_limit * 100, 1) if daily_limit > 0 else 0

    if monthly_cost_limit:
        summary["monthly_cost_limit"] = monthly_cost_limit
        summary["monthly_cost_percent"] = round(estimated_cost / monthly_cost_limit * 100, 1) if monthly_cost_limit > 0 else 0

    if daily_cost_limit:
        summary["daily_cost_limit"] = daily_cost_limit
        summary["daily_cost_percent"] = round(daily_cost / daily_cost_limit * 100, 1) if daily_cost_limit > 0 else 0

    return summary


def get_user_usage_summary(email: str, policy: dict) -> dict:
    """Get user usage and build summary in one call."""
    usage = get_user_usage(email)
    return build_usage_summary(usage, policy)


# ---- Organization-wide quota check ----

import time

_org_policy_cache = None
_org_policy_cache_time = 0
ORG_POLICY_CACHE_TTL = 60  # seconds


def get_org_policy() -> dict | None:
    """Get org policy with 60s in-memory cache."""
    global _org_policy_cache, _org_policy_cache_time
    now = time.time()
    if _org_policy_cache is not None and (now - _org_policy_cache_time) < ORG_POLICY_CACHE_TTL:
        return _org_policy_cache

    policy = get_policy("org", "global")
    _org_policy_cache = policy
    _org_policy_cache_time = now
    return policy


def get_org_usage() -> dict:
    """Get org aggregate usage for current month (UTC+8 boundaries)."""
    now = datetime.now(EFFECTIVE_TZ)
    sk = f"MONTH#{now.strftime('%Y-%m')}"
    try:
        response = quota_table.get_item(Key={"pk": "ORG#global", "sk": sk})
        item = response.get("Item")
        if not item:
            return {"total_tokens": 0, "estimated_cost": 0.0}
        return {
            "total_tokens": float(item.get("total_tokens", 0)),
            "estimated_cost": float(item.get("estimated_cost", 0)),
            "user_count": int(item.get("user_count", 0)),
        }
    except Exception as e:
        print(f"Error getting org usage: {e}")
        return {"total_tokens": 0, "estimated_cost": 0.0}


def check_org_limits() -> dict | None:
    """Check org-wide limits. Returns block response dict if exceeded, None if OK."""
    org_policy = get_org_policy()
    if not org_policy or not org_policy.get("enabled", True):
        return None

    if org_policy.get("enforcement_mode", "alert") != "block":
        return None

    org_usage = get_org_usage()
    total_tokens = org_usage.get("total_tokens", 0)
    estimated_cost = org_usage.get("estimated_cost", 0)
    monthly_limit = org_policy.get("monthly_token_limit", 0)
    monthly_cost_limit = org_policy.get("monthly_cost_limit")

    if monthly_limit > 0 and total_tokens >= monthly_limit:
        return {
            "allowed": False,
            "reason": "org_monthly_tokens_exceeded",
            "enforcement_mode": "block",
            "usage": {
                "monthly_tokens": int(total_tokens),
                "monthly_limit": monthly_limit,
                "monthly_percent": round(total_tokens / monthly_limit * 100, 1) if monthly_limit > 0 else 0,
                "org_total_tokens": int(total_tokens),
                "org_monthly_limit": monthly_limit,
            },
            "policy": {"type": "org", "identifier": "global"},
            "unblock_status": None,
            "message": f"Organization-wide monthly token quota exceeded: {int(total_tokens):,} / {int(monthly_limit):,} tokens. All users are blocked. Contact your administrator."
        }

    if monthly_cost_limit and monthly_cost_limit > 0 and estimated_cost >= monthly_cost_limit:
        return {
            "allowed": False,
            "reason": "org_monthly_cost_exceeded",
            "enforcement_mode": "block",
            "usage": {
                "monthly_tokens": int(total_tokens),
                "monthly_limit": monthly_limit if monthly_limit > 0 else 0,
                "monthly_percent": round(total_tokens / monthly_limit * 100, 1) if monthly_limit > 0 else 0,
                "estimated_cost": round(estimated_cost, 2),
                "monthly_cost_limit": monthly_cost_limit,
                "monthly_cost_percent": round(estimated_cost / monthly_cost_limit * 100, 1),
                "org_estimated_cost": round(estimated_cost, 2),
                "org_monthly_cost_limit": monthly_cost_limit,
            },
            "policy": {"type": "org", "identifier": "global"},
            "unblock_status": None,
            "message": f"Organization-wide monthly cost quota exceeded: ${estimated_cost:,.2f} / ${monthly_cost_limit:,.2f}. All users are blocked. Contact your administrator."
        }

    return None

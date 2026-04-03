# ABOUTME: Lambda function for admin quota management panel on the landing page
# ABOUTME: Provides web UI and API for CRUD operations on quota policies, usage viewing, and user unblocking

import os
import json
import base64
import boto3
import uuid
import traceback
from datetime import datetime, timezone, timedelta
from decimal import Decimal

# Configuration from environment
QUOTA_POLICIES_TABLE = os.environ.get("QUOTA_POLICIES_TABLE", "QuotaPolicies")
USER_QUOTA_METRICS_TABLE = os.environ.get("USER_QUOTA_METRICS_TABLE", "UserQuotaMetrics")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "")
ADMIN_GROUP_NAME = os.environ.get("ADMIN_GROUP_NAME", "")

# DynamoDB
dynamodb = boto3.resource("dynamodb")
policies_table = dynamodb.Table(QUOTA_POLICIES_TABLE)
metrics_table = dynamodb.Table(USER_QUOTA_METRICS_TABLE)


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types from DynamoDB."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            return float(obj)
        return super().default(obj)


# ============================================
# Request handling
# ============================================

def lambda_handler(event, context):
    """Handle ALB requests for admin panel and API."""
    try:
        path = event.get("path", "/")
        method = event.get("httpMethod", "GET")

        # Extract user info and check admin authorization
        user_email, user_groups = extract_user_info(event)
        if not is_admin(user_email, user_groups):
            return build_html_response(403, generate_forbidden_page(user_email))

        # Route requests
        if path == "/admin" or path == "/admin/":
            return build_html_response(200, generate_admin_page(user_email))

        elif path == "/api/policies":
            if method == "GET":
                return api_list_policies()
            elif method == "POST":
                return api_create_policy(event, user_email)
            elif method == "PUT":
                return api_update_policy(event)
            elif method == "DELETE":
                return api_delete_policy(event)

        elif path == "/api/usage" and method == "GET":
            return api_get_usage(event)

        elif path == "/api/users" and method == "GET":
            return api_list_users()

        elif path == "/api/unblock" and method == "POST":
            return api_unblock_user(event, user_email)

        return build_json_response(404, {"error": "Not found"})

    except Exception as e:
        error_id = str(uuid.uuid4())
        print(f"ERROR_ID={error_id}: {traceback.format_exc()}")
        return build_json_response(500, {"error": "Internal error", "error_id": error_id})


# ============================================
# Authentication & Authorization
# ============================================

def extract_user_info(event):
    """Extract user email and groups from ALB OIDC headers.

    ALB has already validated the JWT signature; we decode the payload for claims.
    """
    email = None
    groups = []

    oidc_data = event.get("headers", {}).get("x-amzn-oidc-data", "")
    if oidc_data:
        try:
            parts = oidc_data.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = json.loads(base64.b64decode(payload_b64))

                email = payload.get("email") or payload.get("preferred_username") or payload.get("upn")
                groups = extract_groups_from_claims(payload)
        except Exception:
            pass

    if not email:
        email = event.get("headers", {}).get("x-amzn-oidc-identity", "")

    return email, groups


def extract_groups_from_claims(claims):
    """Extract group memberships from JWT claims.

    Supports multiple claim formats across IdPs:
    - groups: Standard (Okta, Azure AD)
    - cognito:groups: Amazon Cognito
    - custom:department: Custom department claim
    """
    groups = []

    for claim_key in ("groups", "cognito:groups"):
        if claim_key in claims:
            claim_groups = claims[claim_key]
            if isinstance(claim_groups, list):
                groups.extend(claim_groups)
            elif isinstance(claim_groups, str):
                groups.extend([g.strip() for g in claim_groups.split(",") if g.strip()])

    if "custom:department" in claims:
        department = claims["custom:department"]
        if department:
            groups.append(f"department:{department}")

    return list(set(groups))


def is_admin(email, groups):
    """Check if user is authorized as admin via email list or group membership."""
    if not email:
        return False

    # Check email list
    if ADMIN_EMAILS:
        admin_list = [e.strip().lower() for e in ADMIN_EMAILS.split(",") if e.strip()]
        if email.lower() in admin_list:
            return True

    # Check group membership
    if ADMIN_GROUP_NAME:
        if ADMIN_GROUP_NAME in groups:
            return True

    return False


# ============================================
# Response builders
# ============================================

def build_html_response(status_code, body):
    """Build HTML response for ALB."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": body,
    }


def build_json_response(status_code, body):
    """Build JSON response for ALB."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }


# ============================================
# Token formatting helpers
# ============================================

def format_tokens(tokens):
    """Format token count to human-readable string (e.g., 300M, 1.5B)."""
    tokens = int(tokens)
    if tokens >= 1_000_000_000:
        value = tokens / 1_000_000_000
        return f"{value:.1f}B" if value != int(value) else f"{int(value)}B"
    elif tokens >= 1_000_000:
        value = tokens / 1_000_000
        return f"{value:.1f}M" if value != int(value) else f"{int(value)}M"
    elif tokens >= 1_000:
        value = tokens / 1_000
        return f"{value:.1f}K" if value != int(value) else f"{int(value)}K"
    return str(tokens)


def parse_tokens(value):
    """Parse token value with K/M/B suffix support."""
    if isinstance(value, (int, float)):
        return int(value)

    value = str(value).strip().upper()
    multipliers = {"K": 1_000, "M": 1_000_000, "B": 1_000_000_000}

    for suffix, multiplier in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-1]) * multiplier)

    return int(value)


# ============================================
# API handlers
# ============================================

def api_list_policies():
    """List all quota policies."""
    try:
        response = policies_table.scan(
            FilterExpression="sk = :current",
            ExpressionAttributeValues={":current": "CURRENT"},
        )
        policies = []
        for item in response.get("Items", []):
            policies.append({
                "policy_type": item.get("policy_type"),
                "identifier": item.get("identifier"),
                "monthly_token_limit": int(item.get("monthly_token_limit", 0)),
                "daily_token_limit": int(item.get("daily_token_limit", 0)) if item.get("daily_token_limit") else None,
                "monthly_cost_limit": float(item["monthly_cost_limit"]) if item.get("monthly_cost_limit") else None,
                "daily_cost_limit": float(item["daily_cost_limit"]) if item.get("daily_cost_limit") else None,
                "enforcement_mode": item.get("enforcement_mode", "alert"),
                "enabled": item.get("enabled", True),
                "warning_threshold_80": int(item.get("warning_threshold_80", 0)),
                "warning_threshold_90": int(item.get("warning_threshold_90", 0)),
                "created_by": item.get("created_by"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
            })

        # Sort: default first, then groups, then users
        type_order = {"default": 0, "group": 1, "user": 2}
        policies.sort(key=lambda p: (type_order.get(p["policy_type"], 3), p["identifier"]))

        return build_json_response(200, {"policies": policies})
    except Exception as e:
        print(f"Error listing policies: {e}")
        return build_json_response(500, {"error": f"Failed to list policies: {str(e)}"})


def api_create_policy(event, admin_email):
    """Create a new quota policy."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    policy_type = body.get("policy_type", "").lower()
    identifier = body.get("identifier", "").strip()
    monthly_limit_raw = body.get("monthly_token_limit")

    if policy_type not in ("user", "group", "default", "org"):
        return build_json_response(400, {"error": "Invalid policy_type. Use 'user', 'group', 'default', or 'org'."})
    if not identifier and policy_type not in ("default", "org"):
        return build_json_response(400, {"error": "identifier is required for user/group policies."})
    if not monthly_limit_raw and policy_type != "org":
        return build_json_response(400, {"error": "monthly_token_limit is required."})

    if policy_type == "default":
        identifier = "default"
    if policy_type == "org":
        identifier = "global"

    try:
        monthly_limit = parse_tokens(monthly_limit_raw)
    except (ValueError, TypeError):
        return build_json_response(400, {"error": f"Invalid monthly_token_limit: {monthly_limit_raw}"})

    daily_limit = None
    if body.get("daily_token_limit"):
        try:
            daily_limit = parse_tokens(body["daily_token_limit"])
        except (ValueError, TypeError):
            return build_json_response(400, {"error": f"Invalid daily_token_limit: {body['daily_token_limit']}"})

    enforcement = body.get("enforcement_mode", "alert").lower()
    if enforcement not in ("alert", "block"):
        return build_json_response(400, {"error": "enforcement_mode must be 'alert' or 'block'."})

    enabled = body.get("enabled", True)
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("true", "1", "yes")

    now = datetime.now(timezone.utc).isoformat()
    pk = f"POLICY#{policy_type}#{identifier}"
    warning_80 = int(monthly_limit * 0.8)
    warning_90 = int(monthly_limit * 0.9)

    item = {
        "pk": pk,
        "sk": "CURRENT",
        "policy_type": policy_type,
        "identifier": identifier,
        "monthly_token_limit": monthly_limit,
        "warning_threshold_80": warning_80,
        "warning_threshold_90": warning_90,
        "enforcement_mode": enforcement,
        "enabled": enabled,
        "created_at": now,
        "updated_at": now,
        "created_by": admin_email,
    }
    if daily_limit is not None:
        item["daily_token_limit"] = daily_limit

    # Cost limits
    if body.get("monthly_cost_limit"):
        try:
            mcl = Decimal(str(body["monthly_cost_limit"]).lstrip("$"))
            item["monthly_cost_limit"] = str(mcl)
            item["cost_warning_threshold_80"] = str(mcl * Decimal("0.8"))
            item["cost_warning_threshold_90"] = str(mcl * Decimal("0.9"))
        except Exception:
            return build_json_response(400, {"error": f"Invalid monthly_cost_limit: {body['monthly_cost_limit']}"})

    if body.get("daily_cost_limit"):
        try:
            item["daily_cost_limit"] = str(Decimal(str(body["daily_cost_limit"]).lstrip("$")))
        except Exception:
            return build_json_response(400, {"error": f"Invalid daily_cost_limit: {body['daily_cost_limit']}"})

    try:
        policies_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
        return build_json_response(201, {"message": "Policy created", "policy": item})
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return build_json_response(409, {"error": f"Policy already exists for {policy_type}:{identifier}. Use PUT to update."})
    except Exception as e:
        print(f"Error creating policy: {e}")
        return build_json_response(500, {"error": f"Failed to create policy: {str(e)}"})


def api_update_policy(event):
    """Update an existing quota policy."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    policy_type = body.get("policy_type", "").lower()
    identifier = body.get("identifier", "").strip()

    if policy_type not in ("user", "group", "default", "org"):
        return build_json_response(400, {"error": "Invalid policy_type."})
    if policy_type == "default":
        identifier = "default"
    if not identifier:
        return build_json_response(400, {"error": "identifier is required."})

    pk = f"POLICY#{policy_type}#{identifier}"

    update_parts = ["#updated_at = :updated_at"]
    expression_values = {":updated_at": datetime.now(timezone.utc).isoformat()}
    expression_names = {"#updated_at": "updated_at"}

    if body.get("monthly_token_limit"):
        try:
            monthly_limit = parse_tokens(body["monthly_token_limit"])
            update_parts.append("monthly_token_limit = :monthly")
            expression_values[":monthly"] = monthly_limit
            # Auto-update thresholds
            update_parts.append("warning_threshold_80 = :w80")
            expression_values[":w80"] = int(monthly_limit * 0.8)
            update_parts.append("warning_threshold_90 = :w90")
            expression_values[":w90"] = int(monthly_limit * 0.9)
        except (ValueError, TypeError):
            return build_json_response(400, {"error": f"Invalid monthly_token_limit: {body['monthly_token_limit']}"})

    if "daily_token_limit" in body:
        if body["daily_token_limit"]:
            try:
                update_parts.append("daily_token_limit = :daily")
                expression_values[":daily"] = parse_tokens(body["daily_token_limit"])
            except (ValueError, TypeError):
                return build_json_response(400, {"error": f"Invalid daily_token_limit: {body['daily_token_limit']}"})
        else:
            update_parts.append("daily_token_limit = :daily")
            expression_values[":daily"] = 0

    if "monthly_cost_limit" in body:
        if body["monthly_cost_limit"]:
            try:
                mcl = Decimal(str(body["monthly_cost_limit"]).lstrip("$"))
                update_parts.append("monthly_cost_limit = :mcl")
                expression_values[":mcl"] = str(mcl)
                update_parts.append("cost_warning_threshold_80 = :cw80")
                expression_values[":cw80"] = str(mcl * Decimal("0.8"))
                update_parts.append("cost_warning_threshold_90 = :cw90")
                expression_values[":cw90"] = str(mcl * Decimal("0.9"))
            except Exception:
                return build_json_response(400, {"error": f"Invalid monthly_cost_limit: {body['monthly_cost_limit']}"})
        else:
            update_parts.append("monthly_cost_limit = :mcl")
            expression_values[":mcl"] = "0"

    if "daily_cost_limit" in body:
        if body["daily_cost_limit"]:
            try:
                update_parts.append("daily_cost_limit = :dcl")
                expression_values[":dcl"] = str(Decimal(str(body["daily_cost_limit"]).lstrip("$")))
            except Exception:
                return build_json_response(400, {"error": f"Invalid daily_cost_limit: {body['daily_cost_limit']}"})
        else:
            update_parts.append("daily_cost_limit = :dcl")
            expression_values[":dcl"] = "0"

    if "enforcement_mode" in body:
        mode = body["enforcement_mode"].lower()
        if mode not in ("alert", "block"):
            return build_json_response(400, {"error": "enforcement_mode must be 'alert' or 'block'."})
        update_parts.append("enforcement_mode = :mode")
        expression_values[":mode"] = mode

    if "enabled" in body:
        enabled = body["enabled"]
        if isinstance(enabled, str):
            enabled = enabled.lower() in ("true", "1", "yes")
        update_parts.append("#enabled = :enabled")
        expression_values[":enabled"] = bool(enabled)
        expression_names["#enabled"] = "enabled"

    try:
        response = policies_table.update_item(
            Key={"pk": pk, "sk": "CURRENT"},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names if expression_names else None,
            ConditionExpression="attribute_exists(pk)",
            ReturnValues="ALL_NEW",
        )
        return build_json_response(200, {"message": "Policy updated", "policy": response["Attributes"]})
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return build_json_response(404, {"error": f"Policy not found: {policy_type}:{identifier}"})
    except Exception as e:
        print(f"Error updating policy: {e}")
        return build_json_response(500, {"error": f"Failed to update policy: {str(e)}"})


def api_delete_policy(event):
    """Delete a quota policy."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    policy_type = body.get("policy_type", "").lower()
    identifier = body.get("identifier", "").strip()

    if policy_type not in ("user", "group", "default", "org"):
        return build_json_response(400, {"error": "Invalid policy_type."})
    if policy_type == "default":
        identifier = "default"
    if not identifier:
        return build_json_response(400, {"error": "identifier is required."})

    pk = f"POLICY#{policy_type}#{identifier}"

    try:
        response = policies_table.delete_item(
            Key={"pk": pk, "sk": "CURRENT"},
            ReturnValues="ALL_OLD",
        )
        if "Attributes" in response:
            return build_json_response(200, {"message": f"Policy deleted: {policy_type}:{identifier}"})
        else:
            return build_json_response(404, {"error": f"Policy not found: {policy_type}:{identifier}"})
    except Exception as e:
        print(f"Error deleting policy: {e}")
        return build_json_response(500, {"error": f"Failed to delete policy: {str(e)}"})


def api_get_usage(event):
    """Get usage summary for a specific user."""
    params = event.get("queryStringParameters") or {}
    email = params.get("email", "").strip()

    if not email:
        return build_json_response(400, {"error": "email query parameter is required."})

    now = datetime.now(timezone.utc)
    month_prefix = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    pk = f"USER#{email}"
    sk = f"MONTH#{month_prefix}"

    try:
        response = metrics_table.get_item(Key={"pk": pk, "sk": sk})
        item = response.get("Item")

        if not item:
            return build_json_response(200, {
                "email": email,
                "month": month_prefix,
                "total_tokens": 0,
                "daily_tokens": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_tokens": 0,
                "estimated_cost": 0,
                "daily_cost": 0,
            })

        daily_tokens = float(item.get("daily_tokens", 0))
        daily_cost = float(item.get("daily_cost", 0))
        if item.get("daily_date") != current_date:
            daily_tokens = 0
            daily_cost = 0

        return build_json_response(200, {
            "email": email,
            "month": month_prefix,
            "total_tokens": int(float(item.get("total_tokens", 0))),
            "daily_tokens": int(daily_tokens),
            "input_tokens": int(float(item.get("input_tokens", 0))),
            "output_tokens": int(float(item.get("output_tokens", 0))),
            "cache_tokens": int(float(item.get("cache_tokens", 0))),
            "estimated_cost": round(float(item.get("estimated_cost", 0)), 2),
            "daily_cost": round(daily_cost, 2),
            "first_seen": item.get("first_seen"),
        })
    except Exception as e:
        print(f"Error getting usage for {email}: {e}")
        return build_json_response(500, {"error": f"Failed to get usage: {str(e)}"})


def api_list_users():
    """List all users with their usage and join date for the current month."""
    now = datetime.now(timezone.utc)
    month_prefix = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    try:
        users = []
        scan_kwargs = {
            "FilterExpression": "sk = :sk AND begins_with(pk, :prefix)",
            "ExpressionAttributeValues": {":sk": f"MONTH#{month_prefix}", ":prefix": "USER#"},
        }
        while True:
            response = metrics_table.scan(**scan_kwargs)
            for item in response.get("Items", []):
                email = item.get("email")
                if not email:
                    continue
                daily_tokens = float(item.get("daily_tokens", 0))
                daily_cost = float(item.get("daily_cost", 0))
                if item.get("daily_date") != current_date:
                    daily_tokens = 0
                    daily_cost = 0
                users.append({
                    "email": email,
                    "first_seen": item.get("first_seen"),
                    "total_tokens": int(float(item.get("total_tokens", 0))),
                    "daily_tokens": int(daily_tokens),
                    "estimated_cost": round(float(item.get("estimated_cost", 0)), 2),
                    "daily_cost": round(daily_cost, 2),
                    "last_updated": item.get("last_updated"),
                })
            if "LastEvaluatedKey" in response:
                scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            else:
                break

        # Sort by total_tokens descending
        users.sort(key=lambda u: u["total_tokens"], reverse=True)

        # Also get org aggregate
        org_usage = None
        try:
            org_resp = metrics_table.get_item(Key={"pk": "ORG#global", "sk": f"MONTH#{month_prefix}"})
            org_item = org_resp.get("Item")
            if org_item:
                org_usage = {
                    "total_tokens": int(float(org_item.get("total_tokens", 0))),
                    "estimated_cost": round(float(org_item.get("estimated_cost", 0)), 2),
                    "user_count": int(org_item.get("user_count", 0)),
                }
        except Exception:
            pass

        return build_json_response(200, {"users": users, "month": month_prefix, "org_usage": org_usage})
    except Exception as e:
        print(f"Error listing users: {e}")
        return build_json_response(500, {"error": f"Failed to list users: {str(e)}"})


def api_unblock_user(event, admin_email):
    """Temporarily unblock a user who has exceeded their quota."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    email = body.get("email", "").strip()
    days = body.get("days", 1)

    if not email:
        return build_json_response(400, {"error": "email is required."})
    if not isinstance(days, (int, float)) or days < 1 or days > 7:
        return build_json_response(400, {"error": "days must be between 1 and 7."})

    days = int(days)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=days)

    # Calculate TTL (DynamoDB will auto-delete expired records)
    ttl = int(expires_at.timestamp()) + 86400  # 1 day buffer after expiry

    pk = f"USER#{email}"
    sk = "UNBLOCK#CURRENT"

    try:
        metrics_table.put_item(Item={
            "pk": pk,
            "sk": sk,
            "unblocked_by": admin_email,
            "unblocked_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "reason": body.get("reason", "Admin override via web panel"),
            "duration_type": f"{days}_day{'s' if days > 1 else ''}",
            "ttl": ttl,
        })

        return build_json_response(200, {
            "message": f"User {email} unblocked for {days} day(s)",
            "expires_at": expires_at.isoformat(),
            "unblocked_by": admin_email,
        })
    except Exception as e:
        print(f"Error unblocking {email}: {e}")
        return build_json_response(500, {"error": f"Failed to unblock user: {str(e)}"})


# ============================================
# HTML page generation
# ============================================

def generate_forbidden_page(user_email):
    """Generate 403 Forbidden page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Admin Panel</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            max-width: 500px;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            text-align: center;
        }}
        h1 {{ color: #dc3545; font-size: 24px; margin-bottom: 16px; }}
        p {{ color: #666; margin-bottom: 12px; }}
        .email {{ font-weight: 600; color: #333; }}
        a {{ color: #667eea; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Denied</h1>
        <p>You do not have admin access to the quota management panel.</p>
        <p>Signed in as: <span class="email">{user_email or 'unknown'}</span></p>
        <p>Contact your IT administrator to request access.</p>
        <p><a href="/">Back to Downloads</a></p>
    </div>
</body>
</html>"""


def generate_admin_page(admin_email):
    """Generate the admin quota management SPA."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quota Admin - Claude Code</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .header h1 {{ color: #333; font-size: 24px; }}
        .header-info {{ color: #888; font-size: 14px; }}
        .header-info a {{ color: #667eea; text-decoration: none; }}
        .header-info a:hover {{ text-decoration: underline; }}
        .tabs {{
            display: flex;
            gap: 4px;
            margin-bottom: 24px;
            border-bottom: 2px solid #f0f0f0;
        }}
        .tab {{
            padding: 10px 20px;
            border: none;
            background: none;
            font-size: 15px;
            font-weight: 500;
            color: #888;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            margin-bottom: -2px;
            transition: all 0.2s;
        }}
        .tab:hover {{ color: #667eea; }}
        .tab.active {{
            color: #667eea;
            border-bottom-color: #667eea;
        }}
        .panel {{ display: none; }}
        .panel.active {{ display: block; }}

        /* Table styles */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        .data-table th {{
            text-align: left;
            padding: 10px 12px;
            background: #f8f9fa;
            color: #555;
            font-weight: 600;
            border-bottom: 2px solid #e9ecef;
        }}
        .data-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #f0f0f0;
            color: #333;
        }}
        .data-table tr:hover {{ background: #f8f9ff; }}

        /* Badge styles */
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-user {{ background: #e3f2fd; color: #1565c0; }}
        .badge-group {{ background: #f3e5f5; color: #7b1fa2; }}
        .badge-default {{ background: #e8f5e9; color: #2e7d32; }}
        .badge-org {{ background: #fff3e0; color: #e65100; }}
        .badge-alert {{ background: #fff3e0; color: #e65100; }}
        .badge-block {{ background: #ffebee; color: #c62828; }}
        .badge-enabled {{ background: #e8f5e9; color: #2e7d32; }}
        .badge-disabled {{ background: #f5f5f5; color: #999; }}

        /* Button styles */
        .btn {{
            padding: 6px 14px;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-primary:hover {{ opacity: 0.9; transform: translateY(-1px); }}
        .btn-danger {{ background: #dc3545; color: white; }}
        .btn-danger:hover {{ background: #c82333; }}
        .btn-sm {{ padding: 4px 10px; font-size: 12px; }}
        .btn-edit {{ background: #6c757d; color: white; }}
        .btn-edit:hover {{ background: #5a6268; }}

        /* Form styles */
        .form-section {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid #e9ecef;
        }}
        .form-section h3 {{
            color: #333;
            margin-bottom: 16px;
            font-size: 16px;
        }}
        .form-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }}
        .form-group {{ display: flex; flex-direction: column; }}
        .form-group label {{
            font-size: 13px;
            font-weight: 600;
            color: #555;
            margin-bottom: 4px;
        }}
        .form-group input, .form-group select {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }}
        .form-group input:focus, .form-group select:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102,126,234,0.1);
        }}

        /* Alert/notification */
        .alert {{
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 14px;
            display: none;
        }}
        .alert-success {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
        .alert-error {{ background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}

        /* Usage card */
        .usage-card {{
            background: #f8f9fa;
            border-radius: 12px;
            padding: 24px;
            border: 1px solid #e9ecef;
        }}
        .usage-stat {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .usage-stat:last-child {{ border: none; }}
        .usage-label {{ color: #666; font-weight: 500; }}
        .usage-value {{ color: #333; font-weight: 600; }}

        .toolbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .loading {{ color: #888; font-style: italic; }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Quota Management</h1>
            <div class="header-info">
                Signed in as <strong>{admin_email}</strong>
                &nbsp;|&nbsp;
                <a href="/">Back to Downloads</a>
            </div>
        </div>

        <div id="alert" class="alert"></div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('policies')">Policies</button>
            <button class="tab" onclick="switchTab('users')">Users</button>
            <button class="tab" onclick="switchTab('usage')">Usage Lookup</button>
            <button class="tab" onclick="switchTab('unblock')">Unblock User</button>
        </div>

        <!-- Policies Panel -->
        <div id="panel-policies" class="panel active">
            <div class="toolbar">
                <h3 style="color:#333">Quota Policies</h3>
                <button class="btn btn-primary" onclick="showCreateForm()">+ Create Policy</button>
            </div>

            <div id="create-form" class="form-section" style="display:none">
                <h3 id="form-title">Create Policy</h3>
                <input type="hidden" id="form-mode" value="create">
                <div class="form-row">
                    <div class="form-group">
                        <label>Policy Type</label>
                        <select id="pol-type" onchange="onTypeChange()">
                            <option value="user">User</option>
                            <option value="group">Group</option>
                            <option value="default">Default</option>
                            <option value="org">Organization</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Identifier</label>
                        <input type="text" id="pol-id" placeholder="user@company.com or group-name">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Monthly Token Limit</label>
                        <input type="text" id="pol-monthly" placeholder="e.g. 300M, 1B, 50000">
                    </div>
                    <div class="form-group">
                        <label>Daily Token Limit (optional)</label>
                        <input type="text" id="pol-daily" placeholder="e.g. 15M (leave empty to skip)">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Monthly Cost Limit $ (optional)</label>
                        <input type="text" id="pol-monthly-cost" placeholder="e.g. 100, 200.50">
                    </div>
                    <div class="form-group">
                        <label>Daily Cost Limit $ (optional)</label>
                        <input type="text" id="pol-daily-cost" placeholder="e.g. 10, 25">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Enforcement Mode</label>
                        <select id="pol-enforcement">
                            <option value="alert">Alert (warn only)</option>
                            <option value="block">Block (deny access)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Enabled</label>
                        <select id="pol-enabled">
                            <option value="true">Yes</option>
                            <option value="false">No</option>
                        </select>
                    </div>
                </div>
                <div style="display:flex;gap:8px;margin-top:8px">
                    <button class="btn btn-primary" onclick="submitPolicy()">Save Policy</button>
                    <button class="btn" style="background:#e9ecef;color:#333" onclick="hideCreateForm()">Cancel</button>
                </div>
            </div>

            <div id="policies-loading" class="loading">Loading policies...</div>
            <table class="data-table" id="policies-table" style="display:none">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Identifier</th>
                        <th>Monthly Limit</th>
                        <th>Daily Limit</th>
                        <th>Monthly Cost</th>
                        <th>Daily Cost</th>
                        <th>Enforcement</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="policies-body"></tbody>
            </table>
            <div id="policies-empty" class="empty-state" style="display:none">
                No quota policies configured. Click "Create Policy" to add one.
            </div>
        </div>

        <!-- Users Panel -->
        <div id="panel-users" class="panel">
            <div class="toolbar">
                <h3 style="color:#333">Users</h3>
                <button class="btn btn-primary" onclick="loadUsers()">Refresh</button>
            </div>
            <div id="users-loading" class="loading" style="display:none">Loading users...</div>
            <div id="org-summary" style="display:none;margin-bottom:16px;padding:12px 16px;background:#e8f4fd;border-radius:8px">
                <strong>Organization Total:</strong>
                <span id="org-total-tokens"></span> tokens |
                <span id="org-total-cost"></span> cost |
                <span id="org-user-count"></span> active users
            </div>
            <table class="data-table" id="users-table" style="display:none">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>First Seen</th>
                        <th>Monthly Tokens</th>
                        <th>Daily Tokens</th>
                        <th>Monthly Cost</th>
                        <th>Daily Cost</th>
                        <th>Last Active</th>
                    </tr>
                </thead>
                <tbody id="users-body"></tbody>
            </table>
            <div id="users-empty" class="empty-state" style="display:none">
                No user activity found for the current month.
            </div>
        </div>

        <!-- Usage Panel -->
        <div id="panel-usage" class="panel">
            <div class="form-section">
                <h3>Look Up User Usage</h3>
                <div class="form-row">
                    <div class="form-group">
                        <label>User Email</label>
                        <input type="text" id="usage-email" placeholder="user@company.com">
                    </div>
                    <div class="form-group" style="justify-content:flex-end">
                        <button class="btn btn-primary" onclick="lookupUsage()">Look Up</button>
                    </div>
                </div>
            </div>
            <div id="usage-result" style="display:none">
                <div class="usage-card">
                    <h3 style="color:#333;margin-bottom:16px" id="usage-title">Usage Summary</h3>
                    <div id="usage-stats"></div>
                </div>
            </div>
        </div>

        <!-- Unblock Panel -->
        <div id="panel-unblock" class="panel">
            <div class="form-section">
                <h3>Temporarily Unblock User</h3>
                <p style="color:#666;margin-bottom:16px;font-size:14px">
                    Grant temporary access to a user who has exceeded their quota. Maximum duration is 7 days.
                </p>
                <div class="form-row">
                    <div class="form-group">
                        <label>User Email</label>
                        <input type="text" id="unblock-email" placeholder="user@company.com">
                    </div>
                    <div class="form-group">
                        <label>Duration (days)</label>
                        <select id="unblock-days">
                            <option value="1">1 day</option>
                            <option value="2">2 days</option>
                            <option value="3">3 days</option>
                            <option value="7">7 days</option>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Reason (optional)</label>
                        <input type="text" id="unblock-reason" placeholder="e.g. Urgent project deadline">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="unblockUser()">Unblock User</button>
            </div>
        </div>
    </div>

    <script>
    // Tab switching
    function switchTab(name) {{
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.querySelector(`[onclick="switchTab('${{name}}')"]`).classList.add('active');
        document.getElementById('panel-' + name).classList.add('active');
        if (name === 'users') loadUsers();
    }}

    // Alert
    function showAlert(msg, type) {{
        const el = document.getElementById('alert');
        el.textContent = msg;
        el.className = 'alert alert-' + type;
        el.style.display = 'block';
        setTimeout(() => {{ el.style.display = 'none'; }}, 5000);
    }}

    // Format tokens for display
    function fmtTokens(n) {{
        if (!n) return '-';
        n = parseInt(n);
        if (n >= 1e9) return (n/1e9).toFixed(n%1e9===0?0:1) + 'B';
        if (n >= 1e6) return (n/1e6).toFixed(n%1e6===0?0:1) + 'M';
        if (n >= 1e3) return (n/1e3).toFixed(n%1e3===0?0:1) + 'K';
        return n.toString();
    }}

    // Badge HTML
    function typeBadge(t) {{
        return `<span class="badge badge-${{t}}">${{t}}</span>`;
    }}
    function modeBadge(m) {{
        return `<span class="badge badge-${{m}}">${{m}}</span>`;
    }}
    function statusBadge(enabled) {{
        return enabled
            ? '<span class="badge badge-enabled">enabled</span>'
            : '<span class="badge badge-disabled">disabled</span>';
    }}

    // ---- Policies ----
    let policiesData = [];

    async function loadPolicies() {{
        document.getElementById('policies-loading').style.display = 'block';
        document.getElementById('policies-table').style.display = 'none';
        document.getElementById('policies-empty').style.display = 'none';
        try {{
            const resp = await fetch('/api/policies');
            const data = await resp.json();
            policiesData = data.policies || [];
            renderPolicies();
        }} catch(e) {{
            showAlert('Failed to load policies: ' + e.message, 'error');
        }}
        document.getElementById('policies-loading').style.display = 'none';
    }}

    function renderPolicies() {{
        const tbody = document.getElementById('policies-body');
        if (policiesData.length === 0) {{
            document.getElementById('policies-table').style.display = 'none';
            document.getElementById('policies-empty').style.display = 'block';
            return;
        }}
        document.getElementById('policies-table').style.display = 'table';
        document.getElementById('policies-empty').style.display = 'none';

        tbody.innerHTML = policiesData.map(p => `
            <tr>
                <td>${{typeBadge(p.policy_type)}}</td>
                <td>${{p.identifier}}</td>
                <td>${{fmtTokens(p.monthly_token_limit)}}</td>
                <td>${{p.daily_token_limit ? fmtTokens(p.daily_token_limit) : '-'}}</td>
                <td>${{p.monthly_cost_limit ? '$' + parseFloat(p.monthly_cost_limit).toFixed(2) : '-'}}</td>
                <td>${{p.daily_cost_limit ? '$' + parseFloat(p.daily_cost_limit).toFixed(2) : '-'}}</td>
                <td>${{modeBadge(p.enforcement_mode)}}</td>
                <td>${{statusBadge(p.enabled)}}</td>
                <td>
                    <button class="btn btn-edit btn-sm" onclick="editPolicy('${{p.policy_type}}','${{p.identifier}}')">Edit</button>
                    <button class="btn btn-danger btn-sm" onclick="deletePolicy('${{p.policy_type}}','${{p.identifier}}')">Delete</button>
                </td>
            </tr>
        `).join('');
    }}

    function showCreateForm() {{
        document.getElementById('form-mode').value = 'create';
        document.getElementById('form-title').textContent = 'Create Policy';
        document.getElementById('pol-type').value = 'user';
        document.getElementById('pol-type').disabled = false;
        document.getElementById('pol-id').value = '';
        document.getElementById('pol-id').disabled = false;
        document.getElementById('pol-monthly').value = '';
        document.getElementById('pol-daily').value = '';
        document.getElementById('pol-monthly-cost').value = '';
        document.getElementById('pol-daily-cost').value = '';
        document.getElementById('pol-enforcement').value = 'alert';
        document.getElementById('pol-enabled').value = 'true';
        document.getElementById('create-form').style.display = 'block';
    }}

    function hideCreateForm() {{
        document.getElementById('create-form').style.display = 'none';
    }}

    function onTypeChange() {{
        const t = document.getElementById('pol-type').value;
        const idField = document.getElementById('pol-id');
        if (t === 'default') {{
            idField.value = 'default';
            idField.disabled = true;
        }} else if (t === 'org') {{
            idField.value = 'global';
            idField.disabled = true;
        }} else {{
            idField.disabled = false;
            if (idField.value === 'default') idField.value = '';
            idField.placeholder = t === 'user' ? 'user@company.com' : 'group-name';
        }}
    }}

    function editPolicy(type, identifier) {{
        const p = policiesData.find(x => x.policy_type === type && x.identifier === identifier);
        if (!p) return;
        document.getElementById('form-mode').value = 'edit';
        document.getElementById('form-title').textContent = 'Edit Policy';
        document.getElementById('pol-type').value = p.policy_type;
        document.getElementById('pol-type').disabled = true;
        document.getElementById('pol-id').value = p.identifier;
        document.getElementById('pol-id').disabled = true;
        document.getElementById('pol-monthly').value = fmtTokens(p.monthly_token_limit);
        document.getElementById('pol-daily').value = p.daily_token_limit ? fmtTokens(p.daily_token_limit) : '';
        document.getElementById('pol-monthly-cost').value = p.monthly_cost_limit || '';
        document.getElementById('pol-daily-cost').value = p.daily_cost_limit || '';
        document.getElementById('pol-enforcement').value = p.enforcement_mode;
        document.getElementById('pol-enabled').value = p.enabled ? 'true' : 'false';
        document.getElementById('create-form').style.display = 'block';
    }}

    async function submitPolicy() {{
        const mode = document.getElementById('form-mode').value;
        const body = {{
            policy_type: document.getElementById('pol-type').value,
            identifier: document.getElementById('pol-id').value,
            monthly_token_limit: document.getElementById('pol-monthly').value,
            daily_token_limit: document.getElementById('pol-daily').value || null,
            monthly_cost_limit: document.getElementById('pol-monthly-cost').value || null,
            daily_cost_limit: document.getElementById('pol-daily-cost').value || null,
            enforcement_mode: document.getElementById('pol-enforcement').value,
            enabled: document.getElementById('pol-enabled').value === 'true',
        }};

        const method = mode === 'create' ? 'POST' : 'PUT';
        try {{
            const resp = await fetch('/api/policies', {{
                method: method,
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(body),
            }});
            const data = await resp.json();
            if (resp.ok) {{
                showAlert(data.message || 'Policy saved', 'success');
                hideCreateForm();
                loadPolicies();
            }} else {{
                showAlert(data.error || 'Failed to save policy', 'error');
            }}
        }} catch(e) {{
            showAlert('Request failed: ' + e.message, 'error');
        }}
    }}

    async function deletePolicy(type, identifier) {{
        if (!confirm(`Delete ${{type}} policy for "${{identifier}}"?`)) return;
        try {{
            const resp = await fetch('/api/policies', {{
                method: 'DELETE',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{ policy_type: type, identifier: identifier }}),
            }});
            const data = await resp.json();
            if (resp.ok) {{
                showAlert(data.message || 'Policy deleted', 'success');
                loadPolicies();
            }} else {{
                showAlert(data.error || 'Failed to delete policy', 'error');
            }}
        }} catch(e) {{
            showAlert('Request failed: ' + e.message, 'error');
        }}
    }}

    // ---- Users ----
    async function loadUsers() {{
        document.getElementById('users-loading').style.display = 'block';
        document.getElementById('users-table').style.display = 'none';
        document.getElementById('users-empty').style.display = 'none';
        document.getElementById('org-summary').style.display = 'none';
        try {{
            const resp = await fetch('/api/users');
            const data = await resp.json();
            const users = data.users || [];

            // Show org summary if available
            if (data.org_usage) {{
                document.getElementById('org-total-tokens').textContent = fmtTokens(data.org_usage.total_tokens);
                document.getElementById('org-total-cost').textContent = '$' + parseFloat(data.org_usage.estimated_cost).toFixed(2);
                document.getElementById('org-user-count').textContent = data.org_usage.user_count;
                document.getElementById('org-summary').style.display = 'block';
            }}

            if (users.length === 0) {{
                document.getElementById('users-empty').style.display = 'block';
            }} else {{
                document.getElementById('users-table').style.display = 'table';
                const tbody = document.getElementById('users-body');
                tbody.innerHTML = users.map(u => `
                    <tr>
                        <td>${{u.email}}</td>
                        <td>${{u.first_seen ? new Date(u.first_seen).toLocaleDateString() : '-'}}</td>
                        <td>${{fmtTokens(u.total_tokens)}}</td>
                        <td>${{fmtTokens(u.daily_tokens)}}</td>
                        <td>${{u.estimated_cost ? '$' + parseFloat(u.estimated_cost).toFixed(2) : '$0.00'}}</td>
                        <td>${{u.daily_cost ? '$' + parseFloat(u.daily_cost).toFixed(2) : '$0.00'}}</td>
                        <td>${{u.last_updated ? new Date(u.last_updated).toLocaleString() : '-'}}</td>
                    </tr>
                `).join('');
            }}
        }} catch(e) {{
            showAlert('Failed to load users: ' + e.message, 'error');
        }}
        document.getElementById('users-loading').style.display = 'none';
    }}

    // ---- Usage ----
    async function lookupUsage() {{
        const email = document.getElementById('usage-email').value.trim();
        if (!email) {{ showAlert('Enter an email address', 'error'); return; }}
        try {{
            const resp = await fetch('/api/usage?email=' + encodeURIComponent(email));
            const data = await resp.json();
            if (resp.ok) {{
                document.getElementById('usage-title').textContent = 'Usage: ' + data.email;
                document.getElementById('usage-stats').innerHTML = `
                    <div class="usage-stat"><span class="usage-label">Month</span><span class="usage-value">${{data.month}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Member Since</span><span class="usage-value">${{data.first_seen ? new Date(data.first_seen).toLocaleDateString() : 'Unknown'}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Total Tokens</span><span class="usage-value">${{fmtTokens(data.total_tokens)}} (${{parseInt(data.total_tokens).toLocaleString()}})</span></div>
                    <div class="usage-stat"><span class="usage-label">Daily Tokens</span><span class="usage-value">${{fmtTokens(data.daily_tokens)}} (${{parseInt(data.daily_tokens).toLocaleString()}})</span></div>
                    <div class="usage-stat"><span class="usage-label">Estimated Cost (Monthly)</span><span class="usage-value">${{data.estimated_cost ? '$' + parseFloat(data.estimated_cost).toFixed(2) : '$0.00'}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Estimated Cost (Daily)</span><span class="usage-value">${{data.daily_cost ? '$' + parseFloat(data.daily_cost).toFixed(2) : '$0.00'}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Input Tokens</span><span class="usage-value">${{parseInt(data.input_tokens).toLocaleString()}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Output Tokens</span><span class="usage-value">${{parseInt(data.output_tokens).toLocaleString()}}</span></div>
                    <div class="usage-stat"><span class="usage-label">Cache Tokens</span><span class="usage-value">${{parseInt(data.cache_tokens).toLocaleString()}}</span></div>
                `;
                document.getElementById('usage-result').style.display = 'block';
            }} else {{
                showAlert(data.error || 'Failed to look up usage', 'error');
            }}
        }} catch(e) {{
            showAlert('Request failed: ' + e.message, 'error');
        }}
    }}

    // ---- Unblock ----
    async function unblockUser() {{
        const email = document.getElementById('unblock-email').value.trim();
        const days = parseInt(document.getElementById('unblock-days').value);
        const reason = document.getElementById('unblock-reason').value.trim();
        if (!email) {{ showAlert('Enter an email address', 'error'); return; }}
        if (!confirm(`Unblock "${{email}}" for ${{days}} day(s)?`)) return;
        try {{
            const resp = await fetch('/api/unblock', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{ email, days, reason: reason || undefined }}),
            }});
            const data = await resp.json();
            if (resp.ok) {{
                showAlert(data.message, 'success');
                document.getElementById('unblock-email').value = '';
                document.getElementById('unblock-reason').value = '';
            }} else {{
                showAlert(data.error || 'Failed to unblock user', 'error');
            }}
        }} catch(e) {{
            showAlert('Request failed: ' + e.message, 'error');
        }}
    }}

    // Load policies on page load
    loadPolicies();
    </script>
</body>
</html>"""

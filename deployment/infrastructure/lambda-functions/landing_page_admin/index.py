# ABOUTME: Lambda function for admin quota management panel on the landing page
# ABOUTME: Provides web UI and API for CRUD operations on quota policies, usage viewing, and user unblocking

import os
import json
import html
import base64
import boto3
import uuid
import traceback
from datetime import datetime, timezone, timedelta
from decimal import Decimal

# Effective timezone for daily/monthly quota boundaries (UTC+8)
EFFECTIVE_TZ = timezone(timedelta(hours=8))
from boto3.dynamodb.conditions import Attr
from urllib.parse import unquote

# Configuration from environment
QUOTA_POLICIES_TABLE = os.environ.get("QUOTA_POLICIES_TABLE", "QuotaPolicies")
USER_QUOTA_METRICS_TABLE = os.environ.get("USER_QUOTA_METRICS_TABLE", "UserQuotaMetrics")
ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "")   # seed value only — used once on first cold start
ADMIN_GROUP_NAME = os.environ.get("ADMIN_GROUP_NAME", "")  # IdP group, always checked
PRICING_TABLE = os.environ.get("PRICING_TABLE", "BedrockPricing")

# DynamoDB
dynamodb = boto3.resource("dynamodb")
policies_table = dynamodb.Table(QUOTA_POLICIES_TABLE)
metrics_table = dynamodb.Table(USER_QUOTA_METRICS_TABLE)
pricing_table = dynamodb.Table(PRICING_TABLE) if PRICING_TABLE else None

# ============================================
# Admin user management — DDB as single source of truth
# ============================================

_admins_seeded = False  # module-level flag; resets only on cold start


def seed_admins_if_empty():
    """On cold start, if DDB has no admin records, seed from ADMIN_EMAILS env var.

    After seeding, ADMIN_EMAILS is ignored for auth — DDB is the sole source of truth.
    This also serves as automatic recovery if the admin list is wiped.
    """
    global _admins_seeded
    if _admins_seeded:
        return
    _admins_seeded = True

    if not ADMIN_EMAILS:
        return

    try:
        # Check if any ADMIN# records exist (stop at first hit — no need to scan all)
        response = policies_table.scan(
            FilterExpression=Attr("pk").begins_with("ADMIN#") & Attr("sk").eq("ADMIN"),
            Limit=1,
        )
        if response.get("Items"):
            return  # Already seeded — DDB is the source, env var is ignored

        # Seed from env var
        now = datetime.now(timezone.utc).isoformat()
        seed_emails = [e.strip().lower() for e in ADMIN_EMAILS.split(",") if e.strip()]
        with policies_table.batch_writer() as batch:
            for email in seed_emails:
                batch.put_item(Item={
                    "pk": f"ADMIN#{email}",
                    "sk": "ADMIN",
                    "email": email,
                    "added_by": "system:seed",
                    "added_at": now,
                })
        print(f"Seeded {len(seed_emails)} admin(s) from ADMIN_EMAILS env var")
    except Exception as e:
        print(f"Warning: failed to seed admin list: {e}")


def get_all_ddb_admins():
    """Return all admin email records stored in DDB."""
    admins = []
    try:
        scan_kwargs = {
            "FilterExpression": Attr("pk").begins_with("ADMIN#") & Attr("sk").eq("ADMIN"),
        }
        while True:
            response = policies_table.scan(**scan_kwargs)
            for item in response.get("Items", []):
                admins.append({
                    "email": item.get("email", ""),
                    "added_by": item.get("added_by", ""),
                    "added_at": item.get("added_at", ""),
                    "source": "ddb",
                })
            if "LastEvaluatedKey" in response:
                scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            else:
                break
    except Exception as e:
        print(f"Error loading admin list from DDB: {e}")
    return admins


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
        # Seed admin list from env var on first cold start if DDB is empty
        seed_admins_if_empty()

        path = event.get("path", "/")
        method = event.get("httpMethod", "GET")

        # Extract user info (ALB has already validated OIDC authentication)
        user_email, user_groups = extract_user_info(event)

        # /api/me is available to ALL authenticated users — used by the landing page
        # to show the user's own admin status badge. Must be routed before the admin check.
        if path == "/api/me" and method == "GET":
            return api_get_me(user_email, user_groups)

        # All other routes require admin access
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

        elif path == "/api/admins":
            if method == "GET":
                return api_list_admins()
            elif method == "POST":
                return api_add_admin(event, user_email)
            elif method == "DELETE":
                return api_remove_admin(event)

        elif path == "/api/usage" and method == "GET":
            if not user_email or not user_email.lower().endswith("@amazon.com"):
                return build_json_response(403, {"error": "Usage detail restricted"})
            return api_get_usage(event)

        elif path == "/api/users" and method == "GET":
            return api_list_users(event)

        elif path == "/api/user/disable" and method == "POST":
            return api_disable_user(event)

        elif path == "/api/user/enable" and method == "POST":
            return api_enable_user(event)

        elif path == "/api/unblock" and method == "POST":
            return api_unblock_user(event, user_email)

        elif path == "/api/pricing":
            if method == "GET":
                return api_list_pricing()
            elif method == "POST":
                return api_update_pricing(event)
            elif method == "DELETE":
                return api_delete_pricing(event)

        return build_json_response(404, {"error": "Not found"})

    except Exception as e:
        error_id = str(uuid.uuid4())
        print(f"ERROR_ID={error_id}: {traceback.format_exc()}")
        return build_json_response(500, {"error": "Internal error", "error_id": error_id})


# ============================================
# Authentication & Authorization
# ============================================

def get_header(event, name):
    """Get a header value from either headers or multiValueHeaders (ALB multi-value mode)."""
    mvh = event.get("multiValueHeaders", {})
    if mvh:
        val = mvh.get(name) or mvh.get(name.lower())
        if val:
            return val[0]
    h = event.get("headers", {})
    return h.get(name) or h.get(name.lower()) or ""


def extract_user_info(event):
    """Extract user email and groups from ALB OIDC headers.

    ALB has already validated the JWT signature; we decode the payload for claims.
    """
    email = None
    groups = []

    oidc_data = get_header(event, "x-amzn-oidc-data")
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
        email = get_header(event, "x-amzn-oidc-identity")

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
    """Check if user is an admin.

    Checks DDB admin list first (source of truth), then IdP group membership.
    The ADMIN_EMAILS env var is only used for the one-time DDB seed — not checked here.
    """
    if not email:
        return False

    # Check DDB admin records (primary source of truth)
    try:
        response = policies_table.get_item(
            Key={"pk": f"ADMIN#{email.lower()}", "sk": "ADMIN"}
        )
        if response.get("Item"):
            return True
    except Exception as e:
        print(f"Warning: DDB admin check failed for {email}: {e}")

    # Fall back to IdP group membership (read-only, not stored in DDB)
    if ADMIN_GROUP_NAME and ADMIN_GROUP_NAME in groups:
        return True

    return False


# ============================================
# Response builders
# ============================================

def build_html_response(status_code, body):
    """Build HTML response for ALB."""
    return {
        "statusCode": status_code,
        "multiValueHeaders": {"Content-Type": ["text/html; charset=utf-8"]},
        "body": body,
    }


def build_json_response(status_code, body):
    """Build JSON response for ALB."""
    return {
        "statusCode": status_code,
        "multiValueHeaders": {
            "Content-Type": ["application/json"],
            "Cache-Control": ["no-store"],
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

def api_get_me(email, groups):
    """Return current user's identity and admin status.

    Available to ALL authenticated users — used by the landing page
    to display the status badge without requiring admin access.
    """
    admin = is_admin(email, groups)
    # Determine source if admin
    source = None
    if admin:
        source = "group" if (ADMIN_GROUP_NAME and ADMIN_GROUP_NAME in groups) else "ddb"
    return build_json_response(200, {
        "email": email,
        "is_admin": admin,
        "admin_source": source,
    })


def api_list_admins():
    """List all admins: DDB-managed + IdP group (read-only indicator)."""
    admins = get_all_ddb_admins()
    # Mark IdP group separately so the UI can show it as read-only
    group_note = None
    if ADMIN_GROUP_NAME:
        group_note = ADMIN_GROUP_NAME
    return build_json_response(200, {
        "admins": admins,
        "admin_group_name": group_note,
    })


def api_add_admin(event, added_by):
    """Add an email address as a DDB admin."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    email = body.get("email", "").strip().lower()
    if not email or "@" not in email:
        return build_json_response(400, {"error": "Valid email is required."})

    now = datetime.now(timezone.utc).isoformat()
    try:
        policies_table.put_item(Item={
            "pk": f"ADMIN#{email}",
            "sk": "ADMIN",
            "email": email,
            "added_by": added_by,
            "added_at": now,
        })
        print(f"Admin added: {email} by {added_by}")
        return build_json_response(200, {
            "message": f"{email} is now an admin.",
            "email": email,
            "added_by": added_by,
            "added_at": now,
        })
    except Exception as e:
        print(f"Error adding admin {email}: {e}")
        return build_json_response(500, {"error": f"Failed to add admin: {str(e)}"})


def api_remove_admin(event):
    """Remove an email from the DDB admin list.

    Rejects the request if it would leave zero admins in DDB
    (prevents total lockout).
    """
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    email = body.get("email", "").strip().lower()
    if not email:
        return build_json_response(400, {"error": "email is required."})

    # Guard: ensure at least one admin will remain after removal
    current_admins = get_all_ddb_admins()
    remaining = [a for a in current_admins if a["email"] != email]
    if len(remaining) == 0:
        return build_json_response(400, {
            "error": "Cannot remove the last admin. Add another admin first."
        })

    try:
        response = policies_table.delete_item(
            Key={"pk": f"ADMIN#{email}", "sk": "ADMIN"},
            ReturnValues="ALL_OLD",
        )
        if "Attributes" not in response:
            return build_json_response(404, {"error": f"{email} is not in the admin list."})
        print(f"Admin removed: {email}")
        return build_json_response(200, {"message": f"{email} removed from admins."})
    except Exception as e:
        print(f"Error removing admin {email}: {e}")
        return build_json_response(500, {"error": f"Failed to remove admin: {str(e)}"})


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

    remove_parts = []

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
            remove_parts.extend(["monthly_cost_limit", "cost_warning_threshold_80", "cost_warning_threshold_90"])

    if "daily_cost_limit" in body:
        if body["daily_cost_limit"]:
            try:
                update_parts.append("daily_cost_limit = :dcl")
                expression_values[":dcl"] = str(Decimal(str(body["daily_cost_limit"]).lstrip("$")))
            except Exception:
                return build_json_response(400, {"error": f"Invalid daily_cost_limit: {body['daily_cost_limit']}"})
        else:
            remove_parts.append("daily_cost_limit")

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
        update_expr = "SET " + ", ".join(update_parts)
        if remove_parts:
            update_expr += " REMOVE " + ", ".join(remove_parts)

        response = policies_table.update_item(
            Key={"pk": pk, "sk": "CURRENT"},
            UpdateExpression=update_expr,
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


def api_list_pricing():
    """List all pricing entries from BedrockPricing table."""
    if not pricing_table:
        return build_json_response(400, {"error": "Pricing table not configured."})
    try:
        items = []
        scan_kwargs = {}
        while True:
            response = pricing_table.scan(**scan_kwargs)
            items.extend(response.get("Items", []))
            if "LastEvaluatedKey" in response:
                scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            else:
                break
        # Sort: DEFAULT first, then alphabetical by model_id
        items.sort(key=lambda x: ("" if x.get("model_id") == "DEFAULT" else x.get("model_id", "")))
        pricing = []
        for item in items:
            pricing.append({
                "model_id": item.get("model_id"),
                "input_per_1m": float(item.get("input_per_1m", 0)),
                "output_per_1m": float(item.get("output_per_1m", 0)),
                "cache_read_per_1m": float(item.get("cache_read_per_1m", 0)),
                "cache_write_per_1m": float(item.get("cache_write_per_1m", 0)),
                "cache_write_1h_per_1m": float(item.get("cache_write_1h_per_1m", 0)),
            })
        return build_json_response(200, {"pricing": pricing})
    except Exception as e:
        print(f"Error listing pricing: {e}")
        return build_json_response(500, {"error": f"Failed to list pricing: {str(e)}"})


def api_update_pricing(event):
    """Create or update a pricing entry."""
    if not pricing_table:
        return build_json_response(400, {"error": "Pricing table not configured."})
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    model_id = body.get("model_id", "").strip()
    if not model_id:
        return build_json_response(400, {"error": "model_id is required."})

    try:
        item = {
            "model_id": model_id,
            "input_per_1m": Decimal(str(body.get("input_per_1m", 0))),
            "output_per_1m": Decimal(str(body.get("output_per_1m", 0))),
            "cache_read_per_1m": Decimal(str(body.get("cache_read_per_1m", 0))),
            "cache_write_per_1m": Decimal(str(body.get("cache_write_per_1m", 0))),
            "cache_write_1h_per_1m": Decimal(str(body.get("cache_write_1h_per_1m", 0))),
        }
        pricing_table.put_item(Item=item)
        print(f"Pricing upserted: {model_id}")
        return build_json_response(200, {"message": f"Pricing saved for {model_id}"})
    except Exception as e:
        print(f"Error upserting pricing for {model_id}: {e}")
        return build_json_response(500, {"error": f"Failed to save pricing: {str(e)}"})


def api_delete_pricing(event):
    """Delete a pricing entry by model_id query param."""
    if not pricing_table:
        return build_json_response(400, {"error": "Pricing table not configured."})
    model_id = get_query_param(event, "model_id").strip()
    if not model_id:
        return build_json_response(400, {"error": "model_id query parameter is required."})
    if model_id == "DEFAULT":
        return build_json_response(400, {"error": "Cannot delete the DEFAULT pricing entry."})
    try:
        response = pricing_table.delete_item(
            Key={"model_id": model_id},
            ReturnValues="ALL_OLD",
        )
        if "Attributes" not in response:
            return build_json_response(404, {"error": f"Pricing entry not found: {model_id}"})
        print(f"Pricing deleted: {model_id}")
        return build_json_response(200, {"message": f"Pricing deleted for {model_id}"})
    except Exception as e:
        print(f"Error deleting pricing {model_id}: {e}")
        return build_json_response(500, {"error": f"Failed to delete pricing: {str(e)}"})


def get_query_param(event, name):
    """Get a query parameter from either queryStringParameters or multiValueQueryStringParameters."""
    mvp = event.get("multiValueQueryStringParameters") or {}
    if mvp:
        val = mvp.get(name)
        if val:
            return unquote(val[0])
    params = event.get("queryStringParameters") or {}
    return unquote(params.get(name, ""))


def api_get_usage(event):
    """Get usage summary for a specific user."""
    email = get_query_param(event, "email").strip()

    if not email:
        return build_json_response(400, {"error": "email query parameter is required."})

    now = datetime.now(EFFECTIVE_TZ)
    month_prefix = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    pk = f"USER#{email}"

    try:
        # Monthly usage from Bedrock pipeline
        month_sk = f"MONTH#{month_prefix}#BEDROCK"
        month_resp = metrics_table.get_item(Key={"pk": pk, "sk": month_sk})
        month_item = month_resp.get("Item", {})

        # Daily usage from Bedrock pipeline
        day_sk = f"DAY#{current_date}#BEDROCK"
        day_resp = metrics_table.get_item(Key={"pk": pk, "sk": day_sk})
        day_item = day_resp.get("Item", {})

        # Profile for first_activated
        profile_resp = metrics_table.get_item(Key={"pk": pk, "sk": "PROFILE"})
        profile_item = profile_resp.get("Item", {})

        total_tokens = int(float(month_item.get("total_tokens", 0)))
        input_tokens = int(float(month_item.get("input_tokens", 0)))
        output_tokens = int(float(month_item.get("output_tokens", 0)))
        cache_read_tokens = int(float(month_item.get("cache_read_tokens", 0)))
        cache_write_tokens = int(float(month_item.get("cache_write_tokens", 0)))
        estimated_cost = round(float(month_item.get("estimated_cost", 0)), 2)

        daily_tokens = int(float(day_item.get("total_tokens", 0)))
        daily_cost = round(float(day_item.get("estimated_cost", 0)), 2)

        first_seen = profile_item.get("first_activated")

        # Look up active unblock record
        unblock = None
        try:
            ub_resp = metrics_table.get_item(Key={"pk": pk, "sk": "UNBLOCK#CURRENT"})
            ub_item = ub_resp.get("Item")
            if ub_item:
                expires_at = ub_item.get("expires_at")
                if expires_at:
                    expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if now < expires_dt:
                        unblock = {
                            "unblocked_by": ub_item.get("unblocked_by"),
                            "unblocked_at": ub_item.get("unblocked_at"),
                            "expires_at": expires_at,
                            "reason": ub_item.get("reason"),
                        }
        except Exception:
            pass

        return build_json_response(200, {
            "email": email,
            "month": month_prefix,
            "total_tokens": total_tokens,
            "daily_tokens": daily_tokens,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cache_write_tokens": cache_write_tokens,
            "estimated_cost": estimated_cost,
            "daily_cost": daily_cost,
            "first_seen": first_seen,
            "unblock": unblock,
        })
    except Exception as e:
        print(f"Error getting usage for {email}: {e}")
        return build_json_response(500, {"error": f"Failed to get usage: {str(e)}"})


def api_list_users(event):
    """List all users with their usage, join date, status, and admin status for the current month (UTC+8 boundaries).

    Also queries PROFILE records (SK=PROFILE) for user status (active/disabled), first_activated, last_seen.
    Supports ?status=active|disabled|all query parameter for filtering (default: all).
    """
    status_filter = get_query_param(event, "status").strip().lower() or "all"
    if status_filter not in ("active", "disabled", "all"):
        status_filter = "all"

    now = datetime.now(EFFECTIVE_TZ)
    month_prefix = now.strftime("%Y-%m")
    current_date = now.strftime("%Y-%m-%d")

    # Build admin email set for O(1) lookup
    admin_emails = {a["email"] for a in get_all_ddb_admins()}

    try:
        users_by_email = {}
        profiles_by_email = {}
        unblocks_by_email = {}
        daily_data_by_email = {}
        scan_kwargs = {
            "FilterExpression": (
                Attr("sk").eq(f"MONTH#{month_prefix}#BEDROCK")
                | Attr("sk").eq(f"DAY#{current_date}#BEDROCK")
                | Attr("sk").eq("UNBLOCK#CURRENT")
                | Attr("sk").eq("PROFILE")
            ) & Attr("pk").begins_with("USER#"),
        }
        while True:
            response = metrics_table.scan(**scan_kwargs)
            for item in response.get("Items", []):
                sk = item.get("sk", "")
                pk = item.get("pk", "")
                email_from_pk = pk.replace("USER#", "", 1) if pk.startswith("USER#") else None

                if sk == "PROFILE":
                    if not email_from_pk:
                        continue
                    profiles_by_email[email_from_pk] = {
                        "status": item.get("status", "active"),
                        "first_activated": item.get("first_activated"),
                        "last_seen": item.get("last_seen"),
                    }
                elif sk == "UNBLOCK#CURRENT":
                    if not email_from_pk:
                        continue
                    # Check if unblock has expired
                    expires_at = item.get("expires_at")
                    is_active = False
                    if expires_at:
                        try:
                            expires_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                            is_active = now < expires_dt
                        except (ValueError, TypeError):
                            pass
                    if is_active:
                        unblocks_by_email[email_from_pk] = {
                            "unblocked_by": item.get("unblocked_by"),
                            "unblocked_at": item.get("unblocked_at"),
                            "expires_at": expires_at,
                            "reason": item.get("reason"),
                        }
                elif sk.endswith("#BEDROCK") and sk.startswith("DAY#"):
                    if not email_from_pk:
                        continue
                    daily_data_by_email[email_from_pk] = {
                        "daily_tokens": int(float(item.get("total_tokens", 0))),
                        "daily_cost": round(float(item.get("estimated_cost", 0)), 2),
                    }
                else:
                    # MONTH#YYYY-MM#BEDROCK record
                    if not email_from_pk:
                        continue
                    cache_read = float(item.get("cache_read_tokens", 0))
                    cache_write = float(item.get("cache_write_tokens", 0))
                    users_by_email[email_from_pk] = {
                        "email": email_from_pk,
                        "is_admin": email_from_pk.lower() in admin_emails,
                        "first_seen": None,
                        "total_tokens": int(float(item.get("total_tokens", 0))),
                        "daily_tokens": 0,
                        "daily_cost": 0,
                        "estimated_cost": round(float(item.get("estimated_cost", 0)), 2),
                        "cache_read_tokens": int(cache_read),
                        "cache_write_tokens": int(cache_write),
                        "last_updated": item.get("last_updated"),
                    }
            if "LastEvaluatedKey" in response:
                scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            else:
                break

        # Merge daily data into user records
        for email, daily in daily_data_by_email.items():
            if email in users_by_email:
                users_by_email[email]["daily_tokens"] = daily["daily_tokens"]
                users_by_email[email]["daily_cost"] = daily["daily_cost"]

        # Merge PROFILE data into user records, and create entries for profile-only users
        all_emails = set(users_by_email.keys()) | set(profiles_by_email.keys())
        for email in all_emails:
            if email not in users_by_email:
                # User has a PROFILE but no usage this month
                users_by_email[email] = {
                    "email": email,
                    "is_admin": email.lower() in admin_emails,
                    "first_seen": None,
                    "total_tokens": 0,
                    "daily_tokens": 0,
                    "estimated_cost": 0,
                    "daily_cost": 0,
                    "last_updated": None,
                }
            profile = profiles_by_email.get(email, {})
            users_by_email[email]["status"] = profile.get("status", "active")
            users_by_email[email]["first_activated"] = profile.get("first_activated")
            users_by_email[email]["first_seen"] = profile.get("first_activated")
            users_by_email[email]["last_seen"] = profile.get("last_seen")

        # Merge unblock status into user records
        users = list(users_by_email.values())
        for user in users:
            ub = unblocks_by_email.get(user["email"])
            if ub:
                user["unblock"] = ub
            else:
                user["unblock"] = None

        # Apply status filter
        if status_filter != "all":
            users = [u for u in users if u.get("status", "active") == status_filter]

        # Compute blocked status by checking usage against applicable policies
        try:
            pol_resp = policies_table.scan(
                FilterExpression="sk = :current",
                ExpressionAttributeValues={":current": "CURRENT"},
            )
            all_policies = {
                (item.get("policy_type"), item.get("identifier")): item
                for item in pol_resp.get("Items", [])
            }
            default_policy = all_policies.get(("default", "default"))

            for user in users:
                user["is_blocked"] = False
                # Resolve effective policy: user-specific > default
                email_lower = user["email"].lower()
                policy = all_policies.get(("user", email_lower)) or all_policies.get(("user", user["email"])) or default_policy
                if not policy or not policy.get("enabled", True):
                    continue
                if policy.get("enforcement_mode", "alert") != "block":
                    continue
                # Already unblocked — not blocked
                if user.get("unblock"):
                    continue
                # Check limits
                monthly_limit = int(policy.get("monthly_token_limit", 0))
                daily_limit = int(policy.get("daily_token_limit", 0)) if policy.get("daily_token_limit") else None
                monthly_cost_limit = float(policy["monthly_cost_limit"]) if policy.get("monthly_cost_limit") else None
                daily_cost_limit = float(policy["daily_cost_limit"]) if policy.get("daily_cost_limit") else None
                if monthly_limit > 0 and user["total_tokens"] >= monthly_limit:
                    user["is_blocked"] = True
                    user["blocked_reason"] = "monthly_tokens"
                elif monthly_cost_limit and monthly_cost_limit > 0 and user["estimated_cost"] >= monthly_cost_limit:
                    user["is_blocked"] = True
                    user["blocked_reason"] = "monthly_cost"
                elif daily_limit and daily_limit > 0 and user["daily_tokens"] >= daily_limit:
                    user["is_blocked"] = True
                    user["blocked_reason"] = "daily_tokens"
                elif daily_cost_limit and daily_cost_limit > 0 and user["daily_cost"] >= daily_cost_limit:
                    user["is_blocked"] = True
                    user["blocked_reason"] = "daily_cost"
        except Exception as e:
            print(f"Error computing blocked status: {e}")
            for user in users:
                user.setdefault("is_blocked", False)

        # Sort by last_seen descending (most recent first), with None values at the end
        users.sort(key=lambda u: u.get("last_seen") or "", reverse=True)

        # Also get org aggregate
        org_usage = None
        try:
            org_resp = metrics_table.get_item(Key={"pk": "ORG#global", "sk": f"MONTH#{month_prefix}#BEDROCK"})
            org_item = org_resp.get("Item")
            if org_item:
                org_usage = {
                    "total_tokens": int(float(org_item.get("total_tokens", 0))),
                    "estimated_cost": round(float(org_item.get("estimated_cost", 0)), 2),
                    "user_count": len(users_by_email),
                }
        except Exception:
            pass

        return build_json_response(200, {"users": users, "month": month_prefix, "org_usage": org_usage})
    except Exception as e:
        print(f"Error listing users: {e}")
        return build_json_response(500, {"error": f"Failed to list users: {str(e)}"})


def api_disable_user(event):
    """Disable a user by setting status='disabled' on their PROFILE record."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    email = body.get("email", "").strip()
    if not email:
        return build_json_response(400, {"error": "email is required."})

    pk = f"USER#{email}"
    sk = "PROFILE"

    try:
        response = metrics_table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": "disabled"},
            ReturnValues="ALL_NEW",
        )
        print(f"User disabled: {email}")
        return build_json_response(200, {
            "message": f"User {email} has been disabled.",
            "email": email,
            "status": "disabled",
        })
    except Exception as e:
        print(f"Error disabling user {email}: {e}")
        return build_json_response(500, {"error": f"Failed to disable user: {str(e)}"})


def api_enable_user(event):
    """Enable a user by setting status='active' on their PROFILE record."""
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return build_json_response(400, {"error": "Invalid JSON body"})

    email = body.get("email", "").strip()
    if not email:
        return build_json_response(400, {"error": "email is required."})

    pk = f"USER#{email}"
    sk = "PROFILE"

    try:
        response = metrics_table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": "active"},
            ReturnValues="ALL_NEW",
        )
        print(f"User enabled: {email}")
        return build_json_response(200, {
            "message": f"User {email} has been enabled.",
            "email": email,
            "status": "active",
        })
    except Exception as e:
        print(f"Error enabling user {email}: {e}")
        return build_json_response(500, {"error": f"Failed to enable user: {str(e)}"})


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

# Shared CSS design system — extracted from the portal landing page
_PORTAL_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --brand:          #1A3F82;
  --brand-dark:     #122D61;
  --brand-light:    #2B5BA8;
  --accent:         #0078D4;
  --accent-hover:   #0063B1;
  --ok:             #107C10;
  --ok-bg:          #E8F5E8;
  --warn-bg:        #FFF4CE;
  --warn:           #7A4A00;
  --surface:        #F5F7FA;
  --border:         #DDE1E9;
  --text-primary:   #1A1D23;
  --text-secondary: #5A6270;
  --text-muted:     #8B93A1;
  --white:          #FFFFFF;
  --shadow-sm:      0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
  --shadow-md:      0 4px 12px rgba(0,0,0,.10), 0 2px 6px rgba(0,0,0,.06);
  --radius:         6px;
}

html, body {
  min-height: 100%;
  background: var(--surface);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  font-size: 14px;
  color: var(--text-primary);
  line-height: 1.5;
}

/* ---- Topbar ---- */
.topbar {
  background: var(--brand);
  height: 52px;
  display: flex;
  align-items: center;
  padding: 0 32px;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 2px 8px rgba(0,0,0,.25);
}
.topbar-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; }
.topbar-product { color: #fff; font-size: 15px; font-weight: 600; letter-spacing: .01em; }
.topbar-sep { width: 1px; height: 18px; background: rgba(255,255,255,.25); margin: 0 4px; }
.topbar-sub { color: rgba(255,255,255,.7); font-size: 13px; }
.topbar-spacer { flex: 1; }
.topbar-user { display: flex; align-items: center; gap: 8px; color: rgba(255,255,255,.9); font-size: 13px; }
.topbar-user svg { opacity: .7; }
.topbar-back { color: rgba(255,255,255,.75); font-size: 12px; text-decoration: none; display: flex; align-items: center; gap: 4px; }
.topbar-back:hover { color: #fff; }

/* ---- Page layout ---- */
.page { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

/* ---- Cards ---- */
.pkg-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  box-shadow: var(--shadow-sm);
  transition: border-color .15s, box-shadow .15s;
}
.pkg-card:hover { border-color: var(--accent); box-shadow: var(--shadow-md); }

/* ---- Section heading ---- */
.section-heading {
  font-size: 11px;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-bottom: 12px;
}

/* ---- Tabs ---- */
.tabs {
  display: flex;
  gap: 2px;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--border);
}
.tab {
  padding: 9px 18px;
  border: none;
  background: none;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: color .15s, border-color .15s;
}
.tab:hover { color: var(--accent); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
.panel { display: none; }
.panel.active { display: block; }

/* ---- Toolbar ---- */
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.toolbar-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
}

/* ---- Buttons ---- */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 7px 16px;
  border: none;
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: background .15s, box-shadow .15s, opacity .15s;
  text-decoration: none;
  white-space: nowrap;
}
.btn-primary {
  background: var(--accent);
  color: var(--white);
  box-shadow: 0 1px 3px rgba(0,120,212,.3);
}
.btn-primary:hover { background: var(--accent-hover); box-shadow: 0 2px 8px rgba(0,120,212,.4); }
.btn-danger { background: #C42B1C; color: var(--white); }
.btn-danger:hover { background: #A52015; }
.btn-secondary { background: var(--white); color: var(--text-primary); border: 1px solid var(--border); }
.btn-secondary:hover { background: var(--surface); }
.btn-edit { background: var(--surface); color: var(--text-primary); border: 1px solid var(--border); }
.btn-edit:hover { border-color: var(--accent); color: var(--accent); }
.btn-sm { padding: 4px 10px; font-size: 12px; }

/* ---- Download-style primary button (full-width on cards) ---- */
.download-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 18px;
  background: var(--accent);
  color: var(--white);
  text-decoration: none;
  border-radius: var(--radius);
  font-size: 13px;
  font-weight: 600;
  border: none;
  cursor: pointer;
  transition: background .15s, box-shadow .15s;
  box-shadow: 0 1px 3px rgba(0,120,212,.3);
  align-self: flex-start;
}
.download-btn:hover { background: var(--accent-hover); box-shadow: 0 2px 8px rgba(0,120,212,.4); }

/* ---- Form elements ---- */
.form-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: var(--shadow-sm);
}
.form-card-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 18px;
}
.form-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
  margin-bottom: 14px;
}
.form-group { display: flex; flex-direction: column; }
.form-group label {
  font-size: 11px;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: .04em;
  margin-bottom: 5px;
}
.form-group input, .form-group select {
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 13px;
  color: var(--text-primary);
  background: var(--white);
  transition: border-color .15s, box-shadow .15s;
}
.form-group input:focus, .form-group select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(0,120,212,.12);
}
.form-actions { display: flex; gap: 8px; margin-top: 6px; }

/* ---- Alert/notification ---- */
.alert {
  padding: 11px 14px;
  border-radius: var(--radius);
  margin-bottom: 16px;
  font-size: 13px;
  display: none;
  border: 1px solid transparent;
}
.alert-success { background: var(--ok-bg); color: var(--ok); border-color: #A8D5A8; }
.alert-error { background: #FDE7E9; color: #C42B1C; border-color: #F4ACAC; }

/* ---- Badges ---- */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .03em;
  text-transform: uppercase;
}
.badge-user    { background: #EEF3FC; color: var(--brand-light); }
.badge-group   { background: #F3E8FF; color: #6B21A8; }
.badge-default { background: var(--ok-bg); color: var(--ok); }
.badge-org     { background: var(--warn-bg); color: var(--warn); }
.badge-alert   { background: var(--warn-bg); color: var(--warn); }
.badge-block   { background: #FDE7E9; color: #C42B1C; }
.badge-enabled  { background: var(--ok-bg); color: var(--ok); }
.badge-unblocked { background: var(--warn-bg); color: #B45309; }
.badge-disabled { background: var(--surface); color: var(--text-muted); }
.badge-admin   { background: #F0A500; color: #1A1D23; }
.badge-standard { background: var(--surface); color: var(--text-secondary); }

/* ---- Table ---- */
.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.data-table th {
  text-align: left;
  padding: 9px 12px;
  background: var(--surface);
  color: var(--text-secondary);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .04em;
  border-bottom: 1px solid var(--border);
}
.data-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  color: var(--text-primary);
  vertical-align: middle;
}
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: #F0F4FB; }
.table-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
}

/* ---- Usage stats ---- */
.usage-stat {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 9px 0;
  border-bottom: 1px solid var(--border);
}
.usage-stat:last-child { border: none; }
.usage-label { color: var(--text-secondary); font-size: 13px; }
.usage-value { color: var(--text-primary); font-weight: 600; font-size: 13px; }

/* ---- Org summary cards ---- */
.org-summary-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}
.org-metric-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 18px;
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.org-metric-label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--text-muted);
}
.org-metric-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.2;
}
.org-metric-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

/* ---- Usage table email column ---- */
.usage-email-cell {
  font-weight: 600;
  color: var(--text-primary);
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.usage-date-cell {
  font-size: 12px;
  font-weight: 600;
  color: var(--accent);
  white-space: nowrap;
}
.usage-date-cell .date-sub {
  display: block;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-muted);
  margin-top: 1px;
}

/* ---- Usage detail layout ---- */
.usage-detail-grid {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-top: 4px;
}
.usage-detail-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.usage-detail-section-title {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--text-muted);
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border);
}
.usage-detail-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
}
.usage-detail-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.usage-detail-card.highlight {
  border-color: var(--brand);
  background: color-mix(in srgb, var(--brand) 4%, var(--surface));
}
.usage-detail-card.warn {
  border-color: #856404;
  background: #fffcf0;
}
.usage-detail-label {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--text-muted);
}
.usage-detail-value {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.3;
}
.usage-detail-sub {
  font-size: 11px;
  font-weight: 400;
  color: var(--text-muted);
}

/* ---- Org summary strip (legacy, kept for compat) ---- */
.org-strip {
  display: flex;
  gap: 24px;
  align-items: center;
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 16px;
  margin-bottom: 16px;
  box-shadow: var(--shadow-sm);
  font-size: 13px;
  flex-wrap: wrap;
}
.org-strip-item { display: flex; align-items: center; gap: 6px; }
.org-strip-label { color: var(--text-secondary); }
.org-strip-value { font-weight: 700; color: var(--text-primary); }

/* ---- Usage filter input ---- */
.usage-filter-input {
  padding: 7px 10px 7px 30px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 13px;
  color: var(--text-primary);
  background: var(--white);
  width: 280px;
  transition: border-color .15s, box-shadow .15s;
}
.usage-filter-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(0,120,212,.12);
}

/* ---- Pagination ---- */
.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  padding: 12px 16px;
  border-top: 1px solid var(--border);
}
.pagination button {
  min-width: 32px;
  height: 30px;
  padding: 0 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
  transition: all .15s;
}
.pagination button:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent);
}
.pagination button:disabled {
  opacity: .4;
  cursor: default;
}
.pagination button.active {
  background: var(--accent);
  color: #fff;
  border-color: var(--accent);
  font-weight: 600;
}
.pagination .page-info {
  color: var(--text-muted);
  font-size: 12px;
  margin: 0 8px;
}

/* ---- Usage loading state ---- */
.usage-loading-state {
  display: flex;
  align-items: center;
  padding: 20px 0;
  color: var(--text-muted);
  font-size: 13px;
  font-style: italic;
}

/* ---- Info note ---- */
.info-note {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  background: var(--warn-bg);
  border: 1px solid #F0C060;
  border-radius: var(--radius);
  font-size: 13px;
  color: var(--warn);
  margin-bottom: 16px;
}

/* ---- Misc ---- */
.loading { color: var(--text-muted); font-size: 13px; font-style: italic; padding: 16px 0; }
.empty-state {
  text-align: center;
  padding: 48px 32px;
  color: var(--text-muted);
  font-size: 13px;
}
.empty-state strong { display: block; font-size: 14px; color: var(--text-secondary); margin-bottom: 6px; }

/* ---- Footer ---- */
.page-footer {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}
.page-footer-left { color: var(--text-muted); font-size: 12px; }
.page-footer-right a { color: var(--accent); text-decoration: none; font-size: 12px; font-weight: 500; }
.page-footer-right a:hover { text-decoration: underline; }
"""

# SVG icons (reused from portal)
_TOPBAR_LOGO_SVG = """<svg width="24" height="24" viewBox="0 0 24 24" fill="none">
  <rect width="24" height="24" rx="4" fill="rgba(255,255,255,0.15)"/>
  <path d="M7 8h10M7 12h7M7 16h5" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
</svg>"""

_USER_SVG = """<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
  <circle cx="12" cy="7" r="4"/>
</svg>"""


def _topbar(admin_email, subtitle="Admin Panel"):
    """Render the shared topbar HTML."""
    return f"""<nav class="topbar">
  <a class="topbar-logo" href="/">{_TOPBAR_LOGO_SVG}
    <span class="topbar-product">Claude Code Portal</span>
  </a>
  <div class="topbar-sep"></div>
  <span class="topbar-sub">{subtitle}</span>
  <div class="topbar-spacer"></div>
  <div class="topbar-user">
    {_USER_SVG}
    <span>{html.escape(admin_email or 'unknown')}</span>
    <a class="role-chip admin" href="/admin" style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;background:#F0A500;color:#1A1D23;text-decoration:none;">Admin</a>
    <a href="/logout" onclick="return confirm('Sign out of this portal?')" style="margin-left:8px;color:rgba(255,255,255,.6);font-size:12px;text-decoration:none;border:1px solid rgba(255,255,255,.25);padding:2px 8px;border-radius:3px" onmouseover="this.style.color='rgba(255,255,255,.9)'" onmouseout="this.style.color='rgba(255,255,255,.6)'">Sign Out</a>
  </div>
</nav>"""


def generate_forbidden_page(user_email):
    """Generate 403 Forbidden page using portal design system."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied — Claude Code Portal</title>
  <style>{_PORTAL_CSS}</style>
</head>
<body>
  <nav class="topbar">
    <a class="topbar-logo" href="/">{_TOPBAR_LOGO_SVG}
      <span class="topbar-product">Claude Code Portal</span>
    </a>
    <div class="topbar-sep"></div>
    <span class="topbar-sub">Admin Panel</span>
    <div class="topbar-spacer"></div>
    <div class="topbar-user">
      {_USER_SVG}
      <span>{user_email or 'unknown'}</span>
      <a href="/logout" onclick="return confirm('Sign out of this portal?')" style="margin-left:8px;color:rgba(255,255,255,.6);font-size:12px;text-decoration:none;border:1px solid rgba(255,255,255,.25);padding:2px 8px;border-radius:3px" onmouseover="this.style.color='rgba(255,255,255,.9)'" onmouseout="this.style.color='rgba(255,255,255,.6)'">Sign Out</a>
    </div>
  </nav>

  <main class="page" style="max-width:560px">
    <div class="pkg-card" style="margin-top:48px;text-align:center;padding:40px 32px">
      <div style="margin-bottom:16px">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.5" style="display:inline-block">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <h1 style="font-size:18px;font-weight:700;color:var(--text-primary);margin-bottom:10px">Access Denied</h1>
      <p style="color:var(--text-secondary);font-size:13px;margin-bottom:6px">
        You do not have admin access to the quota management panel.
      </p>
      <p style="color:var(--text-secondary);font-size:13px;margin-bottom:20px">
        Signed in as <strong style="color:var(--text-primary)">{html.escape(user_email or 'unknown')}</strong>
      </p>
      <p style="color:var(--text-muted);font-size:12px;margin-bottom:24px">
        Contact your IT administrator to request access.
      </p>
      <a href="/" class="btn btn-primary" style="display:inline-flex">Back to Portal</a>
    </div>
  </main>
</body>
</html>"""


def generate_admin_page(admin_email):
    """Generate the admin quota management SPA using the portal design system."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel — Claude Code Portal</title>
  <style>
{_PORTAL_CSS}
  </style>
</head>
<body>
  {_topbar(admin_email)}

  <main class="page">

    <div id="alert" class="alert"></div>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('usage')">Users</button>
      <button class="tab" onclick="switchTab('policies')">Quota Policies</button>
      <button class="tab" onclick="switchTab('unblock')">Unblock User</button>
      <button class="tab" onclick="switchTab('admins')">Admins</button>
      <button class="tab" onclick="switchTab('pricing')">Pricing</button>
    </div>

    <!-- ======== Users / Usage Panel ======== -->
    <div id="panel-usage" class="panel active">

      <p style="color:var(--text-muted);font-size:12px;margin:0 0 16px 0">Shows all registered users with their activation status and activity information.</p>

      <!-- Org summary metric cards -->
      <div id="org-summary" class="org-summary-grid" style="display:none">
        <div class="org-metric-card">
          <div class="org-metric-label">Total Tokens This Month</div>
          <div class="org-metric-value" id="org-total-tokens">—</div>
          <div class="org-metric-sub">org-wide consumption</div>
        </div>
        <div class="org-metric-card">
          <div class="org-metric-label">Estimated Cost This Month</div>
          <div class="org-metric-value" id="org-total-cost">—</div>
          <div class="org-metric-sub">based on token pricing</div>
        </div>
        <div class="org-metric-card">
          <div class="org-metric-label">Active Users</div>
          <div class="org-metric-value" id="org-user-count">—</div>
          <div class="org-metric-sub">with usage this month</div>
        </div>
      </div>

      <!-- Toolbar with styled filter input and status filter -->
      <div class="toolbar">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="position:relative;display:flex;align-items:center">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="position:absolute;left:9px;pointer-events:none"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="usage-filter" placeholder="Filter by email…" oninput="filterUsageList()" class="usage-filter-input">
          </div>
          <select id="usage-status-filter" onchange="loadUsageList()" style="padding:7px 10px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px;color:var(--text-primary);background:var(--white)">
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <span id="usage-count" style="color:var(--text-muted);font-size:12px;white-space:nowrap"></span>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="loadUsageList()">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.6"/></svg>
          Refresh
        </button>
      </div>

      <!-- Loading state -->
      <div id="usage-loading" class="usage-loading-state" style="display:none">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" style="display:inline-block;vertical-align:middle;margin-right:8px;opacity:.7"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <span>Loading users…</span>
      </div>

      <!-- Users table -->
      <div id="usage-list-wrap" class="table-card" style="display:none">
        <table class="data-table">
          <thead><tr>
            <th style="min-width:220px">Email</th>
            <th style="min-width:80px">Status</th>
            <th style="min-width:110px">First Activated</th>
            <th>Last Seen</th>
            <th style="min-width:120px">Actions</th>
          </tr></thead>
          <tbody id="usage-list-body"></tbody>
        </table>
        <div id="usage-pagination" class="pagination"></div>
      </div>

      <!-- Empty state -->
      <div id="usage-empty" class="empty-state" style="display:none">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--border)" stroke-width="1.5" style="display:inline-block;margin-bottom:14px"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        <strong>No users found</strong>
        Users appear here once they activate their account.
      </div>

      <!-- Detail card — shown on row click -->
      <div id="usage-result" style="display:none;margin-top:20px">
        <div class="form-card" style="margin-bottom:0">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:18px">
            <div>
              <div class="section-heading" style="margin-bottom:4px">Usage Detail</div>
              <div id="usage-title" style="font-size:15px;font-weight:700;color:var(--text-primary)">—</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('usage-result').style.display='none'">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              Close
            </button>
          </div>
          <div id="usage-stats" class="usage-detail-grid"></div>
        </div>
      </div>

    </div>

    <!-- ======== Policies Panel ======== -->
    <div id="panel-policies" class="panel">
      <div class="toolbar">
        <span class="toolbar-title">Quota Policies</span>
        <button class="btn btn-primary" onclick="showCreateForm()">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Create Policy
        </button>
      </div>

      <div id="create-form" class="form-card" style="display:none">
        <div class="form-card-title" id="form-title">Create Policy</div>
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
            <label>Daily Token Limit <span style="font-weight:400;text-transform:none;letter-spacing:0">(optional)</span></label>
            <input type="text" id="pol-daily" placeholder="e.g. 15M (leave empty to skip)">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Monthly Cost Limit $ <span style="font-weight:400;text-transform:none;letter-spacing:0">(optional)</span></label>
            <input type="text" id="pol-monthly-cost" placeholder="e.g. 100, 200.50">
          </div>
          <div class="form-group">
            <label>Daily Cost Limit $ <span style="font-weight:400;text-transform:none;letter-spacing:0">(optional)</span></label>
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
        <div class="form-actions">
          <button class="btn btn-primary" onclick="submitPolicy()">Save Policy</button>
          <button class="btn btn-secondary" onclick="hideCreateForm()">Cancel</button>
        </div>
      </div>

      <div id="policies-loading" class="loading">Loading policies...</div>
      <div id="policies-table-wrap" class="table-card" style="display:none">
        <table class="data-table" id="policies-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Identifier</th>
              <th>Monthly Tokens</th>
              <th>Daily Tokens</th>
              <th>Monthly Cost</th>
              <th>Daily Cost</th>
              <th>Enforcement</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="policies-body"></tbody>
        </table>
      </div>
      <div id="policies-empty" class="empty-state" style="display:none">
        <strong>No quota policies configured</strong>
        Click "Create Policy" to add the first one.
      </div>
    </div>

    <!-- ======== Unblock Panel ======== -->
    <div id="panel-unblock" class="panel">
      <div class="form-card">
        <div class="form-card-title">Temporarily Unblock User</div>
        <p style="color:var(--text-secondary);margin-bottom:18px;font-size:13px">
          Grant temporary access to a user who has exceeded their quota. Maximum duration is 7 days.
        </p>
        <div class="form-row">
          <div class="form-group">
            <label>User Email</label>
            <input type="text" id="unblock-email" placeholder="user@company.com">
          </div>
          <div class="form-group">
            <label>Duration</label>
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
            <label>Reason <span style="font-weight:400;text-transform:none;letter-spacing:0">(optional)</span></label>
            <input type="text" id="unblock-reason" placeholder="e.g. Urgent project deadline">
          </div>
        </div>
        <div class="form-actions">
          <button class="btn btn-primary" onclick="unblockUser()">Unblock User</button>
        </div>
      </div>
    </div>

    <!-- ======== Admins Panel ======== -->
    <div id="panel-admins" class="panel">
      <div class="toolbar">
        <span class="toolbar-title">Admin Users</span>
        <button class="btn btn-secondary" onclick="loadAdmins()">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.6"/></svg>
          Refresh
        </button>
      </div>
      <div id="admins-group-note" class="info-note" style="display:none">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>IdP group <strong id="admins-group-name"></strong> also grants admin access (managed in your identity provider, not here).</span>
      </div>
      <div class="form-card" style="margin-bottom:20px">
        <div class="form-card-title">Add Admin</div>
        <div class="form-row">
          <div class="form-group">
            <label>Email Address</label>
            <input type="text" id="new-admin-email" placeholder="user@company.com">
          </div>
          <div class="form-group" style="justify-content:flex-end">
            <label style="opacity:0">Add</label>
            <button class="btn btn-primary" onclick="addAdmin()">Add Admin</button>
          </div>
        </div>
      </div>
      <div id="admins-loading" class="loading" style="display:none">Loading admins...</div>
      <div id="admins-table-wrap" class="table-card" style="display:none">
        <table class="data-table" id="admins-table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Added By</th>
              <th>Added At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="admins-body"></tbody>
        </table>
      </div>
      <div id="admins-empty" class="empty-state" style="display:none">
        <strong>No admins configured</strong>
        Use the form above to add the first admin.
      </div>
    </div>

    <!-- ======== Pricing Panel ======== -->
    <div id="panel-pricing" class="panel">
      <div class="toolbar">
        <span class="toolbar-title">Model Pricing</span>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary btn-sm" onclick="loadPricing()">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.6"/></svg>
            Refresh
          </button>
          <button class="btn btn-primary" onclick="showPricingForm()">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add Model
          </button>
        </div>
      </div>

      <div id="pricing-form" class="form-card" style="display:none">
        <div class="form-card-title" id="pricing-form-title">Add Model Pricing</div>
        <div class="form-row">
          <div class="form-group">
            <label>Model ID</label>
            <input type="text" id="price-model-id" placeholder="anthropic.claude-sonnet-4-6-v1:0">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Input / 1M Tokens ($)</label>
            <input type="text" id="price-input" placeholder="3">
          </div>
          <div class="form-group">
            <label>Output / 1M Tokens ($)</label>
            <input type="text" id="price-output" placeholder="15">
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Cache Read / 1M Tokens ($)</label>
            <input type="text" id="price-cache-read" placeholder="0.3">
          </div>
          <div class="form-group">
            <label>Cache Write 5m / 1M Tokens ($)</label>
            <input type="text" id="price-cache-write" placeholder="3.75">
          </div>
          <div class="form-group">
            <label>Cache Write 1h / 1M Tokens ($)</label>
            <input type="text" id="price-cache-write-1h" placeholder="6.00">
          </div>
        </div>
        <div class="form-actions">
          <button class="btn btn-primary" onclick="submitPricing()">Save</button>
          <button class="btn btn-secondary" onclick="hidePricingForm()">Cancel</button>
        </div>
      </div>

      <div id="pricing-loading" class="loading" style="display:none">Loading pricing...</div>
      <div id="pricing-table-wrap" class="table-card" style="display:none">
        <table class="data-table" id="pricing-table">
          <thead>
            <tr>
              <th>Model ID</th>
              <th>Input / 1M</th>
              <th>Output / 1M</th>
              <th>Cache Read / 1M</th>
              <th>CW 5m / 1M</th>
              <th>CW 1h / 1M</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="pricing-body"></tbody>
        </table>
      </div>
      <div id="pricing-empty" class="empty-state" style="display:none">
        <strong>No pricing entries configured</strong>
        Click "Add Model" to add the first one.
      </div>
    </div>

    <footer class="page-footer">
      <span class="page-footer-left">Claude Code Portal &middot; Admin Panel</span>
      <div class="page-footer-right"><a href="/">Back to Portal</a></div>
    </footer>

  </main>

  <script>
  const _adminEmail = {json.dumps(admin_email or "")};
  const _canViewUsage = _adminEmail.endsWith('@amazon.com');

  // ---- HTML escaping helper (prevent XSS via innerHTML) ----
  function esc(s) {{ if (s == null) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }}
  function escAttr(s) {{ return esc(s).replace(/'/g, '&#39;').replace(/"/g, '&quot;'); }}

  // ---- Tab switching ----
  function switchTab(name) {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelector(`[onclick="switchTab('${{name}}')"]`).classList.add('active');
    document.getElementById('panel-' + name).classList.add('active');
    if (name === 'usage') loadUsageList();
    if (name === 'policies') loadPolicies();
    if (name === 'admins') loadAdmins();
    if (name === 'pricing') loadPricing();
  }}

  // ---- Alert ----
  function showAlert(msg, type) {{
    const el = document.getElementById('alert');
    el.textContent = msg;
    el.className = 'alert alert-' + type;
    el.style.display = 'block';
    window.scrollTo({{ top: 0, behavior: 'smooth' }});
    setTimeout(() => {{ el.style.display = 'none'; }}, 6000);
  }}

  // ---- Token formatter ----
  function fmtTokens(n) {{
    if (!n) return '—';
    n = parseInt(n);
    if (n >= 1e9) return (n / 1e9).toFixed(n % 1e9 === 0 ? 0 : 1) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(n % 1e6 === 0 ? 0 : 1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(n % 1e3 === 0 ? 0 : 1) + 'K';
    return n.toString();
  }}

  // ---- Badge helpers ----
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

  // ======== Policies ========
  let policiesData = [];

  async function loadPolicies() {{
    document.getElementById('policies-loading').style.display = 'block';
    document.getElementById('policies-table-wrap').style.display = 'none';
    document.getElementById('policies-empty').style.display = 'none';
    try {{
      const resp = await fetch('/api/policies');
      const data = await resp.json();
      policiesData = data.policies || [];
      renderPolicies();
    }} catch (e) {{
      showAlert('Failed to load policies: ' + e.message, 'error');
    }}
    document.getElementById('policies-loading').style.display = 'none';
  }}

  function renderPolicies() {{
    const tbody = document.getElementById('policies-body');
    if (policiesData.length === 0) {{
      document.getElementById('policies-table-wrap').style.display = 'none';
      document.getElementById('policies-empty').style.display = 'block';
      return;
    }}
    document.getElementById('policies-table-wrap').style.display = 'block';
    document.getElementById('policies-empty').style.display = 'none';
    tbody.innerHTML = policiesData.map(p => `
      <tr>
        <td>${{typeBadge(p.policy_type)}}</td>
        <td style="font-weight:500">${{esc(p.identifier)}}</td>
        <td>${{fmtTokens(p.monthly_token_limit)}}</td>
        <td>${{p.daily_token_limit ? fmtTokens(p.daily_token_limit) : '<span style="color:var(--text-muted)">—</span>'}}</td>
        <td>${{p.monthly_cost_limit ? '$' + parseFloat(p.monthly_cost_limit).toFixed(2) : '<span style="color:var(--text-muted)">—</span>'}}</td>
        <td>${{p.daily_cost_limit ? '$' + parseFloat(p.daily_cost_limit).toFixed(2) : '<span style="color:var(--text-muted)">—</span>'}}</td>
        <td>${{modeBadge(p.enforcement_mode)}}</td>
        <td>${{statusBadge(p.enabled)}}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-edit btn-sm" onclick="editPolicy('${{escAttr(p.policy_type)}}','${{escAttr(p.identifier)}}')">Edit</button>
          <button class="btn btn-danger btn-sm" onclick="deletePolicy('${{escAttr(p.policy_type)}}','${{escAttr(p.identifier)}}')" style="margin-left:4px">Delete</button>
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
    document.getElementById('policies-empty').style.display = 'none';
    document.getElementById('create-form').style.display = 'block';
    document.getElementById('create-form').scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
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
      if (idField.value === 'default' || idField.value === 'global') idField.value = '';
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
    document.getElementById('create-form').scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
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
        method,
        headers: {{ 'Content-Type': 'application/json' }},
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
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  async function deletePolicy(type, identifier) {{
    if (!confirm(`Delete ${{type}} policy for "${{identifier}}"?`)) return;
    try {{
      const resp = await fetch('/api/policies', {{
        method: 'DELETE',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ policy_type: type, identifier }}),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message || 'Policy deleted', 'success');
        loadPolicies();
      }} else {{
        showAlert(data.error || 'Failed to delete policy', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  // ======== Users ========
  async function loadUsers() {{
    document.getElementById('users-loading').style.display = 'block';
    document.getElementById('users-table-wrap').style.display = 'none';
    document.getElementById('users-empty').style.display = 'none';
    document.getElementById('org-summary').style.display = 'none';
    try {{
      const resp = await fetch('/api/users');
      const data = await resp.json();
      const users = data.users || [];

      if (data.org_usage) {{
        document.getElementById('org-total-tokens').textContent = fmtTokens(data.org_usage.total_tokens);
        document.getElementById('org-total-cost').textContent = '$' + parseFloat(data.org_usage.estimated_cost).toFixed(2);
        document.getElementById('org-user-count').textContent = data.org_usage.user_count;
        document.getElementById('org-summary').style.display = 'flex';
      }}

      if (users.length === 0) {{
        document.getElementById('users-empty').style.display = 'block';
      }} else {{
        document.getElementById('users-table-wrap').style.display = 'block';
        const tbody = document.getElementById('users-body');
        tbody.innerHTML = users.map(u => `
          <tr>
            <td style="font-weight:500">${{esc(u.email)}}</td>
            <td>${{u.is_admin
              ? '<span class="badge badge-admin">Admin</span>'
              : '<span class="badge badge-standard">User</span>'}}</td>
            <td>${{u.first_seen ? new Date(u.first_seen).toLocaleDateString() : '<span style="color:var(--text-muted)">—</span>'}}</td>
            <td>${{fmtTokens(u.total_tokens)}}</td>
            <td>${{fmtTokens(u.daily_tokens)}}</td>
            <td>${{u.estimated_cost ? '$' + parseFloat(u.estimated_cost).toFixed(2) : '$0.00'}}</td>
            <td>${{u.daily_cost ? '$' + parseFloat(u.daily_cost).toFixed(2) : '$0.00'}}</td>
            <td style="color:var(--text-secondary)">${{u.last_updated ? new Date(u.last_updated).toLocaleString() : '<span style="color:var(--text-muted)">—</span>'}}</td>
          </tr>
        `).join('');
      }}
    }} catch (e) {{
      showAlert('Failed to load users: ' + e.message, 'error');
    }}
    document.getElementById('users-loading').style.display = 'none';
  }}

  // ======== Usage List ========
  let _usageAllRows = [];
  let _usageFiltered = [];
  let _usagePage = 1;
  const _usagePageSize = 20;

  async function loadUsageList() {{
    document.getElementById('usage-loading').style.display = 'block';
    document.getElementById('usage-list-wrap').style.display = 'none';
    document.getElementById('usage-result').style.display = 'none';
    try {{
      const statusFilter = document.getElementById('usage-status-filter').value;
      const resp = await fetch('/api/users?status=' + encodeURIComponent(statusFilter));
      const data = await resp.json();
      _usageAllRows = (data.users || []);
      if (data.org_usage) {{
        document.getElementById('org-total-tokens').textContent = fmtTokens(data.org_usage.total_tokens);
        document.getElementById('org-total-cost').textContent = '$' + parseFloat(data.org_usage.estimated_cost).toFixed(2);
        document.getElementById('org-user-count').textContent = data.org_usage.user_count;
        document.getElementById('org-summary').style.display = 'grid';
      }}
      _usagePage = 1;
      _usageFiltered = _usageAllRows;
      renderUsageList(_usageFiltered);
    }} catch (e) {{
      showAlert('Failed to load usage list: ' + e.message, 'error');
    }}
    document.getElementById('usage-loading').style.display = 'none';
  }}

  function renderUsageList(rows) {{
    document.getElementById('usage-count').textContent = rows.length + ' user' + (rows.length !== 1 ? 's' : '');
    if (rows.length === 0) {{
      document.getElementById('usage-list-wrap').style.display = 'none';
      document.getElementById('usage-pagination').innerHTML = '';
      return;
    }}
    document.getElementById('usage-list-wrap').style.display = 'block';
    const totalPages = Math.ceil(rows.length / _usagePageSize);
    if (_usagePage > totalPages) _usagePage = totalPages;
    const start = (_usagePage - 1) * _usagePageSize;
    const pageRows = rows.slice(start, start + _usagePageSize);

    document.getElementById('usage-list-body').innerHTML = pageRows.map(u => {{
      const isDisabled = u.status === 'disabled';
      let statusBadgeHtml;
      if (isDisabled) {{
        statusBadgeHtml = '<span class="badge badge-disabled">Disabled</span>';
      }} else if (u.is_blocked && !u.unblock) {{
        const reasonMap = {{monthly_tokens:'Monthly tokens',monthly_cost:'Monthly cost',daily_tokens:'Daily tokens',daily_cost:'Daily cost'}};
        const reason = reasonMap[u.blocked_reason] || 'Quota';
        statusBadgeHtml = `<span class="badge badge-block" title="${{reason}} limit reached">Blocked</span>`
          + `<span style="display:block;font-size:10px;color:#C42B1C;margin-top:2px">${{reason}}</span>`;
      }} else if (u.unblock) {{
        const exp = escAttr(new Date(u.unblock.expires_at).toLocaleString());
        const by = escAttr(u.unblock.unblocked_by || 'unknown');
        statusBadgeHtml = `<span class="badge badge-unblocked" title="By: ${{by}}&#10;Expires: ${{exp}}">Unblocked</span>`
          + `<span style="display:block;font-size:10px;color:#B45309;margin-top:2px">until ${{new Date(u.unblock.expires_at).toLocaleDateString(undefined,{{month:'short',day:'numeric'}})}}</span>`;
      }} else {{
        statusBadgeHtml = '<span class="badge badge-enabled">Active</span>';
      }}
      const emailSafe = escAttr(u.email);
      const actionBtn = isDisabled
        ? `<button class="btn btn-sm" style="background:var(--ok);color:#fff" onclick="event.stopPropagation();toggleUserStatus('${{emailSafe}}','enable')">Enable</button>`
        : `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation();toggleUserStatus('${{emailSafe}}','disable')">Disable</button>`;
      const rowStyle = isDisabled ? 'opacity:0.6' : '';
      const clickAttr = _canViewUsage ? `onclick="showUsageDetail('${{emailSafe}}')"` : '';
      const cursorStyle = _canViewUsage ? 'cursor:pointer' : 'cursor:default';
      return `<tr style="${{cursorStyle}};${{rowStyle}}" ${{clickAttr}}>
        <td class="usage-email-cell">${{esc(u.email)}}</td>
        <td>${{statusBadgeHtml}}</td>
        <td class="usage-date-cell">${{u.first_activated
          ? new Date(u.first_activated).toLocaleDateString(undefined, {{year:'numeric',month:'short',day:'numeric'}})
          : '<span style="color:var(--text-muted)">—</span>'}}</td>
        <td style="color:var(--text-secondary);font-size:12px">${{u.last_seen
          ? new Date(u.last_seen).toLocaleString()
          : '<span style="color:var(--text-muted)">—</span>'}}</td>
        <td style="white-space:nowrap">${{actionBtn}}</td>
      </tr>`;
    }}).join('');

    renderUsagePagination(rows.length, totalPages);
  }}

  function renderUsagePagination(total, totalPages) {{
    const el = document.getElementById('usage-pagination');
    if (totalPages <= 1) {{ el.innerHTML = ''; return; }}

    let html = `<button onclick="usageGoPage(1)" ${{_usagePage===1?'disabled':''}}>&#171;</button>`;
    html += `<button onclick="usageGoPage(${{_usagePage-1}})" ${{_usagePage===1?'disabled':''}}>&#8249;</button>`;

    // Show page numbers with ellipsis
    const pages = [];
    for (let i = 1; i <= totalPages; i++) {{
      if (i === 1 || i === totalPages || (i >= _usagePage - 1 && i <= _usagePage + 1)) {{
        pages.push(i);
      }} else if (pages[pages.length - 1] !== '...') {{
        pages.push('...');
      }}
    }}
    pages.forEach(p => {{
      if (p === '...') {{
        html += `<span class="page-info">…</span>`;
      }} else {{
        html += `<button class="${{p===_usagePage?'active':''}}" onclick="usageGoPage(${{p}})">${{p}}</button>`;
      }}
    }});

    html += `<button onclick="usageGoPage(${{_usagePage+1}})" ${{_usagePage===totalPages?'disabled':''}}>&#8250;</button>`;
    html += `<button onclick="usageGoPage(${{totalPages}})" ${{_usagePage===totalPages?'disabled':''}}>&#187;</button>`;
    html += `<span class="page-info">${{(_usagePage-1)*_usagePageSize+1}}–${{Math.min(_usagePage*_usagePageSize, total)}} of ${{total}}</span>`;
    el.innerHTML = html;
  }}

  function usageGoPage(p) {{
    _usagePage = p;
    renderUsageList(_usageFiltered);
    document.getElementById('usage-list-wrap').scrollIntoView({{behavior:'smooth',block:'nearest'}});
  }}

  function filterUsageList() {{
    const q = document.getElementById('usage-filter').value.trim().toLowerCase();
    _usagePage = 1;
    _usageFiltered = q ? _usageAllRows.filter(u => u.email.toLowerCase().includes(q)) : _usageAllRows;
    renderUsageList(_usageFiltered);
  }}

  async function showUsageDetail(email) {{
    try {{
      const resp = await fetch('/api/usage?email=' + encodeURIComponent(email));
      const data = await resp.json();
      if (resp.ok) {{
        document.getElementById('usage-title').textContent = data.email;
        const fmtDate = d => d ? new Date(d).toLocaleString(undefined, {{dateStyle:'medium',timeStyle:'short'}}) : 'Unknown';
        const costFmt = v => v ? '$' + parseFloat(v).toFixed(2) : '$0.00';
        const tokenCard = (label, val) => `
          <div class="usage-detail-card">
            <div class="usage-detail-label">${{label}}</div>
            <div class="usage-detail-value">${{fmtTokens(val)}}</div>
            <div class="usage-detail-sub">${{parseInt(val).toLocaleString()}}</div>
          </div>`;

        document.getElementById('usage-stats').innerHTML = `
          <!-- Overview -->
          <div class="usage-detail-section">
            <div class="usage-detail-section-title">Overview</div>
            <div class="usage-detail-row">
              <div class="usage-detail-card">
                <div class="usage-detail-label">Period</div>
                <div class="usage-detail-value">${{data.month}}</div>
                <div class="usage-detail-sub">First seen: ${{fmtDate(data.first_seen)}}</div>
              </div>
              <div class="usage-detail-card highlight">
                <div class="usage-detail-label">Monthly Cost</div>
                <div class="usage-detail-value" style="color:var(--brand)">${{costFmt(data.estimated_cost)}}</div>
              </div>
              <div class="usage-detail-card">
                <div class="usage-detail-label">Daily Cost</div>
                <div class="usage-detail-value">${{costFmt(data.daily_cost)}}</div>
                <div class="usage-detail-sub">Resets midnight UTC+8</div>
              </div>
            </div>
          </div>

          <!-- Monthly Tokens -->
          <div class="usage-detail-section">
            <div class="usage-detail-section-title">Monthly Tokens</div>
            <div class="usage-detail-row">
              ${{tokenCard('Total', data.total_tokens)}}
              ${{tokenCard('Input', data.input_tokens)}}
              ${{tokenCard('Output', data.output_tokens)}}
              ${{tokenCard('Cache Read', data.cache_read_tokens)}}
              ${{tokenCard('Cache Write', data.cache_write_tokens)}}
            </div>
          </div>

          <!-- Daily -->
          <div class="usage-detail-section">
            <div class="usage-detail-section-title">Today (UTC+8)</div>
            <div class="usage-detail-row">
              ${{tokenCard('Daily Tokens', data.daily_tokens)}}
              <div class="usage-detail-card">
                <div class="usage-detail-label">Daily Cost</div>
                <div class="usage-detail-value">${{costFmt(data.daily_cost)}}</div>
              </div>
            </div>
          </div>

          ${{data.unblock ? `
          <!-- Unblock -->
          <div class="usage-detail-section">
            <div class="usage-detail-section-title">Unblock Status</div>
            <div class="usage-detail-row">
              <div class="usage-detail-card warn">
                <div class="usage-detail-label">Status</div>
                <div class="usage-detail-value" style="font-size:14px;color:#856404">Temporarily Unblocked</div>
                <div class="usage-detail-sub">By: ${{esc(data.unblock.unblocked_by || 'unknown')}}</div>
                <div class="usage-detail-sub">Expires: ${{esc(new Date(data.unblock.expires_at).toLocaleString())}}</div>
                ${{data.unblock.reason ? `<div class="usage-detail-sub">Reason: ${{esc(data.unblock.reason)}}</div>` : ''}}
              </div>
            </div>
          </div>
          ` : ''}}
        `;
        document.getElementById('usage-result').style.display = 'block';
        document.getElementById('usage-result').scrollIntoView({{behavior: 'smooth', block: 'nearest'}});
      }} else {{
        showAlert(data.error || 'Failed to look up usage', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  // ======== Unblock ========
  async function unblockUser() {{
    const email = document.getElementById('unblock-email').value.trim();
    const days = parseInt(document.getElementById('unblock-days').value);
    const reason = document.getElementById('unblock-reason').value.trim();
    if (!email) {{ showAlert('Enter an email address', 'error'); return; }}
    if (!confirm(`Unblock "${{email}}" for ${{days}} day(s)?`)) return;
    try {{
      const resp = await fetch('/api/unblock', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
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
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  function goToUnblock(email) {{
    switchTab('unblock');
    document.getElementById('unblock-email').value = email;
    document.getElementById('unblock-email').focus();
  }}

  async function toggleUserStatus(email, action) {{
    const verb = action === 'disable' ? 'Disable' : 'Enable';
    if (!confirm(`${{verb}} user "${{email}}"?`)) return;
    try {{
      const resp = await fetch('/api/user/' + action, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email }}),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message, 'success');
        loadUsageList();
      }} else {{
        showAlert(data.error || 'Failed to ' + action + ' user', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  // ======== Admins ========
  let adminsData = [];

  async function loadAdmins() {{
    document.getElementById('admins-loading').style.display = 'block';
    document.getElementById('admins-table-wrap').style.display = 'none';
    document.getElementById('admins-empty').style.display = 'none';
    try {{
      const resp = await fetch('/api/admins');
      const data = await resp.json();
      adminsData = data.admins || [];

      if (data.admin_group_name) {{
        document.getElementById('admins-group-name').textContent = data.admin_group_name;
        document.getElementById('admins-group-note').style.display = 'flex';
      }}

      renderAdmins();
    }} catch (e) {{
      showAlert('Failed to load admins: ' + e.message, 'error');
    }}
    document.getElementById('admins-loading').style.display = 'none';
  }}

  function renderAdmins() {{
    const tbody = document.getElementById('admins-body');
    if (adminsData.length === 0) {{
      document.getElementById('admins-table-wrap').style.display = 'none';
      document.getElementById('admins-empty').style.display = 'block';
      return;
    }}
    document.getElementById('admins-table-wrap').style.display = 'block';
    document.getElementById('admins-empty').style.display = 'none';
    tbody.innerHTML = adminsData.map(a => `
      <tr>
        <td style="font-weight:500">${{esc(a.email)}}</td>
        <td style="color:var(--text-secondary)">${{a.added_by === 'system:seed' ? '<em style="color:var(--text-muted)">Initial seed</em>' : esc(a.added_by)}}</td>
        <td style="color:var(--text-secondary)">${{a.added_at ? new Date(a.added_at).toLocaleString() : '—'}}</td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="removeAdmin('${{escAttr(a.email)}}')">Remove</button>
        </td>
      </tr>
    `).join('');
  }}

  async function addAdmin() {{
    const email = document.getElementById('new-admin-email').value.trim();
    if (!email) {{ showAlert('Enter an email address', 'error'); return; }}
    try {{
      const resp = await fetch('/api/admins', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email }}),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message, 'success');
        document.getElementById('new-admin-email').value = '';
        loadAdmins();
      }} else {{
        showAlert(data.error || 'Failed to add admin', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  async function removeAdmin(email) {{
    if (!confirm(`Remove admin access for "${{email}}"?`)) return;
    try {{
      const resp = await fetch('/api/admins', {{
        method: 'DELETE',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ email }}),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message, 'success');
        loadAdmins();
      }} else {{
        showAlert(data.error || 'Failed to remove admin', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  // ======== Pricing ========
  let pricingData = [];

  async function loadPricing() {{
    document.getElementById('pricing-loading').style.display = 'block';
    document.getElementById('pricing-table-wrap').style.display = 'none';
    document.getElementById('pricing-empty').style.display = 'none';
    try {{
      const resp = await fetch('/api/pricing');
      const data = await resp.json();
      pricingData = data.pricing || [];
      renderPricing();
    }} catch (e) {{
      showAlert('Failed to load pricing: ' + e.message, 'error');
    }}
    document.getElementById('pricing-loading').style.display = 'none';
  }}

  function renderPricing() {{
    const tbody = document.getElementById('pricing-body');
    if (pricingData.length === 0) {{
      document.getElementById('pricing-table-wrap').style.display = 'none';
      document.getElementById('pricing-empty').style.display = 'block';
      return;
    }}
    document.getElementById('pricing-table-wrap').style.display = 'block';
    document.getElementById('pricing-empty').style.display = 'none';
    tbody.innerHTML = pricingData.map(p => {{
      const isDefault = p.model_id === 'DEFAULT';
      const modelSafe = escAttr(p.model_id);
      const idCell = isDefault
        ? `<span style="font-weight:700">${{esc(p.model_id)}}</span> <span class="badge badge-default">fallback</span>`
        : `<span style="font-weight:500">${{esc(p.model_id)}}</span>`;
      const delBtn = isDefault
        ? ''
        : `<button class="btn btn-danger btn-sm" onclick="deletePricing('${{modelSafe}}')" style="margin-left:4px">Delete</button>`;
      return `<tr>
        <td>${{idCell}}</td>
        <td>${{fmtPrice(p.input_per_1m)}}</td>
        <td>${{fmtPrice(p.output_per_1m)}}</td>
        <td>${{fmtPrice(p.cache_read_per_1m)}}</td>
        <td>${{fmtPrice(p.cache_write_per_1m)}}</td>
        <td>${{fmtPrice(p.cache_write_1h_per_1m)}}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-edit btn-sm" onclick="editPricing('${{modelSafe}}')">Edit</button>
          ${{delBtn}}
        </td>
      </tr>`;
    }}).join('');
  }}

  function fmtPrice(v) {{
    if (v == null) return '<span style="color:var(--text-muted)">—</span>';
    return '$' + parseFloat(v).toFixed(2);
  }}

  function showPricingForm(modelId) {{
    const p = modelId ? pricingData.find(x => x.model_id === modelId) : null;
    document.getElementById('pricing-form-title').textContent = p ? 'Edit Model Pricing' : 'Add Model Pricing';
    document.getElementById('price-model-id').value = p ? p.model_id : '';
    document.getElementById('price-model-id').disabled = !!p;
    document.getElementById('price-input').value = p ? p.input_per_1m : '';
    document.getElementById('price-output').value = p ? p.output_per_1m : '';
    document.getElementById('price-cache-read').value = p ? p.cache_read_per_1m : '';
    document.getElementById('price-cache-write').value = p ? p.cache_write_per_1m : '';
    document.getElementById('price-cache-write-1h').value = p ? p.cache_write_1h_per_1m : '';
    document.getElementById('pricing-form').style.display = 'block';
    document.getElementById('pricing-form').scrollIntoView({{ behavior: 'smooth', block: 'nearest' }});
  }}

  function hidePricingForm() {{
    document.getElementById('pricing-form').style.display = 'none';
    document.getElementById('price-model-id').disabled = false;
  }}

  function editPricing(modelId) {{
    showPricingForm(modelId);
  }}

  async function submitPricing() {{
    const modelId = document.getElementById('price-model-id').value.trim();
    if (!modelId) {{ showAlert('Model ID is required', 'error'); return; }}
    const body = {{
      model_id: modelId,
      input_per_1m: document.getElementById('price-input').value || '0',
      output_per_1m: document.getElementById('price-output').value || '0',
      cache_read_per_1m: document.getElementById('price-cache-read').value || '0',
      cache_write_per_1m: document.getElementById('price-cache-write').value || '0',
      cache_write_1h_per_1m: document.getElementById('price-cache-write-1h').value || '0',
    }};
    try {{
      const resp = await fetch('/api/pricing', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message || 'Pricing saved', 'success');
        hidePricingForm();
        loadPricing();
      }} else {{
        showAlert(data.error || 'Failed to save pricing', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  async function deletePricing(modelId) {{
    if (!confirm(`Delete pricing for "${{modelId}}"?`)) return;
    try {{
      const resp = await fetch('/api/pricing?model_id=' + encodeURIComponent(modelId), {{
        method: 'DELETE',
      }});
      const data = await resp.json();
      if (resp.ok) {{
        showAlert(data.message || 'Pricing deleted', 'success');
        loadPricing();
      }} else {{
        showAlert(data.error || 'Failed to delete pricing', 'error');
      }}
    }} catch (e) {{
      showAlert('Request failed: ' + e.message, 'error');
    }}
  }}

  // Load usage on page load (default tab)
  loadUsageList();
  </script>
</body>
</html>"""

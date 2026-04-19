# ABOUTME: Lambda function that monitors user token quotas and sends SNS alerts
# ABOUTME: Supports fine-grained quota policies (user, group, default) with token tracking

import json
import boto3
import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal

# Effective timezone for daily/monthly quota boundaries (UTC+8)
EFFECTIVE_TZ = timezone(timedelta(hours=8))
from boto3.dynamodb.conditions import Key, Attr

# Initialize clients
dynamodb = boto3.resource("dynamodb")
sns_client = boto3.client("sns")

# Configuration from environment
QUOTA_TABLE = os.environ.get("QUOTA_TABLE", "UserQuotaMetrics")
POLICIES_TABLE = os.environ.get("POLICIES_TABLE")  # Optional - for fine-grained quotas
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
ENABLE_FINEGRAINED_QUOTAS = os.environ.get("ENABLE_FINEGRAINED_QUOTAS", "false").lower() == "true"

# Default limits (used when no policy is defined)
MONTHLY_TOKEN_LIMIT = int(os.environ.get("MONTHLY_TOKEN_LIMIT", "300000000"))  # 300M default
WARNING_THRESHOLD_80 = int(os.environ.get("WARNING_THRESHOLD_80", "240000000"))  # 240M
WARNING_THRESHOLD_90 = int(os.environ.get("WARNING_THRESHOLD_90", "270000000"))  # 270M

# DynamoDB tables
quota_table = dynamodb.Table(QUOTA_TABLE)
policies_table = dynamodb.Table(POLICIES_TABLE) if POLICIES_TABLE else None


def lambda_handler(event, context):
    """
    Check user token usage against quotas (fine-grained or default) and send alerts.
    Supports monthly, daily, and cost-based limits.
    """
    print(f"Starting quota monitoring check at {datetime.now(timezone.utc).isoformat()}")
    print(f"Fine-grained quotas: {'enabled' if ENABLE_FINEGRAINED_QUOTAS else 'disabled'}")

    # Get current calendar month boundaries (UTC+8)
    now = datetime.now(EFFECTIVE_TZ)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_name = now.strftime("%B %Y")
    current_date = now.strftime("%Y-%m-%d")
    days_in_month = (
        31
        if now.month in [1, 3, 5, 7, 8, 10, 12]
        else (30 if now.month != 2 else (29 if now.year % 4 == 0 else 28))
    )
    days_remaining = days_in_month - now.day

    print(f"Checking usage for {month_name} (day {now.day}/{days_in_month})")

    try:
        # Get user usage data for this month
        user_usage_data = get_monthly_usage(current_date)

        if not user_usage_data:
            print("No user metrics found for current month")
            return {"statusCode": 200, "body": json.dumps("No usage data found")}

        # Load policies if fine-grained quotas are enabled
        policies_cache = {}
        if ENABLE_FINEGRAINED_QUOTAS and policies_table:
            policies_cache = load_all_policies()
            print(f"Loaded {len(policies_cache)} policies")
        else:
            policies_cache = {}

        # Check alerts that have already been sent this month
        sent_alerts = get_sent_alerts(month_name)

        # Process each user
        alerts_to_send = []
        stats = {"total_users": 0, "over_80": 0, "over_90": 0, "exceeded": 0, "daily_exceeded": 0}

        for email, usage in user_usage_data.items():
            stats["total_users"] += 1

            # Resolve the effective quota policy for this user
            policy = resolve_user_quota(email, usage.get("groups", []), policies_cache)

            if policy is None:
                # No policy = unlimited (skip this user)
                continue

            total_tokens = float(usage.get("total_tokens", 0))
            daily_tokens = float(usage.get("daily_tokens", 0))
            estimated_cost = float(usage.get("estimated_cost", 0))
            daily_cost_val = float(usage.get("daily_cost", 0))

            # Check all limit types and generate alerts
            alerts = check_limits_and_generate_alerts(
                email=email,
                total_tokens=total_tokens,
                daily_tokens=daily_tokens,
                policy=policy,
                month_name=month_name,
                current_date=current_date,
                days_remaining=days_remaining,
                days_in_month=days_in_month,
                sent_alerts=sent_alerts,
                estimated_cost=estimated_cost,
                daily_cost=daily_cost_val,
            )

            # Update statistics
            monthly_pct = (total_tokens / policy["monthly_token_limit"]) * 100 if policy["monthly_token_limit"] > 0 else 0
            if monthly_pct > 100:
                stats["exceeded"] += 1
            elif monthly_pct > 90:
                stats["over_90"] += 1
            elif monthly_pct > 80:
                stats["over_80"] += 1

            if policy.get("daily_token_limit") and daily_tokens > policy["daily_token_limit"]:
                stats["daily_exceeded"] += 1

            # Add alerts to send list
            for alert in alerts:
                alert_key = f"{email}#{alert['alert_type']}#{alert['alert_level']}"
                if alert_key not in sent_alerts:
                    alerts_to_send.append(alert)
                    # Record alert to prevent duplicates
                    record_sent_alert(month_name, email, alert["alert_type"], alert["alert_level"], alert)

        # Check reconciler heartbeat
        heartbeat_alerts = check_reconciler_heartbeat(
            month_name=month_name,
            current_date=current_date,
            sent_alerts=sent_alerts,
        )
        for alert in heartbeat_alerts:
            alert_key = f"SYSTEM#reconciler#reconciler_heartbeat#{current_date}#stale"
            if alert_key not in sent_alerts:
                alerts_to_send.append(alert)
                record_sent_alert(month_name, "SYSTEM#reconciler", alert["alert_type"], alert["alert_level"], alert)

        # Check org-wide limits
        org_policy = policies_cache.get("org:global") if policies_cache else None
        if org_policy:
            org_usage = get_org_usage()
            org_usage["user_count"] = stats["total_users"]
            org_alerts = check_org_limits_and_generate_alerts(
                org_usage=org_usage,
                policy=org_policy,
                month_name=month_name,
                sent_alerts=sent_alerts,
            )
            for alert in org_alerts:
                alert_key = f"ORG#global#{alert['alert_type']}#{alert['alert_level']}"
                if alert_key not in sent_alerts:
                    alerts_to_send.append(alert)
                    record_sent_alert(month_name, "ORG#global", alert["alert_type"], alert["alert_level"], alert)

        # Send alerts via SNS
        if alerts_to_send:
            send_alerts(alerts_to_send)
            print(f"Sent {len(alerts_to_send)} quota alerts")
        else:
            print("No new alerts to send")

        # Log summary statistics
        print(f"Summary - Total: {stats['total_users']}, Over 80%: {stats['over_80']}, Over 90%: {stats['over_90']}, Exceeded: {stats['exceeded']}")
        if ENABLE_FINEGRAINED_QUOTAS:
            print(f"  Daily exceeded: {stats['daily_exceeded']}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "users_checked": stats["total_users"],
                "alerts_sent": len(alerts_to_send),
                "users_over_80": stats["over_80"],
                "users_over_90": stats["over_90"],
                "users_exceeded": stats["exceeded"],
                "daily_exceeded": stats["daily_exceeded"],
            }),
        }

    except Exception as e:
        print(f"Error during quota monitoring: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"statusCode": 500, "body": json.dumps(f"Error: {str(e)}")}


def get_monthly_usage(current_date):
    """
    Query the UserQuotaMetrics table for all users in the current month.
    Scans for MONTH#BEDROCK, DAY#BEDROCK, and PROFILE records in one pass.
    Returns dict of email -> usage data including token types and cost.

    Args:
        current_date: Current date string in YYYY-MM-DD format.
    """
    # Extract YYYY-MM format from current_date
    month_prefix = current_date[:7]  # "YYYY-MM"

    scan_filter = (
        Attr("sk").eq(f"MONTH#{month_prefix}#BEDROCK")
        | Attr("sk").eq(f"DAY#{current_date}#BEDROCK")
        | Attr("sk").eq("PROFILE")
    ) & Attr("pk").begins_with("USER#")

    try:
        # Scan for all three record types in one pass
        response = quota_table.scan(FilterExpression=scan_filter)
        items = list(response.get("Items", []))

        # Handle pagination
        while "LastEvaluatedKey" in response:
            response = quota_table.scan(
                FilterExpression=scan_filter,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        # Classify items by record type
        monthly_data = {}   # email -> MONTH#BEDROCK data
        daily_data = {}     # email -> DAY#BEDROCK data
        profiles = {}       # email -> PROFILE data

        for item in items:
            pk = item.get("pk", "")
            sk = item.get("sk", "")
            if not pk.startswith("USER#"):
                continue
            email = pk[len("USER#"):]

            if sk.endswith("#BEDROCK") and sk.startswith("MONTH#"):
                monthly_data[email] = item
            elif sk.endswith("#BEDROCK") and sk.startswith("DAY#"):
                daily_data[email] = item
            elif sk == "PROFILE":
                profiles[email] = item

        # Merge into per-user usage dicts
        user_usage = {}
        all_emails = set(monthly_data) | set(daily_data) | set(profiles)
        for email in all_emails:
            month = monthly_data.get(email, {})
            day = daily_data.get(email, {})
            profile = profiles.get(email, {})

            cache_read = float(month.get("cache_read_tokens", 0))
            cache_write = float(month.get("cache_write_tokens", 0))

            user_usage[email] = {
                "total_tokens": float(month.get("total_tokens", 0)),
                "daily_tokens": float(day.get("total_tokens", 0)),
                "input_tokens": float(month.get("input_tokens", 0)),
                "output_tokens": float(month.get("output_tokens", 0)),
                "cache_tokens": cache_read + cache_write,
                "estimated_cost": float(month.get("estimated_cost", 0)),
                "daily_cost": float(day.get("estimated_cost", 0)),
                "groups": profile.get("groups", []),
            }

        print(f"Found {len(user_usage)} users with usage in {month_prefix}")

    except Exception as e:
        print(f"Error querying quota table: {str(e)}")
        raise

    return user_usage


def _parse_policy_item(item, policy_type, identifier):
    """Parse a DynamoDB policy item into a policy dict."""
    return {
        "policy_type": policy_type,
        "identifier": identifier,
        "monthly_token_limit": int(item.get("monthly_token_limit", 0)),
        "daily_token_limit": int(item.get("daily_token_limit", 0)) if item.get("daily_token_limit") else None,
        "monthly_cost_limit": float(item["monthly_cost_limit"]) if item.get("monthly_cost_limit") else None,
        "daily_cost_limit": float(item["daily_cost_limit"]) if item.get("daily_cost_limit") else None,
        "warning_threshold_80": int(item.get("warning_threshold_80", 0)),
        "warning_threshold_90": int(item.get("warning_threshold_90", 0)),
        "cost_warning_threshold_80": float(item["cost_warning_threshold_80"]) if item.get("cost_warning_threshold_80") else None,
        "cost_warning_threshold_90": float(item["cost_warning_threshold_90"]) if item.get("cost_warning_threshold_90") else None,
        "enforcement_mode": item.get("enforcement_mode", "alert"),
        "enabled": item.get("enabled", True),
    }


def load_all_policies():
    """
    Load all quota policies from the QuotaPolicies table.
    Returns dict keyed by policy type and identifier.
    """
    policies = {}

    if not policies_table:
        return policies

    try:
        response = policies_table.scan(
            FilterExpression=Attr("sk").eq("CURRENT"),
        )

        for item in response.get("Items", []):
            policy_type = item.get("policy_type")
            identifier = item.get("identifier")

            if policy_type and identifier:
                key = f"{policy_type}:{identifier}"
                policies[key] = _parse_policy_item(item, policy_type, identifier)

        # Handle pagination
        while "LastEvaluatedKey" in response:
            response = policies_table.scan(
                FilterExpression=Attr("sk").eq("CURRENT"),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )

            for item in response.get("Items", []):
                policy_type = item.get("policy_type")
                identifier = item.get("identifier")

                if policy_type and identifier:
                    key = f"{policy_type}:{identifier}"
                    policies[key] = _parse_policy_item(item, policy_type, identifier)

    except Exception as e:
        print(f"Error loading policies: {str(e)}")

    return policies


def _policy_restrictiveness(p: dict) -> tuple:
    """Sort key: lower tuple = more restrictive.

    Matches the TVM Lambda's selection logic so that alerts and enforcement
    always agree on which policy applies to a multi-group user.
    """
    return (
        p.get("monthly_token_limit") or float("inf"),
        p.get("monthly_cost_limit") or float("inf"),
        p.get("daily_token_limit") or float("inf"),
        p.get("daily_cost_limit") or float("inf"),
    )


def resolve_user_quota(email, groups, policies_cache):
    """
    Resolve the effective quota policy for a user.
    Precedence: user-specific > group (most restrictive) > default > env defaults

    Args:
        email: User's email address.
        groups: List of group names from JWT claims.
        policies_cache: Dict of all loaded policies.

    Returns:
        Policy dict or None if no policy applies (unlimited).
    """
    if not ENABLE_FINEGRAINED_QUOTAS:
        # Return default limits from environment
        return {
            "policy_type": "default",
            "identifier": "environment",
            "monthly_token_limit": MONTHLY_TOKEN_LIMIT,
            "daily_token_limit": None,
            "warning_threshold_80": WARNING_THRESHOLD_80,
            "warning_threshold_90": WARNING_THRESHOLD_90,
            "enforcement_mode": "alert",
            "enabled": True,
        }

    # 1. Check for user-specific policy
    user_key = f"user:{email}"
    if user_key in policies_cache:
        policy = policies_cache[user_key]
        if policy.get("enabled"):
            return policy

    # 2. Check for group policies (apply most restrictive)
    group_policies = []
    for group in groups or []:
        group_key = f"group:{group}"
        if group_key in policies_cache:
            policy = policies_cache[group_key]
            if policy.get("enabled"):
                group_policies.append(policy)

    if group_policies:
        # Most restrictive: compare (monthly_tokens, monthly_cost, daily_tokens, daily_cost).
        # Aligned with TVM's _policy_restrictiveness — lower tuple = more restrictive.
        return min(group_policies, key=_policy_restrictiveness)

    # 3. Fall back to default policy
    default_key = "default:default"
    if default_key in policies_cache:
        policy = policies_cache[default_key]
        if policy.get("enabled"):
            return policy

    # 4. No policy defined = unlimited (return None)
    return None


def check_limits_and_generate_alerts(
    email, total_tokens, daily_tokens, policy,
    month_name, current_date, days_remaining, days_in_month, sent_alerts,
    estimated_cost=0, daily_cost=0,
):
    """
    Check all limit types (tokens and cost) and generate appropriate alerts.
    Returns list of alert dicts.
    """
    alerts = []
    policy_info = f"{policy['policy_type']}:{policy['identifier']}"
    enforcement_mode = policy.get('enforcement_mode', 'alert')

    # 1. Check monthly token limit
    monthly_limit = policy["monthly_token_limit"]
    monthly_pct = (total_tokens / monthly_limit) * 100 if monthly_limit > 0 else 0
    daily_average = total_tokens / max(1, int(current_date.split("-")[2]))
    projected_total = daily_average * days_in_month

    monthly_alert_level = None
    if total_tokens > monthly_limit:
        monthly_alert_level = "exceeded"
    elif total_tokens > policy["warning_threshold_90"]:
        monthly_alert_level = "critical"
    elif total_tokens > policy["warning_threshold_80"]:
        monthly_alert_level = "warning"

    if monthly_alert_level:
        alert_key = f"{email}#monthly#{monthly_alert_level}"
        if alert_key not in sent_alerts:
            alerts.append({
                "user": email,
                "alert_type": "monthly",
                "alert_level": monthly_alert_level,
                "current_usage": int(total_tokens),
                "limit": monthly_limit,
                "percentage": round(monthly_pct, 1),
                "month": month_name,
                "days_remaining": days_remaining,
                "daily_average": int(daily_average),
                "projected_total": int(projected_total),
                "policy_info": policy_info,
                "enforcement_mode": enforcement_mode,
            })

    # 2. Check monthly cost limit (if configured)
    monthly_cost_limit = policy.get("monthly_cost_limit")
    if monthly_cost_limit and monthly_cost_limit > 0:
        cost_pct = (estimated_cost / monthly_cost_limit) * 100
        cost_threshold_80 = policy.get("cost_warning_threshold_80", monthly_cost_limit * 0.8)
        cost_threshold_90 = policy.get("cost_warning_threshold_90", monthly_cost_limit * 0.9)

        cost_alert_level = None
        if estimated_cost > monthly_cost_limit:
            cost_alert_level = "exceeded"
        elif estimated_cost > cost_threshold_90:
            cost_alert_level = "critical"
        elif estimated_cost > cost_threshold_80:
            cost_alert_level = "warning"

        if cost_alert_level:
            alert_key = f"{email}#monthly_cost#{cost_alert_level}"
            if alert_key not in sent_alerts:
                alerts.append({
                    "user": email,
                    "alert_type": "monthly_cost",
                    "alert_level": cost_alert_level,
                    "current_usage": round(estimated_cost, 2),
                    "limit": monthly_cost_limit,
                    "percentage": round(cost_pct, 1),
                    "month": month_name,
                    "days_remaining": days_remaining,
                    "policy_info": policy_info,
                    "enforcement_mode": enforcement_mode,
                })

    # 3. Check daily token limit (if configured)
    daily_limit = policy.get("daily_token_limit")
    if daily_limit:
        daily_pct = (daily_tokens / daily_limit) * 100 if daily_limit > 0 else 0

        daily_alert_level = None
        if daily_tokens > daily_limit:
            daily_alert_level = "exceeded"
        elif daily_tokens > (daily_limit * 0.9):
            daily_alert_level = "critical"
        elif daily_tokens > (daily_limit * 0.8):
            daily_alert_level = "warning"

        if daily_alert_level:
            # Daily alerts use date in key so they can repeat each day
            alert_key = f"{email}#daily#{current_date}#{daily_alert_level}"
            if alert_key not in sent_alerts:
                alerts.append({
                    "user": email,
                    "alert_type": "daily",
                    "alert_level": daily_alert_level,
                    "current_usage": int(daily_tokens),
                    "limit": daily_limit,
                    "percentage": round(daily_pct, 1),
                    "date": current_date,
                    "policy_info": policy_info,
                    "enforcement_mode": enforcement_mode,
                })

    # 4. Check daily cost limit (if configured)
    daily_cost_limit = policy.get("daily_cost_limit")
    if daily_cost_limit and daily_cost_limit > 0:
        daily_cost_pct = (daily_cost / daily_cost_limit) * 100

        daily_cost_alert_level = None
        if daily_cost > daily_cost_limit:
            daily_cost_alert_level = "exceeded"
        elif daily_cost > (daily_cost_limit * 0.9):
            daily_cost_alert_level = "critical"
        elif daily_cost > (daily_cost_limit * 0.8):
            daily_cost_alert_level = "warning"

        if daily_cost_alert_level:
            alert_key = f"{email}#daily_cost#{current_date}#{daily_cost_alert_level}"
            if alert_key not in sent_alerts:
                alerts.append({
                    "user": email,
                    "alert_type": "daily_cost",
                    "alert_level": daily_cost_alert_level,
                    "current_usage": round(daily_cost, 2),
                    "limit": daily_cost_limit,
                    "percentage": round(daily_cost_pct, 1),
                    "date": current_date,
                    "policy_info": policy_info,
                    "enforcement_mode": enforcement_mode,
                })

    return alerts


def get_sent_alerts(month_name):
    """
    Get list of alerts already sent this month to avoid duplicates.
    Returns set of alert key strings.

    Reads email/alert_type/alert_level from item attributes rather than
    splitting the SK, because some "emails" legitimately contain `#`
    (e.g. ORG#global, SYSTEM#reconciler) which would break positional
    parsing and defeat dedup — causing alerts to re-fire every run.
    """
    sent_alerts = set()

    def _collect(items):
        for item in items:
            email = item.get("email")
            alert_type = item.get("alert_type")
            alert_level = item.get("alert_level")
            if not email or not alert_type or not alert_level:
                continue
            if alert_type in ("daily", "daily_cost", "reconciler_heartbeat"):
                # Date is appended to the SK: ...#{alert_level}#{date}
                date = item.get("sk", "").rsplit("#", 1)[-1]
                sent_alerts.add(f"{email}#{alert_type}#{date}#{alert_level}")
            else:
                sent_alerts.add(f"{email}#{alert_type}#{alert_level}")

    try:
        month_prefix = datetime.now(EFFECTIVE_TZ).strftime("%Y-%m")

        response = quota_table.query(
            KeyConditionExpression=Key("pk").eq("ALERTS")
            & Key("sk").begins_with(f"{month_prefix}#ALERT#")
        )
        _collect(response.get("Items", []))

        while "LastEvaluatedKey" in response:
            response = quota_table.query(
                KeyConditionExpression=Key("pk").eq("ALERTS")
                & Key("sk").begins_with(f"{month_prefix}#ALERT#"),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            _collect(response.get("Items", []))

        if sent_alerts:
            print(f"Found {len(sent_alerts)} alerts already sent this month")

    except Exception as e:
        print(f"Error checking sent alerts: {str(e)}")

    return sent_alerts


def record_sent_alert(month_name, email, alert_type, alert_level, alert_data):
    """
    Record that an alert was sent to prevent duplicates.
    """
    try:
        effective_now = datetime.now(EFFECTIVE_TZ)
        month_prefix = effective_now.strftime("%Y-%m")

        # Build SK based on alert type
        if alert_type in ("daily", "daily_cost", "reconciler_heartbeat"):
            date = alert_data.get("date", effective_now.strftime("%Y-%m-%d"))
            sk = f"{month_prefix}#ALERT#{email}#{alert_type}#{alert_level}#{date}"
        else:
            sk = f"{month_prefix}#ALERT#{email}#{alert_type}#{alert_level}"

        quota_table.put_item(
            Item={
                "pk": "ALERTS",
                "sk": sk,
                "sent_at": datetime.now(timezone.utc).isoformat(),
                "month": month_name,
                "email": email,
                "alert_type": alert_type,
                "alert_level": alert_level,
                "usage_at_alert": Decimal(str(alert_data.get("current_usage", 0))),
                "limit_at_alert": Decimal(str(alert_data.get("limit", 0))),
                "policy_info": alert_data.get("policy_info", ""),
                "ttl": int((datetime.now(timezone.utc).timestamp())) + (60 * 86400),  # 60 day TTL
            }
        )
        print(f"Recorded {alert_type} {alert_level} alert for {email}")

    except Exception as e:
        print(f"Error recording sent alert: {str(e)}")


def send_alerts(alerts):
    """
    Send alerts via SNS with enhanced formatting for different alert types.
    """
    if not SNS_TOPIC_ARN:
        print("Warning: SNS_TOPIC_ARN not configured - skipping alert sending")
        return

    for alert in alerts:
        try:
            alert_type = alert.get("alert_type", "monthly")
            alert_level = alert["alert_level"]

            # Create subject based on alert type and level
            level_prefix = {
                "warning": "WARNING",
                "critical": "CRITICAL",
                "exceeded": "EXCEEDED",
            }.get(alert_level, "ALERT")

            type_label = {
                "monthly": "Monthly Token Quota",
                "daily": "Daily Token Quota",
                "monthly_cost": "Monthly Cost Quota",
                "daily_cost": "Daily Cost Quota",
                "org_monthly_tokens": "Org-Wide Monthly Token Quota",
                "org_monthly_cost": "Org-Wide Monthly Cost Quota",
                "reconciler_heartbeat": "Reconciler Heartbeat",
            }.get(alert_type, "Quota")

            if alert_type == "reconciler_heartbeat":
                subject = f"Claude Code {level_prefix} - {type_label} Stale"
            else:
                subject = f"Claude Code {level_prefix} - {type_label} - {alert['percentage']:.0f}%"

            # Format the message body based on alert type
            if alert_type == "monthly":
                message = format_monthly_alert(alert)
            elif alert_type == "daily":
                message = format_daily_alert(alert)
            elif alert_type == "monthly_cost":
                message = format_cost_alert(alert, "Monthly")
            elif alert_type == "daily_cost":
                message = format_cost_alert(alert, "Daily")
            elif alert_type in ("org_monthly_tokens", "org_monthly_cost"):
                message = format_org_alert(alert)
            elif alert_type == "reconciler_heartbeat":
                message = format_reconciler_heartbeat_alert(alert)
            else:
                message = format_monthly_alert(alert)

            # Send to SNS
            message_attributes = {
                "user": {"DataType": "String", "StringValue": alert["user"]},
                "alert_type": {"DataType": "String", "StringValue": alert_type},
                "alert_level": {"DataType": "String", "StringValue": alert_level},
            }
            if "percentage" in alert:
                message_attributes["percentage"] = {"DataType": "Number", "StringValue": str(alert["percentage"])}

            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=subject,
                Message=message,
                MessageAttributes=message_attributes,
            )

            pct_str = f" ({alert['percentage']:.1f}%)" if "percentage" in alert else ""
            print(f"Sent {alert_type} {alert_level} alert for {alert['user']}{pct_str}")

        except Exception as e:
            print(f"Error sending alert for {alert['user']}: {str(e)}")


def format_monthly_alert(alert):
    """Format monthly token quota alert message with prominent user email."""
    enforcement = alert.get('enforcement_mode', 'alert')
    user_email = alert['user']

    return f"""
=====================================
CLAUDE CODE QUOTA ALERT
=====================================

USER: {user_email}
ALERT: Monthly Token Quota - {alert['alert_level'].upper()}
MONTH: {alert.get('month', 'N/A')}

-------------------------------------
CURRENT USAGE
-------------------------------------
Monthly Tokens: {alert['current_usage']:,} / {alert['limit']:,} ({alert['percentage']:.1f}%)
Daily Average: {alert.get('daily_average', 0):,} tokens
Projected Monthly: {alert.get('projected_total', 0):,} tokens

Days Remaining: {alert.get('days_remaining', 'N/A')}

Policy: {alert.get('policy_info', 'default')}
Enforcement: {enforcement}

-------------------------------------
ACTION REQUIRED
-------------------------------------
{"ACCESS IS BLOCKED until quota resets or admin unblocks." if enforcement == "block" and alert['alert_level'] == 'exceeded' else "User may soon exceed quota limit."}

To temporarily unblock this user:
  ccwb quota unblock {user_email} --duration 24h

To increase their quota:
  ccwb quota set-user {user_email} --monthly-limit 500M

=====================================
This alert is sent once per threshold level per month.
"""


def format_daily_alert(alert):
    """Format daily token quota alert message with prominent user email."""
    enforcement = alert.get('enforcement_mode', 'alert')
    user_email = alert['user']

    return f"""
=====================================
CLAUDE CODE QUOTA ALERT
=====================================

USER: {user_email}
ALERT: Daily Token Quota - {alert['alert_level'].upper()}
DATE: {alert.get('date', 'N/A')}

-------------------------------------
CURRENT USAGE
-------------------------------------
Daily Tokens: {alert['current_usage']:,} / {alert['limit']:,} ({alert['percentage']:.1f}%)

Policy: {alert.get('policy_info', 'default')}
Enforcement: {enforcement}

-------------------------------------
ACTION REQUIRED
-------------------------------------
{"ACCESS IS BLOCKED until daily quota resets at midnight (UTC+8) or admin unblocks." if enforcement == "block" and alert['alert_level'] == 'exceeded' else "User may soon exceed daily quota limit."}

To temporarily unblock this user:
  ccwb quota unblock {user_email} --duration 24h

To increase their daily quota:
  ccwb quota set-user {user_email} --daily-limit 20M

=====================================
Daily quotas reset at midnight (UTC+8).
"""


def format_cost_alert(alert, period="Monthly"):
    """Format cost quota alert message."""
    enforcement = alert.get('enforcement_mode', 'alert')
    user_email = alert['user']
    is_daily = period == "Daily"

    return f"""
=====================================
CLAUDE CODE COST QUOTA ALERT
=====================================

USER: {user_email}
ALERT: {period} Cost Quota - {alert['alert_level'].upper()}
{"DATE: " + alert.get('date', 'N/A') if is_daily else "MONTH: " + alert.get('month', 'N/A')}

-------------------------------------
CURRENT COST USAGE
-------------------------------------
{period} Cost: ${alert['current_usage']:,.2f} / ${alert['limit']:,.2f} ({alert['percentage']:.1f}%)

Policy: {alert.get('policy_info', 'default')}
Enforcement: {enforcement}

-------------------------------------
ACTION REQUIRED
-------------------------------------
{"ACCESS IS BLOCKED until cost quota resets or admin unblocks." if enforcement == "block" and alert['alert_level'] == 'exceeded' else f"User may soon exceed {period.lower()} cost limit."}

To temporarily unblock this user:
  ccwb quota unblock {user_email} --duration 24h

To increase their cost quota:
  ccwb quota set-user {user_email} --{'daily' if is_daily else 'monthly'}-cost-limit {'20' if is_daily else '200'}

=====================================
{"Daily cost quotas reset at midnight (UTC+8)." if is_daily else "This alert is sent once per threshold level per month."}
"""


def get_org_usage():
    """Get org aggregate usage for current month (UTC+8 boundaries)."""
    now = datetime.now(EFFECTIVE_TZ)
    sk = f"MONTH#{now.strftime('%Y-%m')}#BEDROCK"
    try:
        response = quota_table.get_item(Key={"pk": "ORG#global", "sk": sk})
        item = response.get("Item")
        if not item:
            return {"total_tokens": 0, "estimated_cost": 0.0, "user_count": 0}
        return {
            "total_tokens": float(item.get("total_tokens", 0)),
            "estimated_cost": float(item.get("estimated_cost", 0)),
            "user_count": 0,  # Bedrock ORG record does not carry user_count; caller injects it
        }
    except Exception as e:
        print(f"Error getting org usage: {e}")
        return {"total_tokens": 0, "estimated_cost": 0.0, "user_count": 0}


def check_org_limits_and_generate_alerts(org_usage, policy, month_name, sent_alerts):
    """Check org-wide limits and generate alerts at 80%/90%/exceeded thresholds."""
    alerts = []

    if not policy or not policy.get("enabled", True):
        return alerts

    total_tokens = org_usage.get("total_tokens", 0)
    estimated_cost = org_usage.get("estimated_cost", 0)
    user_count = org_usage.get("user_count", 0)
    monthly_limit = policy.get("monthly_token_limit", 0)
    monthly_cost_limit = policy.get("monthly_cost_limit")
    enforcement = policy.get("enforcement_mode", "alert")

    # Token threshold checks
    if monthly_limit > 0:
        pct = (total_tokens / monthly_limit) * 100
        for level, threshold in [("exceeded", 100), ("critical", 90), ("warning", 80)]:
            if pct >= threshold:
                alert_key = f"ORG#global#org_monthly_tokens#{level}"
                if alert_key not in sent_alerts:
                    alerts.append({
                        "user": "ORG#global",
                        "alert_type": "org_monthly_tokens",
                        "alert_level": level,
                        "percentage": pct,
                        "current_usage": total_tokens,
                        "limit": monthly_limit,
                        "month": month_name,
                        "enforcement_mode": enforcement,
                        "user_count": user_count,
                    })
                break

    # Cost threshold checks
    if monthly_cost_limit and monthly_cost_limit > 0:
        cost_pct = (estimated_cost / monthly_cost_limit) * 100
        for level, threshold in [("exceeded", 100), ("critical", 90), ("warning", 80)]:
            if cost_pct >= threshold:
                alert_key = f"ORG#global#org_monthly_cost#{level}"
                if alert_key not in sent_alerts:
                    alerts.append({
                        "user": "ORG#global",
                        "alert_type": "org_monthly_cost",
                        "alert_level": level,
                        "percentage": cost_pct,
                        "current_usage": estimated_cost,
                        "limit": monthly_cost_limit,
                        "month": month_name,
                        "enforcement_mode": enforcement,
                        "user_count": user_count,
                    })
                break

    return alerts


def format_org_alert(alert):
    """Format organization-wide quota alert message."""
    enforcement = alert.get('enforcement_mode', 'alert')
    is_cost = alert.get("alert_type") == "org_monthly_cost"
    user_count = alert.get("user_count", 0)

    if is_cost:
        usage_line = f"Org Monthly Cost: ${alert['current_usage']:,.2f} / ${alert['limit']:,.2f} ({alert['percentage']:.1f}%)"
    else:
        usage_line = f"Org Monthly Tokens: {int(alert['current_usage']):,} / {int(alert['limit']):,} ({alert['percentage']:.1f}%)"

    return f"""
=====================================
ORGANIZATION-WIDE QUOTA ALERT
=====================================

SCOPE: All users ({user_count} active)
ALERT: {'Cost' if is_cost else 'Token'} Quota - {alert['alert_level'].upper()}
MONTH: {alert.get('month', 'N/A')}

-------------------------------------
CURRENT ORG USAGE
-------------------------------------
{usage_line}

Enforcement: {enforcement}

-------------------------------------
ACTION REQUIRED
-------------------------------------
{"ALL USERS ARE BLOCKED. Organization-wide quota exceeded." if enforcement == "block" and alert['alert_level'] == 'exceeded' else "Organization may soon exceed its quota limit. Consider increasing the org limit or reviewing user usage."}

To update the organization limit:
  ccwb quota set-org --monthly-{'cost-limit 10000' if is_cost else 'limit 2B'}

=====================================
This alert is sent once per threshold level per month.
"""


RECONCILER_HEARTBEAT_STALE_MINUTES = 45


def check_reconciler_heartbeat(month_name, current_date, sent_alerts):
    """
    Check if the bedrock_usage_reconciler Lambda has run recently.

    Reads the SYSTEM#reconciler HEARTBEAT record from DynamoDB.
    If last_run is older than 45 minutes (or missing), generates an alert.
    Uses daily dedup key so the alert fires at most once per day.
    """
    alerts = []
    alert_key = f"SYSTEM#reconciler#reconciler_heartbeat#{current_date}#stale"
    if alert_key in sent_alerts:
        return alerts

    try:
        response = quota_table.get_item(
            Key={"pk": "SYSTEM#reconciler", "sk": "HEARTBEAT"}
        )
        item = response.get("Item")

        if not item:
            alerts.append({
                "user": "SYSTEM#reconciler",
                "alert_type": "reconciler_heartbeat",
                "alert_level": "stale",
                "date": current_date,
                "month": month_name,
                "last_run": "never",
                "minutes_stale": -1,
            })
            return alerts

        last_run_str = item.get("last_run", "")
        try:
            last_run = datetime.fromisoformat(last_run_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_run = None

        if last_run is None:
            alerts.append({
                "user": "SYSTEM#reconciler",
                "alert_type": "reconciler_heartbeat",
                "alert_level": "stale",
                "date": current_date,
                "month": month_name,
                "last_run": last_run_str or "unparseable",
                "minutes_stale": -1,
            })
            return alerts

        now_utc = datetime.now(timezone.utc)
        minutes_since = (now_utc - last_run).total_seconds() / 60

        if minutes_since > RECONCILER_HEARTBEAT_STALE_MINUTES:
            alerts.append({
                "user": "SYSTEM#reconciler",
                "alert_type": "reconciler_heartbeat",
                "alert_level": "stale",
                "date": current_date,
                "month": month_name,
                "last_run": last_run_str,
                "minutes_stale": int(minutes_since),
            })

    except Exception as e:
        print(f"Error checking reconciler heartbeat: {e}")

    return alerts


def format_reconciler_heartbeat_alert(alert):
    """Format reconciler heartbeat staleness alert message."""
    last_run = alert.get("last_run", "unknown")
    minutes_stale = alert.get("minutes_stale", -1)

    if minutes_stale < 0:
        staleness_detail = f"Last run: {last_run}"
    else:
        staleness_detail = f"Last run: {last_run} ({minutes_stale} minutes ago)"

    return f"""
=====================================
PIPELINE HEALTH ALERT
=====================================

COMPONENT: bedrock_usage_reconciler Lambda
STATUS: STALE — has not run in over {RECONCILER_HEARTBEAT_STALE_MINUTES} minutes
DATE: {alert.get('date', 'N/A')}

-------------------------------------
DETAILS
-------------------------------------
{staleness_detail}
Expected: every 30 minutes (EventBridge schedule)
Threshold: {RECONCILER_HEARTBEAT_STALE_MINUTES} minutes

-------------------------------------
IMPACT
-------------------------------------
Missed Bedrock usage events will not be reconciled.
Quota enforcement may be based on stale usage data.

-------------------------------------
ACTION REQUIRED
-------------------------------------
1. Check the reconciler Lambda CloudWatch logs for errors
2. Verify the EventBridge schedule rule is enabled:
   aws events describe-rule --name claude-code-reconciler-schedule
3. Redeploy if needed:
   ccwb deploy quota

=====================================
This alert is sent once per day while the reconciler remains stale.
"""

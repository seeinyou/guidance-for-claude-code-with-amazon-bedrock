# ABOUTME: CLI commands for quota policy management
# ABOUTME: Provides commands to set, list, delete, and show quota policies

"""Quota management commands for fine-grained quota control."""

import csv
import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import boto3
from cleo.commands.command import Command
from cleo.helpers import argument, option
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from claude_code_with_bedrock.config import Config, Profile
from claude_code_with_bedrock.models import EnforcementMode, PolicyType
from claude_code_with_bedrock.quota_policies import (
    PolicyAlreadyExistsError,
    QuotaPolicyError,
    QuotaPolicyManager,
)

# Security: Maximum allowed unblock duration in days
MAX_UNBLOCK_DAYS = 7

# Email validation pattern (RFC 5322 simplified)
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MAX_EMAIL_LENGTH = 254


def _validate_email(email: str) -> bool:
    """Validate email format for security.

    Args:
        email: Email address to validate.

    Returns:
        True if valid, False otherwise.
    """
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    return bool(EMAIL_PATTERN.match(email))


def _get_caller_identity() -> str:
    """Get the actual caller identity using STS for audit trail.

    Returns:
        Caller ARN or 'unknown' if unable to determine.
    """
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        return identity.get("Arn", "unknown")
    except Exception:
        return "unknown"


def _get_quota_manager(profile) -> QuotaPolicyManager:
    """Get a QuotaPolicyManager for the given profile.

    Args:
        profile: Configuration profile.

    Returns:
        QuotaPolicyManager instance.

    Raises:
        ValueError: If quota policies table is not configured.
    """
    if not profile.quota_policies_table:
        # Use default table name if not configured
        table_name = "QuotaPolicies"
    else:
        table_name = profile.quota_policies_table

    return QuotaPolicyManager(table_name, profile.aws_region)


def _format_tokens(tokens: int) -> str:
    """Format token count for display.

    Args:
        tokens: Token count.

    Returns:
        Formatted string (e.g., "300M", "1.5B", "50K").
    """
    if tokens >= 1_000_000_000:
        return f"{tokens / 1_000_000_000:.1f}B"
    elif tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M"
    elif tokens >= 1_000:
        return f"{tokens / 1_000:.1f}K"
    return str(tokens)


def _parse_tokens(value: str) -> int:
    """Parse token value with suffix support.

    Args:
        value: Token value string (e.g., "300M", "1.5B", "50000").

    Returns:
        Integer token count.

    Raises:
        ValueError: If value cannot be parsed.
    """
    value = value.strip().upper()

    multipliers = {
        "K": 1_000,
        "M": 1_000_000,
        "B": 1_000_000_000,
    }

    for suffix, multiplier in multipliers.items():
        if value.endswith(suffix):
            return int(float(value[:-1]) * multiplier)

    return int(value)


def _parse_cost(value: str) -> Decimal:
    """Parse cost value, stripping optional $ prefix.

    Args:
        value: Cost value string (e.g., "100", "$100", "10.50").

    Returns:
        Decimal cost value.

    Raises:
        ValueError: If value cannot be parsed.
    """
    value = value.strip().lstrip("$")
    return Decimal(value)


def _print_policy_summary(console: Console, policy) -> None:
    """Print policy summary after create/update."""
    console.print(f"  Monthly limit: {_format_tokens(policy.monthly_token_limit)}")
    if policy.daily_token_limit:
        console.print(f"  Daily limit: {_format_tokens(policy.daily_token_limit)}")
    if policy.monthly_cost_limit is not None:
        console.print(f"  Monthly cost limit: ${policy.monthly_cost_limit}")
    if policy.daily_cost_limit is not None:
        console.print(f"  Daily cost limit: ${policy.daily_cost_limit}")
    console.print(f"  Enforcement: {policy.enforcement_mode.value}")


class QuotaSetUserCommand(Command):
    """Set quota policy for a specific user."""

    name = "quota set-user"
    description = "Set quota policy for a specific user"

    arguments = [
        argument("email", description="User email address"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("monthly-limit", "m", description="Monthly token limit (e.g., 300M, 1B)", flag=False),
        option("daily-limit", "d", description="Daily token limit (e.g., 15M)", flag=False),
        option("monthly-cost-limit", None, description="Monthly cost limit in dollars (e.g., 100, $100)", flag=False),
        option("daily-cost-limit", None, description="Daily cost limit in dollars (e.g., 10, $10)", flag=False),
        option("enforcement", "e", description="Enforcement mode: 'alert' (default) or 'block'", flag=False),
        option("disabled", description="Create policy in disabled state", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        email = self.argument("email")

        # Security: Validate email format before using as DynamoDB key
        if not _validate_email(email):
            console.print(f"[red]Invalid email format: {email}[/red]")
            return 1

        monthly_limit_str = self.option("monthly-limit")

        if not monthly_limit_str:
            console.print("[red]--monthly-limit is required[/red]")
            return 1

        try:
            monthly_limit = _parse_tokens(monthly_limit_str)
        except ValueError:
            console.print(f"[red]Invalid monthly limit: {monthly_limit_str}[/red]")
            return 1

        daily_limit = None
        daily_limit_str = self.option("daily-limit")
        if daily_limit_str:
            try:
                daily_limit = _parse_tokens(daily_limit_str)
            except ValueError:
                console.print(f"[red]Invalid daily limit: {daily_limit_str}[/red]")
                return 1

        # Parse cost limits
        monthly_cost_limit = None
        monthly_cost_str = self.option("monthly-cost-limit")
        if monthly_cost_str:
            try:
                monthly_cost_limit = _parse_cost(monthly_cost_str)
            except Exception:
                console.print(f"[red]Invalid monthly cost limit: {monthly_cost_str}[/red]")
                return 1

        daily_cost_limit = None
        daily_cost_str = self.option("daily-cost-limit")
        if daily_cost_str:
            try:
                daily_cost_limit = _parse_cost(daily_cost_str)
            except Exception:
                console.print(f"[red]Invalid daily cost limit: {daily_cost_str}[/red]")
                return 1

        # Parse enforcement mode
        enforcement_mode = EnforcementMode.ALERT
        enforcement_str = self.option("enforcement")
        if enforcement_str:
            enforcement_str = enforcement_str.lower().strip()
            if enforcement_str == "block":
                enforcement_mode = EnforcementMode.BLOCK
            elif enforcement_str != "alert":
                console.print(f"[red]Invalid enforcement mode: {enforcement_str}. Use 'alert' or 'block'.[/red]")
                return 1

        enabled = not self.option("disabled")

        try:
            manager = _get_quota_manager(profile)
            policy = manager.create_policy(
                policy_type=PolicyType.USER,
                identifier=email,
                monthly_token_limit=monthly_limit,
                daily_token_limit=daily_limit,
                monthly_cost_limit=monthly_cost_limit,
                daily_cost_limit=daily_cost_limit,
                enforcement_mode=enforcement_mode,
                enabled=enabled,
            )
            console.print(f"[green]Created user quota policy for {email}[/green]")
            _print_policy_summary(console, policy)
            return 0

        except PolicyAlreadyExistsError:
            # Update existing policy
            try:
                policy = manager.update_policy(
                    policy_type=PolicyType.USER,
                    identifier=email,
                    monthly_token_limit=monthly_limit,
                    daily_token_limit=daily_limit,
                    monthly_cost_limit=monthly_cost_limit,
                    daily_cost_limit=daily_cost_limit,
                    enforcement_mode=enforcement_mode,
                    enabled=enabled,
                )
                console.print(f"[yellow]Updated existing user quota policy for {email}[/yellow]")
                _print_policy_summary(console, policy)
                return 0
            except QuotaPolicyError as e:
                console.print(f"[red]Failed to update policy: {e}[/red]")
                return 1

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to create policy: {e}[/red]")
            return 1


class QuotaSetGroupCommand(Command):
    """Set quota policy for a group."""

    name = "quota set-group"
    description = "Set quota policy for a group"

    arguments = [
        argument("group", description="Group name"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("monthly-limit", "m", description="Monthly token limit (e.g., 300M, 1B)", flag=False),
        option("daily-limit", "d", description="Daily token limit (e.g., 15M)", flag=False),
        option("monthly-cost-limit", None, description="Monthly cost limit in dollars (e.g., 100, $100)", flag=False),
        option("daily-cost-limit", None, description="Daily cost limit in dollars (e.g., 10, $10)", flag=False),
        option("enforcement", "e", description="Enforcement mode: 'alert' (default) or 'block'", flag=False),
        option("disabled", description="Create policy in disabled state", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        group = self.argument("group")
        monthly_limit_str = self.option("monthly-limit")

        if not monthly_limit_str:
            console.print("[red]--monthly-limit is required[/red]")
            return 1

        try:
            monthly_limit = _parse_tokens(monthly_limit_str)
        except ValueError:
            console.print(f"[red]Invalid monthly limit: {monthly_limit_str}[/red]")
            return 1

        daily_limit = None
        daily_limit_str = self.option("daily-limit")
        if daily_limit_str:
            try:
                daily_limit = _parse_tokens(daily_limit_str)
            except ValueError:
                console.print(f"[red]Invalid daily limit: {daily_limit_str}[/red]")
                return 1

        # Parse cost limits
        monthly_cost_limit = None
        monthly_cost_str = self.option("monthly-cost-limit")
        if monthly_cost_str:
            try:
                monthly_cost_limit = _parse_cost(monthly_cost_str)
            except Exception:
                console.print(f"[red]Invalid monthly cost limit: {monthly_cost_str}[/red]")
                return 1

        daily_cost_limit = None
        daily_cost_str = self.option("daily-cost-limit")
        if daily_cost_str:
            try:
                daily_cost_limit = _parse_cost(daily_cost_str)
            except Exception:
                console.print(f"[red]Invalid daily cost limit: {daily_cost_str}[/red]")
                return 1

        # Parse enforcement mode
        enforcement_mode = EnforcementMode.ALERT
        enforcement_str = self.option("enforcement")
        if enforcement_str:
            enforcement_str = enforcement_str.lower().strip()
            if enforcement_str == "block":
                enforcement_mode = EnforcementMode.BLOCK
            elif enforcement_str != "alert":
                console.print(f"[red]Invalid enforcement mode: {enforcement_str}. Use 'alert' or 'block'.[/red]")
                return 1

        enabled = not self.option("disabled")

        try:
            manager = _get_quota_manager(profile)
            policy = manager.create_policy(
                policy_type=PolicyType.GROUP,
                identifier=group,
                monthly_token_limit=monthly_limit,
                daily_token_limit=daily_limit,
                monthly_cost_limit=monthly_cost_limit,
                daily_cost_limit=daily_cost_limit,
                enforcement_mode=enforcement_mode,
                enabled=enabled,
            )
            console.print(f"[green]Created group quota policy for '{group}'[/green]")
            _print_policy_summary(console, policy)
            return 0

        except PolicyAlreadyExistsError:
            # Update existing policy
            try:
                policy = manager.update_policy(
                    policy_type=PolicyType.GROUP,
                    identifier=group,
                    monthly_token_limit=monthly_limit,
                    daily_token_limit=daily_limit,
                    monthly_cost_limit=monthly_cost_limit,
                    daily_cost_limit=daily_cost_limit,
                    enforcement_mode=enforcement_mode,
                    enabled=enabled,
                )
                console.print(f"[yellow]Updated existing group quota policy for '{group}'[/yellow]")
                _print_policy_summary(console, policy)
                return 0
            except QuotaPolicyError as e:
                console.print(f"[red]Failed to update policy: {e}[/red]")
                return 1

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to create policy: {e}[/red]")
            return 1


class QuotaSetDefaultCommand(Command):
    """Set default quota policy for all users."""

    name = "quota set-default"
    description = "Set default quota policy for all users"

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("monthly-limit", "m", description="Monthly token limit (e.g., 300M, 1B)", flag=False),
        option("daily-limit", "d", description="Daily token limit (e.g., 15M)", flag=False),
        option("monthly-cost-limit", None, description="Monthly cost limit in dollars (e.g., 100, $100)", flag=False),
        option("daily-cost-limit", None, description="Daily cost limit in dollars (e.g., 10, $10)", flag=False),
        option("enforcement", "e", description="Enforcement mode: 'alert' (default) or 'block'", flag=False),
        option("disabled", description="Create policy in disabled state", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        monthly_limit_str = self.option("monthly-limit")

        if not monthly_limit_str:
            console.print("[red]--monthly-limit is required[/red]")
            return 1

        try:
            monthly_limit = _parse_tokens(monthly_limit_str)
        except ValueError:
            console.print(f"[red]Invalid monthly limit: {monthly_limit_str}[/red]")
            return 1

        daily_limit = None
        daily_limit_str = self.option("daily-limit")
        if daily_limit_str:
            try:
                daily_limit = _parse_tokens(daily_limit_str)
            except ValueError:
                console.print(f"[red]Invalid daily limit: {daily_limit_str}[/red]")
                return 1

        # Parse cost limits
        monthly_cost_limit = None
        monthly_cost_str = self.option("monthly-cost-limit")
        if monthly_cost_str:
            try:
                monthly_cost_limit = _parse_cost(monthly_cost_str)
            except Exception:
                console.print(f"[red]Invalid monthly cost limit: {monthly_cost_str}[/red]")
                return 1

        daily_cost_limit = None
        daily_cost_str = self.option("daily-cost-limit")
        if daily_cost_str:
            try:
                daily_cost_limit = _parse_cost(daily_cost_str)
            except Exception:
                console.print(f"[red]Invalid daily cost limit: {daily_cost_str}[/red]")
                return 1

        # Parse enforcement mode
        enforcement_mode = EnforcementMode.ALERT
        enforcement_str = self.option("enforcement")
        if enforcement_str:
            enforcement_str = enforcement_str.lower().strip()
            if enforcement_str == "block":
                enforcement_mode = EnforcementMode.BLOCK
            elif enforcement_str != "alert":
                console.print(f"[red]Invalid enforcement mode: {enforcement_str}. Use 'alert' or 'block'.[/red]")
                return 1

        enabled = not self.option("disabled")

        try:
            manager = _get_quota_manager(profile)
            policy = manager.create_policy(
                policy_type=PolicyType.DEFAULT,
                identifier="default",
                monthly_token_limit=monthly_limit,
                daily_token_limit=daily_limit,
                monthly_cost_limit=monthly_cost_limit,
                daily_cost_limit=daily_cost_limit,
                enforcement_mode=enforcement_mode,
                enabled=enabled,
            )
            console.print("[green]Created default quota policy[/green]")
            _print_policy_summary(console, policy)
            return 0

        except PolicyAlreadyExistsError:
            # Update existing policy
            try:
                policy = manager.update_policy(
                    policy_type=PolicyType.DEFAULT,
                    identifier="default",
                    monthly_token_limit=monthly_limit,
                    daily_token_limit=daily_limit,
                    monthly_cost_limit=monthly_cost_limit,
                    daily_cost_limit=daily_cost_limit,
                    enforcement_mode=enforcement_mode,
                    enabled=enabled,
                )
                console.print("[yellow]Updated existing default quota policy[/yellow]")
                _print_policy_summary(console, policy)
                return 0
            except QuotaPolicyError as e:
                console.print(f"[red]Failed to update policy: {e}[/red]")
                return 1

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to create policy: {e}[/red]")
            return 1


class QuotaSetOrgCommand(Command):
    """Set organization-wide quota limit across all users."""

    name = "quota set-org"
    description = "Set organization-wide quota limit across all users"

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("monthly-limit", "m", description="Monthly token limit (e.g., 1B)", flag=False),
        option("monthly-cost-limit", None, description="Monthly cost limit in dollars (e.g., 5000)", flag=False),
        option("enforcement", "e", description="Enforcement mode: 'alert' (default) or 'block'", flag=False),
        option("disabled", description="Create policy in disabled state", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        monthly_limit_str = self.option("monthly-limit")
        monthly_cost_str = self.option("monthly-cost-limit")

        if not monthly_limit_str and not monthly_cost_str:
            console.print("[red]At least one of --monthly-limit or --monthly-cost-limit is required[/red]")
            return 1

        monthly_limit = 0
        if monthly_limit_str:
            try:
                monthly_limit = _parse_tokens(monthly_limit_str)
            except ValueError:
                console.print(f"[red]Invalid monthly limit: {monthly_limit_str}[/red]")
                return 1

        monthly_cost_limit = None
        if monthly_cost_str:
            try:
                monthly_cost_limit = _parse_cost(monthly_cost_str)
            except Exception:
                console.print(f"[red]Invalid monthly cost limit: {monthly_cost_str}[/red]")
                return 1

        enforcement_mode = EnforcementMode.ALERT
        enforcement_str = self.option("enforcement")
        if enforcement_str:
            enforcement_str = enforcement_str.lower().strip()
            if enforcement_str == "block":
                enforcement_mode = EnforcementMode.BLOCK
            elif enforcement_str != "alert":
                console.print(f"[red]Invalid enforcement mode: {enforcement_str}. Use 'alert' or 'block'.[/red]")
                return 1

        enabled = not self.option("disabled")

        try:
            manager = _get_quota_manager(profile)
            policy = manager.create_policy(
                policy_type=PolicyType.ORG,
                identifier="global",
                monthly_token_limit=monthly_limit,
                monthly_cost_limit=monthly_cost_limit,
                enforcement_mode=enforcement_mode,
                enabled=enabled,
            )
            console.print("[green]Created organization-wide quota policy[/green]")
            _print_policy_summary(console, policy)
            return 0

        except PolicyAlreadyExistsError:
            try:
                policy = manager.update_policy(
                    policy_type=PolicyType.ORG,
                    identifier="global",
                    monthly_token_limit=monthly_limit,
                    monthly_cost_limit=monthly_cost_limit,
                    enforcement_mode=enforcement_mode,
                    enabled=enabled,
                )
                console.print("[yellow]Updated existing organization-wide quota policy[/yellow]")
                _print_policy_summary(console, policy)
                return 0
            except QuotaPolicyError as e:
                console.print(f"[red]Failed to update policy: {e}[/red]")
                return 1

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to create policy: {e}[/red]")
            return 1


class QuotaListCommand(Command):
    """List all quota policies."""

    name = "quota list"
    description = "List all quota policies"

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("type", "t", description="Filter by policy type (user, group, default)", flag=False),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        policy_type = None
        type_filter = self.option("type")
        if type_filter:
            try:
                policy_type = PolicyType(type_filter.lower())
            except ValueError:
                console.print(f"[red]Invalid policy type: {type_filter}. Use 'user', 'group', 'default', or 'org'.[/red]")
                return 1

        try:
            manager = _get_quota_manager(profile)
            policies = manager.list_policies(policy_type)

            if not policies:
                console.print("[yellow]No quota policies found.[/yellow]")
                return 0

            console.print(
                Panel.fit(
                    "[bold cyan]Quota Policies[/bold cyan]",
                    border_style="cyan",
                )
            )

            table = Table(box=box.SIMPLE)
            table.add_column("Type", style="cyan")
            table.add_column("Identifier")
            table.add_column("Monthly Limit", justify="right")
            table.add_column("Daily Limit", justify="right")
            table.add_column("Monthly Cost", justify="right")
            table.add_column("Daily Cost", justify="right")
            table.add_column("Enforcement")
            table.add_column("Status")

            for policy in sorted(policies, key=lambda p: (p.policy_type.value, p.identifier)):
                status = "[green]Enabled[/green]" if policy.enabled else "[dim]Disabled[/dim]"
                daily = _format_tokens(policy.daily_token_limit) if policy.daily_token_limit else "-"
                enforcement = "[red]block[/red]" if policy.enforcement_mode.value == "block" else "alert"
                monthly_cost = f"${policy.monthly_cost_limit}" if policy.monthly_cost_limit is not None else "-"
                daily_cost = f"${policy.daily_cost_limit}" if policy.daily_cost_limit is not None else "-"

                table.add_row(
                    policy.policy_type.value,
                    policy.identifier,
                    _format_tokens(policy.monthly_token_limit),
                    daily,
                    monthly_cost,
                    daily_cost,
                    enforcement,
                    status,
                )

            console.print(table)
            return 0

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to list policies: {e}[/red]")
            return 1


class QuotaDeleteCommand(Command):
    """Delete a quota policy."""

    name = "quota delete"
    description = "Delete a quota policy"

    arguments = [
        argument("type", description="Policy type (user, group, default)"),
        argument("identifier", description="Policy identifier (email, group name, or 'default')"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("force", "f", description="Skip confirmation", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        type_str = self.argument("type")
        identifier = self.argument("identifier")

        try:
            policy_type = PolicyType(type_str.lower())
        except ValueError:
            console.print(f"[red]Invalid policy type: {type_str}. Use 'user', 'group', 'default', or 'org'.[/red]")
            return 1

        if not self.option("force"):
            console.print(f"[yellow]Delete {policy_type.value} policy for '{identifier}'?[/yellow]")
            if not self.confirm("Confirm deletion?"):
                console.print("[dim]Cancelled.[/dim]")
                return 0

        try:
            manager = _get_quota_manager(profile)
            deleted = manager.delete_policy(policy_type, identifier)

            if deleted:
                console.print(f"[green]Deleted {policy_type.value} policy for '{identifier}'[/green]")
                return 0
            else:
                console.print(f"[yellow]Policy not found: {policy_type.value}:{identifier}[/yellow]")
                return 1

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to delete policy: {e}[/red]")
            return 1


class QuotaShowCommand(Command):
    """Show effective quota policy for a user."""

    name = "quota show"
    description = "Show effective quota policy for a user"

    arguments = [
        argument("email", description="User email address"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("groups", "g", description="Comma-separated list of groups", flag=False),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        email = self.argument("email")

        # Security: Validate email format before using as DynamoDB key
        if not _validate_email(email):
            console.print(f"[red]Invalid email format: {email}[/red]")
            return 1

        groups_str = self.option("groups")
        groups = [g.strip() for g in groups_str.split(",")] if groups_str else None

        try:
            manager = _get_quota_manager(profile)
            policy = manager.resolve_quota_for_user(email, groups)

            console.print(
                Panel.fit(
                    f"[bold cyan]Effective Quota for {email}[/bold cyan]",
                    border_style="cyan",
                )
            )

            if policy is None:
                console.print("[yellow]No quota policy applies - usage is unlimited[/yellow]")
                return 0

            console.print(f"[bold]Applied Policy:[/bold] {policy.policy_type.value}:{policy.identifier}")
            console.print(
                f"[bold]Status:[/bold] {'[green]Enabled[/green]' if policy.enabled else '[dim]Disabled[/dim]'}"
            )
            console.print(f"[bold]Enforcement:[/bold] {policy.enforcement_mode.value}")
            console.print()

            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Metric", style="bold")
            table.add_column("Limit", justify="right")

            table.add_row("Monthly Token Limit", _format_tokens(policy.monthly_token_limit))
            if policy.daily_token_limit:
                table.add_row("Daily Token Limit", _format_tokens(policy.daily_token_limit))
            if policy.monthly_cost_limit is not None:
                table.add_row("Monthly Cost Limit", f"${policy.monthly_cost_limit}")
            if policy.daily_cost_limit is not None:
                table.add_row("Daily Cost Limit", f"${policy.daily_cost_limit}")
            table.add_row("Warning (80%)", _format_tokens(policy.warning_threshold_80))
            table.add_row("Critical (90%)", _format_tokens(policy.warning_threshold_90))

            console.print(table)

            if groups:
                console.print(f"\n[dim]Groups evaluated: {', '.join(groups)}[/dim]")

            return 0

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to resolve policy: {e}[/red]")
            return 1


class QuotaUsageCommand(Command):
    """Show current usage against quota limits for a user."""

    name = "quota usage"
    description = "Show current usage against quota limits"

    arguments = [
        argument("email", description="User email address"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option("groups", "g", description="Comma-separated list of groups", flag=False),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        email = self.argument("email")

        # Security: Validate email format before using as DynamoDB key
        if not _validate_email(email):
            console.print(f"[red]Invalid email format: {email}[/red]")
            return 1

        groups_str = self.option("groups")
        groups = [g.strip() for g in groups_str.split(",")] if groups_str else None

        try:
            manager = _get_quota_manager(profile)

            # Fetch actual usage from UserQuotaMetrics table
            usage_data = self._get_user_usage(profile, email)
            current_monthly_tokens = usage_data.get("total_tokens", 0)
            current_daily_tokens = usage_data.get("daily_tokens", 0)

            summary = manager.get_usage_summary(
                email=email,
                groups=groups,
                current_monthly_tokens=current_monthly_tokens,
                current_daily_tokens=current_daily_tokens,
            )

            console.print(
                Panel.fit(
                    f"[bold cyan]Usage Summary for {email}[/bold cyan]",
                    border_style="cyan",
                )
            )

            if summary["unlimited"]:
                console.print("[yellow]No quota policy applies - usage is unlimited[/yellow]")
                if current_monthly_tokens > 0:
                    console.print(f"\n[dim]Current usage: {_format_tokens(current_monthly_tokens)} tokens[/dim]")
                return 0

            console.print(f"[bold]Policy:[/bold] {summary['policy_type']}:{summary['policy_identifier']}")
            console.print(f"[bold]Enforcement:[/bold] {summary.get('enforcement_mode', 'alert')}")
            console.print()

            table = Table(box=box.SIMPLE)
            table.add_column("Metric")
            table.add_column("Current", justify="right")
            table.add_column("Limit", justify="right")
            table.add_column("Used %", justify="right")

            # Monthly tokens
            monthly_pct = summary["monthly_token_pct"]
            pct_color = "green" if monthly_pct < 80 else "yellow" if monthly_pct < 90 else "red"
            table.add_row(
                "Monthly Tokens",
                _format_tokens(summary["monthly_tokens"]),
                _format_tokens(summary["monthly_token_limit"]),
                f"[{pct_color}]{monthly_pct:.1f}%[/{pct_color}]",
            )

            # Daily tokens
            if summary["daily_token_limit"]:
                daily_pct = summary["daily_token_pct"]
                pct_color = "green" if daily_pct < 80 else "yellow" if daily_pct < 90 else "red"
                table.add_row(
                    "Daily Tokens",
                    _format_tokens(summary["daily_tokens"]),
                    _format_tokens(summary["daily_token_limit"]),
                    f"[{pct_color}]{daily_pct:.1f}%[/{pct_color}]",
                )

            console.print(table)

            # Show warning if near/over quota
            if monthly_pct >= 100:
                console.print(
                    "\n[red bold]QUOTA EXCEEDED[/red bold] - Access may be blocked depending on enforcement mode."
                )
            elif monthly_pct >= 90:
                console.print("\n[yellow]Warning: Approaching quota limit (90%+)[/yellow]")

            return 0

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to get usage: {e}[/red]")
            return 1

    def _get_user_usage(self, profile: Profile, email: str) -> dict:
        """Fetch user usage data from UserQuotaMetrics table.

        Args:
            profile: Configuration profile with table info.
            email: User email address.

        Returns:
            Dictionary with usage data (total_tokens, daily_tokens, etc.).
        """
        from datetime import datetime, timedelta, timezone

        import boto3

        # Get the metrics table name from profile or derive it
        table_name = profile.user_quota_metrics_table
        if not table_name:
            # Derive from stack naming convention
            quota_stack = profile.stack_names.get("quota", "")
            if quota_stack:
                table_name = f"{quota_stack}-UserQuotaMetrics"
            else:
                # Default fallback
                table_name = "UserQuotaMetrics"

        try:
            dynamodb = boto3.resource("dynamodb", region_name=profile.aws_region)
            table = dynamodb.Table(table_name)

            # Use UTC+8 to match Bedrock usage pipeline partitioning
            utc8 = timezone(timedelta(hours=8))
            now = datetime.now(utc8)
            current_month = now.strftime("%Y-%m")
            current_date = now.strftime("%Y-%m-%d")
            pk = f"USER#{email}"

            # Fetch monthly Bedrock usage, daily Bedrock usage, and PROFILE
            month_resp = table.get_item(Key={"pk": pk, "sk": f"MONTH#{current_month}#BEDROCK"})
            day_resp = table.get_item(Key={"pk": pk, "sk": f"DAY#{current_date}#BEDROCK"})
            profile_resp = table.get_item(Key={"pk": pk, "sk": "PROFILE"})

            month_item = month_resp.get("Item", {})
            day_item = day_resp.get("Item", {})
            profile_item = profile_resp.get("Item", {})

            cache_read = float(month_item.get("cache_read_tokens", 0))
            cache_write = float(month_item.get("cache_write_tokens", 0))

            return {
                "total_tokens": int(month_item.get("total_tokens", 0)),
                "daily_tokens": int(day_item.get("total_tokens", 0)),
                "input_tokens": int(month_item.get("input_tokens", 0)),
                "output_tokens": int(month_item.get("output_tokens", 0)),
                "cache_tokens": int(cache_read + cache_write),
                "estimated_cost": month_item.get("estimated_cost", "0"),
                "groups": profile_item.get("groups", []),
            }

        except Exception:
            # Return empty data if table doesn't exist or query fails
            return {}


class QuotaUnblockCommand(Command):
    """Temporarily unblock a user who has exceeded their quota."""

    name = "quota unblock"
    description = "Temporarily unblock a user who has exceeded quota"

    arguments = [
        argument("email", description="User email address to unblock"),
    ]

    options = [
        option("profile", description="Configuration profile", flag=False, default=None),
        option(
            "duration",
            "d",
            description="Unblock duration: 24h, 7d, or until-reset (default: 24h)",
            flag=False,
            default="24h",
        ),
        option("reason", "r", description="Reason for unblock (optional)", flag=False),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        email = self.argument("email")
        duration = self.option("duration")
        reason = self.option("reason")

        # Security: Validate email format before using as DynamoDB key
        if not _validate_email(email):
            console.print(f"[red]Invalid email format: {email}[/red]")
            return 1

        # Calculate expiry time
        now = datetime.now(timezone.utc)
        expires_at = self._calculate_expiry(now, duration)

        if expires_at is None:
            console.print(
                f"[red]Invalid duration: {duration}. Use '24h', '{MAX_UNBLOCK_DAYS}d' (max), or 'until-reset'.[/red]"
            )
            return 1

        # Get the UserQuotaMetrics table name
        quota_table_name = profile.user_quota_metrics_table or "UserQuotaMetrics"

        try:
            # Write unblock record to DynamoDB
            dynamodb = boto3.resource("dynamodb", region_name=profile.aws_region)
            table = dynamodb.Table(quota_table_name)

            # Security: Get actual caller identity for audit trail
            caller_identity = _get_caller_identity()

            # Create unblock record
            pk = f"USER#{email}"
            sk = "UNBLOCK#CURRENT"

            item = {
                "pk": pk,
                "sk": sk,
                "email": email,
                "unblocked_at": now.isoformat(),
                "unblocked_by": caller_identity,
                "expires_at": expires_at.isoformat(),
                "duration_type": duration,
                "ttl": int(expires_at.timestamp()),  # DynamoDB TTL for auto-cleanup
            }

            if reason:
                item["reason"] = reason

            table.put_item(Item=item)

            console.print(
                Panel.fit(
                    f"[bold green]Unblocked {email}[/bold green]",
                    border_style="green",
                )
            )

            console.print(f"[bold]Email:[/bold] {email}")
            console.print(f"[bold]Duration:[/bold] {duration}")
            console.print(f"[bold]Expires at:[/bold] {expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if reason:
                console.print(f"[bold]Reason:[/bold] {reason}")

            console.print("\n[dim]The user can now access Claude Code until the unblock expires.[/dim]")
            console.print(f"[dim]To remove the unblock early, delete the record from {quota_table_name}.[/dim]")

            return 0

        except Exception as e:
            console.print(f"[red]Failed to create unblock record: {e}[/red]")
            return 1

    def _calculate_expiry(self, now: datetime, duration: str) -> datetime | None:
        """Calculate expiry time based on duration string.

        Args:
            now: Current time.
            duration: Duration string ('24h', '7d', 'until-reset').

        Returns:
            Expiry datetime or None if invalid duration or exceeds maximum.
        """
        duration = duration.lower().strip()
        max_duration = timedelta(days=MAX_UNBLOCK_DAYS)

        if duration == "24h":
            return now + timedelta(hours=24)
        elif duration == "7d":
            return now + timedelta(days=7)
        elif duration == "until-reset":
            # Until end of current month (UTC midnight on 1st of next month)
            if now.month == 12:
                next_month = now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            else:
                next_month = now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
            # Security: Cap at maximum duration even for until-reset
            if (next_month - now) > max_duration:
                return now + max_duration
            return next_month
        else:
            # Try to parse as hours (e.g., "48h")
            if duration.endswith("h"):
                try:
                    hours = int(duration[:-1])
                    # Security: Enforce maximum duration
                    if hours > MAX_UNBLOCK_DAYS * 24:
                        return None
                    return now + timedelta(hours=hours)
                except ValueError:
                    pass
            # Try to parse as days (e.g., "3d")
            elif duration.endswith("d"):
                try:
                    days = int(duration[:-1])
                    # Security: Enforce maximum duration
                    if days > MAX_UNBLOCK_DAYS:
                        return None
                    return now + timedelta(days=days)
                except ValueError:
                    pass

        return None


class QuotaExportCommand(Command):
    """Export quota policies to a file."""

    name = "quota export"
    description = "Export quota policies to JSON or CSV file"

    arguments = [
        argument("file?", description="Output file path (.json or .csv)"),
    ]

    options = [
        option("profile", "p", description="Configuration profile", flag=False, default=None),
        option("type", "t", description="Filter by policy type (user, group, default)", flag=False),
        option("stdout", None, description="Output to stdout instead of file", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        file_path = self.argument("file")
        to_stdout = self.option("stdout")

        if not file_path and not to_stdout:
            console.print("[red]Either provide a file path or use --stdout[/red]")
            return 1

        policy_type = None
        type_filter = self.option("type")
        if type_filter:
            try:
                policy_type = PolicyType(type_filter.lower())
            except ValueError:
                console.print(f"[red]Invalid policy type: {type_filter}. Use 'user', 'group', 'default', or 'org'.[/red]")
                return 1

        try:
            manager = _get_quota_manager(profile)
            policies = manager.export_policies(policy_type)

            if not policies:
                console.print("[yellow]No quota policies found to export.[/yellow]")
                return 0

            # Determine output format
            if file_path:
                file_ext = Path(file_path).suffix.lower()
            else:
                file_ext = ".json"  # Default to JSON for stdout

            if file_ext == ".csv":
                output = self._format_csv(policies)
            else:
                output = self._format_json(policies)

            if to_stdout:
                print(output)
            else:
                with open(file_path, "w") as f:
                    f.write(output)
                console.print(f"[green]Exported {len(policies)} policies to {file_path}[/green]")

            return 0

        except QuotaPolicyError as e:
            console.print(f"[red]Failed to export policies: {e}[/red]")
            return 1

    def _format_json(self, policies: list[dict]) -> str:
        """Format policies as JSON."""
        export_data = {
            "version": "1.0",
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "policies": policies,
        }
        return json.dumps(export_data, indent=2)

    def _format_csv(self, policies: list[dict]) -> str:
        """Format policies as CSV."""
        from io import StringIO

        output = StringIO()
        fieldnames = ["type", "identifier", "monthly_token_limit", "daily_token_limit", "monthly_cost_limit", "daily_cost_limit", "enforcement_mode", "enabled"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for policy in policies:
            writer.writerow(policy)
        return output.getvalue()


class QuotaImportCommand(Command):
    """Import quota policies from a file."""

    name = "quota import"
    description = "Import quota policies from JSON or CSV file"

    arguments = [
        argument("file", description="Input file path (.json or .csv)"),
    ]

    options = [
        option("profile", "p", description="Configuration profile", flag=False, default=None),
        option("type", "t", description="Import only specific type (user, group, default)", flag=False),
        option("skip-existing", None, description="Skip policies that already exist", flag=True),
        option("update", None, description="Update existing policies (upsert)", flag=True),
        option("dry-run", None, description="Preview changes without applying", flag=True),
        option("auto-daily", None, description="Auto-calculate daily limits if missing", flag=True),
        option("burst", None, description="Burst buffer % for auto-daily (default: 10)", flag=False, default="10"),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        file_path = self.argument("file")
        skip_existing = self.option("skip-existing")
        update_existing = self.option("update")
        dry_run = self.option("dry-run")
        auto_daily = self.option("auto-daily")

        try:
            burst_buffer = int(self.option("burst"))
            if burst_buffer < 0 or burst_buffer > 100:
                console.print("[red]Burst buffer must be between 0 and 100[/red]")
                return 1
        except ValueError:
            console.print(f"[red]Invalid burst buffer: {self.option('burst')}[/red]")
            return 1

        # Filter by type if specified
        type_filter = self.option("type")
        filter_policy_type = None
        if type_filter:
            try:
                filter_policy_type = PolicyType(type_filter.lower())
            except ValueError:
                console.print(f"[red]Invalid policy type: {type_filter}. Use 'user', 'group', 'default', or 'org'.[/red]")
                return 1

        # Check file exists
        if not Path(file_path).exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            return 1

        try:
            # Parse file
            policies = self._parse_file(file_path)

            if not policies:
                console.print("[yellow]No policies found in file.[/yellow]")
                return 0

            # Apply type filter if specified
            if filter_policy_type:
                policies = [p for p in policies if p.get("type", "").lower() == filter_policy_type.value]
                if not policies:
                    console.print(f"[yellow]No policies of type '{filter_policy_type.value}' found in file.[/yellow]")
                    return 0

            if dry_run:
                console.print(
                    Panel.fit(
                        "[bold cyan]Dry Run - No changes will be made[/bold cyan]",
                        border_style="cyan",
                    )
                )

            manager = _get_quota_manager(profile)
            results = manager.bulk_import_policies(
                policies=policies,
                skip_existing=skip_existing,
                update_existing=update_existing,
                auto_daily=auto_daily,
                burst_buffer_percent=burst_buffer,
                dry_run=dry_run,
            )

            # Display results
            self._display_results(console, results, dry_run)

            # Return error code if there were errors
            if results["errors"]:
                return 1

            return 0

        except (json.JSONDecodeError, csv.Error) as e:
            console.print(f"[red]Failed to parse file: {e}[/red]")
            return 1
        except QuotaPolicyError as e:
            console.print(f"[red]Failed to import policies: {e}[/red]")
            return 1

    def _parse_file(self, file_path: str) -> list[dict]:
        """Parse policies from JSON or CSV file.

        Args:
            file_path: Path to file.

        Returns:
            List of policy dictionaries.
        """
        file_ext = Path(file_path).suffix.lower()

        with open(file_path) as f:
            if file_ext == ".csv":
                reader = csv.DictReader(f)
                return list(reader)
            else:
                data = json.load(f)
                # Support both flat array and wrapped format
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "policies" in data:
                    return data["policies"]
                else:
                    raise ValueError("Invalid JSON format. Expected array or object with 'policies' key.")

    def _display_results(self, console: Console, results: dict, dry_run: bool) -> None:
        """Display import results.

        Args:
            console: Rich console.
            results: Import results dictionary.
            dry_run: Whether this was a dry run.
        """
        action_prefix = "Would " if dry_run else ""

        # Show details
        for detail in results["details"]:
            if detail["action"] == "create":
                console.print(
                    f"[green]✓ {action_prefix}Created: {detail['identifier']} "
                    f"({detail['type']}) - {detail.get('monthly_limit', '')}[/green]"
                )
            elif detail["action"] == "update":
                console.print(
                    f"[yellow]✓ {action_prefix}Updated: {detail['identifier']} "
                    f"({detail['type']}) - {detail.get('monthly_limit', '')}[/yellow]"
                )
            elif detail["action"] == "skip":
                console.print(
                    f"[dim]⚠ Skipped: {detail['identifier']} ({detail['type']}) - {detail.get('reason', '')}[/dim]"
                )

        # Show errors
        for error in results["errors"]:
            if "identifier" in error:
                console.print(
                    f"[red]✗ Error: {error['identifier']} ({error.get('type', '?')}) - {error['error']}[/red]"
                )
            else:
                console.print(f"[red]✗ {error['error']}[/red]")

        # Show summary
        console.print()
        summary_title = "[bold]Dry Run Summary[/bold]" if dry_run else "[bold]Import Summary[/bold]"
        console.print(summary_title)
        console.print(f"  Created: {results['created']}")
        console.print(f"  Updated: {results['updated']}")
        console.print(f"  Skipped: {results['skipped']}")
        console.print(f"  Errors:  {len(results['errors'])}")


# Default pricing for Claude models on Bedrock (per 1M tokens in USD)
# Source: https://docs.anthropic.com/en/docs/about-claude/pricing
# Note: 4.6+ models use shorter IDs without :0 suffix (e.g. anthropic.claude-opus-4-7-v1)
# Note: cache_write_per_1m is 5-minute ephemeral cache (1.25x input).
# cache_write_1h_per_1m is 1-hour ephemeral cache (2x input).
# The response body provides cache_creation.ephemeral_5m/1h breakdown.
DEFAULT_BEDROCK_PRICING = {
    # Claude 4.7 (no :0 suffix)
    "anthropic.claude-opus-4-7-v1": {
        "input_per_1m": "5.00", "output_per_1m": "25.00",
        "cache_read_per_1m": "0.50", "cache_write_per_1m": "6.25", "cache_write_1h_per_1m": "10.00",
    },
    # Claude 4.6 (no :0 suffix)
    "anthropic.claude-opus-4-6-v1": {
        "input_per_1m": "5.00", "output_per_1m": "25.00",
        "cache_read_per_1m": "0.50", "cache_write_per_1m": "6.25", "cache_write_1h_per_1m": "10.00",
    },
    "anthropic.claude-sonnet-4-6": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
    # Claude 4.5
    "anthropic.claude-opus-4-5-20251101-v1:0": {
        "input_per_1m": "5.00", "output_per_1m": "25.00",
        "cache_read_per_1m": "0.50", "cache_write_per_1m": "6.25", "cache_write_1h_per_1m": "10.00",
    },
    "anthropic.claude-sonnet-4-5-20250929-v1:0": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
    # Claude 4.1
    "anthropic.claude-opus-4-1-20250805-v1:0": {
        "input_per_1m": "15.00", "output_per_1m": "75.00",
        "cache_read_per_1m": "1.50", "cache_write_per_1m": "18.75", "cache_write_1h_per_1m": "30.00",
    },
    # Claude 4
    "anthropic.claude-sonnet-4-20250514-v1:0": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
    "anthropic.claude-opus-4-20250514-v1:0": {
        "input_per_1m": "15.00", "output_per_1m": "75.00",
        "cache_read_per_1m": "1.50", "cache_write_per_1m": "18.75", "cache_write_1h_per_1m": "30.00",
    },
    # Claude Haiku 4.5
    "anthropic.claude-haiku-4-5-20251001-v1:0": {
        "input_per_1m": "1.00", "output_per_1m": "5.00",
        "cache_read_per_1m": "0.10", "cache_write_per_1m": "1.25", "cache_write_1h_per_1m": "2.00",
    },
    # Claude 3.x
    "anthropic.claude-3-7-sonnet-20250219-v1:0": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
    "anthropic.claude-3-5-sonnet-20241022-v2:0": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
    "anthropic.claude-3-5-haiku-20241022-v1:0": {
        "input_per_1m": "0.80", "output_per_1m": "4.00",
        "cache_read_per_1m": "0.08", "cache_write_per_1m": "1.00", "cache_write_1h_per_1m": "1.60",
    },
    "DEFAULT": {
        "input_per_1m": "3.00", "output_per_1m": "15.00",
        "cache_read_per_1m": "0.30", "cache_write_per_1m": "3.75", "cache_write_1h_per_1m": "6.00",
    },
}


class QuotaSetPricingCommand(Command):
    """Populate the BedrockPricing DynamoDB table with model prices."""

    name = "quota set-pricing"
    description = "Set model pricing for cost-based quotas"

    options = [
        option("profile", "p", description="Configuration profile", flag=False, default=None),
        option("table", "t", description="Pricing table name (default: BedrockPricing)", flag=False, default="BedrockPricing"),
        option("model", None, description="Set pricing for a specific model ID", flag=False),
        option("input-price", None, description="Input price per 1M tokens (e.g., 3.00)", flag=False),
        option("output-price", None, description="Output price per 1M tokens (e.g., 15.00)", flag=False),
        option("cache-read-price", None, description="Cache read price per 1M tokens", flag=False),
        option("cache-write-price", None, description="Cache write price per 1M tokens", flag=False),
        option("defaults", None, description="Load default Bedrock pricing for Claude models", flag=True),
        option("list", "l", description="List current pricing", flag=True),
    ]

    def handle(self) -> int:
        """Execute the command."""
        console = Console()
        config = Config.load()
        profile_name = self.option("profile") or config.active_profile
        profile = config.get_profile(profile_name)

        if not profile:
            console.print(f"[red]Profile '{profile_name}' not found.[/red]")
            return 1

        table_name = self.option("table")
        dynamodb = boto3.resource("dynamodb", region_name=profile.aws_region)
        pricing_table = dynamodb.Table(table_name)

        # List current pricing
        if self.option("list"):
            return self._list_pricing(console, pricing_table)

        # Load defaults
        if self.option("defaults"):
            return self._load_defaults(console, pricing_table)

        # Set pricing for a specific model
        model_id = self.option("model")
        if not model_id:
            console.print("[red]Specify --model to set pricing for a model, or --defaults to load default prices[/red]")
            return 1

        input_price = self.option("input-price")
        output_price = self.option("output-price")

        if not input_price or not output_price:
            console.print("[red]--input-price and --output-price are required[/red]")
            return 1

        try:
            item = {
                "model_id": model_id,
                "input_per_1m": Decimal(input_price),
                "output_per_1m": Decimal(output_price),
                "cache_read_per_1m": Decimal(self.option("cache-read-price") or "0"),
                "cache_write_per_1m": Decimal(self.option("cache-write-price") or "0"),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            pricing_table.put_item(Item=item)
            console.print(f"[green]Set pricing for {model_id}[/green]")
            console.print(f"  Input: ${input_price}/1M  Output: ${output_price}/1M")
            return 0
        except Exception as e:
            console.print(f"[red]Failed to set pricing: {e}[/red]")
            return 1

    def _load_defaults(self, console: Console, pricing_table) -> int:
        """Load default pricing for all known Claude models."""
        try:
            count = 0
            for model_id, prices in DEFAULT_BEDROCK_PRICING.items():
                item = {
                    "model_id": model_id,
                    "input_per_1m": Decimal(prices["input_per_1m"]),
                    "output_per_1m": Decimal(prices["output_per_1m"]),
                    "cache_read_per_1m": Decimal(prices["cache_read_per_1m"]),
                    "cache_write_per_1m": Decimal(prices["cache_write_per_1m"]),
                    "cache_write_1h_per_1m": Decimal(prices.get("cache_write_1h_per_1m", "0")),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                pricing_table.put_item(Item=item)
                count += 1

            console.print(f"[green]Loaded default pricing for {count} models[/green]")
            return 0
        except Exception as e:
            console.print(f"[red]Failed to load defaults: {e}[/red]")
            return 1

    def _list_pricing(self, console: Console, pricing_table) -> int:
        """List current model pricing."""
        try:
            response = pricing_table.scan()
            items = response.get("Items", [])

            if not items:
                console.print("[yellow]No pricing data found. Use --defaults to load default prices.[/yellow]")
                return 0

            console.print(
                Panel.fit(
                    "[bold cyan]Bedrock Model Pricing[/bold cyan]",
                    border_style="cyan",
                )
            )

            table = Table(box=box.SIMPLE)
            table.add_column("Model ID")
            table.add_column("Input/1M", justify="right")
            table.add_column("Output/1M", justify="right")
            table.add_column("Cache Read/1M", justify="right")
            table.add_column("CW 5m/1M", justify="right")
            table.add_column("CW 1h/1M", justify="right")

            for item in sorted(items, key=lambda x: x.get("model_id", "")):
                table.add_row(
                    item.get("model_id", ""),
                    f"${item.get('input_per_1m', 0)}",
                    f"${item.get('output_per_1m', 0)}",
                    f"${item.get('cache_read_per_1m', 0)}",
                    f"${item.get('cache_write_per_1m', 0)}",
                    f"${item.get('cache_write_1h_per_1m', 0)}",
                )

            console.print(table)
            return 0
        except Exception as e:
            console.print(f"[red]Failed to list pricing: {e}[/red]")
            return 1

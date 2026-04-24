#!/usr/bin/env python3
# ABOUTME: AWS Credential Provider for OIDC authentication and Cognito Identity Pool federation
# ABOUTME: Supports multiple OIDC providers including Okta and Azure AD for Bedrock access
"""
AWS Credential Provider for OIDC + Cognito Identity Pool
Supports multiple OIDC providers for Bedrock access
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import sys
import threading
import time
import traceback
import webbrowser
import logging
import logging.handlers
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import boto3
import jwt
import keyring
import requests
from botocore import UNSIGNED
from botocore.config import Config

# No longer using file locks - using port-based locking instead

__version__ = "1.0.0"


class BrowserAuthInProgressError(Exception):
    """Raised when another credential-process already has a browser auth window open."""


class TVMUnreachableError(Exception):
    """Raised when the TVM endpoint is unreachable over the network (timeout / DNS / TLS)."""


class TVMAuthRejectedError(Exception):
    """Raised when TVM returns 401 (id_token rejected by API Gateway)."""


class TVMAccessDeniedError(Exception):
    """Raised when TVM returns 403 (non-quota policy denial)."""


class TVMServiceError(Exception):
    """Raised when TVM returns 5xx or malformed 200 (service-side problem)."""


class QuotaExceededError(Exception):
    """Raised when TVM returns 429 due to quota limits."""

    # Map TVM reason codes to user-friendly templates (label, prefix, is_cost)
    _REASON_LABELS = {
        "daily_cost_exceeded": ("日额度（金额）", "$", True),
        "monthly_cost_exceeded": ("月额度（金额）", "$", True),
        "daily_tokens_exceeded": ("日额度（tokens）", "", False),
        "monthly_tokens_exceeded": ("月额度（tokens）", "", False),
    }

    def __init__(self, reason: str, usage=None, limit=None, raw_message: str = ""):
        self.reason = reason
        self.usage = usage
        self.limit = limit
        self.raw_message = raw_message
        super().__init__(self._format())

    def _format(self) -> str:
        label, prefix, is_cost = self._REASON_LABELS.get(
            self.reason, (self.reason, "", False)
        )
        if self.usage is not None and self.limit is not None:
            if is_cost:
                used = f"{prefix}{self.usage:,.2f}"
                cap = f"{prefix}{self.limit:,.2f}"
            else:
                used = f"{int(self.usage):,}"
                cap = f"{int(self.limit):,}"
            return (
                f"已超出{label}：已使用 {used}，额度上限 {cap}。"
                "请等待下个周期重置，或联系管理员。"
            )
        return self.raw_message or f"已超出额度（{self.reason}）"

# OIDC Provider Configurations
PROVIDER_CONFIGS = {
    "okta": {
        "name": "Okta",
        "authorize_endpoint": "/oauth2/v1/authorize",
        "token_endpoint": "/oauth2/v1/token",
        "scopes": "openid profile email",
        "response_type": "code",
        "response_mode": "query",
    },
    "auth0": {
        "name": "Auth0",
        "authorize_endpoint": "/authorize",
        "token_endpoint": "/oauth/token",
        "scopes": "openid profile email",
        "response_type": "code",
        "response_mode": "query",
    },
    "azure": {
        "name": "Azure AD",
        "authorize_endpoint": "/oauth2/v2.0/authorize",
        "token_endpoint": "/oauth2/v2.0/token",
        "scopes": "openid profile email",
        "response_type": "code",
        "response_mode": "query",
    },
    "cognito": {
        "name": "AWS Cognito User Pool",
        "authorize_endpoint": "/oauth2/authorize",
        "token_endpoint": "/oauth2/token",
        "scopes": "openid email",
        "response_type": "code",
        "response_mode": "query",
    },
}


class MultiProviderAuth:
    def __init__(self, profile=None):
        # Debug mode - set before loading config since _load_config may use _debug_print
        self.debug = os.getenv("COGNITO_AUTH_DEBUG", "").lower() in ("1", "true", "yes")

        # File logging - always enabled, writes to ~/claude-code-with-bedrock/logs/
        self._logger = None
        self._init_file_logging()

        try:
            # Load configuration from environment or config file
            # Auto-detect profile from config.json if not specified
            self.profile = profile or self._auto_detect_profile() or "ClaudeCode"
            self._log(f"profile={self.profile}")

            self.config = self._load_config()

            # Determine provider type from domain
            self.provider_type = self._determine_provider_type()

            # Fail clearly if provider type is unknown
            if self.provider_type not in PROVIDER_CONFIGS:
                raise ValueError(
                    f"Unknown provider type '{self.provider_type}'. "
                    f"Valid providers: {', '.join(PROVIDER_CONFIGS.keys())}"
                )
            self.provider_config = PROVIDER_CONFIGS[self.provider_type]

            # Default otel-helper integrity status (updated in run())
            self.otel_helper_status = "not-configured"

            # OAuth configuration
            self.redirect_port = int(os.getenv("REDIRECT_PORT", "8400"))
            self.redirect_uri = f"http://localhost:{self.redirect_port}/callback"

            # Initialize credential storage
            self._init_credential_storage()

            self._log(f"init OK provider={self.provider_type} federation={self.config.get('federation_type')} storage={self.config.get('credential_storage')}")
        except Exception as e:
            self._log(f"INIT FAILED: {e}")
            raise

    def _init_file_logging(self):
        """Initialize file-based logging to ~/claude-code-with-bedrock/logs/."""
        try:
            log_dir = Path.home() / "claude-code-with-bedrock" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "credential-process.log"
            handler = logging.handlers.TimedRotatingFileHandler(
                log_path, when="midnight", backupCount=3, utc=True,
            )
            fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
            fmt.converter = time.gmtime
            handler.setFormatter(fmt)
            self._logger = logging.getLogger("credential-process")
            self._logger.setLevel(logging.DEBUG)
            self._logger.addHandler(handler)
            self._log(f"--- session start (pid={os.getpid()}) ---")
            self._log(
                f"platform={platform.system()} release={platform.release()} "
                f"arch={platform.machine()} python={platform.python_version()}"
            )
        except Exception:
            self._logger = None  # Non-fatal: logging is best-effort

    def _log(self, message):
        """Write a timestamped message to the log file (always, regardless of debug mode)."""
        if self._logger:
            try:
                self._logger.info(message)
            except Exception:
                pass

    def _debug_print(self, message):
        """Print debug message to stderr if debug mode is enabled, and always log to file."""
        self._log(message)
        if self.debug:
            print(f"Debug: {message}", file=sys.stderr)

    def _auto_detect_profile(self):
        """Auto-detect profile name from config.json when only one profile exists."""
        try:
            # Try same directory as binary first (for testing)
            binary_dir = Path(__file__).parent if not getattr(sys, "frozen", False) else Path(sys.executable).parent
            config_path = binary_dir / "config.json"

            # Fall back to installed location
            if not config_path.exists():
                config_path = Path.home() / "claude-code-with-bedrock" / "config.json"

            if not config_path.exists():
                return None

            with open(config_path) as f:
                file_config = json.load(f)

            # New format with "profiles" key
            if "profiles" in file_config:
                profiles = list(file_config["profiles"].keys())
            else:
                # Old format: profile names are top-level keys
                profiles = list(file_config.keys())

            if len(profiles) == 1:
                self._debug_print(f"Auto-detected profile: {profiles[0]}")
                return profiles[0]
            elif len(profiles) > 1:
                self._debug_print(f"Multiple profiles found: {profiles}. Use --profile to specify.")
                return None
            return None
        except Exception as e:
            self._debug_print(f"Could not auto-detect profile: {e}")
            return None

    def _load_config(self):
        """Load configuration from config.json.

        Priority:
        1. Same directory as the binary (for testing dist/ packages)
        2. ~/claude-code-with-bedrock/config.json (for installed packages)
        """
        # Try same directory as binary first (for testing)
        binary_dir = Path(__file__).parent if not getattr(sys, "frozen", False) else Path(sys.executable).parent
        config_path = binary_dir / "config.json"

        # Fall back to installed location
        if not config_path.exists():
            config_path = Path.home() / "claude-code-with-bedrock" / "config.json"

        if not config_path.exists():
            raise ValueError(
                f"Configuration file not found in {binary_dir} or {Path.home() / 'claude-code-with-bedrock'}"
            )

        with open(config_path) as f:
            file_config = json.load(f)

        # Handle new config format with profiles
        if "profiles" in file_config:
            # New format
            profiles = file_config.get("profiles", {})
            if self.profile not in profiles:
                raise ValueError(f"Profile '{self.profile}' not found in configuration")
            profile_config = profiles[self.profile]

            # Map new field names to expected ones
            profile_config["provider_domain"] = profile_config.get("provider_domain", profile_config.get("okta_domain"))
            profile_config["client_id"] = profile_config.get("client_id", profile_config.get("okta_client_id"))

            # Handle both identity_pool_id and identity_pool_name for compatibility
            # BUT: Don't convert identity_pool_name if federated_role_arn is present (Direct STS mode)
            if "identity_pool_name" in profile_config and "federated_role_arn" not in profile_config:
                profile_config["identity_pool_id"] = profile_config["identity_pool_name"]

            profile_config["credential_storage"] = profile_config.get("credential_storage", "session")
        else:
            # Old format for backward compatibility
            profile_config = file_config.get(self.profile, {})

        # Auto-detect federation type based on configuration
        self._detect_federation_type(profile_config)

        # Validate required configuration based on federation type
        if profile_config.get("federation_type") == "direct":
            required = ["provider_domain", "client_id", "federated_role_arn"]
        else:
            required = ["provider_domain", "client_id", "identity_pool_id"]

        missing = [k for k in required if not profile_config.get(k)]
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")

        # Set defaults
        profile_config.setdefault("aws_region", "us-east-1")
        profile_config.setdefault("provider_type", "auto")
        profile_config.setdefault("credential_storage", "session")
        profile_config.setdefault(
            "max_session_duration", 43200 if profile_config.get("federation_type") == "direct" else 28800
        )

        return profile_config

    def _detect_federation_type(self, config):
        """Auto-detect whether to use Cognito Identity Pool or direct STS federation"""
        # Explicit federation type takes precedence
        if "federation_type" in config:
            return

        # Auto-detect based on available configuration
        if "federated_role_arn" in config:
            config["federation_type"] = "direct"
            self._debug_print("Detected Direct STS federation mode (federated_role_arn found)")
        elif "identity_pool_id" in config or "identity_pool_name" in config:
            config["federation_type"] = "cognito"
            self._debug_print("Detected Cognito Identity Pool federation mode")
        else:
            # Default to cognito for backward compatibility
            config["federation_type"] = "cognito"
            self._debug_print("Defaulting to Cognito Identity Pool federation mode")

    def _determine_provider_type(self):
        """Determine provider type from domain"""
        domain = self.config["provider_domain"].lower()

        # If provider_type is explicitly set and it's NOT 'auto', use it
        provider_type = self.config.get("provider_type", "auto")
        if provider_type != "auto":
            return provider_type

        # Secure provider detection using proper URL parsing
        if not domain:
            # Fail with clear error for unknown providers
            raise ValueError(
                "Unable to auto-detect provider type for empty domain. "
                "Known providers: Okta, Auth0, Microsoft/Azure, AWS Cognito User Pool. "
                "Please check your provider domain configuration."
            )

        # Handle both full URLs and domain-only inputs
        url_to_parse = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"

        try:
            parsed = urlparse(url_to_parse)
            hostname = parsed.hostname

            if not hostname:
                # Fail with clear error for unknown providers
                raise ValueError(
                    f"Unable to auto-detect provider type for domain '{domain}'. "
                    f"Known providers: Okta, Auth0, Microsoft/Azure, AWS Cognito User Pool. "
                    f"Please check your provider domain configuration."
                )

            hostname_lower = hostname.lower()

            # Check for exact domain match or subdomain match
            # Using endswith with leading dot prevents bypass attacks
            if hostname_lower.endswith(".okta.com") or hostname_lower == "okta.com":
                return "okta"
            elif hostname_lower.endswith(".auth0.com") or hostname_lower == "auth0.com":
                return "auth0"
            elif hostname_lower.endswith(".microsoftonline.com") or hostname_lower == "microsoftonline.com":
                return "azure"
            elif hostname_lower.endswith(".windows.net") or hostname_lower == "windows.net":
                return "azure"
            elif hostname_lower.endswith(".amazoncognito.com") or hostname_lower == "amazoncognito.com":
                # Cognito User Pool domain format: my-domain.auth.{region}.amazoncognito.com
                return "cognito"
            else:
                # Fail with clear error for unknown providers
                raise ValueError(
                    f"Unable to auto-detect provider type for domain '{domain}'. "
                    f"Known providers: Okta, Auth0, Microsoft/Azure, AWS Cognito User Pool. "
                    f"Please check your provider domain configuration."
                )
        except ValueError:
            raise
        except Exception as e:
            # Fail with clear error for unknown providers
            raise ValueError(f"Unable to auto-detect provider type for domain '{domain}': {e}") from e

    def _init_credential_storage(self):
        """Initialize secure credential storage"""
        # Check storage method from config
        self.credential_storage = self.config.get("credential_storage", "session")

        if self.credential_storage == "session":
            # Session-based storage uses temporary files
            self.cache_dir = Path.home() / "claude-code-with-bedrock" / "cache"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        # For keyring, no directory setup needed

    def get_cached_credentials(self):
        """Retrieve valid credentials from configured storage"""
        if self.credential_storage == "keyring":
            try:
                # On Windows, credentials are split into multiple entries due to size limits
                if platform.system() == "Windows":
                    # Retrieve split credentials
                    keys_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-keys")
                    token1 = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-token1")
                    token2 = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-token2")
                    meta_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-meta")

                    if not all([keys_json, token1, token2, meta_json]):
                        missing = [n for n, v in [("keys", keys_json), ("token1", token1),
                                                   ("token2", token2), ("meta", meta_json)] if not v]
                        self._log(f"cache miss: storage=keyring reason=partial_windows_entries missing={','.join(missing)}")
                        return None
                    assert keys_json is not None and token1 is not None and token2 is not None and meta_json is not None

                    # Reconstruct credentials
                    keys = json.loads(keys_json)
                    meta = json.loads(meta_json)

                    creds = {
                        "Version": meta["Version"],
                        "AccessKeyId": keys["AccessKeyId"],
                        "SecretAccessKey": keys["SecretAccessKey"],
                        "SessionToken": token1 + token2,
                        "Expiration": meta["Expiration"],
                    }
                else:
                    # Non-Windows: single entry storage
                    creds_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-credentials")

                    if not creds_json:
                        self._log("cache miss: storage=keyring reason=entry_not_found")
                        return None

                    creds = json.loads(creds_json)

                # Check for dummy/cleared credentials first
                # These are set when credentials are cleared to maintain keychain permissions
                if creds.get("AccessKeyId") == "EXPIRED":
                    self._debug_print("cache miss: storage=keyring reason=dummy_expired")
                    return None

                # Validate expiration for real credentials
                exp_str = creds.get("Expiration")
                if not exp_str:
                    self._log("cache miss: storage=keyring reason=missing_expiration_field")
                    return None
                exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                ttl = int((exp_time - now).total_seconds())

                # Use credentials if they expire in more than 30 seconds
                if ttl > 30:
                    self._log(f"cache hit: storage=keyring ttl={ttl}s")
                    return creds
                self._log(f"cache miss: storage=keyring reason=expired ttl={ttl}s")
                return None

            except Exception as e:
                self._log(f"cache miss: storage=keyring reason=exception err={e}")
                return None
        else:
            # Session storage uses ~/.aws/credentials file
            creds_path = Path.home() / ".aws" / "credentials"
            credentials = self.read_from_credentials_file(self.profile)

            if not credentials:
                self._log(f"cache miss: storage=session reason=profile_not_found path={creds_path} exists={creds_path.exists()}")
                return None

            # Check for dummy/cleared credentials first
            if credentials.get("AccessKeyId") == "EXPIRED":
                self._debug_print("cache miss: storage=session reason=dummy_expired")
                return None

            # Validate expiration
            exp_str = credentials.get("Expiration")
            if not exp_str:
                self._log("cache miss: storage=session reason=missing_expiration_field")
                return None
            exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            ttl = int((exp_time - now).total_seconds())

            # Use credentials if they expire in more than 30 seconds
            if ttl > 30:
                self._log(f"cache hit: storage=session ttl={ttl}s")
                return credentials
            self._log(f"cache miss: storage=session reason=expired ttl={ttl}s")
            return None

    def save_credentials(self, credentials):
        """Save credentials to configured storage"""
        if self.credential_storage == "keyring":
            try:
                # On Windows, split credentials into multiple entries due to size limits
                # Windows Credential Manager has a 2560 byte limit, but uses UTF-16LE encoding
                if platform.system() == "Windows":
                    # Split the SessionToken in half
                    token = credentials["SessionToken"]
                    mid = len(token) // 2

                    # Store as 4 separate entries
                    keyring.set_password(
                        "claude-code-with-bedrock",
                        f"{self.profile}-keys",
                        json.dumps(
                            {
                                "AccessKeyId": credentials["AccessKeyId"],
                                "SecretAccessKey": credentials["SecretAccessKey"],
                            }
                        ),
                    )
                    keyring.set_password("claude-code-with-bedrock", f"{self.profile}-token1", token[:mid])
                    keyring.set_password("claude-code-with-bedrock", f"{self.profile}-token2", token[mid:])
                    keyring.set_password(
                        "claude-code-with-bedrock",
                        f"{self.profile}-meta",
                        json.dumps({"Version": credentials["Version"], "Expiration": credentials["Expiration"]}),
                    )
                else:
                    # Non-Windows: store as single entry
                    keyring.set_password(
                        "claude-code-with-bedrock", f"{self.profile}-credentials", json.dumps(credentials)
                    )
            except Exception as e:
                self._debug_print(f"Error saving credentials to keyring: {e}")
                raise Exception(f"Failed to save credentials to keyring: {str(e)}") from e
        else:
            # Session storage uses ~/.aws/credentials file
            self.save_to_credentials_file(credentials, self.profile)

    def clear_cached_credentials(self):
        """Clear all cached credentials for this profile"""
        cleared_items = []

        # Clear from keyring by replacing with expired credentials
        # This maintains keychain access permissions on macOS
        try:
            if platform.system() == "Windows":
                # On Windows, we have 4 separate entries to clear
                entries_to_clear = [
                    f"{self.profile}-keys",
                    f"{self.profile}-token1",
                    f"{self.profile}-token2",
                    f"{self.profile}-meta",
                ]

                for entry in entries_to_clear:
                    if keyring.get_password("claude-code-with-bedrock", entry):
                        # Replace with expired dummy data
                        if "keys" in entry:
                            expired_data = json.dumps({"AccessKeyId": "EXPIRED", "SecretAccessKey": "EXPIRED"})
                        elif "token" in entry:
                            expired_data = "EXPIRED"
                        elif "meta" in entry:
                            expired_data = json.dumps({"Version": 1, "Expiration": "2000-01-01T00:00:00Z"})
                        else:
                            expired_data = "EXPIRED"

                        keyring.set_password("claude-code-with-bedrock", entry, expired_data)

                cleared_items.append("keyring credentials (Windows)")
            else:
                # Non-Windows: single entry storage
                if keyring.get_password("claude-code-with-bedrock", f"{self.profile}-credentials"):
                    # Replace with expired dummy credential instead of deleting
                    # This prevents macOS from asking for "Always Allow" again
                    expired_credential = json.dumps(
                        {
                            "Version": 1,
                            "AccessKeyId": "EXPIRED",
                            "SecretAccessKey": "EXPIRED",
                            "SessionToken": "EXPIRED",
                            "Expiration": "2000-01-01T00:00:00Z",  # Far past date
                        }
                    )
                    keyring.set_password("claude-code-with-bedrock", f"{self.profile}-credentials", expired_credential)
                    cleared_items.append("keyring credentials")
        except Exception as e:
            self._debug_print(f"Could not clear keyring credentials: {e}")

        # Clear monitoring token from keyring
        try:
            if keyring.get_password("claude-code-with-bedrock", f"{self.profile}-monitoring"):
                # Replace with expired dummy token
                expired_token = json.dumps(
                    {"token": "EXPIRED", "expires": 0, "email": "", "profile": self.profile}  # Expired timestamp
                )
                keyring.set_password("claude-code-with-bedrock", f"{self.profile}-monitoring", expired_token)
                cleared_items.append("keyring monitoring token")
        except Exception as e:
            self._debug_print(f"Could not clear keyring monitoring token: {e}")

        # Clear credentials file (for session storage mode)
        try:
            credentials_path = Path.home() / ".aws" / "credentials"
            if credentials_path.exists():
                # Replace with expired dummy credentials instead of deleting
                # This preserves the file for other profiles
                expired_creds = {
                    "Version": 1,
                    "AccessKeyId": "EXPIRED",
                    "SecretAccessKey": "EXPIRED",
                    "SessionToken": "EXPIRED",
                    "Expiration": "2000-01-01T00:00:00Z",
                }
                self.save_to_credentials_file(expired_creds, self.profile)
                cleared_items.append("credentials file")
        except Exception as e:
            self._debug_print(f"Could not clear credentials file: {e}")

        # Clear monitoring token from session directory
        session_dir = Path.home() / ".claude-code-session"
        if session_dir.exists():
            monitoring_file = session_dir / f"{self.profile}-monitoring.json"

            if monitoring_file.exists():
                monitoring_file.unlink()
                cleared_items.append("monitoring token file")

            # Remove directory if empty
            try:
                if not any(session_dir.iterdir()):
                    session_dir.rmdir()
            except Exception:
                pass

        # Clear refresh token from keyring
        try:
            if keyring.get_password("claude-code-with-bedrock", f"{self.profile}-refresh-token"):
                keyring.set_password("claude-code-with-bedrock", f"{self.profile}-refresh-token",
                                    json.dumps({"refresh_token": "EXPIRED", "profile": self.profile}))
                cleared_items.append("keyring refresh token")
        except Exception as e:
            self._debug_print(f"Could not clear keyring refresh token: {e}")

        # Clear refresh token from session directory
        if session_dir.exists():
            refresh_file = session_dir / f"{self.profile}-refresh-token.json"
            if refresh_file.exists():
                refresh_file.unlink()
                cleared_items.append("refresh token file")

        return cleared_items

    def _check_otel_helper_integrity(self) -> str:
        """Verify otel-helper binary's SHA256 hash against config.

        Returns status: 'valid', 'missing', 'hash-mismatch', 'not-configured'.
        Does NOT exit — status is reported to TVM Lambda for server-side enforcement.
        """
        # Support per-platform hashes (new) and legacy single hash (old)
        hashes = self.config.get("otel_helper_hashes")
        legacy_hash = self.config.get("otel_helper_hash")

        if not hashes and not legacy_hash:
            # OTEL helper is bundled as Python source, not a separate binary,
            # so hashes are absent by design. Status is still reported to TVM
            # so server-side policy can choose to reject if it ever requires
            # integrity — no user-facing warning.
            return "not-configured"

        # Resolve expected hash for current platform
        if hashes:
            platform_key = self._get_otel_platform_key()
            expected_hash = hashes.get(platform_key)
            if not expected_hash:
                return "not-configured"
        else:
            expected_hash = legacy_hash

        # Determine binary path — hash the actual binary (otel-helper-bin), not the shell wrapper
        if platform.system() == "Windows":
            helper_path = Path.home() / "claude-code-with-bedrock" / "otel-helper.exe"
        else:
            # Prefer otel-helper-bin (the PyInstaller binary that was hashed at build time)
            # The shell wrapper (otel-helper) is a cache layer and not what was hashed
            helper_path = Path.home() / "claude-code-with-bedrock" / "otel-helper-bin"
            if not helper_path.exists():
                # Fallback: no shell wrapper installed, binary is otel-helper directly
                helper_path = Path.home() / "claude-code-with-bedrock" / "otel-helper"

        if not helper_path.exists():
            # Log only — this status is also sent to TVM via header, and is a
            # soft warning; no need to surface it in Claude Code's error bubble.
            self._log(f"otel-helper binary not found at {helper_path}")
            return "missing"

        # Compute SHA256
        sha256 = hashlib.sha256()
        with open(helper_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()

        if actual_hash != expected_hash:
            self._log(
                f"otel-helper hash mismatch (expected={expected_hash[:16]}..., actual={actual_hash[:16]}...)"
            )
            return "hash-mismatch"

        self._debug_print("otel-helper integrity check passed")
        return "valid"

    @staticmethod
    def _get_otel_platform_key() -> str:
        """Return the otel_helper_hashes key for the current OS+arch."""
        system = platform.system().lower()
        machine = platform.machine().lower()

        if system == "darwin":
            if machine == "arm64":
                return "macos-arm64"
            return "macos-intel"
        elif system == "windows":
            return "windows"
        elif system == "linux":
            if machine in ("aarch64", "arm64"):
                return "linux-arm64"
            return "linux-x64"
        return f"{system}-{machine}"

    def _call_tvm(self, id_token: str, otel_helper_status: str) -> dict:
        """Call TVM Lambda via API Gateway to obtain Bedrock credentials.

        The TVM Lambda validates the JWT, checks quota, and issues
        time-scoped STS credentials. This is the sole path to Bedrock credentials.

        Args:
            id_token: Valid Cognito id_token for Authorization header
            otel_helper_status: One of 'valid', 'missing', 'hash-mismatch', 'not-configured'

        Returns:
            Credential dict with Version, AccessKeyId, SecretAccessKey, SessionToken, Expiration

        Raises:
            Exception: On TVM denial or unreachable
        """
        tvm_endpoint = self.config.get("tvm_endpoint")
        if not tvm_endpoint:
            raise Exception("配置文件缺少 tvm_endpoint，无法获取 Bedrock 凭证。请联系管理员重新部署或重新下载安装包")

        timeout = self.config.get("tvm_request_timeout", 5)

        try:
            response = requests.post(
                f"{tvm_endpoint}/tvm",
                headers={
                    "Authorization": f"Bearer {id_token}",
                    "X-OTEL-Helper-Status": otel_helper_status,
                },
                timeout=timeout,
            )

            if response.status_code == 200:
                result = response.json()
                credentials = result.get("credentials")
                if not credentials:
                    raise TVMServiceError(
                        f"200 but no credentials: {result.get('message', 'unknown error')}"
                    )
                # Ensure Version field is present
                credentials.setdefault("Version", 1)
                return credentials
            elif response.status_code == 401:
                raise TVMAuthRejectedError("id_token rejected by API Gateway")
            elif response.status_code == 429:
                result = response.json()
                raise QuotaExceededError(
                    reason=result.get("reason", "quota_exceeded"),
                    usage=result.get("usage"),
                    limit=result.get("limit"),
                    raw_message=result.get("message", "Quota exceeded"),
                )
            elif response.status_code == 403:
                result = response.json()
                reason = result.get("reason", "unknown")
                message = result.get("message", "Access denied")
                raise TVMAccessDeniedError(f"{reason} — {message}")
            else:
                raise TVMServiceError(
                    f"HTTP {response.status_code}: {response.text[:200]}"
                )
        except requests.exceptions.Timeout as e:
            # Raise a dedicated type so run() can print a user-friendly message
            # while the technical detail still lands in the log file.
            raise TVMUnreachableError(f"timeout after {timeout}s: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise TVMUnreachableError(str(e)) from e

    def _try_refresh_token(self) -> str | None:
        """Exchange refresh_token for new id_token via Cognito /oauth2/token.

        Returns new id_token or None if refresh fails.
        """
        refresh_token = self._get_cached_refresh_token()
        if not refresh_token:
            self._debug_print("No cached refresh_token for silent refresh")
            return None

        provider_domain = self.config["provider_domain"]
        base_url = f"https://{provider_domain}"
        token_url = f"{base_url}{self.provider_config['token_endpoint']}"

        try:
            token_data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.config["client_id"],
            }
            # Include client_secret if configured
            if self.config.get("client_secret"):
                token_data["client_secret"] = self.config["client_secret"]

            response = requests.post(
                token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )

            if response.ok:
                tokens = response.json()
                new_id_token = tokens.get("id_token")
                if new_id_token:
                    self._debug_print("Successfully refreshed id_token via refresh_token")
                    return new_id_token
                else:
                    self._debug_print("Refresh response missing id_token")
                    return None
            else:
                # Log response body so we can distinguish invalid_grant (expired/revoked)
                # vs invalid_client (client_secret mismatch) vs unauthorized_client
                # (ALLOW_REFRESH_TOKEN_AUTH disabled). They need different fixes.
                body = response.text[:200] if response.text else ""
                self._debug_print(
                    f"Refresh token exchange failed: {response.status_code} body={body}"
                )
                self._clear_cached_refresh_token()
                return None
        except Exception as e:
            self._debug_print(f"Refresh token exchange error: {e}")
            return None

    def _save_refresh_token(self, refresh_token: str):
        """Save refresh_token to dedicated storage (similar to monitoring token)."""
        try:
            token_data = {"refresh_token": refresh_token, "profile": self.profile}
            if self.credential_storage == "keyring":
                keyring.set_password("claude-code-with-bedrock", f"{self.profile}-refresh-token", json.dumps(token_data))
            else:
                session_dir = Path.home() / ".claude-code-session"
                session_dir.mkdir(parents=True, exist_ok=True)
                token_file = session_dir / f"{self.profile}-refresh-token.json"
                with open(token_file, "w") as f:
                    json.dump(token_data, f)
                token_file.chmod(0o600)
            self._debug_print("Saved refresh token")
            # Verify round-trip: if the storage backend silently drops writes
            # (keyring ACL denied, read-only volume, etc.) the next invocation
            # will hit "No cached refresh_token" and trigger browser auth.
            readback = self._get_cached_refresh_token()
            if readback != refresh_token:
                self._log(
                    f"WARN refresh_token save did not round-trip: storage={self.credential_storage} "
                    f"readback={'missing' if not readback else 'mismatch'}"
                )
        except Exception as e:
            self._debug_print(f"Warning: Could not save refresh token: {e}")

    def _get_cached_refresh_token(self) -> str | None:
        """Retrieve cached refresh_token."""
        try:
            if self.credential_storage == "keyring":
                token_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-refresh-token")
                if token_json:
                    data = json.loads(token_json)
                    return data.get("refresh_token")
            else:
                session_dir = Path.home() / ".claude-code-session"
                token_file = session_dir / f"{self.profile}-refresh-token.json"
                if token_file.exists():
                    with open(token_file) as f:
                        data = json.load(f)
                    return data.get("refresh_token")
            return None
        except Exception:
            return None

    def _clear_cached_refresh_token(self):
        """Clear cached refresh_token."""
        try:
            if self.credential_storage == "keyring":
                if keyring.get_password("claude-code-with-bedrock", f"{self.profile}-refresh-token"):
                    keyring.set_password("claude-code-with-bedrock", f"{self.profile}-refresh-token",
                                        json.dumps({"refresh_token": "EXPIRED", "profile": self.profile}))
            else:
                session_dir = Path.home() / ".claude-code-session"
                token_file = session_dir / f"{self.profile}-refresh-token.json"
                if token_file.exists():
                    token_file.unlink()
        except Exception as e:
            self._debug_print(f"Could not clear refresh token: {e}")

    def save_monitoring_token(self, id_token, token_claims):
        """Save ID token for monitoring authentication"""
        try:
            # Extract relevant claims
            token_data = {
                "token": id_token,
                "expires": token_claims.get("exp", 0),
                "email": token_claims.get("email", ""),
                "profile": self.profile,
            }

            if self.credential_storage == "keyring":
                # Store monitoring token in keyring
                keyring.set_password("claude-code-with-bedrock", f"{self.profile}-monitoring", json.dumps(token_data))
            else:
                # Save to session directory alongside credentials
                session_dir = Path.home() / ".claude-code-session"
                session_dir.mkdir(parents=True, exist_ok=True)

                # Use simple session file per profile
                token_file = session_dir / f"{self.profile}-monitoring.json"

                with open(token_file, "w") as f:
                    json.dump(token_data, f)
                token_file.chmod(0o600)

            # Also export to environment for this session
            os.environ["CLAUDE_CODE_MONITORING_TOKEN"] = id_token

            self._debug_print(f"Saved monitoring token for {token_claims.get('email', 'user')}")
        except Exception as e:
            # Non-fatal error - monitoring is optional
            self._debug_print(f"Warning: Could not save monitoring token: {e}")

    def get_monitoring_token(self):
        """Retrieve valid monitoring token from configured storage"""
        try:
            # First check if it's in environment (from current session)
            import os

            env_token = os.environ.get("CLAUDE_CODE_MONITORING_TOKEN")
            if env_token:
                return env_token

            if self.credential_storage == "keyring":
                # Retrieve from keyring
                token_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-monitoring")

                if not token_json:
                    return None

                token_data = json.loads(token_json)
            else:
                # Check session file
                session_dir = Path.home() / ".claude-code-session"
                token_file = session_dir / f"{self.profile}-monitoring.json"

                if not token_file.exists():
                    return None

                with open(token_file) as f:
                    token_data = json.load(f)

            # Check expiration
            exp_time = token_data.get("expires", 0)
            now = int(datetime.now(timezone.utc).timestamp())

            # Return token if it expires in more than 60 seconds
            if exp_time - now > 60:
                token = token_data["token"]
                # Set in environment for this session
                os.environ["CLAUDE_CODE_MONITORING_TOKEN"] = token
                return token

            return None
        except Exception:
            return None

    def save_to_credentials_file(self, credentials, profile="ClaudeCode"):
        """Save credentials to ~/.aws/credentials file

        Args:
            credentials: Dict with AccessKeyId, SecretAccessKey, SessionToken, Expiration
            profile: Profile name to use in credentials file (default: ClaudeCode)
        """
        import tempfile
        from configparser import ConfigParser

        credentials_path = Path.home() / ".aws" / "credentials"

        # Create ~/.aws directory if it doesn't exist
        credentials_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing file or create new config
        # Disable inline comment characters so we can use keys like 'x-expiration'
        config = ConfigParser(inline_comment_prefixes=())
        if credentials_path.exists():
            try:
                config.read(credentials_path)
            except Exception as e:
                self._debug_print(f"Warning: Could not read existing credentials file: {e}")

        # Update profile section
        if profile not in config:
            config[profile] = {}

        config[profile]["aws_access_key_id"] = credentials["AccessKeyId"]
        config[profile]["aws_secret_access_key"] = credentials["SecretAccessKey"]
        config[profile]["aws_session_token"] = credentials["SessionToken"]

        # Add expiration as a special key that AWS SDK will ignore
        # Use 'x-' prefix which is a convention for custom/extension fields
        if "Expiration" in credentials:
            config[profile]["x-expiration"] = credentials["Expiration"]

        # Atomic write using temporary file
        try:
            # Write to temporary file first
            temp_fd, temp_path = tempfile.mkstemp(dir=credentials_path.parent, prefix=".credentials.", suffix=".tmp")

            try:
                with os.fdopen(temp_fd, "w") as f:
                    config.write(f)

                # Set restrictive permissions on temp file
                os.chmod(temp_path, 0o600)

                # Atomic rename
                os.replace(temp_path, credentials_path)

                self._debug_print(f"Saved credentials to {credentials_path} for profile '{profile}'")
            except Exception:
                # Clean up temp file on error
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                raise
        except Exception as e:
            raise Exception(f"Failed to save credentials to file: {str(e)}") from e

    def read_from_credentials_file(self, profile="ClaudeCode"):
        """Read credentials from ~/.aws/credentials file

        Args:
            profile: Profile name to read from credentials file

        Returns:
            Dict with credentials or None if not found
        """
        from configparser import ConfigParser

        credentials_path = Path.home() / ".aws" / "credentials"

        if not credentials_path.exists():
            return None

        try:
            # Disable inline comment characters to read keys like 'x-expiration'
            config = ConfigParser(inline_comment_prefixes=())
            config.read(credentials_path)

            if profile not in config:
                return None

            profile_section = config[profile]

            # Build credentials dict
            credentials = {
                "Version": 1,
                "AccessKeyId": profile_section.get("aws_access_key_id"),
                "SecretAccessKey": profile_section.get("aws_secret_access_key"),
                "SessionToken": profile_section.get("aws_session_token"),
            }

            # Extract expiration from custom field if present
            expiration = profile_section.get("x-expiration")
            if expiration:
                credentials["Expiration"] = expiration

            # Validate all required fields are present
            if not all(
                [credentials.get("AccessKeyId"), credentials.get("SecretAccessKey"), credentials.get("SessionToken")]
            ):
                return None

            return credentials

        except Exception as e:
            self._debug_print(f"Error reading credentials from file: {e}")
            return None

    def check_credentials_file_expiration(self, profile="ClaudeCode"):
        """Check if credentials in file are expired

        Args:
            profile: Profile name to check

        Returns:
            True if expired, False if valid
        """
        credentials = self.read_from_credentials_file(profile)

        if not credentials:
            return True  # No credentials = expired

        exp_str = credentials.get("Expiration")
        if not exp_str:
            # No expiration info, assume expired for safety
            return True

        try:
            exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)

            # Use 30-second buffer - consider expired if less than 30s remaining
            remaining_seconds = (exp_time - now).total_seconds()
            return remaining_seconds <= 30

        except Exception as e:
            self._debug_print(f"Error parsing expiration: {e}")
            return True  # Assume expired on parse error

    # Browser-auth overall timeout: how long we wait for the user to finish
    # sign-in in the browser before giving up. Lower = faster retry after a
    # closed browser, higher = tolerates slow enterprise MFA. 3 min is a
    # compromise: most SSO completes in < 60s; slow MFA (push notifications
    # that time out, SMS retries) still fits.
    _BROWSER_AUTH_TIMEOUT_SECONDS = 180

    # Browser-auth global lock: prevent spawning a second browser window while
    # a previous credential-process is still waiting for the user to log in.
    # Without this, every IDE extension / AWS SDK call that hits an unauthenticated
    # profile opens yet another window on top of the unanswered one.
    # TTL must be >= _BROWSER_AUTH_TIMEOUT_SECONDS with headroom.
    _BROWSER_LOCK_TTL_SECONDS = 600  # 10 minutes

    def _browser_lock_path(self) -> Path:
        session_dir = Path.home() / ".claude-code-session"
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir / f"{self.profile}-browser.lock"

    def _is_pid_alive(self, pid: int) -> bool:
        if pid <= 0:
            return False
        if platform.system() == "Windows":
            # os.kill(pid, 0) on Windows terminates the process rather than probing.
            # Use OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION (Vista+).
            try:
                import ctypes
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[attr-defined]
                    PROCESS_QUERY_LIMITED_INFORMATION, False, pid
                )
                if not handle:
                    return False
                ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
                return True
            except Exception:
                # ctypes/kernel32 not available → fail-safe: assume alive so we don't
                # steal a legitimately held lock. TTL will still recover.
                return True
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # pid exists but owned by another user — still alive.
            return True
        except Exception:
            return False

    def _acquire_browser_lock(self) -> bool:
        """Try to acquire the browser-auth lock. Returns True on success.

        Lock is considered valid only if BOTH: the recorded PID is alive AND
        the file mtime is within the TTL. Either stale condition triggers
        takeover — so a crashed credential-process never strands users.
        """
        lock_path = self._browser_lock_path()
        try:
            if lock_path.exists():
                try:
                    data = json.loads(lock_path.read_text())
                    holder_pid = int(data.get("pid", 0))
                except Exception:
                    holder_pid = 0
                mtime = lock_path.stat().st_mtime
                age = time.time() - mtime
                alive = self._is_pid_alive(holder_pid)
                if alive and age < self._BROWSER_LOCK_TTL_SECONDS and holder_pid != os.getpid():
                    self._log(
                        f"browser lock held by pid={holder_pid} age={int(age)}s — "
                        "skipping browser open"
                    )
                    return False
                self._log(
                    f"browser lock stale (pid={holder_pid} alive={alive} age={int(age)}s), taking over"
                )
            payload = json.dumps({"pid": os.getpid(), "profile": self.profile, "ts": int(time.time())})
            # Atomic write: write to a tmp file then rename. Path.replace is atomic
            # on POSIX and Windows (ReplaceFile/MoveFileEx). Avoids partial-write
            # races when another instance is racing to take over a stale lock.
            tmp_path = lock_path.with_suffix(lock_path.suffix + f".{os.getpid()}.tmp")
            tmp_path.write_text(payload)
            try:
                tmp_path.chmod(0o600)  # No-op semantics on Windows, harmless.
            except Exception:
                pass
            tmp_path.replace(lock_path)
            self._log(f"acquired browser lock pid={os.getpid()} path={lock_path}")
            return True
        except Exception as e:
            # Fail-open: if the lock file itself is broken, don't block the user.
            self._log(f"browser lock acquire failed, proceeding without lock: {e}")
            return True

    def _release_browser_lock(self):
        try:
            lock_path = self._browser_lock_path()
            if not lock_path.exists():
                return
            # Only remove if we own it, to avoid racing with a takeover.
            try:
                data = json.loads(lock_path.read_text())
                if int(data.get("pid", 0)) != os.getpid():
                    return
            except Exception:
                pass
            lock_path.unlink()
            self._log("released browser lock")
        except Exception as e:
            self._log(f"browser lock release failed: {e}")

    def authenticate_oidc(self):
        """Perform OIDC authentication with PKCE"""
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)

        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")
        )

        # Build authorization URL based on provider
        provider_domain = self.config["provider_domain"]

        # For Azure/Microsoft, if domain includes /v2.0, we need to strip it
        # since the endpoints already include the full path
        if self.provider_type == "azure" and provider_domain.endswith("/v2.0"):
            provider_domain = provider_domain[:-5]  # Remove '/v2.0'

        # For Cognito User Pool, we need to extract the domain and construct the URL differently
        if self.provider_type == "cognito":
            # Domain format: cognito-idp.{region}.amazonaws.com/{user-pool-id}
            # OAuth2 endpoints are at: https://{user-pool-domain}.auth.{region}.amazoncognito.com
            # We need the User Pool domain (configured separately in Cognito console)
            # For now, we'll use the domain as provided, which should be the User Pool domain
            if "amazoncognito.com" not in provider_domain:
                # If it's the identity pool format, we need the actual User Pool domain
                raise ValueError(
                    "For Cognito User Pool, please provide the User Pool domain "
                    "(e.g., 'my-domain.auth.us-east-1.amazoncognito.com'), "
                    "not the identity pool endpoint."
                )
            base_url = f"https://{provider_domain}"
        else:
            base_url = f"https://{provider_domain}"

        auth_params = {
            "client_id": self.config["client_id"],
            "response_type": self.provider_config["response_type"],
            "scope": self.provider_config["scopes"],
            "redirect_uri": self.redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }

        # Add provider-specific parameters
        if self.provider_type == "azure":
            auth_params["response_mode"] = "query"
            auth_params["prompt"] = "select_account"

        auth_url = f"{base_url}{self.provider_config['authorize_endpoint']}?" + urlencode(auth_params)

        # Setup callback server
        auth_result = {"code": None, "error": None}
        bind_host = os.getenv("REDIRECT_BIND", "127.0.0.1")
        server = HTTPServer((bind_host, self.redirect_port), self._create_callback_handler(state, auth_result, auth_url))

        # Start server in background — handle multiple requests (login redirect + callback)
        def _serve_until_done():
            server.timeout = 5  # per-request timeout
            deadline = time.time() + self._BROWSER_AUTH_TIMEOUT_SECONDS
            while not auth_result["code"] and not auth_result["error"] and time.time() < deadline:
                server.handle_request()

        # Acquire the browser-auth global lock BEFORE starting the callback
        # server / opening a browser. If another credential-process already
        # has an auth window waiting, refuse to open a second one.
        if not self._acquire_browser_lock():
            try:
                server.server_close()
            except Exception:
                pass
            raise BrowserAuthInProgressError(
                "已有一个登录窗口在等待你完成登录。请先在已打开的浏览器标签页中完成登录，"
                "或关闭后重试。"
            )

        try:
            server_thread = threading.Thread(target=_serve_until_done)
            server_thread.daemon = True
            server_thread.start()

            # Open browser - detect headless environment first
            is_headless = not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY") and sys.platform not in ("darwin", "win32")
            browser_opened = False

            if not is_headless:
                self._debug_print(f"Opening browser for {self.provider_config['name']} authentication...")
                try:
                    browser_opened = webbrowser.open(auth_url)
                except Exception:
                    pass

            if browser_opened:
                mins = self._BROWSER_AUTH_TIMEOUT_SECONDS // 60
                hint = (
                    "\n已为你打开浏览器进行登录。\n"
                    f"若未在约 {mins} 分钟内完成，或浏览器已关闭，请退出 Claude Code 后重试。\n"
                )
                print(hint, file=sys.stderr, flush=True)
            else:
                msg = (
                    "\n" + "=" * 60 + "\n"
                    "请在浏览器中打开以下地址完成登录：\n\n"
                    f"  http://localhost:{self.redirect_port}\n\n"
                    "等待登录回调...\n"
                    f"提示：远程机器可用 ssh -L {self.redirect_port}:localhost:{self.redirect_port} <host> 做端口转发\n"
                    + "=" * 60 + "\n"
                )
                print(msg, file=sys.stderr, flush=True)

            # Wait for callback. Slightly longer than server-side deadline so
            # the server loop exits on its own before join times out.
            server_thread.join(timeout=self._BROWSER_AUTH_TIMEOUT_SECONDS + 5)
        finally:
            self._release_browser_lock()

        # Note: stale callbacks are no longer treated as errors — the handler
        # logs and ignores them, so the server keeps listening for the real
        # /callback. Any error here is a real IdP-side failure.
        if auth_result["error"]:
            self._log(f"IdP error on callback: {auth_result['error']}")
            raise Exception(f"身份认证出错：{auth_result['error']}")

        if not auth_result["code"]:
            self._log("Browser auth timeout: no authorization code received within 5 minutes")
            raise Exception("登录超时：浏览器未在 5 分钟内完成登录")

        # Exchange code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_result["code"],
            "redirect_uri": self.redirect_uri,
            "client_id": self.config["client_id"],
            "code_verifier": code_verifier,
        }

        # Include client_secret if configured (for confidential OIDC clients)
        if self.config.get("client_secret"):
            token_data["client_secret"] = self.config["client_secret"]

        # Build token endpoint URL
        token_url = f"{base_url}{self.provider_config['token_endpoint']}"

        token_response = requests.post(
            token_url,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,  # 30 second timeout for token exchange
        )

        if not token_response.ok:
            self._log(f"Token exchange failed: HTTP {token_response.status_code} body={token_response.text[:200]}")
            raise Exception("登录凭证换取失败，请稍后重试或联系管理员")

        tokens = token_response.json()

        # Validate nonce in ID token (if provider includes it)
        id_token_claims = jwt.decode(tokens["id_token"], options={"verify_signature": False})
        if "nonce" in id_token_claims and id_token_claims.get("nonce") != nonce:
            self._log("Invalid nonce in ID token — possible replay or IdP misconfiguration")
            raise Exception("登录校验失败（nonce 不匹配），请重试；如持续失败请联系管理员")

        # Enhanced debug logging for claims
        if self.debug:
            self._debug_print("\n=== ID Token Claims ===")
            self._debug_print(json.dumps(id_token_claims, indent=2, default=str))

            # Log specific important claims
            important_claims = [
                "sub",
                "email",
                "name",
                "preferred_username",
                "groups",
                "cognito:groups",
                "custom:department",
                "custom:role",
            ]
            self._debug_print("\n=== Key Claims for Mapping ===")
            for claim in important_claims:
                if claim in id_token_claims:
                    self._debug_print(f"{claim}: {id_token_claims[claim]}")

        # Save refresh_token if present (for silent refresh up to 12 hours)
        if "refresh_token" in tokens:
            self._save_refresh_token(tokens["refresh_token"])

        return tokens["id_token"], id_token_claims

    def _create_callback_handler(self, expected_state, result_container, auth_url=None):
        """Create HTTP handler for OAuth callback"""
        parent = self

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlparse(self.path).path
                parent._debug_print(f"Received callback request: {self.path}")

                # Serve login redirect on root path
                if path in ("/", "/login") and auth_url:
                    self.send_response(302)
                    self.send_header("Location", auth_url)
                    self.end_headers()
                    return

                # Only /callback is allowed to terminate the auth loop.
                # Probes from browsers (favicon.ico), IDE extensions, or port
                # scanners used to land in the else-branch below and get tagged
                # as "stale_callback", which terminated the server and (prior
                # to this fix) triggered a recursive browser reopen.
                if path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    return

                query = parse_qs(urlparse(self.path).query)

                if query.get("error"):
                    result_container["error"] = query.get("error_description", ["Unknown error"])[0]
                    self._send_response(400, "登录失败")
                elif query.get("state", [""])[0] == expected_state and "code" in query:
                    result_container["code"] = query["code"][0]
                    self._send_response(200, "登录成功！可以关闭此窗口。")
                else:
                    # State mismatch — stale callback from a previous tab/session.
                    # Log and 400 but DO NOT set result_container["error"]:
                    # keep the server listening for the real /callback.
                    parent._debug_print(f"Stale callback ignored (expected={expected_state[:8]}...)")
                    self._send_response(400, "登录会话已过期，请在最新打开的登录标签页中完成。")

            def _send_response(self, code, message):
                self.send_response(code)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                html = f"""
                <html lang="zh-CN">
                <head><meta charset="utf-8"><title>登录</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1>{message}</h1>
                    <p>请返回终端继续。</p>
                </body>
                </html>
                """
                self.wfile.write(html.encode())

            def log_message(self, _format, *_args):
                pass  # Suppress logs

        return CallbackHandler

    def get_aws_credentials(self, id_token, token_claims):
        """Exchange OIDC token for AWS credentials"""
        self._debug_print("Entering get_aws_credentials method")

        # Route to appropriate federation method
        federation_type = self.config.get("federation_type", "cognito")
        self._debug_print(f"Using federation type: {federation_type}")

        if federation_type == "direct":
            return self.get_aws_credentials_direct(id_token, token_claims)
        else:
            return self.get_aws_credentials_cognito(id_token, token_claims)

    def get_aws_credentials_direct(self, id_token, token_claims):
        """Direct STS federation without Cognito Identity Pool - provides 12 hour sessions"""
        self._debug_print("Using Direct STS federation (AssumeRoleWithWebIdentity)")

        # Clear any AWS credentials to prevent recursive calls
        env_vars_to_clear = ["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
        saved_env = {}
        for var in env_vars_to_clear:
            if var in os.environ:
                saved_env[var] = os.environ[var]
                del os.environ[var]

        try:
            # Get the federated role ARN from config
            federated_role_arn = self.config.get("federated_role_arn")
            if not federated_role_arn:
                raise ValueError("federated_role_arn is required for direct STS federation")

            # Create STS client
            sts_client = boto3.client("sts", region_name=self.config["aws_region"])

            # Prepare session tags from token claims
            session_tags = []

            # Map common claims to session tags
            tag_mappings = {
                "email": "UserEmail",
                "sub": "UserId",
                "preferred_username": "UserName",
                "name": "UserName",  # Fallback for providers that use 'name' instead
            }

            for claim_key, tag_key in tag_mappings.items():
                if claim_key in token_claims:
                    # Session tag values have a 256 character limit
                    tag_value = str(token_claims[claim_key])[:256]
                    session_tags.append({"Key": tag_key, "Value": tag_value})

            # Generate session name from user identifier
            # AWS RoleSessionName regex: [\w+=,.@-]*
            # Auth0 often uses pipe-delimited format in sub claims (e.g., auth0|12345)
            # Sanitize to replace invalid characters with hyphens
            session_name = "claude-code"
            if "sub" in token_claims:
                # Use first 52 chars of sub for uniqueness, sanitized for AWS
                # AWS RoleSessionName limit is 64 chars; prefix "claude-code-" is 12 chars
                # 52 chars accommodates standard UUIDs (36 chars) and longer identifiers
                sub_sanitized = re.sub(r"[^\w+=,.@-]", "-", str(token_claims["sub"])[:52])
                session_name = f"claude-code-{sub_sanitized}"
            elif "email" in token_claims:
                # Use email username part, sanitized
                email_part = token_claims["email"].split("@")[0][:52]
                email_sanitized = re.sub(r"[^\w+=,.@-]", "-", email_part)
                session_name = f"claude-code-{email_sanitized}"

            self._debug_print(f"Assuming role: {federated_role_arn}")
            self._debug_print(f"Session name: {session_name}")
            self._debug_print(f"Session tags: {session_tags}")

            # Call AssumeRoleWithWebIdentity
            # Note: AssumeRoleWithWebIdentity doesn't support Tags parameter directly
            # Session tags must be passed via the token claims and configured in the trust policy
            assume_role_params = {
                "RoleArn": federated_role_arn,
                "RoleSessionName": session_name,
                "WebIdentityToken": id_token,
                "DurationSeconds": self.config.get("max_session_duration", 43200),  # 12 hours
            }

            response = sts_client.assume_role_with_web_identity(**assume_role_params)

            # Extract credentials
            creds = response["Credentials"]

            # Format for AWS CLI
            formatted_creds = {
                "Version": 1,
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken": creds["SessionToken"],
                "Expiration": (
                    creds["Expiration"].isoformat()
                    if hasattr(creds["Expiration"], "isoformat")
                    else creds["Expiration"]
                ),
            }

            self._debug_print(
                f"Successfully obtained credentials via Direct STS, expires: {formatted_creds['Expiration']}"
            )
            return formatted_creds

        except Exception as e:
            # Check if this is a credential error that suggests bad cached credentials
            error_str = str(e)
            if any(
                err in error_str
                for err in [
                    "InvalidParameterException",
                    "NotAuthorizedException",
                    "ValidationError",
                    "Invalid AccessKeyId",
                    "ExpiredToken",
                    "Invalid JWT",
                ]
            ):
                self._debug_print("Detected invalid credentials, clearing cache...")
                self.clear_cached_credentials()
                # Add helpful message for user
                raise Exception(
                    f"Authentication failed - cached credentials were invalid and have been cleared.\n"
                    f"Please try again to re-authenticate.\n"
                    f"Original error: {error_str}"
                ) from e
            raise Exception(f"Failed to get AWS credentials via Direct STS: {str(e)}") from None
        finally:
            # Restore environment variables
            for var, value in saved_env.items():
                os.environ[var] = value

    def get_aws_credentials_cognito(self, id_token, token_claims):
        """Exchange OIDC token for AWS credentials via Cognito Identity Pool"""
        self._debug_print("Using Cognito Identity Pool federation")

        # Clear any AWS credentials to prevent recursive calls
        env_vars_to_clear = ["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
        saved_env = {}
        for var in env_vars_to_clear:
            if var in os.environ:
                saved_env[var] = os.environ[var]
                del os.environ[var]

        try:
            # Use unsigned requests for Cognito Identity (no AWS credentials needed)
            self._debug_print("Creating Cognito Identity client...")
            cognito_client = boto3.client(
                "cognito-identity", region_name=self.config["aws_region"], config=Config(signature_version=UNSIGNED)
            )
            self._debug_print("Cognito client created")

            self._debug_print("Creating STS client...")
            boto3.client("sts", region_name=self.config["aws_region"])
            self._debug_print("STS client created")
        finally:
            # Restore environment variables
            for var, value in saved_env.items():
                os.environ[var] = value

        try:
            # Log authentication details for debugging
            self._debug_print(f"Provider type: {self.provider_type}")
            self._debug_print(f"AWS Region: {self.config['aws_region']}")
            self._debug_print(f"Identity Pool ID: {self.config['identity_pool_id']}")

            # Determine the correct login key based on provider type
            if self.provider_type == "cognito":
                # For Cognito User Pool, extract from token issuer to ensure case matches
                if "iss" in token_claims:
                    # Use the issuer from the token to ensure case matches
                    issuer = token_claims["iss"]
                    login_key = issuer.replace("https://", "")
                    self._debug_print("Using issuer from token as login key")
                else:
                    # Fallback: construct from config
                    user_pool_id = self.config.get("cognito_user_pool_id")
                    if not user_pool_id:
                        raise ValueError("cognito_user_pool_id is required for Cognito User Pool authentication")
                    login_key = f"cognito-idp.{self.config['aws_region']}.amazonaws.com/{user_pool_id}"
                    self._debug_print(f"Cognito User Pool ID from config: {user_pool_id}")
            else:
                # For external OIDC providers, use the provider domain
                login_key = self.config["provider_domain"]

            self._debug_print(f"Login key: {login_key}")
            self._debug_print(f"Token claims: {list(token_claims.keys())}")
            if "iss" in token_claims:
                self._debug_print(f"Token issuer: {token_claims['iss']}")

            # Log all claims being passed for principal tags
            if self.debug:
                self._debug_print("\n=== Claims being sent to Cognito Identity ===")
                self._debug_print(f"Provider: {login_key}")
                self._debug_print("Claims that could be mapped to principal tags:")
                for key, value in token_claims.items():
                    self._debug_print(f"  {key}: {value}")

            # Get Cognito identity
            self._debug_print(f"Calling GetId with identity pool: {self.config['identity_pool_id']}")
            identity_response = cognito_client.get_id(
                IdentityPoolId=self.config["identity_pool_id"], Logins={login_key: id_token}
            )

            identity_id = identity_response["IdentityId"]
            self._debug_print(f"Got Cognito Identity ID: {identity_id}")

            # For enhanced flow, directly get credentials
            # Since we have a specific role configured, we'll use the role-based approach
            role_arn = self.config.get("role_arn")
            self._debug_print(f"Configured role ARN: {role_arn if role_arn else 'None (using default pool role)'}")

            if role_arn:
                # Get credentials for identity first to get the OIDC token
                credentials_response = cognito_client.get_credentials_for_identity(
                    IdentityId=identity_id, Logins={login_key: id_token}
                )

                # The credentials from Cognito are temporary credentials for the default role
                # Since we want to use our specific role with session tags, we need to do AssumeRole
                creds = credentials_response["Credentials"]
            else:
                # Get default role from identity pool
                credentials_response = cognito_client.get_credentials_for_identity(
                    IdentityId=identity_id, Logins={login_key: id_token}
                )

                creds = credentials_response["Credentials"]

            # Format for AWS CLI
            formatted_creds = {
                "Version": 1,
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretKey"],
                "SessionToken": creds["SessionToken"],
                "Expiration": (
                    creds["Expiration"].isoformat()
                    if hasattr(creds["Expiration"], "isoformat")
                    else creds["Expiration"]
                ),
            }

            return formatted_creds

        except Exception as e:
            # Check if this is a credential error that suggests bad cached credentials
            error_str = str(e)
            if any(
                err in error_str
                for err in [
                    "InvalidParameterException",
                    "NotAuthorizedException",
                    "ValidationError",
                    "Invalid AccessKeyId",
                    "Token is not from a supported provider",
                ]
            ):
                self._debug_print("Detected invalid credentials, clearing cache...")
                self.clear_cached_credentials()
                # Add helpful message for user
                raise Exception(
                    f"Authentication failed - cached credentials were invalid and have been cleared.\n"
                    f"Please try again to re-authenticate.\n"
                    f"Original error: {error_str}"
                ) from e
            raise Exception(f"Failed to get AWS credentials: {str(e)}") from None

    # Process cmdlines we consider "ours" when checking port ownership.
    # The installed wrapper on end-user machines is usually `credential-process`
    # (dash), which execs `python .../credential_provider/__main__.py`; the latter
    # is what ends up in the cmdline after exec on POSIX. Windows keeps the
    # wrapper visible as credential-process.exe.
    _CCWB_CMDLINE_MARKERS = ("credential_provider", "credential-process", "ccwb")

    def _is_port_held_by_ccwb(self) -> bool:
        """Check if the redirect port is held by another credential-provider process.

        Detection backends (first that works wins):
          - Linux: /proc/net/tcp + /proc/<pid>/fd (no external tools).
          - Windows: netstat -ano + tasklist.
          - macOS / Linux with lsof: lsof -i :PORT + ps.

        Falls back to True (fail-safe) so a sibling ccwb process is not
        mistaken for a stranger when detection is impossible.
        """
        try:
            import subprocess
            port = self.redirect_port

            # Try /proc/net/tcp first (Linux, including Alpine/Docker — no lsof needed)
            proc_net = None
            for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
                try:
                    with open(path) as f:
                        proc_net = f.readlines()
                    break
                except FileNotFoundError:
                    continue

            if proc_net is not None:
                # /proc/net/tcp format: local_address (hex ip:port), state 0A = LISTEN
                hex_port = f":{port:04X}"
                listening_inodes = set()
                for line in proc_net[1:]:  # skip header
                    fields = line.split()
                    if len(fields) >= 10 and fields[1].upper().endswith(hex_port) and fields[3] == "0A":
                        listening_inodes.add(fields[9])  # inode

                if not listening_inodes:
                    return False

                # Find which PID owns these inodes
                import os as _os
                for pid_dir in _os.listdir("/proc"):
                    if not pid_dir.isdigit():
                        continue
                    try:
                        fd_dir = f"/proc/{pid_dir}/fd"
                        for fd in _os.listdir(fd_dir):
                            link = _os.readlink(f"{fd_dir}/{fd}")
                            for inode in listening_inodes:
                                if f"socket:[{inode}]" in link:
                                    # Check command line
                                    with open(f"/proc/{pid_dir}/cmdline") as f:
                                        cmdline = f.read()
                                    if any(m in cmdline for m in self._CCWB_CMDLINE_MARKERS):
                                        return True
                    except (PermissionError, FileNotFoundError, ProcessLookupError):
                        continue
                return False

            # Windows: use netstat -ano + tasklist (no lsof). Both ship with
            # every Windows install, no dependencies.
            if platform.system() == "Windows":
                return self._is_port_held_by_ccwb_windows(port)

            # Fallback: lsof (macOS, or Linux with lsof installed)
            result = subprocess.run(
                ["lsof", "-i", f"TCP:{port}", "-sTCP:LISTEN", "-t"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return False
            for pid_str in result.stdout.strip().split("\n"):
                pid = int(pid_str)
                cmd_result = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "command="],
                    capture_output=True, text=True, timeout=3,
                )
                cmd = cmd_result.stdout.strip()
                if any(m in cmd for m in self._CCWB_CMDLINE_MARKERS):
                    return True
            return False
        except Exception:
            # If we can't determine, assume it's ours (safer — avoids false negatives)
            return True

    def _is_port_held_by_ccwb_windows(self, port: int) -> bool:
        """Windows-specific port ownership check using netstat + tasklist.

        netstat -ano output columns (space-separated, Listening state):
          Proto  Local-Address       Foreign-Address  State     PID
          TCP    0.0.0.0:8400        0.0.0.0:0        LISTENING 12345

        We scan for rows ending in LISTENING whose local address ends in :<port>,
        extract the PID, then ask tasklist for the image name and match against
        our ccwb markers. errors=replace on decode so PowerShell 5.x's
        Windows-1252 / non-UTF-8 output doesn't crash us.
        """
        import subprocess
        try:
            out = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, timeout=5,
            )
            if out.returncode != 0:
                # netstat gone or blocked — fail-safe
                return True
            text = out.stdout.decode("utf-8", errors="replace")
        except Exception:
            return True

        suffix = f":{port}"
        pids = set()
        for line in text.splitlines():
            parts = line.split()
            # Minimum columns: Proto Local Foreign State PID
            if len(parts) < 5:
                continue
            if parts[0].upper() != "TCP":
                continue
            if parts[-2].upper() != "LISTENING":
                continue
            local = parts[1]
            if not local.endswith(suffix):
                continue
            try:
                pids.add(int(parts[-1]))
            except ValueError:
                continue

        if not pids:
            return False

        for pid in pids:
            try:
                tl = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, timeout=5,
                )
                if tl.returncode != 0:
                    continue
                image = tl.stdout.decode("utf-8", errors="replace").strip()
                # tasklist CSV row: "credential-process.exe","12345","Console","1","12,345 K"
                if any(m in image for m in self._CCWB_CMDLINE_MARKERS):
                    return True
            except Exception:
                continue
        return False

    # Must cover the full browser-auth deadline plus token exchange + save
    # so a second CC that lands mid-sign-in doesn't give up before the first
    # one finishes. Derived from _BROWSER_AUTH_TIMEOUT_SECONDS + headroom.
    _WAIT_FOR_AUTH_TIMEOUT_SECONDS = _BROWSER_AUTH_TIMEOUT_SECONDS + 30

    def _wait_for_auth_completion(self, timeout: int | None = None):
        """Wait for another process to complete authentication using port-based detection.

        Sets self._last_wait_result to one of:
          - "cached": cached creds became available.
          - "third_party": port held by a non-ccwb application (caller already got
            a user-facing message printed here).
          - "timeout": a ccwb process was holding the port but didn't finish in time.
        """
        if timeout is None:
            timeout = self._WAIT_FOR_AUTH_TIMEOUT_SECONDS
        start_time = time.time()

        # Check if port is actually held by another ccwb process
        if not self._is_port_held_by_ccwb():
            self._last_wait_result = "third_party"
            port = self.redirect_port
            self._log(f"PORT BUSY: port={port} not held by a ccwb/credential-process — occupied by a third-party app")
            msg = (
                f"\n无法完成登录：本机端口 {port} 已被占用。\n\n"
                f"通常是你自己启动的开发服务器（如本地 Web 服务、调试工具）占用了这个端口。\n\n"
                f"解决办法：\n"
                f"  • 关掉占用该端口的程序，然后重新运行命令。\n"
                f"  • 查看是哪个程序占用的：\n"
                f"      macOS / Linux:   lsof -i :{port}\n"
                f"      Windows (cmd):   netstat -ano | findstr :{port}\n\n"
                f"如果端口反复被占用，请联系管理员。\n"
            )
            print(msg, file=sys.stderr, flush=True)
            return None

        bind_host = os.getenv("REDIRECT_BIND", "127.0.0.1")
        while time.time() - start_time < timeout:
            # Check if port is still in use (another auth in progress)
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_socket.bind((bind_host, self.redirect_port))
                test_socket.close()
                # Port is free, auth must have completed or failed
                # Check for cached credentials
                cached = self.get_cached_credentials()
                if cached:
                    self._last_wait_result = "cached"
                    return cached
                else:
                    # Auth failed or was cancelled
                    self._last_wait_result = "timeout"
                    return None
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    # Port still in use, auth still in progress
                    time.sleep(0.5)
                else:
                    # Other error
                    raise
            finally:
                try:
                    test_socket.close()
                except Exception:
                    pass

        self._last_wait_result = "timeout"
        self._log(
            f"WAIT TIMEOUT: another ccwb process still holding port {self.redirect_port} after {timeout}s"
        )
        return None

    def authenticate_for_monitoring(self):
        """Authenticate specifically for monitoring token (no AWS credential output)"""
        try:
            # Return cached monitoring token if still valid (avoids port 8400 conflict)
            cached_token = self.get_monitoring_token()
            if cached_token:
                self._debug_print("Using cached monitoring token")
                return cached_token

            # Try to acquire port lock by testing if we can bind to it
            bind_host = os.getenv("REDIRECT_BIND", "127.0.0.1")
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_socket.bind((bind_host, self.redirect_port))
                test_socket.close()
                # We got the port, we can proceed with authentication
                self._debug_print("Port available, proceeding with monitoring authentication")
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    # Port in use, another auth is in progress
                    self._debug_print("Another authentication is in progress, waiting...")
                    test_socket.close()

                    # Wait for the other process to complete
                    # After waiting, check if we now have a monitoring token
                    self._wait_for_auth_completion()
                    token = self.get_monitoring_token()
                    if token:
                        return token
                    else:
                        self._debug_print("Authentication timeout or failed in another process")
                        return None
                else:
                    test_socket.close()
                    raise

            # Authenticate with OIDC provider
            self._debug_print(f"Authenticating with {self.provider_config['name']} for monitoring token...")
            id_token, token_claims = self.authenticate_oidc()

            # Get AWS credentials (we need them but won't output them)
            self._debug_print("Exchanging token for AWS credentials...")
            credentials = self.get_aws_credentials(id_token, token_claims)

            # Cache credentials for future use
            self.save_credentials(credentials)

            # Save monitoring token
            self.save_monitoring_token(id_token, token_claims)

            # Return just the monitoring token
            return id_token

        except KeyboardInterrupt:
            # User cancelled
            self._debug_print("Authentication cancelled by user")
            return None
        except Exception as e:
            self._debug_print(f"Error during monitoring authentication: {e}")
            return None

    def _get_cached_token_claims(self) -> dict | None:
        """Get token claims from cached monitoring token for quota re-check."""
        try:
            if self.credential_storage == "keyring":
                token_json = keyring.get_password("claude-code-with-bedrock", f"{self.profile}-monitoring")
                if token_json:
                    token_data = json.loads(token_json)
                    return {"email": token_data.get("email", "")}
            else:
                session_dir = Path.home() / ".claude-code-session"
                token_file = session_dir / f"{self.profile}-monitoring.json"
                if token_file.exists():
                    with open(token_file) as f:
                        token_data = json.load(f)
                        return {"email": token_data.get("email", "")}
            return None
        except Exception:
            return None

    def _extract_groups(self, token_claims: dict) -> list:
        """Extract group memberships from JWT token claims.

        Looks for groups in multiple claim formats:
        - groups: Standard groups claim
        - cognito:groups: Amazon Cognito groups
        - custom:department: Custom department claim (treated as a group)
        """
        groups = []

        # Standard groups claim
        if "groups" in token_claims:
            claim_groups = token_claims["groups"]
            if isinstance(claim_groups, list):
                groups.extend(claim_groups)
            elif isinstance(claim_groups, str):
                groups.append(claim_groups)

        # Cognito groups
        if "cognito:groups" in token_claims:
            claim_groups = token_claims["cognito:groups"]
            if isinstance(claim_groups, list):
                groups.extend(claim_groups)
            elif isinstance(claim_groups, str):
                groups.append(claim_groups)

        # Custom department (treated as a group for policy matching)
        if "custom:department" in token_claims:
            department = token_claims["custom:department"]
            if department:
                groups.append(f"department:{department}")

        return list(set(groups))  # Remove duplicates

    def _try_silent_refresh(self):
        """Attempt silent credential refresh using cached id_token or refresh_token.

        Returns:
            Tuple of (credentials, id_token, token_claims) if successful, (None, None, None) otherwise.
        """
        try:
            # Try cached id_token first (existing behavior)
            id_token = self.get_monitoring_token()
            if id_token:
                self._debug_print("Found valid cached id_token, attempting TVM credential refresh...")
                token_claims = jwt.decode(id_token, options={"verify_signature": False})
                credentials = self._call_tvm(id_token, self.otel_helper_status)
                self.save_credentials(credentials)
                self.save_monitoring_token(id_token, token_claims)
                self._debug_print("Silent credential refresh via cached id_token succeeded")
                return credentials, id_token, token_claims
        except QuotaExceededError:
            raise  # Don't swallow — must reach the user
        except Exception as e:
            self._debug_print(f"Silent refresh with cached id_token failed: {e}")

        # Try refresh_token when id_token is expired
        try:
            new_id_token = self._try_refresh_token()
            if new_id_token:
                token_claims = jwt.decode(new_id_token, options={"verify_signature": False})
                credentials = self._call_tvm(new_id_token, self.otel_helper_status)
                self.save_credentials(credentials)
                self.save_monitoring_token(new_id_token, token_claims)
                self._debug_print("Silent credential refresh via refresh_token succeeded")
                return credentials, new_id_token, token_claims
        except QuotaExceededError:
            raise  # Don't swallow — must reach the user
        except Exception as e:
            self._debug_print(f"Silent refresh with refresh_token failed: {e}")

        return None, None, None

    def run(self):
        """Main execution flow"""
        try:
            self._log(f"run() profile={self.profile} provider={self.provider_type} federation={self.config.get('federation_type')}")
            # Environment fingerprint: surfaces HOME / AWS_PROFILE / storage / platform drift across invocations
            try:
                self._log(
                    f"env platform={platform.system()} release={platform.release()} "
                    f"python={platform.python_version()} arch={platform.machine()} "
                    f"home={Path.home()} storage={getattr(self, 'credential_storage', 'unknown')} "
                    f"aws_profile={os.getenv('AWS_PROFILE', '')} "
                    f"user={os.getenv('USER') or os.getenv('USERNAME', '')}"
                )
            except Exception:
                pass  # Diagnostic log must never break the run

            # 1. Check otel-helper integrity (records status, does NOT exit)
            self.otel_helper_status = self._check_otel_helper_integrity()
            self._log(f"otel_helper_status={self.otel_helper_status}")

            # 2. Check cache first — cached Bedrock credentials still valid
            cached = self.get_cached_credentials()
            if cached:
                self._log("using cached credentials")
                print(json.dumps(cached))
                return 0

            # 3. Try to acquire port lock
            bind_host = os.getenv("REDIRECT_BIND", "127.0.0.1")
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_socket.bind((bind_host, self.redirect_port))
                test_socket.close()
                self._debug_print("Port available, proceeding with authentication")
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    self._debug_print(f"Port {self.redirect_port} in use on {bind_host}, checking...")
                    test_socket.close()
                    cached = self._wait_for_auth_completion()
                    if cached:
                        print(json.dumps(cached))
                        return 0
                    # third_party branch: _wait_for_auth_completion already
                    # printed the port-busy message. timeout branch: another
                    # Claude Code window is still in front-of-browser — tell
                    # the user so they know to finish sign-in there.
                    if getattr(self, "_last_wait_result", None) == "timeout":
                        self._log("Authentication timeout waiting for another ccwb process")
                        mins = self._BROWSER_AUTH_TIMEOUT_SECONDS // 60
                        msg = (
                            "\n另一个 Claude Code 进程正在等待登录（浏览器可能已被关闭）。\n"
                            "你可以：\n"
                            "  • 在那个进程的终端中完成登录；或\n"
                            f"  • 等待它超时（最多约 {mins} 分钟）后，在此处重试。\n"
                        )
                        print(msg, file=sys.stderr, flush=True)
                    return 1
                else:
                    test_socket.close()
                    raise

            # 4. Check cache again (another process might have just finished)
            cached = self.get_cached_credentials()
            if cached:
                print(json.dumps(cached))
                return 0

            # 5. Try silent refresh (cached id_token -> refresh_token -> TVM)
            self._log("attempting silent refresh...")
            silent_creds, id_token, token_claims = self._try_silent_refresh()
            if silent_creds:
                self._log("silent refresh succeeded")
                print(json.dumps(silent_creds))
                return 0

            # 6. Browser auth (only when both id_token and refresh_token are expired)
            self._log("silent refresh failed, falling back to browser auth")
            self._debug_print(f"Authenticating with {self.provider_config['name']} for profile '{self.profile}'...")
            id_token, token_claims = self.authenticate_oidc()

            # 7. Save tokens
            self.save_monitoring_token(id_token, token_claims)

            # 8. Call TVM for Bedrock credentials
            self._log(f"calling TVM endpoint={self.config.get('tvm_endpoint')}")
            self._debug_print("Calling TVM Lambda for Bedrock credentials...")
            try:
                credentials = self._call_tvm(id_token, self.otel_helper_status)
                self._log("TVM returned credentials successfully")
            except TVMUnreachableError as e:
                # Full technical detail (endpoint, exception class) goes to the log
                # for support; the user sees a plain-language reason + next steps.
                self._log(
                    f"TVM UNREACHABLE: endpoint={self.config.get('tvm_endpoint')} detail={e}"
                )
                msg = (
                    "\n无法连接到 Bedrock 登录服务。\n\n"
                    "可能的原因：\n"
                    "  • 当前无网络连接，或处于需要登录的 WiFi 网络（酒店、机场等）。\n"
                    "  • VPN 未连接。\n"
                    "  • 防火墙拦截了访问 AWS 的 HTTPS 流量。\n\n"
                    "请检查网络后重试。\n"
                    "如果问题持续存在，请联系管理员。\n"
                )
                print(msg, file=sys.stderr, flush=True)
                return 1
            except TVMAuthRejectedError as e:
                self._log(f"TVM AUTH REJECTED: {e}")
                msg = (
                    "\n登录凭证已失效。请重新登录。\n"
                    "如果重试后仍失败，请联系管理员。\n"
                )
                print(msg, file=sys.stderr, flush=True)
                return 1
            except TVMAccessDeniedError as e:
                self._log(f"TVM ACCESS DENIED: {e}")
                msg = (
                    "\n你的账号没有访问 Bedrock 的权限。\n"
                    "请联系管理员确认你的账号配置。\n"
                )
                print(msg, file=sys.stderr, flush=True)
                return 1
            except TVMServiceError as e:
                self._log(f"TVM SERVICE ERROR: endpoint={self.config.get('tvm_endpoint')} detail={e}")
                msg = (
                    "\nBedrock 登录服务暂时不可用。\n"
                    "请稍后重试。如果问题持续存在，请联系管理员。\n"
                )
                print(msg, file=sys.stderr, flush=True)
                return 1
            except Exception as e:
                # Catch-all for unexpected errors from _call_tvm.
                self._log(f"TVM ERROR (unclassified): {e}")
                msg = (
                    "\n获取 Bedrock 凭证时出错。\n"
                    "请稍后重试；如果问题持续存在，请把日志文件\n"
                    "  ~/claude-code-with-bedrock/logs/credential-process.log\n"
                    "提供给管理员协助排查。\n"
                )
                print(msg, file=sys.stderr, flush=True)
                return 1

            # 9. Cache and output credentials
            self.save_credentials(credentials)
            print(json.dumps(credentials))
            return 0

        except BrowserAuthInProgressError as e:
            # Lock held by another process — don't open a second browser window.
            # Exit non-zero so the caller (boto3 / AWS CLI) gets a credential error
            # instead of hanging, but no stack trace.
            self._log(f"browser auth already in progress: {e}")
            print(f"\n{e}\n", file=sys.stderr)
            return 1
        except QuotaExceededError as e:
            self._log(f"QUOTA EXCEEDED: {e}")
            print(f"\n额度超限：{e}\n", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\n已取消登录。", file=sys.stderr)
            return 1
        except Exception as e:
            self._log(f"UNCLASSIFIED FAILURE: {type(e).__name__}: {e}")
            msg = (
                f"\n登录失败：{e}\n\n"
                f"详细日志见：~/claude-code-with-bedrock/logs/credential-process.log\n"
                f"如问题持续，请把该日志提供给管理员协助排查。\n"
            )
            print(msg, file=sys.stderr, flush=True)
            if self.debug:
                traceback.print_exc()
            return 1


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AWS credential provider for OIDC + Cognito Identity Pool")
    # Check environment variable first, then use default
    default_profile = os.getenv("CCWB_PROFILE", "ClaudeCode")
    parser.add_argument("--profile", "-p", default=default_profile, help="Configuration profile to use")
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--get-monitoring-token", action="store_true", help="Get cached monitoring token instead of AWS credentials"
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear cached credentials and force re-authentication"
    )
    parser.add_argument(
        "--check-expiration",
        action="store_true",
        help="Check if credentials need refresh (exit 0 if valid, 1 if expired)",
    )
    parser.add_argument(
        "--refresh-if-needed",
        action="store_true",
        help="Refresh credentials if expired (for cron jobs with session storage)",
    )

    args = parser.parse_args()

    try:
        auth = MultiProviderAuth(profile=args.profile)
    except Exception as e:
        print(f"配置错误：{e}", file=sys.stderr)
        sys.exit(1)

    # Handle cache clearing request
    if args.clear_cache:
        cleared = auth.clear_cached_credentials()
        if cleared:
            print(f"已清除 profile '{args.profile}' 的本地凭证缓存：", file=sys.stderr)
            for item in cleared:
                print(f"  • {item}", file=sys.stderr)
        else:
            print(f"profile '{args.profile}' 没有可清除的本地凭证缓存", file=sys.stderr)
        sys.exit(0)

    # Handle monitoring token request
    if args.get_monitoring_token:
        token = auth.get_monitoring_token()
        if token:
            print(token)
            sys.exit(0)
        else:
            # No cached token, trigger authentication to get one
            auth._debug_print("No valid monitoring token found, triggering authentication...")
            # Use the new monitoring-specific authentication method
            token = auth.authenticate_for_monitoring()
            if token:
                print(token)
                sys.exit(0)
            else:
                # Authentication failed or was cancelled
                # Return failure exit code so OTEL helper knows auth failed
                # This prevents OTEL helper from using default/unknown values
                sys.exit(1)

    # Handle check-expiration request
    if args.check_expiration:
        is_expired = auth.check_credentials_file_expiration(args.profile)
        if is_expired:
            print(f"profile '{args.profile}' 的凭证已过期或缺失", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"profile '{args.profile}' 的凭证仍有效", file=sys.stderr)
            sys.exit(0)

    # Handle refresh-if-needed request (for cron jobs with session storage)
    if args.refresh_if_needed:
        # Only works with session storage mode (credentials file)
        if auth.credential_storage != "session":
            print("错误：--refresh-if-needed 仅在 session 模式的凭证存储下可用", file=sys.stderr)
            sys.exit(1)

        is_expired = auth.check_credentials_file_expiration(args.profile)
        if not is_expired:
            # Credentials still valid, nothing to do
            auth._debug_print(f"Credentials still valid for profile '{args.profile}', no refresh needed")
            sys.exit(0)
        # Credentials expired, fall through to normal auth flow

    # Normal AWS credential flow (credential_process mode)
    # For session storage, this automatically uses ~/.aws/credentials
    sys.exit(auth.run())


if __name__ == "__main__":
    main()

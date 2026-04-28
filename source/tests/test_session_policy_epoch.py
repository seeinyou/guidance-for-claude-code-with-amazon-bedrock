# ABOUTME: Tests for TVM Lambda adaptive session duration computation
# ABOUTME: Verifies _compute_session_duration maps quota ratios to correct durations
"""Tests for TVM adaptive session duration and session policy."""

import pytest
import sys
import os

# Add Lambda function path for import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'deployment', 'infrastructure', 'lambda-functions', 'tvm'))


class TestComputeSessionDuration:
    """Tests for _compute_session_duration in TVM Lambda."""

    def _compute(self, usage, policy):
        """Import and call the function."""
        from index import _compute_session_duration
        return _compute_session_duration(usage, policy)

    def test_no_limits_returns_default(self):
        """No quota limits configured returns default 900s."""
        usage = {"estimated_cost": 50, "total_tokens": 1000, "daily_cost": 5, "daily_tokens": 100}
        policy = {"monthly_cost_limit": 0, "monthly_token_limit": 0, "daily_cost_limit": 0, "daily_token_limit": 0}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur == 900
        assert effective == 900

    def test_low_usage_returns_default(self):
        """Usage < 80% returns default 900s.

        Limits are sized so absolute remaining >= 10 units, otherwise
        Strategy 2 (absolute cost remaining) would shorten the session
        regardless of the ratio. Intent of this test is to verify the
        ratio-based path when the user is nowhere near any limit.
        """
        usage = {"estimated_cost": 50, "total_tokens": 500, "daily_cost": 5, "daily_tokens": 50}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 1000, "daily_cost_limit": 100, "daily_token_limit": 1000}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur == 900
        assert effective == 900

    def test_80_percent_returns_300s(self):
        """Usage 80-90% returns 300s."""
        usage = {"estimated_cost": 85, "total_tokens": 0, "daily_cost": 0, "daily_tokens": 0}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 0, "daily_cost_limit": 0, "daily_token_limit": 0}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur == 900  # STS minimum
        assert effective == 300

    def test_90_percent_returns_120s(self):
        """Usage 90-95% returns 120s."""
        usage = {"estimated_cost": 92, "total_tokens": 0, "daily_cost": 0, "daily_tokens": 0}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 0, "daily_cost_limit": 0, "daily_token_limit": 0}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur == 900
        assert effective == 120

    def test_95_percent_returns_60s(self):
        """Usage >= 95% returns 60s."""
        usage = {"estimated_cost": 96, "total_tokens": 0, "daily_cost": 0, "daily_tokens": 0}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 0, "daily_cost_limit": 0, "daily_token_limit": 0}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur == 900
        assert effective == 60

    def test_highest_ratio_wins(self):
        """When multiple dimensions, the highest ratio determines duration."""
        usage = {"estimated_cost": 10, "total_tokens": 960, "daily_cost": 1, "daily_tokens": 10}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 1000, "daily_cost_limit": 10, "daily_token_limit": 100}
        # monthly_tokens = 960/1000 = 96% → 60s (highest)
        sts_dur, effective = self._compute(usage, policy)
        assert effective == 60

    def test_sts_duration_minimum_900(self):
        """STS duration is always >= 900 regardless of effective."""
        usage = {"estimated_cost": 99, "total_tokens": 0, "daily_cost": 0, "daily_tokens": 0}
        policy = {"monthly_cost_limit": 100, "monthly_token_limit": 0, "daily_cost_limit": 0, "daily_token_limit": 0}
        sts_dur, effective = self._compute(usage, policy)
        assert sts_dur >= 900
        assert effective <= sts_dur


class TestAssumeRoleScoped:
    """Tests for _assume_role_for_user scoped vs unscoped behavior."""

    def _call(self, scoped, effective_seconds=900):
        """Invoke _assume_role_for_user with a mocked STS client."""
        from unittest.mock import patch
        from datetime import datetime, timezone

        import index

        fake_creds = {
            "AccessKeyId": "AKIA",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime(2030, 1, 1, tzinfo=timezone.utc),
        }

        captured = {}

        def fake_assume_role(**kwargs):
            captured["kwargs"] = kwargs
            return {"Credentials": fake_creds}

        with patch.object(index.sts_client, "assume_role", side_effect=fake_assume_role):
            with patch.object(index, "BEDROCK_USER_ROLE_ARN", "arn:aws:iam::123:role/r"):
                result = index._assume_role_for_user("alice@example.com", effective_seconds, scoped=scoped)
        return captured["kwargs"], result

    def test_unscoped_omits_policy(self):
        """Default (non-adaptive) mode does not send an inline Policy."""
        kwargs, result = self._call(scoped=False, effective_seconds=900)
        assert "Policy" not in kwargs
        # Native STS expiration preserved (year 2030 from the mock)
        assert result["Expiration"].startswith("2030-")

    def test_scoped_attaches_policy(self):
        """Adaptive mode attaches an aws:EpochTime-scoped inline policy."""
        import json as _json

        kwargs, result = self._call(scoped=True, effective_seconds=60)
        assert "Policy" in kwargs
        policy = _json.loads(kwargs["Policy"])
        stmt = policy["Statement"][0]
        assert stmt["Action"] == "bedrock:InvokeModel*"
        assert "aws:EpochTime" in stmt["Condition"]["NumericLessThan"]
        # Scoped expiration reflects the shorter window, not the STS default
        assert not result["Expiration"].startswith("2030-")

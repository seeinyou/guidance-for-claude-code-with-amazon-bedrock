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

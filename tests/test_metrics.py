"""Unit tests for Wilson score confidence intervals and metrics formatting."""

import pytest
from gauntlet.core.metrics import format_rate_with_ci, wilson_score_interval


def test_wilson_interval_zero_trials() -> None:
    """Verify handling of zero trials."""
    lower, upper = wilson_score_interval(0, 0)
    assert lower == 0.0
    assert upper == 0.0
    assert format_rate_with_ci(0, 0) == "0/0 (0.0%)"


def test_wilson_interval_zero_successes() -> None:
    """Verify confidence interval for 0/10 successes."""
    lower, upper = wilson_score_interval(0, 10, confidence=0.95)
    assert lower == 0.0
    assert 0.25 < upper < 0.35  # For 0/10, Wilson 95% upper bound is ~0.28
    formatted = format_rate_with_ci(0, 10)
    assert "0/10 (0.0% [0.0%, 27." in formatted or "0/10 (0.0% [0.0%, 28." in formatted


def test_wilson_interval_full_successes() -> None:
    """Verify confidence interval for 10/10 successes."""
    lower, upper = wilson_score_interval(10, 10, confidence=0.95)
    assert 0.65 < lower < 0.75  # For 10/10, Wilson 95% lower bound is ~0.717
    assert upper == 1.0
    formatted = format_rate_with_ci(10, 10)
    assert "10/10 (100.0%" in formatted
    assert ", 100.0%]" in formatted


def test_wilson_interval_half_successes() -> None:
    """Verify confidence interval for 5/10 successes."""
    lower, upper = wilson_score_interval(5, 10, confidence=0.95)
    assert 0.20 < lower < 0.26
    assert 0.74 < upper < 0.80
    assert lower < 0.50 < upper

"""Unit tests for Wilson score confidence intervals and metrics formatting."""

import pytest
from gauntlet.core.metrics import format_rate_with_ci, wilson_score_interval


def test_wilson_interval_zero_trials() -> None:
    """Verify handling of zero trials returning 'n/a'."""
    lower, upper = wilson_score_interval(0, 0)
    assert lower == 0.0
    assert upper == 0.0
    assert format_rate_with_ci(0, 0) == "n/a"


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
    assert 0.65 < lower < 0.75  # For 10/10, Wilson 95% lower bound is ~0.722
    assert upper == 1.0
    formatted = format_rate_with_ci(10, 10)
    assert "10/10 (100.0%" in formatted
    assert ", 100.0%]" in formatted


def test_wilson_interval_twenty_of_twenty_regression() -> None:
    """
    Regression test: 20/20 must yield ~[83.9%, 100.0%] Wilson interval,
    NOT the 10/10 interval (~[72.2%, 100.0%]).
    """
    lower, upper = wilson_score_interval(20, 20, confidence=0.95)
    assert round(lower * 100, 1) == 83.9
    assert upper == 1.0
    formatted = format_rate_with_ci(20, 20)
    assert formatted == "20/20 (100.0% [83.9%, 100.0%])"


def test_wilson_interval_aggregated_counts() -> None:
    """
    Verify Wilson score interval across aggregated scenario repetitions (e.g. 2 x 10 runs).
    """
    scen_1_passed, scen_1_total = 10, 10
    scen_2_passed, scen_2_total = 10, 10
    agg_passed = scen_1_passed + scen_2_passed
    agg_total = scen_1_total + scen_2_total

    lower, upper = wilson_score_interval(agg_passed, agg_total)
    assert agg_total == 20
    assert 0.83 < lower < 0.85
    assert upper == 1.0


def test_wilson_interval_half_successes() -> None:
    """Verify confidence interval for 5/10 successes."""
    lower, upper = wilson_score_interval(5, 10, confidence=0.95)
    assert 0.20 < lower < 0.26
    assert 0.74 < upper < 0.80
    assert lower < 0.50 < upper


"""Statistical metrics and confidence interval calculations for Gauntlet."""

import math
from typing import Tuple


def wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Calculate the Wilson score confidence interval for a binomial proportion.
    
    Args:
        k: Number of successes / occurrences.
        n: Total number of trials.
        confidence: Confidence level (default: 0.95).

    Returns:
        (lower_bound, upper_bound) as floats between 0.0 and 1.0.
    """
    if n <= 0:
        return 0.0, 0.0

    # z value for 95% confidence is 1.95996
    if abs(confidence - 0.95) < 0.001:
        z = 1.959963984540054
    elif abs(confidence - 0.99) < 0.001:
        z = 2.5758293035489004
    elif abs(confidence - 0.90) < 0.001:
        z = 1.6448536269514722
    else:
        # Standard normal inverse approximation
        z = 1.95996

    p_hat = float(k) / float(n)
    z_sq = z * z
    denom = 1.0 + (z_sq / n)
    center = (p_hat + (z_sq / (2.0 * n))) / denom
    margin = (z / denom) * math.sqrt((p_hat * (1.0 - p_hat) / n) + (z_sq / (4.0 * n * n)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    if k == 0:
        lower = 0.0
    if k == n:
        upper = 1.0

    return lower, upper


def format_rate_with_ci(k: int, n: int, confidence: float = 0.95) -> str:
    """Format a count k/n with percentage and Wilson 95% confidence interval."""
    if n <= 0:
        return "0/0 (0.0%)"
    pct = (k / n) * 100.0
    lower, upper = wilson_score_interval(k, n, confidence)
    return f"{k}/{n} ({pct:.1f}% [{lower * 100.0:.1f}%, {upper * 100.0:.1f}%])"

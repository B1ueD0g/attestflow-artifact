"""Small exact/descriptive statistics with no third-party dependency.

These routines do not choose a population or experimental unit.  Callers must
first collapse technical repeats to the preregistered independent unit.
"""

from __future__ import annotations

import math
import random
from statistics import NormalDist, fmean, median
from typing import Callable, Iterable, Sequence


def exact_binomial_two_sided(successes: int, trials: int, probability: float = 0.5) -> float:
    """Probability-ordering two-sided exact binomial p-value.

    For p=0.5 this agrees with the conventional doubled-tail form used by the
    exact McNemar test.  Probability ordering keeps the implementation correct
    for other null probabilities as well.
    """

    if not isinstance(successes, int) or not isinstance(trials, int):
        raise TypeError("successes and trials must be integers")
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("require 0 <= successes <= trials")
    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be in (0, 1)")
    if trials == 0:
        return 1.0

    def log_mass(k: int) -> float:
        return (
            math.lgamma(trials + 1)
            - math.lgamma(k + 1)
            - math.lgamma(trials - k + 1)
            + k * math.log(probability)
            + (trials - k) * math.log1p(-probability)
        )

    observed_log = log_mass(successes)
    eligible_logs = [
        candidate
        for k in range(trials + 1)
        if (candidate := log_mass(k)) <= observed_log + 1e-12
    ]
    maximum = max(eligible_logs)
    log_sum = maximum + math.log(sum(math.exp(value - maximum) for value in eligible_logs))
    return min(1.0, math.exp(log_sum))


def exact_mcnemar(a_only: int, b_only: int) -> dict[str, float | int | str]:
    """Two-sided exact McNemar comparison on discordant paired cases."""

    if any(not isinstance(value, int) for value in (a_only, b_only)):
        raise TypeError("discordant counts must be integers")
    if a_only < 0 or b_only < 0:
        raise ValueError("discordant counts must be non-negative")
    discordant = a_only + b_only
    return {
        "a_only": a_only,
        "b_only": b_only,
        "discordant_pairs": discordant,
        "p_value_two_sided_exact": exact_binomial_two_sided(a_only, discordant, 0.5),
        "method": "exact_mcnemar_binomial_probability_ordering",
    }


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""

    if not isinstance(successes, int) or not isinstance(trials, int):
        raise TypeError("successes and trials must be integers")
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("require trials > 0 and 0 <= successes <= trials")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    center = (proportion + z * z / (2.0 * trials)) / denominator
    half_width = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    ) / denominator
    return max(0.0, center - half_width), min(1.0, center + half_width)


def percentile(values: Sequence[float], quantile: float) -> float:
    """Linearly interpolated sample percentile (type-7 style)."""

    if not values:
        raise ValueError("values must be non-empty")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be in [0, 1]")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def paired_bootstrap_interval(
    values: Sequence[float],
    statistic: Callable[[Iterable[float]], float] = fmean,
    *,
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int = 20260902,
) -> tuple[float, float]:
    """Fixed-seed percentile bootstrap over independent paired-block effects."""

    if not values:
        raise ValueError("values must be non-empty")
    if resamples < 100:
        raise ValueError("resamples must be at least 100")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    numbers = tuple(float(value) for value in values)
    rng = random.Random(seed)
    estimates = [
        float(statistic(numbers[rng.randrange(len(numbers))] for _ in numbers))
        for _ in range(resamples)
    ]
    alpha = 1.0 - confidence
    return percentile(estimates, alpha / 2.0), percentile(estimates, 1.0 - alpha / 2.0)


def median_statistic(values: Iterable[float]) -> float:
    return float(median(list(values)))

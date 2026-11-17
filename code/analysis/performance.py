"""Paired fresh-process-block performance summaries."""

from __future__ import annotations

from collections import defaultdict
from statistics import fmean, median
from typing import Any, Iterable, Mapping

from .statistics import exact_binomial_two_sided, median_statistic, paired_bootstrap_interval


def paired_performance_summary(
    records: Iterable[Mapping[str, Any]],
    *,
    metric: str,
    treatment: str = "A_FULL",
    control: str = "NO_INSTRUMENTATION",
    confidence: float = 0.95,
    bootstrap_resamples: int = 10_000,
    seed: int = 20260902,
) -> dict[str, Any]:
    """Summarize block-level paired effects without treating requests as n."""

    by_block: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    duplicate_guard: set[tuple[str, str]] = set()
    all_block_ids: set[str] = set()
    for record in records:
        block_id = record.get("fresh_process_block_id")
        if not block_id:
            raise ValueError("every performance record requires fresh_process_block_id")
        block_id = str(block_id)
        all_block_ids.add(block_id)
        arm = str(record.get("arm", record.get("method", "")))
        if arm not in {treatment, control} or record.get("analysis_role") != "PRIMARY":
            continue
        pair_key = (block_id, arm)
        if pair_key in duplicate_guard:
            raise ValueError(f"duplicate PRIMARY performance record {pair_key}")
        duplicate_guard.add(pair_key)
        by_block[block_id][arm] = record

    differences: list[float] = []
    ratios: list[float] = []
    difference_block_ids: list[str] = []
    ratio_block_ids: list[str] = []
    unavailable: list[dict[str, str]] = []
    unavailable_ratios: list[dict[str, str]] = []
    for block_id in sorted(all_block_ids):
        pair = by_block.get(block_id, {})
        if treatment not in pair or control not in pair:
            unavailable.append({"fresh_process_block_id": block_id, "reason": "MISSING_ARM"})
            continue
        left = pair[treatment]
        right = pair[control]
        if any(
            field not in record
            for record in (left, right)
            for field in ("execution_status", "verdict")
        ):
            unavailable.append(
                {
                    "fresh_process_block_id": block_id,
                    "reason": "MISSING_EXECUTION_STATUS_OR_VERDICT",
                }
            )
            continue
        if (
            left["execution_status"] != "COMPLETE"
            or right["execution_status"] != "COMPLETE"
            or left["verdict"] not in {"PASS", "FAIL"}
            or right["verdict"] not in {"PASS", "FAIL"}
        ):
            unavailable.append({"fresh_process_block_id": block_id, "reason": "INDETERMINATE_OR_FAILED_ARM"})
            continue
        for blocking_field in ("host_id", "day_id", "build_id"):
            if left.get(blocking_field) != right.get(blocking_field):
                raise ValueError(f"{block_id}: paired arms differ on blocking field {blocking_field}")
        try:
            treatment_value = float(left[metric])
            control_value = float(right[metric])
        except (KeyError, TypeError, ValueError) as exc:
            unavailable.append({"fresh_process_block_id": block_id, "reason": f"INVALID_METRIC:{exc}"})
            continue
        if treatment_value < 0.0 or control_value < 0.0:
            raise ValueError("performance metrics must be non-negative")
        differences.append(treatment_value - control_value)
        difference_block_ids.append(block_id)
        if control_value == 0.0:
            unavailable_ratios.append(
                {
                    "fresh_process_block_id": block_id,
                    "reason": "ZERO_CONTROL_RATIO_DENOMINATOR",
                }
            )
            continue
        ratios.append(treatment_value / control_value)
        ratio_block_ids.append(block_id)

    difference_n = len(differences)
    ratio_n = len(ratios)
    positive = sum(value > 0.0 for value in differences)
    negative = sum(value < 0.0 for value in differences)
    sign_n = positive + negative
    output: dict[str, Any] = {
        "metric": metric,
        "treatment": treatment,
        "control": control,
        "independent_unit": "fresh_process_block_id",
        "n_scheduled_blocks": len(all_block_ids),
        "n_paired_blocks": difference_n,
        "n_difference_pairs": difference_n,
        "n_ratio_pairs": ratio_n,
        "paired_block_ids": difference_block_ids,
        "difference_paired_block_ids": difference_block_ids,
        "ratio_paired_block_ids": ratio_block_ids,
        "unavailable_pairs": unavailable,
        "unavailable_ratios": unavailable_ratios,
        "mean_difference": fmean(differences) if difference_n else None,
        "median_difference": median(differences) if difference_n else None,
        "mean_ratio": fmean(ratios) if ratio_n else None,
        "median_ratio": median(ratios) if ratio_n else None,
        "mean_difference_bootstrap_interval": None,
        "median_difference_bootstrap_interval": None,
        "mean_ratio_bootstrap_interval": None,
        "median_ratio_bootstrap_interval": None,
        "sign_test": {
            "positive_differences": positive,
            "negative_differences": negative,
            "ties_excluded": difference_n - sign_n,
            "p_value_two_sided_exact": exact_binomial_two_sided(positive, sign_n, 0.5),
        },
        "boundary": "Difference and ratio denominators are reported separately at the fresh-process-block level. A zero control keeps the difference pair but makes only its ratio unavailable; requests and within-process iterations are not independent observations.",
    }
    if difference_n:
        output["mean_difference_bootstrap_interval"] = list(
            paired_bootstrap_interval(
                differences, confidence=confidence, resamples=bootstrap_resamples, seed=seed
            )
        )
        output["median_difference_bootstrap_interval"] = list(
            paired_bootstrap_interval(
                differences,
                statistic=median_statistic,
                confidence=confidence,
                resamples=bootstrap_resamples,
                seed=seed + 1,
            )
        )
    if ratio_n:
        output["mean_ratio_bootstrap_interval"] = list(
            paired_bootstrap_interval(
                ratios, confidence=confidence, resamples=bootstrap_resamples, seed=seed + 2
            )
        )
        output["median_ratio_bootstrap_interval"] = list(
            paired_bootstrap_interval(
                ratios,
                statistic=median_statistic,
                confidence=confidence,
                resamples=bootstrap_resamples,
                seed=seed + 3,
            )
        )
    return output

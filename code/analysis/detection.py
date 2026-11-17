"""Paired defect-level detection accounting."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from .statistics import exact_mcnemar, wilson_interval


DETECTED = "DETECTED"
NOT_DETECTED = "NOT_DETECTED"
INDETERMINATE = "INDETERMINATE"
VALID_OUTCOMES = {DETECTED, NOT_DETECTED, INDETERMINATE}
VALID_EXECUTION_STATUSES = {"COMPLETE", "FAILED", "TIMEOUT", "CRASHED", "NOT_RUN"}
VALID_VERDICTS = {"PASS", "FAIL", "INDETERMINATE", "NOT_APPLICABLE"}
RegistrySource = Iterable[Mapping[str, Any]] | Mapping[str, Any]


def _outcome(record: Mapping[str, Any]) -> tuple[str, str | None]:
    value = record.get("detection_outcome")
    if value is None and "detected" in record:
        raw = record["detected"]
        if raw is True:
            value = DETECTED
        elif raw is False:
            value = NOT_DETECTED
        elif raw is None:
            value = INDETERMINATE
    if value is not None and value not in VALID_OUTCOMES:
        raise ValueError(f"invalid or missing detection outcome: {value!r}")

    missing_status_fields = [
        field
        for field in ("execution_status", "verdict")
        if field not in record or record.get(field) is None
    ]
    if missing_status_fields:
        return INDETERMINATE, "MISSING_" + "_AND_".join(missing_status_fields).upper()
    execution_status = record["execution_status"]
    verdict = record["verdict"]
    if execution_status not in VALID_EXECUTION_STATUSES:
        raise ValueError(f"invalid execution_status: {execution_status!r}")
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"invalid verdict: {verdict!r}")
    if execution_status != "COMPLETE":
        return INDETERMINATE, f"EXECUTION_STATUS_{execution_status}"
    if verdict in {"INDETERMINATE", "NOT_APPLICABLE"}:
        return INDETERMINATE, f"VERDICT_{verdict}"

    telemetry_valid = (
        record.get("trace_complete") is True and record.get("observer_chain_valid") is True
    )
    if not telemetry_valid:
        if value not in {None, INDETERMINATE}:
            raise ValueError("invalid telemetry/observer must be INDETERMINATE")
        return INDETERMINATE, "TELEMETRY_OR_OBSERVER_INCOMPLETE"
    if value is None:
        return INDETERMINATE, "MISSING_DETECTION_OUTCOME"
    return str(value), None


def _registry_rows(case_registry: RegistrySource) -> list[Mapping[str, Any]]:
    if not isinstance(case_registry, Mapping):
        return list(case_registry)
    cells = case_registry.get("cells")
    if not isinstance(cells, list) or not all(isinstance(cell, Mapping) for cell in cells):
        raise ValueError("case_registry mapping must contain a list of mapping-valued cells")
    return cells


def _case_id(record: Mapping[str, Any]) -> str:
    return str(record.get("defect_case_id", record.get("case_id", ""))).strip()


def _method(record: Mapping[str, Any]) -> str:
    return str(record.get("method", record.get("arm", ""))).strip()


def _normalized_case_kind(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid case_kind={value!r}")
    return value.strip().casefold()


def _sensitivity_contribution(a: str, b: str) -> tuple[int, int]:
    """Return minimum and maximum possible value of A-B for one pair."""

    possibilities_a = (0, 1) if a == INDETERMINATE else (1,) if a == DETECTED else (0,)
    possibilities_b = (0, 1) if b == INDETERMINATE else (1,) if b == DETECTED else (0,)
    values = [left - right for left in possibilities_a for right in possibilities_b]
    return min(values), max(values)


def paired_detection_summary(
    records: Iterable[Mapping[str, Any]],
    *,
    case_registry: RegistrySource,
    schedule_records: Iterable[Mapping[str, Any]],
    method_a: str = "A_FULL",
    method_b: str,
    split: str = "held_out",
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Summarize one preselected paired method comparison.

    The frozen registry and schedule define the analysis universe.  Result rows
    are left-joined to scheduled PRIMARY rows; absence or incomplete status is
    represented as INDETERMINATE rather than deleted.  Each method contributes
    at most one PRIMARY result per defect case.  Clean controls and excluded
    cases remain accounted for but do not enter defect recall or McNemar counts.
    """

    registry_by_case: dict[str, Mapping[str, Any]] = {}
    for case in _registry_rows(case_registry):
        case_id = _case_id(case)
        if not case_id or case_id in registry_by_case:
            raise ValueError(f"missing or duplicate registry case_id={case_id!r}")
        _normalized_case_kind(case.get("case_kind"))
        registry_by_case[case_id] = case

    expected: dict[tuple[str, str], Mapping[str, Any]] = {}
    schedule_id_to_key: dict[str, tuple[str, str]] = {}
    all_schedule_ids: set[str] = set()
    for scheduled in schedule_records:
        case_id = _case_id(scheduled)
        if not case_id or case_id not in registry_by_case:
            raise ValueError(f"scheduled row references unknown case_id={case_id!r}")
        registry_case = registry_by_case[case_id]
        if scheduled.get("split") != registry_case.get("split"):
            raise ValueError(f"schedule/registry split mismatch for case_id={case_id!r}")
        if _normalized_case_kind(scheduled.get("case_kind")) != _normalized_case_kind(
            registry_case.get("case_kind")
        ):
            raise ValueError(f"schedule/registry case_kind mismatch for case_id={case_id!r}")
        schedule_id = str(scheduled.get("schedule_id", "")).strip()
        if schedule_id:
            if schedule_id in all_schedule_ids:
                raise ValueError(f"duplicate schedule_id={schedule_id!r}")
            all_schedule_ids.add(schedule_id)
        method = _method(scheduled)
        if scheduled.get("analysis_role") != "PRIMARY" or method not in {method_a, method_b}:
            continue
        key = (case_id, method)
        if key in expected:
            raise ValueError(f"duplicate scheduled PRIMARY case/method {key}")
        expected[key] = scheduled
        if schedule_id:
            schedule_id_to_key[schedule_id] = key

    target_cases = {
        case_id
        for case_id, case in registry_by_case.items()
        if case.get("split") == split
    }
    for case_id in sorted(target_cases):
        for method in (method_a, method_b):
            if (case_id, method) not in expected:
                raise ValueError(f"frozen schedule lacks PRIMARY row for {(case_id, method)}")

    joined: dict[tuple[str, str], Mapping[str, Any] | None] = {
        key: None for key in expected if key[0] in target_cases
    }
    duplicate_guard: set[tuple[str, str]] = set()
    incomplete_records: list[dict[str, str]] = []
    for record in records:
        schedule_id = str(record.get("schedule_id", "")).strip()
        if schedule_id:
            result_key = schedule_id_to_key.get(schedule_id)
            if result_key is None:
                if schedule_id in all_schedule_ids:
                    continue
                raise ValueError(f"result references unknown schedule_id={schedule_id!r}")
            explicit_case_id = _case_id(record)
            explicit_method = _method(record)
            if explicit_case_id and explicit_case_id != result_key[0]:
                raise ValueError(f"result/schedule case_id mismatch for schedule_id={schedule_id!r}")
            if explicit_method and explicit_method != result_key[1]:
                raise ValueError(f"result/schedule method mismatch for schedule_id={schedule_id!r}")
        else:
            result_key = (_case_id(record), _method(record))
            if result_key not in expected:
                result_split = record.get("split")
                if result_split is not None and result_split != split:
                    continue
                raise ValueError(
                    f"result does not match a frozen scheduled case/method: {result_key}"
                )
        if result_key[0] not in target_cases:
            continue
        if record.get("analysis_role") != "PRIMARY":
            incomplete_records.append(
                {
                    "case_id": result_key[0],
                    "method": result_key[1],
                    "reason": "NON_PRIMARY_RESULT",
                }
            )
            continue
        if result_key in duplicate_guard:
            raise ValueError(f"duplicate PRIMARY result for case/method {result_key}")
        duplicate_guard.add(result_key)
        joined[result_key] = record

    paired: dict[str, dict[str, str]] = defaultdict(dict)
    clean_counts: Counter[str] = Counter()
    specificity_counts: Counter[str] = Counter()
    specificity_case_ids: set[str] = set()
    exclusions: list[dict[str, Any]] = []
    missing_results: list[dict[str, str]] = []

    for (case_id, method), row in sorted(joined.items()):
        case = registry_by_case[case_id]
        exclusion = case.get("exclusion")
        if exclusion:
            exclusions.append({"case_id": case_id, "method": method, "exclusion": exclusion})
            continue
        if row is None:
            scheduled = expected[(case_id, method)]
            missing_results.append(
                {
                    "case_id": case_id,
                    "method": method,
                    "schedule_id": str(scheduled.get("schedule_id", "")),
                }
            )
            outcome = INDETERMINATE
        else:
            outcome, incomplete_reason = _outcome(row)
            if incomplete_reason is not None:
                incomplete_records.append(
                    {"case_id": case_id, "method": method, "reason": incomplete_reason}
                )
        case_kind = _normalized_case_kind(case.get("case_kind"))
        if case_kind == "clean":
            clean_counts[f"{method}:{outcome}"] += 1
        elif case_kind == "specificity_control":
            specificity_counts[f"{method}:{outcome}"] += 1
            specificity_case_ids.add(case_id)
        else:
            paired[case_id][method] = outcome

    counts: Counter[str] = Counter()
    sensitivity_min = 0
    sensitivity_max = 0
    method_detected = {method_a: 0, method_b: 0}
    method_determinate = {method_a: 0, method_b: 0}
    pair_details: list[dict[str, str]] = []
    for case_id in sorted(paired):
        left = paired[case_id].get(method_a, INDETERMINATE)
        right = paired[case_id].get(method_b, INDETERMINATE)
        pair_details.append({"case_id": case_id, method_a: left, method_b: right})
        for method, value in ((method_a, left), (method_b, right)):
            if value != INDETERMINATE:
                method_determinate[method] += 1
                if value == DETECTED:
                    method_detected[method] += 1
        low, high = _sensitivity_contribution(left, right)
        sensitivity_min += low
        sensitivity_max += high
        if INDETERMINATE in {left, right}:
            counts["indeterminate_pair"] += 1
        elif left == DETECTED and right == DETECTED:
            counts["both_detect"] += 1
        elif left == DETECTED and right == NOT_DETECTED:
            counts["a_only"] += 1
        elif left == NOT_DETECTED and right == DETECTED:
            counts["baseline_only"] += 1
        else:
            counts["neither"] += 1

    n_eligible = len(paired)
    n_analyzable = n_eligible - counts["indeterminate_pair"]
    output: dict[str, Any] = {
        "method_a": method_a,
        "method_b": method_b,
        "split": split,
        "independent_unit": "defect_case_id",
        "n_eligible_defect_cases": n_eligible,
        "n_complete_pairs": n_analyzable,
        "n_expected_schedule_rows": len(joined),
        "n_missing_scheduled_results": len(missing_results),
        "n_incomplete_result_records": len(incomplete_records),
        "counts": {
            name: counts[name]
            for name in ("both_detect", "a_only", "baseline_only", "neither", "indeterminate_pair")
        },
        "mcnemar_complete_case": exact_mcnemar(counts["a_only"], counts["baseline_only"]),
        "paired_difference_complete_case": (
            (counts["a_only"] - counts["baseline_only"]) / n_analyzable if n_analyzable else None
        ),
        "paired_difference_sensitivity_bounds_all_eligible": (
            [sensitivity_min / n_eligible, sensitivity_max / n_eligible] if n_eligible else None
        ),
        "recall_determinate": {},
        "clean_control_counts": dict(sorted(clean_counts.items())),
        "n_specificity_control_cases": len(specificity_case_ids),
        "specificity_control_counts": dict(sorted(specificity_counts.items())),
        "specificity_false_positive_determinate": {},
        "excluded_method_records": exclusions,
        "missing_scheduled_results": missing_results,
        "incomplete_result_records": incomplete_records,
        "pair_details": pair_details,
        "boundary": "The frozen registry/schedule is the left-join universe. Exact testing uses only complete determinate defect pairs; CLEAN and SPECIFICITY_CONTROL cases never enter defect recall or McNemar denominators and are reported separately. Missing, incomplete, indeterminate, and excluded cells remain visible.",
        "specificity_boundary": "For frozen SPECIFICITY_CONTROL cases, DETECTED is counted as a false positive. Rates use determinate specificity outcomes only; INDETERMINATE outcomes remain in the outcome counts and outside that denominator.",
    }
    for method in (method_a, method_b):
        n = method_determinate[method]
        successes = method_detected[method]
        output["recall_determinate"][method] = {
            "detected": successes,
            "determinate": n,
            "estimate": successes / n if n else None,
            "wilson_interval": list(wilson_interval(successes, n, confidence)) if n else None,
        }
        false_positives = specificity_counts[f"{method}:{DETECTED}"]
        specificity_determinate = false_positives + specificity_counts[
            f"{method}:{NOT_DETECTED}"
        ]
        output["specificity_false_positive_determinate"][method] = {
            "false_positives": false_positives,
            "determinate": specificity_determinate,
            "estimate": (
                false_positives / specificity_determinate
                if specificity_determinate
                else None
            ),
            "wilson_interval": (
                list(wilson_interval(false_positives, specificity_determinate, confidence))
                if specificity_determinate
                else None
            ),
        }
    return output

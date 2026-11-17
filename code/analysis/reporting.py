"""Transparent indeterminate/exclusion accounting."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping


def audit_case_accounting(
    case_registry: Iterable[Mapping[str, Any]],
    result_records: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Account for every frozen case without turning absence into success."""

    cases: dict[str, Mapping[str, Any]] = {}
    for case in case_registry:
        case_id = str(case.get("case_id", ""))
        if not case_id or case_id in cases:
            raise ValueError(f"missing or duplicate registry case_id={case_id!r}")
        cases[case_id] = case

    by_case: dict[str, list[Mapping[str, Any]]] = {case_id: [] for case_id in cases}
    orphan_results: list[str] = []
    for record in result_records:
        case_id = str(record.get("case_id", record.get("defect_case_id", "")))
        if case_id not in by_case:
            orphan_results.append(case_id)
        else:
            by_case[case_id].append(record)

    status_counts: Counter[str] = Counter()
    exclusions_by_reason: Counter[str] = Counter()
    indeterminate_by_reason: Counter[str] = Counter()
    details: list[dict[str, Any]] = []
    for case_id in sorted(cases):
        case = cases[case_id]
        exclusion = case.get("exclusion")
        records = by_case[case_id]
        if exclusion:
            reason = str(exclusion.get("reason", "UNSPECIFIED"))
            outputs_seen = bool(exclusion.get("method_outputs_seen", False))
            status = "POST_RESULT_EXCLUSION_PROTOCOL_DEVIATION" if outputs_seen else "PREREGISTERED_EXCLUSION"
            exclusions_by_reason[reason] += 1
        elif not records:
            status = "MISSING_RESULT_INDETERMINATE"
            indeterminate_by_reason["MISSING_RESULT"] += 1
        elif any(
            field not in record or record.get(field) is None
            for record in records
            for field in ("execution_status", "verdict")
        ):
            status = "HAS_MISSING_STATUS_INDETERMINATE"
            for record in records:
                if record.get("execution_status") is None:
                    indeterminate_by_reason["MISSING_EXECUTION_STATUS"] += 1
                if record.get("verdict") is None:
                    indeterminate_by_reason["MISSING_VERDICT"] += 1
        elif any(record.get("verdict") == "INDETERMINATE" for record in records):
            status = "HAS_INDETERMINATE"
            for record in records:
                if record.get("verdict") == "INDETERMINATE":
                    indeterminate_by_reason[str(record.get("reason", "UNSPECIFIED"))] += 1
        elif any(record.get("execution_status") != "COMPLETE" for record in records):
            status = "HAS_FAILED_EXECUTION_INDETERMINATE"
            for record in records:
                if record.get("execution_status") != "COMPLETE":
                    indeterminate_by_reason[str(record.get("execution_status", "UNKNOWN"))] += 1
        else:
            status = "RECORDED_DETERMINATE"
        status_counts[status] += 1
        details.append(
            {
                "case_id": case_id,
                "status": status,
                "record_count": len(records),
                "exclusion": exclusion,
            }
        )
    return {
        "frozen_case_count": len(cases),
        "status_counts": dict(sorted(status_counts.items())),
        "exclusions_by_reason": dict(sorted(exclusions_by_reason.items())),
        "indeterminate_by_reason": dict(sorted(indeterminate_by_reason.items())),
        "orphan_result_case_ids": sorted(orphan_results),
        "case_details": details,
        "boundary": "Missing, failed, and excluded cases remain visible; no category is silently mapped to PASS.",
    }

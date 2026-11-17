"""Post-hoc evaluation that joins frozen predictions with ground truth."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .loader import BENCHMARK_ROOT, load_json


def _edge_set(items: list[dict[str, str]]) -> frozenset[tuple[str, str]]:
    return frozenset((item["from"], item["to"]) for item in items)


def evaluate_predictions(prediction_payload: dict[str, Any]) -> dict[str, Any]:
    """Load ground truth only after receiving an already materialized payload."""

    if prediction_payload.get("ground_truth_read_during_prediction") is not False:
        raise ValueError("prediction provenance does not prove ground-truth separation")
    ground_truth_payload = load_json(BENCHMARK_ROOT / "ground_truth" / "cases.json")
    truth = {item["case_id"]: item for item in ground_truth_payload["cases"]}
    predictions = {
        item["case_id"]: item for item in prediction_payload["predictions"]
    }
    if predictions.keys() != truth.keys():
        missing = sorted(truth.keys() - predictions.keys())
        extra = sorted(predictions.keys() - truth.keys())
        raise ValueError(f"prediction case mismatch; missing={missing}; extra={extra}")

    rows: list[dict[str, Any]] = []
    for case_id in sorted(truth):
        expected = truth[case_id]
        observed = predictions[case_id]
        status_match = observed["status"] == expected["expected_analysis"]
        effect_match = (
            observed["positive_effect_count"] == 1
            and bool(observed["test_effect_count"])
            == bool(expected["expected_test_effect"])
        )
        frontier_match: bool | None
        if expected["expected_analysis"] == "FAIL":
            frontier_match = _edge_set(observed["candidate_frontier"]) == _edge_set(
                expected["minimal_loss_frontier"]
            )
        else:
            frontier_match = None
        exact_match = status_match and effect_match and frontier_match is not False
        rows.append(
            {
                "case_id": case_id,
                "family_id": expected["family_id"],
                "split": expected["split"],
                "case_class": expected["case_class"],
                "status_match": status_match,
                "effect_match": effect_match,
                "frontier_match": frontier_match,
                "exact_match": exact_match,
            }
        )

    by_status = Counter(item["expected_analysis"] for item in truth.values())
    return {
        "schema_version": "1.0",
        "benchmark_kind": "synthetic_local_fixture",
        "ground_truth_loaded_after_predictions": True,
        "case_count": len(rows),
        "exact_match_count": sum(item["exact_match"] for item in rows),
        "all_exact": all(item["exact_match"] for item in rows),
        "expected_status_counts": dict(sorted(by_status.items())),
        "rows": rows,
        "evidence_boundary": (
            "Fixture QA only; not evidence for real RATS stacks, natural defects, "
            "held-out external validation, or AttestFlow effectiveness."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    with arguments.predictions.open("r", encoding="utf-8") as handle:
        prediction_payload = json.load(handle)
    report = evaluate_predictions(prediction_payload)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.report:
        arguments.report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["all_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())


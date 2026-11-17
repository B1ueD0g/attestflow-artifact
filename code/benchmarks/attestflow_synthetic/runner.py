"""Run the synthetic suite and emit predictions without reading ground truth."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .adapter import SyntheticFixtureAdapter
from .analyzer import ReferenceContinuityAnalyzer
from .api import ObservationAnalyzer
from .core_analyzer import CoreObservationAnalyzer
from .loader import BENCHMARK_ROOT, load_contract, load_families, load_scenarios, load_variants


def _contract_sha256(family: dict[str, Any]) -> str:
    path = BENCHMARK_ROOT / family["contract_file"]
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_predictions(
    analyzer: ObservationAnalyzer | None = None,
    variants: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Produce predictions; no ground-truth artifact is opened here."""

    selected_analyzer = analyzer or CoreObservationAnalyzer()
    families = load_families()
    scenarios = load_scenarios()
    selected_variants = list(variants) if variants is not None else load_variants()
    predictions: list[dict[str, Any]] = []
    for variant in selected_variants:
        family = families[variant["family_id"]]
        if variant["split"] != family["split"]:
            raise ValueError(f"split mismatch for {variant['case_id']}")
        contract = load_contract(family)
        positive = scenarios[variant["positive_scenario_id"]]
        test = scenarios[variant["test_scenario_id"]]
        input_source = "checked_in_fixture_scenario"
        prepare_inputs = getattr(selected_analyzer, "prepare_fixture_inputs", None)
        if callable(prepare_inputs):
            positive, test = prepare_inputs(contract, positive, test)
            input_source = "attestflow_compiler"
        adapter = SyntheticFixtureAdapter(family, contract, variant)
        observation = adapter.execute_pair(positive, test)

        # The analyzer sees only these two arguments. Variant metadata is used
        # by the fixture adapter but is neither embedded in observations nor
        # provided to the analyzer.
        analysis = selected_analyzer.analyze_pair(contract, observation)
        record = {
            "case_id": variant["case_id"],
            "build_id": variant["build_id"],
            "family_id": variant["family_id"],
            "split": variant["split"],
            "synthetic": True,
            "contract_id": contract["contract_id"],
            "contract_sha256": _contract_sha256(family),
            "input_source": input_source,
            **analysis.as_dict(),
        }
        predictions.append(record)
    return {
        "schema_version": "1.0",
        "benchmark_kind": "synthetic_local_fixture",
        "analyzer": type(selected_analyzer).__name__,
        "ground_truth_read_during_prediction": False,
        "predictions": predictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--analyzer",
        choices=("core", "reference"),
        default="core",
        help="real AttestFlow core (default) or fixture-only reference analyzer",
    )
    parser.add_argument(
        "--predictions",
        type=Path,
        help="optional JSON output path; stdout is used when omitted",
    )
    arguments = parser.parse_args()
    selected_analyzer: ObservationAnalyzer
    if arguments.analyzer == "core":
        selected_analyzer = CoreObservationAnalyzer()
    else:
        selected_analyzer = ReferenceContinuityAnalyzer()
    payload = run_predictions(selected_analyzer)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if arguments.predictions:
        arguments.predictions.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Load public fixtures and private SUT variants without loading ground truth."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .api import TrialInput


BENCHMARK_ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_families() -> dict[str, dict[str, Any]]:
    payload = load_json(BENCHMARK_ROOT / "manifests" / "families.json")
    return {item["family_id"]: item for item in payload["families"]}


def load_contract(family: dict[str, Any]) -> dict[str, Any]:
    return load_json(BENCHMARK_ROOT / family["contract_file"])


def load_scenarios() -> dict[str, TrialInput]:
    payload = load_json(BENCHMARK_ROOT / "inputs" / "scenarios.json")
    result: dict[str, TrialInput] = {}
    for item in payload["scenarios"]:
        trial = TrialInput(
            scenario_id=item["scenario_id"],
            family_id=item["family_id"],
            role=item["role"],
            actual_value=item["actual_value"],
            expected_value=item["expected_value"],
            policy_epoch=int(item["policy_epoch"]),
            request_id=item["request_id"],
            irrelevant_label=item["irrelevant_label"],
            changed_fields=tuple(item["changed_fields"]),
        )
        if trial.scenario_id in result:
            raise ValueError(f"duplicate scenario ID: {trial.scenario_id}")
        result[trial.scenario_id] = trial
    return result


def load_variants() -> list[dict[str, Any]]:
    payload = load_json(BENCHMARK_ROOT / "variants" / "variants.json")
    return list(payload["variants"])

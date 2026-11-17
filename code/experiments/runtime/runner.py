"""Schedule-complete synthetic execution and formal-ledger projection."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from analysis.ledger import append_record, validate_ledger

from .arms import ArmExecutor
from .models import (
    ARM_IDS,
    DEFAULT_BUDGET,
    ArmBudget,
    ArmExecution,
    ArmResult,
    RunBundle,
    SchedulePlan,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ROOT = PROJECT_ROOT / "experiments" / "protocols"
DEFAULT_SCHEDULE = PROTOCOL_ROOT / "schedule.v1.csv"
SCHEDULE_META = PROTOCOL_ROOT / "schedule.v1.meta.json"
SCHEDULE_CASES = PROTOCOL_ROOT / "schedule-cases.v1.json"
PREREGISTRATION = PROTOCOL_ROOT / "attestflow-preregistration.v1.json"
BLANK_LEDGER = PROTOCOL_ROOT / "run-ledger.blank.json"
LEDGER_SCHEMA = PROTOCOL_ROOT / "run-ledger.schema.json"


class ScheduleValidationError(ValueError):
    pass


def render_json(value: Any) -> str:
    """Stable human-readable bytes used for both writing and hashing."""

    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def json_digest(value: Any) -> str:
    return hashlib.sha256(render_json(value).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ScheduleValidationError(f"expected JSON object: {path}")
    return value


def _expected_cell_fields(cell: Mapping[str, Any]) -> dict[str, str]:
    return {
        "experiment_id": str(cell["experiment_id"]),
        "supports_experiment_ids": ";".join(cell["supports_experiment_ids"]),
        "split": str(cell["split"]),
        "stack_id": str(cell["stack_id"]),
        "defect_family": str(cell["defect_family"]),
        "build_id": str(cell["build_id"]),
        "case_kind": str(cell["case_kind"]),
        "case_id": str(cell["case_id"]),
        "independent_unit_kind": str(cell["independent_unit_kind"]),
        "independent_unit_id": str(cell["independent_unit_id"]),
    }


def validate_schedule_rows(
    rows: Iterable[Mapping[str, str]],
    *,
    protocol_id: str,
    registry_version: str,
    registry_cells: Iterable[Mapping[str, Any]],
    expected_arms: Iterable[str] = ARM_IDS,
) -> tuple[Mapping[str, str], ...]:
    """Reject partial, duplicated, or registry-divergent schedule allocations."""

    materialized = tuple(dict(row) for row in rows)
    arms = tuple(expected_arms)
    if set(arms) != set(ARM_IDS) or len(arms) != len(ARM_IDS):
        raise ScheduleValidationError("preregistration arm set does not match B0--B3/A ablations")
    required_fields = {
        "schedule_sequence",
        "schedule_id",
        "protocol_id",
        "registry_version",
        "global_seed",
        "derived_block_seed",
        "block_id",
        "arm_order_in_case",
        "experiment_id",
        "split",
        "stack_id",
        "defect_family",
        "build_id",
        "case_kind",
        "case_id",
        "arm",
        "independent_unit_kind",
        "independent_unit_id",
        "process_instance_id",
        "analysis_role",
        "hardware_required",
        "execution_state",
    }
    if not materialized:
        raise ScheduleValidationError("schedule has no rows")
    for index, row in enumerate(materialized, start=1):
        missing = sorted(required_fields - row.keys())
        if missing:
            raise ScheduleValidationError(f"schedule row {index} lacks fields: {missing}")
        if any(row[field] in (None, "") for field in required_fields):
            raise ScheduleValidationError(f"schedule row {index} contains an empty required field")
        if row["schedule_sequence"] != str(index):
            raise ScheduleValidationError(f"non-contiguous schedule_sequence at row {index}")
        if row["protocol_id"] != protocol_id:
            raise ScheduleValidationError(f"protocol mismatch at schedule row {index}")
        if row["registry_version"] != registry_version:
            raise ScheduleValidationError(f"registry version mismatch at schedule row {index}")
        if row["analysis_role"] != "PRIMARY":
            raise ScheduleValidationError("v1 synthetic schedule may contain only PRIMARY rows")
        if row["hardware_required"] != "false":
            raise ScheduleValidationError("synthetic runner refuses hardware-required rows")
        if row["execution_state"] != "SCHEDULED":
            raise ScheduleValidationError("input schedule contains result state")
        if row["arm"] not in arms:
            raise ScheduleValidationError(f"unimplemented scheduled arm: {row['arm']}")
        if row["experiment_id"] == "E9":
            raise ScheduleValidationError("E9 is PREPARED_ONLY and cannot be executed")

    schedule_ids = [row["schedule_id"] for row in materialized]
    process_ids = [row["process_instance_id"] for row in materialized]
    if len(schedule_ids) != len(set(schedule_ids)):
        raise ScheduleValidationError("duplicate schedule_id")
    if len(process_ids) != len(set(process_ids)):
        raise ScheduleValidationError("duplicate process_instance_id")

    materialized_cells = tuple(registry_cells)
    cells = {str(cell["case_id"]): cell for cell in materialized_cells}
    if len(cells) != len(materialized_cells):
        raise ScheduleValidationError("duplicate case id in schedule registry")
    by_case: dict[str, list[Mapping[str, str]]] = defaultdict(list)
    for row in materialized:
        case_id = row["case_id"]
        if case_id not in cells:
            raise ScheduleValidationError(f"unregistered schedule case: {case_id}")
        by_case[case_id].append(row)
        expected = _expected_cell_fields(cells[case_id])
        mismatches = [
            f"{field}={row.get(field)!r} expected {value!r}"
            for field, value in expected.items()
            if row.get(field) != value
        ]
        if mismatches:
            raise ScheduleValidationError(
                f"schedule registry mismatch for {case_id}: " + "; ".join(mismatches)
            )
    if set(by_case) != set(cells):
        missing_cases = sorted(set(cells) - set(by_case))
        raise ScheduleValidationError(f"schedule omits registry cases: {missing_cases}")
    for case_id, group in by_case.items():
        observed = [row["arm"] for row in group]
        if len(observed) != len(arms) or set(observed) != set(arms):
            raise ScheduleValidationError(
                f"case {case_id} does not allocate every arm exactly once"
            )
        positions = sorted(int(row["arm_order_in_case"]) for row in group)
        if positions != list(range(1, len(arms) + 1)):
            raise ScheduleValidationError(f"case {case_id} has invalid arm positions")
    return materialized


def load_frozen_schedule(path: str | Path = DEFAULT_SCHEDULE) -> SchedulePlan:
    """Load and cross-check the frozen v1 schedule without mutating it."""

    resolved = Path(path).resolve()
    raw = resolved.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    meta_path = resolved.with_name("schedule.v1.meta.json")
    if not meta_path.is_file():
        raise ScheduleValidationError(f"schedule metadata is required: {meta_path}")
    meta = _read_json(meta_path)
    if digest != meta.get("schedule_file_sha256"):
        raise ScheduleValidationError("schedule file digest differs from frozen metadata")
    with resolved.open("r", encoding="utf-8", newline="") as handle:
        rows = tuple(csv.DictReader(handle))
    if len(rows) != int(meta.get("schedule_rows", -1)):
        raise ScheduleValidationError("schedule row count differs from frozen metadata")
    preregistration = _read_json(PREREGISTRATION)
    registry = _read_json(SCHEDULE_CASES)
    if preregistration["protocol_id"] != registry["protocol_id"]:
        raise ScheduleValidationError("preregistration/registry protocol mismatch")
    if meta.get("protocol_id") != preregistration["protocol_id"]:
        raise ScheduleValidationError("schedule metadata protocol mismatch")
    expected_arms = tuple(preregistration["arms"]["defect_arms"])
    validated = validate_schedule_rows(
        rows,
        protocol_id=str(registry["protocol_id"]),
        registry_version=str(registry["registry_version"]),
        registry_cells=tuple(registry["cells"]),
        expected_arms=expected_arms,
    )
    return SchedulePlan(
        path=str(resolved),
        sha256=digest,
        protocol_id=str(registry["protocol_id"]),
        rows=validated,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _trial_metadata(run: Any) -> dict[str, Any]:
    return {
        "scenario_id": run.trial.scenario_id,
        "role": run.trial.role,
        "request_id": run.trial.request_id,
        "changed_fields": list(run.trial.changed_fields),
        "raw_endpoint_values_recorded": False,
    }


def _execution_artifact(
    row: Mapping[str, str],
    execution: ArmExecution,
    *,
    execution_status: str,
    result: ArmResult,
    started_at: str,
    finished_at: str,
    elapsed_ms: float,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_kind": "attestflow_synthetic_arm_execution",
        "synthetic_fixture_only": True,
        "contains_confirmatory_result": False,
        "evidence_level": "E2_LOCAL_SYNTHETIC_CHECK",
        "schedule_row": dict(row),
        "arm_profile": execution.profile.as_dict(),
        "arm_profile_sha256": execution.profile.fingerprint,
        "equal_budget": execution.budget.as_dict(),
        "execution_status": execution_status,
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "elapsed_ms": elapsed_ms,
        "inputs": {
            "positive": _trial_metadata(execution.pair.positive),
            "test": _trial_metadata(execution.pair.test),
        },
        "observations": {
            "positive": {
                "trace_events": [event.as_dict() for event in execution.pair.positive.trace_events],
                "effect_records": [record.as_dict() for record in execution.pair.positive.effect_records],
                "observer_available": execution.pair.positive.observer_available,
            },
            "test": {
                "trace_events": [event.as_dict() for event in execution.pair.test.trace_events],
                "effect_records": [record.as_dict() for record in execution.pair.test.effect_records],
                "observer_available": execution.pair.test.observer_available,
            },
        },
        "evidence_health": execution.health.as_dict(),
        "result": result.as_dict(),
        "boundaries": [
            "This is a controlled local synthetic fixture execution, not a confirmatory experiment.",
            "A held_out schedule label does not make this same-team fixture an independent replication.",
            "B0/B1/B2/B3 are controlled runner implementations, not completed external baseline studies.",
        ],
    }


def _failed_artifact(
    row: Mapping[str, str],
    budget: ArmBudget,
    *,
    started_at: str,
    finished_at: str,
    elapsed_ms: float,
    error: BaseException,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_kind": "attestflow_synthetic_arm_execution",
        "synthetic_fixture_only": True,
        "contains_confirmatory_result": False,
        "evidence_level": "E2_LOCAL_SYNTHETIC_CHECK",
        "schedule_row": dict(row),
        "equal_budget": budget.as_dict(),
        "execution_status": "FAILED",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "elapsed_ms": elapsed_ms,
        "error": {"type": type(error).__name__, "message": str(error)},
        "result": {
            "verdict": "INDETERMINATE",
            "reason": "runner exception retained instead of dropping the scheduled sample",
            "frontier": [],
            "localization_mode": "INDETERMINATE",
        },
        "boundaries": [
            "The failed row remains in the ledger and is not replaced by a rerun.",
            "This controlled synthetic run contains no confirmatory result.",
        ],
    }


def _frontier_records(execution: ArmExecution, result: ArmResult) -> list[dict[str, str]]:
    events = {event.node_id: event for event in execution.pair.test.trace_events}
    attempt_id = next(
        (event.attempt_id for event in execution.pair.test.trace_events),
        "unknown-attempt",
    )
    records: list[dict[str, str]] = []
    for source, target in result.frontier:
        source_event = events.get(source)
        target_event = events.get(target)
        records.append(
            {
                "from_event_id": (
                    source_event.event_id if source_event is not None else f"unobserved:{source}"
                ),
                "to_event_id": (
                    target_event.event_id
                    if target_event is not None
                    else f"ledger:{attempt_id}"
                    if target == "@independent_effect_ledger"
                    else f"unobserved:{target}"
                ),
                "from_node_id": source,
                "to_node_id": target,
            }
        )
    return records


def _metrics(
    row: Mapping[str, str],
    budget: ArmBudget,
    elapsed_ms: float,
    execution: ArmExecution | None,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "arm": row["arm"],
        "budget_id": budget.budget_id,
        "budget_sut_executions": budget.sut_executions,
        "budget_input_candidates": budget.input_candidates,
        "budget_trace_event_limit": budget.trace_event_limit,
        "budget_observer_record_limit": budget.observer_record_limit,
        "budget_timeout_ms": budget.timeout_ms,
        "elapsed_ms": elapsed_ms,
        "synthetic_fixture": True,
        "confirmatory": False,
        "case_kind": row["case_kind"],
        "shared_health_gate_uses_trace_and_observer": True,
    }
    if execution is None:
        base.update(
            {
                "arm_profile_sha256": "unavailable",
                "input_source": "unavailable",
                "detector": "unavailable",
                "localizer": "unavailable",
                "uses_contract_compiler": False,
                "uses_trace_for_verdict": False,
                "uses_effect_for_verdict": False,
                "sut_executions_observed": 0,
                "input_candidates_observed": 0,
                "trace_events_observed": 0,
                "trace_events_consumed_by_method": 0,
                "observer_records_observed": 0,
                "observer_records_consumed_by_method": 0,
            }
        )
        return base
    profile = execution.profile
    base.update(
        {
            "arm_profile_sha256": profile.fingerprint,
            "input_source": profile.input_source,
            "detector": profile.detector,
            "localizer": profile.localizer,
            "uses_contract_compiler": profile.uses_contract_compiler,
            "uses_trace_for_verdict": profile.uses_trace_for_verdict,
            "uses_effect_for_verdict": profile.uses_effect_for_verdict,
            "sut_executions_observed": 2,
            "input_candidates_observed": 1,
            "trace_events_observed": execution.trace_events_observed,
            "trace_events_consumed_by_method": (
                execution.trace_events_observed if profile.uses_trace_for_verdict else 0
            ),
            "observer_records_observed": execution.effect_records_observed,
            "observer_records_consumed_by_method": (
                execution.effect_records_observed if profile.uses_effect_for_verdict else 0
            ),
        }
    )
    return base


def _record(
    row: Mapping[str, str],
    budget: ArmBudget,
    *,
    execution: ArmExecution | None,
    result: ArmResult,
    execution_status: str,
    started_at: str,
    finished_at: str,
    elapsed_ms: float,
    artifact_digests: Mapping[str, str],
) -> dict[str, Any]:
    trace_complete = execution.health.trace_complete if execution is not None else False
    observer_valid = execution.health.observer_chain_valid if execution is not None else False
    if (not trace_complete or not observer_valid) and result.verdict != "INDETERMINATE":
        raise AssertionError("invalid evidence escaped the shared INDETERMINATE gate")
    reason = (
        f"SYNTHETIC_PREFLIGHT_ONLY; arm={row['arm']}; "
        f"{result.reason}"
    )
    return {
        "run_id": f"run-syn-{row['schedule_id'][4:]}",
        "schedule_id": row["schedule_id"],
        "experiment_id": row["experiment_id"],
        "analysis_role": row["analysis_role"],
        "supersedes_run_id": None,
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "execution_status": execution_status,
        "verdict": result.verdict,
        "reason": reason,
        "split": row["split"],
        "stack_id": row["stack_id"],
        "defect_family": row["defect_family"],
        "defect_case_id": row["case_id"],
        "independent_unit_kind": row["independent_unit_kind"],
        "independent_unit_id": row["independent_unit_id"],
        "fresh_process_block_id": None,
        "robustness_block_id": None,
        "process_instance_id": row["process_instance_id"],
        "trace_complete": trace_complete,
        "observer_chain_valid": observer_valid,
        "frontier_mode": result.localization_mode,
        "frontier": _frontier_records(execution, result) if execution is not None else [],
        "metrics": _metrics(row, budget, elapsed_ms, execution),
        "exclusion": None,
        "artifact_digests": dict(artifact_digests),
    }


def validate_formal_ledger(ledger: Mapping[str, Any]) -> None:
    """Apply both semantic hash-chain checks and the checked-in JSON Schema."""

    validate_ledger(ledger)
    schema = _read_json(LEDGER_SCHEMA)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(ledger), key=lambda item: list(item.absolute_path))
    if errors:
        rendered = "; ".join(
            f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"formal run-ledger schema validation failed: {rendered}")


def execute_schedule(
    plan: SchedulePlan,
    *,
    budget: ArmBudget = DEFAULT_BUDGET,
    executor: ArmExecutor | None = None,
    utc_clock: Callable[[], str] = _utc_now,
) -> RunBundle:
    """Execute every plan row and retain failures as INDETERMINATE records."""

    selected_executor = executor or ArmExecutor()
    ledger = _read_json(BLANK_LEDGER)
    ledger["created_at_utc"] = utc_clock()
    artifacts: dict[str, Mapping[str, Any]] = {}
    for row in plan.rows:
        started_at = utc_clock()
        start_ns = time.monotonic_ns()
        execution: ArmExecution | None = None
        try:
            execution = selected_executor.execute(row, budget)
            elapsed_ms = round((time.monotonic_ns() - start_ns) / 1_000_000, 6)
            finished_at = utc_clock()
            result = execution.result
            execution_status = "COMPLETE"
            if elapsed_ms > budget.timeout_ms:
                execution_status = "TIMEOUT"
                result = ArmResult(
                    "INDETERMINATE",
                    f"equal time budget exceeded: elapsed_ms={elapsed_ms} limit={budget.timeout_ms}",
                    localization_mode="INDETERMINATE",
                )
            artifact = _execution_artifact(
                row,
                execution,
                execution_status=execution_status,
                result=result,
                started_at=started_at,
                finished_at=finished_at,
                elapsed_ms=elapsed_ms,
            )
            digests = {
                "schedule": plan.sha256,
                "contract": execution.contract_sha256,
                "arm_evidence": json_digest(artifact),
            }
        except Exception as error:  # each scheduled failure must remain observable
            elapsed_ms = round((time.monotonic_ns() - start_ns) / 1_000_000, 6)
            finished_at = utc_clock()
            execution_status = "FAILED"
            result = ArmResult(
                "INDETERMINATE",
                f"runner retained {type(error).__name__}: {error}",
                localization_mode="INDETERMINATE",
            )
            artifact = _failed_artifact(
                row,
                budget,
                started_at=started_at,
                finished_at=finished_at,
                elapsed_ms=elapsed_ms,
                error=error,
            )
            digests = {
                "schedule": plan.sha256,
                "arm_evidence": json_digest(artifact),
            }
            execution = None
        artifacts[row["schedule_id"]] = artifact
        ledger = append_record(
            ledger,
            _record(
                row,
                budget,
                execution=execution,
                result=result,
                execution_status=execution_status,
                started_at=started_at,
                finished_at=finished_at,
                elapsed_ms=elapsed_ms,
                artifact_digests=digests,
            ),
        )

    expected_ids = [row["schedule_id"] for row in plan.rows]
    recorded_ids = [record["schedule_id"] for record in ledger["records"]]
    if recorded_ids != expected_ids or set(artifacts) != set(expected_ids):
        raise AssertionError("scheduled rows were dropped, duplicated, or reordered")
    ledger["closed"] = True
    validate_formal_ledger(ledger)
    execution_counts = Counter(record["execution_status"] for record in ledger["records"])
    verdict_counts = Counter(record["verdict"] for record in ledger["records"])
    arm_counts = Counter(record["metrics"]["arm"] for record in ledger["records"])
    budget_ids = {record["metrics"]["budget_id"] for record in ledger["records"]}
    summary = {
        "schema_version": "1.0",
        "synthetic_fixture_only": True,
        "contains_confirmatory_results": False,
        "evidence_level": "E2_LOCAL_SYNTHETIC_CHECK",
        "protocol_id": plan.protocol_id,
        "schedule_path": plan.path,
        "schedule_sha256": plan.sha256,
        "scheduled_rows": len(plan.rows),
        "recorded_rows": len(ledger["records"]),
        "artifact_rows": len(artifacts),
        "schedule_coverage_complete": True,
        "equal_budget_verified": budget_ids == {budget.budget_id},
        "budget": budget.as_dict(),
        "execution_status_counts": dict(sorted(execution_counts.items())),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "arm_counts": dict(sorted(arm_counts.items())),
        "failure_rows_retained": execution_counts.get("FAILED", 0)
        + execution_counts.get("TIMEOUT", 0)
        + execution_counts.get("CRASHED", 0),
        "boundary": (
            "Controlled same-team synthetic execution only. The held_out allocation label "
            "does not establish confirmatory, independent, real-stack, or production evidence."
        ),
    }
    return RunBundle(ledger=ledger, artifacts=artifacts, summary=summary)


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_bundle(bundle: RunBundle, output_dir: str | Path) -> Path:
    """Atomically publish a new bundle outside the frozen protocol directory."""

    destination = Path(output_dir).resolve()
    frozen = PROTOCOL_ROOT.resolve()
    if destination == frozen or frozen in destination.parents:
        raise ValueError("runtime outputs may not modify the frozen v1 protocol directory")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing output directory: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        artifacts_dir = temporary / "artifacts"
        artifacts_dir.mkdir()
        artifact_manifest: list[dict[str, Any]] = []
        for schedule_id, artifact in bundle.artifacts.items():
            sequence = int(artifact["schedule_row"]["schedule_sequence"])
            filename = f"{sequence:04d}-{schedule_id}.json"
            path = artifacts_dir / filename
            path.write_text(render_json(artifact), encoding="utf-8")
            digest = _sha256_path(path)
            expected = next(
                record["artifact_digests"]["arm_evidence"]
                for record in bundle.ledger["records"]
                if record["schedule_id"] == schedule_id
            )
            if digest != expected:
                raise AssertionError(f"artifact digest mismatch before publish: {schedule_id}")
            artifact_manifest.append(
                {
                    "schedule_id": schedule_id,
                    "path": f"artifacts/{filename}",
                    "sha256": digest,
                }
            )
        ledger_path = temporary / "run-ledger.json"
        summary_path = temporary / "summary.json"
        ledger_path.write_text(render_json(bundle.ledger), encoding="utf-8")
        summary_path.write_text(render_json(bundle.summary), encoding="utf-8")
        manifest = {
            "schema_version": "1.0",
            "synthetic_fixture_only": True,
            "contains_confirmatory_results": False,
            "files": {
                "run-ledger.json": _sha256_path(ledger_path),
                "summary.json": _sha256_path(summary_path),
            },
            "artifacts": artifact_manifest,
        }
        (temporary / "manifest.json").write_text(render_json(manifest), encoding="utf-8")
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination

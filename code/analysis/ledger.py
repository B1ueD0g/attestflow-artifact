"""Hash-chain and anti-pseudoreplication checks for AttestFlow run ledgers."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]


GENESIS_HASH = "0" * 64
_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_LEDGER_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "protocols"
    / "run-ledger.schema.json"
)
_RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


class LedgerValidationError(ValueError):
    pass


def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if _RFC3339_DATE_TIME.fullmatch(value) is None:
        return False
    normalized = value[:-1] + "+00:00" if value[-1] in {"Z", "z"} else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.utcoffset() is not None


@lru_cache(maxsize=1)
def _ledger_validator() -> Any:
    try:
        schema = json.loads(_LEDGER_SCHEMA_PATH.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LedgerValidationError(
            f"cannot read frozen ledger schema {_LEDGER_SCHEMA_PATH}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise LedgerValidationError(
            f"invalid JSON in frozen ledger schema {_LEDGER_SCHEMA_PATH}: {exc}"
        ) from exc
    if not isinstance(schema, Mapping) or schema.get("$schema") != _DRAFT_2020_12:
        raise LedgerValidationError("frozen ledger schema must declare JSON Schema Draft 2020-12")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise LedgerValidationError(f"invalid frozen Draft 2020-12 ledger schema: {exc}") from exc
    format_checker = FormatChecker()
    # Some minimal jsonschema installations omit the optional RFC 3339
    # dependency and otherwise treat an unknown date-time format as valid.
    format_checker.checks("date-time")(_is_rfc3339_date_time)
    return Draft202012Validator(schema, format_checker=format_checker)


def _validate_against_schema(ledger: Mapping[str, Any]) -> None:
    errors = sorted(
        _ledger_validator().iter_errors(dict(ledger)),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    rendered = []
    for error in errors:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        rendered.append(f"{location}: {error.message}")
    raise LedgerValidationError("ledger schema validation failed: " + "; ".join(rendered))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def append_record(ledger: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a new ledger containing one hash-linked record; never mutate input."""

    validate_ledger(ledger)
    updated = copy.deepcopy(dict(ledger))
    if updated.get("closed"):
        raise LedgerValidationError("cannot append to a closed ledger")
    new_record = copy.deepcopy(dict(record))
    new_record["sequence"] = len(updated["records"]) + 1
    new_record["previous_hash"] = updated["head_hash"] or updated["genesis_hash"]
    new_record["record_hash"] = record_hash(new_record)
    updated["records"].append(new_record)
    updated["head_hash"] = new_record["record_hash"]
    validate_ledger(updated)
    return updated


def validate_ledger(ledger: Mapping[str, Any], *, allow_e9: bool = False) -> None:
    if ledger.get("genesis_hash") != GENESIS_HASH:
        raise LedgerValidationError("unexpected genesis hash")
    records = ledger.get("records")
    if not isinstance(records, list):
        raise LedgerValidationError("records must be a list")
    if not allow_e9 and any(
        isinstance(record, Mapping) and record.get("experiment_id") == "E9"
        for record in records
    ):
        raise LedgerValidationError("E9 is PREPARED_ONLY under v1; hardware results are forbidden")
    _validate_against_schema(ledger)
    previous = GENESIS_HASH
    run_ids: set[str] = set()
    primary_schedule_ids: set[str] = set()
    process_instance_ids: set[str] = set()
    records_by_run: dict[str, Mapping[str, Any]] = {}
    for position, record in enumerate(records, start=1):
        if record.get("sequence") != position:
            raise LedgerValidationError(f"sequence mismatch at position {position}")
        run_id = record.get("run_id")
        if not run_id or run_id in run_ids:
            raise LedgerValidationError(f"missing or duplicate run_id={run_id!r}")
        run_ids.add(str(run_id))
        records_by_run[str(run_id)] = record
        if record.get("previous_hash") != previous:
            raise LedgerValidationError(f"previous_hash mismatch at sequence {position}")
        observed_hash = record.get("record_hash")
        expected_hash = record_hash(record)
        if observed_hash != expected_hash:
            raise LedgerValidationError(f"record_hash mismatch at sequence {position}")
        previous = str(observed_hash)
        if (
            record.get("trace_complete") is False or record.get("observer_chain_valid") is False
        ) and record.get("verdict") != "INDETERMINATE":
            raise LedgerValidationError("invalid trace/observer cannot yield a definitive verdict")
        role = record.get("analysis_role")
        schedule_id = record.get("schedule_id")
        if role == "PRIMARY":
            if schedule_id in primary_schedule_ids:
                raise LedgerValidationError(f"duplicate PRIMARY schedule_id={schedule_id!r}")
            primary_schedule_ids.add(str(schedule_id))
            if record.get("supersedes_run_id") not in (None, ""):
                raise LedgerValidationError("PRIMARY must not supersede another run")
        elif role == "RETRY":
            supersedes = record.get("supersedes_run_id")
            if not supersedes or supersedes not in records_by_run or supersedes == run_id:
                raise LedgerValidationError("RETRY must link an earlier retained run")
            if records_by_run[str(supersedes)].get("schedule_id") != schedule_id:
                raise LedgerValidationError("RETRY and superseded run must share schedule_id")
        process_id = record.get("process_instance_id")
        if not process_id or process_id in process_instance_ids:
            raise LedgerValidationError(f"process_instance_id reused: {process_id!r}")
        process_instance_ids.add(str(process_id))
        if record.get("independent_unit_kind") == "fresh_process_block":
            if not record.get("fresh_process_block_id"):
                raise LedgerValidationError("performance record lacks fresh_process_block_id")
    expected_head = previous if records else None
    if ledger.get("head_hash") != expected_head:
        raise LedgerValidationError("head_hash does not match final record")

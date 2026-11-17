"""An append-only, local dummy-effect observer with hash-chain integrity."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

try:  # pragma: no cover - the current local runners provide fcntl.
    fcntl: ModuleType | None = importlib.import_module("fcntl")
except ImportError:  # pragma: no cover - conservative single-process fallback.
    fcntl = None


ZERO_HASH = "0" * 64
_HMAC_SHA256_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")


class ObserverUnavailableError(RuntimeError):
    """Raised when the independent effect ledger cannot be read or written."""


class LedgerIntegrityError(ObserverUnavailableError):
    """Raised when an append-only ledger record or hash chain is invalid."""


@dataclass(frozen=True, slots=True)
class EffectRecord:
    sequence: int
    trial_id: str
    attempt_id: str
    effect_id: str
    resource_commitment: str
    observed_at_ns: int
    previous_hash: str
    record_hash: str
    request_id: str | None = None
    decision_id: str | None = None
    context_id: str | None = None
    policy_epoch: int | None = None
    event_id: str | None = None
    obligation_id: str | None = None
    record_type: str = "EFFECT"
    observed_effect_count: int | None = None


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


class EffectLedger:
    """Observe synthetic effects in a file opened only in append mode."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except OSError as exc:
            raise ObserverUnavailableError(f"cannot initialize effect ledger: {exc}") from exc

    def _parse_bytes(self, content: bytes) -> tuple[EffectRecord, ...]:
        records: list[EffectRecord] = []
        previous_hash = ZERO_HASH
        if not content:
            return ()
        if not content.endswith(b"\n"):
            raise LedgerIntegrityError("ledger ends with a partial record")
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            try:
                value = json.loads(raw_line.decode("utf-8"))
                record = EffectRecord(**value)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
                raise LedgerIntegrityError(
                    f"invalid ledger record at line {line_number}: {exc}"
                ) from exc
            payload = dict(value)
            claimed_hash = payload.pop("record_hash")
            if record.sequence != line_number:
                raise LedgerIntegrityError(f"invalid sequence at line {line_number}")
            if record.previous_hash != previous_hash:
                raise LedgerIntegrityError(f"broken hash chain at line {line_number}")
            if _record_hash(payload) != claimed_hash:
                raise LedgerIntegrityError(f"record hash mismatch at line {line_number}")
            if not _HMAC_SHA256_RE.fullmatch(record.resource_commitment):
                raise LedgerIntegrityError(f"invalid resource commitment at line {line_number}")
            if record.record_type not in {"EFFECT", "ATTEMPT_COMPLETE"}:
                raise LedgerIntegrityError(f"invalid record type at line {line_number}")
            if record.record_type == "EFFECT" and record.observed_effect_count is not None:
                raise LedgerIntegrityError(
                    f"effect record carries an observation count at line {line_number}"
                )
            if record.record_type == "ATTEMPT_COMPLETE" and (
                not isinstance(record.observed_effect_count, int)
                or isinstance(record.observed_effect_count, bool)
                or record.observed_effect_count < 0
            ):
                raise LedgerIntegrityError(
                    f"attempt receipt lacks a valid effect count at line {line_number}"
                )
            records.append(record)
            previous_hash = claimed_hash
        return tuple(records)

    def records(self) -> tuple[EffectRecord, ...]:
        try:
            return self._parse_bytes(self.path.read_bytes())
        except FileNotFoundError as exc:
            raise ObserverUnavailableError("effect ledger is missing") from exc
        except OSError as exc:
            raise ObserverUnavailableError(f"cannot read effect ledger: {exc}") from exc

    def _append_observation(
        self,
        *,
        record_type: str,
        observed_effect_count: int | None,
        trial_id: str,
        attempt_id: str,
        effect_id: str,
        resource_commitment: str,
        observed_at_ns: int | None = None,
        request_id: str | None = None,
        decision_id: str | None = None,
        context_id: str | None = None,
        policy_epoch: int | None = None,
        event_id: str | None = None,
        obligation_id: str | None = None,
    ) -> EffectRecord:
        if not all(isinstance(value, str) and value for value in (trial_id, attempt_id, effect_id)):
            raise ValueError("trial_id, attempt_id, and effect_id must be non-empty strings")
        if not _HMAC_SHA256_RE.fullmatch(resource_commitment):
            raise ValueError("resource_commitment must be an HMAC-SHA256 commitment")
        optional_strings = {
            "request_id": request_id,
            "decision_id": decision_id,
            "context_id": context_id,
            "event_id": event_id,
            "obligation_id": obligation_id,
        }
        if any(
            value is not None and (not isinstance(value, str) or not value)
            for value in optional_strings.values()
        ):
            raise ValueError("optional correlation ids must be non-empty strings when set")
        if policy_epoch is not None and (not isinstance(policy_epoch, int) or isinstance(policy_epoch, bool)):
            raise ValueError("policy_epoch must be an integer when set")
        if record_type not in {"EFFECT", "ATTEMPT_COMPLETE"}:
            raise ValueError("unsupported observation record type")
        if record_type == "EFFECT" and observed_effect_count is not None:
            raise ValueError("effect records cannot carry observed_effect_count")
        if record_type == "ATTEMPT_COMPLETE" and (
            not isinstance(observed_effect_count, int)
            or isinstance(observed_effect_count, bool)
            or observed_effect_count < 0
        ):
            raise ValueError("attempt receipt requires a non-negative effect count")
        timestamp = time.time_ns() if observed_at_ns is None else observed_at_ns
        try:
            # O_APPEND makes every write land at EOF even though the same
            # descriptor is readable for locked hash-chain verification.
            descriptor = os.open(self.path, os.O_APPEND | os.O_RDWR)
        except OSError as exc:
            raise ObserverUnavailableError(f"cannot open effect ledger for append: {exc}") from exc
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb", closefd=True) as reader:
                existing = self._parse_bytes(reader.read())
            previous_hash = existing[-1].record_hash if existing else ZERO_HASH
            payload: dict[str, Any] = {
                "sequence": len(existing) + 1,
                "trial_id": trial_id,
                "attempt_id": attempt_id,
                "effect_id": effect_id,
                "resource_commitment": resource_commitment,
                "observed_at_ns": timestamp,
                "previous_hash": previous_hash,
                "request_id": request_id,
                "decision_id": decision_id,
                "context_id": context_id,
                "policy_epoch": policy_epoch,
                "event_id": event_id,
                "obligation_id": obligation_id,
                "record_type": record_type,
                "observed_effect_count": observed_effect_count,
            }
            value = dict(payload)
            value["record_hash"] = _record_hash(payload)
            encoded = _canonical(value) + b"\n"
            written = os.write(descriptor, encoded)
            if written != len(encoded):
                raise ObserverUnavailableError("short append to effect ledger")
            os.fsync(descriptor)
            return EffectRecord(**value)
        except OSError as exc:
            raise ObserverUnavailableError(f"cannot append effect ledger: {exc}") from exc
        finally:
            if fcntl is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)

    def append_effect(
        self,
        *,
        trial_id: str,
        attempt_id: str,
        effect_id: str,
        resource_commitment: str,
        observed_at_ns: int | None = None,
        request_id: str | None = None,
        decision_id: str | None = None,
        context_id: str | None = None,
        policy_epoch: int | None = None,
        event_id: str | None = None,
        obligation_id: str | None = None,
    ) -> EffectRecord:
        return self._append_observation(
            record_type="EFFECT",
            observed_effect_count=None,
            trial_id=trial_id,
            attempt_id=attempt_id,
            effect_id=effect_id,
            resource_commitment=resource_commitment,
            observed_at_ns=observed_at_ns,
            request_id=request_id,
            decision_id=decision_id,
            context_id=context_id,
            policy_epoch=policy_epoch,
            event_id=event_id,
            obligation_id=obligation_id,
        )

    def append_attempt_receipt(
        self,
        *,
        trial_id: str,
        attempt_id: str,
        effect_id: str,
        observed_effect_count: int,
        receipt_commitment: str,
        observed_at_ns: int | None = None,
        request_id: str | None = None,
        decision_id: str | None = None,
        context_id: str | None = None,
        policy_epoch: int | None = None,
        event_id: str | None = None,
        obligation_id: str | None = None,
    ) -> EffectRecord:
        return self._append_observation(
            record_type="ATTEMPT_COMPLETE",
            observed_effect_count=observed_effect_count,
            trial_id=trial_id,
            attempt_id=attempt_id,
            effect_id=effect_id,
            resource_commitment=receipt_commitment,
            observed_at_ns=observed_at_ns,
            request_id=request_id,
            decision_id=decision_id,
            context_id=context_id,
            policy_epoch=policy_epoch,
            event_id=event_id,
            obligation_id=obligation_id,
        )

    def effect_observed(self, *, trial_id: str, attempt_id: str, effect_id: str) -> bool:
        return bool(self.matching_records(
            trial_id=trial_id, attempt_id=attempt_id, effect_id=effect_id
        ))

    def matching_records(
        self, *, trial_id: str, attempt_id: str, effect_id: str
    ) -> tuple[EffectRecord, ...]:
        """Return exact effect records after verifying the complete hash chain."""

        return tuple(
            record
            for record in self.records()
            if record.record_type == "EFFECT"
            and record.trial_id == trial_id
            and record.attempt_id == attempt_id
            and record.effect_id == effect_id
        )

    def matching_receipts(
        self, *, trial_id: str, attempt_id: str, effect_id: str
    ) -> tuple[EffectRecord, ...]:
        """Return attempt-complete receipts after verifying the hash chain."""

        return tuple(
            record
            for record in self.records()
            if record.record_type == "ATTEMPT_COMPLETE"
            and record.trial_id == trial_id
            and record.attempt_id == attempt_id
            and record.effect_id == effect_id
        )

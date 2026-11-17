"""Typed runtime records for the controlled synthetic arm runner.

These types describe execution mechanics only.  They are not experiment
results and deliberately contain no ground-truth labels.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Mapping

from benchmarks.attestflow_synthetic.api import PairObservation


ARM_IDS = (
    "B0_NATIVE",
    "B1_GENERIC",
    "B2_MANUAL",
    "B3_TRACE",
    "A_T",
    "A_TR",
    "A_TE",
    "A_FULL",
)


@dataclass(frozen=True, slots=True)
class ArmBudget:
    """One budget ceiling applied identically to every defect arm.

    The values are a controlled-runner budget, not the still-unfrozen
    confirmatory resource budget described by the preregistration.
    """

    budget_id: str = "synthetic-equal-budget-v1"
    sut_executions: int = 2
    input_candidates: int = 1
    trace_event_limit: int = 16
    observer_record_limit: int = 4
    timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        for name in (
            "sut_executions",
            "input_candidates",
            "trace_event_limit",
            "observer_record_limit",
            "timeout_ms",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.sut_executions != 2:
            raise ValueError("the controlled defect-arm budget requires one matched pair")
        if self.input_candidates != 1:
            raise ValueError("the controlled defect-arm budget requires one test candidate")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_BUDGET = ArmBudget()


@dataclass(frozen=True, slots=True)
class ArmProfile:
    """A method's observable behavior, used to prevent name-only aliases."""

    arm_id: str
    input_source: str
    detector: str
    localizer: str
    uses_contract_compiler: bool
    uses_trace_for_verdict: bool
    uses_effect_for_verdict: bool
    boundary: str

    def __post_init__(self) -> None:
        if self.arm_id not in ARM_IDS:
            raise ValueError(f"unknown arm id: {self.arm_id}")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceHealth:
    """Health of collected evidence, independent of an arm's oracle choice."""

    trace_complete: bool
    observer_chain_valid: bool
    positive_control_reachable: bool
    reasons: tuple[str, ...]

    @property
    def usable(self) -> bool:
        return (
            self.trace_complete
            and self.observer_chain_valid
            and self.positive_control_reachable
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "trace_complete": self.trace_complete,
            "observer_chain_valid": self.observer_chain_valid,
            "positive_control_reachable": self.positive_control_reachable,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class ArmResult:
    """One arm's three-valued result before run-ledger projection."""

    verdict: str
    reason: str
    frontier: tuple[tuple[str, str], ...] = ()
    localization_mode: str = "NOT_APPLICABLE"

    def __post_init__(self) -> None:
        if self.verdict not in {"PASS", "FAIL", "INDETERMINATE"}:
            raise ValueError(f"invalid arm verdict: {self.verdict}")
        if self.localization_mode not in {
            "FIRST_OBSERVED_LOSS",
            "CANDIDATE_FRONTIER",
            "UNLOCATED",
            "INDETERMINATE",
            "NOT_APPLICABLE",
        }:
            raise ValueError(f"invalid localization mode: {self.localization_mode}")
        if not self.reason:
            raise ValueError("arm result reason must be non-empty")

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "frontier": [
                {"from_node_id": source, "to_node_id": target}
                for source, target in self.frontier
            ],
            "localization_mode": self.localization_mode,
        }


@dataclass(frozen=True, slots=True)
class ArmExecution:
    """Complete in-memory evidence for one scheduled synthetic row."""

    profile: ArmProfile
    budget: ArmBudget
    pair: PairObservation
    health: EvidenceHealth
    result: ArmResult
    contract_sha256: str

    @property
    def trace_events_observed(self) -> int:
        return len(self.pair.positive.trace_events) + len(self.pair.test.trace_events)

    @property
    def effect_records_observed(self) -> int:
        return len(self.pair.positive.effect_records) + len(self.pair.test.effect_records)


@dataclass(frozen=True, slots=True)
class SchedulePlan:
    """Validated rows and immutable identity of their source schedule."""

    path: str
    sha256: str
    protocol_id: str
    rows: tuple[Mapping[str, str], ...]


@dataclass(frozen=True, slots=True)
class RunBundle:
    """Ledger plus separately hash-addressed per-row evidence artifacts."""

    ledger: Mapping[str, Any]
    artifacts: Mapping[str, Mapping[str, Any]]
    summary: Mapping[str, Any]


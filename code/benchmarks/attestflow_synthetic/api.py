"""Small integration API between synthetic fixtures and an AttestFlow engine.

Ground truth and private SUT variant configuration are intentionally absent
from this API.  An analysis implementation receives only the public contract
and observations produced by a matched positive/test pair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


Edge = tuple[str, str]


@dataclass(frozen=True)
class TrialInput:
    """One generated synthetic input; values never leave the local fixture."""

    scenario_id: str
    family_id: str
    role: str
    actual_value: Any
    expected_value: Any
    policy_epoch: int
    request_id: str
    irrelevant_label: str
    changed_fields: tuple[str, ...]


@dataclass(frozen=True)
class TraceEvent:
    """One sanitized trace event containing commitments, not raw values."""

    event_id: str
    node_id: str
    predecessor_event_ids: tuple[str, ...]
    dependency_commitment: str
    sequence: int
    trial_id: str
    attempt_id: str
    request_id: str
    decision_id: str
    effect_id: str
    policy_epoch: int
    decision: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "node_id": self.node_id,
            "predecessor_event_ids": list(self.predecessor_event_ids),
            "dependency_commitment": self.dependency_commitment,
            "sequence": self.sequence,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "request_id": self.request_id,
            "decision_id": self.decision_id,
            "effect_id": self.effect_id,
            "policy_epoch": self.policy_epoch,
            "decision": self.decision,
        }


@dataclass(frozen=True)
class EffectRecord:
    """Append-only observation of a dummy effect, outside the decision log."""

    effect_id: str
    trial_id: str
    attempt_id: str
    request_id: str
    resource_commitment: str
    observed_at_sequence: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "trial_id": self.trial_id,
            "attempt_id": self.attempt_id,
            "request_id": self.request_id,
            "resource_commitment": self.resource_commitment,
            "observed_at_sequence": self.observed_at_sequence,
        }


@dataclass(frozen=True)
class RunObservation:
    """Observable output of one SUT execution."""

    trial: TrialInput
    trace_events: tuple[TraceEvent, ...]
    effect_records: tuple[EffectRecord, ...]
    observer_available: bool = True


@dataclass(frozen=True)
class PairObservation:
    """Matched positive and single-axis test observations."""

    positive: RunObservation
    test: RunObservation


@dataclass(frozen=True)
class AnalysisResult:
    """Conservative result returned by an observation analyzer."""

    status: str
    candidate_frontier: tuple[Edge, ...]
    positive_effect_count: int
    test_effect_count: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "candidate_frontier": [
                {"from": source, "to": target}
                for source, target in self.candidate_frontier
            ],
            "positive_effect_count": self.positive_effect_count,
            "test_effect_count": self.test_effect_count,
            "reason": self.reason,
        }


class ObservationAnalyzer(Protocol):
    """Interface the future AttestFlow core should implement.

    Deliberately absent: case ID, defect operator, injected location, fixed twin,
    split label, and ground truth.
    """

    def analyze_pair(
        self,
        contract: Mapping[str, Any],
        observation: PairObservation,
    ) -> AnalysisResult:
        ...


def trace_by_node(events: Sequence[TraceEvent]) -> dict[str, TraceEvent]:
    """Index a trace and reject duplicate observations conservatively."""

    indexed: dict[str, TraceEvent] = {}
    for event in events:
        if event.node_id in indexed:
            raise ValueError(f"duplicate trace node: {event.node_id}")
        indexed[event.node_id] = event
    return indexed

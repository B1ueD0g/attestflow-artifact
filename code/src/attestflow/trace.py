"""Typed trace events, per-attempt DAG checks, and conservative localization."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping, Sequence

from .contract import GraphEdge, ObservationGraph


_HMAC_SHA256_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class TraceEvent:
    trial_id: str
    attempt_id: str
    event_id: str
    predecessor_event_ids: tuple[str, ...]
    node_id: str
    commitments: Mapping[str, str]
    decision_id: str | None
    effect_id: str | None
    policy_epoch: int | None
    obligation_id: str
    local_sequence: int = 0
    request_id: str | None = None
    context_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("trial_id", "attempt_id", "event_id", "node_id", "obligation_id"):
            if not getattr(self, name):
                raise ValueError(f"{name} must be non-empty")
        predecessors = tuple(self.predecessor_event_ids)
        if len(predecessors) != len(set(predecessors)):
            raise ValueError("predecessor_event_ids must be unique")
        if self.event_id in predecessors:
            raise ValueError("an event cannot be its own predecessor")
        if self.local_sequence < 0:
            raise ValueError("local_sequence must be non-negative")
        normalized = dict(self.commitments)
        for label, value in normalized.items():
            if not label or not isinstance(value, str) or not _HMAC_SHA256_RE.fullmatch(value):
                raise ValueError(
                    "commitments must map non-empty labels to canonical HMAC-SHA256 strings"
                )
        object.__setattr__(self, "predecessor_event_ids", predecessors)
        object.__setattr__(self, "commitments", MappingProxyType(normalized))


@dataclass(frozen=True, slots=True)
class TraceValidation:
    valid: bool
    complete: bool
    trial_id: str | None
    attempt_id: str | None
    missing_nodes: tuple[str, ...]
    missing_causal_edges: tuple[GraphEdge, ...]
    undeclared_causal_edges: tuple[GraphEdge, ...]
    errors: tuple[str, ...]
    topological_event_ids: tuple[str, ...]

    @property
    def usable(self) -> bool:
        return self.valid and self.complete


def validate_attempt_dag(
    events: Sequence[TraceEvent],
    graph: ObservationGraph,
    *,
    required_commitment_label: str | None = None,
) -> TraceValidation:
    """Validate one complete attempt against the declared happens-before DAG.

    Version 0 deliberately accepts one event occurrence per declared component
    node. Retries belong to separate attempt ids.
    """

    if not events:
        return TraceValidation(
            False,
            False,
            None,
            None,
            graph.nodes,
            (),
            (),
            ("trace is empty",),
            (),
        )
    errors: list[str] = []
    trial_ids = {event.trial_id for event in events}
    attempt_ids = {event.attempt_id for event in events}
    trial_id = next(iter(trial_ids)) if len(trial_ids) == 1 else None
    attempt_id = next(iter(attempt_ids)) if len(attempt_ids) == 1 else None
    if len(trial_ids) != 1:
        errors.append("events span multiple trial ids")
    if len(attempt_ids) != 1:
        errors.append("events span multiple attempt ids")

    by_id: dict[str, TraceEvent] = {}
    by_node: dict[str, TraceEvent] = {}
    for event in events:
        if event.event_id in by_id:
            errors.append(f"duplicate event id: {event.event_id}")
        else:
            by_id[event.event_id] = event
        if event.node_id in by_node:
            errors.append(f"multiple event occurrences for node in one attempt: {event.node_id}")
        else:
            by_node[event.node_id] = event
        if event.node_id not in graph.node_set:
            errors.append(f"event references undeclared node: {event.node_id}")
        if (
            required_commitment_label is not None
            and required_commitment_label not in event.commitments
        ):
            errors.append(
                f"event {event.event_id} lacks required commitment "
                f"{required_commitment_label!r}"
            )

    missing_nodes = tuple(sorted(graph.node_set - set(by_node)))
    extra_edges: list[GraphEdge] = []
    observed_edges: set[GraphEdge] = set()
    for event in events:
        for predecessor_id in event.predecessor_event_ids:
            predecessor = by_id.get(predecessor_id)
            if predecessor is None:
                errors.append(
                    f"event {event.event_id} has missing predecessor {predecessor_id}"
                )
                continue
            edge = GraphEdge(predecessor.node_id, event.node_id)
            observed_edges.add(edge)
            if edge not in graph.edge_set:
                extra_edges.append(edge)
    for edge in sorted(set(extra_edges)):
        errors.append(f"undeclared causal edge: {edge.source}->{edge.target}")
    absent_edges: set[GraphEdge] = set()
    if not missing_nodes:
        absent_edges = set(graph.edge_set - observed_edges)
        for edge in sorted(absent_edges):
            errors.append(f"missing causal edge: {edge.source}->{edge.target}")

    indegree = {event_id: 0 for event_id in by_id}
    successors: dict[str, list[str]] = {event_id: [] for event_id in by_id}
    for event in events:
        if event.event_id not in by_id:
            continue
        for predecessor_id in event.predecessor_event_ids:
            if predecessor_id in by_id:
                indegree[event.event_id] += 1
                successors[predecessor_id].append(event.event_id)
    ready = sorted(event_id for event_id, degree in indegree.items() if degree == 0)
    ordered: list[str] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for successor in sorted(successors[current]):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
                ready.sort()
    if len(ordered) != len(by_id):
        errors.append("event predecessors do not form a DAG")

    # Local sequence is an adapter assertion, not a substitute for causality.
    for event in events:
        for predecessor_id in event.predecessor_event_ids:
            predecessor = by_id.get(predecessor_id)
            if (
                predecessor is not None
                and predecessor.node_id == event.node_id
                and predecessor.local_sequence >= event.local_sequence
            ):
                errors.append("local sequence is not monotonic")
    conformance_prefixes = ("undeclared causal edge:", "missing causal edge:")
    telemetry_errors = [
        error for error in errors if not error.startswith(conformance_prefixes)
    ]
    return TraceValidation(
        valid=not errors,
        complete=not missing_nodes and not telemetry_errors,
        trial_id=trial_id,
        attempt_id=attempt_id,
        missing_nodes=missing_nodes,
        missing_causal_edges=tuple(sorted(absent_edges)),
        undeclared_causal_edges=tuple(sorted(set(extra_edges))),
        errors=tuple(errors),
        topological_event_ids=tuple(ordered),
    )


class LocalizationStatus(str, Enum):
    FIRST_OBSERVED_LOSS = "FIRST_OBSERVED_LOSS"
    CANDIDATE_FRONTIER = "CANDIDATE_FRONTIER"
    NO_PROHIBITED_EFFECT = "NO_PROHIBITED_EFFECT"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True, order=True)
class LossEdge:
    source_event_id: str
    target_event_id: str
    source_node_id: str
    target_node_id: str


@dataclass(frozen=True, slots=True)
class LocalizationResult:
    status: LocalizationStatus
    candidate_frontier: tuple[LossEdge, ...] = ()
    reasons: tuple[str, ...] = ()


def _path_nodes(
    graph: ObservationGraph, sources: Sequence[str], effect: str
) -> frozenset[str]:
    return frozenset(
        node
        for node in graph.nodes
        if any(graph.has_path(source, node) for source in sources)
        and graph.has_path(node, effect)
    )


def localize_minimal_loss(
    positive_events: Sequence[TraceEvent],
    negative_events: Sequence[TraceEvent],
    graph: ObservationGraph,
    *,
    source_node_id: str,
    effect_node_id: str,
    additional_source_node_ids: Sequence[str] = (),
    prohibited_effect_observed: bool,
    commitment_label: str = "dependency",
) -> LocalizationResult:
    """Return the minimal observed loss edge(s) under happens-before.

    A relation-derived negative trial starts with a different actual value from
    its matched positive trial.  The distinction is live while the HMAC
    commitments differ.  Its first collapse to the positive commitment is an
    observation-level loss candidate, never an asserted source-code root cause.
    """

    if not prohibited_effect_observed:
        return LocalizationResult(LocalizationStatus.NO_PROHIBITED_EFFECT)
    positive_validation = validate_attempt_dag(
        positive_events, graph, required_commitment_label=commitment_label
    )
    negative_validation = validate_attempt_dag(
        negative_events, graph, required_commitment_label=commitment_label
    )
    if not positive_validation.usable or not negative_validation.usable:
        reasons = tuple(
            [f"positive trace: {reason}" for reason in positive_validation.errors]
            + [f"positive trace missing node: {node}" for node in positive_validation.missing_nodes]
            + [f"negative trace: {reason}" for reason in negative_validation.errors]
            + [f"negative trace missing node: {node}" for node in negative_validation.missing_nodes]
        )
        return LocalizationResult(LocalizationStatus.INDETERMINATE, reasons=reasons)
    declared_sources = tuple(dict.fromkeys((source_node_id, *additional_source_node_ids)))
    if any(source not in graph.node_set for source in declared_sources) or effect_node_id not in graph.node_set:
        return LocalizationResult(
            LocalizationStatus.INDETERMINATE,
            reasons=("a relation endpoint or effect node is absent from observation graph",),
        )
    if any(not graph.has_path(source, effect_node_id) for source in declared_sources):
        return LocalizationResult(
            LocalizationStatus.INDETERMINATE,
            reasons=("a relation endpoint has no causal path to effect node",),
        )

    positive_by_node = {event.node_id: event for event in positive_events}
    negative_by_node = {event.node_id: event for event in negative_events}
    active_sources: list[str] = []
    for source in declared_sources:
        positive_commitment = positive_by_node[source].commitments.get(commitment_label)
        negative_commitment = negative_by_node[source].commitments.get(commitment_label)
        if positive_commitment is None or negative_commitment is None:
            return LocalizationResult(
                LocalizationStatus.INDETERMINATE,
                reasons=(f"missing {commitment_label!r} commitment at endpoint {source}",),
            )
        if positive_commitment != negative_commitment:
            active_sources.append(source)
    if not active_sources:
        return LocalizationResult(
            LocalizationStatus.INDETERMINATE,
            reasons=("negative distinction is not observable at either relation endpoint",),
        )

    relevant_nodes = _path_nodes(graph, active_sources, effect_node_id)
    live: dict[str, bool] = {}
    for node in relevant_nodes:
        positive_commitment = positive_by_node[node].commitments.get(commitment_label)
        negative_commitment = negative_by_node[node].commitments.get(commitment_label)
        if positive_commitment is None or negative_commitment is None:
            return LocalizationResult(
                LocalizationStatus.INDETERMINATE,
                reasons=(f"missing {commitment_label!r} commitment at node {node}",),
            )
        live[node] = positive_commitment != negative_commitment
    candidates: list[LossEdge] = []
    for edge in graph.edges:
        if edge.source not in relevant_nodes or edge.target not in relevant_nodes:
            continue
        if live[edge.source] and not live[edge.target]:
            candidates.append(
                LossEdge(
                    source_event_id=negative_by_node[edge.source].event_id,
                    target_event_id=negative_by_node[edge.target].event_id,
                    source_node_id=edge.source,
                    target_node_id=edge.target,
                )
            )
    if not candidates and live[effect_node_id]:
        event = negative_by_node[effect_node_id]
        candidates.append(
            LossEdge(
                source_event_id=event.event_id,
                target_event_id=f"ledger:{event.attempt_id}",
                source_node_id=effect_node_id,
                target_node_id="@independent_effect_ledger",
            )
        )
    if not candidates:
        return LocalizationResult(
            LocalizationStatus.INDETERMINATE,
            reasons=("no observable live-to-lost transition reaches the prohibited effect",),
        )

    # Keep candidates with no strictly earlier candidate under graph reachability.
    frontier: list[LossEdge] = []
    for candidate in candidates:
        dominated = False
        for other in candidates:
            if other == candidate:
                continue
            if other.target_node_id == "@independent_effect_ledger":
                continue
            if candidate.source_node_id == "@independent_effect_ledger":
                dominated = True
                break
            if graph.has_path(other.target_node_id, candidate.source_node_id):
                dominated = True
                break
        if not dominated:
            frontier.append(candidate)
    frontier_tuple = tuple(sorted(frontier))
    status = (
        LocalizationStatus.FIRST_OBSERVED_LOSS
        if len(frontier_tuple) == 1
        else LocalizationStatus.CANDIDATE_FRONTIER
    )
    return LocalizationResult(status=status, candidate_frontier=frontier_tuple)

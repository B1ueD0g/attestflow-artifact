"""Three-valued, effect-grounded oracle for matched AttestFlow trials."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .compiler import CompiledSuite, Trial, TrialKind
from .contract import BindingContract
from .ledger import EffectLedger, ObserverUnavailableError
from .trace import (
    LocalizationResult,
    LocalizationStatus,
    LossEdge,
    TraceEvent,
    localize_minimal_loss,
    validate_attempt_dag,
)


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class AttemptObservation:
    trial: Trial
    attempt_id: str
    events: tuple[TraceEvent, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "events", tuple(self.events))


@dataclass(frozen=True, slots=True)
class OracleResult:
    contract_id: str
    pair_id: str
    trial_id: str
    attempt_id: str
    trace_digest: str
    verdict: Verdict
    effect_observed: bool | None
    reasons: tuple[str, ...]
    localization: LocalizationResult | None = None


def _indeterminate(
    observation: AttemptObservation, *reasons: str, effect_observed: bool | None = None
) -> OracleResult:
    return OracleResult(
        contract_id=observation.trial.contract_id,
        pair_id=observation.trial.pair_id,
        trial_id=observation.trial.trial_id,
        attempt_id=observation.attempt_id,
        trace_digest=_trace_digest(observation.events),
        verdict=Verdict.INDETERMINATE,
        effect_observed=effect_observed,
        reasons=tuple(reasons),
    )


def _trace_digest(events: Sequence[TraceEvent]) -> str:
    rows = []
    for event in sorted(events, key=lambda item: item.event_id):
        rows.append(
            {
                "trial_id": event.trial_id,
                "attempt_id": event.attempt_id,
                "event_id": event.event_id,
                "predecessor_event_ids": sorted(event.predecessor_event_ids),
                "node_id": event.node_id,
                "commitments": dict(sorted(event.commitments.items())),
                "decision_id": event.decision_id,
                "effect_id": event.effect_id,
                "policy_epoch": event.policy_epoch,
                "obligation_id": event.obligation_id,
                "local_sequence": event.local_sequence,
                "request_id": event.request_id,
                "context_id": event.context_id,
            }
        )
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _trace_correlations(
    contract: BindingContract, observation: AttemptObservation
) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Validate declared cross-node correlations without trusting SUT decisions."""

    events = observation.events
    required = set(contract.raw["trace_policy"]["correlation_ids"])
    errors: list[str] = []
    values: dict[str, Any] = {}

    for field in ("request_id", "decision_id", "context_id", "policy_epoch"):
        if field not in required:
            continue
        observed = [getattr(event, field) for event in events]
        if any(value is None or value == "" for value in observed):
            errors.append(f"declared correlation {field} is missing")
            continue
        distinct = set(observed)
        if len(distinct) != 1:
            errors.append(f"declared correlation {field} is inconsistent across trace nodes")
            continue
        values[field] = observed[0]

    obligations = {event.obligation_id for event in events}
    if obligations != {contract.contract_id}:
        errors.append("obligation_id does not consistently identify the loaded contract")
    else:
        values["obligation_id"] = contract.contract_id

    effect_events = [event for event in events if event.node_id == contract.effect_boundary_id]
    if len(effect_events) != 1:
        errors.append("effect boundary does not have exactly one trace event")
    else:
        values["event_id"] = effect_events[0].event_id
        values["effect_id"] = effect_events[0].effect_id
    if "effect_id" in required:
        nonnull_effects = {
            event.effect_id for event in events if event.effect_id is not None
        }
        if not effect_events or effect_events[0].effect_id != contract.effect_id:
            errors.append("effect boundary lacks the declared effect_id")
        if any(effect_id != contract.effect_id for effect_id in nonnull_effects):
            errors.append("trace contains an inconsistent effect_id")

    return tuple(errors), values


def _effect_correlation_errors(
    contract: BindingContract,
    records: Sequence[Any],
    correlations: Mapping[str, Any],
) -> tuple[str, ...]:
    required = set(contract.raw["trace_policy"]["correlation_ids"])
    supported = {
        "request_id",
        "decision_id",
        "context_id",
        "policy_epoch",
        "event_id",
        "obligation_id",
    }
    errors: list[str] = []
    for record in records:
        for field in sorted(required & supported):
            expected = correlations.get(field)
            observed = getattr(record, field)
            if expected is None or observed is None:
                errors.append(f"effect record lacks declared correlation {field}")
            elif observed != expected:
                errors.append(f"effect record correlation mismatch for {field}")
    return tuple(dict.fromkeys(errors))


def _matched_dependency_errors(
    contract: BindingContract,
    positive_events: Sequence[TraceEvent],
    test_events: Sequence[TraceEvent],
    *,
    expect_endpoint_change: bool,
) -> tuple[str, ...]:
    positive_validation = validate_attempt_dag(
        positive_events,
        contract.graph,
        required_commitment_label="dependency",
    )
    if not positive_validation.usable:
        return ("matched positive trace is incomplete or invalid",)
    positive_by_node = {event.node_id: event for event in positive_events}
    test_by_node = {event.node_id: event for event in test_events}
    endpoints = tuple(
        dict.fromkeys(
            (contract.actual.boundary_id, contract.expected.boundary_id)
        )
    )
    changed = [
        node
        for node in endpoints
        if positive_by_node[node].commitments["dependency"]
        != test_by_node[node].commitments["dependency"]
    ]
    if expect_endpoint_change and not changed:
        return ("negative distinction is not observable at either relation endpoint",)
    if not expect_endpoint_change and changed:
        return ("specificity control changed a protected relation endpoint",)
    return ()


def _localize_missing_causal_edges(
    contract: BindingContract,
    events: Sequence[TraceEvent],
    missing_edges: Sequence[Any],
) -> LocalizationResult:
    """Localize an affirmative missing happens-before dependency."""

    by_node = {event.node_id: event for event in events}
    sources = tuple(
        dict.fromkeys(
            (contract.actual.boundary_id, contract.expected.boundary_id)
        )
    )
    candidates = [
        edge
        for edge in missing_edges
        if any(contract.graph.has_path(source, edge.source) for source in sources)
        and contract.graph.has_path(edge.target, contract.effect_boundary_id)
    ]
    frontier = []
    for candidate in candidates:
        if any(
            other != candidate
            and contract.graph.has_path(other.target, candidate.source)
            for other in candidates
        ):
            continue
        frontier.append(
            LossEdge(
                source_event_id=by_node[candidate.source].event_id,
                target_event_id=by_node[candidate.target].event_id,
                source_node_id=candidate.source,
                target_node_id=candidate.target,
            )
        )
    if not frontier:
        return LocalizationResult(
            LocalizationStatus.INDETERMINATE,
            reasons=("no missing declared causal edge lies on a relation-to-effect path",),
        )
    ordered = tuple(sorted(frontier))
    status = (
        LocalizationStatus.FIRST_OBSERVED_LOSS
        if len(ordered) == 1
        else LocalizationStatus.CANDIDATE_FRONTIER
    )
    return LocalizationResult(status, candidate_frontier=ordered)


def evaluate_trial(
    contract: BindingContract,
    observation: AttemptObservation,
    ledger: EffectLedger,
    *,
    positive_control: OracleResult | None = None,
    matched_positive_events: Sequence[TraceEvent] | None = None,
) -> OracleResult:
    """Evaluate one attempt; incomplete evidence can never yield PASS."""

    trial = observation.trial
    if trial.contract_id != contract.contract_id or trial.operator is not contract.relation:
        return _indeterminate(observation, "trial does not belong to the loaded contract")
    expected_relation = trial.kind is not TrialKind.NEGATIVE
    if trial.relation_holds() is not expected_relation:
        return _indeterminate(observation, "trial relation does not match its compiler kind")
    validation = validate_attempt_dag(
        observation.events,
        contract.graph,
        required_commitment_label="dependency",
    )
    causal_contract_violation = bool(validation.missing_causal_edges) and validation.complete
    if not validation.usable and not (
        trial.kind is TrialKind.NEGATIVE and causal_contract_violation
    ):
        reasons = list(validation.errors)
        reasons.extend(f"missing trace node: {node}" for node in validation.missing_nodes)
        return _indeterminate(observation, *reasons)
    if any(
        event.trial_id != trial.trial_id or event.attempt_id != observation.attempt_id
        for event in observation.events
    ):
        return _indeterminate(observation, "trace correlation does not match trial/attempt")
    correlation_errors, correlations = _trace_correlations(contract, observation)
    if correlation_errors:
        return _indeterminate(observation, *correlation_errors)
    try:
        effect_records = ledger.matching_records(
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            effect_id=contract.effect_id,
        )
        receipts = ledger.matching_receipts(
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            effect_id=contract.effect_id,
        )
    except ObserverUnavailableError as exc:
        return _indeterminate(observation, f"effect observer unavailable: {exc}")
    if len(receipts) != 1:
        return _indeterminate(
            observation,
            "effect observer lacks exactly one attempt-complete receipt",
        )
    effect_errors = _effect_correlation_errors(
        contract, (*effect_records, *receipts), correlations
    )
    if effect_errors:
        return _indeterminate(observation, *effect_errors, effect_observed=True)
    if receipts[0].observed_effect_count != len(effect_records):
        return _indeterminate(
            observation,
            "effect observer receipt count does not match effect records",
        )
    if any(record.sequence >= receipts[0].sequence for record in effect_records):
        return _indeterminate(
            observation,
            "effect observer receipt does not close the attempt after all effects",
        )
    observed = bool(effect_records)

    if trial.kind is TrialKind.POSITIVE:
        if len(effect_records) > 1:
            return _indeterminate(
                observation,
                "positive control produced duplicate effects",
                effect_observed=True,
            )
        if not observed:
            return _indeterminate(
                observation,
                "positive control did not reach the independently observed effect",
                effect_observed=False,
            )
        return OracleResult(
            contract_id=trial.contract_id,
            pair_id=trial.pair_id,
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            trace_digest=_trace_digest(observation.events),
            verdict=Verdict.PASS,
            effect_observed=True,
            reasons=("positive control is non-vacuously reachable",),
        )

    if positive_control is None or positive_control.verdict is not Verdict.PASS:
        return _indeterminate(
            observation,
            "matched positive control is not proven reachable",
            effect_observed=observed,
        )
    if matched_positive_events is None:
        return _indeterminate(
            observation,
            "matched positive trace is unavailable",
            effect_observed=observed,
        )
    positive_trial_ids = {event.trial_id for event in matched_positive_events}
    positive_attempt_ids = {event.attempt_id for event in matched_positive_events}
    if (
        positive_control.contract_id != contract.contract_id
        or positive_control.pair_id != trial.pair_id
        or positive_control.effect_observed is not True
        or positive_trial_ids != {positive_control.trial_id}
        or positive_attempt_ids != {positive_control.attempt_id}
        or positive_control.trace_digest != _trace_digest(matched_positive_events)
    ):
        return _indeterminate(
            observation,
            "matched positive control lineage does not match this contract, pair, and trace",
            effect_observed=observed,
        )
    dependency_errors = _matched_dependency_errors(
        contract,
        matched_positive_events,
        observation.events,
        expect_endpoint_change=trial.kind is TrialKind.NEGATIVE,
    )
    if dependency_errors:
        return _indeterminate(
            observation,
            *dependency_errors,
            effect_observed=observed,
        )

    if causal_contract_violation:
        localization = _localize_missing_causal_edges(
            contract,
            observation.events,
            validation.missing_causal_edges,
        )
        if localization.status is LocalizationStatus.INDETERMINATE:
            return _indeterminate(
                observation,
                *localization.reasons,
                effect_observed=observed,
            )
        return OracleResult(
            contract_id=trial.contract_id,
            pair_id=trial.pair_id,
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            trace_digest=_trace_digest(observation.events),
            verdict=Verdict.FAIL,
            effect_observed=observed,
            reasons=("complete trace violates a required causal dependency",),
            localization=localization,
        )

    if trial.kind is TrialKind.SPECIFICITY:
        verdict = Verdict.PASS if observed else Verdict.FAIL
        reason = (
            "irrelevant perturbation preserved the allowed effect"
            if observed
            else "irrelevant perturbation incorrectly suppressed the allowed effect"
        )
        return OracleResult(
            contract_id=trial.contract_id,
            pair_id=trial.pair_id,
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            trace_digest=_trace_digest(observation.events),
            verdict=verdict,
            effect_observed=observed,
            reasons=(reason,),
        )

    if not observed:
        return OracleResult(
            contract_id=trial.contract_id,
            pair_id=trial.pair_id,
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            trace_digest=_trace_digest(observation.events),
            verdict=Verdict.PASS,
            effect_observed=False,
            reasons=("relation violation did not produce the prohibited effect",),
            localization=LocalizationResult(LocalizationStatus.NO_PROHIBITED_EFFECT),
        )
    localization = localize_minimal_loss(
        matched_positive_events,
        observation.events,
        contract.graph,
        source_node_id=contract.actual.boundary_id,
        additional_source_node_ids=(contract.expected.boundary_id,),
        effect_node_id=contract.effect_boundary_id,
        prohibited_effect_observed=True,
    )
    if localization.status is LocalizationStatus.INDETERMINATE:
        return OracleResult(
            contract_id=trial.contract_id,
            pair_id=trial.pair_id,
            trial_id=trial.trial_id,
            attempt_id=observation.attempt_id,
            trace_digest=_trace_digest(observation.events),
            verdict=Verdict.INDETERMINATE,
            effect_observed=True,
            reasons=localization.reasons,
            localization=localization,
        )
    return OracleResult(
        contract_id=trial.contract_id,
        pair_id=trial.pair_id,
        trial_id=trial.trial_id,
        attempt_id=observation.attempt_id,
        trace_digest=_trace_digest(observation.events),
        verdict=Verdict.FAIL,
        effect_observed=True,
        reasons=("relation violation produced the independently observed prohibited effect",),
        localization=localization,
    )


def evaluate_matched_suite(
    contract: BindingContract,
    suite: CompiledSuite,
    observations: Mapping[str, AttemptObservation],
    ledger: EffectLedger,
) -> Mapping[str, OracleResult]:
    """Evaluate the positive control first, then all matched trials."""

    expected_ids = {trial.trial_id for trial in suite.trials}
    if set(observations) != expected_ids:
        missing = expected_ids - set(observations)
        extra = set(observations) - expected_ids
        detail = []
        if missing:
            detail.append("missing observations: " + ", ".join(sorted(missing)))
        if extra:
            detail.append("unexpected observations: " + ", ".join(sorted(extra)))
        raise ValueError("; ".join(detail))
    positive_observation = observations[suite.positive.trial_id]
    positive_result = evaluate_trial(contract, positive_observation, ledger)
    results: dict[str, OracleResult] = {suite.positive.trial_id: positive_result}
    for trial in (*suite.negative, *suite.specificity):
        observation = observations[trial.trial_id]
        results[trial.trial_id] = evaluate_trial(
            contract,
            observation,
            ledger,
            positive_control=positive_result,
            matched_positive_events=positive_observation.events,
        )
    return results

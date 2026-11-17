"""Concrete B0--B3 and AttestFlow ablation arm implementations.

Every arm executes the same two SUT attempts and receives the same telemetry
and observer availability.  The shared health gate is deliberately outside the
method-specific oracle: an arm may elect not to *use* traces or effects for its
verdict, but missing evidence can never silently become ``PASS``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from attestflow.contract import BindingContract
from attestflow.trace import (
    LocalizationStatus,
    TraceEvent as CoreTraceEvent,
    localize_minimal_loss,
)
from benchmarks.attestflow_synthetic.adapter import SyntheticFixtureAdapter
from benchmarks.attestflow_synthetic.api import PairObservation, RunObservation, TrialInput
from benchmarks.attestflow_synthetic.core_analyzer import CoreObservationAnalyzer
from benchmarks.attestflow_synthetic.loader import (
    BENCHMARK_ROOT,
    load_contract,
    load_families,
    load_scenarios,
    load_variants,
)

from .models import (
    ARM_IDS,
    ArmBudget,
    ArmExecution,
    ArmProfile,
    ArmResult,
    EvidenceHealth,
)


ObservationTransform = Callable[[Mapping[str, str], PairObservation], PairObservation]


@dataclass(frozen=True, slots=True)
class CaseContext:
    row: Mapping[str, str]
    family: Mapping[str, Any]
    contract: Mapping[str, Any]
    variant: Mapping[str, Any]
    positive: TrialInput
    manual_test: TrialInput


def _relation_holds(contract: Mapping[str, Any], trial: TrialInput) -> bool:
    operator = str(contract["relation"]["operator"])
    actual = trial.actual_value
    expected = trial.expected_value
    if operator in {"equal", "same_decision"}:
        return bool(actual == expected)
    if operator == "fresh":
        return (
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and isinstance(expected, int)
            and not isinstance(expected, bool)
            and actual >= expected
        )
    if operator == "authorized_by_policy":
        if isinstance(expected, (str, bytes)):
            return bool(actual == expected)
        try:
            return bool(actual in expected)
        except TypeError:
            return False
    raise ValueError(f"unsupported relation operator: {operator}")


def _different_value(value: Any, token: str) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, tuple):
        return (token,)
    if isinstance(value, list):
        return [token]
    if isinstance(value, set):
        return {token}
    return token


def _generic_inputs(context: CaseContext) -> tuple[TrialInput, TrialInput]:
    """Create one deterministic, non-compiler generic mutation candidate."""

    positive = context.positive
    material = (
        f"generic-v1|{context.row['global_seed']}|"
        f"{context.row['derived_block_seed']}|{context.row['case_id']}"
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    axis = ("actual", "expected")[int(digest[:2], 16) % 2]
    token = f"generic-{digest[:20]}"
    operator = str(context.contract["relation"]["operator"])
    actual = positive.actual_value
    expected = positive.expected_value
    if operator == "fresh":
        if not isinstance(actual, int) or not isinstance(expected, int):
            raise ValueError("fresh generic mutation requires integer endpoints")
        if axis == "actual":
            actual = expected - 1
        else:
            expected = actual + 1
    elif operator == "authorized_by_policy":
        if axis == "actual":
            actual = token
        else:
            expected = (token,)
    elif axis == "actual":
        actual = _different_value(actual, token)
    else:
        expected = _different_value(expected, token)
    test = replace(
        positive,
        scenario_id=f"{positive.scenario_id}-generic-{digest[:10]}",
        role="negative",
        actual_value=actual,
        expected_value=expected,
        request_id=f"{positive.request_id}-generic-{digest[:8]}",
        changed_fields=(axis,),
    )
    if _relation_holds(context.contract, test):
        raise AssertionError("generic mutator failed to violate the public relation")
    return positive, test


def _compiler_inputs(context: CaseContext) -> tuple[TrialInput, TrialInput]:
    return CoreObservationAnalyzer().prepare_fixture_inputs(
        context.contract,
        context.positive,
        context.manual_test,
    )


def _manual_inputs(context: CaseContext) -> tuple[TrialInput, TrialInput]:
    return context.positive, context.manual_test


def _decision_value(family: Mapping[str, Any], run: RunObservation) -> str | None:
    decision_node = str(family["decision_node"])
    values = [event.decision for event in run.trace_events if event.node_id == decision_node]
    if len(values) != 1 or values[0] not in {"allow", "deny"}:
        return None
    return values[0]


def _decision_oracle(context: CaseContext, pair: PairObservation, label: str) -> ArmResult:
    positive = _decision_value(context.family, pair.positive)
    observed = _decision_value(context.family, pair.test)
    if positive != "allow":
        return ArmResult(
            "INDETERMINATE",
            f"{label}: positive decision signal is missing or unreachable",
            localization_mode="INDETERMINATE",
        )
    if observed is None:
        return ArmResult(
            "INDETERMINATE",
            f"{label}: test decision signal is missing or unparseable",
            localization_mode="INDETERMINATE",
        )
    expected = "allow" if _relation_holds(context.contract, pair.test.trial) else "deny"
    verdict = "PASS" if observed == expected else "FAIL"
    return ArmResult(
        verdict,
        f"{label}: expected decision={expected}; observed decision={observed}",
        localization_mode="NOT_APPLICABLE" if verdict == "PASS" else "UNLOCATED",
    )


def _effect_oracle(context: CaseContext, pair: PairObservation, label: str) -> ArmResult:
    positive_count = len(pair.positive.effect_records)
    test_count = len(pair.test.effect_records)
    if positive_count != 1:
        return ArmResult(
            "INDETERMINATE",
            f"{label}: positive control has {positive_count} independently observed effects",
            localization_mode="INDETERMINATE",
        )
    expected = _relation_holds(context.contract, pair.test.trial)
    if expected:
        if test_count > 1:
            return ArmResult(
                "INDETERMINATE",
                f"{label}: relation-preserving test has duplicate effects ({test_count})",
                localization_mode="INDETERMINATE",
            )
        verdict = "PASS" if test_count == 1 else "FAIL"
    else:
        verdict = "PASS" if test_count == 0 else "FAIL"
    return ArmResult(
        verdict,
        f"{label}: expected effect={str(expected).lower()}; observed count={test_count}",
        localization_mode="NOT_APPLICABLE" if verdict == "PASS" else "UNLOCATED",
    )


def _core_events(run: RunObservation, obligation_id: str) -> tuple[CoreTraceEvent, ...]:
    return tuple(
        CoreTraceEvent(
            trial_id=event.trial_id,
            attempt_id=event.attempt_id,
            event_id=event.event_id,
            predecessor_event_ids=event.predecessor_event_ids,
            node_id=event.node_id,
            commitments={"dependency": f"hmac-sha256:{event.dependency_commitment}"},
            decision_id=event.decision_id,
            effect_id=event.effect_id,
            policy_epoch=event.policy_epoch,
            obligation_id=obligation_id,
            local_sequence=event.sequence,
            request_id=event.request_id,
            context_id=None,
        )
        for event in run.trace_events
    )


def _typed_frontier(
    context: CaseContext, pair: PairObservation
) -> tuple[tuple[tuple[str, str], ...], str, str]:
    binding = BindingContract.from_validated_mapping(context.contract)
    result = localize_minimal_loss(
        _core_events(pair.positive, binding.contract_id),
        _core_events(pair.test, binding.contract_id),
        binding.graph,
        source_node_id=binding.actual.boundary_id,
        additional_source_node_ids=(binding.expected.boundary_id,),
        effect_node_id=binding.effect_boundary_id,
        prohibited_effect_observed=True,
    )
    frontier = tuple(
        (edge.source_node_id, edge.target_node_id)
        for edge in result.candidate_frontier
    )
    if result.status is LocalizationStatus.NO_PROHIBITED_EFFECT:
        mode = "UNLOCATED"
    else:
        mode = result.status.value
    detail = "; ".join(result.reasons) or result.status.value
    return frontier, mode, detail


def _minimal_edges(
    binding: BindingContract, candidates: list[tuple[str, str]]
) -> tuple[tuple[str, str], ...]:
    frontier: list[tuple[str, str]] = []
    for candidate in candidates:
        if any(
            other != candidate
            and other[1] != "@independent_effect_ledger"
            and binding.graph.has_path(other[1], candidate[0])
            for other in candidates
        ):
            continue
        frontier.append(candidate)
    return tuple(sorted(set(frontier)))


def _generic_frontier(
    context: CaseContext, pair: PairObservation
) -> tuple[tuple[str, str], ...]:
    """Generic graph/commitment differencing, separate from the core localizer."""

    binding = BindingContract.from_validated_mapping(context.contract)
    positive = {event.node_id: event for event in pair.positive.trace_events}
    test = {event.node_id: event for event in pair.test.trace_events}
    by_event = {event.event_id: event for event in pair.test.trace_events}
    observed_edges = {
        (by_event[predecessor].node_id, event.node_id)
        for event in pair.test.trace_events
        for predecessor in event.predecessor_event_ids
        if predecessor in by_event
    }
    relevant = [
        (edge.source, edge.target)
        for edge in binding.graph.edges
        if any(
            binding.graph.has_path(source, edge.source)
            for source in (binding.actual.boundary_id, binding.expected.boundary_id)
        )
        and binding.graph.has_path(edge.target, binding.effect_boundary_id)
    ]
    missing = [edge for edge in relevant if edge not in observed_edges]
    if missing:
        return _minimal_edges(binding, missing)
    changed = {
        node: positive[node].dependency_commitment != test[node].dependency_commitment
        for node in binding.graph.nodes
    }
    collapsed = [edge for edge in relevant if changed[edge[0]] and not changed[edge[1]]]
    if collapsed:
        return _minimal_edges(binding, collapsed)
    if changed[binding.effect_boundary_id]:
        return ((binding.effect_boundary_id, "@independent_effect_ledger"),)
    return ()


def _trace_run_errors(
    contract: Mapping[str, Any], run: RunObservation, label: str
) -> list[str]:
    errors: list[str] = []
    events = run.trace_events
    required_nodes = {str(item["id"]) for item in contract["observation_graph"]["nodes"]}
    counts = Counter(event.node_id for event in events)
    missing = sorted(required_nodes - counts.keys())
    duplicates = sorted(node for node, count in counts.items() if count != 1)
    extras = sorted(set(counts) - required_nodes)
    if missing:
        errors.append(f"{label} trace missing nodes={missing}")
    if duplicates:
        errors.append(f"{label} trace duplicate nodes={duplicates}")
    if extras:
        errors.append(f"{label} trace undeclared nodes={extras}")
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        errors.append(f"{label} trace has duplicate event ids")
    event_id_set = set(event_ids)
    if any(
        predecessor not in event_id_set
        for event in events
        for predecessor in event.predecessor_event_ids
    ):
        errors.append(f"{label} trace references a missing predecessor event")
    sequences = [event.sequence for event in events]
    if any(sequence <= 0 for sequence in sequences) or len(sequences) != len(set(sequences)):
        errors.append(f"{label} trace has invalid or duplicate local sequence")

    expected_trial = f"trial-{run.trial.scenario_id}"
    correlations: tuple[tuple[str, set[Any], set[Any]], ...] = (
        ("trial_id", {event.trial_id for event in events}, {expected_trial}),
        ("attempt_id", {event.attempt_id for event in events}, set()),
        ("request_id", {event.request_id for event in events}, {run.trial.request_id}),
        (
            "effect_id",
            {event.effect_id for event in events},
            {str(contract["protected_effect"]["effect_id"])},
        ),
        ("policy_epoch", {event.policy_epoch for event in events}, {run.trial.policy_epoch}),
    )
    for name, observed, expected in correlations:
        if name == "attempt_id":
            if len(observed) != 1 or not next(iter(observed), ""):
                errors.append(f"{label} trace has ambiguous {name}")
        elif observed != expected:
            errors.append(f"{label} trace has inconsistent {name}")
    decision_ids = {event.decision_id for event in events}
    if len(decision_ids) != 1 or not next(iter(decision_ids), ""):
        errors.append(f"{label} trace has ambiguous decision_id")
    return errors


def _observer_run_errors(
    contract: Mapping[str, Any], run: RunObservation, label: str
) -> list[str]:
    if not run.observer_available:
        return [f"{label} effect observer unavailable"]
    errors: list[str] = []
    attempts = {event.attempt_id for event in run.trace_events}
    expected_attempt = next(iter(attempts), None) if len(attempts) == 1 else None
    expected_trial = f"trial-{run.trial.scenario_id}"
    expected_effect = str(contract["protected_effect"]["effect_id"])
    identities: list[tuple[Any, ...]] = []
    for record in run.effect_records:
        if record.trial_id != expected_trial:
            errors.append(f"{label} observer record has mismatched trial_id")
        if expected_attempt is None or record.attempt_id != expected_attempt:
            errors.append(f"{label} observer record has mismatched attempt_id")
        if record.request_id != run.trial.request_id:
            errors.append(f"{label} observer record has mismatched request_id")
        if record.effect_id != expected_effect:
            errors.append(f"{label} observer record has mismatched effect_id")
        if not record.resource_commitment:
            errors.append(f"{label} observer record has empty resource commitment")
        identities.append(
            (
                record.effect_id,
                record.trial_id,
                record.attempt_id,
                record.request_id,
                record.resource_commitment,
                record.observed_at_sequence,
            )
        )
    if len(identities) != len(set(identities)):
        errors.append(f"{label} observer contains duplicate records")
    return errors


def inspect_evidence(
    contract: Mapping[str, Any], pair: PairObservation
) -> EvidenceHealth:
    trace_errors = [
        *_trace_run_errors(contract, pair.positive, "positive"),
        *_trace_run_errors(contract, pair.test, "test"),
    ]
    observer_errors = [
        *_observer_run_errors(contract, pair.positive, "positive"),
        *_observer_run_errors(contract, pair.test, "test"),
    ]
    positive_reachable = not observer_errors and len(pair.positive.effect_records) == 1
    reasons = [*trace_errors, *observer_errors]
    if not positive_reachable:
        reasons.append("positive control did not produce exactly one trusted dummy effect")
    return EvidenceHealth(
        trace_complete=not trace_errors,
        observer_chain_valid=not observer_errors,
        positive_control_reachable=positive_reachable,
        reasons=tuple(reasons),
    )


class ArmStrategy(ABC):
    profile: ArmProfile

    @abstractmethod
    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        raise NotImplementedError

    @abstractmethod
    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        raise NotImplementedError


class B0NativeArm(ArmStrategy):
    profile = ArmProfile(
        "B0_NATIVE",
        "frozen_native_fixture_pair",
        "native_decision_assertion",
        "none",
        False,
        False,
        False,
        "Synthetic surrogate for a frozen project-native suite; no real project tests are claimed.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _manual_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        return _decision_oracle(context, pair, "frozen native decision assertion")


class B1GenericArm(ArmStrategy):
    profile = ArmProfile(
        "B1_GENERIC",
        "seeded_generic_single_axis_mutator",
        "independent_effect_predicate",
        "none",
        False,
        False,
        True,
        "Controlled generic mutator, not a population-level fuzzing evaluation.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _generic_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        return _effect_oracle(context, pair, "generic mutation effect predicate")


class B2ManualArm(ArmStrategy):
    profile = ArmProfile(
        "B2_MANUAL",
        "checked_in_manual_predicate_pair",
        "manual_relation_effect_predicate",
        "none",
        False,
        False,
        True,
        "Checked-in authored fixture; no human-study or author-time claim is made.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _manual_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        return _effect_oracle(context, pair, "manual predicate-first effect check")


class B3TraceArm(ArmStrategy):
    profile = ArmProfile(
        "B3_TRACE",
        "checked_in_manual_predicate_pair",
        "independent_effect_predicate",
        "generic_graph_commitment_diff",
        False,
        True,
        True,
        "Generic trace differencing uses the same graph endpoints but not the AttestFlow localizer.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _manual_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        detected = _effect_oracle(context, pair, "generic trace baseline effect check")
        if detected.verdict != "FAIL" or _relation_holds(context.contract, pair.test.trial):
            return detected
        frontier = _generic_frontier(context, pair)
        mode = (
            "FIRST_OBSERVED_LOSS"
            if len(frontier) == 1
            else "CANDIDATE_FRONTIER"
            if frontier
            else "UNLOCATED"
        )
        return replace(
            detected,
            reason=f"{detected.reason}; generic trace frontier size={len(frontier)}",
            frontier=frontier,
            localization_mode=mode,
        )


class ATArm(ArmStrategy):
    profile = ArmProfile(
        "A_T",
        "attestflow_contract_compiler",
        "decision_side_assertion",
        "none",
        True,
        False,
        False,
        "Generated tests only; trace and effect records are health-gated but not verdict inputs.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _compiler_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        return _decision_oracle(context, pair, "AttestFlow test-only decision assertion")


class ATRArm(ArmStrategy):
    profile = ArmProfile(
        "A_TR",
        "attestflow_contract_compiler",
        "decision_side_assertion",
        "typed_attestflow_trace_frontier",
        True,
        True,
        False,
        "Decision-side ablation: the independent effect count cannot change its verdict.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _compiler_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        detected = _decision_oracle(context, pair, "AttestFlow decision-side trace check")
        if detected.verdict != "FAIL" or _relation_holds(context.contract, pair.test.trial):
            return detected
        frontier, mode, detail = _typed_frontier(context, pair)
        return replace(
            detected,
            reason=f"{detected.reason}; typed localization={detail}",
            frontier=frontier,
            localization_mode=mode,
        )


class ATEArm(ArmStrategy):
    profile = ArmProfile(
        "A_TE",
        "attestflow_contract_compiler",
        "independent_effect_predicate",
        "none",
        True,
        False,
        True,
        "Effect-side detection without intermediate trace localization.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _compiler_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        return _effect_oracle(context, pair, "AttestFlow generated-test effect check")


class AFullArm(ArmStrategy):
    profile = ArmProfile(
        "A_FULL",
        "attestflow_contract_compiler",
        "attestflow_effect_grounded_oracle",
        "typed_attestflow_trace_frontier",
        True,
        True,
        True,
        "Full generated-test, typed-trace, and independent-effect pipeline.",
    )

    def prepare_inputs(self, context: CaseContext) -> tuple[TrialInput, TrialInput]:
        return _compiler_inputs(context)

    def analyze(self, context: CaseContext, pair: PairObservation) -> ArmResult:
        analysis = CoreObservationAnalyzer().analyze_pair(context.contract, pair)
        verdict = analysis.status
        if verdict not in {"PASS", "FAIL", "INDETERMINATE"}:
            verdict = "INDETERMINATE"
        frontier = tuple(analysis.candidate_frontier)
        mode = (
            "INDETERMINATE"
            if verdict == "INDETERMINATE"
            else "FIRST_OBSERVED_LOSS"
            if len(frontier) == 1
            else "CANDIDATE_FRONTIER"
            if frontier
            else "UNLOCATED"
            if verdict == "FAIL"
            else "NOT_APPLICABLE"
        )
        return ArmResult(
            verdict,
            f"full AttestFlow core: {analysis.reason}",
            frontier,
            mode,
        )


def default_strategies() -> dict[str, ArmStrategy]:
    strategies: tuple[ArmStrategy, ...] = (
        B0NativeArm(),
        B1GenericArm(),
        B2ManualArm(),
        B3TraceArm(),
        ATArm(),
        ATRArm(),
        ATEArm(),
        AFullArm(),
    )
    result = {strategy.profile.arm_id: strategy for strategy in strategies}
    if tuple(result) != ARM_IDS:
        raise AssertionError("default strategies do not cover the frozen arm order")
    fingerprints = {strategy.profile.fingerprint for strategy in strategies}
    if len(fingerprints) != len(strategies):
        raise AssertionError("two arm profiles are behaviorally identical aliases")
    return result


class ArmExecutor:
    """Resolve one schedule row, execute a fresh fixture, and apply its arm."""

    def __init__(
        self,
        *,
        strategies: Mapping[str, ArmStrategy] | None = None,
        observation_transform: ObservationTransform | None = None,
    ) -> None:
        self.strategies = dict(strategies or default_strategies())
        self.observation_transform = observation_transform
        self.families = load_families()
        self.scenarios = load_scenarios()
        self.variants = {item["case_id"]: item for item in load_variants()}

    def _context(self, row: Mapping[str, str]) -> CaseContext:
        case_id = row["case_id"]
        try:
            variant = self.variants[case_id]
        except KeyError as exc:
            raise ValueError(f"schedule case has no synthetic variant: {case_id}") from exc
        family = self.families[str(variant["family_id"])]
        expected = {
            "build_id": str(variant["build_id"]),
            "stack_id": str(variant["family_id"]),
            "split": str(variant["split"]),
        }
        mismatches = [
            f"{field}={row.get(field)!r} expected {value!r}"
            for field, value in expected.items()
            if row.get(field) != value
        ]
        if mismatches:
            raise ValueError("schedule/variant mismatch: " + "; ".join(mismatches))
        contract = load_contract(dict(family))
        return CaseContext(
            row=row,
            family=family,
            contract=contract,
            variant=variant,
            positive=self.scenarios[str(variant["positive_scenario_id"])],
            manual_test=self.scenarios[str(variant["test_scenario_id"])],
        )

    def execute(self, row: Mapping[str, str], budget: ArmBudget) -> ArmExecution:
        arm_id = row["arm"]
        try:
            strategy = self.strategies[arm_id]
        except KeyError as exc:
            raise ValueError(f"no implementation for scheduled arm: {arm_id}") from exc
        context = self._context(row)
        positive, test = strategy.prepare_inputs(context)
        # Preserve semantic values while making every attempt correlation
        # globally schedule-scoped.  The simulator otherwise reuses fixture
        # trial/event IDs across arms even though the schedule assigns a fresh
        # logical process instance to each row.
        correlation_suffix = row["schedule_id"]
        positive = replace(
            positive,
            scenario_id=f"{positive.scenario_id}@{correlation_suffix}",
            request_id=f"{positive.request_id}@{correlation_suffix}",
        )
        test = replace(
            test,
            scenario_id=f"{test.scenario_id}@{correlation_suffix}",
            request_id=f"{test.request_id}@{correlation_suffix}",
        )
        pair = SyntheticFixtureAdapter(
            context.family,
            context.contract,
            context.variant,
        ).execute_pair(positive, test)
        if self.observation_transform is not None:
            pair = self.observation_transform(row, pair)
        health = inspect_evidence(context.contract, pair)
        trace_count = len(pair.positive.trace_events) + len(pair.test.trace_events)
        observer_count = len(pair.positive.effect_records) + len(pair.test.effect_records)
        budget_errors: list[str] = []
        if trace_count > budget.trace_event_limit:
            budget_errors.append(
                f"trace budget exceeded: observed={trace_count} limit={budget.trace_event_limit}"
            )
        if observer_count > budget.observer_record_limit:
            budget_errors.append(
                "observer budget exceeded: "
                f"observed={observer_count} limit={budget.observer_record_limit}"
            )
        if not health.trace_complete:
            result = ArmResult(
                "INDETERMINATE",
                "shared evidence gate: trace missing or ambiguous; " + "; ".join(health.reasons),
                localization_mode="INDETERMINATE",
            )
        elif not health.observer_chain_valid:
            result = ArmResult(
                "INDETERMINATE",
                "shared evidence gate: observer unavailable or invalid; "
                + "; ".join(health.reasons),
                localization_mode="INDETERMINATE",
            )
        elif not health.positive_control_reachable:
            result = ArmResult(
                "INDETERMINATE",
                "shared evidence gate: positive control unreachable; "
                + "; ".join(health.reasons),
                localization_mode="INDETERMINATE",
            )
        elif budget_errors:
            result = ArmResult(
                "INDETERMINATE",
                "shared equal-budget gate: " + "; ".join(budget_errors),
                localization_mode="INDETERMINATE",
            )
        else:
            result = strategy.analyze(context, pair)

        contract_path = Path(BENCHMARK_ROOT) / str(context.family["contract_file"])
        return ArmExecution(
            profile=strategy.profile,
            budget=budget,
            pair=pair,
            health=health,
            result=result,
            contract_sha256=hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        )

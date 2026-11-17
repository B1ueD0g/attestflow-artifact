"""Adapter from benchmark observations to the real ``src/attestflow`` core.

The adapter performs representation conversion only.  Contract validation,
trial compilation, effect-ledger decisions, and loss localization are delegated
to the production research core.  No variant or ground-truth object is accepted
by the public analyzer API.
"""

from __future__ import annotations

import json
import importlib
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from .api import AnalysisResult, PairObservation, RunObservation, TrialInput

if TYPE_CHECKING:
    from attestflow.ledger import EffectLedger as CoreEffectLedger
    from attestflow.trace import LocalizationResult as CoreLocalizationResult
    from attestflow.trace import TraceEvent as CoreTraceEvent


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _PROJECT_ROOT / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

core_commitment_module = importlib.import_module("attestflow.commitment")
core_compiler = importlib.import_module("attestflow.compiler")
core_contract = importlib.import_module("attestflow.contract")
core_ledger = importlib.import_module("attestflow.ledger")
core_oracle = importlib.import_module("attestflow.oracle")
core_trace = importlib.import_module("attestflow.trace")

_CONTRACT_SCHEMA = _PROJECT_ROOT / "contracts" / "attestflow-contract.schema.json"
_ADAPTER_COMMITMENT_KEY = b"attestflow-synthetic-core-adapter-key-v1"


class CoreObservationAnalyzer:
    """Analyze fixture output using AttestFlow's real core components."""

    @staticmethod
    def _select_test_template(compiled: Any, test: TrialInput) -> tuple[Any, str]:
        """Select only from public compiler axes declared by the test input.

        The selector never receives a case ID, SUT variant, defect family, or
        ground truth. A two-axis robustness input is composed from two frozen
        one-axis compiler outputs and is not counted as a single-defect trial.
        """

        axes = tuple(test.changed_fields)
        if test.role == "specificity_control":
            if axes != ("irrelevant",):
                raise ValueError("specificity input must declare only the irrelevant axis")
            return compiled.specificity[0], "single-axis:irrelevant"
        actual_trial = next(
            trial
            for trial in compiled.negative
            if trial.changed_semantic_axes == ("actual",)
        )
        expected_trial = next(
            trial
            for trial in compiled.negative
            if trial.changed_semantic_axes == ("expected",)
        )
        if axes == ("actual",):
            return actual_trial, "single-axis:actual"
        if axes == ("expected",):
            return expected_trial, "single-axis:expected"
        if axes == ("actual", "expected"):
            return (
                replace(
                    actual_trial,
                    trial_id=f"{actual_trial.pair_id}-negative-composed-1",
                    expected_value=expected_trial.expected_value,
                    changed_semantic_axes=("actual", "expected"),
                ),
                "pairwise-composed:actual+expected",
            )
        raise ValueError(f"unsupported public compiler axis declaration: {axes!r}")

    def prepare_fixture_inputs(
        self,
        contract: Mapping[str, Any],
        positive: TrialInput,
        test: TrialInput,
    ) -> tuple[TrialInput, TrialInput]:
        """Replace hand-written values with deterministic compiler output.

        This pre-execution hook receives no SUT variant or ground truth.  The
        original input objects contribute only fixture routing/correlation
        fields and the test role (negative versus specificity).
        """

        with tempfile.TemporaryDirectory(prefix="attestflow-input-compiler-") as directory:
            binding = self._load_binding(contract, Path(directory))
            compiled = core_compiler.compile_contract(binding)
        test_template, _ = self._select_test_template(compiled, test)
        compiled_positive = replace(
            positive,
            actual_value=compiled.positive.actual_value,
            expected_value=compiled.positive.expected_value,
            irrelevant_label=compiled.positive.irrelevant_value,
            changed_fields=compiled.positive.changed_semantic_axes,
        )
        compiled_test = replace(
            test,
            actual_value=test_template.actual_value,
            expected_value=test_template.expected_value,
            irrelevant_label=test_template.irrelevant_value,
            changed_fields=test_template.changed_semantic_axes,
        )
        return compiled_positive, compiled_test

    def analyze_pair(
        self,
        contract: Mapping[str, Any],
        observation: PairObservation,
    ) -> AnalysisResult:
        with tempfile.TemporaryDirectory(prefix="attestflow-core-adapter-") as directory:
            temporary_root = Path(directory)
            binding = self._load_binding(contract, temporary_root)
            compiled = core_compiler.compile_contract(binding)

            positive_trial = replace(
                compiled.positive,
                actual_value=observation.positive.trial.actual_value,
                expected_value=observation.positive.trial.expected_value,
                irrelevant_value=observation.positive.trial.irrelevant_label,
                changed_semantic_axes=observation.positive.trial.changed_fields,
            )
            test_template, input_derivation = self._select_test_template(
                compiled, observation.test.trial
            )
            test_trial = replace(
                test_template,
                actual_value=observation.test.trial.actual_value,
                expected_value=observation.test.trial.expected_value,
                irrelevant_value=observation.test.trial.irrelevant_label,
                changed_semantic_axes=observation.test.trial.changed_fields,
            )
            compiler_values_exact = (
                observation.positive.trial.actual_value == compiled.positive.actual_value
                and observation.positive.trial.expected_value
                == compiled.positive.expected_value
                and observation.test.trial.actual_value == test_template.actual_value
                and observation.test.trial.expected_value == test_template.expected_value
            )

            positive_attempt = self._attempt_id(observation.positive, "positive")
            test_attempt = self._attempt_id(observation.test, "test")
            correlation_errors = (
                *self._correlation_errors(
                    observation.positive,
                    effect_id=binding.effect_id,
                ),
                *self._correlation_errors(
                    observation.test,
                    effect_id=binding.effect_id,
                ),
            )
            if correlation_errors:
                return AnalysisResult(
                    status="INDETERMINATE",
                    candidate_frontier=(),
                    positive_effect_count=len(observation.positive.effect_records),
                    test_effect_count=len(observation.test.effect_records),
                    reason="core-adapter correlation failure: "
                    + "; ".join(correlation_errors),
                )
            positive_events = self._convert_events(
                observation.positive,
                trial_id=positive_trial.trial_id,
                attempt_id=positive_attempt,
                obligation_id=binding.contract_id,
            )
            test_events = self._convert_events(
                observation.test,
                trial_id=test_trial.trial_id,
                attempt_id=test_attempt,
                obligation_id=binding.contract_id,
            )
            positive_attempt_observation = core_oracle.AttemptObservation(
                positive_trial,
                positive_attempt,
                positive_events,
            )
            test_attempt_observation = core_oracle.AttemptObservation(
                test_trial,
                test_attempt,
                test_events,
            )

            ledger = core_ledger.EffectLedger(temporary_root / "effects.jsonl")
            if observation.positive.observer_available and observation.test.observer_available:
                self._append_effects(
                    ledger,
                    observation.positive,
                    trial_id=positive_trial.trial_id,
                    attempt_id=positive_attempt,
                    effect_id=binding.effect_id,
                    effect_boundary_id=binding.effect_boundary_id,
                    obligation_id=binding.contract_id,
                )
                self._append_effects(
                    ledger,
                    observation.test,
                    trial_id=test_trial.trial_id,
                    attempt_id=test_attempt,
                    effect_id=binding.effect_id,
                    effect_boundary_id=binding.effect_boundary_id,
                    obligation_id=binding.contract_id,
                )
            else:
                # A missing observer is represented as a genuinely unreadable
                # core ledger rather than as a synthesized negative record.
                ledger.path.unlink()

            positive_result = core_oracle.evaluate_trial(
                binding,
                positive_attempt_observation,
                ledger,
            )
            test_result = core_oracle.evaluate_trial(
                binding,
                test_attempt_observation,
                ledger,
                positive_control=positive_result,
                matched_positive_events=positive_events,
            )

            localization_probe: CoreLocalizationResult | None = None
            if test_trial.kind is core_compiler.TrialKind.NEGATIVE:
                localization_probe = core_trace.localize_minimal_loss(
                    positive_events,
                    test_events,
                    binding.graph,
                    source_node_id=binding.actual.boundary_id,
                    additional_source_node_ids=(binding.expected.boundary_id,),
                    effect_node_id=binding.effect_boundary_id,
                    prohibited_effect_observed=bool(observation.test.effect_records),
                )

            localization = test_result.localization
            frontier: tuple[tuple[str, str], ...] = ()
            if localization is not None:
                frontier = tuple(
                    (edge.source_node_id, edge.target_node_id)
                    for edge in localization.candidate_frontier
                )
            probe_status = (
                localization_probe.status.value
                if localization_probe is not None
                else "NOT_APPLICABLE"
            )
            reasons = "; ".join(
                (
                    f"core-compiler={compiled.compiler_version}",
                    f"core-compiler-values-exact={str(compiler_values_exact).lower()}",
                    f"core-input-derivation={input_derivation}",
                    f"core-positive={positive_result.verdict.value}",
                    f"core-test={test_result.verdict.value}",
                    f"core-localization-probe={probe_status}",
                    *test_result.reasons,
                )
            )
            return AnalysisResult(
                status=test_result.verdict.value,
                candidate_frontier=frontier,
                positive_effect_count=len(observation.positive.effect_records),
                test_effect_count=len(observation.test.effect_records),
                reason=reasons,
            )

    @staticmethod
    def _load_binding(
        contract: Mapping[str, Any],
        temporary_root: Path,
    ) -> Any:
        contract_path = temporary_root / "contract.json"
        contract_path.write_text(
            json.dumps(contract, sort_keys=True),
            encoding="utf-8",
        )
        return core_contract.load_contract(contract_path, _CONTRACT_SCHEMA)

    @staticmethod
    def _correlation_errors(
        run: RunObservation,
        *,
        effect_id: str,
    ) -> tuple[str, ...]:
        """Validate every original correlation before core-ID projection."""

        errors: list[str] = []
        expected_fixture_trial_id = f"trial-{run.trial.scenario_id}"
        trace_attempts = {event.attempt_id for event in run.trace_events}
        trace_trials = {event.trial_id for event in run.trace_events}
        trace_requests = {event.request_id for event in run.trace_events}
        trace_effects = {event.effect_id for event in run.trace_events}
        if trace_trials != {expected_fixture_trial_id}:
            errors.append(
                f"trace trial ids {sorted(trace_trials)} do not match "
                f"{expected_fixture_trial_id}"
            )
        if len(trace_attempts) != 1:
            errors.append(f"trace attempt ids are not unique: {sorted(trace_attempts)}")
        if trace_requests != {run.trial.request_id}:
            errors.append(
                f"trace request ids {sorted(trace_requests)} do not match input request"
            )
        if trace_effects != {effect_id}:
            errors.append(
                f"trace effect ids {sorted(trace_effects)} do not match contract effect"
            )
        expected_attempt = next(iter(trace_attempts), None)
        for index, record in enumerate(run.effect_records):
            if record.trial_id != expected_fixture_trial_id:
                errors.append(f"effect record {index} has mismatched trial id")
            if record.attempt_id != expected_attempt:
                errors.append(f"effect record {index} has mismatched attempt id")
            if record.request_id != run.trial.request_id:
                errors.append(f"effect record {index} has mismatched request id")
            if record.effect_id != effect_id:
                errors.append(f"effect record {index} has mismatched effect id")
        return tuple(errors)

    @staticmethod
    def _attempt_id(run: RunObservation, label: str) -> str:
        if run.trace_events:
            return run.trace_events[0].attempt_id
        return f"core-adapter-{label}-empty-trace"

    @staticmethod
    def _convert_events(
        run: RunObservation,
        *,
        trial_id: str,
        attempt_id: str,
        obligation_id: str,
    ) -> tuple[CoreTraceEvent, ...]:
        events: list[CoreTraceEvent] = []
        for event in run.trace_events:
            events.append(
                core_trace.TraceEvent(
                    trial_id=trial_id,
                    attempt_id=attempt_id,
                    event_id=event.event_id,
                    predecessor_event_ids=event.predecessor_event_ids,
                    node_id=event.node_id,
                    commitments={
                        "dependency": core_commitment_module.commitment(
                            event.dependency_commitment,
                            _ADAPTER_COMMITMENT_KEY,
                            label="attestflow.synthetic.adapter.actual.v1",
                        )
                    },
                    decision_id=event.decision_id,
                    effect_id=event.effect_id,
                    policy_epoch=event.policy_epoch,
                    obligation_id=obligation_id,
                    local_sequence=event.sequence,
                    request_id=event.request_id,
                    context_id=None,
                )
            )
        return tuple(events)

    @staticmethod
    def _append_effects(
        ledger: CoreEffectLedger,
        run: RunObservation,
        *,
        trial_id: str,
        attempt_id: str,
        effect_id: str,
        effect_boundary_id: str,
        obligation_id: str,
    ) -> None:
        effect_events = [
            event for event in run.trace_events if event.node_id == effect_boundary_id
        ]
        if len(effect_events) != 1:
            raise ValueError("effect boundary must have exactly one trace event")
        effect_event = effect_events[0]
        for record in run.effect_records:
            ledger.append_effect(
                trial_id=trial_id,
                attempt_id=attempt_id,
                effect_id=effect_id,
                resource_commitment=core_commitment_module.commitment(
                    record.resource_commitment,
                    _ADAPTER_COMMITMENT_KEY,
                    label="attestflow.synthetic.adapter.resource.v1",
                ),
                observed_at_ns=record.observed_at_sequence,
                request_id=effect_event.request_id,
                decision_id=effect_event.decision_id,
                context_id=None,
                policy_epoch=effect_event.policy_epoch,
                event_id=effect_event.event_id,
                obligation_id=obligation_id,
            )
        ledger.append_attempt_receipt(
            trial_id=trial_id,
            attempt_id=attempt_id,
            effect_id=effect_id,
            observed_effect_count=len(run.effect_records),
            receipt_commitment=core_commitment_module.commitment(
                {
                    "attempt_id": attempt_id,
                    "observed_effect_count": len(run.effect_records),
                },
                _ADAPTER_COMMITMENT_KEY,
                label="attestflow.synthetic.adapter.observer-receipt.v1",
            ),
            observed_at_ns=max(
                (record.observed_at_sequence for record in run.effect_records),
                default=effect_event.sequence,
            )
            + 1,
            request_id=effect_event.request_id,
            decision_id=effect_event.decision_id,
            context_id=None,
            policy_epoch=effect_event.policy_epoch,
            event_id=effect_event.event_id,
            obligation_id=obligation_id,
        )

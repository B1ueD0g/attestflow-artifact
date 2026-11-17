"""Deterministic synthetic pipeline simulator.

This module is a fixture, not an implementation of RATS.  It models only the
observable propagation of one declared dependency through a small DAG.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .api import EffectRecord, RunObservation, TraceEvent, TrialInput


_FIXTURE_HMAC_KEY = b"attestflow-public-synthetic-fixture-key-v1"


def commitment(value: str) -> str:
    """Return a deterministic synthetic commitment; no raw value is logged."""

    return hmac.new(
        _FIXTURE_HMAC_KEY,
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass
class DummyEffectLedger:
    """Append-only in-memory ledger independent of SUT decision events."""

    _records: list[EffectRecord] = field(default_factory=list)

    def append(self, record: EffectRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> tuple[EffectRecord, ...]:
        return tuple(self._records)


class SyntheticPipelineSimulator:
    """Execute one private synthetic SUT variant against a trial."""

    SUPPORTED_BEHAVIORS = {
        "NONE",
        "DROP_EXPECTATION",
        "OVERWRITE_ACTUAL",
        "MIS_KEY",
        "FAIL_OPEN",
        "CACHE_REPLAY",
        "EPOCH_STALE",
        "CROSS_REQUEST_SWAP",
        "RELEASE_BEFORE_DECISION",
        "TRACE_DROP",
        "IRRELEVANT_PERTURBATION",
    }

    def __init__(
        self,
        family: Mapping[str, Any],
        contract: Mapping[str, Any],
        private_variant: Mapping[str, Any],
    ) -> None:
        self.family = family
        self.contract = contract
        self.private_variant = private_variant
        behavior = str(private_variant["behavior"])
        if behavior not in self.SUPPORTED_BEHAVIORS:
            raise ValueError(f"unsupported synthetic behavior: {behavior}")
        if private_variant["family_id"] != family["family_id"]:
            raise ValueError("variant/family mismatch")

    def execute(self, trial: TrialInput, *, attempt_number: int) -> RunObservation:
        if trial.family_id != self.family["family_id"]:
            raise ValueError("trial/family mismatch")

        behavior = str(self.private_variant["behavior"])
        states, allow_effect, decision = self._base_states(trial)
        relation_valid = allow_effect
        states, allow_effect, decision = self._apply_behavior(
            behavior,
            trial,
            states,
            allow_effect,
            decision,
        )

        effect_id = str(self.contract["protected_effect"]["effect_id"])
        trial_id = f"trial-{trial.scenario_id}"
        attempt_id = f"{trial_id}-attempt-{attempt_number}"
        decision_id = f"decision-{trial.scenario_id}-{attempt_number}"
        nodes = [item["id"] for item in self.contract["observation_graph"]["nodes"]]
        edges = [
            (item["from"], item["to"])
            for item in self.contract["observation_graph"]["edges"]
        ]
        event_ids = {node: f"{attempt_id}:{node}" for node in nodes}

        ordered_nodes = list(nodes)
        if behavior == "RELEASE_BEFORE_DECISION" and not relation_valid:
            effect_node = str(self.family["effect_node"])
            decision_node = str(self.family["decision_node"])
            ordered_nodes.remove(effect_node)
            ordered_nodes.insert(ordered_nodes.index(decision_node), effect_node)

        trace_events: list[TraceEvent] = []
        for sequence, node in enumerate(ordered_nodes, start=1):
            if behavior == "TRACE_DROP" and node == self.family["decision_node"]:
                continue
            predecessors = [source for source, target in edges if target == node]
            if (
                behavior == "RELEASE_BEFORE_DECISION"
                and not relation_valid
                and node == self.family["effect_node"]
            ):
                predecessors = [
                    source
                    for source, target in edges
                    if target == self.family["decision_node"]
                ]
            trace_events.append(
                TraceEvent(
                    event_id=event_ids[node],
                    node_id=node,
                    predecessor_event_ids=tuple(event_ids[item] for item in predecessors),
                    dependency_commitment=commitment(states[node]),
                    sequence=sequence,
                    trial_id=trial_id,
                    attempt_id=attempt_id,
                    request_id=trial.request_id,
                    decision_id=decision_id,
                    effect_id=effect_id,
                    policy_epoch=trial.policy_epoch,
                    decision=decision if node == self.family["decision_node"] else None,
                )
            )

        ledger = DummyEffectLedger()
        if allow_effect:
            effect_sequence = next(
                event.sequence
                for event in trace_events
                if event.node_id == self.family["effect_node"]
            )
            ledger.append(
                EffectRecord(
                    effect_id=effect_id,
                    trial_id=trial_id,
                    attempt_id=attempt_id,
                    request_id=trial.request_id,
                    resource_commitment=commitment(
                        f"dummy-resource::{effect_id}::{trial.scenario_id}"
                    ),
                    observed_at_sequence=effect_sequence,
                )
            )

        return RunObservation(
            trial=trial,
            trace_events=tuple(trace_events),
            effect_records=ledger.records,
            observer_available=True,
        )

    def _base_states(self, trial: TrialInput) -> tuple[dict[str, str], bool, str]:
        family_id = self.family["family_id"]
        valid = self._relation_holds(trial.actual_value, trial.expected_value)
        outcome = "allow" if valid else "deny"

        if family_id == "SYN_LINEAR_SESSION":
            states = {
                "evidence_source": f"actual::{trial.actual_value}",
                "request_ingress": f"expected::{trial.expected_value}",
                "appraisal_service": self._pair_state(trial, "appraisal"),
                "authorization_decision": self._pair_state(trial, f"decision::{outcome}"),
                "dummy_effect_boundary": self._pair_state(trial, f"effect::{outcome}"),
            }
        elif family_id == "SYN_POLICY_FANIN":
            states = {
                "workload_evidence": f"actual::{trial.actual_value}",
                "policy_request": f"expected::{trial.expected_value}",
                "tenant_context": "tenant::synthetic-red",
                "policy_lookup": self._pair_state(trial, "policy-lookup"),
                "authorization_decision": self._pair_state(trial, f"decision::{outcome}"),
                "dummy_effect_boundary": self._pair_state(trial, f"effect::{outcome}"),
            }
        elif family_id == "SYN_EPOCH_CACHE":
            states = {
                "fresh_appraisal": "appraisal::synthetic-ok",
                "cached_decision_epoch": f"actual::{trial.actual_value}",
                "current_policy_epoch": f"expected::{trial.expected_value}",
                "decision_cache": f"decision-cache::actual={trial.actual_value}",
                "epoch_guard": self._pair_state(trial, "epoch-guard"),
                "authorization_decision": self._pair_state(trial, f"decision::{outcome}"),
                "dummy_effect_boundary": self._pair_state(trial, f"effect::{outcome}"),
            }
        elif family_id == "SYN_CONCURRENT_DUALPATH":
            states = {
                "evidence_branch_a": f"actual::{trial.actual_value}",
                "evidence_branch_b": f"expected::{trial.expected_value}",
                "evidence_join": self._pair_state(trial, "join"),
                "authorization_decision": self._pair_state(trial, f"decision::{outcome}"),
                "dummy_effect_boundary": self._pair_state(trial, f"effect::{outcome}"),
            }
        else:
            raise ValueError(f"unknown synthetic family: {family_id}")
        return states, valid, outcome

    def _relation_holds(self, actual: Any, expected: Any) -> bool:
        """Evaluate the public contract relation, never a scenario answer label."""

        operator = str(self.contract["relation"]["operator"])
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
        raise ValueError(f"unsupported contract relation: {operator}")

    @staticmethod
    def _pair_state(trial: TrialInput, stage: str) -> str:
        return (
            f"{stage}::actual={trial.actual_value}::"
            f"expected={trial.expected_value}"
        )

    def _apply_behavior(
        self,
        behavior: str,
        trial: TrialInput,
        states: dict[str, str],
        allow_effect: bool,
        decision: str,
    ) -> tuple[dict[str, str], bool, str]:
        if behavior in {"NONE", "IRRELEVANT_PERTURBATION", "TRACE_DROP"}:
            return states, allow_effect, decision

        converge_node: str | None = None
        marker: str | None = None
        if behavior == "DROP_EXPECTATION":
            converge_node = "appraisal_service"
            marker = f"actual-only::{trial.actual_value}"
        elif behavior == "OVERWRITE_ACTUAL":
            converge_node = "appraisal_service"
            marker = f"expected-only::{trial.expected_value}"
        elif behavior == "MIS_KEY":
            converge_node = "policy_lookup"
            marker = "mis-key::synthetic-default-policy"
        elif behavior == "FAIL_OPEN":
            converge_node = "authorization_decision"
            marker = "fail-open::allow"
        elif behavior == "CACHE_REPLAY":
            converge_node = "decision_cache"
            marker = "cache::synthetic-prior-allow"
        elif behavior == "EPOCH_STALE":
            converge_node = "epoch_guard"
            marker = f"stale-guard::cached={trial.actual_value}"
        elif behavior == "CROSS_REQUEST_SWAP":
            converge_node = "evidence_join"
            marker = "join::synthetic-cross-request-accepted"
        elif behavior == "RELEASE_BEFORE_DECISION":
            converge_node = "dummy_effect_boundary"
            marker = "effect::released-without-decision-dependency"

        if converge_node is None or marker is None:
            raise AssertionError(f"unhandled behavior: {behavior}")

        for node in self._reachable_from(converge_node):
            states[node] = f"{marker}::{node}"

        if behavior == "RELEASE_BEFORE_DECISION":
            allow_effect = True
        else:
            allow_effect = True
            decision = "allow"
        return states, allow_effect, decision

    def _reachable_from(self, start: str) -> set[str]:
        edges: Iterable[tuple[str, str]] = (
            (item["from"], item["to"])
            for item in self.contract["observation_graph"]["edges"]
        )
        adjacency: dict[str, set[str]] = {}
        for source, target in edges:
            adjacency.setdefault(source, set()).add(target)
        reached = {start}
        frontier = [start]
        while frontier:
            source = frontier.pop()
            for target in adjacency.get(source, set()):
                if target not in reached:
                    reached.add(target)
                    frontier.append(target)
        return reached

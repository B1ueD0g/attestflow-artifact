"""Relation-specific generation of matched synthetic trials.

The public compiler API intentionally has no mutation-hint, expected-node, or
defect-location argument.  Each relation has one frozen derivation rule.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .contract import BindingContract, RelationOperator


class TrialKind(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    SPECIFICITY = "specificity"


@dataclass(frozen=True, slots=True)
class Trial:
    trial_id: str
    pair_id: str
    contract_id: str
    kind: TrialKind
    operator: RelationOperator
    actual_value: Any
    expected_value: Any
    irrelevant_value: str
    expected_effect: bool
    changed_semantic_axes: tuple[str, ...]

    def relation_holds(self) -> bool:
        return relation_holds(self.operator, self.actual_value, self.expected_value)


@dataclass(frozen=True, slots=True)
class CompiledSuite:
    compiler_version: str
    contract_id: str
    seed: int
    domain_size: int
    positive: Trial
    negative: tuple[Trial, ...]
    specificity: tuple[Trial, ...]

    @property
    def trials(self) -> tuple[Trial, ...]:
        return (self.positive, *self.negative, *self.specificity)


COMPILER_VERSION = "attestflow-compiler/0.3"


def _token(seed: int, namespace: str, index: int) -> str:
    material = f"{COMPILER_VERSION}|{seed}|{namespace}|{index}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:24]


def relation_holds(operator: RelationOperator, actual: Any, expected: Any) -> bool:
    if operator in (RelationOperator.EQUAL, RelationOperator.SAME_DECISION):
        return bool(actual == expected)
    if operator is RelationOperator.FRESH:
        return isinstance(actual, int) and isinstance(expected, int) and actual >= expected
    if operator is RelationOperator.AUTHORIZED_BY_POLICY:
        if isinstance(expected, (str, bytes)):
            return bool(actual == expected)
        try:
            return bool(actual in expected)
        except TypeError:
            return False
    raise ValueError(f"unsupported relation operator: {operator}")


def _derive_values(
    operator: RelationOperator, seed: int, domain_size: int
) -> tuple[Any, Any, tuple[Any, ...], tuple[Any, ...]]:
    """Return positive endpoints plus relation-violating values for either axis."""

    if operator is RelationOperator.EQUAL:
        matching = f"context-{_token(seed, 'context', 0)}"
        nonmatching_actual = tuple(
            f"context-{_token(seed, 'context', index)}"
            for index in range(1, domain_size)
        )
        nonmatching_expected = tuple(
            f"context-{_token(seed, 'context-expected', index)}"
            for index in range(1, domain_size)
        )
        return matching, matching, nonmatching_actual, nonmatching_expected
    if operator is RelationOperator.SAME_DECISION:
        matching = f"decision-{_token(seed, 'decision', 0)}"
        nonmatching_actual = tuple(
            f"decision-{_token(seed, 'decision', index)}"
            for index in range(1, domain_size)
        )
        nonmatching_expected = tuple(
            f"decision-{_token(seed, 'decision-expected', index)}"
            for index in range(1, domain_size)
        )
        return matching, matching, nonmatching_actual, nonmatching_expected
    if operator is RelationOperator.FRESH:
        threshold = 1_800_000_000 + seed % 1_000_000
        actual = threshold + 1
        return (
            actual,
            threshold,
            tuple(threshold - index for index in range(1, domain_size)),
            tuple(actual + index for index in range(1, domain_size)),
        )
    if operator is RelationOperator.AUTHORIZED_BY_POLICY:
        authorized = f"principal-{_token(seed, 'principal', 0)}"
        unauthorized = tuple(
            f"principal-{_token(seed, 'principal', index)}"
            for index in range(1, domain_size)
        )
        policy = (authorized,)
        excluding_policies = tuple(
            (f"principal-{_token(seed, 'policy-principal', index)}",)
            for index in range(1, domain_size)
        )
        return authorized, policy, unauthorized, excluding_policies
    raise ValueError(f"unsupported relation operator: {operator}")


def compile_contract(contract: BindingContract) -> CompiledSuite:
    """Compile a validated contract into one matched low-risk synthetic suite."""

    positive_actual, positive_expected, negative_actuals, negative_expecteds = _derive_values(
        contract.relation, contract.seed, contract.distinct_contexts_min
    )
    pair_digest = hashlib.sha256(
        f"{COMPILER_VERSION}|{contract.contract_id}|{contract.seed}".encode("utf-8")
    ).hexdigest()[:16]
    pair_id = f"pair-{pair_digest}"
    irrelevant_a = f"irrelevant-{_token(contract.seed, 'irrelevant', 0)}"
    irrelevant_b = f"irrelevant-{_token(contract.seed, 'irrelevant', 1)}"
    positive = Trial(
        trial_id=f"{pair_id}-positive",
        pair_id=pair_id,
        contract_id=contract.contract_id,
        kind=TrialKind.POSITIVE,
        operator=contract.relation,
        actual_value=positive_actual,
        expected_value=positive_expected,
        irrelevant_value=irrelevant_a,
        expected_effect=True,
        changed_semantic_axes=(),
    )
    negative = tuple(
        Trial(
            trial_id=f"{pair_id}-negative-actual-{index}",
            pair_id=pair_id,
            contract_id=contract.contract_id,
            kind=TrialKind.NEGATIVE,
            operator=contract.relation,
            actual_value=negative_actual,
            expected_value=positive_expected,
            irrelevant_value=irrelevant_a,
            expected_effect=False,
            changed_semantic_axes=("actual",),
        )
        for index, negative_actual in enumerate(negative_actuals, start=1)
    )
    negative_expected = tuple(
        Trial(
            trial_id=f"{pair_id}-negative-expected-{index}",
            pair_id=pair_id,
            contract_id=contract.contract_id,
            kind=TrialKind.NEGATIVE,
            operator=contract.relation,
            actual_value=positive_actual,
            expected_value=negative_value,
            irrelevant_value=irrelevant_a,
            expected_effect=False,
            changed_semantic_axes=("expected",),
        )
        for index, negative_value in enumerate(negative_expecteds, start=1)
    )
    negative = (*negative, *negative_expected)
    specificity = Trial(
        trial_id=f"{pair_id}-specificity-irrelevant",
        pair_id=pair_id,
        contract_id=contract.contract_id,
        kind=TrialKind.SPECIFICITY,
        operator=contract.relation,
        actual_value=positive_actual,
        expected_value=positive_expected,
        irrelevant_value=irrelevant_b,
        expected_effect=True,
        changed_semantic_axes=("irrelevant",),
    )
    if not positive.relation_holds():
        raise AssertionError("compiler generated a vacuous positive trial")
    if any(trial.relation_holds() for trial in negative):
        raise AssertionError("compiler generated a non-violating negative trial")
    if not specificity.relation_holds():
        raise AssertionError("compiler specificity control changed the protected relation")
    return CompiledSuite(
        compiler_version=COMPILER_VERSION,
        contract_id=contract.contract_id,
        seed=contract.seed,
        domain_size=contract.distinct_contexts_min,
        positive=positive,
        negative=negative,
        specificity=(specificity,),
    )

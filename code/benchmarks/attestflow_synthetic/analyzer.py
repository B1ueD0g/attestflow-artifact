"""Reference analyzer for fixture QA, not the claimed AttestFlow core."""

from __future__ import annotations

from typing import Any, Mapping

from .api import AnalysisResult, PairObservation, trace_by_node


class ReferenceContinuityAnalyzer:
    """Conservatively analyze paired commitments and the dummy effect ledger.

    This intentionally small implementation demonstrates the adapter contract
    and validates expected fixture behavior.  It must not be reported as a real
    system evaluation or as the final localization algorithm.
    """

    def analyze_pair(
        self,
        contract: Mapping[str, Any],
        observation: PairObservation,
    ) -> AnalysisResult:
        positive_count = len(observation.positive.effect_records)
        test_count = len(observation.test.effect_records)
        if not observation.positive.observer_available or not observation.test.observer_available:
            return self._result(
                "INDETERMINATE",
                (),
                positive_count,
                test_count,
                "effect observer unavailable",
            )

        try:
            positive = trace_by_node(observation.positive.trace_events)
            test = trace_by_node(observation.test.trace_events)
        except ValueError as error:
            return self._result(
                "INDETERMINATE",
                (),
                positive_count,
                test_count,
                str(error),
            )

        required_nodes = {
            item["id"] for item in contract["observation_graph"]["nodes"]
        }
        missing_positive = sorted(required_nodes - positive.keys())
        missing_test = sorted(required_nodes - test.keys())
        if missing_positive or missing_test:
            return self._result(
                "INDETERMINATE",
                (),
                positive_count,
                test_count,
                f"missing trace nodes; positive={missing_positive}; test={missing_test}",
            )

        if positive_count != 1:
            return self._result(
                "INVALID_TEST",
                (),
                positive_count,
                test_count,
                "positive control did not produce exactly one dummy effect",
            )

        operator = str(contract["relation"]["operator"])
        if operator in {"equal", "same_decision"}:
            relation_holds = bool(
                observation.test.trial.actual_value
                == observation.test.trial.expected_value
            )
        elif operator == "fresh":
            relation_holds = bool(
                observation.test.trial.actual_value
                >= observation.test.trial.expected_value
            )
        elif operator == "authorized_by_policy":
            relation_holds = bool(
                observation.test.trial.actual_value
                in observation.test.trial.expected_value
            )
        else:
            raise ValueError(f"unsupported contract relation: {operator}")
        if relation_holds:
            if test_count == 1:
                return self._result(
                    "PASS",
                    (),
                    positive_count,
                    test_count,
                    "irrelevant perturbation preserved the required relation",
                )
            return self._result(
                "INVALID_TEST",
                (),
                positive_count,
                test_count,
                "relation-preserving test did not reach the dummy effect",
            )

        if test_count == 0:
            return self._result(
                "PASS",
                (),
                positive_count,
                test_count,
                "relation-violating input was denied and caused no dummy effect",
            )

        changed = {
            node: positive[node].dependency_commitment
            != test[node].dependency_commitment
            for node in required_nodes
        }
        candidate_frontier = tuple(
            (edge["from"], edge["to"])
            for edge in contract["observation_graph"]["edges"]
            if changed[edge["from"]] and not changed[edge["to"]]
        )
        if not candidate_frontier:
            return self._result(
                "INDETERMINATE",
                (),
                positive_count,
                test_count,
                "dummy effect violated the relation but no observable loss edge was identifiable",
            )
        return self._result(
            "FAIL",
            candidate_frontier,
            positive_count,
            test_count,
            "relation-violating input caused a dummy effect",
        )

    @staticmethod
    def _result(
        status: str,
        frontier: tuple[tuple[str, str], ...],
        positive_count: int,
        test_count: int,
        reason: str,
    ) -> AnalysisResult:
        return AnalysisResult(
            status=status,
            candidate_frontier=frontier,
            positive_effect_count=positive_count,
            test_effect_count=test_count,
            reason=reason,
        )

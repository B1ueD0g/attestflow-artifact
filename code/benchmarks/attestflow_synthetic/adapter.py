"""SUT adapter that keeps private variant configuration away from analyzers."""

from __future__ import annotations

from typing import Any, Mapping

from .api import PairObservation, TrialInput
from .simulator import SyntheticPipelineSimulator


class SyntheticFixtureAdapter:
    """Execute matched trials for one synthetic SUT build."""

    def __init__(
        self,
        family: Mapping[str, Any],
        contract: Mapping[str, Any],
        private_variant: Mapping[str, Any],
    ) -> None:
        self._simulator = SyntheticPipelineSimulator(
            family,
            contract,
            private_variant,
        )

    def execute_pair(
        self,
        positive: TrialInput,
        test: TrialInput,
    ) -> PairObservation:
        return PairObservation(
            positive=self._simulator.execute(positive, attempt_number=1),
            test=self._simulator.execute(test, attempt_number=2),
        )


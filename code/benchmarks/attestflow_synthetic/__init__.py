"""Executable, local-only synthetic fixtures for AttestFlow."""

from .adapter import SyntheticFixtureAdapter
from .analyzer import ReferenceContinuityAnalyzer
from .core_analyzer import CoreObservationAnalyzer
from .api import (
    AnalysisResult,
    EffectRecord,
    ObservationAnalyzer,
    PairObservation,
    RunObservation,
    TraceEvent,
    TrialInput,
)

__all__ = [
    "AnalysisResult",
    "CoreObservationAnalyzer",
    "EffectRecord",
    "ObservationAnalyzer",
    "PairObservation",
    "ReferenceContinuityAnalyzer",
    "RunObservation",
    "SyntheticFixtureAdapter",
    "TraceEvent",
    "TrialInput",
]

"""Conservative, result-agnostic analysis primitives for AttestFlow."""

from .detection import paired_detection_summary
from .frontier import frontier_metrics, summarize_frontiers
from .ledger import GENESIS_HASH, LedgerValidationError, append_record, validate_ledger
from .performance import paired_performance_summary
from .statistics import exact_binomial_two_sided, exact_mcnemar, wilson_interval

__all__ = [
    "GENESIS_HASH",
    "LedgerValidationError",
    "append_record",
    "exact_binomial_two_sided",
    "exact_mcnemar",
    "frontier_metrics",
    "paired_detection_summary",
    "paired_performance_summary",
    "summarize_frontiers",
    "validate_ledger",
    "wilson_interval",
]

"""AttestFlow's low-risk, local experimental core.

The package deliberately provides testing and observation primitives, not an
authorization token or a production effect gate.
"""

from .commitment import commitment
from .compiler import CompiledSuite, Trial, TrialKind, compile_contract
from .contract import (
    BindingContract,
    ContractValidationError,
    GraphEdge,
    ObservationGraph,
    RelationOperator,
    load_contract,
)
from .ledger import (
    EffectLedger,
    EffectRecord,
    LedgerIntegrityError,
    ObserverUnavailableError,
)
from .oracle import (
    AttemptObservation,
    OracleResult,
    Verdict,
    evaluate_matched_suite,
    evaluate_trial,
)
from .trace import (
    LocalizationResult,
    LocalizationStatus,
    LossEdge,
    TraceEvent,
    TraceValidation,
    localize_minimal_loss,
    validate_attempt_dag,
)

__all__ = [
    "AttemptObservation",
    "BindingContract",
    "CompiledSuite",
    "ContractValidationError",
    "EffectLedger",
    "EffectRecord",
    "GraphEdge",
    "LedgerIntegrityError",
    "LocalizationResult",
    "LocalizationStatus",
    "LossEdge",
    "ObservationGraph",
    "ObserverUnavailableError",
    "OracleResult",
    "RelationOperator",
    "TraceEvent",
    "TraceValidation",
    "Trial",
    "TrialKind",
    "Verdict",
    "commitment",
    "compile_contract",
    "evaluate_matched_suite",
    "evaluate_trial",
    "load_contract",
    "localize_minimal_loss",
    "validate_attempt_dag",
]


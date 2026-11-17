"""Controlled, non-confirmatory execution framework for synthetic arms."""

from .arms import ArmExecutor, default_strategies, inspect_evidence
from .models import ARM_IDS, DEFAULT_BUDGET, ArmBudget, RunBundle, SchedulePlan
from .runner import (
    ScheduleValidationError,
    execute_schedule,
    json_digest,
    load_frozen_schedule,
    validate_formal_ledger,
    validate_schedule_rows,
    write_bundle,
)

__all__ = [
    "ARM_IDS",
    "DEFAULT_BUDGET",
    "ArmBudget",
    "ArmExecutor",
    "RunBundle",
    "SchedulePlan",
    "ScheduleValidationError",
    "default_strategies",
    "execute_schedule",
    "inspect_evidence",
    "json_digest",
    "load_frozen_schedule",
    "validate_formal_ledger",
    "validate_schedule_rows",
    "write_bundle",
]


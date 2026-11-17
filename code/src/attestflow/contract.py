"""Loading and semantic validation for AttestFlow binding contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]


class ContractValidationError(ValueError):
    """Raised when a contract or its observation graph is invalid."""


class RelationOperator(str, Enum):
    EQUAL = "equal"
    FRESH = "fresh"
    AUTHORIZED_BY_POLICY = "authorized_by_policy"
    SAME_DECISION = "same_decision"


@dataclass(frozen=True, slots=True)
class ValueEndpoint:
    semantic_path: str
    value_type: str
    boundary_id: str


@dataclass(frozen=True, slots=True, order=True)
class GraphEdge:
    source: str
    target: str


@dataclass(frozen=True, slots=True)
class ObservationGraph:
    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]

    def __post_init__(self) -> None:
        if len(self.nodes) != len(set(self.nodes)):
            raise ContractValidationError("observation_graph contains duplicate node ids")
        node_set = set(self.nodes)
        if not node_set:
            raise ContractValidationError("observation_graph has no nodes")
        if len(self.edges) != len(set(self.edges)):
            raise ContractValidationError("observation_graph contains duplicate edges")
        for edge in self.edges:
            if edge.source not in node_set or edge.target not in node_set:
                raise ContractValidationError(
                    f"observation_graph edge references unknown node: {edge.source}->{edge.target}"
                )
            if edge.source == edge.target:
                raise ContractValidationError("observation_graph cannot contain self edges")
        self._assert_acyclic()

    def _assert_acyclic(self) -> None:
        indegree = {node: 0 for node in self.nodes}
        successors: dict[str, list[str]] = {node: [] for node in self.nodes}
        for edge in self.edges:
            indegree[edge.target] += 1
            successors[edge.source].append(edge.target)
        ready = sorted(node for node, degree in indegree.items() if degree == 0)
        visited = 0
        while ready:
            node = ready.pop(0)
            visited += 1
            for successor in sorted(successors[node]):
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    ready.append(successor)
                    ready.sort()
        if visited != len(self.nodes):
            raise ContractValidationError("observation_graph must be a DAG")

    @property
    def node_set(self) -> frozenset[str]:
        return frozenset(self.nodes)

    @property
    def edge_set(self) -> frozenset[GraphEdge]:
        return frozenset(self.edges)

    def successors(self, node: str) -> tuple[str, ...]:
        return tuple(sorted(edge.target for edge in self.edges if edge.source == node))

    def predecessors(self, node: str) -> tuple[str, ...]:
        return tuple(sorted(edge.source for edge in self.edges if edge.target == node))

    def has_path(self, source: str, target: str) -> bool:
        if source == target:
            return True
        pending = [source]
        seen = {source}
        while pending:
            current = pending.pop()
            for successor in self.successors(current):
                if successor == target:
                    return True
                if successor not in seen:
                    seen.add(successor)
                    pending.append(successor)
        return False


@dataclass(frozen=True, slots=True)
class BindingContract:
    contract_id: str
    version: str
    description: str
    actual: ValueEndpoint
    expected: ValueEndpoint
    relation: RelationOperator
    graph: ObservationGraph
    effect_id: str
    effect_boundary_id: str
    seed: int
    distinct_contexts_min: int
    positive_name: str
    raw: Mapping[str, Any]

    @classmethod
    def from_validated_mapping(cls, value: Mapping[str, Any]) -> "BindingContract":
        nodes = tuple(item["id"] for item in value["observation_graph"]["nodes"])
        edges = tuple(
            GraphEdge(item["from"], item["to"])
            for item in value["observation_graph"]["edges"]
        )
        graph = ObservationGraph(nodes=nodes, edges=edges)
        actual = ValueEndpoint(**value["actual"])
        expected = ValueEndpoint(**value["expected"])
        effect_boundary_id = value["effect_observer"]["boundary_id"]
        for boundary in (actual.boundary_id, expected.boundary_id, effect_boundary_id):
            if boundary not in graph.node_set:
                raise ContractValidationError(
                    f"declared boundary {boundary!r} is absent from observation_graph"
                )
        if not graph.has_path(actual.boundary_id, effect_boundary_id):
            raise ContractValidationError(
                "actual boundary has no path to the independently observed effect boundary"
            )
        required_correlations = {"trial_id", "attempt_id", "event_id"}
        correlations = set(value["trace_policy"]["correlation_ids"])
        missing = required_correlations - correlations
        if missing:
            raise ContractValidationError(
                "trace_policy lacks required correlation ids: " + ", ".join(sorted(missing))
            )
        operator = RelationOperator(value["relation"]["operator"])
        _validate_endpoint_types(operator, actual, expected)
        # A recursive copy prevents later caller mutation from silently changing
        # an already validated contract.
        frozen_source = json.loads(json.dumps(value))
        return cls(
            contract_id=value["contract_id"],
            version=value["version"],
            description=value["description"],
            actual=actual,
            expected=expected,
            relation=operator,
            graph=graph,
            effect_id=value["protected_effect"]["effect_id"],
            effect_boundary_id=effect_boundary_id,
            seed=value["test_domain"]["deterministic_seed"],
            distinct_contexts_min=value["test_domain"]["distinct_contexts_min"],
            positive_name=value["controls"]["positive"]["name"],
            raw=MappingProxyType(frozen_source),
        )


def _validate_endpoint_types(
    operator: RelationOperator, actual: ValueEndpoint, expected: ValueEndpoint
) -> None:
    if operator is RelationOperator.EQUAL and actual.value_type != expected.value_type:
        raise ContractValidationError("equal requires endpoints with the same value_type")
    if operator is RelationOperator.FRESH:
        if actual.value_type != "epoch" or expected.value_type != "epoch":
            raise ContractValidationError("fresh requires epoch-valued endpoints")
    if operator is RelationOperator.SAME_DECISION:
        if actual.value_type != "decision" or expected.value_type != "decision":
            raise ContractValidationError("same_decision requires decision-valued endpoints")
    if operator is RelationOperator.AUTHORIZED_BY_POLICY and actual.value_type != "identifier":
        raise ContractValidationError(
            "authorized_by_policy requires an identifier-valued actual endpoint"
        )


def _find_default_schema(contract_path: Path) -> Path:
    for directory in (contract_path.parent, *contract_path.parents):
        candidate = directory / "attestflow-contract.schema.json"
        if candidate.is_file():
            return candidate
    raise ContractValidationError(
        "could not locate attestflow-contract.schema.json; pass schema_path explicitly"
    )


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractValidationError(f"cannot read {label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ContractValidationError(f"invalid JSON in {label} {path}: {exc}") from exc


def load_contract(
    contract_path: str | Path, schema_path: str | Path | None = None
) -> BindingContract:
    """Load a JSON contract, validate Draft 2020-12 syntax, then semantics."""

    resolved_contract = Path(contract_path).resolve()
    resolved_schema = (
        Path(schema_path).resolve()
        if schema_path is not None
        else _find_default_schema(resolved_contract)
    )
    contract_value = _read_json(resolved_contract, "contract")
    schema_value = _read_json(resolved_schema, "schema")
    try:
        Draft202012Validator.check_schema(schema_value)
    except SchemaError as exc:
        raise ContractValidationError(f"invalid JSON Schema {resolved_schema}: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema_value).iter_errors(contract_value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        rendered = []
        for error in errors:
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            rendered.append(f"{location}: {error.message}")
        raise ContractValidationError("contract schema validation failed: " + "; ".join(rendered))
    if not isinstance(contract_value, Mapping):
        raise ContractValidationError("contract root must be an object")
    return BindingContract.from_validated_mapping(contract_value)

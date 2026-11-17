"""Candidate-frontier localization metrics with explicit uncertainty."""

from __future__ import annotations

from collections import deque
from statistics import fmean
from typing import Any, Iterable, Mapping, Sequence


Edge = tuple[str, str]
DEFINITIVE_MODES = {"FIRST_OBSERVED_LOSS", "CANDIDATE_FRONTIER"}


def canonical_edge(value: Any) -> Edge:
    if isinstance(value, Mapping):
        endpoint_pairs = (
            ("from_node_id", "to_node_id"),
            ("source_node_id", "target_node_id"),
            ("from", "to"),
        )
        representations: list[Edge] = []
        for left_key, right_key in endpoint_pairs:
            if left_key not in value and right_key not in value:
                continue
            left = value.get(left_key)
            right = value.get(right_key)
            if not isinstance(left, str) or not left or not isinstance(right, str) or not right:
                raise ValueError(f"node-edge endpoints must be non-empty strings: {value!r}")
            representations.append((left, right))
        if not representations:
            if "from_event_id" in value or "to_event_id" in value:
                raise ValueError("event-only edge cannot be mixed with the node-edge namespace")
            raise ValueError(f"node-edge mapping lacks recognized endpoints: {value!r}")
        if len(set(representations)) != 1:
            raise ValueError(f"conflicting node-edge representations: {value!r}")
        return representations[0]
    elif isinstance(value, (tuple, list)) and len(value) == 2:
        left, right = value
    else:
        raise ValueError(f"invalid edge {value!r}")
    if not isinstance(left, str) or not left or not isinstance(right, str) or not right:
        raise ValueError(f"edge endpoints must be non-empty strings: {value!r}")
    return left, right


def _directed_line_graph_distances(topology_edges: set[Edge], source: Edge) -> dict[Edge, int]:
    if source not in topology_edges:
        return {source: 0}
    distances = {source: 0}
    queue: deque[Edge] = deque([source])
    while queue:
        edge = queue.popleft()
        for candidate in topology_edges:
            if candidate not in distances and edge[1] == candidate[0]:
                distances[candidate] = distances[edge] + 1
                queue.append(candidate)
    return distances


def _comparable_directed_distance(left: Edge, right: Edge, topology: set[Edge]) -> int | None:
    forward = _directed_line_graph_distances(topology, left)
    if right in forward:
        return forward[right]
    backward = _directed_line_graph_distances(topology, right)
    return backward.get(left)


def _symmetric_frontier_distance(predicted: set[Edge], truth: set[Edge], topology: set[Edge]) -> float | None:
    if not predicted or not truth:
        return None

    def nearest(sources: set[Edge], targets: set[Edge]) -> list[float]:
        values: list[float] = []
        for source in sources:
            comparable = [
                distance
                for target in targets
                if (distance := _comparable_directed_distance(source, target, topology))
                is not None
            ]
            if not comparable:
                return []
            values.append(float(min(comparable)))
        return values

    forward = nearest(predicted, truth)
    backward = nearest(truth, predicted)
    if not forward or not backward:
        return None
    return (fmean(forward) + fmean(backward)) / 2.0


def frontier_metrics(
    *,
    defect_case_id: str,
    predicted_edges: Iterable[Any],
    truth_edges: Iterable[Any],
    topology_edges: Iterable[Any],
    frontier_mode: str,
    trace_complete: bool,
) -> dict[str, Any]:
    """Score one defect-case frontier against a frozen edge-set ground truth."""

    if not isinstance(defect_case_id, str) or not defect_case_id.strip():
        raise ValueError("defect_case_id must be a non-empty string")
    predicted = {canonical_edge(edge) for edge in predicted_edges}
    truth = {canonical_edge(edge) for edge in truth_edges}
    topology = {canonical_edge(edge) for edge in topology_edges}
    if not truth:
        raise ValueError("ground-truth frontier must be non-empty")
    unknown_frontier_edges = (predicted | truth) - topology
    if unknown_frontier_edges:
        raise ValueError(
            "frontier contains node edges absent from topology: "
            + ", ".join(f"{source}->{target}" for source, target in sorted(unknown_frontier_edges))
        )
    if frontier_mode not in DEFINITIVE_MODES | {"UNLOCATED", "INDETERMINATE"}:
        raise ValueError(f"invalid frontier_mode={frontier_mode!r}")
    if frontier_mode == "FIRST_OBSERVED_LOSS" and len(predicted) != 1:
        raise ValueError("FIRST_OBSERVED_LOSS must contain exactly one predicted edge")
    if frontier_mode == "CANDIDATE_FRONTIER" and not predicted:
        raise ValueError("CANDIDATE_FRONTIER must contain at least one predicted edge")
    if frontier_mode in {"UNLOCATED", "INDETERMINATE"} and predicted:
        raise ValueError(f"{frontier_mode} cannot carry predicted edges")

    definitive = frontier_mode in DEFINITIVE_MODES
    invalid_definitive = definitive and not trace_complete
    overconfident = invalid_definitive or (
        frontier_mode == "FIRST_OBSERVED_LOSS" and len(truth) != 1
    )
    indeterminate = frontier_mode == "INDETERMINATE" or not trace_complete
    if indeterminate:
        return {
            "defect_case_id": defect_case_id,
            "edge_namespace": "node_id",
            "exact_frontier_set_match": None,
            "true_positive_edges": None,
            "false_positive_edges": None,
            "false_negative_edges": None,
            "edge_precision": None,
            "edge_recall": None,
            "edge_f1": None,
            "symmetric_line_graph_distance": None,
            "unlocated": False,
            "indeterminate": True,
            "overconfident": overconfident,
            "boundary": "Definitive localization metrics are withheld because telemetry is incomplete or mode is INDETERMINATE.",
        }

    tp = len(predicted & truth)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(truth)
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "defect_case_id": defect_case_id,
        "edge_namespace": "node_id",
        "exact_frontier_set_match": predicted == truth,
        "true_positive_edges": tp,
        "false_positive_edges": fp,
        "false_negative_edges": fn,
        "edge_precision": precision,
        "edge_recall": recall,
        "edge_f1": f1,
        "symmetric_line_graph_distance": _symmetric_frontier_distance(predicted, truth, topology),
        "unlocated": frontier_mode == "UNLOCATED",
        "indeterminate": False,
        "overconfident": overconfident,
        "boundary": "Distance is symmetric nearest-comparable-edge distance on the direction-respecting node-edge line graph; candidate frontier is not source-code root cause.",
    }


def summarize_frontiers(case_metrics: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate localization metrics with defect cases as the only n."""

    by_case: dict[str, Mapping[str, Any]] = {}
    for item in case_metrics:
        defect_case_id = item.get("defect_case_id")
        if not isinstance(defect_case_id, str) or not defect_case_id.strip():
            raise ValueError("every frontier metric requires a non-empty defect_case_id")
        if defect_case_id in by_case:
            raise ValueError(f"duplicate frontier metrics for defect_case_id={defect_case_id!r}")
        if item.get("edge_namespace") != "node_id":
            raise ValueError(f"frontier metric has non-node edge namespace for {defect_case_id!r}")
        by_case[defect_case_id] = item

    unique_metrics = [by_case[case_id] for case_id in sorted(by_case)]
    total = len(unique_metrics)
    determinate = [item for item in unique_metrics if not item["indeterminate"]]
    localized = [item for item in determinate if not item["unlocated"]]
    distances = [
        float(item["symmetric_line_graph_distance"])
        for item in determinate
        if item["symmetric_line_graph_distance"] is not None
    ]
    tp = sum(int(item["true_positive_edges"] or 0) for item in determinate)
    fp = sum(int(item["false_positive_edges"] or 0) for item in determinate)
    fn = sum(int(item["false_negative_edges"] or 0) for item in determinate)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "independent_unit": "defect_case_id",
        "defect_case_ids": sorted(by_case),
        "n_cases": total,
        "n_determinate": len(determinate),
        "n_localized": len(localized),
        "n_indeterminate": total - len(determinate),
        "n_unlocated": sum(bool(item["unlocated"]) for item in determinate),
        "exact_frontier_matches": sum(item["exact_frontier_set_match"] is True for item in determinate),
        "exact_frontier_rate_determinate": (
            sum(item["exact_frontier_set_match"] is True for item in determinate) / len(determinate)
            if determinate
            else None
        ),
        "macro_edge_precision": fmean(float(item["edge_precision"]) for item in determinate) if determinate else None,
        "macro_edge_recall": fmean(float(item["edge_recall"]) for item in determinate) if determinate else None,
        "macro_edge_f1": fmean(float(item["edge_f1"]) for item in determinate) if determinate else None,
        "micro_edge_precision": precision,
        "micro_edge_recall": recall,
        "micro_edge_f1": f1,
        "mean_symmetric_line_graph_distance": fmean(distances) if distances else None,
        "overconfidence_count": sum(bool(item["overconfident"]) for item in unique_metrics),
        "overconfidence_rate_all_cases": (
            sum(bool(item["overconfident"]) for item in unique_metrics) / total if total else None
        ),
    }

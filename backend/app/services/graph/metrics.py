"""Architecture metrics and structural issues computed on the module graph.

Cycles and layering use the runtime graph: imports that only exist for type
checking (`import type`, `if TYPE_CHECKING:`) don't load anything, so they can't
create an import cycle.
"""

import hashlib
import itertools
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from app.models import ArchitectureIssueType, Severity
from app.services.graph.builder import ArchitectureGraph
from app.services.graph.layers import STACKS

MAX_CYCLE_LENGTH = 10
MAX_CYCLES = 100
CYCLE_ENUMERATION_CEILING = 10_000
MAX_ISSUES_PER_TYPE = 200
BETWEENNESS_SAMPLE_THRESHOLD = 1000  # sample `k` sources above this many nodes
BETWEENNESS_SAMPLE_SIZE = 500

# God modules must clear both an absolute floor and the repository's 90th percentile.
GOD_MIN_NODES = 10
GOD_MIN_LOC = 300
GOD_MIN_FAN_IN = 5
GOD_MIN_CENTRALITY = 0.05


@dataclass
class ArchitectureIssueData:
    issue_type: ArchitectureIssueType
    severity: Severity
    title: str
    description: str
    involved_modules: list[str]
    involved_edges: list[tuple[str, str]] = field(default_factory=list)
    metric_value: float | None = None
    # Where the matching Finding points: the module and the import line.
    location_module: str = ""
    location_line: int = 1
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity, e.g. for deduplication categories."""
        material = "|".join(
            [self.issue_type, *self.involved_modules, *map(":".join, self.involved_edges)]
        )
        return hashlib.sha1(material.encode(), usedforsecurity=False).hexdigest()[:16]


@dataclass
class NodeMetrics:
    fan_in: int
    fan_out: int
    instability: float | None  # None for isolated modules (fan_in + fan_out == 0)
    centrality: float


@dataclass
class ArchitectureMetrics:
    nodes: dict[str, NodeMetrics]
    issues: list[ArchitectureIssueData]
    summary: dict[str, Any]


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[int(q) - 1]


def node_metrics(graph: "nx.DiGraph[str]") -> dict[str, NodeMetrics]:
    """Fan-in/out count distinct internal modules; betweenness is normalised to [0, 1]."""
    n = graph.number_of_nodes()
    if n == 0:
        return {}
    if n > BETWEENNESS_SAMPLE_THRESHOLD:
        centrality = nx.betweenness_centrality(graph, k=BETWEENNESS_SAMPLE_SIZE, seed=0)
    else:
        centrality = nx.betweenness_centrality(graph)
    result: dict[str, NodeMetrics] = {}
    for node in graph.nodes:
        fan_in, fan_out = graph.in_degree(node), graph.out_degree(node)
        total = fan_in + fan_out
        result[node] = NodeMetrics(
            fan_in=fan_in,
            fan_out=fan_out,
            instability=round(fan_out / total, 4) if total else None,
            centrality=round(float(centrality.get(node, 0.0)), 6),
        )
    return result


def _canonical_cycle(cycle: list[str]) -> list[str]:
    """Rotate so the smallest module id comes first (same cycle, same representation)."""
    start = cycle.index(min(cycle))
    return cycle[start:] + cycle[:start]


def find_cycles(runtime: "nx.DiGraph[str]") -> tuple[list[list[str]], bool]:
    """Simple cycles of up to MAX_CYCLE_LENGTH modules, shortest first. Returns (cycles, truncated).

    Enumerating every cycle is exponential on dense graphs, so enumeration is bounded
    by length and stops after CYCLE_ENUMERATION_CEILING; the MAX_CYCLES shortest are kept.
    `truncated` means some cycles were not reported.
    """
    found: list[list[str]] = []
    truncated = False
    components = [c for c in nx.strongly_connected_components(runtime) if len(c) > 1]
    for component in sorted(components, key=lambda c: (len(c), min(c))):
        budget = CYCLE_ENUMERATION_CEILING - len(found)
        cycles = itertools.islice(
            nx.simple_cycles(runtime.subgraph(component), length_bound=MAX_CYCLE_LENGTH), budget + 1
        )
        found.extend(_canonical_cycle(list(c)) for c in cycles)
        if len(found) > CYCLE_ENUMERATION_CEILING:
            found, truncated = found[:CYCLE_ENUMERATION_CEILING], True
            break
    found.sort(key=lambda c: (len(c), c))
    if len(found) > MAX_CYCLES:
        found, truncated = found[:MAX_CYCLES], True
    return found, truncated


def _cycle_issues(arch: ArchitectureGraph, cycles: list[list[str]]) -> list[ArchitectureIssueData]:
    graph = arch.graph
    issues: list[ArchitectureIssueData] = []
    for cycle in cycles:
        edges = list(zip(cycle, cycle[1:] + cycle[:1], strict=True))
        lazy = [e for e in edges if arch.edges[e].lazy]
        chain = " → ".join(graph.nodes[m]["path"] for m in [*cycle, cycle[0]])
        first = arch.edges[edges[0]].first
        description = f"Import cycle of {len(cycle)} modules: {chain}."
        if lazy:
            description += (
                f" {len(lazy)} of the imports happen inside functions, which avoids a circular"
                " import error at load time but still couples the modules both ways."
            )
        issues.append(
            ArchitectureIssueData(
                issue_type=ArchitectureIssueType.CIRCULAR_DEPENDENCY,
                severity=Severity.WARNING if lazy else Severity.ERROR,
                title=f"Circular dependency ({len(cycle)} modules)",
                description=description,
                involved_modules=cycle,
                involved_edges=edges,
                metric_value=float(len(cycle)),
                location_module=cycle[0],
                location_line=first.line,
                details={"lazy_edges": [list(e) for e in lazy]},
            )
        )
    return issues


def _layer_issues(
    arch: ArchitectureGraph, runtime: "nx.DiGraph[str]"
) -> list[ArchitectureIssueData]:
    graph = arch.graph
    # A skip only counts if the repository actually has the skipped layer.
    present: set[tuple[str, str]] = {
        (data["stack"], data["layer"]) for _, data in graph.nodes(data=True) if data["layer"]
    }
    issues: list[ArchitectureIssueData] = []
    for source, target in sorted(runtime.edges):
        src, dst = graph.nodes[source], graph.nodes[target]
        if not src["layer"] or not dst["layer"] or src["stack"] != dst["stack"]:
            continue
        if src["is_test"] or dst["is_test"]:
            continue
        if dst["layer_root"] != dst["path"] and src["path"].startswith(f"{dst['layer_root']}/"):
            # Colocated: a hook inside components/Dialog/ importing that dialog's context
            # belongs to the component tree, not to a separate hooks layer.
            continue
        stack = STACKS[src["stack"]]
        src_rank, dst_rank = stack.index(src["layer"]), stack.index(dst["layer"])
        line = arch.edges[(source, target)].first.line
        if src_rank > dst_rank:
            issues.append(
                ArchitectureIssueData(
                    issue_type=ArchitectureIssueType.LAYER_VIOLATION,
                    severity=Severity.ERROR,
                    title=f"Layer inversion: {src['layer']} imports {dst['layer']}",
                    description=(
                        f"{src['path']} ({src['layer']} layer) imports {dst['path']}"
                        f" ({dst['layer']} layer). Lower layers must not depend on higher ones."
                    ),
                    involved_modules=[source, target],
                    involved_edges=[(source, target)],
                    metric_value=float(src_rank - dst_rank),
                    location_module=source,
                    location_line=line,
                    details={
                        "kind": "inversion",
                        "from_layer": src["layer"],
                        "to_layer": dst["layer"],
                    },
                )
            )
        elif dst_rank - src_rank >= 2:
            skipped = [
                layer
                for layer in stack[src_rank + 1 : dst_rank]
                if (src["stack"], layer) in present
            ]
            if not skipped:
                continue  # the repository has no such layer to go through
            issues.append(
                ArchitectureIssueData(
                    issue_type=ArchitectureIssueType.LAYER_VIOLATION,
                    severity=Severity.WARNING,
                    title=f"Layer skip: {src['layer']} imports {dst['layer']}",
                    description=(
                        f"{src['path']} ({src['layer']} layer) imports {dst['path']}"
                        f" ({dst['layer']} layer) directly, bypassing the"
                        f" {' and '.join(skipped)} layer."
                    ),
                    involved_modules=[source, target],
                    involved_edges=[(source, target)],
                    metric_value=float(dst_rank - src_rank),
                    location_module=source,
                    location_line=line,
                    details={
                        "kind": "skip",
                        "from_layer": src["layer"],
                        "to_layer": dst["layer"],
                        "skipped_layers": skipped,
                    },
                )
            )
    return issues


def _god_module_issues(
    arch: ArchitectureGraph, metrics: dict[str, NodeMetrics]
) -> list[ArchitectureIssueData]:
    graph = arch.graph
    candidates = [n for n, data in graph.nodes(data=True) if not data["is_test"]]
    if len(candidates) < GOD_MIN_NODES:
        return []
    loc_threshold = max(GOD_MIN_LOC, _percentile([graph.nodes[n]["loc"] for n in candidates], 90))
    fan_in_threshold = max(GOD_MIN_FAN_IN, _percentile([metrics[n].fan_in for n in candidates], 90))
    centrality_threshold = max(
        GOD_MIN_CENTRALITY, _percentile([metrics[n].centrality for n in candidates], 90)
    )
    issues: list[ArchitectureIssueData] = []
    for node in sorted(candidates, key=lambda n: -metrics[n].centrality):
        data, m = graph.nodes[node], metrics[node]
        if (
            data["loc"] < loc_threshold
            or m.fan_in < fan_in_threshold
            or m.centrality < centrality_threshold
        ):
            continue
        issues.append(
            ArchitectureIssueData(
                issue_type=ArchitectureIssueType.GOD_MODULE,
                severity=Severity.WARNING,
                title="God module",
                description=(
                    f"{data['path']} is large ({data['loc']} lines, {data['definition_count']}"
                    f" definitions), imported by {m.fan_in} modules and sits on many dependency"
                    f" paths (betweenness {m.centrality:.3f}). Changes to it ripple widely;"
                    " consider splitting it by responsibility."
                ),
                involved_modules=[node, *sorted(graph.predecessors(node))],
                involved_edges=[(p, node) for p in sorted(graph.predecessors(node))],
                metric_value=m.centrality,
                location_module=node,
                details={
                    "loc": data["loc"],
                    "fan_in": m.fan_in,
                    "centrality": m.centrality,
                    "thresholds": {
                        "loc": loc_threshold,
                        "fan_in": fan_in_threshold,
                        "centrality": round(centrality_threshold, 6),
                    },
                },
            )
        )
    return issues


def _orphan_issues(
    arch: ArchitectureGraph, metrics: dict[str, NodeMetrics]
) -> list[ArchitectureIssueData]:
    graph = arch.graph
    issues: list[ArchitectureIssueData] = []
    for node, data in sorted(graph.nodes(data=True)):
        if metrics[node].fan_in or data["is_entrypoint"] or data["parse_error"]:
            continue
        issues.append(
            ArchitectureIssueData(
                issue_type=ArchitectureIssueType.ORPHAN_MODULE,
                severity=Severity.INFO,
                title="Orphan module",
                description=(
                    f"No module imports {data['path']} and it doesn't look like an entrypoint."
                    " It may be dead code, or loaded dynamically (by string, plugin or framework"
                    " convention)."
                ),
                involved_modules=[node],
                metric_value=0.0,
                location_module=node,
            )
        )
    return issues


def _max_depth(runtime: "nx.DiGraph[str]") -> int:
    """Longest import chain, counted in edges, with each cycle collapsed to one node."""
    if runtime.number_of_nodes() == 0:
        return 0
    condensed = nx.condensation(runtime)
    return int(nx.dag_longest_path_length(condensed))


def _cap(issues: list[ArchitectureIssueData]) -> tuple[list[ArchitectureIssueData], int]:
    ranked = sorted(issues, key=lambda i: -list(Severity).index(i.severity))
    return ranked[:MAX_ISSUES_PER_TYPE], max(0, len(issues) - MAX_ISSUES_PER_TYPE)


def compute_metrics(arch: ArchitectureGraph) -> ArchitectureMetrics:
    graph = arch.graph
    runtime = arch.runtime_graph()
    metrics = node_metrics(graph)
    cycles, cycles_truncated = find_cycles(runtime)

    omitted: dict[str, int] = {}
    issues: list[ArchitectureIssueData] = []
    for issue_type, found in (
        (ArchitectureIssueType.CIRCULAR_DEPENDENCY, _cycle_issues(arch, cycles)),
        (ArchitectureIssueType.LAYER_VIOLATION, _layer_issues(arch, runtime)),
        (ArchitectureIssueType.GOD_MODULE, _god_module_issues(arch, metrics)),
        (ArchitectureIssueType.ORPHAN_MODULE, _orphan_issues(arch, metrics)),
    ):
        kept, dropped = _cap(found)
        issues.extend(kept)
        if dropped:
            omitted[issue_type.value] = dropped

    n, e = graph.number_of_nodes(), graph.number_of_edges()
    counts = Counter(issue.issue_type.value for issue in issues)
    layer_counts = Counter(data["layer"] or "none" for _, data in graph.nodes(data=True))
    summary: dict[str, Any] = {
        "node_count": n,
        "edge_count": e,
        "type_only_edge_count": sum(1 for edge in arch.edges.values() if edge.type_only),
        "density": round(nx.density(graph), 6) if n > 1 else 0.0,
        "average_degree": round(2 * e / n, 3) if n else 0.0,  # in + out
        "max_depth": _max_depth(runtime),
        "cycle_count": len(cycles),
        "cycles_truncated": cycles_truncated,
        "cyclic_module_count": len(
            set(
                itertools.chain.from_iterable(
                    c for c in nx.strongly_connected_components(runtime) if len(c) > 1
                )
            )
        ),
        "layer_violation_count": counts[ArchitectureIssueType.LAYER_VIOLATION.value],
        "god_module_count": counts[ArchitectureIssueType.GOD_MODULE.value],
        "orphan_count": counts[ArchitectureIssueType.ORPHAN_MODULE.value],
        "issues_omitted": omitted,
        "layers": dict(layer_counts),
        "languages": dict(Counter(data["language"] for _, data in graph.nodes(data=True))),
        "total_loc": sum(data["loc"] for _, data in graph.nodes(data=True)),
    }
    return ArchitectureMetrics(nodes=metrics, issues=issues, summary=summary)

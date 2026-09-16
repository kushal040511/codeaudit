import networkx as nx

from app.models import ArchitectureIssueType, Severity
from app.services.graph import metrics as metrics_module
from app.services.graph.builder import ArchitectureGraph, EdgeData, ImportRef
from app.services.graph.metrics import compute_metrics, find_cycles, node_metrics


def make_graph(
    nodes: dict[str, dict[str, object]],
    edges: list[tuple[str, str]],
    **edge_flags: set[tuple[str, str]],
) -> ArchitectureGraph:
    graph: nx.DiGraph[str] = nx.DiGraph()
    for node, attrs in nodes.items():
        defaults: dict[str, object] = {
            "path": f"{node}.py",
            "language": "python",
            "loc": 10,
            "definition_count": 1,
            "symbols": [],
            "layer": None,
            "stack": None,
            "layer_root": None,
            "is_test": False,
            "is_entrypoint": False,
            "parse_error": None,
        }
        graph.add_node(node, **(defaults | attrs))
    data = {
        (s, t): EdgeData(
            s,
            t,
            [
                ImportRef(
                    line=3,
                    statement=f"import {t}",
                    type_only=(s, t) in edge_flags.get("type_only", set()),
                    lazy=(s, t) in edge_flags.get("lazy", set()),
                )
            ],
        )
        for s, t in edges
    }
    graph.add_edges_from(edges)
    return ArchitectureGraph(graph=graph, edges=data, external=[], unresolved=[], module_ids={})


def test_coupling_metrics() -> None:
    arch = make_graph(
        {"a": {}, "b": {}, "c": {}, "lonely": {}}, [("a", "b"), ("b", "c"), ("a", "c"), ("c", "b")]
    )

    metrics = node_metrics(arch.graph)

    assert (metrics["a"].fan_in, metrics["a"].fan_out, metrics["a"].instability) == (0, 2, 1.0)
    assert (metrics["b"].fan_in, metrics["b"].fan_out, metrics["b"].instability) == (2, 1, 0.3333)
    assert metrics["lonely"].instability is None
    # b is on the only shortest path c -> b; nothing passes through a
    assert metrics["b"].centrality == 0 and metrics["a"].centrality == 0
    chain = node_metrics(make_graph({"x": {}, "y": {}, "z": {}}, [("x", "y"), ("y", "z")]).graph)
    assert chain["y"].centrality == 0.5 and chain["x"].centrality == 0


def test_cycles_are_canonical_and_lazy_ones_are_warnings() -> None:
    arch = make_graph(
        {n: {} for n in "abcdxy"},
        [("c", "a"), ("a", "b"), ("b", "c"), ("x", "y"), ("y", "x"), ("d", "a")],
        lazy={("y", "x")},
    )

    result = compute_metrics(arch)

    cycles = [
        (i.involved_modules, i.severity)
        for i in result.issues
        if i.issue_type is ArchitectureIssueType.CIRCULAR_DEPENDENCY
    ]
    # most severe first; each cycle starts at its smallest module id
    assert cycles == [(["a", "b", "c"], Severity.ERROR), (["x", "y"], Severity.WARNING)]


def test_cycle_enumeration_is_capped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(metrics_module, "MAX_CYCLES", 5)
    complete = nx.complete_graph(6, create_using=nx.DiGraph)  # thousands of cycles

    cycles, truncated = find_cycles(complete)

    assert truncated
    assert len(cycles) == 5
    assert all(len(c) == 2 for c in cycles)  # the shortest are kept


def test_layer_skip_requires_the_skipped_layer_to_exist() -> None:
    backend = {"stack": "backend"}
    without_service = make_graph(
        {"routes": {"layer": "presentation", **backend}, "models": {"layer": "data", **backend}},
        [("routes", "models")],
    )
    with_service = make_graph(
        {
            "routes": {"layer": "presentation", **backend},
            "services": {"layer": "service", **backend},
            "models": {"layer": "data", **backend},
            "tests": {"layer": "presentation", **backend, "is_test": True},
        },
        [("routes", "models"), ("services", "models"), ("tests", "models"), ("models", "services")],
    )

    assert compute_metrics(without_service).issues == [] or all(
        i.issue_type is not ArchitectureIssueType.LAYER_VIOLATION
        for i in compute_metrics(without_service).issues
    )
    violations = [
        (i.involved_edges, i.severity, i.details["kind"])
        for i in compute_metrics(with_service).issues
        if i.issue_type is ArchitectureIssueType.LAYER_VIOLATION
    ]
    assert violations == [
        ([("models", "services")], Severity.ERROR, "inversion"),
        ([("routes", "models")], Severity.WARNING, "skip"),
    ]


def test_colocated_modules_are_not_layer_violations() -> None:
    frontend = {"stack": "frontend"}
    arch = make_graph(
        {
            "dialog_hook": {
                "layer": "hooks",
                "path": "src/components/Dialog/useDialog.ts",
                "layer_root": "src/components/Dialog/useDialog.ts",
                **frontend,
            },
            "dialog_context": {
                "layer": "ui",
                "path": "src/components/Dialog/DialogContext.tsx",
                "layer_root": "src/components",
                **frontend,
            },
            "shared_hook": {
                "layer": "hooks",
                "path": "src/hooks/useTheme.ts",
                "layer_root": "src/hooks",
                **frontend,
            },
        },
        [("dialog_hook", "dialog_context"), ("shared_hook", "dialog_context")],
    )

    violations = [
        i.involved_edges
        for i in compute_metrics(arch).issues
        if i.issue_type is ArchitectureIssueType.LAYER_VIOLATION
    ]
    assert violations == [[("shared_hook", "dialog_context")]]


def test_type_only_imports_are_not_cycles_or_violations() -> None:
    backend = {"stack": "backend"}
    arch = make_graph(
        {"models": {"layer": "data", **backend}, "routes": {"layer": "presentation", **backend}},
        [("routes", "models"), ("models", "routes")],
        type_only={("models", "routes")},
    )

    result = compute_metrics(arch)

    assert result.issues == []
    assert result.summary["type_only_edge_count"] == 1


def test_god_module_needs_size_fan_in_and_centrality() -> None:
    nodes: dict[str, dict[str, object]] = {f"caller{i}": {} for i in range(8)}
    nodes |= {f"leaf{i}": {} for i in range(4)}
    nodes["core"] = {"loc": 1200, "definition_count": 80}
    nodes["big_leaf"] = {"loc": 5000}  # large but nothing depends on it through others
    edges = [(f"caller{i}", "core") for i in range(8)] + [("core", f"leaf{i}") for i in range(4)]
    edges += [("caller0", "big_leaf")]

    result = compute_metrics(make_graph(nodes, edges))

    gods = [i for i in result.issues if i.issue_type is ArchitectureIssueType.GOD_MODULE]
    assert [g.involved_modules[0] for g in gods] == ["core"]
    assert gods[0].details["fan_in"] == 8 and gods[0].details["loc"] == 1200
    assert len(gods[0].involved_edges) == 8


def test_orphans_exclude_entrypoints_and_unparsable_files() -> None:
    arch = make_graph(
        {
            "main": {"is_entrypoint": True},
            "used": {},
            "dead": {},
            "broken": {"parse_error": "parse error near line 1"},
        },
        [("main", "used")],
    )

    result = compute_metrics(arch)

    assert [
        i.involved_modules
        for i in result.issues
        if i.issue_type is ArchitectureIssueType.ORPHAN_MODULE
    ] == [["dead"]]


def test_summary() -> None:
    arch = make_graph({n: {} for n in "abcd"}, [("a", "b"), ("b", "c"), ("c", "b"), ("c", "d")])

    summary = compute_metrics(arch).summary

    assert summary["node_count"] == 4 and summary["edge_count"] == 4
    assert summary["average_degree"] == 2.0
    assert summary["density"] == round(4 / 12, 6)
    assert summary["max_depth"] == 2  # a -> {b,c} -> d with the cycle collapsed
    assert summary["cycle_count"] == 1 and summary["cyclic_module_count"] == 2

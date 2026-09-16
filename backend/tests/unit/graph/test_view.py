from dataclasses import dataclass, field

from app.models import ArchitectureIssueType, Severity
from app.services.graph.view import build_view, choose_depth, group_key


@dataclass
class Node:
    module_id: str
    path: str
    language: str = "python"
    loc: int = 10
    definition_count: int = 1
    fan_in: int = 0
    fan_out: int = 0
    instability: float | None = None
    centrality: float = 0.0
    inferred_layer: str | None = None
    is_entrypoint: bool = False
    is_test: bool = False
    parse_error: str | None = None


@dataclass
class Edge:
    source_module: str
    target_module: str
    import_count: int = 1
    type_only: bool = False
    lazy: bool = False


@dataclass
class Issue:
    id: int
    issue_type: ArchitectureIssueType
    involved_modules: list[str]
    involved_edges: list[list[str]] = field(default_factory=list)
    severity: Severity = Severity.ERROR
    title: str = "issue"


PATHS = [
    "app/main.py",
    "app/api/routes/users.py",
    "app/api/routes/orders.py",
    "app/api/deps.py",
    "app/services/users.py",
    "app/models/user.py",
    "app/models/order.py",
    "setup.py",
]
NODES = [Node(p.removesuffix(".py"), p) for p in PATHS]
NODES[4].inferred_layer = "service"
NODES[5].inferred_layer = NODES[6].inferred_layer = "data"
EDGES = [
    Edge("app/api/routes/users", "app/services/users", import_count=2),
    Edge("app/api/routes/orders", "app/models/order"),
    Edge("app/services/users", "app/models/user"),
    Edge("app/models/user", "app/services/users", type_only=True),
    Edge("app/api/routes/users", "app/api/deps"),
]
ISSUES = [
    Issue(
        1,
        ArchitectureIssueType.LAYER_VIOLATION,
        ["app/api/routes/orders", "app/models/order"],
        [["app/api/routes/orders", "app/models/order"]],
    ),
    Issue(
        2,
        ArchitectureIssueType.CIRCULAR_DEPENDENCY,
        ["app/models/user", "app/services/users"],
        [["app/models/user", "app/services/users"], ["app/services/users", "app/models/user"]],
    ),
]


def test_small_graph_is_module_level() -> None:
    view = build_view(NODES, EDGES, ISSUES, max_nodes=100)

    assert not view.aggregated and view.depth is None
    assert len(view.nodes) == 8 and len(view.edges) == 5
    violation = next(e for e in view.edges if e.layer_violation)
    assert violation.id == "app/api/routes/orders->app/models/order"
    assert {e.id for e in view.edges if e.in_cycle} == {
        "app/models/user->app/services/users",
        "app/services/users->app/models/user",
    }
    orders = next(n for n in view.nodes if n.id == "app/api/routes/orders")
    assert orders.issue_ids == [1]


def test_aggregates_by_deepest_directory_level_that_fits() -> None:
    assert choose_depth(PATHS, 8) is None
    assert (
        choose_depth(PATHS, 6) == 3
    )  # app/api/routes, app/api, app/services, app/models, app, setup
    assert choose_depth(PATHS, 3) == 1

    view = build_view(NODES, EDGES, ISSUES, max_nodes=5)

    # depth 2 gives 5 nodes; opening any directory would exceed the budget
    assert view.aggregated and view.depth == 2
    assert sorted(n.id for n in view.nodes) == [
        "dir:app",
        "dir:app/api",
        "dir:app/models",
        "dir:app/services",
        "setup",
    ]
    api = next(n for n in view.nodes if n.id == "dir:app/api")
    assert (api.kind, api.label, api.module_count, api.loc) == ("directory", "api/", 3, 30)
    models = next(n for n in view.nodes if n.id == "dir:app/models")
    assert models.layer == "data"
    edges = {e.id: e for e in view.edges}
    assert set(edges) == {
        "dir:app/api->dir:app/services",
        "dir:app/api->dir:app/models",
        "dir:app/services->dir:app/models",
        "dir:app/models->dir:app/services",
    }
    assert edges["dir:app/api->dir:app/models"].layer_violation
    assert edges["dir:app/models->dir:app/services"].type_only
    assert edges["dir:app/api->dir:app/services"].import_count == 2
    # routes/users -> deps is inside dir:app/api: not an edge of this view
    cycle = next(i for i in view.issues if i.id == 2)
    assert cycle.node_ids == ["dir:app/models", "dir:app/services"]
    assert sorted(cycle.edge_ids) == [
        "dir:app/models->dir:app/services",
        "dir:app/services->dir:app/models",
    ]


def test_expand_and_collapse() -> None:
    assert group_key("app/api/routes/users.py", "m", 2, {"app/api"}, set()) == "dir:app/api/routes"
    assert group_key("app/api/deps.py", "app/api/deps", 2, {"app/api"}, set()) == "app/api/deps"
    assert group_key("app/api/routes/users.py", "m", 2, {"app/api", "app/api/routes"}, set()) == "m"
    assert group_key("app/api/routes/users.py", "m", None, set(), {"app/api"}) == "dir:app/api"

    expanded = build_view(NODES, EDGES, ISSUES, max_nodes=5, expand=["app/api/"])
    assert "dir:app/api/routes" in {n.id for n in expanded.nodes}
    assert "app/api/deps" in {n.id for n in expanded.nodes}
    assert expanded.expanded == ["app/api"]

    collapsed = build_view(NODES, EDGES, ISSUES, max_nodes=100, collapse=["app/models"])
    ids = {n.id for n in collapsed.nodes}
    assert "dir:app/models" in ids and "app/models/user" not in ids
    assert collapsed.aggregated and collapsed.depth is None


def test_auto_expands_largest_directories_within_budget() -> None:
    paths = [f"big/pkg/mod{i}.py" for i in range(10)] + ["small/a.py", "small/b.py"]
    nodes = [Node(p.removesuffix(".py"), p) for p in paths]
    assert choose_depth(paths, 5) == 2  # dir:big/pkg + dir:small

    # big/pkg would need 11 nodes; small/ fits.
    coarse = build_view(nodes, [], [], max_nodes=5)
    assert sorted(n.id for n in coarse.nodes) == ["dir:big/pkg", "small/a", "small/b"]

    # The largest directory is opened first; then small/ no longer fits.
    roomy = build_view(nodes, [], [], max_nodes=11)
    assert sorted(n.id for n in roomy.nodes) == sorted(
        [f"big/pkg/mod{i}" for i in range(10)] + ["dir:small"]
    )
    assert roomy.expanded == []  # auto-expansion is not reported as user state

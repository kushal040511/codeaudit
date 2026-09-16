"""Shape the stored module graph for display, aggregating by directory when it's too big.

A 2000-module graph is unreadable and heavy in the browser, so when a scan has
more modules than `max_nodes` the modules are grouped by directory at the deepest
level that fits. The client can then expand a directory (one level deeper, down
to individual modules) or collapse one (its whole subtree becomes one node).
"""

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from app.models import ArchitectureIssueType, Severity

DIRECTORY_PREFIX = "dir:"
CYCLE_TYPES = frozenset({ArchitectureIssueType.CIRCULAR_DEPENDENCY})
VIOLATION_TYPES = frozenset({ArchitectureIssueType.LAYER_VIOLATION})


class NodeRow(Protocol):
    module_id: str
    path: str
    language: str
    loc: int
    definition_count: int
    fan_in: int
    fan_out: int
    instability: float | None
    centrality: float
    inferred_layer: str | None
    is_entrypoint: bool
    is_test: bool
    parse_error: str | None


class EdgeRow(Protocol):
    source_module: str
    target_module: str
    import_count: int
    type_only: bool
    lazy: bool


class IssueRow(Protocol):
    id: int
    issue_type: ArchitectureIssueType
    severity: Severity
    title: str
    involved_modules: list[str]
    involved_edges: list[list[str]]


@dataclass
class ViewNode:
    id: str
    kind: str  # module | directory
    label: str
    path: str
    module_count: int
    loc: int
    definition_count: int
    fan_in: int
    fan_out: int
    instability: float | None
    centrality: float
    layer: str | None
    language: str | None
    is_entrypoint: bool
    is_test: bool
    parse_error_count: int
    # Issues whose primary module (involved_modules[0]) is in this node.
    issue_ids: list[int] = field(default_factory=list)


@dataclass
class ViewEdge:
    id: str
    source: str
    target: str
    module_edge_count: int
    import_count: int
    type_only: bool
    lazy: bool
    in_cycle: bool
    layer_violation: bool
    issue_ids: list[int] = field(default_factory=list)


@dataclass
class ViewIssue:
    id: int
    issue_type: ArchitectureIssueType
    severity: Severity
    title: str
    node_ids: list[str]
    edge_ids: list[str]


@dataclass
class GraphView:
    nodes: list[ViewNode]
    edges: list[ViewEdge]
    issues: list[ViewIssue]
    total_modules: int
    aggregated: bool
    depth: int | None  # directory depth used, None for module level
    expanded: list[str]
    collapsed: list[str]


def _dirs(path: str) -> tuple[str, ...]:
    parent = PurePosixPath(path).parent
    return () if str(parent) == "." else parent.parts


def directory_id(prefix: Sequence[str]) -> str:
    return DIRECTORY_PREFIX + "/".join(prefix)


def group_key(
    path: str, module_id: str, depth: int | None, expand: set[str], collapse: set[str]
) -> str:
    dirs = _dirs(path)
    for k in range(1, len(dirs) + 1):
        if "/".join(dirs[:k]) in collapse:
            return directory_id(dirs[:k])  # the shallowest collapsed ancestor wins
    if depth is None or not dirs:
        return module_id
    k = min(depth, len(dirs))
    while "/".join(dirs[:k]) in expand:
        if k == len(dirs):
            return module_id  # an expanded directory shows its own files individually
        k += 1
    return directory_id(dirs[:k])


def choose_depth(paths: Iterable[str], max_nodes: int) -> int | None:
    """None if every module fits, else the deepest directory level with <= max_nodes groups."""
    items = list(paths)
    if len(items) <= max_nodes:
        return None
    max_depth = max((len(_dirs(p)) for p in items), default=1)
    for depth in range(max_depth, 0, -1):
        keys = {group_key(p, p, depth, set(), set()) for p in items}
        if len(keys) <= max_nodes:
            return depth
    return 1


def auto_expand(
    nodes: Sequence[NodeRow],
    depth: int,
    max_nodes: int,
    expand: set[str],
    collapse: set[str],
) -> set[str]:
    """Spend the remaining node budget: expand the largest directories while the view fits.

    Directory depth alone is coarse (pydantic: 40 groups at every depth >= 5, but
    577 modules), so the biggest groups are opened one level at a time.
    """
    expanded: set[str] = set()
    while True:
        current = expand | expanded
        members: defaultdict[str, list[NodeRow]] = defaultdict(list)
        for node in nodes:
            members[group_key(node.path, node.module_id, depth, current, collapse)].append(node)
        total = len(members)
        chosen: str | None = None
        for key, group in sorted(members.items(), key=lambda item: (-len(item[1]), item[0])):
            if not key.startswith(DIRECTORY_PREFIX) or len(group) < 2:
                continue
            directory = key.removeprefix(DIRECTORY_PREFIX)
            trial = current | {directory}
            children = {group_key(n.path, n.module_id, depth, trial, collapse) for n in group}
            if len(children) > 1 and total - 1 + len(children) <= max_nodes:
                chosen = directory
                break
        if chosen is None:
            return expanded
        expanded.add(chosen)


def build_view(
    nodes: Sequence[NodeRow],
    edges: Sequence[EdgeRow],
    issues: Sequence[IssueRow],
    *,
    max_nodes: int,
    expand: Iterable[str] = (),
    collapse: Iterable[str] = (),
) -> GraphView:
    expand_set = {e.strip("/") for e in expand if e.strip("/")}
    collapse_set = {c.strip("/") for c in collapse if c.strip("/")}
    depth = choose_depth((n.path for n in nodes), max_nodes)
    effective_expand = expand_set
    if depth is not None:
        effective_expand = expand_set | auto_expand(
            nodes, depth, max_nodes, expand_set, collapse_set
        )
    key_of = {
        n.module_id: group_key(n.path, n.module_id, depth, effective_expand, collapse_set)
        for n in nodes
    }

    members: defaultdict[str, list[NodeRow]] = defaultdict(list)
    for node in nodes:
        members[key_of[node.module_id]].append(node)

    # Module-level issue edges, mapped to view edges below.
    cycle_edges: set[tuple[str, str]] = set()
    violation_edges: set[tuple[str, str]] = set()
    edge_issues: defaultdict[tuple[str, str], list[int]] = defaultdict(list)
    for issue in issues:
        for source, target in issue.involved_edges:
            edge_issues[(source, target)].append(issue.id)
            if issue.issue_type in CYCLE_TYPES:
                cycle_edges.add((source, target))
            elif issue.issue_type in VIOLATION_TYPES:
                violation_edges.add((source, target))

    grouped: dict[tuple[str, str], ViewEdge] = {}
    for edge in edges:
        if edge.source_module not in key_of or edge.target_module not in key_of:
            continue
        source, target = key_of[edge.source_module], key_of[edge.target_module]
        if source == target:
            continue
        pair = (edge.source_module, edge.target_module)
        view_edge = grouped.get((source, target))
        if view_edge is None:
            view_edge = grouped[(source, target)] = ViewEdge(
                id=f"{source}->{target}",
                source=source,
                target=target,
                module_edge_count=0,
                import_count=0,
                type_only=True,
                lazy=True,
                in_cycle=False,
                layer_violation=False,
            )
        view_edge.module_edge_count += 1
        view_edge.import_count += edge.import_count
        view_edge.type_only &= edge.type_only
        view_edge.lazy &= edge.lazy
        view_edge.in_cycle |= pair in cycle_edges
        view_edge.layer_violation |= pair in violation_edges
        view_edge.issue_ids.extend(
            i for i in edge_issues.get(pair, []) if i not in view_edge.issue_ids
        )

    fan_in: Counter[str] = Counter(target for _, target in grouped)
    fan_out: Counter[str] = Counter(source for source, _ in grouped)

    primary_issues: defaultdict[str, list[int]] = defaultdict(list)
    view_issues: list[ViewIssue] = []
    for issue in issues:
        involved = [key_of[m] for m in issue.involved_modules if m in key_of]
        if involved:
            primary_issues[involved[0]].append(issue.id)
        view_issues.append(
            ViewIssue(
                id=issue.id,
                issue_type=issue.issue_type,
                severity=issue.severity,
                title=issue.title,
                node_ids=list(dict.fromkeys(involved)),
                edge_ids=list(
                    dict.fromkeys(
                        grouped[(key_of[s], key_of[t])].id
                        for s, t in issue.involved_edges
                        if s in key_of and t in key_of and (key_of[s], key_of[t]) in grouped
                    )
                ),
            )
        )

    view_nodes: list[ViewNode] = []
    for key, group in sorted(members.items()):
        if key.startswith(DIRECTORY_PREFIX):
            directory = key.removeprefix(DIRECTORY_PREFIX)
            loc_by_layer: Counter[str] = Counter()
            for member in group:
                if member.inferred_layer:
                    loc_by_layer[member.inferred_layer] += max(member.loc, 1)
            total_in, total_out = fan_in[key], fan_out[key]
            view_nodes.append(
                ViewNode(
                    id=key,
                    kind="directory",
                    label=f"{PurePosixPath(directory).name}/",
                    path=directory,
                    module_count=len(group),
                    loc=sum(m.loc for m in group),
                    definition_count=sum(m.definition_count for m in group),
                    fan_in=total_in,
                    fan_out=total_out,
                    instability=(
                        round(total_out / (total_in + total_out), 4)
                        if total_in + total_out
                        else None
                    ),
                    centrality=max(m.centrality for m in group),
                    layer=loc_by_layer.most_common(1)[0][0] if loc_by_layer else None,
                    language=Counter(m.language for m in group).most_common(1)[0][0],
                    is_entrypoint=all(m.is_entrypoint for m in group),
                    is_test=all(m.is_test for m in group),
                    parse_error_count=sum(1 for m in group if m.parse_error),
                    issue_ids=primary_issues.get(key, []),
                )
            )
        else:
            [module] = group
            view_nodes.append(
                ViewNode(
                    id=key,
                    kind="module",
                    label=PurePosixPath(module.path).name,
                    path=module.path,
                    module_count=1,
                    loc=module.loc,
                    definition_count=module.definition_count,
                    fan_in=module.fan_in,
                    fan_out=module.fan_out,
                    instability=module.instability,
                    centrality=module.centrality,
                    layer=module.inferred_layer,
                    language=module.language,
                    is_entrypoint=module.is_entrypoint,
                    is_test=module.is_test,
                    parse_error_count=int(bool(module.parse_error)),
                    issue_ids=primary_issues.get(key, []),
                )
            )

    return GraphView(
        nodes=view_nodes,
        edges=sorted(grouped.values(), key=lambda e: e.id),
        issues=view_issues,
        total_modules=len(nodes),
        aggregated=any(n.kind == "directory" for n in view_nodes),
        depth=depth,
        expanded=sorted(expand_set),
        collapsed=sorted(collapse_set),
    )

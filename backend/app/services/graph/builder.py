"""Build the module dependency graph from parsed modules and resolved imports.

Nodes are internal modules (every discovered source file, including ones that
failed to parse). Edges are internal imports, one per (importer, imported) pair
with all statements aggregated. External packages are not nodes: they are
aggregated per package, per importing module.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import networkx as nx

from app.services.graph.layers import LayerInfo, infer_layer, is_entrypoint, is_frontend_path
from app.services.graph.parser import ParsedModule
from app.services.graph.resolver import ImportStatus, RepoIndex, ResolvedImport

_STRIP_SUFFIXES = (".py", ".d.ts", ".tsx", ".ts", ".mts", ".cts", ".jsx", ".js", ".mjs", ".cjs")


@dataclass
class ImportRef:
    line: int
    statement: str
    type_only: bool
    lazy: bool


@dataclass
class EdgeData:
    source: str  # module id
    target: str
    imports: list[ImportRef] = field(default_factory=list)

    @property
    def type_only(self) -> bool:
        """Every import of the pair is erased at runtime (`import type`, TYPE_CHECKING)."""
        return all(i.type_only for i in self.imports)

    @property
    def lazy(self) -> bool:
        """Every runtime import of the pair happens inside a function."""
        runtime = [i for i in self.imports if not i.type_only]
        return bool(runtime) and all(i.lazy for i in runtime)

    @property
    def first(self) -> ImportRef:
        return min(self.imports, key=lambda i: i.line)


@dataclass
class ExternalImport:
    source: str  # module id
    package: str
    language: str
    evidence: str  # stdlib | node-builtin | declared | undeclared | url
    imports: list[ImportRef] = field(default_factory=list)


@dataclass
class ArchitectureGraph:
    graph: "nx.DiGraph[str]"  # all internal edges; node attrs: see build_graph
    edges: dict[tuple[str, str], EdgeData]
    external: list[ExternalImport]
    unresolved: list[ResolvedImport]
    module_ids: dict[str, str]  # path -> module id

    def runtime_graph(self) -> "nx.DiGraph[str]":
        """The graph without type-only edges: what actually loads at runtime."""
        runtime = nx.DiGraph()
        runtime.add_nodes_from(self.graph.nodes(data=True))
        runtime.add_edges_from(key for key, edge in self.edges.items() if not edge.type_only)
        return runtime


def module_ids_for(paths: list[str]) -> dict[str, str]:
    """Path-based module ids: extension dropped, `pkg/__init__.py` -> `pkg`.

    If two files would get the same id (`utils.ts` and `utils.js`, or `pkg.py` next
    to `pkg/__init__.py`) they keep their full paths instead.
    """
    candidates: dict[str, str] = {}
    for path in paths:
        module_id = path
        for suffix in _STRIP_SUFFIXES:
            if path.endswith(suffix):
                module_id = path[: -len(suffix)]
                break
        if module_id.endswith("/__init__") or module_id == "__init__":
            module_id = module_id.removesuffix("__init__").rstrip("/") or "__init__"
        candidates[path] = module_id
    counts: defaultdict[str, int] = defaultdict(int)
    for module_id in candidates.values():
        counts[module_id] += 1
    return {path: (mid if counts[mid] == 1 else path) for path, mid in candidates.items()}


def _project_key(path: str, package_roots: list[str]) -> str:
    """Nearest directory with a package.json (JS/TS project), else the top-level directory."""
    for root in package_roots:
        if not root or path.startswith(f"{root}/"):
            return root
    return path.split("/", 1)[0] if "/" in path else ""


def build_graph(
    index: RepoIndex, modules: list[ParsedModule], resolved: list[ResolvedImport]
) -> ArchitectureGraph:
    module_ids = module_ids_for([m.path for m in modules])

    package_roots = sorted(
        {
            f.rsplit("/", 1)[0] if "/" in f else ""
            for f in index.files
            if PurePosixPath(f).name == "package.json"
        },
        key=lambda r: -len(r),  # deepest first
    )
    frontend_projects = {
        _project_key(m.path, package_roots)
        for m in modules
        if m.language != "python" and is_frontend_path(m.path)
    }

    graph: nx.DiGraph[str] = nx.DiGraph()
    for module in modules:
        info: LayerInfo = infer_layer(
            module.path,
            module.language,
            _project_key(module.path, package_roots) in frontend_projects,
        )
        graph.add_node(
            module_ids[module.path],
            path=module.path,
            language=module.language,
            loc=module.loc,
            definition_count=module.definition_count,
            symbols=module.symbols[:200],
            layer=info.layer,
            stack=info.stack,
            layer_root=info.layer_root,
            is_test=info.is_test,
            is_entrypoint=is_entrypoint(module.path, module.language, info.is_test),
            parse_error=module.error,
        )

    languages = {m.path: m.language for m in modules}
    edges: dict[tuple[str, str], EdgeData] = {}
    external: dict[tuple[str, str], ExternalImport] = {}
    unresolved: list[ResolvedImport] = []
    for item in resolved:
        ref = ImportRef(item.raw.line, item.raw.statement, item.raw.type_only, item.raw.lazy)
        source = module_ids[item.source]
        if item.status is ImportStatus.INTERNAL and item.target is not None:
            target = module_ids.get(item.target)
            if target is None or target == source:
                continue
            edge = edges.setdefault((source, target), EdgeData(source, target))
            if ref not in edge.imports:
                edge.imports.append(ref)
        elif item.status is ImportStatus.EXTERNAL and item.target:
            key = (source, item.target)
            entry = external.setdefault(
                key,
                ExternalImport(
                    source, item.target, languages[item.source], item.method or "undeclared"
                ),
            )
            entry.imports.append(ref)
        elif item.status is ImportStatus.UNRESOLVED:
            unresolved.append(item)

    graph.add_edges_from(edges)
    return ArchitectureGraph(
        graph=graph,
        edges=edges,
        external=list(external.values()),
        unresolved=unresolved,
        module_ids=module_ids,
    )

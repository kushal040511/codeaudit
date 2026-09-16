from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models import ArchitectureIssueType, EdgeKind, Severity


class GraphNodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str  # module id, or "dir:<path>" for an aggregated directory
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
    issue_ids: list[int]


class GraphEdgeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    target: str
    module_edge_count: int  # module-level edges represented (>1 between directories)
    import_count: int
    type_only: bool
    lazy: bool
    in_cycle: bool
    layer_violation: bool
    issue_ids: list[int]


class GraphIssueRef(BaseModel):
    """An issue mapped onto the nodes/edges of this particular view."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    issue_type: ArchitectureIssueType
    severity: Severity
    title: str
    node_ids: list[str]
    edge_ids: list[str]


class ExternalDependencyRead(BaseModel):
    name: str
    language: str
    importer_count: int  # internal modules importing it
    import_count: int
    evidence: str | None  # stdlib | node-builtin | declared | undeclared | url


class GraphViewInfo(BaseModel):
    total_modules: int
    aggregated: bool
    depth: int | None
    max_nodes: int
    expanded: list[str]
    collapsed: list[str]


class ArchitectureGraphRead(BaseModel):
    summary: dict[str, Any]
    view: GraphViewInfo
    nodes: list[GraphNodeRead]
    edges: list[GraphEdgeRead]
    issues: list[GraphIssueRef]
    external_dependencies: list[ExternalDependencyRead]


class ModuleImportRead(BaseModel):
    module: str  # module id, package name, or raw specifier for unresolved imports
    path: str | None  # internal modules only
    kind: EdgeKind
    import_statement: str
    line: int
    import_count: int
    type_only: bool
    lazy: bool
    resolution: str | None


class ArchitectureIssueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    issue_type: ArchitectureIssueType
    severity: Severity
    title: str
    description: str
    # involved_modules[0] is the primary module (cycle start, importer, god module, orphan).
    involved_modules: list[str]
    involved_edges: list[list[str]]
    metric_value: float | None
    details: dict[str, Any]


class ModuleDetailRead(BaseModel):
    module_id: str
    path: str
    language: str
    loc: int
    definition_count: int
    fan_in: int
    fan_out: int
    instability: float | None
    centrality: float
    layer: str | None
    layer_stack: str | None
    is_entrypoint: bool
    is_test: bool
    parse_error: str | None
    symbols: list[str]
    importers: list[ModuleImportRead]
    imports: list[ModuleImportRead]  # internal, external and unresolved
    issues: list[ArchitectureIssueRead]

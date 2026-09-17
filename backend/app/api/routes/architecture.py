import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import OptionalPrincipal, load_scan
from app.api.errors import NotFoundError
from app.api.pagination import PageParams, page_params, paginate
from app.core.db import get_db
from app.models import (
    ArchitectureIssue,
    ArchitectureIssueType,
    ArchitectureSummary,
    EdgeKind,
    GraphEdge,
    GraphNode,
    Severity,
)
from app.schemas.architecture import (
    ArchitectureGraphRead,
    ArchitectureIssueRead,
    ExternalDependencyRead,
    GraphEdgeRead,
    GraphIssueRef,
    GraphNodeRead,
    GraphViewInfo,
    ModuleDetailRead,
    ModuleImportRead,
)
from app.schemas.errors import ErrorResponse
from app.services.auth.sessions import Principal
from app.services.graph.view import build_view

router = APIRouter(prefix="/scans/{scan_id}", tags=["architecture"])

DbSession = Annotated[Session, Depends(get_db)]
MAX_EXTERNAL_DEPENDENCIES = 100
ERRORS: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
}


def _summary_or_404(
    db: Session, scan_id: uuid.UUID, principal: Principal | None
) -> ArchitectureSummary:
    load_scan(db, scan_id, principal)
    summary = db.get(ArchitectureSummary, scan_id)
    if summary is None:
        raise NotFoundError(
            f"Scan {scan_id} has no architecture graph (not finished, no Python/JS/TS code,"
            " or the architecture analyzer failed)."
        )
    return summary


@router.get("/graph", response_model=ArchitectureGraphRead, responses=ERRORS)
def get_graph(
    scan_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    max_nodes: Annotated[
        int,
        Query(ge=10, le=2000, description="Aggregate by directory above this many modules"),
    ] = 300,
    expand: Annotated[
        list[Annotated[str, Query(max_length=1024)]] | None,
        Query(max_length=200, description="Directories to show one level deeper"),
    ] = None,
    collapse: Annotated[
        list[Annotated[str, Query(max_length=1024)]] | None,
        Query(max_length=200, description="Directories to show as a single node"),
    ] = None,
) -> ArchitectureGraphRead:
    """The module dependency graph, its metrics and issues, sized for display."""
    summary = _summary_or_404(db, scan_id, principal)
    nodes = db.scalars(select(GraphNode).where(GraphNode.scan_id == scan_id)).all()
    edges = db.scalars(
        select(GraphEdge).where(GraphEdge.scan_id == scan_id, GraphEdge.kind == EdgeKind.INTERNAL)
    ).all()
    issues = db.scalars(
        select(ArchitectureIssue)
        .where(ArchitectureIssue.scan_id == scan_id)
        .order_by(ArchitectureIssue.id)
    ).all()
    view = build_view(
        nodes, edges, issues, max_nodes=max_nodes, expand=expand or (), collapse=collapse or ()
    )

    externals = db.execute(
        select(
            GraphEdge.target_module,
            GraphNode.language,
            func.count(func.distinct(GraphEdge.source_module)),
            func.sum(GraphEdge.import_count),
            func.min(GraphEdge.resolution),
        )
        .join(
            GraphNode,
            (GraphNode.scan_id == GraphEdge.scan_id)
            & (GraphNode.module_id == GraphEdge.source_module),
        )
        .where(GraphEdge.scan_id == scan_id, GraphEdge.kind == EdgeKind.EXTERNAL)
        .group_by(GraphEdge.target_module, GraphNode.language)
        .order_by(
            func.count(func.distinct(GraphEdge.source_module)).desc(), GraphEdge.target_module
        )
        .limit(MAX_EXTERNAL_DEPENDENCIES)
    ).all()

    return ArchitectureGraphRead(
        summary=summary.summary,
        view=GraphViewInfo(
            total_modules=view.total_modules,
            aggregated=view.aggregated,
            depth=view.depth,
            max_nodes=max_nodes,
            expanded=view.expanded,
            collapsed=view.collapsed,
        ),
        nodes=[GraphNodeRead.model_validate(n) for n in view.nodes],
        edges=[GraphEdgeRead.model_validate(e) for e in view.edges],
        issues=[GraphIssueRef.model_validate(i) for i in view.issues],
        external_dependencies=[
            ExternalDependencyRead(
                name=name,
                language=language,
                importer_count=importers,
                import_count=int(imports or 0),
                evidence=evidence,
            )
            for name, language, importers, imports, evidence in externals
        ],
    )


@router.get("/graph/module", response_model=ModuleDetailRead, responses=ERRORS)
def get_graph_module(
    scan_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    module_id: Annotated[str, Query(max_length=2048)],
) -> ModuleDetailRead:
    """One module: metrics, importers, imports (internal, external, unresolved) and issues."""
    _summary_or_404(db, scan_id, principal)
    node = db.scalar(
        select(GraphNode).where(GraphNode.scan_id == scan_id, GraphNode.module_id == module_id)
    )
    if node is None:
        raise NotFoundError(f"Module {module_id!r} not found in scan {scan_id}.")

    paths: dict[str, str] = {
        mid: path
        for mid, path in db.execute(
            select(GraphNode.module_id, GraphNode.path).where(GraphNode.scan_id == scan_id)
        ).all()
    }

    def to_read(edge: GraphEdge, other: str) -> ModuleImportRead:
        return ModuleImportRead(
            module=other,
            path=paths.get(other) if edge.kind is EdgeKind.INTERNAL else None,
            kind=edge.kind,
            import_statement=edge.import_statement,
            line=edge.line,
            import_count=edge.import_count,
            type_only=edge.type_only,
            lazy=edge.lazy,
            resolution=edge.resolution,
        )

    importers = db.scalars(
        select(GraphEdge)
        .where(
            GraphEdge.scan_id == scan_id,
            GraphEdge.kind == EdgeKind.INTERNAL,
            GraphEdge.target_module == module_id,
        )
        .order_by(GraphEdge.source_module)
    ).all()
    imports = db.scalars(
        select(GraphEdge)
        .where(GraphEdge.scan_id == scan_id, GraphEdge.source_module == module_id)
        .order_by(GraphEdge.kind, GraphEdge.line)
    ).all()
    issues = db.scalars(
        select(ArchitectureIssue)
        .where(
            ArchitectureIssue.scan_id == scan_id,
            ArchitectureIssue.involved_modules.contains([module_id]),
        )
        .order_by(ArchitectureIssue.id)
    ).all()

    return ModuleDetailRead(
        module_id=node.module_id,
        path=node.path,
        language=node.language,
        loc=node.loc,
        definition_count=node.definition_count,
        fan_in=node.fan_in,
        fan_out=node.fan_out,
        instability=node.instability,
        centrality=node.centrality,
        layer=node.inferred_layer,
        layer_stack=node.layer_stack,
        is_entrypoint=node.is_entrypoint,
        is_test=node.is_test,
        parse_error=node.parse_error,
        symbols=node.symbols,
        importers=[to_read(e, e.source_module) for e in importers],
        imports=[to_read(e, e.target_module) for e in imports],
        issues=[ArchitectureIssueRead.model_validate(i) for i in issues],
    )


@router.get("/architecture-issues", response_model=list[ArchitectureIssueRead], responses=ERRORS)
def list_architecture_issues(
    scan_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    issue_type: Annotated[list[ArchitectureIssueType] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    *,
    request: Request,
    response: Response,
    pages: Annotated[PageParams, Depends(page_params)],
) -> list[ArchitectureIssueRead]:
    """Structural issues, most severe first."""
    _summary_or_404(db, scan_id, principal)
    conditions = [ArchitectureIssue.scan_id == scan_id]
    if issue_type:
        conditions.append(ArchitectureIssue.issue_type.in_(issue_type))
    if severity:
        conditions.append(ArchitectureIssue.severity.in_(severity))
    rows = paginate(
        db,
        select(ArchitectureIssue)
        .where(*conditions)
        .order_by(
            ArchitectureIssue.severity.desc(), ArchitectureIssue.issue_type, ArchitectureIssue.id
        ),
        pages,
        request,
        response,
    )
    return [ArchitectureIssueRead.model_validate(row[0]) for row in rows]

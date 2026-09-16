"""Store an architecture report (nodes, edges, issues, summary) for a scan."""

import uuid
from typing import Any

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.models import (
    ArchitectureIssue,
    ArchitectureSummary,
    EdgeKind,
    GraphEdge,
    GraphNode,
)
from app.services.graph.analysis import ArchitectureReport

_INSERT_BATCH = 2000


def delete_architecture(db: Session, scan_id: uuid.UUID) -> None:
    for model in (GraphNode, GraphEdge, ArchitectureIssue, ArchitectureSummary):
        db.execute(delete(model).where(model.scan_id == scan_id))


def _insert(db: Session, model: Any, rows: list[dict[str, Any]]) -> None:
    for start in range(0, len(rows), _INSERT_BATCH):
        db.execute(insert(model), rows[start : start + _INSERT_BATCH])


def persist_architecture(db: Session, scan_id: uuid.UUID, report: ArchitectureReport) -> None:
    """Replace the scan's architecture data. Does not commit."""
    delete_architecture(db, scan_id)
    graph, metrics = report.graph.graph, report.metrics.nodes

    _insert(
        db,
        GraphNode,
        [
            {
                "scan_id": scan_id,
                "module_id": node,
                "path": data["path"],
                "language": data["language"],
                "loc": data["loc"],
                "definition_count": data["definition_count"],
                "fan_in": metrics[node].fan_in,
                "fan_out": metrics[node].fan_out,
                "instability": metrics[node].instability,
                "centrality": metrics[node].centrality,
                "inferred_layer": data["layer"],
                "layer_stack": data["stack"],
                "is_entrypoint": data["is_entrypoint"],
                "is_test": data["is_test"],
                "parse_error": data["parse_error"],
                "symbols": data["symbols"],
            }
            for node, data in graph.nodes(data=True)
        ],
    )

    edges: list[dict[str, Any]] = [
        {
            "scan_id": scan_id,
            "source_module": edge.source,
            "target_module": edge.target,
            "kind": EdgeKind.INTERNAL,
            "import_statement": edge.first.statement,
            "line": edge.first.line,
            "import_count": len(edge.imports),
            "type_only": edge.type_only,
            "lazy": edge.lazy,
            "resolution": None,
        }
        for edge in report.graph.edges.values()
    ]
    for external in report.graph.external:
        first = min(external.imports, key=lambda i: i.line)
        edges.append(
            {
                "scan_id": scan_id,
                "source_module": external.source,
                "target_module": external.package,
                "kind": EdgeKind.EXTERNAL,
                "import_statement": first.statement,
                "line": first.line,
                "import_count": len(external.imports),
                "type_only": all(i.type_only for i in external.imports),
                "lazy": all(i.lazy for i in external.imports),
                "resolution": external.evidence,
            }
        )
    module_ids = report.graph.module_ids
    for item in report.graph.unresolved:
        edges.append(
            {
                "scan_id": scan_id,
                "source_module": module_ids[item.source],
                "target_module": item.raw.specifier[:1000],
                "kind": EdgeKind.UNRESOLVED,
                "import_statement": item.raw.statement,
                "line": item.raw.line,
                "import_count": 1,
                "type_only": item.raw.type_only,
                "lazy": item.raw.lazy,
                "resolution": item.reason,
            }
        )
    _insert(db, GraphEdge, edges)

    _insert(
        db,
        ArchitectureIssue,
        [
            {
                "scan_id": scan_id,
                "issue_type": issue.issue_type,
                "severity": issue.severity,
                "title": issue.title[:255],
                "description": issue.description,
                "involved_modules": issue.involved_modules,
                "involved_edges": [list(e) for e in issue.involved_edges],
                "metric_value": issue.metric_value,
                "details": issue.details,
            }
            for issue in report.metrics.issues
        ],
    )
    db.add(ArchitectureSummary(scan_id=scan_id, summary=report.summary))

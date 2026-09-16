import enum
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, pg_enum
from app.models.finding import Severity


class EdgeKind(enum.StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"  # target_module is the package name
    UNRESOLVED = "unresolved"  # target_module is the raw import string


class ArchitectureIssueType(enum.StrEnum):
    CIRCULAR_DEPENDENCY = "circular_dependency"
    LAYER_VIOLATION = "layer_violation"
    GOD_MODULE = "god_module"
    ORPHAN_MODULE = "orphan_module"


class GraphNode(Base):
    """An internal module of a scanned repository."""

    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("scan_id", "module_id"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    module_id: Mapped[str] = mapped_column(Text)  # path without extension; packages collapsed
    path: Mapped[str] = mapped_column(Text)
    language: Mapped[str] = mapped_column(String(32))
    loc: Mapped[int] = mapped_column(Integer)
    definition_count: Mapped[int] = mapped_column(Integer)
    fan_in: Mapped[int] = mapped_column(Integer)
    fan_out: Mapped[int] = mapped_column(Integer)
    # fan_out / (fan_in + fan_out); None for modules with neither.
    instability: Mapped[float | None] = mapped_column(Float)
    centrality: Mapped[float] = mapped_column(Float)  # normalised betweenness
    inferred_layer: Mapped[str | None] = mapped_column(String(32))
    layer_stack: Mapped[str | None] = mapped_column(String(32))  # backend | frontend
    is_entrypoint: Mapped[bool] = mapped_column(Boolean)
    is_test: Mapped[bool] = mapped_column(Boolean)
    parse_error: Mapped[str | None] = mapped_column(Text)  # set when the file was skipped
    symbols: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")


class GraphEdge(Base):
    """An import: internal (module -> module), external (module -> package) or unresolved.

    Internal and external edges are aggregated per (source, target); unresolved
    ones are stored per import statement.
    """

    __tablename__ = "graph_edges"
    __table_args__ = (
        Index("ix_graph_edges_scan_id_source_module", "scan_id", "source_module"),
        Index("ix_graph_edges_scan_id_target_module", "scan_id", "target_module"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    source_module: Mapped[str] = mapped_column(Text)
    target_module: Mapped[str] = mapped_column(Text)
    kind: Mapped[EdgeKind] = mapped_column(pg_enum(EdgeKind, "graph_edge_kind"))
    import_statement: Mapped[str] = mapped_column(Text)  # the first statement, source order
    line: Mapped[int] = mapped_column(Integer)
    import_count: Mapped[int] = mapped_column(Integer)
    type_only: Mapped[bool] = mapped_column(Boolean)  # no runtime dependency
    lazy: Mapped[bool] = mapped_column(Boolean)  # imported inside a function
    # Internal: how it resolved; external: stdlib | node-builtin | declared | undeclared;
    # unresolved: the reason.
    resolution: Mapped[str | None] = mapped_column(Text)


class ArchitectureIssue(Base):
    __tablename__ = "architecture_issues"
    __table_args__ = (Index("ix_architecture_issues_scan_id_issue_type", "scan_id", "issue_type"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    issue_type: Mapped[ArchitectureIssueType] = mapped_column(
        pg_enum(ArchitectureIssueType, "architecture_issue_type")
    )
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "finding_severity"))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    involved_modules: Mapped[list[str]] = mapped_column(JSONB)  # module ids
    involved_edges: Mapped[list[list[str]]] = mapped_column(JSONB)  # [[source, target], ...]
    metric_value: Mapped[float | None] = mapped_column(Float)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")


class ArchitectureSummary(Base):
    """Graph-wide metrics, parse and import-resolution statistics, timings."""

    __tablename__ = "architecture_summaries"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB)

import enum
import hashlib
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, pg_enum

if TYPE_CHECKING:
    from app.models.scan import Scan


class Severity(enum.StrEnum):
    # Declaration order is the Postgres enum sort order: ORDER BY severity DESC
    # puts critical first.
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_id_severity", "scan_id", "severity"),
        Index("ix_findings_scan_id_file_path", "scan_id", "file_path"),
        Index("ix_findings_scan_id_analyzer", "scan_id", "analyzer"),
        # Idempotency backstop: a retried or duplicated persist can't store a finding twice.
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_id_fingerprint"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    # Analyzer whose report was kept ("semgrep", "bandit", "ruff", "dependency").
    analyzer: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(512))
    # sha256 of analyzer, rule, file, lines, message and package (see scan_pipeline).
    fingerprint: Mapped[str] = mapped_column(
        String(64), default=lambda ctx: finding_fingerprint(ctx.get_current_parameters())
    )
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "finding_severity"))
    file_path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    # Coarse issue class used for cross-analyzer deduplication ("sql-injection").
    category: Mapped[str | None] = mapped_column(String(512))
    # Other analyzers that reported the same issue. Agreement raises confidence.
    corroborated_by: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), default=list, server_default="{}"
    )
    # The duplicate findings merged into this one: [{analyzer, rule_id, severity, ...}].
    merged_from: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    # Vulnerable dependencies: {ecosystem, package, installed_version, advisory_id, ...}.
    dependency: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Overall score points gained if this finding alone were fixed (scoring rubric).
    score_impact: Mapped[float | None] = mapped_column(Float)
    # The tool's result object (OSV records are trimmed; they include every version).
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)

    scan: Mapped["Scan"] = relationship(back_populates="findings")


def finding_fingerprint(values: dict[str, Any]) -> str:
    """Stable identity of a finding within a scan (also computed in SQL by the migration)."""
    dependency = values.get("dependency") or {}
    parts = [
        values.get("analyzer"),
        values.get("rule_id"),
        values.get("file_path"),
        values.get("start_line"),
        values.get("end_line"),
        values.get("message"),
        dependency.get("package") if isinstance(dependency, dict) else None,
        dependency.get("installed_version") if isinstance(dependency, dict) else None,
    ]
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()

import enum
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
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
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    # Tool that produced the finding ("semgrep", later "bandit", ...).
    analyzer: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(512))
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "finding_severity"))
    file_path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    # The tool's complete, unmodified result object.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)

    scan: Mapped["Scan"] = relationship(back_populates="findings")

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, pg_enum

if TYPE_CHECKING:
    from app.models.scan import Scan


class AnalyzerRunStatus(enum.StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    # Not applicable to the codebase (e.g. Bandit without Python files).
    SKIPPED = "skipped"


FAILED_RUN_STATUSES = frozenset({AnalyzerRunStatus.FAILED, AnalyzerRunStatus.TIMED_OUT})


class AnalyzerRun(Base):
    """One analyzer's execution within a scan."""

    __tablename__ = "analyzer_runs"
    __table_args__ = (UniqueConstraint("scan_id", "analyzer_name"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Lookups by scan use the unique (scan_id, analyzer_name) index.
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    analyzer_name: Mapped[str] = mapped_column(String(64))
    status: Mapped[AnalyzerRunStatus] = mapped_column(
        pg_enum(AnalyzerRunStatus, "analyzer_run_status")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_message: Mapped[str | None] = mapped_column(Text)
    # Findings the tool reported, before cross-analyzer deduplication.
    finding_count: Mapped[int | None] = mapped_column(Integer)
    # Non-fatal problems that reduced coverage.
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped["Scan"] = relationship(back_populates="analyzer_runs")

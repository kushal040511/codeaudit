import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, pg_enum

if TYPE_CHECKING:
    from app.models.analyzer_run import AnalyzerRun
    from app.models.finding import Finding


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    # Findings are stored and readable; LLM enrichment is queued.
    ANALYSIS_COMPLETE = "analysis_complete"
    # LLM enrichment (fix suggestions, architecture review) is running.
    ENRICHING = "enriching"
    COMPLETED = "completed"
    # Finished, but at least one analyzer failed or timed out: not a clean result.
    PARTIAL = "partial"
    FAILED = "failed"


class EnrichmentStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"  # some suggestions or the review could not be generated
    FAILED = "failed"
    SKIPPED = "skipped"  # disabled, no API key, or nothing to enrich


TERMINAL_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED})
# Findings can be shown in these states.
RESULT_STATUSES = frozenset(
    {
        ScanStatus.ANALYSIS_COMPLETE,
        ScanStatus.ENRICHING,
        ScanStatus.COMPLETED,
        ScanStatus.PARTIAL,
    }
)


class ScanSource(enum.StrEnum):
    UPLOAD = "upload"
    GITHUB = "github"


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_user_id_created_at", "user_id", "created_at"),
        Index("ix_scans_repo", "repo_owner", "repo_name", "commit_sha"),
        Index("ix_scans_content_sha256", "content_sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, index=True
    )
    # None: anonymous scan, readable by anyone holding its (unguessable) id.
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[ScanSource] = mapped_column(
        pg_enum(ScanSource, "scan_source"), default=ScanSource.UPLOAD, server_default="upload"
    )
    # Display only. Never used to build filesystem or storage paths.
    original_filename: Mapped[str] = mapped_column(String(255))
    # Uploads only.
    storage_key: Mapped[str | None] = mapped_column(String(1024))
    # GitHub scans: the exact commit analysed; fix PRs are built against it.
    repo_owner: Mapped[str | None] = mapped_column(String(100))
    repo_name: Mapped[str | None] = mapped_column(String(100))
    repo_ref: Mapped[str | None] = mapped_column(String(255))  # as requested (branch/tag/sha)
    repo_default_branch: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    # Cache identity: sha256 of the uploaded archive, and the analyzer set that ran.
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    analysis_version: Mapped[str | None] = mapped_column(String(32))
    repo_private: Mapped[bool | None] = mapped_column(Boolean)
    # [{"language": "python", "file_count": 12, "manifests": ["requirements.txt"]}, ...]
    detected_languages: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Non-blank lines of recognised source code; normalises the score by size.
    source_loc: Mapped[int | None] = mapped_column(Integer)
    # Whether analyzers failed; decides `partial` vs `completed` once enrichment ends.
    analysis_partial: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    enrichment_status: Mapped[EnrichmentStatus | None] = mapped_column(
        pg_enum(EnrichmentStatus, "enrichment_status")
    )
    # Why enrichment was skipped, degraded or failed. Never makes the scan invalid.
    enrichment_error: Mapped[str | None] = mapped_column(Text)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    analyzer_runs: Mapped[list["AnalyzerRun"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AnalyzerRun.id",
    )

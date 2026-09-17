import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, pg_enum


class SiteAnalysisStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SiteAnalysis(Base):
    """Analysis of one website URL: phishing/clone risk evidence and design tokens.

    Everything captured from the site is untrusted data.
    """

    __tablename__ = "site_analyses"
    __table_args__ = (
        Index("ix_site_analyses_normalized_url_created_at", "normalized_url", "created_at"),
        Index("ix_site_analyses_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[SiteAnalysisStatus] = mapped_column(
        pg_enum(SiteAnalysisStatus, "site_analysis_status")
    )
    # capturing | assessing_risk | extracting_design, while running
    stage: Mapped[str | None] = mapped_column(String(32))
    url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[str] = mapped_column(String(2048))
    final_url: Mapped[str | None] = mapped_column(String(2048))
    screenshot_key: Mapped[str | None] = mapped_column(String(1024))
    full_screenshot_key: Mapped[str | None] = mapped_column(String(1024))
    favicon_key: Mapped[str | None] = mapped_column(String(1024))
    dom_key: Mapped[str | None] = mapped_column(String(1024))
    # Title, meta, redirect chain, forms, link domains, TLS, blocked requests.
    capture: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str | None] = mapped_column(String(16))
    # RiskReport.as_dict(): evidence list, visual match, model version, disclaimer.
    risk_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    design_tokens: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Why the vision step was skipped or failed (tokens from CSS are still produced).
    design_notes: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    error_message: Mapped[str | None] = mapped_column(Text)
    # Set when results were copied from a recent analysis of the same URL.
    cached_from_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("site_analyses.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

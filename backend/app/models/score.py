import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ScanScore(Base):
    """The deterministic rubric score of a scan (services/scoring/rubric.py)."""

    __tablename__ = "scan_scores"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    rubric_version: Mapped[str] = mapped_column(String(16))
    # None when no category could be scored.
    overall: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str | None] = mapped_column(String(2))
    # Some analyzer failed: not comparable with complete scores.
    incomplete: Mapped[bool] = mapped_column(Boolean)
    incomplete_reasons: Mapped[list[str]] = mapped_column(JSONB, default=list)
    # [{category, label, score, weight, penalty, finding_count, excluded_reason, rationale}]
    categories: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    source_loc: Mapped[int] = mapped_column(Integer)
    module_count: Mapped[int] = mapped_column(Integer)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

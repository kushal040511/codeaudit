import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, pg_enum


class LLMPurpose(enum.StrEnum):
    FIX_SUGGESTION = "fix_suggestion"
    FIX_REGENERATION = "fix_regeneration"
    ARCHITECTURE_REVIEW = "architecture_review"


class LLMCall(Base):
    """One logical request to the model: tokens, latency, cost and outcome.

    Refused calls (budget) are recorded too, with zero tokens.
    """

    __tablename__ = "llm_calls"
    __table_args__ = (Index("ix_llm_calls_scan_id_purpose", "scan_id", "purpose"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    purpose: Mapped[LLMPurpose] = mapped_column(pg_enum(LLMPurpose, "llm_purpose"))
    model: Mapped[str] = mapped_column(String(128))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_creation_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    # Priced at call time with the table in services/llm/pricing.py.
    cost_usd: Mapped[float] = mapped_column(Numeric(12, 6), default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=1)  # includes retries
    success: Mapped[bool] = mapped_column(Boolean)
    # In flight: counted against the budget as `reserved_tokens` until it finishes.
    pending: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    reserved_tokens: Mapped[int] = mapped_column(Integer, default=0)
    # error: budget_exceeded | rate_limited | api_error | refusal | max_tokens |
    # invalid_output | connection_error
    error_type: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    stop_reason: Mapped[str | None] = mapped_column(String(32))
    request_id: Mapped[str | None] = mapped_column(String(128))
    # What was asked and answered (truncated), for auditing suggestions.
    prompt: Mapped[str | None] = mapped_column(Text)
    response_text: Mapped[str | None] = mapped_column(Text)
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FixStatus(enum.StrEnum):
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"  # the model call failed or returned unusable output


class ValidationStatus(enum.StrEnum):
    VALID = "valid"  # applies cleanly and the result parses
    FAILED_TO_APPLY = "failed_to_apply"
    SYNTAX_ERROR = "syntax_error"
    NO_PATCH = "no_patch"  # the model explained the issue but proposed no change
    NOT_VALIDATED = "not_validated"  # nothing to validate yet (generating / failed)


class Confidence(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BreakingRisk(enum.StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class FixSuggestion(Base):
    """The current fix suggestion for one finding. Regeneration replaces it in place."""

    __tablename__ = "fix_suggestions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True
    )
    status: Mapped[FixStatus] = mapped_column(pg_enum(FixStatus, "fix_status"))
    validation_status: Mapped[ValidationStatus] = mapped_column(
        pg_enum(ValidationStatus, "fix_validation_status")
    )
    # Why validation failed (git apply / parser output), shown to the user.
    validation_detail: Mapped[str | None] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[Confidence | None] = mapped_column(pg_enum(Confidence, "fix_confidence"))
    patch: Mapped[str | None] = mapped_column(Text)  # unified diff, as generated
    breaking_risk: Mapped[BreakingRisk | None] = mapped_column(
        pg_enum(BreakingRisk, "fix_breaking_risk")
    )
    test_suggestion: Mapped[str | None] = mapped_column(Text)
    # Only for valid patches: [{path, start_line, original, patched}] excerpts for a diff view.
    file_changes: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    # Findings addressed by the same generated fix (grouped request).
    shared_with_finding_ids: Mapped[list[int]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    user_hint: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    model: Mapped[str | None] = mapped_column(String(128))
    llm_call_id: Mapped[int | None] = mapped_column(ForeignKey("llm_calls.id", ondelete="SET NULL"))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ReviewStatus(enum.StrEnum):
    READY = "ready"
    FAILED = "failed"


class ArchitectureReview(Base):
    """The model's structural critique of a scan's dependency graph, citation-checked."""

    __tablename__ = "architecture_reviews"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[ReviewStatus] = mapped_column(
        pg_enum(ReviewStatus, "architecture_review_status")
    )
    summary: Mapped[str | None] = mapped_column(Text)
    strengths: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    # Kept issues: {title, severity, evidence, why_it_matters, refactor_steps,
    # rejected_evidence, citations_verified}
    issues: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")
    # Issues dropped because none of their evidence exists in the graph.
    dropped_issues: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default="[]"
    )
    suggested_target_structure: Mapped[str | None] = mapped_column(Text)
    citations_total: Mapped[int] = mapped_column(Integer, default=0)
    citations_invalid: Mapped[int] = mapped_column(Integer, default=0)
    # citations_invalid / citations_total; None when nothing was cited.
    hallucination_rate: Mapped[float | None] = mapped_column(Float)
    model: Mapped[str | None] = mapped_column(String(128))
    llm_call_id: Mapped[int | None] = mapped_column(ForeignKey("llm_calls.id", ondelete="SET NULL"))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

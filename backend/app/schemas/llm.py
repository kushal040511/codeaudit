from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    BreakingRisk,
    Confidence,
    EnrichmentStatus,
    FixStatus,
    LLMPurpose,
    ReviewStatus,
    ValidationStatus,
)


class FileChangeRead(BaseModel):
    path: str
    start_line: int
    original: str
    patched: str


class FixSuggestionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: int
    status: FixStatus
    validation_status: ValidationStatus
    # True only when the patch applies cleanly and the result parses.
    patch_verified: bool
    validation_detail: str | None
    explanation: str | None
    confidence: Confidence | None
    # Withheld unless the patch is valid; broken patches are never offered as fixes.
    patch: str | None
    rejected_patch: str | None
    breaking_risk: BreakingRisk | None
    test_suggestion: str | None
    file_changes: list[FileChangeRead]
    shared_with_finding_ids: list[int]
    user_hint: str | None
    version: int
    model: str | None
    error_message: str | None
    updated_at: datetime


class RegenerateFixRequest(BaseModel):
    hint: str | None = Field(default=None, max_length=2000)


class ReviewIssueRead(BaseModel):
    title: str
    severity: str
    evidence: list[str]
    why_it_matters: str
    refactor_steps: list[str]
    rejected_evidence: list[dict[str, str]] = []
    unverified_mentions: list[str] = []


class ArchitectureReviewRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: ReviewStatus
    summary: str | None
    strengths: list[str]
    issues: list[ReviewIssueRead]
    dropped_issues: list[ReviewIssueRead]
    suggested_target_structure: str | None
    citations_total: int
    citations_invalid: int
    hallucination_rate: float | None
    model: str | None
    error_message: str | None
    created_at: datetime


class LLMCallRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    purpose: LLMPurpose
    model: str
    input_tokens: int
    output_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int
    cost_usd: float
    duration_ms: int
    attempts: int
    success: bool
    pending: bool
    error_type: str | None
    error_message: str | None
    stop_reason: str | None
    context: dict[str, Any]
    created_at: datetime


class LLMUsageByPurpose(BaseModel):
    purpose: LLMPurpose
    calls: int
    failed_calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: float


class LLMUsageRead(BaseModel):
    enrichment_status: EnrichmentStatus | None
    enrichment_error: str | None
    model: str | None
    token_budget: int
    tokens_used: int  # includes in-flight reservations
    input_tokens: int
    output_tokens: int
    cost_usd: float
    calls: int
    failed_calls: int
    total_duration_ms: int
    pricing_note: str
    by_purpose: list[LLMUsageByPurpose]
    recent_calls: list[LLMCallRead]


class LLMUsageSummary(BaseModel):
    """Compact version for the scan response."""

    tokens: int
    cost_usd: float
    calls: int
    fix_suggestions: int
    valid_fix_suggestions: int

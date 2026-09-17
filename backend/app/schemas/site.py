import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models import SiteAnalysisStatus


class SiteAnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    # Re-capture even if a recent analysis of this URL exists.
    force: bool = False


class SiteAnalyzeCreated(BaseModel):
    analysis_id: uuid.UUID
    status: SiteAnalysisStatus
    normalized_url: str
    # Results were copied from a recent analysis of the same URL (no new fetch).
    cached: bool


class EvidenceRead(BaseModel):
    signal: str
    category: Literal["domain", "certificate", "visual", "content", "reputation"]
    label: str
    points: float
    status: Literal["fired", "clear", "unavailable", "info"]
    value: Any = None


class VisualMatchRead(BaseModel):
    brand: str
    brand_name: str
    page: str
    similarity: float
    reference_url: str
    # API path of the reference screenshot, when stored.
    reference_screenshot_url: str | None


class RiskRead(BaseModel):
    score: int
    level: Literal["low", "moderate", "high", "very_high"]
    summary: str
    evidence: list[EvidenceRead]
    impersonated_brand: str | None
    visual_match: VisualMatchRead | None
    model_version: str
    disclaimer: str


class DesignRead(BaseModel):
    tokens: dict[str, Any]
    notes: list[str]


class SiteAnalysisRead(BaseModel):
    id: uuid.UUID
    status: SiteAnalysisStatus
    stage: str | None
    url: str
    normalized_url: str
    final_url: str | None
    error_message: str | None
    cached_from_id: uuid.UUID | None
    owned_by_you: bool
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    screenshot_url: str | None
    full_screenshot_url: str | None
    capture: dict[str, Any] | None
    risk: RiskRead | None
    design: DesignRead | None


class SiteAnalysisListItem(BaseModel):
    id: uuid.UUID
    status: SiteAnalysisStatus
    url: str
    final_url: str | None
    risk_score: int | None
    risk_level: str | None
    created_at: datetime

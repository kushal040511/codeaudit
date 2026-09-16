import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models import ScanSource, ScanStatus
from app.schemas.finding import FindingRead

MAX_LISTED_FINDINGS = 200


class CompareRequest(BaseModel):
    base_scan_id: uuid.UUID
    head_scan_id: uuid.UUID


class ScanSide(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    repository: str | None
    commit_sha: str | None
    score: float | None
    grade: str | None
    rubric_version: str | None
    incomplete: bool
    finding_count: int


class CategoryDelta(BaseModel):
    category: str
    label: str
    base: float | None
    head: float | None
    delta: float | None


class CompareRead(BaseModel):
    base: ScanSide
    head: ScanSide
    # head - base; None if either side has no score.
    score_delta: float | None
    # False when rubric versions differ or either score is incomplete: the delta
    # is shown but shouldn't gate a merge.
    comparable: bool
    warnings: list[str]
    categories: list[CategoryDelta]
    new_count: int
    resolved_count: int
    unchanged_count: int
    new_by_severity: dict[str, int]
    resolved_by_severity: dict[str, int]
    # Most severe first, at most MAX_LISTED_FINDINGS each.
    new_findings: list[FindingRead]
    resolved_findings: list[FindingRead]


class ScanListItem(BaseModel):
    id: uuid.UUID
    status: ScanStatus
    source: ScanSource
    repository: str | None
    commit_sha: str | None
    repo_ref: str | None
    score: float | None
    grade: str | None
    created_at: datetime


class ScanList(BaseModel):
    items: list[ScanListItem]
    total: int = Field(ge=0)

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CategoryScoreRead(BaseModel):
    category: str
    label: str
    score: float | None  # None: excluded (not applicable, or its analyzer failed)
    weight: float
    penalty: float
    finding_count: int
    excluded_reason: str | None
    rationale: list[str]


class ScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rubric_version: str
    overall: float | None
    grade: str | None
    incomplete: bool
    incomplete_reasons: list[str]
    categories: list[CategoryScoreRead]
    source_loc: int
    module_count: int
    computed_at: datetime


class ScoreSummary(BaseModel):
    overall: float | None
    grade: str | None
    incomplete: bool
    rubric_version: str


class ProjectionRequest(BaseModel):
    finding_ids: list[int] = Field(max_length=5000)


class ProjectedScore(BaseModel):
    overall: float | None
    grade: str | None
    categories: list[CategoryScoreRead]


class ProjectionRead(BaseModel):
    current: ProjectedScore
    projected: ProjectedScore
    delta: float | None
    included_finding_ids: list[int]
    ignored_finding_ids: list[int]  # not findings of this scan

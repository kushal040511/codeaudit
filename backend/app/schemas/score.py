from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DeductionRead(BaseModel):
    """One experimental signal applied to a category (rubric 1.1.0)."""

    signal: str | None  # None: the signal was enabled but didn't apply (label says why)
    label: str
    signal_score: float | None = None  # 0-1, 1 = best
    penalty: float | None = None
    points: float  # category points lost, in order of application


class CategoryScoreRead(BaseModel):
    category: str
    label: str
    score: float | None  # None: excluded (not applicable, or its analyzer failed)
    weight: float
    penalty: float
    finding_count: int
    excluded_reason: str | None
    rationale: list[str]
    deductions: list[DeductionRead] = []  # absent in scores stored before rubric 1.1.0


class ScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rubric_version: str
    rubric_config: str = "base"  # experimental signals scored; "base" = none
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

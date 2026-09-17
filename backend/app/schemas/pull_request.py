import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.models import PullRequestStatus, Severity
from app.services.github.urls import InvalidRepoUrlError, validate_ref


class PullRequestPreviewRequest(BaseModel):
    suggestion_ids: list[int] = Field(min_length=1, max_length=200)
    branch: str | None = Field(default=None, max_length=200)
    # Must be set explicitly when you can't push to the repository.
    use_fork: bool = False

    @field_validator("branch")
    @classmethod
    def _valid_branch(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return validate_ref(value)
        except InvalidRepoUrlError as exc:
            raise ValueError(str(exc)) from None


class PullRequestConfirmRequest(BaseModel):
    # Required and must be literally true: there is no implicit confirmation.
    confirm: Literal[True]
    title: str | None = Field(default=None, min_length=1, max_length=255)
    body: str | None = Field(default=None, max_length=60000)


class PatchCheckRead(BaseModel):
    suggestion_ids: list[int]
    paths: list[str]
    status: Literal["applies", "no_longer_applies", "conflicts", "syntax_error"]
    detail: str | None


class PlannedCommitRead(BaseModel):
    message: str
    suggestion_ids: list[int]
    paths: list[str]


class PlannedFileRead(BaseModel):
    path: str
    original: str
    patched: str


class BlockingIssueRead(BaseModel):
    code: str
    message: str


class ScoreProjectionSummary(BaseModel):
    current: float | None
    current_grade: str | None
    projected: float | None
    projected_grade: str | None
    delta: float | None
    rubric_version: str
    incomplete: bool


class PullRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    # The public UUID; the sequential primary key is never exposed.
    id: uuid.UUID = Field(validation_alias=AliasChoices("public_id", "id"))
    scan_id: Any
    status: PullRequestStatus
    repo_full_name: str
    head_repo_full_name: str
    base_branch: str
    base_sha: str
    branch: str
    use_fork: bool
    title: str
    body: str
    included_suggestion_ids: list[int]
    commits: list[dict[str, Any]]
    pr_number: int | None
    pr_url: str | None
    error_code: str | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    confirmed_at: datetime | None


class PullRequestPreviewRead(PullRequestRead):
    scanned_sha: str
    head_moved: bool
    can_push: bool
    requires_fork: bool
    branch_available: bool
    suggested_branch: str | None
    combined_diff: str
    files: list[PlannedFileRead]
    planned_commits: list[PlannedCommitRead]
    patch_checks: list[PatchCheckRead]
    excluded: list[dict[str, Any]]
    blocking: list[BlockingIssueRead]
    score: ScoreProjectionSummary
    # Confirming writes a branch, commits and a pull request to this repository.
    writes_to: str


class FixCandidateRead(BaseModel):
    suggestion_id: int
    finding_id: int
    severity: Severity
    analyzer: str
    rule_id: str
    file_path: str
    start_line: int
    message: str
    explanation: str | None
    confidence: str | None
    breaking_risk: str | None
    score_impact: float | None
    shared_with_finding_ids: list[int]
    patch: str

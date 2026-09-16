import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models import AnalyzerRunStatus, EnrichmentStatus, ScanSource, ScanStatus
from app.schemas.llm import LLMUsageSummary
from app.schemas.score import ScoreSummary


class RepoScanRequest(BaseModel):
    repo_url: str = Field(max_length=500, examples=["https://github.com/owner/repo"])
    # Branch, tag or 40-character commit; the default branch when omitted.
    ref: str | None = Field(default=None, max_length=255)


class RepositoryRead(BaseModel):
    owner: str
    name: str
    full_name: str
    ref: str | None
    default_branch: str | None
    commit_sha: str
    private: bool | None
    html_url: str


class ScanCreated(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus


class DetectedLanguageRead(BaseModel):
    language: str
    file_count: int
    manifests: list[str]


class SeverityCounts(BaseModel):
    critical: int = 0
    error: int = 0
    warning: int = 0
    info: int = 0


class AnalyzerRunRead(BaseModel):
    analyzer: str
    display_name: str
    status: AnalyzerRunStatus
    duration_ms: int | None
    # Findings the tool reported, before deduplication across analyzers.
    finding_count: int | None
    error_message: str | None
    warnings: list[str]
    started_at: datetime | None
    completed_at: datetime | None


class AnalyzerSummary(BaseModel):
    total: int  # applicable analyzers (skipped ones excluded)
    completed: int
    failed: int  # failed or timed out
    running: int
    skipped: int


class ScanRead(BaseModel):
    id: uuid.UUID
    status: ScanStatus
    source: ScanSource
    repository: RepositoryRead | None
    # Whether the caller owns this scan (needed to open pull requests from it).
    owned_by_you: bool
    original_filename: str
    detected_languages: list[DetectedLanguageRead] | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    finding_counts: SeverityCounts
    total_findings: int
    # Deduplicated findings each analyzer reported or corroborated (matches the
    # findings `analyzer` filter, so the counts overlap).
    findings_by_analyzer: dict[str, int]
    # Sum of the tools' own counts, before deduplication.
    findings_before_dedup: int
    analyzer_runs: list[AnalyzerRunRead]
    analyzer_summary: AnalyzerSummary
    # LLM stage: None for scans created before it existed.
    enrichment_status: EnrichmentStatus | None
    enrichment_error: str | None
    llm_usage: LLMUsageSummary
    score: ScoreSummary | None

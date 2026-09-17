# Import every model here so Alembic autogenerate sees the full metadata.
from app.models.analyzer_run import FAILED_RUN_STATUSES, AnalyzerRun, AnalyzerRunStatus
from app.models.architecture import (
    ArchitectureIssue,
    ArchitectureIssueType,
    ArchitectureSummary,
    EdgeKind,
    GraphEdge,
    GraphNode,
)
from app.models.base import Base
from app.models.finding import Finding, Severity
from app.models.llm import (
    ArchitectureReview,
    BreakingRisk,
    Confidence,
    FixStatus,
    FixSuggestion,
    LLMCall,
    LLMPurpose,
    ReviewStatus,
    ValidationStatus,
)
from app.models.pull_request import PullRequest, PullRequestStatus
from app.models.scan import (
    RESULT_STATUSES,
    TERMINAL_STATUSES,
    EnrichmentStatus,
    Scan,
    ScanSource,
    ScanStatus,
)
from app.models.score import ScanScore
from app.models.site_analysis import SiteAnalysis, SiteAnalysisStatus
from app.models.user import ApiToken, GitHubIdentity, User, UserSession

__all__ = [
    "ApiToken",
    "GitHubIdentity",
    "PullRequest",
    "SiteAnalysis",
    "SiteAnalysisStatus",
    "PullRequestStatus",
    "ScanSource",
    "User",
    "UserSession",
    "FAILED_RUN_STATUSES",
    "RESULT_STATUSES",
    "TERMINAL_STATUSES",
    "AnalyzerRun",
    "AnalyzerRunStatus",
    "ArchitectureIssue",
    "ArchitectureIssueType",
    "ArchitectureReview",
    "ArchitectureSummary",
    "Base",
    "BreakingRisk",
    "Confidence",
    "EdgeKind",
    "EnrichmentStatus",
    "Finding",
    "FixStatus",
    "FixSuggestion",
    "GraphEdge",
    "GraphNode",
    "LLMCall",
    "LLMPurpose",
    "ReviewStatus",
    "Scan",
    "ScanScore",
    "ScanStatus",
    "Severity",
    "ValidationStatus",
]

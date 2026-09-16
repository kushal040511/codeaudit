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
from app.models.scan import (
    RESULT_STATUSES,
    TERMINAL_STATUSES,
    EnrichmentStatus,
    Scan,
    ScanStatus,
)

__all__ = [
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
    "ScanStatus",
    "Severity",
    "ValidationStatus",
]

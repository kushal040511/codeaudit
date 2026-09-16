# Import every model here so Alembic autogenerate sees the full metadata.
from app.models.analyzer_run import FAILED_RUN_STATUSES, AnalyzerRun, AnalyzerRunStatus
from app.models.base import Base
from app.models.finding import Finding, Severity
from app.models.scan import TERMINAL_STATUSES, Scan, ScanStatus

__all__ = [
    "FAILED_RUN_STATUSES",
    "TERMINAL_STATUSES",
    "AnalyzerRun",
    "AnalyzerRunStatus",
    "Base",
    "Finding",
    "Scan",
    "ScanStatus",
    "Severity",
]

# Import every model here so Alembic autogenerate sees the full metadata.
from app.models.base import Base
from app.models.finding import Finding, Severity
from app.models.scan import TERMINAL_STATUSES, Scan, ScanStatus

__all__ = ["TERMINAL_STATUSES", "Base", "Finding", "Scan", "ScanStatus", "Severity"]

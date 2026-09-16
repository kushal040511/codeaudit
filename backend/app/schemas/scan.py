import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models import ScanStatus


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


class ScanRead(BaseModel):
    id: uuid.UUID
    status: ScanStatus
    original_filename: str
    detected_languages: list[DetectedLanguageRead] | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    finding_counts: SeverityCounts
    total_findings: int

import logging
import re
import uuid
from pathlib import PurePosixPath
from typing import Annotated, Any, BinaryIO

from fastapi import APIRouter, Depends, File, Query, UploadFile, status
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.errors import AppError, NotFoundError, PayloadTooLargeError, ServiceUnavailableError
from app.config import get_settings
from app.core.db import get_db
from app.core.storage import StorageError, delete_object, upload_fileobj
from app.models import Finding, Scan, ScanStatus, Severity
from app.schemas.errors import ErrorResponse
from app.schemas.finding import FindingPage, FindingRead
from app.schemas.scan import ScanCreated, ScanRead, SeverityCounts
from app.services.archive import UnsafeArchiveError, archive_limits_from_settings, inspect_zip
from app.workers.tasks import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _sanitize_filename(raw: str | None) -> str:
    name = PurePosixPath((raw or "").replace("\\", "/")).name
    name = _CONTROL_CHARS.sub("", name).strip()
    return name[:255] or "upload.zip"


def _stream_size(stream: BinaryIO) -> int:
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    return size


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"Scan {scan_id} not found.")
    return scan


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanCreated,
    responses=_errors(400, 413, 422, 503),
)
def create_scan(
    file: Annotated[UploadFile, File(description="Zip archive of the codebase (max 50 MB)")],
    db: DbSession,
) -> ScanCreated:
    """Upload a zipped codebase and queue a scan. Returns as soon as the job is queued."""
    settings = get_settings()

    filename = _sanitize_filename(file.filename)
    if not filename.lower().endswith(".zip"):
        raise AppError("Only .zip archives are accepted.", code="invalid_file_type")

    size = file.size if file.size is not None else _stream_size(file.file)
    if size == 0:
        raise AppError("The uploaded file is empty.", code="invalid_archive")
    if size > settings.max_upload_bytes:
        raise PayloadTooLargeError(f"Archive exceeds the {settings.max_upload_size_mb} MB limit.")

    try:
        summary = inspect_zip(file.file, archive_limits_from_settings(settings))
    except UnsafeArchiveError as exc:
        raise AppError(str(exc), code="invalid_archive") from exc

    scan_id = uuid.uuid4()
    storage_key = f"uploads/{scan_id}/source.zip"
    try:
        file.file.seek(0)
        upload_fileobj(file.file, storage_key, content_type="application/zip")
    except StorageError as exc:
        logger.exception("storing upload for scan %s failed", scan_id)
        raise ServiceUnavailableError("Object storage is unavailable. Try again later.") from exc

    scan = Scan(
        id=scan_id,
        status=ScanStatus.QUEUED,
        original_filename=filename,
        storage_key=storage_key,
    )
    try:
        db.add(scan)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("creating scan %s failed", scan_id)
        try:
            delete_object(storage_key)
        except StorageError:
            logger.warning("could not delete orphaned upload %s", storage_key)
        raise ServiceUnavailableError("Database is unavailable. Try again later.") from exc

    # Dispatch only after commit so the worker is guaranteed to see the row.
    try:
        run_scan.delay(str(scan_id))
    except BrokerError as exc:
        logger.exception("enqueueing scan %s failed", scan_id)
        scan.status = ScanStatus.FAILED
        scan.error_message = "Could not enqueue the scan job."
        db.commit()
        raise ServiceUnavailableError("Job queue is unavailable. Try again later.") from exc

    logger.info("queued scan %s (%s, %d files)", scan_id, filename, summary.file_count)
    return ScanCreated(scan_id=scan_id, status=ScanStatus.QUEUED)


@router.get("/{scan_id}", response_model=ScanRead, responses=_errors(404, 422))
def get_scan(scan_id: uuid.UUID, db: DbSession) -> ScanRead:
    """Scan status, timestamps, detected languages and finding counts by severity."""
    scan = _get_scan_or_404(db, scan_id)
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    ).all()
    counts = {severity.value: count for severity, count in rows}
    return ScanRead(
        id=scan.id,
        status=scan.status,
        original_filename=scan.original_filename,
        detected_languages=scan.detected_languages,
        error_message=scan.error_message,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        finding_counts=SeverityCounts(**counts),
        total_findings=sum(counts.values()),
    )


@router.get("/{scan_id}/findings", response_model=FindingPage, responses=_errors(404, 422))
def list_findings(
    scan_id: uuid.UUID,
    db: DbSession,
    severity: Annotated[
        list[Severity] | None, Query(description="Repeat to include several severities")
    ] = None,
    file_path: Annotated[
        str | None, Query(max_length=1024, description="Case-insensitive substring match")
    ] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> FindingPage:
    """Findings for a scan, most severe first."""
    _get_scan_or_404(db, scan_id)

    conditions = [Finding.scan_id == scan_id]
    if severity:
        conditions.append(Finding.severity.in_(severity))
    if file_path:
        conditions.append(Finding.file_path.ilike(f"%{_escape_like(file_path)}%", escape="\\"))

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    findings = db.scalars(
        select(Finding)
        .where(*conditions)
        .order_by(Finding.severity.desc(), Finding.file_path, Finding.start_line, Finding.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    return FindingPage(
        items=[FindingRead.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )

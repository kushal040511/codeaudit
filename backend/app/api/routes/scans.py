import logging
import re
import uuid
from pathlib import PurePosixPath
from typing import Annotated, Any, BinaryIO

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from kombu.exceptions import OperationalError as BrokerError
from pydantic import ValidationError
from sqlalchemy import String, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile as StarletteUploadFile

from app.api.deps import OptionalPrincipal, load_scan
from app.api.errors import AppError, ServiceUnavailableError
from app.core.db import get_db
from app.core.storage import StorageError, delete_object, upload_fileobj
from app.models import (
    FAILED_RUN_STATUSES,
    AnalyzerRunStatus,
    Finding,
    FixSuggestion,
    Scan,
    ScanScore,
    ScanStatus,
    Severity,
)
from app.schemas.errors import ErrorResponse
from app.schemas.finding import FindingPage, FindingRead
from app.schemas.scan import (
    AnalyzerRunRead,
    AnalyzerSummary,
    RepoScanRequest,
    RepositoryRead,
    ScanCreated,
    ScanRead,
    SeverityCounts,
)
from app.schemas.score import ScoreSummary
from app.services import quotas, scan_cache
from app.services.analyzers.registry import DISPLAY_NAMES
from app.services.auth.sessions import Principal
from app.services.llm.usage import llm_usage_summary
from app.services.scan_creation import build_repo_scan, enforce_scan_rate_limit, validate_upload
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


_CREATE_SCAN_BODY = {
    "requestBody": {
        "required": True,
        "content": {
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "properties": {"file": {"type": "string", "format": "binary"}},
                    "required": ["file"],
                }
            },
            "application/json": {"schema": RepoScanRequest.model_json_schema()},
        },
    }
}


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanCreated,
    responses=_errors(400, 401, 403, 404, 413, 422, 429, 503),
    openapi_extra=_CREATE_SCAN_BODY,
)
async def create_scan(request: Request, db: DbSession, principal: OptionalPrincipal) -> ScanCreated:
    """Queue a scan of an uploaded zip (multipart `file`, max 50 MB) or of a GitHub
    repository (JSON `{"repo_url", "ref"}`; public repos work without signing in).

    Returns as soon as the job is queued.
    """
    client_ip = quotas.client_ip(request)
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type == "application/json":
        try:
            body = RepoScanRequest.model_validate(await request.json())
        except (ValueError, ValidationError) as exc:
            raise AppError(
                'Expected JSON {"repo_url": ..., "ref": ...}.', code="validation_error"
            ) from exc
        await run_in_threadpool(enforce_scan_rate_limit, principal, client_ip)
        scan = await run_in_threadpool(build_repo_scan, db, principal, body.repo_url, body.ref)
        cached = await run_in_threadpool(
            scan_cache.find_reusable,
            db,
            principal,
            repo_owner=scan.repo_owner or "",
            repo_name=scan.repo_name or "",
            commit_sha=scan.commit_sha or "",
        )
        if cached is not None:
            return ScanCreated(scan_id=cached.id, status=cached.status, cached=True)
        return await run_in_threadpool(_queue, db, scan, None)
    if content_type == "multipart/form-data":
        form = await request.form()
        upload = form.get("file")
        if not isinstance(upload, StarletteUploadFile):
            raise AppError(
                "Send the archive in the multipart field `file`.", code="validation_error"
            )
        return await run_in_threadpool(_create_upload_scan, db, principal, client_ip, upload)
    raise AppError(
        "Send a zip as multipart/form-data or a repository as application/json.",
        code="unsupported_media_type",
    )


def _create_upload_scan(
    db: Session, principal: Principal | None, client_ip: str, file: StarletteUploadFile
) -> ScanCreated:
    filename = _sanitize_filename(file.filename)
    size = file.size if file.size is not None else _stream_size(file.file)
    file_count = validate_upload(filename, size, file.file)
    content_sha256 = scan_cache.sha256_of(file.file)
    cached = scan_cache.find_reusable(db, principal, content_sha256=content_sha256)
    if cached is not None:
        logger.info("upload matches scan %s; reusing its results", cached.id)
        return ScanCreated(scan_id=cached.id, status=cached.status, cached=True)
    enforce_scan_rate_limit(principal, client_ip)

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
        user_id=principal.user.id if principal else None,
        original_filename=filename,
        storage_key=storage_key,
        content_sha256=content_sha256,
    )
    logger.info("upload scan %s (%s, %d files)", scan_id, filename, file_count)
    return _queue(db, scan, storage_key)


def _queue(db: Session, scan: Scan, storage_key: str | None) -> ScanCreated:
    scan.analysis_version = scan_cache.analysis_version()
    try:
        db.add(scan)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("creating scan %s failed", scan.id)
        if storage_key:
            try:
                delete_object(storage_key)
            except StorageError:
                logger.warning("could not delete orphaned upload %s", storage_key)
        raise ServiceUnavailableError("Database is unavailable. Try again later.") from exc

    # Dispatch only after commit so the worker is guaranteed to see the row.
    try:
        run_scan.delay(str(scan.id))
    except BrokerError as exc:
        logger.exception("enqueueing scan %s failed", scan.id)
        scan.status = ScanStatus.FAILED
        scan.error_message = "Could not enqueue the scan job."
        db.commit()
        raise ServiceUnavailableError("Job queue is unavailable. Try again later.") from exc

    logger.info("queued scan %s (%s)", scan.id, scan.original_filename)
    return ScanCreated(scan_id=scan.id, status=ScanStatus.QUEUED)


@router.get("/{scan_id}", response_model=ScanRead, responses=_errors(404, 422))
def get_scan(scan_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal) -> ScanRead:
    """Scan status, per-analyzer runs, detected languages and finding counts."""
    scan = load_scan(db, scan_id, principal)
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    ).all()
    by_severity = {severity.value: count for severity, count in rows}
    # Same semantics as the findings `analyzer` filter: reported or corroborated.
    reporter = func.unnest(func.array_append(Finding.corroborated_by, Finding.analyzer)).alias(
        "reporter"
    )
    by_analyzer = {
        str(name): count
        for name, count in db.execute(
            select(reporter.column, func.count())
            .select_from(Finding)
            .join(reporter, literal(True))
            .where(Finding.scan_id == scan_id)
            .group_by(reporter.column)
        ).all()
    }

    runs = scan.analyzer_runs
    applicable = [r for r in runs if r.status is not AnalyzerRunStatus.SKIPPED]
    return ScanRead(
        id=scan.id,
        status=scan.status,
        source=scan.source,
        repository=(
            RepositoryRead(
                owner=scan.repo_owner,
                name=scan.repo_name,
                full_name=f"{scan.repo_owner}/{scan.repo_name}",
                ref=scan.repo_ref,
                default_branch=scan.repo_default_branch,
                commit_sha=scan.commit_sha,
                private=scan.repo_private,
                html_url=f"https://github.com/{scan.repo_owner}/{scan.repo_name}",
            )
            if scan.repo_owner and scan.repo_name and scan.commit_sha
            else None
        ),
        owned_by_you=principal is not None and scan.user_id == principal.user.id,
        original_filename=scan.original_filename,
        detected_languages=scan.detected_languages,
        error_message=scan.error_message,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        finding_counts=SeverityCounts(**by_severity),
        total_findings=sum(by_severity.values()),
        findings_by_analyzer=by_analyzer,
        findings_before_dedup=sum(r.finding_count or 0 for r in runs),
        analyzer_runs=[
            AnalyzerRunRead(
                analyzer=run.analyzer_name,
                display_name=DISPLAY_NAMES.get(run.analyzer_name, run.analyzer_name),
                status=run.status,
                duration_ms=run.duration_ms,
                finding_count=run.finding_count,
                error_message=run.error_message,
                warnings=run.warnings or [],
                started_at=run.started_at,
                completed_at=run.completed_at,
            )
            for run in runs
        ],
        analyzer_summary=AnalyzerSummary(
            total=len(applicable),
            completed=sum(r.status is AnalyzerRunStatus.COMPLETED for r in runs),
            failed=sum(r.status in FAILED_RUN_STATUSES for r in runs),
            running=sum(r.status is AnalyzerRunStatus.RUNNING for r in runs),
            skipped=len(runs) - len(applicable),
        ),
        enrichment_status=scan.enrichment_status,
        enrichment_error=scan.enrichment_error,
        llm_usage=llm_usage_summary(db, scan_id),
        score=(
            ScoreSummary(
                overall=score_row.overall,
                grade=score_row.grade,
                incomplete=score_row.incomplete,
                rubric_version=score_row.rubric_version,
            )
            if (score_row := db.get(ScanScore, scan_id))
            else None
        ),
    )


@router.get("/{scan_id}/findings", response_model=FindingPage, responses=_errors(404, 422))
def list_findings(
    scan_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    severity: Annotated[
        list[Severity] | None, Query(description="Repeat to include several severities")
    ] = None,
    analyzer: Annotated[
        list[Annotated[str, Query(max_length=64)]] | None,
        Query(
            description=(
                "Repeat to include several analyzers. Matches findings reported by the "
                "analyzer, including ones kept from another analyzer that it corroborated."
            ),
            max_length=20,
        ),
    ] = None,
    file_path: Annotated[
        str | None, Query(max_length=1024, description="Case-insensitive substring match")
    ] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> FindingPage:
    """Findings for a scan, most severe first, then by corroboration and location."""
    load_scan(db, scan_id, principal)

    conditions = [Finding.scan_id == scan_id]
    if severity:
        conditions.append(Finding.severity.in_(severity))
    if analyzer:
        conditions.append(
            or_(
                Finding.analyzer.in_(analyzer),
                Finding.corroborated_by.overlap(cast(analyzer, ARRAY(String(64)))),
            )
        )
    if file_path:
        conditions.append(Finding.file_path.ilike(f"%{_escape_like(file_path)}%", escape="\\"))

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    findings = db.scalars(
        select(Finding)
        .where(*conditions)
        .order_by(
            Finding.severity.desc(),
            func.cardinality(Finding.corroborated_by).desc(),
            Finding.file_path,
            Finding.start_line,
            Finding.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    fixes = {
        finding_id: (status, validation)
        for finding_id, status, validation in db.execute(
            select(
                FixSuggestion.finding_id, FixSuggestion.status, FixSuggestion.validation_status
            ).where(FixSuggestion.finding_id.in_([f.id for f in findings]))
        ).all()
    }

    def to_read(finding: Finding) -> FindingRead:
        item = FindingRead.model_validate(finding)
        if finding.id in fixes:
            item.fix_status, item.fix_validation_status = fixes[finding.id]
        return item

    return FindingPage(
        items=[to_read(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )

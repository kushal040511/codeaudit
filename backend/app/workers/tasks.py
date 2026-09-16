import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import worker_ready
from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError

from app.config import get_settings
from app.core.celery_app import celery_app
from app.core.db import SessionLocal
from app.core.errors import AnalysisError, TransientInfraError
from app.models import Scan, ScanStatus
from app.services.sandbox import SandboxUnavailableError, remove_orphaned_sandboxes
from app.services.scan_pipeline import (
    create_workspace,
    remove_stale_workspaces,
    run_pipeline,
    utcnow,
)

logger = logging.getLogger(__name__)

settings = get_settings()

# Retried with backoff. Analysis failures (bad archive, semgrep crash or timeout)
# are deliberately not in this list: retrying them only burns resources.
TRANSIENT_ERRORS: tuple[type[Exception], ...] = (
    TransientInfraError,
    OperationalError,
    InterfaceError,
)
RETRY_BASE_DELAY_SECONDS = 10
MAX_ERROR_MESSAGE_CHARS = 2000


@celery_app.task(name="codeaudit.ping")
def ping() -> str:
    """Trivial task for verifying broker/worker wiring."""
    return "pong"


def _set_status(scan_id: uuid.UUID, status: ScanStatus, error_message: str | None) -> None:
    """Record a status change in a fresh session (the pipeline's session may be broken)."""
    try:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = status
            scan.error_message = error_message[:MAX_ERROR_MESSAGE_CHARS] if error_message else None
            if status is ScanStatus.FAILED:
                scan.completed_at = utcnow()
            db.commit()
    except SQLAlchemyError:
        logger.exception("could not record status %s for scan %s", status, scan_id)


@celery_app.task(name="codeaudit.run_scan", bind=True, max_retries=settings.scan_max_retries)
def run_scan(self: Task, scan_id: str) -> dict[str, Any]:
    """Download, extract, analyze and persist one scan.

    Transient infrastructure errors are retried (max `scan_max_retries`). Every
    other failure marks the scan failed with a message. The workspace is always
    removed, and sandbox containers are removed by the sandbox runner itself.
    """
    scan_uuid = uuid.UUID(scan_id)
    workdir: Path | None = None
    try:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_uuid)
            if scan is None:
                logger.warning("scan %s no longer exists; skipping", scan_id)
                return {"scan_id": scan_id, "status": "missing"}
            if scan.status is ScanStatus.COMPLETED:
                # Redelivery after a worker restart (acks_late): nothing to do.
                return {"scan_id": scan_id, "status": scan.status.value}

            scan.status = ScanStatus.RUNNING
            scan.started_at = utcnow()
            scan.completed_at = None
            scan.error_message = None
            db.commit()

            workdir = create_workspace(scan_uuid)
            finding_count = run_pipeline(db, scan, workdir)

        logger.info("scan %s completed with %d findings", scan_id, finding_count)
        return {"scan_id": scan_id, "status": "completed", "findings": finding_count}

    except TRANSIENT_ERRORS as exc:
        attempt = self.request.retries
        if attempt < self.max_retries:
            delay = RETRY_BASE_DELAY_SECONDS * 3**attempt
            logger.warning(
                "scan %s: transient error (%s), retry %d/%d in %ds",
                scan_id,
                exc,
                attempt + 1,
                self.max_retries,
                delay,
            )
            _set_status(scan_uuid, ScanStatus.QUEUED, f"Retrying after a temporary error: {exc}")
            raise self.retry(exc=exc, countdown=delay) from exc
        logger.error("scan %s: giving up after %d retries: %s", scan_id, attempt, exc)
        _set_status(
            scan_uuid,
            ScanStatus.FAILED,
            f"Infrastructure error, gave up after {self.max_retries} retries: {exc}",
        )
        return {"scan_id": scan_id, "status": "failed"}

    except SoftTimeLimitExceeded:
        logger.warning("scan %s exceeded the task time limit", scan_id)
        _set_status(
            scan_uuid,
            ScanStatus.FAILED,
            f"Scan exceeded the {settings.scan_timeout_seconds}s time limit.",
        )
        return {"scan_id": scan_id, "status": "failed"}

    except AnalysisError as exc:
        logger.info("scan %s failed: %s", scan_id, exc)
        _set_status(scan_uuid, ScanStatus.FAILED, str(exc))
        return {"scan_id": scan_id, "status": "failed"}

    except Exception:
        logger.exception("scan %s crashed", scan_id)
        _set_status(scan_uuid, ScanStatus.FAILED, "Internal error while running the scan.")
        raise

    finally:
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)


@worker_ready.connect
def cleanup_after_crash(**_: Any) -> None:
    """Remove sandboxes and workspaces a previous crashed run of this worker left behind.

    `finally` blocks don't run when the process is killed (hard time limit, OOM).
    """
    try:
        removed = remove_orphaned_sandboxes()
        if removed:
            logger.warning("removed %d orphaned sandbox containers", removed)
    except SandboxUnavailableError as exc:
        logger.warning("skipping sandbox cleanup: %s", exc)
    stale = remove_stale_workspaces(max_age_seconds=settings.scan_timeout_seconds + 120)
    if stale:
        logger.warning("removed %d stale scan workspaces", stale)

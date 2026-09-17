import logging
import shutil
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import worker_ready
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy import update
from sqlalchemy.exc import InterfaceError, OperationalError, SQLAlchemyError

from app.config import get_settings
from app.core import metrics
from app.core.celery_app import celery_app
from app.core.db import SessionLocal
from app.core.errors import AnalysisError, TransientInfraError
from app.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    EnrichmentStatus,
    Finding,
    FixStatus,
    FixSuggestion,
    PullRequest,
    PullRequestStatus,
    Scan,
    ScanStatus,
    SiteAnalysis,
    SiteAnalysisStatus,
    User,
    ValidationStatus,
)
from app.services.analyzers.sandbox import SandboxUnavailableError, remove_orphaned_sandboxes
from app.services.github.client import GitHubError
from app.services.github.pr_builder import PullRequestError, create_pull_request_from_preview
from app.services.llm.client import LLMClient, LLMError, LLMUnavailableError
from app.services.llm.context import detect_conventions
from app.services.llm.enrichment import (
    finish_enrichment,
    llm_dispatch_block,
    run_enrichment,
    start_enrichment,
)
from app.services.llm.fix_suggester import regenerate_fix
from app.services.scan_pipeline import (
    create_workspace,
    extract_source,
    remove_stale_workspaces,
    run_pipeline,
    stage_timer,
    utcnow,
)
from app.services.web.analysis import run_site_analysis
from app.services.web.capture import CaptureError
from app.services.web.netguard import BlockedUrlError

logger = logging.getLogger(__name__)

settings = get_settings()

# Retried with backoff. Analysis failures (bad archive, every analyzer crashed or
# timed out) are deliberately not in this list: retrying them only burns resources.
# A single failing analyzer never reaches here; the scan is marked partial.
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
    if status in (ScanStatus.FAILED, ScanStatus.COMPLETED, ScanStatus.PARTIAL):
        metrics.scans_finished.labels(status.value).inc()
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
                # Analyzers still marked running will never report back.
                db.execute(
                    update(AnalyzerRun)
                    .where(
                        AnalyzerRun.scan_id == scan_id,
                        AnalyzerRun.status == AnalyzerRunStatus.RUNNING,
                    )
                    .values(
                        status=AnalyzerRunStatus.FAILED,
                        error_message="The scan stopped before this analyzer finished.",
                        completed_at=utcnow(),
                    )
                )
            db.commit()
    except SQLAlchemyError:
        logger.exception("could not record status %s for scan %s", status, scan_id)


@celery_app.task(name="codeaudit.run_scan", bind=True, max_retries=settings.scan_max_retries)
def run_scan(self: Task, scan_id: str) -> dict[str, Any]:
    """Download, extract, analyze and persist one scan.

    Analyzers run concurrently and fail independently (the scan is then `partial`).
    Transient infrastructure errors that stop the whole scan are retried (max
    `scan_max_retries`). Every other failure marks the scan failed with a message.
    The workspace is always removed, and sandbox containers are removed by the
    sandbox runner itself.
    """
    scan_uuid = uuid.UUID(scan_id)
    workdir: Path | None = None
    try:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_uuid)
            if scan is None:
                logger.warning("scan %s no longer exists; skipping", scan_id)
                return {"scan_id": scan_id, "status": "missing"}
            if scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.ENRICHING):
                # Redelivery after a worker restart (acks_late): nothing to do.
                return {"scan_id": scan_id, "status": scan.status.value}
            if scan.status is ScanStatus.ANALYSIS_COMPLETE:
                # Analysis finished but the enrichment task may never have been queued.
                _queue_enrichment(scan_uuid)
                return {"scan_id": scan_id, "status": scan.status.value}

            # Claim the scan atomically: a second delivery of the same task (redelivery
            # while the first run is still going) must not analyze it concurrently.
            claimable = (Scan.status.in_([ScanStatus.QUEUED, ScanStatus.FAILED])) | (
                (Scan.status == ScanStatus.RUNNING)
                & (
                    Scan.started_at
                    < utcnow() - timedelta(seconds=settings.scan_timeout_seconds + 60)
                )
            )
            claimed = db.execute(
                update(Scan)
                .where(Scan.id == scan_uuid, claimable)
                .values(
                    status=ScanStatus.RUNNING,
                    started_at=utcnow(),
                    completed_at=None,
                    error_message=None,
                )
            )
            db.commit()
            if not getattr(claimed, "rowcount", 0):
                logger.warning(
                    "scan %s is already being processed; skipping duplicate delivery", scan_id
                )
                return {"scan_id": scan_id, "status": "duplicate_delivery"}
            db.refresh(scan)

            workdir = create_workspace(scan_uuid)
            with stage_timer("total"):
                outcome = run_pipeline(db, scan, workdir)
            metrics.scans_finished.labels(outcome.status.value).inc()
            # run_pipeline changed the status; re-read it untyped by the earlier narrowing.
            final_status: ScanStatus = getattr(scan, "status")  # noqa: B009
            enrich = final_status is ScanStatus.ANALYSIS_COMPLETE

        if enrich:
            # Queued only after the analysis is committed; never blocks the scan.
            _queue_enrichment(scan_uuid)

        return {
            "scan_id": scan_id,
            "status": outcome.status.value,
            "findings": outcome.findings_after_dedup,
            "findings_before_dedup": outcome.findings_before_dedup,
            "analyzers": {
                r.analyzer: "ok" if r.success else ("timed_out" if r.timed_out else "failed")
                for r in outcome.results
            },
        }

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


def _queue_enrichment(scan_id: uuid.UUID) -> None:
    try:
        enrich_scan.delay(str(scan_id))
    except BrokerError as exc:
        logger.error("could not queue enrichment for scan %s: %s", scan_id, exc)
        with SessionLocal() as db:
            finish_enrichment(
                db, scan_id, EnrichmentStatus.FAILED, "Could not queue the enrichment job."
            )


@celery_app.task(
    name="codeaudit.enrich_scan",
    soft_time_limit=settings.llm_task_timeout_seconds,
    time_limit=settings.llm_task_timeout_seconds + 60,
)
def enrich_scan(scan_id: str) -> dict[str, Any]:
    """LLM stage: fix suggestions and architecture review. Never fails the scan.

    Not retried: a failure leaves the scan complete without (some) suggestions.
    """
    scan_uuid = uuid.UUID(scan_id)
    workdir: Path | None = None
    status = EnrichmentStatus.FAILED
    message: str | None = "Internal error during enrichment."
    claimed = False
    with SessionLocal() as db:
        try:
            scan = db.get(Scan, scan_uuid)
            if scan is None or not start_enrichment(db, scan):
                # A duplicate or late delivery: leave the finished result alone.
                return {"scan_id": scan_id, "status": "skipped"}
            claimed = True
            if blocked := llm_dispatch_block(db, scan):
                status, message = EnrichmentStatus.SKIPPED, blocked
                logger.info("scan %s: LLM stage skipped: %s", scan_id, blocked)
                return {"scan_id": scan_id, "enrichment": status.value, "message": message}
            llm = LLMClient()
            workdir = create_workspace(scan_uuid)
            source_dir = extract_source(db, scan, workdir)
            with stage_timer("enrichment"):
                outcome = run_enrichment(db, scan, source_dir, llm)
            status = outcome.status
            message = " ".join(outcome.problems) or None
            logger.info("scan %s enrichment %s: %s", scan_id, status.value, outcome.fixes)
        except LLMUnavailableError as exc:
            status, message = EnrichmentStatus.SKIPPED, str(exc)
        except SoftTimeLimitExceeded:
            message = f"Enrichment exceeded the {settings.llm_task_timeout_seconds}s time limit."
            logger.warning("scan %s: %s", scan_id, message)
        except (AnalysisError, TransientInfraError, LLMError) as exc:
            message = f"Enrichment failed: {exc}"
            logger.warning("scan %s: %s", scan_id, message)
        except Exception:
            logger.exception("scan %s: enrichment crashed", scan_id)
        finally:
            try:
                if claimed:
                    finish_enrichment(db, scan_uuid, status, message)
            except SQLAlchemyError:
                logger.exception("could not finish enrichment for scan %s", scan_id)
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)
    return {"scan_id": scan_id, "enrichment": status.value, "message": message}


@celery_app.task(
    name="codeaudit.regenerate_fix",
    soft_time_limit=settings.llm_task_timeout_seconds,
    time_limit=settings.llm_task_timeout_seconds + 60,
)
def regenerate_fix_task(
    scan_id: str, finding_id: int, user_hint: str | None = None
) -> dict[str, Any]:
    """Regenerate one finding's suggestion (optionally guided by a reviewer hint)."""
    scan_uuid = uuid.UUID(scan_id)
    workdir: Path | None = None
    with SessionLocal() as db:
        try:
            scan = db.get(Scan, scan_uuid)
            finding = db.get(Finding, finding_id)
            if scan is None or finding is None or finding.scan_id != scan_uuid:
                return {"status": "missing"}
            llm = LLMClient()
            workdir = create_workspace(scan_uuid)
            source_dir = extract_source(db, scan, workdir)
            languages = [lang["language"] for lang in scan.detected_languages or []]
            stats = regenerate_fix(
                db,
                scan_uuid,
                finding,
                source_dir,
                detect_conventions(source_dir, languages),
                llm,
                user_hint,
            )
            return {"status": "done", "validation": stats.by_validation, "errors": stats.errors}
        except Exception as exc:
            logger.warning("scan %s finding %s: regeneration failed: %s", scan_id, finding_id, exc)
            db.rollback()
            suggestion = db.query(FixSuggestion).filter_by(finding_id=finding_id).one_or_none()
            if suggestion is not None and suggestion.status is FixStatus.GENERATING:
                suggestion.status = FixStatus.FAILED
                suggestion.validation_status = ValidationStatus.NOT_VALIDATED
                suggestion.error_message = f"Regeneration failed: {exc}"[:2000]
                db.commit()
            if not isinstance(
                exc, (AnalysisError, TransientInfraError, LLMError, SoftTimeLimitExceeded)
            ):
                raise
            return {"status": "failed", "error": str(exc)}
        finally:
            # Budget errors are stored on the suggestion by regenerate_fix itself.
            db.rollback()
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)


@celery_app.task(name="codeaudit.create_pull_request", soft_time_limit=300, time_limit=360)
def create_pull_request_task(pr_id: int) -> dict[str, Any]:
    """Write a confirmed pull request to GitHub. Only queued by the confirm endpoint.

    Never retried: GitHub writes are not idempotent, and a retry could push twice.
    """
    with SessionLocal() as db:
        row = db.get(PullRequest, pr_id)
        if row is None or row.status is not PullRequestStatus.CREATING or row.confirmed_at is None:
            return {"pull_request": pr_id, "status": "skipped"}
        scan, user = db.get(Scan, row.scan_id), db.get(User, row.user_id)
        code, message = "internal_error", "Internal error while creating the pull request."
        try:
            if scan is None or user is None or scan.user_id != user.id:
                code, message = "not_found", "The scan or its owner no longer exists."
            else:
                create_pull_request_from_preview(db, row, scan, user)
                return {"pull_request": pr_id, "status": "open", "url": row.pr_url}
        except PullRequestError as exc:
            code, message = exc.code, exc.message
        except GitHubError as exc:
            code, message = exc.code, exc.message
        except SoftTimeLimitExceeded:
            code, message = "timeout", "Creating the pull request took too long."
        except Exception:
            logger.exception("pull request %s: creation crashed", pr_id)
        db.rollback()
        row = db.get(PullRequest, pr_id)
        if row is not None:
            row.status = PullRequestStatus.FAILED
            row.error_code = code
            row.error_message = message[:MAX_ERROR_MESSAGE_CHARS]
            db.commit()
        logger.info("pull request %s failed: %s", pr_id, code)
        return {"pull_request": pr_id, "status": "failed", "error": code}


@celery_app.task(
    name="codeaudit.analyze_site",
    soft_time_limit=settings.web_capture_timeout_seconds + 240,
    time_limit=settings.web_capture_timeout_seconds + 300,
)
def analyze_site_task(analysis_id: str) -> dict[str, Any]:
    """Capture a website and assess phishing risk / extract design tokens. Not retried:
    a second fetch of a phishing page is not worth the extra exposure."""
    analysis_uuid = uuid.UUID(analysis_id)
    with SessionLocal() as db:
        analysis = db.get(SiteAnalysis, analysis_uuid)
        if analysis is None or analysis.status is not SiteAnalysisStatus.QUEUED:
            return {"analysis": analysis_id, "status": "skipped"}
        try:
            llm: LLMClient | None = LLMClient()
        except LLMUnavailableError:
            llm = None
        message: str | None = None
        try:
            with stage_timer("site_analysis"):
                run_site_analysis(db, analysis, llm=llm)
            metrics.site_analyses_finished.labels("completed").inc()
            return {"analysis": analysis_id, "status": "completed", "risk": analysis.risk_score}
        except BlockedUrlError as exc:
            message = f"Blocked for safety: {exc.reason}"
        except CaptureError as exc:
            message = str(exc)
        except SandboxUnavailableError as exc:
            message = f"The browser sandbox is unavailable: {exc}"
        except SoftTimeLimitExceeded:
            message = "The analysis took too long and was stopped."
        except Exception:
            logger.exception("site analysis %s crashed", analysis_id)
            message = "Internal error while analyzing the site."
        db.rollback()
        analysis = db.get(SiteAnalysis, analysis_uuid)
        if analysis is not None:
            analysis.status = SiteAnalysisStatus.FAILED
            analysis.stage = None
            analysis.error_message = message[:MAX_ERROR_MESSAGE_CHARS]
            metrics.site_analyses_finished.labels("failed").inc()
            analysis.completed_at = utcnow()
            db.commit()
        return {"analysis": analysis_id, "status": "failed", "error": message}


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
    try:
        from app.workers.maintenance import reap_stale_jobs_once

        reap_stale_jobs_once()
    except SQLAlchemyError as exc:
        logger.warning("skipping stale job cleanup: %s", exc)

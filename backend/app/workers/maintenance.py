"""Periodic maintenance (Celery beat): reapers, retention, spend alerts.

- reap_stale_jobs: scans, enrichments, site analyses and pull requests stuck past their
  maximum runtime are marked failed with a clear reason, never left `running` forever.
- reap_orphaned_sandboxes: sandbox containers older than the longest allowed run are
  removed, whichever worker started them.
- purge_llm_transcripts: prompt/response text (which contains user code) is deleted
  from llm_calls after the retention period; token and cost accounting is kept.
- check_spend_alerts: fires the daily spend alerts even when no call just finished.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import update

from app.config import get_settings
from app.core import metrics
from app.core.celery_app import celery_app
from app.core.db import SessionLocal
from app.models import (
    EnrichmentStatus,
    LLMCall,
    PullRequest,
    PullRequestStatus,
    Scan,
    ScanStatus,
    SiteAnalysis,
    SiteAnalysisStatus,
)
from app.services import costs
from app.services.analyzers.sandbox import SandboxUnavailableError, reap_expired_sandboxes
from app.services.llm.enrichment import finish_enrichment

logger = logging.getLogger(__name__)

# A queued job that no worker picked up for this long has lost its message.
MAX_QUEUED = timedelta(hours=6)


def _now() -> datetime:
    return datetime.now(UTC)


def reap_stale_jobs_once() -> dict[str, int]:
    settings = get_settings()
    grace = timedelta(seconds=settings.stale_job_grace_seconds)
    scan_deadline = _now() - timedelta(seconds=settings.scan_timeout_seconds + 60) - grace
    enrich_deadline = _now() - timedelta(seconds=settings.llm_task_timeout_seconds + 60) - grace
    site_deadline = _now() - timedelta(seconds=settings.web_capture_timeout_seconds + 300) - grace
    reaped: dict[str, int] = {}
    with SessionLocal() as db:

        def mark(kind: str, statement: Any) -> None:
            count = int(getattr(db.execute(statement), "rowcount", 0) or 0)
            if count:
                reaped[kind] = reaped.get(kind, 0) + count
                metrics.tasks_reaped.labels(kind).inc(count)

        mark(
            "scan_running",
            update(Scan)
            .where(Scan.status == ScanStatus.RUNNING, Scan.started_at < scan_deadline)
            .values(
                status=ScanStatus.FAILED,
                completed_at=_now(),
                error_message=(
                    f"The scan did not finish within {settings.scan_timeout_seconds}s (the worker"
                    " stopped or the task was lost). Start a new scan."
                ),
            ),
        )
        mark(
            "scan_queued",
            update(Scan)
            .where(Scan.status == ScanStatus.QUEUED, Scan.created_at < _now() - MAX_QUEUED)
            .values(
                status=ScanStatus.FAILED,
                completed_at=_now(),
                error_message="The scan was never picked up by a worker. Start a new scan.",
            ),
        )
        stuck_enrichment = (
            db.query(Scan.id)
            .filter(
                Scan.status.in_([ScanStatus.ENRICHING, ScanStatus.ANALYSIS_COMPLETE]),
                Scan.completed_at < enrich_deadline,
            )
            .all()
        )
        db.commit()
        for (scan_id,) in stuck_enrichment:
            # Analysis results stay; only the LLM stage is closed out.
            finish_enrichment(
                db,
                scan_id,
                EnrichmentStatus.FAILED,
                "Fix suggestions did not finish in time (the worker stopped).",
            )
            reaped["enrichment"] = reaped.get("enrichment", 0) + 1
            metrics.tasks_reaped.labels("enrichment").inc()
        mark(
            "site_analysis",
            update(SiteAnalysis)
            .where(
                (
                    (SiteAnalysis.status == SiteAnalysisStatus.RUNNING)
                    & (SiteAnalysis.started_at < site_deadline)
                )
                | (
                    (SiteAnalysis.status == SiteAnalysisStatus.QUEUED)
                    & (SiteAnalysis.created_at < _now() - timedelta(hours=1))
                )
            )
            .values(
                status=SiteAnalysisStatus.FAILED,
                stage=None,
                completed_at=_now(),
                error_message="The analysis did not finish in time (the worker stopped).",
            ),
        )
        mark(
            "pull_request",
            update(PullRequest)
            .where(
                PullRequest.status == PullRequestStatus.CREATING,
                PullRequest.confirmed_at < _now() - timedelta(minutes=15),
            )
            .values(
                status=PullRequestStatus.FAILED,
                error_code="interrupted",
                error_message=(
                    "The worker stopped while creating this pull request. Check the repository"
                    " for a partially created branch before trying again."
                ),
            ),
        )
        db.commit()
    if reaped:
        logger.warning("reaped stale jobs: %s", reaped)
    return reaped


@celery_app.task(name="codeaudit.reap_stale_jobs", ignore_result=True)
def reap_stale_jobs() -> dict[str, int]:
    return reap_stale_jobs_once()


@celery_app.task(name="codeaudit.reap_orphaned_sandboxes", ignore_result=True)
def reap_orphaned_sandboxes() -> int:
    try:
        return reap_expired_sandboxes()
    except SandboxUnavailableError as exc:
        logger.warning("sandbox reaper skipped: %s", exc)
        return 0


@celery_app.task(name="codeaudit.purge_llm_transcripts", ignore_result=True)
def purge_llm_transcripts() -> int:
    cutoff = _now() - timedelta(days=get_settings().llm_transcript_retention_days)
    with SessionLocal() as db:
        result = db.execute(
            update(LLMCall)
            .where(
                LLMCall.created_at < cutoff,
                (LLMCall.prompt.is_not(None)) | (LLMCall.response_text.is_not(None)),
            )
            .values(prompt=None, response_text=None)
        )
        db.commit()
    count = int(getattr(result, "rowcount", 0) or 0)
    if count:
        logger.info("purged transcripts of %d LLM calls older than %s", count, cutoff.date())
    return count


@celery_app.task(name="codeaudit.check_spend_alerts", ignore_result=True)
def check_spend_alerts() -> None:
    with SessionLocal() as db:
        costs.check_spend_alerts(db)

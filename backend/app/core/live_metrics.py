"""Gauges refreshed at scrape time: queue depth, jobs by status, today's LLM spend."""

from typing import cast

from redis import Redis
from sqlalchemy import func, select

from app.config import get_settings
from app.core import metrics
from app.core.db import SessionLocal

QUEUES = ("celery",)


def _queue_depth() -> None:
    broker = Redis.from_url(get_settings().celery_broker_url, socket_timeout=2)
    try:
        for queue in QUEUES:
            metrics.queue_depth.labels(queue).set(cast(int, broker.llen(queue)))
    finally:
        broker.close()


def _jobs_and_spend() -> None:
    from app.models import Scan, ScanStatus, SiteAnalysis, SiteAnalysisStatus
    from app.services.costs import spend_today

    with SessionLocal() as db:
        scan_rows = db.execute(select(Scan.status, func.count()).group_by(Scan.status)).all()
        scan_counts: dict[ScanStatus, int] = {row[0]: int(row[1]) for row in scan_rows}
        for status in ScanStatus:
            metrics.jobs_by_status.labels("scan", status.value).set(scan_counts.get(status, 0))
        site_rows = db.execute(
            select(SiteAnalysis.status, func.count()).group_by(SiteAnalysis.status)
        ).all()
        site_counts: dict[SiteAnalysisStatus, int] = {row[0]: int(row[1]) for row in site_rows}
        for site_status in SiteAnalysisStatus:
            metrics.jobs_by_status.labels("site_analysis", site_status.value).set(
                site_counts.get(site_status, 0)
            )
        metrics.llm_spend_today.set(spend_today(db))
    metrics.llm_daily_cap.set(get_settings().llm_daily_spend_cap_usd)


def register_api_collectors() -> None:
    metrics.register_live_collector(_queue_depth)
    metrics.register_live_collector(_jobs_and_spend)

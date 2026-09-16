from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "codeaudit",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Scans are long-running: only ack once finished, fetch one job at a time.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.scan_timeout_seconds,
    task_time_limit=settings.scan_timeout_seconds + 60,
    broker_connection_retry_on_startup=True,
    # Tests run the pipeline inline. Failures are persisted on the Scan row,
    # so they don't need to propagate into the caller.
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=False,
)

import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from celery import Celery, signals
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

celery_app = Celery(
    "codeaudit",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks", "app.workers.maintenance"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Scans are long-running: only ack once finished, fetch one job at a time. A task
    # whose worker dies (OOM, SIGKILL, deploy) goes back to the queue instead of vanishing.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Redis visibility timeout must exceed the longest task, or unacked tasks are redelivered
    # while still running.
    broker_transport_options={"visibility_timeout": settings.scan_timeout_seconds * 2 + 600},
    worker_cancel_long_running_tasks_on_connection_loss=True,
    task_soft_time_limit=settings.scan_timeout_seconds,
    task_time_limit=settings.scan_timeout_seconds + 60,
    broker_connection_retry_on_startup=True,
    result_expires=86_400,
    # Tests run the pipeline inline. Failures are persisted on the Scan row,
    # so they don't need to propagate into the caller.
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=False,
    beat_schedule={
        "reap-stale-jobs": {"task": "codeaudit.reap_stale_jobs", "schedule": 300.0},
        "reap-orphaned-sandboxes": {"task": "codeaudit.reap_orphaned_sandboxes", "schedule": 300.0},
        "purge-llm-transcripts": {
            "task": "codeaudit.purge_llm_transcripts",
            "schedule": crontab(hour=3, minute=17),
        },
        "check-spend-alerts": {"task": "codeaudit.check_spend_alerts", "schedule": 600.0},
    },
)

DEAD_LETTER_KEY = "codeaudit:dead_letters"
DEAD_LETTER_MAX = 500
HEARTBEAT_PREFIX = "codeaudit:worker:heartbeat:"
HEARTBEAT_INTERVAL_SECONDS = 20
CORRELATION_HEADER = "correlation_id"
SCAN_TASKS = {"codeaudit.run_scan", "codeaudit.enrich_scan", "codeaudit.regenerate_fix"}
SITE_TASKS = {"codeaudit.analyze_site"}

_context_tokens: dict[str, list[Any]] = {}


@signals.setup_logging.connect
def _setup_logging(**_: Any) -> None:
    # Our JSON logging, not Celery's default handler.
    from app.core.observability import configure_logging

    configure_logging()


@signals.worker_init.connect
def _reset_metrics(**_: Any) -> None:
    # Main process, before the pool forks: drop samples from the previous run.
    from app.core import metrics

    metrics.reset_multiprocess_dir()


@signals.worker_process_init.connect
def _init_process(**_: Any) -> None:
    from app.core.observability import init_sentry

    init_sentry("worker")


@signals.before_task_publish.connect
def _attach_correlation_id(headers: dict[str, Any] | None = None, **_: Any) -> None:
    from app.core.observability import request_id_var

    if headers is not None and CORRELATION_HEADER not in headers:
        headers[CORRELATION_HEADER] = request_id_var.get() or uuid.uuid4().hex


@signals.task_prerun.connect
def _bind_task_context(
    task_id: str | None = None, task: Any = None, args: tuple[Any, ...] = (), **_: Any
) -> None:
    from app.core.observability import CONTEXT_VARS

    request = getattr(task, "request", None)
    correlation = getattr(request, CORRELATION_HEADER, None) or (
        (getattr(request, "headers", None) or {}).get(CORRELATION_HEADER) if request else None
    )
    values: dict[str, str | None] = {"request_id": correlation, "task_id": task_id}
    name = getattr(task, "name", "")
    if args and isinstance(args[0], str):
        if name in SCAN_TASKS:
            values["scan_id"] = args[0]
        elif name in SITE_TASKS:
            values["site_analysis_id"] = args[0]
    if task_id:
        _context_tokens[task_id] = [
            (CONTEXT_VARS[k], CONTEXT_VARS[k].set(v)) for k, v in values.items()
        ]


@signals.task_postrun.connect
def _unbind_task_context(task_id: str | None = None, **_: Any) -> None:
    for var, token in reversed(_context_tokens.pop(task_id or "", [])):
        try:
            var.reset(token)
        except ValueError:
            pass


@signals.task_failure.connect
def _dead_letter(
    sender: Any = None,
    task_id: str | None = None,
    exception: BaseException | None = None,
    args: tuple[Any, ...] = (),
    **_: Any,
) -> None:
    """Tasks that failed for good (retries exhausted or not retryable) are recorded for
    operators. The domain row (scan, site analysis, PR) is already marked failed by the
    task itself; this keeps the operational trail."""
    from app.core.observability import scrub
    from app.core.redis_client import get_redis

    entry = {
        "task": getattr(sender, "name", None),
        "task_id": task_id,
        "args": [str(a)[:100] for a in args][:3],
        "error": scrub(f"{type(exception).__name__}: {exception}")[:500] if exception else None,
        "failed_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    try:
        redis = get_redis()
        redis.lpush(DEAD_LETTER_KEY, json.dumps(entry))
        redis.ltrim(DEAD_LETTER_KEY, 0, DEAD_LETTER_MAX - 1)
    except Exception:  # noqa: BLE001 - never mask the original failure
        logger.warning("could not record dead letter for %s", task_id)
    logger.error("task %s failed permanently", entry["task"], extra={"dead_letter": entry})


@signals.worker_process_shutdown.connect
def _process_shutdown(pid: int | None = None, **_: Any) -> None:
    from app.core import metrics

    metrics.mark_process_dead(pid or os.getpid())


def _heartbeat_loop(hostname: str) -> None:
    from app.core.redis_client import get_redis
    from app.services.analyzers.sandbox import SANDBOX_LABEL, SandboxUnavailableError, _client

    while True:
        beat: dict[str, Any] = {"hostname": hostname, "at": time.time(), "pid": os.getpid()}
        try:
            client = _client()
            try:
                beat["docker"] = "ok"
                beat["sandboxes_running"] = len(
                    client.containers.list(filters={"label": SANDBOX_LABEL})
                )
            finally:
                client.close()
        except SandboxUnavailableError:
            beat["docker"] = "error"
        except Exception:  # noqa: BLE001
            beat["docker"] = "error"
        try:
            get_redis().set(
                f"{HEARTBEAT_PREFIX}{hostname}", json.dumps(beat), ex=HEARTBEAT_INTERVAL_SECONDS * 4
            )
        except Exception:  # noqa: BLE001, S110 - retried next interval
            pass
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


@signals.worker_ready.connect
def _start_heartbeat(sender: Any = None, **_: Any) -> None:
    hostname = getattr(sender, "hostname", None) or socket.gethostname()
    port = settings.worker_metrics_port
    if port and not settings.celery_task_always_eager:
        from app.core import metrics

        try:
            metrics.serve_worker_metrics(port)
            logger.info("worker metrics on :%d/metrics", port)
        except OSError as exc:
            logger.warning("worker metrics endpoint not started: %s", exc)
    threading.Thread(
        target=_heartbeat_loop, args=(hostname,), daemon=True, name="worker-heartbeat"
    ).start()


@signals.worker_shutting_down.connect
def _shutting_down(sig: str | None = None, how: str | None = None, **_: Any) -> None:
    # Warm shutdown (SIGTERM): no new tasks; running tasks finish within the platform's
    # stop grace period. Anything killed mid-run is redelivered (acks_late) and resumes
    # idempotently; a scan that can't be resumed is failed by the stale-job reaper.
    logger.warning("worker shutting down (%s, %s): finishing in-flight tasks", sig, how)

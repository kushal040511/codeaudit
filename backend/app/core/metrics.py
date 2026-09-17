"""Prometheus metrics shared by the API and the Celery worker.

With PROMETHEUS_MULTIPROC_DIR set, every process of one container (uvicorn workers,
Celery prefork children) writes to a shared directory and one endpoint aggregates
them: `/metrics` on the API, and a small HTTP server on WORKER_METRICS_PORT in the
Celery main process (the worker usually runs on a different host from the API). Label values
are bounded (route templates, analyzer names, fixed status sets): never user input.
"""

import os
from collections.abc import Callable
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client import multiprocess as prometheus_multiprocess

DURATION_BUCKETS = (0.5, 1, 2.5, 5, 10, 20, 30, 60, 120, 300, 600, 900, 1800)
HTTP_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)

http_requests = Counter(
    "codeaudit_http_requests_total",
    "HTTP responses by route and status.",
    ["method", "route", "status"],
)
http_duration = Histogram(
    "codeaudit_http_request_duration_seconds",
    "HTTP request latency.",
    ["method", "route"],
    buckets=HTTP_BUCKETS,
)
scan_stage_duration = Histogram(
    "codeaudit_scan_stage_duration_seconds",
    "Duration of each scan stage (extract, analyzers, persist, enrichment, total).",
    ["stage", "outcome"],
    buckets=DURATION_BUCKETS,
)
scans_finished = Counter(
    "codeaudit_scans_finished_total", "Scans reaching a final state.", ["status"]
)
analyzer_runs = Counter(
    "codeaudit_analyzer_runs_total", "Analyzer runs by outcome.", ["analyzer", "status"]
)
analyzer_duration = Histogram(
    "codeaudit_analyzer_duration_seconds",
    "Analyzer run duration.",
    ["analyzer"],
    buckets=DURATION_BUCKETS,
)
sandbox_containers_active = Gauge(
    "codeaudit_sandbox_containers_active",
    "Sandbox containers currently running (per process).",
    multiprocess_mode="livesum",
)
sandbox_slot_wait = Histogram(
    "codeaudit_sandbox_slot_wait_seconds",
    "Time spent waiting for a global sandbox slot.",
    buckets=(0.01, 0.1, 0.5, 1, 5, 15, 30, 60, 120, 300),
)
sandbox_reaped = Counter(
    "codeaudit_sandbox_containers_reaped_total", "Orphaned containers removed."
)
llm_requests = Counter(
    "codeaudit_llm_requests_total", "LLM calls by purpose and outcome.", ["purpose", "outcome"]
)
llm_latency = Histogram(
    "codeaudit_llm_request_duration_seconds",
    "LLM call latency including retries.",
    ["purpose"],
    buckets=(0.5, 1, 2.5, 5, 10, 20, 40, 60, 120, 240),
)
llm_tokens = Counter("codeaudit_llm_tokens_total", "LLM tokens.", ["purpose", "kind"])
llm_cost = Counter("codeaudit_llm_cost_usd_total", "Estimated LLM spend in USD.", ["purpose"])
patch_validations = Counter(
    "codeaudit_patch_validations_total", "Generated patch validation results.", ["result"]
)
quota_rejections = Counter(
    "codeaudit_quota_rejections_total", "Requests or tasks refused by a limit.", ["limit", "stage"]
)
tasks_reaped = Counter(
    "codeaudit_stale_jobs_reaped_total", "Stuck jobs marked failed by the reaper.", ["kind"]
)
site_analyses_finished = Counter(
    "codeaudit_site_analyses_finished_total", "Site analyses reaching a final state.", ["status"]
)

# Collected at scrape time from Redis/Postgres (see register_live_collectors).
queue_depth = Gauge(
    "codeaudit_queue_depth",
    "Messages waiting in a Celery queue.",
    ["queue"],
    multiprocess_mode="liveall",
)
jobs_by_status = Gauge(
    "codeaudit_jobs_by_status",
    "Scans and site analyses by current status.",
    ["kind", "status"],
    multiprocess_mode="liveall",
)
llm_spend_today = Gauge(
    "codeaudit_llm_spend_today_usd", "LLM spend so far today (UTC).", multiprocess_mode="liveall"
)
llm_daily_cap = Gauge(
    "codeaudit_llm_daily_cap_usd", "Configured daily LLM spend cap.", multiprocess_mode="liveall"
)

_live_collectors: list[Callable[[], None]] = []


def register_live_collector(collector: Callable[[], None]) -> None:
    _live_collectors.append(collector)


def render() -> tuple[bytes, str]:
    for collector in _live_collectors:
        try:
            collector()
        except Exception:  # noqa: BLE001, S110 - a failing gauge must not break /metrics
            pass
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        prometheus_multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
        return generate_latest(registry), CONTENT_TYPE_LATEST
    from prometheus_client import REGISTRY

    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def reset_multiprocess_dir() -> None:
    """Remove the previous run's samples. Call once per container start, before forking."""
    directory = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not directory:
        return
    os.makedirs(directory, exist_ok=True)
    for name in os.listdir(directory):
        if name.endswith(".db"):
            try:
                os.remove(os.path.join(directory, name))
            except OSError:
                pass


def serve_worker_metrics(port: int, addr: str = "0.0.0.0") -> None:  # noqa: S104
    """Expose this container's aggregated metrics over HTTP (Celery main process)."""
    from prometheus_client import start_http_server

    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        prometheus_multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
        start_http_server(port, addr=addr, registry=registry)
    else:
        start_http_server(port, addr=addr)


def mark_process_dead(pid: int) -> None:
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        prometheus_multiprocess.mark_process_dead(pid)  # type: ignore[no-untyped-call]


def observe(histogram: Any, *labels: str) -> Any:
    return histogram.labels(*labels).time() if labels else histogram.time()

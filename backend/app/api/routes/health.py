"""Liveness, readiness and Prometheus metrics.

- `/health`: liveness. The process is up and serving; no dependency checks, so a slow
  database never gets a healthy API container restarted.
- `/ready`: readiness. Database, Redis, object storage, and at least one worker that
  reached the Docker daemon recently (workers publish a heartbeat; the API itself has
  no Docker access). 503 when any is down.
- `/metrics`: Prometheus exposition (optionally bearer-token protected).
"""

import json
import logging
import time
from collections.abc import Callable
from typing import cast

from fastapi import APIRouter, Request, Response, status

from app import __version__
from app.config import get_settings
from app.core import metrics
from app.core.db import check_database
from app.core.redis_client import check_redis, get_redis
from app.core.storage import check_storage
from app.schemas.health import ComponentCheck, HealthResponse, LivenessResponse
from app.services.auth.crypto import secrets_equal

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

WORKER_HEARTBEAT_PREFIX = "codeaudit:worker:heartbeat:"
WORKER_HEARTBEAT_MAX_AGE_SECONDS = 90


def _run_check(name: str, check: Callable[[], None]) -> ComponentCheck:
    start = time.perf_counter()
    try:
        check()
    except Exception as exc:
        logger.warning("readiness check %s failed: %s", name, type(exc).__name__)
        # Only expose the exception type; messages can leak hostnames/DSNs.
        return ComponentCheck(status="error", detail=type(exc).__name__)
    return ComponentCheck(status="ok", latency_ms=round((time.perf_counter() - start) * 1000, 2))


def check_workers() -> None:
    """Raise unless a worker reported a reachable Docker daemon within the last 90s."""
    redis = get_redis()
    now = time.time()
    fresh = []
    for key in redis.scan_iter(f"{WORKER_HEARTBEAT_PREFIX}*", count=100):
        raw = cast(bytes | None, redis.get(key))
        if not raw:
            continue
        beat = json.loads(raw)
        if now - float(beat.get("at", 0)) <= WORKER_HEARTBEAT_MAX_AGE_SECONDS:
            fresh.append(beat)
    if not fresh:
        raise RuntimeError("NoWorkerHeartbeat")
    if not any(beat.get("docker") == "ok" for beat in fresh):
        raise RuntimeError("DockerUnreachable")


@router.get("/health", response_model=LivenessResponse)
def health() -> LivenessResponse:
    """Liveness: the API process is running."""
    return LivenessResponse(status="ok", version=__version__)


@router.get(
    "/ready",
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
def ready(response: Response) -> HealthResponse:
    """Readiness: database, Redis, object storage and a worker with Docker reachable."""
    checks = {
        "database": _run_check("database", check_database),
        "redis": _run_check("redis", check_redis),
        "storage": _run_check("storage", check_storage),
        "workers": _run_check("workers", check_workers),
    }
    healthy = all(c.status == "ok" for c in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if healthy else "unavailable", version=__version__, checks=checks
    )


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request) -> Response:
    token = get_settings().metrics_token
    if token is not None and token.get_secret_value():
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not supplied or not secrets_equal(supplied, token.get_secret_value()):
            return Response("unauthorized\n", status_code=401, media_type="text/plain")
    body, content_type = metrics.render()
    return Response(body, media_type=content_type)

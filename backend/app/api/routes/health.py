import logging
import time
from collections.abc import Callable

from fastapi import APIRouter, Response, status

from app import __version__
from app.core.db import check_database
from app.core.redis_client import check_redis
from app.schemas.health import ComponentCheck, HealthResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


def _run_check(name: str, check: Callable[[], None]) -> ComponentCheck:
    start = time.perf_counter()
    try:
        check()
    except Exception as exc:
        logger.warning("health check %s failed: %s", name, exc)
        # Only expose the exception type; messages can leak hostnames/DSNs.
        return ComponentCheck(status="error", detail=type(exc).__name__)
    return ComponentCheck(status="ok", latency_ms=round((time.perf_counter() - start) * 1000, 2))


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
def health(response: Response) -> HealthResponse:
    """Liveness + dependency check. Returns 503 if the database or Redis is down."""
    checks = {
        "database": _run_check("database", check_database),
        "redis": _run_check("redis", check_redis),
    }
    healthy = all(c.status == "ok" for c in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if healthy else "unavailable",
        version=__version__,
        checks=checks,
    )

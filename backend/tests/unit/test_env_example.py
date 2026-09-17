"""`.env.example` documents every setting, and nothing that no longer exists."""

import re
from pathlib import Path

from app.config import Settings

ENV_EXAMPLE = Path(__file__).parents[3] / ".env.example"
# Read by docker compose, not by the application.
COMPOSE_ONLY = {
    "API_HOST_PORT",
    "CELERY_CONCURRENCY",
    "DOCKER_SOCKET_GID",
    "MINIO_API_HOST_PORT",
    "MINIO_CONSOLE_HOST_PORT",
    "MINIO_IMAGE",
    "MINIO_ROOT_PASSWORD",
    "MINIO_ROOT_USER",
    "POSTGRES_DB",
    "POSTGRES_HOST_PORT",
    "POSTGRES_PASSWORD",
    "POSTGRES_USER",
    "REDIS_HOST_PORT",
    "WORKER_METRICS_HOST_PORT",
}


def test_env_example_matches_settings() -> None:
    documented = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", ENV_EXAMPLE.read_text(), re.M))
    fields = {name.upper() for name in Settings.model_fields}
    assert sorted(fields - documented) == []
    assert sorted(documented - fields - COMPOSE_ONLY) == []

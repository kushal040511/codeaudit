import json
import time

import pytest
from fastapi.testclient import TestClient

from app.api.routes import health as health_routes
from app.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def all_up(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("check_database", "check_redis", "check_storage", "check_workers"):
        monkeypatch.setattr(health_routes, name, lambda: None)


def test_liveness_has_no_dependency_checks(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode() -> None:
        raise AssertionError("liveness must not touch dependencies")

    monkeypatch.setattr(health_routes, "check_database", explode)
    response = client.get("/health")
    assert response.status_code == 200 and response.json()["status"] == "ok"


def test_ready_ok_when_dependencies_up(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    all_up(monkeypatch)
    response = client.get("/ready")
    assert response.status_code == 200
    assert set(response.json()["checks"]) == {"database", "redis", "storage", "workers"}


def test_ready_503_when_dependency_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    all_up(monkeypatch)

    def fail() -> None:
        raise ConnectionError("redis://user:hunter2@redis:6379 down")

    monkeypatch.setattr(health_routes, "check_redis", fail)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["redis"] == {
        "status": "error",
        "latency_ms": None,
        "detail": "ConnectionError",
    }
    assert "hunter2" not in response.text


def test_worker_check_needs_a_fresh_heartbeat_with_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRedis:
        def __init__(self, beats: dict[str, dict[str, object]]) -> None:
            self.beats = beats

        def scan_iter(self, pattern: str, count: int) -> list[str]:
            return list(self.beats)

        def get(self, key: str) -> bytes:
            return json.dumps(self.beats[key]).encode()

    now = time.time()
    cases = [
        ({}, "NoWorkerHeartbeat"),
        ({"a": {"at": now - 600, "docker": "ok"}}, "NoWorkerHeartbeat"),
        ({"a": {"at": now, "docker": "error"}}, "DockerUnreachable"),
        ({"a": {"at": now, "docker": "error"}, "b": {"at": now - 10, "docker": "ok"}}, None),
    ]
    for beats, expected in cases:
        monkeypatch.setattr(health_routes, "get_redis", lambda beats=beats: FakeRedis(beats))
        if expected is None:
            health_routes.check_workers()
        else:
            with pytest.raises(RuntimeError, match=expected):
                health_routes.check_workers()


def test_metrics_endpoint_and_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import SecretStr

    from app.config import get_settings

    body = client.get("/metrics")
    assert body.status_code == 200 and "codeaudit_http_requests_total" in body.text
    monkeypatch.setattr(get_settings(), "metrics_token", SecretStr("s3cret-metrics"))
    assert client.get("/metrics").status_code == 401
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer s3cret-metrics"}).status_code
        == 200
    )

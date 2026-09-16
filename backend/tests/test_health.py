import pytest
from fastapi.testclient import TestClient

from app.api.routes import health as health_routes
from app.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health_ok_when_dependencies_up(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health_routes, "check_database", lambda: None)
    monkeypatch.setattr(health_routes, "check_redis", lambda: None)

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"]["status"] == "ok"
    assert body["checks"]["redis"]["status"] == "ok"


def test_health_503_when_dependency_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail() -> None:
        raise ConnectionError("redis down")

    monkeypatch.setattr(health_routes, "check_database", lambda: None)
    monkeypatch.setattr(health_routes, "check_redis", fail)

    response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["checks"]["redis"] == {
        "status": "error",
        "latency_ms": None,
        "detail": "ConnectionError",
    }

"""Production hardening: quotas, cost controls, sandbox limits, resilience, observability."""

import json
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.config import Settings, get_settings
from app.core.db import SessionLocal
from app.models import (
    LLMCall,
    LLMPurpose,
    PullRequest,
    PullRequestStatus,
    Scan,
    ScanStatus,
    Severity,
    User,
)
from app.services import costs, quotas
from app.services.analyzers.base import FindingData
from tests.integration.conftest import SignedIn, SignIn

pytestmark = pytest.mark.integration


@pytest.fixture
def anon(database: None, redis_clean: None) -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app) as client:
        yield client


def make_scan(**values: Any) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(
            status=values.pop("status", ScanStatus.COMPLETED),
            original_filename="x.zip",
            storage_key=f"k/{uuid.uuid4()}",
            **values,
        )
        db.add(scan)
        db.commit()
        return scan.id


def make_admin(user: SignedIn) -> None:
    with SessionLocal() as db:
        row = db.get(User, user.user_id)
        assert row is not None
        row.is_admin = True
        db.commit()


# ------------------------------------------------------------------ quotas


def test_sliding_window_quota_counts_resets_and_explains(
    redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "quota_anonymous_scans_per_day", 2)
    monkeypatch.setitem(quotas.WINDOWS, "scans", 2)
    subject = quotas.subject_for(None, "203.0.113.9")

    assert quotas.consume(subject, "scans").remaining == 1
    assert quotas.consume(subject, "scans").remaining == 0
    with pytest.raises(quotas.RateLimitedError) as info:
        quotas.consume(subject, "scans")
    error = info.value
    assert error.code == "quota_exceeded"
    assert error.details["limit"] == "scans" and error.details["max"] == 2
    assert 1 <= int(error.headers["Retry-After"]) <= 3
    assert "Limit reached: 2 scans per day (anonymous tier)" in str(error)
    # A refused attempt is not counted.
    assert quotas.peek(subject, "scans").used == 2
    # Another client IP has its own window.
    assert quotas.consume(quotas.subject_for(None, "203.0.113.10"), "scans").allowed

    time.sleep(2.2)
    assert quotas.consume(subject, "scans").allowed


def test_tiers_and_per_user_overrides(database: None, monkeypatch: pytest.MonkeyPatch) -> None:
    user = User(id=uuid.uuid4(), display_name="t", quota_tier="pro")
    assert quotas.limit_for(quotas.subject_for(user, "1.2.3.4"), "scans") == (
        get_settings().quota_pro_scans_per_day
    )
    user.quota_scans = 7
    assert quotas.limit_for(quotas.subject_for(user, "1.2.3.4"), "scans") == 7
    user.quota_tier = "enterprise"  # unknown tiers fall back to free
    assert quotas.subject_for(user, "1.2.3.4").tier == "free"
    # Anonymous clients can't open pull requests at all.
    assert quotas.limit_for(quotas.subject_for(None, "1.2.3.4"), "pull_requests") == 0


def test_per_ip_request_limit_headers_and_429(
    anon: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "quota_anonymous_requests_per_minute", 3)
    responses = [anon.get("/api/quotas") for _ in range(3)]
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert responses[0].headers["X-RateLimit-Limit"] == "3"
    assert [r.headers["X-RateLimit-Remaining"] for r in responses] == ["2", "1", "0"]
    assert "requests" in responses[0].headers["X-RateLimit-Policy"]

    limited = anon.get("/api/quotas")
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    body = limited.json()["error"]
    assert body["code"] == "rate_limited" and "120" not in body["message"]
    assert "3 API requests per minute" in body["message"]
    # Liveness and metrics are never rate limited.
    assert anon.get("/health").status_code == 200


def test_quota_endpoint_reports_remaining(sign_in: SignIn) -> None:
    user = sign_in("quota-reader")
    data = user.client.get("/api/quotas").json()
    assert data["tier"] == "free"
    limits = {item["name"]: item for item in data["limits"]}
    assert limits["scans"]["limit"] == get_settings().quota_free_scans_per_day
    assert limits["scans"]["remaining"] == limits["scans"]["limit"]
    assert limits["scans"]["window_seconds"] == 86_400
    assert data["llm_tokens"]["limit"] == get_settings().quota_free_llm_tokens_per_month
    assert data["llm_available"] is True and data["llm_blocked_reason"] is None


# ------------------------------------------------------------------ cost controls


def _llm_client(fake: Any) -> Any:
    from app.services.llm.client import LLMClient

    settings = Settings(anthropic_model="claude-sonnet-4-6", llm_max_retries=1)  # type: ignore[call-arg]
    return LLMClient(fake.client(), settings=settings, sleep=lambda _: None)


def _ask(client: Any, scan_id: uuid.UUID) -> Any:
    from pydantic import BaseModel

    class Answer(BaseModel):
        verdict: str

    return client.generate_json(
        scan_id=scan_id,
        purpose=LLMPurpose.FIX_SUGGESTION,
        system="Reply with JSON.",
        prompt="Is this safe?",
        schema=Answer,
    )


def _record_spend(usd: float) -> None:
    scan_id = make_scan()
    with SessionLocal() as db:
        db.add(
            LLMCall(
                scan_id=scan_id,
                purpose=LLMPurpose.FIX_SUGGESTION,
                model="claude-sonnet-4-6",
                success=True,
                pending=False,
                cost_usd=usd,
                context={},
            )
        )
        db.commit()


def _clear_spend() -> None:
    from sqlalchemy import delete

    with SessionLocal() as db:
        db.execute(delete(LLMCall))
        db.commit()


def test_daily_spend_cap_refuses_calls_before_they_are_sent(
    database: None, redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.llm.client import LLMBudgetExceededError, LLMSpendCapError
    from tests.llm_fakes import FakeAnthropic, message

    _clear_spend()
    monkeypatch.setattr(get_settings(), "llm_daily_spend_cap_usd", 1.0)
    _record_spend(0.99)
    scan_id = make_scan(status=ScanStatus.ENRICHING)
    fake = FakeAnthropic([message('{"verdict": "safe"}')])

    with pytest.raises(LLMSpendCapError) as info:
        _ask(_llm_client(fake), scan_id)
    assert isinstance(info.value, LLMBudgetExceededError)  # enrichment treats it as a budget cut
    assert "daily LLM spend cap ($1.00)" in str(info.value)
    assert fake.message_requests == []
    with SessionLocal() as db:
        [call] = db.scalars(select(LLMCall).where(LLMCall.scan_id == scan_id)).all()
        assert (call.error_type, call.pending, float(call.cost_usd)) == ("spend_cap", False, 0.0)

    # Enrichment dispatch is blocked too, with the same reason.
    from app.services.llm.enrichment import llm_dispatch_block

    monkeypatch.setattr(get_settings(), "llm_daily_spend_cap_usd", 0.5)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert "spend cap" in (llm_dispatch_block(db, scan) or "")
    _clear_spend()


def test_in_flight_calls_count_against_the_cap(
    database: None, redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent reservations can't overshoot: a pending call counts at its worst case."""
    from app.services.llm.pricing import estimate_cost_usd

    _clear_spend()
    estimate = estimate_cost_usd("claude-sonnet-4-6", 2000, get_settings().llm_max_output_tokens)
    monkeypatch.setattr(get_settings(), "llm_daily_spend_cap_usd", estimate * 1.5)
    with SessionLocal() as db:
        assert costs.blocked_reason(db, estimate) is None
        db.add(
            LLMCall(
                scan_id=make_scan(),
                purpose=LLMPurpose.FIX_SUGGESTION,
                model="claude-sonnet-4-6",
                success=False,
                pending=True,
                cost_usd=estimate,
                context={},
            )
        )
        db.commit()
        assert costs.blocked_reason(db, estimate) is not None
    _clear_spend()


def test_kill_switch_and_admin_endpoints(sign_in: SignIn, monkeypatch: pytest.MonkeyPatch) -> None:
    user = sign_in("not-an-operator")
    admin = sign_in("operator")
    make_admin(admin)

    for method, path, body in (
        ("get", "/api/admin/costs", None),
        ("post", "/api/admin/llm-kill-switch", {"enabled": True}),
        ("get", "/api/admin/dead-letters", None),
    ):
        response = getattr(user.client, method)(
            path, **({"json": body, "headers": user.headers} if body else {})
        )
        assert response.status_code == 403 and response.json()["error"]["code"] == "admin_required"

    on = admin.client.post(
        "/api/admin/llm-kill-switch",
        json={"enabled": True, "reason": "runaway costs"},
        headers=admin.headers,
    )
    assert on.status_code == 200 and "runaway costs (by operator)" in on.json()["kill_switch"]
    with SessionLocal() as db:
        assert "switched off by an operator" in (costs.blocked_reason(db) or "")
    # Everyone sees that suggestions are paused; only operators see why.
    assert user.client.get("/api/quotas").json()["llm_blocked_reason"] == (
        "Fix suggestions are temporarily paused."
    )
    assert "runaway" in admin.client.get("/api/quotas").json()["llm_blocked_reason"]

    off = admin.client.post(
        "/api/admin/llm-kill-switch", json={"enabled": False}, headers=admin.headers
    )
    assert off.json() == {"kill_switch": None}

    # Operators can move users between tiers and override single limits.
    patched = admin.client.patch(
        f"/api/admin/users/{user.user_id}/quota",
        json={"tier": "pro", "overrides": {"scans": 3}},
        headers=admin.headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["tier"] == "pro" and patched.json()["overrides"]["scans"] == 3
    limits = {i["name"]: i for i in user.client.get("/api/quotas").json()["limits"]}
    assert limits["scans"]["limit"] == 3
    assert limits["pull_requests"]["limit"] == get_settings().quota_pro_pull_requests_per_day


def test_spend_alerts_fire_once_per_level_and_post_webhook(
    database: None, redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_spend()
    posted: list[costs.Alert] = []
    done = threading.Event()

    def fake_post(url: str, alert: costs.Alert) -> None:
        posted.append(alert)
        done.set()

    monkeypatch.setattr(costs, "_post_webhook", fake_post)
    monkeypatch.setattr(get_settings(), "llm_daily_spend_cap_usd", 10.0)
    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://hooks.example/alert")

    _record_spend(7.0)
    with SessionLocal() as db:
        assert costs.check_spend_alerts(db) is None  # 70%: below the 80% threshold
    _record_spend(1.5)
    with SessionLocal() as db:
        alert = costs.check_spend_alerts(db)
        assert alert is not None and alert.level == "threshold" and alert.spent == 8.5
        assert costs.check_spend_alerts(db) is None  # once per day
    assert done.wait(5) and posted[0].level == "threshold"
    _record_spend(2.0)
    with SessionLocal() as db:
        cap_alert = costs.check_spend_alerts(db)
        assert cap_alert is not None and cap_alert.level == "cap_reached"
    _clear_spend()


def test_cost_dashboard_breaks_spend_down(sign_in: SignIn, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_spend()
    admin = sign_in("cost-viewer")
    make_admin(admin)
    owned = make_scan(user_id=admin.user_id)
    with SessionLocal() as db:
        for scan_id, purpose, usd in (
            (owned, LLMPurpose.FIX_SUGGESTION, 0.25),
            (owned, LLMPurpose.FIX_SUGGESTION, 0.5),
            (make_scan(), LLMPurpose.FIX_SUGGESTION, 0.1),
        ):
            db.add(
                LLMCall(
                    scan_id=scan_id,
                    purpose=purpose,
                    model="claude-sonnet-4-6",
                    success=True,
                    pending=False,
                    cost_usd=usd,
                    input_tokens=100,
                    output_tokens=10,
                    context={},
                )
            )
        db.commit()
    report = admin.client.get("/api/admin/costs?days=7").json()
    assert report["total_usd"] == pytest.approx(0.85)
    assert report["by_day"][-1]["calls"] == 3 and report["by_day"][-1]["tokens"] == 330
    assert report["by_purpose"][0]["purpose"] == "fix_suggestion"
    by_user = {row["display_name"]: row["cost_usd"] for row in report["by_user"]}
    assert by_user == {"cost-viewer": 0.75, "(anonymous)": 0.1}
    assert report["today"]["cap_usd"] == get_settings().llm_daily_spend_cap_usd
    _clear_spend()


# ------------------------------------------------------------------ sandbox


def test_sandbox_slots_are_shared_and_leases_expire(
    redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.redis_client import get_redis
    from app.services.analyzers import sandbox

    monkeypatch.setattr(get_settings(), "max_concurrent_sandboxes", 1)
    monkeypatch.setattr(get_settings(), "sandbox_slot_timeout_seconds", 1)
    get_redis().delete(sandbox.SLOTS_KEY)

    with sandbox.SandboxSlot(lease_seconds=60):
        started = time.monotonic()
        with pytest.raises(sandbox.SandboxCapacityError, match="1 analysis sandboxes"):
            with sandbox.SandboxSlot(lease_seconds=60):
                pass
        assert time.monotonic() - started >= 1
    # Released on exit.
    with sandbox.SandboxSlot(lease_seconds=60):
        pass
    # A crashed holder's slot frees itself when its lease runs out.
    get_redis().zadd(sandbox.SLOTS_KEY, {"dead-worker": time.time() + 1})
    with sandbox.SandboxSlot(lease_seconds=60):
        pass


def test_disk_watch_kills_a_container_that_fills_its_workspace(tmp_path: Path) -> None:
    from app.services.analyzers.sandbox import DiskWatch

    killed = threading.Event()
    container = SimpleNamespace(kill=killed.set)
    watch = DiskWatch(container, [tmp_path], quota=1024 * 1024)
    watch.INTERVAL_SECONDS = 0.05  # type: ignore[misc]
    with watch:
        (tmp_path / "small").write_bytes(b"x" * 1000)
        time.sleep(0.2)
        assert not killed.is_set()
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "bomb").write_bytes(b"\0" * (2 * 1024 * 1024))
        assert killed.wait(3)
    assert watch.exceeded


def test_orphan_reaper_removes_only_expired_sandboxes(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.analyzers import sandbox

    now = datetime.now(UTC)
    removed: list[str] = []

    def container(name: str, age: timedelta) -> SimpleNamespace:
        return SimpleNamespace(
            short_id=name,
            labels={"codeaudit.analyzer": "semgrep"},
            attrs={"Created": (now - age).isoformat().replace("+00:00", "Z")},
            name=name,
        )

    containers = [container("old", timedelta(hours=2)), container("new", timedelta(seconds=5))]
    filters_seen: list[dict[str, Any]] = []

    class FakeContainers:
        def list(self, all: bool, filters: dict[str, Any]) -> list[SimpleNamespace]:
            filters_seen.append(filters)
            return containers

    fake = SimpleNamespace(containers=FakeContainers(), close=lambda: None)
    monkeypatch.setattr(sandbox, "_client", lambda: fake)
    monkeypatch.setattr(sandbox, "_remove_quietly", lambda c: removed.append(c.short_id))

    assert sandbox.reap_expired_sandboxes(max_age_seconds=3600) == 1
    assert removed == ["old"]
    assert filters_seen == [{"label": f"{sandbox.SANDBOX_LABEL}=true"}]


# ------------------------------------------------------------------ resilience


def test_persisting_the_same_findings_twice_is_idempotent(database: None) -> None:
    from app.services.scan_pipeline import persist_results

    finding = FindingData(
        analyzer="bandit",
        rule_id="B608",
        severity=Severity.ERROR,
        file_path="app.py",
        start_line=3,
        end_line=3,
        message="Possible SQL injection",
    )
    scan_id = make_scan(status=ScanStatus.RUNNING)
    for _ in range(2):
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            assert scan is not None
            # The same finding twice in one batch (a retried analyzer) is stored once.
            persist_results(db, scan, [finding, finding], ScanStatus.COMPLETED)
    with SessionLocal() as db:
        from app.models import Finding

        count = db.scalar(select(func.count()).where(Finding.scan_id == scan_id))
        assert count == 1


def test_redelivered_scan_task_is_a_no_op(database: None) -> None:
    from app.workers.tasks import run_scan

    finished = make_scan(status=ScanStatus.COMPLETED)
    # A finished scan is reported, not analyzed again.
    assert run_scan.run(str(finished)) == {"scan_id": str(finished), "status": "completed"}
    running = make_scan(status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
    assert run_scan.run(str(running)).get("status") == "duplicate_delivery"
    with SessionLocal() as db:
        scan = db.get(Scan, running)
        assert scan is not None and scan.status is ScanStatus.RUNNING


def test_stale_job_reaper_fails_stuck_work_with_a_reason(
    database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.workers.maintenance import reap_stale_jobs_once

    long_ago = datetime.now(UTC) - timedelta(hours=12)
    stuck_running = make_scan(status=ScanStatus.RUNNING, started_at=long_ago)
    stuck_queued = make_scan(status=ScanStatus.QUEUED)
    healthy = make_scan(status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
    with SessionLocal() as db:
        queued = db.get(Scan, stuck_queued)
        assert queued is not None
        queued.created_at = long_ago
        db.commit()

    reaped = reap_stale_jobs_once()
    assert reaped.get("scan_running", 0) >= 1 and reaped.get("scan_queued", 0) >= 1
    with SessionLocal() as db:
        running = db.get(Scan, stuck_running)
        queued = db.get(Scan, stuck_queued)
        fine = db.get(Scan, healthy)
        assert running is not None and queued is not None and fine is not None
        assert running.status is ScanStatus.FAILED
        assert "did not finish within" in (running.error_message or "")
        assert queued.status is ScanStatus.FAILED and "never picked up" in (
            queued.error_message or ""
        )
        assert fine.status is ScanStatus.RUNNING


def test_failed_tasks_are_dead_lettered_and_visible(
    sign_in: SignIn, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.celery_app import _dead_letter

    token = "ghp_" + "a" * 36
    _dead_letter(
        sender=SimpleNamespace(name="codeaudit.run_scan"),
        task_id="t-1",
        exception=RuntimeError(f"clone failed with token {token}"),
        args=("scan-id",),
    )
    admin = sign_in("dead-letter-reader")
    make_admin(admin)
    [entry] = admin.client.get("/api/admin/dead-letters").json()
    assert entry["task"] == "codeaudit.run_scan" and entry["task_id"] == "t-1"
    assert token not in entry["error"] and "RuntimeError" in entry["error"]


# ------------------------------------------------------------------ caching


def test_scan_cache_reuses_only_visible_matching_results(database: None) -> None:
    from app.services import scan_cache

    digest = uuid.uuid4().hex * 2
    owner = User(id=uuid.uuid4(), display_name="cache-owner")
    stranger = User(id=uuid.uuid4(), display_name="cache-stranger")
    with SessionLocal() as db:
        db.add_all([owner, stranger])
        db.commit()
    version = scan_cache.analysis_version()
    private = make_scan(content_sha256=digest, analysis_version=version, user_id=owner.id)

    def principal(user: User | None) -> Any:
        return SimpleNamespace(user=user) if user else None

    with SessionLocal() as db:
        hit = scan_cache.find_reusable(db, principal(owner), content_sha256=digest)
        assert hit is not None and hit.id == private
        assert scan_cache.find_reusable(db, principal(stranger), content_sha256=digest) is None
        assert scan_cache.find_reusable(db, None, content_sha256=digest) is None

    other = uuid.uuid4().hex * 2
    make_scan(content_sha256=other, analysis_version="old-analyzers")
    make_scan(content_sha256=other, analysis_version=version, status=ScanStatus.FAILED)
    with SessionLocal() as db:
        assert scan_cache.find_reusable(db, None, content_sha256=other) is None
    shared = make_scan(content_sha256=other, analysis_version=version)
    with SessionLocal() as db:
        hit = scan_cache.find_reusable(db, principal(stranger), content_sha256=other)
        assert hit is not None and hit.id == shared


# ------------------------------------------------------------------ API surface


def test_security_headers_and_request_ids(anon: TestClient) -> None:
    response = anon.get("/health")
    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert len(headers["X-Request-ID"]) >= 16

    assert (
        anon.get("/health", headers={"X-Request-ID": "client-trace-1234"}).headers["X-Request-ID"]
        == "client-trace-1234"
    )
    injected = anon.get("/health", headers={"X-Request-ID": "bad id\r\nx"}).headers["X-Request-ID"]
    assert injected != "bad id\r\nx" and " " not in injected
    # Errors carry the headers too.
    missing = anon.get(f"/api/scans/{uuid.uuid4()}")
    assert missing.status_code == 404 and missing.headers["X-Frame-Options"] == "DENY"


def test_list_endpoints_are_paginated(sign_in: SignIn) -> None:
    user = sign_in("paginator")
    for _ in range(3):
        make_scan(user_id=user.user_id)
    first = user.client.get("/api/scans?limit=2")
    assert first.status_code == 200 and len(first.json()["items"]) == 2
    assert first.json()["total"] == 3
    assert len(user.client.get("/api/scans?limit=2&page=2").json()["items"]) == 1

    for _ in range(3):
        user.client.post("/api/auth/tokens", json={"name": "t"}, headers=user.headers)
    page = user.client.get("/api/auth/tokens?page=2&page_size=2")
    assert page.status_code == 200 and len(page.json()) == 1
    assert page.headers["X-Total-Count"] == "3"
    assert 'rel="prev"' in page.headers["Link"] and 'rel="next"' not in page.headers["Link"]
    assert user.client.get("/api/auth/tokens?page_size=101").status_code == 422
    # Tokens are addressed by UUID, never by sequential id.
    token_id = page.json()[0]["id"]
    assert uuid.UUID(token_id)
    assert (
        user.client.delete(f"/api/auth/tokens/{token_id}", headers=user.headers).status_code == 204
    )


def test_pull_requests_have_uuid_public_ids(database: None) -> None:
    scan_id = make_scan()
    user = User(id=uuid.uuid4(), display_name="pr-owner")
    with SessionLocal() as db:
        db.add(user)
        db.flush()
        pr = PullRequest(
            scan_id=scan_id,
            user_id=user.id,
            status=PullRequestStatus.PREVIEWED,
            repo_full_name="o/r",
            head_repo_full_name="o/r",
            base_branch="main",
            base_sha="0" * 40,
            branch="codeaudit/fix",
            title="t",
            body="b",
            included_suggestion_ids=[],
            preview_fingerprint="f",
            combined_diff="",
            commits=[],
        )
        db.add(pr)
        db.commit()
        assert isinstance(pr.public_id, uuid.UUID) and pr.public_id.version == 4
        from app.schemas.pull_request import PullRequestRead

        assert PullRequestRead.model_validate(pr).id == pr.public_id


def test_metrics_expose_http_and_pipeline_series(anon: TestClient) -> None:
    anon.get("/api/quotas")
    body = anon.get("/metrics").text
    for series in (
        "codeaudit_http_requests_total",
        "codeaudit_http_request_duration_seconds",
        "codeaudit_scan_stage_duration_seconds",
        "codeaudit_llm_tokens_total",
        "codeaudit_sandbox_containers_active",
        "codeaudit_queue_depth",
    ):
        assert series in body, series
    assert 'route="/api/quotas"' in body


# ------------------------------------------------------------------ logging


def test_logs_are_json_with_context_and_secrets_scrubbed() -> None:
    from app.core.observability import JsonFormatter, bind, scrub

    for secret in (
        "ghp_" + "b" * 36,
        "gho_" + "c" * 36,
        "sk-ant-api03-" + "d" * 40,
        "AKIA" + "E" * 16,
    ):
        assert secret not in scrub(f"failed using {secret} for request")
    assert "hunter2" not in scrub("postgresql://codeaudit:hunter2@db:5432/codeaudit")
    assert "hunter2" not in scrub("Authorization: Bearer hunter2hunter2")

    record = logging.LogRecord(
        "codeaudit.test", logging.WARNING, __file__, 1, "clone with %s", ("ghp_" + "f" * 36,), None
    )
    with bind(request_id="req-12345678", scan_id="scan-1"):
        payload = json.loads(JsonFormatter().format(record))
    assert payload["request_id"] == "req-12345678" and payload["scan_id"] == "scan-1"
    assert "ghp_" + "f" * 36 not in payload["message"] and payload["level"] == "warning"


def test_sandbox_slot_is_released_when_docker_is_unreachable(
    redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.core.redis_client import get_redis
    from app.services.analyzers import sandbox

    def unreachable() -> None:
        raise sandbox.SandboxUnavailableError("Docker daemon unavailable: test")

    monkeypatch.setattr(sandbox, "_client", unreachable)
    get_redis().delete(sandbox.SLOTS_KEY)
    with pytest.raises(sandbox.SandboxUnavailableError):
        sandbox.run_in_sandbox(
            image="busybox",
            command=["true"],
            mounts=[],
            limits=sandbox.SandboxLimits(cpus=0.1, memory="16m", timeout_seconds=5),
            working_dir="/",
        )
    assert get_redis().zcard(sandbox.SLOTS_KEY) == 0


def test_monthly_token_quota_counts_reservations_only_while_in_flight(database: None) -> None:
    user = User(id=uuid.uuid4(), display_name="token-counter")
    with SessionLocal() as db:
        db.add(user)
        db.commit()
    scan_id = make_scan(user_id=user.id)
    with SessionLocal() as db:
        db.add_all(
            [
                # Finished: 1,000 used; its earlier 20,000 reservation no longer counts.
                LLMCall(
                    scan_id=scan_id,
                    purpose=LLMPurpose.FIX_SUGGESTION,
                    model="ollama/qwen2.5-coder:7b",
                    success=True,
                    pending=False,
                    input_tokens=800,
                    output_tokens=200,
                    reserved_tokens=20_000,
                    context={},
                ),
                # In flight: counts at its reservation.
                LLMCall(
                    scan_id=scan_id,
                    purpose=LLMPurpose.FIX_SUGGESTION,
                    model="ollama/qwen2.5-coder:7b",
                    success=False,
                    pending=True,
                    reserved_tokens=5_000,
                    context={},
                ),
            ]
        )
        db.commit()
        assert quotas.llm_tokens_used_this_month(db, user.id) == 6_000


def test_late_enrichment_delivery_does_not_overwrite_a_finished_result(database: None) -> None:
    from app.models import EnrichmentStatus
    from app.workers.tasks import enrich_scan

    scan_id = make_scan(status=ScanStatus.COMPLETED)
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        scan.enrichment_status = EnrichmentStatus.COMPLETED
        db.commit()
    assert enrich_scan.run(str(scan_id)) == {"scan_id": str(scan_id), "status": "skipped"}
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.enrichment_status is EnrichmentStatus.COMPLETED
        assert scan.enrichment_error is None

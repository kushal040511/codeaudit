"""Site analyzer API end to end, with the browser capture and all external lookups mocked."""

import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.db import SessionLocal
from app.models import SiteAnalysis
from app.services.web import analysis as analysis_module
from app.services.web.analysis import Intel
from app.services.web.capture import CaptureBlockedError, CaptureError
from app.services.web.intel import CertificateInfo, DnsInfo, Registration, Reputation
from tests.integration.conftest import SignedIn, SignIn
from tests.unit.web.factories import make_capture

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).parents[1] / "fixtures" / "web"
PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch, database: None, redis_clean: None) -> dict[str, Any]:
    """No DNS, no browser, no RDAP/TLS/reputation: everything comes from here."""
    state: dict[str, Any] = {"captures": [], "resolve": {}, "capture_error": None}

    def resolver(host: str, port: int) -> list[str]:
        return state["resolve"].get(host, [PUBLIC])

    monkeypatch.setattr("app.services.web.netguard.system_resolver", resolver)
    from app.services.web import netguard

    original_resolve = netguard.resolve_public
    monkeypatch.setattr(
        netguard,
        "resolve_public",
        lambda host, port, resolver_=resolver: original_resolve(host, port, resolver_),
    )

    def validate(raw: str, resolver_: Any = resolver):  # type: ignore[no-untyped-def]
        url = netguard.normalize_url(raw)
        return url, original_resolve(url.host, url.port, resolver)

    monkeypatch.setattr("app.api.routes.sites.validate_url", validate)
    monkeypatch.setattr(analysis_module, "validate_url", validate)

    def capture(url: str, workdir: Path, *, label: str):  # type: ignore[no-untyped-def]
        state["captures"].append(url)
        if state["capture_error"]:
            raise state["capture_error"]
        captured = make_capture(
            final_url=url,
            title="Sign in to your PayPal account" if "paypal" in url else "Fixture design page",
            forms=(
                [{"action": "https://collector.example.net/x", "inputs": [{"type": "password"}]}]
                if "paypal" in url
                else []
            ),
            styles=json.loads((FIXTURES / "design_page.styles.json").read_text()),
        )
        captured.fold_png = (FIXTURES / "login_clone.png").read_bytes()
        captured.full_png = captured.fold_png
        return captured

    def intel(captured):  # type: ignore[no-untyped-def]
        young = "paypal" in captured.final_url
        return Intel(
            registration=Registration(
                registered_at=datetime.now(UTC) - timedelta(days=2 if young else 4000),
                registrar="Test Registrar",
            ),
            dns=DnsInfo(a=[PUBLIC], mx=[] if young else ["mx.example.com"]),
            certificate=CertificateInfo(
                issuer="Test CA",
                not_before=datetime.now(UTC) - timedelta(days=90),
                san=["x"],
                hostname_matches=True,
                trusted=True,
            ),
            reputation=[
                Reputation("google_safe_browsing", None, error="not configured"),
                Reputation("openphish", False),
            ],
        )

    monkeypatch.setattr(analysis_module, "capture_page", capture)
    monkeypatch.setattr(analysis_module, "gather_intel", intel)
    run = analysis_module.run_site_analysis
    monkeypatch.setattr(
        analysis_module,
        "run_site_analysis",
        lambda db, a, *, llm, **kw: run(db, a, llm=None, capture_fn=capture, intel_fn=intel),
    )
    monkeypatch.setattr("app.workers.tasks.run_site_analysis", analysis_module.run_site_analysis)
    uploads: dict[str, bytes] = {}
    monkeypatch.setattr(
        analysis_module,
        "upload_bytes",
        lambda key, data, content_type: uploads.__setitem__(key, data),
    )
    monkeypatch.setattr("app.api.routes.sites.get_bytes", lambda key, max_bytes=0: uploads[key])
    state["uploads"] = uploads
    return state


@pytest.fixture
def anon() -> TestClient:
    from app.main import app

    with TestClient(app) as client:
        yield client  # type: ignore[misc]


def analyze(client: TestClient, url: str, **extra: Any) -> Any:
    return client.post("/api/sites/analyze", json={"url": url, **extra})


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/",
        "http://localhost:8080/",
        "file:///etc/passwd",
        "http://metadata.google.internal/",
        "http://rebind.example/",  # resolves to a private address
    ],
)
def test_forbidden_urls_are_rejected_before_anything_is_queued(
    anon: TestClient, offline: dict[str, Any], url: str
) -> None:
    offline["resolve"]["rebind.example"] = ["10.0.0.5"]
    response = analyze(anon, url)
    assert response.status_code == 400 and response.json()["error"]["code"] == "url_not_allowed"
    assert offline["captures"] == []
    with SessionLocal() as db:
        assert db.query(SiteAnalysis).filter(SiteAnalysis.url == url).count() == 0


def test_dns_that_changes_to_private_after_acceptance_is_blocked_at_run_time(
    anon: TestClient, offline: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.routes import sites

    queued: list[str] = []
    monkeypatch.setattr(
        "app.workers.tasks.analyze_site_task.delay", lambda analysis_id: queued.append(analysis_id)
    )
    created = analyze(anon, "https://flip.example/").json()
    offline["resolve"]["flip.example"] = ["127.0.0.1"]  # rebinds before the worker starts
    from app.workers.tasks import analyze_site_task

    analyze_site_task.run(queued[0])
    body = anon.get(f"/api/sites/{created['analysis_id']}").json()
    assert body["status"] == "failed" and "loopback" in body["error_message"]
    assert offline["captures"] == []
    del sites


def test_full_analysis_returns_evidence_and_tokens(
    anon: TestClient, offline: dict[str, Any]
) -> None:
    created = analyze(anon, "https://paypal-account-verify.com/signin")
    assert created.status_code == 202, created.text
    body = created.json()
    assert (
        body["cached"] is False
        and body["normalized_url"] == "https://paypal-account-verify.com/signin"
    )

    result = anon.get(f"/api/sites/{body['analysis_id']}").json()
    assert result["status"] == "completed", result
    risk = result["risk"]
    assert "not a determination" in risk["disclaimer"]
    fired = {e["signal"]: e for e in risk["evidence"] if e["status"] == "fired"}
    assert {
        "domain_age_under_7d",
        "brand_in_domain",
        "brand_in_title",
        "credentials_cross_domain_form",
        "password_field",
    } <= set(fired)
    assert risk["score"] == min(100, round(sum(e["points"] for e in risk["evidence"])))
    assert risk["impersonated_brand"] == "paypal"
    assert result["design"]["tokens"]["colors"]["roles"]["primary"]["hex"] == "#4f46e5"
    assert (
        "No Anthropic API key" in " ".join(result["design"]["notes"]) or result["design"]["notes"]
    )

    screenshot = anon.get(result["screenshot_url"])
    assert screenshot.status_code == 200 and screenshot.headers["content-type"] == "image/png"
    assert screenshot.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in screenshot.headers["content-security-policy"]

    tailwind = anon.get(f"/api/sites/{body['analysis_id']}/tokens", params={"format": "tailwind"})
    assert (
        tailwind.status_code == 200
        and 'filename="tailwind.config.js"' in tailwind.headers["content-disposition"]
    )
    assert '"primary": {\n' in tailwind.text and "#4f46e5" in tailwind.text
    css = anon.get(f"/api/sites/{body['analysis_id']}/tokens", params={"format": "css"})
    assert (
        css.headers["content-type"].startswith("text/css")
        and "--color-primary: #4f46e5;" in css.text
    )
    tokens = anon.get(f"/api/sites/{body['analysis_id']}/tokens").json()
    assert tokens["typography"]["base_size_px"] == 16
    assert (
        anon.get(f"/api/sites/{body['analysis_id']}/tokens", params={"format": "yaml"}).status_code
        == 422
    )


def test_recent_results_are_reused_instead_of_refetching(
    anon: TestClient, offline: dict[str, Any]
) -> None:
    first = analyze(anon, "https://shop.example/").json()
    second = analyze(anon, "HTTPS://SHOP.example./#frag").json()  # same normalized URL
    assert second["cached"] is True and second["analysis_id"] != first["analysis_id"]
    assert offline["captures"] == ["https://shop.example/"]
    copy = anon.get(f"/api/sites/{second['analysis_id']}").json()
    assert (
        copy["cached_from_id"] == first["analysis_id"]
        and copy["risk"]["score"]
        == anon.get(f"/api/sites/{first['analysis_id']}").json()["risk"]["score"]
    )

    forced = analyze(anon, "https://shop.example/", force=True).json()
    assert forced["cached"] is False and len(offline["captures"]) == 2

    with SessionLocal() as db:
        original = db.get(SiteAnalysis, uuid.UUID(first["analysis_id"]))
        assert original is not None
        original.created_at = datetime.now(UTC) - timedelta(
            seconds=get_settings().site_cache_ttl_seconds + 60
        )
        forced_row = db.get(SiteAnalysis, uuid.UUID(forced["analysis_id"]))
        assert forced_row is not None
        forced_row.created_at = original.created_at
        db.commit()
    assert analyze(anon, "https://shop.example/").json()["cached"] is False  # expired


def test_capture_failures_are_reported(anon: TestClient, offline: dict[str, Any]) -> None:
    offline["capture_error"] = CaptureBlockedError(
        "Blocked a redirect to http://169.254.169.254/: The URL points to a cloud metadata address."
    )
    blocked = anon.get(
        f"/api/sites/{analyze(anon, 'https://redirector.example/').json()['analysis_id']}"
    ).json()
    assert blocked["status"] == "failed" and "metadata" in blocked["error_message"]
    offline["capture_error"] = CaptureError(
        "The page could not be loaded (net::ERR_NAME_NOT_RESOLVED)."
    )
    dead = anon.get(
        f"/api/sites/{analyze(anon, 'https://dead.example/').json()['analysis_id']}"
    ).json()
    assert dead["status"] == "failed" and "ERR_NAME_NOT_RESOLVED" in dead["error_message"]
    assert anon.get(
        f"/api/sites/{analyze(anon, 'https://dead.example/').json()['analysis_id']}/tokens"
    ).status_code in (409, 404)


def test_rate_limits(anon: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "quota_anonymous_site_analyses_per_day", 2)
    codes = [analyze(anon, f"https://site{i}.example/").status_code for i in range(3)]
    assert codes == [202, 202, 429]
    assert (
        "Sign in for higher limits"
        in analyze(anon, "https://site9.example/").json()["error"]["message"]
    )
    # Cache hits don't count against the limit.
    assert analyze(anon, "https://site0.example/").json()["cached"] is True


def test_ownership(anon: TestClient, sign_in: SignIn) -> None:
    owner: SignedIn = sign_in("site-owner")
    other: SignedIn = sign_in("site-other")
    created = owner.client.post(
        "/api/sites/analyze", json={"url": "https://private-check.example/"}, headers=owner.headers
    ).json()
    analysis_id = created["analysis_id"]
    assert owner.client.get(f"/api/sites/{analysis_id}").json()["owned_by_you"] is True
    for client in (anon, other.client):
        assert client.get(f"/api/sites/{analysis_id}").status_code == 404
        assert client.get(f"/api/sites/{analysis_id}/tokens").status_code == 404
        assert client.get(f"/api/sites/{analysis_id}/screenshot").status_code == 404
    # Another user's private result is never served from the cache.
    other_created = other.client.post(
        "/api/sites/analyze", json={"url": "https://private-check.example/"}, headers=other.headers
    ).json()
    assert other_created["cached"] is False
    assert [item["id"] for item in owner.client.get("/api/sites").json()] == [analysis_id]
    assert anon.get("/api/sites").status_code == 401
    assert ipaddress.ip_address(PUBLIC)

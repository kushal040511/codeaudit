"""Risk signals and scoring on synthetic captures (no network)."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.services.web.capture import CaptureBlockedError, CaptureError, parse_capture
from app.services.web.intel import (
    CertificateInfo,
    DnsInfo,
    Registration,
    Reputation,
    hostname_matches,
    parse_rdap,
)
from app.services.web.lexical import ascii_skeleton, levenshtein, skeleton
from app.services.web.references import Reference
from app.services.web.risk import DISCLAIMER, WEIGHTS, RiskInputs, assess
from app.services.web.visual import hash_favicon, hash_screenshot
from tests.unit.web.factories import make_capture

FIXTURES = Path(__file__).parents[2] / "fixtures" / "web"
NOW = datetime(2026, 9, 17, tzinfo=UTC)


def reference(brand: str = "paypal", page: str = "login") -> Reference:
    shot = hash_screenshot((FIXTURES / "login_original.png").read_bytes())
    icon = hash_favicon((FIXTURES / "favicon_brand.png").read_bytes())
    assert shot is not None
    return Reference(
        brand,
        page,
        "https://www.paypal.com/signin",
        "https://www.paypal.com/signin",
        shot.phash,
        shot.dhash,
        False,
        icon.sha256,
        icon.phash,
        f"web-references/{brand}/{page}.png",
        "2026-09-01T00:00:00+00:00",
    )


def inputs(**overrides: Any) -> RiskInputs:
    base = RiskInputs(
        capture=make_capture(),
        registration=Registration(
            registered_at=NOW - timedelta(days=4000), registrar="MarkMonitor Inc."
        ),
        dns=DnsInfo(a=["93.184.216.34"], mx=["mx.example.com"], ns=["ns1.example.com"]),
        certificate=CertificateInfo(
            issuer="DigiCert Inc",
            not_before=NOW - timedelta(days=60),
            san=["example.com", "www.example.com"],
            hostname_matches=True,
            trusted=True,
        ),
        reputation=[Reputation("google_safe_browsing", False), Reputation("openphish", False)],
        screenshot=hash_screenshot((FIXTURES / "landing_other.png").read_bytes()),
        favicon=hash_favicon((FIXTURES / "favicon_other.png").read_bytes()),
        references=(reference(),),
        now=NOW,
    )
    return replace(base, **overrides)


def fired(report) -> dict[str, float]:  # type: ignore[no-untyped-def]
    return {e.signal: e.points for e in report.evidence if e.status == "fired"}


def test_established_ordinary_site_scores_low() -> None:
    report = assess(inputs())
    assert report.score == 0 and report.level == "low"
    assert fired(report) == {"domain_age_over_3y": WEIGHTS["domain_age_over_3y"]}
    assert report.disclaimer == DISCLAIMER and "not a determination" in report.disclaimer


def test_typical_credential_phishing_clone() -> None:
    capture = make_capture(
        final_url="https://paypa1-secure-login.top/signin",
        title="Log in to your PayPal account",
        forms=[
            {
                "action": "https://collector.example.net/gate.php",
                "method": "post",
                "inputs": [{"type": "email"}, {"type": "password"}],
            }
        ],
        links=["https://www.paypal.com/us/webapps/mpp/ua/privacy-full"] * 6
        + ["https://paypa1-secure-login.top/help"],
    )
    report = assess(
        inputs(
            capture=capture,
            registration=Registration(
                registered_at=NOW - timedelta(days=3), registrar="NameSilo, LLC"
            ),
            dns=DnsInfo(a=["203.0.113.9"]),
            certificate=CertificateInfo(
                issuer="Let's Encrypt",
                not_before=NOW - timedelta(days=2),
                san=["paypa1-secure-login.top"],
                hostname_matches=True,
                trusted=True,
            ),
            screenshot=hash_screenshot((FIXTURES / "login_clone.png").read_bytes()),
            favicon=hash_favicon((FIXTURES / "favicon_brand.png").read_bytes()),
        )
    )
    signals = fired(report)
    for expected in (
        "visual_match_strong",
        "favicon_match",
        "domain_age_under_7d",
        "brand_in_domain",
        "tld_high_risk",
        "brand_in_title",
        "password_field",
        "credentials_cross_domain_form",
        "links_to_brand",
        "cert_new",
        "no_mx_record",
    ):
        assert expected in signals, expected
    assert report.score == 100 and report.level == "very_high"
    assert report.impersonated_brand == "paypal"
    assert (
        report.visual_match is not None
        and report.visual_match.brand == "paypal"
        and report.visual_match.similarity >= 0.9
    )
    labels = " | ".join(e.label for e in report.evidence)
    assert "visual similarity to the PayPal login page" in labels
    assert "registered 3 days ago" in labels
    assert "Password field posts to a different domain (example.net)" in labels
    # The summary names the strongest reasons.
    assert report.summary.split("; ")[0].endswith("visual similarity to the PayPal login page")


def test_evidence_points_add_up_to_the_score_before_clamping() -> None:
    capture = make_capture(
        final_url="http://login-docusign.example.xyz/",
        forms=[{"action": "http://login-docusign.example.xyz/p", "inputs": [{"type": "password"}]}],
    )
    report = assess(
        inputs(
            capture=capture,
            registration=Registration(registered_at=NOW - timedelta(days=20)),
            certificate=None,
        )
    )
    total = sum(e.points for e in report.evidence)
    assert 0 < total < 100 and report.score == round(total)


def test_official_brand_domain_is_not_flagged_for_looking_like_the_brand() -> None:
    capture = make_capture(
        final_url="https://www.paypal.com/signin",
        title="Log in to your PayPal account",
        forms=[{"action": "https://www.paypal.com/signin", "inputs": [{"type": "password"}]}],
        links=["https://www.paypal.com/x"] * 10,
    )
    report = assess(
        inputs(
            capture=capture,
            screenshot=hash_screenshot((FIXTURES / "login_original.png").read_bytes()),
            favicon=hash_favicon((FIXTURES / "favicon_brand.png").read_bytes()),
        )
    )
    signals = fired(report)
    assert "visual_match_strong" not in signals and "favicon_match" not in signals
    assert "brand_in_title" not in signals and "links_to_brand" not in signals
    assert report.impersonated_brand is None
    assert any(e.signal == "official_brand_domain" for e in report.evidence)
    assert report.score <= 10  # the password field alone


def test_legitimate_page_mentioning_brands_is_not_flagged() -> None:
    # "Pay with PayPal" / "Sign in with Google" on an ordinary shop without a login form.
    capture = make_capture(
        final_url="https://shop.example.com/checkout",
        title="Checkout – Example Shop",
        text="Pay with PayPal or sign in with Google.",
    )
    assert fired(assess(inputs(capture=capture))) == {
        "domain_age_over_3y": WEIGHTS["domain_age_over_3y"]
    }


@pytest.mark.parametrize(
    ("host", "signal"),
    [
        ("xn--pypal-4ve.com", "homoglyph_brand"),  # Cyrillic а
        ("paypa1.com", "homoglyph_brand"),  # digit look-alike
        ("paypall.com", "typosquat_brand"),
        ("netfIix.com", "typosquat_brand"),  # hostnames are case-insensitive: netfiix
        ("rnicrosoft.com", "homoglyph_brand"),
        ("paypal-verify.com", "brand_in_domain"),
        ("secure-coinbase-wallet.io", "brand_in_domain"),
        ("paypal.com.account-check.net", "brand_in_subdomain"),
    ],
)
def test_lookalike_domains(host: str, signal: str) -> None:
    capture = make_capture(final_url=f"https://{host.lower()}/")
    assert signal in fired(assess(inputs(capture=capture)))


def test_unrelated_domains_are_not_lookalikes() -> None:
    for host in ("apply.com", "chaser.com", "github.com", "adobo.com", "steamy.com", "goggles.com"):
        signals = fired(assess(inputs(capture=make_capture(final_url=f"https://{host}/"))))
        assert not {"homoglyph_brand", "typosquat_brand"} & set(signals), host


def test_reputation_listings_dominate_and_unavailable_sources_are_reported() -> None:
    listed = assess(
        inputs(
            reputation=[
                Reputation("google_safe_browsing", True, detail="SOCIAL_ENGINEERING"),
                Reputation("openphish", None, error="feed unavailable"),
            ]
        )
    )
    assert "reputation_safe_browsing" in fired(listed)
    unavailable = [e for e in listed.evidence if e.status == "unavailable"]
    assert any("OpenPhish: not checked" in e.label for e in unavailable)


def test_missing_intel_is_unavailable_not_guessed() -> None:
    report = assess(
        inputs(
            registration=Registration(error="no RDAP record"),
            certificate=CertificateInfo(error="TLS handshake failed"),
            dns=None,
            screenshot=None,
            favicon=None,
        )
    )
    statuses = {e.signal: e.status for e in report.evidence}
    assert statuses["domain_age"] == "unavailable"
    assert statuses["certificate"] == "unavailable"
    assert statuses["visual_similarity"] == "unavailable"
    assert report.score == 0


def test_certificate_problems() -> None:
    cert = CertificateInfo(
        issuer="Unknown CA",
        not_before=NOW - timedelta(days=1),
        san=["other.example"],
        hostname_matches=False,
        trusted=False,
        verify_error="self-signed certificate",
    )
    signals = fired(assess(inputs(certificate=cert)))
    assert {"cert_untrusted", "cert_hostname_mismatch", "cert_new"} <= set(signals)


def test_insecure_credential_page() -> None:
    capture = make_capture(
        final_url="http://example.com/login",
        forms=[
            {
                "action": "http://example.com/login",
                "inputs": [{"type": "password"}, {"type": "text", "card_like": True}],
            }
        ],
    )
    signals = fired(assess(inputs(capture=capture, certificate=None)))
    assert {"no_https", "password_field", "payment_fields", "sensitive_fields_insecure"} <= set(
        signals
    )


def test_lexical_helpers() -> None:
    assert levenshtein("paypal", "paypa1") == 1 and levenshtein("kitten", "sitting") == 3
    assert skeleton("xn--pypal-4ve") == "paypal"
    assert ascii_skeleton("rnicrosoft") == "microsoft"


def test_certificate_and_rdap_parsing() -> None:
    assert hostname_matches("www.example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])
    assert not hostname_matches("example.com", ["*.example.com"])
    rdap = parse_rdap(
        {
            "events": [
                {"eventAction": "registration", "eventDate": "2026-09-14T10:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-09-14T10:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Example Registrar, Inc."],
                        ],
                    ],
                }
            ],
        }
    )
    assert (
        rdap.registered_at == datetime(2026, 9, 14, 10, tzinfo=UTC)
        and rdap.registrar == "Example Registrar, Inc."
    )


# ------------------------------------------------------------------ capture output parsing


def write_capture(tmp_path: Path, data: dict[str, Any]) -> Path:
    import json

    (tmp_path / "capture.json").write_text(json.dumps(data))
    return tmp_path


def test_redirect_to_private_address_in_browser_chain_fails_the_capture(tmp_path: Path) -> None:
    out = write_capture(
        tmp_path,
        {
            "final_url": "http://169.254.169.254/latest/meta-data/",
            "redirect_chain": [
                {"url": "https://public.example/", "status": 302},
                {"url": "http://169.254.169.254/latest/meta-data/", "status": None},
            ],
            "page": {"title": "x"},
            "errors": [],
        },
    )
    with pytest.raises(CaptureBlockedError, match="metadata"):
        parse_capture("https://public.example/", out)


def test_proxy_block_reported_by_the_browser_fails_the_capture(tmp_path: Path) -> None:
    out = write_capture(
        tmp_path,
        {
            "final_url": "https://public.example/next",
            "redirect_chain": [
                {"url": "https://public.example/", "status": 302},
                {"url": "https://public.example/next", "status": 403},
            ],
            "blocked_requests": [
                {
                    "url": "https://public.example/next",
                    "reason": "rebinding.example resolves to a loopback address.",
                }
            ],
            "page": {},
            "errors": [],
        },
    )
    with pytest.raises(CaptureBlockedError, match="loopback"):
        parse_capture("https://public.example/", out)


def test_failed_navigation_and_missing_output(tmp_path: Path) -> None:
    with pytest.raises(CaptureError, match="no capture output"):
        parse_capture("https://x.example/", tmp_path)
    out = write_capture(
        tmp_path,
        {
            "final_url": "about:blank",
            "navigation_failed": True,
            "errors": ["navigation failed: net::ERR_NAME_NOT_RESOLVED at https://dead.example/"],
        },
    )
    with pytest.raises(CaptureError, match="ERR_NAME_NOT_RESOLVED"):
        parse_capture("https://dead.example/", out)


def test_too_many_redirects(tmp_path: Path) -> None:
    out = write_capture(
        tmp_path,
        {
            "final_url": "https://a.example/11",
            "redirect_chain": [{"url": f"https://a.example/{i}"} for i in range(12)],
            "too_many_redirects": True,
            "page": {},
        },
    )
    with pytest.raises(CaptureError, match="redirected more than"):
        parse_capture("https://a.example/0", out)


def test_empty_or_garbage_openphish_feed_is_unavailable_not_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx

    from app.services.web import intel

    class FakeRedis:
        def get(self, key: str) -> None:
            return None

        def set(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("a bad feed must not be cached")

    monkeypatch.setattr(intel, "get_redis", lambda: FakeRedis())
    html = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, text="<html><h1>302 Found</h1></html>")
        )
    )
    result = intel.check_openphish(["https://phish.example/"], client=html)
    assert result.listed is None and result.error


def test_brand_name_under_another_suffix() -> None:
    signals = fired(
        assess(inputs(capture=make_capture(final_url="https://www.paypal.com.bi/users/1/profile")))
    )
    assert "brand_name_other_suffix" in signals
    assert "brand_name_other_suffix" not in fired(
        assess(inputs(capture=make_capture(final_url="https://www.paypal.me/x")))
    )


def test_brands_on_public_suffix_hosts_are_recognised_as_official() -> None:
    capture = make_capture(
        final_url="https://www.gov.uk/government/organisations/hm-revenue-customs",
        title="HM Revenue & Customs - GOV.UK",
    )
    report = assess(inputs(capture=capture))
    assert any(e.signal == "official_brand_domain" for e in report.evidence)
    assert "brand_in_title" not in fired(report)


def test_shared_platform_tenants_get_no_platform_domain_age(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.web import analysis

    calls: list[str] = []
    monkeypatch.setattr(analysis, "lookup_registration", lambda domain: calls.append(domain))
    monkeypatch.setattr(analysis, "lookup_dns", lambda host, registrable: DnsInfo())
    monkeypatch.setattr(
        analysis, "check_safe_browsing", lambda urls: Reputation("google_safe_browsing", None)
    )
    monkeypatch.setattr(analysis, "check_openphish", lambda urls: Reputation("openphish", None))
    monkeypatch.setattr(analysis, "fetch_certificate", lambda host, port: CertificateInfo())
    intel = analysis.gather_intel(make_capture(final_url="https://xfinity-555.weeblysite.com/"))
    assert calls == []
    assert intel.registration is not None and "shared hosting platform" in (
        intel.registration.error or ""
    )


def test_site_builder_tenants_are_separate_sites() -> None:
    from app.services.web.intel import split_domain

    parts = split_domain("www.login-xfinityweb.weebly.com")
    assert (parts.registrable, parts.label, parts.subdomain, parts.hosting_platform) == (
        "login-xfinityweb.weebly.com",
        "login-xfinityweb",
        "www",
        True,
    )
    assert split_domain("weebly.com").hosting_platform is False

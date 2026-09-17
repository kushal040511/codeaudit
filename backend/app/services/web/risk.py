"""Phishing / clone risk assessment from independent evidence signals.

This is a heuristic risk assessment, not a verdict. Each signal reports what was
observed, whether it fired, and how many points it contributed. The score is the
sum of contributions clamped to 0-100, so the evidence list always adds up to it.

Weights are hand-set priors (model version below). The validation harness
(validation/phishing/) measures how well they separate labeled phishing and
legitimate sites and which signals carry predictive weight; update the weights
from its results rather than by intuition.
"""

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from app.services.web.brands import BRANDS, BRANDS_BY_KEY, Brand, brand_for_domain
from app.services.web.capture import Capture
from app.services.web.intel import CertificateInfo, DnsInfo, Registration, Reputation, split_domain
from app.services.web.lexical import (
    ascii_skeleton,
    levenshtein,
    mentions,
    scripts,
    skeleton,
    title_mentions,
    tokens,
)
from app.services.web.netguard import BlockedUrlError, normalize_url
from app.services.web.references import Reference
from app.services.web.visual import FaviconHashes, ImageHashes, screenshot_similarity, similarity

RISK_MODEL_VERSION = "0.1.1-prior"
DISCLAIMER = (
    "This is an automated, heuristic risk assessment based on observable signals. It is not a "
    "determination that the site is fraudulent or malicious, and a low score does not mean a site "
    "is safe. Verify independently before acting on it."
)

# Points per signal (positive = more risk, negative = evidence of legitimacy).
WEIGHTS: dict[str, float] = {
    "domain_age_under_7d": 25,
    "domain_age_under_30d": 18,
    "domain_age_under_90d": 10,
    "domain_age_under_1y": 4,
    "domain_age_over_3y": -8,
    "tld_high_risk": 8,
    "tld_elevated_risk": 4,
    "ip_address_host": 15,
    "hosting_platform": 6,
    "deep_subdomain": 5,
    "punycode": 8,
    "homoglyph_brand": 30,
    "typosquat_brand": 25,
    "brand_in_domain": 20,
    "brand_name_other_suffix": 20,
    "brand_in_subdomain": 18,
    "no_mx_record": 3,
    "no_https": 8,
    "cert_untrusted": 12,
    "cert_hostname_mismatch": 15,
    "cert_new": 5,
    "visual_match_strong": 35,
    "visual_match_moderate": 18,
    "favicon_match": 30,
    "brand_in_title": 15,
    "brand_in_text_with_credentials": 8,
    "links_to_brand": 15,
    "password_field": 8,
    "payment_fields": 10,
    "credentials_cross_domain_form": 22,
    "sensitive_fields_insecure": 15,
    "cross_domain_redirect": 4,
    "reputation_safe_browsing": 60,
    "reputation_openphish_url": 60,
    "reputation_openphish_host": 35,
}
VISUAL_STRONG = 0.90
VISUAL_MODERATE = 0.84
FAVICON_MATCH = 0.95

# TLDs with disproportionate abuse (Spamhaus "most abused TLDs", Interisle phishing
# landscape reports, 2023-2025). A weak prior only: plenty of legitimate sites use them.
HIGH_RISK_TLDS = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "top",
        "xyz",
        "icu",
        "buzz",
        "cyou",
        "rest",
        "sbs",
        "cfd",
        "bond",
        "click",
        "zip",
        "mov",
        "quest",
        "cam",
        "monster",
        "lol",
        "bar",
        "support",
    }
)
ELEVATED_RISK_TLDS = frozenset(
    {
        "online",
        "site",
        "live",
        "shop",
        "store",
        "info",
        "club",
        "vip",
        "work",
        "life",
        "pw",
        "ru",
        "cn",
        "cc",
        "ws",
        "win",
        "loan",
        "link",
        "digital",
        "app",
        "dev",
        "page",
    }
)


@dataclass
class Evidence:
    signal: str
    category: str  # domain | certificate | visual | content | reputation
    label: str  # human-readable sentence
    points: float
    status: str  # fired | clear | unavailable | info
    value: Any = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VisualMatch:
    brand: str
    brand_name: str
    page: str
    similarity: float
    reference_url: str
    screenshot_key: str | None


@dataclass
class RiskInputs:
    capture: Capture
    registration: Registration | None
    dns: DnsInfo | None
    certificate: CertificateInfo | None
    reputation: list[Reputation]
    screenshot: ImageHashes | None
    favicon: FaviconHashes | None
    references: tuple[Reference, ...]
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class RiskReport:
    score: int
    level: str
    summary: str
    evidence: list[Evidence]
    impersonated_brand: str | None
    visual_match: VisualMatch | None
    model_version: str = RISK_MODEL_VERSION
    disclaimer: str = DISCLAIMER

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "summary": self.summary,
            "evidence": [e.as_dict() for e in self.evidence],
            "impersonated_brand": self.impersonated_brand,
            "visual_match": asdict(self.visual_match) if self.visual_match else None,
            "model_version": self.model_version,
            "disclaimer": self.disclaimer,
        }


def _fired(signal: str, category: str, label: str, value: Any = None) -> Evidence:
    return Evidence(signal, category, label, WEIGHTS[signal], "fired", value)


def _info(
    signal: str, category: str, label: str, value: Any = None, status: str = "clear"
) -> Evidence:
    return Evidence(signal, category, label, 0.0, status, value)


def _host(url: str) -> str | None:
    try:
        return normalize_url(url).host
    except BlockedUrlError:
        return urlsplit(url).hostname


# ------------------------------------------------------------------------- domain


def domain_signals(inputs: RiskInputs, host: str) -> tuple[list[Evidence], Brand | None]:
    parts = split_domain(host)
    evidence: list[Evidence] = []
    official = brand_for_domain(parts.registrable, host)
    suspected: Brand | None = None

    if host.replace(".", "").isdigit() or ":" in host:
        evidence.append(
            _fired(
                "ip_address_host",
                "domain",
                f"The site is addressed by IP ({host}), not a domain name",
                host,
            )
        )

    registration = inputs.registration
    if registration is None or registration.registered_at is None:
        reason = registration.error if registration else "not looked up"
        evidence.append(
            _info(
                "domain_age",
                "domain",
                f"Registration date unavailable ({reason})",
                None,
                "unavailable",
            )
        )
    else:
        days = (inputs.now - registration.registered_at).days
        value = {
            "days": days,
            "registered_at": registration.registered_at.date().isoformat(),
            "registrar": registration.registrar,
        }
        when = f"registered {days} day{'s' if days != 1 else ''} ago"
        if days < 7:
            evidence.append(_fired("domain_age_under_7d", "domain", f"Domain {when}", value))
        elif days < 30:
            evidence.append(_fired("domain_age_under_30d", "domain", f"Domain {when}", value))
        elif days < 90:
            evidence.append(_fired("domain_age_under_90d", "domain", f"Domain {when}", value))
        elif days < 365:
            evidence.append(_fired("domain_age_under_1y", "domain", f"Domain {when}", value))
        elif days >= 3 * 365:
            evidence.append(
                _fired(
                    "domain_age_over_3y",
                    "domain",
                    f"Domain registered {days // 365} years ago",
                    value,
                )
            )
        else:
            evidence.append(_info("domain_age", "domain", f"Domain {when}", value))
        if registration.registrar:
            evidence.append(
                _info(
                    "registrar",
                    "domain",
                    f"Registrar: {registration.registrar}",
                    registration.registrar,
                    "info",
                )
            )

    tld = parts.suffix.split(".")[-1] if parts.suffix else ""
    if parts.hosting_platform:
        evidence.append(
            _fired(
                "hosting_platform",
                "domain",
                f"Hosted on a shared platform subdomain ({parts.suffix})",
                parts.suffix,
            )
        )
    elif tld in HIGH_RISK_TLDS:
        evidence.append(
            _fired(
                "tld_high_risk", "domain", f".{tld} is among the most abused top-level domains", tld
            )
        )
    elif tld in ELEVATED_RISK_TLDS:
        evidence.append(
            _fired("tld_elevated_risk", "domain", f".{tld} has elevated abuse rates", tld)
        )

    if parts.subdomain.count(".") >= 3:
        evidence.append(
            _fired(
                "deep_subdomain",
                "domain",
                f"Unusually deep subdomain ({parts.subdomain})",
                parts.subdomain,
            )
        )

    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels):
        evidence.append(
            _fired(
                "punycode",
                "domain",
                f"Domain uses internationalized characters ({skeleton(parts.label)})",
                sorted(scripts(parts.label)),
            )
        )

    if official is None and parts.label:
        label = parts.label.lower()
        label_skeleton = ascii_skeleton(label)
        for brand in BRANDS:
            if label in brand.labels and parts.registrable not in brand.domains:
                evidence.append(
                    _fired(
                        "brand_name_other_suffix",
                        "domain",
                        f"Uses the {brand.name} name under a different suffix ({parts.registrable}) than {brand.name}'s official domains",
                        {"brand": brand.key},
                    )
                )
                suspected = brand
                break
        for brand in BRANDS if suspected is None else ():
            for brand_label in brand.labels:
                if label != brand_label and (
                    label_skeleton == brand_label or skeleton(label) == brand_label
                ):
                    evidence.append(
                        _fired(
                            "homoglyph_brand",
                            "domain",
                            f"Domain imitates {brand.name} with look-alike characters ({parts.registrable})",
                            {"brand": brand.key},
                        )
                    )
                    suspected = suspected or brand
                    break
                distance = levenshtein(label, brand_label)
                # Short brand names are ordinary words one edit from many legitimate
                # domains (apple/apply), so they only match via look-alike characters.
                limit = 0 if len(brand_label) < 6 else 1 if len(brand_label) < 9 else 2
                if 0 < distance <= limit:
                    evidence.append(
                        _fired(
                            "typosquat_brand",
                            "domain",
                            f"Domain is {distance} edit{'s' if distance > 1 else ''} away from {brand_label} ({brand.name})",
                            {"brand": brand.key, "distance": distance},
                        )
                    )
                    suspected = suspected or brand
                    break
                if (
                    brand_label in tokens(label_skeleton)
                    and len(tokens(label_skeleton)) > 1
                    or (
                        len(brand_label) >= 5
                        and brand_label in label_skeleton
                        and label_skeleton != brand_label
                    )
                ):
                    evidence.append(
                        _fired(
                            "brand_in_domain",
                            "domain",
                            f"Domain contains the brand name {brand.name} but isn't an official {brand.name} domain",
                            {"brand": brand.key},
                        )
                    )
                    suspected = suspected or brand
                    break
                if brand_label in tokens(parts.subdomain) or any(
                    d in parts.subdomain for d in brand.domains
                ):
                    evidence.append(
                        _fired(
                            "brand_in_subdomain",
                            "domain",
                            f"Subdomain contains {brand.name} ({parts.subdomain}.{parts.registrable})",
                            {"brand": brand.key},
                        )
                    )
                    suspected = suspected or brand
                    break
            if suspected:
                break

    dns = inputs.dns
    if (
        dns is not None
        and dns.error is None
        and not parts.hosting_platform
        and not dns.mx
        and (dns.a or dns.aaaa)
    ):
        evidence.append(
            _fired("no_mx_record", "domain", f"{parts.registrable} has no mail (MX) records", None)
        )
    return evidence, suspected


# ------------------------------------------------------------------------- certificate


def certificate_signals(inputs: RiskInputs, final_url: str) -> list[Evidence]:
    evidence: list[Evidence] = []
    if urlsplit(final_url).scheme != "https":
        evidence.append(_fired("no_https", "certificate", "The page is served without HTTPS", None))
        return evidence
    cert = inputs.certificate
    if cert is None or cert.error:
        evidence.append(
            _info(
                "certificate",
                "certificate",
                f"Certificate unavailable ({cert.error if cert else 'not checked'})",
                None,
                "unavailable",
            )
        )
        return evidence
    value = {
        "issuer": cert.issuer,
        "subject": cert.subject,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
        "san": cert.san[:10],
    }
    evidence.append(
        _info(
            "certificate_issuer",
            "certificate",
            f"Certificate issued by {cert.issuer or 'unknown'}",
            value,
            "info",
        )
    )
    if cert.trusted is False:
        evidence.append(
            _fired(
                "cert_untrusted",
                "certificate",
                f"Certificate is not trusted ({cert.verify_error})",
                value,
            )
        )
    if cert.hostname_matches is False:
        evidence.append(
            _fired(
                "cert_hostname_mismatch",
                "certificate",
                "Certificate names don't match the domain",
                value,
            )
        )
    if cert.not_before is not None:
        age = (inputs.now - cert.not_before).days
        if age < 7:
            evidence.append(
                _fired(
                    "cert_new",
                    "certificate",
                    f"Certificate issued {age} day{'s' if age != 1 else ''} ago",
                    value,
                )
            )
    return evidence


# ------------------------------------------------------------------------- visual


def visual_signals(
    inputs: RiskInputs, official: Brand | None
) -> tuple[list[Evidence], VisualMatch | None, Brand | None]:
    evidence: list[Evidence] = []
    best: tuple[float, Reference] | None = None
    if inputs.screenshot is None:
        evidence.append(
            _info("visual_similarity", "visual", "No screenshot to compare", None, "unavailable")
        )
    elif inputs.screenshot.low_information:
        evidence.append(
            _info(
                "visual_similarity",
                "visual",
                "The page is nearly blank, so it can't be compared visually",
                None,
                "unavailable",
            )
        )
    else:
        for reference in inputs.references:
            if reference.low_information:
                continue
            score = screenshot_similarity(
                inputs.screenshot, ImageHashes(reference.phash, reference.dhash, False)
            )
            if score is not None and (best is None or score > best[0]):
                best = (score, reference)

    match: VisualMatch | None = None
    suspected: Brand | None = None
    if best is not None:
        score, reference = best
        match = VisualMatch(
            reference.brand,
            reference.brand_name,
            reference.page,
            round(score, 4),
            reference.final_url,
            reference.screenshot_key,
        )
        percent = f"{score:.0%}"
        same_brand = official is not None and official.key == reference.brand
        value = {"brand": reference.brand, "page": reference.page, "similarity": round(score, 4)}
        if same_brand:
            evidence.append(
                _info(
                    "visual_similarity",
                    "visual",
                    f"{percent} visual similarity to {reference.brand_name}, and this is an official {reference.brand_name} domain",
                    value,
                    "info",
                )
            )
        elif score >= VISUAL_STRONG:
            evidence.append(
                _fired(
                    "visual_match_strong",
                    "visual",
                    f"{percent} visual similarity to the {reference.brand_name} {reference.page} page",
                    value,
                )
            )
            suspected = BRANDS_BY_KEY.get(reference.brand)
        elif score >= VISUAL_MODERATE:
            evidence.append(
                _fired(
                    "visual_match_moderate",
                    "visual",
                    f"{percent} visual similarity to the {reference.brand_name} {reference.page} page",
                    value,
                )
            )
            suspected = BRANDS_BY_KEY.get(reference.brand)
        else:
            evidence.append(
                _info(
                    "visual_similarity",
                    "visual",
                    f"No close visual match (closest: {reference.brand_name}, {percent})",
                    value,
                )
            )

    if inputs.favicon is not None:
        for reference in inputs.references:
            if official is not None and official.key == reference.brand:
                continue
            exact = (
                reference.favicon_sha256 is not None
                and reference.favicon_sha256 == inputs.favicon.sha256
            )
            close = (
                reference.favicon_phash is not None
                and inputs.favicon.phash is not None
                and similarity(reference.favicon_phash, inputs.favicon.phash) >= FAVICON_MATCH
            )
            if exact or close:
                how = "identical" if exact else "near-identical"
                evidence.append(
                    _fired(
                        "favicon_match",
                        "visual",
                        f"Favicon is {how} to {reference.brand_name}'s",
                        {"brand": reference.brand, "exact": exact},
                    )
                )
                suspected = suspected or BRANDS_BY_KEY.get(reference.brand)
                break
    return evidence, match, suspected


# ------------------------------------------------------------------------- content


def _sensitive(inputs_list: list[dict[str, Any]]) -> tuple[bool, bool]:
    password = any(i.get("type") == "password" for i in inputs_list)
    card = any(i.get("card_like") for i in inputs_list)
    return password, card


def content_signals(
    inputs: RiskInputs, final_url: str, registrable: str, official: Brand | None
) -> tuple[list[Evidence], Brand | None]:
    capture = inputs.capture
    evidence: list[Evidence] = []
    suspected: Brand | None = None

    all_inputs = [
        i for form in capture.forms for i in form.get("inputs") or []
    ] + capture.orphan_inputs
    password, card = _sensitive(all_inputs)
    if password:
        evidence.append(_fired("password_field", "content", "The page asks for a password", None))
    if card:
        evidence.append(
            _fired("payment_fields", "content", "The page asks for payment card details", None)
        )
    if (password or card) and urlsplit(final_url).scheme != "https":
        evidence.append(
            _fired(
                "sensitive_fields_insecure",
                "content",
                "Password or card fields on a page without HTTPS",
                None,
            )
        )

    for form in capture.forms:
        form_password, form_card = _sensitive(form.get("inputs") or [])
        action = str(form.get("action") or "")
        if not (form_password or form_card) or not action.startswith(("http://", "https://")):
            continue
        action_host = _host(action)
        if action_host and split_domain(action_host).registrable != registrable:
            what = "Password" if form_password else "Card"
            evidence.append(
                _fired(
                    "credentials_cross_domain_form",
                    "content",
                    f"{what} field posts to a different domain ({split_domain(action_host).registrable})",
                    {"action": action[:300]},
                )
            )
            break

    if official is None:
        for brand in BRANDS:
            in_title = any(
                title_mentions(capture.title, keyword, brand.name) for keyword in brand.keywords
            )
            if in_title:
                evidence.append(
                    _fired(
                        "brand_in_title",
                        "content",
                        f"Page title mentions {brand.name} (\"{capture.title[:80]}\") but the domain isn't {brand.name}'s",
                        {"brand": brand.key},
                    )
                )
                suspected = brand
                break
        if suspected is None and (password or card):
            for brand in BRANDS:
                if any(mentions(capture.text[:5000], keyword) for keyword in brand.keywords):
                    evidence.append(
                        _fired(
                            "brand_in_text_with_credentials",
                            "content",
                            f"Page mentions {brand.name} and asks for credentials, on a non-{brand.name} domain",
                            {"brand": brand.key},
                        )
                    )
                    suspected = brand
                    break

        link_domains = [split_domain(h).registrable for h in (_host(u) for u in capture.links) if h]
        if len(link_domains) >= 5:
            for brand in BRANDS:
                share = sum(d in brand.domains for d in link_domains) / len(link_domains)
                if share >= 0.5:
                    evidence.append(
                        _fired(
                            "links_to_brand",
                            "content",
                            f"{share:.0%} of the page's links point to {brand.name}'s official site (typical of a copied page)",
                            {"brand": brand.key, "share": round(share, 3)},
                        )
                    )
                    suspected = suspected or brand
                    break

    chain_hosts = [_host(hop.get("url") or "") for hop in capture.redirect_chain]
    registrables = [split_domain(h).registrable for h in chain_hosts if h]
    if len(set(registrables)) > 1:
        evidence.append(
            _fired(
                "cross_domain_redirect",
                "content",
                f"Redirected across domains: {' → '.join(dict.fromkeys(registrables))}",
                registrables,
            )
        )
    return evidence, suspected


# ------------------------------------------------------------------------- reputation


def reputation_signals(
    inputs: RiskInputs, parts_platform: bool, official: Brand | None
) -> list[Evidence]:
    evidence: list[Evidence] = []
    for rep in inputs.reputation:
        name = "Google Safe Browsing" if rep.source == "google_safe_browsing" else "OpenPhish"
        if rep.listed is None:
            evidence.append(
                _info(
                    f"reputation_{rep.source}",
                    "reputation",
                    f"{name}: not checked ({rep.error})",
                    None,
                    "unavailable",
                )
            )
        elif not rep.listed:
            evidence.append(
                _info(
                    f"reputation_{rep.source}",
                    "reputation",
                    f"{name}: not listed (fresh phishing pages often aren't yet)",
                    None,
                )
            )
        elif rep.source == "google_safe_browsing":
            evidence.append(
                _fired(
                    "reputation_safe_browsing",
                    "reputation",
                    f"Listed by Google Safe Browsing ({rep.detail})",
                    rep.detail,
                )
            )
        elif rep.detail and rep.detail.startswith("host listed"):
            if official is None and not parts_platform:
                evidence.append(
                    _fired(
                        "reputation_openphish_host",
                        "reputation",
                        f"Host is listed in the OpenPhish feed ({rep.detail})",
                        rep.detail,
                    )
                )
        else:
            evidence.append(
                _fired(
                    "reputation_openphish_url",
                    "reputation",
                    "URL is listed in the OpenPhish feed",
                    rep.detail,
                )
            )
    return evidence


# ------------------------------------------------------------------------- assessment


def level_for(score: int) -> str:
    if score >= 70:
        return "very_high"
    if score >= 45:
        return "high"
    if score >= 20:
        return "moderate"
    return "low"


def assess(inputs: RiskInputs) -> RiskReport:
    final_url = inputs.capture.final_url
    host = _host(final_url) or ""
    parts = split_domain(host)
    official = brand_for_domain(parts.registrable, host)

    domain_evidence, lexical_brand = domain_signals(inputs, host)
    visual_evidence, match, visual_brand = visual_signals(inputs, official)
    content_evidence, content_brand = content_signals(
        inputs, final_url, parts.registrable, official
    )
    evidence = [
        *reputation_signals(inputs, parts.hosting_platform, official),
        *visual_evidence,
        *domain_evidence,
        *content_evidence,
        *certificate_signals(inputs, final_url),
    ]
    if official is not None:
        evidence.insert(
            0,
            _info(
                "official_brand_domain",
                "domain",
                f"{parts.registrable} is an official {official.name} domain",
                {"brand": official.key},
                "info",
            ),
        )

    raw = sum(e.points for e in evidence)
    score = int(round(max(0.0, min(100.0, raw))))
    fired = sorted((e for e in evidence if e.points > 0), key=lambda e: -e.points)
    summary = "; ".join(e.label for e in fired[:3]) if fired else "No risk signals fired."
    brand = visual_brand or lexical_brand or content_brand
    return RiskReport(
        score=score,
        level=level_for(score),
        summary=summary,
        evidence=sorted(evidence, key=lambda e: (-abs(e.points), e.category)),
        impersonated_brand=brand.key if brand and official is None else None,
        visual_match=match,
    )

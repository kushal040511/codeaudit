"""External facts about a site: registration (RDAP), DNS, TLS certificate, reputation.

Every lookup is best-effort: failures become `None` / an `error` string and the
corresponding risk signal is reported as unavailable, never guessed.

Network rules:
- The TLS check connects to the target itself, so it resolves through netguard
  and connects to the verified address (pinned), with SNI set to the hostname.
- RDAP, Safe Browsing and OpenPhish are fixed third-party services; RDAP redirects
  (rdap.org -> registry) are followed manually and each hop is validated.
"""

import json
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, cast

import dns.exception
import dns.resolver
import httpx
import tldextract
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.config import get_settings
from app.core.redis_client import get_redis
from app.services.web.netguard import BlockedUrlError, normalize_url, resolve_public

logger = logging.getLogger(__name__)

MAX_RDAP_REDIRECTS = 3
TLS_TIMEOUT_SECONDS = 8.0


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # Bundled Public Suffix List snapshot: no network fetch at runtime.
    # Private suffixes (web.app, github.io, blogspot.com...) count as suffixes, so
    # tenants of hosting platforms are separate sites.
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


@dataclass(frozen=True)
class DomainParts:
    host: str
    subdomain: str
    label: str  # registrable label without suffix, e.g. "paypal"
    suffix: str  # "com", "co.uk"
    registrable: str  # "paypal.co.uk"; the host itself for IPs / unknown suffixes
    hosting_platform: bool  # suffix is a private PSL entry (e.g. web.app, github.io)


# Shared hosting and site-builder platforms whose tenants get subdomains but that are
# not in the Public Suffix List's private section. Treated like private suffixes.
HOSTING_PLATFORMS = frozenset(
    {
        "weebly.com",
        "weeblysite.com",
        "godaddysites.com",
        "wixsite.com",
        "wixstudio.io",
        "square.site",
        "webflow.io",
        "framer.app",
        "framer.website",
        "gitbook.io",
        "notion.site",
        "glitch.me",
        "replit.app",
        "repl.co",
        "replit.dev",
        "railway.app",
        "onrender.com",
        "000webhostapp.com",
        "wordpress.com",
        "carrd.co",
        "mystrikingly.com",
        "jimdosite.com",
        "site123.me",
        "yolasite.com",
        "webnode.page",
        "tilda.ws",
        "myshopify.com",
        "hstn.me",
        "ukit.me",
        "canva.site",
        "my.canva.site",
        "typedream.app",
        "glide.page",
        "softr.app",
        "wiki.gd",
        "blogspot.com",
        "bubbleapps.io",
        "hpage.com",
    }
)


def split_domain(host: str) -> DomainParts:
    parts = _extractor()(host)
    registrable = parts.top_domain_under_public_suffix or host
    if registrable in HOSTING_PLATFORMS and parts.subdomain:
        tenant = parts.subdomain.split(".")[-1]
        subdomain = ".".join(parts.subdomain.split(".")[:-1])
        return DomainParts(host, subdomain, tenant, registrable, f"{tenant}.{registrable}", True)
    return DomainParts(
        host, parts.subdomain, parts.domain, parts.suffix, registrable, bool(parts.is_private)
    )


# ------------------------------------------------------------------------- RDAP


@dataclass
class Registration:
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    registrar: str | None = None
    error: str | None = None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_rdap(payload: dict[str, Any]) -> Registration:
    result = Registration()
    for event in payload.get("events") or []:
        action = str(event.get("eventAction", "")).lower()
        if action == "registration":
            result.registered_at = _parse_time(event.get("eventDate"))
        elif action == "expiration":
            result.expires_at = _parse_time(event.get("eventDate"))
    for entity in payload.get("entities") or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray") or []
            for item in vcard[1] if len(vcard) > 1 else []:
                if item and item[0] == "fn":
                    result.registrar = str(item[3])[:200]
            if result.registrar is None:
                names = [p.get("value") for p in entity.get("publicIds") or []]
                result.registrar = next((str(n) for n in names if n), None)
    return result


def lookup_registration(domain: str, client: httpx.Client | None = None) -> Registration:
    settings = get_settings()
    url = f"{settings.rdap_bootstrap_url.rstrip('/')}/domain/{domain}"
    own = client is None
    http = client or httpx.Client(timeout=settings.web_http_timeout_seconds, follow_redirects=False)
    try:
        for _ in range(MAX_RDAP_REDIRECTS + 1):
            target = normalize_url(url)
            if client is None:
                resolve_public(target.host, target.port)
            response = http.get(url, headers={"Accept": "application/rdap+json"})
            if response.is_redirect and response.headers.get("location"):
                url = str(httpx.URL(url).join(response.headers["location"]))
                continue
            if response.status_code == 404:
                return Registration(error="no RDAP record (registry may not publish RDAP)")
            if response.status_code != 200:
                return Registration(error=f"RDAP lookup failed (HTTP {response.status_code})")
            return parse_rdap(response.json())
        return Registration(error="too many RDAP redirects")
    except (httpx.HTTPError, ValueError, BlockedUrlError) as exc:
        return Registration(error=f"RDAP lookup failed ({type(exc).__name__})")
    finally:
        if own:
            http.close()


# ------------------------------------------------------------------------- DNS


@dataclass
class DnsInfo:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    error: str | None = None


def lookup_dns(host: str, registrable: str) -> DnsInfo:
    info = DnsInfo()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    queries = (
        (host, "A", info.a),
        (host, "AAAA", info.aaaa),
        (registrable, "MX", info.mx),
        (registrable, "NS", info.ns),
    )
    failures = 0
    for name, record, bucket in queries:
        try:
            answer = resolver.resolve(name, record)
            bucket.extend(sorted(str(r).rstrip(".") for r in answer)[:20])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException as exc:
            failures += 1
            logger.debug("dns %s %s failed: %s", name, record, exc)
    if failures == len(queries):
        info.error = "DNS lookups failed"
    return info


# ------------------------------------------------------------------------- TLS


@dataclass
class CertificateInfo:
    issuer: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    san: list[str] = field(default_factory=list)
    hostname_matches: bool | None = None
    trusted: bool | None = None
    verify_error: str | None = None
    error: str | None = None


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


def _name(name: x509.Name) -> str | None:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        values = name.get_attributes_for_oid(oid)
        if values:
            return str(values[0].value)[:200]
    return None


def parse_certificate(der: bytes, host: str) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der)
    info = CertificateInfo(
        issuer=_name(cert.issuer),
        subject=_name(cert.subject),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.san = [str(n) for n in extension.value.get_values_for_type(x509.DNSName)][:100]
    except x509.ExtensionNotFound:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info.san = [str(cn[0].value)] if cn else []
    info.hostname_matches = hostname_matches(host, info.san)
    return info


def fetch_certificate(host: str, port: int = 443) -> CertificateInfo:
    try:
        addresses = resolve_public(host, port)
    except BlockedUrlError as exc:
        return CertificateInfo(error=exc.reason)

    def handshake(verify: bool) -> bytes:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        last: Exception | None = None
        for address in addresses:
            try:
                with socket.create_connection(
                    (str(address), port), timeout=TLS_TIMEOUT_SECONDS
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        return tls.getpeercert(binary_form=True) or b""
            except ssl.SSLCertVerificationError:
                raise
            except OSError as exc:
                last = exc
        raise last or OSError("unreachable")

    trusted: bool | None
    verify_error: str | None = None
    try:
        der = handshake(verify=True)
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        trusted, verify_error = (
            False,
            (exc.verify_message or "certificate verification failed")[:200],
        )
        try:
            der = handshake(verify=False)
        except (OSError, ssl.SSLError) as inner:
            return CertificateInfo(
                trusted=False,
                verify_error=verify_error,
                error=f"TLS handshake failed ({type(inner).__name__})",
            )
    except (OSError, ssl.SSLError) as exc:
        return CertificateInfo(error=f"TLS handshake failed ({type(exc).__name__})")
    if not der:
        return CertificateInfo(error="no certificate presented")
    info = parse_certificate(der, host)
    info.trusted, info.verify_error = trusted, verify_error
    return info


# ------------------------------------------------------------------------- reputation


@dataclass
class Reputation:
    source: str
    listed: bool | None  # None: not checked (unconfigured or failed)
    detail: str | None = None
    error: str | None = None


SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(urls: list[str], client: httpx.Client | None = None) -> Reputation:
    settings = get_settings()
    key = settings.google_safe_browsing_api_key
    if key is None or not key.get_secret_value():
        return Reputation(
            "google_safe_browsing", None, error="not configured (GOOGLE_SAFE_BROWSING_API_KEY)"
        )
    body = {
        "client": {"clientId": "codeaudit", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in dict.fromkeys(urls)][:500],
        },
    }
    own = client is None
    http = client or httpx.Client(timeout=settings.web_http_timeout_seconds, follow_redirects=False)
    try:
        response = http.post(SAFE_BROWSING_URL, params={"key": key.get_secret_value()}, json=body)
        if response.status_code != 200:
            return Reputation(
                "google_safe_browsing", None, error=f"lookup failed (HTTP {response.status_code})"
            )
        matches = response.json().get("matches") or []
    except (httpx.HTTPError, ValueError) as exc:
        return Reputation(
            "google_safe_browsing", None, error=f"lookup failed ({type(exc).__name__})"
        )
    finally:
        if own:
            http.close()
    if not matches:
        return Reputation("google_safe_browsing", False)
    kinds = sorted({str(m.get("threatType")) for m in matches})
    return Reputation("google_safe_browsing", True, detail=", ".join(kinds))


OPENPHISH_KEY = "codeaudit:openphish:feed"
MIN_FEED_ENTRIES = 20


def load_openphish(client: httpx.Client | None = None) -> set[str]:
    """Normalized URLs and hosts in the OpenPhish community feed (cached in Redis)."""
    settings = get_settings()
    redis = get_redis()
    cached = cast(bytes | None, redis.get(OPENPHISH_KEY))
    if cached:
        return set(json.loads(cached))
    own = client is None
    http = client or httpx.Client(timeout=settings.web_http_timeout_seconds, follow_redirects=True)
    try:
        response = http.get(settings.openphish_feed_url)
        response.raise_for_status()
    finally:
        if own:
            http.close()
    entries: set[str] = set()
    for line in response.text.splitlines()[:100_000]:
        try:
            url = normalize_url(line.strip())
        except BlockedUrlError:
            continue
        entries.add(url.url)
        entries.add(f"host:{url.host}")
    if len(entries) < MIN_FEED_ENTRIES:
        # An empty or non-feed response (e.g. an HTML error page) must not read as "not listed".
        raise OSError(f"feed returned only {len(entries)} usable entries")
    redis.set(OPENPHISH_KEY, json.dumps(sorted(entries)), ex=settings.openphish_cache_seconds)
    return entries


def check_openphish(urls: list[str], client: httpx.Client | None = None) -> Reputation:
    try:
        feed = load_openphish(client)
    except (httpx.HTTPError, OSError) as exc:
        return Reputation("openphish", None, error=f"feed unavailable ({type(exc).__name__})")
    for raw in urls:
        try:
            url = normalize_url(raw)
        except BlockedUrlError:
            continue
        if url.url in feed:
            return Reputation("openphish", True, detail=f"URL listed: {url.url[:200]}")
        if f"host:{url.host}" in feed:
            return Reputation("openphish", True, detail=f"host listed: {url.host}")
    return Reputation("openphish", False)

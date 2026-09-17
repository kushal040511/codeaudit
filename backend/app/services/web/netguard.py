"""SSRF guard for fetching user-supplied URLs.

Users give us arbitrary URLs and we fetch them server-side, so every hop must be
checked. The layers:

1. `normalize_url` accepts only http/https URLs without credentials, on an allowed
   port, and canonicalises the host (IDNA, trailing dot, browser-style IPv4 forms
   such as `http://2130706433/` or `http://0x7f.1/`).
2. `check_host` rejects forbidden hostnames (localhost, *.internal, cloud metadata
   names) and, for IP literals, forbidden addresses.
3. `resolve_public` resolves a hostname and rejects it if *any* address is
   private, loopback, link-local, reserved, multicast, a cloud metadata address,
   or an IPv6 form embedding such an IPv4 address (mapped, 6to4, Teredo, NAT64).
   Callers connect to the returned addresses, never re-resolve, so a DNS answer
   can't change between the check and the connection (DNS rebinding).

The browser never resolves or connects by itself: all its traffic goes through the
egress proxy (egress_proxy.py), which applies the same checks to every request,
including redirects and subresources.
"""

import ipaddress
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Sequence[str]]

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_URL_LENGTH = 2048

# Explicitly blocked even where the address space is technically public.
METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, GCP, Azure IMDS, OpenStack, DigitalOcean
        "169.254.170.2",  # AWS ECS task metadata
        "169.254.169.253",  # AWS DNS
        "168.63.129.16",  # Azure wireserver (public range)
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IMDS over IPv6
        "fd00:ec2::23",
    )
)
FORBIDDEN_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "kubernetes",
        "kubernetes.default",
        "host.docker.internal",
        "gateway.docker.internal",
    }
)
FORBIDDEN_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".lan",
    ".svc",
    ".cluster.local",
)
NAT64 = ipaddress.ip_network("64:ff9b::/96")
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class BlockedUrlError(ValueError):
    """The URL is not allowed; `reason` is safe to show to users."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NormalizedUrl:
    scheme: str
    host: str  # lowercase ASCII (punycode) hostname, or an IP literal without brackets
    port: int
    path: str
    query: str
    ip: IPAddress | None  # set when the host is an IP literal

    @property
    def default_port(self) -> bool:
        return self.port == (443 if self.scheme == "https" else 80)

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if isinstance(self.ip, ipaddress.IPv6Address) else self.host
        return host if self.default_port else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return urlunsplit(SplitResult(self.scheme, self.netloc, self.path or "/", self.query, ""))


def forbidden_ip_reason(ip: IPAddress) -> str | None:
    """Why connecting to `ip` is not allowed, or None if it's a public address."""
    if ip in METADATA_ADDRESSES:
        return "a cloud metadata address"
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: ipaddress.IPv4Address | None = ip.ipv4_mapped or ip.sixtofour
        if ip.teredo:
            embedded = ip.teredo[1]
        if ip in NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            inner = forbidden_ip_reason(embedded)
            return f"an IPv6 form of {embedded} ({inner})" if inner else None
        if ip.scope_id:
            return "a scoped (link-local) IPv6 address"
    checks = (
        (ip.is_loopback, "a loopback address"),
        (ip.is_unspecified, "an unspecified address"),
        (ip.is_link_local, "a link-local address"),
        (ip.is_private, "a private network address"),
        (ip.is_multicast, "a multicast address"),
        (ip.is_reserved, "a reserved address"),
        (getattr(ip, "is_site_local", False), "a site-local address"),
    )
    for flagged, reason in checks:
        if flagged:
            return reason
    if not ip.is_global:
        return "a non-public address"
    return None


def parse_ipv4_like(host: str) -> ipaddress.IPv4Address | None:
    """IPv4 literal forms browsers accept (WHATWG URL): decimal, hex, octal, 1-4 parts.

    Returns None if the host isn't numeric; raises BlockedUrlError if it is numeric
    but invalid (never let a numeric-looking host fall through to DNS).
    """
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not parts or not re.fullmatch(r"(0x[0-9a-f]*|[0-9]+)", parts[-1]):
        return None
    if len(parts) > 4:
        raise BlockedUrlError("Invalid IP address.")
    numbers: list[int] = []
    for part in parts:
        try:
            if part.startswith("0x"):
                numbers.append(int(part[2:] or "0", 16))
            elif len(part) > 1 and part.startswith("0"):
                numbers.append(int(part, 8))
            else:
                numbers.append(int(part, 10))
        except ValueError:
            raise BlockedUrlError("Invalid IP address.") from None
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise BlockedUrlError("Invalid IP address.")
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return ipaddress.IPv4Address(value)


def _hostname_reason(host: str) -> str | None:
    if host in FORBIDDEN_HOSTNAMES or host.endswith(FORBIDDEN_SUFFIXES):
        return "an internal hostname"
    if "." not in host:
        return "a single-label hostname"
    return None


def normalize_url(raw: str) -> NormalizedUrl:
    text = raw.strip()
    if not text or len(text) > MAX_URL_LENGTH or any(ord(c) < 33 for c in text):
        raise BlockedUrlError("Enter a valid http(s) URL.")
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedUrlError("Only http and https URLs can be analyzed.")
    if "@" in parts.netloc or parts.username or parts.password:
        raise BlockedUrlError("URLs with credentials are not allowed.")
    if "\\" in parts.netloc:
        raise BlockedUrlError("Enter a valid http(s) URL.")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise BlockedUrlError("Invalid port.") from None
    if port not in ALLOWED_PORTS:
        raise BlockedUrlError(f"Port {port} is not allowed (only 80, 443, 8080 and 8443).")

    raw_host = parts.hostname
    if not raw_host:
        raise BlockedUrlError("The URL has no host.")
    ip: IPAddress | None = None
    if parts.netloc.split("@")[-1].startswith("["):
        try:
            ip = ipaddress.IPv6Address(raw_host)
        except ValueError:
            raise BlockedUrlError("Invalid IPv6 address.") from None
        host = str(ip)
    else:
        try:
            host = raw_host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise BlockedUrlError("Invalid hostname.") from None
        ip = parse_ipv4_like(host)
        if ip is not None:
            host = str(ip)
        elif len(host) > 253 or not all(_HOST_LABEL.match(label) for label in host.split(".")):
            raise BlockedUrlError("Invalid hostname.")
    normalized = NormalizedUrl(scheme, host, port, parts.path or "/", parts.query, ip)
    check_host(normalized)
    return normalized


def check_host(url: NormalizedUrl) -> None:
    if url.ip is not None:
        if reason := forbidden_ip_reason(url.ip):
            raise BlockedUrlError(f"The URL points to {reason}.")
    elif reason := _hostname_reason(url.host):
        raise BlockedUrlError(f"The URL points to {reason}.")


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def resolve_public(host: str, port: int, resolver: Resolver = system_resolver) -> list[IPAddress]:
    """Addresses for `host`, all verified public. Connect only to these."""
    try:
        literal: IPAddress | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if reason := forbidden_ip_reason(literal):
            raise BlockedUrlError(f"The URL points to {reason}.")
        return [literal]
    if reason := _hostname_reason(host):
        raise BlockedUrlError(f"The URL points to {reason}.")
    try:
        answers = resolver(host, port)
    except (OSError, UnicodeError):
        raise BlockedUrlError(f"{host} could not be resolved.") from None
    addresses: list[IPAddress] = []
    for answer in answers:
        address = ipaddress.ip_address(answer.split("%")[0])
        if "%" in answer:
            raise BlockedUrlError(f"{host} resolves to a scoped (link-local) IPv6 address.")
        if reason := forbidden_ip_reason(address):
            raise BlockedUrlError(f"{host} resolves to {reason}.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise BlockedUrlError(f"{host} could not be resolved.")
    return addresses


def validate_url(
    raw: str, resolver: Resolver = system_resolver
) -> tuple[NormalizedUrl, list[IPAddress]]:
    url = normalize_url(raw)
    return url, resolve_public(url.host, url.port, resolver)

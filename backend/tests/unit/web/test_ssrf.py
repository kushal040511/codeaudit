"""SSRF protection: URL validation, resolution and the browser's egress proxy."""

import asyncio
import ipaddress
from collections.abc import Sequence

import pytest

from app.services.web.egress_proxy import EgressProxy
from app.services.web.netguard import (
    BlockedUrlError,
    forbidden_ip_reason,
    normalize_url,
    resolve_public,
    validate_url,
)

PUBLIC = "93.184.216.34"


def resolver_for(mapping: dict[str, Sequence[str]]):  # type: ignore[no-untyped-def]
    calls: list[str] = []

    def resolve(host: str, port: int) -> Sequence[str]:
        calls.append(host)
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


# ---------------------------------------------------------------- direct addresses


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.1/",
        "http://0/",
        "http://0.0.0.0/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f000001/",  # hex
        "http://0x7f.0.0.1/",
        "http://017700000001/",  # octal
        "http://0177.0.0.1/",
        "http://10.0.0.5/",
        "http://172.16.3.4/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",  # CGNAT
        "http://198.18.0.1/",  # benchmarking
        "http://224.0.0.1/",  # multicast
        "http://240.0.0.1/",  # reserved
        "http://255.255.255.255/",
        "https://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/v2/credentials",
        "http://168.63.129.16/machine",  # Azure wireserver, public range
        "http://100.100.100.200/latest/meta-data",
        "http://[::1]/",
        "http://[::]/",
        "http://[0:0:0:0:0:0:0:1]/",
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::127.0.0.1]/",  # IPv4-compatible (deprecated)
        "http://[2002:7f00:1::]/",  # 6to4 of 127.0.0.1
        "http://[2002:a9fe:a9fe::]/",  # 6to4 of 169.254.169.254
        "http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/",  # Teredo embedding 127.0.0.1
        "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 of 169.254.169.254
        "http://[fe80::1]/",
        "http://[fe80::1%25eth0]/",
        "http://[fc00::1]/",
        "http://[fd00:ec2::254]/",
        "http://[ff02::1]/",
    ],
)
def test_private_and_special_addresses_are_rejected(url: str) -> None:
    with pytest.raises(BlockedUrlError):
        normalize_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://LOCALHOST./",
        "http://foo.localhost/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/",
        "http://instance-data/latest/",
        "http://db.internal/",
        "http://printer.local/",
        "http://host.docker.internal/",
        "http://kubernetes.default.svc/",
        "http://intranet/",  # single label
    ],
)
def test_internal_hostnames_are_rejected(url: str) -> None:
    with pytest.raises(BlockedUrlError):
        normalize_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/",
        "gopher://example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "http://user:pass@example.com/",
        "http://example.com@169.254.169.254/",
        "http://example.com:22/",
        "http://example.com:6379/",
        "http://exa mple.com/",
        "http://example.com\\@evil.com/",
        "",
        "http://" + "a" * 3000 + ".com/",
    ],
)
def test_other_schemes_credentials_ports_and_junk_are_rejected(url: str) -> None:
    with pytest.raises(BlockedUrlError):
        normalize_url(url)


def test_public_urls_are_normalized() -> None:
    url = normalize_url("HTTPS://Example.COM./login?x=1#frag")
    assert (url.scheme, url.host, url.port, url.path, url.query) == (
        "https",
        "example.com",
        443,
        "/login",
        "x=1",
    )
    assert url.url == "https://example.com/login?x=1"
    assert normalize_url("example.com").url == "https://example.com/"
    idn = normalize_url("https://pаypal.com/")  # Cyrillic а
    assert idn.host == "xn--pypal-4ve.com"
    assert normalize_url(f"http://{PUBLIC}:8080/").ip == ipaddress.ip_address(PUBLIC)
    assert normalize_url("http://[2606:4700:4700::1111]/").url == "http://[2606:4700:4700::1111]/"


# ---------------------------------------------------------------- DNS


def test_hostnames_resolving_to_private_addresses_are_rejected() -> None:
    resolver = resolver_for(
        {
            "evil.example": ["127.0.0.1"],
            "meta.example": ["169.254.169.254"],
            "v6.example": ["::1"],
            "mapped.example": ["::ffff:10.0.0.1"],
            "scoped.example": ["fe80::1%eth0"],
            "mixed.example": [PUBLIC, "10.0.0.7"],  # any private answer fails the whole host
        }
    )
    for host in [
        "evil.example",
        "meta.example",
        "v6.example",
        "mapped.example",
        "scoped.example",
        "mixed.example",
    ]:
        with pytest.raises(BlockedUrlError):
            resolve_public(host, 443, resolver)
    with pytest.raises(BlockedUrlError, match="could not be resolved"):
        resolve_public("nxdomain.example", 443, resolver)


def test_validate_url_returns_the_addresses_to_pin() -> None:
    url, addresses = validate_url(
        "https://shop.example/", resolver_for({"shop.example": [PUBLIC, PUBLIC]})
    )
    assert url.host == "shop.example" and addresses == [ipaddress.ip_address(PUBLIC)]


def test_forbidden_ip_reason_accepts_public_addresses() -> None:
    for address in (
        PUBLIC,
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2002:5db8:d822::",
    ):  # 6to4 of public
        assert forbidden_ip_reason(ipaddress.ip_address(address)) is None, address


# ---------------------------------------------------------------- egress proxy


class FakeUpstream:
    """Records which pinned address the proxy connected to and answers like a web server."""

    def __init__(self, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") -> None:
        self.connected: list[tuple[str, int]] = []
        self.received = b""
        self.response = response

    async def __call__(self, address, port):  # type: ignore[no-untyped-def]
        self.connected.append((str(address), port))
        client_to_up = asyncio.StreamReader()
        up_reader = asyncio.StreamReader()
        upstream = self

        class Writer:
            def write(self, data: bytes) -> None:
                upstream.received += data
                if b"\r\n\r\n" in upstream.received and not up_reader.at_eof():
                    up_reader.feed_data(upstream.response)
                    up_reader.feed_eof()

            async def drain(self) -> None:
                return None

            def can_write_eof(self) -> bool:
                return False

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        del client_to_up
        return up_reader, Writer()


async def run_proxy(proxy: EgressProxy, request: bytes) -> bytes:
    server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 5)
        writer.close()
    return response


@pytest.mark.parametrize(
    "request_line",
    [
        b"CONNECT 169.254.169.254:443 HTTP/1.1",
        b"CONNECT [::1]:443 HTTP/1.1",
        b"CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1",
        b"CONNECT 2130706433:443 HTTP/1.1",
        b"CONNECT metadata.google.internal:443 HTTP/1.1",
        b"CONNECT evil.example:443 HTTP/1.1",  # resolves to loopback
        b"CONNECT public.example:22 HTTP/1.1",  # port
        b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1",
        b"GET http://evil.example/ HTTP/1.1",
        b"GET http://[fd00:ec2::254]/ HTTP/1.1",
        b"GET /relative HTTP/1.1",
    ],
)
def test_proxy_blocks_forbidden_destinations(request_line: bytes) -> None:
    upstream = FakeUpstream()
    proxy = EgressProxy(
        resolver=resolver_for({"evil.example": ["127.0.0.1"], "public.example": [PUBLIC]}),
        connector=upstream,
    )
    response = asyncio.run(run_proxy(proxy, request_line + b"\r\nHost: x\r\n\r\n"))
    assert response.startswith((b"HTTP/1.1 403", b"HTTP/1.1 400"))
    assert upstream.connected == []  # never connected anywhere


def test_proxy_pins_the_validated_address_against_dns_rebinding() -> None:
    answers = iter([[PUBLIC], ["127.0.0.1"]])  # a rebinding resolver: public first, then loopback

    def rebinding(host: str, port: int) -> Sequence[str]:
        return next(answers)

    upstream = FakeUpstream()
    proxy = EgressProxy(resolver=rebinding, connector=upstream)
    response = asyncio.run(
        run_proxy(
            proxy,
            b"GET http://rebind.example/a?b=1 HTTP/1.1\r\nHost: rebind.example\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
    )
    assert response.startswith(b"HTTP/1.1 200")
    # Resolved once, connected to the checked address; the second answer is never used.
    assert upstream.connected == [(PUBLIC, 80)]
    assert upstream.received.startswith(b"GET /a?b=1 HTTP/1.1\r\n")
    assert b"Proxy-Connection" not in upstream.received


def test_redirect_to_private_address_is_blocked_at_the_next_hop() -> None:
    """A public page redirecting to the metadata service: the browser's follow-up
    request is a new proxy request, validated like the first."""
    upstream = FakeUpstream(
        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n"
    )
    proxy = EgressProxy(resolver=resolver_for({"redirector.example": [PUBLIC]}), connector=upstream)
    first = asyncio.run(
        run_proxy(
            proxy, b"GET http://redirector.example/ HTTP/1.1\r\nHost: redirector.example\r\n\r\n"
        )
    )
    assert b"302 Found" in first
    location = first.split(b"Location: ")[1].split(b"\r\n")[0]
    second = asyncio.run(
        run_proxy(proxy, b"GET " + location + b" HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
    )
    assert (
        second.startswith(b"HTTP/1.1 403")
        and b"X-CodeAudit-Blocked: The URL points to a cloud metadata address." in second
    )
    assert upstream.connected == [(PUBLIC, 80)]
    assert proxy.stats.blocked and "metadata" in proxy.stats.blocked[0][1]


def test_connect_tunnel_to_public_host() -> None:
    upstream = FakeUpstream(response=b"tls-bytes")
    proxy = EgressProxy(resolver=resolver_for({"public.example": [PUBLIC]}), connector=upstream)
    response = asyncio.run(
        run_proxy(proxy, b"CONNECT public.example:443 HTTP/1.1\r\n\r\nclienthello\r\n\r\n")
    )
    assert response.startswith(b"HTTP/1.1 200 Connection established")
    assert upstream.connected == [(PUBLIC, 443)]

"""Egress proxy for the page-capture browser: the only way its traffic leaves.

The capture container sits on an internal Docker network whose only other member
is this proxy. Chromium is started with this proxy and with DNS resolution
disabled, so every request (the page, each redirect hop, every image, script,
iframe and fetch) arrives here as either `CONNECT host:port` (https) or an
absolute-URI request (http). For each one the proxy:

1. validates the host and port (netguard.normalize_url rules),
2. resolves the host itself and rejects the request if any address is private,
   loopback, link-local, reserved, a metadata address or an IPv6 form of one,
3. connects to one of *those* addresses (pinned), so a DNS answer can't change
   between the check and the connection.

Blocked requests get `403` with an `X-CodeAudit-Blocked` reason. Connections are
capped in lifetime and bytes. Run with `python -m app.services.web.egress_proxy`.
"""

import asyncio
import contextlib
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from app.services.web.netguard import (
    ALLOWED_PORTS,
    BlockedUrlError,
    IPAddress,
    Resolver,
    normalize_url,
    resolve_public,
    system_resolver,
)

logger = logging.getLogger(__name__)

MAX_HEAD_BYTES = 32 * 1024
CONNECTION_LIFETIME_SECONDS = 60.0
IDLE_TIMEOUT_SECONDS = 30.0
MAX_BYTES_PER_CONNECTION = 64 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10.0
HOP_BY_HOP = frozenset(
    {
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "upgrade",
    }
)

Connector = Callable[[IPAddress, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


async def open_pinned(
    address: IPAddress, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(
        asyncio.open_connection(str(address), port), timeout=CONNECT_TIMEOUT_SECONDS
    )


@dataclass
class ProxyStats:
    allowed: int = 0
    blocked: list[tuple[str, str]] = field(default_factory=list)  # (target, reason)


class EgressProxy:
    def __init__(
        self,
        *,
        resolver: Resolver = system_resolver,
        connector: Connector = open_pinned,
    ) -> None:
        self.resolver = resolver
        self.connector = connector
        self.stats = ProxyStats()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(self._handle(reader, writer), CONNECTION_LIFETIME_SECONDS)
        except (
            TimeoutError,
            ConnectionError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
        ):
            pass
        except Exception:
            logger.exception("egress proxy connection failed")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT_SECONDS)
        if len(head) > MAX_HEAD_BYTES:
            await self._reply(writer, 431, "Request header too large")
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ")
        except ValueError:
            await self._reply(writer, 400, "Bad request")
            return

        if method.upper() == "CONNECT":
            host, _, port_text = target.rpartition(":")
            url_text = f"https://{host}:{port_text}/"
        else:
            if not target.lower().startswith(("http://", "https://")):
                await self._reply(writer, 400, "Absolute URI required")
                return
            url_text = target

        try:
            url = normalize_url(url_text)
            if url.port not in ALLOWED_PORTS:
                raise BlockedUrlError(f"Port {url.port} is not allowed.")
            loop = asyncio.get_running_loop()
            addresses = await loop.run_in_executor(
                None, resolve_public, url.host, url.port, self.resolver
            )
        except BlockedUrlError as exc:
            self.stats.blocked.append((url_text, exc.reason))
            logger.info("egress blocked %s: %s", url_text[:200], exc.reason)
            await self._reply(writer, 403, "Blocked", blocked=exc.reason)
            return

        upstream = await self._connect(addresses, url.port)
        if upstream is None:
            await self._reply(writer, 502, "Upstream unreachable")
            return
        up_reader, up_writer = upstream
        self.stats.allowed += 1
        try:
            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            else:
                path = url.path + (f"?{url.query}" if url.query else "")
                headers = [
                    line
                    for line in lines[1:]
                    if line and line.split(":", 1)[0].strip().lower() not in HOP_BY_HOP
                ]
                request = [f"{method} {path} {version}", *headers, "Connection: close", "", ""]
                up_writer.write("\r\n".join(request).encode("latin-1"))
                await up_writer.drain()
            await self._splice(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()
            with contextlib.suppress(Exception):
                await up_writer.wait_closed()

    async def _connect(
        self, addresses: list[IPAddress], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        for address in addresses:
            try:
                return await self.connector(address, port)
            except (OSError, TimeoutError):
                continue
        return None

    async def _splice(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
    ) -> None:
        budget = [MAX_BYTES_PER_CONNECTION]

        async def pump(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
            while True:
                chunk = await asyncio.wait_for(source.read(65536), IDLE_TIMEOUT_SECONDS)
                if not chunk:
                    break
                budget[0] -= len(chunk)
                if budget[0] < 0:
                    break
                sink.write(chunk)
                await sink.drain()
            with contextlib.suppress(Exception):
                if sink.can_write_eof():
                    sink.write_eof()

        tasks = [
            asyncio.create_task(pump(client_reader, up_writer)),
            asyncio.create_task(pump(up_reader, client_writer)),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        # Give the other direction a moment to finish a response, then stop.
        if pending:
            await asyncio.wait(pending, timeout=IDLE_TIMEOUT_SECONDS)
        for task in tasks:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    @staticmethod
    async def _reply(
        writer: asyncio.StreamWriter, status: int, message: str, *, blocked: str | None = None
    ) -> None:
        body = message.encode()
        headers = [
            f"HTTP/1.1 {status} {message}",
            "Content-Type: text/plain",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if blocked:
            headers.append(f"X-CodeAudit-Blocked: {blocked}")
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + body)
        with contextlib.suppress(ConnectionError):
            await writer.drain()


async def serve(host: str, port: int) -> None:
    proxy = EgressProxy()
    server = await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEAD_BYTES * 2)
    logger.info("egress proxy listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(
        serve(
            os.environ.get("EGRESS_PROXY_HOST", "0.0.0.0"),  # noqa: S104 - internal network only
            int(os.environ.get("EGRESS_PROXY_PORT", "8888")),
        )
    )  # noqa: S104

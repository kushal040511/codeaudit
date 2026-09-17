"""Capture a web page in the sandboxed browser.

The capture container runs Playwright's Chromium with:
- no network except an internal Docker network whose only other member is the
  egress proxy (every request is SSRF-checked and pinned there),
- a read-only root filesystem, an unprivileged user, no capabilities, memory/CPU/PID
  caps and a hard timeout,
- no host filesystem access: it sees only its own job directory (script in,
  results out).

Captured content is untrusted data. It is parsed as data here and never executed,
rendered as HTML, or used as instructions.
"""

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.core.errors import AnalysisError
from app.services.analyzers.sandbox import (
    SandboxLimits,
    SandboxMount,
    SandboxTimeoutError,
    run_in_sandbox,
)
from app.services.web.netguard import BlockedUrlError, normalize_url

logger = logging.getLogger(__name__)

SCRIPT = Path(__file__).with_name("capture_script.py")
JOB_MOUNT = "/job"
OUT_MOUNT = "/out"
MAX_CAPTURE_JSON_BYTES = 20 * 1024 * 1024


class CaptureError(AnalysisError):
    """The page could not be captured; the message is safe to show."""


class CaptureBlockedError(CaptureError):
    """The URL or a redirect hop was refused by the SSRF guard."""


@dataclass
class Capture:
    requested_url: str
    final_url: str
    status: int | None
    redirect_chain: list[dict[str, Any]]
    title: str
    meta: list[dict[str, Any]]
    text: str
    links: list[str]
    resources: list[str]
    forms: list[dict[str, Any]]
    orphan_inputs: list[dict[str, Any]]
    tls: dict[str, Any] | None
    styles: list[dict[str, Any]]
    fold_png: bytes | None
    full_png: bytes | None
    favicon: bytes | None
    favicon_url: str | None
    dom_html: bytes | None
    blocked_requests: list[dict[str, Any]] = field(default_factory=list)
    failed_requests: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int | None = None


def _read(path: Path, limit: int | None = None) -> bytes | None:
    if not path.is_file() or path.is_symlink():
        return None
    if limit is not None and path.stat().st_size > limit:
        return None
    return path.read_bytes()


def parse_capture(requested_url: str, out_dir: Path) -> Capture:
    raw = _read(out_dir / "capture.json", MAX_CAPTURE_JSON_BYTES)
    if raw is None:
        raise CaptureError("The browser produced no capture output.")
    try:
        data = json.loads(raw)
    except ValueError:
        raise CaptureError("The browser's capture output was unreadable.") from None
    page = data.get("page") or {}
    chain = [hop for hop in data.get("redirect_chain") or [] if isinstance(hop, dict)]

    # Re-validate every URL the browser ended up on. The proxy already refused
    # forbidden destinations; this turns a refusal into a clear error.
    for blocked in data.get("blocked_requests") or []:
        if any(blocked.get("url") == hop.get("url") for hop in chain) or blocked.get(
            "url"
        ) == data.get("final_url"):
            raise CaptureBlockedError(f"Blocked a redirect: {blocked.get('reason')}")
    for hop in [*chain, {"url": data.get("final_url")}]:
        url = hop.get("url") or ""
        if url.startswith(("http://", "https://")):
            try:
                normalize_url(url)
            except BlockedUrlError as exc:
                raise CaptureBlockedError(
                    f"Blocked a redirect to {url[:200]}: {exc.reason}"
                ) from None
    if data.get("too_many_redirects"):
        raise CaptureError(
            f"The page redirected more than {get_settings().web_max_redirects} times."
        )
    if data.get("navigation_failed") and not page:
        detail = next((e for e in data.get("errors", []) if e.startswith("navigation failed")), "")
        reason = detail.removeprefix("navigation failed: ") or "unknown error"
        raise CaptureError(f"The page could not be loaded ({reason}).")

    return Capture(
        requested_url=requested_url,
        final_url=str(data.get("final_url") or requested_url)[:2048],
        status=data.get("status"),
        redirect_chain=chain,
        title=str(page.get("title") or "")[:500],
        meta=list(page.get("meta") or [])[:200],
        text=str(page.get("text") or "")[:20000],
        links=[str(u) for u in page.get("links") or []][:5000],
        resources=[str(u) for u in page.get("resources") or []][:5000],
        forms=list(page.get("forms") or [])[:100],
        orphan_inputs=list(page.get("orphan_inputs") or [])[:100],
        tls=data.get("tls") if isinstance(data.get("tls"), dict) else None,
        styles=list(data.get("styles") or []),
        fold_png=_read(out_dir / "fold.png", 20 * 1024 * 1024),
        full_png=_read(out_dir / "full.png", 40 * 1024 * 1024),
        favicon=_read(out_dir / "favicon.bin", 256 * 1024),
        favicon_url=data.get("favicon_url"),
        dom_html=_read(out_dir / "dom.html", 4 * 1024 * 1024),
        blocked_requests=list(data.get("blocked_requests") or []),
        failed_requests=list(data.get("failed_requests") or []),
        errors=[str(e) for e in data.get("errors") or []],
        duration_ms=data.get("duration_ms"),
    )


def capture_page(
    url: str, workdir: Path, *, label: str, html_fixture: Path | None = None
) -> Capture:
    """Load `url` (already validated with netguard) in the sandboxed browser."""
    settings = get_settings()
    job = workdir / "job"
    out = workdir / "out"
    job.mkdir(parents=True)
    out.mkdir()
    os.chmod(job, 0o750)  # noqa: S103 - read by the sandbox (worker group)
    os.chmod(out, 0o770)  # noqa: S103 - written by the sandbox (worker group)
    shutil.copyfile(SCRIPT, job / "capture_script.py")
    environment = {
        "TARGET_URL": url,
        "PAGE_TIMEOUT_MS": str(settings.web_page_timeout_ms),
        "MAX_REDIRECTS": str(settings.web_max_redirects),
        "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
    }
    network: bool | str = False
    if html_fixture is not None:
        shutil.copyfile(html_fixture, job / "fixture.html")
        environment["CAPTURE_HTML_FILE"] = f"{JOB_MOUNT}/fixture.html"
    else:
        environment["PROXY_SERVER"] = settings.web_egress_proxy_url
        network = settings.web_capture_network
    for path in job.iterdir():
        os.chmod(path, 0o640)

    try:
        result = run_in_sandbox(
            image=settings.web_capture_image,
            entrypoint=["python3"],
            command=[f"{JOB_MOUNT}/capture_script.py"],
            working_dir="/tmp",  # noqa: S108 - tmpfs
            mounts=[
                SandboxMount(job, JOB_MOUNT, read_only=True),
                SandboxMount(out, OUT_MOUNT, read_only=False),
            ],
            limits=SandboxLimits(
                cpus=settings.web_capture_cpus,
                memory=settings.web_capture_memory_limit,
                timeout_seconds=settings.web_capture_timeout_seconds + 10,
                pids=1024,
                tmpfs_size="768m",
            ),
            labels={"codeaudit.site_analysis": label, "codeaudit.analyzer": "web-capture"},
            environment=environment,
            network=network,
        )
    except SandboxTimeoutError:
        raise CaptureError(
            f"The page did not finish loading within {settings.web_capture_timeout_seconds}s."
        ) from None
    if result.oom_killed:
        raise CaptureError("The page used more memory than the capture limit allows.")
    if result.exit_code not in (0, 3):
        logger.info("capture %s exited %s: %s", label, result.exit_code, result.stderr[-1000:])
    return parse_capture(url, out)

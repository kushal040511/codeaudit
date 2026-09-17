"""Runs INSIDE the capture sandbox container (Playwright image). No app imports.

Loads one URL in headless Chromium and writes to /out:
  capture.json  metadata, links, forms, redirects, TLS details, computed styles
  fold.png      above-the-fold screenshot (1366x768)
  full.png      full-page screenshot (height-capped)
  favicon.bin   favicon bytes, if any
  dom.html      serialized DOM (size-capped)

All page content is untrusted data: it is collected, never interpreted. Downloads,
popups, dialogs, service workers and permission prompts are blocked. Network
access exists only through the egress proxy (PROXY_SERVER); Chromium itself
resolves no hostnames.

Environment:
  TARGET_URL           the page to load
  PROXY_SERVER         http://egress-proxy:8888 (absent: fixture mode only)
  CAPTURE_HTML_FILE    load this local HTML instead of a URL (tests)
  PAGE_TIMEOUT_MS      navigation budget
  MAX_REDIRECTS
"""

import json
import os
import sys
import threading
import time
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

OUT = "/out"
VIEWPORT = {"width": 1366, "height": 768}
MAX_FULL_HEIGHT = 8000
MAX_DOM_BYTES = 3 * 1024 * 1024
MAX_TEXT_CHARS = 20000
MAX_STYLE_ELEMENTS = 4000
MAX_FAVICON_BYTES = 256 * 1024
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)

started = time.monotonic()
page_timeout = int(os.environ.get("PAGE_TIMEOUT_MS", "20000"))
max_redirects = int(os.environ.get("MAX_REDIRECTS", "10"))
result: dict = {"errors": [], "blocked_requests": [], "failed_requests": []}


def write_result() -> None:
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    with open(f"{OUT}/capture.json", "w", encoding="utf-8") as fh:
        json.dump(result, fh)


def watchdog() -> None:
    # Hard stop inside the container; the worker also kills the container on timeout.
    time.sleep(page_timeout / 1000 + 12)
    result["errors"].append("capture watchdog fired")
    write_result()
    os._exit(3)


threading.Thread(target=watchdog, daemon=True).start()

PAGE_DATA_JS = """
(maxText) => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href } catch { return null } };
  const meta = [...document.querySelectorAll('meta')].slice(0, 200).map(m => ({
    name: m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv'),
    content: (m.getAttribute('content') || '').slice(0, 500),
  })).filter(m => m.name);
  const links = [...document.querySelectorAll('a[href], area[href]')].slice(0, 5000)
    .map(a => abs(a.getAttribute('href'))).filter(Boolean);
  const resources = [...document.querySelectorAll('script[src], link[href], img[src], iframe[src]')]
    .slice(0, 5000).map(e => abs(e.getAttribute('src') || e.getAttribute('href'))).filter(Boolean);
  const cardPattern = /(card.?num|cc.?num|cardnumber|credit.?card|cvv|cvc|csc|security.?code|expir|exp.?month|exp.?year)/i;
  const describe = (i) => ({
    type: (i.getAttribute('type') || i.tagName.toLowerCase()).toLowerCase(),
    name: (i.getAttribute('name') || '').slice(0, 100),
    id: (i.id || '').slice(0, 100),
    autocomplete: (i.getAttribute('autocomplete') || '').slice(0, 100),
    placeholder: (i.getAttribute('placeholder') || '').slice(0, 100),
    card_like: cardPattern.test([i.name, i.id, i.getAttribute('autocomplete'), i.getAttribute('placeholder'), i.getAttribute('aria-label')].join(' '))
      || /^cc-/.test(i.getAttribute('autocomplete') || ''),
  });
  const forms = [...document.forms].slice(0, 100).map(f => ({
    action: abs(f.getAttribute('action') || document.location.href),
    raw_action: (f.getAttribute('action') || '').slice(0, 500),
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    inputs: [...f.querySelectorAll('input, select, textarea')].slice(0, 100).map(describe),
  }));
  const orphanInputs = [...document.querySelectorAll('input')].filter(i => !i.form).slice(0, 100).map(describe);
  const icons = [...document.querySelectorAll('link[rel]')]
    .filter(l => /(^|\\s)(icon|shortcut icon|apple-touch-icon)(\\s|$)/i.test(l.getAttribute('rel')))
    .map(l => ({ rel: l.getAttribute('rel'), href: abs(l.getAttribute('href')), sizes: l.getAttribute('sizes') }));
  return {
    title: (document.title || '').slice(0, 500),
    lang: document.documentElement.lang || null,
    meta, links, resources, forms, orphan_inputs: orphanInputs, icons,
    text: (document.body ? document.body.innerText : '').slice(0, maxText),
    document_height: Math.max(document.body ? document.body.scrollHeight : 0, document.documentElement.scrollHeight),
  };
}
"""

STYLES_JS = """
(maxElements) => {
  const out = [];
  const viewportArea = window.innerWidth * window.innerHeight;
  const all = document.querySelectorAll('body, body *');
  for (const el of all) {
    if (out.length >= maxElements) break;
    const tag = el.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'template', 'svg', 'path', 'meta', 'link'].includes(tag)) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    let ownText = 0;
    for (const n of el.childNodes) if (n.nodeType === 3) ownText += n.textContent.trim().length;
    const top = r.top + window.scrollY;
    out.push({
      tag,
      role: el.getAttribute('role'),
      is_button: tag === 'button' || el.getAttribute('role') === 'button' || (tag === 'input' && ['submit', 'button'].includes(el.type)) || (tag === 'a' && /btn|button/i.test(el.className)),
      is_link: tag === 'a',
      is_heading: /^h[1-6]$/.test(tag),
      area: Math.round(r.width * r.height),
      above_fold: top < window.innerHeight,
      area_ratio: Math.round((r.width * r.height / viewportArea) * 10000) / 10000,
      text_len: ownText,
      color: cs.color,
      background_color: cs.backgroundColor,
      background_image: cs.backgroundImage === 'none' ? null : cs.backgroundImage.slice(0, 300),
      border_color: parseFloat(cs.borderTopWidth) > 0 ? cs.borderTopColor : null,
      font_family: cs.fontFamily,
      font_size: cs.fontSize,
      font_weight: cs.fontWeight,
      line_height: cs.lineHeight,
      letter_spacing: cs.letterSpacing,
      margin: [cs.marginTop, cs.marginRight, cs.marginBottom, cs.marginLeft],
      padding: [cs.paddingTop, cs.paddingRight, cs.paddingBottom, cs.paddingLeft],
      gap: cs.display.includes('flex') || cs.display.includes('grid') ? [cs.rowGap, cs.columnGap] : null,
      border_radius: cs.borderTopLeftRadius,
      box_shadow: cs.boxShadow === 'none' ? null : cs.boxShadow.slice(0, 300),
    });
  }
  return out;
}
"""


def main() -> int:
    target = os.environ.get("TARGET_URL", "")
    proxy = os.environ.get("PROXY_SERVER")
    html_file = os.environ.get("CAPTURE_HTML_FILE")
    args = [
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--disable-quic",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--disable-features=Translate,MediaRouter,OptimizationHints",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    ]
    if proxy:
        proxy_host = urlsplit(proxy).hostname
        # Chromium resolves nothing itself: only the proxy's name.
        args.append(f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {proxy_host}")

    with sync_playwright() as playwright:
        # The container is the sandbox (unprivileged, no capabilities), so Chromium's
        # own setuid/namespace sandbox can't start and is disabled.
        browser = playwright.chromium.launch(
            headless=True,
            args=args,
            chromium_sandbox=False,
            proxy={"server": proxy, "bypass": "<-loopback>"} if proxy else None,
        )
        context = browser.new_context(
            viewport=VIEWPORT,
            user_agent=USER_AGENT,
            accept_downloads=False,
            service_workers="block",
            ignore_https_errors=True,  # certificates are assessed separately
            java_script_enabled=True,
            locale="en-US",
        )
        page = context.new_page()

        # Popups and new windows are closed immediately; downloads and dialogs refused.
        context.on("page", lambda extra: extra.close() if extra != page else None)
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("download", lambda download: download.cancel())

        navigations: list[str] = []
        page.on(
            "framenavigated",
            lambda frame: navigations.append(frame.url) if frame == page.main_frame else None,
        )

        def on_failed(request) -> None:  # type: ignore[no-untyped-def]
            if len(result["failed_requests"]) < 200:
                result["failed_requests"].append(
                    {
                        "url": request.url[:500],
                        "error": request.failure,
                        "navigation": request.is_navigation_request(),
                    }
                )

        def on_response(response) -> None:  # type: ignore[no-untyped-def]
            if (
                response.headers.get("x-codeaudit-blocked")
                and len(result["blocked_requests"]) < 200
            ):
                result["blocked_requests"].append(
                    {"url": response.url[:500], "reason": response.headers["x-codeaudit-blocked"]}
                )

        page.on("requestfailed", on_failed)
        page.on("response", on_response)

        response = None
        try:
            if html_file:
                with open(html_file, encoding="utf-8") as fh:
                    page.set_content(fh.read(), wait_until="load", timeout=page_timeout)
            else:
                response = page.goto(target, wait_until="load", timeout=page_timeout)
        except PlaywrightTimeout:
            result["errors"].append("page load timed out; captured what had rendered")
        except PlaywrightError as exc:
            result["errors"].append(f"navigation failed: {str(exc).splitlines()[0][:300]}")
            result["navigation_failed"] = True

        if not result.get("navigation_failed"):
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except PlaywrightError:
                pass

        # Redirect chain: HTTP redirects of the main request, then script/meta navigations.
        chain = []
        if response is not None:
            request = response.request
            hops = []
            while request is not None:
                hops.append(request)
                request = request.redirected_from
            for hop in reversed(hops):
                hop_response = hop.response() if hop != response.request else response
                chain.append(
                    {"url": hop.url, "status": hop_response.status if hop_response else None}
                )
            result["status"] = response.status
            result["headers"] = {k: v[:500] for k, v in list(response.headers.items())[:60]}
            try:
                details = response.security_details()
                result["tls"] = details
            except PlaywrightError:
                result["tls"] = None
        for url in navigations:
            if not chain or chain[-1]["url"] != url:
                chain.append({"url": url, "status": None})
        result["redirect_chain"] = chain[:50]
        result["too_many_redirects"] = len(chain) - 1 > max_redirects
        result["final_url"] = page.url

        if result.get("navigation_failed") and page.url in ("about:blank", ""):
            write_result()
            browser.close()
            return 0

        try:
            result["page"] = page.evaluate(PAGE_DATA_JS, MAX_TEXT_CHARS)
            result["styles"] = page.evaluate(STYLES_JS, MAX_STYLE_ELEMENTS)
        except PlaywrightError as exc:
            result["errors"].append(f"page inspection failed: {str(exc).splitlines()[0][:300]}")

        try:
            page.screenshot(path=f"{OUT}/fold.png", timeout=10000)
            height = min(
                int((result.get("page") or {}).get("document_height") or 768), MAX_FULL_HEIGHT
            )
            page.set_viewport_size({"width": VIEWPORT["width"], "height": max(768, height)})
            page.screenshot(path=f"{OUT}/full.png", timeout=10000)
            result["full_height"] = max(768, height)
            page.set_viewport_size(VIEWPORT)
        except PlaywrightError as exc:
            result["errors"].append(f"screenshot failed: {str(exc).splitlines()[0][:300]}")

        try:
            html = page.content().encode("utf-8")[:MAX_DOM_BYTES]
            with open(f"{OUT}/dom.html", "wb") as fh:
                fh.write(html)
        except PlaywrightError:
            pass

        if not html_file:
            icons = (result.get("page") or {}).get("icons") or []
            candidates = [i["href"] for i in icons if i.get("href")] + [
                urljoin(page.url, "/favicon.ico")
            ]
            for candidate in candidates[:3]:
                if not candidate.startswith(("http://", "https://")):
                    continue
                try:
                    icon = context.request.get(candidate, timeout=5000, max_redirects=3)
                    body = icon.body()
                    if icon.ok and 0 < len(body) <= MAX_FAVICON_BYTES:
                        with open(f"{OUT}/favicon.bin", "wb") as fh:
                            fh.write(body)
                        result["favicon_url"] = candidate
                        break
                except PlaywrightError:
                    continue

        write_result()
        browser.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - report anything to the worker
        result["errors"].append(f"capture crashed: {type(exc).__name__}: {str(exc)[:300]}")
        write_result()
        sys.exit(2)

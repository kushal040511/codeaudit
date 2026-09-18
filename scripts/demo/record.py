"""Frame recorder for the demo GIFs. Runs inside the web-capture image (Playwright + Chromium);
scripts/demo/make_gifs.py starts it and turns the frames into GIFs.

    python3 record.py <scene> <base-url> <arg> <out-dir>

Scenes: `graph` and `fixes` take a scan id; `pr` takes a pull request URL.
Each writes frame-NNN.png plus frames.json ([[file, milliseconds], ...]).
"""

import json
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

scene, base, arg, out_dir = sys.argv[1:5]
out = Path(out_dir)
out.mkdir(parents=True, exist_ok=True)
frames: list[list] = []


def snap(page: Page, ms: int = 120, clip: dict | None = None) -> None:
    path = out / f"frame-{len(frames):03d}.png"
    page.screenshot(path=str(path), clip=clip)
    frames.append([path.name, ms])


def hold(page: Page, ms: int, clip: dict | None = None) -> None:
    snap(page, ms, clip)


def graph(page: Page) -> None:
    page.goto(f"{base}/scans/{arg}", wait_until="networkidle")
    page.get_by_role("tab", name="Architecture").click()
    page.wait_for_selector(".react-flow__node", timeout=30_000)
    page.wait_for_timeout(1500)
    page.get_by_text("Architecture").first.scroll_into_view_if_needed()
    hold(page, 1500)
    issue = page.get_by_text("Circular dependency (3 modules)").first
    issue.scroll_into_view_if_needed()
    hold(page, 800)
    issue.click()
    page.wait_for_timeout(700)
    hold(page, 2500)
    edge = page.locator(".react-flow__node").first
    edge.scroll_into_view_if_needed()
    hold(page, 3000)


def fixes(page: Page) -> None:
    page.goto(f"{base}/scans/{arg}", wait_until="networkidle")
    page.get_by_role("tab", name="Fixes").click()
    page.get_by_role("checkbox").first.wait_for(timeout=30_000)
    page.wait_for_timeout(800)
    hold(page, 1500)
    for box in page.get_by_role("checkbox").all()[:5]:
        box.scroll_into_view_if_needed()
        box.click()
        page.wait_for_timeout(900)  # projection request
        hold(page, 1100)
    page.evaluate("window.scrollTo(0, 0)")
    page.get_by_role("tab", name="Fixes").scroll_into_view_if_needed()
    page.wait_for_timeout(300)
    hold(page, 3000)


def pr(page: Page) -> None:
    page.goto(arg, wait_until="networkidle")
    page.wait_for_timeout(1500)
    hold(page, 2500)
    for _ in range(4):
        page.mouse.wheel(0, 450)
        page.wait_for_timeout(400)
        hold(page, 1200)
    page.goto(f"{arg.rstrip('/')}/files", wait_until="networkidle")
    page.wait_for_timeout(1500)
    hold(page, 2500)
    for _ in range(3):
        page.mouse.wheel(0, 500)
        page.wait_for_timeout(400)
        hold(page, 1200)


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1280, "height": 800}, device_scale_factor=1,
                            color_scheme="light", reduced_motion="no-preference")
    {"graph": graph, "fixes": fixes, "pr": pr}[scene](page)
    browser.close()

(out / "frames.json").write_text(json.dumps(frames))
print(f"{scene}: {len(frames)} frames")

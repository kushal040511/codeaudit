"""Pre-populate a running stack with finished demo results, so no demo step waits on a live scan.

Creates (and waits for, including LLM enrichment):

1. the demo repository scan: `demo/sample-repo` uploaded as a zip, or the GitHub
   copy with `--repo-url` (needed for the "open a pull request" step);
2. two contrast scans at pinned commits: pallets/flask (healthy library) and
   excalidraw/excalidraw (large TypeScript graph), fetched with `gh`;
3. a design-token analysis of `--design-url`;
4. a phishing risk analysis of `--phishing-url`, or of the newest reachable URL
   in the OpenPhish feed with `--phishing-from-openphish`.

Writes demo/state.json with the UI links for docs/demo.md. Stdlib only:

    python scripts/demo/seed.py --design-url https://stripe.com --phishing-from-openphish
"""

import argparse
import io
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRAST = {
    "pallets/flask": "d73fa1cdcbd8b1465c151db8924ba58b1dd14e35",
    "excalidraw/excalidraw": "c0ad61c6743aef7623e641cd1460d757cc6cacf3",
}
SCAN_DONE = {"completed", "partial", "failed"}
ENRICHMENT_DONE = {"completed", "partial", "failed", "skipped"}
OPENPHISH_FEED = "https://openphish.com/feed.txt"


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def call(api: str, method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{api}{path}", data=data, method=method, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def upload(api: str, name: str, data: bytes) -> str:
    boundary = uuid.uuid4().hex
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"{api}/api/scans", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response)["scan_id"]


def zip_directory(path: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(path.rglob("*")):
            if file.is_file() and "__pycache__" not in file.parts:
                archive.write(file, file.relative_to(path))
    return buffer.getvalue()


def github_zip(repo: str, sha: str) -> bytes:
    return subprocess.run(
        ["gh", "api", f"repos/{repo}/zipball/{sha}"], capture_output=True, check=True
    ).stdout


def wait_scan(api: str, scan_id: str, timeout: float) -> dict:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        scan = call(api, "GET", f"/api/scans/{scan_id}")
        if scan["status"] in SCAN_DONE and scan.get("enrichment_status") in ENRICHMENT_DONE:
            return scan
        time.sleep(5)
    raise SystemExit(f"scan {scan_id} did not finish within {timeout:.0f} s")


def wait_site(api: str, analysis_id: str, timeout: float = 300) -> dict:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        site = call(api, "GET", f"/api/sites/{analysis_id}")
        if site["status"] in {"completed", "failed"}:
            return site
        time.sleep(3)
    raise SystemExit(f"site analysis {analysis_id} did not finish within {timeout} s")


def analyze_site(api: str, url: str) -> dict:
    created = call(api, "POST", "/api/sites/analyze", {"url": url, "force": True})
    return wait_site(api, created["analysis_id"])


def live_openphish(api: str, tries: int) -> dict:
    """Newest OpenPhish URLs, in order, until one is still serving a page."""
    with urllib.request.urlopen(OPENPHISH_FEED, timeout=30) as response:
        urls = [u.strip() for u in response.read().decode().splitlines() if u.strip()]
    for url in urls[:tries]:
        try:
            site = analyze_site(api, url)
        except urllib.error.HTTPError as exc:
            log(f"  {url}: HTTP {exc.code}")
            continue
        if site["status"] == "completed" and (site.get("risk") or {}).get("score") is not None:
            return site
        log(f"  {url}: {site['status']} {site.get('error_message') or ''}")
    raise SystemExit(f"none of the first {tries} OpenPhish URLs could be captured")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--ui", default="http://localhost:5173")
    parser.add_argument("--repo-url", help="scan the demo repo from GitHub instead of uploading demo/sample-repo")
    parser.add_argument("--design-url", default="https://stripe.com")
    phishing = parser.add_mutually_exclusive_group()
    phishing.add_argument("--phishing-url")
    phishing.add_argument("--phishing-from-openphish", action="store_true")
    parser.add_argument("--skip-contrast", action="store_true")
    parser.add_argument("--timeout", type=float, default=3600)
    args = parser.parse_args()

    state: dict = {"created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scans": {}, "sites": {}}

    log("demo repository …")
    if args.repo_url:
        scan_id = call(args.api, "POST", "/api/scans", {"repo_url": args.repo_url})["scan_id"]
    else:
        scan_id = upload(args.api, "codeaudit-demo.zip", zip_directory(ROOT / "demo" / "sample-repo"))
    scan = wait_scan(args.api, scan_id, args.timeout)
    score = call(args.api, "GET", f"/api/scans/{scan_id}/score")
    state["scans"]["demo"] = {"id": scan_id, "status": scan["status"], "enrichment": scan.get("enrichment_status"),
                              "score": score["overall"], "grade": score["grade"],
                              "url": f"{args.ui}/scans/{scan_id}"}
    log(f"  {scan['status']}, enrichment {scan.get('enrichment_status')}, score {score['overall']} ({score['grade']})")

    if not args.skip_contrast:
        for repo, sha in CONTRAST.items():
            log(f"{repo}@{sha[:7]} …")
            scan_id = upload(args.api, f"{repo.replace('/', '-')}.zip", github_zip(repo, sha))
            scan = wait_scan(args.api, scan_id, args.timeout)
            score = call(args.api, "GET", f"/api/scans/{scan_id}/score")
            state["scans"][repo] = {"id": scan_id, "status": scan["status"], "score": score["overall"],
                                    "grade": score["grade"], "url": f"{args.ui}/scans/{scan_id}"}
            log(f"  {scan['status']}, score {score['overall']} ({score['grade']})")

    log(f"design: {args.design_url} …")
    site = analyze_site(args.api, args.design_url)
    state["sites"]["design"] = {"id": site["id"], "url": args.design_url, "status": site["status"],
                                "link": f"{args.ui}/sites/{site['id']}"}
    log(f"  {site['status']}")

    if args.phishing_url or args.phishing_from_openphish:
        log("phishing …")
        site = analyze_site(args.api, args.phishing_url) if args.phishing_url else live_openphish(args.api, 15)
        risk = site.get("risk") or {}
        state["sites"]["phishing"] = {"id": site["id"], "url": site["url"], "status": site["status"],
                                      "score": risk.get("score"), "level": risk.get("level"),
                                      "link": f"{args.ui}/sites/{site['id']}"}
        log(f"  {site['status']}, risk {risk.get('score')} ({risk.get('level')})")

    out = ROOT / "demo" / "state.json"
    out.write_text(json.dumps(state, indent=2) + "\n")
    log(f"wrote {out}")
    print(json.dumps(state, indent=2))


if __name__ == "__main__":
    main()

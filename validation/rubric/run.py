"""Scan every repository in labels.csv at its pinned SHA and record the API's scores.

Runs on the host against a running stack (stdlib only). Resumable: repositories
already in the output file are skipped.

    python validation/rubric/run.py --api http://localhost:8000 \\
        --out validation/rubric/results/20260918/scans.jsonl

The stack should run with LLM enrichment off (the score never depends on it) and
anonymous scan quotas raised; see validation/rubric/README.md.
"""

import argparse
import csv
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINAL = {"analysis_complete", "completed", "partial", "failed"}


def call(api: str, method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{api}{path}", data=data, method=method, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def upload_zip(api: str, path: Path) -> dict:
    boundary = uuid.uuid4().hex
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"{api}/api/scans", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response)


def fetch_zip(repo: str, sha: str, cache: Path) -> Path:
    """The commit's source archive, via the authenticated GitHub CLI (`gh`)."""
    path = cache / f"{repo.replace('/', '_')}-{sha[:7]}.zip"
    if not path.exists() or path.stat().st_size == 0:
        cache.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            subprocess.run(["gh", "api", f"repos/{repo}/zipball/{sha}"], stdout=handle, check=True)
    return path


def scan(api: str, repo: str, sha: str, timeout: float, zip_cache: Path | None) -> dict:
    started = time.monotonic()
    if zip_cache is None:
        created = call(api, "POST", "/api/scans", {"repo_url": f"https://github.com/{repo}", "ref": sha})
    else:
        created = upload_zip(api, fetch_zip(repo, sha, zip_cache))
    scan_id = created["scan_id"]
    while True:
        status = call(api, "GET", f"/api/scans/{scan_id}")
        if status["status"] in FINAL:
            break
        if time.monotonic() - started > timeout:
            return {"scan_id": scan_id, "status": "timeout", "seconds": round(time.monotonic() - started, 1)}
        time.sleep(3)
    record = {
        "scan_id": scan_id,
        "status": status["status"],
        "error_message": status.get("error_message"),
        "seconds": round(time.monotonic() - started, 1),
        "analyzer_runs": [
            {k: run.get(k) for k in ("analyzer", "status", "duration_ms", "finding_count", "error_message")}
            for run in status.get("analyzer_runs", [])
        ],
    }
    if status["status"] != "failed":
        record["score"] = call(api, "GET", f"/api/scans/{scan_id}/score")
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--labels", default=str(HERE / "labels.csv"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--timeout", type=float, default=1200)
    parser.add_argument("--zip-cache", help="upload each commit as a zip (fetched with `gh`) instead of scanning by URL")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():
        done = {json.loads(line)["repo"] for line in out.read_text().splitlines() if line.strip()}

    with open(args.labels, newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row["repo"] in done:
            continue
        print(f"scanning {row['repo']}@{row['sha'][:7]} …", file=sys.stderr, flush=True)
        try:
            record = scan(args.api, row["repo"], row["sha"], args.timeout, Path(args.zip_cache) if args.zip_cache else None)
        except urllib.error.HTTPError as exc:
            record = {"status": "request_failed", "error_message": f"HTTP {exc.code}: {exc.read()[:300]!r}"}
        record = {"repo": row["repo"], "sha": row["sha"], "mode": "zip" if args.zip_cache else "url", **record}
        with out.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        overall = (record.get("score") or {}).get("overall")
        print(f"  → {record['status']} in {record.get('seconds')} s, score {overall}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()

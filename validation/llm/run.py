"""Scan a fixed set of repositories with LLM enrichment on and wait for enrichment to finish.

Uses the pinned commits from validation/rubric/labels.csv (zips fetched with `gh`),
so the inputs are identical to the rubric study. Resumable.

    python validation/llm/run.py --zip-cache /tmp/zips --out validation/llm/results/<date>/scans.jsonl

The stack must have LLM_ENABLED=true and a provider configured (see README.md).
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "rubric"))

from run import call, fetch_zip, upload_zip

# Python and JS/TS apps with enough security and dependency findings to exercise
# the fix suggester; libraries are left out (few findings, little to fix).
# fastapi/full-stack-fastapi-template is excluded: its archive contains symlinks,
# which zip upload rejects.
REPOS = [
    "adeyosemanputra/pygoat",
    "we45/Vulnerable-Flask-App",
    "anxolerd/dvpwa",
    "appsecco/dvna",
    "OWASP/NodeGoat",
    "gothinkster/flask-realworld-example-app",
    "gothinkster/django-realworld-example-app",
    "miguelgrinberg/microblog",
    "mjhea0/flaskr-tdd",
]
DONE = {"completed", "partial", "failed"}
ENRICHMENT_DONE = {"completed", "partial", "failed", "skipped"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--zip-cache", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--timeout", type=float, default=3600)
    args = parser.parse_args()

    with open(HERE.parent / "rubric" / "labels.csv", newline="") as handle:
        shas = {row["repo"]: row["sha"] for row in csv.DictReader(handle)}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = {json.loads(line)["repo"] for line in out.read_text().splitlines()} if out.exists() else set()

    for repo in REPOS:
        if repo in done:
            continue
        started = time.monotonic()
        print(f"{repo} …", file=sys.stderr, flush=True)
        scan_id = upload_zip(args.api, fetch_zip(repo, shas[repo], Path(args.zip_cache)))["scan_id"]
        while True:
            status = call(args.api, "GET", f"/api/scans/{scan_id}")
            if status["status"] in DONE and status.get("enrichment_status") in ENRICHMENT_DONE:
                break
            if time.monotonic() - started > args.timeout:
                break
            time.sleep(10)
        record = {
            "repo": repo,
            "sha": shas[repo],
            "scan_id": scan_id,
            "status": status["status"],
            "enrichment_status": status.get("enrichment_status"),
            "enrichment_error": status.get("enrichment_error"),
            "seconds": round(time.monotonic() - started, 1),
        }
        with out.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        print(f"  → {record['status']} / enrichment {record['enrichment_status']} in {record['seconds']} s",
              file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()

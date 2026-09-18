"""Scan CodeAudit's own repository at HEAD and record the result for the README badge.

Archives the committed tree (`git archive`, so node_modules, virtualenvs and build
output are never included), leaves out the intentionally vulnerable fixtures and
demo app, uploads it to a running stack and waits for analysis. Writes
docs/self-scan.json and prints the shields.io badge URL.

    python scripts/selfscan.py [--api http://localhost:8000]
"""

import argparse
import io
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "validation" / "rubric"))

from run import call, upload_zip

# Deliberately insecure code that exists to be found; scanning it would measure the fixtures.
EXCLUDE = ("backend/tests/fixtures/", "demo/sample-repo/")
COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


def build_zip(ref: str) -> bytes:
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=zip", ref], capture_output=True, check=True).stdout
    source = zipfile.ZipFile(io.BytesIO(archive))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            if info.is_dir() or info.filename.startswith(EXCLUDE):
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:  # symlink
                continue
            target.writestr(info.filename, source.read(info))
    return out.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()

    sha = subprocess.run(["git", "-C", str(ROOT), "rev-parse", args.ref], capture_output=True, text=True, check=True).stdout.strip()
    path = Path("/tmp") / f"codeaudit-self-{sha[:7]}.zip"
    path.write_bytes(build_zip(args.ref))
    scan_id = upload_zip(args.api, path)["scan_id"]
    while (status := call(args.api, "GET", f"/api/scans/{scan_id}"))["status"] not in {
        "analysis_complete", "enriching", "completed", "partial", "failed"
    }:
        time.sleep(3)
    score = call(args.api, "GET", f"/api/scans/{scan_id}/score")
    result = {
        "commit": sha,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan_id": scan_id,
        "status": status["status"],
        "excluded": list(EXCLUDE),
        "rubric_version": score["rubric_version"],
        "overall": score["overall"],
        "grade": score["grade"],
        "incomplete": score["incomplete"],
        "categories": {c["category"]: c["score"] for c in score["categories"]},
        "finding_counts": status["finding_counts"],
        "analyzers": {r["analyzer"]: r["status"] for r in status["analyzer_runs"]},
    }
    label = urllib.parse.quote(f"{score['overall']:.1f} ({score['grade']})")
    result["badge"] = f"https://img.shields.io/badge/CodeAudit%20self--scan-{label}-{COLORS[score['grade']]}"
    (ROOT / "docs" / "self-scan.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

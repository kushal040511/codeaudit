"""Run the risk assessment over a labeled dataset. Resumable; one JSON line per URL.

Phishing URLs die fast, so every URL ends in one of these states, and only `ok`
rows count towards the metrics:

    ok            captured and scored
    unreachable   DNS failure, connection refused/reset, TLS failure, timeout
    dead_http     the final page answered 4xx/5xx
    taken_down    captured, but the page is a takedown/suspension/parking/warning page
    blocked       refused by the SSRF guard (e.g. resolves to a private address)
    error         anything else (reported, never silently dropped)

Runs the same capture (sandbox + egress proxy), intel and scoring code as the API,
without the database or the vision model. Run inside the worker container:

    docker compose run --rm -v ./validation:/app/validation worker \\
        python /app/validation/phishing/run.py validation/phishing/data/dataset-20260917.csv
"""

import argparse
import csv
import json
import re
import shutil
import sys
import tempfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, "/app")

from app.config import get_settings  # noqa: E402
from app.services.analyzers.sandbox import SandboxError  # noqa: E402
from app.services.web.analysis import gather_intel  # noqa: E402
from app.services.web.capture import CaptureBlockedError, CaptureError, capture_page  # noqa: E402
from app.services.web.netguard import BlockedUrlError, validate_url  # noqa: E402
from app.services.web.references import load_references  # noqa: E402
from app.services.web.risk import RISK_MODEL_VERSION, RiskInputs, assess  # noqa: E402
from app.services.web.visual import hash_favicon, hash_screenshot  # noqa: E402

HERE = Path(__file__).resolve().parent
UNREACHABLE = re.compile(
    r"ERR_NAME_NOT_RESOLVED|ERR_CONNECTION|ERR_TUNNEL_CONNECTION_FAILED|ERR_TIMED_OUT|ERR_SSL|ERR_CERT|"
    r"ERR_EMPTY_RESPONSE|ERR_ADDRESS_UNREACHABLE|ERR_PROXY|could not be resolved|did not finish loading|timed out",
    re.IGNORECASE,
)
TAKEDOWN = re.compile(
    r"suspected phishing|deceptive site ahead|this (site|account|website) (has been|is) suspended|"
    r"account suspended|site (is )?(temporarily )?(unavailable|disabled)|has been (disabled|removed|taken down)|"
    r"this domain (is|may be) for sale|domain (has )?expired|parked (free|domain)|404 not found|"
    r"page not found|web page not available|this deployment has been disabled|site not found|"
    r"no such app|there isn't a github pages site here|phishing warning|reported for phishing",
    re.IGNORECASE,
)


def classify_capture(capture) -> tuple[str, str | None]:  # type: ignore[no-untyped-def]
    status = capture.status
    if status is not None and status >= 400:
        return "dead_http", f"HTTP {status}"
    text = f"{capture.title}\n{capture.text[:3000]}"
    if TAKEDOWN.search(text):
        return "taken_down", TAKEDOWN.search(text).group(0)  # type: ignore[union-attr]
    if not capture.styles and not capture.text.strip():
        return "unreachable", "empty page"
    return "ok", None


def evaluate(url: str, label: int, source: str) -> dict:
    record: dict = {"url": url, "label": label, "source": source, "model_version": RISK_MODEL_VERSION}
    started = time.monotonic()
    root = Path(get_settings().scan_workspace_dir)
    root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="scan-validate-", dir=root))
    try:
        normalized, _ = validate_url(url)
        capture = capture_page(normalized.url, workdir, label="validation")
        record["final_url"] = capture.final_url
        record["http_status"] = capture.status
        state, reason = classify_capture(capture)
        record["state"], record["reason"] = state, reason
        if state != "ok":
            return record
        intel = gather_intel(capture)
        report = assess(
            RiskInputs(
                capture=capture,
                registration=intel.registration,
                dns=intel.dns,
                certificate=intel.certificate,
                reputation=intel.reputation,
                screenshot=hash_screenshot(capture.fold_png) if capture.fold_png else None,
                favicon=hash_favicon(capture.favicon) if capture.favicon else None,
                references=load_references(),
            )
        )
        record["score"] = report.score
        record["evidence"] = [asdict(e) for e in report.evidence]
        record["impersonated_brand"] = report.impersonated_brand
        record["visual_match"] = asdict(report.visual_match) if report.visual_match else None
        record["title"] = capture.title[:200]
    except CaptureBlockedError as exc:
        record["state"], record["reason"] = "blocked", str(exc)
    except BlockedUrlError as exc:
        state = "unreachable" if "could not be resolved" in exc.reason else "blocked"
        record["state"], record["reason"] = state, exc.reason
    except (CaptureError, SandboxError) as exc:
        message = str(exc)
        record["state"] = "unreachable" if UNREACHABLE.search(message) else "error"
        record["reason"] = message[:300]
    except Exception as exc:  # noqa: BLE001 - every URL gets a recorded outcome
        record["state"], record["reason"] = "error", f"{type(exc).__name__}: {exc}"[:300]
        record["traceback"] = traceback.format_exc()[-2000:]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        record["seconds"] = round(time.monotonic() - started, 1)
        record["evaluated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--out", type=Path, help="results JSONL (default: next to the dataset)")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    out = args.out or args.dataset.with_suffix(".results.jsonl")
    done: set[str] = set()
    if out.exists():
        done = {json.loads(line)["url"] for line in out.read_text().splitlines() if line.strip()}
    with args.dataset.open() as fh:
        rows = [r for r in csv.DictReader(fh) if r["url"] not in done]
    if args.limit:
        rows = rows[: args.limit]
    print(f"{len(done)} already evaluated, {len(rows)} to go -> {out}", flush=True)

    lock = Lock()
    counts: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool, out.open("a") as sink:
        futures = [pool.submit(evaluate, r["url"], int(r["label"]), r["source"]) for r in rows]
        for index, future in enumerate(as_completed(futures), start=1):
            record = future.result()
            with lock:
                sink.write(json.dumps(record, default=str) + "\n")
                sink.flush()
                counts[record["state"]] = counts.get(record["state"], 0) + 1
            print(f"[{index}/{len(rows)}] label={record['label']} {record['state']:<11} score={record.get('score', '-')!s:>3} {record['seconds']}s", flush=True)
    print(json.dumps(counts), flush=True)


if __name__ == "__main__":
    main()

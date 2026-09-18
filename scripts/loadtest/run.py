"""Load test: upload the same zip N times concurrently and measure the whole pipeline.

Stdlib only; runs on the host against a running stack. The stack must run with
SCAN_CACHE_TTL_SECONDS=0 (otherwise uploads 2..N are cache hits) and anonymous
scan quotas raised; see scripts/loadtest/README.md.

    python scripts/loadtest/run.py --zip /tmp/drf.zip --concurrency 20 \\
        --out docs/load-test-results/20260918.json
"""

import argparse
import json
import statistics
import subprocess
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

FINAL = {"analysis_complete", "completed", "partial", "failed"}


def pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo), 2)


def upload(api: str, data: bytes, name: str) -> tuple[str, float]:
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        f"{api}/api/scans", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=300) as response:
        payload = json.load(response)
    if payload.get("cached"):
        raise SystemExit("upload was served from the scan cache; set SCAN_CACHE_TTL_SECONDS=0")
    return payload["scan_id"], time.monotonic() - started


def get(api: str, path: str) -> dict:
    with urllib.request.urlopen(f"{api}{path}", timeout=60) as response:
        return json.load(response)


def one(api: str, data: bytes, name: str, t0: float) -> dict:
    submitted = time.monotonic()
    scan_id, upload_s = upload(api, data, name)
    while True:
        status = get(api, f"/api/scans/{scan_id}")
        if status["status"] in FINAL:
            break
        time.sleep(1)
    finished = time.monotonic()

    def ts(key: str) -> float | None:
        value = status.get(key)
        return datetime.fromisoformat(value).timestamp() if value else None

    created, started, completed = ts("created_at"), ts("started_at"), ts("completed_at")
    return {
        "scan_id": scan_id,
        "status": status["status"],
        "upload_s": round(upload_s, 2),
        "end_to_end_s": round(finished - submitted, 2),
        "queued_s": round(started - created, 2) if created and started else None,
        "running_s": round(completed - started, 2) if started and completed else None,
        "finished_at_s": round(finished - t0, 2),
        "findings": status.get("finding_counts"),
        "analyzers": {
            r["analyzer"]: {"status": r["status"], "duration_ms": r.get("duration_ms")}
            for r in status.get("analyzer_runs", [])
        },
    }


def sample_docker(stop: threading.Event, samples: list[dict]) -> None:
    while not stop.is_set():
        try:
            out = subprocess.run(
                ["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
                capture_output=True, text=True, timeout=20, check=False,
            ).stdout
        except subprocess.TimeoutExpired:
            continue
        cpu = mem = 0.0
        for line in out.splitlines():
            _name, cpu_s, mem_s = line.split("\t")
            cpu += float(cpu_s.rstrip("%") or 0)
            used = mem_s.split("/")[0].strip()
            unit = {"GiB": 1024, "MiB": 1, "KiB": 1 / 1024, "B": 1 / 1024**2}
            for suffix, factor in unit.items():
                if used.endswith(suffix):
                    mem += float(used[: -len(suffix)]) * factor
                    break
        samples.append({"t": time.monotonic(), "cpu_percent": round(cpu, 1), "mem_mib": round(mem, 1)})
        stop.wait(2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--zip", required=True)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    data = Path(args.zip).read_bytes()
    samples: list[dict] = []
    stop = threading.Event()
    sampler = threading.Thread(target=sample_docker, args=(stop, samples), daemon=True)
    sampler.start()
    t0 = time.monotonic()
    with ThreadPoolExecutor(args.concurrency) as pool:
        futures = [pool.submit(one, args.api, data, f"load-{i}.zip", t0) for i in range(args.concurrency)]
        runs = [f.result() for f in futures]
    wall = time.monotonic() - t0
    stop.set()
    sampler.join(timeout=30)

    ok = [r for r in runs if r["status"] in {"completed", "analysis_complete"}]
    per_analyzer: dict[str, list[float]] = {}
    for r in runs:
        for name, a in r["analyzers"].items():
            if a["duration_ms"] is not None:
                per_analyzer.setdefault(name, []).append(a["duration_ms"] / 1000)
    summary = {
        "label": args.label,
        "zip_bytes": len(data),
        "concurrency": args.concurrency,
        "completed": len(ok),
        "not_completed": len(runs) - len(ok),
        "statuses": sorted({r["status"] for r in runs}),
        "wall_clock_s": round(wall, 1),
        "scans_per_minute": round(len(ok) / wall * 60, 1),
        "end_to_end_s": {"p50": pct([r["end_to_end_s"] for r in runs], 50), "p95": pct([r["end_to_end_s"] for r in runs], 95)},
        "queued_s": {"p50": pct([r["queued_s"] for r in runs if r["queued_s"] is not None], 50),
                     "p95": pct([r["queued_s"] for r in runs if r["queued_s"] is not None], 95)},
        "running_s": {"p50": pct([r["running_s"] for r in runs if r["running_s"] is not None], 50),
                      "p95": pct([r["running_s"] for r in runs if r["running_s"] is not None], 95)},
        "upload_s": {"p50": pct([r["upload_s"] for r in runs], 50), "max": max(r["upload_s"] for r in runs)},
        "analyzer_s": {k: {"p50": pct(v, 50), "p95": pct(v, 95)} for k, v in sorted(per_analyzer.items())},
        "identical_findings": len({json.dumps(r["findings"], sort_keys=True) for r in ok}) == 1,
        "peak_cpu_percent": max((s["cpu_percent"] for s in samples), default=None),
        "peak_mem_mib": max((s["mem_mib"] for s in samples), default=None),
        "findings_by_severity": json.loads(statistics.mode(json.dumps(r["findings"], sort_keys=True) for r in ok)) if ok else None,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"summary": summary, "runs": runs}, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

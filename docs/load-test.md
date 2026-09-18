# Load test: 20 concurrent scans

**Regenerated 2026-09-18** with the committed driver [`scripts/loadtest/run.py`](../scripts/loadtest/run.py). Raw per-scan results are in [`docs/load-test-results/`](load-test-results/). The first run (2026-09-17) used a driver that was never committed. Its numbers are kept at the bottom for comparison, and the new run reproduces its conclusions.

## Setup

- **Host:** MacBook, Docker Desktop VM with 14 CPUs and 12.5 GB RAM. Other projects' containers were stopped for the run. Ollama was idle.
- **Stack:** the dev `docker compose` stack, with one API, one worker at `CELERY_CONCURRENCY=8`, and Postgres, Redis and MinIO.
- **Measurement override:** LLM enrichment off, `SCAN_CACHE_TTL_SECONDS=0` so every upload is analyzed, and anonymous quotas raised.
- **Input:** `encode/django-rest-framework` at `b92edf5`, a 10.9 MB zip with 585 files (SHA-256 and host details in [`20260918-environment.json`](load-test-results/20260918-environment.json)), fetched with `gh api repos/encode/django-rest-framework/zipball/b92edf5…`.
- **Driver:** uploads the zip from N threads at once and polls every scan to a final state. It samples `docker stats` (summed over all running containers, sandboxes included) about every 2 s.

```sh
CELERY_CONCURRENCY=8 docker compose -f docker-compose.yml -f measure.override.yml up -d --wait
python scripts/loadtest/run.py --zip drf.zip --concurrency 1  --out docs/load-test-results/<date>-baseline.json
python scripts/loadtest/run.py --zip drf.zip --concurrency 20 --out docs/load-test-results/<date>-c20-slots6.json
# 12 slots: add MAX_CONCURRENT_SANDBOXES=12 to the worker's environment and repeat
```

## Results

| | 1 scan | 20 concurrent, 6 sandbox slots (default) | 20 concurrent, 12 slots |
|---|---|---|---|
| Completed / failed | 1 / 0 | **20 / 0** | 20 / 0 |
| Wall clock for all scans | 7.2 s | **44.4 s** | 49.2 s |
| Throughput | — | **27.0 scans/min** | 24.4 scans/min |
| End to end per scan (upload → completed), p50 / p95 | 7.2 s | **30.8 s / 44.4 s** | 38.2 s / 48.2 s |
| Waiting in the queue, p50 / p95 | 0.03 s | 11.4 s / 30.3 s | 19.1 s / 36.6 s |
| Running (claimed → completed), p50 / p95 | 6.6 s | 12.5 s / 42.9 s | 18.8 s / 20.8 s |
| Semgrep run, p50 / p95 | 5.8 s | 11.3 s / 42.0 s | 17.6 s / 19.5 s |
| Ruff run, p50 / p95 | 0.23 s | 1.4 s / 12.1 s | 0.7 s / 4.4 s |
| Upload request, p50 / max | 0.13 s | 1.2 s / 1.4 s | 1.0 s / 1.3 s |
| Peak CPU, all containers (1400% = 14 cores) | 246% | 882% | **1260%** |
| Peak memory, all containers | 1.7 GiB | 3.7 GiB | 4.7 GiB |

Every scan in every run produced identical findings: 1 error, 176 warnings and 2,359 info. Concurrency didn't change or drop anything.

## What it shows

- **Throughput is limited by CPU, specifically Semgrep.** With the default 6 slots, CPU peaked at 63% of the machine. Doubling the slots to 12 pushed CPU to 90% and made the run *slower* (49.2 s vs 44.4 s): Semgrep's median time rose from 11.3 s to 17.6 s because more containers shared the same cores.
- **With 6 slots, the queue is the visible bottleneck.** Short analyzers wait for a slot: Ruff normally takes 0.2 s but reached 12.1 s at p95. With 12 slots, analyzers wait less and scans run longer, so the latency moves around but the total doesn't improve.
- **The right slot count is about `cores ÷ SEMGREP_CPUS`** (14 ÷ 2 = 7), so the default of 6 fits this host. To scale out, add worker VMs. The slot semaphore is global, so raise `MAX_CONCURRENT_SANDBOXES` by the same amount for each VM.
- **Memory never limited anything:** peak was 4.7 GiB of the VM's 11.7 GiB (12.5 GB).

## First run (2026-09-17), for comparison ⚠

The same repository at `main` (identical findings), the same stack settings and an uncommitted driver. ⚠ These numbers come from the original write-up; their raw data wasn't kept, so they can't be regenerated.

| | 1 scan | 20 concurrent, 6 slots | 20 concurrent, 12 slots |
|---|---|---|---|
| Wall clock | 7.6 s | 51 s | 51 s |
| End to end p50 / p95 | 7.6 s | 33.0 s / 47.1 s | 39.4 s / 49.4 s |
| Peak CPU | — | 922% | 1256% |

The rerun is 13% faster in wall clock (44.4 s vs 51 s), with the same shape and the same conclusion. Two runs aren't enough for an error bar. On a laptop, thermal state, Docker Desktop's VM and background load all move these numbers, so treat them as approximate.

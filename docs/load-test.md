# Load test: 20 concurrent scans

**Date:** 2026-09-17. **Host:** Docker Desktop VM, 14 CPUs and 12.5 GB RAM. Other projects' containers were stopped for the run and restarted afterwards.
**Stack:** `docker compose` dev stack (one API, one worker with `--concurrency=8`, Postgres, Redis, MinIO). LLM enrichment was off (no API key), so these numbers cover analysis only.
**Input:** `encode/django-rest-framework` at `main`: a 10.9 MB zip with 758 files (Python, HTML/JS, translations). It was uploaded 20 times at once through `POST /api/scans`, with `SCAN_CACHE_TTL_SECONDS=0` so each upload was analyzed rather than served from the cache. Anonymous quotas were raised for the run.
**Driver:** a Python script that uploads from 20 threads, polls every scan to a final state, and samples queue length, unacked tasks, sandbox slots, `docker stats` memory and CPU about every 3 s. Worker-side numbers come from the worker's `/metrics`.

## Results

| | 1 scan (baseline) | 20 concurrent, 6 sandbox slots (default) | 20 concurrent, 12 slots |
|---|---|---|---|
| Scans completed / failed | 1 / 0 | **20 / 0** | 20 / 0 |
| Wall clock for all scans | 7.6 s | **51 s** | 51 s |
| End-to-end per scan (upload → completed), p50 / p95 | 7.6 s | **33.0 s / 47.1 s** | 39.4 s / 49.4 s |
| Waiting in the Celery queue, p50 / p95 | 0 | 12.1 s / 34.1 s | — |
| Running (claimed → completed), p50 / p95 | 7.6 s | 12.1 s / 46.8 s | 20.2 s / 20.9 s |
| Semgrep run, p50 / p95 | 6.9 s | 10.9 s / 45.6 s | 18.6 s / 19.4 s |
| Ruff run, p50 / p95 | 0.3 s | 0.7 s / 17.6 s | 0.7 s / 6.0 s |
| Peak queued tasks / running tasks | 0 / 1 | 12 / 8 | 12 / 8 |
| Peak sandbox slots held | 1 | **6 (the cap)** | 11 |
| Sandbox slot wait (sum over all sandbox runs) | 0 | 343 s over 84 runs; 38 got a slot in under 0.5 s, 2 waited 30–60 s | 106 s over 80 runs |
| Peak memory, all containers (idle baseline 1.65 GB) | 2.1 GB | **4.1 GB** (sandboxes 1.5 GB, worker 1.3 GB) | 5.2 GB |
| Peak CPU (1400% = 14 cores) | — | 922% | **1256%** |
| Upload request time, p50 / max | 0.33 s | 1.5 s / 1.9 s | 1.5 s / 1.8 s |

All 20 scans produced identical results: 1 error, 176 warnings, 2,359 info, with every analyzer `completed`. Running concurrently didn't change or drop any findings.

## Queue behavior

The worker ran 8 tasks and 12 waited in Redis (`LLEN celery` peaked at 12, with 8 unacked). Tasks are acknowledged after completion (`acks_late`), one message is fetched at a time, and they drained in order. The last scan waited 34 s before a worker claimed it. Every scan acquired its claim exactly once, with no `duplicate_delivery` skips.

## Container concurrency

With the default `MAX_CONCURRENT_SANDBOXES=6`, the Redis semaphore held exactly 6 slots at peak across 8 running scans. Each scan wants up to 4 sandboxes at once, so up to 32 were requested. The rest waited with backoff, which shows up as inflated per-analyzer durations. Ruff normally takes 0.3 s but reached 17.6 s at p95, and that was almost entirely slot wait. No containers were left behind (`docker ps --filter label=codeaudit.sandbox` was empty afterwards), and the reaper had nothing to do.

## Memory ceiling

Peak was 4.1 GB of 12.5 GB with 6 slots and 5.2 GB with 12. Memory was never close to binding. The worst-case per-sandbox limits (Semgrep 2 GB, OSV 2 GB, Bandit 1 GB, Ruff 512 MB, clone 1 GB) cap the theoretical sandbox ceiling at about 6 × 2 GB = 12 GB with 6 slots. Actual Semgrep use on this repo was far below its limit.

## First real bottleneck: CPU, specifically Semgrep

- At 6 slots the queue for sandbox slots is what you see first. CPU was at 66%, so the slots were not yet saturating the machine.
- Doubling slots to 12 **did not improve throughput**: the wall clock stayed at 51 s. Semgrep's own run time rose from 10.9 s to 18.6 s (p50) and CPU reached 90% of all cores. Semgrep is CPU-bound (`SEMGREP_CPUS=2`), so more parallel Semgrep containers just share the same cores.
- **Conclusion:** this host's throughput limit is CPU, at about 20 mid-size scans in 51 s (roughly 23 per minute). The right slot count is about `cores ÷ SEMGREP_CPUS` (14 ÷ 2 = 7), so the default of 6 is correctly sized. Scale by adding worker VMs: the slot semaphore is global, so raise `MAX_CONCURRENT_SANDBOXES` by the same amount per VM. Adding Celery concurrency or slots on one host won't help.
- Next in line: Postgres persist was 11 s total over 21 scans (bulk `INSERT … ON CONFLICT` of about 2,500 findings each), and upload handling (1.5 s p50 under 20 parallel 11 MB uploads) is bounded by the single API process. Neither was close to limiting.

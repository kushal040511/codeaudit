# Query performance review

Measured with `EXPLAIN (ANALYZE, BUFFERS)` on Postgres 16 against a synthetic dataset
sized well beyond current production: 1,000 users, 20,000 scans, 2,000,000 findings
(100 per scan), 500,000 graph edges and 300,000 LLM calls spread over 60 days.

| # | Query (where it runs) | Plan | Time |
|---|---|---|---|
| Q1 | Findings page for a scan, severity filter, sorted (`GET /scans/{id}/findings`) | Bitmap index scan `ix_findings_scan_id_severity`, in-memory sort of 40 rows | 0.94 ms |
| Q2 | Findings total for the same filter | Index-only scan `ix_findings_scan_id_severity` | 0.06 ms |
| Q3 | "My scans" page (`GET /scans`) | Bitmap index scan `ix_scans_user_id_created_at` | 0.64 ms |
| Q4 | Internal graph edges for a scan (graph endpoint) | Bitmap index scan on `(scan_id, …)` edge index | 0.36 ms |
| Q5 | **Today's LLM spend** (every LLM reservation, under the spend lock) | before: parallel seq scan of `llm_calls`; after: index scan `ix_llm_calls_created_at` | **27.0 → 1.9 ms** |
| Q6 | User's monthly LLM tokens (every reservation) | `ix_scans_user_id_created_at` → nested loop on `ix_llm_calls_scan_id_purpose` | 1.24 ms |
| Q7 | Cost dashboard, 30 days by day (admin) | Parallel seq scan: the range covers half the table, so a scan is the right plan | 26 → 21 ms |
| Q8 | Stale-job reaper: running scans past deadline | Bitmap index scan `ix_scans_status` | 2.4 ms |
| Q9 | Transcript purge candidates (nightly) | Seq scan (older than 30 days is most of the table) | 9.3 ms |
| Q10 | Anonymous monthly token pool (anonymous reservations) | before: seq scan; after: bitmap scan `ix_llm_calls_created_at` | 27.6 → 12.5 ms |

## What changed

- **Added `ix_llm_calls_created_at`** (migration `8aecabc45c80`). Q5 runs inside the
  transaction-scoped advisory lock that serialises spend reservations across workers,
  so its duration is how long every concurrent LLM call waits. Without the index it
  grows linearly with total history; with it, it tracks only today's rows.
- The indexes requested for this milestone already existed from earlier migrations:
  `findings (scan_id, severity)`, `scans (user_id, created_at)`, and graph edges by
  `scan_id` (as the leading column of both edge indexes). Q1–Q4 confirm the planner uses them.
- Every list endpoint is now bounded. Array endpoints take `page`/`page_size` (max 100)
  and return `X-Total-Count` and `Link` headers. `GET /scans` keeps its `{items, total}`
  body and gained `page`. The graph endpoint aggregates beyond `max_nodes` (≤ 2000).
- Not indexed on purpose: Q7 and Q9 read most of the table, and an index would not be used.

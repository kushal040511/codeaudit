# ADR 0003: Per-analyzer failure isolation

- Status: accepted
- Code: `backend/app/services/analyzers/orchestrator.py`, `backend/app/services/scan_pipeline.py`, `backend/app/services/graph/isolated.py`, `backend/app/services/scoring/rubric.py`, `backend/app/workers/tasks.py`

## Context

A scan runs up to five analyzers: Semgrep, Bandit, Ruff, OSV-Scanner and the architecture graph (`registry.py`). Any of them can crash, time out, run out of memory or fail to start, because image pulls, rule downloads and OSV databases all depend on infrastructure. Failing the whole scan for one tool would throw away good results. Hiding the failure would present an incomplete result as clean.

The architecture analyzer adds a harder case. tree-sitter is native code parsing untrusted input. The [reference](../reference.md) records that py-tree-sitter 0.26.0 corrupted memory (SIGBUS/SIGSEGV) after parsing a few files in one process. It is pinned below 0.26 (`backend/pyproject.toml`). With `task_acks_late` and `task_reject_on_worker_lost` (`backend/app/core/celery_app.py`), an in-process crash would kill the worker, and the redelivered scan would crash the next worker too.

## Decision

- **The orchestrator never raises.** `run_analyzer_safely` turns every outcome into an `AnalyzerResult`: success, timeout (`timed_out`), infrastructure error (`transient`), analysis error, or unexpected exception. Analyzers run in a thread pool, each in its own sandbox container.
- **Every analyzer gets an `analyzer_runs` row.** `analyze_and_persist` creates `running` rows for the applicable analyzers and `skipped` rows (with a reason) for the rest. The `record` callback sets each row to `completed`, `failed` or `timed_out`, with duration, count, error and warnings, as it finishes.
- **The scan status reflects it.** At least one success with any failure gives `partial` (`scan.analysis_partial` survives enrichment, `finish_enrichment`). If every analyzer failed, the scan is retried when any cause was transient (`TransientInfraError`); otherwise it fails with the combined reasons.
- **The score is flagged.** `rubric.score` excludes a category whose analyzer failed and adds an `incomplete_reasons` entry. The score is marked `incomplete`, and the [reference](../reference.md) says it shouldn't be compared with complete scores. A category that doesn't apply (for example, no Python) is excluded without the flag.
- **The architecture graph runs in a child process.** `graph/isolated.py` runs `python -m app.services.graph.isolated` with a timeout. A signal exit becomes `AnalysisError("... crashed (SIGSEGV in the parser process)")`, and exit code 3 or a `TimeoutExpired` becomes `AnalyzerTimeoutError`. Either way, it's one failed analyzer run.

## Consequences

Positive:

- One flaky tool degrades a scan to `partial` instead of losing it. The UI shows which tools failed ([reference.md](../reference.md), "Failure isolation").
- A native parser crash can't take down the worker or cascade through redeliveries.
- Scores from incomplete runs are distinguishable from clean ones.

Negative:

- Consumers must handle `partial` and `incomplete` as well as `completed`. The frontend has a "Partial results" banner ([reference.md](../reference.md), "Frontend").
- The child process adds interpreter start-up time. In the rubric study, the whole architecture run, start-up included, took 0.6–2.0 s on the larger repositories (excalidraw: 2.0 s for 672 modules; `analyzer_runs` in [`scans.jsonl`](../../validation/rubric/results/20260918-v1.0/scans.jsonl)).
- The child process has no network or resource limits beyond a timeout ([reference.md](../reference.md), "Known gaps" item 4).
- When every analyzer fails for an analysis reason, the scan isn't retried. That's deliberate, because retrying burns resources (comment on `TRANSIENT_ERRORS` in `tasks.py`).

## Alternatives considered

- **Fail the scan on any analyzer failure.** Simpler, but it loses valid results to one unreliable tool.
- **Silently drop failed analyzers.** This would make an incomplete result look clean and make scores non-comparable.
- **Run tree-sitter in-process with cooperative timeouts.** Ruled out by the memory-corruption case and by `acks_late` redelivery amplification.
- **Run tree-sitter in a sandbox container.** A stronger boundary, and listed as a future improvement in [reference.md](../reference.md), "Known gaps" item 4. It isn't done because it needs another image and the container overhead.

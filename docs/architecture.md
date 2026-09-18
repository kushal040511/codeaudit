# Architecture

CodeAudit has two independent pipelines that share the API, the Celery workers, Postgres, object storage and the sandbox runner:

- **Code scans**: a zip upload or a GitHub commit is analyzed by sandboxed tools and an architecture graph, deduplicated, scored, and optionally enriched by an LLM.
- **Site Analyzer**: a live URL is captured in a sandboxed browser behind an SSRF-checking egress proxy, then turned into phishing-risk signals and design tokens.

Design decisions are recorded in [`docs/adr/`](adr/README.md).

## System diagram

```mermaid
flowchart LR
    subgraph clients["Clients"]
        browser["Browser<br/>React SPA (frontend/src)"]
        action["GitHub Action<br/>(action/)"]
    end

    subgraph api["API (FastAPI, backend/app/api)"]
        scansApi["POST /api/scans<br/>zip or repo_url"]
        readApi["Read API<br/>findings, graph, score, fix, review"]
        compareApi["POST /api/scans/compare"]
        prApi["PR preview / confirm"]
        sitesApi["POST /api/sites/analyze"]
    end

    pg[("Postgres<br/>scans, analyzer_runs, findings,<br/>graph_*, scores, fix_suggestions,<br/>llm_calls, pull_requests, site_analyses")]
    minio[("MinIO / S3<br/>uploaded zips, site screenshots")]
    redis[("Redis<br/>Celery broker, quotas,<br/>sandbox slots, kill switch")]

    browser --> scansApi & readApi & prApi & sitesApi
    action --> scansApi & compareApi
    scansApi -->|"stream zip"| minio
    scansApi -->|"INSERT scan (queued)"| pg
    scansApi -->|"run_scan.delay"| redis
    readApi --> pg
    compareApi --> pg

    subgraph worker["Celery worker (backend/app/workers)"]
        runScan["run_scan"]
        extract["extract: download zip / git clone sandbox<br/>safe_extract, detect languages"]
        orch["orchestrator: thread pool,<br/>one analyzer_runs row per tool"]
        dedup["dedup (cross-analyzer)"]
        scoring["scoring rubric v1.0<br/>+ score_impact per finding"]
        enrich["enrich_scan"]
        fixes["fix suggestions<br/>+ patch validation"]
        review["architecture review<br/>+ citation verification"]
        createPr["create_pull_request_task"]
        siteTask["analyze_site_task"]
    end

    subgraph sandboxes["Sandbox containers (no network, read-only /src)"]
        semgrep["Semgrep"]
        bandit["Bandit"]
        ruff["Ruff"]
        osv["OSV-Scanner"]
    end
    child["Architecture graph<br/>isolated child process<br/>(tree-sitter + networkx)"]

    llm{{"LLM provider<br/>Anthropic API or Ollama"}}
    github[("GitHub API")]

    redis --> runScan --> extract --> orch
    extract -. "fetch zip" .-> minio
    orch --> semgrep & bandit & ruff & osv & child
    semgrep & bandit & ruff & osv & child --> dedup --> scoring -->|"findings, graph, score<br/>status analysis_complete"| pg
    scoring -->|"enrich_scan.delay"| redis
    redis --> enrich --> fixes & review
    fixes & review <--> llm
    fixes & review -->|"suggestions, review, llm_calls"| pg

    prApi -->|"preview: build_plan<br/>(writes nothing to GitHub)"| pg
    prApi -->|"confirm {confirm: true}<br/>create_pull_request_task.delay"| redis
    redis --> createPr -->|"rebuild plan, fingerprint check,<br/>Git Data API writes"| github

    subgraph site["Site Analyzer (parallel path)"]
        ssrf["netguard: normalize_url,<br/>check_host, resolve_public"]
        capture["web-capture container<br/>headless Chromium,<br/>internal web_capture network"]
        proxy["egress-proxy<br/>per-request SSRF check,<br/>pinned connect"]
        intel["intel: RDAP, DNS, TLS,<br/>Safe Browsing, OpenPhish"]
        risk["risk signals + score"]
        design["design tokens<br/>(computed CSS, optional vision LLM)"]
    end
    internet(("Public internet"))

    sitesApi -->|"validate_url at accept"| ssrf
    sitesApi -->|"analyze_site.delay"| redis
    redis --> siteTask -->|"validate_url again"| ssrf
    siteTask --> capture --> proxy --> internet
    siteTask --> intel --> risk --> design
    design -. "vision call" .-> llm
    siteTask -->|"screenshots"| minio
    siteTask -->|"risk_evidence, design_tokens"| pg

    subgraph beat["Celery beat (workers/maintenance.py)"]
        reapJobs["reap_stale_jobs (300 s)"]
        reapBoxes["reap_orphaned_sandboxes (300 s)"]
        purge["purge_llm_transcripts (daily)"]
        alerts["check_spend_alerts (600 s)"]
    end
    reapJobs --> pg
    reapBoxes --> sandboxes
    purge --> pg
```

The beat schedule is defined in `backend/app/core/celery_app.py` (`beat_schedule`).

## Scan lifecycle

Status values come from `ScanStatus` and `EnrichmentStatus` in `backend/app/models/scan.py`. Transitions are in `backend/app/workers/tasks.py` (`run_scan`, `_set_status`, `_queue_enrichment`, `enrich_scan`), `backend/app/services/scan_pipeline.py` (`analyze_and_persist`, `persist_results`) and `backend/app/services/llm/enrichment.py` (`start_enrichment`, `run_enrichment`, `finish_enrichment`).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (browser / Action)
    participant A as API (routes/scans.py)
    participant S as MinIO
    participant DB as Postgres
    participant Q as Redis / Celery
    participant W as Worker run_scan
    participant X as Analyzers (sandboxes + child process)
    participant E as Worker enrich_scan
    participant L as LLM (Anthropic / Ollama)

    C->>A: POST /api/scans (zip or repo_url + ref)
    A->>A: quota, zip central-directory checks / resolve ref to SHA
    A->>DB: scan_cache.find_reusable (same bytes or commit)
    alt reusable earlier scan
        A-->>C: earlier scan_id, cached: true
    else new scan
        A->>S: upload zip (upload scans only)
        A->>DB: INSERT scan status=queued, commit
        A->>Q: run_scan.delay(scan_id)
        Note over A,DB: broker error: scan marked failed
        A-->>C: 202 {scan_id, status: queued}
    end

    Q->>W: run_scan(scan_id)
    W->>DB: redelivery guard (completed / partial / enriching: no-op,<br/>analysis_complete: re-queue enrichment)
    W->>DB: atomic claim queued|failed|stale running → running
    W->>S: download zip (or clone commit in git sandbox)
    W->>W: safe_extract, detect_languages, count LOC
    W->>DB: analyzer_runs rows: running (applicable) / skipped (not applicable)
    par each applicable analyzer
        W->>X: Semgrep, Bandit, Ruff, OSV-Scanner, architecture
        X-->>W: AnalyzerResult (success / failed / timed_out)
        W->>DB: update its analyzer_runs row
    end

    alt every analyzer failed, some transient
        W->>DB: status=queued ("Retrying after a temporary error")
        W->>Q: retry, countdown 10 s · 3^attempt (max scan_max_retries)
        Note over W,DB: retries exhausted: status=failed
    else every analyzer failed (analysis error)
        W->>DB: status=failed + error_message, running analyzer_runs → failed
    else at least one succeeded
        W->>W: fill_snippets, deduplicate, score + finding_impacts
        alt LLM not configured (llm_configured returns a reason)
            W->>DB: findings, graph, score, status=completed | partial,<br/>enrichment_status=skipped
        else LLM configured
            W->>DB: findings, graph, score, status=analysis_complete,<br/>enrichment_status=pending, analysis_partial flag
            W->>Q: enrich_scan.delay(scan_id)
            Note over W,DB: broker error: finish_enrichment(failed)<br/>→ completed | partial
        end
    end

    Q->>E: enrich_scan(scan_id)
    E->>DB: start_enrichment: status=enriching, enrichment_status=running<br/>(only from analysis_complete / enriching)
    alt llm_dispatch_block (spend cap, monthly token quota)
        E->>DB: finish_enrichment(skipped, reason)
    else
        E->>E: re-extract source into a fresh workspace
        E->>L: fix suggestions for top findings by score_impact
        L-->>E: diffs → validate_patch (git apply --check, parse)
        E->>L: architecture review from graph digest
        L-->>E: review → verify_review against graph_nodes / graph_edges
        E->>DB: finish_enrichment: status = partial if analysis_partial else completed,<br/>enrichment_status = completed | partial | failed | skipped
    end
    Note over E,DB: any exception or soft time limit: enrichment_status=failed,<br/>scan still completed | partial, generating suggestions → failed

    Note over DB: beat reap_stale_jobs every 300 s: running/queued scans past deadline → failed,<br/>stuck analysis_complete/enriching → finish_enrichment(failed)
    C->>A: GET /api/scans/{id} (UI polls every 2 s)
```

Notes on the transitions:

- `failed` is also claimable by `run_scan`, so a retried delivery can pick up a scan that `_set_status` marked failed (`claimable` in `run_scan`).
- A scan whose analysis finished is never failed by enrichment. `finish_enrichment` always sets `completed` or `partial` from `scan.analysis_partial`.
- `run_enrichment` decides `enrichment_status`: `partial` if something was produced despite problems, `skipped` if the only problems were budget cuts, `failed` otherwise, and `skipped` when there was nothing to enrich.

## Components

### API

FastAPI app factory in `backend/app/main.py`; routers in `backend/app/api/routes/` (`scans.py`, `compare.py`, `score.py`, `architecture.py`, `llm.py`, `pull_requests.py`, `sites.py`, `auth.py`, `admin.py`, `health.py`). Request body limit in `backend/app/api/middleware.py`, error shape in `backend/app/api/errors.py`, rate limits in `backend/app/api/rate_limit.py`. Scan creation (upload checks, GitHub ref resolution) is in `backend/app/services/scan_creation.py`; archive validation in `backend/app/services/archive.py`; the reuse lookup in `backend/app/services/scan_cache.py`. The API commits the scan row before dispatching `run_scan`.

### Storage and queue

- Postgres models: `backend/app/models/` (`scan.py`, `analyzer_run.py`, `finding.py`, `architecture.py`, `score.py`, `llm.py`, `pull_request.py`, `site_analysis.py`, `user.py`); migrations in `backend/alembic/versions/`.
- Object storage client: `backend/app/core/storage.py`.
- Celery app, `acks_late`, `reject_on_worker_lost`, prefetch 1, beat schedule and worker heartbeat: `backend/app/core/celery_app.py`. Redis client: `backend/app/core/redis_client.py`.

### Worker tasks

`backend/app/workers/tasks.py`: `run_scan`, `enrich_scan`, `regenerate_fix_task`, `create_pull_request_task`, `analyze_site_task`, and `cleanup_after_crash` (on `worker_ready`: removes orphaned sandboxes, stale workspaces, runs the stale-job reaper once). The scan pipeline itself is `backend/app/services/scan_pipeline.py`.

### Sandboxed analyzers

- Interface: `backend/app/services/analyzers/base.py`. Registry (Semgrep, Bandit, Ruff, OSV-Scanner, architecture): `registry.py`. Concurrent, failure-isolated execution: `orchestrator.py`.
- Container runner: `backend/app/services/analyzers/sandbox.py` (`run_in_sandbox`, `run_tool`). Containers run as `nobody`, `network_mode` `none`, read-only root, `cap_drop ALL`, `no-new-privileges`, PID limit, and are always removed. A Redis-backed `SandboxSlot` caps concurrent containers across workers (`MAX_CONCURRENT_SANDBOXES`).
- Tools: `semgrep.py` + `semgrep_rules.py` (registry packs, see [ADR 0001](adr/0001-semgrep-registry-rules-not-custom-taint-engine.md)), `bandit.py`, `ruff.py`, `dependency.py` + `osv_db.py` (offline OSV databases).
- Git clone sandbox (the only container with network): `backend/app/services/github/clone.py`.

### Architecture graph

`backend/app/services/analyzers/architecture.py` runs `backend/app/services/graph/isolated.py` in a child process with a timeout. Pipeline in `backend/app/services/graph/`: `parser.py` (tree-sitter) → `resolver.py` → `builder.py` (module-level NetworkX graph) → `metrics.py` + `layers.py` (cycles, coupling, god modules, layering, orphans) → `persistence.py`. `view.py` groups nodes by directory for the UI. See [ADR 0002](adr/0002-module-level-dependency-graph.md) and [ADR 0003](adr/0003-per-analyzer-failure-isolation.md).

### Dedup and scoring

- Dedup: `backend/app/services/analyzers/dedup.py` with categories from `categories.py`; snippets read from source by `snippets.py`.
- Scoring: `backend/app/services/scoring/rubric.py` (rubric v1.0, `score`, `finding_impacts`, `incomplete` flag), `service.py` (store, rescore, projection), `priority.py` (`top_fixable` for fix suggestions), `backfill.py`.

### LLM enrichment

- Orchestration and status: `backend/app/services/llm/enrichment.py`.
- Client with per-scan token reservation, retries, JSON validation and `llm_calls` logging: `client.py`; Ollama adapter: `ollama.py`; provider chosen by `LLM_PROVIDER` (`backend/app/config.py`, default `anthropic`, model `claude-sonnet-4-6`).
- Fix suggestions: `fix_suggester.py`; patch validation (`validate_patch`): `patches.py`.
- Architecture review and citation verification (`verify_review`): `architect.py`.
- Spend cap and kill switch: `backend/app/services/costs.py`; quotas: `backend/app/services/quotas.py`.

### GitHub pull requests

`backend/app/api/routes/pull_requests.py` (preview, confirm, reads) and `backend/app/services/github/pr_builder.py` (`build_plan`, `save_preview`, `create_pull_request_from_preview`). GitHub REST client: `backend/app/services/github/client.py`. OAuth and token encryption: `backend/app/services/auth/`. See [ADR 0004](adr/0004-pull-requests-require-explicit-confirmation.md).

### Site Analyzer

- Route: `backend/app/api/routes/sites.py` (validates the URL on accept, reuses recent analyses of the same normalized URL).
- Pipeline: `backend/app/services/web/analysis.py` (`run_site_analysis`: re-validate → capture → intel → risk → design tokens).
- SSRF guard: `netguard.py`. Egress proxy (run as the `egress-proxy` compose service): `egress_proxy.py`. Browser sandbox: `capture.py` + `capture_script.py`, image `codeaudit-web-capture` on the internal `codeaudit_web_capture` network (`docker-compose.yml`).
- Signals: `intel.py` (RDAP, DNS, certificate, reputation), `lexical.py`, `brands.py`, `visual.py` + `references.py` (perceptual hashes), `risk.py` (evidence and score). Design tokens: `design.py`, `colors.py`.

### Maintenance

`backend/app/workers/maintenance.py`: `reap_stale_jobs` (scans, enrichments, site analyses, PR creations), `reap_orphaned_sandboxes`, `purge_llm_transcripts`, `check_spend_alerts`.

### Frontend

`frontend/src/router.tsx`, pages in `frontend/src/pages/` (`UploadPage`, `ScanDetailPage`, `SiteAnalyzerPage`, `SiteAnalysisPage`, `SettingsPage`), typed API client in `frontend/src/lib/api.ts`, components in `frontend/src/components/`.

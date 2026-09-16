# CodeAudit

Upload a codebase and get security findings, architectural quality and code-health signals, a validated score, and LLM-generated fix suggestions.

> **Status:** zip upload → queue → five analyzers running concurrently (Semgrep, Bandit, Ruff, OSV-Scanner in sandbox containers; the architecture graph in a child process) → cross-analyzer dedup → Postgres → read API and UI with an interactive dependency graph. Scoring and the LLM layer are still stubs.

## Stack

| Layer | Tech |
|---|---|
| API | FastAPI, Uvicorn, Pydantic v2, pydantic-settings |
| Jobs | Celery 5 + Redis 7 |
| Data | PostgreSQL 16, SQLAlchemy 2.0, Alembic |
| Object storage | MinIO (S3 API via boto3, so any S3-compatible store works) |
| Sandbox | Throwaway Docker containers via the Docker SDK, one per analyzer run |
| Analysis | Semgrep 1.177, Bandit 1.9.4, Ruff 0.16.7, OSV-Scanner 2.5.1 (each in its own image); tree-sitter 0.25 + networkx for the architecture graph |
| LLM | Anthropic SDK (stub) |
| Frontend | Vite 8, React 18, TypeScript 6, Tailwind CSS 4, shadcn/ui, TanStack Query 5, React Router 7, React Flow 12 + dagre |

## How a scan works

```
Browser ──POST /api/scans (zip)──▶ API
                                   │ 1. stream-limit body (50 MB), validate zip central directory
                                   │    (zip magic, ≤10k files, no traversal / absolute paths / symlinks / encryption)
                                   │ 2. stream archive to MinIO (multipart, 8 MB parts)
                                   │ 3. INSERT scan (queued), commit, enqueue run_scan  ──▶ 202 {scan_id}
                                   ▼
Celery worker  run_scan(scan_id)
  mark running ─▶ download zip ─▶ safe_extract (re-validates, enforces real byte limits)
  ─▶ detect languages (extensions + manifests) ─▶ registry picks analyzers via applies_to(languages)
  ─▶ run them concurrently (thread pool), each in its own sandbox container; record an analyzer_runs
     row (completed / failed / timed_out / skipped, duration, count, warnings) as each finishes
  ─▶ fill snippets from source ─▶ deduplicate ─▶ bulk INSERT findings + mark completed | partial
  every analyzer failed: mark failed (retry if infrastructure) · always: remove workspace
```

### Analyzers

| Analyzer | Applies to | Command (in sandbox) | Severity normalisation |
|---|---|---|---|
| Semgrep | any | registry packs for the detected languages | INFO/LOW→info, WARNING/MEDIUM→warning, ERROR/HIGH→error, CRITICAL→critical |
| Bandit | Python | `bandit -r . -f json --ini /dev/null --ignore-nosec` | LOW→info, MEDIUM→warning, HIGH→error; one step lower at LOW confidence |
| Ruff | Python | `ruff check --isolated --select E4,E7,E9,F,B,C90,PLE` | by rule code: syntax/undefined names/pylint errors→error, bugbear/bare except→warning, hygiene→info |
| OSV-Scanner | any lockfile | `osv-scanner scan source -r --offline --no-resolve` | CVSS ≥9 critical, ≥7 error, ≥4 warning; unscored→GHSA label, else warning |

All share `services/analyzers/base.py` (`Analyzer`: `applies_to`, `run`, `parse`; `AnalyzerResult`; `FindingData`) and `services/analyzers/sandbox.py` (`run_tool`: read-only repo at `/src`, writable `/out`, limits, exit-code and output checks, guaranteed container removal). A new tool is one module plus a line in `registry.py`.

**Uploaded code can't switch checks off:** a repo's `.bandit` file would otherwise be auto-loaded and can skip every test (verified: 11 findings → 0), hence `--ini /dev/null`; Ruff runs `--isolated` so the project's config (including `extend` paths) is ignored; `# nosec` is ignored.

**Failure isolation:** an analyzer that crashes, times out or can't start is recorded on its `analyzer_runs` row and the scan becomes `partial` (not `completed`). The UI shows which tools failed and says the result is not clean.

**OSV offline databases:** the worker downloads `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` for the ecosystems whose lockfiles are present (npm ≈ 200 MB, PyPI ≈ 35 MB), caches them for 24 h under `<workspace>/_vulndb/osv` (file-locked, atomic replace, stale copy used if refresh fails) and mounts them read-only. OSV-Scanner *silently skips* ecosystems without a database, so that case is surfaced as a run warning.

### Architecture graph

Repository-wide structure rather than per-file issues (`services/graph/`):

1. **Parse** (`parser.py`): tree-sitter for Python, JavaScript, TypeScript/TSX. Per module: imports with the raw statement and line (Python `import`/`from`/relative/`importlib.import_module`; JS/TS ESM, `export … from`, CJS `require`, `import x = require()`, dynamic `import()`), whether each import is type-only (`import type`, `if TYPE_CHECKING:`) or lazy (inside a function), top-level symbols, LOC and definition count. `node_modules`, virtualenvs, build output, `.d.ts` and minified files are skipped. A file with a parse error is kept as a node without imports and reported as a warning; it never fails the scan.
2. **Resolve** (`resolver.py`): every import becomes `internal` (a module → an edge), `asset` (CSS, JSON, images, `.d.ts`), `external` (with evidence: `stdlib`, `node-builtin`, `declared` in requirements/pyproject/package.json, or `undeclared`) or `unresolved` with a reason. Python: source roots inferred from package structure (`src/` layouts, nested projects), relative imports limited to the package hierarchy, submodules in `from pkg import mod`, PEP 420 namespace packages (a declared package wins over a same-named local directory). JS/TS: extensions and index files, `./x.js` → `x.ts`, `tsconfig`/`jsconfig` `paths` and `baseUrl` (JSONC, `extends`, Vite-style project references), workspace packages, Vite `public/`, `@/` aliases as a recorded heuristic.
3. **Build + metrics** (`builder.py`, `metrics.py`): a NetworkX DiGraph of internal modules; external packages are aggregated per package, not nodes. Cycles and layering use the runtime graph (type-only imports excluded).
   - **Circular dependencies:** `simple_cycles` with a length bound of 10, an enumeration ceiling of 10 000 and the 100 shortest reported. Cycles where an import is lazy are warnings, others errors.
   - **Coupling:** fan-in, fan-out, instability `I = fan_out / (fan_in + fan_out)`, betweenness centrality (sampled above 1 000 nodes).
   - **God modules:** LOC, fan-in and centrality all at or above both the repo's 90th percentile and absolute floors (300 LOC, fan-in 5, centrality 0.05).
   - **Layering** (`layers.py`): layers inferred from the nearest matching path segment. Backend: routes/controllers/views → services → models/repositories/db. Frontend: components/pages → hooks (`use*`) → api/clients → store/state. Python `api/` is presentation, JS `api/` is the client layer. Inversions (a model importing a controller) are errors; skips (a route importing a model) are warnings, only if the repository has the skipped layer. Tests and colocated modules (a hook inside `components/Dialog/` using that dialog's context) are not violations.
   - **Orphans:** no importers and not an entrypoint (tests, `__init__`, `main`/`index`/`server`/`cli`, configs and dotfiles, scripts/docs/migrations directories, file-system routes).
   - **Summary:** nodes, edges, density, average degree, max depth (longest chain with cycles collapsed), parse and resolution statistics (coverage, unresolved by reason and by import form), timings.
4. **Persist:** `graph_nodes`, `graph_edges` (internal and external aggregated per pair, unresolved per statement), `architecture_issues` (involved modules and edges for highlighting) and `architecture_summaries`. Each issue is also a Finding with `analyzer="architecture"`.

**Isolation:** tree-sitter is native code parsing untrusted input, so the analysis runs in a child process (`graph/isolated.py`) with a hard timeout. A parser crash fails only the architecture run; in-process, it would kill the Celery worker and, with `acks_late`, crash every worker the scan is redelivered to. This is not hypothetical: **py-tree-sitter 0.26.0 corrupts memory** (SIGBUS/SIGSEGV) after parsing a few files in one process, so it is pinned to 0.25.2.

**Measured** (MacBook, one run each, `analyze_architecture` directly):

| Repository | Files | LOC | Parse | Resolve | Build + metrics | Total | Import resolution |
|---|---|---|---|---|---|---|---|
| pydantic @7b15a78 | 454 | 143k | 938 ms | 41 ms | 63 ms | 1.04 s | 99.6% (13 of 3 472 unresolved: 11 non-literal `import_module`, 2 compiled/fixture modules) |
| excalidraw @a918648 | 670 | 186k | 993 ms | 51 ms | 200 ms | 1.24 s | 99.8% (9 of 4 821: 8 non-literal `require`/`import()`, 1 missing file) |
| full-stack-fastapi-template @cb740b6 | 151 | 12k | 78 ms | 10 ms | 8 ms | 96 ms | 100% |

Through the whole stack, pydantic (uploaded as a zip) finished all five analyzers in 17 s, with the architecture run at 2.1 s including process start-up.

Known limits: 3 valid excalidraw test files are skipped because tree-sitter-typescript 0.23 can't parse `fn<typeof import("x")>()`; layers are path heuristics; modules loaded by string (plugins, Celery `include`, framework conventions) show up as orphans (severity info).

### Deduplication

Findings are merged when they share a normalised file path, an issue category and a location (same start line, or a ≤5-line range containing the other's start line). Categories come from rule-id keywords first, then CWE ids: Semgrep's CWE tags are unreliable (its Flask SQL-injection rule is CWE-704). The finding with the longest message is kept at the group's highest severity; the other analyzers go into `findings.corroborated_by` and every merged finding into `merged_from`, for scoring to use as confidence. Ruff and dependency findings have unique categories and are never merged with other tools.

Semgrep runs in its own container with **no network, a read-only root fs, a tmpfs `/tmp`, uid `nobody`, all capabilities dropped, no-new-privileges, 2 GB memory with no swap, 2 CPUs, a 512 PID limit and a 5-minute wall-clock timeout** (the container is killed when it's reached). The code is mounted read-only. Only a per-scan output directory is writable.

**Retries:** transient infrastructure errors (database, MinIO, Docker daemon, rule registry) are retried up to 2 times with backoff (10 s, 30 s). Analysis failures (unsafe archive, Semgrep crash, OOM or timeout) fail immediately with a user-visible `error_message`.

### API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scans` | multipart field `file` (.zip, ≤50 MB). `202 {"scan_id", "status": "queued"}` |
| `GET` | `/api/scans/{id}` | status (`queued`, `running`, `completed`, `partial`, `failed`), timestamps, `detected_languages`, `analyzer_runs` (status, `duration_ms`, `finding_count`, `error_message`, `warnings`), `analyzer_summary`, `finding_counts` by severity, `findings_by_analyzer`, `total_findings`, `findings_before_dedup` |
| `GET` | `/api/scans/{id}/findings` | `?severity=error&analyzer=bandit&file_path=app.py&page=1&page_size=50`. `analyzer` also matches findings that analyzer corroborated. Items include `analyzer`, `category`, `corroborated_by`, `merged_from`, `dependency` (package, installed/fixed version, advisory id). Most severe first, corroborated first. |
| `GET` | `/api/scans/{id}/graph` | nodes, edges, issue highlights, external dependencies and the summary. `?max_nodes=300` (10–2000): above it modules are grouped by directory at the deepest level that fits, then the largest directories are opened while the view still fits. `&expand=dir` shows a directory one level deeper, `&collapse=dir` folds it into one node |
| `GET` | `/api/scans/{id}/graph/module?module_id=` | one module: metrics, importers, internal/external/unresolved imports, issues |
| `GET` | `/api/scans/{id}/architecture-issues` | `?issue_type=circular_dependency&severity=error` |
| `GET` | `/health` | DB + Redis check, 200 or 503 |

Every error has the shape `{"error": {"code", "message", "details?"}}`, with codes `invalid_file_type`, `invalid_archive`, `payload_too_large` (413), `not_found` (404), `validation_error` (422) and `service_unavailable` (503). Interactive docs are at http://localhost:8000/docs.

### Why not `--config=auto`?

`--config=auto` downloads rules from semgrep.dev *at scan time* (and requires metrics to be on), so it cannot work with `--network none` (verified: it fails with a DNS error). Instead, the **worker** downloads registry packs chosen from the detected languages (always `p/security-audit` and `p/secrets`, plus e.g. `p/python`, `p/flask`, `p/javascript`, `p/nodejs`). It caches them for 24 h under `<workspace>/_rules/semgrep` and mounts them read-only into the sandbox. If a refresh fails, the stale cache is used. See `app/services/analyzers/semgrep_rules.py`.

> **License check needed:** Semgrep Registry rules are under the Semgrep Rules License, which restricts using them to provide a competing hosted service. Review it before running CodeAudit commercially. Writing or licensing your own rules is the alternative.

## Repository layout

```
.
├── docker-compose.yml         # api, worker, postgres, redis, minio (+ minio-init)
├── .env.example               # all backend/infra variables, documented
├── docker/backend/Dockerfile  # image for api + worker (NOT a sandbox image)
├── backend/
│   ├── alembic/versions/      # scans + findings migration
│   ├── app/
│   │   ├── main.py            # app factory, body-size limit, error handlers
│   │   ├── config.py          # Settings (env / .env)
│   │   ├── api/               # errors.py (error shape), middleware.py (body limit), routes/{health,scans}.py
│   │   ├── core/              # db, redis, celery app, storage client, error base classes
│   │   ├── models/            # Scan, Finding
│   │   ├── schemas/           # Pydantic request/response models
│   │   ├── services/
│   │   │   ├── archive.py         # zip validation + safe extraction
│   │   │   ├── languages.py       # language detection
│   │   │   ├── scan_pipeline.py   # download → extract → detect → analyze → persist
│   │   │   ├── analyzers/         # base, sandbox (container runner), registry, orchestrator, dedup,
│   │   │   │                      # categories, snippets; semgrep(+_rules), bandit, ruff, dependency(+osv_db)
│   │   │   ├── graph/             # parser, resolver, layers, builder, metrics, analysis, isolated, persistence, view
│   │   │   ├── scoring/ llm/      # stubs
│   │   └── workers/tasks.py   # run_scan (status, retries, cleanup), crash cleanup on worker start
│   └── tests/
│       ├── unit/              # parsers (real tool output), dedup, orchestrator (fake analyzers), caches
│       ├── integration/       # persistence with fake analyzers (Postgres only); upload → all real analyzers → DB
│       ├── fakes.py           # FakeAnalyzer: the analyzer interface without Docker
│       └── fixtures/          # polyglot_app/ + vulnerable_flask_app/ (intentionally insecure), real tool outputs,
│                              # architecture/{clean_layered,cycle_repo,layer_violation,mixed_repo}
└── frontend/src/
    ├── lib/api.ts             # typed API client + ApiError
    ├── pages/                 # UploadPage (drag & drop, progress), ScanDetailPage (2 s polling)
    ├── components/scans/      # AnalyzerStatusPanel, FindingsTable (severity + analyzer filters), SeverityBadge, StatusIndicator
    └── components/architecture/  # ArchitectureTab, ArchitectureGraphView (React Flow + dagre), ModuleNode, ModulePanel, IssuesList
```

## Prerequisites

- Docker Desktop (Compose v2.24+, Engine API ≥ 1.45 for volume subpath mounts)
- [uv](https://docs.astral.sh/uv/) ≥ 0.12 (it installs Python 3.12 for you)
- Node.js ≥ 22.12 and npm

## Quick start (everything in Docker)

```bash
cp .env.example .env          # then change the passwords
# optional: otherwise pulled on the first scan (image digests/tags in .env.example)
docker pull returntocorp/semgrep:1.177.0 && docker pull ghcr.io/astral-sh/ruff:0.16.7 && docker pull ghcr.io/google/osv-scanner:v2.5.1
docker compose up -d --build --wait
```

| Service | URL |
|---|---|
| API health | http://localhost:8000/health |
| API docs (OpenAPI) | http://localhost:8000/docs |
| MinIO console | http://localhost:9001 (`MINIO_ROOT_*`) |
| Postgres | `localhost:5432` (`POSTGRES_*`) |
| Redis | `localhost:6379` |

The `api` container runs `alembic upgrade head` on start (with hot reload on `backend/app`). **The worker does not hot reload:** run `docker compose restart worker` after changing backend code.

On Linux, set `DOCKER_SOCKET_GID` in `.env` to the group that owns `/var/run/docker.sock` (`stat -c %g /var/run/docker.sock`). Docker Desktop uses `0`.

If a host port is taken, change `*_HOST_PORT` in `.env`. If you change `POSTGRES_HOST_PORT`, update the port in `DATABASE_URL` too.

## Frontend

```bash
cd frontend
npm install
npm run dev             # http://localhost:5173 (proxies /api and /health to :8000)
```

- `/upload`: drag and drop (or browse for) a zip, with upload progress. Redirects to the scan when done.
- `/scans/:id`: status indicator, polling every 2 s until finished, an analyzer panel (live status, duration, count, errors and coverage warnings per tool), a "Partial results" banner when a tool failed, and two tabs: **Findings** (severity and analyzer filters, "also found by" corroboration, dependency upgrade hints) and **Architecture** (loaded on demand): summary metrics and coverage warnings, the issue list, and a layered React Flow graph. Node size is LOC, color is the inferred layer, red edges are cycles or violations, dashed edges are type-only. Selecting an issue highlights its modules and dims the rest; clicking a module opens its metrics, importers and imports; directories can be expanded and collapsed. Failed scans show the error message.

Scripts: `npm run build`, `npm run typecheck`, `npm run lint`.

## Backend development (on the host)

Python tooling uses **uv** (fast resolution of the large semgrep dependency tree, a managed Python 3.12, and a single `uv.lock` shared with the Docker image).

```bash
cd backend
uv sync
docker compose up -d postgres redis minio minio-init

uv run uvicorn app.main:app --reload
# A worker on the host bind-mounts scan dirs into sandboxes, so the workspace must be
# writable and shared with Docker Desktop (e.g. under /tmp):
SCAN_WORKSPACE_DIR=/tmp/codeaudit-workspace uv run celery -A app.core.celery_app:celery_app worker -l INFO
```

### Tests

```bash
uv run pytest -m "not integration"     # unit tests, no services needed
uv run pytest -m integration           # needs the compose stack (Postgres, MinIO) + Docker
uv run ruff check . && uv run black --check . && uv run mypy app
```

The integration tests recreate a separate `<db>_test` database and migrate it to head, use a `codeaudit-test-uploads` bucket, run Celery eagerly (`CELERY_TASK_ALWAYS_EAGER`), and run the real sandboxed Semgrep against `tests/fixtures/vulnerable_flask_app`. They skip if a service is unreachable. The workspace is kept under the system temp dir so rule packs and OSV databases (~240 MB, first run only) stay cached between runs.

**Dependencies:** `pyproject.toml` is the source of truth, and `uv.lock` pins exact versions. `requirements*.txt` mirror the direct dependencies with major-version pins. Keep them in sync.

**Migrations:** `uv run alembic revision --autogenerate -m "..."` then `uv run alembic upgrade head`. Autogenerate doesn't drop Postgres enum types on downgrade; add that by hand (see the existing migration).

## Sandboxing: what's done and what isn't

**Done:** Semgrep runs in an isolated container per scan with the limits listed above. Archives are validated in the API and re-validated during extraction in the worker (path confinement, real decompressed-byte limits, no symlinks). Containers are removed in `finally`. On startup the worker removes containers and workspaces left behind by a crashed run.

**Known gaps (must be addressed before handling untrusted uploads in production):**

1. **The worker mounts the Docker socket.** That is root-equivalent on the Docker host: a compromise of the worker process (not of the sandbox) owns the host. Move container launching into a small dedicated runner service with a fixed API, use a rootless daemon, or use Kubernetes Jobs.
2. **Containers share the host kernel.** Add gVisor (`runsc`) or Kata for a stronger boundary against kernel exploits from within the Semgrep process.
3. **Rule downloads run in the worker, which has network access.** Pin rule versions or bake them into a versioned image for reproducible results.
4. **Extraction and tree-sitter parsing run outside the sandbox** (extraction in the worker, parsing in a child process without network or resource limits beyond a timeout). It is hardened (see `archive.py`), but moving it into the sandbox would shrink the attack surface further.
5. **No per-user quotas or rate limits** on uploads yet.

## Known limitations and version notes

- **Semgrep coverage:** the registry packs catch injection flaws well (SQL injection, command injection, Flask misconfiguration). They **do not flag generic hardcoded passwords** (`DB_PASSWORD = "..."`) or `app.secret_key = "..."`, because `p/secrets` matches provider-specific token formats. They also miss some JS DOM sinks without a taint source. A dedicated secrets scanner or custom rules are needed.
- **Snippets:** Semgrep CE returns `"requires login"` for `extra.lines`, so the worker reads snippet lines from the extracted source.
- **Rule IDs:** local rule files get their directory as an id prefix (`rules.python...`). The parser strips it so ids match the public registry.
- **React 18 → React Router 7.** `react-router@8` requires React ≥ 19.2.
- **`redis` capped at `<6.5`.** kombu (Celery's Redis transport) requires it.
- **MinIO image:** `minio/minio` is gone from Docker Hub, so compose uses `quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z`.
- **`returntocorp/semgrep`** is the legacy image name. It is still published and identical to `semgrep/semgrep`.
- **Anthropic SDK 1.x** uses `httpx2`, which coexists with `httpx`.

# CodeAudit

Upload a codebase and get security findings, architectural quality and code-health signals, a validated score, and LLM-generated fix suggestions.

> **Status:** the first end-to-end pipeline works: zip upload → queue → Semgrep in a sandbox container → Postgres → read API and UI. Scoring, the other analyzers, the dependency graph and the LLM layer are still stubs.

## Stack

| Layer | Tech |
|---|---|
| API | FastAPI, Uvicorn, Pydantic v2, pydantic-settings |
| Jobs | Celery 5 + Redis 7 |
| Data | PostgreSQL 16, SQLAlchemy 2.0, Alembic |
| Object storage | MinIO (S3 API via boto3, so any S3-compatible store works) |
| Sandbox | Throwaway Docker containers via the Docker SDK (`returntocorp/semgrep:1.177.0`) |
| Analysis | semgrep (live); bandit, ruff, pip-audit, tree-sitter and networkx installed but not wired up yet |
| LLM | Anthropic SDK (stub) |
| Frontend | Vite 8, React 18, TypeScript 6, Tailwind CSS 4, shadcn/ui, TanStack Query 5, React Router 7 |

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
  ─▶ detect languages (extensions + manifests) ─▶ fetch/cached Semgrep rule packs for those languages
  ─▶ Semgrep in sandbox container ─▶ parse JSON ─▶ bulk INSERT findings + mark completed (one transaction)
  on error: mark failed with message · always: remove workspace; container removed by the runner
```

Semgrep runs in its own container with **no network, a read-only root fs, a tmpfs `/tmp`, uid `nobody`, all capabilities dropped, no-new-privileges, 2 GB memory with no swap, 2 CPUs, a 512 PID limit and a 5-minute wall-clock timeout** (the container is killed when it's reached). The code is mounted read-only. Only a per-scan output directory is writable.

**Retries:** transient infrastructure errors (database, MinIO, Docker daemon, rule registry) are retried up to 2 times with backoff (10 s, 30 s). Analysis failures (unsafe archive, Semgrep crash, OOM or timeout) fail immediately with a user-visible `error_message`.

### API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scans` | multipart field `file` (.zip, ≤50 MB). `202 {"scan_id", "status": "queued"}` |
| `GET` | `/api/scans/{id}` | status, timestamps, `detected_languages`, `finding_counts` by severity, `total_findings` |
| `GET` | `/api/scans/{id}/findings` | `?severity=error&severity=critical&file_path=app.py&page=1&page_size=50`, most severe first |
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
│   │   │   ├── sandbox/runner.py  # isolated container execution
│   │   │   ├── analyzers/         # semgrep.py (+ parser), semgrep_rules.py; bandit/dependency stubs
│   │   │   ├── graph/ scoring/ llm/   # stubs
│   │   └── workers/tasks.py   # run_scan (status, retries, cleanup), crash cleanup on worker start
│   └── tests/
│       ├── unit/              # archive safety, language detection, semgrep parser, rule-pack cache
│       ├── integration/       # upload → eager Celery → real sandboxed Semgrep → DB
│       └── fixtures/          # vulnerable_flask_app/ (intentionally insecure), semgrep_output.json (real output)
└── frontend/src/
    ├── lib/api.ts             # typed API client + ApiError
    ├── pages/                 # UploadPage (drag & drop, progress), ScanDetailPage (2 s polling)
    └── components/scans/      # FindingsTable, SeverityBadge, StatusIndicator
```

## Prerequisites

- Docker Desktop (Compose v2.24+, Engine API ≥ 1.45 for volume subpath mounts)
- [uv](https://docs.astral.sh/uv/) ≥ 0.12 (it installs Python 3.12 for you)
- Node.js ≥ 22.12 and npm

## Quick start (everything in Docker)

```bash
cp .env.example .env          # then change the passwords
docker pull returntocorp/semgrep:1.177.0   # optional: otherwise pulled on the first scan
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
- `/scans/:id`: status indicator, polling every 2 s until completed or failed, detected languages, and a findings table with severity filter and pagination. Failed scans show the error message.

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

The integration tests recreate a separate `<db>_test` database and migrate it to head, use a `codeaudit-test-uploads` bucket, run Celery eagerly (`CELERY_TASK_ALWAYS_EAGER`), and run the real sandboxed Semgrep against `tests/fixtures/vulnerable_flask_app`. They skip if a service is unreachable.

**Dependencies:** `pyproject.toml` is the source of truth, and `uv.lock` pins exact versions. `requirements*.txt` mirror the direct dependencies with major-version pins. Keep them in sync.

**Migrations:** `uv run alembic revision --autogenerate -m "..."` then `uv run alembic upgrade head`. Autogenerate doesn't drop Postgres enum types on downgrade; add that by hand (see the existing migration).

## Sandboxing: what's done and what isn't

**Done:** Semgrep runs in an isolated container per scan with the limits listed above. Archives are validated in the API and re-validated during extraction in the worker (path confinement, real decompressed-byte limits, no symlinks). Containers are removed in `finally`. On startup the worker removes containers and workspaces left behind by a crashed run.

**Known gaps (must be addressed before handling untrusted uploads in production):**

1. **The worker mounts the Docker socket.** That is root-equivalent on the Docker host: a compromise of the worker process (not of the sandbox) owns the host. Move container launching into a small dedicated runner service with a fixed API, use a rootless daemon, or use Kubernetes Jobs.
2. **Containers share the host kernel.** Add gVisor (`runsc`) or Kata for a stronger boundary against kernel exploits from within the Semgrep process.
3. **Rule downloads run in the worker, which has network access.** Pin rule versions or bake them into a versioned image for reproducible results.
4. **Extraction runs in the worker process**, not a sandbox. It is hardened (see `archive.py`), but moving it into the sandbox would shrink the attack surface further.
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

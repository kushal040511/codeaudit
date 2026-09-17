# Security review (production hardening, 2026-09-17)

Four sources: CodeAudit scanning its own repository, a route-by-route ownership audit, dependency audits (OSV-Scanner, pip-audit, npm audit), and the new hardening tests.

## CodeAudit on itself

The self-scan covered the repository zip, excluding `node_modules`, `.venv`, build output, `.git` and the deliberately vulnerable test fixtures under `backend/tests/fixtures`.

| | Before fixes | After fixes |
|---|---|---|
| Score | **72.3 (C)** | **78.5 (C)** |
| Security / Dependencies / Architecture / Code health | 45.9 / 87.1 / 83.3 / 99.3 | 52.0 / 100 / 88.7 / 99.7 |
| Findings: critical / error / warning / info | 0 / **7** / 48 / 1,263 | 0 / **0** / 49 / 1,259 |
| Vulnerable dependencies | 4 (DOMPurify) | 0 |

Compare (`POST /api/scans/compare`): 28 resolved, 18 new, 1,290 unchanged. All 18 "new" findings are the same permission and import lines rewritten by the fixes and re-flagged at lower severity (see *Accepted* below).

The security score stays at C mostly because of volume, not severity: 1,199 of the 1,259 info findings are Bandit `B101` (`assert`) in the test suite.

## Issues found and fixed

| # | Found by | Issue | Fix |
|---|---|---|---|
| 1 | Self-scan (Bandit B103 / Semgrep, error) | Per-scan output, clone and capture directories were **world-writable (0o777)** so the `nobody` sandbox user could write to them. Any local user on the worker host could tamper with analyzer output while a scan ran. | Sandboxes now run as `nobody` **in the worker's group** (`65534:<worker gid>`). Directories are 0o770 (written by the sandbox) or 0o750 (read by it), extracted files 0o640. Nothing in a workspace is world-readable. Verified on the Linux worker: upload scans, a GitHub clone scan and all analyzers complete. |
| 2 | Manual review prompted by #1 | The clone sandbox ran git with **`umask 0000`**, so every cloned file was world-writable. | `umask 0007`. |
| 3 | Self-scan (dependency analyzer) | **DOMPurify 3.4.8** (bundled by Monaco): 4 advisories, including CVE-2026-75838 (XSS via a detached subtree) and CVE-2026-65898 (config pollution). | npm `overrides` pin `dompurify ^3.4.15`. `npm audit`: 0 vulnerabilities. |
| 4 | Self-scan (architecture, error) | Layer violations in new code: `services/quotas.py` imported `api.errors` and `api.deps`, and `services/scan_creation.py` imported `api.errors`. Services depended on the web layer. | User-facing error types moved to `app/core/errors.py` (framework-free; `app/api/errors.py` re-exports them). The per-request rate-limit dependency moved to `app/api/rate_limit.py`. |
| 5 | Self-scan (Semgrep dynamic-urllib, B310) | The GitHub Action's HTTP helper passed URLs to `urllib`, which also opens `file://`. Only the CodeAudit URL was validated, not `GITHUB_API_URL`. | The helper refuses anything that isn't `http(s)://`. |
| 6 | Self-scan (orphan modules) | Dead components `CodeViewer.tsx` and `ScoreChart.tsx`, plus the unused `recharts` dependency. | Removed. |
| 7 | Ownership audit | `POST …/fix/regenerate` queued LLM work without checking the **daily spend cap, kill switch or monthly token quota** (the call was refused later, but only after queueing). | Checks `llm_dispatch_block` first and returns 503 with the reason. |
| 8 | Brief / audit | **Sequential integer IDs** in public URLs for pull requests (`/api/pull-requests/{id}`) and API tokens (`DELETE /api/auth/tokens/{id}`). | `public_id` UUIDv4 columns (backfilled with `gen_random_uuid()`). Routes and response bodies use them; internal integer keys never leave the server. |
| 9 | Hardening tests | The cost dashboard's per-user breakdown failed in Postgres (`GROUP BY user_id` was ambiguous after the join), which returned a 500 to operators. | Groups by the expression. Covered by `test_cost_dashboard_breaks_spend_down`. |
| 10 | Hardening tests | `reap_expired_sandboxes(max_age_seconds=0)` silently used the default age (`0 or default`). | Explicit `None` check. |
| 11 | Code review of the sandbox runner | If the Docker daemon was unreachable, a sandbox **slot leaked** until its lease expired, up to timeout + 5 min. Enough daemon hiccups could starve every scan. | The client is created inside the `try` whose `finally` releases the slot. Covered by a test. |
| 12 | Deployment review | Worker metrics (stage durations, analyzer, LLM and sandbox series) were only written to the worker container's local directory and never exposed, so they were invisible when the worker runs on its own VM. | The Celery main process serves the aggregated multiprocess registry on `WORKER_METRICS_PORT` (9100), and stale samples are cleared at startup. |
| 13 | Deployment review | The API applied migrations on boot (`alembic upgrade head && uvicorn`). Concurrent replicas raced, and a bad migration crash-looped the API. | A separate `migrate` one-shot service in both compose files and a CI step. The API never migrates. |
| 14 | Image review | Stock Caddy binary with file capabilities failed to exec under `cap_drop: ALL`. | The web image ships the binary without file capabilities and listens on 8080 as uid 10002. |

## Controls added in this milestone (security-relevant)

- **Headers:**
  - The API sends `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, `Permissions-Policy`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, and HSTS in production.
  - The edge (Caddy) sends a strict SPA CSP (`script-src 'self'`, no inline scripts, `connect-src 'self'`, `frame-ancestors 'none'`) plus HSTS.
  - Verified in headless Chromium across the home, scan, settings and site pages: no CSP violations.
- **Upload caps at the proxy:** 52 MB on `POST /api/scans` and 1 MB on every other `/api` body. Both verified to return 413 before reaching Python. `/metrics` is not reachable through the edge (404).
- **Ownership:**
  - Every scan-scoped route goes through `load_scan` (anonymous scans are readable by ID holders, owned scans only by the owner, otherwise 404).
  - Pull requests go through `_owned_pull_request`, site analyses through `_load`, and tokens through `user_id` + `public_id`.
  - Admin routes require `is_admin`, and non-admins get `403 admin_required` (tested).
- **Request IDs:** client-supplied `X-Request-ID` values are accepted only if they match `^[A-Za-z0-9._-]{8,128}$`; anything else is replaced, which prevents header or log injection. Tested.
- **Logs:**
  - JSON with request, task and scan IDs.
  - Every message, extra field and traceback passes through `scrub()`: GitHub/Anthropic/AWS/API tokens, bearer and basic auth, `key=value` secrets, URL passwords. Tested.
  - Sentry drops request bodies, cookies, auth headers and local variables.
  - Tool stderr is logged only after token redaction, and LLM prompt/response text (which contains user code) is purged after `LLM_TRANSCRIPT_RETENTION_DAYS`.
  - Access logs record route templates, never query strings.
- **Dead letters:** failed task errors are scrubbed before they are stored (tested with a token in the exception).
- **Containers:**
  - Non-root images (API/worker uid 10001, web uid 10002).
  - Read-only root filesystems, `cap_drop: ALL` and `no-new-privileges` in `docker-compose.prod.yml`.
  - Redis requires a password in production.

## Sandbox audit

Every sandbox container (Semgrep, Bandit, Ruff, OSV-Scanner, git clone, Playwright capture) is created by one function, `run_in_sandbox`, with:

| Control | Setting |
|---|---|
| Network | `none` for analyzers. The capture browser is on the internal `web_capture` network, whose only exit is the SSRF-checking egress proxy. The git clone uses `bridge` (see residual risks). |
| Filesystem | `read_only=True`; `/tmp` tmpfs `nosuid,nodev` with a size cap; source mounted read-only; one writable output mount |
| User | `nobody` in the worker group, never root |
| Capabilities | `cap_drop=["ALL"]`, `no-new-privileges` |
| Limits | memory = memory+swap (no swap), `nano_cpus`, `pids_limit`, `ulimit fsize` = disk quota, `nofile` 4096, `core` 0 |
| Disk quota | `DiskWatch` kills the container when its writable mounts exceed `disk_bytes` (512 MB default), a zip-bomb or runaway-output defense on top of the `fsize` ulimit and the extraction limits. Tested. |
| Other | `init=True` (zombie reaping), `oom_score_adj=800` (killed before host processes), private IPC, log size capped at 10 MB |
| Concurrency | Global Redis semaphore `MAX_CONCURRENT_SANDBOXES` across all workers, with leases that expire if a worker dies. Tested. |
| Cleanup | Removed in `finally`, removed on worker restart, and reaped by beat every 5 min when older than the longest allowed run (any worker). Tested. |

The Playwright capture sandbox gets the same controls (same function) with `pids=1024` and a 768 MB tmpfs for Chromium.

## Accepted (reviewed, not changed)

- **0o770 / 0o750 permission findings** (Semgrep `insecure-file-permissions`, Bandit B103, now warnings). Group access is the mechanism that lets the `nobody` sandbox read and write without world permissions. The group is the worker's own.
- **Routes importing models and `core.db`** (architecture warnings, presentation → data). This is the conventional FastAPI dependency-injection pattern; a repository layer would add indirection without a security benefit.
- **`pickle` in `services/graph/isolated.py`.** It only loads a file that its own child process wrote moments earlier into a private workspace. An attacker who could replace that file already runs code as the worker user.
- **B104 "binding to all interfaces"** (worker metrics, egress proxy): intentional inside containers. Neither port is published by `docker-compose.prod.yml`.
- **B108 `/tmp` usage** refers to the tmpfs inside the sandbox container.
- **B101 asserts (1,199)** are in tests.

## Residual risks

1. **Docker socket on the worker** is root-equivalent on the worker VM. Mitigations: dedicated VM with nothing else on it, no inbound ports except metrics on a private network, rootless Docker or a small container-runner service as the next step.
2. **Shared kernel.** Use gVisor (`runsc`) as the Docker runtime on the worker VM for a stronger boundary. It is compatible with every sandbox image used here.
3. **The git clone container has general egress** (`bridge`). Git is restricted to `https://github.com` with redirects, hooks, submodules and symlinks off, and the host is checked before cloning. A git exploit could still reach the network. On the worker VM, block private ranges and cloud metadata from the Docker bridge (`DOCKER-USER` iptables rules, see README "Deploying").
4. **Monthly LLM token quota for anonymous users is a shared pool.** Anonymous abuse can exhaust it for other anonymous users (never for signed-in users, and never past the daily spend cap).

# CodeAudit

Upload a codebase and get security findings, architectural quality and code-health signals, a validated score, and LLM-generated fix suggestions.

> **Status:** zip upload → queue → five analyzers running concurrently (Semgrep, Bandit, Ruff, OSV-Scanner in sandbox containers; the architecture graph in a child process) → cross-analyzer dedup → Postgres → read API and UI with an interactive dependency graph → optional LLM enrichment (validated fix suggestions, citation-checked architecture review). Every scan gets a deterministic, versioned score (0–100, A–F), and the findings that improve it most get fix suggestions first.

## Stack

| Layer | Tech |
|---|---|
| API | FastAPI, Uvicorn, Pydantic v2, pydantic-settings |
| Jobs | Celery 5 + Redis 7 |
| Data | PostgreSQL 16, SQLAlchemy 2.0, Alembic |
| Object storage | MinIO (S3 API via boto3, so any S3-compatible store works) |
| Sandbox | Throwaway Docker containers via the Docker SDK, one per analyzer run |
| Analysis | Semgrep 1.177, Bandit 1.9.4, Ruff 0.16.7, OSV-Scanner 2.5.1 (each in its own image); tree-sitter 0.25 + networkx for the architecture graph |
| LLM | Anthropic Python SDK 1.x, `claude-sonnet-4-6` by default (`ANTHROPIC_MODEL`) |
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

### Scoring

`services/scoring/rubric.py`, rubric **v1.0**. Deterministic: LLM output never affects it.

| Category | Weight | Analyzers | Size normalisation | Half-life |
|---|---|---|---|---|
| Security | 40% | Semgrep, Bandit | ∛KLOC, capped at 6 | 12 |
| Dependencies | 20% | OSV-Scanner | none | 25 |
| Architecture | 20% | architecture issues | √(modules / 20) | 20 |
| Code health | 20% | Ruff (lint severity weights) | √KLOC | 25 |

- **Category score** = `100 · 2^(−penalty / half-life)`: every half-life of penalty halves the score.
- **Finding weight** = severity (critical 10, error 5, warning 2, info 0.5; lint 3 / 1.5 / 0.5 / 0.1) × 1.25 if corroborated by another analyzer × 0.2 in test code.
- **Repeats:** within one rule, the i-th heaviest occurrence counts `1/i^0.75`, so pydantic's 14,723 test `assert`s cost about as much as four real findings.
- **Size:** security is barely diluted by size (a SQL injection is an absolute risk); lint debt grows with size, so it's divided by √KLOC.
- **Overall** = weighted mean over the categories that were scored. A category that doesn't apply (no Python → no Ruff) is excluded and the weights renormalise. If an analyzer *failed*, the score is flagged `incomplete` and shouldn't be compared with complete scores.
- **Grades:** A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55, else F.

**Impact.** `findings.score_impact` is the exact number of points gained if that finding alone were fixed. It's computed in O(n log n) per rule with a closed form, so pydantic's 15,699 findings take 62 ms, and it's tested against brute-force rescoring. `POST /score/projection` rescores any selection exactly; fixes compound, so a selection gains at least the sum of its impacts. Fix suggestions go to the highest-impact findings.

**Validation.** Property tests (fixing never lowers the score, impacts equal rescoring, severity/corroboration/test-path ordering, damping, size and incompleteness rules) and a benchmark over the committed fixtures that must keep its order: clean layered repo 100 (A) > one layering skip > an import cycle > the vulnerable polyglot app (F). Calibration on real scans: the vulnerable polyglot app scores 43 (F); pydantic scores 68.6 (D): security 76, architecture 85, code health 96, dependencies 10 (CVEs in its lockfiles).

Scans analysed before the rubric existed can be scored with `uv run python -m app.services.scoring.backfill` (`--all` to rescore after a rubric change).

### LLM enrichment

After analysis the scan is `analysis_complete`: findings, graph and issues are readable. A separate Celery task (`enrich_scan`) then moves it to `enriching` and finally `completed` (or `partial` if analyzers failed). `enrichment_status` (`pending`, `running`, `completed`, `partial`, `failed`, `skipped`) and `enrichment_error` record how the LLM stage went; **nothing in it can fail the scan**. Without `ANTHROPIC_API_KEY`, or with `LLM_ENABLED=false`, scans go straight to `completed` with enrichment `skipped`.

**Client** (`services/llm/client.py`): every request is logged as an `llm_calls` row (purpose, model, input/output/cache tokens, cost at list price, latency, attempts, stop reason, request id, prompt and response, truncated). Before each call the input is counted (`count_tokens`, free) and *input + max output* is reserved against `LLM_TOKEN_BUDGET_PER_SCAN` under a row lock on the scan; a call that could exceed the budget is refused and logged, never sent. Rate limits, 408/409, every 5xx (including 529 overloaded) and connection errors are retried with exponential backoff honouring `retry-after`. Responses must be JSON: fences and surrounding prose are stripped, the result is validated with Pydantic, and unparsable output gets exactly one correction request. Refusals and `max_tokens` truncation are recorded and surfaced as failures. Adaptive thinking is on (`LLM_EFFORT`). Uploaded code only ever appears inside the user message, delimited, with instructions to treat it as data.

**Fix suggestions** (`fix_suggester.py`): the top `LLM_MAX_FIX_FINDINGS` findings by score impact (`services/scoring/priority.py`; structural findings are left to the review) are grouped, same rule in the same file, or all advisories for one package, up to `LLM_MAX_FINDINGS_PER_REQUEST` per request. Each request carries the findings, ±`LLM_CONTEXT_LINES` lines of code (merged when they overlap), detected frameworks and style configuration, and for dependencies the installed/fixed versions, whether that's a major bump, and which manifest to edit (`package.json` for npm lockfiles). Output per fix: explanation, confidence, unified diff, breaking risk, regression-test suggestion.

**Patch validation** (`patches.py`), before anything is stored as usable:
- Paths must be existing files inside the repository (no absolute paths, `..`, symlinks, new or deleted files).
- `git apply --check --recount` on a throwaway copy (no system/global git config), then applied to get the result. `--recount` forgives wrong hunk line counts; the context lines must still match.
- Python results must pass `ast.parse`; JS/TS results must have no tree-sitter error nodes (a file that didn't parse before isn't blamed on the patch).
- `validation_status`: `valid`, `failed_to_apply`, `syntax_error`, `no_patch` or `not_validated`, with the git or parser message. The API returns `patch` only when `valid` (the unverified diff is in `rejected_patch`), and the UI marks unverified suggestions clearly and never offers them as copyable fixes.
- **Limits:** "valid" means "applies and parses", not "compiles, type-checks and passes tests". tree-sitter is error-tolerant: it misses some syntax errors (it accepts `{ a: 1,, }`).

**Architecture review** (`architect.py`): the model gets a digest of the stored graph, never the code: stack, layer inventory, cycles with import statements, layering violations with the statements, god modules, orphans, top modules by fan-in / fan-out / centrality / LOC, a depth-3 directory tree and the most used external packages. It returns a summary, strengths, issues (severity, evidence, why it matters, ordered refactor steps) and a suggested target structure. **Every citation is verified** against that scan's `graph_nodes`/`graph_edges`: a module path or id, a directory, or an import `a -> b` that actually exists (directory-to-directory imports count if some module pair backs them). Invalid citations are removed and logged; an issue left without valid evidence is dropped. `hallucination_rate` = invalid module references ÷ all module references, stored per review; path-like mentions in the prose that aren't in the graph are listed separately.

### Deduplication

Findings are merged when they share a normalised file path, an issue category and a location (same start line, or a ≤5-line range containing the other's start line). Categories come from rule-id keywords first, then CWE ids: Semgrep's CWE tags are unreliable (its Flask SQL-injection rule is CWE-704). The finding with the longest message is kept at the group's highest severity; the other analyzers go into `findings.corroborated_by` and every merged finding into `merged_from`, for scoring to use as confidence. Ruff and dependency findings have unique categories and are never merged with other tools.

Semgrep runs in its own container with **no network, a read-only root fs, a tmpfs `/tmp`, uid `nobody`, all capabilities dropped, no-new-privileges, 2 GB memory with no swap, 2 CPUs, a 512 PID limit and a 5-minute wall-clock timeout** (the container is killed when it's reached). The code is mounted read-only. Only a per-scan output directory is writable.

**Retries:** transient infrastructure errors (database, MinIO, Docker daemon, rule registry) are retried up to 2 times with backoff (10 s, 30 s). Analysis failures (unsafe archive, Semgrep crash, OOM or timeout) fail immediately with a user-visible `error_message`.

### API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scans` | multipart field `file` (.zip, ≤50 MB). `202 {"scan_id", "status": "queued"}` |
| `GET` | `/api/scans/{id}` | status (`queued`, `running`, `analysis_complete`, `enriching`, `completed`, `partial`, `failed`), `enrichment_status`, `enrichment_error`, `llm_usage` (tokens, cost, calls, verified fixes), timestamps, `detected_languages`, `analyzer_runs` (status, `duration_ms`, `finding_count`, `error_message`, `warnings`), `analyzer_summary`, `finding_counts` by severity, `findings_by_analyzer`, `total_findings`, `findings_before_dedup` |
| `GET` | `/api/scans/{id}/findings` | `?severity=error&analyzer=bandit&file_path=app.py&page=1&page_size=50`. `analyzer` also matches findings that analyzer corroborated. Items include `analyzer`, `category`, `corroborated_by`, `merged_from`, `dependency` (package, installed/fixed version, advisory id). Most severe first, corroborated first. |
| `GET` | `/api/scans/{id}/graph` | nodes, edges, issue highlights, external dependencies and the summary. `?max_nodes=300` (10–2000): above it modules are grouped by directory at the deepest level that fits, then the largest directories are opened while the view still fits. `&expand=dir` shows a directory one level deeper, `&collapse=dir` folds it into one node |
| `GET` | `/api/scans/{id}/graph/module?module_id=` | one module: metrics, importers, internal/external/unresolved imports, issues |
| `GET` | `/api/scans/{id}/architecture-issues` | `?issue_type=circular_dependency&severity=error` |
| `GET` | `/api/scans/{id}/score` | overall, grade, `incomplete` + reasons, per-category score, weight, penalty, finding count and worst rules, rubric version |
| `POST` | `/api/scans/{id}/score/projection` | body `{"finding_ids": [...]}`: current and projected score and categories, `delta`; ids from other scans are ignored and listed |
| `GET` | `/api/scans/{id}/findings/{finding_id}/fix` | the suggestion: `status`, `validation_status`, `patch_verified`, `explanation`, `confidence`, `patch` (verified only) / `rejected_patch`, `breaking_risk`, `test_suggestion`, `file_changes` (before/after excerpts), `version`. 404 if none |
| `POST` | `/api/scans/{id}/findings/{finding_id}/fix/regenerate` | body `{"hint": "…"}` (optional). 202, generated by a Celery task; the prompt includes the previous patch and why it failed validation. 409 while generating, for structural findings, or when the token budget is spent; 503 without an API key |
| `GET` | `/api/scans/{id}/architecture-review` | summary, strengths, verified issues, dropped issues, suggested structure, `citations_total`, `citations_invalid`, `hallucination_rate` |
| `GET` | `/api/scans/{id}/llm-usage` | budget, tokens used (including in-flight reservations), tokens and cost by purpose, failed calls, the last 100 calls |
| `GET` | `/health` | DB + Redis check, 200 or 503 |

Every error has the shape `{"error": {"code", "message", "details?"}}`, with codes `invalid_file_type`, `invalid_archive`, `payload_too_large` (413), `not_found` (404), `validation_error` (422) and `service_unavailable` (503). Interactive docs are at http://localhost:8000/docs.

### Why not `--config=auto`?

`--config=auto` downloads rules from semgrep.dev *at scan time* (and requires metrics to be on), so it cannot work with `--network none` (verified: it fails with a DNS error). Instead, the **worker** downloads registry packs chosen from the detected languages (always `p/security-audit` and `p/secrets`, plus e.g. `p/python`, `p/flask`, `p/javascript`, `p/nodejs`). It caches them for 24 h under `<workspace>/_rules/semgrep` and mounts them read-only into the sandbox. If a refresh fails, the stale cache is used. See `app/services/analyzers/semgrep_rules.py`.

> **License check needed:** Semgrep Registry rules are under the Semgrep Rules License, which restricts using them to provide a competing hosted service. Review it before running CodeAudit commercially. Writing or licensing your own rules is the alternative.

## GitHub integration

**Setup.** Register a GitHub OAuth app with the callback `http://localhost:8000/api/auth/github/callback`. Put `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` and a Fernet key in `TOKEN_ENCRYPTION_KEYS` into `.env`; see `.env.example`. Without them, public repositories can still be scanned by URL.

**Scans by URL.** `POST /api/scans` with `{"repo_url", "ref"}` works like this:
- **URL handling.** Only `https://github.com/<owner>/<repo>` is accepted. Owner and name are parsed out and CodeAudit builds its own URLs from them.
- **Resolution.** The ref is resolved to a commit SHA, and repos over 200 MB are refused using GitHub's reported size.
- **Clone.** The one commit is shallow-cloned inside a sandbox container. The clone is the only sandbox with network access, is https-only, doesn't follow redirects, and runs no hooks.
- **Private repos.** These need a signed-in user whose token has the `repo` scope. Only then is the token passed to the clone, as an HTTP header through git's environment config.

**Fix pull requests** take two steps, both from a browser session:

1. **Preview.** `POST /api/scans/{id}/pull-requests/preview` rebuilds the change against the base branch's current head. It includes only verified patches, re-checks each one, and reports any that no longer apply. It returns the full diff, commits, PR body and score projection, and writes nothing to GitHub.
2. **Confirm.** `POST /api/pull-requests/{id}/confirm` requires `{"confirm": true}`. It rebuilds the plan and refuses if anything changed since the preview. Then, through the Git Data API, it creates one commit per fix, a `codeaudit/fix-<scan>` branch (in your fork if you can't push), and the pull request. No other code path creates pull requests; a test checks that statically.

Errors have distinct codes: `insufficient_permissions`, `fork_required`, `branch_exists`, `branch_protected`, `preview_outdated`, `stale_head`, `merge_conflict`.

**Security.**
- Tokens are Fernet-encrypted at rest and never returned or logged.
- OAuth `state` is single-use and must match an HttpOnly cookie.
- Cookie-authenticated mutations require `X-CSRF-Token`.
- Other users' scans return 404.
- API tokens (`cat_…`) can create and read scans, but can't open pull requests or manage the account.

**CI.** [`action/`](action/README.md) is a GitHub Action that scans each pull request, compares it with the base commit via `POST /api/scans/compare`, comments the score delta and new findings, and can fail the check.

## Site Analyzer

A separate module, apart from code scans, for analyzing a live URL (`/sites` in the UI, `POST /api/sites/analyze`). It produces two things.

**Phishing / clone risk signals.** The score (0-100) is a heuristic risk assessment, not a determination of fraud. It is the clamped sum of independent evidence signals, each reported with its value and its contribution:
- **Domain:** RDAP registration age and registrar, TLD abuse rates, punycode and homoglyphs, typosquatting and brand names in the domain.
- **Certificate:** trust, hostname match, certificate age.
- **Visual:** pHash and dHash similarity to a reference set of brand pages, and favicon reuse.
- **Content:** brand names on non-brand domains, password and card fields, credentials posted to another domain, links pointing back to the brand.
- **Reputation:** Google Safe Browsing (needs a key) and the OpenPhish feed.

The weights are hand-set priors (model `0.1-prior`). `validation/phishing/` measures them on labeled data.

**Design tokens.** Colors (with roles and contrast), typography, spacing grid, radii and shadows come from the page's computed CSS. They are exported as JSON, a Tailwind theme extension, and CSS custom properties, along with a recreation prompt. The vision model (needs `ANTHROPIC_API_KEY`) only describes layout and style. Any color it names is kept only if it exists in the computed styles.

**Isolation** (see `services/web/`):
- **Browser sandbox.** Pages load in headless Chromium in a throwaway container: unprivileged, read-only root filesystem, no capabilities, memory/CPU/PID caps, hard timeout, no host filesystem access. Downloads, popups, dialogs and service workers are blocked.
- **Egress proxy.** The container's only network is the internal `web_capture` network, whose only other member is `egress-proxy`. Chromium resolves no hostnames itself. Every request (page, redirect hop, subresource) goes through the proxy. The proxy allows only http/https on ports 80/443/8080/8443, and resolves each host itself. It rejects the request if any address is private, loopback, link-local, reserved, a cloud metadata address or an IPv6 form of one. It then connects to the checked address, so DNS rebinding can't swap it.
- **Server-side checks.** Submitted URLs are also checked when accepted and again when the job starts.
- **Untrusted content.** Everything captured is treated as untrusted data. Screenshots are served as images with a sandbox CSP, and captured HTML is never rendered.

Setup: `docker compose build web-capture`, then `docker compose up -d`. The brand reference set is rebuilt with `docker compose exec worker python -m app.services.web.references build`. Only hashes are committed; reference screenshots are stored in object storage.

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
│   │   │   ├── llm/               # client (budget, retries, logging), json_output, pricing, context, patches,
│   │   │   │                      # fix_suggester, architect, enrichment, usage
│   │   │   ├── scoring/           # rubric (v1.0), service (store, rescore, project), priority, backfill
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
- `/scans/:id`: status indicator, polling every 2 s until finished, an analyzer panel (live status, duration, count, errors and coverage warnings per tool), a "Partial results" banner when a tool failed, a **score** card (grade, category bars, incomplete warning), an **AI suggestions** card (status, cost, tokens, verified fixes, budget use), and two tabs: **Findings** (severity and analyzer filters, "also found by" corroboration, dependency upgrade hints, fix status per row; clicking a finding opens a drawer with the explanation, confidence, breaking-risk warning, a side-by-side Monaco diff and copy button for verified patches only, a clear "not verified" state with the validator's reason otherwise, and regenerate-with-hint) and **Architecture** (loaded on demand): summary metrics and coverage warnings, the issue list, and a layered React Flow graph. Node size is LOC, color is the inferred layer, red edges are cycles or violations, dashed edges are type-only. Selecting an issue highlights its modules and dims the rest; clicking a module opens its metrics, importers and imports; directories can be expanded and collapsed. Its **AI review** sub-tab shows the critique, the hallucination rate and removed citations; clicking a cited module or import highlights it in the graph. Failed scans show the error message. Monaco is bundled locally (no CDN) and loaded only when a diff is opened.

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

LLM tests never call the real API: the real SDK client talks to an in-process fake (`tests/llm_fakes.py`, an `httpx2.MockTransport`), and a guard fails any test that builds a networked client. The integration tests recreate a separate `<db>_test` database and migrate it to head, use a `codeaudit-test-uploads` bucket, run Celery eagerly (`CELERY_TASK_ALWAYS_EAGER`), and run the real sandboxed Semgrep against `tests/fixtures/vulnerable_flask_app`. They skip if a service is unreachable. The workspace is kept under the system temp dir so rule packs and OSV databases (~240 MB, first run only) stay cached between runs.

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

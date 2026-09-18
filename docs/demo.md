# Demo script (2–3 minutes)

Every step opens a result that already exists. Nothing waits on a live scan, an LLM call or a website.

## Before the demo (15–30 minutes ahead)

```sh
ollama serve &                                   # only for seeding; the demo itself doesn't call the LLM
docker compose up -d --wait
(cd frontend && npm run dev)
python scripts/demo/seed.py --phishing-from-openphish   # several minutes with a local 7B model (enrichment dominates)
scripts/demo/snapshot.sh                          # offline fallback: demo/snapshot/
```

`seed.py` writes `demo/state.json` with every link used below. It seeds:
- **The demo repository:** [`demo/sample-repo`](../demo/sample-repo), also published as [kushal040511/codeaudit-demo](https://github.com/kushal040511/codeaudit-demo). A small Flask shop API that is intentionally insecure, with an import cycle and a layering inversion. It scores 44.3 (F).
- **Two contrast scans at pinned commits:** pallets/flask (a healthy library) and excalidraw (a 672-module TypeScript graph).
- **Design tokens** for `https://stripe.com`.
- **A phishing analysis** of the newest OpenPhish URL that is still up. Phishing pages die fast (in the validation run, 35% of feed URLs were already dead the same day), so no fixed URL can be relied on. The seeded result is what's shown, and `demo/state.json` is gitignored because it holds that live URL.

For the pull-request step, sign in with GitHub, scan `https://github.com/kushal040511/codeaudit-demo` from the UI, and open a PR from its Fixes tab once. That PR stays open as the thing to show.

Rehearse once with Wi-Fi off (see *Fallbacks*).

## Click path

The scores, counts and percentages quoted below come from the 2026-09-18 seed, recorded in `demo/state.json`, which is gitignored. The demo scan's score is deterministic. The LLM-dependent details (which fixes verified, the review's citations) vary from seed to seed, so check them against your own seed before presenting.

| Time | Screen | Click / say |
|---|---|---|
| 0:00 | Home | "Upload a repo or paste a GitHub URL. It runs Semgrep, Bandit, Ruff, OSV-Scanner and an import-graph analyzer, each in its own sandbox container." |
| 0:10 | `state.scans.demo.url` | Score card: **44.3 (F)**. "Deterministic and versioned. The LLM never changes it." Point at Security 25 and Dependencies 10. |
| 0:25 | **Findings** tab | Click the unsafe `yaml.load` finding (Bandit B506) in `shop/services/reports.py`. The drawer shows the explanation and a side-by-side diff marked **verified**: it applies with `git apply` and parses. Then click the SQL injection in `shop/services/users.py`: that suggestion is **not verified** (the model's patch didn't apply), and the UI says so instead of offering it. "The model is only trusted as far as the validator can check it." |
| 0:45 | **Architecture** tab | The graph opens. Click **Circular dependency (3 modules)**: `routes/orders → services/orders → models/order → routes/orders` lights up red. "Module level, built with tree-sitter, cycles and layer inversions." |
| 1:05 | **Architecture → AI review** | "Every file the model cites is checked against the graph." This seeded review cited 7 modules, and 1 didn't exist: it was removed and counted (hallucination rate 14.3%, shown on the panel). |
| 1:20 | **Fixes** tab | Tick the verified fixes one by one: the YAML fix and the dependency bumps. The projected score updates live: "each fix shows exactly how many points it's worth, and they compound." |
| 1:40 | GitHub PR (browser tab) | The PR CodeAudit opened on codeaudit-demo: one commit per fix, the score projection in the body. "Nothing is pushed until you preview and explicitly confirm." |
| 2:00 | `state.sites.phishing.link` | Risk gauge and evidence list: each signal with its points. Be straight about it: most of the score (+60) is the OpenPhish listing. The heuristics alone (new domain, no mail records) give 13. "Without reputation feeds, the heuristics catch about 38% of live phishing at 95% precision. It's a heuristic, not a verdict." |
| 2:20 | `state.sites.design.link` | Design tokens: palette with contrast, type scale, spacing grid. Export as Tailwind. |
| 2:40 | `state.scans["excalidraw/excalidraw"].url` → Architecture | A 672-module graph grouped by directory. Close. |

## Fallbacks

| Failure | What still works | Do this |
|---|---|---|
| **No network** | Everything local: scans, graph, fixes, projections, seeded site analyses. | Show the PR from [`docs/assets/demo-pr.gif`](assets/demo-pr.gif) instead of github.com. |
| **Ollama or the Anthropic API down** | Everything seeded: suggestions and reviews are already stored. Only *Regenerate* fails, and it fails with a clear 503. | Don't click Regenerate. |
| **Postgres/MinIO state lost, or the wrong machine** | — | `scripts/demo/restore.sh demo/snapshot`, then reload. The database restore was tested into a scratch database on 2026-09-18. Uploading the bucket back to MinIO wasn't tested or timed, and it's slow if the snapshot contains large uploads (1.1 GB here, because of the load test). Snapshot a clean stack for demo machines. |
| **Docker won't start** | — | Play the three GIFs in `docs/assets/` in order and narrate the same script. |
| **A seeded phishing page shows `failed`** | The design analysis and code scans. | Re-run `seed.py --phishing-from-openphish` before the demo, never during it. |
| **GitHub rate limit (URL scans)** | Zip uploads. | Seed with the default zip upload. Only the PR step needs a GitHub scan. |

## Money-shot GIFs

Regenerate against the seeded stack with `cd backend && uv run python ../scripts/demo/make_gifs.py`:

| GIF | Shows |
|---|---|
| [`demo-graph.gif`](assets/demo-graph.gif) | The architecture tab, with the 3-module cycle clicked and highlighted |
| [`demo-fixes.gif`](assets/demo-fixes.gif) | Verified fixes being selected, with the projected score and delta updating |
| [`demo-pr.gif`](assets/demo-pr.gif) | The pull request CodeAudit opened on codeaudit-demo: description, then the diff |

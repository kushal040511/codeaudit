# Rubric validation protocol (pre-registered)

Written and committed **before any of these repositories was scanned** (check with `git log -- validation/rubric/labels.csv`). The labels may not be edited after scanning. If a label is wrong, add a correction to `label_corrections.csv` with the reason. The report shows results with and without corrections.

## Question

Does the CodeAudit score *rank* repositories in the same order as an independent judgement of their quality, overall and per category?

## Why rank correlation

A 0–100 score has no ground-truth scale: nobody can say whether Flask "should" score 91 or 84. What we can check is whether the rubric orders repositories the way a reviewer would. Spearman's ρ measures that ordering, tolerates the monotone but non-linear shape of `100·2^(−penalty/half-life)`, and handles the ties that a 1–5 label scale produces. The same 20 repositories are also reported per group (vulnerable / tutorial / mature), because a ρ that only reflects "vulnerable apps score low" is a much weaker result than one that also orders repos within a group.

## Dataset

20 public GitHub repositories in the languages CodeAudit analyses (Python, JavaScript, TypeScript), each pinned to a commit SHA. Three groups:

- **vulnerable (6):** training apps that are insecure on purpose (PyGoat, DVPWA, DVNA, DVWS, NodeGoat, Vulnerable-Flask-App).
- **mature (9):** widely deployed, actively maintained libraries, frameworks and templates.
- **tutorial (5):** example and tutorial applications, some archived.

pydantic was left out because GitHub reports it as 453 MB, over the 200 MB clone limit. encode/starlette replaced it.

## Labels

- One labeller (the AI assistant building CodeAudit) assigned a 1–5 label per category and overall.
- The labels use only facts available without running CodeAudit: the project's stated purpose, maintenance activity and last commit date, archival status, and general knowledge of each project's structure.
- No analyzer, score or finding for any of these commits had been seen when the labels were written.

| Category | 1 | 3 | 5 |
|---|---|---|---|
| security | insecure by design | tutorial/demo code, no security review | widely deployed, security policy, active |
| dependencies | deps frozen ≥ 3 years | last maintained 1–3 years ago | actively maintained (commit within ~6 months) |
| architecture | single module or copy-paste structure | conventional but loose layout | clear package / layer structure |
| code_health | unmaintained, no lint discipline | ordinary | strict lint/type discipline |

## Known weaknesses (stated in advance)

- **One labeller, not blind to project reputation.** The labels encode reputation. The expected halo effect (a famous project labelled 5 everywhere) inflates correlations across categories.
- **Groups dominate.** The vulnerable-vs-mature contrast will drive most of ρ. The within-group numbers are the stricter test.
- **Code health applies to Python only** (Ruff), so that category has fewer data points.
- **n = 20.** The confidence intervals are wide. The report gives bootstrap 95% intervals.

## Procedure

1. Scan each repository by URL at its pinned SHA (`POST /api/scans {repo_url, ref}`) with LLM enrichment off (the score never depends on it).
2. Record the overall and per-category scores plus the `incomplete` flag (`results/<date>/scores.csv`).
3. Report Spearman ρ between label and score, overall and per category, with bootstrap CIs, plus per-group medians.
4. List every **inversion**: a pair where the labels differ by ≥ 2 but the scores order them the other way. Diagnose each one by reading the findings behind it.
5. If the rubric is changed as a result, keep the first-pass numbers in the report, rescore the stored findings under the new rubric, and report both. The labels stay fixed.
6. Weight sensitivity: rescore the stored findings with each category weight and half-life varied ±50%, and report the range of ρ.

# Experimental signals (rubric 1.1.0)

Five candidate signals were added to the rubric **as an experiment**: error handling, dependency health, git history, CI substance and test quality. Naming and comment metrics were added too, but as advisory only; see [ADR 0005](adr/0005-naming-and-comment-signals-are-advisory.md). Each signal is flag-gated and **off by default**, and each was measured against the pre-registered 20-repository labels before any decision.

**Status: every signal flag is still off.** With all flags off, rubric 1.1.0 scores exactly like 1.0 (tested). The recommendation at the end of this page is for review, not something that has been applied.

## How it's wired

| Flag (`.env`) | Default | What it does |
|---|---|---|
| `EXPERIMENTAL_SIGNALS_ENABLED` | false | Runs the six experimental analyzers and stores their output in `scans.signal_metrics` / `scans.advisory_metrics`. URL scans fetch `GIT_HISTORY_DEPTH` (200) commits instead of 1. **Never changes the score by itself.** |
| `RUBRIC_SIGNAL_ERROR_HANDLING`, `…_DEP_HEALTH`, `…_GIT_HISTORY`, `…_CI_QUALITY`, `…_TEST_QUALITY` | false | Scores that signal. |
| `RUBRIC_PROCESS_DIMENSION` | false | Scores git history and CI in a separate *Process* dimension (weight 0.15, others renormalised) instead of in architecture. |
| `RUBRIC_DEP_HEALTH_TARGET` | dependencies | Where dependency health's supply-chain part goes: `dependencies` or `security`. The unused/phantom part always goes to architecture. |

**Scoring rule.** Each enabled, applicable signal adds **one deduction line** to its dimension:

`penalty = half-life × (1 − signal score)`

A signal scoring 0 halves the dimension. Signals are rates, so they're already size-normalised. A signal that isn't applicable (no `.git`, no CI config, no manifest) is skipped with its reason and is never a penalty. The score breakdown (`GET /score`, and the UI's score card) lists every deduction, plus a zero-point line for each enabled signal that didn't apply. `scan_scores.rubric_config` records which signals were scored.

| Signal | Scored into | Analyzer |
|---|---|---|
| Error handling | code health ("Code Quality") | [`error_handling.py`](../backend/app/services/analyzers/error_handling.py): bare/swallowed excepts, empty catch, console-only catch, unhandled promises, un-awaited-in-try I/O, share of I/O call sites inside error handling |
| Test quality | code health | [`test_quality.py`](../backend/app/services/analyzers/test_quality.py): test/source LOC ratio, assertions per test (zero-assertion tests flagged), unit/integration/e2e mix, coverage from an existing report only. Tests are never executed. |
| Dependency health | dependencies (or security) and architecture | [`dep_health.py`](../backend/app/services/analyzers/dep_health.py): direct count vs baseline, freshness (PyPI/npm registry, cached, degrades offline), transitive count and depth from lockfiles, trivial packages; unused and phantom dependencies from the import graph |
| Git history | architecture ("Organization"), or Process | [`git_history.py`](../backend/app/services/analyzers/git_history.py): conventional and low-information messages, recency, activity, bus factor, author Gini, churn × complexity hotspots, direct-to-main ratio |
| CI substance | architecture, or Process | [`ci_quality.py`](../backend/app/services/analyzers/ci_quality.py): runs tests / lint / security scan / build, runs on PRs, deploy gated on tests |

**Naming.** The brief's "Code Quality" and "Organization" map to CodeAudit's existing `code_health` and `architecture` dimensions. CodeAudit also has a separate *Dependencies* dimension, which is the natural home for dependency health, so both targets were measured.

**Where it runs, and why.**
- **tree-sitter work** (error handling, test quality, advisory metrics, hotspot complexity) runs in a child process, like the architecture graph (`isolated_signal.py`).
- **git history** is read by `git log` **inside the sandbox container**, with the repository's own config hooks (external diff, textconv, fsmonitor) disabled. It's never read by the worker. URL scans capture it in the clone sandbox before `.git` is deleted. Uploads that include `.git` are read in a no-network sandbox.
- **Dependency health and git history run in a second phase**, after the import graph exists.
- **Experimental analyzers never make a scan `partial`.** A failed experimental analyzer is stored as "not applicable", with the error as its reason.

**Baselines.** The normal direct-dependency count (runtime + dev) is 23 for PyPI and 44 for npm. These are the medians over the study repositories that have a manifest (13 PyPI, 8 npm), computed without labels. They are in-sample.

## The experiment

- **Data.** The same 20 pinned commits and the same pre-registered labels as the [rubric study](validation.md#1-does-the-score-rank-repositories-correctly). Each commit was uploaded as a zip **including 200 commits of `.git` history**, so git history applies to all 20.
- **Baseline check.** The baseline rescored to the v1.0 result (overall ρ 0.66), so the new inputs didn't move it.
- **Outputs.** Snapshot, scans and full report: [`validation/rubric/results/20260919-v1.1/`](../validation/rubric/results/20260919-v1.1/signals-experiment.md), from [`signals_experiment.py`](../validation/rubric/signals_experiment.py).

**Coverage** (repos each signal applied to):
- error handling 20/20
- dependency health 20/20: freshness from live registries, but the transitive component on only 9 (the rest have no supported lockfile)
- git history 20/20
- test quality 20/20
- **CI 15/20**: five repos have no CI configuration
- advisory metrics 20/20

### Results: Spearman ρ against the labels

The Δ column is a **paired** bootstrap (2,000 resamples) of the change in overall ρ against the baseline. *Code health, same 13* restricts to the 13 Python repos, because enabling a code-quality signal also scores code health for JS repos, and that changes n from 13 to 20.

| Configuration | overall | Δ overall [95% CI] · P(Δ>0) | security | dependencies | architecture | code health (n) | code health, same 13 | median vuln / tut / mature |
|---|---|---|---|---|---|---|---|---|
| **baseline (rubric 1.0)** | **0.66** | — | 0.32 | 0.42 | −0.16 | 0.34 (13) | 0.34 | 40.5 / 69.5 / 74.1 |
| + error handling | 0.59 | **−0.07** [−0.26, +0.08] · 18% | 0.32 | 0.42 | −0.16 | −0.09 (20) | **−0.14** | 43.4 / 69.9 / 70.7 |
| + dependency health | 0.71 | +0.04 [+0.00, +0.16] · 76% | 0.32 | 0.44 | 0.09 | 0.34 (13) | 0.34 | 37.2 / 67.2 / 71.1 |
| + dependency health → security | 0.70 | +0.03 [−0.03, +0.14] · 76% | 0.33 | 0.42 | 0.09 | 0.34 (13) | 0.34 | 36.4 / 61.2 / 69.9 |
| + git history | 0.74 | +0.08 [−0.02, +0.24] · 90% | 0.32 | 0.42 | 0.19 | 0.34 (13) | 0.34 | 34.1 / 63.3 / 70.8 |
| + git history, **without recency/activity** | 0.73 | +0.07 [+0.00, +0.20] · 90% | 0.32 | 0.42 | 0.07 | 0.34 (13) | 0.34 | 34.5 / 64.6 / 69.9 |
| + git history (Process dimension) | 0.74 | +0.08 [−0.03, +0.23] · 88% | 0.32 | 0.42 | −0.16 | 0.34 (13) | 0.34 | 44.7 / 69.3 / 75.1 |
| + CI (in architecture) | 0.56 | **−0.10** [−0.35, +0.07] · 14% | 0.32 | 0.42 | −0.15 | 0.34 (13) | 0.34 | 33.2 / 69.5 / 68.8 |
| + CI (Process dimension) | 0.71 | +0.04 [−0.08, +0.20] · 74% | 0.32 | 0.42 | −0.16 | 0.34 (13) | 0.34 | 44.0 / 69.5 / 73.6 |
| + test quality | 0.70 | +0.03 [−0.15, +0.23] · 66% | 0.32 | 0.42 | −0.16 | 0.58 (20) | **0.74** | 45.9 / 63.4 / 73.7 |
| + git + CI (Process dimension) | 0.71 | +0.04 [−0.04, +0.18] · 74% | 0.32 | 0.42 | −0.16 | 0.34 (13) | 0.34 | 41.2 / 69.3 / 72.0 |
| + git + CI (in architecture) | 0.72 | +0.06 [−0.16, +0.25] · 74% | 0.32 | 0.42 | 0.11 | 0.34 (13) | 0.34 | 29.1 / 63.3 / 66.5 |
| all five (git/CI in architecture) | 0.70 | +0.04 [−0.15, +0.26] · 67% | 0.32 | 0.44 | 0.16 | 0.27 (20) | 0.47 | 30.7 / 52.2 / 59.0 |
| all five (Process dimension) | 0.69 | +0.03 [−0.14, +0.19] · 63% | 0.32 | 0.44 | 0.09 | 0.27 (20) | 0.47 | 40.2 / 58.8 / 64.9 |
| best subset, in-sample search: CI + dep health→security + git + test quality | 0.81 | +0.15 [−0.04, +0.43] · 91% ⚠ | 0.33 | 0.42 | 0.16 | 0.58 (20) | 0.74 | 34.2 / 49.5 / 64.3 |

**Group separation** is measured with Cliff's δ:
- **Mature vs vulnerable:** 0.85 at baseline. Every config except CI in architecture holds or improves it, up to 1.00 for the best subset.
- **Mature vs tutorial:** 0.33 at baseline. This is the weak spot in 1.0, and git history (0.56) and the best subset (0.69) improve it most.
- **Tutorial vs vulnerable:** error handling drops it from 0.73 to 0.53.

### Is the best subset real?

The exhaustive search covered 5 signals × Process on/off × dependency target, 84 configurations in all. It finds 0.81 in sample. That is a best-of-84 on 20 repos. To estimate how much of that gain survives:
1. re-select the best configuration inside each bootstrap resample;
2. score the chosen configuration on the out-of-bag repos only.

| | Selected config, out-of-bag ρ | Baseline, out-of-bag ρ | Mean gain | Resamples where selection helped |
|---|---|---|---|---|
| All components | 0.67 | 0.61 | +0.06 | **54%** |
| git recency/activity removed | 0.64 | 0.61 | +0.03 | **44%** |

**The search doesn't generalise:** picking the best subset beats the baseline on unseen repos about as often as a coin flip. So the 0.81 should not be adopted.

### Collinearity

This is the Spearman matrix across the four base dimensions and the signal scores; the full table is in the [report](../validation/rubric/results/20260919-v1.1/signals-experiment.md#collinearity-spearman-ρ-between-signals-n--repos-where-both-exist). Only one pair of distinct signals exceeds |0.8|:

- **CI × git history = 0.81** (n = 15). Both mostly measure "an actively run project with a process". One should go.

The composite dependency-health score against its own sub-parts (0.89–0.90) is excluded, because it's collinear by construction. Next highest:
- test quality × git history 0.63
- test quality × CI 0.61
- architecture × code health −0.62

### Weights: hand-picked vs fitted

Dimension weights were fitted by non-negative least squares against the overall label.

| Dimension | Hand-picked | Learned, baseline | Learned, best subset |
|---|---|---|---|
| security | 0.40 | 0.46 | 0.32 |
| dependencies | 0.20 | 0.32 | 0.27 |
| architecture | 0.20 | **0.00** | **0.00** |
| code health | 0.20 | 0.23 | 0.41 |

| ρ | Baseline dimensions | Best-subset dimensions |
|---|---|---|
| Hand-picked weights | **0.66** | 0.81 |
| Learned, in sample | 0.74 | 0.80 |
| Learned, **leave-one-out** | **0.46** | 0.74 |

- **The learned weights overfit.** In sample they beat the hand-picked ones (0.74 vs 0.66), but leave-one-out they're worse (0.46). **Keep the hand-picked weights.**
- **Architecture gets zero weight.** Both fits give it none, which agrees with its ρ ≈ 0: the architecture dimension currently adds noise to the overall score. That's the same conclusion as [validation diagnosis #5](validation.md#the-inversions-diagnosed).

## Verdicts

| Signal | Measured effect | Verdict |
|---|---|---|
| **Error handling** | Overall −0.07. Code health drops from +0.34 to **−0.14** on the same repos. Tutorial vs vulnerable separation drops from 0.73 to 0.53. | **Drop.** Its central component (share of I/O sites inside try) penalises well-designed libraries: DRF, Starlette and the FastAPI template score 0.0, because a library should let I/O errors propagate to its caller. Tutorials with 1–4 handlers get extreme, noisy scores. The Python findings partly duplicate Ruff (E722 bare except is already scored). |
| **CI substance** | In architecture: overall −0.10. In Process: +0.04 [−0.08, +0.20]. Applies to only 15/20. Collinear with git history (0.81). | **Drop.** It's redundant with git history, and its sign depends on where it's put. |
| **Git history** | +0.07 [0.00, +0.20] with recency/activity removed (90% of resamples improve). With them, +0.08. | **Keep as a candidate**, without the recency and activity components. The dependencies label was *defined* by last-commit date, so those two components leak the label; the remaining components hold almost the same gain. The strongest candidate, but not established at n = 20. |
| **Test quality** | Overall +0.03 [−0.15, +0.23]. But **code health on the same 13 repos: 0.34 → 0.74**, the largest per-dimension gain of any signal. | **Keep as a candidate** for the code health dimension. The overall gain is small because code health carries 20%. |
| **Dependency health** | +0.04 [0.00, +0.16]. Architecture −0.16 → 0.09, from the unused/phantom part. Security target isn't better than dependencies. | **Borderline.** It's the most expensive signal (registry lookups) for a small gain. Keep it collected and unscored until held-out data decides. |
| **Process dimension vs Organization** | git alone: 0.74 vs 0.74. git + CI: 0.71 vs 0.72. git without recency: 0.71 vs 0.73. | **No measurable difference.** Process has no labels of its own, so only its effect on overall can be measured. Putting git in architecture raises architecture ρ a little, but only because the architecture labels share the maintenance halo. Prefer a separate Process dimension for interpretability, if git history is enabled at all. |
| **Naming and comments** | Not scored ([ADR 0005](adr/0005-naming-and-comment-signals-are-advisory.md)) | **Advisory only.** Stored and given to the architecture review. |

**Bottom line.**
- **Two signals are clearly worse and should be dropped:** error handling and CI.
- **Three are weak positives** whose 95% intervals all touch or cross zero: git history without recency, test quality, dependency health.
- **Nothing is enabled.** With n = 20, one labeller, and a best-subset search that fails its out-of-bag check, none of these can be *established* on this data.
- **To decide:** enable test quality and git history (without recency) together on a held-out, independently labelled set, then keep whatever still improves.

## Limitations of this experiment

- **The labels.** They're the same 20 repositories and the same single-labeller labels as rubric 1.0, and the halo effect favours anything that tracks "well-known, maintained project". Git history and CI are exposed to that the most.
- **Recency on pinned commits** is measured against scan time, so archived repositories look stale. That is correct for a current scan, but it's also the labelling criterion for dependencies. That's why the leak-free variant is reported.
- **Dependency freshness is live:** it's measured against today's PyPI and npm, not the registry as of each commit's date.
- **In-sample choices:** the baselines (23/44) and the component formulas are hand-set priors, and the baselines come from the same repositories.
- **The zips include `.git`** so git history applies to all 20. In normal use, only URL scans, and uploads that include `.git`, have history. Zip uploads usually don't.

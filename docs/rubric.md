# Scoring rubric (v1.0)

Implementation: [`backend/app/services/scoring/rubric.py`](../backend/app/services/scoring/rubric.py). The rubric is deterministic: the same findings always give the same score, and LLM output never enters it. Each stored score carries `rubric_version`, and scores are only comparable within a version.

Validation results, including where it fails, are summarised at the end and covered fully in [validation.md](validation.md).

## Categories and weights

| Category | Weight | Analyzers | Severity weights (critical / error / warning / info) | Size normalisation | Half-life |
|---|---|---|---|---|---|
| Security | 40% | Semgrep, Bandit | 10 / 5 / 2 / 0.5 | ∛KLOC, capped at 6 (reached at 216 KLOC) | 12 |
| Dependencies | 20% | OSV-Scanner | 10 / 5 / 2 / 0.5 | none | 25 |
| Architecture | 20% | cycles, layering, god modules, orphans | 10 / 5 / 2 / 0.5 | √(modules / 20) | 20 |
| Code health | 20% | Ruff | 3 / 1.5 / 0.5 / 0.1 | √KLOC | 25 |

**Overall** is the weighted mean of the categories that could be scored. A category that doesn't apply is dropped and the weights are renormalised; for example, a JavaScript repo has no Ruff run, so there's no code-health score. **If an analyzer *failed*,** the score is flagged `incomplete` with the reason, and shouldn't be compared with complete scores.

**Grades:** A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55, otherwise F.

## From findings to a category score

**1. Finding weight.**

`weight = severity weight × 1.25 if corroborated × 0.2 if in test code`

- **Corroborated** means another analyzer reported the same issue (see [Deduplication](reference.md#deduplication) in the reference).
- **Test code** is matched by path: `tests/`, `__tests__/`, `spec/`, `e2e/`, `test_*.py`, `*_test.py`, `*.test.ts`, `*.spec.js`, `conftest.py`.

**2. Repeat damping, within one rule.** Sort the rule's findings by weight, heaviest first. The i-th finding counts `weight × i^−0.75`. So:
- 1 finding counts 1×
- 10 count about 3.8×
- 100 count about 9.2×
- 15,000 count about 40.8×

A pattern repeated 500 times is worse than once, but not 500 times worse. For example, Starlette's 1,776 Bandit B101 `assert` findings are info-level (0.5), and 1,659 of them are in test code (×0.2). Together they add a raw penalty of **6.1** (224 without damping), which is about one error-level finding (5). Source: the rubric study snapshot. The rubric docstring's claim that 15,000 test asserts cost "about four real findings" is loose: 15,000 test asserts come to about 0.1 × 40.8 ≈ 4, about two warnings.

**3. Size normalisation.** The rule penalties are summed, then divided by the size factor.
- **Security** uses ∛KLOC, capped, because a SQL injection is an absolute risk that a bigger codebase barely dilutes.
- **Code health** uses √KLOC, because lint debt grows with size.
- **Architecture** normalises by module count.
- **Dependencies** isn't normalised: a vulnerable lockfile entry is equally bad in any size of repo.

**4. Curve.**

`category score = 100 · 2^(−penalty / half-life)`

Every half-life of penalty halves the score. The curve never reaches 0, so two very bad repos stay distinguishable. It's steep at the top, so the first few serious findings cost the most.

| Security penalty (half-life 12) | 0 | 6 | 12 | 24 | 36 | 48 |
|---|---|---|---|---|---|---|
| Score | 100 | 70.7 | 50 | 25 | 12.5 | 6.25 |

One error-level Semgrep finding in a 1 KLOC repo is a penalty of 5, which scores 74.9.

## Properties the code guarantees (and tests)

Tests are in [`tests/unit/scoring/`](../backend/tests/unit/scoring/); all 25 pass on 2026-09-18.

- **Fixing never lowers the score.** The damping multipliers decrease, so removing any finding never raises a penalty. This is checked by a randomised property test.
- **Impacts are exact.** `findings.score_impact` is how many overall points fixing that one finding gains. It's computed in closed form, O(n log n) per rule, and tested against brute-force rescoring. Fixes compound, so fixing a set gains at least the sum of its impacts. `POST /score/projection` rescores any selection exactly, and that's what the Fixes tab shows.
- **Severity, corroboration and test paths order impacts as expected.**
- **Size rules:** a larger codebase tolerates more findings in the size-normalised categories.
- **Incompleteness:** a failed analyzer drops its category, renormalises the weights and flags the score `incomplete`.
- **Fixture benchmark:** clean layered repo 100 (A) > one layering skip > an import cycle > the vulnerable polyglot app (F).

## How fixes are prioritised

[`priority.py`](../backend/app/services/scoring/priority.py) sends the top `LLM_MAX_FIX_FINDINGS` (default 20) findings to the LLM, ordered by:
1. `score_impact`, descending
2. severity, then corroboration
3. then file and line, so the order is deterministic

Architecture findings are excluded; the architecture review covers them. The fixes CodeAudit suggests are therefore the ones worth the most points.

## Where the weights came from

The weights, half-lives and curve are **hand-set priors**. They were chosen to make the property tests and the fixture benchmark hold, and tuned on two real scans (pydantic and the vulnerable polyglot fixture). **They were not fitted to labelled data.** The first external check was the pre-registered 20-repository study on 2026-09-18; see below.

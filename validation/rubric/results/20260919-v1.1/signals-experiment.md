# Rubric 1.1 signal experiment

## Configurations (Spearman ρ vs pre-registered labels)

| Configuration | overall [95% CI] | Δ overall vs baseline [paired 95% CI] · P(Δ>0) | security | dependencies | architecture | code_health | code_health, same 13 Python repos | median vuln / tut / mature | Cliff's δ mature>vuln | mature>tut |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline (no signals = rubric 1.0) | **0.66** [0.28, 0.87] | +0.00 [+0.00, +0.00] · 0% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.34 (n=13) | 0.34 | 40.5 / 69.5 / 74.1 | 0.85 | 0.33 |
| + error_handling | **0.59** [0.19, 0.84] | -0.07 [-0.26, +0.08] · 18% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | -0.09 (n=20) | -0.14 | 43.4 / 69.9 / 70.7 | 0.89 | 0.16 |
| + dep_health | **0.71** [0.36, 0.89] | +0.04 [+0.00, +0.16] · 76% | 0.32 (n=20) | 0.44 (n=20) | 0.09 (n=20) | 0.34 (n=13) | 0.34 | 37.2 / 67.2 / 71.1 | 0.93 | 0.38 |
| + git_history | **0.74** [0.41, 0.90] | +0.08 [-0.02, +0.24] · 90% | 0.32 (n=20) | 0.42 (n=20) | 0.19 (n=20) | 0.34 (n=13) | 0.34 | 34.1 / 63.3 / 70.8 | 0.93 | 0.56 |
| + ci_quality | **0.56** [0.12, 0.82] | -0.10 [-0.35, +0.07] · 14% | 0.32 (n=20) | 0.42 (n=20) | -0.15 (n=20) | 0.34 (n=13) | 0.34 | 33.2 / 69.5 / 68.8 | 0.74 | 0.16 |
| + test_quality | **0.70** [0.35, 0.91] | +0.03 [-0.15, +0.23] · 66% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.58 (n=20) | 0.74 | 45.9 / 63.4 / 73.7 | 0.96 | 0.38 |
| + dep_health → security | **0.70** [0.34, 0.88] | +0.03 [-0.03, +0.14] · 76% | 0.33 (n=20) | 0.42 (n=20) | 0.09 (n=20) | 0.34 (n=13) | 0.34 | 36.4 / 61.2 / 69.9 | 0.85 | 0.47 |
| + git_history (process dimension) | **0.74** [0.41, 0.90] | +0.08 [-0.03, +0.23] · 88% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.34 (n=13) | 0.34 | 44.7 / 69.3 / 75.1 | 0.93 | 0.56 |
| + ci_quality (process dimension) | **0.71** [0.37, 0.89] | +0.04 [-0.08, +0.20] · 74% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.34 (n=13) | 0.34 | 44.0 / 69.5 / 73.6 | 0.93 | 0.47 |
| + git_history + ci_quality (process dimension) | **0.71** [0.35, 0.89] | +0.04 [-0.04, +0.18] · 74% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.34 (n=13) | 0.34 | 41.2 / 69.3 / 72.0 | 0.85 | 0.51 |
| + git_history + ci_quality (in architecture) | **0.72** [0.36, 0.89] | +0.06 [-0.16, +0.25] · 74% | 0.32 (n=20) | 0.42 (n=20) | 0.11 (n=20) | 0.34 (n=13) | 0.34 | 29.1 / 63.3 / 66.5 | 0.89 | 0.47 |
| all signals (git/CI in architecture) | **0.70** [0.36, 0.89] | +0.04 [-0.15, +0.26] · 67% | 0.32 (n=20) | 0.44 (n=20) | 0.16 (n=20) | 0.27 (n=20) | 0.47 | 30.7 / 52.2 / 59.0 | 0.96 | 0.38 |
| all signals (process dimension) | **0.69** [0.33, 0.89] | +0.03 [-0.14, +0.19] · 63% | 0.32 (n=20) | 0.44 (n=20) | 0.09 (n=20) | 0.27 (n=20) | 0.47 | 40.2 / 58.8 / 64.9 | 0.93 | 0.38 |
| + git_history without recency/activity | **0.73** [0.40, 0.90] | +0.07 [+0.00, +0.20] · 90% | 0.32 (n=20) | 0.42 (n=20) | 0.07 (n=20) | 0.34 (n=13) | 0.34 | 34.5 / 64.6 / 69.9 | 0.93 | 0.47 |
| + git_history without recency/activity (process dimension) | **0.71** [0.36, 0.90] | +0.05 [-0.04, +0.18] · 80% | 0.32 (n=20) | 0.42 (n=20) | -0.16 (n=20) | 0.34 (n=13) | 0.34 | 44.9 / 70.3 / 74.5 | 0.89 | 0.51 |
| best subset (in-sample search): ci_quality,dep_health>security,git_history,test_quality | **0.81** [0.57, 0.93] | +0.15 [-0.04, +0.43] · 91% | 0.33 (n=20) | 0.42 (n=20) | 0.16 (n=20) | 0.58 (n=20) | 0.74 | 34.2 / 49.5 / 64.3 | 1.00 | 0.69 |

## Coverage: repositories each signal applied to

| Signal | applicable | collected | reasons when not applicable |
|---|---|---|---|
| error_handling | 20 | 20 |  |
| dep_health | 20 | 20 |  |
| git_history | 20 | 20 |  |
| ci_quality | 15 | 20 | no CI configuration found |
| test_quality | 20 | 20 |  |
| advisory | 20 | 0 |  |

## Raw signal score vs labels (ρ, repos where applicable)

| Signal | n | security | dependencies | architecture | code_health | overall |
|---|---|---|---|---|---|---|
| error_handling | 20 | -0.01 | -0.05 | -0.13 | -0.17 | -0.03 |
| dep_health | 20 | 0.29 | 0.29 | 0.24 | 0.27 | 0.36 |
| git_history | 20 | 0.69 | 0.85 | 0.60 | 0.63 | 0.70 |
| ci_quality | 15 | 0.68 | 0.85 | 0.39 | 0.51 | 0.68 |
| test_quality | 20 | 0.71 | 0.78 | 0.72 | 0.71 | 0.76 |

## Best subset

In-sample best: `ci_quality,dep_health>security,git_history,test_quality` (overall ρ 0.81).

Top 5 in sample: `ci_quality,dep_health>security,git_history,test_quality` 0.81; `git_history,test_quality` 0.80; `dep_health>security,git_history,test_quality` 0.80; `dep_health>dependencies,git_history,test_quality` 0.79; `ci_quality,dep_health>security,test_quality,process-dimension` 0.77

Out-of-bag check (299 bootstraps: select the best subset on the resample, evaluate on the left-out repos): selected ρ 0.67 vs baseline ρ 0.61, mean improvement 0.06, improved in 54% of resamples.

Same search with git_history's recency/activity removed (leak-free): in-sample best `dep_health>security,git_history,test_quality` (0.79); top 5: `dep_health>security,git_history,test_quality` 0.79; `ci_quality,dep_health>security,git_history,test_quality` 0.77; `ci_quality,dep_health>security,test_quality,process-dimension` 0.77; `dep_health>dependencies,git_history` 0.75; `dep_health>security,test_quality` 0.75. Out-of-bag: selected ρ 0.64 vs baseline 0.61, mean improvement 0.03, improved in 44% of resamples.

## Collinearity (Spearman ρ between signals; n = repos where both exist)

| | security | dependencies | architecture | code_health | error_handling | dep_health | git_history | ci_quality | test_quality | dep_health.supply | dep_health.hygiene |
|---|---|---|---|---|---|---|---|---|---|---|---|
| security | — | -0.00 | -0.26 | 0.34 | 0.33 | 0.24 | 0.23 | 0.30 | 0.52 | 0.18 | 0.37 |
| dependencies | -0.00 | — | 0.32 | 0.07 | -0.01 | 0.52 | 0.20 | 0.49 | 0.28 | 0.54 | 0.37 |
| architecture | -0.26 | 0.32 | — | -0.62 | -0.05 | 0.41 | 0.13 | 0.25 | 0.01 | 0.39 | 0.32 |
| code_health | 0.34 | 0.07 | -0.62 | — | -0.13 | 0.43 | -0.15 | -0.26 | 0.50 | 0.28 | 0.54 |
| error_handling | 0.33 | -0.01 | -0.05 | -0.13 | — | 0.13 | -0.13 | -0.12 | 0.15 | -0.03 | 0.27 |
| dep_health | 0.24 | 0.52 | 0.41 | 0.43 | 0.13 | — | 0.28 | 0.30 | 0.54 | **0.90** | **0.89** |
| git_history | 0.23 | 0.20 | 0.13 | -0.15 | -0.13 | 0.28 | — | **0.81** | 0.63 | 0.29 | 0.23 |
| ci_quality | 0.30 | 0.49 | 0.25 | -0.26 | -0.12 | 0.30 | **0.81** | — | 0.61 | 0.43 | 0.12 |
| test_quality | 0.52 | 0.28 | 0.01 | 0.50 | 0.15 | 0.54 | 0.63 | 0.61 | — | 0.52 | 0.53 |
| dep_health.supply | 0.18 | 0.54 | 0.39 | 0.28 | -0.03 | **0.90** | 0.29 | 0.43 | 0.52 | — | 0.65 |
| dep_health.hygiene | 0.37 | 0.37 | 0.32 | 0.54 | 0.27 | **0.89** | 0.23 | 0.12 | 0.53 | 0.65 | — |

Pairs above |0.8|: signal:ci_quality × signal:git_history = 0.81 (n=15).

## Weights: hand-picked vs fitted (NNLS against the overall label)

**baseline**

| Dimension | hand-picked | learned |
|---|---|---|
| security | 0.40 | 0.46 |
| dependencies | 0.20 | 0.32 |
| architecture | 0.20 | 0.00 |
| code_health | 0.20 | 0.23 |

ρ with hand-picked weights 0.66; learned, in sample 0.74; learned, leave-one-out 0.46.

**best_subset**

| Dimension | hand-picked | learned |
|---|---|---|
| security | 0.40 | 0.32 |
| dependencies | 0.20 | 0.27 |
| architecture | 0.20 | 0.00 |
| code_health | 0.20 | 0.41 |

ρ with hand-picked weights 0.81; learned, in sample 0.80; learned, leave-one-out 0.74.


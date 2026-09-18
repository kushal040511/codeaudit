# LLM enrichment evaluation

6 scans, model(s): ollama/qwen2.5-coder:7b.

## Patch validation

94 fix suggestions; 86 contained a patch that was validated.

- **Pass rate (valid ÷ validated patches): 23/86 = 26.7%**
- Valid ÷ all suggestions: 24.5%

| Status | Count |
|---|---|
| failed_to_apply | 63 |
| valid | 23 |
| not_validated | 6 |
| no_patch | 2 |

Failure reasons:

- context does not match the file: 42
- not a unified diff: 21

By analyzer of the finding:

| Analyzer | valid | failed_to_apply | syntax_error | other |
|---|---|---|---|---|
| bandit | 3 | 14 | 0 | 8 |
| dependency | 17 | 23 | 0 | 0 |
| ruff | 0 | 14 | 0 | 0 |
| semgrep | 3 | 12 | 0 | 0 |

## Architecture review citations

4 of 5 reviews completed. Module citations: 52, invalid: 0 → **pooled hallucination rate 0.0%**
Issues kept: 5, dropped for lack of valid evidence: 1.

Stricter view: 0 of 28 evidence citations were rejected (**0.0%**), of which 0 claimed an import between real modules that doesn't exist (not counted by the stored rate). Paths named in prose but absent from the graph (not counted anywhere): 0.

| Repository | Status | Module refs | Invalid refs | Stored rate | Evidence rejected | Issues kept | Dropped |
|---|---|---|---|---|---|---|---|
| adhoc-33554202 | ready | 48 | 0 | 0.0% | 0/24 | 1 | 0 |
| adhoc-456fedfa | ready | 1 | 0 | 0.0% | 0/1 | 1 | 0 |
| adhoc-4ee367b5 | failed | 0 | 0 | n/a | 0/0 | 0 | 0 |
| adhoc-7dea999f | ready | 2 | 0 | 0.0% | 0/2 | 2 | 0 |
| adhoc-f849c614 | ready | 1 | 0 | 0.0% | 0/1 | 1 | 1 |

Failed LLM calls by reason:

- invalid_output: invalid JSON: Expecting value at line 1 column 1: 2
- interrupted: The worker restarted while this request was running.: 1
- max_tokens: Output hit the 16,000 token limit.: 1
- max_tokens: Output hit the 4,096 token limit.: 1
- None: : 1

LLM calls: 76 (6 failed). Fix-suggestion call latency p50 9 s, p95 19 s.

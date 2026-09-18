# LLM enrichment evaluation

9 scans, model(s): ollama/qwen2.5-coder:7b.

## Patch validation

171 fix suggestions; 145 contained a patch that was validated.

- **Pass rate (valid ÷ validated patches): 21/145 = 14.5%**
- Valid ÷ all suggestions: 12.3%

| Status | Count |
|---|---|
| failed_to_apply | 124 |
| valid | 21 |
| no_patch | 14 |
| not_validated | 12 |

Failure reasons:

- not a unified diff: 65
- context does not match the file: 42
- corrupt patch: 13
- touches a file it may not: 4

By analyzer of the finding:

| Analyzer | valid | failed_to_apply | syntax_error | other |
|---|---|---|---|---|
| bandit | 1 | 26 | 0 | 13 |
| dependency | 17 | 21 | 0 | 1 |
| ruff | 2 | 15 | 0 | 9 |
| semgrep | 1 | 62 | 0 | 3 |

## Architecture review citations

6 of 9 reviews completed. Module citations: 56, invalid: 0 → **pooled hallucination rate 0.0%**
Issues kept: 9, dropped for lack of valid evidence: 0.

Stricter view: 0 of 38 evidence citations were rejected (**0.0%**), of which 0 claimed an import between real modules that doesn't exist (not counted by the stored rate). Paths named in prose but absent from the graph (not counted anywhere): 0.

| Repository | Status | Module refs | Invalid refs | Stored rate | Evidence rejected | Issues kept | Dropped |
|---|---|---|---|---|---|---|---|
| OWASP/NodeGoat | ready | 3 | 0 | 0.0% | 0/3 | 1 | 0 |
| adeyosemanputra/pygoat | failed | 0 | 0 | n/a | 0/0 | 0 | 0 |
| anxolerd/dvpwa | failed | 0 | 0 | n/a | 0/0 | 0 | 0 |
| appsecco/dvna | ready | 7 | 0 | 0.0% | 0/7 | 2 | 0 |
| gothinkster/django-realworld-example-app | ready | 9 | 0 | 0.0% | 0/7 | 2 | 0 |
| gothinkster/flask-realworld-example-app | failed | 0 | 0 | n/a | 0/0 | 0 | 0 |
| miguelgrinberg/microblog | ready | 28 | 0 | 0.0% | 0/14 | 1 | 0 |
| mjhea0/flaskr-tdd | ready | 5 | 0 | 0.0% | 0/3 | 2 | 0 |
| we45/Vulnerable-Flask-App | ready | 4 | 0 | 0.0% | 0/4 | 1 | 0 |

Failed LLM calls by reason:

- invalid_output: schema validation failed: fixes.0.breaking_risk: Field required: 9
- invalid_output: invalid JSON: Expecting value at line 1 column 1: 8
- max_tokens: Output hit the 4,096 token limit.: 1

LLM calls: 131 (18 failed). Fix-suggestion call latency p50 11 s, p95 32 s.

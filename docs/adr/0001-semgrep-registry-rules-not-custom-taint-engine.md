# ADR 0001: Use Semgrep registry rules, not a custom taint engine

- Status: accepted
- Code: `backend/app/services/analyzers/semgrep.py`, `backend/app/services/analyzers/semgrep_rules.py`

## Context

CodeAudit needs to find injection-style flaws, where untrusted input flows into a dangerous sink, such as SQL injection, command injection or `eval`. Pattern matching alone can't find these because source and sink are usually on different lines. That takes dataflow (taint) analysis.

The sandbox constraints are strict. Semgrep runs with no network (`network_mode` `none` in `run_in_sandbox`, `backend/app/services/analyzers/sandbox.py`), so `--config=auto` can't fetch rules at scan time. The README records that this was verified: it fails with a DNS error.

## Decision

Use Semgrep's own dataflow engine with rules from the Semgrep Registry. Don't write a taint engine or custom taint rules.

- `select_packs` in `semgrep_rules.py` always picks `p/security-audit` and `p/secrets`. It adds language packs from `LANGUAGE_PACKS`, for example `p/python` and `p/flask` for Python, or `p/javascript` and `p/nodejs` for JavaScript.
- The worker (not the sandbox) downloads each pack from `https://semgrep.dev/c/{pack}`. It caches the pack for `semgrep_rules_max_age_hours` (24 by default, `backend/app/config.py`) under `<workspace>/_rules/semgrep`, replacing it atomically. If a refresh fails, the stale copy is used. The pack is mounted read-only into the sandbox (`SemgrepAnalyzer.run`).
- Some of these packs include taint-mode (`mode: taint`) rules. For example, a locally cached `p/flask` contains `python.flask.security.injection.tainted-sql-string.tainted-sql-string`. Semgrep runs them like any other rule, and CodeAudit contains no taint logic of its own (the repository has no `mode: taint` rules).

## Consequences

Positive:

- Dataflow coverage for several languages without building or maintaining an engine. Adding a language means adding one entry to `LANGUAGE_PACKS`.
- Results follow upstream rule fixes within the 24 h cache window.
- Rule IDs match the public registry because the parser strips the local directory prefix (README, "Known limitations").

Negative and known gaps:

- **Licensing.** Registry rules are under the Semgrep Rules License, which restricts using them to provide a competing hosted service. The README and the `semgrep_rules.py` docstring both flag this as a review item before commercial use.
- **Known misses** (README, "Known limitations"). `p/secrets` matches provider-specific token formats, so it doesn't flag generic hardcoded passwords (`DB_PASSWORD = "..."`) or `app.secret_key = "..."`. Some JS DOM sinks without a taint source are also missed.
- **No interprocedural cross-file taint.** Semgrep Community Edition's taint analysis doesn't track flows across files or function boundaries. That needs the commercial Pro engine. A source in one module that reaches a sink in another isn't reported.
- **Reproducibility.** Rules change upstream, so the same code can get different findings on different days. README, "Known gaps" item 3, suggests pinning rule versions or baking them into an image.
- **Network in the worker.** The rule download runs in the worker, which has network access (README, "Known gaps" item 3).
- Semgrep's CWE tags are unreliable for dedup, so `categories.py` classifies by rule-id keywords first (README, "Deduplication").

## Alternatives considered

- **Custom taint engine** on top of the tree-sitter parsers already used for the graph (`backend/app/services/graph/parser.py`). This would need per-language source, sink and sanitizer models and propagation rules. It's a large, open-ended effort, and it would be a new component parsing untrusted code.
- **Custom Semgrep taint rules.** These avoid the license restriction, and the README names writing or licensing your own rules as the alternative. They're not done yet, and they would still be limited by the Community Edition engine.
- **`--config=auto`.** Ruled out because it needs network at scan time and metrics turned on.
- **Bandit only.** Bandit is kept as a second Python signal (`bandit.py`), and cross-analyzer corroboration raises confidence in scoring. On its own it covers only Python.

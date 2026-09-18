# ADR 0005: Naming and comment signals are advisory

- Status: accepted
- Code: `backend/app/services/analyzers/advisory.py`, `backend/app/services/analyzers/signals.py`, `backend/app/services/scan_pipeline.py` (`store_signals`), `backend/app/services/llm/architect.py` (`advisory_digest`)

## Context

Rubric 1.1 adds experimental signals beyond tool findings: error handling, dependency health, git history, CI quality and test quality. Naming and comments are obvious candidates too. They're cheap to measure with tree-sitter: naming-convention conformance per language, single-letter and generic names (`data`, `tmp`, `manager`...), comment density and docstring coverage on public definitions.

As quality judgments, though, they're weak:

- **Conventions differ legitimately.** Django, React, SQLAlchemy, `unittest` (`setUp`), `ast.NodeVisitor` (`visit_Name`) and generated clients all impose names that break a language's default style. PascalCase functions are the convention for React components. Tuning around every framework isn't practical.
- **Low reproducibility.** Two reviewers disagree on whether `data` or `handler` is too generic in context, and on whether a function needs a docstring. There's no ground truth to validate a threshold against.
- **Easy to game.** Comment density and docstring coverage go up with boilerplate (`"""Get the user."""` on `get_user`) that adds nothing. Scoring them would reward that.
- **Subjective thresholds.** Any cut-off for "enough comments" or "too many short names" would be arbitrary. Unlike the other signals, we have no evidence linking them to defects.

## Decision

- The `advisory` analyzer computes the metrics (see the module docstring for exact definitions) but **never emits findings and is never scored**. Its `SignalReport` always has `score=None` and no components. The pipeline stores it in `scans.advisory_metrics`, separately from `scans.signal_metrics`, which is what the rubric reads.
- The metrics reach the user through the **LLM architecture review**. The digest gets a compact `advisory_metrics` summary: per-language naming conformance, single-letter and generic-name rates, comment density, docstring coverage and at most 10 examples. The system prompt says these are qualitative, non-scored hints, to be used only as supporting context and never as the basis of an issue on their own.
- We'll revisit this only with validation evidence: for example, a study showing that a metric separates repositories that reviewers rate differently, reproducibly across frameworks.

## Consequences

Positive:

- Scores stay comparable across projects with different, equally valid conventions.
- Nobody can raise their grade by adding boilerplate comments or renaming variables.
- The measurements are still collected, so a future validation study can use stored scans.
- The review can mention naming or documentation when it supports a structural point ("`utils/` modules named `helper`, `manager`...").

Negative:

- One more child-process tree-sitter pass per scan when experimental signals are on.
- Advisory numbers don't appear in the grade, so a user reading only the score won't see them.
- The LLM may still over-weight the hints despite the prompt. Citations are verified against the graph as usual, but prose isn't.

## Alternatives considered

- **Score them like the other signals.** Rejected for the reasons in Context: no ground truth, framework-dependent and gameable.
- **Emit findings (as pep8-naming or ESLint's `camelcase` do).** Every non-conforming or undocumented name would become a finding. Since scans can't use the project's own lint configuration to opt out, that would add noise to every scan, and findings feed the score indirectly.
- **Don't compute them at all.** That would lose useful context for the review and the data needed to ever validate them.

# Architecture decision records

Short records of decisions that shape CodeAudit. Each has a context, the decision, its consequences and the alternatives considered. For the overall system, see [`../architecture.md`](../architecture.md).

| # | Decision | Status |
|---|---|---|
| [0001](0001-semgrep-registry-rules-not-custom-taint-engine.md) | Use Semgrep registry rules (including their taint-mode rules), not a custom taint engine | accepted |
| [0002](0002-module-level-dependency-graph.md) | Model architecture as a module-level dependency graph | accepted |
| [0003](0003-per-analyzer-failure-isolation.md) | Isolate analyzer failures: `partial` scans, `analyzer_runs` rows, `incomplete` scores, tree-sitter in a child process | accepted |
| [0004](0004-pull-requests-require-explicit-confirmation.md) | Pull requests require preview plus explicit `{"confirm": true}`, with only verified patches and a single code path | accepted |
| [0005](0005-naming-and-comment-signals-are-advisory.md) | Naming and comment metrics are computed but advisory: never scored, never findings, passed to the LLM review as qualitative context | accepted |

New ADRs take the next number and use the same four sections.

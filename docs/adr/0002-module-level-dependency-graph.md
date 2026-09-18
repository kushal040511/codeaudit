# ADR 0002: Module-level dependency graph

- Status: accepted
- Code: `backend/app/services/graph/` (`parser.py`, `resolver.py`, `builder.py`, `metrics.py`, `layers.py`, `view.py`, `isolated.py`)

## Context

The architecture analyzer reports repository-wide structure: import cycles, coupling, god modules, layering violations and orphans. It also feeds a graph view in the UI and a digest for the LLM architecture review (`backend/app/services/llm/architect.py`). The unit of analysis has to be one that the parser can extract reliably from Python, JavaScript and TypeScript, and that stays readable for mid-size repositories.

## Decision

Nodes are modules (source files), and edges are imports between them.

- `builder.py`: "Nodes are internal modules (every discovered source file, including ones that failed to parse). Edges are internal imports, one per (importer, imported) pair with all statements aggregated." External packages are aggregated per package, not added as nodes.
- `parser.py` extracts only what's needed per module: imports (with statement text, line, and type-only and lazy flags), top-level symbols, LOC and a definition count (`ParsedModule`). It doesn't build function bodies into a call graph.
- `resolver.py` classifies every import as `internal`, `asset`, `external` or `unresolved` with a reason. `metrics.py` computes cycles, fan-in, fan-out, instability, betweenness, god modules, layering and orphans on the runtime graph, with type-only imports excluded.
- The UI view groups modules by directory when the graph exceeds `max_nodes` (`view.py`).

## Consequences

Positive:

- Imports are syntactic and explicit in all three languages, so tree-sitter plus path resolution is enough. The README's measured resolution coverage (README, "Architecture graph", **Measured** table, one run each on a MacBook) is 99.6% for pydantic @7b15a78 (454 files, 143k LOC), 99.8% for excalidraw @a918648 (670 files, 186k LOC) and 100% for full-stack-fastapi-template @cb740b6.
- It's fast enough to run on every scan. The same table reports totals of 1.04 s (pydantic), 1.24 s (excalidraw) and 96 ms (full-stack-fastapi-template) for `analyze_architecture`. Through the whole stack, the README reports the architecture run at 2.1 s including process start-up for pydantic.
- Cycles, layering and coupling are defined naturally at module level, and each issue cites concrete import statements. That lets the LLM review's citations be checked against `graph_nodes` and `graph_edges` (`verify_review` in `architect.py`).

Negative:

- No function-level or call-level information. A cycle between two modules isn't broken down into which functions cause it, beyond the import statements.
- Modules loaded by string (plugins, Celery `include`, framework conventions) have no edge and show up as orphans at info severity (README, "Known limits").
- Layers are path heuristics (`layers.py`), not derived from call behaviour.
- Non-literal dynamic imports stay `unresolved`. These account for most of the unresolved imports in the README's measurements.

## Alternatives considered

- **Function-level call graph.** Resolving calls in Python and JavaScript needs type and dataflow information (dynamic dispatch, higher-order functions) that a syntax parser doesn't provide. It would add many more nodes than the UI's grouped view is designed for, and it would be a larger native-parsing surface for untrusted input.
- **Package or directory-level graph only.** Too coarse to report which import creates a cycle or a layering violation. Directory grouping is still available as a view over the module graph (`view.py`), so this isn't needed as the stored model.
- **Language-specific tools** (for example, Python- or JS-only import analyzers). These would mean one tool and one output format per language. A single tree-sitter pipeline gives one graph model for all supported languages.

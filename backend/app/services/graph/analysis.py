"""Run the whole architecture analysis: parse -> resolve -> build -> metrics."""

import logging
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.errors import AnalyzerTimeoutError
from app.services.graph.builder import ArchitectureGraph, build_graph
from app.services.graph.metrics import ArchitectureMetrics, compute_metrics
from app.services.graph.parser import ParsedModule, RawImport, discover_source_files, parse_file
from app.services.graph.resolver import (
    RepoIndex,
    ResolvedImport,
    resolution_stats,
    resolve_imports,
)

logger = logging.getLogger(__name__)

MAX_REPORTED_SKIPS = 50
MAX_UNRESOLVED_SAMPLES = 50


@dataclass
class ArchitectureReport:
    modules: list[ParsedModule]
    resolved: list[ResolvedImport]
    graph: ArchitectureGraph
    metrics: ArchitectureMetrics
    summary: dict[str, Any]  # metrics.summary + parse, resolution and timing details


def import_form(raw: RawImport) -> str:
    """Syntactic form of an import, for reporting which forms fail to resolve."""
    if raw.dynamic:
        target = "non-literal"
    elif raw.level or raw.specifier.startswith("."):
        target = "relative"
    elif raw.specifier.startswith(("@/", "~/", "#")):
        target = "alias"
    else:
        target = "absolute"
    return f"{raw.kind} ({target})"


def _unresolved_reason_kind(reason: str) -> str:
    """Group reasons without the module name: "file './x' not found" -> "file not found"."""
    words = [w for w in reason.split() if not (w.startswith(("'", '"')) and len(w) > 1)]
    return " ".join(words)


def analyze_architecture(root: Path, deadline: float | None = None) -> ArchitectureReport:
    """Analyze the repository at `root`. `deadline` is a time.monotonic() value."""

    def check_deadline(phase: str) -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise AnalyzerTimeoutError(f"Architecture analysis ran out of time while {phase}.")

    timings: dict[str, int] = {}

    started = time.perf_counter()
    files = discover_source_files(root)
    modules: list[ParsedModule] = []
    for rel_path in files:
        check_deadline("parsing")
        module = parse_file(root, rel_path)
        if module.error:
            logger.warning("architecture: skipping %s (%s)", rel_path, module.error)
        elif module.warning:
            logger.info("architecture: %s (%s)", rel_path, module.warning)
        modules.append(module)
    timings["parse_ms"] = round((time.perf_counter() - started) * 1000)

    check_deadline("resolving imports")
    started = time.perf_counter()
    index = RepoIndex(root, files)
    resolved = resolve_imports(index, modules)
    timings["resolve_ms"] = round((time.perf_counter() - started) * 1000)

    check_deadline("building the graph")
    started = time.perf_counter()
    graph = build_graph(index, modules, resolved)
    timings["build_ms"] = round((time.perf_counter() - started) * 1000)

    check_deadline("computing metrics")
    started = time.perf_counter()
    metrics = compute_metrics(graph)
    timings["metrics_ms"] = round((time.perf_counter() - started) * 1000)

    stats = resolution_stats(resolved)
    unresolved = [r for r in resolved if not r.resolved]
    skipped = [m for m in modules if m.error]
    partial = [m for m in modules if m.warning and not m.error]
    summary = {
        **metrics.summary,
        "parse": {
            "files": len(modules),
            "parsed": len(modules) - len(skipped),
            "skipped": len(skipped),
            "skipped_files": [{"path": m.path, "reason": m.error} for m in skipped][
                :MAX_REPORTED_SKIPS
            ],
            # Parsed with errors: kept in the graph, but possibly missing imports.
            "partial": len(partial),
            "partial_files": [{"path": m.path, "reason": m.warning} for m in partial][
                :MAX_REPORTED_SKIPS
            ],
        },
        "resolution": {
            "total": stats.total,
            "internal": stats.internal,
            "external": stats.external,
            "asset": stats.asset,
            "unresolved": stats.unresolved,
            "undeclared_external": stats.undeclared_external,
            "coverage": round(stats.coverage, 4),
            "unresolved_by_reason": dict(
                Counter(_unresolved_reason_kind(r.reason or "") for r in unresolved).most_common()
            ),
            "unresolved_by_form": dict(
                Counter(import_form(r.raw) for r in unresolved).most_common()
            ),
        },
        "external_dependency_count": len(
            {(e.language == "python", e.package) for e in graph.external}
        ),
        "timings": {**timings, "total_ms": sum(timings.values())},
    }
    return ArchitectureReport(
        modules=modules, resolved=resolved, graph=graph, metrics=metrics, summary=summary
    )

"""Architecture analyzer: repository-wide import graph, cycles, coupling, layering.

Unlike the other analyzers this doesn't need a sandbox container: tree-sitter only
parses (never executes) the code and input files are size-capped. It runs in a
child process of the worker (graph/isolated.py) so a native parser crash or a
runaway analysis can't take the worker down.
"""

import json
import time
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.sandbox import AnalyzerOutputError
from app.services.graph.analysis import ArchitectureReport
from app.services.graph.isolated import run_isolated

ANALYZER_NAME = "architecture"
LOW_COVERAGE = 0.85


def issue_payload(report: ArchitectureReport) -> list[dict[str, Any]]:
    graph = report.graph.graph
    return [
        {
            "key": issue.key,
            "issue_type": issue.issue_type.value,
            "severity": issue.severity.value,
            "title": issue.title,
            "description": issue.description,
            "involved_modules": issue.involved_modules,
            "involved_edges": [list(e) for e in issue.involved_edges],
            "metric_value": issue.metric_value,
            "file_path": graph.nodes[issue.location_module]["path"],
            "line": issue.location_line,
            "details": issue.details,
        }
        for issue in report.metrics.issues
    ]


def coverage_warnings(summary: dict[str, Any]) -> tuple[str, ...]:
    warnings: list[str] = []
    parse = summary["parse"]
    if parse["skipped"]:
        listed = ", ".join(f["path"] for f in parse["skipped_files"][:5])
        more = f" and {parse['skipped'] - 5} more" if parse["skipped"] > 5 else ""
        warnings.append(
            f"{parse['skipped']} file(s) could not be parsed and have no dependencies in the"
            f" graph: {listed}{more}."
        )
    resolution = summary["resolution"]
    if resolution["total"] and resolution["coverage"] < LOW_COVERAGE:
        warnings.append(
            f"Only {resolution['coverage']:.0%} of imports could be resolved"
            f" ({resolution['unresolved']} of {resolution['total']}); the graph is incomplete."
        )
    if summary["cycles_truncated"]:
        warnings.append(f"Only the {summary['cycle_count']} shortest import cycles are reported.")
    for issue_type, count in summary["issues_omitted"].items():
        warnings.append(f"{count} further {issue_type.replace('_', ' ')} issues were not reported.")
    return tuple(warnings)


class ArchitectureAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Architecture"
    supported_languages = frozenset({"python", "javascript", "typescript"})

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = None  # runs in a child process of the worker
        self.timeout_seconds = self._settings.architecture_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        report = run_isolated(repo_path, context.work_dir, self.timeout_seconds)
        raw_output = json.dumps({"summary": report.summary, "issues": issue_payload(report)})
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=self.parse(raw_output),
            raw_output=raw_output,
            duration_ms=int((time.monotonic() - started) * 1000),
            warnings=coverage_warnings(report.summary),
            artifact=report,
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        try:
            payload = json.loads(raw_output)
            issues = payload["issues"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AnalyzerOutputError("Architecture analysis produced invalid output.") from exc
        return [
            FindingData(
                analyzer=self.name,
                rule_id=f"architecture/{issue['issue_type']}",
                severity=Severity(issue["severity"]),
                file_path=issue["file_path"],
                start_line=issue["line"],
                end_line=issue["line"],
                message=issue["description"],
                # Structural issues are never duplicates of other analyzers' findings.
                category=f"architecture:{issue['key']}",
                raw=issue,
            )
            for issue in issues
        ]

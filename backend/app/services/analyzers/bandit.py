"""Bandit analyzer: Python security linter, run in the sandbox with JSON output."""

import json
import logging
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.categories import categorize, parse_cwe_ids
from app.services.analyzers.sandbox import (
    OUTPUT_FILENAME,
    OUTPUT_MOUNT,
    AnalyzerOutputError,
    SandboxLimits,
    run_tool,
)
from app.services.analyzers.snippets import normalize_path, strip_nul

logger = logging.getLogger(__name__)

ANALYZER_NAME = "bandit"

# 0 = no issues, 1 = issues found. Anything else is a failure.
_OK_EXIT_CODES = frozenset({0, 1})

_SEVERITY_MAP = {"LOW": Severity.INFO, "MEDIUM": Severity.WARNING, "HIGH": Severity.ERROR}
_DOWNGRADE = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARNING,
    Severity.WARNING: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def normalize_severity(issue_severity: object, issue_confidence: object = "HIGH") -> Severity:
    """LOW/MEDIUM/HIGH -> info/warning/error, one step lower when Bandit's confidence is LOW.

    Bandit has no "critical": pattern matching alone can't establish exploitability.
    """
    severity = _SEVERITY_MAP.get(str(issue_severity).upper(), Severity.INFO)
    if str(issue_confidence).upper() == "LOW":
        severity = _DOWNGRADE[severity]
    return severity


def parse_bandit_output(payload: dict[str, Any]) -> list[FindingData]:
    results = payload.get("results")
    if not isinstance(results, list):
        raise AnalyzerOutputError("Bandit output is missing the results list.")

    findings: list[FindingData] = []
    for result in results:
        try:
            test_id = str(result["test_id"])
            test_name = str(result.get("test_name", ""))
            path = normalize_path(str(result["filename"]))
            start_line = int(result["line_number"])
            line_range = [int(n) for n in result.get("line_range") or [start_line]]
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("skipping malformed bandit result: %r", exc)
            continue

        cwe = result.get("issue_cwe")
        cwe_ids = parse_cwe_ids(cwe.get("id")) if isinstance(cwe, dict) else ()
        findings.append(
            FindingData(
                analyzer=ANALYZER_NAME,
                rule_id=strip_nul(test_id)[:512],
                severity=normalize_severity(
                    result.get("issue_severity"), result.get("issue_confidence")
                ),
                file_path=strip_nul(path),
                start_line=start_line,
                end_line=max([start_line, *line_range]),
                message=strip_nul(str(result.get("issue_text", "")).strip()),
                # Bandit's `code` has line-number prefixes and context lines; the
                # pipeline reads the exact lines from the source tree instead.
                code_snippet=None,
                category=categorize(f"{test_id} {test_name}", cwe_ids),
                cwe_ids=cwe_ids,
                raw=strip_nul(result),
            )
        )
    return findings


class BanditAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Bandit"
    supported_languages = frozenset({"python"})

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = self._settings.bandit_image
        self.timeout_seconds = self._settings.bandit_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        settings = self._settings
        output = run_tool(
            display_name=self.display_name,
            image=settings.bandit_image,
            entrypoint=["bandit"],
            command=[
                "--recursive",
                ".",
                "--format",
                "json",
                "--output",
                f"{OUTPUT_MOUNT}/{OUTPUT_FILENAME}",
                # Uploaded code must not be able to hide issues: a project-level
                # `.bandit` file is otherwise auto-loaded and can skip every test.
                "--ini",
                "/dev/null",
                "--ignore-nosec",
                "--quiet",
            ],
            repo_path=repo_path,
            output_dir=context.work_dir / f"{self.name}-out",
            limits=SandboxLimits(
                cpus=settings.bandit_cpus,
                memory=settings.bandit_memory_limit,
                timeout_seconds=self.timeout_seconds,
            ),
            ok_exit_codes=_OK_EXIT_CODES,
            labels={"codeaudit.scan_id": context.scan_id, "codeaudit.analyzer": self.name},
        )
        payload = _load(output.raw_output)
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=parse_bandit_output(payload),
            raw_output=output.raw_output,
            duration_ms=int(output.duration_seconds * 1000),
            warnings=bandit_warnings(payload),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        return parse_bandit_output(_load(raw_output))


def _load(raw_output: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise AnalyzerOutputError("Bandit produced invalid JSON output.") from exc
    if not isinstance(payload, dict):
        raise AnalyzerOutputError("Bandit output is not a JSON object.")
    return payload


def bandit_warnings(payload: dict[str, Any]) -> tuple[str, ...]:
    """Files Bandit could not scan (syntax errors, Python 2 code)."""
    errors = payload.get("errors") or []
    if not isinstance(errors, list) or not errors:
        return ()
    paths = sorted(
        {
            normalize_path(str(err["filename"]))
            for err in errors
            if isinstance(err, dict) and err.get("filename")
        }
    )
    listed = ", ".join(paths[:5]) + (f" and {len(paths) - 5} more" if len(paths) > 5 else "")
    return (f"Bandit could not scan {len(errors)} file(s): {listed}.",)

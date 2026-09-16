"""Ruff analyzer: Python code-health linter, run in the sandbox with JSON output.

Ruff reports every rule with the same severity, so severity is derived from the
rule code. Security rules (flake8-bandit, "S") are left to Bandit.
"""

import json
import logging
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.sandbox import (
    OUTPUT_FILENAME,
    OUTPUT_MOUNT,
    AnalyzerOutputError,
    SandboxLimits,
    run_tool,
)
from app.services.analyzers.snippets import normalize_path, strip_nul

logger = logging.getLogger(__name__)

ANALYZER_NAME = "ruff"

# pyflakes, pycodestyle errors, bugbear, complexity, pylint errors.
SELECTED_RULES = ("E4", "E7", "E9", "F", "B", "C90", "PLE")

# First matching prefix wins, so more specific codes come first.
_SEVERITY_PREFIXES: tuple[tuple[str, Severity], ...] = (
    # Code that fails at runtime or doesn't parse: syntax errors, undefined names,
    # invalid format strings, `return` outside a function, pylint errors.
    ("E9", Severity.ERROR),
    ("F5", Severity.ERROR),
    ("F63", Severity.ERROR),
    ("F7", Severity.ERROR),
    ("F82", Severity.ERROR),
    ("PLE", Severity.ERROR),
    # Likely bugs: bare except, redefined names, duplicate keys, bugbear.
    ("E722", Severity.WARNING),
    ("F6", Severity.WARNING),
    ("F811", Severity.WARNING),
    ("B", Severity.WARNING),
    # Hygiene: unused imports/variables, style, complexity.
)


def normalize_severity(code: str | None) -> Severity:
    if not code:  # syntax errors have no rule code
        return Severity.ERROR
    for prefix, severity in _SEVERITY_PREFIXES:
        if code.startswith(prefix):
            return severity
    return Severity.INFO


def parse_ruff_output(payload: list[Any]) -> list[FindingData]:
    findings: list[FindingData] = []
    for result in payload:
        try:
            code = result.get("code")
            path = normalize_path(str(result["filename"]))
            start_line = int(result["location"]["row"])
            end = result.get("end_location") or {}
            end_line = int(end.get("row", start_line))
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            logger.warning("skipping malformed ruff result: %r", exc)
            continue

        rule_id = str(code) if code else str(result.get("name") or "syntax-error")
        findings.append(
            FindingData(
                analyzer=ANALYZER_NAME,
                rule_id=strip_nul(rule_id)[:512],
                severity=normalize_severity(code),
                file_path=strip_nul(path),
                start_line=start_line,
                end_line=max(end_line, start_line),
                message=strip_nul(str(result.get("message", "")).strip()),
                # Lint rules have no cross-tool equivalent; never merged with others.
                category=f"code-quality:{rule_id}",
                raw=strip_nul(result),
            )
        )
    return findings


class RuffAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Ruff"
    supported_languages = frozenset({"python"})

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = self._settings.ruff_image
        self.timeout_seconds = self._settings.ruff_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        settings = self._settings
        output = run_tool(
            display_name=self.display_name,
            image=settings.ruff_image,
            entrypoint=["/ruff"],
            command=[
                "check",
                # Ignore the project's own config: uploaded code must not choose its
                # rules, and `extend` could point anywhere on the filesystem.
                "--isolated",
                "--no-cache",  # the source mount is read-only
                "--exit-zero",
                "--select",
                ",".join(SELECTED_RULES),
                "--output-format",
                "json",
                "--output-file",
                f"{OUTPUT_MOUNT}/{OUTPUT_FILENAME}",
                ".",
            ],
            repo_path=repo_path,
            output_dir=context.work_dir / f"{self.name}-out",
            limits=SandboxLimits(
                cpus=settings.ruff_cpus,
                memory=settings.ruff_memory_limit,
                timeout_seconds=self.timeout_seconds,
            ),
            # --exit-zero: findings don't change the exit code; 2 is a ruff crash.
            ok_exit_codes=frozenset({0}),
            labels={"codeaudit.scan_id": context.scan_id, "codeaudit.analyzer": self.name},
        )
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=self.parse(output.raw_output),
            raw_output=output.raw_output,
            duration_ms=int(output.duration_seconds * 1000),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise AnalyzerOutputError("Ruff produced invalid JSON output.") from exc
        if not isinstance(payload, list):
            raise AnalyzerOutputError("Ruff output is not a JSON list.")
        return parse_ruff_output(payload)

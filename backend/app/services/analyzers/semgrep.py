"""Semgrep analyzer: runs the semgrep CLI in the sandbox and normalises its JSON output."""

import json
import logging
from datetime import timedelta
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
    SandboxMount,
    run_tool,
)
from app.services.analyzers.semgrep_rules import ensure_rule_packs, select_packs
from app.services.analyzers.snippets import normalize_path, strip_nul

logger = logging.getLogger(__name__)

ANALYZER_NAME = "semgrep"
RULES_MOUNT = "/rules"

# Semgrep prefixes ids of rules loaded from local files with their directory
# ("rules.python.flask..."). Strip it so ids match the public registry.
RULE_ID_PREFIX = RULES_MOUNT.strip("/") + "."

# Semgrep CE returns this instead of `extra.lines` without a registry login.
_LINES_PLACEHOLDER = "requires login"

_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "LOW": Severity.INFO,
    "WARNING": Severity.WARNING,
    "MEDIUM": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "HIGH": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
}

# 0 = success, 1 = findings reported with --error. Anything else is a failure.
_OK_EXIT_CODES = frozenset({0, 1})


def map_severity(value: object) -> Severity:
    return _SEVERITY_MAP.get(str(value).upper(), Severity.INFO)


def parse_semgrep_output(
    payload: dict[str, Any], rule_id_prefix: str = RULE_ID_PREFIX
) -> list[FindingData]:
    """Map `semgrep --json` output to findings.

    Duplicate results (the same rule at the same location, e.g. from overlapping
    packs) are collapsed. Snippets come from `extra.lines` when semgrep provides
    them; otherwise the pipeline reads them from the source tree.
    """
    results = payload.get("results")
    if not isinstance(results, list):
        raise AnalyzerOutputError("Semgrep output is missing the results list.")

    findings: list[FindingData] = []
    seen: set[tuple[Any, ...]] = set()
    for result in results:
        try:
            check_id = str(result["check_id"])
            path = normalize_path(str(result["path"]))
            start, end = result["start"], result["end"]
            start_line, end_line = int(start["line"]), int(end["line"])
            extra = result.get("extra") or {}
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("skipping malformed semgrep result: %r", exc)
            continue

        rule_id = check_id.removeprefix(rule_id_prefix)[:512]
        key = (rule_id, path, start_line, start.get("col"), end_line, end.get("col"))
        if key in seen:
            continue
        seen.add(key)

        snippet = extra.get("lines")
        if not isinstance(snippet, str) or snippet.strip() in {"", _LINES_PLACEHOLDER}:
            snippet = None
        metadata = extra.get("metadata")
        cwe_ids = parse_cwe_ids(metadata.get("cwe", [])) if isinstance(metadata, dict) else ()

        findings.append(
            FindingData(
                analyzer=ANALYZER_NAME,
                rule_id=strip_nul(rule_id),
                severity=map_severity(extra.get("severity")),
                file_path=strip_nul(path),
                start_line=start_line,
                end_line=max(end_line, start_line),
                message=strip_nul(str(extra.get("message", "")).strip()),
                code_snippet=strip_nul(snippet),
                category=categorize(rule_id, cwe_ids),
                cwe_ids=cwe_ids,
                raw=strip_nul(result),
            )
        )
    return findings


class SemgrepAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Semgrep"
    supported_languages = frozenset()  # security-audit and secrets packs apply to any code

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = self._settings.semgrep_image
        self.timeout_seconds = self._settings.semgrep_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        settings = self._settings
        packs = select_packs(sorted(context.language_names))
        rules_dir = Path(settings.scan_workspace_dir) / "_rules" / "semgrep"
        rule_files = ensure_rule_packs(
            packs, rules_dir, timedelta(hours=settings.semgrep_rules_max_age_hours)
        )

        command = [
            "semgrep",
            "scan",
            *(f"--config={RULES_MOUNT}/{rule_file.name}" for rule_file in rule_files),
            f"--json-output={OUTPUT_MOUNT}/{OUTPUT_FILENAME}",
            "--metrics=off",
            "--disable-version-check",
            f"--jobs={max(1, int(settings.semgrep_cpus))}",
            "--quiet",
            ".",
        ]
        logger.info("running semgrep for scan %s with packs %s", context.scan_id, packs)
        output = run_tool(
            display_name=self.display_name,
            image=settings.semgrep_image,
            command=command,
            repo_path=repo_path,
            output_dir=context.work_dir / f"{self.name}-out",
            extra_mounts=[SandboxMount(rules_dir, RULES_MOUNT, read_only=True)],
            limits=SandboxLimits(
                cpus=settings.semgrep_cpus,
                memory=settings.semgrep_memory_limit,
                timeout_seconds=self.timeout_seconds,
            ),
            ok_exit_codes=_OK_EXIT_CODES,
            labels={"codeaudit.scan_id": context.scan_id, "codeaudit.analyzer": self.name},
        )
        payload = _load(output.raw_output)
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=parse_semgrep_output(payload),
            raw_output=output.raw_output,
            duration_ms=int(output.duration_seconds * 1000),
            warnings=semgrep_warnings(payload),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        return parse_semgrep_output(_load(raw_output))


def _load(raw_output: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise AnalyzerOutputError("Semgrep produced invalid JSON output.") from exc
    if not isinstance(payload, dict):
        raise AnalyzerOutputError("Semgrep output is not a JSON object.")
    return payload


def semgrep_warnings(payload: dict[str, Any]) -> tuple[str, ...]:
    """Summarise non-fatal errors (unparsable files, rule timeouts) that reduce coverage."""
    errors = payload.get("errors") or []
    if not isinstance(errors, list) or not errors:
        return ()
    paths = sorted(
        {
            normalize_path(str(err["path"]))
            for err in errors
            if isinstance(err, dict) and err.get("path")
        }
    )
    listed = ", ".join(paths[:5]) + (f" and {len(paths) - 5} more" if len(paths) > 5 else "")
    detail = f" in {listed}" if paths else ""
    return (
        f"Semgrep reported {len(errors)} non-fatal error(s){detail}; coverage may be incomplete.",
    )

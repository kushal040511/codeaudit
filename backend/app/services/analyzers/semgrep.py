"""Semgrep analyzer: runs the semgrep CLI in the sandbox and normalises its JSON output."""

import json
import logging
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.core.errors import AnalysisError
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerContext, AnalyzerFinding
from app.services.analyzers.semgrep_rules import ensure_rule_packs, select_packs
from app.services.sandbox import SandboxLimits, SandboxMount, run_in_sandbox

logger = logging.getLogger(__name__)

ANALYZER_NAME = "semgrep"

SOURCE_MOUNT = "/src"
RULES_MOUNT = "/rules"
OUTPUT_MOUNT = "/out"
RESULTS_FILENAME = "results.json"

# Semgrep prefixes ids of rules loaded from local files with their directory
# ("rules.python.flask..."). Strip it so ids match the public registry.
RULE_ID_PREFIX = RULES_MOUNT.strip("/") + "."

MAX_OUTPUT_BYTES = 100 * 1024 * 1024
SNIPPET_MAX_LINES = 20
SNIPPET_MAX_CHARS = 4000

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


class SemgrepError(AnalysisError):
    """Semgrep failed or produced unusable output."""


def map_severity(value: object) -> Severity:
    return _SEVERITY_MAP.get(str(value).upper(), Severity.INFO)


def _strip_nul(value: Any) -> Any:
    """Postgres text and JSONB reject NUL characters."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    return value


def read_snippet(source_root: Path, rel_path: str, start_line: int, end_line: int) -> str | None:
    """Read lines [start_line, end_line] (capped) from a scanned file."""
    root = source_root.resolve()
    path = (root / rel_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None

    last = min(end_line, start_line + SNIPPET_MAX_LINES - 1)
    lines: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                if lineno > last:
                    break
                if lineno >= start_line:
                    lines.append(line.rstrip("\r\n"))
    except OSError:
        return None
    snippet = "\n".join(lines)[:SNIPPET_MAX_CHARS]
    return snippet or None


def parse_semgrep_output(
    payload: dict[str, Any],
    source_root: Path | None = None,
    rule_id_prefix: str = RULE_ID_PREFIX,
) -> list[AnalyzerFinding]:
    """Map `semgrep --json` output to findings.

    Duplicate results (the same rule at the same location, e.g. from overlapping
    packs) are collapsed. Snippets come from `extra.lines` when semgrep provides
    them, otherwise they are read from `source_root`.
    """
    results = payload.get("results")
    if not isinstance(results, list):
        raise SemgrepError("Semgrep output is missing the results list.")

    findings: list[AnalyzerFinding] = []
    seen: set[tuple[Any, ...]] = set()
    for result in results:
        try:
            check_id = str(result["check_id"])
            path = str(result["path"]).removeprefix("./")
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
            snippet = read_snippet(source_root, path, start_line, end_line) if source_root else None

        findings.append(
            AnalyzerFinding(
                analyzer=ANALYZER_NAME,
                rule_id=_strip_nul(rule_id),
                severity=map_severity(extra.get("severity")),
                file_path=_strip_nul(path),
                start_line=start_line,
                end_line=max(end_line, start_line),
                message=_strip_nul(str(extra.get("message", "")).strip()),
                code_snippet=_strip_nul(snippet),
                raw=_strip_nul(result),
            )
        )
    return findings


class SemgrepAnalyzer(Analyzer):
    name = ANALYZER_NAME

    def run(self, ctx: AnalyzerContext) -> list[AnalyzerFinding]:
        settings = get_settings()

        packs = select_packs(lang.language for lang in ctx.languages)
        rules_dir = Path(settings.scan_workspace_dir) / "_rules" / "semgrep"
        rule_files = ensure_rule_packs(
            packs, rules_dir, timedelta(hours=settings.semgrep_rules_max_age_hours)
        )

        out_dir = ctx.work_dir / "semgrep-out"
        out_dir.mkdir()
        os.chmod(out_dir, 0o777)  # noqa: S103 - per-scan dir; the sandbox runs as nobody

        command = [
            "semgrep",
            "scan",
            *(f"--config={RULES_MOUNT}/{rule_file.name}" for rule_file in rule_files),
            f"--json-output={OUTPUT_MOUNT}/{RESULTS_FILENAME}",
            "--metrics=off",
            "--disable-version-check",
            f"--jobs={max(1, int(settings.semgrep_cpus))}",
            "--quiet",
            ".",
        ]
        logger.info("running semgrep for scan %s with packs %s", ctx.scan_id, packs)
        result = run_in_sandbox(
            image=settings.semgrep_image,
            command=command,
            working_dir=SOURCE_MOUNT,
            mounts=[
                SandboxMount(ctx.source_dir, SOURCE_MOUNT, read_only=True),
                SandboxMount(rules_dir, RULES_MOUNT, read_only=True),
                SandboxMount(out_dir, OUTPUT_MOUNT, read_only=False),
            ],
            limits=SandboxLimits(
                cpus=settings.semgrep_cpus,
                memory=settings.semgrep_memory_limit,
                timeout_seconds=settings.semgrep_timeout_seconds,
            ),
            labels={"codeaudit.scan_id": ctx.scan_id, "codeaudit.analyzer": self.name},
        )

        if result.oom_killed:
            raise SemgrepError(
                f"Semgrep ran out of memory (limit {settings.semgrep_memory_limit})."
            )
        if result.exit_code not in _OK_EXIT_CODES:
            stderr_tail = result.stderr.strip()[-500:] or "no error output"
            raise SemgrepError(f"Semgrep exited with code {result.exit_code}: {stderr_tail}")

        results_path = out_dir / RESULTS_FILENAME
        if not results_path.is_file():
            raise SemgrepError("Semgrep finished without writing results.")
        if results_path.stat().st_size > MAX_OUTPUT_BYTES:
            raise SemgrepError("Semgrep output exceeds the size limit.")
        try:
            payload = json.loads(results_path.read_bytes())
        except json.JSONDecodeError as exc:
            raise SemgrepError("Semgrep produced invalid JSON output.") from exc

        if errors := payload.get("errors"):
            logger.warning(
                "semgrep reported %d non-fatal errors for scan %s", len(errors), ctx.scan_id
            )
        findings = parse_semgrep_output(payload, source_root=ctx.source_dir)
        logger.info(
            "semgrep finished for scan %s in %ss: %d findings",
            ctx.scan_id,
            result.duration_seconds,
            len(findings),
        )
        return findings

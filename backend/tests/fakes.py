"""Test doubles for the analyzer layer (no Docker)."""

import threading
from collections.abc import Callable
from pathlib import Path

from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext


def make_finding(
    analyzer: str = "fake",
    rule_id: str = "rule",
    *,
    file_path: str = "app.py",
    start_line: int = 1,
    end_line: int | None = None,
    severity: Severity = Severity.WARNING,
    message: str = "issue",
    category: str | None = None,
    code_snippet: str | None = None,
) -> FindingData:
    return FindingData(
        analyzer=analyzer,
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line if end_line is not None else start_line,
        message=message,
        code_snippet=code_snippet,
        category=category,
        raw={"rule": rule_id},
    )


class FakeAnalyzer(Analyzer):
    """Implements the analyzer interface without a sandbox.

    `behavior` runs inside run(): return findings, or raise to simulate a crash,
    a timeout (SandboxTimeoutError) or an infrastructure error.
    """

    display_name = "Fake"

    def __init__(
        self,
        name: str,
        findings: list[FindingData] | None = None,
        *,
        languages: frozenset[str] = frozenset(),
        behavior: Callable[[], list[FindingData]] | None = None,
        timeout_seconds: int = 30,
        barrier: threading.Barrier | None = None,
    ) -> None:
        self.name = name
        self.display_name = name.title()
        self.supported_languages = languages
        self.docker_image = None
        self.timeout_seconds = timeout_seconds
        self._findings = findings or []
        self._behavior = behavior
        self._barrier = barrier
        self.calls: list[tuple[Path, ScanContext]] = []

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        self.calls.append((repo_path, context))
        if self._barrier is not None:
            # Only returns once every analyzer sharing the barrier is running at once.
            self._barrier.wait(timeout=5)
        findings = self._behavior() if self._behavior else self._findings
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=list(findings),
            raw_output=f"{len(findings)} findings",
            duration_ms=1,
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        return list(self._findings)

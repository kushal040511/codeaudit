"""The analyzer interface: every tool is run, parsed and reported the same way."""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from app.models import Severity
from app.services.languages import DetectedLanguage


@dataclass(frozen=True)
class FindingData:
    """Tool-agnostic finding, normalised from an analyzer's native output."""

    analyzer: str
    rule_id: str
    severity: Severity
    file_path: str  # relative to the repository root, POSIX separators
    start_line: int
    end_line: int
    message: str
    code_snippet: str | None = None
    # Coarse issue class used to find the same issue reported by several tools
    # ("sql-injection"). None means "unique to this rule" (see dedup.py).
    category: str | None = None
    cwe_ids: tuple[int, ...] = ()
    # Vulnerable-dependency details: package, installed_version, advisory_id, fixed_version...
    dependency: dict[str, Any] | None = None
    # Other analyzers that reported the same issue (filled by deduplication).
    corroborated_by: tuple[str, ...] = ()
    # The findings merged into this one: [{"analyzer", "rule_id", "severity", "message"}].
    merged_from: tuple[dict[str, Any], ...] = ()
    # The tool's own result object (possibly trimmed for very large outputs).
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AnalyzerResult:
    analyzer: str
    success: bool
    findings: list[FindingData]
    raw_output: str
    duration_ms: int
    error_message: str | None = None
    # Non-fatal problems that reduce coverage (files the tool could not parse,
    # ecosystems without a vulnerability database). Shown to the user.
    warnings: tuple[str, ...] = ()
    timed_out: bool = False
    # The failure was infrastructure (Docker daemon, downloads), not the tool itself.
    transient: bool = False
    # Structured output beyond findings that the pipeline persists (the architecture graph).
    artifact: object | None = None


@dataclass(frozen=True)
class ScanContext:
    """Per-scan information an analyzer may need beyond the source tree."""

    scan_id: str
    work_dir: Path  # per-scan scratch directory inside the workspace
    languages: list[DetectedLanguage]
    # Commit history captured by the clone sandbox (git_log.py format), if any.
    git_log_path: Path | None = None
    # Phase-2 analyzers see the phase-1 results (e.g. the architecture graph).
    prior_results: Mapping[str, "AnalyzerResult"] = field(default_factory=dict)

    @property
    def language_names(self) -> set[str]:
        return {lang.language for lang in self.languages}


class Analyzer(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    # Empty set = language-agnostic: the analyzer applies to every codebase.
    supported_languages: ClassVar[frozenset[str]] = frozenset()
    # 2 = runs after every phase-1 analyzer and receives their results.
    phase: ClassVar[int] = 1
    # Experimental (rubric 1.1 signals): registered only with EXPERIMENTAL_SIGNALS_ENABLED,
    # and a failure doesn't make the scan partial.
    experimental: ClassVar[bool] = False

    docker_image: str | None
    timeout_seconds: int

    def applies_to(self, detected_languages: set[str]) -> bool:
        return not self.supported_languages or bool(self.supported_languages & detected_languages)

    @abstractmethod
    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        """Analyze the codebase at `repo_path` (read-only) inside the sandbox.

        Implementations may raise AnalysisError / TransientInfraError instead of
        returning a failed result; the orchestrator records either the same way.
        """

    @abstractmethod
    def parse(self, raw_output: str) -> list[FindingData]:
        """Map the tool's raw output to findings. Pure: no filesystem or network access."""

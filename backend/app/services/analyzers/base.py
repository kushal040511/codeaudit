from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from app.models import Severity
from app.services.languages import DetectedLanguage


@dataclass(frozen=True)
class AnalyzerFinding:
    """Tool-agnostic finding, normalised from an analyzer's native output."""

    analyzer: str
    rule_id: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    message: str
    code_snippet: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class AnalyzerContext:
    scan_id: str
    source_dir: Path  # extracted codebase; analyzers must treat it as read-only
    work_dir: Path  # per-scan scratch directory inside the workspace
    languages: list[DetectedLanguage]


class Analyzer(ABC):
    name: ClassVar[str]

    @abstractmethod
    def run(self, ctx: AnalyzerContext) -> list[AnalyzerFinding]:
        """Analyze the codebase. Tools must execute through app.services.sandbox."""

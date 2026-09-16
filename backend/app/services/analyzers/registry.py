"""The set of analyzers a scan can run."""

from collections.abc import Iterable, Iterator

from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.bandit import BanditAnalyzer
from app.services.analyzers.base import Analyzer
from app.services.analyzers.dependency import DependencyAnalyzer
from app.services.analyzers.ruff import RuffAnalyzer
from app.services.analyzers.semgrep import SemgrepAnalyzer


class AnalyzerRegistry:
    def __init__(self, analyzers: Iterable[Analyzer] = ()) -> None:
        self._analyzers: dict[str, Analyzer] = {}
        for analyzer in analyzers:
            self.register(analyzer)

    def register(self, analyzer: Analyzer) -> None:
        if analyzer.name in self._analyzers:
            raise ValueError(f"Analyzer {analyzer.name!r} is already registered.")
        self._analyzers[analyzer.name] = analyzer

    def get(self, name: str) -> Analyzer:
        return self._analyzers[name]

    def __iter__(self) -> Iterator[Analyzer]:
        return iter(self._analyzers.values())

    def __len__(self) -> int:
        return len(self._analyzers)

    def select(self, detected_languages: set[str]) -> tuple[list[Analyzer], list[Analyzer]]:
        """Split analyzers into (applicable, not applicable), in registration order."""
        applicable = [a for a in self if a.applies_to(detected_languages)]
        skipped = [a for a in self if not a.applies_to(detected_languages)]
        return applicable, skipped


ANALYZER_CLASSES: tuple[type[Analyzer], ...] = (
    SemgrepAnalyzer,
    BanditAnalyzer,
    RuffAnalyzer,
    DependencyAnalyzer,
    ArchitectureAnalyzer,
)

DISPLAY_NAMES: dict[str, str] = {cls.name: cls.display_name for cls in ANALYZER_CLASSES}


def default_registry() -> AnalyzerRegistry:
    return AnalyzerRegistry(cls() for cls in ANALYZER_CLASSES)

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


def experimental_classes() -> tuple[type[Analyzer], ...]:
    """Rubric-1.1 signal analyzers (imported lazily: only needed when enabled)."""
    from app.services.analyzers.advisory import AdvisoryAnalyzer
    from app.services.analyzers.ci_quality import CIQualityAnalyzer
    from app.services.analyzers.dep_health import DepHealthAnalyzer
    from app.services.analyzers.error_handling import ErrorHandlingAnalyzer
    from app.services.analyzers.git_history import GitHistoryAnalyzer
    from app.services.analyzers.test_quality import TestQualityAnalyzer

    return (
        ErrorHandlingAnalyzer,
        TestQualityAnalyzer,
        CIQualityAnalyzer,
        AdvisoryAnalyzer,
        DepHealthAnalyzer,
        GitHistoryAnalyzer,
    )


DISPLAY_NAMES: dict[str, str] = {
    **{cls.name: cls.display_name for cls in ANALYZER_CLASSES},
    "error_handling": "Error handling",
    "test_quality": "Test quality",
    "ci_quality": "CI pipeline",
    "advisory": "Naming & comments (advisory)",
    "dep_health": "Dependency health",
    "git_history": "Git history",
}


def default_registry() -> AnalyzerRegistry:
    from app.config import get_settings

    classes = ANALYZER_CLASSES
    if get_settings().experimental_signals_enabled:
        classes = (*classes, *experimental_classes())
    return AnalyzerRegistry(cls() for cls in classes)

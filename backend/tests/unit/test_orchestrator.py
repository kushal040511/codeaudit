import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from app.core.errors import AnalysisError
from app.services.analyzers.base import FindingData, ScanContext
from app.services.analyzers.orchestrator import run_analyzers
from app.services.analyzers.registry import AnalyzerRegistry, default_registry
from app.services.analyzers.sandbox import SandboxTimeoutError, SandboxUnavailableError
from app.services.languages import DetectedLanguage
from tests.fakes import FakeAnalyzer, make_finding


def context(tmp_path: Path, *languages: str) -> ScanContext:
    return ScanContext(
        scan_id="scan-1",
        work_dir=tmp_path,
        languages=[
            DetectedLanguage(language=lang, file_count=1, manifests=[]) for lang in languages
        ],
    )


def raises(exc: Exception) -> Callable[[], list[FindingData]]:
    def behavior() -> list[FindingData]:
        raise exc

    return behavior


def test_applies_to_language_specific_and_agnostic() -> None:
    python_only = FakeAnalyzer("py", languages=frozenset({"python"}))
    agnostic = FakeAnalyzer("any")

    assert python_only.applies_to({"python", "javascript"})
    assert not python_only.applies_to({"javascript"})
    assert agnostic.applies_to(set())


def test_registry_selects_applicable_in_registration_order() -> None:
    registry = AnalyzerRegistry(
        [
            FakeAnalyzer("semgrep"),
            FakeAnalyzer("bandit", languages=frozenset({"python"})),
            FakeAnalyzer("eslint", languages=frozenset({"javascript", "typescript"})),
        ]
    )

    applicable, skipped = registry.select({"typescript"})

    assert [a.name for a in applicable] == ["semgrep", "eslint"]
    assert [a.name for a in skipped] == ["bandit"]


def test_registry_rejects_duplicate_names() -> None:
    with pytest.raises(ValueError, match="already registered"):
        AnalyzerRegistry([FakeAnalyzer("x"), FakeAnalyzer("x")])


def test_default_registry_languages() -> None:
    registry = default_registry()

    assert [a.name for a in registry] == ["semgrep", "bandit", "ruff", "dependency"]
    applicable, skipped = registry.select({"javascript"})
    assert [a.name for a in applicable] == ["semgrep", "dependency"]
    assert [a.name for a in skipped] == ["bandit", "ruff"]


def test_runs_analyzers_concurrently(tmp_path: Path) -> None:
    # Each analyzer blocks until all three are running; sequential execution
    # would hit the barrier timeout and break it.
    barrier = threading.Barrier(3)
    analyzers = [
        FakeAnalyzer(name, [make_finding(name)], barrier=barrier) for name in ("a", "b", "c")
    ]

    results = run_analyzers(analyzers, tmp_path, context(tmp_path), max_workers=3)

    assert [r.analyzer for r in results] == ["a", "b", "c"]
    assert all(r.success for r in results), [r.error_message for r in results]
    assert not barrier.broken


def test_one_analyzer_failing_does_not_affect_the_others(tmp_path: Path) -> None:
    analyzers = [
        FakeAnalyzer("ok1", [make_finding("ok1")]),
        FakeAnalyzer("crash", behavior=raises(RuntimeError("boom"))),
        FakeAnalyzer("broken", behavior=raises(AnalysisError("Broken exited with code 2"))),
        FakeAnalyzer("slow", behavior=raises(SandboxTimeoutError("killed")), timeout_seconds=120),
        FakeAnalyzer("nodocker", behavior=raises(SandboxUnavailableError("daemon down"))),
        FakeAnalyzer("ok2", [make_finding("ok2"), make_finding("ok2", start_line=2)]),
    ]
    reported: list[str] = []

    results = {
        r.analyzer: r
        for r in run_analyzers(
            analyzers,
            tmp_path,
            context(tmp_path),
            max_workers=4,
            on_result=lambda r: reported.append(r.analyzer),
        )
    }

    assert sorted(reported) == sorted(a.name for a in analyzers)
    assert results["ok1"].success and len(results["ok1"].findings) == 1
    assert results["ok2"].success and len(results["ok2"].findings) == 2

    crash = results["crash"]
    assert not crash.success and not crash.timed_out and not crash.transient
    assert crash.error_message == "Crash crashed with an internal error."  # no internals leaked
    assert results["broken"].error_message == "Broken exited with code 2"

    slow = results["slow"]
    assert slow.timed_out and not slow.success
    assert slow.error_message == "Slow timed out after 120s and was stopped."

    nodocker = results["nodocker"]
    assert nodocker.transient and not nodocker.success
    assert nodocker.error_message is not None and "daemon down" in nodocker.error_message


def test_on_result_runs_in_calling_thread(tmp_path: Path) -> None:
    caller = threading.get_ident()
    threads: set[int] = set()

    run_analyzers(
        [FakeAnalyzer("a"), FakeAnalyzer("b")],
        tmp_path,
        context(tmp_path),
        max_workers=2,
        on_result=lambda _: threads.add(threading.get_ident()),
    )

    assert threads == {caller}


def test_no_analyzers(tmp_path: Path) -> None:
    assert run_analyzers([], tmp_path, context(tmp_path), max_workers=4) == []

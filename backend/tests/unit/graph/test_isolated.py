import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.core.errors import AnalysisError, AnalyzerTimeoutError
from app.services.graph import isolated
from app.services.graph.isolated import run_isolated

FIXTURES = Path(__file__).parents[2] / "fixtures" / "architecture"


def test_runs_in_a_child_process_and_returns_the_report(tmp_path: Path) -> None:
    report = run_isolated(FIXTURES / "cycle_repo", tmp_path, timeout_seconds=60)

    assert [i.involved_modules for i in report.metrics.issues] == [["pkg/a", "pkg/b", "pkg/c"]]
    assert list(tmp_path.iterdir()) == []  # the hand-off file is removed


def fake_run(returncode: int, stderr: bytes = b"") -> Any:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, returncode, b"", stderr)

    return run


def test_native_crash_becomes_an_analysis_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(isolated.subprocess, "run", fake_run(-11))

    with pytest.raises(AnalysisError, match=r"crashed \(SIGSEGV in the parser process\)"):
        run_isolated(FIXTURES / "cycle_repo", tmp_path, timeout_seconds=60)


def test_hard_timeout_kills_the_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(command: list[str], **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(isolated.subprocess, "run", hang)

    with pytest.raises(AnalyzerTimeoutError):
        run_isolated(FIXTURES / "cycle_repo", tmp_path, timeout_seconds=1)


def test_child_deadline_and_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    message = b"WARNING x\nArchitecture analysis ran out of time while parsing."
    monkeypatch.setattr(isolated.subprocess, "run", fake_run(isolated.EXIT_TIMEOUT, message))
    with pytest.raises(AnalyzerTimeoutError, match="ran out of time while parsing"):
        run_isolated(FIXTURES / "cycle_repo", tmp_path, timeout_seconds=60)

    monkeypatch.setattr(isolated.subprocess, "run", fake_run(1, b"Traceback...\nMemoryError"))
    with pytest.raises(AnalysisError, match="failed: MemoryError"):
        run_isolated(FIXTURES / "cycle_repo", tmp_path, timeout_seconds=60)

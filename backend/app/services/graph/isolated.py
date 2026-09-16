"""Run the architecture analysis in a child process.

tree-sitter is native code parsing untrusted input. A crash in it (py-tree-sitter
0.26.0 corrupts memory after a few files, for example) must not take the Celery
worker down: with acks_late the scan would be redelivered and crash the next
worker too. In a child process a crash is just a failed analyzer run, and the
time limit is enforced by killing the process rather than by cooperative checks.

Usage (internal): python -m app.services.graph.isolated <repo> <output.pickle> <timeout>
"""

import logging
import pickle
import signal
import subprocess
import sys
import time
from pathlib import Path

import app
from app.core.errors import AnalysisError, AnalyzerTimeoutError
from app.services.graph.analysis import ArchitectureReport, analyze_architecture

logger = logging.getLogger(__name__)

BACKEND_ROOT = Path(app.__file__).resolve().parents[1]
EXIT_TIMEOUT = 3
# Grace period for interpreter start-up and writing the report.
KILL_GRACE_SECONDS = 30


def run_isolated(repo_path: Path, work_dir: Path, timeout_seconds: int) -> ArchitectureReport:
    output = work_dir / "architecture-report.pickle"
    command = [
        sys.executable,
        "-m",
        "app.services.graph.isolated",
        str(repo_path),
        str(output),
        str(timeout_seconds),
    ]
    try:
        # The command is fixed; only paths inside the scan workspace are passed.
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=BACKEND_ROOT,
            capture_output=True,
            timeout=timeout_seconds + KILL_GRACE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # subprocess.run kills the child
        raise AnalyzerTimeoutError("Architecture analysis exceeded its time limit.") from exc

    stderr = completed.stderr.decode("utf-8", "replace").strip()
    if stderr:
        logger.info("architecture analysis output:\n%s", stderr[-4000:])
    if completed.returncode == EXIT_TIMEOUT:
        raise AnalyzerTimeoutError(
            stderr.splitlines()[-1] if stderr else "Architecture analysis timed out."
        )
    if completed.returncode < 0:
        name = signal.Signals(-completed.returncode).name
        raise AnalysisError(f"Architecture analysis crashed ({name} in the parser process).")
    if completed.returncode != 0 or not output.is_file():
        last_line = stderr.splitlines()[-1] if stderr else f"exit code {completed.returncode}"
        raise AnalysisError(f"Architecture analysis failed: {last_line[:500]}")

    try:
        with output.open("rb") as fh:
            # Written by our own child process a moment ago, inside the scan workspace.
            report: ArchitectureReport = pickle.load(fh)  # noqa: S301
    finally:
        output.unlink(missing_ok=True)
    return report


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    repo, output, timeout = Path(argv[0]), Path(argv[1]), int(argv[2])
    try:
        report = analyze_architecture(repo, deadline=time.monotonic() + timeout)
    except AnalyzerTimeoutError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_TIMEOUT
    temporary = output.with_suffix(".tmp")
    with temporary.open("wb") as fh:
        pickle.dump(report, fh, protocol=pickle.HIGHEST_PROTOCOL)
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

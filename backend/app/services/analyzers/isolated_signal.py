"""Run a tree-sitter based signal collector in a child process.

Same reasoning as graph/isolated.py: tree-sitter is native code parsing untrusted
input, so a crash or a runaway parse must only fail that analyzer, never the worker.
A collector is a module-level function `collect(repo: Path, deadline: float) -> dict`
whose result is JSON-serialisable; it's named as "package.module:function" and only
collectors in ALLOWED can be run.

Usage (internal):
    python -m app.services.analyzers.isolated_signal COLLECTOR REPO OUT TIMEOUT [EXTRA]
"""

import importlib
import json
import logging
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import app
from app.core.errors import AnalysisError, AnalyzerTimeoutError

logger = logging.getLogger(__name__)

BACKEND_ROOT = Path(app.__file__).resolve().parents[1]
EXIT_TIMEOUT = 3
KILL_GRACE_SECONDS = 30
ALLOWED = frozenset(
    {
        "app.services.analyzers.error_handling:collect",
        "app.services.analyzers.test_quality:collect",
        "app.services.analyzers.advisory:collect",
        "app.services.analyzers.git_history:collect_complexity",
    }
)


class CollectorTimeout(Exception):
    """Raised by a collector that ran past its deadline."""


def run_collector(
    collector: str,
    repo_path: Path,
    work_dir: Path,
    timeout_seconds: int,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run `collector` on `repo_path` in a child process and return its result."""
    if collector not in ALLOWED:
        raise ValueError(f"unknown collector {collector}")
    name = collector.rsplit(":", 1)[-1]
    output = work_dir / f"signal-{collector.split('.')[-1].replace(':', '-')}-{name}.json"
    extra_file = output.with_suffix(".in.json")
    extra_file.write_text(json.dumps(extra or {}))
    command = [
        sys.executable,
        "-m",
        "app.services.analyzers.isolated_signal",
        collector,
        str(repo_path),
        str(output),
        str(timeout_seconds),
        str(extra_file),
    ]
    try:
        # Fixed module, allow-listed collector, paths inside the scan workspace.
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=BACKEND_ROOT,
            capture_output=True,
            timeout=timeout_seconds + KILL_GRACE_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerTimeoutError(f"{collector} exceeded its time limit.") from exc
    finally:
        extra_file.unlink(missing_ok=True)

    stderr = completed.stderr.decode("utf-8", "replace").strip()
    if stderr:
        logger.info("%s output:\n%s", collector, stderr[-2000:])
    if completed.returncode == EXIT_TIMEOUT:
        raise AnalyzerTimeoutError(f"{collector} ran out of time.")
    if completed.returncode < 0:
        raise AnalysisError(
            f"Parser process crashed ({signal.Signals(-completed.returncode).name})."
        )
    if completed.returncode != 0 or not output.is_file():
        last = stderr.splitlines()[-1] if stderr else f"exit code {completed.returncode}"
        raise AnalysisError(f"Signal collection failed: {last[:300]}")
    try:
        return json.loads(output.read_text())  # type: ignore[no-any-return]
    finally:
        output.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    collector, repo, output, timeout = argv[0], Path(argv[1]), Path(argv[2]), int(argv[3])
    extra = json.loads(Path(argv[4]).read_text()) if len(argv) > 4 else {}
    if collector not in ALLOWED:
        print(f"unknown collector {collector}", file=sys.stderr)
        return 2
    module_name, function_name = collector.split(":")
    function = getattr(importlib.import_module(module_name), function_name)
    try:
        result = function(repo, time.monotonic() + timeout, **extra)
    except CollectorTimeout as exc:
        print(str(exc) or "timed out", file=sys.stderr)
        return EXIT_TIMEOUT
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(result))
    temporary.replace(output)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

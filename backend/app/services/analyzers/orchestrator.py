"""Run analyzers concurrently with failure isolation.

Each analyzer mostly waits on its sandbox container, so threads are enough.
Whatever an analyzer does (return a failed result, raise, time out), the
orchestrator turns it into an AnalyzerResult and the other analyzers carry on.
"""

import dataclasses
import logging
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path

from app.core.errors import AnalysisError, AnalyzerTimeoutError, TransientInfraError
from app.services.analyzers.base import Analyzer, AnalyzerResult, ScanContext

logger = logging.getLogger(__name__)

MAX_ERROR_MESSAGE_CHARS = 2000


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def run_analyzer_safely(
    analyzer: Analyzer, repo_path: Path, context: ScanContext
) -> AnalyzerResult:
    """Run one analyzer; never raises."""
    started = time.monotonic()

    def failed(message: str, *, timed_out: bool = False, transient: bool = False) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=analyzer.name,
            success=False,
            findings=[],
            raw_output="",
            duration_ms=_elapsed_ms(started),
            error_message=message[:MAX_ERROR_MESSAGE_CHARS],
            timed_out=timed_out,
            transient=transient,
        )

    try:
        result = analyzer.run(repo_path, context)
    except AnalyzerTimeoutError:
        logger.warning("%s timed out for scan %s", analyzer.name, context.scan_id)
        return failed(
            f"{analyzer.display_name} timed out after {analyzer.timeout_seconds}s and was stopped.",
            timed_out=True,
        )
    except TransientInfraError as exc:
        logger.warning(
            "%s: infrastructure error for scan %s: %s", analyzer.name, context.scan_id, exc
        )
        return failed(f"{analyzer.display_name} could not run: {exc}", transient=True)
    except AnalysisError as exc:
        logger.info("%s failed for scan %s: %s", analyzer.name, context.scan_id, exc)
        return failed(str(exc))
    except Exception:
        logger.exception("%s crashed for scan %s", analyzer.name, context.scan_id)
        return failed(f"{analyzer.display_name} crashed with an internal error.")

    if result.analyzer != analyzer.name:
        result = dataclasses.replace(result, analyzer=analyzer.name)
    # Wall-clock time including image pulls and database downloads, not just the tool.
    return dataclasses.replace(result, duration_ms=_elapsed_ms(started))


def run_analyzers(
    analyzers: Sequence[Analyzer],
    repo_path: Path,
    context: ScanContext,
    *,
    max_workers: int,
    on_result: Callable[[AnalyzerResult], None] | None = None,
) -> list[AnalyzerResult]:
    """Run `analyzers` concurrently. Results are returned in the order of `analyzers`.

    `on_result` is called from the calling thread as each analyzer finishes, so it
    may use objects that aren't thread-safe (such as a database session).
    """
    if not analyzers:
        return []

    results: dict[str, AnalyzerResult] = {}
    executor = ThreadPoolExecutor(
        max_workers=max(1, min(max_workers, len(analyzers))), thread_name_prefix="analyzer"
    )
    try:
        futures: dict[Future[AnalyzerResult], Analyzer] = {
            executor.submit(run_analyzer_safely, analyzer, repo_path, context): analyzer
            for analyzer in analyzers
        }
        for future in as_completed(futures):
            result = future.result()
            results[futures[future].name] = result
            logger.info(
                "analyzer %s for scan %s: %s in %dms, %d findings",
                result.analyzer,
                context.scan_id,
                "ok" if result.success else "failed",
                result.duration_ms,
                len(result.findings),
            )
            if on_result is not None:
                on_result(result)
    finally:
        # On an early exit (e.g. the task's soft time limit) don't wait for the
        # remaining containers; their own timeouts and cleanup still apply.
        executor.shutdown(wait=len(results) == len(analyzers), cancel_futures=True)

    return [results[analyzer.name] for analyzer in analyzers]

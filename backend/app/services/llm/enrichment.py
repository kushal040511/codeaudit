"""The LLM stage of a scan: fix suggestions, then the architecture review.

Runs after analysis as its own task. Whatever happens here, the scan ends valid and
`completed` (or `partial` if analyzers failed); problems are recorded in
`enrichment_status` / `enrichment_error` and on the individual suggestions.
"""

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models import (
    EnrichmentStatus,
    FixStatus,
    FixSuggestion,
    Scan,
    ScanStatus,
    ValidationStatus,
)
from app.services.llm.architect import generate_architecture_review
from app.services.llm.client import LLMBudgetExceededError, LLMClient, LLMError
from app.services.llm.context import detect_conventions
from app.services.llm.fix_suggester import FixRunStats, generate_fixes

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentOutcome:
    status: EnrichmentStatus
    fixes: FixRunStats = field(default_factory=FixRunStats)
    review_generated: bool = False
    problems: list[str] = field(default_factory=list)


def start_enrichment(db: Session, scan: Scan) -> bool:
    """Mark the scan as enriching. False if it isn't waiting for enrichment."""
    if scan.status not in (ScanStatus.ANALYSIS_COMPLETE, ScanStatus.ENRICHING):
        return False
    scan.status = ScanStatus.ENRICHING
    scan.enrichment_status = EnrichmentStatus.RUNNING
    scan.enrichment_error = None
    db.commit()
    return True


def run_enrichment(db: Session, scan: Scan, source_dir: Path, llm: LLMClient) -> EnrichmentOutcome:
    languages = [lang["language"] for lang in scan.detected_languages or []]
    conventions = detect_conventions(source_dir, languages)
    outcome = EnrichmentOutcome(EnrichmentStatus.COMPLETED)

    outcome.fixes = generate_fixes(db, scan.id, source_dir, conventions, llm)
    stats = outcome.fixes
    if stats.budget_exhausted:
        # A budget cut (scan ceiling, monthly quota or daily spend cap) is not a failure:
        # the scan stays complete, enrichment is partial or skipped with this reason.
        reason = stats.errors[-1] if stats.errors else "The token budget ran out."
        outcome.problems.append(f"Fix suggestions stopped early: {reason}")
    if stats.llm_requests_failed:
        outcome.problems.append(
            f"{stats.llm_requests_failed} of {stats.groups} fix requests failed: {stats.errors[0]}"
        )

    if stats.budget_exhausted:
        outcome.problems.append("Architecture review skipped: the LLM budget is exhausted.")
    else:
        try:
            outcome.review_generated = (
                generate_architecture_review(db, scan.id, conventions, llm) is not None
            )
        except LLMBudgetExceededError as exc:
            outcome.problems.append(f"Architecture review skipped: {exc}")
        except LLMError as exc:
            outcome.problems.append(f"Architecture review failed: {exc}")

    produced_something = outcome.review_generated or sum(stats.by_validation.values()) > 0
    attempted_something = stats.groups > 0 or outcome.review_generated or outcome.problems
    budget_cut = stats.budget_exhausted or any("skipped:" in p for p in outcome.problems)
    if outcome.problems:
        if produced_something:
            outcome.status = EnrichmentStatus.PARTIAL
        elif budget_cut and not stats.llm_requests_failed:
            outcome.status = EnrichmentStatus.SKIPPED
        else:
            outcome.status = EnrichmentStatus.FAILED
    elif not attempted_something:
        outcome.status = EnrichmentStatus.SKIPPED
        outcome.problems.append("Nothing to enrich: no fixable findings and no architecture graph.")
    return outcome


def finish_enrichment(
    db: Session, scan_id: uuid.UUID, status: EnrichmentStatus, message: str | None
) -> None:
    """Make the scan final. Suggestions left `generating` by a crash are marked failed."""
    db.rollback()
    db.execute(
        update(FixSuggestion)
        .where(FixSuggestion.scan_id == scan_id, FixSuggestion.status == FixStatus.GENERATING)
        .values(
            status=FixStatus.FAILED,
            validation_status=ValidationStatus.NOT_VALIDATED,
            error_message="Generation stopped before this suggestion was produced.",
        )
    )
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = ScanStatus.PARTIAL if scan.analysis_partial else ScanStatus.COMPLETED
    scan.enrichment_status = status
    scan.enrichment_error = message[:2000] if message else None
    db.commit()


def llm_dispatch_block(db: Session, scan: Scan) -> str | None:
    """Checked when the enrichment task starts, before cloning or counting tokens:
    why the LLM stage must not run for this scan right now, or None."""
    from app.config import get_settings
    from app.core import metrics
    from app.models import User
    from app.services import costs, quotas

    if reason := costs.blocked_reason(db):
        metrics.quota_rejections.labels("spend_cap", "dispatch").inc()
        return reason
    owner = db.get(User, scan.user_id) if scan.user_id else None
    quota = quotas.llm_token_quota(db, owner)
    if quota.remaining < get_settings().llm_max_output_tokens:
        metrics.quota_rejections.labels("llm_tokens", "dispatch").inc()
        return (
            f"The monthly LLM token quota ({quota.limit:,}) is used up; it resets"
            f" {quota.resets_at:%Y-%m-%d}."
        )
    return None

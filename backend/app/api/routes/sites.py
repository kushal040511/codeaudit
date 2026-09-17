"""Website analyzer: phishing/clone risk evidence and design tokens for a URL.

Every submitted URL is SSRF-checked (scheme, port, hostname, resolved addresses)
before it is accepted, again when the job starts, and every request the browser
makes goes through the egress proxy.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, OptionalPrincipal
from app.api.errors import (
    AppError,
    ConflictError,
    NotFoundError,
    ServiceUnavailableError,
)
from app.api.pagination import PageParams, page_params, paginate
from app.config import get_settings
from app.core.db import get_db
from app.core.storage import StorageError, get_bytes
from app.models import SiteAnalysis, SiteAnalysisStatus
from app.schemas.errors import ErrorResponse
from app.schemas.site import (
    DesignRead,
    RiskRead,
    SiteAnalysisListItem,
    SiteAnalysisRead,
    SiteAnalyzeCreated,
    SiteAnalyzeRequest,
    VisualMatchRead,
)
from app.services import quotas
from app.services.auth.sessions import Principal
from app.services.web.design import to_css, to_tailwind
from app.services.web.netguard import BlockedUrlError, validate_url
from app.services.web.references import load_references

router = APIRouter(prefix="/sites", tags=["sites"])

DbSession = Annotated[Session, Depends(get_db)]
IN_FLIGHT_WINDOW = timedelta(minutes=10)
IMAGE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": "private, max-age=3600",
}


def _errors(*codes: int) -> dict[int | str, dict[str, object]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _load(db: Session, analysis_id: uuid.UUID, principal: Principal | None) -> SiteAnalysis:
    """Owned analyses are visible only to their owner; anonymous ones to id holders."""
    analysis = db.get(SiteAnalysis, analysis_id)
    if analysis is None or (
        analysis.user_id is not None
        and (principal is None or principal.user.id != analysis.user_id)
    ):
        raise NotFoundError(f"Site analysis {analysis_id} not found.")
    return analysis


def _visible_to(principal: Principal | None):  # type: ignore[no-untyped-def]
    if principal is None:
        return SiteAnalysis.user_id.is_(None)
    return or_(SiteAnalysis.user_id.is_(None), SiteAnalysis.user_id == principal.user.id)


def _read(analysis: SiteAnalysis, principal: Principal | None) -> SiteAnalysisRead:
    risk = None
    if analysis.risk_evidence:
        data = dict(analysis.risk_evidence)
        match = data.get("visual_match")
        if match:
            match = VisualMatchRead(
                **{k: v for k, v in match.items() if k != "screenshot_key"},
                reference_screenshot_url=(
                    f"/api/sites/references/{match['brand']}/{match['page']}/screenshot"
                    if match.get("screenshot_key")
                    else None
                ),
            )
        risk = RiskRead(**{**data, "visual_match": match})
    base = f"/api/sites/{analysis.id}"
    return SiteAnalysisRead(
        id=analysis.id,
        status=analysis.status,
        stage=analysis.stage,
        url=analysis.url,
        normalized_url=analysis.normalized_url,
        final_url=analysis.final_url,
        error_message=analysis.error_message,
        cached_from_id=analysis.cached_from_id,
        owned_by_you=principal is not None and analysis.user_id == principal.user.id,
        created_at=analysis.created_at,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        screenshot_url=f"{base}/screenshot?kind=fold" if analysis.screenshot_key else None,
        full_screenshot_url=(
            f"{base}/screenshot?kind=full" if analysis.full_screenshot_key else None
        ),
        capture=analysis.capture,
        risk=risk,
        design=(
            DesignRead(tokens=analysis.design_tokens, notes=analysis.design_notes)
            if analysis.design_tokens is not None
            else None
        ),
    )


def _enforce_rate_limit(principal: Principal | None, client_ip: str) -> None:
    quotas.consume(
        quotas.subject_for(principal.user if principal else None, client_ip), "site_analyses"
    )


@router.post(
    "/analyze",
    response_model=SiteAnalyzeCreated,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_errors(400, 422, 429, 503),
)
async def analyze_site(
    body: SiteAnalyzeRequest, request: Request, db: DbSession, principal: OptionalPrincipal
) -> SiteAnalyzeCreated:
    """Queue an analysis of `url`. Recent results for the same URL are reused (cached=true)."""
    try:
        url, _ = await run_in_threadpool(validate_url, body.url)
    except BlockedUrlError as exc:
        raise AppError(exc.reason, code="url_not_allowed") from None
    return await run_in_threadpool(_create, db, principal, request, body, url.url)


def _create(
    db: Session,
    principal: Principal | None,
    request: Request,
    body: SiteAnalyzeRequest,
    normalized: str,
) -> SiteAnalyzeCreated:
    settings = get_settings()
    now = datetime.now(UTC)
    owner = principal.user.id if principal else None

    if not body.force:
        recent = db.scalar(
            select(SiteAnalysis)
            .where(
                SiteAnalysis.normalized_url == normalized,
                SiteAnalysis.status == SiteAnalysisStatus.COMPLETED,
                SiteAnalysis.cached_from_id.is_(None),
                SiteAnalysis.created_at >= now - timedelta(seconds=settings.site_cache_ttl_seconds),
                _visible_to(principal),
            )
            .order_by(SiteAnalysis.created_at.desc())
            .limit(1)
        )
        if recent is not None:
            copy = SiteAnalysis(
                id=uuid.uuid4(),
                user_id=owner,
                status=SiteAnalysisStatus.COMPLETED,
                url=body.url[:2048],
                normalized_url=normalized,
                final_url=recent.final_url,
                screenshot_key=recent.screenshot_key,
                full_screenshot_key=recent.full_screenshot_key,
                favicon_key=recent.favicon_key,
                dom_key=recent.dom_key,
                capture=recent.capture,
                risk_score=recent.risk_score,
                risk_level=recent.risk_level,
                risk_evidence=recent.risk_evidence,
                design_tokens=recent.design_tokens,
                design_notes=recent.design_notes,
                cached_from_id=recent.id,
                started_at=now,
                completed_at=now,
            )
            db.add(copy)
            db.commit()
            return SiteAnalyzeCreated(
                analysis_id=copy.id, status=copy.status, normalized_url=normalized, cached=True
            )
        in_flight = db.scalar(
            select(SiteAnalysis).where(
                SiteAnalysis.normalized_url == normalized,
                SiteAnalysis.status.in_([SiteAnalysisStatus.QUEUED, SiteAnalysisStatus.RUNNING]),
                SiteAnalysis.created_at >= now - IN_FLIGHT_WINDOW,
                SiteAnalysis.user_id == owner if owner else SiteAnalysis.user_id.is_(None),
            )
        )
        if in_flight is not None:
            return SiteAnalyzeCreated(
                analysis_id=in_flight.id,
                status=in_flight.status,
                normalized_url=normalized,
                cached=False,
            )

    _enforce_rate_limit(principal, quotas.client_ip(request))
    analysis = SiteAnalysis(
        id=uuid.uuid4(),
        user_id=owner,
        status=SiteAnalysisStatus.QUEUED,
        url=body.url[:2048],
        normalized_url=normalized,
    )
    db.add(analysis)
    db.commit()

    from app.workers.tasks import analyze_site_task

    try:
        analyze_site_task.delay(str(analysis.id))
    except BrokerError as exc:
        analysis.status = SiteAnalysisStatus.FAILED
        analysis.error_message = "Could not queue the analysis."
        db.commit()
        raise ServiceUnavailableError("Job queue is unavailable. Try again later.") from exc
    return SiteAnalyzeCreated(
        analysis_id=analysis.id, status=analysis.status, normalized_url=normalized, cached=False
    )


@router.get("", response_model=list[SiteAnalysisListItem], responses=_errors(401))
def list_site_analyses(
    db: DbSession,
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    pages: Annotated[PageParams, Depends(page_params)],
) -> list[SiteAnalysisListItem]:
    rows = [
        row[0]
        for row in paginate(
            db,
            select(SiteAnalysis)
            .where(SiteAnalysis.user_id == principal.user.id)
            .order_by(SiteAnalysis.created_at.desc()),
            pages,
            request,
            response,
        )
    ]
    return [
        SiteAnalysisListItem(
            id=r.id,
            status=r.status,
            url=r.url,
            final_url=r.final_url,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get(
    "/references/{brand}/{page}/screenshot",
    responses={200: {"content": {"image/png": {}}}, **_errors(404)},
)
def reference_screenshot(brand: str, page: str) -> Response:
    reference = next(
        (r for r in load_references() if r.brand == brand and r.page == page and r.screenshot_key),
        None,
    )
    if reference is None or reference.screenshot_key is None:
        raise NotFoundError("Reference screenshot not found.")
    try:
        data = get_bytes(reference.screenshot_key)
    except StorageError:
        raise NotFoundError("Reference screenshot not found.") from None
    return Response(data, media_type="image/png", headers=IMAGE_HEADERS)


@router.get("/{analysis_id}", response_model=SiteAnalysisRead, responses=_errors(404, 422))
def get_site_analysis(
    analysis_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal
) -> SiteAnalysisRead:
    return _read(_load(db, analysis_id, principal), principal)


@router.get(
    "/{analysis_id}/screenshot",
    responses={200: {"content": {"image/png": {}}}, **_errors(404, 422)},
)
def site_screenshot(
    analysis_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    kind: Annotated[Literal["fold", "full"], Query()] = "fold",
) -> Response:
    """The captured screenshot (an image of untrusted content; never HTML)."""
    analysis = _load(db, analysis_id, principal)
    key = analysis.screenshot_key if kind == "fold" else analysis.full_screenshot_key
    if not key:
        raise NotFoundError("No screenshot for this analysis.")
    try:
        data = get_bytes(key)
    except StorageError:
        raise NotFoundError("Screenshot not available.") from None
    return Response(data, media_type="image/png", headers=IMAGE_HEADERS)


@router.get(
    "/{analysis_id}/tokens",
    responses={
        200: {"content": {"application/json": {}, "text/javascript": {}, "text/css": {}}},
        **_errors(404, 409, 422),
    },
)
def site_tokens(
    analysis_id: uuid.UUID,
    db: DbSession,
    principal: OptionalPrincipal,
    format: Annotated[Literal["json", "tailwind", "css"], Query()] = "json",  # noqa: A002
) -> Response:
    """Design tokens as a downloadable file: tokens.json, tailwind.config.js or tokens.css."""
    analysis = _load(db, analysis_id, principal)
    if analysis.status is not SiteAnalysisStatus.COMPLETED or analysis.design_tokens is None:
        raise ConflictError(
            "Design tokens are not available for this analysis.", code="tokens_not_ready"
        )
    tokens = analysis.design_tokens
    if format == "tailwind":
        body, media, filename = to_tailwind(tokens), "text/javascript", "tailwind.config.js"
    elif format == "css":
        body, media, filename = to_css(tokens), "text/css", "tokens.css"
    else:
        import json

        body, media, filename = (
            json.dumps(tokens, indent=2),
            "application/json",
            "design-tokens.json",
        )
    return Response(
        body,
        media_type=f"{media}; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )

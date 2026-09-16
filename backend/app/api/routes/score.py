import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import OptionalPrincipal, load_scan
from app.api.errors import NotFoundError
from app.core.db import get_db
from app.models import ScanScore
from app.schemas.errors import ErrorResponse
from app.schemas.score import (
    CategoryScoreRead,
    ProjectedScore,
    ProjectionRead,
    ProjectionRequest,
    ScoreRead,
)
from app.services.scoring.rubric import ScoreReport
from app.services.scoring.service import project

router = APIRouter(prefix="/scans/{scan_id}", tags=["score"])

DbSession = Annotated[Session, Depends(get_db)]
ERRORS: dict[int | str, dict[str, object]] = {
    404: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
}


def _projected(report: ScoreReport) -> ProjectedScore:
    return ProjectedScore(
        overall=report.overall,
        grade=report.grade,
        categories=[CategoryScoreRead(**c.as_dict()) for c in report.categories],
    )


@router.get("/score", response_model=ScoreRead, responses=ERRORS)
def get_score(scan_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal) -> ScoreRead:
    """The rubric score with its per-category breakdown."""
    load_scan(db, scan_id, principal)
    row = db.get(ScanScore, scan_id)
    if row is None:
        raise NotFoundError(f"Scan {scan_id} has no score (analysis not finished).")
    return ScoreRead.model_validate(row)


@router.post("/score/projection", response_model=ProjectionRead, responses=ERRORS)
def project_score(
    scan_id: uuid.UUID, body: ProjectionRequest, db: DbSession, principal: OptionalPrincipal
) -> ProjectionRead:
    """The score if exactly these findings were fixed. Exact, not an estimate."""
    scan = load_scan(db, scan_id, principal)
    if db.get(ScanScore, scan_id) is None:
        raise NotFoundError(f"Scan {scan_id} has no score (analysis not finished).")
    projection = project(db, scan, body.finding_ids)
    return ProjectionRead(
        current=_projected(projection.current),
        projected=_projected(projection.projected),
        delta=projection.delta,
        included_finding_ids=projection.included_finding_ids,
        ignored_finding_ids=projection.ignored_finding_ids,
    )

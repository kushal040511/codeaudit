"""Score scans analysed before the rubric existed (or after a rubric change).

    python -m app.services.scoring.backfill [--all]

Only scans with recorded analyzer runs can be scored; `--all` rescores scans that
already have a score.
"""

import sys

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import RESULT_STATUSES, AnalyzerRun, Scan, ScanScore
from app.services.scoring.service import rescore_scan


def main(argv: list[str]) -> int:
    rescore_all = "--all" in argv
    scored = skipped = 0
    with SessionLocal() as db:
        scans = db.scalars(select(Scan).where(Scan.status.in_(RESULT_STATUSES))).all()
        for scan in scans:
            has_runs = db.scalar(
                select(AnalyzerRun.id).where(AnalyzerRun.scan_id == scan.id).limit(1)
            )
            already_scored = db.get(ScanScore, scan.id) is not None
            if not has_runs or (already_scored and not rescore_all):
                skipped += 1
                continue
            row = rescore_scan(db, scan)
            db.commit()
            scored += 1
            print(f"{scan.id} {scan.original_filename}: {row.overall} {row.grade}")
    print(f"scored {scored}, skipped {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

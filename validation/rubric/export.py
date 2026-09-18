"""Snapshot the scorable inputs of the study scans so the rubric can be re-run offline.

Reads scan ids from scans.jsonl, loads each scan's findings and score context from
the database, and writes one JSON line per scan to stdout. Findings keep only what
the rubric reads (analyzer, rule, severity, path, corroboration), so the snapshot
contains no source code. Run inside the worker container:

    docker compose exec -T worker python - < validation/rubric/export.py \\
        < scans.jsonl > findings.jsonl        # see README.md for the exact command
"""

import json
import os
import sys
import uuid

sys.path.insert(0, "/app")

from app.core.db import SessionLocal
from app.models import Finding, Scan
from app.models.architecture import ArchitectureIssue, ArchitectureSummary
from app.services.scoring.service import context_for_scan
from sqlalchemy import select

scans = [json.loads(line) for line in os.environ["SCANS_JSONL"].splitlines() if line.strip()]
with SessionLocal() as db:
    for record in scans:
        if "scan_id" not in record or record.get("status") in {"failed", "timeout"}:
            continue
        scan = db.get(Scan, uuid.UUID(record["scan_id"]))
        context = context_for_scan(db, scan)
        findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        # Strongly connected components formed by the reported cycles (union of their
        # modules), for the per-component cycle experiment in report.py.
        cycles = db.scalars(
            select(ArchitectureIssue).where(
                ArchitectureIssue.scan_id == scan.id,
                ArchitectureIssue.issue_type == "circular_dependency",
            )
        ).all()
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for issue in cycles:
            modules = list(issue.involved_modules)
            for other in modules[1:]:
                parent[find(other)] = find(modules[0])
        components: dict[str, dict] = {}
        for issue in cycles:
            root = find(issue.involved_modules[0])
            entry = components.setdefault(root, {"modules": set(), "severities": []})
            entry["modules"].update(issue.involved_modules)
            entry["severities"].append(issue.severity.value)
        print(
            json.dumps(
                {
                    "repo": record["repo"],
                    "sha": record["sha"],
                    "scan_id": record["scan_id"],
                    "context": {
                        "source_loc": context.source_loc,
                        "module_count": context.module_count,
                        "analyzers_run": sorted(context.analyzers_run),
                        "analyzers_failed": sorted(context.analyzers_failed),
                    },
                    "findings": [
                        [f.id, f.analyzer, f.rule_id, f.severity.value, f.file_path, list(f.corroborated_by or [])]
                        for f in findings
                    ],
                    # Extra inputs for the counterfactual experiments (not read by the shipped rubric).
                    "dependency_packages": {
                        str(f.id): f"{(f.dependency or {}).get('ecosystem')}:{(f.dependency or {}).get('package')}"
                        for f in findings
                        if f.analyzer == "dependency"
                    },
                    "import_resolution": (
                        (db.get(ArchitectureSummary, scan.id).summary or {}).get("resolution", {})
                        if db.get(ArchitectureSummary, scan.id)
                        else None
                    ),
                    "cycle_components": [
                        {"size": len(c["modules"]), "cycles": len(c["severities"]),
                         "severity": "error" if "error" in c["severities"] else c["severities"][0]}
                        for c in components.values()
                    ],
                }
            )
        )

"""Compare two scans (typically a pull request's base and head): new/resolved findings.

Findings are matched across commits without line numbers, which shift whenever
code above them changes. A finding's identity is its analyzer, rule, file and
the whitespace-normalised flagged code (or, without a snippet, the message;
for dependencies, the package). Identical identities are matched as a
multiset, so a second copy of the same issue in a file still counts as new.
"""

import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, Scan, ScanScore, Severity

_WHITESPACE = re.compile(r"\s+")
_NUMBERS = re.compile(r"\d+")


def finding_identity(finding: Finding) -> tuple[str, ...]:
    if finding.dependency:
        dep = finding.dependency
        return (
            finding.analyzer,
            finding.rule_id,
            str(dep.get("ecosystem", "")),
            str(dep.get("package", "")),
            str(dep.get("installed_version", "")),
        )
    if finding.code_snippet and finding.code_snippet.strip():
        evidence = _WHITESPACE.sub(" ", finding.code_snippet).strip()
    else:
        # Messages can embed line numbers or counts that move with unrelated edits.
        evidence = _NUMBERS.sub("#", _WHITESPACE.sub(" ", finding.message)).strip()
    return (finding.analyzer, finding.rule_id, finding.file_path, evidence)


@dataclass
class Comparison:
    new: list[Finding]
    resolved: list[Finding]
    unchanged_count: int


def diff_findings(base: Sequence[Finding], head: Sequence[Finding]) -> Comparison:
    remaining: defaultdict[tuple[str, ...], list[Finding]] = defaultdict(list)
    for finding in base:
        remaining[finding_identity(finding)].append(finding)
    new: list[Finding] = []
    unchanged = 0
    for finding in head:
        matches = remaining.get(finding_identity(finding))
        if matches:
            matches.pop()
            unchanged += 1
        else:
            new.append(finding)
    resolved = [f for group in remaining.values() for f in group]
    order = list(Severity)

    def key(f: Finding) -> tuple[int, str, int]:
        return (-order.index(f.severity), f.file_path, f.start_line)

    return Comparison(sorted(new, key=key), sorted(resolved, key=key), unchanged)


def severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {severity.value: counts[severity.value] for severity in Severity}


def load_findings(db: Session, scan: Scan) -> Sequence[Finding]:
    return db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()


def load_score(db: Session, scan: Scan) -> ScanScore | None:
    return db.get(ScanScore, scan.id)

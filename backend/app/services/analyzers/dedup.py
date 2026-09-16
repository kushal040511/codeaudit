"""Merge the same issue reported by several analyzers (or several rules of one analyzer).

Findings are duplicates when they are in the same file, have the same issue
category, and are at the same location: the same start line, or one finding's
short line range contains the other's start line (tools anchor multi-line calls
differently). The finding with the most informative message is kept, raised to
the highest severity in the group; the other analyzers that agreed are recorded
in `corroborated_by` and every merged finding in `merged_from`, so scoring can
treat agreement between tools as extra confidence.
"""

import dataclasses
from collections import defaultdict
from collections.abc import Sequence

from app.models import Severity
from app.services.analyzers.base import FindingData
from app.services.analyzers.snippets import normalize_path

# A finding spanning more lines than this is too broad to prove two tools mean the
# same code; such findings only merge on an identical start line.
MAX_CONTAINING_SPAN = 5

_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def dedup_category(finding: FindingData) -> str:
    """Findings without a known category are only ever merged with the same rule."""
    return finding.category or f"rule:{finding.analyzer}:{finding.rule_id}"


def _same_location(a: FindingData, b: FindingData) -> bool:
    if a.start_line == b.start_line:
        return True
    for outer, inner in ((a, b), (b, a)):
        span = outer.end_line - outer.start_line
        if span <= MAX_CONTAINING_SPAN and outer.start_line <= inner.start_line <= outer.end_line:
            return True
    return False


def _richness(finding: FindingData) -> tuple[int, int, int]:
    """Longest message wins; ties go to the more severe finding, then to one with a snippet."""
    return (
        len(finding.message.strip()),
        _SEVERITY_RANK[finding.severity],
        int(bool(finding.code_snippet)),
    )


def _merge(group: list[FindingData]) -> FindingData:
    keeper = max(group, key=_richness)
    if len(group) == 1:
        return keeper

    others = [f for f in group if f is not keeper]
    corroborated_by = sorted({f.analyzer for f in others} - {keeper.analyzer})
    severity = max((f.severity for f in group), key=_SEVERITY_RANK.__getitem__)
    cwe_ids = tuple(dict.fromkeys(cwe for f in group for cwe in f.cwe_ids))
    merged_from = [
        {
            "analyzer": f.analyzer,
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "start_line": f.start_line,
            "message": f.message,
        }
        for f in others
    ]
    return dataclasses.replace(
        keeper,
        severity=severity,
        cwe_ids=cwe_ids,
        corroborated_by=tuple(sorted({*keeper.corroborated_by, *corroborated_by})),
        merged_from=(*keeper.merged_from, *merged_from),
    )


def deduplicate(findings: Sequence[FindingData]) -> list[FindingData]:
    """Merge duplicate findings. Output order follows each group's first finding in the input."""
    buckets: defaultdict[tuple[str, str], list[tuple[int, FindingData]]] = defaultdict(list)
    for index, finding in enumerate(findings):
        buckets[(normalize_path(finding.file_path), dedup_category(finding))].append(
            (index, finding)
        )

    merged: list[tuple[int, FindingData]] = []
    for bucket in buckets.values():
        groups: list[list[tuple[int, FindingData]]] = []
        for index, finding in sorted(bucket, key=lambda item: (item[1].start_line, item[0])):
            # Compare against each group's first finding (its anchor) so groups can't
            # chain along a file one overlapping line at a time.
            target = next((g for g in groups if _same_location(g[0][1], finding)), None)
            if target is None:
                groups.append([(index, finding)])
            else:
                target.append((index, finding))
        for group in groups:
            merged.append((min(i for i, _ in group), _merge([f for _, f in group])))

    return [finding for _, finding in sorted(merged, key=lambda item: item[0])]

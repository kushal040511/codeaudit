"""Patch validation pass rate and architecture-citation hallucination rate for a set of scans.

Reads the scan ids from scans.jsonl (passed in SCANS_JSONL) and queries the database.
Run inside the worker container; see README.md for the exact command. Prints a JSON
document; `--markdown` prints the report instead.
"""

import json
import os
import re
import statistics
import sys
import uuid
from collections import Counter, defaultdict

sys.path.insert(0, "/app")

from app.core.db import SessionLocal
from app.models import Finding
from app.models.llm import ArchitectureReview, FixSuggestion, LLMCall
from sqlalchemy import select


def failure_reason(detail: str | None) -> str:
    text = detail or ""
    if "Not a unified diff" in text:
        return "not a unified diff"
    if "patch does not apply" in text or "patch failed" in text:
        return "context does not match the file"
    if "corrupt patch" in text:
        return "corrupt patch"
    if re.search(r"does not exist|outside the repository|new file|deleted file|absolute", text, re.IGNORECASE):
        return "touches a file it may not"
    return "other: " + text[:80]


def pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


records = [json.loads(line) for line in os.environ["SCANS_JSONL"].splitlines() if line.strip()]
scan_ids = [uuid.UUID(r["scan_id"]) for r in records]
repo_of = {uuid.UUID(r["scan_id"]): r["repo"] for r in records}

with SessionLocal() as db:
    rows = db.execute(
        select(FixSuggestion, Finding.analyzer, Finding.file_path)
        .join(Finding, Finding.id == FixSuggestion.finding_id)
        .where(FixSuggestion.scan_id.in_(scan_ids))
    ).all()
    reviews = db.scalars(select(ArchitectureReview).where(ArchitectureReview.scan_id.in_(scan_ids))).all()
    calls = db.scalars(select(LLMCall).where(LLMCall.scan_id.in_(scan_ids))).all()

statuses = Counter(fix.validation_status.value for fix, _, _ in rows)
by_analyzer: dict[str, Counter] = defaultdict(Counter)
by_language: dict[str, Counter] = defaultdict(Counter)
by_repo: dict[str, Counter] = defaultdict(Counter)
reasons = Counter()
for fix, analyzer, path in rows:
    status = fix.validation_status.value
    by_analyzer[analyzer][status] += 1
    ext = path.rsplit(".", 1)[-1] if "." in path else "(none)"
    by_language[ext][status] += 1
    by_repo[repo_of[fix.scan_id]][status] += 1
    if status == "failed_to_apply":
        reasons[failure_reason(fix.validation_detail)] += 1
    elif status == "syntax_error":
        reasons["applies, but the result doesn't parse"] += 1

total = sum(statuses.values())
with_patch = total - statuses.get("no_patch", 0) - statuses.get("not_validated", 0)
review_rows = [
    {
        "repo": repo_of[r.scan_id],
        "status": r.status.value,
        "citations_total": r.citations_total,
        "citations_invalid": r.citations_invalid,
        "hallucination_rate": r.hallucination_rate,
        "issues_kept": len(r.issues or []),
        # Stricter than the stored rate: every rejected citation counts, including an
        # import edge between two real modules that doesn't exist (the stored rate only
        # counts references to modules missing from the graph).
        "evidence_total": sum(len(i.get("evidence", [])) + len(i.get("rejected_evidence", []))
                              for i in [*(r.issues or []), *(r.dropped_issues or [])]),
        "evidence_rejected": sum(len(i.get("rejected_evidence", [])) for i in [*(r.issues or []), *(r.dropped_issues or [])]),
        "edge_claims_rejected": sum(1 for i in [*(r.issues or []), *(r.dropped_issues or [])]
                                    for e in i.get("rejected_evidence", []) if e["reason"].startswith("no import")),
        "unverified_prose_mentions": sum(len(i.get("unverified_mentions", [])) for i in [*(r.issues or []), *(r.dropped_issues or [])]),
        "issues_dropped": len(r.dropped_issues or []),
        "error": r.error_message,
        # What was actually cited, so qualitative claims about the reviews can be checked.
        "kept_issues": [{"title": i.get("title"), "evidence": i.get("evidence", [])} for i in (r.issues or [])],
    }
    for r in reviews
]
cited = sum(r["citations_total"] for r in review_rows)
invalid = sum(r["citations_invalid"] for r in review_rows)
fix_calls = [c for c in calls if c.purpose.value == "fix_suggestion"]
metrics = {
    "scans": len(records),
    "models": sorted({c.model for c in calls}),
    "fix_suggestions": {
        "total": total,
        "by_status": dict(statuses),
        "with_patch": with_patch,
        "valid": statuses.get("valid", 0),
        "pass_rate_of_all": statuses.get("valid", 0) / total if total else None,
        "pass_rate_of_patches": statuses.get("valid", 0) / with_patch if with_patch else None,
        "failure_reasons": dict(reasons.most_common()),
        "by_analyzer": {k: dict(v) for k, v in sorted(by_analyzer.items())},
        "by_extension": {k: dict(v) for k, v in sorted(by_language.items())},
        "by_repo": {k: dict(v) for k, v in sorted(by_repo.items())},
    },
    "architecture_reviews": {
        "reviews": review_rows,
        "completed": sum(r["status"] == "ready" for r in review_rows),
        "citations_total": cited,
        "citations_invalid": invalid,
        "pooled_hallucination_rate": invalid / cited if cited else None,
        "issues_kept": sum(r["issues_kept"] for r in review_rows),
        "evidence_total": sum(r["evidence_total"] for r in review_rows),
        "evidence_rejected": sum(r["evidence_rejected"] for r in review_rows),
        "edge_claims_rejected": sum(r["edge_claims_rejected"] for r in review_rows),
        "unverified_prose_mentions": sum(r["unverified_prose_mentions"] for r in review_rows),
        "rejected_evidence_rate": (sum(r["evidence_rejected"] for r in review_rows) / ev)
        if (ev := sum(r["evidence_total"] for r in review_rows)) else None,
        "issues_dropped": sum(r["issues_dropped"] for r in review_rows),
    },
    "llm_calls": {
        "total": len(calls),
        "failed": sum(not c.success for c in calls),
        "failure_reasons": dict(
            Counter(f"{c.error_type}: {(c.error_message or '')[:70]}" for c in calls if not c.success).most_common()
        ),
        "fix_call_latency_s_p50": (pct([c.duration_ms / 1000 for c in fix_calls if c.duration_ms], 50)),
        "fix_call_latency_s_p95": (pct([c.duration_ms / 1000 for c in fix_calls if c.duration_ms], 95)),
        "output_tokens_median": statistics.median([c.output_tokens or 0 for c in calls]) if calls else None,
    },
}

if "--markdown" not in sys.argv:
    print(json.dumps(metrics, indent=2, sort_keys=True, default=str))
    sys.exit(0)

f = metrics["fix_suggestions"]
a = metrics["architecture_reviews"]
lines = [
    "# LLM enrichment evaluation",
    "",
    f"{metrics['scans']} scans, model(s): {', '.join(metrics['models'])}.",
    "",
    "## Patch validation",
    "",
    f"{f['total']} fix suggestions; {f['with_patch']} contained a patch that was validated.",
    "",
    f"- **Pass rate (valid ÷ validated patches): {f['valid']}/{f['with_patch']} = "
    f"{(f['pass_rate_of_patches'] or 0):.1%}**",
    f"- Valid ÷ all suggestions: {(f['pass_rate_of_all'] or 0):.1%}",
    "",
    "| Status | Count |",
    "|---|---|",
    *[f"| {k} | {v} |" for k, v in sorted(f["by_status"].items(), key=lambda kv: -kv[1])],
    "",
    "Failure reasons:",
    "",
    *[f"- {k}: {v}" for k, v in f["failure_reasons"].items()],
    "",
    "By analyzer of the finding:",
    "",
    "| Analyzer | valid | failed_to_apply | syntax_error | other |",
    "|---|---|---|---|---|",
]
for name, counts in f["by_analyzer"].items():
    other = sum(v for k, v in counts.items() if k not in {"valid", "failed_to_apply", "syntax_error"})
    lines.append(f"| {name} | {counts.get('valid', 0)} | {counts.get('failed_to_apply', 0)} | {counts.get('syntax_error', 0)} | {other} |")
lines += [
    "",
    "## Architecture review citations",
    "",
    f"{a['completed']} of {len(a['reviews'])} reviews completed. "
    f"Module citations: {a['citations_total']}, invalid: {a['citations_invalid']}"
    + (f" → **pooled hallucination rate {a['pooled_hallucination_rate']:.1%}**" if a["pooled_hallucination_rate"] is not None else ""),
    f"Issues kept: {a['issues_kept']}, dropped for lack of valid evidence: {a['issues_dropped']}.",
    "",
    f"Stricter view: {a['evidence_rejected']} of {a['evidence_total']} evidence citations were rejected"
    + (f" (**{a['rejected_evidence_rate']:.1%}**)" if a["rejected_evidence_rate"] is not None else "")
    + f", of which {a['edge_claims_rejected']} claimed an import between real modules that doesn't exist "
    "(not counted by the stored rate). "
    f"Paths named in prose but absent from the graph (not counted anywhere): {a['unverified_prose_mentions']}.",
    "",
    "| Repository | Status | Module refs | Invalid refs | Stored rate | Evidence rejected | Issues kept | Dropped |",
    "|---|---|---|---|---|---|---|---|",
]
for r in sorted(a["reviews"], key=lambda r: r["repo"]):
    rate = "n/a" if r["hallucination_rate"] is None else f"{r['hallucination_rate']:.1%}"
    lines.append(f"| {r['repo']} | {r['status']} | {r['citations_total']} | {r['citations_invalid']} | {rate} | {r['evidence_rejected']}/{r['evidence_total']} | {r['issues_kept']} | {r['issues_dropped']} |")
c = metrics["llm_calls"]
lines += [
    "",
    "Failed LLM calls by reason:",
    "",
    *[f"- {k}: {v}" for k, v in c["failure_reasons"].items()],
    "",
    f"LLM calls: {c['total']} ({c['failed']} failed). Fix-suggestion call latency p50 "
    f"{(c['fix_call_latency_s_p50'] or 0):.0f} s, p95 {(c['fix_call_latency_s_p95'] or 0):.0f} s.",
]
print("\n".join(lines))

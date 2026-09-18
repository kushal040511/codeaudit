"""Recompute the self-scan figures quoted in docs/validation.md §6 from the committed snapshot.

    cd backend && uv run python ../scripts/selfscan_breakdown.py

Reads docs/self-scan-findings.jsonl (made by validation/rubric/export.py for the
self-scan) and prints the score as shipped, the score without the repo's own
tooling directories, and where the urllib findings are.
"""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "validation" / "rubric"))
sys.path.insert(0, str(ROOT / "backend"))

from report import score_all  # noqa: E402

TOOLING = ("scripts/", "validation/")
URLLIB = ("B310", "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected")

scan = json.loads((ROOT / "docs" / "self-scan-findings.jsonl").read_text().splitlines()[0])
without = dict(scan, findings=[f for f in scan["findings"] if not f[4].startswith(TOOLING)])
shipped, trimmed = score_all([scan])[scan["repo"]], score_all([without])[scan["repo"]]
print(json.dumps({
    "overall": shipped["overall"],
    "categories": {k: v for k, v in shipped.items() if k not in {"overall", "incomplete"}},
    "without_scripts_and_validation": {"overall": trimmed["overall"], "security": round(trimmed["security"], 2)},
    "urllib_findings_by_top_dir": {
        f"{rule} {path}": n
        for (rule, path), n in sorted(Counter((f[2], f[4].split("/")[0]) for f in scan["findings"] if f[2] in URLLIB).items())
    },
}, indent=2))

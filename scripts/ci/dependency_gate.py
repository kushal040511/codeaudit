"""Fail CI on critical vulnerabilities in locked dependencies that nobody has reviewed.

Input: `osv-scanner scan source --format json` output (file argument or stdin).
A vulnerability is critical when OSV's max severity score is >= 9.0 or the advisory
database labels it CRITICAL. Reviewed exceptions live in .github/dependency-allowlist.txt,
one `ID  YYYY-MM-DD  reason` per line (the date is when the exception expires).
Everything else is printed as a summary but does not fail the build.
"""

import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

ALLOWLIST = Path(__file__).parents[2] / ".github" / "dependency-allowlist.txt"
CRITICAL_SCORE = 9.0


def load_allowlist(path: Path = ALLOWLIST) -> dict[str, date]:
    allowed: dict[str, date] = {}
    if not path.is_file():
        return allowed
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        vuln_id, expires, *_ = line.split()
        allowed[vuln_id] = date.fromisoformat(expires)
    return allowed


def findings(report: dict) -> list[dict]:
    rows = []
    for result in report.get("results") or []:
        source = result.get("source", {}).get("path", "?")
        for package in result.get("packages", []):
            name = package["package"]["name"]
            version = package["package"].get("version", "?")
            labels = {
                v["id"]: str(v.get("database_specific", {}).get("severity", "")).upper()
                for v in package.get("vulnerabilities", [])
            }
            for group in package.get("groups", []):
                ids = sorted(set(group.get("aliases", [])) | set(group.get("ids", [])))
                try:
                    score = float(group.get("max_severity") or 0)
                except ValueError:
                    score = 0.0
                critical = score >= CRITICAL_SCORE or any(
                    labels.get(i) == "CRITICAL" for i in group.get("ids", [])
                )
                rows.append(
                    {
                        "ids": ids,
                        "package": f"{name}@{version}",
                        "source": source,
                        "score": score,
                        "critical": critical,
                    }
                )
    return rows


def gate(report: dict, allowlist: dict[str, date], today: date | None = None) -> int:
    today = today or datetime.now(UTC).date()
    failures = 0
    rows = findings(report)
    for row in sorted(rows, key=lambda r: -r["score"]):
        allowed = [i for i in row["ids"] if i in allowlist and allowlist[i] >= today]
        if row["critical"] and not allowed:
            status = "FAIL"
            failures += 1
        elif row["critical"]:
            status = "allowed"
        else:
            status = "info"
        print(f"{status:8} {row['score']:4.1f} {row['package']:40} {', '.join(row['ids'])}")
    print(f"{len(rows)} vulnerable package versions, {failures} unreviewed critical.")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    raw = Path(argv[0]).read_text() if argv else sys.stdin.read()
    return gate(json.loads(raw or "{}"), load_allowlist())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

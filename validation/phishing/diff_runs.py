"""Which evidence signals changed per URL between two validation runs (e.g. model v0.1 -> v0.1.1).

    python validation/phishing/diff_runs.py data/dataset-20260917.results.jsonl data/dataset-20260917-rerun.results.jsonl

Hosts are printed (not full URLs); inputs are the gitignored raw results, whose
SHA-256 hashes are listed in docs/validation.md.
"""

import json
import sys
from collections import Counter, defaultdict


def load(path: str) -> dict[str, dict]:
    with open(path) as handle:
        return {r["url"]: r for r in map(json.loads, handle)}


before, after = load(sys.argv[1]), load(sys.argv[2])
changes: Counter[str] = Counter()
hosts: defaultdict[str, list[str]] = defaultdict(list)
for url, new in after.items():
    old = before.get(url)
    if not old or old.get("state") != "ok" or new.get("state") != "ok":
        continue
    fired_old = {e["signal"] for e in old["evidence"] if e["status"] == "fired"}
    fired_new = {e["signal"] for e in new["evidence"] if e["status"] == "fired"}
    for signal in sorted(fired_new - fired_old):
        changes[f"+{signal}"] += 1
        hosts[f"+{signal}"].append(url.split("/")[2].replace(".", "[.]"))
    for signal in sorted(fired_old - fired_new):
        changes[f"-{signal}"] += 1
        hosts[f"-{signal}"].append(url.split("/")[2].replace(".", "[.]"))
for change, count in changes.most_common():
    print(f"{count:3d} {change:28s} {', '.join(hosts[change][:6])}")

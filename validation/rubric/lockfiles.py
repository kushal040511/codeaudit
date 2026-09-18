"""Which study commits pin any dependency versions OSV-Scanner can check (for report.py's
"no lockfile = not assessed" experiment). Uses the authenticated GitHub CLI.

    python validation/rubric/lockfiles.py > validation/rubric/results/<date>/lockfiles.json

A commit counts as pinned if it has a real lockfile, or a requirements*.txt with at
least one `==` pin. OSV-Scanner runs with --no-resolve, so manifests with ranges only
(package.json, pyproject.toml) are not checked at all.
"""

import base64
import csv
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
    "composer.lock",
}
PIN = re.compile(r"^\s*[A-Za-z0-9_.\-\[\]]+\s*==\s*[0-9]", re.MULTILINE)


def gh(path: str) -> dict:
    return json.loads(subprocess.run(["gh", "api", path], capture_output=True, check=True, text=True).stdout)


result = {}
with open(HERE / "labels.csv", newline="") as handle:
    for row in csv.DictReader(handle):
        repo, sha = row["repo"], row["sha"]
        tree = gh(f"repos/{repo}/git/trees/{sha}?recursive=1")["tree"]
        paths = [t["path"] for t in tree if t["type"] == "blob" and "node_modules/" not in t["path"]]
        lockfiles = [p for p in paths if p.rsplit("/", 1)[-1] in LOCKFILES]
        pinned_requirements = []
        for p in paths:
            name = p.rsplit("/", 1)[-1]
            if name.startswith("requirements") and name.endswith(".txt"):
                blob = gh(f"repos/{repo}/contents/{p}?ref={sha}")
                if PIN.search(base64.b64decode(blob["content"]).decode(errors="replace")):
                    pinned_requirements.append(p)
        result[repo] = {
            "lockfiles": lockfiles,
            "pinned_requirements": pinned_requirements,
            "pinned": bool(lockfiles or pinned_requirements),
        }
print(json.dumps(result, indent=2, sort_keys=True))

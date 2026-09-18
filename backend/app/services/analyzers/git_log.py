"""Capture and parse commit history for the git history signal.

History is read with `git log` **inside a sandbox container**, never by the worker:
a repository's own `.git/config` can name programs for git to run (external diff
drivers, textconv, fsmonitor), so an untrusted `.git` is only ever touched by git
running as nobody, without network, with those features disabled.

Two sources:
- URL scans: the clone sandbox fetches `GIT_HISTORY_DEPTH` commits, writes the log
  with LOG_SHELL, then deletes `.git` (clone.py).
- Uploads that include a `.git` directory: `capture_uploaded_history` runs the same
  command in a no-network sandbox against the read-only source.

Format: one record per commit, `\\x1e` + hash, parents, author name, author email,
author time and subject separated by `\\x1f`, followed by `--numstat` lines. The
commits at the shallow boundary (listed in `.git/shallow`) are recorded with
BOUNDARY_MARKER so their "everything added" diffs can be ignored.
"""

from dataclasses import dataclass, field
from pathlib import Path

from app.config import get_settings
from app.services.analyzers.sandbox import SandboxError, SandboxLimits, SandboxMount, run_in_sandbox

HISTORY_MOUNT = "/history"
LOG_FILENAME = "git-log.txt"
BOUNDARY_FILENAME = "shallow.txt"
BOUNDARY_MARKER = "boundary"
MAX_COMMITS = 5000
LOG_FORMAT = "%x1e%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s"

# Disables every repository-config hook into external programs for the log command.
SAFE_GIT = (
    "git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c diff.external= "
    "-c core.pager=cat -c log.showSignature=false -c core.quotePath=false"
)
LOG_SHELL = (
    f"{SAFE_GIT} log --no-ext-diff --no-textconv --no-renames --numstat "
    f"--max-count={MAX_COMMITS} --format='{LOG_FORMAT}' HEAD > {HISTORY_MOUNT}/{LOG_FILENAME}; "
    f"cp .git/shallow {HISTORY_MOUNT}/{BOUNDARY_FILENAME} 2>/dev/null || true"
)
SAFE_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": "*",
}


@dataclass
class Commit:
    sha: str
    parents: list[str]
    author: str  # "name <email>"
    timestamp: int
    subject: str
    # (path, added, deleted); binary files have None counts
    files: list[tuple[str, int | None, int | None]] = field(default_factory=list)
    boundary: bool = False  # shallow boundary: its numstat is the whole tree, not a change

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1


_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote_path(path: str) -> str:
    """Undo git's C-style quoting of unusual paths (a tab, a quote, a backslash...).

    Git quotes such paths in numstat output: `"a\\tb"`; octal escapes (`\\303\\251`)
    are UTF-8 bytes. Unquoted paths are returned unchanged.
    """
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path
    body = path[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 == len(body):
            out += char.encode("utf-8")
            index += 1
            continue
        following = body[index + 1]
        octal = body[index + 1 : index + 4]
        if len(octal) == 3 and all(c in "01234567" for c in octal):
            out.append(int(octal, 8) & 0xFF)
            index += 4
        else:
            out.append(_ESCAPES.get(following, ord(following) & 0xFF))
            index += 2
    return out.decode("utf-8", "replace")


def parse_log(text: str, boundary: set[str] | None = None) -> list[Commit]:
    """Parse LOG_FORMAT output, newest first. Malformed records are skipped."""
    boundary = boundary or set()
    commits: list[Commit] = []
    for record in text.split("\x1e"):
        if not record.strip():
            continue
        header, _, body = record.partition("\n")
        parts = header.split("\x1f")
        if len(parts) != 6:
            continue
        sha, parents, name, email, timestamp, subject = parts
        try:
            when = int(timestamp)
        except ValueError:
            continue
        commit = Commit(
            sha=sha,
            parents=parents.split(),
            author=f"{name} <{email.lower()}>",
            timestamp=when,
            subject=subject,
            boundary=sha in boundary,
        )
        for line in body.splitlines():
            columns = line.split("\t")
            if len(columns) != 3:
                continue
            added, deleted, path = columns
            commit.files.append(
                (
                    _unquote_path(path),
                    int(added) if added.isdigit() else None,
                    int(deleted) if deleted.isdigit() else None,
                )
            )
        commits.append(commit)
    return commits


def read_history(directory: Path) -> list[Commit] | None:
    """Commits captured into `directory`, or None if nothing was captured."""
    log = directory / LOG_FILENAME
    if not log.is_file():
        return None
    shallow = directory / BOUNDARY_FILENAME
    boundary = set(shallow.read_text().split()) if shallow.is_file() else set()
    return parse_log(log.read_text(encoding="utf-8", errors="replace"), boundary)


def capture_uploaded_history(repo_path: Path, output_dir: Path, scan_id: str) -> Path | None:
    """Run LOG_SHELL against an uploaded `.git` in a no-network sandbox. None if it fails."""
    if not (repo_path / ".git").is_dir():
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir.chmod(0o770)
    settings = get_settings()
    try:
        result = run_in_sandbox(
            image=settings.git_image,
            entrypoint=["sh", "-c"],
            command=[f"set -u; cd /src; {LOG_SHELL}"],
            working_dir="/src",
            mounts=[
                SandboxMount(repo_path, "/src", read_only=True),
                SandboxMount(output_dir, HISTORY_MOUNT, read_only=False),
            ],
            limits=SandboxLimits(cpus=1.0, memory="512m", timeout_seconds=120),
            labels={"codeaudit.scan_id": scan_id, "codeaudit.analyzer": "git-history"},
            environment=SAFE_ENV,
            network=False,
        )
    except SandboxError:
        return None
    if result.exit_code != 0 or not (output_dir / LOG_FILENAME).is_file():
        return None
    return output_dir

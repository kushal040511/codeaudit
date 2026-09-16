"""Validate a model-generated unified diff against the scanned source before showing it.

A suggestion is only `valid` if the diff applies cleanly to the real files and every
patched file still parses. Diffs are untrusted: paths must be existing files inside
the repository, and `git apply` runs on a throwaway copy with no user or system
git configuration.
"""

import ast
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.models import ValidationStatus
from app.services.graph.parser import GRAMMAR_BY_EXTENSION, grammar_language

GIT_TIMEOUT_SECONDS = 20
MAX_PATCH_BYTES = 512 * 1024
EXCERPT_CONTEXT_LINES = 12
MAX_EXCERPT_LINES = 400

_DIFF_PATH = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class PatchValidation:
    status: ValidationStatus
    detail: str | None = None
    # [{path, start_line, original, patched}] for a side-by-side view
    file_changes: list[dict[str, Any]] = field(default_factory=list)


def normalize_patch(patch: str) -> str:
    """Strip Markdown fences and make sure the diff ends with a newline."""
    text = patch.strip("\n")
    fenced = re.match(r"^```[\w-]*\n(.*?)\n?```\s*$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    return text.rstrip("\n") + "\n" if text.strip() else ""


def patch_paths(patch: str) -> list[str]:
    """Files a unified diff touches, from its ---/+++ headers."""
    paths: list[str] = []
    for line in patch.splitlines():
        match = _DIFF_PATH.match(line)
        if match and match.group(1) != "/dev/null" and match.group(1) not in paths:
            paths.append(match.group(1))
    return paths


def _unsafe_path(path: str, repo: Path) -> str | None:
    posix = PurePosixPath(path)
    if posix.is_absolute() or ".." in posix.parts or "\\" in path:
        return f"path {path!r} is outside the repository"
    target = repo / path
    if target.is_symlink() or not target.resolve().is_relative_to(repo.resolve()):
        return f"path {path!r} is outside the repository"
    if not target.is_file():
        return f"{path!r} does not exist (fixes may only modify existing files)"
    return None


def _git(args: list[str], cwd: Path, patch: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "LC_ALL": "C",
    }
    return subprocess.run(  # noqa: S603 - fixed git command, diff passed on stdin
        ["git", "apply", *args, "-"],  # noqa: S607
        cwd=cwd,
        input=patch,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        env=env,
        check=False,
    )


def syntax_error(path: str, source: str) -> str | None:
    """A parse error in `source`, or None. Only Python, JavaScript and TypeScript are checked."""
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".py":
        try:
            ast.parse(source, filename=path)
        except SyntaxError as exc:
            return f"{path}:{exc.lineno}: {exc.msg}"
        return None
    grammar = GRAMMAR_BY_EXTENSION.get(suffix)
    if grammar is None:
        return None
    from tree_sitter import Parser

    tree = Parser(grammar_language(grammar[1])).parse(source.encode("utf-8"))
    if not tree.root_node.has_error:
        return None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            return f"{path}:{node.start_point.row + 1}: parse error"
        stack.extend(node.children)
    return f"{path}: parse error"


def _changed_ranges(patch: str, path: str) -> list[tuple[int, int]]:
    """New-file line ranges of each hunk for `path`."""
    ranges: list[tuple[int, int]] = []
    current: str | None = None
    for line in patch.splitlines():
        header = _DIFF_PATH.match(line)
        if header and line.startswith("+++"):
            current = header.group(1)
        elif current == path and (hunk := _HUNK.match(line)):
            start = int(hunk.group(3))
            length = int(hunk.group(4) or "1")
            ranges.append((start, start + max(length, 1) - 1))
    return ranges


def _excerpts(path: str, original: str, patched: str, patch: str) -> dict[str, Any]:
    """The region around the changes, so the UI doesn't need whole files."""
    new_lines = patched.splitlines()
    ranges = _changed_ranges(patch, path) or [(1, len(new_lines))]
    start = max(1, min(r[0] for r in ranges) - EXCERPT_CONTEXT_LINES)
    end_new = max(r[1] for r in ranges) + EXCERPT_CONTEXT_LINES
    end_new = min(end_new, start + MAX_EXCERPT_LINES - 1)
    old_lines = original.splitlines()
    delta = len(new_lines) - len(old_lines)
    end_old = max(start, end_new - delta)
    return {
        "path": path,
        "start_line": start,
        "original": "\n".join(old_lines[start - 1 : end_old]),
        "patched": "\n".join(new_lines[start - 1 : end_new]),
    }


def validate_patch(repo: Path, patch: str | None) -> PatchValidation:
    patch = normalize_patch(patch or "")
    if not patch:
        return PatchValidation(ValidationStatus.NO_PATCH, "No change was proposed.")
    if len(patch.encode()) > MAX_PATCH_BYTES:
        return PatchValidation(ValidationStatus.FAILED_TO_APPLY, "The patch is too large.")
    if "/dev/null" in {m.group(1) for line in patch.splitlines() if (m := _DIFF_PATH.match(line))}:
        return PatchValidation(
            ValidationStatus.FAILED_TO_APPLY, "Patches may not create or delete files."
        )
    paths = patch_paths(patch)
    if not paths:
        return PatchValidation(
            ValidationStatus.FAILED_TO_APPLY, "Not a unified diff (no ---/+++ file headers)."
        )
    for path in paths:
        if problem := _unsafe_path(path, repo):
            return PatchValidation(ValidationStatus.FAILED_TO_APPLY, problem)

    with tempfile.TemporaryDirectory(prefix="codeaudit-patch-") as tmp:
        work = Path(tmp)
        originals: dict[str, str] = {}
        for path in paths:
            destination = work / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repo / path, destination)
            originals[path] = (repo / path).read_text(encoding="utf-8", errors="replace")

        strip = ["-p1"] if re.search(r"^--- a/", patch, re.MULTILINE) else ["-p0"]
        try:
            # --recount: models get hunk line counts wrong; the context lines must still match.
            check = _git(["--check", "--recount", *strip], work, patch)
            if check.returncode != 0:
                detail = (check.stderr or check.stdout).strip()
                return PatchValidation(
                    ValidationStatus.FAILED_TO_APPLY,
                    detail[-2000:] or "git apply rejected the patch.",
                )
            applied = _git(["--recount", *strip], work, patch)
        except subprocess.TimeoutExpired:
            return PatchValidation(ValidationStatus.FAILED_TO_APPLY, "git apply timed out.")
        if applied.returncode != 0:
            return PatchValidation(
                ValidationStatus.FAILED_TO_APPLY, (applied.stderr or "git apply failed.")[-2000:]
            )

        changes: list[dict[str, Any]] = []
        for path in paths:
            patched = (work / path).read_text(encoding="utf-8", errors="replace")
            if (error := syntax_error(path, patched)) and not syntax_error(path, originals[path]):
                # Only blame the patch if the file parsed before it.
                return PatchValidation(ValidationStatus.SYNTAX_ERROR, error)
            changes.append(_excerpts(path, originals[path], patched, patch))
    return PatchValidation(ValidationStatus.VALID, None, changes)


def apply_patch_in_place(repo: Path, patch: str) -> tuple[bool, str | None]:
    """Apply a unified diff to files in `repo` (a throwaway working copy). (applied, error)."""
    patch = normalize_patch(patch)
    for path in patch_paths(patch):
        if problem := _unsafe_path(path, repo):
            return False, problem
    strip = ["-p1"] if re.search(r"^--- a/", patch, re.MULTILINE) else ["-p0"]
    try:
        check = _git(["--check", "--recount", *strip], repo, patch)
        if check.returncode != 0:
            return (
                False,
                (check.stderr or check.stdout).strip()[-2000:] or "git apply rejected the patch.",
            )
        applied = _git(["--recount", *strip], repo, patch)
    except subprocess.TimeoutExpired:
        return False, "git apply timed out."
    if applied.returncode != 0:
        return False, (applied.stderr or "git apply failed.").strip()[-2000:]
    return True, None

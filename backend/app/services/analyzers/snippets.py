"""Shared helpers for normalising tool output: paths, snippets and database-safe text."""

import dataclasses
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from app.services.analyzers.base import FindingData

SNIPPET_MAX_LINES = 20
SNIPPET_MAX_CHARS = 4000

# Where run_tool mounts the repository; tools that print absolute paths use it.
_SANDBOX_ROOTS = ("/src/",)


def normalize_path(path: str) -> str:
    """Repository-relative POSIX path: strips the sandbox mount, "./" and duplicate slashes."""
    value = path.replace("\\", "/")
    for root in _SANDBOX_ROOTS:
        if value.startswith(root):
            value = value[len(root) :]
            break
    parts = [p for p in PurePosixPath(value).parts if p not in ("", ".", "/")]
    return "/".join(parts)


def strip_nul(value: Any) -> Any:
    """Postgres text and JSONB reject NUL characters."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    return value


def read_snippet(source_root: Path, rel_path: str, start_line: int, end_line: int) -> str | None:
    """Read lines [start_line, end_line] (capped) from a scanned file."""
    root = source_root.resolve()
    path = (root / rel_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None

    last = min(end_line, start_line + SNIPPET_MAX_LINES - 1)
    lines: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                if lineno > last:
                    break
                if lineno >= start_line:
                    lines.append(line.rstrip("\r\n"))
    except OSError:
        return None
    snippet = strip_nul("\n".join(lines)[:SNIPPET_MAX_CHARS])
    return snippet or None


def fill_snippets(findings: Sequence[FindingData], source_root: Path) -> list[FindingData]:
    """Read the code snippet from the source tree for findings whose tool gave none."""
    return [
        (
            f
            if f.code_snippet
            else dataclasses.replace(
                f, code_snippet=read_snippet(source_root, f.file_path, f.start_line, f.end_line)
            )
        )
        for f in findings
    ]

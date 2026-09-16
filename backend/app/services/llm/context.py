"""Context sent with a fix request: surrounding code and project conventions."""

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

MAX_MANIFEST_BYTES = 256 * 1024

# Import / package name -> framework label.
PYTHON_FRAMEWORKS = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "sqlalchemy": "SQLAlchemy",
    "pydantic": "Pydantic",
    "celery": "Celery",
    "pytest": "pytest",
}
JS_FRAMEWORKS = {
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "svelte": "Svelte",
    "@angular/core": "Angular",
    "express": "Express",
    "fastify": "Fastify",
    "@nestjs/core": "NestJS",
    "vite": "Vite",
    "jest": "Jest",
    "vitest": "Vitest",
    "typescript": "TypeScript",
}
STYLE_FILES = (
    ".editorconfig",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.js",
    "prettier.config.js",
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.js",
    "eslint.config.js",
    "biome.json",
    "ruff.toml",
    ".flake8",
    "setup.cfg",
    "tox.ini",
    ".pylintrc",
)
IGNORED = ("node_modules/", ".venv/", "venv/", "dist/", "build/", ".git/")


@dataclass
class ProjectConventions:
    languages: list[str]
    frameworks: list[str] = field(default_factory=list)
    style: list[str] = field(default_factory=list)  # human-readable facts

    def describe(self) -> str:
        lines = [f"Languages: {', '.join(self.languages) or 'unknown'}"]
        lines.append(f"Frameworks and libraries: {', '.join(self.frameworks) or 'none detected'}")
        lines.extend(f"Style: {fact}" for fact in self.style)
        return "\n".join(lines)


def _read(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _manifests(repo: Path, names: set[str]) -> list[Path]:
    found = [
        p
        for p in repo.rglob("*")
        if p.name in names and not any(part in p.as_posix() for part in IGNORED)
    ]
    return sorted(found)[:20]


def detect_conventions(repo: Path, languages: list[str]) -> ProjectConventions:
    frameworks: list[str] = []
    style: list[str] = []

    def add(label: str) -> None:
        if label not in frameworks:
            frameworks.append(label)

    for manifest in _manifests(
        repo, {"requirements.txt", "pyproject.toml", "Pipfile", "setup.cfg"}
    ):
        text = (_read(manifest) or "").lower()
        for name, label in PYTHON_FRAMEWORKS.items():
            if re.search(
                rf"(^|[\s\"'\[,]){re.escape(name)}([\s\"'=<>~!\[;,]|$)", text, re.MULTILINE
            ):
                add(label)
        if manifest.name == "pyproject.toml":
            try:
                tool = tomllib.loads(_read(manifest) or "").get("tool", {})
            except tomllib.TOMLDecodeError:
                tool = {}
            for formatter in ("black", "ruff", "isort"):
                if formatter in tool:
                    length = tool[formatter].get("line-length")
                    style.append(
                        f"{formatter} configured"
                        + (f" (line length {length})" if length else "")
                        + f" in {manifest.relative_to(repo).as_posix()}"
                    )

    for manifest in _manifests(repo, {"package.json"}):
        try:
            data: dict[str, Any] = json.loads(_read(manifest) or "{}")
        except ValueError:
            continue
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name, label in JS_FRAMEWORKS.items():
            if name in deps:
                add(label)
        if data.get("type") == "module":
            style.append(
                f'ES modules ("type": "module" in {manifest.relative_to(repo).as_posix()})'
            )

    for name in STYLE_FILES:
        for path in _manifests(repo, {name})[:1]:
            rel = path.relative_to(repo).as_posix()
            text = _read(path) or ""
            if name.startswith(".prettierrc") and text.strip().startswith("{"):
                try:
                    config = json.loads(text)
                    facts = [
                        f"{k}={config[k]}"
                        for k in ("semi", "singleQuote", "tabWidth", "printWidth")
                        if k in config
                    ]
                    style.append(f"Prettier ({', '.join(facts) or 'defaults'}) in {rel}")
                    continue
                except ValueError:
                    pass
            if name == ".editorconfig":
                editor: list[tuple[str, str]] = re.findall(
                    r"^(indent_style|indent_size|max_line_length)\s*=\s*(\S+)", text, re.MULTILINE
                )
                style.append(
                    f"EditorConfig ({', '.join(f'{k}={v}' for k, v in editor) or 'present'})"
                    f" in {rel}"
                )
                continue
            style.append(f"{name} in {rel}")
    return ProjectConventions(languages=languages, frameworks=frameworks, style=style[:12])


@dataclass(frozen=True)
class CodeWindow:
    path: str
    start_line: int
    end_line: int
    text: str


def code_window(
    repo: Path, rel_path: str, start: int, end: int, context_lines: int
) -> CodeWindow | None:
    root = repo.resolve()
    path = (root / rel_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    first = max(1, start - context_lines)
    last = min(len(lines), max(start, end) + context_lines)
    return CodeWindow(rel_path, first, last, "\n".join(lines[first - 1 : last]))


def merge_windows(windows: list[CodeWindow]) -> list[CodeWindow]:
    """Overlapping or adjacent windows in the same file become one."""
    merged: list[CodeWindow] = []
    for window in sorted(windows, key=lambda w: (w.path, w.start_line)):
        previous = merged[-1] if merged else None
        if previous and previous.path == window.path and window.start_line <= previous.end_line + 1:
            overlap = previous.end_line - window.start_line + 1
            lines = previous.text.split("\n") + window.text.split("\n")[max(0, overlap) :]
            merged[-1] = CodeWindow(
                window.path,
                previous.start_line,
                max(previous.end_line, window.end_line),
                "\n".join(lines),
            )
        else:
            merged.append(window)
    return merged


def _version_parts(version: str) -> list[int]:
    return [int(p) for p in re.findall(r"\d+", version)[:3]]


def is_major_bump(installed: str, fixed: str | None) -> bool | None:
    """True if upgrading crosses a major version (for 0.x, a minor version). None if unknown."""
    if not fixed:
        return None
    old, new = _version_parts(installed), _version_parts(fixed)
    if not old or not new:
        return None
    if old[0] == 0 and new[0] == 0:
        return (old[1:2] or [0]) != (new[1:2] or [0])
    return old[0] != new[0]


def dependency_manifest(repo: Path, finding_path: str, ecosystem: str) -> str:
    """The file a dependency fix should edit: package.json next to an npm lockfile."""
    posix = PurePosixPath(finding_path)
    if ecosystem == "npm" and posix.name in {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    }:
        candidate = posix.parent / "package.json"
        if (repo / candidate).is_file():
            return candidate.as_posix()
    return finding_path

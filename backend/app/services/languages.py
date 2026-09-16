"""Detect which languages a codebase contains."""

import os
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".swift": "swift",
    ".scala": "scala",
}

MANIFEST_LANGUAGES: dict[str, str] = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Pipfile": "python",
    "package.json": "javascript",
    "tsconfig.json": "typescript",
    "go.mod": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "kotlin",
    "Gemfile": "ruby",
    "composer.json": "php",
    "Cargo.toml": "rust",
    "Package.swift": "swift",
}

# Vendored / generated trees that would skew the counts.
IGNORED_DIRS = frozenset(
    {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build"}
)
_MAX_MANIFESTS_PER_LANGUAGE = 20


@dataclass(frozen=True)
class DetectedLanguage:
    language: str
    file_count: int
    manifests: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_languages(root: Path) -> list[DetectedLanguage]:
    """Count source files per language and collect manifest files, most common first."""
    file_counts: Counter[str] = Counter()
    manifests: defaultdict[str, list[str]] = defaultdict(list)

    for dirpath, dirnames, filenames in os.walk(root):  # does not follow symlinks
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        for name in sorted(filenames):
            if (manifest_lang := MANIFEST_LANGUAGES.get(name)) is not None:
                if len(manifests[manifest_lang]) < _MAX_MANIFESTS_PER_LANGUAGE:
                    manifests[manifest_lang].append(
                        Path(dirpath, name).relative_to(root).as_posix()
                    )
            if (lang := EXTENSION_LANGUAGES.get(Path(name).suffix.lower())) is not None:
                file_counts[lang] += 1

    detected = [
        DetectedLanguage(language=lang, file_count=file_counts[lang], manifests=manifests[lang])
        for lang in set(file_counts) | set(manifests)
    ]
    return sorted(detected, key=lambda d: (-d.file_count, d.language))


MAX_COUNTED_FILE_BYTES = 1024 * 1024  # larger files are generated or bundled


def count_source_lines(root: Path) -> int:
    """Non-blank lines in recognised source files (vendored/generated trees skipped)."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() not in EXTENSION_LANGUAGES:
                continue
            path = Path(dirpath, name)
            try:
                if path.is_symlink() or path.stat().st_size > MAX_COUNTED_FILE_BYTES:
                    continue
                with path.open("rb") as fh:
                    total += sum(1 for line in fh if line.strip())
            except OSError:
                continue
    return total

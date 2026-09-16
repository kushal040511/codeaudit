from dataclasses import dataclass, field
from pathlib import Path

# File extension -> tree-sitter grammar name.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}


@dataclass
class ParsedModule:
    path: str
    language: str
    imports: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)


def parse_file(path: Path) -> ParsedModule:
    """Parse one source file with tree-sitter and extract imports/definitions.

    TODO: load grammars (tree_sitter_python / tree_sitter_javascript /
    tree_sitter_typescript), run import/definition queries, enforce max file
    size to avoid pathological inputs.
    """
    raise NotImplementedError

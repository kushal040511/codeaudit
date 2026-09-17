"""Parse source files with tree-sitter and extract imports, top-level symbols and size.

Parsing runs in the worker process (not the sandbox): tree-sitter only builds a
syntax tree and never executes code, and files are size-capped. See the README
"Sandboxing" section for the remaining risk.

tree-sitter never raises on invalid code; it returns a tree containing ERROR
nodes. A file whose tree has errors is recorded with `error` set and no imports,
so one broken file can't produce bogus edges or stop the scan. Note that valid
code can hit this too when the grammar lags the language (tree-sitter-typescript
0.23 rejects `fn<typeof import("x")>()`).
"""

import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path, PurePosixPath

import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

logger = logging.getLogger(__name__)

# File extension -> (language family, tree-sitter grammar).
GRAMMAR_BY_EXTENSION: dict[str, tuple[str, str]] = {
    ".py": ("python", "python"),
    ".js": ("javascript", "javascript"),
    ".jsx": ("javascript", "javascript"),
    ".mjs": ("javascript", "javascript"),
    ".cjs": ("javascript", "javascript"),
    ".ts": ("typescript", "typescript"),
    ".mts": ("typescript", "typescript"),
    ".cts": ("typescript", "typescript"),
    ".tsx": ("typescript", "tsx"),
}

# Vendored, generated or environment trees: never part of the project's architecture.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "vendor",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "site-packages",
        "dist",
        "build",
        "out",
        ".next",
        ".nuxt",
        ".svelte-kit",
        "coverage",
        ".turbo",
        ".cache",
    }
)

MAX_FILE_BYTES = 1024 * 1024  # larger files are almost always generated or bundled
MAX_STATEMENT_CHARS = 300


@dataclass(frozen=True)
class RawImport:
    """One import as written in the source."""

    specifier: str  # "a.b", ".mod", "./x", "@scope/pkg/sub"
    # python: "import" | "from"; js/ts: "import" | "export-from" | "require" | "dynamic-import"
    kind: str
    line: int
    statement: str
    # Python `from x import a, b`: the imported names (they may be submodules).
    names: tuple[str, ...] = ()
    level: int = 0  # Python relative import dots
    type_only: bool = False  # `if TYPE_CHECKING:` / `import type`: no runtime dependency
    lazy: bool = False  # inside a function body (Python)
    dynamic: bool = False  # non-literal specifier (`require(name)`); cannot be resolved


@dataclass
class ParsedModule:
    path: str  # repo-relative POSIX path
    language: str  # python | javascript | typescript
    loc: int = 0  # non-blank lines
    definition_count: int = 0  # classes and functions/methods, at any depth
    symbols: list[str] = field(default_factory=list)  # top-level classes/functions (+ JS exports)
    imports: list[RawImport] = field(default_factory=list)
    error: str | None = None  # set when the file could not be used at all
    # Set when the grammar choked on part of the file: what parsed is still used.
    warning: str | None = None


@cache
def grammar_language(grammar: str) -> Language:
    if grammar == "python":
        return Language(tree_sitter_python.language())
    if grammar == "javascript":
        return Language(tree_sitter_javascript.language())
    if grammar == "typescript":
        return Language(tree_sitter_typescript.language_typescript())
    if grammar == "tsx":
        return Language(tree_sitter_typescript.language_tsx())
    raise ValueError(f"unknown grammar {grammar}")


def language_for(path: str) -> tuple[str, str] | None:
    name = PurePosixPath(path).name
    if name.endswith(".d.ts") or name.endswith((".min.js", ".bundle.js")):
        return None  # type declarations and bundles aren't modules of the project
    return GRAMMAR_BY_EXTENSION.get(PurePosixPath(path).suffix.lower())


def discover_source_files(root: Path) -> list[str]:
    """Repo-relative paths of every parseable source file, sorted."""
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):  # does not follow symlinks
        dirnames[:] = sorted(
            d for d in dirnames if d not in IGNORED_DIRS and not d.endswith(".egg-info")
        )
        for name in sorted(filenames):
            rel = Path(dirpath, name).relative_to(root).as_posix()
            if language_for(rel) is not None:
                files.append(rel)
    return files


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _statement(node: Node) -> str:
    return " ".join(_text(node).split())[:MAX_STATEMENT_CHARS]


def _walk(node: Node) -> Iterator[Node]:
    """Pre-order traversal without recursion (deeply nested code can't overflow the stack)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _first_argument(call: Node) -> Node | None:
    """First argument of a call, skipping comments (`import(/* webpackChunkName */ "x")`)."""
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    return next((c for c in arguments.named_children if c.type != "comment"), None)


def _count_loc(source: bytes) -> int:
    return sum(1 for line in source.splitlines() if line.strip())


def parse_file(root: Path, rel_path: str) -> ParsedModule:
    """Parse one file. Never raises: problems are reported through `ParsedModule.error`."""
    detected = language_for(rel_path)
    if detected is None:
        return ParsedModule(path=rel_path, language="unknown", error="unsupported file type")
    language, grammar = detected
    module = ParsedModule(path=rel_path, language=language)

    try:
        path = root / rel_path
        if path.stat().st_size > MAX_FILE_BYTES:
            module.error = f"file larger than {MAX_FILE_BYTES // 1024} KB"
            return module
        source = path.read_bytes()
    except OSError as exc:
        module.error = f"unreadable: {exc.strerror or exc}"
        return module

    module.loc = _count_loc(source)
    try:
        tree = Parser(grammar_language(grammar)).parse(source)
        if tree.root_node.has_error:
            # Invalid code, or syntax the grammar doesn't support yet (tree-sitter lags
            # the language). Keep what did parse: imports are usually at the top and
            # fine, so the module still appears in the graph.
            module.warning = (
                f"partial parse near line {_first_error_line(tree.root_node)};"
                " some imports may be missing"
            )
        if language == "python":
            _extract_python(tree.root_node, module)
        else:
            _extract_js(tree.root_node, module)
    except Exception as exc:  # a parser bug must not stop the scan
        logger.warning("parsing %s failed: %r", rel_path, exc)
        module.error = "parser failure"
        module.imports.clear()
    return module


def _first_error_line(root: Node) -> int:
    for node in _walk(root):
        if node.type == "ERROR" or node.is_missing:
            return node.start_point.row + 1
    return root.start_point.row + 1


# ----------------------------------------------------------------------------- Python


def _python_type_checking(node: Node) -> bool:
    """Inside the body of `if TYPE_CHECKING:` (not its else branch)."""
    child, parent = node, node.parent
    while parent is not None:
        if parent.type == "if_statement":
            condition = _text(parent.child_by_field_name("condition"))
            consequence = parent.child_by_field_name("consequence")
            if condition in {"TYPE_CHECKING", "typing.TYPE_CHECKING"} and child == consequence:
                return True
        child, parent = parent, parent.parent
    return False


def _inside_function(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in {"function_definition", "lambda"}:
            return True
        parent = parent.parent
    return False


def _python_import_name(node: Node) -> str:
    """dotted_name, or the `name` of an aliased_import."""
    if node.type == "aliased_import":
        return _text(node.child_by_field_name("name"))
    return _text(node)


def _extract_python(root: Node, module: ParsedModule) -> None:
    for child in root.named_children:
        target = child
        if child.type == "decorated_definition":
            target = child.child_by_field_name("definition") or child
        if target.type in {"class_definition", "function_definition"}:
            module.symbols.append(_text(target.child_by_field_name("name")))

    for node in _walk(root):
        kind = node.type
        if kind in {"class_definition", "function_definition"}:
            module.definition_count += 1
        elif kind == "import_statement":
            type_only, lazy = _python_flags(node)
            for name_node in node.children_by_field_name("name"):
                module.imports.append(
                    RawImport(
                        specifier=_python_import_name(name_node),
                        kind="import",
                        line=node.start_point.row + 1,
                        statement=_statement(node),
                        type_only=type_only,
                        lazy=lazy,
                    )
                )
        elif kind == "import_from_statement":
            module_name = node.child_by_field_name("module_name")
            level, dotted = 0, _text(module_name)
            if module_name is not None and module_name.type == "relative_import":
                prefix = next((c for c in module_name.children if c.type == "import_prefix"), None)
                level = len(_text(prefix))
                dotted = _text(
                    next((c for c in module_name.children if c.type == "dotted_name"), None)
                )
            names = tuple(_python_import_name(n) for n in node.children_by_field_name("name"))
            type_only, lazy = _python_flags(node)
            module.imports.append(
                RawImport(
                    specifier=dotted,
                    kind="from",
                    line=node.start_point.row + 1,
                    statement=_statement(node),
                    names=names,  # empty for `from x import *`
                    level=level,
                    type_only=type_only,
                    lazy=lazy,
                )
            )
        elif kind == "call":
            _python_dynamic_import(node, module)


def _python_flags(node: Node) -> tuple[bool, bool]:
    """(type_only, lazy)"""
    return _python_type_checking(node), _inside_function(node)


def _python_dynamic_import(node: Node, module: ParsedModule) -> None:
    function = _text(node.child_by_field_name("function"))
    if function not in {"importlib.import_module", "import_module", "__import__"}:
        return
    first = _first_argument(node)
    literal = _python_string_literal(first)
    if literal is not None and literal.startswith("."):
        return  # relative import_module needs the `package` argument; rare, skip
    module.imports.append(
        RawImport(
            specifier=literal or _text(first)[:MAX_STATEMENT_CHARS],
            kind="dynamic-import",
            line=node.start_point.row + 1,
            statement=_statement(node),
            lazy=_inside_function(node),
            dynamic=literal is None,
        )
    )


def _python_string_literal(node: Node | None) -> str | None:
    if node is None or node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.children):
        return None
    content = [c for c in node.children if c.type == "string_content"]
    return "".join(_text(c) for c in content)


# ----------------------------------------------------------------------------- JS / TS

_JS_DEFINITIONS = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "abstract_class_declaration",
        "method_definition",
    }
)
_JS_FUNCTION_VALUES = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function", "class"}
)


def _js_string_literal(node: Node | None) -> str | None:
    """Value of a string or substitution-free template literal, else None."""
    if node is None:
        return None
    if node.type == "string":
        return "".join(_text(c) for c in node.named_children if c.type == "string_fragment")
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return "".join(_text(c) for c in node.named_children if c.type == "string_fragment")
    return None


def _has_anon_child(node: Node, token: str) -> bool:
    return any(not c.is_named and c.type == token for c in node.children)


def _js_type_only_import(node: Node) -> bool:
    if _has_anon_child(node, "type"):  # import type {...} / export type {...} from
        return True
    clause = next((c for c in node.named_children if c.type == "import_clause"), None)
    if clause is None or any(c.type != "named_imports" for c in clause.named_children):
        return False
    specifiers = [
        s
        for named in clause.named_children
        for s in named.named_children
        if s.type == "import_specifier"
    ]
    # import {type A, type B} from "x": erased at compile time
    return bool(specifiers) and all(_has_anon_child(s, "type") for s in specifiers)


def _js_top_level_symbols(root: Node, module: ParsedModule) -> None:
    for child in root.named_children:
        declaration = child
        exported = child.type == "export_statement"
        if exported:
            declaration = child.child_by_field_name("declaration") or child
        if declaration.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "abstract_class_declaration",
        }:
            module.symbols.append(_text(declaration.child_by_field_name("name")))
        elif exported and declaration.type in {"lexical_declaration", "variable_declaration"}:
            for declarator in declaration.named_children:
                if declarator.type == "variable_declarator":
                    module.symbols.append(_text(declarator.child_by_field_name("name")))
        elif exported and _has_anon_child(child, "default") and "default" not in module.symbols:
            module.symbols.append("default")


def _extract_js(root: Node, module: ParsedModule) -> None:
    _js_top_level_symbols(root, module)

    for node in _walk(root):
        kind = node.type
        if kind in _JS_DEFINITIONS:
            module.definition_count += 1
        elif kind == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in _JS_FUNCTION_VALUES:
                module.definition_count += 1
        elif kind in {"import_statement", "export_statement"}:
            source = node.child_by_field_name("source")
            if source is not None:
                module.imports.append(
                    RawImport(
                        specifier=_js_string_literal(source) or "",
                        kind="import" if kind == "import_statement" else "export-from",
                        line=node.start_point.row + 1,
                        statement=_statement(node),
                        type_only=_js_type_only_import(node),
                    )
                )
        elif kind == "import_require_clause":  # TS: import x = require("y")
            source = node.child_by_field_name("source") or next(
                (c for c in node.named_children if c.type == "string"), None
            )
            module.imports.append(
                RawImport(
                    specifier=_js_string_literal(source) or "",
                    kind="require",
                    line=node.start_point.row + 1,
                    statement=_statement(node.parent or node),
                )
            )
        elif kind == "call_expression":
            _js_call_import(node, module)


def _js_call_import(node: Node, module: ParsedModule) -> None:
    function = node.child_by_field_name("function")
    if function is None:
        return
    if function.type == "import":
        import_kind = "dynamic-import"
    elif function.type == "identifier" and _text(function) == "require":
        import_kind = "require"
    else:
        return
    first = _first_argument(node)
    if first is None:
        return
    literal = _js_string_literal(first)
    module.imports.append(
        RawImport(
            specifier=literal if literal is not None else _text(first)[:MAX_STATEMENT_CHARS],
            kind=import_kind,
            line=node.start_point.row + 1,
            statement=_statement(node),
            dynamic=literal is None,
        )
    )

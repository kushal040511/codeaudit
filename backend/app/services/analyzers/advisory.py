"""Advisory naming and comment metrics: measured, never scored, never findings.

Experimental (rubric 1.1). See docs/adr/0005-naming-and-comment-signals-are-advisory.md
for why these are advisory: they're stored in `scans.advisory_metrics` and passed to
the LLM architecture review as qualitative context, but the rubric ignores them.

tree-sitter parses the project's own Python, JavaScript and TypeScript files (test
files excluded) in a child process (`isolated_signal.run_collector`).

Metrics:
- `naming`: per language and identifier kind, the share of definitions that follow
  the language's convention. Python: functions and variables snake_case (module
  constants UPPER_SNAKE allowed), classes PascalCase. JS/TS: functions, methods and
  variables camelCase, `const` UPPER_SNAKE allowed, functions PascalCase allowed (React
  components); classes, interfaces, type aliases and enums PascalCase. Leading
  underscores (and `$` in JS) are ignored; dunder names are skipped.
- `single_letter`: one-character variable/parameter names, excluding `_`, loop
  variables (`for`), comprehension variables, lambda / arrow-function parameters and a
  catch parameter named `e`. Count and rate per 1,000 identifiers.
- `generic_names`: identifiers whose whole name (case-insensitive, underscores stripped)
  is one of GENERIC_NAMES. Count, rate per 1,000 identifiers, per-name counts and up to
  20 examples (path:line).
- `comments`: comment lines / non-blank lines (docstrings are not comments here).
- `docstrings`: share of public definitions with documentation. Python: functions,
  methods and classes not nested in a function whose name doesn't start with `_`,
  documented when the first statement is a string. JS/TS: exported functions and
  classes (including `export const f = () => ...`), documented when immediately
  preceded by a `/** ... */` comment.

Identifiers are definition sites (functions, methods, classes, variables, parameters),
counted once per name per scope.
"""

import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Node

from app.config import Settings, get_settings
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.error_handling import (
    SourceTree,
    iter_source_trees,
    line_of,
    node_text,
)
from app.services.analyzers.isolated_signal import run_collector
from app.services.analyzers.signals import ADVISORY, SignalReport, not_applicable
from app.services.graph.parser import _walk

COLLECTOR = "app.services.analyzers.advisory:collect"
MAX_EXAMPLES = 20

GENERIC_NAMES = frozenset(
    {
        "data",
        "temp",
        "tmp",
        "foo",
        "bar",
        "handler",
        "manager",
        "util",
        "utils",
        "helper",
        "obj",
        "stuff",
        "thing",
        "info",
    }
)

_SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")
_PASCAL = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
_CAMEL = re.compile(r"^[a-z][a-zA-Z0-9]*$")

# kind -> "function" | "class" | "variable" (parameters count as variables)
_PY_SCOPES = frozenset({"function_definition", "class_definition", "lambda"})
_JS_SCOPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
        "class_declaration",
        "class",
    }
)
_JS_FUNCTION_VALUES = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function"}
)
_JS_TYPE_DECLARATIONS = frozenset(
    {
        "class_declaration",
        "abstract_class_declaration",
        "class",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
    }
)


@dataclass(frozen=True)
class Identifier:
    name: str
    kind: str  # function | class | variable
    line: int
    # Loop/comprehension/lambda variable or catch parameter: exempt from single-letter.
    exempt_short: bool = False
    const: bool = False  # JS `const` (may be UPPER_SNAKE)


@dataclass
class Totals:
    naming: dict[str, dict[str, list[int]]] = field(default_factory=dict)  # lang -> kind -> [ok, n]
    naming_examples: list[dict[str, Any]] = field(default_factory=list)
    identifiers: int = 0
    single_letter: int = 0
    single_letter_examples: list[str] = field(default_factory=list)
    generic: Counter[str] = field(default_factory=Counter)
    generic_examples: list[str] = field(default_factory=list)
    comments: dict[str, list[int]] = field(default_factory=dict)  # lang -> [comment, non-blank]
    docs: dict[str, list[int]] = field(default_factory=dict)  # lang -> [documented, public]
    undocumented_examples: list[str] = field(default_factory=list)


def _strip(name: str) -> str:
    return name.lstrip("_$").rstrip("_")


def _conforms(language: str, ident: Identifier) -> bool:
    name = _strip(ident.name)
    if not name:
        return True
    if ident.kind == "class":
        return bool(_PASCAL.match(name))
    if language == "python":
        if ident.kind == "variable" and _UPPER_SNAKE.match(name):
            return True  # module constants
        return bool(_SNAKE.match(name))
    if ident.kind == "function" and _PASCAL.match(name):
        return True  # React components
    if ident.const and _UPPER_SNAKE.match(name):
        return True
    return bool(_CAMEL.match(name))


def _expected(language: str, kind: str) -> str:
    if kind == "class":
        return "PascalCase"
    return "snake_case" if language == "python" else "camelCase"


# ----------------------------------------------------------------------------- Python


def _py_scope(node: Node) -> int:
    parent = node.parent
    while parent is not None:
        if parent.type in _PY_SCOPES:
            return parent.start_byte
        parent = parent.parent
    return -1


def _py_targets(node: Node | None) -> list[Node]:
    """Plain identifiers bound by an assignment / for target (not attributes/subscripts)."""
    if node is None:
        return []
    if node.type == "identifier":
        return [node]
    if node.type in {"pattern_list", "tuple_pattern", "list_pattern", "tuple", "list"}:
        return [t for child in node.named_children for t in _py_targets(child)]
    if node.type in {"list_splat_pattern", "parenthesized_expression"}:
        return [t for child in node.named_children for t in _py_targets(child)]
    return []


def _py_parameters(parameters: Node | None) -> list[Node]:
    names: list[Node] = []
    for child in parameters.named_children if parameters else []:
        if child.type == "identifier":
            names.append(child)
        elif child.type in {"default_parameter", "typed_default_parameter"}:
            name = child.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                names.append(name)
        elif child.type in {"typed_parameter", "list_splat_pattern", "dictionary_splat_pattern"}:
            names.extend(c for c in child.named_children[:1] if c.type == "identifier")
    return names


def _python_identifiers(tree: SourceTree) -> list[tuple[Identifier, int]]:
    found: list[tuple[Identifier, int]] = []

    def add(node: Node, kind: str, exempt: bool = False, scope: int | None = None) -> None:
        name = node_text(node)
        if name.startswith("__") and name.endswith("__"):
            return
        ident = Identifier(name, kind, line_of(node), exempt_short=exempt)
        found.append((ident, _py_scope(node) if scope is None else scope))

    for node in _walk(tree.root):
        kind = node.type
        if kind == "function_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                add(name, "function", scope=_py_scope(node))
            for parameter in _py_parameters(node.child_by_field_name("parameters")):
                add(parameter, "variable", scope=node.start_byte)
        elif kind == "lambda":
            for parameter in _py_parameters(node.child_by_field_name("parameters")):
                add(parameter, "variable", exempt=True, scope=node.start_byte)
        elif kind == "class_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                add(name, "class", scope=_py_scope(node))
        elif kind in {"assignment", "augmented_assignment"}:
            for target in _py_targets(node.child_by_field_name("left")):
                add(target, "variable")
        elif kind in {"for_statement", "for_in_clause"}:
            for target in _py_targets(node.child_by_field_name("left")):
                add(target, "variable", exempt=True)
        elif kind == "as_pattern_target":
            for target in _py_targets(node.named_children[0] if node.named_children else None):
                parent = node.parent.parent if node.parent else None
                in_except = parent is not None and parent.type == "except_clause"
                add(target, "variable", exempt=in_except and node_text(target) == "e")
    return found


def _py_documented(definition: Node) -> bool:
    body = definition.child_by_field_name("body")
    first = next((c for c in body.named_children if c.type != "comment"), None) if body else None
    return (
        first is not None
        and first.type == "expression_statement"
        and bool(first.named_children)
        and first.named_children[0].type in {"string", "concatenated_string"}
    )


def _py_nested_in_function(node: Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type in {"function_definition", "lambda"}:
            return True
        parent = parent.parent
    return False


def _python_docs(tree: SourceTree, totals: Totals) -> None:
    counts = totals.docs.setdefault(tree.language, [0, 0])
    for node in _walk(tree.root):
        if node.type not in {"function_definition", "class_definition"}:
            continue
        name = node_text(node.child_by_field_name("name"))
        if not name or name.startswith("_") or _py_nested_in_function(node):
            continue
        counts[1] += 1
        if _py_documented(node):
            counts[0] += 1
        elif len(totals.undocumented_examples) < MAX_EXAMPLES:
            totals.undocumented_examples.append(f"{tree.path}:{line_of(node)}")


# ----------------------------------------------------------------------------- JS / TS


def _js_scope(node: Node) -> int:
    parent = node.parent
    while parent is not None:
        if parent.type in _JS_SCOPES:
            return parent.start_byte
        parent = parent.parent
    return -1


def _js_pattern_names(node: Node | None) -> list[Node]:
    """Identifiers bound by a declaration pattern (`a`, `{a, b: c}`, `[a, ...b]`, `a = 1`)."""
    if node is None:
        return []
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return [node]
    if node.type == "pair_pattern":
        return _js_pattern_names(node.child_by_field_name("value"))
    if node.type in {"assignment_pattern", "object_assignment_pattern"}:
        return _js_pattern_names(node.child_by_field_name("left"))
    if node.type in {"required_parameter", "optional_parameter"}:
        return _js_pattern_names(node.child_by_field_name("pattern"))
    if node.type in {"object_pattern", "array_pattern", "rest_pattern"}:
        return [n for child in node.named_children for n in _js_pattern_names(child)]
    return []


def _js_is_loop_declaration(declarator: Node) -> bool:
    declaration = declarator.parent
    loop = declaration.parent if declaration is not None else None
    return loop is not None and loop.type == "for_statement"


def _js_identifiers(tree: SourceTree) -> list[tuple[Identifier, int]]:
    found: list[tuple[Identifier, int]] = []

    def add(node: Node, kind: str, scope: int, exempt: bool = False, const: bool = False) -> None:
        name = node_text(node).lstrip("#")
        if name:
            found.append((Identifier(name, kind, line_of(node), exempt, const), scope))

    for node in _walk(tree.root):
        kind = node.type
        if kind in {"function_declaration", "generator_function_declaration"}:
            name = node.child_by_field_name("name")
            if name is not None:
                add(name, "function", _js_scope(node))
        elif kind == "method_definition":
            name = node.child_by_field_name("name")
            if (
                name is not None
                and name.type in {"property_identifier", "private_property_identifier"}
                and node_text(name) != "constructor"
            ):
                add(name, "function", _js_scope(node))
        elif kind in _JS_TYPE_DECLARATIONS:
            name = node.child_by_field_name("name")
            if name is not None:
                add(name, "class", _js_scope(node))
        elif kind == "variable_declarator":
            value = node.child_by_field_name("value")
            declaration = node.parent
            const = declaration is not None and any(
                not c.is_named and c.type == "const" for c in declaration.children
            )
            is_function = value is not None and value.type in _JS_FUNCTION_VALUES
            for bound in _js_pattern_names(node.child_by_field_name("name")):
                add(
                    bound,
                    "function" if is_function else "variable",
                    _js_scope(node),
                    exempt=_js_is_loop_declaration(node),
                    const=const,
                )
        elif kind == "for_in_statement":
            for name in _js_pattern_names(node.child_by_field_name("left")):
                add(name, "variable", _js_scope(node), exempt=True)
        elif kind == "formal_parameters":
            function = node.parent
            arrow = function is not None and function.type == "arrow_function"
            scope = function.start_byte if function is not None else -1
            for parameter in node.named_children:
                for name in _js_pattern_names(parameter):
                    add(name, "variable", scope, exempt=arrow)
        elif kind == "arrow_function":
            bare = node.child_by_field_name("parameter")  # `x => ...`
            if bare is not None and bare.type == "identifier":
                add(bare, "variable", node.start_byte, exempt=True)
        elif kind == "catch_clause":
            for name in _js_pattern_names(node.child_by_field_name("parameter")):
                add(name, "variable", node.start_byte, exempt=node_text(name) == "e")
    return found


def _js_documented(statement: Node) -> bool:
    previous = statement.prev_named_sibling
    return (
        previous is not None
        and previous.type == "comment"
        and node_text(previous).startswith("/**")
        and previous.end_point.row >= statement.start_point.row - 1
    )


def _js_docs(tree: SourceTree, totals: Totals) -> None:
    counts = totals.docs.setdefault(tree.language, [0, 0])
    for statement in tree.root.named_children:
        if statement.type != "export_statement":
            continue
        declaration = statement.child_by_field_name("declaration") or statement.child_by_field_name(
            "value"
        )
        if declaration is None:
            continue
        public = declaration.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
            "abstract_class_declaration",
            "function_expression",
            "function",
            "class",
            "arrow_function",
        } or (
            declaration.type in {"lexical_declaration", "variable_declaration"}
            and any(
                d.type == "variable_declarator"
                and (value := d.child_by_field_name("value")) is not None
                and value.type in _JS_FUNCTION_VALUES
                for d in declaration.named_children
            )
        )
        if not public:
            continue
        counts[1] += 1
        if _js_documented(statement):
            counts[0] += 1
        elif len(totals.undocumented_examples) < MAX_EXAMPLES:
            totals.undocumented_examples.append(f"{tree.path}:{line_of(statement)}")


# ----------------------------------------------------------------------------- shared


def _comment_lines(tree: SourceTree) -> int:
    rows: set[int] = set()
    for node in _walk(tree.root):
        if node.type == "comment":
            rows.update(range(node.start_point.row, node.end_point.row + 1))
    return len(rows)


def _tally(tree: SourceTree, identifiers: list[tuple[Identifier, int]], totals: Totals) -> None:
    seen: set[tuple[str, str, int]] = set()
    naming = totals.naming.setdefault(tree.language, {})
    for ident, scope in identifiers:
        key = (ident.name, ident.kind, scope)
        if key in seen:
            continue
        seen.add(key)
        totals.identifiers += 1
        counts = naming.setdefault(ident.kind, [0, 0])
        counts[1] += 1
        if _conforms(tree.language, ident):
            counts[0] += 1
        elif len(totals.naming_examples) < MAX_EXAMPLES:
            totals.naming_examples.append(
                {
                    "name": ident.name,
                    "kind": ident.kind,
                    "expected": _expected(tree.language, ident.kind),
                    "location": f"{tree.path}:{ident.line}",
                }
            )
        if (
            ident.kind == "variable"
            and len(ident.name) == 1
            and ident.name != "_"
            and not ident.exempt_short
        ):
            totals.single_letter += 1
            if len(totals.single_letter_examples) < MAX_EXAMPLES:
                totals.single_letter_examples.append(f"{tree.path}:{ident.line} {ident.name}")
        generic = ident.name.strip("_$").lower()
        if generic in GENERIC_NAMES:
            totals.generic[generic] += 1
            if len(totals.generic_examples) < MAX_EXAMPLES:
                totals.generic_examples.append(f"{tree.path}:{ident.line} {ident.name}")


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _per_1k(count: int, identifiers: int) -> float | None:
    return round(count * 1000 / identifiers, 2) if identifiers else None


def collect(repo: Path, deadline: float, **_: Any) -> dict[str, Any]:
    """Measure naming, comments and docstrings. JSON-serialisable; runs in the child process."""
    totals = Totals()
    skipped: list[dict[str, str]] = []
    languages: Counter[str] = Counter()
    for tree in iter_source_trees(repo, deadline, skipped):
        languages[tree.language] += 1
        if tree.language == "python":
            identifiers = _python_identifiers(tree)
            _python_docs(tree, totals)
        else:
            identifiers = _js_identifiers(tree)
            _js_docs(tree, totals)
        _tally(tree, identifiers, totals)
        comment = totals.comments.setdefault(tree.language, [0, 0])
        comment[0] += _comment_lines(tree)
        comment[1] += sum(1 for line in tree.source.splitlines() if line.strip())

    naming = {
        language: {
            **{
                kind: {"conforming": ok, "total": n, "rate": _ratio(ok, n)}
                for kind, (ok, n) in sorted(kinds.items())
            },
            "overall_rate": _ratio(
                sum(ok for ok, _ in kinds.values()), sum(n for _, n in kinds.values())
            ),
        }
        for language, kinds in sorted(totals.naming.items())
    }
    comment_total = [sum(c[0] for c in totals.comments.values()), 0]
    comment_total[1] = sum(c[1] for c in totals.comments.values())
    docs_total = [sum(d[0] for d in totals.docs.values()), sum(d[1] for d in totals.docs.values())]
    generic_count = sum(totals.generic.values())
    return {
        "files_parsed": sum(languages.values()),
        "languages": dict(sorted(languages.items())),
        "files_skipped": len(skipped),
        "identifiers": totals.identifiers,
        "naming": naming,
        "naming_examples": totals.naming_examples,
        "single_letter": {
            "count": totals.single_letter,
            "per_1k_identifiers": _per_1k(totals.single_letter, totals.identifiers),
            "examples": totals.single_letter_examples,
        },
        "generic_names": {
            "count": generic_count,
            "per_1k_identifiers": _per_1k(generic_count, totals.identifiers),
            "by_name": dict(totals.generic.most_common()),
            "examples": totals.generic_examples,
        },
        "comments": {
            "comment_lines": comment_total[0],
            "non_blank_lines": comment_total[1],
            "density": _ratio(comment_total[0], comment_total[1]),
            "by_language": {
                language: _ratio(lines, non_blank)
                for language, (lines, non_blank) in sorted(totals.comments.items())
            },
        },
        "docstrings": {
            "documented": docs_total[0],
            "public_definitions": docs_total[1],
            "coverage": _ratio(docs_total[0], docs_total[1]),
            "by_language": {
                language: _ratio(documented, public)
                for language, (documented, public) in sorted(totals.docs.items())
            },
            "undocumented_examples": totals.undocumented_examples,
        },
    }


def build_report(collected: dict[str, Any]) -> SignalReport:
    if not collected.get("files_parsed"):
        return not_applicable(ADVISORY, "no non-test Python, JavaScript or TypeScript source files")
    return SignalReport(
        name=ADVISORY, applicable=True, score=None, components={}, metrics=collected
    )


class AdvisoryAnalyzer(Analyzer):
    """Naming and comment metrics for the LLM review; never findings, never scored."""

    name = ADVISORY
    display_name = "Naming & comments (advisory)"
    supported_languages = frozenset({"python", "javascript", "typescript"})
    phase = 1
    experimental = True

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = None  # tree-sitter in a child process of the worker
        self.timeout_seconds = self._settings.experimental_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        collected = run_collector(COLLECTOR, repo_path, context.work_dir, self.timeout_seconds)
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=[],
            raw_output=json.dumps(collected),
            duration_ms=int((time.monotonic() - started) * 1000),
            artifact=build_report(collected),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        return []  # advisory: never findings (ADR 0005)

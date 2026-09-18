"""Error-handling signal: swallowed exceptions, unguarded I/O and unhandled promises.

Experimental (rubric 1.1). tree-sitter parses the project's own Python, JavaScript
and TypeScript files (test files excluded, see `rubric.is_test_path`) in a child
process (`isolated_signal.run_collector`), because the parser is native code reading
untrusted input.

Rules (one finding per occurrence; severity in brackets):

Python
- `bare-except` [warning]: `except:`.
- `swallowed-broad-except` [warning]: `except Exception/BaseException:` whose body is
  only `pass` / `...`.
- `exception-ignored` [info]: any other handler that neither re-raises (`raise`),
  logs (see `_PY_LOG_*`), nor uses the bound exception name. Handlers that only catch
  "expected" EAFP exceptions (`_PY_EXPECTED`, e.g. `except KeyError: return None`)
  are not flagged: that is idiomatic control flow, not a swallowed error.
- `broad-except-large-block` [info]: a broad handler (bare/Exception/BaseException)
  guarding a try body longer than 25 lines. Reported in addition to the rules above.

JavaScript / TypeScript
- `empty-catch` [warning]: `catch {}` / `catch (e) {}` (a comment-only body counts as
  empty: the error is still dropped).
- `catch-only-logs-to-console` [info]: the catch body only calls `console.*`.
- `unhandled-promise` [info]: an expression statement whose call chain uses `.then(`
  without any `.catch(` and without a rejection handler (second argument) on a `.then`.
- `await-io-outside-try` [info]: `await` of an I/O call (list below) inside an async
  function, not inside a try block of that function and without `.catch(` on the chain.

I/O and network call sites (`io_wrapped_ratio`). A call is an I/O site when:
- Python: `open`/`io.open`; `requests.*`, `httpx.*`, `aiohttp.*` HTTP verbs
  (get/post/put/patch/delete/head/options/request/stream); `urllib.request.urlopen` /
  `urlopen`; `socket.create_connection/create_server/getaddrinfo/gethostbyname*`;
  `subprocess.run/call/check_call/check_output/Popen/getoutput/getstatusoutput`;
  `os.remove/unlink/rename/replace/rmdir/removedirs/mkdir/makedirs/listdir/scandir/
  open/system/popen/chmod/chown/symlink/link`; `shutil.copy*/move/rmtree`; any
  `.execute(` / `.executemany(` (DB cursors); any `.read_text/.write_text/.read_bytes/
  .write_bytes(` (pathlib). boto3 and other SDK client calls are out of scope.
- JS/TS: `fetch` (also `window.`/`globalThis.`); `axios(...)` and `axios.<verb>`;
  `http(s).request/get`; any `fs.*`, `fs.promises.*`, `fsp.*`, `fsPromises.*`;
  `child_process.*` / `childProcess.*` and bare `exec/execSync/execFile/execFileSync/
  spawn/spawnSync`; `new XMLHttpRequest()`; any `.query(` (DB clients).
A site is *wrapped* when it is lexically inside the body of a `try` in the same function
(a try around a nested function definition doesn't count), or, for JS/TS, when its
promise chain has a `.catch(` or a two-argument `.then(`.

SignalReport components (each in [0, 1], 1 = best; None when there is nothing to measure):
- `swallow_rate` = 1 - (bare-except + swallowed-broad-except + empty-catch +
  exception-ignored + catch-only-logs-to-console) / handlers, where handlers is the
  number of except/catch clauses. None if there are no handlers.
- `io_wrapped_ratio` = wrapped I/O sites / I/O sites. None if there are no I/O sites.
- `promise_handling` = 1 - (unhandled-promise + await-io-outside-try) / promise sites,
  where promise sites are `.then(` chains in expression statements plus awaited I/O
  calls in async functions. None if there are none.
score = mean of the available components. Not applicable when the repository has no
non-test Python/JavaScript/TypeScript source.

Known limits: purely syntactic. Loggers are recognised by name (`logger`, `log`,
`logging`, `*logger`), I/O calls by the names above (an aliased import such as
`from requests import get` is missed), and a promise stored in a variable and handled
later is reported as unhandled.
"""

import json
import logging
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tree_sitter import Node, Parser

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.isolated_signal import CollectorTimeout, run_collector
from app.services.analyzers.sandbox import AnalyzerOutputError
from app.services.analyzers.signals import SignalReport, mean_score, not_applicable
from app.services.graph.parser import (
    MAX_FILE_BYTES,
    _walk,
    discover_source_files,
    grammar_language,
    language_for,
)
from app.services.scoring.rubric import is_test_path

logger = logging.getLogger(__name__)

ANALYZER_NAME = "error_handling"
COLLECTOR = "app.services.analyzers.error_handling:collect"
LARGE_TRY_LINES = 25
MAX_FINDINGS_PER_RULE = 200  # counts stay exact; only the reported findings are capped
MAX_SNIPPET_CHARS = 200
MAX_EXAMPLES = 10

RULES: dict[str, tuple[Severity, str]] = {
    "bare-except": (
        Severity.WARNING,
        "Bare `except:` catches everything, including KeyboardInterrupt and SystemExit.",
    ),
    "swallowed-broad-except": (
        Severity.WARNING,
        "Broad exception handler silently discards the error (body is only `pass`/`...`).",
    ),
    "exception-ignored": (
        Severity.INFO,
        "Exception handler neither re-raises, logs, nor uses the caught exception.",
    ),
    "broad-except-large-block": (
        Severity.INFO,
        f"Broad exception handler guards a try block longer than {LARGE_TRY_LINES} lines.",
    ),
    "empty-catch": (Severity.WARNING, "Empty catch block silently discards the error."),
    "catch-only-logs-to-console": (
        Severity.INFO,
        "Catch block only logs to the console and then carries on as if nothing failed.",
    ),
    "unhandled-promise": (
        Severity.INFO,
        "Promise chain has `.then(` but no `.catch(` or rejection handler.",
    ),
    "await-io-outside-try": (
        Severity.INFO,
        "Awaited I/O call is not inside a try block and has no `.catch(`.",
    ),
}
SWALLOW_RULES = frozenset(
    {
        "bare-except",
        "swallowed-broad-except",
        "empty-catch",
        "exception-ignored",
        "catch-only-logs-to-console",
    }
)
PROMISE_RULES = frozenset({"unhandled-promise", "await-io-outside-try"})

# ----------------------------------------------------------------------------- shared parsing


@dataclass
class SourceTree:
    path: str  # repo-relative POSIX
    language: str  # python | javascript | typescript
    source: bytes
    root: Node
    partial: bool  # the grammar reported syntax errors; what parsed is still used


def iter_source_trees(
    repo: Path, deadline: float, skipped: list[dict[str, str]]
) -> Iterator[SourceTree]:
    """Parse every non-test source file; problems are appended to `skipped`."""
    for rel_path in discover_source_files(repo):
        if time.monotonic() > deadline:
            raise CollectorTimeout(f"timed out after reading files up to {rel_path}")
        if is_test_path(rel_path):
            continue
        detected = language_for(rel_path)
        if detected is None:
            continue
        language, grammar = detected
        path = repo / rel_path
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append({"path": rel_path, "reason": "too large"})
                continue
            source = path.read_bytes()
        except OSError as exc:
            skipped.append({"path": rel_path, "reason": f"unreadable: {exc.strerror or exc}"})
            continue
        tree = Parser(grammar_language(grammar)).parse(source)
        yield SourceTree(rel_path, language, source, tree.root_node, tree.root_node.has_error)


def node_text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def line_of(node: Node) -> int:
    return node.start_point.row + 1


def _snippet(node: Node) -> str:
    return node_text(node).splitlines()[0].strip()[:MAX_SNIPPET_CHARS] if node.text else ""


_PY_FUNCTIONS = frozenset({"function_definition", "lambda"})
_JS_FUNCTIONS = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)


def _inside_try_body(node: Node, functions: frozenset[str]) -> bool:
    """Lexically inside a try body (not its handlers/finally) of the same function."""
    child, parent = node, node.parent
    while parent is not None:
        if parent.type in functions:
            return False
        if parent.type == "try_statement" and parent.child_by_field_name("body") == child:
            return True
        child, parent = parent, parent.parent
    return False


# ----------------------------------------------------------------------------- Python

_PY_BROAD = frozenset({"Exception", "BaseException"})
# Exceptions that signal an expected condition (EAFP); ignoring them isn't swallowing.
_PY_EXPECTED = frozenset(
    {
        "KeyError",
        "IndexError",
        "LookupError",
        "AttributeError",
        "StopIteration",
        "StopAsyncIteration",
        "ImportError",
        "ModuleNotFoundError",
        "FileNotFoundError",
        "FileExistsError",
        "NotADirectoryError",
        "IsADirectoryError",
        "ProcessLookupError",
    }
)
_PY_LOG_OBJECTS = frozenset({"logger", "logging", "log", "_logger", "_log", "LOGGER", "LOG"})
_PY_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
# Reporting calls that aren't a logger but still surface the error.
_PY_REPORT_CALLS = frozenset(
    {
        "warnings.warn",
        "traceback.print_exc",
        "traceback.print_exception",
        "sentry_sdk.capture_exception",
        "capture_exception",
    }
)
_PY_HTTP_VERBS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
)
_PY_IO_EXACT = frozenset(
    {"open", "io.open", "urlopen", "urllib.request.urlopen", "aiohttp.request"}
)
_PY_IO_MODULE_FUNCTIONS: dict[str, frozenset[str]] = {
    "requests": _PY_HTTP_VERBS,
    "httpx": _PY_HTTP_VERBS,
    "aiohttp": _PY_HTTP_VERBS,
    "socket": frozenset(
        {
            "create_connection",
            "create_server",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostbyaddr",
        }
    ),
    "subprocess": frozenset(
        {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
    ),
    "os": frozenset(
        {
            "remove",
            "unlink",
            "rename",
            "replace",
            "rmdir",
            "removedirs",
            "mkdir",
            "makedirs",
            "listdir",
            "scandir",
            "open",
            "system",
            "popen",
            "chmod",
            "chown",
            "symlink",
            "link",
        }
    ),
    "shutil": frozenset({"copy", "copy2", "copyfile", "copytree", "move", "rmtree"}),
}
_PY_IO_METHODS = frozenset(
    {"execute", "executemany", "read_text", "write_text", "read_bytes", "write_bytes"}
)


def python_io_call(call: Node) -> bool:
    function = call.child_by_field_name("function")
    if function is None:
        return False
    name = node_text(function)
    if name in _PY_IO_EXACT:
        return True
    if function.type != "attribute":
        return False
    method = node_text(function.child_by_field_name("attribute"))
    if method in _PY_IO_METHODS:
        return True
    module = node_text(function.child_by_field_name("object"))
    return method in _PY_IO_MODULE_FUNCTIONS.get(module, frozenset())


def _py_is_log_call(call: Node) -> bool:
    function = call.child_by_field_name("function")
    name = node_text(function)
    if name in _PY_REPORT_CALLS:
        return True
    if function is None or function.type != "attribute":
        return False
    method = node_text(function.child_by_field_name("attribute"))
    owner = node_text(function.child_by_field_name("object")).rsplit(".", 1)[-1]
    is_logger = owner in _PY_LOG_OBJECTS or owner.lower().endswith("logger")
    return is_logger and method in _PY_LOG_METHODS


def _py_handler_parts(clause: Node) -> tuple[list[str], str | None, Node | None]:
    """(caught type names, bound name, body) of an except clause; no types = bare."""
    body = next((c for c in clause.named_children if c.type == "block"), None)
    types: list[str] = []
    alias: str | None = None
    for child in clause.named_children:
        if child.type in {"block", "comment"}:
            continue
        type_node: Node | None = child
        if child.type == "as_pattern":
            target = child.child_by_field_name("alias")
            alias = node_text(target) or None
            type_node = child.named_children[0] if child.named_children else None
        if type_node is None:
            continue
        elements = type_node.named_children if type_node.type == "tuple" else [type_node]
        types.extend(node_text(e).rsplit(".", 1)[-1] for e in elements)
    return types, alias, body


def _own_nodes(body: Node) -> Iterator[Node]:
    """Nodes of a block, not descending into nested function or class definitions."""
    stack = list(reversed(body.children))
    while stack:
        current = stack.pop()
        yield current
        if current.type not in {"function_definition", "class_definition", "lambda"}:
            stack.extend(reversed(current.children))


def _py_trivial_body(body: Node) -> bool:
    statements = [c for c in body.named_children if c.type != "comment"]
    return all(
        s.type == "pass_statement"
        or (
            s.type == "expression_statement"
            and len(s.named_children) == 1
            and s.named_children[0].type == "ellipsis"
        )
        for s in statements
    )


@dataclass
class Collected:
    findings: list[dict[str, Any]]
    handlers: int = 0
    io_sites: int = 0
    io_wrapped: int = 0
    promise_sites: int = 0

    def add(self, rule: str, path: str, node: Node, end: Node | None = None) -> None:
        self.findings.append(
            {
                "rule": rule,
                "path": path,
                "line": line_of(node),
                "end_line": (end or node).end_point.row + 1,
                "snippet": _snippet(node),
            }
        )


def _collect_python(tree: SourceTree, out: Collected, unwrapped: list[str]) -> None:
    for node in _walk(tree.root):
        if node.type == "except_clause":
            _python_handler(node, tree.path, out)
        elif node.type == "call" and python_io_call(node):
            out.io_sites += 1
            if _inside_try_body(node, _PY_FUNCTIONS):
                out.io_wrapped += 1
            else:
                unwrapped.append(f"{tree.path}:{line_of(node)}")


def _python_handler(clause: Node, path: str, out: Collected) -> None:
    out.handlers += 1
    types, alias, body = _py_handler_parts(clause)
    bare = not types
    broad = bare or any(t in _PY_BROAD for t in types)
    if bare:
        out.add("bare-except", path, clause)
    elif broad and body is not None and _py_trivial_body(body):
        out.add("swallowed-broad-except", path, clause)
    elif body is not None and not all(t in _PY_EXPECTED for t in types):
        handled = False
        for node in _own_nodes(body):
            if node.type == "raise_statement":
                handled = True
            elif node.type == "call" and _py_is_log_call(node):
                handled = True
            elif alias and node.type == "identifier" and node_text(node) == alias:
                handled = True
            if handled:
                break
        if not handled:
            out.add("exception-ignored", path, clause)

    try_statement = clause.parent
    try_body = try_statement.child_by_field_name("body") if try_statement else None
    if broad and try_body is not None:
        span = try_body.end_point.row - try_body.start_point.row + 1
        if span > LARGE_TRY_LINES:
            out.add("broad-except-large-block", path, clause)


# ----------------------------------------------------------------------------- JS / TS

_JS_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
_JS_IO_EXACT = frozenset(
    {
        "fetch",
        "window.fetch",
        "globalThis.fetch",
        "axios",
        "http.request",
        "http.get",
        "https.request",
        "https.get",
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "spawn",
        "spawnSync",
    }
)
_JS_IO_OBJECTS = frozenset(
    {"fs", "fsp", "fsPromises", "fs.promises", "child_process", "childProcess"}
)
_JS_IO_METHODS = frozenset({"query"})


def js_io_call(call: Node) -> bool:
    function = call.child_by_field_name("function")
    if function is None:
        return False
    name = node_text(function)
    if name in _JS_IO_EXACT:
        return True
    if function.type != "member_expression":
        return False
    owner = node_text(function.child_by_field_name("object"))
    method = node_text(function.child_by_field_name("property"))
    if owner == "axios":
        return method in _JS_HTTP_VERBS
    return owner in _JS_IO_OBJECTS or method in _JS_IO_METHODS


def _js_new_io(node: Node) -> bool:
    return node_text(node.child_by_field_name("constructor")) == "XMLHttpRequest"


def _argument_count(call: Node) -> int:
    arguments = call.child_by_field_name("arguments")
    return len([a for a in arguments.named_children if a.type != "comment"]) if arguments else 0


def _chain_methods_above(call: Node) -> list[tuple[str, int]]:
    """(method, argument count) of the calls chained onto `call`: x().then(a).catch(b)."""
    methods: list[tuple[str, int]] = []
    current = call
    while True:
        member = current.parent
        if member is None or member.type != "member_expression":
            return methods
        if member.child_by_field_name("object") != current:
            return methods
        outer = member.parent
        if outer is None or outer.type != "call_expression":
            return methods
        if outer.child_by_field_name("function") != member:
            return methods
        methods.append((node_text(member.child_by_field_name("property")), _argument_count(outer)))
        current = outer


def _chain_methods_below(call: Node) -> list[tuple[str, int]]:
    """(method, argument count) of every call in the chain ending at `call`."""
    methods: list[tuple[str, int]] = []
    current: Node | None = call
    while current is not None and current.type == "call_expression":
        function = current.child_by_field_name("function")
        if function is None or function.type != "member_expression":
            break
        property_name = node_text(function.child_by_field_name("property"))
        methods.append((property_name, _argument_count(current)))
        current = function.child_by_field_name("object")
    return methods


def _chain_calls_below(call: Node) -> list[Node]:
    calls: list[Node] = []
    current: Node | None = call
    while current is not None and current.type == "call_expression":
        calls.append(current)
        function = current.child_by_field_name("function")
        if function is None or function.type != "member_expression":
            break
        current = function.child_by_field_name("object")
    return calls


def _handles_rejection(methods: list[tuple[str, int]]) -> bool:
    return any(m == "catch" or (m == "then" and n >= 2) for m, n in methods)


def _enclosing_function(node: Node) -> Node | None:
    parent = node.parent
    while parent is not None:
        if parent.type in _JS_FUNCTIONS:
            return parent
        parent = parent.parent
    return None


def _is_async(function: Node) -> bool:
    return any(not c.is_named and c.type == "async" for c in function.children)


def _unwrap(node: Node | None) -> Node | None:
    while node is not None and node.type == "parenthesized_expression":
        node = node.named_children[0] if node.named_children else None
    return node


def _collect_js(tree: SourceTree, out: Collected, unwrapped: list[str]) -> None:
    for node in _walk(tree.root):
        kind = node.type
        if kind == "catch_clause":
            _js_handler(node, tree.path, out)
        elif kind == "call_expression" and js_io_call(node):
            out.io_sites += 1
            if _inside_try_body(node, _JS_FUNCTIONS) or _handles_rejection(
                _chain_methods_above(node)
            ):
                out.io_wrapped += 1
            else:
                unwrapped.append(f"{tree.path}:{line_of(node)}")
        elif kind == "new_expression" and _js_new_io(node):
            out.io_sites += 1
            if _inside_try_body(node, _JS_FUNCTIONS):
                out.io_wrapped += 1
            else:
                unwrapped.append(f"{tree.path}:{line_of(node)}")
        elif kind == "expression_statement":
            expression = _unwrap(node.named_children[0] if node.named_children else None)
            if expression is None or expression.type != "call_expression":
                continue
            methods = _chain_methods_below(expression)
            if any(m == "then" for m, _ in methods):
                out.promise_sites += 1
                if not _handles_rejection(methods):
                    out.add("unhandled-promise", tree.path, node)
        elif kind == "await_expression":
            _js_await(node, tree.path, out)


def _js_await(node: Node, path: str, out: Collected) -> None:
    argument = _unwrap(node.named_children[0] if node.named_children else None)
    if argument is None or argument.type != "call_expression":
        return
    calls = _chain_calls_below(argument)
    if not any(js_io_call(c) for c in calls):
        return
    function = _enclosing_function(node)
    if function is None or not _is_async(function):
        return
    out.promise_sites += 1
    if _inside_try_body(node, _JS_FUNCTIONS) or _handles_rejection(_chain_methods_below(argument)):
        return
    out.add("await-io-outside-try", path, node)


def _js_handler(clause: Node, path: str, out: Collected) -> None:
    out.handlers += 1
    body = clause.child_by_field_name("body")
    if body is None:
        return
    statements = [c for c in body.named_children if c.type != "comment"]
    if not statements:
        out.add("empty-catch", path, clause)
        return

    def console_call(statement: Node) -> bool:
        if statement.type != "expression_statement" or not statement.named_children:
            return False
        call = _unwrap(statement.named_children[0])
        if call is None or call.type != "call_expression":
            return False
        function = call.child_by_field_name("function")
        return (
            function is not None
            and function.type == "member_expression"
            and node_text(function.child_by_field_name("object")) == "console"
        )

    if all(console_call(s) for s in statements):
        out.add("catch-only-logs-to-console", path, clause)


# ----------------------------------------------------------------------------- collector


def collect(repo: Path, deadline: float, **_: Any) -> dict[str, Any]:
    """Run every rule over the repository. JSON-serialisable; runs in the child process."""
    out = Collected(findings=[])
    unwrapped: list[str] = []
    skipped: list[dict[str, str]] = []
    languages: Counter[str] = Counter()
    partial: list[str] = []
    for tree in iter_source_trees(repo, deadline, skipped):
        languages[tree.language] += 1
        if tree.partial:
            partial.append(tree.path)
        if tree.language == "python":
            _collect_python(tree, out, unwrapped)
        else:
            _collect_js(tree, out, unwrapped)
    out.findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    return {
        "files_parsed": sum(languages.values()),
        "languages": dict(sorted(languages.items())),
        "files_skipped": skipped,
        "files_partial": partial,
        "handlers": out.handlers,
        "io_sites": out.io_sites,
        "io_wrapped": out.io_wrapped,
        "promise_sites": out.promise_sites,
        "unwrapped_io_examples": unwrapped[:MAX_EXAMPLES],
        "findings": out.findings,
    }


def build_report(collected: dict[str, Any]) -> SignalReport:
    """Turn the collector output into the signal report (pure)."""
    if not collected.get("files_parsed"):
        return not_applicable(
            ANALYZER_NAME, "no non-test Python, JavaScript or TypeScript source files"
        )
    counts = Counter(f["rule"] for f in collected["findings"])
    handlers = collected["handlers"]
    io_sites = collected["io_sites"]
    promise_sites = collected["promise_sites"]
    swallowed = sum(counts[r] for r in SWALLOW_RULES)
    unhandled = sum(counts[r] for r in PROMISE_RULES)
    components: dict[str, float | None] = {
        "swallow_rate": 1 - swallowed / max(1, handlers) if handlers else None,
        "io_wrapped_ratio": collected["io_wrapped"] / io_sites if io_sites else None,
        "promise_handling": (1 - unhandled / max(1, promise_sites) if promise_sites else None),
    }
    reason = None
    if all(v is None for v in components.values()):
        reason = "no exception handlers, I/O calls or promise chains found"
    return SignalReport(
        name=ANALYZER_NAME,
        applicable=True,
        score=mean_score(components),
        components=components,
        metrics={
            "rule_counts": {rule: counts[rule] for rule in RULES},
            "handlers": handlers,
            "swallowed_handlers": swallowed,
            "io_sites": io_sites,
            "io_wrapped": collected["io_wrapped"],
            "promise_sites": promise_sites,
            "unhandled_promises": unhandled,
            "files_parsed": collected["files_parsed"],
            "languages": collected["languages"],
            "files_skipped": len(collected["files_skipped"]),
            "files_partial": len(collected["files_partial"]),
            "unwrapped_io_examples": collected["unwrapped_io_examples"],
        },
        reason=reason,
    )


class ErrorHandlingAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Error handling"
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
        raw_output = json.dumps(collected)
        findings = self.parse(raw_output)
        warnings: list[str] = []
        if collected["files_skipped"]:
            warnings.append(
                f"{len(collected['files_skipped'])} file(s) were not analysed for error handling"
                " (too large or unreadable)."
            )
        if collected["files_partial"]:
            warnings.append(
                f"{len(collected['files_partial'])} file(s) only partially parsed; error-handling"
                " detection in them may be incomplete."
            )
        if len(findings) < len(collected["findings"]):
            warnings.append(
                f"Only the first {MAX_FINDINGS_PER_RULE} error-handling findings per rule are"
                " reported; the signal counts all of them."
            )
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=findings,
            raw_output=raw_output,
            duration_ms=int((time.monotonic() - started) * 1000),
            warnings=tuple(warnings),
            artifact=build_report(collected),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        try:
            items = json.loads(raw_output)["findings"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AnalyzerOutputError("Error-handling analysis produced invalid output.") from exc
        per_rule: Counter[str] = Counter()
        findings: list[FindingData] = []
        for item in items:
            rule = item["rule"]
            if rule not in RULES:
                continue
            per_rule[rule] += 1
            if per_rule[rule] > MAX_FINDINGS_PER_RULE:
                continue
            severity, message = RULES[rule]
            findings.append(
                FindingData(
                    analyzer=self.name,
                    rule_id=f"error_handling/{rule}",
                    severity=severity,
                    file_path=item["path"],
                    start_line=item["line"],
                    end_line=item["end_line"],
                    message=message,
                    code_snippet=item.get("snippet") or None,
                    # Never merged with other analyzers' findings (dedup.py).
                    category=f"error_handling:{rule}:{item['path']}:{item['line']}",
                    raw=item,
                )
            )
        return findings

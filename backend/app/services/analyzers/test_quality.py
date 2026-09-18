"""Test quality signal: how much test code there is and whether the tests check anything.

The source tree is parsed with tree-sitter in a child process (`run_collector`), never
executed; tests are NOT run. Measured for Python, JavaScript and TypeScript:

Test files: paths matching `rubric.is_test_path`. Test LOC / source LOC = non-blank
lines of test files / non-blank lines of the other source files.

Test functions:
    Python  functions named `test*` at module level, and methods named `test*` in
            classes named `Test*` or subclassing `*TestCase` (pytest's default
            collection rules, plus unittest).
    JS/TS   each call of `it`, `test` (also `.only`, `.concurrent`) or `it.each(...)` /
            `test.each(...)` whose arguments include a function.

Assertions counted inside a test function:
    Python  `assert` statements; `self.assert*(...)` / `self.fail(...)`; `pytest.raises`,
            `pytest.warns`, `pytest.fail`, `pytest.deprecated_call`; any `.assert_*()`
            method call (unittest.mock `assert_called_once_with`...). `pytest.approx` is
            only meaningful inside an `assert`, which is already counted.
    JS/TS   `expect(...)` calls (a whole `expect(x).toBe(y)` chain counts once, including
            `toMatchSnapshot`), `expect.assertions`/`expect.hasAssertions`, `assert(...)`,
            `assert.*(...)`, `.should` chains and supertest-style `.expect(...)` calls.
    Both    heuristic: a call to a helper whose name starts with `assert`, `check_`/`check`
            + uppercase, `verify` or `expect` (e.g. `assert_valid(x)`, `expectOk(res)`)
            counts as one assertion (the helper presumably asserts).
A test function with zero assertions is reported as an INFO finding.

Test type, per test file with tests: e2e if it imports playwright/selenium/cypress/
puppeteer or its path contains "e2e"; integration if it imports an HTTP client or
test client (requests, httpx, TestClient, supertest...) or a database driver/fixture
(sqlalchemy, psycopg, sqlite3, pymongo, pg, prisma, testcontainers...) or its path
contains "integration" (fetch mocks such as msw or jest-fetch-mock don't count);
otherwise unit.

Coverage: read from a report committed to the repository (Cobertura coverage.xml,
lcov.info, istanbul coverage-summary.json / coverage-final.json); `.coverage` is a
SQLite database and is skipped. Reports in the same directory describe the same run,
so one per directory is used (summary > lcov > final > Cobertura); reports in
different directories are summed by lines.

Components (1 = best):
    test_presence      min(1, test_loc / (0.3 * source_loc)): a test suite about a third
                       the size of the code under test is treated as complete.
    assertion_density  min(1, mean assertions per test / 2)
    assertion_free     1 - assertion-free tests / tests
    type_mix           1 if at least two of unit/integration/e2e are present, else 0.5
    coverage           line coverage from a committed report, or None
    score = mean of the available components.
Without any test function: score 0, test_presence 0, the other components None (a
codebase without tests is a finding). Without any source code: not applicable.
"""

import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tree_sitter import Node, Parser

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.isolated_signal import CollectorTimeout, run_collector
from app.services.analyzers.sandbox import AnalyzerOutputError
from app.services.analyzers.signals import SignalReport, clamp01, mean_score, not_applicable
from app.services.graph.parser import (
    IGNORED_DIRS,
    MAX_FILE_BYTES,
    ParsedModule,
    _extract_js,
    _extract_python,
    _walk,
    discover_source_files,
    grammar_language,
    language_for,
)
from app.services.scoring.rubric import is_test_path

ANALYZER_NAME = "test_quality"
COLLECTOR = "app.services.analyzers.test_quality:collect"
RULE_ID = "assertion-free-test"
TARGET_TEST_RATIO = 0.3
TARGET_ASSERTIONS = 2.0
MAX_TESTS_REPORTED = 5000
MAX_FLAGGED_IN_METRICS = 50
MAX_COVERAGE_BYTES = 20 * 1024 * 1024
COVERAGE_SEARCH_DEPTH = 4
COVERAGE_UNAVAILABLE = "unavailable (no coverage report in the repository)"

# ----------------------------------------------------------------------------- patterns

_PY_HELPER = re.compile(r"^(assert\w*|check_\w+|verify\w*|expect\w*)$")
_PY_HELPER_EXCLUDED = frozenset({"check_output", "check_call"})  # subprocess
_PY_PYTEST_ASSERTIONS = frozenset(
    {"pytest.raises", "pytest.warns", "pytest.fail", "pytest.deprecated_call"}
)
_JS_HELPER = re.compile(r"^(assert\w*|check[A-Z_]\w*|verify\w*|expect\w+)$")
_JS_EXPECT = frozenset({"expect", "expect.assertions", "expect.hasAssertions", "expect.soft"})
_JS_TEST_CALLS = frozenset(
    {"it", "test", "it.only", "test.only", "it.concurrent", "test.concurrent"}
)
_JS_EACH_CALLS = frozenset({"it.each", "test.each", "it.only.each", "test.only.each"})
_FUNCTION_NODES = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function"}
)

E2E_PACKAGES = frozenset(
    {"playwright", "@playwright/test", "selenium", "cypress", "puppeteer", "pyppeteer"}
)
INTEGRATION_PACKAGES = frozenset(
    {
        # HTTP / test clients
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "fastapi.testclient",
        "starlette.testclient",
        "supertest",
        "axios",
        "node-fetch",
        "undici",
        "got",
        # databases, drivers, containers
        "sqlalchemy",
        "psycopg",
        "psycopg2",
        "asyncpg",
        "sqlite3",
        "pymongo",
        "motor",
        "redis",
        "testcontainers",
        "pg",
        "mysql",
        "mysql2",
        "mongodb",
        "mongoose",
        "prisma",
        "@prisma/client",
        "knex",
        "typeorm",
        "sequelize",
        "ioredis",
    }
)
INTEGRATION_NAMES = frozenset({"TestClient"})

# ----------------------------------------------------------------------------- helpers


def _text(node: Node | None) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def _loc(source: bytes) -> int:
    return sum(1 for line in source.splitlines() if line.strip())


# ----------------------------------------------------------------------------- Python


def _py_callee_name(function: Node) -> tuple[str, str | None]:
    """(last name, object text) of a call's function: `self.assertEqual` -> (assertEqual, self)."""
    if function.type == "identifier":
        return _text(function), None
    if function.type == "attribute":
        return _text(function.child_by_field_name("attribute")), _text(
            function.child_by_field_name("object")
        )
    return "", None


def _count_assertions(body: Node, is_assertion: Callable[[Node], bool]) -> int:
    """Assertions under `body`; nothing inside an assertion is counted again
    (`assert check_x(y)` and `expect(a).toBe(b).expect(...)` count once)."""
    count = 0
    stack = [body]
    while stack:
        node = stack.pop()
        if is_assertion(node):
            count += 1
            continue
        stack.extend(reversed(node.children))
    return count


def _is_python_assertion(node: Node) -> bool:
    if node.type == "assert_statement":
        return True
    if node.type != "call":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    name, obj = _py_callee_name(function)
    if _text(function) in _PY_PYTEST_ASSERTIONS:
        return True
    if obj == "self":
        return name.startswith("assert") or name == "fail"  # unittest, or a class helper
    if obj is not None:
        return name.startswith("assert_")  # unittest.mock: m.assert_called_once_with(...)
    return bool(_PY_HELPER.match(name)) and name not in _PY_HELPER_EXCLUDED  # helper heuristic


def count_python_assertions(body: Node) -> int:
    return _count_assertions(body, _is_python_assertion)


def _py_definition(node: Node) -> Node | None:
    if node.type == "decorated_definition":
        return node.child_by_field_name("definition")
    return node


def _py_is_test_class(cls: Node) -> bool:
    name = _text(cls.child_by_field_name("name"))
    bases = _text(cls.child_by_field_name("superclasses"))
    return name.startswith("Test") or bool(re.search(r"TestCase\b", bases))


def python_tests(root: Node) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []

    def add(function: Node, prefix: str) -> None:
        name = _text(function.child_by_field_name("name"))
        body = function.child_by_field_name("body")
        if not name.startswith("test") or body is None:
            return
        tests.append(
            {
                "name": f"{prefix}{name}",
                "line": function.start_point.row + 1,
                "end_line": function.end_point.row + 1,
                "assertions": count_python_assertions(body),
            }
        )

    for child in root.named_children:
        definition = _py_definition(child)
        if definition is None:
            continue
        if definition.type == "function_definition":
            add(definition, "")
        elif definition.type == "class_definition" and _py_is_test_class(definition):
            class_name = _text(definition.child_by_field_name("name"))
            body = definition.child_by_field_name("body")
            for member in body.named_children if body is not None else []:
                method = _py_definition(member)
                if method is not None and method.type == "function_definition":
                    add(method, f"{class_name}.")
    return tests


# ----------------------------------------------------------------------------- JS / TS


def _is_js_assertion(node: Node) -> bool:
    if node.type == "member_expression":
        return _text(node.child_by_field_name("property")) == "should"
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    full = _text(function)
    if full in _JS_EXPECT or full == "assert":
        return True
    if function.type == "member_expression":
        obj = function.child_by_field_name("object")
        if obj is not None and obj.type == "identifier" and _text(obj) == "assert":
            return True  # assert.equal(...)
        # supertest: request(app).get("/").expect(200)
        return _text(function.child_by_field_name("property")) == "expect"
    return function.type == "identifier" and bool(_JS_HELPER.match(full))  # helper heuristic


def count_js_assertions(body: Node) -> int:
    return _count_assertions(body, _is_js_assertion)


def _js_test_callee(call: Node) -> str | None:
    """ "it"/"test"/"it.each"... when `call` declares a test, else None."""
    function = call.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "call_expression":  # it.each(table)(name, fn)
        inner = function.child_by_field_name("function")
        name = _text(inner)
        return name if name in _JS_EACH_CALLS else None
    name = _text(function)
    # `it.each(table)` itself is not a test: the outer call carries the test function.
    return name if name in _JS_TEST_CALLS else None


def _js_string(node: Node | None) -> str | None:
    if node is None or node.type not in {"string", "template_string"}:
        return None
    return _text(node)[1:-1]


def javascript_tests(root: Node) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for node in _walk(root):
        if node.type != "call_expression":
            continue
        callee = _js_test_callee(node)
        if callee is None:
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            continue
        args = [a for a in arguments.named_children if a.type != "comment"]
        functions = [a for a in args if a.type in _FUNCTION_NODES]
        if not functions:
            continue
        body = functions[-1].child_by_field_name("body") or functions[-1]
        title = _js_string(args[0]) if args else None
        tests.append(
            {
                "name": title if title is not None else callee,
                "line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
                "assertions": count_js_assertions(body),
            }
        )
    return tests


# ----------------------------------------------------------------------------- test types


def _package_keys(specifier: str) -> set[str]:
    """Names an import can match: every dotted prefix (Python) / the package (JS)."""
    keys = {specifier}
    if specifier.startswith((".", "/")):
        return keys
    if "/" in specifier:
        parts = specifier.split("/")
        keys.add("/".join(parts[:2]) if specifier.startswith("@") else parts[0])
    parts = specifier.split(".")
    keys.update(".".join(parts[: i + 1]) for i in range(len(parts)))
    return keys


def classify_test_file(path: str, module: ParsedModule) -> str:
    lowered = path.lower()
    keys: set[str] = set()
    names: set[str] = set()
    for imp in module.imports:
        keys |= _package_keys(imp.specifier)
        names.update(imp.names)
    if "e2e" in lowered or keys & E2E_PACKAGES:
        return "e2e"
    if "integration" in lowered or keys & INTEGRATION_PACKAGES or names & INTEGRATION_NAMES:
        return "integration"
    return "unit"


# ----------------------------------------------------------------------------- coverage


def _cobertura(text: str) -> tuple[float, int | None, int | None] | None:
    """(rate, covered, valid) from the root <coverage> element (no XML parser needed)."""
    match = re.search(r"<coverage\b[^>]*>", text[:65536])
    if match is None:
        return None
    tag = match.group(0)
    rate = re.search(r'\bline-rate="([0-9.]+)"', tag)
    covered = re.search(r'\blines-covered="(\d+)"', tag)
    valid = re.search(r'\blines-valid="(\d+)"', tag)
    if rate is None:
        return None
    return (
        float(rate.group(1)),
        int(covered.group(1)) if covered else None,
        int(valid.group(1)) if valid else None,
    )


def _lcov(text: str) -> tuple[int, int]:
    hit = sum(int(m) for m in re.findall(r"^LH:(\d+)", text, re.MULTILINE))
    found = sum(int(m) for m in re.findall(r"^LF:(\d+)", text, re.MULTILINE))
    return hit, found


def _istanbul_final(data: dict[str, Any]) -> tuple[int, int]:
    covered = total = 0
    for entry in data.values():
        statements = entry.get("s") if isinstance(entry, dict) else None
        if isinstance(statements, dict):
            total += len(statements)
            covered += sum(1 for hits in statements.values() if isinstance(hits, int) and hits > 0)
    return covered, total


# File name -> (kind, priority within a directory; lower wins).
COVERAGE_FILES = {
    "coverage-summary.json": ("istanbul-summary", 0),
    "lcov.info": ("lcov", 1),
    "coverage-final.json": ("istanbul-final", 2),
    "coverage.xml": ("cobertura", 3),
    "cobertura.xml": ("cobertura", 3),
    "cobertura-coverage.xml": ("cobertura", 3),
    ".coverage": ("coverage-sqlite", 9),
}


def _read_report(path: Path, kind: str) -> dict[str, Any]:
    """{"covered", "total", "pct"} for one report; raises ValueError when unusable."""
    text = path.read_text("utf-8", "replace")
    if kind == "cobertura":
        parsed = _cobertura(text)
        if parsed is None:
            raise ValueError("no <coverage line-rate> element")
        rate, covered, valid = parsed
        return {"covered": covered, "total": valid, "pct": round(rate * 100, 2)}
    if kind == "lcov":
        hit, found = _lcov(text)
    elif kind == "istanbul-summary":
        lines = json.loads(text)["total"]["lines"]
        hit, found = int(lines["covered"]), int(lines["total"])
        return {"covered": hit, "total": found, "pct": float(lines["pct"])}
    else:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not an istanbul coverage map")
        hit, found = _istanbul_final(data)
    if not found:
        raise ValueError("no lines")
    return {"covered": hit, "total": found, "pct": round(100 * hit / found, 2)}


def collect_coverage(repo: Path) -> dict[str, Any]:
    """Coverage reports committed to the repository, and the combined line coverage."""
    candidates: dict[str, tuple[int, str, str]] = {}  # dir -> (priority, rel, kind)
    notes: list[str] = []
    ignored = IGNORED_DIRS - {"coverage"}
    for dirpath, dirnames, filenames in os.walk(repo):
        depth = len(Path(dirpath).relative_to(repo).parts)
        dirnames[:] = (
            []
            if depth >= COVERAGE_SEARCH_DEPTH
            else sorted(d for d in dirnames if d not in ignored)
        )
        for name in sorted(filenames):
            if name not in COVERAGE_FILES:
                continue
            kind, priority = COVERAGE_FILES[name]
            rel = Path(dirpath, name).relative_to(repo).as_posix()
            if kind == "coverage-sqlite":
                notes.append(f"{rel}: coverage.py SQLite data file, not read")
                continue
            directory = Path(rel).parent.as_posix()
            if directory not in candidates or priority < candidates[directory][0]:
                candidates[directory] = (priority, rel, kind)

    reports: list[dict[str, Any]] = []
    for _, rel, kind in sorted(candidates.values(), key=lambda c: c[1]):
        path = repo / rel
        try:
            if path.is_symlink() or path.stat().st_size > MAX_COVERAGE_BYTES:
                notes.append(f"{rel}: skipped (symlink or larger than 20 MB)")
                continue
            reports.append({"path": rel, "kind": kind, **_read_report(path, kind)})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            notes.append(f"{rel}: unreadable ({type(exc).__name__})")

    pct: float | None = None
    if reports:
        if all(r["total"] for r in reports):
            covered = sum(r["covered"] for r in reports)
            total = sum(r["total"] for r in reports)
            pct = round(100 * covered / total, 2) if total else None
        else:
            pct = round(sum(r["pct"] for r in reports) / len(reports), 2)
    return {"reports": reports, "pct": pct, "notes": notes}


_COVERAGE_CONFIG_FILES = (".coveragerc", ".nycrc", ".nycrc.json", ".nycrc.yml", ".c8rc.json")
_COVERAGE_CONFIG_TEXT = {
    "pyproject.toml": re.compile(r"^\[tool\.coverage|--cov\b", re.MULTILINE),
    "setup.cfg": re.compile(r"^\[coverage:|--cov\b", re.MULTILINE),
    "tox.ini": re.compile(r"^\[coverage:|--cov\b", re.MULTILINE),
    "pytest.ini": re.compile(r"--cov\b"),
    "package.json": re.compile(
        r'"(nyc|c8|collectCoverage|coverageThreshold)"|--coverage\b|\bnyc\b|\bc8\b'
    ),
}
_COVERAGE_CONFIG_GLOBS = ("jest.config.*", "vitest.config.*", "vite.config.*")


def coverage_config(repo: Path) -> list[str]:
    """Files (at the root or one level down) that configure coverage measurement."""
    roots = [repo] + sorted(
        p
        for p in repo.iterdir()
        if p.is_dir() and not p.is_symlink() and p.name not in IGNORED_DIRS
    )
    found: list[str] = []
    for base in roots:
        for name in _COVERAGE_CONFIG_FILES:
            if (base / name).is_file():
                found.append((base / name).relative_to(repo).as_posix())
        candidates = [(base / n, p) for n, p in _COVERAGE_CONFIG_TEXT.items()]
        candidates += [
            (path, re.compile(r"\bcoverage\b"))
            for pattern in _COVERAGE_CONFIG_GLOBS
            for path in sorted(base.glob(pattern))
        ]
        for path, regex in candidates:
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024:
                    if regex.search(path.read_text("utf-8", "replace")):
                        found.append(path.relative_to(repo).as_posix())
            except OSError:
                continue
    return found


# ----------------------------------------------------------------------------- collector


def collect(repo: Path, deadline: float) -> dict[str, Any]:
    """Collector run in the child process (see isolated_signal). JSON-serialisable result."""
    source_files = source_loc = test_files = test_loc = 0
    tests: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    warnings: list[str] = []
    for rel in discover_source_files(repo):
        if time.monotonic() > deadline:
            raise CollectorTimeout("test quality collection ran out of time")
        path = repo / rel
        try:
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_bytes()
        except OSError:
            continue
        loc = _loc(source)
        if not is_test_path(rel):
            source_files += 1
            source_loc += loc
            continue
        test_files += 1
        test_loc += loc
        detected = language_for(rel)
        if detected is None:
            continue
        language, grammar = detected
        try:
            root = Parser(grammar_language(grammar)).parse(source).root_node
            module = ParsedModule(path=rel, language=language)
            if language == "python":
                found = python_tests(root)
                _extract_python(root, module)
            else:
                found = javascript_tests(root)
                _extract_js(root, module)
        except Exception as exc:  # a parser bug must only skip this file
            warnings.append(f"{rel}: {type(exc).__name__}")
            continue
        if root.has_error:
            warnings.append(f"{rel}: partial parse")
        if not found:
            continue
        kind = classify_test_file(rel, module)
        files.append(
            {
                "path": rel,
                "language": language,
                "type": kind,
                "tests": len(found),
                "assertions": sum(t["assertions"] for t in found),
            }
        )
        tests.extend({"file": rel, **t} for t in found)

    zero = [t for t in tests if t["assertions"] == 0]
    type_counts = {
        kind: sum(1 for f in files if f["type"] == kind) for kind in ("unit", "integration", "e2e")
    }
    config = coverage_config(repo)
    return {
        "source_files": source_files,
        "source_loc": source_loc,
        "test_files": test_files,
        "test_loc": test_loc,
        "test_functions": len(tests),
        "assertions": sum(t["assertions"] for t in tests),
        "tests": tests[:MAX_TESTS_REPORTED],
        "tests_truncated": len(tests) > MAX_TESTS_REPORTED,
        "zero_assertion_tests": zero,
        "files": files,
        "type_counts": type_counts,
        "coverage": collect_coverage(repo),
        "coverage_configured": bool(config),
        "coverage_config": config,
        "warnings": warnings,
    }


# ----------------------------------------------------------------------------- scoring


def build_report(data: dict[str, Any]) -> SignalReport:
    """Turn the collector output into the SignalReport (pure)."""
    source_loc, test_loc = int(data["source_loc"]), int(data["test_loc"])
    tests, zero = int(data["test_functions"]), len(data["zero_assertion_tests"])
    if data["source_files"] + data["test_files"] == 0:
        return not_applicable(ANALYZER_NAME, "no Python, JavaScript or TypeScript source code")

    coverage = data["coverage"]
    metrics: dict[str, Any] = {
        "source_files": data["source_files"],
        "source_loc": source_loc,
        "test_files": data["test_files"],
        "test_loc": test_loc,
        "test_to_source_ratio": round(test_loc / source_loc, 4) if source_loc else None,
        "test_functions": tests,
        "assertions": data["assertions"],
        "mean_assertions": round(data["assertions"] / tests, 4) if tests else None,
        "assertion_free_tests": zero,
        "assertion_free_examples": [
            f"{t['file']}:{t['line']} {t['name']}"
            for t in data["zero_assertion_tests"][:MAX_FLAGGED_IN_METRICS]
        ],
        "type_counts": data["type_counts"],
        "coverage_pct": coverage["pct"],
        "coverage_reports": coverage["reports"],
        "coverage_notes": coverage["notes"],
        "coverage_status": "available" if coverage["pct"] is not None else COVERAGE_UNAVAILABLE,
        "coverage_configured": data["coverage_configured"],
        "coverage_config": data["coverage_config"],
        "parse_warnings": data["warnings"][:20],
    }
    if tests == 0:
        components: dict[str, float | None] = {
            "test_presence": 0.0,
            "assertion_density": None,
            "assertion_free": None,
            "type_mix": None,
            "coverage": None,
        }
        return SignalReport(
            name=ANALYZER_NAME,
            applicable=True,
            score=0.0,
            components=components,
            metrics=metrics,
            reason="no tests found",
        )

    present = sum(1 for count in data["type_counts"].values() if count)
    components = {
        "test_presence": (
            clamp01(test_loc / (TARGET_TEST_RATIO * source_loc)) if source_loc else 1.0
        ),
        "assertion_density": clamp01(data["assertions"] / tests / TARGET_ASSERTIONS),
        "assertion_free": 1.0 - zero / tests,
        "type_mix": 1.0 if present >= 2 else 0.5,
        "coverage": None if coverage["pct"] is None else clamp01(coverage["pct"] / 100),
    }
    return SignalReport(
        name=ANALYZER_NAME,
        applicable=True,
        score=mean_score(components),
        components=components,
        metrics=metrics,
    )


class TestQualityAnalyzer(Analyzer):
    """Experimental rubric-1.1 signal: test presence, assertion density, test mix, coverage."""

    __test__ = False  # not a pytest test class despite the name

    name = ANALYZER_NAME
    display_name = "Test quality"
    supported_languages = frozenset({"python", "javascript", "typescript"})
    phase = 1
    experimental = True

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = None  # tree-sitter in a child process of the worker
        self.timeout_seconds = self._settings.experimental_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        data = run_collector(COLLECTOR, repo_path, context.work_dir, self.timeout_seconds)
        report = build_report(data)
        raw_output = json.dumps({"zero_assertion_tests": data["zero_assertion_tests"]})
        warnings: tuple[str, ...] = ()
        if data["warnings"]:
            warnings = (
                f"{len(data['warnings'])} test file(s) only partially parsed; counts may be low.",
            )
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=self.parse(raw_output),
            raw_output=raw_output,
            duration_ms=int((time.monotonic() - started) * 1000),
            warnings=warnings,
            artifact=report,
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        """One INFO finding per assertion-free test function."""
        try:
            tests = json.loads(raw_output)["zero_assertion_tests"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AnalyzerOutputError("Test quality analysis produced invalid output.") from exc
        return [
            FindingData(
                analyzer=self.name,
                rule_id=RULE_ID,
                severity=Severity.INFO,
                file_path=test["file"],
                start_line=test["line"],
                end_line=test["end_line"],
                message=(
                    f"Test `{test['name']}` makes no assertions: it only fails if the code"
                    " raises, so it can pass without checking any behaviour."
                ),
                category=f"{ANALYZER_NAME}:{RULE_ID}:{test['file']}:{test['line']}",
                raw=test,
            )
            for test in tests
        ]

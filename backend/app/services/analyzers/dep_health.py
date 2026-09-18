"""Dependency health (experimental rubric-1.1 signal): supply chain and dependency hygiene.

Phase-2 analyzer: it reads the architecture analyzer's `ArchitectureReport`
(`context.prior_results["architecture"].artifact`) for the resolved imports. Without
it, `unused` and `phantom` are None. It never executes anything from the repository
(package.json scripts, setup.py) and only reads files inside it.

Ecosystems: PyPI and npm.

Manifests (direct dependencies) and how they are classified runtime / dev:
- requirements*.txt / requirements*.in: runtime, or dev when a `-`/`_`/`.` separated
  token of the file name is dev-like (dev, test, tests, testing, lint, docs, doc, ci,
  typing, types). A requirements.txt next to a same-named .in (pip-tools) is treated
  as a lockfile: its pins give versions, its names are not direct dependencies.
- pyproject.toml: [project].dependencies (runtime), [project.optional-dependencies]
  (dev when the group name is dev-like, else runtime), [dependency-groups] (dev),
  [tool.poetry.dependencies] (runtime, `python` skipped), [tool.poetry.dev-dependencies]
  and [tool.poetry.group.<g>.dependencies] (dev, except group "main"),
  [tool.pdm.dev-dependencies] and [tool.uv.dev-dependencies] (dev).
- Pipfile: [packages] runtime, [dev-packages] dev.
- setup.cfg: [options] install_requires / [options.extras_require] runtime,
  tests_require dev.
- setup.py: loose, never executed: string literals inside `install_requires=[...]` /
  `extras_require={...}` (runtime) and `tests_require=[...]` (dev). Requirements held
  in variables or read from files at build time are not followed.
- package.json (any directory): dependencies, peerDependencies, optionalDependencies
  (runtime), devDependencies (dev). Packages of the repository's own workspaces and
  `workspace:`/`file:`/`link:` specs are internal, not dependencies.
Dependencies are deduplicated per ecosystem by name (PyPI: PEP 503 normalised), runtime
winning over dev.

Components (all in [0, 1], 1 = best; the score is their unweighted mean over the
available ones; the rubric splits them into supply chain = direct_count, freshness,
transitive, trivial and hygiene = unused, phantom):

1. direct_count: per ecosystem with a manifest, baseline / max(count, baseline) where
   count = runtime + dev direct dependencies and baseline = settings.dep_health_baseline_
   {pypi,npm}: 1 at or below the baseline, baseline/count above it. Mean over ecosystems.
2. unused: 1 - unused / declared, over all declared direct dependencies. A dependency is
   used when any module imports it: Python import top-level names are mapped to
   distributions like the resolver's `_is_declared` (normalised name, python_<name>,
   py<name>, PYTHON_IMPORT_ALIASES) plus EXTRA_IMPORT_ALIASES (dns -> dnspython, ...) and
   dotted namespace prefixes (`google.cloud.storage` -> google-cloud-storage); npm uses the
   package name of the import (scoped `@a/b`, deep `pkg/sub`), plus imports found by regex
   in .vue/.svelte/.astro/.mdx files and stylesheet `@import`/`@use` of packages. Excluded
   (never "unused"): TOOLING_ALLOW_LIST / RUNTIME_PLUGIN_ALLOW_LIST below, and any name
   appearing as a word in package.json "scripts", [project.scripts]/[project.gui-scripts]/
   [tool.poetry.scripts], Procfile, Dockerfile*, docker-compose*.yml, Makefile, and JS
   tool config files (*.config.{js,cjs,mjs,ts,json}, .eslintrc*, .babelrc*, .prettierrc*).
   None without an architecture report or when nothing is declared.
3. phantom: 1 - phantom_packages / max(1, distinct external packages imported), where
   phantom = an external, non-stdlib/non-builtin import with resolver evidence
   "undeclared" (Python imports that map to a declared distribution through
   EXTRA_IMPORT_ALIASES are not phantom). Only languages with at least one manifest
   count (otherwise the code may be a script collection); None when no language
   qualifies or without an architecture report.
4. freshness: mean over checked direct dependencies of
       1 / (1 + majors_behind) * (1.0 if versions_behind <= 2 else 0.8 if <= 10 else 0.6)
   versions_behind = stable (non-prerelease) registry releases newer than the installed
   version (and not newer than the registry's latest); majors_behind = distinct newer
   major lines, where a major line is the first release component, or (0, minor) for
   0.x versions (semver: 0.x minors are breaking). Stale majors are the main penalty.
   Installed version = lockfile version, else an exact `==` pin, else the minimum of the
   declared range. PyPI versions use `packaging.version` (loose fallback if missing), npm
   a small semver comparator. Calendar-versioned packages count each year as a major.
5. transitive: from lockfiles, T = total transitive packages, D = direct packages found
   in the lockfiles: 1 / (1 + max(0, T - 10*D) / (50 * max(1, D))). Up to 10 transitive
   per direct dependency is free; beyond that it decays smoothly. None without a lockfile.
   Supported: package-lock.json / npm-shrinkwrap.json (v1 nested and v2/v3 "packages",
   Node resolution up the node_modules chain, workspace links followed), yarn.lock v1,
   uv.lock, poetry.lock (count + depth by BFS from the direct deps); Pipfile.lock (count
   only, depth None); pnpm-lock.yaml (packages counted by line scan, depth None).
   Unsupported: yarn berry (v2+) lockfiles, bun.lock(b), pdm.lock, pylock.toml.
   Transitive count per lockfile = distinct name@version packages - direct packages.
6. trivial: 1 - trivial / checked, over direct dependencies with registry size data.
   npm: the latest version's dist.unpackedSize < settings.dep_health_trivial_bytes or
   dist.fileCount <= 2. PyPI: the smallest distribution file of the installed release
   (else the latest) < the threshold. Type-stub packages (@types/*, types-*, *-stubs) are
   not checked. None when nothing could be checked.

Registry: PyPI https://pypi.org/pypi/<name>/json, npm https://registry.npmjs.org/<name>
with the abbreviated `application/vnd.npm.install-v1+json` metadata. A normalised summary
is cached atomically under <scan_workspace_dir>/_registry/<ecosystem>/<name>.json for
dep_health_registry_cache_hours. At most dep_health_max_registry_lookups packages per scan
(runtime dependencies first). If lookups are disabled or a registry is unreachable
(transport error or 5xx; further lookups to it stop), the scan never fails: freshness
and trivial become None (or use what was checked) and the reason is recorded.

Findings: one INFO finding per unused dependency (file = the manifest) and per phantom
package (file = the first importing file).
"""

from __future__ import annotations

import configparser
import fnmatch
import json
import logging
import os
import re
import threading
import time
import tomllib
import uuid
from collections import deque
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.sandbox import AnalyzerOutputError
from app.services.analyzers.signals import SignalReport, clamp01, mean_score
from app.services.graph.resolver import (
    PYTHON_IMPORT_ALIASES,
    ImportStatus,
    RepoIndex,
    ResolvedImport,
    _normalize_dist,
)

logger = logging.getLogger(__name__)

ANALYZER_NAME = "dep_health"
PYPI = "PyPI"
NPM = "npm"
ECOSYSTEMS = (PYPI, NPM)
RUNTIME = "runtime"
DEV = "dev"

PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"
USER_AGENT = "codeaudit-dep-health/1.0"
REGISTRY_WORKERS = 8
MAX_LOCKFILE_BYTES = 30 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LISTED = 200
MAX_TEMPLATE_FILES = 2000

# Legitimately never imported: test runners, linters, formatters, type checkers and
# stubs, docs generators, bundlers/compilers, process managers, build backends.
TOOLING_ALLOW_LIST: tuple[str, ...] = (
    "pytest*",
    "black",
    "ruff",
    "mypy",
    "flake8*",
    "isort",
    "pre-commit",
    "coverage",
    "tox",
    "nox",
    "sphinx*",
    "mkdocs*",
    "types-*",
    "*-stubs",
    "@types/*",
    "typescript",
    "eslint*",
    "prettier*",
    "jest",
    "vitest",
    "webpack*",
    "vite",
    "@vitejs/*",
    "babel*",
    "@babel/*",
    "ts-node",
    "nodemon",
    "husky",
    "lint-staged",
    "gunicorn",
    "uvicorn",
    "setuptools",
    "wheel",
    "pip",
    "build",
    "twine",
    "hatchling",
    "poetry-core",
)
# Loaded by name at runtime (database URLs, server/validator extras), never imported.
RUNTIME_PLUGIN_ALLOW_LIST: tuple[str, ...] = (
    "psycopg2",
    "psycopg2-binary",
    "psycopg",
    "psycopg-binary",
    "asyncpg",
    "pymysql",
    "mysqlclient",
    "aiosqlite",
    "cx-oracle",
    "oracledb",
    "python-multipart",
    "email-validator",
    "uvloop",
    "httptools",
)
STUB_PATTERNS = ("@types/*", "types-*", "*-stubs")
_DEV_TOKENS = frozenset(
    {"dev", "develop", "development", "test", "tests", "testing", "lint", "docs", "doc", "ci"}
    | {"typing", "types"}
)
_NON_REGISTRY_NPM: tuple[str, ...] = (
    "file:",
    "link:",
    "workspace:",
    "git",
    "http:",
    "https:",
    "github:",
    "npm:",
    "portal:",
    "patch:",
)
_TEMPLATE_EXTENSIONS = (".vue", ".svelte", ".astro", ".mdx")
_STYLE_EXTENSIONS = (".css", ".scss", ".sass", ".less")
_TEMPLATE_IMPORT = re.compile(r"""(?:\bfrom|\bimport|\brequire\()\s*['"]([^'"./][^'"]*)['"]""")
_STYLE_IMPORT = re.compile(
    r"""@(?:import|use|forward|plugin)\s+(?:url\()?['"]~?([^'"./][^'"]*)['"]"""
)
# Import name -> distribution, beyond the resolver's PYTHON_IMPORT_ALIASES.
EXTRA_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "dns": ("dnspython",),
    "kafka": ("kafka_python",),
    "fitz": ("pymupdf",),
    "websocket": ("websocket_client",),
    "Xlib": ("python_xlib",),
    "ldap": ("python_ldap",),
    "usb": ("pyusb",),
    "nacl": ("pynacl",),
    "faiss": ("faiss_cpu", "faiss_gpu"),
    "github": ("pygithub",),
    "jose": ("python_jose",),
    "mpl_toolkits": ("matplotlib",),
}
_SCRIPT_FILES = ("Procfile", "Makefile", "makefile", "GNUmakefile")
_CONFIG_FILE = re.compile(
    r"(.+\.config\.(js|cjs|mjs|ts|cts|mts|json)|\.(eslintrc|babelrc|prettierrc).*)"
)


# ----------------------------------------------------------------------------- data


@dataclass
class Dependency:
    """A direct dependency declared in a manifest."""

    name: str  # as written in the (first) manifest
    key: str  # identity: PyPI _normalize_dist(name), npm the package name
    ecosystem: str
    kind: str  # RUNTIME | DEV
    manifest: str
    spec: str | None = None  # version constraint text
    registry: bool = True  # False for URL / path / git / workspace specs


@dataclass
class Lockfile:
    path: str
    format: str
    ecosystem: str
    packages: int | None = None  # distinct name@version (the project itself excluded)
    direct: int | None = None
    transitive: int | None = None
    max_depth: int | None = None
    note: str | None = None
    versions: dict[str, str] = field(default_factory=dict)  # dependency key -> version

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "ecosystem": self.ecosystem,
            "packages": self.packages,
            "direct": self.direct,
            "transitive": self.transitive,
            "max_depth": self.max_depth,
            "note": self.note,
        }


@dataclass
class Manifests:
    files: dict[str, list[str]] = field(default_factory=lambda: {PYPI: [], NPM: []})
    deps: dict[str, dict[str, Dependency]] = field(default_factory=lambda: {PYPI: {}, NPM: {}})
    pins: dict[str, str] = field(default_factory=dict)  # PyPI key -> version (compiled reqs)
    workspace_packages: set[str] = field(default_factory=set)
    corpus: list[tuple[str, str]] = field(default_factory=list)  # (file, text) tool references

    def add(self, dep: Dependency) -> None:
        existing = self.deps[dep.ecosystem].get(dep.key)
        if existing is None:
            self.deps[dep.ecosystem][dep.key] = dep
        elif existing.kind == DEV and dep.kind == RUNTIME:
            existing.kind = RUNTIME
            existing.manifest = dep.manifest
            existing.spec = dep.spec or existing.spec
        elif existing.spec is None and dep.spec:
            existing.spec = dep.spec


@dataclass(frozen=True)
class RegistryInfo:
    """Normalised registry metadata (what is cached)."""

    found: bool
    latest: str | None = None
    versions: tuple[str, ...] = ()
    sizes: Mapping[str, int] = field(default_factory=dict)  # version -> bytes
    file_counts: Mapping[str, int] = field(default_factory=dict)  # npm only


class RegistryUnavailableError(Exception):
    """The registry could not be reached (transport error or server error)."""


def canonical_pypi(name: str) -> str:
    """PEP 503 normalised project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _dependency_key(ecosystem: str, name: str) -> str:
    return _normalize_dist(name) if ecosystem == PYPI else name


def _is_dev_group(name: str) -> bool:
    return any(token in _DEV_TOKENS for token in re.split(r"[-_.\s]+", name.lower()))


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _allow_listed(dep: Dependency) -> bool:
    name = canonical_pypi(dep.name) if dep.ecosystem == PYPI else dep.name.lower()
    return _matches(name, TOOLING_ALLOW_LIST) or _matches(name, RUNTIME_PLUGIN_ALLOW_LIST)


# ----------------------------------------------------------------------------- versions


@dataclass(frozen=True)
class Version:
    text: str
    key: Any  # comparable within one ecosystem
    major_key: tuple[int, ...]
    prerelease: bool


def _major_key(release: tuple[int, ...]) -> tuple[int, ...]:
    major = release[0] if release else 0
    minor = release[1] if len(release) > 1 else 0
    return (major,) if major > 0 else (0, minor)


def _loose_version(text: str) -> Version | None:
    match = re.match(r"^\s*v?(\d+(?:\.\d+)*)(.*)$", text)
    if not match:
        return None
    release = tuple(int(p) for p in match.group(1).split("."))
    rest = match.group(2).lower()
    pre = bool(re.match(r"^[-.]?(a|b|c|rc|alpha|beta|pre|preview|dev)\d*", rest))
    padded = (release + (0, 0, 0, 0))[:4]
    return Version(text, (padded, 0 if pre else 1, rest), _major_key(release), pre)


def parse_pypi_version(text: str) -> Version | None:
    """PEP 440 version via `packaging`, or a loose parse if packaging is unavailable."""
    try:
        from packaging.version import InvalidVersion
        from packaging.version import Version as PackagingVersion
    except ImportError:  # pragma: no cover - packaging ships with pip/pytest
        return _loose_version(text)
    try:
        version = PackagingVersion(text)
    except InvalidVersion:
        return None
    return Version(
        text, version, _major_key(version.release), version.is_prerelease or version.is_devrelease
    )


_SEMVER = re.compile(
    r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


def parse_npm_version(text: str) -> Version | None:
    """Semver 2.0 ordering: prereleases sort before their release, identifiers compared
    numerically when numeric."""
    match = _SEMVER.match(text)
    if not match:
        return None
    release = tuple(int(match.group(i) or 0) for i in (1, 2, 3))
    pre = match.group(4)
    if pre:
        identifiers = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
        key: tuple[Any, ...] = (release, 0, identifiers)
    else:
        key = (release, 1, ())
    return Version(text, key, _major_key(release), bool(pre))


def parse_version(ecosystem: str, text: str) -> Version | None:
    return parse_pypi_version(text) if ecosystem == PYPI else parse_npm_version(text)


def minimum_version(ecosystem: str, spec: str | None) -> tuple[str, bool] | None:
    """(lowest version allowed by `spec`, whether it is an exact pin) or None."""
    if not spec:
        return None
    spec = spec.strip()
    if ecosystem == NPM:
        if spec.startswith(_NON_REGISTRY_NPM) or spec in {"*", "", "latest", "next", "x"}:
            return None
        candidates: list[tuple[str, bool]] = []
        for alternative in spec.split("||"):
            found = _npm_lower_bound(alternative.strip())
            if found:
                candidates.append(found)
        valid: list[tuple[Version, str, bool]] = []
        for text, exact in candidates:
            parsed = parse_npm_version(text)
            if parsed is not None:
                valid.append((parsed, text, exact))
        if not valid:
            return None
        _lowest, text, exact = min(valid, key=lambda item: item[0].key)
        return text, exact and len(valid) == 1
    for clause in spec.split(","):
        clause = clause.strip()
        match = re.match(r"^(===|==|>=|~=|\^|~|>|=)?\s*v?(\d[0-9A-Za-z.!+*-]*)$", clause)
        if not match:
            continue
        operator = match.group(1) or ""
        text = re.sub(r"(\.\*)+$", "", match.group(2))
        exact = operator in {"==", "===", "="} or (not operator and "*" not in match.group(2))
        return text, exact and "*" not in match.group(2)
    return None


def _npm_lower_bound(spec: str) -> tuple[str, bool] | None:
    hyphen = re.match(r"^(\S+)\s+-\s+\S+$", spec)
    if hyphen:
        spec = hyphen.group(1)
    for part in spec.split():
        match = re.match(
            r"^(\^|~|>=|>|=)?\s*v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[\w.-]+)?$", part
        )
        if not match:
            continue
        numbers = [g if g and g.isdigit() else "0" for g in match.group(2, 3, 4)]
        if not match.group(2).isdigit():
            return None
        text = ".".join(numbers) + (match.group(5) or "")
        exact = not match.group(1) or match.group(1) == "="
        exact = exact and all(g and g.isdigit() for g in match.group(2, 3, 4))
        return text, exact
    return None


# ----------------------------------------------------------------------------- manifests


def _requirement(line: str) -> tuple[str, str, bool] | None:
    """(name, version spec, installable from the registry) of a PEP 508 requirement."""
    line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if not line or line.startswith(("#", "-")):
        return None
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
    if not match:
        return None
    rest = match.group(3).split(";", 1)[0].strip()
    if rest.startswith("@"):
        return match.group(1), "", False
    rest = rest.strip("()").strip()
    return match.group(1), rest, True


def _poetry_spec(value: Any) -> tuple[str | None, bool]:
    if isinstance(value, str):
        return value, True
    if isinstance(value, dict):
        if any(k in value for k in ("git", "path", "url", "file")):
            return None, False
        version = value.get("version")
        return (version if isinstance(version, str) else None), True
    if isinstance(value, list) and value:  # multiple-constraint dependency
        return _poetry_spec(value[0])
    return None, True


def _string_literals(text: str) -> list[str]:
    return [a or b for a, b in re.findall(r"'([^'\n]*)'|\"([^\"\n]*)\"", text)]


def _bracketed(text: str, keyword: str, opener: str, closer: str) -> list[str]:
    """Bodies of `keyword = <opener> ... <closer>` (balanced) in setup.py source."""
    bodies: list[str] = []
    for match in re.finditer(rf"\b{keyword}\s*=\s*\{opener}", text):
        depth, start = 0, match.end() - 1
        for i in range(start, min(len(text), start + 50_000)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    bodies.append(text[start + 1 : i])
                    break
    return bodies


class ManifestReader:
    """Collect direct dependencies and tool-reference text from every manifest."""

    def __init__(self, index: RepoIndex) -> None:
        self.index = index
        self.result = Manifests()

    def read(self) -> Manifests:
        files = sorted(self.index.files, key=lambda f: (f.count("/"), f))
        package_jsons = [f for f in files if PurePosixPath(f).name == "package.json"]
        for rel in package_jsons:
            data = self._json(rel)
            if isinstance(data, dict) and isinstance(data.get("name"), str):
                self.result.workspace_packages.add(data["name"])
        for rel in files:
            name = PurePosixPath(rel).name
            if name.startswith("requirements") and name.endswith((".txt", ".in")):
                self._requirements(rel, name)
            elif name == "pyproject.toml":
                self._pyproject(rel)
            elif name == "Pipfile":
                self._pipfile(rel)
            elif name == "setup.cfg":
                self._setup_cfg(rel)
            elif name == "setup.py":
                self._setup_py(rel)
            elif name == "package.json":
                self._package_json(rel)
            if (
                name in _SCRIPT_FILES
                or name.startswith("Dockerfile")
                or name.endswith(".dockerfile")
                or re.fullmatch(r"docker-compose.*\.ya?ml|compose\.ya?ml", name)
                or _CONFIG_FILE.fullmatch(name)
            ):
                text = self.index.read_text(rel, MAX_MANIFEST_BYTES)
                if text:
                    self.result.corpus.append((rel, text))
        return self.result

    def _json(self, rel: str) -> Any:
        text = self.index.read_text(rel, MAX_MANIFEST_BYTES)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _toml(self, rel: str) -> dict[str, Any] | None:
        text = self.index.read_text(rel, MAX_MANIFEST_BYTES)
        if text is None:
            return None
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            logger.info("dep_health: could not parse %s", rel)
            return None

    def _add_python(self, rel: str, spec_line: str, kind: str) -> None:
        parsed = _requirement(spec_line)
        if parsed is None:
            return
        name, spec, registry = parsed
        self.result.add(
            Dependency(name, _normalize_dist(name), PYPI, kind, rel, spec or None, registry)
        )

    def _mark(self, ecosystem: str, rel: str) -> None:
        if rel not in self.result.files[ecosystem]:
            self.result.files[ecosystem].append(rel)

    def _requirements(self, rel: str, name: str) -> None:
        text = self.index.read_text(rel, MAX_MANIFEST_BYTES) or ""
        if name.endswith(".txt") and f"{rel[:-4]}.in" in self.index.files:
            # pip-tools output: a lock of the .in file, not a list of direct dependencies.
            for line in text.splitlines():
                parsed = _requirement(line)
                if parsed and (bound := minimum_version(PYPI, parsed[1])) and bound[1]:
                    self.result.pins.setdefault(_normalize_dist(parsed[0]), bound[0])
            return
        self._mark(PYPI, rel)
        stem = name.rsplit(".", 1)[0]
        kind = DEV if _is_dev_group(stem.removeprefix("requirements")) else RUNTIME
        for line in text.replace("\\\n", " ").splitlines():
            self._add_python(rel, line, kind)

    def _pyproject(self, rel: str) -> None:
        data = self._toml(rel)
        if data is None:
            return
        project = data.get("project") or {}
        tool = data.get("tool") or {}
        poetry = tool.get("poetry") or {}
        declares = False
        for spec in project.get("dependencies") or []:
            if isinstance(spec, str):
                declares = True
                self._add_python(rel, spec, RUNTIME)
        for group, specs in (project.get("optional-dependencies") or {}).items():
            for spec in specs or []:
                if isinstance(spec, str):
                    declares = True
                    self._add_python(rel, spec, DEV if _is_dev_group(group) else RUNTIME)
        for group_specs in [
            *(data.get("dependency-groups") or {}).values(),
            *((tool.get("pdm") or {}).get("dev-dependencies") or {}).values(),
            (tool.get("uv") or {}).get("dev-dependencies") or [],
        ]:
            for spec in group_specs or []:
                if isinstance(spec, str):
                    declares = True
                    self._add_python(rel, spec, DEV)
        poetry_tables: list[tuple[dict[str, Any], str]] = [
            (poetry.get("dependencies") or {}, RUNTIME),
            (poetry.get("dev-dependencies") or {}, DEV),
        ]
        for group_name, group in (poetry.get("group") or {}).items():
            if isinstance(group, dict):
                kind = RUNTIME if group_name == "main" else DEV
                poetry_tables.append((group.get("dependencies") or {}, kind))
        for table, kind in poetry_tables:
            for name, value in table.items():
                if name.lower() == "python":
                    continue
                declares = True
                spec, registry = _poetry_spec(value)
                self.result.add(
                    Dependency(name, _normalize_dist(name), PYPI, kind, rel, spec, registry)
                )
        if declares or project or poetry:
            self._mark(PYPI, rel)
        scripts: list[str] = []
        for scripts_table in (
            project.get("scripts"),
            project.get("gui-scripts"),
            poetry.get("scripts"),
        ):
            if isinstance(scripts_table, dict):
                scripts.extend(str(v) for v in scripts_table.values())
        if scripts:
            self.result.corpus.append((rel, "\n".join(scripts)))

    def _pipfile(self, rel: str) -> None:
        data = self._toml(rel)
        if data is None:
            return
        self._mark(PYPI, rel)
        for section, kind in (("packages", RUNTIME), ("dev-packages", DEV)):
            for name, value in (data.get(section) or {}).items():
                spec, registry = _poetry_spec(value)
                spec = None if spec == "*" else spec
                self.result.add(
                    Dependency(name, _normalize_dist(name), PYPI, kind, rel, spec, registry)
                )

    def _setup_cfg(self, rel: str) -> None:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(self.index.read_text(rel, MAX_MANIFEST_BYTES) or "")
        except configparser.Error:
            return
        found = False
        if parser.has_section("options"):
            for option, kind in (("install_requires", RUNTIME), ("tests_require", DEV)):
                for line in parser.get("options", option, fallback="").splitlines():
                    found = True
                    self._add_python(rel, line, kind)
        if parser.has_section("options.extras_require"):
            for _group, value in parser.items("options.extras_require"):
                for line in value.splitlines():
                    found = True
                    self._add_python(rel, line, RUNTIME)
        if found:
            self._mark(PYPI, rel)

    def _setup_py(self, rel: str) -> None:
        text = self.index.read_text(rel, MAX_MANIFEST_BYTES) or ""
        self._mark(PYPI, rel)
        for keyword, opener, closer, kind in (
            ("install_requires", "[", "]", RUNTIME),
            ("extras_require", "{", "}", RUNTIME),
            ("tests_require", "[", "]", DEV),
        ):
            for body in _bracketed(text, keyword, opener, closer):
                for literal in _string_literals(body):
                    if keyword == "extras_require" and re.fullmatch(r"[\w.-]+", literal):
                        # dict keys (extra names) look like bare names; values carry specs
                        # or appear in lists, so only keep names followed by ':' out.
                        if re.search(rf"['\"]{re.escape(literal)}['\"]\s*:", body):
                            continue
                    self._add_python(rel, literal, kind)

    def _package_json(self, rel: str) -> None:
        data = self._json(rel)
        if not isinstance(data, dict):
            return
        self._mark(NPM, rel)
        for section, kind in (
            ("dependencies", RUNTIME),
            ("peerDependencies", RUNTIME),
            ("optionalDependencies", RUNTIME),
            ("devDependencies", DEV),
        ):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                spec_text = spec if isinstance(spec, str) else None
                if name in self.result.workspace_packages or (spec_text or "").startswith(
                    ("workspace:", "file:", "link:", "portal:")
                ):
                    continue
                registry = not (spec_text or "").startswith(_NON_REGISTRY_NPM)
                self.result.add(Dependency(name, name, NPM, kind, rel, spec_text, registry))
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            self.result.corpus.append((rel, "\n".join(str(v) for v in scripts.values())))


# ----------------------------------------------------------------------------- lockfiles


def _bfs_depth(roots: Iterable[str], edges: Mapping[str, Iterable[str]]) -> int:
    """Longest shortest-path distance from the root's direct dependencies (depth 1)."""
    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for root in roots:
        if root not in depth:
            depth[root] = 1
            queue.append(root)
    while queue:
        node = queue.popleft()
        for child in edges.get(node, ()):
            if child not in depth:
                depth[child] = depth[node] + 1
                queue.append(child)
    return max(depth.values(), default=0)


def _dep_names(entry: Mapping[str, Any], *sections: str) -> list[str]:
    names: list[str] = []
    for section in sections:
        deps = entry.get(section)
        if isinstance(deps, dict):
            names.extend(deps)
    return names


_NPM_ROOT_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_NPM_CHILD_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")


def _node_resolve(entries: Mapping[str, Any], from_path: str, name: str) -> str | None:
    """Node's lookup: <from>/node_modules/<name>, then each enclosing node_modules."""
    path = from_path
    while True:
        candidate = f"{path}/node_modules/{name}" if path else f"node_modules/{name}"
        if candidate in entries:
            return candidate
        if not path:
            return None
        index = path.rfind("node_modules/")
        path = "" if index == -1 else path[:index].rstrip("/")


def parse_package_lock(
    data: Mapping[str, Any], root_deps: list[str] | None
) -> tuple[int, int, int, dict[str, str]] | None:
    """(packages, direct, max_depth, hoisted versions) of an npm lockfile (v1, v2, v3)."""
    packages = data.get("packages")
    entries: dict[str, dict[str, Any]] = {}
    root: dict[str, Any] = {}
    if isinstance(packages, dict) and packages:
        root_entry = packages.get("")
        root = root_entry if isinstance(root_entry, dict) else {}
        entries = {k: v for k, v in packages.items() if k and isinstance(v, dict)}
    elif isinstance(data.get("dependencies"), dict):  # lockfileVersion 1: a nested tree

        def walk(tree: Mapping[str, Any], prefix: str) -> None:
            for name, entry in tree.items():
                if not isinstance(entry, dict):
                    continue
                path = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
                entries[path] = {
                    "version": entry.get("version"),
                    "dependencies": entry.get("requires") or {},
                }
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested, path)

        walk(data["dependencies"], "")
    else:
        return None

    def target(path: str | None) -> str | None:
        seen = 0
        while path is not None and entries.get(path, {}).get("link") and seen < 5:
            resolved = entries[path].get("resolved")
            path = resolved if isinstance(resolved, str) and resolved in entries else None
            seen += 1
        return path

    counted = {
        path: entry
        for path, entry in entries.items()
        if "node_modules/" in path and not entry.get("link")
    }

    def identity(path: str) -> tuple[str, str]:
        return path.rsplit("node_modules/", 1)[1], str(counted[path].get("version"))

    names = root_deps if root_deps is not None else _dep_names(root, *_NPM_ROOT_SECTIONS)
    if not names and not root:  # v1 without a package.json: top-level entries
        names = [p.removeprefix("node_modules/") for p in entries if p.count("node_modules/") == 1]
    roots: list[str] = []
    for name in dict.fromkeys(names):
        resolved = target(_node_resolve(entries, "", name))
        if resolved is not None:
            roots.append(resolved)

    edges: dict[str, list[str]] = {}
    for path, entry in entries.items():
        children: list[str] = []
        for name in _dep_names(entry, *_NPM_CHILD_SECTIONS):
            resolved = target(_node_resolve(entries, path, name))
            if resolved is not None:
                children.append(resolved)
        edges[path] = children
    all_packages = {identity(p) for p in counted}
    direct = {identity(p) for p in roots if p in counted}
    versions = {
        p.removeprefix("node_modules/"): str(e.get("version"))
        for p, e in counted.items()
        if p.count("node_modules/") == 1 and e.get("version")
    }
    return len(all_packages), len(direct), _bfs_depth(roots, edges), versions


def _yarn_descriptor_name(descriptor: str) -> tuple[str, str]:
    at = descriptor.rfind("@")
    if at <= 0:
        return descriptor, ""
    return descriptor[:at], descriptor[at + 1 :]


def parse_yarn_v1(
    text: str, root_specs: Mapping[str, str | None]
) -> tuple[int, int, int, dict[str, str]]:
    """(packages, direct, max_depth, versions) of a yarn v1 lockfile."""
    descriptors: dict[str, int] = {}
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_deps = False
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if indent == 0 and line.endswith(":"):
            keys = [k.strip().strip('"') for k in line[:-1].split(",")]
            name = _yarn_descriptor_name(keys[0])[0]
            current = {"name": name, "version": "", "deps": []}
            entries.append(current)
            for key in keys:
                descriptors[key] = len(entries) - 1
            in_deps = False
        elif current is None:
            continue
        elif indent == 2:
            in_deps = line in {"dependencies:", "optionalDependencies:"}
            match = re.match(r'^version\s+"?([^"]+)"?$', line)
            if match:
                current["version"] = match.group(1)
        elif indent >= 4 and in_deps:
            match = re.match(r'^"?([^"\s]+?)"?\s+"?([^"]*)"?$', line)
            if match:
                current["deps"].append((match.group(1), match.group(2)))
    by_name: dict[str, int] = {}
    for position, entry in enumerate(entries):
        by_name.setdefault(entry["name"], position)

    def lookup(name: str, spec: str | None) -> int | None:
        if spec is not None and f"{name}@{spec}" in descriptors:
            return descriptors[f"{name}@{spec}"]
        return by_name.get(name)

    edges: dict[str, list[str]] = {}
    for position, entry in enumerate(entries):
        edges[str(position)] = [
            str(found) for n, s in entry["deps"] if (found := lookup(n, s)) is not None
        ]
    roots = [str(found) for n, s in root_specs.items() if (found := lookup(n, s)) is not None]
    identities = {(e["name"], e["version"]) for e in entries}
    direct = {(entries[int(r)]["name"], entries[int(r)]["version"]) for r in roots}
    versions = {name: entries[pos]["version"] for name, pos in by_name.items()}
    return len(identities), len(direct), _bfs_depth(dict.fromkeys(roots), edges), versions


def parse_uv_lock(
    data: Mapping[str, Any], fallback_roots: Iterable[str]
) -> tuple[int, int, int, dict[str, str]]:
    packages = [p for p in data.get("package") or [] if isinstance(p, dict) and p.get("name")]

    def dep_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [
                _normalize_dist(d["name"]) for d in value if isinstance(d, dict) and d.get("name")
            ]
        if isinstance(value, dict):  # optional-dependencies / dev-dependencies groups
            return [n for group in value.values() for n in dep_list(group)]
        return []

    project_names: set[str] = set()
    edges: dict[str, list[str]] = {}
    root_children: list[str] = []
    versions: dict[str, str] = {}
    identities: set[tuple[str, str]] = set()
    for package in packages:
        name = _normalize_dist(package["name"])
        source = package.get("source") or {}
        children = dep_list(package.get("dependencies"))
        children += dep_list(package.get("optional-dependencies"))
        edges.setdefault(name, []).extend(children)
        if isinstance(source, dict) and ("editable" in source or "virtual" in source):
            project_names.add(name)
            root_children += children + dep_list(package.get("dev-dependencies"))
        else:
            identities.add((name, str(package.get("version"))))
            versions.setdefault(name, str(package.get("version")))
    roots = [r for r in dict.fromkeys(root_children) if r not in project_names]
    if not project_names:
        roots = [r for r in fallback_roots if r in edges]
    direct = {(n, versions[n]) for n in roots if n in versions}
    return len(identities), len(direct), _bfs_depth(roots, edges), versions


def parse_poetry_lock(
    data: Mapping[str, Any], roots: Iterable[str]
) -> tuple[int, int, int, dict[str, str]]:
    edges: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    identities: set[tuple[str, str]] = set()
    for package in data.get("package") or []:
        if not isinstance(package, dict) or not package.get("name"):
            continue
        name = _normalize_dist(package["name"])
        deps = package.get("dependencies") or {}
        edges.setdefault(name, []).extend(_normalize_dist(d) for d in deps)
        identities.add((name, str(package.get("version"))))
        versions.setdefault(name, str(package.get("version")))
    root_list = [r for r in dict.fromkeys(roots) if r in versions]
    direct = {(n, versions[n]) for n in root_list}
    return len(identities), len(direct), _bfs_depth(root_list, edges), versions


def count_pnpm_packages(text: str) -> int | None:
    """Number of entries under the top-level `packages:` key (line scan, no YAML parser)."""
    count, inside = 0, False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            inside = line.rstrip() == "packages:"
            continue
        if inside and re.match(r"^  \S.*:\s*$", line) and not line.startswith("   "):
            count += 1
    return count if count else None


LOCKFILE_NAMES = {
    "package-lock.json": NPM,
    "npm-shrinkwrap.json": NPM,
    "yarn.lock": NPM,
    "pnpm-lock.yaml": NPM,
    "uv.lock": PYPI,
    "poetry.lock": PYPI,
    "Pipfile.lock": PYPI,
    "bun.lock": NPM,
    "bun.lockb": NPM,
    "pdm.lock": PYPI,
    "pylock.toml": PYPI,
}


class LockfileReader:
    def __init__(self, index: RepoIndex, manifests: Manifests) -> None:
        self.index = index
        self.manifests = manifests

    def _dir_manifest_deps(self, directory: str, ecosystem: str) -> dict[str, str | None] | None:
        """Direct deps (key -> spec) declared by manifests in `directory`, or None."""
        found: dict[str, str | None] = {}
        local = [
            m
            for m in self.manifests.files[ecosystem]
            if (m.rsplit("/", 1)[0] if "/" in m else "") == directory
        ]
        if not local:
            return None
        for dep in self.manifests.deps[ecosystem].values():
            if dep.manifest in local:
                found[dep.key] = dep.spec
        # A dependency may be recorded under another manifest after deduplication.
        for rel in local:
            if PurePosixPath(rel).name == "package.json":
                data = self._json(rel, MAX_MANIFEST_BYTES)
                if isinstance(data, dict):
                    for section in _NPM_ROOT_SECTIONS:
                        deps = data.get(section)
                        if isinstance(deps, dict):
                            for name, spec in deps.items():
                                found.setdefault(name, spec if isinstance(spec, str) else None)
        return found

    def _json(self, rel: str, limit: int = MAX_LOCKFILE_BYTES) -> Any:
        text = self.index.read_text(rel, limit)
        if text is None:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def read(self) -> list[Lockfile]:
        lockfiles: list[Lockfile] = []
        for rel in sorted(self.index.files, key=lambda f: (f.count("/"), f)):
            name = PurePosixPath(rel).name
            ecosystem = LOCKFILE_NAMES.get(name)
            if ecosystem is None:
                continue
            directory = "" if "/" not in rel else rel.rsplit("/", 1)[0]
            lock = Lockfile(path=rel, format=name, ecosystem=ecosystem)
            try:
                self._fill(lock, directory)
            except (ValueError, KeyError, TypeError, AttributeError, tomllib.TOMLDecodeError):
                logger.info("dep_health: could not parse %s", rel, exc_info=True)
                lock.note = "could not be parsed"
                lock.packages = None
            if lock.packages is not None and lock.direct is not None:
                lock.transitive = max(0, lock.packages - lock.direct)
            lockfiles.append(lock)
        return lockfiles

    def _fill(self, lock: Lockfile, directory: str) -> None:
        name, eco = lock.format, lock.ecosystem
        local = self._dir_manifest_deps(directory, eco)
        repo_roots = list(self.manifests.deps[eco])
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            data = self._json(lock.path)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            has_root = isinstance(data.get("packages"), dict) and "" in data["packages"]
            roots = None if has_root else list(local or {}) or None
            parsed = parse_package_lock(data, roots)
            if parsed is None:
                raise ValueError("no packages")
            lock.packages, lock.direct, lock.max_depth, lock.versions = parsed
        elif name == "yarn.lock":
            text = self.index.read_text(lock.path, MAX_LOCKFILE_BYTES) or ""
            if "__metadata:" in text:
                lock.note = "yarn berry (v2+) lockfiles are not supported"
                return
            specs = local if local is not None else {k: None for k in repo_roots}
            lock.packages, lock.direct, lock.max_depth, lock.versions = parse_yarn_v1(text, specs)
        elif name == "uv.lock":
            toml_data = tomllib.loads(self.index.read_text(lock.path, MAX_LOCKFILE_BYTES) or "")
            roots = list(local) if local is not None else repo_roots
            parsed = parse_uv_lock(toml_data, roots)
            lock.packages, lock.direct, lock.max_depth, lock.versions = parsed
        elif name == "poetry.lock":
            toml_data = tomllib.loads(self.index.read_text(lock.path, MAX_LOCKFILE_BYTES) or "")
            roots = list(local) if local is not None else repo_roots
            parsed = parse_poetry_lock(toml_data, roots)
            lock.packages, lock.direct, lock.max_depth, lock.versions = parsed
        elif name == "Pipfile.lock":
            data = self._json(lock.path)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            names: dict[str, str] = {}
            for section in ("default", "develop"):
                for dep, entry in (data.get(section) or {}).items():
                    version = entry.get("version", "") if isinstance(entry, dict) else ""
                    names.setdefault(_normalize_dist(dep), str(version).lstrip("="))
            declared = set(local) if local is not None else set(repo_roots)
            lock.packages = len(names)
            lock.direct = len(declared & set(names))
            lock.versions = {k: v for k, v in names.items() if v}
            lock.note = "flat lockfile: depth unknown"
        elif name == "pnpm-lock.yaml":
            text = self.index.read_text(lock.path, MAX_LOCKFILE_BYTES) or ""
            lock.packages = count_pnpm_packages(text)
            if lock.packages is None:
                lock.note = "pnpm lockfile layout not recognised"
                return
            lock.direct = min(lock.packages, len(local if local is not None else repo_roots))
            lock.note = "packages counted only: depth unknown"
        else:
            lock.note = f"{name} is not supported"


# ----------------------------------------------------------------------------- registry


class RegistryClient:
    """Cached PyPI / npm metadata lookups. Never raises for per-package problems."""

    def __init__(self, settings: Settings, client: httpx.Client) -> None:
        self.settings = settings
        self.client = client
        self.cache_dir = Path(settings.scan_workspace_dir) / "_registry"
        self.ttl_seconds = settings.dep_health_registry_cache_hours * 3600
        self.unreachable: dict[str, str] = {}
        self.cache_hits = 0
        self.requests = 0
        self._lock = threading.Lock()

    def _cache_path(self, ecosystem: str, name: str) -> Path:
        return self.cache_dir / ecosystem.lower() / f"{quote(name, safe='')}.json"

    def _read_cache(self, path: Path) -> RegistryInfo | None:
        try:
            data = json.loads(path.read_text())
            if time.time() - float(data["fetched_at"]) > self.ttl_seconds:
                return None
            return RegistryInfo(
                found=bool(data["found"]),
                latest=data.get("latest"),
                versions=tuple(data.get("versions") or ()),
                sizes=data.get("sizes") or {},
                file_counts=data.get("file_counts") or {},
            )
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write_cache(self, path: Path, info: RegistryInfo) -> None:
        payload = {
            "fetched_at": time.time(),
            "found": info.found,
            "latest": info.latest,
            "versions": list(info.versions),
            "sizes": dict(info.sizes),
            "file_counts": dict(info.file_counts),
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_text(json.dumps(payload))
            os.replace(temporary, path)
        except OSError:
            logger.info("dep_health: could not write registry cache %s", path, exc_info=True)

    def lookup(self, ecosystem: str, name: str) -> RegistryInfo | None:
        """Metadata, a not-found marker, or None if the registry is unreachable."""
        registry_name = canonical_pypi(name) if ecosystem == PYPI else name
        path = self._cache_path(ecosystem, registry_name)
        cached = self._read_cache(path)
        if cached is not None:
            with self._lock:
                self.cache_hits += 1
            return cached
        if ecosystem in self.unreachable:
            return None
        try:
            info = self._fetch(ecosystem, registry_name)
        except RegistryUnavailableError as exc:
            with self._lock:
                self.unreachable.setdefault(ecosystem, str(exc)[:200])
            return None
        self._write_cache(path, info)
        return info

    def _fetch(self, ecosystem: str, name: str) -> RegistryInfo:
        if ecosystem == PYPI:
            url, headers = PYPI_URL.format(name=quote(name, safe="")), {}
        else:
            url = NPM_URL.format(name=quote(name, safe="@"))
            headers = {"Accept": NPM_ABBREVIATED}
        with self._lock:
            self.requests += 1
        try:
            response = self.client.get(url, headers=headers)
        except httpx.TransportError as exc:
            raise RegistryUnavailableError(f"{type(exc).__name__}: {exc}") from exc
        if response.status_code == 404:
            return RegistryInfo(found=False)
        if response.status_code >= 500 or response.status_code == 429:
            raise RegistryUnavailableError(f"HTTP {response.status_code}")
        if response.status_code != 200:
            return RegistryInfo(found=False)
        try:
            data = response.json()
        except ValueError as exc:
            raise RegistryUnavailableError("invalid JSON from the registry") from exc
        if not isinstance(data, dict):
            return RegistryInfo(found=False)
        return self._normalise_pypi(data) if ecosystem == PYPI else self._normalise_npm(data)

    @staticmethod
    def _normalise_pypi(data: Mapping[str, Any]) -> RegistryInfo:
        versions: list[str] = []
        sizes: dict[str, int] = {}
        for version, files in (data.get("releases") or {}).items():
            live = [f for f in files or [] if isinstance(f, dict) and not f.get("yanked")]
            if not live:
                continue
            versions.append(version)
            file_sizes = [int(f["size"]) for f in live if isinstance(f.get("size"), int)]
            if file_sizes:
                sizes[version] = min(file_sizes)
        latest = (data.get("info") or {}).get("version")
        return RegistryInfo(
            True, latest if isinstance(latest, str) else None, tuple(versions), sizes
        )

    @staticmethod
    def _normalise_npm(data: Mapping[str, Any]) -> RegistryInfo:
        versions: list[str] = []
        sizes: dict[str, int] = {}
        counts: dict[str, int] = {}
        for version, meta in (data.get("versions") or {}).items():
            versions.append(version)
            dist = meta.get("dist") if isinstance(meta, dict) else None
            if isinstance(dist, dict):
                if isinstance(dist.get("unpackedSize"), int):
                    sizes[version] = dist["unpackedSize"]
                if isinstance(dist.get("fileCount"), int):
                    counts[version] = dist["fileCount"]
        latest = (data.get("dist-tags") or {}).get("latest")
        return RegistryInfo(
            True, latest if isinstance(latest, str) else None, tuple(versions), sizes, counts
        )


def freshness_of(ecosystem: str, installed: str, info: RegistryInfo) -> dict[str, Any] | None:
    """versions/majors behind and the per-dependency freshness score, or None."""
    current = parse_version(ecosystem, installed)
    if current is None:
        return None
    latest = parse_version(ecosystem, info.latest) if info.latest else None
    ceiling = latest if latest is not None and not latest.prerelease else None
    newer: list[Version] = []
    for text in info.versions:
        version = parse_version(ecosystem, text)
        if version is None or version.prerelease or not version.key > current.key:
            continue
        if ceiling is not None and version.key > ceiling.key:
            continue
        newer.append(version)
    majors = {v.major_key for v in newer if v.major_key > current.major_key}
    behind = len(newer)
    factor = 1.0 if behind <= 2 else 0.8 if behind <= 10 else 0.6
    return {
        "installed": installed,
        "latest": info.latest,
        "versions_behind": behind,
        "majors_behind": len(majors),
        "score": factor / (1 + len(majors)),
    }


def trivial_size(
    ecosystem: str, installed: str | None, info: RegistryInfo
) -> dict[str, Any] | None:
    """Size facts used for the trivial-package check, or None if the registry has none."""
    if ecosystem == NPM:
        version = info.latest
    else:
        version = installed if installed in info.sizes else info.latest
    if version is None or (version not in info.sizes and version not in info.file_counts):
        return None
    return {
        "version": version,
        "size": info.sizes.get(version),
        "file_count": info.file_counts.get(version),
    }


# ----------------------------------------------------------------------------- imports


@dataclass
class ImportUsage:
    """What the code imports, per ecosystem."""

    used: dict[str, set[str]] = field(default_factory=lambda: {PYPI: set(), NPM: set()})
    external: dict[str, set[str]] = field(default_factory=lambda: {PYPI: set(), NPM: set()})
    phantom: dict[str, dict[str, tuple[str, int]]] = field(
        default_factory=lambda: {PYPI: {}, NPM: {}}
    )
    # Python import top-level name -> distribution keys it may belong to.
    candidates: dict[str, set[str]] = field(default_factory=dict)


def _python_candidates(item: ResolvedImport) -> set[str]:
    """Distribution keys an import may belong to (the resolver's `_is_declared` rules, plus
    dotted namespace prefixes: google.cloud.storage -> google_cloud_storage)."""
    top = item.target or item.raw.specifier.split(".", 1)[0]
    normal = _normalize_dist(top)
    candidates = {normal, f"python_{normal}", f"py{normal}", *PYTHON_IMPORT_ALIASES.get(top, ())}
    candidates.update(EXTRA_IMPORT_ALIASES.get(top, ()))
    dotted = [p for p in item.raw.specifier.split(".") if p]
    if item.raw.kind == "from" and len(item.raw.names) > 0:
        dotted_with_names = [[*dotted, n] for n in item.raw.names]
    else:
        dotted_with_names = [dotted]
    for parts in dotted_with_names:
        for end in range(2, len(parts) + 1):
            candidates.add(_normalize_dist("_".join(parts[:end])))
    return candidates


def collect_usage(resolved: Iterable[ResolvedImport], languages: Mapping[str, str]) -> ImportUsage:
    usage = ImportUsage()
    for item in sorted(resolved, key=lambda r: (r.source, r.raw.line)):
        if item.status is not ImportStatus.EXTERNAL or not item.target:
            continue
        if item.method not in {"declared", "undeclared"}:
            continue  # stdlib, node builtin, URL imports
        ecosystem = PYPI if languages.get(item.source) == "python" else NPM
        package = item.target
        usage.external[ecosystem].add(package)
        if ecosystem == PYPI:
            candidates = _python_candidates(item)
            usage.used[PYPI].update(candidates)
            usage.candidates.setdefault(package, set()).update(candidates)
        else:
            usage.used[NPM].add(package)
        if item.method == "undeclared":
            usage.phantom[ecosystem].setdefault(package, (item.source, item.raw.line))
    return usage


def _template_imports(index: RepoIndex) -> set[str]:
    """npm packages imported from files the parser doesn't read: single-file components
    (.vue/.svelte/.astro/.mdx) and stylesheets (`@import "pkg/..."`)."""
    packages: set[str] = set()
    files = sorted(f for f in index.files if f.endswith(_TEMPLATE_EXTENSIONS + _STYLE_EXTENSIONS))
    for rel in files[:MAX_TEMPLATE_FILES]:
        pattern = _STYLE_IMPORT if rel.endswith(_STYLE_EXTENSIONS) else _TEMPLATE_IMPORT
        for specifier in pattern.findall(index.read_text(rel) or ""):
            parts = specifier.split("/")
            packages.add("/".join(parts[:2]) if specifier.startswith("@") else parts[0])
    return packages


def _referenced(dep: Dependency, corpus: list[tuple[str, str]]) -> str | None:
    """The first tool file whose text mentions `dep` as a word, if any."""
    names = {dep.name}
    flags = 0
    if dep.ecosystem == PYPI:
        names |= {canonical_pypi(dep.name), dep.key}
        flags = re.IGNORECASE
    pattern = re.compile(
        r"(?<![\w@.-])(" + "|".join(re.escape(n) for n in sorted(names)) + r")(?![\w-])", flags
    )
    for rel, text in corpus:
        if pattern.search(text):
            return rel
    return None


def _line_of(index: RepoIndex, rel: str, name: str) -> int:
    text = index.read_text(rel, MAX_MANIFEST_BYTES) or ""
    pattern = re.compile(rf"(?<![\w@/.-]){re.escape(name)}(?![\w-])", re.IGNORECASE)
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return number
    return 1


# ----------------------------------------------------------------------------- analyzer


def transitive_component(transitive: int, direct: int) -> float:
    """1 / (1 + max(0, T - 10D) / (50 * max(1, D)))."""
    excess = max(0, transitive - 10 * direct)
    return 1.0 / (1.0 + excess / (50.0 * max(1, direct)))


class DepHealthAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Dependency health"
    supported_languages = frozenset()
    phase = 2
    experimental = True

    def __init__(
        self, settings: Settings | None = None, client: httpx.Client | None = None
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client
        self.docker_image = None  # reads files in the worker; registry calls from the worker
        self.timeout_seconds = self._settings.experimental_timeout_seconds

    # --- entry points ---------------------------------------------------------------------

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        prior = context.prior_results.get("architecture")
        architecture = getattr(prior, "artifact", None) if prior is not None else None
        deadline = started + self.timeout_seconds * 0.5
        report, findings = self.collect(repo_path, architecture, deadline=deadline)
        raw_output = json.dumps(
            {"report": report.as_dict(), "findings": [self._finding_payload(f) for f in findings]}
        )
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=self.parse(raw_output),
            raw_output=raw_output,
            duration_ms=int((time.monotonic() - started) * 1000),
            warnings=(report.reason,) if report.reason and report.applicable else (),
            artifact=report,
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        try:
            items = json.loads(raw_output)["findings"]
            return [
                FindingData(
                    analyzer=self.name,
                    rule_id=item["rule_id"],
                    severity=Severity.INFO,
                    file_path=item["file_path"],
                    start_line=int(item["line"]),
                    end_line=int(item["line"]),
                    message=item["message"],
                    category=item["category"],
                    dependency=item["dependency"],
                    raw=item,
                )
                for item in items
            ]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AnalyzerOutputError("Dependency health produced invalid output.") from exc

    @staticmethod
    def _finding_payload(finding: FindingData) -> dict[str, Any]:
        return {
            "rule_id": finding.rule_id,
            "file_path": finding.file_path,
            "line": finding.start_line,
            "message": finding.message,
            "category": finding.category,
            "dependency": finding.dependency,
        }

    # --- computation ----------------------------------------------------------------------

    def collect(
        self, repo_path: Path, architecture: Any, deadline: float | None = None
    ) -> tuple[SignalReport, list[FindingData]]:
        """Compute the signal for the repository at `repo_path`."""
        index = RepoIndex(repo_path, [])
        manifests = ManifestReader(index).read()
        if not any(manifests.files.values()):
            return (
                SignalReport(
                    name=ANALYZER_NAME, applicable=False, reason="No dependency manifest found."
                ),
                [],
            )
        notes: list[str] = []
        metrics: dict[str, Any] = {"manifests": {e: sorted(f) for e, f in manifests.files.items()}}
        components: dict[str, float | None] = {}
        findings: list[FindingData] = []

        components["direct_count"] = self._direct_counts(manifests, metrics)
        lockfiles = LockfileReader(index, manifests).read()
        components["transitive"] = self._transitive(lockfiles, metrics, notes)
        components["freshness"], components["trivial"] = self._registry(
            manifests, lockfiles, metrics, notes, deadline
        )
        if hasattr(architecture, "resolved") and hasattr(architecture, "modules"):
            languages = {m.path: m.language for m in architecture.modules}
            usage = collect_usage(architecture.resolved, languages)
            usage.used[NPM] |= _template_imports(index)
            components["unused"] = self._unused(index, manifests, usage, metrics, findings)
            components["phantom"] = self._phantom(manifests, usage, metrics, findings, notes)
        else:
            components["unused"] = components["phantom"] = None
            notes.append("architecture report unavailable: unused/phantom not computed")
        ordered = {
            key: components[key]
            for key in ("direct_count", "freshness", "transitive", "trivial", "unused", "phantom")
        }
        metrics["notes"] = notes
        report = SignalReport(
            name=ANALYZER_NAME,
            applicable=True,
            score=mean_score(ordered),
            components=ordered,
            metrics=metrics,
            reason="; ".join(notes) or None,
        )
        return report, findings

    def _direct_counts(self, manifests: Manifests, metrics: dict[str, Any]) -> float | None:
        baselines = {
            PYPI: self._settings.dep_health_baseline_pypi,
            NPM: self._settings.dep_health_baseline_npm,
        }
        per_ecosystem: dict[str, Any] = {}
        values: list[float] = []
        for ecosystem in ECOSYSTEMS:
            if not manifests.files[ecosystem]:
                continue
            deps = manifests.deps[ecosystem].values()
            runtime = sum(1 for d in deps if d.kind == RUNTIME)
            dev = sum(1 for d in deps if d.kind == DEV)
            baseline = max(1, baselines[ecosystem])
            value = clamp01(baseline / max(runtime + dev, baseline))
            values.append(value)
            per_ecosystem[ecosystem] = {
                "runtime": runtime,
                "dev": dev,
                "total": runtime + dev,
                "baseline": baseline,
                "component": round(value, 4),
            }
        metrics["direct"] = per_ecosystem
        return sum(values) / len(values) if values else None

    @staticmethod
    def _transitive(
        lockfiles: list[Lockfile], metrics: dict[str, Any], notes: list[str]
    ) -> float | None:
        usable = [lf for lf in lockfiles if lf.transitive is not None and lf.direct is not None]
        depths = [lf.max_depth for lf in usable if lf.max_depth is not None]
        total = sum(lf.transitive or 0 for lf in usable)
        direct = sum(lf.direct or 0 for lf in usable)
        metrics["transitive"] = {
            "lockfiles": [lf.as_dict() for lf in lockfiles],
            "transitive_count": total if usable else None,
            "direct_in_lockfiles": direct if usable else None,
            "max_depth": max(depths) if depths else None,
        }
        if not usable:
            notes.append("no supported lockfile: transitive dependencies unknown")
            return None
        return transitive_component(total, direct)

    def _installed_version(
        self,
        dep: Dependency,
        lock_versions: Mapping[str, Mapping[str, str]],
        pins: Mapping[str, str],
    ) -> tuple[str, str] | None:
        locked = lock_versions[dep.ecosystem].get(dep.key)
        if locked:
            return locked, "lockfile"
        if dep.ecosystem == PYPI and dep.key in pins:
            return pins[dep.key], "compiled requirements"
        bound = minimum_version(dep.ecosystem, dep.spec)
        if bound is None:
            return None
        return bound[0], "pin" if bound[1] else "range minimum"

    def _registry(
        self,
        manifests: Manifests,
        lockfiles: list[Lockfile],
        metrics: dict[str, Any],
        notes: list[str],
        deadline: float | None,
    ) -> tuple[float | None, float | None]:
        settings = self._settings
        registry_metrics: dict[str, Any] = {"enabled": settings.dep_health_registry_enabled}
        metrics["registry"] = registry_metrics
        if not settings.dep_health_registry_enabled:
            notes.append("registry lookups disabled: freshness and trivial packages not computed")
            metrics["freshness"] = metrics["trivial"] = None
            return None, None

        lock_versions: dict[str, dict[str, str]] = {PYPI: {}, NPM: {}}
        for lock in lockfiles:
            for key, version in lock.versions.items():
                lock_versions[lock.ecosystem].setdefault(
                    _dependency_key(lock.ecosystem, key), version
                )
        candidates = [d for eco in ECOSYSTEMS for d in manifests.deps[eco].values() if d.registry]
        candidates.sort(key=lambda d: (d.kind != RUNTIME, d.ecosystem, d.key))
        limit = max(0, settings.dep_health_max_registry_lookups)
        selected, skipped = candidates[:limit], candidates[limit:]

        owns_client = self._client is None
        client = self._client or httpx.Client(
            timeout=settings.dep_health_registry_timeout_seconds,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        )
        registry = RegistryClient(settings, client)
        results: dict[tuple[str, str], RegistryInfo | None] = {}
        timed_out: list[Dependency] = []

        def work(dep: Dependency) -> None:
            if deadline is not None and time.monotonic() > deadline:
                timed_out.append(dep)
                return
            results[(dep.ecosystem, dep.key)] = registry.lookup(dep.ecosystem, dep.name)

        try:
            with ThreadPoolExecutor(max_workers=REGISTRY_WORKERS) as pool:
                list(pool.map(work, selected))
        finally:
            if owns_client:
                client.close()

        freshness: list[dict[str, Any]] = []
        trivial_checked: list[dict[str, Any]] = []
        not_found: list[str] = []
        unversioned: list[str] = []
        for dep in selected:
            info = results.get((dep.ecosystem, dep.key))
            if info is None:
                continue
            if not info.found:
                not_found.append(f"{dep.ecosystem}:{dep.name}")
                continue
            installed = self._installed_version(dep, lock_versions, manifests.pins)
            if installed is None:
                unversioned.append(f"{dep.ecosystem}:{dep.name}")
            else:
                fresh = freshness_of(dep.ecosystem, installed[0], info)
                if fresh is not None:
                    freshness.append(
                        {
                            "ecosystem": dep.ecosystem,
                            "name": dep.name,
                            "kind": dep.kind,
                            "version_source": installed[1],
                            **fresh,
                        }
                    )
            registry_name = canonical_pypi(dep.name) if dep.ecosystem == PYPI else dep.name
            if not _matches(registry_name, STUB_PATTERNS):
                size = trivial_size(dep.ecosystem, installed[0] if installed else None, info)
                if size is not None:
                    threshold = settings.dep_health_trivial_bytes
                    is_trivial = (size["size"] is not None and size["size"] < threshold) or (
                        size["file_count"] is not None and size["file_count"] <= 2
                    )
                    trivial_checked.append(
                        {
                            "ecosystem": dep.ecosystem,
                            "name": dep.name,
                            "trivial": is_trivial,
                            **size,
                        }
                    )

        registry_metrics.update(
            {
                "lookups": len(selected),
                "requests": registry.requests,
                "cache_hits": registry.cache_hits,
                "unreachable": dict(registry.unreachable),
                "not_found": not_found[:MAX_LISTED],
                "skipped_over_limit": len(skipped),
                "skipped_deadline": len(timed_out),
                "without_version": unversioned[:MAX_LISTED],
            }
        )
        for ecosystem, error in registry.unreachable.items():
            notes.append(f"{ecosystem} registry unreachable ({error})")
        if skipped:
            notes.append(f"{len(skipped)} dependencies not checked (lookup limit {limit})")
        if timed_out:
            notes.append(f"{len(timed_out)} dependencies not checked (time limit)")

        outdated = sorted(
            (f for f in freshness if f["majors_behind"] or f["versions_behind"] > 2),
            key=lambda f: (-f["majors_behind"], -f["versions_behind"], f["name"]),
        )
        freshness_value = sum(f["score"] for f in freshness) / len(freshness) if freshness else None
        metrics["freshness"] = {
            "checked": len(freshness),
            "mean": None if freshness_value is None else round(freshness_value, 4),
            "outdated": outdated[:MAX_LISTED],
            "dependencies": freshness[:MAX_LISTED],
        }
        trivial = [t for t in trivial_checked if t["trivial"]]
        trivial_value = 1 - len(trivial) / len(trivial_checked) if trivial_checked else None
        metrics["trivial"] = {
            "checked": len(trivial_checked),
            "threshold_bytes": settings.dep_health_trivial_bytes,
            "trivial": [f"{t['ecosystem']}:{t['name']}" for t in trivial][:MAX_LISTED],
        }
        if freshness_value is None and selected:
            notes.append("freshness not computed: no dependency could be checked")
        return freshness_value, trivial_value

    def _unused(
        self,
        index: RepoIndex,
        manifests: Manifests,
        usage: ImportUsage,
        metrics: dict[str, Any],
        findings: list[FindingData],
    ) -> float | None:
        declared = unused_count = 0
        unused: list[dict[str, str]] = []
        excluded: list[dict[str, str]] = []
        for ecosystem in ECOSYSTEMS:
            for dep in sorted(manifests.deps[ecosystem].values(), key=lambda d: d.key):
                declared += 1
                if dep.key in usage.used[ecosystem]:
                    continue
                if _allow_listed(dep):
                    excluded.append({"ecosystem": ecosystem, "name": dep.name, "why": "allow-list"})
                    continue
                reference = _referenced(dep, manifests.corpus)
                if reference is not None:
                    excluded.append(
                        {
                            "ecosystem": ecosystem,
                            "name": dep.name,
                            "why": f"referenced in {reference}",
                        }
                    )
                    continue
                unused_count += 1
                unused.append({"ecosystem": ecosystem, "name": dep.name, "manifest": dep.manifest})
                line = _line_of(index, dep.manifest, dep.name)
                findings.append(
                    FindingData(
                        analyzer=ANALYZER_NAME,
                        rule_id="unused-dependency",
                        severity=Severity.INFO,
                        file_path=dep.manifest,
                        start_line=line,
                        end_line=line,
                        message=(
                            f"{dep.name} ({ecosystem}) is declared in {dep.manifest} but no"
                            " module imports it."
                        ),
                        category=f"dep_health:unused:{ecosystem}:{dep.key}",
                        dependency={"ecosystem": ecosystem, "package": dep.name, "kind": dep.kind},
                    )
                )
        metrics["unused"] = unused[:MAX_LISTED]
        metrics["unused_count"] = unused_count
        metrics["declared_count"] = declared
        metrics["unused_excluded"] = excluded[:MAX_LISTED]
        return None if declared == 0 else clamp01(1 - unused_count / declared)

    @staticmethod
    def _phantom(
        manifests: Manifests,
        usage: ImportUsage,
        metrics: dict[str, Any],
        findings: list[FindingData],
        notes: list[str],
    ) -> float | None:
        phantom: list[dict[str, Any]] = []
        external = 0
        counted: list[str] = []
        for ecosystem in ECOSYSTEMS:
            if not manifests.files[ecosystem]:
                if usage.phantom[ecosystem]:
                    notes.append(f"no {ecosystem} manifest: undeclared imports not counted")
                continue
            counted.append(ecosystem)
            external += len(usage.external[ecosystem])
            declared = set(manifests.deps[ecosystem])
            for package, (source, line) in sorted(usage.phantom[ecosystem].items()):
                if ecosystem == PYPI and usage.candidates.get(package, set()) & declared:
                    continue  # declared under a distribution name the resolver doesn't map
                phantom.append(
                    {"ecosystem": ecosystem, "name": package, "file": source, "line": line}
                )
                findings.append(
                    FindingData(
                        analyzer=ANALYZER_NAME,
                        rule_id="phantom-dependency",
                        severity=Severity.INFO,
                        file_path=source,
                        start_line=line,
                        end_line=line,
                        message=(
                            f"{package} is imported but not declared in any {ecosystem}"
                            " manifest; it only works if something else installs it."
                        ),
                        category=f"dep_health:phantom:{ecosystem}:{package}",
                        dependency={"ecosystem": ecosystem, "package": package},
                    )
                )
        metrics["phantom"] = phantom[:MAX_LISTED]
        metrics["phantom_count"] = len(phantom)
        metrics["external_packages_imported"] = external
        if not counted:
            return None
        return clamp01(1 - len(phantom) / max(1, external))

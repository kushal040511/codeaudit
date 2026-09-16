"""Resolve raw import strings to internal modules or external packages.

Every import ends up as exactly one of:
- internal: a module (source file) of this repository -> a graph edge
- asset: a non-code file of this repository (CSS, JSON, images, .d.ts) -> no edge
- external: a package outside the repository (stdlib, node builtin, dependency)
- unresolved: with a reason; the share of these is reported as a quality signal

Resolution never reads outside the repository and never executes anything
(including package.json scripts or setup.py).
"""

import json
import logging
import os
import re
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property
from pathlib import Path, PurePosixPath
from typing import Any

from app.services.graph.parser import IGNORED_DIRS, ParsedModule, RawImport

logger = logging.getLogger(__name__)


class ImportStatus(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    ASSET = "asset"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ResolvedImport:
    source: str  # importing module path
    raw: RawImport
    status: ImportStatus
    target: str | None = None  # internal module path, asset path, or external package name
    # How it was resolved ("relative", "tsconfig-paths", ...) or, for externals, the
    # evidence ("stdlib", "node-builtin", "declared", "undeclared").
    method: str | None = None
    reason: str | None = None  # why it is unresolved

    @property
    def resolved(self) -> bool:
        return self.status is not ImportStatus.UNRESOLVED


JS_CODE_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_JS_TO_TS = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
# Imported for their side effects or content; real files but not graph modules.
ASSET_EXTENSIONS = frozenset(
    {
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".styl",
        ".pcss",
        ".json",
        ".json5",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".avif",
        ".ico",
        ".bmp",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".wasm",
        ".html",
        ".md",
        ".mdx",
        ".txt",
        ".graphql",
        ".gql",
        ".yaml",
        ".yml",
        ".vue",
        ".svelte",
        ".astro",
        ".worker",
    }
)

NODE_BUILTINS = frozenset(
    {
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)

# Import name -> distribution names, where they differ.
PYTHON_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "yaml": ("pyyaml",),
    "PIL": ("pillow",),
    "cv2": ("opencv_python", "opencv_python_headless", "opencv_contrib_python"),
    "bs4": ("beautifulsoup4",),
    "sklearn": ("scikit_learn",),
    "skimage": ("scikit_image",),
    "dateutil": ("python_dateutil",),
    "jwt": ("pyjwt",),
    "jose": ("python_jose",),
    "dotenv": ("python_dotenv",),
    "multipart": ("python_multipart",),
    "attr": ("attrs",),
    "OpenSSL": ("pyopenssl",),
    "Crypto": ("pycryptodome", "pycrypto"),
    "Cryptodome": ("pycryptodomex",),
    "psycopg2": ("psycopg2_binary", "psycopg2"),
    "git": ("gitpython",),
    "serial": ("pyserial",),
    "zmq": ("pyzmq",),
    "docx": ("python_docx",),
    "pptx": ("python_pptx",),
    "slugify": ("python_slugify",),
    "magic": ("python_magic",),
    "google": ("protobuf", "google_cloud_storage", "google_api_python_client", "google_auth"),
    "googleapiclient": ("google_api_python_client",),
    "grpc": ("grpcio",),
    "MySQLdb": ("mysqlclient",),
    "pkg_resources": ("setuptools",),
    "setuptools": ("setuptools",),
    "socketio": ("python_socketio",),
    "engineio": ("python_engineio",),
    "telegram": ("python_telegram_bot",),
    "rest_framework": ("djangorestframework",),
    "corsheaders": ("django_cors_headers",),
    "debug_toolbar": ("django_debug_toolbar",),
    "tree_sitter_python": ("tree_sitter_python",),
    "lxml": ("lxml",),
    "Levenshtein": ("python_levenshtein", "levenshtein"),
    "markdown": ("markdown",),
    "win32api": ("pywin32",),
    "typing_extensions": ("typing_extensions",),
}

# Packages installed by default with the interpreter or the build system.
PYTHON_IMPLICIT = frozenset(
    {"pkg_resources", "setuptools", "pip", "_pytest", "pytest", "typing_extensions"}
)


def _normalize_dist(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


# ----------------------------------------------------------------------------- repository index


class RepoIndex:
    """Files and directories of the repository (ignored trees excluded)."""

    def __init__(self, root: Path, source_files: Iterable[str]) -> None:
        self.root = root
        self.modules = frozenset(source_files)
        files: set[str] = set()
        dirs: set[str] = {""}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            rel_dir = Path(dirpath).relative_to(root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            dirs.add(rel_dir)
            for name in filenames:
                files.add(f"{rel_dir}/{name}" if rel_dir else name)
        self.files = frozenset(files)
        self.dirs = frozenset(dirs)

    def read_text(self, rel_path: str, max_bytes: int = 512 * 1024) -> str | None:
        path = (self.root / rel_path).resolve()
        if not path.is_relative_to(self.root.resolve()) or not path.is_file():
            return None
        try:
            if path.stat().st_size > max_bytes:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


def _join(*parts: str) -> str | None:
    """Normalise a repo-relative path; None if it escapes the repository root."""
    stack: list[str] = []
    for part in "/".join(p for p in parts if p).split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return None
            stack.pop()
        else:
            stack.append(part)
    return "/".join(stack)


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _in_dir(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


def _ancestors(directory: str) -> list[str]:
    """directory, its parent, ..., "" (repo root)."""
    result = [directory]
    while directory:
        directory = _parent(directory)
        result.append(directory)
    return result


# ----------------------------------------------------------------------------- Python


class PythonResolver:
    def __init__(self, index: RepoIndex) -> None:
        self.index = index
        self._stdlib = frozenset(sys.stdlib_module_names) | {"__future__"}

    @cached_property
    def source_roots(self) -> list[str]:
        """Directories that act as sys.path entries: the parents of top-level packages."""
        roots = {""}
        package_dirs = {_parent(f) for f in self.index.files if f.endswith("/__init__.py")}
        for package in package_dirs:
            top = package
            while _parent(top) in package_dirs:
                top = _parent(top)
            roots.add(_parent(top))
        for marker in ("pyproject.toml", "setup.py", "setup.cfg"):
            roots.update(_parent(f) for f in self.index.files if PurePosixPath(f).name == marker)
        roots.update(d for d in self.index.dirs if d == "src" or d.endswith("/src"))
        # Deepest first: the most specific root wins.
        return sorted(roots, key=lambda r: (-(r.count("/") + bool(r)), r))

    @cached_property
    def internal_top_names(self) -> frozenset[str]:
        names: set[str] = set()
        for root in self.source_roots:
            prefix = f"{root}/" if root else ""
            for module in self.index.modules:
                if module.endswith(".py") and module.startswith(prefix):
                    first = module[len(prefix) :].split("/", 1)[0]
                    names.add(first.removesuffix(".py"))
        return frozenset(names)

    @cached_property
    def declared_distributions(self) -> frozenset[str]:
        declared: set[str] = set()
        for rel in self.index.files:
            name = PurePosixPath(rel).name
            if name.startswith("requirements") and name.endswith((".txt", ".in")):
                declared.update(self._requirements(self.index.read_text(rel) or ""))
            elif name == "pyproject.toml":
                declared.update(self._pyproject(self.index.read_text(rel) or ""))
            elif name in {"setup.cfg", "setup.py", "Pipfile"}:
                # Loose: any requirement-looking token. Never executes setup.py.
                text = self.index.read_text(rel) or ""
                declared.update(
                    _normalize_dist(m)
                    for m in re.findall(r"['\"\s]([A-Za-z][\w.-]+)\s*[=<>~!\[]", text)
                )
        return frozenset(declared)

    @staticmethod
    def _requirement_name(line: str) -> str | None:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            return None
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        return _normalize_dist(match.group(1)) if match else None

    def _requirements(self, text: str) -> set[str]:
        return {n for line in text.splitlines() if (n := self._requirement_name(line))}

    def _pyproject(self, text: str) -> set[str]:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return set()
        specs: list[str] = []
        project = data.get("project") or {}
        specs.extend(project.get("dependencies") or [])
        for group in (project.get("optional-dependencies") or {}).values():
            specs.extend(group)
        for group in (data.get("dependency-groups") or {}).values():
            specs.extend(s for s in group if isinstance(s, str))
        poetry = (data.get("tool") or {}).get("poetry") or {}
        names = {_normalize_dist(n) for n in (poetry.get("dependencies") or {})}
        for group in (poetry.get("group") or {}).values():
            names.update(_normalize_dist(n) for n in (group.get("dependencies") or {}))
        names.update(n for s in specs if isinstance(s, str) and (n := self._requirement_name(s)))
        return names

    def _module_file(self, directory: str, dotted: str) -> str | None:
        base = _join(directory, dotted.replace(".", "/")) if dotted else directory
        if base is None:
            return None
        for candidate in (f"{base}.py", f"{base}/__init__.py" if base else "__init__.py"):
            if candidate in self.index.modules:
                return candidate
        return None

    def _is_namespace_package(self, directory: str, dotted: str) -> bool:
        base = _join(directory, dotted.replace(".", "/"))
        return (
            bool(base)
            and base in self.index.dirs
            and any(m.startswith(f"{base}/") and m.endswith(".py") for m in self.index.modules)
        )

    def _candidate_roots(self, source: str) -> list[str]:
        source_dir = _parent(source)
        ancestors = set(_ancestors(source_dir))
        nearest = [r for r in self.source_roots if r in ancestors]
        others = [r for r in self.source_roots if r not in ancestors]
        # A script's own directory is sys.path[0] when it is run directly. Modules
        # inside a package are not scripts: `from typing import X` in pkg/types.py
        # must not resolve to a sibling pkg/typing.py.
        script_dir = (
            [] if _in_dir(source_dir, "__init__.py") in self.index.modules else [source_dir]
        )
        return list(dict.fromkeys([*nearest, *script_dir, *others]))

    def resolve(self, source: str, raw: RawImport) -> list[ResolvedImport]:
        if raw.dynamic:
            return [self._unresolved(source, raw, "dynamic import with a non-literal module name")]
        if raw.level:
            return self._resolve_relative(source, raw)
        return self._resolve_absolute(source, raw)

    def _unresolved(self, source: str, raw: RawImport, reason: str) -> ResolvedImport:
        return ResolvedImport(source, raw, ImportStatus.UNRESOLVED, reason=reason)

    def _from_targets(
        self,
        source: str,
        raw: RawImport,
        directory: str,
        base: str,
        method: str,
        allow_namespace: bool,
    ) -> list[ResolvedImport] | None:
        """`from base import names`: names that are submodules become edges to them;
        any other name (a symbol) is an edge to `base` itself."""
        results: list[ResolvedImport] = []
        needs_base = not raw.names  # `from base import *`
        for name in raw.names:
            submodule = self._module_file(directory, f"{base}.{name}" if base else name)
            if submodule is not None and submodule != source:
                results.append(
                    ResolvedImport(source, raw, ImportStatus.INTERNAL, submodule, method)
                )
            else:
                needs_base = True
        if not needs_base:
            return results
        base_module = self._module_file(directory, base)
        if base_module is not None and base_module != source:
            results.append(ResolvedImport(source, raw, ImportStatus.INTERNAL, base_module, method))
            return results
        is_package_dir = (not base and directory in self.index.dirs) or self._is_namespace_package(
            directory, base
        )
        if allow_namespace and is_package_dir:
            # PEP 420 namespace package (no __init__.py): no module to depend on.
            return results or [
                ResolvedImport(source, raw, ImportStatus.INTERNAL, None, "namespace-package")
            ]
        return None

    def _resolve_relative(self, source: str, raw: RawImport) -> list[ResolvedImport]:
        directory = _parent(source)
        # A relative import can only climb through packages: level N needs N nested
        # packages (`from .. import x` in a top-level package is an ImportError). A
        # namespace package (no __init__.py) still allows `from . import x`.
        package_depth = 0
        for ancestor in _ancestors(directory):
            if _in_dir(ancestor, "__init__.py") not in self.index.modules:
                break
            package_depth += 1
        if raw.level > max(package_depth, 1):
            return [self._unresolved(source, raw, "relative import beyond the top-level package")]
        for _ in range(raw.level - 1):
            directory = _parent(directory)
        if raw.kind == "import":
            target = self._module_file(directory, raw.specifier)
            if target:
                return [ResolvedImport(source, raw, ImportStatus.INTERNAL, target, "relative")]
        else:
            found = self._from_targets(
                source, raw, directory, raw.specifier, "relative", allow_namespace=True
            )
            if found:
                return found
        shown = "." * raw.level + raw.specifier
        return [self._unresolved(source, raw, f"relative module {shown!r} not found")]

    def _resolve_absolute(self, source: str, raw: RawImport) -> list[ResolvedImport]:
        dotted = raw.specifier
        if not dotted:
            return [self._unresolved(source, raw, "empty module name")]
        top = dotted.split(".", 1)[0]
        internal_name = top in self.internal_top_names
        namespace_match: list[ResolvedImport] | None = None
        for root in self._candidate_roots(source):
            if raw.kind == "from":
                found = self._from_targets(
                    source, raw, root, dotted, "absolute", allow_namespace=internal_name
                )
            else:
                target = self._module_file(root, dotted)  # `import a.b` must name a module
                found = (
                    [ResolvedImport(source, raw, ImportStatus.INTERNAL, target, "absolute")]
                    if target is not None and target != source
                    else None
                )
                if found is None and internal_name and self._is_namespace_package(root, dotted):
                    found = [
                        ResolvedImport(
                            source, raw, ImportStatus.INTERNAL, None, "namespace-package"
                        )
                    ]
            if found and any(r.method != "namespace-package" for r in found):
                return found
            namespace_match = namespace_match or found

        # A regular package (stdlib or installed) takes precedence over a PEP 420
        # namespace directory: a local `alembic/` migrations folder is not `alembic`.
        if top in self._stdlib:
            return [ResolvedImport(source, raw, ImportStatus.EXTERNAL, top, "stdlib")]
        declared = self._is_declared(top)
        if declared:
            return [ResolvedImport(source, raw, ImportStatus.EXTERNAL, top, "declared")]
        if namespace_match:
            return namespace_match
        if internal_name:
            reason = f"module {dotted!r} not found in internal package {top!r}"
            return [self._unresolved(source, raw, reason)]
        return [ResolvedImport(source, raw, ImportStatus.EXTERNAL, top, "undeclared")]

    def _is_declared(self, top: str) -> bool:
        if top in PYTHON_IMPLICIT:
            return True
        candidates = {
            _normalize_dist(top),
            f"python_{_normalize_dist(top)}",
            f"py{_normalize_dist(top)}",
        }
        candidates.update(PYTHON_IMPORT_ALIASES.get(top, ()))
        return bool(candidates & self.declared_distributions)


# ----------------------------------------------------------------------------- JS / TS


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings (tsconfig is JSONC)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


@dataclass(frozen=True)
class PathAliases:
    base_dir: str  # directory `paths` targets are relative to
    paths: tuple[tuple[str, tuple[str, ...]], ...]  # pattern -> targets, longest prefix first
    base_url: str | None  # directory non-relative imports may resolve against


_CONFIG_NAME = re.compile(r"(ts|js)config(\.[\w.-]+)?\.json")


class JsResolver:
    def __init__(self, index: RepoIndex) -> None:
        self.index = index
        self._config_cache: dict[str, dict[str, Any] | None] = {}
        self._aliases_cache: dict[str, PathAliases | None] = {}
        self._package_json_cache: dict[str, dict[str, Any] | None] = {}

    # --- config files ---------------------------------------------------------------

    def _load_json(self, rel_path: str) -> dict[str, Any] | None:
        if rel_path in self._package_json_cache:
            return self._package_json_cache[rel_path]
        text = self.index.read_text(rel_path)
        data: dict[str, Any] | None = None
        if text is not None:
            try:
                loaded = json.loads(_strip_jsonc(text))
                data = loaded if isinstance(loaded, dict) else None
            except ValueError:
                logger.info("could not parse %s", rel_path)
        self._package_json_cache[rel_path] = data
        return data

    def _compiler_options(self, config_path: str, depth: int = 0) -> dict[str, Any] | None:
        """compilerOptions with `extends` applied; paths/baseUrl made repo-relative."""
        if config_path in self._config_cache:
            return self._config_cache[config_path]
        data = self._load_json(config_path)
        if data is None or depth > 5:
            return None
        config_dir = _parent(config_path)
        merged: dict[str, Any] = {}
        extends = data.get("extends")
        for parent in [extends] if isinstance(extends, str) else (extends or []):
            if isinstance(parent, str) and parent.startswith("."):
                parent_path = _join(config_dir, parent)
                if parent_path and not parent_path.endswith(".json"):
                    parent_path += ".json"
                inherited = self._compiler_options(parent_path, depth + 1) if parent_path else None
                merged.update(inherited or {})
        options = data.get("compilerOptions") or {}
        if isinstance(options, dict):
            if isinstance(options.get("baseUrl"), str):
                merged["_baseUrl"] = _join(config_dir, options["baseUrl"])
            if isinstance(options.get("paths"), dict):
                merged["_paths"] = options["paths"]
                merged["_pathsDir"] = config_dir
        self._config_cache[config_path] = merged
        return merged

    def _aliases_for(self, directory: str) -> PathAliases | None:
        """Aliases from the nearest directory containing a tsconfig/jsconfig.

        Project-reference setups (Vite: tsconfig.json -> tsconfig.app.json) keep `paths`
        in a sibling config, so every config in that directory is considered.
        """
        if directory in self._aliases_cache:
            return self._aliases_cache[directory]
        result: PathAliases | None = None
        for ancestor in _ancestors(directory):
            prefix = f"{ancestor}/" if ancestor else ""
            configs = sorted(
                (
                    f
                    for f in self.index.files
                    if f.startswith(prefix) and _CONFIG_NAME.fullmatch(f[len(prefix) :])
                ),
                # tsconfig.json / jsconfig.json first, then e.g. tsconfig.app.json
                key=lambda f: (PurePosixPath(f).name not in {"tsconfig.json", "jsconfig.json"}, f),
            )
            if not configs:
                continue
            base_url = paths_dir = None
            paths: dict[str, Any] = {}
            for config in configs:
                options = self._compiler_options(config) or {}
                base_url = base_url or options.get("_baseUrl")
                if options.get("_paths") and not paths:
                    paths = options["_paths"]
                    paths_dir = options.get("_baseUrl") or options.get("_pathsDir")
            if paths or base_url is not None:
                ordered = sorted(
                    (
                        (str(p), tuple(str(t) for t in targets if isinstance(t, str)))
                        for p, targets in paths.items()
                        if isinstance(targets, list)
                    ),
                    key=lambda item: -len(item[0].split("*", 1)[0]),
                )
                result = PathAliases(
                    base_dir=paths_dir if paths_dir is not None else ancestor,
                    paths=tuple(ordered),
                    base_url=base_url,
                )
            break
        self._aliases_cache[directory] = result
        return result

    def _package_root(self, directory: str) -> str | None:
        for ancestor in _ancestors(directory):
            if _in_dir(ancestor, "package.json") in self.index.files:
                return ancestor
        return None

    @cached_property
    def _workspace_packages(self) -> dict[str, str]:
        packages: dict[str, str] = {}
        for rel in sorted(self.index.files):
            if PurePosixPath(rel).name == "package.json":
                data = self._load_json(rel) or {}
                name = data.get("name")
                if isinstance(name, str) and name and name not in packages:
                    packages[name] = _parent(rel)
        return packages

    def _declared(self, directory: str, package: str) -> bool:
        for ancestor in _ancestors(directory):
            manifest = _in_dir(ancestor, "package.json")
            if manifest not in self.index.files:
                continue
            data = self._load_json(manifest) or {}
            for key in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                deps = data.get(key)
                if isinstance(deps, dict) and package in deps:
                    return True
        return False

    # --- file probing -----------------------------------------------------------------

    def _probe(self, base: str) -> tuple[ImportStatus, str, str] | None:
        """Resolve a repo-relative path like Node/TypeScript do: exact, extensions, index."""
        suffix = PurePosixPath(base).suffix.lower()
        if base in self.index.modules:
            return ImportStatus.INTERNAL, base, "file"
        if base in self.index.files and suffix in ASSET_EXTENSIONS:
            return ImportStatus.ASSET, base, "asset"
        stem = base[: -len(suffix)] if suffix else base
        for replacement in _JS_TO_TS.get(suffix, ()):  # ESM TS: "./x.js" means ./x.ts
            if f"{stem}{replacement}" in self.index.modules:
                return ImportStatus.INTERNAL, f"{stem}{replacement}", "file"
        for extension in JS_CODE_EXTENSIONS:
            if f"{base}{extension}" in self.index.modules:
                return ImportStatus.INTERNAL, f"{base}{extension}", "extension"
        if f"{base}.d.ts" in self.index.files:
            return ImportStatus.ASSET, f"{base}.d.ts", "type-declaration"
        if base in self.index.dirs:
            manifest = self._load_json(_in_dir(base, "package.json")) if base else None
            if manifest:
                for field in ("source", "module", "main", "types"):
                    entry = manifest.get(field)
                    if isinstance(entry, str) and (joined := _join(base, entry)):
                        found = self._probe(joined)
                        if found:
                            return found
            for extension in JS_CODE_EXTENSIONS:
                candidate = _in_dir(base, f"index{extension}")
                if candidate in self.index.modules:
                    return ImportStatus.INTERNAL, candidate, "index"
            if _in_dir(base, "index.d.ts") in self.index.files:
                return ImportStatus.ASSET, _in_dir(base, "index.d.ts"), "type-declaration"
        return None

    # --- resolution ---------------------------------------------------------------------

    @staticmethod
    def _clean(specifier: str) -> str:
        specifier = specifier.rsplit("!", 1)[-1]  # webpack loaders: "raw-loader!./x"
        return re.split(r"[?#]", specifier, maxsplit=1)[0]  # vite: "./x.svg?react"

    @staticmethod
    def package_name(specifier: str) -> str:
        parts = specifier.split("/")
        return "/".join(parts[:2]) if specifier.startswith("@") and len(parts) > 1 else parts[0]

    def resolve(self, source: str, raw: RawImport) -> list[ResolvedImport]:
        def internal(result: tuple[ImportStatus, str, str], method: str) -> list[ResolvedImport]:
            status, target, _how = result
            return [ResolvedImport(source, raw, status, target, method)]

        def unresolved(reason: str) -> list[ResolvedImport]:
            return [ResolvedImport(source, raw, ImportStatus.UNRESOLVED, reason=reason)]

        if raw.dynamic:
            return unresolved("dynamic import with a non-literal specifier")
        specifier = self._clean(raw.specifier.strip())
        if not specifier:
            return unresolved("empty import specifier")
        source_dir = _parent(source)

        if re.match(r"^[a-z][a-z0-9+.-]*:", specifier, re.IGNORECASE) and not specifier.startswith(
            "node:"
        ):
            return [
                ResolvedImport(
                    source, raw, ImportStatus.EXTERNAL, specifier.split("?")[0][:200], "url"
                )
            ]
        if specifier.startswith("node:") or self.package_name(specifier) in NODE_BUILTINS:
            name = specifier.removeprefix("node:").split("/", 1)[0]
            return [ResolvedImport(source, raw, ImportStatus.EXTERNAL, name, "node-builtin")]

        if specifier.startswith((".", "/")):
            if specifier.startswith("/"):
                project = self._package_root(source_dir) or ""
                # Vite/CRA serve "/x" from the project's public/ directory.
                candidates = [
                    _join(project, specifier),
                    _join(project, "public", specifier),
                    _join(specifier),
                ]
                method = "root-relative"
            else:
                candidates = [_join(source_dir, specifier)]
                method = "relative"
            for base in candidates:
                if base is not None and (found := self._probe(base)):
                    return internal(found, method)
            if candidates[0] is None:
                return unresolved("relative import beyond the repository root")
            return unresolved(f"file {specifier!r} not found")

        aliases = self._aliases_for(source_dir)
        if aliases is not None:
            for pattern, targets in aliases.paths:
                prefix, star, suffix = pattern.partition("*")
                if star:
                    if not (
                        specifier.startswith(prefix)
                        and specifier.endswith(suffix)
                        and len(specifier) >= len(prefix) + len(suffix)
                    ):
                        continue
                    matched = specifier[
                        len(prefix) : len(specifier) - len(suffix) if suffix else None
                    ]
                elif specifier != pattern:
                    continue
                else:
                    matched = ""
                for target in targets:
                    base = _join(aliases.base_dir, target.replace("*", matched, 1))
                    if base is not None and (found := self._probe(base)):
                        return internal(found, "tsconfig-paths")
                return unresolved(f"path alias {pattern!r} matched but no file found")
            if aliases.base_url is not None:
                base = _join(aliases.base_url, specifier)
                if base is not None and (found := self._probe(base)):
                    return internal(found, "tsconfig-baseUrl")

        package = self.package_name(specifier)
        workspace_dir = self._workspace_packages.get(package)
        if workspace_dir is not None and self._package_root(source_dir) != workspace_dir:
            subpath = specifier[len(package) :].lstrip("/")
            for base in (
                [_join(workspace_dir, subpath), _join(workspace_dir, "src", subpath)]
                if subpath
                else [workspace_dir, _join(workspace_dir, "src")]
            ):
                if base is not None and (found := self._probe(base)):
                    return internal(found, "workspace-package")

        declared = self._declared(source_dir, package)
        if not declared and re.match(r"^[@~#]/", specifier):
            # Bundler aliases without a tsconfig entry ("@/x" -> src/x); scoped npm
            # packages never look like "@/".
            alias_root = self._package_root(source_dir) or ""
            rest = specifier[2:]
            for base in (_join(alias_root, "src", rest), _join(alias_root, rest)):
                if base is not None and (found := self._probe(base)):
                    return internal(found, "heuristic-alias")
            return unresolved(f"alias {specifier[:2]!r} is not configured in tsconfig/jsconfig")
        if not declared:
            package_root = self._package_root(source_dir)
            first = specifier.split("/", 1)[0]
            if (
                package_root is not None
                and (candidate := _join(package_root, first))
                and candidate in self.index.dirs
                and candidate != package_root
            ):
                # e.g. `import x from "src/utils"` with a bundler/NODE_PATH root alias
                rooted = _join(package_root, specifier)
                if rooted is not None and (found := self._probe(rooted)):
                    return internal(found, "heuristic-project-root")
        return [
            ResolvedImport(
                source,
                raw,
                ImportStatus.EXTERNAL,
                package,
                "declared" if declared else "undeclared",
            )
        ]


# ----------------------------------------------------------------------------- facade


@dataclass(frozen=True)
class ResolutionStats:
    total: int
    internal: int
    external: int
    asset: int
    unresolved: int
    undeclared_external: int

    @property
    def coverage(self) -> float:
        """Share of imports classified (internal, asset or external)."""
        return 1.0 if self.total == 0 else (self.total - self.unresolved) / self.total


def resolve_imports(index: RepoIndex, modules: list[ParsedModule]) -> list[ResolvedImport]:
    python, js = PythonResolver(index), JsResolver(index)
    resolved: list[ResolvedImport] = []
    for module in modules:
        resolver: PythonResolver | JsResolver = python if module.language == "python" else js
        for raw in module.imports:
            try:
                resolved.extend(resolver.resolve(module.path, raw))
            except Exception:  # one odd import must not stop the scan
                logger.exception("resolving %r in %s failed", raw.specifier, module.path)
                resolved.append(
                    ResolvedImport(
                        module.path, raw, ImportStatus.UNRESOLVED, reason="resolver error"
                    )
                )
    return resolved


def resolution_stats(resolved: list[ResolvedImport]) -> ResolutionStats:
    """Counts per import statement: `from x import a, b` with two submodule targets counts once."""
    by_statement: dict[tuple[str, int, str, str], list[ResolvedImport]] = {}
    for item in resolved:
        key = (item.source, item.raw.line, item.raw.kind, item.raw.specifier)
        by_statement.setdefault(key, []).append(item)
    counts = {status: 0 for status in ImportStatus}
    undeclared = 0
    for items in by_statement.values():
        status = min((i.status for i in items), key=list(ImportStatus).index)
        if any(i.status is ImportStatus.UNRESOLVED for i in items):
            status = ImportStatus.UNRESOLVED
        counts[status] += 1
        undeclared += int(status is ImportStatus.EXTERNAL and items[0].method == "undeclared")
    return ResolutionStats(
        total=len(by_statement),
        internal=counts[ImportStatus.INTERNAL],
        external=counts[ImportStatus.EXTERNAL],
        asset=counts[ImportStatus.ASSET],
        unresolved=counts[ImportStatus.UNRESOLVED],
        undeclared_external=undeclared,
    )

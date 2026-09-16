"""Heuristic architectural layers and entrypoints, inferred from path conventions.

Two stacks, each ordered top (0) to bottom:
- backend:  presentation (routes, controllers, views) -> service -> data (models, db)
- frontend: ui (components, pages) -> hooks -> api (clients) -> store (state)

The nearest matching path segment wins: `app/models/routes_helper.py` is
presentation, `app/routes/models.py` is data. Only the last word of a segment is
matched (`user_service.py`, `user.controller.ts`, `api_routes/`). Modules without
a match (utils, core, config, types) have no layer and never violate layering.
"""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

BACKEND = "backend"
FRONTEND = "frontend"

STACKS: dict[str, tuple[str, ...]] = {
    BACKEND: ("presentation", "service", "data"),
    FRONTEND: ("ui", "hooks", "api", "store"),
}

# word -> layer. Plural and singular forms.
_BACKEND_WORDS: dict[str, str] = {
    **dict.fromkeys(
        (
            "route",
            "routes",
            "router",
            "routers",
            "controller",
            "controllers",
            "handler",
            "handlers",
            "endpoint",
            "endpoints",
            "view",
            "views",
            "resource",
            "resources",
        ),
        "presentation",
    ),
    **dict.fromkeys(
        (
            "service",
            "services",
            "usecase",
            "usecases",
            "interactor",
            "interactors",
            "manager",
            "managers",
        ),
        "service",
    ),
    **dict.fromkeys(
        (
            "model",
            "models",
            "entity",
            "entities",
            "repository",
            "repositories",
            "repo",
            "repos",
            "dao",
            "daos",
            "db",
            "database",
            "orm",
        ),
        "data",
    ),
}
_FRONTEND_WORDS: dict[str, str] = {
    **dict.fromkeys(
        (
            "component",
            "components",
            "page",
            "pages",
            "screen",
            "screens",
            "layout",
            "layouts",
            "container",
            "containers",
            "widget",
            "widgets",
        ),
        "ui",
    ),
    **dict.fromkeys(("hook", "hooks", "composable", "composables"), "hooks"),
    **dict.fromkeys(
        ("api", "apis", "client", "clients", "query", "queries", "request", "requests"), "api"
    ),
    **dict.fromkeys(
        (
            "store",
            "stores",
            "state",
            "redux",
            "slice",
            "slices",
            "reducer",
            "reducers",
            "atom",
            "atoms",
        ),
        "store",
    ),
}
# Words that mean different things per language/project type.
_PYTHON_OVERRIDES = {"api": ("presentation", BACKEND), "apis": ("presentation", BACKEND)}
_TEST_WORDS = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "e2e", "testing", "cypress", "playwright"}
)

_ENTRYPOINT_NAMES = frozenset(
    {
        "__main__.py",
        "__init__.py",
        "manage.py",
        "wsgi.py",
        "asgi.py",
        "setup.py",
        "conftest.py",
        "noxfile.py",
        "fabfile.py",
        "tasks.py",
    }
)
_ENTRYPOINT_STEMS = frozenset(
    {"main", "index", "server", "cli", "app", "worker", "celery", "run", "entry"}
)
_ROUTING_STEMS = frozenset(
    {
        "page",
        "layout",
        "route",
        "loading",
        "error",
        "not-found",
        "template",
        "middleware",
        "_app",
        "_document",
    }
)
_ENTRYPOINT_DIRS = frozenset(
    {
        "scripts",
        "script",
        "bin",
        "examples",
        "example",
        "docs",
        "docs_src",
        "migrations",
        "versions",
        "benchmarks",
        "bench",
        "stories",
        "fixtures",
    }
)


def _words(segment: str) -> list[str]:
    """`user.controller.ts` -> [user, controller]; `UserService` -> [user, service]."""
    base = re.sub(r"\.(py|[cm]?[jt]sx?)$", "", segment)
    words: list[str] = []
    for token in re.split(r"[._\-\s]+", base):
        words.extend(w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", token))
    return words


@dataclass(frozen=True)
class LayerInfo:
    layer: str | None
    stack: str | None
    is_test: bool
    # Directory whose name gave the layer ("src/components"), or the file itself.
    layer_root: str | None = None

    @property
    def rank(self) -> int | None:
        if self.layer is None or self.stack is None:
            return None
        return STACKS[self.stack].index(self.layer)


def _match_segment(
    segment: str, is_file: bool, stem: str, language: str, frontend_project: bool
) -> tuple[str, str] | None:
    """(layer, stack) named by one path segment, if any."""
    words = _words(segment)
    if not words:
        return None
    if language != "python" and is_file and re.match(r"^use[A-Z0-9]", stem):
        return "hooks", FRONTEND
    word = words[-1]
    if language == "python":
        if word in _PYTHON_OVERRIDES:
            return _PYTHON_OVERRIDES[word]
        return (_BACKEND_WORDS[word], BACKEND) if word in _BACKEND_WORDS else None
    if frontend_project:
        if word in _FRONTEND_WORDS:
            return _FRONTEND_WORDS[word], FRONTEND
        if word in {"service", "services"}:
            return "api", FRONTEND  # React "services/" are API clients
    if word in _BACKEND_WORDS:
        return _BACKEND_WORDS[word], BACKEND
    if not frontend_project and word in {"api", "apis"}:
        return "presentation", BACKEND
    return None


def infer_layer(path: str, language: str, frontend_project: bool) -> LayerInfo:
    """Layer of a module. `frontend_project`: its JS/TS project has UI directories."""
    posix = PurePosixPath(path)
    segments = [*posix.parent.parts, posix.name]
    if any(w in _TEST_WORDS for s in segments for w in _words(s)) or re.search(
        r"(^test_|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$)", posix.name
    ):
        return LayerInfo(None, None, is_test=True)

    for index, segment in enumerate(reversed(segments)):
        matched = _match_segment(segment, index == 0, posix.stem, language, frontend_project)
        if matched is not None:
            layer, stack = matched
            return LayerInfo(layer, stack, False, "/".join(segments[: len(segments) - index]))
    return LayerInfo(None, None, is_test=False)


def is_frontend_path(path: str) -> bool:
    """Path suggests UI code (used to classify a JS/TS project as frontend)."""
    posix = PurePosixPath(path)
    if posix.suffix in {".tsx", ".jsx"}:
        return True
    return any(
        _FRONTEND_WORDS.get(w) in {"ui", "hooks"}
        for s in posix.parent.parts
        for w in _words(s)[-1:]
    )


def is_entrypoint(path: str, language: str, is_test: bool) -> bool:
    """Modules expected to have no importers: scripts, tests, packages, framework entries."""
    posix = PurePosixPath(path)
    if is_test or posix.name in _ENTRYPOINT_NAMES or posix.name.startswith("."):
        return True  # dotfiles are tool configuration (.eslintrc.js, .lintstagedrc.js)
    stem = posix.name.split(".")[0]
    if (
        stem.lower() in _ENTRYPOINT_STEMS
        or ".config." in posix.name
        or posix.name.startswith(("setupTests", "vite-env"))
    ):
        return True
    if any(part.lower() in _ENTRYPOINT_DIRS for part in posix.parent.parts):
        return True
    if language != "python":
        # File-system routing (Next.js, Remix, SvelteKit, Nuxt) and stories.
        if ".stories." in posix.name or stem in _ROUTING_STEMS or "pages" in posix.parent.parts:
            return True
    return False

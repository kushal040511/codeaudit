from pathlib import Path

from app.services.graph.parser import discover_source_files, parse_file
from app.services.graph.resolver import (
    RepoIndex,
    ResolvedImport,
    resolution_stats,
    resolve_imports,
)


def make_repo(root: Path, files: dict[str, str]) -> list[ResolvedImport]:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    sources = discover_source_files(root)
    modules = [parse_file(root, f) for f in sources]
    return resolve_imports(RepoIndex(root, sources), modules)


def outcome(
    resolved: list[ResolvedImport], source: str
) -> list[tuple[str, str, str | None, str | None]]:
    return [
        (r.raw.specifier, r.status.value, r.target, r.method if r.resolved else r.reason)
        for r in resolved
        if r.source == source
    ]


def test_python_absolute_relative_packages_and_externals(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "backend/pyproject.toml": (
                '[project]\nname = "svc"\ndependencies = ["PyYAML>=6", "fastapi"]\n'
            ),
            "backend/requirements-dev.txt": "pytest==8.0  # tests\n-r base.txt\n",
            "backend/app/__init__.py": "",
            "backend/app/models/__init__.py": "from .user import User\n",
            "backend/app/models/user.py": "class User: ...\n",
            "backend/app/services/__init__.py": "",
            "backend/app/services/users.py": (
                "import os\n"
                "import yaml\n"
                "import requests\n"
                "import app.models.user\n"
                "from app.models import User\n"
                "from app.services import helpers\n"
                "from . import helpers as h\n"
                "from .. import models\n"
                "from ..models.user import User as U\n"
                "from ... import beyond\n"
                "from .missing import thing\n"
                "from app.nothing import x\n"
                "import fastapi.routing\n"
            ),
            "backend/app/services/helpers.py": "",
        },
    )

    assert outcome(resolved, "backend/app/services/users.py") == [
        ("os", "external", "os", "stdlib"),
        ("yaml", "external", "yaml", "declared"),  # PyYAML
        ("requests", "external", "requests", "undeclared"),
        ("app.models.user", "internal", "backend/app/models/user.py", "absolute"),
        ("app.models", "internal", "backend/app/models/__init__.py", "absolute"),
        ("app.services", "internal", "backend/app/services/helpers.py", "absolute"),  # submodule
        ("", "internal", "backend/app/services/helpers.py", "relative"),
        ("", "internal", "backend/app/models/__init__.py", "relative"),  # `from .. import models`
        ("models.user", "internal", "backend/app/models/user.py", "relative"),
        ("", "unresolved", None, "relative import beyond the top-level package"),
        ("missing", "unresolved", None, "relative module '.missing' not found"),
        (
            "app.nothing",
            "unresolved",
            None,
            "module 'app.nothing' not found in internal package 'app'",
        ),
        ("fastapi.routing", "external", "fastapi", "declared"),
    ]
    assert outcome(resolved, "backend/app/models/__init__.py") == [
        ("user", "internal", "backend/app/models/user.py", "relative")
    ]


def test_python_relative_beyond_root_and_dynamic(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {"top.py": "from .. import x\nimport importlib\nimportlib.import_module(name)\n"},
    )

    assert outcome(resolved, "top.py") == [
        ("", "unresolved", None, "relative import beyond the top-level package"),
        ("importlib", "external", "importlib", "stdlib"),
        ("name", "unresolved", None, "dynamic import with a non-literal module name"),
    ]


def test_python_src_layout_scripts_and_namespace_packages(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "src/mylib/__init__.py": "",
            "src/mylib/core.py": "",
            "tests/test_core.py": "from mylib.core import run\nfrom helpers import util\n",
            "tests/helpers.py": "",
            "pkg/__init__.py": "",
            "pkg/types.py": "from typing import Any\nimport helpers\n",
            "pkg/typing.py": "",
            "ns/plugins/csv_plugin.py": "",  # namespace package: no __init__.py
            "scripts/run.py": "from ns.plugins import csv_plugin\nimport ns.plugins\n",
            "alembic/env.py": "from alembic import context\n",  # local dir named like a package
            "requirements.txt": "alembic\n",
        },
    )

    assert outcome(resolved, "tests/test_core.py") == [
        ("mylib.core", "internal", "src/mylib/core.py", "absolute"),
        ("helpers", "internal", "tests/helpers.py", "absolute"),  # script directory on sys.path
    ]
    # Inside a package the module's own directory is not on sys.path.
    assert outcome(resolved, "pkg/types.py") == [
        ("typing", "external", "typing", "stdlib"),
        ("helpers", "external", "helpers", "undeclared"),
    ]
    assert outcome(resolved, "scripts/run.py") == [
        ("ns.plugins", "internal", "ns/plugins/csv_plugin.py", "absolute"),
        ("ns.plugins", "internal", None, "namespace-package"),
    ]
    # The installed package wins over a local namespace directory with the same name.
    assert outcome(resolved, "alembic/env.py") == [("alembic", "external", "alembic", "declared")]


def test_js_relative_extensions_index_esm_and_assets(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "web/package.json": '{"dependencies": {"react": "18", "@tanstack/react-query": "5"}}',
            "web/src/main.tsx": (
                "import App from './App'\n"
                "import { api } from './lib'\n"
                "import client from './api/client.js'\n"
                "import './index.css'\n"
                "import logo from './logo.svg?react'\n"
                "import data from '../data.json'\n"
                "import type { T } from './types'\n"
                "import React from 'react'\n"
                "import { useQuery } from '@tanstack/react-query/build'\n"
                "import fs from 'node:fs'\n"
                "import path from 'path'\n"
                "import lodash from 'lodash'\n"
                "import gone from './gone'\n"
                "import far from '../../../outside'\n"
                "import remote from 'https://esm.sh/preact'\n"
                "const x = require('./App.tsx')\n"
                "import icon from '/assets/icon.svg'\n"
            ),
            "web/public/assets/icon.svg": "",
            "web/src/App.tsx": "export default function App() { return null }\n",
            "web/src/lib/index.ts": "export const api = 1\n",
            "web/src/api/client.ts": "export default {}\n",
            "web/src/index.css": "",
            "web/src/logo.svg": "",
            "web/data.json": "{}",
            "web/src/types.d.ts": "export type T = 1\n",
        },
    )

    assert outcome(resolved, "web/src/main.tsx") == [
        ("./App", "internal", "web/src/App.tsx", "relative"),
        ("./lib", "internal", "web/src/lib/index.ts", "relative"),
        ("./api/client.js", "internal", "web/src/api/client.ts", "relative"),
        ("./index.css", "asset", "web/src/index.css", "relative"),
        ("./logo.svg?react", "asset", "web/src/logo.svg", "relative"),
        ("../data.json", "asset", "web/data.json", "relative"),
        ("./types", "asset", "web/src/types.d.ts", "relative"),
        ("react", "external", "react", "declared"),
        ("@tanstack/react-query/build", "external", "@tanstack/react-query", "declared"),
        ("node:fs", "external", "fs", "node-builtin"),
        ("path", "external", "path", "node-builtin"),
        ("lodash", "external", "lodash", "undeclared"),
        ("./gone", "unresolved", None, "file './gone' not found"),
        ("../../../outside", "unresolved", None, "relative import beyond the repository root"),
        ("https://esm.sh/preact", "external", "https://esm.sh/preact", "url"),
        ("./App.tsx", "internal", "web/src/App.tsx", "relative"),
        ("/assets/icon.svg", "asset", "web/public/assets/icon.svg", "root-relative"),
    ]


def test_tsconfig_paths_with_references_extends_comments_and_base_url(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "app/package.json": '{"name": "app", "dependencies": {"shared-ui": "workspace:*"}}',
            "app/tsconfig.json": (
                '{\n  // references only\n  "files": [],\n'
                '  "references": [{"path": "./tsconfig.app.json"}],\n}'
            ),
            "app/tsconfig.base.json": (
                '{"compilerOptions": {"baseUrl": "./src",'
                ' "paths": {"@/*": ["./*"], "~lib": ["./lib/index.ts"]}}}'
            ),
            "app/tsconfig.app.json": (
                '{"extends": "./tsconfig.base.json", /* inherits paths */'
                ' "compilerOptions": {"strict": true}}'
            ),
            "app/src/pages/Home.tsx": (
                "import { Button } from '@/components/Button'\n"
                "import lib from '~lib'\n"
                "import util from 'utils/format'\n"
                "import { Card } from 'shared-ui'\n"
                "import { theme } from 'shared-ui/theme'\n"
                "import missing from '@/nope'\n"
            ),
            "app/src/components/Button.tsx": "export const Button = 1\n",
            "app/src/lib/index.ts": "export default 1\n",
            "app/src/utils/format.ts": "export default 1\n",
            "packages/shared-ui/package.json": '{"name": "shared-ui", "main": "src/index.ts"}',
            "packages/shared-ui/src/index.ts": "export const Card = 1\n",
            "packages/shared-ui/theme.ts": "export const theme = 1\n",
        },
    )

    assert outcome(resolved, "app/src/pages/Home.tsx") == [
        ("@/components/Button", "internal", "app/src/components/Button.tsx", "tsconfig-paths"),
        ("~lib", "internal", "app/src/lib/index.ts", "tsconfig-paths"),
        ("utils/format", "internal", "app/src/utils/format.ts", "tsconfig-baseUrl"),
        ("shared-ui", "internal", "packages/shared-ui/src/index.ts", "workspace-package"),
        ("shared-ui/theme", "internal", "packages/shared-ui/theme.ts", "workspace-package"),
        ("@/nope", "unresolved", None, "path alias '@/*' matched but no file found"),
    ]


def test_js_alias_heuristics_without_tsconfig(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "package.json": "{}",
            "src/App.jsx": (
                "import Nav from '@/components/Nav'\n"
                "import api from 'src/api'\n"
                "import gone from '~/missing'\n"
                "const plugin = require(name)\n"
            ),
            "src/components/Nav.jsx": "export default 1\n",
            "src/api/index.js": "module.exports = {}\n",
        },
    )

    assert outcome(resolved, "src/App.jsx") == [
        ("@/components/Nav", "internal", "src/components/Nav.jsx", "heuristic-alias"),
        ("src/api", "internal", "src/api/index.js", "heuristic-project-root"),
        ("~/missing", "unresolved", None, "alias '~/' is not configured in tsconfig/jsconfig"),
        ("name", "unresolved", None, "dynamic import with a non-literal specifier"),
    ]


def test_resolution_stats_count_statements_once(tmp_path: Path) -> None:
    resolved = make_repo(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": "",
            "pkg/b.py": "",
            "main.py": "from pkg import a, b\nimport os\nfrom .x import y\nimport requests\n",
        },
    )

    stats = resolution_stats(resolved)

    assert (stats.total, stats.internal, stats.external, stats.unresolved) == (4, 1, 2, 1)
    assert stats.undeclared_external == 1
    assert stats.coverage == 0.75

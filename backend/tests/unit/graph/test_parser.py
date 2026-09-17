from pathlib import Path

from app.services.graph.parser import RawImport, discover_source_files, parse_file


def parse(tmp_path: Path, name: str, source: str):  # type: ignore[no-untyped-def]
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    return parse_file(tmp_path, name)


def specs(module) -> list[tuple[str, str, int]]:  # type: ignore[no-untyped-def]
    return [(i.specifier, i.kind, i.level) for i in module.imports]


def test_python_import_forms(tmp_path: Path) -> None:
    module = parse(
        tmp_path,
        "pkg/mod.py",
        """import os
import a.b.c as abc, json
from . import sibling
from .. import parent_thing
from .models import User, Order as O
from ...deep.pkg import thing
from x.y import *
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app.types import T
else:
    import runtime_only

def load():
    import lazy_mod
    return importlib.import_module("plugins.csv")

importlib.import_module(name)
""",
    )

    assert module.error is None
    assert specs(module) == [
        ("os", "import", 0),
        ("a.b.c", "import", 0),
        ("json", "import", 0),
        ("", "from", 1),
        ("", "from", 2),
        ("models", "from", 1),
        ("deep.pkg", "from", 3),
        ("x.y", "from", 0),
        ("typing", "from", 0),
        ("app.types", "from", 0),
        ("runtime_only", "import", 0),
        ("lazy_mod", "import", 0),
        ("plugins.csv", "dynamic-import", 0),
        ("name", "dynamic-import", 0),
    ]
    by_spec = {i.specifier: i for i in module.imports}
    assert by_spec["models"].names == ("User", "Order")
    assert module.imports[3].names == ("sibling",)
    assert module.imports[4].names == ("parent_thing",)
    assert by_spec["x.y"].names == ()
    assert by_spec["app.types"].type_only and not by_spec["runtime_only"].type_only
    assert by_spec["lazy_mod"].lazy and not by_spec["os"].lazy
    assert by_spec["plugins.csv"].lazy and not by_spec["plugins.csv"].dynamic
    assert by_spec["name"].dynamic
    assert by_spec["models"].line == 5
    assert by_spec["models"].statement == "from .models import User, Order as O"


def test_python_symbols_and_size(tmp_path: Path) -> None:
    module = parse(
        tmp_path,
        "service.py",
        """
@decorator
class UserService:
    def get(self): ...

    def put(self): ...


def helper():
    def inner(): ...


VALUE = 1
""",
    )

    assert module.symbols == ["UserService", "helper"]
    assert module.definition_count == 5  # class, 2 methods, helper, inner
    assert module.loc == 7  # blank lines excluded


def test_js_and_ts_import_forms(tmp_path: Path) -> None:
    module = parse(
        tmp_path,
        "src/app.tsx",
        """import React from 'react'
import { a, b } from "./lib"
import * as utils from '../utils/index.js'
import './styles.css'
import type { Props } from './types'
import { type A, type B } from './only-types'
import { type C, D } from './mixed'
export { x } from './reexport'
export * from '@scope/pkg/sub'
export type { Y } from './type-reexport'
import legacy = require('legacy')
const fs = require('fs')
const tpl = require(`./template`)
const dyn = require(moduleName)
const Page = lazy(() => import('./pages/Page'))
const Chunk = lazy(() => import(/* webpackChunkName: "chunk" */ './pages/Chunk'))
const other = import(`./pages/${name}`)

export default function App() { return <div /> }
export class Store {}
export const selector = () => 1
function internal() {}
""",
    )

    assert module.error is None
    assert [(i.specifier, i.kind) for i in module.imports] == [
        ("react", "import"),
        ("./lib", "import"),
        ("../utils/index.js", "import"),
        ("./styles.css", "import"),
        ("./types", "import"),
        ("./only-types", "import"),
        ("./mixed", "import"),
        ("./reexport", "export-from"),
        ("@scope/pkg/sub", "export-from"),
        ("./type-reexport", "export-from"),
        ("legacy", "require"),
        ("fs", "require"),
        ("./template", "require"),
        ("moduleName", "require"),
        ("./pages/Page", "dynamic-import"),
        ("./pages/Chunk", "dynamic-import"),
        ("`./pages/${name}`", "dynamic-import"),
    ]
    type_only = {i.specifier for i in module.imports if i.type_only}
    assert type_only == {"./types", "./only-types", "./type-reexport"}
    assert {i.specifier for i in module.imports if i.dynamic} == {"moduleName", "`./pages/${name}`"}
    assert module.symbols == ["App", "Store", "selector", "internal"]
    assert module.definition_count == 4  # App, Store, selector arrow, internal


def test_commonjs_javascript(tmp_path: Path) -> None:
    module = parse(
        tmp_path,
        "server.js",
        "const express = require('express')\nmodule.exports = function handler() {}\n",
    )

    assert module.imports == [
        RawImport(
            specifier="express",
            kind="require",
            line=1,
            statement="require('express')",
        )
    ]


def test_syntax_errors_keep_what_parsed(tmp_path: Path) -> None:
    """Broken code, or syntax the grammar lags behind, still yields its imports."""
    python = parse(tmp_path, "broken.py", "import os\ndef f(:\n    pass\n")
    typescript = parse(tmp_path, "broken.ts", "import x from './x'\nexport const = ;\n")

    assert python.error is None
    assert python.warning == "partial parse near line 2; some imports may be missing"
    assert [i.specifier for i in python.imports] == ["os"]
    assert python.loc == 3  # still measured
    assert typescript.error is None
    assert [i.specifier for i in typescript.imports] == ["./x"]


def test_oversized_and_unreadable_files(tmp_path: Path) -> None:
    (tmp_path / "bundle.js").write_bytes(b"x=1;" * 300_000)

    assert parse_file(tmp_path, "bundle.js").error == "file larger than 1024 KB"
    assert parse_file(tmp_path, "missing.py").error is not None


def test_discover_skips_vendored_generated_and_declaration_files(tmp_path: Path) -> None:
    for name in (
        "app/main.py",
        "app/types.d.ts",
        "web/index.ts",
        "web/vendor.min.js",
        "node_modules/react/index.js",
        ".venv/lib/site.py",
        "dist/bundle.js",
        "pkg.egg-info/x.py",
        "README.md",
    ):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("")

    assert discover_source_files(tmp_path) == ["app/main.py", "web/index.ts"]

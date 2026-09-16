from pathlib import Path

import pytest

from app.models import ValidationStatus
from app.services.llm.patches import normalize_patch, patch_paths, syntax_error, validate_patch

APP = """import subprocess


def ping(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True)
"""
SERVER = """const { exec } = require('child_process')

function run(dir, res) {
  exec('ls ' + dir, (err, out) => res.send(out))
}

module.exports = { run }
"""

GOOD = """--- a/api/app.py
+++ b/api/app.py
@@ -3,3 +3,3 @@
 
 def ping(host):
-    return subprocess.check_output("ping -c 1 " + host, shell=True)
+    return subprocess.check_output(["ping", "-c", "1", host])
"""


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "app.py").write_text(APP)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "server.js").write_text(SERVER)
    (tmp_path / "legacy.py").write_text("def broken(:\n    return 1\n")
    return tmp_path


def test_valid_patch_with_excerpts(repo: Path) -> None:
    result = validate_patch(repo, GOOD)

    assert result.status is ValidationStatus.VALID
    [change] = result.file_changes
    assert change["path"] == "api/app.py"
    assert "shell=True" in change["original"] and "shell=True" not in change["patched"]
    assert (repo / "api" / "app.py").read_text() == APP  # validation never touches the source


def test_wrong_hunk_counts_are_tolerated_but_wrong_context_is_not(repo: Path) -> None:
    assert (
        validate_patch(repo, GOOD.replace("@@ -3,3 +3,3 @@", "@@ -3,9 +3,12 @@")).status
        is ValidationStatus.VALID
    )

    result = validate_patch(repo, GOOD.replace(" def ping(host):", " def ping(hostname):"))

    assert result.status is ValidationStatus.FAILED_TO_APPLY
    assert "patch does not apply" in (result.detail or "")
    assert result.file_changes == []


def test_python_syntax_error_after_patch(repo: Path) -> None:
    broken = GOOD.replace("host])", "host]")

    result = validate_patch(repo, broken)

    assert result.status is ValidationStatus.SYNTAX_ERROR
    assert result.detail is not None and result.detail.startswith("api/app.py:5:")


def test_javascript_patch_checked_with_tree_sitter(repo: Path) -> None:
    js_patch = """--- a/web/server.js
+++ b/web/server.js
@@ -1,5 +1,5 @@
-const { exec } = require('child_process')
+const { execFile } = require('child_process')
 
 function run(dir, res) {
-  exec('ls ' + dir, (err, out) => res.send(out))
+  execFile('ls', [dir], (err, out) => res.send(out))
 }
"""
    assert validate_patch(repo, js_patch).status is ValidationStatus.VALID

    broken = js_patch.replace("res.send(out))\n }", "res.send(out)\n }")
    result = validate_patch(repo, broken)
    assert result.status is ValidationStatus.SYNTAX_ERROR
    assert (result.detail or "").startswith("web/server.js:")


def test_file_that_never_parsed_is_not_blamed_on_the_patch(repo: Path) -> None:
    patch = """--- a/legacy.py
+++ b/legacy.py
@@ -1,2 +1,2 @@
 def broken(:
-    return 1
+    return 2
"""
    assert validate_patch(repo, patch).status is ValidationStatus.VALID


@pytest.mark.parametrize(
    ("patch", "detail"),
    [
        (GOOD.replace("api/app.py", "../outside.py"), "outside the repository"),
        (
            GOOD.replace("a/api/app.py", "/etc/passwd").replace("b/api/app.py", "/etc/passwd"),
            "outside the repository",
        ),
        (GOOD.replace("api/app.py", "api/new.py"), "does not exist"),
        ("--- /dev/null\n+++ b/api/new.py\n@@ -0,0 +1 @@\n+x = 1\n", "may not create or delete"),
        ("Just change shell=True to a list.", "Not a unified diff"),
    ],
)
def test_unsafe_or_malformed_patches_rejected_before_git(
    repo: Path, patch: str, detail: str
) -> None:
    result = validate_patch(repo, patch)

    assert result.status is ValidationStatus.FAILED_TO_APPLY
    assert detail in (result.detail or "")


def test_empty_and_fenced_patches(repo: Path) -> None:
    assert validate_patch(repo, "").status is ValidationStatus.NO_PATCH
    assert validate_patch(repo, None).status is ValidationStatus.NO_PATCH
    assert validate_patch(repo, f"```diff\n{GOOD}```").status is ValidationStatus.VALID
    assert normalize_patch(f"```diff\n{GOOD}```") == GOOD


def test_tree_sitter_syntax_check_is_lenient_for_some_errors() -> None:
    # Known limitation: tree-sitter is an error-tolerant parser, not a validator. It
    # rejects unbalanced brackets and malformed declarations but accepts some invalid
    # code, so a JS/TS patch marked valid can still fail to compile.
    assert syntax_error("x.ts", "const x = { a: 1,, }") is None
    assert syntax_error("x.ts", "const x = { a: 1 b: 2 }") is not None
    assert syntax_error("x.ts", "function f( { }") is not None


def test_patch_paths_and_syntax_helper() -> None:
    assert patch_paths(GOOD) == ["api/app.py"]
    assert syntax_error("x.ts", "const a: number = 1") is None
    assert syntax_error("x.ts", "const = ;") is not None
    assert syntax_error("README.md", "# anything") is None

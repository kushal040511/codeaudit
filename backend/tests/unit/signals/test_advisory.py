import time
from pathlib import Path
from typing import Any

from app.services.analyzers.advisory import AdvisoryAnalyzer, build_report, collect
from app.services.analyzers.base import ScanContext
from app.services.analyzers.signals import SignalReport
from app.services.llm.architect import advisory_digest

PYTHON = '''"""Module docstring."""

MAX_SIZE = 10


class userStore:
    """Documented class."""

    def Save(self, data):
        # a comment
        x = [v for v in data]
        for i in x:
            print(i)
        return x

    def _private(self):
        return None


def load_all(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError as e:
        return lambda q: q


def helper():
    """Documented."""
    temp = 1
    return temp
'''

TYPESCRIPT = """// line comment
const API_URL = "x";

/** Documented. */
export function fetchUser(user_id: string): string {
  const d = user_id;
  for (let i = 0; i < 3; i++) {}
  [1].map((n) => n);
  return d;
}

export const Button = () => null;

export class widget_box {
  renderItem(): void {}
}

interface Props {}

try {} catch (e) {}
try {} catch (err) {}
let obj = 1;
"""


def make_repo(root: Path) -> Path:
    (root / "pkg").mkdir()
    (root / "pkg" / "core.py").write_text(PYTHON)
    (root / "pkg" / "ui.ts").write_text(TYPESCRIPT)
    (root / "tests").mkdir()
    (root / "tests" / "test_core.py").write_text("def TestBad(x):\n    data = x\n")  # excluded
    return root


def run_collect(repo: Path) -> dict[str, Any]:
    return collect(repo, time.monotonic() + 60)


def test_naming_conformance(tmp_path: Path) -> None:
    metrics = run_collect(make_repo(tmp_path))

    assert metrics["files_parsed"] == 2
    # py variables: MAX_SIZE, self x2 (two scopes), data, x, v, i, path, f, e, q, temp
    # ts variables: API_URL, user_id, d, i, n, e, err, obj
    assert metrics["identifiers"] == 30
    assert metrics["naming"]["python"]["class"] == {"conforming": 0, "total": 1, "rate": 0.0}
    assert metrics["naming"]["python"]["function"] == {"conforming": 3, "total": 4, "rate": 0.75}
    assert metrics["naming"]["python"]["variable"]["rate"] == 1.0
    assert metrics["naming"]["typescript"]["class"] == {"conforming": 1, "total": 2, "rate": 0.5}
    assert metrics["naming"]["typescript"]["function"]["rate"] == 1.0  # Button: component
    assert metrics["naming"]["typescript"]["variable"] == {
        "conforming": 7,
        "total": 8,
        "rate": 0.875,
    }
    assert [e["location"] for e in metrics["naming_examples"]] == [
        "pkg/core.py:6",
        "pkg/core.py:9",
        "pkg/ui.ts:5",
        "pkg/ui.ts:14",
    ]


def test_single_letter_and_generic_names(tmp_path: Path) -> None:
    metrics = run_collect(make_repo(tmp_path))

    # v, i (loops), q (lambda), n (arrow), e (catch) are exempt.
    assert metrics["single_letter"] == {
        "count": 3,
        "per_1k_identifiers": 100.0,
        "examples": ["pkg/core.py:11 x", "pkg/core.py:22 f", "pkg/ui.ts:6 d"],
    }
    generic = metrics["generic_names"]
    assert generic["count"] == 4
    assert generic["per_1k_identifiers"] == 133.33
    assert generic["by_name"] == {"data": 1, "helper": 1, "temp": 1, "obj": 1}
    assert generic["examples"][0] == "pkg/core.py:9 data"


def test_comments_and_docstrings(tmp_path: Path) -> None:
    metrics = run_collect(make_repo(tmp_path))

    assert metrics["comments"]["comment_lines"] == 3
    assert metrics["comments"]["by_language"] == {
        "python": round(1 / 22, 4),
        "typescript": round(2 / 17, 4),
    }
    docstrings = metrics["docstrings"]
    # python: userStore, helper documented; Save, load_all not. ts: fetchUser only.
    assert (docstrings["documented"], docstrings["public_definitions"]) == (3, 7)
    assert docstrings["by_language"] == {"python": 0.5, "typescript": round(1 / 3, 4)}
    assert docstrings["undocumented_examples"] == [
        "pkg/core.py:9",
        "pkg/core.py:20",
        "pkg/ui.ts:12",
        "pkg/ui.ts:14",
    ]


def test_report_is_never_scored(tmp_path: Path) -> None:
    report = build_report(run_collect(make_repo(tmp_path)))

    assert report.name == "advisory"
    assert report.applicable is True
    assert report.score is None
    assert report.components == {}


def test_not_applicable_without_source_files(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello\n")

    report = build_report(run_collect(tmp_path))

    assert report.applicable is False
    assert report.reason == "no non-test Python, JavaScript or TypeScript source files"


def test_analyzer_never_emits_findings(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    make_repo(repo)
    work = tmp_path / "work"
    work.mkdir()

    result = AdvisoryAnalyzer().run(repo, ScanContext(scan_id="s", work_dir=work, languages=[]))

    assert result.success is True
    assert result.findings == []
    assert AdvisoryAnalyzer().parse(result.raw_output) == []
    assert isinstance(result.artifact, SignalReport)
    assert result.artifact.metrics["identifiers"] == 30


def test_architecture_digest_summary(tmp_path: Path) -> None:
    stored = build_report(run_collect(make_repo(tmp_path))).as_dict()

    digest = advisory_digest(stored)

    assert digest is not None
    assert digest["naming_conformance"] == {"python": 0.8824, "typescript": 0.8462}
    assert digest["single_letter_per_1k_identifiers"] == 100.0
    assert digest["docstring_coverage"] == round(3 / 7, 4)
    assert len(digest["examples"]) == 8  # 4 naming + 4 generic, capped at 10
    assert digest["examples"][0] == "pkg/core.py:6 class 'userStore' (expected PascalCase)"
    assert advisory_digest(None) is None
    assert advisory_digest({"applicable": False, "metrics": {}}) is None

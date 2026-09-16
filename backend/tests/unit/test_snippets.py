from pathlib import Path

import pytest

from app.services.analyzers.snippets import fill_snippets, normalize_path, read_snippet
from tests.fakes import make_finding


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/src/api/app.py", "api/app.py"),
        ("./api/app.py", "api/app.py"),
        ("api//app.py", "api/app.py"),
        ("api\\app.py", "api/app.py"),
        ("app.py", "app.py"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


def test_fill_snippets_reads_missing_ones_only(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nthree\n")
    missing = make_finding(start_line=2, end_line=3)
    present = make_finding(start_line=1, code_snippet="from the tool")
    outside = make_finding(file_path="../etc/passwd", start_line=1)

    filled = fill_snippets([missing, present, outside], tmp_path)

    assert [f.code_snippet for f in filled] == ["two\nthree", "from the tool", None]
    assert read_snippet(tmp_path, "nope.py", 1, 1) is None

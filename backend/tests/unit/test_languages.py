from pathlib import Path

from app.services.languages import DetectedLanguage, detect_languages


def touch(root: Path, rel: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")


def test_detects_languages_by_extension_and_manifest(tmp_path: Path) -> None:
    for rel in [
        "app.py",
        "pkg/util.py",
        "requirements.txt",
        "web/index.ts",
        "web/package.json",
        "web/node_modules/lib/index.js",  # vendored: ignored
        "go.mod",
    ]:
        touch(tmp_path, rel)

    assert detect_languages(tmp_path) == [
        DetectedLanguage("python", 2, ["requirements.txt"]),
        DetectedLanguage("typescript", 1, []),
        DetectedLanguage("go", 0, ["go.mod"]),
        DetectedLanguage("javascript", 0, ["web/package.json"]),
    ]


def test_empty_tree(tmp_path: Path) -> None:
    assert detect_languages(tmp_path) == []

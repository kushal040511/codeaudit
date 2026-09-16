import io
import stat
import zipfile
from pathlib import Path

import pytest

from app.services.archive import ArchiveLimits, UnsafeArchiveError, inspect_zip, safe_extract

LIMITS = ArchiveLimits(max_files=10, max_total_bytes=1024 * 1024, max_file_bytes=256 * 1024)


def build_zip(entries: dict[str, bytes], *, symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3  # unix, so external_attr carries the file mode
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def write_zip(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "upload.zip"
    path.write_bytes(data)
    return path


def test_safe_extract_writes_files_inside_dest(tmp_path: Path) -> None:
    archive = write_zip(
        tmp_path, build_zip({"repo/app.py": b"print('hi')\n", "repo/pkg/util.py": b"x = 1\n"})
    )
    dest = tmp_path / "out"

    summary = safe_extract(archive, dest, LIMITS)

    assert summary.file_count == 2
    assert (dest / "repo/app.py").read_bytes() == b"print('hi')\n"
    assert stat.S_IMODE((dest / "repo/pkg/util.py").stat().st_mode) == 0o644


@pytest.mark.parametrize(
    "name",
    [
        "../evil.txt",
        "repo/../../evil.txt",
        "/etc/evil.txt",
        "C:/evil.txt",
        "repo\\..\\..\\evil.txt",
    ],
)
def test_rejects_path_traversal(tmp_path: Path, name: str) -> None:
    archive = write_zip(tmp_path, build_zip({"ok.txt": b"fine", name: b"pwned"}))
    dest = tmp_path / "nested" / "out"

    with pytest.raises(UnsafeArchiveError):
        safe_extract(archive, dest, LIMITS)

    assert not list(tmp_path.rglob("evil.txt"))
    # Validation runs before extraction starts, so nothing is written at all.
    assert not (dest / "ok.txt").exists()


def test_rejects_symlink_entries(tmp_path: Path) -> None:
    data = build_zip({"ok.txt": b"fine"}, symlinks={"link": "/etc/passwd"})

    with pytest.raises(UnsafeArchiveError, match="symbolic link"):
        inspect_zip(io.BytesIO(data), LIMITS)


def test_rejects_too_many_files() -> None:
    data = build_zip({f"f{i}.txt": b"x" for i in range(LIMITS.max_files + 1)})

    with pytest.raises(UnsafeArchiveError, match="more than 10 files"):
        inspect_zip(io.BytesIO(data), LIMITS)


def test_directories_do_not_count_towards_file_limit() -> None:
    entries = {f"d{i}/": b"" for i in range(20)} | {f"d{i}/f.txt": b"x" for i in range(10)}

    assert inspect_zip(io.BytesIO(build_zip(entries)), LIMITS).file_count == 10


def test_rejects_oversized_entry() -> None:
    data = build_zip({"big.bin": b"\0" * (LIMITS.max_file_bytes + 1)})

    with pytest.raises(UnsafeArchiveError, match="too large"):
        inspect_zip(io.BytesIO(data), LIMITS)


def test_rejects_non_zip_and_empty_archives() -> None:
    with pytest.raises(UnsafeArchiveError, match="not a zip"):
        inspect_zip(io.BytesIO(b"definitely not a zip"), LIMITS)
    with pytest.raises(UnsafeArchiveError, match="no files"):
        inspect_zip(io.BytesIO(build_zip({"empty-dir/": b""})), LIMITS)

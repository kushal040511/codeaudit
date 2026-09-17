"""Validation and safe extraction of untrusted zip archives."""

import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO

from app.core.errors import AnalysisError

if TYPE_CHECKING:
    from app.config import Settings

_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_CHUNK = 64 * 1024


class UnsafeArchiveError(AnalysisError):
    """The archive is malformed, too large, or has entries that could escape extraction."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_files: int
    max_total_bytes: int
    max_file_bytes: int


@dataclass(frozen=True)
class ArchiveSummary:
    file_count: int
    declared_uncompressed_bytes: int


def archive_limits_from_settings(settings: "Settings") -> ArchiveLimits:
    return ArchiveLimits(
        max_files=settings.max_archive_files,
        max_total_bytes=settings.max_extracted_size_mb * 1024 * 1024,
        max_file_bytes=settings.max_extracted_file_size_mb * 1024 * 1024,
    )


def validate_member_name(name: str) -> PurePosixPath:
    """Return the entry path if it is a plain relative path, else raise."""
    if not name or "\x00" in name:
        raise UnsafeArchiveError("Archive contains an entry with an empty or invalid name.")
    if "\\" in name:
        raise UnsafeArchiveError(f"Archive entry uses backslashes: {name!r}")
    if name.startswith("/") or _WINDOWS_DRIVE.match(name):
        raise UnsafeArchiveError(f"Archive entry has an absolute path: {name!r}")
    path = PurePosixPath(name)
    if ".." in path.parts:
        raise UnsafeArchiveError(f"Archive entry escapes the archive root: {name!r}")
    return path


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def inspect_zip(fileobj: BinaryIO, limits: ArchiveLimits) -> ArchiveSummary:
    """Validate an archive from its central directory, without extracting anything.

    Header sizes can lie; `safe_extract` re-checks limits against real bytes.
    """
    fileobj.seek(0)
    if fileobj.read(4) != _ZIP_LOCAL_HEADER:
        raise UnsafeArchiveError("File is not a zip archive.")
    fileobj.seek(0)
    try:
        with zipfile.ZipFile(fileobj) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, EOFError) as exc:
        raise UnsafeArchiveError("Zip archive is corrupt or unsupported.") from exc

    file_count = 0
    declared_total = 0
    for info in infos:
        validate_member_name(info.filename)
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError("Encrypted zip archives are not supported.")
        if _is_symlink(info):
            raise UnsafeArchiveError(f"Archive entry is a symbolic link: {info.filename!r}")
        if info.is_dir():
            continue
        file_count += 1
        if file_count > limits.max_files:
            raise UnsafeArchiveError(f"Archive contains more than {limits.max_files} files.")
        if info.file_size > limits.max_file_bytes:
            raise UnsafeArchiveError(f"Archive entry is too large: {info.filename!r}")
        declared_total += info.file_size
        if declared_total > limits.max_total_bytes:
            raise UnsafeArchiveError("Archive expands beyond the allowed size.")

    if file_count == 0:
        raise UnsafeArchiveError("Archive contains no files.")
    return ArchiveSummary(file_count=file_count, declared_uncompressed_bytes=declared_total)


def safe_extract(archive_path: Path, dest: Path, limits: ArchiveLimits) -> ArchiveSummary:
    """Extract an untrusted archive into `dest`.

    Every entry is re-validated (the worker doesn't trust the API's checks), paths
    are confined to `dest`, byte limits apply to actual decompressed data (zip
    bombs), symlinks are never created, and permissions are normalised
    (0644 files, 0755 dirs) so the unprivileged sandbox user can read them.
    """
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()

    with archive_path.open("rb") as fh:
        summary = inspect_zip(fh, limits)
        fh.seek(0)
        try:
            with zipfile.ZipFile(fh) as zf:
                written_total = 0
                for info in zf.infolist():
                    target = (root / validate_member_name(info.filename)).resolve()
                    if target != root and not target.is_relative_to(root):
                        raise UnsafeArchiveError(
                            f"Archive entry escapes the extraction root: {info.filename!r}"
                        )
                    if info.is_dir():
                        target.mkdir(mode=0o750, parents=True, exist_ok=True)
                        continue

                    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                    written = 0
                    with zf.open(info) as src, target.open("wb") as out:
                        while chunk := src.read(_CHUNK):
                            written += len(chunk)
                            written_total += len(chunk)
                            if written > limits.max_file_bytes:
                                raise UnsafeArchiveError(
                                    f"Archive entry is too large: {info.filename!r}"
                                )
                            if written_total > limits.max_total_bytes:
                                raise UnsafeArchiveError("Archive expands beyond the allowed size.")
                            out.write(chunk)
                    os.chmod(target, 0o640)
        except zipfile.BadZipFile as exc:
            raise UnsafeArchiveError("Zip archive is corrupt (CRC or header mismatch).") from exc
        except NotImplementedError as exc:
            raise UnsafeArchiveError("Zip archive uses an unsupported compression method.") from exc
        except IsADirectoryError as exc:
            raise UnsafeArchiveError(
                "Archive contains conflicting file and directory names."
            ) from exc

    return summary

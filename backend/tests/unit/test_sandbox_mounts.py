from pathlib import Path

import pytest

from app.services.analyzers.sandbox import SandboxError, SandboxMount, _to_docker_mount


def test_volume_subpath_mounts_never_copy_image_content(tmp_path: Path) -> None:
    source = tmp_path / "scan-1" / "src"
    source.mkdir(parents=True)
    mount = _to_docker_mount(SandboxMount(source, "/src", read_only=False), tmp_path, "workspace")
    assert mount["Type"] == "volume" and mount["Source"] == "workspace"
    assert mount["ReadOnly"] is False
    # Without NoCopy, Docker copies the image's /src (and its root ownership) into an
    # empty directory, and the sandbox user can no longer write the clone there.
    assert mount["VolumeOptions"] == {"NoCopy": True, "Subpath": "scan-1/src"}


def test_host_worker_uses_bind_mounts(tmp_path: Path) -> None:
    mount = _to_docker_mount(SandboxMount(tmp_path / "a", "/src", read_only=True), tmp_path, "")
    assert mount["Type"] == "bind" and mount["ReadOnly"] is True


def test_paths_outside_the_workspace_are_refused(tmp_path: Path) -> None:
    with pytest.raises(SandboxError):
        _to_docker_mount(SandboxMount(Path("/etc"), "/src", read_only=True), tmp_path, "workspace")

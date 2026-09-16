"""Run analysis tools against untrusted code in throwaway Docker containers.

Every container gets:
- no network, a read-only root filesystem, and a size-capped tmpfs for /tmp
- an unprivileged user (nobody), all capabilities dropped, no-new-privileges
- memory (no swap), CPU and PID limits, and a wall-clock timeout that kills it
- source mounted read-only; only an explicit per-run output directory is writable

Known gaps (see README "Sandboxing"): the worker talks to the Docker daemon
through its socket, which is root-equivalent on the Docker host, and containers
share the host kernel. gVisor/Kata or a dedicated runner service is still TODO.
"""

import logging
import socket
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.types import LogConfig, Mount
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout

from app.config import get_settings
from app.core.errors import AnalysisError, TransientInfraError

logger = logging.getLogger(__name__)

SANDBOX_USER = "65534:65534"  # nobody:nogroup
SANDBOX_LABEL = "codeaudit.sandbox"
WORKER_LABEL = "codeaudit.worker"


class SandboxUnavailableError(TransientInfraError):
    """Docker daemon unreachable, image pull failed, or a daemon-side error."""


class SandboxError(AnalysisError):
    """The sandbox container could not be run as configured."""


class SandboxTimeoutError(AnalysisError):
    """The tool exceeded its time limit and the container was killed."""


@dataclass(frozen=True)
class SandboxMount:
    source: Path  # must live inside settings.scan_workspace_dir
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class SandboxLimits:
    cpus: float
    memory: str
    timeout_seconds: int
    pids: int = 512
    tmpfs_size: str = "512m"


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stderr: str
    oom_killed: bool
    duration_seconds: float


def _worker_id() -> str:
    return socket.gethostname()


def _to_docker_mount(mount: SandboxMount, workspace_root: Path, volume: str) -> Mount:
    root = workspace_root.resolve()
    source = mount.source.resolve()
    if not source.is_relative_to(root):
        raise SandboxError(f"Refusing to mount a path outside the scan workspace: {source}")

    if not volume:
        # Worker runs on the host: the daemon can see the path directly.
        return Mount(
            target=mount.target, source=str(source), type="bind", read_only=mount.read_only
        )

    # Worker runs in a container: its workspace is a named volume, so mount only
    # the relevant subdirectory of that volume (Docker Engine API >= 1.45).
    docker_mount = Mount(
        target=mount.target, source=volume, type="volume", read_only=mount.read_only
    )
    subpath = source.relative_to(root).as_posix()
    if subpath != ".":
        docker_mount["VolumeOptions"] = {"Subpath": subpath}
    return docker_mount


def _client() -> Any:
    try:
        client = docker.from_env(version="auto", timeout=60)
        client.ping()
    except DockerException as exc:
        raise SandboxUnavailableError(f"Docker daemon unavailable: {exc}") from exc
    return client


def _ensure_image(client: Any, image: str) -> None:
    try:
        client.images.get(image)
    except ImageNotFound:
        logger.info("pulling sandbox image %s", image)
        try:
            client.images.pull(image)
        except DockerException as exc:
            raise SandboxUnavailableError(f"Could not pull sandbox image {image}: {exc}") from exc
    except DockerException as exc:
        raise SandboxUnavailableError(f"Could not inspect sandbox image {image}: {exc}") from exc


def _remove_quietly(container: Any) -> None:
    try:
        container.remove(force=True)
    except NotFound:
        pass
    except DockerException:
        logger.warning("could not remove sandbox container %s", container.id, exc_info=True)


def run_in_sandbox(
    *,
    image: str,
    command: Sequence[str],
    mounts: Sequence[SandboxMount],
    limits: SandboxLimits,
    working_dir: str,
    labels: Mapping[str, str] | None = None,
) -> SandboxResult:
    """Run `command` in an isolated container and wait for it, killing it on timeout.

    The container is always removed, whether the tool succeeds, fails or times out.
    """
    settings = get_settings()
    docker_mounts = [
        _to_docker_mount(m, Path(settings.scan_workspace_dir), settings.sandbox_workspace_volume)
        for m in mounts
    ]

    client = _client()
    container: Any = None
    started = time.monotonic()
    try:
        _ensure_image(client, image)
        container = client.containers.create(
            image=image,
            command=list(command),
            working_dir=working_dir,
            user=SANDBOX_USER,
            environment={"HOME": "/tmp"},  # noqa: S108 - tmpfs inside the container
            network_mode="none",
            read_only=True,
            tmpfs={"/tmp": f"rw,nosuid,nodev,size={limits.tmpfs_size}"},  # noqa: S108
            mounts=docker_mounts,
            mem_limit=limits.memory,
            memswap_limit=limits.memory,  # no swap
            nano_cpus=int(limits.cpus * 1_000_000_000),
            pids_limit=limits.pids,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            log_config=LogConfig(type="json-file", config={"max-size": "10m", "max-file": "1"}),
            labels={SANDBOX_LABEL: "true", WORKER_LABEL: _worker_id(), **(labels or {})},
        )
        container.start()

        try:
            status = container.wait(timeout=limits.timeout_seconds)
        except (ReadTimeout, RequestsConnectionError) as exc:
            if time.monotonic() - started < limits.timeout_seconds:
                raise SandboxUnavailableError("Lost connection to the Docker daemon.") from exc
            try:
                container.kill()
            except DockerException:
                logger.warning("could not kill timed-out container %s", container.id)
            raise SandboxTimeoutError(
                f"Analyzer exceeded the {limits.timeout_seconds}s time limit and was stopped."
            ) from exc

        container.reload()
        return SandboxResult(
            exit_code=int(status.get("StatusCode", -1)),
            stderr=container.logs(stdout=False, stderr=True, tail=200).decode("utf-8", "replace"),
            oom_killed=bool(container.attrs.get("State", {}).get("OOMKilled")),
            duration_seconds=round(time.monotonic() - started, 2),
        )
    except APIError as exc:
        if exc.is_server_error():
            raise SandboxUnavailableError(f"Docker daemon error: {exc.explanation}") from exc
        raise SandboxError(f"Sandbox container could not be run: {exc.explanation}") from exc
    except DockerException as exc:
        raise SandboxUnavailableError(f"Docker daemon unavailable: {exc}") from exc
    finally:
        if container is not None:
            _remove_quietly(container)
        client.close()


def remove_orphaned_sandboxes() -> int:
    """Remove sandbox containers left behind by a previous (crashed) run of this worker."""
    client = _client()
    try:
        containers = client.containers.list(
            all=True, filters={"label": [f"{SANDBOX_LABEL}=true", f"{WORKER_LABEL}={_worker_id()}"]}
        )
        for container in containers:
            _remove_quietly(container)
        return len(containers)
    finally:
        client.close()

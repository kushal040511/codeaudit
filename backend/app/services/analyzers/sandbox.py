"""Run analysis tools against untrusted code in throwaway Docker containers.

Shared by every analyzer: `run_tool` mounts the repository read-only, gives the
tool a writable output directory, enforces the limits below and returns the
tool's output file. `run_in_sandbox` is the lower-level container runner.

Every container gets:
- no network, a read-only root filesystem, and a size-capped tmpfs for /tmp
- an unprivileged user (nobody, in the worker's group), all capabilities dropped,
  no-new-privileges
- memory (no swap), CPU and PID limits, and a wall-clock timeout that kills it
- source mounted read-only; only an explicit per-run output directory is writable

Known gaps (see README "Sandboxing"): the worker talks to the Docker daemon
through its socket, which is root-equivalent on the Docker host, and containers
share the host kernel. gVisor/Kata or a dedicated runner service is still TODO.
"""

import logging
import os
import socket
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, DockerException, ImageNotFound, NotFound
from docker.types import LogConfig, Mount, Ulimit
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout

from app.config import get_settings
from app.core.errors import AnalysisError, AnalyzerTimeoutError, TransientInfraError

logger = logging.getLogger(__name__)

SANDBOX_UID = 65534  # nobody


def sandbox_user() -> str:
    """nobody, in the worker's primary group: per-scan directories are shared through
    the group (0o770 / 0o750), never world-writable."""
    return f"{SANDBOX_UID}:{os.getgid()}"


SANDBOX_LABEL = "codeaudit.sandbox"
WORKER_LABEL = "codeaudit.worker"


class SandboxUnavailableError(TransientInfraError):
    """Docker daemon unreachable, image pull failed, or a daemon-side error."""


class SandboxError(AnalysisError):
    """The sandbox container could not be run as configured."""


class SandboxTimeoutError(AnalyzerTimeoutError):
    """The tool exceeded its time limit and the container was killed."""


class AnalyzerOutputError(AnalysisError):
    """The tool ran but its output could not be parsed."""


class SandboxDiskQuotaError(AnalysisError):
    """The container wrote more than its disk quota and was killed."""


class SandboxCapacityError(TransientInfraError):
    """No global sandbox slot became free in time (the job is retried later)."""


# ------------------------------------------------------------------ global capacity

SLOTS_KEY = "codeaudit:sandbox:slots"
# Atomic counting semaphore with leases: expired leases (crashed holders) are dropped.
ACQUIRE_SLOT_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, 0, now)
if redis.call('ZCARD', key) < limit then
  redis.call('ZADD', key, tonumber(ARGV[3]), ARGV[4])
  return 1
end
return 0
"""


class SandboxSlot:
    """Holds one of MAX_CONCURRENT_SANDBOXES slots shared by every worker (Redis).

    Bursts of scans queue here instead of starting more containers than the host can
    run. A lease outlives the container's own timeout, so a crashed holder's slot is
    freed automatically.
    """

    def __init__(self, lease_seconds: int) -> None:
        self.member = f"{_worker_id()}:{os.getpid()}:{time.monotonic_ns()}"
        self.lease_seconds = lease_seconds

    def __enter__(self) -> "SandboxSlot":
        from app.core import metrics
        from app.core.redis_client import get_redis

        settings = get_settings()
        redis = get_redis()
        started = time.monotonic()
        delay = 0.25
        while True:
            now = time.time()
            acquired = redis.eval(
                ACQUIRE_SLOT_LUA,
                1,
                SLOTS_KEY,
                str(now),
                str(settings.max_concurrent_sandboxes),
                str(now + self.lease_seconds),
                self.member,
            )
            if acquired:
                metrics.sandbox_slot_wait.observe(time.monotonic() - started)
                return self
            if time.monotonic() - started > settings.sandbox_slot_timeout_seconds:
                metrics.quota_rejections.labels("sandbox_slots", "sandbox").inc()
                raise SandboxCapacityError(
                    f"All {settings.max_concurrent_sandboxes} analysis sandboxes stayed busy for"
                    f" {settings.sandbox_slot_timeout_seconds}s."
                )
            time.sleep(delay)
            delay = min(delay * 1.5, 3.0)

    def __exit__(self, *_: object) -> None:
        from app.core.redis_client import get_redis

        try:
            get_redis().zrem(SLOTS_KEY, self.member)
        except Exception:  # noqa: BLE001 - the lease expires on its own
            logger.warning("could not release sandbox slot %s", self.member)


def _directory_bytes(paths: Sequence[Path], stop_after: int) -> int:
    total = 0
    stack = [p for p in paths if p.exists()]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    else:
                        total += entry.stat(follow_symlinks=False).st_size
                        if total > stop_after:
                            return total
        except OSError:
            continue
    return total


class DiskWatch:
    """Kills the container when its writable mounts exceed the quota."""

    INTERVAL_SECONDS = 1.0

    def __init__(self, container: Any, paths: Sequence[Path], quota: int) -> None:
        self.container = container
        self.paths = list(paths)
        self.quota = quota
        self.exceeded = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="sandbox-disk-watch")

    def __enter__(self) -> "DiskWatch":
        if self.paths:
            self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.wait(self.INTERVAL_SECONDS):
            if _directory_bytes(self.paths, self.quota) > self.quota:
                self.exceeded = True
                try:
                    self.container.kill()
                except DockerException:
                    pass
                return


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
    # Total bytes the container may write into its writable mounts. Enforced twice:
    # RLIMIT_FSIZE caps any single file, and a watcher kills the container when the
    # writable mounts together exceed it (zip bombs, runaway tool output, huge clones).
    disk_bytes: int = 512 * 1024 * 1024


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stderr: str
    oom_killed: bool
    duration_seconds: float


@dataclass(frozen=True)
class ToolOutput:
    raw_output: str
    exit_code: int
    stderr: str
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
    # NoCopy: an empty directory would otherwise get the image's content *and ownership*
    # at the target copied into it ("copy-up"), leaving it root-owned and unwritable
    # for the sandbox user (e.g. the clone destination).
    options: dict[str, object] = {"NoCopy": True}
    subpath = source.relative_to(root).as_posix()
    if subpath != ".":
        options["Subpath"] = subpath
    docker_mount["VolumeOptions"] = options
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
    entrypoint: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
    network: bool | str = False,
) -> SandboxResult:
    """Run `command` in an isolated container and wait for it, killing it on timeout.

    `network`: False = no network; True = bridge (git clone only); a string = that
    Docker network (the page-capture browser's internal network, whose only exit
    is the egress proxy).

    The container is always removed, whether the tool succeeds, fails or times out.
    """
    settings = get_settings()
    docker_mounts = [
        _to_docker_mount(m, Path(settings.scan_workspace_dir), settings.sandbox_workspace_volume)
        for m in mounts
    ]

    from app.core import metrics

    writable = [m.source for m in mounts if not m.read_only]
    slot = SandboxSlot(lease_seconds=limits.timeout_seconds + 300)
    slot.__enter__()
    client: Any = None
    container: Any = None
    started = time.monotonic()
    active = False
    try:
        # Inside the try: a daemon that can't be reached must still release the slot.
        client = _client()
        _ensure_image(client, image)
        container = client.containers.create(
            image=image,
            command=list(command),
            entrypoint=list(entrypoint) if entrypoint is not None else None,
            working_dir=working_dir,
            user=sandbox_user(),
            environment={**(environment or {}), "HOME": "/tmp"},  # noqa: S108 - tmpfs
            network_mode=(
                network if isinstance(network, str) else ("bridge" if network else "none")
            ),
            read_only=True,
            tmpfs={"/tmp": f"rw,nosuid,nodev,size={limits.tmpfs_size}"},  # noqa: S108
            mounts=docker_mounts,
            mem_limit=limits.memory,
            memswap_limit=limits.memory,  # no swap
            nano_cpus=int(limits.cpus * 1_000_000_000),
            pids_limit=limits.pids,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            # PID 1 reaps zombies; the kernel kills the sandbox before anything else on OOM.
            init=True,
            oom_score_adj=800,
            ulimits=[
                Ulimit(name="fsize", soft=limits.disk_bytes, hard=limits.disk_bytes),
                Ulimit(name="nofile", soft=4096, hard=4096),
                Ulimit(name="core", soft=0, hard=0),
            ],
            ipc_mode="private",
            log_config=LogConfig(type="json-file", config={"max-size": "10m", "max-file": "1"}),
            labels={SANDBOX_LABEL: "true", WORKER_LABEL: _worker_id(), **(labels or {})},
        )
        container.start()
        metrics.sandbox_containers_active.inc()
        active = True

        watch = DiskWatch(container, writable, limits.disk_bytes)
        try:
            with watch:
                status = container.wait(timeout=limits.timeout_seconds)
        except (ReadTimeout, RequestsConnectionError) as exc:
            if time.monotonic() - started < limits.timeout_seconds:
                raise SandboxUnavailableError("Lost connection to the Docker daemon.") from exc
            try:
                container.kill()
            except DockerException:
                logger.warning("could not kill timed-out container %s", container.id)
            raise SandboxTimeoutError(
                f"Exceeded the {limits.timeout_seconds}s time limit and was stopped."
            ) from exc

        if watch.exceeded:
            raise SandboxDiskQuotaError(
                f"The sandbox wrote more than {limits.disk_bytes // (1024 * 1024)} MB"
                " and was stopped."
            )
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
        if active:
            metrics.sandbox_containers_active.dec()
        if container is not None:
            _remove_quietly(container)
        if client is not None:
            client.close()
        slot.__exit__()


SOURCE_MOUNT = "/src"
OUTPUT_MOUNT = "/out"
OUTPUT_FILENAME = "results.json"
MAX_OUTPUT_BYTES = 100 * 1024 * 1024


def run_tool(
    *,
    display_name: str,
    image: str,
    command: Sequence[str],
    repo_path: Path,
    output_dir: Path,
    limits: SandboxLimits,
    ok_exit_codes: frozenset[int],
    labels: Mapping[str, str],
    extra_mounts: Sequence[SandboxMount] = (),
    entrypoint: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> ToolOutput:
    """Run one analysis tool against `repo_path` and return the output file it wrote.

    The repository is mounted read-only at SOURCE_MOUNT (also the working directory);
    `output_dir` is mounted writable at OUTPUT_MOUNT, and the tool must write
    OUTPUT_MOUNT/OUTPUT_FILENAME. Raises SandboxTimeoutError when the tool is
    killed for exceeding its time limit and SandboxError for crashes, OOM kills,
    unexpected exit codes and missing or oversized output.
    """
    output_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(output_dir, 0o770)  # noqa: S103 - shared with the sandbox through the group

    result = run_in_sandbox(
        image=image,
        command=command,
        entrypoint=entrypoint,
        environment=environment,
        working_dir=SOURCE_MOUNT,
        mounts=[
            SandboxMount(repo_path, SOURCE_MOUNT, read_only=True),
            *extra_mounts,
            SandboxMount(output_dir, OUTPUT_MOUNT, read_only=False),
        ],
        limits=limits,
        labels=labels,
    )

    if result.oom_killed:
        raise SandboxError(f"{display_name} ran out of memory (limit {limits.memory}).")
    if result.exit_code not in ok_exit_codes:
        stderr_tail = result.stderr.strip()[-500:] or "no error output"
        raise SandboxError(f"{display_name} exited with code {result.exit_code}: {stderr_tail}")

    output_path = output_dir / OUTPUT_FILENAME
    if not output_path.is_file():
        raise SandboxError(f"{display_name} finished without writing results.")
    if output_path.stat().st_size > MAX_OUTPUT_BYTES:
        raise SandboxError(f"{display_name} output exceeds the size limit.")
    return ToolOutput(
        raw_output=output_path.read_bytes().decode("utf-8", "replace"),
        exit_code=result.exit_code,
        stderr=result.stderr,
        duration_seconds=result.duration_seconds,
    )


def max_sandbox_seconds() -> int:
    """The longest any sandbox may legitimately run (plus margin)."""
    settings = get_settings()
    return (
        max(
            settings.semgrep_timeout_seconds,
            settings.bandit_timeout_seconds,
            settings.ruff_timeout_seconds,
            settings.osv_scanner_timeout_seconds,
            settings.git_clone_timeout_seconds,
            settings.web_capture_timeout_seconds + 10,
            settings.architecture_timeout_seconds,
        )
        + 120
    )


def reap_expired_sandboxes(max_age_seconds: int | None = None) -> int:
    """Remove sandbox containers (from any worker) older than the longest allowed run.

    Covers workers that died without cleaning up (OOM kill, host restart, deploy).
    """
    from datetime import UTC, datetime

    from app.core import metrics

    limit = max_sandbox_seconds() if max_age_seconds is None else max_age_seconds
    client = _client()
    removed = 0
    try:
        for container in client.containers.list(
            all=True, filters={"label": f"{SANDBOX_LABEL}=true"}
        ):
            created = container.attrs.get("Created", "")
            try:
                started = datetime.fromisoformat(created.replace("Z", "+00:00")[:26] + "+00:00")
            except ValueError:
                continue
            if (datetime.now(UTC) - started).total_seconds() > limit:
                logger.warning(
                    "reaping sandbox %s (%s) older than %ss",
                    container.short_id,
                    container.labels.get("codeaudit.analyzer"),
                    limit,
                )
                _remove_quietly(container)
                removed += 1
        metrics.sandbox_reaped.inc(removed)
        return removed
    finally:
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

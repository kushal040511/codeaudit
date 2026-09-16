"""Shallow-clone one commit of a GitHub repository inside a sandbox container.

The clone container is the only sandbox with network access. It runs as nobody
with a read-only root filesystem, dropped capabilities, memory/CPU/PID limits and
a timeout, and receives no host credentials: for private repositories the user's
token is passed only as an HTTP header through git's environment config (never
on the command line), and is redacted from any output. Git is restricted to
https, doesn't follow redirects, runs no hooks, writes symlinks as plain files and
skips LFS. The .git directory is removed afterwards and the tree is checked
against the same size limits as uploads.
"""

import base64
import logging
import os
import re
from pathlib import Path

from app.config import get_settings
from app.core.errors import AnalysisError
from app.services.analyzers.sandbox import SandboxError, SandboxLimits, SandboxMount, run_in_sandbox
from app.services.archive import ArchiveLimits
from app.services.github.urls import OWNER, REPO, SHA, UnsafeHostError, assert_public_host

logger = logging.getLogger(__name__)

CLONE_MOUNT = "/src"
# Fixed script; repository coordinates arrive as environment variables.
CLONE_SCRIPT = (
    "set -eu; umask 0000; cd /src; git init -q .; "
    'git remote add origin "$CLONE_URL"; '
    'git fetch -q --depth 1 --no-tags origin "$CLONE_SHA"; '
    "git checkout -q FETCH_HEAD; rm -rf .git"
)
GIT_CONFIG = {
    "protocol.allow": "never",
    "protocol.https.allow": "always",
    "http.followRedirects": "false",
    "core.symlinks": "false",
    "core.hooksPath": "/dev/null",
    "advice.detachedHead": "false",
    "init.defaultBranch": "main",
    "fetch.recurseSubmodules": "false",
    # The mounted directory belongs to the host user, git runs as nobody.
    "safe.directory": CLONE_MOUNT,
}


class CloneError(AnalysisError):
    """The repository could not be cloned; the message is safe to show."""


class RepositoryTooLargeError(CloneError):
    """The cloned tree exceeds the configured limits."""


def clone_environment(clone_url: str, sha: str, token: str | None) -> dict[str, str]:
    config = dict(GIT_CONFIG)
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        config["http.https://github.com/.extraheader"] = f"AUTHORIZATION: basic {basic}"
    env = {
        "CLONE_URL": clone_url,
        "CLONE_SHA": sha,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_COUNT": str(len(config)),
    }
    for index, (key, value) in enumerate(config.items()):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


def redact(text: str, token: str | None) -> str:
    if token:
        text = text.replace(token, "***")
        text = text.replace(base64.b64encode(f"x-access-token:{token}".encode()).decode(), "***")
    # Anything that looks like a GitHub token, just in case.
    return re.sub(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "***", text)


def enforce_tree_limits(root: Path, limits: ArchiveLimits) -> int:
    files = total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames + dirnames:
            if Path(dirpath, name).is_symlink():
                raise CloneError("The repository contains a symbolic link, which isn't supported.")
        for name in filenames:
            size = Path(dirpath, name).stat().st_size
            files += 1
            total += size
            if size > limits.max_file_bytes:
                raise RepositoryTooLargeError(
                    "The repository has a file larger than"
                    f" {limits.max_file_bytes // (1024 * 1024)} MB."
                )
            if files > limits.max_files:
                raise RepositoryTooLargeError(
                    f"The repository has more than {limits.max_files} files."
                )
            if total > limits.max_total_bytes:
                raise RepositoryTooLargeError(
                    f"The repository is larger than {limits.max_total_bytes // (1024 * 1024)} MB."
                )
    return files


def clone_repository(
    *,
    scan_id: str,
    owner: str,
    name: str,
    sha: str,
    token: str | None,
    workdir: Path,
    limits: ArchiveLimits,
) -> Path:
    if not (OWNER.match(owner) and REPO.match(name) and SHA.match(sha)):
        raise CloneError("Invalid repository coordinates.")
    try:
        assert_public_host("github.com")
    except UnsafeHostError as exc:
        raise CloneError(str(exc)) from None

    settings = get_settings()
    destination = workdir / "src"
    destination.mkdir()
    os.chmod(destination, 0o777)  # noqa: S103 - written by the sandbox user, then read-only mounted
    clone_url = f"https://github.com/{owner}/{name}.git"
    try:
        result = run_in_sandbox(
            image=settings.git_image,
            entrypoint=["sh", "-c"],
            command=[CLONE_SCRIPT],
            working_dir=CLONE_MOUNT,
            mounts=[SandboxMount(destination, CLONE_MOUNT, read_only=False)],
            limits=SandboxLimits(
                cpus=1.0,
                memory=settings.git_clone_memory_limit,
                timeout_seconds=settings.git_clone_timeout_seconds,
            ),
            labels={"codeaudit.scan_id": scan_id, "codeaudit.analyzer": "git-clone"},
            environment=clone_environment(clone_url, sha, token),
            network=True,
        )
    except SandboxError as exc:
        raise CloneError(redact(f"Could not run the clone sandbox: {exc}", token)) from None

    if result.exit_code != 0:
        stderr = redact(result.stderr.strip(), token)
        logger.info("clone of %s/%s failed: %s", owner, name, stderr[-500:])
        lowered = stderr.lower()
        if (
            "could not read username" in lowered
            or "authentication failed" in lowered
            or "repository not found" in lowered
        ):
            raise CloneError(
                f"GitHub refused access to {owner}/{name}. For a private repository, connect"
                " GitHub with private repository access."
            )
        if "not our ref" in lowered or "couldn't find remote ref" in lowered:
            raise CloneError(f"Commit {sha[:12]} is no longer available in {owner}/{name}.")
        if result.oom_killed:
            raise RepositoryTooLargeError(
                "The repository is too large to clone within the memory limit."
            )
        raise CloneError(
            f"Cloning {owner}/{name} failed: {stderr[-300:] or f'exit code {result.exit_code}'}"
        )

    count = enforce_tree_limits(destination, limits)
    logger.info("cloned %s/%s@%s: %d files", owner, name, sha[:12], count)
    return destination

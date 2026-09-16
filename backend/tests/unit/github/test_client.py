"""GitHub client: error mapping, and tokens never appear in reprs, errors or logs."""

import logging

import httpx
import pytest

from app.services.github.client import (
    GitHubAuthError,
    GitHubClient,
    GitHubNotFoundError,
    GitHubPermissionError,
    GitHubRateLimitError,
    GitHubUnavailableError,
    GitHubValidationError,
)
from app.services.github.clone import clone_environment, redact

TOKEN = "gho_SuperSecretToken0123456789"


def client_for(handler, token: str | None = TOKEN) -> GitHubClient:  # type: ignore[no-untyped-def]
    return GitHubClient(token, transport=httpx.MockTransport(handler))


def test_rate_limit_error_is_clear(caplog: pytest.LogCaptureFixture) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"message": "API rate limit exceeded for 1.2.3.4."},
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"},
        )

    with pytest.raises(GitHubRateLimitError) as info:
        client_for(handler, token=None).get_repo("o", "r")
    assert "rate limit" in info.value.message and "resets at" in info.value.message
    assert "connect GitHub" in info.value.message  # unauthenticated hint
    assert info.value.code == "github_rate_limited" and info.value.http_status == 429

    with pytest.raises(GitHubRateLimitError) as info:
        client_for(handler).get_repo("o", "r")
    assert "connect GitHub" not in info.value.message


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, GitHubAuthError),
        (403, GitHubPermissionError),
        (404, GitHubNotFoundError),
        (422, GitHubValidationError),
        (502, GitHubUnavailableError),
    ],
)
def test_status_mapping(status: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        client_for(lambda r: httpx.Response(status, json={"message": "x"})).get_repo("o", "r")


def test_token_never_in_repr_errors_or_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return httpx.Response(401, json={"message": "Bad credentials"})

    client = client_for(handler)
    assert TOKEN not in repr(client)
    with pytest.raises(GitHubAuthError) as info:
        client.get_repo("o", "r")
    assert seen == [f"Bearer {TOKEN}"]
    assert TOKEN not in str(info.value) and TOKEN not in repr(info.value.details)
    assert TOKEN not in caplog.text


def test_connection_errors_dont_chain_request_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed with header {request.headers['authorization']}")

    with pytest.raises(GitHubUnavailableError) as info:
        client_for(handler).get_repo("o", "r")
    assert TOKEN not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_redirects_are_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    with pytest.raises(Exception):  # noqa: B017, PT011 - any error, as long as it's not followed
        client_for(handler).get_repo("o", "r")
    assert calls == ["https://api.github.com/repos/o/r"]


def test_resolve_commit_reads_plain_text_sha() -> None:
    sha = "a" * 40

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"] == "application/vnd.github.sha"
        return httpx.Response(200, text=sha + "\n")

    assert client_for(handler).resolve_commit("o", "r", "main") == sha


def test_clone_environment_keeps_token_out_of_argv_and_redacts() -> None:
    env = clone_environment("https://github.com/o/r.git", "b" * 40, TOKEN)
    assert TOKEN not in env["CLONE_URL"]
    config = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert config["protocol.allow"] == "never" and config["protocol.https.allow"] == "always"
    assert config["http.followRedirects"] == "false"
    assert config["core.hooksPath"] == "/dev/null"
    header = config["http.https://github.com/.extraheader"]
    message = f"fatal: auth failed {TOKEN} {header}"
    assert TOKEN not in redact(message, TOKEN)
    assert header.split()[-1] not in redact(message, TOKEN)

    public = clone_environment("https://github.com/o/r.git", "b" * 40, None)
    assert not any("extraheader" in v for v in public.values())

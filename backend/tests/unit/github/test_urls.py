"""Repository URLs are untrusted input: only github.com repositories, nothing else (SSRF)."""

import socket

import pytest

from app.services.github.urls import (
    InvalidRepoUrlError,
    UnsafeHostError,
    assert_public_host,
    parse_repo_url,
    validate_ref,
)


@pytest.mark.parametrize(
    ("url", "owner", "name", "ref"),
    [
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World.git", "octocat", "Hello-World", None),
        ("https://www.github.com/octocat/hello.world/", "octocat", "hello.world", None),
        ("github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("https://GitHub.com/octocat/repo/tree/feature/x", "octocat", "repo", "feature/x"),
        ("https://github.com:443/octocat/repo", "octocat", "repo", None),
    ],
)
def test_accepts_github_repository_urls(url: str, owner: str, name: str, ref: str | None) -> None:
    parsed = parse_repo_url(url)
    assert (parsed.owner, parsed.name, parsed.ref) == (owner, name, ref)
    # Outgoing URLs are always rebuilt, never the user's string.
    assert parsed.clone_url == f"https://github.com/{owner}/{name}.git"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/octocat/repo",  # not https
        "ssh://git@github.com/octocat/repo.git",
        "git@github.com:octocat/repo.git",
        "file:///etc/passwd",
        "https://gitlab.com/octocat/repo",
        "https://github.com.evil.example/octocat/repo",
        "https://evil.example/github.com/octocat/repo",
        "https://github.com@169.254.169.254/octocat/repo",  # userinfo trick
        "https://user:pass@github.com/octocat/repo",
        "https://127.0.0.1/octocat/repo",
        "https://localhost/octocat/repo",
        "https://[::1]/octocat/repo",
        "https://169.254.169.254/latest/meta-data",
        "https://github.com:8443/octocat/repo",
        "https://github.com/octocat/repo?redirect=http://10.0.0.1",
        "https://github.com/octocat/repo#frag",
        "https://github.com/octocat",
        "https://github.com/../etc/passwd",
        "https://github.com/octocat/..",
        "https://github.com/-octocat/repo",
        "https://github.com/octocat/repo/blob/main/x.py",
        "https://github.com/octocat/repo\n.evil",
        "https://github.com/octo%2F..%2Fcat/repo",
        "",
    ],
)
def test_rejects_everything_else(url: str) -> None:
    with pytest.raises(InvalidRepoUrlError):
        parse_repo_url(url)


@pytest.mark.parametrize(
    "ref", ["--upload-pack=touch /tmp/x", "a..b", "main.lock", "x@{1}", "a//b", "bad ref", "x/"]
)
def test_rejects_dangerous_refs(ref: str) -> None:
    with pytest.raises(InvalidRepoUrlError):
        validate_ref(ref)
    with pytest.raises(InvalidRepoUrlError):
        parse_repo_url("https://github.com/octocat/repo", ref)


def _resolver(*addresses: str):  # type: ignore[no-untyped-def]
    def resolve(host: str, port: int, type: int = 0):  # type: ignore[no-untyped-def]  # noqa: A002
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    return resolve


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.5",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "0.0.0.0",  # noqa: S104
    ],
)
def test_hosts_resolving_to_internal_addresses_are_refused(address: str) -> None:
    with pytest.raises(UnsafeHostError):
        assert_public_host("github.com", resolver=_resolver(address))


def test_any_internal_address_among_several_is_refused() -> None:
    # DNS rebinding style: one public and one private answer.
    with pytest.raises(UnsafeHostError):
        assert_public_host("github.com", resolver=_resolver("140.82.112.3", "10.0.0.7"))


def test_public_addresses_pass() -> None:
    assert_public_host("github.com", resolver=_resolver("140.82.112.3"))


def test_unresolvable_host_is_refused() -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise socket.gaierror("nope")

    with pytest.raises(UnsafeHostError):
        assert_public_host("github.com", resolver=fail)

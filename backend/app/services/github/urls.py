"""Parse and validate GitHub repository URLs. Repo URLs are untrusted input (SSRF).

Only https://github.com/<owner>/<repo> is accepted (optionally .git, a trailing
slash, or /tree/<ref>). We never fetch the URL the user gave: owner and repo
are extracted, validated against GitHub's naming rules, and our own URLs to
github.com / api.github.com are built from them. Hosts are also checked to
resolve only to public addresses before cloning.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# git refs: no "..", no control chars, no leading "-" (never an option to git), etc.
REF = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)[A-Za-z0-9._/@+-]{1,255}(?<![./])$")
SHA = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_HOSTS = frozenset({"github.com", "www.github.com"})


class InvalidRepoUrlError(ValueError):
    """Not a GitHub repository URL we accept."""


class UnsafeHostError(ValueError):
    """The host resolves to a non-public address."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str
    ref: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"

    @property
    def html_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


def validate_ref(ref: str) -> str:
    ref = ref.strip()
    if not REF.match(ref) or ref.endswith(".lock"):
        raise InvalidRepoUrlError(f"{ref[:80]!r} is not a valid branch, tag or commit.")
    return ref


def parse_repo_url(url: str, ref: str | None = None) -> RepoRef:
    text = url.strip()
    if len(text) > 500 or any(ord(c) < 32 for c in text):
        raise InvalidRepoUrlError("That doesn't look like a GitHub repository URL.")
    if not re.match(r"^https?://", text, re.IGNORECASE):
        text = (
            f"https://{text}"
            if text.lower().startswith(("github.com/", "www.github.com/"))
            else text
        )
    parts = urlsplit(text)
    if parts.scheme.lower() != "https":
        raise InvalidRepoUrlError("Only https://github.com/<owner>/<repo> URLs are supported.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise InvalidRepoUrlError("Repository URLs must not contain credentials.")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidRepoUrlError("Invalid port in URL.") from exc
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in ALLOWED_HOSTS or port not in (None, 443):
        raise InvalidRepoUrlError("Only repositories on github.com are supported.")
    if parts.query or parts.fragment:
        raise InvalidRepoUrlError("Repository URLs must not contain a query or fragment.")

    segments = [unquote(s) for s in parts.path.split("/") if s]
    if len(segments) < 2:
        raise InvalidRepoUrlError("Expected https://github.com/<owner>/<repo>.")
    owner, name = segments[0], segments[1].removesuffix(".git")
    url_ref: str | None = None
    rest = segments[2:]
    if rest:
        if rest[0] != "tree" or len(rest) < 2:
            raise InvalidRepoUrlError("Expected https://github.com/<owner>/<repo>[/tree/<ref>].")
        url_ref = "/".join(rest[1:])
    if not OWNER.match(owner) or not REPO.match(name) or name in {".", ".."}:
        raise InvalidRepoUrlError("Invalid GitHub owner or repository name.")
    chosen = ref if ref else url_ref
    return RepoRef(owner, name, validate_ref(chosen) if chosen else None)


def assert_public_host(host: str, resolver=socket.getaddrinfo) -> None:  # type: ignore[no-untyped-def]
    """Raise unless every address `host` resolves to is a public (global) IP."""
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeHostError(f"Could not resolve {host}.") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise UnsafeHostError(f"{host} did not resolve.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeHostError(f"{host} resolves to a non-public address; refusing to connect.")

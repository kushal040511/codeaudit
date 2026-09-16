import json
import os
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from app.services.analyzers.semgrep_rules import (
    RulesUnavailableError,
    ensure_rule_packs,
    select_packs,
)

YAML_PACK = (
    "rules:\n- id: demo\n  pattern: eval(...)\n  message: m\n"
    "  languages: [python]\n  severity: ERROR\n"
)
JSON_PACK = json.dumps({"rules": [{"id": "demo", "pattern": "eval(...)", "message": "m"}]})
MAX_AGE = timedelta(hours=1)


def http_returning(body: str, status: int = 200) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status, text=body)))


def test_select_packs_always_includes_base_and_dedupes() -> None:
    assert select_packs(["python", "typescript", "javascript", "cobol"]) == [
        "p/security-audit",
        "p/secrets",
        "p/python",
        "p/flask",
        "p/typescript",
        "p/nodejs",
        "p/javascript",
    ]


@pytest.mark.parametrize("body", [YAML_PACK, JSON_PACK], ids=["yaml", "json"])
def test_downloads_yaml_or_json_packs(tmp_path: Path, body: str) -> None:
    [path] = ensure_rule_packs(["p/python"], tmp_path, MAX_AGE, http=http_returning(body))

    assert path == tmp_path / "p-python.yml"
    assert path.read_text() == body


def test_rejects_non_rules_response_without_cache(tmp_path: Path) -> None:
    with pytest.raises(RulesUnavailableError):
        ensure_rule_packs(
            ["p/python"], tmp_path, MAX_AGE, http=http_returning("<html>maintenance</html>")
        )


def test_uses_stale_cache_when_refresh_fails(tmp_path: Path) -> None:
    cached = tmp_path / "p-python.yml"
    cached.write_text(YAML_PACK)
    two_hours_ago = time.time() - 7200
    os.utime(cached, (two_hours_ago, two_hours_ago))

    [path] = ensure_rule_packs(
        ["p/python"], tmp_path, MAX_AGE, http=http_returning("down", status=503)
    )

    assert path == cached
    assert path.read_text() == YAML_PACK


def test_fresh_cache_skips_network(tmp_path: Path) -> None:
    cached = tmp_path / "p-python.yml"
    cached.write_text(YAML_PACK)

    def no_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request to {request.url}")

    http = httpx.Client(transport=httpx.MockTransport(no_network))
    assert ensure_rule_packs(["p/python"], tmp_path, MAX_AGE, http=http) == [cached]

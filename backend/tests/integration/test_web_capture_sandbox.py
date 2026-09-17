"""The real capture sandbox (Docker + the Playwright image), on local fixtures only: no network."""

import json
import shutil
import tempfile
from pathlib import Path

import docker
import pytest
from docker.errors import DockerException, ImageNotFound

from app.config import get_settings
from app.services.web.capture import capture_page
from app.services.web.design import extract_tokens
from app.services.web.visual import hash_screenshot
from tests.unit.web.test_design import assert_fixture_tokens

pytestmark = pytest.mark.integration
FIXTURE = Path(__file__).parents[1] / "fixtures" / "web" / "design_page.html"


@pytest.fixture
def workdir() -> Path:
    try:
        client = docker.from_env()
        client.images.get(get_settings().web_capture_image)
    except (DockerException, ImageNotFound) as exc:
        pytest.skip(f"capture image unavailable (docker compose build web-capture): {exc}")
    root = Path(get_settings().scan_workspace_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="scan-webtest-", dir=root))
    yield path
    shutil.rmtree(path, ignore_errors=True)


def test_design_tokens_from_a_real_browser(workdir: Path) -> None:
    capture = capture_page("about:blank", workdir, label="test", html_fixture=FIXTURE)
    assert capture.errors == []
    assert capture.fold_png and hash_screenshot(capture.fold_png) is not None
    assert capture.title == "Fixture design page"
    assert_fixture_tokens(extract_tokens(capture.styles, "https://fixture.example/"))


def test_capture_container_has_no_network(workdir: Path) -> None:
    """Fixture mode runs with network=none: a page trying to fetch anything fails."""
    page = workdir.parent / f"{workdir.name}-net.html"
    page.write_text(
        "<title>net</title><script>fetch('https://example.com/').then(()=>document.title='reached')"
        ".catch(()=>document.title='blocked')</script>"
    )
    try:
        capture = capture_page("about:blank", workdir, label="test-net", html_fixture=page)
    finally:
        page.unlink()
    assert capture.title in ("net", "blocked")
    assert "reached" not in json.dumps(capture.title)

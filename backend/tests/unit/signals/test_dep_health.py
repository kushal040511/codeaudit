"""Dependency health signal: manifests, lockfiles, import usage and (mocked) registries."""

from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from app.config import Settings, get_settings
from app.services.analyzers.base import AnalyzerResult, ScanContext
from app.services.analyzers.dep_health import (
    NPM,
    PYPI,
    DepHealthAnalyzer,
    RegistryInfo,
    freshness_of,
    minimum_version,
    parse_npm_version,
    parse_poetry_lock,
    parse_yarn_v1,
    transitive_component,
)
from app.services.analyzers.signals import SignalReport
from app.services.graph.analysis import ArchitectureReport, analyze_architecture

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "signals"
PYTHON_REPO = FIXTURES / "deps_python"
NODE_REPO = FIXTURES / "deps_node"
COMPONENTS = ["direct_count", "freshness", "transitive", "trivial", "unused", "phantom"]

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(scope="module")
def python_report() -> ArchitectureReport:
    return analyze_architecture(PYTHON_REPO)


@pytest.fixture(scope="module")
def node_report() -> ArchitectureReport:
    return analyze_architecture(NODE_REPO)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    return get_settings().model_copy(
        update={"scan_workspace_dir": str(tmp_path / "workspace"), **overrides}
    )


def offline(tmp_path: Path) -> DepHealthAnalyzer:
    return DepHealthAnalyzer(settings=make_settings(tmp_path, dep_health_registry_enabled=False))


class Registry:
    """httpx.MockTransport handler serving canned metadata and recording requests."""

    def __init__(self, pypi: dict[str, Any] | None = None, npm: dict[str, Any] | None = None):
        self.pypi = pypi or {}
        self.npm = npm or {}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = unquote(request.url.raw_path.decode())
        if request.url.host == "pypi.org":
            name = path.removeprefix("/pypi/").removesuffix("/json")
            body = self.pypi.get(name)
        else:
            body = self.npm.get(path.removeprefix("/"))
        return httpx.Response(200, json=body) if body is not None else httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    @property
    def names(self) -> list[str]:
        return [unquote(r.url.raw_path.decode()) for r in self.requests]


def pypi_meta(latest: str, releases: dict[str, int]) -> dict[str, Any]:
    return {
        "info": {"version": latest},
        "releases": {
            version: [{"size": size, "packagetype": "sdist", "yanked": False}]
            for version, size in releases.items()
        },
    }


def npm_meta(latest: str, versions: dict[str, int]) -> dict[str, Any]:
    return {
        "dist-tags": {"latest": latest},
        "versions": {
            v: {"dist": {"unpackedSize": size, "fileCount": 10}} for v, size in versions.items()
        },
    }


PYPI_METADATA = {
    "requests": pypi_meta(
        "2.32.3",
        {
            "2.30.0": 60_000,
            "2.31.0": 60_000,
            "2.32.0": 61_000,
            "2.32.1": 61_000,
            "2.32.2": 61_000,
            "2.32.3": 61_000,
            "3.0.0b1": 62_000,  # prerelease: never counted
        },
    ),
    "flask": pypi_meta("3.1.0", {"2.3.3": 100_000, "3.0.0": 100_000, "3.1.0": 100_000}),
    "pyyaml": pypi_meta("6.0.1", {"6.0.1": 1_000}),  # tiny -> trivial
}
NPM_METADATA = {
    "react": npm_meta(
        "19.1.0",
        {
            "18.2.0": 300_000,
            "18.3.0": 300_000,
            "18.3.1": 300_000,
            "19.0.0-rc.1": 300_000,
            "19.0.0": 300_000,
            "19.1.0": 300_000,
        },
    ),
    "@scope/ui": npm_meta("1.4.0", {"1.0.0": 1_200, "1.4.0": 1_200}),
}


def collect(
    analyzer: DepHealthAnalyzer, repo: Path, report: ArchitectureReport | None
) -> SignalReport:
    signal, _findings = analyzer.collect(repo, report)
    return signal


# ----------------------------------------------------------------------------- offline parts


def test_python_repo_manifests_usage_and_lockfile(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    signal, findings = offline(tmp_path).collect(PYTHON_REPO, python_report)

    assert signal.applicable
    assert list(signal.components) == COMPONENTS
    metrics = signal.metrics
    assert metrics["direct"] == {
        "PyPI": {"runtime": 4, "dev": 2, "total": 6, "baseline": 23, "component": 1.0}
    }
    # PyYAML is used through `import yaml`; pytest is imported by the tests; black is tooling.
    assert metrics["unused"] == [
        {"ecosystem": PYPI, "name": "boto3", "manifest": "requirements.txt"}
    ]
    assert [e["name"] for e in metrics["unused_excluded"]] == ["black"]
    assert metrics["phantom"] == [
        {"ecosystem": PYPI, "name": "numpy", "file": "app/main.py", "line": 3}
    ]
    assert metrics["external_packages_imported"] == 5  # requests yaml flask numpy pytest
    transitive = metrics["transitive"]
    assert transitive["transitive_count"] == 12
    assert transitive["max_depth"] == 4  # boto3 -> botocore -> python-dateutil -> six
    assert transitive["lockfiles"][0]["direct"] == 6

    assert signal.components["direct_count"] == 1.0
    assert signal.components["unused"] == pytest.approx(1 - 1 / 6)
    assert signal.components["phantom"] == pytest.approx(1 - 1 / 5)
    assert signal.components["transitive"] == 1.0  # 12 <= 10 * 6
    assert signal.components["freshness"] is None
    assert signal.components["trivial"] is None
    assert signal.reason is not None and "disabled" in signal.reason

    by_rule = {(f.rule_id, f.file_path, f.start_line) for f in findings}
    assert by_rule == {
        ("unused-dependency", "requirements.txt", 5),
        ("phantom-dependency", "app/main.py", 3),
    }
    assert len({f.category for f in findings}) == len(findings)
    assert all(f.analyzer == "dep_health" and f.severity.value == "info" for f in findings)


def test_node_repo_manifests_usage_and_lockfile(
    tmp_path: Path, node_report: ArchitectureReport
) -> None:
    signal = collect(offline(tmp_path), NODE_REPO, node_report)

    metrics = signal.metrics
    assert metrics["direct"] == {
        "npm": {"runtime": 4, "dev": 4, "total": 8, "baseline": 44, "component": 1.0}
    }
    # @scope/ui is used through the deep import "@scope/ui/button".
    assert metrics["unused"] == [{"ecosystem": NPM, "name": "lodash", "manifest": "package.json"}]
    excluded = {e["name"]: e["why"] for e in metrics["unused_excluded"]}
    assert excluded == {
        "eslint": "allow-list",
        "jest": "allow-list",
        "typescript": "allow-list",
        "rimraf": "referenced in package.json",  # "clean": "rimraf dist"
    }
    assert metrics["phantom"] == [
        {"ecosystem": NPM, "name": "chalk", "file": "src/index.ts", "line": 5}
    ]
    assert metrics["external_packages_imported"] == 4  # react @scope/ui express chalk
    lock = metrics["transitive"]["lockfiles"][0]
    assert (lock["packages"], lock["direct"], lock["transitive"]) == (20, 8, 12)
    # express -> body-parser -> nested debug@2.6.9 -> nested ms@2.0.0
    assert lock["max_depth"] == 4
    assert signal.components["unused"] == pytest.approx(7 / 8)
    assert signal.components["phantom"] == pytest.approx(0.75)


def test_run_uses_the_architecture_prior_result(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    analyzer = offline(tmp_path)
    assert analyzer.phase == 2 and analyzer.experimental and not analyzer.supported_languages
    prior = AnalyzerResult("architecture", True, [], "{}", 1, artifact=python_report)
    context = ScanContext("scan", tmp_path, [], prior_results={"architecture": prior})

    result = analyzer.run(PYTHON_REPO, context)

    assert result.success
    assert isinstance(result.artifact, SignalReport) and result.artifact.name == "dep_health"
    assert sorted(f.rule_id for f in result.findings) == [
        "phantom-dependency",
        "unused-dependency",
    ]
    assert analyzer.parse(result.raw_output) == result.findings


def test_without_architecture_report_unused_and_phantom_are_none(tmp_path: Path) -> None:
    analyzer = offline(tmp_path)
    result = analyzer.run(PYTHON_REPO, ScanContext("scan", tmp_path, []))
    signal = result.artifact
    assert isinstance(signal, SignalReport)
    assert signal.components["unused"] is None and signal.components["phantom"] is None
    assert signal.components["direct_count"] == 1.0
    assert signal.score == pytest.approx(1.0)
    assert result.findings == []


def test_no_manifest_is_not_applicable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("import requests\n")
    signal = collect(offline(tmp_path), repo, analyze_architecture(repo))
    assert not signal.applicable and signal.score is None


def test_phantom_needs_a_manifest_for_that_language(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "web").mkdir(parents=True)
    (repo / "requirements.txt").write_text("requests\n")
    (repo / "app.py").write_text("import requests\n")
    (repo / "web" / "index.js").write_text('import chalk from "chalk";\n')
    signal = collect(offline(tmp_path), repo, analyze_architecture(repo))
    assert signal.metrics["phantom"] == []  # no package.json: JS imports aren't judged
    assert signal.components["phantom"] == 1.0


# ----------------------------------------------------------------------------- registry


def test_freshness_and_trivial_from_pypi_metadata(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    registry = Registry(pypi=PYPI_METADATA)
    analyzer = DepHealthAnalyzer(settings=make_settings(tmp_path), client=registry.client())
    signal = collect(analyzer, PYTHON_REPO, python_report)

    fresh = {d["name"]: d for d in signal.metrics["freshness"]["dependencies"]}
    assert fresh["requests"]["versions_behind"] == 4  # 2.32.0-2.32.3, not 3.0.0b1
    assert fresh["requests"]["majors_behind"] == 0
    assert fresh["requests"]["version_source"] == "lockfile"
    assert fresh["flask"]["majors_behind"] == 1
    assert fresh["PyYAML"]["versions_behind"] == 0
    # requests 1 * 0.8, flask 1/2 * 1.0, PyYAML 1.0
    assert signal.components["freshness"] == pytest.approx((0.8 + 0.5 + 1.0) / 3)
    assert signal.metrics["trivial"]["trivial"] == ["PyPI:PyYAML"]
    assert signal.components["trivial"] == pytest.approx(2 / 3)
    assert sorted(signal.metrics["registry"]["not_found"]) == [
        "PyPI:black",
        "PyPI:boto3",
        "PyPI:pytest",
    ]
    assert signal.score is not None
    assert all(signal.components[k] is not None for k in COMPONENTS)


def test_npm_abbreviated_metadata_and_scoped_names(
    tmp_path: Path, node_report: ArchitectureReport
) -> None:
    registry = Registry(npm=NPM_METADATA)
    analyzer = DepHealthAnalyzer(settings=make_settings(tmp_path), client=registry.client())
    signal = collect(analyzer, NODE_REPO, node_report)

    assert "/@scope/ui" in registry.names
    assert all(
        "application/vnd.npm.install-v1+json" in r.headers["accept"] for r in registry.requests
    )
    fresh = {d["name"]: d for d in signal.metrics["freshness"]["dependencies"]}
    assert (fresh["react"]["versions_behind"], fresh["react"]["majors_behind"]) == (4, 1)
    assert signal.components["freshness"] == pytest.approx((0.4 + 1.0) / 2)
    assert signal.metrics["trivial"]["trivial"] == ["npm:@scope/ui"]
    assert signal.components["trivial"] == pytest.approx(0.5)


def test_unreachable_registry_does_not_fail(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(refuse))
    analyzer = DepHealthAnalyzer(settings=make_settings(tmp_path), client=client)
    signal = collect(analyzer, PYTHON_REPO, python_report)

    assert signal.applicable
    assert signal.components["freshness"] is None
    assert signal.components["trivial"] is None
    assert "PyPI" in signal.metrics["registry"]["unreachable"]
    assert signal.reason is not None and "unreachable" in signal.reason
    for key in ("direct_count", "transitive", "unused", "phantom"):
        assert signal.components[key] is not None
    assert signal.score is not None


def test_registry_cache_avoids_a_second_request(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    settings = make_settings(tmp_path)
    registry = Registry(pypi=PYPI_METADATA)
    first = collect(
        DepHealthAnalyzer(settings=settings, client=registry.client()), PYTHON_REPO, python_report
    )
    requests_made = len(registry.requests)
    assert requests_made == 6
    assert (tmp_path / "workspace" / "_registry" / "pypi" / "requests.json").is_file()

    second = collect(
        DepHealthAnalyzer(settings=settings, client=registry.client()), PYTHON_REPO, python_report
    )
    assert len(registry.requests) == requests_made
    assert second.metrics["registry"]["cache_hits"] == 6
    assert second.components == first.components


def test_expired_cache_is_refetched(tmp_path: Path, python_report: ArchitectureReport) -> None:
    settings = make_settings(tmp_path, dep_health_registry_cache_hours=0)
    registry = Registry(pypi=PYPI_METADATA)
    for _ in range(2):
        collect(
            DepHealthAnalyzer(settings=settings, client=registry.client()),
            PYTHON_REPO,
            python_report,
        )
    assert len(registry.requests) == 12


def test_registry_disabled_makes_no_requests(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    registry = Registry(pypi=PYPI_METADATA)
    settings = make_settings(tmp_path, dep_health_registry_enabled=False)
    signal = collect(
        DepHealthAnalyzer(settings=settings, client=registry.client()), PYTHON_REPO, python_report
    )
    assert registry.requests == []
    assert signal.components["freshness"] is None and signal.components["trivial"] is None
    assert signal.metrics["registry"] == {"enabled": False}


def test_lookup_limit_prefers_runtime_dependencies(
    tmp_path: Path, python_report: ArchitectureReport
) -> None:
    registry = Registry(pypi=PYPI_METADATA)
    settings = make_settings(tmp_path, dep_health_max_registry_lookups=4)
    signal = collect(
        DepHealthAnalyzer(settings=settings, client=registry.client()), PYTHON_REPO, python_report
    )
    assert sorted(registry.names) == [
        "/pypi/boto3/json",
        "/pypi/flask/json",
        "/pypi/pyyaml/json",
        "/pypi/requests/json",
    ]
    assert signal.metrics["registry"]["skipped_over_limit"] == 2


# ----------------------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("ecosystem", "spec", "expected"),
    [
        (PYPI, "==2.31.0", ("2.31.0", True)),
        (PYPI, ">=2.0,<3", ("2.0", False)),
        (PYPI, "<3,>=2.1", ("2.1", False)),
        (PYPI, "~=1.4.2", ("1.4.2", False)),
        (PYPI, "^1.2", ("1.2", False)),
        (PYPI, "==1.2.*", ("1.2", False)),
        (PYPI, "*", None),
        (NPM, "^18.2.0", ("18.2.0", False)),
        (NPM, "18.2.0", ("18.2.0", True)),
        (NPM, "1.x", ("1.0.0", False)),
        (NPM, ">=1.2.0 <2", ("1.2.0", False)),
        (NPM, "^2.0.0 || ^1.5.0", ("1.5.0", False)),
        (NPM, "workspace:*", None),
        (NPM, "github:user/repo", None),
        (NPM, "latest", None),
    ],
)
def test_minimum_version(ecosystem: str, spec: str, expected: tuple[str, bool] | None) -> None:
    assert minimum_version(ecosystem, spec) == expected


def test_semver_ordering() -> None:
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0", "1.2.0"]
    keys = [parse_npm_version(v).key for v in order]  # type: ignore[union-attr]
    assert keys == sorted(keys)


def test_zero_major_minors_count_as_majors() -> None:
    info = RegistryInfo(True, "0.5.0", ("0.3.0", "0.3.1", "0.4.0", "0.5.0"))
    fresh = freshness_of(NPM, "0.3.0", info)
    assert fresh is not None
    assert (fresh["versions_behind"], fresh["majors_behind"]) == (3, 2)
    assert fresh["score"] == pytest.approx(0.8 / 3)


def test_yarn_v1_lockfile() -> None:
    text = """# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/x"
  dependencies:
    "@babel/highlight" "^7.12.13"

"@babel/highlight@^7.12.13":
  version "7.14.0"
  dependencies:
    chalk "^2.0.0"

chalk@^2.0.0:
  version "2.4.2"

left-pad@1.3.0:
  version "1.3.0"
"""
    packages, direct, depth, versions = parse_yarn_v1(
        text, {"@babel/code-frame": "^7.0.0", "left-pad": "1.3.0"}
    )
    assert (packages, direct, depth) == (4, 2, 3)
    assert versions["@babel/code-frame"] == "7.12.13"


def test_poetry_lock() -> None:
    data = {
        "package": [
            {"name": "Flask", "version": "3.0.0", "dependencies": {"Jinja2": ">=3"}},
            {"name": "jinja2", "version": "3.1.2", "dependencies": {"MarkupSafe": ">=2"}},
            {"name": "markupsafe", "version": "2.1.3"},
            {"name": "requests", "version": "2.31.0"},
        ]
    }
    assert parse_poetry_lock(data, ["flask", "requests"])[:3] == (4, 2, 3)


def test_transitive_component_is_monotone() -> None:
    assert transitive_component(50, 10) == 1.0
    values = [transitive_component(t, 10) for t in (100, 200, 600, 2000)]
    assert values == sorted(values, reverse=True)
    assert transitive_component(600, 10) == pytest.approx(1 / (1 + 500 / 500))

import json
from pathlib import Path

import pytest

from app.models import Severity
from app.services.analyzers.dependency import (
    DependencyAnalyzer,
    fixed_versions,
    locate_package_line,
    normalize_severity,
)
from app.services.analyzers.sandbox import AnalyzerOutputError

FIXTURES = Path(__file__).parents[1] / "fixtures"
# Real `osv-scanner scan source -r --offline --format json` output for fixtures/polyglot_app.
OSV_OUTPUT = FIXTURES / "osv_scanner_output.json"
POLYGLOT_APP = FIXTURES / "polyglot_app"


@pytest.fixture(scope="module")
def findings():  # type: ignore[no-untyped-def]
    return DependencyAnalyzer().parse(OSV_OUTPUT.read_text())


def test_one_finding_per_advisory_group(findings) -> None:  # type: ignore[no-untyped-def]
    assert len(findings) == 23
    packages = {(f.file_path, f.dependency["package"]) for f in findings}
    assert packages == {
        ("api/requirements.txt", "flask"),
        ("api/requirements.txt", "jinja2"),
        ("api/requirements.txt", "pyyaml"),
        ("api/requirements.txt", "requests"),
        ("web/package-lock.json", "express"),
        ("web/package-lock.json", "lodash"),
        ("web/package-lock.json", "minimist"),
    }
    assert {f.analyzer for f in findings} == {"dependency"}
    # Categories are unique per advisory: dependency findings never merge with code findings.
    assert len({f.category for f in findings}) == 23


def test_dependency_details(findings) -> None:  # type: ignore[no-untyped-def]
    by_rule = {f.rule_id: f for f in findings}

    yaml = by_rule["CVE-2020-14343"]
    assert yaml.dependency == {
        "ecosystem": "PyPI",
        "package": "pyyaml",
        "installed_version": "5.3",
        "advisory_id": "CVE-2020-14343",
        "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"],
        "fixed_version": "5.4",
        "fixed_versions": ["5.4"],
        "cvss_score": "9.8",
    }
    assert yaml.severity is Severity.CRITICAL
    assert yaml.message.startswith("pyyaml 5.3: ")
    assert yaml.message.endswith("Upgrade to 5.4 or later.")
    # Trimmed raw record: no giant version lists
    assert '"versions"' not in json.dumps(yaml.raw["vulnerabilities"])
    assert '"affected"' not in json.dumps(yaml.raw["vulnerabilities"])
    assert yaml.raw["group"]["ids"] == ["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4"]


def test_group_fixed_version_is_the_highest_needed(findings) -> None:  # type: ignore[no-untyped-def]
    # GHSA-35jh-r3h4-6jhm is fixed in 4.17.21, GHSA-r5fr-rjxr-66jc (same group) in 4.18.0.
    lodash = next(f for f in findings if f.rule_id == "CVE-2021-23337")

    assert lodash.dependency is not None
    assert lodash.dependency["fixed_version"] == "4.18.0"
    assert lodash.dependency["fixed_versions"] == ["4.17.21", "4.18.0"]
    assert lodash.severity is Severity.ERROR  # CVSS 8.1


def test_ghsa_only_advisory_ids(findings) -> None:  # type: ignore[no-untyped-def]
    minimist = next(f for f in findings if f.rule_id == "CVE-2021-44906")

    assert minimist.dependency is not None
    assert minimist.dependency["aliases"] == ["CVE-2021-44906", "GHSA-xvch-5gv4-984h"]
    assert minimist.severity is Severity.CRITICAL


def test_summary_prefers_advisory_with_summary(findings) -> None:  # type: ignore[no-untyped-def]
    # The PYSEC record has no summary; the GHSA record in the same group does.
    jinja = next(f for f in findings if f.rule_id == "CVE-2019-10906")

    assert jinja.message == (
        "jinja2 2.10: Jinja2 sandbox escape via string formatting. Upgrade to 2.10.1 or later."
    )


def test_summary_falls_back_to_first_sentence_of_details() -> None:
    raw = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "/src/requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "oldlib", "version": "1.0", "ecosystem": "PyPI"},
                            "groups": [{"ids": ["PYSEC-1"], "aliases": [], "max_severity": ""}],
                            "vulnerabilities": [
                                {
                                    "id": "PYSEC-1",
                                    "details": "Oldlib  before 1.1 leaks memory. More text.",
                                    "affected": [],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )

    [finding] = DependencyAnalyzer().parse(raw)

    assert finding.rule_id == "PYSEC-1"
    assert finding.message == (
        "oldlib 1.0: Oldlib before 1.1 leaks memory. No fixed version is known."
    )
    assert finding.severity is Severity.WARNING  # unscored vulnerabilities are never info
    assert finding.dependency is not None and finding.dependency["fixed_version"] is None


@pytest.mark.parametrize(
    ("score", "labels", "expected"),
    [
        ("9.8", [], Severity.CRITICAL),
        ("9.0", [], Severity.CRITICAL),
        ("8.9", [], Severity.ERROR),
        ("7.0", [], Severity.ERROR),
        ("6.9", [], Severity.WARNING),
        ("4.0", [], Severity.WARNING),
        ("3.9", [], Severity.INFO),
        ("", ["MODERATE", "HIGH"], Severity.ERROR),
        ("", ["CRITICAL"], Severity.CRITICAL),
        ("", ["LOW"], Severity.INFO),
        ("", [None], Severity.WARNING),
        (None, None, Severity.WARNING),
    ],
)
def test_severity_normalization(
    score: str | None, labels: list[object] | None, expected: Severity
) -> None:
    assert normalize_severity(score, labels) is expected


def test_fixed_versions_only_from_ranges_containing_installed() -> None:
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Some_Package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0"},
                            {"fixed": "1.2.3"},
                            {"introduced": "2.0"},
                            {"fixed": "2.0.10"},
                        ],
                    }
                ],
            },
            {"package": {"ecosystem": "npm", "name": "some-package"}, "ranges": []},
        ]
    }
    package = {"ecosystem": "PyPI", "name": "some-package", "version": "2.0.9"}

    assert fixed_versions(vuln, package) == ["2.0.10"]  # not 1.2.3; 10 > 9 numerically


def test_locate_package_line() -> None:
    assert locate_package_line(POLYGLOT_APP, "api/requirements.txt", "pyyaml") == 2  # PyYAML
    assert locate_package_line(POLYGLOT_APP, "api/requirements.txt", "jinja2") == 4
    # The installed entry ("node_modules/lodash"), not the root dependency range on line 12
    assert locate_package_line(POLYGLOT_APP, "web/package-lock.json", "lodash") == 20
    assert locate_package_line(POLYGLOT_APP, "web/package-lock.json", "left-pad") is None
    assert locate_package_line(POLYGLOT_APP, "../../conftest.py", "pytest") is None


@pytest.mark.parametrize("raw", ["", '{"results": null}'])
def test_no_package_sources(raw: str) -> None:
    assert DependencyAnalyzer().parse(raw) == []


@pytest.mark.parametrize("raw", ["garbage", "[]", '{"results": {}}'])
def test_invalid_output_raises(raw: str) -> None:
    with pytest.raises(AnalyzerOutputError):
        DependencyAnalyzer().parse(raw)

"""CI pipeline signal: exact detections on small fixture repositories."""

from pathlib import Path

import pytest

from app.services.analyzers.base import ScanContext
from app.services.analyzers.ci_quality import CIQualityAnalyzer, analyze, classify
from app.services.analyzers.signals import SignalReport

FIXTURES = Path(__file__).parents[2] / "fixtures" / "signals"


def test_substantive_github_workflow() -> None:
    report = analyze(FIXTURES / "ci_substantive")

    assert report.applicable
    assert report.components == {
        "tests": 1.0,
        "lint": 1.0,
        "security": 1.0,
        "build": 1.0,
        "pr_trigger": 1.0,
        "gating": 1.0,
    }
    assert report.score == 1.0
    [workflow] = report.metrics["ci_files"]
    assert workflow["path"] == ".github/workflows/ci.yml"
    assert workflow["categories"] == ["tests", "lint", "security", "build"]
    assert workflow["matched"] == {
        "lint": ["ruff check .", "mypy app"],
        "tests": ["pytest -q"],
        "security": ["github/codeql-action/init", "github/codeql-action/analyze"],
        "build": ["docker build -t app ."],
    }
    assert workflow["triggers"] == ["push", "pull_request"]
    assert workflow["push_branches"] == ["main"]
    assert workflow["runs_on_pr"] is True
    assert workflow["gated"] == ["image: needs test"]
    assert report.metrics["branch_protection_hint"] is True


def test_token_workflow_scores_zero() -> None:
    report = analyze(FIXTURES / "ci_token")

    assert report.applicable
    assert report.components == {
        "tests": 0.0,
        "lint": 0.0,
        "security": 0.0,
        "build": 0.0,
        "pr_trigger": 0.0,
        "gating": None,  # nothing is built or deployed
    }
    assert report.score == 0.0
    [workflow] = report.metrics["ci_files"]
    assert workflow["categories"] == []
    assert workflow["triggers"] == ["workflow_dispatch"]
    assert report.metrics["runs_on_pr"] is False
    assert report.metrics["branch_protection_hint"] is False


def test_no_ci_is_not_applicable() -> None:
    report = analyze(FIXTURES / "ci_none")

    assert not report.applicable
    assert report.score is None
    assert report.reason == "no CI configuration found"


def test_gitlab_merge_request_pipeline() -> None:
    report = analyze(FIXTURES / "ci_gitlab")

    [pipeline] = report.metrics["ci_files"]
    assert pipeline["provider"] == "gitlab"
    assert pipeline["categories"] == ["tests", "lint"]
    assert pipeline["matched"] == {
        "lint": ["flake8 src", "black --check src"],
        "tests": ["python -m pytest tests"],
    }
    assert pipeline["jobs"] == 2
    assert report.metrics["runs_on_pr"] is True
    assert report.components == {
        "tests": 1.0,
        "lint": 1.0,
        "security": 0.0,
        "build": 0.0,
        "pr_trigger": 1.0,
        "gating": None,
    }
    assert report.score == pytest.approx(0.6)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("pip install pytest ruff pip-audit", set()),  # installing is not running
        ("pip-audit -r requirements.txt", {"security"}),
        ("npm ci", set()),
        ("npm run test -- --coverage", {"tests"}),
        ("yarn lint", {"lint"}),
        ("npx tsc --noEmit", {"lint"}),
        ("echo pytest", set()),
        ("npm test && npm run build", {"tests", "build"}),
        ("peaceiris/actions-gh-pages", {"build"}),
        ("./gradlew test", {"tests"}),
        ("trivy image app:latest", {"security"}),
    ],
)
def test_classify(line: str, expected: set[str]) -> None:
    assert classify(line) == expected


def test_jenkinsfile_sequential_stages_gate_the_deploy(tmp_path: Path) -> None:
    (tmp_path / "Jenkinsfile").write_text(
        "pipeline {\n  stages {\n"
        "    stage('Test') { steps { sh 'pytest' } }\n"
        "    stage('Deploy') { steps { sh \"./deploy.sh prod\" } }\n"
        "  }\n}\n"
    )

    report = analyze(tmp_path)

    assert report.metrics["ci_files"][0]["categories"] == ["tests", "build"]
    assert report.metrics["gated"] == ["Jenkinsfile Jenkinsfile: runs after tests in the same job"]
    assert report.components["gating"] == 1.0
    assert report.components["pr_trigger"] == 0.0


def test_probot_required_status_checks_is_a_hint(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yaml").write_text(
        "on:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n"
    )
    (tmp_path / ".github" / "settings.yml").write_text(
        "branches:\n  - name: main\n    protection:\n      required_status_checks:\n"
        "        strict: true\n"
    )

    report = analyze(tmp_path)

    assert report.metrics["branch_protection_hints"] == [
        "required status checks mentioned in .github/settings.yml"
    ]
    assert report.components["build"] == 1.0
    assert report.components["gating"] == 1.0


def test_invalid_yaml_is_reported_not_raised(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text("test: [unclosed\n")

    report = analyze(tmp_path)

    assert report.applicable
    assert report.metrics["errors"][0].startswith(".gitlab-ci.yml: invalid YAML")
    assert report.score == 0.0


def test_analyzer_run_returns_the_report(tmp_path: Path) -> None:
    analyzer = CIQualityAnalyzer()
    context = ScanContext(scan_id="s", work_dir=tmp_path, languages=[])

    result = analyzer.run(FIXTURES / "ci_substantive", context)

    assert analyzer.experimental and analyzer.phase == 1
    assert result.success and result.findings == []
    assert isinstance(result.artifact, SignalReport)
    assert result.artifact.name == "ci_quality"
    assert result.artifact.score == 1.0

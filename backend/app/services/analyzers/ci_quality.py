"""CI pipeline signal: what the repository's CI configuration actually checks.

Reads CI configuration files and classifies every shell command and action
reference into tests, lint/type checks, security scans and build/deploy steps,
then looks at when the pipeline runs (pull requests?) and whether building or
deploying is gated on the tests.

Files read (each capped at 512 KB, parsed with `yaml.safe_load`; nothing is executed):
    .github/workflows/*.yml|yaml, .gitlab-ci.yml, Jenkinsfile (text heuristics),
    .circleci/config.yml, azure-pipelines.yml, .travis.yml, bitbucket-pipelines.yml

Components (1 = best, None = not applicable):
    tests       1 if any test command/action runs, else 0
    lint        1 if any lint or type check runs, else 0
    security    1 if any security scan runs, else 0
    build       1 if any build/deploy step runs, else 0
    pr_trigger  1 if the pipeline runs on pull/merge requests, else 0
    gating      1 if a build/deploy job depends (transitively) on a test job, or runs
                after tests in the same sequential job, or a branch-protection hint is
                present; 0 otherwise; None when there is no build/deploy step
    score = unweighted mean of the available components.

A repository without any CI file gets `applicable=False` ("no CI configuration
found"), not a zero score.

Branch protection itself lives in the hosting platform's settings and CANNOT be
verified from the code. `branch_protection_hint` only reports indirect evidence:
deploy jobs gated with `needs:` on test jobs, `if: github.event_name == 'pull_request'`
conditions, or `required_status_checks` in a probot `.github/settings.yml` / a
required-status mention in CODEOWNERS.

Known limitations: commands hidden in scripts (`./ci.sh`, `make all`), reusable
workflows and composite actions from other repositories, GitLab `include:` and
CircleCI orbs are not followed; classification is keyword based.
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # no types-PyYAML in the venv

from app.config import Settings, get_settings
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.signals import SignalReport, mean_score, not_applicable

ANALYZER_NAME = "ci_quality"
MAX_CI_FILE_BYTES = 512 * 1024
MAX_MATCHES_PER_CATEGORY = 5
MAX_MATCH_CHARS = 120

CATEGORIES = ("tests", "lint", "security", "build")

# Classification patterns, applied (case-insensitively) to each command line and to
# each action/task reference (`uses: owner/repo@v1` with the version stripped).
CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "tests": (
        r"\bpytest\b",
        r"\bpython[0-9.]*\s+-m\s+(pytest|unittest)\b",
        r"\bunittest\b",
        r"\btox\b",
        r"\bnox\b",
        r"\b(npm|yarn|pnpm|bun)\s+(run\s+)?test\b",
        r"\bjest\b",
        r"\bvitest\b",
        r"\bmocha\b",
        r"\bgo\s+test\b",
        r"\bcargo\s+test\b",
        r"\bmvnw?\b[^\n]*\btest\b",
        r"\bgradlew?\b[^\n]*\btest\b",
        r"\bmake\s+test\b",
        r"\bplaywright\s+test\b",
        r"\bcypress\s+run\b",
        r"cypress-io/github-action",
    ),
    "lint": (
        r"\bruff\b",
        r"\bflake8\b",
        r"\bpylint\b",
        r"\bblack\b[^\n]*--check\b",
        r"\bmypy\b",
        r"\bpyright\b",
        r"\beslint\b",
        r"\btsc\b",
        r"\bprettier\b[^\n]*--check\b",
        r"\b(npm|yarn|pnpm|bun)\s+(run\s+)?lint\b",
        r"\bgolangci-lint\b",
        r"super-linter",
        r"\bpre-commit\s+run\b",
        r"pre-commit/action",
    ),
    "security": (
        r"codeql",
        r"\bsemgrep\b",
        r"\bbandit\b",
        r"\bsnyk\b",
        r"\btrivy\b",
        r"osv-scanner",
        r"pip-audit",
        r"\b(npm|yarn|pnpm)\s+audit\b",
        r"\bsafety\s+(check|scan)\b",
        r"\bgitleaks\b",
        r"\btrufflehog\b",
        r"dependency-review-action",
        r"\bzap\b|zaproxy",
    ),
    "build": (
        r"\bdocker\s+(build|push|buildx\s+build|compose\s+build)\b",
        r"docker/build-push-action",
        r"\b(npm|yarn|pnpm|bun)\s+(run\s+)?build\b",
        r"\bpython[0-9.]*\s+-m\s+build\b",
        r"\bvite\s+build\b",
        r"\b(deploy|publish|release)\b",
        r"aws-actions/",
        r"azure/[^@\s]*deploy",
        r"peaceiris/actions-gh-pages",
        r"pypa/gh-action-pypi-publish",
        r"\btwine\s+upload\b",
        r"\bgoreleaser\b",
    ),
}
_COMPILED = {
    category: tuple(re.compile(p, re.IGNORECASE) for p in patterns)
    for category, patterns in CATEGORY_PATTERNS.items()
}
# Dependency installation lines mention tool names without running them.
_INSTALL_LINE = re.compile(
    r"^\s*(sudo\s+)?(?:(?:pip3?|python[0-9.]*\s+-m\s+pip|pipx|uv\s+(?:pip|add|sync|tool\s+install)"
    r"|poetry\s+(?:add|install)|(?:npm|pnpm|bun)\s+(?:i|install|ci|add)|yarn\s+(?:add|install)"
    r"|apt(?:-get)?\s+install|brew\s+install|go\s+install|cargo\s+install|gem\s+install)(?=\s|$)"
    r"|yarn\s*(?:$|--))",
    re.IGNORECASE,
)
_ECHO_LINE = re.compile(r"^\s*(echo|printf|#)", re.IGNORECASE)
_PR_EVENT_CONDITION = re.compile(r"github\.event_name\s*==\s*['\"]pull_request")
_REQUIRED_STATUS = re.compile(r"required_status_checks|required status", re.IGNORECASE)

# Keys whose values are shell commands / action references in the supported formats.
_COMMAND_KEYS = frozenset(
    {
        "run",
        "script",
        "before_script",
        "after_script",
        "command",
        "bash",
        "pwsh",
        "powershell",
        "install",
        "before_install",
        "after_success",
        "before_deploy",
        "deploy",
    }
)
_REF_KEYS = frozenset({"uses", "task", "pipe"})
_GITLAB_RESERVED = frozenset(
    {
        "stages",
        "variables",
        "default",
        "include",
        "workflow",
        "image",
        "services",
        "cache",
        "before_script",
        "after_script",
        "types",
    }
)
_GITLAB_DEFAULT_STAGES = [".pre", "build", "test", "deploy", ".post"]
_JENKINS_STEP = re.compile(
    r"\b(?:sh|bat|pwsh|powershell)\s*\(?\s*(?:script\s*:\s*)?"
    r"('''(?P<a>.*?)'''|\"\"\"(?P<b>.*?)\"\"\"|'(?P<c>[^'\n]*)'|\"(?P<d>[^\"\n]*)\")",
    re.DOTALL,
)

SINGLE_FILES = {
    ".gitlab-ci.yml": "gitlab",
    "Jenkinsfile": "jenkins",
    ".circleci/config.yml": "circleci",
    "azure-pipelines.yml": "azure",
    ".travis.yml": "travis",
    "bitbucket-pipelines.yml": "bitbucket",
}


@dataclass
class Job:
    """One CI job: its ordered steps (command lines / refs) and dependencies."""

    name: str
    items: list[str] = field(default_factory=list)
    needs: list[str] = field(default_factory=list)
    stage_index: int | None = None  # GitLab: jobs in later stages wait for earlier ones

    def categories(self) -> set[str]:
        return {c for item in self.items for c in classify(item)}


@dataclass
class CIFile:
    path: str
    provider: str
    jobs: list[Job] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    push_branches: list[str] = field(default_factory=list)
    runs_on_pr: bool = False
    pr_condition: bool = False  # `if: github.event_name == 'pull_request'`
    error: str | None = None


def classify(text: str) -> set[str]:
    """Categories a single command line or action reference belongs to."""
    if _INSTALL_LINE.search(text) or _ECHO_LINE.search(text):
        return set()
    return {c for c, patterns in _COMPILED.items() if any(p.search(text) for p in patterns)}


def _command_lines(value: Any) -> list[str]:
    """Split a command block (string or list) into logical lines."""
    blocks: list[str] = []
    if isinstance(value, str):
        blocks = [value]
    elif isinstance(value, list):
        blocks = [v for v in value if isinstance(v, str)]
    lines: list[str] = []
    for block in blocks:
        for line in block.replace("\\\n", " ").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
    return lines


def _strip_ref(ref: str) -> str:
    return ref.split("@", 1)[0].strip()


def _collect_items(node: Any, items: list[str]) -> None:
    """Depth-first, in document order: every command line and action ref under `node`."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _COMMAND_KEYS and isinstance(value, str | list):
                if isinstance(value, list) and any(isinstance(v, dict) for v in value):
                    _collect_items(value, items)  # e.g. Travis `deploy: [{provider: ...}]`
                else:
                    items.extend(_command_lines(value))
            elif key in _REF_KEYS and isinstance(value, str):
                items.append(_strip_ref(value))
            elif key in {"deploy", "deployment"}:  # Travis/Bitbucket deployment sections
                items.append(f"{key}: {value}" if isinstance(value, str) else key)
                _collect_items(value, items)
            else:
                _collect_items(value, items)
    elif isinstance(node, list):
        for value in node:
            _collect_items(value, items)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, str | int)]
    return []


# ----------------------------------------------------------------------------- providers


def _parse_github(ci: CIFile, doc: Any, text: str) -> None:
    if not isinstance(doc, dict):
        return
    # YAML 1.1 reads the bare key `on` as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        ci.triggers = [on]
    elif isinstance(on, list):
        ci.triggers = [str(t) for t in on]
    elif isinstance(on, dict):
        ci.triggers = [str(t) for t in on]
        push = on.get("push")
        if isinstance(push, dict):
            ci.push_branches = _as_list(push.get("branches"))
    ci.runs_on_pr = any(t in {"pull_request", "pull_request_target"} for t in ci.triggers)
    ci.pr_condition = bool(_PR_EVENT_CONDITION.search(text))
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for name, spec in jobs.items():
        job = Job(name=str(name))
        if isinstance(spec, dict):
            job.needs = _as_list(spec.get("needs"))
            if isinstance(spec.get("uses"), str):  # reusable workflow call
                job.items.append(_strip_ref(spec["uses"]))
            _collect_items(spec.get("steps", []), job.items)
        ci.jobs.append(job)


def _gitlab_pr(node: Any) -> bool:
    """`only: [merge_requests]` or a rule on `$CI_PIPELINE_SOURCE == "merge_request_event"`."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "only":
                refs = value.get("refs") if isinstance(value, dict) else value
                if "merge_requests" in _as_list(refs):
                    return True
            elif key == "if" and isinstance(value, str):
                if "merge_request_event" in value or "CI_MERGE_REQUEST" in value:
                    return True
            elif key != "except" and _gitlab_pr(value):
                return True
    elif isinstance(node, list):
        return any(_gitlab_pr(v) for v in node)
    return False


def _parse_gitlab(ci: CIFile, doc: Any) -> None:
    if not isinstance(doc, dict):
        return
    stages = _as_list(doc.get("stages")) or _GITLAB_DEFAULT_STAGES
    global_before = _command_lines(doc.get("before_script"))
    for name, spec in doc.items():
        if name in _GITLAB_RESERVED or not isinstance(spec, dict) or str(name).startswith("."):
            continue
        if not any(k in spec for k in ("script", "trigger", "extends")):
            continue
        job = Job(name=str(name))
        job.items.extend(global_before)
        _collect_items({k: v for k, v in spec.items() if k != "rules"}, job.items)
        stage = str(spec.get("stage", "test"))
        job.stage_index = stages.index(stage) if stage in stages else None
        needs = spec.get("needs")
        if isinstance(needs, list):
            job.needs = [
                n if isinstance(n, str) else str(n.get("job", ""))
                for n in needs
                if isinstance(n, str | dict)
            ]
        job.needs += _as_list(spec.get("dependencies"))
        ci.jobs.append(job)
    ci.runs_on_pr = _gitlab_pr(doc)
    ci.triggers = ["merge_request"] if ci.runs_on_pr else ["push"]


def _parse_circleci(ci: CIFile, doc: Any) -> None:
    if not isinstance(doc, dict):
        return
    jobs = doc.get("jobs")
    by_name: dict[str, Job] = {}
    if isinstance(jobs, dict):
        for name, spec in jobs.items():
            job = Job(name=str(name))
            _collect_items(spec, job.items)
            by_name[job.name] = job
    workflows = doc.get("workflows")
    if isinstance(workflows, dict):
        for workflow in workflows.values():
            entries = workflow.get("jobs", []) if isinstance(workflow, dict) else []
            for entry in entries if isinstance(entries, list) else []:
                if isinstance(entry, dict):
                    for name, options in entry.items():
                        job = by_name.setdefault(str(name), Job(name=str(name), items=[str(name)]))
                        if isinstance(options, dict):
                            job.needs += _as_list(options.get("requires"))
    ci.jobs = list(by_name.values())
    # CircleCI builds pull requests only if enabled in the project settings: unknown.
    ci.triggers = ["push"]


def _parse_single_job(ci: CIFile, doc: Any) -> None:
    """Azure, Travis, Bitbucket: treated as one sequential job."""
    job = Job(name=ci.provider)
    _collect_items(doc, job.items)
    ci.jobs = [job]
    if not isinstance(doc, dict):
        return
    if ci.provider == "travis":
        ci.runs_on_pr = True  # Travis builds pull requests by default
        ci.triggers = ["push", "pull_request"]
    elif ci.provider == "azure":
        pr = doc.get("pr", "default")
        ci.runs_on_pr = pr not in ("none", False, None)
        ci.triggers = ["push", "pull_request"] if ci.runs_on_pr else ["push"]
    elif ci.provider == "bitbucket":
        pipelines = doc.get("pipelines")
        ci.runs_on_pr = isinstance(pipelines, dict) and "pull-requests" in pipelines
        ci.triggers = ["push", "pull_request"] if ci.runs_on_pr else ["push"]


def _parse_jenkins(ci: CIFile, text: str) -> None:
    job = Job(name="Jenkinsfile")
    for match in _JENKINS_STEP.finditer(text):
        body = next(g for g in match.group("a", "b", "c", "d") if g is not None)
        job.items.extend(_command_lines(body))
    ci.jobs = [job]
    ci.runs_on_pr = "changeRequest" in text or "CHANGE_ID" in text
    ci.triggers = ["push", "pull_request"] if ci.runs_on_pr else ["push"]


# ----------------------------------------------------------------------------- analysis


def discover_ci_files(repo: Path) -> list[tuple[str, str]]:
    """(repo-relative path, provider) of every CI configuration file, sorted."""
    found: list[tuple[str, str]] = []
    workflows = repo / ".github" / "workflows"
    if workflows.is_dir() and not workflows.is_symlink():
        for path in sorted(workflows.iterdir()):
            if path.suffix in {".yml", ".yaml"} and path.is_file() and not path.is_symlink():
                found.append((path.relative_to(repo).as_posix(), "github"))
    for rel, provider in SINGLE_FILES.items():
        path = repo / rel
        if path.is_file() and not path.is_symlink():
            found.append((rel, provider))
    return found


def load_ci_file(repo: Path, rel: str, provider: str) -> CIFile:
    ci = CIFile(path=rel, provider=provider)
    path = repo / rel
    try:
        if path.stat().st_size > MAX_CI_FILE_BYTES:
            ci.error = f"larger than {MAX_CI_FILE_BYTES // 1024} KB, skipped"
            return ci
        text = path.read_text("utf-8", "replace")
    except OSError as exc:
        ci.error = f"unreadable: {exc.strerror or exc}"
        return ci
    if provider == "jenkins":
        _parse_jenkins(ci, text)
        return ci
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        ci.error = f"invalid YAML: {str(exc).splitlines()[0][:200]}"
        return ci
    if provider == "github":
        _parse_github(ci, doc, text)
    elif provider == "gitlab":
        _parse_gitlab(ci, doc)
    elif provider == "circleci":
        _parse_circleci(ci, doc)
    else:
        _parse_single_job(ci, doc)
    return ci


def _ancestors(job: Job, by_name: dict[str, Job]) -> set[str]:
    seen: set[str] = set()
    stack = list(job.needs)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in by_name:
            stack.extend(by_name[name].needs)
    return seen


def gated_jobs(ci: CIFile) -> list[str]:
    """Build/deploy jobs that only run after tests passed ("job: reason")."""
    by_name = {job.name: job for job in ci.jobs}
    test_jobs = {job.name for job in ci.jobs if "tests" in job.categories()}
    gated: list[str] = []
    for job in ci.jobs:
        builds = [i for i, item in enumerate(job.items) if "build" in classify(item)]
        if not builds:
            continue
        upstream = _ancestors(job, by_name) & test_jobs
        if upstream:
            gated.append(f"{job.name}: needs {', '.join(sorted(upstream))}")
            continue
        tests = [i for i, item in enumerate(job.items) if "tests" in classify(item)]
        if tests and min(tests) < max(builds):
            gated.append(f"{job.name}: runs after tests in the same job")
            continue
        if job.stage_index is not None and any(
            other.stage_index is not None and other.stage_index < job.stage_index
            for other in ci.jobs
            if other.name in test_jobs
        ):
            gated.append(f"{job.name}: later stage than the test jobs")
    return gated


def _file_metrics(ci: CIFile) -> dict[str, Any]:
    matched: dict[str, list[str]] = {}
    for job in ci.jobs:
        for item in job.items:
            for category in sorted(classify(item)):
                bucket = matched.setdefault(category, [])
                if len(bucket) < MAX_MATCHES_PER_CATEGORY and item[:MAX_MATCH_CHARS] not in bucket:
                    bucket.append(item[:MAX_MATCH_CHARS])
    return {
        "path": ci.path,
        "provider": ci.provider,
        "categories": [c for c in CATEGORIES if c in matched],
        "matched": matched,
        "triggers": ci.triggers,
        "push_branches": ci.push_branches,
        "runs_on_pr": ci.runs_on_pr,
        "jobs": len(ci.jobs),
        "gated": gated_jobs(ci),
        "error": ci.error,
    }


def _settings_hints(repo: Path) -> list[str]:
    hints: list[str] = []
    for rel in (".github/settings.yml", ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        path = repo / rel
        try:
            if (
                path.is_file()
                and not path.is_symlink()
                and path.stat().st_size <= MAX_CI_FILE_BYTES
            ):
                if _REQUIRED_STATUS.search(path.read_text("utf-8", "replace")):
                    hints.append(f"required status checks mentioned in {rel}")
        except OSError:
            continue
    return hints


def analyze(repo: Path) -> SignalReport:
    """Compute the CI signal for the repository at `repo` (pure file reading)."""
    files = [load_ci_file(repo, rel, provider) for rel, provider in discover_ci_files(repo)]
    if not files:
        return not_applicable(ANALYZER_NAME, "no CI configuration found")

    per_file = [_file_metrics(ci) for ci in files]
    present = {c for f in per_file for c in f["categories"]}
    runs_on_pr = any(ci.runs_on_pr for ci in files)
    gated = [f"{f['path']} {g}" for f in per_file for g in f["gated"]]

    hints = _settings_hints(repo)
    hints += [f"{f['path']} gates {g}" for f in per_file for g in f["gated"] if ": needs " in g]
    hints += [f"{ci.path} has pull_request-only conditions" for ci in files if ci.pr_condition]
    branch_protection_hint = bool(hints)

    components: dict[str, float | None] = {c: 1.0 if c in present else 0.0 for c in CATEGORIES}
    components["pr_trigger"] = 1.0 if runs_on_pr else 0.0
    components["gating"] = (
        (1.0 if gated or branch_protection_hint else 0.0) if "build" in present else None
    )
    errors = [f"{ci.path}: {ci.error}" for ci in files if ci.error]
    return SignalReport(
        name=ANALYZER_NAME,
        applicable=True,
        score=mean_score(components),
        components=components,
        metrics={
            "ci_files": per_file,
            "providers": sorted({ci.provider for ci in files}),
            "triggers": sorted({t for ci in files for t in ci.triggers}),
            "runs_on_pr": runs_on_pr,
            "gated": gated,
            "branch_protection_hint": branch_protection_hint,
            "branch_protection_hints": hints,
            "branch_protection_note": "branch protection can't be verified from the repository",
            "errors": errors,
        },
        reason=f"{len(errors)} CI file(s) could not be read" if errors else None,
    )


class CIQualityAnalyzer(Analyzer):
    """Experimental rubric-1.1 signal: quality of the CI pipeline configuration."""

    name = ANALYZER_NAME
    display_name = "CI pipeline"
    supported_languages = frozenset()
    phase = 1
    experimental = True

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = None  # reads YAML in-process; never executes anything
        self.timeout_seconds = self._settings.experimental_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        report = analyze(repo_path)
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=[],
            raw_output=json.dumps(report.as_dict()),
            duration_ms=int((time.monotonic() - started) * 1000),
            artifact=report,
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        """This signal produces no findings, only a SignalReport."""
        return []

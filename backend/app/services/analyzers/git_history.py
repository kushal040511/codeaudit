"""Git history signal: commit hygiene, activity, ownership spread, hotspots, review flow.

Input is the commit log captured in a sandbox (git_log.py): URL scans fetch
`GIT_HISTORY_DEPTH` commits; uploads that include `.git` are read by
`capture_uploaded_history`. Without history (zip upload without `.git`) the signal is
not applicable, which is never a penalty; fewer than MIN_COMMITS commits likewise.

Definitions (a "merge" has more than one parent; a "boundary" commit sits on the
shallow-clone boundary and its numstat is the whole tree, so it is never used as a
change):

- Commit messages, over non-merge commits (boundary included, bots included):
  `conventional_share` = subjects matching CONVENTIONAL; `low_info_share` = subjects
  that (stripped) fully match LOW_INFO case-insensitively or are shorter than
  MIN_SUBJECT_CHARS characters; `avg_subject_length` in characters.
- Recency, relative to `now` (the scan time by default): `days_since_last_commit`
  from the newest author timestamp, and `commits_last_90d` = non-merge commits
  authored in the 90 days before `now`. The benchmark harness scans pinned historical
  commits, so for those this measures how stale the snapshot is as of the scan.
- Line churn counts added + deleted lines from non-merge, non-boundary commits,
  excluding lockfiles and generated/vendored paths (`is_excluded`); binary files count 0.
- Authors are identified by lowercased email. Bots (`[bot]`, dependabot, renovate,
  github-actions in the name or email) are left out of the author statistics and
  reported separately as `bot_commits`.
- `bus_factor` = the minimum number of human authors whose line churn together reaches
  at least 50% of all human line churn (None without any churn).
- `author_gini` = Gini coefficient of per-author non-merge commit counts (humans):
  G = 2·Σ i·x_i / (n·Σ x) − (n + 1)/n with x ascending, i = 1..n. One author gives 0
  (the bus factor captures single ownership).
- Churn hotspots: a file's change frequency is the number of non-merge, non-boundary
  commits touching it; only files still present in the tree (and not excluded) count.
  Complexity = decision points per file from tree-sitter (`collect_complexity`, run in
  a child process for every parseable source file). The top decile of each is
  the first max(1, ceil(n / 10)) of its n files ordered by value desc, then path
  (files with complexity 0 never qualify). `hotspots` = top-decile churn ∩ top-decile
  complexity (max 20 listed), `hotspot_share` = |hotspots| / max(1, |top-decile churn|).
- Review flow: walk the first-parent chain from HEAD through the fetched commits; a
  commit came "via PR" when it's a merge or its subject ends with `(#<number>)` (GitHub
  squash merge). `direct_ratio` = direct commits / first-parent commits.

Components (each in [0, 1], 1 = best; score = mean of the available ones):
`conventional` = conventional_share; `informative` = 1 − low_info_share;
`recency` = exp(−days_since_last_commit / 365); `activity` = min(1, commits_last_90d / 10);
`bus_factor` = min(bus_factor, 3) / 3; `concentration` = 1 − author_gini;
`hotspots` = 1 − hotspot_share; `review_flow` = 1 − direct_ratio.

Limitations: with a shallow history (the default 200 commits) every statistic is over
that window only, and the oldest (boundary) commit's changes are unknown. The squash
heuristic depends on GitHub's default "(#123)" subject suffix; rebase merges look
direct. Complexity is measured on the scanned tree only, not per revision.
"""

import json
import math
import os
import re
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from app.config import Settings, get_settings
from app.core.errors import AnalysisError
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.git_log import (
    MAX_COMMITS,
    Commit,
    capture_uploaded_history,
    read_history,
)
from app.services.analyzers.signals import SignalReport, mean_score, not_applicable

ANALYZER_NAME = "git_history"
COLLECTOR = "app.services.analyzers.git_history:collect_complexity"
MIN_COMMITS = 5
MIN_SUBJECT_CHARS = 8
RECENT_DAYS = 90
ACTIVE_COMMITS = 10  # commits in RECENT_DAYS for full activity
BUS_FACTOR_TARGET = 3
MAX_HOTSPOTS = 20
DAY = 86400.0

CONVENTIONAL = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([^)]+\))?!?: .+"
)
LOW_INFO = re.compile(
    r"^(fix|fixes|fixed|update|updates|updated|wip|test|tests|asdf|misc|changes|minor|stuff|\.)\.?$",
    re.IGNORECASE,
)
SQUASH_SUFFIX = re.compile(r"\(#\d+\)\s*$")
BOT_MARKERS = ("[bot]", "dependabot", "renovate", "github-actions")

EXCLUDED_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
        "poetry.lock",
        "pipfile.lock",
        "uv.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
    }
)
EXCLUDED_DIRS = frozenset({"dist", "build", "vendor", "node_modules"})
EXCLUDED_SUFFIXES = (".min.js", ".min.css", ".map")

# Decision points counted by collect_complexity, per grammar family.
PYTHON_DECISIONS = frozenset(
    {
        "if_statement",
        "elif_clause",
        "for_statement",
        "while_statement",
        "except_clause",
        "case_clause",
        "conditional_expression",
        "boolean_operator",  # one `and` / `or`
        "if_clause",  # comprehension filter
    }
)
JS_DECISIONS = frozenset(
    {
        "if_statement",  # `else if` is a nested if_statement
        "for_statement",
        "for_in_statement",  # for-in and for-of
        "while_statement",
        "do_statement",
        "switch_case",  # not `default`
        "catch_clause",
        "ternary_expression",
    }
)
JS_LOGICAL = frozenset({"&&", "||"})


# --- helpers -------------------------------------------------------------------------


def author_email(author: str) -> str:
    """Lowercased email from a "name <email>" author string."""
    _, _, rest = author.rpartition("<")
    return rest.rstrip(">").strip().lower() if rest else author.strip().lower()


def is_bot(author: str) -> bool:
    lowered = author.lower()
    return any(marker in lowered for marker in BOT_MARKERS)


def is_excluded(path: str) -> bool:
    """Lockfiles and generated/vendored files don't count as churn."""
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name in EXCLUDED_NAMES or name.endswith(EXCLUDED_SUFFIXES):
        return True
    return any(part in EXCLUDED_DIRS for part in pure.parts[:-1])


def is_low_info(subject: str) -> bool:
    stripped = subject.strip()
    return len(stripped) < MIN_SUBJECT_CHARS or LOW_INFO.fullmatch(stripped) is not None


def gini(values: Iterable[int]) -> float | None:
    """Gini coefficient of non-negative counts; None for no data or all zeros."""
    ordered = sorted(values)
    total = sum(ordered)
    n = len(ordered)
    if n == 0 or total == 0:
        return None
    weighted = sum(i * x for i, x in enumerate(ordered, start=1))
    return 2 * weighted / (n * total) - (n + 1) / n


def bus_factor(lines_by_author: Mapping[str, int]) -> int | None:
    """Minimum number of authors covering at least half of all changed lines."""
    total = sum(lines_by_author.values())
    if total <= 0:
        return None
    covered = 0
    for count, lines in enumerate(sorted(lines_by_author.values(), reverse=True), start=1):
        covered += lines
        if 2 * covered >= total:
            return count
    return len(lines_by_author)  # unreachable


def top_decile(values: Mapping[str, int]) -> list[str]:
    """Top max(1, ceil(n/10)) of all n entries by value desc, then path; zeros never count."""
    if not values:
        return []
    size = max(1, math.ceil(len(values) / 10))
    ordered = sorted(values.items(), key=lambda item: (-item[1], item[0]))
    return [path for path, value in ordered[:size] if value > 0]


def _share(part: int, whole: int) -> float | None:
    return part / whole if whole else None


# --- metrics -------------------------------------------------------------------------


def message_metrics(commits: list[Commit]) -> dict[str, Any]:
    subjects = [c.subject for c in commits if not c.is_merge]
    conventional = sum(1 for s in subjects if CONVENTIONAL.match(s.strip()))
    low_info = sum(1 for s in subjects if is_low_info(s))
    return {
        "message_commits": len(subjects),
        "conventional_commits": conventional,
        "conventional_share": _share(conventional, len(subjects)),
        "low_info_commits": low_info,
        "low_info_share": _share(low_info, len(subjects)),
        "avg_subject_length": (
            sum(len(s.strip()) for s in subjects) / len(subjects) if subjects else None
        ),
    }


def recency_metrics(commits: list[Commit], now: float) -> dict[str, Any]:
    newest = max(c.timestamp for c in commits)
    since = now - RECENT_DAYS * DAY
    return {
        "last_commit_timestamp": newest,
        "days_since_last_commit": max(0.0, (now - newest) / DAY),
        "commits_last_90d": sum(1 for c in commits if not c.is_merge and c.timestamp >= since),
    }


def author_metrics(commits: list[Commit]) -> dict[str, Any]:
    lines: Counter[str] = Counter()
    commit_counts: Counter[str] = Counter()
    bot_commits = 0
    for commit in commits:
        if commit.is_merge:
            continue
        if is_bot(commit.author):
            bot_commits += 1
            continue
        identity = author_email(commit.author)
        commit_counts[identity] += 1
        lines[identity] += 0  # authors without countable lines still exist
        if commit.boundary:
            continue
        for path, added, deleted in commit.files:
            if not is_excluded(path):
                lines[identity] += (added or 0) + (deleted or 0)
    return {
        "authors": len(commit_counts),
        "bot_commits": bot_commits,
        "bus_factor": bus_factor(lines),
        "author_gini": gini(commit_counts.values()),
        "changed_lines": sum(lines.values()),
        "lines_by_author": dict(lines.most_common(10)),
        "commits_by_author": dict(commit_counts.most_common(10)),
    }


def change_frequency(commits: list[Commit], present: set[str]) -> dict[str, int]:
    """Commits touching each file still in the tree (non-merge, non-boundary)."""
    frequency: Counter[str] = Counter()
    for commit in commits:
        if commit.is_merge or commit.boundary:
            continue
        for path in {p for p, _, _ in commit.files}:
            if path in present and not is_excluded(path):
                frequency[path] += 1
    return dict(frequency)


def hotspot_metrics(
    frequency: Mapping[str, int], complexity: Mapping[str, int] | None
) -> dict[str, Any]:
    churn_top = top_decile(frequency)
    if complexity is None:
        return {
            "top_churn_files": churn_top[:MAX_HOTSPOTS],
            "hotspots": None,
            "hotspot_share": None,
        }
    complex_top = set(top_decile(complexity))
    hotspots = [p for p in churn_top if p in complex_top]
    share = len(hotspots) / max(1, len(churn_top)) if churn_top and complex_top else None
    return {
        "top_churn_files": churn_top[:MAX_HOTSPOTS],
        "top_complexity_files": sorted(complex_top)[:MAX_HOTSPOTS],
        "hotspots": [
            {"path": p, "commits": frequency[p], "complexity": complexity[p]}
            for p in hotspots[:MAX_HOTSPOTS]
        ],
        "hotspot_count": len(hotspots),
        "hotspot_share": share,
    }


def review_flow_metrics(commits: list[Commit]) -> dict[str, Any]:
    if not commits:
        return {"first_parent_commits": 0, "direct_commits": 0, "direct_ratio": None}
    by_sha = {c.sha: c for c in commits}
    current: Commit | None = commits[0]  # git log prints HEAD first
    seen: set[str] = set()
    total = direct = 0
    while current is not None and current.sha not in seen:
        seen.add(current.sha)
        total += 1
        if not (current.is_merge or SQUASH_SUFFIX.search(current.subject)):
            direct += 1
        current = by_sha.get(current.parents[0]) if current.parents else None
    return {
        "first_parent_commits": total,
        "direct_commits": direct,
        "direct_ratio": _share(direct, total),
    }


def build_report(
    commits: list[Commit],
    now: float,
    present_files: set[str],
    complexity: Mapping[str, int] | None,
) -> SignalReport:
    """Score a parsed history; pure apart from its inputs."""
    if len(commits) < MIN_COMMITS:
        return not_applicable(ANALYZER_NAME, f"too little history (<{MIN_COMMITS} commits)")
    metrics: dict[str, Any] = {
        "history_depth": len(commits),
        "merge_commits": sum(1 for c in commits if c.is_merge),
        "truncated_by_shallow_boundary": any(c.boundary for c in commits),
        "truncated_by_max_commits": len(commits) >= MAX_COMMITS,
        "first_commit_timestamp": min(c.timestamp for c in commits),
    }
    metrics |= message_metrics(commits)
    metrics |= recency_metrics(commits, now)
    metrics |= author_metrics(commits)
    frequency = change_frequency(commits, present_files)
    metrics["files_with_churn"] = len(frequency)
    metrics |= hotspot_metrics(frequency, complexity)
    metrics |= review_flow_metrics(commits)

    def inverse(value: float | None) -> float | None:
        return None if value is None else 1.0 - value

    bus = metrics["bus_factor"]
    components: dict[str, float | None] = {
        "conventional": metrics["conventional_share"],
        "informative": inverse(metrics["low_info_share"]),
        "recency": math.exp(-metrics["days_since_last_commit"] / 365),
        "activity": min(1.0, metrics["commits_last_90d"] / ACTIVE_COMMITS),
        "bus_factor": None if bus is None else min(bus, BUS_FACTOR_TARGET) / BUS_FACTOR_TARGET,
        "concentration": inverse(metrics["author_gini"]),
        "hotspots": inverse(metrics["hotspot_share"]),
        "review_flow": inverse(metrics["direct_ratio"]),
    }
    reason = None
    if metrics["truncated_by_shallow_boundary"]:
        reason = f"based on the latest {len(commits)} commits only (shallow history)"
    return SignalReport(
        name=ANALYZER_NAME,
        applicable=True,
        score=mean_score(components),
        components=components,
        metrics=metrics,
        reason=reason,
    )


# --- tree-sitter collector (runs in a child process, see isolated_signal.py) ---------


def collect_complexity(repo: Path, deadline: float, paths: list[str]) -> dict[str, int]:
    """Decision-point count per parseable source file in `paths` (repo-relative)."""
    from tree_sitter import Parser

    from app.services.analyzers.isolated_signal import CollectorTimeout
    from app.services.graph.parser import MAX_FILE_BYTES, _walk, grammar_language, language_for

    root = repo.resolve()
    result: dict[str, int] = {}
    for rel in paths:
        if time.monotonic() > deadline:
            raise CollectorTimeout("complexity collection ran out of time")
        detected = language_for(rel)
        if detected is None:
            continue
        family, grammar = detected
        path = repo / rel
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_bytes()
        except OSError:
            continue
        tree = Parser(grammar_language(grammar)).parse(source)
        count = 0
        for node in _walk(tree.root_node):
            if family == "python":
                count += node.type in PYTHON_DECISIONS
            elif node.type in JS_DECISIONS:
                count += 1
            elif node.type == "binary_expression":
                operator = node.child_by_field_name("operator")
                count += operator is not None and operator.type in JS_LOGICAL
        result[rel] = count
    return result


def present_files(repo: Path) -> set[str]:
    """Repo-relative POSIX paths of the regular files in the tree.

    `.git` and excluded (vendored/generated) directories are skipped: they never count.
    """
    files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(repo):  # does not follow symlinks
        dirnames[:] = [d for d in dirnames if d != ".git" and d not in EXCLUDED_DIRS]
        for name in filenames:
            path = Path(dirpath, name)
            if not path.is_symlink():
                files.add(path.relative_to(repo).as_posix())
    return files


# --- analyzer --------------------------------------------------------------------------


class GitHistoryAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "Git history"
    supported_languages = frozenset()
    experimental = True
    phase = 2

    def __init__(self, settings: Settings | None = None, now: float | None = None) -> None:
        self._settings = settings or get_settings()
        self._now = now  # fixed "current time" for tests; None = time.time() per run
        self.docker_image = None  # log captured by the clone/upload sandbox; parsing is local
        self.timeout_seconds = self._settings.experimental_timeout_seconds

    def _history(self, repo_path: Path, context: ScanContext) -> list[Commit] | None:
        if context.git_log_path is not None:
            history = read_history(context.git_log_path)
            if history is not None:
                return history
        if (repo_path / ".git").is_dir():
            captured = capture_uploaded_history(
                repo_path, context.work_dir / "history-upload", context.scan_id
            )
            if captured is not None:
                return read_history(captured)
        return None

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        started = time.monotonic()
        warnings: list[str] = []
        commits = self._history(repo_path, context)
        if commits is None:
            report = not_applicable(ANALYZER_NAME, "no git history (zip upload without .git)")
        elif len(commits) < MIN_COMMITS:
            report = not_applicable(ANALYZER_NAME, f"too little history (<{MIN_COMMITS} commits)")
        else:
            present = present_files(repo_path)
            complexity = self._complexity(repo_path, context, present, warnings)
            now = self._now if self._now is not None else time.time()
            report = build_report(commits, now, present, complexity)
        raw_output = json.dumps(report.as_dict())
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=[],
            raw_output=raw_output,
            duration_ms=int((time.monotonic() - started) * 1000),
            warnings=tuple(warnings),
            artifact=report,
        )

    def _complexity(
        self, repo_path: Path, context: ScanContext, present: set[str], warnings: list[str]
    ) -> dict[str, int] | None:
        from app.services.analyzers.isolated_signal import run_collector
        from app.services.graph.parser import IGNORED_DIRS, language_for

        paths = sorted(
            p
            for p in present
            if language_for(p) is not None
            and not IGNORED_DIRS.intersection(PurePosixPath(p).parts[:-1])
        )
        if not paths:
            return {}
        try:
            result = run_collector(
                COLLECTOR, repo_path, context.work_dir, self.timeout_seconds, {"paths": paths}
            )
        except AnalysisError as exc:  # includes timeouts: hotspots become unavailable
            warnings.append(f"Complexity for churn hotspots unavailable: {exc}")
            return None
        return {str(k): int(v) for k, v in result.items()}

    def parse(self, raw_output: str) -> list[FindingData]:
        return []  # a signal, not findings

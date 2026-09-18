"""Git history signal: log parsing, each metric on synthetic histories, and a real repo."""

import math
import os
import subprocess
from pathlib import Path

import pytest

from app.services.analyzers import git_history
from app.services.analyzers.base import ScanContext
from app.services.analyzers.git_history import (
    GitHistoryAnalyzer,
    author_metrics,
    build_report,
    bus_factor,
    change_frequency,
    collect_complexity,
    gini,
    hotspot_metrics,
    is_excluded,
    message_metrics,
    recency_metrics,
    review_flow_metrics,
    top_decile,
)
from app.services.analyzers.git_log import (
    BOUNDARY_FILENAME,
    HISTORY_MOUNT,
    LOG_FILENAME,
    LOG_SHELL,
    SAFE_ENV,
    Commit,
    parse_log,
    read_history,
)
from app.services.analyzers.signals import SignalReport

DAY = 86400
T0 = 1_700_000_000


def record(sha: str, parents: str, name: str, email: str, when: int, subject: str) -> str:
    return "\x1e" + "\x1f".join([sha, parents, name, email, str(when), subject]) + "\n"


def commit(
    sha: str,
    subject: str = "a sufficiently long subject",
    parents: tuple[str, ...] = (),
    author: str = "A <a@x.io>",
    when: int = T0,
    files: list[tuple[str, int | None, int | None]] | None = None,
    boundary: bool = False,
) -> Commit:
    return Commit(sha, list(parents), author, when, subject, files or [], boundary)


# --- parse_log ---------------------------------------------------------------------------


def test_parse_log_reads_commits_merges_binary_files_and_boundary() -> None:
    text = (
        record("c3", "c2 b1", "Merger", "M@X.io", T0 + 2, "Merge pull request #4 from x/y")
        + record("c2", "c1", "Ann", "Ann@Example.COM", T0 + 1, "feat: add logo")
        + "\n5\t1\tsrc/a.py\n-\t-\tassets/logo.png\n"
        + record("c1", "", "Ann", "ann@example.com", T0, "initial")
        + "\n100\t0\tsrc/a.py\n"
    )

    commits = parse_log(text, boundary={"c1"})

    assert [c.sha for c in commits] == ["c3", "c2", "c1"]
    assert commits[0].is_merge and commits[0].parents == ["c2", "b1"]
    assert commits[1].author == "Ann <ann@example.com>"
    assert commits[1].files == [("src/a.py", 5, 1), ("assets/logo.png", None, None)]
    assert [c.boundary for c in commits] == [False, False, True]
    assert commits[2].files == [("src/a.py", 100, 0)]


def test_parse_log_skips_malformed_records() -> None:
    text = (
        "\x1egarbage without separators\n1\t1\tx.py\n"
        + "\x1e"
        + "\x1f".join(["c9", "", "N", "n@x", "not-a-time", "s"])
        + "\n"
        + record("c1", "", "Ann", "a@x", T0, "ok subject")
        + "\nnot a numstat line\n2\t3\tb.py\n"
    )

    commits = parse_log(text)

    assert [c.sha for c in commits] == ["c1"]
    assert commits[0].files == [("b.py", 2, 3)]


def test_parse_log_unquotes_unusual_paths() -> None:
    text = (
        record("c1", "", "A", "a@x", T0, "s") + '\n1\t0\t"tab\\there"\n1\t0\t"caf\\303\\251.py"\n'
    )

    assert [f[0] for f in parse_log(text)[0].files] == ["tab\there", "café.py"]


def test_read_history_marks_shallow_boundary(tmp_path: Path) -> None:
    (tmp_path / LOG_FILENAME).write_text(
        record("c2", "c1", "A", "a@x", T0, "s") + record("c1", "", "A", "a@x", T0, "s")
    )
    (tmp_path / BOUNDARY_FILENAME).write_text("c1\n")

    commits = read_history(tmp_path)

    assert commits is not None and [c.boundary for c in commits] == [False, True]
    assert read_history(tmp_path / "missing") is None


# --- metrics on synthetic histories ------------------------------------------------------


def test_message_metrics() -> None:
    commits = [
        commit("1", "feat(api)!: drop v1"),
        commit("2", "fix: handle empty input"),
        commit("3", "Fixed."),
        commit("4", "WIP"),
        commit("5", "short"),  # < 8 characters
        commit("6", "Refactor the loader"),
        commit("7", "Merge branch 'x'", parents=("6", "b")),  # merges are ignored
        commit("8", "feat:missing space"),  # not conventional, but informative
    ]

    metrics = message_metrics(commits)

    assert metrics["message_commits"] == 7
    assert metrics["conventional_commits"] == 2
    assert metrics["conventional_share"] == pytest.approx(2 / 7)
    assert metrics["low_info_commits"] == 3
    assert metrics["low_info_share"] == pytest.approx(3 / 7)
    lengths = [19, 23, 6, 3, 5, 19, 18]
    assert metrics["avg_subject_length"] == pytest.approx(sum(lengths) / 7)


def test_recency_metrics() -> None:
    now = T0 + 100 * DAY
    commits = [
        commit("3", when=T0 + 95 * DAY),
        commit("2", when=T0 + 20 * DAY, parents=("1", "b")),  # merge: not counted as activity
        commit("1", when=T0 + 20 * DAY),
        commit("0", when=T0),
    ]

    metrics = recency_metrics(commits, now)

    assert metrics["days_since_last_commit"] == pytest.approx(5.0)
    assert metrics["commits_last_90d"] == 2


def test_bus_factor_and_gini_values() -> None:
    assert bus_factor({"a": 50, "b": 30, "c": 20}) == 1  # exactly half is enough
    assert bus_factor({"a": 40, "b": 30, "c": 30}) == 2
    assert bus_factor({"a": 10, "b": 10, "c": 10, "d": 10}) == 2
    assert bus_factor({"a": 0}) is None
    assert gini([5, 5, 5]) == pytest.approx(0.0)
    assert gini([1, 3]) == pytest.approx(0.25)
    assert gini([0, 0, 0, 10]) == pytest.approx(0.75)
    assert gini([7]) == pytest.approx(0.0)
    assert gini([]) is None


def test_author_metrics_ignore_merges_boundary_bots_and_lockfiles() -> None:
    commits = [
        commit("m", parents=("5", "b"), author="Ann <ann@x.io>", files=[("a.py", 999, 0)]),
        commit(
            "5",
            author="dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
            files=[("package-lock.json", 50, 50)],
        ),
        commit("4", author="Bob <BOB@x.io>", files=[("b.py", 30, 10), ("yarn.lock", 500, 0)]),
        commit("3", author="Robert <bob@x.io>", files=[("b.py", 20, 0), ("img.png", None, None)]),
        commit("2", author="Ann <ann@x.io>", files=[("a.py", 45, 5), ("dist/app.js", 900, 0)]),
        commit("1", author="Ann <ann@x.io>", files=[("a.py", 5000, 0)], boundary=True),
    ]

    metrics = author_metrics(commits)

    assert metrics["authors"] == 2  # bob@x.io under two names is one author
    assert metrics["bot_commits"] == 1
    assert metrics["lines_by_author"] == {"bob@x.io": 60, "ann@x.io": 50}
    assert metrics["changed_lines"] == 110
    assert metrics["bus_factor"] == 1
    # commit counts: ann 2 (incl. the boundary commit), bob 2
    assert metrics["commits_by_author"] == {"ann@x.io": 2, "bob@x.io": 2}
    assert metrics["author_gini"] == pytest.approx(0.0)


def test_excluded_paths() -> None:
    for path in (
        "package-lock.json",
        "web/yarn.lock",
        "a/b.min.js",
        "dist/x.js",
        "build/y.py",
        "vendor/lib.go",
        "node_modules/p/index.js",
    ):
        assert is_excluded(path), path
    for path in ("src/build.py", "distance.py", "app.js"):
        assert not is_excluded(path), path


def test_review_flow_follows_first_parent_and_counts_squash_merges() -> None:
    commits = [
        commit("h", "docs: readme (#12)", parents=("m",)),  # squash merge
        commit("m", "Merge pull request #11", parents=("d", "f")),  # merge
        commit("f", "feature work on a branch", parents=("d",)),  # second parent: skipped
        commit("d", "pushed straight to main", parents=("c",)),
        commit("c", "fix: mention #12 in text", parents=("b",)),  # not a suffix: direct
        commit("b", "Add thing (#7)  ", parents=("a",)),  # squash with trailing spaces
        commit("a", "initial", parents=("outside-history",)),
    ]

    metrics = review_flow_metrics(commits)

    assert metrics["first_parent_commits"] == 6
    assert metrics["direct_commits"] == 3  # d, c, a
    assert metrics["direct_ratio"] == pytest.approx(0.5)


def test_top_decile_and_hotspots() -> None:
    frequency = {f"f{i:02}.py": 20 - i for i in range(20)}  # f00 most changed
    assert top_decile(frequency) == ["f00.py", "f01.py"]
    assert top_decile({"a": 1, "b": 1}) == ["a"]  # ties broken by path, at least one
    assert top_decile({"a": 0, "b": 0}) == []
    complexity = {f"f{i:02}.py": i for i in range(20)} | {"f00.py": 99}

    metrics = hotspot_metrics(frequency, complexity)

    assert metrics["top_churn_files"] == ["f00.py", "f01.py"]
    assert metrics["hotspots"] == [{"path": "f00.py", "commits": 20, "complexity": 99}]
    assert metrics["hotspot_share"] == pytest.approx(0.5)
    assert hotspot_metrics(frequency, None)["hotspot_share"] is None


def test_change_frequency_counts_present_files_once_per_commit() -> None:
    commits = [
        commit("3", files=[("a.py", 1, 0), ("gone.py", 1, 0)]),
        commit("2", files=[("a.py", 1, 0), ("b.py", 1, 1)], parents=("1", "x")),  # merge
        commit("1", files=[("a.py", 1, 0), ("b.py", 1, 1)], boundary=True),
        commit("0", files=[("b.py", 2, 0), ("package-lock.json", 3, 3)]),
    ]

    assert change_frequency(commits, {"a.py", "b.py", "package-lock.json"}) == {
        "a.py": 1,
        "b.py": 1,
    }


def test_build_report_requires_five_commits() -> None:
    report = build_report([commit(str(i)) for i in range(4)], T0, set(), None)

    assert not report.applicable
    assert report.reason == "too little history (<5 commits)"


def test_collect_complexity_counts_decision_points(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(a, b):\n"
        "    if a and b or a:\n        pass\n"
        "    elif b:\n        x = 1 if a else 2\n"
        "    for i in []:\n        pass\n"
        "    while a:\n        pass\n"
        "    try:\n        pass\n    except E:\n        pass\n"
        "    match a:\n        case 1:\n            pass\n"
        "    y = [i for i in a if i]\n"
    )
    (tmp_path / "b.ts").write_text(
        "function f(a, b) { if (a && b || c) {} else if (b) {} for (;;) {} for (x of y) {}\n"
        "for (k in o) {} while (a) {} do {} while (a); switch (a) { case 1: break; default: }\n"
        "try {} catch (e) {} const q = a ? 1 : 2; const r = a ?? b; }\n"
    )
    (tmp_path / "notes.txt").write_text("if and or")

    result = collect_complexity(tmp_path, float("inf"), ["a.py", "b.ts", "notes.txt", "none.py"])

    assert result == {"a.py": 10, "b.ts": 12}


# --- absence -----------------------------------------------------------------------------


def context(tmp_path: Path, git_log_path: Path | None = None) -> ScanContext:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return ScanContext(scan_id="s1", work_dir=work, languages=[], git_log_path=git_log_path)


def test_no_history_is_not_applicable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text("print(1)\n")

    result = GitHistoryAnalyzer(now=T0).run(repo, context(tmp_path))

    assert result.success and isinstance(result.artifact, SignalReport)
    assert not result.artifact.applicable
    assert "no git history" in (result.artifact.reason or "")


def test_uploaded_git_that_cannot_be_read_is_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    calls: list[Path] = []

    def fail(repo_path: Path, output_dir: Path, scan_id: str) -> None:
        calls.append(output_dir)
        return None

    monkeypatch.setattr(git_history, "capture_uploaded_history", fail)

    result = GitHistoryAnalyzer(now=T0).run(repo, context(tmp_path, tmp_path / "empty"))

    assert calls == [tmp_path / "work" / "history-upload"]
    assert isinstance(result.artifact, SignalReport) and not result.artifact.applicable
    assert "no git history" in (result.artifact.reason or "")


# --- a real repository with poor hygiene -------------------------------------------------

ALICE = ("Alice", "alice@example.com")
BOB = ("Bob", "BOB@Example.com")
BOT = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")


def git(repo: Path, *args: str, author: tuple[str, str] = ALICE, when: int = T0) -> None:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_DATE": f"@{when} +0000",
        "GIT_COMMITTER_DATE": f"@{when} +0000",
    }
    subprocess.run(
        [
            "git",
            "-c",
            f"user.name={author[0]}",
            "-c",
            f"user.email={author[1]}",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )


def append(repo: Path, rel: str, lines: list[str]) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write("".join(f"{line}\n" for line in lines))


def commit_all(repo: Path, subject: str, author: tuple[str, str], day: float) -> None:
    git(repo, "add", "-A", author=author)
    git(repo, "commit", "-q", "-m", subject, author=author, when=int(T0 + day * DAY))


def capture_log(repo: Path, out: Path) -> Path:
    """Run the exact LOG_SHELL used by the sandboxes, writing to `out` instead of /history."""
    out.mkdir(parents=True, exist_ok=True)
    assert LOG_SHELL.count(f" {HISTORY_MOUNT}/") == 2  # the log and the shallow list
    command = LOG_SHELL.replace(f" {HISTORY_MOUNT}/", f" {out}/")
    env = {"PATH": os.environ["PATH"], "HOME": str(repo), **SAFE_ENV}
    subprocess.run(["bash", "-c", command], cwd=repo, env=env, check=True, capture_output=True)
    return out


@pytest.fixture
def sloppy_repo(tmp_path: Path) -> Path:
    """Ten commits: two humans, one bot, one merge, mostly uninformative messages.

    Lines: alice 10+4+30+2+6 = 52 (package-lock.json excluded), bob 5+20+3 = 28.
    """
    repo = tmp_path / "sloppy"
    repo.mkdir()
    git(repo, "init", "-q")
    app_line = "x = 1 if a else 2"  # one decision point per line
    append(repo, "src/app.py", [app_line] * 10)
    append(repo, "package-lock.json", ["{}"] * 100)
    commit_all(repo, "initial commit", ALICE, 0)
    append(repo, "src/app.py", [app_line] * 5)
    commit_all(repo, "wip", BOB, 1)
    append(repo, "src/app.py", [app_line] * 4)
    commit_all(repo, "fix", ALICE, 2)
    append(repo, "src/util.py", ["y = 1"] * 20)
    commit_all(repo, "asdf", BOB, 3)
    append(repo, "src/parser.py", ["p = a or b"] * 3 + ["z = 1"] * 27)
    commit_all(repo, "feat(core): add parser", ALICE, 4)
    append(repo, "src/app.py", [app_line] * 2)
    commit_all(repo, "update", ALICE, 5)
    git(repo, "checkout", "-q", "-b", "feature")
    append(repo, "src/util.py", ["y = 2"] * 3)
    commit_all(repo, "fix: handle empty input (#12)", BOB, 6)
    git(repo, "checkout", "-q", "main")
    git(
        repo,
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "Merge pull request #13 from bob/feature",
        "feature",
        when=int(T0 + 6.5 * DAY),
    )
    append(repo, "package-lock.json", ["{}"])
    commit_all(repo, "Bump lodash from 4.17.20 to 4.17.21", BOT, 7)
    append(repo, "README.md", ["usage"] * 6)
    commit_all(repo, "docs: describe usage (#14)", ALICE, 8)
    return repo


def test_sloppy_repository_metrics(sloppy_repo: Path, tmp_path: Path) -> None:
    history = capture_log(sloppy_repo, tmp_path / "history")
    now = T0 + 18 * DAY
    work = tmp_path / "work"
    work.mkdir()
    ctx = ScanContext(scan_id="s1", work_dir=work, languages=[], git_log_path=history)

    result = GitHistoryAnalyzer(now=now).run(sloppy_repo, ctx)

    assert result.success and result.warnings == ()
    report = result.artifact
    assert isinstance(report, SignalReport) and report.applicable
    m = report.metrics
    assert m["history_depth"] == 10
    assert m["merge_commits"] == 1
    assert m["truncated_by_shallow_boundary"] is False
    assert m["message_commits"] == 9
    assert m["conventional_commits"] == 3
    assert m["low_info_commits"] == 4  # wip, fix, asdf, update
    assert m["avg_subject_length"] == pytest.approx(142 / 9)
    assert m["days_since_last_commit"] == pytest.approx(10.0)
    assert m["commits_last_90d"] == 9
    assert m["authors"] == 2
    assert m["bot_commits"] == 1
    assert m["lines_by_author"] == {"alice@example.com": 52, "bob@example.com": 28}
    assert m["bus_factor"] == 1
    assert m["commits_by_author"] == {"alice@example.com": 5, "bob@example.com": 3}
    assert m["author_gini"] == pytest.approx(0.125)
    assert m["files_with_churn"] == 4  # app, util, parser, README (lockfile excluded)
    assert m["top_churn_files"] == ["src/app.py"]
    assert m["hotspots"] == [{"path": "src/app.py", "commits": 4, "complexity": 21}]
    assert m["hotspot_share"] == pytest.approx(1.0)
    assert m["first_parent_commits"] == 9
    assert m["direct_commits"] == 7  # all but the merge and the "(#14)" squash
    assert report.components == pytest.approx(
        {
            "conventional": 3 / 9,
            "informative": 5 / 9,
            "recency": math.exp(-10 / 365),
            "activity": 0.9,
            "bus_factor": 1 / 3,
            "concentration": 0.875,
            "hotspots": 0.0,
            "review_flow": 2 / 9,
        }
    )
    assert report.score == pytest.approx(sum(report.components.values()) / 8)  # type: ignore[arg-type]


def test_shallow_clone_ignores_the_boundary_commits_changes(
    sloppy_repo: Path, tmp_path: Path
) -> None:
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "5", f"file://{sloppy_repo}", str(shallow)],
        check=True,
        capture_output=True,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(tmp_path),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )
    commits = read_history(capture_log(shallow, tmp_path / "history"))

    assert commits is not None
    boundary = [c for c in commits if c.boundary]
    assert [c.subject for c in boundary] == ["feat(core): add parser"]
    # The boundary numstat is the whole tree (all 19 lines of src/app.py at that point).
    assert ("src/app.py", 19, 0) in boundary[0].files
    report = build_report(commits, T0 + 18 * DAY, {"src/app.py", "src/parser.py"}, None)
    assert report.applicable
    assert report.metrics["truncated_by_shallow_boundary"] is True
    assert report.metrics["history_depth"] == 6
    # Only "update" touched src/app.py after the boundary; parser.py only at the boundary.
    assert report.metrics["top_churn_files"] == ["src/app.py"]
    assert report.metrics["files_with_churn"] == 1
    assert report.metrics["lines_by_author"] == {"alice@example.com": 8, "bob@example.com": 3}

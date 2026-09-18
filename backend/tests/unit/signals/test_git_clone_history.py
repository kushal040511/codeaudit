"""The clone sandbox fetches history only when asked, and writes it with LOG_SHELL."""

from app.services.analyzers.git_log import HISTORY_MOUNT, LOG_FILENAME, LOG_SHELL
from app.services.github.clone import CLONE_SCRIPT, clone_environment

URL = "https://github.com/o/r.git"
SHA = "a" * 40


def test_clone_environment_carries_the_depth() -> None:
    assert clone_environment(URL, SHA, None)["CLONE_DEPTH"] == "1"
    assert clone_environment(URL, SHA, None, depth=200)["CLONE_DEPTH"] == "200"
    assert clone_environment(URL, SHA, None, depth=0)["CLONE_DEPTH"] == "1"  # never below one


def test_clone_script_writes_history_only_for_deep_clones() -> None:
    assert '--depth "$CLONE_DEPTH"' in CLONE_SCRIPT
    guarded = f'if [ "$CLONE_DEPTH" -gt 1 ]; then {LOG_SHELL}; fi'
    assert guarded in CLONE_SCRIPT
    assert CLONE_SCRIPT.count(LOG_SHELL) == 1  # never run unguarded
    assert f"{HISTORY_MOUNT}/{LOG_FILENAME}" in LOG_SHELL
    # The log is written before .git is removed.
    assert CLONE_SCRIPT.index(guarded) < CLONE_SCRIPT.index("rm -rf .git")


def test_log_shell_disables_external_programs() -> None:
    for option in (
        "core.fsmonitor=false",
        "core.hooksPath=/dev/null",
        "diff.external=",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
    ):
        assert option in LOG_SHELL

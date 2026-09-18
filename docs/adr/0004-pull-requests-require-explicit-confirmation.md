# ADR 0004: Pull requests require explicit confirmation

- Status: accepted
- Code: `backend/app/api/routes/pull_requests.py`, `backend/app/services/github/pr_builder.py`, `backend/app/workers/tasks.py` (`create_pull_request_task`), `backend/app/schemas/pull_request.py`
- Test: `backend/tests/integration/test_pull_requests.py`

## Context

CodeAudit can turn LLM-generated fix suggestions into a GitHub pull request, using the user's OAuth token. Writing to someone's repository is the one action with effects outside CodeAudit, and GitHub writes aren't idempotent. LLM patches can be wrong, and the base branch can move between the scan and the write.

## Decision

Two steps, and only one code path writes to GitHub.

1. **Preview.** `POST /api/scans/{id}/pull-requests/preview` calls `build_plan` and `save_preview`. The plan re-applies each patch to the base branch's current head and reports patches that no longer apply or that conflict with each other (`stale_head` or `merge_conflict`). It returns the full diff, commits, body and score projection, stores a `preview_fingerprint`, and writes nothing to GitHub.
2. **Confirm.** `POST /api/pull-requests/{id}/confirm` requires `confirm: Literal[True]` (`PullRequestConfirmRequest`). A missing, false, `"yes"` or null value is a 422. The endpoint refuses previews that were already confirmed or are older than `PREVIEW_TTL` (30 minutes). It then sets `creating` plus `confirmed_at` and queues `create_pull_request_task`.
3. **Write.** `create_pull_request_from_preview` refuses unless the row is `creating` with `confirmed_at` set (`not_confirmed`). It rebuilds the plan and raises `preview_outdated` if the fingerprint differs from the preview. Only then does it create the branch, one commit per fix group, and the PR. The task is never retried (docstring in `tasks.py`).

**Only verified patches.** `load_groups` excludes any suggestion that isn't `READY` with `validation_status == VALID` and a patch, and it tells the user why.

**Single code path, enforced by a test.** `test_only_the_confirm_endpoint_can_start_pull_request_creation` in `backend/tests/integration/test_pull_requests.py` walks the AST of every file under `app/`. It asserts that `create_pull_request_task` is only dispatched from `api/routes/pull_requests.py` and that `create_pull_request_from_preview` is only called from `workers/tasks.py`. `test_no_pull_request_without_explicit_confirmation` in the same file checks the 422 cases and the missing-CSRF 403. It also checks that running the task or the builder directly on an unconfirmed preview writes nothing.

## Consequences

Positive:

- Nothing reaches GitHub without an explicit, recent confirmation of an exact diff the user has seen.
- A moved base branch or changed selection is caught before any write (`preview_outdated`, `stale_head`).
- Unverified LLM output can't end up in a PR.
- New code that queues PR creation elsewhere fails CI.

Negative:

- Two round trips, and previews expire after 30 minutes.
- A worker dying mid-write can leave a partial branch. The beat reaper marks the row `failed` with `interrupted` after 15 minutes and tells the user to check the repository (`workers/maintenance.py`).
- The static test only recognises direct calls and `delay`/`apply_async`/signature calls on the task name. Indirect dispatch, such as `send_task` by string name, wouldn't be caught.
- API tokens (`cat_…`) can't open pull requests (README, "Security"). Pull requests need a browser session.

## Alternatives considered

- **Create the PR automatically after enrichment.** Rejected because it writes to a user's repository without review and uses unverified or stale patches.
- **One-step confirm without a preview fingerprint.** The user could approve a diff that is no longer what gets pushed.
- **Include unverified patches marked as drafts.** Contradicts the rule that only `valid` patches are offered as fixes (README, "Patch validation").

# CodeAudit GitHub Action

Scans every pull request with your CodeAudit server and posts one comment (updated on each push) with:

- the head commit's score and grade, next to the base commit's,
- the score change,
- findings the pull request introduces (and how many it resolves),

and can fail the check when the score drops under a threshold or new critical findings appear.

The action never writes code or opens pull requests. It only reads scan results and comments.

## Setup

1. **A reachable CodeAudit server.** The runner calls your server's API, so it must be reachable from GitHub-hosted runners (or use a self-hosted runner on your network).
2. **An API token.** Sign in to CodeAudit with GitHub, open *Settings → API tokens*, and create one. Add it to the repository as the secret `CODEAUDIT_API_TOKEN`.
   - Scans are created as the token's owner, so that user's GitHub connection is used to read the repository. For private repositories, connect GitHub with private repository access.
   - Each run needs up to two scans (head and base); already-scanned commits are reused. The default limit is 30 scans per user per hour.
3. **The workflow.** Copy [`examples/codeaudit.yml`](examples/codeaudit.yml) to `.github/workflows/codeaudit.yml`. The job needs `pull-requests: write` to comment.

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-url` | required | Base URL of your CodeAudit server. |
| `api-token` | required | CodeAudit API token (use a secret). |
| `fail-under` | *(off)* | Fail if the head score is below this value. An unscored scan also fails. |
| `fail-on-new-critical` | `false` | Fail if the pull request adds critical findings. |
| `comment` | `true` | Post or update the report comment. |
| `timeout-minutes` | `30` | How long to wait for scans. |
| `frontend-url` | `api-url` | Base URL of the web app, for the "Full report" link. |
| `github-token` | `${{ github.token }}` | Token used to comment. |

## Outputs

`scan-id`, `score`, `grade`, `score-delta`, `new-findings`, `new-critical`. `score-delta`, `new-findings` and `new-critical` are empty outside pull requests.

## How findings are compared

Findings are matched between base and head by analyzer, rule, file and the flagged code (whitespace-insensitive), not by line number, so code moving around doesn't count as new findings. A second copy of an existing issue does count as new.

The score delta is only reliable when both scans use the same rubric version and every analyzer completed. Otherwise the comment says so. Failing on the threshold still applies to the head score.

## Security notes

- The API token is masked in logs and sent only to `api-url`.
- For pull requests from forks, GitHub doesn't expose secrets to `pull_request` workflows, so the action can't authenticate. Don't work around this with `pull_request_target` plus a checkout of the fork's code. This action doesn't need a checkout at all, but keep that rule in mind if you add other steps.

## Other events

On `push` or `workflow_dispatch` the action scans `GITHUB_SHA`, sets `score`/`grade`, applies `fail-under`, and writes the job summary. It doesn't compare or comment.

# Rubric validation

Does the score order repositories the way an independent quality judgement does? The design, labels and known weaknesses are in [PROTOCOL.md](PROTOCOL.md) (committed before any scan). The findings are in [docs/validation.md](../../docs/validation.md).

| File | What it is |
|---|---|
| `labels.csv` | 20 repositories pinned to commits, with 1–5 labels per category. Pre-registered, never edited after scanning. |
| `run.py` | Scans every labelled commit through the API and records the stored scores (`scans.jsonl`). |
| `export.py` | Dumps each scan's scorable inputs (analyzer, rule, severity, path, corroboration, LOC, module count) to `findings.jsonl`. No source code. |
| `report.py` | Rescores `findings.jsonl` with the rubric in the working tree. Reports Spearman ρ with bootstrap CIs and permutation p-values, within-group ρ, inversions and parameter sensitivity. |
| `results/<date>-v<rubric>/` | `scans.jsonl`, `findings.jsonl`, `metrics.json` and `report.md` for each run. |

## Reproduce the report (no Docker needed)

The committed snapshot is enough to regenerate every number in the report exactly:

```sh
cd backend
uv run python ../validation/rubric/report.py \
    ../validation/rubric/results/20260918-v1.0/findings.jsonl --out /tmp/rubric-check
diff /tmp/rubric-check/metrics.json ../validation/rubric/results/20260918-v1.0/metrics.json
```

`report.py` stops if rescoring the snapshot doesn't reproduce the scores the API stored, so a stale snapshot can't pass silently.

## Re-run the scans

Start the stack with LLM enrichment off (the score never depends on it) and anonymous quotas raised, for example with a compose override:

```yaml
# measure.override.yml
x-env: &env {LLM_ENABLED: "false", SCAN_CACHE_TTL_SECONDS: "0", QUOTA_ANONYMOUS_SCANS_PER_DAY: "1000"}
services: {api: {environment: *env}, worker: {environment: *env}, beat: {environment: *env}}
```

```sh
docker compose -f docker-compose.yml -f measure.override.yml up -d --wait
python validation/rubric/run.py --zip-cache /tmp/zips --out validation/rubric/results/<date>/scans.jsonl
docker compose exec -T -e SCANS_JSONL="$(cat validation/rubric/results/<date>/scans.jsonl)" worker \
    python - < validation/rubric/export.py > validation/rubric/results/<date>/findings.jsonl
```

- `--zip-cache` fetches each commit's archive with the authenticated `gh` CLI and uploads it. Without it, `run.py` scans by URL, which uses GitHub's unauthenticated API (60 requests per hour per IP).
- Zip upload rejects archives that contain symbolic links. Two repositories (psf/requests and fastapi/full-stack-fastapi-template) have symlinks, so they were scanned by URL. Both paths run the same analyzers on the same commit.
- Scores can change when analyzer images or Semgrep registry rules change. Registry packs are downloaded at scan time and cached for 24 hours, and aren't pinned. That's why the committed snapshot, not a rescan, is the reproducible artifact.

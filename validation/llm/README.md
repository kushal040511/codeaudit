# LLM enrichment evaluation

Measures two things on a fixed set of pinned commits (a subset of the rubric study's repositories):

- **Patch validation pass rate:** of the fix suggestions whose patch was validated, how many apply to the scanned commit with `git apply` and still parse.
- **Architecture citation hallucination rate:** of the module references the architecture review cites, how many don't exist in the scan's import graph. The stricter *rejected-evidence rate* (below) is reported alongside.

## Run

With the stack up, LLM enrichment on and a provider configured (Ollama or Anthropic), and anonymous quotas raised as in `validation/rubric/README.md`:

```sh
python validation/llm/run.py --zip-cache /tmp/zips \
    --out validation/llm/results/<date>-<model>/scans.jsonl
D=validation/llm/results/<date>-<model>
docker compose exec -T -e SCANS_JSONL="$(cat $D/scans.jsonl)" worker python - < validation/llm/report.py > $D/metrics.json
docker compose exec -T -e SCANS_JSONL="$(cat $D/scans.jsonl)" worker python - --markdown < validation/llm/report.py > $D/report.md
```

## Caveats

- **"Valid" means applies and parses.** It doesn't mean compiles, type-checks or passes tests.
- **Sampling isn't seeded.** Ollama runs at temperature 0.2 with no seed, so pass rates vary between runs. Report the model digest (`ollama show <model>`) with the numbers.
- **Two hallucination measures:**
  - **Stored rate** (what the API shows): only counts module references that don't exist in the graph. A cited import `a -> b` between two real modules that doesn't exist is rejected, but it isn't counted as a hallucination.
  - **Rejected-evidence rate** (in this report): counts every citation the verifier rejected, including those fabricated edges.
  - **Prose:** paths mentioned in the prose that aren't in the graph are listed separately, and neither rate counts them.
- **fastapi/full-stack-fastapi-template is left out.** Its archive contains symlinks, which zip upload rejects.

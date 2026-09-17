# Phishing risk validation

Measures how well the site analyzer's risk score separates confirmed phishing pages from legitimate sites, and which signals carry predictive weight.

```sh
# 1. Build a labeled dataset (OpenPhish positives; brand official pages + Tranco popular sites as negatives)
docker compose run --rm -v ./validation:/app/validation worker \
  python /app/validation/phishing/build_dataset.py --phishing 150 --popular 150

# 2. Evaluate every URL (sandboxed capture through the egress proxy; resumable)
docker compose run --rm -v ./validation:/app/validation worker \
  python /app/validation/phishing/run.py /app/validation/phishing/data/dataset-YYYYMMDD.csv --workers 3

# 3. Report
docker compose run --rm -v ./validation:/app/validation worker \
  python /app/validation/phishing/report.py /app/validation/phishing/data/dataset-YYYYMMDD.results.jsonl \
  --out /app/validation/phishing/results/YYYYMMDD
```

Notes:
- **Dead URLs.** Phishing URLs die within hours. Every URL gets a state (`ok`, `unreachable`, `dead_http`, `taken_down`, `blocked`, `error`), and only `ok` rows are scored. The report says how many were unreachable.
- **Label leakage.** Positives come from OpenPhish, and OpenPhish and Safe Browsing are also reputation signals. The headline metrics exclude reputation; the full score is shown separately and is inflated.
- **Defanged output.** The dataset and raw results contain live phishing URLs and are gitignored. Reports defang URLs.
- **Negatives are easier than real traffic.** Popular sites are established domains with valid certificates. The false positive rate on a random sample of the long tail (small businesses, new sites) will be higher.
- **Visiting pages.** The run loads live phishing pages from this machine's network, inside the capture sandbox.

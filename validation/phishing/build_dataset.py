"""Build a labeled URL dataset for validating the phishing risk score.

Positives: confirmed phishing URLs from the OpenPhish community feed (at most one
per registrable domain, so one campaign can't dominate). Optionally PhishTank's
online-valid feed when PHISHTANK_APP_KEY is set.

Negatives:
- official brand pages from the reference set (the hardest negatives: they look
  exactly like the brands phishing imitates), and
- a seeded random sample of popular sites from the Tranco top list.

Writes validation/phishing/data/dataset-<date>.csv (gitignored: it contains live
phishing URLs, which must not be published).

    python validation/phishing/build_dataset.py --phishing 150 --popular 150
"""

import argparse
import csv
import io
import os
import random
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, "/app")

from app.services.web.brands import BRANDS  # noqa: E402
from app.services.web.intel import split_domain  # noqa: E402
from app.services.web.netguard import BlockedUrlError, normalize_url  # noqa: E402

HERE = Path(__file__).resolve().parent
OPENPHISH = "https://openphish.com/feed.txt"
PHISHTANK = "https://data.phishtank.com/data/{key}/online-valid.json"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def _registrable(url: str) -> str | None:
    try:
        return split_domain(normalize_url(url).host).registrable
    except BlockedUrlError:
        return None


def phishing_urls(limit: int, rng: random.Random, http: httpx.Client) -> list[tuple[str, str]]:
    lines = [line.strip() for line in http.get(OPENPHISH).text.splitlines() if line.strip()]
    candidates = [("openphish", url) for url in lines]
    key = os.environ.get("PHISHTANK_APP_KEY")
    if key:
        response = http.get(PHISHTANK.format(key=key))
        if response.status_code == 200:
            candidates += [("phishtank", entry["url"]) for entry in response.json()]
    rng.shuffle(candidates)
    seen: set[str] = set()
    chosen: list[tuple[str, str]] = []
    for source, url in candidates:
        registrable = _registrable(url)
        if registrable is None or registrable in seen:
            continue
        seen.add(registrable)
        chosen.append((url, source))
        if len(chosen) >= limit:
            break
    return chosen


def popular_urls(limit: int, rng: random.Random, http: httpx.Client, top: int) -> list[tuple[str, str]]:
    archive = zipfile.ZipFile(io.BytesIO(http.get(TRANCO).content))
    rows = list(csv.reader(io.TextIOWrapper(archive.open(archive.namelist()[0]), encoding="utf-8")))[:top]
    brand_domains = {d for brand in BRANDS for d in brand.domains}
    domains = [domain for _, domain in rows if domain not in brand_domains]
    return [(f"https://{domain}/", "tranco") for domain in rng.sample(domains, min(limit, len(domains)))]


def brand_urls() -> list[tuple[str, str]]:
    return [(url, "brand_official") for brand in BRANDS for _, url in brand.references]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phishing", type=int, default=150)
    parser.add_argument("--popular", type=int, default=150)
    parser.add_argument("--tranco-top", type=int, default=10_000, help="sample popular sites from this many top ranks")
    parser.add_argument("--seed", type=int, default=20260917)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    with httpx.Client(timeout=60, follow_redirects=True, headers={"User-Agent": "CodeAudit-validation/1.0"}) as http:
        rows = [(url, 1, source) for url, source in phishing_urls(args.phishing, rng, http)]
        rows += [(url, 0, source) for url, source in brand_urls()]
        rows += [(url, 0, source) for url, source in popular_urls(args.popular, rng, http, args.tranco_top)]

    out = HERE / "data" / f"dataset-{datetime.now(UTC):%Y%m%d}.csv"
    out.parent.mkdir(exist_ok=True)
    added = datetime.now(UTC).isoformat(timespec="seconds")
    with out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label", "source", "added_at"])
        writer.writerows((url, label, source, added) for url, label, source in rows)
    positives = sum(1 for _, label, _ in rows if label)
    print(f"wrote {out} ({positives} phishing, {len(rows) - positives} legitimate)")


if __name__ == "__main__":
    main()

"""Visual reference set: hashes of known brand pages and favicons.

`reference_data/references.json` (committed) holds only hashes and capture
metadata. The reference screenshots, used for side-by-side comparison in the UI,
are stored in object storage by the build command, not in the repository.

Build or refresh (captures every reference page through the normal sandboxed
browser and egress proxy):

    python -m app.services.web.references build [--brand paypal ...]
"""

import argparse
import json
import logging
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from app.config import get_settings
from app.core.storage import upload_bytes
from app.services.web.brands import BRANDS, BRANDS_BY_KEY
from app.services.web.visual import hash_favicon, hash_screenshot

logger = logging.getLogger(__name__)

DATA_FILE = Path(__file__).with_name("reference_data") / "references.json"

# Brands often serve bot checks, block pages or unfinished app shells to a headless
# browser. Those are not the page a phishing kit copies, so they are never stored.
# (CAPTCHAs are never solved or bypassed.)
NOT_A_REFERENCE = re.compile(
    r"confirm you.?re (a )?human|are you a robot|verify you are human|captcha|access denied|"
    r"request (could not|can.?t) be processed|don.?t have permission to view|unusual traffic|"
    r"something went wrong|^sorry\b|pardon our interruption|checking your browser",
    re.IGNORECASE | re.MULTILINE,
)
MIN_REFERENCE_TEXT = 40


@dataclass(frozen=True)
class Reference:
    brand: str
    page: str
    url: str
    final_url: str
    phash: str
    dhash: str
    low_information: bool
    favicon_sha256: str | None
    favicon_phash: str | None
    screenshot_key: str | None
    captured_at: str

    @property
    def brand_name(self) -> str:
        return BRANDS_BY_KEY[self.brand].name if self.brand in BRANDS_BY_KEY else self.brand


def reference_screenshot_key(brand: str, page: str) -> str:
    return f"web-references/{brand}/{page}.png"


@lru_cache(maxsize=1)
def load_references(path: Path = DATA_FILE) -> tuple[Reference, ...]:
    if not path.is_file():
        return ()
    data = json.loads(path.read_text())
    return tuple(Reference(**item) for item in data.get("references", []))


def build(brand_keys: list[str] | None) -> None:
    from app.services.web.capture import CaptureError, capture_page
    from app.services.web.netguard import validate_url

    settings = get_settings()
    existing = {(r.brand, r.page): r for r in load_references()}
    brands = [BRANDS_BY_KEY[k] for k in brand_keys] if brand_keys else list(BRANDS)
    root = Path(settings.scan_workspace_dir)
    root.mkdir(parents=True, exist_ok=True)
    for brand in brands:
        for page, url in brand.references:
            workdir = Path(tempfile.mkdtemp(prefix="scan-ref-", dir=root))
            try:
                validate_url(url)
                capture = capture_page(url, workdir, label=f"reference-{brand.key}-{page}")
            except (CaptureError, ValueError) as exc:
                logger.warning("reference %s/%s failed: %s", brand.key, page, exc)
                continue
            finally:
                pass
            try:
                visible = f"{capture.title}\n{capture.text}".strip()
                if (
                    NOT_A_REFERENCE.search(visible)
                    or len(capture.text.strip()) < MIN_REFERENCE_TEXT
                ):
                    logger.warning(
                        "reference %s/%s skipped: bot check, block page or unrendered page (%r)",
                        brand.key,
                        page,
                        visible[:80],
                    )
                    existing.pop((brand.key, page), None)
                    continue
                if capture.fold_png is None:
                    logger.warning("reference %s/%s: no screenshot", brand.key, page)
                    continue
                hashes = hash_screenshot(capture.fold_png)
                if hashes is None:
                    continue
                favicon = hash_favicon(capture.favicon) if capture.favicon else None
                key = reference_screenshot_key(brand.key, page)
                upload_bytes(key, capture.fold_png, "image/png")
                existing[(brand.key, page)] = Reference(
                    brand=brand.key,
                    page=page,
                    url=url,
                    final_url=capture.final_url,
                    phash=hashes.phash,
                    dhash=hashes.dhash,
                    low_information=hashes.low_information,
                    favicon_sha256=favicon.sha256 if favicon else None,
                    favicon_phash=favicon.phash if favicon else None,
                    screenshot_key=key,
                    captured_at=datetime.now(UTC).isoformat(timespec="seconds"),
                )
                logger.info("reference %s/%s captured (%s)", brand.key, page, capture.final_url)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
    DATA_FILE.parent.mkdir(exist_ok=True)
    ordered = sorted(existing.values(), key=lambda r: (r.brand, r.page))
    DATA_FILE.write_text(
        json.dumps({"version": 1, "references": [asdict(r) for r in ordered]}, indent=2) + "\n"
    )
    load_references.cache_clear()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--brand", action="append", choices=sorted(BRANDS_BY_KEY))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.command == "build":
        build(args.brand)


if __name__ == "__main__":
    main()

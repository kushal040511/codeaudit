"""Site analysis pipeline: capture -> intel -> risk evidence -> design tokens.

A failed capture fails the analysis. Everything after it degrades per signal: an
unavailable lookup becomes an "unavailable" evidence item, and a failed vision
step leaves CSS-derived tokens with a note.
"""

import io
import logging
import shutil
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from PIL import Image
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.storage import upload_bytes
from app.models import LLMPurpose, SiteAnalysis, SiteAnalysisStatus
from app.services.llm.client import ImageInput, LLMClient, LLMError, llm_configured
from app.services.web.capture import Capture, capture_page
from app.services.web.design import VISION_SYSTEM, VisionDesign, extract_tokens
from app.services.web.intel import (
    CertificateInfo,
    DnsInfo,
    Registration,
    Reputation,
    check_openphish,
    check_safe_browsing,
    fetch_certificate,
    lookup_dns,
    lookup_registration,
    split_domain,
)
from app.services.web.netguard import normalize_url, validate_url
from app.services.web.references import load_references
from app.services.web.risk import RiskInputs, RiskReport, assess
from app.services.web.visual import hash_favicon, hash_screenshot

logger = logging.getLogger(__name__)

VISION_MAX_EDGE = 1568
VISION_MAX_FULL_HEIGHT = 4000


@dataclass
class Intel:
    registration: Registration | None
    dns: DnsInfo | None
    certificate: CertificateInfo | None
    reputation: list[Reputation]


def gather_intel(capture: Capture) -> Intel:
    final = normalize_url(capture.final_url)
    parts = split_domain(final.host)
    urls = list(dict.fromkeys([capture.requested_url, capture.final_url]))
    is_ip = final.ip is not None
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="site-intel") as pool:
        # A tenant of a shared platform (x.vercel.app, y.weebly.com) has no registration of
        # its own; the platform's decades-old record says nothing about the site.
        registration = (
            pool.submit(lookup_registration, parts.registrable)
            if not is_ip and not parts.hosting_platform
            else None
        )
        dns = pool.submit(lookup_dns, final.host, parts.registrable) if not is_ip else None
        certificate = (
            pool.submit(fetch_certificate, final.host, final.port)
            if final.scheme == "https"
            else None
        )
        safe_browsing = pool.submit(check_safe_browsing, urls)
        openphish = pool.submit(check_openphish, urls)
        return Intel(
            registration=(
                registration.result()
                if registration
                else Registration(
                    error=(
                        "shared hosting platform subdomain;"
                        " the platform's registration date doesn't apply"
                        if parts.hosting_platform
                        else "IP address host"
                    )
                )
            ),
            dns=dns.result() if dns else None,
            certificate=certificate.result() if certificate else None,
            reputation=[safe_browsing.result(), openphish.result()],
        )


def capture_summary(capture: Capture) -> dict[str, Any]:
    link_domains: dict[str, int] = {}
    for url in capture.links:
        try:
            host = normalize_url(url).host
        except ValueError:
            continue
        registrable = split_domain(host).registrable
        link_domains[registrable] = link_domains.get(registrable, 0) + 1
    forms = [
        {
            "action": str(form.get("action") or "")[:500],
            "method": form.get("method"),
            "input_types": sorted({str(i.get("type")) for i in form.get("inputs") or []}),
            "has_password": any(i.get("type") == "password" for i in form.get("inputs") or []),
            "has_card_fields": any(i.get("card_like") for i in form.get("inputs") or []),
        }
        for form in capture.forms
    ]
    return {
        "title": capture.title,
        "status": capture.status,
        "redirect_chain": capture.redirect_chain,
        "meta": [
            m
            for m in capture.meta
            if m.get("name")
            in {
                "description",
                "og:title",
                "og:site_name",
                "og:description",
                "generator",
                "robots",
                "theme-color",
            }
        ],
        "link_domains": sorted(link_domains.items(), key=lambda item: -item[1])[:50],
        "forms": forms,
        "tls": capture.tls,
        "favicon_url": capture.favicon_url,
        "blocked_requests": capture.blocked_requests[:50],
        "errors": capture.errors,
        "duration_ms": capture.duration_ms,
    }


def _vision_images(capture: Capture) -> list[ImageInput]:
    images = []
    for data, max_height in ((capture.fold_png, None), (capture.full_png, VISION_MAX_FULL_HEIGHT)):
        if not data:
            continue
        with Image.open(io.BytesIO(data)) as source:
            image: Image.Image = source.convert("RGB")
        if max_height and image.height > max_height:
            image = image.crop((0, 0, image.width, max_height))
        scale = min(1.0, VISION_MAX_EDGE / max(image.size))
        if scale < 1:
            image = image.resize((int(image.width * scale), int(image.height * scale)))
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=85)
        images.append(ImageInput(buffer.getvalue(), "image/jpeg"))
    return images


def describe_design(
    analysis_id: uuid.UUID, capture: Capture, llm: LLMClient | None
) -> tuple[VisionDesign | None, str | None]:
    if llm is None:
        return None, llm_configured() or "Vision model unavailable."
    images = _vision_images(capture)
    if not images:
        return None, "No screenshot to describe."
    try:
        result = llm.generate_json(
            site_analysis_id=analysis_id,
            purpose=LLMPurpose.DESIGN_VISION,
            system=VISION_SYSTEM,
            prompt=(
                "The first image is the above-the-fold view (1366x768); the second, if present, is "
                "the top of the full page. Describe the design as specified."
            ),
            schema=VisionDesign,
            context={"final_url": capture.final_url[:500]},
            max_tokens=4000,
        )
    except LLMError as exc:
        return None, f"Vision description failed: {exc}"
    return result.parsed, None


def _store_artifacts(analysis: SiteAnalysis, capture: Capture) -> None:
    prefix = f"sites/{analysis.id}"
    for attribute, data, name, content_type in (
        ("screenshot_key", capture.fold_png, "fold.png", "image/png"),
        ("full_screenshot_key", capture.full_png, "full.png", "image/png"),
        ("favicon_key", capture.favicon, "favicon.bin", "application/octet-stream"),
        ("dom_key", capture.dom_html, "dom.html", "text/plain"),  # never served as HTML
    ):
        if data:
            key = f"{prefix}/{name}"
            upload_bytes(key, data, content_type)
            setattr(analysis, attribute, key)


def run_site_analysis(
    db: Session,
    analysis: SiteAnalysis,
    *,
    llm: LLMClient | None,
    capture_fn: Any = capture_page,
    intel_fn: Any = gather_intel,
) -> None:
    settings = get_settings()
    analysis.status = SiteAnalysisStatus.RUNNING
    analysis.started_at = datetime.now(UTC)
    analysis.stage = "capturing"
    db.commit()

    # Re-validate at run time: DNS may have changed since the request was accepted.
    url, _ = validate_url(analysis.normalized_url)
    root = Path(settings.scan_workspace_dir)
    root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix=f"scan-site-{analysis.id.hex[:8]}-", dir=root))
    try:
        capture = capture_fn(url.url, workdir, label=str(analysis.id))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    analysis.final_url = capture.final_url
    analysis.capture = capture_summary(capture)
    _store_artifacts(analysis, capture)
    analysis.stage = "assessing_risk"
    db.commit()

    intel = intel_fn(capture)
    screenshot = hash_screenshot(capture.fold_png) if capture.fold_png else None
    favicon = hash_favicon(capture.favicon) if capture.favicon else None
    report: RiskReport = assess(
        RiskInputs(
            capture=capture,
            registration=intel.registration,
            dns=intel.dns,
            certificate=intel.certificate,
            reputation=intel.reputation,
            screenshot=screenshot,
            favicon=favicon,
            references=load_references(),
        )
    )
    analysis.risk_score = report.score
    analysis.risk_level = report.level
    analysis.risk_evidence = report.as_dict()
    analysis.stage = "extracting_design"
    db.commit()

    notes: list[str] = []
    vision, note = describe_design(analysis.id, capture, llm)
    if note:
        notes.append(note)
    if not capture.styles:
        notes.append("No computed styles were captured; design tokens are empty.")
    analysis.design_tokens = extract_tokens(capture.styles, capture.final_url, vision)
    if analysis.design_tokens.get("dropped_colors"):
        notes.append(
            f"{len(analysis.design_tokens['dropped_colors'])} color(s) named by the vision model"
            " were not found in the page's CSS and were dropped."
        )
    analysis.design_notes = notes
    analysis.status = SiteAnalysisStatus.COMPLETED
    analysis.stage = None
    analysis.completed_at = datetime.now(UTC)
    db.commit()
    logger.info(
        "site analysis %s: risk %s, %d elements", analysis.id, report.score, len(capture.styles)
    )

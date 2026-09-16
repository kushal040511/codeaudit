"""The LLM stage end to end: fix suggestions with patch validation, architecture review
with citation checking, endpoints, and graceful degradation. Fake Anthropic API, real DB."""

import re
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import Settings
from app.core.db import SessionLocal
from app.models import (
    ArchitectureReview,
    EnrichmentStatus,
    Finding,
    FixStatus,
    FixSuggestion,
    Scan,
    ScanStatus,
    Severity,
    ValidationStatus,
)
from app.services import scan_pipeline
from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.base import FindingData
from app.services.analyzers.registry import AnalyzerRegistry
from app.services.languages import detect_languages
from app.services.llm.client import LLMClient
from app.services.llm.enrichment import finish_enrichment, run_enrichment, start_enrichment
from app.workers import tasks
from tests.fakes import FakeAnalyzer
from tests.llm_fakes import FakeAnthropic, api_error, message, user_prompt

pytestmark = pytest.mark.integration

MIXED = Path(__file__).parents[1] / "fixtures" / "architecture" / "mixed_repo"

VALID_PRICING_PATCH = """--- a/backend/app/services/pricing.py
+++ b/backend/app/services/pricing.py
@@ -5,4 +5,4 @@
 
 
 def price_with_tax(product: Product) -> str:
-    return json.dumps(utils.round_money(product.price * 1.2))
+    return json.dumps(utils.round_money(product.price * 1.25))
"""
# Context that doesn't exist in routes.py
STALE_ROUTES_PATCH = """--- a/backend/app/api/routes.py
+++ b/backend/app/api/routes.py
@@ -6,3 +6,3 @@
 router = APIRouter(prefix="/api")
 router.add_api_route("/price", price_with_tax)
-config = yaml.safe_load("a: 1")
+config = {"a": 1}
"""
BROKEN_TS_PATCH = """--- a/frontend/src/store/cartSlice.ts
+++ b/frontend/src/store/cartSlice.ts
@@ -5,4 +5,4 @@
 export const cartStore: { current: Cart; render: typeof Price } = {
   current: { items: [] },
-  render: Price,
+  render: Price(,
 }
"""
DEPENDENCY_PATCH = """--- a/backend/requirements.txt
+++ b/backend/requirements.txt
@@ -1,2 +1,2 @@
 fastapi==0.115.0
-PyYAML==6.0.2
+PyYAML==6.0.3
"""


def fix_json(ids: list[int], patch: str, **extra: str) -> str:
    import json

    return json.dumps(
        {
            "fixes": [
                {
                    "finding_ids": ids,
                    "explanation": extra.get("explanation", "Explains the problem."),
                    "confidence": extra.get("confidence", "high"),
                    "patch": patch,
                    "breaking_risk": extra.get("breaking_risk", "none"),
                    "test_suggestion": "A regression test.",
                }
            ]
        }
    )


REVIEW_JSON = """{
  "summary": "Small two-part app.",
  "strengths": ["Backend routes go through a service layer."],
  "issues": [
    {"title": "Store depends on UI", "severity": "high",
     "evidence": [
       "frontend/src/store/cartSlice.ts -> frontend/src/components/Price.tsx",
       "frontend/src/utils/cache.ts"
     ],
     "why_it_matters": "Lower layers importing UI couples state to rendering.",
     "refactor_steps": ["Move Price formatting to a util", "Import the util from the store"]},
    {"title": "Invented repository layer", "severity": "warning",
     "evidence": ["backend/app/repositories/product_repository.py"],
     "why_it_matters": "Made up.", "refactor_steps": []}
  ],
  "suggested_target_structure": "backend/app/{api,services}\\nfrontend/src/{components,store}"
}"""


def responder(body: dict[str, Any]) -> httpx2.Response:
    if "principal software architect" in body["system"]:
        return message(REVIEW_JSON, input_tokens=4000, output_tokens=900)
    prompt = user_prompt(body)
    ids = [int(i) for i in re.findall(r'<finding id="(\d+)">', prompt)]
    if "backend/app/services/pricing.py" in prompt:
        return message(fix_json(ids, VALID_PRICING_PATCH))
    if "backend/app/api/routes.py" in prompt:
        return message(fix_json(ids, STALE_ROUTES_PATCH, confidence="medium"))
    if "cartSlice" in prompt:
        return message(fix_json(ids, BROKEN_TS_PATCH))
    if "backend/app/services/utils.py" in prompt:
        return message(
            fix_json(ids, "", confidence="low", explanation="Unused import; not a risk.")
        )
    if "PyYAML" in prompt:
        # Fenced, with chatter: must still parse.
        return message(
            "Here you go:\n```json\n"
            + fix_json(ids, DEPENDENCY_PATCH, breaking_risk="low")
            + "\n```"
        )
    raise AssertionError(f"unexpected prompt: {prompt[:200]}")


FINDINGS = [
    FindingData(
        "semgrep",
        "hardcoded-tax",
        Severity.ERROR,
        "backend/app/services/pricing.py",
        8,
        8,
        "Hardcoded tax rate.",
    ),
    FindingData("bandit", "B506", Severity.ERROR, "backend/app/api/routes.py", 8, 8, "yaml.load"),
    FindingData(
        "semgrep",
        "ts-any",
        Severity.WARNING,
        "frontend/src/store/cartSlice.ts",
        7,
        7,
        "Untyped render.",
    ),
    FindingData(
        "dependency",
        "CVE-2099-0001",
        Severity.CRITICAL,
        "backend/requirements.txt",
        2,
        2,
        "pyyaml 6.0.2: test advisory",
        dependency={
            "ecosystem": "PyPI",
            "package": "pyyaml",
            "installed_version": "6.0.2",
            "advisory_id": "CVE-2099-0001",
            "fixed_version": "6.0.3",
            "fixed_versions": ["6.0.3"],
            "aliases": [],
        },
    ),
    FindingData(
        "ruff", "F401", Severity.INFO, "backend/app/services/utils.py", 1, 1, "unused import"
    ),
]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    shutil.copytree(MIXED, source)
    return source


@pytest.fixture
def analyzed_scan(database: None, repo: Path, monkeypatch: pytest.MonkeyPatch) -> uuid.UUID:
    """A scan analyzed with the real architecture analyzer plus fake findings."""
    monkeypatch.setattr(scan_pipeline, "llm_configured", lambda: None)  # pretend a key is set
    with SessionLocal() as db:
        scan = Scan(
            status=ScanStatus.RUNNING, original_filename="mixed.zip", storage_key="uploads/x"
        )
        db.add(scan)
        db.commit()
        scan_pipeline.analyze_and_persist(
            db,
            scan,
            repo,
            repo.parent,
            detect_languages(repo),
            AnalyzerRegistry([ArchitectureAnalyzer(), FakeAnalyzer("semgrep", FINDINGS)]),
        )
        assert scan.status is ScanStatus.ANALYSIS_COMPLETE
        assert scan.enrichment_status is EnrichmentStatus.PENDING
        return scan.id


def llm(fake: FakeAnthropic, **overrides: object) -> LLMClient:
    values = {"anthropic_model": "claude-sonnet-4-6", "llm_max_retries": 1} | overrides
    settings = Settings(**values)  # type: ignore[arg-type]
    return LLMClient(fake.client(), settings=settings, sleep=lambda _: None)


def enrich(scan_id: uuid.UUID, repo: Path, client: LLMClient) -> EnrichmentStatus:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and start_enrichment(db, scan)
        outcome = run_enrichment(db, scan, repo, client)
        finish_enrichment(db, scan_id, outcome.status, " ".join(outcome.problems) or None)
        return outcome.status


def suggestions(scan_id: uuid.UUID) -> dict[str, FixSuggestion]:
    with SessionLocal() as db:
        rows = db.execute(
            select(Finding.rule_id, FixSuggestion)
            .join(FixSuggestion, FixSuggestion.finding_id == Finding.id)
            .where(Finding.scan_id == scan_id)
        ).all()
        return {rule: suggestion for rule, suggestion in rows}


def test_enrichment_validates_patches_and_citations(
    analyzed_scan: uuid.UUID, repo: Path, api: TestClient
) -> None:
    fake = FakeAnthropic(responder=responder)

    status = enrich(analyzed_scan, repo, llm(fake))

    assert status is EnrichmentStatus.COMPLETED
    fixes = suggestions(analyzed_scan)
    assert {rule: s.validation_status for rule, s in fixes.items()} == {
        "CVE-2099-0001": ValidationStatus.VALID,  # fenced output with chatter, still parsed
        "hardcoded-tax": ValidationStatus.VALID,
        "B506": ValidationStatus.FAILED_TO_APPLY,
        "ts-any": ValidationStatus.SYNTAX_ERROR,
        "F401": ValidationStatus.NO_PATCH,
    }
    assert all(s.status is FixStatus.READY for s in fixes.values())
    assert "patch does not apply" in (fixes["B506"].validation_detail or "")
    assert (fixes["ts-any"].validation_detail or "").startswith("frontend/src/store/cartSlice.ts:7")
    assert fixes["CVE-2099-0001"].breaking_risk is not None
    assert fixes["CVE-2099-0001"].breaking_risk.value == "low"
    assert (repo / "backend/app/services/pricing.py").read_text().count("* 1.2)") == 1  # untouched

    with SessionLocal() as db:
        scan = db.get(Scan, analyzed_scan)
        assert scan is not None and scan.status is ScanStatus.COMPLETED
        review = db.get(ArchitectureReview, analyzed_scan)
        assert review is not None
        # Kept issue: a real edge (2 refs) + 1 invented module; dropped issue: 1 invented.
        assert (review.citations_total, review.citations_invalid) == (4, 2)
        assert review.hallucination_rate == 0.5
        assert [i["title"] for i in review.issues] == ["Store depends on UI"]
        assert review.issues[0]["evidence"] == [
            "frontend/src/store/cartSlice.ts -> frontend/src/components/Price.tsx"
        ]
        assert [i["title"] for i in review.dropped_issues] == ["Invented repository layer"]

    # API: a broken patch is never offered as a fix
    stale_id = fixes["B506"].finding_id
    broken = api.get(f"/api/scans/{analyzed_scan}/findings/{stale_id}/fix").json()
    assert broken["patch_verified"] is False and broken["patch"] is None
    assert broken["rejected_patch"].startswith("--- a/backend/app/api/routes.py")
    assert broken["file_changes"] == []
    good = api.get(
        f"/api/scans/{analyzed_scan}/findings/{fixes['hardcoded-tax'].finding_id}/fix"
    ).json()
    assert good["patch_verified"] is True and good["patch"] == VALID_PRICING_PATCH
    assert good["file_changes"][0]["path"] == "backend/app/services/pricing.py"

    review = api.get(f"/api/scans/{analyzed_scan}/architecture-review").json()
    assert review["hallucination_rate"] == 0.5
    assert review["issues"][0]["rejected_evidence"][0]["evidence"] == "frontend/src/utils/cache.ts"

    usage = api.get(f"/api/scans/{analyzed_scan}/llm-usage").json()
    assert usage["enrichment_status"] == "completed"
    assert {p["purpose"]: p["calls"] for p in usage["by_purpose"]} == {
        "architecture_review": 1,
        "fix_suggestion": usage["calls"] - 1,
    }
    assert (
        usage["cost_usd"] > 0
        and usage["tokens_used"] == usage["input_tokens"] + usage["output_tokens"]
    )
    assert len(fake.count_requests) == len(fake.message_requests)

    scan_body = api.get(f"/api/scans/{analyzed_scan}").json()
    assert scan_body["status"] == "completed" and scan_body["enrichment_status"] == "completed"
    assert scan_body["llm_usage"]["valid_fix_suggestions"] == 2
    listed = api.get(f"/api/scans/{analyzed_scan}/findings", params={"page_size": 100}).json()[
        "items"
    ]
    by_rule = {i["rule_id"]: i for i in listed}
    assert by_rule["B506"]["fix_validation_status"] == "failed_to_apply"
    assert by_rule["architecture/layer_violation"]["fix_status"] is None  # structural: no patch


def test_grouping_and_priority_limit(
    analyzed_scan: uuid.UUID, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeAnthropic(responder=responder)
    from app.services.llm import fix_suggester

    real_settings = fix_suggester.get_settings()
    monkeypatch.setattr(
        fix_suggester,
        "get_settings",
        lambda: real_settings.model_copy(update={"llm_max_fix_findings": 2}),
    )

    enrich(analyzed_scan, repo, llm(fake))

    fixes = suggestions(analyzed_scan)
    # Ordered by score impact: the two security errors in application code gain more
    # than the critical dependency CVE (security weighs 40%, dependencies 20%).
    assert set(fixes) == {"B506", "hardcoded-tax"}


def test_budget_exhaustion_degrades_gracefully(analyzed_scan: uuid.UUID, repo: Path) -> None:
    fake = FakeAnthropic(responder=responder)

    status = enrich(analyzed_scan, repo, llm(fake, llm_token_budget_per_scan=19_000))

    # A call reserves 2,000 counted input + 16,000 output. The first fits; it uses 1,200,
    # so the next needs 19,200 of the 19,000 budget and is refused without being sent.
    assert status is EnrichmentStatus.PARTIAL
    fixes = suggestions(analyzed_scan)
    assert sum(s.status is FixStatus.READY for s in fixes.values()) == 1
    assert len(fake.message_requests) == 1
    failed = [s for s in fixes.values() if s.status is FixStatus.FAILED]
    assert failed and all("token budget" in (s.error_message or "") for s in failed)
    with SessionLocal() as db:
        scan = db.get(Scan, analyzed_scan)
        assert scan is not None
        assert scan.status is ScanStatus.COMPLETED
        assert "budget" in (scan.enrichment_error or "")
        assert db.get(ArchitectureReview, analyzed_scan) is None


def test_scan_completes_when_llm_stage_fails_entirely(
    analyzed_scan: uuid.UUID, repo: Path, monkeypatch: pytest.MonkeyPatch, api: TestClient
) -> None:
    fake = FakeAnthropic(responder=lambda _: api_error(500, "api_error"))
    monkeypatch.setattr(tasks, "LLMClient", lambda: llm(fake))
    monkeypatch.setattr(tasks, "extract_source", lambda db, scan, workdir: repo)

    result = tasks.enrich_scan.run(str(analyzed_scan))

    assert result["enrichment"] == "failed"
    body = api.get(f"/api/scans/{analyzed_scan}").json()
    assert body["status"] == "completed"
    assert body["enrichment_status"] == "failed"
    assert "fix requests failed" in body["enrichment_error"]
    assert body["total_findings"] > 0  # the analysis is untouched
    assert all(s.status is FixStatus.FAILED for s in suggestions(analyzed_scan).values())
    assert api.get(f"/api/scans/{analyzed_scan}/architecture-review").json()["status"] == "failed"


def test_scan_completes_when_enrichment_crashes(
    analyzed_scan: uuid.UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(db: object, scan: Scan, workdir: Path) -> Path:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(tasks, "LLMClient", lambda: object())
    monkeypatch.setattr(tasks, "extract_source", explode)

    result = tasks.enrich_scan.run(str(analyzed_scan))

    assert result["enrichment"] == "failed"
    with SessionLocal() as db:
        scan = db.get(Scan, analyzed_scan)
        assert scan is not None
        assert (scan.status, scan.enrichment_status) == (
            ScanStatus.COMPLETED,
            EnrichmentStatus.FAILED,
        )
        assert scan.enrichment_error == "Internal error during enrichment."


def test_partial_analysis_stays_partial_after_enrichment(analyzed_scan: uuid.UUID) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, analyzed_scan)
        assert scan is not None
        scan.analysis_partial = True
        db.commit()
        finish_enrichment(db, analyzed_scan, EnrichmentStatus.COMPLETED, None)
        db.refresh(scan)
        assert scan.status is ScanStatus.PARTIAL


def test_regenerate_endpoint(
    analyzed_scan: uuid.UUID, repo: Path, monkeypatch: pytest.MonkeyPatch, api: TestClient
) -> None:
    from app.api.routes import llm as llm_routes

    seen_prompts: list[str] = []

    def hinted(body: dict[str, Any]) -> httpx2.Response:
        seen_prompts.append(user_prompt(body))
        return responder(body)

    fake = FakeAnthropic(responder=hinted)
    monkeypatch.setattr(llm_routes, "llm_configured", lambda: None)
    monkeypatch.setattr(tasks, "LLMClient", lambda: llm(fake))
    monkeypatch.setattr(tasks, "extract_source", lambda db, scan, workdir: repo)
    with SessionLocal() as db:
        finding_id = db.scalar(
            select(Finding.id).where(Finding.scan_id == analyzed_scan, Finding.rule_id == "B506")
        )
        structural_id = db.scalar(
            select(Finding.id).where(
                Finding.scan_id == analyzed_scan, Finding.analyzer == "architecture"
            )
        )
        scan = db.get(Scan, analyzed_scan)
        assert scan is not None
        scan.status = ScanStatus.COMPLETED
        db.commit()

    missing = api.get(f"/api/scans/{analyzed_scan}/findings/{finding_id}/fix")
    assert missing.status_code == 404

    # Celery runs eagerly in tests: the task completes inside the request.
    response = api.post(
        f"/api/scans/{analyzed_scan}/findings/{finding_id}/fix/regenerate",
        json={"hint": "Keep YAML support, use yaml.safe_load"},
    )
    assert response.status_code == 202
    assert (
        "<reviewer_hint>\nKeep YAML support, use yaml.safe_load\n</reviewer_hint>"
        in seen_prompts[0]
    )

    fix = api.get(f"/api/scans/{analyzed_scan}/findings/{finding_id}/fix").json()
    assert (fix["status"], fix["validation_status"], fix["version"]) == (
        "ready",
        "failed_to_apply",
        1,
    )
    assert fix["user_hint"] == "Keep YAML support, use yaml.safe_load"

    api.post(f"/api/scans/{analyzed_scan}/findings/{finding_id}/fix/regenerate")
    assert "<previous_attempt>\nValidation result: failed_to_apply" in seen_prompts[1]
    assert api.get(f"/api/scans/{analyzed_scan}/findings/{finding_id}/fix").json()["version"] == 2

    conflict = api.post(f"/api/scans/{analyzed_scan}/findings/{structural_id}/fix/regenerate")
    assert conflict.status_code == 409
    usage = api.get(f"/api/scans/{analyzed_scan}/llm-usage").json()
    assert {p["purpose"] for p in usage["by_purpose"]} == {"fix_regeneration"}


@pytest.fixture(autouse=True)
def _no_real_anthropic(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail loudly if anything tries to build a real client with network access."""
    import anthropic

    def refuse(*args: object, **kwargs: object) -> None:
        if "http_client" not in kwargs:
            raise AssertionError("tests must not create a networked Anthropic client")

    original = anthropic.Anthropic.__init__

    def guarded(self: anthropic.Anthropic, *args: Any, **kwargs: Any) -> None:
        refuse(*args, **kwargs)
        original(self, *args, **kwargs)

    monkeypatch.setattr(anthropic.Anthropic, "__init__", guarded)
    yield

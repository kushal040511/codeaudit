import uuid

from app.services.llm.architect import (
    GraphFacts,
    ReviewIssueOutput,
    ReviewOutput,
    verify_evidence,
    verify_review,
)

FACTS = GraphFacts(
    paths={"app/api/routes.py", "app/services/pricing.py", "app/models.py", "web/src/App.tsx"},
    module_ids={
        "app/api/routes": "app/api/routes.py",
        "app/services/pricing": "app/services/pricing.py",
        "app/models": "app/models.py",
        "web/src/App": "web/src/App.tsx",
    },
    directories={"app", "app/api", "app/services", "web", "web/src"},
    edges={
        ("app/api/routes.py", "app/services/pricing.py"),
        ("app/services/pricing.py", "app/models.py"),
    },
)


def test_valid_citations() -> None:
    for evidence in [
        "app/api/routes.py",
        "`app/services/pricing.py`",
        "./app/models.py",
        "app/models.py (fan-in 12)",
        "app/models.py:14",
        "app/services/pricing",  # module id
        "app/services/",
        "app/api/routes.py -> app/services/pricing.py",
        "app/api/routes.py → app/services/pricing.py → app/models.py",
        "app/api/ -> app/services/",  # directory coupling backed by a real import
    ]:
        assert verify_evidence(evidence, FACTS)[2] is None, evidence


def test_hallucinated_modules_and_edges() -> None:
    assert verify_evidence("app/utils/helpers.py", FACTS) == (
        0,
        1,
        "not in the graph: 'app/utils/helpers.py'",
    )
    assert verify_evidence("app/api/routes.py -> app/db/session.py", FACTS)[:2] == (1, 1)
    # both modules exist, but there is no such import
    valid, invalid, reason = verify_evidence("app/models.py -> app/api/routes.py", FACTS)
    assert (valid, invalid) == (2, 0)
    assert reason == "no import app/models.py -> app/api/routes.py in the graph"
    assert verify_evidence("web/ -> app/", FACTS)[2] is not None


def issue(title: str, evidence: list[str], why: str = "Coupling.") -> ReviewIssueOutput:
    return ReviewIssueOutput(title=title, severity="high", evidence=evidence, why_it_matters=why)


def test_review_filters_issues_and_reports_hallucination_rate() -> None:
    output = ReviewOutput(
        summary="ok",
        issues=[
            issue("Real", ["app/api/routes.py -> app/services/pricing.py", "app/models.py"]),
            issue(
                "Partly made up",
                ["app/models.py", "app/core/cache.py"],
                "See app/core/cache.py and app/models.py.",
            ),
            issue("Invented", ["app/repositories/user_repo.py", "lib/legacy.ts -> app/models.py"]),
        ],
    )

    result = verify_review(output, FACTS, uuid.uuid4())

    assert [i["title"] for i in result.issues] == ["Real", "Partly made up"]
    assert result.issues[0]["severity"] == "error"  # "high" normalised
    partly = result.issues[1]
    assert partly["evidence"] == ["app/models.py"]
    assert partly["rejected_evidence"] == [
        {"evidence": "app/core/cache.py", "reason": "not in the graph: 'app/core/cache.py'"}
    ]
    assert partly["unverified_mentions"] == ["app/core/cache.py"]
    assert [d["title"] for d in result.dropped] == ["Invented"]
    # module references: real 3, partly 2 (1 bad), invented 3 (2 bad)
    assert (result.references_total, result.references_invalid) == (8, 3)
    assert result.hallucination_rate == 0.375


def test_no_citations_means_no_rate() -> None:
    assert verify_review(ReviewOutput(summary="x"), FACTS, uuid.uuid4()).hallucination_rate is None

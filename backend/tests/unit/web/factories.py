from typing import Any

from app.services.web.capture import Capture


def make_capture(
    *,
    final_url: str = "https://www.example.com/",
    title: str = "Example Domain",
    text: str = "This domain is for use in illustrative examples.",
    forms: list[dict[str, Any]] | None = None,
    links: list[str] | None = None,
    redirect_chain: list[dict[str, Any]] | None = None,
    styles: list[dict[str, Any]] | None = None,
) -> Capture:
    return Capture(
        requested_url=final_url,
        final_url=final_url,
        status=200,
        redirect_chain=redirect_chain or [{"url": final_url, "status": 200}],
        title=title,
        meta=[],
        text=text,
        links=links or [],
        resources=[],
        forms=forms or [],
        orphan_inputs=[],
        tls=None,
        styles=styles or [],
        fold_png=None,
        full_png=None,
        favicon=None,
        favicon_url=None,
        dom_html=None,
    )

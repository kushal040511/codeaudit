"""Design token extraction from computed styles, and vision color verification."""

import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.services.web.design import VisionColor, VisionDesign, extract_tokens, to_css, to_tailwind

VIEWPORT = 1366 * 768


def el(
    tag: str,
    *,
    w: float,
    h: float,
    text: int = 0,
    color: str = "rgb(17, 24, 39)",
    bg: str = "rgba(0, 0, 0, 0)",
    font: str = '"Fixture Sans", Arial, sans-serif',
    size: str = "16px",
    weight: str = "400",
    line: str = "24px",
    margin: str = "0px",
    padding: str = "0px",
    gap: list[str] | None = None,
    radius: str = "0px",
    shadow: str | None = None,
    border: str | None = None,
    fold: bool = True,
    **flags: Any,
) -> dict[str, Any]:
    return {
        "tag": tag,
        "area": w * h,
        "area_ratio": round(w * h / VIEWPORT, 4),
        "above_fold": fold,
        "text_len": text,
        "color": color,
        "background_color": bg,
        "border_color": border,
        "font_family": font,
        "font_size": size,
        "font_weight": weight,
        "line_height": line,
        "margin": margin.split() if " " in margin else [margin] * 4,
        "padding": padding.split() if " " in padding else [padding] * 4,
        "gap": gap,
        "border_radius": radius,
        "box_shadow": shadow,
        "is_button": flags.get("is_button", False),
        "is_link": flags.get("is_link", False),
        "is_heading": flags.get("is_heading", False),
    }


DISPLAY = '"Fixture Display", Georgia, serif'
PRIMARY = "rgb(79, 70, 229)"
ACCENT = "rgb(219, 39, 119)"
SURFACE = "rgb(249, 250, 251)"
BORDER = "rgb(229, 231, 235)"
MUTED = "rgb(107, 114, 128)"


def fixture_styles() -> list[dict[str, Any]]:
    """Mirrors tests/fixtures/web/design_page.html as Chrome computes it."""
    styles = [
        el("body", w=1366, h=1600, bg="rgb(255, 255, 255)"),
        el(
            "header",
            w=1366,
            h=72,
            padding="16px 32px 16px 32px",
            gap=["24px", "24px"],
            border=BORDER,
        ),
        el("strong", w=60, h=24, text=7, weight="700"),
    ]
    for label in ("Features", "Pricing", "Docs", "Blog"):
        styles.append(
            el(
                "a",
                w=80,
                h=36,
                text=len(label),
                color=PRIMARY,
                size="14px",
                padding="8px",
                is_link=True,
            )
        )
    styles += [
        el(
            "h1",
            w=1300,
            h=56,
            text=28,
            font=DISPLAY,
            size="48px",
            weight="700",
            line="56px",
            margin="48px 32px 16px 32px",
            is_heading=True,
        ),
        el("p", w=1300, h=32, text=81, size="20px", line="32px", margin="0px 32px 16px 32px"),
        el(
            "p",
            w=1300,
            h=20,
            text=70,
            color=MUTED,
            size="14px",
            line="20px",
            margin="0px 32px 16px 32px",
        ),
        el("div", w=1300, h=40, margin="24px 32px 24px 32px", gap=["16px", "16px"]),
        el(
            "button",
            w=160,
            h=40,
            text=16,
            color="rgb(255, 255, 255)",
            bg=PRIMARY,
            weight="600",
            padding="8px 16px 8px 16px",
            radius="8px",
            is_button=True,
        ),
        el(
            "button",
            w=140,
            h=40,
            text=11,
            color="rgb(255, 255, 255)",
            bg=PRIMARY,
            weight="600",
            padding="8px 16px 8px 16px",
            radius="9999px",
            is_button=True,
        ),
        el(
            "h2",
            w=1300,
            h=40,
            text=21,
            font=DISPLAY,
            size="32px",
            weight="700",
            line="40px",
            margin="32px 32px 16px 32px",
            is_heading=True,
            fold=False,
        ),
        el("div", w=1366, h=300, padding="0px 32px 48px 32px", gap=["24px", "24px"], fold=False),
    ]
    for text in (95, 88, 80):
        styles.append(
            el(
                "div",
                w=420,
                h=240,
                bg=SURFACE,
                padding="24px",
                radius="8px",
                shadow="rgba(0, 0, 0, 0.1) 0px 1px 3px 0px",
                border=BORDER,
                fold=False,
            )
        )
        styles.append(el("p", w=370, h=120, text=text, margin="0px 32px 16px 32px", fold=False))
    styles.append(
        el(
            "span",
            w=48,
            h=28,
            text=3,
            color="rgb(255, 255, 255)",
            bg=ACCENT,
            size="14px",
            padding="4px 8px 4px 8px",
            radius="9999px",
            fold=False,
        )
    )
    styles += [
        el(
            "footer",
            w=1366,
            h=120,
            bg=SURFACE,
            padding="32px",
            margin="48px 0px 0px 0px",
            fold=False,
        ),
        el(
            "p",
            w=1300,
            h=20,
            text=66,
            color=MUTED,
            size="14px",
            line="20px",
            margin="0px 32px 16px 32px",
            fold=False,
        ),
    ]
    return styles


@pytest.fixture
def tokens() -> dict[str, Any]:
    return extract_tokens(fixture_styles(), "https://fixture.example/")


def test_color_roles_match_the_known_styles(tokens: dict[str, Any]) -> None:
    roles = {name: role["hex"] for name, role in tokens["colors"]["roles"].items()}
    assert roles["background"] == "#ffffff"
    assert roles["text"] == "#111827"
    assert roles["text_muted"] == "#6b7280"
    assert roles["surface"] == "#f9fafb"
    assert roles["primary"] == "#4f46e5"
    assert roles["accent" if "accent" in roles else "secondary"] == "#db2777"
    assert roles["border"] == "#e5e7eb"
    assert tokens["colors"]["roles"]["text"]["contrast_on_background"] > 15
    palette = [entry["hex"] for entry in tokens["colors"]["palette"]]
    # Every palette entry is a color that actually appears in the computed styles.
    observed = {"#ffffff", "#111827", "#6b7280", "#f9fafb", "#4f46e5", "#db2777", "#e5e7eb"}
    assert set(palette) <= observed


def test_typography(tokens: dict[str, Any]) -> None:
    typo = tokens["typography"]
    assert typo["families"]["body"]["name"] == "Fixture Sans"
    assert typo["families"]["heading"]["name"] == "Fixture Display"
    assert typo["base_size_px"] == 16
    assert [s["px"] for s in typo["sizes"]] == [14, 16, 20, 32, 48]
    assert {s["px"]: s["line_height"] for s in typo["sizes"]}[48] == "56px"
    assert {w["value"] for w in typo["weights"]} >= {"400", "700"}


def test_spacing_radii_and_shadows(tokens: dict[str, Any]) -> None:
    spacing = tokens["spacing"]
    assert spacing["base_px"] == 8 or spacing["base_px"] == 4
    assert set(spacing["scale"]) >= {8, 16, 24, 32, 48}
    assert set(spacing["scale"]) <= {4, 8, 16, 24, 32, 48}
    assert {r["value"] for r in tokens["radii"]} == {"8px", "9999px"}
    assert tokens["shadows"][0]["value"] == "rgba(0, 0, 0, 0.1) 0px 1px 3px 0px"


def test_hallucinated_vision_colors_are_dropped_and_matches_use_observed_values() -> None:
    vision = VisionDesign(
        layout="Header, hero, three cards, footer.",
        visual_hierarchy="Headline, then primary button.",
        style="Minimal SaaS landing page.",
        mood_keywords=["calm"],
        colors=[
            VisionColor(role="primary", hex="#4f46e6", where="buttons"),  # 1 off: matches #4f46e5
            VisionColor(role="accent", hex="#d92a75", where="badge"),  # close to #db2777
            VisionColor(role="secondary", hex="#22c55e", where="(invented) green highlights"),
            VisionColor(role="background", hex="#0f766e", where="(invented) teal hero"),
            VisionColor(role="other", hex="blue", where="not a hex value"),
        ],
    )
    result = extract_tokens(fixture_styles(), "https://fixture.example/", vision)
    kept = {c["claimed_hex"]: c["hex"] for c in result["vision"]["colors"]}
    assert kept == {"#4f46e6": "#4f46e5", "#d92a75": "#db2777"}
    dropped = {c["hex"]: c["reason"] for c in result["dropped_colors"]}
    assert set(dropped) == {"#22c55e", "#0f766e", "blue"}
    assert dropped["#22c55e"] == "not present in the page's computed styles"

    # No invented color reaches any output format.
    outputs = json.dumps(result) + to_tailwind(result) + to_css(result)
    exported = (
        json.dumps({k: v for k, v in result.items() if k != "dropped_colors"})
        + to_tailwind(result)
        + to_css(result)
    )
    for invented in ("#22c55e", "#0f766e", "#4f46e6", "#d92a75"):
        claimed_only = invented in {"#4f46e6", "#d92a75"}
        if claimed_only:
            # The model's approximate value is recorded for transparency, never exported as a token.
            assert invented not in to_tailwind(result) + to_css(result)
        else:
            assert invented not in exported
    assert "#22c55e" in outputs  # listed under dropped_colors only
    assert "Minimal SaaS landing page." in result["prompt"]


def test_tailwind_and_css_outputs(tokens: dict[str, Any]) -> None:
    tailwind = to_tailwind(tokens)
    assert tailwind.startswith(
        "// Design tokens extracted by CodeAudit from https://fixture.example/"
    )
    config = json.loads(tailwind.split("module.exports = ", 1)[1])
    extend = config["theme"]["extend"]
    assert extend["colors"]["primary"] == {"DEFAULT": "#4f46e5"}
    assert extend["colors"]["background"] == "#ffffff"
    assert extend["fontFamily"]["sans"][0] == "Fixture Sans"
    assert extend["fontFamily"]["heading"][0] == "Fixture Display"
    assert extend["fontSize"]["base"] == ["16px", {"lineHeight": "24px"}]
    assert extend["fontSize"]["5xl"][0] == "48px"
    assert extend["spacing"]["4"] == "16px" and extend["spacing"]["12"] == "48px"
    assert extend["borderRadius"] == {"sm": "8px", "full": "9999px"}

    css = to_css(tokens)
    assert ":root {" in css and css.strip().endswith("}")
    assert "--color-primary: #4f46e5;" in css
    assert '--font-heading: "Fixture Display", Georgia, serif;' in css
    assert "--text-base: 16px;" in css
    assert re.search(r"--space-4: 16px;", css)


def test_modern_color_syntaxes_are_converted() -> None:
    styles = [
        el("body", w=1366, h=768, bg="oklch(0.985 0 0)"),
        el(
            "button",
            w=200,
            h=40,
            text=10,
            color="lab(100 0 0)",
            bg="oklch(0.546 0.245 262.881)",
            is_button=True,
        ),
        el("p", w=800, h=100, text=300, color="color(srgb 0.07 0.09 0.15)"),
    ]
    roles = {
        n: r["hex"]
        for n, r in extract_tokens(styles, "https://x.example/")["colors"]["roles"].items()
    }
    assert roles["primary"] == "#155dfc"  # Tailwind v4 blue-600
    assert roles["text"] == "#121726"


def test_empty_styles_produce_empty_tokens() -> None:
    tokens = extract_tokens([], "https://x.example/")
    assert tokens["colors"]["roles"] == {} and tokens["typography"]["sizes"] == []
    assert "module.exports" in to_tailwind(tokens) and ":root {" in to_css(tokens)


# ------------------------------------------------------------------ real browser output

RECORDED = Path(__file__).parents[2] / "fixtures" / "web" / "design_page.styles.json"
EXPECTED_ROLES = {
    "background": "#ffffff",
    "text": "#111827",
    "text_muted": "#6b7280",
    "surface": "#f9fafb",
    "primary": "#4f46e5",
    "secondary": "#db2777",
    "border": "#e5e7eb",
}


def assert_fixture_tokens(result: dict[str, Any]) -> None:
    assert {k: v["hex"] for k, v in result["colors"]["roles"].items()} == EXPECTED_ROLES
    typo = result["typography"]
    assert [s["px"] for s in typo["sizes"]] == [14, 16, 20, 32, 48]
    assert typo["families"]["body"]["name"] == "Fixture Sans"
    assert typo["families"]["heading"]["name"] == "Fixture Display"
    assert result["spacing"]["base_px"] == 8
    assert result["spacing"]["scale"] == [4, 8, 16, 24, 32, 48]
    assert [r["value"] for r in result["radii"]] == ["8px", "9999px"]
    assert [s["value"] for s in result["shadows"]] == ["rgba(0, 0, 0, 0.1) 0px 1px 3px 0px"]


def test_tokens_from_recorded_chromium_computed_styles() -> None:
    """Styles captured by the real sandboxed Chromium from design_page.html."""
    assert_fixture_tokens(
        extract_tokens(json.loads(RECORDED.read_text()), "https://fixture.example/")
    )


def test_dark_theme_roles_neutral_primary_and_odd_spacing() -> None:
    """Modeled on a dark SaaS landing page (linear.app, captured 2026-09-17): white
    headlines over grey body copy, a light neutral call-to-action button, pastel accents
    far down the page, and spacing on a 4px grid with a few odd values."""
    white, grey, dim = "rgb(247, 248, 248)", "rgb(138, 143, 152)", "rgb(98, 102, 109)"
    styles = [el("body", w=1366, h=6000, bg="rgb(8, 9, 10)", color=grey)]
    styles.append(
        el(
            "h1",
            w=800,
            h=130,
            text=58,
            color=white,
            size="64px",
            line="64px",
            is_heading=True,
            margin="0px",
        )
    )
    styles.append(
        el(
            "button",
            w=72,
            h=32,
            text=7,
            color="rgb(8, 9, 10)",
            bg="rgb(230, 230, 230)",
            size="13px",
            padding="0px 12px 0px 12px",
            radius="9999px",
            is_button=True,
        )
    )
    for _ in range(12):
        styles.append(
            el(
                "a",
                w=60,
                h=20,
                text=8,
                color=grey,
                size="13px",
                padding="4px 8px 4px 8px",
                is_link=True,
            )
        )
    for _ in range(20):
        styles.append(
            el(
                "p",
                w=600,
                h=40,
                text=90,
                color=grey,
                size="15px",
                line="24px",
                margin="0px 0px 16px 0px",
                fold=False,
            )
        )
        styles.append(
            el(
                "span",
                w=200,
                h=16,
                text=20,
                color=dim,
                size="12px",
                margin="0px 0px 7px 0px",
                fold=False,
            )
        )
    styles.append(
        el(
            "div",
            w=1300,
            h=500,
            bg="rgb(15, 16, 17)",
            border="rgb(28, 29, 30)",
            radius="12px",
            padding="32px",
            fold=False,
        )
    )
    for color in ("rgb(247, 191, 139)", "rgb(228, 242, 34)"):
        styles.append(
            el(
                "span",
                w=40,
                h=20,
                text=3,
                color="rgb(8, 9, 10)",
                bg=color,
                size="12px",
                padding="4px",
                fold=False,
            )
        )
    result = extract_tokens(styles, "https://dark.example/")
    roles = {k: v["hex"] for k, v in result["colors"]["roles"].items()}
    assert roles["background"] == "#08090a"
    assert roles["text"] == "#f7f8f8"
    assert roles["text_muted"] == "#8a8f98"
    assert roles["surface"] == "#0f1011"
    assert roles["primary"] == "#e6e6e6"
    assert result["spacing"]["base_px"] == 4 and 7 in result["spacing"]["scale"]


def test_tinted_near_black_headings_count_as_text() -> None:
    navy, slate = "rgb(6, 27, 49)", "rgb(100, 116, 141)"
    styles = [el("body", w=1366, h=3000, bg="rgb(255, 255, 255)")]
    styles += [
        el("h2", w=800, h=50, text=40, color=navy, size="32px", is_heading=True) for _ in range(6)
    ]
    styles += [el("p", w=800, h=60, text=120, color=slate, size="16px") for _ in range(10)]
    styles.append(
        el(
            "a",
            w=150,
            h=40,
            text=10,
            color="rgb(255, 255, 255)",
            bg="rgb(83, 58, 253)",
            is_button=True,
        )
    )
    roles = {
        k: v["hex"]
        for k, v in extract_tokens(styles, "https://light.example/")["colors"]["roles"].items()
    }
    assert (roles["text"], roles["text_muted"], roles["primary"]) == (
        "#061b31",
        "#64748d",
        "#533afd",
    )
    assert "#061b31" not in {roles.get("secondary"), roles.get("accent")}

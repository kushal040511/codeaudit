from pathlib import Path

import pytest

from app.services.web.visual import hash_favicon, hash_screenshot, screenshot_similarity, similarity

FIXTURES = Path(__file__).parents[2] / "fixtures" / "web"


def hashes(name: str):  # type: ignore[no-untyped-def]
    result = hash_screenshot((FIXTURES / f"{name}.png").read_bytes())
    assert result is not None
    return result


def test_a_copied_page_is_visually_similar_despite_reencoding_and_small_edits() -> None:
    score = screenshot_similarity(hashes("login_original"), hashes("login_clone"))
    assert score is not None and score >= 0.90


@pytest.mark.parametrize("other", ["login_restyled", "landing_other"])
def test_different_layouts_are_not_similar(other: str) -> None:
    score = screenshot_similarity(hashes("login_original"), hashes(other))
    assert score is not None and score < 0.70


def test_blank_pages_are_never_compared() -> None:
    blank = hashes("blank")
    assert blank.low_information
    assert screenshot_similarity(hashes("login_original"), blank) is None
    assert screenshot_similarity(blank, blank) is None  # would be 100% otherwise


def test_similarity_is_share_of_equal_bits() -> None:
    assert similarity("ffffffffffffffff", "ffffffffffffffff") == 1.0
    assert similarity("ffffffffffffffff", "0000000000000000") == 0.0
    assert similarity("ffffffff00000000", "ffffffffffffffff") == 0.5


def test_favicon_hashes_match_rescaled_copies_but_not_other_icons() -> None:
    brand = hash_favicon((FIXTURES / "favicon_brand.png").read_bytes())
    rescaled = hash_favicon((FIXTURES / "favicon_brand_64.png").read_bytes())
    other = hash_favicon((FIXTURES / "favicon_other.png").read_bytes())
    assert brand.sha256 != rescaled.sha256
    assert brand.phash and rescaled.phash and other.phash
    assert similarity(brand.phash, rescaled.phash) >= 0.95
    assert similarity(brand.phash, other.phash) < 0.8


def test_undecodable_images_are_handled() -> None:
    assert hash_screenshot(b"not an image") is None
    svg = hash_favicon(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>")
    assert svg.phash is None and len(svg.sha256) == 64

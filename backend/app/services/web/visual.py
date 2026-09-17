"""Perceptual hashing of screenshots and favicons.

pHash (DCT) and dHash (gradient) are 64-bit hashes; similarity is the share of
matching bits. Two unrelated pages land around 50% by chance, so only high values
mean anything: see VISUAL_* thresholds in risk.py.

Low-information images (blank or nearly single-colour pages) hash alike regardless
of content, so they are never compared.
"""

import hashlib
import io
from dataclasses import dataclass

import imagehash
from PIL import Image, ImageStat, UnidentifiedImageError

HASH_BITS = 64
# Below this grey-level standard deviation, or above this share of one colour, an
# image carries too little structure to compare.
MIN_STDDEV = 12.0
MAX_DOMINANT_SHARE = 0.92
MAX_IMAGE_PIXELS = 40_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS  # refuse decompression bombs


@dataclass(frozen=True)
class ImageHashes:
    phash: str
    dhash: str
    low_information: bool


@dataclass(frozen=True)
class FaviconHashes:
    sha256: str
    phash: str | None  # None when the format can't be decoded (e.g. SVG)


def _open(data: bytes) -> Image.Image | None:
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return None
    return image


def is_low_information(image: Image.Image) -> bool:
    grey = image.convert("L").resize((128, 128))
    if ImageStat.Stat(grey).stddev[0] < MIN_STDDEV:
        return True
    histogram = grey.quantize(colors=16).histogram()
    return max(histogram) / sum(histogram) > MAX_DOMINANT_SHARE


def hash_screenshot(data: bytes) -> ImageHashes | None:
    image = _open(data)
    if image is None:
        return None
    rgb = image.convert("RGB")
    return ImageHashes(
        phash=str(imagehash.phash(rgb)),
        dhash=str(imagehash.dhash(rgb)),
        low_information=is_low_information(rgb),
    )


def hash_favicon(data: bytes) -> FaviconHashes:
    digest = hashlib.sha256(data).hexdigest()
    image = _open(data)
    if image is None:
        return FaviconHashes(digest, None)
    # Composite transparency onto white so the same icon hashes the same either way.
    rgba = image.convert("RGBA").resize((64, 64))
    background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    background.alpha_composite(rgba)
    return FaviconHashes(digest, str(imagehash.phash(background.convert("RGB"))))


def similarity(hash_a: str, hash_b: str) -> float:
    """Share of equal bits between two hex hashes, 0..1."""
    distance = imagehash.hex_to_hash(hash_a) - imagehash.hex_to_hash(hash_b)
    return 1.0 - distance / HASH_BITS


def screenshot_similarity(a: ImageHashes, b: ImageHashes) -> float | None:
    """Mean of pHash and dHash similarity; None when either image can't be compared."""
    if a.low_information or b.low_information:
        return None
    return (similarity(a.phash, b.phash) + similarity(a.dhash, b.dhash)) / 2

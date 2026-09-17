"""Regenerate the perceptual-hash fixture images: python tests/fixtures/web/make_images.py

- login_original.png   a synthetic brand login page
- login_clone.png      the same page as a clone would copy it: re-encoded as JPEG,
                       slightly shifted, different footer text, a changed input label
- login_restyled.png   same brand, heavily different layout (should NOT match)
- landing_other.png    an unrelated landing page (should NOT match)
- blank.png            a nearly empty page (low information, never compared)
"""

import io
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).parent
SIZE = (1366, 768)


def login(offset: tuple[int, int] = (0, 0), footer: str = "(c) 2026 Brand Inc.", label: str = "Email") -> Image.Image:
    image = Image.new("RGB", SIZE, "#f5f7fa")
    draw = ImageDraw.Draw(image)
    dx, dy = offset
    draw.rectangle((0 + dx, 0 + dy, 1366 + dx, 72 + dy), fill="#003087")
    draw.rectangle((40 + dx, 18 + dy, 170 + dx, 54 + dy), fill="#ffffff")
    draw.rounded_rectangle((483 + dx, 150 + dy, 883 + dx, 600 + dy), 12, fill="#ffffff", outline="#d9dde3", width=2)
    draw.ellipse((653 + dx, 180 + dy, 713 + dx, 240 + dy), fill="#0070e0")
    draw.text((523 + dx, 270 + dy), label, fill="#2c2e2f")
    draw.rounded_rectangle((523 + dx, 290 + dy, 843 + dx, 340 + dy), 6, outline="#8f9aa6", width=2)
    draw.text((523 + dx, 360 + dy), "Password", fill="#2c2e2f")
    draw.rounded_rectangle((523 + dx, 380 + dy, 843 + dx, 430 + dy), 6, outline="#8f9aa6", width=2)
    draw.rounded_rectangle((523 + dx, 470 + dy, 843 + dx, 520 + dy), 25, fill="#0070e0")
    draw.text((653 + dx, 488 + dy), "Log In", fill="#ffffff")
    draw.text((590 + dx, 700 + dy), footer, fill="#6c7378")
    return image


def restyled() -> Image.Image:
    image = Image.new("RGB", SIZE, "#0b1120")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 683, 768), fill="#1e3a8a")
    for i in range(6):
        draw.rectangle((80, 120 + i * 90, 600, 170 + i * 90), fill="#3b82f6")
    draw.rounded_rectangle((780, 220, 1280, 560), 30, fill="#f8fafc")
    draw.rectangle((820, 260, 1240, 300), fill="#cbd5e1")
    draw.rectangle((820, 330, 1240, 370), fill="#cbd5e1")
    draw.rectangle((820, 440, 1240, 500), fill="#f97316")
    return image


def landing() -> Image.Image:
    image = Image.new("RGB", SIZE, "#ffffff")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1366, 420), fill="#fde68a")
    draw.ellipse((900, 60, 1300, 400), fill="#f59e0b")
    draw.rectangle((80, 140, 700, 200), fill="#111827")
    draw.rectangle((80, 230, 600, 250), fill="#374151")
    for i in range(3):
        x = 80 + i * 420
        draw.rounded_rectangle((x, 470, x + 380, 740), 16, fill="#f3f4f6", outline="#e5e7eb")
        draw.rectangle((x + 30, 500, x + 200, 540), fill="#10b981")
    return image


def blank() -> Image.Image:
    image = Image.new("RGB", SIZE, "#ffffff")
    ImageDraw.Draw(image).text((660, 380), "Loading...", fill="#dddddd")
    return image


def jpeg_roundtrip(image: Image.Image, quality: int = 60) -> Image.Image:
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    return Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")


if __name__ == "__main__":
    login().save(HERE / "login_original.png")
    clone = jpeg_roundtrip(login(offset=(3, 2), footer="Copyright 2026 All rights reserved", label="Email or mobile"))
    clone.filter(ImageFilter.GaussianBlur(0.6)).save(HERE / "login_clone.png")
    restyled().save(HERE / "login_restyled.png")
    landing().save(HERE / "landing_other.png")
    blank().save(HERE / "blank.png")
    # Favicons: identical bytes, re-encoded copy, and an unrelated icon.
    icon = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    draw = ImageDraw.Draw(icon)
    draw.ellipse((2, 2, 30, 30), fill="#003087")
    draw.rectangle((11, 8, 16, 24), fill="#ffffff")
    draw.ellipse((12, 8, 22, 17), fill="#ffffff")
    icon.save(HERE / "favicon_brand.png")
    icon.resize((64, 64)).save(HERE / "favicon_brand_64.png")
    other = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
    ImageDraw.Draw(other).polygon([(16, 2), (30, 30), (2, 30)], fill="#dc2626")
    other.save(HERE / "favicon_other.png")

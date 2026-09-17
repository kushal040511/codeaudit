"""CSS color parsing and color math (sRGB, OKLab/OKLCH, CIE Lab/LCH, Display P3, WCAG).

Computed styles report colors as rgb()/rgba(), but Chrome keeps modern syntaxes in
their own space (oklch(), oklab(), lab(), lch(), color(srgb|display-p3 ...)), e.g. for
Tailwind v4 sites. Everything is converted to sRGB (gamut-clipped) hex.
"""

import math
import re
from dataclasses import dataclass

_FUNC = re.compile(r"^(rgba?|hsla?|oklch|oklab|lab|lch|color)\((.*)\)$", re.IGNORECASE)


@dataclass(frozen=True)
class RGBA:
    r: float  # 0..1, sRGB (gamma-encoded)
    g: float
    b: float
    a: float = 1.0

    @property
    def hex(self) -> str:
        channels = [round(max(0.0, min(1.0, c)) * 255) for c in (self.r, self.g, self.b)]
        return "#" + "".join(f"{c:02x}" for c in channels)

    @property
    def hex8(self) -> str:
        return self.hex if self.a >= 0.999 else f"{self.hex}{round(self.a * 255):02x}"

    def over(self, background: "RGBA") -> "RGBA":
        a = self.a
        return RGBA(
            self.r * a + background.r * (1 - a),
            self.g * a + background.g * (1 - a),
            self.b * a + background.b * (1 - a),
        )


WHITE = RGBA(1, 1, 1)


def _parse_component(token: str, scale: float, percent_scale: float | None = None) -> float:
    token = token.strip()
    if token in ("none", ""):
        return 0.0
    if token.endswith("%"):
        return float(token[:-1]) / 100 * (percent_scale if percent_scale is not None else scale)
    return float(token)


def _split(args: str) -> tuple[list[str], str | None]:
    args = args.replace(",", " ")
    alpha = None
    if "/" in args:
        args, alpha = args.split("/", 1)
    return args.split(), alpha


def _alpha(token: str | None, legacy: str | None = None) -> float:
    value = token if token is not None else legacy
    if value is None:
        return 1.0
    value = value.strip()
    return float(value[:-1]) / 100 if value.endswith("%") else float(value)


def _srgb_encode(linear: float) -> float:
    if linear <= 0.0031308:
        return 12.92 * linear
    return 1.055 * math.copysign(abs(linear) ** (1 / 2.4), linear) - 0.055


def _srgb_decode(channel: float) -> float:
    if channel <= 0.04045:
        return channel / 12.92
    return float(((channel + 0.055) / 1.055) ** 2.4)


def oklab_to_rgb(lightness: float, a: float, b: float) -> tuple[float, float, float]:
    l_ = lightness + 0.3963377774 * a + 0.2158037573 * b
    m_ = lightness - 0.1055613458 * a - 0.0638541728 * b
    s_ = lightness - 0.0894841775 * a - 1.2914855480 * b
    l3, m3, s3 = l_**3, m_**3, s_**3
    red = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3
    green = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3
    blue = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3
    return _srgb_encode(red), _srgb_encode(green), _srgb_encode(blue)


def rgb_to_oklab(color: RGBA) -> tuple[float, float, float]:
    red, green, blue = (_srgb_decode(max(0.0, min(1.0, c))) for c in (color.r, color.g, color.b))
    l_ = (0.4122214708 * red + 0.5363325363 * green + 0.0514459929 * blue) ** (1 / 3)
    m_ = (0.2119034982 * red + 0.6806995451 * green + 0.1073969566 * blue) ** (1 / 3)
    s_ = (0.0883024619 * red + 0.2817188376 * green + 0.6299787005 * blue) ** (1 / 3)
    return (
        0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_,
        1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_,
        0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_,
    )


def oklch(color: RGBA) -> tuple[float, float, float]:
    lightness, a, b = rgb_to_oklab(color)
    return lightness, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360


def _lab_to_rgb(lightness: float, a: float, b: float) -> tuple[float, float, float]:
    # CIE Lab (D50) -> XYZ D50 -> XYZ D65 (Bradford) -> linear sRGB
    fy = (lightness + 16) / 116
    fx = fy + a / 500
    fz = fy - b / 200
    eps, kappa = 216 / 24389, 24389 / 27

    def finv(t: float) -> float:
        return t**3 if t**3 > eps else (116 * t - 16) / kappa

    x = finv(fx) * 0.96422
    y = (fy**3 if lightness > kappa * eps else lightness / kappa) * 1.0
    z = finv(fz) * 0.82521
    xd = 0.9554734527 * x - 0.0230985368 * y + 0.0632593086 * z
    yd = -0.0283697093 * x + 1.0099954580 * y + 0.0210413945 * z
    zd = 0.0123140016 * x - 0.0205076964 * y + 1.3303659366 * z
    red = 3.2409699419 * xd - 1.5373831776 * yd - 0.4986107603 * zd
    green = -0.9692436363 * xd + 1.8759675015 * yd + 0.0415550574 * zd
    blue = 0.0556300797 * xd - 0.2039769589 * yd + 1.0569715142 * zd
    return _srgb_encode(red), _srgb_encode(green), _srgb_encode(blue)


def _p3_to_rgb(r: float, g: float, b: float) -> tuple[float, float, float]:
    lr, lg, lb = (_srgb_decode(c) for c in (r, g, b))  # same transfer function
    red = 1.2249401 * lr - 0.2249404 * lg + 0.0 * lb
    green = -0.0420569 * lr + 1.0420571 * lg + 0.0 * lb
    blue = -0.0196376 * lr - 0.0786361 * lg + 1.0982735 * lb
    return _srgb_encode(red), _srgb_encode(green), _srgb_encode(blue)


def _hsl_to_rgb(h: float, s: float, lightness: float) -> tuple[float, float, float]:
    def channel(n: int) -> float:
        k = (n + h / 30) % 12
        return lightness - s * min(lightness, 1 - lightness) * max(-1, min(k - 3, 9 - k, 1))

    return channel(0), channel(8), channel(4)


def parse_color(value: str | None) -> RGBA | None:
    """A CSS computed color as sRGB, or None for transparent/unparseable values."""
    if not value:
        return None
    text = value.strip().lower()
    if text in ("transparent", "none", "currentcolor", "inherit", "initial"):
        return None
    if text.startswith("#"):
        digits = text[1:]
        if len(digits) in (3, 4):
            digits = "".join(c * 2 for c in digits)
        if len(digits) not in (6, 8) or not re.fullmatch(r"[0-9a-f]+", digits):
            return None
        values = [int(digits[i : i + 2], 16) / 255 for i in range(0, len(digits), 2)]
        return RGBA(values[0], values[1], values[2], values[3] if len(values) == 4 else 1.0)
    match = _FUNC.match(text)
    if not match:
        return None
    name, args = match.group(1), match.group(2)
    try:
        if name == "color":
            space, *rest = args.replace(",", " ").split(None, 1)
            tokens, alpha = _split(rest[0] if rest else "")
            channels = [_parse_component(t, 1.0) for t in tokens[:3]]
            if space in ("srgb", "srgb-linear"):
                if space == "srgb-linear":
                    channels = [_srgb_encode(c) for c in channels]
                r, g, b = channels
            elif space == "display-p3":
                r, g, b = _p3_to_rgb(*channels)
            else:
                return None
            color = RGBA(r, g, b, _alpha(alpha))
        else:
            tokens, alpha = _split(args)
            legacy_alpha = tokens[3] if len(tokens) > 3 else None
            if name in ("rgb", "rgba"):
                # rgb(37 99 235) or rgb(15% 39% 92%)
                r, g, b = (
                    float(t[:-1]) / 100 if t.endswith("%") else _parse_component(t, 1.0) / 255
                    for t in tokens[:3]
                )
                color = RGBA(r, g, b, _alpha(alpha, legacy_alpha))
            elif name in ("hsl", "hsla"):
                h = float(tokens[0].removesuffix("deg"))
                s = _parse_component(tokens[1], 1.0, 1.0) / (1 if tokens[1].endswith("%") else 100)
                lightness = _parse_component(tokens[2], 1.0, 1.0) / (
                    1 if tokens[2].endswith("%") else 100
                )
                color = RGBA(*_hsl_to_rgb(h, s, lightness), _alpha(alpha, legacy_alpha))
            elif name == "oklab":
                lightness = _parse_component(tokens[0], 1.0, 1.0)
                a = _parse_component(tokens[1], 1.0, 0.4)
                b = _parse_component(tokens[2], 1.0, 0.4)
                color = RGBA(*oklab_to_rgb(lightness, a, b), _alpha(alpha))
            elif name == "oklch":
                lightness = _parse_component(tokens[0], 1.0, 1.0)
                chroma = _parse_component(tokens[1], 1.0, 0.4)
                hue = math.radians(
                    float(tokens[2].removesuffix("deg")) if tokens[2] != "none" else 0.0
                )
                color = RGBA(
                    *oklab_to_rgb(lightness, chroma * math.cos(hue), chroma * math.sin(hue)),
                    _alpha(alpha),
                )
            elif name == "lab":
                lightness = _parse_component(tokens[0], 1.0, 100.0)
                a = _parse_component(tokens[1], 1.0, 125.0)
                b = _parse_component(tokens[2], 1.0, 125.0)
                color = RGBA(*_lab_to_rgb(lightness, a, b), _alpha(alpha))
            elif name == "lch":
                lightness = _parse_component(tokens[0], 1.0, 100.0)
                chroma = _parse_component(tokens[1], 1.0, 150.0)
                hue = math.radians(
                    float(tokens[2].removesuffix("deg")) if tokens[2] != "none" else 0.0
                )
                color = RGBA(
                    *_lab_to_rgb(lightness, chroma * math.cos(hue), chroma * math.sin(hue)),
                    _alpha(alpha),
                )
            else:
                return None
    except (ValueError, IndexError):
        return None
    if color.a <= 0.001:
        return None
    return color


def distance(a: RGBA, b: RGBA) -> float:
    """Perceptual distance (Euclidean in OKLab). ~0.02 is a just-noticeable difference."""
    la, aa, ba = rgb_to_oklab(a)
    lb, ab, bb = rgb_to_oklab(b)
    return math.sqrt((la - lb) ** 2 + (aa - ab) ** 2 + (ba - bb) ** 2)


def relative_luminance(color: RGBA) -> float:
    red, green, blue = (_srgb_decode(max(0.0, min(1.0, c))) for c in (color.r, color.g, color.b))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(a: RGBA, b: RGBA) -> float:
    la, lb = sorted((relative_luminance(a), relative_luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)

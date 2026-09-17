"""Lexical domain analysis: edit distance, homoglyph skeletons, brand mentions."""

import re
import unicodedata

# Characters commonly substituted for Latin letters in lookalike domains (Unicode
# confusables subset: Cyrillic, Greek, Latin extended), plus ASCII look-alikes.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "һ": "h",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "ѕ": "s",
    "т": "t",
    "у": "y",
    "х": "x",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ɡ": "g",
    "ӏ": "l",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ω": "w",
    # Latin extended / IPA
    "ı": "i",
    "ł": "l",
    "ƚ": "l",
    "ɩ": "i",
    "ɑ": "a",
    "ʀ": "r",
    "ɢ": "g",
    "ᴄ": "c",
    "ᴏ": "o",
    "ṁ": "m",
    "ṅ": "n",
    "ạ": "a",
    "ẹ": "e",
    "ọ": "o",
    "ụ": "u",
}
ASCII_LOOKALIKES = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("7", "t"),
)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b))
            )
        previous = current
    return previous[-1]


def to_unicode(label: str) -> str:
    try:
        return label.encode("ascii").decode("idna") if label.startswith("xn--") else label
    except UnicodeError:
        return label


def skeleton(label: str) -> str:
    """Map confusable characters to the Latin letters they imitate."""
    text = unicodedata.normalize("NFKC", to_unicode(label).lower())
    mapped = "".join(CONFUSABLES.get(char, char) for char in text)
    # Strip remaining diacritics (é -> e).
    mapped = "".join(
        c for c in unicodedata.normalize("NFKD", mapped) if not unicodedata.combining(c)
    )
    return mapped


def ascii_skeleton(label: str) -> str:
    text = skeleton(label)
    for lookalike, letter in ASCII_LOOKALIKES:
        text = text.replace(lookalike, letter)
    return text


def scripts(label: str) -> set[str]:
    found = set()
    for char in to_unicode(label):
        if char.isascii():
            if char.isalpha():
                found.add("LATIN")
            continue
        name = unicodedata.name(char, "")
        found.add(name.split(" ")[0] if name else "UNKNOWN")
    return found


def tokens(label: str) -> list[str]:
    return [t for t in re.split(r"[^a-z]+", label.lower()) if t]


# Brand names that are also common words: only an exact, capitalised mention in the
# page title counts.
AMBIGUOUS_KEYWORDS = frozenset({"ups", "steam", "apple", "chase bank", "adobe", "yahoo"})


def mentions(text: str, keyword: str) -> bool:
    if keyword in AMBIGUOUS_KEYWORDS:
        return False
    return re.search(rf"(?<![\w]){re.escape(keyword)}(?![\w])", text, re.IGNORECASE) is not None


def title_mentions(title: str, keyword: str, brand_name: str) -> bool:
    if keyword in AMBIGUOUS_KEYWORDS:
        return re.search(rf"(?<![\w]){re.escape(brand_name)}(?![\w])", title) is not None
    return mentions(title, keyword)

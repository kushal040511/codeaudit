"""Coarse issue categories, so the same issue reported by different tools can be matched.

Tools describe issues differently: Semgrep's rule ids are descriptive but its CWE
tags are unreliable (its Flask SQL-injection rule is tagged CWE-704), while
Bandit's "blacklist" rules are only identifiable by CWE. So keywords in the rule
id/name are checked first, then CWE ids.
"""

import re
from collections.abc import Iterable
from typing import Any

# Order matters: the first matching category wins ("subprocess" before "exec").
KEYWORD_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (category, re.compile(pattern))
    for category, pattern in (
        ("debug-enabled", r"debug"),
        ("insecure-deserialization", r"pickle|marshal|deserial|yaml[._-]?load|unsafe[._-]?load"),
        ("sql-injection", r"sql"),
        (
            "command-injection",
            r"subprocess|shell|os[._-]?system|popen|command[._-]?injection|child[._-]?process"
            r"|spawn|start[._-]?process",
        ),
        ("code-injection", r"eval|exec|code[._-]?injection|new[._-]?function"),
        ("xss", r"xss|cross[._-]?site|raw[._-]?html|innerhtml|mark[._-]?safe|autoescape"),
        ("path-traversal", r"path[._-]?traversal|directory[._-]?traversal"),
        ("ssrf", r"ssrf"),
        ("xxe", r"xxe|xml[._-]?external"),
        ("open-redirect", r"open[._-]?redirect"),
        ("tls-verification", r"verify|certificate|ssl|tls"),
        (
            "weak-crypto",
            r"md5|sha1|hashlib|weak[._-]?hash|insecure[._-]?hash|des\b|weak[._-]?cipher",
        ),
        ("insecure-randomness", r"random"),
        ("bind-all-interfaces", r"bind[._-]?all|0\.0\.0\.0|bad[._-]?host"),
        ("hardcoded-secret", r"password|secret|token|credential|api[._-]?key|hardcoded"),
    )
)

CWE_CATEGORIES: dict[int, str] = {
    89: "sql-injection",
    564: "sql-injection",
    77: "command-injection",
    78: "command-injection",
    94: "code-injection",
    95: "code-injection",
    79: "xss",
    80: "xss",
    502: "insecure-deserialization",
    22: "path-traversal",
    23: "path-traversal",
    918: "ssrf",
    611: "xxe",
    601: "open-redirect",
    295: "tls-verification",
    327: "weak-crypto",
    328: "weak-crypto",
    326: "weak-crypto",
    916: "weak-crypto",
    330: "insecure-randomness",
    338: "insecure-randomness",
    489: "debug-enabled",
    215: "debug-enabled",
    605: "bind-all-interfaces",
    259: "hardcoded-secret",
    321: "hardcoded-secret",
    798: "hardcoded-secret",
}

_CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def categorize(rule_text: str, cwe_ids: Iterable[int] = ()) -> str | None:
    """Category for a rule, from its id/name, falling back to CWE ids. None if unknown."""
    text = rule_text.lower()
    for category, pattern in KEYWORD_CATEGORIES:
        if pattern.search(text):
            return category
    for cwe in cwe_ids:
        if cwe in CWE_CATEGORIES:
            return CWE_CATEGORIES[cwe]
    return None


def parse_cwe_ids(values: Any) -> tuple[int, ...]:
    """CWE ids from "CWE-89: ..." strings, ints, or lists of either."""
    items = values if isinstance(values, list | tuple) else [values]
    ids: list[int] = []
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            found = [item]
        else:
            found = [int(m) for m in _CWE_PATTERN.findall(str(item))]
        ids.extend(cwe for cwe in found if cwe not in ids)
    return tuple(ids)

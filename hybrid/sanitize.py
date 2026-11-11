"""Sanitizers for tool evidence and a fail-closed prompt audit.

Source cleaning is handled by the shared ``juliet_llm.cleaning`` module.  This
module only scrubs tool messages and asserts that no label, path, CWE id, or
file name survived into anything that is sent to a model.
"""

from __future__ import annotations

import re

_IDENT = re.compile(r"[A-Za-z_]\w*")
_ABS_PATH = re.compile(r"(?:/mnt/|/home/|/tmp/|[A-Za-z]:\\)[^\s\"'<>]*")
_FILE_WITH_EXT = re.compile(r"[\w./\\-]+\.(?:c|cc|cpp|cxx|h|hpp)(?::\d+)?", re.IGNORECASE)
_LINE_REF = re.compile(r"\bon line \d+\b", re.IGNORECASE)
_CWE_ID = re.compile(r"(?i)\bCWE\s*[-_]?\s*\d+\b")
_OMIT = re.compile(r"\bOMIT(?:BAD|GOOD)\b")
_UNIT_ID = re.compile(r"\bCWE\d+_[A-Za-z0-9_]+\b")

_SAFE_EVIDENCE_WORDS = {
    "bad": "unfavourable",
    "good": "favourable",
    "Bad": "Unfavourable",
    "Good": "Favourable",
}


def _neutral_identifier(name: str) -> bool:
    lowered = name.lower()
    return bool(
        re.search(
            r"bad|good|cwe\d|memory_leak|testcase|benign|fixed|flaw|vulnerab",
            lowered,
        )
        or lowered.startswith("omit")
    )


def scrub_evidence_text(text: str) -> str:
    """Scrub a tool message/evidence fragment of identifiers and paths."""
    text = _ABS_PATH.sub("<path>", text)
    text = _FILE_WITH_EXT.sub("<file>", text)
    text = _LINE_REF.sub("at an unstated location", text)
    text = _CWE_ID.sub("[cwe]", text)
    text = _OMIT.sub("<macro>", text)
    text = _UNIT_ID.sub("<unit>", text)

    def ident(match: re.Match[str]) -> str:
        name = match.group(0)
        if _neutral_identifier(name):
            return "<symbol>"
        return name

    text = _IDENT.sub(ident, text)
    for word, replacement in _SAFE_EVIDENCE_WORDS.items():
        text = re.sub(rf"\b{word}\b", replacement, text)
    return re.sub(r"\s+", " ", text).strip()


_FORBIDDEN = [
    re.compile(r"(?i)/mnt/"),
    re.compile(r"(?i)\b[A-Za-z]:\\"),
    re.compile(r"(?i)\bCWE\s*[-_]?\s*\d+\b"),
    re.compile(r"(?i)\bOMIT(?:BAD|GOOD)\b"),
    re.compile(r"(?i)\b(?:bad|good)(?:sink|source|g2b|b2g)?\b"),
    re.compile(r"(?i)\b(?:benign|fixed|flaw|vulnerable|vulnerability)\b"),
    re.compile(r"(?i)memory_leak"),
    re.compile(r"(?i)testcase"),
    re.compile(r"(?i)\b\w+\.(?:c|cc|cpp|cxx|h|hpp)\b"),
]


def assert_clean(text: str, where: str) -> None:
    """Raise when a label or path marker survived sanitisation."""
    for pattern in _FORBIDDEN:
        match = pattern.search(text)
        if match:
            excerpt = text[max(0, match.start() - 40) : match.end() + 40].replace("\n", " ")
            raise ValueError(f"{where}: forbidden marker {match.group(0)!r} in: ...{excerpt}...")

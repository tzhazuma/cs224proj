"""Conservative extraction of model-safe context from SecVulEval records.

The raw ``context`` cell is a Python-repr-like string containing numpy arrays.
It is never evaluated and never forwarded verbatim.  This module parses the
literal structure with ``ast``, keeps only a small allow-list of context
sections, and drops any item that could reveal ground truth (labels, CVE/CWE
identifiers, fix indices, or changed-line data).  ``Explanation`` is not
allow-listed at all because it can describe the vulnerability directly.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any, Iterable

ALLOWED_CONTEXT_KEYS: tuple[str, ...] = (
    "Execution Environment",
    "External Function",
    "Function Argument",
    "Globals",
    "Type Execution Declaration",
)

# Values are identifiers/short labels.  Keep the prompt bounded and keep any
# suspicious ground-truth-like string out of the model input.
MAX_ITEM_CHARS = 200
MAX_ITEMS_PER_SECTION = 30
MAX_TOTAL_CHARS = 4000

_FORBIDDEN_SUBSTRINGS = (
    "cve",
    "cwe",
    "nvd-cwe",
    "fixed_func_idx",
    "fixed-func-idx",
    "fixed_idx",
    "changed_lines",
    "changed-lines",
    "changed_statements",
    "changed-statements",
    "is_vulnerable",
    "vulnerab",
    "ground truth",
    "ground_truth",
    "fixed function",
    "patch",
)
_FORBIDDEN_RE = re.compile(r"\b(?:CVE|CWE)[-_]?\d", re.IGNORECASE)


@dataclass(frozen=True)
class SafeContext:
    sections: tuple[tuple[str, tuple[str, ...]], ...]
    provided: bool
    parse_ok: bool
    parse_error: str | None
    excluded_keys: tuple[str, ...]

    def render(self) -> str:
        if not self.sections:
            return "(No usable structured context was available.)"
        lines: list[str] = []
        for key, items in self.sections:
            lines.append(f"{key}:")
            for item in items:
                lines.append(f"- {item}")
        return "\n".join(lines)

    def metadata(self) -> dict[str, Any]:
        return {
            "provided": self.provided,
            "parse_ok": self.parse_ok,
            "parse_error": self.parse_error,
            "excluded_keys": list(self.excluded_keys),
            "section_item_counts": {key: len(items) for key, items in self.sections},
        }


def _is_forbidden(text: str) -> bool:
    lowered = text.casefold()
    if any(token in lowered for token in _FORBIDDEN_SUBSTRINGS):
        return True
    return bool(_FORBIDDEN_RE.search(text))


def _constant_strings(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            yield node.value
        elif isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            yield str(node.value)
        return
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for child in node.elts:
            yield from _constant_strings(child)
        return
    if isinstance(node, ast.Call):
        # numpy array([...], dtype=object): inspect the first positional arg.
        if node.args:
            yield from _constant_strings(node.args[0])


def _parse_context_mapping(raw: str) -> tuple[dict[str, list[str]], str | None]:
    try:
        tree = ast.parse(raw.strip(), mode="eval")
    except SyntaxError as exc:
        return {}, f"context is not parseable as a Python expression ({exc.msg})"
    node = tree.body
    if not isinstance(node, ast.Dict):
        return {}, "context expression is not a dictionary"
    result: dict[str, list[str]] = {}
    for key_node, value_node in zip(node.keys, node.values):
        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
            continue
        key = key_node.value
        values = list(_constant_strings(value_node))
        result[key] = values
    return result, None


def extract_safe_context(raw: str | None) -> SafeContext:
    """Return only allow-listed, sanitised context sections."""
    if raw is None or not raw.strip():
        return SafeContext(
            sections=(),
            provided=False,
            parse_ok=True,
            parse_error=None,
            excluded_keys=(),
        )
    mapping, error = _parse_context_mapping(raw)
    if error is not None:
        return SafeContext(
            sections=(),
            provided=True,
            parse_ok=False,
            parse_error=error,
            excluded_keys=(),
        )

    sections: list[tuple[str, tuple[str, ...]]] = []
    total_chars = 0
    for key in ALLOWED_CONTEXT_KEYS:
        kept: list[str] = []
        seen: set[str] = set()
        for value in mapping.get(key, []):
            item = " ".join(value.split())
            if not item or len(item) > MAX_ITEM_CHARS:
                continue
            if _is_forbidden(item) or item in seen:
                continue
            if total_chars + len(item) > MAX_TOTAL_CHARS:
                break
            seen.add(item)
            kept.append(item)
            total_chars += len(item)
            if len(kept) >= MAX_ITEMS_PER_SECTION:
                break
        if kept:
            sections.append((key, tuple(kept)))

    excluded = tuple(sorted(key for key in mapping if key not in ALLOWED_CONTEXT_KEYS))
    return SafeContext(
        sections=tuple(sections),
        provided=True,
        parse_ok=True,
        parse_error=None,
        excluded_keys=excluded,
    )


def rendered_context_is_safe(rendered: str) -> bool:
    """Defensive check used by tests/dry-run diagnostics.

    It intentionally checks only the rendered context block, not source code:
    code may legitimately mention CVE identifiers or the word "fixed".
    """
    return not _is_forbidden(rendered)

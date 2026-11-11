"""Strict parsing and structural checks for model output.

The parser deliberately rejects markdown fences, trailing prose, duplicate
object keys, and non-finite JSON numbers.  A response is either a single JSON
object that matches the task schema, or it is recorded as invalid.  Repair
"completeness" is only a structural proxy: no compiler or test oracle is
available in this runner.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any


class OutputSchemaError(ValueError):
    """Raised when a model response is not the required JSON object."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_json_object(content: str) -> dict[str, Any]:
    """Parse exactly one JSON object, with no surrounding text or fences."""
    if not isinstance(content, str):
        raise OutputSchemaError("response content is not a string")
    text = content.strip()
    if not text:
        raise OutputSchemaError("response content is empty")
    if text.startswith("```") or text.endswith("```"):
        raise OutputSchemaError("markdown code fences are not accepted")
    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicate_keys,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise OutputSchemaError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise OutputSchemaError("top-level JSON value must be an object")
    return value


def validate_detection_output(content: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = parse_json_object(content)
    expected = {"is_vulnerable", "confidence", "rationale"}
    actual = set(parsed)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise OutputSchemaError(f"detection JSON keys mismatch (missing={missing}, extra={extra})")
    if not isinstance(parsed["is_vulnerable"], bool):
        raise OutputSchemaError("is_vulnerable must be a boolean")
    confidence = parsed["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise OutputSchemaError("confidence must be a number")
    if not math.isfinite(float(confidence)) or not 0.0 <= float(confidence) <= 1.0:
        raise OutputSchemaError("confidence must be finite and between 0 and 1")
    if not isinstance(parsed["rationale"], str):
        raise OutputSchemaError("rationale must be a string")
    return (
        {
            "is_vulnerable": parsed["is_vulnerable"],
            "confidence": float(confidence),
            "rationale": parsed["rationale"],
        },
        {"valid": True},
    )


def validate_repair_output(content: str, source_code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed = parse_json_object(content)
    expected = {"fixed_function", "explanation"}
    actual = set(parsed)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise OutputSchemaError(f"repair JSON keys mismatch (missing={missing}, extra={extra})")
    fixed = parsed["fixed_function"]
    explanation = parsed["explanation"]
    if not isinstance(fixed, str) or not fixed.strip():
        raise OutputSchemaError("fixed_function must be a non-empty string")
    if not isinstance(explanation, str):
        raise OutputSchemaError("explanation must be a string")
    checks = analyze_repair(fixed, source_code)
    return (
        {"fixed_function": fixed, "explanation": explanation},
        checks,
    )


def normalize_code(code: str) -> str:
    """Normalise line endings/trailing spaces while preserving indentation."""
    text = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def collapse_whitespace(code: str) -> str:
    return re.sub(r"\s+", " ", normalize_code(code)).strip()


@dataclass(frozen=True)
class BalanceScan:
    balanced: bool
    first_open_brace: int | None
    first_close_brace: int | None
    unclosed_delimiters: tuple[str, ...]


def scan_delimiters(code: str) -> BalanceScan:
    """Check (), [], {} outside strings, chars, and C/C++ comments.

    This intentionally does not try to be a C++ parser.  It catches truncated
    or diff-style outputs, which is what the structural repair metric claims.
    """
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    first_open: int | None = None
    first_close: int | None = None
    state = "normal"
    i = 0
    length = len(code)
    while i < length:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < length else ""
        if state == "normal":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "string"
                i += 1
                continue
            if ch == "'":
                state = "char"
                i += 1
                continue
            if ch in "([{":
                if ch == "{" and first_open is None:
                    first_open = i
                stack.append((ch, i))
            elif ch in ")]}":
                if ch == "}" and first_close is None:
                    first_close = i
                if not stack or stack[-1][0] != pairs[ch]:
                    return BalanceScan(False, first_open, first_close, tuple(item[0] for item in stack))
                stack.pop()
        elif state == "line_comment":
            if ch == "\n":
                state = "normal"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "normal"
                i += 2
                continue
        elif state in {"string", "char"}:
            if ch == "\\":
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "normal"
        i += 1
    balanced = not stack and state in {"normal", "line_comment"}
    return BalanceScan(balanced, first_open, first_close, tuple(item[0] for item in stack))


def analyze_repair(fixed_code: str, source_code: str) -> dict[str, Any]:
    normalized = normalize_code(fixed_code)
    collapsed = collapse_whitespace(fixed_code)
    scan = scan_delimiters(fixed_code)
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    starts_like_diff = bool(lines) and (
        lines[0].startswith("diff --git")
        or lines[0].startswith("@@")
        or all(line[:1] in {"+", "-"} for line in lines[: min(4, len(lines))])
    )
    has_fence = "```" in fixed_code
    prefix = fixed_code[: scan.first_open_brace] if scan.first_open_brace is not None else ""
    function_like = (
        scan.first_open_brace is not None
        and scan.first_close_brace is not None
        and "(" in prefix
        and ")" in prefix
        and not prefix.rstrip().endswith(";")
    )
    complete = bool(
        normalized
        and not has_fence
        and not starts_like_diff
        and scan.balanced
        and function_like
    )
    source_normalized = normalize_code(source_code)
    source_collapsed = collapse_whitespace(source_code)
    return {
        "complete_function": complete,
        "balanced_delimiters": scan.balanced,
        "function_like_prefix": function_like,
        "contains_markdown_fence": has_fence,
        "starts_like_diff": starts_like_diff,
        "changed_from_input": normalized != source_normalized,
        "whitespace_changed_from_input": collapsed != source_collapsed,
        "fixed_line_count": normalized.count("\n") + 1 if normalized else 0,
        "fixed_code_sha256": hashlib.sha256(fixed_code.encode("utf-8")).hexdigest(),
    }

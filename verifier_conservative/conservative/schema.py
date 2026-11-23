"""Strict validation of one three-way conservative verifier response.

The contract has exactly six keys.  A response is ``ok`` only when the JSON
object, types, line ranges, and assessment/kind combinations are internally
consistent:

* supported or insufficient -> no rebuttal kind, no lines, no counterexample;
* unsupported + guard_present -> at least one cited line;
* unsupported + counterexample -> at least one cited line and a concrete
  counterexample string.

Line *numbers* are validated here (in range, unique).  Whether a cited line is
usable evidence (not blank, not only a comment or brace, guard-like for
``guard_present``) is recorded as audit flags; the decision layer uses those
flags and keeps the claim when grounding fails.  The verifier never silently
repairs a response.
"""

from __future__ import annotations

import math
import re
from typing import Any, Sequence

from secvul_runner.validation import OutputSchemaError, parse_json_object

EXPECTED_KEYS = frozenset(
    {
        "assessment",
        "confidence",
        "rebuttal_kind",
        "rebuttal_lines",
        "counterexample",
        "reason",
    }
)

ASSESSMENTS = frozenset({"supported", "unsupported", "insufficient"})
REBUTTAL_KINDS = frozenset({"none", "guard_present", "counterexample"})
MAX_REBUTTAL_LINES = 64
MIN_REASON_CHARS = 20
MIN_COUNTEREXAMPLE_CHARS = 12

_NONE_LIKE = {
    "",
    "none",
    "n/a",
    "na",
    "not applicable",
    "null",
    "no counterexample",
    "not provided",
}

_COMMENT_ONLY_RE = re.compile(r"^\s*(//|/\*|\*|\*/)")
_BRACE_ONLY_RE = re.compile(r"^[\s{}();,]*$")
_GUARD_TOKEN_RE = re.compile(
    r"("
    r"\bif\b|\belse\b|\breturn\b|\bbreak\b|\bcontinue\b|\bgoto\b|\bswitch\b|"
    r"\bassert\b|\babort\b|\bthrow\b|\bexit\b|"
    r"&&|\|\||==|!=|<=|>=|<|>|\?|"
    r"\b(min|max|clamp|limit|bound|bounds|check|validate|valid|safe|guard|"
    r"strncpy|strlcpy|snprintf|memcpy_s|sizeof|strlen|size|len|null|NULL)\b"
    r")",
    re.IGNORECASE,
)


class ConservativeSchemaError(OutputSchemaError):
    """Schema failure with a coarse family used for the failure taxonomy."""

    def __init__(self, message: str, family: str) -> None:
        super().__init__(message)
        self.family = family


def _none_like(value: str) -> bool:
    return value.strip().lower().rstrip(".") in _NONE_LIKE


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_code_line(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if _BRACE_ONLY_RE.match(stripped):
        return False
    if _COMMENT_ONLY_RE.match(stripped):
        return False
    return True


def line_quality(line_texts: Sequence[str], lines: Sequence[int]) -> dict[str, Any]:
    """Audit whether cited line numbers point at usable code lines."""
    blank = [line for line in lines if not line_texts[line - 1].strip()]
    code = [line for line in lines if _is_code_line(line_texts[line - 1])]
    guard = [
        line
        for line in lines
        if _is_code_line(line_texts[line - 1])
        and _GUARD_TOKEN_RE.search(line_texts[line - 1])
    ]
    return {
        "rebuttal_grounded": not blank,
        "blank_rebuttal_lines": blank,
        "code_line_cited": bool(code),
        "code_rebuttal_lines": code,
        "guard_lexical_match": bool(guard),
        "guard_lexical_lines": guard,
    }


def validate_conservative_output(
    content: str,
    line_texts: tuple[str, ...] | list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse and validate one conservative response.

    Returns ``(parsed, audit)`` and raises :class:`ConservativeSchemaError` on
    any contract violation.  The error string is stored verbatim in the record.
    """
    line_count = len(line_texts)
    try:
        parsed = parse_json_object(content)
    except OutputSchemaError as exc:
        raise ConservativeSchemaError(str(exc), "parse") from exc

    actual = set(parsed)
    if actual != EXPECTED_KEYS:
        missing = sorted(EXPECTED_KEYS - actual)
        extra = sorted(actual - EXPECTED_KEYS)
        raise ConservativeSchemaError(
            f"verifier JSON keys mismatch (missing={missing}, extra={extra})", "keys"
        )

    assessment = parsed["assessment"]
    if assessment not in ASSESSMENTS:
        raise ConservativeSchemaError(
            f"assessment must be one of {sorted(ASSESSMENTS)}", "assessment"
        )

    confidence = parsed["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ConservativeSchemaError("confidence must be a number", "types")
    confidence_value = float(confidence)
    if not math.isfinite(confidence_value) or not 0.0 <= confidence_value <= 1.0:
        raise ConservativeSchemaError(
            "confidence must be finite and between 0 and 1", "confidence"
        )

    rebuttal_kind = parsed["rebuttal_kind"]
    if rebuttal_kind not in REBUTTAL_KINDS:
        raise ConservativeSchemaError(
            f"rebuttal_kind must be one of {sorted(REBUTTAL_KINDS)}", "rebuttal_kind"
        )

    rebuttal_lines = parsed["rebuttal_lines"]
    if not isinstance(rebuttal_lines, list):
        raise ConservativeSchemaError("rebuttal_lines must be an array", "types")
    if len(rebuttal_lines) > MAX_REBUTTAL_LINES:
        raise ConservativeSchemaError(
            f"rebuttal_lines exceeds {MAX_REBUTTAL_LINES} entries", "semantic"
        )
    clean_lines: list[int] = []
    seen: set[int] = set()
    for position, value in enumerate(rebuttal_lines):
        if not _is_int(value):
            raise ConservativeSchemaError(
                f"rebuttal_lines[{position}] must be an integer", "types"
            )
        if value < 1 or value > line_count:
            raise ConservativeSchemaError(
                f"rebuttal_lines[{position}]={value} is outside 1..{line_count}", "range"
            )
        if value in seen:
            raise ConservativeSchemaError(
                f"rebuttal_lines contains duplicate line {value}", "range"
            )
        seen.add(value)
        clean_lines.append(value)

    counterexample = parsed["counterexample"]
    reason = parsed["reason"]
    if not isinstance(counterexample, str):
        raise ConservativeSchemaError("counterexample must be a string", "types")
    if not isinstance(reason, str):
        raise ConservativeSchemaError("reason must be a string", "types")
    if len(reason.strip()) < MIN_REASON_CHARS:
        raise ConservativeSchemaError(
            f"reason must be at least {MIN_REASON_CHARS} characters", "semantic"
        )

    counterexample_provided = not _none_like(counterexample)
    if counterexample_provided and len(counterexample.strip()) < MIN_COUNTEREXAMPLE_CHARS:
        raise ConservativeSchemaError(
            f"counterexample must be at least {MIN_COUNTEREXAMPLE_CHARS} characters "
            "or 'none'",
            "semantic",
        )

    if assessment in {"supported", "insufficient"}:
        if rebuttal_kind != "none":
            raise ConservativeSchemaError(
                f"{assessment} requires rebuttal_kind 'none'", "semantic"
            )
        if clean_lines:
            raise ConservativeSchemaError(
                f"{assessment} must not cite rebuttal lines", "semantic"
            )
        if counterexample_provided:
            raise ConservativeSchemaError(
                f"{assessment} must not report a counterexample", "semantic"
            )
    else:  # unsupported
        if rebuttal_kind == "none":
            raise ConservativeSchemaError(
                "unsupported requires rebuttal_kind guard_present or counterexample",
                "semantic",
            )
        if not clean_lines:
            raise ConservativeSchemaError(
                f"unsupported rebuttal_kind {rebuttal_kind} requires at least one "
                "rebuttal line",
                "semantic",
            )
        if rebuttal_kind == "counterexample" and not counterexample_provided:
            raise ConservativeSchemaError(
                "unsupported counterexample requires a concrete counterexample string",
                "semantic",
            )

    quality = line_quality(line_texts, clean_lines)
    audit = {
        "schema_valid": True,
        "assessment": assessment,
        "confidence": confidence_value,
        "rebuttal_kind": rebuttal_kind,
        "rebuttal_lines": clean_lines,
        "rebuttal_line_count": len(clean_lines),
        "counterexample_provided": counterexample_provided,
        "counterexample_chars": len(counterexample),
        "reason_chars": len(reason),
        "line_count": line_count,
        **quality,
    }
    clean_parsed = {
        "assessment": assessment,
        "confidence": confidence_value,
        "rebuttal_kind": rebuttal_kind,
        "rebuttal_lines": clean_lines,
        "counterexample": counterexample,
        "reason": reason,
    }
    return clean_parsed, audit

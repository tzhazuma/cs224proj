"""Strict validation and audit metadata for the evidence-grounded output.

A response is ``ok`` only when it is one JSON object with exactly the six
contract keys, correct types, in-range unique evidence lines, and a
label-consistent evidence shape:

* vulnerable  -> at least one evidence line, a non-sentinel mechanism, a
  non-sentinel repair;
* non-vulnerable -> no evidence lines, sentinel mechanism and repair, and
  ``counterfactual_confirms == false``.

``counterfactual_confirms == false`` on a vulnerable prediction does not make
the record schema-invalid.  It is recorded as an audit flag because the model
may legitimately say that its repair only mitigates the defect; downstream
analysis reports both the raw and the counterfactual-confirmed view.
"""

from __future__ import annotations

import math
from typing import Any

from secvul_runner.validation import OutputSchemaError, parse_json_object

EXPECTED_KEYS = frozenset(
    {
        "is_vulnerable",
        "confidence",
        "evidence_lines",
        "mechanism",
        "counterfactual_fix",
        "counterfactual_confirms",
    }
)

_NONE_LIKE = {
    "",
    "none",
    "n/a",
    "na",
    "not applicable",
    "null",
    "no vulnerability",
    "no defect",
    "no issue",
    "safe",
    "not vulnerable",
    "no fix needed",
    "no repair needed",
    "nothing",
}


class EvidenceSchemaError(OutputSchemaError):
    """Schema failure with a coarse family used for failure taxonomy."""

    def __init__(self, message: str, family: str) -> None:
        super().__init__(message)
        self.family = family


def _is_none_like(value: str) -> bool:
    return value.strip().lower().rstrip(".") in _NONE_LIKE


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_evidence_output(
    content: str,
    line_texts: tuple[str, ...] | list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse and validate one model response.

    Returns ``(parsed, audit)``.  Raises :class:`EvidenceSchemaError` when the
    response violates the contract; the error string is stored verbatim in the
    run record.
    """
    line_count = len(line_texts)
    try:
        parsed = parse_json_object(content)
    except OutputSchemaError as exc:
        raise EvidenceSchemaError(str(exc), "parse") from exc

    actual = set(parsed)
    if actual != EXPECTED_KEYS:
        missing = sorted(EXPECTED_KEYS - actual)
        extra = sorted(actual - EXPECTED_KEYS)
        raise EvidenceSchemaError(
            f"evidence JSON keys mismatch (missing={missing}, extra={extra})", "keys"
        )

    is_vulnerable = parsed["is_vulnerable"]
    if not isinstance(is_vulnerable, bool):
        raise EvidenceSchemaError("is_vulnerable must be a boolean", "types")

    confidence = parsed["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise EvidenceSchemaError("confidence must be a number", "types")
    confidence_value = float(confidence)
    if not math.isfinite(confidence_value) or not 0.0 <= confidence_value <= 1.0:
        raise EvidenceSchemaError("confidence must be finite and between 0 and 1", "confidence")

    evidence_lines = parsed["evidence_lines"]
    if not isinstance(evidence_lines, list):
        raise EvidenceSchemaError("evidence_lines must be an array", "types")
    clean_lines: list[int] = []
    seen: set[int] = set()
    for position, value in enumerate(evidence_lines):
        if not _is_int(value):
            raise EvidenceSchemaError(
                f"evidence_lines[{position}] must be an integer", "types"
            )
        if value < 1 or value > line_count:
            raise EvidenceSchemaError(
                f"evidence_lines[{position}]={value} is outside 1..{line_count}", "range"
            )
        if value in seen:
            raise EvidenceSchemaError(
                f"evidence_lines contains duplicate line {value}", "range"
            )
        seen.add(value)
        clean_lines.append(value)

    mechanism = parsed["mechanism"]
    fix = parsed["counterfactual_fix"]
    confirms = parsed["counterfactual_confirms"]
    if not isinstance(mechanism, str):
        raise EvidenceSchemaError("mechanism must be a string", "types")
    if not isinstance(fix, str):
        raise EvidenceSchemaError("counterfactual_fix must be a string", "types")
    if not isinstance(confirms, bool):
        raise EvidenceSchemaError("counterfactual_confirms must be a boolean", "types")

    if is_vulnerable:
        if not clean_lines:
            raise EvidenceSchemaError(
                "vulnerable prediction requires at least one evidence line", "semantic"
            )
        if _is_none_like(mechanism) or len(mechanism.strip()) < 12:
            raise EvidenceSchemaError(
                "vulnerable prediction requires a concrete mechanism", "semantic"
            )
        if _is_none_like(fix) or len(fix.strip()) < 8:
            raise EvidenceSchemaError(
                "vulnerable prediction requires a concrete counterfactual fix", "semantic"
            )
    else:
        if clean_lines:
            raise EvidenceSchemaError(
                "non-vulnerable prediction must not cite evidence lines", "semantic"
            )
        if not _is_none_like(mechanism):
            raise EvidenceSchemaError(
                "non-vulnerable prediction must set mechanism to 'none'", "semantic"
            )
        if not _is_none_like(fix):
            raise EvidenceSchemaError(
                "non-vulnerable prediction must set counterfactual_fix to 'none'", "semantic"
            )
        if confirms is not False:
            raise EvidenceSchemaError(
                "non-vulnerable prediction must set counterfactual_confirms to false",
                "semantic",
            )

    blank_lines = [line for line in clean_lines if not line_texts[line - 1].strip()]
    comment_only = [
        line
        for line in clean_lines
        if line_texts[line - 1].strip().startswith(("//", "/*", "*", "*/"))
    ]
    audit = {
        "schema_valid": True,
        "evidence_lines": clean_lines,
        "evidence_line_count": len(clean_lines),
        "evidence_line_texts": [line_texts[line - 1] for line in clean_lines],
        "blank_evidence_lines": blank_lines,
        "comment_only_evidence_lines": comment_only,
        "evidence_grounded": not blank_lines,
        "counterfactual_confirms": confirms,
        "counterfactual_unconfirmed": bool(is_vulnerable and not confirms),
        "mechanism_chars": len(mechanism),
        "counterfactual_fix_chars": len(fix),
        "line_count": line_count,
    }
    clean_parsed = {
        "is_vulnerable": is_vulnerable,
        "confidence": confidence_value,
        "evidence_lines": clean_lines,
        "mechanism": mechanism,
        "counterfactual_fix": fix,
        "counterfactual_confirms": confirms,
    }
    return clean_parsed, audit

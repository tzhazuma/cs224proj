"""Strict validation of one refutation response.

A record is ``ok`` only when the response is one JSON object with exactly the
seven contract keys, in-range unique rebuttal lines, and a verdict/evidence
shape that is internally consistent:

* sustain -> evidence is supported or partially supported, no rebuttal type or
  lines, and no counterexample;
* retract -> a concrete rebuttal type, and either rebuttal lines (all types
  except ``insufficient_evidence``) or no lines (``insufficient_evidence``).

Anything else is recorded as ``invalid`` and counted as an error by the strict
view; the verifier never silently repairs a response.
"""

from __future__ import annotations

import math
from typing import Any

from secvul_runner.validation import OutputSchemaError, parse_json_object

EXPECTED_KEYS = frozenset(
    {
        "verdict",
        "confidence",
        "evidence_check",
        "rebuttal_type",
        "rebuttal_lines",
        "counterexample",
        "reason",
    }
)

VERDICTS = frozenset({"sustain", "retract"})
EVIDENCE_CHECKS = frozenset({"supported", "partially_supported", "unsupported"})
REBUTTAL_TYPES = frozenset(
    {
        "none",
        "no_reachable_flow",
        "guard_present",
        "evidence_mislocated",
        "not_security_relevant",
        "insufficient_evidence",
    }
)

_NONE_LIKE = {"", "none", "n/a", "na", "not applicable", "null", "no counterexample"}


class VerificationSchemaError(OutputSchemaError):
    """Schema failure with a coarse family used for the failure taxonomy."""

    def __init__(self, message: str, family: str) -> None:
        super().__init__(message)
        self.family = family


def _none_like(value: str) -> bool:
    return value.strip().lower().rstrip(".") in _NONE_LIKE


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_verification_output(
    content: str,
    line_texts: tuple[str, ...] | list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse and validate one refutation response.

    Returns ``(parsed, audit)`` and raises :class:`VerificationSchemaError` on
    any contract violation.  The error string is stored verbatim in the record.
    """
    line_count = len(line_texts)
    try:
        parsed = parse_json_object(content)
    except OutputSchemaError as exc:
        raise VerificationSchemaError(str(exc), "parse") from exc

    actual = set(parsed)
    if actual != EXPECTED_KEYS:
        missing = sorted(EXPECTED_KEYS - actual)
        extra = sorted(actual - EXPECTED_KEYS)
        raise VerificationSchemaError(
            f"verifier JSON keys mismatch (missing={missing}, extra={extra})", "keys"
        )

    verdict = parsed["verdict"]
    if verdict not in VERDICTS:
        raise VerificationSchemaError(f"verdict must be one of {sorted(VERDICTS)}", "verdict")

    confidence = parsed["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise VerificationSchemaError("confidence must be a number", "types")
    confidence_value = float(confidence)
    if not math.isfinite(confidence_value) or not 0.0 <= confidence_value <= 1.0:
        raise VerificationSchemaError("confidence must be finite and between 0 and 1", "confidence")

    evidence_check = parsed["evidence_check"]
    if evidence_check not in EVIDENCE_CHECKS:
        raise VerificationSchemaError(
            f"evidence_check must be one of {sorted(EVIDENCE_CHECKS)}", "evidence_check"
        )

    rebuttal_type = parsed["rebuttal_type"]
    if rebuttal_type not in REBUTTAL_TYPES:
        raise VerificationSchemaError(
            f"rebuttal_type must be one of {sorted(REBUTTAL_TYPES)}", "rebuttal_type"
        )

    rebuttal_lines = parsed["rebuttal_lines"]
    if not isinstance(rebuttal_lines, list):
        raise VerificationSchemaError("rebuttal_lines must be an array", "types")
    clean_lines: list[int] = []
    seen: set[int] = set()
    for position, value in enumerate(rebuttal_lines):
        if not _is_int(value):
            raise VerificationSchemaError(
                f"rebuttal_lines[{position}] must be an integer", "types"
            )
        if value < 1 or value > line_count:
            raise VerificationSchemaError(
                f"rebuttal_lines[{position}]={value} is outside 1..{line_count}", "range"
            )
        if value in seen:
            raise VerificationSchemaError(
                f"rebuttal_lines contains duplicate line {value}", "range"
            )
        seen.add(value)
        clean_lines.append(value)

    counterexample = parsed["counterexample"]
    reason = parsed["reason"]
    if not isinstance(counterexample, str):
        raise VerificationSchemaError("counterexample must be a string", "types")
    if not isinstance(reason, str):
        raise VerificationSchemaError("reason must be a string", "types")
    if len(reason.strip()) < 20:
        raise VerificationSchemaError("reason must be at least 20 characters", "semantic")

    if verdict == "sustain":
        if evidence_check == "unsupported":
            raise VerificationSchemaError(
                "sustain requires evidence_check supported or partially_supported", "semantic"
            )
        if rebuttal_type != "none":
            raise VerificationSchemaError(
                "sustain requires rebuttal_type 'none'", "semantic"
            )
        if clean_lines:
            raise VerificationSchemaError(
                "sustain must not cite rebuttal lines", "semantic"
            )
        if not _none_like(counterexample):
            raise VerificationSchemaError(
                "sustain must not report a counterexample", "semantic"
            )
    else:
        if rebuttal_type == "none":
            raise VerificationSchemaError(
                "retract requires a concrete rebuttal_type", "semantic"
            )
        if rebuttal_type == "insufficient_evidence":
            if clean_lines:
                raise VerificationSchemaError(
                    "insufficient_evidence must not cite rebuttal lines", "semantic"
                )
        elif not clean_lines:
            raise VerificationSchemaError(
                f"rebuttal_type {rebuttal_type} requires at least one rebuttal line", "semantic"
            )

    blank_lines = [line for line in clean_lines if not line_texts[line - 1].strip()]
    audit = {
        "schema_valid": True,
        "verdict": verdict,
        "retracted": verdict == "retract",
        "confidence": confidence_value,
        "evidence_check": evidence_check,
        "rebuttal_type": rebuttal_type,
        "rebuttal_lines": clean_lines,
        "rebuttal_line_count": len(clean_lines),
        "rebuttal_grounded": not blank_lines,
        "blank_rebuttal_lines": blank_lines,
        "counterexample_provided": not _none_like(counterexample),
        "counterexample_chars": len(counterexample),
        "reason_chars": len(reason),
        "line_count": line_count,
    }
    clean_parsed = {
        "verdict": verdict,
        "confidence": confidence_value,
        "evidence_check": evidence_check,
        "rebuttal_type": rebuttal_type,
        "rebuttal_lines": clean_lines,
        "counterexample": counterexample,
        "reason": reason,
    }
    return clean_parsed, audit

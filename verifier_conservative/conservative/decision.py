"""The conservative decision rule applied to one recorded verifier response.

Only an ``unsupported`` assessment with a concrete, line-grounded guard or
counterexample may retract a positive prediction.  Everything else keeps the
first-pass prediction:

* ``supported`` -> keep;
* ``insufficient`` -> keep (explicitly not a refutation);
* ``unsupported`` whose cited lines are blank, comment/brace-only, or (for a
  guard) contain no guard-like token -> keep as ungrounded;
* ``unsupported`` counterexample without a concrete counterexample string ->
  keep;
* schema-invalid response or API error -> keep (fail-open, no fail-closed).
"""

from __future__ import annotations

from typing import Any

KEEP_SUPPORTED = "keep_supported"
KEEP_INSUFFICIENT = "keep_insufficient"
KEEP_FAILURE = "keep_verifier_failure"
KEEP_UNGROUNDED = "keep_unsupported_ungrounded"
KEEP_MISSING_COUNTEREXAMPLE = "keep_counterexample_missing"
RETRACT_GUARD = "retract_guard_grounded"
RETRACT_COUNTEREXAMPLE = "retract_counterexample_grounded"
KEEP_UNKNOWN = "keep_unknown"


def decide(
    status: str,
    parsed: dict[str, Any] | None,
    validation: dict[str, Any] | None,
) -> tuple[bool, str]:
    """Return ``(retract, decision_reason)`` for one verifier record."""
    if status != "ok" or not isinstance(parsed, dict):
        return False, KEEP_FAILURE
    if not isinstance(validation, dict) or validation.get("schema_valid") is not True:
        return False, KEEP_FAILURE

    assessment = parsed.get("assessment")
    if assessment == "supported":
        return False, KEEP_SUPPORTED
    if assessment == "insufficient":
        return False, KEEP_INSUFFICIENT
    if assessment != "unsupported":
        return False, KEEP_UNKNOWN

    kind = parsed.get("rebuttal_kind")
    grounded = validation.get("rebuttal_grounded") is True
    code_line = validation.get("code_line_cited") is True
    if not grounded or not code_line:
        return False, KEEP_UNGROUNDED

    if kind == "guard_present":
        if validation.get("guard_lexical_match") is not True:
            return False, KEEP_UNGROUNDED
        return True, RETRACT_GUARD
    if kind == "counterexample":
        if validation.get("counterexample_provided") is not True:
            return False, KEEP_MISSING_COUNTEREXAMPLE
        return True, RETRACT_COUNTEREXAMPLE
    return False, KEEP_UNKNOWN


# Decision reasons that indicate a retraction; used by the evaluator.
RETRACT_REASONS = frozenset({RETRACT_GUARD, RETRACT_COUNTEREXAMPLE})

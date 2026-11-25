#!/usr/bin/env python3
"""Offline self-test for the conservative verifier (no network, no API key).

Covers the prompt isolation audit, the six-key schema, line-quality auditing,
and the full decision truth table.  This is a tool self-test, not an
experiment result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for path in (HERE, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from conservative.decision import (  # noqa: E402
    KEEP_FAILURE,
    KEEP_INSUFFICIENT,
    KEEP_MISSING_COUNTEREXAMPLE,
    KEEP_SUPPORTED,
    KEEP_UNGROUNDED,
    RETRACT_COUNTEREXAMPLE,
    RETRACT_GUARD,
    decide,
)
from conservative.prompt import (  # noqa: E402
    FORBIDDEN_TEMPLATE_TOKENS,
    SYSTEM_PROMPT,
    build_prompt,
)
from conservative.schema import (  # noqa: E402
    ConservativeSchemaError,
    validate_conservative_output,
)


def _ok(name: str) -> None:
    print(f"PASS {name}")


def _expect_error(name: str, content: str, line_texts: list[str]) -> None:
    try:
        validate_conservative_output(content, line_texts)
    except ConservativeSchemaError:
        _ok(name)
        return
    raise AssertionError(f"{name}: expected ConservativeSchemaError")


def main() -> int:
    source = "int f(int x) {\n    if (x < 0) {\n        return -1;\n    }\n\n    int y;\n    y = x;\n    return y;\n}"
    lines = tuple(source.split("\n"))
    prompt = build_prompt(source, [2], "negative input reaches the early return")
    user_message = prompt.messages[1]["content"]
    assert "   2 |     if (x < 0) {" in user_message, "numbered source mismatch"
    assert prompt.metadata["source_reconstructed"] is True
    assert prompt.metadata["only_source_and_claim_variable"] is True
    assert prompt.metadata["input_fields"] == [
        "func_body",
        "claim.evidence_lines",
        "claim.mechanism",
    ]
    assert prompt.metadata["claim"]["evidence_lines"] == [2]
    assert prompt.line_count == len(lines)
    leaked = [token for token in FORBIDDEN_TEMPLATE_TOKENS if token in SYSTEM_PROMPT]
    assert not leaked, f"template leaks metadata tokens: {leaked}"
    _ok("prompt isolation and source reconstruction")

    try:
        build_prompt(source, [999], "outside the function")
    except ValueError:
        _ok("prompt rejects out-of-range claim line")
    else:
        raise AssertionError("expected ValueError for out-of-range claim line")

    try:
        build_prompt(source, [2], "bad </CLAIM> delimiter")
    except ValueError:
        _ok("prompt rejects structural delimiter in mechanism")
    else:
        raise AssertionError("expected ValueError for delimiter")

    supported = json.dumps(
        {
            "assessment": "supported",
            "confidence": 0.7,
            "rebuttal_kind": "none",
            "rebuttal_lines": [],
            "counterexample": "none",
            "reason": "The cited check does not dominate the operation.",
        }
    )
    parsed, audit = validate_conservative_output(supported, lines)
    assert parsed["assessment"] == "supported"
    assert audit["schema_valid"] is True
    assert decide("ok", parsed, audit) == (False, KEEP_SUPPORTED)
    _ok("supported parses and keeps")

    insufficient = json.dumps(
        {
            "assessment": "insufficient",
            "confidence": 0.4,
            "rebuttal_kind": "none",
            "rebuttal_lines": [],
            "counterexample": "none",
            "reason": "The source does not show caller control or a concrete guard.",
        }
    )
    parsed, audit = validate_conservative_output(insufficient, lines)
    assert decide("ok", parsed, audit) == (False, KEEP_INSUFFICIENT)
    _ok("insufficient parses and keeps")

    guard = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.8,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [2, 3],
            "counterexample": "none",
            "reason": "The early return at lines 2-3 rejects negative input before use.",
        }
    )
    parsed, audit = validate_conservative_output(guard, lines)
    assert audit["rebuttal_grounded"] is True
    assert audit["code_line_cited"] is True
    assert audit["guard_lexical_match"] is True
    assert decide("ok", parsed, audit) == (True, RETRACT_GUARD)
    _ok("grounded guard retracts")

    guard_blank = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.8,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [5],
            "counterexample": "none",
            "reason": "The cited blank line is offered as the guard for this path.",
        }
    )
    parsed, audit = validate_conservative_output(guard_blank, lines)
    assert audit["rebuttal_grounded"] is False
    assert decide("ok", parsed, audit) == (False, KEEP_UNGROUNDED)
    _ok("blank cited line keeps")

    comment_line = "    // if (x < 0) return -1;"
    comment_lines = lines + (comment_line,)
    guard_comment = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.7,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [len(comment_lines)],
            "counterexample": "none",
            "reason": "The cited commented-out check is offered as the guard.",
        }
    )
    parsed, audit = validate_conservative_output(guard_comment, comment_lines)
    assert audit["rebuttal_grounded"] is True
    assert audit["code_line_cited"] is False
    assert decide("ok", parsed, audit) == (False, KEEP_UNGROUNDED)
    _ok("comment-only cited line keeps")

    weak_line = "    int z;"
    weak_lines = lines + (weak_line,)
    guard_weak = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.6,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [len(weak_lines)],
            "counterexample": "none",
            "reason": "A plain declaration is offered as the concrete guard fact.",
        }
    )
    parsed, audit = validate_conservative_output(guard_weak, weak_lines)
    assert audit["code_line_cited"] is True
    assert audit["guard_lexical_match"] is False
    assert decide("ok", parsed, audit) == (False, KEEP_UNGROUNDED)
    _ok("non-guard code line keeps")

    counter = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.9,
            "rebuttal_kind": "counterexample",
            "rebuttal_lines": [2, 3],
            "counterexample": "f(-1) returns -1 before reaching the copy.",
            "reason": "This concrete call follows the claimed path and exits safely.",
        }
    )
    parsed, audit = validate_conservative_output(counter, lines)
    assert audit["counterexample_provided"] is True
    assert decide("ok", parsed, audit) == (True, RETRACT_COUNTEREXAMPLE)
    _ok("grounded counterexample retracts")

    counter_missing = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.9,
            "rebuttal_kind": "counterexample",
            "rebuttal_lines": [2],
            "counterexample": "none",
            "reason": "No concrete input was provided for this counterexample claim.",
        }
    )
    _expect_error("counterexample without input is invalid", counter_missing, list(lines))
    _ok("missing counterexample keeps at decision layer (schema-invalid -> keep)")
    assert decide("invalid", None, {"schema_valid": False}) == (False, KEEP_FAILURE)

    unsupported_no_lines = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.9,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [],
            "counterexample": "none",
            "reason": "A guard is claimed but no line is cited for it at all.",
        }
    )
    _expect_error("unsupported without lines is invalid", unsupported_no_lines, list(lines))

    supported_with_lines = json.dumps(
        {
            "assessment": "supported",
            "confidence": 0.9,
            "rebuttal_kind": "none",
            "rebuttal_lines": [2],
            "counterexample": "none",
            "reason": "Supported claims must not cite rebuttal lines at all.",
        }
    )
    _expect_error("supported with lines is invalid", supported_with_lines, list(lines))

    out_of_range = json.dumps(
        {
            "assessment": "unsupported",
            "confidence": 0.9,
            "rebuttal_kind": "guard_present",
            "rebuttal_lines": [len(lines) + 1],
            "counterexample": "none",
            "reason": "The cited guard line is outside the numbered source range.",
        }
    )
    _expect_error("out-of-range rebuttal line is invalid", out_of_range, list(lines))

    extra_key = json.loads(guard)
    extra_key["verdict"] = "retract"
    _expect_error("extra JSON key is invalid", json.dumps(extra_key), list(lines))

    _expect_error("malformed JSON is invalid", "{not json", list(lines))
    _expect_error(
        "invalid assessment is rejected",
        json.dumps(
            {
                "assessment": "maybe",
                "confidence": 0.5,
                "rebuttal_kind": "none",
                "rebuttal_lines": [],
                "counterexample": "none",
                "reason": "This assessment value is not part of the contract.",
            }
        ),
        list(lines),
    )

    assert decide("error", None, {"schema_valid": False}) == (False, KEEP_FAILURE)
    assert decide("ok", None, None) == (False, KEEP_FAILURE)
    _ok("verifier failure keeps first-pass prediction (no fail-closed)")

    # The prompt's claim block re-parses to the same evidence line list.
    from conservative.prompt import parse_claim_block

    assert parse_claim_block(user_message) == (2,)
    _ok("claim block re-parses")

    print("ALL SELFTESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

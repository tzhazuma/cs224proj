#!/usr/bin/env python3
"""Offline self-test for the evidence-prompt package.

No network and no model calls.  It checks the source-only prompt invariant,
strict output validation, changed-line mapping, and the paired statistics used
by ``analyze.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from analysis.stats import detection_scores, holm_adjust, mcnemar_exact  # noqa: E402
from evidence_prompt.prompt import build_prompt  # noqa: E402
from evidence_prompt.validation import (  # noqa: E402
    EvidenceSchemaError,
    validate_evidence_output,
)

FUNCTION = """int copy_name(const char *src, int n) {
  char buf[16];
  memcpy(buf, src, n);
  return 0;
}"""


def check_prompt() -> None:
    prompt = build_prompt(FUNCTION)
    assert prompt.line_count == 5, prompt.line_count
    assert prompt.metadata["only_source_variable"] is True
    assert prompt.metadata["source_reconstructed"] is True
    assert prompt.metadata["context"] == {"used": False}
    assert prompt.metadata["input_fields"] == ["func_body"]
    user = prompt.messages[1]["content"]
    assert '<FUNCTION_SOURCE lines="5">' in user
    assert "   1 | int copy_name" in user
    assert "CONTEXT_DATA" not in user
    assert "project" not in prompt.messages[0]["content"]
    assert "filepath" not in prompt.messages[0]["content"]
    assert "changed_lines" not in prompt.messages[0]["content"]
    assert "is_vulnerable" in prompt.messages[0]["content"]  # output contract, not metadata
    print("prompt: PASS")


def _expect_error(payload: dict, family: str) -> None:
    try:
        validate_evidence_output(json.dumps(payload), FUNCTION.split("\n"))
    except EvidenceSchemaError as exc:
        assert exc.family == family, (exc.family, family, str(exc))
        return
    raise AssertionError(f"expected {family} error")


def check_validation() -> None:
    lines = tuple(FUNCTION.split("\n"))
    positive = {
        "is_vulnerable": True,
        "confidence": 0.8,
        "evidence_lines": [3],
        "mechanism": "memcpy copies n bytes into a 16-byte stack buffer without a bounds check.",
        "counterfactual_fix": "reject n > sizeof(buf) before memcpy.",
        "counterfactual_confirms": True,
    }
    parsed, audit = validate_evidence_output(json.dumps(positive), lines)
    assert parsed["is_vulnerable"] is True
    assert audit["evidence_grounded"] is True
    assert audit["counterfactual_unconfirmed"] is False

    negative = {
        "is_vulnerable": False,
        "confidence": 0.9,
        "evidence_lines": [],
        "mechanism": "none",
        "counterfactual_fix": "none",
        "counterfactual_confirms": False,
    }
    parsed, audit = validate_evidence_output(json.dumps(negative), lines)
    assert parsed["is_vulnerable"] is False
    assert audit["evidence_line_count"] == 0

    unconfirmed = dict(positive, counterfactual_confirms=False)
    parsed, audit = validate_evidence_output(json.dumps(unconfirmed), lines)
    assert audit["counterfactual_unconfirmed"] is True

    _expect_error(dict(positive, extra=1), "keys")
    _expect_error(dict(positive, evidence_lines=[]), "semantic")
    _expect_error(dict(positive, evidence_lines=[9]), "range")
    _expect_error(dict(positive, evidence_lines=[3, 3]), "range")
    _expect_error(dict(positive, confidence=True), "types")
    _expect_error(dict(positive, mechanism="none"), "semantic")
    _expect_error(dict(negative, evidence_lines=[3]), "semantic")
    _expect_error(dict(negative, counterfactual_confirms=True), "semantic")
    try:
        validate_evidence_output("```json\n{}\n```", lines)
    except EvidenceSchemaError as exc:
        assert exc.family == "parse"
    else:
        raise AssertionError("markdown fence must be rejected")
    print("validation: PASS")


def check_mapping() -> None:
    from analyze import map_changed_lines

    sample = {
        "func_body": "int f(void) {\n  char buf[4];\n  strcpy(buf, src);\n}\n",
        "changed_lines": [
            [10, "  char buf[4];"],
            [11, "  strcpy(buf, src);"],
        ],
    }
    mapped, quality, mapped_count, total_count, offset = map_changed_lines(sample)
    assert mapped == {2, 3}, mapped
    assert quality == "full"
    assert mapped_count == 2 and total_count == 2
    assert offset == 9, offset
    empty, quality_empty, _, _, _ = map_changed_lines(
        {"func_body": "int g(void) { return 0; }", "changed_lines": []}
    )
    assert empty == set() and quality_empty == "none"
    print("mapping: PASS")


def check_stats() -> None:
    labels = [True, True, True, False, False]
    predictions = [True, False, True, False, False]
    scores = detection_scores(labels, predictions)
    assert scores["confusion"] == {"tp": 2, "fp": 0, "tn": 2, "fn": 1}
    assert abs(scores["recall"] - 2 / 3) < 1e-12
    assert abs(scores["positive_f1"] - 0.8) < 1e-12
    assert scores["macro_f1"] is not None

    m = mcnemar_exact(a_correct_b_wrong=2, a_wrong_b_correct=0, total=4)
    assert abs(m["p_value"] - 0.5) < 1e-12, m
    adjusted = holm_adjust([0.01, 0.04, 0.03, 0.02])
    assert all(abs(a - b) < 1e-12 for a, b in zip(adjusted, [0.04, 0.06, 0.06, 0.06]))
    print("stats: PASS")


def main() -> int:
    check_prompt()
    check_validation()
    check_mapping()
    check_stats()
    print("self-test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

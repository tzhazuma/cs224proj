#!/usr/bin/env python3
"""Local self-tests for pair_joint.  Makes no network calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.stats import mcnemar_exact, wilson_interval  # noqa: E402

from pair_joint.common import (  # noqa: E402
    ORDER_SALT,
    audit_dataset,
    audit_prompt,
    build_order_map,
    build_prompt,
    evaluate_output,
    load_pairs,
    numbered_lines,
    parse_output,
    reference_vuln_lines,
)

EXPECTED_TEST = "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d"


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_dataset() -> None:
    units, metadata, digest = load_pairs(ROOT / "splits" / "test_pairs_180.json")
    _assert(len(units) == 180, f"expected 180 pairs, got {len(units)}")
    _assert(digest == EXPECTED_TEST, f"unexpected test dataset digest {digest}")
    _assert(metadata.get("split", {}).get("role") == "test", "dataset is not the frozen test split")
    for unit in units:
        _assert(unit.vulnerable_label and not unit.fixed_label, f"{unit.pair_id}: bad labels")
        _assert(unit.vulnerable_body != unit.fixed_body, f"{unit.pair_id}: identical bodies")


def test_order_map() -> None:
    units, _metadata, _digest = load_pairs(ROOT / "splits" / "test_pairs_180.json")
    first = build_order_map(units)
    second = build_order_map(units)
    _assert(first == second, "order map is not deterministic")
    _assert(first["counts"] == {"A": 90, "B": 90}, f"order map is not 90/90: {first['counts']}")
    _assert(len(first["assignments"]) == 180, "order map missing pairs")
    for unit in units:
        assignment = first["assignments"][unit.pair_id]
        _assert({assignment["vulnerable_slot"], assignment["fixed_slot"]} == {"A", "B"}, "bad slots")
        _assert(len(assignment["digest"]) == 64, "order digest is not SHA-256 hex")
    _assert(first["salt"] == ORDER_SALT, "order salt changed")


def test_prompt_and_audit() -> None:
    units, _metadata, _digest = load_pairs(ROOT / "splits" / "test_pairs_180.json")
    order = build_order_map(units)
    residue = audit_dataset(units)
    _assert(residue["pairs"] == 180, "dataset audit count")
    for unit in units:
        assignment = order["assignments"][unit.pair_id]
        prompt = build_prompt(unit, assignment)
        audit = audit_prompt(unit, assignment, prompt)
        _assert(audit["wrapper_clean"], f"{unit.pair_id}: wrapper leak {audit['wrapper_hits']}")
        _assert(not audit["slot_leak"], f"{unit.pair_id}: slot leak in wrapper")
        text = prompt.text
        _assert("<BODY_A>" not in text and "<BODY_B>" not in text, "unrendered body placeholder")
        _assert(unit.pair_id not in text, f"{unit.pair_id}: pair_id leaked")
        _assert(unit.commit_id not in text, f"{unit.pair_id}: commit_id leaked")
        _assert("fixed_func_idx" not in text, f"{unit.pair_id}: fixed_func_idx leaked")
        _assert("changed_lines" not in text, f"{unit.pair_id}: changed_lines leaked")
        _assert("changed_statements" not in text, f"{unit.pair_id}: changed_statements leaked")
        _assert("is_vulnerable" not in text, f"{unit.pair_id}: is_vulnerable leaked")
        _assert("project_url" not in text, f"{unit.pair_id}: project_url leaked")
        _assert("commit_message" not in text, f"{unit.pair_id}: commit_message leaked")
        for cve in unit.cve_list:
            _assert(cve.lower() not in prompt.wrapper_text.lower(), f"{unit.pair_id}: CVE in wrapper")
        for cwe in unit.cwe_list:
            _assert(cwe.lower() not in prompt.wrapper_text.lower(), f"{unit.pair_id}: CWE in wrapper")
        rendered_a, lines_a = numbered_lines(
            unit.vulnerable_body if assignment["vulnerable_slot"] == "A" else unit.fixed_body
        )
        _assert(rendered_a in text, f"{unit.pair_id}: rendered body missing")
        _assert(prompt.metadata["version_line_counts"]["A"] == len(lines_a), "line count A")
        _, lines_b = numbered_lines(
            unit.fixed_body if assignment["vulnerable_slot"] == "A" else unit.vulnerable_body
        )
        _assert(prompt.metadata["version_line_counts"]["B"] == len(lines_b), "line count B")
        _assert(prompt.metadata["order_salt"] == ORDER_SALT, "prompt metadata salt")


def test_parser() -> None:
    raw = {
        "vulnerable_version": "a",
        "confidence": 0.8,
        "evidence": [{"version": "A", "line": 3, "code": "    if (x) {"}],
        "rationale": "bounds check missing",
    }
    parsed, validation = parse_output(json.dumps(raw))
    _assert(validation["json_parse_ok"], "valid JSON rejected")
    _assert(validation["decision_parsed"] == "A", "A not parsed")
    _assert(validation["decision_valid"], "A not valid")
    _assert(validation["schema_exact"], "schema should be exact")
    _assert(validation["confidence_valid"], "confidence should be valid")

    fenced, validation = parse_output("```json\n" + json.dumps(raw) + "\n```")
    _assert(fenced is not None and validation["decision_valid"], "fenced JSON rejected")

    both, validation = parse_output(
        json.dumps({"vulnerable_version": "both", "confidence": 0.5, "evidence": [], "rationale": "x"})
    )
    _assert(both is not None and both["vulnerable_version"] == "both", "both not parsed")
    _assert(not validation["decision_valid"], "both must not be a forced-choice valid decision")

    neither, validation = parse_output(
        json.dumps({"vulnerable_version": "neither", "confidence": 0.5, "evidence": [], "rationale": "x"})
    )
    _assert(neither is not None and neither["vulnerable_version"] == "neither", "neither not parsed")

    bad, validation = parse_output("not json")
    _assert(bad is None and validation["error_code"], "invalid JSON not rejected")

    extra, validation = parse_output(
        json.dumps({**raw, "cwe": "CWE-20"})
    )
    _assert(extra is not None and not validation["schema_exact"], "extra key not flagged")
    _assert(validation["decision_valid"], "extra key should not destroy the decision")


def test_evidence() -> None:
    units, _metadata, _digest = load_pairs(ROOT / "splits" / "test_pairs_180.json")
    order = build_order_map(units)
    unit = units[0]
    assignment = order["assignments"][unit.pair_id]
    body = unit.vulnerable_body
    rendered, lines = numbered_lines(body)
    _assert(rendered.startswith("   1 | "), "line numbering does not start at 1")
    parsed, validation = parse_output(
        json.dumps(
            {
                "vulnerable_version": assignment["vulnerable_slot"],
                "confidence": 0.9,
                "evidence": [
                    {"version": assignment["vulnerable_slot"], "line": 1, "code": lines[0]},
                ],
                "rationale": "test",
            }
        )
    )
    evaluation = evaluate_output(parsed, validation, unit, assignment)
    _assert(evaluation["evidence_compliant"], "valid evidence row rejected")
    _assert(evaluation["evidence_text_match_rate"] == 1.0, "exact text should match")
    _assert(evaluation["localization_scored"], "localization should be scorable")
    reference = reference_vuln_lines(unit.vulnerable_body, unit.fixed_body)
    _assert(reference, "reference diff is empty")

    parsed["evidence"] = [{"version": "A" if assignment["vulnerable_slot"] == "B" else "B", "line": 1, "code": lines[0]}]
    bad = evaluate_output(parsed, validation, unit, assignment)
    _assert(not bad["evidence_compliant"], "wrong-version evidence accepted")


def test_stats() -> None:
    result = mcnemar_exact(a_correct_b_wrong=10, a_wrong_b_correct=2, total=12)
    _assert(abs(result["p_value"] - 158 / 4096) < 1e-12, f"McNemar mismatch: {result['p_value']}")
    interval = wilson_interval(50, 100)
    _assert(interval is not None and interval["low"] < 0.5 < interval["high"], "Wilson interval")
    _assert(interval["low"] > 0.39 and interval["high"] < 0.61, "Wilson interval width")


def main() -> int:
    test_dataset()
    test_order_map()
    test_prompt_and_audit()
    test_parser()
    test_evidence()
    test_stats()
    print("pair_joint selftest: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

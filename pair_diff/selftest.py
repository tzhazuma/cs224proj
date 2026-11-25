#!/usr/bin/env python3
"""Offline self-test for pair_diff: maps, prompts, diffs, parsing, length.

Runs without network access and without any API key.  Every check reads the
frozen split and the published pair_joint run, so a green run also proves that
the forward assignment is the same one used by pair_joint / pair_debias and
that the reverse assignment is its exact complement.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.stats import mcnemar_exact, wilson_interval  # noqa: E402
from pair_diff.common import (  # noqa: E402
    CONDITIONS,
    PROMPT_VERSION,
    PairJointError,
    audit_condition_prompt,
    build_condition_order_map,
    build_prompt,
    changed_line_sets,
    condition_mode,
    condition_reverses,
    control_block,
    estimate_tokens,
    evaluate_changes,
    is_length_matched,
    length_features,
    load_condition_map,
    load_pairs,
    load_position_map,
    map_sha256,
    normalize_decision,
    score_output,
    semantic_choice,
    unified_diff,
)

DATASET = ROOT / "splits" / "test_pairs_180.json"
BASE_MAP = ROOT / "pair_joint" / "runs" / "test_deepseek_180" / "position_map.json"
PILOT_DATASET = ROOT / "splits" / "pilot_pairs_18.json"
PILOT_MAP = ROOT / "pair_joint" / "runs" / "pilot_deepseek_8" / "position_map.json"

CHECKS = 0


def check(condition: bool, message: str) -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(message)


def check_close(value: float, target: float, tolerance: float, message: str) -> None:
    check(abs(value - target) <= tolerance, f"{message}: {value!r} vs {target!r}")


def test_dataset_and_maps() -> tuple[list, dict, dict[str, dict]]:
    units, metadata, digest = load_pairs(DATASET)
    check(len(units) == 180, "expected 180 frozen test pairs")
    check(len(digest) == 64, "dataset digest is not sha256")
    check(metadata["pair_count"] == 180, "metadata pair_count mismatch")

    base = load_position_map(BASE_MAP)
    check(base["counts"] == {"A": 90, "B": 90}, f"base map is not 90/90: {base['counts']}")
    check(len(base["assignments"]) == 180, "base map must cover 180 pairs")

    maps: dict[str, dict] = {}
    for condition in CONDITIONS:
        derived = build_condition_order_map(base, condition, units)
        maps[condition] = derived
        check(derived["counts"]["A"] + derived["counts"]["B"] == 180, f"{condition}: coverage")
        check(derived["counts"] == {"A": 90, "B": 90}, f"{condition}: not 90/90")
        check(derived["sha256"] == map_sha256(derived), f"{condition}: hash mismatch")
        for unit in units:
            source = base["assignments"][unit.pair_id]
            target = derived["assignments"][unit.pair_id]
            if condition_reverses(condition):
                check(
                    target["vulnerable_slot"] != source["vulnerable_slot"],
                    f"{condition}: slot was not reversed for {unit.pair_id}",
                )
            else:
                check(
                    target["vulnerable_slot"] == source["vulnerable_slot"],
                    f"{condition}: forward slot changed for {unit.pair_id}",
                )
            check(
                {target["vulnerable_slot"], target["fixed_slot"]} == {"A", "B"},
                f"{condition}: invalid slots",
            )

    forward = maps["diff_fwd"]
    reverse = maps["diff_rev"]
    for unit in units:
        f = forward["assignments"][unit.pair_id]
        r = reverse["assignments"][unit.pair_id]
        check(f["vulnerable_slot"] != r["vulnerable_slot"], "diff_rev is not the exact complement")
        check(f["fixed_slot"] != r["fixed_slot"], "diff_rev fixed slot is not exchanged")

    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "position_map.json"
        path.write_text(json.dumps(maps["diff_rev"]), encoding="utf-8")
        loaded = load_condition_map(path, "diff_rev", units)
        check(loaded["sha256"] == maps["diff_rev"]["sha256"], "map round-trip changed the hash")
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["counts"]["A"] += 1
        path.write_text(json.dumps(tampered), encoding="utf-8")
        try:
            load_condition_map(path, "diff_rev", units)
        except PairJointError:
            pass
        else:
            raise AssertionError("tampered position map was accepted")

    pilot_units, _, _ = load_pairs(PILOT_DATASET)
    pilot = load_position_map(PILOT_MAP)
    selected = pilot_units[:8]
    derived = build_condition_order_map(pilot, "diff_fwd", selected)
    check(len(derived["assignments"]) == 8, "pilot map must cover 8 pairs")
    check(derived["counts"] == {"A": 4, "B": 4}, "pilot map must stay 4/4")
    return units, base, maps


def test_diffs_and_length(units: list, maps: dict[str, dict]) -> None:
    for condition in CONDITIONS:
        positions = maps[condition]
        max_delta = 0
        max_prompt_delta = 0
        for unit in units:
            assignment = positions["assignments"][unit.pair_id]
            prompt = build_prompt(unit, assignment, condition)
            audit = audit_condition_prompt(unit, assignment, prompt)
            check(audit["wrapper_clean"], f"{condition}/{unit.pair_id}: wrapper leak {audit['wrapper_hits']}")
            check(not audit["slot_leak"], f"{condition}/{unit.pair_id}: slot leak")
            check(audit["diff_direction_ok"], f"{condition}/{unit.pair_id}: diff direction")
            body_a = (
                unit.vulnerable_body
                if assignment["vulnerable_slot"] == "A"
                else unit.fixed_body
            )
            body_b = (
                unit.fixed_body
                if assignment["vulnerable_slot"] == "A"
                else unit.vulnerable_body
            )
            expected_diff = unified_diff(body_a, body_b)
            if condition_mode(condition) == "diff":
                check(expected_diff in prompt.text, f"{condition}/{unit.pair_id}: diff text missing")
                check("--- VERSION_A" in prompt.text and "+++ VERSION_B" in prompt.text, f"{condition}/{unit.pair_id}: diff labels")
                check("--- VERSION_B" not in prompt.text, f"{condition}/{unit.pair_id}: reverse diff label leaked")
            else:
                check("<CHANGE_NOTES>" in prompt.text, f"{condition}/{unit.pair_id}: control block missing")
                check(expected_diff not in prompt.text, f"{condition}/{unit.pair_id}: control contains the diff")
            delta = prompt.metadata.get("control_delta_tokens_est")
            if delta is not None:
                max_delta = max(max_delta, abs(int(delta)))
            # The diff and control prompts must be token-length matched.
            if condition == "ctrl_fwd":
                diff_prompt = build_prompt(
                    unit,
                    maps["diff_fwd"]["assignments"][unit.pair_id],
                    "diff_fwd",
                )
                max_prompt_delta = max(max_prompt_delta, abs(estimate_tokens(diff_prompt.text) - estimate_tokens(prompt.text)))
        if condition_mode(condition) == "ctrl":
            check(max_delta <= 4, f"{condition}: control token delta too large: {max_delta}")
    check(max_prompt_delta <= 4, f"diff/ctrl total prompt token delta too large: {max_prompt_delta}")

    # The two full versions themselves are byte-identical across conditions.
    unit = units[0]
    for condition in CONDITIONS:
        prompt = build_prompt(unit, maps[condition]["assignments"][unit.pair_id], condition)
        check(prompt.metadata["prompt_version"] == PROMPT_VERSION, "prompt version mismatch")
        check(prompt.metadata["version_line_counts"]["A"] > 0, "empty A body")
        check(prompt.metadata["version_line_counts"]["B"] > 0, "empty B body")
        check(prompt.metadata["diff_direction"] == "A_to_B", "diff direction metadata mismatch")

    # Determinism and exact slot rendering.
    unit = units[3]
    for condition in CONDITIONS:
        assignment = maps[condition]["assignments"][unit.pair_id]
        first = build_prompt(unit, assignment, condition)
        second = build_prompt(unit, assignment, condition)
        check(first.sha256() == second.sha256(), f"{condition}: prompt is not deterministic")
        body_a = unit.vulnerable_body if assignment["vulnerable_slot"] == "A" else unit.fixed_body
        check(body_a.splitlines()[0] in first.messages[1]["content"], f"{condition}: A body missing")

    # Length features and the shorter-side heuristic are independent of the prompt.
    shorter = 0
    for unit in units:
        features = length_features(unit)
        check(features["vulnerable_chars"] > 0, "empty vulnerable body")
        check(features["fixed_chars"] > 0, "empty fixed body")
        check(0.0 <= features["relative_char_difference"] <= 1.0, "bad relative length")
        shorter += int(features["vulnerable_chars"] < features["fixed_chars"])
    check(0 < shorter < len(units), "length direction is degenerate")
    check(is_length_matched(units[0], 1.0), "is_length_matched rejects an exact match")
    check(not is_length_matched(units[0], -0.1), "is_length_matched accepts a negative threshold")


def _synthetic(unit, assignment, decision: str = "A", change_lines: tuple[int, int] = (1, 1)) -> str:
    a_line, b_line = change_lines
    return json.dumps(
        {
            "semantic_changes": [
                {
                    "summary": "a real change",
                    "a_lines": [a_line],
                    "b_lines": [b_line],
                    "security_relevant": True,
                }
            ],
            "vulnerable_version": decision,
            "confidence": 0.75,
            "evidence": [
                {
                    "version": decision if decision in {"A", "B"} else "A",
                    "line": a_line,
                    "code": "x",
                }
            ],
            "rationale": "because",
        }
    )


def test_parsing(units: list, maps: dict[str, dict]) -> None:
    unit = units[0]
    assignment = maps["diff_fwd"]["assignments"][unit.pair_id]
    parsed, validation, evaluation = score_output(_synthetic(unit, assignment), unit, assignment, "diff_fwd")
    check(parsed is not None, "valid JSON did not parse")
    check(parsed["vulnerable_version"] in {"A", "B", "both", "neither"}, "decision not normalised")
    check(validation["json_parse_ok"], "json_parse_ok false")
    check(validation["schema_exact"], "schema_exact false")
    check(validation["changes_first"], "changes_first false")
    check(validation["changes_all_valid"], "changes_all_valid false")
    check(evaluation["changes"]["changes_count"] == 1, "change count wrong")
    check(evaluation["changes"]["cited_lines"] == 2, "cited line count wrong")

    fenced = "```json\n" + _synthetic(unit, assignment) + "\n```"
    parsed_f, validation_f, _ = score_output(fenced, unit, assignment, "diff_fwd")
    check(parsed_f is not None and validation_f["json_parse_ok"], "fenced JSON did not parse")

    reordered = json.loads(_synthetic(unit, assignment))
    reordered = {
        "vulnerable_version": reordered["vulnerable_version"],
        "semantic_changes": reordered["semantic_changes"],
        "confidence": reordered["confidence"],
        "evidence": reordered["evidence"],
        "rationale": reordered["rationale"],
    }
    parsed_r, validation_r, _ = score_output(json.dumps(reordered), unit, assignment, "diff_fwd")
    check(parsed_r is not None, "reordered JSON did not parse")
    check(not validation_r["changes_first"], "reordered JSON was accepted as changes_first")
    check(not validation_r["changes_before_verdict_raw"], "raw order check is wrong")

    missing = json.loads(_synthetic(unit, assignment))
    del missing["semantic_changes"]
    parsed_m, validation_m, _ = score_output(json.dumps(missing), unit, assignment, "diff_fwd")
    check(parsed_m is not None, "missing semantic_changes lost the verdict")
    check(validation_m["error_code"] == "missing_keys", "missing key error code wrong")
    check(not validation_m["schema_exact"], "missing key marked schema exact")

    both = json.loads(_synthetic(unit, assignment))
    both["vulnerable_version"] = "both"
    parsed_b, validation_b, _ = score_output(json.dumps(both), unit, assignment, "diff_fwd")
    check(parsed_b is not None and parsed_b["vulnerable_version"] == "both", "both not parsed")

    neither = json.loads(_synthetic(unit, assignment))
    neither["vulnerable_version"] = "neither"
    neither["evidence"] = []
    parsed_n, validation_n, _ = score_output(json.dumps(neither), unit, assignment, "diff_fwd")
    check(parsed_n is not None and parsed_n["vulnerable_version"] == "neither", "neither not parsed")

    bad = json.loads(_synthetic(unit, assignment))
    bad["vulnerable_version"] = "C"
    parsed_x, validation_x, _ = score_output(json.dumps(bad), unit, assignment, "diff_fwd")
    check(parsed_x["vulnerable_version"] is None, "invalid decision was accepted")
    check(not validation_x["decision_valid"], "invalid decision marked valid")

    check(normalize_decision("BOTH") == "both", "normalize BOTH")
    check(normalize_decision("none") == "neither", "normalize none")
    check(normalize_decision("A") == "A", "normalize A")
    check(normalize_decision("C") is None, "normalize C")

    # Grounding is checked against the actual diff hunks.
    body_a = unit.vulnerable_body if assignment["vulnerable_slot"] == "A" else unit.fixed_body
    body_b = unit.fixed_body if assignment["vulnerable_slot"] == "A" else unit.vulnerable_body
    changed_a, changed_b = changed_line_sets(body_a, body_b)
    check(bool(changed_a or changed_b), "no changed lines in a pair")
    grounded = evaluate_changes(
        {
            "raw_keys": ["semantic_changes"],
            "semantic_changes": [
                {
                    "summary": "real change",
                    "a_lines": [changed_a[0]] if changed_a else [],
                    "b_lines": [changed_b[0]] if changed_b else [],
                    "security_relevant": True,
                    "valid": True,
                }
            ],
        },
        unit,
        assignment,
    )
    check(grounded["grounded_items"] == 1, "grounded change not detected")
    check(grounded["cited_line_precision"] == 1.0, "grounded precision wrong")

    hallucinated = evaluate_changes(
        {
            "raw_keys": ["semantic_changes"],
            "semantic_changes": [
                {
                    "summary": "not a change",
                    "a_lines": [9999],
                    "b_lines": [9999],
                    "security_relevant": False,
                    "valid": True,
                }
            ],
        },
        unit,
        assignment,
    )
    check(hallucinated["out_of_range_lines"] == 2, "out-of-range lines not counted")
    check(hallucinated["grounded_items"] == 0, "out-of-range line counted as grounded")

    check(semantic_choice(assignment["vulnerable_slot"], assignment) == "vulnerable", "semantic vulnerable")
    check(semantic_choice(assignment["fixed_slot"], assignment) == "fixed", "semantic fixed")
    check(semantic_choice("both", assignment) == "both", "semantic both")
    check(semantic_choice("neither", assignment) == "neither", "semantic neither")


def test_statistics() -> None:
    wilson = wilson_interval(50, 100)
    check(wilson is not None and 0.40 < wilson["low"] < 0.50 < wilson["high"] < 0.60, "wilson interval")
    m = mcnemar_exact(a_correct_b_wrong=10, a_wrong_b_correct=0, total=100)
    check(float(m["p_value"]) < 0.01, "mcnemar should be significant")
    m2 = mcnemar_exact(a_correct_b_wrong=5, a_wrong_b_correct=5, total=100)
    check_close(float(m2["p_value"]), 1.0, 1e-12, "mcnemar null")


def main() -> int:
    units, base, maps = test_dataset_and_maps()
    test_diffs_and_length(units, maps)
    test_parsing(units, maps)
    test_statistics()
    print(f"all checks passed ({CHECKS} assertions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

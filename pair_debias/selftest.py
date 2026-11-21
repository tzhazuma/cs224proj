#!/usr/bin/env python3
"""Offline self-test for pair_debias: maps, prompts, parsing, leaks, statistics.

Runs without network access and without any API key.  Every check reads the
frozen split and the published pair_joint run, so a green run also proves that
the forward condition is byte-identical to the experiment it is paired with.
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
from pair_debias.common import (  # noqa: E402
    CONDITIONS,
    FORCED_PROMPT_VERSION,
    OPEN_PROMPT_VERSION,
    PairJointError,
    build_condition_order_map,
    build_condition_prompt,
    condition_is_open,
    condition_reverses,
    is_length_matched,
    length_features,
    load_condition_map,
    load_pairs,
    load_position_map,
    map_sha256,
    normalize_decision,
    score_output,
    semantic_choice,
)

DATASET = ROOT / "splits" / "test_pairs_180.json"
BASE_MAP = ROOT / "pair_joint" / "runs" / "test_deepseek_180" / "position_map.json"
JOINT_REQUESTS = ROOT / "pair_joint" / "runs" / "test_deepseek_180" / "requests.jsonl"
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


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_dataset_and_maps() -> tuple[list, dict, dict[str, dict]]:
    units, metadata, digest = load_pairs(DATASET)
    check(len(units) == 180, "expected 180 frozen test pairs")
    check(metadata["pair_count"] == 180, "metadata pair_count mismatch")
    check(len(digest) == 64, "dataset digest is not sha256")

    base = load_position_map(BASE_MAP)
    check(base["counts"] == {"A": 90, "B": 90}, f"base map is not 90/90: {base['counts']}")
    check(len(base["assignments"]) == 180, "base map must cover 180 pairs")

    maps: dict[str, dict] = {}
    for condition in ("forced_rev", "open_fwd", "open_rev"):
        derived = build_condition_order_map(base, condition, units)
        maps[condition] = derived
        check(derived["counts"]["A"] + derived["counts"]["B"] == 180, f"{condition}: coverage")
        check(abs(derived["counts"]["A"] - derived["counts"]["B"]) <= 1, f"{condition}: balance")
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

    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "position_map.json"
        path.write_text(json.dumps(maps["open_rev"]), encoding="utf-8")
        loaded = load_condition_map(path, "open_rev", units)
        check(loaded["sha256"] == maps["open_rev"]["sha256"], "map round-trip changed the hash")
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["counts"]["A"] += 1
        path.write_text(json.dumps(tampered), encoding="utf-8")
        try:
            load_condition_map(path, "open_rev", units)
        except PairJointError:
            pass
        else:
            raise AssertionError("tampered position map was accepted")

    pilot_units, _, _ = load_pairs(PILOT_DATASET)
    pilot = load_position_map(PILOT_MAP)
    pilot_selected = pilot_units[:8]
    derived = build_condition_order_map(pilot, "forced_rev", pilot_selected)
    check(len(derived["assignments"]) == 8, "pilot map must cover 8 pairs")
    check(derived["counts"] == {"A": 4, "B": 4}, "pilot reverse map must stay 4/4")
    return units, base, maps


def test_forced_prompt_identity(units, base, maps) -> None:
    records = _read_jsonl(JOINT_REQUESTS)
    by_pair = {record["pair_id"]: record for record in records}
    for unit in units:
        assignment = base["assignments"][unit.pair_id]
        prompt = build_condition_prompt(unit, assignment, "forced_fwd")
        expected = by_pair[unit.pair_id]["messages"]
        check(
            [dict(message) for message in prompt.messages] == expected,
            f"forced_fwd prompt differs from the published pair_joint request for {unit.pair_id}",
        )
        check(prompt.metadata["prompt_version"] == FORCED_PROMPT_VERSION, "forced prompt version")
        check("exactly one revision contains" in prompt.wrapper_text, "forced prompt lost its premise")

        reversed_assignment = maps["forced_rev"]["assignments"][unit.pair_id]
        reversed_prompt = build_condition_prompt(unit, reversed_assignment, "forced_rev")
        check(
            reversed_prompt.wrapper_text == prompt.wrapper_text,
            "reversing the order changed the forced wrapper",
        )
        forward_hashes = prompt.metadata["version_sha256"]
        reverse_hashes = reversed_prompt.metadata["version_sha256"]
        check(
            forward_hashes["A"] == reverse_hashes["B"] and forward_hashes["B"] == reverse_hashes["A"],
            "reversed prompt did not exchange the two bodies",
        )


def test_open_prompt(units, base) -> None:
    unit = units[0]
    assignment = base["assignments"][unit.pair_id]
    prompt = build_condition_prompt(unit, assignment, "open_fwd")
    check(prompt.metadata["prompt_version"] == OPEN_PROMPT_VERSION, "open prompt version")
    check("exactly one revision" not in prompt.wrapper_text.lower(), "open wrapper still claims exactly one")
    check("both" in prompt.wrapper_text and "neither" in prompt.wrapper_text, "open wrapper lacks both/neither")
    check("VERSION_A" in prompt.text and "VERSION_B" in prompt.text, "open prompt lacks version tags")
    check(condition_is_open("open_fwd") and condition_is_open("open_rev"), "open condition detection")
    check(not condition_is_open("forced_rev"), "forced condition misdetected")


def _evidence(unit, slot: str, line: int = 1) -> dict:
    body = unit.vulnerable_body if slot == "A" else unit.fixed_body
    text = body.splitlines()[line - 1]
    return {"version": slot, "line": line, "code": text}


def test_open_parsing(units, base) -> None:
    unit = units[0]
    assignment = base["assignments"][unit.pair_id]
    vulnerable_slot = assignment["vulnerable_slot"]
    fixed_slot = assignment["fixed_slot"]

    def parse(payload: dict):
        return score_output(json.dumps(payload), unit, assignment, "open_fwd")

    base_payload = {
        "confidence": 0.8,
        "evidence": [_evidence(unit, vulnerable_slot)],
        "rationale": "x",
    }
    parsed, validation, evidence = parse({**base_payload, "vulnerable_version": vulnerable_slot})
    check(parsed and parsed["vulnerable_version"] == vulnerable_slot, "open A/B decision not parsed")
    check(validation["decision_valid"], "open A/B decision marked invalid")
    check(evidence["evidence_policy_ok"], "open A/B evidence policy failed")
    check(evidence["evidence_text_match_count"] == 1, "open evidence text did not match")

    parsed, validation, evidence = parse({**base_payload, "vulnerable_version": "both"})
    check(parsed and parsed["vulnerable_version"] == "both", "open both decision not parsed")
    check(evidence["evidence_policy_ok"], "both with one item should pass the minimum policy")
    both_evidence = [_evidence(unit, "A"), _evidence(unit, "B")]
    parsed, validation, evidence = parse(
        {**base_payload, "vulnerable_version": "both", "evidence": both_evidence}
    )
    check(evidence["evidence_policy_ok"], "both with A and B evidence should pass")

    parsed, validation, evidence = parse(
        {**base_payload, "vulnerable_version": "neither", "evidence": []}
    )
    check(parsed and parsed["vulnerable_version"] == "neither", "neither decision not parsed")
    check(validation["decision_valid"], "neither marked invalid")
    check(evidence["evidence_policy_ok"], "neither with empty evidence should pass")

    parsed, validation, evidence = parse(
        {**base_payload, "vulnerable_version": fixed_slot, "evidence": [_evidence(unit, vulnerable_slot)]}
    )
    check(parsed and parsed["vulnerable_version"] == fixed_slot, "open fixed-slot decision not parsed")
    check(not evidence["evidence_policy_ok"], "A/B decision citing the other version should fail policy")

    parsed, validation, evidence = parse({**base_payload, "vulnerable_version": "maybe"})
    check(parsed is not None, "bad decision should still parse JSON")
    check(not validation["decision_valid"], "bad decision marked valid")

    parsed, validation, evidence = parse(
        {**base_payload, "vulnerable_version": "both", "evidence": [{"version": "A", "line": 999, "code": "x"}]}
    )
    check(not evidence["evidence_policy_ok"], "out-of-range line should fail policy")

    check(normalize_decision("Both") == "both", "both normalization")
    check(normalize_decision("NEITHER") == "neither", "neither normalization")
    check(normalize_decision("C") is None, "bad normalization")


def test_forced_parsing(units, base) -> None:
    unit = units[0]
    assignment = base["assignments"][unit.pair_id]
    vulnerable_slot = assignment["vulnerable_slot"]
    fixed_slot = assignment["fixed_slot"]
    payload = {
        "vulnerable_version": vulnerable_slot,
        "confidence": 0.7,
        "evidence": [_evidence(unit, vulnerable_slot)],
        "rationale": "x",
    }
    parsed, validation, evidence = score_output(json.dumps(payload), unit, assignment, "forced_rev")
    check(parsed and parsed["vulnerable_version"] == vulnerable_slot, "forced decision not parsed")
    check(evidence["compliant"], "compliant forced evidence rejected")
    payload["vulnerable_version"] = "both"
    parsed, validation, evidence = score_output(json.dumps(payload), unit, assignment, "forced_rev")
    check(parsed and parsed["vulnerable_version"] == "both", "forced both output not parsed")
    check(not evidence["compliant"], "forced both output must violate the instruction")


def test_semantics_and_length(units, base) -> None:
    unit = units[0]
    assignment = base["assignments"][unit.pair_id]
    check(semantic_choice(assignment["vulnerable_slot"], assignment) == "vulnerable", "semantic vulnerable")
    check(semantic_choice(assignment["fixed_slot"], assignment) == "fixed", "semantic fixed")
    check(semantic_choice("both", assignment) == "both", "semantic both")
    check(semantic_choice("neither", assignment) == "neither", "semantic neither")

    strata = {"vulnerable_shorter": 0, "vulnerable_longer": 0, "tie": 0}
    matched = {0.05: 0, 0.10: 0, 0.20: 0}
    line_equal = 0
    for item in units:
        features = length_features(item)
        strata[features["stratum"]] += 1
        for threshold in matched:
            matched[threshold] += int(is_length_matched(item, threshold))
        line_equal += int(features["line_difference"] == 0)
    check(strata == {"vulnerable_shorter": 130, "vulnerable_longer": 44, "tie": 6}, f"length strata: {strata}")
    check(matched == {0.05: 107, 0.10: 144, 0.20: 165}, f"length matched counts: {matched}")
    check(line_equal == 60, f"equal line count: {line_equal}")


def test_statistics() -> None:
    interval = wilson_interval(50, 100)
    check(interval is not None, "wilson interval missing")
    check_close(interval["estimate"], 0.5, 1e-12, "wilson estimate")
    check(0.39 < interval["low"] < 0.41, f"wilson low: {interval['low']}")
    check(0.59 < interval["high"] < 0.61, f"wilson high: {interval['high']}")

    left = mcnemar_exact(a_correct_b_wrong=10, a_wrong_b_correct=2, total=100)
    right = mcnemar_exact(a_correct_b_wrong=2, a_wrong_b_correct=10, total=100)
    check_close(left["p_value"], right["p_value"], 1e-12, "mcnemar symmetry")
    check(left["p_value"] < 0.05, "mcnemar should reject at 10 vs 2")
    check(left["discordant"] == 12, "mcnemar discordant count")


def test_leak_audits(units, maps) -> None:
    sampled = [units[0], units[60], units[120], units[179]]
    for condition in ("forced_rev", "open_fwd", "open_rev"):
        for unit in sampled:
            assignment = maps[condition]["assignments"][unit.pair_id]
            from pair_debias.common import audit_condition_prompt

            prompt = build_condition_prompt(unit, assignment, condition)
            audit = audit_condition_prompt(unit, assignment, prompt)
            check(audit["wrapper_clean"], f"{condition}/{unit.pair_id}: wrapper leak {audit['wrapper_hits']}")
            check(not audit["slot_leak"], f"{condition}/{unit.pair_id}: slot leak")
            check(unit.pair_id not in prompt.wrapper_text, f"{condition}/{unit.pair_id}: pair id in wrapper")
            check(unit.commit_id not in prompt.wrapper_text, f"{condition}/{unit.pair_id}: commit id in wrapper")
            check(unit.func_name not in prompt.wrapper_text, f"{condition}/{unit.pair_id}: function name in wrapper")


def main() -> int:
    units, base, maps = test_dataset_and_maps()
    test_forced_prompt_identity(units, base, maps)
    test_open_prompt(units, base)
    test_open_parsing(units, base)
    test_forced_parsing(units, base)
    test_semantics_and_length(units, base)
    test_statistics()
    test_leak_audits(units, maps)
    print(f"all checks passed ({CHECKS} assertions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

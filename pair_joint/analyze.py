#!/usr/bin/env python3
"""Analyse pair-joint runs and compare them with separate-side baselines.

All statistics are standard library only (Wilson intervals, exact McNemar,
Fisher exact test, percentile cluster bootstrap).  The primary bootstrap
clusters by project, as the frozen evaluation protocol specifies; a
pair-level bootstrap is reported as a sensitivity analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.stats import (  # noqa: E402
    cluster_bootstrap,
    mcnemar_exact,
    percentile,
    wilson_interval,
)

from .common import PairJointError, PairUnit, load_pairs, order_map_sha256  # noqa: E402

BASELINES = {
    "deepseek-v4.1-flash": (
        ("direct", "runner/runs/test_v1_direct_pairs"),
        ("context", "runner/runs/test_v1_context_pairs"),
    ),
    "mimo-v2.6-flash": (
        ("direct", "runner/runs/test_v1_mimo_direct_pairs"),
        ("context", "runner/runs/test_v1_mimo_context_pairs"),
    ),
}
CATEGORY_KEYS = ("correct", "swapped", "both_vulnerable", "both_safe", "invalid")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _ratio(numerator: int | float, denominator: int | float) -> float | None:
    if denominator == 0:
        return None
    return float(numerator) / float(denominator)


def _round(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(float(value), digits)


def _wilson(successes: int, total: int) -> dict[str, Any] | None:
    if total == 0:
        return None
    result = wilson_interval(successes, total)
    if result is None:
        return None
    return {
        "estimate": _round(result["estimate"]),
        "low": _round(result["low"]),
        "high": _round(result["high"]),
        "successes": successes,
        "total": total,
        "method": "wilson_95",
    }


def _binomial_two_sided(k: int, n: int, p: float = 0.5) -> float | None:
    if n == 0:
        return None
    if k < 0 or k > n:
        raise ValueError("k must be in [0, n]")
    observed = math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))
    total = 0.0
    for i in range(n + 1):
        prob = math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
        if prob <= observed + 1e-15:
            total += prob
    return min(1.0, total)


def _fisher_two_sided(a: int, b: int, c: int, d: int) -> float | None:
    """Exact two-sided Fisher test for [[a, b], [c, d]]."""
    row1 = a + b
    row2 = c + d
    col1 = a + c
    n = row1 + row2
    if n == 0:
        return None
    low = max(0, col1 - row2)
    high = min(row1, col1)
    denominator = math.comb(n, col1)

    def probability(x: int) -> float:
        return math.comb(row1, x) * math.comb(row2, col1 - x) / denominator

    observed = probability(a)
    total = 0.0
    for x in range(low, high + 1):
        value = probability(x)
        if value <= observed + 1e-15:
            total += value
    return min(1.0, total)


def _category(
    record: dict[str, Any],
    assignment: dict[str, Any],
) -> tuple[str, str | None]:
    if record.get("status") != "ok":
        return "invalid", record.get("status")
    parsed = record.get("parsed")
    if not isinstance(parsed, dict):
        return "invalid", "no_parsed"
    decision = parsed.get("vulnerable_version")
    if decision == assignment["vulnerable_slot"]:
        return "correct", decision
    if decision == assignment["fixed_slot"]:
        return "swapped", decision
    if decision == "both":
        return "both_vulnerable", decision
    if decision == "neither":
        return "both_safe", decision
    return "invalid", "bad_decision"


def _joint_records(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    manifest = _read_json(run_dir / "manifest.json")
    results = _read_jsonl(run_dir / "results.jsonl")
    position = _read_json(run_dir / "position_map.json")
    expected = int(manifest.get("counts", {}).get("planned_requests") or 0)
    if expected and len(results) != expected:
        raise PairJointError(
            f"{run_dir}: results has {len(results)} records but manifest planned {expected}"
        )
    if position.get("sha256") != manifest.get("order", {}).get("position_map_sha256"):
        raise PairJointError(f"{run_dir}: position map hash does not match the manifest")
    computed = order_map_sha256({key: value for key, value in position.items() if key != "sha256"})
    if computed != position.get("sha256"):
        raise PairJointError(f"{run_dir}: position map content hash mismatch")
    return manifest, results, position


def _baseline_records(run_dir: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest = _read_json(run_dir / "manifest.json")
    results = _read_jsonl(run_dir / "results.jsonl")
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for record in results:
        if record.get("task") != "detection":
            continue
        pair_id = record.get("pair_id")
        side = record.get("side")
        if pair_id and side:
            by_key[(str(pair_id), str(side))] = record
    summary: dict[str, Any] = {
        "run_id": manifest.get("run_id"),
        "run_dir": str(run_dir.relative_to(ROOT)) if run_dir.is_relative_to(ROOT) else str(run_dir),
        "model": (manifest.get("api") or {}).get("model"),
        "strategy": manifest.get("strategy") or (manifest.get("config") or {}).get("strategy"),
        "task": manifest.get("task") or (manifest.get("config") or {}).get("task"),
        "dataset_sha256": (manifest.get("dataset") or {}).get("sha256"),
        "detection_records": len([record for record in results if record.get("task") == "detection"]),
        "statuses": dict(Counter(str(record.get("status")) for record in results if record.get("task") == "detection")),
    }
    return summary, by_key


def _per_pair_baseline(
    units: list[PairUnit],
    by_key: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "correct": {},
        "valid": {},
        "vuln_pred": {},
        "fixed_pred": {},
        "categories": Counter(),
        "missing": [],
    }
    for unit in units:
        vulnerable = by_key.get((unit.pair_id, "vulnerable"))
        fixed = by_key.get((unit.pair_id, "fixed"))
        valid = (
            vulnerable is not None
            and fixed is not None
            and vulnerable.get("status") == "ok"
            and fixed.get("status") == "ok"
            and isinstance(vulnerable.get("parsed"), dict)
            and isinstance(fixed.get("parsed"), dict)
            and isinstance(vulnerable["parsed"].get("is_vulnerable"), bool)
            and isinstance(fixed["parsed"].get("is_vulnerable"), bool)
        )
        if not valid:
            result["missing"].append(unit.pair_id)
            result["correct"][unit.pair_id] = False
            result["valid"][unit.pair_id] = False
            result["vuln_pred"][unit.pair_id] = None
            result["fixed_pred"][unit.pair_id] = None
            result["categories"]["invalid"] += 1
            continue
        vuln_pred = bool(vulnerable["parsed"]["is_vulnerable"])
        fixed_pred = bool(fixed["parsed"]["is_vulnerable"])
        result["valid"][unit.pair_id] = True
        result["vuln_pred"][unit.pair_id] = vuln_pred
        result["fixed_pred"][unit.pair_id] = fixed_pred
        correct = vuln_pred and not fixed_pred
        result["correct"][unit.pair_id] = correct
        if correct:
            result["categories"]["correct"] += 1
        elif vuln_pred and fixed_pred:
            result["categories"]["both_vulnerable"] += 1
        elif not vuln_pred and not fixed_pred:
            result["categories"]["both_safe"] += 1
        else:
            result["categories"]["swapped"] += 1
    return result


def _comparison(
    units: list[PairUnit],
    correct_a: dict[str, bool],
    correct_b: dict[str, bool],
    valid_a: dict[str, bool],
    valid_b: dict[str, bool],
    *,
    label_a: str,
    label_b: str,
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    n = len(units)
    both = sum(1 for unit in units if correct_a[unit.pair_id] and correct_b[unit.pair_id])
    a_only = sum(1 for unit in units if correct_a[unit.pair_id] and not correct_b[unit.pair_id])
    b_only = sum(1 for unit in units if not correct_a[unit.pair_id] and correct_b[unit.pair_id])
    neither = n - both - a_only - b_only
    mcnemar = mcnemar_exact(a_correct_b_wrong=a_only, a_wrong_b_correct=b_only, total=n)

    a_correct = sum(1 for unit in units if correct_a[unit.pair_id])
    b_correct = sum(1 for unit in units if correct_b[unit.pair_id])

    intersection = [
        unit for unit in units if valid_a.get(unit.pair_id) and valid_b.get(unit.pair_id)
    ]
    inter_a = sum(1 for unit in intersection if correct_a[unit.pair_id])
    inter_b = sum(1 for unit in intersection if correct_b[unit.pair_id])
    inter_a_only = sum(
        1 for unit in intersection if correct_a[unit.pair_id] and not correct_b[unit.pair_id]
    )
    inter_b_only = sum(
        1 for unit in intersection if not correct_a[unit.pair_id] and correct_b[unit.pair_id]
    )
    inter_mcnemar = (
        mcnemar_exact(
            a_correct_b_wrong=inter_a_only,
            a_wrong_b_correct=inter_b_only,
            total=len(intersection),
        )
        if intersection
        else None
    )

    project_ids = [unit.project for unit in units]
    pair_ids = [unit.pair_id for unit in units]

    def da_a(indices: Sequence[int]) -> float | None:
        return _ratio(sum(1 for i in indices if correct_a[units[i].pair_id]), len(indices))

    def da_b(indices: Sequence[int]) -> float | None:
        return _ratio(sum(1 for i in indices if correct_b[units[i].pair_id]), len(indices))

    def diff(indices: Sequence[int]) -> float | None:
        value_a = da_a(indices)
        value_b = da_b(indices)
        if value_a is None or value_b is None:
            return None
        return value_a - value_b

    project_bootstrap = cluster_bootstrap(
        project_ids,
        {"da_a": da_a, "da_b": da_b, "difference": diff},
        resamples=resamples,
        seed=seed,
    )
    pair_bootstrap = cluster_bootstrap(
        pair_ids,
        {"da_a": da_a, "da_b": da_b, "difference": diff},
        resamples=resamples,
        seed=seed,
    )
    return {
        "label_a": label_a,
        "label_b": label_b,
        "n_pairs": n,
        "accuracy_a_all": _round(_ratio(a_correct, n)),
        "accuracy_b_all": _round(_ratio(b_correct, n)),
        "accuracy_a_valid_intersection": _round(_ratio(inter_a, len(intersection))),
        "accuracy_b_valid_intersection": _round(_ratio(inter_b, len(intersection))),
        "wilson_a_all": _wilson(a_correct, n),
        "wilson_b_all": _wilson(b_correct, n),
        "table": {
            "both_correct": both,
            "a_correct_b_wrong": a_only,
            "a_wrong_b_correct": b_only,
            "both_wrong": neither,
        },
        "mcnemar_all": mcnemar,
        "intersection": {
            "n_pairs": len(intersection),
            "a_correct": inter_a,
            "b_correct": inter_b,
            "a_only": inter_a_only,
            "b_only": inter_b_only,
            "mcnemar": inter_mcnemar,
        },
        "bootstrap": {
            "primary_project_cluster": project_bootstrap,
            "sensitivity_pair_cluster": pair_bootstrap,
            "settings": {"resamples": resamples, "seed": seed, "confidence": 0.95},
        },
    }


def _pick_shorter_slot(unit: PairUnit, assignment: dict[str, Any], key) -> str:
    body_a = unit.vulnerable_body if assignment["vulnerable_slot"] == "A" else unit.fixed_body
    body_b = unit.fixed_body if assignment["vulnerable_slot"] == "A" else unit.vulnerable_body
    size_a, size_b = key(body_a), key(body_b)
    if size_a < size_b:
        return "A"
    if size_b < size_a:
        return "B"
    return "A"  # fixed tie rule, chosen before looking at outcomes


def _length_confound(
    units: list[PairUnit],
    by_pair: dict[str, dict[str, Any]],
    assignments: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    strata: dict[str, dict[str, int]] = {
        "vulnerable_shorter": {"n": 0, "correct": 0},
        "vulnerable_longer": {"n": 0, "correct": 0},
        "tie": {"n": 0, "correct": 0},
    }
    heuristic_chars = 0
    heuristic_lines = 0
    joint_heuristic_b = 0
    joint_heuristic_c = 0
    for unit in units:
        assignment = assignments[unit.pair_id]
        category, _ = _category(by_pair[unit.pair_id], assignment)
        correct = category == "correct"
        v_len = len(unit.vulnerable_body)
        f_len = len(unit.fixed_body)
        stratum = "vulnerable_shorter" if v_len < f_len else ("vulnerable_longer" if v_len > f_len else "tie")
        strata[stratum]["n"] += 1
        strata[stratum]["correct"] += int(correct)

        pick_chars = _pick_shorter_slot(unit, assignment, len)
        pick_lines = _pick_shorter_slot(unit, assignment, lambda body: len(body.splitlines()))
        h_chars = pick_chars == assignment["vulnerable_slot"]
        h_lines = pick_lines == assignment["vulnerable_slot"]
        heuristic_chars += int(h_chars)
        heuristic_lines += int(h_lines)
        if correct and not h_chars:
            joint_heuristic_b += 1
        elif h_chars and not correct:
            joint_heuristic_c += 1

    n = len(units)
    for bucket in strata.values():
        bucket["accuracy"] = _round(_ratio(bucket["correct"], bucket["n"]))
    return {
        "definition": (
            "Post-hoc diagnostic, not a pre-registered baseline. Compares character length of the "
            "vulnerable and fixed bodies; 'pick shorter' chooses the shorter slot and A on ties."
        ),
        "strata": strata,
        "shorter_body_heuristic": {
            "characters_tie_A": _round(_ratio(heuristic_chars, n)),
            "characters_correct": heuristic_chars,
            "lines_tie_A": _round(_ratio(heuristic_lines, n)),
            "lines_correct": heuristic_lines,
            "n": n,
        },
        "mcnemar_joint_vs_shorter_characters": mcnemar_exact(
            a_correct_b_wrong=joint_heuristic_b,
            a_wrong_b_correct=joint_heuristic_c,
            total=n,
        ),
    }


def _joint_metrics(
    units: list[PairUnit],
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    position: dict[str, Any],
) -> dict[str, Any]:
    by_pair = {str(record.get("pair_id")): record for record in results}
    assignments = position.get("assignments") or {}
    missing = [unit.pair_id for unit in units if unit.pair_id not in by_pair]
    if missing:
        raise PairJointError(f"run is missing {len(missing)} pairs, e.g. {missing[0]}")
    missing_assignments = [unit.pair_id for unit in units if unit.pair_id not in assignments]
    if missing_assignments:
        raise PairJointError(f"position map is missing {len(missing_assignments)} pairs")

    n = len(units)
    categories: dict[str, int] = {key: 0 for key in CATEGORY_KEYS}
    category_by_slot: dict[str, Counter[str]] = {"A": Counter(), "B": Counter()}
    invalid_reasons: Counter[str] = Counter()
    evidence_present = 0
    evidence_compliant = 0
    schema_exact = 0
    compliant_correct = 0
    localization_scored = 0
    localization_hit = 0
    joint_localization = 0
    evidence_items_total = 0
    evidence_text_matches = 0
    confidence_values: list[float] = []
    confidence_by_category: dict[str, list[float]] = {}
    unit_rows: list[dict[str, Any]] = []

    for unit in units:
        record = by_pair[unit.pair_id]
        assignment = assignments[unit.pair_id]
        category, decision = _category(record, assignment)
        categories[category] += 1
        category_by_slot[assignment["vulnerable_slot"]][category] += 1
        validation = record.get("validation") or {}
        if category == "invalid":
            invalid_reasons[str(validation.get("error_code") or record.get("status"))] += 1
        else:
            if validation.get("schema_exact"):
                schema_exact += 1
            evidence = validation.get("evidence") or {}
            if evidence.get("evidence_compliant"):
                evidence_compliant += 1
            if validation.get("compliant"):
                compliant_correct += 1 if category == "correct" else 0
            parsed = record.get("parsed") or {}
            items = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
            if items:
                evidence_present += 1
            evidence_items_total += len(evidence.get("evidence_items") or [])
            evidence_text_matches += int(evidence.get("evidence_text_match_count") or 0)
            if isinstance(parsed.get("confidence"), (int, float)) and not isinstance(parsed.get("confidence"), bool):
                confidence_values.append(float(parsed["confidence"]))
                confidence_by_category.setdefault(category, []).append(float(parsed["confidence"]))
            if category == "correct":
                if evidence.get("localization_scored"):
                    localization_scored += 1
                    if evidence.get("localization_hit"):
                        localization_hit += 1
                        joint_localization += 1
        unit_rows.append(
            {
                "pair_id": unit.pair_id,
                "project": unit.project,
                "vulnerable_slot": assignment["vulnerable_slot"],
                "decision": decision,
                "category": category,
                "status": record.get("status"),
            }
        )

    parsed_count = n - categories["invalid"]
    forced_count = categories["correct"] + categories["swapped"]
    correct = categories["correct"]

    by_slot: dict[str, Any] = {}
    for slot in ("A", "B"):
        counts = category_by_slot[slot]
        slot_n = sum(counts.values())
        slot_correct = counts.get("correct", 0)
        slot_parsed = slot_n - counts.get("invalid", 0)
        by_slot[slot] = {
            "n": slot_n,
            "categories": {key: counts.get(key, 0) for key in CATEGORY_KEYS},
            "accuracy_all": _round(_ratio(slot_correct, slot_n)),
            "accuracy_parsed": _round(_ratio(slot_correct, slot_parsed)),
            "wilson_all": _wilson(slot_correct, slot_n),
            "wilson_parsed": _wilson(slot_correct, slot_parsed),
        }

    da_a = by_slot["A"]["accuracy_all"]
    da_b = by_slot["B"]["accuracy_all"]
    diff = None if da_a is None or da_b is None else da_a - da_b
    strict_a = by_slot["A"]["categories"]["correct"]
    strict_b = by_slot["B"]["categories"]["correct"]
    parsed_a = by_slot["A"]["n"] - by_slot["A"]["categories"]["invalid"]
    parsed_b = by_slot["B"]["n"] - by_slot["B"]["categories"]["invalid"]
    fisher_all = _fisher_two_sided(
        strict_a,
        by_slot["A"]["n"] - strict_a,
        strict_b,
        by_slot["B"]["n"] - strict_b,
    )
    fisher_parsed = _fisher_two_sided(
        strict_a,
        parsed_a - strict_a,
        strict_b,
        parsed_b - strict_b,
    )

    selected_counts: Counter[str] = Counter()
    selection_by_slot: dict[str, Counter[str]] = {"A": Counter(), "B": Counter()}
    for unit in units:
        record = by_pair[unit.pair_id]
        parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
        decision = parsed.get("vulnerable_version") if parsed else None
        slot = assignments[unit.pair_id]["vulnerable_slot"]
        if decision in {"A", "B"}:
            selected_counts[decision] += 1
            selection_by_slot[slot][decision] += 1
        elif decision in {"both", "neither"}:
            selected_counts[decision] += 1
            selection_by_slot[slot][decision] += 1
        else:
            selected_counts["invalid"] += 1
            selection_by_slot[slot]["invalid"] += 1

    ab_selected = selected_counts.get("A", 0) + selected_counts.get("B", 0)
    slot_a_share = _ratio(selected_counts.get("A", 0), ab_selected)
    slot_binomial = _binomial_two_sided(selected_counts.get("A", 0), ab_selected)

    identity_residual = None
    if parsed_count:
        consistent = (categories["correct"] + categories["swapped"]) / parsed_count
        identity_residual = (
            consistent
            - categories["both_vulnerable"] / parsed_count
            - categories["both_safe"] / parsed_count
            - 1.0
        )

    def mean(values: list[float]) -> float | None:
        return _round(sum(values) / len(values)) if values else None

    evidence_block = {
        "decisions_with_evidence": evidence_present,
        "evidence_present_rate": _round(_ratio(evidence_present, parsed_count)),
        "schema_exact": schema_exact,
        "schema_exact_rate": _round(_ratio(schema_exact, parsed_count)),
        "evidence_compliant": evidence_compliant,
        "evidence_compliance_rate": _round(_ratio(evidence_compliant, parsed_count)),
        "compliant_correct": compliant_correct,
        "compliant_correct_rate_all": _round(_ratio(compliant_correct, n)),
        "compliant_correct_rate_parsed": _round(_ratio(compliant_correct, parsed_count)),
        "evidence_items_total": evidence_items_total,
        "evidence_text_matches": evidence_text_matches,
        "evidence_text_match_rate": _round(_ratio(evidence_text_matches, evidence_items_total)),
        "localization_scored_correct": localization_scored,
        "localization_hit_correct": localization_hit,
        "localization_hit_rate_correct": _round(_ratio(localization_hit, localization_scored)),
        "joint_correct_and_localization": joint_localization,
        "joint_correct_and_localization_rate_all": _round(_ratio(joint_localization, n)),
        "joint_correct_and_localization_rate_parsed": _round(_ratio(joint_localization, parsed_count)),
    }

    metrics = {
        "schema_version": 1,
        "run": {
            "run_id": manifest.get("run_id"),
            "run_label": manifest.get("run_label"),
            "model": (manifest.get("api") or {}).get("model"),
            "prompt_version": manifest.get("prompt_version"),
            "partial": manifest.get("partial"),
            "limit": manifest.get("limit"),
            "dataset_path": manifest.get("dataset_path"),
            "dataset_sha256": manifest.get("dataset_sha256"),
            "selected_units": n,
            "started_at": manifest.get("started_at"),
            "completed_at": manifest.get("completed_at"),
            "position_map_sha256": position.get("sha256"),
            "vulnerable_slot_counts": position.get("counts"),
        },
        "counts": {
            "pairs": n,
            "parsed_outputs": parsed_count,
            "forced_choice_outputs": forced_count,
            "categories": categories,
            "invalid_reasons": dict(invalid_reasons),
            "by_vulnerable_slot": {slot: by_slot[slot]["categories"] for slot in ("A", "B")},
            "status": dict(Counter(str(record.get("status")) for record in results)),
        },
        "rates": {
            "over_all_pairs": {
                key: _round(_ratio(value, n)) for key, value in categories.items()
            },
            "over_parsed_outputs": {
                key: _round(_ratio(value, parsed_count)) for key, value in categories.items()
            },
            "over_forced_choice_outputs": {
                "correct": _round(_ratio(categories["correct"], forced_count)),
                "swapped": _round(_ratio(categories["swapped"], forced_count)),
            },
            "consistency_identity_residual": _round(identity_residual),
        },
        "joint_accuracy": {
            "all_pairs": _round(_ratio(correct, n)),
            "parsed_outputs": _round(_ratio(correct, parsed_count)),
            "forced_choice_outputs": _round(_ratio(correct, forced_count)),
            "wilson_all_pairs": _wilson(correct, n),
            "wilson_parsed": _wilson(correct, parsed_count),
            "wilson_forced_choice": _wilson(correct, forced_count),
        },
        "position_bias": {
            "by_vulnerable_slot": by_slot,
            "difference_da_A_minus_da_B_all": _round(diff),
            "difference_da_A_minus_da_B_parsed": _round(
                None if by_slot["A"]["accuracy_parsed"] is None or by_slot["B"]["accuracy_parsed"] is None
                else by_slot["A"]["accuracy_parsed"] - by_slot["B"]["accuracy_parsed"]
            ),
            "fisher_exact_p_all": _round(fisher_all),
            "fisher_exact_p_parsed": _round(fisher_parsed),
            "selected_slot_counts": dict(selected_counts),
            "selection_by_vulnerable_slot": {slot: dict(selection_by_slot[slot]) for slot in ("A", "B")},
            "slot_a_share_of_ab_selections": _round(slot_a_share),
            "binomial_p_select_A_vs_B": _round(slot_binomial),
        },
        "evidence": evidence_block,
        "confidence": {
            "mean_all": mean(confidence_values),
            "mean_by_category": {key: mean(values) for key, values in sorted(confidence_by_category.items())},
        },
        "length_confound": _length_confound(units, by_pair, assignments),
        "per_pair": unit_rows,
    }
    return metrics


def _usage_metrics(manifest: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    prompt = completion = cached = reasoning = 0
    with_usage = 0
    cost_total = 0.0
    with_cost = 0
    latencies: list[float] = []
    for record in results:
        response = record.get("response") or {}
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else None
        if usage:
            with_usage += 1
            for key in ("prompt_tokens", "completion_tokens"):
                if isinstance(usage.get(key), int) and not isinstance(usage.get(key), bool):
                    if key == "prompt_tokens":
                        prompt += usage[key]
                    else:
                        completion += usage[key]
            cached_value = usage.get("prompt_cache_hit_tokens")
            if not isinstance(cached_value, int):
                details = usage.get("prompt_tokens_details")
                cached_value = details.get("cached_tokens") if isinstance(details, dict) else None
            if isinstance(cached_value, int) and not isinstance(cached_value, bool):
                cached += cached_value
            details = usage.get("completion_tokens_details")
            reasoning_value = details.get("reasoning_tokens") if isinstance(details, dict) else None
            if isinstance(reasoning_value, int) and not isinstance(reasoning_value, bool):
                reasoning += reasoning_value
        cost = response.get("cost") if isinstance(response.get("cost"), dict) else None
        value = cost.get("cost_usd") if cost else None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            cost_total += float(value)
            with_cost += 1
        latency = response.get("request_latency_seconds")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool) and math.isfinite(float(latency)):
            latencies.append(float(latency))
    latencies.sort()

    def pct(fraction: float) -> float | None:
        if not latencies:
            return None
        position = (len(latencies) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return _round(latencies[lower])
        return _round(latencies[lower] * (1 - (position - lower)) + latencies[upper] * (position - lower))

    cost_value = _round(cost_total) if with_cost else None
    observed = manifest.get("counts", {}).get("recorded_requests") or len(results)
    return {
        "usage": {
            "records": len(results),
            "records_with_usage": with_usage,
            "prompt_tokens": prompt if with_usage else None,
            "completion_tokens": completion if with_usage else None,
            "cached_prompt_tokens": cached if with_usage else None,
            "reasoning_tokens": reasoning if with_usage else None,
            "prompt_tokens_per_pair": _round(_ratio(prompt, observed)) if with_usage else None,
            "completion_tokens_per_pair": _round(_ratio(completion, observed)) if with_usage else None,
        },
        "cost": {
            "total_cost_usd": cost_value,
            "records_with_cost": with_cost,
            "records_missing_cost": len(results) - with_cost,
            "cost_per_pair_usd": _round(_ratio(cost_total, observed)) if with_cost else None,
            "cost_basis": "provider usage x configured per-1M prices",
            "prices": (manifest.get("api") or {}),
        },
        "latency_seconds": {
            "n": len(latencies),
            "mean": _round(sum(latencies) / len(latencies)) if latencies else None,
            "p50": pct(0.5),
            "p95": pct(0.95),
            "max": _round(max(latencies)) if latencies else None,
        },
        "run_wall_seconds": _wall_seconds(manifest),
    }


def _wall_seconds(manifest: dict[str, Any]) -> float | None:
    started = manifest.get("started_at")
    completed = manifest.get("completed_at")
    if not started or not completed:
        return None
    try:
        start = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(completed).replace("Z", "+00:00"))
    except ValueError:
        return None
    return _round((end - start).total_seconds())


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.2f}%"


def _num(value: float | None, digits: int = 4) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _pvalue(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value < 1e-4:
        return f"{value:.3e}"
    return f"{value:.4f}"


def _ci(bucket: dict[str, Any] | None) -> str:
    if not bucket:
        return "n/a"
    return f"{_pct(bucket['estimate'])} [{_pct(bucket['low'])}, {_pct(bucket['high'])}]"


def _bootstrap_cell(block: dict[str, Any], name: str) -> str:
    metric = (block.get("metrics") or {}).get(name)
    if not metric:
        return "n/a"
    return f"[{_num(metric.get('ci_low'))}, {_num(metric.get('ci_high'))}]"


def _render_markdown(metrics: dict[str, Any], comparisons: list[dict[str, Any]]) -> str:
    run = metrics["run"]
    counts = metrics["counts"]
    rates = metrics["rates"]
    da = metrics["joint_accuracy"]
    position = metrics["position_bias"]
    evidence = metrics["evidence"]
    length = metrics["length_confound"]
    usage = metrics["usage"]
    cost = metrics["cost"]
    latency = metrics["latency_seconds"]
    lines = [
        f"# Pair-joint A/B 结果：{run['model']}",
        "",
        f"- 运行目录：`{run['run_id']}`",
        f"- 数据：`{run['dataset_path']}`（SHA-256 `{run['dataset_sha256']}`，{run['selected_units']} 对）",
        f"- Prompt：`{run['prompt_version']}`；A/B 位置按位置映射文件 SHA-256 `{run['position_map_sha256']}`",
        f"- 部分运行：`{run['partial']}`；开始 `{run['started_at']}`，结束 `{run['completed_at']}`",
        f"- 位置计数：{run['vulnerable_slot_counts']}",
        "",
        "## 1. 输出有效性（四类 + 无效）",
        "",
        "| 类别 | 计数 | 占全部对 | 占可解析输出 |",
        "| --- | ---: | ---: | ---: |",
    ]
    category_labels = {
        "correct": "correct（选对漏洞版本）",
        "swapped": "swapped（判反）",
        "both_vulnerable": "both_vulnerable（称两侧都有漏洞）",
        "both_safe": "both_safe（称两侧都安全）",
        "invalid": "invalid（不可解析/API 错误）",
    }
    for key in CATEGORY_KEYS:
        lines.append(
            f"| {category_labels[key]} | {counts['categories'][key]} | "
            f"{_pct(rates['over_all_pairs'][key])} | "
            f"{_pct(rates['over_parsed_outputs'][key])} |"
        )
    lines.extend(
        [
            "",
            f"- 可解析输出：{counts['parsed_outputs']}/{counts['pairs']}；"
            f"强制二选一输出：{counts['forced_choice_outputs']}/{counts['pairs']}。",
            f"- 无效原因：`{json.dumps(counts['invalid_reasons'], ensure_ascii=False)}`。",
            f"- 恒等式残差（一致率 − both_vulnerable − both_safe − 1）："
            f"`{rates['consistency_identity_residual']}`。",
            "",
            "## 2. 配对判别准确率（DA）",
            "",
            "| 口径 | 值 | 95% Wilson | 分母 |",
            "| --- | ---: | --- | ---: |",
            f"| DA（全部 180 对，invalid 记错） | {_pct(da['all_pairs'])} | {_ci(da['wilson_all_pairs'])} | {counts['pairs']} |",
            f"| DA（可解析输出） | {_pct(da['parsed_outputs'])} | {_ci(da['wilson_parsed'])} | {counts['parsed_outputs']} |",
            f"| DA（强制二选一输出） | {_pct(da['forced_choice_outputs'])} | {_ci(da['wilson_forced_choice'])} | {counts['forced_choice_outputs']} |",
            "",
            "## 2.1 长度混淆检查（post-hoc，不是预注册基线）",
            "",
            "| 子集（按字符长度） | n | joint correct | joint DA |",
            "| --- | ---: | ---: | ---: |",
            f"| 漏洞版本更短 | {length['strata']['vulnerable_shorter']['n']} | {length['strata']['vulnerable_shorter']['correct']} | {_pct(length['strata']['vulnerable_shorter']['accuracy'])} |",
            f"| 漏洞版本更长 | {length['strata']['vulnerable_longer']['n']} | {length['strata']['vulnerable_longer']['correct']} | {_pct(length['strata']['vulnerable_longer']['accuracy'])} |",
            f"| 等长 | {length['strata']['tie']['n']} | {length['strata']['tie']['correct']} | {_pct(length['strata']['tie']['accuracy'])} |",
            "",
            "| 平凡启发式 | 正确 | DA |",
            "| --- | ---: | ---: |",
            f"| 选较短版本（字符，tie=A） | {length['shorter_body_heuristic']['characters_correct']} | {_pct(length['shorter_body_heuristic']['characters_tie_A'])} |",
            f"| 选较短版本（行数，tie=A） | {length['shorter_body_heuristic']['lines_correct']} | {_pct(length['shorter_body_heuristic']['lines_tie_A'])} |",
            "",
            f"- joint vs 字符长度启发式 McNemar："
            f"b={length['mcnemar_joint_vs_shorter_characters']['a_correct_b_wrong']}，"
            f"c={length['mcnemar_joint_vs_shorter_characters']['a_wrong_b_correct']}，"
            f"p={_pvalue(length['mcnemar_joint_vs_shorter_characters']['p_value'])}。",
            "- 该诊断在测试结果之后加入，仅用于判断“修复版本通常更长”这一数据伪影能在多大程度上解释 DA；"
            "它不改变主指标，也不把长度当作模型能力。",
            "",
            "## 3. Position bias",
            "",
            "| 漏洞版本位置 | n | correct | swapped | both | neither | invalid | DA（全部） | DA（可解析） |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for slot in ("A", "B"):
        bucket = position["by_vulnerable_slot"][slot]
        cats = bucket["categories"]
        lines.append(
            f"| {slot} | {bucket['n']} | {cats['correct']} | {cats['swapped']} | "
            f"{cats['both_vulnerable']} | {cats['both_safe']} | {cats['invalid']} | "
            f"{_pct(bucket['accuracy_all'])} | {_pct(bucket['accuracy_parsed'])} |"
        )
    lines.extend(
        [
            "",
            f"- DA(A) − DA(B)（全部）：{_pct(position['difference_da_A_minus_da_B_all'])}；"
            f"Fisher 精确 p = {_pvalue(position['fisher_exact_p_all'])}。",
            f"- DA(A) − DA(B)（可解析）：{_pct(position['difference_da_A_minus_da_B_parsed'])}；"
            f"Fisher 精确 p = {_pvalue(position['fisher_exact_p_parsed'])}。",
            f"- 选择 A/B 的次数：{position['selected_slot_counts']}；"
            f"在 A/B 选择中 A 的占比 = {_pct(position['slot_a_share_of_ab_selections'])}，"
            f"二项检验 p = {_pvalue(position['binomial_p_select_A_vs_B'])}。",
            "- 选择矩阵（行=漏洞版本位置，列=模型选择）："
            f"`{json.dumps(position['selection_by_vulnerable_slot'], ensure_ascii=False)}`。",
            "",
            "## 4. 证据行与定位",
            "",
            "| 指标 | 值 |",
            "| --- | ---: |",
            f"| 有 evidence 的可解析输出 | {evidence['decisions_with_evidence']} ({_pct(evidence['evidence_present_rate'])}) |",
            f"| schema 完全匹配 | {evidence['schema_exact']} ({_pct(evidence['schema_exact_rate'])}) |",
            f"| evidence 合规（引用所选版本、行号在范围、code 非空） | {evidence['evidence_compliant']} ({_pct(evidence['evidence_compliance_rate'])}) |",
            f"| 正确且 evidence 合规 | {evidence['compliant_correct']} ({_pct(evidence['compliant_correct_rate_all'])} of all) |",
            f"| evidence 行文本精确匹配 | {evidence['evidence_text_matches']}/{evidence['evidence_items_total']} ({_pct(evidence['evidence_text_match_rate'])}) |",
            f"| localization 可评分（correct） | {evidence['localization_scored_correct']} |",
            f"| localization 命中（correct） | {evidence['localization_hit_correct']} ({_pct(evidence['localization_hit_rate_correct'])}) |",
            f"| 判对且定位命中 | {evidence['joint_correct_and_localization']} ({_pct(evidence['joint_correct_and_localization_rate_all'])} of all) |",
            "",
            "## 5. 与原分侧调用对比",
            "",
        ]
    )
    if not comparisons:
        lines.append("未提供基线运行（`--no-baseline`）。")
    for comp in comparisons:
        lines.extend(
            [
                f"### {comp['label_a']} vs {comp['label_b']}",
                "",
                f"- 基线：`{comp['baseline_run_id']}`（{comp['baseline_model']}，策略 `{comp['baseline_strategy']}`）；"
                f"基线数据集 SHA-256 `{comp['baseline_dataset_sha256']}`。",
                f"- 基线检测记录状态：`{json.dumps(comp['baseline_statuses'], ensure_ascii=False)}`；"
                f"有效对 {comp['baseline_valid_pairs']}/{comp['n_pairs']}。",
                f"- 基线四类：`{json.dumps(comp['baseline_categories'], ensure_ascii=False, sort_keys=True)}`。",
                "",
                "| 方法 | 正确/对 | DA（全部） | 95% Wilson |",
                "| --- | ---: | ---: | --- |",
                f"| {comp['label_a']} | {comp['joint_correct']} | {_pct(comp['accuracy_a_all'])} | {_ci(comp['wilson_a_all'])} |",
                f"| {comp['label_b']} | {comp['baseline_correct']} | {_pct(comp['accuracy_b_all'])} | {_ci(comp['wilson_b_all'])} |",
                "",
                f"- 2×2：both correct={comp['table']['both_correct']}，"
                f"joint-only={comp['table']['a_correct_b_wrong']}，"
                f"baseline-only={comp['table']['a_wrong_b_correct']}，"
                f"both wrong={comp['table']['both_wrong']}。",
                f"- McNemar 精确检验（全部 {comp['n_pairs']} 对，invalid 记错）："
                f"b={comp['mcnemar_all']['a_correct_b_wrong']}，c={comp['mcnemar_all']['a_wrong_b_correct']}，"
                f"p={_pvalue(comp['mcnemar_all']['p_value'])}，"
                f"风险差={_num(comp['mcnemar_all']['risk_difference'])}。",
                f"- 仅双方都有效的 {comp['intersection']['n_pairs']} 对："
                f"joint {comp['intersection']['a_correct']} vs baseline {comp['intersection']['b_correct']}；"
                f"McNemar p={_pvalue((comp['intersection']['mcnemar'] or {}).get('p_value'))}。",
                f"- 项目聚类 bootstrap ΔDA 95% CI（10k）："
                f"{_bootstrap_cell(comp['bootstrap']['primary_project_cluster'], 'difference')}；"
                f"joint DA CI {_bootstrap_cell(comp['bootstrap']['primary_project_cluster'], 'da_a')}；"
                f"baseline DA CI {_bootstrap_cell(comp['bootstrap']['primary_project_cluster'], 'da_b')}。",
                f"- 配对级 bootstrap ΔDA 95% CI（敏感性）："
                f"{_bootstrap_cell(comp['bootstrap']['sensitivity_pair_cluster'], 'difference')}。",
                "",
            ]
        )
    lines.extend(
        [
            "## 6. 用量、成本、延迟",
            "",
            "| 指标 | 值 |",
            "| --- | ---: |",
            f"| prompt tokens 合计 | {usage['prompt_tokens']} |",
            f"| completion tokens 合计 | {usage['completion_tokens']} |",
            f"| cached prompt tokens | {usage['cached_prompt_tokens']} |",
            f"| reasoning tokens | {usage['reasoning_tokens']} |",
            f"| 每对 prompt tokens | {_num(usage['prompt_tokens_per_pair'], 2)} |",
            f"| 总成本 USD | {_num(cost['total_cost_usd'], 6)} |",
            f"| 每对成本 USD | {_num(cost['cost_per_pair_usd'], 6)} |",
            f"| 每正确对成本 USD | {_num(_ratio(cost['total_cost_usd'], metrics['counts']['categories']['correct']) if cost['total_cost_usd'] is not None else None, 6)} |",
            f"| 延迟 mean / p50 / p95 / max (s) | {_num(latency['mean'])} / {_num(latency['p50'])} / {_num(latency['p95'])} / {_num(latency['max'])} |",
            f"| run wall (s) | {_num(metrics.get('run_wall_seconds'))} |",
            "",
            "## 7. 解释限制",
            "",
            "- 联合提示强制模型二选一，不能直接复现“两侧分别调用”时的 both_flagged / both_safe 失败模式；"
            "本表的 both_vulnerable / both_safe 是模型违反指令的输出，不是两次独立判定的组合。",
            "- 主推断按项目聚类 bootstrap；但 180 对中 `linux` 占 53 对，项目聚类区间受少数大项目支配，"
            "配对级 bootstrap 仅作敏感性分析。",
            "- McNemar 以对为单位且假设独立；同项目相关会使 p 值偏小，因此只作为次要检验。",
            "- 证据行定位使用 `difflib` 对漏洞/修复版本做行级 diff；源码注释中的 CVE/CWE 字符串属于数据残留，"
            "不是注入的元数据，详见 `leak_audit.json`。",
            "- 单次贪心解码（temperature=0），没有重复采样；结果不代表模型方差。",
            "",
        ]
    )
    return "\n".join(lines)


def _analyse_one(
    run_dir: Path,
    units: list[PairUnit],
    *,
    with_baseline: bool,
    resamples: int,
    seed: int,
    baseline_override: dict[str, str] | None,
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    manifest, results, position = _joint_records(run_dir)
    selected_ids = set((position.get("assignments") or {}).keys())
    run_units = [unit for unit in units if unit.pair_id in selected_ids]
    if len(run_units) != len(selected_ids):
        raise PairJointError(
            f"{run_dir}: {len(selected_ids)} pairs in the position map are not in the dataset"
        )
    units = run_units
    metrics = _joint_metrics(units, manifest, results, position)
    usage = _usage_metrics(manifest, results)
    metrics.update(usage)

    by_pair = {str(record["pair_id"]): record for record in results}
    assignments = position["assignments"]
    joint_correct: dict[str, bool] = {}
    joint_valid: dict[str, bool] = {}
    for unit in units:
        category, _ = _category(by_pair[unit.pair_id], assignments[unit.pair_id])
        joint_correct[unit.pair_id] = category == "correct"
        joint_valid[unit.pair_id] = category != "invalid"

    comparisons: list[dict[str, Any]] = []
    model = str((manifest.get("api") or {}).get("model") or "")
    candidates = list((baseline_override or {}).items())
    if not candidates and with_baseline:
        candidates = list(BASELINES.get(model, ()))
    for strategy, relative_path in candidates:
        baseline_dir = Path(relative_path)
        if not baseline_dir.is_absolute():
            baseline_dir = ROOT / baseline_dir
        if not (baseline_dir / "results.jsonl").exists():
            metrics.setdefault("warnings", []).append(f"baseline not found: {baseline_dir}")
            continue
        baseline_summary, baseline_by_key = _baseline_records(baseline_dir)
        baseline = _per_pair_baseline(units, baseline_by_key)
        if len(baseline["missing"]) == len(units):
            metrics.setdefault("warnings", []).append(
                f"baseline {baseline_dir} has no overlapping pairs; skipped"
            )
            continue
        comparison = _comparison(
            units,
            joint_correct,
            baseline["correct"],
            joint_valid,
            baseline["valid"],
            label_a=f"pair_joint ({model})",
            label_b=f"separate {strategy} ({baseline_summary['model']})",
            resamples=resamples,
            seed=seed,
        )
        comparison.update(
            {
                "baseline_run_id": baseline_summary["run_id"],
                "baseline_run_dir": baseline_summary["run_dir"],
                "baseline_model": baseline_summary["model"],
                "baseline_strategy": baseline_summary["strategy"],
                "baseline_dataset_sha256": baseline_summary["dataset_sha256"],
                "baseline_statuses": baseline_summary["statuses"],
                "baseline_valid_pairs": sum(1 for value in baseline["valid"].values() if value),
                "baseline_categories": dict(baseline["categories"]),
                "baseline_missing_pairs": len(baseline["missing"]),
                "joint_correct": sum(1 for value in joint_correct.values() if value),
                "baseline_correct": sum(1 for value in baseline["correct"].values() if value),
                "primary": strategy == "direct",
            }
        )
        comparisons.append(comparison)

    if comparisons:
        metrics["comparisons"] = comparisons
    return metrics, _render_markdown(metrics, comparisons), comparisons


def _arrays_from_metrics(metrics: dict[str, Any]) -> tuple[dict[str, bool], dict[str, bool]]:
    correct: dict[str, bool] = {}
    valid: dict[str, bool] = {}
    for row in metrics.get("per_pair") or []:
        pair_id = str(row.get("pair_id"))
        category = str(row.get("category"))
        correct[pair_id] = category == "correct"
        valid[pair_id] = category != "invalid"
    return correct, valid


def _combined_markdown(
    entries: list[tuple[dict[str, Any], str]],
    cross_model: dict[str, Any] | None = None,
) -> str:
    lines = [
        "# Pair-joint：DeepSeek V4.1 Flash vs MiMo V2.6 Flash",
        "",
        "同一 180 对冻结测试集、同一 prompt 版本、同一 A/B 平衡顺序；每对一次请求。",
        "",
        "| 模型 | DA（全部） | 长度启发式 DA | DA（可解析） | swapped | both | neither | invalid |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for metrics, _ in entries:
        cats = metrics["counts"]["categories"]
        lines.append(
            f"| {metrics['run']['model']} | {_pct(metrics['joint_accuracy']['all_pairs'])} | "
            f"{_pct(metrics['length_confound']['shorter_body_heuristic']['characters_tie_A'])} | "
            f"{_pct(metrics['joint_accuracy']['parsed_outputs'])} | {cats['swapped']} | "
            f"{cats['both_vulnerable']} | {cats['both_safe']} | {cats['invalid']} |"
        )
    lines.extend(
        [
            "",
            "| 模型 | DA(A) | DA(B) | 差值 | Fisher p | 证据合规 | 定位命中 | 成本 USD | p95 延迟 s |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for metrics, _ in entries:
        pos = metrics["position_bias"]
        lines.append(
            f"| {metrics['run']['model']} | {_pct(pos['by_vulnerable_slot']['A']['accuracy_all'])} | "
            f"{_pct(pos['by_vulnerable_slot']['B']['accuracy_all'])} | "
            f"{_pct(pos['difference_da_A_minus_da_B_all'])} | {_pvalue(pos['fisher_exact_p_all'])} | "
            f"{_pct(metrics['evidence']['evidence_compliance_rate'])} | "
            f"{_pct(metrics['evidence']['localization_hit_rate_correct'])} | "
            f"{_num(metrics['cost']['total_cost_usd'], 6)} | {_num(metrics['latency_seconds']['p95'])} |"
        )
    lines.extend(["", "## 统计对比", ""])
    for metrics, _ in entries:
        for comp in metrics.get("comparisons") or []:
            lines.append(
                f"- **{metrics['run']['model']}** vs `{comp['baseline_run_id']}`（{comp['baseline_strategy']}）："
                f"joint DA={_pct(comp['accuracy_a_all'])}，baseline DA={_pct(comp['accuracy_b_all'])}，"
                f"ΔDA={_pct((comp['accuracy_a_all'] or 0) - (comp['accuracy_b_all'] or 0))}，"
                f"McNemar p={_pvalue(comp['mcnemar_all']['p_value'])}，"
                f"项目聚类 ΔDA 95% CI {_bootstrap_cell(comp['bootstrap']['primary_project_cluster'], 'difference')}。"
            )
    if cross_model:
        lines.extend(
            [
                "",
                "## 跨模型对比（同一批对）",
                "",
                f"- `{cross_model['label_a']}` vs `{cross_model['label_b']}`："
                f"{cross_model['joint_correct_a']} vs {cross_model['joint_correct_b']} 对正确；"
                f"ΔDA={_pct((cross_model['accuracy_a_all'] or 0) - (cross_model['accuracy_b_all'] or 0))}。",
                f"- 2×2：both correct={cross_model['table']['both_correct']}，"
                f"A-only={cross_model['table']['a_correct_b_wrong']}，"
                f"B-only={cross_model['table']['a_wrong_b_correct']}，"
                f"both wrong={cross_model['table']['both_wrong']}。",
                f"- McNemar p={_pvalue(cross_model['mcnemar_all']['p_value'])}；"
                f"项目聚类 ΔDA 95% CI "
                f"{_bootstrap_cell(cross_model['bootstrap']['primary_project_cluster'], 'difference')}；"
                f"配对级 95% CI "
                f"{_bootstrap_cell(cross_model['bootstrap']['sensitivity_pair_cluster'], 'difference')}。",
            ]
        )
    lines.extend(
        [
            "",
            "说明：`both` / `neither` 是模型违反“恰好一个”指令的输出；`invalid` 为不可解析/API 错误。"
            "所有数字均来自对应运行目录的 `results.jsonl`，未手工改写。",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, action="append", required=True)
    parser.add_argument("--dataset", type=Path, default=ROOT / "splits" / "test_pairs_180.json")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "pair_joint" / "results")
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--baseline", action="append", default=[], metavar="STRATEGY=PATH")
    parser.add_argument("--bootstrap", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    units, _metadata, dataset_sha = load_pairs(args.dataset)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    override: dict[str, str] = {}
    for item in args.baseline:
        if "=" not in item:
            print(f"ERROR: --baseline must be STRATEGY=PATH, got {item!r}", file=sys.stderr)
            return 2
        strategy, path = item.split("=", 1)
        override[strategy] = path

    entries: list[tuple[dict[str, Any], str]] = []
    comparison_rows: list[dict[str, Any]] = []
    for run_dir in args.run_dir:
        run_dir = run_dir if run_dir.is_absolute() else ROOT / run_dir
        try:
            metrics, markdown, comparisons = _analyse_one(
                run_dir,
                units,
                with_baseline=not args.no_baseline,
                resamples=args.bootstrap,
                seed=args.seed,
                baseline_override=override or None,
            )
        except (PairJointError, OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: {run_dir}: {exc}", file=sys.stderr)
            return 2
        model = str(metrics["run"]["model"] or run_dir.name)
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in model)
        json_path = args.out_dir / f"analysis_{safe}.json"
        md_path = args.out_dir / f"analysis_{safe}.md"
        metrics["analysis"] = {
            "source_run_dir": str(run_dir.relative_to(ROOT)) if run_dir.is_relative_to(ROOT) else str(run_dir),
            "dataset_sha256": dataset_sha,
            "bootstrap_resamples": args.bootstrap,
            "bootstrap_seed": args.seed,
            "bootstrap_primary_cluster": "project",
            "bootstrap_sensitivity_cluster": "pair",
            "mcnemar_unit": "pair",
        }
        json_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        md_path.write_text(markdown + "\n", encoding="utf-8")
        entries.append((metrics, markdown))
        for comparison in comparisons:
            comparison_rows.append(
                {
                    "model": model,
                    "run_id": metrics["run"]["run_id"],
                    "baseline_run_id": comparison["baseline_run_id"],
                    "baseline_strategy": comparison["baseline_strategy"],
                    "joint_accuracy_all": comparison["accuracy_a_all"],
                    "baseline_accuracy_all": comparison["accuracy_b_all"],
                    "delta": _round((comparison["accuracy_a_all"] or 0) - (comparison["accuracy_b_all"] or 0)),
                    "mcnemar_p": comparison["mcnemar_all"]["p_value"],
                    "bootstrap_primary": comparison["bootstrap"]["primary_project_cluster"],
                    "bootstrap_sensitivity": comparison["bootstrap"]["sensitivity_pair_cluster"],
                }
            )
        print(f"Analysed {run_dir}: DA(all)={_pct(metrics['joint_accuracy']['all_pairs'])}, "
              f"invalid={metrics['counts']['categories']['invalid']}")

    cross_model: dict[str, Any] | None = None
    if len(entries) >= 2:
        correct_a, valid_a = _arrays_from_metrics(entries[0][0])
        correct_b, valid_b = _arrays_from_metrics(entries[1][0])
        common_ids = set(correct_a) & set(correct_b)
        common_units = [unit for unit in units if unit.pair_id in common_ids]
        if len(common_units) >= 2:
            cross_model = _comparison(
                common_units,
                correct_a,
                correct_b,
                valid_a,
                valid_b,
                label_a=str(entries[0][0]["run"]["model"]),
                label_b=str(entries[1][0]["run"]["model"]),
                resamples=args.bootstrap,
                seed=args.seed,
            )
            cross_model["joint_correct_a"] = sum(1 for value in correct_a.values() if value)
            cross_model["joint_correct_b"] = sum(1 for value in correct_b.values() if value)
        combined = _combined_markdown(entries, cross_model)
        (args.out_dir / "comparison.md").write_text(combined + "\n", encoding="utf-8")
        payload = {
            "schema_version": 1,
            "dataset_sha256": dataset_sha,
            "runs": [
                {
                    "model": metrics["run"]["model"],
                    "run_id": metrics["run"]["run_id"],
                    "joint_accuracy_all": metrics["joint_accuracy"]["all_pairs"],
                    "joint_accuracy_parsed": metrics["joint_accuracy"]["parsed_outputs"],
                    "categories": metrics["counts"]["categories"],
                    "position": metrics["position_bias"],
                    "evidence": metrics["evidence"],
                    "length_confound": metrics["length_confound"],
                    "usage": metrics["usage"],
                    "cost": {"total_cost_usd": metrics["cost"]["total_cost_usd"]},
                    "latency": metrics["latency_seconds"],
                }
                for metrics, _ in entries
            ],
            "comparisons": comparison_rows,
            "cross_model": cross_model,
        }
        (args.out_dir / "comparison.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    export = {
        "schema_version": 1,
        "method": "pair_joint",
        "prompt_version": entries[0][0]["run"]["prompt_version"] if entries else None,
        "dataset_sha256": dataset_sha,
        "dataset_units": len(units),
        "models": [
            {
                "model": metrics["run"]["model"],
                "run_id": metrics["run"]["run_id"],
                "partial": metrics["run"]["partial"],
                "n_pairs": metrics["run"]["selected_units"],
                "da_all": metrics["joint_accuracy"]["all_pairs"],
                "da_wilson": metrics["joint_accuracy"]["wilson_all_pairs"],
                "categories": metrics["counts"]["categories"],
                "position_bias": {
                    "da_when_vulnerable_A": metrics["position_bias"]["by_vulnerable_slot"]["A"]["accuracy_all"],
                    "da_when_vulnerable_B": metrics["position_bias"]["by_vulnerable_slot"]["B"]["accuracy_all"],
                    "difference": metrics["position_bias"]["difference_da_A_minus_da_B_all"],
                    "fisher_p": metrics["position_bias"]["fisher_exact_p_all"],
                    "selected_slot_counts": metrics["position_bias"]["selected_slot_counts"],
                },
                "evidence": {
                    "compliance_rate": metrics["evidence"]["evidence_compliance_rate"],
                    "localization_hit_rate_correct": metrics["evidence"]["localization_hit_rate_correct"],
                    "joint_correct_and_localization_rate_all": metrics["evidence"]["joint_correct_and_localization_rate_all"],
                },
                "length_confound": {
                    "shorter_characters_da": metrics["length_confound"]["shorter_body_heuristic"]["characters_tie_A"],
                    "strata": metrics["length_confound"]["strata"],
                    "mcnemar_p_vs_shorter": metrics["length_confound"]["mcnemar_joint_vs_shorter_characters"]["p_value"],
                },
                "usage": metrics["usage"],
                "cost": {
                    "total_cost_usd": metrics["cost"]["total_cost_usd"],
                    "cost_per_pair_usd": metrics["cost"]["cost_per_pair_usd"],
                },
                "latency_seconds": metrics["latency_seconds"],
                "comparisons": [
                    {
                        "baseline_run_id": comp["baseline_run_id"],
                        "baseline_strategy": comp["baseline_strategy"],
                        "baseline_da": comp["accuracy_b_all"],
                        "delta_da": _round((comp["accuracy_a_all"] or 0) - (comp["accuracy_b_all"] or 0)),
                        "mcnemar_p": comp["mcnemar_all"]["p_value"],
                        "bootstrap_project_delta": comp["bootstrap"]["primary_project_cluster"]["metrics"].get("difference"),
                        "bootstrap_pair_delta": comp["bootstrap"]["sensitivity_pair_cluster"]["metrics"].get("difference"),
                    }
                    for comp in metrics.get("comparisons") or []
                ],
            }
            for metrics, _ in entries
        ],
        "cross_model": cross_model,
    }
    (args.out_dir / "benchmark_export.json").write_text(
        json.dumps(export, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = ["# Pair-joint 汇总", ""]
    for metrics, _markdown in entries:
        summary.append(
            f"- `{metrics['run']['model']}`：DA(all)={_pct(metrics['joint_accuracy']['all_pairs'])}，"
            f"DA(parsed)={_pct(metrics['joint_accuracy']['parsed_outputs'])}，"
            f"invalid={metrics['counts']['categories']['invalid']}，"
            f"位置差={_pct(metrics['position_bias']['difference_da_A_minus_da_B_all'])}，"
            f"成本={_num(metrics['cost']['total_cost_usd'], 6)} USD。"
        )
    (args.out_dir / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

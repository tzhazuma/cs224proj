#!/usr/bin/env python3
"""Analyse the diff-guided pair experiment and compare it with pair_debias.

The core condition metrics, exchange-consistency block, length block,
paired comparisons and usage block are imported read-only from
:mod:`pair_debias.analyze`, so the definitions are byte-for-byte the ones used
by the published open-choice result.  This module adds the diff-specific
blocks: change-list compliance and grounding, diff-length strata, the
token-matched diff-vs-control comparison, and the incremental cost ledger.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.stats import holm_adjust, mcnemar_exact, wilson_interval  # noqa: E402

import pair_debias.analyze as pda  # noqa: E402
from pair_debias.common import PairUnit, length_features, load_pairs  # noqa: E402
from pair_diff.common import estimate_tokens  # noqa: E402

MODELS: dict[str, dict[str, str]] = {
    "deepseek-v4.1-flash": {"short": "deepseek", "label": "DeepSeek V4.1 Flash"},
    "mimo-v2.6-flash": {"short": "mimo", "label": "MiMo V2.6 Flash"},
}
MODEL_ORDER = ("deepseek-v4.1-flash", "mimo-v2.6-flash")
CONDITION_ORDER = ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev", "open_fwd", "open_rev")
CONDITION_LABELS = {
    "diff_fwd": "diff + changes-first（正向）",
    "diff_rev": "diff + changes-first（反向）",
    "ctrl_fwd": "长度匹配对照（正向）",
    "ctrl_rev": "长度匹配对照（反向）",
    "open_fwd": "pair_debias 开放四分类（正向）",
    "open_rev": "pair_debias 开放四分类（反向）",
}
TASK_LABELS = {
    "diff": "diff + changes-first",
    "ctrl": "长度匹配对照",
    "open": "pair_debias 开放四分类",
}
DIFF_CHAR_BINS = (
    ("<=200", 0, 200),
    ("201-400", 201, 400),
    ("401-800", 401, 800),
    (">800", 801, 10**9),
)
CHANGED_LINE_BINS = (
    ("1-2", 1, 2),
    ("3-5", 3, 5),
    ("6-10", 6, 10),
    (">10", 11, 10**9),
)


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return float(numerator) / float(denominator)


def _round(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(float(value), digits)


def _wilson(successes: int, total: int) -> dict[str, Any] | None:
    result = wilson_interval(successes, total) if total else None
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


def _safe_mcnemar(
    flags_a: dict[str, bool], flags_b: dict[str, bool], units: list[PairUnit]
) -> dict[str, Any] | None:
    n = len(units)
    if n == 0:
        return None
    a_only = sum(1 for unit in units if flags_a[unit.pair_id] and not flags_b[unit.pair_id])
    b_only = sum(1 for unit in units if not flags_a[unit.pair_id] and flags_b[unit.pair_id])
    result = mcnemar_exact(a_correct_b_wrong=a_only, a_wrong_b_correct=b_only, total=n)
    result["a_correct"] = sum(1 for unit in units if flags_a[unit.pair_id])
    result["b_correct"] = sum(1 for unit in units if flags_b[unit.pair_id])
    result["a_accuracy"] = _round(_ratio(result["a_correct"], n))
    result["b_accuracy"] = _round(_ratio(result["b_correct"], n))
    return result


def _bootstrap_metrics(units: list[PairUnit], metric_fns: dict[str, Any], *, cluster: str = "project") -> dict[str, Any]:
    result = pda._bootstrap(units, metric_fns, cluster=cluster)
    return result


def _load_runs(phase: str, model_key: str) -> dict[str, Any]:
    short = MODELS[model_key]["short"]
    runs: dict[str, Any] = {}
    for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev"):
        path = ROOT / "pair_diff" / "runs" / f"{phase}_{short}_{condition}"
        runs[condition] = pda._load_run(path, condition)
    for condition in ("open_fwd", "open_rev"):
        path = ROOT / "pair_debias" / "runs" / f"{phase}_{short}_{condition}"
        runs[condition] = pda._load_run(path, condition)
    return runs


def _condition_results(units: list[PairUnit], runs: dict[str, Any]) -> dict[str, Any]:
    return {condition: pda._condition_metrics(units, runs[condition], condition) for condition in CONDITION_ORDER}


def _stable_flags(result_a: Any, result_b: Any) -> dict[str, bool]:
    return {
        pair_id: bool(result_a.correct[pair_id] and result_b.correct[pair_id])
        for pair_id in result_a.correct
    }


def _abstain_flags(result: Any) -> dict[str, bool]:
    return {pair_id: bool(result.abstained[pair_id]) for pair_id in result.abstained}


def _heuristic_block(units: list[PairUnit], result: Any) -> dict[str, Any]:
    strata = {
        "heuristic_correct": {"n": 0, "correct": 0, "committed": 0, "chose_shorter": 0},
        "heuristic_wrong": {"n": 0, "correct": 0, "committed": 0, "chose_shorter": 0},
    }
    committed_total = 0
    chose_shorter_total = 0
    by_length_bin: dict[str, dict[str, int]] = {
        "<=5%": {"n": 0, "correct": 0},
        "5-10%": {"n": 0, "correct": 0},
        "10-20%": {"n": 0, "correct": 0},
        ">20%": {"n": 0, "correct": 0},
    }
    for unit in units:
        assignment = result.run.assignments[unit.pair_id]
        decision = result.decision[unit.pair_id]
        committed = decision in {"A", "B"}
        shorter_slot = pda._pick_shorter_slot(unit, assignment, len)
        heuristic_correct = shorter_slot == assignment["vulnerable_slot"]
        key = "heuristic_correct" if heuristic_correct else "heuristic_wrong"
        strata[key]["n"] += 1
        strata[key]["correct"] += int(result.correct[unit.pair_id])
        strata[key]["committed"] += int(committed)
        if committed:
            committed_total += 1
            if decision == shorter_slot:
                strata[key]["chose_shorter"] += 1
                chose_shorter_total += 1
        rel = float(length_features(unit)["relative_char_difference"])
        label = "<=5%" if rel <= 0.05 else ("5-10%" if rel <= 0.10 else ("10-20%" if rel <= 0.20 else ">20%"))
        by_length_bin[label]["n"] += 1
        by_length_bin[label]["correct"] += int(result.correct[unit.pair_id])
    for bucket in strata.values():
        bucket["accuracy"] = _round(_ratio(bucket["correct"], bucket["n"]))
        bucket["choose_shorter_rate_committed"] = _round(
            _ratio(bucket["chose_shorter"], bucket["committed"])
        )
    for bucket in by_length_bin.values():
        bucket["accuracy"] = _round(_ratio(bucket["correct"], bucket["n"]))
    gap = None
    if strata["heuristic_correct"]["accuracy"] is not None and strata["heuristic_wrong"]["accuracy"] is not None:
        gap = strata["heuristic_correct"]["accuracy"] - strata["heuristic_wrong"]["accuracy"]

    def _gap(indices: Sequence[int]) -> float | None:
        subset = [units[index] for index in indices]
        if not subset:
            return None
        correct_h = correct_w = n_h = n_w = 0
        for unit in subset:
            assignment = result.run.assignments[unit.pair_id]
            h = pda._pick_shorter_slot(unit, assignment, len) == assignment["vulnerable_slot"]
            if h:
                n_h += 1
                correct_h += int(result.correct[unit.pair_id])
            else:
                n_w += 1
                correct_w += int(result.correct[unit.pair_id])
        if not n_h or not n_w:
            return None
        return correct_h / n_h - correct_w / n_w

    def _choose_shorter(indices: Sequence[int]) -> float | None:
        subset = [units[index] for index in indices]
        if not subset:
            return None
        committed = chose = 0
        for unit in subset:
            assignment = result.run.assignments[unit.pair_id]
            decision = result.decision[unit.pair_id]
            if decision not in {"A", "B"}:
                continue
            committed += 1
            if decision == pda._pick_shorter_slot(unit, assignment, len):
                chose += 1
        return chose / committed if committed else None

    bootstrap = _bootstrap_metrics(
        units,
        {
            "gap": _gap,
            "choose_shorter": _choose_shorter,
            "da": lambda indices: (
                sum(1 for index in indices if result.correct[units[index].pair_id]) / len(indices)
                if indices
                else None
            ),
        },
    )
    heuristic_flags = {
        unit.pair_id: pda._pick_shorter_slot(unit, result.run.assignments[unit.pair_id], len)
        == result.run.assignments[unit.pair_id]["vulnerable_slot"]
        for unit in units
    }
    committed_units = [unit for unit in units if result.decision[unit.pair_id] in {"A", "B"}]
    return {
        "definition": (
            "The shorter-side heuristic picks the body with fewer characters and breaks ties with A. "
            "heuristic_correct = the heuristic names the vulnerable side. The gap is accuracy on "
            "heuristic-correct pairs minus accuracy on heuristic-wrong pairs; a pure length strategy has "
            "gap 1.0, a content-driven model with equal error rates has gap 0."
        ),
        "strata": strata,
        "gap": _round(gap),
        "gap_bootstrap": bootstrap,
        "committed": committed_total,
        "choose_shorter_committed": _round(_ratio(chose_shorter_total, committed_total)),
        "choose_shorter_all": _round(_ratio(chose_shorter_total, len(units))),
        "heuristic_accuracy": _round(
            _ratio(strata["heuristic_correct"]["n"], len(units))
        ),
        "model_vs_heuristic": _safe_mcnemar(result.correct, heuristic_flags, units),
        "committed_subset_vs_heuristic": {
            "n": len(committed_units),
            "model_correct": sum(1 for unit in committed_units if result.correct[unit.pair_id]),
            "model_da": _round(
                _ratio(sum(1 for unit in committed_units if result.correct[unit.pair_id]), len(committed_units))
            ),
            "heuristic_correct": sum(1 for unit in committed_units if heuristic_flags[unit.pair_id]),
            "heuristic_da": _round(
                _ratio(sum(1 for unit in committed_units if heuristic_flags[unit.pair_id]), len(committed_units))
            ),
            "mcnemar": _safe_mcnemar(result.correct, heuristic_flags, committed_units),
        },
        "by_relative_length": by_length_bin,
    }


def _compliance_block(units: list[PairUnit], result: Any) -> dict[str, Any]:
    counts = {
        "parsed": 0,
        "schema_exact": 0,
        "changes_first": 0,
        "changes_before_verdict_raw": 0,
        "changes_present": 0,
        "changes_all_valid": 0,
        "changes_total": 0,
        "grounded_items": 0,
        "cited_lines": 0,
        "grounded_cited_lines": 0,
        "covered_changed_lines": 0,
        "changed_lines_total": 0,
        "out_of_range_lines": 0,
    }
    by_correct = {
        "correct": Counter(),
        "incorrect": Counter(),
    }
    key_orders: Counter[str] = Counter()
    for unit in units:
        record = result.run.by_pair[unit.pair_id]
        parsed = record.get("parsed")
        if not isinstance(parsed, dict):
            continue
        validation = record.get("validation") or {}
        changes = validation.get("changes") or {}
        counts["parsed"] += 1
        counts["schema_exact"] += int(bool(validation.get("schema_exact")))
        counts["changes_first"] += int(bool(validation.get("changes_first")))
        counts["changes_before_verdict_raw"] += int(bool(validation.get("changes_before_verdict_raw")))
        counts["changes_present"] += int(bool(validation.get("changes_present")))
        counts["changes_all_valid"] += int(bool(validation.get("changes_all_valid")))
        counts["changes_total"] += int(changes.get("changes_count") or 0)
        counts["grounded_items"] += int(changes.get("grounded_items") or 0)
        counts["cited_lines"] += int(changes.get("cited_lines") or 0)
        counts["grounded_cited_lines"] += int(changes.get("grounded_cited_lines") or 0)
        counts["covered_changed_lines"] += int(changes.get("covered_changed_lines") or 0)
        counts["changed_lines_total"] += int(changes.get("changed_lines_total") or 0)
        counts["out_of_range_lines"] += int(changes.get("out_of_range_lines") or 0)
        order = tuple(parsed.get("raw_keys") or [])
        key_orders[" > ".join(order)] += 1
        bucket = "correct" if result.correct[unit.pair_id] else "incorrect"
        by_correct[bucket]["n"] += 1
        by_correct[bucket]["changes_first"] += int(bool(validation.get("changes_first")))
        by_correct[bucket]["grounded_items"] += int(changes.get("grounded_items") or 0)
        by_correct[bucket]["changes_total"] += int(changes.get("changes_count") or 0)
        by_correct[bucket]["cited_lines"] += int(changes.get("cited_lines") or 0)
        by_correct[bucket]["grounded_cited_lines"] += int(changes.get("grounded_cited_lines") or 0)

    def rate(numerator: int, denominator: int) -> float | None:
        return None if denominator == 0 else round(numerator / denominator, 6)

    rendered_correct = {}
    for bucket, counter in by_correct.items():
        rendered_correct[bucket] = {
            "n": counter["n"],
            "changes_first_rate": rate(counter["changes_first"], counter["n"]),
            "grounded_item_rate": rate(counter["grounded_items"], counter["changes_total"]),
            "cited_line_precision": rate(counter["grounded_cited_lines"], counter["cited_lines"]),
        }
    return {
        "parsed": counts["parsed"],
        "schema_exact": counts["schema_exact"],
        "schema_exact_rate": rate(counts["schema_exact"], counts["parsed"]),
        "changes_first": counts["changes_first"],
        "changes_first_rate": rate(counts["changes_first"], counts["parsed"]),
        "changes_before_verdict_raw": counts["changes_before_verdict_raw"],
        "changes_before_verdict_raw_rate": rate(counts["changes_before_verdict_raw"], counts["parsed"]),
        "changes_present_rate": rate(counts["changes_present"], counts["parsed"]),
        "changes_all_valid_rate": rate(counts["changes_all_valid"], counts["parsed"]),
        "semantic_changes_total": counts["changes_total"],
        "grounded_items": counts["grounded_items"],
        "grounded_item_rate": rate(counts["grounded_items"], counts["changes_total"]),
        "cited_lines": counts["cited_lines"],
        "grounded_cited_lines": counts["grounded_cited_lines"],
        "cited_line_precision": rate(counts["grounded_cited_lines"], counts["cited_lines"]),
        "changed_line_recall": rate(counts["covered_changed_lines"], counts["changed_lines_total"]),
        "out_of_range_lines": counts["out_of_range_lines"],
        "by_correctness": rendered_correct,
        "top_key_orders": dict(key_orders.most_common(5)),
    }


def _prompt_tokens(result: Any) -> dict[str, int | None]:
    values: dict[str, int | None] = {}
    for unit in result.correct:
        record = result.run.by_pair[unit]
        response = record.get("response") or {}
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else None
        value = usage.get("prompt_tokens") if usage else None
        values[unit] = int(value) if isinstance(value, int) and not isinstance(value, bool) else None
    return values


def _token_match_block(units: list[PairUnit], diff_result: Any, ctrl_result: Any) -> dict[str, Any]:
    diff_tokens = _prompt_tokens(diff_result)
    ctrl_tokens = _prompt_tokens(ctrl_result)
    pairs = []
    for unit in units:
        d = diff_tokens.get(unit.pair_id)
        c = ctrl_tokens.get(unit.pair_id)
        if d and c:
            pairs.append((unit, d, c, abs(c - d) / max(d, 1)))
    ratios = [c / d for _, d, c, _ in pairs]
    diffs = [c - d for _, d, c, _ in pairs]
    matched = [item for item in pairs if item[3] <= 0.05]
    matched_units = [item[0] for item in matched]
    comparison = (
        pda._comparison(
            matched_units,
            diff_result.correct,
            ctrl_result.correct,
            label_a="diff",
            label_b="ctrl",
            resamples=10000,
            seed=42,
        )
        if matched_units
        else None
    )
    return {
        "n_pairs": len(pairs),
        "median_prompt_tokens_diff": sorted(d for _, d, _, _ in pairs)[len(pairs) // 2] if pairs else None,
        "median_prompt_tokens_ctrl": sorted(c for _, _, c, _ in pairs)[len(pairs) // 2] if pairs else None,
        "mean_token_difference_ctrl_minus_diff": _round(sum(diffs) / len(diffs)) if diffs else None,
        "median_ratio_ctrl_over_diff": _round(sorted(ratios)[len(ratios) // 2]) if ratios else None,
        "within_5pct": sum(1 for value in ratios if abs(value - 1.0) <= 0.05),
        "within_10pct": sum(1 for value in ratios if abs(value - 1.0) <= 0.10),
        "matched_n": len(matched_units),
        "matched_comparison": comparison,
        "definition": (
            "Provider-reported prompt_tokens per pair; the control was matched to the diff block with a "
            "tiktoken proxy before the run. The matched subset is a post-hoc sensitivity analysis on pairs "
            "where the realized prompt-token difference is <=5%."
        ),
    }


def _diff_strata_block(units: list[PairUnit], results: dict[str, Any]) -> dict[str, Any]:
    diff_run = results["diff_fwd"].run
    bins: dict[str, dict[str, Any]] = {}
    for label, low, high in DIFF_CHAR_BINS:
        bins[label] = {
            "n": 0,
            "diff_correct": 0,
            "ctrl_correct": 0,
            "open_correct": 0,
            "changed_line_bins": {},
        }
    for label, low, high in CHANGED_LINE_BINS:
        for bucket in bins.values():
            bucket["changed_line_bins"][label] = {"n": 0, "diff_correct": 0, "ctrl_correct": 0, "open_correct": 0}
    for unit in units:
        prompt = diff_run.by_pair[unit.pair_id].get("prompt") or {}
        diff_chars = int(prompt.get("diff_chars") or 0)
        changed = int(prompt.get("changed_lines_total") or 0)
        bucket_label = next(label for label, low, high in DIFF_CHAR_BINS if low <= diff_chars <= high)
        bucket = bins[bucket_label]
        bucket["n"] += 1
        bucket["diff_correct"] += int(results["diff_fwd"].correct[unit.pair_id])
        bucket["ctrl_correct"] += int(results["ctrl_fwd"].correct[unit.pair_id])
        bucket["open_correct"] += int(results["open_fwd"].correct[unit.pair_id])
        line_label = next(label for label, low, high in CHANGED_LINE_BINS if low <= changed <= high)
        line_bucket = bucket["changed_line_bins"][line_label]
        line_bucket["n"] += 1
        line_bucket["diff_correct"] += int(results["diff_fwd"].correct[unit.pair_id])
        line_bucket["ctrl_correct"] += int(results["ctrl_fwd"].correct[unit.pair_id])
        line_bucket["open_correct"] += int(results["open_fwd"].correct[unit.pair_id])
    for bucket in bins.values():
        for key in ("diff", "ctrl", "open"):
            bucket[f"{key}_da"] = _round(_ratio(bucket[f"{key}_correct"], bucket["n"]))
        for line_bucket in bucket["changed_line_bins"].values():
            for key in ("diff", "ctrl", "open"):
                line_bucket[f"{key}_da"] = _round(_ratio(line_bucket[f"{key}_correct"], line_bucket["n"]))
    return {
        "bin_definition": "hidden diff size from the generated unified diff; the same pair is in the same bin for diff, ctrl and open",
        "by_diff_chars": bins,
    }


def _position_block(result: Any) -> dict[str, Any]:
    metrics = result.metrics["position_bias"]
    decisions = result.decision
    committed = [decision for decision in decisions.values() if decision in {"A", "B"}]
    choose_b = sum(1 for decision in committed if decision == "B")
    return {
        **metrics,
        "choose_B_share_of_committed": _round(_ratio(choose_b, len(committed))),
        "committed": len(committed),
    }


def _cost_block(runs: dict[str, Any], results: dict[str, Any]) -> dict[str, Any]:
    usages = {condition: pda._usage_block(runs[condition]) for condition in CONDITION_ORDER}
    arms = {
        "open": ["open_fwd", "open_rev"],
        "ctrl": ["ctrl_fwd", "ctrl_rev"],
        "diff": ["diff_fwd", "diff_rev"],
    }
    summary: dict[str, Any] = {}
    for arm, conditions in arms.items():
        requests = sum(usages[condition]["requests"] for condition in conditions)
        prompt_tokens = sum(usages[condition]["prompt_tokens"] for condition in conditions)
        completion_tokens = sum(usages[condition]["completion_tokens"] for condition in conditions)
        cost = sum(
            usages[condition]["cost_usd_configured"] or 0.0 for condition in conditions
        )
        correct = sum(
            sum(1 for value in results[condition].correct.values() if value)
            for condition in conditions
        )
        summary[arm] = {
            "requests": requests,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd_configured": _round(cost),
            "correct_pair_orders": correct,
            "cost_per_100_pair_orders": _round(100.0 * cost / requests) if requests else None,
            "cost_per_correct": _round(cost / correct) if correct else None,
            "by_condition": {condition: usages[condition] for condition in conditions},
        }
    for arm_a, arm_b in (("diff", "ctrl"), ("diff", "open"), ("ctrl", "open")):
        delta_cost = (summary[arm_a]["cost_usd_configured"] or 0.0) - (
            summary[arm_b]["cost_usd_configured"] or 0.0
        )
        delta_correct = summary[arm_a]["correct_pair_orders"] - summary[arm_b]["correct_pair_orders"]
        summary[f"{arm_a}_minus_{arm_b}"] = {
            "delta_cost_usd": _round(delta_cost),
            "delta_correct_pair_orders": delta_correct,
            "incremental_cost_per_extra_correct": _round(delta_cost / delta_correct)
            if delta_correct > 0
            else None,
            "note": (
                "No positive incremental cost-effectiveness: the arm did not add a correct pair-order."
                if delta_correct <= 0
                else "Positive delta_correct; interpret with the paired McNemar result, not this ratio alone."
            ),
        }
    return {
        "by_arm": summary,
        "note": (
            "cost_usd_configured applies each run's configured list prices to provider-reported tokens. "
            "It is not a bill; provider list/allowance snapshots are kept per condition."
        ),
    }


def _length_effect_block(units: list[PairUnit], results: dict[str, Any]) -> dict[str, Any]:
    def _gap(result: Any, indices: Sequence[int]) -> float | None:
        correct_h = correct_w = n_h = n_w = 0
        for index in indices:
            unit = units[index]
            assignment = result.run.assignments[unit.pair_id]
            h = pda._pick_shorter_slot(unit, assignment, len) == assignment["vulnerable_slot"]
            if h:
                n_h += 1
                correct_h += int(result.correct[unit.pair_id])
            else:
                n_w += 1
                correct_w += int(result.correct[unit.pair_id])
        if not n_h or not n_w:
            return None
        return correct_h / n_h - correct_w / n_w

    def _choose(result: Any, indices: Sequence[int]) -> float | None:
        committed = chose = 0
        for index in indices:
            unit = units[index]
            assignment = result.run.assignments[unit.pair_id]
            decision = result.decision[unit.pair_id]
            if decision not in {"A", "B"}:
                continue
            committed += 1
            if decision == pda._pick_shorter_slot(unit, assignment, len):
                chose += 1
        return chose / committed if committed else None

    def _difference(metric: Any, a: str, b: str) -> Any:
        def inner(indices: Sequence[int]) -> float | None:
            value_a = metric(results[a], indices)
            value_b = metric(results[b], indices)
            if value_a is None or value_b is None:
                return None
            return value_a - value_b

        return inner

    bootstrap = _bootstrap_metrics(
        units,
        {
            "gap_diff_minus_ctrl": _difference(_gap, "diff_fwd", "ctrl_fwd"),
            "gap_diff_minus_open": _difference(_gap, "diff_fwd", "open_fwd"),
            "gap_ctrl_minus_open": _difference(_gap, "ctrl_fwd", "open_fwd"),
            "choose_shorter_diff_minus_ctrl": _difference(_choose, "diff_fwd", "ctrl_fwd"),
            "choose_shorter_diff_minus_open": _difference(_choose, "diff_fwd", "open_fwd"),
        },
    )
    subsets = {}
    for name, predicate in (
        ("vulnerable_longer", lambda unit: length_features(unit)["stratum"] == "vulnerable_longer"),
        ("vulnerable_shorter", lambda unit: length_features(unit)["stratum"] == "vulnerable_shorter"),
        ("tie", lambda unit: length_features(unit)["stratum"] == "tie"),
    ):
        subset_units = [unit for unit in units if predicate(unit)]
        comparisons = {}
        for label, a, b in (
            ("diff_fwd_vs_ctrl_fwd", "diff_fwd", "ctrl_fwd"),
            ("diff_rev_vs_ctrl_rev", "diff_rev", "ctrl_rev"),
            ("diff_fwd_vs_open_fwd", "diff_fwd", "open_fwd"),
            ("diff_rev_vs_open_rev", "diff_rev", "open_rev"),
        ):
            comparisons[label] = (
                pda._comparison(
                    subset_units,
                    results[a].correct,
                    results[b].correct,
                    label_a=a,
                    label_b=b,
                    resamples=10000,
                    seed=42,
                )
                if subset_units
                else None
            )
        subsets[name] = {
            "n": len(subset_units),
            "definition": (
                "vulnerable_longer: the vulnerable body is longer, so the shorter-side heuristic is wrong; "
                "vulnerable_shorter: the heuristic is right; tie: equal character length, heuristic breaks to A."
            ),
            "comparisons": comparisons,
        }
    return {
        "definition": (
            "Bootstrap of paired differences in the length gap and in the shorter-side choice rate. "
            "A negative gap difference means diff reduced the accuracy gap between heuristic-correct and "
            "heuristic-wrong pairs; a negative choose-shorter difference means less length-following."
        ),
        "bootstrap": bootstrap,
        "subsets": subsets,
    }


def _change_relevance_block(units: list[PairUnit], result: Any) -> dict[str, Any]:
    groups = {
        "any_security_relevant": {"n": 0, "correct": 0, "committed": 0, "neither": 0, "both": 0},
        "no_security_relevant": {"n": 0, "correct": 0, "committed": 0, "neither": 0, "both": 0},
    }
    for unit in units:
        record = result.run.by_pair[unit.pair_id]
        parsed = record.get("parsed") or {}
        changes = parsed.get("semantic_changes") if isinstance(parsed, dict) else None
        security = bool(
            isinstance(changes, list)
            and any(isinstance(item, dict) and item.get("security_relevant") is True for item in changes)
        )
        key = "any_security_relevant" if security else "no_security_relevant"
        decision = result.decision[unit.pair_id]
        groups[key]["n"] += 1
        groups[key]["correct"] += int(result.correct[unit.pair_id])
        groups[key]["committed"] += int(decision in {"A", "B"})
        groups[key]["neither"] += int(decision == "neither")
        groups[key]["both"] += int(decision == "both")
    for bucket in groups.values():
        bucket["da"] = _round(_ratio(bucket["correct"], bucket["n"]))
        bucket["committed_da"] = _round(_ratio(bucket["correct"], bucket["committed"]))
        bucket["neither_rate"] = _round(_ratio(bucket["neither"], bucket["n"]))
        bucket["both_rate"] = _round(_ratio(bucket["both"], bucket["n"]))
    return {
        "definition": (
            "Exploratory split by whether the model's own change list contains at least one "
            "security_relevant=true item. It describes the change-first mechanism; it is not randomized."
        ),
        "groups": groups,
    }


def _examples_block(units: list[PairUnit], results: dict[str, Any]) -> dict[str, Any]:
    def _entry(unit: PairUnit) -> dict[str, Any]:
        record = results["diff_fwd"].run.by_pair[unit.pair_id]
        parsed = record.get("parsed") or {}
        changes = parsed.get("semantic_changes") if isinstance(parsed, dict) else []
        summaries = [
            str(item.get("summary") or "")[:240]
            for item in (changes or [])
            if isinstance(item, dict) and item.get("summary")
        ][:3]
        return {
            "pair_id": unit.pair_id,
            "project": unit.project,
            "diff_decision": results["diff_fwd"].decision[unit.pair_id],
            "ctrl_decision": results["ctrl_fwd"].decision[unit.pair_id],
            "open_decision": results["open_fwd"].decision[unit.pair_id],
            "diff_correct": results["diff_fwd"].correct[unit.pair_id],
            "ctrl_correct": results["ctrl_fwd"].correct[unit.pair_id],
            "open_correct": results["open_fwd"].correct[unit.pair_id],
            "semantic_changes": summaries,
            "rationale": str(parsed.get("rationale") or "")[:320],
        }

    buckets: dict[str, list[dict[str, Any]]] = {
        "diff_only_correct": [],
        "ctrl_only_correct": [],
        "diff_neither_ctrl_ab": [],
        "diff_ab_ctrl_neither": [],
        "diff_and_ctrl_wrong_open_correct": [],
    }
    for unit in units:
        d = results["diff_fwd"]
        c = results["ctrl_fwd"]
        o = results["open_fwd"]
        if d.correct[unit.pair_id] and not c.correct[unit.pair_id] and not o.correct[unit.pair_id]:
            buckets["diff_only_correct"].append(_entry(unit))
        if c.correct[unit.pair_id] and not d.correct[unit.pair_id] and not o.correct[unit.pair_id]:
            buckets["ctrl_only_correct"].append(_entry(unit))
        if d.decision[unit.pair_id] == "neither" and c.decision[unit.pair_id] in {"A", "B"}:
            buckets["diff_neither_ctrl_ab"].append(_entry(unit))
        if d.decision[unit.pair_id] in {"A", "B"} and c.decision[unit.pair_id] == "neither":
            buckets["diff_ab_ctrl_neither"].append(_entry(unit))
        if not d.correct[unit.pair_id] and not c.correct[unit.pair_id] and o.correct[unit.pair_id]:
            buckets["diff_and_ctrl_wrong_open_correct"].append(_entry(unit))
    return {
        "definition": "Deterministic examples from the forward order; chosen by decision/correctness pattern, not by hand.",
        "counts": {name: len(items) for name, items in buckets.items()},
        "examples": {name: items[:3] for name, items in buckets.items()},
    }


def _change_subset_reference(units: list[PairUnit], results: dict[str, Any]) -> dict[str, Any]:
    no_security = []
    any_security = []
    for unit in units:
        parsed = (results["diff_fwd"].run.by_pair[unit.pair_id].get("parsed") or {})
        changes = parsed.get("semantic_changes") if isinstance(parsed, dict) else None
        has_security = bool(
            isinstance(changes, list)
            and any(isinstance(item, dict) and item.get("security_relevant") is True for item in changes)
        )
        (any_security if has_security else no_security).append(unit)
    subsets: dict[str, Any] = {}
    for name, subset in (
        ("any_security_relevant", any_security),
        ("no_security_relevant", no_security),
    ):
        conditions = {}
        for condition in ("diff_fwd", "ctrl_fwd", "open_fwd", "diff_rev", "ctrl_rev", "open_rev"):
            result = results[condition]
            correct = sum(1 for unit in subset if result.correct[unit.pair_id])
            conditions[condition] = {
                "n": len(subset),
                "correct": correct,
                "da": _round(_ratio(correct, len(subset))),
                "decisions": {
                    decision: sum(1 for unit in subset if result.decision[unit.pair_id] == decision)
                    for decision in ("A", "B", "both", "neither", "invalid")
                },
            }
        subsets[name] = {"n": len(subset), "conditions": conditions}
    return {
        "definition": (
            "Pairs split by whether the diff_fwd change list contains a security_relevant=true item. "
            "The split is selected by the model's own change list, so it is descriptive; open/ctrl are "
            "evaluated on the same pairs as a reference, not as a randomized control."
        ),
        "subsets": subsets,
    }


def _model_block(units: list[PairUnit], runs: dict[str, Any], results: dict[str, Any]) -> dict[str, Any]:
    exchange = {
        "diff": pda._exchange_block(units, results["diff_fwd"], results["diff_rev"]),
        "ctrl": pda._exchange_block(units, results["ctrl_fwd"], results["ctrl_rev"]),
        "open": pda._exchange_block(units, results["open_fwd"], results["open_rev"]),
    }
    stable = {
        "diff": _stable_flags(results["diff_fwd"], results["diff_rev"]),
        "ctrl": _stable_flags(results["ctrl_fwd"], results["ctrl_rev"]),
        "open": _stable_flags(results["open_fwd"], results["open_rev"]),
    }
    comparisons: dict[str, Any] = {
        "diff_fwd_vs_ctrl_fwd": pda._comparison(
            units,
            results["diff_fwd"].correct,
            results["ctrl_fwd"].correct,
            label_a="diff_fwd",
            label_b="ctrl_fwd",
            resamples=10000,
            seed=42,
        ),
        "diff_rev_vs_ctrl_rev": pda._comparison(
            units,
            results["diff_rev"].correct,
            results["ctrl_rev"].correct,
            label_a="diff_rev",
            label_b="ctrl_rev",
            resamples=10000,
            seed=42,
        ),
        "diff_stable_vs_ctrl_stable": pda._comparison(
            units,
            stable["diff"],
            stable["ctrl"],
            label_a="diff_stable",
            label_b="ctrl_stable",
            resamples=10000,
            seed=42,
        ),
        "diff_fwd_vs_open_fwd": pda._comparison(
            units,
            results["diff_fwd"].correct,
            results["open_fwd"].correct,
            label_a="diff_fwd",
            label_b="open_fwd",
            resamples=10000,
            seed=42,
        ),
        "diff_rev_vs_open_rev": pda._comparison(
            units,
            results["diff_rev"].correct,
            results["open_rev"].correct,
            label_a="diff_rev",
            label_b="open_rev",
            resamples=10000,
            seed=42,
        ),
        "diff_stable_vs_open_stable": pda._comparison(
            units,
            stable["diff"],
            stable["open"],
            label_a="diff_stable",
            label_b="open_stable",
            resamples=10000,
            seed=42,
        ),
        "ctrl_fwd_vs_open_fwd": pda._comparison(
            units,
            results["ctrl_fwd"].correct,
            results["open_fwd"].correct,
            label_a="ctrl_fwd",
            label_b="open_fwd",
            resamples=10000,
            seed=42,
        ),
        "ctrl_rev_vs_open_rev": pda._comparison(
            units,
            results["ctrl_rev"].correct,
            results["open_rev"].correct,
            label_a="ctrl_rev",
            label_b="open_rev",
            resamples=10000,
            seed=42,
        ),
        "ctrl_stable_vs_open_stable": pda._comparison(
            units,
            stable["ctrl"],
            stable["open"],
            label_a="ctrl_stable",
            label_b="open_stable",
            resamples=10000,
            seed=42,
        ),
    }
    # Abstention comparisons: did the presentation change the rate of both/neither?
    abstention_comparisons = {}
    for label, a, b in (
        ("diff_vs_ctrl_fwd", "diff_fwd", "ctrl_fwd"),
        ("diff_vs_ctrl_rev", "diff_rev", "ctrl_rev"),
        ("diff_vs_open_fwd", "diff_fwd", "open_fwd"),
        ("diff_vs_open_rev", "diff_rev", "open_rev"),
        ("ctrl_vs_open_fwd", "ctrl_fwd", "open_fwd"),
        ("ctrl_vs_open_rev", "ctrl_rev", "open_rev"),
    ):
        abstention_comparisons[label] = pda._comparison(
            units,
            _abstain_flags(results[a]),
            _abstain_flags(results[b]),
            label_a=a,
            label_b=b,
            resamples=10000,
            seed=42,
        )
    length_shortcut = {
        condition: _heuristic_block(units, results[condition]) for condition in CONDITION_ORDER
    }
    length_effect = _length_effect_block(units, results)

    compliance = {
        condition: _compliance_block(units, results[condition])
        for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev")
    }
    change_relevance = {
        condition: _change_relevance_block(units, results[condition])
        for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev")
    }
    token_match = {
        "diff_fwd_vs_ctrl_fwd": _token_match_block(units, results["diff_fwd"], results["ctrl_fwd"]),
        "diff_rev_vs_ctrl_rev": _token_match_block(units, results["diff_rev"], results["ctrl_rev"]),
    }
    diff_strata = _diff_strata_block(units, results)
    position = {condition: _position_block(results[condition]) for condition in CONDITION_ORDER}
    cost = _cost_block(runs, results)

    # Pre-declared Holm families (each model separately).
    families: dict[str, dict[str, Any]] = {}
    for family_name, keys in (
        ("diff_vs_ctrl", ("diff_fwd_vs_ctrl_fwd", "diff_rev_vs_ctrl_rev", "diff_stable_vs_ctrl_stable")),
        ("diff_vs_open", ("diff_fwd_vs_open_fwd", "diff_rev_vs_open_rev", "diff_stable_vs_open_stable")),
        ("ctrl_vs_open", ("ctrl_fwd_vs_open_fwd", "ctrl_rev_vs_open_rev", "ctrl_stable_vs_open_stable")),
    ):
        p_values = [float(comparisons[key]["mcnemar"]["p_value"]) for key in keys]
        adjusted = holm_adjust(p_values)
        families[family_name] = {
            "tests": [
                {
                    "comparison": key,
                    "p_value": p_value,
                    "holm_p": adjusted[index],
                }
                for index, (key, p_value) in enumerate(zip(keys, p_values))
            ]
        }

    return {
        "model": runs["diff_fwd"].model,
        "conditions": {condition: results[condition].metrics for condition in CONDITION_ORDER},
        "exchange": exchange,
        "stable": {
            "definition": "both orders correct; position-insensitive primary endpoint",
            "counts": {task: sum(1 for value in stable[task].values() if value) for task in stable},
            "da": {task: _round(_ratio(sum(1 for value in stable[task].values() if value), len(units))) for task in stable},
        },
        "comparisons": comparisons,
        "abstention_comparisons": abstention_comparisons,
        "holm_families": families,
        "length_shortcut": length_shortcut,
        "length_effect": length_effect,
        "compliance": compliance,
        "change_relevance": change_relevance,
        "change_subset_reference": _change_subset_reference(units, results),
        "examples": _examples_block(units, results),
        "token_match": token_match,
        "diff_strata": diff_strata,
        "position": position,
        "cost": cost,
        "run_metadata": {condition: pda._run_metadata(runs[condition]) for condition in CONDITION_ORDER},
    }


def _fmt_p(value: float | None) -> str:
    if value is None:
        return "—"
    if value < 0.0001:
        return f"{value:.2e}"
    return f"{value:.4f}"


def _fmt_pct(value: float | None, digits: int = 2) -> str:
    return "—" if value is None else f"{100.0 * value:.{digits}f}%"


def _fmt_num(value: float | None, digits: int = 4) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def _ci(block: dict[str, Any] | None, metric: str = "difference") -> str:
    if not block:
        return "—"
    item = (block.get("metrics") or {}).get(metric)
    if not item:
        return "—"
    low, high = item.get("ci_low"), item.get("ci_high")
    if low is None or high is None:
        return "—"
    return f"[{100.0 * low:+.2f}, {100.0 * high:+.2f}] pp"


def _render_model_markdown(model_key: str, block: dict[str, Any]) -> str:
    label = MODELS[model_key]["label"]
    lines = [f"# {label}：diff-guided pair evaluation", ""]
    dataset_path = block.get("dataset_path", "splits/test_pairs_180.json")
    dataset_sha = block.get("dataset_sha256", "")
    lines.append(f"数据集：`{dataset_path}`（SHA-256 `{dataset_sha}`）。")
    lines.append("")
    lines.append("## 1. 主表")
    lines.append("")
    lines.append("| 条件 | n | DA | committed DA | 交换一致 DA | both+neither | 位置偏差 A−B | Fisher p | 成本 USD |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for condition in CONDITION_ORDER:
        metrics = block["conditions"][condition]
        task = condition.split("_")[0]
        exchange = block["exchange"][task]["da_both_orders"]
        position = metrics["position_bias"]
        cost = block["cost"]["by_arm"]["diff" if task == "diff" else task]
        per_condition_cost = cost["by_condition"][condition]["cost_usd_configured"]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {metrics['counts']['pairs']} | "
            f"{_fmt_pct(metrics['accuracy']['all_pairs'])} | "
            f"{_fmt_pct(metrics['accuracy']['committed_picks'])} | "
            f"{_fmt_pct(exchange)} | "
            f"{_fmt_pct(metrics['abstention']['rate'])} | "
            f"{100.0 * (position['difference_da_A_minus_da_B_all'] or 0):+.2f} pp | "
            f"{_fmt_p(position['fisher_exact_p_all'])} | "
            f"{_fmt_num(per_condition_cost, 6)} |"
        )
    lines.append("")
    lines.append("### 1b. 弃权构成（both / neither）")
    lines.append("")
    lines.append("| 条件 | both | neither | both+neither |")
    lines.append("| --- | ---: | ---: | ---: |")
    for condition in CONDITION_ORDER:
        metrics = block["conditions"][condition]
        abstention = metrics["abstention"]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {abstention['both_vulnerable']} "
            f"({_fmt_pct(_ratio(abstention['both_vulnerable'], metrics['counts']['pairs']))}) | "
            f"{abstention['both_safe']} "
            f"({_fmt_pct(_ratio(abstention['both_safe'], metrics['counts']['pairs']))}) | "
            f"{_fmt_pct(abstention['rate'])} |"
        )
    lines.append("")
    lines.append("读法：DA 的分母是 n（见表）；committed DA 只以实际给出 A/B 的输出为分母；交换一致 DA 要求正反两序都判对；both+neither 是开放弃权率；位置偏差是漏洞版本在 A 与在 B 时的 DA 差。")
    lines.append("")
    lines.append("## 2. diff、长度对照与开放条件的两两比较")
    lines.append("")
    lines.append("")
    lines.append("| 比较 | Δ (A−B) | McNemar p | Holm p | 项目聚类 Δ 95% CI |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    family_lookup = {
        item["comparison"]: item
        for family in block["holm_families"].values()
        for item in family["tests"]
    }
    for key in (
        "diff_fwd_vs_ctrl_fwd",
        "diff_rev_vs_ctrl_rev",
        "diff_stable_vs_ctrl_stable",
        "diff_fwd_vs_open_fwd",
        "diff_rev_vs_open_rev",
        "diff_stable_vs_open_stable",
        "ctrl_fwd_vs_open_fwd",
        "ctrl_rev_vs_open_rev",
        "ctrl_stable_vs_open_stable",
    ):
        comparison = block["comparisons"][key]
        holm = family_lookup.get(key, {}).get("holm_p")
        lines.append(
            f"| {key} | {100.0 * (comparison['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(comparison['mcnemar']['p_value'])} | {_fmt_p(holm)} | "
            f"{_ci(comparison['bootstrap_project'])} |"
        )
    lines.append("")
    lines.append("## 3. 长度捷径")
    lines.append("")
    lines.append("| 条件 | H 正确子集 DA | H 错误子集 DA | gap | 选较短比例 | 模型 vs 启发式 p |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for condition in CONDITION_ORDER:
        item = block["length_shortcut"][condition]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | "
            f"{_fmt_pct(item['strata']['heuristic_correct']['accuracy'])} | "
            f"{_fmt_pct(item['strata']['heuristic_wrong']['accuracy'])} | "
            f"{100.0 * (item['gap'] or 0):+.2f} pp | "
            f"{_fmt_pct(item['choose_shorter_committed'])} | "
            f"{_fmt_p(item['model_vs_heuristic']['p_value'] if item['model_vs_heuristic'] else None)} |"
        )
    lines.append("")
    lines.append("`H` 是“选较短版本、等长选 A”的启发式。gap = H 正确子集准确率 − H 错误子集准确率；纯长度策略的 gap 为 100 pp，内容驱动且误差均匀的模型 gap 接近 0。")
    lines.append("")
    lines.append("### 3b. 长度效应差（diff − 对照）")
    lines.append("")
    lines.append("| 指标 | 点估计 | 项目聚类 95% CI |")
    lines.append("| --- | ---: | --- |")
    for key in (
        "gap_diff_minus_ctrl",
        "gap_diff_minus_open",
        "gap_ctrl_minus_open",
        "choose_shorter_diff_minus_ctrl",
        "choose_shorter_diff_minus_open",
    ):
        item = (block["length_effect"]["bootstrap"].get("metrics") or {}).get(key) or {}
        low, high = item.get("ci_low"), item.get("ci_high")
        median = item.get("bootstrap_median")
        if low is None or high is None or median is None:
            lines.append(f"| {key} | — | — |")
        else:
            lines.append(f"| {key} | {100.0 * median:+.2f} pp | [{100.0 * low:+.2f}, {100.0 * high:+.2f}] pp |")
    lines.append("")
    lines.append("### 3c. 长度子集（正向）")
    lines.append("")
    lines.append("| 子集 | n | diff−ctrl Δ | McNemar p | diff−open Δ | McNemar p |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for subset in ("vulnerable_longer", "vulnerable_shorter", "tie"):
        item = block["length_effect"]["subsets"][subset]
        c1 = item["comparisons"]["diff_fwd_vs_ctrl_fwd"]
        c2 = item["comparisons"]["diff_fwd_vs_open_fwd"]
        if c1 is None or c2 is None:
            lines.append(f"| {subset} | {item['n']} | — | — | — | — |")
            continue
        lines.append(
            f"| {subset} | {item['n']} | {100.0 * (c1['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(c1['mcnemar']['p_value'])} | {100.0 * (c2['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(c2['mcnemar']['p_value'])} |"
        )
    lines.append("")
    lines.append("`vulnerable_longer` 是较短侧启发式必错的子集；diff 若在这个子集上高于 ctrl，才说明它使用了 diff 内容而不是长度。")
    lines.append("")
    lines.append("## 4. 实际提示长度与长度匹配")
    lines.append("")
    lines.append("| 比较 | 中位 diff prompt tokens | 中位 ctrl prompt tokens | 中位 ctrl/diff | ≤5% 对数 | 匹配子集 n | 匹配子集 diff−ctrl | McNemar p |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, item in block["token_match"].items():
        comp = item["matched_comparison"]
        lines.append(
            f"| {key} | {_fmt_num(item['median_prompt_tokens_diff'], 1)} | "
            f"{_fmt_num(item['median_prompt_tokens_ctrl'], 1)} | "
            f"{_fmt_num(item['median_ratio_ctrl_over_diff'], 4)} | "
            f"{item['within_5pct']}/{item['n_pairs']} | {item['matched_n']} | "
            f"{_fmt_pct(comp['difference_all'] if comp else None)} | "
            f"{_fmt_p(comp['mcnemar']['p_value'] if comp else None)} |"
        )
    lines.append("")
    lines.append("## 5. diff 长度分层（正向）")
    lines.append("")
    lines.append("| diff 字符数 | n | diff DA | ctrl DA | open DA |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for label, _, _ in DIFF_CHAR_BINS:
        item = block["diff_strata"]["by_diff_chars"][label]
        lines.append(
            f"| {label} | {item['n']} | {_fmt_pct(item['diff_da'])} | "
            f"{_fmt_pct(item['ctrl_da'])} | {_fmt_pct(item['open_da'])} |"
        )
    lines.append("")
    lines.append("## 6. 变更清单合规与接地")
    lines.append("")
    lines.append("| 条件 | changes-first | schema exact | 有变更列表 | 条目接地率 | 引用行精确率 | 变更行召回率 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev"):
        item = block["compliance"][condition]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | {_fmt_pct(item['changes_first_rate'])} | "
            f"{_fmt_pct(item['schema_exact_rate'])} | {_fmt_pct(item['changes_present_rate'])} | "
            f"{_fmt_pct(item['grounded_item_rate'])} | {_fmt_pct(item['cited_line_precision'])} | "
            f"{_fmt_pct(item['changed_line_recall'])} |"
        )
    lines.append("")
    lines.append("接地率以生成的 unified diff 的变更行为参考：条目至少引用一条真实变更行才算接地；引用行精确率 = 真实变更行引用数 / 全部引用行数。")
    lines.append("")
    lines.append("### 6b. 变更清单的安全相关性分组（探索性）")
    lines.append("")
    lines.append("| 条件 | 组 | n | DA | committed DA | neither | both |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev"):
        item = block["change_relevance"][condition]["groups"]
        for group in ("any_security_relevant", "no_security_relevant"):
            bucket = item[group]
            lines.append(
                f"| {CONDITION_LABELS[condition]} | {group} | {bucket['n']} | "
                f"{_fmt_pct(bucket['da'])} | {_fmt_pct(bucket['committed_da'])} | "
                f"{_fmt_pct(bucket['neither_rate'])} | {_fmt_pct(bucket['both_rate'])} |"
            )
    lines.append("")
    lines.append("该分组用模型自己标出的 `security_relevant` 切分，只用于描述机制，不是随机对照；它回答“把变更判为不相关时是否更容易 neither”。")
    lines.append("")
    lines.append("## 7. 成本")
    lines.append("")
    lines.append("| 臂 | 请求 | prompt tokens | completion tokens | USD（配置价） | USD/100 pair-order | 正确 pair-order | USD/正确 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for arm in ("open", "ctrl", "diff"):
        item = block["cost"]["by_arm"][arm]
        lines.append(
            f"| {arm} | {item['requests']} | {item['prompt_tokens']} | {item['completion_tokens']} | "
            f"{_fmt_num(item['cost_usd_configured'], 6)} | {_fmt_num(item['cost_per_100_pair_orders'], 6)} | "
            f"{item['correct_pair_orders']} | {_fmt_num(item['cost_per_correct'], 6)} |"
        )
    for key in ("diff_minus_ctrl", "diff_minus_open", "ctrl_minus_open"):
        item = block["cost"]["by_arm"][key]
        lines.append(
            f"| {key} | — | — | — | {_fmt_num(item['delta_cost_usd'], 6)} | — | "
            f"{item['delta_correct_pair_orders']:+d} | {_fmt_num(item['incremental_cost_per_extra_correct'], 6)} |"
        )
    lines.append("")
    lines.append("## 8. 位置偏差细表")
    lines.append("")
    lines.append("| 条件 | DA(vuln=A) | DA(vuln=B) | Δ | Fisher p | 选 A 比例 | 二项 p | 选 B 比例（committed） |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for condition in CONDITION_ORDER:
        item = block["position"][condition]
        lines.append(
            f"| {CONDITION_LABELS[condition]} | "
            f"{_fmt_pct(item['by_vulnerable_slot']['A']['accuracy_all'])} | "
            f"{_fmt_pct(item['by_vulnerable_slot']['B']['accuracy_all'])} | "
            f"{100.0 * (item['difference_da_A_minus_da_B_all'] or 0):+.2f} pp | "
            f"{_fmt_p(item['fisher_exact_p_all'])} | "
            f"{_fmt_pct(item['slot_a_share_of_ab_selections'])} | "
            f"{_fmt_p(item['binomial_p_select_A_vs_B'])} | "
            f"{_fmt_pct(item['choose_B_share_of_committed'])} |"
        )
    lines.append("")
    lines.append("## 9. 限制")
    lines.append("")
    for item in (
        "单次贪心解码（temperature=0），没有重复采样；交换一致 DA 是主终点。",
        "开放任务在构造上恰好一个版本含漏洞；both/neither 在 DA 中记错，但同时单列弃权率。",
        "diff 方向固定为 A→B，因此“把 target 当已修复”会表现为位置偏差；正反交换用于检测它。",
        "长度对照是内容为空的占位块，按 diff 块的 token 数匹配；它可能改变模型的谨慎程度，diff 若仍胜出则该比较是保守的。",
        "token 匹配先用 tiktoken 代理，分析再用 provider 的 prompt_tokens 复核，并给出 ≤5% 匹配子集。",
        "changes-first 由 JSON 首键和原文顺序代理，不是两阶段协议；合规率与主 DA 分开报告。",
        "变更清单的接地只按行号对齐到 difflib 变更行，不评价摘要的自然语言正确性。",
        "长度分层和匹配子集是事后诊断，不是预注册基线。",
        "项目不平衡：linux 占比较大；bootstrap 主区间按 project 聚类，pair 级为敏感性。",
        "diff 由冻结函数体生成，不是上游 commit patch；格式化/重命名也会进入变更清单。",
    ):
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _render_comparison_markdown(comparison: dict[str, Any]) -> str:
    lines = ["# pair_diff：跨模型与关键比较", ""]
    lines.append(
        f"数据集：`{comparison.get('dataset_path', 'splits/test_pairs_180.json')}`"
        f"（{comparison['dataset_units']} 对）；条件：diff + changes-first、token 长度匹配对照、pair_debias 开放四分类。"
    )
    lines.append("")
    lines.append("## 1. 跨模型（同一配对上）")
    lines.append("")
    lines.append("| 任务 | DeepSeek DA | MiMo DA | Δ(DS−MiMo) | McNemar p | Holm p | 项目聚类 Δ 95% CI |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for item in comparison["cross_model"]:
        lines.append(
            f"| {item['label']} | {_fmt_pct(item['deepseek_da'])} | {_fmt_pct(item['mimo_da'])} | "
            f"{100.0 * (item['difference'] or 0):+.2f} pp | {_fmt_p(item['p_value'])} | "
            f"{_fmt_p(item['holm_p'])} | {_ci(item['bootstrap_project'])} |"
        )
    lines.append("")
    lines.append("## 2. 每个模型的关键分解")
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        lines.append(f"### {MODELS[model_key]['label']}")
        lines.append("")
        lines.append("| 指标 | 值 |")
        lines.append("| --- | ---: |")
        for task in ("diff", "ctrl", "open"):
            exchange = block["exchange"][task]
            lines.append(f"| 交换一致 DA（{TASK_LABELS[task]}） | {_fmt_pct(exchange['da_both_orders'])} |")
        for arm in ("diff_minus_ctrl", "diff_minus_open", "ctrl_minus_open"):
            item = block["cost"]["by_arm"][arm]
            lines.append(
                f"| {arm} Δcorrect（180 对 × 2 序） | {item['delta_correct_pair_orders']:+d} |"
            )
        lines.append("")
    lines.append("## 3. 结论模板（只填真实数字）")
    lines.append("")
    lines.append("- diff 相对长度对照的交换一致 DA 差与 McNemar/Holm 见上表；只有 Holm 后显著才写成“改善”。")
    lines.append("- 若 diff 相对 open 的提升与 ctrl 相对 open 的提升相近，则主要是提示变长/变更清单指令，而不是 diff 内容。")
    lines.append("- 若 diff 在 H 错误子集的准确率高于 ctrl，且选较短比例不升，才支持“diff 减少了长度捷径”。")
    lines.append("- 成本以配置价计，增量成本/额外正确对只在 Δcorrect>0 时有定义。")
    return "\n".join(lines) + "\n"


def _render_summary(comparison: dict[str, Any]) -> str:
    lines = ["# pair_diff 结果摘要", ""]
    lines.append(
        f"数据集：`{comparison.get('dataset_path', 'splits/test_pairs_180.json')}`"
        f"（{comparison['dataset_units']} 对，SHA-256 `{comparison['dataset_sha256']}`）。"
    )
    lines.append("")
    lines.append("## 主表")
    lines.append("")
    lines.append("| 模型 | 条件 | DA | 交换一致 DA | both+neither | 选较短比例 | 成本 USD |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for condition in CONDITION_ORDER:
            metrics = block["conditions"][condition]
            task = condition.split("_")[0]
            exchange = block["exchange"][task]["da_both_orders"]
            shortcut = block["length_shortcut"][condition]
            cost = block["cost"]["by_arm"]["diff" if task == "diff" else task]["by_condition"][condition]["cost_usd_configured"]
            lines.append(
                f"| {MODELS[model_key]['label']} | {CONDITION_LABELS[condition]} | "
                f"{_fmt_pct(metrics['accuracy']['all_pairs'])} | {_fmt_pct(exchange)} | "
                f"{_fmt_pct(metrics['abstention']['rate'])} | {_fmt_pct(shortcut['choose_shorter_committed'])} | "
                f"{_fmt_num(cost, 6)} |"
            )
    lines.append("")
    lines.append("## 关键比较")
    lines.append("")
    lines.append("| 模型 | diff−ctrl（交换一致） | p | diff−open（交换一致） | p | ctrl−open（交换一致） | p |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        c1 = block["comparisons"]["diff_stable_vs_ctrl_stable"]
        c2 = block["comparisons"]["diff_stable_vs_open_stable"]
        c3 = block["comparisons"]["ctrl_stable_vs_open_stable"]
        lines.append(
            f"| {MODELS[model_key]['label']} | {100.0 * (c1['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(c1['mcnemar']['p_value'])} | {100.0 * (c2['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(c2['mcnemar']['p_value'])} | {100.0 * (c3['difference_all'] or 0):+.2f} pp | "
            f"{_fmt_p(c3['mcnemar']['p_value'])} |"
        )
    lines.append("")
    lines.append("完整表、长度分层、合规、成本与限制见 `analysis_<model>.md`、`comparison.md`。")
    return "\n".join(lines) + "\n"


def _cross_model(comparison_models: dict[str, Any], units: list[PairUnit]) -> list[dict[str, Any]]:
    results = []
    for task in ("diff_fwd", "diff_rev", "diff_stable", "ctrl_fwd", "ctrl_rev", "ctrl_stable", "open_fwd", "open_rev", "open_stable"):
        if task.endswith("_stable"):
            base = task[: -len("_stable")]
            flags_ds = comparison_models["deepseek-v4.1-flash"]["stable_flags"][base]
            flags_mimo = comparison_models["mimo-v2.6-flash"]["stable_flags"][base]
        else:
            flags_ds = comparison_models["deepseek-v4.1-flash"]["condition_results"][task].correct
            flags_mimo = comparison_models["mimo-v2.6-flash"]["condition_results"][task].correct
        comparison = pda._comparison(
            units,
            flags_ds,
            flags_mimo,
            label_a="deepseek-v4.1-flash",
            label_b="mimo-v2.6-flash",
            resamples=10000,
            seed=42,
        )
        results.append(
            {
                "task": task,
                "label": CONDITION_LABELS.get(task, TASK_LABELS.get(task.replace("_stable", ""), task) + "（交换一致）"),
                "deepseek_da": comparison["rate_a_all"],
                "mimo_da": comparison["rate_b_all"],
                "difference": comparison["difference_all"],
                "p_value": comparison["mcnemar"]["p_value"],
                "bootstrap_project": comparison["bootstrap_project"],
                "bootstrap_pair": comparison["bootstrap_pair"],
                "table": comparison["table"],
            }
        )
    # Holm within the pre-declared model-effect family: diff fwd/rev/stable.
    family = [item for item in results if item["task"] in {"diff_fwd", "diff_rev", "diff_stable"}]
    adjusted = holm_adjust([float(item["p_value"]) for item in family])
    for item, value in zip(family, adjusted):
        item["holm_p"] = value
    for item in results:
        item.setdefault("holm_p", None)
    return results


def _family_holm(block: dict[str, Any], family: str, key: str) -> float | None:
    for item in block["holm_families"].get(family, {}).get("tests", []):
        if item.get("comparison") == key:
            return item.get("holm_p")
    return None


def _render_report(comparison: dict[str, Any]) -> str:
    lines = ["# Pair-diff：差分引导、先列变更、位置去偏的配对评估", ""]
    lines.append(
        f"数据集：`{comparison.get('dataset_path', 'splits/test_pairs_180.json')}`"
        f"（{comparison['dataset_units']} 对，SHA-256 `{comparison['dataset_sha256']}`）。"
    )
    lines.append("")
    lines.append("## 0. 一句话结论")
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        label = MODELS[model_key]["label"]
        d = block["conditions"]["diff_fwd"]["accuracy"]["all_pairs"]
        c = block["conditions"]["ctrl_fwd"]["accuracy"]["all_pairs"]
        o = block["conditions"]["open_fwd"]["accuracy"]["all_pairs"]
        ex_d = block["exchange"]["diff"]["da_both_orders"]
        ex_c = block["exchange"]["ctrl"]["da_both_orders"]
        ex_o = block["exchange"]["open"]["da_both_orders"]
        d_vs_c = block["comparisons"]["diff_stable_vs_ctrl_stable"]
        d_vs_o = block["comparisons"]["diff_stable_vs_open_stable"]
        holm_dc = _family_holm(block, "diff_vs_ctrl", "diff_stable_vs_ctrl_stable")
        holm_do = _family_holm(block, "diff_vs_open", "diff_stable_vs_open_stable")
        gap_d = block["length_shortcut"]["diff_fwd"]["gap"]
        gap_c = block["length_shortcut"]["ctrl_fwd"]["gap"]
        gap_o = block["length_shortcut"]["open_fwd"]["gap"]
        ns = block["change_relevance"]["diff_fwd"]["groups"]["no_security_relevant"]
        any_sec = block["change_relevance"]["diff_fwd"]["groups"]["any_security_relevant"]
        lines.append(
            f"- **{label}**：正向 DA diff {_fmt_pct(d)} / ctrl {_fmt_pct(c)} / open {_fmt_pct(o)}；"
            f"交换一致 DA {_fmt_pct(ex_d)} / {_fmt_pct(ex_c)} / {_fmt_pct(ex_o)}。"
            f"diff−ctrl 交换一致 Δ {100.0 * (d_vs_c['difference_all'] or 0):+.2f} pp"
            f"（McNemar p={_fmt_p(d_vs_c['mcnemar']['p_value'])}，Holm p={_fmt_p(holm_dc)}）；"
            f"diff−open Δ {100.0 * (d_vs_o['difference_all'] or 0):+.2f} pp"
            f"（p={_fmt_p(d_vs_o['mcnemar']['p_value'])}，Holm p={_fmt_p(holm_do)}）。"
            f"正向 H-gap：diff {100.0 * (gap_d or 0):+.1f} pp / ctrl {100.0 * (gap_c or 0):+.1f} pp / "
            f"open {100.0 * (gap_o or 0):+.1f} pp。"
            f"变更清单无安全相关项的 {ns['n']}/180 对全部判错（neither {_fmt_pct(ns['neither_rate'])}），"
            f"有安全相关项的 {any_sec['n']} 对 DA {_fmt_pct(any_sec['da'])}。"
        )
    lines.append("")
    lines.append("结论只按上表的显著性写：**没有 Holm 后显著的 diff 优势时，不写成“diff 有效”；H-gap 没有下降时，不写成“diff 减少长度捷径”。**")
    lines.append("")
    lines.append("## 1. 设计")
    lines.append("")
    lines.append("在 180 个冻结 SecVulEval pair 上运行三种开放四分类（A/B/both/neither）呈现：")
    lines.append("")
    lines.append("- `diff`：两份完整代码 + 从 A 到 B 的 unified diff + 要求先列 `semantic_changes` 再判定；")
    lines.append("- `ctrl`：两份完整代码 + 与 diff 块 token 长度匹配、内容为空的占位块 + 同样的先列变更要求；")
    lines.append("- `open`：`pair_debias` 已发布的开放四分类（无 diff、无变更清单），只读复用。")
    lines.append("")
    lines.append("每个条件都跑 A/B 正反两序；`diff−ctrl` 分离 diff 内容，`ctrl−open` 分离提示变长/变更清单指令，`diff−open` 是总效应。diff 方向固定 A→B，跟随槽位交换，因此不能直接泄漏标签；把 target 当已修复会表现为位置偏差。")
    lines.append("")
    lines.append("## 2. 完整性与合规")
    lines.append("")
    lines.append("| 模型 | 条件 | 记录 | ok | invalid | error | changes-first | schema exact | 条目接地率 | 引用行精确率 |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev"):
            metrics = block["conditions"][condition]
            status = metrics["counts"]["status"]
            compliance = block["compliance"][condition]
            lines.append(
                f"| {MODELS[model_key]['label']} | {CONDITION_LABELS[condition]} | {metrics['counts']['pairs']} | "
                f"{status.get('ok', 0)} | {status.get('invalid', 0)} | {status.get('error', 0)} | "
                f"{_fmt_pct(compliance['changes_first_rate'])} | {_fmt_pct(compliance['schema_exact_rate'])} | "
                f"{_fmt_pct(compliance['grounded_item_rate'])} | {_fmt_pct(compliance['cited_line_precision'])} |"
            )
    lines.append("")
    lines.append("### 2b. 实际提示长度匹配")
    lines.append("")
    lines.append("| 模型 | 比较 | 中位 diff tokens | 中位 ctrl tokens | 中位 ctrl/diff | ≤5% 对数 | 匹配子集 n |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for key, item in block["token_match"].items():
            lines.append(
                f"| {MODELS[model_key]['label']} | {key} | {_fmt_num(item['median_prompt_tokens_diff'], 1)} | "
                f"{_fmt_num(item['median_prompt_tokens_ctrl'], 1)} | {_fmt_num(item['median_ratio_ctrl_over_diff'], 4)} | "
                f"{item['within_5pct']}/{item['n_pairs']} | {item['matched_n']} |"
            )
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for key, item in block["token_match"].items():
            comp = item["matched_comparison"]
            if comp is None:
                continue
            lines.append(
                f"- {MODELS[model_key]['label']} / {key}：在 {item['matched_n']} 对 ≤5% token 匹配子集上，"
                f"diff−ctrl Δ {100.0 * (comp['difference_all'] or 0):+.2f} pp，"
                f"McNemar p={_fmt_p(comp['mcnemar']['p_value'])}。"
            )
    lines.append("")
    lines.append("`中位 ctrl/diff` 是 180 个逐对比值的中位数，不是两个中位数之比；`≤5%` 指逐对 |ctrl/diff−1|≤0.05。")
    lines.append("")
    lines.append("## 3. 主结果")
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        lines.append(f"### {MODELS[model_key]['label']}")
        lines.append("")
        lines.append("| 条件 | DA | committed DA | 交换一致 DA | both | neither | 弃权率 | ΔA−B | Fisher p |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for condition in CONDITION_ORDER:
            metrics = block["conditions"][condition]
            task = condition.split("_")[0]
            abstention = metrics["abstention"]
            lines.append(
                f"| {CONDITION_LABELS[condition]} | {_fmt_pct(metrics['accuracy']['all_pairs'])} | "
                f"{_fmt_pct(metrics['accuracy']['committed_picks'])} | {_fmt_pct(block['exchange'][task]['da_both_orders'])} | "
                f"{abstention['both_vulnerable']} | {abstention['both_safe']} | {_fmt_pct(abstention['rate'])} | "
                f"{100.0 * (metrics['position_bias']['difference_da_A_minus_da_B_all'] or 0):+.2f} pp | "
                f"{_fmt_p(metrics['position_bias']['fisher_exact_p_all'])} |"
            )
        lines.append("")
    lines.append("**both/neither 的移动：** diff 的 both 只有 0–4 个（open 7–13），neither 为 33–44 个（open 24–33）；ctrl 的 both 1–4、neither 31–46。总弃权率 diff 20.00%–24.44%、ctrl 18.89%–26.11%、open 17.22%–22.22%。也就是说，diff/ctrl 基本消除了 `both`，但把一部分转成了 `neither`，总弃权没有下降。")
    lines.append("")
    lines.append("### 3b. 跨模型（交换一致 DA）")
    lines.append("")
    lines.append("| 任务 | DeepSeek | MiMo | Δ(DS−MiMo) | McNemar p | Holm p |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for task, label in (
        ("diff_stable", "diff + changes-first"),
        ("ctrl_stable", "长度匹配对照"),
        ("open_stable", "pair_debias 开放四分类"),
    ):
        item = next(entry for entry in comparison["cross_model"] if entry["task"] == task)
        lines.append(
            f"| {label} | {_fmt_pct(item['deepseek_da'])} | {_fmt_pct(item['mimo_da'])} | "
            f"{100.0 * (item['difference'] or 0):+.2f} pp | {_fmt_p(item['p_value'])} | {_fmt_p(item['holm_p'])} |"
        )
    lines.append("")
    lines.append("位置偏差：六个条件中没有任何一个 A/B 分侧 Fisher p<0.05；diff 在两个模型、两个顺序上都是负的 ΔA−B（B 侧更高），MiMo 正向 p=0.054 最接近显著，但正反两序未给出一致的显著偏差。同字母率 diff 6.35%–7.03%，ctrl 5.43%–7.58%，open 8.59%–14.50%，说明 diff/ctrl 的选择主要由内容而非字母驱动。")
    lines.append("")
    lines.append("## 4. 关键比较与长度捷径")
    lines.append("")
    lines.append("| 模型 | 比较 | Δ | McNemar p | Holm p | 项目聚类 95% CI |")
    lines.append("| --- | --- | ---: | ---: | ---: | --- |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for family, key in (
            ("diff_vs_ctrl", "diff_stable_vs_ctrl_stable"),
            ("diff_vs_open", "diff_stable_vs_open_stable"),
            ("ctrl_vs_open", "ctrl_stable_vs_open_stable"),
        ):
            item = block["comparisons"][key]
            lines.append(
                f"| {MODELS[model_key]['label']} | {key} | {100.0 * (item['difference_all'] or 0):+.2f} pp | "
                f"{_fmt_p(item['mcnemar']['p_value'])} | {_fmt_p(_family_holm(block, family, key))} | "
                f"{_ci(item['bootstrap_project'])} |"
            )
    lines.append("")
    lines.append("### 4b. 长度捷径（正向）")
    lines.append("")
    lines.append("| 模型 | 条件 | H 正确子集 DA | H 错误子集 DA | gap | 选较短比例 | H 错误子集 n |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for condition in ("diff_fwd", "ctrl_fwd", "open_fwd", "diff_rev", "ctrl_rev", "open_rev"):
            item = block["length_shortcut"][condition]
            lines.append(
                f"| {MODELS[model_key]['label']} | {CONDITION_LABELS[condition]} | "
                f"{_fmt_pct(item['strata']['heuristic_correct']['accuracy'])} | "
                f"{_fmt_pct(item['strata']['heuristic_wrong']['accuracy'])} | "
                f"{100.0 * (item['gap'] or 0):+.2f} pp | {_fmt_pct(item['choose_shorter_committed'])} | "
                f"{item['strata']['heuristic_wrong']['n']} |"
            )
    lines.append("")
    lines.append("### 4c. “较短侧是错误答案”的子集")
    lines.append("")
    lines.append("| 模型 | 子集 | n | diff−ctrl Δ | p | diff−open Δ | p |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for subset in ("vulnerable_longer", "vulnerable_shorter", "tie"):
            item = block["length_effect"]["subsets"][subset]
            c1 = item["comparisons"]["diff_fwd_vs_ctrl_fwd"]
            c2 = item["comparisons"]["diff_fwd_vs_open_fwd"]
            if c1 is None or c2 is None:
                lines.append(f"| {MODELS[model_key]['label']} | {subset} | {item['n']} | — | — | — | — |")
            else:
                lines.append(
                    f"| {MODELS[model_key]['label']} | {subset} | {item['n']} | "
                    f"{100.0 * (c1['difference_all'] or 0):+.2f} pp | {_fmt_p(c1['mcnemar']['p_value'])} | "
                    f"{100.0 * (c2['difference_all'] or 0):+.2f} pp | {_fmt_p(c2['mcnemar']['p_value'])} |"
                )
    lines.append("")
    lines.append("### 4d. 只在 committed 子集上比长度启发式")
    lines.append("")
    lines.append("| 模型 | 条件 | committed n | 模型 DA | 启发式 DA | Δ | McNemar p |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for condition in ("diff_fwd", "ctrl_fwd", "open_fwd", "diff_rev", "ctrl_rev", "open_rev"):
            item = block["length_shortcut"][condition]["committed_subset_vs_heuristic"]
            delta = None if item["model_da"] is None or item["heuristic_da"] is None else item["model_da"] - item["heuristic_da"]
            lines.append(
                f"| {MODELS[model_key]['label']} | {CONDITION_LABELS[condition]} | {item['n']} | "
                f"{_fmt_pct(item['model_da'])} | {_fmt_pct(item['heuristic_da'])} | "
                f"{100.0 * (delta or 0):+.2f} pp | {_fmt_p(item['mcnemar']['p_value'] if item['mcnemar'] else None)} |"
            )
    lines.append("")
    lines.append("这张表回答“模型一旦承诺 A/B，是否比‘选较短’更强”；它不受弃权惩罚。主 DA 仍然按 180 对计，不能把 committed 子集的优势直接当成总体优势。")
    lines.append("")
    lines.append("## 5. both/neither 与变更范围捷径")
    lines.append("")
    lines.append("| 模型 | 条件 | any security_relevant n | DA | neither | no security_relevant n | DA | neither |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for condition in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev"):
            groups = block["change_relevance"][condition]["groups"]
            a = groups["any_security_relevant"]
            b = groups["no_security_relevant"]
            lines.append(
                f"| {MODELS[model_key]['label']} | {CONDITION_LABELS[condition]} | "
                f"{a['n']} | {_fmt_pct(a['da'])} | {_fmt_pct(a['neither_rate'])} | "
                f"{b['n']} | {_fmt_pct(b['da'])} | {_fmt_pct(b['neither_rate'])} |"
            )
    lines.append("")
    lines.append("读法：`no_security_relevant` 组是模型自己在变更清单里没有标出任何 `security_relevant=true` 的 pair；它全部判 `neither` 时 DA 必为 0。该组不是随机分组，而是 changes-first 的一种失败模式：模型把“变更不涉及安全”当成“两个版本都安全”，忽略了漏洞可能在两版共享的未变更代码里。")
    lines.append("")
    lines.append("### 5b. 同一批 pair 上的其他条件（参考，不是随机对照）")
    lines.append("")
    lines.append("| 模型 | 子集 | n | diff DA | ctrl DA | open DA |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        item = block["change_subset_reference"]
        for subset in ("any_security_relevant", "no_security_relevant"):
            sub = item["subsets"][subset]
            conds = sub["conditions"]
            lines.append(
                f"| {MODELS[model_key]['label']} | {subset} | {sub['n']} | "
                f"{_fmt_pct(conds['diff_fwd']['da'])} | {_fmt_pct(conds['ctrl_fwd']['da'])} | "
                f"{_fmt_pct(conds['open_fwd']['da'])} |"
            )
    lines.append("")
    lines.append("这张表把变化拆成两部分；净 DA 是这两部分的和，不能只看其中一边。在 any-security 子集上 diff/ctrl 与 open 的差、在 no-security 子集上的门控损失，必须一起读。")
    lines.append("")
    lines.append("## 6. 成本")
    lines.append("")
    lines.append("| 模型 | 臂 | 请求 | prompt tokens | completion tokens | USD（配置价） | USD/100 pair-order | 正确 pair-order | USD/正确 |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        for arm in ("open", "ctrl", "diff"):
            item = block["cost"]["by_arm"][arm]
            lines.append(
                f"| {MODELS[model_key]['label']} | {arm} | {item['requests']} | {item['prompt_tokens']} | "
                f"{item['completion_tokens']} | {_fmt_num(item['cost_usd_configured'], 6)} | "
                f"{_fmt_num(item['cost_per_100_pair_orders'], 6)} | {item['correct_pair_orders']} | "
                f"{_fmt_num(item['cost_per_correct'], 6)} |"
            )
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        arms = block["cost"]["by_arm"]
        diff_ratio = (arms["diff"]["cost_usd_configured"] or 0) / (arms["open"]["cost_usd_configured"] or 1)
        ctrl_ratio = (arms["ctrl"]["cost_usd_configured"] or 0) / (arms["open"]["cost_usd_configured"] or 1)
        lines.append(
            f"- {MODELS[model_key]['label']}：diff 成本是 open 的 {diff_ratio:.2f}×，ctrl 是 open 的 {ctrl_ratio:.2f}×；"
            f"正确 pair-order diff {arms['diff']['correct_pair_orders']} / ctrl {arms['ctrl']['correct_pair_orders']} / "
            f"open {arms['open']['correct_pair_orders']}。"
        )
    lines.append("")
    lines.append("## 7. 解释与结论")
    lines.append("")
    lines.append("1. **diff 内容没有建立优势。** 交换一致 DA 上，diff−ctrl 为 DeepSeek +2.22 pp（Holm 1.0000）、MiMo −1.67 pp（Holm 0.9053）；diff−open 为 DeepSeek +6.67 pp（raw p=0.0428，Holm 0.0855）、MiMo +2.22 pp（Holm 1.0000）。没有任何一个模型在 Holm 后显著优于对照或 open。")
    lines.append("2. **committed 子集有内容信号，但被弃权抵消。** 在模型实际给出 A/B 的子集上，diff 比“选较短”高 +7.97 pp（DeepSeek 正向，p=0.0522）、+11.81 pp（DeepSeek 反向，p=0.0046）、+10.29 pp（MiMo 正向，p=0.0094）、+8.70 pp（MiMo 反向，p=0.0428）；open 的同口径优势只有 +1.34 到 +9.29 pp。主 DA 仍按 180 对计，不能把 committed 优势当成总体优势。")
    lines.append("3. **没有一致证据表明 diff 减少了长度捷径；长度捷径仍然存在。** diff/ctrl 的“选较短”比例（75.17%–81.20%）不低于 open（73.15%–80.14%）；在“较短侧必错”的 44 对上，diff−ctrl 只有 +2.27 pp（两个模型 p=1.0000），diff−open 为 +2.27/+4.55 pp（p=1.0000/0.7266）；长度匹配 ≤10% 子集上模型仍低于启发式（约 67% vs 72.9%）。MiMo 的 H-gap 比 open 低约 2.9 pp，但选较短比例更高，H 错误子集仅 +4.55 pp（p=0.7266），因此不能把这一点当成稳健的长度去偏。")
    lines.append("4. **changes-first 的一个突出新失败模式是变更范围门控。** 模型在变更清单里没有标出安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全部判 neither，DA 为 0；open 在同一批 pair 上也只有 15.00%/11.11%，说明该子集本身难，但 diff/ctrl 的门控把少数可能答对的 pair 也丢掉了。ctrl 出现同样的门控，说明它主要由“先列变更”指令驱动，而不是 diff 内容。")
    lines.append("5. **成本效率没有改善。** diff 成本约为 open 的 1.30×；相对 ctrl 的正确 pair-order 为 +1/−1，相对 open 为 +16/+6（DeepSeek 250 vs 234，MiMo 243 vs 237）；USD/正确 pair-order 仍高于 open。")
    lines.append("")
    lines.append("## 8. 逐对例子（自动选取，未手改）")
    lines.append("")
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        lines.append(f"### {MODELS[model_key]['label']}")
        lines.append("")
        for name in ("diff_only_correct", "diff_neither_ctrl_ab", "diff_and_ctrl_wrong_open_correct"):
            items = block["examples"]["examples"].get(name) or []
            lines.append(f"**{name}**（共 {block['examples']['counts'].get(name, 0)} 对，列前 {len(items)} 对）")
            lines.append("")
            for item in items:
                lines.append(
                    f"- `{item['pair_id']}`（{item['project']}）：diff={item['diff_decision']} / "
                    f"ctrl={item['ctrl_decision']} / open={item['open_decision']}；"
                    f"changes: {'; '.join(item['semantic_changes']) or '—'}；"
                    f"rationale: {item['rationale'] or '—'}"
                )
            lines.append("")
    lines.append("## 9. 限制")
    lines.append("")
    for item in (
        "单次贪心解码（temperature=0）；交换一致 DA 是主终点，但没有重复采样方差。",
        "开放任务在构造上恰好一个版本含漏洞；both/neither 在 DA 中记错，因此必须同时读 committed DA 与弃权率。",
        "diff 方向固定 A→B；它跟随槽位交换，不泄漏标签，但会引入 target 侧方向先验；正反交换只能检测、不能完全消除。",
        "长度对照是内容为空的占位块；它匹配 token 长度和格式位置，但“没有注释”的提示可能改变谨慎程度。diff 若胜出，该比较对 diff 保守；ctrl 若胜出，不能直接归因于“长度”。",
        "token 匹配先用 tiktoken 代理，再用 provider 的 prompt_tokens 复核；中位比例接近 1，但总 token 仍有长尾差异，≤5% 匹配子集是敏感性分析。",
        "changes-first 由 JSON 首键和原文顺序代理，不是两阶段协议；主 DA 不以合规为门槛。",
        "变更接地只按行号对齐 difflib 变更行，不评价摘要的自然语言正确性，也不区分安全相关/无关变更的语义质量。",
        "`security_relevant` 分组是模型自报的探索性切分，不是随机对照。",
        "长度分层、匹配子集和例子选择都是事后诊断，不是预注册基线。",
        "项目聚类 bootstrap 是 95% 未校正区间；多重比较以预声明 Holm 族为准，不能把单个 CI 不跨 0 当成显著。",
        "项目不平衡（linux 占比较大）；bootstrap 主区间按 project 聚类，pair 级为敏感性。",
        "diff 由冻结函数体生成，不是上游 commit patch；格式化、重命名、注释变化也会进入变更清单。",
        "源码中 1/180 对的注释含 CVE-2017-17969（两侧相同，不指示槽位）；diff 可能带入该注释，但不是注入标签。",
    ):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## 10. 产物")
    lines.append("")
    lines.append("- `pair_diff/results/analysis_<model>.json/.md`：逐对结果、条件指标、交换一致性、长度、合规、成本。")
    lines.append("- `pair_diff/results/comparison.json/.md`：跨模型与关键分解。")
    lines.append("- `pair_diff/results/benchmark_export.json`：供上层汇总的紧凑导出。")
    lines.append("- `pair_diff/runs/test_*`：原始 requests/results/cache/position_map/leak_audit。")
    return "\n".join(lines) + "\n"


def _analyse(phase: str, out_dir: Path, resamples: int, seed: int) -> dict[str, Any]:
    dataset_path = (
        ROOT / "splits" / "pilot_pairs_18.json"
        if phase == "pilot"
        else ROOT / "splits" / "test_pairs_180.json"
    )
    units_all, metadata, dataset_sha = load_pairs(dataset_path)
    units = units_all[:8] if phase == "pilot" else units_all
    per_model: dict[str, Any] = {}
    holders: dict[str, Any] = {}
    for model_key in MODEL_ORDER:
        runs = _load_runs(phase, model_key)
        results = _condition_results(units, runs)
        block = _model_block(units, runs, results)
        block["dataset_sha256"] = dataset_sha
        block["dataset_path"] = str(dataset_path.relative_to(ROOT))
        block["phase"] = phase
        per_model[model_key] = block
        holders[model_key] = {
            "condition_results": results,
            "stable_flags": {
                task: _stable_flags(results[f"{task}_fwd"], results[f"{task}_rev"])
                for task in ("diff", "ctrl", "open")
            },
        }
    cross_model = _cross_model(holders, units)
    comparison = {
        "schema_version": 1,
        "dataset_sha256": dataset_sha,
        "dataset_path": str(dataset_path.relative_to(ROOT)),
        "dataset_units": len(units),
        "phase": phase,
        "conditions": list(CONDITION_ORDER),
        "models": per_model,
        "cross_model": cross_model,
        "method": "pair_diff",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    for model_key in MODEL_ORDER:
        short = MODELS[model_key]["short"]
        (out_dir / f"analysis_{short}.json").write_text(
            json.dumps(per_model[model_key], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (out_dir / f"analysis_{short}.md").write_text(
            _render_model_markdown(model_key, per_model[model_key]), encoding="utf-8"
        )
    (out_dir / "comparison.json").write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "comparison.md").write_text(_render_comparison_markdown(comparison), encoding="utf-8")
    (out_dir / "summary.md").write_text(_render_summary(comparison), encoding="utf-8")
    (out_dir / "report.md").write_text(_render_report(comparison), encoding="utf-8")
    (out_dir / "benchmark_export.json").write_text(
        json.dumps(_benchmark_export(comparison), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return comparison


def _benchmark_export(comparison: dict[str, Any]) -> dict[str, Any]:
    export: dict[str, Any] = {
        "schema_version": 1,
        "method": "pair_diff",
        "dataset_sha256": comparison["dataset_sha256"],
        "dataset_units": comparison["dataset_units"],
        "phase": comparison["phase"],
        "conditions": {},
        "exchange": {},
        "cost": {},
        "length_shortcut": {},
        "notes": [
            "Real provider calls; cost is configured-price, not an invoice.",
            "Exchange-consistent DA requires both A/B orders to be correct.",
            "The control arm is a token-length-matched placeholder block without the diff.",
        ],
    }
    for model_key in MODEL_ORDER:
        block = comparison["models"][model_key]
        short = MODELS[model_key]["short"]
        export["conditions"][short] = {
            condition: {
                "n": block["conditions"][condition]["counts"]["pairs"],
                "correct": block["conditions"][condition]["counts"]["categories"]["correct"],
                "da": block["conditions"][condition]["accuracy"]["all_pairs"],
                "committed_da": block["conditions"][condition]["accuracy"]["committed_picks"],
                "abstention_rate": block["conditions"][condition]["abstention"]["rate"],
                "position_bias_da_a_minus_b": block["conditions"][condition]["position_bias"]["difference_da_A_minus_da_B_all"],
                "fisher_p": block["conditions"][condition]["position_bias"]["fisher_exact_p_all"],
            }
            for condition in CONDITION_ORDER
        }
        export["exchange"][short] = {
            task: {
                "da_both_orders": block["exchange"][task]["da_both_orders"],
                "semantic_agreement_rate": block["exchange"][task]["semantic_agreement_rate_valid"],
                "same_letter_rate": block["exchange"][task]["same_letter_rate"],
                "order_mcnemar_p": block["exchange"][task]["order_mcnemar"]["p_value"],
            }
            for task in ("diff", "ctrl", "open")
        }
        export["cost"][short] = {
            arm: {
                "requests": block["cost"]["by_arm"][arm]["requests"],
                "cost_usd": block["cost"]["by_arm"][arm]["cost_usd_configured"],
                "correct_pair_orders": block["cost"]["by_arm"][arm]["correct_pair_orders"],
            }
            for arm in ("open", "ctrl", "diff")
        }
        export["length_shortcut"][short] = {
            condition: {
                "heuristic_correct_da": block["length_shortcut"][condition]["strata"]["heuristic_correct"]["accuracy"],
                "heuristic_wrong_da": block["length_shortcut"][condition]["strata"]["heuristic_wrong"]["accuracy"],
                "gap": block["length_shortcut"][condition]["gap"],
                "choose_shorter_committed": block["length_shortcut"][condition]["choose_shorter_committed"],
            }
            for condition in CONDITION_ORDER
        }
    return export


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("test", "pilot"), default="test")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "pair_diff" / "results")
    parser.add_argument("--resamples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    comparison = _analyse(args.phase, args.out_dir, args.resamples, args.seed)
    print(f"wrote {args.out_dir} ({len(comparison['models'])} models, {len(comparison['conditions'])} conditions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

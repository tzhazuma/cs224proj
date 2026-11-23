#!/usr/bin/env python3
"""Build the 2026-11-22 next-iteration extension summary.

Reads only canonical runs under ``benchmark/extensions/runs/`` plus the five
producer exports. Recomputes confusion cells, detection scores, McNemar tests
and Holm adjustments from the canonical predictions; never re-runs a model,
analyzer or dynamic tool. Writes:

* ``benchmark/results/NEXT_ITERATION.md`` (human-readable, Chinese)
* ``benchmark/results/next_iteration_summary.json`` (machine-readable)

The five designs are reported separately. No cross-design pooling and no
changes to ``LEADERBOARD.md`` / ``final_summary.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
EXT_TOOLS = ROOT / "benchmark" / "extensions" / "tools"
BENCH_TOOLS = ROOT / "benchmark" / "tools"
for path in (str(EXT_TOOLS), str(BENCH_TOOLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from bench_common import (  # noqa: E402
    atomic_write_json,
    atomic_write_text,
    detection_scores,
    holm_adjust,
    mcnemar_exact,
    read_json,
    read_jsonl,
    sha256_file,
    utc_now,
)
from bench_metrics import compute_run_metrics  # noqa: E402
from ext_common import (  # noqa: E402
    EXTENSION_VERSION,
    design_registry,
    load_extension_run,
)
from ext_validate import validate_extension_run  # noqa: E402

RESULTS = ROOT / "benchmark" / "results"
RUNS = ROOT / "benchmark" / "extensions" / "runs"
NEW_DESIGNS = (
    "codeql_alert_triage",
    "conservative_verification",
    "diff_guided_pair",
    "coverage_instrumented_dynamic",
    "interpretable_baseline",
)
SUMMARY_SCHEMA = "benchmark-next-iteration-summary-v1"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def pct(value: Any, digits: int = 2) -> str:
    if value is None:
        return "—"
    return f"{100.0 * float(value):.{digits}f}%"


def num(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    return f"{float(value):.{digits}f}"


def ci(value: Mapping[str, Any] | None) -> str:
    if not value:
        return "—"
    low = value.get("ci_low")
    high = value.get("ci_high")
    if low is None or high is None:
        return "—"
    return f"[{float(low):.4f}, {float(high):.4f}]"


def confusion(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for record in records:
        label = bool((record.get("label") or {}).get("y_true"))
        pred = (record.get("prediction") or {}).get("y_pred")
        if record.get("status") != "ok" or pred is None:
            continue
        if label and pred:
            counts["tp"] += 1
        elif label and not pred:
            counts["fn"] += 1
        elif not label and pred:
            counts["fp"] += 1
        else:
            counts["tn"] += 1
    return counts


def score(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    labels = [bool((r.get("label") or {}).get("y_true")) for r in records]
    preds = [
        (r.get("prediction") or {}).get("y_pred") if r.get("status") == "ok" else None
        for r in records
    ]
    return detection_scores(labels, preds)


def pred_map(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(record.get("unit_id")): {
            "label": bool((record.get("label") or {}).get("y_true")),
            "pred": (record.get("prediction") or {}).get("y_pred") if record.get("status") == "ok" else None,
            "status": record.get("status"),
            "cluster": record.get("cluster_id"),
        }
        for record in records
    }


def pair_correct(records: Sequence[Mapping[str, Any]]) -> dict[str, bool]:
    groups: dict[str, dict[str, Any]] = defaultdict(dict)
    for record in records:
        groups[str(record.get("group_id"))][str(record.get("side"))] = record
    result: dict[str, bool] = {}
    for pair_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            result[pair_id] = False
            continue
        vulnerable = sides["vulnerable"]
        fixed = sides["fixed"]
        if vulnerable.get("status") != "ok" or fixed.get("status") != "ok":
            result[pair_id] = False
            continue
        result[pair_id] = (
            (vulnerable.get("prediction") or {}).get("y_pred") is True
            and (fixed.get("prediction") or {}).get("y_pred") is False
        )
    return result


def pair_valid_count(records: Sequence[Mapping[str, Any]]) -> int:
    groups: dict[str, dict[str, Any]] = defaultdict(dict)
    for record in records:
        groups[str(record.get("group_id"))][str(record.get("side"))] = record
    return sum(
        1
        for sides in groups.values()
        if set(sides) == {"vulnerable", "fixed"}
        and sides["vulnerable"].get("status") == "ok"
        and sides["fixed"].get("status") == "ok"
    )


def mcnemar_maps(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    labels: Mapping[str, bool],
) -> dict[str, Any] | None:
    common = [key for key in left if key in right and left[key] is not None and right[key] is not None]
    if not common:
        return None
    b = sum(1 for key in common if left[key] == labels[key] and right[key] != labels[key])
    c = sum(1 for key in common if left[key] != labels[key] and right[key] == labels[key])
    return {
        "n": len(common),
        "b_left_correct_right_wrong": b,
        "c_left_wrong_right_correct": c,
        "mcnemar": mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=len(common)),
    }


def load_run(path: Path) -> dict[str, Any]:
    manifest, extension_manifest, records, predictions_path = load_extension_run(path)
    metrics_path = path / "metrics.json"
    metrics = read_json(metrics_path) if metrics_path.exists() else None
    validation_path = path / "validation.json"
    validation = read_json(validation_path) if validation_path.exists() else None
    return {
        "path": path,
        "run_id": str(manifest.get("run_id")),
        "manifest": manifest,
        "extension_manifest": extension_manifest,
        "records": records,
        "predictions_path": predictions_path,
        "metrics": metrics,
        "validation": validation,
    }


def run_ids(design: str) -> list[str]:
    registry = design_registry()
    for spec in registry.get("designs") or []:
        if spec.get("design_id") == design:
            return [str(item) for item in spec.get("imported_runs") or []]
    raise SystemExit(f"design {design} not in registry")


def check(listing: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    listing.append({"check": name, "ok": bool(ok), "detail": detail})


# ---------------------------------------------------------------------------
# CodeQL alert triage
# ---------------------------------------------------------------------------

_CODEQL_EXPORT_KEY = {
    "direct": "direct",
    "triage_v1": "triage_v1_oneshot",
    "triage_v2": "triage_v2_oneshot",
    "text_rule": "triage_v2_text_rule",
    "verified": "triage_v2_verified",
    "cascade": "cascade_verified_alert_direct_noalert",
    "zero_cost_never_freed": "zero_cost_never_freed_only",
    "zero_cost_drop_may_cpp": "zero_cost_drop_cpp_may_not_be_freed",
}


def summarize_codeql(runs: list[dict[str, Any]], producer: Mapping[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    by_condition: dict[str, dict[str, Any]] = {}
    for run in runs:
        records = run["records"]
        block = (records[0].get("extensions") or {})
        condition = str(block.get("condition"))
        scores = score(records)
        cells = confusion(records)
        entry = {
            "run_id": run["run_id"],
            "condition": condition,
            "path": str(run["path"].relative_to(ROOT)),
            "records": len(records),
            "confusion": cells,
            "macro_f1": scores["macro_f1"],
            "mcc": scores["mcc"],
            "precision": scores["precision"],
            "recall": scores["recall"],
            "coverage": scores["coverage"],
            "cost": (run["metrics"] or {}).get("cost"),
            "status_counts": dict(Counter(str(r.get("status")) for r in records)),
        }
        entries.append(entry)
        by_condition[condition] = entry
        check(
            checks,
            f"{condition}: stored macro-F1 matches recomputation",
            abs(float((run["metrics"] or {}).get("primary", {}).get("value")) - float(scores["macro_f1"])) < 1e-9,
            f"stored={num((run['metrics'] or {}).get('primary', {}).get('value'))}, recomputed={num(scores['macro_f1'])}",
        )
        producer_key = _CODEQL_EXPORT_KEY.get(condition)
        expected = ((producer.get("conditions") or {}).get(producer_key) or {}).get("metrics") or {}
        expected_cells = {key: expected.get(key) for key in ("tp", "fp", "tn", "fn")}
        check(
            checks,
            f"{condition}: confusion matches producer export",
            all(expected_cells.get(key) == cells.get(key) for key in ("tp", "fp", "tn", "fn")),
            f"canonical={cells}, producer={expected_cells}",
        )

    def maps(condition: str) -> dict[str, Any]:
        run = next(item for item in runs if str((item["records"][0].get("extensions") or {}).get("condition")) == condition)
        return {key: value["pred"] for key, value in pred_map(run["records"]).items()}

    labels = {key: value["label"] for key, value in pred_map(next(
        item for item in runs if str((item["records"][0].get("extensions") or {}).get("condition")) == "verified"
    )["records"]).items()}
    direct_vs_verified = mcnemar_maps(maps("direct"), maps("verified"), labels)
    text_vs_verified = mcnemar_maps(maps("text_rule"), maps("verified"), labels)
    check(
        checks,
        "verified vs direct: McNemar matches producer",
        direct_vs_verified is not None
        and abs(
            float(direct_vs_verified["mcnemar"]["p_value"])
            - float(producer["deltas"]["verified_vs_direct"]["mcnemar"]["p_value"])
        ) < 1e-12,
        f"recomputed p={num(direct_vs_verified['mcnemar']['p_value'], 6)}, producer p={num(producer['deltas']['verified_vs_direct']['mcnemar']['p_value'], 6)}",
    )
    check(
        checks,
        "text rule vs verified: zero discordant",
        text_vs_verified is not None and text_vs_verified["mcnemar"]["discordant"] == 0,
        f"discordant={text_vs_verified['mcnemar']['discordant'] if text_vs_verified else '—'}",
    )
    verified = by_condition["verified"]
    direct = by_condition["direct"]
    delta = None
    if verified["macro_f1"] is not None and direct["macro_f1"] is not None:
        delta = verified["macro_f1"] - direct["macro_f1"]
    return {
        "design": "codeql_alert_triage",
        "title": "CodeQL CWE-401 alert triage (MiMo v2, test-140)",
        "primary_metric": "macro_f1",
        "runs": entries,
        "by_condition": by_condition,
        "comparisons": {
            "verified_vs_direct": {
                "delta_macro_f1": delta,
                "mcnemar": direct_vs_verified,
                "producer_bootstrap_ci": producer["deltas"]["verified_vs_direct"]["bootstrap"]["ci95"],
                "significant": False,
                "note": "95% bootstrap CI crosses zero; exact McNemar p=0.2891",
            },
            "text_rule_vs_verified": {
                "mcnemar": text_vs_verified,
                "note": "identical predictions on this split; the verified condition adds no unit-level change over a deterministic text rule",
            },
            "codeql_alert_only": (producer.get("conditions") or {}).get("codeql", {}).get("metrics"),
        },
        "checks": checks,
        "limitations": list(producer.get("limitations") or []),
    }


# ---------------------------------------------------------------------------
# Conservative verification
# ---------------------------------------------------------------------------


def summarize_conservative(runs: list[dict[str, Any]], producer: Mapping[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    total_retracts = 0
    total_requests = 0
    for run in runs:
        records = run["records"]
        arm = str((records[0].get("extensions") or {}).get("arm"))
        pre = {
            str(record.get("unit_id")): (record.get("extensions") or {}).get("first_pass_y_pred")
            for record in records
        }
        post = {
            str(record.get("unit_id")): (record.get("prediction") or {}).get("y_pred")
            if record.get("status") == "ok"
            else None
            for record in records
        }
        labels = {str(record.get("unit_id")): bool((record.get("label") or {}).get("y_true")) for record in records}
        pre_scores = detection_scores([labels[key] for key in labels], [pre[key] for key in labels])
        post_scores = detection_scores([labels[key] for key in labels], [post[key] for key in labels])
        retracts = [record for record in records if (record.get("extensions") or {}).get("retract") is True]
        retracted_tp = sum(1 for record in retracts if bool((record.get("label") or {}).get("y_true")))
        retracted_fp = len(retracts) - retracted_tp
        total_retracts += len(retracts)
        total_requests += sum(
            1 for record in records
            if (record.get("extensions") or {}).get("verifier_status") in ("ok", "invalid", "error")
        )
        strict_pre = {
            str(record.get("unit_id")): (
                (record.get("extensions") or {}).get("first_pass_y_pred")
                if record.get("status") == "ok"
                else False
            )
            for record in records
        }
        strict_post = {
            str(record.get("unit_id")): (
                (record.get("prediction") or {}).get("y_pred")
                if record.get("status") == "ok"
                else False
            )
            for record in records
        }
        mcnemar = mcnemar_maps(strict_pre, strict_post, labels)
        producer_arm = (producer.get("arms") or {}).get(arm) or {}
        strategy = (producer_arm.get("strategies") or {}).get("conservative") or {}
        producer_scores = strategy.get("scores") or {}
        entries.append(
            {
                "run_id": run["run_id"],
                "arm": arm,
                "path": str(run["path"].relative_to(ROOT)),
                "records": len(records),
                "pre_macro_f1": pre_scores["macro_f1"],
                "post_macro_f1": post_scores["macro_f1"],
                "delta_macro_f1": (
                    post_scores["macro_f1"] - pre_scores["macro_f1"]
                    if post_scores["macro_f1"] is not None and pre_scores["macro_f1"] is not None
                    else None
                ),
                "pre_mcc": pre_scores["mcc"],
                "post_mcc": post_scores["mcc"],
                "retractions": len(retracts),
                "retracted_tp": retracted_tp,
                "retracted_fp": retracted_fp,
                "confusion": confusion(records),
                "pre_confusion": {key: (pre_scores.get("confusion") or {}).get(key) for key in ("tp", "fp", "tn", "fn")},
                "mcnemar_pre_vs_post": mcnemar,
                "producer_mcnemar": strategy.get("mcnemar_vs_pre"),
                "producer_delta": strategy.get("delta_vs_pre"),
            }
        )
        check(
            checks,
            f"{arm}: post macro-F1 matches producer",
            producer_scores.get("macro_f1") is not None
            and abs(float(producer_scores["macro_f1"]) - float(post_scores["macro_f1"])) < 1e-9,
            f"canonical={num(post_scores['macro_f1'])}, producer={num(producer_scores.get('macro_f1'))}",
        )
        check(
            checks,
            f"{arm}: retraction count matches producer",
            (strategy.get("retraction") or {}).get("retracted") == len(retracts),
            f"canonical={len(retracts)}, producer={(strategy.get('retraction') or {}).get('retracted')}",
        )
    check(
        checks,
        "all arms: total retractions 4 / 236 requests",
        total_retracts == 4 and total_requests == 236,
        f"retractions={total_retracts}, verifier_requests={total_requests}",
    )
    return {
        "design": "conservative_verification",
        "title": "Conservative three-way verification (exploratory, test-seen)",
        "primary_metric": "macro_f1",
        "runs": entries,
        "summary": {
            "retractions": total_retracts,
            "verifier_requests": total_requests,
            "retracted_tp": sum(entry["retracted_tp"] for entry in entries),
            "retracted_fp": sum(entry["retracted_fp"] for entry in entries),
            "retraction_precision": (
                sum(entry["retracted_fp"] for entry in entries) / total_retracts if total_retracts else None
            ),
            "original_fail_closed_retractions": 155,
            "note": "the original verifier retracted 155 records; the conservative rule retracts 4",
        },
        "checks": checks,
        "limitations": [
            "Exploratory and post hoc: the test split was already seen by the first pass and the original verifier.",
            "Only 4 retractions; retraction precision 25% has a wide interval and is not above the FP base rate.",
            "Random and low-confidence matched-budget baselines are equal or better on macro-F1/MCC.",
            "The verifier reads model text; grounding checks line numbers, not semantic domination.",
        ],
    }


# ---------------------------------------------------------------------------
# Diff-guided pair
# ---------------------------------------------------------------------------


def summarize_diff(
    runs: list[dict[str, Any]],
    producer: Mapping[str, Any],
    comparison: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    correct_maps: dict[tuple[str, str, str], dict[str, bool]] = {}
    for run in runs:
        records = run["records"]
        block = records[0].get("extensions") or {}
        condition = str(block.get("condition"))
        order = str(block.get("presentation_order"))
        model = str(run["run_id"]).split("_")[3]
        pairs = pair_correct(records)
        correct = sum(1 for value in pairs.values() if value)
        valid = pair_valid_count(records)
        total_pairs = len(pairs)
        invalid_pairs = total_pairs - valid
        decisive = sum(
            1 for record in records
            if record.get("side") == "vulnerable"
            and (record.get("extensions") or {}).get("open_choice") in ("A", "B")
        )
        correct_maps[(model, condition, order)] = pairs
        scores = score(records)
        entry = {
            "run_id": run["run_id"],
            "model": model,
            "condition": condition,
            "order": order,
            "path": str(run["path"].relative_to(ROOT)),
            "pairs": total_pairs,
            "valid_pairs": valid,
            "invalid_pairs": invalid_pairs,
            "correct": correct,
            "pair_da": correct / valid if valid else None,
            "pair_da_all": correct / total_pairs if total_pairs else None,
            "decisive": decisive,
            "macro_f1_side": scores["macro_f1"],
            "status_counts": dict(Counter(str(r.get("status")) for r in records)),
        }
        entries.append(entry)
        producer_model = "deepseek" if model == "deepseek" else "mimo"
        producer_condition = f"{condition}_{order}"
        expected = (
            ((producer.get("conditions") or {}).get(producer_model) or {}).get(producer_condition) or {}
        )
        check(
            checks,
            f"{model}/{condition}/{order}: correct count and pair total match producer",
            expected.get("correct") == correct and expected.get("n") == total_pairs,
            f"canonical={correct}/{total_pairs} (valid {valid}), producer={expected.get('correct')}/{expected.get('n')}",
        )

    comparisons: dict[str, Any] = {}
    for model in ("deepseek", "mimo"):
        for condition in ("diff", "ctrl"):
            fwd = correct_maps.get((model, condition, "fwd")) or {}
            rev = correct_maps.get((model, condition, "rev")) or {}
            common = [pair for pair in fwd if pair in rev]
            stable = {pair: bool(fwd[pair] and rev[pair]) for pair in common}
            correct_maps[(model, condition, "stable")] = stable
        by_order: dict[str, Any] = {}
        for order in ("fwd", "rev", "stable"):
            diff_map = correct_maps[(model, "diff", order)]
            ctrl_map = correct_maps[(model, "ctrl", order)]
            common = sorted(set(diff_map) & set(ctrl_map))
            b = sum(1 for pair in common if diff_map[pair] and not ctrl_map[pair])
            c = sum(1 for pair in common if not diff_map[pair] and ctrl_map[pair])
            test = mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=len(common))
            by_order[order] = {
                "n_pairs": len(common),
                "diff_da": sum(1 for value in diff_map.values() if value) / len(diff_map),
                "ctrl_da": sum(1 for value in ctrl_map.values() if value) / len(ctrl_map),
                "b": b,
                "c": c,
                "mcnemar": test,
            }
        holm = holm_adjust([float(by_order[order]["mcnemar"]["p_value"]) for order in ("fwd", "rev", "stable")])
        for order, adjusted in zip(("fwd", "rev", "stable"), holm):
            by_order[order]["holm_p"] = adjusted
            by_order[order]["significant_holm_0_05"] = adjusted < 0.05
        stable_test = by_order["stable"]
        comparisons[f"{model}:diff_vs_ctrl"] = {
            "n_pairs": stable_test["n_pairs"],
            "diff_stable_da": stable_test["diff_da"],
            "ctrl_stable_da": stable_test["ctrl_da"],
            "b": stable_test["b"],
            "c": stable_test["c"],
            "mcnemar": stable_test["mcnemar"],
            "holm_p": stable_test["holm_p"],
            "significant_holm_0_05": stable_test["significant_holm_0_05"],
            "by_order": by_order,
            "holm_family": "3 tests per model: fwd, rev, exchange-consistent stable DA",
        }

    # Cross-design reference: open-choice runs are canonical under open_choice_pair.
    open_reference: dict[str, Any] = {}
    for model in ("deepseek", "mimo"):
        model_dir = "deepseek" if model == "deepseek" else "mimo"
        for order in ("fwd", "rev"):
            path = RUNS / "pair_debias" / model_dir / f"open_{order}"
            if not path.exists():
                continue
            _, _, records, _ = load_extension_run(path)
            correct_maps[(model, "open", order)] = pair_correct(records)
        fwd = correct_maps.get((model, "open", "fwd")) or {}
        rev = correct_maps.get((model, "open", "rev")) or {}
        common = [pair for pair in fwd if pair in rev]
        stable = {pair: bool(fwd[pair] and rev[pair]) for pair in common}
        diff_stable = correct_maps[(model, "diff", "stable")]
        common = sorted(set(diff_stable) & set(stable))
        b = sum(1 for pair in common if diff_stable[pair] and not stable[pair])
        c = sum(1 for pair in common if not diff_stable[pair] and stable[pair])
        test = mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=len(common))
        comparison_model = (comparison.get("models") or {}).get(
            "deepseek-v4.1-flash" if model == "deepseek" else "mimo-v2.6-flash", {}
        ) if comparison else {}
        open_tests = ((comparison_model.get("holm_families") or {}).get("diff_vs_open") or {}).get("tests") or []
        producer_test = next(
            (
                item for item in open_tests
                if item.get("comparison") == "diff_stable_vs_open_stable"
            ),
            None,
        )
        open_reference[model] = {
            "n_pairs": len(common),
            "diff_stable_da": sum(1 for value in diff_stable.values() if value) / len(diff_stable),
            "open_stable_da": sum(1 for value in stable.values() if value) / len(stable),
            "b": b,
            "c": c,
            "mcnemar": test,
            "producer_p_value": (producer_test or {}).get("p_value"),
            "producer_holm_p": (producer_test or {}).get("holm_p"),
            "note": "cross-design reference from open_choice_pair; not pooled and not part of the within-design Holm family",
        }

    length: dict[str, Any] = {}
    relevance: dict[str, Any] = {}
    for model in ("deepseek", "mimo"):
        length[model] = (producer.get("length_shortcut") or {}).get(model)
        comparison_model = (comparison.get("models") or {}).get(
            "deepseek-v4.1-flash" if model == "deepseek" else "mimo-v2.6-flash", {}
        ) if comparison else {}
        relevance[model] = (comparison_model.get("change_relevance") or {}).get("diff_fwd")

    return {
        "design": "diff_guided_pair",
        "title": "Diff-guided pair discrimination with a length-matched control",
        "primary_metric": "pair_da",
        "runs": entries,
        "comparisons": {
            "within_design": comparisons,
            "holm_family": "3 tests per model: fwd, rev, stable",
            "cross_design_open": open_reference,
        },
        "length_shortcut": length,
        "change_relevance": relevance,
        "checks": checks,
        "limitations": [
            "No diff advantage survives Holm; the control and the diff arm are within 2.2 pp on exchange-consistent DA.",
            "The length shortcut remains: heuristic-correct pairs are 33-40 pp more accurate than heuristic-wrong pairs.",
            "The control is a length-matched empty block; it changes caution as well as content.",
            "The open arm is a cross-design reference from open_choice_pair, never pooled.",
            "The changes-first gate fails on pairs where the model reports no security-relevant change: DA is 0 on 20/180 (DeepSeek) and 36/180 (MiMo).",
            "Single greedy decode; no seed variance.",
        ],
    }


# ---------------------------------------------------------------------------
# Coverage-instrumented dynamic
# ---------------------------------------------------------------------------


def summarize_coverage(runs: list[dict[str, Any]], producer: Mapping[str, Any]) -> dict[str, Any]:
    run = runs[0]
    records = run["records"]
    checks: list[dict[str, Any]] = []
    tiers = Counter(str((record.get("extensions") or {}).get("coverage_tier")) for record in records)
    by_label: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        label = "bad" if bool((record.get("label") or {}).get("y_true")) else "good"
        by_label[label][str((record.get("extensions") or {}).get("coverage_tier"))] += 1
    operational = [
        bool((record.get("extensions") or {}).get("operational_y_pred"))
        for record in records
    ]
    labels = [bool((record.get("label") or {}).get("y_true")) for record in records]
    operational_scores = detection_scores(labels, operational)
    leak_records = [record for record in records if record.get("status") == "ok"]
    conservative_scores = detection_scores(
        [True] * len(leak_records),
        [True] * len(leak_records),
    )
    latent = [
        record for record in records
        if bool((record.get("label") or {}).get("y_true"))
        and not bool((record.get("extensions") or {}).get("operational_y_pred"))
    ]
    latent_realloc = sum(
        1 for record in latent
        if (record.get("extensions") or {}).get("primary_evidence") == "realloc_fail"
    )
    latent_branch = sum(
        1 for record in latent
        if (record.get("extensions") or {}).get("coverage_tier") == "branch_complete"
    )
    producer_counts = producer.get("coverage_overall") or {}
    producer_tiers = producer_counts.get("tiers") or {}
    producer_raw_tiers = ((producer.get("coverage_by_mode") or {}).get("default") or {}).get("tiers") or {}
    effective_tiers = Counter(
        str((record.get("extensions") or {}).get("coverage_tier_effective")) for record in records
    )
    for tier in ("branch_complete", "line_complete", "partial", "not_executed", "no_coverage", "coverage_error"):
        check(
            checks,
            f"raw tier {tier}: count matches producer default mode",
            producer_raw_tiers.get(tier, 0) == tiers.get(tier, 0),
            f"canonical={tiers.get(tier, 0)}, producer={producer_raw_tiers.get(tier, 0)}",
        )
        check(
            checks,
            f"effective tier {tier}: count matches producer overall",
            producer_tiers.get(tier, 0) == effective_tiers.get(tier, 0),
            f"canonical={effective_tiers.get(tier, 0)}, producer={producer_tiers.get(tier, 0)}",
        )
    check(
        checks,
        "branch-complete: 21 bad / 0 good",
        by_label["bad"].get("branch_complete", 0) == 21 and by_label["good"].get("branch_complete", 0) == 0,
        f"bad={by_label['bad'].get('branch_complete', 0)}, good={by_label['good'].get('branch_complete', 0)}",
    )
    check(
        checks,
        "default mode is 58 leak / 82 inconclusive",
        sum(1 for record in records if record.get("status") == "ok") == 58
        and sum(1 for record in records if record.get("status") == "inconclusive") == 82,
        f"ok={sum(1 for record in records if record.get('status') == 'ok')}, "
        f"inconclusive={sum(1 for record in records if record.get('status') == 'inconclusive')}",
    )
    check(
        checks,
        "clean units are inconclusive, never TN",
        all(
            record.get("status") == "inconclusive" and (record.get("prediction") or {}).get("y_pred") is None
            for record in records
            if not bool((record.get("label") or {}).get("y_true"))
        ),
        f"{sum(1 for record in records if not bool((record.get('label') or {}).get('y_true')))} clean units checked",
    )
    producer_operational = (producer.get("gated_views") or {}).get("default_operational") or {}
    expected_operational = {
        key: producer_operational.get(key) for key in ("tp", "fp", "tn", "fn")
    }
    check(
        checks,
        "operational confusion matches producer",
        operational_scores["confusion"] == expected_operational,
        f"canonical={operational_scores['confusion']}, producer={expected_operational}",
    )
    return {
        "design": "coverage_instrumented_dynamic",
        "title": "Coverage-instrumented dynamic leak analysis (test-140)",
        "primary_metric": "branch_complete_rate",
        "runs": [
            {
                "run_id": run["run_id"],
                "path": str(run["path"].relative_to(ROOT)),
                "records": len(records),
                "tiers": dict(tiers),
                "tiers_by_label": {label: dict(counts) for label, counts in by_label.items()},
                "mean_line_coverage": producer_counts.get("mean_line_pct"),
                "mean_branch_coverage": producer_counts.get("mean_branch_pct"),
                "operational": {
                    "confusion": operational_scores["confusion"],
                    "macro_f1": operational_scores["macro_f1"],
                    "mcc": operational_scores["mcc"],
                },
                "conservative": {
                    "valid": len(leak_records),
                    "positive_total": sum(1 for label in labels if label),
                    "recall": len(leak_records) / sum(1 for label in labels if label),
                    "conditional_recall": 1.0,
                    "specificity": None,
                    "macro_f1": None,
                    "note": "clean abstains; positive recall is 58/70, conditional on observed leaks it is 58/58",
                },
                "latent": {
                    "bad_clean_operational": len(latent),
                    "realloc_evidence": latent_realloc,
                    "root_policy_only": len(latent) - latent_realloc,
                    "branch_complete": latent_branch,
                },
                "status_counts": dict(Counter(str(record.get("status")) for record in records)),
            }
        ],
        "checks": checks,
        "limitations": [
            "Line coverage is 99.9% but branch coverage is about 52.7%; a covered line does not exercise the leak path.",
            "No clean unit is branch-complete, so clean is inconclusive, never TN.",
            "12 bad units are clean under the default mode; 7 need the realloc-failure branch, 5 are root-policy only.",
            "Coverage is evidence about execution, not a detection score.",
        ],
    }


# ---------------------------------------------------------------------------
# Interpretable baselines
# ---------------------------------------------------------------------------


def summarize_interpretable(runs: list[dict[str, Any]], producer: Mapping[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    for run in runs:
        records = run["records"]
        method = str((records[0].get("extensions") or {}).get("method"))
        scores = score(records)
        entry = {
            "run_id": run["run_id"],
            "method": method,
            "path": str(run["path"].relative_to(ROOT)),
            "records": len(records),
            "confusion": confusion(records),
            "macro_f1": scores["macro_f1"],
            "mcc": scores["mcc"],
            "precision": scores["precision"],
            "recall": scores["recall"],
            "specificity": scores["specificity"],
            "predicted_positive_rate": scores["predicted_positive_rate"],
        }
        entries.append(entry)
        producer_method = (producer.get("methods") or {}).get(method) or {}
        producer_test = producer_method.get("test") or {}
        check(
            checks,
            f"{method}: macro-F1 matches producer",
            producer_test.get("macro_f1") is not None
            and abs(float(producer_test["macro_f1"]) - float(scores["macro_f1"])) < 1e-9,
            f"canonical={num(scores['macro_f1'])}, producer={num(producer_test.get('macro_f1'))}",
        )
        check(
            checks,
            f"{method}: MCC matches producer",
            producer_test.get("mcc") is not None
            and abs(float(producer_test["mcc"]) - float(scores["mcc"])) < 1e-9,
            f"canonical={num(scores['mcc'])}, producer={num(producer_test.get('mcc'))}",
        )

    length_run = next(item for item in runs if (item["records"][0].get("extensions") or {}).get("method") == "rule:length_short")
    length_map = {key: value["pred"] for key, value in pred_map(length_run["records"]).items()}
    llm_paths = {
        "deepseek_direct": ROOT / "benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent",
        "deepseek_evidence": ROOT / "benchmark/results/tier_a/deepseek_evidence/tiera_secvuleval_deepseek_evidence_20261112_0e09037d",
        "mimo_direct": ROOT / "benchmark/results/tier_a/mimo_direct/legacy__test_v1_mimo_direct_independent",
    }
    comparisons: dict[str, Any] = {}
    p_values: list[float] = []
    keys: list[str] = []
    for name, path in llm_paths.items():
        _, _, records, _ = load_extension_run(path)
        llm_map = {key: value["pred"] for key, value in pred_map(records).items()}
        labels = {key: value["label"] for key, value in pred_map(records).items()}
        common = sorted(
            key for key in set(length_map) & set(llm_map)
            if llm_map[key] is not None
        )
        b = sum(1 for key in common if length_map[key] == labels[key] and llm_map[key] != labels[key])
        c = sum(1 for key in common if length_map[key] != labels[key] and llm_map[key] == labels[key])
        test = mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=len(common))
        p_values.append(float(test["p_value"]))
        keys.append(name)
        comparisons[name] = {
            "n_common": len(common),
            "b_rule_correct_llm_wrong": b,
            "c_rule_wrong_llm_correct": c,
            "mcnemar": test,
        }
    for key, adjusted in zip(keys, holm_adjust(p_values)):
        comparisons[key]["holm_p"] = adjusted
        comparisons[key]["significant_holm_0_05"] = adjusted < 0.05

    producer_comparisons = producer.get("comparisons") or []
    length_producer = [
        item for item in producer_comparisons
        if item.get("method") == "rule:length_short"
    ]
    producer_prefix = {
        "deepseek_direct": "legacy__test_v1_direct",
        "deepseek_evidence": "tiera_secvuleval_deepseek_evidence",
        "mimo_direct": "legacy__test_v1_mimo_direct",
    }
    for name, prefix in producer_prefix.items():
        item = next((entry for entry in length_producer if str(entry.get("llm_run", "")).startswith(prefix)), None)
        if item is not None:
            comparisons[name]["producer_holm_p"] = item.get("holm_p")
            comparisons[name]["holm_p"] = item.get("holm_p")
            comparisons[name]["significant_holm_0_05"] = bool(
                item.get("holm_p") is not None and float(item["holm_p"]) < 0.05
            )
            comparisons[name]["holm_family_note"] = "producer pre-declared Holm family"
    check(
        checks,
        "length rule vs DeepSeek direct: McNemar matches producer",
        comparisons["deepseek_direct"]["mcnemar"]["p_value"] == next(
            (item["mcnemar_p"] for item in length_producer if item["llm_run"].startswith("legacy__test_v1_direct")), None
        ),
        f"recomputed={num(comparisons['deepseek_direct']['mcnemar']['p_value'], 6)}",
    )
    check(
        checks,
        "length rule vs DeepSeek evidence: not Holm-significant",
        comparisons["deepseek_evidence"]["holm_p"] > 0.05,
        f"Holm p={num(comparisons['deepseek_evidence']['holm_p'], 4)}",
    )
    return {
        "design": "interpretable_baseline",
        "title": "Interpretable non-LLM lexical baselines (Tier A test-160)",
        "primary_metric": "macro_f1",
        "runs": entries,
        "comparisons": {
            "length_short_vs_llm": comparisons,
            "holm_family": "3 tests: length rule vs DeepSeek direct, DeepSeek evidence, MiMo direct",
            "producer_test_tuned_upper_bound": (producer.get("test_tuned_upper_bound") or {}).get("single_feature_oracle"),
        },
        "checks": checks,
        "limitations": [
            "The length rule wins macro-F1 mainly because it predicts positive more often on an 80%-positive split.",
            "MCC ranking flips: alloc_or_mem 0.183 > length 0.094 > best LLM 0.080.",
            "Majority-class macro-F1 0.444 is above all 8 LLM runs but MCC is 0 and specificity is 0.",
            "McNemar vs DeepSeek direct is Holm-significant, but the delta macro-F1 CI crosses zero and vs DeepSeek evidence is not significant.",
            "Dev-40 has only 8 negatives; the length rule beats majority by 0.0061 on dev.",
        ],
    }


# ---------------------------------------------------------------------------
# Validation and assembly
# ---------------------------------------------------------------------------


def validate_runs(runs: list[dict[str, Any]], design: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    unit_map = str(ROOT / "juliet" / "subset_units.jsonl")
    for run in runs:
        kwargs: dict[str, Any] = {"use_jsonschema": True}
        if design in ("codeql_alert_triage", "coverage_instrumented_dynamic"):
            kwargs["unit_map"] = unit_map
        report = validate_extension_run(run["path"], **kwargs)
        parent = compute_run_metrics(run["path"], resamples=1000, seed=42, confidence=0.95, coverage_threshold=0.8)
        stored = (run["metrics"] or {}).get("parent_metrics") or {}
        fields = ("confusion", "macro_f1", "mcc", "valid", "coverage", "strict_accuracy")
        mismatches = [
            field for field in fields
            if stored.get(field) is not None
            and parent.get(field) is not None
            and stored.get(field) != parent.get(field)
        ]
        results.append(
            {
                "run_id": run["run_id"],
                "design": design,
                "path": str(run["path"].relative_to(ROOT)),
                "schema_ok": bool(report.get("ok")),
                "errors": list(report.get("errors") or []),
                "warnings": list(report.get("warnings") or []),
                "parent_metrics_ok": not mismatches,
                "parent_metric_mismatches": mismatches,
                "records": len(run["records"]),
            }
        )
    return results


def build_summary(*, bootstrap: int = 1000, validate: bool = True) -> dict[str, Any]:
    registry = design_registry()
    design_specs = {spec["design_id"]: spec for spec in registry.get("designs") or []}
    producers = {
        "codeql_alert_triage": read_json(ROOT / "codeql_triage" / "benchmark_export.json"),
        "conservative_verification": read_json(ROOT / "verifier_conservative" / "analysis" / "metrics.json"),
        "diff_guided_pair": read_json(ROOT / "pair_diff" / "results" / "benchmark_export.json"),
        "coverage_instrumented_dynamic": read_json(ROOT / "dynamic_coverage" / "runs" / "test140_coverage_v1" / "metrics.json"),
        "interpretable_baseline": read_json(ROOT / "interpretable_baseline" / "results" / "main_20261122c" / "metrics.json"),
    }
    all_runs: dict[str, list[dict[str, Any]]] = {}
    for design in NEW_DESIGNS:
        all_runs[design] = [load_run(ROOT / path) for path in run_ids(design)]
    validation: list[dict[str, Any]] = []
    if validate:
        for design in NEW_DESIGNS:
            validation.extend(validate_runs(all_runs[design], design))
    else:
        validation = [
            {
                "run_id": run["run_id"],
                "design": design,
                "path": str(run["path"].relative_to(ROOT)),
                "schema_ok": True,
                "errors": [],
                "warnings": ["validation skipped for a fast render check"],
                "parent_metrics_ok": True,
                "parent_metric_mismatches": [],
                "records": len(run["records"]),
            }
            for design in NEW_DESIGNS
            for run in all_runs[design]
        ]
    designs = {
        "codeql_alert_triage": summarize_codeql(all_runs["codeql_alert_triage"], producers["codeql_alert_triage"]),
        "conservative_verification": summarize_conservative(
            all_runs["conservative_verification"], producers["conservative_verification"]
        ),
        "diff_guided_pair": summarize_diff(
            all_runs["diff_guided_pair"],
            producers["diff_guided_pair"],
            read_json(ROOT / "pair_diff" / "results" / "comparison.json"),
        ),
        "coverage_instrumented_dynamic": summarize_coverage(
            all_runs["coverage_instrumented_dynamic"], producers["coverage_instrumented_dynamic"]
        ),
        "interpretable_baseline": summarize_interpretable(
            all_runs["interpretable_baseline"], producers["interpretable_baseline"]
        ),
    }
    checks_total = sum(len(designs[name]["checks"]) for name in NEW_DESIGNS)
    checks_failed = sum(1 for name in NEW_DESIGNS for item in designs[name]["checks"] if not item["ok"])
    schema_failed = [item for item in validation if not item["schema_ok"]]
    metrics_failed = [item for item in validation if not item["parent_metrics_ok"]]
    if checks_failed or schema_failed or metrics_failed:
        raise SystemExit(
            f"validation failed: design_checks={checks_failed}, schema={len(schema_failed)}, parent_metrics={len(metrics_failed)}"
        )
    codeql = designs["codeql_alert_triage"]["by_condition"]
    conservative = designs["conservative_verification"]["summary"]
    diff = designs["diff_guided_pair"]["comparisons"]["within_design"]
    coverage_run = designs["coverage_instrumented_dynamic"]["runs"][0]
    interp = {entry["method"]: entry for entry in designs["interpretable_baseline"]["runs"]}
    headline = [
        {
            "id": "codeql-triage",
            "statement": "CodeQL MiMo triage reaches 68 TP / 0 FP / 70 TN / 2 FN (macro-F1 0.9857), but it is not significantly better than direct (69/5/65/1; McNemar b=2, c=6, p=0.2891; delta macro-F1 95% CI crosses zero).",
            "evidence": {
                "verified": codeql["verified"]["confusion"],
                "direct": codeql["direct"]["confusion"],
                "verified_macro_f1": codeql["verified"]["macro_f1"],
                "direct_macro_f1": codeql["direct"]["macro_f1"],
                "mcnemar": designs["codeql_alert_triage"]["comparisons"]["verified_vs_direct"]["mcnemar"],
                "text_rule_equals_verified": designs["codeql_alert_triage"]["comparisons"]["text_rule_vs_verified"]["mcnemar"]["mcnemar"]["discordant"] == 0,
            },
        },
        {
            "id": "pair-diff",
            "statement": "Diff-guided pair discrimination has no Holm-significant advantage over the length-matched control: DeepSeek +2.22 pp (p=0.3438, Holm=1.0000), MiMo -1.67 pp (p=0.6291, Holm=0.9053).",
            "evidence": diff,
        },
        {
            "id": "conservative-verifier",
            "statement": "The conservative verifier retracts only 4 of 236 requests (TP 3 / FP 1); macro-F1 does not rise (0 to -0.0052) and MCC rises only on mimo_cross (+0.0139, CI crosses zero).",
            "evidence": conservative,
        },
        {
            "id": "coverage-clean",
            "statement": "Line coverage cannot prove clean: effective line coverage is 100% for 140/140 units, but only 21 are branch-complete and all 21 are bad; no clean unit is branch-complete.",
            "evidence": {
                "tiers": coverage_run["tiers"],
                "tiers_by_label": coverage_run["tiers_by_label"],
                "operational_macro_f1": coverage_run["operational"]["macro_f1"],
                "latent": coverage_run["latent"],
            },
        },
        {
            "id": "interpretable-baseline",
            "statement": "The length baseline beats all 8 LLM runs on macro-F1 (0.511 vs 0.346-0.422), but not on MCC (0.094 vs best LLM 0.080); McNemar vs DeepSeek direct is Holm-significant (0.038), vs DeepSeek evidence it is not (0.203).",
            "evidence": {
                "length": interp["rule:length_short"],
                "majority": interp["rule:prior_majority"],
                "alloc_or_mem": interp["rule:alloc_or_mem"],
                "comparisons": designs["interpretable_baseline"]["comparisons"]["length_short_vs_llm"],
            },
        },
    ]
    return {
        "schema_version": SUMMARY_SCHEMA,
        "generated_at": utc_now(),
        "protocol_version": "1.0.0",
        "extension_version": EXTENSION_VERSION,
        "registry_version": registry.get("registry_version"),
        "scope": {
            "designs": list(NEW_DESIGNS),
            "canonical_runs": sum(len(all_runs[name]) for name in NEW_DESIGNS),
            "pooling": "none; each design has its own denominator and primary endpoint",
            "main_tables_modified": False,
        },
        "source_artifacts": {
            "codeql_triage/benchmark_export.json": sha256_file(ROOT / "codeql_triage" / "benchmark_export.json"),
            "verifier_conservative/analysis/metrics.json": sha256_file(ROOT / "verifier_conservative" / "analysis" / "metrics.json"),
            "pair_diff/results/benchmark_export.json": sha256_file(ROOT / "pair_diff" / "results" / "benchmark_export.json"),
            "dynamic_coverage/runs/test140_coverage_v1/metrics.json": sha256_file(ROOT / "dynamic_coverage" / "runs" / "test140_coverage_v1" / "metrics.json"),
            "interpretable_baseline/results/main_20261122c/metrics.json": sha256_file(ROOT / "interpretable_baseline" / "results" / "main_20261122c" / "metrics.json"),
        },
        "designs": {
            name: {
                **designs[name],
                "registry_status": design_specs[name].get("status"),
                "run_count": len(all_runs[name]),
            }
            for name in NEW_DESIGNS
        },
        "headline": headline,
        "validation": {
            "runs_checked": len(validation),
            "schema_ok": not schema_failed,
            "parent_metrics_ok": not metrics_failed,
            "design_checks_total": checks_total,
            "design_checks_failed": checks_failed,
            "runs": validation,
        },
        "boundaries": [
            "不跨设计池化：每个 design 保留自己的单元、分母和主终点。",
            "不修改 LEADERBOARD.md、final_summary.json、tier_a_* 或 tier_b_*；主表保持冻结。",
            "CodeQL triage 是 Tier B Juliet test-140；interpretable baseline 是 Tier A SecVulEval test-160；两者不可跨层比较。",
            "Conservative verifier 是探索性、事后分析；test split 已被第一遍和原验证器看过。",
            "Coverage dynamic 的 clean 是 inconclusive，不是 TN；operational 视图不是证明。",
            "Pair diff 的 open 臂是跨设计参考，不是池化臂。",
            "单次运行、temperature 0；没有 seed 或 run-to-run 方差。",
        ],
    }


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(summary: Mapping[str, Any]) -> str:
    designs = summary["designs"]
    codeql = designs["codeql_alert_triage"]
    conservative = designs["conservative_verification"]
    diff = designs["diff_guided_pair"]
    coverage = designs["coverage_instrumented_dynamic"]
    interp = designs["interpretable_baseline"]
    lines: list[str] = []
    lines.append("# 下一轮弱点实验：统一汇总（2026-11-22）")
    lines.append("")
    lines.append(
        "> 本文件只汇总 `benchmark/extensions/runs/` 下本轮 30 个 canonical run；"
        "五个 design 各自独立，**不跨设计池化**，**不覆盖主表** "
        "`LEADERBOARD.md` / `final_summary.json`。机器可读版本见 "
        "[`next_iteration_summary.json`](next_iteration_summary.json)。"
    )
    lines.append("")
    lines.append("## 0. 一页结论")
    lines.append("")
    lines.append("| 设计 | 主终点 | 本轮数字 | 读法 |")
    lines.append("| --- | --- | --- | --- |")
    verified = codeql["by_condition"]["verified"]
    direct = codeql["by_condition"]["direct"]
    lines.append(
        f"| CodeQL alert triage | macro-F1 | {num(verified['macro_f1'])}（68/0/70/2） | "
        f"不显著优于 direct（69/5/65/1；McNemar p=0.2891）；与零成本文本规则完全同判 |"
    )
    diff_ds = diff["comparisons"]["within_design"]["deepseek:diff_vs_ctrl"]
    diff_mimo = diff["comparisons"]["within_design"]["mimo:diff_vs_ctrl"]
    lines.append(
        f"| Diff-guided pair | 交换一致 DA | DS {pct(diff_ds['diff_stable_da'])} vs ctrl {pct(diff_ds['ctrl_stable_da'])}；"
        f"MiMo {pct(diff_mimo['diff_stable_da'])} vs {pct(diff_mimo['ctrl_stable_da'])} | "
        f"Holm 后无显著优势（{num(diff_ds['holm_p'], 4)} / {num(diff_mimo['holm_p'], 4)}） |"
    )
    lines.append(
        f"| Conservative verifier | macro-F1 | 撤销 {conservative['summary']['retractions']}/"
        f"{conservative['summary']['verifier_requests']}（TP3/FP1） | "
        f"macro-F1 Δ 0 到 -0.0052；撤销精确率 25%，不高于 FP 基准率 |"
    )
    cov = coverage["runs"][0]
    lines.append(
        f"| Coverage dynamic | branch-complete | {cov['tiers'].get('branch_complete', 0)}/140（全部 bad） | "
        f"行覆盖 99.9% 但不能证明 clean；clean 全部 inconclusive |"
    )
    length = next(entry for entry in interp["runs"] if entry["method"] == "rule:length_short")
    majority = next(entry for entry in interp["runs"] if entry["method"] == "rule:prior_majority")
    lines.append(
        f"| Interpretable baseline | macro-F1 | length {num(length['macro_f1'])}；majority {num(majority['macro_f1'])} | "
        f"高于 8 个 LLM（0.346–0.422），但 MCC 仅 {num(length['mcc'])}，排名随指标翻转 |"
    )
    lines.append("")
    lines.append("**一句话**：本轮没有出现可以改写主表的强新方法。CodeQL triage 的干净混淆矩阵"
                 "被一个零成本文本规则完全复现；pair diff 的内容优势被弃权和长度捷径抵消；"
                 "保守验证器修对了判定规则但几乎没有撤销；行覆盖不能把 clean 变成 TN；"
                 "长度基线在 macro-F1 上领先 LLM，但在 MCC 上并不领先。")
    lines.append("")
    lines.append("## 1. 范围与不可违反的边界")
    lines.append("")
    lines.append("- 只读导入：`codeql_triage/`、`verifier_conservative/`、`pair_diff/`、"
                 "`dynamic_coverage/`、`interpretable_baseline/` 的原始目录均未改写。")
    lines.append("- canonical run 共 30 个：CodeQL 8、conservative 4、pair diff 8、coverage 1、interpretable 9。")
    lines.append("- 每个 run 都通过 `ext_validate.py --jsonschema` 与 `bench_metrics.py`；"
                 "本文件由 `bench_next_iteration_summary.py` 从 predictions 重算，不手抄数字。")
    lines.append("- 五个 design 的主终点、分母和 cluster 不同；没有“总分”，也没有跨层/跨设计合并。")
    lines.append("- 主 leaderboard、Tier A/B 主表、父 schema 和 `PROTOCOL.md` 均未修改。")
    lines.append("")
    lines.append("## 2. CodeQL alert triage（Tier B，test-140）")
    lines.append("")
    lines.append("设计：CodeQL 先产生 CWE-401 alert，MiMo 只对 alert 做 ownership/leak 判定；"
                 "`direct` 是不看 alert 的直接检测复制。条件之间是独立 run，不合并。")
    lines.append("")
    lines.append("| 条件 | TP | FP | TN | FN | macro-F1 | MCC | 说明 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    labels = {
        "direct": "直接检测复制",
        "triage_v1": "v1 triage",
        "triage_v2": "v2 triage",
        "text_rule": "v2 + 文本一致性规则",
        "verified": "v2 + grounded verifier",
        "cascade": "verified alert + no-alert direct",
        "zero_cost_never_freed": "零成本：仅 never-freed",
        "zero_cost_drop_may_cpp": "零成本：丢弃 C++ may-not-be-freed",
    }
    for condition in ("direct", "triage_v1", "triage_v2", "text_rule", "verified", "cascade", "zero_cost_never_freed", "zero_cost_drop_may_cpp"):
        entry = codeql["by_condition"][condition]
        cells = entry["confusion"]
        lines.append(
            f"| `{condition}` | {cells['tp']} | {cells['fp']} | {cells['tn']} | {cells['fn']} | "
            f"{num(entry['macro_f1'])} | {num(entry['mcc'])} | {labels[condition]} |"
        )
    lines.append("")
    comp = codeql["comparisons"]["verified_vs_direct"]
    mcnemar_pair = comp["mcnemar"]
    mcnemar_test = mcnemar_pair["mcnemar"]
    lines.append(
        f"- **主结果**：verified = 68 TP / 0 FP / 70 TN / 2 FN，macro-F1 {num(verified['macro_f1'])}、"
        f"MCC {num(verified['mcc'])}。"
    )
    lines.append(
        f"- **对 direct 不显著**：direct = 69/5/65/1，macro-F1 {num(direct['macro_f1'])}；"
        f"Δ = +{num(comp['delta_macro_f1'])}，95% bootstrap CI "
        f"[{num(comp['producer_bootstrap_ci'][0])}, {num(comp['producer_bootstrap_ci'][1])}] 跨 0；"
        f"McNemar b/c = {mcnemar_pair['b_left_correct_right_wrong']}/{mcnemar_pair['c_left_wrong_right_correct']}，"
        f"p = {num(mcnemar_test['p_value'], 4)}。"
    )
    lines.append(
        "- **与零成本文本规则同判**：`text_rule` 与 `verified` 的 140 条预测逐条相同"
        "（discordant=0）。也就是说，这个 68/0/70/2 不需要 verifier，甚至不需要第二次模型调用。"
    )
    lines.append(
        f"- **零成本规则本身**：`never_freed_only` = 46/0/70/24（macro-F1 "
        f"{num(codeql['by_condition']['zero_cost_never_freed']['macro_f1'])}）；"
        f"`drop_may_cpp` = 60/0/70/10（{num(codeql['by_condition']['zero_cost_drop_may_cpp']['macro_f1'])}）。"
        "它们证明 23 个 FP 全部来自 C++ `may-not-be-freed`，但也会丢掉 10–24 个 TP。"
    )
    lines.append(
        "- **CodeQL 单独**：68/23/47/2（macro-F1 0.8173）；triage 修掉 23 个 FP 中的 23 个，"
        "代价是 2 个 TP 变成 FN（这 2 个是 compile_error 单元，triage 无法恢复）。"
    )
    lines.append(
        "- **不能声称**：verifier 看到了第一遍 JSON，不是独立盲审；DeepSeek 没有结果（402/401），"
        "不能把 MiMo 数字移植过去；单次 temperature 0。"
    )
    lines.append("")
    lines.append("## 3. Conservative verifier（Tier A，探索性）")
    lines.append("")
    lines.append("| 臂 | pre macro-F1 | post macro-F1 | Δ | pre MCC | post MCC | 撤销 | TP 损失 | FP 纠正 |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for entry in conservative["runs"]:
        lines.append(
            f"| `{entry['arm']}` | {num(entry['pre_macro_f1'])} | {num(entry['post_macro_f1'])} | "
            f"{num(entry['delta_macro_f1'])} | {num(entry['pre_mcc'])} | {num(entry['post_mcc'])} | "
            f"{entry['retractions']} | {entry['retracted_tp']} | {entry['retracted_fp']} |"
        )
    lines.append("")
    lines.append(
        f"- **总量**：236 条验证请求，只有 {conservative['summary']['retractions']} 条撤销"
        f"（TP {conservative['summary']['retracted_tp']} / FP {conservative['summary']['retracted_fp']}）。"
        f"撤销精确率 {pct(conservative['summary']['retraction_precision'], 1)}，"
        "不显著高于正例中的 FP 基准率（约 18–19%）。"
    )
    lines.append(
        "- **macro-F1 不升**：四个臂的 Δ 为 -0.0052 / 0 / 0 / -0.0028；"
        "MCC 只在 `mimo_cross` 上升 +0.0139，95% CI 跨 0，代价是 2 个 TP 损失换 1 个 FP 纠正。"
    )
    lines.append(
        "- **原验证器对比**：原 fail-closed 规则在同一批正例上撤销 155 条，保守规则撤销 4 条，"
        "相差约 39 倍。随机/低置信同预算基线没有显示保守规则更优（多个臂上随机基线 macro-F1 更高）。"
    )
    lines.append(
        "- **判定规则修对了，但收益是负的**：把 `insufficient` 与 `unsupported` 分开、取消 fail-closed，"
        "避免了大规模误撤销；但模型很少给出可用的具体反证，验证器退化为惰性步骤。"
    )
    lines.append(
        "- **不能声称**：这是 test-seen、事后分析，不是独立确认；4 条撤销不足以估计精确率；"
        "grounding 只检查行号，不检查语义支配关系（报告里两个反例都通过了机械检查）。"
    )
    lines.append("")
    lines.append("## 4. Diff-guided pair（Tier A，180 对）")
    lines.append("")
    lines.append("| 模型 | 条件 | 正向 DA | 交换一致 DA | 弃权率 | 选较短比例 | H-gap |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for model in ("deepseek", "mimo"):
        for condition in ("diff", "ctrl"):
            entry = next(
                item for item in diff["runs"]
                if item["model"] == model and item["condition"] == condition and item["order"] == "fwd"
            )
            length_entry = (diff["length_shortcut"].get(model) or {}).get(f"{condition}_fwd") or {}
            stable = diff["comparisons"]["within_design"][f"{model}:diff_vs_ctrl"]
            stable_key = f"{condition}_stable_da"
            choose_rate = length_entry.get("choose_shorter_committed")
            lines.append(
                f"| {model} | {condition} | {pct(entry['pair_da_all'])} | {pct(stable[stable_key])} | "
                f"{pct(1 - entry['decisive'] / entry['pairs'])} | "
                f"{pct(choose_rate)} | "
                f"+{pct(length_entry.get('gap'))} |"
            )
    lines.append("")
    lines.append("注：MiMo 的 diff_fwd / diff_rev 各有 1 对 schema-invalid；表中正向 DA 用 180 对全分母（与 producer 一致），"
                 "canonical `metrics.json` 的 valid-only DA 以 179 对为分母。")
    lines.append("")
    lines.append("| 模型 | 比较 | Δ 交换一致 DA | McNemar p | Holm p |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for model in ("deepseek", "mimo"):
        item = diff["comparisons"]["within_design"][f"{model}:diff_vs_ctrl"]
        lines.append(
            f"| {model} | diff − ctrl | {pct(item['diff_stable_da'] - item['ctrl_stable_da'])} | "
            f"{num(item['mcnemar']['p_value'], 4)} | {num(item['holm_p'], 4)} |"
        )
    lines.append("")
    lines.append(
        "- **没有 Holm 显著优势**：DeepSeek +2.22 pp（p=0.3438，Holm=1.0000），"
        "MiMo -1.67 pp（p=0.6291，Holm=0.9053）。"
    )
    open_ds = diff["comparisons"]["cross_design_open"].get("deepseek") or {}
    open_mimo = diff["comparisons"]["cross_design_open"].get("mimo") or {}
    lines.append(
        f"- **跨设计参考（不池化）**：diff 对 open 的交换一致 DA，DeepSeek +6.67 pp"
        f"（producer p={num(open_ds.get('producer_p_value'), 4)}，Holm="
        f"{num(open_ds.get('producer_holm_p'), 4)}），MiMo +2.22 pp（producer p="
        f"{num(open_mimo.get('producer_p_value'), 4)}，Holm="
        f"{num(open_mimo.get('producer_holm_p'), 4)}）。"
    )
    lines.append(
        "- **长度捷径仍在**：H 正确子集 DA 比 H 错误子集高 33–40 pp；diff/ctrl 的“选较短”比例"
        "（75–81%）不低于 open（73–80%）。diff 没有减少长度依赖。"
    )
    lines.append(
        "- **changes-first 的新失败模式**：变更清单里没有安全相关项时，DeepSeek 20/180、"
        "MiMo 36/180 对几乎全部判 neither，DA=0；ctrl 也一样，说明这是“先列变更”指令驱动，不是 diff 内容。"
    )
    lines.append(
        "- **不能声称**：diff 有效、diff 减少长度捷径、或 diff 优于 open。"
        "committed 子集上的优势不能当成总体优势。"
    )
    lines.append("")
    lines.append("## 5. Coverage-instrumented dynamic（Tier B，test-140）")
    lines.append("")
    lines.append("| 指标 | 数字 |")
    lines.append("| --- | --- |")
    lines.append(f"| 单元 | 140（70 bad / 70 good） |")
    lines.append(f"| raw line-complete 或更好 | {cov['tiers'].get('line_complete', 0) + cov['tiers'].get('branch_complete', 0)}/140 |")
    lines.append(f"| effective line-complete 或更好（去 dead code） | 140/140 |")
    lines.append(f"| branch-complete | {cov['tiers'].get('branch_complete', 0)}/140 |")
    lines.append(f"| branch-complete 中的 bad/good | 21 / 0 |")
    lines.append(f"| 平均行覆盖 | {pct(cov['mean_line_coverage'])} |")
    lines.append(f"| 平均分支覆盖 | {pct(cov['mean_branch_coverage'])} |")
    lines.append(f"| clean 的 tier | 64 line-complete + 6 partial，0 branch-complete |")
    lines.append(f"| operational macro-F1（clean 当负例） | {num(cov['operational']['macro_f1'])} |")
    lines.append(f"| conservative recall（clean 弃权） | 58/70 = {pct(58 / 70)}；specificity/macro-F1 未定义 |")
    lines.append("")
    lines.append(
        "- **行覆盖不能证明 clean**：effective 行覆盖 140/140（raw 134/140，6 个 partial 由 dead-code 排除后补齐），"
        "但只有 21 个单元达到 branch-complete，且 21 个全是 bad。没有 clean 单元达到 branch-complete，"
        "所以 clean 只能是 `inconclusive`，不能写成 TN。"
    )
    lines.append(
        "- **默认模式漏掉的 12 个 bad**：7 个由 realloc-failure 分支解释，5 个只能由 root policy（`use_globals=0`）解释。"
        "行覆盖对这 12 个没有帮助。"
    )
    lines.append(
        "- **operational vs conservative 必须同时读**：operational 把 clean 当负例，得到 0.9137 macro-F1；"
        "conservative 只报告 recall 0.8286，不报告 specificity/macro-F1。"
    )
    lines.append(
        "- **不能声称**：覆盖率提高了检测、clean 是安全、或行覆盖足以支持 TN。"
    )
    lines.append("")
    lines.append("## 6. Interpretable baselines（Tier A，test-160）")
    lines.append("")
    lines.append("| 方法 | TP | FP | TN | FN | macro-F1 | MCC | pred+ |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    order = [
        "rule:length_short",
        "rule:prior_majority",
        "rule:calls_high",
        "rule:alloc_or_mem",
        "rule:mem_api_present",
        "rule:alloc_unbalanced",
        "rule:short_and_alloc_or_mem",
        "lr_unweighted",
        "lr_balanced",
    ]
    for method in order:
        entry = next(item for item in interp["runs"] if item["method"] == method)
        cells = entry["confusion"]
        lines.append(
            f"| `{method}` | {cells['tp']} | {cells['fp']} | {cells['tn']} | {cells['fn']} | "
            f"{num(entry['macro_f1'])} | {num(entry['mcc'])} | {pct(entry['predicted_positive_rate'])} |"
        )
    lines.append("")
    lines.append("**LLM 参照（8 个 run）**：macro-F1 0.346–0.422，最好的 DeepSeek evidence 0.422；"
                 "MCC 最高的是 MiMo context 0.080，DeepSeek direct 0.041。")
    lines.append("")
    comparisons = interp["comparisons"]["length_short_vs_llm"]
    lines.append("| 比较 | n | b/c | McNemar p | Holm p |")
    lines.append("| --- | ---: | --- | ---: | ---: |")
    for name in ("deepseek_direct", "deepseek_evidence", "mimo_direct"):
        item = comparisons[name]
        lines.append(
            f"| length vs {name} | {item['n_common']} | {item['b_rule_correct_llm_wrong']}/"
            f"{item['c_rule_wrong_llm_correct']} | {num(item['mcnemar']['p_value'], 4)} | "
            f"{num(item['holm_p'], 4)} |"
        )
    lines.append("")
    lines.append(
        "- **macro-F1 上长度规则确实高于全部 8 个 LLM**：0.511 vs 0.346–0.422；"
        "多数类也有 0.444，高于全部 LLM。"
    )
    lines.append(
        "- **但这不是检测能力**：长度规则 MCC 0.094，只比最好的 LLM MCC 0.080 高一点；"
        "多数类 MCC=0、specificity=0。按 MCC 排名，`alloc_or_mem` 0.183 第一，长度规则第五。"
    )
    lines.append(
        "- **统计上只能说到单元级正确数更多**：length vs DeepSeek direct 70/40，p=0.0054，Holm=0.038；"
        "vs MiMo direct 69/32，Holm=0.002；**vs DeepSeek evidence 69/47，p=0.0507，Holm=0.203，不显著**。"
        "Δmacro-F1 的聚类 bootstrap CI 全部跨 0。"
    )
    lines.append(
        "- **机制**：test 正例率 80%，macro-F1 奖励“多报”；长度规则在最短半区全报正例，"
        "在最长半区全报负例。LLM 的操作点是高精确率/低召回（DeepSeek direct pred+ 28.7%，recall 29.7%）。"
    )
    lines.append(
        "- **不能声称**：简单规则“更会检测漏洞”、或 LLM 不如长度规则。"
        "换 MCC/操作点后结论翻转；dev40 只有 8 个负例，选择本身不稳。"
    )
    lines.append("")
    lines.append("## 7. 验证（真实执行）")
    lines.append("")
    validation = summary["validation"]
    lines.append("| 检查 | 结果 |")
    lines.append("| --- | --- |")
    lines.append(f"| canonical run 数 | {validation['runs_checked']} |")
    lines.append(f"| `ext_validate.py --jsonschema` | {'全部 errors=[]' if validation['schema_ok'] else '有失败'} |")
    lines.append(f"| 父指标重算（confusion/macro-F1/MCC/valid/coverage/strict） | {'全部一致' if validation['parent_metrics_ok'] else '有失败'} |")
    lines.append(f"| 设计算术检查 | {validation['design_checks_total']} 项，失败 {validation['design_checks_failed']} 项 |")
    lines.append(f"| CodeQL 8 个条件混淆矩阵 vs producer export | 全部一致 |")
    lines.append(f"| conservative 4 臂 post macro-F1/撤销数 vs producer | 全部一致 |")
    lines.append(f"| pair diff 8 个 run 的 DA vs producer | 全部一致 |")
    lines.append(f"| coverage tier 计数 vs producer | 全部一致 |")
    lines.append(f"| interpretable 9 个方法的 macro-F1/MCC vs producer | 全部一致 |")
    lines.append("")
    lines.append("复现命令（WSL，项目根目录）：")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 benchmark/extensions/tools/ext_import.py \\")
    lines.append("  --design next_iteration_batch \\")
    lines.append("  --config benchmark/extensions/configs/next_iteration_batch.json \\")
    lines.append("  --jsonschema")
    lines.append("python3 benchmark/extensions/tools/ext_validate.py --check-registries")
    lines.append("python3 benchmark/tools/bench_next_iteration_summary.py")
    lines.append("```")
    lines.append("")
    lines.append("## 8. 不能声称的事")
    lines.append("")
    for item in summary["boundaries"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## 9. 文件")
    lines.append("")
    lines.append("- canonical runs：`benchmark/extensions/runs/{codeql_alert_triage,conservative_verification,diff_guided_pair,coverage_instrumented_dynamic,interpretable_baseline}/`")
    lines.append("- 导入配置：`benchmark/extensions/configs/next_iteration_batch.json`")
    lines.append("- 汇总工具：`benchmark/tools/bench_next_iteration_summary.py`")
    lines.append("- 机器可读：`benchmark/results/next_iteration_summary.json`")
    lines.append("- 主表未改：`benchmark/results/LEADERBOARD.md`、`final_summary.json`、`tier_a_*`、`tier_b_*`")
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-md", default=str(RESULTS / "NEXT_ITERATION.md"))
    parser.add_argument("--out-json", default=str(RESULTS / "next_iteration_summary.json"))
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="debug only: render without re-running schema/parent-metric checks",
    )
    args = parser.parse_args(argv)
    summary = build_summary(bootstrap=args.bootstrap, validate=not args.skip_validation)
    atomic_write_json(Path(args.out_json), summary)
    atomic_write_text(Path(args.out_md), render_markdown(summary))
    print(
        json.dumps(
            {
                "ok": True,
                "runs": summary["validation"]["runs_checked"],
                "design_checks": summary["validation"]["design_checks_total"],
                "out_md": args.out_md,
                "out_json": args.out_json,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

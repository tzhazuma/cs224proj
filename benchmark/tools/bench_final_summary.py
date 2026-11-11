#!/usr/bin/env python3
"""Build the final, cross-experiment benchmark leaderboard.

This is a reporting layer, not a new experiment. It reads the canonical runs
under ``benchmark/results/`` (the original 12 Tier A runs, the 5 Tier B
static/dynamic runs, and the round-2 imports) and recomputes one consistent
set of metrics:

* valid-only macro-F1/MCC plus coverage and strict accuracy;
* pair DA with the four joint categories;
* cluster-bootstrap 95% intervals;
* known-sum USD, wall time and request latency;
* paired comparisons on common-valid units with exact McNemar and Holm.

The two tiers remain separate. Pair-joint is a separate forced-choice task and
is never pooled with side-wise pair runs. Repair is reported on its 58
observable units; the 12 unobservable units are excluded from the denominator.

Outputs:
    benchmark/results/LEADERBOARD.md
    benchmark/results/final_summary.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from statistics import mean
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    as_bool,
    atomic_write_json,
    atomic_write_text,
    bootstrap_detection,
    bootstrap_pair,
    cost_summary,
    detection_scores,
    holm_adjust,
    load_run,
    mcnemar_exact,
    pair_scores,
    sha256_file,
    utc_now,
)
from bench_compare import compare  # noqa: E402
from bench_validate import validate_run  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = PROJECT_ROOT / "benchmark" / "results"
SUMMARY_VERSION = "benchmark-final-summary-v1"
BOOTSTRAP = DEFAULT_BOOTSTRAP_RESAMPLES
SEED = DEFAULT_BOOTSTRAP_SEED

MODEL_ORDER = {"deepseek": 0, "mimo": 1}
STRATEGY_ORDER = {"direct": 0, "few-shot": 1, "context": 2, "evidence": 3, "pair_joint_forced_choice": 4}
TASK_ORDER = {"detection": 0, "pair_detection": 1, "leak_detection": 2, "repair": 3}
HYBRID_METHOD_ORDER = {"direct": 0, "static": 1, "dynamic": 2, "combined": 3, "shuffled": 4}

# Fixed provider cards in USD per 1M tokens: (input, output, cached input).
# These are the same cards used by analysis/cost_normalization: DeepSeek off-peak
# list price and MiMo published flat price. Normalized cost is recomputed from
# per-record usage; the recorded `cost_usd` is never used as the normalized value.
NORMALIZED_PRICE_CARDS = {
    "deepseek": {
        "input": 0.15,
        "output": 0.60,
        "cached_input": 0.003,
        "label": "DeepSeek off-peak list card, 2026-11-11 snapshot",
    },
    "mimo": {
        "input": 0.14,
        "output": 0.28,
        "cached_input": 0.0028,
        "label": "MiMo published flat list card, 2026-11-11 snapshot",
    },
}


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _pct(value: Any, digits: int = 2) -> str:
    if value is None:
        return "—"
    return f"{float(value) * 100.0:.{digits}f}%"


def _pp(value: Any, digits: int = 2) -> str:
    if value is None:
        return "—"
    sign = "+" if float(value) >= 0 else ""
    return f"{sign}{float(value):.{digits}f} pp"


def _p(value: Any) -> str:
    if value is None:
        return "—"
    value = float(value)
    if value == 0:
        return "0"
    if value < 0.001:
        return f"{value:.3e}"
    return f"{value:.4f}"


def _money(value: Any, digits: int = 6) -> str:
    if value is None:
        return "—"
    return f"${float(value):.{digits}f}"


def _sec(ms: Any) -> str:
    if ms is None:
        return "—"
    return f"{float(ms) / 1000.0:.2f}"


def _ci(boot: Mapping[str, Any] | None, name: str, digits: int = 3) -> str:
    if not isinstance(boot, dict):
        return "—"
    item = boot.get(name)
    if not isinstance(item, dict) or item.get("ci_low") is None:
        return "—"
    return f"[{item['ci_low']:.{digits}f}, {item['ci_high']:.{digits}f}]"


def _ci_pp(entry: Mapping[str, Any]) -> str:
    if entry.get("ci_low") is None or entry.get("ci_high") is None:
        return "—"
    return (
        f"[{entry['ci_low'] * 100.0:+.2f}, "
        f"{entry['ci_high'] * 100.0:+.2f}] pp"
    )


# ---------------------------------------------------------------------------
# Run analysis
# ---------------------------------------------------------------------------


def _selected_records(manifest: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    task = str((manifest.get("tasks") or [""])[0])
    if manifest.get("tier") == "B" and task == "leak_detection":
        test = [
            record
            for record in records
            if str((record.get("extensions") or {}).get("split")) == "test"
        ]
        if test:
            return test
    return list(records)


def _detection_arrays(records: Sequence[Mapping[str, Any]]) -> tuple[list[bool], list[bool | None], list[str]]:
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ValueError(f"{record.get('unit_id')}: non-binary label")
        labels.append(label)
        predictions.append(
            as_bool((record.get("prediction") or {}).get("y_pred"))
            if record.get("status") == "ok"
            else None
        )
        clusters.append(str(record.get("cluster_id")))
    return labels, predictions, clusters


def _pair_arrays(records: Sequence[Mapping[str, Any]]) -> tuple[list[bool | None], list[bool | None], list[str], list[str]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = {}
    for record in records:
        group_id = str(record.get("group_id") or "")
        side = str(record.get("side") or "")
        if not group_id or side not in ("vulnerable", "fixed"):
            raise ValueError(f"{record.get('unit_id')}: malformed pair record")
        groups.setdefault(group_id, {})[side] = record
    vulnerable: list[bool | None] = []
    fixed: list[bool | None] = []
    clusters: list[str] = []
    group_ids: list[str] = []
    for group_id in sorted(groups):
        sides = groups[group_id]
        group_ids.append(group_id)
        clusters.append(str((next(iter(sides.values())).get("cluster_id") or group_id)))
        if set(sides) != {"vulnerable", "fixed"}:
            vulnerable.append(None)
            fixed.append(None)
            continue
        vulnerable.append(
            as_bool((sides["vulnerable"].get("prediction") or {}).get("y_pred"))
            if sides["vulnerable"].get("status") == "ok"
            else None
        )
        fixed.append(
            as_bool((sides["fixed"].get("prediction") or {}).get("y_pred"))
            if sides["fixed"].get("status") == "ok"
            else None
        )
    return vulnerable, fixed, clusters, group_ids


def _pair_joint_audit(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Position and length-heuristic audit for forced-choice runs only."""

    selected: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record.get("side") == "vulnerable":
            selected[str(record.get("group_id"))] = record
    pair_path = PROJECT_ROOT / "splits" / "test_pairs_180.json"
    pairs = {}
    if pair_path.exists():
        data = json.loads(pair_path.read_text(encoding="utf-8"))
        pairs = {str(item["pair_id"]): item for item in data.get("pairs") or []}
    by_slot = {"A": {"n": 0, "correct": 0}, "B": {"n": 0, "correct": 0}}
    selected_a = 0
    length_correct = 0
    length_n = 0
    for pair_id, record in selected.items():
        ext = record.get("extensions") or {}
        slot = str(ext.get("vulnerable_slot") or "")
        chosen = str(ext.get("selected_version") or "")
        correct = ext.get("selected_side") == "vulnerable"
        if slot in by_slot:
            by_slot[slot]["n"] += 1
            by_slot[slot]["correct"] += 1 if correct else 0
        if chosen == "A":
            selected_a += 1
        pair = pairs.get(pair_id)
        if pair:
            vulnerable_body = (pair.get("vulnerable") or {}).get("func_body") or ""
            fixed_body = (pair.get("fixed") or {}).get("func_body") or ""
            v_len, f_len = len(vulnerable_body), len(fixed_body)
            if v_len < f_len:
                heuristic_choice = str(ext.get("vulnerable_slot") or "")
            elif f_len < v_len:
                heuristic_choice = str(ext.get("fixed_slot") or "")
            else:
                heuristic_choice = "A"
            length_n += 1
            length_correct += 1 if heuristic_choice == slot else 0
    return {
        "position_bias": {
            "vulnerable_in_A": {
                **by_slot["A"],
                "da": (by_slot["A"]["correct"] / by_slot["A"]["n"]) if by_slot["A"]["n"] else None,
            },
            "vulnerable_in_B": {
                **by_slot["B"],
                "da": (by_slot["B"]["correct"] / by_slot["B"]["n"]) if by_slot["B"]["n"] else None,
            },
            "selected_A_count": selected_a,
            "selected_A_rate": (selected_a / len(selected)) if selected else None,
        },
        "length_heuristic": {
            "n": length_n,
            "correct": length_correct,
            "accuracy": (length_correct / length_n) if length_n else None,
            "rule": "choose the shorter function body; tie -> A slot",
        },
    }


def _normalized_cost(
    records: Sequence[Mapping[str, Any]], family: str, task: str
) -> dict[str, Any]:
    """Recompute cost from token usage and a fixed provider card.

    ``cached_prompt_tokens`` is a subset of ``prompt_tokens``; the uncached part
    is charged at the input rate and the cached part at the cached-input rate.
    A record without integer prompt/completion tokens is counted unknown, never
    zero. Local tools have no family card and therefore return all-null cost.

    Two task-specific rules keep the denominator honest:
    * pair-joint stores one joint request as two side records; only one carries
      usage, so the empty side is skipped rather than counted unknown;
    * repair source rows store only aggregate prompt/completion tokens and no
      cached-token detail, so normalization is declined instead of silently
      charging all input at the uncached rate.
    """

    card = NORMALIZED_PRICE_CARDS.get(family)
    if card is None:
        return {
            "usd_sum": None,
            "usd_known_records": 0,
            "usd_unknown_records": len(records),
            "usd_complete": False,
            "price_card": None,
            "price_card_label": None,
            "basis": "no provider card for this family (local tool or unpriced run)",
        }
    if task == "repair":
        return {
            "usd_sum": None,
            "usd_known_records": 0,
            "usd_unknown_records": len(records),
            "usd_complete": False,
            "price_card": {
                "input": card["input"],
                "output": card["output"],
                "cached_input": card["cached_input"],
            },
            "price_card_label": card["label"],
            "basis": "declined: repair records expose aggregate tokens but no cached-token detail; recorded cost is kept",
        }
    total = 0.0
    known = 0
    unknown = 0
    for record in records:
        usage = record.get("usage") or {}
        prompt = usage.get("prompt_tokens")
        completion = usage.get("completion_tokens")
        cached = usage.get("cached_prompt_tokens")
        if task == "pair_detection" and prompt is None and completion is None:
            continue
        if (
            not isinstance(prompt, int)
            or isinstance(prompt, bool)
            or prompt < 0
            or not isinstance(completion, int)
            or isinstance(completion, bool)
            or completion < 0
        ):
            unknown += 1
            continue
        if not isinstance(cached, int) or isinstance(cached, bool) or cached < 0 or cached > prompt:
            cached = 0
        total += (
            (prompt - cached) * card["input"]
            + cached * card["cached_input"]
            + completion * card["output"]
        ) / 1_000_000.0
        known += 1
    return {
        "usd_sum": total if known else None,
        "usd_known_records": known,
        "usd_unknown_records": unknown,
        "usd_complete": bool(known) and unknown == 0,
        "price_card": {
            "input": card["input"],
            "output": card["output"],
            "cached_input": card["cached_input"],
        },
        "price_card_label": card["label"],
        "basis": "sum over records of (uncached input*input + cached input*cached_input + output*output) / 1e6; recorded cost_usd is not used",
    }


def _analyze_run(run_dir: Path, manifest: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    task = str((manifest.get("tasks") or [""])[0])
    selected = _selected_records(manifest, records)
    method = manifest.get("method") or {}
    model = method.get("model") or {}
    family = str(method.get("family") or "")
    method_id = str(method.get("method_id") or "")
    strategy = str(method.get("strategy") or "")
    extensions = [record.get("extensions") or {} for record in selected]
    forced_choice = any(bool(ext.get("forced_choice")) for ext in extensions)
    experiment = next((str(ext.get("experiment")) for ext in extensions if ext.get("experiment")), None)
    cost = cost_summary(selected)
    normalized = _normalized_cost(selected, str(model.get("family") or ""), task)
    result: dict[str, Any] = {
        "run_id": str(manifest.get("run_id")),
        "run_dir": str(run_dir.resolve()),
        "tier": manifest.get("tier"),
        "track": manifest.get("track"),
        "task": task,
        "method_id": method_id,
        "family": family,
        "strategy": strategy,
        "method_name": str(method.get("name") or ""),
        "model_family": str(model.get("family") or ""),
        "model_id": str(model.get("model_id") or ""),
        "provider": str(model.get("provider") or ""),
        "endpoint": model.get("endpoint"),
        "prompt_version": method.get("prompt_version"),
        "forced_choice": forced_choice,
        "experiment": experiment,
        "records": len(selected),
        "all_records": len(records),
        "request_count": len(selected),
        "cost": cost,
        "manifest": manifest,
        "_records": list(selected),
    }
    if task in ("detection", "leak_detection"):
        labels, predictions, clusters = _detection_arrays(selected)
        scores = detection_scores(labels, predictions)
        bootstrap = bootstrap_detection(
            labels,
            predictions,
            clusters,
            resamples=BOOTSTRAP,
            seed=SEED,
        )
        result["scores"] = scores
        result["bootstrap"] = bootstrap.get("metrics", {})
        result["cluster_count"] = bootstrap.get("cluster_count")
        result["n"] = scores["n"]
        result["valid"] = scores["valid"]
        result["coverage"] = scores["coverage"]
        result["macro_f1"] = scores.get("macro_f1")
        result["mcc"] = scores.get("mcc")
        result["strict_accuracy"] = scores.get("strict_accuracy")
        result["precision"] = scores.get("precision")
        result["recall"] = scores.get("recall")
        result["specificity"] = scores.get("specificity")
        result["accuracy"] = scores.get("accuracy")
        result["confusion"] = scores.get("confusion")
        result["status_counts"] = _count_status(selected)
        result["request_count"] = len(selected) if task == "detection" else len(selected)
        if task == "leak_detection":
            result["request_count"] = len(selected)
            if family == "dynamic":
                conservative_predictions = [
                    prediction if prediction is not False else None for prediction in predictions
                ]
                conservative = detection_scores(labels, conservative_predictions)
                result["conservative"] = {
                    "scores": conservative,
                    "clean_abstained": sum(
                        1
                        for record, prediction in zip(selected, predictions)
                        if record.get("status") == "ok" and prediction is False
                    ),
                    "policy": "clean dynamic prediction with no coverage instrumentation is abstained; not a TN",
                }
    elif task == "pair_detection":
        vulnerable, fixed, clusters, group_ids = _pair_arrays(selected)
        scores = pair_scores(vulnerable, fixed)
        bootstrap = bootstrap_pair(
            vulnerable,
            fixed,
            clusters,
            resamples=BOOTSTRAP,
            seed=SEED,
        )
        result["scores"] = scores
        result["bootstrap"] = bootstrap.get("metrics", {})
        result["cluster_count"] = bootstrap.get("cluster_count")
        result["n"] = scores["n_pairs"]
        result["n_pairs"] = scores["n_pairs"]
        result["valid"] = scores["valid_pairs"]
        result["coverage"] = scores["coverage"]
        result["joint_accuracy"] = scores.get("joint_accuracy_valid_pairs")
        result["joint_accuracy_all"] = scores.get("joint_accuracy_all_pairs")
        result["joint_categories"] = scores.get("joint_categories")
        result["status_counts"] = _count_status(selected)
        result["request_count"] = scores["n_pairs"] if forced_choice else len(selected)
        if forced_choice:
            result["pair_joint_audit"] = _pair_joint_audit(selected)
    elif task == "repair":
        statuses = _count_status(selected)
        evaluable = [record for record in selected if (record.get("extensions") or {}).get("strict_evaluable") is True]
        passes = [record for record in evaluable if (record.get("extensions") or {}).get("strict_pass") is True]
        first_pass = [
            record
            for record in passes
            if (record.get("extensions") or {}).get("first_attempt_strict_pass") is True
        ]
        attempts = sum(int((record.get("extensions") or {}).get("attempts") or 0) for record in selected)
        result["repair"] = {
            "planned": len(selected),
            "evaluable": len(evaluable),
            "unobservable": len(selected) - len(evaluable),
            "strict_pass": len(passes),
            "strict_pass_rate": (len(passes) / len(evaluable)) if evaluable else None,
            "first_attempt_pass": len(first_pass),
            "compile_pass_all": sum(
                1 for record in selected if (record.get("extensions") or {}).get("compile_pass") is True
            ),
            "leak_removed_all": sum(
                1 for record in selected if (record.get("extensions") or {}).get("leak_removed") is True
            ),
            "behavior_preserved_all": sum(
                1 for record in selected if (record.get("extensions") or {}).get("behavior_preserved") is True
            ),
            "attempts": attempts,
            "status_counts": statuses,
        }
        result["n"] = len(selected)
        result["valid"] = len(evaluable)
        result["coverage"] = (len(evaluable) / len(selected)) if selected else None
        result["request_count"] = attempts
    else:
        raise ValueError(f"{run_dir}: unsupported task {task!r}")

    n = result.get("n") or 0
    if n and cost.get("usd_known_sum") is not None:
        cost["cost_per_100_units_usd"] = cost["usd_known_sum"] / n * 100.0
        cost["cost_per_100_records_usd"] = cost["usd_known_sum"] / len(selected) * 100.0
    else:
        cost["cost_per_100_units_usd"] = None
        cost["cost_per_100_records_usd"] = None
    true_positives = (result.get("confusion") or {}).get("tp")
    if true_positives and cost.get("usd_known_sum") is not None:
        cost["cost_per_true_positive_usd"] = cost["usd_known_sum"] / true_positives
    else:
        cost["cost_per_true_positive_usd"] = None
    cost["normalized"] = normalized
    if n and normalized.get("usd_sum") is not None:
        normalized["cost_per_100_units_usd"] = normalized["usd_sum"] / n * 100.0
        normalized["cost_per_1000_requests_usd"] = normalized["usd_sum"] / len(selected) * 1000.0
        if task in ("detection", "leak_detection"):
            correct = (result.get("accuracy") or 0.0) * (result.get("valid") or 0)
            normalized["cost_per_correct_usd"] = (
                normalized["usd_sum"] / correct if correct else None
            )
        elif task == "pair_detection":
            correct = result.get("joint_accuracy_all") or 0.0
            normalized["cost_per_correct_usd"] = (
                normalized["usd_sum"] / (correct * n) if correct else None
            )
        elif task == "repair":
            correct = (result.get("repair") or {}).get("strict_pass") or 0
            normalized["cost_per_correct_usd"] = (
                normalized["usd_sum"] / correct if correct else None
            )
        else:
            normalized["cost_per_correct_usd"] = None
        normalized["cost_per_true_positive_usd"] = (
            normalized["usd_sum"] / true_positives if true_positives else None
        )
    else:
        normalized["cost_per_100_units_usd"] = None
        normalized["cost_per_1000_requests_usd"] = None
        normalized["cost_per_correct_usd"] = None
        normalized["cost_per_true_positive_usd"] = None
    return result


def _count_status(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        status = str(record.get("status"))
        counts[status] = counts.get(status, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Paired comparisons
# ---------------------------------------------------------------------------


def _comparison_entry(
    run_a: Mapping[str, Any],
    run_b: Mapping[str, Any],
    *,
    label: str,
    family: str,
    note: str | None = None,
) -> dict[str, Any]:
    result = compare(
        Path(run_a["run_dir"]),
        Path(run_b["run_dir"]),
        resamples=BOOTSTRAP,
        seed=SEED,
    )
    task = result["task"]
    metrics = result.get("metrics") or {}
    if task in ("detection", "leak_detection"):
        a = metrics.get("a", {}).get("valid_only") or {}
        b = metrics.get("b", {}).get("valid_only") or {}
        delta = (metrics.get("delta") or {}).get("macro_f1")
        boot = (metrics.get("delta_bootstrap") or {}).get("delta_macro_f1") or {}
        primary = "macro_f1"
        a_primary = a.get("macro_f1")
        b_primary = b.get("macro_f1")
        delta_accuracy = (
            (a.get("accuracy") - b.get("accuracy"))
            if a.get("accuracy") is not None and b.get("accuracy") is not None
            else None
        )
        common_valid = (result.get("alignment") or {}).get("common_valid_units")
    else:
        a_da = metrics.get("a", {}).get("valid_only_joint_accuracy")
        b_da = metrics.get("b", {}).get("valid_only_joint_accuracy")
        delta = metrics.get("delta_joint_accuracy")
        boot = (metrics.get("delta_bootstrap") or {}).get("delta_joint_accuracy") or {}
        primary = "pair_da"
        a_primary = a_da
        b_primary = b_da
        delta_accuracy = delta
        common_valid = (result.get("alignment") or {}).get("common_valid_pairs")
    mcnemar = metrics.get("mcnemar") or {}
    entry = {
        "label": label,
        "task": task,
        "family": family,
        "run_a": run_a["run_id"],
        "run_b": run_b["run_id"],
        "model_a": run_a.get("model_family"),
        "model_b": run_b.get("model_family"),
        "method_a": run_a.get("method_id"),
        "method_b": run_b.get("method_id"),
        "primary_metric": primary,
        "a_primary": a_primary,
        "b_primary": b_primary,
        "delta": delta,
        "delta_accuracy": delta_accuracy,
        "ci_low": boot.get("ci_low"),
        "ci_high": boot.get("ci_high"),
        "common_valid": common_valid,
        "raw_p": mcnemar.get("p_value"),
        "mcnemar": mcnemar,
        "alignment": result.get("alignment"),
        "strict_a": (metrics.get("a", {}).get("strict") or {}).get("strict_accuracy"),
        "strict_b": (metrics.get("b", {}).get("strict") or {}).get("strict_accuracy"),
        "note": note,
        "holm_p": None,
        "family_m": None,
    }
    return entry


def _apply_holm(entries: Sequence[dict[str, Any]]) -> None:
    families: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        families.setdefault(str(entry["family"]), []).append(entry)
    for family, items in families.items():
        p_values = [item.get("raw_p") for item in items]
        if any(value is None for value in p_values):
            continue
        adjusted = holm_adjust([float(value) for value in p_values])
        for item, adjusted_p in zip(items, adjusted):
            item["holm_p"] = adjusted_p
            item["family_m"] = len(items)


# ---------------------------------------------------------------------------
# Build the summary
# ---------------------------------------------------------------------------


def discover_runs() -> list[dict[str, Any]]:
    analyses: list[dict[str, Any]] = []
    for manifest_path in sorted(RESULTS_ROOT.rglob("run_manifest.json")):
        run_dir = manifest_path.parent
        rel_parts = manifest_path.relative_to(RESULTS_ROOT).parts
        if "superseded" in rel_parts:
            continue
        manifest, records, _ = load_run(run_dir)
        if manifest.get("tier") not in ("A", "B"):
            continue
        analyses.append(_analyze_run(run_dir, manifest, records))
    if not analyses:
        raise ValueError(f"no benchmark runs found under {RESULTS_ROOT}")
    return analyses


def discover_superseded() -> list[dict[str, Any]]:
    """Light audit view of historical runs; never mixed into the main tables."""

    entries: list[dict[str, Any]] = []
    root = RESULTS_ROOT / "superseded"
    if not root.exists():
        return entries
    for manifest_path in sorted(root.rglob("run_manifest.json")):
        run_dir = manifest_path.parent
        manifest, records, _ = load_run(run_dir)
        if manifest.get("tier") != "B":
            continue
        method = manifest.get("method") or {}
        model = method.get("model") or {}
        selected = _selected_records(manifest, records)
        rel_parts = manifest_path.relative_to(root).parts
        group = rel_parts[0] if rel_parts else "unknown"
        reason = (
            "leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase"
            if group == "leakage_sensitive_v1"
            else "superseded harness: prompting.py changed before the formal postleakfix run"
            if group.startswith("pre_postleakfix")
            else "superseded by a later canonical run"
        )
        entries.append(
            {
                "run_id": manifest.get("run_id"),
                "run_dir": str(run_dir.resolve()),
                "group": group,
                "method_id": method.get("method_id"),
                "method_name": method.get("name"),
                "model_family": model.get("family"),
                "prompt_version": method.get("prompt_version"),
                "n": len(selected),
                "reason": reason,
                "metrics_withheld": True,
            }
        )
    return entries


def _lookup(runs: Sequence[Mapping[str, Any]], method_id: str, task: str, **extra: Any) -> Mapping[str, Any]:
    candidates = [
        run
        for run in runs
        if run.get("method_id") == method_id and run.get("task") == task
        and all(run.get(key) == value for key, value in extra.items())
    ]
    if len(candidates) != 1:
        raise ValueError(
            f"expected one run for method={method_id!r} task={task!r} extras={extra}, "
            f"found {len(candidates)}: {[run['run_id'] for run in candidates]}"
        )
    return candidates[0]


def _build_comparisons(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    # Tier A legacy model comparisons, same strategy and task.
    for strategy in ("direct", "few-shot", "context"):
        entries.append(
            _comparison_entry(
                _lookup(runs, f"llm.deepseek.{strategy}", "detection"),
                _lookup(runs, f"llm.mimo.{strategy}", "detection"),
                label=f"detection {strategy}: DeepSeek - MiMo",
                family="A-MODEL-DETECTION",
                note="Derived legacy runs; same frozen split and prompt semantics.",
            )
        )
        entries.append(
            _comparison_entry(
                _lookup(runs, f"llm.deepseek.{strategy}", "pair_detection", forced_choice=False),
                _lookup(runs, f"llm.mimo.{strategy}", "pair_detection", forced_choice=False),
                label=f"pair side-wise {strategy}: DeepSeek - MiMo",
                family="A-MODEL-PAIR",
                note="Free-form side-wise pair task; fixed split.",
            )
        )
    # Tier A evidence prompt.
    entries.append(
        _comparison_entry(
            _lookup(runs, "llm.deepseek.evidence", "detection"),
            _lookup(runs, "llm.deepseek.direct", "detection"),
            label="evidence vs direct: DeepSeek",
            family="A-EVIDENCE-DEEPSEEK",
            note="Different prompt contract; same 160-function split.",
        )
    )
    entries.append(
        _comparison_entry(
            _lookup(runs, "llm.mimo.evidence", "detection"),
            _lookup(runs, "llm.mimo.direct", "detection"),
            label="evidence vs direct: MiMo",
            family="A-EVIDENCE-MIMO",
            note="Different prompt contract; same 160-function split.",
        )
    )
    entries.append(
        _comparison_entry(
            _lookup(runs, "llm.deepseek.evidence", "detection"),
            _lookup(runs, "llm.mimo.evidence", "detection"),
            label="evidence: DeepSeek - MiMo",
            family="A-EVIDENCE-MODEL",
            note="Same prompt contract; endpoint/decoding differ.",
        )
    )
    # Pair joint, forced binary. Never pooled with side-wise rows.
    for model in ("deepseek", "mimo"):
        joint = _lookup(runs, f"llm.{model}.pair_joint_forced_choice", "pair_detection")
        for strategy in ("direct", "context"):
            side = _lookup(runs, f"llm.{model}.{strategy}", "pair_detection", forced_choice=False)
            entries.append(
                _comparison_entry(
                    joint,
                    side,
                    label=f"pair joint vs side-wise {strategy}: {model}",
                    family=f"A-PAIRJOINT-{model.upper()}",
                    note="Different task: forced binary joint choice vs two free-form side verdicts; descriptive only.",
                )
            )
    entries.append(
        _comparison_entry(
            _lookup(runs, "llm.deepseek.pair_joint_forced_choice", "pair_detection"),
            _lookup(runs, "llm.mimo.pair_joint_forced_choice", "pair_detection"),
            label="pair joint: DeepSeek - MiMo",
            family="A-PAIRJOINT-MODEL",
            note="Same 180 pairs and A/B map; forced binary task.",
        )
    )
    # Tier B hybrid: direct vs each evidence condition, within model.
    for model in ("deepseek", "mimo"):
        direct = _lookup(runs, f"llm.{model}.juliet_direct", "leak_detection")
        for method in ("static", "dynamic", "combined", "shuffled"):
            entry = _comparison_entry(
                _lookup(runs, f"hybrid.{model}.{method}", "leak_detection"),
                direct,
                label=f"{method} - direct: {model}",
                family=f"B-HYBRID-{model.upper()}",
                note="Same 140 test units; direct is the no-evidence control.",
            )
            entries.append(entry)
    # Tier B hybrid combined vs traditional tools.
    tools = (
        ("static.clang.sa", "Clang SA"),
        ("static.cppcheck", "Cppcheck"),
        ("dynamic.asan_lsan", "ASan/LSan"),
        ("dynamic.valgrind", "Valgrind"),
        ("dynamic.combined", "ASan+Valgrind"),
    )
    for model in ("deepseek", "mimo"):
        combined = _lookup(runs, f"hybrid.{model}.combined", "leak_detection")
        for tool_id, _tool_name in tools:
            entries.append(
                _comparison_entry(
                    combined,
                    _lookup(runs, tool_id, "leak_detection"),
                    label=f"combined - {tool_id}: {model}",
                    family=f"B-HYBRID-VS-TOOLS-{model.upper()}",
                    note="Common-valid cohort; static compile errors are excluded from valid-only and counted wrong in strict.",
                )
            )
    # Endpoint sensitivity: same MiMo model id, Xiaomi official vs OpenCode Go.
    entries.append(
        _comparison_entry(
            _lookup(runs, "llm.mimo.xiaomi_juliet_direct", "leak_detection"),
            _lookup(runs, "llm.mimo.juliet_direct", "leak_detection"),
            label="MiMo endpoint: Xiaomi official (postleakfix) - OpenCode Go v2 direct",
            family="B-ENDPOINT-MIMO",
            note="Same model id, prompt contract and 140 units; endpoint/serving stack and harness differ. Not a model comparison.",
        )
    )
    _apply_holm(entries)
    return entries


def _placebo_audit(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    audit: dict[str, Any] = {}
    for model in ("deepseek", "mimo"):
        direct = _lookup(runs, f"llm.{model}.juliet_direct", "leak_detection")
        shuffled = _lookup(runs, f"hybrid.{model}.shuffled", "leak_detection")
        direct_map = {
            record.get("unit_id"): (record.get("prediction") or {}).get("y_pred")
            for record in direct.get("_records", [])
        }
        shuffled_map = {
            record.get("unit_id"): (record.get("prediction") or {}).get("y_pred")
            for record in shuffled.get("_records", [])
        }
        flips = [
            unit_id
            for unit_id in direct_map
            if direct_map.get(unit_id) != shuffled_map.get(unit_id)
        ]
        to_positive = [
            unit_id for unit_id in flips if direct_map.get(unit_id) == 0 and shuffled_map.get(unit_id) == 1
        ]
        to_negative = [
            unit_id for unit_id in flips if direct_map.get(unit_id) == 1 and shuffled_map.get(unit_id) == 0
        ]
        audit[model] = {
            "direct_accuracy": direct.get("accuracy"),
            "shuffled_accuracy": shuffled.get("accuracy"),
            "direct_macro_f1": direct.get("macro_f1"),
            "shuffled_macro_f1": shuffled.get("macro_f1"),
            "flips": len(flips),
            "flips_to_positive": len(to_positive),
            "flips_to_negative": len(to_negative),
            "flip_units": flips,
        }
    return audit


def _evidence_audit(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Recall/FPR decomposition for the evidence prompt vs direct.

    The overall McNemar on common-valid units answers a different question from
    the two pre-specified endpoints (recall on vulnerable functions and FPR on
    non-vulnerable functions). Both are reported; the 32-negative FPR test is
    explicitly underpowered.
    """

    entries: list[dict[str, Any]] = []
    for model in ("deepseek", "mimo"):
        evidence = _lookup(runs, f"llm.{model}.evidence", "detection")
        direct = _lookup(runs, f"llm.{model}.direct", "detection")
        ev_map = {record["unit_id"]: record for record in evidence["_records"]}
        dir_map = {record["unit_id"]: record for record in direct["_records"]}
        common = sorted(set(ev_map) & set(dir_map))
        common_valid = [
            unit_id
            for unit_id in common
            if ev_map[unit_id].get("status") == "ok" and dir_map[unit_id].get("status") == "ok"
        ]
        recall_ids = [
            unit_id
            for unit_id in common_valid
            if bool((ev_map[unit_id].get("label") or {}).get("y_true"))
        ]
        fpr_ids = [
            unit_id
            for unit_id in common_valid
            if not bool((ev_map[unit_id].get("label") or {}).get("y_true"))
        ]
        ev_recall = sum(
            1 for unit_id in recall_ids if (ev_map[unit_id].get("prediction") or {}).get("y_pred") == 1
        )
        dir_recall = sum(
            1 for unit_id in recall_ids if (dir_map[unit_id].get("prediction") or {}).get("y_pred") == 1
        )
        ev_fp = sum(
            1 for unit_id in fpr_ids if (ev_map[unit_id].get("prediction") or {}).get("y_pred") == 1
        )
        dir_fp = sum(
            1 for unit_id in fpr_ids if (dir_map[unit_id].get("prediction") or {}).get("y_pred") == 1
        )
        recall_mcnemar = mcnemar_exact(
            a_correct_b_wrong=sum(
                1
                for unit_id in recall_ids
                if (ev_map[unit_id].get("prediction") or {}).get("y_pred") == 1
                and (dir_map[unit_id].get("prediction") or {}).get("y_pred") != 1
            ),
            a_wrong_b_correct=sum(
                1
                for unit_id in recall_ids
                if (ev_map[unit_id].get("prediction") or {}).get("y_pred") != 1
                and (dir_map[unit_id].get("prediction") or {}).get("y_pred") == 1
            ),
            total=len(recall_ids),
        )
        fpr_mcnemar = mcnemar_exact(
            a_correct_b_wrong=sum(
                1
                for unit_id in fpr_ids
                if (ev_map[unit_id].get("prediction") or {}).get("y_pred") != 1
                and (dir_map[unit_id].get("prediction") or {}).get("y_pred") == 1
            ),
            a_wrong_b_correct=sum(
                1
                for unit_id in fpr_ids
                if (ev_map[unit_id].get("prediction") or {}).get("y_pred") == 1
                and (dir_map[unit_id].get("prediction") or {}).get("y_pred") != 1
            ),
            total=len(fpr_ids),
        )
        overall_mcnemar = mcnemar_exact(
            a_correct_b_wrong=sum(
                1
                for unit_id in common_valid
                if bool((ev_map[unit_id].get("prediction") or {}).get("y_pred"))
                == bool((ev_map[unit_id].get("label") or {}).get("y_true"))
                and not (
                    bool((dir_map[unit_id].get("prediction") or {}).get("y_pred"))
                    == bool((dir_map[unit_id].get("label") or {}).get("y_true"))
                )
            ),
            a_wrong_b_correct=sum(
                1
                for unit_id in common_valid
                if not (
                    bool((ev_map[unit_id].get("prediction") or {}).get("y_pred"))
                    == bool((ev_map[unit_id].get("label") or {}).get("y_true"))
                )
                and bool((dir_map[unit_id].get("prediction") or {}).get("y_pred"))
                == bool((dir_map[unit_id].get("label") or {}).get("y_true"))
            ),
            total=len(common_valid),
        )
        all_ids = sorted(ev_map)
        strict_mcnemar = mcnemar_exact(
            a_correct_b_wrong=sum(
                1
                for unit_id in all_ids
                if ev_map[unit_id].get("status") == "ok"
                and bool((ev_map[unit_id].get("prediction") or {}).get("y_pred"))
                == bool((ev_map[unit_id].get("label") or {}).get("y_true"))
                and not (
                    dir_map[unit_id].get("status") == "ok"
                    and bool((dir_map[unit_id].get("prediction") or {}).get("y_pred"))
                    == bool((dir_map[unit_id].get("label") or {}).get("y_true"))
                )
            ),
            a_wrong_b_correct=sum(
                1
                for unit_id in all_ids
                if not (
                    ev_map[unit_id].get("status") == "ok"
                    and bool((ev_map[unit_id].get("prediction") or {}).get("y_pred"))
                    == bool((ev_map[unit_id].get("label") or {}).get("y_true"))
                )
                and dir_map[unit_id].get("status") == "ok"
                and bool((dir_map[unit_id].get("prediction") or {}).get("y_pred"))
                == bool((dir_map[unit_id].get("label") or {}).get("y_true"))
            ),
            total=len(all_ids),
        )
        common_labels = [bool((ev_map[unit_id].get("label") or {}).get("y_true")) for unit_id in common_valid]
        common_ev = [
            bool((ev_map[unit_id].get("prediction") or {}).get("y_pred")) for unit_id in common_valid
        ]
        common_dir = [
            bool((dir_map[unit_id].get("prediction") or {}).get("y_pred")) for unit_id in common_valid
        ]
        ev_scores = detection_scores(common_labels, common_ev)
        dir_scores = detection_scores(common_labels, common_dir)
        entries.append(
            {
                "model": model,
                "recall_n": len(recall_ids),
                "recall_a": (ev_recall / len(recall_ids)) if recall_ids else None,
                "recall_b": (dir_recall / len(recall_ids)) if recall_ids else None,
                "delta_recall": (ev_recall - dir_recall) / len(recall_ids) if recall_ids else None,
                "recall_mcnemar": recall_mcnemar,
                "fpr_n": len(fpr_ids),
                "fpr_a": (ev_fp / len(fpr_ids)) if fpr_ids else None,
                "fpr_b": (dir_fp / len(fpr_ids)) if fpr_ids else None,
                "delta_fpr": (ev_fp - dir_fp) / len(fpr_ids) if fpr_ids else None,
                "fpr_mcnemar": fpr_mcnemar,
                "overall_mcnemar": overall_mcnemar,
                "strict_mcnemar": strict_mcnemar,
                "common_valid": len(common_valid),
                "strict_n": len(all_ids),
                "balanced_accuracy_a": ev_scores.get("balanced_accuracy"),
                "balanced_accuracy_b": dir_scores.get("balanced_accuracy"),
                "delta_balanced_accuracy": (
                    ev_scores.get("balanced_accuracy") - dir_scores.get("balanced_accuracy")
                    if ev_scores.get("balanced_accuracy") is not None
                    and dir_scores.get("balanced_accuracy") is not None
                    else None
                ),
                "mcc_a": ev_scores.get("mcc"),
                "mcc_b": dir_scores.get("mcc"),
                "delta_mcc": (
                    ev_scores.get("mcc") - dir_scores.get("mcc")
                    if ev_scores.get("mcc") is not None and dir_scores.get("mcc") is not None
                    else None
                ),
            }
        )
    p_values = []
    for entry in entries:
        p_values.extend(
            [entry["recall_mcnemar"]["p_value"], entry["fpr_mcnemar"]["p_value"]]
        )
    adjusted = holm_adjust(p_values)
    index = 0
    for entry in entries:
        entry["recall_holm_p"] = adjusted[index]
        entry["fpr_holm_p"] = adjusted[index + 1]
        index += 2
    return {
        "families": {
            "A-EVIDENCE-RECALL-FPR": {
                "tests": 4,
                "description": "2 models x {recall, FPR}; Holm over the four pre-specified endpoint tests",
            }
        },
        "entries": entries,
    }


def build_summary() -> dict[str, Any]:
    runs = discover_runs()
    comparisons = _build_comparisons(runs)
    by_id = {run["run_id"]: run for run in runs}

    validation_errors: list[str] = []
    for run in runs:
        report = validate_run(Path(run["run_dir"]))
        if report.get("errors"):
            validation_errors.extend(
                f"{run['run_id']}: {message}" for message in report["errors"][:3]
            )

    tier_a = [run for run in runs if run["tier"] == "A"]
    tier_b = [run for run in runs if run["tier"] == "B"]
    tier_a.sort(
        key=lambda run: (
            TASK_ORDER.get(run["task"], 9),
            0 if run["forced_choice"] else 1,
            MODEL_ORDER.get(run["model_family"], 9),
            STRATEGY_ORDER.get(run["strategy"], 9),
        )
    )
    tier_b.sort(
        key=lambda run: (
            0 if run["task"] == "repair" else 1,
            {"static": 0, "dynamic": 1, "llm": 2, "hybrid": 3}.get(run["family"], 9),
            MODEL_ORDER.get(run["model_family"], 9),
            STRATEGY_ORDER.get(run["strategy"], 9),
        )
    )

    def strip(run: Mapping[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in run.items() if key not in ("_records", "manifest")}

    placebo = _placebo_audit(runs)
    evidence_audit = _evidence_audit(runs)
    superseded = discover_superseded()
    summary: dict[str, Any] = {
        "schema_version": SUMMARY_VERSION,
        "generated_at": utc_now(),
        "protocol_version": "1.0.0",
        "scope": {
            "tiers": [
                "Tier A: SecVulEval real-project functions (160 detection; 180 pairs)",
                "Tier B: Juliet CWE-401 frozen subset (test 140)",
            ],
            "pooling": "none; Tier A and Tier B are never pooled; pair-joint and side-wise pair are never pooled; repair is separate",
        },
        "datasets": {
            "tier_a_detection": {
                "dataset_id": "secvul-split-v1",
                "path": "splits/test_detection_160.json",
                "sha256": "bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8",
                "units": 160,
                "labels": {"vulnerable": 128, "non_vulnerable": 32},
            },
            "tier_a_pairs": {
                "dataset_id": "secvul-split-v1",
                "path": "splits/test_pairs_180.json",
                "sha256": "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d",
                "pairs": 180,
                "sides": 360,
            },
            "tier_b_juliet": {
                "dataset_id": "juliet-cwe401-v1.3-subset-v1",
                "path": "juliet/subset_units.jsonl",
                "sha256": "4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24",
                "unit_manifest_sha256": "8df222f84a4295f3b90ae7cabe165adc04858d91def3fda19a073db6e17cafd6",
                "units": 200,
                "groups": 100,
                "test": 140,
                "dev": 60,
                "labels": {"bad": 100, "good": 100},
            },
        },
        "settings": {
            "bootstrap_resamples": BOOTSTRAP,
            "bootstrap_seed": SEED,
            "confidence": 0.95,
            "interval_method": "cluster percentile bootstrap for F1/MCC/DA; Wilson for proportions in run metrics",
            "cluster_unit": "Tier A detection: project; Tier A pair: pair_id; Tier B: case_family",
            "strict_policy": "non-ok records count wrong; valid-only excludes them",
            "cost_policy": "known API list-price sum only; local static/dynamic have usd=null, never zero",
            "normalized_cost_policy": "fixed provider card: DeepSeek 0.15/0.60/0.003 USD per 1M input/output/cached tokens; MiMo 0.14/0.28/0.0028; recomputed from per-record usage, recorded cost_usd is not reused; unknown records stay unknown",
            "normalized_cost_fields": [
                "cost.normalized.usd_sum",
                "cost.normalized.cost_per_100_units_usd",
                "cost.normalized.cost_per_1000_requests_usd",
                "cost.normalized.cost_per_correct_usd",
                "cost.normalized.cost_per_true_positive_usd",
            ],
            "canonical_policy": "Tier B hybrid canonical = hybrid_v2 (leak-fixed inputs); hybrid_v1 is superseded/leakage-sensitive and excluded from every main table; MiMo Xiaomi canonical = postleakfix run",
            "latency_policy": "per-request latency; p50/p95 over the run's selected records",
            "pair_joint_policy": "forced binary joint choice; separate from side-wise four-category task",
            "repair_policy": "strict_pass denominator = 58 units with an observable baseline leak; 12 unobservable units excluded",
        },
        "tier_a": {
            "runs": [strip(run) for run in tier_a],
            "detection": [strip(run) for run in tier_a if run["task"] == "detection"],
            "pair_sidewise": [
                strip(run) for run in tier_a if run["task"] == "pair_detection" and not run["forced_choice"]
            ],
            "pair_joint": [
                strip(run) for run in tier_a if run["task"] == "pair_detection" and run["forced_choice"]
            ],
            "evidence_audit": evidence_audit,
            "comparisons": [
                entry for entry in comparisons if str(entry["family"]).startswith("A-")
            ],
        },
        "tier_b": {
            "runs": [strip(run) for run in tier_b if run["task"] != "repair"],
            "leak_test_140": [strip(run) for run in tier_b if run["task"] == "leak_detection"],
            "repair": [strip(run) for run in tier_b if run["task"] == "repair"],
            "placebo": placebo,
            "comparisons": [
                entry for entry in comparisons if str(entry["family"]).startswith("B-")
            ],
        },
        "validation": {
            "runs_discovered": len(runs),
            "structural_errors": validation_errors,
            "all_structural_valid": not validation_errors,
            "new_runs_jsonschema_validated": 17,
            "superseded_runs_excluded": len(superseded),
            "note": "All 17 round-2 derived runs were re-imported and validated with bench_validate.py --jsonschema; hybrid/LLM canonical runs were replaced by v2/postleakfix and the old directories were moved to results/superseded/ without editing their files.",
        },
        "superseded": {
            "policy": "historical only; never enters a main table, comparison or pooled statistic",
            "runs": superseded,
        },
        "limitations": [
            "Tier A and Tier B use different datasets, labels and unit structures; no cross-tier ranking or overall score.",
            "Pair-joint is a forced binary task; its DA cannot be compared directly with side-wise free-form four-category DA.",
            "Tier A evidence prompt raises recall but also raises false positives; the FPR test is underpowered (32 negatives).",
            "Pair-joint length is a strong confound: a character-length heuristic alone reaches 74.44%; DeepSeek is not significantly above it.",
            "DeepSeek has a strong A-position bias in pair-joint; MiMo does not. The A/B map is balanced but not repeated in reverse order.",
            "Tier B static Clang has 4 compile errors in test 140; valid-only macro-F1 excludes them and strict counts them wrong.",
            "Dynamic clean is NO_LEAK_OBSERVED, not a verified true negative; the conservative view abstains on clean.",
            "Hybrid v2 evidence gains over direct are at most one unit per model and are not significant after Holm; the shuffled placebo is used as the length/content control.",
            "Hybrid v1 is leakage-sensitive (six good units still showed the literal 'Benign, fixed string') and is excluded from every main table; only v2 is canonical.",
            "The Juliet MiMo LLM result uses the Xiaomi official endpoint (the OpenCode Go fallback), not OpenCode Go; DeepSeek Juliet LLM is unavailable (401/402). Its cost is a reference-price computation because the endpoint returned no billing fields.",
            "Repair passes are reported only on 58 baseline-observable units; the 12 unobservable units cannot prove leak removal.",
            "Single run per cell; no seed/run-to-run variance. Cost is list-price computation, not necessarily the actual bill.",
        ],
    }
    summary["provenance"] = {
        "run_manifests": {
            run["run_dir"]: sha256_file(Path(run["run_dir"]) / "run_manifest.json")
            for run in runs
        },
        "builder": "bench_final_summary.py",
    }
    return summary


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_run_table(runs: Sequence[Mapping[str, Any]], *, tier_b: bool = False) -> list[str]:
    lines = [
        "| method | family | n | valid | coverage | macro-F1 | 95% CI | MCC | strict | P | R | spec | USD | norm $/100u | p50/p95 s |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for run in runs:
        cost = run.get("cost") or {}
        normalized = cost.get("normalized") or {}
        lines.append(
            f"| {run['method_name']} | {run['family']} | {run['n']} | {run['valid']} | "
            f"{_pct(run.get('coverage'))} | {_fmt(run.get('macro_f1'), 4)} | "
            f"{_ci(run.get('bootstrap'), 'macro_f1')} | {_fmt(run.get('mcc'))} | "
            f"{_pct(run.get('strict_accuracy'))} | {_fmt(run.get('precision'))} | "
            f"{_fmt(run.get('recall'))} | {_fmt(run.get('specificity'))} | "
            f"{_money(cost.get('usd_known_sum')) if cost.get('usd_known_sum') is not None else '— (local)'} | "
            f"{_money(normalized.get('cost_per_100_units_usd')) if normalized.get('cost_per_100_units_usd') is not None else '—'} | "
            f"{_sec(cost.get('latency_ms_p50'))}/{_sec(cost.get('latency_ms_p95'))} |"
        )
    return lines


def _md_comparison_table(entries: Sequence[Mapping[str, Any]], *, pair: bool = False) -> list[str]:
    lines = [
        "| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |",
        "| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |",
    ]
    for entry in entries:
        if pair:
            delta = f"{_pp((entry['delta'] or 0) * 100)}"
            ci = _ci_pp(entry)
            metric = "ΔDA"
        else:
            delta = f"{_fmt(entry['delta'], 4)}"
            ci = f"[{entry['ci_low']:.4f}, {entry['ci_high']:.4f}]" if entry.get("ci_low") is not None else "—"
            metric = "Δmacro-F1"
        mcnemar = entry.get("mcnemar") or {}
        lines.append(
            f"| {entry['label']} | {entry.get('common_valid')} | {delta} | {ci} | "
            f"{_pp((entry.get('delta_accuracy') or 0) * 100)} | "
            f"{mcnemar.get('a_correct_b_wrong')}/{mcnemar.get('a_wrong_b_correct')} | "
            f"{_p(entry.get('raw_p'))} | {_p(entry.get('holm_p'))} | "
            f"`{entry['family']}` (m={entry.get('family_m')}) |"
        )
    return lines


def build_markdown(summary: Mapping[str, Any]) -> str:
    a = summary["tier_a"]
    b = summary["tier_b"]
    det = sorted(
        a["detection"],
        key=lambda run: (MODEL_ORDER.get(run["model_family"], 9), STRATEGY_ORDER.get(run["strategy"], 9)),
    )
    side = sorted(
        a["pair_sidewise"],
        key=lambda run: (MODEL_ORDER.get(run["model_family"], 9), STRATEGY_ORDER.get(run["strategy"], 9)),
    )
    joint = sorted(a["pair_joint"], key=lambda run: MODEL_ORDER.get(run["model_family"], 9))
    def leak_rank(run: Mapping[str, Any]) -> tuple[int, int, int, str]:
        method_id = str(run.get("method_id") or "")
        method_rank = 0
        if run.get("family") in ("llm", "hybrid"):
            method_rank = 9
            for name, rank in HYBRID_METHOD_ORDER.items():
                if method_id.endswith(f".{name}") or method_id.endswith(f"_{name}"):
                    method_rank = rank
                    break
        group_rank = (
            0 if method_id.startswith("static.") else
            1 if method_id.startswith("dynamic.") else
            2 if run.get("family") == "llm" else 3
        )
        return (
            group_rank,
            MODEL_ORDER.get(run.get("model_family"), 9),
            method_rank,
            method_id,
        )

    leak_runs = sorted(b["leak_test_140"], key=leak_rank)
    repair_runs = sorted(b["repair"], key=lambda run: MODEL_ORDER.get(run["model_family"], 9))
    a_comp = a["comparisons"]
    b_comp = b["comparisons"]
    det_comp = [e for e in a_comp if e["task"] == "detection"]
    pair_side_comp = [e for e in a_comp if e["task"] == "pair_detection" and "pair joint" not in e["label"]]
    pair_joint_comp = [e for e in a_comp if e["task"] == "pair_detection" and "pair joint" in e["label"]]
    hybrid_comp = [e for e in b_comp if e["family"].startswith("B-HYBRID-") and "VS-TOOLS" not in e["family"]]
    tool_comp = [e for e in b_comp if "VS-TOOLS" in e["family"]]
    endpoint_comp = [e for e in b_comp if e["family"] == "B-ENDPOINT-MIMO"]

    ds_det = next(run for run in det if run["model_family"] == "deepseek" and run["strategy"] == "direct")
    ds_ev = next(run for run in det if run["model_family"] == "deepseek" and run["strategy"] == "evidence")
    mimo_det = next(run for run in det if run["model_family"] == "mimo" and run["strategy"] == "direct")
    mimo_ev = next(run for run in det if run["model_family"] == "mimo" and run["strategy"] == "evidence")
    ds_joint = next(run for run in joint if run["model_family"] == "deepseek")
    mimo_joint = next(run for run in joint if run["model_family"] == "mimo")
    ds_comb = next(run for run in leak_runs if run["method_id"] == "hybrid.deepseek.combined")
    mimo_comb = next(run for run in leak_runs if run["method_id"] == "hybrid.mimo.combined")
    llm = next(run for run in leak_runs if run["method_id"] == "llm.mimo.xiaomi_juliet_direct")
    clang = next(run for run in leak_runs if run["method_id"] == "static.clang.sa")
    asan = next(run for run in leak_runs if run["method_id"] == "dynamic.asan_lsan")
    ds_repair = next(run for run in repair_runs if run["model_family"] == "deepseek")
    mimo_repair = next(run for run in repair_runs if run["model_family"] == "mimo")

    lines = [
        "# Unified benchmark leaderboard — final integration",
        "",
        f"- generated: `{summary['generated_at']}`",
        f"- protocol: `{summary['protocol_version']}`; builder: `bench_final_summary.py`",
        f"- runs: {summary['validation']['runs_discovered']} canonical runs "
        f"(Tier A {len(a['runs'])}, Tier B {len(b['runs']) + len(b['repair'])}); "
        f"{summary['validation'].get('superseded_runs_excluded', 0)} superseded historical runs excluded",
        "- **Canonical Tier B hybrid = `hybrid_v2` (leak-fixed inputs).** `hybrid_v1` is leakage-sensitive and does not appear in any main table.",
        "- **Tier A and Tier B are not pooled. Pair-joint is not pooled with side-wise pair. Repair is separate.**",
        "",
        "## 0. TL;DR",
        "",
        f"- **Tier A detection (160)**: evidence prompt raises macro-F1 from "
        f"{_fmt(ds_det['macro_f1'], 4)} to {_fmt(ds_ev['macro_f1'], 4)} for DeepSeek and from "
        f"{_fmt(mimo_det['macro_f1'], 4)} to {_fmt(mimo_ev['macro_f1'], 4)} for MiMo; "
        "the gain is mostly recall/operating-point shift, not a proven discrimination gain.",
        f"- **Tier A pair-joint (180 forced choices)**: DeepSeek {_pct(ds_joint['joint_accuracy'])} "
        f"(95% CI {_ci(ds_joint.get('bootstrap'), 'joint_accuracy_valid_pairs')}), "
        f"MiMo {_pct(mimo_joint['joint_accuracy'])} "
        f"(95% CI {_ci(mimo_joint.get('bootstrap'), 'joint_accuracy_valid_pairs')}). "
        "This is a forced binary task; do not compare it directly with side-wise DA.",
        f"- **Tier B test 140**: best traditional tools are ASan/LSan and Valgrind at "
        f"{_fmt(asan['macro_f1'], 4)} macro-F1; Clang SA is {_fmt(clang['macro_f1'], 4)} "
        f"(4 compile errors); MiMo Xiaomi postleakfix LLM is {_fmt(llm['macro_f1'], 4)}. "
        f"Hybrid v2 combined reaches {_fmt(ds_comb['macro_f1'], 4)} (DeepSeek, 136/140) and "
        f"{_fmt(mimo_comb['macro_f1'], 4)} (MiMo, 136/140); the gain over direct is at most one unit and is not significant after Holm. "
        "The old v1 perfect score is withdrawn as leakage-sensitive.",
        f"- **Repair**: both models pass {ds_repair['repair']['strict_pass']}/"
        f"{ds_repair['repair']['evaluable']} observable units; the 12 LSan-unobservable units are excluded from the denominator.",
        "",
        "## 1. Scope, datasets and denominators",
        "",
        "| tier | dataset | primary view | units | labels |",
        "| --- | --- | --- | ---: | --- |",
        f"| A | SecVulEval `secvul-split-v1` | detection 160 functions | 160 | 128 vulnerable / 32 non-vulnerable |",
        f"| A | SecVulEval `secvul-split-v1` | pair 180 pairs (side-wise and joint) | 180 pairs / 360 sides | vulnerable / fixed |",
        f"| B | Juliet CWE-401 `juliet-cwe401-v1.3-subset-v1` | test 140 | 140 (70 bad / 70 good) | Juliet intended |",
        f"| B | Juliet repair | test 70 bad units | 70 (58 baseline-observable) | all bad |",
        "",
        "Tier B test 140 is the only primary comparison set. The dev 60 split exists for the frozen static/dynamic runs but is reference-only; "
        "LLM/hybrid/repair runs are test-only.",
        "",
        "## 2. Tier A — SecVulEval",
        "",
        "### 2.1 Detection (160 functions; valid-only with strict view)",
        "",
        *_md_run_table(det),
        "",
        "`evidence` is the new six-field evidence-line/counterfactual prompt. The legacy direct/few-shot/context rows are read-only derived views. "
        "`strict` counts schema-invalid/API failures wrong; valid-only excludes them and coverage is shown.",
        "",
        "### 2.2 Detection paired comparisons",
        "",
        "Direction: `run_a - run_b`; positive means the first named method has higher macro-F1. McNemar is exact two-sided on common-valid units; "
        "Holm is applied inside each pre-registered family.",
        "",
        *_md_comparison_table(det_comp),
        "",
        "The evidence-vs-direct rows are paired on common-valid units (DeepSeek 159, MiMo 148); the raw McNemar is on paired correctness, "
        "not on the macro-F1 difference. The recall gain is larger than the F1 gain because false positives also rise.",
        "",
        "Evidence-prompt endpoint decomposition (pre-specified: recall on vulnerable functions, FPR on non-vulnerable functions):",
        "",
        "| model | recall n | recall direct → evidence | Δrecall | recall p (Holm) | FPR n | FPR direct → evidence | ΔFPR | FPR p (Holm) | overall common-valid p | strict p (all 160) |",
        "| --- | ---: | --- | ---: | --- | ---: | --- | ---: | --- | ---: | ---: |",
    ]
    for entry in (a.get("evidence_audit") or {}).get("entries", []):
        lines.append(
            f"| {entry['model']} | {entry['recall_n']} | {_pct(entry['recall_b'])} → {_pct(entry['recall_a'])} | "
            f"{_pp((entry['delta_recall'] or 0) * 100)} | {_p(entry['recall_mcnemar']['p_value'])} "
            f"({_p(entry['recall_holm_p'])}) | {entry['fpr_n']} | {_pct(entry['fpr_b'])} → {_pct(entry['fpr_a'])} | "
            f"{_pp((entry['delta_fpr'] or 0) * 100)} | {_p(entry['fpr_mcnemar']['p_value'])} "
            f"({_p(entry['fpr_holm_p'])}) | {_p(entry['overall_mcnemar']['p_value'])} | "
            f"{_p(entry['strict_mcnemar']['p_value'])} |"
        )
    lines += [
        "",
        "Recall rises significantly for both models after Holm; FPR also rises in point estimate but the test has only 32/29 negative functions and is underpowered. "
        "The overall common-valid McNemar is borderline (p≈0.049); the all-160 strict McNemar, which counts the one evidence invalid output wrong, is p≈0.096 for DeepSeek and p≈0.0026 for MiMo.",
    ]
    for entry in (a.get("evidence_audit") or {}).get("entries", []):
        lines.append(
            f"- {entry['model']} common-valid: Δbalanced accuracy "
            f"{_pp((entry.get('delta_balanced_accuracy') or 0) * 100)}, ΔMCC {_fmt(entry.get('delta_mcc'), 4)} "
            f"(MCC {_fmt(entry.get('mcc_b'))} → {_fmt(entry.get('mcc_a'))})."
        )
    lines += [
        "",
        "The correct reading is an operating-point shift, not a consistent gain in balanced discrimination: recall/F1 rise, FPR also rises, and balanced accuracy/MCC are flat or slightly lower.",
        "",
        "### 2.3 Pair discrimination: side-wise vs joint forced choice",
        "",
        "**Side-wise free-form** (two independent verdicts per pair):",
        "",
        "| model | strategy | pairs | valid | coverage | pair DA | 95% CI | both flagged | both clean | swapped | USD | p50/p95 s |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for run in side:
        scores = run.get("scores") or {}
        categories = run.get("joint_categories") or {}
        cost = run.get("cost") or {}
        lines.append(
            f"| {run['method_name']} | {run['strategy']} | {run['n_pairs']} | {run['valid']} | "
            f"{_pct(run['coverage'])} | {_pct(run['joint_accuracy'])} | "
            f"{_ci(run.get('bootstrap'), 'joint_accuracy_valid_pairs')} | "
            f"{categories.get('both_flagged', 0)} | {categories.get('both_clean', 0)} | "
            f"{categories.get('vulnerable_missed_fixed_flagged', 0)} | "
            f"{_money(cost.get('usd_known_sum'))} | "
            f"{_sec(cost.get('latency_ms_p50'))}/{_sec(cost.get('latency_ms_p95'))} |"
        )
    lines += [
        "",
        "**Joint A/B forced binary** (one request per pair; exactly one version must be chosen):",
        "",
        "| model | task | pairs | valid | pair DA | 95% CI | correct | swapped | both flagged/clean | USD | p50/p95 s |",
        "| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |",
    ]
    for run in joint:
        categories = run.get("joint_categories") or {}
        cost = run.get("cost") or {}
        lines.append(
            f"| {run['method_name']} | forced binary | {run['n_pairs']} | {run['valid']} | "
            f"{_pct(run['joint_accuracy'])} | {_ci(run.get('bootstrap'), 'joint_accuracy_valid_pairs')} | "
            f"{categories.get('vulnerable_detected_fixed_clean', 0)} | "
            f"{categories.get('vulnerable_missed_fixed_flagged', 0)} | "
            f"{categories.get('both_flagged', 0)} / {categories.get('both_clean', 0)} | "
            f"{_money(cost.get('usd_known_sum'))} | "
            f"{_sec(cost.get('latency_ms_p50'))}/{_sec(cost.get('latency_ms_p95'))} |"
        )
    lines += [
        "",
        "> **Do not mix the two tables.** The side-wise task allows both/neither and is scored as two independent verdicts.",
        "> The joint task asks for a single A/B choice; its `both`/`neither` categories are structurally impossible.",
        "> A higher joint DA is therefore not evidence that the model is better at the side-wise task.",
        "",
        "### 2.4 Pair-joint paired comparisons and audit",
        "",
        "These comparisons are **task-change comparisons** and are descriptive only. Direction is `joint - side-wise` or `DeepSeek - MiMo`.",
        "",
        *_md_comparison_table(pair_joint_comp, pair=True),
        "",
        "| model | joint DA | length-heuristic DA | vulnerable-in-A DA | vulnerable-in-B DA | selected A |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for run in joint:
        audit = run.get("pair_joint_audit") or {}
        pos = audit.get("position_bias") or {}
        length = audit.get("length_heuristic") or {}
        lines.append(
            f"| {run['method_name']} | {_pct(run['joint_accuracy'])} | "
            f"{_pct(length.get('accuracy'))} | {_pct((pos.get('vulnerable_in_A') or {}).get('da'))} | "
            f"{_pct((pos.get('vulnerable_in_B') or {}).get('da'))} | "
            f"{_pct(pos.get('selected_A_rate'))} |"
        )
    lines += [
        "",
        "The length heuristic chooses the shorter function body (tie -> A) without looking at code semantics. "
        "If a model is close to this heuristic, its joint DA is not evidence of semantic vulnerability reasoning. "
        "DeepSeek's strong A-position bias is visible as a large A-vs-B gap; MiMo's bias is small.",
        "",
        "### 2.5 Tier A cost and limitations",
        "",
        "- Legacy Tier A runs are derived from `runner/runs/test_v1_*`; they are not new calls. The task cost shown is the detection or pair task only, not the full 2,484-request run (which also includes repair).",
        "- Evidence runs use 160 independent detection requests per model; pair-joint uses 180 joint requests per model.",
        "- Context rows retain the known context artifact: the non-empty context stratum is single-class, so the overall difference cannot be attributed to context reasoning alone.",
        "- Single run per cell; no seed/run-to-run variance.",
        "",
        "## 3. Tier B — Juliet CWE-401 (test 140)",
        "",
        "All rows below use the same 140 test units (70 bad / 70 good). Static/dynamic rows are traditional tools; "
        "LLM and hybrid rows are real API runs. `macro-F1` is valid-only; `strict` counts every non-ok record as wrong. "
        "Hybrid rows are **v2** (leak-fixed inputs); v1 is superseded/leakage-sensitive and is not in this table.",
        "",
        "### 3.1 Main test-140 table",
        "",
        *_md_run_table(leak_runs),
        "",
        "`macro-F1` here is the two-class macro average, not the positive-class F1 printed in some upstream reports; "
        "they can differ by ~0.001–0.002. Local static/dynamic tools have `usd=null` (not zero). Their wall time is local compute; "
        "it is not a cloud bill. `Clang SA` has 4 compile errors; they are excluded from valid-only macro-F1 and counted wrong in strict. "
        "Dynamic clean means `NO_LEAK_OBSERVED`, not verified safety; the conservative view abstains on clean.",
        "",
        "**Dynamic conservative view** (clean is not a true negative):",
        "",
        "| dynamic method | clean abstained | valid | coverage | recall | specificity | macro-F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for run in leak_runs:
        if run["family"] != "dynamic":
            continue
        conservative = run.get("conservative") or {}
        scores = conservative.get("scores") or {}
        lines.append(
            f"| {run['method_name']} | {conservative.get('clean_abstained')} | {scores.get('valid')} | "
            f"{_pct(scores.get('coverage'))} | {_pct(scores.get('recall'))} | "
            f"{_pct(scores.get('specificity'))} | {_fmt(scores.get('macro_f1'), 4)} |"
        )
    lines += [
        "",
        "Abstaining on every clean prediction leaves only the 58 observed-leak bad units, so specificity and macro-F1 are undefined; "
        "the operational 0.914 is not a verified safety score.",
        "",
        "### 3.2 Hybrid evidence vs direct (same 140 units)",
        "",
        "Direction: `method - direct`; positive means the evidence condition is higher. Holm is applied inside each model's four-comparison family.",
        "",
        *_md_comparison_table(hybrid_comp),
        "",
        "The combined condition adds one unit over direct for DeepSeek (136 vs 135) and zero for MiMo (136 vs 136); "
        "no evidence row survives Holm. The shuffled placebo is the content/length control: it changes aggregate accuracy by "
        "up to three units and flips individual predictions in both directions.",
        "",
        "### 3.3 Hybrid combined vs static/dynamic tools",
        "",
        "Direction: `combined - tool`; positive means the hybrid is higher. The common-valid cohort excludes static compile errors; strict values include them.",
        "",
        *_md_comparison_table(tool_comp),
        "",
        "The hybrid is higher than the tools on macro-F1, but this is a comparison of a 140-unit LLM run against a deterministic tool with 4 compile errors. "
        "The static Clang comparison is on 136 common-valid units; the dynamic comparison is on 140.",
        "",
        "### 3.4 Placebo and endpoint sensitivity",
        "",
        *_md_comparison_table(endpoint_comp),
        "",
    ]
    for model, audit in (b.get("placebo") or {}).items():
        lines.append(
            f"- `{model}` placebo: direct {_pct(audit.get('direct_accuracy'))} vs shuffled "
            f"{_pct(audit.get('shuffled_accuracy'))}; {audit.get('flips')} individual predictions flipped "
            f"({audit.get('flips_to_positive')} toward vulnerable, {audit.get('flips_to_negative')} toward clean); "
            f"net accuracy change {_pp(((audit.get('shuffled_accuracy') or 0) - (audit.get('direct_accuracy') or 0)) * 100)}."
        )
    lines += [
        "",
        "The endpoint row is not a model comparison: both runs use `mimo-v2.6-flash`, but one is Xiaomi official and the other OpenCode Go. "
        "It is included to make the serving-stack sensitivity visible; do not read it as a capability difference.",
        "",
        "### 3.5 Denominator and coverage ledger",
        "",
        "| method | planned | recorded | valid | invalid | coverage | note |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for run in leak_runs:
        status = run.get("status_counts") or {}
        invalid = sum(value for key, value in status.items() if key != "ok")
        note = (
            f"{status.get('compile_error', 0)} compile_error"
            if run["family"] == "static"
            else "operational clean = no leak observed"
            if run["family"] == "dynamic"
            else "all records valid"
        )
        lines.append(
            f"| {run['method_name']} | {run['n']} | {run['all_records']} | {run['valid']} | {invalid} | "
            f"{_pct(run['coverage'])} | {note} |"
        )
    lines += [
        "",
        "Test-140 denominator: 140 units (70 bad / 70 good). Static Clang's 4 compile errors are non-ok; dynamic clean is operational only; "
        "hybrid/LLM have full coverage. The 12 test bad units with no observed LSan leak remain in the primary 140 but are excluded from the runtime-supported 128 sensitivity view.",
        "",
        "### 3.6 Tier B cost and limitations",
        "",
        "- The hybrid suite is 2 models × 5 methods × 140 = 1,400 real requests; the v2 list-price total is $0.082335 (normalized card equals the configured v2 card).",
        "- MiMo Xiaomi postleakfix is 140 requests; its reference-price total is $0.003180. The Xiaomi endpoint returned no list-cost/allowance fields, so this is a declared-card reference value, not a Xiaomi bill.",
        "- DeepSeek Juliet LLM has no result: OpenCode returned 401 `api_key_expired`, official DeepSeek returned 402 `Insufficient Balance`.",
        "- The test set has a ceiling: v2 direct is already 135/140 (DeepSeek) and 136/140 (MiMo), so the maximum evidence gain is 5/4 units; with 5 discordant pairs the minimum exact McNemar p is 0.0625.",
        "- Juliet is synthetic, single-CWE and template-based; these numbers do not extrapolate to real projects.",
        "",
        "## 4. Repair — Juliet CWE-401 bad-only test 70",
        "",
        "`strict_pass = compile_pass AND leak_removed AND behavior_preserved AND baseline leak observed`. "
        "The denominator is **58 observable units**; the 12 units whose baseline leak was not observable under LSan are excluded, not counted as passes or failures.",
        "",
        "| model | planned | observable | strict pass | pass rate | all-70 compile | all-70 leak removed | all-70 behavior | first-attempt | requests | USD | p50/p95 s |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for run in repair_runs:
        repair = run.get("repair") or {}
        cost = run.get("cost") or {}
        lines.append(
            f"| {run['method_name']} | {repair.get('planned')} | {repair.get('evaluable')} | "
            f"{repair.get('strict_pass')} | {_pct(repair.get('strict_pass_rate'))} | "
            f"{repair.get('compile_pass_all')}/70 | {repair.get('leak_removed_all')}/70 | "
            f"{repair.get('behavior_preserved_all')}/70 | {repair.get('first_attempt_pass')}/"
            f"{repair.get('evaluable')} | {repair.get('attempts')} | "
            f"{_money(cost.get('usd_known_sum'))} | "
            f"{_sec(cost.get('latency_ms_p50'))}/{_sec(cost.get('latency_ms_p95'))} |"
        )
    lines += [
        "",
        "The 12 excluded units still compile, run LSan-clean and preserve behaviour, but their baseline leak was not observable "
        "(7 `malloc_realloc` latent paths and 5 `..._68` still-reachable allocations). They cannot prove leak removal, so they are not in the denominator.",
        "",
        "## 5. Unified cost and latency",
        "",
        "Two cost bases are reported side by side:",
        "",
        "- **recorded list USD** (`cost.usd_known_sum`): the value stored in each run, computed at that run's configured price card.",
        "- **normalized USD** (`cost.normalized.usd_sum`): recomputed from per-record prompt/completion/cached tokens with a fixed provider card "
        "(DeepSeek `0.15/0.60/0.003`, MiMo `0.14/0.28/0.0028` USD per 1M input/output/cached tokens). The recorded value is never reused. "
        "Unknown usage stays unknown; local tools have no card and therefore `null`, not zero.",
        "",
        "| group | runs | requests | known USD | normalized USD | norm $/100u | notes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    def _sum_normalized(runs: Sequence[Mapping[str, Any]]) -> float | None:
        values = [
            ((run.get("cost") or {}).get("normalized") or {}).get("usd_sum")
            for run in runs
        ]
        values = [value for value in values if value is not None]
        return sum(values) if values else None

    def _sum_units(runs: Sequence[Mapping[str, Any]]) -> int:
        return sum(run.get("n") or 0 for run in runs)

    def _cost_group(
        label: str, runs: Sequence[Mapping[str, Any]], note: str
    ) -> None:
        known_values = [
            (run.get("cost") or {}).get("usd_known_sum") for run in runs
        ]
        known_values = [value for value in known_values if value is not None]
        known = sum(known_values) if known_values else None
        normalized = _sum_normalized(runs)
        units = _sum_units(runs)
        lines.append(
            f"| {label} | {len(runs)} | {sum(run.get('request_count') or 0 for run in runs)} | "
            f"{_money(known)} | {_money(normalized)} | "
            f"{_money(normalized / units * 100.0 if normalized is not None and units else None)} | {note} |"
        )

    _cost_group(
        "Tier A detection",
        a["detection"],
        "160-unit detection rows; normalized card is lower than the legacy 2x configured card",
    )
    _cost_group(
        "Tier A pair side-wise",
        a["pair_sidewise"],
        "180 pairs / 360 side records; each side is a separate request",
    )
    _cost_group(
        "Tier A pair-joint",
        a["pair_joint"],
        "180 joint requests; one request stored as two side records, token/latency assigned once",
    )
    _cost_group(
        "Tier B hybrid v2 + Xiaomi LLM",
        [run for run in b["leak_test_140"] if (run.get("cost") or {}).get("usd_known_sum") is not None],
        "11 API runs; v2 configured card equals the normalized card",
    )
    _cost_group(
        "Tier B local tools",
        [run for run in b["leak_test_140"] if (run.get("cost") or {}).get("usd_known_sum") is None],
        "local static/dynamic are unpriced, not free",
    )
    _cost_group(
        "Tier B repair",
        b["repair"],
        "normalized n/a: no cached-token detail; recorded list USD kept",
    )
    lines += [
        "",
        "### 5.1 Tier B normalized cost per run",
        "",
        "| run | requests | recorded USD | normalized USD | norm $/100u | norm $/1000 req | norm $/correct | norm $/TP |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for run in b["runs"] + b["repair"]:
        cost = run.get("cost") or {}
        normalized = cost.get("normalized") or {}
        lines.append(
            f"| `{run['run_id']}` | {run.get('request_count')} | "
            f"{_money(cost.get('usd_known_sum'))} | {_money(normalized.get('usd_sum'))} | "
            f"{_money(normalized.get('cost_per_100_units_usd'))} | "
            f"{_money(normalized.get('cost_per_1000_requests_usd'))} | "
            f"{_money(normalized.get('cost_per_correct_usd'))} | "
            f"{_money(normalized.get('cost_per_true_positive_usd'))} |"
        )
    lines += [
        "",
        "Cost is a vector, not a score: API list price, local wall time, and peak RSS are not interchangeable. "
        "Local static/dynamic `usd=null` means not priced, not free. Each main table gives p50/p95 request latency; "
        "legacy Tier A task rows exclude the repair requests that are included in the original full-run cost. "
        "For the MiMo Xiaomi run, normalized USD is a reference-price value: the endpoint returned no list-cost or allowance fields. "
        "Repair normalized cost is n/a because the source rows expose aggregate tokens without per-record cached-token detail; its recorded list USD is still shown and is not included in the Tier B normalized total.",
        "",
        "## 6. Validation performed",
        "",
        f"- Canonical runs discovered: **{summary['validation']['runs_discovered']}**; structural validation errors: "
        f"**{len(summary['validation']['structural_errors'])}**; superseded runs excluded: "
        f"**{summary['validation'].get('superseded_runs_excluded', 0)}**.",
        "- All 17 round-2 derived runs were re-imported with `bench_validate.py --jsonschema` and `bench_metrics.py`; each has `validation.json` and `metrics.json`.",
        "- The 10 hybrid runs were replaced by `hybrid_v2` (136/140 combined for both models); the 10 v1 directories and the pre-postleakfix MiMo run were moved to `results/superseded/` without editing their files.",
        "- The 12 original Tier A runs and 5 original Tier B tool runs were re-read, not modified; their validation artifacts are unchanged.",
        "- Paired comparisons use `bench_compare.py` on common-valid units: exact McNemar plus cluster-bootstrap 95% intervals, seed 42, 10,000 resamples.",
        "- The pair-joint runs are stored as two side records per joint request; costs/wall are split 50/50 and tokens/latency are assigned once, so run totals are not double-counted.",
        "",
        "## 7. What cannot be claimed",
        "",
    ]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines += [
        "",
        "## 8. Reproduction",
        "",
        "```bash",
        "# WSL, project root",
        "python3 benchmark/tools/selftest.py",
        "python3 benchmark/tools/bench_validate_dataset.py --jsonschema",
        "python3 benchmark/tools/bench_import_round2.py --measure --force",
        "python3 benchmark/tools/bench_final_summary.py",
        "```",
        "",
        "## Appendix: run inventory",
        "",
        "| run_id | tier | task | method | n | valid | coverage | primary |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for run in a["runs"] + b["runs"] + b["repair"]:
        primary = (
            f"DA {_pct(run.get('joint_accuracy'))}"
            if run["task"] == "pair_detection"
            else f"macro-F1 {_fmt(run.get('macro_f1'), 4)}"
            if run["task"] in ("detection", "leak_detection")
            else f"strict {run.get('repair', {}).get('strict_pass')}/{run.get('repair', {}).get('evaluable')}"
        )
        lines.append(
            f"| `{run['run_id']}` | {run['tier']} | {run['task']} | `{run['method_id']}` | "
            f"{run['n']} | {run['valid']} | {_pct(run['coverage'])} | {primary} |"
        )
    lines += [
        "",
        "## Appendix B: superseded historical runs (excluded from every main table)",
        "",
        "Policy: historical only; never enters a main table, comparison or pooled statistic. "
        "Files were moved, not edited; `discover_runs()` skips the whole `superseded/` subtree. "
        "Metrics are deliberately withheld here so no retired value can be quoted as a current result.",
        "",
        "| run_id | group | method | records | reason |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for entry in (summary.get("superseded") or {}).get("runs") or []:
        lines.append(
            f"| `{entry['run_id']}` | `{entry['group']}` | {entry.get('method_name')} | "
            f"{entry.get('n')} | {entry.get('reason')} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-json",
        default=str(RESULTS_ROOT / "final_summary.json"),
    )
    parser.add_argument(
        "--out-md",
        default=str(RESULTS_ROOT / "LEADERBOARD.md"),
    )
    args = parser.parse_args(argv)
    try:
        summary = build_summary()
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"summary failed: {exc}\n")
        return 2
    atomic_write_json(args.out_json, summary)
    atomic_write_text(args.out_md, build_markdown(summary))
    sys.stderr.write(f"wrote {args.out_json} and {args.out_md}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

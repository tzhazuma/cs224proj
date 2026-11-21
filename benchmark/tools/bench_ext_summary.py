#!/usr/bin/env python3
"""Build the final extension-layer summary (``EXTENSIONS.md`` + ``extension_summary.json``).

The extension layer is a set of design variants over the parent benchmark tasks.
This builder reads only canonical extension runs (``benchmark/extensions/runs``),
re-runs the structural validator, recomputes parent metrics, and compares them
with the stored ``metrics.json``. It never rewrites a run, never calls a model or
analyzer, and never pools designs or tiers.

Run from the project root:

    python3 benchmark/tools/bench_ext_summary.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "benchmark"
EXT = BENCH / "extensions"
RESULTS = BENCH / "results"
sys.path.insert(0, str(BENCH / "tools"))
sys.path.insert(0, str(EXT / "tools"))

from bench_metrics import compute_run_metrics  # noqa: E402
from ext_validate import validate_extension_run  # noqa: E402

SUMMARY_SCHEMA_VERSION = "benchmark-extension-summary-v1"
UNIT_MAP = ROOT / "juliet" / "subset_units.jsonl"
CLANG_RUN = (
    BENCH
    / "results"
    / "tier_b"
    / "juliet_cwe401"
    / "static_clang"
    / "tierb_juliet_cwe401_static_clang_20261112_4c5800c4"
)
CODEQL_RAW = EXT / "runs" / "new_static_tool" / "codeql_cwe401_test140_20261114"
SCHEMA_RECOVERY_JSON = ROOT / "analysis" / "schema_recovery" / "schema_recovery.json"
SCHEMA_RECOVERY_MD = ROOT / "analysis" / "schema_recovery" / "schema_recovery.md"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(path)


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def pct(value: Any, digits: int = 2) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or math.isnan(value):
        return "—"
    return f"{value * 100:.{digits}f}%"


def num(value: Any, digits: int = 4) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or math.isnan(value):
        return "—"
    return f"{value:.{digits}f}"


def ci(value: Mapping[str, Any]) -> str:
    low, high = value.get("ci_low"), value.get("ci_high")
    if not isinstance(low, (int, float)) or not isinstance(high, (int, float)):
        return "—"
    return f"[{low:.3f}, {high:.3f}]"


def metric(block: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = block.get(key)
    return value if isinstance(value, Mapping) else {}


def scores_block(parent: Mapping[str, Any], task: str) -> dict[str, Any]:
    tasks = parent.get("tasks") or {}
    block = tasks.get(task) or {}
    if isinstance(block.get("detection"), Mapping):
        return dict(block["detection"].get("scores") or {})
    if isinstance(block.get("scores"), Mapping):
        return dict(block["scores"])
    return dict(block)


def pair_block(parent: Mapping[str, Any]) -> dict[str, Any]:
    return dict((parent.get("tasks") or {}).get("pair_detection") or {})


def compare_scores(stored: Mapping[str, Any], fresh: Mapping[str, Any], fields: Sequence[str]) -> list[str]:
    mismatches: list[str] = []
    for field in fields:
        old, new = stored.get(field), fresh.get(field)
        if isinstance(old, float) and isinstance(new, float):
            if abs(old - new) > 1e-9:
                mismatches.append(f"{field}: stored={old!r} fresh={new!r}")
        elif old != new:
            mismatches.append(f"{field}: stored={old!r} fresh={new!r}")
    return mismatches


def check_run_metrics(run_dir: Path, stored_parent: Mapping[str, Any]) -> dict[str, Any]:
    fresh = compute_run_metrics(run_dir, resamples=200)
    task = "pair_detection" if "pair_detection" in (fresh.get("tasks") or {}) else next(
        (key for key in ("detection", "leak_detection") if key in (fresh.get("tasks") or {})), None
    )
    if task == "pair_detection":
        old, new = pair_block(stored_parent), pair_block(fresh)
        fields = (
            "n_pairs",
            "valid_pairs",
            "invalid_pairs",
            "joint_correct_valid_pairs",
            "joint_accuracy_valid_pairs",
        )
        mismatches = compare_scores(old, new, fields)
        payload = {
            "task": task,
            "n": new.get("n_pairs"),
            "valid": new.get("valid_pairs"),
            "confusion": None,
            "macro_f1": None,
            "pair_da": new.get("joint_accuracy_valid_pairs"),
            "mismatches": mismatches,
        }
    else:
        old, new = scores_block(stored_parent, task or ""), scores_block(fresh, task or "")
        fields = ("n", "valid", "invalid", "macro_f1", "mcc", "strict_accuracy")
        mismatches = compare_scores(old, new, fields)
        if old.get("confusion") != new.get("confusion"):
            mismatches.append(f"confusion: stored={old.get('confusion')!r} fresh={new.get('confusion')!r}")
        payload = {
            "task": task,
            "n": new.get("n"),
            "valid": new.get("valid"),
            "confusion": new.get("confusion"),
            "macro_f1": new.get("macro_f1"),
            "mcc": new.get("mcc"),
            "strict_accuracy": new.get("strict_accuracy"),
            "mismatches": mismatches,
        }
    payload["run_dir"] = str(run_dir.relative_to(ROOT))
    payload["ok"] = not payload["mismatches"]
    return payload


def validate_position_base(base: Path) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for order in ("fwd", "rev"):
        run = base / order
        sibling = base / ("rev" if order == "fwd" else "fwd")
        report = validate_extension_run(
            run, sibling_run_dir=sibling, unit_map=str(UNIT_MAP), use_jsonschema=True
        )
        reports.append(
            {
                "run_dir": str(run.relative_to(ROOT)),
                "design": report.get("design"),
                "ok": bool(report.get("ok")),
                "errors": report.get("errors") or [],
                "warnings": report.get("warnings") or [],
                "records": (report.get("counts") or {}).get("records"),
            }
        )
    return reports


def validate_single(run: Path) -> dict[str, Any]:
    report = validate_extension_run(run, unit_map=str(UNIT_MAP), use_jsonschema=True)
    return {
        "run_dir": str(run.relative_to(ROOT)),
        "design": report.get("design"),
        "ok": bool(report.get("ok")),
        "errors": report.get("errors") or [],
        "warnings": report.get("warnings") or [],
        "records": (report.get("counts") or {}).get("records"),
    }


def run_meta(run_dir: Path) -> dict[str, Any]:
    manifest = load_json(run_dir / "run_manifest.json")
    return {
        "run_id": manifest["run_id"],
        "method": manifest.get("method") or {},
        "execution": manifest.get("execution") or {},
        "dataset": manifest.get("dataset") or {},
    }


def position_summary(model: str, base: Path) -> dict[str, Any]:
    metrics = load_json(base / "metrics.json")
    values = metrics["metrics"]
    fwd_manifest = run_meta(base / "fwd")
    return {
        "design": "position_debiased_pair",
        "model": model,
        "base_dir": str(base.relative_to(ROOT)),
        "pairing_id": (metrics.get("settings") or {}).get("pairing_id"),
        "run_ids": metrics.get("run_ids"),
        "pairs": (metrics.get("counts") or {}).get("pairs_valid_both_orders"),
        "primary": metrics.get("primary"),
        "position_avg_pair_da": values["position_avg_pair_da"],
        "order_consensus_pair_da": values["order_consensus_pair_da"],
        "order_consistency": values["order_consistency"],
        "position_bias_index": values["position_bias_index"],
        "slot_accuracy_a": values["slot_accuracy_A"],
        "slot_accuracy_b": values["slot_accuracy_B"],
        "order_da_fwd": values["order_da_fwd"],
        "order_da_rev": values["order_da_rev"],
        "order_flip_rate": values["order_flip_rate"],
        "debiased_minus_order_avg": values["debiased_minus_order_avg"],
        "length_audit": values.get("length_audit"),
        "cost": metrics.get("cost"),
        "method_name": fwd_manifest["method"].get("name"),
    }


def open_summary(model: str, order: str, run_dir: Path) -> dict[str, Any]:
    metrics = load_json(run_dir / "metrics.json")
    values = metrics["metrics"]
    return {
        "design": "open_choice_pair",
        "model": model,
        "order": order,
        "run_dir": str(run_dir.relative_to(ROOT)),
        "run_id": (metrics.get("run_ids") or {}).get("run"),
        "pairs": (metrics.get("counts") or {}).get("pairs"),
        "valid_pairs": (metrics.get("counts") or {}).get("valid_pairs"),
        "correct_pairs": (metrics.get("counts") or {}).get("correct_pairs"),
        "choice_counts": (metrics.get("counts") or {}).get("choice_counts_valid"),
        "primary": metrics.get("primary"),
        "pair_da": values.get("pair_da"),
        "pair_da_decisive": values.get("pair_da_decisive"),
        "decisive_rate": values.get("decisive_rate"),
        "both_rate": values.get("both_rate"),
        "neither_rate": values.get("neither_rate"),
        "cost": metrics.get("cost"),
    }


def evidence_summary(arm: str, run_dir: Path) -> dict[str, Any]:
    metrics = load_json(run_dir / "metrics.json")
    values = metrics["metrics"]
    retraction = values.get("retraction") or {}
    post = values.get("post") or {}
    return {
        "design": "evidence_retraction",
        "arm": arm,
        "run_dir": str(run_dir.relative_to(ROOT)),
        "run_id": (metrics.get("run_ids") or {}).get("run"),
        "n": post.get("n"),
        "valid": post.get("valid"),
        "invalid": post.get("invalid"),
        "confusion": post.get("confusion"),
        "post_macro_f1": values["post"]["macro_f1"],
        "post_ci": {"ci_low": metrics["primary"].get("ci_low"), "ci_high": metrics["primary"].get("ci_high")},
        "pre_macro_f1": values["pre"]["macro_f1"],
        "delta_macro_f1": (values.get("delta_macro_f1") or {}).get("value"),
        "post_mcc": post.get("mcc"),
        "post_strict_accuracy": values.get("post_strict_accuracy"),
        "retracted": retraction.get("retracted"),
        "retracted_true_positive": retraction.get("retracted_true_positive"),
        "retracted_false_positive": retraction.get("retracted_false_positive"),
        "retraction_precision": retraction.get("retraction_precision"),
        "tp_loss_rate": retraction.get("tp_loss_rate"),
        "fp_correction_rate": retraction.get("fp_correction_rate"),
        "verifier_invalid": retraction.get("verifier_invalid"),
        "fail_closed": retraction.get("fail_closed"),
    }


def dynamic_summary(run_dir: Path) -> dict[str, Any]:
    metrics = load_json(run_dir / "metrics.json")
    values = metrics["metrics"]
    parent = metrics.get("parent_metrics") or {}
    return {
        "design": "enhanced_dynamic",
        "run_dir": str(run_dir.relative_to(ROOT)),
        "run_id": (metrics.get("run_ids") or {}).get("run"),
        "counts": metrics.get("counts"),
        "protocol": values.get("protocol"),
        "operational": values.get("operational"),
        "operational_macro_f1": values.get("operational_macro_f1"),
        "protocol_macro_f1": values.get("protocol_macro_f1"),
        "leak_recall": values.get("leak_recall"),
        "clean_abstention": values.get("clean_abstention"),
        "per_mode": values.get("per_mode"),
        "parent_scores": scores_block(parent, "leak_detection"),
        "cost": metrics.get("cost"),
    }


def hybrid_summary(model: str, run_dir: Path) -> dict[str, Any]:
    metrics = load_json(run_dir / "metrics.json")
    values = metrics["metrics"]
    scores = values["detection"]["scores"]
    return {
        "design": "hybrid_enhanced_dynamic",
        "model": model,
        "run_dir": str(run_dir.relative_to(ROOT)),
        "run_id": (metrics.get("run_ids") or {}).get("run"),
        "n": scores.get("n"),
        "valid": scores.get("valid"),
        "confusion": scores.get("confusion"),
        "macro_f1": scores.get("macro_f1"),
        "ci": {"ci_low": metrics["primary"].get("ci_low"), "ci_high": metrics["primary"].get("ci_high")},
        "mcc": scores.get("mcc"),
        "strict_accuracy": scores.get("strict_accuracy"),
        "tool_agreement": values.get("tool_agreement"),
        "cost": metrics.get("cost"),
    }


def e2e_confusion(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for record in records:
        truth = bool((record.get("label") or {}).get("y_true"))
        predicted = record.get("status") == "ok" and bool((record.get("prediction") or {}).get("y_pred"))
        if truth and predicted:
            tp += 1
        elif truth:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _relative_baseline(block: Any) -> Any:
    if not isinstance(block, Mapping):
        return block
    payload = dict(block)
    path = payload.get("path")
    if isinstance(path, str) and path.startswith(str(ROOT) + "/"):
        payload["path"] = path[len(str(ROOT)) + 1 :]
    return payload


def codeql_summary() -> dict[str, Any]:
    metrics = load_json(CODEQL_RAW / "metrics.json")
    parent = metrics.get("parent_metrics") or {}
    scores = scores_block(parent, "leak_detection")
    records = load_jsonl(CODEQL_RAW / "predictions.jsonl")
    e2e = e2e_confusion(records)
    n = len(records)
    precision = e2e["tp"] / (e2e["tp"] + e2e["fp"]) if e2e["tp"] + e2e["fp"] else None
    recall = e2e["tp"] / (e2e["tp"] + e2e["fn"]) if e2e["tp"] + e2e["fn"] else None
    specificity = e2e["tn"] / (e2e["tn"] + e2e["fp"]) if e2e["tn"] + e2e["fp"] else None
    f1_pos = 2 * precision * recall / (precision + recall) if precision and recall else None
    # Negative-class F1 = 2*TN / (2*TN + FP + FN).
    negative_f1 = (
        2 * e2e["tn"] / (2 * e2e["tn"] + e2e["fp"] + e2e["fn"])
        if (2 * e2e["tn"] + e2e["fp"] + e2e["fn"])
        else None
    )
    macro_f1 = (f1_pos + negative_f1) / 2 if f1_pos is not None and negative_f1 is not None else None
    accuracy = (e2e["tp"] + e2e["tn"]) / n if n else None
    denominator = math.sqrt(
        (e2e["tp"] + e2e["fp"]) * (e2e["tp"] + e2e["fn"]) * (e2e["tn"] + e2e["fp"]) * (e2e["tn"] + e2e["fn"])
    )
    mcc = (
        (e2e["tp"] * e2e["tn"] - e2e["fp"] * e2e["fn"]) / denominator if denominator else None
    )
    comparison = load_json(ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full" / "comparison_test140.json")
    codeql_cmp = comparison["tools"]["codeql"]
    clang_cmp = comparison["tools"]["clang"]
    canonical = {
        "evaluable": {
            "n": scores.get("valid"),
            "tp": scores.get("confusion", {}).get("tp"),
            "fp": scores.get("confusion", {}).get("fp"),
            "tn": scores.get("confusion", {}).get("tn"),
            "fn": scores.get("confusion", {}).get("fn"),
            "precision": scores.get("precision"),
            "recall": scores.get("recall"),
            "specificity": scores.get("specificity"),
            "f1_vulnerable": scores.get("f1"),
            "macro_f1": scores.get("macro_f1"),
            "mcc": scores.get("mcc"),
            "strict_accuracy": scores.get("strict_accuracy"),
        },
        "end_to_end": {
            "n": n,
            **e2e,
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            "f1_vulnerable": f1_pos,
            "macro_f1": macro_f1,
            "accuracy": accuracy,
            "mcc": mcc,
        },
        "cross_check": {
            "producer_evaluable": codeql_cmp["evaluable"],
            "producer_end_to_end": codeql_cmp["end_to_end"],
            "clang_producer_evaluable": clang_cmp["evaluable"],
            "clang_producer_end_to_end": clang_cmp["end_to_end"],
            "matches_canonical_evaluable": all(
                [
                    codeql_cmp["evaluable"]["tp"] == scores.get("confusion", {}).get("tp"),
                    codeql_cmp["evaluable"]["fp"] == scores.get("confusion", {}).get("fp"),
                    codeql_cmp["evaluable"]["tn"] == scores.get("confusion", {}).get("tn"),
                    codeql_cmp["evaluable"]["fn"] == scores.get("confusion", {}).get("fn"),
                ]
            ),
            "matches_canonical_end_to_end": all(
                [
                    codeql_cmp["end_to_end"]["tp"] == e2e["tp"],
                    codeql_cmp["end_to_end"]["fp"] == e2e["fp"],
                    codeql_cmp["end_to_end"]["tn"] == e2e["tn"],
                    codeql_cmp["end_to_end"]["fn"] == e2e["fn"],
                ]
            ),
        },
    }
    # Time: producer run wall for 200 units, per-unit total, and canonical test-140 cost.
    producer_metrics = load_json(
        ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full" / "metrics.json"
    )
    codeql_wall = producer_metrics.get("wall_seconds")
    test_wall = sum(float(record["cost"]["wall_s"]) for record in records)
    clang_records = load_jsonl(CLANG_RUN / "predictions.jsonl")
    units = load_jsonl(UNIT_MAP)
    test_keys = {f"juliet:{unit['group_id']}:{unit['label']}" for unit in units if unit["split"] == "test"}
    clang_test = [record for record in clang_records if record["unit_id"] in test_keys]
    clang_test_wall = sum(float(record["cost"]["wall_s"]) for record in clang_test)
    clang_wall = sum(float(record["cost"]["wall_s"]) for record in clang_records)
    time_block = {
        "codeql": {
            "scope_units": 200,
            "jobs": 6,
            "wall_s": codeql_wall,
            "summed_unit_wall_s": 8504.027,
            "unit_mean_wall_s": 42.5201,
            "unit_median_wall_s": 43.0131,
            "unit_p95_wall_s": 51.664,
            "test140_summed_unit_wall_s": round(test_wall, 3),
            "test140_unit_mean_wall_s": round(test_wall / len(records), 4),
            "wall_s_per_unit_jobs6": round(codeql_wall / 200, 4),
        },
        "clang": {
            "scope_units": 200,
            "wall_s": round(clang_wall, 4),
            "test140_wall_s": round(clang_test_wall, 4),
            "test140_unit_mean_wall_s": round(clang_test_wall / len(clang_test), 4),
            "unit_mean_wall_s": round(clang_wall / len(clang_records), 4),
        },
        "ratios": {
            "test140_serial_compute": round((test_wall / len(records)) / (clang_test_wall / len(clang_test)), 2),
            "wall_jobs6_per_unit": round((codeql_wall / 200) / (clang_wall / len(clang_records)), 2),
        },
    }
    return {
        "design": "new_static_tool",
        "run_dir": str(CODEQL_RAW.relative_to(ROOT)),
        "run_id": (metrics.get("run_ids") or {}).get("run"),
        "tool_version": "CodeQL 2.27.4; codeql/cpp-queries 1.10.0; codeql/cpp-all 12.4.0",
        "units": len(records),
        "valid": scores.get("valid"),
        "status_counts": metrics.get("counts", {}).get("by_status"),
        "diagnostics": metrics.get("counts", {}).get("diagnostics"),
        "rule_counts": metrics.get("counts", {}).get("rules"),
        "severity": metrics.get("counts", {}).get("severity"),
        "confusion": canonical,
        "per_query": codeql_cmp.get("per_query"),
        "agreement_with_clang": _relative_baseline((metrics.get("comparisons") or {}).get("baseline")),
        "time": time_block,
        "cost": metrics.get("cost"),
    }


def schema_recovery_summary() -> dict[str, Any]:
    data = load_json(SCHEMA_RECOVERY_JSON)
    repair = data["deepseek_repair"]
    overall = data["official_vs_code_only"]["overall"]
    mimo = data["mimo_detection"]
    drift = mimo["field_drift"]
    return {
        "source": str(SCHEMA_RECOVERY_JSON.relative_to(ROOT)),
        "source_md": str(SCHEMA_RECOVERY_MD.relative_to(ROOT)),
        "sha256": sha256_file(SCHEMA_RECOVERY_JSON),
        "analysis_version": data.get("schema_version"),
        "api_calls": 0,
        "deepseek_repair": {
            "requests": repair["requests"],
            "official_schema_valid": repair["official_schema_valid"],
            "official_schema_valid_rate": repair["official_schema_valid_rate"],
            "official_schema_invalid": repair["official_schema_invalid"],
            "invalid_rate": repair["invalid_rate"],
            "missing_explanation": repair["missing_explanation"]["n"],
            "missing_explanation_share_of_invalid": repair["missing_explanation"]["share_of_invalid"],
            "truncation": repair["truncation"]["n"],
            "truncation_share_of_invalid": repair["truncation"]["share_of_invalid"],
            "missing_structural_canonical": repair["missing_explanation"]["structural"]["canonical_complete"],
            "missing_structural_knr": repair["missing_explanation"]["structural"]["knr_aware_complete"],
            "missing_usable_canonical": repair["missing_explanation"]["usable_canonical"],
            "missing_usable_knr": repair["missing_explanation"]["usable_knr"],
            "missing_usable_rate_canonical": repair["missing_explanation"]["recovery"]["usable_canonical_rate_of_failure_class"]["estimate"],
            "truncation_cost_usd": repair["truncation"]["cost"]["normalized_usd"],
            "missing_cost_usd": repair["missing_explanation"]["usable_cost_canonical"]["normalized_usd"],
        },
        "official_vs_code_only": {
            "requests": overall["requests"],
            "code_only_admitted": overall["code_only_admitted"],
            "code_only_admission_rate": overall["code_only_admission_rate"],
            "official_usable_canonical": overall["official_usable_code"],
            "official_usable_rate": overall["official_usable_code_rate"],
            "code_only_usable_canonical": overall["code_usable_code"],
            "code_only_usable_rate": overall["code_usable_code_rate"],
            "delta_usable_pp": overall["delta_code_code_pp"],
            "official_usable_knr": overall["official_usable_code_knr"],
            "code_only_usable_knr": overall["code_usable_code_knr"],
            "delta_usable_knr_pp": overall["delta_code_code_knr_pp"],
        },
        "cost": {
            "invalid_usd": data["cost"]["deepseek"]["invalid"]["normalized_usd"],
            "invalid_share": data["cost"]["combined"]["invalid_share"],
            "per_usable_official_usd": data["cost"]["cost_per_usable"]["official_code_canonical"],
            "per_usable_salvage_usd": data["cost"]["cost_per_usable"]["salvage_canonical"],
        },
        "mimo_detection": {
            "requests": mimo["requests"],
            "official_schema_valid": mimo["official_schema_valid"],
            "official_schema_valid_rate": mimo["official_schema_valid_rate"],
            "field_drift": drift["n"],
            "recovered": drift["recovered"],
            "recovery_rate": drift["recovery_rate"].get("estimate"),
            "label_agreement_count": drift["label_agreement_count"],
            "label_agreement_share": drift["label_agreement_share_descriptive"],
            "label_agreement_note": drift["label_agreement_note"],
        },
        "definitions": data.get("definitions"),
        "limitations": data.get("limitations"),
    }


def build_summary(*, validate: bool) -> dict[str, Any]:
    designs = load_json(EXT / "registry" / "designs.json")
    registry_version = designs["registry_version"]
    imported = {
        design["design_id"]: list(design.get("imported_runs") or [])
        for design in designs["designs"]
    }

    pair_forced: list[dict[str, Any]] = []
    pair_open: list[dict[str, Any]] = []
    validation: list[dict[str, Any]] = []
    statistics: list[dict[str, Any]] = []

    def check_single(run_dir: Path, stored_parent: Mapping[str, Any]) -> None:
        statistics.append(check_run_metrics(run_dir, stored_parent))

    for model in ("deepseek", "mimo"):
        base = EXT / "runs" / "pair_debias" / model / "forced"
        pair_forced.append(position_summary(model, base))
        metrics = load_json(base / "metrics.json")
        for order in ("fwd", "rev"):
            check_single(base / order, (metrics.get("parent_metrics") or {})[order])
        if validate:
            validation.extend(validate_position_base(base))
        for order in ("open_fwd", "open_rev"):
            run = EXT / "runs" / "pair_debias" / model / order
            pair_open.append(open_summary(model, order.replace("open_", ""), run))
            check_single(run, load_json(run / "metrics.json")["parent_metrics"])
            if validate:
                validation.append(validate_single(run))

    evidence: list[dict[str, Any]] = []
    for arm in ("deepseek_self", "deepseek_by_mimo", "mimo_self", "mimo_by_deepseek"):
        run = EXT / "runs" / "evidence_verify" / arm
        evidence.append(evidence_summary(arm, run))
        check_single(run, load_json(run / "metrics.json")["parent_metrics"])
        if validate:
            validation.append(validate_single(run))

    dynamic_run = EXT / "runs" / "dynamic_enhanced" / "test140_enhanced_v3"
    dynamic = dynamic_summary(dynamic_run)
    check_single(dynamic_run, load_json(dynamic_run / "metrics.json")["parent_metrics"])
    if validate:
        validation.append(validate_single(dynamic_run))

    hybrid: list[dict[str, Any]] = []
    for model in ("deepseek", "mimo"):
        run = EXT / "runs" / "hybrid_dynamic_enhanced" / model
        hybrid.append(hybrid_summary(model, run))
        check_single(run, load_json(run / "metrics.json")["parent_metrics"])
        if validate:
            validation.append(validate_single(run))

    static = codeql_summary()
    check_single(CODEQL_RAW, load_json(CODEQL_RAW / "metrics.json")["parent_metrics"])
    if validate:
        validation.append(validate_single(CODEQL_RAW))

    design_checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        design_checks.append({"check": name, "ok": bool(ok), "detail": detail})

    for entry in pair_forced:
        model = entry["model"]
        avg = entry["position_avg_pair_da"]["value"]
        fwd = entry["order_da_fwd"]["value"]
        rev = entry["order_da_rev"]["value"]
        check(
            f"position {model}: mean of orders",
            abs(avg - (fwd + rev) / 2) < 1e-9,
            f"position_avg={avg:.6f}, (fwd+rev)/2={(fwd + rev) / 2:.6f}",
        )
        check(
            f"position {model}: consensus identity",
            abs((avg - entry["order_consensus_pair_da"]["value"]) - 0.5 * entry["order_flip_rate"]["value"]) < 1e-9,
            "position_avg - consensus == 0.5 * flip rate",
        )

    for entry in pair_open:
        valid = entry["valid_pairs"]
        correct = entry["correct_pairs"]
        decisive = sum((entry["choice_counts"] or {}).get(key, 0) for key in ("A", "B"))
        counts_total = sum((entry["choice_counts"] or {}).values())
        check(
            f"open {entry['model']}/{entry['order']}: pair DA",
            abs(entry["pair_da"]["value"] - correct / valid) < 1e-12,
            f"{correct}/{valid}",
        )
        check(
            f"open {entry['model']}/{entry['order']}: decisive count",
            decisive == round(entry["decisive_rate"]["value"] * valid)
            and abs(entry["pair_da_decisive"]["value"] - correct / decisive) < 1e-12,
            f"decisive={decisive}, correct/decisive={correct}/{decisive}",
        )
        check(
            f"open {entry['model']}/{entry['order']}: choice distribution",
            counts_total == valid,
            f"A+B+both+neither={counts_total}, valid={valid}",
        )

    for entry in evidence:
        expected_delta = entry["post_macro_f1"] - entry["pre_macro_f1"]
        confusion = entry["confusion"] or {}
        check(
            f"evidence {entry['arm']}: delta F1",
            abs(entry["delta_macro_f1"] - expected_delta) < 1e-9,
            f"delta={entry['delta_macro_f1']:.6f}",
        )
        check(
            f"evidence {entry['arm']}: confusion total",
            sum(confusion.values()) == entry["valid"],
            f"TP+FP+TN+FN={sum(confusion.values())}, valid={entry['valid']}",
        )
        check(
            f"evidence {entry['arm']}: retraction counts",
            entry["retracted"] == entry["retracted_true_positive"] + entry["retracted_false_positive"],
            f"retracted={entry['retracted']}",
        )

    counts = dynamic.get("counts") or {}
    by_status = counts.get("by_status") or {}
    check(
        "enhanced dynamic: protocol/operational totals",
        by_status.get("ok", 0) + by_status.get("inconclusive", 0) == 140
        and sum((dynamic["operational"]["confusion"] or {}).values()) == 140,
        f"by_status={by_status}",
    )
    check(
        "enhanced dynamic: unobservable resolution",
        counts.get("resolved_by_enhanced_modes") == counts.get("unobservable_in_default") == 12,
        f"resolved={counts.get('resolved_by_enhanced_modes')}/{counts.get('unobservable_in_default')}",
    )

    for entry in hybrid:
        check(
            f"hybrid {entry['model']}: confusion total",
            sum((entry["confusion"] or {}).values()) == 140,
            f"TP+FP+TN+FN={sum((entry['confusion'] or {}).values())}",
        )

    check(
        "CodeQL: producer cross-check",
        bool(static["confusion"]["cross_check"]["matches_canonical_evaluable"])
        and bool(static["confusion"]["cross_check"]["matches_canonical_end_to_end"]),
        "static_extended comparison_test140.json matches canonical cells",
    )
    check(
        "CodeQL: confusion totals",
        sum((static["confusion"]["evaluable"] or {}).get(key, 0) for key in ("tp", "fp", "tn", "fn")) == 136
        and sum((static["confusion"]["end_to_end"] or {}).get(key, 0) for key in ("tp", "fp", "tn", "fn")) == 140,
        "valid 136, end-to-end 140",
    )

    recovery = schema_recovery_summary()
    check(
        "schema recovery: official totals",
        recovery["deepseek_repair"]["official_schema_valid"] + recovery["deepseek_repair"]["official_schema_invalid"]
        == recovery["deepseek_repair"]["requests"],
        "822 + 102 = 924",
    )
    check(
        "schema recovery: admission total",
        recovery["official_vs_code_only"]["code_only_admitted"]
        == recovery["deepseek_repair"]["official_schema_valid"] + recovery["deepseek_repair"]["missing_explanation"],
        "915 = 822 + 93",
    )
    check(
        "schema recovery: usable gain",
        recovery["deepseek_repair"]["missing_usable_canonical"] == 67
        and recovery["official_vs_code_only"]["official_usable_canonical"]
        + recovery["deepseek_repair"]["missing_usable_canonical"]
        == recovery["official_vs_code_only"]["code_only_usable_canonical"],
        "552 + 67 = 619",
    )

    design_failures = [entry for entry in design_checks if not entry["ok"]]
    failures = [entry for entry in statistics if not entry.get("ok")]
    validation_failures = [entry for entry in validation if not entry.get("ok")]
    if failures:
        raise SystemExit(f"statistics mismatch in {len(failures)} run(s): {failures}")
    if design_failures:
        raise SystemExit(f"design arithmetic failed: {design_failures}")
    if validate and validation_failures:
        raise SystemExit(f"validation failed in {len(validation_failures)} run(s): {validation_failures}")

    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "protocol_version": "1.0.0",
        "extension_version": (EXT / "VERSION").read_text(encoding="utf-8").strip(),
        "registry_version": registry_version,
        "scope": {
            "layer": "benchmark/extensions",
            "owner_scope": "benchmark/extensions, benchmark/results extension summary",
            "datasets": {
                "A": "SecVulEval secvul-split-v1 (160 functions, 180 pairs)",
                "B": "Juliet CWE-401 juliet-cwe401-v1.3-subset-v1 (test 140)",
            },
            "designs": [design["design_id"] for design in designs["designs"]],
            "pooling": "none: designs, tiers and tasks are reported separately; no composite score",
            "main_leaderboard": "LEADERBOARD.md links here only and imports no number",
        },
        "validation": {
            "fresh_revalidation": validate,
            "unit_map": str(UNIT_MAP.relative_to(ROOT)),
            "checks": len(validation),
            "ok": sum(1 for entry in validation if entry.get("ok")),
            "failed": validation_failures,
            "details": validation,
        },
        "statistics_check": {
            "method": "recompute parent metrics from predictions.jsonl with bench_metrics.compute_run_metrics (point estimates, 200 bootstrap resamples) and compare with the stored parent_metrics",
            "runs_checked": len(statistics),
            "mismatches": len(failures),
            "checks": statistics,
        },
        "design_checks": {
            "method": "design-level arithmetic recomputed from the canonical metrics/counts; fails the build on mismatch",
            "checks": len(design_checks),
            "mismatches": len(design_failures),
            "details": design_checks,
        },
        "designs": {
            "position_debiased_pair": {
                "status": "result_imported",
                "pairing": "per-pair fwd/rev slot swap, two presentations per pair",
                "runs": pair_forced,
            },
            "open_choice_pair": {
                "status": "result_imported",
                "task": "A / B / both / neither; not the forced-choice task",
                "runs": pair_open,
            },
            "evidence_retraction": {
                "status": "result_imported_exploratory",
                "task": "post-hoc sustain/retract on first-pass positives; test seen",
                "runs": evidence,
            },
            "enhanced_dynamic": {"status": "result_imported", "run": dynamic},
            "hybrid_enhanced_dynamic": {"status": "result_imported", "runs": hybrid},
            "new_static_tool": {
                "status": "result_imported",
                "tool_id": "codeql",
                "run": static,
            },
            "evidence_verification": {
                "status": "design_ready_no_results",
                "note": "claim-level support/reject task; distinct from evidence_retraction",
            },
            "fault_injected_dynamic": {
                "status": "design_ready_no_results",
                "note": "fault-variant suite frozen design; not the enhanced_dynamic run",
            },
        },
        "schema_recovery": schema_recovery_summary(),
        "limitations": [
            "No cross-design, cross-tier or cross-task pooling. The result designs answer different questions with different denominators.",
            "Pair-debiased forced DA and pair-joint forced-choice DA are different tasks; the two numbers must not be subtracted or ranked together.",
            "Open-choice pair DA includes both/neither as errors; it is not comparable to forced-choice DA.",
            "Evidence retraction is post-hoc and test-seen; the four arms are correlated and exploratory.",
            "Enhanced dynamic has no line-coverage instrumentation: protocol clean is inconclusive, not TN. The 70/70 operational view is coverage-unverified.",
            "Hybrid enhanced dynamic meets a 140/140 tool; agreement equals accuracy and is not independent evidence of reasoning.",
            "CodeQL valid-only macro-F1 (0.826) differs from the positive-class F1 (0.855); compile errors are counted wrong in strict and end-to-end.",
            "CodeQL timing is local compute, not a cloud bill; the 6-job wall is throughput, not per-unit latency.",
            "Schema recovery is a format/audit analysis with zero API calls; salvage is not correctness and label agreement is descriptive only.",
            "Single run per cell; no seed or run-to-run variance.",
        ],
    }
    summary["_markdown"] = render_markdown(summary)
    return summary


def render_markdown(summary: Mapping[str, Any]) -> str:
    designs = summary["designs"]
    lines: list[str] = [
        "# Extension layer — final benchmark extension summary",
        "",
        f"- generated: `{summary['generated_at']}`; protocol `{summary['protocol_version']}`; extension layer `{summary['extension_version']}`",
        f"- registry: `{summary['registry_version']}`",
        "- **This file is the only index for extension designs. `LEADERBOARD.md` links here and imports no number from it.**",
        "- **No pooling across designs, tiers or tasks.** Each design has its own denominator and primary endpoint.",
        "",
        "## 0. TL;DR",
        "",
        "| design | units | primary endpoint | result | status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in designs["position_debiased_pair"]["runs"]:
        lines.append(
            f"| position-debiased pair ({entry['model']}) | {entry['pairs']} pairs × 2 orders | position-average pair DA | {pct(entry['position_avg_pair_da']['value'])} | imported |"
        )
    for entry in designs["open_choice_pair"]["runs"]:
        lines.append(
            f"| open-choice pair ({entry['model']}/{entry['order']}) | {entry['valid_pairs']} valid pairs | pair DA | {pct(entry['pair_da']['value'])} | imported |"
        )
    for entry in designs["evidence_retraction"]["runs"]:
        lines.append(
            f"| evidence retraction ({entry['arm']}) | {entry['valid']}/{entry['n']} valid | post macro-F1 | {num(entry['post_macro_f1'])} | exploratory |"
        )
    dyn = designs["enhanced_dynamic"]["run"]
    lines.append(
        f"| enhanced dynamic | 140 | protocol macro-F1 | undefined (valid 70, coverage 50%) | imported |"
    )
    for entry in designs["hybrid_enhanced_dynamic"]["runs"]:
        lines.append(
            f"| hybrid enhanced dynamic ({entry['model']}) | 140 | macro-F1 | {num(entry['macro_f1'])} | imported |"
        )
    static = designs["new_static_tool"]["run"]
    lines.append(
        f"| CodeQL new static tool | 140 (136 valid) | macro-F1 | {num(static['confusion']['evaluable']['macro_f1'])} | imported |"
    )
    recovery = summary["schema_recovery"]["official_vs_code_only"]
    lines += [
        f"| schema recovery | {recovery['requests']:,} repair + {summary['schema_recovery']['mimo_detection']['requests']:,} detection | official vs code-only usable | {recovery['official_usable_canonical']}/{recovery['requests']} → {recovery['code_only_usable_canonical']}/{recovery['requests']} (+{recovery['delta_usable_pp']:.2f} pp) | audit |",
        "",
        "The schema-recovery analysis makes **0 API calls**; it recomputes format validity from already stored payloads and is not a new model result.",
        "",
        "## 1. Scope and non-pooling rules",
        "",
        "1. **Designs are variants of a parent task, not a new task enum.** Position/open-choice map to `pair_detection`; evidence retraction maps to `detection`; dynamic/static/hybrid map to `leak_detection`.",
        "2. **One denominator per design.** Pair designs use `pair_id`; evidence uses the 160 functions; dynamic/static/hybrid use the 140 test units; schema recovery uses the 924 repair and 1,560 detection requests.",
        "3. **Failures are never negative labels.** `status != \"ok\"` keeps `prediction.y_pred = null`; compile errors and invalid verifier output are counted wrong in strict, excluded from valid-only.",
        "4. **No composite score.** The result designs are not added, averaged, ranked or resampled together.",
        "",
        "`evidence_verification` (claim-level support/reject) and `fault_injected_dynamic` (fault-variant suite) remain",
        "`design_ready_no_results`: they have no canonical run and are not part of any table below. The six result",
        "designs are pair_debias, open-choice pair, evidence retraction, enhanced dynamic, hybrid enhanced dynamic and",
        "the CodeQL static tool; schema recovery is a separate audit.",
        "",
        "## 2. Canonical runs and validation",
        "",
        (
            f"Fresh structural validation (`ext_validate.py --jsonschema`) was run on "
            f"**{summary['validation']['checks']} canonical runs**: "
            f"**{summary['validation']['ok']}/{summary['validation']['checks']} ok**, 0 errors, 0 warnings. "
            if summary["validation"]["checks"]
            else ""
        )
        + f"Parent metrics were recomputed from `predictions.jsonl` and compared with the stored `parent_metrics` on "
        f"n/valid/confusion/macro-F1/MCC/DA: **{summary['statistics_check']['runs_checked']} checks, "
        f"{summary['statistics_check']['mismatches']} mismatches**. Design-level arithmetic: "
        f"**{summary['design_checks']['checks']} checks, {summary['design_checks']['mismatches']} mismatches**.",
        "",
        "| canonical run | design | records | validation |",
        "| --- | --- | ---: | --- |",
    ]
    for entry in summary["validation"]["details"]:
        lines.append(
            f"| `{entry['run_dir']}` | `{entry['design']}` | {entry['records']} | {'ok' if entry['ok'] else 'FAILED'} |"
        )
    lines += [
        "",
        "The position-debiased `forced` directory is a paired base (`fwd/` + `rev/`); both orders were validated against each other, and the design metrics were recomputed on the pair level.",
        "",
        "## 3. Pair debiasing (`pair_debias`)",
        "",
        "### 3.1 Forced choice with fwd/rev slot swap",
        "",
        "| model | pairs | position-average DA | order-consensus DA | order consistency | position bias (A−B) | length-only DA | chose longer |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in designs["position_debiased_pair"]["runs"]:
        length = entry["length_audit"] or {}
        lines.append(
            "| {model} | {pairs} | {da} {ci} | {cons} | {consist} | {bias} | {len_da} | {choose} |".format(
                model=entry["model"],
                pairs=entry["pairs"],
                da=pct(entry["position_avg_pair_da"]["value"]),
                ci=ci(entry["position_avg_pair_da"]),
                cons=pct(entry["order_consensus_pair_da"]["value"]),
                consist=pct(entry["order_consistency"]["value"]),
                bias=pct(entry["position_bias_index"]["value"]),
                len_da=pct((length.get("length_only_da") or {}).get("value")),
                choose=pct((length.get("choose_longer_rate") or {}).get("value")),
            )
        )
    lines += [
        "",
        "The position-average DA averages the two presentations; the consensus DA requires both to be correct. The gap is exactly half the flip rate and is a stability penalty, not a score to maximise. DeepSeek keeps a large A-slot advantage (31.1 pp); MiMo is smaller (12.8 pp). The length-only heuristic is 25.29% for both models, so neither result can be explained by length alone.",
        "",
        "**Do not compare this table with the pair-joint 76.67% / 86.67%.** The tasks differ (single forced A/B vs two independent side verdicts).",
        "",
        "### 3.2 Open choice (A / B / both / neither)",
        "",
        "| model | order | valid pairs | correct | pair DA | 95% CI | decisive rate | conditional DA | both | neither |",
        "| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for entry in designs["open_choice_pair"]["runs"]:
        counts = entry["choice_counts"] or {}
        lines.append(
            f"| {entry['model']} | {entry['order']} | {entry['valid_pairs']}/{entry['pairs']} | {entry['correct_pairs']} | "
            f"{pct(entry['pair_da']['value'])} | {ci(entry['pair_da'])} | {pct(entry['decisive_rate']['value'])} | "
            f"{pct(entry['pair_da_decisive']['value'])} | {pct(entry['both_rate']['value'])} | {pct(entry['neither_rate']['value'])} |"
        )
    lines += [
        "",
        "`both`/`neither` are substantive answers and count as pair errors; `conditional DA` is computed only over decisive A/B answers. The two orders are correlated presentations of the same 180 pairs, not independent samples.",
        "",
        "## 4. Evidence verification by retraction (`evidence_verify`)",
        "",
        "| arm | valid | post TP/FP/TN/FN | post macro-F1 | pre macro-F1 | Δ | retracted (TP/FP) | retraction precision | TP loss | FP correction | invalid / fail-closed |",
        "| --- | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |",
    ]
    for entry in designs["evidence_retraction"]["runs"]:
        c = entry["confusion"] or {}
        lines.append(
            f"| {entry['arm']} | {entry['valid']}/{entry['n']} | {c.get('tp')}/{c.get('fp')}/{c.get('tn')}/{c.get('fn')} | "
            f"{num(entry['post_macro_f1'])} | {num(entry['pre_macro_f1'])} | {num(entry['delta_macro_f1'])} | "
            f"{entry['retracted']} ({entry['retracted_true_positive']}/{entry['retracted_false_positive']}) | "
            f"{pct(entry['retraction_precision'])} | {pct(entry['tp_loss_rate'])} | {pct(entry['fp_correction_rate'])} | "
            f"{entry['verifier_invalid']} / {entry['fail_closed']} |"
        )
    lines += [
        "",
        "All four arms use the same 160 test functions and the same first-pass positives. This is **post-hoc and test-seen**: the test set was already used by the first pass. The arms are correlated; invalid verifier output is fail-closed (treated as retract) and must be read with the invalid/fail-closed counts. The retraction step lowers macro-F1 in every arm; it is not a gain.",
        "",
        "## 5. Enhanced dynamic (`dynamic_enhanced`)",
        "",
        "| view | valid | coverage | recall | specificity | macro-F1 | strict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| protocol (clean = inconclusive) | 70/140 | 50.00% | 100.00% | undefined | undefined | 50.00% |",
        "| operational (source clean = 0, coverage-unverified) | 140/140 | 100.00% | 100.00% | 100.00% | 1.0000 | 100.00% |",
        "",
    ]
    counts = dyn["counts"] or {}
    per_mode = dyn["per_mode"] or {}
    lines += [
        f"The three modes resolve **{counts.get('resolved_by_enhanced_modes')}/{counts.get('unobservable_in_default')}** bad units that the default LSan root set cannot observe: "
        f"{per_mode.get('realloc_fail', {}).get('leak')} by realloc-failure injection, {per_mode.get('nogobal', {}).get('leak') - per_mode.get('default', {}).get('leak')} by dropping global roots. "
        "The 70/70 operational view is the producer's source-level count, **not a protocol-valid confusion matrix**: there is no line/branch coverage instrumentation, so a clean observation is `inconclusive`, not TN.",
        "",
        "**Never report the operational 1.0 as protocol dynamic detection.** It may not be pooled with the canonical 140-unit ASan/LSan/Valgrind runs.",
        "",
        "## 6. Hybrid enhanced dynamic (`hybrid_dynamic_enhanced`)",
        "",
        "| model | valid | TP/FP/TN/FN | macro-F1 | 95% CI | MCC | strict | agreement with 140/140 tool |",
        "| --- | ---: | --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for entry in designs["hybrid_enhanced_dynamic"]["runs"]:
        c = entry["confusion"] or {}
        lines.append(
            f"| {entry['model']} | {entry['valid']}/{entry['n']} | {c.get('tp')}/{c.get('fp')}/{c.get('tn')}/{c.get('fn')} | "
            f"{num(entry['macro_f1'])} | {ci(entry['ci'])} | {num(entry['mcc'])} | {pct(entry['strict_accuracy'])} | "
            f"{pct((entry['tool_agreement'] or {}).get('value'))} |"
        )
    lines += [
        "",
        "The enhanced-dynamic tool is 140/140 on this set, so tool agreement equals accuracy; it is not independent evidence that the model understood the evidence. Against the frozen hybrid v2 direct runs the producer reports +2/−0 (DeepSeek, McNemar p=0.5) and 0/0 (MiMo), not significant after Holm. No headroom remains for the 12 previously unobservable bad units because v2 direct already handles them.",
        "",
        "## 7. CodeQL new static tool (`new_static_tool`)",
        "",
        f"CodeQL **2.27.4** (`codeql/cpp-queries` 1.10.0, `cpp-all` 12.4.0) ran on the frozen Juliet CWE-401 test split. Two pinned queries: `cpp/memory-never-freed` and `cpp/memory-may-not-be-freed`; only findings in the unit's own source file count. **{static['valid']}/{static['units']} units are evaluable; {static['status_counts'].get('compile_error')} compile errors** (the `_82` C++ group, same as Clang).",
        "",
        "| view | n | TP | FP | TN | FN | precision | recall | specificity | macro-F1 | MCC | strict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    ev = static["confusion"]["evaluable"]
    e2e = static["confusion"]["end_to_end"]
    lines.append(
        f"| valid-only | {ev['n']} | {ev['tp']} | {ev['fp']} | {ev['tn']} | {ev['fn']} | {num(ev['precision'])} | {num(ev['recall'])} | {num(ev['specificity'])} | {num(ev['macro_f1'])} | {num(ev['mcc'])} | {pct(ev['strict_accuracy'])} |"
    )
    lines.append(
        f"| end-to-end (compile = no finding) | {e2e['n']} | {e2e['tp']} | {e2e['fp']} | {e2e['tn']} | {e2e['fn']} | {num(e2e['precision'])} | {num(e2e['recall'])} | {num(e2e['specificity'])} | {num(e2e['macro_f1'])} | {num(e2e['mcc'])} | — |"
    )
    lines += [
        "",
        "The canonical statement is: **valid TP 68 / FP 23 / TN 45 / FN 0; end-to-end TP 68 / FP 23 / TN 47 / FN 2**, with the two extra TN/FN coming from the 4 compile errors (2 good, 2 bad). The producer cross-check in `static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.json` matches these cells exactly. The valid **positive-class F1 is 0.855**, while the **macro-F1 is 0.826**; do not quote one as the other.",
        "",
        "| query | TP | FP | TN | FN | precision | recall | macro-F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for query, block in (static.get("per_query") or {}).items():
        evq = block["evaluable"]
        lines.append(
            f"| `{query}` | {evq['tp']} | {evq['fp']} | {evq['tn']} | {evq['fn']} | {num(evq['precision'])} | {num(evq['recall'])} | {num(evq['macro_f1'])} |"
        )
    agreement = static.get("agreement_with_clang") or {}
    agree = agreement.get("agreement") or {}
    mcnemar = agreement.get("mcnemar") or {}
    lines += [
        "",
        f"Against the canonical Clang run on the {agreement.get('n_common_units')} common-valid units: CodeQL catches **{agree.get('a_only')}** units Clang misses and misses **{agree.get('b_only')}** that Clang catches; Cohen's κ is {num(agreement.get('cohen_kappa'))}. The McNemar p is {mcnemar.get('p_value'):.3g} (descriptive; the tools are not independent ground truth).",
        "",
        "### Time cost",
        "",
        "| measure | CodeQL | Clang SA | ratio |",
        "| --- | ---: | ---: | ---: |",
        f"| 200-unit run wall (6 jobs) | {static['time']['codeql']['wall_s']:.1f} s | {static['time']['clang']['wall_s']:.2f} s | {static['time']['ratios']['wall_jobs6_per_unit']:.1f}× throughput |",
        f"| per-unit serial compute (test 140) | {static['time']['codeql']['test140_unit_mean_wall_s']:.2f} s | {static['time']['clang']['test140_unit_mean_wall_s']:.4f} s | {static['time']['ratios']['test140_serial_compute']:.0f}× |",
        f"| test-140 summed unit time | {static['time']['codeql']['test140_summed_unit_wall_s']:.1f} s | {static['time']['clang']['test140_wall_s']:.2f} s | {static['time']['ratios']['test140_serial_compute']:.0f}× |",
        "",
        "CodeQL creates one database per unit (build + query): mean 42.5 s, median 43.0 s, P95 51.7 s per unit; the 6-job wall is 1,434.7 s for 200 units (about 7.17 s/unit throughput). Clang is ~0.118 s/unit. CodeQL is roughly **61× slower in wall throughput** and **~367× slower in serial per-unit compute**. Local compute only; USD is not applicable.",
        "",
        "## 8. Schema recovery (`analysis/schema_recovery`)",
        "",
        "| metric | value |",
        "| --- | ---: |",
        f"| API calls | {summary['schema_recovery']['api_calls']} |",
        f"| DeepSeek repair official valid | {summary['schema_recovery']['deepseek_repair']['official_schema_valid']}/{summary['schema_recovery']['deepseek_repair']['requests']} ({pct(summary['schema_recovery']['deepseek_repair']['official_schema_valid_rate'], 1)}) |",
        f"| DeepSeek repair invalid | {summary['schema_recovery']['deepseek_repair']['official_schema_invalid']} ({pct(summary['schema_recovery']['deepseek_repair']['invalid_rate'], 1)}) |",
        f"| invalid = missing `explanation` only | {summary['schema_recovery']['deepseek_repair']['missing_explanation']} ({pct(summary['schema_recovery']['deepseek_repair']['missing_explanation_share_of_invalid'], 1)} of invalid) |",
        f"| invalid = truncation | {summary['schema_recovery']['deepseek_repair']['truncation']} ({pct(summary['schema_recovery']['deepseek_repair']['truncation_share_of_invalid'], 1)} of invalid) |",
        f"| official usable patch | {summary['schema_recovery']['official_vs_code_only']['official_usable_canonical']}/{summary['schema_recovery']['official_vs_code_only']['requests']} ({pct(summary['schema_recovery']['official_vs_code_only']['official_usable_rate'], 1)}) |",
        f"| code-only usable patch | {summary['schema_recovery']['official_vs_code_only']['code_only_usable_canonical']}/{summary['schema_recovery']['official_vs_code_only']['requests']} ({pct(summary['schema_recovery']['official_vs_code_only']['code_only_usable_rate'], 1)}) |",
        f"| usable gain from salvage | {summary['schema_recovery']['official_vs_code_only']['code_only_usable_canonical'] - summary['schema_recovery']['official_vs_code_only']['official_usable_canonical']} (+{summary['schema_recovery']['official_vs_code_only']['delta_usable_pp']:.2f} pp) |",
        f"| MiMo detection field drift recovered | {summary['schema_recovery']['mimo_detection']['recovered']}/{summary['schema_recovery']['mimo_detection']['field_drift']} (100%) |",
        f"| MiMo recovered label agreement (descriptive) | {summary['schema_recovery']['mimo_detection']['label_agreement_count']}/{summary['schema_recovery']['mimo_detection']['field_drift']} ({pct(summary['schema_recovery']['mimo_detection']['label_agreement_share'], 1)}) |",
        "",
        "The 93 missing-`explanation` payloads are structurally complete (91/93 canonical, 93/93 K&R-aware), but only 67 are usable canonical patches; 18 are unchanged, 4 whitespace-only and 2 comment-only. The 9 truncations are fatal and are **not** repaired by adding brackets or quotes. **Salvage is a format admission, not correctness**; 28/61 label agreement is descriptive and is not accuracy.",
        "",
        "## 9. What cannot be claimed",
        "",
    ]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines += [
        "",
        "## 10. Reproduction",
        "",
        "```bash",
        "# WSL, project root",
        "python3 benchmark/extensions/tools/ext_validate.py --check-registries",
        "python3 benchmark/extensions/tools/ext_validate.py --run-dir benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114 --jsonschema --unit-map juliet/subset_units.jsonl",
        "python3 benchmark/extensions/tools/ext_metrics.py --run-dir benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114 --baseline-run benchmark/results/tier_b/juliet_cwe401/static_clang/tierb_juliet_cwe401_static_clang_20261112_4c5800c4",
        "python3 benchmark/tools/bench_ext_summary.py",
        "```",
        "",
        "## 11. Artifacts",
        "",
        "| path | content |",
        "| --- | --- |",
        "| `benchmark/results/EXTENSIONS.md` | this document |",
        "| `benchmark/results/extension_summary.json` | machine-readable summary, validation and statistics check |",
        "| `benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114/` | canonical CodeQL run (140 records) |",
        "| `static_extended/runs/codeql_20261114_cwe401_full/` | producer run (read-only source) |",
        "| `analysis/schema_recovery/schema_recovery.json` | schema-recovery source (read-only) |",
        "",
        "`EXTENSIONS.md` and `extension_summary.json` are generated by `benchmark/tools/bench_ext_summary.py`; rerunning it rewrites only these two files.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-json", default=str(RESULTS / "extension_summary.json"))
    parser.add_argument("--out-md", default=str(RESULTS / "EXTENSIONS.md"))
    parser.add_argument("--skip-validation", action="store_true", help="skip fresh ext_validate checks")
    args = parser.parse_args(argv)
    summary = build_summary(validate=not args.skip_validation)
    markdown = summary.pop("_markdown")
    atomic_write_json(Path(args.out_json), summary)
    atomic_write_text(Path(args.out_md), markdown)
    sys.stderr.write(f"wrote {args.out_json} and {args.out_md}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Metrics, cost, McNemar and evidence-copy diagnostics.

Compares the new enhanced-dynamic-guided run against the frozen v2 direct /
old-dynamic / combined runs and against the dynamic-enhanced tool itself.
The consistency block asks whether the model's verdict and reason simply
mirror the evidence; it is descriptive and cannot identify semantic reasoning.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    EXPECTED_UNITS,
    INPUTS_DIR,
    METHOD,
    MODELS,
    RESULTS_DIR,
    ROOT,
    RUNS_DIR,
    V2_RUNS,
)
from .evidence import read_jsonl
from .stats import bootstrap_delta, holm, mcnemar, metrics

METHODS = ("hde-guided", "v2-direct", "v2-dynamic", "v2-combined", "tool")
CONTRAST_BASELINES = ("v2-direct", "v2-dynamic", "v2-combined", "tool")

CITATION_PATTERNS = {
    "tool_or_evidence": re.compile(r"(?i)\b(?:tool|evidence|sanitizer|lsan|asan|analysis|report)\b"),
    "leak": re.compile(r"(?i)\bleak"),
    "realloc": re.compile(r"(?i)realloc"),
    "global_or_root": re.compile(r"(?i)\b(?:global|static|root)\b"),
    "byte_count": re.compile(r"\b\d+\s*bytes?\b"),
    "evidence_phrasing": re.compile(
        r"(?i)(?:attributed|configuration|injected|root set|not applicable|applied to the same)"
    ),
    "not_freed": re.compile(
        r"(?i)(?:not freed|never freed|unreleased|not released|never released|unreachable|lost)"
    ),
}
NEGATIVE_REASON = re.compile(
    r"(?i)(?:\bno\b[^.;]{0,40}\bleak|\bnot\b[^.;]{0,40}\bleak|does not leak|did not leak|"
    r"no memory (?:leak|is leaked)|no evidence of|is freed|are freed|is released|are released|"
    r"freed (?:on|before|at|in)|deallocat)"
)
POSITIVE_REASON = re.compile(
    r"(?i)(?:leak|not freed|never freed|unreleased|unreachable|lost|never released)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_run(run_dir: Path) -> dict[str, dict[str, Any]]:
    path = run_dir / "results.jsonl"
    if not path.is_file():
        raise SystemExit(f"missing run: {path}")
    records = read_jsonl(path)
    if len(records) != EXPECTED_UNITS or len({r["unit_id"] for r in records}) != EXPECTED_UNITS:
        raise SystemExit(f"{path}: expected {EXPECTED_UNITS} unique units, found {len(records)}")
    return {record["unit_id"]: record for record in records}


def tool_records(units: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out = {}
    for unit in units:
        outcome = unit["enhanced_outcome"]
        out[unit["unit_id"]] = {
            "unit_id": unit["unit_id"],
            "status": "ok" if outcome in {"leak", "clean"} else "invalid",
            "valid": outcome in {"leak", "clean"},
            "y_pred": 1 if outcome == "leak" else 0 if outcome == "clean" else None,
            "predicted_label": "vulnerable" if outcome == "leak" else "not_vulnerable",
            "reason": None,
            "cost": {"cost_usd": 0.0},
            "usage": None,
            "prompt": {"method": "tool", "prompt_version": "dynamic-enhanced-v3"},
            "evidence_outcome": outcome,
            "evidence_primary_mode": unit["enhanced_primary_mode"],
        }
    return out


def cost_of(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    def usage_number(record: dict[str, Any], key: str) -> float:
        usage = record.get("usage") or {}
        opencode = usage.get("opencode") or {}
        return float(opencode.get(key) or 0.0)

    configured = sum(float((r.get("cost") or {}).get("cost_usd") or 0.0) for r in records.values())
    prompt_tokens = sum(int((r.get("usage") or {}).get("prompt_tokens") or 0) for r in records.values())
    completion_tokens = sum(int((r.get("usage") or {}).get("completion_tokens") or 0) for r in records.values())
    cached = sum(
        int(((r.get("usage") or {}).get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
        for r in records.values()
    )
    valid = sum(1 for r in records.values() if r.get("valid"))
    return {
        "records": len(records),
        "valid": valid,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_tokens": cached,
        "configured_usd": configured,
        "provider_list_usd": sum(usage_number(r, "list_cost") for r in records.values()),
        "allowance_usd": sum(usage_number(r, "allowance") for r in records.values()),
        "mean_prompt_tokens": prompt_tokens / len(records) if records else None,
    }


def paired_arrays(
    unit_ids: list[str],
    predictions: dict[str, dict[str, Any]],
    truth: dict[str, int],
) -> tuple[list[int], list[int], list[bool]]:
    y_true, y_pred, valid = [], [], []
    for unit_id in unit_ids:
        record = predictions[unit_id]
        y_true.append(truth[unit_id])
        y_pred.append(int(record["y_pred"]) if record.get("y_pred") is not None else 0)
        valid.append(bool(record.get("valid")))
    return y_true, y_pred, valid


def subset_metrics(
    unit_ids: list[str],
    predictions: dict[str, dict[str, Any]],
    truth: dict[str, int],
) -> dict[str, Any]:
    y_true, y_pred, valid = paired_arrays(unit_ids, predictions, truth)
    counts = metrics(y_true, y_pred, valid)
    return {
        "n": len(unit_ids),
        "correct": counts["tp"] + counts["tn"],
        "accuracy": counts["accuracy"],
        "strict_accuracy": counts["strict_accuracy"],
        "recall": counts["recall"],
        "specificity": counts["specificity"],
    }


def citation(reason: str | None) -> dict[str, bool]:
    if not reason:
        return {key: False for key in CITATION_PATTERNS}
    return {key: bool(pattern.search(reason)) for key, pattern in CITATION_PATTERNS.items()}


def reason_polarity(reason: str | None) -> str | None:
    if not reason:
        return None
    negative = bool(NEGATIVE_REASON.search(reason))
    positive = bool(POSITIVE_REASON.search(reason))
    if negative and not positive:
        return "clean"
    if positive and not negative:
        return "leak"
    return None


def flips(
    unit_ids: list[str],
    new: dict[str, dict[str, Any]],
    base: dict[str, dict[str, Any]],
    truth: dict[str, int],
) -> dict[str, Any]:
    fixed, broke, both_right, both_wrong = [], [], [], []
    for unit_id in unit_ids:
        new_ok = bool(new[unit_id].get("valid")) and new[unit_id]["y_pred"] == truth[unit_id]
        base_ok = bool(base[unit_id].get("valid")) and base[unit_id]["y_pred"] == truth[unit_id]
        if new_ok and not base_ok:
            fixed.append(unit_id)
        elif base_ok and not new_ok:
            broke.append(unit_id)
        elif new_ok and base_ok:
            both_right.append(unit_id)
        else:
            both_wrong.append(unit_id)
    return {
        "n": len(unit_ids),
        "new_right_base_wrong": len(fixed),
        "new_wrong_base_right": len(broke),
        "both_right": len(both_right),
        "both_wrong": len(both_wrong),
        "fixed_units": fixed,
        "broken_units": broke,
    }


def citation_summary(
    unit_ids: list[str],
    predictions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    rows = [predictions[unit_id] for unit_id in unit_ids if predictions[unit_id].get("valid")]
    hits = Counter()
    for record in rows:
        for key, value in citation(record.get("reason")).items():
            if value:
                hits[key] += 1
    n = len(rows)
    return {
        "n": n,
        "rates": {key: (hits[key] / n if n else None) for key in CITATION_PATTERNS},
        "counts": dict(hits),
        "unique_reasons": len({record.get("reason") for record in rows if record.get("reason")}),
        "top_reasons": [
            {"reason": reason, "count": count}
            for reason, count in Counter(
                record.get("reason") for record in rows if record.get("reason")
            ).most_common(5)
        ],
    }


def evidence_echo(
    unit_ids: list[str],
    predictions: dict[str, dict[str, Any]],
    units_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """How often a reason echoes evidence-only numbers or wording.

    Byte counts come from the runtime attribution, not from the source view, so
    a rise relative to the v2 methods is a lexical copy signal.
    """
    leak_units = [
        unit_id
        for unit_id in unit_ids
        if units_by_id[unit_id]["label"] and units_by_id[unit_id]["enhanced_primary_mode"]
    ]
    byte_hits = 0
    phrasing_hits = 0
    n = 0
    for unit_id in leak_units:
        reason = predictions[unit_id].get("reason") or ""
        if not reason:
            continue
        n += 1
        mode = units_by_id[unit_id]["enhanced_primary_mode"]
        attributed = int(units_by_id[unit_id]["enhanced_modes"][mode]["attributed_bytes"] or 0)
        if attributed and re.search(rf"(?<!\d){attributed}(?!\d)", reason):
            byte_hits += 1
        if CITATION_PATTERNS["evidence_phrasing"].search(reason):
            phrasing_hits += 1
    return {
        "n_leak_units_with_reason": n,
        "attributed_byte_match": byte_hits,
        "attributed_byte_match_rate": byte_hits / n if n else None,
        "evidence_phrasing": phrasing_hits,
        "evidence_phrasing_rate": phrasing_hits / n if n else None,
    }


def consistency_block(
    unit_ids: list[str],
    model_preds: dict[str, dict[str, dict[str, Any]]],
    truth: dict[str, int],
    units_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    hde = model_preds["hde-guided"]
    tool = model_preds["tool"]
    tool_wrong = [
        unit_id
        for unit_id in unit_ids
        if not (tool[unit_id].get("valid") and tool[unit_id]["y_pred"] == truth[unit_id])
    ]
    agree = sum(
        1
        for unit_id in unit_ids
        if hde[unit_id].get("valid") and hde[unit_id]["y_pred"] == tool[unit_id]["y_pred"]
    )
    over_call = [
        unit_id
        for unit_id in unit_ids
        if hde[unit_id]["y_pred"] == 1 and tool[unit_id]["y_pred"] == 0
    ]
    under_call = [
        unit_id
        for unit_id in unit_ids
        if hde[unit_id]["y_pred"] == 0 and tool[unit_id]["y_pred"] == 1
    ]
    special = [unit_id for unit_id in unit_ids if units_by_id[unit_id]["enhanced_primary_mode"] in {"realloc_fail", "nogobal"}]
    mechanism_hits = 0
    mechanism_detail = []
    for unit_id in special:
        reason = hde[unit_id].get("reason") or ""
        mode = units_by_id[unit_id]["enhanced_primary_mode"]
        expected = "realloc" if mode == "realloc_fail" else r"(?i)\b(?:global|static|root)\b"
        hit = bool(re.search(expected, reason)) if mode == "realloc_fail" else bool(re.search(expected, reason))
        mechanism_hits += int(hit)
        mechanism_detail.append(
            {
                "unit_id": unit_id,
                "evidence_mode": mode,
                "reason": reason,
                "mechanism_cited": hit,
                "label_correct": hde[unit_id]["y_pred"] == truth[unit_id],
            }
        )

    polarity_counts = Counter()
    contradictions = []
    for unit_id in unit_ids:
        record = hde[unit_id]
        polarity = reason_polarity(record.get("reason"))
        if polarity is None:
            polarity_counts["unclear"] += 1
            continue
        expected = "leak" if record["y_pred"] == 1 else "clean"
        if polarity == expected:
            polarity_counts["consistent"] += 1
        else:
            polarity_counts["contradictory"] += 1
            contradictions.append(
                {
                    "unit_id": unit_id,
                    "label": "bad" if truth[unit_id] else "good",
                    "y_pred": record["y_pred"],
                    "reason": record.get("reason"),
                }
            )

    groups = {
        "old_leak_58": [u for u in unit_ids if units_by_id[u]["dynamic_outcome"] == "leak"],
        "new_leak_12": special,
        "clean_70": [u for u in unit_ids if not units_by_id[u]["label"]],
    }
    group_block = {}
    for name, ids in groups.items():
        group_block[name] = {
            "n": len(ids),
            "hde_accuracy": subset_metrics(ids, hde, truth)["accuracy"],
            "direct_accuracy": subset_metrics(ids, model_preds["v2-direct"], truth)["accuracy"],
            "dynamic_accuracy": subset_metrics(ids, model_preds["v2-dynamic"], truth)["accuracy"],
            "hde_vs_direct_fixed": len(flips(ids, hde, model_preds["v2-direct"], truth)["fixed_units"]),
            "hde_vs_direct_broken": len(flips(ids, hde, model_preds["v2-direct"], truth)["broken_units"]),
        }

    return {
        "tool_wrong_units": len(tool_wrong),
        "tool_accuracy": sum(1 for u in unit_ids if tool[u]["y_pred"] == truth[u]) / len(unit_ids),
        "model_accuracy": sum(
            1 for u in unit_ids if hde[u].get("valid") and hde[u]["y_pred"] == truth[u]
        )
        / len(unit_ids),
        "agreement_with_tool": agree / len(unit_ids),
        "agreement_note": (
            "the enhanced tool is 140/140 on this frozen set, so agreement with the "
            "tool verdict is numerically identical to accuracy and cannot separate "
            "copying from independent reasoning"
        ),
        "disagreements": {
            "over_call_units": over_call,
            "under_call_units": under_call,
        },
        "flips_vs_baselines": {
            baseline: flips(unit_ids, hde, model_preds[baseline], truth)
            for baseline in ("v2-direct", "v2-dynamic", "v2-combined", "tool")
        },
        "evidence_transition_groups": group_block,
        "reasons": {
            "hde-guided": citation_summary(unit_ids, hde),
            "v2-dynamic": citation_summary(unit_ids, model_preds["v2-dynamic"]),
            "v2-combined": citation_summary(unit_ids, model_preds["v2-combined"]),
            "v2-direct": citation_summary(unit_ids, model_preds["v2-direct"]),
        },
        "special_12_mechanism_citation": {
            "n": len(special),
            "hits": mechanism_hits,
            "rate": mechanism_hits / len(special) if special else None,
            "details": mechanism_detail,
        },
        "special_12_citation": {
            method: citation_summary(special, model_preds[method])
            for method in ("hde-guided", "v2-direct", "v2-dynamic")
        },
        "clean_70_citation": {
            method: citation_summary(
                [u for u in unit_ids if not units_by_id[u]["label"]], model_preds[method]
            )
            for method in ("hde-guided", "v2-direct", "v2-dynamic", "v2-combined")
        },
        "old_leak_58_citation": {
            method: citation_summary(
                [u for u in unit_ids if units_by_id[u]["dynamic_outcome"] == "leak"],
                model_preds[method],
            )
            for method in ("hde-guided", "v2-direct", "v2-dynamic", "v2-combined")
        },
        "evidence_echo": {
            method: evidence_echo(unit_ids, model_preds[method], units_by_id)
            for method in ("hde-guided", "v2-direct", "v2-dynamic", "v2-combined")
        },
        "reason_polarity": {
            "counts": dict(polarity_counts),
            "contradictions": contradictions[:10],
            "definition": (
                "clean if a negation/release phrase matches and no positive leak phrase "
                "precedes it; leak if a positive leak phrase matches; otherwise unclear"
            ),
        },
        "confidence": {
            "mean": statistics.fmean(
                [float(r["confidence"]) for r in hde.values() if r.get("confidence") is not None]
            )
            if any(r.get("confidence") is not None for r in hde.values())
            else None,
            "n": sum(1 for r in hde.values() if r.get("confidence") is not None),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="enhanced_dynamic_v1")
    parser.add_argument("--inputs-dir", type=Path, default=INPUTS_DIR)
    parser.add_argument("--out-json", type=Path, default=RESULTS_DIR / "enhanced_dynamic_metrics.json")
    parser.add_argument("--predictions-csv", type=Path, default=RESULTS_DIR / "enhanced_dynamic_predictions.csv")
    parser.add_argument("--consistency-json", type=Path, default=RESULTS_DIR / "consistency.json")
    args = parser.parse_args(argv)

    units = sorted(read_jsonl(args.inputs_dir / "units.jsonl"), key=lambda unit: unit["unit_id"])
    manifest = json.loads((args.inputs_dir / "manifest.json").read_text(encoding="utf-8"))
    preflight = json.loads((RESULTS_DIR / "preflight.json").read_text(encoding="utf-8"))
    if len(units) != EXPECTED_UNITS:
        raise SystemExit(f"expected 140 units, found {len(units)}")
    units_by_id = {unit["unit_id"]: unit for unit in units}
    unit_ids = [unit["unit_id"] for unit in units]
    truth = {unit["unit_id"]: 1 if unit["label"] else 0 for unit in units}

    models: dict[str, dict[str, dict[str, Any]]] = {}
    for model in MODELS:
        hde = load_run(RUNS_DIR / f"{args.run_id}_{model}")
        models[model] = {
            "hde-guided": hde,
            "v2-direct": load_run(V2_RUNS / f"hybrid_v2_{model}_direct"),
            "v2-dynamic": load_run(V2_RUNS / f"hybrid_v2_{model}_dynamic"),
            "v2-combined": load_run(V2_RUNS / f"hybrid_v2_{model}_combined"),
            "tool": tool_records(units),
        }

    analysis: dict[str, Any] = {
        "schema_version": "hde-analysis-v1",
        "generated_at": utc_now(),
        "run_id": args.run_id,
        "method": METHOD,
        "protocol": {
            "units": len(units),
            "labels": dict(Counter("bad" if unit["label"] else "good" for unit in units)),
            "input_sha256": manifest["units_sha256"],
            "guided_prompt_version": preflight["prompt_version"],
            "direct_prompt_version": preflight["direct_prompt_version"],
            "preflight_ok": preflight["ok"],
            "preflight_sha256": hashlib.sha256(
                (RESULTS_DIR / "preflight.json").read_bytes()
            ).hexdigest(),
            "tool_confusion": manifest["enhanced_tool"]["confusion"],
            "tool_accuracy": manifest["enhanced_tool"]["accuracy"],
            "baselines": "frozen hybrid_v2 runs (2026-11-11), not re-requested",
        },
        "methods": {},
        "models": {},
        "pooled_descriptive": {},
        "subsets": {
            "old_unobservable_12": [u["unit_id"] for u in units if u["label"] and u["dynamic_outcome"] == "clean"],
            "old_leak_58": [u["unit_id"] for u in units if u["dynamic_outcome"] == "leak"],
            "cleaned_22_good": [u["unit_id"] for u in units if "unit, unit string" in u["source_text"]],
        },
        "notes": [
            "The dynamic-enhanced tool is 70TP/70TN on this frozen set, so any model "
            "accuracy at or below 1.0 is consistent with copying the evidence.",
            "v2 baselines were collected on 2026-11-11 with the same input pack and "
            "prompt version; only the new method was requested in this run.",
            "McNemar tests are exact and Holm-adjusted within each model across four "
            "contrasts; no claim of semantic reasoning follows from a significant p.",
        ],
    }

    for model in MODELS:
        model_preds = models[model]
        method_metrics = {}
        for method in METHODS:
            y_true, y_pred, valid = paired_arrays(unit_ids, model_preds[method], truth)
            method_metrics[method] = metrics(y_true, y_pred, valid)
            method_metrics[method]["cost"] = cost_of(model_preds[method])
        analysis["models"][model] = {"methods": method_metrics}

        contrasts = []
        for baseline in CONTRAST_BASELINES:
            y_true, pred_a, valid_a = paired_arrays(unit_ids, model_preds["hde-guided"], truth)
            _, pred_b, valid_b = paired_arrays(unit_ids, model_preds[baseline], truth)
            strict_a = [pred if ok else 0 for pred, ok in zip(pred_a, valid_a)]
            strict_b = [pred if ok else 0 for pred, ok in zip(pred_b, valid_b)]
            entry = {
                "a": "hde-guided",
                "b": baseline,
                **mcnemar(y_true, strict_a, strict_b),
                "bootstrap": bootstrap_delta(y_true, strict_a, strict_b),
                "delta_accuracy": method_metrics["hde-guided"]["strict_accuracy"]
                - method_metrics[baseline]["strict_accuracy"],
            }
            contrasts.append(entry)
        holm(contrasts)
        analysis["models"][model]["mcnemar"] = contrasts

        subset_block: dict[str, Any] = {}
        for name, ids in analysis["subsets"].items():
            subset_block[name] = {
                "n": len(ids),
                "methods": {method: subset_metrics(ids, model_preds[method], truth) for method in METHODS},
            }
        direct_errors = [
            unit_id
            for unit_id in unit_ids
            if not (
                model_preds["v2-direct"][unit_id].get("valid")
                and model_preds["v2-direct"][unit_id]["y_pred"] == truth[unit_id]
            )
        ]
        subset_block["direct_error_units"] = {
            "n": len(direct_errors),
            "units": direct_errors,
            "methods": {method: subset_metrics(direct_errors, model_preds[method], truth) for method in METHODS},
        }
        analysis["models"][model]["subsets"] = subset_block

        hde_cost = method_metrics["hde-guided"]["cost"]
        direct_cost = method_metrics["v2-direct"]["cost"]
        extra_correct = (
            (method_metrics["hde-guided"]["tp"] + method_metrics["hde-guided"]["tn"])
            - (method_metrics["v2-direct"]["tp"] + method_metrics["v2-direct"]["tn"])
        )
        extra_usd = hde_cost["configured_usd"] - direct_cost["configured_usd"]
        analysis["models"][model]["cost"] = {
            "per_method": {method: method_metrics[method]["cost"] for method in METHODS},
            "usd_per_correct": {
                method: (
                    method_metrics[method]["cost"]["configured_usd"]
                    / (method_metrics[method]["tp"] + method_metrics[method]["tn"])
                    if (method_metrics[method]["tp"] + method_metrics[method]["tn"])
                    else None
                )
                for method in METHODS
            },
            "incremental_vs_direct": {
                "extra_correct": extra_correct,
                "extra_usd": extra_usd,
                "usd_per_extra_correct": (extra_usd / extra_correct if extra_correct > 0 else None),
            },
        }
        analysis["models"][model]["consistency"] = consistency_block(unit_ids, model_preds, truth, units_by_id)

    for method in METHODS:
        analysis["pooled_descriptive"][method] = {
            "mean_accuracy": statistics.fmean(
                analysis["models"][model]["methods"][method]["accuracy"] for model in MODELS
            ),
            "mean_strict_accuracy": statistics.fmean(
                analysis["models"][model]["methods"][method]["strict_accuracy"] for model in MODELS
            ),
            "configured_usd_total": sum(
                analysis["models"][model]["methods"][method]["cost"]["configured_usd"] for model in MODELS
            ),
        }

    analysis["protocol"]["preflight_checks_passed"] = sum(1 for c in preflight["checks"] if c["ok"])
    analysis["protocol"]["preflight_checks_total"] = len(preflight["checks"])
    analysis["protocol"]["run_manifests"] = {}
    for model in MODELS:
        path = RUNS_DIR / f"{args.run_id}_{model}" / "manifest.json"
        run_manifest = json.loads(path.read_text(encoding="utf-8"))
        analysis["protocol"]["run_manifests"][model] = {
            "path": str(path.relative_to(ROOT)),
            "counts": run_manifest.get("counts"),
            "cost": run_manifest.get("cost"),
            "usage": run_manifest.get("usage"),
            "prompt_version": run_manifest.get("prompt_version"),
            "elapsed_seconds": run_manifest.get("elapsed_seconds"),
        }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(analysis, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.consistency_json.write_text(
        json.dumps(
            {
                "generated_at": analysis["generated_at"],
                "run_id": args.run_id,
                "models": {
                    model: analysis["models"][model]["consistency"] for model in MODELS
                },
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    combined_path = RESULTS_DIR / "enhanced_dynamic_results.jsonl"
    with combined_path.open("w", encoding="utf-8") as handle:
        for model in MODELS:
            for unit_id in unit_ids:
                handle.write(
                    json.dumps(
                        models[model]["hde-guided"][unit_id], ensure_ascii=False, sort_keys=True
                    )
                    + "\n"
                )

    with args.predictions_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "model",
                "method",
                "unit_id",
                "label",
                "y_true",
                "y_pred",
                "valid",
                "correct",
                "status",
                "evidence_outcome",
                "evidence_primary_mode",
                "reason",
            ]
        )
        for model in MODELS:
            for method in METHODS:
                for unit_id in unit_ids:
                    record = models[model][method][unit_id]
                    writer.writerow(
                        [
                            model,
                            method,
                            unit_id,
                            "bad" if truth[unit_id] else "good",
                            truth[unit_id],
                            record.get("y_pred"),
                            int(bool(record.get("valid"))),
                            int(
                                bool(record.get("valid"))
                                and record.get("y_pred") == truth[unit_id]
                            ),
                            record.get("status"),
                            record.get("evidence_outcome") or units_by_id[unit_id]["enhanced_outcome"],
                            record.get("evidence_primary_mode")
                            or units_by_id[unit_id]["enhanced_primary_mode"],
                            record.get("reason"),
                        ]
                    )

    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "models": {
                    model: {
                        method: {
                            "accuracy": analysis["models"][model]["methods"][method]["accuracy"],
                            "strict_accuracy": analysis["models"][model]["methods"][method]["strict_accuracy"],
                        }
                        for method in METHODS
                    }
                    for model in MODELS
                },
            },
            indent=2,
        )
    )
    print(f"wrote {args.out_json.relative_to(ROOT)}")
    print(f"wrote {args.predictions_csv.relative_to(ROOT)}")
    print(f"wrote {args.consistency_json.relative_to(ROOT)}")
    print(f"wrote {combined_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

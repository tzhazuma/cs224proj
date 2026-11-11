"""Metrics and paired statistics for the hybrid evidence experiment.

Strict metrics score every planned unit; an invalid or failed request is
counted as wrong (never as a correct negative).  Valid-only metrics are also
reported, always next to coverage, so the two views cannot be confused.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
MODELS = ("deepseek", "mimo")
METHODS = ("direct", "static", "dynamic", "combined", "shuffled")
BOOTSTRAP_REPS = 10000
SEED = 20261112
Z95 = 1.959963984540054


def wilson(k: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denominator = 1 + Z95 * Z95 / n
    centre = (p + Z95 * Z95 / (2 * n)) / denominator
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95 * Z95 / (4 * n * n)) / denominator
    return [max(0.0, centre - half), min(1.0, centre + half)]


def confusion(y_true: list[int], y_pred: list[int]) -> dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    counts = confusion(y_true, y_pred)
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = len(y_true)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0
    )
    accuracy = (tp + tn) / total if total else None
    balanced = (
        (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None
    )
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denominator if denominator else 0.0
    return {
        "n": total,
        **counts,
        "accuracy": accuracy,
        "accuracy_ci95": wilson(tp + tn, total) if total else None,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "balanced_accuracy": balanced,
        "mcc": mcc,
        "predicted_positive_rate": (tp + fp) / total if total else None,
    }


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def mcnemar(y_true: list[int], pred_a: list[int], pred_b: list[int]) -> dict[str, Any]:
    assert len(y_true) == len(pred_a) == len(pred_b)
    a_right_b_wrong = 0
    a_wrong_b_right = 0
    for truth, a, b in zip(y_true, pred_a, pred_b):
        ra, rb = a == truth, b == truth
        if ra and not rb:
            a_right_b_wrong += 1
        elif rb and not ra:
            a_wrong_b_right += 1
    n = a_right_b_wrong + a_wrong_b_right
    if n == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(n, k) for k in range(0, min(a_right_b_wrong, a_wrong_b_right) + 1))
        p_value = min(1.0, 2.0 * tail / (2**n))
    return {
        "a_right_b_wrong": a_right_b_wrong,
        "a_wrong_b_right": a_wrong_b_right,
        "discordant": n,
        "p_value_exact": p_value,
    }


def paired_bootstrap(
    y_true: list[int], pred_a: list[int], pred_b: list[int], reps: int = BOOTSTRAP_REPS
) -> dict[str, Any]:
    rng = random.Random(SEED)
    n = len(y_true)
    differences: list[float] = []
    acc_a_values: list[float] = []
    acc_b_values: list[float] = []
    for _ in range(reps):
        indexes = [rng.randrange(n) for _ in range(n)]
        truth = [y_true[i] for i in indexes]
        a = [pred_a[i] for i in indexes]
        b = [pred_b[i] for i in indexes]
        acc_a = sum(1 for t, p in zip(truth, a) if t == p) / n
        acc_b = sum(1 for t, p in zip(truth, b) if t == p) / n
        differences.append(acc_a - acc_b)
        acc_a_values.append(acc_a)
        acc_b_values.append(acc_b)
    observed_a = sum(1 for t, p in zip(y_true, pred_a) if t == p) / n
    observed_b = sum(1 for t, p in zip(y_true, pred_b) if t == p) / n
    return {
        "difference": observed_a - observed_b,
        "ci95": [percentile(differences, 0.025), percentile(differences, 0.975)],
        "p_two_sided_bootstrap": min(
            1.0, 2.0 * min(
                sum(1 for value in differences if value <= 0) / reps,
                sum(1 for value in differences if value >= 0) / reps,
            )
        ),
        "reps": reps,
        "seed": SEED,
    }


def summarize_run(records: list[dict[str, Any]], unit_meta: dict[str, dict[str, Any]]) -> dict[str, Any]:
    truth = [r["y_true"] for r in records]
    strict = [r["y_pred"] if r["valid"] else 1 - r["y_true"] for r in records]
    valid_pairs = [(r["y_true"], r["y_pred"]) for r in records if r["valid"]]
    latencies = [r["latency_seconds"] for r in records if r.get("latency_seconds") is not None]
    costs = [
        r["cost"]["cost_usd"]
        for r in records
        if isinstance(r.get("cost"), dict) and r["cost"].get("cost_usd") is not None
    ]
    prompt_tokens = sum(
        int(r["usage"].get("prompt_tokens", 0) or 0) for r in records if r.get("usage")
    )
    completion_tokens = sum(
        int(r["usage"].get("completion_tokens", 0) or 0) for r in records if r.get("usage")
    )
    cached_tokens = sum(
        int(r["cost"].get("cached_prompt_tokens", 0) or 0)
        for r in records
        if isinstance(r.get("cost"), dict)
    )
    reasoning_tokens = sum(
        int((r.get("response_meta") or {}).get("reasoning_tokens", 0) or 0)
        for r in records
    )
    allowances = []
    for record in records:
        usage = record.get("usage") or {}
        opencode = usage.get("opencode") if isinstance(usage, dict) else None
        if isinstance(opencode, dict) and isinstance(opencode.get("allowance"), (int, float)):
            allowances.append(float(opencode["allowance"]))
    by_language: dict[str, Any] = {}
    for language in ("c", "cpp"):
        subset = [r for r in records if r["language"] == language]
        if subset:
            by_language[language] = metrics(
                [r["y_true"] for r in subset],
                [r["y_pred"] if r["valid"] else 1 - r["y_true"] for r in subset],
            )
    evidence_groups: dict[str, Any] = {}
    if records and records[0]["method"] in {"dynamic", "combined"}:
        for outcome in ("leak", "clean", "inconclusive"):
            subset = [r for r in records if r.get("dynamic_outcome") == outcome]
            if subset:
                evidence_groups[outcome] = metrics(
                    [r["y_true"] for r in subset],
                    [r["y_pred"] if r["valid"] else 1 - r["y_true"] for r in subset],
                )
                evidence_groups[outcome]["n_units"] = len(subset)
                evidence_groups[outcome]["predicted_vulnerable"] = sum(
                    1 for r in subset if r["valid"] and r["y_pred"] == 1
                )
    if records and records[0]["method"] == "shuffled":
        donor_labels = [
            bool(unit_meta[unit_meta[r["unit_id"]]["placebo_donor_unit"]]["label"])
            for r in records
            if r["unit_id"] in unit_meta
        ]
        for donor_bad in (True, False):
            subset = [
                r
                for r, donor_bad_value in zip(records, donor_labels)
                if donor_bad_value == donor_bad
            ]
            if subset:
                key = "donor_bad" if donor_bad else "donor_good"
                evidence_groups[key] = metrics(
                    [r["y_true"] for r in subset],
                    [r["y_pred"] if r["valid"] else 1 - r["y_true"] for r in subset],
                )
                evidence_groups[key]["n_units"] = len(subset)
    return {
        "n_total": len(records),
        "n_valid": len(valid_pairs),
        "n_invalid": sum(1 for r in records if r["status"] == "invalid"),
        "n_api_error": sum(1 for r in records if r["status"] == "api_error"),
        "coverage": len(valid_pairs) / len(records) if records else 0.0,
        "strict": metrics(truth, strict),
        "valid_only": metrics([t for t, _ in valid_pairs], [p for _, p in valid_pairs]),
        "by_language": by_language,
        "evidence_groups": evidence_groups,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cached_prompt_tokens": cached_tokens,
            "reasoning_tokens": reasoning_tokens,
            "cost_usd_sum": sum(costs) if costs else 0.0,
            "provider_allowance_usd_sum": sum(allowances) if allowances else None,
            "allowance_records": len(allowances),
            "cost_records": len(costs),
            "mean_cost_usd": sum(costs) / len(costs) if costs else None,
        },
        "latency_seconds": {
            "mean": statistics.fmean(latencies) if latencies else None,
            "p50": percentile(latencies, 0.5),
            "p95": percentile(latencies, 0.95),
            "max": max(latencies) if latencies else None,
        },
    }


def load_run(run_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    with (run_dir / "results.jsonl").open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            latest[record["unit_id"]] = record
    records = [latest[key] for key in sorted(latest)]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    return records, manifest


def tool_metrics(units: list[dict[str, Any]], key: str) -> dict[str, Any]:
    truth = [1 if unit["label"] else 0 for unit in units]
    if key == "dynamic":
        pred = []
        for unit in units:
            outcome = unit["dynamic_outcome"]
            pred.append(1 if outcome == "leak" else 0)
        return metrics(truth, pred)
    if key == "static":
        pred = []
        for unit in units:
            clang = unit["static_findings"]["clang"][1]
            cppcheck = unit["static_findings"]["cppcheck"][1]
            pred.append(1 if (clang + cppcheck) > 0 else 0)
        return metrics(truth, pred)
    raise ValueError(key)


def fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        if math.isnan(value):
            return "n/a"
        return f"{value:.{digits}f}"
    return str(value)


def pct(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{100 * value:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, default=HYBRID / "runs")
    parser.add_argument("--run-id", default="hybrid_v2")
    parser.add_argument("--inputs-dir", type=Path, default=HYBRID / "inputs_v2")
    parser.add_argument("--out", type=Path, default=HYBRID / "results")
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    args.inputs_dir = args.inputs_dir.resolve()
    args.runs_root = args.runs_root.resolve()

    units = [
        json.loads(line)
        for line in (args.inputs_dir / "units.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    unit_meta = {unit["unit_id"]: unit for unit in units}
    input_manifest = json.loads(
        (args.inputs_dir / "manifest.json").read_text(encoding="utf-8")
    )

    runs: dict[tuple[str, str], dict[str, Any]] = {}
    prediction_rows: list[dict[str, Any]] = []
    for model in MODELS:
        for method in METHODS:
            run_dir = args.runs_root / f"{args.run_id}_{model}_{method}"
            if not (run_dir / "results.jsonl").is_file():
                continue
            records, manifest = load_run(run_dir)
            summary = summarize_run(records, unit_meta)
            summary["manifest"] = manifest
            summary["run_dir"] = str(run_dir.relative_to(ROOT))
            summary["records"] = {
                record["unit_id"]: {
                    "y_true": record["y_true"],
                    "y_pred": record["y_pred"],
                    "valid": record["valid"],
                }
                for record in records
            }
            runs[(model, method)] = summary
            for record in records:
                usage = record.get("usage") or {}
                opencode = usage.get("opencode") if isinstance(usage, dict) else None
                allowance = opencode.get("allowance") if isinstance(opencode, dict) else None
                prediction_rows.append(
                    {
                        "model": model,
                        "method": method,
                        "unit_id": record["unit_id"],
                        "group_id": record["group_id"],
                        "language": record["language"],
                        "label": record["label"],
                        "predicted_label": record["predicted_label"],
                        "y_true": record["y_true"],
                        "y_pred": record["y_pred"],
                        "status": record["status"],
                        "valid": record["valid"],
                        "confidence": record["confidence"],
                        "cost_usd": (record.get("cost") or {}).get("cost_usd"),
                        "provider_allowance_usd": allowance,
                        "latency_seconds": record.get("latency_seconds"),
                        "dynamic_outcome": record.get("dynamic_outcome"),
                        "placebo_donor_unit": record.get("placebo_donor_unit"),
                        "reason": record.get("reason"),
                    }
                )
            per_run = {
                "run_id": manifest["run_id"],
                "model": model,
                "method": method,
                "n_total": summary["n_total"],
                "n_valid": summary["n_valid"],
                "coverage": summary["coverage"],
                "strict": summary["strict"],
                "valid_only": summary["valid_only"],
                "by_language": summary["by_language"],
                "evidence_groups": summary["evidence_groups"],
                "usage": summary["usage"],
                "latency_seconds": summary["latency_seconds"],
            }
            (run_dir / "metrics.json").write_text(
                json.dumps(per_run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )

    comparisons: list[dict[str, Any]] = []
    for model in MODELS:
        available = [m for m in METHODS if (model, m) in runs]
        for baseline in available:
            for other in available:
                if baseline == other:
                    continue
                base = runs[(model, baseline)]
                comp = runs[(model, other)]
                common = sorted(set(base["records"]) & set(comp["records"]))
                truth = [base["records"][u]["y_true"] for u in common]
                pred_base = [
                    base["records"][u]["y_pred"]
                    if base["records"][u]["valid"]
                    else 1 - base["records"][u]["y_true"]
                    for u in common
                ]
                pred_other = [
                    comp["records"][u]["y_pred"]
                    if comp["records"][u]["valid"]
                    else 1 - comp["records"][u]["y_true"]
                    for u in common
                ]
                test = mcnemar(truth, pred_other, pred_base)
                boot = paired_bootstrap(truth, pred_other, pred_base)
                comparisons.append(
                    {
                        "model": model,
                        "baseline": baseline,
                        "method": other,
                        "n_pairs": len(common),
                        "baseline_accuracy": sum(
                            1 for t, p in zip(truth, pred_base) if t == p
                        ) / len(common),
                        "method_accuracy": sum(
                            1 for t, p in zip(truth, pred_other) if t == p
                        ) / len(common),
                        "accuracy_difference": boot["difference"],
                        "accuracy_difference_ci95": boot["ci95"],
                        "mcnemar": test,
                        "bootstrap": boot,
                    }
                )

    cross_model: list[dict[str, Any]] = []
    for method in METHODS:
        if ("deepseek", method) not in runs or ("mimo", method) not in runs:
            continue
        left = runs[("deepseek", method)]
        right = runs[("mimo", method)]
        common = sorted(set(left["records"]) & set(right["records"]))
        truth = [left["records"][u]["y_true"] for u in common]
        pred_left = [
            left["records"][u]["y_pred"]
            if left["records"][u]["valid"]
            else 1 - left["records"][u]["y_true"]
            for u in common
        ]
        pred_right = [
            right["records"][u]["y_pred"]
            if right["records"][u]["valid"]
            else 1 - right["records"][u]["y_true"]
            for u in common
        ]
        test = mcnemar(truth, pred_left, pred_right)
        boot = paired_bootstrap(truth, pred_left, pred_right)
        cross_model.append(
            {
                "method": method,
                "n_pairs": len(common),
                "deepseek_accuracy": sum(1 for t, p in zip(truth, pred_left) if t == p)
                / len(common),
                "mimo_accuracy": sum(1 for t, p in zip(truth, pred_right) if t == p)
                / len(common),
                "accuracy_difference": boot["difference"],
                "accuracy_difference_ci95": boot["ci95"],
                "mcnemar": test,
            }
        )

    payload = {
        "schema_version": "hybrid-analysis-v2",
        "run_id": args.run_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_manifest": input_manifest,
        "runs": {
            f"{model}/{method}": {
                key: value for key, value in summary.items() if key != "records"
            }
            for (model, method), summary in runs.items()
        },
        "comparisons": comparisons,
        "cross_model": cross_model,
        "tools": {
            "dynamic": tool_metrics(units, "dynamic"),
            "static_any": tool_metrics(units, "static"),
        },
    }
    (args.out / f"{args.run_id}_metrics.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    fieldnames = [
        "model",
        "method",
        "unit_id",
        "group_id",
        "language",
        "label",
        "predicted_label",
        "y_true",
        "y_pred",
        "status",
        "valid",
        "confidence",
        "cost_usd",
        "provider_allowance_usd",
        "latency_seconds",
        "dynamic_outcome",
        "placebo_donor_unit",
        "reason",
    ]
    with (args.out / f"{args.run_id}_predictions.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(prediction_rows)

    lines = [
        "# Hybrid evidence-guidance results",
        "",
        f"Generated {payload['generated_at_utc']}.",
        "",
        f"Frozen test units: {input_manifest['unit_count']} "
        f"({input_manifest['label_counts']}).",
        "",
        "## Per-run metrics",
        "",
        "| Model | Method | Valid | Coverage | Acc (strict) | Precision | Recall | F1 | Balanced | List USD | Allowance USD | p95 s |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for (model, method), summary in runs.items():
        strict = summary["strict"]
        lines.append(
            f"| {model} | {method} | {summary['n_valid']}/{summary['n_total']} | "
            f"{pct(summary['coverage'])} | {pct(strict['accuracy'])} | "
            f"{pct(strict['precision'])} | {pct(strict['recall'])} | {fmt(strict['f1'])} | "
            f"{pct(strict['balanced_accuracy'])} | {fmt(summary['usage']['cost_usd_sum'], 6)} | "
            f"{fmt(summary['usage']['provider_allowance_usd_sum'], 6)} | "
            f"{fmt(summary['latency_seconds']['p95'], 2)} |"
        )
    lines += ["", "## Paired comparisons (strict scoring, exact McNemar)", ""]
    lines.append("| Model | Baseline | Method | n | Acc base | Acc method | Diff | 95% CI | p |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: |")
    for item in comparisons:
        ci = item["accuracy_difference_ci95"]
        lines.append(
            f"| {item['model']} | {item['baseline']} | {item['method']} | {item['n_pairs']} | "
            f"{pct(item['baseline_accuracy'])} | {pct(item['method_accuracy'])} | "
            f"{item['accuracy_difference']:+.4f} | "
            f"[{ci[0]:+.4f}, {ci[1]:+.4f}] | {item['mcnemar']['p_value_exact']:.4g} |"
        )
    lines += ["", "## Tool evidence vs labels", ""]
    for name, values in payload["tools"].items():
        lines.append(
            f"- {name}: accuracy {pct(values['accuracy'])}, precision {pct(values['precision'])}, "
            f"recall {pct(values['recall'])}, specificity {pct(values['specificity'])}."
        )
    lines += ["", "## Dynamic-evidence conditioned results", ""]
    for (model, method), summary in runs.items():
        if method not in {"dynamic", "combined"}:
            continue
        groups = summary["evidence_groups"]
        parts = []
        for outcome in ("leak", "clean", "inconclusive"):
            if outcome in groups:
                groups[outcome]["n_units"] = groups[outcome].get("n_units", groups[outcome]["n"])
                parts.append(
                    f"{outcome}: n={groups[outcome]['n_units']}, "
                    f"pred-vuln={groups[outcome]['predicted_positive_rate']:.2f}, "
                    f"acc={groups[outcome]['accuracy']:.2f}"
                )
        lines.append(f"- {model}/{method}: " + "; ".join(parts))
    lines += ["", "## Placebo diagnostics", ""]
    for (model, method), summary in runs.items():
        if method != "shuffled":
            continue
        parts = [
            f"{key}: n={value['n_units']}, acc={value['accuracy']:.2f}"
            for key, value in summary["evidence_groups"].items()
        ]
        lines.append(f"- {model}/shuffled by donor label: " + "; ".join(parts))
    (args.out / f"{args.run_id}_tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

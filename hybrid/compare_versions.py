"""Compare the frozen hybrid v1 runs with the leak-fixed hybrid v2 runs.

Both versions use the same 140 test units, the same frozen tool evidence and
the same seed-20261112 placebo; only the source views (and therefore the
prompts) changed.  This script reports per-run accuracy movement, exact
McNemar tests on the paired unit outcomes, the units whose prediction flipped,
and the six units whose cleaned source actually changed.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent

import sys

if str(HYBRID) not in sys.path:
    sys.path.insert(0, str(HYBRID))

from analyze import METHODS, MODELS, mcnemar, paired_bootstrap, pct  # noqa: E402


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_run(run_dir: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(run_dir / "results.jsonl"):
        latest[record["unit_id"]] = record
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    return latest, manifest


def strict_pred(record: dict[str, Any]) -> int:
    return record["y_pred"] if record["valid"] else 1 - record["y_true"]


def usage_totals(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    prompt = sum(int((r.get("usage") or {}).get("prompt_tokens", 0) or 0) for r in records.values())
    completion = sum(
        int((r.get("usage") or {}).get("completion_tokens", 0) or 0) for r in records.values()
    )
    costs = [
        float((r.get("cost") or {}).get("cost_usd"))
        for r in records.values()
        if isinstance((r.get("cost") or {}).get("cost_usd"), (int, float))
    ]
    allowances = []
    for r in records.values():
        opencode = (r.get("usage") or {}).get("opencode") if isinstance(r.get("usage"), dict) else None
        if isinstance(opencode, dict) and isinstance(opencode.get("allowance"), (int, float)):
            allowances.append(float(opencode["allowance"]))
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "list_cost_usd": sum(costs) if costs else None,
        "allowance_usd": sum(allowances) if allowances else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, default=HYBRID / "runs")
    parser.add_argument("--v1-run-id", default="hybrid_v1")
    parser.add_argument("--v2-run-id", default="hybrid_v2")
    parser.add_argument("--v1-inputs", type=Path, default=HYBRID / "inputs")
    parser.add_argument("--v2-inputs", type=Path, default=HYBRID / "inputs_v2")
    parser.add_argument("--out-dir", type=Path, default=HYBRID / "results")
    args = parser.parse_args()
    args.runs_root = args.runs_root.resolve()
    args.v1_inputs = args.v1_inputs.resolve()
    args.v2_inputs = args.v2_inputs.resolve()
    args.out_dir = args.out_dir.resolve()

    v1_units = {u["unit_id"]: u for u in read_jsonl(args.v1_inputs / "units.jsonl")}
    v2_units = {u["unit_id"]: u for u in read_jsonl(args.v2_inputs / "units.jsonl")}
    v1_manifest = json.loads((args.v1_inputs / "manifest.json").read_text(encoding="utf-8"))
    v2_manifest = json.loads((args.v2_inputs / "manifest.json").read_text(encoding="utf-8"))
    common_units = sorted(set(v1_units) & set(v2_units))
    changed_units = sorted(
        unit_id
        for unit_id in common_units
        if v1_units[unit_id]["source_text"] != v2_units[unit_id]["source_text"]
    )

    rows: list[dict[str, Any]] = []
    flips: list[dict[str, Any]] = []
    for model in MODELS:
        for method in METHODS:
            v1_dir = args.runs_root / f"{args.v1_run_id}_{model}_{method}"
            v2_dir = args.runs_root / f"{args.v2_run_id}_{model}_{method}"
            if not (v1_dir / "results.jsonl").is_file() or not (v2_dir / "results.jsonl").is_file():
                continue
            v1, v1_run_manifest = load_run(v1_dir)
            v2, v2_run_manifest = load_run(v2_dir)
            ids = sorted(set(v1) & set(v2))
            truth = [v1[u]["y_true"] for u in ids]
            pred_v1 = [strict_pred(v1[u]) for u in ids]
            pred_v2 = [strict_pred(v2[u]) for u in ids]
            correct_v1 = sum(1 for t, p in zip(truth, pred_v1) if t == p)
            correct_v2 = sum(1 for t, p in zip(truth, pred_v2) if t == p)
            test = mcnemar(truth, pred_v2, pred_v1)
            boot = paired_bootstrap(truth, pred_v2, pred_v1)
            row = {
                "model": model,
                "method": method,
                "n": len(ids),
                "v1_accuracy": correct_v1 / len(ids),
                "v2_accuracy": correct_v2 / len(ids),
                "delta": (correct_v2 - correct_v1) / len(ids),
                "delta_ci95": boot["ci95"],
                "v1_correct": correct_v1,
                "v2_correct": correct_v2,
                "mcnemar": test,
                "v1_valid": sum(1 for r in v1.values() if r["valid"]),
                "v2_valid": sum(1 for r in v2.values() if r["valid"]),
                "v1_right_v2_wrong": test["a_wrong_b_right"],
                "v1_wrong_v2_right": test["a_right_b_wrong"],
                "v1_usage": usage_totals(v1),
                "v2_usage": usage_totals(v2),
                "v1_prompt_version": v1_run_manifest.get("prompt_version"),
                "v2_prompt_version": v2_run_manifest.get("prompt_version"),
            }
            rows.append(row)
            for unit_id in ids:
                a, b = v1[unit_id], v2[unit_id]
                if strict_pred(a) != strict_pred(b):
                    flips.append(
                        {
                            "model": model,
                            "method": method,
                            "unit_id": unit_id,
                            "label": "bad" if a["y_true"] else "good",
                            "v1_predicted_label": a["predicted_label"],
                            "v2_predicted_label": b["predicted_label"],
                            "v1_correct": strict_pred(a) == a["y_true"],
                            "v2_correct": strict_pred(b) == b["y_true"],
                            "source_changed": unit_id in changed_units,
                        }
                    )

    pooled = []
    for model in MODELS:
        subset = [row for row in rows if row["model"] == model]
        if not subset:
            continue
        pooled.append(
            {
                "model": model,
                "runs": len(subset),
                "v1_accuracy": sum(row["v1_correct"] for row in subset)
                / sum(row["n"] for row in subset),
                "v2_accuracy": sum(row["v2_correct"] for row in subset)
                / sum(row["n"] for row in subset),
            }
        )
    if rows:
        pooled.append(
            {
                "model": "all",
                "runs": len(rows),
                "v1_accuracy": sum(row["v1_correct"] for row in rows)
                / sum(row["n"] for row in rows),
                "v2_accuracy": sum(row["v2_correct"] for row in rows)
                / sum(row["n"] for row in rows),
            }
        )
    for item in pooled:
        item["delta"] = item["v2_accuracy"] - item["v1_accuracy"]

    payload = {
        "schema_version": "hybrid-version-compare-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "v1_run_id": args.v1_run_id,
        "v2_run_id": args.v2_run_id,
        "v1_units_sha256": v1_manifest.get("units_sha256"),
        "v2_units_sha256": v2_manifest.get("units_sha256"),
        "changed_source_units": changed_units,
        "changed_source_count": len(changed_units),
        "rows": rows,
        "pooled": pooled,
        "flips": flips,
        "flip_counts": {
            "v1_right_v2_wrong": sum(
                1 for item in flips if item["v1_correct"] and not item["v2_correct"]
            ),
            "v1_wrong_v2_right": sum(
                1 for item in flips if not item["v1_correct"] and item["v2_correct"]
            ),
        },
    }

    lines = [
        "# Hybrid v1 vs v2 (leak-fixed sources)",
        "",
        f"Generated {payload['generated_at_utc']}.",
        "",
        f"- v1 input pack: `{args.v1_inputs.relative_to(ROOT)}`  ",
        f"  sha256 `{payload['v1_units_sha256']}`",
        f"- v2 input pack: `{args.v2_inputs.relative_to(ROOT)}`  ",
        f"  sha256 `{payload['v2_units_sha256']}`",
        f"- Source views changed in {len(changed_units)}/140 units: "
        + ", ".join(f"`{unit_id}`" for unit_id in changed_units),
        "",
        "## Per-run accuracy",
        "",
        "| Model | Method | n | v1 acc | v2 acc | Δ (v2−v1) | 95% CI | v1 right / v2 wrong | v1 wrong / v2 right | McNemar p |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        ci = row["delta_ci95"]
        lines.append(
            f"| {row['model']} | {row['method']} | {row['n']} | {pct(row['v1_accuracy'])} | "
            f"{pct(row['v2_accuracy'])} | {100 * row['delta']:+.2f} pp | "
            f"[{100 * ci[0]:+.2f}, {100 * ci[1]:+.2f}] pp | "
            f"{row['v1_right_v2_wrong']} | {row['v1_wrong_v2_right']} | "
            f"{row['mcnemar']['p_value_exact']:.4g} |"
        )
    lines += [
        "",
        "## Pooled descriptive accuracy",
        "",
        "| Model | Runs | v1 acc | v2 acc | Δ |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for item in pooled:
        lines.append(
            f"| {item['model']} | {item['runs']} | {pct(item['v1_accuracy'])} | "
            f"{pct(item['v2_accuracy'])} | {100 * item['delta']:+.2f} pp |"
        )
    lines += [
        "",
        "## Prediction flips",
        "",
        f"- v1 right → v2 wrong: {payload['flip_counts']['v1_right_v2_wrong']}",
        f"- v1 wrong → v2 right: {payload['flip_counts']['v1_wrong_v2_right']}",
        "",
        "| Model | Method | Unit | Label | v1 | v2 | v1 correct | v2 correct | Source changed |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in sorted(
        flips, key=lambda x: (x["model"], x["method"], x["unit_id"])
    )[:80]:
        lines.append(
            f"| {item['model']} | {item['method']} | `{item['unit_id']}` | {item['label']} | "
            f"{item['v1_predicted_label']} | {item['v2_predicted_label']} | "
            f"{'yes' if item['v1_correct'] else 'no'} | "
            f"{'yes' if item['v2_correct'] else 'no'} | "
            f"{'yes' if item['source_changed'] else 'no'} |"
        )
    if len(flips) > 80:
        lines.append(f"| ... | | | | | | | | ({len(flips) - 80} more rows in JSON) |")
    lines += [
        "",
        "## Usage and cost",
        "",
        "| Model | Method | v1 tokens (in/out) | v2 tokens (in/out) | v1 list USD | v2 list USD | v1 allowance USD | v2 allowance USD |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        u1, u2 = row["v1_usage"], row["v2_usage"]
        a1 = "n/a" if u1["allowance_usd"] is None else f"{u1['allowance_usd']:.6f}"
        a2 = "n/a" if u2["allowance_usd"] is None else f"{u2['allowance_usd']:.6f}"
        lines.append(
            f"| {row['model']} | {row['method']} | {u1['prompt_tokens']}/{u1['completion_tokens']} | "
            f"{u2['prompt_tokens']}/{u2['completion_tokens']} | "
            f"{u1['list_cost_usd']:.6f} | {u2['list_cost_usd']:.6f} | {a1} | {a2} |"
        )
    lines += [
        "",
        "DeepSeek v1 rows were priced at the old 2× list price ($0.30/$1.20); v2 uses the",
        "provider snapshot ($0.15/$0.60), so DeepSeek list-cost movement is not a workload change.",
        "Provider allowance is unaffected by the configured list price and is the comparable figure.",
        "MiMo v2 rows also show substantially more prompt-cache reads than v1 (e.g. 72,512 vs",
        "15,616 cached tokens in the static run), so its list cost drops without a workload change.",
        "",
    ]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f"{args.v2_run_id}_vs_{args.v1_run_id}.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (args.out_dir / f"{args.v2_run_id}_vs_{args.v1_run_id}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

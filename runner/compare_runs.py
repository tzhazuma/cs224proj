#!/usr/bin/env python3
"""Build a side-by-side table from completed SecVulEval run metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence


def _load_metrics(path: Path) -> dict[str, Any]:
    metrics_path = path / "metrics.json" if path.is_dir() else path
    if not metrics_path.exists():
        raise ValueError(f"metrics.json not found: {metrics_path}")
    value = json.loads(metrics_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"unsupported metrics schema in {metrics_path}")
    return value


def _fmt_rate(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{float(value):.4f}"
    return "n/a"


def _fmt_cost(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"${float(value):.6f}"
    return "null"


def _row(metrics: dict[str, Any]) -> dict[str, Any]:
    run = metrics.get("run", {})
    counts = metrics.get("counts", {})
    detection = metrics.get("detection") or {}
    valid = (detection.get("metrics_valid_only") or {}) if detection else {}
    pair = metrics.get("pair_joint") or {}
    repair = metrics.get("repair") or {}
    cost = metrics.get("cost", {})
    latency = metrics.get("latency", {})
    return {
        "run_id": run.get("run_id"),
        "dataset": run.get("dataset_type"),
        "strategy": run.get("strategy"),
        "task": run.get("task"),
        "model": run.get("model"),
        "partial": bool(run.get("partial")),
        "records": counts.get("records"),
        "expected": counts.get("expected_requests"),
        "detection_valid": detection.get("valid_predictions") if detection else None,
        "detection_errors": (
            (detection.get("schema_invalid", 0) + detection.get("api_errors", 0))
            if detection
            else None
        ),
        "precision": valid.get("precision"),
        "recall": valid.get("recall"),
        "f1": valid.get("f1"),
        "pair_discrimination_valid": pair.get("discrimination_accuracy_valid_pairs"),
        "pair_discrimination_all": pair.get("discrimination_accuracy_all_pairs"),
        "repair_schema_valid": repair.get("schema_valid"),
        "repair_complete": repair.get("complete_function"),
        "repair_requested": repair.get("requested"),
        "total_cost_usd": cost.get("total_cost_usd"),
        "p95_latency_seconds": latency.get("p95_request_latency_seconds"),
    }


def render(rows: list[dict[str, Any]], warnings: list[str]) -> str:
    lines = ["# SecVulEval run comparison", ""]
    if warnings:
        for warning in warnings:
            lines.append(f"> **Warning:** {warning}")
        lines.append("")
    lines.append(
        "| Run | Dataset | Strategy | Task | Model | Records | Det. valid | Precision | Recall | F1 | Pair disc. (valid) | Repair complete / valid | Cost USD | p95 latency (s) |"
    )
    lines.append("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in rows:
        partial = " (partial)" if row["partial"] else ""
        records = f"{row['records']}/{row['expected']}" if row["expected"] is not None else row["records"]
        repair = (
            f"{row['repair_complete']}/{row['repair_schema_valid']}"
            if row["repair_schema_valid"] is not None
            else "n/a"
        )
        lines.append(
            "| {run}{partial} | {dataset} | {strategy} | {task} | {model} | {records} | {dv} | {p} | {r} | {f} | {pair} | {repair} | {cost} | {lat} |".format(
                run=row["run_id"],
                partial=partial,
                dataset=row["dataset"],
                strategy=row["strategy"],
                task=row["task"],
                model=row["model"],
                records=records,
                dv="n/a" if row["detection_valid"] is None else row["detection_valid"],
                p=_fmt_rate(row["precision"]),
                r=_fmt_rate(row["recall"]),
                f=_fmt_rate(row["f1"]),
                pair=_fmt_rate(row["pair_discrimination_valid"]),
                repair=repair,
                cost=_fmt_cost(row["total_cost_usd"]),
                lat=_fmt_rate(row["p95_latency_seconds"]),
            )
        )
    lines.append("")
    lines.append(
        "Detection precision/recall/F1 use valid predictions only. `null` cost means prices were "
        "not configured or usage was incomplete. A `(partial)` row used `--limit` and is not a "
        "full-dataset result."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare completed SecVulEval runs.")
    parser.add_argument("runs", nargs="+", type=Path, help="Run directories or metrics.json paths.")
    parser.add_argument("--out", type=Path, default=None, help="Write Markdown here instead of stdout.")
    parser.add_argument("--json-out", type=Path, default=None, help="Also write machine-readable rows.")
    args = parser.parse_args(argv)
    try:
        metrics_list = [_load_metrics(path) for path in args.runs]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    rows = [_row(metrics) for metrics in metrics_list]
    datasets = {row["dataset"] for row in rows}
    tasks = {row["task"] for row in rows}
    warnings: list[str] = []
    if len(datasets) > 1:
        warnings.append("runs use different datasets; rows are not directly comparable")
    if len(tasks) > 1:
        warnings.append("runs use different tasks; blank/n.a. cells reflect that difference")
    if any(row["partial"] for row in rows):
        warnings.append("at least one run is partial (--limit); do not report it as full-dataset evidence")
    markdown = render(rows, warnings)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(markdown, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(markdown)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps({"rows": rows, "warnings": warnings}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

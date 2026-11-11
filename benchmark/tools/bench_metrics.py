#!/usr/bin/env python3
"""Compute unified metrics for one benchmark run.

The output is intentionally split into task blocks (detection, pair,
leak) and a cost block. It never pools tasks or tiers into a single score.
Failures are retained: ``strict_accuracy`` counts non-ok records as wrong,
while valid-only metrics use only ``status == "ok"`` records and are always
reported next to coverage.

Usage:
    python3 benchmark/tools/bench_metrics.py --run-dir <run_dir>
    python3 benchmark/tools/bench_metrics.py --run-dir <run_dir> --force

The script writes ``metrics.json`` and ``metrics.md`` next to the run by
default. It refuses to overwrite an existing metrics file without ``--force``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    DEFAULT_CONFIDENCE,
    METRICS_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    as_bool,
    bootstrap_detection,
    bootstrap_pair,
    cost_summary,
    count_by,
    detection_scores,
    load_run,
    pair_scores,
    sha256_file,
    utc_now,
    atomic_write_json,
    atomic_write_text,
)
from bench_validate import validate_run  # noqa: E402


def _task_records(records: Sequence[Mapping[str, Any]], task: str) -> list[Mapping[str, Any]]:
    return [record for record in records if record.get("task") == task]


def _labels_predictions(
    records: Sequence[Mapping[str, Any]],
) -> tuple[list[bool], list[bool | None], list[str]]:
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    for record in records:
        label = as_bool(record.get("label", {}).get("y_true"))
        if label is None:
            raise ValueError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        if record.get("status") == "ok":
            predictions.append(as_bool(record.get("prediction", {}).get("y_pred")))
        else:
            predictions.append(None)
        clusters.append(str(record.get("cluster_id")))
    return labels, predictions, clusters


def detection_block(
    records: Sequence[Mapping[str, Any]],
    *,
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    labels, predictions, clusters = _labels_predictions(records)
    scores = detection_scores(labels, predictions, confidence=confidence)
    bootstrap = bootstrap_detection(
        labels,
        predictions,
        clusters,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    return {
        "scores": scores,
        "bootstrap": bootstrap.get("metrics", {}),
        "cluster_count": bootstrap.get("cluster_count"),
        "by_status": count_by(str(record.get("status")) for record in records),
        "by_side": count_by(str(record.get("side")) for record in records if record.get("side")),
    }


def _pair_arrays(
    records: Sequence[Mapping[str, Any]],
) -> tuple[list[bool | None], list[bool | None], list[str], dict[str, Any]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = {}
    for record in records:
        group_id = str(record.get("group_id") or "")
        if not group_id:
            raise ValueError(f"{record.get('unit_id')}: pair record missing group_id")
        side = str(record.get("side") or "")
        if side not in ("vulnerable", "fixed"):
            raise ValueError(f"{record.get('unit_id')}: bad pair side {side!r}")
        if side in groups.setdefault(group_id, {}):
            raise ValueError(f"duplicate pair side {group_id}:{side}")
        groups[group_id][side] = record

    vulnerable: list[bool | None] = []
    fixed: list[bool | None] = []
    clusters: list[str] = []
    missing: list[str] = []
    for group_id in sorted(groups):
        sides = groups[group_id]
        cluster = str(next(iter(sides.values())).get("cluster_id") or group_id)
        clusters.append(cluster)
        if set(sides) != {"vulnerable", "fixed"}:
            missing.append(group_id)
            vulnerable.append(None)
            fixed.append(None)
            continue
        v_record = sides["vulnerable"]
        f_record = sides["fixed"]
        vulnerable.append(
            as_bool(v_record.get("prediction", {}).get("y_pred"))
            if v_record.get("status") == "ok"
            else None
        )
        fixed.append(
            as_bool(f_record.get("prediction", {}).get("y_pred"))
            if f_record.get("status") == "ok"
            else None
        )
    metadata = {"groups": groups, "missing": missing}
    return vulnerable, fixed, clusters, metadata


def pair_block(
    records: Sequence[Mapping[str, Any]],
    *,
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    vulnerable, fixed, clusters, metadata = _pair_arrays(records)
    scores = pair_scores(vulnerable, fixed, confidence=confidence)
    bootstrap = bootstrap_pair(
        vulnerable,
        fixed,
        clusters,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    scores["missing_pairs"] = len(metadata["missing"])
    scores["by_status"] = count_by(str(record.get("status")) for record in records)
    scores["bootstrap"] = bootstrap.get("metrics", {})
    scores["cluster_count"] = bootstrap.get("cluster_count")
    return scores


def _coverage_bucket(record: Mapping[str, Any]) -> str:
    coverage = record.get("coverage")
    if not isinstance(coverage, dict):
        return "unknown"
    value = coverage.get("line_coverage")
    if value is None:
        return "unknown"
    value = float(value)
    if value >= 0.9:
        return "ge_0.90"
    if value >= 0.5:
        return "0.50_0.90"
    return "lt_0.50"


def _effective_leak_predictions(
    records: Sequence[Mapping[str, Any]],
    *,
    coverage_threshold: float,
) -> tuple[list[bool], list[bool | None], list[str], int]:
    """Return labels, effective predictions, clusters and coverage-inconclusive count.

    A clean dynamic result on a path with coverage below the threshold is not
    evidence of safety. It is converted to an effective ``None`` so that it is
    excluded from valid-only metrics and counted as an error in strict
    accuracy. A positive leak observation remains positive even at low
    coverage, because the leak was actually observed.
    """

    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    inconclusive = 0
    for record in records:
        label = as_bool(record.get("label", {}).get("y_true"))
        if label is None:
            raise ValueError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        clusters.append(str(record.get("cluster_id")))
        if record.get("status") != "ok":
            predictions.append(None)
            continue
        prediction = as_bool(record.get("prediction", {}).get("y_pred"))
        coverage = record.get("coverage")
        line_coverage = coverage.get("line_coverage") if isinstance(coverage, dict) else None
        if (
            prediction is False
            and line_coverage is not None
            and float(line_coverage) < coverage_threshold
        ):
            predictions.append(None)
            inconclusive += 1
        else:
            predictions.append(prediction)
    return labels, predictions, clusters, inconclusive


def leak_block(
    records: Sequence[Mapping[str, Any]],
    *,
    resamples: int,
    seed: int,
    confidence: float,
    coverage_threshold: float,
) -> dict[str, Any]:
    labels, predictions, clusters, coverage_inconclusive = _effective_leak_predictions(
        records, coverage_threshold=coverage_threshold
    )
    scores = detection_scores(labels, predictions, confidence=confidence)
    bootstrap = bootstrap_detection(
        labels,
        predictions,
        clusters,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )

    strata: dict[str, Any] = {}
    for bucket in ("ge_0.90", "0.50_0.90", "lt_0.50", "unknown"):
        indices = [
            index
            for index, record in enumerate(records)
            if _coverage_bucket(record) == bucket
        ]
        if not indices:
            strata[bucket] = None
            continue
        sub_labels = [labels[i] for i in indices]
        sub_predictions = [predictions[i] for i in indices]
        strata[bucket] = detection_scores(sub_labels, sub_predictions, confidence=confidence)

    oracle_counts: dict[str, int] = {}
    mismatches = 0
    for record in records:
        oracle = record.get("oracle")
        if not isinstance(oracle, dict):
            continue
        consensus = str(oracle.get("dynamic_consensus") or "unknown")
        oracle_counts[consensus] = oracle_counts.get(consensus, 0) + 1
        if oracle.get("mismatch") is True:
            mismatches += 1

    return {
        "detection": {
            "scores": scores,
            "bootstrap": bootstrap.get("metrics", {}),
            "cluster_count": bootstrap.get("cluster_count"),
            "by_status": count_by(str(record.get("status")) for record in records),
            "by_side": count_by(str(record.get("side")) for record in records if record.get("side")),
        },
        "coverage_strata": strata,
        "inconclusive": {
            "count": coverage_inconclusive
            + sum(1 for record in records if record.get("status") == "inconclusive"),
            "coverage_inconclusive": coverage_inconclusive,
            "coverage_threshold": coverage_threshold,
            "policy": "clean prediction below threshold is excluded from valid-only and counted wrong in strict accuracy",
            "strict_treated_as": "error",
        },
        "oracle_consistency": {
            "counts": oracle_counts,
            "mismatches": mismatches,
        },
    }


def _write_markdown(path: Path, metrics: Mapping[str, Any]) -> None:
    lines = [
        f"# Benchmark metrics: `{metrics['run_id']}`",
        "",
        f"- protocol: `{metrics['protocol_version']}`",
        f"- tier / track: `{metrics['tier']}` / `{metrics['track']}`",
        f"- generated: `{metrics['generated_at']}`",
        "",
        "## Counts",
        "",
        "| field | value |",
        "| --- | ---: |",
    ]
    for key, value in metrics["counts"].items():
        lines.append(f"| `{key}` | {value} |")

    tasks = metrics.get("tasks", {})
    if "detection" in tasks:
        block = tasks["detection"]["scores"]
        lines += [
            "",
            "## Detection (valid-only, with strict view)",
            "",
            "| metric | value |",
            "| --- | ---: |",
        ]
        for key in (
            "n",
            "valid",
            "invalid",
            "coverage",
            "precision",
            "recall",
            "specificity",
            "f1",
            "macro_f1",
            "balanced_accuracy",
            "accuracy",
            "strict_accuracy",
            "mcc",
        ):
            lines.append(f"| `{key}` | {_fmt(block.get(key))} |")
        lines += [
            "",
            f"Confusion: `{block.get('confusion')}`",
            "",
        ]

    if "leak_detection" in tasks:
        block = tasks["leak_detection"]
        scores = block["detection"]["scores"]
        lines += [
            "",
            "## Leak detection (CWE-401)",
            "",
            "| metric | value |",
            "| --- | ---: |",
        ]
        for key in (
            "n",
            "valid",
            "invalid",
            "coverage",
            "precision",
            "recall",
            "specificity",
            "f1",
            "macro_f1",
            "mcc",
            "strict_accuracy",
        ):
            lines.append(f"| `{key}` | {_fmt(scores.get(key))} |")
        lines += [
            "",
            f"Coverage-inconclusive records: `{block['inconclusive']['count']}` "
            f"(threshold `{block['inconclusive']['coverage_threshold']}`)",
            "",
            "### Coverage strata",
            "",
            "| stratum | n | valid | recall | specificity | macro_f1 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
        for name, value in block["coverage_strata"].items():
            if value is None:
                lines.append(f"| `{name}` | 0 | 0 | — | — | — |")
            else:
                lines.append(
                    f"| `{name}` | {value['n']} | {value['valid']} | "
                    f"{_fmt(value['recall'])} | {_fmt(value['specificity'])} | "
                    f"{_fmt(value['macro_f1'])} |"
                )

    if "pair_detection" in tasks:
        block = tasks["pair_detection"]
        lines += [
            "",
            "## Pair discrimination",
            "",
            "| metric | value |",
            "| --- | ---: |",
        ]
        for key in (
            "n_pairs",
            "valid_pairs",
            "invalid_pairs",
            "missing_pairs",
            "coverage",
            "joint_accuracy_valid_pairs",
            "joint_accuracy_all_pairs",
            "consistent_rate",
            "swapped_rate",
        ):
            lines.append(f"| `{key}` | {_fmt(block.get(key))} |")
        lines += [
            "",
            f"Joint categories: `{block.get('joint_categories')}`",
            "",
        ]

    cost = metrics.get("cost", {})
    lines += [
        "",
        "## Cost and latency",
        "",
        "| field | value |",
        "| --- | ---: |",
    ]
    for key in (
        "usd_known_sum",
        "usd_unknown_records",
        "usd_complete",
        "wall_s_sum",
        "cpu_s_sum",
        "peak_rss_mb_max",
        "prompt_tokens_sum",
        "completion_tokens_sum",
        "latency_ms_p50",
        "latency_ms_p95",
        "cost_per_100_units_usd",
        "cost_per_true_positive_usd",
        "wall_s_per_100_units",
    ):
        lines.append(f"| `{key}` | {_fmt(cost.get(key))} |")

    lines += [
        "",
        "## Notes",
        "",
        "- Valid-only metrics exclude `status != \"ok\"`; `strict_accuracy` counts those records as wrong.",
        "- Cost is reported as known sum with an explicit unknown-record count; it is not imputed.",
        "- Leak clean predictions below the coverage threshold are treated as inconclusive, not true negatives.",
        "",
    ]
    atomic_write_text(path, "\n".join(lines))


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def compute_run_metrics(
    run_dir: str | Path,
    *,
    resamples: int = DEFAULT_BOOTSTRAP_RESAMPLES,
    seed: int = DEFAULT_BOOTSTRAP_SEED,
    confidence: float = DEFAULT_CONFIDENCE,
    coverage_threshold: float = 0.8,
) -> dict[str, Any]:
    manifest, records, predictions_path = load_run(run_dir)
    tasks: dict[str, Any] = {}
    for task in ("detection", "pair_detection", "leak_detection", "repair"):
        subset = _task_records(records, task)
        if not subset:
            continue
        if task == "detection":
            tasks[task] = detection_block(
                subset, resamples=resamples, seed=seed, confidence=confidence
            )
        elif task == "pair_detection":
            tasks[task] = pair_block(
                subset, resamples=resamples, seed=seed, confidence=confidence
            )
        elif task == "leak_detection":
            tasks[task] = leak_block(
                subset,
                resamples=resamples,
                seed=seed,
                confidence=confidence,
                coverage_threshold=coverage_threshold,
            )
        else:
            tasks[task] = {
                "records": len(subset),
                "by_status": count_by(str(record.get("status")) for record in subset),
                "note": "Repair correctness is outside the v1 detection benchmark; use repair_eval/.",
            }

    planned_units = (manifest.get("execution") or {}).get("planned_units")
    cost = cost_summary(records)
    primary_n = len(records)
    if tasks:
        first = next(iter(tasks.values()))
        if isinstance(first, dict) and isinstance(first.get("scores"), dict):
            primary_n = first["scores"].get("n", primary_n)
        elif isinstance(first, dict) and isinstance(first.get("detection"), dict):
            primary_n = first["detection"]["scores"].get("n", primary_n)
        elif isinstance(first, dict) and isinstance(first.get("n_pairs"), int):
            primary_n = first["n_pairs"]
    if primary_n:
        if cost.get("usd_known_sum") is not None:
            cost["cost_per_100_units_usd"] = cost["usd_known_sum"] / primary_n * 100.0
        if cost.get("wall_s_sum") is not None:
            cost["wall_s_per_100_units"] = cost["wall_s_sum"] / primary_n * 100.0
        true_positives = 0
        detection = tasks.get("detection") or tasks.get("leak_detection") or {}
        scores = detection.get("scores") if isinstance(detection, dict) else None
        if not isinstance(scores, dict) and isinstance(detection, dict):
            nested = detection.get("detection")
            scores = nested.get("scores") if isinstance(nested, dict) else None
        if isinstance(scores, dict):
            true_positives = scores.get("confusion", {}).get("tp", 0)
        if true_positives and cost.get("usd_known_sum") is not None:
            cost["cost_per_true_positive_usd"] = cost["usd_known_sum"] / true_positives
        else:
            cost.setdefault("cost_per_true_positive_usd", None)
    else:
        cost.setdefault("cost_per_100_units_usd", None)
        cost.setdefault("cost_per_true_positive_usd", None)
        cost.setdefault("wall_s_per_100_units", None)

    counts = {
        "records": len(records),
        "planned_units": planned_units if isinstance(planned_units, int) else None,
        "by_task": count_by(str(record.get("task")) for record in records),
        "by_status": count_by(str(record.get("status")) for record in records),
        "missing_units": (
            max(planned_units - len(records), 0) if isinstance(planned_units, int) else None
        ),
    }

    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "run_id": manifest.get("run_id"),
        "protocol_version": manifest.get("protocol_version", PROTOCOL_VERSION),
        "tier": manifest.get("tier"),
        "track": manifest.get("track"),
        "generated_at": utc_now(),
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "record.cluster_id",
            "coverage_threshold": coverage_threshold,
            "strict_policy": "non-ok records count as errors in strict_accuracy; valid-only metrics exclude them",
        },
        "tasks": tasks,
        "cost": cost,
        "counts": counts,
        "provenance": {
            "run_manifest_sha256": sha256_file(Path(run_dir).resolve() / "run_manifest.json"),
            "predictions_sha256": sha256_file(predictions_path),
        },
        "notes": [
            "Tasks and tiers are not pooled into a single score.",
            "Detection and pair metrics use valid predictions only; strict accuracy is separate.",
            "Leak clean predictions below the coverage threshold are inconclusive, not true negatives.",
            "Cost is a known-sum plus unknown count, never an imputed total.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out-dir", help="output directory (default: run directory)")
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    parser.add_argument("--coverage-threshold", type=float, default=0.8)
    parser.add_argument("--force", action="store_true", help="overwrite existing metrics files")
    parser.add_argument(
        "--allow-invalid",
        action="store_true",
        help="compute metrics even if structural validation reports errors",
    )
    args = parser.parse_args(argv)

    report = validate_run(args.run_dir)
    if report["errors"] and not args.allow_invalid:
        sys.stderr.write(
            "refusing to compute metrics: run failed validation\n"
            + "\n".join(f"- {message}" for message in report["errors"][:20])
            + "\n"
        )
        return 2
    if report["warnings"]:
        sys.stderr.write(f"validation warnings: {len(report['warnings'])}\n")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else Path(args.run_dir).resolve()
    metrics_path = out_dir / "metrics.json"
    markdown_path = out_dir / "metrics.md"
    if not args.force and (metrics_path.exists() or markdown_path.exists()):
        sys.stderr.write(
            f"refusing to overwrite {metrics_path} / {markdown_path}; pass --force\n"
        )
        return 2

    metrics = compute_run_metrics(
        args.run_dir,
        resamples=args.bootstrap,
        seed=args.seed,
        coverage_threshold=args.coverage_threshold,
    )
    atomic_write_json(metrics_path, metrics)
    _write_markdown(markdown_path, metrics)
    sys.stderr.write(f"wrote {metrics_path} and {markdown_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

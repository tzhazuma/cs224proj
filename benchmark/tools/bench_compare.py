#!/usr/bin/env python3
"""Paired comparison of two runs on their common evaluation units.

This tool implements the pre-registered paired comparison in
``benchmark/PROTOCOL.md``: align by ``unit_id`` (detection/leak) or
``group_id`` (pair), compute each method on the common-valid cohort, then
report a paired bootstrap interval and an exact McNemar test. It never
pools tasks or invents missing predictions.

Two runs must share the same tier, track, task and dataset SHA-256. This is
intentional: a comparison across different datasets is not a benchmark
comparison.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    as_bool,
    atomic_write_json,
    atomic_write_text,
    cluster_bootstrap,
    cost_summary,
    detection_scores,
    load_run,
    mcnemar_exact,
    pair_scores,
    sha256_file,
    utc_now,
)

COMPARISON_SCHEMA_VERSION = "benchmark-comparison-v1"


def _record_prediction(record: Mapping[str, Any]) -> bool | None:
    if record.get("status") != "ok":
        return None
    return as_bool(record.get("prediction", {}).get("y_pred"))


def _record_label(record: Mapping[str, Any]) -> bool:
    value = as_bool(record.get("label", {}).get("y_true"))
    if value is None:
        raise ValueError(f"{record.get('unit_id')}: non-binary label")
    return value


def _by_unit(records: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for record in records:
        unit_id = str(record.get("unit_id") or "")
        if not unit_id:
            raise ValueError("record without unit_id")
        if unit_id in result:
            raise ValueError(f"duplicate unit_id {unit_id!r}")
        result[unit_id] = record
    return result


def _delta_bootstrap(
    labels: Sequence[bool],
    preds_a: Sequence[bool | None],
    preds_b: Sequence[bool | None],
    clusters: Sequence[str],
    *,
    metric_names: Sequence[str],
    resamples: int,
    seed: int,
) -> dict[str, Any]:
    def metric(indices: Sequence[int], name: str) -> float | None:
        sub_labels = [labels[i] for i in indices]
        a = detection_scores(sub_labels, [preds_a[i] for i in indices]).get(name)
        b = detection_scores(sub_labels, [preds_b[i] for i in indices]).get(name)
        if a is None or b is None:
            return None
        return float(a) - float(b)

    return cluster_bootstrap(
        clusters,
        {f"delta_{name}": (lambda idx, n=name: metric(idx, n)) for name in metric_names},
        resamples=resamples,
        seed=seed,
    )


def _difference(value_a: Any, value_b: Any) -> float | None:
    if value_a is None or value_b is None:
        return None
    return float(value_a) - float(value_b)


def _pair_correctness(
    records: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, bool | None], dict[str, str]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = {}
    for record in records:
        group_id = str(record.get("group_id") or "")
        side = str(record.get("side") or "")
        if not group_id or side not in ("vulnerable", "fixed"):
            raise ValueError(f"{record.get('unit_id')}: malformed pair record")
        groups.setdefault(group_id, {})[side] = record
    correctness: dict[str, bool | None] = {}
    clusters: dict[str, str] = {}
    for group_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            correctness[group_id] = None
            clusters[group_id] = str(next(iter(sides.values())).get("cluster_id") or group_id)
            continue
        v = _record_prediction(sides["vulnerable"])
        f = _record_prediction(sides["fixed"])
        correctness[group_id] = None if v is None or f is None else (v is True and f is False)
        clusters[group_id] = str(sides["vulnerable"].get("cluster_id") or group_id)
    return correctness, clusters


def compare(run_a: Path, run_b: Path, *, resamples: int, seed: int) -> dict[str, Any]:
    manifest_a, records_a, predictions_a_path = load_run(run_a)
    manifest_b, records_b, predictions_b_path = load_run(run_b)
    for key in ("tier", "track"):
        if manifest_a.get(key) != manifest_b.get(key):
            raise ValueError(f"run {key} differs: {manifest_a.get(key)!r} vs {manifest_b.get(key)!r}")
    sha_a = (manifest_a.get("dataset") or {}).get("sha256")
    sha_b = (manifest_b.get("dataset") or {}).get("sha256")
    if sha_a != sha_b:
        raise ValueError("runs use different dataset SHA-256; comparison refused")

    tasks_a = {str(r.get("task")) for r in records_a}
    tasks_b = {str(r.get("task")) for r in records_b}
    if len(tasks_a) != 1 or tasks_a != tasks_b:
        raise ValueError(f"comparison expects one identical task; got {sorted(tasks_a)} vs {sorted(tasks_b)}")
    task = tasks_a.pop()

    result: dict[str, Any] = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "task": task,
        "run_a": manifest_a.get("run_id"),
        "run_b": manifest_b.get("run_id"),
        "dataset": {
            "sha256": sha_a,
            "dataset_id": (manifest_a.get("dataset") or {}).get("dataset_id"),
            "split_id": (manifest_a.get("dataset") or {}).get("split_id"),
        },
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "cohort": "common units with valid predictions in both runs for primary metrics",
            "test": "exact two-sided McNemar on paired correctness",
        },
        "alignment": {},
        "metrics": {},
        "cost": {},
        "notes": [],
    }

    if task in ("detection", "leak_detection"):
        map_a = _by_unit([r for r in records_a if r.get("task") == task])
        map_b = _by_unit([r for r in records_b if r.get("task") == task])
        common = sorted(set(map_a) & set(map_b))
        labels: list[bool] = []
        preds_a: list[bool | None] = []
        preds_b: list[bool | None] = []
        clusters: list[str] = []
        for unit_id in common:
            ra, rb = map_a[unit_id], map_b[unit_id]
            label = _record_label(ra)
            if _record_label(rb) != label:
                raise ValueError(f"{unit_id}: label mismatch between runs")
            labels.append(label)
            preds_a.append(_record_prediction(ra))
            preds_b.append(_record_prediction(rb))
            if str(ra.get("cluster_id")) != str(rb.get("cluster_id")):
                raise ValueError(f"{unit_id}: cluster_id mismatch between runs")
            clusters.append(str(ra.get("cluster_id")))

        valid_indices = [
            i for i, (a, b) in enumerate(zip(preds_a, preds_b)) if a is not None and b is not None
        ]
        valid_labels = [labels[i] for i in valid_indices]
        valid_a = [preds_a[i] for i in valid_indices]
        valid_b = [preds_b[i] for i in valid_indices]
        valid_clusters = [clusters[i] for i in valid_indices]

        scores_a = detection_scores(valid_labels, valid_a)
        scores_b = detection_scores(valid_labels, valid_b)
        strict_a = detection_scores(labels, preds_a)
        strict_b = detection_scores(labels, preds_b)
        delta = _delta_bootstrap(
            valid_labels,
            valid_a,
            valid_b,
            valid_clusters,
            metric_names=("macro_f1", "f1", "mcc", "balanced_accuracy"),
            resamples=resamples,
            seed=seed,
        )

        mcnemar = None
        if valid_labels:
            a_correct = [pred == label for pred, label in zip(valid_a, valid_labels)]
            b_correct = [pred == label for pred, label in zip(valid_b, valid_labels)]
            mcnemar = mcnemar_exact(
                a_correct_b_wrong=sum(1 for a, b in zip(a_correct, b_correct) if a and not b),
                a_wrong_b_correct=sum(1 for a, b in zip(a_correct, b_correct) if b and not a),
                total=len(valid_labels),
            )

        result["alignment"] = {
            "units_a": len(map_a),
            "units_b": len(map_b),
            "common_units": len(common),
            "common_valid_units": len(valid_indices),
            "only_a": len(set(map_a) - set(map_b)),
            "only_b": len(set(map_b) - set(map_a)),
            "valid_a_on_common": sum(1 for value in preds_a if value is not None),
            "valid_b_on_common": sum(1 for value in preds_b if value is not None),
            "common_valid_coverage": len(valid_indices) / len(common) if common else None,
        }
        result["metrics"] = {
            "a": {
                "valid_only": scores_a,
                "strict": strict_a,
            },
            "b": {
                "valid_only": scores_b,
                "strict": strict_b,
            },
            "delta": {
                "macro_f1": _difference(scores_a.get("macro_f1"), scores_b.get("macro_f1")),
                "f1": _difference(scores_a.get("f1"), scores_b.get("f1")),
                "mcc": _difference(scores_a.get("mcc"), scores_b.get("mcc")),
            },
            "delta_bootstrap": delta.get("metrics", {}),
            "mcnemar": mcnemar,
        }
        result["cost"] = {
            "a": cost_summary([r for r in records_a if r.get("task") == task]),
            "b": cost_summary([r for r in records_b if r.get("task") == task]),
            "note": "cost is compared descriptively; no cross-family monetary equivalence is assumed",
        }
        result["notes"].append(
            "Primary metrics use the common-valid cohort; strict views on all common units are reported separately."
        )

    elif task == "pair_detection":
        correct_a, clusters_a = _pair_correctness(
            [r for r in records_a if r.get("task") == task]
        )
        correct_b, clusters_b = _pair_correctness(
            [r for r in records_b if r.get("task") == task]
        )
        common = sorted(set(correct_a) & set(correct_b))
        valid = [
            group_id
            for group_id in common
            if correct_a[group_id] is not None and correct_b[group_id] is not None
        ]
        clusters = [clusters_a[g] for g in valid]
        a_correct = [bool(correct_a[g]) for g in valid]
        b_correct = [bool(correct_b[g]) for g in valid]
        da_a = (sum(a_correct) / len(valid)) if valid else None
        da_b = (sum(b_correct) / len(valid)) if valid else None
        strict_da_a = (sum(1 for g in common if correct_a[g] is True) / len(common)) if common else None
        strict_da_b = (sum(1 for g in common if correct_b[g] is True) / len(common)) if common else None

        def delta_pair(indices: Sequence[int]) -> float | None:
            if not indices:
                return None
            a = sum(1 for i in indices if a_correct[i]) / len(indices)
            b = sum(1 for i in indices if b_correct[i]) / len(indices)
            return a - b

        delta = cluster_bootstrap(
            clusters,
            {"delta_joint_accuracy": delta_pair},
            resamples=resamples,
            seed=seed,
        )
        mcnemar = None
        if valid:
            mcnemar = mcnemar_exact(
                a_correct_b_wrong=sum(1 for a, b in zip(a_correct, b_correct) if a and not b),
                a_wrong_b_correct=sum(1 for a, b in zip(a_correct, b_correct) if b and not a),
                total=len(valid),
            )
        result["alignment"] = {
            "pairs_a": len(correct_a),
            "pairs_b": len(correct_b),
            "common_pairs": len(common),
            "common_valid_pairs": len(valid),
            "only_a": len(set(correct_a) - set(correct_b)),
            "only_b": len(set(correct_b) - set(correct_a)),
        }
        result["metrics"] = {
            "a": {
                "valid_only_joint_accuracy": da_a,
                "strict_joint_accuracy": strict_da_a,
                "valid_pairs": len(valid),
            },
            "b": {
                "valid_only_joint_accuracy": da_b,
                "strict_joint_accuracy": strict_da_b,
                "valid_pairs": len(valid),
            },
            "delta_joint_accuracy": _difference(da_a, da_b),
            "delta_bootstrap": delta.get("metrics", {}),
            "mcnemar": mcnemar,
        }
        result["cost"] = {
            "a": cost_summary([r for r in records_a if r.get("task") == task]),
            "b": cost_summary([r for r in records_b if r.get("task") == task]),
            "note": "cost is descriptive; pair units are not function units",
        }
        result["notes"].append(
            "Pair DA is the proportion of pairs where vulnerable is flagged and fixed is clean; it is not per-function accuracy."
        )
    else:
        raise ValueError(f"unsupported task for comparison: {task}")

    result["hashes"] = {
        "run_a_manifest": sha256_file(run_a.resolve() / "run_manifest.json"),
        "run_b_manifest": sha256_file(run_b.resolve() / "run_manifest.json"),
        "run_a_predictions": sha256_file(predictions_a_path),
        "run_b_predictions": sha256_file(predictions_b_path),
    }
    return result


def _markdown(result: Mapping[str, Any]) -> str:
    lines = [
        f"# Paired comparison: `{result['run_a']}` vs `{result['run_b']}`",
        "",
        f"- task: `{result['task']}`",
        f"- dataset SHA-256: `{result['dataset']['sha256']}`",
        f"- generated: `{result['generated_at']}`",
        "",
        "## Alignment",
        "",
        "| field | value |",
        "| --- | ---: |",
    ]
    for key, value in result["alignment"].items():
        lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Metrics", "", "| field | value |", "| --- | ---: |"]
    for key, value in result["metrics"].items():
        if key == "mcnemar" and isinstance(value, dict):
            for name in ("a_correct_b_wrong", "a_wrong_b_correct", "p_value"):
                lines.append(f"| `mcnemar.{name}` | {value.get(name)} |")
        elif key == "delta_bootstrap" and isinstance(value, dict):
            for name, item in value.items():
                lines.append(
                    f"| `{name}` CI | [{item.get('ci_low')}, {item.get('ci_high')}] |"
                )
        else:
            lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Notes", ""]
    for note in result.get("notes", []):
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-a", required=True)
    parser.add_argument("--run-b", required=True)
    parser.add_argument("--out", help="output JSON path")
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    run_a = Path(args.run_a).resolve()
    run_b = Path(args.run_b).resolve()
    default_name = f"{run_a.name}__vs__{run_b.name}"
    out_path = (
        Path(args.out).resolve()
        if args.out
        else run_a.parent / f"{default_name}.comparison.json"
    )
    if out_path.exists() and not args.force:
        sys.stderr.write(f"refusing to overwrite {out_path}; pass --force\n")
        return 2
    try:
        result = compare(run_a, run_b, resamples=args.bootstrap, seed=args.seed)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"comparison failed: {exc}\n")
        return 2
    atomic_write_json(out_path, result)
    atomic_write_text(out_path.with_suffix(".md"), _markdown(result))
    sys.stderr.write(f"wrote {out_path} and {out_path.with_suffix('.md')}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

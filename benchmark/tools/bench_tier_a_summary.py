#!/usr/bin/env python3
"""Summarise Tier A SecVulEval runs and their paired comparisons.

Reads the 12 imported runs (DeepSeek and MiMo, three strategies, detection and
pair tasks) plus the comparison JSON files produced by ``bench_compare.py``.
It reports run-level macro-F1 / MCC / pair DA / coverage / cost / latency,
model-level paired deltas with cluster-bootstrap intervals, and exact McNemar
p-values with Holm correction inside pre-registered families.

The runs are derived views over the frozen ``runner/runs/test_v1_*``
experiments; no prediction is changed and no model is re-run.
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
    atomic_write_json,
    atomic_write_text,
    holm_adjust,
    load_run,
    p50_p95,
    read_json,
    sha256_file,
    utc_now,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_VERSION = "benchmark-tier-a-summary-v1"
STRATEGY_ORDER = ("direct", "few-shot", "context")
TASK_ORDER = ("detection", "pair")


def _strategy_key(value: str) -> int:
    try:
        return STRATEGY_ORDER.index(value)
    except ValueError:
        return 99


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _ci(bootstrap: Mapping[str, Any] | None, name: str) -> str:
    if not isinstance(bootstrap, dict):
        return "—"
    item = bootstrap.get(name)
    if not isinstance(item, dict) or item.get("ci_low") is None:
        return "—"
    return f"[{item['ci_low']:.3f}, {item['ci_high']:.3f}]"


def _wilson(scores: Mapping[str, Any], name: str) -> str:
    wilson = scores.get("wilson")
    if not isinstance(wilson, dict):
        return "—"
    item = wilson.get(name)
    if not isinstance(item, dict) or item.get("low") is None:
        return "—"
    return f"[{item['low']:.3f}, {item['high']:.3f}]"


def _load_runs(root: Path) -> dict[str, dict[str, Any]]:
    runs: dict[str, dict[str, Any]] = {}
    for manifest_path in sorted(root.rglob("run_manifest.json")):
        run_dir = manifest_path.parent
        manifest, records, _ = load_run(run_dir)
        # This tool is the historical 12-run Tier A view. Round-2 evidence and
        # pair-joint runs live in the same tree but are owned by
        # bench_final_summary.py; do not fold them into the 12-run aggregate.
        if not manifest.get("legacy_import"):
            continue
        metrics_path = run_dir / "metrics.json"
        if not metrics_path.exists():
            raise FileNotFoundError(f"missing metrics.json in {run_dir}")
        metrics = read_json(metrics_path)
        method = manifest.get("method") or {}
        model = method.get("model") or {}
        strategy = str(method.get("strategy") or "")
        run_id = str(manifest.get("run_id") or "")
        tasks = list((manifest.get("tasks") or []))
        if len(tasks) != 1:
            raise ValueError(f"{run_id}: expected one task, got {tasks}")
        raw_task = tasks[0]
        task = "pair" if raw_task == "pair_detection" else raw_task
        metric_task = "pair_detection" if task == "pair" else "detection"
        latencies = [
            float(record["usage"]["latency_ms"])
            for record in records
            if isinstance(record.get("usage"), dict)
            and isinstance(record["usage"].get("latency_ms"), (int, float))
        ]
        p50, p95 = p50_p95(latencies)
        runs[run_id] = {
            "run_id": run_id,
            "run_dir": str(run_dir),
            "tier": manifest.get("tier"),
            "track": manifest.get("track"),
            "task": task,
            "metric_task": metric_task,
            "strategy": strategy,
            "model_id": str(model.get("model_id") or ""),
            "model_family": str(model.get("family") or ""),
            "method_name": str(method.get("name") or ""),
            "method_id": str(method.get("method_id") or ""),
            "requested_units": len(records),
            "coverage": (
                (metrics.get("tasks", {}).get("detection", {}).get("scores") or {}).get("coverage")
                if task == "detection"
                else (metrics.get("tasks", {}).get("pair_detection") or {}).get("coverage")
            ),
            "latency_ms_p50": p50,
            "latency_ms_p95": p95,
            "latency_samples": len(latencies),
            "metrics": metrics,
            "manifest": manifest,
        }
    if len(runs) != 12:
        raise ValueError(f"expected 12 Tier A runs, found {len(runs)}")
    return runs


def _run_row(run: Mapping[str, Any]) -> dict[str, Any]:
    metrics = run["metrics"]
    task = run["task"]
    task_block = metrics.get("tasks", {}).get(run["metric_task"]) or {}
    bootstrap = None
    if task == "detection":
        scores = task_block.get("scores") or {}
        bootstrap = task_block.get("bootstrap")
        values = {
            "n": scores.get("n"),
            "valid": scores.get("valid"),
            "coverage": scores.get("coverage"),
            "precision": scores.get("precision"),
            "recall": scores.get("recall"),
            "specificity": scores.get("specificity"),
            "macro_f1": scores.get("macro_f1"),
            "mcc": scores.get("mcc"),
            "strict_accuracy": scores.get("strict_accuracy"),
            "confusion": scores.get("confusion"),
            "wilson": scores.get("wilson"),
            "cluster_count": task_block.get("cluster_count"),
        }
    else:
        scores = task_block
        bootstrap = task_block.get("bootstrap")
        values = {
            "n_pairs": scores.get("n_pairs"),
            "valid_pairs": scores.get("valid_pairs"),
            "coverage": scores.get("coverage"),
            "joint_accuracy_valid_pairs": scores.get("joint_accuracy_valid_pairs"),
            "joint_accuracy_all_pairs": scores.get("joint_accuracy_all_pairs"),
            "joint_categories": scores.get("joint_categories"),
            "consistent_rate": scores.get("consistent_rate"),
            "swapped_rate": scores.get("swapped_rate"),
            "wilson": scores.get("wilson"),
            "cluster_count": scores.get("cluster_count"),
        }
    legacy = run["manifest"].get("legacy_import") or {}
    cost = metrics.get("cost") or {}
    return {
        "run_id": run["run_id"],
        "model_family": run["model_family"],
        "model_id": run["model_id"],
        "strategy": run["strategy"],
        "task": task,
        "scores": values,
        "bootstrap": bootstrap,
        "cost": {
            "task_usd": cost.get("usd_known_sum"),
            "task_usd_unknown_records": cost.get("usd_unknown_records"),
            "full_run_usd": legacy.get("full_run_cost_usd"),
            "full_run_requests": legacy.get("full_run_requests"),
            "wall_s_sum": cost.get("wall_s_sum"),
            "latency_ms_p50": cost.get("latency_ms_p50"),
            "latency_ms_p95": cost.get("latency_ms_p95"),
            "cost_per_100_units_usd": cost.get("cost_per_100_units_usd"),
        },
        "status_counts": metrics.get("counts", {}).get("by_status"),
        "latency_ms_p50_all_requests": run["latency_ms_p50"],
        "latency_ms_p95_all_requests": run["latency_ms_p95"],
        "cluster_count_all_requests": None,
    }


def _comparison_entries(root: Path, runs: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.comparison.json")):
        data = read_json(path)
        run_a = runs.get(str(data.get("run_a")))
        run_b = runs.get(str(data.get("run_b")))
        if run_a is None or run_b is None:
            raise ValueError(f"{path}: unknown run id in comparison")
        raw_task = str(data.get("task"))
        task = "pair" if raw_task == "pair_detection" else raw_task
        metrics = data.get("metrics") or {}
        if task == "detection":
            delta = metrics.get("delta", {}).get("macro_f1")
            bootstrap = metrics.get("delta_bootstrap", {}).get("delta_macro_f1")
            delta_mcc = metrics.get("delta", {}).get("mcc")
        else:
            delta = metrics.get("delta_joint_accuracy")
            bootstrap = metrics.get("delta_bootstrap", {}).get("delta_joint_accuracy")
            delta_mcc = None
        mcnemar = metrics.get("mcnemar")
        entries.append(
            {
                "path": str(path),
                "task": task,
                "run_a": run_a["run_id"],
                "run_b": run_b["run_id"],
                "model_a": run_a["model_family"],
                "model_b": run_b["model_family"],
                "strategy_a": run_a["strategy"],
                "strategy_b": run_b["strategy"],
                "delta": delta,
                "delta_mcc": delta_mcc,
                "delta_ci": bootstrap,
                "mcnemar": mcnemar,
                "alignment": data.get("alignment"),
                "raw_p": (mcnemar or {}).get("p_value"),
                "holm_p": None,
                "family": None,
            }
        )
    return entries


def _apply_holm(entries: Sequence[dict[str, Any]], family: str) -> None:
    p_values = [entry["raw_p"] for entry in entries]
    if any(value is None for value in p_values):
        return
    adjusted = holm_adjust([float(value) for value in p_values])
    for entry, p_holm in zip(entries, adjusted):
        entry["family"] = family
        entry["holm_p"] = p_holm


def _model_comparisons(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    model_entries = [e for e in entries if e["model_a"] != e["model_b"]]
    for task in TASK_ORDER:
        subset = [e for e in model_entries if e["task"] == task]
        subset.sort(key=lambda e: _strategy_key(e["strategy_a"]))
        _apply_holm(subset, f"A-MODEL-{task.upper()}")
    return {
        "direction": "delta = model_a minus model_b; positive means model_a higher",
        "families": {
            "A-MODEL-DETECTION": {"task": "detection", "holm_m": 3},
            "A-MODEL-PAIR": {"task": "pair", "holm_m": 3},
        },
        "entries": sorted(model_entries, key=lambda e: (TASK_ORDER.index(e["task"]), _strategy_key(e["strategy_a"]))),
    }


def _within_model_comparisons(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    within = [e for e in entries if e["model_a"] == e["model_b"]]
    families: dict[str, list[dict[str, Any]]] = {}
    for entry in within:
        key = f"A-STRATEGY-{entry['model_a'].upper()}-{entry['task'].upper()}"
        families.setdefault(key, []).append(entry)
    for key, subset in families.items():
        subset.sort(key=lambda e: (_strategy_key(e["strategy_a"]), _strategy_key(e["strategy_b"])))
        _apply_holm(subset, key)
    return {
        "direction": "delta = strategy_a minus strategy_b; positive means strategy_a higher",
        "families": {
            key: {"task": subset[0]["task"], "model": subset[0]["model_a"], "holm_m": len(subset)}
            for key, subset in families.items()
        },
        "entries": sorted(
            within,
            key=lambda e: (e["model_a"], TASK_ORDER.index(e["task"]), _strategy_key(e["strategy_a"]), _strategy_key(e["strategy_b"])),
        ),
    }


def _model_summary(runs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for model in sorted({run["model_family"] for run in runs.values()}):
        model_runs = [dict(_run_row(run)) for run in runs.values() if run["model_family"] == model]
        detection = [row for row in model_runs if row["task"] == "detection"]
        pair = [row for row in model_runs if row["task"] == "pair"]
        detection_macro = [row["scores"]["macro_f1"] for row in detection]
        pair_da = [row["scores"]["joint_accuracy_valid_pairs"] for row in pair]
        coverage = [row["scores"]["coverage"] for row in model_runs]
        full_usd = [row["cost"]["full_run_usd"] for row in model_runs]
        task_usd = [row["cost"]["task_usd"] for row in model_runs]
        latencies = [
            latency
            for run in runs.values()
            if run["model_family"] == model
            for latency in [
                record["usage"]["latency_ms"]
                for record in load_run(run["run_dir"])[1]
                if isinstance(record.get("usage"), dict)
                and isinstance(record["usage"].get("latency_ms"), (int, float))
            ]
        ]
        p50, p95 = p50_p95(latencies)
        summary[model] = {
            "model_id": next(iter({run["model_id"] for run in runs.values() if run["model_family"] == model})),
            "runs": len(model_runs),
            "requests": sum((row["cost"]["full_run_requests"] or 0) for row in model_runs),
            "detection": {
                "strategies": len(detection),
                "macro_f1_mean": mean([value for value in detection_macro if value is not None]) if any(value is not None for value in detection_macro) else None,
                "macro_f1_min": min([value for value in detection_macro if value is not None]) if any(value is not None for value in detection_macro) else None,
                "macro_f1_max": max([value for value in detection_macro if value is not None]) if any(value is not None for value in detection_macro) else None,
                "coverage_mean": mean([row["scores"]["coverage"] for row in detection if row["scores"]["coverage"] is not None]),
            },
            "pair": {
                "strategies": len(pair),
                "pair_da_mean": mean([value for value in pair_da if value is not None]) if any(value is not None for value in pair_da) else None,
                "pair_da_min": min([value for value in pair_da if value is not None]) if any(value is not None for value in pair_da) else None,
                "pair_da_max": max([value for value in pair_da if value is not None]) if any(value is not None for value in pair_da) else None,
                "coverage_mean": mean([row["scores"]["coverage"] for row in pair if row["scores"]["coverage"] is not None]),
            },
            "coverage_mean": mean([value for value in coverage if value is not None]),
            "full_run_usd": sum([value for value in full_usd if value is not None]) if any(value is not None for value in full_usd) else None,
            "task_usd": sum([value for value in task_usd if value is not None]) if any(value is not None for value in task_usd) else None,
            "usd_per_100_requests": (
                (sum([value for value in full_usd if value is not None]) / sum((row["cost"]["full_run_requests"] or 0) for row in model_runs) * 100.0)
                if any(value is not None for value in full_usd)
                else None
            ),
            "latency_ms_p50": p50,
            "latency_ms_p95": p95,
            "latency_samples": len(latencies),
        }
    return summary


def build_summary(runs_root: Path, comparisons_root: Path) -> dict[str, Any]:
    runs = _load_runs(runs_root)
    rows = sorted(
        (_run_row(run) for run in runs.values()),
        key=lambda row: (row["model_family"], TASK_ORDER.index(row["task"]), _strategy_key(row["strategy"])),
    )
    entries = _comparison_entries(comparisons_root, runs)
    model_comparisons = _model_comparisons(entries)
    within = _within_model_comparisons(entries)
    models = _model_summary(runs)
    first_manifest = next(iter(runs.values()))["manifest"]
    dataset = first_manifest.get("dataset") or {}
    detection_runs = [run for run in runs.values() if run["task"] == "detection"]
    pair_runs = [run for run in runs.values() if run["task"] == "pair"]
    summary = {
        "schema_version": SUMMARY_VERSION,
        "generated_at": utc_now(),
        "protocol_version": "1.0.0",
        "tier": "A",
        "track": "secvuleval",
        "historical_view": {
            "status": "superseded",
            "scope": "12 legacy runs only",
            "superseded_by": "benchmark/results/final_summary.json",
            "note": "Round-2 evidence/pair-joint/LLM/hybrid/repair are not in this historical summary.",
        },
        "dataset": {
            "dataset_id": dataset.get("dataset_id"),
            "detection_sha256": next(
                (
                    (run["manifest"].get("dataset") or {}).get("sha256")
                    for run in detection_runs
                ),
                None,
            ),
            "pairs_sha256": next(
                (
                    (run["manifest"].get("dataset") or {}).get("sha256")
                    for run in pair_runs
                ),
                None,
            ),
            "detection_units": 160,
            "detection_labels": {"vulnerable": 128, "non_vulnerable": 32},
            "pairs": 180,
            "pair_sides": 360,
        },
        "runs": rows,
        "models": models,
        "comparisons": {
            "model": model_comparisons,
            "within_model": within,
        },
        "static_feasibility": {
            "status": "pending",
            "f1_reported": False,
            "note": (
                "Tier A static tools need a complete translation unit. The 160 SecVulEval functions are "
                "extracted fragments; the existing 3-snippet CWE-401 smoke is not a benchmark. "
                "A4 remains planned and no static F1 is reported."
            ),
        },
        "juliet_llm_hybrid": {
            "status": "out_of_scope_for_this_historical_view",
            "note": "This tool reproduces the 12 legacy runs only. Round-2 evidence/pair-joint/LLM/hybrid/repair are in final_summary.json and LEADERBOARD.md.",
        },
        "settings": {
            "bootstrap_resamples": 10000,
            "bootstrap_seed": 42,
            "bootstrap_cohort": "common-valid units for paired comparisons; cluster by project (detection) or pair_id (pair)",
            "mcnemar": "exact two-sided on paired correctness; secondary evidence",
            "holm_families": [
                "A-MODEL-DETECTION (m=3)",
                "A-MODEL-PAIR (m=3)",
                "A-STRATEGY-DS-DETECTION (m=3)",
                "A-STRATEGY-DS-PAIR (m=3)",
                "A-STRATEGY-MIMO-DETECTION (m=3)",
                "A-STRATEGY-MIMO-PAIR (m=3)",
            ],
            "cost_policy": "USD from per-request usage at the prices recorded in the runner config; no separate price-snapshot date is stored for DeepSeek, MiMo prices were verified 2026-11-12; full run total includes repair requests, task cost excludes them",
            "latency_policy": "request-level latency from the runner attempts; p50/p95 over all records in the model's six runs",
        },
        "limitations": [
            "Single run per model/strategy; run-to-run variance is not estimated.",
            "MiMo uses reasoning_effort=none with max_completion_tokens on OpenCode Go; its decoding/transport differs from DeepSeek's non-thinking max_tokens setup.",
            "Detection negatives are source-unlabelled, not proven safe; pair fixed sides are also unlabelled.",
            "CWE-401 has only 3 test functions; no per-CWE claim is made.",
            "McNemar assumes independent units; project/pair clustering can make p-values anti-conservative, so cluster-bootstrap intervals are the primary evidence.",
            "Derived runs are read-only views over runner/runs/test_v1_*; they are not new model calls.",
            "Price snapshots are not identical: DeepSeek prices come from the runner config, MiMo prices were verified on the OpenCode Go page on 2026-11-12.",
        ],
    }
    summary["provenance"] = {
        "run_manifests": {
            run["run_dir"]: sha256_file(Path(run["run_dir"]) / "run_manifest.json")
            for run in runs.values()
        },
        "comparison_files": {
            entry["path"]: sha256_file(entry["path"]) for entry in entries
        },
        "builder": "bench_tier_a_summary.py",
    }
    return summary


def build_markdown(summary: Mapping[str, Any]) -> str:
    rows = summary["runs"]
    models = summary["models"]
    model_comparisons = summary["comparisons"]["model"]["entries"]
    within = summary["comparisons"]["within_model"]["entries"]
    lines = [
        "# Tier A leaderboard: SecVulEval",
        "",
        "> **Historical detailed view (12 legacy runs).** The current integrated leaderboard, including evidence and pair-joint, is [`LEADERBOARD.md`](LEADERBOARD.md); machine-readable integrated results are in [`final_summary.json`](final_summary.json).",
        "",
        f"- dataset: `{summary['dataset']['dataset_id']}`",
        f"- detection SHA-256: `{summary['dataset']['detection_sha256']}`",
        f"- pair SHA-256: `{summary['dataset']['pairs_sha256']}`",
        "- detection: 160 functions (128 vulnerable / 32 non-vulnerable); pair: 180 pairs / 360 sides",
        f"- runs: {len(rows)} (DeepSeek and MiMo x direct / few-shot / context x detection / pair)",
        "",
        "> Tier A only. These rows are not comparable to Tier B (Juliet). "
        "Derived views over frozen `runner/runs/test_v1_*`; no model was re-run and no prediction changed.",
        "",
        "## 1. Detection (valid-only, cluster bootstrap by project)",
        "",
        "| model | strategy | n | valid | cov | macro-F1 | 95% CI | MCC | strict | recall | spec | task USD | full run USD | p50/p95 s |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        if row["task"] != "detection":
            continue
        s = row["scores"]
        lines.append(
            f"| {row['model_family']} | {row['strategy']} | {s['n']} | {s['valid']} | "
            f"{_fmt(s['coverage'])} | {_fmt(s['macro_f1'])} | {_ci(row['bootstrap'], 'macro_f1')} | "
            f"{_fmt(s['mcc'])} | {_fmt(s['strict_accuracy'])} | {_fmt(s['recall'])} | "
            f"{_fmt(s['specificity'])} | {_fmt(row['cost']['task_usd'], 6)} | "
            f"{_fmt(row['cost']['full_run_usd'], 6)} | "
            f"{_fmt(row['cost']['latency_ms_p50'] / 1000.0, 2)}/{_fmt(row['cost']['latency_ms_p95'] / 1000.0, 2)} |"
        )
    lines += [
        "",
        "`task USD` covers the 160 detection requests only; `full run USD` covers all 288 requests including repair. "
        "Detection valid-only excludes schema-invalid outputs; `strict` counts them wrong.",
        "",
        "## 2. Pair discrimination (valid-only, cluster bootstrap by pair_id)",
        "",
        "| model | strategy | pairs | valid | cov | pair DA | 95% CI | DA all | both flagged | both clean | swapped | task USD | p50/p95 s |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        if row["task"] != "pair":
            continue
        s = row["scores"]
        categories = s.get("joint_categories") or {}
        lines.append(
            f"| {row['model_family']} | {row['strategy']} | {s['n_pairs']} | {s['valid_pairs']} | "
            f"{_fmt(s['coverage'])} | {_fmt(s['joint_accuracy_valid_pairs'])} | "
            f"{_ci(row['bootstrap'], 'joint_accuracy_valid_pairs')} | "
            f"{_fmt(s['joint_accuracy_all_pairs'])} | {categories.get('both_flagged', 0)} | "
            f"{categories.get('both_clean', 0)} | {categories.get('vulnerable_missed_fixed_flagged', 0)} | "
            f"{_fmt(row['cost']['task_usd'], 6)} | "
            f"{_fmt(row['cost']['latency_ms_p50'] / 1000.0, 2)}/{_fmt(row['cost']['latency_ms_p95'] / 1000.0, 2)} |"
        )
    lines += [
        "",
        "`pair DA` is the fraction of pairs where the vulnerable side is flagged and the fixed side is clean. "
        "`DA all` includes pairs with an invalid side as failures. `swapped` is the reversed-error category.",
        "",
        "### 2b. Wilson 95% intervals for proportions",
        "",
        "| task | model | strategy | coverage | recall | specificity | pair DA |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        s = row["scores"]
        if row["task"] == "detection":
            lines.append(
                f"| detection | {row['model_family']} | {row['strategy']} | {_wilson(s, 'coverage')} | "
                f"{_wilson(s, 'recall')} | {_wilson(s, 'specificity')} | — |"
            )
        else:
            lines.append(
                f"| pair | {row['model_family']} | {row['strategy']} | {_wilson(s, 'coverage')} | — | — | "
                f"{_wilson(s, 'joint_accuracy_valid_pairs')} |"
            )
    lines += [
        "",
        "Wilson intervals use valid predictions; pair-side recall/specificity are not reported here because the pair run is scored jointly by design.",
        "",
        "## 3. Model comparison: DeepSeek vs MiMo (same strategy, same task)",
        "",
        "| task | strategy | Δ (DeepSeek − MiMo) | 95% CI | n common | McNemar b/c | raw p | Holm p | Holm family |",
        "| --- | --- | ---: | --- | ---: | --- | ---: | ---: | --- |",
    ]
    for entry in model_comparisons:
        label = "Δ macro-F1" if entry["task"] == "detection" else "Δ pair DA"
        mcnemar = entry.get("mcnemar") or {}
        n_common = (
            (entry.get("alignment") or {}).get("common_valid_units")
            if entry["task"] == "detection"
            else (entry.get("alignment") or {}).get("common_valid_pairs")
        )
        lines.append(
            f"| {entry['task']} | {entry['strategy_a']} | {label} {_fmt(entry['delta'])} | "
            f"{_ci({'x': entry['delta_ci']}, 'x')} | {n_common} | "
            f"{mcnemar.get('a_correct_b_wrong')}/{mcnemar.get('a_wrong_b_correct')} | "
            f"{_fmt(entry['raw_p'], 4)} | {_fmt(entry['holm_p'], 4)} | `{entry['family']}` |"
        )
    lines += [
        "",
        "`b/c` are the discordant counts (DeepSeek correct / MiMo correct). "
        "Holm is applied inside each task family (m=3). No model difference survives Holm on McNemar. "
        "The few-shot detection macro-F1 interval excludes zero, but the secondary McNemar test does not, "
        "and this is one run per cell; treat it as suggestive, not a confirmed ranking.",
        "",
        "## 4. Within-model strategy comparisons (secondary)",
        "",
        "| model | task | comparison | Δ | 95% CI | raw p | Holm p | Holm family |",
        "| --- | --- | --- | ---: | --- | ---: | ---: | --- |",
    ]
    for entry in within:
        label = "macro-F1" if entry["task"] == "detection" else "pair DA"
        lines.append(
            f"| {entry['model_a']} | {entry['task']} | {entry['strategy_a']} vs {entry['strategy_b']} | "
            f"{_fmt(entry['delta'])} | {_ci({'x': entry['delta_ci']}, 'x')} | "
            f"{_fmt(entry['raw_p'], 4)} | {_fmt(entry['holm_p'], 4)} | `{entry['family']}` |"
        )
    lines += [
        "",
        "These are exploratory/secondary; the pre-registered primary model comparison is §3.",
        "",
        "## 5. Model aggregate (descriptive, no pooled unit metric)",
        "",
        "| model | detection mean macro-F1 (range) | pair mean DA (range) | mean coverage | full USD | USD / 100 requests | p50/p95 s | requests |",
        "| --- | --- | --- | ---: | ---: | ---: | --- | ---: |",
    ]
    for family in sorted(models):
        model = models[family]
        det = model["detection"]
        pair = model["pair"]
        lines.append(
            f"| {family} | {_fmt(det['macro_f1_mean'])} ({_fmt(det['macro_f1_min'])}–{_fmt(det['macro_f1_max'])}) | "
            f"{_fmt(pair['pair_da_mean'])} ({_fmt(pair['pair_da_min'])}–{_fmt(pair['pair_da_max'])}) | "
            f"{_fmt(model['coverage_mean'])} | {_fmt(model['full_run_usd'], 6)} | "
            f"{_fmt(model['usd_per_100_requests'], 6)} | "
            f"{_fmt((model['latency_ms_p50'] or 0) / 1000.0, 2)}/{_fmt((model['latency_ms_p95'] or 0) / 1000.0, 2)} | "
            f"{model['requests']} |"
        )
    lines += [
        "",
        "Means are across the three strategies, not pooled over units. USD is the sum of the six full runs "
        "(2,484 requests including repair); `task USD` in the run tables excludes repair.",
        "",
        "## 6. Explicitly not reported",
        "",
        "- **Tier A static F1**: pending. The 160 SecVulEval functions are fragments; static tools cannot parse most of them. "
        "No compile failure is converted to a zero prediction. A4 remains planned.",
        "- **Round-2 evidence/pair-joint**: not in this historical 12-run file; see `LEADERBOARD.md` §2.",
        "- **Juliet LLM / hybrid / repair**: out of scope for this Tier A historical file; see `LEADERBOARD.md` §3–§4.",
        "",
        "## 7. Limitations",
        "",
    ]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs-root",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_a"),
    )
    parser.add_argument(
        "--comparisons-root",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "comparisons" / "tier_a"),
    )
    parser.add_argument(
        "--out-json",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_a_summary.json"),
    )
    parser.add_argument(
        "--out-md",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_a_leaderboard.md"),
    )
    args = parser.parse_args(argv)
    try:
        summary = build_summary(Path(args.runs_root).resolve(), Path(args.comparisons_root).resolve())
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"summary failed: {exc}\n")
        return 2
    atomic_write_json(args.out_json, summary)
    atomic_write_text(args.out_md, build_markdown(summary))
    sys.stderr.write(f"wrote {args.out_json} and {args.out_md}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

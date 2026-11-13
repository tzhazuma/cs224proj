"""Turn the per-unit records into metrics and an archived-result comparison."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from . import config
from .units import sha256_file

OLD_RUN = config.PROJECT / "traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind"


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def normalize_source(path: str) -> str:
    path = path.replace("\\", "/")
    marker = "CWE401_Memory_Leak/"
    if marker in path:
        return path.split(marker, 1)[1]
    return Path(path).name


def source_key(sources: list[str], defines: list[str]) -> tuple:
    return (
        tuple(sorted(normalize_source(source) for source in sources)),
        tuple(sorted(defines)),
    )


def load_old() -> dict:
    if not OLD_RUN.exists():
        return {"available": False}
    cases = read_jsonl(OLD_RUN / "cases.jsonl")
    results = {row["case_id"]: row for row in read_jsonl(OLD_RUN / "results.jsonl")}
    by_key = {}
    for case in cases:
        result = results.get(case["case_id"])
        if result is None:
            continue
        key = source_key(case["sources"], case["defines"])
        by_key[key] = {"case": case, "result": result}
    return {
        "available": True,
        "path": str(OLD_RUN.relative_to(config.PROJECT)),
        "cases": len(cases),
        "results": len(results),
        "by_key": by_key,
        "cases_sha256": sha256_file(OLD_RUN / "cases.jsonl"),
        "results_sha256": sha256_file(OLD_RUN / "results.jsonl"),
    }


def _old_status(result: dict, detector: str) -> dict:
    entry = (result.get("detectors") or {}).get(detector) or {}
    execution = entry.get("execution") or {}
    return {
        "status": entry.get("status"),
        "leak_detected": entry.get("leak_detected"),
        "duration_ms": execution.get("duration_ms"),
        "still_reachable_bytes": (entry.get("evidence") or {}).get("still_reachable_bytes"),
    }


def _percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def build_metrics(run_dir: Path) -> dict:
    records = read_jsonl(run_dir / "results_units.jsonl")
    old = load_old()
    bad = [row for row in records if row["label"] == "bad"]
    good = [row for row in records if row["label"] == "good"]

    def confusion(rows: list[dict]) -> dict:
        tp = sum(1 for row in rows if row["label"] == "bad" and row["y_pred"] == 1)
        fn = sum(1 for row in rows if row["label"] == "bad" and row["y_pred"] == 0)
        fp = sum(1 for row in rows if row["label"] == "good" and row["y_pred"] == 1)
        tn = sum(1 for row in rows if row["label"] == "good" and row["y_pred"] == 0)
        undecided = sum(1 for row in rows if row["y_pred"] is None)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        )
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "undecided": undecided,
            "coverage": (len(rows) - undecided) / len(rows) if rows else 0.0,
            "precision": precision, "recall": recall, "f1": f1,
        }

    def mode_stats(mode: str) -> dict:
        applicable = []
        for row in records:
            entry = (row.get("modes") or {}).get(mode) or {}
            if entry.get("applicable"):
                applicable.append((row, entry))
        bad_rows = [(row, entry) for row, entry in applicable if row["label"] == "bad"]
        good_rows = [(row, entry) for row, entry in applicable if row["label"] == "good"]
        return {
            "applicable_units": len(applicable),
            "not_applicable_units": len(records) - len(applicable),
            "bad_attributed": sum(1 for _, entry in bad_rows if entry.get("leak_attributed")),
            "bad_raw": sum(1 for _, entry in bad_rows if entry.get("leak_raw")),
            "good_attributed": sum(1 for _, entry in good_rows if entry.get("leak_attributed")),
            "good_raw": sum(1 for _, entry in good_rows if entry.get("leak_raw")),
            "good_units_with_raw_only": [
                row["unit_id"] for row, entry in good_rows
                if entry.get("leak_raw") and not entry.get("leak_attributed")
            ],
            "leak_kinds": sorted({
                kind for _, entry in applicable for kind in (entry.get("leak_kinds") or [])
            }),
        }

    resolved = [
        {
            "unit_id": row["unit_id"],
            "group_id": row["group_id"],
            "primary_evidence": row.get("primary_evidence"),
            "evidence_modes": row.get("evidence_modes"),
            "default": (row.get("modes") or {}).get("default", {}).get("decision"),
            "realloc_fail": (row.get("modes") or {}).get("realloc_fail", {}).get("decision"),
            "realloc_applicable": (row.get("modes") or {}).get("realloc_fail", {}).get("applicable"),
            "realloc_injected_at": ((row.get("modes") or {}).get("realloc_fail", {}).get("injection") or {}).get("injected_at_call"),
            "nogobal": (row.get("modes") or {}).get("nogobal", {}).get("decision"),
            "attributed_bytes": sum(
                entry.get("attributed_bytes", 0)
                for entry in (row.get("modes") or {}).values()
                if entry.get("leak_attributed")
            ),
        }
        for row in bad
        if row.get("conditionally_observable")
    ]
    resolved.sort(key=lambda item: item["unit_id"])

    failures = {}
    for row in records:
        key = row.get("failure_class") or "unknown"
        failures[key] = failures.get(key, 0) + 1

    runtimes = [row.get("runtime_ms", 0) for row in records]
    runtime_by_mode = {}
    for mode in config.MODES:
        values = [
            (row.get("modes") or {}).get(mode, {}).get("wall_ms", 0)
            for row in records
            if (row.get("modes") or {}).get(mode, {}).get("wall_ms") is not None
        ]
        values = [value for value in values if value]
        runtime_by_mode[mode] = {
            "runs": len(values),
            "mean_ms": round(statistics.mean(values), 1) if values else None,
            "p95_ms": _percentile([int(value) for value in values], 0.95) if values else None,
            "max_ms": max(values) if values else None,
        }

    comparison = {}
    if old["available"]:
        agreements = {"default_vs_old_asan": 0, "union_vs_old_any": 0}
        changes = []
        per_unit = []
        matched = 0
        for row in records:
            key = source_key(row["sources"], row["defines"])
            entry = old["by_key"].get(key)
            if entry is None:
                per_unit.append({"unit_id": row["unit_id"], "old": None})
                continue
            matched += 1
            asan = _old_status(entry["result"], "asan")
            valgrind = _old_status(entry["result"], "valgrind")
            old_any = bool(asan["leak_detected"]) or bool(valgrind["leak_detected"])
            new_default = (row.get("modes") or {}).get("default", {}).get("decision") == "leak"
            new_union = row.get("y_pred") == 1
            if new_default == bool(asan["leak_detected"]):
                agreements["default_vs_old_asan"] += 1
            if new_union == old_any:
                agreements["union_vs_old_any"] += 1
            if new_union != bool(asan["leak_detected"]):
                changes.append(
                    {
                        "unit_id": row["unit_id"],
                        "label": row["label"],
                        "old_asan": asan["status"],
                        "old_valgrind": valgrind["status"],
                        "new_default": (row.get("modes") or {}).get("default", {}).get("decision"),
                        "new_union": "leak" if new_union else "clean",
                        "evidence": row.get("primary_evidence"),
                    }
                )
            per_unit.append(
                {
                    "unit_id": row["unit_id"],
                    "label": row["label"],
                    "old_asan": asan,
                    "old_valgrind": valgrind,
                    "new_default": (row.get("modes") or {}).get("default", {}).get("decision"),
                    "new_union": "leak" if new_union else "clean",
                    "evidence": row.get("primary_evidence"),
                }
            )
        old_asan_ms = [
            item["old_asan"]["duration_ms"]
            for item in per_unit
            if item.get("old_asan") and item["old_asan"].get("duration_ms")
        ]
        comparison = {
            "old_run": old["path"],
            "old_cases": old["cases"],
            "matched_units": matched,
            "agreements": agreements,
            "changes": changes,
            "old_asan_duration_mean_ms": round(statistics.mean(old_asan_ms), 1) if old_asan_ms else None,
            "per_unit": per_unit,
        }

    return {
        "run_id": run_dir.name,
        "units": len(records),
        "labels": {"bad": len(bad), "good": len(good)},
        "confusion": confusion(records),
        "per_mode": {mode: mode_stats(mode) for mode in config.MODES},
        "resolved_conditional": resolved,
        "default_unobservable_bad": [
            row["unit_id"] for row in bad
            if not (row.get("modes") or {}).get("default", {}).get("leak_attributed")
            and row.get("y_pred") == 1
        ],
        "good_false_positives": [
            row["unit_id"] for row in good if row.get("y_pred") == 1
        ],
        "good_undecided": [row["unit_id"] for row in good if row.get("y_pred") is None],
        "bad_undecided": [row["unit_id"] for row in bad if row.get("y_pred") is None],
        "failures": failures,
        "runtime": {
            "total_ms": sum(runtimes),
            "mean_ms": round(statistics.mean(runtimes), 1) if runtimes else None,
            "p50_ms": _percentile(runtimes, 0.50),
            "p95_ms": _percentile(runtimes, 0.95),
            "max_ms": max(runtimes) if runtimes else None,
            "by_mode": runtime_by_mode,
        },
        "old_comparison": comparison,
    }

#!/usr/bin/env python3
"""Self-test for the benchmark validator and metric arithmetic.

All records here are synthetic fixtures created in a temporary directory and
deleted at the end. They are not experimental results and must never be cited
as model/tool performance.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    PREDICTION_SCHEMA_VERSION,
    RUN_SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    sha256_file,
    utc_now,
)
from bench_metrics import compute_run_metrics  # noqa: E402
from bench_validate import validate_run  # noqa: E402

ZERO = "0" * 64
CREATED = "2026-11-12T00:00:00Z"


def _record(
    *,
    run_id: str,
    tier: str,
    track: str,
    task: str,
    unit_id: str,
    cluster_id: str,
    y_true: bool,
    y_pred: bool | None,
    status: str,
    dataset_id: str,
    group_id: str | None = None,
    side: str | None = None,
    coverage: dict[str, Any] | None = None,
    family: str = "llm",
) -> dict[str, Any]:
    return {
        "schema_version": PREDICTION_SCHEMA_VERSION,
        "run_id": run_id,
        "tier": tier,
        "track": track,
        "task": task,
        "unit_id": unit_id,
        "cluster_id": cluster_id,
        "group_id": group_id,
        "side": side,
        "dataset": {
            "dataset_id": dataset_id,
            "split_id": "test",
            "sha256": ZERO,
            "unit_manifest_sha256": None,
        },
        "method": {
            "method_id": f"test.{family}",
            "family": family,
            "name": f"synthetic {family}",
            "strategy": None,
            "model": (
                {"model_id": "test-model", "family": "test", "provider": "test"}
                if family == "llm"
                else None
            ),
            "tool": (
                {"name": "test-tool", "version": "0"}
                if family in ("static", "dynamic")
                else None
            ),
            "config_sha256": None,
        },
        "input": {
            "view": "function",
            "source_sha256": ZERO,
            "prompt_sha256": ZERO,
            "context_mode": "none",
            "sanitized": True,
            "sanitizer_version": "synthetic",
            "evidence_sha256": None,
        },
        "label": {
            "y_true": y_true,
            "cwe": ["CWE-401"],
            "label_source": "juliet_intended" if tier == "B" else "secvuleval",
            "label_note": None,
        },
        "prediction": {
            "y_pred": y_pred,
            "cwe_pred": ["CWE-401"],
            "confidence": None,
            "evidence_lines": [],
            "rationale": None,
            "raw_output_sha256": None,
            "fixed_function": None,
        },
        "status": status,
        "error": None,
        "coverage": coverage,
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "cached_prompt_tokens": 0,
            "reasoning_tokens": 0,
            "latency_ms": 100.0,
            "api_attempts": 1,
        },
        "cost": {
            "usd": 0.001,
            "wall_s": 0.1,
            "cpu_s": None,
            "peak_rss_mb": None,
            "currency": "USD",
            "cost_basis": "api_price",
            "pricing_snapshot": "synthetic",
            "note": "synthetic fixture",
        },
        "provenance": {
            "produced_by": "selftest.py",
            "created_at": CREATED,
            "source_artifact": "synthetic",
            "source_sha256": None,
            "record_index": 0,
            "command_sha256": None,
            "legacy_run_id": None,
            "note": "synthetic fixture",
        },
    }


def _write_run(
    directory: Path,
    run_id: str,
    tier: str,
    track: str,
    task: str,
    records: list[dict[str, Any]],
    *,
    family: str = "llm",
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    predictions = directory / "predictions.jsonl"
    atomic_write_text(
        predictions,
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
    )
    manifest = {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": CREATED,
        "protocol_version": "1.0.0",
        "tier": tier,
        "track": track,
        "tasks": [task],
        "dataset": {
            "dataset_id": "synthetic",
            "split_id": "test",
            "path": str(predictions),
            "sha256": ZERO,
            "unit_manifest": None,
            "unit_count": len(records),
            "label_counts": {},
        },
        "method": {
            "method_id": f"test.{family}",
            "family": family,
            "name": f"synthetic {family}",
            "strategy": None,
            "prompt_version": None,
            "config_sha256": None,
            "model": (
                {"model_id": "test-model", "family": "test", "provider": "test"}
                if family == "llm"
                else None
            ),
            "tool": (
                {"name": "test-tool", "version": "0"}
                if family in ("static", "dynamic")
                else None
            ),
        },
        "execution": {
            "started_at": CREATED,
            "finished_at": CREATED,
            "status": "completed",
            "planned_units": len(records),
            "recorded_units": len(records),
            "retries": 0,
            "concurrency": 1,
            "command": None,
            "command_sha256": None,
            "environment": {"synthetic": True},
        },
        "artifacts": {
            "predictions": "predictions.jsonl",
            "metrics": None,
            "validation": None,
            "log": None,
        },
        "hashes": {"predictions_sha256": sha256_file(predictions)},
        "legacy_import": None,
        "notes": ["synthetic fixture"],
    }
    atomic_write_json(directory / "run_manifest.json", manifest)


def _close(actual: float | None, expected: float, label: str, tolerance: float = 1e-9) -> None:
    if actual is None or abs(float(actual) - expected) > tolerance:
        raise AssertionError(f"{label}: expected {expected}, got {actual}")


def test_detection(root: Path) -> None:
    records = []
    labels = [True, True, True, True, False, False, False, False]
    predictions: list[bool | None] = [True, True, False, None, False, True, False, False]
    statuses = ["ok", "ok", "ok", "api_error", "ok", "ok", "ok", "ok"]
    for index, (label, prediction, status) in enumerate(zip(labels, predictions, statuses)):
        records.append(
            _record(
                run_id="synthetic_detection",
                tier="A",
                track="secvuleval",
                task="detection",
                unit_id=f"unit:{index}",
                cluster_id=f"p{index // 2}",
                y_true=label,
                y_pred=prediction,
                status=status,
                dataset_id="synthetic",
            )
        )
    run_dir = root / "detection"
    _write_run(run_dir, "synthetic_detection", "A", "secvuleval", "detection", records)
    report = validate_run(run_dir)
    assert report["ok"], report["errors"]
    metrics = compute_run_metrics(run_dir, resamples=50)
    scores = metrics["tasks"]["detection"]["scores"]
    _close(scores["precision"], 2 / 3, "precision")
    _close(scores["recall"], 2 / 3, "recall")
    _close(scores["f1"], 2 / 3, "f1")
    _close(scores["macro_f1"], (2 / 3 + 0.75) / 2, "macro_f1")
    _close(scores["accuracy"], 5 / 7, "accuracy")
    _close(scores["strict_accuracy"], 5 / 8, "strict_accuracy")
    _close(scores["mcc"], 5 / 12, "mcc")
    _close(scores["coverage"], 7 / 8, "coverage")
    assert scores["confusion"] == {"tp": 2, "fp": 1, "tn": 3, "fn": 1}


def test_pair(root: Path) -> None:
    records = []
    cases = [
        ("p1", True, False, "ok", "ok"),
        ("p2", True, True, "ok", "ok"),
        ("p3", False, False, "ok", "ok"),
        ("p4", False, True, "ok", "ok"),
        ("p5", None, False, "api_error", "ok"),
    ]
    for index, (pair_id, v_pred, f_pred, v_status, f_status) in enumerate(cases):
        for side, label, prediction, status in (
            ("vulnerable", True, v_pred, v_status),
            ("fixed", False, f_pred, f_status),
        ):
            records.append(
                _record(
                    run_id="synthetic_pair",
                    tier="A",
                    track="secvuleval",
                    task="pair_detection",
                    unit_id=f"pair:{pair_id}:{side}",
                    cluster_id=pair_id,
                    y_true=label,
                    y_pred=prediction,
                    status=status,
                    dataset_id="synthetic-pairs",
                    group_id=pair_id,
                    side=side,
                )
            )
    run_dir = root / "pair"
    _write_run(run_dir, "synthetic_pair", "A", "secvuleval", "pair_detection", records)
    report = validate_run(run_dir)
    assert report["ok"], report["errors"]
    metrics = compute_run_metrics(run_dir, resamples=50)
    block = metrics["tasks"]["pair_detection"]
    _close(block["joint_accuracy_valid_pairs"], 1 / 4, "pair DA valid")
    _close(block["joint_accuracy_all_pairs"], 1 / 5, "pair DA all")
    assert block["joint_categories"] == {
        "vulnerable_detected_fixed_clean": 1,
        "both_flagged": 1,
        "both_clean": 1,
        "vulnerable_missed_fixed_flagged": 1,
    }
    assert block["valid_pairs"] == 4 and block["invalid_pairs"] == 1


def test_leak(root: Path) -> None:
    records = []
    cases = [
        ("c1", "bad", True, True, "ok", 1.0),
        ("c1", "good", False, False, "ok", 1.0),
        ("c2", "bad", True, True, "ok", 0.2),
        ("c2", "good", False, False, "ok", 0.2),
    ]
    for index, (case_id, side, label, prediction, status, coverage) in enumerate(cases):
        records.append(
            _record(
                run_id="synthetic_leak",
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=f"juliet:{case_id}:{side}",
                cluster_id=case_id,
                y_true=label,
                y_pred=prediction,
                status=status,
                dataset_id="synthetic-juliet",
                group_id=case_id,
                side=side,
                coverage={
                    "unit_executed": True,
                    "target_function_entered": True,
                    "line_coverage": coverage,
                    "branch_coverage": None,
                    "allocation_site_executed": True,
                    "free_site_executed": True,
                    "coverage_source": "gcov",
                    "notes": None,
                },
                family="dynamic",
            )
        )
    run_dir = root / "leak"
    _write_run(run_dir, "synthetic_leak", "B", "juliet_cwe401", "leak_detection", records, family="dynamic")
    report = validate_run(run_dir)
    assert report["ok"], report["errors"]
    metrics = compute_run_metrics(run_dir, resamples=50)
    block = metrics["tasks"]["leak_detection"]
    scores = block["detection"]["scores"]
    _close(scores["precision"], 1.0, "leak precision")
    _close(scores["recall"], 1.0, "leak recall")
    _close(scores["specificity"], 1.0, "leak specificity")
    _close(scores["strict_accuracy"], 3 / 4, "leak strict accuracy")
    assert block["inconclusive"]["count"] == 1
    assert block["coverage_strata"]["ge_0.90"]["n"] == 2
    assert block["coverage_strata"]["lt_0.50"]["n"] == 2


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="bench_selftest_") as temporary:
        root = Path(temporary)
        test_detection(root)
        test_pair(root)
        test_leak(root)
    print("PASS: validator + detection/pair/leak metric arithmetic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

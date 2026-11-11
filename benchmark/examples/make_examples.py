#!/usr/bin/env python3
"""Generate tiny SYNTHETIC schema examples for benchmark/examples/.

These are not experimental results. They exist only to validate the JSON
Schema and the validator. Every record is hand-written; no model, static tool
or dynamic tool was run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from bench_common import sha256_file  # noqa: E402

ROOT = Path(__file__).resolve().parent
CREATED = "2026-11-12T00:00:00Z"
ZERO_HASH = "0" * 64
PROJECT = "example-project"


def _base_dataset(dataset_id: str, split_id: str) -> dict:
    return {
        "dataset_id": dataset_id,
        "split_id": split_id,
        "sha256": ZERO_HASH,
        "unit_manifest_sha256": None,
    }


def _base_method(family: str, method_id: str, name: str, *, strategy=None) -> dict:
    if family == "llm":
        return {
            "method_id": method_id,
            "family": "llm",
            "name": name,
            "strategy": strategy,
            "model": {
                "model_id": "example-model",
                "family": "example",
                "provider": "example-provider",
                "endpoint": "https://example.invalid/v1",
                "version": "0",
                "context_window": 8192,
                "tokenizer": "example",
                "decoding": {"temperature": 0.0, "max_tokens": 128},
                "price_snapshot": "synthetic",
            },
            "tool": None,
            "config_sha256": None,
        }
    return {
        "method_id": method_id,
        "family": family,
        "name": name,
        "strategy": None,
        "model": None,
        "tool": {
            "name": "example-tool",
            "version": "0",
            "command_template": "example --check {file}",
            "rules": ["CWE-401"],
            "license": "example",
        },
        "config_sha256": None,
    }


def _provenance(source: str, index: int) -> dict:
    return {
        "produced_by": "make_examples.py",
        "created_at": CREATED,
        "source_artifact": source,
        "source_sha256": None,
        "record_index": index,
        "command_sha256": None,
        "legacy_run_id": None,
        "note": "synthetic schema example, not an experimental result",
    }


def _cost(usd: float | None, wall_s: float, basis: str) -> dict:
    return {
        "usd": usd,
        "wall_s": wall_s,
        "cpu_s": None,
        "peak_rss_mb": None,
        "currency": "USD",
        "cost_basis": basis,
        "pricing_snapshot": "synthetic",
        "note": "synthetic",
    }


def _usage(latency_ms: int) -> dict:
    return {
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "cached_prompt_tokens": 0,
        "reasoning_tokens": 0,
        "latency_ms": latency_ms,
        "api_attempts": 1,
    }


def _write_run(name: str, manifest: dict, records: list[dict]) -> None:
    directory = ROOT / name
    directory.mkdir(parents=True, exist_ok=True)
    predictions = directory / "predictions.jsonl"
    predictions.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )
    manifest = json.loads(json.dumps(manifest))
    manifest["hashes"]["predictions_sha256"] = sha256_file(predictions)
    (directory / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def make_detection() -> None:
    run_id = "example_detection_v1"
    records = [
        {
            "schema_version": "benchmark-prediction-v1",
            "run_id": run_id,
            "tier": "A",
            "track": "secvuleval",
            "task": "detection",
            "unit_id": "secvul:det:1",
            "cluster_id": PROJECT,
            "group_id": None,
            "side": None,
            "dataset": _base_dataset("secvul-demo", "test"),
            "method": _base_method("llm", "llm.example.direct", "Example LLM / direct", strategy="direct"),
            "input": {
                "view": "function",
                "source_sha256": ZERO_HASH,
                "prompt_sha256": ZERO_HASH,
                "context_mode": "none",
                "sanitized": True,
                "sanitizer_version": "synthetic",
                "evidence_sha256": None,
            },
            "label": {
                "y_true": True,
                "cwe": ["CWE-401"],
                "label_source": "secvuleval",
                "label_note": None,
            },
            "prediction": {
                "y_pred": True,
                "cwe_pred": ["CWE-401"],
                "confidence": 0.8,
                "evidence_lines": [12],
                "rationale": "synthetic example",
                "raw_output_sha256": None,
                "fixed_function": None,
            },
            "status": "ok",
            "error": None,
            "coverage": None,
            "usage": _usage(1200),
            "cost": _cost(0.0001, 1.2, "api_price"),
            "provenance": _provenance("examples/run_detection/predictions.jsonl", 0),
            "extensions": {"synthetic": True},
        }
    ]
    manifest = {
        "schema_version": "benchmark-run-v1",
        "run_id": run_id,
        "created_at": CREATED,
        "protocol_version": "1.0.0",
        "tier": "A",
        "track": "secvuleval",
        "tasks": ["detection"],
        "dataset": {
            "dataset_id": "secvul-demo",
            "split_id": "test",
            "path": "examples/run_detection/predictions.jsonl",
            "sha256": ZERO_HASH,
            "unit_manifest": None,
            "unit_count": 1,
            "group_count": 1,
            "label_counts": {"vulnerable": 1, "non_vulnerable": 0},
        },
        "method": _base_method("llm", "llm.example.direct", "Example LLM / direct", strategy="direct"),
        "execution": {
            "started_at": CREATED,
            "finished_at": CREATED,
            "status": "completed",
            "planned_units": 1,
            "recorded_units": 1,
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
        "hashes": {"predictions_sha256": ZERO_HASH},
        "legacy_import": None,
        "notes": ["synthetic schema example; not an experimental result"],
    }
    _write_run("run_detection", manifest, records)


def make_pair() -> None:
    run_id = "example_pair_v1"
    records = []
    for index, (side, label, prediction) in enumerate(
        [("vulnerable", True, True), ("fixed", False, False)]
    ):
        records.append(
            {
                "schema_version": "benchmark-prediction-v1",
                "run_id": run_id,
                "tier": "A",
                "track": "secvuleval",
                "task": "pair_detection",
                "unit_id": f"secvul:pair:demo:1:{side}",
                "cluster_id": "demo:1",
                "group_id": "demo:1",
                "side": side,
                "dataset": _base_dataset("secvul-demo-pairs", "test"),
                "method": _base_method("llm", "llm.example.direct", "Example LLM / direct", strategy="direct"),
                "input": {
                    "view": "function",
                    "source_sha256": ZERO_HASH,
                    "prompt_sha256": ZERO_HASH,
                    "context_mode": "none",
                    "sanitized": True,
                    "sanitizer_version": "synthetic",
                    "evidence_sha256": None,
                },
                "label": {
                    "y_true": label,
                    "cwe": ["CWE-401"],
                    "label_source": "secvuleval",
                    "label_note": None,
                },
                "prediction": {
                    "y_pred": prediction,
                    "cwe_pred": ["CWE-401"],
                    "confidence": 0.7,
                    "evidence_lines": [],
                    "rationale": "synthetic example",
                    "raw_output_sha256": None,
                    "fixed_function": None,
                },
                "status": "ok",
                "error": None,
                "coverage": None,
                "usage": _usage(1000),
                "cost": _cost(0.0001, 1.0, "api_price"),
                "provenance": _provenance("examples/run_pair/predictions.jsonl", index),
                "extensions": {"synthetic": True},
            }
        )
    manifest = {
        "schema_version": "benchmark-run-v1",
        "run_id": run_id,
        "created_at": CREATED,
        "protocol_version": "1.0.0",
        "tier": "A",
        "track": "secvuleval",
        "tasks": ["pair_detection"],
        "dataset": {
            "dataset_id": "secvul-demo-pairs",
            "split_id": "test",
            "path": "examples/run_pair/predictions.jsonl",
            "sha256": ZERO_HASH,
            "unit_manifest": None,
            "unit_count": 2,
            "group_count": 1,
            "label_counts": {"vulnerable": 1, "non_vulnerable": 1},
        },
        "method": _base_method("llm", "llm.example.direct", "Example LLM / direct", strategy="direct"),
        "execution": {
            "started_at": CREATED,
            "finished_at": CREATED,
            "status": "completed",
            "planned_units": 2,
            "recorded_units": 2,
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
        "hashes": {"predictions_sha256": ZERO_HASH},
        "legacy_import": None,
        "notes": ["synthetic schema example; not an experimental result"],
    }
    _write_run("run_pair", manifest, records)


def make_leak() -> None:
    run_id = "example_leak_v1"
    records = []
    for index, (side, label, prediction, consensus) in enumerate(
        [("bad", True, True, "leak"), ("good", False, False, "clean")]
    ):
        records.append(
            {
                "schema_version": "benchmark-prediction-v1",
                "run_id": run_id,
                "tier": "B",
                "track": "juliet_cwe401",
                "task": "leak_detection",
                "unit_id": f"juliet:CWE401_demo__01:{side}",
                "cluster_id": "CWE401_demo",
                "group_id": "CWE401_demo__01",
                "side": side,
                "dataset": _base_dataset("juliet-cwe401-demo", "test"),
                "method": _base_method("dynamic", "dynamic.example.lsan", "Example LSan"),
                "input": {
                    "view": "unit",
                    "source_sha256": ZERO_HASH,
                    "prompt_sha256": None,
                    "context_mode": "none",
                    "sanitized": True,
                    "sanitizer_version": "synthetic",
                    "evidence_sha256": None,
                },
                "label": {
                    "y_true": label,
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                "prediction": {
                    "y_pred": prediction,
                    "cwe_pred": ["CWE-401"],
                    "confidence": None,
                    "evidence_lines": [],
                    "rationale": None,
                    "raw_output_sha256": None,
                    "fixed_function": None,
                },
                "status": "ok",
                "error": None,
                "coverage": {
                    "unit_executed": True,
                    "target_function_entered": True,
                    "line_coverage": 1.0,
                    "branch_coverage": None,
                    "allocation_site_executed": True,
                    "free_site_executed": True,
                    "coverage_source": "gcov",
                    "notes": "synthetic",
                },
                "oracle": {
                    "reference": "juliet_intended",
                    "dynamic_consensus": consensus,
                    "lsan": consensus,
                    "valgrind": consensus,
                    "mismatch": False,
                    "note": "synthetic",
                },
                "usage": None,
                "cost": _cost(0.0, 0.2, "local_compute"),
                "provenance": _provenance("examples/run_leak/predictions.jsonl", index),
                "extensions": {"synthetic": True},
            }
        )
    manifest = {
        "schema_version": "benchmark-run-v1",
        "run_id": run_id,
        "created_at": CREATED,
        "protocol_version": "1.0.0",
        "tier": "B",
        "track": "juliet_cwe401",
        "tasks": ["leak_detection"],
        "dataset": {
            "dataset_id": "juliet-cwe401-demo",
            "split_id": "test",
            "path": "examples/run_leak/predictions.jsonl",
            "sha256": ZERO_HASH,
            "unit_manifest": None,
            "unit_count": 2,
            "group_count": 1,
            "label_counts": {"bad": 1, "good": 1},
        },
        "method": _base_method("dynamic", "dynamic.example.lsan", "Example LSan"),
        "execution": {
            "started_at": CREATED,
            "finished_at": CREATED,
            "status": "completed",
            "planned_units": 2,
            "recorded_units": 2,
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
        "hashes": {"predictions_sha256": ZERO_HASH},
        "legacy_import": None,
        "notes": ["synthetic schema example; not an experimental result"],
    }
    _write_run("run_leak", manifest, records)


def main() -> int:
    make_detection()
    make_pair()
    make_leak()
    print("wrote synthetic examples under", ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

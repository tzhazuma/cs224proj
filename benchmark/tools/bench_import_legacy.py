#!/usr/bin/env python3
"""Convert existing SecVulEval runner runs into the unified benchmark schema.

This is a read-only importer for the runner runs under ``runner/runs/``. It
recognises the DeepSeek V4.1 Flash and MiMo-V2.6-Flash runs and derives the
method identity from the run's own model ID. It copies the original
predictions and labels; it does not re-run a model, change a prediction, or
overwrite the source run. Repair records are counted and omitted because
repair correctness is outside the v1 detection benchmark.

The derived run is clearly marked with ``legacy_import.derived_not_rerun``.
Do not describe it as a new experiment.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    PREDICTION_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    RUN_SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    read_json,
    read_jsonl,
    sha256_file,
    sha256_text,
    utc_now,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPORT_VERSION = "bench-import-legacy-1.0.1"
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)

MODEL_LABELS = {
    "deepseek-v4.1-flash": ("deepseek", "DeepSeek V4.1 Flash"),
    "mimo-v2.6-flash": ("mimo", "MiMo-V2.6-Flash"),
}


def model_identity(model_id: object) -> tuple[str, str]:
    """Return (family, display name) for a runner model ID.

    The mapping is deliberately explicit for the two models used in this
    project; anything else keeps its raw ID instead of being mislabelled.
    """

    key = str(model_id or "").strip().lower()
    if key in MODEL_LABELS:
        return MODEL_LABELS[key]
    if key.startswith("mimo"):
        return "mimo", str(model_id)
    if key.startswith("deepseek"):
        return "deepseek", str(model_id)
    return "unknown", str(model_id or "unknown")


def split_cwes(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        for match in CWE_RE.finditer(item):
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in found:
                found.append(cwe)
    return found


def _resolve(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_dataset_index(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, dict[str, Any]]]]:
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: dataset must be an object")
    metadata = data.get("metadata") or {}
    detection: dict[str, dict[str, Any]] = {}
    pairs: dict[str, dict[str, dict[str, Any]]] = {}
    if isinstance(data.get("samples"), list):
        for sample in data["samples"]:
            if not isinstance(sample, dict) or "idx" not in sample:
                continue
            detection[str(sample["idx"])] = {
                "project": str(sample.get("project") or "unknown"),
                "label": bool(sample.get("is_vulnerable")),
                "cwe": split_cwes(sample.get("cwe_list")),
            }
    if isinstance(data.get("pairs"), list):
        for pair in data["pairs"]:
            if not isinstance(pair, dict) or "pair_id" not in pair:
                continue
            entry: dict[str, dict[str, Any]] = {}
            for side in ("vulnerable", "fixed"):
                member = pair.get(side) or {}
                entry[side] = {
                    "idx": str(member.get("idx", "")),
                    "project": str(member.get("project") or "unknown"),
                    "label": bool(member.get("is_vulnerable")),
                    "cwe": split_cwes(member.get("cwe_list")),
                }
            pairs[str(pair["pair_id"])] = entry
    return metadata, detection, pairs


def _status(record: Mapping[str, Any]) -> tuple[str, str | None]:
    raw = str(record.get("status") or "not_run")
    if raw == "ok":
        parsed = record.get("parsed")
        if isinstance(parsed, dict) and isinstance(parsed.get("is_vulnerable"), bool):
            return "ok", None
        return "schema_invalid", "status=ok but parsed.is_vulnerable is missing or not boolean"
    if raw == "invalid":
        return "schema_invalid", "legacy status=invalid"
    if raw in ("error", "api_error"):
        return "api_error", "legacy status=error"
    if raw in ("timeout", "tool_error", "compile_error", "harness_error", "crash", "unsupported"):
        return raw, f"legacy status={raw}"
    return "not_run", f"legacy status={raw}"


def _record_cost(record: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    response = record.get("response") or {}
    cost_block = response.get("cost") if isinstance(response, dict) else None
    cost_block = cost_block if isinstance(cost_block, dict) else {}
    response_usage = response.get("usage") if isinstance(response, dict) else None
    response_usage = response_usage if isinstance(response_usage, dict) else {}
    token_details = response_usage.get("completion_tokens_details")
    reasoning_tokens = (
        token_details.get("reasoning_tokens") if isinstance(token_details, dict) else None
    )
    usage = {
        "prompt_tokens": cost_block.get("prompt_tokens"),
        "completion_tokens": cost_block.get("completion_tokens"),
        "cached_prompt_tokens": cost_block.get("cached_prompt_tokens"),
        "reasoning_tokens": (
            reasoning_tokens if isinstance(reasoning_tokens, int) else None
        ),
        "latency_ms": None,
        "api_attempts": None,
    }
    attempts = response.get("attempts") if isinstance(response, dict) else None
    if isinstance(attempts, list) and attempts:
        usage["api_attempts"] = len(attempts)
        last = attempts[-1]
        if isinstance(last, dict) and isinstance(last.get("latency_seconds"), (int, float)):
            usage["latency_ms"] = float(last["latency_seconds"]) * 1000.0
    if usage["latency_ms"] is None:
        request_latency = response.get("request_latency_seconds")
        if isinstance(request_latency, (int, float)):
            usage["latency_ms"] = float(request_latency) * 1000.0
    wall_seconds = response.get("wall_seconds") if isinstance(response, dict) else None
    if not isinstance(wall_seconds, (int, float)):
        wall_seconds = (
            usage["latency_ms"] / 1000.0 if usage["latency_ms"] is not None else None
        )
    cost = {
        "usd": cost_block.get("cost_usd") if isinstance(cost_block.get("cost_usd"), (int, float)) else None,
        "wall_s": float(wall_seconds) if isinstance(wall_seconds, (int, float)) else None,
        "cpu_s": None,
        "peak_rss_mb": None,
        "currency": "USD",
        "cost_basis": "api_price",
        "pricing_snapshot": None,
    }
    return usage, cost


def convert_run(
    run_dir: Path,
    out_dir: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    metrics_path = run_dir / "metrics.json"
    results_path = run_dir / "results.jsonl"
    config_path = run_dir / "config.json"
    for path in (manifest_path, metrics_path, results_path):
        if not path.exists():
            raise FileNotFoundError(f"missing legacy artifact: {path}")

    legacy_manifest = read_json(manifest_path)
    legacy_metrics = read_json(metrics_path)
    config = read_json(config_path) if config_path.exists() else {}
    run = legacy_metrics.get("run") or {}
    model_id = str(run.get("model") or "")
    model_family, model_name = model_identity(model_id)
    strategy = str(run.get("strategy") or "unknown")
    method_id = f"llm.{model_family}.{strategy}"
    method_name = f"{model_name} / {strategy}"
    api_config = config.get("api") or {}
    dataset_path = _resolve(str(run.get("dataset_path") or ""))
    if not dataset_path.exists():
        raise FileNotFoundError(f"dataset not found: {dataset_path}")
    dataset_metadata, detection_index, pair_index = load_dataset_index(dataset_path)

    records = read_jsonl(results_path)
    predictions: list[dict[str, Any]] = []
    repair_omitted = 0
    omitted_task_counts: dict[str, int] = {}
    retry_count = 0
    dataset_type = str(run.get("dataset_type") or "")
    for index, record in enumerate(records):
        if record.get("task") != "detection":
            omitted_task = str(record.get("task") or "unknown")
            omitted_task_counts[omitted_task] = omitted_task_counts.get(omitted_task, 0) + 1
            if omitted_task == "repair":
                repair_omitted += 1
            continue
        status, error_message = _status(record)
        parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
        y_pred = parsed.get("is_vulnerable") if status == "ok" else None
        confidence = parsed.get("confidence") if isinstance(parsed.get("confidence"), (int, float)) else None
        rationale = parsed.get("rationale") if isinstance(parsed.get("rationale"), str) else None
        usage, cost = _record_cost(record)
        attempts = usage.get("api_attempts")
        if isinstance(attempts, int) and attempts > 1:
            retry_count += attempts - 1

        pair_id = record.get("pair_id")
        side = record.get("side")
        idx = record.get("idx")
        if dataset_type == "pairs":
            if not pair_id or side not in ("vulnerable", "fixed"):
                raise ValueError(f"{results_path}:{index + 1}: pair record lacks pair_id/side")
            pair_entry = pair_index.get(str(pair_id))
            if pair_entry is None:
                raise ValueError(f"{results_path}:{index + 1}: unknown pair_id {pair_id!r}")
            member = pair_entry[side]
            y_true = member["label"]
            cluster_id = str(pair_id)
            unit_id = f"secvul:pair:{pair_id}:{side}"
            task = "pair_detection"
            group_id = str(pair_id)
            cwe = member["cwe"]
            source_sha256 = None
        else:
            if idx is None:
                raise ValueError(f"{results_path}:{index + 1}: detection record lacks idx")
            entry = detection_index.get(str(idx))
            if entry is None:
                raise ValueError(f"{results_path}:{index + 1}: unknown idx {idx!r}")
            y_true = entry["label"]
            cluster_id = entry["project"]
            unit_id = f"secvul:det:{idx}"
            task = "detection"
            group_id = None
            cwe = entry["cwe"]
            source_sha256 = None

        prompt = record.get("prompt") or {}
        function_block = prompt.get("function") if isinstance(prompt, dict) else {}
        request = record.get("request") or {}
        if isinstance(function_block, dict):
            source_sha256 = function_block.get("code_sha256")
        prompt_sha256 = request.get("body_sha256") if isinstance(request, dict) else None
        raw_content = (record.get("response") or {}).get("content")
        raw_output_sha256 = sha256_text(raw_content) if isinstance(raw_content, str) else None
        created_at = record.get("created_at") or utc_now()

        prediction_record = {
            "schema_version": PREDICTION_SCHEMA_VERSION,
            "run_id": f"legacy__{run.get('run_id') or run_dir.name}",
            "tier": "A",
            "track": "secvuleval",
            "task": task,
            "unit_id": unit_id,
            "cluster_id": cluster_id,
            "group_id": group_id,
            "side": side if task == "pair_detection" else None,
            "dataset": {
                "dataset_id": str((dataset_metadata.get("split") or {}).get("split_id") or "secvul-split-v1"),
                "split_id": str((dataset_metadata.get("split") or {}).get("split_id") or "secvul-split-v1"),
                "sha256": str(run.get("dataset_sha256") or sha256_file(dataset_path)),
                "unit_manifest_sha256": None,
            },
            "method": {
                "method_id": method_id,
                "family": "llm",
                "name": method_name,
                "strategy": strategy,
                "model": {
                    "model_id": model_id,
                    "family": model_family,
                    "provider": "opencode-go",
                    "endpoint": str(run.get("base_url") or ""),
                    "version": None,
                    "context_window": None,
                    "tokenizer": None,
                    "decoding": {
                        "temperature": api_config.get("temperature"),
                        "max_tokens": api_config.get("max_tokens"),
                        "max_tokens_field": api_config.get("max_tokens_field") or "max_tokens",
                        "thinking": api_config.get("thinking"),
                        "reasoning_effort": api_config.get("reasoning_effort"),
                        "response_format": api_config.get("response_format"),
                        "timeout_seconds": api_config.get("timeout_seconds"),
                    },
                    "pricing_usd_per_1m": {
                        "input": api_config.get("input_price_usd_per_1m"),
                        "output": api_config.get("output_price_usd_per_1m"),
                        "cached_input": api_config.get("cached_input_price_usd_per_1m"),
                    },
                    "price_snapshot": None,
                },
                "tool": None,
                "config_sha256": run.get("config_fingerprint"),
            },
            "input": {
                "view": "function",
                "source_sha256": source_sha256,
                "prompt_sha256": prompt_sha256,
                "context_mode": "project" if run.get("strategy") == "context" else "none",
                "sanitized": True,
                "sanitizer_version": "legacy-runner-1.0.0",
                "evidence_sha256": None,
            },
            "label": {
                "y_true": y_true,
                "cwe": cwe,
                "label_source": "secvuleval",
                "label_note": None,
            },
            "prediction": {
                "y_pred": y_pred,
                "cwe_pred": [],
                "confidence": confidence,
                "evidence_lines": [],
                "rationale": rationale,
                "raw_output_sha256": raw_output_sha256,
                "fixed_function": None,
            },
            "status": status,
            "error": (
                None
                if status == "ok"
                else {
                    "type": status,
                    "message": error_message or "legacy failure",
                    "retryable": False,
                    "attempt": None,
                    "http_status": None,
                }
            ),
            "coverage": None,
            "usage": usage,
            "cost": cost,
            "provenance": {
                "produced_by": IMPORT_VERSION,
                "created_at": str(created_at),
                "source_artifact": str(results_path.relative_to(PROJECT_ROOT)),
                "source_sha256": sha256_file(results_path),
                "record_index": index,
                "command_sha256": None,
                "legacy_run_id": str(run.get("run_id") or run_dir.name),
                "note": "prediction and label copied from the legacy run; not re-run",
            },
            "extensions": {
                "legacy": {
                    "sample_id": record.get("sample_id"),
                    "request_fingerprint": request.get("request_fingerprint") if isinstance(request, dict) else None,
                    "legacy_task": record.get("task"),
                }
            },
        }
        predictions.append(prediction_record)

    if not predictions:
        raise ValueError(f"{run_dir}: no detection records found")

    run_id = f"legacy__{run.get('run_id') or run_dir.name}"
    tasks = sorted({record["task"] for record in predictions})
    predictions_path = out_dir / "predictions.jsonl"
    out_dir.mkdir(parents=True, exist_ok=True)
    if not force and any(out_dir.iterdir()):
        raise FileExistsError(f"{out_dir} is not empty; pass --force to replace derived artifacts")
    atomic_write_text(
        predictions_path,
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in predictions),
    )

    legacy_counts = legacy_metrics.get("counts") or {}
    legacy_cost = legacy_metrics.get("cost") or {}
    full_run_cost = legacy_cost.get("total_cost_usd")
    if not isinstance(full_run_cost, (int, float)):
        full_run_cost = legacy_cost.get("known_cost_usd")
    recorded_requests = legacy_counts.get("records")
    expected_requests = legacy_counts.get("expected_requests")
    complete = bool(legacy_counts.get("complete_planned_requests", True))
    if isinstance(recorded_requests, int) and isinstance(expected_requests, int):
        complete = complete and recorded_requests >= expected_requests
    execution_status = "completed" if complete and not config.get("partial") else "partial"

    manifest = {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "protocol_version": PROTOCOL_VERSION,
        "tier": "A",
        "track": "secvuleval",
        "tasks": tasks,
        "dataset": {
            "dataset_id": str((dataset_metadata.get("split") or {}).get("split_id") or "secvul-split-v1"),
            "split_id": str((dataset_metadata.get("split") or {}).get("split_id") or "secvul-split-v1"),
            "path": str(run.get("dataset_path") or ""),
            "sha256": str(run.get("dataset_sha256") or sha256_file(dataset_path)),
            "unit_manifest": None,
            "unit_count": len(predictions),
            "group_count": (
                int(run.get("dataset_units")) if dataset_type == "pairs" else len(predictions)
            ),
            "label_counts": (run.get("dataset_label_counts") or {}),
        },
        "method": {
            "method_id": method_id,
            "family": "llm",
            "name": method_name,
            "strategy": strategy,
            "prompt_version": run.get("prompt_version"),
            "config_sha256": run.get("config_fingerprint"),
            "model": {
                "model_id": model_id,
                "family": model_family,
                "provider": "opencode-go",
                "endpoint": str(run.get("base_url") or ""),
                "version": None,
                "decoding": {
                    "temperature": api_config.get("temperature"),
                    "max_tokens": api_config.get("max_tokens"),
                    "max_tokens_field": api_config.get("max_tokens_field") or "max_tokens",
                    "thinking": api_config.get("thinking"),
                    "reasoning_effort": api_config.get("reasoning_effort"),
                    "response_format": api_config.get("response_format"),
                    "timeout_seconds": api_config.get("timeout_seconds"),
                },
                "pricing_usd_per_1m": {
                    "input": api_config.get("input_price_usd_per_1m"),
                    "output": api_config.get("output_price_usd_per_1m"),
                    "cached_input": api_config.get("cached_input_price_usd_per_1m"),
                },
                "price_snapshot": None,
            },
            "tool": None,
        },
        "execution": {
            "started_at": legacy_manifest.get("started_at"),
            "finished_at": legacy_manifest.get("completed_at"),
            "status": execution_status,
            "planned_units": len(predictions),
            "recorded_units": len(predictions),
            "retries": retry_count,
            "concurrency": config.get("concurrency"),
            "command": None,
            "command_sha256": None,
            "environment": {
                "python_version": legacy_manifest.get("python_version"),
                "platform": legacy_manifest.get("platform"),
            },
        },
        "artifacts": {
            "predictions": "predictions.jsonl",
            "metrics": "metrics.json",
            "validation": None,
            "log": None,
        },
        "hashes": {
            "predictions_sha256": sha256_file(predictions_path),
            "source_results_sha256": sha256_file(results_path),
            "source_metrics_sha256": sha256_file(metrics_path),
        },
        "legacy_import": {
            "source_run_dir": str(run_dir),
            "source_results_sha256": sha256_file(results_path),
            "conversion_tool": IMPORT_VERSION,
            "derived_not_rerun": True,
            "repair_records_omitted": repair_omitted,
            "omitted_task_counts": omitted_task_counts,
            "full_run_cost_usd": full_run_cost,
            "full_run_requests": recorded_requests,
            "model_id": model_id,
            "model_family": model_family,
            "strategy": strategy,
        },
        "notes": [
            "Derived from an existing runner run; no model call and no prediction change.",
            "Repair records are omitted; this run is for the v1 detection/pair benchmark only.",
            "Legacy metrics are valid-only; the unified metrics recompute both valid-only and strict views.",
            "Cost sums on this run cover the imported task only; full_run_cost_usd preserves the original run total.",
            (
                "MiMo uses reasoning_effort=none with max_completion_tokens on OpenCode Go; "
                "this is a model/configuration difference from the DeepSeek non-thinking runs."
                if model_family == "mimo"
                else "DeepSeek run uses thinking disabled, temperature 0, max_tokens=8192."
            ),
        ],
    }
    atomic_write_json(out_dir / "run_manifest.json", manifest)
    atomic_write_text(
        out_dir / "PROVENANCE.md",
        "\n".join(
            [
                f"# Legacy import: `{run_id}`",
                "",
                f"- source run: `{run_dir}`",
                f"- source results SHA-256: `{sha256_file(results_path)}`",
                f"- source metrics SHA-256: `{sha256_file(metrics_path)}`",
                f"- conversion tool: `{IMPORT_VERSION}`",
                f"- derived model: `{model_id}` ({model_family})",
                f"- derived strategy: `{strategy}`",
                "- derived, not re-run; predictions and labels are copied record by record",
                f"- omitted task records: {omitted_task_counts}",
                f"- full source-run cost (all tasks): {full_run_cost}",
                "",
            ]
        ),
    )
    return {
        "run_id": run_id,
        "out_dir": str(out_dir),
        "records": len(predictions),
        "repair_omitted": repair_omitted,
        "omitted_task_counts": omitted_task_counts,
        "model_id": model_id,
        "model_family": model_family,
        "strategy": strategy,
        "tasks": tasks,
        "full_run_cost_usd": full_run_cost,
        "predictions_sha256": sha256_file(predictions_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="legacy runner run directory")
    parser.add_argument(
        "--out-dir",
        help="derived run directory (default: benchmark/results/tier_a/imported/<run_id>)",
    )
    parser.add_argument("--force", action="store_true", help="replace a non-empty derived directory")
    args = parser.parse_args(argv)

    source = Path(args.run_dir).resolve()
    default_name = source.name
    out_dir = (
        Path(args.out_dir).resolve()
        if args.out_dir
        else PROJECT_ROOT / "benchmark" / "results" / "tier_a" / "imported" / default_name
    )
    try:
        summary = convert_run(source, out_dir, force=args.force)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"import failed: {exc}\n")
        return 2
    sys.stderr.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

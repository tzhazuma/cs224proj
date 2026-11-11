#!/usr/bin/env python3
"""Validate one unified-benchmark run directory.

The validator is deliberately standard-library-only. It checks the invariants
that the JSON Schema cannot express cheaply (duplicate unit IDs, pair
completeness, status/label consistency, coverage presence for dynamic leak
runs, planned-vs-recorded counts). Optional ``--jsonschema`` validates the
same files against ``benchmark/schemas/`` when the package is installed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    FAMILIES,
    PREDICTION_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    RUN_SCHEMA_VERSION,
    STATUSES,
    TASKS,
    as_bool,
    is_number,
    read_json,
    read_jsonl,
    sha256_file,
    utc_now,
)

VALIDATION_SCHEMA_VERSION = "benchmark-validation-v1"
HEX64 = "0123456789abcdef"


def _error(report: dict[str, Any], message: str) -> None:
    report["errors"].append(message)


def _warning(report: dict[str, Any], message: str) -> None:
    report["warnings"].append(message)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in HEX64 for c in value)


def _check_manifest(report: dict[str, Any], manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != RUN_SCHEMA_VERSION:
        _error(report, f"manifest.schema_version must be {RUN_SCHEMA_VERSION!r}")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        _error(report, "manifest.run_id is required")
    if manifest.get("protocol_version") != PROTOCOL_VERSION:
        _warning(
            report,
            f"manifest.protocol_version is {manifest.get('protocol_version')!r}, "
            f"validator speaks {PROTOCOL_VERSION!r}",
        )
    if manifest.get("tier") not in ("A", "B"):
        _error(report, "manifest.tier must be A or B")
    if manifest.get("track") not in ("secvuleval", "juliet_cwe401"):
        _error(report, "manifest.track must be secvuleval or juliet_cwe401")

    dataset = manifest.get("dataset")
    if not isinstance(dataset, dict):
        _error(report, "manifest.dataset is required")
    else:
        for key in ("dataset_id", "split_id", "path"):
            if not isinstance(dataset.get(key), str) or not dataset[key]:
                _error(report, f"manifest.dataset.{key} is required")
        if not _is_sha256(dataset.get("sha256")):
            _error(report, "manifest.dataset.sha256 must be 64 lowercase hex characters")
        if not isinstance(dataset.get("unit_count"), int) or dataset.get("unit_count", -1) < 0:
            _error(report, "manifest.dataset.unit_count must be a non-negative integer")

    method = manifest.get("method")
    if not isinstance(method, dict):
        _error(report, "manifest.method is required")
    else:
        if method.get("family") not in FAMILIES:
            _error(report, f"manifest.method.family must be one of {FAMILIES}")
        if not isinstance(method.get("method_id"), str) or not method["method_id"]:
            _error(report, "manifest.method.method_id is required")
        if not isinstance(method.get("name"), str) or not method["name"]:
            _error(report, "manifest.method.name is required")
        if method.get("family") == "llm" and not isinstance(method.get("model"), dict):
            _error(report, "manifest.method.model is required for family=llm")
        if method.get("family") in ("static", "dynamic") and not isinstance(method.get("tool"), dict):
            _error(report, f"manifest.method.tool is required for family={method.get(family)}")

    execution = manifest.get("execution")
    if not isinstance(execution, dict):
        _error(report, "manifest.execution is required")
    else:
        if execution.get("status") not in ("running", "completed", "partial", "failed"):
            _error(report, "manifest.execution.status is invalid")
        for key in ("planned_units", "recorded_units"):
            if not isinstance(execution.get(key), int) or execution.get(key, -1) < 0:
                _error(report, f"manifest.execution.{key} must be a non-negative integer")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not isinstance(artifacts.get("predictions"), str):
        _error(report, "manifest.artifacts.predictions is required")
    if not isinstance(manifest.get("hashes"), dict):
        _error(report, "manifest.hashes is required")

    tasks = manifest.get("tasks")
    if tasks is not None:
        if not isinstance(tasks, list) or any(t not in TASKS for t in tasks):
            _error(report, f"manifest.tasks must be a subset of {TASKS}")


def _check_coverage(report: dict[str, Any], record: dict[str, Any]) -> None:
    coverage = record.get("coverage")
    if coverage is None:
        return
    if not isinstance(coverage, dict):
        _error(report, f"{record.get('unit_id')}: coverage must be an object or null")
        return
    if coverage.get("unit_executed") not in (True, False, None):
        _error(report, f"{record.get('unit_id')}: coverage.unit_executed must be boolean or null")
    if coverage.get("target_function_entered") not in (True, False, None):
        _error(
            report,
            f"{record.get('unit_id')}: coverage.target_function_entered must be boolean or null",
        )
    value = coverage.get("line_coverage")
    if value is not None and (not is_number(value) or not 0.0 <= float(value) <= 1.0):
        _error(report, f"{record.get('unit_id')}: coverage.line_coverage must be in [0,1] or null")


def _check_cost_usage(report: dict[str, Any], record: dict[str, Any]) -> None:
    unit_id = record.get("unit_id")
    cost = record.get("cost")
    if cost is not None:
        if not isinstance(cost, dict):
            _error(report, f"{unit_id}: cost must be an object or null")
        else:
            usd = cost.get("usd")
            if usd is not None and (not is_number(usd) or float(usd) < 0):
                _error(report, f"{unit_id}: cost.usd must be non-negative or null")
            for key in ("wall_s", "cpu_s", "peak_rss_mb"):
                value = cost.get(key)
                if value is not None and (not is_number(value) or float(value) < 0):
                    _error(report, f"{unit_id}: cost.{key} must be non-negative or null")
            if not isinstance(cost.get("currency"), str):
                _error(report, f"{unit_id}: cost.currency is required")
            if cost.get("cost_basis") not in (
                "api_price",
                "local_compute",
                "license",
                "mixed",
                "unknown",
            ):
                _error(report, f"{unit_id}: cost.cost_basis is invalid")
    usage = record.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            _error(report, f"{unit_id}: usage must be an object or null")
        else:
            for key in (
                "prompt_tokens",
                "completion_tokens",
                "cached_prompt_tokens",
                "reasoning_tokens",
            ):
                value = usage.get(key)
                if value is not None and (
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                ):
                    _error(report, f"{unit_id}: usage.{key} must be a non-negative integer or null")
            latency = usage.get("latency_ms")
            if latency is not None and (not is_number(latency) or float(latency) < 0):
                _error(report, f"{unit_id}: usage.latency_ms must be non-negative or null")


def _check_record(
    report: dict[str, Any],
    record: dict[str, Any],
    manifest: dict[str, Any],
    *,
    strict: bool,
) -> None:
    unit_id = record.get("unit_id", "<missing unit_id>")
    required = (
        "schema_version",
        "run_id",
        "tier",
        "track",
        "task",
        "unit_id",
        "cluster_id",
        "dataset",
        "method",
        "input",
        "label",
        "prediction",
        "status",
        "provenance",
    )
    for key in required:
        if key not in record:
            _error(report, f"{unit_id}: missing required field {key!r}")
    if record.get("schema_version") != PREDICTION_SCHEMA_VERSION:
        _error(report, f"{unit_id}: schema_version must be {PREDICTION_SCHEMA_VERSION!r}")
    if record.get("run_id") != manifest.get("run_id"):
        _error(report, f"{unit_id}: run_id does not match manifest")
    if record.get("tier") != manifest.get("tier"):
        _error(report, f"{unit_id}: tier does not match manifest")
    if record.get("track") != manifest.get("track"):
        _error(report, f"{unit_id}: track does not match manifest")
    task = record.get("task")
    if task not in TASKS:
        _error(report, f"{unit_id}: task must be one of {TASKS}")
    if isinstance(manifest.get("tasks"), list) and task not in manifest["tasks"]:
        _error(report, f"{unit_id}: task {task!r} is not declared in manifest.tasks")
    if not isinstance(record.get("unit_id"), str) or not record.get("unit_id"):
        _error(report, f"{unit_id}: unit_id must be a non-empty string")
    if not isinstance(record.get("cluster_id"), str) or not record.get("cluster_id"):
        _error(report, f"{unit_id}: cluster_id must be a non-empty string")

    dataset = record.get("dataset")
    manifest_dataset = manifest.get("dataset") or {}
    if not isinstance(dataset, dict):
        _error(report, f"{unit_id}: dataset must be an object")
    elif dataset.get("sha256") != manifest_dataset.get("sha256"):
        _error(report, f"{unit_id}: dataset.sha256 does not match manifest")

    method = record.get("method")
    if not isinstance(method, dict):
        _error(report, f"{unit_id}: method must be an object")
    else:
        if method.get("family") not in FAMILIES:
            _error(report, f"{unit_id}: method.family is invalid")
        if not isinstance(method.get("method_id"), str) or not method["method_id"]:
            _error(report, f"{unit_id}: method.method_id is required")
        if method.get("family") == "llm" and not isinstance(method.get("model"), dict):
            _error(report, f"{unit_id}: method.model is required for family=llm")
        if method.get("family") in ("static", "dynamic") and not isinstance(method.get("tool"), dict):
            _error(report, f"{unit_id}: method.tool is required for family={method.get(family)}")

    input_block = record.get("input")
    if not isinstance(input_block, dict):
        _error(report, f"{unit_id}: input must be an object")
    else:
        if input_block.get("view") not in ("function", "unit", "file", "pair", "other"):
            _error(report, f"{unit_id}: input.view is invalid")
        if not isinstance(input_block.get("sanitized"), bool):
            _error(report, f"{unit_id}: input.sanitized must be boolean")

    label = record.get("label")
    y_true = None
    if not isinstance(label, dict):
        _error(report, f"{unit_id}: label must be an object")
    else:
        y_true = as_bool(label.get("y_true"))
        if y_true is None:
            _error(report, f"{unit_id}: label.y_true must be boolean or 0/1")
        if label.get("label_source") not in (
            "secvuleval",
            "juliet_intended",
            "dynamic_consensus",
            "manual",
        ):
            _error(report, f"{unit_id}: label.label_source is invalid")

    prediction = record.get("prediction")
    y_pred = None
    if not isinstance(prediction, dict):
        _error(report, f"{unit_id}: prediction must be an object")
    else:
        y_pred = as_bool(prediction.get("y_pred"))
        raw = prediction.get("y_pred")
        if raw is not None and y_pred is None:
            _error(report, f"{unit_id}: prediction.y_pred must be boolean, 0/1, or null")
        confidence = prediction.get("confidence")
        if confidence is not None and (
            not is_number(confidence) or not 0.0 <= float(confidence) <= 1.0
        ):
            _error(report, f"{unit_id}: prediction.confidence must be in [0,1] or null")

    status = record.get("status")
    if status not in STATUSES:
        _error(report, f"{unit_id}: status is invalid")
    if status == "ok" and y_pred is None:
        _error(report, f"{unit_id}: status=ok requires a non-null prediction.y_pred")
    if status != "ok" and y_pred is not None:
        _error(report, f"{unit_id}: status!=ok requires prediction.y_pred=null")

    if task == "pair_detection":
        if not record.get("group_id"):
            _error(report, f"{unit_id}: pair_detection requires group_id")
        side = record.get("side")
        if side not in ("vulnerable", "fixed"):
            _error(report, f"{unit_id}: pair_detection side must be vulnerable or fixed")
        if y_true is not None and side == "vulnerable" and not y_true:
            _warning(report, f"{unit_id}: vulnerable side has y_true=false")
        if y_true is not None and side == "fixed" and y_true:
            _warning(report, f"{unit_id}: fixed side has y_true=true")
    elif task == "leak_detection":
        if not record.get("group_id"):
            _error(report, f"{unit_id}: leak_detection requires group_id")
        side = record.get("side")
        if side not in ("bad", "good"):
            _error(report, f"{unit_id}: leak_detection side must be bad or good")
        if y_true is not None and side == "bad" and not y_true:
            _warning(report, f"{unit_id}: bad variant has y_true=false")
        if y_true is not None and side == "good" and y_true:
            _warning(report, f"{unit_id}: good variant has y_true=true")
        if isinstance(method, dict) and method.get("family") == "dynamic":
            if record.get("coverage") is None:
                _error(report, f"{unit_id}: dynamic leak_detection requires coverage")
    elif task == "detection":
        if record.get("group_id") not in (None, ""):
            _warning(report, f"{unit_id}: detection has a non-null group_id")
        if record.get("side") not in (None, ""):
            _warning(report, f"{unit_id}: detection has a non-null side")

    _check_coverage(report, record)
    _check_cost_usage(report, record)

    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        _error(report, f"{unit_id}: provenance must be an object")
    else:
        for key in ("produced_by", "created_at", "source_artifact"):
            if not isinstance(provenance.get(key), str) or not provenance[key]:
                _error(report, f"{unit_id}: provenance.{key} is required")

    if strict and status in ("not_run", "skipped_budget"):
        _warning(report, f"{unit_id}: strict mode sees {status} as an incomplete unit")


def validate_run(
    run_dir: str | Path,
    *,
    strict: bool = False,
    use_jsonschema: bool = False,
    schema_dir: str | Path | None = None,
) -> dict[str, Any]:
    directory = Path(run_dir).resolve()
    report: dict[str, Any] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "checked_at": utc_now(),
        "run_dir": str(directory),
        "ok": False,
        "errors": [],
        "warnings": [],
        "counts": {},
        "hashes": {},
    }

    manifest_path = directory / "run_manifest.json"
    if not manifest_path.exists():
        _error(report, f"missing run_manifest.json in {directory}")
        return report
    try:
        manifest = read_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        _error(report, f"cannot read run_manifest.json: {exc}")
        return report
    if not isinstance(manifest, dict):
        _error(report, "run_manifest.json must be an object")
        return report

    report["hashes"]["run_manifest_sha256"] = sha256_file(manifest_path)
    _check_manifest(report, manifest)

    predictions_name = (manifest.get("artifacts") or {}).get("predictions") or "predictions.jsonl"
    predictions_path = directory / predictions_name
    if not predictions_path.exists():
        _error(report, f"missing predictions file: {predictions_path}")
        return report
    report["hashes"]["predictions_sha256"] = sha256_file(predictions_path)
    try:
        records = read_jsonl(predictions_path)
    except (OSError, Exception) as exc:  # BenchError carries line context
        _error(report, f"cannot read predictions: {exc}")
        return report

    if use_jsonschema:
        try:
            import jsonschema  # type: ignore
        except ImportError:
            _warning(report, "jsonschema is not installed; skipped schema validation")
        else:
            base = Path(schema_dir) if schema_dir else Path(__file__).resolve().parents[1] / "schemas"
            for filename, value in (
                ("run_manifest.schema.json", manifest),
                ("prediction.schema.json", None),
            ):
                schema_path = base / filename
                if not schema_path.exists():
                    _warning(report, f"schema not found: {schema_path}")
                    continue
                try:
                    schema = read_json(schema_path)
                    if value is None:
                        for index, record in enumerate(records, start=1):
                            try:
                                jsonschema.validate(record, schema)
                            except jsonschema.ValidationError as exc:
                                _error(report, f"record {index}: {exc.message}")
                    else:
                        try:
                            jsonschema.validate(value, schema)
                        except jsonschema.ValidationError as exc:
                            _error(report, f"manifest: {exc.message}")
                except (OSError, json.JSONDecodeError) as exc:
                    _warning(report, f"cannot load schema {schema_path}: {exc}")

    seen: dict[str, int] = {}
    by_task: dict[str, int] = {}
    by_status: dict[str, int] = {}
    groups: dict[str, set[str]] = {}
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            _error(report, f"record {index}: must be an object")
            continue
        unit_id = str(record.get("unit_id") or f"<record {index}>")
        if unit_id in seen:
            _error(report, f"duplicate unit_id {unit_id!r} (records {seen[unit_id]} and {index})")
        else:
            seen[unit_id] = index
        by_task[str(record.get("task"))] = by_task.get(str(record.get("task")), 0) + 1
        by_status[str(record.get("status"))] = by_status.get(str(record.get("status")), 0) + 1
        _check_record(report, record, manifest, strict=strict)
        task = record.get("task")
        if task in ("pair_detection", "leak_detection"):
            group_id = str(record.get("group_id") or "")
            side = str(record.get("side") or "")
            if group_id:
                groups.setdefault(group_id, set()).add(side)

    for group_id, sides in groups.items():
        expected = {"vulnerable", "fixed"} if any(
            r.get("task") == "pair_detection" and r.get("group_id") == group_id
            for r in records
        ) else {"bad", "good"}
        if sides != expected:
            message = f"group {group_id!r} has sides {sorted(sides)}, expected {sorted(expected)}"
            if strict:
                _error(report, message)
            else:
                _warning(report, message)

    execution = manifest.get("execution") or {}
    planned = execution.get("planned_units")
    recorded = execution.get("recorded_units")
    report["counts"] = {
        "records": len(records),
        "unique_units": len(seen),
        "by_task": by_task,
        "by_status": by_status,
        "groups": len(groups),
        "planned_units": planned,
        "recorded_units": recorded,
    }
    if isinstance(planned, int) and planned != len(records):
        message = f"manifest.planned_units={planned} but predictions has {len(records)} records"
        if strict and execution.get("status") == "completed":
            _error(report, message)
        else:
            _warning(report, message)
    if isinstance(recorded, int) and recorded != len(records):
        _error(report, f"manifest.recorded_units={recorded} but predictions has {len(records)} records")
    if execution.get("status") == "completed" and isinstance(planned, int) and planned != len(records):
        _warning(report, "completed run does not cover all planned units; mark it partial")

    report["ok"] = not report["errors"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="directory containing run_manifest.json")
    parser.add_argument("--json-out", help="write validation report to this path (default: stdout only)")
    parser.add_argument("--strict", action="store_true", help="treat group/count anomalies as errors")
    parser.add_argument(
        "--jsonschema",
        action="store_true",
        help="also validate against benchmark/schemas using the jsonschema package",
    )
    parser.add_argument("--schema-dir", help="schema directory (default: benchmark/schemas)")
    args = parser.parse_args(argv)

    report = validate_run(
        args.run_dir,
        strict=args.strict,
        use_jsonschema=args.jsonschema,
        schema_dir=args.schema_dir,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.json_out:
        from bench_common import atomic_write_text

        atomic_write_text(args.json_out, text)
    else:
        sys.stdout.write(text)

    if report["errors"]:
        sys.stderr.write(f"validation failed: {len(report['errors'])} error(s)\n")
        return 2
    sys.stderr.write(
        f"validation ok: {report['counts'].get('records', 0)} records, "
        f"{len(report['warnings'])} warning(s)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

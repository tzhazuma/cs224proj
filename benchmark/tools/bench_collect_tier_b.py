#!/usr/bin/env python3
"""Materialise Tier B static/dynamic results as unified benchmark runs.

The static adapter and the dynamic evaluator own their raw artifacts. This
collector only reads those artifacts and maps them onto the frozen Juliet
CWE-401 subset (``juliet/subset_units.jsonl``). It never changes a source
prediction and never overwrites the source run.

Output: one immutable run directory per method under
``benchmark/results/tier_b/juliet_cwe401/`` with ``run_manifest.json`` and
``predictions.jsonl``. Metrics are computed separately with
``bench_metrics.py`` so the same arithmetic is used for every tier.

Static compile failures are kept as ``status="compile_error"`` with a null
prediction. They are not converted to ``y_pred=0``.

Dynamic clean results are kept as ``y_pred=false`` with
``coverage.line_coverage=null`` and ``coverage_source="none"``. The summary
tool reports an operational view and a conservative view, because this run
did not instrument line coverage and a clean observation is not proof of
safety.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

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
COLLECTOR_VERSION = "bench-collect-tier-b-1.0.0"
DATASET_ID = "juliet-cwe401-v1.3-subset-v1"
TRACK = "juliet_cwe401"


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def _normalise_source(value: str) -> str:
    text = str(value).replace("\\", "/")
    marker = "raw/testcases/"
    if marker in text:
        return text[text.index(marker) :]
    return text


def _unit_id(group_id: str, side: str) -> str:
    return f"juliet:{group_id}:{side}"


def _runtime_supported(manifest_unit: Mapping[str, Any]) -> bool:
    label = str(manifest_unit.get("label") or "")
    runtime = manifest_unit.get("runtime_check") or {}
    leak = runtime.get("leak_detected")
    if label == "bad":
        return leak is True
    if label == "good":
        return leak is False
    return False


def _oracle(unit: Mapping[str, Any], manifest_unit: Mapping[str, Any]) -> dict[str, Any]:
    runtime = manifest_unit.get("runtime_check") or {}
    label = str(unit["label"])
    leak = runtime.get("leak_detected")
    consensus = "leak" if leak is True else "clean" if leak is False else "unknown"
    mismatch = (label == "bad" and leak is not True) or (label == "good" and leak is True)
    return {
        "reference": "juliet_intended",
        "dynamic_consensus": consensus,
        "lsan": consensus if consensus in ("leak", "clean") else "unknown",
        "valgrind": None,
        "mismatch": mismatch,
        "note": (
            "runtime_check from juliet/manifest.json (AddressSanitizer + LeakSanitizer); "
            "22 bad units had no observed leak and are not runtime-supported"
        ),
    }


def _load_units(units_path: Path, manifest_path: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    units = read_jsonl(units_path)
    if len(units) != 200:
        raise ValueError(f"{units_path}: expected 200 units, found {len(units)}")
    manifest = read_json(manifest_path)
    by_id: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("units") or []:
        unit_id = str(entry.get("unit_id") or "")
        if unit_id:
            by_id[unit_id] = entry
    missing = [str(unit.get("unit_id")) for unit in units if str(unit.get("unit_id")) not in by_id]
    if missing:
        raise ValueError(f"{manifest_path}: {len(missing)} subset units lack a manifest entry")
    groups = {str(unit["group_id"]) for unit in units}
    families = {str(unit["family"]) for unit in units}
    if len(groups) != 100 or len(families) != 42:
        raise ValueError(f"unexpected frozen counts: groups={len(groups)} families={len(families)}")
    return units, by_id, manifest


def _check_complete(units: Sequence[Mapping[str, Any]]) -> None:
    seen: set[tuple[str, str]] = set()
    for unit in units:
        key = (str(unit["group_id"]), str(unit.get("label")))
        if key in seen:
            raise ValueError(f"duplicate unit {key}")
        seen.add(key)
    for group_id in {str(unit["group_id"]) for unit in units}:
        sides = {str(unit["label"]) for unit in units if str(unit["group_id"]) == group_id}
        if sides != {"bad", "good"}:
            raise ValueError(f"group {group_id}: sides {sorted(sides)}")


def _base_record(
    *,
    run_id: str,
    unit: Mapping[str, Any],
    manifest_unit: Mapping[str, Any],
    dataset_sha256: str,
    method: dict[str, Any],
    source_artifact: str,
    source_sha256: str,
    record_index: int,
    created_at: str,
    source_unit_id: str,
) -> dict[str, Any]:
    group_id = str(unit["group_id"])
    side = str(unit["label"])
    return {
        "schema_version": PREDICTION_SCHEMA_VERSION,
        "run_id": run_id,
        "tier": "B",
        "track": TRACK,
        "task": "leak_detection",
        "unit_id": _unit_id(group_id, side),
        "cluster_id": str(unit["family"]),
        "group_id": group_id,
        "side": side,
        "dataset": {
            "dataset_id": DATASET_ID,
            "split_id": DATASET_ID,
            "sha256": dataset_sha256,
            "unit_manifest_sha256": None,
        },
        "method": method,
        "input": {
            "view": "unit",
            "source_sha256": None,
            "prompt_sha256": None,
            "context_mode": None,
            "sanitized": False,
            "sanitizer_version": None,
            "evidence_sha256": None,
        },
        "label": {
            "y_true": 1 if side == "bad" else 0,
            "cwe": ["CWE-401"],
            "label_source": "juliet_intended",
            "label_note": (
                "frozen Juliet designed label; runtime support is recorded in oracle/extensions"
            ),
        },
        "prediction": {
            "y_pred": None,
            "cwe_pred": [],
            "confidence": None,
            "evidence_lines": [],
            "rationale": None,
            "raw_output_sha256": None,
            "fixed_function": None,
        },
        "status": "not_run",
        "error": None,
        "coverage": None,
        "oracle": _oracle(unit, manifest_unit),
        "usage": None,
        "cost": None,
        "provenance": {
            "produced_by": COLLECTOR_VERSION,
            "created_at": created_at,
            "source_artifact": source_artifact,
            "source_sha256": source_sha256,
            "record_index": record_index,
            "command_sha256": None,
            "legacy_run_id": source_artifact,
            "note": "mapped from a real static/dynamic artifact; prediction not re-run",
        },
        "extensions": {
            "split": str(unit["split"]),
            "runtime_supported": _runtime_supported(manifest_unit),
            "runtime_leak_detected": (manifest_unit.get("runtime_check") or {}).get("leak_detected"),
            "source_unit_id": source_unit_id,
            "family": str(unit["family"]),
            "language": str(unit.get("language") or ""),
            "sources": list(unit.get("sources") or []),
        },
    }


def _cost_block(wall_s: float | None, note: str) -> dict[str, Any]:
    return {
        "usd": None,
        "wall_s": wall_s,
        "cpu_s": None,
        "peak_rss_mb": None,
        "currency": "USD",
        "cost_basis": "local_compute",
        "pricing_snapshot": None,
        "note": note,
    }


def _usage_block(latency_ms: float | None) -> dict[str, Any]:
    return {
        "prompt_tokens": None,
        "completion_tokens": None,
        "cached_prompt_tokens": None,
        "reasoning_tokens": None,
        "latency_ms": latency_ms,
        "api_attempts": None,
    }


def _write_run(
    out_dir: Path,
    *,
    run_id: str,
    method: dict[str, Any],
    predictions: list[dict[str, Any]],
    dataset_path: Path,
    dataset_sha256: str,
    manifest_path: Path,
    source_started_at: str | None,
    source_finished_at: str | None,
    command: str | None,
    concurrency: int | None,
    source_artifact: str,
    source_manifest_sha256: str,
    source_metrics_sha256: str | None,
    source_results_sha256: str,
    notes: list[str],
    force: bool,
) -> Path:
    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise FileExistsError(f"{out_dir} is not empty; pass --force")
    out_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = out_dir / "predictions.jsonl"
    atomic_write_text(
        predictions_path,
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in predictions),
    )
    manifest = {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "protocol_version": PROTOCOL_VERSION,
        "tier": "B",
        "track": TRACK,
        "tasks": ["leak_detection"],
        "dataset": {
            "dataset_id": DATASET_ID,
            "split_id": DATASET_ID,
            "path": _rel(dataset_path),
            "sha256": dataset_sha256,
            "unit_manifest": {
                "path": _rel(manifest_path),
                "sha256": sha256_file(manifest_path),
            },
            "unit_count": len(predictions),
            "group_count": 100,
            "label_counts": {"bad": 100, "good": 100},
        },
        "method": method,
        "execution": {
            "started_at": source_started_at,
            "finished_at": source_finished_at,
            "status": "completed",
            "planned_units": len(predictions),
            "recorded_units": len(predictions),
            "retries": 0,
            "concurrency": concurrency,
            "command": command,
            "command_sha256": sha256_text(command) if command else None,
            "environment": {
                "collector": COLLECTOR_VERSION,
                "source_artifact": source_artifact,
            },
        },
        "artifacts": {
            "predictions": "predictions.jsonl",
            "metrics": "metrics.json",
            "validation": "validation.json",
            "log": None,
        },
        "hashes": {
            "predictions_sha256": sha256_file(predictions_path),
            "source_results_sha256": source_results_sha256,
            "source_manifest_sha256": source_manifest_sha256,
            "source_metrics_sha256": source_metrics_sha256,
            "units_sha256": dataset_sha256,
        },
        "legacy_import": None,
        "notes": [
            "Derived view over a frozen source run; predictions are copied, not re-executed.",
            "All 200 frozen units (dev 60 + test 140) are present in one run; the summary tool marks test 140 as primary.",
            "Static compile errors and dynamic inconclusive records stay non-ok; they are never rewritten as y_pred=0.",
        ]
        + notes,
    }
    atomic_write_json(out_dir / "run_manifest.json", manifest)
    atomic_write_text(
        out_dir / "PROVENANCE.md",
        "\n".join(
            [
                f"# Tier B run: `{run_id}`",
                "",
                f"- source artifact: `{source_artifact}`",
                f"- source results SHA-256: `{source_results_sha256}`",
                f"- frozen units: `{_rel(dataset_path)}` ({dataset_sha256})",
                f"- collector: `{COLLECTOR_VERSION}`",
                "- derived view: no model/tool call, no prediction change",
                "- metrics: run `python3 benchmark/tools/bench_metrics.py --run-dir <this dir>`",
                "",
            ]
        ),
    )
    return out_dir


def collect_static(
    *,
    units: Sequence[Mapping[str, Any]],
    manifest_units: Mapping[str, Mapping[str, Any]],
    static_run: Path,
    out_root: Path,
    dataset_path: Path,
    dataset_sha256: str,
    manifest_path: Path,
    force: bool,
) -> list[Path]:
    predictions_path = static_run / "predictions.jsonl"
    manifest_path_source = static_run / "manifest.json"
    metrics_path_source = static_run / "metrics.json"
    records = read_jsonl(predictions_path)
    source_sha = sha256_file(predictions_path)
    source_manifest_sha = sha256_file(manifest_path_source)
    source_metrics_sha = sha256_file(metrics_path_source) if metrics_path_source.exists() else None
    static_manifest = read_json(manifest_path_source)
    tool_info = static_manifest.get("tools") or {}
    settings = static_manifest.get("settings") or {}
    generated_at = str(static_manifest.get("generated_at") or utc_now())

    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for index, record in enumerate(records):
        sample_id = str(record.get("sample_id") or "")
        tool = str(record.get("tool") or "")
        if not sample_id or not tool:
            raise ValueError(f"{predictions_path}:{index + 1}: missing sample_id/tool")
        by_key[(sample_id, tool)] = record

    outputs: list[Path] = []
    for tool in ("clang", "cppcheck"):
        info = tool_info.get(tool) or {}
        if not info.get("available", True):
            raise ValueError(f"static tool {tool} is not available in the source run")
        version = str(info.get("version") or "unknown")
        if tool == "clang":
            tool_name = "Clang Static Analyzer"
            method_id = "static.clang.sa"
            display = f"Clang Static Analyzer ({version})"
            rules = ["unix.Malloc", "cplusplus.NewDeleteLeaks"]
            license_name = "Apache-2.0 WITH LLVM-exception"
        else:
            tool_name = "Cppcheck"
            method_id = "static.cppcheck"
            display = f"Cppcheck ({version})"
            rules = ["memleak", "memleakOnRealloc", "cwe=401"]
            license_name = "GPL-3.0-or-later"
        config_sha = sha256_text(
            json.dumps(
                {
                    "tool": tool,
                    "version": version,
                    "settings": settings,
                    "rules": rules,
                },
                sort_keys=True,
            )
        )
        method = {
            "method_id": method_id,
            "family": "static",
            "name": display,
            "strategy": None,
            "tool": {
                "name": tool_name,
                "version": version,
                "command_template": (
                    "clang --analyze ..." if tool == "clang" else "cppcheck --enable=warning ..."
                ),
                "rules": rules,
                "license": license_name,
            },
            "config_sha256": config_sha,
        }
        run_id = f"tierb_juliet_cwe401_static_{tool}_20261112_{config_sha[:8]}"
        predictions: list[dict[str, Any]] = []
        for unit in units:
            source_unit_id = str(unit["unit_id"])
            record = by_key.get((source_unit_id, tool))
            if record is None:
                raise ValueError(f"static run lacks {source_unit_id} for {tool}")
            unit_manifest = manifest_units[source_unit_id]
            item = _base_record(
                run_id=run_id,
                unit=unit,
                manifest_unit=unit_manifest,
                dataset_sha256=dataset_sha256,
                method=method,
                source_artifact=_rel(predictions_path),
                source_sha256=source_sha,
                record_index=len(predictions),
                created_at=generated_at,
                source_unit_id=source_unit_id,
            )
            raw_status = str(record.get("status") or "not_run")
            status = {
                "ok": "ok",
                "compile_error": "compile_error",
                "timeout": "timeout",
                "tool_error": "tool_error",
                "unavailable": "unsupported",
            }.get(raw_status, "tool_error")
            item["status"] = status
            if status == "ok":
                prediction = record.get("prediction") or {}
                y_pred = prediction.get("is_vulnerable")
                if not isinstance(y_pred, bool):
                    raise ValueError(f"{source_unit_id}/{tool}: ok record without boolean prediction")
                item["prediction"]["y_pred"] = y_pred
                if y_pred:
                    item["prediction"]["cwe_pred"] = ["CWE-401"]
                diagnostics = record.get("diagnostics") or []
                lines = sorted(
                    {
                        int(diagnostic.get("line"))
                        for diagnostic in diagnostics
                        if isinstance(diagnostic, dict)
                        and diagnostic.get("counts_as_finding")
                        and isinstance(diagnostic.get("line"), int)
                        and diagnostic.get("line") > 0
                    }
                )
                item["prediction"]["evidence_lines"] = lines[:50]
                item["prediction"]["rationale"] = (
                    f"{len(diagnostics)} raw diagnostic(s); "
                    f"{int((record.get('diagnostic_counts') or {}).get('cwe401') or 0)} mapped to CWE-401"
                )
            else:
                errors = record.get("errors") or []
                message = str(errors[0]) if errors else f"static status={raw_status}"
                item["error"] = {
                    "type": status,
                    "message": message[:2000],
                    "retryable": False,
                    "attempt": None,
                    "http_status": None,
                }
            duration = (record.get("runtime") or {}).get("duration_seconds")
            wall = float(duration) if isinstance(duration, (int, float)) else None
            item["usage"] = _usage_block(wall * 1000.0 if wall is not None else None)
            item["cost"] = _cost_block(wall, "local static analysis; USD not applicable")
            counts = record.get("diagnostic_counts") or {}
            item["extensions"].update(
                {
                    "tool": tool,
                    "tool_version": version,
                    "raw_status": raw_status,
                    "diagnostics_total": counts.get("total"),
                    "diagnostics_cwe401": counts.get("cwe401"),
                    "compile_ok": status == "ok",
                }
            )
            predictions.append(item)

        out_dir = out_root / f"static_{tool}" / run_id
        outputs.append(
            _write_run(
                out_dir,
                run_id=run_id,
                method=method,
                predictions=predictions,
                dataset_path=dataset_path,
                dataset_sha256=dataset_sha256,
                manifest_path=manifest_path,
                source_started_at=str(static_manifest.get("started_at") or generated_at),
                source_finished_at=str(static_manifest.get("generated_at") or generated_at),
                command=str(static_manifest.get("command") or "") or None,
                concurrency=(settings.get("jobs") if isinstance(settings.get("jobs"), int) else None),
                source_artifact=_rel(predictions_path),
                source_manifest_sha256=source_manifest_sha,
                source_metrics_sha256=source_metrics_sha,
                source_results_sha256=source_sha,
                notes=[
                    f"Static tool: {tool_name} {version}.",
                    "compile_error records are retained and excluded from valid-only metrics; strict views count them wrong.",
                ],
                force=force,
            )
        )
    return outputs


def collect_dynamic(
    *,
    units: Sequence[Mapping[str, Any]],
    manifest_units: Mapping[str, Mapping[str, Any]],
    dynamic_run: Path,
    out_root: Path,
    dataset_path: Path,
    dataset_sha256: str,
    manifest_path: Path,
    force: bool,
) -> list[Path]:
    results_path = dynamic_run / "results.jsonl"
    manifest_path_source = dynamic_run / "manifest.json"
    metrics_path_source = dynamic_run / "metrics.json"
    records = read_jsonl(results_path)
    source_sha = sha256_file(results_path)
    source_manifest_sha = sha256_file(manifest_path_source)
    source_metrics_sha = sha256_file(metrics_path_source) if metrics_path_source.exists() else None
    dynamic_manifest = read_json(manifest_path_source)
    config = dynamic_manifest.get("config") or {}
    toolchain = dynamic_manifest.get("toolchain") or {}
    generated_at = str(dynamic_manifest.get("generated_at_utc") or utc_now())

    by_key: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for index, record in enumerate(records):
        sources = record.get("sources") or []
        key = (tuple(sorted(_normalise_source(str(source)) for source in sources)), str(record.get("variant") or ""))
        if key in by_key:
            raise ValueError(f"{results_path}:{index + 1}: duplicate dynamic case key")
        by_key[key] = record

    mapped: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for unit in units:
        key = (tuple(sorted(str(source) for source in unit.get("sources") or [])), str(unit["label"]))
        record = by_key.get(key)
        if record is None:
            raise ValueError(f"dynamic run lacks unit {unit['unit_id']} ({key})")
        mapped.append((unit, record))
    if len(mapped) != len(units):
        raise ValueError("dynamic mapping is incomplete")

    asan_version = str(
        (toolchain.get("cxx") or {}).get("version")
        or (toolchain.get("cc") or {}).get("version")
        or "unknown"
    )
    valgrind_version = str((toolchain.get("valgrind") or {}).get("version") or "unknown")
    methods = [
        (
            "asan",
            "ASan+LSan",
            "dynamic.asan_lsan",
            "AddressSanitizer + LeakSanitizer",
            asan_version,
            ["LeakSanitizer direct/indirect leak"],
        ),
        (
            "valgrind",
            "Valgrind Memcheck",
            "dynamic.valgrind",
            "Valgrind Memcheck",
            valgrind_version,
            ["definite/indirect leak"],
        ),
        (
            "combined",
            "ASan+LSan+Valgrind (any leak)",
            "dynamic.combined",
            "ASan/LSan + Valgrind combined",
            f"LSan ({asan_version}); Valgrind {valgrind_version}",
            ["any detector reports definite/indirect leak"],
        ),
    ]

    outputs: list[Path] = []
    for detector_key, label, method_id, tool_name, version, rules in methods:
        config_sha = sha256_text(
            json.dumps(
                {
                    "detector": detector_key,
                    "config": config,
                    "toolchain": toolchain,
                },
                sort_keys=True,
            )
        )
        method = {
            "method_id": method_id,
            "family": "dynamic",
            "name": label,
            "strategy": None,
            "tool": {
                "name": tool_name,
                "version": version,
                "command_template": (
                    "gcc -fsanitize=address ... && ASAN_OPTIONS=detect_leaks=1 ./case"
                    if detector_key == "asan"
                    else "valgrind --leak-check=full --show-leak-kinds=definite,indirect ..."
                    if detector_key == "valgrind"
                    else "ASan/LSan run + Valgrind Memcheck run; leak if either reports"
                ),
                "rules": rules,
                "license": "GPL-2.0-or-later (Valgrind); GCC runtime (ASan/LSan)",
            },
            "config_sha256": config_sha,
        }
        run_id = f"tierb_juliet_cwe401_dynamic_{detector_key}_20261111_{config_sha[:8]}"
        predictions: list[dict[str, Any]] = []
        for unit, record in mapped:
            unit_manifest = manifest_units[str(unit["unit_id"])]
            item = _base_record(
                run_id=run_id,
                unit=unit,
                manifest_unit=unit_manifest,
                dataset_sha256=dataset_sha256,
                method=method,
                source_artifact=_rel(results_path),
                source_sha256=source_sha,
                record_index=len(predictions),
                created_at=generated_at,
                source_unit_id=str(unit["unit_id"]),
            )
            if detector_key == "combined":
                outcome = str(record.get("outcome") or "")
                status = "ok" if outcome in ("leak", "clean") else "inconclusive"
                y_pred = True if outcome == "leak" else False if outcome == "clean" else None
                detector_statuses = {
                    name: (block or {}).get("status")
                    for name, block in (record.get("detectors") or {}).items()
                }
            else:
                block = (record.get("detectors") or {}).get(detector_key) or {}
                detector_status = str(block.get("status") or "")
                status = (
                    "ok"
                    if detector_status in ("leak", "clean")
                    else "inconclusive"
                    if detector_status == "inconclusive"
                    else "unsupported"
                )
                y_pred = True if detector_status == "leak" else False if detector_status == "clean" else None
                detector_statuses = {detector_key: detector_status}
            item["status"] = status
            if status == "ok":
                item["prediction"]["y_pred"] = y_pred
                if y_pred:
                    item["prediction"]["cwe_pred"] = ["CWE-401"]
                item["prediction"]["rationale"] = (
                    f"runtime outcome={record.get('outcome')}; "
                    f"detectors={detector_statuses}"
                )
            else:
                item["error"] = {
                    "type": status,
                    "message": (
                        f"dynamic outcome={record.get('outcome')}; "
                        f"failure_class={record.get('failure_class')}; "
                        f"detectors={detector_statuses}"
                    ),
                    "retryable": False,
                    "attempt": None,
                    "http_status": None,
                }
            duration_ms = record.get("duration_ms")
            wall = float(duration_ms) / 1000.0 if isinstance(duration_ms, (int, float)) else None
            item["coverage"] = {
                "unit_executed": status == "ok",
                "target_function_entered": None,
                "line_coverage": None,
                "branch_coverage": None,
                "allocation_site_executed": None,
                "free_site_executed": None,
                "coverage_source": "none",
                "notes": (
                    "No line/branch coverage instrumentation in the source run. "
                    "A clean result means no leak was observed on the executed path; "
                    "it is not a verified true negative."
                ),
            }
            oracle = item["oracle"]
            detector_leaks = [
                value for value in detector_statuses.values() if value in ("leak", "clean")
            ]
            if "leak" in detector_leaks:
                oracle["dynamic_consensus"] = "leak"
            elif detector_leaks and all(value == "clean" for value in detector_leaks):
                oracle["dynamic_consensus"] = "clean"
            elif len(set(detector_leaks)) > 1:
                oracle["dynamic_consensus"] = "disagree"
            else:
                oracle["dynamic_consensus"] = "unknown"
            oracle["lsan"] = (
                (record.get("detectors") or {}).get("asan", {}).get("status")
                if (record.get("detectors") or {}).get("asan", {}).get("status") in ("leak", "clean")
                else "error"
            )
            oracle["valgrind"] = (
                (record.get("detectors") or {}).get("valgrind", {}).get("status")
                if (record.get("detectors") or {}).get("valgrind", {}).get("status") in ("leak", "clean")
                else "error"
            )
            oracle["mismatch"] = (
                record.get("detected_label") is not None
                and record.get("expected_label") is not None
                and record.get("detected_label") != record.get("expected_label")
            )
            item["usage"] = _usage_block(duration_ms if isinstance(duration_ms, (int, float)) else None)
            item["cost"] = _cost_block(wall, "local dynamic analysis; USD not applicable")
            item["extensions"].update(
                {
                    "detector": detector_key,
                    "source_case_id": record.get("case_id"),
                    "outcome": record.get("outcome"),
                    "runtime_class": record.get("runtime_class"),
                    "failure_class": record.get("failure_class"),
                    "detector_statuses": detector_statuses,
                    "expected_label": record.get("expected_label"),
                    "detected_label": record.get("detected_label"),
                    "language": record.get("language"),
                    "feature": record.get("feature"),
                    "duration_ms": duration_ms,
                }
            )
            predictions.append(item)

        out_dir = out_root / f"dynamic_{detector_key}" / run_id
        outputs.append(
            _write_run(
                out_dir,
                run_id=run_id,
                method=method,
                predictions=predictions,
                dataset_path=dataset_path,
                dataset_sha256=dataset_sha256,
                manifest_path=manifest_path,
                source_started_at=dynamic_manifest.get("generated_at_utc"),
                source_finished_at=dynamic_manifest.get("finished_at_utc"),
                command=None,
                concurrency=(config.get("jobs") if isinstance(config.get("jobs"), int) else None),
                source_artifact=_rel(results_path),
                source_manifest_sha256=source_manifest_sha,
                source_metrics_sha256=source_metrics_sha,
                source_results_sha256=source_sha,
                notes=[
                    f"Dynamic detector: {label}.",
                    "The source run has no line/branch coverage instrumentation; clean is 'no leak observed', not verified TN.",
                    "Runtime-supported population is defined by the LSan preflight; ASan scores on that subset are largely circular.",
                ],
                force=force,
            )
        )
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", default=str(PROJECT_ROOT / "juliet" / "subset_units.jsonl"))
    parser.add_argument("--manifest", default=str(PROJECT_ROOT / "juliet" / "manifest.json"))
    parser.add_argument(
        "--static-run",
        default=str(
            PROJECT_ROOT
            / "traditional"
            / "static"
            / "runs"
            / "juliet_formal_20261112_clang_cppcheck_gnu"
        ),
    )
    parser.add_argument(
        "--dynamic-run",
        default=str(
            PROJECT_ROOT
            / "traditional"
            / "dynamic"
            / "runs"
            / "cwe401_juliet_v1_3_asan_valgrind"
        ),
    )
    parser.add_argument(
        "--out-root",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "tier_b" / TRACK),
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    units_path = Path(args.units).resolve()
    manifest_path = Path(args.manifest).resolve()
    units, manifest_units, _ = _load_units(units_path, manifest_path)
    _check_complete(units)
    dataset_sha = sha256_file(units_path)
    out_root = Path(args.out_root).resolve()
    try:
        outputs = collect_static(
            units=units,
            manifest_units=manifest_units,
            static_run=Path(args.static_run).resolve(),
            out_root=out_root,
            dataset_path=units_path,
            dataset_sha256=dataset_sha,
            manifest_path=manifest_path,
            force=args.force,
        )
        outputs += collect_dynamic(
            units=units,
            manifest_units=manifest_units,
            dynamic_run=Path(args.dynamic_run).resolve(),
            out_root=out_root,
            dataset_path=units_path,
            dataset_sha256=dataset_sha,
            manifest_path=manifest_path,
            force=args.force,
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"collect failed: {exc}\n")
        return 2
    sys.stderr.write(json.dumps([str(path) for path in outputs], indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

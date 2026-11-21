"""Execute the 140 frozen test units in all three dynamic modes."""

from __future__ import annotations

import concurrent.futures
import json
import platform
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .build import compile_unit, injection_object, support_objects
from .execute import run_binary
from .parse import classify, summarize_run
from .units import Unit, freeze_record, load_test_units, sha256_file, unit_input_hashes

PRIORITY = ("default", "realloc_fail", "nogobal")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tool_version(command: list[str]) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return (proc.stdout or proc.stderr).splitlines()[0].strip()
    except Exception:  # noqa: BLE001 - recorded as unavailable
        return "unavailable"


def run_unit(
    unit: Unit,
    run_dir: Path,
    build_root: Path,
    objects: dict[str, Path],
    injection: Path,
) -> dict:
    started = time.monotonic()
    case_dir = run_dir / "cases" / f"{unit.unit_key}_{unit.label}"
    case_dir.mkdir(parents=True, exist_ok=True)
    record: dict = {
        "unit_id": unit.unit_id,
        "unit_key": unit.unit_key,
        "group_id": unit.group_id,
        "family": unit.family,
        "variant": unit.variant,
        "language": unit.language,
        "label": unit.label,
        "sources": [str(path.relative_to(config.PROJECT)) for path in unit.sources],
        "defines": list(unit.defines),
        "modes": {},
        "build": {},
        "decision": "not_evaluable",
        "y_pred": None,
        "evidence_modes": [],
        "primary_evidence": None,
        "conditionally_observable": False,
        "unobservable_in_default": False,
        "failure_class": None,
        "runtime_ms": 0,
        "errors": [],
    }
    try:
        builds = {}
        for variant in ("plain", "wrap"):
            builds[variant] = compile_unit(
                unit, unit.label, case_dir / "build", build_root,
                variant, objects, injection,
            )
            record["build"][variant] = builds[variant].as_dict()
            (case_dir / f"build_{variant}.json").write_text(
                json.dumps(builds[variant].as_dict(), indent=2) + "\n", encoding="utf-8"
            )
            (case_dir / f"build_{variant}.stderr").write_text(
                builds[variant].stderr_tail, encoding="utf-8"
            )
        if not builds["plain"].ok:
            record["failure_class"] = "compile_error:plain"
            record["errors"].append("plain build failed")
            record["runtime_ms"] = int((time.monotonic() - started) * 1000)
            return record
        plan = [
            ("default", builds["plain"].exe, "plain"),
            ("nogobal", builds["plain"].exe, "plain"),
            ("realloc_fail", builds["wrap"].exe if builds["wrap"].ok else None, "wrap"),
        ]
        for mode, exe, variant in plan:
            if exe is None:
                record["modes"][mode] = {
                    "mode": mode,
                    "applicable": False,
                    "build_variant": variant,
                    "decision": "not_evaluable",
                    "leak_attributed": False,
                    "failure_class": "compile_error:wrap",
                }
                continue
            run = run_binary(exe, mode, case_dir / f"run_{mode}")
            summary = summarize_run(run.stderr, unit)
            failure = classify(summary, run.timed_out, run.returncode)
            if summary["leak_attributed"]:
                mode_failure = "leak"
            elif summary["leak_raw"]:
                mode_failure = "unattributed_runtime_leak"
            elif failure == "leak":
                mode_failure = "clean"
            else:
                mode_failure = failure
            mode_record = {
                **summary,
                "mode": mode,
                "build_variant": variant,
                "applicable": True,
                "returncode": run.returncode,
                "timed_out": run.timed_out,
                "wall_ms": run.wall_ms,
                "failure_class": mode_failure,
                "stdout_sha256": run.stdout_sha256,
                "stdout_lines": [line for line in run.stdout.replace("\r\n", "\n").split("\n") if line.strip()],
                "stderr_path": str(Path(run.stderr_path).relative_to(run_dir)),
                "stdout_path": str(Path(run.stdout_path).relative_to(run_dir)),
                "env": run.env,
            }
            if mode == "realloc_fail":
                mode_record["applicable"] = summary["injection"]["injected"]
            if summary["leak_attributed"]:
                mode_record["decision"] = "leak"
            elif failure.startswith("asan_error") or failure in ("timeout", "no_returncode"):
                mode_record["decision"] = failure
            else:
                mode_record["decision"] = "clean"
            record["modes"][mode] = mode_record
            (case_dir / f"run_{mode}.json").write_text(
                json.dumps(mode_record, indent=2, default=str) + "\n", encoding="utf-8"
            )

        # Verdict: a unit is positive iff an applicable mode reports a leak
        # whose allocation site is in the unit's own source.
        evidence = [
            mode for mode in PRIORITY
            if record["modes"].get(mode, {}).get("applicable")
            and record["modes"][mode].get("leak_attributed")
        ]
        record["evidence_modes"] = evidence
        record["primary_evidence"] = evidence[0] if evidence else None
        if evidence:
            record["decision"] = "leak"
            record["y_pred"] = 1
        else:
            record["decision"] = "clean"
            record["y_pred"] = 0
        record["unobservable_in_default"] = (
            record["y_pred"] == 1
            and not record["modes"].get("default", {}).get("leak_attributed", False)
        )
        record["conditionally_observable"] = record["unobservable_in_default"]
        failures = [
            mode["failure_class"]
            for mode in record["modes"].values()
            if mode.get("failure_class")
            and (
                mode["failure_class"] in ("compile_error:wrap", "timeout")
                or mode["failure_class"].startswith("asan_error")
            )
            and mode.get("applicable", True)
        ]
        if failures:
            record["failure_class"] = failures[0]
        elif record["y_pred"] == 1:
            record["failure_class"] = "leak"
        else:
            record["failure_class"] = "clean"
    except Exception as exc:  # noqa: BLE001 - recorded, never hidden
        record["errors"].append(f"{type(exc).__name__}: {exc}")
        record["traceback"] = traceback.format_exc()
        record["decision"] = "not_evaluable"
        record["y_pred"] = None
        record["failure_class"] = "harness_error"
    record["runtime_ms"] = int((time.monotonic() - started) * 1000)
    (case_dir / "unit.json").write_text(
        json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return record


def run_all(run_id: str, jobs: int = 8) -> dict:
    run_dir = config.RUNS / run_id
    if run_dir.exists():
        raise SystemExit(f"{run_dir} already exists; choose a new run id (old results are never overwritten)")
    (run_dir / "build").mkdir(parents=True)
    units = load_test_units()
    freeze = freeze_record()
    started = time.monotonic()
    build_root = run_dir / "build"
    objects = support_objects(build_root)
    injection = injection_object(build_root)
    created_at = utc_now()
    manifest = {
        "schema": "dynamic-enhanced-run-v1",
        "run_id": run_id,
        "created_at_utc": created_at,
        "units": len(units),
        "labels": {"bad": sum(1 for unit in units if unit.label == "bad"),
                   "good": sum(1 for unit in units if unit.label == "good")},
        "groups": len({unit.group_id for unit in units}),
        "freeze": freeze,
        "modes": {mode: config.MODE_DESCRIPTION[mode] for mode in config.MODES},
        "env": {
            "ASAN_OPTIONS": config.ASAN_OPTIONS,
            "LSAN_OPTIONS_default": config.LSAN_OPTIONS_BASE,
            "LSAN_OPTIONS_nogobal": config.LSAN_OPTIONS_NOGLOBAL,
            "DYNENH_REALLOC_FAIL_NONNULL": "1 (realloc_fail only)",
        },
        "tools": {
            "gcc": tool_version(["gcc", "--version"]),
            "g++": tool_version(["g++", "--version"]),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "unit_inputs": unit_input_hashes(units),
        "attribution_rule": (
            "the first allocation-stack frame with a source location outside "
            "the toolchain/sanitizer runtime must point into the unit's own "
            "sources or a group-local header"
        ),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    records: list[dict] = []
    print(f"running {len(units)} units with {jobs} workers", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(run_unit, unit, run_dir, build_root, objects, injection): unit
            for unit in units
        }
        for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            unit = futures[future]
            try:
                record = future.result()
            except Exception as exc:  # noqa: BLE001
                record = {
                    "unit_id": unit.unit_id,
                    "unit_key": unit.unit_key,
                    "label": unit.label,
                    "decision": "not_evaluable",
                    "y_pred": None,
                    "failure_class": "harness_error",
                    "errors": [f"{type(exc).__name__}: {exc}"],
                    "traceback": traceback.format_exc(),
                }
            records.append(record)
            if count % 10 == 0 or count == len(units):
                print(f"  {count}/{len(units)}", flush=True)
    records.sort(key=lambda item: item["unit_key"])
    with (run_dir / "results_units.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    raw_rows = []
    for record in records:
        for mode, mode_record in record.get("modes", {}).items():
            raw_rows.append(
                {
                    "unit_id": record["unit_id"],
                    "unit_key": record["unit_key"],
                    "label": record["label"],
                    "mode": mode,
                    **{key: value for key, value in mode_record.items() if key != "mode"},
                }
            )
    with (run_dir / "results_raw.jsonl").open("w", encoding="utf-8") as handle:
        for row in raw_rows:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
    manifest["finished_at_utc"] = utc_now()
    manifest["wall_seconds"] = round(time.monotonic() - started, 2)
    manifest["results_units_sha256"] = sha256_file(run_dir / "results_units.jsonl")
    manifest["results_raw_sha256"] = sha256_file(run_dir / "results_raw.jsonl")
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {"run_dir": run_dir, "records": records, "manifest": manifest}

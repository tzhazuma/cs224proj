"""Run the 140 frozen units under gcov and collect coverage + leak evidence.

Per unit:
  1. compile once with GCC ASan + gcov (objects carry the .gcno notes),
  2. link a plain and a --wrap=realloc binary,
  3. run default / realloc_fail / nogobal, deleting stale .gcda before each,
  4. read the gcov JSON for the unit's own files,
  5. record per-mode and union line/branch coverage next to the leak verdict.

The leak verdict logic mirrors dynamic_enhanced/pipeline.py: a unit leaks iff
an applicable mode attributes a leak block to the unit's own sources.  The
new part is that every verdict now carries the exact set of lines and
branches that were executed when it was produced.
"""

from __future__ import annotations

import concurrent.futures
import json
import platform
import statistics
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .build import build_unit, prepare_support
from .execute import run_binary
from .gcov import (
    Coverage,
    annotate_dead_code,
    entry_executed,
    filter_owned,
    run_gcov,
    site_coverage,
    summarize,
    tier,
)
from .units import (
    find_entry,
    freeze_record,
    load_test_units,
    sha256_file,
    summarize_run,
    unit_input_hashes,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def tool_version(command: list[str]) -> str:
    import subprocess

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return (proc.stdout or proc.stderr).splitlines()[0].strip()
    except Exception:  # noqa: BLE001
        return "unavailable"


def _clear_gcda(object_dir: Path) -> None:
    for path in object_dir.glob("*.gcda"):
        try:
            path.unlink()
        except OSError:
            pass


def _coverage_payload(coverage: Coverage, summary: dict, unit_id: str) -> dict:
    files = []
    for key in sorted(coverage.files):
        file_cov = coverage.files[key]
        try:
            display = str(Path(key).resolve().relative_to(config.PROJECT))
        except ValueError:
            display = key
        branches = []
        for branch_key, count in sorted(file_cov.branches.items(), key=lambda item: str(item[0])):
            line, source_block, destination_block, throw, fallthrough = branch_key
            branches.append(
                {
                    "line": line,
                    "source_block_id": source_block,
                    "destination_block_id": destination_block,
                    "throw": throw,
                    "fallthrough": fallthrough,
                    "count": count,
                }
            )
        files.append(
            {
                "file": display,
                "lines": {str(line): count for line, count in sorted(file_cov.lines.items())},
                "branches": branches,
            }
        )
    return {
        "unit": unit_id,
        "summary": summary,
        "files": files,
    }


def _mode_decision(summary: dict, run) -> tuple[str, str | None]:
    """Return (decision, failure_class) using the archived rule."""
    if run.timed_out:
        return "not_evaluable", "timeout"
    errors = summary.get("asan_errors") or []
    if errors:
        return "not_evaluable", "asan_error:" + errors[0]
    if summary.get("leak_attributed"):
        return "leak", "leak"
    if run.returncode is None:
        return "not_evaluable", "no_returncode"
    if run.returncode != 0:
        return "clean", f"exit_{run.returncode}"
    return "clean", "clean"


def run_unit(
    unit,
    run_dir: Path,
    build_root: Path,
    support: dict[str, Path],
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
        "decision": "not_evaluable",
        "y_pred": None,
        "evidence_modes": [],
        "primary_evidence": None,
        "failure_class": None,
        "runtime_ms": 0,
        "errors": [],
    }
    try:
        build = build_unit(unit, case_dir, build_root, support, injection)
        record["build"] = build.as_dict()
        (case_dir / "build.json").write_text(
            json.dumps(build.as_dict(), indent=2) + "\n", encoding="utf-8"
        )
        if not build.ok:
            record["failure_class"] = "compile_error:coverage"
            record["errors"].append("; ".join(build.errors)[-4000:])
            record["coverage_tier"] = "compile_error"
            record["coverage_tier_effective"] = "compile_error"
            record["compile_error"] = True
            record["covered_clean"] = False
            record["uncovered"] = False
            record["coverage_class"] = "compile_error"
            record["runtime_ms"] = int((time.monotonic() - started) * 1000)
            return record

        entry_name, _ = find_entry(unit, unit.label)
        plan = [
            ("default", build.plain_exe, "plain"),
            ("realloc_fail", build.wrap_exe, "wrap"),
            ("nogobal", build.plain_exe, "plain"),
        ]
        coverages: dict[str, Coverage] = {}
        for mode, exe, variant in plan:
            mode_dir = case_dir / f"run_{mode}"
            mode_dir.mkdir(parents=True, exist_ok=True)
            if exe is None:
                record["modes"][mode] = {
                    "mode": mode,
                    "applicable": False,
                    "build_variant": variant,
                    "decision": "not_evaluable",
                    "failure_class": "compile_error:wrap",
                    "leak_attributed": False,
                    "coverage_tier": "coverage_error",
                    "coverage_error": ["binary not linked"],
                }
                continue
            _clear_gcda(build.object_dir)
            run = run_binary(exe, mode, mode_dir)
            summary = summarize_run(run.stderr, unit)
            decision, failure_class = _mode_decision(summary, run)
            applicable = True
            if mode == "realloc_fail":
                applicable = bool(summary["injection"]["injected"])
            gcda = sorted(path.name for path in build.object_dir.glob("*.gcda"))
            coverage = run_gcov(mode_dir, list(unit.sources), build.object_dir)
            coverage = filter_owned(coverage, unit)
            coverage_summary = summarize(coverage)
            coverage_summary = annotate_dead_code(coverage_summary, unit)
            coverage_error = bool(coverage.errors) or not coverage.files
            if not coverage_error and run.returncode is not None and not gcda:
                coverage_error = True
                coverage.errors.append(
                    "no .gcda written although the process returned; coverage is not trustworthy"
                )
            if coverage_error and not coverage.errors:
                coverage.errors.append("no unit-owned coverage record")
            mode_tier = tier(coverage_summary, coverage_error)
            mode_tier_effective = tier(coverage_summary, coverage_error, effective=True)
            mode_record = {
                **summary,
                "mode": mode,
                "build_variant": variant,
                "applicable": applicable,
                "returncode": run.returncode,
                "timed_out": run.timed_out,
                "wall_ms": run.wall_ms,
                "failure_class": failure_class,
                "decision": decision,
                "stdout_sha256": run.stdout_sha256,
                "stdout_lines": [
                    line for line in run.stdout.replace("\r\n", "\n").split("\n") if line.strip()
                ],
                "stderr_path": str(Path(run.stderr_path).relative_to(run_dir)),
                "stdout_path": str(Path(run.stdout_path).relative_to(run_dir)),
                "env": run.env,
                "gcda_files": gcda,
                "gcov_checks": [
                    {
                        "source": Path(run["source"]).name,
                        "returncode": run["returncode"],
                        "lines_total": run["lines_total"],
                        "lines_hit": run["lines_hit"],
                        "lines_total_parsed": run.get("lines_total_parsed"),
                        "lines_hit_parsed": run.get("lines_hit_parsed"),
                    }
                    for run in coverage.gcov_runs
                ],
                "coverage": coverage_summary,
                "coverage_tier": mode_tier,
                "coverage_tier_effective": mode_tier_effective,
                "coverage_error": list(coverage.errors),
                "entry_executed": entry_executed(coverage_summary, entry_name),
                "site_coverage": site_coverage(unit, coverage),
            }
            record["modes"][mode] = mode_record
            (mode_dir / "run.json").write_text(
                json.dumps(mode_record, indent=2, default=str) + "\n", encoding="utf-8"
            )
            (mode_dir / "coverage.json").write_text(
                json.dumps(
                    _coverage_payload(coverage, coverage_summary, record["unit_id"]),
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            if mode_tier != "coverage_error":
                coverages[mode] = coverage

        # Union over every mode that actually produced coverage.  A
        # non-applicable realloc_fail run repeats the default path, so it adds
        # no new lines; including it cannot inflate the union.
        union = Coverage()
        for mode in config.MODE_PRIORITY:
            if mode in coverages:
                union.merge(coverages[mode])
        union_summary = summarize(union)
        union_summary = annotate_dead_code(union_summary, unit)
        union_error = not union.files
        record["coverage_union"] = union_summary
        record["coverage_tier"] = tier(union_summary, union_error)
        record["coverage_tier_effective"] = tier(union_summary, union_error, effective=True)
        record["coverage_union_error"] = union.errors
        record["entry_executed"] = entry_executed(union_summary, entry_name)
        record["site_coverage_union"] = site_coverage(unit, union)
        (case_dir / "coverage_union.json").write_text(
            json.dumps(
                _coverage_payload(union, union_summary, record["unit_id"]), indent=2
            )
            + "\n",
            encoding="utf-8",
        )

        evidence = [
            mode
            for mode in config.MODE_PRIORITY
            if record["modes"].get(mode, {}).get("applicable")
            and record["modes"][mode].get("leak_attributed")
        ]
        record["evidence_modes"] = evidence
        record["primary_evidence"] = evidence[0] if evidence else None
        if evidence:
            record["decision"] = "leak"
            record["y_pred"] = 1
        else:
            failures = [
                entry["failure_class"]
                for entry in record["modes"].values()
                if entry.get("applicable", True)
                and entry.get("failure_class")
                and (
                    entry["failure_class"] in ("timeout", "no_returncode")
                    or str(entry["failure_class"]).startswith("asan_error")
                )
            ]
            if failures:
                record["decision"] = "not_evaluable"
                record["y_pred"] = None
            else:
                record["decision"] = "clean"
                record["y_pred"] = 0
        record["failure_class"] = (
            "leak"
            if record["y_pred"] == 1
            else ("clean" if record["y_pred"] == 0 else record["decision"])
        )
        record["compile_error"] = False
        if record["y_pred"] == 1:
            record["coverage_class"] = "leak"
            record["covered_clean"] = False
            record["uncovered"] = False
        elif (
            record["y_pred"] == 0
            and record.get("coverage_tier_effective") in ("line_complete", "branch_complete")
            and record.get("entry_executed")
        ):
            record["coverage_class"] = "covered_clean"
            record["covered_clean"] = True
            record["uncovered"] = False
        else:
            record["coverage_class"] = "uncovered"
            record["covered_clean"] = False
            record["uncovered"] = True
        record["runtime_ms"] = int((time.monotonic() - started) * 1000)
    except Exception as exc:  # noqa: BLE001 - recorded, never hidden
        record["errors"].append(f"{type(exc).__name__}: {exc}")
        record["traceback"] = traceback.format_exc()
        record["decision"] = "not_evaluable"
        record["y_pred"] = None
        record["failure_class"] = "harness_error"
        record["coverage_tier"] = "coverage_error"
        record["coverage_tier_effective"] = "coverage_error"
        record["compile_error"] = False
        record["covered_clean"] = False
        record["uncovered"] = True
        record["coverage_class"] = "uncovered"
    (case_dir / "unit.json").write_text(
        json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return record


def _percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def run_all(run_id: str, jobs: int = 8) -> dict:
    run_dir = config.RUNS / run_id
    if run_dir.exists():
        raise SystemExit(
            f"{run_dir} already exists; choose a new run id (old results are never overwritten)"
        )
    (run_dir / "build").mkdir(parents=True)
    units = load_test_units()
    freeze = freeze_record()
    started = time.monotonic()
    build_root = run_dir / "build"
    support, injection = prepare_support(build_root)
    manifest = {
        "schema": "dynamic-coverage-run-v1",
        "run_id": run_id,
        "created_at_utc": utc_now(),
        "units": len(units),
        "labels": {
            "bad": sum(1 for unit in units if unit.label == "bad"),
            "good": sum(1 for unit in units if unit.label == "good"),
        },
        "groups": len({unit.group_id for unit in units}),
        "freeze": freeze,
        "modes": {mode: config.MODE_DESCRIPTION[mode] for mode in config.MODES},
        "coverage_tool": {
            "instrumentation": "gcc --coverage (-fprofile-arcs -ftest-coverage)",
            "reader": "gcov -j -b -c (JSON)",
            "gcc": tool_version(["gcc", "--version"]),
            "g++": tool_version(["g++", "--version"]),
            "gcov": tool_version(["gcov", "--version"]),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "env": {
            "ASAN_OPTIONS": config.ASAN_OPTIONS,
            "LSAN_OPTIONS_default": config.LSAN_OPTIONS_BASE,
            "LSAN_OPTIONS_nogobal": config.LSAN_OPTIONS_NOGLOBAL,
            "DYNENH_REALLOC_FAIL_NONNULL": "1 (realloc_fail only)",
        },
        "archived_results": str(config.ARCHIVED_RUN.relative_to(config.PROJECT)),
        "unit_inputs": unit_input_hashes(units),
        "coverage_tiers": {
            "branch_complete": "every executable line and every recorded branch executed",
            "line_complete": "every executable line executed, at least one branch never taken",
            "partial": "at least one executable line in the unit's own files never executed",
            "not_executed": "no executable line in the unit's own files executed",
            "no_coverage": "gcov returned no line record for the unit's own files",
            "coverage_error": "gcov failed or .gcda was not written",
        },
        "attribution_rule": (
            "leak blocks are attributed only when the first source-located frame "
            "outside the toolchain points into the unit's own sources or a "
            "group-local header (same rule as dynamic_enhanced)"
        ),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"running {len(units)} units with {jobs} workers", flush=True)
    records: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(run_unit, unit, run_dir, build_root, support, injection): unit
            for unit in units
        }
        for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            unit = futures[future]
            try:
                records.append(future.result())
            except Exception as exc:  # noqa: BLE001
                records.append(
                    {
                        "unit_id": unit.unit_id,
                        "unit_key": unit.unit_key,
                        "label": unit.label,
                        "decision": "not_evaluable",
                        "y_pred": None,
                        "failure_class": "harness_error",
                        "coverage_tier": "coverage_error",
                        "errors": [f"{type(exc).__name__}: {exc}"],
                        "traceback": traceback.format_exc(),
                    }
                )
            if count % 10 == 0 or count == len(units):
                print(f"  {count}/{len(units)}", flush=True)
    records.sort(key=lambda item: item["unit_key"])
    with (run_dir / "results_units.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    raw_rows = []
    for record in records:
        for mode in config.MODES:
            mode_record = record.get("modes", {}).get(mode)
            if mode_record is None:
                continue
            raw_rows.append(
                {
                    "unit_id": record["unit_id"],
                    "unit_key": record["unit_key"],
                    "label": record["label"],
                    "mode": mode,
                    "coverage_tier": mode_record.get("coverage_tier"),
                    "coverage": mode_record.get("coverage"),
                    "site_coverage": mode_record.get("site_coverage"),
                    **{
                        key: value
                        for key, value in mode_record.items()
                        if key not in {"mode", "coverage", "site_coverage"}
                    },
                }
            )
    with (run_dir / "results_raw.jsonl").open("w", encoding="utf-8") as handle:
        for row in raw_rows:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
    manifest["finished_at_utc"] = utc_now()
    manifest["wall_seconds"] = round(time.monotonic() - started, 2)
    manifest["runtime_ms"] = {
        "mean": int(statistics.mean([row["runtime_ms"] for row in records])),
        "p50": _percentile([row["runtime_ms"] for row in records], 0.50),
        "p95": _percentile([row["runtime_ms"] for row in records], 0.95),
        "max": max(row["runtime_ms"] for row in records),
    }
    manifest["results_units_sha256"] = sha256_file(run_dir / "results_units.jsonl")
    manifest["results_raw_sha256"] = sha256_file(run_dir / "results_raw.jsonl")
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return {"run_dir": run_dir, "records": records, "manifest": manifest}

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .classify import combine_outcome, failure_class, runtime_class, summarize
from .discover import CaseSpec
from .execute import run_asan, run_valgrind
from .metrics import compute_metrics, render_markdown
from .toolchain import Toolchain, build_support, check_tools
from .util import (
    read_text,
    sha256_file,
    slugify,
    truncate_text,
    utc_now_iso,
    write_json,
    write_jsonl,
)


@dataclass
class RunOptions:
    detectors: list[str] = field(default_factory=lambda: ["asan", "valgrind"])
    jobs: int = 4
    compile_timeout_s: float = 120.0
    valgrind_timeout_factor: float = 3.0
    asan_options_extra: str = ""
    valgrind_extra_args: list[str] = field(default_factory=list)
    extra_cflags: list[str] = field(default_factory=list)
    extra_ldflags: list[str] = field(default_factory=list)
    max_cases: Optional[int] = None
    filter_text: Optional[str] = None
    dry_run: bool = False
    rel_root: Optional[Path] = None


def _relative(path: str | Path, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return str(path)


def _relativize_artifacts(value: Any, root: Path) -> Any:
    if isinstance(value, str):
        candidate = Path(value)
        if candidate.is_absolute():
            return _relative(candidate, root)
        return value
    if isinstance(value, list):
        return [_relativize_artifacts(item, root) for item in value]
    if isinstance(value, dict):
        return {key: _relativize_artifacts(item, root) for key, item in value.items()}
    return value


class RunLogger:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, message: str) -> None:
        line = f"{utc_now_iso()} {message}\n"
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)


def _detector_scaffold(name: str, available: bool, note: str) -> dict[str, Any]:
    return {
        "name": name,
        "available": available,
        "status": "unavailable" if not available else "not_run",
        "leak_detected": None,
        "leaked_bytes": None,
        "build": None,
        "execution": None,
        "evidence": None,
        "notes": [note] if note else [],
        "artifacts": {},
    }


def evaluate_case(
    case: CaseSpec,
    tc: Toolchain,
    run_dir: Path,
    support_objects: list[Path],
    options: RunOptions,
    asan_available: bool,
    valgrind_available: bool,
) -> dict[str, Any]:
    started = utc_now_iso()
    started_monotonic = time.monotonic()
    case_dir = run_dir / "cases" / slugify(case.case_id, 120)
    case_dir.mkdir(parents=True, exist_ok=True)
    detectors: dict[str, dict[str, Any]] = {}
    harness_error: Optional[str] = None
    try:
        if "asan" in options.detectors:
            if asan_available:
                detectors["asan"] = run_asan(
                    case,
                    tc,
                    run_dir,
                    case_dir,
                    support_objects,
                    compile_timeout_s=options.compile_timeout_s,
                    extra_cflags=options.extra_cflags,
                    extra_ldflags=options.extra_ldflags,
                    asan_options_extra=options.asan_options_extra,
                )
            else:
                detectors["asan"] = _detector_scaffold(
                    "asan", False, "LeakSanitizer/ASan smoke check failed"
                )
        if "valgrind" in options.detectors:
            if valgrind_available:
                detectors["valgrind"] = run_valgrind(
                    case,
                    tc,
                    run_dir,
                    case_dir,
                    support_objects,
                    compile_timeout_s=options.compile_timeout_s,
                    valgrind_timeout_factor=options.valgrind_timeout_factor,
                    extra_cflags=options.extra_cflags,
                    extra_ldflags=options.extra_ldflags,
                    valgrind_extra_args=options.valgrind_extra_args,
                )
            else:
                detectors["valgrind"] = _detector_scaffold(
                    "valgrind", False, "valgrind binary not available"
                )
    except Exception as exc:  # keep the run alive; record a harness failure
        harness_error = f"{type(exc).__name__}: {exc}"

    outcome = combine_outcome(detectors) if detectors else "unavailable"
    if harness_error and not any(
        (detector.get("status") in {"leak", "clean"}) for detector in detectors.values()
    ):
        outcome = "inconclusive"
    failure = "harness.exception" if harness_error else failure_class(detectors, outcome)
    record: dict[str, Any] = {
        "schema_version": "dynamic-cwe401/1.0",
        "task": "cwe401_dynamic_detection",
        "case_id": case.case_id,
        "source": _relative(case.source, options.rel_root or run_dir),
        "source_sha256": sha256_file(case.source),
        "sources": [_relative(path, options.rel_root or run_dir) for path in case.sources],
        "language": case.language,
        "cwe": case.cwe,
        "origin": case.origin,
        "variant": case.variant,
        "feature": case.feature,
        "expected_label": case.expected_label,
        "label_source": case.label_source,
        "outcome": outcome,
        "detected_label": 1 if outcome == "leak" else (0 if outcome == "clean" else None),
        "failure_class": failure,
        "runtime_class": runtime_class(detectors),
        "detectors": detectors,
        "evidence_summary": summarize(detectors, outcome),
        "harness_error": harness_error,
        "started_at_utc": started,
        "duration_ms": int((time.monotonic() - started_monotonic) * 1000),
        "metadata": dict(case.metadata),
        "artifacts": _relativize_artifacts(
            {
                "case_dir": str(case_dir),
                "detectors": {
                    name: detector.get("artifacts") or {}
                    for name, detector in detectors.items()
                },
            },
            run_dir,
        ),
    }
    return record


def _write_partial(path: Path, record: dict[str, Any], lock: threading.Lock) -> None:
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    with lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)


def run_evaluation(
    cases: list[CaseSpec],
    run_dir: Path,
    run_id: str,
    tc: Toolchain,
    options: RunOptions,
    *,
    input_metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    if run_dir.exists() and any(run_dir.iterdir()):
        raise RuntimeError(f"refusing to overwrite non-empty run directory: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "cases").mkdir(exist_ok=True)
    (run_dir / "support").mkdir(exist_ok=True)
    logger = RunLogger(run_dir / "run.log")
    rel_root = (options.rel_root or run_dir).resolve()

    if options.filter_text:
        needle = options.filter_text.lower()
        cases = [
            case
            for case in cases
            if needle
            in " ".join(
                [
                    case.case_id,
                    str(case.source),
                    str(case.variant or ""),
                    str(case.feature or ""),
                    str(case.metadata.get("juliet_relpath", "")),
                ]
            ).lower()
        ]
    if options.max_cases is not None:
        cases = cases[: max(0, options.max_cases)]
    if not cases:
        raise RuntimeError("no cases selected after filtering")

    cases_rows = [case.to_manifest_row(rel_root) for case in cases]
    write_jsonl(run_dir / "cases.jsonl", cases_rows)
    logger.write(f"run_id={run_id} selected_cases={len(cases)} detectors={','.join(options.detectors)}")
    if options.dry_run:
        write_json(
            run_dir / "manifest.json",
            {
                "schema_version": "dynamic-cwe401/1.0",
                "kind": "traditional_dynamic_cwe401_run",
                "run_id": run_id,
                "generated_at_utc": utc_now_iso(),
                "dry_run": True,
                "input": input_metadata or {},
                "toolchain": {
                    "cc": {"path": tc.cc, "version": tc.cc_version},
                    "cxx": {"path": tc.cxx, "version": tc.cxx_version},
                    "valgrind": {"path": tc.valgrind_bin, "version": tc.valgrind_version},
                },
                "config": {
                    "detectors": options.detectors,
                    "jobs": options.jobs,
                    "compile_timeout_s": options.compile_timeout_s,
                    "max_cases": options.max_cases,
                    "filter_text": options.filter_text,
                },
                "n_cases": len(cases),
                "cases_file": "cases.jsonl",
                "cases_sha256": sha256_file(run_dir / "cases.jsonl"),
            },
        )
        logger.write("dry run: manifests written, no compilation or execution")
        return {"manifest": {}, "results": [], "metrics": None}

    tool_check = check_tools(tc)
    asan_available = "asan" in options.detectors and bool(
        tool_check.get("asan", {}).get("available")
        and tool_check.get("asan", {}).get("leak_detected")
    )
    valgrind_available = "valgrind" in options.detectors and bool(
        tool_check.get("valgrind", {}).get("available")
        and tool_check.get("valgrind", {}).get("leak_detected")
        and not tool_check.get("valgrind", {}).get("parse_error")
    )
    if "asan" in options.detectors and not asan_available:
        logger.write("warning: ASan/LSan smoke check did not detect a leak; asan marked unavailable")
    if "valgrind" in options.detectors and not valgrind_available:
        logger.write("warning: Valgrind smoke check unavailable; valgrind marked unavailable")
    if not asan_available and not valgrind_available:
        raise RuntimeError("no selected detector passed its smoke test")

    support_objects: list[Path] = []
    support_logs: list[dict[str, Any]] = []
    support_dirs = sorted(
        {
            Path(case.metadata["support_dir"])
            for case in cases
            if case.metadata.get("support_dir")
        }
    )
    if support_dirs:
        if len(support_dirs) > 1:
            raise RuntimeError(f"multiple testcasesupport directories: {support_dirs}")
        support_objects, support_logs = build_support(support_dirs[0], run_dir / "support", tc)
        if not any(obj.name == "io.o" for obj in support_objects):
            raise RuntimeError(f"failed to build Juliet support objects: {support_logs}")
        logger.write(f"support_objects={[obj.name for obj in support_objects]}")

    manifest: dict[str, Any] = {
        "schema_version": "dynamic-cwe401/1.0",
        "kind": "traditional_dynamic_cwe401_run",
        "run_id": run_id,
        "generated_at_utc": utc_now_iso(),
        "finished_at_utc": None,
        "project_root": str(rel_root),
        "run_dir": str(run_dir.resolve()),
        "input": input_metadata or {},
        "toolchain": {
            "cc": {"path": tc.cc, "version": tc.cc_version},
            "cxx": {"path": tc.cxx, "version": tc.cxx_version},
            "valgrind": {
                "path": tc.valgrind_bin,
                "version": tc.valgrind_version,
            },
        },
        "tool_check": tool_check,
        "config": {
            "detectors": options.detectors,
            "jobs": options.jobs,
            "compile_timeout_s": options.compile_timeout_s,
            "valgrind_timeout_factor": options.valgrind_timeout_factor,
            "max_cases": options.max_cases,
            "filter_text": options.filter_text,
            "asan_options_extra": options.asan_options_extra,
            "valgrind_extra_args": options.valgrind_extra_args,
            "extra_cflags": options.extra_cflags,
            "extra_ldflags": options.extra_ldflags,
            "rel_root": str(rel_root),
            "dry_run": options.dry_run,
        },
        "label_rule": (
            "Ground truth comes from the manifest or from Juliet's preprocessor "
            "build variant. Predictions come only from runtime LeakSanitizer/Valgrind "
            "evidence; function names are not used as labels."
        ),
        "n_cases": len(cases),
        "cases_file": "cases.jsonl",
        "cases_sha256": sha256_file(run_dir / "cases.jsonl"),
        "results_file": "results.jsonl",
        "metrics_file": "metrics.json",
        "partial_file": "results.partial.jsonl",
        "limitations": [
            "Dynamic analysis only observes executed paths; untriggered branches are not evaluated.",
            "LeakSanitizer and Valgrind may disagree on reachability and leak kind.",
            "Juliet w32 cases are excluded; wchar_t cases are included unless excluded by the caller.",
            "No fault injection is used; leaks that require an allocation failure (e.g. realloc failure) may not be triggered.",
        ],
    }
    write_json(run_dir / "manifest.json", manifest)

    partial_path = run_dir / "results.partial.jsonl"
    if partial_path.exists():
        partial_path.unlink()
    partial_lock = threading.Lock()
    results: list[dict[str, Any]] = []
    started = time.monotonic()
    completed = 0
    total = len(cases)
    logger.write(f"starting {total} cases with {options.jobs} workers")
    with ThreadPoolExecutor(max_workers=max(1, options.jobs)) as pool:
        futures = {
            pool.submit(
                evaluate_case,
                case,
                tc,
                run_dir,
                support_objects,
                options,
                asan_available,
                valgrind_available,
            ): case
            for case in cases
        }
        for future in as_completed(futures):
            case = futures[future]
            try:
                record = future.result()
            except Exception as exc:
                record = {
                    "schema_version": "dynamic-cwe401/1.0",
                    "task": "cwe401_dynamic_detection",
                    "case_id": case.case_id,
                    "source": _relative(case.source, rel_root),
                    "language": case.language,
                    "origin": case.origin,
                    "variant": case.variant,
                    "feature": case.feature,
                    "expected_label": case.expected_label,
                    "outcome": "inconclusive",
                    "detected_label": None,
                    "failure_class": "harness.exception",
                    "runtime_class": "not_run",
                    "detectors": {},
                    "harness_error": f"{type(exc).__name__}: {exc}",
                }
                logger.write(f"worker_error case={case.case_id}: {record['harness_error']}")
            results.append(record)
            _write_partial(partial_path, record, partial_lock)
            completed += 1
            if completed % 25 == 0 or completed == total:
                elapsed = time.monotonic() - started
                rate = completed / elapsed if elapsed > 0 else 0.0
                logger.write(
                    f"progress {completed}/{total} ({rate:.2f} cases/s, "
                    f"{elapsed:.1f}s elapsed)"
                )

    results.sort(key=lambda item: item["case_id"])
    write_jsonl(run_dir / "results.jsonl", results)
    try:
        partial_path.unlink()
    except OSError:
        pass

    config = manifest["config"]
    metrics = compute_metrics(
        results,
        run_id=run_id,
        toolchain=manifest["toolchain"],
        config={**config, "support_logs": support_logs},
        generated_at_utc=utc_now_iso(),
    )
    write_json(run_dir / "metrics.json", metrics)
    (run_dir / "metrics.md").write_text(render_markdown(metrics), encoding="utf-8")

    manifest["finished_at_utc"] = utc_now_iso()
    manifest["n_results"] = len(results)
    manifest["results_sha256"] = sha256_file(run_dir / "results.jsonl")
    manifest["metrics_sha256"] = sha256_file(run_dir / "metrics.json")
    manifest["counts"] = metrics["counts"]
    manifest["combined"] = metrics["combined"]
    manifest["detectors"] = metrics["detectors"]
    write_json(run_dir / "manifest.json", manifest)
    logger.write(
        "finished: "
        + ", ".join(f"{key}={value}" for key, value in metrics["counts"]["outcomes"].items())
    )
    return {"manifest": manifest, "results": results, "metrics": metrics}

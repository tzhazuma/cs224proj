from __future__ import annotations

from typing import Any, Optional


def _first_execution(detectors: dict[str, dict[str, Any]]) -> Optional[dict[str, Any]]:
    for name in ("asan", "valgrind"):
        detector = detectors.get(name) or {}
        execution = detector.get("execution")
        if execution:
            return execution
    return None


def runtime_class(detectors: dict[str, dict[str, Any]]) -> str:
    execution = _first_execution(detectors)
    if not execution:
        return "not_run"
    if execution.get("timed_out"):
        return "timeout"
    if execution.get("spawn_error"):
        return "spawn_error"
    if execution.get("signal_name"):
        return f"signal:{execution['signal_name']}"
    exit_code = execution.get("exit_code")
    if exit_code == 0:
        return "exited_zero"
    if exit_code is not None:
        return "exited_nonzero"
    return "unknown"


def combine_outcome(detectors: dict[str, dict[str, Any]]) -> str:
    statuses = {name: detector.get("status") for name, detector in detectors.items()}
    available = {
        name: detector
        for name, detector in detectors.items()
        if detector.get("available", True)
    }
    if any(status == "leak" for status in statuses.values()):
        return "leak"
    if any(status == "clean" for status in statuses.values()):
        return "clean"
    if not available or all(
        detector.get("status") in {"unavailable", "not_run"} and not detector.get("build")
        for detector in available.values()
    ):
        return "unavailable"

    builds = [
        detector.get("build")
        for detector in detectors.values()
        if detector.get("build")
    ]
    any_execution = any(detector.get("execution") for detector in detectors.values())
    any_timeout = any(
        (detector.get("execution") or {}).get("timed_out")
        for detector in detectors.values()
    )
    build_failed = any(build and not build.get("ok") for build in builds)
    if build_failed and not any_execution:
        return "build_failed"
    if any_timeout:
        return "timeout"
    if build_failed and not any(
        detector.get("status") in {"leak", "clean"} for detector in detectors.values()
    ):
        return "build_failed"
    return "inconclusive"


def failure_class(detectors: dict[str, dict[str, Any]], outcome: str) -> Optional[str]:
    if outcome in {"leak", "clean"}:
        return None
    if outcome == "unavailable":
        return "tool.unavailable"
    if outcome == "build_failed":
        classes: list[str] = []
        for name in ("asan", "valgrind"):
            build = (detectors.get(name) or {}).get("build")
            if build and not build.get("ok"):
                status = build.get("status") or "unknown"
                classes.append(f"compile.{status}")
        if classes:
            return ",".join(sorted(set(classes)))
        return "compile.unknown"
    if outcome == "timeout":
        return "runtime.timeout"
    for name in ("asan", "valgrind"):
        evidence = (detectors.get(name) or {}).get("evidence") or {}
        errors = list(evidence.get("memory_errors") or [])
        if not errors:
            errors = [
                item.get("kind")
                for item in evidence.get("other_errors", [])
                if item.get("kind")
            ]
        if errors:
            return f"runtime.{name}_error:{errors[0]}"
    execution = _first_execution(detectors)
    if execution:
        if execution.get("spawn_error"):
            return "runtime.spawn_error"
        if execution.get("signal_name"):
            return f"runtime.signal:{execution['signal_name']}"
        if execution.get("exit_code") not in (None, 0, 23, 99):
            return "runtime.nonzero_exit"
        if execution.get("exit_code") in (23, 99):
            return "runtime.detector_exit_without_parsed_evidence"
    for detector in detectors.values():
        notes = detector.get("notes") or []
        if any("fatal" in note.lower() or "error" in note.lower() for note in notes):
            return "tool.error"
    return "runtime.unknown"


def summarize(detectors: dict[str, dict[str, Any]], outcome: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "outcome": outcome,
        "detectors": {},
    }
    for name in ("asan", "valgrind"):
        detector = detectors.get(name)
        if not detector:
            continue
        summary["detectors"][name] = {
            "status": detector.get("status"),
            "leak_detected": detector.get("leak_detected"),
            "leaked_bytes": detector.get("leaked_bytes"),
            "notes": detector.get("notes") or [],
        }
    return summary

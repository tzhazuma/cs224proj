from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from .build import build_case
from .config import asan_environment, valgrind_command
from .discover import CaseSpec
from .sanitizer import detector_status as lsan_status
from .sanitizer import parse_lsan
from .toolchain import Toolchain
from .util import ProcResult, read_text, run_process, truncate_text
from .valgrind import detector_status as valgrind_status
from .valgrind import parse_valgrind_xml


def _execution_record(proc: ProcResult) -> dict[str, Any]:
    return {
        "status": "timeout" if proc.timed_out else ("spawn_error" if proc.spawn_error else "completed"),
        "exit_code": proc.exit_code,
        "signal": proc.signal_number,
        "signal_name": proc.signal_name,
        "timed_out": proc.timed_out,
        "spawn_error": proc.spawn_error,
        "duration_ms": proc.duration_ms,
        "command": proc.command,
        "stdout_path": proc.stdout_path,
        "stderr_path": proc.stderr_path,
        "stdout_excerpt": truncate_text(proc.stdout, 4000),
        "stderr_excerpt": truncate_text(proc.stderr, 8000),
    }


def _base_env(case: CaseSpec) -> dict[str, str]:
    env = dict(os.environ)
    env.update(case.env)
    return env


def _run_cwd(case: CaseSpec) -> Path:
    return case.cwd if case.cwd is not None else case.source.parent


def _stdin(case: CaseSpec) -> Optional[bytes]:
    if case.stdin_data is None:
        return None
    if isinstance(case.stdin_data, str):
        return case.stdin_data.encode("utf-8")
    return bytes(case.stdin_data)


def _existing_asan_logs(log_dir: Path) -> list[Path]:
    return sorted(path for path in log_dir.glob("asan.*") if path.is_file())


def run_asan(
    case: CaseSpec,
    tc: Toolchain,
    run_dir: Path,
    case_dir: Path,
    support_objects: list[Path],
    *,
    compile_timeout_s: float = 120.0,
    extra_cflags: Optional[list[str]] = None,
    extra_ldflags: Optional[list[str]] = None,
    asan_options_extra: str = "",
) -> dict[str, Any]:
    build = build_case(
        case,
        "asan",
        tc,
        case_dir,
        support_objects,
        compile_timeout_s=compile_timeout_s,
        extra_cflags=extra_cflags,
        extra_ldflags=extra_ldflags,
    )
    result: dict[str, Any] = {
        "name": "asan",
        "available": True,
        "status": "not_run",
        "leak_detected": None,
        "leaked_bytes": None,
        "build": build,
        "execution": None,
        "evidence": None,
        "notes": [],
        "artifacts": {},
    }
    if not build["ok"]:
        result["notes"].append(f"build failed: {build['status']}")
        return result

    log_dir = case_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    for old in _existing_asan_logs(log_dir):
        try:
            old.unlink()
        except OSError:
            pass
    prefix = log_dir / "asan"
    stdout_path = log_dir / "run_asan.stdout"
    stderr_path = log_dir / "run_asan.stderr"
    command = [build["binary"], *case.argv]
    proc = run_process(
        command,
        cwd=_run_cwd(case),
        env=asan_environment(_base_env(case), prefix, asan_options_extra),
        timeout_s=case.timeout_s,
        stdin_data=_stdin(case),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        capture_limit=65536,
    )
    result["execution"] = _execution_record(proc)

    asan_logs = _existing_asan_logs(log_dir)
    if asan_logs:
        text = "\n".join(read_text(path) for path in asan_logs)
        evidence_source = "asan_log"
    else:
        text = proc.stderr
        evidence_source = "stderr"
    parsed = parse_lsan(text)
    status, notes = lsan_status(
        parsed,
        exit_code=proc.exit_code,
        timed_out=proc.timed_out,
        spawn_error=proc.spawn_error,
        signal_name=proc.signal_name,
    )
    result.update(
        {
            "status": status,
            "leak_detected": bool(parsed["leak_detected"]),
            "leaked_bytes": parsed["leaked_bytes"],
            "evidence": parsed,
            "notes": notes,
            "artifacts": {
                "binary": str(build["binary"]),
                "build_log": build["log_path"],
                "build_stderr": build["stderr_path"],
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
                "asan_logs": [str(path) for path in asan_logs],
                "evidence_source": evidence_source,
            },
        }
    )
    return result


def run_valgrind(
    case: CaseSpec,
    tc: Toolchain,
    run_dir: Path,
    case_dir: Path,
    support_objects: list[Path],
    *,
    compile_timeout_s: float = 120.0,
    valgrind_timeout_factor: float = 3.0,
    extra_cflags: Optional[list[str]] = None,
    extra_ldflags: Optional[list[str]] = None,
    valgrind_extra_args: Optional[list[str]] = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": "valgrind",
        "available": bool(tc.valgrind_bin),
        "status": "not_run",
        "leak_detected": None,
        "leaked_bytes": None,
        "build": None,
        "execution": None,
        "evidence": None,
        "notes": [],
        "artifacts": {},
    }
    if not tc.valgrind_bin:
        result["notes"].append("valgrind binary not available")
        return result
    build = build_case(
        case,
        "native",
        tc,
        case_dir,
        support_objects,
        compile_timeout_s=compile_timeout_s,
        extra_cflags=extra_cflags,
        extra_ldflags=extra_ldflags,
    )
    result["build"] = build
    if not build["ok"]:
        result["notes"].append(f"build failed: {build['status']}")
        return result

    log_dir = case_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    xml_path = log_dir / "valgrind.xml"
    log_path = log_dir / "valgrind.log"
    for old in (xml_path, log_path):
        try:
            old.unlink()
        except OSError:
            pass
    stderr_path = log_dir / "run_valgrind.stderr"
    stdout_path = log_dir / "run_valgrind.stdout"
    command = valgrind_command(
        tc.valgrind_bin,
        Path(build["binary"]),
        xml_path,
        log_path,
        case.argv,
        valgrind_extra_args,
    )
    timeout_s = max(case.timeout_s * valgrind_timeout_factor, case.timeout_s + 5.0)
    proc = run_process(
        command,
        cwd=_run_cwd(case),
        env=_base_env(case),
        timeout_s=timeout_s,
        stdin_data=_stdin(case),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        capture_limit=65536,
    )
    result["execution"] = _execution_record(proc)
    parsed = parse_valgrind_xml(xml_path)
    status, notes = valgrind_status(
        parsed,
        exit_code=proc.exit_code,
        timed_out=proc.timed_out,
        spawn_error=proc.spawn_error,
        signal_name=proc.signal_name,
    )
    result.update(
        {
            "status": status,
            "leak_detected": bool(parsed["leak_detected"]),
            "leaked_bytes": parsed["definite_bytes"] if parsed["leak_detected"] else 0,
            "evidence": parsed,
            "notes": notes,
            "artifacts": {
                "binary": str(build["binary"]),
                "build_log": build["log_path"],
                "build_stderr": build["stderr_path"],
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
                "valgrind_xml": str(xml_path),
                "valgrind_log": str(log_path),
                "evidence_source": "valgrind_xml",
            },
        }
    )
    return result

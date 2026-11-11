from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from .discover import CaseSpec
from .toolchain import Toolchain
from .util import run_process, truncate_text


BUILD_STATUSES = {
    "ok",
    "compiler_error",
    "link_error",
    "missing_header",
    "timeout",
    "spawn_error",
    "unknown_error",
}


def classify_build(stderr: str, exit_code: Optional[int], timed_out: bool, spawn_error: Optional[str]) -> str:
    if spawn_error:
        return "spawn_error"
    if timed_out:
        return "timeout"
    if exit_code == 0:
        return "ok"
    text = (stderr or "").lower()
    if "fatal error:" in text and "no such file or directory" in text:
        return "missing_header"
    if (
        "undefined reference" in text
        or "ld returned" in text
        or "collect2: error" in text
        or "linker command failed" in text
    ):
        return "link_error"
    if "error:" in text or "fatal error:" in text or "compilation terminated" in text:
        return "compiler_error"
    return "unknown_error"


def build_case(
    case: CaseSpec,
    detector: str,
    tc: Toolchain,
    case_dir: Path,
    support_objects: list[Path],
    *,
    compile_timeout_s: float = 120.0,
    extra_cflags: Optional[list[str]] = None,
    extra_ldflags: Optional[list[str]] = None,
) -> dict[str, Any]:
    log_dir = case_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    binary = case_dir / f"case.{detector}"
    compiler = tc.cxx if case.language == "cpp" else tc.cc
    std_flag = "-std=gnu++14" if case.language == "cpp" else "-std=gnu11"
    command: list[str] = [compiler, "-g", "-O0", "-fno-omit-frame-pointer", "-w", std_flag]
    command.extend(case.cflags)
    command.extend(extra_cflags or [])
    if detector == "asan":
        command.append("-fsanitize=address")
    command.extend(f"-D{define}" for define in case.defines)
    command.extend(f"-I{directory}" for directory in case.include_dirs)
    command.extend(str(source) for source in case.sources)
    command.extend(str(obj) for obj in support_objects)
    command.extend(case.ldflags)
    command.extend(extra_ldflags or [])
    command.extend(["-lm", "-pthread", "-o", str(binary)])

    log_path = log_dir / f"build_{detector}.log"
    error_path = log_dir / f"build_{detector}.stderr"
    proc = run_process(
        command,
        cwd=case.source.parent,
        timeout_s=compile_timeout_s,
        stdout_path=log_path,
        stderr_path=error_path,
        capture_limit=32768,
    )
    status = classify_build(proc.stderr, proc.exit_code, proc.timed_out, proc.spawn_error)
    ok = status == "ok" and binary.is_file()
    if status == "ok" and not binary.is_file():
        status = "unknown_error"
        ok = False
    return {
        "detector": detector,
        "ok": ok,
        "status": status,
        "exit_code": proc.exit_code,
        "signal": proc.signal_name,
        "timed_out": proc.timed_out,
        "duration_ms": proc.duration_ms,
        "command": command,
        "binary": str(binary),
        "log_path": str(log_path),
        "stderr_path": str(error_path),
        "stderr_excerpt": truncate_text(proc.stderr, 8000),
    }

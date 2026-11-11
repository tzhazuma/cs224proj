from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import asan_environment, valgrind_command
from .sanitizer import parse_lsan
from .util import ProcResult, run_process, tool_version, which
from .valgrind import parse_valgrind_xml


@dataclass
class Toolchain:
    cc: str
    cxx: str
    cc_version: str
    cxx_version: str
    valgrind_bin: Optional[str] = None
    valgrind_version: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


def resolve_compiler(explicit: Optional[str], default: str, fallback: str) -> str:
    candidate = explicit or which(default) or which(fallback)
    if not candidate:
        raise RuntimeError(f"neither {default} nor {fallback} found on PATH")
    path = Path(candidate).expanduser()
    if not path.is_file() and not which(str(path)):
        raise RuntimeError(f"compiler not found: {candidate}")
    return str(path) if path.is_file() else str(candidate)


def resolve_valgrind(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return str(path)
        found = which(str(path))
        if found:
            return found
        raise RuntimeError(f"valgrind not found: {explicit}")
    return which("valgrind")


def make_toolchain(cc: Optional[str], cxx: Optional[str], valgrind_bin: Optional[str]) -> Toolchain:
    resolved_cc = resolve_compiler(cc, "gcc", "clang")
    resolved_cxx = resolve_compiler(cxx, "g++", "clang++")
    resolved_vg = resolve_valgrind(valgrind_bin)
    return Toolchain(
        cc=resolved_cc,
        cxx=resolved_cxx,
        cc_version=tool_version(resolved_cc),
        cxx_version=tool_version(resolved_cxx),
        valgrind_bin=resolved_vg,
        valgrind_version=tool_version(resolved_vg) if resolved_vg else None,
    )


def build_support(
    support_dir: Path,
    out_dir: Path,
    tc: Toolchain,
    *,
    timeout_s: float = 120.0,
) -> tuple[list[Path], list[dict[str, Any]]]:
    """Compile Juliet's io.c / std_thread.c once and return object files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    objects: list[Path] = []
    logs: list[dict[str, Any]] = []
    sources = [support_dir / "io.c", support_dir / "std_thread.c"]
    for source in sources:
        if not source.is_file():
            continue
        target = out_dir / (source.stem + ".o")
        command = [
            tc.cc,
            "-g",
            "-O0",
            "-w",
            "-pthread",
            f"-I{support_dir}",
            "-c",
            str(source),
            "-o",
            str(target),
        ]
        proc = run_process(
            command,
            cwd=out_dir,
            timeout_s=timeout_s,
            stdout_path=out_dir / (source.stem + ".build.log"),
            stderr_path=out_dir / (source.stem + ".build.err"),
        )
        logs.append(
            {
                "source": str(source),
                "command": command,
                "exit_code": proc.exit_code,
                "timed_out": proc.timed_out,
                "duration_ms": proc.duration_ms,
                "stderr": proc.stderr,
                "ok": proc.exit_code == 0 and not proc.timed_out and target.is_file(),
            }
        )
        if proc.exit_code == 0 and not proc.timed_out and target.is_file():
            objects.append(target)
    return objects, logs


def _smoke_text(workdir: Path, prefix: Path, stderr: str) -> str:
    logs = sorted(
        path for path in workdir.glob(prefix.name + ".*") if path.is_file()
    )
    if logs:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in logs)
    return stderr


def _asan_smoke(cc: str, workdir: Path) -> dict[str, Any]:
    leak_source = workdir / "smoke_leak.c"
    clean_source = workdir / "smoke_clean.c"
    leak_source.write_text(
        "#include <stdlib.h>\n"
        "int main(void) { char *p = (char *)malloc(32); if (!p) return 2; "
        "p[0] = 1; return 0; }\n",
        encoding="utf-8",
    )
    clean_source.write_text(
        "#include <stdlib.h>\n"
        "int main(void) { char *p = (char *)malloc(32); if (!p) return 2; "
        "p[0] = 1; free(p); return 0; }\n",
        encoding="utf-8",
    )
    result: dict[str, Any] = {"available": False, "leak_detected": None, "clean_detected": None}
    binary = workdir / "smoke_asan"
    build = run_process(
        [cc, "-g", "-O0", "-fsanitize=address", str(leak_source), "-o", str(binary)],
        cwd=workdir,
        timeout_s=60,
        stdout_path=workdir / "smoke_build.out",
        stderr_path=workdir / "smoke_build.err",
    )
    result["build_exit_code"] = build.exit_code
    result["build_stderr"] = build.stderr
    if build.exit_code != 0 or not binary.is_file():
        result["error"] = "ASan smoke build failed"
        return result
    run = run_process(
        [str(binary)],
        cwd=workdir,
        env=asan_environment(None, workdir / "smoke"),
        timeout_s=20,
        stdout_path=workdir / "smoke_run.out",
        stderr_path=workdir / "smoke_run.err",
    )
    parsed = parse_lsan(_smoke_text(workdir, workdir / "smoke", run.stderr))
    result.update(
        {
            "available": True,
            "leak_detected": parsed["leak_detected"],
            "leaked_bytes": parsed["leaked_bytes"],
            "exit_code": run.exit_code,
            "timed_out": run.timed_out,
            "evidence_excerpt": parsed["evidence_excerpt"],
        }
    )
    clean_binary = workdir / "smoke_clean"
    clean_build = run_process(
        [cc, "-g", "-O0", "-fsanitize=address", str(clean_source), "-o", str(clean_binary)],
        cwd=workdir,
        timeout_s=60,
        stdout_path=workdir / "smoke_clean_build.out",
        stderr_path=workdir / "smoke_clean_build.err",
    )
    if clean_build.exit_code == 0 and clean_binary.is_file():
        clean_run = run_process(
            [str(clean_binary)],
            cwd=workdir,
            env=asan_environment(None, workdir / "smoke_clean"),
            timeout_s=20,
            stdout_path=workdir / "smoke_clean_run.out",
            stderr_path=workdir / "smoke_clean_run.err",
        )
        clean_parsed = parse_lsan(_smoke_text(workdir, workdir / "smoke_clean", clean_run.stderr))
        result["clean_detected"] = not clean_parsed["leak_detected"]
        result["clean_exit_code"] = clean_run.exit_code
    result["leak_exit_code"] = run.exit_code
    return result


def _valgrind_smoke(cc: str, vg: str, workdir: Path) -> dict[str, Any]:
    source = workdir / "smoke_valgrind.c"
    source.write_text(
        "#include <stdlib.h>\n"
        "int main(void) { char *p = (char *)malloc(32); if (!p) return 2; "
        "p[0] = 1; return 0; }\n",
        encoding="utf-8",
    )
    binary = workdir / "smoke_plain"
    build = run_process(
        [cc, "-g", "-O0", str(source), "-o", str(binary)],
        cwd=workdir,
        timeout_s=60,
        stdout_path=workdir / "smoke_vg_build.out",
        stderr_path=workdir / "smoke_vg_build.err",
    )
    result: dict[str, Any] = {"available": False, "leak_detected": None}
    if build.exit_code != 0 or not binary.is_file():
        result["error"] = "Valgrind smoke build failed"
        result["build_stderr"] = build.stderr
        return result
    xml = workdir / "smoke_valgrind.xml"
    log = workdir / "smoke_valgrind.log"
    command = valgrind_command(vg, binary, xml, log, [])
    run = run_process(
        command,
        cwd=workdir,
        timeout_s=60,
        stdout_path=workdir / "smoke_vg_run.out",
        stderr_path=workdir / "smoke_vg_run.err",
    )
    parsed = parse_valgrind_xml(xml)
    result.update(
        {
            "available": True,
            "leak_detected": parsed["leak_detected"],
            "definite_bytes": parsed["definite_bytes"],
            "exit_code": run.exit_code,
            "timed_out": run.timed_out,
            "parse_error": parsed["parse_error"],
            "evidence_excerpt": parsed["evidence_excerpt"],
        }
    )
    return result


def check_tools(tc: Toolchain) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dynleak-toolcheck-") as tmp:
        workdir = Path(tmp)
        asan = _asan_smoke(tc.cc, workdir)
        valgrind_result: dict[str, Any] = {
            "available": False,
            "reason": "valgrind binary not found",
        }
        if tc.valgrind_bin:
            valgrind_result = _valgrind_smoke(tc.cc, tc.valgrind_bin, workdir)
        report = {
            "ok": bool(asan.get("available") and asan.get("leak_detected")),
            "python": sys.version.split()[0],
            "platform": os.uname().sysname + " " + os.uname().release if hasattr(os, "uname") else os.name,
            "cc": {"path": tc.cc, "version": tc.cc_version},
            "cxx": {"path": tc.cxx, "version": tc.cxx_version},
            "asan": asan,
            "valgrind": {
                "path": tc.valgrind_bin,
                "version": tc.valgrind_version,
                **valgrind_result,
            },
        }
        return report

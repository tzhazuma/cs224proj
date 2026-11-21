"""Compile one Juliet unit in the two variants the experiment needs.

variant "plain": normal ASan build used by the default and nogobal modes.
variant "wrap":  the same build plus the --wrap=realloc injection object used
                 by the realloc_fail mode.

The raw frozen sources are compiled unchanged; the only evaluator-provided
translation unit is the probe main.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from .probe import write_probe
from .units import Unit


@dataclass
class BuildResult:
    ok: bool
    variant: str
    command: list[str]
    exe: Path | None
    returncode: int | None
    timed_out: bool
    compile_ms: int
    stderr_tail: str
    probe_text: str
    probe_path: Path | None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "variant": self.variant,
            "command": self.command,
            "exe": str(self.exe) if self.exe else None,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "compile_ms": self.compile_ms,
            "stderr_tail": self.stderr_tail,
            "probe_path": str(self.probe_path) if self.probe_path else None,
        }


def _run(cmd: list[str], timeout: int, cwd: Path) -> dict:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed = int((time.monotonic() - started) * 1000)
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace"),
            "timed_out": False,
            "ms": elapsed,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return {
            "returncode": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "timed_out": True,
            "ms": elapsed,
        }


def support_objects(build_root: Path) -> dict[str, Path]:
    obj_dir = build_root / "support"
    obj_dir.mkdir(parents=True, exist_ok=True)
    objects: dict[str, Path] = {}
    for name in config.SUPPORT_SOURCES:
        source = config.SUPPORT / name
        obj = obj_dir / (source.stem + ".o")
        if not obj.exists() or obj.stat().st_mtime < source.stat().st_mtime:
            result = _run(
                [
                    "gcc", "-std=gnu11", "-O0", "-g", "-fsanitize=address",
                    "-fno-omit-frame-pointer", "-w", "-I", str(config.SUPPORT),
                    "-c", str(source), "-o", str(obj),
                ],
                timeout=config.COMPILE_TIMEOUT,
                cwd=build_root,
            )
            if result["returncode"] != 0:
                raise RuntimeError(f"support build failed for {name}:\n{result['stderr']}")
        objects[name] = obj
    return objects


def injection_object(build_root: Path) -> Path:
    obj_dir = build_root / "support"
    obj_dir.mkdir(parents=True, exist_ok=True)
    source = config.ASSETS / "inject_realloc.c"
    obj = obj_dir / "inject_realloc.o"
    if not obj.exists() or obj.stat().st_mtime < source.stat().st_mtime:
        result = _run(
            [
                "gcc", "-std=gnu11", "-O0", "-g", "-fsanitize=address",
                "-fno-omit-frame-pointer", "-w", "-c", str(source), "-o", str(obj),
            ],
            timeout=config.COMPILE_TIMEOUT,
            cwd=build_root,
        )
        if result["returncode"] != 0:
            raise RuntimeError(f"injection build failed:\n{result['stderr']}")
    return obj


def compile_unit(
    unit: Unit,
    label: str,
    workdir: Path,
    build_root: Path,
    variant: str,
    objects: dict[str, Path],
    injection: Path | None,
) -> BuildResult:
    if variant not in ("plain", "wrap"):
        raise ValueError(f"unknown build variant {variant}")
    workdir.mkdir(parents=True, exist_ok=True)
    probe_path, probe_text = write_probe(unit, label, workdir)
    exe = workdir / f"{label}.{variant}.exe"
    omit = "-DOMITGOOD" if label == "bad" else "-DOMITBAD"
    include_dirs = [str(config.SUPPORT)]
    for source in unit.sources:
        parent = str(source.parent)
        if parent not in include_dirs:
            include_dirs.append(parent)
    cmd = [
        unit.compiler, unit.std, "-O0", "-g", "-fsanitize=address",
        "-fno-omit-frame-pointer", "-w", omit,
    ]
    for directory in include_dirs:
        cmd.extend(["-I", directory])
    cmd.extend(["-o", str(exe)])
    cmd.extend(str(source) for source in unit.sources)
    cmd.append(str(probe_path))
    cmd.extend([str(objects["io.c"]), str(objects["std_thread.c"])])
    if variant == "wrap":
        if injection is None:
            raise ValueError("wrap build requires the injection object")
        cmd.append(str(injection))
        cmd.append("-Wl,--wrap=realloc")
    cmd.extend(["-lpthread", "-lm"])
    result = _run(cmd, timeout=config.COMPILE_TIMEOUT, cwd=workdir)
    ok = result["returncode"] == 0 and exe.exists()
    return BuildResult(
        ok=ok,
        variant=variant,
        command=cmd,
        exe=exe if ok else None,
        returncode=result["returncode"],
        timed_out=result["timed_out"],
        compile_ms=result["ms"],
        stderr_tail=result["stderr"][-6000:],
        probe_text=probe_text,
        probe_path=probe_path,
    )

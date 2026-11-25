"""Compile the frozen unit once with gcov+ASan and link the two binaries.

The unit sources and the evaluator probe are compiled once.  The plain binary
serves the ``default`` and ``nogobal`` runs; the wrap binary adds the same
``--wrap=realloc`` injection object used by ``dynamic_enhanced``.  Compiling
once (instead of once per mode) keeps the gcov block numbering identical
across modes, which is what makes the union of branch hits meaningful.

The raw Juliet files are compiled unchanged; the only extra translation unit
is the probe main.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .units import Unit, write_probe

# units.py inserted the read-only dynamic_enhanced package root into sys.path.
from dyne.build import injection_object, support_objects  # noqa: E402


@dataclass
class StepResult:
    ok: bool
    command: list[str]
    returncode: int | None
    timed_out: bool
    ms: int
    stderr_tail: str

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "command": self.command,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "ms": self.ms,
            "stderr_tail": self.stderr_tail,
        }


@dataclass
class UnitBuild:
    ok: bool
    probe_path: Path | None
    probe_text: str
    objects: list[Path] = field(default_factory=list)
    object_dir: Path | None = None
    plain: StepResult | None = None
    wrap: StepResult | None = None
    plain_exe: Path | None = None
    wrap_exe: Path | None = None
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "probe_path": str(self.probe_path) if self.probe_path else None,
            "object_dir": str(self.object_dir) if self.object_dir else None,
            "objects": [str(path) for path in self.objects],
            "plain": self.plain.as_dict() if self.plain else None,
            "wrap": self.wrap.as_dict() if self.wrap else None,
            "plain_exe": str(self.plain_exe) if self.plain_exe else None,
            "wrap_exe": str(self.wrap_exe) if self.wrap_exe else None,
            "errors": list(self.errors),
        }


def _run(cmd: list[str], timeout: int, cwd: Path) -> dict:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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


def compile_objects(
    unit: Unit, workdir: Path, object_dir: Path
) -> tuple[Path, str, list[Path], list[StepResult]]:
    object_dir.mkdir(parents=True, exist_ok=True)
    probe_path, probe_text = write_probe(unit, unit.label, workdir)
    omit = "-DOMITGOOD" if unit.label == "bad" else "-DOMITBAD"
    include_dirs = [str(config.SUPPORT)]
    for source in unit.sources:
        parent = str(source.parent)
        if parent not in include_dirs:
            include_dirs.append(parent)
    steps: list[StepResult] = []
    objects: list[Path] = []
    for source in list(unit.sources) + [probe_path]:
        obj = object_dir / (source.stem + ".o")
        cmd = [
            unit.compiler, unit.std, "-O0", "-g", "-fsanitize=address",
            "-fno-omit-frame-pointer", "--coverage", "-w", omit,
        ]
        for directory in include_dirs:
            cmd.extend(["-I", directory])
        cmd.extend(["-c", str(source), "-o", str(obj)])
        result = _run(cmd, config.COMPILE_TIMEOUT, workdir)
        steps.append(
            StepResult(
                ok=result["returncode"] == 0 and obj.exists(),
                command=cmd,
                returncode=result["returncode"],
                timed_out=result["timed_out"],
                ms=result["ms"],
                stderr_tail=result["stderr"][-6000:],
            )
        )
        if not steps[-1].ok:
            break
        objects.append(obj)
    return probe_path, probe_text, objects, steps


def link_binary(
    unit: Unit,
    objects: list[Path],
    support: dict[str, Path],
    injection: Path,
    exe: Path,
    workdir: Path,
    variant: str,
) -> StepResult:
    if variant not in ("plain", "wrap"):
        raise ValueError(variant)
    cmd = [unit.compiler, "--coverage", "-fsanitize=address", "-o", str(exe)]
    cmd.extend(str(obj) for obj in objects)
    cmd.extend([str(support["io.c"]), str(support["std_thread.c"])])
    if variant == "wrap":
        cmd.extend([str(injection), "-Wl,--wrap=realloc"])
    cmd.extend(["-lpthread", "-lm"])
    result = _run(cmd, config.COMPILE_TIMEOUT, workdir)
    return StepResult(
        ok=result["returncode"] == 0 and exe.exists(),
        command=cmd,
        returncode=result["returncode"],
        timed_out=result["timed_out"],
        ms=result["ms"],
        stderr_tail=result["stderr"][-6000:],
    )


def build_unit(
    unit: Unit,
    case_dir: Path,
    build_root: Path,
    support: dict[str, Path],
    injection: Path,
) -> UnitBuild:
    workdir = case_dir / "build"
    workdir.mkdir(parents=True, exist_ok=True)
    object_dir = workdir / "obj"
    probe_path, probe_text, objects, steps = compile_objects(unit, workdir, object_dir)
    error = None
    for index, step in enumerate(steps):
        if not step.ok:
            error = f"compile failed at object {index}: {step.stderr_tail[-1200:]}"
            break
    build = UnitBuild(
        ok=error is None,
        probe_path=probe_path,
        probe_text=probe_text,
        objects=objects,
        object_dir=object_dir,
        errors=[error] if error else [],
    )
    if not build.ok:
        build.plain = steps[-1] if steps else None
        return build
    plain_exe = workdir / "unit.plain.exe"
    wrap_exe = workdir / "unit.wrap.exe"
    build.plain = link_binary(unit, objects, support, injection, plain_exe, workdir, "plain")
    build.plain_exe = plain_exe if build.plain.ok else None
    build.wrap = link_binary(unit, objects, support, injection, wrap_exe, workdir, "wrap")
    build.wrap_exe = wrap_exe if build.wrap.ok else None
    if not build.plain.ok:
        build.ok = False
        build.errors.append("plain link failed")
    if not build.wrap.ok:
        # The default/nogobal modes are still evaluable; the realloc_fail mode
        # is reported as not_evaluable rather than guessed.
        build.errors.append("wrap link failed")
    return build


def prepare_support(build_root: Path) -> tuple[dict[str, Path], Path]:
    return support_objects(build_root), injection_object(build_root)

#!/usr/bin/env python3
"""Compile and run individual Juliet CWE-401 test cases with ASan/LSan."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_juliet as lj  # noqa: E402

ASAN_OPTIONS = "detect_leaks=1:abort_on_error=0:exitcode=23"
LSAN_OPTIONS = "exitcode=23"


def _run(cmd: list[str], timeout: int, env: dict | None = None, cwd: Path | None = None) -> dict:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace"),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "timed_out": True,
        }


def support_objects(build_root: Path) -> dict[str, Path]:
    obj_dir = build_root / "support"
    obj_dir.mkdir(parents=True, exist_ok=True)
    objs = {}
    for name in ("io.c", "std_thread.c"):
        src = lj.SUPPORT / name
        obj = obj_dir / (src.stem + ".o")
        if not obj.exists() or obj.stat().st_mtime < src.stat().st_mtime:
            res = _run(
                [
                    "gcc", "-std=gnu11", "-O0", "-g", "-fsanitize=address",
                    "-fno-omit-frame-pointer", "-w", "-I", str(lj.SUPPORT),
                    "-c", str(src), "-o", str(obj),
                ],
                timeout=120,
            )
            if res["returncode"] != 0:
                raise RuntimeError(f"support build failed for {name}:\n{res['stderr']}")
        objs[name] = obj
    return objs


def _parse_part(path: Path) -> str | None:
    info = lj.parse_name(path.name)
    return info["part"] if info else None


def sources_for_label(tc: lj.TestCase, label: str) -> tuple[list[Path] | None, str | None]:
    main_srcs = sorted({p for p, _ in tc.main_defs})
    if not main_srcs:
        return None, "no INCLUDEMAIN source"
    if len(main_srcs) == 1:
        return tc.sources, None
    wanted = "bad" if label == "bad" else "good"
    chosen = [p for p in main_srcs if (_parse_part(p) or "").startswith(wanted)]
    if len(chosen) != 1:
        return None, f"cannot choose {wanted} main among {[p.name for p in main_srcs]}"
    others = [p for p in tc.sources if p not in main_srcs]
    return [chosen[0]] + others, None


def compile_unit(tc: lj.TestCase, label: str, build_root: Path, objs: dict[str, Path]) -> dict:
    assert label in ("bad", "good")
    sources, err = sources_for_label(tc, label)
    if err:
        return {"ok": False, "error": err, "sources": [], "command": []}
    out_dir = build_root / ("bad" if label == "bad" else "good")
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = out_dir / f"{tc.group_id}_{label}"
    omit = "OMITGOOD" if label == "bad" else "OMITBAD"
    compiler = "g++" if tc.language == "cpp" else "gcc"
    std = "-std=gnu++11" if tc.language == "cpp" else "-std=gnu11"
    cmd = [
        compiler, std, "-O0", "-g", "-fsanitize=address",
        "-fno-omit-frame-pointer", "-w", "-DINCLUDEMAIN", f"-D{omit}",
        "-I", str(lj.SUPPORT), "-o", str(exe),
        *[str(p) for p in sources],
        str(objs["io.c"]), str(objs["std_thread.c"]), "-lpthread", "-lm",
    ]
    res = _run(cmd, timeout=120)
    ok = res["returncode"] == 0 and exe.exists()
    return {
        "ok": ok,
        "error": None if ok else (res["stderr"][-4000:] or "compile failed"),
        "sources": [lj.rel(p) for p in sources],
        "command": cmd,
        "executable": str(exe),
        "compiler": compiler,
        "defines": ["INCLUDEMAIN", omit],
        "returncode": res["returncode"],
        "stderr_tail": res["stderr"][-2000:],
    }


def nm_entries(exe: Path) -> dict:
    res = _run(["nm", "-C", "--defined-only", str(exe)], timeout=60)
    bad, good = [], []
    names = []
    for line in res["stdout"].splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        name = parts[2]
        names.append(name)
        short = name.split("(", 1)[0].rsplit("::", 1)[-1]
        if short == "bad" or short.endswith("_bad"):
            bad.append(name)
        if short == "good" or short.endswith("_good"):
            good.append(name)
    return {"bad_symbols": bad, "good_symbols": good, "symbol_count": len(names)}


def run_unit(exe: Path, label: str, timeout: int = 30) -> dict:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = ASAN_OPTIONS
    env["LSAN_OPTIONS"] = LSAN_OPTIONS
    res = _run([str(exe)], timeout=timeout, env=env)
    out = res["stdout"]
    err = res["stderr"]
    leak = "LeakSanitizer: detected memory leaks" in err or "SUMMARY: AddressSanitizer:" in err and "leaked" in err
    asan_error = "ERROR: AddressSanitizer:" in err and "LeakSanitizer" not in err
    summary = None
    for line in err.splitlines():
        if "SUMMARY: AddressSanitizer:" in line:
            summary = line.strip()
            break
    return {
        "returncode": res["returncode"],
        "timed_out": res["timed_out"],
        "leak_detected": bool(leak),
        "other_asan_error": bool(asan_error),
        "summary": summary,
        "stdout_head": out[:500],
        "stderr_tail": err[-1500:],
    }


def evaluate(tc: lj.TestCase, label: str, build_root: Path, objs: dict[str, Path]) -> dict:
    comp = compile_unit(tc, label, build_root, objs)
    if not comp["ok"]:
        return {"ok": False, "label_ok": False, "compile": comp}
    sym = nm_entries(Path(comp["executable"]))
    run = run_unit(Path(comp["executable"]), label)
    if label == "bad":
        symbol_ok = bool(sym["bad_symbols"]) and not sym["good_symbols"]
        # A Juliet "bad" case may leak only on a path that the default main does
        # not reach (e.g. realloc failure) or may keep the block reachable via a
        # global.  The macro gate is authoritative; a missing leak observation is
        # recorded, not treated as a label failure.
        label_ok = symbol_ok and not run["other_asan_error"] and not run["timed_out"]
        runtime_supports = bool(run["leak_detected"])
    else:
        symbol_ok = bool(sym["good_symbols"]) and not sym["bad_symbols"]
        label_ok = (not run["leak_detected"]) and (not run["other_asan_error"]) and (not run["timed_out"])
        runtime_supports = not run["leak_detected"]
    label_ok = bool(label_ok)
    return {
        "ok": bool(label_ok),
        "label_ok": bool(label_ok),
        "symbol_ok": symbol_ok,
        "runtime_supports_label": bool(runtime_supports),
        "compile": comp,
        "symbols": sym,
        "run": run,
    }


def write_result_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

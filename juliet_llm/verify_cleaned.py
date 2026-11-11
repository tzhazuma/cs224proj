"""Compile and run every cleaned Juliet view to prove cleaning keeps semantics.

``clean_unit`` rewrites identifiers and string literals.  This check rebuilds
all 200 cleaned views, adds the dropped support header back, compiles each with
AddressSanitizer and runs it, then compares the leak outcome with the frozen
``juliet/verification.json`` / ``juliet/manifest.json`` runtime flags.  A
cleaning change that broke the program would show up as a compile failure or a
leak-outcome mismatch; the check prints JSON and exits non-zero on any problem.

Requires gcc/g++ with ASan support (the same toolchain ``juliet/scripts`` uses).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .cleaning import clean_unit, load_units

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUPPORT = PROJECT_ROOT / "juliet" / "raw" / "testcasesupport"
MANIFEST = PROJECT_ROOT / "juliet" / "manifest.json"
ASAN_OPTIONS = "detect_leaks=1:abort_on_error=0:exitcode=23"
LSAN_OPTIONS = "exitcode=23"


def _run(
    command: list[str], timeout: int, env: dict[str, str] | None = None
) -> tuple[int | None, str, str, bool]:
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
            False,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            None,
            (exc.stdout or b"").decode("utf-8", "replace"),
            (exc.stderr or b"").decode("utf-8", "replace"),
            True,
        )


def probe(unit: dict[str, Any]) -> dict[str, Any]:
    cleaned = clean_unit(unit)
    cpp = cleaned.language == "cpp"
    compiler = "g++" if cpp else "gcc"
    standard = "-std=gnu++11" if cpp else "-std=gnu11"
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / ("unit.cpp" if cpp else "unit.c")
        source.write_text('#include "std_testcase.h"\n' + cleaned.code, encoding="utf-8")
        executable = Path(tmp) / "unit"
        command = [
            compiler,
            standard,
            "-O0",
            "-g",
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-w",
            "-I",
            str(SUPPORT),
            "-o",
            str(executable),
            str(source),
            str(SUPPORT / "io.c"),
            str(SUPPORT / "std_thread.c"),
            "-lpthread",
            "-lm",
        ]
        code, _, stderr, timed_out = _run(command, timeout=120)
        if code != 0:
            return {
                "unit_id": cleaned.unit_id,
                "label": cleaned.label,
                "compile_ok": False,
                "error": stderr[-800:],
            }
        env = dict(os.environ, ASAN_OPTIONS=ASAN_OPTIONS, LSAN_OPTIONS=LSAN_OPTIONS)
        code, stdout, stderr, timed_out = _run([str(executable)], timeout=60, env=env)
    return {
        "unit_id": cleaned.unit_id,
        "label": cleaned.label,
        "compile_ok": True,
        "returncode": code,
        "timed_out": timed_out,
        "leak_detected": "LeakSanitizer" in stderr or code == 23,
        "asan_error": "AddressSanitizer" in stderr and "LeakSanitizer" not in stderr,
        "stdout_lines": len(stdout.splitlines()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args(argv)

    units = load_units()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(probe, units))
    frozen = {
        unit["unit_id"]: unit
        for unit in json.loads(MANIFEST.read_text(encoding="utf-8"))["units"]
    }

    problems: list[str] = []
    for row in results:
        if not row["compile_ok"]:
            problems.append(f"{row['unit_id']}: compile failed")
            continue
        if row["timed_out"]:
            problems.append(f"{row['unit_id']}: runtime timeout")
        if row["asan_error"]:
            problems.append(f"{row['unit_id']}: AddressSanitizer error")
        reference = frozen[row["unit_id"]]["runtime_check"]
        if row["label"] == "good" and row["leak_detected"]:
            problems.append(f"{row['unit_id']}: good unit leaked")
        if row["label"] == "bad" and row["leak_detected"] != reference["leak_detected"]:
            problems.append(
                f"{row['unit_id']}: leak {row['leak_detected']} != frozen "
                f"{reference['leak_detected']}"
            )

    summary = {
        "units": len(results),
        "compile_ok": sum(1 for row in results if row["compile_ok"]),
        "bad_leak": sum(
            1 for row in results if row["label"] == "bad" and row.get("leak_detected")
        ),
        "good_clean": sum(
            1 for row in results if row["label"] == "good" and not row.get("leak_detected")
        ),
        "problems": problems,
    }
    print(json.dumps(summary, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())

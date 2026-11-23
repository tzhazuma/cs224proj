#!/usr/bin/env python3
"""Compile and run every unit to check (never change) its Juliet label.

For each unit of layer1.jsonl and the good units of original.jsonl (original bad == layer-1 bad):
  * gcc/g++ 13 build from the unit's `build` spec with -fsanitize=address -g -O0, run with
    ASAN_OPTIONS=detect_leaks=1, stdin closed, 10 s timeout -> asan_leak;
  * clang/clang++ 23 compiles and links the same spec -> compile_clang;
  * valgrind --leak-check=full on a stratified sample (~200 units, no sanitizer) -> valgrind_leak.
Results go to build/verify_results.jsonl; build_units.py merges them into the unit files.
A mismatch with the label is recorded in `note` with the known LSan blind-spot reason.

Usage: python verify_labels.py [--units build/layer1_sample.jsonl] [--jobs 8] [--no-valgrind]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
import random
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
BUILD_DIR = DATA_DIR / "build"
RESULTS = BUILD_DIR / "verify_results.jsonl"
CLANG_BIN = Path("/home/barton/tools/cs224/llvm-23.1.6/bin")
VALGRIND = Path("/home/barton/tools/cs224/valgrind-3.28.0/bin/valgrind")
SEED = 20261123
TIMEOUT_S = 10
RANDOM_RUNS = 6
FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer", "-w"]
ASAN = ["-fsanitize=address"]
LIBS = ["-lpthread", "-lm"]


def compile_cmd(unit: dict, compiler: str, out: Path, sanitize: bool) -> list[str]:
    build = unit["build"]
    cmd = [compiler, f"-std={build['std']}", *FLAGS, *(ASAN if sanitize else [])]
    cmd += [f"-I{d}" for d in build["include_dirs"]] + [f"-D{d}" for d in build["defines"]]
    cmd += build["sources"] + ["-o", str(out)] + LIBS
    return cmd


def run(cmd: list[str], cwd: str, timeout: int, env: dict | None = None) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, errors="replace", timeout=timeout, env=env)
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return None, "timeout"


def first_error(log: str) -> str:
    lines = [l for l in log.splitlines() if "error" in l] or log.strip().splitlines() or ["?"]
    return lines[0][:200]


def blind_spot(unit: dict) -> str | None:
    if unit["mechanism"] == "realloc_fail":
        return "realloc_fail (leak needs realloc failure)"
    if unit["variant"] == "12":
        return "variant 12 random branch"
    if unit["variant"] in {"45", "68"}:
        return "memory still reachable from a global at exit"
    return None


def verify_unit(unit: dict, valgrind: bool, workroot: Path) -> dict:
    pdir = unit["program_dir"]
    work = Path(tempfile.mkdtemp(dir=workroot))
    gnu = "g++" if unit["build"]["compiler"] == "g++" else "gcc"
    clang = str(CLANG_BIN / ("clang++" if gnu == "g++" else "clang"))
    notes: list[str] = []
    rc, log = run(compile_cmd(unit, gnu, work / "asan", True), pdir, 120)
    compile_gcc = rc == 0
    if not compile_gcc:
        notes.append("gcc compile error: " + first_error(log))
    rc_c, log_c = run(compile_cmd(unit, clang, work / "clang", False), pdir, 120)
    compile_clang = rc_c == 0
    if not compile_clang:
        notes.append("clang compile error: " + first_error(log_c))
    asan_leak = None
    run_status = None
    if compile_gcc:
        # Primary run: stacks are not leak roots. The check runs at exit, after the entry
        # returned, so stack roots are only stale -O0 slots that hide real leaks (seen on
        # variant 31). The default-option run is kept in the note when it disagrees.
        leaks = {}
        # variant 12 picks its branches with rand() seeded by time(NULL): repeat the primary
        # run in different seconds (up to RANDOM_RUNS) and count a leak if any run leaks.
        runs = RANDOM_RUNS if unit["variant"] == "12" else 1
        configs = [("primary", "exitcode=23:use_stacks=0")] * runs + [("default", "exitcode=23")]
        other_errors = set()
        for attempt, (tag, lsan) in enumerate(configs):
            if tag == "primary" and leaks.get("primary"):
                continue
            if attempt and runs > 1 and tag == "primary":
                time.sleep(1.05)
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=0:exitcode=23",
                       LSAN_OPTIONS=lsan)
            rc_r, out = run([str(work / "asan")], pdir, TIMEOUT_S, env)
            if rc_r is None:
                run_status = "timeout"
                leaks.setdefault(tag, None)
                continue
            leaks[tag] = leaks.get(tag) or "LeakSanitizer: detected memory leaks" in out
            match = re.search(r"ERROR: AddressSanitizer: ([\w-]+(?: [\w-]+)*)", out)
            if match:
                other_errors.add(match.group(1)[:60])
            elif rc_r not in (0, 23):
                run_status = f"exit {rc_r}"
        asan_leak = leaks["primary"]
        if other_errors:
            notes.append("other ASan error in some run: " + ", ".join(sorted(other_errors)))
        if runs > 1:
            notes.append(f"random branches: leak if any of up to {runs} runs leaks")
        if leaks["default"] != leaks["primary"]:
            notes.append(f"default LSan options (stacks as roots): asan_leak={leaks['default']}")
    valgrind_leak = None
    if valgrind and compile_gcc:
        rc_v, _ = run(compile_cmd(unit, gnu, work / "plain", False), pdir, 120)
        if rc_v == 0:
            rc_r, out = run([str(VALGRIND), "--leak-check=full", "--errors-for-leak-kinds=definite,indirect",
                             "--error-exitcode=42", str(work / "plain")], pdir, 60)
            if rc_r is None:
                notes.append("valgrind timeout")
            else:
                valgrind_leak = rc_r == 42 and ("definitely lost" in out or "indirectly lost" in out)
    expected = unit["truth"] == 1
    if asan_leak is not None and asan_leak != expected:
        reason = blind_spot(unit) if expected else None
        notes.append(f"mismatch: label {unit['label']} but asan_leak={asan_leak}"
                     + (f" [known blind spot: {reason}]" if reason else ""))
    if run_status:
        notes.append(f"run: {run_status}")
    shutil.rmtree(work, ignore_errors=True)
    return {"compile_gcc": compile_gcc, "compile_clang": compile_clang, "asan_leak": asan_leak,
            "valgrind_leak": valgrind_leak, "note": "; ".join(notes) or None}


def valgrind_sample(units: list[dict], size: int = 200) -> set[str]:
    """Stratified by (flow_category, mechanism, label): proportional with >=1 per stratum."""
    strata: dict[tuple, list[str]] = defaultdict(list)
    for u in units:
        strata[(u["flow_category"], u["mechanism"], u["label"])].append(u["unit_id"])
    rng = random.Random(SEED)
    picked: set[str] = set()
    for key in sorted(strata):
        ids = sorted(strata[key])
        k = max(1, round(size * len(ids) / len(units)))
        picked.update(rng.sample(ids, min(k, len(ids))))
    return picked


def write_report(results: list[dict], unit_files: list[Path], out: Path) -> str:
    units = {}
    for path in unit_files:
        layer = "original" if "original" in path.name else "layer1"
        for line in path.read_text().splitlines():
            u = json.loads(line)
            units[(layer, u["unit_id"])] = u
    rows = [(r["layer"], units[(r["layer"], r["unit_id"])], r["verify"]) for r in results
            if (r["layer"], r["unit_id"]) in units]
    lines = ["# Label verification (verify_labels.py)", "",
             "gcc/g++ 13 `-fsanitize=address -g -O0`, run with `ASAN_OPTIONS=detect_leaks=1` and "
             "`LSAN_OPTIONS=use_stacks=0` (primary), stdin closed, 10 s timeout; clang/clang++ 23 compile+link "
             "check; valgrind 3.28 `--leak-check=full` (definite/indirect) on a stratified sample. "
             "Labels are never changed; mismatches are recorded in `verify.note`.", "",
             "## Compile rates", "", "| layer | units | gcc ok | clang ok |", "|---|---|---|---|"]
    for layer in ("layer1", "original"):
        sel = [v for l, _, v in rows if l == layer]
        if sel:
            lines.append(f"| {layer} | {len(sel)} | {sum(bool(v['compile_gcc']) for v in sel)} | "
                         f"{sum(bool(v['compile_clang']) for v in sel)} |")
    for dim in ("mechanism", "flow_category"):
        lines += ["", f"## LSan agreement with the Juliet label by {dim} (layer1; original good in last column)", "",
                  f"| {dim} | bad: leak reported | good (layer1): no leak | good (orig): no leak |", "|---|---|---|---|"]
        keys = sorted({u[dim] for _, u, _ in rows})
        for key in keys:
            def frac(layer, label):
                sel = [v for l, u, v in rows if l == layer and u["label"] == label and u[dim] == key]
                ok = sum(v["asan_leak"] == (label == "bad") for v in sel)
                return f"{ok}/{len(sel)}" if sel else "-"
            lines.append(f"| {key} | {frac('layer1', 'bad')} | {frac('layer1', 'good')} | {frac('original', 'good')} |")
    reasons = Counter()
    for layer, u, v in rows:
        if layer != "layer1" or v["asan_leak"] == (u["truth"] == 1):
            continue
        note = v["note"] or ""
        reason = note.split("[known blind spot: ")[1].split("]")[0] if "known blind spot" in note else "unexplained"
        reasons[(u["label"], reason, u["variant"] if reason == "unexplained" else "")] += 1
    lines += ["", "## Mismatch reasons (layer1)", "", "| label | reason | units |", "|---|---|---|"]
    for (label, reason, variant), n in sorted(reasons.items()):
        lines.append(f"| {label} | {reason}{' (variant ' + variant + ')' if variant else ''} | {n} |")
    default_diff = Counter(u["label"] for l, u, v in rows if l == "layer1" and "default LSan options" in (v["note"] or ""))
    other = Counter(v["note"].split("other ASan error in some run: ")[1].split(";")[0]
                    for l, _, v in rows if l == "layer1" and "other ASan error" in (v["note"] or ""))
    lines += ["", f"- layer1 units where default LSan options (stacks as roots) disagree with the primary run: "
              f"{dict(default_diff)} (stale -O0 stack slots in the exited frames hide the leak)" if default_diff else ""]
    if other:
        lines.append(f"- other ASan errors (layer1): {dict(other)}")
    vg = [(u, v) for l, u, v in rows if l == "layer1" and v["valgrind_leak"] is not None]
    if vg:
        lines += ["", "## Valgrind sample (layer1)", "", "| label | units | valgrind agrees with label | valgrind agrees with LSan |",
                  "|---|---|---|---|"]
        for label in ("bad", "good"):
            sel = [(u, v) for u, v in vg if u["label"] == label]
            lines.append(f"| {label} | {len(sel)} | {sum(v['valgrind_leak'] == (label == 'bad') for _, v in sel)} | "
                         f"{sum(v['valgrind_leak'] == v['asan_leak'] for _, v in sel)} |")
    else:
        lines += ["", "Valgrind: not run."]
    text = "\n".join(lines) + "\n"
    out.write_text(text)
    return text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--units", nargs="*", default=[str(BUILD_DIR / "layer1.jsonl"),
                                                      str(BUILD_DIR / "original.jsonl")])
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--no-valgrind", action="store_true")
    parser.add_argument("--out", default=str(RESULTS))
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    if args.report_only:
        results = [json.loads(l) for l in Path(args.out).read_text().splitlines()]
        print(write_report(results, [Path(p) for p in args.units], BUILD_DIR / "verify_report.md"))
        return
    jobs: list[tuple[str, dict]] = []
    for path in args.units:
        layer = "original" if "original" in Path(path).name else "layer1"
        for line in Path(path).read_text().splitlines():
            unit = json.loads(line)
            if layer == "original" and unit["label"] == "bad":
                continue  # same program as the layer-1 bad unit; copied below
            jobs.append((layer, unit))
    use_valgrind = VALGRIND.exists() and not args.no_valgrind
    vg_ids = valgrind_sample([u for layer, u in jobs if layer == "layer1"]) if use_valgrind else set()
    workroot = Path(tempfile.mkdtemp(prefix="verify_", dir="/tmp"))
    with ThreadPoolExecutor(max_workers=min(args.jobs, 8)) as pool:
        futures = [pool.submit(verify_unit, u, layer == "layer1" and u["unit_id"] in vg_ids, workroot)
                   for layer, u in jobs]
        results = []
        for (layer, unit), fut in zip(jobs, futures):
            results.append({"layer": layer, "unit_id": unit["unit_id"], "verify": fut.result()})
    by_l1 = {r["unit_id"]: r for r in results if r["layer"] == "layer1"}
    if any(layer == "original" for layer, _ in jobs):
        for uid, rec in sorted(by_l1.items()):
            if uid.endswith("__bad"):
                results.append({"layer": "original", "unit_id": uid, "verify": rec["verify"]})
    results.sort(key=lambda r: (r["layer"], r["unit_id"]))
    Path(args.out).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in results))
    shutil.rmtree(workroot, ignore_errors=True)
    summary = Counter((r["layer"], r["verify"]["compile_gcc"], r["verify"]["compile_clang"],
                       r["verify"]["asan_leak"]) for r in results)
    for key, n in sorted(summary.items(), key=str):
        print(key, n)
    print(f"valgrind: {'ran on ' + str(len(vg_ids)) + ' units' if use_valgrind else 'skipped'}")
    if Path(args.out) == RESULTS:
        print(write_report(results, [Path(p) for p in args.units], BUILD_DIR / "verify_report.md"))


if __name__ == "__main__":
    main()

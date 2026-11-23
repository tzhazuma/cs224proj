#!/usr/bin/env python3
"""Dynamic reference-line predictions in the contract format (juliet_full/README.md section 4).

Methods (all gcc/g++ 13, -O0 -g -fno-omit-frame-pointer, Juliet io.c linked, stdin closed):
  asan_lsan          ASan build, one execution, LSAN_OPTIONS=use_stacks=0 (the stage-1 primary option).
                     pred = 1 iff LSan reports a leaked block whose allocation site is in the unit.
  asan_lsan_default  same binary, one execution, default LSan options (stacks/registers are roots).
  valgrind           plain build under valgrind --leak-check=full; pred = 1 iff definitely + indirectly
                     lost bytes > 0.  Still-reachable bytes (total and allocated in the unit) go to extra.
  dynamic_enhanced   same ASan binary; 3 configurations x 8 fixed seeds (DYNENH_TIME=1..8 makes
                     srand(time(NULL)) use that seed), pred = OR over the 24 executions:
                       base     LSAN use_stacks=0
                       globals  LSAN use_stacks=0:use_globals=0 (memory reachable only from globals counts)
                       realloc  base + DYNENH_REALLOC_FAIL=1 (first realloc of a non-NULL block returns NULL)
Every ASan binary is linked with dynamic/inject.c (-Wl,--wrap=realloc -Wl,--wrap=time); with no DYNENH_*
variable set the hooks forward to the real functions, so asan_lsan/asan_lsan_default run the plain behaviour.
Attribution (all ASan methods): a leak block counts iff the first stack frame with a source location, after
skipping sanitizer frames and inject.c, is a file of the unit's program directory (this drops the stdio buffers
that use_globals=0 exposes).  Non-leak ASan errors (Juliet's variant-12 bad-free) are recorded in extra;
pred comes from the leak reports only.

Layers: layer1 (all 4 methods), stress = layer3.jsonl and placebo (asan_lsan, dynamic_enhanced),
original (asan_lsan; bad units are the layer-1 bad programs, rows copied from layer1).

  python3 dynamic_runs.py bulk --jobs 6            # results/<method>/<layer>/full_v1.jsonl (+ .meta.json)
  python3 dynamic_runs.py latency --wait-quiet     # latency300, concurrency 1 -> lat300_c1
Partial results are kept in results/_work/<run_id>/ so an interrupted run resumes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DATA_DIR))
import verify_labels  # noqa: E402

BUILD = DATA_DIR / "build"
RESULTS = DATA_DIR / "results"
INJECT_C = DATA_DIR / "dynamic" / "inject.c"
VALGRIND = verify_labels.VALGRIND
TIMEOUT_S = 10
VALGRIND_TIMEOUT_S = 60
SEEDS = tuple(range(1, 9))
ASAN_ENV = "detect_leaks=1:abort_on_error=0:exitcode=23"
LSAN_PRIMARY = "exitcode=23:use_stacks=0"
LSAN_DEFAULT = "exitcode=23"
LSAN_GLOBALS = "exitcode=23:use_stacks=0:use_globals=0"
HOOK_FLAGS = ["-Wl,--wrap=realloc", "-Wl,--wrap=time"]
VALGRIND_ARGS = ["--leak-check=full", "--show-leak-kinds=all", "--errors-for-leak-kinds=definite,indirect",
                 "--error-exitcode=42"]
ENH_CONFIGS = {"base": ({}, LSAN_PRIMARY), "globals": ({}, LSAN_GLOBALS),
               "realloc": ({"DYNENH_REALLOC_FAIL": "1"}, LSAN_PRIMARY)}
LAYERS = {"layer1": ("layer1.jsonl", ("asan_lsan", "asan_lsan_default", "valgrind", "dynamic_enhanced")),
          "stress": ("layer3.jsonl", ("asan_lsan", "dynamic_enhanced")),
          "placebo": ("placebo.jsonl", ("asan_lsan", "dynamic_enhanced")),
          "original": ("original.jsonl", ("asan_lsan",))}
LEAK_HEAD = re.compile(r"^(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:")
FRAME = re.compile(r"^\s+#\d+ 0x[0-9a-f]+ ")
SOURCE_LOC = re.compile(r" (/?[^\s()]+:\d+)(?::\d+)?\s*$")  # file:line[:col] at the end of a frame line
SUMMARY = re.compile(r"^SUMMARY: AddressSanitizer: ([A-Za-z][\w-]*)", re.M)
VG_SUMMARY = re.compile(r"(definitely lost|indirectly lost|possibly lost|still reachable): ([\d,]+) bytes")
VG_RECORD = re.compile(r"([\d,]+) bytes in [\d,]+ blocks are (still reachable|definitely lost|indirectly lost"
                       r"|possibly lost) in loss record")
VG_FRAME = re.compile(r"(?:at|by) 0x[0-9A-F]+: .* \(([^()\s:]+):(\d+)\)\s*$")


# ---------------------------------------------------------------------------
# build + execute
# ---------------------------------------------------------------------------
def hooks_object(workroot: Path) -> Path:
    obj = workroot / "inject.o"
    if not obj.exists():
        subprocess.run(["gcc", "-c", "-O0", "-g", "-w", str(INJECT_C), "-o", str(obj)], check=True)
    return obj


def compile_unit(unit: dict, exe: Path, sanitize: bool, hooks: Path | None) -> tuple[bool, float, str]:
    gnu = "g++" if unit["build"]["compiler"] == "g++" else "gcc"
    cmd = verify_labels.compile_cmd(unit, gnu, exe, sanitize)
    if hooks is not None:
        cmd += [str(hooks), *HOOK_FLAGS]
    start = time.perf_counter()
    rc, log = verify_labels.run(cmd, unit["program_dir"], 120)
    return rc == 0, time.perf_counter() - start, verify_labels.first_error(log) if rc != 0 else ""


def execute(cmd: list[str], cwd: str, env: dict, timeout: int) -> dict:
    start = time.perf_counter()
    try:
        p = subprocess.run(cmd, cwd=cwd, env={**os.environ, **env}, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout)
        rc, err = p.returncode, p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        rc, err = None, (exc.stderr or b"").decode("utf-8", "replace")
    return {"rc": rc, "stderr": err, "wall_s": time.perf_counter() - start}


def asan_run(exe: Path, unit: dict, lsan: str, extra_env: dict | None = None, seed: int | None = None) -> dict:
    env = {"ASAN_OPTIONS": ASAN_ENV, "LSAN_OPTIONS": lsan, **(extra_env or {})}
    if seed is not None:
        env["DYNENH_TIME"] = str(seed)
    r = execute([str(exe)], unit["program_dir"], env, TIMEOUT_S)
    out = parse_asan(r["stderr"], unit["program_dir"])
    out.update(rc=r["rc"], wall_s=round(r["wall_s"], 4), timeout=r["rc"] is None,
               injected="[dynenh] injected realloc failure" in r["stderr"])
    return out


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------
def leak_site(frames: list[str]) -> str | None:
    """First frame with an absolute source location, skipping sanitizer frames and the inject.c hooks.

    glibc frames carry relative source paths (wcsmbs/wcsdup.c:28, libio/filedoalloc.c:101) and are skipped,
    so a wcsdup() called from the unit is attributed to the unit, while stdio buffers stay attributed to
    io.c (absolute path outside the program dir).
    """
    for line in frames:
        m = SOURCE_LOC.search(line)
        if not m:
            continue
        loc = m.group(1)
        if (not loc.startswith("/") or "libsanitizer" in loc or "/asan_" in loc
                or loc.startswith(str(INJECT_C))):
            continue
        return loc
    return None


def parse_asan(stderr: str, program_dir: str) -> dict:
    blocks = []
    lines = stderr.splitlines()
    for i, line in enumerate(lines):
        m = LEAK_HEAD.match(line)
        if not m:
            continue
        frames = []
        for nxt in lines[i + 1:]:
            if not FRAME.match(nxt):
                break
            frames.append(nxt)
        site = leak_site(frames)
        blocks.append({"kind": m.group(1).lower(), "bytes": int(m.group(2)), "site": site,
                       "unit": bool(site) and site.startswith(program_dir.rstrip("/") + "/")})
    errors = [k for k in SUMMARY.findall(stderr) if k != "detected"]
    unit_blocks = [b for b in blocks if b["unit"]]
    return {"leak": bool(unit_blocks), "unit_blocks": len(unit_blocks),
            "unit_bytes": sum(b["bytes"] for b in unit_blocks), "other_blocks": len(blocks) - len(unit_blocks),
            "sites": sorted({b["site"].rsplit("/", 1)[-1] for b in unit_blocks}),
            "asan_error": errors[0] if errors else None}


def parse_valgrind(stderr: str, unit_files: set[str]) -> dict:
    summary = {k.replace(" ", "_"): int(v.replace(",", "")) for k, v in VG_SUMMARY.findall(stderr)}
    for k in ("definitely_lost", "indirectly_lost", "possibly_lost", "still_reachable"):
        summary.setdefault(k, 0)
    reachable_unit = 0
    lines = stderr.splitlines()
    for i, line in enumerate(lines):
        m = VG_RECORD.search(line)
        if not m or m.group(2) != "still reachable":
            continue
        for nxt in lines[i + 1:i + 30]:
            f = VG_FRAME.search(nxt)
            if f and not f.group(1).startswith("vg_replace"):
                if f.group(1) in unit_files:
                    reachable_unit += int(m.group(1).replace(",", ""))
                break
    m = re.search(r"ERROR SUMMARY: (\d+) errors", stderr)
    summary.update(still_reachable_unit=reachable_unit, error_summary=int(m.group(1)) if m else None,
                   invalid_free="Invalid free" in stderr or "Mismatched free" in stderr)
    return summary


# ---------------------------------------------------------------------------
# per-unit methods
# ---------------------------------------------------------------------------
def row(unit: dict, method: str, layer: str, pred, latency: float | None, status: str, extra: dict) -> dict:
    return {"unit_id": unit["unit_id"], "method": method, "strategy": None, "model": None, "layer": layer,
            "pred": pred, "score": None, "latency_s": None if latency is None else round(latency, 4),
            "status": status, "extra": extra}


def asan_methods(unit: dict, layer: str, methods: tuple[str, ...], workroot: Path, hooks: Path) -> list[dict]:
    exe = workroot / f"{layer}__{unit['unit_id']}__asan"
    ok, compile_s, err = compile_unit(unit, exe, True, hooks)
    rows = []
    if not ok:
        return [row(unit, m, layer, None, compile_s, "compile_error", {"compile_error": err}) for m in methods]
    for method in methods:
        if method in ("asan_lsan", "asan_lsan_default"):
            r = asan_run(exe, unit, LSAN_PRIMARY if method == "asan_lsan" else LSAN_DEFAULT)
            status = "timeout" if r["timeout"] else "ok"
            extra = {k: r[k] for k in ("unit_blocks", "unit_bytes", "other_blocks", "sites", "asan_error", "rc")}
            extra["compile_s"] = round(compile_s, 4)
            rows.append(row(unit, method, layer, None if r["timeout"] else int(r["leak"]),
                            compile_s + r["wall_s"], status, extra))
        elif method == "dynamic_enhanced":
            runs = {name: [asan_run(exe, unit, lsan, env, seed) for seed in SEEDS]
                    for name, (env, lsan) in ENH_CONFIGS.items()}
            wall = sum(r["wall_s"] for rs in runs.values() for r in rs)
            done = [r for rs in runs.values() for r in rs if not r["timeout"]]
            leak = any(r["leak"] for r in done)
            parts = {name: {"leak_runs": sum(r["leak"] for r in rs), "timeouts": sum(r["timeout"] for r in rs),
                            "unit_bytes_max": max(r["unit_bytes"] for r in rs),
                            "other_blocks_max": max(r["other_blocks"] for r in rs),
                            "asan_error_runs": sum(r["asan_error"] is not None for r in rs)}
                     for name, rs in runs.items()}
            parts["realloc"]["injected_runs"] = sum(r["injected"] for r in runs["realloc"])
            extra = {"parts": parts, "leak_parts": [n for n, p in parts.items() if p["leak_runs"]],
                     "asan_errors": sorted({r["asan_error"] for r in done if r["asan_error"]}),
                     "seeds": list(SEEDS), "executions": len(SEEDS) * len(ENH_CONFIGS),
                     "compile_s": round(compile_s, 4)}
            status = "ok" if done else "timeout"
            rows.append(row(unit, method, layer, int(leak) if done else None, compile_s + wall, status, extra))
    exe.unlink(missing_ok=True)
    return rows


def valgrind_method(unit: dict, layer: str, workroot: Path) -> dict:
    exe = workroot / f"{layer}__{unit['unit_id']}__plain"
    ok, compile_s, err = compile_unit(unit, exe, False, None)
    if not ok:
        return row(unit, "valgrind", layer, None, compile_s, "compile_error", {"compile_error": err})
    r = execute([str(VALGRIND), *VALGRIND_ARGS, str(exe)], unit["program_dir"], {}, VALGRIND_TIMEOUT_S)
    exe.unlink(missing_ok=True)
    if r["rc"] is None:
        return row(unit, "valgrind", layer, None, compile_s + r["wall_s"], "timeout", {})
    unit_files = {Path(s).name for s in unit["build"]["sources"] if not s.startswith("/")} | {"unit.h"}
    v = parse_valgrind(r["stderr"], unit_files)
    v.update(rc=r["rc"], compile_s=round(compile_s, 4))
    pred = int(v["definitely_lost"] + v["indirectly_lost"] > 0)
    return row(unit, "valgrind", layer, pred, compile_s + r["wall_s"], "ok", v)


def unit_rows(unit: dict, layer: str, methods: tuple[str, ...], workroot: Path, hooks: Path) -> list[dict]:
    asan = tuple(m for m in methods if m != "valgrind")
    rows = asan_methods(unit, layer, asan, workroot, hooks) if asan else []
    if "valgrind" in methods:
        rows.append(valgrind_method(unit, layer, workroot))
    return rows


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def tool_versions() -> dict:
    def first(cmd):
        return subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()[0]
    return {"gcc": first(["gcc", "--version"]), "g++": first(["g++", "--version"]),
            "valgrind": first([str(VALGRIND), "--version"])}


def load_units(layer: str) -> list[dict]:
    return [json.loads(l) for l in (BUILD / LAYERS[layer][0]).read_text().splitlines()]


def options(method: str) -> dict:
    if method == "valgrind":
        return {"build": "gcc/g++ -O0 -g -fno-omit-frame-pointer (no sanitizer)", "valgrind": VALGRIND_ARGS,
                "pred": "definitely_lost + indirectly_lost > 0", "timeout_s": VALGRIND_TIMEOUT_S}
    base = {"build": "gcc/g++ -O0 -g -fno-omit-frame-pointer -fsanitize=address + dynamic/inject.c hooks "
                     + " ".join(HOOK_FLAGS), "ASAN_OPTIONS": ASAN_ENV, "timeout_s": TIMEOUT_S,
            "attribution": "first frame with an absolute source path (sanitizer, inject.c and relative-path glibc frames skipped) inside program_dir"}
    if method == "asan_lsan":
        return {**base, "LSAN_OPTIONS": LSAN_PRIMARY, "executions": 1}
    if method == "asan_lsan_default":
        return {**base, "LSAN_OPTIONS": LSAN_DEFAULT, "executions": 1}
    return {**base, "configs": {k: {"env": v[0], "LSAN_OPTIONS": v[1]} for k, v in ENH_CONFIGS.items()},
            "seeds (DYNENH_TIME)": list(SEEDS), "pred": "OR over 24 executions"}


def write_outputs(run_id: str, layer: str, rows: list[dict], meta: dict) -> None:
    by_method: dict[str, list[dict]] = {}
    for r in rows:
        by_method.setdefault(r["method"], []).append(r)
    for method, rs in by_method.items():
        rs.sort(key=lambda r: r["unit_id"])
        out = RESULTS / method / layer / f"{run_id}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rs))
        m = {**meta, "method": method, "layer": layer, "units": len(rs), "options": options(method)}
        out.with_suffix(".meta.json").write_text(json.dumps(m, indent=1) + "\n")
        print(f"wrote {out} ({len(rs)} rows)")


def run_jobs(run_id: str, jobs: list[tuple[str, dict, tuple[str, ...]]], n_jobs: int) -> list[dict]:
    work = RESULTS / "_work" / run_id
    work.mkdir(parents=True, exist_ok=True)
    partial = work / "rows.jsonl"
    done_rows = [json.loads(l) for l in partial.read_text().splitlines()] if partial.exists() else []
    done = {(r["layer"], r["unit_id"]) for r in done_rows}
    todo = [j for j in jobs if (j[0], j[1]["unit_id"]) not in done]
    print(f"{len(jobs)} unit jobs, {len(done)} already done, {len(todo)} to run", flush=True)
    lock = threading.Lock()
    workroot = Path(tempfile.mkdtemp(prefix="dynruns_", dir="/tmp"))
    hooks = hooks_object(workroot)
    counter = [0]

    def task(job):
        layer, unit, methods = job
        rows = unit_rows(unit, layer, methods, workroot, hooks)
        with lock:
            with partial.open("a") as fh:
                fh.write("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
            done_rows.extend(rows)
            counter[0] += 1
            if counter[0] % 200 == 0:
                print(f"{now()} {counter[0]}/{len(todo)} load {os.getloadavg()[0]:.1f}", flush=True)

    with ThreadPoolExecutor(max_workers=n_jobs) as pool:
        list(pool.map(task, todo))
    return done_rows


def bulk(args) -> None:
    layers = args.layers or list(LAYERS)
    jobs = []
    for layer in layers:
        methods = LAYERS[layer][1]
        for u in load_units(layer):
            if layer == "original" and u["label"] == "bad":
                continue  # identical program to the layer-1 bad unit; rows copied below
            jobs.append((layer, u, methods))
    meta = {"run_id": args.run_id, "host": socket.gethostname(), "concurrency": args.jobs, "start_utc": now(),
            "loadavg_start": os.getloadavg(), "tools": tool_versions(),
            "note": "bulk run; latency_s measured under concurrency, not the reported latency (see lat300_c1)"}
    rows = run_jobs(args.run_id, jobs, args.jobs)
    meta.update(end_utc=now(), loadavg_end=os.getloadavg())
    if "original" in layers:
        l1 = [r for r in rows if r["layer"] == "layer1" and r["method"] == "asan_lsan"
              and r["unit_id"].endswith("__bad")]
        if not l1:
            l1 = [json.loads(x) for x in (RESULTS / "asan_lsan" / "layer1" / f"{args.run_id}.jsonl")
                  .read_text().splitlines() if json.loads(x)["unit_id"].endswith("__bad")]
        rows = [r for r in rows if not (r["layer"] == "original" and r["unit_id"].endswith("__bad"))]
        rows += [{**r, "layer": "original", "extra": {**r["extra"], "copied_from": "layer1"}} for r in l1]
    for layer in layers:
        write_outputs(args.run_id, layer, [r for r in rows if r["layer"] == layer], meta)


def wait_quiet(limit: float, poll_s: int = 180) -> list[float]:
    while True:
        samples = []
        for _ in range(12):
            samples.append(os.getloadavg()[0])
            if samples[-1] >= limit:
                break
            time.sleep(5)
        if len(samples) == 12 and max(samples) < limit:
            return samples
        print(f"{now()} load1 {samples[-1]:.2f} >= {limit}; waiting {poll_s} s", flush=True)
        time.sleep(poll_s)


def latency(args) -> None:
    groups = set(json.loads((BUILD / "subsets.json").read_text())["latency300"])
    units = [u for u in load_units("layer1") if u["group_id"] in groups]
    lock_acquired = time.time()  # run under `flock /tmp/cs224_latency.lock`; the quiet check comes after the lock
    quiet_start = now()
    quiet = wait_quiet(args.load_limit) if args.wait_quiet else None
    lock_wait = None if args.lock_requested_epoch is None else round(lock_acquired - args.lock_requested_epoch, 1)
    meta = {"run_id": "lat300_c1", "host": socket.gethostname(), "concurrency": 1, "start_utc": now(),
            "loadavg_start": os.getloadavg(), "quiet_check_load1_samples": quiet, "tools": tool_versions(),
            "lock": "/tmp/cs224_latency.lock (flock)", "lock_wait_s": lock_wait,
            "quiet_wait_start_utc": quiet_start, "quiet_wait_s": round(time.time() - lock_acquired, 1),
            "subset": "latency300", "note": "concurrency 1; each method compiled and run on its own "
                                            "(latency_s = compile + its executions)"}
    workroot = Path(tempfile.mkdtemp(prefix="dynlat_", dir="/tmp"))
    hooks = hooks_object(workroot)
    rows = []
    for i, u in enumerate(units):
        for method in ("asan_lsan", "valgrind", "dynamic_enhanced"):
            rows += unit_rows(u, "layer1", (method,), workroot, hooks)
        if (i + 1) % 50 == 0:
            print(f"{now()} {i + 1}/{len(units)} load {os.getloadavg()[0]:.2f}", flush=True)
    meta.update(end_utc=now(), loadavg_end=os.getloadavg())
    write_outputs("lat300_c1", "layer1", rows, meta)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bulk")
    b.add_argument("--jobs", type=int, default=6)
    b.add_argument("--run-id", default="full_v1")
    b.add_argument("--layers", nargs="*", choices=list(LAYERS))
    lat = sub.add_parser("latency")
    lat.add_argument("--wait-quiet", action="store_true")
    lat.add_argument("--load-limit", type=float, default=2.5)
    lat.add_argument("--lock-requested-epoch", type=float, default=None,
                     help="time.time() when flock was requested (to record the lock wait)")
    args = parser.parse_args()
    if args.cmd == "bulk":
        args.jobs = min(args.jobs, 6)
        bulk(args)
    else:
        latency(args)


if __name__ == "__main__":
    main()

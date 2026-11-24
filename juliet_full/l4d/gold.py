#!/usr/bin/env python3
"""Gold fact labels for the L4-D questions from dynamic analysis of instrumented copies of the unit programs.

Per unit (sources copied from program_dir to a scratch dir; data/build/programs* are never modified):
  1. Every candidate site of parse_sites.py that shares a source line with other code is moved onto its own
     line(s) in the copy (newline before / after the statement), so gcov line counts are per statement.
     The site -> (file, new line) map is computed from line_map (model_text lines are identical to source lines).
  2. Build: gcc/g++ 13 -O0 -g --coverage, -no-pie, linked with gold/l4d_trace.c (+ gold/l4d_trace_new.cpp for
     C++) and -Wl,--wrap=malloc,calloc,realloc,free,strdup,wcsdup,time.
  3. SEEDS runs (L4D_TIME=1..8 fixes srand(time(NULL)), as in data/dynamic_runs.py dynamic_enhanced):
     gcov --json-format per run -> per-site executed flag; trace of allocations/releases with call stacks.
  4. Realloc-failure injection: for every distinct base trace and every non-NULL realloc k in it, one run with
     L4D_FAIL_REALLOC=k (that realloc returns NULL, block untouched).
Gold facts:
  exec_any(s) = executed in >= 1 run; exec_all(s) = executed in every run         (gold_source "gcov8")
  heap(a)     = executed: an allocation event attributed to a (trace); else allocator name ("trace" | "name")
  rel(f, a)   = both executed: some run has a release attributed to f of a block attributed to a; else null
  realloc_safe(r) = injected failure at r: the old block is released later in every such run ("inject");
                r only ever saw NULL input: 1 ("inject:no_block"); r never executed: null
Event attribution: the innermost stack frame that lies on a site of the needed role (alloc role = alloc|realloc,
release role = release, realloc role = realloc); hook frames and frames outside the unit files are skipped.

  .venv/bin/python gold.py --layer layer1_sample --jobs 8     -> build/gold_<layer>.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

L4D_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(L4D_DIR))
from parse_sites import DATA_BUILD, layer_name, layer_path, parse_unit  # noqa: E402

BUILD = L4D_DIR / "build"
TRACE_C = L4D_DIR / "gold" / "l4d_trace.c"
TRACE_CPP = L4D_DIR / "gold" / "l4d_trace_new.cpp"
SEEDS = tuple(range(1, 9))
TIMEOUT_S = 10
FLAGS = ["-g", "-O0", "-fno-omit-frame-pointer", "-w"]
WRAPS = "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup,--wrap=wcsdup,--wrap=time"
STACK_ALLOCATORS = {"ALLOCA", "alloca", "_alloca"}
ALLOC_ROLE = ("alloc", "realloc")
RELEASE_ROLE = ("release",)
GCOV_RUNTIME = ("__gcov", "_sub_D_", "_sub_I_", "gcov_")


def run(cmd, cwd, timeout=120, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           errors="replace", timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return None, "", "timeout"


# ---------------------------------------------------------------------------
# support objects (one per compiler)
# ---------------------------------------------------------------------------
def support_objects(workroot: Path, unit: dict) -> list[Path]:
    comp = unit["build"]["compiler"]
    d = workroot / f"support_{comp.replace('+', 'x')}"
    objs = []
    lock = workroot / f".lock_{comp.replace('+', 'x')}"
    with open(lock, "w") as lf:
        import fcntl
        fcntl.flock(lf, fcntl.LOCK_EX)
        d.mkdir(exist_ok=True)
        for src in [s for s in unit["build"]["sources"] if s.startswith("/")]:
            obj = d / (Path(src).stem + ".o")
            if not obj.exists():
                cmd = [comp, f"-std={unit['build']['std']}", *FLAGS, *[f"-I{i}" for i in unit["build"]["include_dirs"]],
                       "-c", src, "-o", str(obj)]
                rc, _, err = run(cmd, str(d))
                if rc != 0:
                    raise RuntimeError(f"support compile failed: {err[-300:]}")
            objs.append(obj)
        tr = d / "l4d_trace.o"
        if not tr.exists():
            rc, _, err = run(["gcc", "-O0", "-g", "-w", "-c", str(TRACE_C), "-o", str(tr)], str(d))
            if rc != 0:
                raise RuntimeError(err)
        objs.append(tr)
        if comp == "g++":
            tn = d / "l4d_trace_new.o"
            if not tn.exists():
                rc, _, err = run(["g++", "-std=gnu++17", "-O0", "-g", "-w", "-c", str(TRACE_CPP), "-o", str(tn)], str(d))
                if rc != 0:
                    raise RuntimeError(err)
            objs.append(tn)
    return objs


# ---------------------------------------------------------------------------
# instrumented copy: every site on its own lines
# ---------------------------------------------------------------------------
def model_positions(model_text: str):
    starts = [0]
    for i, ch in enumerate(model_text):
        if ch == "\n":
            starts.append(i + 1)
    def pos(offset: int) -> tuple[int, int]:
        line = bisect_right(starts, offset)  # 1-based
        return line, offset - starts[line - 1]
    return pos


def prepare_sources(unit: dict, sites: list[dict], src_dir: Path) -> dict:
    """Copy the unit files, split shared lines; return site placement + line maps."""
    pdir = Path(unit["program_dir"])
    for f in pdir.iterdir():
        if f.is_file():
            shutil.copy(f, src_dir / f.name)
    m2s = {ml: (f, sl) for f, sl, ml in unit["line_map"]}
    pos = model_positions(unit["model_text"])
    inserts: dict[str, set] = {}
    placed = {}
    texts = {f: (src_dir / f).read_text().split("\n") for f in {f for f, _, _ in unit["line_map"]}}
    for s in sites:
        (l0, c0), (l1, c1) = pos(s["span"][0]), pos(s["span"][1])
        if l0 not in m2s or l1 not in m2s:
            placed[s["site_id"]] = None
            continue
        f, sl0 = m2s[l0]
        f1, sl1 = m2s[l1]
        if f1 != f or sl1 - sl0 != l1 - l0:
            placed[s["site_id"]] = None
            continue
        lines = texts[f]
        ins = inserts.setdefault(f, set())
        if lines[sl0 - 1][:c0].strip():
            ins.add((sl0, c0))
        if lines[sl1 - 1][c1:].strip():
            ins.add((sl1, c1))
        placed[s["site_id"]] = (f, sl0, c0, sl1, c1)
    new_of: dict[str, callable] = {}
    old_of: dict[str, dict] = {}
    for f, lines in texts.items():
        ins = sorted(inserts.get(f, ()))
        out = list(lines)
        for (l, c) in sorted(ins, reverse=True):
            row = out[l - 1]
            out[l - 1:l] = [row[:c], row[c:]]
        (src_dir / f).write_text("\n".join(out))

        def newline(l, c, ins=ins):
            return l + sum(1 for (il, ic) in ins if il < l or (il == l and ic <= c))
        new_of[f] = newline
        rev = {}
        for l in range(1, len(lines) + 1):
            first = newline(l, 0)
            last = newline(l, max(len(lines[l - 1]), 0))
            for nl in range(first, last + 1):
                rev[nl] = l
        old_of[f] = rev
    site_lines = {}
    for sid, p in placed.items():
        if p is None:
            site_lines[sid] = None
            continue
        f, sl0, c0, sl1, c1 = p
        site_lines[sid] = (f, new_of[f](sl0, c0), new_of[f](sl1, max(c1 - 1, 0)))
    s2m = {(f, sl): ml for f, sl, ml in unit["line_map"]}
    return {"site_lines": site_lines, "old_of": old_of, "s2m": s2m, "files": set(texts)}


# ---------------------------------------------------------------------------
# run + collect
# ---------------------------------------------------------------------------
def gcov_counts(src_dir: Path, objs: list[str], files: set[str]) -> dict:
    rc, out, err = run(["gcov", "--json-format", "--stdout", *objs], str(src_dir), 60)
    counts: dict[tuple[str, int], int] = {}
    dec = json.JSONDecoder()
    i = 0
    while i < len(out):
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            break
        doc, i = dec.raw_decode(out, i)
        for fe in doc.get("files", []):
            name = os.path.basename(fe["file"])
            if name not in files:
                continue
            for ln in fe["lines"]:
                k = (name, ln["line_number"])
                counts[k] = counts.get(k, 0) + ln["count"]
    for g in src_dir.glob("*.gcda"):
        g.unlink()
    return counts


def parse_trace(path: Path) -> list[dict]:
    events = []
    if not path.exists():
        return events
    for line in path.read_text().splitlines():
        head, _, addrs = line.partition(" | ")
        parts = head.split()
        events.append({"op": parts[0], "args": parts[1:], "addrs": addrs.split()})
    return events


def symbolize(exe: Path, addrs: set[str], cwd: Path) -> dict[str, tuple[str, int] | None]:
    addrs = sorted(addrs)
    lookup = [a for a in addrs if int(a, 16) < 0x7f0000000000 and int(a, 16) < 0x10000000]
    res = {a: None for a in addrs}
    if lookup:
        inp = "\n".join(hex(int(a, 16) - 1) for a in lookup) + "\n"
        p = subprocess.run(["addr2line", "-f", "-e", str(exe)], input=inp, capture_output=True, text=True,
                           cwd=cwd)
        outl = p.stdout.splitlines()
        for a, fn, loc in zip(lookup, outl[0::2], outl[1::2]):
            fpart, _, lpart = loc.rpartition(":")
            lpart = lpart.split()[0] if lpart else ""
            res[a] = (fpart, int(lpart) if lpart.isdigit() else 0, fn)
    return res


def gold_unit(unit: dict, layer: str, workroot: Path) -> dict:
    t0 = time.perf_counter()
    parsed = parse_unit(unit["model_text"], unit["language"])
    sites = parsed["sites"]
    by_id = {s["site_id"]: s for s in sites}
    out = {"unit_id": unit["unit_id"], "layer": layer_name(layer), "status": "ok", "note": [],
           "n_sites": len(sites)}
    wdir = Path(tempfile.mkdtemp(prefix="u_", dir=workroot))
    try:
        src_dir = wdir / "src"
        src_dir.mkdir()
        prep = prepare_sources(unit, sites, src_dir)
        comp = unit["build"]["compiler"]
        b = unit["build"]
        objs = []
        for src in [s for s in b["sources"] if not s.startswith("/")]:
            obj = Path(src).stem + ".o"
            cmd = [comp, f"-std={b['std']}", *FLAGS, "--coverage", *[f"-I{i}" for i in b["include_dirs"]],
                   *[f"-D{d}" for d in b["defines"]], "-c", src, "-o", obj]
            rc, _, err = run(cmd, str(src_dir))
            if rc != 0:
                out.update(status="compile_error", note=[err[-300:]])
                return out
            objs.append(obj)
        exe = src_dir / "exe"
        cmd = [comp, "-no-pie", "--coverage", *objs, *[str(o) for o in support_objects(workroot, unit)], WRAPS,
               "-lpthread", "-lm", "-o", str(exe)]
        rc, _, err = run(cmd, str(src_dir))
        if rc != 0:
            out.update(status="link_error", note=[err[-300:]])
            return out
        site_at: dict[tuple[str, int], str] = {}
        for sid, sl in prep["site_lines"].items():
            if sl is None:
                continue
            f, a, z = sl
            for nl in range(a, z + 1):
                site_at[(f, nl)] = sid
        runs = []
        base_env = {k: v for k, v in os.environ.items() if not k.startswith("L4D_")}
        for seed in SEEDS:
            tr = wdir / f"trace_{seed}.txt"
            rc, _, _ = run([str(exe)], str(src_dir), TIMEOUT_S,
                           {**base_env, "L4D_TIME": str(seed), "L4D_TRACE": str(tr)})
            counts = gcov_counts(src_dir, objs, prep["files"])
            runs.append({"seed": seed, "rc": rc, "counts": counts, "events": parse_trace(tr)})
        # injection runs, one per (distinct base trace, non-NULL realloc k)
        inj = []
        seen = set()
        for r in runs:
            key = hashlib.sha1(json.dumps([(e["op"], e["addrs"]) for e in r["events"]]).encode()).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            n_re = sum(1 for e in r["events"] if e["op"] == "R")
            for k in range(1, n_re + 1):
                tr = wdir / f"inj_{r['seed']}_{k}.txt"
                rc, _, _ = run([str(exe)], str(src_dir), TIMEOUT_S,
                               {**base_env, "L4D_TIME": str(r["seed"]), "L4D_TRACE": str(tr),
                                "L4D_FAIL_REALLOC": str(k)})
                inj.append({"seed": r["seed"], "k": k, "rc": rc, "events": parse_trace(tr)})
        for g in src_dir.glob("*.gcda"):
            g.unlink()
        addrs = {a for r in runs + inj for e in r["events"] for a in e["addrs"]}
        sym = symbolize(exe, addrs, src_dir)

        def frames(e):
            """(file basename, line) of the stack frames below the hooks; [] for gcov-runtime events."""
            res = []
            for a in e["addrs"]:
                loc = sym.get(a)
                if loc is None:
                    continue
                if loc[2].startswith(GCOV_RUNTIME):
                    return []
                name = os.path.basename(loc[0])
                if name.startswith("l4d_trace") or loc[1] == 0:
                    continue
                res.append((name, loc[1]))
            return res

        def attribute(e, kinds):
            for fl in frames(e):
                sid = site_at.get(fl)
                if sid is not None and by_id[sid]["kind"] in kinds:
                    return sid
            return None

        def first_unit_line(e):
            fr = frames(e)
            if not fr:
                return None
            name, nl = fr[0]
            if name not in prep["files"]:
                return None
            old = prep["old_of"][name].get(nl)
            return prep["s2m"].get((name, old)) if old else None

        # coverage per site
        exec_runs, no_code = {}, {}
        for s in sites:
            sl = prep["site_lines"][s["site_id"]]
            if sl is None:
                exec_runs[s["site_id"]] = None
                continue
            f, a, z = sl
            vals = []
            for r in runs:
                c = next((r["counts"][(f, nl)] for nl in range(a, z + 1) if (f, nl) in r["counts"]), None)
                vals.append(None if c is None else int(c > 0))
            # no gcov record on any line of the statement: gcc emitted no code for it (constant-folded dead
            # branch such as `default:` of switch(6), or an inline method that is never used) -> never executes
            no_code[s["site_id"]] = all(v is None for v in vals)
            exec_runs[s["site_id"]] = [0 if v is None else v for v in vals]
        bad_rc = [r["seed"] for r in runs if r["rc"] != 0]
        if bad_rc:
            out["note"].append(f"nonzero rc seeds {bad_rc} rc={[r['rc'] for r in runs if r['rc'] != 0][:3]}")
        # trace analysis
        heap_ev = set()
        rel_pos = set()
        trace_alloc_lines, trace_release_lines = set(), set()
        untracked = []
        for r in runs:
            block_site = {}
            for e in r["events"]:
                op = e["op"]
                if op == "A":
                    a = attribute(e, ALLOC_ROLE)
                    block_site[e["args"][0]] = a
                    if a is not None:
                        heap_ev.add(a)
                    ml = first_unit_line(e)
                    if ml is not None:
                        trace_alloc_lines.add(ml)
                elif op == "F":
                    f = attribute(e, RELEASE_ROLE)
                    a = block_site.get(e["args"][0])
                    if f is not None and a is not None:
                        rel_pos.add((f, a))
                    ml = first_unit_line(e)
                    if ml is not None:
                        trace_release_lines.add(ml)
                elif op == "R":
                    rsite = attribute(e, ("realloc",))
                    old, new = e["args"]
                    a = block_site.get(old)
                    if rsite is not None and a is not None:
                        rel_pos.add((rsite, a))
                    block_site[new] = rsite
                    if rsite is not None:
                        heap_ev.add(rsite)
                    ml = first_unit_line(e)
                    if ml is not None:
                        trace_alloc_lines.add(ml)
                        trace_release_lines.add(ml)
                elif op == "U":
                    ml = first_unit_line(e)
                    untracked.append(ml)
        # realloc injection
        inj_res: dict[str, list[int]] = {}
        for r in inj:
            evs = r["events"]
            for i, e in enumerate(evs):
                if e["op"] != "I":
                    continue
                rsite = attribute(e, ("realloc",))
                old = e["args"][0]
                if rsite is None or old == "0":
                    continue
                released = any((x["op"] == "F" and x["args"][0] == old) or (x["op"] == "R" and x["args"][0] == old)
                               for x in evs[i + 1:])
                inj_res.setdefault(rsite, []).append(int(released))
        # facts
        site_gold = {}
        for s in sites:
            sid = s["site_id"]
            er = exec_runs[sid]
            g = {"exec_runs": er, "exec_any": None if er is None else int(any(er)),
                 "exec_all": None if er is None else int(all(er)),
                 "exec_source": "gcov8:no_code" if no_code.get(sid) else "gcov8"}
            if s["kind"] == "alloc":
                if g["exec_any"]:
                    g["heap"], g["heap_source"] = int(sid in heap_ev), "trace"
                else:
                    g["heap"], g["heap_source"] = int(s["callee"] not in STACK_ALLOCATORS), "name"
            if s["kind"] == "realloc":
                if not g["exec_any"]:
                    g["realloc_safe"], g["realloc_safe_source"] = None, "not_executed"
                elif sid in inj_res:
                    g["realloc_safe"], g["realloc_safe_source"] = int(all(inj_res[sid])), "inject"
                else:
                    g["realloc_safe"], g["realloc_safe_source"] = 1, "inject:no_block"
            site_gold[sid] = g
        rel = {}
        for f in sites:
            if f["kind"] not in ("release", "realloc"):
                continue
            for a in sites:
                if a["kind"] not in ALLOC_ROLE or a["site_id"] == f["site_id"]:
                    continue
                if site_gold[f["site_id"]]["exec_any"] and site_gold[a["site_id"]]["exec_any"]:
                    rel[f"{f['site_id']}|{a['site_id']}"] = int((f["site_id"], a["site_id"]) in rel_pos)
                else:
                    rel[f"{f['site_id']}|{a['site_id']}"] = None
        site_model_lines = set()
        for s in sites:
            if s["kind"] in ALLOC_ROLE:
                site_model_lines.update(range(s["line"], s["end_line"] + 1))
        out.update(sites=site_gold, rel=rel, seeds=list(SEEDS), n_inject_runs=len(inj),
                   trace_alloc_lines=sorted(trace_alloc_lines), trace_release_lines=sorted(trace_release_lines),
                   untracked_release_lines=untracked,
                   trace_alloc_missed=sorted(trace_alloc_lines - site_model_lines))
        return out
    except Exception as exc:  # noqa: BLE001
        out.update(status="error", note=out["note"] + [f"{type(exc).__name__}: {exc}"[:300]])
        return out
    finally:
        out["seconds"] = round(time.perf_counter() - t0, 3)
        shutil.rmtree(wdir, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", required=True)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only", default=None, help="comma-separated unit ids")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    units = [json.loads(l) for l in layer_path(args.layer).open()]
    if args.only:
        keep = set(args.only.split(","))
        units = [u for u in units if u["unit_id"] in keep]
    if args.limit:
        units = units[:args.limit]
    BUILD.mkdir(exist_ok=True)
    workroot = Path(tempfile.mkdtemp(prefix=f"l4d_gold_{args.layer}_", dir="/tmp"))
    outp = Path(args.out) if args.out else BUILD / f"gold_{args.layer}.jsonl"
    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=min(args.jobs, 8)) as ex, open(outp, "w") as fo:
        for res in ex.map(lambda u: gold_unit(u, args.layer, workroot), units):
            fo.write(json.dumps(res) + "\n")
            done += 1
            if done % 100 == 0:
                print(f"{done}/{len(units)} {time.time() - t0:.0f}s", flush=True)
    shutil.rmtree(workroot, ignore_errors=True)
    print(f"done {done} units in {time.time() - t0:.0f}s -> {outp}")


if __name__ == "__main__":
    main()

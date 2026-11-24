#!/usr/bin/env python3
"""L4-D derivation (contract l4d/README.md section 3): Yes/No answers -> facts -> leak verdict per unit.

    .venv/bin/python derive.py --questions build/questions_layer1.jsonl --answers answers.jsonl --tau 0.5 \
        --method l4d_qwen --out results/l4d/layer1/run.jsonl [--souffle]
    .venv/bin/python derive.py --questions build/questions_layer1.jsonl --gold --out /tmp/oracle.jsonl   # oracle

Answers rows: {qid, p_yes, ...} (contract section 4; extra fields are ignored).  --gold uses each question's gold
label as p_yes (null -> 0).  A unit with any unanswered question gets pred null, status "invalid".

Hard verdict: fact true iff p_yes >= tau, then the rules of l4d.dl, evaluated by `evaluate_unit` (Python, used for
the output and the timing).  --souffle also runs l4d.dl once over all units with Souffle and fails if any unit
verdict differs from the Python evaluator.
Soft score: max over heap blocks a of p_heap(a) * p_any(a) * prod_f (1 - p_rel(f,a) * p_all(f)) and over realloc
sites r of p_any(r) * (1 - p_safe(r)); p_heap(r) = 1 for realloc sites (heap_block(r) :- realloc(r)).

Output rows follow ../README.md section 4.  latency_s is the derive time of the unit only (fact building + rules +
score); the caller adds the time of the model calls.  The layer field uses the section-4 names (layer3 -> stress).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

L4D_DIR = Path(__file__).resolve().parent
DL_FILE = L4D_DIR / "l4d.dl"
SOUFFLE_ROOT = Path.home() / "tools/cs224/souffle-2.5/usr"
SOUFFLE_BIN = SOUFFLE_ROOT / "bin/souffle"
SOUFFLE_LIB = SOUFFLE_ROOT / "lib/x86_64-linux-gnu"
PRED_LAYER = {"layer1": "layer1", "layer3": "stress", "placebo": "placebo", "original": "original"}


def unit_inputs(questions: list[dict]) -> dict:
    """Site lists and per-qtype question index of one unit (from its question rows)."""
    alloc, realloc = [], []
    for q in questions:
        if q["qtype"] in ("exec_any",):
            kind = q["site_kinds"][0]
            if kind == "alloc":
                alloc.append(q["site_ids"][0])
            elif kind == "realloc":
                realloc.append(q["site_ids"][0])
    return {"alloc": alloc, "realloc": realloc}


def evaluate_unit(sites: dict, p: dict, tau: float) -> dict:
    """sites: {"alloc": [...], "realloc": [...]}; p: {(qtype, site_ids tuple): p_yes}. Returns verdict + score."""
    def fact(qt, *ids):
        return p.get((qt, ids), 0.0) >= tau

    rel_by_a = defaultdict(list)
    for (qt, ids), v in p.items():
        if qt == "rel":
            rel_by_a[ids[1]].append((ids[0], v))
    leaks = []
    score = 0.0
    heap_blocks = [(a, p.get(("heap", (a,)), 0.0)) for a in sites["alloc"]] + [(r, 1.0) for r in sites["realloc"]]
    for a, p_heap in heap_blocks:
        is_heap = a in sites["realloc"] or p_heap >= tau
        freed = any(v >= tau and fact("exec_all", f) for f, v in rel_by_a[a])
        if is_heap and fact("exec_any", a) and not freed:
            leaks.append([a, "never_freed"])
        s = p_heap * p.get(("exec_any", (a,)), 0.0)
        for f, v in rel_by_a[a]:
            s *= 1.0 - v * p.get(("exec_all", (f,)), 0.0)
        score = max(score, s)
    for r in sites["realloc"]:
        if fact("exec_any", r) and not fact("realloc_safe", r):
            leaks.append([r, "realloc_fail"])
        score = max(score, p.get(("exec_any", (r,)), 0.0) * (1.0 - p.get(("realloc_safe", (r,)), 0.0)))
    return {"pred": int(bool(leaks)), "score": score, "leaks": leaks}


def load_answers(path: Path) -> dict:
    out = {}
    with path.open() as fh:
        for line in fh:
            r = json.loads(line)
            out[r["qid"]] = float(r["p_yes"])
    return out


def souffle_verdicts(units: dict, tau: float) -> dict:
    """Run l4d.dl once over all units; returns {unit_id: set of (site, reason)}."""
    rels = {k: [] for k in ("unit", "alloc", "realloc", "heap", "exec_any", "exec_all", "rel", "realloc_safe")}
    for uid, (sites, p) in units.items():
        rels["unit"].append((uid,))
        rels["alloc"] += [(uid, a) for a in sites["alloc"]]
        rels["realloc"] += [(uid, r) for r in sites["realloc"]]
        for (qt, ids), v in p.items():
            if v >= tau:
                rels[qt].append((uid, *ids))
    env = dict(os.environ)
    if SOUFFLE_LIB.is_dir():
        env["LD_LIBRARY_PATH"] = f"{SOUFFLE_LIB}:{env.get('LD_LIBRARY_PATH', '')}"
    with tempfile.TemporaryDirectory(prefix="l4d_souffle_") as td:
        fdir, odir = Path(td, "facts"), Path(td, "out")
        fdir.mkdir()
        odir.mkdir()
        for name, rows in rels.items():
            Path(fdir, f"{name}.facts").write_text("".join("\t".join(r) + "\n" for r in rows))
        subprocess.run([str(SOUFFLE_BIN), "-F", str(fdir), "-D", str(odir), str(DL_FILE)], check=True, env=env,
                       capture_output=True, text=True)
        res = defaultdict(set)
        for line in Path(odir, "leak.csv").read_text().splitlines():
            u, a, reason = line.split("\t")
            res[u].add((a, reason))
        for line in Path(odir, "unit_leak.csv").read_text().splitlines():
            res[line.strip()]
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--questions", required=True, type=Path)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--answers", type=Path)
    src.add_argument("--gold", action="store_true", help="use the gold labels of the questions as answers")
    ap.add_argument("--tau", type=float, default=0.5)
    ap.add_argument("--method", default="l4d")
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--souffle", action="store_true")
    args = ap.parse_args()

    by_unit = defaultdict(list)
    with args.questions.open() as fh:
        for line in fh:
            q = json.loads(line)
            by_unit[q["unit_id"]].append(q)
    answers = None if args.gold else load_answers(args.answers)
    method, model = (args.method if not args.gold else "l4d_oracle"), (args.model if not args.gold else "gold")

    rows, inputs = [], {}
    for uid, qs in by_unit.items():
        t0 = time.perf_counter()
        sites = unit_inputs(qs)
        p, missing = {}, 0
        for q in qs:
            if args.gold:
                v = float(q["gold"] or 0)
            elif q["qid"] in answers:
                v = answers[q["qid"]]
            else:
                missing += 1
                continue
            p[(q["qtype"], tuple(q["site_ids"]))] = v
        res = evaluate_unit(sites, p, args.tau)
        dt = time.perf_counter() - t0
        inputs[uid] = (sites, p)
        ok = missing == 0
        rows.append({"unit_id": uid, "method": method, "strategy": "L4D", "model": model,
                     "layer": PRED_LAYER.get(qs[0]["layer"], qs[0]["layer"]),
                     "pred": res["pred"] if ok else None, "score": res["score"] if ok else None,
                     "latency_s": dt, "status": "ok" if ok else "invalid",
                     "extra": {"tau": args.tau, "n_questions": len(qs), "n_missing": missing,
                               "leaks": res["leaks"], "derive_s": dt}})
    if args.souffle:
        t0 = time.perf_counter()
        sv = souffle_verdicts(inputs, args.tau)
        ts = time.perf_counter() - t0
        diff = [r["unit_id"] for r in rows
                if {tuple(x) for x in r["extra"]["leaks"]} != sv.get(r["unit_id"], set())]
        print(f"souffle: {len(rows)} units in {ts:.2f}s, {len(diff)} differ from the Python evaluator {diff[:10]}",
              file=sys.stderr)
        if diff:
            sys.exit(1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    lat = sorted(r["latency_s"] for r in rows)
    print(f"{len(rows)} units -> {args.out}; derive median {lat[len(lat) // 2] * 1e3:.3f} ms, "
          f"max {lat[-1] * 1e3:.3f} ms", file=sys.stderr)


if __name__ == "__main__":
    main()

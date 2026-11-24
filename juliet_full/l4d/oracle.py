#!/usr/bin/env python3
"""Oracle check (contract l4d/README.md section 3): gold facts -> derive.py --gold --souffle -> macro-F1 per set,
every failing unit listed; parser recall of the allocation lines seen in the dynamic trace.

    .venv/bin/python oracle.py --layer layer1      -> build/oracle_<layer>.json (+ build/oracle_pred_<layer>.jsonl)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

L4D_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(L4D_DIR))
from parse_sites import BUILD, layer_path  # noqa: E402


def macro_f1(pairs: list[tuple[int, int | None]]) -> dict:
    """pairs of (label, pred); pred None counts as wrong (bad -> FN, good -> FP, ../README.md section 4)."""
    f1s = []
    out = {}
    eff = [(y, 1 - y if p is None else p) for y, p in pairs]
    for cls in (1, 0):
        tp = sum(1 for y, p in eff if y == cls and p == cls)
        fp = sum(1 for y, p in eff if y != cls and p == cls)
        fn = sum(1 for y, p in eff if y == cls and p != cls)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out[f"f1_{cls}"] = f1
        f1s.append(f1)
    out["macro_f1"] = sum(f1s) / 2
    out["n"] = len(pairs)
    out["errors"] = sum(1 for y, p in pairs if y != p)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", required=True)
    args = ap.parse_args()
    qpath = BUILD / f"questions_{args.layer}.jsonl"
    ppath = BUILD / f"oracle_pred_{args.layer}.jsonl"
    p = subprocess.run([sys.executable, str(L4D_DIR / "derive.py"), "--questions", str(qpath), "--gold",
                        "--souffle", "--out", str(ppath)], capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode:
        sys.exit(p.returncode)
    units = {}
    for line in layer_path(args.layer).open():
        u = json.loads(line)
        units[u["unit_id"]] = u
    preds = {}
    for line in ppath.open():
        r = json.loads(line)
        preds[r["unit_id"]] = r
    res = {"layer": args.layer, "sets": {}, "failures": []}
    for st in ("dev", "eval"):
        pairs = [(u["truth"], preds[uid]["pred"] if uid in preds else None)
                 for uid, u in units.items() if u["set"] == st]
        if pairs:
            res["sets"][st] = macro_f1(pairs)
    for uid, u in units.items():
        pr = preds.get(uid)
        if pr is None or pr["pred"] != u["truth"]:
            res["failures"].append({"unit_id": uid, "set": u["set"], "label": u["truth"],
                                    "pred": None if pr is None else pr["pred"], "variant": u["variant"],
                                    "flow_category": u["flow_category"], "mechanism": u["mechanism"],
                                    "leaks": None if pr is None else pr["extra"]["leaks"]})
    # parser recall of trace-observed allocation lines
    gold_path = BUILD / f"gold_{args.layer}.jsonl"
    seen = missed = 0
    missed_units = []
    for line in gold_path.open():
        g = json.loads(line)
        seen += len(g.get("trace_alloc_lines") or [])
        m = g.get("trace_alloc_missed") or []
        missed += len(m)
        if m:
            missed_units.append([g["unit_id"], m])
    res["parser_recall"] = {"trace_alloc_lines": seen, "missed": missed,
                            "recall": (seen - missed) / seen if seen else None, "missed_units": missed_units}
    res["failure_summary"] = dict(Counter(f"{f['set']}/label{f['label']}/v{f['variant']}/{f['mechanism']}"
                                          for f in res["failures"]))
    (BUILD / f"oracle_{args.layer}.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "failures"}, indent=1))


if __name__ == "__main__":
    main()

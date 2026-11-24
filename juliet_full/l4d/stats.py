#!/usr/bin/env python3
"""Per-layer question statistics: build/qcounts_<layer>.json -> build/<layer>_stats.json.

Per-unit question-count distribution (total and per qtype, per set) and label balance per set/qtype.
    python3 stats.py --layer layer1
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

BUILD = Path(__file__).resolve().parent / "build"
QTYPES = ("heap", "exec_any", "exec_all", "rel", "realloc_safe")


def dist(xs: list[int]) -> dict:
    xs = sorted(xs)
    q = lambda f: xs[min(len(xs) - 1, int(f * len(xs)))]  # noqa: E731
    return {"n_units": len(xs), "sum": sum(xs), "mean": round(statistics.mean(xs), 3), "min": xs[0], "p50": q(0.5),
            "p90": q(0.9), "p99": q(0.99), "max": xs[-1]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", required=True)
    args = ap.parse_args()
    qc = json.loads((BUILD / f"qcounts_{args.layer}.json").read_text())
    units = {}
    data = Path(__file__).resolve().parent.parent / "data" / "build" / f"{args.layer}.jsonl"
    for line in data.open():
        u = json.loads(line)
        units[u["unit_id"]] = u["set"]
    out = {"layer": qc["layer"], "template_sha256": qc["template_sha256"], "units": qc["units"],
           "questions": qc["questions"], "per_unit_questions": {}, "label_balance": {}}
    for st in ("all", "dev", "eval"):
        pu = {uid: c for uid, c in qc["per_unit"].items() if st == "all" or units[uid] == st}
        if not pu:
            continue
        d = {"total": dist([c["total"] for c in pu.values()])}
        for qt in QTYPES:
            d[qt] = dist([c.get(qt, 0) for c in pu.values()])
        out["per_unit_questions"][st] = d
    for key, c in qc["labels"].items():
        n = sum(c.values())
        out["label_balance"][key] = {"yes": c.get("1", 0), "no": c.get("0", 0), "null": c.get("None", 0), "n": n,
                                     "frac_yes": round(c.get("1", 0) / n, 4) if n else None}
    (BUILD / f"{args.layer}_stats.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out["label_balance"], indent=1))
    print(json.dumps(out["per_unit_questions"]["all"]["total"]))


if __name__ == "__main__":
    main()

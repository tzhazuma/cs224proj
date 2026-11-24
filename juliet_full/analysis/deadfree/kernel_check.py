#!/usr/bin/env python3
"""Check that the Intern-Decision server (:8002) reproduces the stored DeadFree predictions.

Re-sends the first N latency300 layer3 units (sorted by unit_id) of the stored eval runs
gpu/results/intern_decision/layer3/l3_eval_L{1,3}_r1.jsonl with the frozen run_decide.py request and compares
calibrated scores (|d score|, BF16 tolerance) and verdicts at 0.5. Used after restarting :8002 with the built
causal_conv1d kernel (pyext_cc1d) instead of the transformers reference fallback.

  python kernel_check.py --tag kernel [--n 50] [--strategies L1 L3]   -> kernel_check_<tag>.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JF = HERE.parents[1]
sys.path.insert(0, str(JF / "gpu"))
from run_decide import (CLANG_EVIDENCE_TEMPLATE, DecideClient, PromptSet, frozen_evidence, load_evidence,  # noqa: E402
                        load_units, request_body)

TOLERANCE = 0.02  # |d calibrated p|; BF16 kernel differences move p by ~1e-3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--strategies", nargs="+", default=["L1", "L3"])
    ap.add_argument("--endpoint", default="http://10.15.89.184:8002")
    args = ap.parse_args()
    groups = set(json.loads((JF / "data/build/subsets.json").read_text())["latency300"])
    units = {u["unit_id"]: u for u in load_units(JF / "data/build/layer3.jsonl")}
    ids = sorted(uid for uid, u in units.items() if u["group_id"] in groups)[:args.n]
    client = DecideClient(args.endpoint)
    code, health = client.call("GET", "/health")
    assert code == 200, code
    out = {"tag": args.tag, "endpoint": args.endpoint, "server_health": health, "n": len(ids),
           "tolerance_abs_score": TOLERANCE, "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "strategies": {}}
    for strategy in args.strategies:
        stored = {}
        for line in (JF / f"gpu/results/intern_decision/layer3/l3_eval_{strategy}_r1.jsonl").open():
            r = json.loads(line)
            stored[r["unit_id"]] = r
        prompts = PromptSet(strategy, "jev")
        evidence = None
        if strategy == "L3":
            path, _ = frozen_evidence(Path(str(CLANG_EVIDENCE_TEMPLATE).format(layer="layer3")).parent)
            evidence = load_evidence(path)
        rows = []
        for uid in ids:
            state, _ = prompts.jev_state(units[uid], evidence.get(uid) if evidence is not None else None)
            t0 = time.perf_counter()
            code, payload = client.call("POST", "/decide", request_body(prompts, state))
            dt = time.perf_counter() - t0
            assert code == 200, (uid, code, str(payload)[:200])
            score, old = float(payload["probs"]["yes"]), stored[uid]
            rows.append({"unit_id": uid, "score": score, "stored_score": old["score"], "pred": int(score >= 0.5),
                         "stored_pred": old["pred"], "abs_d": abs(score - old["score"]), "client_s": dt,
                         "forward_ms": payload["forward_ms"], "stored_forward_ms": old["extra"]["forward_ms"],
                         "latency_ms_server": payload["latency_ms_server"]})
        d = [r["abs_d"] for r in rows]
        out["strategies"][strategy] = {
            "max_abs_d": max(d), "mean_abs_d": statistics.fmean(d),
            "n_pred_mismatch": sum(r["pred"] != r["stored_pred"] for r in rows),
            "n_over_tolerance": sum(x > TOLERANCE for x in d),
            "median_forward_ms": statistics.median(r["forward_ms"] for r in rows),
            "median_stored_forward_ms": statistics.median(r["stored_forward_ms"] for r in rows),
            "median_client_s": statistics.median(r["client_s"] for r in rows), "rows": rows}
        s = out["strategies"][strategy]
        print(strategy, {k: v for k, v in s.items() if k != "rows"}, flush=True)
    dest = HERE / f"kernel_check_{args.tag}.json"
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print("wrote", dest)


if __name__ == "__main__":
    main()

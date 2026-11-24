"""Re-measure Intern-Decision-4B /decide on latency300, c1, from dell (kernel check; lane l4d-train).

    flock /tmp/cs224_latency.lock python3 kernel/intern_lat300.py --tag kernel --layer layer3 --strategies L1 L3 \
        --endpoint http://10.15.89.184:8002
Runs gpu/run_decide.py `run` unchanged (read-only import; frozen Jev prompts, frozen clang_sa evidence for L3,
latency300, concurrency 1) with its RESULTS redirected to l4d_ft/results/kernel/intern_decision/<tag>/ (the FROZEN
file is still read from the gpu lane). Equivalence: per-unit p_leak/pred vs the stored full-eval run of the gpu lane
(layer1 eval_L<S>_r1.jsonl, layer3 l3_eval_L<S>_r1.jsonl), stored latency300 timing where it exists (layer1 L1)
-> results/scores/kernel_equiv_intern_decision_<layer>_<tag>.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
JULIET_FULL = HERE.parent
sys.path.insert(0, str(JULIET_FULL / "gpu"))
import run_decide  # noqa: E402  (gpu lane, read-only)

STORED_EVAL = {"layer1": "eval_L{s}_r1.jsonl", "layer3": "l3_eval_L{s}_r1.jsonl"}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[int(q * (len(xs) - 1))]


def lat(rows: list[dict], key) -> dict:
    v = [key(r) for r in rows]
    return {"median": statistics.median(v), "p90": pct(v, 0.9)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--layer", choices=("layer1", "layer3"), default="layer1")
    ap.add_argument("--strategies", nargs="+", default=["L1"], choices=["L1", "L3"])
    ap.add_argument("--endpoint", default="http://10.15.89.184:8002")
    args = ap.parse_args()
    stored_dir = run_decide.RESULTS / args.layer
    run_decide.RESULTS = HERE / "results" / "kernel" / "intern_decision" / args.tag
    out = {"tag": args.tag, "layer": args.layer, "endpoint": args.endpoint}
    for s in args.strategies:
        while os.getloadavg()[0] >= 2.5:
            time.sleep(15)
        run_id = f"lat300_{s}_c1"
        rc = run_decide.main(["run", "--units", str(JULIET_FULL / "data/build" / f"{args.layer}.jsonl"),
                              "--set", "eval", "--strategy", s, "--layer", args.layer, "--subset", "latency300",
                              "--run-id", run_id, "--endpoint", args.endpoint, "--concurrency", "1", "--overwrite"])
        assert rc in (0, None), rc
        new = read_jsonl(run_decide.RESULTS / args.layer / f"{run_id}.jsonl")
        ref_path = stored_dir / STORED_EVAL[args.layer].format(s=s[1:])
        ref = {r["unit_id"]: r for r in read_jsonl(ref_path)}
        d = [abs(r["score"] - ref[r["unit_id"]]["score"]) for r in new]
        res = {"n": len(new), "reference": str(ref_path.relative_to(JULIET_FULL)),
               "max_abs_delta_p_leak": max(d), "mean_abs_delta_p_leak": statistics.fmean(d),
               "pred_flips": sum(r["pred"] != ref[r["unit_id"]]["pred"] for r in new),
               "e2e_s": lat(new, lambda r: r["latency_s"]),
               "server_s": lat(new, lambda r: r["extra"]["latency_ms_server"] / 1000),
               "forward_s": lat(new, lambda r: r["extra"]["forward_ms"] / 1000)}
        stored_lat = stored_dir / f"{run_id}.jsonl"
        if stored_lat.exists():
            old = read_jsonl(stored_lat)
            res |= {"stored_latency_run": str(stored_lat.relative_to(JULIET_FULL)),
                    "e2e_s_stored": lat(old, lambda r: r["latency_s"]),
                    "server_s_stored": lat(old, lambda r: r["extra"]["latency_ms_server"] / 1000),
                    "forward_s_stored": lat(old, lambda r: r["extra"]["forward_ms"] / 1000)}
        out[s] = res
        print(s, json.dumps(res), flush=True)
    dest = HERE / "results" / "scores" / f"kernel_equiv_intern_decision_{args.layer}_{args.tag}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out))


if __name__ == "__main__":
    main()

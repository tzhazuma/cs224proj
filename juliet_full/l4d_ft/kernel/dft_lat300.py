"""Re-measure the decision_ft LoRA L1/L3 endpoint (:8003) on latency300, c1, from dell; kernel check (lane l4d-train).

    flock /tmp/cs224_latency.lock python3 kernel/dft_lat300.py --tag kernel --layer layer3
Runs decision_ft/endpoint_client.py cmd_latency unchanged (read-only import; same 5 warm-ups per fold model, same
quiet rule load1 < 2.5); for --layer != layer1 its input loader is pointed at data/build/<layer>.jsonl and the static
lane's frozen clang_sa evidence of that layer (same files decision_ft used for its stored <layer> predictions).
Output redirected to l4d_ft/results/kernel/decision_ft/<tag>/<layer>/ (row/meta "layer" rewritten to <layer>).
Equivalence: per-unit score/pred vs the stored merged held-out predictions decision_ft/results/decision_ft/<layer>/
<S>_cv_v1.jsonl -> results/scores/kernel_equiv_decision_ft_<layer>_<tag>.json (+ stored latency300 meta, layer1).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
JULIET_FULL = HERE.parent
DFT_DIR = JULIET_FULL / "decision_ft"
sys.path.insert(0, str(DFT_DIR))
import endpoint_client  # noqa: E402  (decision_ft lane, read-only)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--layer", choices=("layer1", "layer3"), default="layer1")
    args = ap.parse_args()
    if args.layer != "layer1":
        ev_dir = JULIET_FULL / "static/results/clang_sa" / args.layer
        ev_file = ev_dir / f"{(ev_dir / 'EVIDENCE_FROZEN').read_text().split()[0]}.evidence.jsonl"

        def load_inputs():
            units = {u["unit_id"]: u for u in read_jsonl(JULIET_FULL / "data/build" / f"{args.layer}.jsonl")}
            return units, {r["unit_id"]: r for r in read_jsonl(ev_file)}
        endpoint_client.load_inputs = load_inputs
    out_dir = HERE / "results" / "kernel" / "decision_ft" / args.tag / args.layer
    out_dir.mkdir(parents=True, exist_ok=True)
    stored_lat_dir = endpoint_client.RESULTS
    endpoint_client.RESULTS = out_dir
    endpoint_client.cmd_latency()
    summary = {"tag": args.tag, "layer": args.layer}
    for strategy in ("L1", "L3"):
        path = out_dir / f"latency300_{strategy}_v1.jsonl"
        rows = read_jsonl(path)
        for r in rows:
            r["layer"] = args.layer
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        meta_path = path.with_name(f"latency300_{strategy}_v1.meta.json")
        meta = json.loads(meta_path.read_text()) | {"layer": args.layer}
        meta_path.write_text(json.dumps(meta, indent=1) + "\n")
        ref_path = DFT_DIR / "results/decision_ft" / args.layer / f"{strategy}_cv_v1.jsonl"
        ref = {r["unit_id"]: r for r in read_jsonl(ref_path)}
        d = [abs(r["score"] - ref[r["unit_id"]]["score"]) for r in rows]
        s = {"n": len(rows), "reference": str(ref_path.relative_to(JULIET_FULL)),
             "max_abs_delta_score": max(d), "mean_abs_delta_score": statistics.fmean(d),
             "pred_flips": sum(r["pred"] != ref[r["unit_id"]]["pred"] for r in rows),
             "median_s": meta["median_s"], "p90_s": meta["p90_s"], "loadavg_start": meta.get("loadavg_start")}
        stored_meta = stored_lat_dir / f"latency300_{strategy}_v1.meta.json"
        if args.layer == "layer1" and stored_meta.exists():
            m = json.loads(stored_meta.read_text())
            s |= {"stored_latency_meta": str(stored_meta.relative_to(JULIET_FULL)),
                  "median_s_stored": m["median_s"], "p90_s_stored": m["p90_s"]}
        summary[strategy] = s
    dest = HERE / "results" / "scores" / f"kernel_equiv_decision_ft_{args.layer}_{args.tag}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()

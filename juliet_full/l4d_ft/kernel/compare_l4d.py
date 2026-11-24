"""Live L4-D latency-run answers vs the stored frozen batch answers (dell, CPU; lane l4d-train).

    ../l4d/.venv/bin/python kernel/compare_l4d.py --run results/lora_l4d/layer1/lat300_c1_kernel.jsonl
    ../l4d/.venv/bin/python kernel/compare_l4d.py --run results/lora_l4d_opt/layer3/lat300_c1_kernel.jsonl
Reference = the stored lora_l4d eval answers results/lora_l4d/<layer>/eval_r1.jsonl (PyTorch causal_conv1d
fallback, each unit answered by its own fold model, batched per unit) and its units file. Compared on the questions
the run asked (all, or the kept ones for lora_l4d_opt): max/mean |delta p_yes|, question flips at p_yes 0.5, and unit
verdict flips (pred and leak list vs the stored lora_l4d unit rows) -> results/scores/kernel_equiv_<method>_<layer>_<run>.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True, help="latency.py output with extra.answers")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    run_path = HERE / args.run
    run = read_jsonl(run_path)
    method, layer = run[0]["method"], run[0]["layer"]
    stored_ans = HERE / "results" / "lora_l4d" / layer / "eval_r1.jsonl"
    stored = {a["qid"]: a["p_yes"] for a in read_jsonl(stored_ans)}
    stored_units = {r["unit_id"]: r for r in read_jsonl(stored_ans.with_name("eval_r1_units.jsonl"))}
    deltas, q_flips, flipped_units, leak_diff_units = [], 0, [], []
    for r in run:
        for qid, new in r["extra"]["answers"].items():
            old = stored[qid]
            deltas.append(abs(new - old))
            q_flips += (new >= 0.5) != (old >= 0.5)
        s = stored_units[r["unit_id"]]
        if s["pred"] != r["pred"]:
            flipped_units.append(r["unit_id"])
        if s["extra"]["leaks"] != r["extra"]["leaks"]:
            leak_diff_units.append(r["unit_id"])
    out = {"run": args.run, "method": method, "layer": layer, "reference": str(stored_ans.relative_to(HERE)),
           "n_units": len(run), "n_questions": len(deltas),
           "max_abs_delta_p_yes": max(deltas) if deltas else None,
           "mean_abs_delta_p_yes": statistics.fmean(deltas) if deltas else None,
           "question_flips_at_0.5": q_flips, "unit_pred_flips": len(flipped_units), "flipped_units": flipped_units,
           "unit_leak_list_diffs": len(leak_diff_units), "leak_diff_units": leak_diff_units}
    dest = HERE / (args.out or f"results/scores/kernel_equiv_{method}_{layer}_{run_path.stem}.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k not in ("flipped_units", "leak_diff_units")}))


if __name__ == "__main__":
    main()

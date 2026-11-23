"""dell: score every collected decision_ft / qwen_readout_zeroshot prediction file with analysis/score.py --set eval
(+ AUROC of the score, which score.py does not compute: pooled over all
eval units, and per fold, because the three fold models' score scales differ, so the pooled AUROC mixes scales) -> runs/score/<method>_<layer>_<run_id>.json, runs/score/summary.json.

    python3 score_all.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET = HERE.parent
OUT = HERE / "runs" / "score"
FILES = [("decision_ft", layer, f"{s}_cv_v1") for layer in ("layer1", "layer3", "placebo", "original")
         for s in ("L1", "L3") if not (layer == "original" and s == "L3")]
FILES += [("decision_ft", "layer1", f"unmerged_{s}_cv_v1") for s in ("L1", "L3")]  # = 3 unmerged fold files, in /tmp
FILES += [("qwen_readout_zeroshot", layer, f"{s}_v1") for layer in ("layer1", "layer3") for s in ("L1", "L3")]


def auroc(scores: list[float], truth: list[int]) -> float:
    """Mann-Whitney AUROC with ties counted 1/2."""
    pairs = sorted(zip(scores, truth))
    n_pos = sum(truth)
    n_neg = len(truth) - n_pos
    rank_sum, i = 0.0, 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2  # 1-based ranks i+1..j
        rank_sum += avg_rank * sum(t for _, t in pairs[i:j])
        i = j
    return (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []
    for method, layer, run_id in FILES:
        pred = HERE / "results" / method / layer / f"{run_id}.jsonl"
        if run_id.startswith("unmerged_"):  # appendix check: concatenate the three held-out fold files
            parts = [HERE / "results" / method / layer / (run_id.replace("_cv_", f"_fold{k}_") + ".jsonl")
                     for k in (0, 1, 2)]
            pred = Path("/tmp") / f"dft_{run_id}.jsonl"
            pred.write_text("".join(p.read_text() for p in parts))
        units_path = JULIET / "data" / "build" / f"{layer}.jsonl"
        report = OUT / f"{method}_{layer}_{run_id}.json"
        subprocess.run([sys.executable, str(JULIET / "analysis" / "score.py"), "--pred", str(pred), "--units",
                        str(units_path), "--set", "eval", "--json", "--out", str(report)],
                       check=True, stdout=subprocess.DEVNULL)
        rep = json.loads(report.read_text())
        truth = {u["unit_id"]: u["truth"] for u in map(json.loads, units_path.read_text().splitlines())
                 if u["set"] == "eval"}
        rows = [json.loads(line) for line in pred.read_text().splitlines()]
        rows = [r for r in rows if r["unit_id"] in truth]
        e2e = rep["end_to_end"]
        entry = {"method": method, "layer": layer, "run_id": run_id, "n": e2e["n"], "missing": rep["missing"],
                 "macro_f1": e2e["macro_f1"], "f1_leak": e2e["f1_leak"], "precision_leak": e2e["precision_leak"],
                 "recall_leak": e2e["recall_leak"], "specificity": e2e["specificity"], "mcc": e2e["mcc"],
                 "accuracy": e2e["accuracy"], "auroc": auroc([r["score"] for r in rows],
                                                             [truth[r["unit_id"]] for r in rows]),
                 "auroc_per_fold": {k: auroc([r["score"] for r in rows if r["extra"]["unit_fold"] == k],
                                             [truth[r["unit_id"]] for r in rows if r["extra"]["unit_fold"] == k])
                                    for k in (0, 1, 2)},
                 "latency_median_s": rep["latency"]["median_s"],
                 "macro_f1_ci95": rep.get("bootstrap", {}).get("ci95", {}).get("macro_f1")}
        if method == "qwen_readout_zeroshot":
            alt = [{**r, "pred": r["extra"]["pred_at_dev_threshold"]} for r in rows]
            alt_path = Path("/tmp") / f"dft_readout_devthr_{layer}_{run_id}.jsonl"
            alt_path.write_text("".join(json.dumps(r) + "\n" for r in alt))
            alt_rep = json.loads(subprocess.run(
                [sys.executable, str(JULIET / "analysis" / "score.py"), "--pred", str(alt_path), "--units",
                 str(units_path), "--set", "eval", "--json", "--bootstrap", "0"],
                check=True, capture_output=True, text=True).stdout)
            entry["dev_threshold"] = rows[0]["extra"]["dev_threshold"]
            entry["macro_f1_at_dev_threshold"] = alt_rep["end_to_end"]["macro_f1"]
        summary.append(entry)
        print(json.dumps(entry), flush=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")


if __name__ == "__main__":
    main()

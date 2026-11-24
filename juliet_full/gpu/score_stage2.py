#!/usr/bin/env python3
"""Score the stage-2 gpu-lane runs (eval set) with analysis/score.py and analysis/robustness.py.

Intern-Decision runs are scored at the primary threshold 0.5 (the run file itself) and at the frozen secondary
threshold of the strategy (results/intern_decision/FROZEN): a copy of the run with pred := extra.pred_secondary is
written to results/intern_decision_th2/<layer>/<run_id>.jsonl (method "intern_decision_th2") and scored the same way.
LineVul has no frozen secondary threshold (primary 0.5 only).

Outputs: results/scores/<method>/<layer>/<run_id>.json (score.py --json), results/robustness/<label>.json
(robustness.py --json) and .md, results/STAGE2_SCORES.md (tables), results/stage2_scores.json.
Also checks det50_L1_r2 against eval_L1_r1 (determinism) and adds AUROC (scores of status-ok units).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

GPU = Path(__file__).resolve().parent
JF = GPU.parent
RES = GPU / "results"
BUILD = JF / "data/build"
BOOTSTRAP = "2000"
sys.path.insert(0, str(GPU))
from run_decide import FROZEN_PATH, auroc  # noqa: E402

ID_RUNS = {  # (layer, run_id) per strategy
    "L1": {"layer1": "eval_L1_r1", "layer3": "l3_eval_L1_r1", "placebo": "pl_eval_L1_r1", "original": "orig_eval_L1_r1"},
    "L2": {"layer1": "eval_L2_r1", "layer3": "l3_eval_L2_r1"},
    "L3": {"layer1": "eval_L3_r1", "layer3": "l3_eval_L3_r1", "placebo": "pl_eval_L3_r1"},
}
LINEVUL_RUNS = {"layer1": "deveval_v1", "layer3": "all_v1", "placebo": "all_v1", "original": "all_v1"}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_th2(layer: str, run_id: str) -> Path:
    rows = read_jsonl(RES / "intern_decision" / layer / f"{run_id}.jsonl")
    out = RES / "intern_decision_th2" / layer / f"{run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as handle:
        for r in rows:
            pred = r["extra"].get("pred_secondary") if r["status"] == "ok" else None
            if r["status"] == "ok" and pred is None:
                raise SystemExit(f"{run_id}: ok row without pred_secondary ({r['unit_id']})")
            handle.write(json.dumps({**r, "method": "intern_decision_th2", "pred": pred}) + "\n")
    return out


def score(method: str, layer: str, run_id: str, pred: Path) -> dict:
    out = RES / "scores" / method / layer / f"{run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(JF / "analysis/score.py"), "--pred", str(pred), "--units",
                    str(BUILD / f"{layer}.jsonl"), "--set", "eval", "--bootstrap", BOOTSTRAP, "--json",
                    "--out", str(out)], check=True, stdout=subprocess.DEVNULL)
    report = json.loads(out.read_text())
    rows = [r for r in read_jsonl(pred)]
    truth = {json.loads(l)["unit_id"]: int(json.loads(l)["truth"]) for l in (BUILD / f"{layer}.jsonl").open()}
    pairs = [(truth[r["unit_id"]], r["score"]) for r in rows if r["status"] == "ok" and r["score"] is not None]
    e = report["end_to_end"]
    ci = report.get("bootstrap", {}).get("ci95", {}).get("macro_f1")
    return {"method": method, "layer": layer, "run_id": run_id, "n": e["n"], "macro_f1": e["macro_f1"],
            "macro_f1_ci95": ci, "f1_leak": e["f1_leak"], "precision_leak": e["precision_leak"],
            "recall_leak": e["recall_leak"], "specificity": e["specificity"], "mcc": e["mcc"],
            "tp": e["tp"], "fn": e["fn"], "fp": e["fp"], "tn": e["tn"], "invalid": e["invalid"],
            "auroc": auroc(pairs), "latency_median_s": report["latency"]["median_s"]}


def robustness(label: str, base: Path, stress: Path, placebo: Path | None) -> dict:
    out = RES / "robustness" / f"{label}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(JF / "analysis/robustness.py"), "--base", str(base), "--stress", str(stress),
           "--set", "eval", "--bootstrap", BOOTSTRAP, "--label", label]
    if placebo:
        cmd += ["--placebo", str(placebo)]
    md = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    out.with_suffix(".md").write_text(md)
    subprocess.run(cmd + ["--json", "--out", str(out)], check=True, stdout=subprocess.DEVNULL)
    return {"label": label, "json": str(out.relative_to(GPU)), "markdown": md}


def determinism() -> dict:
    a = {r["unit_id"]: r for r in read_jsonl(RES / "intern_decision/layer1/eval_L1_r1.jsonl")}
    b = read_jsonl(RES / "intern_decision/layer1/det50_L1_r2.jsonl")
    same_pred = sum(r["pred"] == a[r["unit_id"]]["pred"] for r in b)
    same_th2 = sum(r["extra"].get("pred_secondary") == a[r["unit_id"]]["extra"].get("pred_secondary") for r in b)
    diffs = [abs(r["score"] - a[r["unit_id"]]["score"]) for r in b if r["score"] is not None]
    return {"n": len(b), "pred_agree": same_pred, "pred_secondary_agree": same_th2,
            "max_abs_score_diff": max(diffs), "identical_scores": sum(d == 0 for d in diffs)}


def fmt(x: float | None) -> str:
    return "-" if x is None else f"{x:.3f}"


def main() -> int:
    frozen = json.loads(FROZEN_PATH.read_text())
    rows, robust = [], []
    for strategy, runs in ID_RUNS.items():
        th2 = frozen["strategies"][strategy]["threshold_secondary"]
        paths = {}
        for layer, run_id in runs.items():
            p1 = RES / "intern_decision" / layer / f"{run_id}.jsonl"
            p2 = write_th2(layer, run_id)
            paths[layer] = (p1, p2)
            rows.append({**score("intern_decision", layer, run_id, p1), "strategy": strategy, "threshold": 0.5})
            rows.append({**score("intern_decision_th2", layer, run_id, p2), "strategy": strategy, "threshold": th2})
        for i, name in enumerate(("th05", "th2")):
            robust.append(robustness(f"intern_decision_{strategy}_{name}", paths["layer1"][i], paths["layer3"][i],
                                     paths["placebo"][i] if "placebo" in paths else None))
    lv = {}
    for layer, run_id in LINEVUL_RUNS.items():
        lv[layer] = RES / "linevul_gpu" / layer / f"{run_id}.jsonl"
        rows.append({**score("linevul_gpu", layer, run_id, lv[layer]), "strategy": None, "threshold": 0.5})
    rows.append({**score("linevul_cpu", "layer1", "deveval_v1", RES / "linevul_cpu/layer1/deveval_v1.jsonl"),
                 "strategy": None, "threshold": 0.5})
    robust.append(robustness("linevul_gpu_th05", lv["layer1"], lv["layer3"], lv["placebo"]))
    det = determinism()
    (RES / "stage2_scores.json").write_text(json.dumps({"scores": rows, "determinism": det, "frozen": frozen,
                                                         "robustness": [{k: v for k, v in r.items() if k != "markdown"}
                                                                        for r in robust]}, indent=2) + "\n")
    lines = ["# Stage-2 gpu-lane scores (eval set, analysis/score.py end-to-end, invalid counted wrong)", "",
             f"Generated by `gpu/score_stage2.py`; family-cluster bootstrap {BOOTSTRAP} for the macro-F1 CI.", "",
             "| method | strategy | layer | run | threshold | n | macro-F1 [95% CI] | F1_leak | P | R | spec | "
             "AUROC | TP FN FP TN | invalid |", "|" + "---|" * 14]
    for r in rows:
        ci = r["macro_f1_ci95"]
        ci_s = f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else ""
        lines.append(f"| {r['method']} | {r['strategy'] or '-'} | {r['layer']} | {r['run_id']} | {r['threshold']:.4g} | "
                     f"{r['n']} | {fmt(r['macro_f1'])}{ci_s} | {fmt(r['f1_leak'])} | {fmt(r['precision_leak'])} | "
                     f"{fmt(r['recall_leak'])} | {fmt(r['specificity'])} | {fmt(r['auroc'])} | "
                     f"{r['tp']} {r['fn']} {r['fp']} {r['tn']} | {r['invalid']} |")
    lines += ["", f"Determinism (det50_L1_r2 vs eval_L1_r1): {json.dumps(det)}", "", "# Robustness", ""]
    for r in robust:
        lines += [r["markdown"].strip(), ""]
    (RES / "STAGE2_SCORES.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())

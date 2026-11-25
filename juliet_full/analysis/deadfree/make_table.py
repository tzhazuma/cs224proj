#!/usr/bin/env python3
"""DeadFree (layer3) eval quality table for every method, plus the time-quality Pareto merge.

Run from anywhere: python3 juliet_full/analysis/deadfree/make_table.py
Rerunnable; prediction files that do not exist yet become "pending" rows.

Eval set = data/build/layer3.jsonl with set == eval (2,656 units, 1,328 groups).
Scoring follows analysis/score.py (contract §4/§5): a missing or null prediction counts as wrong
(bad -> FN, good -> FP). macro-F1 = mean of leak-F1 and no-leak-F1.
Bootstrap follows analysis/near_llm_bootstrap.py: one shared set of B=2000 family-cluster resamples,
random.seed(20261123), random.choices(sorted families, k=#families); 95% CI = sorted[int(.025B)],
sorted[int(.975B)]. The same resamples are used for every method, so the deltas are paired.
Gap closed = (mF1_m - mF1_QwenL1) / (mF1_ref - mF1_QwenL1), ref in {DeepSeek L1, DeepSeek L4};
naive local baseline = untuned Qwen3.5-4B generative L1. "F1" in the gap is macro-F1.

Outputs (this directory): deadfree_quality.{csv,json,md}, deadfree_by_flow.csv and, if
latency_deadfree.csv exists, deadfree_pareto.json.
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
JF = HERE.parent.parent  # juliet_full/
UNITS = JF / "data" / "build" / "layer3.jsonl"
SEED = 20261123
B = 2000
FLOWS = ["01", "02-22", "31-45", "51-68", "71-84"]

# key, group, model, strategy, label, source (relative to juliet_full/), role
# role: primary (main table), secondary (alternative threshold / config), backup (appendix only)
METHODS = [
    ("deepseek_L1", "cloud-LLM", "deepseek-flash", "L1", "DeepSeek L1", "llm/results/deepseek_flash/layer3/l3_eval_L1_r1.jsonl", "primary"),
    ("deepseek_L2", "cloud-LLM", "deepseek-flash", "L2", "DeepSeek L2", "llm/results/deepseek_flash/layer3/l3_eval_L2_r1.jsonl", "primary"),
    ("deepseek_L3", "cloud-LLM", "deepseek-flash", "L3", "DeepSeek L3", "llm/results/deepseek_flash/layer3/l3_eval_L3_r1.jsonl", "primary"),
    ("deepseek_L4", "cloud-LLM", "deepseek-flash", "L4", "DeepSeek L4", "llm/results/deepseek_flash/layer3/l3_eval_L4_r1.jsonl", "primary"),
    ("jev_L1", "cloud-decision", "jev-latest (jev-1.14.0)", "L1", "Jev L1 @0.5", "llm/results/jev/layer3/l3_eval_L1_r1.jsonl", "primary"),
    ("jev_L2", "cloud-decision", "jev-latest (jev-1.14.0)", "L2", "Jev L2 @0.5", "llm/results/jev/layer3/l3_eval_L2_r1.jsonl", "primary"),
    ("jev_L3", "cloud-decision", "jev-latest (jev-1.14.0)", "L3", "Jev L3 @0.5", "llm/results/jev/layer3/l3_eval_L3_r1.jsonl", "primary"),
    ("jev_l4d", "cloud-decision", "jev-latest (jev-1.14.0)", "L4D", "Jev L4-D @0.5", "l4d_ft/results/jev_l4d/layer3/eval_r1_units.jsonl", "primary"),
    ("qwen_L1", "local-LLM", "qwen3.5-4b", "L1", "Qwen3.5-4B L1 (gen.)", "llm/results/qwen3_5_4b/layer3/l3_eval_L1_r1.jsonl", "primary"),
    ("qwen_L2", "local-LLM", "qwen3.5-4b", "L2", "Qwen3.5-4B L2 (gen.)", "llm/results/qwen3_5_4b/layer3/l3_eval_L2_r1.jsonl", "primary"),
    ("qwen_L3", "local-LLM", "qwen3.5-4b", "L3", "Qwen3.5-4B L3 (gen.)", "llm/results/qwen3_5_4b/layer3/l3_eval_L3_r1.jsonl", "primary"),
    ("qwen_L4", "local-LLM", "qwen3.5-4b", "L4", "Qwen3.5-4B L4 (gen.)", "llm/results/qwen3_5_4b/layer3/l3_eval_L4_r1.jsonl", "primary"),
    ("intern_L1", "local-decision", "Intern-Decision-4B", "L1", "Intern-Decision L1 @0.5", "gpu/results/intern_decision/layer3/l3_eval_L1_r1.jsonl", "primary"),
    ("intern_L2", "local-decision", "Intern-Decision-4B", "L2", "Intern-Decision L2 @0.5", "gpu/results/intern_decision/layer3/l3_eval_L2_r1.jsonl", "primary"),
    ("intern_L3", "local-decision", "Intern-Decision-4B", "L3", "Intern-Decision L3 @0.5", "gpu/results/intern_decision/layer3/l3_eval_L3_r1.jsonl", "primary"),
    ("intern_l4d", "local-decision", "Intern-Decision-4B", "L4D", "Intern-Decision L4-D", "l4d_ft/results/intern_l4d/layer3/eval_r1_tau05_units.jsonl", "primary"),
    ("intern_th2_L1", "local-decision", "Intern-Decision-4B", "L1", "Intern-Decision L1 (dev thr.)", "gpu/results/intern_decision_th2/layer3/l3_eval_L1_r1.jsonl", "secondary"),
    ("intern_th2_L2", "local-decision", "Intern-Decision-4B", "L2", "Intern-Decision L2 (dev thr.)", "gpu/results/intern_decision_th2/layer3/l3_eval_L2_r1.jsonl", "secondary"),
    ("intern_th2_L3", "local-decision", "Intern-Decision-4B", "L3", "Intern-Decision L3 (dev thr.)", "gpu/results/intern_decision_th2/layer3/l3_eval_L3_r1.jsonl", "secondary"),
    ("intern_l4d_devtau", "local-decision", "Intern-Decision-4B", "L4D", "Intern-Decision L4-D (dev τ 0.18)", "l4d_ft/results/intern_l4d/layer3/eval_r1_units.jsonl", "secondary"),
    ("jev_l4d_devtau", "cloud-decision", "jev-latest (jev-1.14.0)", "L4D", "Jev L4-D (dev τ 0.27)", "l4d_ft/results/jev_l4d/layer3/eval_r1_devtau_units.jsonl", "secondary"),
    ("readout_l4d", "local-decision", "qwen3.5-4b (base read-out)", "L4D", "Qwen3.5-4B read-out L4-D (pre-FT)", "l4d_ft/results/qwen_readout_l4d/layer3/eval_r1_units.jsonl", "primary"),
    ("readout_L1", "local-decision", "qwen3.5-4b (base read-out)", "L1", "Qwen3.5-4B read-out L1 (pre-FT)", "decision_ft/results/qwen_readout_zeroshot/layer3/L1_v1.jsonl", "backup"),
    ("readout_L3", "local-decision", "qwen3.5-4b (base read-out)", "L3", "Qwen3.5-4B read-out L3 (pre-FT)", "decision_ft/results/qwen_readout_zeroshot/layer3/L3_v1.jsonl", "backup"),
    ("lora_L1", "local-FT", "qwen3.5-4b + LoRA (unit label)", "L1", "LoRA L1 (unit-label FT)", "decision_ft/results/decision_ft/layer3/L1_cv_v1.jsonl", "primary"),
    ("lora_L3", "local-FT", "qwen3.5-4b + LoRA (unit label)", "L3", "LoRA L3 (unit-label FT)", "decision_ft/results/decision_ft/layer3/L3_cv_v1.jsonl", "primary"),
    ("lora_l4d", "local-FT", "qwen3.5-4b + LoRA (L4-D facts)", "L4D", "LoRA L4-D (fact FT)", "l4d_ft/results/lora_l4d/layer3/eval_r1_units.jsonl", "primary"),
    ("lora_l4d_opt", "local-FT", "qwen3.5-4b + LoRA (L4-D facts)", "L4D", "LoRA L4-D (opt.)", "l4d_ft/results/lora_l4d_opt/layer3/eval_r1_units.jsonl", "primary"),
    ("vulnllmr", "other-local", "VulnLLM-R-7B", "policy", "VulnLLM-R-7B (policy hint)", "vulnllmr/results/vulnllm_r_7b/layer3/eval_policy_r1.jsonl", "primary"),
    ("linevul", "other-local", "LineVul", None, "LineVul (zero-shot)", "gpu/results/linevul_gpu/layer3/all_v1.jsonl", "backup"),
    ("clang_sa", "static", "clang 23.1.6", None, "Clang SA", "static/results/clang_sa/layer3/full_v1.jsonl", "primary"),
    ("codeql", "static", "codeql 2.27.5", None, "CodeQL (batch50)", "static/results/codeql/layer3/full_batch50.jsonl", "primary"),
    ("infer", "static", "infer 1.3.0", None, "Infer", "static/results/infer/layer3/full_per_file.jsonl", "primary"),
    ("cppcheck", "static", "cppcheck 2.22.0", None, "Cppcheck", "static/results/cppcheck/layer3/full_v1.jsonl", "primary"),
    ("grep_v0", "static", "grep v0", None, "grep v0", "static/results/grep_v0/layer3/full_v1.jsonl", "primary"),
    ("asan_lsan", "dynamic-reference", "ASan+LSan", None, "ASan/LSan (dynamic)", "data/results/asan_lsan/stress/full_v1.jsonl", "primary"),
    ("dynamic_enhanced", "dynamic-reference", "ASan+LSan enhanced", None, "Dynamic enhanced", "data/results/dynamic_enhanced/stress/full_v1.jsonl", "primary"),
]

# strategy x fine-tuning sub-table: row -> column -> method key
STRATEGY_FT = {
    "L1": {"Qwen gen.": "qwen_L1", "Intern-Decision": "intern_L1", "read-out": "readout_L1", "our FT": "lora_L1",
           "Jev (cloud)": "jev_L1"},
    "L3": {"Qwen gen.": "qwen_L3", "Intern-Decision": "intern_L3", "read-out": "readout_L3", "our FT": "lora_L3",
           "Jev (cloud)": "jev_L3"},
    "L4 / L4-D": {"Qwen gen.": "qwen_L4", "Intern-Decision": "intern_l4d", "read-out": "readout_l4d", "our FT": "lora_l4d_opt",
                  "Jev (cloud)": "jev_l4d"},
}

# expected macro-F1 values given by the parent (cross-check, ±0.0015)
# extra paired family-cluster bootstrap deltas (a − b), same resamples as all other CIs
PAIRED_DELTAS = [("lora_l4d_opt", "intern_l4d"), ("intern_l4d", "readout_l4d"),
                 ("jev_l4d", "jev_L3"), ("jev_l4d", "lora_l4d_opt"), ("jev_l4d", "deepseek_L4"), ("jev_l4d", "jev_L1")]
NOTES = [
    "intern_l4d: l4d_ft/results/intern_l4d/FROZEN listed the layer1-dev τ 0.182426 as primary; the parent switched "
    "the primary to τ = 0.5 after seeing the eval results, for consistency with Intern-Decision L1–L3 (calibrated "
    "default 0.5 primary, dev threshold secondary); the switch favours the baseline (.799 vs .373).",
    "intern_l4d_devtau failure: with the low dev τ every exec/release question is answered Yes (Intern's calibrated "
    "p_yes for exec_all/exec_any/rel lie in ~0.45–0.65), so \"the release executes on every path\" is accepted for "
    "dead frees and leak recall collapses to .037; a threshold tuned on Debiased (no dead frees) does not transfer "
    "to DeadFree.",
    "jev_l4d: primary τ = 0.5 fixed by the parent (2026-11-24 19:05) before any Jev L4-D call; dev τ 0.268941 "
    "(layer1 dev, run_decide_l4d.py select rule) is secondary. Same pruned questions as intern_l4d / lora_l4d_opt, "
    "one noul question per request, neutral criteria not refined after the 40-unit pilot "
    "(l4d_ft/results/jev_l4d/FROZEN; analysis/deadfree/REPORT_jev_l4d.md).",
]
CROSS_CHECK = {"deepseek_L1": 0.863, "deepseek_L4": 0.900, "jev_L3": 0.949, "qwen_L1": 0.533,
               "lora_l4d": 0.826, "vulnllmr": 0.471}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def valid_pred(row: dict | None) -> int | None:
    if row is None:
        return None
    p = row.get("pred")
    return p if p in (0, 1) and not isinstance(p, bool) else None


def macro_from_counts(c: np.ndarray) -> np.ndarray:
    """c[..., 0:4] = tp, fp, tn, fn -> macro-F1 (score.py definition; both classes are non-empty here)."""
    tp, fp, tn, fn = c[..., 0], c[..., 1], c[..., 2], c[..., 3]
    with np.errstate(invalid="ignore", divide="ignore"):
        f_leak = np.where(tp > 0, 2 * tp / (2 * tp + fp + fn), 0.0)
        f_ok = np.where(tn > 0, 2 * tn / (2 * tn + fn + fp), 0.0)
    return (f_leak + f_ok) / 2


def ci(samples: np.ndarray) -> list[float]:
    s = np.sort(samples)
    return [float(s[int(.025 * B)]), float(s[int(.975 * B)])]


def r(x, nd=4):
    return None if x is None else round(float(x), nd)


def main() -> None:
    units = [u for u in read_jsonl(UNITS) if u["set"] == "eval"]
    assert len(units) == 2656, len(units)
    uid = [u["unit_id"] for u in units]
    truth = np.array([int(u["truth"]) for u in units])
    families = sorted({u["family"] for u in units})
    fam_index = {f: i for i, f in enumerate(families)}
    fam = np.array([fam_index[u["family"]] for u in units])
    flow = np.array([u["flow_category"] for u in units])
    F = len(families)

    random.seed(SEED)
    W = np.zeros((B, F))
    for b in range(B):
        for f in random.choices(families, k=F):
            W[b, fam_index[f]] += 1

    results: dict[str, dict] = {}
    boots: dict[str, np.ndarray] = {}
    for key, group, model, strategy, label, src, role in METHODS:
        path = JF / src
        row = {"key": key, "group": group, "model": model, "strategy": strategy, "label": label,
               "source": src, "role": role}
        if not path.exists():
            row["status"] = "pending"
            results[key] = row
            continue
        index = {}
        for p in read_jsonl(path):
            index[p["unit_id"]] = p
        pred = [valid_pred(index.get(u)) for u in uid]
        missing = sum(u not in index for u in uid)
        invalid = sum(p is None for p in pred)
        # invalid/missing counts as wrong
        yhat = np.array([(1 - t) if p is None else p for p, t in zip(pred, truth)])
        cell = np.stack([(yhat == 1) & (truth == 1), (yhat == 1) & (truth == 0),
                         (yhat == 0) & (truth == 0), (yhat == 0) & (truth == 1)], axis=1).astype(float)
        per_fam = np.zeros((F, 4))
        np.add.at(per_fam, fam, cell)
        tot = per_fam.sum(0)
        tp, fp, tn, fn = tot
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn)
        f1_leak = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        boots[key] = macro_from_counts(W @ per_fam)
        by_flow = {}
        for fc in FLOWS:
            m = flow == fc
            c = cell[m].sum(0)
            by_flow[fc] = {"n": int(m.sum()), "macro_f1": r(macro_from_counts(c)),
                           "fp": int(c[1]), "fn": int(c[3])}
        row.update({
            "status": "ok", "n": len(uid), "n_pred_rows_eval": len(uid) - missing, "missing": missing,
            "extra_rows": len(set(index) - set(uid)), "invalid": invalid,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "precision_leak": r(prec), "recall_leak": r(rec), "f1_leak": r(f1_leak),
            "macro_f1": r(macro_from_counts(tot)), "macro_f1_ci": [r(x) for x in ci(boots[key])],
            "by_flow": by_flow, "_point": float(macro_from_counts(tot)),
        })
        results[key] = row

    base = "qwen_L1"
    for key, row in results.items():
        if row["status"] != "ok":
            continue
        for ref, tag in (("deepseek_L1", "ds_l1"), ("deepseek_L4", "ds_l4")):
            if results.get(ref, {}).get("status") != "ok":
                continue
            d = row["_point"] - results[ref]["_point"]
            row[f"delta_vs_{tag}"] = r(d)
            row[f"delta_vs_{tag}_ci"] = [r(x) for x in ci(boots[key] - boots[ref])]
            if results.get(base, {}).get("status") == "ok":
                den = results[ref]["_point"] - results[base]["_point"]
                row[f"gap_closed_{tag}"] = r((row["_point"] - results[base]["_point"]) / den, 3)
                gs = (boots[key] - boots[base]) / (boots[ref] - boots[base])
                row[f"gap_closed_{tag}_ci"] = [r(x, 3) for x in ci(gs)]

    pairs = []
    for a, b in PAIRED_DELTAS:
        if results[a]["status"] == "ok" and results[b]["status"] == "ok":
            pairs.append({"a": a, "b": b, "label": f"{results[a]['label']} − {results[b]['label']}",
                          "delta": r(results[a]["_point"] - results[b]["_point"]),
                          "delta_ci": [r(x) for x in ci(boots[a] - boots[b])]})

    checks = []
    for key, want in CROSS_CHECK.items():
        got = results[key].get("_point")
        ok = got is not None and abs(got - want) <= 0.0015
        checks.append({"key": key, "expected": want, "got": r(got), "ok": ok})

    for row in results.values():
        row.pop("_point", None)

    out = {"eval_set": "layer3 (DeadFree) eval", "units_file": "data/build/layer3.jsonl", "n_units": len(uid),
           "n_families": F, "bootstrap": {"B": B, "seed": SEED, "clusters": "family",
                                          "ci": "sorted[int(.025B)], sorted[int(.975B)]",
                                          "resampler": "random.seed(seed); random.choices(sorted families)"},
           "invalid_rule": "missing or null pred counts as wrong (bad->FN, good->FP)",
           "gap_closed": "(mF1_m - mF1_qwen_L1) / (mF1_ref - mF1_qwen_L1)",
           "cross_check": checks, "paired_deltas": pairs, "notes": NOTES, "methods": list(results.values()),
           "strategy_x_ft": {row: {col: k for col, k in cols.items()} for row, cols in STRATEGY_FT.items()}}
    (HERE / "deadfree_quality.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")

    cols = ["key", "group", "model", "strategy", "label", "role", "status", "n", "missing", "invalid",
            "tp", "fp", "tn", "fn", "precision_leak", "recall_leak", "f1_leak", "macro_f1", "macro_f1_lo",
            "macro_f1_hi", "delta_vs_ds_l1", "delta_vs_ds_l1_lo", "delta_vs_ds_l1_hi", "delta_vs_ds_l4",
            "delta_vs_ds_l4_lo", "delta_vs_ds_l4_hi", "gap_closed_ds_l1", "gap_closed_ds_l1_lo",
            "gap_closed_ds_l1_hi", "gap_closed_ds_l4", "gap_closed_ds_l4_lo", "gap_closed_ds_l4_hi", "source"]
    with open(HERE / "deadfree_quality.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for row in results.values():
            flat = {k: row.get(k) for k in cols}
            for name in ("macro_f1", "delta_vs_ds_l1", "delta_vs_ds_l4", "gap_closed_ds_l1", "gap_closed_ds_l4"):
                c = row.get(f"{name}_ci")
                if c:
                    flat[f"{name}_lo"], flat[f"{name}_hi"] = c
            w.writerow(flat)
    with open(HERE / "deadfree_by_flow.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "label", "flow_category", "n", "macro_f1", "fp", "fn"])
        for row in results.values():
            for fc, v in (row.get("by_flow") or {}).items():
                w.writerow([row["key"], row["label"], fc, v["n"], v["macro_f1"], v["fp"], v["fn"]])

    write_md(out, results)
    write_pareto(results)
    bad = [c for c in checks if not c["ok"]]
    print(f"wrote deadfree_quality.{{csv,json,md}}; {sum(r['status'] == 'ok' for r in results.values())} ok, "
          f"{sum(r['status'] == 'pending' for r in results.values())} pending; cross-check "
          f"{'OK' if not bad else 'MISMATCH ' + str(bad)}")


def f3(x):
    return "–" if x is None else f"{x:.3f}"


def fci(c, signed=False):
    if not c:
        return ""
    fmt = "{:+.3f}" if signed else "{:.3f}"
    return f" [{fmt.format(c[0])}, {fmt.format(c[1])}]"


def write_md(out: dict, results: dict) -> None:
    L = ["# DeadFree (layer3) eval quality — all methods", "",
         f"Generated by `analysis/deadfree/make_table.py`. Eval set: {out['n_units']} units "
         f"({out['n_families']} families) of `data/build/layer3.jsonl` (set = eval). Missing/null predictions "
         "count as wrong. 95% CIs: family-cluster bootstrap, 2,000 resamples, seed 20261123 (shared resamples → "
         "paired Δ). Gap closed = (mF1 − mF1[Qwen3.5-4B L1]) / (mF1[ref] − mF1[Qwen3.5-4B L1]). "
         "role: primary = main table, secondary = alternative threshold, backup = appendix only.", "",
         "| group | method | role | n | inv. | P_leak | R_leak | F1_leak | macro-F1 [95% CI] | Δ vs DS L1 [CI] | "
         "Δ vs DS L4 [CI] | gap closed (DS L1) [CI] | gap closed (DS L4) [CI] |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for row in results.values():
        if row["status"] != "ok":
            L.append(f"| {row['group']} | {row['label']} | {row['role']} | pending | | | | | | | | | |")
            continue
        L.append(
            f"| {row['group']} | {row['label']} | {row['role']} | {row['n']} | {row['invalid']} | "
            f"{f3(row['precision_leak'])} | {f3(row['recall_leak'])} | {f3(row['f1_leak'])} | "
            f"{f3(row['macro_f1'])}{fci(row['macro_f1_ci'])} | "
            f"{row['delta_vs_ds_l1']:+.3f}{fci(row['delta_vs_ds_l1_ci'], True)} | "
            f"{row['delta_vs_ds_l4']:+.3f}{fci(row['delta_vs_ds_l4_ci'], True)} | "
            f"{row['gap_closed_ds_l1']:.2f}{fci(row['gap_closed_ds_l1_ci'])} | "
            f"{row['gap_closed_ds_l4']:.2f}{fci(row['gap_closed_ds_l4_ci'])} |")
    L += ["", "## Strategy × fine-tuning (macro-F1 [95% CI])", "",
          "Qwen gen. = Qwen3.5-4B generative (untuned); Intern-Decision = untuned decision model @0.5 "
          "(also L4-D; dev-τ value in brackets); read-out = Qwen3.5-4B base Yes/No read-out (pre-FT; L1/L3 are backup-only); "
          "our FT = Qwen3.5-4B + LoRA (L1/L3 unit-label FT; L4-D fact FT, opt. inference).", "",
          "Jev (cloud) = Jev (TypeSafe System One, jev-latest) @0.5, cloud decision-model reference, not an FT variant "
          "(L4-D: same pruned questions, one noul question per request; dev-τ value in brackets).", "",
          "| strategy | " + " | ".join(next(iter(STRATEGY_FT.values()))) + " |",
          "|---|" + "---|" * len(next(iter(STRATEGY_FT.values())))]
    for srow, cols in STRATEGY_FT.items():
        cells = []
        for k in cols.values():
            m = results[k]
            cells.append("pending" if m["status"] != "ok" else f"{f3(m['macro_f1'])}{fci(m['macro_f1_ci'])}")
            if k == "intern_l4d" and results["intern_l4d_devtau"]["status"] == "ok":
                cells[-1] += f" (dev τ 0.18: {f3(results['intern_l4d_devtau']['macro_f1'])})"
            if k == "jev_l4d" and m["status"] == "ok" and results["jev_l4d_devtau"]["status"] == "ok":
                cells[-1] += f" (dev τ 0.27: {f3(results['jev_l4d_devtau']['macro_f1'])})"
        L.append(f"| {srow} | " + " | ".join(cells) + " |")
    L += ["", "## Paired differences (family-cluster bootstrap, same resamples)", ""]
    for pd in out["paired_deltas"]:
        L.append(f"- {pd['label']}: {pd['delta']:+.3f}{fci(pd['delta_ci'], True)}")
    L += ["", "## Notes", ""] + [f"- {n}" for n in out["notes"]]
    L += ["", "## Per flow category (macro-F1; FP/FN)", "",
          "| method | " + " | ".join(f"{fc} (n={next(r for r in results.values() if r['status'] == 'ok')['by_flow'][fc]['n']})"
                                      for fc in FLOWS) + " |",
          "|---|" + "---|" * len(FLOWS)]
    for row in results.values():
        if row["status"] != "ok":
            continue
        L.append(f"| {row['label']} | " + " | ".join(
            f"{f3(row['by_flow'][fc]['macro_f1'])} ({row['by_flow'][fc]['fp']}/{row['by_flow'][fc]['fn']})"
            for fc in FLOWS) + " |")
    L += ["", "## Cross-check against previously reported numbers", ""]
    for c in out["cross_check"]:
        L.append(f"- {c['key']}: expected {c['expected']:.3f}, got {f3(c['got'])} → {'OK' if c['ok'] else 'MISMATCH'}")
    L += ["", "## Sources (relative to juliet_full/)", ""]
    for row in results.values():
        L.append(f"- `{row['key']}`: `{row['source']}`" + (" (pending)" if row["status"] != "ok" else ""))
    (HERE / "deadfree_quality.md").write_text("\n".join(L) + "\n")


def write_pareto(results: dict) -> None:
    lat_path = HERE / "latency_deadfree.csv"
    if not lat_path.exists():
        return
    points = []
    with open(lat_path) as fh:
        for lat in csv.DictReader(fh):
            q = results.get(lat.get("quality_key") or "", {})
            median = float(lat["median_s"]) if lat.get("median_s") not in (None, "", "pending") else None
            points.append({
                "method": lat["method"], "label": q.get("label") or lat["method"], "group": lat.get("group"),
                "model": lat.get("model"), "strategy": lat.get("strategy"), "quality_key": lat.get("quality_key"),
                "macro_f1": q.get("macro_f1"), "macro_f1_ci": q.get("macro_f1_ci"),
                "median_s": median,
                "p90_s": float(lat["p90_s"]) if lat.get("p90_s") not in (None, "", "pending") else None,
                "mean_s": float(lat["mean_s"]) if lat.get("mean_s") not in (None, "", "pending") else None,
                "hardware": lat.get("hardware"), "kernel": lat.get("kernel"),
                "latency_role": lat.get("role", "primary"), "quality_role": q.get("role"), "status":
                    "ok" if median is not None and q.get("macro_f1") is not None else "pending",
            })
    ok = sorted((p for p in points if p["status"] == "ok" and p["latency_role"] == "primary"
                 and p["quality_role"] == "primary"), key=lambda p: (p["median_s"], -p["macro_f1"]))
    best = -1.0
    for p in ok:
        p["pareto"] = p["macro_f1"] > best
        best = max(best, p["macro_f1"])
    (HERE / "deadfree_pareto.json").write_text(json.dumps(
        {"x": "c1 end-to-end median latency (s), latency300 DeadFree units, from dell",
         "y": "DeadFree eval macro-F1 (2,656 units)",
          "pareto_rule": "frontier over points with latency_role and quality_role primary", "points": points}, indent=1, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()

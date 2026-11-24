"""Markdown tables for REPORT_stage1.md from build/scores/*.json, FROZEN, build/select/*.json and the latency meta.

    python3 report_tables.py > build/report_tables.md
Structure-only baseline (all p_yes = 1.0, v1 rules, tau 0.5; all eval units) from analysis/l4d_const/RESULT.txt.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
LAYERS = ("layer1", "layer3", "placebo", "original")
METHODS = ("lora_l4d", "qwen_readout_l4d")


def f3(x) -> str:
    return "–" if x is None else f"{x:.3f}"


def ci(c) -> str:
    return "–" if not c or c[0] is None else f"[{c[0]:.3f}, {c[1]:.3f}]"


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def const_baseline() -> dict:
    out = {}
    for line in (JULIET_FULL / "analysis/l4d_const/RESULT.txt").read_text().splitlines():
        m = re.match(r"(\w+)\s+.*macro-F1 ([\d.]+)", line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def main() -> None:
    const = const_baseline()
    scores = {(m, l): load(HERE / "results/scores" / f"{m}_{l}_eval_r1.json") for m in METHODS for l in LAYERS}
    print("## Unit level, all eval units (analysis/score.py --set eval)\n")
    print("| layer | method | n | macro-F1 [95% CI] | P(leak) | R(leak) | specificity | invalid | latency_s median (model+derive) |")
    print("|---|---|---|---|---|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            s = scores[(m, l)]
            if s is None:
                print(f"| {l} | {m} | missing | | | | | | |")
                continue
            a = s["all_eval"]
            print(f"| {l} | {m} | {a['n']} | {f3(a['macro_f1'])} {ci(a['ci95_macro_f1'])} | {f3(a['precision_leak'])} | "
                  f"{f3(a['recall_leak'])} | {f3(a['specificity'])} | {a['invalid']} | {f3(a['latency_median_s'])} |")
        print(f"| {l} | structure-only (all Yes, τ 0.5) | all eval | {f3(const.get(l))} | | | | | |")
    print("\n## Same units as the DeepSeek reference (layer1: full eval 2,656; others: nested25 eval 664)\n")
    print("| layer | system | macro-F1 [95% CI] | P(leak) | R(leak) | Δ model − this (paired family bootstrap) [95% CI] |")
    print("|---|---|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            s = scores[(m, l)]
            if s is None:
                continue
            r = s["ref_units"]
            print(f"| {l} | **{m}** ({r['which']}, n={r['n']}) | {f3(r['macro_f1'])} {ci(r['ci95_macro_f1'])} | "
                  f"{f3(r['precision_leak'])} | {f3(r['recall_leak'])} | |")
        s = scores[("lora_l4d", l)] or scores[("qwen_readout_l4d", l)]
        if s is None:
            continue
        for strat, d in s["deepseek"].items():
            deltas = []
            for m in METHODS:
                sm = scores[(m, l)]
                if sm is not None:
                    p = sm["deepseek"][strat]["paired_delta_model_minus_ref"]
                    deltas.append(f"{m}: {p['delta_macro_f1']:+.3f} {ci(p['ci95'])}")
            best = " (best DeepSeek)" if strat == s["deepseek_best_strategy"] else ""
            print(f"| {l} | DeepSeek {strat}{best} | {f3(d['macro_f1'])} {ci(d['ci95_macro_f1'])} | "
                  f"{f3(d['precision_leak'])} | {f3(d['recall_leak'])} | {'; '.join(deltas)} |")
    print("\n## Contract §6 criteria (reference DeepSeek L1, same units)\n")
    print("| layer | method | near-LLM: mF1 ≥ ref−0.02 | equivalent: CI low of Δ ≥ −0.02 |")
    print("|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            s = scores[(m, l)]
            if s is None:
                continue
            c = s["criteria"]
            n, e = c["near_llm"], c["equivalent_within_2pt"]
            print(f"| {l} | {m} | {f3(n['value'])} vs {f3(n['threshold'])} → {'PASS' if n['pass'] else 'FAIL'} | "
                  f"{f3(e['value'])} → {'PASS' if e['pass'] else 'FAIL'} |")
    print("\n## Gain over the structure-only baseline (all eval units)\n")
    print("| layer | lora_l4d − const | qwen_readout_l4d − const |")
    print("|---|---|---|")
    for l in LAYERS:
        cells = []
        for m in METHODS:
            s = scores[(m, l)]
            cells.append("–" if s is None or l not in const else f"{s['all_eval']['macro_f1'] - const[l]:+.3f}")
        print(f"| {l} | {' | '.join(cells)} |")
    print("\n## Per-fold macro-F1 (all eval units of each fold; lora_l4d = that fold's own model)\n")
    print("| layer | method | fold 0 | fold 1 | fold 2 |")
    print("|---|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            s = scores[(m, l)]
            if s is None:
                continue
            pf = s["per_fold"]
            print(f"| {l} | {m} | " + " | ".join(f"{f3(pf[k]['macro_f1'])} (n={pf[k]['n']})" for k in ("0", "1", "2"))
                  + " |")
    print("\n## By flow category (all eval units)\n")
    print("| layer | method | flow_category | n | macro-F1 | accuracy |")
    print("|---|---|---|---|---|---|")
    for l in ("layer1", "layer3"):
        for m in METHODS:
            s = scores[(m, l)]
            if s is None:
                continue
            for cat, r in s["score_py_all_eval"]["by_flow_category"].items():
                print(f"| {l} | {m} | {cat} | {r['n']} | {f3(r.get('macro_f1'))} | {f3(r.get('accuracy'))} |")
    print("\n## Question level, eval questions, all fold models pooled (threshold p_yes ≥ 0.5; gold null excluded)\n")
    print("| layer | method | qtype | n | n_yes | accuracy | AUROC |")
    print("|---|---|---|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            fs = load(HERE / "results/scores" / f"{m}_{l}_eval_r1_facts.json")
            if fs is None:
                continue
            for k, r in {**fs["pooled_tau_0.5"], **fs["splits_tau_0.5"]}.items():
                if r.get("n"):
                    print(f"| {l} | {m} | {k} | {r['n']} | {r['n_yes']} | {f3(r['accuracy'])} | {f3(r['auroc'])} |")
    print("\n## Question level per fold model (l4d/score_facts.py rows, eval questions, p_yes ≥ 0.5)\n")
    print("| layer | model | qtype | n | n_yes | accuracy | AUROC | majority |")
    print("|---|---|---|---|---|---|---|---|")
    for l in LAYERS:
        for m in METHODS:
            fs = load(HERE / "results/scores" / f"{m}_{l}_eval_r1_facts.json")
            if fs is None:
                continue
            for r in fs["score_facts"]["rows"]:
                if r.get("set") not in (None, "eval"):
                    continue
                print(f"| {l} | {r['model']} | {r['qtype']} | {r['n']} | {r['n_yes']} | {f3(r['accuracy'])} | "
                      f"{f3(r['auroc'])} | {f3(r['majority_baseline'])} |")


if __name__ == "__main__":
    main()

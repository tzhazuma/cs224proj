#!/usr/bin/env python3
"""Stage-2e analysis (parent brief 2026-11-24 06:10 PST): DeepSeek layer3 (DeadFree) on the full eval set.

1 merge (originals untouched): results/deepseek_flash/layer3/l3_eval_L{1,2,3}_r1.jsonl = l3_n25 ∪ l3_apirest ∪
  l3_rest, l3_eval_L4_r1.jsonl = l3_n25_L4 ∪ l3_rest75_L4, each with a .meta.json (components, counts, prompt
  hashes, models returned, ledger spend); checks 2,656 unique eval unit_ids, no duplicates.
2 analysis/score.py per strategy (--set eval, bootstrap 2000, seed 20261123) -> results/scores/deepseek_flash/;
  paired Δ between strategies (L2/L3/L4 − L1, L4 − L3) and vs layer1 eval_L*_r1 with analysis/robustness.py
  (family-cluster bootstrap 2000, seed 20261123) + McNemar (score.mcnemar, exploratory); FP/FN by good_kind
  and flow_category; consistency on nested25 / api_subset vs the stage-2c files; sampling check (subset part vs
  the rest, independent family bootstraps).
3 comparison rows on the same full eval layer3 from existing predictions (no new runs).
Writes results/stage2e/analysis.json and results/stage2e/tables.md.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
import sys
from collections import Counter
from pathlib import Path

LLM_DIR = Path(__file__).resolve().parent
JF = LLM_DIR.parent
sys.path.insert(0, str(JF / "analysis"))
from robustness import robustness  # noqa: E402
from score import family_bootstrap, mcnemar, score, select_units, valid_pred  # noqa: E402

UNITS3 = JF / "data" / "build" / "layer3.jsonl"
SUBSETS = JF / "data" / "build" / "subsets.json"
DS = LLM_DIR / "results" / "deepseek_flash"
OUT = LLM_DIR / "results" / "stage2e"
SEED, ITER = 20261123, 2000
COMPONENTS = {s: [f"l3_n25_{s}_r1", f"l3_apirest_{s}_r1", f"l3_rest_{s}_r1"] for s in ("L1", "L2", "L3")}
COMPONENTS["L4"] = ["l3_n25_L4_r1", "l3_rest75_L4_r1"]
STRATS = ("L1", "L2", "L3", "L4")
THRESHOLDS = json.loads((LLM_DIR / "results" / "jev_thresholds.json").read_text())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merge(strategy: str, eval_ids: set[str]) -> dict:
    rows, comps = [], []
    for run_id in COMPONENTS[strategy]:
        path = DS / "layer3" / f"{run_id}.jsonl"
        part = load_jsonl(path)
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        rows += part
        comps.append({"run_id": run_id, "n": len(part), "sha256": sha256(path), "status_counts": meta["status_counts"],
                      "prompt_hash": meta["prompt_hash"], "models_returned": meta.get("models_returned"),
                      "cost_total": meta["cost_total"], "subset": meta.get("subset"),
                      "unit_ids_file": (meta.get("selection") or {}).get("unit_ids_file"),
                      "evidence_sha256": meta.get("evidence_sha256"), "start_utc": meta.get("start_utc"),
                      "usage_totals": meta.get("usage_totals")})
    ids = [r["unit_id"] for r in rows]
    dup = [u for u, k in Counter(ids).items() if k > 1]
    hashes = {c["prompt_hash"] for c in comps}
    assert not dup, f"{strategy}: duplicate unit_ids {dup[:5]}"
    assert set(ids) == eval_ids, f"{strategy}: {len(set(ids))} ids, missing {len(eval_ids - set(ids))}"
    assert len(hashes) == 1, f"{strategy}: prompt hashes differ {hashes}"
    out = DS / "layer3" / f"l3_eval_{strategy}_r1.jsonl"
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    first = json.loads((DS / "layer3" / f"{comps[0]['run_id']}.meta.json").read_text())
    models = Counter()
    for c in comps:
        models.update(c["models_returned"] or {})
    status = Counter()
    for c in comps:
        status.update(c["status_counts"])
    cost = round(sum(c["cost_total"] for c in comps), 8)
    meta = dict(first)
    meta.update({"run_id": f"l3_eval_{strategy}_r1", "merged": True, "subset": None, "n_units": len(rows),
                 "components": comps, "status_counts": dict(status), "models_returned": dict(models),
                 "cost_total": cost, "cost_per_call": cost / len(rows), "n_unique_unit_ids": len(set(ids)),
                 "duplicates": 0, "invalid": status.get("invalid", 0), "error": status.get("error", 0),
                 "selection": {"merged_from": [c["run_id"] for c in comps]},
                 "note": "stage-2e merge (stage2e_analysis.py) of the component runs; the components are unchanged"})
    for key in ("wall_s", "balance_before", "balance_after", "loadavg_start", "loadavg_end", "peak_pause_s"):
        meta.pop(key, None)
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    return meta


def thresholded(rows: list[dict], thr: float) -> list[dict]:
    return [dict(r, pred=None if r.get("score") is None else int(r["score"] >= thr)) for r in rows]


def brief(rep: dict) -> dict:
    e = rep["end_to_end"]
    ci = (rep.get("bootstrap") or {}).get("ci95", {}).get("macro_f1")
    return {"n": e["n"], "macro_f1": e["macro_f1"], "ci": ci, "f1_leak": e["f1_leak"], "p": e["precision_leak"],
            "r": e["recall_leak"], "fp": e["fp"], "fn": e["fn"], "invalid": e["invalid"]}


def part_bootstrap_diff(units_a: list[dict], rows: dict[str, dict], units_b: list[dict]) -> dict:
    """macro-F1(a) − macro-F1(b) with independent family bootstraps of the two disjoint unit sets."""
    def recs(us):
        return [(u["family"], int(u["truth"]), valid_pred(rows.get(u["unit_id"]))) for u in us]
    ra, rb = recs(units_a), recs(units_b)
    from score import confusion, metrics_from_counts
    point = (metrics_from_counts(confusion((t, p) for _, t, p in ra))["macro_f1"]
             - metrics_from_counts(confusion((t, p) for _, t, p in rb))["macro_f1"])
    rng = random.Random(SEED)

    def sample(rs):
        fams: dict[str, list] = {}
        for f, t, p in rs:
            fams.setdefault(f, []).append((t, p))
        keys = sorted(fams)
        pick = rng.choices(keys, k=len(keys))
        return metrics_from_counts(confusion(x for k in pick for x in fams[k]))["macro_f1"]
    diffs = sorted(sample(ra) - sample(rb) for _ in range(ITER))
    return {"delta": point, "ci95": [diffs[int(0.025 * ITER)], diffs[int(0.975 * ITER) - 1]]}


def comparison_files() -> list[tuple[str, str, Path, float | None]]:
    """(method, strategy, prediction file on layer3, threshold or None) for existing full-eval runs."""
    gpu, dft, st = JF / "gpu" / "results", JF / "decision_ft" / "results", JF / "static" / "results"
    out = []
    for s in ("L1", "L2", "L3"):
        out.append(("jev @0.5", s, LLM_DIR / "results" / "jev" / "layer3" / f"l3_eval_{s}_r1.jsonl", None))
        out.append((f"jev @{THRESHOLDS[s]['threshold']:.3f} (frozen dev thr)", s,
                    LLM_DIR / "results" / "jev" / "layer3" / f"l3_eval_{s}_r1.jsonl", THRESHOLDS[s]["threshold"]))
    for s in STRATS:
        out.append(("qwen3_5_4b", s, LLM_DIR / "results" / "qwen3_5_4b" / "layer3" / f"l3_eval_{s}_r1.jsonl", None))
    for s in ("L1", "L2", "L3"):
        out.append(("intern_decision @0.5", s, gpu / "intern_decision" / "layer3" / f"l3_eval_{s}_r1.jsonl", None))
        out.append(("intern_decision_th2 (dev thr)", s, gpu / "intern_decision_th2" / "layer3" / f"l3_eval_{s}_r1.jsonl",
                    None))
    for s in ("L1", "L3"):
        out.append(("decision_ft (old LoRA, cv)", s, dft / "decision_ft" / "layer3" / f"{s}_cv_v1.jsonl", None))
    out.append(("linevul_gpu", "-", gpu / "linevul_gpu" / "layer3" / "all_v1.jsonl", None))
    out.append(("clang_sa", "-", st / "clang_sa" / "layer3" / "full_v1.jsonl", None))
    out.append(("codeql", "-", st / "codeql" / "layer3" / "full_batch50.jsonl", None))
    out.append(("infer", "-", st / "infer" / "layer3" / "full_per_file.jsonl", None))
    return out


def fmt(x: float | None, signed: bool = False) -> str:
    if x is None:
        return "–"
    return f"{x:+.3f}" if signed else f"{x:.3f}"


def row_line(name: str, s: str, b: dict) -> str:
    ci = f" [{b['ci'][0]:.3f}, {b['ci'][1]:.3f}]" if b.get("ci") else ""
    return (f"| {name} | {s} | {b['n']} | {fmt(b['macro_f1'])}{ci} | {fmt(b['f1_leak'])} | {fmt(b['p'])} | "
            f"{fmt(b['r'])} | {b['fp']}/{b['fn']} | {b['invalid']} |")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    units3 = load_jsonl(UNITS3)
    eval3 = select_units(units3, "eval", None, SUBSETS)
    eval_ids = {u["unit_id"] for u in eval3}
    by_id = {u["unit_id"]: u for u in eval3}
    result: dict = {"seed": SEED, "iterations": ITER, "merged": {}, "scores": {}, "paired": [], "robustness": [],
                    "consistency": [], "sampling": [], "comparison": []}
    merged_rows = {}
    for s in STRATS:
        meta = merge(s, eval_ids)
        result["merged"][s] = {k: meta[k] for k in ("n_units", "n_unique_unit_ids", "duplicates", "invalid", "error",
                                                    "status_counts", "prompt_hash", "models_returned", "cost_total")}
        result["merged"][s]["components"] = [{k: c[k] for k in ("run_id", "n", "cost_total", "prompt_hash")}
                                             for c in meta["components"]]
        pred = DS / "layer3" / f"l3_eval_{s}_r1.jsonl"
        out = LLM_DIR / "results" / "scores" / "deepseek_flash" / f"l3_eval_{s}_r1.json"
        subprocess.run([sys.executable, str(JF / "analysis" / "score.py"), "--pred", str(pred), "--units", str(UNITS3),
                        "--set", "eval", "--bootstrap", str(ITER), "--seed", str(SEED), "--out", str(out)],
                       check=True, capture_output=True, cwd=JF)
        rep = json.loads(out.read_text())
        merged_rows[s] = load_jsonl(pred)
        result["scores"][s] = {"all": brief(rep),
                               "by_good_kind": {k: {"n": v["n"], "fp": v["fp"], "specificity": v["specificity"]}
                                                for k, v in rep["by_good_kind"].items()},
                               "by_flow_category": {k: {"n": v["n"], "fp": v["fp"], "fn": v["fn"],
                                                        "macro_f1": v["macro_f1"]}
                                                    for k, v in rep["by_flow_category"].items()},
                               "by_mechanism": {k: {"n": v["n"], "fp": v["fp"], "fn": v["fn"]}
                                                for k, v in rep["by_mechanism"].items()}}
    # paired Δ between strategies
    for a, b in (("L1", "L2"), ("L1", "L3"), ("L1", "L4"), ("L3", "L4")):
        rep = robustness(eval3, merged_rows[a], merged_rows[b], None, ITER, SEED, by=())
        ci = rep["bootstrap"]["ci95"]
        result["paired"].append({"from": a, "to": b, "delta_macro_f1": rep["stats"]["delta_stress.macro_f1"],
                                 "ci95": ci["delta_stress.macro_f1"], "delta_f1_leak": rep["stats"]["delta_stress.f1_leak"],
                                 "ci95_f1_leak": ci["delta_stress.f1_leak"],
                                 "mcnemar": mcnemar(eval3, merged_rows[a], merged_rows[b])})
    # robustness vs layer1 full eval (and placebo-adjusted where a placebo run covers all eval; DS placebo = n25 only)
    eval1 = select_units(load_jsonl(JF / "data" / "build" / "layer1.jsonl"), "eval", None, SUBSETS)
    for s in STRATS:
        base = load_jsonl(DS / "layer1" / f"eval_{s}_r1.jsonl")
        rep = robustness(eval1, base, merged_rows[s], None, ITER, SEED, by=())
        st, ci = rep["stats"], rep["bootstrap"]["ci95"]
        result["robustness"].append({"strategy": s, "layer1_macro_f1": st["base.macro_f1"],
                                     "layer3_macro_f1": st["stress.macro_f1"],
                                     "delta_macro_f1": st["delta_stress.macro_f1"], "ci95": ci["delta_stress.macro_f1"],
                                     "delta_f1_leak": st["delta_stress.f1_leak"], "ci95_f1_leak": ci["delta_stress.f1_leak"],
                                     "bad_right_to_wrong": st["stress.bad.right_to_wrong"],
                                     "good_right_to_wrong": st["stress.good.right_to_wrong"],
                                     "good_wrong_to_right": st["stress.good.wrong_to_right"],
                                     "mcnemar": mcnemar(eval3, base, merged_rows[s])})
        (LLM_DIR / "results" / "robustness" / f"deepseek_flash_{s}_layer1_to_layer3_eval.json").write_text(
            json.dumps(rep, indent=1) + "\n")
    # consistency with stage-2c subset numbers, and sampling check
    for s in STRATS:
        for subset in ("nested25", "api_subset"):
            if s == "L4" and subset == "api_subset":
                continue
            us = select_units(units3, "eval", subset, SUBSETS)
            new = score(us, merged_rows[s], bootstrap=0)["end_to_end"]
            old_rows = load_jsonl(DS / "layer3" / f"l3_n25_{s}_r1.jsonl")
            if subset == "api_subset":
                old_rows += load_jsonl(DS / "layer3" / f"l3_apirest_{s}_r1.jsonl")
            old = score(us, old_rows, bootstrap=0)["end_to_end"]
            keys = ("tp", "fp", "tn", "fn", "invalid")
            entry = {"strategy": s, "subset": subset, "n": len(us), "macro_f1_merged": new["macro_f1"],
                     "macro_f1_stage2c": old["macro_f1"], "identical": all(new[k] == old[k] for k in keys)}
            if subset == "nested25":
                old_score = json.loads((LLM_DIR / "results" / "scores" / "deepseek_flash" / f"l3_n25_{s}_r1.json")
                                       .read_text())["end_to_end"]
                entry["identical_to_stage2c_score_file"] = all(new[k] == old_score[k] for k in keys)
            result["consistency"].append(entry)
        subset = "nested25" if s == "L4" else "api_subset"
        sub_ids = {u["unit_id"] for u in select_units(units3, "eval", subset, SUBSETS)}
        part_in = [u for u in eval3 if u["unit_id"] in sub_ids]
        part_out = [u for u in eval3 if u["unit_id"] not in sub_ids]
        index = {r["unit_id"]: r for r in merged_rows[s]}
        b_in, b_out = brief(score(part_in, merged_rows[s], ITER, SEED)), brief(score(part_out, merged_rows[s], ITER, SEED))
        result["sampling"].append({"strategy": s, "subset": subset, "in": b_in, "rest": b_out,
                                   "subset_minus_rest": part_bootstrap_diff(part_in, index, part_out)})
    # comparison rows
    for method, s, path, thr in comparison_files():
        rows = load_jsonl(path)
        if thr is not None:
            rows = thresholded(rows, thr)
        rep = score(eval3, rows, ITER, SEED)
        result["comparison"].append({"method": method, "strategy": s, "file": str(path.relative_to(JF)),
                                     **brief(rep), "status_counts": rep["status_counts"],
                                     "extra_pred_lines": rep["extra_pred_lines"]})
    (OUT / "analysis.json").write_text(json.dumps(result, indent=1) + "\n")
    (OUT / "tables.md").write_text(tables(result, by_id) + "\n")
    print(f"wrote {OUT / 'analysis.json'} and {OUT / 'tables.md'}")
    return 0


def tables(r: dict, by_id: dict) -> str:
    hdr = "| method | strategy | n | macro-F1 [95% CI] | F1 leak | P | R | FP/FN | invalid |\n|---|---|---|---|---|---|---|---|---|"
    out = ["### DeepSeek layer3 (DeadFree), full eval (merged)", "",
           "| strategy | components (n, CNY) | invalid | models returned | prompt hash |", "|---|---|---|---|---|"]
    for s, m in r["merged"].items():
        comps = ", ".join(f"{c['run_id']} ({c['n']}, {c['cost_total']:.4f})" for c in m["components"])
        out.append(f"| {s} | {comps} | {m['invalid']} | {m['models_returned']} | {m['prompt_hash'][:16]} |")
    out += ["", hdr] + [row_line("deepseek_flash", s, v["all"]) for s, v in r["scores"].items()]
    kinds = sorted({k for v in r["scores"].values() for k in v["by_good_kind"]})
    flows = sorted({k for v in r["scores"].values() for k in v["by_flow_category"]})
    out += ["", "FP by good_kind (FP/goods) and FP/FN by flow_category:", "",
            "| strategy | " + " | ".join(f"FP {k}" for k in kinds) + " | " + " | ".join(f"FP/FN {f}" for f in flows) + " |",
            "|---|" + "---|" * (len(kinds) + len(flows))]
    for s, v in r["scores"].items():
        gk = [f"{v['by_good_kind'][k]['fp']}/{v['by_good_kind'][k]['n']}" if k in v["by_good_kind"] else "–" for k in kinds]
        fl = [f"{v['by_flow_category'][f]['fp']}/{v['by_flow_category'][f]['fn']}" for f in flows]
        out.append(f"| {s} | " + " | ".join(gk + fl) + " |")
    out += ["", "### Paired strategy differences on full eval layer3 (exploratory)", "",
            "| from → to | Δ macro-F1 [95% CI] | Δ F1 leak [CI] | McNemar (from-only right / to-only right, p) |",
            "|---|---|---|---|"]
    for p in r["paired"]:
        mc = p["mcnemar"]
        out.append(f"| {p['from']} → {p['to']} | {p['delta_macro_f1']:+.3f} [{p['ci95'][0]:+.3f}, {p['ci95'][1]:+.3f}] | "
                   f"{p['delta_f1_leak']:+.3f} [{p['ci95_f1_leak'][0]:+.3f}, {p['ci95_f1_leak'][1]:+.3f}] | "
                   f"{mc['a_only_right']}/{mc['b_only_right']}, p={mc['p_value']:.2g} |")
    out += ["", "### Robustness: layer1 eval_L*_r1 → layer3 full eval (paired on 2,656 unit_ids)", "",
            "| strategy | layer1 mF1 | layer3 mF1 | Δ macro-F1 [95% CI] | Δ F1 leak [CI] | bad→NL | good→L | good L→NL | "
            "McNemar (l1-only right / l3-only right, p) |", "|---|---|---|---|---|---|---|---|---|"]
    for p in r["robustness"]:
        mc = p["mcnemar"]
        out.append(f"| {p['strategy']} | {p['layer1_macro_f1']:.3f} | {p['layer3_macro_f1']:.3f} | "
                   f"{p['delta_macro_f1']:+.3f} [{p['ci95'][0]:+.3f}, {p['ci95'][1]:+.3f}] | "
                   f"{p['delta_f1_leak']:+.3f} [{p['ci95_f1_leak'][0]:+.3f}, {p['ci95_f1_leak'][1]:+.3f}] | "
                   f"{p['bad_right_to_wrong']:.3f} | {p['good_right_to_wrong']:.3f} | {p['good_wrong_to_right']:.3f} | "
                   f"{mc['a_only_right']}/{mc['b_only_right']}, p={mc['p_value']:.2g} |")
    out += ["", "### Consistency: merged file on the stage-2c subsets", "",
            "| strategy | subset | n | mF1 merged | mF1 stage 2c | identical confusion |", "|---|---|---|---|---|---|"]
    for c in r["consistency"]:
        same = c["identical"] and c.get("identical_to_stage2c_score_file", True)
        out.append(f"| {c['strategy']} | {c['subset']} | {c['n']} | {c['macro_f1_merged']:.3f} | "
                   f"{c['macro_f1_stage2c']:.3f} | {'yes' if same else 'NO'} |")
    out += ["", "### Sampling check: subset units vs the rest (same merged predictions)", "",
            "| strategy | subset | subset mF1 [CI] (FP/FN) | rest mF1 [CI] (FP/FN) | subset − rest [95% CI] |",
            "|---|---|---|---|---|"]
    for c in r["sampling"]:
        a, b, d = c["in"], c["rest"], c["subset_minus_rest"]
        out.append(f"| {c['strategy']} | {c['subset']} ({a['n']}) vs rest ({b['n']}) | {a['macro_f1']:.3f} "
                   f"[{a['ci'][0]:.3f}, {a['ci'][1]:.3f}] ({a['fp']}/{a['fn']}) | {b['macro_f1']:.3f} "
                   f"[{b['ci'][0]:.3f}, {b['ci'][1]:.3f}] ({b['fp']}/{b['fn']}) | {d['delta']:+.3f} "
                   f"[{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}] |")
    out += ["", "### All methods on the same full eval layer3 (2,656 units; existing predictions, rescored with "
            f"analysis/score.py, bootstrap {r['iterations']} seed {r['seed']})", "", hdr]
    out += [row_line("deepseek_flash", s, v["all"]) for s, v in r["scores"].items()]
    out += [row_line(c["method"], c["strategy"], c) for c in r["comparison"]]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())

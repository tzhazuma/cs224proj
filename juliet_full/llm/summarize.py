#!/usr/bin/env python3
"""Build results/SUMMARY.md from results/scores/<method>/<run_id>.json (analysis/score.py reports) and run metas.

Adds what score.py does not compute:
- AUROC from the prediction `score` (P(leak); Jev probability, DeepSeek confidence mapped to P(leak)),
  invalid units excluded (count shown separately).
- Jev secondary threshold: per strategy, the threshold maximising macro-F1 on the full-dev run dev_<L>_r1
  (candidates = midpoints between consecutive distinct dev scores plus 0.5; ties -> closest to 0.5). It is
  written to results/jev_thresholds.json and applied to every Jev eval run (invalid counted wrong, as in
  score.py). The primary threshold stays 0.5 (pre-registered).
- Repeat agreement: share of units with identical pred between repeats of the same strategy.
- L4 fact quality: strict parse, grounded-fact share, invalid/error counts from the per-unit `extra`.
- Robustness (analysis/robustness.py, imported): layer1 vs layer3 (stress) on the paired unit_ids, with the
  placebo layer as control (adjusted = stress Δ minus placebo Δ), and original Juliet vs layer1; Jev also at
  the frozen secondary thresholds (results/jev_thresholds.json, never re-selected on other layers). JSON
  reports in results/robustness/. Strongest flips: units turning right→wrong from layer1 to layer3 in the
  most strategies of a method.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR  # noqa: E402

sys.path.insert(0, str(LLM_DIR.parent / "analysis"))
from robustness import robustness  # noqa: E402
from score import select_units  # noqa: E402

JF = LLM_DIR.parent
RESULTS = LLM_DIR / "results"
UNITS = JF / "data" / "build" / "layer1.jsonl"
SUBSETS_FILE = JF / "data" / "build" / "subsets.json"
LAYER_ORDER = {"layer1": 0, "layer3": 1, "placebo": 2, "original": 3}
FULL_EVAL_METHODS = ("jev", "qwen3_5_4b")  # their layer3/placebo/original runs cover all eval units
THRESHOLDS = RESULTS / "jev_thresholds.json"
ROBUSTNESS_BOOTSTRAP = 1000
FLOWS = ["02-22", "31-45", "51-68", "71-84"]
MECHS = ["c_alloc", "cpp_new", "realloc_fail", "destructor"]
KINDS = ["G2B", "B2G", "other"]


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def auroc(pairs: list[tuple[float, int]]) -> float | None:
    pos = sum(t for _, t in pairs)
    neg = len(pairs) - pos
    if not pos or not neg:
        return None
    pairs = sorted(pairs)
    rank_sum, i = 0.0, 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2
        rank_sum += avg_rank * sum(t for _, t in pairs[i:j])
        i = j
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


def macro_f1(rows: list[dict], truth: dict[str, int], threshold: float) -> float:
    tp = fp = tn = fn = 0
    for r in rows:
        t = truth[r["unit_id"]]
        p = None if r["score"] is None else int(r["score"] >= threshold)
        if p is None:
            p = 1 - t
        tp += p == 1 and t == 1
        fp += p == 1 and t == 0
        tn += p == 0 and t == 0
        fn += p == 0 and t == 1
    f_pos = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    f_neg = 2 * tn / (2 * tn + fn + fp) if tn else 0.0
    return (f_pos + f_neg) / 2


def best_threshold(rows: list[dict], truth: dict[str, int]) -> tuple[float, float]:
    scores = sorted({r["score"] for r in rows if r["score"] is not None})
    cands = {0.5} | {(a + b) / 2 for a, b in zip(scores, scores[1:])}
    best = max(cands, key=lambda c: (round(macro_f1(rows, truth, c), 12), -abs(c - 0.5)))
    return best, macro_f1(rows, truth, best)


def f3(x: float | None) -> str:
    return "–" if x is None else f"{x:.3f}"


def thresholded(rows: list[dict], threshold: float) -> list[dict]:
    """Jev rows re-labelled at another threshold (rows without a score keep their pred/status)."""
    return [r if r["score"] is None else {**r, "pred": int(r["score"] >= threshold)} for r in rows]


def effective_pred(row: dict | None, t: int) -> int:
    """score.py convention: a missing or invalid prediction is the wrong verdict."""
    if row is None or row.get("status") != "ok" or row.get("pred") not in (0, 1):
        return 1 - t
    return row["pred"]


def confusion_metrics(rows: list[dict], truth: dict[str, int]) -> dict[str, float | int]:
    tp = fp = tn = fn = 0
    for r in rows:
        t = truth[r["unit_id"]]
        p = effective_pred(r, t)
        tp += p == 1 and t == 1
        fp += p == 1 and t == 0
        tn += p == 0 and t == 0
        fn += p == 0 and t == 1
    f_pos = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    f_neg = 2 * tn / (2 * tn + fn + fp) if tn else 0.0
    return {"precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
            "f1": f_pos, "macro_f1": (f_pos + f_neg) / 2, "fp": fp, "fn": fn}


def load_runs() -> list[dict]:
    runs = []
    for score_path in sorted((RESULTS / "scores").glob("*/*.json")):
        rep = json.loads(score_path.read_text())
        pred_path = JF / rep["inputs"]["pred"]
        meta = json.loads(pred_path.with_suffix(".meta.json").read_text())
        runs.append({"method": score_path.parent.name, "run_id": score_path.stem, "layer": meta["layer"],
                     "meta": meta, "rep": rep, "rows": load_jsonl(pred_path), "subset": rep["inputs"].get("subset")})
    runs.sort(key=lambda r: (r["method"], LAYER_ORDER.get(r["layer"], 9), r["run_id"]))
    return runs


def jev_thresholds(runs: list[dict], truth: dict[str, int]) -> dict[str, dict]:
    """Frozen once written: chosen on the layer-1 full-dev runs dev_<L>_r1, never re-selected."""
    if THRESHOLDS.exists():
        return json.loads(THRESHOLDS.read_text())
    thresholds = {}
    for run in runs:
        if run["method"] == "jev" and run["layer"] == "layer1" and run["run_id"].startswith("dev_"):
            thr, mf = best_threshold(run["rows"], truth)
            thresholds[run["meta"]["strategy"]] = {"threshold": thr, "dev_macro_f1": mf,
                                                   "dev_macro_f1_at_0.5": macro_f1(run["rows"], truth, 0.5),
                                                   "dev_run": run["run_id"], "prompt_hash": run["meta"]["prompt_hash"]}
    THRESHOLDS.write_text(json.dumps(thresholds, indent=1) + "\n")
    return thresholds


def robustness_comparisons(by_key: dict, thresholds: dict) -> list[dict]:
    """(method, strategy, comparison, subset, base rows, stress rows, placebo rows) for every available pair."""
    def rows(method: str, layer: str, run_id: str) -> list[dict] | None:
        run = by_key.get((method, layer, run_id))
        return run["rows"] if run else None

    comps = []
    ds = "deepseek_flash"
    for s in ("L1", "L2", "L3", "L4"):
        base, stress = rows(ds, "layer1", f"eval_{s}_r1"), rows(ds, "layer3", f"l3_n25_{s}_r1")
        placebo, rest = rows(ds, "placebo", f"pl_n25_{s}_r1"), rows(ds, "layer3", f"l3_apirest_{s}_r1")
        orig = rows(ds, "original", f"orig_n25_{s}_r1")
        if base and stress:
            comps.append({"method": ds, "strategy": s, "comparison": "layer1→layer3", "subset": "nested25",
                          "base": base, "stress": stress, "placebo": placebo, "flips": True})
            if rest:
                comps.append({"method": ds, "strategy": s, "comparison": "layer1→layer3", "subset": "api_subset",
                              "base": base, "stress": stress + rest, "placebo": None})
        if base and orig:
            comps.append({"method": ds, "strategy": s, "comparison": "original→layer1", "subset": "nested25",
                          "base": orig, "stress": base, "placebo": None})
    qwen = "qwen3_5_4b"
    for s in ("L1", "L2", "L3", "L4"):
        base, stress = rows(qwen, "layer1", f"eval_{s}_r1"), rows(qwen, "layer3", f"l3_eval_{s}_r1")
        placebo, orig = rows(qwen, "placebo", f"pl_eval_{s}_r1"), rows(qwen, "original", f"orig_eval_{s}_r1")
        for subset in (None, "nested25", "api_subset"):
            if base and stress:
                comps.append({"method": qwen, "strategy": s, "comparison": "layer1→layer3", "subset": subset,
                              "base": base, "stress": stress, "placebo": placebo, "flips": subset is None})
            if base and orig:
                comps.append({"method": qwen, "strategy": s, "comparison": "original→layer1", "subset": subset,
                              "base": orig, "stress": base, "placebo": None})
    for s in ("L1", "L2", "L3"):
        base, stress = rows("jev", "layer1", f"eval_{s}_r1"), rows("jev", "layer3", f"l3_eval_{s}_r1")
        placebo, orig = rows("jev", "placebo", f"pl_eval_{s}_r1"), rows("jev", "original", f"orig_eval_{s}_r1")
        variants = [("@0.5", lambda x: x)]
        if s in thresholds:
            thr = thresholds[s]["threshold"]
            variants.append((f"@{thr:.3f}", lambda x, thr=thr: thresholded(x, thr)))
        for tag, f in variants:
            if base and stress:
                for subset in (None, "nested25", "api_subset"):
                    comps.append({"method": "jev", "strategy": f"{s} {tag}", "comparison": "layer1→layer3",
                                  "subset": subset, "base": f(base), "stress": f(stress),
                                  "placebo": f(placebo) if placebo else None,
                                  "flips": subset is None and tag == "@0.5"})
            if base and orig:
                comps.append({"method": "jev", "strategy": f"{s} {tag}", "comparison": "original→layer1",
                              "subset": "nested25", "base": f(orig), "stress": f(base), "placebo": None})
    return comps


def strongest_flips(comps: list[dict], units: dict[str, dict]) -> list[str]:
    """Per method: units going right→wrong from layer1 to layer3 in the most strategies (up to 5)."""
    out = []
    for method in sorted({c["method"] for c in comps if c.get("flips")}):
        hits: dict[str, list[str]] = defaultdict(list)
        placebo_hits: dict[str, list[str]] = defaultdict(list)
        for c in comps:
            if c["method"] != method or not c.get("flips"):
                continue
            base = {r["unit_id"]: r for r in c["base"]}
            for layer, target in (("stress", hits), ("placebo", placebo_hits)):
                for r in c[layer] or []:
                    u = r["unit_id"]
                    t = int(units[u]["truth"])
                    if effective_pred(base.get(u), t) == t and effective_pred(r, t) != t:
                        target[u].append(c["strategy"].split()[0])
        top = sorted(hits.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:5]
        n_bad = sum(int(units[u]["truth"]) == 1 for u in hits)
        out.append(f"- **{method}**: {len(hits)} units right→wrong in ≥1 strategy ({n_bad} bad→not-leak, "
                   f"{len(hits) - n_bad} good→leak); placebo right→wrong {len(placebo_hits)} units.")
        for u, strategies in top:
            unit = units[u]
            kind = "bad→not-leak" if int(unit["truth"]) == 1 else f"good({unit.get('good_kind')})→leak"
            pl = ", ".join(placebo_hits.get(u, [])) or "none"
            out.append(f"  - `{u}` ({unit['mechanism']}, {kind}): layer3 flips in {', '.join(strategies)}; "
                       f"placebo flips: {pl}")
    return out


def metrics_on(rows: list[dict] | None, unit_ids: list[str], truth: dict[str, int]) -> dict | None:
    """confusion_metrics on exactly `unit_ids` (missing prediction = wrong verdict)."""
    if rows is None:
        return None
    index = {r["unit_id"]: r for r in rows}
    return confusion_metrics([index.get(u, {"unit_id": u}) for u in unit_ids], truth)


def layer_rows(by_key: dict, method: str, layer: str, strategy: str, subset: str) -> list[dict] | None:
    """Predictions of one method/layer/strategy covering `subset` (None if not run on all of it)."""
    def rows(run_id: str) -> list[dict] | None:
        run = by_key.get((method, layer, run_id))
        return run["rows"] if run else None

    if method in FULL_EVAL_METHODS:
        prefix = {"layer1": "eval", "layer3": "l3_eval", "placebo": "pl_eval", "original": "orig_eval"}[layer]
        return rows(f"{prefix}_{strategy}_r1")
    if layer == "layer1":
        return rows(f"eval_{strategy}_r1")
    prefix = {"layer3": "l3", "placebo": "pl", "original": "orig"}[layer]
    n25 = rows(f"{prefix}_n25_{strategy}_r1")
    if subset == "nested25" or n25 is None:
        return n25
    rest = rows(f"{prefix}_apirest_{strategy}_r1")
    return n25 + rest if rest else None


def paired_table(by_key: dict, units_all: list[dict], truth: dict[str, int], thresholds: dict) -> list[str]:
    out = ["", "## DeepSeek vs Qwen vs Jev on the same units (eval ∩ nested25 / eval ∩ api_subset)", "",
           "macro-F1 (FP/FN); Qwen and Jev from their full-eval runs restricted to the subset, Jev at 0.5 and at "
           "the frozen dev threshold. DeepSeek layer3 api_subset = l3_n25 + l3_apirest runs.", "",
           "| layer | strategy | subset | units | DeepSeek | Qwen3.5-4B | Jev @0.5 | Jev @thr |",
           "|---|---|---|---|---|---|---|---|"]

    def fmt(m: dict | None) -> str:
        return "–" if m is None else f"{m['macro_f1']:.3f} ({m['fp']}/{m['fn']})"

    for layer in LAYER_ORDER:
        for strategy in ("L1", "L2", "L3", "L4"):
            for subset in ("nested25", "api_subset"):
                ids = [u["unit_id"] for u in select_units(units_all, "eval", subset, SUBSETS_FILE)]
                ds = metrics_on(layer_rows(by_key, "deepseek_flash", layer, strategy, subset), ids, truth)
                qw = metrics_on(layer_rows(by_key, "qwen3_5_4b", layer, strategy, subset), ids, truth)
                jev_rows = layer_rows(by_key, "jev", layer, strategy, subset) if strategy != "L4" else None
                jev = metrics_on(jev_rows, ids, truth)
                jev_thr = None
                if jev_rows is not None and strategy in thresholds:
                    jev_thr = metrics_on(thresholded(jev_rows, thresholds[strategy]["threshold"]), ids, truth)
                if ds is None and qw is None and jev is None:
                    continue
                out.append(f"| {layer} | {strategy} | {subset} | {len(ids)} | {fmt(ds)} | {fmt(qw)} | {fmt(jev)} | "
                           f"{fmt(jev_thr)} |")
    return out


def stress_category(unit: dict) -> str:
    """What the layer-3 transform did to a unit (data/build/layer3.jsonl `transform`)."""
    t = unit["transform"]
    if unit["truth"]:
        site = "dead free at flaw site" if t.get("n_flaw_sites") else "no flaw-site free"
        return f"bad {unit['mechanism']}: {site}" + (", real free in always-true guard"
                                                     if t.get("wrapped_real_frees") else "")
    wrapped = "real free in always-true guard" if t.get("wrapped_real_frees") else "no free wrapped"
    return f"good {unit['good_kind']}: {wrapped}, {t.get('n_dead', 0)} dead free(s)"


def stress_error_split(by_key: dict, truth: dict[str, int]) -> list[str]:
    layer3 = {u["unit_id"]: u for u in load_jsonl(JF / "data" / "build" / "layer3.jsonl")}
    units_all = list(layer3.values())
    cats = sorted({stress_category(u) for u in units_all if u["set"] == "eval"})
    out = ["", "## Layer 3 errors by transform category (errors on layer3 / units; in brackets the same units on "
           "layer1)", "",
           "bad = FN (leak verdict lost), good = FP. Categories from layer3.jsonl `transform`: dead frees are "
           "inserted under always-false guards; for B2G and realloc ('other') goods the real free is wrapped in "
           "an always-true guard.", "",
           "| method | strategy | subset | " + " | ".join(cats) + " |", "|---|---|---|" + "---|" * len(cats)]
    for method, strategies in (("deepseek_flash", ("L1", "L2", "L3", "L4")), ("qwen3_5_4b", ("L1", "L2", "L3", "L4")),
                               ("jev", ("L1", "L2", "L3"))):
        for strategy in strategies:
            for subset in ("nested25", "api_subset"):
                stress = layer_rows(by_key, method, "layer3", strategy, subset)
                base = layer_rows(by_key, method, "layer1", strategy, subset)
                if stress is None or base is None:
                    continue
                ids = [u["unit_id"] for u in select_units(units_all, "eval", subset, SUBSETS_FILE)]
                s_idx, b_idx = {r["unit_id"]: r for r in stress}, {r["unit_id"]: r for r in base}
                cells = []
                for cat in cats:
                    sel = [u for u in ids if stress_category(layer3[u]) == cat]
                    err_s = sum(effective_pred(s_idx.get(u), truth[u]) != truth[u] for u in sel)
                    err_b = sum(effective_pred(b_idx.get(u), truth[u]) != truth[u] for u in sel)
                    cells.append(f"{err_s}/{len(sel)} ({err_b})" if sel else "–")
                out.append(f"| {method} | {strategy} | {subset} | " + " | ".join(cells) + " |")
    return out


def original_fp_analysis(by_key: dict, truth: dict[str, int]) -> list[str]:
    orig = {u["unit_id"]: u for u in load_jsonl(JF / "data" / "build" / "original.jsonl")}
    layer1 = {u["unit_id"]: u for u in load_jsonl(UNITS)}
    out = ["", "## Original-Juliet false positives (eval ∩ nested25)", "",
           "The original good unit is the whole OMITBAD program (every goodG2B*/goodB2G* function plus the good() "
           "wrapper, good_kind 'orig'); layer1 keeps one good entry. FPs by Juliet flow variant (FP/goods) and by "
           "number of `static void` good functions in the unit; layer1 FPs on the same unit_ids in brackets.", ""]
    ids = {u["unit_id"] for u in select_units(list(orig.values()), "eval", "nested25", SUBSETS_FILE)}
    for method, run_id, base_id in (("deepseek_flash", "orig_n25_L1_r1", "eval_L1_r1"),
                                    ("qwen3_5_4b", "orig_eval_L1_r1", "eval_L1_r1"),
                                    ("jev", "orig_eval_L1_r1", "eval_L1_r1")):
        run, base = by_key.get((method, "original", run_id)), by_key.get((method, "layer1", base_id))
        if not run or not base:
            continue
        idx, b_idx = {r["unit_id"]: r for r in run["rows"]}, {r["unit_id"]: r for r in base["rows"]}
        goods = sorted(u for u in ids if truth[u] == 0)
        fps = [u for u in goods if effective_pred(idx.get(u), 0) == 1]
        by_variant: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
        by_nfunc: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        for u in goods:
            fp = effective_pred(idx.get(u), 0) == 1
            v = by_variant[orig[u]["variant"]]
            v[0] += 1
            v[1] += fp
            v[2] += effective_pred(b_idx.get(u), 0) == 1
            n = len([ln for ln in orig[u]["model_text"].splitlines() if ln.startswith("static void ")])
            by_nfunc[n][0] += 1
            by_nfunc[n][1] += fp
        variants = ", ".join(f"{v} {c[1]}/{c[0]} ({c[2]})" for v, c in sorted(by_variant.items()) if c[1] or c[2])
        nfunc = ", ".join(f"{n} fn: {c[1]}/{c[0]}" for n, c in sorted(by_nfunc.items()))
        kinds = defaultdict(int)
        for u in fps:
            kinds[layer1[u]["good_kind"]] += 1
        out += [f"- **{method} {run_id}**: {len(fps)} FP of {len(goods)} goods; variants with FPs: {variants}; "
                f"by good functions: {nfunc}; layer1 good_kind of the same groups: {dict(kinds)}.",
                "  FP units: " + ", ".join("`" + u.removeprefix("CWE401_Memory_Leak__") + "`" for u in fps)]
    return out


def main() -> int:
    units_all = load_jsonl(UNITS)
    units = {u["unit_id"]: u for u in units_all}
    truth = {k: int(u["truth"]) for k, u in units.items()}
    runs = load_runs()
    by_key = {(r["method"], r["layer"], r["run_id"]): r for r in runs}
    thresholds = jev_thresholds(runs, truth)

    out = ["# LLM lane run summary", "",
           "Generated by `llm/summarize.py` from `results/scores/<method>/<run_id>.json` (analysis/score.py on the "
           "run's own layer file, end-to-end: invalid counted wrong) and run metas. Run-id prefix = layer: none = "
           "layer1 (debiased, main), `l3_` = layer3 (stress), `pl_` = placebo, `orig_` = original Juliet. P/R/F1 = "
           "leak class. CI = family-cluster bootstrap 95% (1000 it.; stage-2b subset runs have none). AUROC from "
           "`score` = P(leak). Latency = per-call client latency (s). Cost in CNY (DeepSeek) / USD (Jev).", "",
           "| method | run | layer | strategy | set/subset | n | P | R | F1 | macro-F1 [95% CI] | FP/FN | invalid | "
           "AUROC | lat med/p90 | cost total | cost/call | prompt hash |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for run in runs:
        m, rep, e = run["meta"], run["rep"], run["rep"]["end_to_end"]
        ci = (rep.get("bootstrap") or {}).get("ci95", {}).get("macro_f1")
        ci_s = f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else ""
        auc = auroc([(r["score"], truth[r["unit_id"]]) for r in run["rows"] if r["score"] is not None])
        lat = rep.get("latency") or {}
        out.append(f"| {run['method']} | {run['run_id']} | {run['layer']} | {m['strategy']} | "
                   f"{m['set']}/{run['subset'] or m['subset'] or 'all'} | "
                   f"{e['n']} | {f3(e['precision_leak'])} | {f3(e['recall_leak'])} | {f3(e['f1_leak'])} | "
                   f"{f3(e['macro_f1'])}{ci_s} | {e['fp']}/{e['fn']} | {e['invalid']} | {f3(auc)} | "
                   f"{lat.get('median_s', 0):.3f}/{lat.get('p90_s', 0):.3f} | {m['cost_total']:.4f} | "
                   f"{m['cost_per_call']:.6f} | {m['prompt_hash'][:8]} |")

    out += ["", "## Breakdowns", "",
            "macro-F1 by flow_category; recall/specificity by mechanism; specificity by good_kind.", "",
            "| method | run | " + " | ".join(f"mF1 {f}" for f in FLOWS) + " | "
            + " | ".join(f"R/S {k}" for k in MECHS) + " | " + " | ".join(f"S {k}" for k in KINDS) + " |",
            "|---|---|" + "---|" * (len(FLOWS) + len(MECHS) + len(KINDS))]
    for run in runs:
        rep = run["rep"]
        cells = [f3((rep["by_flow_category"].get(f) or {}).get("macro_f1")) for f in FLOWS]
        for k in MECHS:
            b = rep["by_mechanism"].get(k) or {}
            cells.append(f"{f3(b.get('recall_leak'))}/{f3(b.get('specificity'))}")
        cells += [f3((rep["by_good_kind"].get(k) or {}).get("specificity")) for k in KINDS]
        out.append(f"| {run['method']} | {run['run_id']} | " + " | ".join(cells) + " |")

    l4_runs = [r for r in runs if r["meta"]["strategy"] == "L4"]
    if l4_runs:
        out += ["", "## L4 fact quality (per unit `extra` of run_llm.py)", "",
                "strict parse = every non-empty answer line is a schema fact; grounded = facts kept by the line "
                "check / (kept + dropped); invalid = no parseable fact and no `none`; error = Souffle failure.", "",
                "| method | run | layer | n | strict parse | grounded facts | answered none | invalid | error | "
                "facts/unit |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        for run in l4_runs:
            rows = run["rows"]
            ex = [r.get("extra") or {} for r in rows]
            kept = sum(x.get("n_facts", 0) for x in ex)
            dropped = sum(x.get("n_ungrounded", 0) for x in ex)
            n = len(rows)
            out.append(f"| {run['method']} | {run['run_id']} | {run['layer']} | {n} | "
                       f"{sum(bool(x.get('facts_strict_ok')) for x in ex) / n:.4f} | "
                       f"{kept / (kept + dropped) if kept + dropped else 0:.4f} ({kept}/{kept + dropped}) | "
                       f"{sum(bool(x.get('facts_none')) for x in ex)} | "
                       f"{sum(r['status'] == 'invalid' for r in rows)} | {sum(r['status'] == 'error' for r in rows)} | "
                       f"{kept / n:.2f} |")

    if thresholds:
        out += ["", "## Jev at the frozen secondary threshold (chosen on layer-1 full dev by macro-F1; primary = 0.5)",
                "", "| strategy | threshold | dev mF1 @thr | dev mF1 @0.5 |", "|---|---|---|---|"]
        for s, t in sorted(thresholds.items()):
            out.append(f"| {s} | {t['threshold']:.4f} | {t['dev_macro_f1']:.3f} | {t['dev_macro_f1_at_0.5']:.3f} |")
        out += ["", "| run | layer | strategy | set/subset | mF1 @0.5 | mF1 @thr | P/R @thr | FP/FN @thr |",
                "|---|---|---|---|---|---|---|---|"]
        for run in runs:
            s = run["meta"]["strategy"]
            if run["method"] != "jev" or run["meta"]["set"] != "eval" or s not in thresholds:
                continue
            at05 = confusion_metrics(run["rows"], truth)
            at = confusion_metrics(thresholded(run["rows"], thresholds[s]["threshold"]), truth)
            out.append(f"| {run['run_id']} | {run['layer']} | {s} | eval/{run['subset'] or 'all'} | "
                       f"{at05['macro_f1']:.3f} | {at['macro_f1']:.3f} | {f3(at['precision'])}/{f3(at['recall'])} | "
                       f"{at['fp']}/{at['fn']} |")

    lat_runs = [r for r in runs if r["run_id"].startswith("lat300_c1_")]
    if lat_runs:
        out += ["", "## Concurrency-1 latency (latency300, L1)", "",
                "Per-call client latency. load1 = dell 1-min load average at run start; `_quiet` runs (and the Qwen "
                "stage-2d run) waited for the latency lock /tmp/cs224_latency.lock and load1 < 2.5 over 2 min.", "",
                "| method | run | median s | p90 s | load1 at start | condition |", "|---|---|---|---|---|---|"]
        for run in lat_runs:
            m, lat = run["meta"], run["rep"].get("latency") or {}
            lock = m.get("latency_lock") or {}
            cond = "quiet (lock + load1 < 2.5 for 2 min)" if lock.get("quiet", bool(lock)) else "loaded"
            if m.get("gpu_state"):
                cond += "; " + m["gpu_state"].split(":")[0]
            out.append(f"| {run['method']} | {run['run_id']} | {lat.get('median_s', 0):.3f} | "
                       f"{lat.get('p90_s', 0):.3f} | {(m.get('loadavg_start') or [0])[0]:.2f} | {cond} |")

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for run in runs:
        if run["layer"] == "layer1" and run["meta"]["set"] == "eval" and run["run_id"].startswith(("eval_", "rep_")):
            groups[(run["method"], run["meta"]["strategy"])].append(run)
    lines = []
    for (method, strategy), rs in sorted(groups.items()):
        if len(rs) < 2:
            continue
        common = set.intersection(*({r["unit_id"] for r in x["rows"]} for x in rs))
        preds = [{r["unit_id"]: r["pred"] for r in x["rows"] if r["unit_id"] in common} for x in rs]
        same = sum(len({p[u] for p in preds}) == 1 for u in common)
        lines.append(f"| {method} | {strategy} | {', '.join(r['run_id'] for r in rs)} | {len(common)} | "
                     f"{same / len(common):.3f} |")
    if lines:
        out += ["", "## Repeat agreement (layer1; units in all listed runs; identical pred in every run)", "",
                "| method | strategy | runs | units | agreement |", "|---|---|---|---|---|"] + lines

    comps = robustness_comparisons(by_key, thresholds)
    if comps:
        rob_dir = RESULTS / "robustness"
        rob_dir.mkdir(exist_ok=True)
        out += ["", "## ROBUSTNESS (analysis/robustness.py; paired unit_ids, eval set)", "",
                "from/to = macro-F1 on the first/second layer of the comparison; Δ = to − from with family-cluster "
                f"bootstrap 95% CI ({ROBUSTNESS_BOOTSTRAP} it.); flip rates are shares of all bad (good) units: "
                "bad→NL = leak verdict lost, NL→L = gained; good→L = new false positive, L→NL = FP fixed. "
                "adjusted = layer3 statistic minus placebo statistic (both relative to layer1). Invalid/missing "
                "predictions count as the wrong verdict. Jev rows tagged @thr use the frozen dev threshold.", "",
                "| method | strategy | comparison | subset | units | from mF1 | to mF1 | Δ macro-F1 [CI] | ΔF1 [CI] | "
                "bad→NL | bad NL→L | good→L | good L→NL | placebo Δ mF1 | adjusted Δ mF1 [CI] | adj. bad→NL | "
                "adj. good→L |",
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for c in comps:
            rep = robustness(select_units(units_all, "eval", c["subset"], SUBSETS_FILE), c["base"], c["stress"],
                             c["placebo"], ROBUSTNESS_BOOTSTRAP)
            slug = f"{c['method']}_{c['strategy'].replace(' ', '').replace('@', 'at')}_" \
                   f"{c['comparison'].replace('→', '_to_')}_{c['subset'] or 'eval'}"
            (rob_dir / f"{slug}.json").write_text(json.dumps(rep, indent=1) + "\n")
            st = rep["stats"]
            ci = rep.get("bootstrap", {}).get("ci95", {})

            def cell(key: str, signed: bool = True, with_ci: bool = True) -> str:
                v = st.get(key)
                if v is None:
                    return "–"
                text = f"{v:+.3f}" if signed else f"{v:.3f}"
                if with_ci and key in ci and ci[key][0] is not None:
                    text += f" [{ci[key][0]:+.3f}, {ci[key][1]:+.3f}]"
                return text

            if c["placebo"] is not None:
                pl_cells = [cell("delta_placebo.macro_f1", True, False), cell("adjusted.macro_f1"),
                            cell("adjusted.bad.right_to_wrong", True, False),
                            cell("adjusted.good.right_to_wrong", True, False)]
            else:
                pl_cells = ["–"] * 4
            out.append(f"| {c['method']} | {c['strategy']} | {c['comparison']} | {c['subset'] or 'all eval'} | "
                       f"{rep['n_units']} | {st['base.macro_f1']:.3f} | {st['stress.macro_f1']:.3f} | "
                       f"{cell('delta_stress.macro_f1')} | {cell('delta_stress.f1_leak')} | "
                       f"{st['stress.bad.right_to_wrong']:.3f} | {st['stress.bad.wrong_to_right']:.3f} | "
                       f"{st['stress.good.right_to_wrong']:.3f} | {st['stress.good.wrong_to_right']:.3f} | "
                       + " | ".join(pl_cells) + " |")
        out += ["", "### Strongest layer1→layer3 flips (right→wrong; DeepSeek on nested25, Qwen and Jev @0.5 on all eval)", ""]
        out += strongest_flips(comps, units)
    out += paired_table(by_key, units_all, truth, thresholds)
    out += stress_error_split(by_key, truth)
    out += original_fp_analysis(by_key, truth)
    (RESULTS / "SUMMARY.md").write_text("\n".join(out) + "\n")
    print(f"wrote {RESULTS / 'SUMMARY.md'} ({len(runs)} runs, {len(comps)} robustness comparisons)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

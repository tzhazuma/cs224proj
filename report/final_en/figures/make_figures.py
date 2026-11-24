#!/usr/bin/env python3
"""Paper-results lane generator: score every result file and write the paper's figures, tables and macros.

Adapted from presentation/pre/figures/make_figures.py (same registry, same run selection, same scorer), restyled
for the IEEE paper.  Read-only on juliet_full/; writes only inside report/final_en/:

  generated/numbers.tex          \\res{<key>-<layer>}{<metric>} macros (slides' key names kept, new keys added)
  generated/results_summary.json everything that was scored, with the files used
  tables/res_*.tex               generated tables (each a complete float with caption and label)
  figures/*.pdf                  vector figures sized for \\columnwidth (3.5 in), Times-like 8 pt text

Every run is scored on the eval set (39 flow variants, 2,656 units; DeepSeek on the stress, placebo and original
layers: the nested25 subset, 664 units) with juliet_full/analysis/score.py (95% family-cluster bootstrap CI,
2,000 resamples).  Robustness deltas are paired: the main layer is rescored on exactly the units of the other run.
Latency comes only from the concurrency-1 measurements in figures/latency_c1.csv (recomputed from the latency
files listed there); latency_s of bulk prediction files is never used.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import itertools
import json
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

HERE = Path(__file__).resolve().parent            # report/final_en/figures
PAPER = HERE.parent                                # report/final_en
REPO = HERE.parents[2]
JULIET_FULL = REPO / "juliet_full"
GENERATED = PAPER / "generated"
TABLES = PAPER / "tables"
UNITS_PATH = JULIET_FULL / "data" / "build" / "layer1.jsonl"
SUBSETS_PATH = JULIET_FULL / "data" / "build" / "subsets.json"
PROBES_PATH = JULIET_FULL / "data" / "build" / "probes_layer3.json"
LEDGER_PATH = JULIET_FULL / "llm" / "ledger.jsonl"
DEMO_PATH = REPO / "presentation" / "demo" / "recordings" / "stage_dryrun.json"
FT_RUNS = JULIET_FULL / "decision_ft" / "runs"
FT_SPOT = FT_RUNS / "endpoint" / "spot_check.json"
REGISTRY_PATH = HERE / "methods.json"
LATENCY_PATH = HERE / "latency_c1.csv"
EVAL_SET = "eval"
LAYERS = ("layer1", "layer3", "placebo", "original")
LAYER_TEX = {"layer1": "\\Deb", "layer3": "\\Dead", "placebo": "\\Plac", "original": "\\Orig"}
FLOW_CATEGORIES = ["01", "02-22", "31-45", "51-68", "71-84"]
MECHANISMS = ["c_alloc", "cpp_new", "realloc_fail", "destructor"]
GOOD_KINDS = ["G2B", "B2G", "other"]
BOOTSTRAP = 2000
SEED = 20261126  # = score.BOOTSTRAP_SEED
# Okabe-Ito
BLUE, SKY, ORANGE, GREEN, VERMIL, PURPLE, YELLOW = ("#0072B2", "#56B4E9", "#E69F00", "#009E73", "#D55E00",
                                                    "#CC79A7", "#F0E442")
INK, GREY, LIGHT = "#222222", "#7F7F7F", "#E8E8E8"
FAMILY_STYLE = {"Static": (BLUE, "s"), "Learned": (PURPLE, "D"), "DeepSeek": (VERMIL, "o"),
                "Qwen3.5-4B": (ORANGE, "^"), "Decision": (GREEN, "v"), "Dynamic": (GREY, "X"), "Ablation": (GREY, "o")}
FAMILY_TEX = {"Static": "Static analyzers and baselines", "Learned": "Learned (zero-shot)",
              "Dynamic": "Dynamic (reference, not ranked)", "DeepSeek": "DeepSeek-V4.1-Flash",
              "Qwen3.5-4B": "Qwen3.5-4B", "Decision": "Decision models"}
MAIN_ORDER = ("Static", "Learned", "DeepSeek", "Qwen3.5-4B", "Decision", "Dynamic")
LABEL_TEX = {"lora_L1": "LoRA L1", "lora_L3": "LoRA L3", "dynamic_enhanced": "Dynamic-enh."}

sys.dont_write_bytecode = True  # do not leave __pycache__ in juliet_full/analysis
sys.path.insert(0, str(JULIET_FULL / "analysis"))
import score as scorer  # noqa: E402  juliet_full/analysis/score.py


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Run selection and scoring (same rules as the slides' generator)
# ---------------------------------------------------------------------------
def load_rows(path: Path, entry: dict) -> list[dict]:
    rows = read_jsonl(path)
    if entry.get("strategy"):
        rows = [r for r in rows if r.get("strategy") in (None, entry["strategy"])]
    if entry.get("pred_field"):  # e.g. the read-out ablation at the dev-selected threshold
        rows = [{**r, "pred": (r.get("extra") or {}).get(entry["pred_field"])} for r in rows]
    if entry.get("rethreshold"):  # Jev at its frozen dev-selected secondary threshold (llm/summarize.py rule)
        spec = entry["rethreshold"]
        thr = json.loads((JULIET_FULL / spec["file"]).read_text())[spec["key"]]["threshold"]
        rows = [r if r.get("score") is None else {**r, "pred": int(r["score"] >= thr)} for r in rows]
    return rows


def candidates(patterns: list[str], exclude: list[str]) -> list[list[Path]]:
    seen: set[Path] = set()
    out = []
    for pattern in patterns:
        files = [p for p in JULIET_FULL.glob(pattern) if p.is_file() and p.suffix == ".jsonl"
                 and not p.name.endswith(".evidence.jsonl") and not p.name.startswith(tuple(exclude))
                 and p not in seen]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        seen.update(files)
        out.append(files)
    return out


def select_run(entry: dict, patterns: list[str], target: set[str], min_cov: float, exclude: list[str]) -> dict:
    groups = candidates(patterns, exclude)
    if entry.get("mode") == "union":  # one file per fold: newer file wins per unit
        merged: dict[str, dict] = {}
        files = sorted({p for g in groups for p in g}, key=lambda p: p.stat().st_mtime)
        for path in files:
            merged.update({r["unit_id"]: r for r in load_rows(path, entry)})
        cov = len(set(merged) & target) / len(target)
        return {"rows": list(merged.values()) if cov >= min_cov else None, "files": files, "coverage": cov}
    best = 0.0
    for files in groups:
        for path in files:
            rows = load_rows(path, entry)
            cov = len({r["unit_id"] for r in rows} & target) / len(target)
            if cov >= min_cov:
                return {"rows": rows, "files": [path], "coverage": cov}
            best = max(best, cov)
    return {"rows": None, "files": [], "coverage": best}


def summarize(rep: dict) -> dict:
    e2e = rep["end_to_end"]
    ci = (rep.get("bootstrap") or {}).get("ci95", {})
    return {
        "n": rep["n_units"], "tp": e2e["tp"], "fp": e2e["fp"], "tn": e2e["tn"], "fn": e2e["fn"],
        "invalid": e2e["invalid"], "p": e2e["precision_leak"], "r": e2e["recall_leak"], "f1": e2e["f1_leak"],
        "macro": e2e["macro_f1"], "spec": e2e["specificity"], "macro_ci": ci.get("macro_f1"),
        "f1_ci": ci.get("f1_leak"),
        "by_flow": {c: m["macro_f1"] for c, m in rep["by_flow_category"].items()},
        "recall_by_mech": {k: m["recall_leak"] for k, m in rep["by_mechanism"].items()},
        "spec_by_good_kind": {k: m["specificity"] for k, m in rep["by_good_kind"].items()},
    }


def lost_gained(units: list[dict], before: list[dict], after: list[dict]) -> tuple[int, int, int]:
    """Bad units detected before and missed after; good units clean before and flagged after; all flips."""
    b = {r["unit_id"]: scorer.valid_pred(r) for r in before}
    a = {r["unit_id"]: scorer.valid_pred(r) for r in after}
    lost = sum(u["truth"] == 1 and b.get(u["unit_id"]) == 1 and a.get(u["unit_id"]) != 1 for u in units)
    gained = sum(u["truth"] == 0 and b.get(u["unit_id"]) == 0 and a.get(u["unit_id"]) != 0 for u in units)
    flips = sum(b.get(u["unit_id"]) != a.get(u["unit_id"]) for u in units)
    return lost, gained, flips


def family_counts(units: list[dict], rows: list[dict]) -> dict[str, dict[str, int]]:
    index, _ = scorer.index_predictions(rows)
    out: dict[str, dict[str, int]] = {}
    for u in units:
        c = scorer.confusion([(int(u["truth"]), scorer.valid_pred(index.get(u["unit_id"])))])
        slot = out.setdefault(u["family"], {k: 0 for k in c})
        for k, v in c.items():
            slot[k] += v
    return out


def paired_delta_ci(units: list[dict], before: list[dict], after: list[dict]) -> list[float]:
    """95% family-cluster bootstrap CI of macro-F1(after) - macro-F1(before) on the same units."""
    fa, fb = family_counts(units, after), family_counts(units, before)
    fams = sorted(fa)
    rng = random.Random(SEED)
    diffs = []
    for _ in range(BOOTSTRAP):
        ta = {k: 0 for k in ("tp", "fp", "tn", "fn", "invalid", "n")}
        tb = dict(ta)
        for f in rng.choices(fams, k=len(fams)):
            for k in ta:
                ta[k] += fa[f][k]
                tb[k] += fb[f][k]
        ma, mb = scorer.metrics_from_counts(ta)["macro_f1"], scorer.metrics_from_counts(tb)["macro_f1"]
        if ma is not None and mb is not None:
            diffs.append(ma - mb)
    return [scorer.percentile(diffs, 0.025), scorer.percentile(diffs, 0.975)]


def collect(registry: dict, units: list[dict], subsets: dict[str, set]) -> list[dict]:
    results = []
    for entry in registry["methods"]:
        res = {k: entry.get(k) for k in ("key", "label", "family", "model", "strategy")}
        res["ranked"] = entry.get("ranked", entry["family"] not in ("Dynamic", "Ablation"))
        res["layers"] = {}
        exclude = entry.get("exclude", registry["exclude"])
        rows_by_layer = {}
        for layer, patterns in entry["runs"].items():
            subset = (entry.get("subset") or {}).get(layer)
            target_units = [u for u in units if not subset or u["group_id"] in subsets[subset]]
            target = {u["unit_id"] for u in target_units}
            run = select_run(entry, patterns, target, registry["min_coverage"], exclude)
            info = {"subset": subset, "coverage": round(run["coverage"], 4),
                    "files": [str(p.relative_to(JULIET_FULL)) for p in run["files"]]}
            if run["rows"] is None:
                info["status"] = "pending"
            else:
                info.update(status="ok", sha256=[sha256(p) for p in run["files"]],
                            **summarize(scorer.score(target_units, run["rows"], bootstrap=BOOTSTRAP)))
                rows_by_layer[layer] = (target_units, run["rows"])
            res["layers"][layer] = info
        if "layer1" in rows_by_layer:  # paired deltas: layer 1 rescored on the units of the other layer
            for layer, (target_units, rows) in rows_by_layer.items():
                if layer == "layer1":
                    continue
                base = scorer.score(target_units, rows_by_layer["layer1"][1], bootstrap=0)["end_to_end"]
                lost, gained, flips = lost_gained(target_units, rows_by_layer["layer1"][1], rows)
                info = res["layers"][layer]
                info.update(base=base["macro_f1"], base_r=base["recall_leak"], base_spec=base["specificity"],
                            base_fp=base["fp"], base_fn=base["fn"], d=info["macro"] - base["macro_f1"],
                            lost=lost, gained=gained, flips=flips,
                            dci=paired_delta_ci(target_units, rows_by_layer["layer1"][1], rows))
            l3, pl = res["layers"].get("layer3"), res["layers"].get("placebo")
            if l3 and pl and "d" in l3 and "d" in pl and l3["subset"] == pl["subset"]:
                l3["adj"] = l3["d"] - pl["d"]
        res["_rows"] = rows_by_layer
        results.append(res)
    return results


def get(results: list[dict], key: str) -> dict:
    return next(r for r in results if r["key"] == key)


def ok(r: dict, layer: str) -> dict | None:
    info = r["layers"].get(layer)
    return info if info and info["status"] == "ok" else None


# ---------------------------------------------------------------------------
# Latency (concurrency 1), cost, training time, repeats, folds, McNemar
# ---------------------------------------------------------------------------
def read_latency() -> dict[str, dict]:
    """latency_c1.csv; median/p90 are recomputed from the listed latency file when there is one."""
    out = {}
    with LATENCY_PATH.open() as fh:
        for row in csv.DictReader(fh):
            row["median"], row["p90"] = float(row["latency_s"]), float(row["p90_s"])
            if row["file"]:
                stats = scorer.latency_stats(read_jsonl(JULIET_FULL / row["file"]))
                for k, v in (("median", stats["median_s"]), ("p90", stats["p90_s"])):
                    if abs(v - row[k]) > max(0.0015, 0.002 * row[k]):
                        print(f"WARNING latency {row['key']} {k}: csv {row[k]} vs file {v:.4f}; using the file")
                    row[k] = v
                row["n"] = stats["n"]
            out[row["key"]] = row
    return out


def ledger_costs() -> dict[tuple[str, str], dict]:
    """(provider, run_id) -> calls, cost, currency (juliet_full/llm/ledger.jsonl)."""
    out: dict[tuple[str, str], dict] = defaultdict(lambda: {"calls": 0, "cost": 0.0, "currency": None})
    for line in LEDGER_PATH.read_text().splitlines():
        r = json.loads(line)
        if r.get("kind") != "call":
            continue
        c = out[(r["provider"], r["run_id"])]
        c["calls"] += 1
        c["cost"] += r.get("cost") or 0.0
        c["currency"] = r.get("currency")
    return out


def ft_training() -> dict[str, float]:
    """Wall-clock hours per LoRA job (first to last train_log timestamp, one RTX 3090 each)."""
    out = {}
    for log in sorted(FT_RUNS.glob("L?/fold?/train_log.jsonl")):
        rows = read_jsonl(log)
        ts = [dt.datetime.fromisoformat(r["t"].replace("Z", "+00:00")) for r in rows if r.get("t")]
        out[f"{log.parts[-3]}_{log.parts[-2]}"] = (max(ts) - min(ts)).total_seconds() / 3600
    return out


def auroc(pairs: list[tuple[int, float]]) -> float | None:
    """Mann-Whitney AUROC with ties counted half."""
    pos = [s for t, s in pairs if t == 1]
    neg = [s for t, s in pairs if t == 0]
    if not pos or not neg:
        return None
    ranked = sorted([(s, t) for t, s in pairs])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(1 for k in range(i, j) if ranked[k][1] == 1)
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def fold_metrics(results: list[dict]) -> dict[str, dict]:
    """LoRA: macro-F1 and AUROC per fold (each fold scored by the adapter that did not see it)."""
    out = {}
    for key in ("lora_L1", "lora_L3", "lora_unmerged_L1", "lora_unmerged_L3"):
        r = get(results, key)
        for layer, (units, rows) in r["_rows"].items():
            index, _ = scorer.index_predictions(rows)
            per = {}
            for fold in (0, 1, 2):
                fu = [u for u in units if (index.get(u["unit_id"]) or {}).get("extra", {}).get("fold") == fold]
                if not fu:
                    continue
                m = scorer.score(fu, rows, bootstrap=0)["end_to_end"]
                per[fold] = {"n": len(fu), "macro": m["macro_f1"], "r": m["recall_leak"],
                             "auroc": auroc([(int(u["truth"]), index[u["unit_id"]]["score"]) for u in fu])}
            out[f"{key}-{layer}"] = per
    for key in ("readout_L1", "readout_L3"):  # single base model: one AUROC over the eval units
        r = get(results, key)
        for layer, (units, rows) in r["_rows"].items():
            index, _ = scorer.index_predictions(read_jsonl(JULIET_FULL / ok(r, layer)["files"][0]))
            out[f"{key}-{layer}"] = {"all": {"auroc": auroc([(int(u["truth"]), index[u["unit_id"]]["score"])
                                                             for u in units if u["unit_id"] in index])}}
    return out


def repeats(registry: dict, units: list[dict]) -> list[dict]:
    truth = {u["unit_id"]: int(u["truth"]) for u in units}
    out = []
    for rep in registry["repeats"]:
        paths = [JULIET_FULL / p for p in rep["files"]]
        if not all(p.exists() for p in paths):
            out.append({"label": rep["label"], "status": "pending"})
            continue
        preds = [{r["unit_id"]: r.get("pred") for r in read_jsonl(p)} for p in paths]
        common = sorted(set.intersection(*(set(p) for p in preds)) & set(truth))
        agree = sum(len({p[u] for p in preds}) == 1 for u in common)
        cu = [u for u in units if u["unit_id"] in set(common)]
        macros = [scorer.score(cu, [{"unit_id": k, "pred": v} for k, v in p.items()], bootstrap=0)
                  ["end_to_end"]["macro_f1"] for p in preds]
        out.append({"label": rep["label"], "status": "ok", "n": len(common), "agree": agree / len(common),
                    "macros": macros, "files": rep["files"]})
    return out


def determinism(units: list[dict]) -> dict:
    """Intern-Decision 50-unit rerun vs the eval run; LoRA endpoint spot check."""
    out = {}
    base = {r["unit_id"]: r for r in read_jsonl(JULIET_FULL / "gpu/results/intern_decision/layer1/eval_L1_r1.jsonl")}
    det = read_jsonl(JULIET_FULL / "gpu/results/intern_decision/layer1/det50_L1_r2.jsonl")
    same_pred = sum(base[r["unit_id"]]["pred"] == r["pred"] for r in det if r["unit_id"] in base)
    same_score = sum(base[r["unit_id"]]["score"] == r["score"] for r in det if r["unit_id"] in base)
    out["intern_det"] = {"n": len(det), "same_pred": same_pred, "same_score": same_score}
    spot = json.loads(FT_SPOT.read_text())
    out["lora_spot"] = {"n": spot["n"], "max_abs_delta": spot["max_abs_delta"], "preds_match": spot["all_preds_match"]}
    jev = []
    for s in ("L1", "L2", "L3"):
        ms = [scorer.score(units, read_jsonl(JULIET_FULL / f"llm/results/jev/layer1/eval_{s}_r{k}.jsonl"),
                           bootstrap=0)["end_to_end"]["macro_f1"] for k in (1, 2, 3)]
        jev.append({"strategy": s, "macros": ms, "mean": statistics.fmean(ms), "sd": statistics.stdev(ms)})
    out["jev_full"] = jev
    return out


def cluster_diff_ci(units: list[dict], rows_a: list[dict], rows_b: list[dict]) -> list[float]:
    """95% family-cluster bootstrap CI of accuracy(A) - accuracy(B) on paired units."""
    ia, _ = scorer.index_predictions(rows_a)
    ib, _ = scorer.index_predictions(rows_b)
    fam: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for u in units:
        t = int(u["truth"])
        d = (scorer.valid_pred(ia.get(u["unit_id"])) == t) - (scorer.valid_pred(ib.get(u["unit_id"])) == t)
        fam[u["family"]][0] += d
        fam[u["family"]][1] += 1
    fams = sorted(fam)
    rng = random.Random(SEED)
    diffs = []
    for _ in range(BOOTSTRAP):
        pick = rng.choices(fams, k=len(fams))
        diffs.append(sum(fam[f][0] for f in pick) / sum(fam[f][1] for f in pick))
    return [scorer.percentile(diffs, 0.025), scorer.percentile(diffs, 0.975)]


def mcnemar_family(results: list[dict], units: list[dict]) -> list[dict]:
    """Pre-registered comparisons (PLAN.md 4.2) on the 2,656 paired eval units of the main layer, Holm over all."""
    def macro(k):
        return ok(get(results, k), "layer1")["macro"]

    tests = []
    for model, prefix in (("DeepSeek", "deepseek"), ("Qwen", "qwen")):
        for a, b in itertools.combinations(("L1", "L2", "L3", "L4"), 2):
            tests.append({"group": f"{model}: strategies", "a": f"{prefix}_{a}", "b": f"{prefix}_{b}"})
    for s in ("L1", "L2", "L3", "L4"):
        tests.append({"group": "DeepSeek vs Qwen", "a": f"deepseek_{s}", "b": f"qwen_{s}"})
    llms = [r["key"] for r in results if r["family"] in ("DeepSeek", "Qwen3.5-4B") and ok(r, "layer1")]
    statics = [r["key"] for r in results if r["family"] == "Static" and r["key"] != "grep" and ok(r, "layer1")]
    ranked = [r["key"] for r in results if r["ranked"] and r["key"] != "grep" and ok(r, "layer1")]
    best_llm, best_static = max(llms, key=macro), max(statics, key=macro)
    best = max(ranked, key=macro)
    tests.append({"group": "best LLM vs best static", "a": best_llm, "b": best_static})
    tests.append({"group": "best method vs grep", "a": best, "b": "grep"})
    for t in tests:
        ra, rb = get(results, t["a"])["_rows"]["layer1"][1], get(results, t["b"])["_rows"]["layer1"][1]
        t.update(scorer.mcnemar(units, ra, rb))
        t["acc_diff_ci"] = cluster_diff_ci(units, ra, rb)
        t["macro_a"], t["macro_b"] = macro(t["a"]), macro(t["b"])
    for t, adj in zip(tests, scorer.holm([t["p_value"] for t in tests])):
        t["p_holm"] = adj
    return tests


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def f3(v) -> str:
    return "--" if v is None else f"{v:.3f}"


def signed(v) -> str:
    return "--" if v is None else ("$-$" if v < -0.0005 else "+" if v > 0.0005 else "$\\pm$") + f"{abs(v):.3f}"


def ci_tex(ci) -> str:
    return "--" if not ci or ci[0] is None else f"[{ci[0]:.3f}, {ci[1]:.3f}]"


def pval(p: float) -> str:
    if p >= 0.001:
        return f"{p:.3f}"
    mant, exp = f"{p:.1e}".split("e")
    return f"\\ensuremath{{{mant}{{\\times}}10^{{{int(exp)}}}}}"


def tex_escape(s: str) -> str:
    return s.replace("\\", "\\textbackslash{}").replace("_", "\\_").replace("%", "\\%").replace("&", "\\&") \
        .replace("#", "\\#").replace("$", "\\$")


def label_tex(r: dict) -> str:
    return LABEL_TEX.get(r["key"], tex_escape(r["label"]))


def write_table(name: str, lines: list[str], sources: list[str]) -> None:
    head = ["% generated by figures/make_figures.py -- do not edit",
            "% src: juliet_full/analysis/score.py on " + "; ".join(sources)]
    (TABLES / name).write_text("\n".join(head + lines) + "\n")
    print(f"wrote tables/{name}")


def main_rows(results: list[dict], layer: str, families=MAIN_ORDER) -> list[dict]:
    rows = [r for r in results if r["family"] in families and ok(r, layer)]
    return sorted(rows, key=lambda r: families.index(r["family"]))


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------
def setup_style() -> None:
    gyre = Path.home() / ".local/share/texlive/2026/texmf-dist/fonts/opentype/public/tex-gyre"
    family = "DejaVu Serif"
    for name in ("texgyretermes-regular.otf", "texgyretermes-bold.otf", "texgyretermes-italic.otf"):
        if (gyre / name).exists():
            font_manager.fontManager.addfont(str(gyre / name))
            family = "TeX Gyre Termes"
    plt.rcParams.update({
        "font.family": family, "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7, "axes.edgecolor": INK,
        "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "text.color": INK,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.6,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6, "xtick.major.size": 2.5, "ytick.major.size": 2.5,
        "pdf.fonttype": 3, "savefig.bbox": "tight", "savefig.pad_inches": 0.02, "mathtext.fontset": "stix",
    })


def save(fig, name: str) -> None:
    fig.savefig(HERE / name, metadata={"CreationDate": None})
    plt.close(fig)
    print(f"wrote figures/{name}")


def short(v: float | None) -> str:
    return "–" if v is None else (f"{v:.3f}".replace("0.", ".", 1) if v < 1 else "1.0")


def label_points(ax, points: list[tuple[str, float, float, str, str]]) -> None:
    """Labels at hand-placed offsets (points: key, x, y, text, color); PARETO_OFFSET[key] = (dx pt, dy pt, ha)."""
    for key, x, y, text, color in points:
        dx, dy, ha = PARETO_OFFSET.get(key, (5, -3, "left"))
        ax.annotate(text, (x, y), xytext=(dx, dy), textcoords="offset points", fontsize=6.5, color=color,
                    ha=ha, va="bottom")


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
PARETO_LABEL = {"grep": "grep (1 µs)", "cppcheck": "Cppcheck", "clang_sa": "Clang SA", "infer": "Infer",
                "codeql": "CodeQL", "linevul": "LineVul", "deepseek_L1": "DeepSeek L1", "qwen_L1": "Qwen L1",
                "jev_L1": "Jev L1", "intern_L1": "Intern-Dec. L1", "lora_L1": "LoRA L1", "lora_L3": "LoRA L3",
                "valgrind": "Valgrind", "dynamic_enhanced": "Dyn.-enh.", "asan_lsan": "ASan/LSan"}
PARETO_OFFSET = {"lora_L1": (-5, -3, "right"), "deepseek_L1": (0, 3, "center"), "jev_L1": (5, -7, "left"),
                 "valgrind": (5, -10, "left"), "intern_L1": (-5, -3, "right"), "codeql": (0, 5, "center"),
                 "clang_sa": (5, 1, "left"), "grep": (5, 1, "left"), "linevul": (-5, -3, "right"),
                 "cppcheck": (5, -3, "left")}


def plot_pareto(results: list[dict], latency: dict[str, dict]) -> None:
    """Concurrency-1 median latency (log) vs main-layer macro-F1 with 95% CI; deployment budget bands."""
    fig, ax = plt.subplots(figsize=(3.45, 2.55), layout="constrained")
    xmin, xmax, floor = 4e-4, 20.0, 1.2e-3  # grep (1 µs) is drawn at `floor` with an off-scale arrow
    bands = [(xmin, 0.1, "IDE < 0.1 s"), (0.1, 1.0, "pre-commit < 1 s"), (1.0, 10.0, "CI < 10 s")]
    for (a, b, name), shade in zip(bands, ("#EAF1F8", "#FBF3E4", "#EAF1F8")):
        ax.axvspan(a, b, color=shade, zorder=0, lw=0)
        ax.text((a * b) ** 0.5, 1.035, name, ha="center", va="bottom", fontsize=6.5, color=GREY)
    pts, front_pts = [], []
    for r in results:
        info, lat = ok(r, "layer1"), latency.get(r["key"])
        if r["family"] == "Ablation" or lat is None or info is None:
            continue
        x, y = max(lat["median"], floor), info["macro"]
        color, marker = FAMILY_STYLE[r["family"]]
        if lat["median"] < floor:
            ax.annotate("", (xmin * 1.25, y), (x / 1.2, y),
                        arrowprops=dict(arrowstyle="-|>", color=color, lw=0.7, mutation_scale=6))
        if info["macro_ci"]:
            ax.plot([x, x], info["macro_ci"], color=color, lw=0.8, zorder=2)
        ax.scatter(x, y, s=22 if r["ranked"] else 18, marker=marker, color=color, zorder=3,
                   edgecolors="white", linewidths=0.4)
        if r["key"] == "codeql" and "codeql_amortized" in latency:
            xa = latency["codeql_amortized"]["median"]
            ax.plot([xa, x], [y, y], color=color, lw=0.6, ls=":", zorder=2)
            ax.scatter(xa, y, s=18, marker=marker, facecolors="white", edgecolors=color, linewidths=0.8, zorder=3)
        if r["ranked"]:
            front_pts.append((x, y))
        if r["key"] not in ("asan_lsan", "lora_L3"):
            text = "LoRA L1, L3" if r["key"] == "lora_L1" else PARETO_LABEL.get(r["key"], r["label"])
            pts.append((r["key"], x, y, text, color if r["ranked"] else GREY))
    ref = ok(get(results, "asan_lsan"), "layer1")
    if ref:
        ax.axhline(ref["macro"], color=GREY, ls="--", lw=0.7, zorder=1)
        ax.text(xmin * 1.2, ref["macro"] + 0.004, f"ASan/LSan {short(ref['macro'])} (reference)", fontsize=6.3,
                color=GREY, va="bottom")
    front, best = [], -1.0
    for x, y in sorted(front_pts):
        if y > best:
            front.append((x, y))
            best = y
    ax.step([p[0] for p in front], [p[1] for p in front], where="post", color=INK, lw=0.6, alpha=0.45, zorder=1)
    ax.set_xscale("log")
    ax.set_xlim(xmin, xmax)
    ax.set_ylim(0.44, 1.035)
    ax.set_yticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    label_points(ax, pts)
    ax.set_xlabel("median latency per unit at concurrency 1 (s, log scale)")
    ax.set_ylabel("macro-F1 on \\Deb{} (95% CI)".replace("\\Deb", "Debiased"))
    handles = [Line2D([], [], marker=FAMILY_STYLE[f][1], color=FAMILY_STYLE[f][0], ls="", markersize=4,
                      label={"Static": "static", "Learned": "LineVul", "DeepSeek": "DeepSeek", "Qwen3.5-4B": "Qwen",
                             "Decision": "decision models", "Dynamic": "dynamic (ref.)"}[f])
               for f in ("Static", "Learned", "DeepSeek", "Qwen3.5-4B", "Decision", "Dynamic")]
    handles += [Line2D([], [], marker="s", markerfacecolor="white", color=BLUE, ls=":", lw=0.6, markersize=4,
                       label="CodeQL, 50 units/db"),
                Line2D([], [], color=INK, alpha=0.45, lw=0.6, label="Pareto front")]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.45, -0.2), ncol=4, frameon=False,
              fontsize=6.3, handletextpad=0.3, columnspacing=0.8, handlelength=1.4, borderaxespad=0)
    save(fig, "pareto.pdf")


ROBUST_EXCLUDE = frozenset({"valgrind"})


def plot_robust(results: list[dict]) -> None:
    """Paired main-layer -> dead-free macro-F1 (arrow), placebo (diamond), delta on the right."""
    rows: list = []
    for fam in MAIN_ORDER:
        members = [r for r in results if r["family"] == fam and ok(r, "layer3") and r["key"] not in ROBUST_EXCLUDE]
        if members:
            rows.append(fam)
            rows += sorted(members, key=lambda r: -ok(r, "layer3")["d"]) if fam not in ("DeepSeek", "Qwen3.5-4B") \
                else members
    ys, y = [], 0.0
    for i, row in enumerate(rows):
        if isinstance(row, str) and i:
            y += 0.3
        ys.append(y)
        y += 0.85 if isinstance(row, str) else 1.0
    fig, ax = plt.subplots(figsize=(3.45, 0.102 * y + 0.5), layout="constrained")
    labels = []
    for row in rows:
        labels.append({"Static": "Static", "Learned": "Learned", "DeepSeek": "DeepSeek (nested25†)",
                       "Qwen3.5-4B": "Qwen3.5-4B", "Decision": "Decision models",
                       "Dynamic": "Dynamic (reference)"}[row] if isinstance(row, str) else
                      PARETO_LABEL.get(row["key"], row["label"]).replace(" (1 µs)", ""))
    ax.set_yticks(ys, labels)
    for tick, row in zip(ax.get_yticklabels(), rows):
        if isinstance(row, str):
            tick.set_fontweight("bold")
            tick.set_color(FAMILY_STYLE[row][0])
    ax.tick_params(axis="y", length=0, labelsize=6.8)
    ax.set_ylim(y - 0.4, -0.6)
    ax.set_xlim(0.3, 1.01)
    ax.spines["left"].set_visible(False)
    ax.grid(axis="x", color=LIGHT, lw=0.5, zorder=0)
    ax.set_axisbelow(True)
    for yy, r in zip(ys, rows):
        if isinstance(r, str):
            continue
        info = ok(r, "layer3")
        color = FAMILY_STYLE[r["family"]][0]
        a, b = info["base"], info["macro"]
        if abs(b - a) > 0.012:
            ax.annotate("", (b, yy), (a, yy), arrowprops=dict(arrowstyle="-|>", color=color, lw=1.0,
                                                              mutation_scale=6, shrinkA=0, shrinkB=1), zorder=3)
        ax.scatter(a, yy, s=14, facecolors="white", edgecolors=color, linewidths=0.9, zorder=4)
        ax.scatter(b, yy, s=14, color=color, zorder=4)
        pl = ok(r, "placebo")
        if pl and "base" in pl:
            ax.scatter(pl["macro"], yy, s=11, marker="D", facecolors="none", edgecolors=INK, linewidths=0.6,
                       zorder=5)
        d = info["d"]
        txt = "±0" if abs(d) < 0.0005 else f"{d:+.3f}".replace("-", "−")
        ax.text(1.015, yy, txt, transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=6.5,
                color=VERMIL if d < -0.05 else INK, clip_on=False)
    ax.text(1.015, -0.6, "Δ", transform=ax.get_yaxis_transform(), ha="left", va="bottom", fontsize=7)
    ax.set_xticks([0.4, 0.6, 0.8, 1.0], [".4", ".6", ".8", "1"])
    ax.set_xlabel("macro-F1 (paired units)")
    ax.legend(handles=[Line2D([], [], marker="o", markerfacecolor="white", color=INK, ls="", markersize=3.5,
                               label="Debiased"),
                        Line2D([], [], marker="o", color=INK, ls="", markersize=3.5, label="DeadFree"),
                        Line2D([], [], marker="D", markerfacecolor="none", color=INK, ls="", markersize=3,
                               label="Placebo")],
               loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, fontsize=6.8,
               handletextpad=0.2, columnspacing=1.0, borderaxespad=0.2)
    save(fig, "robust.pdf")


# ---------------------------------------------------------------------------
# numbers.tex
# ---------------------------------------------------------------------------
def write_numbers(results: list[dict], extra: dict[str, str]) -> None:
    lines = ["% generated by figures/make_figures.py -- do not edit",
             "% \\res{<method key>-<layer>}{<metric>}: p r f1 macro spec ci n tp fp tn fn; paired vs layer1: base d",
             "% lost gained flips (+ dci adj base_r base_spec); \\res{x}{<name>} = extra numbers; "
             "unknown or pending -> \\textit{pending}",
             "% src: juliet_full/analysis/score.py (eval set, family bootstrap 2000) on the files in "
             "generated/results_summary.json",
             "\\providecommand{\\res}[2]{\\ifcsname res-#1-#2\\endcsname\\csname res-#1-#2\\endcsname"
             "\\else\\textit{pending}\\fi}"]

    def put(name, metric, value):
        lines.append(f"\\expandafter\\def\\csname res-{name}-{metric}\\endcsname{{{value}}}")

    for r in results:
        for layer, info in r["layers"].items():
            if info["status"] != "ok":
                continue
            name = f"{r['key']}-{layer}"
            for m in ("p", "r", "f1", "macro", "spec", "base", "base_r", "base_spec"):
                if m in info:
                    put(name, m, f3(info[m]))
            for m in ("n", "tp", "fp", "tn", "fn", "lost", "gained", "flips", "base_fp", "base_fn"):
                if m in info:
                    put(name, m, f"{info[m]:,}")
            for m in ("d", "adj"):
                if m in info:
                    put(name, m, signed(info[m]))
            if info["macro_ci"]:
                put(name, "ci", ci_tex(info["macro_ci"]))
            if info.get("dci"):
                put(name, "dci", ci_tex(info["dci"]))
            for mech, v in info["recall_by_mech"].items():
                if v is not None:
                    put(name, f"r_{mech}", f3(v))
            for kind, v in info["spec_by_good_kind"].items():
                if v is not None:
                    put(name, f"spec_{kind}", f3(v))
            for cat, v in info["by_flow"].items():
                if v is not None:
                    put(name, f"flow_{cat}", f3(v))
    for k, v in extra.items():
        put("x", k, v)
    (GENERATED / "numbers.tex").write_text("\n".join(lines) + "\n")
    print("wrote generated/numbers.tex")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
PROBE_ROWS = [("static_void", "\\code{static void} $\\Rightarrow$ good"), ("func_count", "function count"),
              ("length_lines", "length (lines)"), ("length_tokens", "length (tokens)"),
              ("grep_v0", "grep: no \\code{free}/\\code{delete} $\\Rightarrow$ leak"),
              ("grep_v1", "grep v1: \\code{free} outside \\code{if} $\\Rightarrow$ good"),
              ("grep_v2", "grep v2: free-count threshold"), ("bow_lr", "bag-of-words LR")]


def write_probes_table() -> dict[str, str]:
    probes = json.loads(PROBES_PATH.read_text())
    lines = ["\\begin{table}[t]", "\\centering", "\\caption{Shortcut probes (macro-F1 on the 2,656 eval units; "
             "thresholds and the bag-of-words model are fitted on dev). The last row is the bag-of-words AUROC. "
             "A one-class predictor scores 0.333.}", "\\label{tab:probes}", "\\scriptsize", "\\setlength{\\tabcolsep}{3pt}",
             "\\begin{tabular}{@{}lrrrr@{}}", "\\toprule",
             "Probe & \\Orig{} & \\Deb{} & \\Dead{} & \\Plac{} \\\\", "\\midrule"]
    extra = {}
    for key, name in PROBE_ROWS + [("bow_auroc", "bag-of-words AUROC")]:
        cells = [name]
        for layer in LAYERS[3:] + LAYERS[:3]:
            p = probes[layer]["bow_lr"]["auroc"]["all"] if key == "bow_auroc" else probes[layer][key]["macro_f1"]["all"]
            cells.append(f"{p:.3f}")
            extra[f"probe_{key}_{layer}"] = f"{p:.3f}"
        lines.append(" & ".join(cells[:1] + [cells[1], cells[2], cells[3], cells[4]]) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_probes.tex", lines, ["juliet_full/data/build/probes_layer3.json (eval set)"])
    return extra


def write_orig_table(results: list[dict]) -> None:
    rows = []
    for r in results:
        o, l1 = ok(r, "original"), ok(r, "layer1")
        if not o or r["family"] == "Ablation":
            continue
        rows.append((r, o, l1))
    rows.sort(key=lambda t: -t[1]["macro"])
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Every method on original Juliet (\\Orig) and on our debiased units (\\Deb), macro-F1 on "
             "the same eval units. $\\Delta$ = \\Deb{} $-$ \\Orig. $^\\dagger$DeepSeek: nested25 subset "
             "(664 units). Dynamic tools are a reference, not ranked.}",
             "\\label{tab:orig}", "\\scriptsize", "\\setlength{\\tabcolsep}{4pt}", "\\begin{tabular}{@{}lrrr@{}}", "\\toprule",
             "Detector & \\Orig{} & \\Deb{} & $\\Delta$ \\\\", "\\midrule"]
    probes = json.loads(PROBES_PATH.read_text())
    sv = (probes["original"]["static_void"]["macro_f1"]["all"], probes["layer1"]["static_void"]["macro_f1"]["all"])
    lines.append(f"probe: \\code{{static void}} $\\Rightarrow$ good & {sv[0]:.3f} & {sv[1]:.3f} & "
                 f"{signed(sv[1] - sv[0])} \\\\")
    for r, o, _ in rows:
        name = label_tex(r) + ("$^\\dagger$" if o.get("subset") else "") + ("" if r["ranked"] else " (ref.)")
        if r["key"] == "grep":
            name = "grep (no \\code{free}/\\code{delete} $\\Rightarrow$ leak)"
        lines.append(f"{name} & {o['macro']:.3f} & {o['base']:.3f} & {signed(-o['d'])} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_orig.tex", lines, ["original/ and layer1/ runs listed in generated/results_summary.json",
                                        "probe row: juliet_full/data/build/probes_layer3.json"])


def family_header(fam: str, ncols: int) -> str:
    return f"\\multicolumn{{{ncols}}}{{@{{}}l}}{{\\textit{{{FAMILY_TEX[fam]}}}}} \\\\"


def write_main_table(results: list[dict]) -> None:
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Results on \\Deb{} (2,656 eval units). P, R, F1: leak class; Spec: specificity; macro-F1 "
             "with 95\\% family-cluster bootstrap CI. Invalid outputs count as wrong.}",
             "\\label{tab:main}", "\\scriptsize", "\\setlength{\\tabcolsep}{3.2pt}",
             "\\begin{tabular}{@{}lrrrrrl@{}}", "\\toprule",
             "Method & P & R & F1 & Spec & macro-F1 & 95\\% CI \\\\", "\\midrule"]
    fam = None
    for r in main_rows(results, "layer1"):
        info = ok(r, "layer1")
        if r["family"] != fam:
            if fam is not None:
                lines.append("\\addlinespace[2pt]")
            fam = r["family"]
            lines.append(family_header(fam, 7))
        lines.append(f"\\quad {label_tex(r)} & {f3(info['p'])} & {f3(info['r'])} & {f3(info['f1'])} & "
                     f"{f3(info['spec'])} & {f3(info['macro'])} & {ci_tex(info['macro_ci'])} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_main.tex", lines, ["layer1/ runs listed in generated/results_summary.json"])


FLOW_KEYS = ["grep", "cppcheck", "clang_sa", "infer", "codeql", "linevul", "deepseek_L1", "deepseek_L4",
             "qwen_L1", "qwen_L3", "jev_L3", "intern_L3", "lora_L1", "asan_lsan", "dynamic_enhanced"]


def write_flow_table(results: list[dict], units: list[dict]) -> dict[str, str]:
    n_flow = {c: sum(u["flow_category"] == c for u in units) for c in FLOW_CATEGORIES}
    n_mech = {m: sum(u["mechanism"] == m and u["truth"] == 1 for u in units) for m in MECHANISMS}
    n_kind = {k: sum(u.get("good_kind") == k for u in units) for k in GOOD_KINDS}
    lines = ["\\begin{table*}[t]", "\\centering",
             "\\caption{Breakdown by program type on \\Deb. Left: macro-F1 per flow-variant category (01 baseline; "
             "02--22 control flow; 31--45 data flow; 51--68 cross-file; 71--84 C++ objects). Middle: leak recall "
             "per allocation mechanism (bad units; destructor has only 2). Right: specificity per good kind "
             "(G2B, B2G, and the realloc goods ``other''). $n$ = eval units.}",
             "\\label{tab:flow}", "\\scriptsize", "\\setlength{\\tabcolsep}{4pt}",
             "\\begin{tabular}{@{}l rrrrr r rrrr r rrr@{}}", "\\toprule",
             " & \\multicolumn{5}{c}{macro-F1 by flow category} && \\multicolumn{4}{c}{recall by mechanism} && "
             "\\multicolumn{3}{c}{specificity by good kind} \\\\",
             "\\cmidrule(lr){2-6}\\cmidrule(lr){8-11}\\cmidrule(l){13-15}",
             "Method & 01 & 02--22 & 31--45 & 51--68 & 71--84 && \\code{malloc} & \\code{new} & realloc & dtor && "
             "G2B & B2G & other \\\\",
             "$n$ & " + " & ".join(f"{n_flow[c]:,}" for c in FLOW_CATEGORIES) + " && "
             + " & ".join(f"{n_mech[m]:,}" for m in MECHANISMS) + " && "
             + " & ".join(f"{n_kind[k]:,}" for k in GOOD_KINDS) + " \\\\", "\\midrule"]
    for key in FLOW_KEYS:
        r = get(results, key)
        info = ok(r, "layer1")
        if not info:
            continue
        cells = [label_tex(r) + ("" if r["ranked"] else " (ref.)")]
        cells += [f3(info["by_flow"].get(c)) for c in FLOW_CATEGORIES] + [""]
        cells += [f3(info["recall_by_mech"].get(m)) for m in MECHANISMS] + [""]
        cells += [f3(info["spec_by_good_kind"].get(k)) for k in GOOD_KINDS]
        lines.append(" & ".join(cells) + " \\\\")
        if key in ("linevul", "qwen_L3", "lora_L1"):
            lines.append("\\addlinespace[2pt]")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    write_table("res_flow.tex", lines, ["layer1/ runs listed in generated/results_summary.json"])
    extra = {f"n_flow_{c}": f"{n_flow[c]:,}" for c in FLOW_CATEGORIES}
    extra.update({f"n_mech_{m}": f"{n_mech[m]:,}" for m in MECHANISMS})
    extra.update({f"n_kind_{k}": f"{n_kind[k]:,}" for k in GOOD_KINDS})
    return extra


def write_robust_table(results: list[dict]) -> None:
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Robustness to never-executed frees, paired on the same units. \\Deb, \\Dead: macro-F1; "
             "$\\Delta$ = \\Dead{} $-$ \\Deb; $\\Delta_{\\mathrm{pl}}$ = \\Plac{} $-$ \\Deb; adj = $\\Delta - "
             "\\Delta_{\\mathrm{pl}}$; flips: changed verdicts; lost: leaks found on \\Deb{} and missed on \\Dead; "
             "new FP: goods correct on \\Deb{} and flagged on \\Dead. $^\\dagger$nested25 (664 units), else 2,656.}",
             "\\label{tab:robust}", "\\scriptsize", "\\setlength{\\tabcolsep}{1.5pt}",
             "\\begin{tabular}{@{}lrrrrrrrr@{}}", "\\toprule",
             "Method & \\Deb{} & \\Dead{} & $\\Delta$ & $\\Delta_{\\mathrm{pl}}$ & adj & flips & lost & new FP \\\\",
             "\\midrule"]
    fam = None
    for r in main_rows(results, "layer3"):
        if r["key"] in ROBUST_EXCLUDE:
            continue
        info, pl = ok(r, "layer3"), ok(r, "placebo")
        if r["family"] != fam:
            if fam is not None:
                lines.append("\\addlinespace[2pt]")
            fam = r["family"]
            lines.append(family_header(fam, 9))
        name = label_tex(r) + ("$^\\dagger$" if info.get("subset") else "")
        lines.append(f"\\quad {name} & {f3(info['base'])} & {f3(info['macro'])} & {signed(info['d'])} & "
                     f"{signed(pl['d']) if pl else '--'} & {signed(info['adj']) if 'adj' in info else '--'} & "
                     f"{info['flips']:,} & {info['lost']:,} & {info['gained']:,} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_robust.tex", lines, ["layer1/, layer3/ (data/results/*/stress/) and placebo/ runs in "
                                          "generated/results_summary.json"])


def write_lora_table(results: list[dict], folds: dict) -> None:
    def fold_auc(key, layer):
        per = folds.get(f"{key}-{layer}") or {}
        if "all" in per:
            return f3(per["all"]["auroc"])
        return "/".join(short(per[f]["auroc"]) for f in sorted(per)) if per else "--"

    rows = [("lora_L1", "LoRA L1"), ("lora_L3", "LoRA L3 (+Clang)"),
            ("readout_L1", "no LoRA, L1"), ("readout_L3", "no LoRA, L3"),
            ("lora_unmerged_L1", "unmerged L1"), ("lora_unmerged_L3", "unmerged L3")]
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Our LoRA decision model (3-fold CV; every unit scored by the adapter that did not train on "
             "it) against the same base model and read-out head without LoRA (threshold chosen on dev). "
             "R: leak recall on \\Dead. AUROC per fold 0/1/2 (one value for the single base model).}",
             "\\label{tab:lora}", "\\scriptsize", "\\setlength{\\tabcolsep}{1.4pt}",
             "\\begin{tabular}{@{}lrrrrll@{}}", "\\toprule",
             " & \\multicolumn{4}{c}{macro-F1 (R)} & \\multicolumn{2}{c}{AUROC} \\\\",
             "\\cmidrule(lr){2-5}\\cmidrule(l){6-7}",
             "Variant & \\Deb{} & \\Dead{} & R & \\Plac{} & \\Deb{} & \\Dead{} \\\\", "\\midrule"]
    for key, name in rows:
        r = get(results, key)
        l1, l3, pl = ok(r, "layer1"), ok(r, "layer3"), ok(r, "placebo")
        lines.append(f"{name} & {f3(l1['macro']) if l1 else '--'} & {f3(l3['macro']) if l3 else '--'} & "
                     f"{f3(l3['r']) if l3 else '--'} & {f3(pl['macro']) if pl else '--'} & "
                     f"{fold_auc(key, 'layer1')} & {fold_auc(key, 'layer3') if l3 else '--'} \\\\")
        if key == "lora_L3" or key == "readout_L3":
            lines.append("\\addlinespace[2pt]")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_lora.tex", lines, ["decision_ft/results/decision_ft/<layer>/L{1,3}_cv_v1.jsonl, "
                                        "unmerged_L*_fold*_v1.jsonl, qwen_readout_zeroshot/<layer>/L*_v1.jsonl"])


def write_repeat_table(reps: list[dict], det: dict) -> dict[str, str]:
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Run-to-run variation on \\Deb. Three runs (the main run and two repeats) on the repeat "
             "sample (eval $\\cap$ repeat100); Jev was repeated on all 2,656 eval units. Agreement = share of units "
             "with the same verdict in all three runs.}",
             "\\label{tab:repeat}", "\\footnotesize", "\\begin{tabular}{@{}lrrl@{}}", "\\toprule",
             "Model & units & agreement & macro-F1 per run \\\\", "\\midrule"]
    extra = {}
    for rep in reps:
        if rep["status"] != "ok":
            lines.append(f"{tex_escape(rep['label'])} & & \\textit{{pending}} & \\\\")
            continue
        key = rep["label"].replace(" ", "_")
        extra[f"rep_{key}"] = f"{rep['agree']:.3f}"
        extra[f"rep_{key}_n"] = f"{rep['n']:,}"
        lines.append(f"{tex_escape(rep['label'])} & {rep['n']:,} & {rep['agree']:.3f} & "
                     + "/".join(short(m) for m in rep["macros"]) + " \\\\")
    lines.append("\\midrule")
    for j in det["jev_full"]:
        extra[f"jev_full_{j['strategy']}_mean"] = f"{j['mean']:.3f}"
        extra[f"jev_full_{j['strategy']}_sd"] = f"{j['sd']:.4f}"
    d = det["intern_det"]
    lines.append(f"Intern-Dec. L1 rerun & {d['n']} & {d['same_pred'] / d['n']:.3f} & identical scores "
                 f"{d['same_score']}/{d['n']} \\\\")
    s = det["lora_spot"]
    lines.append(f"LoRA endpoint replay & {s['n']} & {1.0 if s['preds_match'] else 0.0:.3f} & "
                 f"max $|\\Delta s|$ = {s['max_abs_delta']:.1f} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    extra.update(intern_det_n=f"{d['n']}", intern_det_same=f"{d['same_pred']}", lora_spot_n=f"{s['n']}")
    write_table("res_repeat.tex", lines, ["registry repeats in figures/methods.json; "
                                          "gpu/results/intern_decision/layer1/det50_L1_r2.jsonl; "
                                          "decision_ft/runs/endpoint/spot_check.json"])
    return extra


LAT_ROWS = [("grep", "grep"), ("cppcheck", "Cppcheck"), ("clang_sa", "Clang SA"), ("infer", "Infer (Pulse)"),
            ("codeql", "CodeQL, 1 unit/db"), ("codeql_amortized", "CodeQL, 50 units/db"),
            ("linevul", "LineVul (GPU)"), ("linevul_cpu", "LineVul (CPU)"), ("lora_L1", "LoRA L1 (GPU)"),
            ("lora_L3", "LoRA L3 (GPU)$^\\ddagger$"), ("intern_L1", "Intern-Dec. L1 (GPU)"),
            ("qwen_L1", "Qwen L1 (GPU, vLLM)"), ("deepseek_L1", "DeepSeek L1 (API)"), ("jev_L1", "Jev L1 (API)"),
            ("asan_lsan", "ASan/LSan (ref.)"), ("valgrind", "Valgrind (ref.)"),
            ("dynamic_enhanced", "Dynamic-enh.\\ (ref.)")]
SRC_TAGS = {"lane_reports/2026-11-23_static_stage2.md": "a", "lane_reports/2026-11-23_gpu_stage1.md": "b",
            "lane_reports/2026-11-23_gpu_stage2.md": "c", "lane_reports/2026-11-23_decision_ft_stage2.md": "d",
            "lane_reports/2026-11-23_llm_stage2d.md": "e", "lane_reports/2026-11-23_data_stage4.md": "f"}


def fmt_lat(v: float) -> str:
    if v < 0.001:
        return "$<$0.001"
    return f"{v:.3f}" if v < 1 else f"{v:.2f}"


def write_latency_table(latency: dict[str, dict], costs: dict, train: dict[str, float]) -> dict[str, str]:
    extra = {}
    cost1k = {}
    for prov, sym in (("deepseek", "\\textyen"), ("jev", "\\$")):
        for s in ("L1", "L2", "L3", "L4"):
            c = costs.get((prov, f"eval_{s}_r1"))
            if c:
                v = 1000 * c["cost"] / c["calls"]
                cost1k[f"{prov}_{s}"] = f"{sym}{v:.3f}" if prov == "deepseek" else f"{sym}{v:.4f}"
                extra[f"cost1k_{prov}_{s}"] = f"{v:.3f}" if prov == "deepseek" else f"{v:.4f}"
    gpu_h = {k: 1000 * latency[k]["median"] / 3600 for k in ("lora_L1", "lora_L3", "intern_L1", "qwen_L1", "linevul")}
    for k, v in gpu_h.items():
        extra[f"gpuh1k_{k}"] = f"{v:.3f}"
    for k, row in latency.items():
        extra[f"lat_{k}"] = fmt_lat(row["median"]).replace("$<$", "<")
        extra[f"lat_{k}_p90"] = fmt_lat(row["p90"]).replace("$<$", "<")
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Latency per unit at concurrency 1 on the 300-unit latency sample (CodeQL per unit: 20 units; "
             "LineVul GPU: server side) as median and p90 in seconds, compile time included for dynamic tools, and marginal cost per 1,000 units: API price paid "
             "(off-peak DeepSeek, from the call ledger) or GPU-hours at the measured median. Sources: "
             "lane reports (a) static\\_stage2, (b) gpu\\_stage1, (c) gpu\\_stage2, (d) decision\\_ft\\_stage2, "
             "(e) llm\\_stage2d, (f) data\\_stage4, recomputed from the latency files where they exist. "
             "$^\\ddagger$Our LoRA training cost "
             f"{sum(train.values()):.1f} GPU-hours in total (six adapters, RTX 3090).}}",
             "\\label{tab:latency}", "\\scriptsize", "\\setlength{\\tabcolsep}{3pt}",
             "\\begin{tabular}{@{}lrrlc@{}}", "\\toprule", "Method & median & p90 & cost / 1k units & src \\\\",
             "\\midrule"]
    cost_cell = {"deepseek_L1": cost1k.get("deepseek_L1", "--"), "jev_L1": cost1k.get("jev_L1", "--")}
    for k in ("lora_L1", "lora_L3", "intern_L1", "qwen_L1", "linevul"):
        cost_cell[k] = f"{gpu_h[k]:.3f} GPU-h"
    for key, name in LAT_ROWS:
        row = latency.get(key)
        if not row:
            continue
        lines.append(f"{name} & {fmt_lat(row['median'])} & {fmt_lat(row['p90'])} & {cost_cell.get(key, 'CPU')} & "
                     f"{SRC_TAGS.get(row['source'], '?')} \\\\")
        if key in ("codeql_amortized", "jev_L1"):
            lines.append("\\midrule")
    lines += ["\\midrule",
              "\\multicolumn{5}{@{}p{\\linewidth}@{}}{DeepSeek L1/L2/L3/L4: " + " / ".join(cost1k.get(f"deepseek_{s}", "--")
                                                                        for s in ("L1", "L2", "L3", "L4"))
              + "; Jev L1/L2/L3: " + " / ".join(cost1k.get(f"jev_{s}", "--") for s in ("L1", "L2", "L3"))
              + " per 1k} \\\\", "\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_latency.tex", lines, ["figures/latency_c1.csv (latency files listed there)",
                                           "juliet_full/llm/ledger.jsonl", "decision_ft/runs/L?/fold?/train_log.jsonl"])
    return extra


def write_mcnemar_table(tests: list[dict], results: list[dict]) -> dict[str, str]:
    names = {r["key"]: label_tex(r) for r in results}
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{Pre-registered paired McNemar tests on the 2,656 \\Deb{} eval units (correct/incorrect per "
             "unit). $b$: only A right; $c$: only B right; $p$: exact binomial if $b+c\\le 25$, else "
             "continuity-corrected $\\chi^2$; Holm over all 18 tests. Last column: 95\\% family-cluster "
             "bootstrap CI of the accuracy difference A $-$ B.}",
             "\\label{tab:mcnemar}", "\\scriptsize", "\\setlength{\\tabcolsep}{2pt}",
             "\\begin{tabular}{@{}llrrrrl@{}}", "\\toprule",
             "A & B & $b$ & $c$ & $p$ & $p_{\\mathrm{Holm}}$ & $\\Delta$acc CI \\\\", "\\midrule"]
    extra = {}
    group = None
    for i, t in enumerate(tests, 1):
        if t["group"] != group:
            if group is not None:
                lines.append("\\addlinespace[2pt]")
            group = t["group"]
            lines.append(f"\\multicolumn{{7}}{{@{{}}l}}{{\\textit{{{group}}}}} \\\\")
        ci = t["acc_diff_ci"]
        lines.append(f"{names[t['a']]} & {names[t['b']]} & {t['a_only_right']} & {t['b_only_right']} & "
                     f"{pval(t['p_value'])} & {pval(t['p_holm'])} & [{ci[0]:+.3f}, {ci[1]:+.3f}] \\\\")
        tag = f"mc_{t['a']}_vs_{t['b']}".replace("_", "")
        extra[f"{tag}_p"] = pval(t["p_value"])
        extra[f"{tag}_holm"] = pval(t["p_holm"])
        extra[f"{tag}_b"] = f"{t['a_only_right']}"
        extra[f"{tag}_c"] = f"{t['b_only_right']}"
    extra["mc_n_sig"] = str(sum(t["p_holm"] < 0.05 for t in tests))
    extra["mc_n_tests"] = str(len(tests))
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_mcnemar.tex", lines, ["layer1/ runs in generated/results_summary.json; "
                                           "scorer.mcnemar and scorer.holm"])
    return extra


def write_full_tables(results: list[dict]) -> None:
    """Appendix: every method and variant on every layer."""
    lines = ["\\begin{table*}[t]", "\\centering",
             "\\caption{Full results on \\Deb{} (2,656 eval units), including the ablations and the "
             "secondary-threshold variants (thresholds frozen on dev).}",
             "\\label{tab:full-main}", "\\scriptsize", "\\setlength{\\tabcolsep}{4pt}",
             "\\begin{tabular}{@{}lrrrrrrrrrll@{}}", "\\toprule",
             "Method & TP & FP & TN & FN & inv. & P & R & F1 & Spec & macro-F1 & 95\\% CI \\\\", "\\midrule"]
    for r in main_rows(results, "layer1", MAIN_ORDER + ("Ablation",)):
        i = ok(r, "layer1")
        lines.append(f"{label_tex(r)} & {i['tp']:,} & {i['fp']:,} & {i['tn']:,} & {i['fn']:,} & {i['invalid']} & "
                     f"{f3(i['p'])} & {f3(i['r'])} & {f3(i['f1'])} & {f3(i['spec'])} & {f3(i['macro'])} & "
                     f"{ci_tex(i['macro_ci'])} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    write_table("res_full_main.tex", lines, ["layer1/ runs in generated/results_summary.json"])

    lines = ["\\begin{table*}[t]", "\\centering",
             "\\caption{Macro-F1 [95\\% CI] on every layer, with the paired change from \\Deb{} and its 95\\% "
             "family-cluster bootstrap CI. $^\\dagger$nested25 (664 units).}",
             "\\label{tab:full-layers}", "\\scriptsize", "\\setlength{\\tabcolsep}{3pt}",
             "\\begin{tabular}{@{}lllll@{}}", "\\toprule",
             "Method & \\Deb{} & \\Dead: macro-F1; $\\Delta$ [CI] & \\Plac: macro-F1; $\\Delta$ [CI] & "
             "\\Orig: macro-F1; $\\Delta$ [CI] \\\\", "\\midrule"]
    for r in main_rows(results, "layer1", MAIN_ORDER + ("Ablation",)):
        cells = [label_tex(r), f"{f3(ok(r, 'layer1')['macro'])} {ci_tex(ok(r, 'layer1')['macro_ci'])}"]
        for layer in ("layer3", "placebo", "original"):
            i = ok(r, layer)
            if not i:
                cells.append("--")
                continue
            dag = "$^\\dagger$" if i.get("subset") else ""
            cells.append(f"{f3(i['macro'])}{dag}; {signed(i['d'])} {ci_tex(i.get('dci'))}")
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table*}"]
    write_table("res_full_layers.tex", lines, ["all runs in generated/results_summary.json"])


def write_folds_table(folds: dict) -> None:
    lines = ["\\begin{table}[t]", "\\centering",
             "\\caption{LoRA decision model per cross-validation fold: macro-F1 / AUROC of the adapter that did not "
             "train on the fold (merged weights; unmerged in the last rows, \\Deb{} only).}",
             "\\label{tab:folds}", "\\scriptsize", "\\setlength{\\tabcolsep}{3pt}",
             "\\begin{tabular}{@{}llrrr@{}}", "\\toprule", "Model & Layer & fold 0 & fold 1 & fold 2 \\\\",
             "\\midrule"]
    for key, name in (("lora_L1", "LoRA L1"), ("lora_L3", "LoRA L3"), ("lora_unmerged_L1", "unmerged L1"),
                      ("lora_unmerged_L3", "unmerged L3")):
        for layer in LAYERS:
            per = folds.get(f"{key}-{layer}")
            if not per:
                continue
            cells = [name, LAYER_TEX[layer]] + [f"{short(per[f]['macro'])} / {short(per[f]['auroc'])}"
                                                for f in (0, 1, 2)]
            lines.append(" & ".join(cells) + " \\\\")
    lines.append("\\midrule")
    lines.append("$n$ (eval units) & \\Deb{} & " + " & ".join(str(folds["lora_L1-layer1"][f]["n"]) for f in (0, 1, 2))
                 + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    write_table("res_folds.tex", lines, ["decision_ft/results/decision_ft/<layer>/*.jsonl (extra.fold)"])


def write_provenance(results: list[dict], latency: dict[str, dict]) -> None:
    """Full provenance list -> generated/provenance.tsv (kind, method, layer, file, sha256);
    the paper gets a short paragraph with the count and the key inputs (parent change, 2026-11-23)."""
    rows = []
    seen = set()
    for r in results:
        for layer, info in r["layers"].items():
            if info["status"] != "ok":
                continue
            for f, h in zip(info["files"], info["sha256"]):
                rows.append(("result", r["label"], layer, f, h))
                seen.add(f)
    for key, row in latency.items():
        if row["file"] and row["file"] not in seen:
            rows.append(("latency", key, "latency300", row["file"], sha256(JULIET_FULL / row["file"])))
            seen.add(row["file"])
    inputs = ("data/build/layer1.jsonl", "data/build/subsets.json", "data/build/probes_layer3.json",
              "llm/ledger.jsonl", "llm/results/jev_thresholds.json")
    for rel in inputs:
        rows.append(("input", "-", "-", rel, sha256(JULIET_FULL / rel)))
    tsv = GENERATED / "provenance.tsv" if "GENERATED" in globals() else TABLES.parent / "generated" / "provenance.tsv"
    tsv.write_text("kind\tmethod\tlayer\tfile\tsha256\n" + "".join("\t".join(x) + "\n" for x in rows))
    n_files = len({x[3] for x in rows})
    layer1_sha = sha256(JULIET_FULL / "data/build/layer1.jsonl")
    lines = [
        f"The generator lists all {n_files} files it reads (prediction files, latency samples and inputs),",
        "each with its SHA-256, to \\code{report/final\\_en/generated/provenance.tsv} in the project repository.",
        f"The benchmark file \\code{{data/build/layer1.jsonl}} has SHA-256 prefix \\code{{{layer1_sha[:16]}}}.",
    ]
    (TABLES / "res_provenance.tex").write_text("% generated by figures/make_figures.py -- do not edit\n"
                                               + "\n".join(lines) + "\n")
    print("wrote tables/res_provenance.tex and generated/provenance.tsv")


# ---------------------------------------------------------------------------
# Extra numbers
# ---------------------------------------------------------------------------
def demo_numbers() -> dict[str, str]:
    if not DEMO_PATH.exists():
        return {}
    rec = json.loads(DEMO_PATH.read_text())
    return {"demo_run": tex_escape(rec["run_id"]), "demo_cny": f"{rec['spent']['deepseek']:.4f}",
            "demo_usd": f"{rec['spent']['jev']:.5f}"}


def cost_numbers(costs: dict) -> dict[str, str]:
    out = {}
    for prov in ("deepseek", "jev"):
        out[f"cost_{prov}"] = f"{sum(c['cost'] for (p, _), c in costs.items() if p == prov):.2f}"
        out[f"calls_{prov}"] = f"{sum(c['calls'] for (p, _), c in costs.items() if p == prov):,}"
    return out


def unmerged_flips(results: list[dict]) -> dict[str, str]:
    out = {}
    for s in ("L1", "L3"):
        a = get(results, f"lora_{s}")["_rows"].get("layer1")
        b = get(results, f"lora_unmerged_{s}")["_rows"].get("layer1")
        if a and b:
            out[f"unmerged_flips_{s}"] = f"{lost_gained(a[0], a[1], b[1])[2]:,}"
    return out


def fold_numbers(folds: dict) -> dict[str, str]:
    out = {}
    for name, per in folds.items():
        key = name.replace("-", "_")
        for f, m in per.items():
            if m.get("auroc") is not None:
                out[f"auroc_{key}_f{f}"] = f3(m["auroc"])
            if m.get("macro") is not None:
                out[f"macro_{key}_f{f}"] = f3(m["macro"])
    return out


def train_numbers(train: dict[str, float]) -> dict[str, str]:
    out = {f"ft_hours_{k}": f"{v:.2f}" for k, v in train.items()}
    out["ft_hours_total"] = f"{sum(train.values()):.1f}"
    return out


def breakdown_numbers(results: list[dict], units: list[dict], subsets: dict[str, set]) -> dict[str, str]:
    """Counts used in the text: where errors fall on the dead-free layer and on the main layer."""
    out = {"n_eval": f"{len(units):,}",
           "n_nested25": f"{sum(u['group_id'] in subsets['nested25'] for u in units):,}"}
    for key in ("deepseek_L1", "deepseek_L4", "qwen_L1", "qwen_L3", "intern_L1", "intern_L3", "jev_L1", "jev_L3",
                "lora_L1", "lora_L3", "codeql", "grep", "clang_sa", "infer"):
        r = get(results, key)
        for layer in ("layer1", "layer3"):
            if layer not in r["_rows"]:
                continue
            us, rows = r["_rows"][layer]
            index, _ = scorer.index_predictions(rows)
            for kind in GOOD_KINDS:
                g = [u for u in us if u.get("good_kind") == kind]
                fp = sum(scorer.valid_pred(index.get(u["unit_id"])) != 0 for u in g)
                out[f"fp_{key}_{layer}_{kind}"] = f"{fp}"
                out[f"n_{key}_{layer}_{kind}"] = f"{len(g)}"
            for mech in MECHANISMS:
                b = [u for u in us if u["mechanism"] == mech and u["truth"] == 1]
                fn = sum(scorer.valid_pred(index.get(u["unit_id"])) != 1 for u in b)
                out[f"fn_{key}_{layer}_{mech}"] = f"{fn}"
    return out


# ---------------------------------------------------------------------------
def main() -> None:
    GENERATED.mkdir(exist_ok=True)
    TABLES.mkdir(exist_ok=True)
    setup_style()
    registry = json.loads(REGISTRY_PATH.read_text())
    units = [u for u in read_jsonl(UNITS_PATH) if u.get("set") == EVAL_SET]
    subsets = {k: set(v) for k, v in json.loads(SUBSETS_PATH.read_text()).items()}
    latency = read_latency()
    results = collect(registry, units, subsets)
    costs = ledger_costs()
    train = ft_training()
    folds = fold_metrics(results)
    reps = repeats(registry, units)
    det = determinism(units)
    tests = mcnemar_family(results, units)

    plot_pareto(results, latency)
    plot_robust(results)
    extra = {**demo_numbers(), **cost_numbers(costs), **unmerged_flips(results), **write_probes_table()}
    write_orig_table(results)
    write_main_table(results)
    extra.update(write_flow_table(results, units))
    write_robust_table(results)
    write_lora_table(results, folds)
    extra.update(write_repeat_table(reps, det))
    extra.update(write_latency_table(latency, costs, train))
    extra.update(write_mcnemar_table(tests, results))
    write_full_tables(results)
    write_folds_table(folds)
    write_provenance(results, latency)
    extra.update(fold_numbers(folds))
    extra.update(train_numbers(train))
    extra.update(breakdown_numbers(results, units, subsets))
    write_numbers(results, extra)

    summary = [{k: v for k, v in r.items() if k != "_rows"} for r in results]
    (GENERATED / "results_summary.json").write_text(json.dumps(
        {"generated": dt.datetime.now().isoformat(timespec="seconds"), "scorer": "juliet_full/analysis/score.py",
         "set": EVAL_SET, "bootstrap": BOOTSTRAP, "methods": summary, "mcnemar": tests, "repeats": reps,
         "determinism": det, "folds": {k: {str(f): v for f, v in per.items()} for k, per in folds.items()},
         "ft_training_hours": train, "latency": latency}, indent=1))
    print("wrote generated/results_summary.json")
    for r in results:
        cells = []
        for layer in LAYERS:
            if layer in r["layers"]:
                info = r["layers"][layer]
                cells.append(f"{layer} " + (f"{info['macro']:.3f}" + (f" (Δ{info['d']:+.3f})" if "d" in info else "")
                                            if info["status"] == "ok" else "PENDING"))
        print(f"  {r['key']:<20} " + " | ".join(cells))
    for t in tests:
        print(f"  McNemar {t['a']} vs {t['b']}: b={t['a_only_right']} c={t['b_only_right']} "
              f"p={t['p_value']:.3g} holm={t['p_holm']:.3g}")


if __name__ == "__main__":
    main()

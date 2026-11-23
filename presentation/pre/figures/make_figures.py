#!/usr/bin/env python3
"""Render the result figures of the pre from whatever result files exist.

Read-only on juliet_full/: result files follow the lane contract
juliet_full/<lane>/results/<method>/<layer>/<run_id>.jsonl (+ .meta.json); they are scored on the eval set
(39 flow variants, 2,656 units) with juliet_full/analysis/score.py when it is importable, else with the
small fallback below.  Methods without an eval run that covers >= min_coverage of the eval units are drawn
as "pending" (never as numbers).

Outputs (next to this file): probes.pdf, prf1.pdf, pareto.pdf, heatmap.pdf, results_summary.json,
numbers.tex (\\res{key}{metric} macros) and provenance.tex (backup-slide table).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import statistics
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parents[2] / "juliet_full"
UNITS_PATH = JULIET_FULL / "data" / "build" / "layer1.jsonl"
PROBES_PATH = JULIET_FULL / "data" / "build" / "probes.json"
REGISTRY_PATH = HERE / "methods.json"
EVAL_SET = "eval"
FLOW_CATEGORIES = ["01", "02-22", "31-45", "51-68", "71-84"]
FLOW_LABELS = {"01": "01\nbaseline", "02-22": "02–22\ncontrol flow", "31-45": "31–45\ndata flow",
               "51-68": "51–68\ncross-file", "71-84": "71–84\nC++ objects"}
FAMILY_LABELS = {"Static": "Static analysis", "Learned": "Learned", "DeepSeek": "DeepSeek V4.1 Flash",
                 "Qwen3.5-4B": "Qwen3.5-4B (SLM)", "Decision": "Decision models", "Dynamic": "Dynamic (ref.)"}
# Okabe-Ito
BLUE, SKY, ORANGE, GREEN, VERMIL, PURPLE, YELLOW = "#0072B2", "#56B4E9", "#E69F00", "#009E73", "#D55E00", "#CC79A7", "#F0E442"
INK, GREY, LIGHT = "#26303A", "#8A939C", "#ECEFF3"
FAMILY_STYLE = {"Static": (BLUE, "s"), "Learned": (PURPLE, "D"), "DeepSeek": (VERMIL, "o"),
                "Qwen3.5-4B": (ORANGE, "^"), "Decision": (GREEN, "v"), "Dynamic": (GREY, "x")}
BOOTSTRAP = 2000

sys.dont_write_bytecode = True  # do not leave __pycache__ in juliet_full/analysis
sys.path.insert(0, str(JULIET_FULL / "analysis"))
try:
    import score as scorer  # juliet_full/analysis/score.py
except ImportError:  # pragma: no cover - fallback when the scorer is absent
    scorer = None


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def fallback_score(units: list[dict], preds: list[dict]) -> dict:
    """P/R/F1 with leak as positive class; missing/invalid predictions count as wrong (same rule as score.py)."""
    index = {r["unit_id"]: r for r in preds}

    def metrics(pairs):
        tp = fp = tn = fn = 0
        for truth, pred in pairs:
            pred = pred if pred in (0, 1) else 1 - truth
            tp += truth == 1 and pred == 1
            fn += truth == 1 and pred == 0
            fp += truth == 0 and pred == 1
            tn += truth == 0 and pred == 0
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        p0 = tn / (tn + fn) if tn + fn else 0.0
        r0 = tn / (tn + fp) if tn + fp else 0.0
        f0 = 2 * p0 * r0 / (p0 + r0) if p0 + r0 else 0.0
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision_leak": p, "recall_leak": r, "f1_leak": f,
                "macro_f1": (f + f0) / 2}

    pairs = [(int(u["truth"]), (index.get(u["unit_id"]) or {}).get("pred")) for u in units]
    by_cat = {}
    for cat in sorted({u["flow_category"] for u in units}):
        by_cat[cat] = metrics([pair for pair, u in zip(pairs, units) if u["flow_category"] == cat])
    lat = [r["latency_s"] for r in index.values() if isinstance(r.get("latency_s"), (int, float))]
    return {"end_to_end": metrics(pairs), "by_flow_category": by_cat,
            "latency": {"median_s": statistics.median(lat) if lat else None}}


def score_units(units: list[dict], preds: list[dict]) -> dict:
    if scorer is not None:
        return scorer.score(units, preds, bootstrap=BOOTSTRAP)
    return fallback_score(units, preds)


# ---------------------------------------------------------------------------
# Run selection
# ---------------------------------------------------------------------------
def is_prediction_file(path: Path) -> bool:
    return (path.suffix == ".jsonl" and not path.name.endswith(".evidence.jsonl") and path.name != "evidence.jsonl"
            and not {"raw_logs", "scratch", ".venv"} & set(path.parts))


def load_rows(path: Path, entry: dict) -> list[dict]:
    if entry.get("loader") == "verify":  # label verification run (ASan/LSan, use_stacks=0)
        rows = []
        for r in read_jsonl(path):
            if r.get("layer") != "layer1":
                continue
            leak = r["verify"].get("asan_leak")
            rows.append({"unit_id": r["unit_id"], "method": "asan_lsan", "pred": None if leak is None else int(leak),
                         "latency_s": None, "status": "ok"})
        return rows
    rows = read_jsonl(path)
    if entry.get("strategy"):
        rows = [r for r in rows if r.get("strategy") == entry["strategy"]]
    if entry.get("own_fold"):
        rows = [r for r in rows if (r.get("extra") or {}).get("fold") == (r.get("extra") or {}).get("unit_fold")]
    return rows


def read_meta(path: Path) -> dict:
    meta = path.with_name(path.name[: -len(".jsonl")] + ".meta.json")
    try:
        return json.loads(meta.read_text())
    except (OSError, ValueError):
        return {}


def candidates(entry: dict) -> list[list[Path]]:
    """One list per glob, newest file first, duplicates across globs dropped."""
    seen: set[Path] = set()
    out = []
    for pattern in entry["globs"]:
        files = [p for p in JULIET_FULL.glob(pattern) if p.is_file() and is_prediction_file(p) and p not in seen]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        seen.update(files)
        out.append(files)
    return out


def coverage(rows: list[dict], eval_ids: set[str]) -> float:
    return len({r["unit_id"] for r in rows} & eval_ids) / len(eval_ids)


def select_run(entry: dict, eval_ids: set[str], min_cov: float) -> dict:
    """Returns {"rows", "files", "coverage", "meta"}; rows is None when nothing reaches min_cov."""
    best_partial = 0.0
    groups = candidates(entry)
    if entry.get("mode") == "union":
        files = sorted({p for g in groups for p in g}, key=lambda p: p.stat().st_mtime)
        merged: dict[str, dict] = {}
        for path in files:  # newer file wins per unit
            for r in load_rows(path, entry):
                merged[r["unit_id"]] = r
        rows = list(merged.values())
        cov = coverage(rows, eval_ids) if rows else 0.0
        metas = [read_meta(p) for p in files]
        used = [p for p in files if load_rows(p, entry)]
        return {"rows": rows if cov >= min_cov else None, "files": used, "coverage": cov,
                "meta": metas[-1] if metas else {}}
    for files in groups:
        for path in files:
            rows = load_rows(path, entry)
            cov = coverage(rows, eval_ids) if rows else 0.0
            if cov >= min_cov:
                return {"rows": rows, "files": [path], "coverage": cov, "meta": read_meta(path)}
            best_partial = max(best_partial, cov)
    return {"rows": None, "files": [], "coverage": best_partial, "meta": {}}


def latency_is_c1(meta: dict, rows: list[dict]) -> bool:
    """True when latency was recorded per unit at concurrency 1 (solid marker); batched/amortized or concurrent
    runs (also inside merged runs' source_metas or rows' extra.batch_size) are drawn hollow."""
    metas = [meta, *(meta.get("source_metas") or {}).values()]
    if any(m.get("timing_mode") == "batched" or m.get("concurrency") not in (1, None) for m in metas):
        return False
    return not any((r.get("extra") or {}).get("batch_size") not in (None, 1) for r in rows)


def sha_short(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(p.read_bytes())
    return h.hexdigest()[:8]


def collect() -> tuple[list[dict], dict]:
    registry = json.loads(REGISTRY_PATH.read_text())
    units = [u for u in read_jsonl(UNITS_PATH) if u.get("set") == EVAL_SET]
    eval_ids = {u["unit_id"] for u in units}
    results = []
    for entry in registry["methods"]:
        run = select_run(entry, eval_ids, registry["min_coverage"])
        res = {"key": entry["key"], "label": entry["label"], "family": entry["family"],
               "strategy": entry.get("strategy"), "ranked": entry.get("ranked", True),
               "coverage": round(run["coverage"], 4),
               "files": [str(p.relative_to(JULIET_FULL)) for p in run["files"]]}
        if run["rows"] is None:
            res["status"] = "pending"
        else:
            rep = score_units(units, run["rows"])
            e2e = rep["end_to_end"]
            ci = (rep.get("bootstrap") or {}).get("ci95", {})
            meta = run["meta"]
            res.update({
                "status": "ok", "sha256_8": sha_short(run["files"]), "n_units": len(units),
                "tp": e2e["tp"], "fp": e2e["fp"], "tn": e2e["tn"], "fn": e2e["fn"],
                "precision": e2e["precision_leak"], "recall": e2e["recall_leak"], "f1": e2e["f1_leak"],
                "macro_f1": e2e["macro_f1"], "f1_ci95": ci.get("f1_leak"),
                "latency_median_s": rep["latency"]["median_s"], "latency_p90_s": rep["latency"].get("p90_s"),
                "concurrency": meta.get("concurrency"), "timing_mode": meta.get("timing_mode"),
                "by_flow_f1": {c: m["f1_leak"] for c, m in rep["by_flow_category"].items()},
            })
            res["latency_c1"] = latency_is_c1(meta, run["rows"])
        results.append(res)
    return results, registry


# ---------------------------------------------------------------------------
# Plot style
# ---------------------------------------------------------------------------
def setup_style() -> None:
    fira = Path.home() / ".local/share/texlive/2026/texmf-dist/fonts/opentype/public/fira"
    family = "DejaVu Sans"
    for name in ("FiraSans-Regular.otf", "FiraSans-Medium.otf", "FiraSans-Italic.otf", "FiraSans-SemiBold.otf"):
        if (fira / name).exists():
            font_manager.fontManager.addfont(str(fira / name))
            family = "Fira Sans"
    plt.rcParams.update({
        "font.family": family, "font.size": 10, "axes.titlesize": 10.5, "axes.labelsize": 10,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9, "axes.edgecolor": INK,
        "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "text.color": INK,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.7,
        "pdf.fonttype": 3, "savefig.bbox": "tight", "savefig.pad_inches": 0.03,
    })


def stamp(fig) -> None:
    fig.suptitle(f"PRELIMINARY · eval set · {dt.date.today().isoformat()}", x=0.995, ha="right", fontsize=6.5,
                 color=GREY)


def pending_summary(results: list[dict]) -> str:
    """'pending: Infer · DeepSeek L1–L4 · ...' (strategies of one method collapsed)."""
    groups: dict[str, list[str]] = {}
    for r in results:
        if r["status"] == "ok":
            continue
        name = r["label"] if r["family"] in ("Static", "Learned", "Decision", "Dynamic") else f"{r['family']} {r['label']}"
        head, _, tail = name.rpartition(" ")
        if tail[:1] == "L" and tail[1:].isdigit() and head:
            groups.setdefault(head, []).append(tail)
        else:
            groups.setdefault(name, [])
    parts = []
    for head, strategies in groups.items():
        nums = [int(t[1:]) for t in strategies]
        if len(nums) > 2 and nums == list(range(nums[0], nums[-1] + 1)):
            parts.append(f"{head} L{nums[0]}–L{nums[-1]}")
        elif nums:
            parts.append(f"{head} " + ", ".join(strategies))
        else:
            parts.append(head)
    return "pending: " + " · ".join(parts) if parts else ""


def save(fig, name: str) -> None:
    fig.savefig(HERE / name, metadata={"CreationDate": None})
    plt.close(fig)
    print(f"wrote figures/{name}")


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def plot_probes() -> None:
    """Shortcut probes, original Juliet vs debiased layer 1 (eval macro-F1, from data/build/probes.json)."""
    probes = json.loads(PROBES_PATH.read_text())
    rows = [("static_void", "'static void' → good"), ("func_count", "# functions"), ("length_lines", "# lines"),
            ("length_tokens", "# tokens"), ("grep_v0", "grep: no free/delete → leak"),
            ("bow_lr", "bag-of-words LR")]
    fig, ax = plt.subplots(figsize=(3.8, 2.6), layout="constrained")
    for i, (key, label) in enumerate(rows):
        a = probes["original"][key]["macro_f1"]["all"]
        b = probes["layer1"][key]["macro_f1"]["all"]
        ax.plot([b, a], [i, i], color=GREY, lw=1.6, zorder=1)
        ax.scatter([a], [i], s=40, color=VERMIL, marker="o", zorder=3)
        ax.scatter([b], [i], s=44, color=BLUE, marker="D", zorder=3)
        ax.text(a + 0.045, i, f"{a:.3f}", va="center", ha="left", fontsize=8, color=VERMIL)
        ax.text(b - 0.045, i, f"{b:.3f}", va="center", ha="right", fontsize=8, color=BLUE)
    ax.axvline(1 / 3, color=GREY, ls=":", lw=0.8)
    ax.text(1 / 3 + 0.008, -0.75, "one-class predictor", fontsize=6.5, color=GREY, va="center")
    ax.set_yticks(range(len(rows)), [r[1] for r in rows])
    ax.set_ylim(len(rows) - 0.5, -1.1)
    ax.set_xlim(0.12, 1.13)
    ax.set_xlabel("macro-F1 on the eval set (2,656 units)")
    ax.legend(handles=[Line2D([], [], marker="o", color=VERMIL, ls="", label="original Juliet"),
                       Line2D([], [], marker="D", color=BLUE, ls="", label="debiased layer 1")],
              loc="lower left", frameon=False, ncol=2, bbox_to_anchor=(0.0, 1.0), borderaxespad=0.1)
    save(fig, "probes.pdf")


def plot_prf1(results: list[dict]) -> None:
    ranked = [r for r in results if r["ranked"]]
    ref = [r for r in results if not r["ranked"] and r["status"] == "ok"]
    fig, ax = plt.subplots(figsize=(6.6, 2.4), layout="constrained")
    width, gap = 0.27, 0.6
    x, xs, fam_spans = 0.0, [], []
    prev = None
    for r in ranked:
        if prev is not None and r["family"] != prev:
            x += gap
        xs.append(x)
        if not fam_spans or fam_spans[-1][0] != r["family"]:
            fam_spans.append([r["family"], x, x])
        fam_spans[-1][2] = x
        prev = r["family"]
        x += 1.0
    for xi, r in zip(xs, ranked):
        if r["status"] == "ok":
            for k, (metric, color, hatch) in enumerate([("precision", SKY, ""), ("recall", ORANGE, "///"),
                                                         ("f1", BLUE, "")]):
                ax.bar(xi + (k - 1) * width, r[metric], width, color=color, hatch=hatch, edgecolor="white",
                       linewidth=0.4)
            top = max(r["precision"], r["recall"], r["f1"])
            ax.text(xi, top + 0.02, f"{r['f1']:.3f}".lstrip("0"), ha="center", va="bottom", fontsize=7, color=BLUE,
                    fontweight="medium")
        else:
            ax.bar(xi, 1.0, 3 * width, color=LIGHT, edgecolor="none")
            note = "pending" if r["coverage"] < 0.01 else f"running {100 * r['coverage']:.0f}%"
            ax.text(xi, 0.5, note, rotation=90, ha="center", va="center", fontsize=6.5, color=GREY)
    ref_handles = []
    for r in ref:
        ax.axhline(r["f1"], color=GREY, ls="--", lw=0.9, zorder=0)
        ref_handles.append(Line2D([], [], color=GREY, ls="--", lw=0.9,
                                  label=f"{r['label']} F1 {r['f1']:.2f} (reference, not ranked)"))
    ax.set_xticks(xs, [r["label"] for r in ranked], rotation=55, ha="right", rotation_mode="anchor")
    ax.set_ylim(0, 1.05)
    ax.set_xlim(-0.6, xs[-1] + 0.6)
    # family names go a fixed distance (in points) below the tallest rotated tick label
    fig.draw_without_rendering()
    tick_h = max(t.get_window_extent().height for t in ax.get_xticklabels()) * 72.0 / fig.dpi
    off = tick_h + 3.5 + 4.0  # + tick pad + gap
    below = ax.get_xaxis_transform() + mtransforms.ScaledTranslation(0, -off / 72.0, fig.dpi_scale_trans)
    for fam, a, b in fam_spans:
        ax.plot([a - 0.4, b + 0.4], [0, 0], color=GREY, lw=0.8, transform=below, clip_on=False)
        ax.text((a + b) / 2, -0.012, FAMILY_LABELS[fam].replace(" (", "\n(").replace(" V4", "\nV4"),
                ha="center", va="top", fontsize=8, linespacing=1.0, transform=below, color=INK,
                fontweight="medium")
    ax.set_ylabel("score (leak = positive)")
    ax.legend(handles=[Patch(color=SKY, label="Precision"), Patch(facecolor=ORANGE, hatch="///",
                                                                   edgecolor="white", label="Recall"),
                       Patch(color=BLUE, label="F1"), *ref_handles], ncol=4, frameon=False, loc="lower left",
              bbox_to_anchor=(0.0, 1.0), borderaxespad=0.1)
    stamp(fig)
    save(fig, "prf1.pdf")


def plot_pareto(results: list[dict]) -> None:
    ok = [r for r in results if r["status"] == "ok" and r["ranked"] and r["latency_median_s"]]
    pending = [r for r in results if r["status"] != "ok" and r["ranked"]]
    fig, ax = plt.subplots(figsize=(6.4, 2.45), layout="constrained")
    pts = sorted(ok, key=lambda r: r["latency_median_s"])
    front, best = [], -1.0
    for r in pts:  # non-dominated: no faster method with higher-or-equal F1
        if r["f1"] > best:
            front.append(r)
            best = r["f1"]
    if len(front) > 1:
        ax.step([r["latency_median_s"] for r in front], [r["f1"] for r in front], where="post", color=GREY,
                lw=0.9, ls="--", zorder=1)
    for r in ok:
        color, marker = FAMILY_STYLE[r["family"]]
        lat = r["latency_median_s"]
        ci = r.get("f1_ci95")
        if ci and None not in ci:
            ax.errorbar(lat, r["f1"], yerr=[[r["f1"] - ci[0]], [ci[1] - r["f1"]]], color=color, lw=0.8,
                        capsize=2, zorder=2)
        ax.scatter(lat, r["f1"], s=46, marker=marker, zorder=3, linewidths=1.2,
                   facecolors=color if r["latency_c1"] else "white", edgecolors=color)
    ax.set_xscale("log")
    ax.set_xlim(3e-7, 30)
    ax.set_ylim(0, 1.08)
    label_points(ax, ok)
    ax.set_xlabel("median latency per unit (s, log scale)")
    ax.set_ylabel("F1 (leak), 95% CI")
    handles = [Line2D([], [], marker=FAMILY_STYLE[f][1], color=FAMILY_STYLE[f][0], ls="", label=FAMILY_LABELS[f])
               for f in ("Static", "Learned", "DeepSeek", "Qwen3.5-4B", "Decision")]
    handles.append(Line2D([], [], marker="o", markerfacecolor="white", color=GREY, ls="",
                          label="hollow = batched or concurrent run"))
    handles.append(Line2D([], [], color=GREY, ls="--", lw=0.9, label="Pareto front (available methods)"))
    ax.legend(handles=handles, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False, fontsize=8)
    if pending:
        fig.supxlabel(wrap_text(pending_summary(results), 110), fontsize=7, color=GREY)
    stamp(fig)
    save(fig, "pareto.pdf")


def strategy_span(labels: list[str]) -> str:
    """['L1', 'L2', 'L3'] -> 'L1–L3'; ['L1', 'L3'] -> 'L1, L3'."""
    nums = sorted(int(t[1:]) for t in labels)
    if len(nums) > 2 and nums == list(range(nums[0], nums[-1] + 1)):
        return f"L{nums[0]}–L{nums[-1]}"
    return ", ".join(f"L{n}" for n in nums)


def label_points(ax, rows: list[dict]) -> None:
    """Label scatter points without overlaps. Strategies of one model that sit close together share one label
    ("DeepSeek L1–L3"); each label takes the first free slot around its point (markers count as occupied)."""
    ax.figure.draw_without_rendering()  # settle the constrained layout before measuring

    def pt(r):
        return ax.transData.transform((r["latency_median_s"], r["f1"])) * 72.0 / ax.figure.dpi  # points

    labels: list[tuple[dict, str, list[dict]]] = []  # anchor row, text, rows the label stands for
    by_family: dict[str, list[dict]] = {}
    for r in rows:
        if r["family"] in ("Static", "Learned"):
            labels.append((r, r["label"], [r]))
        else:
            # one model = family name (DeepSeek, Qwen3.5-4B) or, for decision models, the label head (Jev, LoRA)
            model = r["label"].rsplit(" ", 1)[0] if r["family"] == "Decision" else r["family"].split(" ")[0]
            by_family.setdefault(model, []).append(r)
    for model, members in by_family.items():
        xy = [pt(r) for r in members]
        tight = (max(p[0] for p in xy) - min(p[0] for p in xy) < 30
                 and max(p[1] for p in xy) - min(p[1] for p in xy) < 14)
        strategies = [r["label"].rsplit(" ", 1)[-1] for r in members]
        if tight and all(t[:1] == "L" and t[1:].isdigit() for t in strategies):
            labels.append((max(members, key=lambda r: r["f1"]), f"{model} {strategy_span(strategies)}", members))
        else:
            labels += [(r, f"{model} {t}", [r]) for r, t in zip(members, strategies)]

    slots = [(6, 2, "left"), (6, -10, "left"), (-6, 2, "right"), (-6, -10, "right"), (6, 11, "left"),
             (-6, 11, "right"), (6, -19, "left"), (-6, -19, "right"), (0, 14, "center")]
    # occupied areas: markers and CI bars (tagged with their row, so a label may touch its own points), then labels
    boxes: list[tuple[tuple[float, float, float, float], int | None]] = []
    for r in rows:
        x, y = pt(r)
        boxes.append(((x - 6, y - 6, x + 6, y + 6), id(r)))
        if r.get("f1_ci95"):
            _, lo = ax.transData.transform((r["latency_median_s"], r["f1_ci95"][0])) * 72.0 / ax.figure.dpi
            _, hi = ax.transData.transform((r["latency_median_s"], r["f1_ci95"][1])) * 72.0 / ax.figure.dpi
            boxes.append(((x - 3, lo, x + 3, hi), id(r)))
    for r, name, members in sorted(labels, key=lambda t: (-t[0]["f1"], t[0]["latency_median_s"])):
        own = {id(m) for m in members}
        x, y = pt(r)
        w, h = 5.2 * len(name), 9.0
        for dx, dy, ha in slots:
            x0 = {"left": x + dx, "right": x + dx - w, "center": x - w / 2}[ha]
            box = (x0, y + dy, x0 + w, y + dy + h)
            if not any(box[0] < b[2] and b[0] < box[2] and box[1] < b[3] and b[1] < box[3]
                       for b, owner in boxes if owner is None or owner not in own):
                break
        boxes.append((box, None))
        ax.annotate(name, (r["latency_median_s"], r["f1"]), xytext=(dx, dy), textcoords="offset points",
                    fontsize=8.5, color=FAMILY_STYLE[r["family"]][0], ha=ha, va="bottom")


def wrap_text(text: str, width: int) -> str:
    lines, cur = [], ""
    for word in text.split(" "):
        if len(cur) + len(word) + 1 > width:
            lines.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}".strip()
    lines.append(cur)
    return "\n".join(lines)


def plot_heatmap(results: list[dict]) -> None:
    """F1 per flow category; methods are columns so the figure keeps its shape as methods arrive."""
    ok = [r for r in results if r["status"] == "ok"]
    pending = [r for r in results if r["status"] != "ok"]
    names = [(r["label"] if r["family"] in ("Static", "Learned", "Decision", "Dynamic") else
              f"{r['family'].split()[0]} {r['label']}") + (" (ref.)" if not r["ranked"] else "") for r in ok]
    grid = [[float("nan") if r["by_flow_f1"].get(c) is None else r["by_flow_f1"][c] for r in ok]
            for c in FLOW_CATEGORIES] if ok else [[float("nan")] for _ in FLOW_CATEGORIES]
    fig, ax = plt.subplots(figsize=(6.6, 2.45), layout="constrained")
    cmap = plt.get_cmap("cividis")
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            if v != v:  # NaN
                continue
            rgb = cmap(v)[:3]
            lum = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
            label = f"{v:.2f}"
            ax.text(j, i, "1" if label == "1.00" else label.lstrip("0"), ha="center", va="center", fontsize=7.5,
                    color="black" if lum > 0.5 else "white")
    ax.set_yticks(range(len(FLOW_CATEGORIES)), [FLOW_LABELS[c].replace("\n", " ") for c in FLOW_CATEGORIES])
    ax.set_xticks(range(len(names)), names, rotation=40, ha="right", rotation_mode="anchor")
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.01)
    cb.set_label("F1 (leak)")
    cb.outline.set_visible(False)
    if pending:
        fig.supxlabel(wrap_text(pending_summary(results), 120), fontsize=7, color=GREY)
    stamp(fig)
    save(fig, "heatmap.pdf")


# ---------------------------------------------------------------------------
# TeX side files
# ---------------------------------------------------------------------------
def fmt(v, nd=2):
    return "--" if v is None else f"{v:.{nd}f}"


def write_numbers(results: list[dict]) -> None:
    lines = ["% generated by figures/make_figures.py -- do not edit", "\\providecommand{\\res}[2]{"
             "\\ifcsname res-#1-#2\\endcsname\\csname res-#1-#2\\endcsname\\else\\textit{pending}\\fi}"]
    for r in results:
        vals = {}
        if r["status"] == "ok":
            lat = r["latency_median_s"]
            vals = {"p": fmt(r["precision"], 3), "r": fmt(r["recall"], 3), "f1": fmt(r["f1"], 3),
                    "macro": fmt(r["macro_f1"], 3), "lat": "--" if lat is None else f"{lat:.2g}"}
        for k, v in vals.items():
            lines.append(f"\\expandafter\\def\\csname res-{r['key']}-{k}\\endcsname{{{v}}}")
    (HERE / "numbers.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/numbers.tex")


def tex_escape(s: str) -> str:
    return s.replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")


def write_provenance(results: list[dict]) -> None:
    lines = ["% generated by figures/make_figures.py -- do not edit",
             "\\begin{tabular}{@{}llrrl@{}}", "\\toprule",
             "Method & Run file (juliet\\_full/\\ldots) & Cov. & F1 & sha256 \\\\", "\\midrule"]
    for r in results:
        if r["status"] != "ok":
            continue
        name = r["label"] if r["family"] in ("Static", "Learned", "Decision", "Dynamic") else \
            f"{r['family'].split()[0]} {r['label']}"
        files = r["files"]
        shown = tex_escape(files[0]) + (f" (+{len(files) - 1})" if len(files) > 1 else "")
        lines.append(f"{tex_escape(name)} & \\texttt{{{shown}}} & {100 * r['coverage']:.0f}\\% & {fmt(r['f1'], 3)} & "
                     f"\\texttt{{{r['sha256_8']}}} \\\\")
    pending = pending_summary(results)
    if pending:
        lines += ["\\midrule", f"\\multicolumn{{5}}{{@{{}}l}}{{\\textit{{{tex_escape(pending)}}}}} \\\\"]
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "provenance.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/provenance.tex")


def main() -> None:
    setup_style()
    results, _ = collect()
    (HERE / "results_summary.json").write_text(json.dumps(
        {"generated": dt.datetime.now().isoformat(timespec="seconds"),
         "scorer": "juliet_full/analysis/score.py" if scorer else "fallback", "set": EVAL_SET,
         "note": "PRELIMINARY; pending = no eval run with enough coverage yet", "methods": results}, indent=1))
    print("wrote figures/results_summary.json")
    for r in results:
        status = f"F1 {r['f1']:.3f} lat {r['latency_median_s']}" if r["status"] == "ok" else \
            f"pending (best coverage {100 * r['coverage']:.0f}%)"
        print(f"  {r['key']:<12} {status}")
    plot_probes()
    plot_prf1(results)
    plot_pareto(results)
    plot_heatmap(results)
    write_numbers(results)
    write_provenance(results)


if __name__ == "__main__":
    main()

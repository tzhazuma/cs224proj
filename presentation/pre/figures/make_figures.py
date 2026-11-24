#!/usr/bin/env python3
"""Render the figures and generated TeX tables of the pre from whatever result files exist.

Read-only on juliet_full/.  Result files follow the lane contract juliet_full/<lane>/results/<method>/<layer>/<run>.jsonl
and are listed per method and layer in methods.json.  Every run is scored on the eval set (39 flow variants,
2,656 units; DeepSeek on layers 3/placebo/original: the nested25 subset, 664 units) with
juliet_full/analysis/score.py (macro-F1 with a 95% family-cluster bootstrap CI).  A method/layer whose run does not
cover >= min_coverage of its target units is "pending": drawn grey, printed as "pending", never as a number.
Robustness deltas are paired: layer 1 is rescored on exactly the units of the layer-3 (placebo) run.
Latency on the Pareto plot comes only from latency_c1.csv (concurrency-1 measurements with their source).

Layer names on the slides: layer1 = Debiased, layer3 = DeadFree (never-executed frees), placebo = Placebo
(never-executed prints), original = Original Juliet.

Outputs (next to this file): probes.pdf, prf1.pdf, pareto.pdf, robustness.pdf, lora.pdf, heatmap.pdf,
mechanism.pdf, the single-message main-slide figures hook_original.pdf, quality.pdf, nearllm.pdf, deadfree.pdf,
numbers.tex (\\res{<key>-<layer>}{<metric>}), original.tex, demo.tex, repeat.tex, cost.tex,
latency.tex, provenance.tex and results_summary.json.
"""
from __future__ import annotations

import ast
import csv
import datetime as dt
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parents[2] / "juliet_full"
UNITS_PATH = JULIET_FULL / "data" / "build" / "layer1.jsonl"
SUBSETS_PATH = JULIET_FULL / "data" / "build" / "subsets.json"
PROBES_PATH = JULIET_FULL / "data" / "build" / "probes.json"
LEDGER_PATH = JULIET_FULL / "llm" / "ledger.jsonl"
# newest stage recording first: stage_final_v2 (with the L4-D row, demo stage 3), stage_final, stage_dryrun
DEMO_PATHS = [HERE.parents[1] / "demo" / "recordings" / f"{n}.json" for n in ("stage_final_v2", "stage_final", "stage_dryrun")]
REGISTRY_PATH = HERE / "methods.json"
LATENCY_PATH = HERE / "latency_c1.csv"
EVAL_SET = "eval"
LAYERS = ("layer1", "layer3", "placebo", "original")
LAYER_NAMES = {"layer1": "Debiased", "layer3": "DeadFree", "placebo": "Placebo", "original": "Original"}
FLOW_CATEGORIES = ["01", "02-22", "31-45", "51-68", "71-84"]
FLOW_LABELS = {"01": "01 baseline", "02-22": "02–22 control flow", "31-45": "31–45 data flow",
               "51-68": "51–68 cross-file", "71-84": "71–84 C++ objects"}
FAMILY_LABELS = {"Static": "Static analysis", "Learned": "Learned (zero-shot)", "Dynamic": "Dynamic (reference)",
                 "DeepSeek": "DeepSeek V4.1 Flash", "Qwen3.5-4B": "Qwen3.5-4B (SLM)", "Decision": "Decision models"}
# Okabe-Ito
BLUE, SKY, ORANGE, GREEN, VERMIL, PURPLE = "#0072B2", "#56B4E9", "#E69F00", "#009E73", "#D55E00", "#CC79A7"
INK, GREY, LIGHT = "#26303A", "#7F8891", "#E6E9EE"
FAMILY_STYLE = {"Static": (BLUE, "s"), "Learned": (PURPLE, "D"), "DeepSeek": (VERMIL, "o"),
                "Qwen3.5-4B": (ORANGE, "^"), "Decision": (GREEN, "v"), "Dynamic": (GREY, "X"), "Ablation": (GREY, "o")}
# the two panels of the layer-1 and robustness figures
PANELS = (("Static", "Dynamic", "Learned", "DeepSeek"), ("Qwen3.5-4B", "Decision"))
BOOTSTRAP = 2000

sys.dont_write_bytecode = True  # do not leave __pycache__ in juliet_full/analysis
sys.path.insert(0, str(JULIET_FULL / "analysis"))
import score as scorer  # noqa: E402  juliet_full/analysis/score.py


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Run selection and scoring
# ---------------------------------------------------------------------------
def load_rows(path: Path, entry: dict) -> list[dict]:
    rows = read_jsonl(path)
    if entry.get("strategy"):
        rows = [r for r in rows if r.get("strategy") in (None, entry["strategy"])]
    if entry.get("pred_field"):  # e.g. the read-out ablation at the dev-selected threshold
        rows = [{**r, "pred": (r.get("extra") or {}).get(entry["pred_field"])} for r in rows]
    return rows


def candidates(patterns: list[str], exclude: list[str]) -> list[list[Path]]:
    """One list per glob, newest file first; files already matched by an earlier glob are dropped."""
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
    """{"rows", "files", "coverage"}; rows is None when no run covers min_cov of the target units."""
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
        "p": e2e["precision_leak"], "r": e2e["recall_leak"], "f1": e2e["f1_leak"], "macro": e2e["macro_f1"],
        "spec": e2e["specificity"], "macro_ci": ci.get("macro_f1"), "f1_ci": ci.get("f1_leak"),
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


def sha_short(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(p.read_bytes())
    return h.hexdigest()[:8]


def collect(registry: dict) -> list[dict]:
    units = [u for u in read_jsonl(UNITS_PATH) if u.get("set") == EVAL_SET]
    subsets = {k: set(v) for k, v in json.loads(SUBSETS_PATH.read_text()).items()}
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
                info.update(status="ok", sha256_8=sha_short(run["files"]),
                            **summarize(scorer.score(target_units, run["rows"], bootstrap=BOOTSTRAP)))
                rows_by_layer[layer] = (target_units, run["rows"])
            res["layers"][layer] = info
        if "layer1" in rows_by_layer:  # paired deltas: layer 1 rescored on the units of the other layer
            for layer, (target_units, rows) in rows_by_layer.items():
                if layer == "layer1":
                    continue
                base = scorer.score(target_units, rows_by_layer["layer1"][1], bootstrap=0)["end_to_end"]
                lost, gained, flips = lost_gained(target_units, rows_by_layer["layer1"][1], rows)
                res["layers"][layer].update(base=base["macro_f1"], base_r=base["recall_leak"],
                                            d=res["layers"][layer]["macro"] - base["macro_f1"],
                                            lost=lost, gained=gained, flips=flips)
        res["_rows"] = rows_by_layer
        results.append(res)
    return results


def get(results: list[dict], key: str) -> dict:
    return next(r for r in results if r["key"] == key)


def ok(r: dict, layer: str) -> dict | None:
    info = r["layers"].get(layer)
    return info if info and info["status"] == "ok" else None


def read_latency() -> dict[str, dict]:
    with LATENCY_PATH.open() as fh:
        return {row["key"]: row for row in csv.DictReader(fh)}


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------
def setup_style() -> None:
    fira = Path.home() / ".local/share/texlive/2026/texmf-dist/fonts/opentype/public/fira"
    family = "DejaVu Sans"
    for name in ("FiraSans-Regular.otf", "FiraSans-Medium.otf", "FiraSans-Italic.otf", "FiraSans-SemiBold.otf"):
        if (fira / name).exists():
            font_manager.fontManager.addfont(str(fira / name))
            family = "Fira Sans"
    plt.rcParams.update({
        "font.family": family, "font.size": 10, "axes.titlesize": 10, "axes.labelsize": 10,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 8.5, "axes.edgecolor": INK,
        "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "text.color": INK,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.7,
        "pdf.fonttype": 3, "savefig.bbox": "tight", "savefig.pad_inches": 0.03,
    })


def save(fig, name: str) -> None:
    fig.savefig(HERE / name, metadata={"CreationDate": None})
    plt.close(fig)
    print(f"wrote figures/{name}")


def short(v: float | None) -> str:
    return "–" if v is None else f"{v:.3f}".replace("0.", ".", 1) if v < 1 else "1.0"


def pending_note(fig, items: list[str], y: float = -0.01) -> None:
    if items:
        fig.text(0.5, y, "pending (grey): " + " · ".join(items), ha="center", va="top", fontsize=7, color=GREY)


def collapse(labels: list[str]) -> list[str]:
    """['Qwen L1', 'Qwen L3', 'Intern-D L2'] -> ['Qwen L1, L3', 'Intern-D L2']."""
    heads: dict[str, list[str]] = {}
    for lab in labels:
        head, _, tail = lab.rpartition(" ")
        if head and tail[:1] == "L" and tail[1:].isdigit():
            heads.setdefault(head, []).append(tail)
        else:
            heads.setdefault(lab, [])
    out = []
    for head, tails in heads.items():
        nums = sorted(int(t[1:]) for t in tails)
        if len(nums) > 2 and nums == list(range(nums[0], nums[-1] + 1)):
            out.append(f"{head} L{nums[0]}–L{nums[-1]}")
        else:
            out.append(head + (" " + ", ".join(f"L{n}" for n in nums) if nums else ""))
    return out


def panel_rows(results: list[dict], families: tuple[str, ...], layer: str, sort_key) -> list[dict | str]:
    """Rows of one panel: a family header (str) followed by its methods, sorted within the family."""
    rows: list[dict | str] = []
    for fam in families:
        members = [r for r in results if r["family"] == fam and layer in r["layers"]]
        if not members:
            continue
        done = sorted([r for r in members if ok(r, layer)], key=sort_key)
        rows.append(fam)
        rows += done + [r for r in members if not ok(r, layer)]
    return rows


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def plot_probes() -> None:
    """Shortcut probes, original Juliet vs debiased layer 1 (macro-F1, from data/build/probes.json)."""
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
    ax.set_xlabel("macro-F1 (probe fitted on dev)")
    ax.legend(handles=[Line2D([], [], marker="o", color=VERMIL, ls="", label="original Juliet"),
                       Line2D([], [], marker="D", color=BLUE, ls="", label="Debiased")],
              loc="lower left", frameon=False, ncol=2, bbox_to_anchor=(0.0, 1.0), borderaxespad=0.1)
    save(fig, "probes.pdf")


def setup_panel(ax, rows: list, xlim: tuple[float, float]) -> list[float]:
    """y positions (header rows get a smaller step) and family headers on the left."""
    ys, y = [], 0.0
    for i, row in enumerate(rows):
        if isinstance(row, str) and i:
            y += 0.35
        ys.append(y)
        y += 0.8 if isinstance(row, str) else 1.0
    labels = []
    for row in rows:
        labels.append(FAMILY_LABELS[row] if isinstance(row, str) else row["label"])
    ax.set_yticks(ys, labels)
    for tick, row in zip(ax.get_yticklabels(), rows):
        if isinstance(row, str):
            tick.set_fontweight("semibold")
            tick.set_color(FAMILY_STYLE[row][0] if row != "Dynamic" else GREY)
            tick.set_fontsize(8.5)
        elif not row["ranked"]:
            tick.set_color(GREY)
    ax.tick_params(axis="y", length=0, labelsize=8.5)
    ax.set_ylim(y - 0.4, -0.6)
    ax.set_xlim(*xlim)
    ax.spines["left"].set_visible(False)
    ax.grid(axis="x", color=LIGHT, lw=0.6, zorder=0)
    ax.set_axisbelow(True)
    return ys


# Main-slide versions leave out few-shot L2 and Valgrind (close to L1 / ASan); the *_full.pdf backups keep every row.
MAIN_EXCLUDE = frozenset({"deepseek_L2", "qwen_L2", "jev_L2", "intern_L2", "valgrind"})


def plot_prf1(results: list[dict], name: str, exclude: frozenset = frozenset(),
              figsize: tuple[float, float] = (6.9, 2.95)) -> list[str]:
    """Layer 1: macro-F1 bar with 95% CI; precision and recall of the leak class as markers."""
    fig, axes = plt.subplots(1, 2, figsize=figsize, layout="constrained")
    pending = []
    results = [r for r in results if r["key"] not in exclude]
    for ax, fams in zip(axes, PANELS):
        rows = panel_rows(results, fams, "layer1", lambda r: -r["layers"]["layer1"]["macro"])
        ys = setup_panel(ax, rows, (0.0, 1.0))
        for y, r in zip(ys, rows):
            if isinstance(r, str):
                continue
            info = ok(r, "layer1")
            if info is None:
                ax.barh(y, 1.0, 0.62, color=LIGHT, zorder=1)
                ax.text(0.5, y, "pending", ha="center", va="center", fontsize=7.5, color=GREY)
                pending.append(r["label"])
                continue
            color = FAMILY_STYLE[r["family"]][0]
            ax.barh(y, info["macro"], 0.62, color=color, alpha=0.30 if not r["ranked"] else 0.85, zorder=2)
            if info["macro_ci"]:
                lo, hi = info["macro_ci"]
                ax.plot([lo, hi], [y, y], color=INK, lw=0.8, zorder=3)
            ax.scatter(info["p"], y, marker="|", s=55, color=INK, linewidths=1.4, zorder=4)
            ax.scatter(info["r"], y, marker="o", s=16, facecolors="white", edgecolors=INK, linewidths=0.9, zorder=4)
            ax.text(0.015, y, short(info["macro"]), ha="left", va="center", fontsize=7.5, zorder=5,
                    color="white" if r["ranked"] else INK, fontweight="semibold")
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0", ".25", ".5", ".75", "1"])
    axes[0].set_xlabel("score on Debiased", fontsize=9)
    axes[1].set_xlabel("score on Debiased", fontsize=9)
    fig.legend(handles=[Patch(color=GREY, label="bar: macro-F1 (95% CI)"),
                        Line2D([], [], marker="|", color=INK, ls="", markersize=8, markeredgewidth=1.4,
                               label="precision (leak)"),
                        Line2D([], [], marker="o", markerfacecolor="white", color=INK, ls="", markersize=4.5,
                               label="recall (leak)")],
               loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False, fontsize=8)
    pending_note(fig, pending)
    save(fig, name)
    return pending


def label_points(ax, points: list[tuple[float, float, str, str, bool]]) -> None:
    """points = (x, y, text, color, optional).  Each label takes the first free slot around its point; an optional
    label (reference methods) is dropped when no slot is free."""
    ax.figure.draw_without_rendering()

    def pt(x, y):
        return ax.transData.transform((x, y)) * 72.0 / ax.figure.dpi

    boxes = [(*(pt(x, y) - 5), *(pt(x, y) + 5)) for x, y, *_ in points]
    slots = [(6, 1, "left"), (-6, 1, "right"), (6, -10, "left"), (-6, -10, "right"), (0, 7, "center"),
             (0, -16, "center"), (6, 9, "left"), (-6, 9, "right")]
    for x, y, text, color, optional in sorted(points, key=lambda p: (p[4], -p[1])):
        px, py = pt(x, y)
        w, h = (4.0 if optional else 4.6) * len(text), 9.0
        for dx, dy, ha in slots:
            x0 = {"left": px + dx, "right": px + dx - w, "center": px - w / 2}[ha]
            box = (x0, py + dy, x0 + w, py + dy + h)
            if not any(box[0] < b[2] and b[0] < box[2] and box[1] < b[3] and b[1] < box[3] for b in boxes):
                break
        else:
            if optional:
                continue
        boxes.append(box)
        ax.annotate(text, (x, y), xytext=(dx, dy), textcoords="offset points", fontsize=7 if optional else 8,
                    color=color, ha=ha, va="bottom")


def plot_pareto(results: list[dict], latency: dict[str, dict]) -> list[str]:
    """Concurrency-1 latency (log) vs layer-1 macro-F1 with CI; deployment budget bands; dynamic = reference."""
    fig, ax = plt.subplots(figsize=(6.6, 2.95), layout="constrained")
    xmin, xmax, floor = 2e-4, 25.0, 6e-4  # methods faster than `floor` (grep, 1 µs) are drawn at it, off-scale
    bands = [(xmin, 0.1, "IDE: < 0.1 s"), (0.1, 1.0, "pre-commit: < 1 s"), (1.0, 10.0, "CI: < 10 s")]
    for (a, b, name), shade in zip(bands, ("#EAF1F8", "#F7F0E1", "#EAF1F8")):
        ax.axvspan(a, b, color=shade, zorder=0, lw=0)
        ax.text((a * b) ** 0.5, 1.035, name, ha="center", va="bottom", fontsize=7.5, color=GREY)
    pts, front_pts, pending = [], [], []
    by_model: dict[str, list] = {}
    for r in results:
        info = ok(r, "layer1")
        lat = latency.get(r["key"])
        if r["family"] == "Ablation" or lat is None:
            continue
        if info is None:
            pending.append(r["label"])
            continue
        x, y = max(float(lat["latency_s"]), floor), info["macro"]
        color, marker = FAMILY_STYLE[r["family"]]
        if float(lat["latency_s"]) < floor:
            ax.annotate("", (xmin * 1.15, y), (x / 1.25, y), arrowprops=dict(arrowstyle="-|>", color=color, lw=0.8,
                                                                         mutation_scale=7))
        if info["macro_ci"]:
            ax.plot([x, x], info["macro_ci"], color=color, lw=0.9, zorder=2)
        ax.scatter(x, y, s=44 if r["ranked"] else 36, marker=marker, color=color, zorder=3,
                   edgecolors="white" if r["ranked"] else color, linewidths=0.5)
        if r["key"] == "codeql" and "codeql_amortized" in latency:  # batched databases: amortized time
            xa = float(latency["codeql_amortized"]["latency_s"])
            ax.plot([xa, x], [y, y], color=color, lw=0.7, ls=":", zorder=2)
            ax.scatter(xa, y, s=40, marker=marker, facecolors="white", edgecolors=color, linewidths=1.1, zorder=3)
        if r["ranked"]:
            front_pts.append((x, y))
            by_model.setdefault(r["model"], []).append((x, y, r["label"], color))
        elif r["key"] != "asan_lsan":
            pts.append((x, y, r["label"], GREY, True))
    for model, members in by_model.items():  # strategies of one model share a label
        x, y, label, color = max(members, key=lambda m: m[1])
        if len(members) > 1:
            label = collapse([m[2] for m in members])[0]
        if model == "grep":
            label = "grep (1 µs, off-scale)"
        pts.append((x, y, label, color, False))
    ref = get(results, "asan_lsan")
    if ok(ref, "layer1"):
        ax.axhline(ok(ref, "layer1")["macro"], color=GREY, ls="--", lw=0.9, zorder=1)
        ax.text(xmin * 1.3, ok(ref, "layer1")["macro"] + 0.006, f"ASan/LSan reference "
                f"{short(ok(ref, 'layer1')['macro'])}", fontsize=7.5, color=GREY, va="bottom")
    front, best = [], -1.0
    for x, y in sorted(front_pts):
        if y > best:
            front.append((x, y))
            best = y
    if len(front) > 1:
        ax.step([p[0] for p in front], [p[1] for p in front], where="post", color=INK, lw=0.8, ls="-", alpha=0.5,
                zorder=1)
    ax.set_xscale("log")
    ax.set_xlim(xmin, xmax)
    ax.set_ylim(0.42, 1.03)
    label_points(ax, pts)
    ax.set_xlabel("latency per unit at concurrency 1 (s, log scale)")
    ax.set_ylabel("macro-F1 on Debiased (95% CI)")
    handles = [Line2D([], [], marker=FAMILY_STYLE[f][1], color=FAMILY_STYLE[f][0], ls="", label=FAMILY_LABELS[f])
               for f in ("Static", "Learned", "DeepSeek", "Qwen3.5-4B", "Decision", "Dynamic")]
    handles += [Line2D([], [], marker="s", markerfacecolor="white", color=BLUE, ls=":", lw=0.7,
                       label="CodeQL amortized (50/db)"),
                Line2D([], [], color=INK, alpha=0.5, lw=0.8, label="Pareto front (ranked)")]
    ax.legend(handles=handles, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False, fontsize=7.5)
    pending_note(fig, pending)
    save(fig, "pareto.pdf")
    return pending


def plot_robustness(results: list[dict], name: str, exclude: frozenset = frozenset(),
                    figsize: tuple[float, float] = (6.9, 3.0)) -> list[str]:
    """Paired layer 1 → layer 3 macro-F1 (arrow), placebo (grey diamond), delta on the right."""
    fig, axes = plt.subplots(1, 2, figsize=figsize, layout="constrained")
    pending = []
    results = [r for r in results if r["key"] not in exclude]
    for ax, fams in zip(axes, PANELS):
        members = [r for r in results if r["family"] in fams and "layer3" in r["layers"]]
        rows = panel_rows(members, fams, "layer3", lambda r: -r["layers"]["layer3"]["d"])
        ys = setup_panel(ax, rows, (0.3, 1.0))
        for y, r in zip(ys, rows):
            if isinstance(r, str):
                continue
            info = ok(r, "layer3")
            if info is None or "base" not in info:
                ax.barh(y, 0.7, 0.62, left=0.3, color=LIGHT, zorder=1)
                ax.text(0.65, y, "pending", ha="center", va="center", fontsize=7.5, color=GREY)
                pending.append(r["label"] + " DeadFree")
                continue
            color = FAMILY_STYLE[r["family"]][0] if r["ranked"] else GREY
            a, b = info["base"], info["macro"]
            if abs(b - a) > 0.012:
                ax.annotate("", (b, y), (a, y), arrowprops=dict(arrowstyle="-|>", color=color, lw=1.3,
                                                                 mutation_scale=8, shrinkA=0, shrinkB=1), zorder=3)
            ax.scatter(a, y, s=26, facecolors="white", edgecolors=color, linewidths=1.1, zorder=4)
            ax.scatter(b, y, s=26, color=color, zorder=4)
            pl = ok(r, "placebo")
            if pl and "base" in pl:
                ax.scatter(pl["macro"], y, s=20, marker="D", facecolors="none", edgecolors=GREY, linewidths=0.8,
                           zorder=5)
            elif "placebo" in r["layers"]:
                pending.append(r["label"] + " placebo")
            d = info["d"]
            txt = f"{d:+.3f}".replace("-", "−").replace("+0.000", "±0").replace("−0.000", "±0")
            if info.get("subset"):
                txt += "†"
            ax.text(1.005, y, txt, transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=7.5,
                    color=VERMIL if d < -0.05 else INK, clip_on=False)
        ax.set_xticks([0.4, 0.6, 0.8, 1.0], [".4", ".6", ".8", "1"])
        ax.set_xlabel("macro-F1", fontsize=9)
    fig.legend(handles=[Line2D([], [], marker="o", markerfacecolor="white", color=INK, ls="", label="Debiased"),
                        Line2D([], [], marker="o", color=INK, ls="", label="DeadFree"),
                        Line2D([], [], marker="D", markerfacecolor="none", color=GREY, ls="", label="Placebo"),
                        Line2D([], [], ls="", label="Δ = DeadFree − Debiased, paired;  † nested25 (664 units)")],
               loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=4, frameon=False, fontsize=8, handletextpad=0.3, columnspacing=1.2)
    pending_note(fig, pending)
    save(fig, name)
    return pending


def plot_lora(results: list[dict]) -> list[str]:
    """Shortcut amplification: zero-shot read-out (same base, no LoRA) vs LoRA, layer 1 / 3 / placebo."""
    groups = [("readout_L1", "no LoRA\nL1"), ("lora_L1", "LoRA\nL1"), ("readout_L3", "no LoRA\nL3"),
              ("lora_L3", "LoRA\nL3")]
    series = [("layer1", "Debiased", BLUE, ""), ("layer3", "DeadFree", VERMIL, ""),
              ("placebo", "Placebo", GREY, "")]
    fig, ax = plt.subplots(figsize=(3.7, 2.5), layout="constrained")
    width, pending = 0.26, []
    for i, (key, _) in enumerate(groups):
        r = get(results, key)
        for k, (layer, _, color, _) in enumerate(series):
            if layer not in r["layers"]:
                continue
            info = ok(r, layer)
            x = i + (k - 1) * width
            if info is None:
                ax.bar(x, 1.0, width, color=LIGHT)
                ax.text(x, 0.5, "pending", rotation=90, ha="center", va="center", fontsize=6.5, color=GREY)
                pending.append(f"{r['label']} {layer}")
                continue
            ax.bar(x, info["macro"], width, color=color, edgecolor="white", linewidth=0.4)
            ax.text(x, info["macro"] + 0.015, short(info["macro"]), ha="center", va="bottom", fontsize=6.8,
                    color=INK, rotation=90 if width < 0.3 else 0)
    ax.axhline(1 / 3, color=GREY, ls=":", lw=0.8)
    ax.set_xticks(range(len(groups)), [g[1] for g in groups], fontsize=8.5)
    ax.axvline(1.5, color=LIGHT, lw=1)
    ax.set_ylim(0, 1.13)
    ax.set_ylabel("macro-F1")
    ax.legend(handles=[*(Patch(color=c, label=lab) for _, lab, c, _ in series),
                       Line2D([], [], color=GREY, ls=":", lw=0.8, label="always \"no leak\"")], ncol=2, frameon=False,
              loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=7.5, handlelength=1.0, columnspacing=0.8)
    pending_note(fig, pending)
    save(fig, "lora.pdf")
    return pending


# ---------------------------------------------------------------------------
# Single-message figures for the main slides (v3): few methods, one claim each
# ---------------------------------------------------------------------------
# primary axis of the talk: generative LLM vs decision model; static analyzers are baselines
KIND_COLOR = {"DeepSeek": VERMIL, "Qwen3.5-4B": VERMIL, "Decision": GREEN, "Static": BLUE, "Learned": PURPLE}
KIND_LEGEND = [(VERMIL, "generative LLM"), (GREEN, "decision model"), (BLUE, "static analyzer"),
               (PURPLE, "learned classifier")]


def bar_labels(ax, ys, values, colors, fmt=short, dx=0.012, fontsize=8.5):
    for y, v, c in zip(ys, values, colors):
        ax.text(v + dx, y, fmt(v), va="center", ha="left", fontsize=fontsize, color=c, fontweight="semibold")


def plot_hook_original(results: list[dict]) -> None:
    """Intro: on Original Juliet two shortcut rules score above the static analyzers (eval set, macro-F1)."""
    probes = json.loads(PROBES_PATH.read_text())
    rows = [("'static void' → good", probes["original"]["static_void"]["macro_f1"]["all"], VERMIL),
            ("no free/delete → leak", ok(get(results, "grep"), "original")["macro"], VERMIL)]
    rows += [(get(results, k)["label"], ok(get(results, k), "original")["macro"], BLUE)
             for k in ("clang_sa", "codeql", "infer")]
    fig, ax = plt.subplots(figsize=(4.4, 1.95), layout="constrained")
    ys = list(range(len(rows)))
    ax.barh(ys, [r[1] for r in rows], 0.62, color=[r[2] for r in rows], alpha=0.88)
    bar_labels(ax, ys, [r[1] for r in rows], [r[2] for r in rows], fmt=lambda v: f"{v:.3f}", fontsize=9.5)
    ax.set_yticks(ys, [r[0] for r in rows], fontsize=10)
    ax.set_ylim(len(rows) - 0.5, -0.5)
    ax.set_xlim(0, 1.13)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0", ".25", ".5", ".75", "1"])
    ax.set_xlabel("macro-F1 on Original Juliet (eval, 2,656 units)", fontsize=9)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.legend(handles=[Patch(color=VERMIL, label="one-line shortcut rule"), Patch(color=BLUE, label="static analyzer")],
              loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, frameon=False, fontsize=8.5)
    save(fig, "hook_original.pdf")


def plot_quality(results: list[dict]) -> None:
    """Main quality comparison on Debiased: L1 of every model, the static tools, LineVul; ASan/LSan as a line."""
    keys = ["deepseek_L1", "lora_L1", "jev_L1", "intern_L1", "qwen_L1", "codeql", "clang_sa", "infer", "grep",
            "cppcheck", "linevul"]
    rows = sorted((get(results, k) for k in keys), key=lambda r: -ok(r, "layer1")["macro"])
    fig, ax = plt.subplots(figsize=(5.2, 2.75), layout="constrained")
    ys = list(range(len(rows)))
    vals = [ok(r, "layer1")["macro"] for r in rows]
    cols = [KIND_COLOR[r["family"]] for r in rows]
    ax.barh(ys, vals, 0.66, color=cols, alpha=0.88, zorder=2)
    for y, r in zip(ys, rows):
        lo, hi = ok(r, "layer1")["macro_ci"]
        ax.plot([lo, hi], [y, y], color=INK, lw=0.8, zorder=3)
    tips = [max(v, ok(r, "layer1")["macro_ci"][1]) for v, r in zip(vals, rows)]
    for y, v, t, c in zip(ys, vals, tips, cols):
        ax.text(t + 0.015, y, short(v), va="center", ha="left", fontsize=8, color=c, fontweight="semibold", zorder=4,
                bbox=dict(fc="white", ec="none", pad=0.6))
    ax.set_yticks(ys, [r["label"] for r in rows], fontsize=8.5)
    for tick, r in zip(ax.get_yticklabels(), rows):
        if r["key"] == "lora_L1":
            tick.set_fontweight("bold")
    ref = ok(get(results, "asan_lsan"), "layer1")["macro"]
    ax.axvline(ref, color=GREY, ls="--", lw=0.9, zorder=1)
    ax.text(ref + 0.012, len(rows) - 1, f"ASan/LSan\n{short(ref)}", ha="left", va="center",
            fontsize=7.5, color=GREY)
    ax.set_ylim(len(rows) - 0.4, -0.6)
    ax.set_xlim(0, 1.1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0", ".25", ".5", ".75", "1"])
    ax.set_xlabel("macro-F1 on Debiased (eval, 2,656 units; 95% CI)", fontsize=8.5)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.legend(handles=[Patch(color=c, label=lab) for c, lab in KIND_LEGEND], loc="lower left",
              bbox_to_anchor=(0, 1.0), ncol=4, frameon=False, fontsize=8, handlelength=1.0, columnspacing=1.0)
    save(fig, "quality.pdf")


def plot_nearllm(results: list[dict], latency: dict[str, dict]) -> None:
    """Near-LLM quality: DeepSeek L1 vs our LoRA decision model L1 (and Jev L1), macro-F1 and c1 latency."""
    keys = [("deepseek_L1", "DeepSeek L1 (API)", VERMIL), ("jev_L1", "Jev L1 (API)", "#7CC4AE"),
            ("lora_L1", "LoRA decision model L1", GREEN)]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(5.6, 1.6), layout="constrained", sharey=True)
    ys = list(range(len(keys)))
    vals = [ok(get(results, k), "layer1")["macro"] for k, _, _ in keys]
    lats = [float(latency[k]["latency_s"]) for k, _, _ in keys]
    cols = [c for _, _, c in keys]
    a1.barh(ys, vals, 0.62, color=cols)
    bar_labels(a1, ys, vals, [INK] * 3, fmt=lambda v: f"{v:.3f}", dx=0.02, fontsize=9)
    a1.set_xlim(0, 1.25)
    a1.set_xticks([0, 0.5, 1.0], ["0", ".5", "1"])
    a1.set_xlabel("macro-F1 on Debiased", fontsize=9)
    a2.barh(ys, lats, 0.62, color=cols)
    bar_labels(a2, ys, lats, [INK] * 3, fmt=lambda v: f"{v:.3f} s", dx=0.02, fontsize=9)
    a2.set_xlim(0, 1.2)
    a2.set_xlabel("latency per unit, median (s)", fontsize=9)
    a1.set_yticks(ys, [lab for _, lab, _ in keys], fontsize=9.5)
    for tick, (k, _, _) in zip(a1.get_yticklabels(), keys):
        if k == "lora_L1":
            tick.set_fontweight("bold")
    a1.set_ylim(len(keys) - 0.5, -0.5)
    for ax in (a1, a2):
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)
    save(fig, "nearllm.pdf")


def plot_deadfree(results: list[dict]) -> None:
    """DeadFree, key methods: paired Debiased -> DeadFree macro-F1, Placebo as a diamond, failure mode on the right.
    Mode: 0 flips = robust; |delta| < 0.05 = small drop; else more new misses (lost) or more new false alarms (gained)."""
    keys = ["clang_sa", "infer", "jev_L1", "deepseek_L1", "codeql", "qwen_L1", "intern_L1", "lora_L3", "grep",
            "lora_L1"]
    fig, ax = plt.subplots(figsize=(5.6, 2.75), layout="constrained")
    for y, key in enumerate(keys):
        r = get(results, key)
        info, pl = ok(r, "layer3"), ok(r, "placebo")
        a, b = info["base"], info["macro"]
        if info["flips"] == 0:
            color, note = BLUE, "0 flips"
        elif abs(info["d"]) < 0.05:
            color, note = GREY, "small drop"
        elif info["lost"] >= info["gained"]:
            color, note = VERMIL, f"+{info['lost']:,} misses"
        else:
            color, note = ORANGE, f"+{info['gained']:,} false alarms"
        if abs(b - a) > 0.012:
            ax.annotate("", (b, y), (a, y), arrowprops=dict(arrowstyle="-|>", color=color, lw=1.5, mutation_scale=9,
                                                             shrinkA=0, shrinkB=1), zorder=3)
        ax.scatter(a, y, s=30, facecolors="white", edgecolors=color, linewidths=1.2, zorder=4)
        ax.scatter(b, y, s=30, color=color, zorder=4)
        if pl and "base" in pl:
            ax.scatter(pl["macro"], y, s=22, marker="D", facecolors="none", edgecolors=GREY, linewidths=0.9, zorder=5)
        d = f"{info['d']:+.3f}".replace("-", "−").replace("+0.000", "±0")
        ax.text(1.03, y, d + ("†" if info.get("subset") else ""), transform=ax.get_yaxis_transform(), ha="left",
                va="center", fontsize=8.5, color=INK, clip_on=False)
        ax.text(1.20, y, note, transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=8.5,
                color=color, clip_on=False, fontweight="semibold")
    ax.set_yticks(range(len(keys)), [get(results, k)["label"] for k in keys], fontsize=8.5)
    ax.set_ylim(len(keys) - 0.5, -0.6)
    ax.set_xlim(0.3, 1.02)
    ax.set_xticks([0.4, 0.6, 0.8, 1.0], [".4", ".6", ".8", "1"])
    ax.set_xlabel("macro-F1 (paired units)", fontsize=9)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=LIGHT, lw=0.6, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(handles=[Line2D([], [], marker="o", markerfacecolor="white", color=INK, ls="", label="Debiased"),
                       Line2D([], [], marker="o", color=INK, ls="", label="DeadFree"),
                       Line2D([], [], marker="D", markerfacecolor="none", color=GREY, ls="", label="Placebo"),
                       Line2D([], [], ls="", label="† nested25 (664 units)")],
              loc="lower left", bbox_to_anchor=(0, 1.0), ncol=4, frameon=False, fontsize=8, handletextpad=0.3,
              columnspacing=1.0)
    save(fig, "deadfree.pdf")


def heat(ax, grid, xlabels, ylabels, cmap="cividis", fontsize=7.0):
    cm = plt.get_cmap(cmap)
    im = ax.imshow(grid, cmap=cm, vmin=0, vmax=1, aspect="auto")
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            if v != v:
                ax.text(j, i, "–", ha="center", va="center", fontsize=fontsize, color=GREY)
                continue
            rgb = cm(v)[:3]
            lum = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
            ax.text(j, i, short(v), ha="center", va="center", fontsize=fontsize,
                    color="black" if lum > 0.5 else "white")
    ax.set_yticks(range(len(ylabels)), ylabels)
    ax.set_xticks(range(len(xlabels)), xlabels)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    return im


def main_rows(results: list[dict], layer: str) -> list[dict]:
    order = [f for fams in PANELS for f in fams]
    rows = [r for r in results if r["family"] in order and ok(r, layer)]
    return sorted(rows, key=lambda r: order.index(r["family"]))


def plot_heatmap(results: list[dict]) -> None:
    """Layer-1 macro-F1 per flow category; methods are columns."""
    rows = main_rows(results, "layer1")
    grid = [[ok(r, "layer1")["by_flow"].get(c, float("nan")) for r in rows] for c in FLOW_CATEGORIES]
    fig, ax = plt.subplots(figsize=(6.9, 2.5), layout="constrained")
    im = heat(ax, grid, [r["label"] for r in rows], [FLOW_LABELS[c] for c in FLOW_CATEGORIES], fontsize=6.5)
    ax.tick_params(axis="x", labelrotation=55, labelsize=7.5)
    for t in ax.get_xticklabels():
        t.set_ha("right")
        t.set_rotation_mode("anchor")
    ax.tick_params(axis="y", labelsize=8)
    cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cb.set_label("macro-F1", fontsize=8)
    cb.outline.set_visible(False)
    save(fig, "heatmap.pdf")


def plot_mechanism(results: list[dict]) -> None:
    """Recall by leak mechanism and specificity by good kind, layer 1 and layer 3."""
    cols = [("recall_by_mech", "c_alloc", "R malloc"), ("recall_by_mech", "cpp_new", "R new"),
            ("recall_by_mech", "realloc_fail", "R realloc"), ("spec_by_good_kind", "G2B", "Spec G2B"),
            ("spec_by_good_kind", "B2G", "Spec B2G")]
    rows = main_rows(results, "layer1")
    fig, axes = plt.subplots(1, 2, figsize=(6.9, 3.1), layout="constrained", sharey=True)
    for ax, layer, title in zip(axes, ("layer1", "layer3"), ("Debiased", "DeadFree")):
        grid = []
        for r in rows:
            info = ok(r, layer)
            grid.append([float("nan") if info is None or info[f].get(k) is None else info[f][k] for f, k, _ in cols])
        heat(ax, grid, [c[2] for c in cols], [r["label"] + ("†" if (ok(r, layer) or {}).get("subset") else "")
                                              for r in rows], fontsize=6.2)
        ax.set_title(title, fontsize=9)
        ax.tick_params(axis="x", labelsize=7, labelrotation=30)
        ax.tick_params(axis="y", labelsize=7)
    save(fig, "mechanism.pdf")


# ---------------------------------------------------------------------------
# DeadFree figures for the v4 main deck.  Every model comparison is on DeadFree only.  Quality comes from
# juliet_full/analysis/deadfree/deadfree_quality.json, concurrency-1 latency from latency_deadfree.csv (both written
# by lane latency-deadfree).  A value missing from either file is drawn grey and printed as "pending".
# ---------------------------------------------------------------------------
FACT_ATTRIBUTION_PATH = JULIET_FULL / "analysis" / "l4d_peek" / "fact_error_attribution.out.txt"
PRUNE_TEST_PATH = JULIET_FULL / "l4d_ft" / "results" / "scores" / "prune_test.json"
L4D_SCORES_DIR = JULIET_FULL / "l4d_ft" / "results" / "scores"
PROBES_ALL_PATH = JULIET_FULL / "data" / "build" / "probes_layer3.json"
# cloud = warm colours, local = cool colours, analyzers grey; our fine-tuned models green
DF_STYLE = {"deepseek": (VERMIL, "o"), "jev": (PURPLE, "D"), "qwen": (ORANGE, "^"), "intern": (SKY, "v"),
            "readout": (BLUE, "o"), "lora": (GREEN, "P"), "vulnllmr": (INK, "h"), "static": (GREY, "s"),
            "dynamic": (GREY, "X")}
DF_GROUP_LABELS = [("deepseek", "DeepSeek V4.1 Flash (cloud)"), ("jev", "Jev decision API (cloud)"),
                   ("qwen", "Qwen3.5-4B generative (local)"), ("intern", "Intern-Decision-4B (local)"),
                   ("readout", "Qwen read-out, no FT (local)"), ("lora", "ours: Qwen3.5-4B + LoRA (local)"),
                   ("vulnllmr", "VulnLLM-R-7B (local)"), ("static", "static analyzer"),
                   ("dynamic", "dynamic analysis (reference)")]
BUDGETS = [(0.1, "IDE < 0.1 s"), (1.0, "pre-commit < 1 s"), (10.0, "CI < 10 s")]


def df_kind(m: dict) -> str:
    if m["group"] == "static":
        return "static"
    if m["group"] == "dynamic-reference":
        return "dynamic"
    return next(k for k in ("deepseek", "jev", "qwen", "intern", "readout", "lora", "vulnllmr")
                if m["key"].startswith(k))


def load_deadfree(registry: dict) -> dict[str, dict]:
    """{key: quality row + lat / lat_p90 / lat_hw (None when pending)}; empty dict until the quality file exists."""
    cfg = registry["deadfree"]
    qpath, lpath = JULIET_FULL / cfg["quality"], JULIET_FULL / cfg["latency"]
    methods = {m["key"]: dict(m) for m in json.loads(qpath.read_text())["methods"]} if qpath.exists() else {}
    latency: dict[str, dict] = {}
    if lpath.exists():
        with lpath.open() as fh:
            for row in csv.DictReader(fh):
                # role "primary" = the configuration that produced the reported predictions; "secondary" rows
                # (other kernel) are checks only. Older files without a role column: first row per key wins.
                if row.get("quality_key") and row.get("role", "primary") == "primary":
                    latency.setdefault(row["quality_key"], row)

    def num(row, field):
        v = (row or {}).get(field)
        return None if v in (None, "", "pending") else float(v)

    for key, m in methods.items():
        m["short"] = cfg["short"].get(key, m["label"])
        m["lat"], m["lat_p90"] = num(latency.get(key), "median_s"), num(latency.get(key), "p90_s")
        m["lat_hw"] = (latency.get(key) or {}).get("hardware") or ""
        if m["status"] != "ok":
            m["macro_f1"] = None
    return methods


def df_f1(df: dict, key: str | None) -> float | None:
    return (df.get(key) or {}).get("macro_f1") if key else None


def df_lat(df: dict, key: str | None) -> float | None:
    return (df.get(key) or {}).get("lat") if key else None


def fmt_s(v: float | None) -> str:
    if v is None:
        return "pending"
    return f"{v * 1000:.0f} ms" if v < 1 else f"{v:.2f} s" if v < 10 else f"{v:.0f} s"


def shade_budgets(ax, xmin: float, y: float | None = None) -> None:
    lo = xmin
    for (hi, name), shade in zip(BUDGETS, ("#EAF1F8", "#F7F0E1", "#EAF1F8")):
        ax.axvspan(lo, hi, color=shade, zorder=0, lw=0)
        if y is not None:
            ax.text((lo * hi) ** 0.5, y, name, ha="center", va="bottom", fontsize=7.5, color=GREY,
                    transform=ax.get_xaxis_transform())
        lo = hi


def pending_bar(ax, x, width, log: bool, horizontal: bool = False, top: float = 1.0) -> None:
    style = dict(color=LIGHT, edgecolor=GREY, hatch="///", lw=0.4)
    lo = 0.01 if log else 0.0
    if horizontal:
        ax.barh(x, top - lo, width, left=lo, **style)
    else:
        ax.bar(x, top - lo, width, bottom=lo, **style)


def plot_df_intro_time(df: dict, cfg: dict) -> list[str]:
    """Intro (a): concurrency-1 latency per DeadFree unit, cloud vs local, against the deployment budgets."""
    keys = cfg["intro_time"]
    fig, ax = plt.subplots(figsize=(5.4, 2.1), layout="constrained")
    xmin, xmax = 0.01, 30.0
    shade_budgets(ax, xmin, y=1.0)
    pending = []
    ys = list(range(len(keys)))
    for y, key in zip(ys, keys):
        m = df.get(key)
        lat = (m or {}).get("lat")
        if lat is None:
            pending.append((m or {}).get("short", key))
            pending_bar(ax, y, 0.6, log=True, horizontal=True, top=xmax)
            ax.text(0.013, y, "latency pending", va="center", fontsize=8, color=GREY)
            continue
        color = DF_STYLE[df_kind(m)][0]
        ax.barh(y, lat - xmin, 0.6, left=xmin, color=color, alpha=0.9)
        ax.text(lat * 1.12, y, fmt_s(lat), va="center", fontsize=8.5, color=color, fontweight="semibold")
    where = ["cloud" if (df.get(k) or {}).get("group", "").startswith("cloud") else "local" for k in keys]
    ax.set_yticks(ys, [f"{(df.get(k) or {}).get('short', k)} ({w})" for k, w in zip(keys, where)], fontsize=9)
    ax.set_ylim(len(keys) - 0.5, -0.5)
    ax.set_xscale("log")
    ax.set_xlim(xmin, xmax)
    ax.set_xlabel("median latency per DeadFree unit, one request at a time (s, log)", fontsize=8.5)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "df_intro_time.pdf")
    return pending


def plot_df_intro_quality(df: dict, cfg: dict) -> None:
    """Intro (b): DeadFree macro-F1 of every strategy, one row per model; cloud on top."""
    rows = cfg["intro_quality"]
    fig, ax = plt.subplots(figsize=(5.2, 2.2), layout="constrained")
    ys = list(range(len(rows)))
    for y, (name, where, keys) in zip(ys, rows):
        got = [v for v in (df_f1(df, k) for k in keys) if v is not None]
        color = DF_STYLE[df_kind(df[keys[0]])][0] if keys[0] in df else GREY
        if not got:
            ax.text(0.42, y, "pending", va="center", fontsize=8, color=GREY)
            continue
        ax.plot([min(got), max(got)], [y, y], color=color, lw=7, alpha=0.25, solid_capstyle="round", zorder=1)
        ax.scatter(got, [y] * len(got), s=26, color=color, zorder=3, edgecolors="white", linewidths=0.5)
        span = short(min(got)) if len(got) == 1 else f"{short(min(got))}–{short(max(got))}"
        ax.text(max(got) + 0.02, y, span, va="center", fontsize=9, color=color, fontweight="semibold")
    ax.axhline(1.5, color=GREY, lw=0.6, ls=":")
    ax.set_yticks(ys, [f"{r[0]} ({r[1]})" for r in rows], fontsize=9)
    ax.set_ylim(len(rows) - 0.5, -0.5)
    ax.set_xlim(0.4, 1.06)
    ax.set_xticks([0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0], [".4", ".5", ".6", ".7", ".8", ".9", "1"])
    ax.set_xlabel("DeadFree macro-F1 (eval, 2,656 units); one dot per strategy", fontsize=8.5)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "df_intro_quality.pdf")


def grouped_bars(ax, df: dict, cfg: dict, value, log: bool = False) -> None:
    cols, rows = cfg["strategy_columns"], cfg["strategy_rows"]
    width = 0.8 / len(rows)
    for i, (_, keys) in enumerate(rows):
        for j, key in enumerate(keys):
            if key is None:
                continue
            x = j + (i - (len(rows) - 1) / 2) * width
            v = value(df, key)
            if v is None:
                pending_bar(ax, x, width * 0.9, log, top=3.0 if log else 1.0)
                ax.text(x, 0.012 if log else 0.03, "pending", rotation=90, ha="center", va="bottom", fontsize=6.5,
                        color=GREY, bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none"))
                continue
            kind = df_kind(df[key])
            lo = 0.01 if log else 0.0
            ax.bar(x, v - lo, width * 0.9, bottom=lo, color=DF_STYLE[kind][0], alpha=0.95 if kind == "lora" else 0.7,
                   edgecolor=INK if kind == "lora" else "none", lw=0.6)
            ax.text(x, v * 1.12 if log else v + 0.015, fmt_s(v).replace(" ", "") if log else short(v),
                    ha="center", va="bottom", fontsize=6.5, color=INK, rotation=90 if log else 0)
    ax.set_xticks(range(len(cols)), cols)
    ax.set_xlim(-0.5, len(cols) - 0.5)


def plot_df_strategies(df: dict, cfg: dict) -> None:
    """Results (b): local models x strategies on DeadFree, quality (left) and concurrency-1 latency (right)."""
    fig, (top, bot) = plt.subplots(1, 2, figsize=(6.4, 2.3), layout="constrained",
                                   gridspec_kw={"width_ratios": [1.25, 1]})
    grouped_bars(top, df, cfg, df_f1)
    top.set_ylim(0, 1.38)
    top.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0", ".25", ".5", ".75", "1"])
    top.set_ylabel("macro-F1", fontsize=9)
    grouped_bars(bot, df, cfg, df_lat, log=True)
    bot.set_yscale("log")
    bot.set_ylim(0.01, 60)
    bot.set_yticks([0.01, 0.1, 1, 10], ["0.01", "0.1", "1", "10"])
    bot.set_ylabel("latency (s)", fontsize=9)
    handles = [Patch(color=DF_STYLE[k][0], alpha=0.95 if k == "lora" else 0.7, label=lab) for k, lab in
               (("qwen", "Qwen3.5-4B generative"), ("intern", "Intern-Decision-4B"), ("readout", "Qwen read-out"),
                ("lora", "ours (LoRA)"))]
    top.legend(handles=handles, loc="upper left", ncol=2, frameon=False, fontsize=7, borderaxespad=0.2)
    top.set_title("quality", fontsize=8.5, loc="left")
    bot.set_title("speed (log)", fontsize=8.5, loc="left")
    save(fig, "df_strategies.pdf")


def before_after_rows(df: dict, meta: dict) -> list[tuple[str, list[tuple[str, str]], str]]:
    """[(strategy, [(baseline name, key)], fine-tuned key)] from strategy_x_ft; backup-role baselines dropped."""
    out = []
    for strategy, cells in (meta.get("strategy_x_ft") or {}).items():
        base = [(name, key) for name, key in cells.items()
                if name != "our FT" and (df.get(key) or {}).get("role", "primary") == "primary"]
        out.append((strategy.replace("L4 / L4-D", "L4-D"), base, cells["our FT"]))
    return out


def plot_df_before_after(df: dict, meta: dict) -> None:
    """Results (c): DeadFree macro-F1 before vs after fine-tuning, per strategy."""
    rows = before_after_rows(df, meta)
    fig, ax = plt.subplots(figsize=(6.4, 2.2), layout="constrained")
    kinds = {"Qwen gen.": "qwen", "Intern-Decision": "intern", "read-out": "readout"}
    width = 0.2
    for j, (strategy, base, ft) in enumerate(rows):
        bars = [(kinds[n], k) for n, k in base] + [("lora", ft)]
        xs = [j + (i - (len(bars) - 1) / 2) * width for i in range(len(bars))]
        for x, (kind, key) in zip(xs, bars):
            v = df_f1(df, key)
            if v is None:
                pending_bar(ax, x, width * 0.9, log=False)
                ax.text(x, 0.03, "pending", rotation=90, ha="center", va="bottom", fontsize=7, color=GREY,
                        bbox=dict(boxstyle="square,pad=0.1", fc="white", ec="none"))
                continue
            ax.bar(x, v, width * 0.9, color=DF_STYLE[kind][0], alpha=0.95 if kind == "lora" else 0.7,
                   edgecolor=INK if kind == "lora" else "none", lw=0.7)
            ax.text(x, v + 0.015, short(v), ha="center", va="bottom", fontsize=7.5, color=INK)
        pre = [df_f1(df, k) for _, k in base if df_f1(df, k) is not None]
        post = df_f1(df, ft)
        if pre and post is not None:
            d = post - max(pre)
            ax.text(j, 1.03, "FT vs best untuned\n" + signed(d).replace("0.", "."), ha="center", va="bottom",
                    fontsize=8.5, color=GREEN if d > 0 else VERMIL, fontweight="semibold", linespacing=1.1)
    ax.set_xticks(range(len(rows)), [f"{s}\n" + ("fact labels" if s == "L4-D" else "unit labels") for s, *_ in rows],
                  fontsize=9)
    ax.set_ylim(0, 1.22)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0", ".25", ".5", ".75", "1"])
    ax.set_ylabel("DeadFree macro-F1", fontsize=9)
    handles = [Patch(color=DF_STYLE[k][0], alpha=0.95 if k == "lora" else 0.7, label=lab) for k, lab in
               (("qwen", "Qwen3.5-4B gen. (untuned)"), ("intern", "Intern-Decision-4B (untuned)"),
                ("readout", "Qwen read-out (untuned)"), ("lora", "after LoRA fine-tuning"))]
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.0, 1.0), frameon=False, fontsize=8)
    save(fig, "df_before_after.pdf")


def plot_df_pareto(df: dict, cfg: dict) -> list[str]:
    """Results (d): DeadFree macro-F1 vs concurrency-1 latency (log).  Front over the model-based methods; static
    analyzers grey; dynamic analysis as a reference line.  Methods whose latency is still pending sit in a grey strip
    at the right edge at their (known) macro-F1."""
    fig, ax = plt.subplots(figsize=(6.7, 3.1), layout="constrained")
    xmin, xmax, xend, strip = 0.005, 30.0, 200.0, 80.0
    shade_budgets(ax, xmin, y=1.0)
    strip_artists = [ax.axvspan(xmax, xend, color=LIGHT, zorder=0, lw=0),
                     ax.text(strip, 1.0, "latency\npending", ha="center", va="bottom", fontsize=7, color=GREY,
                             transform=ax.get_xaxis_transform())]
    pts, front_pts, pending = [], [], []
    exclude = set(cfg["pareto_exclude"])
    # cloud services: one label per service (at its best strategy), the legend names the rest
    cloud_label = {}
    for kind, name in (("deepseek", "DeepSeek"), ("jev", "Jev")):
        ks = [k for k, m in df.items() if k not in exclude and m.get("role") == "primary" and m["macro_f1"] is not None
              and m["lat"] is not None and df_kind(m) == kind]
        if ks:
            strategies = sorted(df[k]["strategy"] for k in ks)
            cloud_label[max(ks, key=lambda k: df[k]["macro_f1"])] = f"{name} {strategies[0]}–{strategies[-1]}"
    for key, m in df.items():
        if key in exclude or m["macro_f1"] is None or m.get("role") != "primary":
            continue
        kind = df_kind(m)
        color, marker = DF_STYLE[kind]
        y = m["macro_f1"]
        if kind == "dynamic":
            ax.axhline(y, color=GREY, ls="--", lw=0.8, zorder=1)
            ax.text(xmin * 1.15, y + 0.004, f"{m['short']} {short(y)}", fontsize=7, color=GREY, va="bottom")
            continue
        if m["lat"] is None:
            pending.append(m["short"])
            ax.scatter(strip, y, s=24, marker=marker, facecolors="white", edgecolors=color, linewidths=1.0, zorder=3)
            continue
        x = max(m["lat"], xmin * 1.2)
        hero = key == "lora_l4d_opt"
        if m.get("macro_f1_ci") and kind != "static":
            ax.plot([x, x], m["macro_f1_ci"], color=color, lw=0.8, zorder=2)
        ax.scatter(x, y, s=130 if hero else 36, marker="*" if hero else marker, color=color, zorder=4,
                   edgecolors=INK if hero else "white", linewidths=0.6)
        if kind in ("deepseek", "jev"):
            if key in cloud_label:
                pts.append((x, y, cloud_label[key], color, False))
        else:
            pts.append((x, y, m["short"], color, kind == "static"))
        if kind != "static":
            front_pts.append((x, y))
    full, opt = df.get("lora_l4d") or {}, df.get("lora_l4d_opt") or {}
    if full.get("lat") and opt.get("lat"):  # speed-up from asking only the facts the rules read
        ax.scatter(full["lat"], full["macro_f1"], s=30, marker="P", facecolors="white", edgecolors=GREEN, zorder=3)
        pts.append((full["lat"], full["macro_f1"], "all questions", GREEN, True))
        ax.annotate("", (opt["lat"], opt["macro_f1"]), (full["lat"], full["macro_f1"]),
                    arrowprops=dict(arrowstyle="-|>", color=GREEN, lw=0.8))
    front, best = [], -1.0
    for x, y in sorted(front_pts):
        if y > best:
            front.append((x, y))
            best = y
    if len(front) > 1:
        ax.step([p[0] for p in front], [p[1] for p in front], where="post", color=INK, lw=0.9, alpha=0.55, zorder=1)
    ax.set_xscale("log")
    if pending:
        ax.set_xlim(xmin, xend)
    else:
        for a in strip_artists:
            a.remove()
        ax.set_xlim(xmin, xmax)
    ax.set_xticks([0.01, 0.1, 1, 10], ["0.01", "0.1", "1", "10"])
    ax.set_ylim(0.3, 1.04)
    label_points(ax, pts)
    ax.set_xlabel("median latency per DeadFree unit at concurrency 1 (s, log)")
    ax.set_ylabel("DeadFree macro-F1 (95% CI)")
    present = {df_kind(m) for k, m in df.items() if k not in exclude and m.get("role") == "primary"}
    handles = [Line2D([], [], marker=DF_STYLE[k][1], color=DF_STYLE[k][0], ls="--" if k == "dynamic" else "",
                      label=lab) for k, lab in DF_GROUP_LABELS if k in present]
    handles += [Line2D([], [], marker="*", color=GREEN, markeredgecolor=INK, ms=10, ls="", label="FT L4-D (opt.)"),
                Line2D([], [], color=INK, alpha=0.55, lw=0.9, label="front, model-based methods")]
    ax.legend(handles=handles, loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False, fontsize=7.2)
    save(fig, "df_pareto.pdf")
    return pending


def read_fact_attribution() -> dict[str, dict[str, tuple[float, int, int]]]:
    """{layer: {substituted fact type: (macro-F1, FP, FN)}} from the parent's gold-fact substitution run."""
    out: dict[str, dict] = {}
    layer = None
    lines = FACT_ATTRIBUTION_PATH.read_text().splitlines() if FACT_ATTRIBUTION_PATH.exists() else []
    for line in lines:
        if line.startswith("== "):
            layer = line[3:].strip()
            out[layer] = {}
        elif "macro-F1" in line and layer:
            name, rest = line.split("macro-F1")
            f1, _, fp, _, fn = rest.split()[:5]
            out[layer][name.strip().removeprefix("gold").strip()] = (float(f1), int(fp), int(fn))
    return out


def plot_df_attribution(attr: dict) -> None:
    """Methods: replace one fact type by its gold (dynamic-analysis) value; DeadFree eval macro-F1, rules frozen."""
    rows = attr.get("layer3")
    fig, ax = plt.subplots(figsize=(4.6, 2.05), layout="constrained")
    if not rows:
        ax.text(0.5, 0.5, "fact attribution pending", ha="center", color=GREY, transform=ax.transAxes)
        save(fig, "df_attribution.pdf")
        return
    order = [("none", "model facts (FT L4-D)"), ("heap", "+ gold heap"), ("exec_any", "+ gold exec_any"),
             ("realloc_safe", "+ gold realloc_safe"), ("rel", "+ gold rel"), ("exec_all", "+ gold exec_all"),
             ("all", "all facts gold (oracle)")]
    order = [(k, lab) for k, lab in order if k in rows]
    ys = list(range(len(order)))
    vals = [rows[k][0] for k, _ in order]
    colors = [GREEN if k == "none" else VERMIL if k == "exec_all" else GREY if k == "all" else SKY for k, _ in order]
    ax.barh(ys, [v - 0.7 for v in vals], 0.62, left=0.7, color=colors, alpha=0.88)
    bar_labels(ax, ys, vals, [INK] * len(vals), fontsize=8.5, dx=0.006)
    ax.set_yticks(ys, [lab for _, lab in order], fontsize=8.5)
    ax.set_ylim(len(order) - 0.5, -0.5)
    ax.set_xlim(0.7, 1.04)
    ax.set_xticks([0.7, 0.8, 0.9, 1.0], [".7", ".8", ".9", "1"])
    ax.set_xlabel("DeadFree macro-F1 (eval), rules unchanged", fontsize=8.5)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    save(fig, "df_attribution.pdf")


def deadfree_numbers(df: dict, attr: dict, meta: dict) -> dict[str, dict[str, str]]:
    """\\res{df-<key>}{<metric>}: macro ci p r f1 tp fp tn fn lat p90 d1 d1ci gap1 gap1ci d4 d4ci gap4 gap4ci;
    \\res{df-x}{...}: speed-up, paired deltas (pd_<a>__<b>, pd_<a>__<b>_ci), pruning, fact attribution,
    per-layer / per-fold L4-D scores, shortcut probes."""
    out: dict[str, dict[str, str]] = {}
    for key, m in df.items():
        cells = {}
        if m["macro_f1"] is not None:
            ci = m.get("macro_f1_ci")
            cells.update(macro=f3(m["macro_f1"]), p=f3(m["precision_leak"]), r=f3(m["recall_leak"]),
                         f1=f3(m["f1_leak"]), **{k: f"{m[k]:,}" for k in ("tp", "fp", "tn", "fn")})
            if ci:
                cells["ci"] = f"[{ci[0]:.3f}, {ci[1]:.3f}]"
            for tag, field in (("d1", "delta_vs_ds_l1"), ("d4", "delta_vs_ds_l4")):
                if m.get(field) is not None:
                    cells[tag] = signed(m[field])
                    cells[tag + "ci"] = "[" + ", ".join(signed(v) for v in m[field + "_ci"]) + "]"
            for tag, field in (("gap1", "gap_closed_ds_l1"), ("gap4", "gap_closed_ds_l4")):
                if m.get(field) is not None:
                    cells[tag] = f"{100 * m[field]:.0f}\\,\\%"
                    cells[tag + "ci"] = "[" + ", ".join(f"{100 * v:.0f}" for v in m[field + "_ci"]) + "]\\,\\%"
        if m["lat"] is not None:
            cells["lat"] = fmt_s(m["lat"]).replace(" ", "\\,")
        if m["lat_p90"] is not None:
            cells["p90"] = fmt_s(m["lat_p90"]).replace(" ", "\\,")
        out[f"df-{key}"] = cells
    x: dict[str, str] = {}
    ds, ours = df.get("deepseek_L1") or {}, df.get("lora_l4d_opt") or {}
    if ds.get("lat") and ours.get("lat"):
        x["speedup_ds_l1"] = f"{ds['lat'] / ours['lat']:.1f}"
    for pd in meta.get("paired_deltas", []):
        tag = f"pd_{pd['a']}__{pd['b']}"
        x[tag] = signed(pd["delta"])
        x[tag + "_ci"] = "[" + ", ".join(signed(v) for v in pd["delta_ci"]) + "]"
    if PRUNE_TEST_PATH.exists():
        total = 0
        for layer, info in json.loads(PRUNE_TEST_PATH.read_text())["layers"].items():
            q = info["questions_per_unit_eval"]
            x[f"q_full_{layer}"], x[f"q_pruned_{layer}"] = f"{q['full']['median']:.0f}", f"{q['pruned']['median']:.0f}"
            diffs = sum(v["pred_diffs"] for run in ("gold", "stored_lora_l4d") for v in info.get(run, {}).values())
            x[f"prune_diffs_{layer}"] = f"{diffs:,}"
            total += diffs
        x["prune_diffs_total"] = f"{total:,}"
    for layer, rows in attr.items():
        for name, (f1, fp, fn) in rows.items():
            tag = name.replace("+", "_")
            x[f"attr_{layer}_{tag}"], x[f"attr_{layer}_{tag}_fp"], x[f"attr_{layer}_{tag}_fn"] = f3(f1), str(fp), str(fn)
    for path in sorted(L4D_SCORES_DIR.glob("lora_l4d_opt_*_eval_r1.json")):
        layer = path.name.removeprefix("lora_l4d_opt_").removesuffix("_eval_r1.json")
        s = json.loads(path.read_text())
        x[f"l4d_{layer}"] = f3(s["all_eval"]["macro_f1"])
        for fold, v in s.get("per_fold", {}).items():
            x[f"l4d_{layer}_fold{fold}"] = f3(v["macro_f1"])
    if PROBES_ALL_PATH.exists():
        for layer, rows in json.loads(PROBES_ALL_PATH.read_text()).items():
            for probe in ("static_void", "grep_v0", "bow_lr"):
                x[f"probe_{probe}_{layer}"] = f3(rows[probe]["macro_f1"]["all"])
            for sub in ("all", "B2G", "G2B"):
                x[f"probe_bow_auroc_{sub}_{layer}"] = f3(rows["bow_lr"]["auroc"][sub])
    out["df-x"] = x
    return out


def write_df_strategy_table(df: dict, cfg: dict) -> None:
    """Backup: the strategy grid as a table, macro-F1 / concurrency-1 latency."""
    cols = cfg["strategy_columns"]
    lines = ["% generated by figures/make_figures.py from juliet_full/analysis/deadfree (quality + latency)",
             "\\begin{tabular}{@{}l" + "c" * len(cols) + "@{}}", "\\toprule",
             "Local model & " + " & ".join(cols) + " \\\\", "\\midrule"]
    for name, keys in cfg["strategy_rows"]:
        cells = []
        for key in keys:
            m = df.get(key) if key else None
            if key is None:
                cells.append("--")
                continue
            f1 = "\\textit{pending}" if not m or m["macro_f1"] is None else f3(m["macro_f1"])
            lat = "\\textit{pending}" if not m or m["lat"] is None else fmt_s(m["lat"]).replace(" ", "\\,")
            cells.append(f"{f1} / {{\\scriptsize {lat}}}")
        lines.append(tex_escape(name) + " & " + " & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "df_strategies.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/df_strategies.tex")


def write_df_by_flow(df: dict) -> None:
    """Backup: DeadFree macro-F1 per flow category for the main methods."""
    keys = ["deepseek_L1", "deepseek_L4", "jev_L3", "qwen_L3", "intern_L3", "intern_l4d", "lora_L1", "lora_l4d_opt", "clang_sa"]
    lines = ["% generated by figures/make_figures.py from juliet_full/analysis/deadfree/deadfree_quality.json",
             "\\begin{tabular}{@{}l" + "c" * len(FLOW_CATEGORIES) + "@{}}", "\\toprule",
             "Method & " + " & ".join(FLOW_LABELS[c] for c in FLOW_CATEGORIES) + " \\\\", "\\midrule"]
    for key in keys:
        m = df.get(key)
        if not m or m["macro_f1"] is None:
            lines.append(tex_escape(key) + " & " + " & ".join(["\\textit{pending}"] * len(FLOW_CATEGORIES)) + " \\\\")
            continue
        cells = [f3(m["by_flow"][c]["macro_f1"]) if c in m["by_flow"] else "--" for c in FLOW_CATEGORIES]
        lines.append(tex_escape(m["short"]) + " & " + " & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "df_by_flow.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/df_by_flow.tex")


# ---------------------------------------------------------------------------
# TeX side files
# ---------------------------------------------------------------------------
def f3(v) -> str:
    return "--" if v is None else f"{v:.3f}"


def signed(v) -> str:
    return "--" if v is None else ("$-$" if v < -0.0005 else "+" if v > 0.0005 else "$\\pm$") + f"{abs(v):.3f}"


def tex_escape(s: str) -> str:
    return s.replace("_", "\\_").replace("%", "\\%").replace("&", "\\&").replace("#", "\\#")


def write_numbers(results: list[dict], extra: dict[str, str], deadfree: dict[str, dict[str, str]]) -> None:
    lines = ["% generated by figures/make_figures.py -- do not edit",
             "% \\res{<method key>-<layer>}{<metric>}: p r f1 macro spec ci n tp fp tn fn; paired vs layer1: base d",
             "% lost gained flips; \\res{df-<key>}{<metric>}: DeadFree quality + latency (see deadfree_numbers);",
             "% unknown or pending -> \\textit{pending}",
             "\\providecommand{\\res}[2]{\\ifcsname res-#1-#2\\endcsname\\csname res-#1-#2\\endcsname"
             "\\else\\textit{pending}\\fi}"]

    def put(name, metric, value):
        lines.append(f"\\expandafter\\def\\csname res-{name}-{metric}\\endcsname{{{value}}}")

    for r in results:
        for layer, info in r["layers"].items():
            if info["status"] != "ok":
                continue
            name = f"{r['key']}-{layer}"
            for m in ("p", "r", "f1", "macro", "spec", "base"):
                if m in info:
                    put(name, m, f3(info[m]))
            for m in ("n", "tp", "fp", "tn", "fn", "lost", "gained", "flips"):
                if m in info:
                    put(name, m, f"{info[m]:,}")
            if "d" in info:
                put(name, "d", signed(info["d"]))
            if info["macro_ci"]:
                put(name, "ci", f"[{info['macro_ci'][0]:.3f}, {info['macro_ci'][1]:.3f}]")
            for mech, v in info["recall_by_mech"].items():
                if v is not None:
                    put(name, f"r_{mech}", f3(v))
    for k, v in extra.items():
        put("x", k, v)
    for name, cells in deadfree.items():
        for metric, v in cells.items():
            put(name, metric, v)
    (HERE / "numbers.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/numbers.tex")


def write_original_table(results: list[dict]) -> None:
    """Hook table: original Juliet vs layer 1, eval set, every method with an original-layer run."""
    probes = json.loads(PROBES_PATH.read_text())
    rows = [("\\code{static void} $\\Rightarrow$ good (probe)", probes["original"]["static_void"]["macro_f1"]["all"],
             probes["layer1"]["static_void"]["macro_f1"]["all"], "", False)]
    for r in results:
        if "original" not in r["layers"] or r["family"] == "Ablation":
            continue
        o, l1 = ok(r, "original"), ok(r, "layer1")
        name = {"grep": "grep: no \\code{free}/\\code{delete} $\\Rightarrow$ leak"}.get(r["key"], r["label"])
        mark = "$^\\dagger$" if o and o.get("subset") else ""
        rows.append((name + ("" if r["ranked"] else " (ref.)"), o and o["macro"], l1 and l1["macro"], mark,
                     not r["ranked"]))
    done = sorted([x for x in rows if x[1] is not None], key=lambda x: -x[1])
    pend = [x for x in rows if x[1] is None]
    lines = ["% generated by figures/make_figures.py -- do not edit", "\\begin{tabular}{@{}lrr@{}}", "\\toprule",
             "Detector & Original & Debiased \\\\", "\\midrule"]
    for name, o, l1, mark, ref in done + pend:
        cells = [name, ("\\textit{pending}" if o is None else f"{o:.3f}{mark}"),
                 "\\textit{pending}" if l1 is None else f"{l1:.3f}"]
        if name.startswith("grep") or name.startswith("\\code{static"):
            cells = [f"\\alert{{{c}}}" for c in cells]
        if ref:
            cells = [f"\\textcolor{{NeutDraw}}{{{c}}}" for c in cells]
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "original.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/original.tex")


def write_demo_table() -> dict[str, str]:
    """Verdict table of the newest stage recording (DEMO_PATHS); \\res{x}{demo_flipped|demo_held}: detectors whose
    verdict on the dead-free bad unit flips to no-leak vs stays leak.  A recording without the L4-D row gets a
    pending row."""
    path = next((p for p in DEMO_PATHS if p.exists()), None)
    if path is None:
        (HERE / "demo.tex").write_text("\\textit{demo recording pending}\n")
        return {}
    rec = json.loads(path.read_text())
    names = {"grep": "grep", "clang": "Clang SA", "ft": "old LoRA L1 (unit labels)", "ft_l3": "old LoRA L3 (unit labels)",
             "l4d": "FT L4-D (opt.)", "ds_l1": "DeepSeek L1", "ds_l3": "DeepSeek L3", "jev": "Jev L1"}
    truth = {c["key"]: c["truth"] for c in rec["cases"]}
    lines = [f"% generated by figures/make_figures.py from presentation/demo/recordings/{path.name}",
             "\\begin{tabular}{@{}lccc r@{}}", "\\toprule",
             "Detector & bad & good twin & bad + dead free & ms \\\\", "\\midrule"]
    flipped, held = [], []
    for m in rec["methods"]:
        cells = [names.get(m, m)]
        for case in ("bad", "good", "attacked"):
            res = rec["results"][case][m]
            verdict = {1: "leak", 0: "no leak"}.get(res["pred"], "error")
            mark = "\\cmark" if res["pred"] == truth[case] else "\\xmark"
            flip = (case == "attacked" and res["pred"] != rec["results"]["bad"][m]["pred"])
            cells.append(f"{mark}\\,{verdict}" + ("\\,\\textcolor{OIvermil}{\\small flipped}" if flip else ""))
        attacked = rec["results"]["attacked"][m]["pred"]
        (held if attacked == truth["attacked"] else flipped).append(names.get(m, m))
        cells.append(f"{rec['results']['bad'][m]['latency_ms']:.0f}")
        lines.append(" & ".join(cells) + " \\\\")
    l4d_eval = None if "l4d" in rec["methods"] else demo_l4d_eval_row(rec)
    if l4d_eval is not None:
        cells = [names["l4d"] + "$^*$"]
        for case in ("bad", "good", "attacked"):
            pred = l4d_eval[case]
            mark = "\\cmark" if pred == truth[case] else "\\xmark"
            flip = case == "attacked" and pred != l4d_eval["bad"]
            cells.append(f"{mark}\\,{ {1: 'leak', 0: 'no leak'}[pred]}"
                         + ("\\,\\textcolor{OIvermil}{\\small flipped}" if flip else ""))
        cells.append("--")
        lines.append(" & ".join(cells) + " \\\\")
        (held if l4d_eval["attacked"] == truth["attacked"] else flipped).append(names["l4d"])
    elif "l4d" not in rec["methods"]:
        lines.append(names["l4d"] + " & \\multicolumn{4}{c}{\\textit{pending: recording without the L4-D row}} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    if l4d_eval is not None:
        lines.append("\n\\par\\vspace{2pt}{\\scriptsize $^*$ from the frozen eval run (\\code{lora\\_l4d\\_opt}, same units), "
                     "not the live recording\\par}")
    (HERE / "demo.tex").write_text("\n".join(lines) + "\n")
    print(f"wrote figures/demo.tex from {path.name}")
    return {"demo_run": tex_escape(rec["run_id"]), "demo_file": tex_escape(path.name),
            "demo_cny": f"{rec['spent']['deepseek']:.4f}", "demo_usd": f"{rec['spent']['jev']:.5f}",
            "demo_flipped": ", ".join(flipped) or "none", "demo_held": ", ".join(held) or "none",
            "demo_has_l4d": "yes" if "l4d" in rec["methods"] else ("eval run" if l4d_eval else "no")}


DEMO_CASE_LAYERS = {"bad": "layer1", "good": "layer1", "attacked": "layer3"}


def demo_l4d_eval_row(rec: dict) -> dict[str, int] | None:
    """FT L4-D (opt.) predictions on the demo's three cases taken from the frozen eval runs, used until a recording
    with the L4-D row exists.  The stage cases are the layer1 bad/good units and the layer3 (DeadFree) bad unit; the
    attacked case must be the unchanged layer3 unit (attack.matches_layer3), otherwise no row is produced."""
    if not rec.get("attack", {}).get("matches_layer3"):
        return None
    out = {}
    for c in rec["cases"]:
        unit = c["unit"] if isinstance(c["unit"], dict) else ast.literal_eval(c["unit"])
        uid = unit["unit_id"].removesuffix("__stress")
        path = JULIET_FULL / "l4d_ft" / "results" / "lora_l4d_opt" / DEMO_CASE_LAYERS[c["key"]] / "eval_r1_units.jsonl"
        if not path.exists():
            return None
        pred = next((json.loads(line)["pred"] for line in path.open() if f'"{uid}"' in line
                     and json.loads(line)["unit_id"] == uid), None)
        if pred not in (0, 1):
            return None
        out[c["key"]] = pred
    return out


def write_repeat_table(registry: dict) -> None:
    lines = ["% generated by figures/make_figures.py -- do not edit", "\\begin{tabular}{@{}lrr@{}}", "\\toprule",
             "Model & units & all 3 runs agree \\\\", "\\midrule"]
    for rep in registry["repeats"]:
        paths = [JULIET_FULL / p for p in rep["files"]]
        if not all(p.exists() for p in paths):
            lines.append(f"{tex_escape(rep['label'])} & & \\textit{{pending}} \\\\")
            continue
        preds = [{r["unit_id"]: r.get("pred") for r in read_jsonl(p)} for p in paths]
        common = set.intersection(*(set(p) for p in preds))
        agree = sum(len({p[u] for p in preds}) == 1 for u in common)
        lines.append(f"{tex_escape(rep['label'])} & {len(common):,} & {agree / len(common):.3f} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "repeat.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/repeat.tex")


def write_cost_table() -> dict[str, str]:
    cost: dict[tuple[str, str], list] = defaultdict(lambda: [0, 0.0])
    currency = {}
    for line in LEDGER_PATH.read_text().splitlines():
        r = json.loads(line)
        if r.get("kind") != "call":
            continue
        layer = "demo" if r.get("purpose") == "demo" else r.get("layer") or "?"
        c = cost[(r["provider"], layer)]
        c[0] += 1
        c[1] += r.get("cost") or 0.0
        currency[r["provider"]] = r.get("currency")
    names = {"layer1": "Debiased (incl.\\ dev, repeats, latency)", "layer3": "DeadFree",
             "placebo": "Placebo", "original": "Original", "demo": "demo"}
    lines = ["% generated by figures/make_figures.py from juliet_full/llm/ledger.jsonl",
             "\\begin{tabular}{@{}llrr@{}}", "\\toprule", "Provider & Runs & calls & cost \\\\", "\\midrule"]
    extra = {}
    for provider, label, sym in (("deepseek", "DeepSeek", "\\textyen"), ("jev", "Jev", "\\$")):
        total = [0, 0.0]
        for layer in ("layer1", "layer3", "placebo", "original", "demo"):
            if (provider, layer) in cost:
                n, c = cost[(provider, layer)]
                total[0] += n
                total[1] += c
                lines.append(f"{label} & {names[layer]} & {n:,} & {sym}{c:.2f} \\\\")
        lines.append(f"\\textbf{{{label}}} & \\textbf{{total}} & \\textbf{{{total[0]:,}}} & "
                     f"\\textbf{{{sym}{total[1]:.2f}}} \\\\")
        lines.append("\\midrule" if provider == "deepseek" else "\\bottomrule")
        extra[f"cost_{provider}"] = f"{total[1]:.2f}"
    lines.append("\\end{tabular}")
    (HERE / "cost.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/cost.tex")
    return extra


def write_latency_table(latency: dict[str, dict], results: list[dict]) -> None:
    labels = {r["key"]: r["label"] for r in results}
    labels.update({"codeql_amortized": "CodeQL (50 per database)", "linevul_cpu": "LineVul (CPU)",
                   "linevul": "LineVul (GPU)"})
    lines = ["% generated by figures/make_figures.py from figures/latency_c1.csv", "\\begin{tabular}{@{}lrl@{}}",
             "\\toprule", "Method & s / unit & Source (juliet\\_full/\\ldots); note \\\\", "\\midrule"]
    for key, row in latency.items():
        src = row["source"].removeprefix("juliet_full/").removeprefix("lane_reports/2026-11-23_")
        lines.append(f"{tex_escape(labels.get(key, key))} & {tex_escape(row['shown'])} & "
                     f"\\texttt{{{tex_escape(src)}}}; {tex_escape(row['note'])} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (HERE / "latency.tex").write_text("\n".join(lines) + "\n")
    print("wrote figures/latency.tex")


def write_provenance(results: list[dict], rows_per_frame: int = 22) -> None:
    """Backup frames listing every scored run file; split into as many frames as the rows need."""
    rows, pend = [], []
    for r in results:
        for layer, info in r["layers"].items():
            if info["status"] != "ok":
                pend.append(f"{r['label']} {layer}")
                continue
            f = info["files"][0].replace("results/", "r/") + (f" (+{len(info['files']) - 1})"
                                                               if len(info["files"]) > 1 else "")
            rows.append(f"{tex_escape(r['label'])} & {LAYER_NAMES[layer]} & \\texttt{{{tex_escape(f)}}} & "
                        f"\\texttt{{{info['sha256_8']}}} \\\\")
    chunks = [rows[i:i + rows_per_frame] for i in range(0, len(rows), rows_per_frame)] or [[]]
    out = ["% generated by figures/make_figures.py -- do not edit (input outside a frame)"]
    for k, chunk in enumerate(chunks, 1):
        out += [f"\\begin{{frame}}{{Backup: result files used ({k}/{len(chunks)})}}", "\\centering",
                "{\\tiny\\renewcommand{\\arraystretch}{0.85}\\setlength{\\tabcolsep}{4pt}\\begin{tabular}{@{}llll@{}}", "\\toprule",
                "Method & Layer & Run file (juliet\\_full/\\ldots; r = results) & sha256 \\\\", "\\midrule"] + chunk
        if k == len(chunks) and pend:
            out += ["\\midrule", f"\\multicolumn{{4}}{{@{{}}p{{0.9\\textwidth}}}}{{\\textit{{pending: "
                                  f"{tex_escape(', '.join(pend))}}}}} \\\\"]
        out += ["\\bottomrule", "\\end{tabular}\\par}", "\\vfill",
                "{\\scriptsize Scored with \\texttt{juliet\\_full/analysis/score.py} on the eval set (2,656 units); "
                "\\texttt{figures/make\\_figures.py}.\\par}", "\\end{frame}"]
    (HERE / "provenance.tex").write_text("\n".join(out) + "\n")
    print(f"wrote figures/provenance.tex ({len(chunks)} frames)")


def probe_numbers() -> dict[str, str]:
    """\\res{x}{probe_<probe>_<layer>}: shortcut-probe macro-F1 from data/build/probes.json (eval set)."""
    probes = json.loads(PROBES_PATH.read_text())
    return {f"probe_{key}_{layer}": f3(probes[layer][key]["macro_f1"]["all"])
            for layer in ("original", "layer1") for key in ("static_void", "func_count", "length_lines", "bow_lr")}


def unmerged_flips(results: list[dict]) -> dict[str, str]:
    out = {}
    for s in ("L1", "L3"):
        a, b = get(results, f"lora_{s}")["_rows"].get("layer1"), get(results, f"lora_unmerged_{s}")["_rows"].get("layer1")
        if a and b:
            out[f"unmerged_flips_{s}"] = f"{lost_gained(a[0], a[1], b[1])[2]:,}"
    return out


def main() -> None:
    setup_style()
    registry = json.loads(REGISTRY_PATH.read_text())
    latency = read_latency()
    results = collect(registry)
    plot_prf1(results, "prf1.pdf", MAIN_EXCLUDE, (5.6, 2.6))
    plot_robustness(results, "robustness.pdf", MAIN_EXCLUDE, (5.7, 2.25))
    pending = {"prf1": plot_prf1(results, "prf1_full.pdf"), "pareto": plot_pareto(results, latency),
               "robustness": plot_robustness(results, "robustness_full.pdf"), "lora": plot_lora(results)}
    plot_hook_original(results)
    plot_quality(results)
    plot_nearllm(results, latency)
    plot_deadfree(results)
    plot_probes()
    plot_heatmap(results)
    plot_mechanism(results)
    df, cfg = load_deadfree(registry), registry["deadfree"]
    df_meta = json.loads((JULIET_FULL / cfg["quality"]).read_text()) if (JULIET_FULL / cfg["quality"]).exists() else {}
    attr = read_fact_attribution()
    pending["df_intro_time"] = plot_df_intro_time(df, cfg)
    pending["df_pareto"] = plot_df_pareto(df, cfg)
    plot_df_intro_quality(df, cfg)
    plot_df_strategies(df, cfg)
    plot_df_before_after(df, df_meta)
    plot_df_attribution(attr)
    write_df_strategy_table(df, cfg)
    write_df_by_flow(df)
    extra = {**write_demo_table(), **write_cost_table(), **unmerged_flips(results), **probe_numbers()}
    write_numbers(results, extra, deadfree_numbers(df, attr, df_meta))
    write_original_table(results)
    write_repeat_table(registry)
    write_latency_table(latency, results)
    write_provenance(results)
    summary = [{k: v for k, v in r.items() if k != "_rows"} for r in results]
    (HERE / "results_summary.json").write_text(json.dumps(
        {"generated": dt.datetime.now().isoformat(timespec="seconds"), "scorer": "juliet_full/analysis/score.py",
         "set": EVAL_SET, "bootstrap": BOOTSTRAP, "pending_by_figure": pending, "methods": summary}, indent=1))
    print("wrote figures/results_summary.json")
    for r in results:
        cells = []
        for layer in LAYERS:
            if layer in r["layers"]:
                info = r["layers"][layer]
                cells.append(f"{layer} " + (f"{info['macro']:.3f}" + (f" (Δ{info['d']:+.3f})" if "d" in info else "")
                                            if info["status"] == "ok" else "PENDING"))
        print(f"  {r['key']:<20} " + " | ".join(cells))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Robustness of one method from layer 1 to the stress layer (layer 3), with the placebo layer as control.

All three layers have the same unit_ids, labels and families (juliet_full/README.md section 3), so
labels and clusters come from one units file (default data/build/layer1.jsonl).  Predictions are
scored as in score.py: a missing or invalid prediction counts as wrong (bad -> 0, good -> 1), and
that effective verdict is the one compared across layers.

Reported per comparison (stress vs base, placebo vs base), separately for bad and good units:
  flip_rate      share of units whose effective verdict changed
  right_to_wrong share that went from correct to wrong (lost detections on bad, new FPs on good)
  wrong_to_right share that went from wrong to correct
and the metric deltas (layer minus base) for f1_leak, macro_f1, precision, recall, specificity,
accuracy.  The placebo-adjusted value of every statistic is stress minus placebo, i.e.
(stress - base) - (placebo - base).  95% percentile CIs come from a family-cluster bootstrap
(families resampled with replacement, the same resample for every statistic).

Usage:
  analysis/robustness.py --base L1.jsonl --stress L3.jsonl [--placebo P.jsonl] [--set eval]
      [--subset nested25] [--units data/build/layer1.jsonl] [--bootstrap 2000] [--json] [--out F]
  analysis/robustness.py --self-test
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from score import (confusion, index_predictions, metrics_from_counts, percentile, read_jsonl,  # noqa: E402
                   select_units, valid_pred)

JULIET_FULL = Path(__file__).resolve().parents[1]
DEFAULT_UNITS = JULIET_FULL / "data" / "build" / "layer1.jsonl"
DEFAULT_SUBSETS = JULIET_FULL / "data" / "build" / "subsets.json"
DELTA_METRICS = ("f1_leak", "macro_f1", "precision_leak", "recall_leak", "specificity", "accuracy", "mcc")
FLIP_KEYS = ("flip_rate", "right_to_wrong", "wrong_to_right")
LABELS = {1: "bad", 0: "good"}


def effective(row: dict[str, Any] | None, truth: int) -> tuple[int, bool]:
    """(verdict used for flips, is_invalid); invalid/missing = the wrong verdict."""
    pred = valid_pred(row)
    return (1 - truth, True) if pred is None else (pred, False)


def unit_records(units: list[dict[str, Any]], layers: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    indexed = {name: index_predictions(rows)[0] for name, rows in layers.items()}
    records = []
    for unit in units:
        rec: dict[str, Any] = {"unit_id": unit["unit_id"], "family": unit["family"], "truth": unit["truth"],
                               "mechanism": unit.get("mechanism"), "good_kind": unit.get("good_kind"),
                               "flow_category": unit.get("flow_category")}
        for name, index in indexed.items():
            rec[name], rec[name + "_invalid"] = effective(index.get(unit["unit_id"]), unit["truth"])
        records.append(rec)
    return records


def counts_of(records: list[dict[str, Any]], layers: list[str]) -> dict[str, int]:
    """Additive counts: confusion per layer and flip counts per (layer vs base, label)."""
    out: dict[str, int] = {}
    for name in layers:
        pairs = [(r["truth"], None if r[name + "_invalid"] else r[name]) for r in records]
        for key, value in confusion(pairs).items():
            out[f"{name}.{key}"] = value
    for name in layers:
        if name == "base":
            continue
        for truth, label in LABELS.items():
            sel = [r for r in records if r["truth"] == truth]
            out[f"{name}.{label}.n"] = len(sel)
            out[f"{name}.{label}.changed"] = sum(r[name] != r["base"] for r in sel)
            out[f"{name}.{label}.right_to_wrong"] = sum(r["base"] == truth != r[name] for r in sel)
            out[f"{name}.{label}.wrong_to_right"] = sum(r["base"] != truth == r[name] for r in sel)
    return out


def layer_metrics(counts: dict[str, int], name: str) -> dict[str, Any]:
    return metrics_from_counts({k: counts[f"{name}.{k}"] for k in ("tp", "fp", "tn", "fn", "invalid", "n")})


def statistics_of(counts: dict[str, int], layers: list[str]) -> dict[str, float | None]:
    """Flat dict of every reported statistic (point estimate for one count vector)."""
    stats: dict[str, float | None] = {}
    metrics = {name: layer_metrics(counts, name) for name in layers}
    for name in layers:
        for m in DELTA_METRICS:
            stats[f"{name}.{m}"] = metrics[name][m]
    for name in layers:
        if name == "base":
            continue
        for m in DELTA_METRICS:
            a, b = metrics[name][m], metrics["base"][m]
            stats[f"delta_{name}.{m}"] = None if a is None or b is None else a - b
        for label in LABELS.values():
            n = counts[f"{name}.{label}.n"]
            stats[f"{name}.{label}.flip_rate"] = counts[f"{name}.{label}.changed"] / n if n else None
            for key in ("right_to_wrong", "wrong_to_right"):
                stats[f"{name}.{label}.{key}"] = counts[f"{name}.{label}.{key}"] / n if n else None
    if "stress" in layers and "placebo" in layers:
        for m in DELTA_METRICS:
            a, b = stats[f"delta_stress.{m}"], stats[f"delta_placebo.{m}"]
            stats[f"adjusted.{m}"] = None if a is None or b is None else a - b
        for label in LABELS.values():
            for key in FLIP_KEYS:
                a, b = stats[f"stress.{label}.{key}"], stats[f"placebo.{label}.{key}"]
                stats[f"adjusted.{label}.{key}"] = None if a is None or b is None else a - b
    return stats


def cluster_bootstrap(records: list[dict[str, Any]], layers: list[str], iterations: int,
                      seed: int) -> dict[str, list[float | None]]:
    by_family: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_family.setdefault(rec["family"], []).append(rec)
    family_counts = {f: counts_of(rs, layers) for f, rs in by_family.items()}
    families = sorted(family_counts)
    keys = list(next(iter(family_counts.values())))
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {}
    for _ in range(iterations):
        total = dict.fromkeys(keys, 0)
        for family in rng.choices(families, k=len(families)):
            for key, value in family_counts[family].items():
                total[key] += value
        for key, value in statistics_of(total, layers).items():
            if value is not None:
                samples.setdefault(key, []).append(value)
    return {key: [percentile(v, 0.025), percentile(v, 0.975)] for key, v in samples.items()}


def robustness(units: list[dict[str, Any]], base: list[dict[str, Any]], stress: list[dict[str, Any]],
               placebo: list[dict[str, Any]] | None = None, bootstrap: int = 2000, seed: int = 20261126,
               by: tuple[str, ...] = ("mechanism", "good_kind", "flow_category")) -> dict[str, Any]:
    layers = {"base": base, "stress": stress}
    if placebo is not None:
        layers["placebo"] = placebo
    names = list(layers)
    records = unit_records(units, layers)
    counts = counts_of(records, names)
    report: dict[str, Any] = {
        "n_units": len(records), "n_families": len({r["family"] for r in records}), "layers": names,
        "methods": {name: sorted({r.get("method") for r in rows}, key=str) for name, rows in layers.items()},
        "invalid": {name: counts[f"{name}.invalid"] for name in names},
        "stats": statistics_of(counts, names),
        "transitions": {f"{name}.{label}": {k: counts[f"{name}.{label}.{k}"]
                                             for k in ("n", "changed", "right_to_wrong", "wrong_to_right")}
                        for name in names if name != "base" for label in LABELS.values()},
    }
    if bootstrap:
        report["bootstrap"] = {"iterations": bootstrap, "seed": seed, "clusters": "family",
                               "ci95": cluster_bootstrap(records, names, bootstrap, seed)}
    report["breakdowns"] = {}
    for key in by:
        groups: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            if rec.get(key) is not None:
                groups.setdefault(str(rec[key]), []).append(rec)
        report["breakdowns"][key] = {}
        for value, rs in sorted(groups.items()):
            s = statistics_of(counts_of(rs, names), names)
            report["breakdowns"][key][value] = {"n": len(rs), **{
                k: s[k] for k in s if k.endswith(FLIP_KEYS) or k.startswith(("delta_", "adjusted."))}}
    return report


# ---------------------------------------------------------------- rendering

def fmt(value: Any, signed: bool = False) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:+.3f}" if signed else f"{value:.3f}"
    return str(value)


def with_ci(report: dict[str, Any], key: str, signed: bool = False) -> str:
    text = fmt(report["stats"].get(key), signed)
    ci = report.get("bootstrap", {}).get("ci95", {}).get(key)
    if ci and ci[0] is not None:
        text += f" [{fmt(ci[0], signed)}, {fmt(ci[1], signed)}]"
    return text


def render(report: dict[str, Any], label: str) -> str:
    names = report["layers"]
    lines = [f"## {label}: robustness ({report['n_units']} units, {report['n_families']} families)", ""]
    lines.append("| layer | macro-F1 | F1_leak | recall | specificity | invalid |")
    lines.append("|---|---|---|---|---|---|")
    for name in names:
        lines.append(f"| {name} | {with_ci(report, name + '.macro_f1')} | {with_ci(report, name + '.f1_leak')} | "
                     f"{fmt(report['stats'][name + '.recall_leak'])} | {fmt(report['stats'][name + '.specificity'])} | "
                     f"{report['invalid'][name]} |")
    lines += ["", "| comparison | Δmacro-F1 | ΔF1_leak | bad flip | bad right→wrong | good flip | good right→wrong |",
              "|---|---|---|---|---|---|---|"]
    rows = [(n, f"delta_{n}", n) for n in names if n != "base"]
    if "placebo" in names:
        rows.append(("stress − placebo (adjusted)", "adjusted", "adjusted"))
    for title, dkey, fkey in rows:
        lines.append(f"| {title} | {with_ci(report, dkey + '.macro_f1', True)} | {with_ci(report, dkey + '.f1_leak', True)} | "
                     f"{with_ci(report, fkey + '.bad.flip_rate', fkey == 'adjusted')} | "
                     f"{with_ci(report, fkey + '.bad.right_to_wrong', fkey == 'adjusted')} | "
                     f"{with_ci(report, fkey + '.good.flip_rate', fkey == 'adjusted')} | "
                     f"{with_ci(report, fkey + '.good.right_to_wrong', fkey == 'adjusted')} |")
    return "\n".join(lines)


# ---------------------------------------------------------------- self-test

def self_test() -> None:
    units = []
    for g in range(40):
        for truth, label in ((1, "bad"), (0, "good")):
            units.append({"unit_id": f"g{g}__{label}", "family": f"f{g % 8}", "truth": truth, "set": "eval",
                          "mechanism": "c_alloc" if g % 2 else "cpp_new",
                          "good_kind": None if truth else ("G2B" if g % 2 else "B2G"), "flow_category": "01"})

    def preds(fn):
        return [{"unit_id": u["unit_id"], "method": "m", "pred": fn(u), "status": "ok"} for u in units]

    base = preds(lambda u: u["truth"])                                   # perfect
    stress = preds(lambda u: 0 if u["truth"] or int(u["unit_id"][1:].split("_")[0]) < 30 else 1)  # all bad lost, 10 FPs
    placebo = preds(lambda u: u["truth"])
    rep = robustness(units, base, stress, placebo, bootstrap=200, seed=1)
    s = rep["stats"]
    assert s["base.macro_f1"] == 1.0 and s["placebo.macro_f1"] == 1.0, s
    assert s["stress.bad.flip_rate"] == 1.0 and s["stress.bad.right_to_wrong"] == 1.0
    assert abs(s["stress.good.flip_rate"] - 10 / 40) < 1e-12 and s["stress.good.wrong_to_right"] == 0.0
    assert s["placebo.bad.flip_rate"] == 0.0 and s["adjusted.bad.flip_rate"] == 1.0
    assert s["delta_stress.f1_leak"] == -1.0 and s["adjusted.f1_leak"] == -1.0
    # stress: tp 0, fn 40, tn 30, fp 10 -> f1_leak 0, f1_noleak 2*30/(2*30+40+10)
    assert abs(s["delta_stress.macro_f1"] - (60 / 110 / 2 - 1.0)) < 1e-12
    ci = rep["bootstrap"]["ci95"]["stress.good.flip_rate"]
    assert ci[0] <= s["stress.good.flip_rate"] <= ci[1], ci
    assert rep["transitions"]["stress.good"] == {"n": 40, "changed": 10, "right_to_wrong": 10, "wrong_to_right": 0}
    # missing / invalid predictions count as wrong, and a wrong -> invalid change is not a flip
    stress2 = preds(lambda u: u["truth"])
    stress2[0] = {**stress2[0], "pred": None, "status": "timeout"}     # g0__bad: right -> invalid (wrong)
    del stress2[1]                                                      # g0__good missing: right -> wrong
    rep2 = robustness(units, base, stress2, None, bootstrap=0)
    assert rep2["invalid"]["stress"] == 2 and "bootstrap" not in rep2
    assert rep2["transitions"]["stress.bad"]["right_to_wrong"] == 1
    assert rep2["transitions"]["stress.good"]["right_to_wrong"] == 1
    base3 = preds(lambda u: 1 - u["truth"])                               # all wrong
    rep3 = robustness(units, base3, stress2, None, bootstrap=0)
    assert rep3["transitions"]["stress.bad"]["changed"] == 39             # invalid g0__bad stays "wrong"
    assert rep["breakdowns"]["good_kind"]["G2B"]["n"] == 20
    render(rep, "self-test")
    print("robustness.py self-test: OK")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", type=Path, help="layer-1 predictions")
    ap.add_argument("--stress", type=Path, help="layer-3 (stress) predictions")
    ap.add_argument("--placebo", type=Path, help="placebo-layer predictions (optional)")
    ap.add_argument("--units", type=Path, default=DEFAULT_UNITS, help="labels and families (default layer1.jsonl)")
    ap.add_argument("--set", choices=("dev", "eval"))
    ap.add_argument("--subset")
    ap.add_argument("--subsets-file", type=Path, default=DEFAULT_SUBSETS)
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20261126)
    ap.add_argument("--label", help="name in the rendered table (default: method of --base)")
    ap.add_argument("--json", action="store_true", help="print the JSON report instead of markdown")
    ap.add_argument("--out", type=Path, help="also write the JSON report here")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.base or not args.stress:
        ap.error("--base and --stress are required")
    units = select_units(read_jsonl(args.units), args.set, args.subset, args.subsets_file)
    base = read_jsonl(args.base)
    report = robustness(units, base, read_jsonl(args.stress),
                        read_jsonl(args.placebo) if args.placebo else None, args.bootstrap, args.seed)
    report["inputs"] = {"base": str(args.base), "stress": str(args.stress),
                        "placebo": str(args.placebo) if args.placebo else None, "units": str(args.units),
                        "set": args.set, "subset": args.subset}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1) + "\n")
    label = args.label or ",".join(str(m) for m in report["methods"]["base"])
    print(json.dumps(report, indent=1) if args.json else render(report, label))
    return 0


if __name__ == "__main__":
    sys.exit(main())

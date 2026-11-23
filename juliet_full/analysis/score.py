#!/usr/bin/env python3
"""Score juliet_full predictions (contract: juliet_full/README.md sections 4 and 5).

    score.py --pred <file.jsonl> [--units data/build/layer1.jsonl] [--subset api_subset] [--set eval]
             [--bootstrap 2000] [--compare <other.jsonl> ...] [--json] [--out report.json]
    score.py --self-test

Positive class = leak (truth 1, label "bad").  A unit counts as valid iff its prediction line has pred 0 or 1;
units with pred null and units missing from the prediction file are invalid and counted wrong
(bad -> FN, good -> FP).  Headline metrics are end-to-end (invalid counted wrong); valid-only metrics are also
reported.  Confidence intervals: family-cluster percentile bootstrap (families resampled with replacement).
--compare runs a paired McNemar test (exact binomial when discordant pairs <= 25) against each other file, on
end-to-end correctness, with Holm adjustment across the comparisons given.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

JULIET_FULL = Path(__file__).resolve().parent.parent
DEFAULT_UNITS = JULIET_FULL / "data" / "build" / "layer1.jsonl"
DEFAULT_SUBSETS = JULIET_FULL / "data" / "build" / "subsets.json"
BOOTSTRAP_SEED = 20261126
CI_METRICS = ("macro_f1", "f1_leak", "precision_leak", "recall_leak", "specificity", "mcc", "accuracy")
MCNEMAR_EXACT_MAX = 25


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def select_units(units: list[dict[str, Any]], set_name: str | None, subset: str | None,
                 subsets_path: Path) -> list[dict[str, Any]]:
    if set_name:
        units = [u for u in units if u.get("set") == set_name]
    if subset:
        groups = set(json.loads(subsets_path.read_text())[subset])
        units = [u for u in units if u["group_id"] in groups]
    return units


def index_predictions(preds: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], int]:
    """unit_id -> prediction line (last line wins) and the number of duplicate lines."""
    out: dict[str, dict[str, Any]] = {}
    duplicates = 0
    for row in preds:
        duplicates += row["unit_id"] in out
        out[row["unit_id"]] = row
    return out, duplicates


def valid_pred(row: dict[str, Any] | None) -> int | None:
    if row is None:
        return None
    pred = row.get("pred")
    return pred if pred in (0, 1) and not isinstance(pred, bool) else None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def confusion(pairs: Iterable[tuple[int, int | None]]) -> dict[str, int]:
    """pairs of (truth, valid pred or None); None is counted wrong."""
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "invalid": 0, "n": 0}
    for truth, pred in pairs:
        counts["n"] += 1
        if pred is None:
            counts["invalid"] += 1
            pred = 1 - truth
        if truth == 1:
            counts["tp" if pred == 1 else "fn"] += 1
        else:
            counts["fp" if pred == 1 else "tn"] += 1
    return counts


def ratio(num: float, den: float) -> float | None:
    return num / den if den else None


def f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def metrics_from_counts(c: dict[str, int]) -> dict[str, Any]:
    tp, fp, tn, fn, n = c["tp"], c["fp"], c["tn"], c["fn"], c["n"]
    precision_leak, recall_leak = ratio(tp, tp + fp), ratio(tp, tp + fn)
    precision_ok, recall_ok = ratio(tn, tn + fn), ratio(tn, tn + fp)
    # an empty predicted class with a non-empty true class has F1 0 (precision undefined, recall 0)
    f1_leak = f1(precision_leak if tp + fp else 0.0, recall_leak) if tp + fn else None
    f1_ok = f1(precision_ok if tn + fn else 0.0, recall_ok) if tn + fp else None
    macro = (f1_leak + f1_ok) / 2 if f1_leak is not None and f1_ok is not None else None
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "invalid": c["invalid"],
        "coverage": ratio(n - c["invalid"], n),
        "precision_leak": precision_leak, "recall_leak": recall_leak, "f1_leak": f1_leak,
        "specificity": recall_ok, "f1_noleak": f1_ok, "macro_f1": macro,
        "mcc": (tp * tn - fp * fn) / den if den else 0.0,
        "accuracy": ratio(tp + tn, n),
    }


def percentile(values: list[float], q: float) -> float | None:
    """Linear-interpolation percentile, q in [0, 1]."""
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low, high = math.floor(pos), math.ceil(pos)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def latency_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(r["latency_s"]) for r in rows if isinstance(r.get("latency_s"), (int, float))]
    return {"n": len(values), "median_s": statistics.median(values) if values else None,
            "p90_s": percentile(values, 0.9), "mean_s": statistics.fmean(values) if values else None,
            "total_s": sum(values) if values else None}


def family_bootstrap(records: list[tuple[str, int, int | None]], iterations: int, seed: int) -> dict[str, Any]:
    """Percentile CIs (95%) by resampling families with replacement; records = (family, truth, pred)."""
    by_family: dict[str, dict[str, int]] = {}
    for family, truth, pred in records:
        counts = confusion([(truth, pred)])
        slot = by_family.setdefault(family, {k: 0 for k in counts})
        for key, value in counts.items():
            slot[key] += value
    families = sorted(by_family)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {m: [] for m in CI_METRICS}
    for _ in range(iterations):
        total = {k: 0 for k in ("tp", "fp", "tn", "fn", "invalid", "n")}
        for family in rng.choices(families, k=len(families)):
            for key, value in by_family[family].items():
                total[key] += value
        result = metrics_from_counts(total)
        for metric in CI_METRICS:
            if result[metric] is not None:
                samples[metric].append(result[metric])
    return {"iterations": iterations, "seed": seed, "clusters": "family", "n_clusters": len(families),
            "ci95": {m: [percentile(v, 0.025), percentile(v, 0.975)] for m, v in samples.items()}}


def breakdown(records: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[tuple[int, int | None]]] = defaultdict(list)
    for rec in records:
        groups[str(rec["unit"].get(key))].append((rec["truth"], rec["pred"]))
    return {name: metrics_from_counts(confusion(pairs)) for name, pairs in sorted(groups.items())}


def score(units: list[dict[str, Any]], preds: list[dict[str, Any]], bootstrap: int = 2000,
          seed: int = BOOTSTRAP_SEED) -> dict[str, Any]:
    index, duplicates = index_predictions(preds)
    unit_ids = {u["unit_id"] for u in units}
    records = []
    statuses: dict[str, int] = defaultdict(int)
    for unit in units:
        row = index.get(unit["unit_id"])
        statuses[row.get("status", "missing_status") if row else "missing"] += 1
        records.append({"unit": unit, "truth": int(unit["truth"]), "pred": valid_pred(row), "row": row})
    e2e = metrics_from_counts(confusion((r["truth"], r["pred"]) for r in records))
    valid_only = metrics_from_counts(confusion((r["truth"], r["pred"]) for r in records if r["pred"] is not None))
    methods = sorted({str(r.get("method")) for r in preds if r["unit_id"] in unit_ids})
    report: dict[str, Any] = {
        "methods": methods, "n_units": len(units), "n_pred_lines": len(preds), "duplicate_pred_lines": duplicates,
        "missing": statuses.get("missing", 0), "extra_pred_lines": len(set(index) - unit_ids),
        "status_counts": dict(sorted(statuses.items())),
        "end_to_end": e2e, "valid_only": valid_only,
        "latency": latency_stats([r["row"] for r in records if r["row"] is not None]),
        "by_flow_category": breakdown(records, "flow_category"),
        "by_mechanism": breakdown(records, "mechanism"),
        "by_good_kind": breakdown([r for r in records if r["truth"] == 0], "good_kind"),
        "by_label": breakdown(records, "label"),
    }
    if bootstrap:
        report["bootstrap"] = family_bootstrap([(r["unit"]["family"], r["truth"], r["pred"]) for r in records],
                                               bootstrap, seed)
    return report


# ---------------------------------------------------------------------------
# Paired comparison
# ---------------------------------------------------------------------------
def binom_two_sided(k: int, n: int) -> float:
    """Exact two-sided binomial test p-value for k successes of n at p = 0.5."""
    if n == 0:
        return 1.0
    low = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(low + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def mcnemar(units: list[dict[str, Any]], preds_a: list[dict[str, Any]], preds_b: list[dict[str, Any]]) -> dict[str, Any]:
    """Paired test on end-to-end correctness (invalid/missing = wrong).

    b = A right & B wrong, c = A wrong & B right.  Exact binomial when b + c <= MCNEMAR_EXACT_MAX, else the
    continuity-corrected chi-square (1 df)."""
    index_a, _ = index_predictions(preds_a)
    index_b, _ = index_predictions(preds_b)
    b = c = both = neither = 0
    for unit in units:
        truth = int(unit["truth"])
        right_a = valid_pred(index_a.get(unit["unit_id"])) == truth
        right_b = valid_pred(index_b.get(unit["unit_id"])) == truth
        if right_a and right_b:
            both += 1
        elif right_a:
            b += 1
        elif right_b:
            c += 1
        else:
            neither += 1
    discordant = b + c
    if discordant <= MCNEMAR_EXACT_MAX:
        test, statistic, p_value = "exact_binomial", None, binom_two_sided(b, discordant)
    else:
        statistic = (abs(b - c) - 1) ** 2 / discordant
        test, p_value = "chi2_continuity", math.erfc(math.sqrt(statistic / 2))
    return {"n": len(units), "both_right": both, "a_only_right": b, "b_only_right": c, "both_wrong": neither,
            "test": test, "statistic": statistic, "p_value": p_value}


def holm(p_values: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, in input order."""
    order = sorted(range(len(p_values)), key=lambda i: p_values[i])
    adjusted = [0.0] * len(p_values)
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(p_values) - rank) * p_values[i]))
        adjusted[i] = running
    return adjusted


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def fmt(value: Any) -> str:
    if value is None:
        return "-"
    return f"{value:.3f}" if isinstance(value, float) else str(value)


def render(report: dict[str, Any], label: str) -> str:
    e2e, valid = report["end_to_end"], report["valid_only"]
    lines = [f"== {label}  methods={','.join(report['methods'])}  units={report['n_units']}  "
             f"status={report['status_counts']}"]
    cis = report.get("bootstrap", {}).get("ci95", {})
    for metric in ("macro_f1", "f1_leak", "precision_leak", "recall_leak", "specificity", "mcc", "accuracy"):
        ci = cis.get(metric)
        ci_text = f"  [{fmt(ci[0])}, {fmt(ci[1])}]" if ci else ""
        lines.append(f"  {metric:15s} {fmt(e2e[metric])}{ci_text}   (valid-only {fmt(valid[metric])})")
    lines.append(f"  confusion tp={e2e['tp']} fp={e2e['fp']} tn={e2e['tn']} fn={e2e['fn']}  invalid={e2e['invalid']} "
                 f"coverage={fmt(e2e['coverage'])}  missing={report['missing']}")
    lat = report["latency"]
    lines.append(f"  latency median={fmt(lat['median_s'])}s p90={fmt(lat['p90_s'])}s (n={lat['n']})")
    for key in ("by_flow_category", "by_mechanism", "by_good_kind"):
        lines.append(f"  {key}:")
        for name, m in report[key].items():
            lines.append(f"    {name:12s} n={m['n']:4d} acc={fmt(m['accuracy'])} recall={fmt(m['recall_leak'])} "
                         f"spec={fmt(m['specificity'])} macroF1={fmt(m['macro_f1'])} invalid={m['invalid']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def synthetic_units() -> list[dict[str, Any]]:
    units = []
    for f in range(10):
        for v in range(3):
            for label, truth, good_kind in (("bad", 1, None), ("good", 0, "G2B" if v % 2 else "B2G")):
                group = f"CWE401_Memory_Leak__fam{f}_{v:02d}"
                units.append({"unit_id": f"{group}__{label}", "group_id": group, "family": f"fam{f}",
                              "flow_category": "01" if v == 0 else "02-22", "mechanism": "c_alloc" if f < 5 else "cpp_new",
                              "set": "dev" if f < 3 else "eval", "label": label, "truth": truth, "good_kind": good_kind})
    return units


def self_test() -> None:
    units = synthetic_units()
    perfect = [{"unit_id": u["unit_id"], "pred": u["truth"], "status": "ok", "latency_s": 1.0, "method": "oracle"}
               for u in units]
    r = score(units, perfect, bootstrap=200)
    assert r["end_to_end"]["macro_f1"] == 1.0 and r["end_to_end"]["mcc"] == 1.0, r["end_to_end"]
    assert r["bootstrap"]["ci95"]["macro_f1"] == [1.0, 1.0]

    always_leak = [{**p, "pred": 1} for p in perfect]
    m = score(units, always_leak, bootstrap=0)["end_to_end"]
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (30, 30, 0, 0)
    assert m["precision_leak"] == 0.5 and m["recall_leak"] == 1.0 and m["f1_noleak"] == 0.0
    assert abs(m["macro_f1"] - (2 / 3) / 2) < 1e-12 and m["mcc"] == 0.0

    # invalid and missing are counted wrong: bad -> FN, good -> FP
    broken = [dict(p) for p in perfect]
    broken[0]["pred"], broken[0]["status"] = None, "timeout"   # bad unit -> FN
    broken[1]["pred"], broken[1]["status"] = None, "invalid"   # good unit -> FP
    del broken[2]                                              # bad unit missing -> FN
    r = score(units, broken, bootstrap=0)
    m = r["end_to_end"]
    assert (m["tp"], m["fp"], m["tn"], m["fn"], m["invalid"]) == (28, 1, 29, 2, 3), m
    assert r["missing"] == 1 and abs(m["coverage"] - 57 / 60) < 1e-12
    assert r["valid_only"]["macro_f1"] == 1.0 and r["valid_only"]["n"] == 57

    # known confusion: tp=20 fn=10 tn=25 fp=5
    mixed = [dict(p) for p in perfect]
    bad_rows = [p for p in mixed if p["unit_id"].endswith("__bad")]
    good_rows = [p for p in mixed if p["unit_id"].endswith("__good")]
    for p in bad_rows[:10]:
        p["pred"] = 0
    for p in good_rows[:5]:
        p["pred"] = 1
    m = score(units, mixed, bootstrap=0)["end_to_end"]
    precision, recall = 20 / 25, 20 / 30
    f1_leak = 2 * precision * recall / (precision + recall)
    f1_ok = 2 * (25 / 35) * (25 / 30) / ((25 / 35) + (25 / 30))
    mcc = (20 * 25 - 5 * 10) / math.sqrt(25 * 30 * 30 * 35)
    assert abs(m["f1_leak"] - f1_leak) < 1e-12 and abs(m["macro_f1"] - (f1_leak + f1_ok) / 2) < 1e-12
    assert abs(m["mcc"] - mcc) < 1e-12 and m["accuracy"] == 45 / 60
    r = score(units, mixed, bootstrap=500)
    low, high = r["bootstrap"]["ci95"]["macro_f1"]
    assert low <= r["end_to_end"]["macro_f1"] <= high and low < high
    assert r["by_good_kind"].keys() == {"B2G", "G2B"} and sum(v["n"] for v in r["by_good_kind"].values()) == 30
    assert r["by_mechanism"]["c_alloc"]["n"] == 30

    # latency median/p90
    lat = latency_stats([{"latency_s": float(x)} for x in range(1, 11)])
    assert lat["median_s"] == 5.5 and abs(lat["p90_s"] - 9.1) < 1e-12

    # subset/set filters
    assert len(select_units(units, "dev", None, DEFAULT_SUBSETS)) == 18

    # McNemar: perfect vs mixed -> b=15 (exact), p = 2 * 0.5**15
    t = mcnemar(units, perfect, mixed)
    assert (t["a_only_right"], t["b_only_right"], t["test"]) == (15, 0, "exact_binomial")
    assert abs(t["p_value"] - 2 * 0.5 ** 15) < 1e-15
    assert mcnemar(units, perfect, perfect)["p_value"] == 1.0
    assert abs(binom_two_sided(2, 10) - 0.109375) < 1e-12      # scipy.stats.binomtest(2, 10).pvalue
    assert binom_two_sided(5, 10) == 1.0
    # chi-square branch: b=30, c=10 -> (|30-10|-1)^2/40 = 9.025, p = 0.002663
    assert abs(math.erfc(math.sqrt(9.025 / 2)) - 0.0026635) < 1e-6
    assert [round(x, 6) for x in holm([0.01, 0.04, 0.03])] == [0.03, 0.06, 0.06]
    print("score.py self-test: OK")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pred", type=Path, help="prediction JSONL")
    parser.add_argument("--units", type=Path, default=DEFAULT_UNITS)
    parser.add_argument("--subset", help="subset name in --subsets-file (group ids)")
    parser.add_argument("--subsets-file", type=Path, default=DEFAULT_SUBSETS)
    parser.add_argument("--set", choices=("dev", "eval"))
    parser.add_argument("--bootstrap", type=int, default=2000, help="family-cluster bootstrap iterations (0 = off)")
    parser.add_argument("--seed", type=int, default=BOOTSTRAP_SEED)
    parser.add_argument("--compare", type=Path, action="append", default=[], help="paired McNemar vs this file")
    parser.add_argument("--json", action="store_true", help="print the JSON report instead of text")
    parser.add_argument("--out", type=Path, help="also write the JSON report here")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.pred:
        parser.error("--pred is required")
    units = select_units(read_jsonl(args.units), args.set, args.subset, args.subsets_file)
    if not units:
        raise SystemExit("no units selected")
    preds = read_jsonl(args.pred)
    report = score(units, preds, args.bootstrap, args.seed)
    report["inputs"] = {"pred": str(args.pred), "units": str(args.units), "set": args.set, "subset": args.subset}
    if args.compare:
        tests = [{"other": str(path), **mcnemar(units, preds, read_jsonl(path))} for path in args.compare]
        for test, adjusted in zip(tests, holm([t["p_value"] for t in tests])):
            test["p_holm"] = adjusted
        report["mcnemar"] = tests
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render(report, args.pred.name))
        for test in report.get("mcnemar", []):
            print(f"  McNemar vs {Path(test['other']).name}: a_only={test['a_only_right']} b_only={test['b_only_right']}"
                  f" {test['test']} p={test['p_value']:.4g} holm={test['p_holm']:.4g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

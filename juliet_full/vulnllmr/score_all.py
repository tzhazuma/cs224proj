#!/usr/bin/env python3
"""Score every VulnLLM-R-7B run with analysis/score.py and summarise it for REPORT_run.md.

    python3 score_all.py [--bootstrap 2000]

Writes results/scores/<layer>__<run_id>.json (score.py report, pred = lenient `#judge: yes`),
results/scores/<layer>__<run_id>__strict.json (pred_strict = yes AND type CWE-401), results/scores/summary.json
(per-run metrics, deltas, hint vs no-hint, run stats) and build/report_tables.md (markdown tables for the report).
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
JF = HERE.parent
RES = HERE / "results" / "vulnllm_r_7b"
SCORES = HERE / "results" / "scores"
SCORE_PY = JF / "analysis" / "score.py"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def score(pred: Path, layer: str, set_: str, subset: str | None, subsets_file: Path | None, bootstrap: int,
          out: Path, compare: list[Path] | None = None) -> dict[str, Any]:
    cmd = [sys.executable, str(SCORE_PY), "--pred", str(pred), "--units", str(JF / "data" / "build" / f"{layer}.jsonl"),
           "--set", set_, "--bootstrap", str(bootstrap), "--json", "--out", str(out)]
    if subset:
        cmd += ["--subset", subset]
    if subsets_file:
        cmd += ["--subsets-file", str(subsets_file)]
    for other in compare or []:
        cmd += ["--compare", str(other)]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    return json.loads(out.read_text())


def strict_copy(pred: Path) -> Path:
    out = HERE / "build" / "strict" / pred.parent.name / pred.name
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as handle:
        for row in read_jsonl(pred):
            row = {**row, "pred": row["extra"].get("pred_strict") if row["status"] == "ok" else None,
                   "strategy": row["strategy"] + "_strict"}
            handle.write(json.dumps(row) + "\n")
    return out


def subset_of(run_id: str, meta: dict[str, Any]) -> tuple[str | None, Path | None]:
    if meta.get("selection", {}).get("c1_groups"):
        path = HERE / "build" / f"subsets_{run_id}.json"
        if not path.exists():
            groups = sorted({r["unit_id"].rsplit("__", 1)[0] for r in read_jsonl(RES / meta["layer"] / f"{run_id}.jsonl")})
            path.write_text(json.dumps({"c1_capped": groups}))
        return "c1_capped", path
    return meta.get("subset"), None


def metrics(rep: dict[str, Any]) -> dict[str, Any]:
    e = rep["end_to_end"]
    ci = rep.get("bootstrap", {}).get("ci95", {})
    return {"n": e["n"], "macro_f1": e["macro_f1"], "macro_f1_ci95": ci.get("macro_f1"), "precision": e["precision_leak"],
            "recall": e["recall_leak"], "specificity": e["specificity"], "f1_leak": e["f1_leak"], "mcc": e["mcc"],
            "tp": e["tp"], "fp": e["fp"], "tn": e["tn"], "fn": e["fn"], "invalid": e["invalid"],
            "valid_only_macro_f1": rep["valid_only"]["macro_f1"], "latency": rep.get("latency"),
            "by_good_kind": {k: {"n": v["n"], "fp": v["fp"], "specificity": v["specificity"]}
                             for k, v in rep.get("by_good_kind", {}).items()},
            "mcnemar": rep.get("mcnemar")}


def run_stats(pred: Path, meta: dict[str, Any]) -> dict[str, Any]:
    rows = read_jsonl(pred)
    comp = [r["extra"]["completion_tokens"] for r in rows if r["extra"].get("completion_tokens") is not None]
    lat = [r["latency_s"] for r in rows if r["latency_s"] is not None]
    n = len(rows)
    return {"units": n, "status_counts": meta["status_counts"], "invalid_rate": meta["invalid_rate"],
            "truncated": sum(1 for r in rows if r["extra"].get("truncated")),
            "truncation_rate": round(sum(1 for r in rows if r["extra"].get("truncated")) / max(1, n), 4),
            "pred_counts": meta["pred_counts"], "pred_strict_counts": meta["pred_strict_counts"],
            "yes_type_counts": meta["yes_type_counts"], "finish_reason_counts": meta["finish_reason_counts"],
            "completion_tokens_mean": round(statistics.mean(comp), 1) if comp else None,
            "completion_tokens_median": statistics.median(comp) if comp else None,
            "completion_tokens_p90": pct(comp, 0.9), "completion_tokens_max": max(comp) if comp else None,
            "latency_median_s": round(statistics.median(lat), 3) if lat else None,
            "latency_p90_s": pct(lat, 0.9), "wall_s": meta["wall_s"], "concurrency": meta["concurrency"],
            "units_per_s": round(n / meta["wall_s"], 3) if meta["wall_s"] else None,
            "output_tok_per_s": round(sum(comp) / meta["wall_s"], 1) if meta["wall_s"] else None,
            "start_utc": meta["start_utc"], "end_utc": meta["end_utc"], "loadavg_start": meta["loadavg_start"],
            "latency_lock": meta.get("latency_lock")}


def fmt(x: Any, nd: int = 3) -> str:
    if x is None:
        return "–"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)


def main() -> int:
    global RES, SCORES
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--res", type=Path, default=RES, help="results/vulnllm_r_7b root")
    ap.add_argument("--scores", type=Path, default=SCORES, help="output dir")
    args = ap.parse_args()
    RES, SCORES = args.res, args.scores
    SCORES.mkdir(parents=True, exist_ok=True)
    runs: dict[str, dict[str, Any]] = {}
    for pred in sorted(RES.glob("*/*.jsonl")):
        meta = json.loads(pred.with_suffix(".meta.json").read_text())
        run_id, layer = meta["run_id"], meta["layer"]
        if run_id.startswith("smoke"):
            continue
        subset, subsets_file = subset_of(run_id, meta)
        key = f"{layer}__{run_id}"
        compare = []
        if layer != "layer1" and (RES / "layer1" / pred.name).exists():
            compare = [RES / "layer1" / pred.name]
        rep = score(pred, layer, meta["set"], subset, subsets_file, args.bootstrap, SCORES / f"{key}.json", compare)
        rep_s = score(strict_copy(pred), layer, meta["set"], subset, subsets_file, args.bootstrap,
                      SCORES / f"{key}__strict.json")
        runs[key] = {"layer": layer, "run_id": run_id, "set": meta["set"], "subset": subset,
                     "cwe_hint": meta["cwe_hint"], "lenient": metrics(rep), "strict": metrics(rep_s),
                     "stats": run_stats(pred, meta)}
        print(f"scored {key}: macro-F1 {rep['end_to_end']['macro_f1']:.3f} (strict "
              f"{rep_s['end_to_end']['macro_f1']:.3f})", file=sys.stderr)

    # hint vs no-hint on nested25 (paired, same units), per layer that has a no-hint run
    hint_vs = {}
    for nohint in sorted(RES.glob("*/n25_nohint_r1.jsonl")):
        layer = nohint.parent.name
        policy = RES / layer / "eval_policy_r1.jsonl"
        if not policy.exists():
            continue
        rep_p = score(policy, layer, "eval", "nested25", None, args.bootstrap,
                      SCORES / f"{layer}__eval_policy_r1__n25.json", [nohint])
        rep_n = json.loads((SCORES / f"{layer}__n25_nohint_r1.json").read_text())
        hint_vs[layer] = {"policy_n25": metrics(rep_p), "nohint_n25": metrics(rep_n)}

    deltas = {}
    base = runs.get("layer1__eval_policy_r1")
    if base:
        for layer in ("layer3", "placebo", "original"):
            other = runs.get(f"{layer}__eval_policy_r1")
            if other:
                deltas[f"{layer}-layer1"] = {
                    "macro_f1": other["lenient"]["macro_f1"] - base["lenient"]["macro_f1"],
                    "macro_f1_strict": other["strict"]["macro_f1"] - base["strict"]["macro_f1"],
                    "mcnemar": other["lenient"]["mcnemar"]}
        if "layer3-layer1" in deltas and "placebo-layer1" in deltas:
            deltas["layer3-placebo_adjusted"] = deltas["layer3-layer1"]["macro_f1"] - deltas["placebo-layer1"]["macro_f1"]
    summary = {"runs": runs, "deltas_vs_layer1_eval": deltas, "hint_vs_nohint_nested25": hint_vs,
               "bootstrap": args.bootstrap}
    (SCORES / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    lines = ["| layer / run | n | macro-F1 [95% CI] | P | R | spec | FP | FN | invalid | strict macro-F1 | strict R |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for key, r in runs.items():
        m, s = r["lenient"], r["strict"]
        ci = m["macro_f1_ci95"] or [None, None]
        lines.append(f"| {key} | {m['n']} | {fmt(m['macro_f1'])} [{fmt(ci[0])}, {fmt(ci[1])}] | {fmt(m['precision'])} | "
                     f"{fmt(m['recall'])} | {fmt(m['specificity'])} | {m['fp']} | {m['fn']} | {m['invalid']} | "
                     f"{fmt(s['macro_f1'])} | {fmt(s['recall'])} |")
    lines += ["", "| layer / run | invalid rate | truncated | out tok mean / median / p90 / max | latency median / p90 s |"
              " wall s | units/s | out tok/s | yes types |", "|---|---|---|---|---|---|---|---|---|"]
    for key, r in runs.items():
        st = r["stats"]
        lines.append(f"| {key} | {st['invalid_rate']} | {st['truncated']} | {st['completion_tokens_mean']} / "
                     f"{st['completion_tokens_median']} / {st['completion_tokens_p90']} / {st['completion_tokens_max']} | "
                     f"{st['latency_median_s']} / {fmt(st['latency_p90_s'])} | {st['wall_s']} | {st['units_per_s']} | "
                     f"{st['output_tok_per_s']} | {st['yes_type_counts']} |")
    (HERE / "build" / "report_tables.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(json.dumps({"deltas": deltas, "hint_vs_nohint": hint_vs}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())

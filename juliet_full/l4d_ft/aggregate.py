"""Unit verdicts, scores and reference comparisons for L4-D runs (lane l4d-train, dell, CPU).

  aggregate.py units --method lora_l4d|qwen_readout_l4d --layer L [--run-id eval_r1]
      question answers collected from 184-toast (build/remote_results/<method>/<L>/<run>[_fold<k>].jsonl) ->
      results/<method>/<L>/<run>.jsonl (question level, all folds) and, through derive.py --souffle with the frozen
      tau of each fold (readout: the frozen readout tau), results/<method>/<L>/<run>_units.jsonl + .meta.json.
      latency_s = model time of the unit (unit_forward_s: one forward batch of all its questions, server side)
                  + derive time; the end-to-end client latency is measured separately (latency.py).
  aggregate.py score --method M --layer L [--run-id eval_r1]
      score.py report (set eval, family-cluster bootstrap) on all eval units and on the reference units, DeepSeek
      L1 reference + best DeepSeek strategy on the same units, paired family-cluster bootstrap of delta macro-F1
      (2,000 resamples, seed 20261123), contract section 6 criteria -> build/scores/<M>_<L>_<run>.json
  aggregate.py facts --method M --layer L [--run-id eval_r1]
      score_facts.py table + exec_any without the masked NULL-check line + rel same- vs cross-function
      -> build/scores/<M>_<L>_<run>_facts.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
L4D_DIR = JULIET_FULL / "l4d"
L4D_PY = L4D_DIR / ".venv" / "bin" / "python"
sys.path.insert(0, str(JULIET_FULL / "analysis"))
import score as score_mod  # noqa: E402  (analysis/score.py, read-only)

PAIRED_SEED = 20261123
PAIRED_ITER = 2000
MARGIN = 0.02
SPEED_MAX_S = 0.36
DEEPSEEK = JULIET_FULL / "llm" / "results" / "deepseek_flash"
REF_L1 = {"layer1": DEEPSEEK / "layer1/eval_L1_r1.jsonl", "layer3": DEEPSEEK / "layer3/l3_n25_L1_r1.jsonl",
          "placebo": DEEPSEEK / "placebo/pl_n25_L1_r1.jsonl", "original": DEEPSEEK / "original/orig_n25_L1_r1.jsonl"}
REF_GLOB = {"layer1": "layer1/eval_L*_r1.jsonl", "layer3": "layer3/l3_n25_L*_r1.jsonl",
            "placebo": "placebo/pl_n25_L*_r1.jsonl", "original": "original/orig_n25_L*_r1.jsonl"}
NULL_CHECK_TARGET = re.compile(r"if\s*\(\s*[^()]*==\s*NULL\s*\)\s*\{?\s*__TARGET__\(\);")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path) -> str:
    return os.path.relpath(path, JULIET_FULL)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def questions_path(layer: str) -> Path:
    return L4D_DIR / "build" / f"questions_{layer}.jsonl"


def eval_units(layer: str) -> list[dict]:
    return [u for u in read_jsonl(JULIET_FULL / "data" / "build" / f"{layer}.jsonl") if u["set"] == "eval"]


def answer_sources(method: str, layer: str, run_id: str) -> list[tuple[int | None, Path]]:
    base = HERE / "build" / "remote_results" / method / layer
    if method == "lora_l4d":
        return [(k, base / f"{run_id}_fold{k}.jsonl") for k in (0, 1, 2)]
    return [(None, base / f"{run_id}.jsonl")]


def cmd_units(args) -> None:
    frozen = json.loads((HERE / "FROZEN").read_text())
    units = eval_units(args.layer)
    fold_of = {u["unit_id"]: u["fold"] for u in units}
    questions = [q for q in read_jsonl(questions_path(args.layer)) if q["set"] == "eval"]
    out_dir = HERE / "results" / args.method / args.layer
    all_answers, unit_rows, metas, derive_logs = [], [], [], []
    for fold, src in answer_sources(args.method, args.layer, args.run_id):
        answers = read_jsonl(src)
        meta = json.loads(src.with_suffix(".meta.json").read_text())
        metas.append({"fold": fold, "file": src.name, "sha256": file_sha256(src), **{
            k: meta.get(k) for k in ("model", "checkpoint", "merged", "freeze_guard", "frozen_utc", "start_utc",
                                     "end_utc", "host", "cuda_visible_devices", "loadavg_start", "loadavg_end",
                                     "unit_forward_s_median", "unit_forward_s_p90", "versions", "kernels",
                                     "template_sha256", "chat_template_sha256", "question_metrics")}})
        tau = frozen["folds"][str(fold)]["tau"] if fold is not None else frozen["readout"]["tau"]
        qs = [q for q in questions if fold is None or fold_of[q["unit_id"]] == fold]
        got = {a["qid"] for a in answers}
        missing = [q["qid"] for q in qs if q["qid"] not in got]
        assert not missing, f"{src.name}: {len(missing)} questions unanswered, e.g. {missing[:3]}"
        extra_q = got - {q["qid"] for q in qs}
        assert not extra_q, f"{src.name}: answers for questions outside its units, e.g. {sorted(extra_q)[:3]}"
        model_s = {a["unit_id"]: a["unit_forward_s"] for a in answers}
        with tempfile.TemporaryDirectory(prefix="l4dft_agg_") as td:
            qf, af, uf = Path(td, "q.jsonl"), Path(td, "a.jsonl"), Path(td, "u.jsonl")
            write_jsonl(qf, qs)
            write_jsonl(af, answers)
            model = metas[-1]["model"]
            res = subprocess.run([str(L4D_PY), str(L4D_DIR / "derive.py"), "--questions", str(qf), "--answers",
                                  str(af), "--tau", str(tau), "--method", args.method, "--model", model,
                                  "--out", str(uf), "--souffle"], capture_output=True, text=True, check=True)
            derive_logs.append({"fold": fold, "tau": tau, "stderr": res.stderr.strip()})
            for r in read_jsonl(uf):
                r["extra"].update({"fold": fold, "model_s": model_s[r["unit_id"]], "run_id": args.run_id})
                r["latency_s"] = model_s[r["unit_id"]] + r["extra"]["derive_s"]
                unit_rows.append(r)
        all_answers += answers
    ids = [r["unit_id"] for r in unit_rows]
    assert len(ids) == len(set(ids)) and set(ids) == set(fold_of), "unit coverage mismatch"
    order = {u["unit_id"]: i for i, u in enumerate(units)}
    unit_rows.sort(key=lambda r: order[r["unit_id"]])
    q_out, u_out = out_dir / f"{args.run_id}.jsonl", out_dir / f"{args.run_id}_units.jsonl"
    write_jsonl(q_out, all_answers)
    write_jsonl(u_out, unit_rows)
    meta = {"method": args.method, "strategy": "L4D", "layer": args.layer, "run_id": args.run_id,
            "n_units": len(unit_rows), "n_questions": len(all_answers),
            "questions": str(questions_path(args.layer).relative_to(JULIET_FULL)),
            "questions_sha256": file_sha256(questions_path(args.layer)),
            "derive_py_sha256": file_sha256(L4D_DIR / "derive.py"), "rules_sha256": file_sha256(L4D_DIR / "l4d.dl"),
            "frozen_sha256": file_sha256(HERE / "FROZEN"), "frozen_common": frozen["common"],
            "tau": {str(m["fold"]): (frozen["folds"][str(m["fold"])]["tau"] if m["fold"] is not None
                                     else frozen["readout"]["tau"]) for m in metas},
            "start_utc": min(m["start_utc"] for m in metas), "end_utc": max(m["end_utc"] for m in metas),
            "concurrency": 1, "batching": "all questions of one unit in one forward batch, units sequential",
            "latency_note": "latency_s = unit_forward_s (server-side model time, one RTX 3090) + derive_s; "
                            "end-to-end client latency is in the latency run",
            "question_files": metas, "derive": derive_logs, "aggregated_utc": utc_now(),
            "answers_sha256": file_sha256(q_out), "units_sha256": file_sha256(u_out)}
    u_out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(f"{len(unit_rows)} units -> {u_out}")


def macro_from(records) -> float:
    return score_mod.metrics_from_counts(score_mod.confusion(records))["macro_f1"]


def paired_bootstrap(units: list[dict], pred_a: dict, pred_b: dict) -> dict:
    """Delta macro-F1 (a - b), families resampled with replacement, both systems on the same resample."""
    by_family = defaultdict(list)
    for u in units:
        by_family[u["family"]].append((int(u["truth"]), pred_a.get(u["unit_id"]), pred_b.get(u["unit_id"])))
    families = sorted(by_family)
    rng = random.Random(PAIRED_SEED)
    deltas = []
    for _ in range(PAIRED_ITER):
        a, b = [], []
        for fam in rng.choices(families, k=len(families)):
            for t, pa, pb in by_family[fam]:
                a.append((t, pa))
                b.append((t, pb))
        ma, mb = macro_from(a), macro_from(b)
        if ma is not None and mb is not None:
            deltas.append(ma - mb)
    point = macro_from([(int(u["truth"]), pred_a.get(u["unit_id"])) for u in units]) - \
        macro_from([(int(u["truth"]), pred_b.get(u["unit_id"])) for u in units])
    return {"delta_macro_f1": point, "ci95": [score_mod.percentile(deltas, 0.025), score_mod.percentile(deltas, 0.975)],
            "iterations": PAIRED_ITER, "valid_iterations": len(deltas), "seed": PAIRED_SEED,
            "clusters": "family", "n_clusters": len(families), "n_units": len(units)}


def preds_of(path: Path) -> dict:
    index, _ = score_mod.index_predictions(read_jsonl(path))
    return {uid: score_mod.valid_pred(r) for uid, r in index.items()}


def short(report: dict) -> dict:
    e = report["end_to_end"]
    return {"n": e["n"], "macro_f1": e["macro_f1"], "ci95_macro_f1": report.get("bootstrap", {}).get("ci95", {})
            .get("macro_f1"), "precision_leak": e["precision_leak"], "recall_leak": e["recall_leak"],
            "specificity": e["specificity"], "invalid": e["invalid"], "missing": report["missing"],
            "latency_median_s": report["latency"]["median_s"], "latency_p90_s": report["latency"]["p90_s"]}


def cmd_score(args) -> None:
    pred_file = HERE / "results" / args.method / args.layer / f"{args.run_id}_units.jsonl"
    units_file = JULIET_FULL / "data" / "build" / f"{args.layer}.jsonl"
    all_units = score_mod.read_jsonl(units_file)
    preds_rows = read_jsonl(pred_file)
    cli = subprocess.run([sys.executable, str(JULIET_FULL / "analysis" / "score.py"), "--pred", str(pred_file),
                          "--units", str(units_file), "--set", "eval", "--json"],
                         capture_output=True, text=True, check=True)
    full_report = json.loads(cli.stdout)
    ref_l1 = REF_L1[args.layer]
    ref_ids = {r["unit_id"] for r in read_jsonl(ref_l1)}
    ref_units = [u for u in all_units if u["unit_id"] in ref_ids]
    if args.layer != "layer1":
        n25 = score_mod.select_units(all_units, "eval", "nested25", score_mod.DEFAULT_SUBSETS)
        assert {u["unit_id"] for u in n25} == ref_ids, "DeepSeek reference units != nested25 eval units"
    assert len(ref_units) == len(ref_ids), "reference has units outside the unit file"
    model_on_ref = score_mod.score(ref_units, preds_rows, 2000, score_mod.BOOTSTRAP_SEED)
    mine = preds_of(pred_file)
    refs = {}
    for path in sorted(DEEPSEEK.glob(REF_GLOB[args.layer])):
        strat = re.search(r"_(L\d)_r1", path.name).group(1)
        rep = score_mod.score(ref_units, read_jsonl(path), 2000, score_mod.BOOTSTRAP_SEED)
        refs[strat] = {"file": str(path.relative_to(JULIET_FULL)), **short(rep),
                       "paired_delta_model_minus_ref": paired_bootstrap(ref_units, mine, preds_of(path))}
    best = max(refs, key=lambda s: refs[s]["macro_f1"])
    ref = refs["L1"]
    lo = ref["paired_delta_model_minus_ref"]["ci95"][0]
    criteria = {
        "near_llm": {"rule": "macro-F1 >= ref L1 - 0.02 (same units)",
                     "value": model_on_ref["end_to_end"]["macro_f1"], "threshold": ref["macro_f1"] - MARGIN,
                     "pass": model_on_ref["end_to_end"]["macro_f1"] >= ref["macro_f1"] - MARGIN},
        "equivalent_within_2pt": {"rule": "lower 95% family-cluster paired bootstrap bound of delta >= -0.02",
                                  "value": lo, "pass": lo is not None and lo >= -MARGIN},
        "speed": {"rule": f"e2e c1 median <= {SPEED_MAX_S} s on layer1 latency300 (latency run; not decided here)"},
    }
    out = {"method": args.method, "layer": args.layer, "run_id": args.run_id, "pred_file": rel(pred_file),
           "pred_sha256": file_sha256(pred_file), "all_eval": short(full_report),
           "ref_units": {"n": len(ref_units), "which": "full eval" if args.layer == "layer1" else "nested25 eval",
                         **short(model_on_ref)},
           "deepseek": refs, "deepseek_best_strategy": best, "criteria": criteria,
           "score_py_all_eval": full_report, "scored_utc": utc_now()}
    dest = HERE / "build" / "scores" / f"{args.method}_{args.layer}_{args.run_id}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: out[k] for k in ("all_eval", "ref_units")}, indent=None))
    print(json.dumps({s: {k: refs[s][k] for k in ("macro_f1", "ci95_macro_f1")} | {
        "delta": refs[s]["paired_delta_model_minus_ref"]["delta_macro_f1"],
        "delta_ci": refs[s]["paired_delta_model_minus_ref"]["ci95"]} for s in refs}))
    print(json.dumps({k: v.get("pass") for k, v in criteria.items()}))


def fact_rows(pairs: list[tuple[float, int]], tau: float) -> dict:
    from select_fold import auroc
    if not pairs:
        return {"n": 0}
    return {"n": len(pairs), "n_yes": sum(g for _, g in pairs),
            "accuracy": sum((p >= tau) == bool(g) for p, g in pairs) / len(pairs),
            "auroc": auroc([p for p, _ in pairs], [g for _, g in pairs])}


def cmd_facts(args) -> None:
    ans_file = HERE / "results" / args.method / args.layer / f"{args.run_id}.jsonl"
    qfile = questions_path(args.layer)
    dest = HERE / "build" / "scores" / f"{args.method}_{args.layer}_{args.run_id}_facts.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    table = HERE / "build" / "scores" / f"{args.method}_{args.layer}_{args.run_id}_score_facts.json"
    res = subprocess.run([str(L4D_PY), str(L4D_DIR / "score_facts.py"), "--answers", str(ans_file), "--questions",
                          str(qfile), "--tau", "0.5", "--out", str(table)], capture_output=True, text=True, check=True)
    p = {r["qid"]: r["p_yes"] for r in read_jsonl(ans_file)}
    funcs = {r["unit_id"]: {s["site_id"]: s["func"] for s in r["sites"]}
             for r in read_jsonl(L4D_DIR / "build" / f"sites_{args.layer}.jsonl")}
    splits = defaultdict(list)
    for q in read_jsonl(qfile):
        if q["qid"] not in p or q["gold"] not in (0, 1):
            continue
        pair = (p[q["qid"]], q["gold"])
        if q["qtype"] == "exec_any":
            target = q["state"].split("\n")[q["lines"][0] - 1]
            splits["exec_any/null_check_target" if NULL_CHECK_TARGET.search(target) else "exec_any/other"].append(pair)
        if q["qtype"] == "rel":
            f, a = q["site_ids"]
            same = funcs[q["unit_id"]][f] == funcs[q["unit_id"]][a]
            splits["rel/same_function" if same else "rel/cross_function"].append(pair)
    out = {"method": args.method, "layer": args.layer, "answers": rel(ans_file),
           "score_facts": json.loads(table.read_text()), "score_facts_table": res.stdout,
           "splits_tau_0.5": {k: fact_rows(v, 0.5) for k, v in sorted(splits.items())}, "utc": utc_now()}
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(res.stdout)
    print(json.dumps(out["splits_tau_0.5"], indent=1))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("units", "score", "facts"):
        p = sub.add_parser(name)
        p.add_argument("--method", choices=("lora_l4d", "qwen_readout_l4d"), required=True)
        p.add_argument("--layer", choices=("layer1", "layer3", "placebo", "original"), required=True)
        p.add_argument("--run-id", default="eval_r1")
    args = ap.parse_args()
    {"units": cmd_units, "score": cmd_score, "facts": cmd_facts}[args.cmd](args)


if __name__ == "__main__":
    main()

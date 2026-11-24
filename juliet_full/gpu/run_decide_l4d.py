#!/usr/bin/env python3
"""Intern-Decision-4B on the L4-D questions (method intern_l4d; lane latency-deadfree).

Per unit: the L4-D questions of l4d/build/questions_<layer>.jsonl, pruned to the questions the v1 rules read
(l4d_ft/prune.py, the same pruning as lora_l4d_opt; verdicts identical to the full question set). Each question is one
POST /decide to the Intern-Decision server (gpu/server/decide_server.py): state = the question's state, question =
the question text unchanged, options ["Yes", "No"]; p_yes = calibrated probs["Yes"] (as run_decide.py uses
probs["yes"]). Unit verdicts: l4d/derive.py (--souffle) on the pruned questions; a unit without a kept question has no
heap block -> pred 0, score 0, no model call (as prune.py cmd_units).

tau: chosen on layer1 dev by unit macro-F1 exactly as the Qwen read-out tau (l4d_ft/select_fold.py: TAU_GRID, max dev
unit macro-F1 through derive.evaluate_unit, ties -> |tau - 0.5| smallest; all 660 dev units), frozen in
l4d_ft/results/intern_l4d/FROZEN before any eval call; tau = 0.5 is reported as secondary.

  run_decide_l4d.py answer --layer layer1 --set dev --run-id dev_r1      # answers rows (l4d/README.md section 4)
  run_decide_l4d.py select --run-id dev_r1                                # -> results/intern_l4d/select_tau.json
  run_decide_l4d.py freeze                                                # -> results/intern_l4d/FROZEN
  run_decide_l4d.py answer --layer layer3 --set eval --run-id eval_r1     # refuses without a matching FROZEN
  run_decide_l4d.py units --layer layer3 --run-id eval_r1                 # eval_r1_units.jsonl, eval_r1_tau05_units.jsonl
  ../l4d/.venv/bin/python run_decide_l4d.py latency --run-id lat300_c1   # c1 end-to-end on latency300 (tree-sitter)

Outputs only under l4d_ft/results/intern_l4d/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

GPU_DIR = Path(__file__).resolve().parent
JF = GPU_DIR.parent
L4D_DIR = JF / "l4d"
L4D_FT = JF / "l4d_ft"
sys.path.insert(0, str(L4D_DIR))
sys.path.insert(0, str(L4D_FT))
sys.path.insert(0, str(GPU_DIR))
import derive  # noqa: E402  (l4d-data lane, read-only)
from prune import prune  # noqa: E402  (l4d-train lane, read-only)
from run_decide import DecideClient  # noqa: E402

METHOD = "intern_l4d"
MODEL = "intern-decision-4b"
OUT = L4D_FT / "results" / METHOD
FROZEN = OUT / "FROZEN"
DEFAULT_ENDPOINT = "http://10.15.89.184:8002"
OPTIONS = ["Yes", "No"]
TAU_GRID = [round(1 / (1 + math.exp(-0.5 * t)), 6) for t in range(-20, 21)]  # = l4d_ft/select_fold.py TAU_GRID
SECONDARY_TAU = 0.5
L4D_PY = L4D_DIR / ".venv" / "bin" / "python"
HASHED = {"l4d_templates_py": L4D_DIR / "templates.py", "l4d_questions_py": L4D_DIR / "questions.py",
          "derive_py": L4D_DIR / "derive.py", "rules_l4d_dl": L4D_DIR / "l4d.dl", "prune_py": L4D_FT / "prune.py",
          "script": Path(__file__).resolve(), "decide_server_py": GPU_DIR / "server" / "decide_server.py",
          "questions_layer1": L4D_DIR / "build" / "questions_layer1.jsonl",
          "questions_layer3": L4D_DIR / "build" / "questions_layer3.jsonl"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def current_hashes() -> dict:
    import templates  # noqa: E402  (l4d-data lane, read-only)
    return {"l4d_templates_sha256": templates.TEMPLATE_SHA256,
            **{f"{k}_sha256": file_sha256(p) for k, p in HASHED.items()}}


def pruned_questions(layer: str, set_name: str) -> list[dict]:
    return prune([q for q in read_jsonl(L4D_DIR / "build" / f"questions_{layer}.jsonl") if q["set"] == set_name])


def request_body(q: dict) -> dict:
    return {"state": q["state"], "question": q["question"], "options": OPTIONS}


def ask(client: DecideClient, q: dict) -> dict:
    t0 = time.perf_counter()
    code, payload = client.call("POST", "/decide", request_body(q))
    latency = time.perf_counter() - t0
    if code != 200:
        raise RuntimeError(f"{q['qid']}: http {code}: {str(payload)[:300]}")
    raw_yes, raw_no = payload["probs_raw"]["Yes"], payload["probs_raw"]["No"]
    return {"qid": q["qid"], "unit_id": q["unit_id"], "qtype": q["qtype"], "p_yes": float(payload["probs"]["Yes"]),
            "logit_diff": math.log(max(raw_yes, 1e-300)) - math.log(max(raw_no, 1e-300)), "model": MODEL,
            "fold": None, "p_yes_raw": raw_yes, "input_tokens": payload["input_tokens"],
            "forward_ms": payload["forward_ms"], "latency_ms_server": payload["latency_ms_server"],
            "latency_s": latency}


def health(client: DecideClient) -> dict:
    code, h = client.call("GET", "/health")
    assert code == 200, f"/health returned {code}"
    return h


def cmd_answer(args) -> None:
    if args.set == "eval" or args.layer != "layer1":
        assert FROZEN.exists(), f"refused: {FROZEN} missing (select + freeze on layer1 dev first)"
        frozen = json.loads(FROZEN.read_text())
        diff = {k: v for k, v in current_hashes().items() if frozen["hashes"].get(k) != v}
        assert not diff, f"refused: inputs changed since the freeze: {sorted(diff)}"
        assert args.server_kernel == frozen["server_kernel"], "refused: server kernel differs from the freeze"
    qs = pruned_questions(args.layer, args.set)
    if args.limit:
        qs = qs[:args.limit]
    out = OUT / args.layer / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    done = {r["qid"] for r in read_jsonl(out)} if out.exists() else set()
    todo = [q for q in qs if q["qid"] not in done]
    client = DecideClient(args.endpoint)
    h = health(client)
    print(f"[intern_l4d] {args.run_id}: {len(qs)} pruned questions ({args.layer} {args.set}), {len(done)} done, "
          f"{len(todo)} to ask, concurrency {args.concurrency}", flush=True)
    start = utc_now()
    t0 = time.time()
    with out.open("a") as fh, ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for i, row in enumerate(pool.map(lambda q: ask(client, q), todo), 1):
            fh.write(json.dumps(row) + "\n")
            if i % 500 == 0:
                fh.flush()
                print(f"[intern_l4d] {i}/{len(todo)} {time.time() - t0:.0f} s", flush=True)
    rows = read_jsonl(out)
    assert {r["qid"] for r in rows} == {q["qid"] for q in qs} and len(rows) == len(qs), "answers incomplete"
    meta_path = out.with_suffix(".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {"segments": []}
    meta.update({"method": METHOD, "model": MODEL, "layer": args.layer, "set": args.set, "run_id": args.run_id,
                 "n_questions": len(rows), "pruning": "l4d_ft/prune.py prune() (rules-read questions only)",
                 "request_template": request_body({"state": "{state}", "question": "{question}"}),
                 "p_yes": "calibrated probs['Yes'] of /decide (server temperature in server_health)",
                 "endpoint": args.endpoint, "server_health": h, "server_kernel": args.server_kernel,
                 "hashes": current_hashes(),
                 "frozen_sha256": file_sha256(FROZEN) if FROZEN.exists() else None, "host": socket.gethostname(),
                 "concurrency": args.concurrency,
                 "latency_note": "latency_s = dell wall time per request (bulk, concurrency > 1: includes queueing); "
                                 "use the lat300_c1 run for latency"})
    meta["segments"].append({"start_utc": start, "end_utc": utc_now(), "asked": len(todo)})
    meta_path.write_text(json.dumps(meta, indent=1) + "\n")
    print(f"[intern_l4d] wrote {out} ({len(rows)} answers)")


def macro_f1(pred: list[int], truth: list[int]) -> float:
    """= l4d_ft/select_fold.py macro_f1."""
    f1s = []
    for c in (1, 0):
        tp = sum(p == c and t == c for p, t in zip(pred, truth))
        fp = sum(p == c and t != c for p, t in zip(pred, truth))
        fn = sum(p != c and t == c for p, t in zip(pred, truth))
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0)
    return sum(f1s) / 2


def unit_verdicts(units: list[str], by_unit: dict, p_of: dict, tau: float) -> list[int]:
    out = []
    for u in units:
        kept = by_unit.get(u, [])
        if not kept:
            out.append(0)
            continue
        p = {(q["qtype"], tuple(q["site_ids"])): p_of[q["qid"]] for q in kept}
        out.append(derive.evaluate_unit(derive.unit_inputs(kept), p, tau)["pred"])
    return out


def cmd_select(args) -> None:
    """tau on layer1 dev: the select_fold.py readout rule over all dev units (units without kept questions -> 0)."""
    dev_units = sorted({q["unit_id"] for q in read_jsonl(L4D_DIR / "build" / "questions_layer1.jsonl")
                        if q["set"] == "dev"})
    truth_of = {u["unit_id"]: u["truth"] for u in read_jsonl(JF / "data/build/layer1.jsonl")}
    truth = [truth_of[u] for u in dev_units]
    kept = pruned_questions("layer1", "dev")
    by_unit = defaultdict(list)
    for q in kept:
        by_unit[q["unit_id"]].append(q)
    ans_path = OUT / "layer1" / f"{args.run_id}.jsonl"
    p_of = {a["qid"]: a["p_yes"] for a in read_jsonl(ans_path)}
    assert all(q["qid"] in p_of for q in kept), "dev answers incomplete"
    grid = []
    for tau in TAU_GRID:
        pred = unit_verdicts(dev_units, by_unit, p_of, tau)
        grid.append({"tau": tau, "macro_f1": macro_f1(pred, truth),
                     "n_fp": sum(a == 1 and t == 0 for a, t in zip(pred, truth)),
                     "n_fn": sum(a == 0 and t == 1 for a, t in zip(pred, truth))})
    best = max(grid, key=lambda r: (round(r["macro_f1"], 12), -abs(r["tau"] - 0.5)))
    at05 = macro_f1(unit_verdicts(dev_units, by_unit, p_of, SECONDARY_TAU), truth)
    out = {"method": METHOD, "rule": "max layer1-dev unit macro-F1 over TAU_GRID (derive.evaluate_unit on the pruned "
                                     "questions); ties -> tau closest to 0.5 (= select_fold.py readout rule)",
           "tau_grid": TAU_GRID, "best_tau": best["tau"], "best_macro_f1": best["macro_f1"],
           "dev_macro_f1_tau05": at05, "n_units": len(dev_units), "n_questions_pruned": len(kept),
           "answers": str(ans_path.relative_to(JF)), "answers_sha256": file_sha256(ans_path), "grid": grid,
           "utc": utc_now()}
    (OUT / "select_tau.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k not in ("grid", "tau_grid")}))


def cmd_freeze(args) -> None:
    assert not FROZEN.exists(), f"refused: {FROZEN} exists"
    sel = json.loads((OUT / "select_tau.json").read_text())
    dev_meta = json.loads((JF / sel["answers"]).with_suffix(".meta.json").read_text())
    assert file_sha256(JF / sel["answers"]) == sel["answers_sha256"]
    frozen = {"method": METHOD, "model": MODEL, "tau": sel["best_tau"], "tau_secondary": SECONDARY_TAU,
              "dev_macro_f1": sel["best_macro_f1"], "dev_macro_f1_tau05": sel["dev_macro_f1_tau05"],
              "dev_n_units": sel["n_units"], "tau_rule": sel["rule"],
              "dev_answers": sel["answers"], "dev_answers_sha256": sel["answers_sha256"],
              "select_tau_sha256": file_sha256(OUT / "select_tau.json"),
              "server_health": dev_meta["server_health"], "server_kernel": dev_meta["server_kernel"],
              "request_template": dev_meta["request_template"],
              "hashes": current_hashes(), "frozen_utc": utc_now()}
    FROZEN.write_text(json.dumps(frozen, indent=1) + "\n")
    print(json.dumps(frozen, indent=1))


def cmd_units(args) -> None:
    frozen = json.loads(FROZEN.read_text())
    layer = args.layer
    units = [u for u in read_jsonl(JF / "data/build" / f"{layer}.jsonl") if u["set"] == "eval"]
    kept = pruned_questions(layer, "eval")
    ans_path = OUT / layer / f"{args.run_id}.jsonl"
    answers = {a["qid"]: a for a in read_jsonl(ans_path)}
    n_kept = defaultdict(int)
    for q in kept:
        n_kept[q["unit_id"]] += 1
    model_s = defaultdict(float)
    for q in kept:
        model_s[q["unit_id"]] += answers[q["qid"]]["latency_ms_server"] / 1000
    for tau, suffix in ((frozen["tau"], ""), (SECONDARY_TAU, "_tau05")):
        with tempfile.TemporaryDirectory(prefix="intern_l4d_") as td:
            qf, af, uf = Path(td, "q.jsonl"), Path(td, "a.jsonl"), Path(td, "u.jsonl")
            qf.write_text("".join(json.dumps(q) + "\n" for q in kept))
            af.write_text("".join(json.dumps(answers[q["qid"]]) + "\n" for q in kept))
            proc = subprocess.run([str(L4D_PY), str(L4D_DIR / "derive.py"), "--questions", str(qf), "--answers",
                                   str(af), "--tau", str(tau), "--method", METHOD, "--model", MODEL, "--out", str(uf),
                                   "--souffle"], capture_output=True, text=True, check=True)
            rows = {r["unit_id"]: r for r in read_jsonl(uf)}
        out_rows = []
        for u in units:
            r = rows.get(u["unit_id"]) or {
                "unit_id": u["unit_id"], "method": METHOD, "strategy": "L4D", "model": MODEL,
                "layer": derive.PRED_LAYER[layer], "pred": 0, "score": 0.0, "latency_s": 0.0, "status": "ok",
                "extra": {"tau": tau, "leaks": [], "no_kept_question": True, "derive_s": 0.0}}
            r["extra"].update({"n_questions_kept": n_kept[u["unit_id"]], "model_s": model_s[u["unit_id"]],
                               "run_id": args.run_id})
            r["latency_s"] = r["extra"]["derive_s"] + model_s[u["unit_id"]]
            out_rows.append(r)
        dest = OUT / layer / f"{args.run_id}{suffix}_units.jsonl"
        dest.write_text("".join(json.dumps(r) + "\n" for r in out_rows))
        meta = {"method": METHOD, "strategy": "L4D", "layer": layer, "run_id": args.run_id, "tau": tau,
                "tau_role": "primary (layer1-dev tau, FROZEN)" if not suffix else "secondary (tau = 0.5)",
                "n_units": len(out_rows), "n_questions_pruned": len(kept),
                "n_units_without_kept_question": sum(not n_kept[u["unit_id"]] for u in units),
                "answers": str(ans_path.relative_to(JF)), "answers_sha256": file_sha256(ans_path),
                "frozen_sha256": file_sha256(FROZEN), "derive_stderr": proc.stderr.strip().splitlines()[-2:],
                "latency_note": "latency_s = sum of server-side /decide times of the unit's questions + derive_s; "
                                "end-to-end client latency is in lat300_c1", "utc": utc_now()}
        dest.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        print(json.dumps({k: meta[k] for k in ("tau", "n_units", "n_units_without_kept_question", "derive_stderr")}))


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def summary(values: list[float]) -> dict:
    return {"median": statistics.median(values), "p90": pct(values, 0.9), "mean": statistics.fmean(values),
            "max": max(values)}


def cmd_latency(args) -> None:
    """c1 end-to-end per unit on latency300 (layer3): live questions + prune + one /decide per question + derive."""
    from questions import make_questions  # noqa: E402  (tree-sitter; run with l4d/.venv/bin/python)
    frozen = json.loads(FROZEN.read_text())
    tau = frozen["tau"]
    layer = "layer3"
    groups = set(json.loads((JF / "data/build/subsets.json").read_text())["latency300"])
    units = [u for u in read_jsonl(JF / "data/build" / f"{layer}.jsonl") if u["group_id"] in groups]
    assert len(units) == 300 and all(u["set"] == "eval" for u in units)
    units.sort(key=lambda u: (u["fold"], u["unit_id"]))
    if args.limit:
        units = units[:args.limit]
    pre = defaultdict(list)
    for q in read_jsonl(L4D_DIR / "build" / f"questions_{layer}.jsonl"):
        pre[q["unit_id"]].append(q)
    stored_path = OUT / layer / "eval_r1.jsonl"
    stored = {a["qid"]: a["p_yes"] for a in read_jsonl(stored_path)} if stored_path.exists() else {}
    client = DecideClient(args.endpoint)
    h = health(client)
    load_start = os.getloadavg()
    q0 = prune(pre[units[0]["unit_id"]])[0]
    ask(client, q0)  # warm-up, not timed
    rows, start = [], utc_now()
    for u in units:
        t0 = time.perf_counter()
        qs = prune(make_questions(u, layer))
        t1 = time.perf_counter()
        answers = [ask(client, q) for q in qs]
        t2 = time.perf_counter()
        if qs:
            p = {(q["qtype"], tuple(q["site_ids"])): a["p_yes"] for q, a in zip(qs, answers)}
            res = derive.evaluate_unit(derive.unit_inputs(qs), p, tau)
        else:
            res = {"pred": 0, "score": 0.0, "leaks": []}
        t3 = time.perf_counter()
        same = [(q["qid"], q["state"], q["question"]) for q in qs] == \
            [(q["qid"], q["state"], q["question"]) for q in prune(pre[u["unit_id"]])]
        assert same, f"live questions differ from precomputed for {u['unit_id']}"
        diffs = [abs(a["p_yes"] - stored[a["qid"]]) for a in answers if a["qid"] in stored]
        rows.append({"unit_id": u["unit_id"], "method": METHOD, "strategy": "L4D", "model": MODEL,
                     "layer": derive.PRED_LAYER[layer], "pred": res["pred"], "score": res["score"],
                     "latency_s": t3 - t0, "status": "ok",
                     "extra": {"tau": tau, "n_questions": len(qs), "n_questions_full": len(pre[u["unit_id"]]),
                               "parse_prune_s": t1 - t0, "http_s": t2 - t1, "derive_s": t3 - t2,
                               "e2e_no_parse_s": t3 - t1,
                               "server_latency_s": sum(a["latency_ms_server"] for a in answers) / 1000,
                               "server_forward_s": sum(a["forward_ms"] for a in answers) / 1000,
                               "input_tokens": sum(a["input_tokens"] for a in answers), "leaks": res["leaks"],
                               "max_abs_dp_vs_eval_r1": max(diffs) if diffs else None,
                               "answers": {a["qid"]: a["p_yes"] for a in answers}, "truth": u["truth"]}})
    end, load_end = utc_now(), os.getloadavg()
    out = OUT / layer / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    ex = [r["extra"] for r in rows]
    dps = [e["max_abs_dp_vs_eval_r1"] for e in ex if e["max_abs_dp_vs_eval_r1"] is not None]
    meta = {"method": METHOD, "model": MODEL, "strategy": "L4D", "layer": layer, "subset": "latency300",
            "run_id": args.run_id, "n_units": len(rows), "concurrency": 1, "tau": tau,
            "n_units_without_model_call": sum(not e["n_questions"] for e in ex), "client_host": socket.gethostname(),
            "endpoint": args.endpoint, "server_health": h, "kernel_note": args.kernel_note,
            "start_utc": start, "end_utc": end, "loadavg_start": load_start, "loadavg_end": load_end,
            "e2e_s": summary([r["latency_s"] for r in rows]), "e2e_no_parse_s": summary([e["e2e_no_parse_s"] for e in ex]),
            "parse_prune_s": summary([e["parse_prune_s"] for e in ex]), "http_s": summary([e["http_s"] for e in ex]),
            "derive_s": summary([e["derive_s"] for e in ex]),
            "server_latency_s": summary([e["server_latency_s"] for e in ex]),
            "server_forward_s": summary([e["server_forward_s"] for e in ex]),
            "questions_per_unit": summary([e["n_questions"] for e in ex]),
            "max_abs_dp_vs_eval_r1": max(dps) if dps else None,
            "accuracy_vs_truth": sum(r["pred"] == r["extra"]["truth"] for r in rows) / len(rows),
            "hashes": current_hashes(), "frozen_sha256": file_sha256(FROZEN),
            "note": "e2e = live sites+questions (tree-sitter, dell) + prune + one POST /decide per kept question, "
                    "sequential (Intern-Decision-4B, one RTX 3090) + derive (dell); warm-up request excluded"}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps({k: meta[k] for k in ("n_units", "e2e_s", "parse_prune_s", "http_s", "server_latency_s",
                                           "questions_per_unit", "max_abs_dp_vs_eval_r1", "accuracy_vs_truth")},
                     indent=1))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("answer")
    p.add_argument("--layer", choices=("layer1", "layer3"), required=True)
    p.add_argument("--set", choices=("dev", "eval"), required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=2)
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p.add_argument("--server-kernel", default="causal_conv1d reference fallback (transformers), as all stored "
                                             "Intern-Decision predictions")
    p = sub.add_parser("select")
    p.add_argument("--run-id", default="dev_r1")
    sub.add_parser("freeze")
    p = sub.add_parser("units")
    p.add_argument("--layer", default="layer3")
    p.add_argument("--run-id", default="eval_r1")
    p = sub.add_parser("latency")
    p.add_argument("--run-id", default="lat300_c1")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    p.add_argument("--kernel-note", default="")
    args = ap.parse_args()
    {"answer": cmd_answer, "select": cmd_select, "freeze": cmd_freeze, "units": cmd_units,
     "latency": cmd_latency}[args.cmd](args)


if __name__ == "__main__":
    main()

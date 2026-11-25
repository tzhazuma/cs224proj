#!/usr/bin/env python3
"""Jev (TypeSafe System One, jev-latest) on the L4-D questions (method jev_l4d; lane jev-l4d).

Mirror of gpu/run_decide_l4d.py (intern_l4d) with the decision model swapped for the Jev API.
Per unit: the L4-D questions of l4d/build/questions_<layer>.jsonl, pruned to the questions the v1 rules read
(l4d_ft/prune.py, as intern_l4d and lora_l4d_opt; verdicts identical to the full question set). Each question is one
POST /systemone (llmlane.clients.JevClient.ask): state = the question's state unchanged, questions =
{"answer": {"type": "noul", "instructions": <question text unchanged>, "criteria": CRITERIA}}; p_yes = the noul
probability. One question per request, so co-questions cannot influence each other. Unit verdicts: l4d/derive.py
(--souffle) on the pruned questions; a unit without a kept question has no heap block -> pred 0, score 0, no call.

tau: primary 0.5, fixed before any Jev L4-D call (parent 2026-11-24 19:05; Jev L1-L3 convention). Secondary tau:
chosen on all 660 layer1 dev units by the run_decide_l4d.py select rule (TAU_GRID, max dev unit macro-F1 through
derive.evaluate_unit, ties -> |tau - 0.5| smallest), frozen in l4d_ft/results/jev_l4d/FROZEN before any eval call.

Every call goes through the llmlane ledger (provider jev, purpose jev_l4d, strategy L4D) and a Budget whose run cap
is min(--max-cost, lane cap USD 1.00 - lane spend so far) and whose global stop is the ledger Jev total USD 3.2.
A returned model version that differs from the run's (or the FROZEN) version stops the run.

  python3 run_jev_l4d.py answer --layer layer1 --set dev --run-id pilot_r1 --pilot --max-cost 0.03
  python3 run_jev_l4d.py answer --layer layer1 --set dev --run-id dev_r1 --max-cost 0.15
  python3 run_jev_l4d.py select --run-id dev_r1                                # -> results/jev_l4d/select_tau.json
  python3 run_jev_l4d.py freeze                                                # -> results/jev_l4d/FROZEN
  python3 run_jev_l4d.py answer --layer layer3 --set eval --run-id eval_r1 --max-cost 0.6   # needs FROZEN
  python3 run_jev_l4d.py units --layer layer3 --run-id eval_r1   # eval_r1_units.jsonl (0.5), eval_r1_devtau_units.jsonl
  ../l4d/.venv/bin/python run_jev_l4d.py latency --run-id lat300_c1 --max-cost 0.1   # c1 e2e on latency300

Runs are resumable (answered qids are skipped). Outputs only under l4d_ft/results/jev_l4d/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LLM_DIR = Path(__file__).resolve().parent
JF = LLM_DIR.parent
L4D_DIR = JF / "l4d"
L4D_FT = JF / "l4d_ft"
sys.path.insert(0, str(L4D_DIR))
sys.path.insert(0, str(L4D_FT))
sys.path.insert(0, str(LLM_DIR))
import derive  # noqa: E402  (l4d-data lane, read-only)
from prune import prune  # noqa: E402  (l4d-train lane, read-only)
from llmlane import clients  # noqa: E402
from llmlane.ledger import LEDGER_PATH, Budget, BudgetExceeded, Ledger  # noqa: E402
from llmlane.pricing import JEV_USD_PER_M_INPUT, jev_cost_usd, jev_estimate_usd  # noqa: E402

METHOD = "jev_l4d"
MODEL = clients.JEV_MODEL  # "jev-latest"; the returned version is recorded per answer and in FROZEN
PURPOSE = "jev_l4d"  # ledger purpose of every call of this lane
OUT = L4D_FT / "results" / METHOD
FROZEN = OUT / "FROZEN"
QUESTION_NAME = "answer"
CRITERIA = {"true": "The answer to the question is Yes.", "false": "The answer to the question is No."}
PRIMARY_TAU = 0.5  # fixed by the parent before any Jev L4-D call
TAU_GRID = [round(1 / (1 + math.exp(-0.5 * t)), 6) for t in range(-20, 21)]  # = l4d_ft/select_fold.py TAU_GRID
LANE_CAP_USD = 1.00  # this lane's total Jev spend (ledger rows with purpose jev_l4d)
LEDGER_JEV_STOP_USD = 3.2  # hard stop on the ledger's Jev total (all lanes)
PILOT_N = 40
PILOT_SEED = 20261123
L4D_PY = L4D_DIR / ".venv" / "bin" / "python"
HASHED = {"l4d_templates_py": L4D_DIR / "templates.py", "l4d_questions_py": L4D_DIR / "questions.py",
          "derive_py": L4D_DIR / "derive.py", "rules_l4d_dl": L4D_DIR / "l4d.dl", "prune_py": L4D_FT / "prune.py",
          "script": Path(__file__).resolve(), "llmlane_clients_py": LLM_DIR / "llmlane" / "clients.py",
          "llmlane_prompts_py": LLM_DIR / "llmlane" / "prompts.py",
          "questions_layer1": L4D_DIR / "build" / "questions_layer1.jsonl",
          "questions_layer3": L4D_DIR / "build" / "questions_layer3.jsonl"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def pilot_units(questions: list[dict]) -> list[str]:
    """PILOT_N layer1 dev units with at least one kept question, seeded sample (seed PILOT_SEED)."""
    units = sorted({q["unit_id"] for q in questions})
    return sorted(random.Random(PILOT_SEED).sample(units, min(PILOT_N, len(units))))


def question_spec(q: dict) -> dict:
    return {"type": "noul", "instructions": q["question"], "criteria": dict(CRITERIA)}


def request_body(q: dict) -> dict:
    """The JSON body JevClient.ask sends for question q."""
    return {"model": MODEL, "state": q["state"], "questions": {QUESTION_NAME: question_spec(q)}}


def answer_row(q: dict, result: clients.CallResult, cost: float) -> dict:
    """Answers row (l4d/README.md section 4) plus call bookkeeping."""
    usage = result.usage or {}
    return {"qid": q["qid"], "unit_id": q["unit_id"], "qtype": q["qtype"], "p_yes": float(result.score),
            "logit_diff": None, "model": result.model, "fold": None, "model_requested": MODEL,
            "input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
            "cost_usd": cost, "latency_s": result.latency_s, "attempts": len(result.attempts),
            "http_status": result.http_status}


def lane_spent(ledger: Ledger) -> float:
    return sum(float(r.get("cost") or 0.0) for r in ledger.records()
               if r.get("kind") == "call" and r.get("provider") == "jev" and r.get("purpose") == PURPOSE)


def make_budget(ledger: Ledger, max_cost: float) -> Budget:
    lane = lane_spent(ledger)
    run_cap = min(max_cost, LANE_CAP_USD - lane)
    if run_cap <= 0:
        raise BudgetExceeded(f"lane cap USD {LANE_CAP_USD} reached (lane spend {lane:.6f})")
    total = ledger.spent("jev")
    if total >= LEDGER_JEV_STOP_USD:
        raise BudgetExceeded(f"ledger Jev total {total:.6f} >= hard stop {LEDGER_JEV_STOP_USD}")
    return Budget("jev", run_cap, total, global_cap=LEDGER_JEV_STOP_USD)


class Asker:
    """One Jev call per question: budget reservation, model-version guard, ledger + raw-log records."""

    def __init__(self, client: Any, budget: Budget, ledger: Ledger, run_id: str, layer: str, set_name: str,
                 raw_path: Path, expected_model: str | None) -> None:
        self.client, self.budget, self.ledger = client, budget, ledger
        self.run_id, self.layer, self.set_name = run_id, layer, set_name
        self.raw_path = raw_path
        self.expected_model = expected_model
        self.stop = threading.Event()
        self.abort_reason: str | None = None
        self.lock = threading.Lock()
        self.totals = {"calls": 0, "ok": 0, "failed": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
        self.models: dict[str, int] = {}

    def abort(self, reason: str) -> None:
        with self.lock:
            if not self.stop.is_set():
                self.abort_reason = reason
                print(f"[jev_l4d] ABORT: {reason}", flush=True)
            self.stop.set()

    def call(self, q: dict) -> dict | None:
        """Ask q; returns {"q", "result", "cost", "row" (None unless ok), "fatal"} or None if not asked."""
        if self.stop.is_set():
            return None
        estimate = jev_estimate_usd(len(q["state"]) + len(q["question"]) + 200)
        try:
            self.budget.reserve(estimate)
        except BudgetExceeded as exc:
            self.abort(str(exc))
            return None
        fatal = None
        try:
            result = self.client.ask(q["state"], question_spec(q), name=QUESTION_NAME, stop=self.stop)
        except clients.FatalApiError as exc:
            fatal, result = str(exc), exc.result
            self.abort(f"fatal: {fatal}")
        cost = jev_cost_usd(result.usage if result is not None else None)
        self.budget.settle(estimate, cost)
        if result is None:
            return None
        if result.model:
            with self.lock:
                if self.expected_model is None:
                    self.expected_model = result.model
                version_ok = result.model == self.expected_model
            if not version_ok:
                self.abort(f"returned model version changed: {result.model} != {self.expected_model}")
        ok = result.status == "ok" and fatal is None and result.score is not None
        return {"q": q, "result": result, "cost": cost, "fatal": fatal,
                "row": answer_row(q, result, cost) if ok and result.model == self.expected_model else None}

    def commit(self, bundle: dict) -> None:
        """Ledger row (as run_llm.py Run.account) + raw log line; thread-safe."""
        q, result, cost = bundle["q"], bundle["result"], bundle["cost"]
        usage = result.usage or {}
        self.ledger.append({
            "kind": "call", "ts_utc": iso(result.ended_utc or time.time()), "run_id": self.run_id,
            "provider": "jev", "purpose": PURPOSE, "model_requested": self.client.model,
            "model_returned": result.model, "strategy": "L4D", "set": self.set_name, "layer": self.layer,
            "unit_id": q["unit_id"], "qid": q["qid"], "status": result.status, "http_status": result.http_status,
            "attempts": len(result.attempts), "usage": result.usage, "peak_price": None, "cost": round(cost, 10),
            "currency": "USD"})
        entry = {"qid": q["qid"], "unit_id": q["unit_id"], "status": result.status, "error": result.error,
                 "fatal": bundle["fatal"], "latency_s": result.latency_s, "attempts": result.attempts,
                 "raw": result.raw, "started_utc": iso(result.started_utc), "ended_utc": iso(result.ended_utc)}
        with self.lock:
            self.totals["calls"] += 1
            self.totals["ok" if bundle["row"] is not None else "failed"] += 1
            self.totals["input_tokens"] += int(usage.get("input_tokens") or 0)
            self.totals["output_tokens"] += int(usage.get("output_tokens") or 0)
            self.totals["cost"] += cost
            if result.model:
                self.models[result.model] = self.models.get(result.model, 0) + 1
            self.raw_path.parent.mkdir(parents=True, exist_ok=True)
            with self.raw_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_frozen_checked() -> dict:
    assert FROZEN.exists(), f"refused: {FROZEN} missing (select + freeze on layer1 dev first)"
    frozen = json.loads(FROZEN.read_text())
    diff = {k: v for k, v in current_hashes().items() if frozen["hashes"].get(k) != v}
    assert not diff, f"refused: inputs changed since the freeze: {sorted(diff)}"
    assert frozen["criteria"] == CRITERIA and frozen["question_name"] == QUESTION_NAME, \
        "refused: request criteria differ from the freeze"
    assert frozen["request_template"] == request_body({"state": "{state}", "question": "{question}"}), \
        "refused: request template differs from the freeze"
    return frozen


def cmd_answer(args) -> int:
    frozen = None
    if args.set == "eval" or args.layer != "layer1":
        frozen = load_frozen_checked()
    qs = pruned_questions(args.layer, args.set)
    if args.pilot:
        assert args.layer == "layer1" and args.set == "dev", "the pilot uses layer1 dev units only"
        keep = set(pilot_units(qs))
        qs = [q for q in qs if q["unit_id"] in keep]
    if args.limit:
        qs = qs[:args.limit]
    out = OUT / args.layer / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    prior = read_jsonl(out) if out.exists() else []
    done = {r["qid"] for r in prior}
    todo = [q for q in qs if q["qid"] not in done]
    expected = frozen["model_returned"] if frozen else (prior[0]["model"] if prior else None)
    ledger = Ledger(LEDGER_PATH)
    try:
        budget = make_budget(ledger, args.max_cost)
    except BudgetExceeded as exc:
        print(f"refused: {exc}")
        return 2
    client = clients.JevClient()
    asker = Asker(client, budget, ledger, args.run_id, args.layer, args.set,
                  OUT / "raw_logs" / args.layer / f"{args.run_id}.jsonl", expected)
    print(f"[jev_l4d] {args.run_id}: {len(qs)} pruned questions ({args.layer} {args.set}"
          f"{', pilot ' + str(PILOT_N) + ' units' if args.pilot else ''}), {len(done)} done, {len(todo)} to ask, "
          f"concurrency {args.concurrency}; lane spend {lane_spent(ledger):.6f} USD, ledger Jev "
          f"{budget.ledger_spent:.6f} USD, run cap {budget.run_cap:.6f}, stop {budget.global_cap}", flush=True)
    start = utc_now()
    t0 = time.time()
    write_lock = threading.Lock()
    with out.open("a") as fh:
        def work(q: dict) -> None:
            bundle = asker.call(q)
            if bundle is None:
                return
            asker.commit(bundle)
            if bundle["row"] is not None:
                with write_lock:
                    fh.write(json.dumps(bundle["row"]) + "\n")
                    fh.flush()
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            for i, _ in enumerate(pool.map(work, todo), 1):
                if i % 500 == 0:
                    print(f"[jev_l4d] {i}/{len(todo)} {time.time() - t0:.0f} s; cost {asker.totals['cost']:.6f} USD; "
                          f"failed {asker.totals['failed']}", flush=True)
    rows = read_jsonl(out)
    complete = {r["qid"] for r in rows} == {q["qid"] for q in qs} and len(rows) == len(qs)
    meta_path = out.with_suffix(".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {"segments": []}
    meta.update({"method": METHOD, "model": MODEL, "models_returned": dict(Counter(r["model"] for r in rows)),
                 "layer": args.layer, "set": args.set, "run_id": args.run_id, "pilot": bool(args.pilot),
                 "pilot_units": pilot_units(pruned_questions("layer1", "dev")) if args.pilot else None,
                 "n_questions": len(qs), "n_answered": len(rows), "complete": complete,
                 "pruning": "l4d_ft/prune.py prune() (rules-read questions only)",
                 "request_template": request_body({"state": "{state}", "question": "{question}"}),
                 "criteria": CRITERIA, "question_name": QUESTION_NAME,
                 "p_yes": "noul probability of the single question 'answer' (POST /systemone)",
                 "client": client.public_config(), "hashes": current_hashes(),
                 "frozen_sha256": file_sha256(FROZEN) if FROZEN.exists() else None, "host": socket.gethostname(),
                 "concurrency": args.concurrency, "usd_per_m_input": JEV_USD_PER_M_INPUT,
                 "cost_usd_total": round(sum(r["cost_usd"] for r in rows), 8),
                 "input_tokens_total": sum(r["input_tokens"] or 0 for r in rows),
                 "raw_log": str(asker.raw_path.relative_to(JF)),
                 "latency_note": "latency_s = dell wall time per request incl. retries (bulk, concurrency > 1: "
                                 "includes client-side queueing at the API); use the lat300_c1 run for latency"})
    meta["segments"].append({"start_utc": start, "end_utc": utc_now(), "asked": len(todo), **asker.totals,
                             "models_seen": asker.models, "aborted": asker.abort_reason,
                             "lane_spend_after": lane_spent(ledger), "ledger_jev_after": ledger.spent("jev")})
    meta_path.write_text(json.dumps(meta, indent=1) + "\n")
    print(f"[jev_l4d] wrote {out} ({len(rows)}/{len(qs)} answers; this segment {asker.totals}); "
          f"lane spend {lane_spent(ledger):.6f} USD, ledger Jev {ledger.spent('jev'):.6f} USD", flush=True)
    if asker.abort_reason or not complete:
        print(f"[jev_l4d] INCOMPLETE (aborted: {asker.abort_reason}); rerun the same command to resume", flush=True)
        return 3
    return 0


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


def cmd_select(args) -> int:
    """Secondary tau on layer1 dev: the run_decide_l4d.py select rule over all dev units (no kept question -> 0)."""
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
    pred05 = unit_verdicts(dev_units, by_unit, p_of, PRIMARY_TAU)
    out = {"method": METHOD, "rule": "max layer1-dev unit macro-F1 over TAU_GRID (derive.evaluate_unit on the pruned "
                                     "questions); ties -> tau closest to 0.5 (= run_decide_l4d.py select rule)",
           "primary_tau": PRIMARY_TAU, "primary_rule": "fixed 0.5 (parent 2026-11-24 19:05, before any call)",
           "tau_grid": TAU_GRID, "best_tau": best["tau"], "best_macro_f1": best["macro_f1"],
           "dev_macro_f1_tau05": macro_f1(pred05, truth),
           "n_fp_tau05": sum(a == 1 and t == 0 for a, t in zip(pred05, truth)),
           "n_fn_tau05": sum(a == 0 and t == 1 for a, t in zip(pred05, truth)),
           "n_units": len(dev_units), "n_questions_pruned": len(kept),
           "answers": str(ans_path.relative_to(JF)), "answers_sha256": file_sha256(ans_path), "grid": grid,
           "utc": utc_now()}
    (OUT / "select_tau.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k not in ("grid", "tau_grid")}))
    return 0


def cmd_freeze(args) -> int:
    assert not FROZEN.exists(), f"refused: {FROZEN} exists"
    sel = json.loads((OUT / "select_tau.json").read_text())
    dev_path = JF / sel["answers"]
    dev_meta = json.loads(dev_path.with_suffix(".meta.json").read_text())
    assert file_sha256(dev_path) == sel["answers_sha256"]
    versions = {r["model"] for r in read_jsonl(dev_path)}
    assert len(versions) == 1, f"dev answers have several model versions: {versions}"
    assert dev_meta["criteria"] == CRITERIA
    frozen = {"method": METHOD, "model": MODEL, "model_returned": versions.pop(),
              "tau": PRIMARY_TAU, "tau_role": "primary, fixed 0.5 before any Jev L4-D call (parent 2026-11-24 19:05)",
              "tau_secondary": sel["best_tau"], "tau_secondary_rule": sel["rule"],
              "dev_macro_f1_tau05": sel["dev_macro_f1_tau05"], "dev_macro_f1_tau_secondary": sel["best_macro_f1"],
              "dev_n_units": sel["n_units"], "dev_n_questions_pruned": sel["n_questions_pruned"],
              "dev_answers": sel["answers"], "dev_answers_sha256": sel["answers_sha256"],
              "select_tau_sha256": file_sha256(OUT / "select_tau.json"),
              "request_template": dev_meta["request_template"], "question_name": QUESTION_NAME,
              "criteria": dev_meta["criteria"], "client": dev_meta["client"],
              "hashes": current_hashes(), "frozen_utc": utc_now()}
    FROZEN.write_text(json.dumps(frozen, indent=1) + "\n")
    print(json.dumps(frozen, indent=1))
    return 0


def cmd_units(args) -> int:
    frozen = load_frozen_checked()
    layer = args.layer
    units = [u for u in read_jsonl(JF / "data/build" / f"{layer}.jsonl") if u["set"] == "eval"]
    kept = pruned_questions(layer, "eval")
    ans_path = OUT / layer / f"{args.run_id}.jsonl"
    answers = {a["qid"]: a for a in read_jsonl(ans_path)}
    assert all(q["qid"] in answers for q in kept), "eval answers incomplete"
    assert {a["model"] for a in answers.values()} == {frozen["model_returned"]}, "model version differs from FROZEN"
    n_kept = defaultdict(int)
    model_s = defaultdict(float)
    for q in kept:
        n_kept[q["unit_id"]] += 1
        model_s[q["unit_id"]] += answers[q["qid"]]["latency_s"]
    for tau, suffix, role in ((frozen["tau"], "", "primary (tau = 0.5, fixed before any call)"),
                              (frozen["tau_secondary"], "_devtau", "secondary (layer1-dev tau, FROZEN)")):
        with tempfile.TemporaryDirectory(prefix="jev_l4d_") as td:
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
                               "run_id": args.run_id, "model_returned": frozen["model_returned"]})
            r["latency_s"] = r["extra"]["derive_s"] + model_s[u["unit_id"]]
            out_rows.append(r)
        dest = OUT / layer / f"{args.run_id}{suffix}_units.jsonl"
        dest.write_text("".join(json.dumps(r) + "\n" for r in out_rows))
        meta = {"method": METHOD, "strategy": "L4D", "layer": layer, "run_id": args.run_id, "tau": tau,
                "tau_role": role, "model": MODEL, "model_returned": frozen["model_returned"],
                "n_units": len(out_rows), "n_questions_pruned": len(kept),
                "n_units_without_kept_question": sum(not n_kept[u["unit_id"]] for u in units),
                "answers": str(ans_path.relative_to(JF)), "answers_sha256": file_sha256(ans_path),
                "frozen_sha256": file_sha256(FROZEN), "derive_stderr": proc.stderr.strip().splitlines()[-2:],
                "latency_note": "latency_s = sum of bulk client wall times of the unit's Jev calls (concurrency > 1) "
                                "+ derive_s; c1 end-to-end latency is in lat300_c1", "utc": utc_now()}
        dest.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        print(json.dumps({k: meta[k] for k in ("tau", "n_units", "n_units_without_kept_question", "derive_stderr")}))
    return 0


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def summary(values: list[float]) -> dict:
    return {"median": statistics.median(values), "p90": pct(values, 0.9), "mean": statistics.fmean(values),
            "max": max(values)}


def cmd_latency(args) -> int:
    """c1 end-to-end per unit on latency300 (layer3): live questions + prune + Jev calls + derive.

    Units run one after another (unit-level concurrency 1); the questions of one unit are sent concurrently, one
    thread per question (primary). The sequential figure (secondary) = parse/prune + sum of per-call latencies +
    derive. Ledger/raw-log writes happen after a unit's timing window."""
    from questions import make_questions  # noqa: E402  (tree-sitter; run with l4d/.venv/bin/python)
    frozen = load_frozen_checked()
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
    stored_units_path = OUT / layer / "eval_r1_units.jsonl"
    stored_pred = {r["unit_id"]: r["pred"] for r in read_jsonl(stored_units_path)} if stored_units_path.exists() else {}
    ledger = Ledger(LEDGER_PATH)
    try:
        budget = make_budget(ledger, args.max_cost)
    except BudgetExceeded as exc:
        print(f"refused: {exc}")
        return 2
    client = clients.JevClient()
    asker = Asker(client, budget, ledger, args.run_id, layer, "eval",
                  OUT / "raw_logs" / layer / f"{args.run_id}.jsonl", frozen["model_returned"])
    load_start = os.getloadavg()
    warm = asker.call(prune(pre[units[0]["unit_id"]])[0])  # warm-up (connection, TLS), not timed
    if warm is not None:
        asker.commit(warm)
    rows, start = [], utc_now()
    for u in units:
        if asker.stop.is_set():
            break
        t0 = time.perf_counter()
        qs = prune(make_questions(u, layer))
        t1 = time.perf_counter()
        if qs:
            with ThreadPoolExecutor(max_workers=len(qs)) as pool:
                bundles = list(pool.map(asker.call, qs))
        else:
            bundles = []
        t2 = time.perf_counter()
        ok = bool(bundles) and all(b is not None and b["row"] is not None for b in bundles)
        res = {"pred": 0, "score": 0.0, "leaks": []}
        if qs and ok:
            p = {(q["qtype"], tuple(q["site_ids"])): b["row"]["p_yes"] for q, b in zip(qs, bundles)}
            res = derive.evaluate_unit(derive.unit_inputs(qs), p, tau)
        t3 = time.perf_counter()
        for b in bundles:
            if b is not None:
                asker.commit(b)
        same = [(q["qid"], q["state"], q["question"]) for q in qs] == \
            [(q["qid"], q["state"], q["question"]) for q in prune(pre[u["unit_id"]])]
        assert same, f"live questions differ from precomputed for {u['unit_id']}"
        status = "ok" if (ok or not qs) else "error"
        answers = [b["row"] for b in bundles if b is not None and b["row"] is not None]
        call_s = [b["result"].latency_s for b in bundles if b is not None]
        diffs = [abs(a["p_yes"] - stored[a["qid"]]) for a in answers if a["qid"] in stored]
        seq = (t1 - t0) + sum(call_s) + (t3 - t2)
        rows.append({"unit_id": u["unit_id"], "method": METHOD, "strategy": "L4D", "model": MODEL,
                     "layer": derive.PRED_LAYER[layer], "pred": res["pred"] if status == "ok" else None,
                     "score": res["score"] if status == "ok" else None, "latency_s": t3 - t0, "status": status,
                     "extra": {"tau": tau, "n_questions": len(qs), "n_questions_full": len(pre[u["unit_id"]]),
                               "parse_prune_s": t1 - t0, "http_s": t2 - t1, "derive_s": t3 - t2,
                               "e2e_no_parse_s": t3 - t1, "call_latency_s": call_s,
                               "sequential_s": seq, "sum_call_s": sum(call_s),
                               "max_call_s": max(call_s) if call_s else 0.0,
                               "attempts": sum(len(b["result"].attempts) for b in bundles if b is not None),
                               "input_tokens": sum(a["input_tokens"] or 0 for a in answers),
                               "cost_usd": sum(b["cost"] for b in bundles if b is not None), "leaks": res["leaks"],
                               "max_abs_dp_vs_eval_r1": max(diffs) if diffs else None,
                               "pred_eval_r1": stored_pred.get(u["unit_id"]),
                               "models_returned": sorted({a["model"] for a in answers}),
                               "answers": {a["qid"]: a["p_yes"] for a in answers}, "truth": u["truth"]}})
    end, load_end = utc_now(), os.getloadavg()
    out = OUT / layer / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    okr = [r for r in rows if r["status"] == "ok"]
    ex = [r["extra"] for r in okr]
    dps = [e["max_abs_dp_vs_eval_r1"] for e in ex if e["max_abs_dp_vs_eval_r1"] is not None]
    flips = [r["unit_id"] for r in okr if r["extra"]["pred_eval_r1"] is not None
             and r["pred"] != r["extra"]["pred_eval_r1"]]
    meta = {"method": METHOD, "model": MODEL, "model_returned": frozen["model_returned"], "strategy": "L4D",
            "layer": layer, "subset": "latency300", "run_id": args.run_id, "n_units": len(rows),
            "n_ok": len(okr), "aborted": asker.abort_reason, "unit_concurrency": 1,
            "question_concurrency": "one thread per question of the unit (all questions of a unit in flight)",
            "tau": tau, "n_units_without_model_call": sum(not e["n_questions"] for e in ex),
            "client_host": socket.gethostname(), "client": client.public_config(),
            "start_utc": start, "end_utc": end, "loadavg_start": load_start, "loadavg_end": load_end,
            "latency_lock": {"path": "/tmp/cs224_latency.lock", "held": bool(os.environ.get("CS224_LATENCY_LOCK")),
                             "start_utc": start},
            "e2e_s": summary([r["latency_s"] for r in okr]),
            "sequential_s": summary([e["sequential_s"] for e in ex]),
            "e2e_no_parse_s": summary([e["e2e_no_parse_s"] for e in ex]),
            "parse_prune_s": summary([e["parse_prune_s"] for e in ex]), "http_s": summary([e["http_s"] for e in ex]),
            "derive_s": summary([e["derive_s"] for e in ex]),
            "per_call_s": summary([c for e in ex for c in e["call_latency_s"]] or [0.0]),
            "questions_per_unit": summary([e["n_questions"] for e in ex]),
            "max_abs_dp_vs_eval_r1": max(dps) if dps else None, "n_units_compared_dp": len(dps),
            "verdict_flips_vs_eval_r1": flips,
            "accuracy_vs_truth": sum(r["pred"] == r["extra"]["truth"] for r in okr) / max(1, len(okr)),
            "calls": asker.totals, "models_seen": asker.models,
            "hashes": current_hashes(), "frozen_sha256": file_sha256(FROZEN),
            "note": "e2e (primary) = live sites+questions (tree-sitter, dell) + prune + the unit's Jev calls sent "
                    "concurrently (one thread per question) + derive (dell); sequential_s (secondary) = parse/prune "
                    "+ sum of the per-call latencies + derive (Intern-Decision L4-D was measured sequentially); "
                    "warm-up call excluded; latency includes retries"}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps({k: meta[k] for k in ("n_units", "n_ok", "aborted", "e2e_s", "sequential_s", "parse_prune_s",
                                           "per_call_s", "questions_per_unit", "max_abs_dp_vs_eval_r1",
                                           "verdict_flips_vs_eval_r1", "accuracy_vs_truth", "calls")}, indent=1))
    return 3 if asker.abort_reason or len(okr) != len(rows) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("answer")
    p.add_argument("--layer", choices=("layer1", "layer3"), required=True)
    p.add_argument("--set", choices=("dev", "eval"), required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--pilot", action="store_true", help=f"only the {PILOT_N} seeded pilot layer1 dev units")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--max-cost", type=float, required=True, help="per-run cap, USD")
    p = sub.add_parser("select")
    p.add_argument("--run-id", default="dev_r1")
    sub.add_parser("freeze")
    p = sub.add_parser("units")
    p.add_argument("--layer", default="layer3")
    p.add_argument("--run-id", default="eval_r1")
    p = sub.add_parser("latency")
    p.add_argument("--run-id", default="lat300_c1")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-cost", type=float, required=True, help="per-run cap, USD")
    args = ap.parse_args(argv)
    return {"answer": cmd_answer, "select": cmd_select, "freeze": cmd_freeze, "units": cmd_units,
            "latency": cmd_latency}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

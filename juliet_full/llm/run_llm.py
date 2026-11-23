#!/usr/bin/env python3
"""Run one model x strategy over a unit set and write predictions + meta (README section 4).

  python3 run_llm.py --model deepseek --strategy L1 --units ../data/build/layer1_sample.jsonl \
      --set dev --layer layer1 --concurrency 8 --max-cost 0.05

DeepSeek: refuses to start in Beijing peak hours and pauses if a peak window opens mid-run;
every call is appended to ledger.jsonl and checked against the per-run cap (--max-cost, CNY)
and the global hard stop (CNY 9.5). Jev: --max-cost in USD, global hard stop USD 4.0.
Exit codes: 0 finished, 2 refused to start, 3 aborted mid-run (remaining units status error).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR, PROJECT_ROOT, PROMPT_DIR  # noqa: E402
from llmlane import clients, l4  # noqa: E402
from llmlane.ledger import LEDGER_PATH, Budget, BudgetExceeded, Ledger  # noqa: E402
from llmlane.parse import parse_verdict  # noqa: E402
from llmlane.pricing import (  # noqa: E402
    DEEPSEEK_OFFPEAK_CNY_PER_M, DEEPSEEK_PEAK_MULTIPLIER, JEV_USD_PER_M_INPUT, PeakGate, PeakHours,
    deepseek_cost_cny, deepseek_estimate_cny, is_deepseek_peak, jev_cost_usd, jev_estimate_usd,
)
from llmlane.prompts import PromptAuditError, PromptSet  # noqa: E402
from llmlane.units import CLANG_EVIDENCE_TEMPLATE, SUBSETS_PATH, file_sha256, load_evidence, load_units, \
    select_units  # noqa: E402

METHOD = {"deepseek": "deepseek_flash", "qwen": "qwen3_5_4b", "jev": "jev"}
PAID = {"deepseek", "jev"}
L2_EXAMPLES_JSON = PROMPT_DIR / "l2_examples.json"
LOCK_PATH = LLM_DIR / "scratch" / "deepseek_run.lock"
# Prompt-set hashes frozen by the parent at commit 780ec1e (2026-11-23 11:08 PST). Eval runs refuse any other.
FROZEN_PROMPT_HASHES = {
    ("chat", "L1"): "ed8676d1c68c37b01b597d9662dda9e6fde961412ef84eb40a96e8d641ac25c3",
    ("chat", "L2"): "a932f4394ee0790969095dc9b8a993c20dcf4a7f5a017978781729765308cfc8",
    ("chat", "L3"): "1b4e5f65088efea1cfff841ca49470f717920fa26aed65d51050baa1d1ee32ae",
    ("jev", "L1"): "6de1c2a48b327b16b0e8f990f0a701a7647b923ff938965c943dfd40a9dc21ea",
    ("jev", "L2"): "b623ac7f8d24e75bce174b17d17678a15f7dde22b38da06b4cf15ff25ef69477",
    ("jev", "L3"): "668f6ef93cadf6915f39b9e0eb8a140a4646be2f360c4feff6c6006415c8c37a",
    # L4 v3c, frozen by the parent 2026-11-23 12:15 PST (l4/FREEZE_PROPOSAL.md).
    ("chat", "L4"): "00a81aa6fe372e612d3ea9430b11a7087b6c569a2ed8b0ecacf89958045365e6",
}
# The L4 verdict also depends on the Datalog rules and the fact parser; eval runs check them too.
FROZEN_L4_FILES = {
    "l4/leak.dl": "ee9cc78ed05b5c496a60e77b33f69584dc6bd58408e77dac2f8a76b3fb057dbc",
    "llmlane/l4.py": "22f3e53c49456df424c7c922af0b446a13f0c6d500f575605eb8f68320eeffff",
}
EVIDENCE_FROZEN_MARKER = "EVIDENCE_FROZEN"


def frozen_evidence(evidence_dir: Path) -> tuple[Path, dict[str, str]]:
    """Resolve the static lane's frozen L3 evidence: marker line `<run_id> <sha256>` -> <run_id>.evidence.jsonl.

    Raises ValueError when the marker is missing/malformed or the file hash differs from the marker."""
    marker = evidence_dir / EVIDENCE_FROZEN_MARKER
    if not marker.exists():
        raise ValueError(f"{marker} does not exist (evidence not frozen yet)")
    fields = marker.read_text().split()
    if len(fields) != 2:
        raise ValueError(f"{marker}: expected '<run_id> <sha256>', got {fields!r}")
    run_id, sha = fields
    path = marker.parent / f"{run_id}.evidence.jsonl"
    if not path.exists():
        raise ValueError(f"{path} named by {marker} does not exist")
    actual = file_sha256(path)
    if actual != sha:
        raise ValueError(f"{path}: sha256 {actual} != frozen {sha}")
    return path, {"marker": str(marker), "run_id": run_id, "sha256": sha}


def iso(ts: float | None = None) -> str:
    moment = datetime.now(timezone.utc) if ts is None else datetime.fromtimestamp(ts, timezone.utc)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def git_head() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(PROJECT_ROOT), "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=10).stdout.strip() or None
    except OSError:
        return None


def l2_example_groups() -> set[str]:
    """Groups of the L2 few-shot examples; both units of each group are near-identical code."""
    if not L2_EXAMPLES_JSON.exists():
        return set()
    return {e["group_id"] for e in json.loads(L2_EXAMPLES_JSON.read_text())["examples"]}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", required=True, choices=sorted(METHOD))
    p.add_argument("--strategy", required=True, choices=["L1", "L2", "L3", "L4"])
    p.add_argument("--units", required=True, type=Path)
    p.add_argument("--set", required=True, choices=["dev", "eval"])
    p.add_argument("--subset", help="key of data/build/subsets.json (group ids)")
    p.add_argument("--subsets-file", type=Path, default=SUBSETS_PATH)
    p.add_argument("--layer", default="layer1", choices=["layer1", "original", "stress", "placebo"])
    p.add_argument("--unit-ids", type=Path, help="file with one unit_id per line")
    p.add_argument("--limit", type=int, help="first N units in stratified round-robin order")
    p.add_argument("--keep-l2-examples", action="store_true",
                   help="do not drop the groups of the fixed L2 examples (both units dropped by default in every run)")
    p.add_argument("--evidence", type=Path, help="L3 evidence.jsonl (default: static/results/clang_sa/<layer>/)")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--max-cost", type=float, help="per-run cap: CNY for deepseek, USD for jev (required)")
    p.add_argument("--max-tokens", type=int)
    p.add_argument("--warmup-wait", type=float, default=5.0, help="seconds between warm-up request and burst")
    p.add_argument("--run-id")
    p.add_argument("--out-root", type=Path, default=LLM_DIR / "results")
    p.add_argument("--raw-root", type=Path, default=LLM_DIR / "raw_logs")
    p.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    p.add_argument("--base-url", help="override endpoint (qwen: vLLM base, e.g. a mock server)")
    p.add_argument("--no-json-mode", action="store_true", help="do not send response_format json_object")
    p.add_argument("--jev-long-context", action="store_true")
    p.add_argument("--allow-eval", action="store_true", help="parent only, after the prompt freeze")
    p.add_argument("--dry-run", action="store_true", help="build and audit prompts, estimate cost, no calls")
    return p.parse_args(argv)


class Run:
    def __init__(self, args: argparse.Namespace, prompt_set: PromptSet, run_id: str) -> None:
        self.args = args
        self.prompts = prompt_set
        self.run_id = run_id
        self.model_key = args.model
        self.method = METHOD[args.model]
        self.max_tokens = args.max_tokens or (512 if args.strategy == "L4" else 64)
        self.stop = threading.Event()
        self.abort_reason: str | None = None
        self.ledger = Ledger(args.ledger)
        self.budget: Budget | None = None
        self.gate: PeakGate | None = None
        self.client: Any = None
        self.raw_lock = threading.Lock()
        self.raw_path = args.raw_root / self.method / args.layer / f"{run_id}.jsonl"
        self.returned_models: dict[str, int] = {}
        self.totals = {"calls": 0, "prompt_tokens": 0, "cache_hit_tokens": 0, "cache_miss_tokens": 0,
                       "completion_tokens": 0, "input_tokens": 0, "cost": 0.0, "peak_calls": 0}
        self.totals_lock = threading.Lock()

    # ---- request construction -------------------------------------------------------
    def build(self, unit: dict[str, Any], evidence: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
        ev = evidence.get(unit["unit_id"]) if evidence is not None else None
        try:
            if self.model_key == "jev":
                state, info = self.prompts.jev_state(unit, ev)
                return {"unit": unit, "state": state, "chars": len(state), "info": info}
            messages, info = self.prompts.messages(unit, ev)
            return {"unit": unit, "messages": messages, "chars": sum(len(m["content"]) for m in messages),
                    "info": info}
        except PromptAuditError as exc:
            return {"unit": unit, "audit_error": str(exc), "chars": 0, "info": {}}

    # ---- one unit -------------------------------------------------------------------
    def record(self, unit: dict[str, Any], pred: Any, score: Any, latency: float, status: str,
               model: str | None, extra: dict[str, Any]) -> dict[str, Any]:
        return {"unit_id": unit["unit_id"], "method": self.method, "strategy": self.args.strategy,
                "model": model, "layer": self.args.layer, "pred": pred, "score": score,
                "latency_s": round(latency, 4), "status": status, "extra": extra}

    def not_run(self, req: dict[str, Any], reason: str) -> dict[str, Any]:
        return self.record(req["unit"], None, None, 0.0, "error", None, {"error": f"not_run: {reason}"})

    def abort(self, reason: str) -> None:
        if not self.stop.is_set():
            self.abort_reason = reason
            print(f"[run] ABORT: {reason}", flush=True)
        self.stop.set()

    def work(self, req: dict[str, Any]) -> dict[str, Any]:
        unit = req["unit"]
        if "audit_error" in req:
            return self.record(unit, None, None, 0.0, "error", None, {"error": f"prompt_audit: {req['audit_error']}"})
        if self.stop.is_set():
            return self.not_run(req, self.abort_reason or "stopped")
        if self.gate is not None:
            self.gate.wait_offpeak(self.stop)
            if self.stop.is_set():
                return self.not_run(req, self.abort_reason or "stopped")
        estimate = 0.0
        if self.budget is not None:
            estimate = (deepseek_estimate_cny(req["chars"], self.max_tokens) if self.model_key == "deepseek"
                        else jev_estimate_usd(req["chars"]))
            try:
                self.budget.reserve(estimate)
            except BudgetExceeded as exc:
                self.abort(str(exc))
                return self.not_run(req, "budget")
        result = None
        fatal = None
        try:
            if self.model_key == "jev":
                result = self.client.ask(req["state"], self.prompts.jev_question, stop=self.stop)
            else:
                result = self.client.complete(req["messages"], self.max_tokens, stop=self.stop)
        except clients.FatalApiError as exc:
            fatal = str(exc)
            result = exc.result
            self.abort(fatal)
        cost, peak = self.account(unit, result, estimate)
        if result is None:
            return self.record(unit, None, None, 0.0, "error", None, {"error": f"fatal: {fatal}"})
        self.write_raw(unit, req, result, fatal)
        extra: dict[str, Any] = {"usage": result.usage, "cost": cost, "http_status": result.http_status,
                                 "attempts": len(result.attempts), **req["info"]}
        if self.model_key == "deepseek":
            extra["peak_price"] = peak
        if result.error and result.status != "ok":
            extra["error"] = result.error
        if fatal:
            extra["error"] = f"fatal: {fatal}"
            return self.record(unit, None, None, result.latency_s, "error", result.model, extra)
        if result.status != "ok":
            return self.record(unit, None, None, result.latency_s, result.status, result.model, extra)
        if self.model_key == "jev":
            pred = 1 if result.score >= 0.5 else 0
            return self.record(unit, pred, result.score, result.latency_s, "ok", result.model, extra)
        extra["content"] = (result.content or "")[:300]
        extra["finish_reason"] = result.finish_reason
        if self.args.strategy == "L4":
            return self.finish_l4(unit, result, extra)
        verdict = parse_verdict(result.content)
        extra.update({"label_out": verdict.label, "confidence": verdict.confidence})
        if verdict.note:
            extra["parse_note"] = verdict.note
        return self.record(unit, verdict.pred, verdict.score, result.latency_s, verdict.status, result.model, extra)

    def finish_l4(self, unit: dict[str, Any], result: Any, extra: dict[str, Any]) -> dict[str, Any]:
        parsed = l4.parse_facts(result.content, unit["model_text"].rstrip())
        extra["content"] = (result.content or "")[:1500]
        extra.update({"n_facts": parsed.n_facts, "n_bad_lines": len(parsed.bad_lines),
                      "n_ungrounded": len(parsed.ungrounded), "facts_strict_ok": parsed.strict_ok,
                      "facts_none": parsed.said_none, "bad_lines": parsed.bad_lines[:5],
                      "ungrounded": parsed.ungrounded[:5]})
        if parsed.n_facts == 0 and not parsed.said_none:
            extra["parse_note"] = "no parseable facts"
            return self.record(unit, None, None, result.latency_s, "invalid", result.model, extra)
        derived = l4.run_souffle(parsed)
        extra.update({"souffle_status": derived.status, "souffle_s": round(derived.seconds, 4),
                      "leaks": [list(x) for x in derived.leaks]})
        latency = result.latency_s + derived.seconds
        if derived.status != "ok":
            extra["error"] = derived.error
            return self.record(unit, None, None, latency, "error", result.model, extra)
        return self.record(unit, 1 if derived.leaks else 0, None, latency, "ok", result.model, extra)

    def account(self, unit: dict[str, Any], result: Any, estimate: float) -> tuple[float, bool]:
        usage = result.usage if result is not None else None
        peak = False
        cost = 0.0
        if result is not None:
            peak = any(is_deepseek_peak(datetime.fromtimestamp(t, timezone.utc))
                       for t in (result.started_utc, result.ended_utc) if t)
        if self.model_key == "deepseek":
            cost = deepseek_cost_cny(usage, peak)
        elif self.model_key == "jev":
            cost = jev_cost_usd(usage)
        if self.budget is not None:
            self.budget.settle(estimate, cost)
        with self.totals_lock:
            if result is not None:
                self.totals["calls"] += 1
                if result.model:
                    self.returned_models[result.model] = self.returned_models.get(result.model, 0) + 1
            if usage:
                self.totals["prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
                self.totals["cache_hit_tokens"] += int(usage.get("prompt_cache_hit_tokens") or 0)
                self.totals["cache_miss_tokens"] += int(usage.get("prompt_cache_miss_tokens") or 0)
                self.totals["completion_tokens"] += int(usage.get("completion_tokens") or 0)
                self.totals["input_tokens"] += int(usage.get("input_tokens") or 0)
            self.totals["cost"] += cost
            self.totals["peak_calls"] += int(peak)
        if self.model_key in PAID and result is not None:
            self.ledger.append({
                "kind": "call", "ts_utc": iso(result.ended_utc or None), "run_id": self.run_id,
                "provider": self.model_key, "model_requested": self.client.model, "model_returned": result.model,
                "strategy": self.args.strategy, "set": self.args.set, "layer": self.args.layer,
                "unit_id": unit["unit_id"], "status": result.status, "http_status": result.http_status,
                "attempts": len(result.attempts), "usage": usage, "peak_price": peak if self.model_key == "deepseek" else None,
                "cost": round(cost, 10), "currency": "CNY" if self.model_key == "deepseek" else "USD",
            })
        return cost, peak

    def write_raw(self, unit: dict[str, Any], req: dict[str, Any], result: Any, fatal: str | None) -> None:
        entry = {"unit_id": unit["unit_id"], "status": result.status, "error": result.error, "fatal": fatal,
                 "latency_s": result.latency_s, "attempts": result.attempts, "raw": result.raw,
                 "started_utc": iso(result.started_utc), "ended_utc": iso(result.ended_utc)}
        with self.raw_lock:
            self.raw_path.parent.mkdir(parents=True, exist_ok=True)
            with self.raw_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.set == "eval" and args.model in PAID and not args.allow_eval and not args.dry_run:
        print("refused: eval-set API calls need --allow-eval (parent only, after the prompt freeze)")
        return 2
    if args.model in PAID and args.max_cost is None and not args.dry_run:
        print("refused: --max-cost is required for paid models")
        return 2
    target = "jev" if args.model == "jev" else "chat"
    prompt_set = PromptSet(args.strategy, target)
    if args.set == "eval":
        frozen = FROZEN_PROMPT_HASHES.get((target, args.strategy))
        if frozen is None:
            print(f"refused: no frozen {target} {args.strategy} prompt; eval runs need a frozen prompt set")
            return 2
        if prompt_set.prompt_hash != frozen:
            print(f"refused: {target} {args.strategy} prompt hash {prompt_set.prompt_hash} != frozen {frozen}")
            return 2
        if args.strategy == "L4":
            import hashlib
            here = Path(__file__).resolve().parent
            for rel, want in FROZEN_L4_FILES.items():
                got = hashlib.sha256((here / rel).read_bytes()).hexdigest()
                if got != want:
                    print(f"refused: {rel} sha256 {got} != frozen {want}")
                    return 2
    units = load_units(args.units)
    unit_ids = None
    if args.unit_ids:
        unit_ids = [x.strip() for x in args.unit_ids.read_text().splitlines() if x.strip()]
    example_groups = set() if args.keep_l2_examples else l2_example_groups()
    excluded = {u["unit_id"] for u in units if u["group_id"] in example_groups}
    selected = select_units(units, args.set, args.subset, args.subsets_file, unit_ids, args.limit, excluded)
    if not selected:
        print("no units selected")
        return 2
    evidence = None
    evidence_path = None
    evidence_frozen = None
    if args.strategy == "L3":
        if args.evidence:
            if args.set == "eval":
                print("refused: eval L3 runs use the frozen evidence (EVIDENCE_FROZEN), not --evidence")
                return 2
            evidence_path = args.evidence
        else:
            try:
                evidence_path, evidence_frozen = frozen_evidence(Path(str(CLANG_EVIDENCE_TEMPLATE).format(layer=args.layer)).parent)
            except ValueError as exc:
                print(f"refused: {exc}")
                return 2
        evidence = load_evidence(evidence_path)
        missing = sum(u["unit_id"] not in evidence for u in selected)
        if missing and args.set == "eval":
            print(f"refused: frozen evidence lacks {missing} of the selected units")
            return 2

    started = time.time()
    run_id = args.run_id or f"{args.strategy}_{args.set}{'_' + args.subset if args.subset else ''}_" \
                            f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    run = Run(args, prompt_set, run_id)
    requests = [run.build(u, evidence) for u in selected]
    n_audit = sum("audit_error" in r for r in requests)
    est = sum((deepseek_estimate_cny(r["chars"], run.max_tokens) / DEEPSEEK_PEAK_MULTIPLIER) for r in requests)
    print(f"[run] {run_id}: {len(requests)} units, prompt audit failures {n_audit}, "
          f"prompt chars median {sorted(r['chars'] for r in requests)[len(requests) // 2]}, "
          f"no-cache off-peak DeepSeek upper estimate CNY {est:.4f}", flush=True)
    if args.dry_run:
        return 0

    lock_handle = None
    balance_before = balance_after = None
    models_listing = None
    if args.model == "deepseek":
        run.gate = PeakGate()
        try:
            run.gate.check_start()
        except PeakHours as exc:
            print(f"refused: {exc}")
            return 2
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock_handle = LOCK_PATH.open("w")
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("refused: another DeepSeek run holds the lock")
            return 2
        run.client = clients.deepseek_client()
        balance_before = clients.deepseek_balance()
        run.ledger.append({"kind": "balance", "ts_utc": iso(), "run_id": run_id, "provider": "deepseek",
                           "when": "before", "balance": balance_before})
    elif args.model == "jev":
        run.client = clients.JevClient(long_context=args.jev_long_context)
        status, payload = run.client.list_models()
        models_listing = payload if status == 200 else {"http_status": status}
    else:
        run.client = clients.qwen_client(args.base_url or clients.QWEN_BASE,
                                         response_format_json=not args.no_json_mode)
        try:
            status, payload = run.client.list_models()
        except OSError as exc:
            print(f"refused: qwen endpoint unreachable: {exc}")
            return 2
        if status != 200:
            print(f"refused: qwen endpoint /models returned {status}")
            return 2
        models_listing = payload
    if args.model in PAID:
        spent = run.ledger.spent(args.model)
        run.budget = Budget(args.model, args.max_cost, spent)
        print(f"[run] ledger spend so far ({args.model}): {spent:.6f} {run.budget.currency}; "
              f"run cap {args.max_cost}; global stop {run.budget.global_cap}", flush=True)
    if args.model != "jev" and (args.no_json_mode or args.strategy == "L4"):
        # L4 answers with fact lines, not JSON; DeepSeek rejects json_object mode (HTTP 400) when
        # the prompt never mentions JSON.
        run.client.response_format_json = False

    load_start = os.getloadavg()
    records: list[dict[str, Any] | None] = [None] * len(requests)
    done = 0
    try:
        first = 0
        if len(requests) > 1 and args.model != "jev":
            while first < len(requests) and "audit_error" in requests[first]:
                records[first] = run.work(requests[first])
                first += 1
            if first < len(requests):
                records[first] = run.work(requests[first])
                first += 1
                time.sleep(args.warmup_wait)
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            futures = {pool.submit(run.work, requests[i]): i for i in range(first, len(requests))}
            for future in as_completed(futures):
                records[futures[future]] = future.result()
                done += 1
                if done % 20 == 0:
                    print(f"[run] {done + first}/{len(requests)} done; cost so far "
                          f"{run.totals['cost']:.6f}", flush=True)
    except KeyboardInterrupt:
        run.abort("interrupted")
    records = [r if r is not None else run.not_run(requests[i], run.abort_reason or "interrupted")
               for i, r in enumerate(records)]

    if args.model == "deepseek":
        balance_after = clients.deepseek_balance()
        run.ledger.append({"kind": "balance", "ts_utc": iso(), "run_id": run_id, "provider": "deepseek",
                           "when": "after", "balance": balance_after})
    ended = time.time()
    out_dir = args.out_root / run.method / args.layer
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / f"{run_id}.jsonl"
    with pred_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    statuses: dict[str, int] = {}
    for record in records:
        statuses[record["status"]] = statuses.get(record["status"], 0) + 1
    n_calls = max(1, run.totals["calls"])
    meta = {
        "run_id": run_id, "method": run.method, "strategy": args.strategy, "layer": args.layer,
        "set": args.set, "subset": args.subset, "n_units": len(records), "status_counts": statuses,
        "aborted": run.abort_reason,
        "model_requested": run.client.model, "models_returned": run.returned_models,
        "models_listing": models_listing, "client": run.client.public_config(), "max_tokens": run.max_tokens,
        "prompt_hash": prompt_set.prompt_hash, "prompt_files": prompt_set.files,
        "l2_examples_excluded": sorted(excluded),
        "l2_examples_json_sha256": file_sha256(L2_EXAMPLES_JSON) if L2_EXAMPLES_JSON.exists() else None,
        "units_file": str(args.units.resolve()), "units_sha256": file_sha256(args.units),
        "selection": {"limit": args.limit, "unit_ids_file": str(args.unit_ids) if args.unit_ids else None},
        "evidence_file": str(evidence_path) if evidence_path else None,
        "evidence_sha256": file_sha256(evidence_path) if evidence_path else None,
        "evidence_frozen": evidence_frozen,
        "start_utc": iso(started), "end_utc": iso(ended), "wall_s": round(ended - started, 2),
        "host": socket.gethostname(), "concurrency": args.concurrency, "warmup_wait_s": args.warmup_wait,
        "loadavg_start": load_start, "loadavg_end": os.getloadavg(), "git_head": git_head(),
        "usage_totals": {k: v for k, v in run.totals.items() if k != "cost"},
        "cost_total": round(run.totals["cost"], 8),
        "cost_currency": {"deepseek": "CNY", "jev": "USD"}.get(args.model),
        "cost_per_call": round(run.totals["cost"] / n_calls, 8),
        "prices": {"deepseek": {"offpeak_cny_per_m": DEEPSEEK_OFFPEAK_CNY_PER_M,
                                "peak_multiplier": DEEPSEEK_PEAK_MULTIPLIER},
                   "jev": {"usd_per_m_input": JEV_USD_PER_M_INPUT}}.get(args.model),
        "peak_pause_s": run.gate.paused_seconds if run.gate else None,
        "balance_before": balance_before, "balance_after": balance_after,
        "ledger_total_after": run.ledger.spent(args.model) if args.model in PAID else None,
        "souffle": l4.souffle_version() if args.strategy == "L4" else None,
        "raw_log": str(run.raw_path),
    }
    pred_path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    if lock_handle is not None:
        lock_handle.close()
    print(f"[run] wrote {pred_path} ({statuses}); cost {meta['cost_total']} {meta['cost_currency']}", flush=True)
    return 3 if run.abort_reason else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Intern-Decision-4B zero-shot runs against the /decide service (gpu/server/decide_server.py).

The state is exactly the frozen Jev state of the LLM lane (llm/llmlane/prompts.py, target "jev": task.txt
[+ l2_examples.txt] + filled user_L1/user_L3 template; L3 evidence = the static lane's EVIDENCE_FROZEN file of
the layer). The Jev noul question (llm/prompts/jev_question.json) is sent as Intern-Decision's own noul
question (values no, yes; criteria false/true pass through), field name "leak" as in the Jev client.
score = calibrated P(yes) = P(leak); pred = score >= 0.5 (primary threshold).

Units of the four L2 example groups are dropped in every run, as llm/run_llm.py does.
Eval-set runs refuse to start unless gpu/results/intern_decision/FROZEN exists and its template hash for the
strategy equals the current one.

  run_decide.py run --units ../data/build/layer1.jsonl --set dev --strategy L1 --run-id dev_L1_r1
  run_decide.py freeze --dev-runs dev_L1_r1 dev_L2_r1 dev_L3_r1      # secondary thresholds, writes FROZEN
  run_decide.py score --units ../data/build/layer1.jsonl --preds results/intern_decision/layer1/eval_L1_r1.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import bisect
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

GPU_DIR = Path(__file__).resolve().parent
JULIET_FULL = GPU_DIR.parent
sys.path.insert(0, str(JULIET_FULL / "llm"))
sys.path.insert(0, str(JULIET_FULL / "analysis"))
from llmlane.prompts import PromptAuditError, PromptSet, sha256_text  # noqa: E402
from llmlane.units import CLANG_EVIDENCE_TEMPLATE, file_sha256, load_evidence, load_units, select_units  # noqa: E402
from run_llm import FROZEN_PROMPT_HASHES, L2_EXAMPLES_JSON, frozen_evidence, l2_example_groups  # noqa: E402
from score import confusion, metrics_from_counts  # noqa: E402

METHOD = "intern_decision"
MODEL = "Intern-Decision-4B"
FIELD_NAME = "leak"
RESULTS = GPU_DIR / "results" / METHOD
FROZEN_PATH = RESULTS / "FROZEN"
DEFAULT_ENDPOINT = "http://10.15.89.184:8002"
PRIMARY_THRESHOLD = 0.5
SERVER_FILE = GPU_DIR / "server" / "decide_server.py"


def iso(ts: float | None = None) -> str:
    moment = datetime.now(timezone.utc) if ts is None else datetime.fromtimestamp(ts, timezone.utc)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def request_body(prompts: PromptSet, state: str) -> dict[str, Any]:
    question = prompts.jev_question
    return {"state": state, "question": question["instructions"], "type": question["type"],
            "options": question.get("criteria"), "name": FIELD_NAME}


def template_hash(prompts: PromptSet) -> str:
    """Hash of everything but the unit: frozen Jev prompt-set hash + the /decide request template."""
    template = request_body(prompts, "{state}")
    return sha256_text(json.dumps({"jev_prompt_hash": prompts.prompt_hash, "request": template}, sort_keys=True))


class DecideClient:
    """One keep-alive HTTP connection per thread."""

    def __init__(self, endpoint: str, timeout: float = 120.0) -> None:
        url = urlparse(endpoint)
        self.host, self.port, self.timeout = url.hostname, url.port or 80, timeout
        self.local = threading.local()

    def _conn(self) -> http.client.HTTPConnection:
        if getattr(self.local, "conn", None) is None:
            self.local.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        return self.local.conn

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(3):
            conn = self._conn()
            try:
                conn.request(method, path, body=data, headers={"Content-Type": "application/json"})
                resp = conn.getresponse()
                payload = resp.read()
                return resp.status, json.loads(payload) if payload else None
            except (OSError, http.client.HTTPException):
                conn.close()
                self.local.conn = None
                if attempt == 2:
                    raise
                time.sleep(1.0 + attempt)
        raise AssertionError("unreachable")


def cmd_run(args: argparse.Namespace) -> int:
    prompts = PromptSet(args.strategy, "jev")
    if prompts.prompt_hash != FROZEN_PROMPT_HASHES[("jev", args.strategy)]:
        print(f"refused: jev {args.strategy} prompt hash {prompts.prompt_hash} != frozen")
        return 2
    t_hash = template_hash(prompts)
    frozen = None
    if args.set == "eval":
        if not FROZEN_PATH.exists():
            print(f"refused: eval runs need {FROZEN_PATH} (run `freeze` on the dev runs first)")
            return 2
        frozen = json.loads(FROZEN_PATH.read_text())
        if frozen["strategies"][args.strategy]["template_sha256"] != t_hash:
            print(f"refused: {args.strategy} template hash {t_hash} != FROZEN")
            return 2
    units = load_units(args.units)
    unit_ids = None
    if args.unit_ids:
        unit_ids = [x.strip() for x in args.unit_ids.read_text().splitlines() if x.strip()]
    example_groups = l2_example_groups()
    excluded = {u["unit_id"] for u in units if u["group_id"] in example_groups}
    selected = select_units(units, args.set, args.subset, unit_ids=unit_ids, limit=args.limit,
                            exclude_unit_ids=excluded)
    if not selected:
        print("no units selected")
        return 2
    evidence = evidence_path = evidence_frozen = None
    if args.strategy == "L3":
        evidence_path, evidence_frozen = frozen_evidence(
            Path(str(CLANG_EVIDENCE_TEMPLATE).format(layer=args.layer)).parent)
        evidence = load_evidence(evidence_path)
        missing = sum(u["unit_id"] not in evidence for u in selected)
        if missing:
            print(f"refused: frozen evidence lacks {missing} of the selected units")
            return 2
    requests = []
    for unit in selected:
        try:
            state, info = prompts.jev_state(unit, evidence.get(unit["unit_id"]) if evidence is not None else None)
            requests.append((unit, request_body(prompts, state), info))
        except PromptAuditError as exc:
            requests.append((unit, None, {"error": f"prompt_audit: {exc}"}))

    client = DecideClient(args.endpoint)
    status, health = client.call("GET", "/health")
    if status != 200:
        print(f"refused: {args.endpoint}/health returned {status}")
        return 2
    threshold2 = frozen["strategies"][args.strategy]["threshold_secondary"] if frozen else None
    temperatures: set[float] = set()

    def work(item: tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]) -> dict[str, Any]:
        unit, body, info = item
        base = {"unit_id": unit["unit_id"], "method": METHOD, "strategy": args.strategy, "model": None,
                "layer": args.layer}
        if body is None:
            return {**base, "pred": None, "score": None, "latency_s": 0.0, "status": "error", "extra": info}
        start = time.perf_counter()
        try:
            code, payload = client.call("POST", "/decide", body)
        except (OSError, http.client.HTTPException) as exc:
            return {**base, "pred": None, "score": None, "latency_s": round(time.perf_counter() - start, 4),
                    "status": "error", "extra": {**info, "error": repr(exc)}}
        latency = time.perf_counter() - start
        if code != 200:
            return {**base, "pred": None, "score": None, "latency_s": round(latency, 4), "status": "error",
                    "extra": {**info, "error": f"http {code}: {str(payload)[:300]}"}}
        score = float(payload["probs"]["yes"])
        temperatures.add(payload["temperature"])
        extra = {**info, "p_raw": payload["probs_raw"]["yes"], "input_tokens": payload["input_tokens"],
                 "forward_ms": payload["forward_ms"], "latency_ms_server": payload["latency_ms_server"]}
        if threshold2 is not None:
            extra["pred_secondary"] = int(score >= threshold2)
        return {**base, "model": payload["model"], "pred": int(score >= PRIMARY_THRESHOLD), "score": score,
                "latency_s": round(latency, 4), "status": "ok", "extra": extra}

    run_id = args.run_id
    out = RESULTS / args.layer / f"{run_id}.jsonl"
    if out.exists() and not args.overwrite:
        print(f"refused: {out} exists")
        return 2
    print(f"[decide] {run_id}: {len(requests)} units ({args.layer} {args.set} {args.strategy}), "
          f"concurrency {args.concurrency}", flush=True)
    load_start = os.getloadavg()
    started = time.time()
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        for i, record in enumerate(pool.map(work, requests), 1):
            records.append(record)
            if i % 250 == 0:
                print(f"[decide] {i}/{len(requests)}", flush=True)
    ended = time.time()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    statuses: dict[str, int] = {}
    for record in records:
        statuses[record["status"]] = statuses.get(record["status"], 0) + 1
    meta = {
        "run_id": run_id, "method": METHOD, "model": MODEL, "strategy": args.strategy, "layer": args.layer,
        "set": args.set, "subset": args.subset, "n_units": len(records), "status_counts": statuses,
        "endpoint": args.endpoint, "server_health": health, "server_file_sha256": file_sha256(SERVER_FILE),
        "server_calibration_temperature": sorted(temperatures),
        "prompt_target": "jev", "prompt_hash": prompts.prompt_hash, "prompt_files": prompts.files,
        "template_sha256": t_hash, "request_template": request_body(prompts, "{state}"),
        "threshold_primary": PRIMARY_THRESHOLD, "threshold_secondary": threshold2,
        "frozen_file_sha256": file_sha256(FROZEN_PATH) if frozen else None,
        "l2_examples_excluded": sorted(excluded),
        "l2_examples_json_sha256": file_sha256(L2_EXAMPLES_JSON),
        "units_file": str(args.units.resolve()), "units_sha256": file_sha256(args.units),
        "selection": {"limit": args.limit, "unit_ids_file": str(args.unit_ids) if args.unit_ids else None},
        "evidence_file": str(evidence_path) if evidence_path else None, "evidence_frozen": evidence_frozen,
        "start_utc": iso(started), "end_utc": iso(ended), "wall_s": round(ended - started, 2),
        "host": socket.gethostname(), "concurrency": args.concurrency,
        "loadavg_start": load_start, "loadavg_end": os.getloadavg(),
        "latency_note": "latency_s = dell wall time per request incl. queueing behind the other worker "
                        "(server serialises forwards); use the concurrency-1 latency300 run for latency",
    }
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    print(f"[decide] wrote {out} {statuses} in {meta['wall_s']} s", flush=True)
    return 0


# ---- scoring / threshold freeze -------------------------------------------------------------------
def auroc(pairs: list[tuple[int, float]]) -> float | None:
    """Mann-Whitney AUROC with ties counted 1/2."""
    pos = sorted(s for t, s in pairs if t == 1)
    neg = sorted(s for t, s in pairs if t == 0)
    if not pos or not neg:
        return None
    total = 0.0
    for s in pos:
        lo, hi = bisect.bisect_left(neg, s), bisect.bisect_right(neg, s)
        total += lo + 0.5 * (hi - lo)
    return total / (len(pos) * len(neg))


def macro_f1_at(pairs: list[tuple[int, float | None]], threshold: float) -> float:
    m = metrics_from_counts(confusion([(t, None if s is None else int(s >= threshold)) for t, s in pairs]))
    return m["macro_f1"] or 0.0


def best_threshold(pairs: list[tuple[int, float | None]]) -> tuple[float, float]:
    """Threshold maximising macro-F1; candidates are midpoints of adjacent distinct scores; ties -> nearest 0.5."""
    scores = sorted({s for _, s in pairs if s is not None})
    candidates = [PRIMARY_THRESHOLD] + [(a + b) / 2 for a, b in zip(scores, scores[1:])]
    best = max(candidates, key=lambda th: (round(macro_f1_at(pairs, th), 12), -abs(th - PRIMARY_THRESHOLD)))
    return best, macro_f1_at(pairs, best)


def truth_pairs(units_path: Path, preds_path: Path) -> list[tuple[int, float | None]]:
    truth = {u["unit_id"]: int(u["truth"]) for u in load_units(units_path)}
    rows = [json.loads(line) for line in preds_path.read_text().splitlines() if line.strip()]
    return [(truth[r["unit_id"]], r["score"] if r["status"] == "ok" else None) for r in rows]


def summary(pairs: list[tuple[int, float | None]], thresholds: dict[str, float]) -> dict[str, Any]:
    out: dict[str, Any] = {"n": len(pairs), "auroc": auroc([(t, s) for t, s in pairs if s is not None])}
    for name, th in thresholds.items():
        m = metrics_from_counts(confusion([(t, None if s is None else int(s >= th)) for t, s in pairs]))
        out[name] = {"threshold": th, **{k: m[k] for k in ("macro_f1", "f1_leak", "precision_leak", "recall_leak",
                                                           "specificity", "accuracy", "mcc", "tp", "fn", "fp",
                                                           "tn", "invalid")}}
    return out


def cmd_freeze(args: argparse.Namespace) -> int:
    if FROZEN_PATH.exists():
        print(f"refused: {FROZEN_PATH} exists")
        return 2
    strategies = {}
    for run_id in args.dev_runs:
        path = RESULTS / "layer1" / f"{run_id}.jsonl"
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        if meta["set"] != "dev" or meta["layer"] != "layer1":
            print(f"refused: {run_id} is not a layer1 dev run")
            return 2
        pairs = truth_pairs(Path(meta["units_file"]), path)
        th, mf1 = best_threshold(pairs)
        strategies[meta["strategy"]] = {
            "prompt_hash": meta["prompt_hash"], "template_sha256": meta["template_sha256"],
            "threshold_primary": PRIMARY_THRESHOLD, "threshold_secondary": th,
            "dev_run": run_id, "dev_run_sha256": file_sha256(path), "dev_n": len(pairs),
            "dev_macro_f1_primary": macro_f1_at(pairs, PRIMARY_THRESHOLD), "dev_macro_f1_secondary": mf1,
            "dev_auroc": auroc([(t, s) for t, s in pairs if s is not None])}
    frozen = {"method": METHOD, "model": MODEL, "frozen_utc": iso(), "server_file_sha256": file_sha256(SERVER_FILE),
              "selection_rule": "secondary threshold = argmax dev macro-F1 over midpoints of distinct dev scores "
                                "(ties -> nearest 0.5); primary threshold 0.5",
              "strategies": strategies}
    FROZEN_PATH.write_text(json.dumps(frozen, indent=2) + "\n")
    print(json.dumps(frozen, indent=2))
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    frozen = json.loads(FROZEN_PATH.read_text()) if FROZEN_PATH.exists() else None
    for preds in args.preds:
        meta = json.loads(preds.with_suffix(".meta.json").read_text())
        thresholds = {"primary": PRIMARY_THRESHOLD}
        if frozen and meta["strategy"] in frozen["strategies"]:
            thresholds["secondary"] = frozen["strategies"][meta["strategy"]]["threshold_secondary"]
        result = summary(truth_pairs(args.units, preds), thresholds)
        print(json.dumps({"preds": str(preds), "layer": meta["layer"], "set": meta["set"],
                          "strategy": meta["strategy"], **result}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--units", required=True, type=Path)
    r.add_argument("--set", required=True, choices=["dev", "eval"])
    r.add_argument("--strategy", required=True, choices=["L1", "L2", "L3"])
    r.add_argument("--layer", default="layer1", choices=["layer1", "layer3", "placebo", "original"])
    r.add_argument("--subset")
    r.add_argument("--unit-ids", type=Path)
    r.add_argument("--limit", type=int)
    r.add_argument("--run-id", required=True)
    r.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    r.add_argument("--concurrency", type=int, default=2)
    r.add_argument("--overwrite", action="store_true")
    f = sub.add_parser("freeze")
    f.add_argument("--dev-runs", nargs="+", required=True)
    s = sub.add_parser("score")
    s.add_argument("--units", required=True, type=Path)
    s.add_argument("--preds", nargs="+", required=True, type=Path)
    args = ap.parse_args(argv)
    return {"run": cmd_run, "freeze": cmd_freeze, "score": cmd_score}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

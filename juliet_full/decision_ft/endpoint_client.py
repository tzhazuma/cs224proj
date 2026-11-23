"""dell-side client for the decision_ft endpoint http://10.15.89.184:8003 (README section 10).

  python3 endpoint_client.py check
      spot check: 20 layer-1 held-out units (from all six fold models) + 2 dev units are sent with their model_text and frozen
      Clang evidence; the endpoint score must match the stored merged prediction (|delta| < 1e-3) and its
      prompt_sha256 must equal the sha256 of the rendered training-template text in data/. -> runs/endpoint/spot_check.json
  flock /tmp/cs224_latency.lock python3 endpoint_client.py latency
      concurrency-1 latency on the latency300 eval units (subsets.json, 150 groups = 300 units), L1 and L3, requests
      grouped by fold model with 5 warm-up requests per model; waits (max 20 min) for load1 < 2.5 after getting the
      lock, else measures anyway and labels the run under_load.
      -> results/decision_ft/layer1/latency300_<strategy>_v1.jsonl (+ .meta.json)
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILD = HERE.parent / "data" / "build"
EVIDENCE = HERE.parent / "static" / "results" / "clang_sa" / "layer1" / "full_v2.evidence.jsonl"  # EVIDENCE_FROZEN
URL = os.environ.get("DFT_URL", "http://10.15.89.184:8003")
RESULTS = HERE / "results" / "decision_ft" / "layer1"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def post(payload: dict) -> tuple[dict, float]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(URL + "/score", data=data, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.loads(resp.read())
    return out, time.perf_counter() - t0


def load_inputs():
    units = {u["unit_id"]: u for u in read_jsonl(BUILD / "layer1.jsonl")}
    evidence = {r["unit_id"]: r for r in read_jsonl(EVIDENCE)}
    return units, evidence


def request_for(unit: dict, evidence: dict, strategy: str, fold: int | None = None) -> dict:
    """fold = the fold model; default = the unit's own fold (held-out model of an eval unit)."""
    return {"code": unit["model_text"], "language": unit["language"], "strategy": strategy,
            "evidence": evidence[unit["unit_id"]]["warnings"] if strategy == "L3" else None,
            "model": f"qwen3.5-4b-lora-{strategy}-fold{unit['fold'] if fold is None else fold}"}


def cmd_check() -> None:
    units, evidence = load_inputs()
    picks = []
    for i, (strategy, fold) in enumerate([(s, k) for s in ("L1", "L3") for k in (0, 1, 2)]):
        merged = sorted(read_jsonl(RESULTS / f"{strategy}_fold{fold}_v1.jsonl"), key=lambda r: r["unit_id"])
        texts = {r["unit_id"]: r["text"] for r in read_jsonl(HERE / "data" / strategy / f"fold{fold}" / "pred.jsonl")}
        n = 4 if i < 2 else 3  # 4 + 4 + 3 * 4 = 20
        step = len(merged) // n
        picks += [(strategy, fold, "eval_heldout", r, texts[r["unit_id"]]) for r in merged[step // 2::step][:n]]
    # plus 2 dev units (one bad, one good) against the stored merged dev predictions (L1 fold 1, L3 fold 2)
    for strategy, fold in (("L1", 1), ("L3", 2)):
        dev = sorted(read_jsonl(RESULTS / f"dev_{strategy}_fold{fold}_v1.jsonl"), key=lambda r: r["unit_id"])
        texts = {r["unit_id"]: r["text"] for r in read_jsonl(HERE / "data" / strategy / f"fold{fold}" / "dev.jsonl")}
        ref = next(r for r in dev if units[r["unit_id"]]["truth"] == (1 if strategy == "L1" else 0))
        picks.append((strategy, fold, "dev", ref, texts[ref["unit_id"]]))
    rows = []
    for strategy, fold, split, ref, text in picks:
        out, wall = post(request_for(units[ref["unit_id"]], evidence, strategy, fold))
        rows.append({"unit_id": ref["unit_id"], "split": split, "model": out["model"], "score_endpoint": out["score"],
                     "score_merged_prediction": ref["score"], "abs_delta": abs(out["score"] - ref["score"]),
                     "pred_endpoint": out["pred"], "pred_merged_prediction": ref["pred"],
                     "prompt_sha256_match": out["prompt_sha256"] == hashlib.sha256(text.encode()).hexdigest(),
                     "n_tokens": out["n_tokens"], "switch_ms": out["switch_ms"], "wall_s": wall})
    summary = {"utc": utc_now(), "url": URL, "n": len(rows), "max_abs_delta": max(r["abs_delta"] for r in rows),
               "all_prompts_match": all(r["prompt_sha256_match"] for r in rows),
               "all_preds_match": all(r["pred_endpoint"] == r["pred_merged_prediction"] for r in rows),
               "pass": all(r["abs_delta"] < 1e-3 and r["prompt_sha256_match"] for r in rows), "rows": rows}
    out_path = HERE / "runs" / "endpoint" / "spot_check.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=1))


def cmd_latency() -> None:
    units, evidence = load_inputs()
    groups = set(json.loads((BUILD / "subsets.json").read_text())["latency300"])
    chosen = sorted((u for u in units.values() if u["group_id"] in groups), key=lambda u: (u["fold"], u["unit_id"]))
    assert len(chosen) == 300 and all(u["set"] == "eval" for u in chosen)
    lock_utc, load_lock = utc_now(), os.getloadavg()
    waited, deadline = 0.0, time.time() + 20 * 60
    while os.getloadavg()[0] >= 2.5 and time.time() < deadline:
        time.sleep(15)
        waited += 15
    load_start = os.getloadavg()
    under_load = load_start[0] >= 2.5
    for strategy in ("L1", "L3"):
        start = utc_now()
        load_s = os.getloadavg()
        rows = []
        for fold in (0, 1, 2):
            fold_units = [u for u in chosen if u["fold"] == fold]
            for u in fold_units[:5]:  # warm-up: model switch + JIT, not recorded
                post(request_for(u, evidence, strategy))
            for u in fold_units:
                out, wall = post(request_for(u, evidence, strategy))
                assert out["switch_ms"] == 0.0, out
                rows.append({"unit_id": u["unit_id"], "method": "decision_ft", "strategy": strategy,
                             "model": out["model"], "layer": "layer1", "pred": out["pred"], "score": out["score"],
                             "latency_s": wall, "status": "ok",
                             "extra": {"fold": fold, "checkpoint": out["checkpoint"], "threshold": out["threshold"],
                                       "server_latency_s": out["latency_ms_server"] / 1000,
                                       "server_forward_s": out["forward_ms"] / 1000, "n_tokens": out["n_tokens"],
                                       "endpoint": URL, "under_load": under_load}})
        load_e = os.getloadavg()
        path = RESULTS / f"latency300_{strategy}_v1.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))

        def median(key):
            v = sorted(key(r) for r in rows)
            return v[len(v) // 2]

        def p90(key):
            v = sorted(key(r) for r in rows)
            return v[int(0.9 * (len(v) - 1))]
        meta = {"method": "decision_ft", "strategy": strategy, "layer": "layer1", "run_id": path.stem,
                "subset": "latency300", "n_units": len(rows), "endpoint": URL, "host": socket.gethostname(),
                "concurrency": 1, "grouping": "requests grouped by fold model, 5 warm-up requests per model",
                "lock": "/tmp/cs224_latency.lock (flock)", "lock_acquired_utc": lock_utc,
                "loadavg_at_lock": load_lock, "quiet_wait_s": waited, "quiet_rule": "load1 < 2.5, wait <= 20 min",
                "under_load": under_load, "start_utc": start, "end_utc": utc_now(),
                "loadavg_start": load_s, "loadavg_end": load_e,
                "latency_note": "latency_s = end-to-end on dell (JSON request over LAN + server render/tokenise + "
                                "forward); extra.server_latency_s = server handler time (render + tokenise + "
                                "forward), extra.server_forward_s = GPU forward only",
                "median_s": {"end_to_end": median(lambda r: r["latency_s"]),
                             "server": median(lambda r: r["extra"]["server_latency_s"]),
                             "server_forward": median(lambda r: r["extra"]["server_forward_s"])},
                "p90_s": {"end_to_end": p90(lambda r: r["latency_s"]),
                          "server": p90(lambda r: r["extra"]["server_latency_s"]),
                          "server_forward": p90(lambda r: r["extra"]["server_forward_s"])}}
        path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        print(json.dumps({k: meta[k] for k in ("run_id", "under_load", "loadavg_start", "loadavg_end",
                                                "median_s", "p90_s")}), flush=True)


if __name__ == "__main__":
    {"check": cmd_check, "latency": cmd_latency}[sys.argv[1]]()

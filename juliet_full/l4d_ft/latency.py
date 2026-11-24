"""End-to-end L4-D latency from dell, concurrency 1 (contract l4d/README.md section 5; lane l4d-train).

    flock /tmp/cs224_latency.lock ../l4d/.venv/bin/python latency.py --url http://10.15.89.184:8004 [--run-id lat300_c1]

Units: layer1 latency300 (data/build/subsets.json key latency300 = group ids -> both units, all eval). Per unit, timed
on dell with perf_counter:
  parse_s  = l4d/questions.make_questions(unit, "layer1") (tree-sitter parse + sites + masking + question text)
  http_s   = one POST /l4d with all of the unit's questions (server renders the chat template, one forward batch)
  derive_s = derive.unit_inputs + derive.evaluate_unit with the fold's frozen tau (returned by the server)
  e2e_s    = parse_s + http_s + derive_s (latency_s of the row); e2e without parse is reported as well.
The questions built live must equal the precomputed l4d/build/questions_layer1.jsonl rows (qid, state, question).
Units are sent fold by fold so the adapter switch (reported as switch_ms) happens 3 times, outside the units' timing
(one warm-up request per fold before its first unit). Start only when dell load1 < 2.5.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
L4D_DIR = JULIET_FULL / "l4d"
sys.path.insert(0, str(L4D_DIR))
import derive  # noqa: E402  (l4d-data lane, read-only)
from questions import make_questions  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with OPENER.open(req, timeout=120) as resp:
        return json.loads(resp.read())


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def summary(values: list[float]) -> dict:
    return {"median": statistics.median(values), "p90": pct(values, 0.9), "mean": statistics.fmean(values),
            "max": max(values)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://10.15.89.184:8004")
    ap.add_argument("--run-id", default="lat300_c1")
    ap.add_argument("--limit", type=int, default=0, help="first N units only (smoke)")
    ap.add_argument("--max-load1", type=float, default=2.5)
    args = ap.parse_args()

    load_start = os.getloadavg()
    assert load_start[0] < args.max_load1, f"dell load1 {load_start[0]} >= {args.max_load1}"
    health = json.loads(OPENER.open(args.url + "/health", timeout=10).read())
    groups = set(json.loads((JULIET_FULL / "data/build/subsets.json").read_text())["latency300"])
    units = [u for u in read_jsonl(JULIET_FULL / "data/build/layer1.jsonl") if u["group_id"] in groups]
    assert all(u["set"] == "eval" for u in units)
    units.sort(key=lambda u: (u["fold"], u["unit_id"]))
    if args.limit:
        units = units[:args.limit]
    pre = {}
    for q in read_jsonl(L4D_DIR / "build/questions_layer1.jsonl"):
        pre.setdefault(q["unit_id"], []).append(q)
    truth = {u["unit_id"]: u["truth"] for u in units}

    rows, switch_ms, warmed = [], {}, set()
    start = utc_now()
    for u in units:
        if u["fold"] not in warmed:
            q0 = pre[u["unit_id"]][0]
            w = post(args.url + "/l4d", {"fold": u["fold"], "questions": [{"qid": q0["qid"], "state": q0["state"],
                                                                         "question": q0["question"]}]})
            switch_ms[u["fold"]] = w["switch_ms"]
            warmed.add(u["fold"])
        t0 = time.perf_counter()
        qs = make_questions(u, "layer1")
        t1 = time.perf_counter()
        resp = post(args.url + "/l4d", {"fold": u["fold"], "questions": [
            {"qid": q["qid"], "state": q["state"], "question": q["question"]} for q in qs]})
        t2 = time.perf_counter()
        p = {(q["qtype"], tuple(q["site_ids"])): a["p_yes"] for q, a in zip(qs, resp["answers"])}
        res = derive.evaluate_unit(derive.unit_inputs(qs), p, resp["tau"])
        t3 = time.perf_counter()
        same = [(q["qid"], q["state"], q["question"]) for q in qs] == \
            [(q["qid"], q["state"], q["question"]) for q in pre[u["unit_id"]]]
        assert same, f"live questions differ from precomputed for {u['unit_id']}"
        assert resp["switch_ms"] == 0.0, resp["switch_ms"]
        rows.append({"unit_id": u["unit_id"], "method": "lora_l4d", "strategy": "L4D",
                     "model": f"qwen3.5-4b-lora-l4d-fold{u['fold']}", "layer": "layer1", "pred": res["pred"],
                     "score": res["score"], "latency_s": t3 - t0, "status": "ok",
                     "extra": {"fold": u["fold"], "tau": resp["tau"], "checkpoint": resp["checkpoint"],
                               "n_questions": len(qs), "n_tokens": resp["n_tokens"], "parse_s": t1 - t0,
                               "http_s": t2 - t1, "derive_s": t3 - t2, "e2e_no_parse_s": t3 - t1,
                               "server_latency_s": resp["latency_ms_server"] / 1000,
                               "server_forward_s": resp["forward_ms"] / 1000,
                               "server_render_tokenize_s": resp["render_tokenize_ms"] / 1000,
                               "n_forward_chunks": resp["n_forward_chunks"], "leaks": res["leaks"],
                               "truth": truth[u["unit_id"]]}})
    end, load_end = utc_now(), os.getloadavg()
    out_dir = HERE / "results" / "lora_l4d" / "layer1"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.run_id}.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    ex = [r["extra"] for r in rows]
    meta = {"method": "lora_l4d", "strategy": "L4D", "layer": "layer1", "subset": "latency300", "n_units": len(rows),
            "concurrency": 1, "client_host": socket.gethostname(), "url": args.url, "server_health": health,
            "start_utc": start, "end_utc": end, "loadavg_start": load_start, "loadavg_end": load_end,
            "switch_ms_per_fold": switch_ms,
            "e2e_s": summary([r["latency_s"] for r in rows]),
            "e2e_no_parse_s": summary([e["e2e_no_parse_s"] for e in ex]),
            "parse_s": summary([e["parse_s"] for e in ex]), "http_s": summary([e["http_s"] for e in ex]),
            "derive_s": summary([e["derive_s"] for e in ex]),
            "server_latency_s": summary([e["server_latency_s"] for e in ex]),
            "server_forward_s": summary([e["server_forward_s"] for e in ex]),
            "questions_per_unit": summary([e["n_questions"] for e in ex]),
            "tokens_per_unit": summary([e["n_tokens"] for e in ex]),
            "accuracy_vs_truth": sum(r["pred"] == r["extra"]["truth"] for r in rows) / len(rows),
            "note": "e2e = live parse (dell) + POST /l4d (all questions of the unit, one forward batch on one RTX "
                    "3090, merged fold adapter) + derive (dell); adapter switches excluded (warm-up per fold)"}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps({k: meta[k] for k in ("n_units", "e2e_s", "e2e_no_parse_s", "parse_s", "server_latency_s",
                                           "questions_per_unit", "accuracy_vs_truth", "loadavg_start")}, indent=1))


if __name__ == "__main__":
    main()

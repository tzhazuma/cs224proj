"""Probe + latency benchmark of the Intern-Decision-4B read-out (POST /decide), run from dell (stdlib only).

verify: 6 units, prints probabilities; latency: 30 sequential requests (concurrency 1), client
median/p90 and the server-reported latency_ms_server / forward_ms; throughput: concurrency 4
(the server serialises requests, so this measures queueing, not parallel speed-up).
Keep-alive connections (one per client thread). Writes juliet_full/gpu/results/bench/decide_<UTC>.json.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import statistics
import time
from pathlib import Path

from http_keepalive import post_json
from probe_units import load_probe_units

HERE = Path(__file__).resolve().parent
QUESTION = ("Does the executed code unit leak heap memory (memory from malloc, calloc, realloc, strdup or "
            "new/new[] that is not released with free, delete or delete[] before the program ends, "
            "on some path)?")
OPTIONS = {"leak": "The code leaks heap memory on at least one executed path.",
           "no_leak": "All heap memory is released on every executed path, or no heap memory is used."}


def decide(base: str, text: str) -> dict:
    body = {"state": text, "question": QUESTION, "options": OPTIONS}
    t0 = time.perf_counter()
    out = post_json(base + "/decide", body)
    out["_latency_s"] = time.perf_counter() - t0
    return out


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def summarize(xs: list[float], unit: str) -> dict:
    return {f"median_{unit}": round(statistics.median(xs), 4), f"p90_{unit}": round(pct(xs, 0.9), 4),
            f"mean_{unit}": round(statistics.mean(xs), 4)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://10.15.89.184:8002")
    args = ap.parse_args()
    source, units = load_probe_units(6 + 30 + 32)
    report: dict = {"endpoint": args.base, "units_source": source, "question": QUESTION, "options": OPTIONS,
                    "start_utc": dt.datetime.now(dt.timezone.utc).isoformat()}

    rows = []
    for u in units[:6]:
        r = decide(args.base, u["text"])
        rows.append({"unit_id": u["unit_id"], "truth": u["truth"], "probs": r["probs"], "probs_raw": r["probs_raw"],
                     "decision": r["decision"], "input_tokens": r["input_tokens"],
                     "latency_ms_server": r["latency_ms_server"], "latency_s": round(r["_latency_s"], 4)})
        print(json.dumps(rows[-1]))
    report["verify"] = rows

    res = [decide(args.base, u["text"]) for u in units[6:36]]
    report["latency_c1"] = {"n": len(res), **summarize([r["_latency_s"] for r in res], "s"),
                            "server_latency": summarize([r["latency_ms_server"] for r in res], "ms"),
                            "server_forward": summarize([r["forward_ms"] for r in res], "ms"),
                            "client_minus_server": summarize(
                                [1000 * r["_latency_s"] - r["latency_ms_server"] for r in res], "ms"),
                            "input_tokens_median": statistics.median(r["input_tokens"] for r in res)}
    print("latency_c1", json.dumps(report["latency_c1"]))

    batch = units[36:68]
    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(4) as ex:
        res = list(ex.map(lambda u: decide(args.base, u["text"]), batch))
    wall = time.perf_counter() - t0
    report["throughput_c4"] = {"requests": len(batch), "wall_s": round(wall, 2), "req_per_s": round(len(batch) / wall, 2),
                               **summarize([r["_latency_s"] for r in res], "s")}
    print("throughput_c4", json.dumps(report["throughput_c4"]))

    report["end_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    out = HERE.parent / "results/bench" / f"decide_{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()

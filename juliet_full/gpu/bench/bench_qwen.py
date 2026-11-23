"""Probe + latency/throughput benchmark of the Qwen3.5-4B vLLM endpoint, run from dell (stdlib only).

Phases (distinct units per request, so no unit text is served from the prefix cache twice):
  verify      6 units, prints the answer, checks JSON / no thinking text
  latency     30 sequential requests (concurrency 1): client median/p90 + server-side means from /metrics
  throughput  concurrency 16 and 32, 8 x concurrency requests each
Keep-alive connections (one per client thread). Writes juliet_full/gpu/results/bench/qwen_<UTC>.json.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import re
import statistics
import time
import urllib.request
from pathlib import Path

from http_keepalive import post_json
from probe_units import load_probe_units

HERE = Path(__file__).resolve().parent
PROMPT = (HERE / "l1_probe_prompt.txt").read_text()
SYSTEM, USER_TEMPLATE = PROMPT.split("=====\n")
SERVER_HISTOGRAMS = ["e2e_request_latency_seconds", "time_to_first_token_seconds", "request_queue_time_seconds",
                     "request_prefill_time_seconds", "request_decode_time_seconds", "inter_token_latency_seconds"]
SERVER_COUNTERS = ["prompt_tokens_total", "generation_tokens_total", "prefix_cache_queries_total",
                   "prefix_cache_hits_total"]


def metrics(base: str) -> dict[str, float]:
    text = urllib.request.urlopen(base + "/metrics", timeout=10).read().decode()
    out: dict[str, float] = {}
    for line in text.splitlines():
        m = re.match(r"^vllm:([a-z_]+?)(_sum|_count|)\{[^}]*\}\s+([0-9.eE+-]+)$", line)
        if m:
            key = m.group(1) + m.group(2)
            out[key] = out.get(key, 0.0) + float(m.group(3))
    return out


def server_delta(before: dict, after: dict) -> dict:
    res = {}
    for h in SERVER_HISTOGRAMS:
        n = after.get(h + "_count", 0) - before.get(h + "_count", 0)
        if n:
            res[h.replace("_seconds", "_mean_ms")] = round(1000 * (after[h + "_sum"] - before[h + "_sum"]) / n, 2)
    for c in SERVER_COUNTERS:
        res[c] = after.get(c, 0) - before.get(c, 0)
    return res


def chat(base: str, text: str, max_tokens: int) -> dict:
    body = {"model": "qwen3.5-4b", "temperature": 0, "max_tokens": max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": USER_TEMPLATE.replace("{code}", text)}]}
    t0 = time.perf_counter()
    resp = post_json(base + "/v1/chat/completions", body)
    resp["_latency_s"] = time.perf_counter() - t0
    return resp


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def summarize(lat: list[float]) -> dict:
    return {"n": len(lat), "median_s": round(statistics.median(lat), 4), "p90_s": round(pct(lat, 0.9), 4),
            "mean_s": round(statistics.mean(lat), 4)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://10.15.89.184:8001")
    ap.add_argument("--max-tokens", type=int, default=128)
    ap.add_argument("--concurrency", type=int, nargs="*", default=[16, 32])
    args = ap.parse_args()

    n_total = 6 + 30 + sum(8 * c for c in args.concurrency)
    source, units = load_probe_units(n_total)
    report: dict = {"endpoint": args.base, "units_source": source, "max_tokens": args.max_tokens,
                    "prompt": "bench/l1_probe_prompt.txt", "start_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
    pos = 0

    # verify
    rows = []
    for u in units[pos:pos + 6]:
        r = chat(args.base, u["text"], args.max_tokens)
        content = r["choices"][0]["message"]["content"]
        msg = r["choices"][0]["message"]
        try:
            parsed = json.loads(content.strip())
            ok_json = isinstance(parsed, dict) and parsed.get("label") in {"vulnerable", "not_vulnerable"}
        except json.JSONDecodeError:
            parsed, ok_json = None, False
        thinking = "<think>" in content or "</think>" in content or bool(msg.get("reasoning_content") or msg.get("reasoning"))
        rows.append({"unit_id": u["unit_id"], "truth": u["truth"], "content": content, "json_ok": ok_json,
                     "thinking_text": thinking, "usage": r["usage"], "model": r["model"],
                     "latency_s": round(r["_latency_s"], 4)})
        print(json.dumps(rows[-1]))
    pos += 6
    report["verify"] = rows

    # latency, concurrency 1
    m0 = metrics(args.base)
    lat, out_tok = [], []
    for u in units[pos:pos + 30]:
        r = chat(args.base, u["text"], args.max_tokens)
        lat.append(r["_latency_s"])
        out_tok.append(r["usage"]["completion_tokens"])
    pos += 30
    report["latency_c1"] = {**summarize(lat), "completion_tokens_median": statistics.median(out_tok),
                            "server": server_delta(m0, metrics(args.base))}
    print("latency_c1", json.dumps(report["latency_c1"]))

    # throughput
    report["throughput"] = []
    for c in args.concurrency:
        batch = units[pos:pos + 8 * c]
        pos += 8 * c
        m0 = metrics(args.base)
        t0 = time.perf_counter()
        with cf.ThreadPoolExecutor(c) as ex:
            res = list(ex.map(lambda u: chat(args.base, u["text"], args.max_tokens), batch))
        wall = time.perf_counter() - t0
        prompt_tok = sum(r["usage"]["prompt_tokens"] for r in res)
        gen_tok = sum(r["usage"]["completion_tokens"] for r in res)
        entry = {"concurrency": c, "requests": len(batch), "wall_s": round(wall, 2),
                 "req_per_s": round(len(batch) / wall, 2), "units_per_hour": round(3600 * len(batch) / wall),
                 "prompt_tok_per_s": round(prompt_tok / wall), "gen_tok_per_s": round(gen_tok / wall),
                 "latency": summarize([r["_latency_s"] for r in res]),
                 "server": server_delta(m0, metrics(args.base))}
        report["throughput"].append(entry)
        print("throughput", json.dumps(entry))

    report["end_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    out = HERE.parent / "results/bench" / f"qwen_{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()

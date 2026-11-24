#!/usr/bin/env python3
"""Run VulnLLM-R-7B (authors' prompt, README.md section 2) over a juliet_full unit set via a vLLM OpenAI server.

    python3 run_vulnllmr.py --layer layer1 --set dev                      # bulk, run_id dev_policy_r1
    python3 run_vulnllmr.py --layer layer1 --set eval --subset nested25 --cwe-hint none   # n25_nohint_r1
    python3 run_vulnllmr.py --layer layer1 --c1-latency                   # latency300, concurrency 1, lock + load gate
    python3 run_vulnllmr.py --layer layer1 --set dev --limit 20 --dry-run # render prompts only, no requests

Resumable: every finished request is appended to build/raw/<layer>/<run_id>.raw.jsonl (full output); a rerun with
the same run_id skips units whose last raw record is ok/invalid and retries the rest.  The prediction file
results/vulnllm_r_7b/<layer>/<run_id>.jsonl and its .meta.json are rewritten from the raw log at the end.
Stdlib only (python3 >= 3.10).
"""
from __future__ import annotations

import argparse
import collections
import fcntl
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vulnllmr_prompt as prompt  # noqa: E402

JULIET_FULL = HERE.parent
DATA_BUILD = JULIET_FULL / "data" / "build"
LAYERS = ("layer1", "layer3", "placebo", "original")
SUBSET_TAGS = {"nested25": "n25", "latency300": "lat300", "api_subset": "api", "repeat100": "rep100"}
HINT_TAGS = {"policy": "policy", "none": "nohint"}
METHOD = "vulnllm_r_7b"
MODEL = "VulnLLM-R-7B"
HF_REPO = "Virtue-AI-HUB/VulnLLM-R-7B"
HF_REVISION = "8cd13d7a35f13b187102dba166413d4450836a40"
MODEL_SHA_FILE = HERE / "model_files.sha256"
DEFAULT_BASE_URL = "http://10.15.89.184:8005/v1"
SERVED_MODEL_NAME = "vulnllm-r-7b"
# Authors: vulscan/test/test.py:97 (seed 42), :130 (temperature 0.0); README.md:40 and paper sec. 5.3 (max 8192);
# generation_utils.py:209-217 run_default_model (top_p 0.9, irrelevant at temperature 0).  repetition_penalty 1.0
# and top_k -1 are the vLLM SamplingParams defaults the authors' offline LLM.chat used; they are sent explicitly
# because the checkpoint's generation_config.json (rep. penalty 1.05, top_k 20, top_p 0.8) would otherwise apply.
GENERATION = {"temperature": 0.0, "top_p": 0.9, "top_k": -1, "repetition_penalty": 1.0, "seed": 42,
              "max_tokens": 8192}
OUTPUT_TAIL_CHARS = 300
LATENCY_LOCK = Path("/tmp/cs224_latency.lock")
LOAD1_MAX = 2.5
DONE_STATUSES = ("ok", "invalid")


def iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if ts is None else ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git_head() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(HERE), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def log(msg: str) -> None:
    print(f"[{iso()}] {msg}", flush=True)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--layer", required=True, choices=LAYERS)
    p.add_argument("--set", choices=["dev", "eval"], help="unit split (default eval for --c1-latency)")
    p.add_argument("--subset", choices=sorted(SUBSET_TAGS), help="group subset from data/build/subsets.json")
    p.add_argument("--cwe-hint", choices=prompt.CWE_HINTS, default="policy",
                   help="policy = --use_policy CWE list of their Juliet CWE-401 rows (default); none = README:40")
    p.add_argument("--run-id", help="default <set|subset tag>_<hint tag>_r1, e.g. eval_policy_r1, n25_nohint_r1")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--served-model-name", default=SERVED_MODEL_NAME)
    p.add_argument("--concurrency", type=int, default=64)
    p.add_argument("--timeout", type=float, default=1800.0, help="per-request HTTP timeout, s")
    p.add_argument("--retries", type=int, default=3, help="retries per unit after the first attempt")
    p.add_argument("--max-tokens", type=int, default=GENERATION["max_tokens"])
    p.add_argument("--limit", type=int, help="first N selected units only (smoke tests)")
    p.add_argument("--c1-latency", action="store_true",
                   help="latency300 eval units, concurrency 1, flock /tmp/cs224_latency.lock, load1 < 2.5")
    p.add_argument("--c1-groups", type=int,
                   help="c1: only N latency300 groups (both units each), stratified by flow_category x mechanism")
    p.add_argument("--lock-wait", type=float, default=1200.0, help="c1: max seconds to wait for lock + quiet load")
    p.add_argument("--dry-run", action="store_true", help="render prompts to build/prompts/, send nothing")
    p.add_argument("--units-file", type=Path, help="override data/build/<layer>.jsonl")
    p.add_argument("--out-root", type=Path, default=HERE / "results")
    p.add_argument("--raw-root", type=Path, default=HERE / "build" / "raw")
    args = p.parse_args(argv)
    if args.c1_latency:
        if args.subset not in (None, "latency300") or args.set not in (None, "eval"):
            p.error("--c1-latency always uses --set eval --subset latency300")
        args.set, args.subset, args.concurrency = "eval", "latency300", 1
    elif args.c1_groups:
        p.error("--c1-groups needs --c1-latency")
    if args.set is None:
        p.error("--set is required")
    if args.run_id is None:
        scope = SUBSET_TAGS[args.subset] if args.subset else args.set
        if args.c1_groups:
            scope = f"lat{2 * args.c1_groups}"
        c1 = "_c1" if args.c1_latency else ""
        args.run_id = f"{scope}{c1}_{HINT_TAGS[args.cwe_hint]}_r1"
    return args


def stratified_groups(order: list[str], first_unit: dict[str, dict[str, Any]], n: int) -> set[str]:
    """n groups from `order`: largest-remainder proportional quota per (flow_category, mechanism) stratum, filled
    with each stratum's groups in `order` (subsets.json) order."""
    strata: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for g in order:
        strata[(first_unit[g]["flow_category"], first_unit[g]["mechanism"])].append(g)
    exact = {k: n * len(v) / len(order) for k, v in strata.items()}
    quota = {k: int(x) for k, x in exact.items()}
    for k in sorted(exact, key=lambda k: (-(exact[k] - quota[k]), k))[: n - sum(quota.values())]:
        quota[k] += 1
    return {g for k, v in strata.items() for g in v[: quota[k]]}


def select_units(args: argparse.Namespace) -> tuple[Path, list[dict[str, Any]]]:
    path = args.units_file or DATA_BUILD / f"{args.layer}.jsonl"
    units = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    units = [u for u in units if u["set"] == args.set]
    if args.subset:
        groups = set(json.loads((DATA_BUILD / "subsets.json").read_text())[args.subset])
        units = [u for u in units if u["group_id"] in groups]
    if args.c1_groups:
        order = json.loads((DATA_BUILD / "subsets.json").read_text())["latency300"]
        chosen = stratified_groups(order, {u["group_id"]: u for u in units}, args.c1_groups)
        units = [u for u in units if u["group_id"] in chosen]
    if args.limit:
        units = units[: args.limit]
    return path, units


def chat_request(args: argparse.Namespace, unit: dict[str, Any]) -> dict[str, Any]:
    body = {"model": args.served_model_name,
            "messages": prompt.messages(unit["model_text"], unit["unit_id"], args.cwe_hint),
            **{k: v for k, v in GENERATION.items() if k != "max_tokens"}, "max_tokens": args.max_tokens}
    return body


def http_json(url: str, body: dict[str, Any] | None, timeout: float) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="GET" if body is None else "POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


class RawLog:
    """Append-only JSONL of finished requests; last record per unit wins."""

    def __init__(self, path: Path, config_sha: str) -> None:
        self.path = path
        self.config_sha = config_sha
        self.lock = threading.Lock()
        self.records: dict[str, dict[str, Any]] = {}
        if path.exists():
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec["config_sha"] != config_sha:
                    raise SystemExit(f"refused: {path} was written with config {rec['config_sha']}, now "
                                     f"{config_sha}; use a new --run-id")
                self.records[rec["unit_id"]] = rec
        path.parent.mkdir(parents=True, exist_ok=True)

    def done(self, unit_id: str) -> bool:
        rec = self.records.get(unit_id)
        return rec is not None and rec["status"] in DONE_STATUSES

    def append(self, rec: dict[str, Any]) -> None:
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.records[rec["unit_id"]] = rec


def work(args: argparse.Namespace, unit: dict[str, Any], raw: RawLog) -> dict[str, Any]:
    body = chat_request(args, unit)
    url = args.base_url.rstrip("/") + "/chat/completions"
    errors: list[str] = []
    for attempt in range(args.retries + 1):
        started = time.time()
        try:
            resp = http_json(url, body, args.timeout)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as exc:
            detail = exc.read().decode(errors="replace")[:500] if isinstance(exc, urllib.error.HTTPError) else ""
            errors.append(f"{type(exc).__name__}: {exc} {detail}".strip())
            if isinstance(exc, urllib.error.HTTPError) and exc.code == 400:
                break  # request itself rejected (e.g. prompt too long): retrying cannot help
            time.sleep(min(60, 5 * 2 ** attempt))
            continue
        latency = time.time() - started
        choice = resp["choices"][0]
        text = choice["message"].get("content") or ""
        finish = choice.get("finish_reason")
        v = prompt.verdict(text, finish)
        usage = resp.get("usage") or {}
        rec = {"unit_id": unit["unit_id"], "config_sha": raw.config_sha, "status": "ok" if v["pred"] is not None
               else "invalid", "verdict": v, "latency_s": round(latency, 3), "finish_reason": finish,
               "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
               "attempts": attempt + 1, "errors": errors, "model_returned": resp.get("model"),
               "started_utc": iso(started), "output": text}
        raw.append(rec)
        return rec
    rec = {"unit_id": unit["unit_id"], "config_sha": raw.config_sha, "status": "error", "verdict": None,
           "latency_s": None, "finish_reason": None, "prompt_tokens": None, "completion_tokens": None,
           "attempts": len(errors), "errors": errors, "model_returned": None, "started_utc": None, "output": None}
    raw.append(rec)
    return rec


def prediction_row(args: argparse.Namespace, unit: dict[str, Any], rec: dict[str, Any] | None) -> dict[str, Any]:
    base = {"unit_id": unit["unit_id"], "method": METHOD, "strategy": HINT_TAGS[args.cwe_hint], "model": MODEL,
            "layer": args.layer, "score": None}
    if rec is None:
        return {**base, "pred": None, "latency_s": None, "status": "error", "extra": {"reason": "not run"}}
    v = rec["verdict"] or {}
    extra = {"prompt_tokens": rec["prompt_tokens"], "completion_tokens": rec["completion_tokens"],
             "finish_reason": rec["finish_reason"], "judge": v.get("judge"), "pred_type": v.get("pred_type"),
             "pred_strict": v.get("pred_strict"), "truncated": v.get("truncated"),
             "cwe_order": prompt.cwe_order(unit["unit_id"]) if args.cwe_hint == "policy" else None,
             "attempts": rec["attempts"], "errors": rec["errors"][-2:],
             "output_tail": (rec["output"] or "")[-OUTPUT_TAIL_CHARS:],
             "raw": os.path.relpath(args.raw_path, HERE)}
    return {**base, "pred": v.get("pred"), "latency_s": rec["latency_s"], "status": rec["status"], "extra": extra}


def wait_quiet(deadline: float) -> bool:
    """True once load1 < LOAD1_MAX in every 15-s sample over 2 consecutive minutes; False at the deadline."""
    quiet_since = None
    while time.time() < deadline:
        if os.getloadavg()[0] < LOAD1_MAX:
            quiet_since = quiet_since or time.time()
            if time.time() - quiet_since >= 120:
                return True
        else:
            quiet_since = None
        time.sleep(15)
    return False


def acquire_latency_lock(args: argparse.Namespace) -> tuple[Any, dict[str, Any]]:
    handle = LATENCY_LOCK.open("a")
    t0 = time.time()
    deadline = t0 + args.lock_wait
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.time() > deadline:
                raise SystemExit(f"refused: {LATENCY_LOCK} not acquired within {args.lock_wait:.0f} s")
            time.sleep(5)
    lock_wait = round(time.time() - t0, 1)
    log(f"latency lock acquired after {lock_wait} s; waiting for load1 < {LOAD1_MAX} over 2 min")
    if not wait_quiet(deadline):
        raise SystemExit(f"refused: load1 never < {LOAD1_MAX} for 2 min within {args.lock_wait:.0f} s")
    return handle, {"lock": str(LATENCY_LOCK), "lock_wait_s": lock_wait,
                    "quiet_wait_s": round(time.time() - t0 - lock_wait, 1), "loadavg_at_start": os.getloadavg()}


def server_running_requests(base_url: str) -> float | None:
    """vllm:num_requests_running from the server's /metrics (None if unavailable)."""
    url = base_url.rstrip("/").removesuffix("/v1") + "/metrics"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            text = resp.read().decode()
    except (urllib.error.URLError, OSError):
        return None
    total = 0.0
    for line in text.splitlines():
        if line.startswith("vllm:num_requests_running"):
            total += float(line.rsplit(" ", 1)[1])
    return total


def model_sha() -> dict[str, Any]:
    info: dict[str, Any] = {"hf_repo": HF_REPO, "hf_revision": HF_REVISION}
    if MODEL_SHA_FILE.exists():
        info["files_sha256_list"] = str(MODEL_SHA_FILE.relative_to(HERE))
        info["files_sha256_list_sha256"] = file_sha256(MODEL_SHA_FILE)
        pairs = [line.split() for line in MODEL_SHA_FILE.read_text().splitlines() if line.strip()]
        info["safetensors"] = {name.removeprefix("./"): sha for sha, name in pairs if name.endswith(".safetensors")}
    return info


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = collections.Counter(r["status"] for r in rows)
    yes_types = collections.Counter(r["extra"].get("pred_type") for r in rows if r["pred"] == 1)
    finish = collections.Counter(r["extra"].get("finish_reason") for r in rows if r["status"] != "error")
    comp = [r["extra"]["completion_tokens"] for r in rows if r["extra"].get("completion_tokens") is not None]
    prm = [r["extra"]["prompt_tokens"] for r in rows if r["extra"].get("prompt_tokens") is not None]
    lat = [r["latency_s"] for r in rows if r["latency_s"] is not None]
    return {"n_units": len(rows), "status_counts": dict(statuses),
            "invalid_rate": round((len(rows) - statuses.get("ok", 0)) / max(1, len(rows)), 4),
            "pred_counts": dict(collections.Counter(str(r["pred"]) for r in rows)),
            "pred_strict_counts": dict(collections.Counter(str(r["extra"].get("pred_strict")) for r in rows)),
            "yes_type_counts": dict(yes_types.most_common()), "finish_reason_counts": dict(finish),
            "usage_totals": {"prompt_tokens": sum(prm), "completion_tokens": sum(comp), "requests": len(comp)},
            "completion_tokens_mean": round(sum(comp) / len(comp), 1) if comp else None,
            "completion_tokens_max": max(comp) if comp else None,
            "latency_s_mean": round(sum(lat) / len(lat), 3) if lat else None}


def dry_run(args: argparse.Namespace, units: list[dict[str, Any]]) -> int:
    out = HERE / "build" / "prompts" / args.layer / f"{args.run_id}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for unit in units:
            handle.write(json.dumps({"unit_id": unit["unit_id"], "request": chat_request(args, unit)},
                                    ensure_ascii=False) + "\n")
    log(f"dry run: {len(units)} rendered requests -> {out}; prompt_sha256 {prompt.prompt_sha256(args.cwe_hint)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    units_path, units = select_units(args)
    if args.dry_run:
        return dry_run(args, units)
    gen = {**GENERATION, "max_tokens": args.max_tokens}
    config = {"prompt_sha256": prompt.prompt_sha256(args.cwe_hint), "generation": gen,
              "served_model_name": args.served_model_name, "layer": args.layer,
              "units_sha256": file_sha256(units_path)}
    config_sha = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:16]
    args.raw_path = args.raw_root / args.layer / f"{args.run_id}.raw.jsonl"
    raw = RawLog(args.raw_path, config_sha)

    lock_handle, lock_info = (None, None)
    if args.c1_latency:
        lock_handle, lock_info = acquire_latency_lock(args)
    started = time.time()
    load_start = os.getloadavg()
    listing = http_json(args.base_url.rstrip("/") + "/models", None, 30)
    running_before = server_running_requests(args.base_url)
    if args.c1_latency and running_before:
        raise SystemExit(f"refused: server already has {running_before:.0f} running requests (c1 needs it idle)")

    todo = [u for u in units if not raw.done(u["unit_id"])]
    log(f"{args.run_id}: {len(units)} units, {len(units) - len(todo)} already done, {len(todo)} to run, "
        f"concurrency {args.concurrency}, raw {args.raw_path}")
    warmup = None
    if args.c1_latency and todo:
        t0 = time.time()
        http_json(args.base_url.rstrip("/") + "/chat/completions", chat_request(args, todo[0]), args.timeout)
        warmup = {"unit_id": todo[0]["unit_id"], "latency_s": round(time.time() - t0, 3), "recorded": False}
        log(f"warm-up request (not recorded) {warmup['latency_s']} s")
    n_done = 0
    pool = ThreadPoolExecutor(max_workers=max(1, args.concurrency))
    try:
        futures = [pool.submit(work, args, u, raw) for u in todo]
        for future in as_completed(futures):
            future.result()
            n_done += 1
            if n_done % 50 == 0 or n_done == len(todo):
                log(f"{n_done}/{len(todo)} done")
        pool.shutdown(wait=True)
    except KeyboardInterrupt:
        log("interrupted; writing partial results (rerun the same command to resume)")
        pool.shutdown(wait=False, cancel_futures=True)
    ended = time.time()

    rows = [prediction_row(args, u, raw.records.get(u["unit_id"])) for u in units]
    out_dir = args.out_root / METHOD / args.layer
    out_dir.mkdir(parents=True, exist_ok=True)
    pred_path = out_dir / f"{args.run_id}.jsonl"
    with pred_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    meta = {"run_id": args.run_id, "method": METHOD, "strategy": HINT_TAGS[args.cwe_hint], "model": MODEL,
            "layer": args.layer, "set": args.set, "subset": args.subset, "cwe_hint": args.cwe_hint,
            "c1_latency": args.c1_latency, **summarize(rows),
            "prompt_sha256": config["prompt_sha256"], "prompt_spec": prompt.prompt_spec(args.cwe_hint),
            "prompt_module": "vulnllmr_prompt.py", "prompt_module_sha256": file_sha256(HERE / "vulnllmr_prompt.py"),
            "generation": gen, "config_sha": config_sha, "model_sha": model_sha(),
            "server": {"base_url": args.base_url, "served_model_name": args.served_model_name,
                       "models_listing": listing, "running_requests_before": running_before},
            "units_file": str(units_path), "units_sha256": config["units_sha256"],
            "selection": {"limit": args.limit, "c1_groups": args.c1_groups,
                          "c1_group_rule": "stratified_groups(): largest-remainder quota per flow_category x "
                                           "mechanism, subsets.json order" if args.c1_groups else None},
            "start_utc": iso(started), "end_utc": iso(ended), "wall_s": round(ended - started, 2),
            "host": socket.gethostname(), "concurrency": args.concurrency, "timeout_s": args.timeout,
            "retries": args.retries, "loadavg_start": load_start, "loadavg_end": os.getloadavg(),
            "latency_lock": lock_info, "warmup": warmup, "git_head": git_head(), "raw_log": str(args.raw_path)}
    pred_path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    if lock_handle is not None:
        lock_handle.close()
    log(f"wrote {pred_path}: {meta['status_counts']}; invalid rate {meta['invalid_rate']}")
    return 0 if meta["status_counts"].get("error", 0) == 0 else 3


if __name__ == "__main__":
    sys.exit(main())

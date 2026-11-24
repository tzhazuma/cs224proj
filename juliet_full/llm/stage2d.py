#!/usr/bin/env python3
"""Stage-2d driver (parent brief 2026-11-23 13:07, after commit aa46b64), run under nohup.

Qwen3.5-4B (vLLM http://10.15.89.184:8001/v1, thinking disabled via chat_template_kwargs, temperature 0) with
the frozen chat prompts, concurrency 16:
  0 wait for the endpoint: GET /v1/models every 5 min, at most 60 min
  1 dev sanity, layer1 dev (L2 example groups dropped): dev_L{1,2,3,4}_r1, scored on dev_minus_l2.
    STOP (no eval runs) if any L1-L3 dev run has > 5% invalid, or any dev run > 5% error.
    L4 dev with > 5% invalid: L4 eval runs are skipped (reported; Qwen L4 failures are wrong verdicts).
  2 layer1 eval: eval_L{1,2,3}_r1, eval_L4_r1
  3 layer3 eval: l3_eval_L{1,2,3,4}_r1     4 placebo eval: pl_eval_L{1,3}_r1     5 original eval: orig_eval_L1_r1
  5b repeats rep_L{1,2,3}_r{2,3} on eval ∩ repeat100 only (parent 14:21: GPU 1 is shared)
  Every eval run: STOP if > 5% error (server trouble); L1-L3 also if > 5% invalid.
  6 latency: exclusive flock on /tmp/cs224_latency.lock (flock -w 1200), then the quiet check (dell load1 < 2.5
    in every 15-s sample over 2 min, at most 20 min); vLLM :8001/:8002 running/waiting request counts from
    /metrics are recorded. Qwen lat300_c1_L1 runs either way (meta latency_lock.quiet says whether it was quiet);
    DeepSeek (cap CNY 0.10) and Jev (cap USD 0.02) lat300_c1_L1_quiet only when quiet, still under the lock.
Progress: scratch/stage2d/status.txt; per-run logs scratch/stage2d/<model>_<run_id>.log. Restartable: existing
predictions are skipped (scored if unscored); waits for a stage-2d run_llm.py still running.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR  # noqa: E402
from llmlane.clients import QWEN_BASE  # noqa: E402
from llmlane.ledger import Ledger  # noqa: E402

JF = LLM_DIR.parent
BUILD = JF / "data" / "build"
SCORE = JF / "analysis" / "score.py"
WORK = LLM_DIR / "scratch" / "stage2d"
STATUS = WORK / "status.txt"
METHOD = {"qwen": "qwen3_5_4b", "deepseek": "deepseek_flash", "jev": "jev"}
DEV_SUBSETS = LLM_DIR / "dev_check" / "dev_minus_l2_subsets.json"
VLLM_PORTS = {"qwen_8001": "http://10.15.89.184:8001", "decision_8002": "http://10.15.89.184:8002"}
LATENCY_LOCK = Path("/tmp/cs224_latency.lock")
LATENCY_WAIT_S = 20 * 60
ENDPOINT_POLL_S, ENDPOINT_WAIT_S = 5 * 60, 60 * 60
BROKEN_SHARE = 0.05
# Parent caps for the quiet latency remeasure (300 calls each; stage 2b: CNY 0.000276 / USD 0.000034 per call).
LATENCY_CAP = {"deepseek": 0.10, "jev": 0.02}
CONCURRENCY = 16


class Stop(Exception):
    pass


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with STATUS.open("a") as handle:
        handle.write(line + "\n")
    print(line, flush=True)


def uptime() -> str:
    return subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()


def get(url: str, timeout: float = 10) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode()
    except OSError:
        return None


def vllm_load() -> dict[str, dict[str, float] | None]:
    """vllm:num_requests_running / _waiting per server (None if /metrics does not answer)."""
    out: dict[str, dict[str, float] | None] = {}
    for name, base in VLLM_PORTS.items():
        text = get(f"{base}/metrics", 5)
        if text is None:
            out[name] = None
            continue
        vals: dict[str, float] = {}
        for key in ("num_requests_running", "num_requests_waiting"):
            hits = re.findall(rf"^vllm:{key}\{{[^}}]*\}} ([0-9.eE+-]+)$", text, re.M)
            vals[key] = sum(float(h) for h in hits)
        out[name] = vals
    return out


def wait_endpoint() -> bool:
    deadline = time.time() + ENDPOINT_WAIT_S
    while True:
        text = get(f"{QWEN_BASE}/models")
        if text is not None:
            log(f"qwen endpoint up: {text[:300]}")
            return True
        if time.time() + ENDPOINT_POLL_S > deadline:
            return False
        log(f"qwen endpoint not answering; next poll in {ENDPOINT_POLL_S} s")
        time.sleep(ENDPOINT_POLL_S)


def run(model: str, strategy: str, run_id: str, layer: str, set_: str = "eval", subset: str | None = None,
        concurrency: int = CONCURRENCY, max_cost: float | None = None, extra_meta: dict | None = None) -> dict:
    """run_llm.py then score.py; returns the run's status_counts (empty if no predictions)."""
    units = BUILD / f"{layer}.jsonl"
    pred = LLM_DIR / "results" / METHOD[model] / layer / f"{run_id}.jsonl"
    score_out = LLM_DIR / "results" / "scores" / METHOD[model] / f"{run_id}.json"
    score_cmd = [sys.executable, str(SCORE), "--pred", str(pred), "--units", str(units), "--set", set_,
                 "--bootstrap", "1000", "--out", str(score_out)]
    if set_ == "dev":
        score_cmd += ["--subset", "dev_minus_l2", "--subsets-file", str(DEV_SUBSETS)]
    elif subset:
        score_cmd += ["--subset", subset]
    logfile = WORK / f"{model}_{run_id}.log"
    if pred.exists():
        if not score_out.exists():
            score(model, run_id, pred, score_cmd, logfile)
        log(f"{model} {run_id}: exists, skipped")
        return json.loads(pred.with_suffix(".meta.json").read_text())["status_counts"]
    cmd = [sys.executable, str(LLM_DIR / "run_llm.py"), "--model", model, "--strategy", strategy,
           "--units", str(units), "--layer", layer, "--set", set_, "--concurrency", str(concurrency),
           "--run-id", run_id]
    if model != "qwen":
        cmd += ["--allow-eval", "--max-cost", str(max_cost)]
    if subset:
        cmd += ["--subset", subset]
    log(f"{model} {run_id}: start (uptime: {uptime()}; vllm {vllm_load()})")
    with logfile.open("a") as handle:
        code = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=LLM_DIR).returncode
    log(f"{model} {run_id}: exit {code} (uptime: {uptime()})")
    if not pred.exists():
        return {}
    meta_path = pred.with_suffix(".meta.json")
    if extra_meta:
        meta = json.loads(meta_path.read_text())
        meta.update(extra_meta)
        meta_path.write_text(json.dumps(meta, indent=1) + "\n")
    score(model, run_id, pred, score_cmd, logfile)
    return json.loads(meta_path.read_text())["status_counts"]


def score(model: str, run_id: str, pred: Path, score_cmd: list[str], logfile: Path) -> None:
    out = Path(score_cmd[score_cmd.index("--out") + 1])
    out.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("a") as handle:
        subprocess.run(score_cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=JF)
    meta = json.loads(pred.with_suffix(".meta.json").read_text())
    rep = json.loads(out.read_text())["end_to_end"] if out.exists() else {}
    log(f"{model} {run_id}: {meta['status_counts']} wall {meta.get('wall_s')} s macroF1 {rep.get('macro_f1')} "
        f"fp {rep.get('fp')} fn {rep.get('fn')} invalid {rep.get('invalid')}")


def check_broken(run_id: str, strategy: str, counts: dict) -> bool:
    """Raise Stop on server trouble or (L1-L3) parse failures above 5%; True if L4 invalid is above 5%."""
    n = sum(counts.values())
    if not n:
        raise Stop(f"{run_id}: no predictions written")
    error, invalid = counts.get("error", 0) / n, counts.get("invalid", 0) / n
    if error > BROKEN_SHARE:
        raise Stop(f"{run_id}: {error:.1%} error")
    if invalid > BROKEN_SHARE:
        if strategy != "L4":
            raise Stop(f"{run_id}: {invalid:.1%} invalid")
        log(f"{run_id}: L4 invalid {invalid:.1%} > 5%")
        return True
    return False


def wait_for_inflight_runs() -> None:
    while True:
        found = subprocess.run(["pgrep", "-f", "run_llm.py --model qwen"], capture_output=True,
                               text=True).stdout.split()
        if not found:
            return
        log(f"waiting for in-flight run_llm.py pids {found}")
        time.sleep(30)


def wait_quiet(deadline: float) -> bool:
    """True once load1 < 2.5 in every 15-s sample over 2 consecutive minutes; False at the deadline."""
    quiet_since = None
    while time.time() < deadline:
        if os.getloadavg()[0] < 2.5:
            quiet_since = quiet_since or time.time()
            if time.time() - quiet_since >= 120:
                return True
        else:
            quiet_since = None
        time.sleep(15)
    return False


def latency_runs() -> None:
    t0 = time.time()
    with LATENCY_LOCK.open("a") as lock:
        while True:  # flock -w 1200
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() - t0 >= LATENCY_WAIT_S:
                    log(f"latency runs SKIPPED: {LATENCY_LOCK} not acquired within 20 min")
                    return
                time.sleep(5)
        lock_wait = round(time.time() - t0, 1)
        log(f"latency lock acquired after {lock_wait} s; quiet check (uptime: {uptime()})")
        t1 = time.time()
        quiet = wait_quiet(t1 + LATENCY_WAIT_S)
        quiet_wait = round(time.time() - t1, 1)
        log(f"quiet={quiet} after {quiet_wait} s (uptime: {uptime()}; vllm {vllm_load()})")
        models = ["qwen"] + (["deepseek", "jev"] if quiet else [])
        if not quiet:
            log("deepseek/jev lat300_c1_L1_quiet SKIPPED: load1 never < 2.5 for 2 min within 20 min")
        for model in models:
            run_id = "lat300_c1_L1" if model == "qwen" else "lat300_c1_L1_quiet"
            before = {"loadavg": list(os.getloadavg()), "uptime": uptime(), "vllm": vllm_load()}
            run(model, "L1", run_id, "layer1", subset="latency300", concurrency=1, max_cost=LATENCY_CAP.get(model))
            meta_path = LLM_DIR / "results" / METHOD[model] / "layer1" / f"{run_id}.meta.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                meta["latency_lock"] = {"lock": str(LATENCY_LOCK), "lock_wait_s": lock_wait, "quiet": quiet,
                                        "quiet_wait_s": quiet_wait, "before": before,
                                        "after": {"loadavg": list(os.getloadavg()), "uptime": uptime(),
                                                  "vllm": vllm_load()}}
                meta_path.write_text(json.dumps(meta, indent=1) + "\n")


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    log(f"driver start; ledger deepseek {Ledger().spent('deepseek'):.6f} CNY, jev {Ledger().spent('jev'):.6f} USD")
    wait_for_inflight_runs()
    if not wait_endpoint():
        log("STOP: qwen endpoint not up within 60 min")
        return 1
    try:
        l4_broken = False
        for s in ("L1", "L2", "L3", "L4"):
            counts = run("qwen", s, f"dev_{s}_r1", "layer1", set_="dev")
            l4_broken |= check_broken(f"dev_{s}_r1", s, counts)
        if l4_broken:
            log("L4 eval runs will be SKIPPED (dev L4 invalid > 5%)")
        queue = [("L1", "eval_L1_r1", "layer1"), ("L2", "eval_L2_r1", "layer1"), ("L3", "eval_L3_r1", "layer1"),
                 ("L4", "eval_L4_r1", "layer1")]
        queue += [(s, f"l3_eval_{s}_r1", "layer3") for s in ("L1", "L2", "L3", "L4")]
        queue += [(s, f"pl_eval_{s}_r1", "placebo") for s in ("L1", "L3")]
        queue += [("L1", "orig_eval_L1_r1", "original")]
        # Parent 14:21 PST (GPU 1 shared with Intern-Decision): repeats only on eval ∩ repeat100, after the rest.
        queue += [(s, f"rep_{s}_r{r}", "layer1", "repeat100") for r in (2, 3) for s in ("L1", "L2", "L3")]
        for s, run_id, layer, *subset in queue:
            if s == "L4" and l4_broken:
                log(f"qwen {run_id}: SKIPPED (dev L4 invalid > 5%)")
                continue
            check_broken(run_id, s, run("qwen", s, run_id, layer, subset=subset[0] if subset else None))
    except Stop as exc:
        log(f"STOP: {exc}")
        return 1
    log(f"bulk done; latency: lock {LATENCY_LOCK}, then quiet check (uptime: {uptime()})")
    latency_runs()
    ledger = Ledger()
    log(f"driver done; ledger deepseek {ledger.spent('deepseek'):.6f} CNY, jev {ledger.spent('jev'):.6f} USD")
    return 0


if __name__ == "__main__":
    sys.exit(main())

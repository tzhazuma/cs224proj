#!/usr/bin/env python3
"""Stage-2c driver (parent brief 2026-11-23, after the L4 v3c freeze at 216054a), run under nohup.

Queues, in the brief's priority order (each run = run_llm.py, then analysis/score.py on the run's layer file
--out results/scores/<method>/<run_id>.json; run ids carry the layer: l3_ = layer3 (stress), pl_ = placebo,
orig_ = original Juliet, none = layer1):
  deepseek: 1 eval_L4_r1 (layer1 full eval)
            2 l3_n25_L1_r1, l3_n25_L3_r1, l3_n25_L2_r1, l3_n25_L4_r1 (layer3, eval ∩ nested25)
            3 pl_n25_L1_r1, pl_n25_L3_r1          4 orig_n25_L1_r1
            6 only if the cumulative DeepSeek ledger is <= CNY 7.4: l3_apirest_L{1,2,3}_r1 (layer3, eval groups
              of api_subset not in nested25, dev_check/api_rest332_subsets.json)
  jev (in parallel, item 5): l3_eval_L{1,2,3}_r1, pl_eval_L{1,3}_r1, orig_eval_L1_r1 (full eval)
  7 then lat300_c1_L1_quiet (layer1, latency300, c1) for deepseek and jev, serialized with the other lanes'
    c1 latency runs by an exclusive flock on /tmp/cs224_latency.lock (same lock as `flock(1)`); after the lock
    is held, wait until dell load1 < 2.5 for 2 consecutive minutes; give up 20 min after the queues finish
    (lock wait included). Lock wait and load before/after are added to each latency meta (`latency_lock`).
Caps: a run is skipped when its expected cost exceeds what is left of the stage budget (DeepSeek CNY 4.4 and
cumulative ledger CNY 8.1, raised to 4.55 / 8.25 by the parent at 12:31 for l3_apirest_L3_r1; Jev USD 0.9 and cumulative USD 2.2); its --max-cost is min(1.5 x expected, left).
A deepseek run refused in peak hours waits for the next off-peak window and retries.
Progress: scratch/stage2c/status.txt; per-run logs scratch/stage2c/<model>_<run_id>.log.
Restartable: the ledger base is the one of the first `driver start` line in status.txt; a restarted driver
waits for stage-2c run_llm.py processes still running, and scores existing predictions without a score.
"""

from __future__ import annotations

import ast
import fcntl
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR  # noqa: E402
from llmlane.ledger import Ledger  # noqa: E402
from llmlane.pricing import is_deepseek_peak, next_offpeak, utc_now  # noqa: E402

JF = LLM_DIR.parent
BUILD = JF / "data" / "build"
SCORE = JF / "analysis" / "score.py"
WORK = LLM_DIR / "scratch" / "stage2c"
STATUS = WORK / "status.txt"
METHOD = {"deepseek": "deepseek_flash", "jev": "jev"}
# Parent 12:31 PST: DeepSeek caps raised (from 4.4 / 8.1) so that l3_apirest_L3_r1 and the quiet-latency
# remeasure fit with the cumulative ledger <= CNY 8.25.
STAGE_CAP = {"deepseek": 4.55, "jev": 0.9}
CUMULATIVE_CAP = {"deepseek": 8.25, "jev": 2.2}
EXTENSION_IF_CUMULATIVE_BELOW = 7.4
LATENCY_LOCK = Path("/tmp/cs224_latency.lock")
LATENCY_WAIT_S = 20 * 60
API_REST = LLM_DIR / "dev_check" / "api_rest332_subsets.json"
# Measured stage-2b cost per call (CNY / USD), x1.15 margin for longer layer-3 code and evidence.
PER_CALL = {("deepseek", "L1"): 0.00040, ("deepseek", "L2"): 0.00035, ("deepseek", "L3"): 0.00030,
            ("deepseek", "L4"): 0.00062, ("jev", "L1"): 0.000034, ("jev", "L2"): 0.000064,
            ("jev", "L3"): 0.000037}
status_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with status_lock:
        with STATUS.open("a") as handle:
            handle.write(line + "\n")
    print(line, flush=True)


def uptime() -> str:
    return subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()


def budget_left(model: str, base: dict[str, float]) -> float:
    spent = Ledger().spent(model)
    return min(STAGE_CAP[model] - (spent - base[model]), CUMULATIVE_CAP[model] - spent)


def run(model: str, strategy: str, run_id: str, layer: str, subset: str | None, n_units: int,
        concurrency: int, base: dict[str, float], subsets_file: Path | None = None,
        per_call: float | None = None) -> bool:
    units = BUILD / f"{layer}.jsonl"
    pred = LLM_DIR / "results" / METHOD[model] / layer / f"{run_id}.jsonl"
    score_out = LLM_DIR / "results" / "scores" / METHOD[model] / f"{run_id}.json"
    score_cmd = [sys.executable, str(SCORE), "--pred", str(pred), "--units", str(units), "--set", "eval",
                 "--bootstrap", "1000", "--out", str(score_out)]
    if subset:
        score_cmd += ["--subset", subset]
    if subsets_file:
        score_cmd += ["--subsets-file", str(subsets_file)]
    logfile = WORK / f"{model}_{run_id}.log"
    if pred.exists():
        if not score_out.exists():
            score(model, run_id, pred, score_cmd, logfile)
        log(f"{model} {run_id}: exists, skipped")
        return True
    expected = 1.15 * (per_call or PER_CALL[(model, strategy)]) * n_units
    left = budget_left(model, base)
    if expected > left:
        log(f"{model} {run_id}: SKIPPED, expected {expected:.4f} > budget left {left:.4f}")
        return False
    cap = round(min(1.5 * expected + 0.02, left), 4)
    cmd = [sys.executable, str(LLM_DIR / "run_llm.py"), "--model", model, "--strategy", strategy,
           "--units", str(units), "--layer", layer, "--set", "eval", "--allow-eval",
           "--concurrency", str(concurrency), "--max-cost", str(cap), "--run-id", run_id]
    if subset:
        cmd += ["--subset", subset]
    if subsets_file:
        cmd += ["--subsets-file", str(subsets_file)]
    while True:
        log(f"{model} {run_id}: start (expected {expected:.4f}, cap {cap}; uptime: {uptime()})")
        with logfile.open("a") as handle:
            code = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=LLM_DIR).returncode
        if code == 2 and model == "deepseek" and is_deepseek_peak(utc_now()):
            wake = next_offpeak(utc_now())
            log(f"{model} {run_id}: refused in peak hours; sleeping until {wake.isoformat()}")
            time.sleep(max(60.0, (wake - utc_now()).total_seconds() + 30))
            continue
        break
    log(f"{model} {run_id}: exit {code} (uptime: {uptime()})")
    if not pred.exists():
        return False
    score(model, run_id, pred, score_cmd, logfile)
    return code == 0


def score(model: str, run_id: str, pred: Path, score_cmd: list[str], logfile: Path) -> None:
    out = Path(score_cmd[score_cmd.index("--out") + 1])
    out.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("a") as handle:
        subprocess.run(score_cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=JF)
    meta = json.loads(pred.with_suffix(".meta.json").read_text())
    rep = json.loads(out.read_text())["end_to_end"] if out.exists() else {}
    log(f"{model} {run_id}: {meta['status_counts']} cost {meta['cost_total']} {meta['cost_currency']} "
        f"macroF1 {rep.get('macro_f1')} fp {rep.get('fp')} fn {rep.get('fn')} invalid {rep.get('invalid')}")


def wait_for_inflight_runs() -> None:
    """Block while a stage-2c run_llm.py (started by an earlier driver) is still running."""
    while True:
        found = subprocess.run(["pgrep", "-f", "run_llm.py .*--run-id (eval_L4_r1|l3_|pl_|orig_|lat300_c1_L1_quiet)"],
                               capture_output=True, text=True).stdout.split()
        if not found:
            return
        log(f"waiting for in-flight run_llm.py pids {found}")
        time.sleep(30)


def first_base() -> dict[str, float] | None:
    if not STATUS.exists():
        return None
    for line in STATUS.read_text().splitlines():
        if "driver start; ledger base " in line:
            return ast.literal_eval(line.split("ledger base ", 1)[1])
    return None


def wait_quiet(deadline: float) -> bool:
    """True once load1 < 2.5 in every 15-s sample over 2 consecutive minutes; False at the deadline."""
    quiet_since = None
    while time.time() < deadline:
        load1 = os.getloadavg()[0]
        if load1 < 2.5:
            quiet_since = quiet_since or time.time()
            if time.time() - quiet_since >= 120:
                return True
        else:
            quiet_since = None
        time.sleep(15)
    return False


def latency_runs(base: dict[str, float]) -> None:
    deadline = time.time() + LATENCY_WAIT_S
    t0 = time.time()
    with LATENCY_LOCK.open("a") as lock:
        while True:  # flock -w: exclusive lock, give up at the deadline
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() >= deadline:
                    log(f"latency re-measure SKIPPED: {LATENCY_LOCK} not acquired within 20 min")
                    return
                time.sleep(5)
        lock_wait = round(time.time() - t0, 1)
        log(f"latency lock acquired after {lock_wait} s; waiting for load1 < 2.5 over 2 min (uptime: {uptime()})")
        t1 = time.time()
        if not wait_quiet(deadline):
            log(f"latency re-measure SKIPPED: load1 never < 2.5 for 2 min within 20 min (uptime: {uptime()})")
            return
        quiet_wait = round(time.time() - t1, 1)
        for model in ("deepseek", "jev"):
            before = {"loadavg": list(os.getloadavg()), "uptime": uptime()}
            # c1 L1 on latency300 cost CNY 0.000276 / USD 0.000034 per call in stage 2b
            run(model, "L1", "lat300_c1_L1_quiet", "layer1", "latency300", 300, 1, base,
                per_call=0.00030 if model == "deepseek" else None)
            meta_path = LLM_DIR / "results" / METHOD[model] / "layer1" / "lat300_c1_L1_quiet.meta.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                meta["latency_lock"] = {"lock": str(LATENCY_LOCK), "lock_wait_s": lock_wait,
                                        "quiet_wait_s": quiet_wait, "before": before,
                                        "after": {"loadavg": list(os.getloadavg()), "uptime": uptime()}}
                meta_path.write_text(json.dumps(meta, indent=1) + "\n")


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    base = first_base()
    if base is None:
        ledger = Ledger()
        base = {m: ledger.spent(m) for m in METHOD}
        log(f"driver start; ledger base {base}")
    else:
        log(f"driver restart; ledger base of first start {base}")
    wait_for_inflight_runs()

    def deepseek_queue() -> None:
        run("deepseek", "L4", "eval_L4_r1", "layer1", None, 2656, 16, base)
        for s in ("L1", "L3", "L2", "L4"):
            run("deepseek", s, f"l3_n25_{s}_r1", "layer3", "nested25", 664, 16, base)
        for s in ("L1", "L3"):
            run("deepseek", s, f"pl_n25_{s}_r1", "placebo", "nested25", 664, 16, base)
        run("deepseek", "L1", "orig_n25_L1_r1", "original", "nested25", 664, 16, base)
        spent = Ledger().spent("deepseek")
        started = (LLM_DIR / "results" / METHOD["deepseek"] / "layer3" / "l3_apirest_L1_r1.jsonl").exists()
        if spent > EXTENSION_IF_CUMULATIVE_BELOW and not started:
            log(f"deepseek layer3 api_subset extension SKIPPED: cumulative ledger {spent:.4f} > "
                f"{EXTENSION_IF_CUMULATIVE_BELOW}")
            return
        for s in ("L1", "L2", "L3"):
            run("deepseek", s, f"l3_apirest_{s}_r1", "layer3", "api_rest332", 664, 16, base, API_REST)

    def jev_queue() -> None:
        for s in ("L1", "L2", "L3"):
            run("jev", s, f"l3_eval_{s}_r1", "layer3", None, 2656, 8, base)
        for s in ("L1", "L3"):
            run("jev", s, f"pl_eval_{s}_r1", "placebo", None, 2656, 8, base)
        run("jev", "L1", "orig_eval_L1_r1", "original", None, 2656, 8, base)

    threads = [threading.Thread(target=q) for q in (deepseek_queue, jev_queue)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log(f"queues done; latency re-measure: lock {LATENCY_LOCK}, then load1 < 2.5 over 2 min (uptime: {uptime()})")
    latency_runs(base)
    ledger = Ledger()
    log(f"driver done; stage spend deepseek {ledger.spent('deepseek') - base['deepseek']:.6f} CNY, "
        f"jev {ledger.spent('jev') - base['jev']:.6f} USD; cumulative deepseek {ledger.spent('deepseek'):.6f}, "
        f"jev {ledger.spent('jev'):.6f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

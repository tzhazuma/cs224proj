#!/usr/bin/env python3
"""Stage-2b driver (parent brief 2026-11-23 11:10 PST): frozen-prompt eval runs, run under nohup.

Queues (each run = run_llm.py, then analysis/score.py --out results/scores/<method>/<run_id>.json):
  deepseek: eval_L1_r1, eval_L2_r1, eval_L3_r1 (full eval, c16), rep_L{1,2,3}_r{2,3} (repeat100, c16)
  jev (in parallel): dev_L{1,2,3}_r1 (full dev minus L2 groups), eval_L{1,2,3}_r{1,2,3}
  then, with nothing else running: lat300_c1_L1 for deepseek, then for jev (latency300, c1), with uptime.
Stage caps (ledger spend since driver start): deepseek CNY 4.0 minus 0.3 kept for L4 dev; jev USD 1.30.
A deepseek run refused in peak hours (exit 2 while peak) waits for the next off-peak window and retries.
Progress: scratch/stage2b/status.txt; per-run logs scratch/stage2b/<method>_<run_id>.log.
"""

from __future__ import annotations

import argparse
import json
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
UNITS = JF / "data" / "build" / "layer1.jsonl"
SCORE = JF / "analysis" / "score.py"
WORK = LLM_DIR / "scratch" / "stage2b"
STATUS = WORK / "status.txt"
METHOD = {"deepseek": "deepseek_flash", "jev": "jev"}
STAGE_CAP = {"deepseek": 4.0 - 0.3, "jev": 1.30}
status_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with status_lock:
        with STATUS.open("a") as handle:
            handle.write(line + "\n")
    print(line, flush=True)


def uptime() -> str:
    return subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()


def run(model: str, strategy: str, run_id: str, set_: str, subset: str | None, concurrency: int,
        max_cost: float, base: dict[str, float]) -> bool:
    ledger = Ledger()
    stage_left = STAGE_CAP[model] - (ledger.spent(model) - base[model])
    cap = round(min(max_cost, stage_left), 4)
    pred = LLM_DIR / "results" / METHOD[model] / "layer1" / f"{run_id}.jsonl"
    if pred.exists():
        log(f"{model} {run_id}: exists, skipped")
        return True
    if cap <= 0.01:
        log(f"{model} {run_id}: SKIPPED, stage budget left {stage_left:.4f}")
        return False
    cmd = [sys.executable, str(LLM_DIR / "run_llm.py"), "--model", model, "--strategy", strategy,
           "--units", str(UNITS), "--set", set_, "--concurrency", str(concurrency), "--max-cost", str(cap),
           "--run-id", run_id]
    if set_ == "eval":
        cmd.append("--allow-eval")
    if subset:
        cmd += ["--subset", subset]
    logfile = WORK / f"{model}_{run_id}.log"
    while True:
        log(f"{model} {run_id}: start (cap {cap}; uptime: {uptime()})")
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
    out = LLM_DIR / "results" / "scores" / METHOD[model] / f"{run_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    score_cmd = [sys.executable, str(SCORE), "--pred", str(pred), "--units", str(UNITS), "--set", set_,
                 "--bootstrap", "1000" if subset is None else "0", "--out", str(out)]
    if subset:
        score_cmd += ["--subset", subset]
    elif set_ == "dev":  # run_llm.py drops the L2 example groups from dev; score only what was run
        score_cmd += ["--subset", "dev_minus_l2", "--subsets-file",
                      str(LLM_DIR / "dev_check" / "dev_minus_l2_subsets.json")]
    with logfile.open("a") as handle:
        subprocess.run(score_cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=JF)
    meta = json.loads(pred.with_suffix(".meta.json").read_text())
    rep = json.loads(out.read_text())["end_to_end"] if out.exists() else {}
    log(f"{model} {run_id}: {meta['status_counts']} cost {meta['cost_total']} {meta['cost_currency']} "
        f"macroF1 {rep.get('macro_f1')} fp {rep.get('fp')} fn {rep.get('fn')}")
    return code == 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--skip-latency", action="store_true")
    args = p.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    ledger = Ledger()
    base = {m: ledger.spent(m) for m in METHOD}
    log(f"driver start; ledger base {base}")

    def deepseek_queue() -> None:
        for s in ("L1", "L2", "L3"):
            run("deepseek", s, f"eval_{s}_r1", "eval", None, 16, 1.5, base)
        for r in (2, 3):
            for s in ("L1", "L2", "L3"):
                run("deepseek", s, f"rep_{s}_r{r}", "eval", "repeat100", 16, 0.2, base)

    def jev_queue() -> None:
        for s in ("L1", "L2", "L3"):
            run("jev", s, f"dev_{s}_r1", "dev", None, 8, 0.05, base)
        for r in (1, 2, 3):
            for s in ("L1", "L2", "L3"):
                run("jev", s, f"eval_{s}_r{r}", "eval", None, 8, 0.25 if s == "L2" else 0.15, base)

    threads = [threading.Thread(target=q) for q in (deepseek_queue, jev_queue)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if not args.skip_latency:
        run("deepseek", "L1", "lat300_c1_L1", "eval", "latency300", 1, 0.3, base)
        run("jev", "L1", "lat300_c1_L1", "eval", "latency300", 1, 0.05, base)
    ledger = Ledger()
    log(f"driver done; stage spend deepseek {ledger.spent('deepseek') - base['deepseek']:.6f} CNY, "
        f"jev {ledger.spent('jev') - base['jev']:.6f} USD")
    return 0


if __name__ == "__main__":
    sys.exit(main())

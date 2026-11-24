#!/usr/bin/env python3
"""Stage-2e driver (parent brief 2026-11-24 06:10 PST; user decision 06:05), run under nohup. DeepSeek only.

Fills DeepSeek layer3 (DeadFree) L1-L4 to the full eval set with the frozen prompts, same run_llm.py flags as the
stage-2c l3_n25_* / l3_apirest_* runs (--layer layer3 --set eval --allow-eval, concurrency 16, frozen Clang
evidence for L3), restricted by --unit-ids to the parent's lists (copied to results/deepseek_flash/layer3/fill_unit_ids/):
  l3_rest_L1_r1, l3_rest_L3_r1, l3_rest_L2_r1   rest_api_unit_ids.txt (1,328 eval units outside api_subset)
  l3_rest75_L4_r1                               rest_n25_unit_ids.txt (1,992 eval units outside nested25)
Per-run caps CNY 0.75 / 0.50 / 0.75 / 1.90. Before L4 the account balance must be >= CNY 1.80; otherwise poll it
every 10 min for up to 3 h, then stop. A run refused in peak hours waits for off-peak and retries.
Progress: scratch/stage2e/status.txt; per-run logs scratch/stage2e/<run_id>.log. Restartable: existing
predictions are skipped.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR  # noqa: E402
from llmlane.clients import deepseek_balance  # noqa: E402
from llmlane.ledger import Ledger  # noqa: E402
from llmlane.pricing import is_deepseek_peak, next_offpeak, utc_now  # noqa: E402

BUILD = LLM_DIR.parent / "data" / "build"
LISTS = LLM_DIR / "results" / "deepseek_flash" / "layer3" / "fill_unit_ids"
WORK = LLM_DIR / "scratch" / "stage2e"
STATUS = WORK / "status.txt"
RUNS = [("L1", "l3_rest_L1_r1", "rest_api_unit_ids.txt", 0.75),
        ("L3", "l3_rest_L3_r1", "rest_api_unit_ids.txt", 0.50),
        ("L2", "l3_rest_L2_r1", "rest_api_unit_ids.txt", 0.75),
        ("L4", "l3_rest75_L4_r1", "rest_n25_unit_ids.txt", 1.90)]
L4_MIN_BALANCE = 1.80
BALANCE_POLL_S, BALANCE_WAIT_S = 10 * 60, 3 * 3600


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with STATUS.open("a") as handle:
        handle.write(line + "\n")
    print(line, flush=True)


def balance_cny() -> float | None:
    payload = deepseek_balance()
    for info in (payload or {}).get("balance_infos", []):
        if info.get("currency") == "CNY":
            return float(info["total_balance"])
    return None


def wait_balance() -> bool:
    deadline = time.time() + BALANCE_WAIT_S
    while True:
        bal = balance_cny()
        log(f"balance CNY {bal} (L4 needs >= {L4_MIN_BALANCE})")
        if bal is not None and bal >= L4_MIN_BALANCE:
            return True
        if time.time() + BALANCE_POLL_S > deadline:
            return False
        time.sleep(BALANCE_POLL_S)


def run(strategy: str, run_id: str, ids_file: str, cap: float) -> int:
    pred = LLM_DIR / "results" / "deepseek_flash" / "layer3" / f"{run_id}.jsonl"
    if pred.exists():
        log(f"{run_id}: exists, skipped")
        return 0
    cmd = [sys.executable, str(LLM_DIR / "run_llm.py"), "--model", "deepseek", "--strategy", strategy,
           "--units", str(BUILD / "layer3.jsonl"), "--layer", "layer3", "--set", "eval", "--allow-eval",
           "--unit-ids", str(LISTS / ids_file), "--concurrency", "16", "--max-cost", str(cap), "--run-id", run_id]
    while True:
        log(f"{run_id}: start (cap {cap}; ledger {Ledger().spent('deepseek'):.6f})")
        with (WORK / f"{run_id}.log").open("a") as handle:
            code = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, cwd=LLM_DIR).returncode
        if code == 2 and is_deepseek_peak(utc_now()):
            wake = next_offpeak(utc_now())
            log(f"{run_id}: refused in peak hours; sleeping until {wake.isoformat()}")
            time.sleep(max(60.0, (wake - utc_now()).total_seconds() + 30))
            continue
        break
    log(f"{run_id}: exit {code}; ledger {Ledger().spent('deepseek'):.6f}")
    return code


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    log(f"driver start; ledger deepseek {Ledger().spent('deepseek'):.6f}; balance CNY {balance_cny()}")
    for strategy, run_id, ids_file, cap in RUNS:
        if strategy == "L4" and not (LLM_DIR / "results" / "deepseek_flash" / "layer3" / f"{run_id}.jsonl").exists():
            if not wait_balance():
                log("STOP: balance below CNY 1.80 for 3 h; l3_rest75_L4_r1 not run")
                return 1
        if run(strategy, run_id, ids_file, cap) != 0:
            log(f"STOP: {run_id} did not exit 0")
            return 1
    log(f"driver done; ledger deepseek {Ledger().spent('deepseek'):.6f}; balance CNY {balance_cny()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

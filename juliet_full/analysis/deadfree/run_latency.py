#!/usr/bin/env python3
"""DeadFree (layer3) concurrency-1 latency jobs on the latency300 subset, one job at a time from dell.

    nohup python3 run_latency.py ds_L1 ds_L2 jev_L1 clang_sa ... > raw_logs/latency_<tag>.log 2>&1 &

Every job: exclusive flock on /tmp/cs224_latency.lock (shared with the vulnllmr and l4d-train lanes), then the quiet
check (dell load1 < 2.5 on 12 samples 5 s apart; at most 20 min, else the job runs and is labelled LOADED), then the
job's frozen command, then the lock is released (other lanes can take it between jobs). The lock wait, quiet flag and
load before/after are added as "latency_lock" to the meta of the run file the job wrote (new lat300_c1*/lat100_c1*
files only). A job whose output already exists is skipped (rerun = resume).
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JF = HERE.parent.parent
LOCK = Path("/tmp/cs224_latency.lock")
LOAD_LIMIT = 2.5
QUIET_MAX_S = 1200
UNITS3 = str(JF / "data/build/layer3.jsonl")
PY = sys.executable
L4D_PY = str(JF / "l4d/.venv/bin/python")
LLM_COMMON = ["--units", UNITS3, "--set", "eval", "--subset", "latency300", "--layer", "layer3",
              "--concurrency", "1", "--allow-eval"]
# DeepSeek caps (CNY) sum to 0.78 <= lane budget 0.8; Jev caps (USD) sum to 0.05.
DS_CAP = {"L1": "0.18", "L2": "0.18", "L3": "0.12", "L4": "0.30"}
JEV_CAP = {"L1": "0.014", "L2": "0.022", "L3": "0.014"}


def llm_job(model: str, method_dir: str, k: str, cap: str | None) -> tuple[list[str], Path, Path]:
    cmd = [PY, str(JF / "llm/run_llm.py"), "--model", model, "--strategy", k, *LLM_COMMON,
           "--run-id", f"lat300_c1_{k}"]
    if cap is not None:
        cmd += ["--max-cost", cap]
    return cmd, JF / "llm", JF / f"llm/results/{method_dir}/layer3/lat300_c1_{k}.jsonl"


def static_job(tool: str) -> tuple[list[str], Path, Path]:
    run_id = "lat100_c1" if tool == "codeql" else "lat300_c1"
    cmd = [PY, str(JF / "static/run_static.py"), "--tool", tool, "--units", UNITS3, "--set", "eval",
           "--subset", "latency300", "--layer", "layer3", "--no-evidence", "--run-id", run_id]
    if tool == "infer":
        cmd += ["--tu-mode", "per_file"]  # frozen layer3 config full_per_file
    if tool == "codeql":
        cmd += ["--limit", "100"]  # per-unit database + queries, capped at 100 units
    return cmd, JF / "static", JF / f"static/results/{tool}/layer3/{run_id}.jsonl"


def jobs() -> dict[str, tuple[list[str], Path, Path]]:
    out = {}
    for k in ("L1", "L2", "L3", "L4"):
        out[f"ds_{k}"] = llm_job("deepseek", "deepseek_flash", k, DS_CAP[k])
        out[f"qwen_{k}"] = llm_job("qwen", "qwen3_5_4b", k, "0")
    for k in ("L1", "L2", "L3"):
        out[f"jev_{k}"] = llm_job("jev", "jev", k, JEV_CAP[k])
        out[f"intern_{k}"] = ([PY, str(JF / "gpu/run_decide.py"), "run", "--units", UNITS3, "--set", "eval",
                               "--subset", "latency300", "--layer", "layer3", "--strategy", k, "--concurrency", "1",
                               "--run-id", f"lat300_c1_{k}"], JF / "gpu",
                              JF / f"gpu/results/intern_decision/layer3/lat300_c1_{k}.jsonl")
        # intern_{k}: :8002 with the transformers reference causal_conv1d (primary, = stored predictions);
        # intern_{k}_kernel: :8002 restarted with the built kernel (secondary, not score-identical)
        cmd = [c if c != f"lat300_c1_{k}" else f"lat300_c1_{k}_kernel" for c in out[f"intern_{k}"][0]]
        out[f"intern_{k}_kernel"] = (cmd, JF / "gpu",
                                     JF / f"gpu/results/intern_decision/layer3/lat300_c1_{k}_kernel.jsonl")
    for suffix, note in (("", "causal_conv1d reference fallback (transformers), = stored predictions"),
                         ("_kernel", "causal_conv1d 1.7.0 built kernel (pyext_cc1d), not score-identical")):
        out[f"intern_l4d{suffix}"] = ([L4D_PY, str(JF / "gpu/run_decide_l4d.py"), "latency", "--run-id",
                                      f"lat300_c1{suffix}", "--kernel-note", note], JF / "gpu",
                                     JF / f"l4d_ft/results/intern_l4d/layer3/lat300_c1{suffix}.jsonl")
    for tool in ("clang_sa", "cppcheck", "infer", "grep_v0", "codeql"):
        out[tool] = static_job(tool)
    for method in ("asan_lsan", "dynamic_enhanced"):
        out[method] = ([PY, str(HERE / "dyn_latency.py"), method], JF / "data",
                       JF / f"data/results/{method}/stress/lat300_c1.jsonl")
    return out


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"{utc()} {msg}", flush=True)


def wait_quiet() -> tuple[bool, list[float]]:
    deadline = time.time() + QUIET_MAX_S
    while True:
        samples = []
        for _ in range(12):
            samples.append(round(os.getloadavg()[0], 2))
            if samples[-1] >= LOAD_LIMIT:
                break
            time.sleep(5)
        if len(samples) == 12 and max(samples) < LOAD_LIMIT:
            return True, samples
        if time.time() >= deadline:
            return False, samples
        time.sleep(30)


def run(name: str, spec: tuple[list[str], Path, Path], extra_env: dict[str, str]) -> int:
    cmd, cwd, out = spec
    if out.exists():
        log(f"{name}: {out.relative_to(JF)} exists, skipped")
        return 0
    t0 = time.time()
    with LOCK.open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        lock_wait = round(time.time() - t0, 1)
        t1 = time.time()
        quiet, samples = wait_quiet()
        info = {"lock": str(LOCK), "lock_wait_s": lock_wait, "quiet": quiet, "quiet_wait_s": round(time.time() - t1, 1),
                "load1_samples": samples, "load_before": os.getloadavg(), "start_utc": utc(), "job": name,
                "driver": "analysis/deadfree/run_latency.py"}
        log(f"{name}: lock after {lock_wait} s, quiet={quiet} {samples[-3:]}; {' '.join(cmd[1:])}")
        rc = subprocess.run(cmd, cwd=cwd, env={**os.environ, **extra_env}).returncode
        info.update(load_after=os.getloadavg(), end_utc=utc(), rc=rc)
    meta = out.with_suffix(".meta.json")
    if meta.exists():
        m = json.loads(meta.read_text())
        m["latency_lock"] = info
        meta.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n")
    log(f"{name}: rc={rc} in {info['end_utc']} (load after {info['load_after'][0]:.2f})")
    return rc


def main() -> int:
    table = jobs()
    names = sys.argv[1:]
    unknown = [n for n in names if n not in table]
    if unknown or not names:
        print(f"unknown/no jobs {unknown}; choose from {sorted(table)}")
        return 2
    worst = 0
    for name in names:
        worst = max(worst, run(name, table[name], {}))
    return worst


if __name__ == "__main__":
    sys.exit(main())

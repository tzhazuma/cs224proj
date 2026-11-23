#!/usr/bin/env bash
# One line per job: state, phase, last dev eval; plus GPU use and worker tails.
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
"$VENV/bin/python" - <<'EOF'
import json, pathlib
for line in pathlib.Path("queue.txt").read_text().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    strategy, fold = line.split()[:2]
    job = f"{strategy}_fold{fold}"
    path = pathlib.Path("status") / f"{job}.json"
    claimed = (pathlib.Path("status") / f"{job}.claim").exists()
    if not path.exists():
        print(f"{job:10s} {'claimed' if claimed else 'pending'}")
        continue
    s = json.loads(path.read_text())
    log = pathlib.Path(strategy) / f"fold{fold}" / "train_log.jsonl"
    last_train = None
    if log.exists():
        for l in log.read_text().splitlines():
            r = json.loads(l)
            if r.get("type") == "train":
                last_train = r
    info = pathlib.Path("status") / f"{job}.claim" / "info"
    rc = [x for x in info.read_text().split() if x.startswith("rc=")] if info.exists() else []
    tr = (f"step {last_train['step']} ep {last_train['epoch']:.2f} loss {last_train['loss']:.4f} "
          f"{last_train['tokens_per_s']:.0f} tok/s {last_train['peak_mem_gb']} GB") if last_train else ""
    print(f"{job:10s} {s['state']:7s} {s['phase']:14s} gpu={s.get('cuda_visible_devices')} {tr} "
          f"step0_auroc={s.get('dev_auroc_step0')} last_eval={s.get('last_eval')} selected={s.get('selected')} "
          f"{' '.join(rc)} updated={s.get('updated_utc')}")
EOF
nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv,noheader
tail -n 2 logs/worker0.log logs/worker1.log 2>/dev/null

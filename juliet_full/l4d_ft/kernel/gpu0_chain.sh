#!/usr/bin/env bash
# kernel/gpu0_chain.sh   (dell, detached) remaining GPU-0 work of lane l4d-train, no agent needed:
#   1. wait for the running `kernel/lat_all.sh fallback ...` (L4-D opt+full latency300 c1 on layer3 then layer1,
#      against serve_l4d.sh on GPU0, L4D_KERNEL=0) to finish
#   2. stop the :8004 instance on GPU0 (serve_l4d.sh stop)
#   3. start :8003 in the prediction config (`bash ~/disk4/cs224/decision_ft/server/serve.sh start`, no kernel),
#      wait for /health
#   4. old LoRA L1/L3 latency300 c1 on DeadFree (layer3) under flock (kernel/dft_lat300.py --tag fallback)
#   5. leave :8003 running, touch ~/disk4/cs224/GPU0_L4D_DONE
# Log: raw_logs/gpu0_chain.log (UTC timestamps per step).
set -uo pipefail
cd "$(dirname "$0")/.."
log() { echo "$(date -u +%FT%TZ) $*"; }
{
  log "chain start"
  while pgrep -f "bash kernel/lat_all.sh fallback" > /dev/null; do sleep 30; done
  log "lat_all fallback finished: $(grep -c '^{"run"' raw_logs/lat_fallback.log) equivalence lines"
  ssh 184-toast 'bash ~/disk4/cs224/l4d_ft/server/serve_l4d.sh stop'
  sleep 10
  ssh 184-toast 'nvidia-smi --query-gpu=index,memory.used --format=csv,noheader'
  log "start :8003 (serve.sh start, prediction config)"
  ssh 184-toast 'bash ~/disk4/cs224/decision_ft/server/serve.sh start'
  for _ in $(seq 60); do
    curl -fsS -m 5 --noproxy '*' http://10.15.89.184:8003/health > /dev/null 2>&1 && break
    sleep 10
  done
  log ":8003 health: $(curl -sS -m 5 --noproxy '*' http://10.15.89.184:8003/health)"
  while awk '{exit !($1 >= 2.5)}' /proc/loadavg; do sleep 15; done
  log "old LoRA L1/L3 latency300 DeadFree (flock)"
  PYTHONPYCACHEPREFIX=/tmp/l4dft-pycache flock /tmp/cs224_latency.lock python3 kernel/dft_lat300.py --tag fallback --layer layer3
  log "dft_lat300 exit $?"
  log ":8003 health: $(curl -sS -m 5 --noproxy '*' http://10.15.89.184:8003/health)"
  ssh 184-toast 'touch ~/disk4/cs224/GPU0_L4D_DONE; nvidia-smi --query-gpu=index,memory.used --format=csv,noheader'
  log "touched GPU0_L4D_DONE; chain done"
} >> raw_logs/gpu0_chain.log 2>&1

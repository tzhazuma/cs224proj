#!/usr/bin/env bash
# serve_l4d.sh start|stop|health|status   L4-D decision endpoint (lane l4d-train), port 8004, GPU $L4D_GPU (default 1).
#   l4dft.py serve --port 8004 --frozen FROZEN: the 3 frozen fold models (merged LoRA, cached on the GPU, ~15 GB)
#   with their frozen tau. POST /l4d {"fold": k, "questions": [{"qid", "state", "question"}, ...]} -> p_yes per
#   question (one forward batch); GET /health. Request format + e2e verdict recipe: juliet_full/l4d_ft/REPORT_stage1.md.
#   Default L4D_KERNEL=0 = the PyTorch causal_conv1d fallback that produced the frozen predictions (the kernel moved
#   p_yes by up to 0.985 and flipped a unit verdict on DeadFree latency300: results/scores/kernel_equiv_*.json), so
#   live verdicts match the stored results. L4D_KERNEL=1 puts the causal_conv1d 1.7.0 kernel
#   (~/disk4/cs224/pyext_cc1d) on PYTHONPATH (secondary latency rows only).
#   Log ~/disk4/cs224/l4d_ft/logs/serve_l4d.log, pid ~/disk4/cs224/l4d_ft/run/serve_l4d.pid; ready ~20 s after start.
set -euo pipefail
source "$HOME/disk4/cs224/l4d_ft/server/env.sh"
cd "$L4D"; mkdir -p run logs
ACTION=${1:?usage: serve_l4d.sh start|stop|health|status}
PORT=8004
PIDFILE=$L4D/run/serve_l4d.pid
LOG=$L4D/logs/serve_l4d.log
HEALTH_URL=http://127.0.0.1:$PORT/health
PYPATH=${PYTHONPATH:-}
if [[ ${L4D_KERNEL:-0} == 1 ]]; then PYPATH=$HOME/disk4/cs224/pyext_cc1d${PYPATH:+:$PYPATH}; fi
CMD=(env CUDA_VISIBLE_DEVICES=${L4D_GPU:-1} PYTHONPATH="$PYPATH" "$VENV/bin/python" server/l4dft.py serve
     --port $PORT --frozen FROZEN)

running() { [[ -f $PIDFILE ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case $ACTION in
  start)
    if running; then echo "serve_l4d already running (pid $(cat "$PIDFILE"))"; exit 0; fi
    echo "=== start $(date -u +%FT%TZ) ${CMD[*]}" >> "$LOG"
    nohup setsid "${CMD[@]}" >> "$LOG" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
    echo "serve_l4d started (pid $(cat "$PIDFILE"), GPU ${L4D_GPU:-1}, kernel ${L4D_KERNEL:-0}), log $LOG"
    ;;
  stop)
    if ! running; then echo "serve_l4d not running"; rm -f "$PIDFILE"; exit 0; fi
    PID=$(cat "$PIDFILE")
    kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID"
    for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$PID" 2>/dev/null; then kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID"; fi
    rm -f "$PIDFILE"
    echo "serve_l4d stopped"
    ;;
  health)
    if curl -fsS -m 5 "$HEALTH_URL"; then echo; else echo "serve_l4d NOT healthy"; exit 1; fi
    ;;
  status)
    if running; then echo "serve_l4d running (pid $(cat "$PIDFILE"))"; else echo "serve_l4d not running"; fi
    nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv,noheader
    ;;
  *) echo "unknown action $ACTION" >&2; exit 2 ;;
esac

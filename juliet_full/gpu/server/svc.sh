#!/usr/bin/env bash
# Start/stop/health for the two 184-toast services.
#   svc.sh qwen   start|stop|health|status   vLLM OpenAI API, Qwen3.5-4B, GPU $QWEN_GPU (default 1), port 8001
#   svc.sh decide start|stop|health|status   Intern-Decision-4B read-out, GPU $DECIDE_GPU (default 1), port 8002
# Both share GPU 1 by default (GPU 0 belongs to the decision_ft lane); start qwen first, then decide:
# vLLM checks at start-up that QWEN_GPU_UTIL x 24 GiB is still free on its GPU.
# Logs: ~/disk4/cs224/logs/<name>.log   pid files: ~/disk4/cs224/run/<name>.pid
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"

NAME=${1:?usage: svc.sh qwen|decide start|stop|health|status}
ACTION=${2:?usage: svc.sh qwen|decide start|stop|health|status}
PIDFILE=$RUN/$NAME.pid
LOG=$LOGS/$NAME.log

case $NAME in
  qwen)
    PORT=8001
    HEALTH_URL=http://127.0.0.1:$PORT/health
    QWEN_GPU_UTIL=${QWEN_GPU_UTIL:-0.45}
    CMD=(env CUDA_VISIBLE_DEVICES=${QWEN_GPU:-1} "$VENV/bin/vllm" serve "$MODELS/Qwen3.5-4B"
         --served-model-name qwen3.5-4b --host 0.0.0.0 --port $PORT
         --dtype bfloat16 --max-model-len 8192 --enable-prefix-caching
         --language-model-only --gpu-memory-utilization "$QWEN_GPU_UTIL" --max-num-seqs 64
         --default-chat-template-kwargs '{"enable_thinking": false}'
         --generation-config vllm)
    ;;
  decide)
    PORT=8002
    HEALTH_URL=http://127.0.0.1:$PORT/health
    CMD=(env CUDA_VISIBLE_DEVICES=${DECIDE_GPU:-1} "$VENV/bin/python" "$HERE/decide_server.py"
         --checkpoint "$MODELS/Intern-Decision-4B" --host 0.0.0.0 --port $PORT)
    ;;
  *) echo "unknown service $NAME" >&2; exit 2 ;;
esac

running() { [[ -f $PIDFILE ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case $ACTION in
  start)
    if running; then echo "$NAME already running (pid $(cat "$PIDFILE"))"; exit 0; fi
    echo "=== start $(date -u +%FT%TZ) ${CMD[*]}" >> "$LOG"
    nohup setsid "${CMD[@]}" >> "$LOG" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
    echo "$NAME started (pid $(cat "$PIDFILE")), log $LOG"
    ;;
  stop)
    if ! running; then echo "$NAME not running"; rm -f "$PIDFILE"; exit 0; fi
    PID=$(cat "$PIDFILE")
    kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID"
    for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$PID" 2>/dev/null; then kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID"; fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
    ;;
  health)
    if curl -fsS -m 5 "$HEALTH_URL" > /dev/null; then echo "$NAME healthy ($HEALTH_URL)"; else echo "$NAME NOT healthy"; exit 1; fi
    ;;
  status)
    if running; then echo "$NAME running (pid $(cat "$PIDFILE"))"; else echo "$NAME not running"; fi
    nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv,noheader
    ;;
  *) echo "unknown action $ACTION" >&2; exit 2 ;;
esac

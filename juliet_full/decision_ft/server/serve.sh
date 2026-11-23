#!/usr/bin/env bash
# Fine-tuned decision-model endpoint on GPU 0, port 8003 (contract section 6): serve.sh start|stop|status
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
mkdir -p run
pidfile=run/serve.pid
running() { [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; }
case "${1:-status}" in
  start)
    running && { echo "already running (pid $(cat "$pidfile"))"; exit 0; }
    CUDA_VISIBLE_DEVICES=0 setsid nohup "$VENV/bin/python" server/stage2.py serve --port 8003 \
      >> logs/serve.log 2>&1 < /dev/null &
    echo $! > "$pidfile"
    echo "started pid $! (ready when logs/serve.log prints \"ready\", ~1-2 min)";;
  stop)
    running || { echo "not running"; exit 0; }
    kill "$(cat "$pidfile")"
    for _ in $(seq 30); do running || break; sleep 1; done
    running && kill -9 "$(cat "$pidfile")"
    rm -f "$pidfile"; echo "stopped";;
  status)
    running && echo "running pid $(cat "$pidfile")" || echo "not running"
    curl -s -m 5 http://127.0.0.1:8003/health; echo;;
esac

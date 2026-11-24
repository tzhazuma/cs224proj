#!/usr/bin/env bash
# chain_train.sh <wait-queue>... : detached; waits until every named queue (status/<q>.queue) is no longer "running",
# then trains fold 1 and fold 2 back to back with 2-GPU DDP (same config as fold 0). logs/chain_train.log
set -euo pipefail
source "$HOME/disk4/cs224/l4d_ft/server/env.sh"
cd "$L4D"
setsid nohup bash -c '
  for q in "$@"; do
    while [ "$(cat "status/$q.queue" 2>/dev/null)" = running ]; do sleep 10; done
    echo "$(date -u +%FT%TZ) queue $q: $(cat "status/$q.queue")"
  done
  for k in 1 2; do
    bash server/job.sh "fold$k" 0,1 train --fold "$k" --train "data/train_fold$k.jsonl" --dev data/q_layer1.jsonl \
      --epochs 1.5 --evals-per-epoch 2
    sleep 60
    while ! grep -q "\"state\": \"done\"" "status/fold$k.json" 2>/dev/null; do
      kill -0 "$(cat "run/fold$k.pid")" 2>/dev/null || { echo "$(date -u +%FT%TZ) fold$k died"; exit 1; }
      sleep 30
    done
    echo "$(date -u +%FT%TZ) fold$k done"
    sleep 20
  done
' _ "$@" >> logs/chain_train.log 2>&1 < /dev/null &
echo "chain started pid $!"

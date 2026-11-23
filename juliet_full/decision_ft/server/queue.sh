#!/usr/bin/env bash
# Queue worker for one GPU: queue.sh <gpu>. Start one worker per GPU (start_queue.sh).
# Jobs are lines "<strategy> <fold> <max_epochs>" in $DFT/queue.txt, taken in file order; a job is claimed
# atomically with mkdir $DFT/status/<job>.claim, so each job runs once and never two jobs share a GPU.
# Jobs whose rendered data is not on the server yet are skipped (re-checked after every finished job), so
# appending lines to queue.txt while workers run is safe. A worker exits when nothing claimable is left.
set -uo pipefail
GPU=$1
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
[ -f "$CS224/GPU_FREE_FOR_FT" ] || { echo "no $CS224/GPU_FREE_FOR_FT"; exit 1; }
while true; do
  picked=""
  while read -r strategy fold epochs _; do
    [[ -z "${strategy:-}" || "$strategy" == \#* ]] && continue
    job="${strategy}_fold${fold}"
    [ -f "data/$strategy/fold$fold/train.jsonl" ] || continue
    if mkdir "status/$job.claim" 2>/dev/null; then picked="$strategy $fold $epochs"; break; fi
  done < queue.txt
  [ -z "$picked" ] && { echo "$(date -u +%FT%TZ) gpu$GPU: queue empty, exit"; exit 0; }
  read -r strategy fold epochs <<< "$picked"
  job="${strategy}_fold${fold}"
  # never share a card: wait until no compute process is on this GPU
  while [ -n "$(nvidia-smi -i "$GPU" --query-compute-apps=pid --format=csv,noheader)" ]; do
    echo "$(date -u +%FT%TZ) gpu$GPU: busy, waiting"; sleep 60
  done
  echo "$(date -u +%FT%TZ) gpu$GPU: start $job epochs=$epochs"
  echo "gpu=$GPU worker_pid=$$ start=$(date -u +%FT%TZ)" > "status/$job.claim/info"
  CUDA_VISIBLE_DEVICES=$GPU "$VENV/bin/python" server/dft.py train --strategy "$strategy" --fold "$fold" \
    --max-epochs "$epochs" > "logs/$job.log" 2>&1
  rc=$?
  echo "rc=$rc end=$(date -u +%FT%TZ)" >> "status/$job.claim/info"
  echo "$(date -u +%FT%TZ) gpu$GPU: end $job rc=$rc"
done

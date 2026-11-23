#!/usr/bin/env bash
# Stage 2 on GPU 0 only, sequential: predictions of the six fold models on all layers, zero-shot read-out,
# CV files, then the :8003 endpoint. Each step waits until its training job is done and GPU 0 is free.
# Start: setsid nohup bash server/stage2_run.sh >> logs/stage2.log 2>&1 < /dev/null &
# A finished step leaves logs/stage2_<step>.done, so re-running skips it.
set -uo pipefail
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
export CUDA_VISIBLE_DEVICES=0
gpu0_free() { [ -z "$(nvidia-smi -i 0 --query-compute-apps=pid --format=csv,noheader)" ]; }
job_done() { [ -f "status/$1.json" ] && grep -q '"state": "done"' "status/$1.json"; }
run_step() {  # run_step <name> <training job to wait for or -> <stage2.py args...>
  local name=$1 job=$2; shift 2
  [ -f "logs/stage2_$name.done" ] && { echo "$(date -u +%FT%TZ) skip $name (done)"; return 0; }
  [ "$job" = "-" ] || until job_done "$job"; do sleep 60; done
  until gpu0_free; do sleep 30; done
  echo "$(date -u +%FT%TZ) start $name"
  "$VENV/bin/python" server/stage2.py "$@" > "logs/stage2_$name.log" 2>&1
  local rc=$?
  echo "$(date -u +%FT%TZ) end $name rc=$rc"
  [ $rc -eq 0 ] && touch "logs/stage2_$name.done"
  return 0
}
run_step predict_L1_fold0 L1_fold0 predict --strategy L1 --fold 0
run_step predict_L1_fold1 L1_fold1 predict --strategy L1 --fold 1
run_step predict_L1_fold2 L1_fold2 predict --strategy L1 --fold 2
run_step predict_L3_fold0 L3_fold0 predict --strategy L3 --fold 0
run_step predict_L3_fold1 L3_fold1 predict --strategy L3 --fold 1
run_step predict_L3_fold2 L3_fold2 predict --strategy L3 --fold 2
run_step readout_L1 - readout --strategy L1
run_step readout_L3 - readout --strategy L3
run_step combine - combine
until gpu0_free; do sleep 30; done
bash server/serve.sh start
echo "$(date -u +%FT%TZ) stage2 chain finished"

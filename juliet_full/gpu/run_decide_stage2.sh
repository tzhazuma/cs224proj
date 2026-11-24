#!/usr/bin/env bash
# Stage-2 Intern-Decision zero-shot sequence (order fixed by the parent):
#   a. layer1 dev L1-L3, then `freeze` (secondary thresholds -> results/intern_decision/FROZEN) before any eval call
#   b. layer1 eval L1-L3   c. layer3 eval L1-L3   d. placebo eval L1, L3   e. original eval L1
#   f. determinism: layer1 eval L1 again on 50 units (stratified --limit 50) -> det50_L1_r2
# Existing outputs are kept (a run whose .jsonl exists is skipped), so the script can be resumed.
set -euo pipefail
cd "$(dirname "$0")"
B=../data/build
OUT=results/intern_decision
run() {  # run <layer> <set> <strategy> <run_id> [extra args]
  local layer=$1 set=$2 strategy=$3 run_id=$4; shift 4
  if [[ -f $OUT/$layer/$run_id.jsonl ]]; then echo "skip $layer/$run_id (exists)"; return; fi
  local units=$B/$layer.jsonl
  python3 run_decide.py run --units "$units" --layer "$layer" --set "$set" --strategy "$strategy" --run-id "$run_id" "$@"
}
for s in L1 L2 L3; do run layer1 dev $s dev_${s}_r1; done
[[ -f $OUT/FROZEN ]] || python3 run_decide.py freeze --dev-runs dev_L1_r1 dev_L2_r1 dev_L3_r1
for s in L1 L2 L3; do run layer1 eval $s eval_${s}_r1; done
for s in L1 L2 L3; do run layer3 eval $s l3_eval_${s}_r1; done
for s in L1 L3; do run placebo eval $s pl_eval_${s}_r1; done
run original eval L1 orig_eval_L1_r1
run layer1 eval L1 det50_L1_r2 --limit 50
echo "stage2 decide sequence done $(date -u +%FT%TZ)"

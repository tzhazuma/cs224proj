#!/usr/bin/env bash
# One-command VulnLLM-R-7B run plan (RUNBOOK.md). Run on dell, from anywhere:
#   nohup juliet_full/vulnllmr/run_all.sh <gpus> > juliet_full/vulnllmr/raw_logs/run_all.log 2>&1 &
#   <gpus> = 1 (one RTX 3090) or 0,1 (both; vLLM data parallel behind port 8005)
# Steps: start server on 184-toast -> health -> layer1 dev -> layer1 eval -> layer3 eval -> placebo eval ->
# original eval -> c1 latency (layer1 latency300) -> [optional nested25 no-hint] -> score -> stop server.
# Every run is resumable: rerunning this script skips finished units.  Env:
#   VULNLLMR_NOHINT=1   also run the optional layer1 nested25 --cwe-hint none run
#   VULNLLMR_KEEP=1     leave the server running at the end
#   VULNLLMR_BASE_URL   default http://10.15.89.184:8005/v1
#   VULNLLMR_C1_GROUPS  cap c1 latency to N stratified latency300 groups (run_id lat<2N>_c1_policy_r1); empty = all 150
#   VULNLLMR_LOCK_WAIT  c1: max seconds to wait for /tmp/cs224_latency.lock + quiet load (default 43200)
set -euo pipefail
GPUS=${1:?usage: run_all.sh <gpu index: 0, 1 or 0,1>}
HERE=$(cd "$(dirname "$0")" && pwd)
JF=$(dirname "$HERE")
BASE_URL=${VULNLLMR_BASE_URL:-http://10.15.89.184:8005/v1}
SERVE="bash ~/disk4/cs224/vulnllmr/serve_vulnllmr.sh"
RES=$HERE/results/vulnllm_r_7b
ts() { date -u +%FT%TZ; }

stop_server() { [[ ${VULNLLMR_KEEP:-0} == 1 ]] || ssh 184-toast "$SERVE stop" || true; }

echo "[$(ts)] start server on GPU $GPUS"
ssh 184-toast "$SERVE start $GPUS"
trap stop_server EXIT
for i in $(seq 120); do
  if curl -fsS -m 5 "${BASE_URL%/v1}/health" > /dev/null 2>&1 \
     && curl -fsS -m 5 "$BASE_URL/models" | grep -q vulnllm-r-7b; then
    echo "[$(ts)] server healthy"; break
  fi
  if ! ssh 184-toast "$SERVE status" | grep -q 'running (pid'; then
    echo "[$(ts)] server died; tail of log:"; ssh 184-toast 'tail -40 ~/disk4/cs224/vulnllmr/logs/vulnllmr.log'
    exit 1
  fi
  (( i == 120 )) && { echo "[$(ts)] server not healthy after 10 min"; exit 1; }
  sleep 5
done

run() {  # run <layer> <set> [extra runner args...]
  local layer=$1 set=$2; shift 2
  echo "[$(ts)] run $layer $set $*"
  python3 "$HERE/run_vulnllmr.py" --layer "$layer" --set "$set" --base-url "$BASE_URL" "$@"
}
score() {  # score <layer> <run_id> <set> [--subset name]
  local layer=$1 run_id=$2 set=$3; shift 3
  python3 "$JF/analysis/score.py" --pred "$RES/$layer/$run_id.jsonl" --units "$JF/data/build/$layer.jsonl" \
    --set "$set" "$@" --json --out "$RES/$layer/$run_id.score.json" > /dev/null
  echo "[$(ts)] scored $layer/$run_id -> $RES/$layer/$run_id.score.json"
}

run layer1 dev;  score layer1 dev_policy_r1 dev
run layer1 eval; score layer1 eval_policy_r1 eval
for layer in layer3 placebo original; do
  run "$layer" eval; score "$layer" eval_policy_r1 eval
done
C1_GROUPS=${VULNLLMR_C1_GROUPS:-}
echo "[$(ts)] c1 latency (layer1 latency300${C1_GROUPS:+, $C1_GROUPS stratified groups})"
python3 "$HERE/run_vulnllmr.py" --layer layer1 --c1-latency --base-url "$BASE_URL" \
  --lock-wait "${VULNLLMR_LOCK_WAIT:-43200}" ${C1_GROUPS:+--c1-groups "$C1_GROUPS"}
if [[ -n $C1_GROUPS ]]; then
  C1_ID=lat$((2 * C1_GROUPS))_c1_policy_r1
  python3 - "$RES/layer1/$C1_ID.jsonl" "$HERE/build/subsets_$C1_ID.json" <<'EOF'
import json, sys
groups = sorted({json.loads(line)["unit_id"].rsplit("__", 1)[0] for line in open(sys.argv[1])})
json.dump({"c1_capped": groups}, open(sys.argv[2], "w"))
EOF
  score layer1 "$C1_ID" eval --subset c1_capped --subsets-file "$HERE/build/subsets_$C1_ID.json"
else
  score layer1 lat300_c1_policy_r1 eval --subset latency300
fi
if [[ ${VULNLLMR_NOHINT:-0} == 1 ]]; then
  run layer1 eval --subset nested25 --cwe-hint none; score layer1 n25_nohint_r1 eval --subset nested25
fi
echo "[$(ts)] all done"

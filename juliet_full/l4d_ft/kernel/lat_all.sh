#!/usr/bin/env bash
# kernel/lat_all.sh <tag> <gpu-note> <spec>...   (dell) L4-D latency300 c1 runs against the :8004 endpoint now up.
#   <spec> = opt:<layer> (lora_l4d_opt) | full:<layer> (lora_l4d); run in the given order (DeadFree = layer3 first).
#   Each run under flock /tmp/cs224_latency.lock after dell load1 < 2.5, followed by the live-vs-stored equivalence
#   check (kernel/compare_l4d.py). Output results/<method>/<layer>/lat300_c1_<tag>.jsonl
set -euo pipefail
cd "$(dirname "$0")/.."
tag=$1; note=$2; shift 2
PY=../l4d/.venv/bin/python
export PYTHONPYCACHEPREFIX=/tmp/l4dft-pycache
for spec in "$@"; do
  kind=${spec%%:*}; layer=${spec#*:}
  case $kind in opt) flag=--prune; method=lora_l4d_opt ;; full) flag=; method=lora_l4d ;; *) echo "bad $spec"; exit 1 ;; esac
  while awk '{exit !($1 >= 2.5)}' /proc/loadavg; do sleep 15; done
  echo "$(date -u +%FT%TZ) start $spec"
  flock /tmp/cs224_latency.lock $PY latency.py --layer "$layer" $flag --run-id "lat300_c1_$tag" --gpu-note "$note"
  $PY kernel/compare_l4d.py --run "results/$method/$layer/lat300_c1_$tag.jsonl"
done
echo "$(date -u +%FT%TZ) all done"

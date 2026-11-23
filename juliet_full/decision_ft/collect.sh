#!/usr/bin/env bash
# Pull finished decision_ft results from 184-toast to dell (safe to run repeatedly, also while jobs run).
#   predictions (contract section 4): results/decision_ft/layer1/<strategy>_fold<k>_v1.jsonl (+ .meta.json)
#                                     results/decision_ft/layer1/dev_<strategy>_fold<k>_v1.jsonl (+ .meta.json)
#   per-job small artifacts:          runs/<strategy>/fold<k>/{config,selection,dev_metrics}.json, train_log.jsonl,
#                                     adapter_config.json; with --adapters also adapter_model.safetensors, head.pt
#   speed tests:                      runs/speedtest/
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REMOTE=184-toast:disk4/cs224/decision_ft
mkdir -p "$HERE/results/decision_ft/layer1" "$HERE/runs"
extra=()
[ "${1:-}" = "--adapters" ] && extra=(--include='adapter_model.safetensors' --include='head.pt')
for strategy in L1 L3; do
  for fold in 0 1 2; do
    rsync -a "$REMOTE/$strategy/fold$fold/results/" "$HERE/results/decision_ft/layer1/" 2>/dev/null || true
    mkdir -p "$HERE/runs/$strategy/fold$fold"
    rsync -a --include='config.json' --include='selection.json' --include='dev_metrics.json' \
      --include='train_log.jsonl' --include='adapter_config.json' "${extra[@]}" --exclude='*' \
      "$REMOTE/$strategy/fold$fold/" "$HERE/runs/$strategy/fold$fold/" 2>/dev/null || true
  done
done
rsync -a "$REMOTE/speedtest/" "$HERE/runs/speedtest/" 2>/dev/null || true
ls -l "$HERE/results/decision_ft/layer1/"

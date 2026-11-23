#!/usr/bin/env bash
# Pull decision_ft results from 184-toast to dell (safe to run repeatedly, also while jobs run).
#   predictions (contract section 4, written by server/stage2.py):
#     results/decision_ft/<layer>/<strategy>_fold<k>_v1.jsonl   held-out fold k, merged model (reported)
#     results/decision_ft/<layer>/<strategy>_cv_v1.jsonl        the three folds together (all eval units)
#     results/decision_ft/layer1/dev_<strategy>_fold<k>_v1.jsonl dev units, merged (threshold chosen on them)
#     results/decision_ft/layer1/unmerged_<strategy>_fold<k>_v1.jsonl   appendix check (adapter not merged)
#     results/qwen_readout_zeroshot/<layer>/[dev_]<strategy>_v1.jsonl   zero-shot read-out ablation
#   per-job small artifacts: runs/<strategy>/fold<k>/{config,selection,dev_metrics}.json, train_log.jsonl,
#     adapter_config.json; with --adapters also adapter_model.safetensors, head.pt
#   speed tests: runs/speedtest/; stage-2 and endpoint logs: runs/logs/
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REMOTE=184-toast:disk4/cs224/decision_ft
mkdir -p "$HERE/results" "$HERE/runs/logs"
extra=()
[ "${1:-}" = "--adapters" ] && extra=(--include='adapter_model.safetensors' --include='head.pt')
rsync -a --exclude='*.tmp' "$REMOTE/results/" "$HERE/results/" 2>/dev/null || true
for strategy in L1 L3; do
  for fold in 0 1 2; do
    mkdir -p "$HERE/runs/$strategy/fold$fold"
    rsync -a --include='config.json' --include='selection.json' --include='dev_metrics.json' \
      --include='train_log.jsonl' --include='adapter_config.json' "${extra[@]}" --exclude='*' \
      "$REMOTE/$strategy/fold$fold/" "$HERE/runs/$strategy/fold$fold/" 2>/dev/null || true
  done
done
rsync -a "$REMOTE/speedtest/" "$HERE/runs/speedtest/" 2>/dev/null || true
rsync -a --include='stage2*' --include='serve.log' --include='L?_fold?.log' --include='worker?.log' \
  --include='release_gpu1.log' --exclude='*' "$REMOTE/logs/" "$HERE/runs/logs/" 2>/dev/null || true
find "$HERE/results" -name '*.jsonl' | sort | sed "s#$HERE/##"

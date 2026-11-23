#!/usr/bin/env bash
# Run LineVul zero-shot on dell CPU (linevul_cpu) and on 184-toast GPU 1 (linevul_gpu) for one units file.
#   run_linevul.sh <units.jsonl> <run_id> [set=all] [layer=layer1]
# Predictions land in juliet_full/gpu/results/<method>/<layer>/<run_id>.jsonl (+ .meta.json).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
UNITS=$(realpath "$1"); RUN_ID=$2; SET=${3:-all}; LAYER=${4:-layer1}
MODELS_DELL=$HOME/tools/cs224/models
REMOTE=184-toast
REMOTE_GPU='~/disk4/cs224/gpu'

"$HERE/.venv/bin/python" "$HERE/linevul_infer.py" --units "$UNITS" --set "$SET" --layer "$LAYER" \
  --method linevul_cpu --checkpoint "$MODELS_DELL/LineVul" --tokenizer "$MODELS_DELL/codebert-base" \
  --out-root "$HERE/results" --run-id "$RUN_ID"

rsync -a "$HERE/linevul_infer.py" "$HERE/server" "$REMOTE:$REMOTE_GPU/"
rsync -a "$UNITS" "$REMOTE:$REMOTE_GPU/scratch/$(basename "$UNITS")"
ssh "$REMOTE" "source $REMOTE_GPU/server/env.sh && cd $REMOTE_GPU && CUDA_VISIBLE_DEVICES=1 \$VENV/bin/python linevul_infer.py \
  --units scratch/$(basename "$UNITS") --set $SET --layer $LAYER --method linevul_gpu \
  --checkpoint \$MODELS/LineVul --tokenizer \$MODELS/codebert-base --out-root results --run-id $RUN_ID"
rsync -a "$REMOTE:$REMOTE_GPU/results/linevul_gpu" "$HERE/results/"

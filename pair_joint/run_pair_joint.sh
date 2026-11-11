#!/usr/bin/env bash
# Real pair-joint runs on the frozen SecVulEval splits (WSL only).
#
# Usage:
#   bash pair_joint/run_pair_joint.sh pilot   # 8 dev pairs per model (partial, plumbing only)
#   bash pair_joint/run_pair_joint.sh full    # 180 frozen test pairs per model
#
# Credentials: read from the Kimi Code provider config into process memory by
# pair_joint.runner; the key is never printed or written to run artifacts.
# Prices (checked 2026-11-12, same as the existing runner configs):
#   deepseek-v4.1-flash: input $0.30, output $1.20, cached $0.006 / 1M
#   mimo-v2.6-flash:     input $0.14, output $0.28, cached $0.0028 / 1M
set -euo pipefail

MODE="${1:?usage: run_pair_joint.sh pilot|full}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KIMI_CONFIG="/mnt/c/Users/tzh03/.kimi-code/config.toml"
KIMI_PROVIDER="opencode-go"
BASE_URL="https://opencode.ai/zen/go/v1"

case "$MODE" in
  pilot)
    DATASET="splits/pilot_pairs_18.json"
    EXPECT="e237137718a973af0a1c9cde1fc7ecf594b51feb6ce5600f5a47894f29e54747"
    LIMIT=8
    DS_CONCURRENCY=4
    MIMO_CONCURRENCY=8
    DS_OUT="pair_joint/runs/pilot_deepseek_8"
    MIMO_OUT="pair_joint/runs/pilot_mimo_8"
    LABEL="pair-joint-pilot"
    ;;
  full)
    DATASET="splits/test_pairs_180.json"
    EXPECT="21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d"
    LIMIT=0
    DS_CONCURRENCY=8
    MIMO_CONCURRENCY=16
    DS_OUT="pair_joint/runs/test_deepseek_180"
    MIMO_OUT="pair_joint/runs/test_mimo_180"
    LABEL="pair-joint-frozen-test"
    ;;
  *)
    printf 'unknown mode: %s (expected pilot or full)\n' "$MODE" >&2
    exit 2
    ;;
esac

resume_flag() {
  local out="$1"
  if [[ -f "$out/manifest.json" ]]; then
    printf '%s' "--resume"
  fi
}

run_deepseek() {
  local extra=()
  local resume
  resume="$(resume_flag "$DS_OUT")"
  if [[ -n "$resume" ]]; then extra+=("$resume"); fi
  python3 -m pair_joint.runner \
    --kimi-config "$KIMI_CONFIG" --kimi-provider "$KIMI_PROVIDER" \
    --base-url "$BASE_URL" \
    --dataset "$DATASET" --expect-sha256 "$EXPECT" --limit "$LIMIT" \
    --model deepseek-v4.1-flash \
    --max-tokens 8192 --max-tokens-field max_tokens \
    --concurrency "$DS_CONCURRENCY" --timeout 240 \
    --input-price-usd-per-1m 0.30 \
    --output-price-usd-per-1m 1.20 \
    --cached-input-price-usd-per-1m 0.006 \
    --run-label "$LABEL-deepseek" \
    --out-dir "$DS_OUT" "${extra[@]}"
}

run_mimo() {
  local extra=()
  local resume
  resume="$(resume_flag "$MIMO_OUT")"
  if [[ -n "$resume" ]]; then extra+=("$resume"); fi
  python3 -m pair_joint.runner \
    --kimi-config "$KIMI_CONFIG" --kimi-provider "$KIMI_PROVIDER" \
    --base-url "$BASE_URL" \
    --dataset "$DATASET" --expect-sha256 "$EXPECT" --limit "$LIMIT" \
    --model mimo-v2.6-flash \
    --thinking disabled --reasoning-effort none \
    --max-tokens 8192 --max-tokens-field max_completion_tokens \
    --concurrency "$MIMO_CONCURRENCY" --timeout 300 \
    --input-price-usd-per-1m 0.14 \
    --output-price-usd-per-1m 0.28 \
    --cached-input-price-usd-per-1m 0.0028 \
    --run-label "$LABEL-mimo" \
    --out-dir "$MIMO_OUT" "${extra[@]}"
}

run_deepseek
run_mimo

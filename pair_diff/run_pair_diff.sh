#!/usr/bin/env bash
# Real diff-guided pair runs on the frozen SecVulEval splits (WSL only).
#
# Usage:
#   bash pair_diff/run_pair_diff.sh pilot          # 8 dev pairs, 4 conditions, 2 models
#   bash pair_diff/run_pair_diff.sh full           # 180 frozen test pairs, 4 conditions, 2 models
#   bash pair_diff/run_pair_diff.sh analyze-pilot  # analysis of the pilot artifacts
#   bash pair_diff/run_pair_diff.sh analyze        # analysis of the full artifacts
#   bash pair_diff/run_pair_diff.sh selftest       # offline checks
#
# Credentials: read from the Kimi Code provider config into process memory by
# pair_diff.runner; the key is never printed or written to run artifacts.
# Prices (same as the existing pair_joint / pair_debias runs, checked 2026-11-12):
#   deepseek-v4.1-flash: input $0.30, output $1.20, cached $0.006 / 1M
#   mimo-v2.6-flash:     input $0.14, output $0.28, cached $0.0028 / 1M
set -euo pipefail

MODE="${1:?usage: run_pair_diff.sh pilot|full|analyze|analyze-pilot|selftest}"
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
    BASE_MAP="pair_joint/runs/pilot_deepseek_8/position_map.json"
    BASE_SHA="512c9a9b350b923ed307501d196bb8bc78c8367146d6ad5b8a877437f6aee285"
    PREFIX="pair_diff/runs/pilot"
    DS_CONCURRENCY=4
    MIMO_CONCURRENCY=8
    ;;
  full)
    DATASET="splits/test_pairs_180.json"
    EXPECT="21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d"
    LIMIT=0
    BASE_MAP="pair_joint/runs/test_deepseek_180/position_map.json"
    BASE_SHA="82c40fd03b1d0ae6d34eb51ad780da3cd543bb5d38f45d7e44d86c7044e6e7c8"
    PREFIX="pair_diff/runs/test"
    DS_CONCURRENCY="${DS_CONCURRENCY:-8}"
    MIMO_CONCURRENCY="${MIMO_CONCURRENCY:-16}"
    ;;
  analyze)
    exec python3 -m pair_diff.analyze --phase test --out-dir pair_diff/results
    ;;
  analyze-pilot)
    exec python3 -m pair_diff.analyze --phase pilot --out-dir pair_diff/results/pilot
    ;;
  selftest)
    exec python3 pair_diff/selftest.py
    ;;
  *)
    printf 'unknown mode: %s (expected pilot, full, analyze, analyze-pilot or selftest)\n' "$MODE" >&2
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
  local condition="$1"
  local out="$PREFIX"_deepseek_"$condition"
  local extra=()
  local resume
  resume="$(resume_flag "$out")"
  if [[ -n "$resume" ]]; then extra+=("$resume"); fi
  python3 -m pair_diff.runner \
    --kimi-config "$KIMI_CONFIG" --kimi-provider "$KIMI_PROVIDER" \
    --base-url "$BASE_URL" \
    --dataset "$DATASET" --expect-sha256 "$EXPECT" --limit "$LIMIT" \
    --base-map "$BASE_MAP" --expect-base-sha256 "$BASE_SHA" \
    --condition "$condition" \
    --model deepseek-v4.1-flash \
    --max-tokens 8192 --max-tokens-field max_tokens \
    --concurrency "$DS_CONCURRENCY" --timeout 240 \
    --input-price-usd-per-1m 0.30 \
    --output-price-usd-per-1m 1.20 \
    --cached-input-price-usd-per-1m 0.006 \
    --run-label "pair-diff-$MODE-deepseek-$condition" \
    --out-dir "$out" "${extra[@]}"
}

run_mimo() {
  local condition="$1"
  local out="$PREFIX"_mimo_"$condition"
  local extra=()
  local resume
  resume="$(resume_flag "$out")"
  if [[ -n "$resume" ]]; then extra+=("$resume"); fi
  python3 -m pair_diff.runner \
    --kimi-config "$KIMI_CONFIG" --kimi-provider "$KIMI_PROVIDER" \
    --base-url "$BASE_URL" \
    --dataset "$DATASET" --expect-sha256 "$EXPECT" --limit "$LIMIT" \
    --base-map "$BASE_MAP" --expect-base-sha256 "$BASE_SHA" \
    --condition "$condition" \
    --model mimo-v2.6-flash \
    --thinking disabled --reasoning-effort none \
    --max-tokens 8192 --max-tokens-field max_completion_tokens \
    --concurrency "$MIMO_CONCURRENCY" --timeout 300 \
    --input-price-usd-per-1m 0.14 \
    --output-price-usd-per-1m 0.28 \
    --cached-input-price-usd-per-1m 0.0028 \
    --run-label "pair-diff-$MODE-mimo-$condition" \
    --out-dir "$out" "${extra[@]}"
}

for condition in diff_fwd diff_rev ctrl_fwd ctrl_rev; do
  run_deepseek "$condition"
done
for condition in diff_fwd diff_rev ctrl_fwd ctrl_rev; do
  run_mimo "$condition"
done

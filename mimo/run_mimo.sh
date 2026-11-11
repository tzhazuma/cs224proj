#!/usr/bin/env bash
# MiMo-V2.6-Flash comparison matrix on the frozen SecVulEval splits.
#
# Usage:
#   bash mimo/run_mimo.sh pilot   # per strategy: independent limit 6 + pairs limit 3
#   bash mimo/run_mimo.sh test    # per strategy: full 288 + 540 = 828 requests
#
# Prices checked against https://opencode.ai/v2/docs/console/go/ on 2026-11-12:
#   MiMo-V2.6-Flash: input $0.14, output $0.28, cached read $0.0028 per 1M tokens.
# Re-check that page before reusing this script; prices can change.
#
# MiMo on OpenCode Go ignores thinking={"type":"disabled"}; reasoning_effort="none"
# is what actually disables reasoning (verified 2026-11-12: 0 reasoning tokens).
# The native output-limit field is max_completion_tokens.
#
# Credentials are read from the Windows Kimi Code config by
# runner/run_with_kimi_config.py and only ever live in process memory.
set -euo pipefail

MODE="${1:?usage: run_mimo.sh pilot|test}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMMON=(
  --model mimo-v2.6-flash
  --base-url https://opencode.ai/zen/go/v1
  --thinking disabled
  --reasoning-effort none
  --max-tokens-field max_completion_tokens
  --max-tokens 8192
  --input-price-usd-per-1m 0.14
  --output-price-usd-per-1m 0.28
  --cached-input-price-usd-per-1m 0.0028
  --concurrency 16
  --timeout 300
)
WRAPPER=(
  python3 runner/run_with_kimi_config.py
  --kimi-config /mnt/c/Users/tzh03/.kimi-code/config.toml
  --kimi-provider opencode-go
)

case "$MODE" in
  pilot)
    INDEPENDENT_DATA=splits/pilot_detection_36.json
    PAIR_DATA=splits/pilot_pairs_18.json
    INDEPENDENT_LIMIT=6
    PAIR_LIMIT=3
    PREFIX=pilot_v1_mimo
    LABEL=split-v1-dev-pilot-mimo
    ;;
  test)
    INDEPENDENT_DATA=splits/test_detection_160.json
    PAIR_DATA=splits/test_pairs_180.json
    INDEPENDENT_LIMIT=0
    PAIR_LIMIT=0
    PREFIX=test_v1_mimo
    LABEL=split-v1-frozen-test-mimo
    ;;
  *)
    printf 'unknown mode: %s (expected pilot or test)\n' "$MODE" >&2
    exit 2
    ;;
esac

for STRATEGY in direct few-shot context; do
  EXTRA=()
  if [[ "$STRATEGY" == "few-shot" ]]; then
    EXTRA=(--dev-examples splits/dev_examples_fewshot.json)
  fi

  INDEPENDENT_OUT="runner/runs/${PREFIX}_${STRATEGY}_independent"
  PAIR_OUT="runner/runs/${PREFIX}_${STRATEGY}_pairs"

  RESUME=()
  if [[ -f "$INDEPENDENT_OUT/manifest.json" ]]; then
    RESUME=(--resume)
  fi
  "${WRAPPER[@]}" \
    --dataset independent --dataset-file "$INDEPENDENT_DATA" \
    --strategy "$STRATEGY" --task both --limit "$INDEPENDENT_LIMIT" \
    "${COMMON[@]}" "${EXTRA[@]}" "${RESUME[@]}" \
    --out-dir "$INDEPENDENT_OUT" --run-label "$LABEL"

  RESUME=()
  if [[ -f "$PAIR_OUT/manifest.json" ]]; then
    RESUME=(--resume)
  fi
  "${WRAPPER[@]}" \
    --dataset pairs --dataset-file "$PAIR_DATA" \
    --strategy "$STRATEGY" --task both --limit "$PAIR_LIMIT" \
    "${COMMON[@]}" "${EXTRA[@]}" "${RESUME[@]}" \
    --out-dir "$PAIR_OUT" --run-label "$LABEL"
done

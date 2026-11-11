#!/usr/bin/env bash
set -euo pipefail

MODE="${1:?usage: run_matrix.sh pilot|test}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMMON=(
  --model deepseek-v4.1-flash
  --input-price-usd-per-1m 0.30
  --output-price-usd-per-1m 1.20
  --cached-input-price-usd-per-1m 0.006
  --concurrency 8
  --timeout 180
)
WRAPPER=(
  python3 runner/run_with_kimi_config.py
  --kimi-config /mnt/c/Users/tzh03/.kimi-code/config.toml
  --kimi-provider opencode-go
)

for STRATEGY in direct few-shot context; do
  EXTRA=()
  if [[ "$STRATEGY" == "few-shot" ]]; then
    EXTRA=(--dev-examples splits/dev_examples_fewshot.json)
  fi
  if [[ "$MODE" == "pilot" ]]; then
    INDEPENDENT_DATA=splits/pilot_detection_36.json
    PAIR_DATA=splits/pilot_pairs_18.json
    INDEPENDENT_LIMIT=6
    PAIR_LIMIT=3
    PREFIX=dev_pilot
    LABEL=split-v1-dev-pilot-nonthinking
  elif [[ "$MODE" == "test" ]]; then
    INDEPENDENT_DATA=splits/test_detection_160.json
    PAIR_DATA=splits/test_pairs_180.json
    INDEPENDENT_LIMIT=0
    PAIR_LIMIT=0
    PREFIX=test_v1
    LABEL=split-v1-frozen-test-nonthinking
  else
    printf 'unknown mode: %s\n' "$MODE" >&2
    exit 2
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

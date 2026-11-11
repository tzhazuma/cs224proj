#!/usr/bin/env bash
# Evidence-grounded detection prompt on the frozen SecVulEval test split.
#
# Usage:
#   bash evidence_prompt/run_evidence.sh deepseek dryrun
#   bash evidence_prompt/run_evidence.sh deepseek smoke
#   bash evidence_prompt/run_evidence.sh deepseek test
#   bash evidence_prompt/run_evidence.sh mimo dryrun|smoke|test
#
# The test stage sends exactly 160 detection requests per model (one per
# frozen test function).  Outputs go to evidence_prompt/runs/ and never
# overwrite runner/runs/ or any other experiment directory.
#
# Credentials are read from the Windows Kimi Code config by
# evidence_prompt/run_with_kimi_config.py and only live in process memory.
# Prices are the same as the corresponding baseline runs:
#   DeepSeek V4.1 Flash: input 0.30, output 1.20, cached 0.006 USD/1M.
#   MiMo-V2.6-Flash:     input 0.14, output 0.28, cached 0.0028 USD/1M.
# Re-check prices before reusing this script.
set -euo pipefail

MODEL_KIND="${1:?usage: run_evidence.sh deepseek|mimo dryrun|smoke|test}"
STAGE="${2:?usage: run_evidence.sh deepseek|mimo dryrun|smoke|test}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KIMI_CONFIG="/mnt/c/Users/tzh03/.kimi-code/config.toml"
if [[ ! -f "$KIMI_CONFIG" ]]; then
  echo "missing Kimi Code config: $KIMI_CONFIG" >&2
  exit 2
fi

case "$MODEL_KIND" in
  deepseek)
    MODEL="deepseek-v4.1-flash"
    COMMON=(
      --model "$MODEL"
      --base-url https://opencode.ai/zen/go/v1
      --concurrency 8
      --timeout 180
      --max-tokens 8192
      --input-price-usd-per-1m 0.3
      --output-price-usd-per-1m 1.2
      --cached-input-price-usd-per-1m 0.006
    )
    ;;
  mimo)
    MODEL="mimo-v2.6-flash"
    COMMON=(
      --model "$MODEL"
      --base-url https://opencode.ai/zen/go/v1
      --thinking disabled
      --reasoning-effort none
      --max-tokens-field max_completion_tokens
      --max-tokens 8192
      --concurrency 16
      --timeout 300
      --input-price-usd-per-1m 0.14
      --output-price-usd-per-1m 0.28
      --cached-input-price-usd-per-1m 0.0028
    )
    ;;
  *)
    echo "unknown model kind: $MODEL_KIND (expected deepseek or mimo)" >&2
    exit 2
    ;;
esac

WRAPPER=(
  python3 evidence_prompt/run_with_kimi_config.py
  --kimi-config "$KIMI_CONFIG"
  --kimi-provider opencode-go
)

case "$STAGE" in
  test)
    DATA="splits/test_detection_160.json"
    LIMIT=0
    OUT="evidence_prompt/runs/test_evidence_${MODEL_KIND}"
    LABEL="frozen-test-160-evidence-${MODEL_KIND}"
    EXTRA=()
    ;;
  smoke)
    DATA="splits/dev_detection_40.json"
    LIMIT=4
    OUT="evidence_prompt/runs/smoke_dev_evidence_${MODEL_KIND}"
    LABEL="dev-schema-smoke-evidence-${MODEL_KIND}"
    EXTRA=()
    ;;
  dryrun)
    DATA="splits/test_detection_160.json"
    LIMIT=0
    OUT="evidence_prompt/runs/dryrun_evidence_${MODEL_KIND}"
    LABEL="frozen-test-160-evidence-${MODEL_KIND}-dryrun"
    EXTRA=(--dry-run)
    if [[ -f "$OUT/dry_run_manifest.json" ]]; then
      echo "dry-run artifacts already exist: $OUT"
      exit 0
    fi
    ;;
  *)
    echo "unknown stage: $STAGE (expected dryrun, smoke, or test)" >&2
    exit 2
    ;;
esac

RESUME=()
if [[ "$STAGE" != "dryrun" && -f "$OUT/manifest.json" ]]; then
  RESUME=(--resume)
fi

"${WRAPPER[@]}" \
  --dataset-file "$DATA" \
  --limit "$LIMIT" \
  "${COMMON[@]}" "${EXTRA[@]}" "${RESUME[@]}" \
  --out-dir "$OUT" --run-label "$LABEL"

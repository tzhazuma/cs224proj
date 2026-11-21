#!/usr/bin/env bash
# Positive-claim refutation on the frozen SecVulEval test split.
#
# Usage:
#   bash evidence_verify/run_verify.sh deepseek_self  dryrun|smoke|test
#   bash evidence_verify/run_verify.sh deepseek_cross dryrun|smoke|test
#   bash evidence_verify/run_verify.sh mimo_self      dryrun|smoke|test
#   bash evidence_verify/run_verify.sh mimo_cross     dryrun|smoke|test
#
# Arms:
#   <model>_self  : claims from <model>'s first-pass run, verified by <model>
#   <model>_cross : claims from <model>'s first-pass run, verified by the other model
#
# The test stage sends exactly one verifier request per schema-valid positive
# first-pass prediction.  Outputs go to evidence_verify/runs/ and never touch
# evidence_prompt/ or runner/runs/.
#
# Credentials are read from the Windows Kimi Code config by
# evidence_verify/run_with_kimi_config.py and only live in process memory.
# Prices are copied from the corresponding first-pass run:
#   DeepSeek V4.1 Flash: input 0.30, output 1.20, cached 0.006 USD/1M.
#   MiMo-V2.6-Flash:     input 0.14, output 0.28, cached 0.0028 USD/1M.
# Re-check prices before reusing this script.
set -euo pipefail

ARM="${1:?usage: run_verify.sh deepseek_self|deepseek_cross|mimo_self|mimo_cross dryrun|smoke|test}"
STAGE="${2:?usage: run_verify.sh <arm> dryrun|smoke|test}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

KIMI_CONFIG="/mnt/c/Users/tzh03/.kimi-code/config.toml"
if [[ ! -f "$KIMI_CONFIG" ]]; then
  echo "missing Kimi Code config: $KIMI_CONFIG" >&2
  exit 2
fi

# WSL mirrored networking with autoProxy exports the Windows-side proxy address.
# When the proxy client is not running, that address is closed and every call
# fails with ECONNREFUSED. Probe it and drop the proxy env only if it is dead.
PROXY_URL="${HTTPS_PROXY:-${https_proxy:-}}"
if [[ -n "$PROXY_URL" && "$PROXY_URL" =~ ^http://([^:/]+):([0-9]+) ]] && command -v timeout >/dev/null; then
  PROXY_HOST="${BASH_REMATCH[1]}"
  PROXY_PORT="${BASH_REMATCH[2]}"
  if ! timeout 2 bash -c ">/dev/tcp/${PROXY_HOST}/${PROXY_PORT}" 2>/dev/null; then
    echo "note: proxy ${PROXY_URL} is unreachable; running without proxy env" >&2
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
  fi
fi

deepseek_args() {
  cat <<'EOF'
--model deepseek-v4.1-flash
--base-url https://opencode.ai/zen/go/v1
--concurrency 8
--timeout 180
--max-tokens 2048
--max-tokens-field max_tokens
--input-price-usd-per-1m 0.3
--output-price-usd-per-1m 1.2
--cached-input-price-usd-per-1m 0.006
EOF
}

mimo_args() {
  cat <<'EOF'
--model mimo-v2.6-flash
--base-url https://opencode.ai/zen/go/v1
--thinking disabled
--reasoning-effort none
--max-tokens-field max_completion_tokens
--max-tokens 2048
--concurrency 16
--timeout 300
--input-price-usd-per-1m 0.14
--output-price-usd-per-1m 0.28
--cached-input-price-usd-per-1m 0.0028
EOF
}

case "$ARM" in
  deepseek_self)
    CLAIM_KIND="deepseek"; VERIFIER_KIND="deepseek"; ARM_TAG="deepseek_self"
    ;;
  deepseek_cross)
    CLAIM_KIND="deepseek"; VERIFIER_KIND="mimo"; ARM_TAG="deepseek_by_mimo"
    ;;
  mimo_self)
    CLAIM_KIND="mimo"; VERIFIER_KIND="mimo"; ARM_TAG="mimo_self"
    ;;
  mimo_cross)
    CLAIM_KIND="mimo"; VERIFIER_KIND="deepseek"; ARM_TAG="mimo_by_deepseek"
    ;;
  *)
    echo "unknown arm: $ARM" >&2
    exit 2
    ;;
esac

# shellcheck disable=SC2207
MODEL_ARGS=($(if [[ "$VERIFIER_KIND" == "deepseek" ]]; then deepseek_args; else mimo_args; fi))
# shellcheck disable=SC2207
WRAPPER=(python3 evidence_verify/run_with_kimi_config.py --kimi-config "$KIMI_CONFIG" --kimi-provider opencode-go)

case "$STAGE" in
  test)
    DATA="splits/test_detection_160.json"
    CLAIMS="evidence_prompt/runs/test_evidence_${CLAIM_KIND}/results.jsonl"
    OUT="evidence_verify/runs/test_verify_${ARM_TAG}"
    LABEL="frozen-test-160-verify-${ARM_TAG}"
    EXTRA=()
    ;;
  smoke)
    DATA="splits/dev_detection_40.json"
    CLAIMS="evidence_prompt/runs/smoke_dev_evidence_${CLAIM_KIND}/results.jsonl"
    OUT="evidence_verify/runs/smoke_verify_${ARM_TAG}"
    LABEL="dev-schema-smoke-verify-${ARM_TAG}"
    EXTRA=()
    ;;
  dryrun)
    DATA="splits/test_detection_160.json"
    CLAIMS="evidence_prompt/runs/test_evidence_${CLAIM_KIND}/results.jsonl"
    OUT="evidence_verify/runs/dryrun_verify_${ARM_TAG}"
    LABEL="frozen-test-160-verify-${ARM_TAG}-dryrun"
    EXTRA=(--dry-run)
    if [[ -f "$OUT/manifest.json" ]]; then
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
  --claims-from "$CLAIMS" \
  "${MODEL_ARGS[@]}" "${EXTRA[@]}" "${RESUME[@]}" \
  --out-dir "$OUT" --run-label "$LABEL"

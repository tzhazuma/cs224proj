#!/usr/bin/env bash
# Run the Juliet LLM CLI through the shared Kimi Code credential loader.
# The key is read from the TOML config and never printed or written.
set -euo pipefail
cd "$(dirname "$0")/.."
CONFIG="${KIMI_CONFIG:-/home/azuma/.kimi-code/config.toml}"
exec python3 juliet_llm/launch.py \
  --kimi-config "$CONFIG" \
  --kimi-provider "${KIMI_PROVIDER:-opencode-go}" \
  -- "$@"

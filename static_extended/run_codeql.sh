#!/usr/bin/env bash
# Reproduce the CodeQL CWE-401 run on the frozen Juliet subset.
# Usage: bash static_extended/run_codeql.sh [output-dir]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
CODEQL_BIN="${CODEQL_BIN:-$HOME/tools/codeql-2.27.4/codeql/codeql}"
OUT="${1:-$HERE/runs/codeql_$(date -u +%Y%m%d_%H%M%S)}"

if [ ! -x "$CODEQL_BIN" ]; then
  echo "CodeQL not found at $CODEQL_BIN; set CODEQL_BIN or install the bundle" >&2
  exit 2
fi
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "refusing to overwrite non-empty output directory: $OUT" >&2
  exit 2
fi

cd "$ROOT"
python3 static_extended/codeql_adapter.py \
  --units juliet/subset_units.jsonl \
  --juliet-root juliet \
  --out "$OUT" \
  --codeql "$CODEQL_BIN" \
  --jobs "${JOBS:-6}" --timeout 600

python3 static_extended/compare_test140.py \
  --units juliet/subset_units.jsonl \
  --baseline traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl \
  --codeql-run "$OUT" \
  --out "$OUT/comparison_test140.json"

echo "done: $OUT"

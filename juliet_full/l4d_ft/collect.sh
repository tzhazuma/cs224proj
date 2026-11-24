#!/usr/bin/env bash
# 184-toast -> dell: small run artifacts (config, logs, step0 check, dev answers) to build/runs/, results/ to
# build/remote_results/, job logs to raw_logs/remote/. --adapters also copies ckpt/ (adapter + head).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REMOTE=184-toast:disk4/cs224/l4d_ft
mkdir -p "$HERE/build/runs" "$HERE/build/remote_results" "$HERE/raw_logs/remote"
ex=(--exclude='ckpt/'); [ "${1:-}" = "--adapters" ] && ex=()
rsync -a --exclude='*.tmp' --exclude='*.rank*.json' "${ex[@]}" "$REMOTE/runs/" "$HERE/build/runs/"
rsync -a --exclude='*.tmp' "$REMOTE/results/" "$HERE/build/remote_results/" 2>/dev/null || true
rsync -a "$REMOTE/logs/" "$HERE/raw_logs/remote/"
rsync -a "$REMOTE/status/" "$HERE/build/status/" 2>/dev/null || true

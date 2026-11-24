#!/usr/bin/env bash
# dell -> 184-toast: server code + rendered data (data/*.jsonl, data/manifest.json); FROZEN (JSON) when present.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REMOTE=184-toast:disk4/cs224/l4d_ft
ssh 184-toast 'mkdir -p ~/disk4/cs224/l4d_ft/data'
rsync -a --exclude=__pycache__ "$HERE/server/" "$REMOTE/server/"
rsync -a "$HERE/data/" "$REMOTE/data/"
if [ -f "$HERE/FROZEN" ]; then rsync -a "$HERE/FROZEN" "$REMOTE/FROZEN"; fi
echo uploaded

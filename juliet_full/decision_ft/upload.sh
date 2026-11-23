#!/usr/bin/env bash
# dell -> 184-toast: server code, rendered data, and a read-only copy of the prompt code used by the :8003
# endpoint to render prompts exactly as render_data.py does (server/vendor/ mirrors the repo layout:
# juliet_full/llm/llmlane/{__init__,prompts}.py, juliet_full/llm/prompts/*, juliet_llm/{__init__,cleaning}.py).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
REMOTE=184-toast:disk4/cs224/decision_ft
stage=$(mktemp -d /tmp/dft-vendor.XXXXXX)
mkdir -p "$stage/juliet_full/llm/llmlane" "$stage/juliet_full/llm/prompts" "$stage/juliet_llm"
cp "$ROOT/juliet_full/llm/llmlane/__init__.py" "$ROOT/juliet_full/llm/llmlane/prompts.py" "$stage/juliet_full/llm/llmlane/"
cp "$ROOT/juliet_full/llm/prompts/"{task.txt,answer_format.txt,user_suffix.txt,user_L1.txt,user_L3.txt,jev_question.json} \
  "$stage/juliet_full/llm/prompts/"
cp "$ROOT/juliet_llm/__init__.py" "$ROOT/juliet_llm/cleaning.py" "$stage/juliet_llm/"
(cd "$stage" && find . -type f | sort | xargs sha256sum) > "$stage/SHA256SUMS"
rsync -a --exclude=__pycache__ --exclude=vendor "$HERE/server/" "$REMOTE/server/"
rsync -a --delete "$stage/" "$REMOTE/server/vendor/"
rsync -a "$HERE/data/" "$REMOTE/data/"
rm -rf "$stage"
echo "uploaded server/, server/vendor/, data/"

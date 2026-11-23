#!/usr/bin/env bash
# Demo doctor: venv, clang, API keys (presence only, never printed), endpoints, DeepSeek balance,
# Beijing peak gate, ledger totals, terminal size, recording tools. Exit 0 = everything green.
#   ./check.sh            full doctor
#   ./check.sh --warm     only pre-warm (clang run + endpoint pings), right before the talk
set -u
cd "$(dirname "$0")"
UV="${UV:-$HOME/.local/bin/uv}"

if [ ! -x .venv/bin/python ]; then
  echo "creating .venv (uv, python 3.12, rich + pytest)"
  "$UV" venv --quiet --python 3.12 .venv && "$UV" pip install --quiet --python .venv/bin/python rich pytest || {
    echo "FAIL: could not create .venv"; exit 1; }
fi
.venv/bin/python -c "import rich" 2>/dev/null || { echo "FAIL: rich missing in .venv"; exit 1; }

if [ "${1:-}" = "--warm" ]; then
  exec .venv/bin/python demo.py --warm
fi

status=0
.venv/bin/python demo.py --check || status=1

echo
echo "recording tools (only needed for record.sh):"
for tool in .tools/agg /usr/bin/ffmpeg "$HOME/.local/bin/uvx"; do
  if [ -x "$tool" ]; then echo "  ok      $tool"; else echo "  missing $tool"; fi
done
echo "  recordings: $(ls recordings/*.json 2>/dev/null | wc -l) replay file(s) in recordings/"
exit $status

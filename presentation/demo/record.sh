#!/usr/bin/env bash
# Record one unattended demo run as a backup:
#   recordings/<name>.json   replay file  (demo.py --replay recordings/<name>.json)
#   recordings/<name>.cast   asciinema 2 cast (or <name>.typescript + .timing via `script` if asciinema fails)
#   recordings/<name>.gif    agg render     (backup slide)
#   recordings/<name>.mp4    ffmpeg from the gif
# Usage: ./record.sh [demo.py args...]        (default: the stage command of README.md)
#   REC_NAME=stage_final ./record.sh --allow-eval --allow-peak
#   REC_COLS=120 REC_ROWS=40 REC_HOLD=4 REC_FONT=20 to change the canvas / per-step hold / gif font size
set -euo pipefail
cd "$(dirname "$0")"
NAME="${REC_NAME:-demo_$(date -u +%Y%m%dT%H%M%SZ)}"
COLS="${REC_COLS:-120}"
ROWS="${REC_ROWS:-40}"
HOLD="${REC_HOLD:-4}"
FONT="${REC_FONT:-20}"
UVX="${UVX:-$HOME/.local/bin/uvx}"
mkdir -p recordings
if [ "$#" -eq 0 ]; then
  set -- --allow-eval
fi
CMD=".venv/bin/python demo.py --auto-pause $HOLD --record recordings/$NAME.json $*"
echo "recording: $CMD"

if timeout 600 "$UVX" --from 'asciinema>=2.4,<3' asciinema rec --overwrite --quiet --cols "$COLS" --rows "$ROWS" \
     --idle-time-limit 5 --title "CS224 CWE-401 demo ($NAME)" -c "$CMD" "recordings/$NAME.cast" </dev/null; then
  echo "cast   -> recordings/$NAME.cast   (play: uvx --from 'asciinema<3' asciinema play recordings/$NAME.cast)"
  if [ -x .tools/agg ]; then
    .tools/agg --quiet --font-size "$FONT" --theme monokai --idle-time-limit 5 --last-frame-duration 6 \
      "recordings/$NAME.cast" "recordings/$NAME.gif"
    echo "gif    -> recordings/$NAME.gif"
    if [ -x /usr/bin/ffmpeg ]; then
      /usr/bin/ffmpeg -loglevel error -y -i "recordings/$NAME.gif" -movflags faststart -pix_fmt yuv420p \
        -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" "recordings/$NAME.mp4"
      echo "mp4    -> recordings/$NAME.mp4"
    fi
  else
    echo "no .tools/agg: download it (README.md, 'Backup recording') to render a gif"
  fi
else
  echo "asciinema failed; falling back to script(1) with timing"
  stty cols "$COLS" rows "$ROWS" 2>/dev/null || true
  script -q -c "$CMD" --log-timing "recordings/$NAME.timing" "recordings/$NAME.typescript"
  echo "typescript -> recordings/$NAME.typescript (play: scriptreplay -t recordings/$NAME.timing recordings/$NAME.typescript)"
fi
echo "replay -> recordings/$NAME.json   (play: .venv/bin/python demo.py --replay recordings/$NAME.json)"

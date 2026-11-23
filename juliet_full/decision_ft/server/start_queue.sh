#!/usr/bin/env bash
# Start (or restart after a crash) one detached queue worker per GPU. Claimed jobs are not re-run;
# to re-run a failed job remove $DFT/status/<job>.claim and $DFT/status/<job>.json first.
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
for gpu in 0 1; do
  if [ -f "run/worker$gpu.pid" ] && kill -0 "$(cat "run/worker$gpu.pid")" 2>/dev/null; then
    echo "worker$gpu already running (pid $(cat "run/worker$gpu.pid"))"; continue
  fi
  mkdir -p run
  setsid nohup bash server/queue.sh "$gpu" >> "logs/worker$gpu.log" 2>&1 < /dev/null &
  echo $! > "run/worker$gpu.pid"
  echo "worker$gpu started (pid $!)"
done

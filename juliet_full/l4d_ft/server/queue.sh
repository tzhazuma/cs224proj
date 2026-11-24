#!/usr/bin/env bash
# queue.sh <name> <gpu> <cmdfile>   detached: runs every line of <cmdfile> (l4dft.py arguments) in order on one GPU;
#   stops at the first failure. logs/<name>.log, run/<name>.pid, status/<name>.queue = running|done|failed:<line>
set -euo pipefail
source "$HOME/disk4/cs224/l4d_ft/server/env.sh"
cd "$L4D"; mkdir -p run status logs
name=$1; gpu=$2; cmdfile=$3
[ -f "$cmdfile" ] || { echo "no $cmdfile"; exit 1; }
CUDA_VISIBLE_DEVICES=$gpu setsid nohup bash -c '
  name=$1; cmdfile=$2
  echo running > "status/$name.queue"
  n=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    n=$((n + 1))
    echo "$(date -u +%FT%TZ) [$n] l4dft.py $line"
    # shellcheck disable=SC2086
    if ! "$VENV/bin/python" server/l4dft.py $line < /dev/null; then
      echo "failed:$n $line" > "status/$name.queue"; exit 1
    fi
  done < "$cmdfile"
  echo "$(date -u +%FT%TZ) queue done"
  echo done > "status/$name.queue"
' _ "$name" "$cmdfile" >> "logs/$name.log" 2>&1 < /dev/null &
echo $! > "run/$name.pid"
echo "started queue $name pid $! gpu=$gpu"

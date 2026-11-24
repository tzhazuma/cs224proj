#!/usr/bin/env bash
# job.sh <name> <gpus> <l4dft.py args...>   detached job: logs/<name>.log, pid run/<name>.pid
#   <gpus> = "0", "1" (single GPU) or "0,1" (torchrun, 2-GPU data parallel)
set -euo pipefail
source "$HOME/disk4/cs224/l4d_ft/server/env.sh"
cd "$L4D"; mkdir -p run
name=$1; gpus=$2; shift 2
if [[ $gpus == *,* ]]; then
  n=$(( $(tr -cd , <<< "$gpus" | wc -c) + 1 ))
  cmd=("$VENV/bin/torchrun" --standalone --nproc_per_node "$n" server/l4dft.py "$@")
else
  cmd=("$VENV/bin/python" server/l4dft.py "$@")
fi
echo "$(date -u +%FT%TZ) start gpus=$gpus ${cmd[*]}" >> "logs/$name.log"
CUDA_VISIBLE_DEVICES=$gpus setsid nohup "${cmd[@]}" >> "logs/$name.log" 2>&1 < /dev/null &
echo $! > "run/$name.pid"
echo "started $name pid $! gpus=$gpus"

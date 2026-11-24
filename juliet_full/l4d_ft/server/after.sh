#!/usr/bin/env bash
# after.sh <name> <gpu> <cmdfile> <wait>...   detached: waits for every <wait> condition, then runs queue.sh <name> <gpu> <cmdfile>.
#   <wait> = queue:<q>   status/<q>.queue is "done" (aborts if it failed)
#            train:<job> status/<job>.json has "state": "done"
#            frozen:<k>  FROZEN has a fold <k> entry (freeze guard in l4dft.py re-checks hashes)
#   logs/<name>.after.log; status/<name>.queue = waiting until queue.sh takes over.
set -euo pipefail
source "$HOME/disk4/cs224/l4d_ft/server/env.sh"
cd "$L4D"; mkdir -p status logs
name=$1; gpu=$2; cmdfile=$3; shift 3
[ -f "$cmdfile" ] || { echo "no $cmdfile"; exit 1; }
echo waiting > "status/$name.queue"
setsid nohup bash -c '
  name=$1; gpu=$2; cmdfile=$3; shift 3
  for w in "$@"; do
    kind=${w%%:*}; arg=${w#*:}
    while :; do
      case $kind in
        queue)  s=$(cat "status/$arg.queue" 2>/dev/null || true)
                [ "$s" = done ] && break
                case $s in failed*) echo "$(date -u +%FT%TZ) $w $s, abort"; echo "failed:wait $w" > "status/$name.queue"; exit 1;; esac ;;
        train)  grep -q "\"state\": \"done\"" "status/$arg.json" 2>/dev/null && break ;;
        frozen) "$VENV/bin/python" -c "import json,sys; sys.exit(0 if sys.argv[1] in json.load(open(\"FROZEN\"))[\"folds\"] else 1)" "$arg" 2>/dev/null && break ;;
        *) echo "bad wait $w"; echo "failed:wait $w" > "status/$name.queue"; exit 1 ;;
      esac
      sleep 15
    done
    echo "$(date -u +%FT%TZ) $w ok"
  done
  bash server/queue.sh "$name" "$gpu" "$cmdfile"
' _ "$name" "$gpu" "$cmdfile" "$@" >> "logs/$name.after.log" 2>&1 < /dev/null &
echo "after $name pid $! gpu=$gpu waits: $*"

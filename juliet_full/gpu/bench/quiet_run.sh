#!/usr/bin/env bash
# quiet_run.sh <label> <command...>: run a latency measurement on dell under the shared lock
# /tmp/cs224_latency.lock, after load1 < 2.5 (checked once the lock is held). Waits at most 20 minutes in
# total (lock + quiet); if dell does not get quiet it runs anyway and labels the run LOADED.
# Appends one line per run to results/bench/quiet_runs.log (label, load before/after, quiet flag, rc).
set -uo pipefail
LABEL=${1:?label}; shift
LOG=$(cd "$(dirname "$0")/.." && pwd)/results/bench/quiet_runs.log
DEADLINE=$(( $(date +%s) + 1200 ))
exec 9> /tmp/cs224_latency.lock
if ! flock -w 1200 9; then echo "lock not acquired in 20 min" >&2; exit 3; fi
QUIET=quiet
while :; do
  LOAD1=$(cut -d' ' -f1 /proc/loadavg)
  awk -v l="$LOAD1" 'BEGIN{exit !(l < 2.5)}' && break
  if (( $(date +%s) >= DEADLINE )); then QUIET=LOADED; break; fi
  sleep 15
done
BEFORE=$(cut -d' ' -f1-3 /proc/loadavg)
"$@"; RC=$?
AFTER=$(cut -d' ' -f1-3 /proc/loadavg)
echo "$(date -u +%FT%TZ) $LABEL $QUIET load_before=[$BEFORE] load_after=[$AFTER] rc=$RC" | tee -a "$LOG"
exit $RC

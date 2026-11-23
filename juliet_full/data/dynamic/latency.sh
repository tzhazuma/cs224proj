#!/bin/sh
# c1 latency for the dynamic reference line, serialized with the other lanes via the shared lock;
# dynamic_runs.py waits for load1 < 2.5 (one minute) only after the lock is held.
cd "$(dirname "$0")/.." || exit 1
exec flock /tmp/cs224_latency.lock python3 dynamic_runs.py latency --wait-quiet --lock-requested-epoch "$(date +%s.%N)"

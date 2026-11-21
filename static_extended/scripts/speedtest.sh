#!/usr/bin/env bash
# Measure aria2c throughput against a mirror for N seconds, then stop.
set -u
URL="$1"
OUTDIR="$2"
SECS="${3:-45}"
mkdir -p "$OUTDIR"
cd "$OUTDIR" || exit 1
env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY \
aria2c --no-conf --allow-overwrite=true --auto-file-renaming=false \
  --max-connection-per-server=8 --split=8 --min-split-size=4M \
  --console-log-level=warn --summary-interval=0 --timeout=30 --retry-wait=2 \
  --max-tries=2 -o probe.bin "$URL" >/tmp/aria_probe.log 2>&1 &
pid=$!
for _ in $(seq 1 "$SECS"); do sleep 1; kill -0 "$pid" 2>/dev/null || break; done
kill "$pid" 2>/dev/null
sleep 1
pkill -f "aria2c.*probe.bin" 2>/dev/null
du -b probe.bin* 2>/dev/null | tail -5
tail -3 /tmp/aria_probe.log

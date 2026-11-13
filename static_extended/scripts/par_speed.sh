#!/usr/bin/env bash
# Measure true parallel throughput with 4 range requests (no preallocation tricks).
set -u
URL="https://github.com/github/codeql-cli-binaries/releases/download/v2.27.4/codeql-linux64.zip"
DIR=/tmp/par_probe
rm -rf "$DIR"; mkdir -p "$DIR"
for i in 0 1 2 3; do
  S=$((i*10485760)); E=$((S+10485759))
  curl -4 -sSL --noproxy '*' -m 45 -r ${S}-${E} -o "$DIR/p$i" "$URL" &
done
sleep 35
du -cb "$DIR"/p* 2>/dev/null | tail -1
wait
du -cb "$DIR"/p* 2>/dev/null | tail -1

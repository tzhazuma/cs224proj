#!/usr/bin/env bash
# Download CodeQL CLI bundle over a single connection with resume + hash check.
set -uo pipefail
VER="${1:-v2.27.4}"
EXPECT="${2:-393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d}"
DEST="$HOME/tools/downloads"
mkdir -p "$DEST"
ZIP="$DEST/codeql-linux64-${VER}.zip"
URL="https://gh-proxy.com/https://github.com/github/codeql-cli-binaries/releases/download/${VER}/codeql-linux64.zip"
rm -f "$ZIP"
for attempt in 1 2 3 4; do
  echo "== attempt $attempt $(date -u +%H:%M:%S)"
  curl -4 -sSL --noproxy '*' -C - --retry 5 --retry-delay 5 --retry-all-errors \
    -m 3600 -o "$ZIP" "$URL"
  SIZE=$(stat -c %s "$ZIP" 2>/dev/null || echo 0)
  echo "size=$SIZE"
  if [ "$SIZE" = "418431999" ]; then
    GOT=$(sha256sum "$ZIP" | awk '{print $1}')
    echo "sha256=$GOT"
    if [ "$GOT" = "$EXPECT" ]; then echo CHECKSUM_OK; exit 0; fi
    echo CHECKSUM_MISMATCH; rm -f "$ZIP"
  fi
done
echo DOWNLOAD_FAILED
exit 1

#!/usr/bin/env bash
# Download CodeQL bundle from a mirror and verify the official SHA-256.
set -uo pipefail
VER="${1:-v2.27.4}"
EXPECT="${2:-393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d}"
DEST="$HOME/tools/downloads"
mkdir -p "$DEST"
cd "$DEST"
ZIP="codeql-linux64-${VER}.zip"
for MIRROR in https://ghproxy.net https://gh-proxy.com https://ghproxy.cc https://gh.llkk.cc; do
  URL="${MIRROR}/https://github.com/github/codeql-cli-binaries/releases/download/${VER}/codeql-linux64.zip"
  echo "== try ${MIRROR}"
  rm -f "$ZIP" "${ZIP}.aria2"
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY \
  aria2c --no-conf --allow-overwrite=true --auto-file-renaming=false \
    --max-connection-per-server=4 --split=4 --min-split-size=8M \
    --console-log-level=warn --summary-interval=30 --timeout=30 --retry-wait=3 \
    --max-tries=3 --check-certificate=true -o "$ZIP" "$URL" || continue
  GOT=$(sha256sum "$ZIP" | awk '{print $1}')
  echo "got=${GOT}"
  if [ "$GOT" = "$EXPECT" ]; then echo "CHECKSUM_OK"; exit 0; fi
  echo "CHECKSUM_MISMATCH"
done
exit 1

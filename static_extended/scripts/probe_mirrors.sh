#!/usr/bin/env bash
# Probe GitHub mirrors for range support and throughput (5 MiB range).
set -u
PATH_PART="github/codeql-cli-binaries/releases/download/v2.27.4/codeql-linux64.zip"
for M in https://ghproxy.net https://gh-proxy.com https://ghproxy.cc https://gh.llkk.cc https://github.moeyy.xyz https://ghproxy.cfd https://gh-proxy.net https://ghproxy.1888866.xyz; do
  U="$M/https://$PATH_PART"
  R=$(curl -sSL --noproxy '*' -m 25 -r 0-5242879 -o /tmp/probe_$$.bin \
      -w '%{http_code} %{size_download} %{speed_download}' "$U" 2>/dev/null)
  printf '%-30s %s\n' "$M" "$R"
  rm -f /tmp/probe_$$.bin
done

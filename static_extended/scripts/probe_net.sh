#!/usr/bin/env bash
# Network reachability probe (read-only), run in WSL.
set -u
UA='Mozilla/5.0'
probe() {
  local name="$1" url="$2"
  local out
  out=$(curl -sS --noproxy '*' -m 20 -A "$UA" -o /dev/null -w '%{http_code} %{size_download} %{time_total}' "$url" 2>&1) || out="curl-fail: $out"
  printf '%-28s %s\n' "$name" "$out"
}
probe github-raw https://raw.githubusercontent.com/github/codeql/main/README.md
probe ghfast https://ghfast.top/https://raw.githubusercontent.com/github/codeql/main/README.md
probe ghproxy https://gh-proxy.com/https://raw.githubusercontent.com/github/codeql/main/README.md
probe ghproxy-net https://ghproxy.net/https://raw.githubusercontent.com/github/codeql/main/README.md
probe ghapi https://api.github.com/repos/github/codeql-cli-binaries/releases/latest
probe objects https://objects.githubusercontent.com
probe pypi https://pypi.org/simple/semgrep/
probe aliyun https://mirrors.aliyun.com/pypi/simple/semgrep/
probe npm https://registry.npmmirror.com
probe sourceforge https://sourceforge.net

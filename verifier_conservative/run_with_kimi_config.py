#!/usr/bin/env python3
"""Run the conservative verifier with a Kimi Code credential held in memory only.

The key is read from the provider section of the Kimi Code config and copied
into an environment variable for the child process.  It is never printed and
never written to run artifacts; manifests only record whether the variable was
non-empty.

This WSL instance has broken IPv6 reachability to the API host, and Python's
``getaddrinfo`` returns AAAA records first.  Unless ``SECVUL_IPV4_ONLY=0`` is
set, this wrapper filters ``getaddrinfo`` results to IPv4 inside the run
process only.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for path in (HERE, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from conservative.runner import main  # noqa: E402


def _prefer_ipv4() -> bool:
    if os.environ.get("SECVUL_IPV4_ONLY", "1") == "0":
        return False
    original = socket.getaddrinfo

    def ipv4_first(host, port, family=0, type=0, proto=0, flags=0):  # type: ignore[no-untyped-def]
        results = original(host, port, family, type, proto, flags)
        v4 = [item for item in results if item[0] == socket.AF_INET]
        return v4 or results

    socket.getaddrinfo = ipv4_first  # type: ignore[assignment]
    os.environ["SECVUL_IPV4_ONLY"] = "1"
    return True


def main_wrapper() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kimi-config", type=Path, required=True)
    parser.add_argument("--kimi-provider", default="opencode-go")
    args, runner_args = parser.parse_known_args()
    if "--api-key-env" in runner_args:
        parser.error("the wrapper supplies --api-key-env; do not specify it again")
    with args.kimi_config.open("rb") as stream:
        config = tomllib.load(stream)
    provider = config.get("providers", {}).get(args.kimi_provider)
    if not isinstance(provider, dict):
        parser.error(f"provider not found: {args.kimi_provider}")
    api_key = provider.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        parser.error(f"provider has no usable API key: {args.kimi_provider}")
    _prefer_ipv4()
    os.environ["OPENCODE_API_KEY"] = api_key.strip()
    os.environ.setdefault("SECVUL_BASE_URL", provider.get("base_url", ""))
    return main([*runner_args, "--api-key-env", "OPENCODE_API_KEY"])


if __name__ == "__main__":
    sys.exit(main_wrapper())

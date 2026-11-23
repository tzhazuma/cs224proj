#!/usr/bin/env python3
"""Load a provider credential from the Kimi Code TOML into the child process.

The value is copied into an environment variable and is never printed or
written.  This mirrors the credential path already used by ``juliet_llm`` and
``evidence_verify``; only the entry point (the CodeQL triage runner) differs.
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

from codeql_triage.run_triage import main  # noqa: E402


def _prefer_ipv4() -> None:
    original = socket.getaddrinfo

    def ipv4_first(host, port, family=0, type=0, proto=0, flags=0):  # type: ignore[no-untyped-def]
        results = original(host, port, family, type, proto, flags)
        if family == socket.AF_INET6:
            return results
        ipv4 = [item for item in results if item[0] == socket.AF_INET]
        return ipv4 or results

    socket.getaddrinfo = ipv4_first  # type: ignore[assignment]


def main_wrapper() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kimi-config", type=Path, required=True)
    parser.add_argument("--kimi-provider", required=True)
    args, runner_args = parser.parse_known_args()
    if runner_args and runner_args[0] == "--":
        runner_args = runner_args[1:]
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
    os.environ["CODEQL_TRIAGE_API_KEY"] = api_key.strip()
    runner_args = [*runner_args, "--api-key-env", "CODEQL_TRIAGE_API_KEY"]
    return main(runner_args)


if __name__ == "__main__":
    sys.exit(main_wrapper())

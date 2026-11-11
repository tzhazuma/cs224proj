"""Run SecVulEval with a Kimi Code provider credential kept in memory."""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

from secvul_runner.cli import main


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
    os.environ["OPENCODE_API_KEY"] = api_key.strip()
    os.environ.setdefault("SECVUL_BASE_URL", provider.get("base_url", ""))
    return main([*runner_args, "--api-key-env", "OPENCODE_API_KEY"])


if __name__ == "__main__":
    sys.exit(main_wrapper())

#!/usr/bin/env python3
"""Run the evidence prompt with a Kimi Code provider credential in memory.

The key is read from the provider section of the Kimi Code config, copied into
an environment variable for the child process, and never printed or written to
run artifacts.  This mirrors ``runner/run_with_kimi_config.py`` but targets the
evidence-prompt runner.
"""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from evidence_prompt.runner import main  # noqa: E402


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

"""Launch the Juliet LLM CLI with the shared Kimi Code credential loader.

``runner/run_with_kimi_config.py`` reads ``providers.<name>.api_key`` from the
Kimi Code TOML config, puts it in ``OPENCODE_API_KEY`` for the child process,
and never prints it.  That wrapper imports ``secvul_runner.cli.main``; this
launcher replaces that entry point with the Juliet CLI, so the credential path
is reused byte for byte and no second key-reading implementation exists.

Usage::

    python3 juliet_llm/launch.py --kimi-config <config.toml> \
        --kimi-provider opencode-go -- run --model mimo-v2.6-flash --split test
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
RUNNER_DIR = PROJECT_ROOT / "runner"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from juliet_llm.llm_run import main as juliet_main  # noqa: E402

import secvul_runner.cli as runner_cli  # noqa: E402

runner_cli.main = juliet_main

WRAPPER = RUNNER_DIR / "run_with_kimi_config.py"
if not WRAPPER.is_file():
    raise SystemExit(f"shared credential wrapper not found: {WRAPPER}")

sys.argv = [str(WRAPPER), *sys.argv[1:]]
runpy.run_path(str(WRAPPER), run_name="__main__")

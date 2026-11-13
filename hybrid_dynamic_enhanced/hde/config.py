"""Shared configuration for the enhanced-dynamic-guidance experiment.

All paths and identifiers live here so the preflight, runner, analysis and
audit cannot drift apart.  No credential is stored in this module.
"""

from __future__ import annotations

import sys
from pathlib import Path

HDE = Path(__file__).resolve().parent.parent
ROOT = HDE.parent
for _path in (str(ROOT), str(ROOT / "runner"), str(ROOT / "hybrid")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

V2_INPUTS = ROOT / "hybrid" / "inputs_v2"
V2_RUNS = ROOT / "hybrid" / "runs"
JULIET = ROOT / "juliet"
DYNE_EXPORT = ROOT / "dynamic_enhanced" / "exports" / "hybrid"
KIMI_CONFIG = Path("/mnt/c/Users/tzh03/.kimi-code/config.toml")
PROVIDER = "opencode-go"

INPUTS_DIR = HDE / "inputs"
RUNS_DIR = HDE / "runs"
RESULTS_DIR = HDE / "results"

METHOD = "enhanced-dynamic-guided"
GUIDED_PROMPT_VERSION = "hde-juliet-llm-binary-2026-11-14.1"
DIRECT_PROMPT_VERSION = "hybrid-v2-juliet-llm-binary-2026-11-12.2"
SCHEMA_VERSION = "hde-v1"

V2_METHODS = ("direct", "dynamic", "combined")
MODELS = ("deepseek", "mimo")
EXPECTED_UNITS = 140
EXPECTED_LABELS = {"bad": 70, "good": 70}
EXPECTED_TOOL_CONFUSION = {"tp": 70, "fp": 0, "tn": 70, "fn": 0}

# Same endpoint, model ids, budgets and price card as the frozen hybrid v2
# runs, so cost and accuracy are directly comparable.
MODEL_CONFIGS = {
    "deepseek": {
        "display_name": "DeepSeek-V4.1-Flash",
        "model": "deepseek-v4.1-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "max_tokens": 8192,
        "timeout_seconds": 180.0,
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
        "input_price_usd_per_1m": 0.15,
        "output_price_usd_per_1m": 0.60,
        "cached_input_price_usd_per_1m": 0.003,
    },
    "mimo": {
        "display_name": "MiMo-V2.6-Flash",
        "model": "mimo-v2.6-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "max_tokens": 8192,
        "timeout_seconds": 300.0,
        "thinking": "disabled",
        "reasoning_effort": "none",
        "max_tokens_field": "max_completion_tokens",
        "input_price_usd_per_1m": 0.14,
        "output_price_usd_per_1m": 0.28,
        "cached_input_price_usd_per_1m": 0.0028,
    },
}

METHOD_LABELS = {
    "v2-direct": "v2 direct",
    "v2-dynamic": "v2 dynamic (old ASan/LSan + Valgrind evidence)",
    "v2-combined": "v2 combined (old static + old dynamic)",
    "hde-guided": "hde enhanced-dynamic-guided",
    "tool": "dynamic-enhanced tool (default+realloc_fail+nogobal)",
}

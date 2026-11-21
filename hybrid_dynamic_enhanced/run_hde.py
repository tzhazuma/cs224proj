#!/usr/bin/env python3
"""CLI for the enhanced-dynamic-guidance experiment.

    python3 run_hde.py build
    python3 run_hde.py preflight --smoke --run-id enhanced_dynamic_v1
    python3 run_hde.py run --model all --run-id enhanced_dynamic_v1
    python3 run_hde.py analyze
    python3 run_hde.py report
    python3 run_hde.py verify
"""

from __future__ import annotations

import sys

from hde import analyze, audit, build_inputs, preflight, report, run

COMMANDS = {
    "build": build_inputs.main,
    "preflight": preflight.main,
    "run": run.main,
    "analyze": analyze.main,
    "report": report.main,
    "verify": audit.main,
}

USAGE = """usage: run_hde.py <command> [options]

commands:
  build       build inputs/units.jsonl with sanitized enhanced evidence
  preflight   fail-closed gate; add --smoke for one live request per model
  run         run enhanced-dynamic-guided (140 real requests per model)
  analyze     metrics, cost, McNemar and evidence-copy consistency
  report      write REPORT.md and results tables
  verify      artifact audit
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        print(USAGE)
        return 0 if argv else 2
    command, rest = argv[0], argv[1:]
    if command not in COMMANDS:
        print(f"unknown command {command!r}\n\n{USAGE}", file=sys.stderr)
        return 2
    return COMMANDS[command](rest)


if __name__ == "__main__":
    sys.exit(main())

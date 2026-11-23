#!/usr/bin/env python3
"""Dynamic coverage evidence for the frozen Juliet CWE-401 test 140.

Usage (all inside WSL):

    python3 run_dynamic_coverage.py selftest
    python3 run_dynamic_coverage.py run --run-id test140_coverage_v1 --jobs 8
    python3 run_dynamic_coverage.py report --run-dir runs/test140_coverage_v1
    python3 run_dynamic_coverage.py verify --run-dir runs/test140_coverage_v1

`run` never writes into an existing run directory.  It runs the synthetic
selftest first and aborts if the reader is wrong, so a parser bug cannot
silently produce a full run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dyncov import config
from dyncov.pipeline import run_all
from dyncov.report import write_report
from dyncov.selftest import run_selftest
from dyncov.verify import run_verify


def _resolve_run_dir(value: str) -> Path:
    path = Path(value)
    if path.is_dir():
        return path.resolve()
    candidate = config.RUNS / value
    if candidate.is_dir():
        return candidate
    raise SystemExit(f"run directory not found: {value}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest", help="synthetic gcov reader / union control")

    run_parser = sub.add_parser("run", help="run all 140 units x 3 modes")
    run_parser.add_argument("--run-id", default=config.DEFAULT_RUN_ID)
    run_parser.add_argument("--jobs", type=int, default=8)

    for name, help_text in (
        ("report", "build metrics.json, metrics.md and CSV exports"),
        ("verify", "check counts, totals, gcov totals and archived agreement"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--run-dir", required=True)

    args = parser.parse_args(argv)

    if args.command == "selftest":
        result = run_selftest()
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "PASS" else 1

    if args.command == "run":
        selftest = run_selftest()
        if selftest["status"] != "PASS":
            print(json.dumps(selftest, indent=2))
            raise SystemExit("selftest failed; refusing to start a full run")
        result = run_all(args.run_id, jobs=args.jobs)
        run_dir = result["run_dir"]
        metrics = write_report(run_dir)
        verification = run_verify(run_dir)
        print(
            json.dumps(
                {
                    "run_dir": str(run_dir),
                    "wall_seconds": result["manifest"]["wall_seconds"],
                    "units": metrics["units"],
                    "tiers": metrics["coverage_overall"]["tiers"],
                    "crosscheck": metrics["crosscheck"],
                    "verify": verification["status"],
                    "verify_problems": verification["problems"],
                },
                indent=2,
            )
        )
        return 0 if verification["status"] == "PASS" else 1

    run_dir = _resolve_run_dir(args.run_dir)
    if args.command == "report":
        metrics = write_report(run_dir)
        print(json.dumps({"run_dir": str(run_dir), "units": metrics["units"]}, indent=2))
        return 0

    if args.command == "verify":
        result = run_verify(run_dir)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "PASS" else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())

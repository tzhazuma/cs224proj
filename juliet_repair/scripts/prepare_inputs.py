#!/usr/bin/env python3
"""Freeze the 70 sanitised Juliet CWE-401 bad units used for repair."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repair_lib as rl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=0, help="Only the first N units (debug only).")
    parser.add_argument("--force", action="store_true", help="Replace an existing frozen input set.")
    args = parser.parse_args()
    units = rl.load_test_units(limit=args.limit)
    if args.limit or len(units) != 70:
        raise SystemExit(
            f"expected the frozen 70 test bad units, got {len(units)}; "
            "use --limit only for a throwaway debug directory"
        )
    manifest = rl.write_input_freeze(units, force=args.force)
    print(json.dumps(
        {
            "units": manifest["units"],
            "groups": manifest["groups"],
            "c_units": manifest["c_units"],
            "cpp_units": manifest["cpp_units"],
            "leak_audit": manifest["leak_audit"],
            "units_jsonl_sha256": manifest["units_jsonl_sha256"],
        },
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())

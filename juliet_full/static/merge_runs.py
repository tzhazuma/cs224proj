#!/usr/bin/env python3
"""Merge prediction runs by unit_id: lines of later runs replace those of earlier runs.

    merge_runs.py --out results/codeql/layer1/full_batch50_merged.jsonl BASE.jsonl RERUN.jsonl [...]

Used to rerun a few units (e.g. those listed in data/build/changed_units.json, or units hit by a runner fix)
without rerunning a whole layer.  Writes <out> and <out>.meta.json; the meta lists the source runs, how many
lines each contributed and the source metas (versions, commands, timing) verbatim.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("runs", type=Path, nargs="+", help="prediction files, earliest first")
    args = parser.parse_args()
    merged: dict[str, dict] = {}
    source_of: dict[str, str] = {}
    for run in args.runs:
        for line in run.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                merged[row["unit_id"]] = row
                source_of[row["unit_id"]] = str(run)
    args.out.write_text("".join(json.dumps(row) + "\n" for row in merged.values()))
    metas = {}
    for run in args.runs:
        meta_path = run.with_suffix(".meta.json")
        metas[str(run)] = json.loads(meta_path.read_text()) if meta_path.exists() else None
    status_counts: dict[str, int] = {}
    for row in merged.values():
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    meta = {
        "merged_from": [str(r) for r in args.runs],
        "rule": "by unit_id; a later run replaces an earlier one",
        "lines_per_source": {str(r): sum(1 for s in source_of.values() if s == str(r)) for r in args.runs},
        "n_units": len(merged), "status_counts": status_counts,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_metas": metas,
    }
    args.out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps({"out": str(args.out), "n_units": len(merged), "status_counts": status_counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

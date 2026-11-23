#!/usr/bin/env python3
"""Stratified DEV check sample for prompt validation (never touches eval units).

Groups of the dev set minus the L2 example groups (prompts/l2_examples.json) are stratified by
flow_category x mechanism; N groups are allocated proportionally (largest remainder, ties by
stratum name) and drawn with random.Random(seed).sample inside each sorted stratum.
Writes dev_check/<name>_subsets.json ({name: [group_id, ...]}, usable as --subsets-file for
run_llm.py and analysis/score.py) and dev_check/<name>_unit_ids.txt.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR, PROMPT_DIR  # noqa: E402
from llmlane.units import file_sha256, load_units  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--units", required=True, type=Path)
    p.add_argument("--groups", type=int, default=150)
    p.add_argument("--seed", type=int, default=20261123)
    p.add_argument("--name", default="devcheck150")
    p.add_argument("--out-dir", type=Path, default=LLM_DIR / "dev_check")
    p.add_argument("--exclude", type=Path, action="append", default=[],
                   help="subsets file whose groups are also excluded (e.g. an earlier sample)")
    args = p.parse_args(argv)

    examples = {e["group_id"] for e in json.loads((PROMPT_DIR / "l2_examples.json").read_text())["examples"]}
    for path in args.exclude:
        examples |= {g for groups in json.loads(path.read_text()).values() for g in groups}
    units = [u for u in load_units(args.units) if u["set"] == "dev"]
    strata: dict[tuple[str, str], set[str]] = defaultdict(set)
    for u in units:
        if u["group_id"] not in examples:
            strata[(u["flow_category"], u["mechanism"])].add(u["group_id"])
    total = sum(len(g) for g in strata.values())
    quota = {k: args.groups * len(g) / total for k, g in strata.items()}
    alloc = {k: int(q) for k, q in quota.items()}
    for k in sorted(quota, key=lambda k: (-(quota[k] - alloc[k]), k))[: args.groups - sum(alloc.values())]:
        alloc[k] += 1
    rng = random.Random(args.seed)
    chosen = []
    for k in sorted(strata):
        chosen += rng.sample(sorted(strata[k]), alloc[k])
    chosen.sort()
    unit_ids = sorted(u["unit_id"] for u in units if u["group_id"] in set(chosen))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / f"{args.name}_subsets.json").write_text(json.dumps({args.name: chosen}, indent=1) + "\n")
    (args.out_dir / f"{args.name}_unit_ids.txt").write_text("\n".join(unit_ids) + "\n")
    (args.out_dir / f"{args.name}.meta.json").write_text(json.dumps({
        "units_file": str(args.units.resolve()), "units_sha256": file_sha256(args.units), "seed": args.seed,
        "groups": len(chosen), "units": len(unit_ids), "excluded_groups": sorted(examples), "exclude_files": [str(x) for x in args.exclude],
        "allocation": {f"{a}|{b}": [alloc[(a, b)], len(strata[(a, b)])] for a, b in sorted(strata)},
    }, indent=1) + "\n")
    print(f"{len(chosen)} groups, {len(unit_ids)} units; allocation (chosen/available):")
    for a, b in sorted(strata):
        print(f"  {a} {b}: {alloc[(a, b)]}/{len(strata[(a, b)])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

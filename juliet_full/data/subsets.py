#!/usr/bin/env python3
"""Write build/subsets.json (README section 3, PLAN 2.7).

api_subset  = 664 eval groups, stratified by flow_category x mechanism (seed 20261123);
nested25    = 332 groups inside api_subset (same strata);
repeat100   = 100 groups inside nested25;
latency300  = 150 groups (300 units) inside api_subset.
Each draw allocates proportionally per stratum (largest remainder, seeded tie-break) and
samples within the stratum with a seeded RNG over sorted group ids.
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DATA_DIR.parents[1]
SPLIT_PATH = PROJECT_ROOT / "juliet" / "full_split_v1.json"
OUT = DATA_DIR / "build" / "subsets.json"
SEED = 20261123


def stratified(ids: list[str], stratum: dict[str, tuple], k: int, rng: random.Random) -> list[str]:
    groups: dict[tuple, list[str]] = defaultdict(list)
    for gid in sorted(ids):
        groups[stratum[gid]].append(gid)
    total = len(ids)
    quotas = {key: k * len(members) / total for key, members in groups.items()}
    alloc = {key: int(q) for key, q in quotas.items()}
    keys = sorted(groups)
    tie = {key: rng.random() for key in keys}
    leftover = k - sum(alloc.values())
    for key in sorted(keys, key=lambda key: (-(quotas[key] - alloc[key]), tie[key]))[:leftover]:
        alloc[key] += 1
    picked: list[str] = []
    for key in keys:
        picked.extend(rng.sample(groups[key], alloc[key]))
    return sorted(picked)


def main() -> None:
    rows = json.loads(SPLIT_PATH.read_text())["groups"]
    stratum = {r["group_id"]: (r["flow_category"], r["mechanism"]) for r in rows}
    eval_ids = sorted(r["group_id"] for r in rows if r["set"] == "eval")
    rng = random.Random(SEED)
    api = stratified(eval_ids, stratum, 664, rng)
    nested = stratified(api, stratum, 332, rng)
    repeat = stratified(nested, stratum, 100, rng)
    latency = stratified(api, stratum, 150, rng)
    assert set(nested) <= set(api) and set(repeat) <= set(nested) and set(latency) <= set(api)
    out = {"api_subset": api, "nested25": nested, "repeat100": repeat, "latency300": latency}
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    for name, ids in out.items():
        print(name, len(ids), dict(sorted(Counter(stratum[g] for g in ids).items())))


if __name__ == "__main__":
    main()

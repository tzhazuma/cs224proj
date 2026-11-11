#!/usr/bin/env python3
"""Near-duplicate audit for the selected dev/test groups."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_juliet as lj  # noqa: E402
import select_lib as sl  # noqa: E402
import split_clusters as sc  # noqa: E402


def main() -> int:
    groups = {g.group_id: g for g in lj.discover_groups()}
    plans = sl.plan_families(list(groups.values()))
    sc.assign(plans, sc.build_clusters(groups, plans))
    selected = []
    for p in plans.values():
        for g in p.groups:
            tc = groups[g.group_id]
            selected.append((p.split, tc, lj.shingles(lj.normalize_code(lj.iter_group_code(tc)))))
    print(f"selected groups: {len(selected)}")
    for split in ("dev", "test"):
        print(f"  {split}: {sum(1 for s, _, _ in selected if s == split)}")
    cross = []
    within = []
    for (s1, g1, sh1), (s2, g2, sh2) in itertools.combinations(selected, 2):
        if g1.group_id == g2.group_id:
            continue
        j = lj.jaccard(sh1, sh2)
        rec = (j, g1.group_id, g2.group_id, g1.family, g2.family)
        if s1 != s2:
            cross.append(rec)
        else:
            within.append(rec)
    cross.sort(reverse=True)
    within.sort(reverse=True)
    print(f"\ncross-split pairs: {len(cross)}  max={cross[0][0]:.3f}  >=0.8: {sum(j>=0.8 for j,*_ in cross)}  >=0.9: {sum(j>=0.9 for j,*_ in cross)}  >=0.95: {sum(j>=0.95 for j,*_ in cross)}")
    print("top 15 cross-split:")
    for j, a, b, fa, fb in cross[:15]:
        print(f"  {j:.4f} {fa:40s} vs {fb:40s}  {a.split('__')[-1]} / {b.split('__')[-1]}")
    print(f"\nwithin-split max={within[0][0]:.3f}  >=0.9: {sum(j>=0.9 for j,*_ in within)}")
    print("top 8 within:")
    for j, a, b, fa, fb in within[:8]:
        print(f"  {j:.4f} {fa:40s} vs {fb:40s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

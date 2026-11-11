#!/usr/bin/env python3
"""Preflight: discover CWE-401 test cases and verify macro-gated labels."""

from __future__ import annotations

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_juliet as lj  # noqa: E402


def main() -> int:
    groups = lj.discover_groups()
    print(f"testcase groups: {len(groups)}")
    print(f"  C  : {sum(g.language == 'c' for g in groups)}")
    print(f"  C++: {sum(g.language == 'cpp' for g in groups)}")
    by_family = collections.Counter(g.family for g in groups)
    print(f"  families: {len(by_family)}")
    problems = [g for g in groups if g.problems]
    print(f"groups with structural problems: {len(problems)}")
    for g in problems[:40]:
        print(f"  {g.group_id} [{g.language}] {g.problems}")
    multi_main = [g for g in groups if len({p for p, _ in g.main_defs}) > 1]
    print(f"groups with multiple INCLUDEMAIN sources: {len(multi_main)}")
    for g in multi_main:
        print(f"  {g.group_id}: {[p.name for p in g.sources]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

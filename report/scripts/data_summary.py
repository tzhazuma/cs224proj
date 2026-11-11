#!/usr/bin/env python3
"""Print the descriptive statistics used in Table 2 of report_zh.tex.

Reads only the two evaluation JSON files; writes nothing. Run from any
directory with a Python 3 interpreter (standard library only).
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ROOT / "datasets"


def load(name: str):
    with (DATASETS / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def quartiles(rows):
    lines = sorted(row["func_body"].count("\n") + 1 for row in rows)

    def pct(p: float) -> float:
        pos = (len(lines) - 1) * p
        lo = int(pos)
        hi = min(lo + 1, len(lines) - 1)
        return lines[lo] + (lines[hi] - lines[lo]) * (pos - lo)

    return lines[0], pct(0.25), statistics.median(lines), pct(0.75), lines[-1]


def summarize(name: str, rows) -> None:
    low, q1, med, q3, high = quartiles(rows)
    projects = len({row["project"] for row in rows})
    commits = len({(row["project"], row["commit_id"]) for row in rows})
    with_cve = sum(1 for row in rows if row["cve_list"])
    with_changed = sum(1 for row in rows if row["changed_statements"])
    print(
        f"{name}: n={len(rows)} projects={projects} commits={commits} "
        f"lines min={low} q1={q1:.2f} median={med:.1f} q3={q3:.2f} max={high} "
        f"cve={with_cve} changed_statements={with_changed}"
    )


def main() -> None:
    independent = load("independent_200.json")["samples"]
    pairs = load("vulnerable_fixed_200_pairs.json")["pairs"]
    vulnerable = [pair["vulnerable"] for pair in pairs]
    fixed = [pair["fixed"] for pair in pairs]

    summarize("D_ind", independent)
    summarize("D_pair_vulnerable", vulnerable)
    summarize("D_pair_fixed", fixed)

    ind_projects = {row["project"] for row in independent}
    pair_projects = {row["project"] for row in vulnerable}
    print(
        "project_overlap="
        f"{len(ind_projects & pair_projects)} "
        f"project_union={len(ind_projects | pair_projects)}"
    )


if __name__ == "__main__":
    main()

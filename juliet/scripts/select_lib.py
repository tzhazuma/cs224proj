#!/usr/bin/env python3
"""Deterministic family-level selection and dev/test partition."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import lib_juliet as lj

TARGET_GROUPS = 100
TARGET_DEV_UNITS = 60
SEED = "juliet-cwe401-subset-v1"


def _hkey(s: str) -> str:
    return hashlib.sha256(f"{SEED}:{s}".encode()).hexdigest()


def _pick_even(items: list, k: int) -> list:
    if k <= 0:
        return []
    if k >= len(items):
        return list(items)
    if k == 1:
        return [items[0]]
    idxs = sorted({round(i * (len(items) - 1) / (k - 1)) for i in range(k)})
    if len(idxs) != k:
        idxs = list(range(k))
    return [items[i] for i in idxs]


C_INTERPROC = ["22", "54", "68", "21", "51", "52", "53", "41", "42", "44", "45", "31"]
CPP_INTERPROC = ["31", "82", "54", "68", "22", "43", "72", "83", "84"]


def _pick_c(groups: list, k: int, family: str) -> list:
    by_var = {g.variant: g for g in groups}
    if k <= 0:
        return []
    picks = []
    if "01" in by_var:
        picks.append(by_var["01"])
    primary = C_INTERPROC[:3]
    start = int(_hkey(family)[:8], 16) % len(primary)
    order = primary[start:] + primary[:start] + C_INTERPROC[3:]
    for v in order:
        if len(picks) >= k:
            break
        if v in by_var and by_var[v] not in picks:
            picks.append(by_var[v])
    if len(picks) < k:
        for g in _pick_even(groups, k):
            if g not in picks:
                picks.append(g)
            if len(picks) >= k:
                break
    return sorted(picks, key=lambda g: (int(g.variant), g.variant))[:k]


def _pick_cpp(groups: list, k: int, family: str, dual: bool) -> list:
    by_var = {g.variant: g for g in groups}
    if k <= 0:
        return []
    if dual:
        for v in ("33", "43", "82"):
            if v in by_var:
                return [by_var[v]]
        return [groups[0]]
    picks = []
    if "01" in by_var:
        picks.append(by_var["01"])
    start = int(_hkey("cpp:" + family)[:8], 16) % max(1, len(CPP_INTERPROC))
    order = CPP_INTERPROC[start:] + CPP_INTERPROC[:start]
    for v in order:
        if len(picks) >= k:
            break
        if v in by_var and by_var[v] not in picks:
            picks.append(by_var[v])
    if len(picks) < k:
        for g in _pick_even(groups, k):
            if g not in picks:
                picks.append(g)
            if len(picks) >= k:
                break
    return sorted(picks, key=lambda g: (int(g.variant), g.variant))[:k]


@dataclass
class FamilyPlan:
    family: str
    k: int
    c_groups: list
    cpp_groups: list
    split: str | None = None

    @property
    def groups(self) -> list:
        return self.c_groups + self.cpp_groups

    @property
    def units(self) -> int:
        return 2 * self.k

    @property
    def c_units(self) -> int:
        return 2 * len(self.c_groups)

    @property
    def cpp_units(self) -> int:
        return 2 * len(self.cpp_groups)

    @property
    def category(self) -> str:
        if self.c_groups and self.cpp_groups:
            return "dual"
        return "c" if self.c_groups else "cpp"


def plan_families(groups: list[lj.TestCase]) -> dict[str, FamilyPlan]:
    by_family: dict[str, dict[str, list]] = {}
    for g in groups:
        if g.problems:
            continue
        by_family.setdefault(g.family, {"c": [], "cpp": []})[g.language].append(g)
    for fam, d in by_family.items():
        for lang in ("c", "cpp"):
            d[lang].sort(key=lambda g: (int(g.variant), g.variant))
    families = sorted(by_family)
    k = {f: min(2, len(by_family[f]["c"]) + len(by_family[f]["cpp"])) for f in families}

    extras = TARGET_GROUPS - sum(k.values())
    if extras < 0:
        raise SystemExit(f"base selection already exceeds target: {sum(k.values())}")
    eligible = sorted(families, key=_hkey)
    while extras:
        progressed = False
        for fam in eligible:
            total = len(by_family[fam]["c"]) + len(by_family[fam]["cpp"])
            if k[fam] < min(3, total):
                k[fam] += 1
                extras -= 1
                progressed = True
                if not extras:
                    break
        if not progressed:
            raise SystemExit("not enough eligible families to reach target group count")

    plans: dict[str, FamilyPlan] = {}
    for fam in families:
        c_all = by_family[fam]["c"]
        cpp_all = by_family[fam]["cpp"]
        have_c, have_cpp = bool(c_all), bool(cpp_all)
        kk = k[fam]
        if have_c and have_cpp:
            n_cpp = 1
            n_c = kk - n_cpp
        elif have_c:
            n_c, n_cpp = kk, 0
        else:
            n_c, n_cpp = 0, kk
        c_pick = _pick_c(c_all, n_c, fam) if n_c else []
        cpp_pick = _pick_cpp(cpp_all, n_cpp, fam, dual=have_c and have_cpp) if n_cpp else []
        plans[fam] = FamilyPlan(fam, kk, c_pick, cpp_pick)
    return plans


def assign_splits(plans: dict[str, FamilyPlan]) -> dict[str, list[str]]:
    families = sorted(plans, key=_hkey)
    states: dict[tuple[int, int, int], tuple[int, ...]] = {(0, 0, 0): ()}
    for i, fam in enumerate(families):
        p = plans[fam]
        additions = {}
        for (units, nfam, cunits), subset in states.items():
            nu = units + p.units
            if nu > 72:
                continue
            key = (nu, nfam + 1, cunits + p.c_units)
            if key not in states and key not in additions:
                additions[key] = subset + (i,)
        states.update(additions)

    best = None
    for (units, nfam, cunits), subset in states.items():
        cppunits = units - cunits
        if not (56 <= units <= 64 and 10 <= nfam <= 16):
            continue
        if cunits < 12 or cppunits < 12:
            continue
        chosen = [families[i] for i in subset]
        cats = {plans[f].category for f in chosen}
        if cats != {"dual", "c", "cpp"}:
            continue
        score = (
            abs(units - TARGET_DEV_UNITS) * 20
            + abs(nfam - 13) * 3
            + abs(cunits - cppunits) * 2
        )
        tie = _hkey(",".join(chosen))
        cand = (score, tie, chosen)
        if best is None or cand[:2] < best[:2]:
            best = cand
    if best is None:
        raise SystemExit("no feasible family-level dev/test partition found")

    dev = set(best[2])
    for fam in families:
        plans[fam].split = "dev" if fam in dev else "test"
    return {
        "dev": sorted(dev),
        "test": sorted(set(families) - dev),
        "score": {"units": sum(plans[f].units for f in dev), "families": len(dev)},
    }


def summarize(plans: dict[str, FamilyPlan]) -> dict:
    out = {"total_groups": 0, "total_units": 0, "splits": {}}
    for split in ("dev", "test"):
        ps = [p for p in plans.values() if p.split == split]
        out["splits"][split] = {
            "families": len(ps),
            "groups": sum(p.k for p in ps),
            "units": sum(p.units for p in ps),
            "units_bad": sum(p.units // 2 for p in ps),
            "units_good": sum(p.units // 2 for p in ps),
            "c_units": sum(p.c_units for p in ps),
            "cpp_units": sum(p.cpp_units for p in ps),
            "family_names": sorted(p.family for p in ps),
        }
        out["total_groups"] += sum(p.k for p in ps)
        out["total_units"] += sum(p.units for p in ps)
    return out

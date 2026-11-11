#!/usr/bin/env python3
"""Partition families into near-duplicate clusters and assign clusters to splits."""

from __future__ import annotations

import hashlib
import itertools

import lib_juliet as lj
import select_lib as sl

THRESHOLD = 0.85


class _UF:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_clusters(groups: dict[str, lj.TestCase], plans: dict[str, sl.FamilyPlan], threshold: float = THRESHOLD) -> dict:
    items = []
    for p in plans.values():
        for g in p.groups:
            tc = groups[g.group_id]
            items.append(
                (p.family, lj.shingles(lj.normalize_code(lj.iter_group_code(tc))))
            )
    uf = _UF()
    for f in plans:
        uf.find(f)
    for (f1, s1), (f2, s2) in itertools.combinations(items, 2):
        if f1 == f2:
            continue
        if lj.jaccard(s1, s2) >= threshold:
            uf.union(f1, f2)
    clusters: dict[str, list[str]] = {}
    for f in plans:
        clusters.setdefault(uf.find(f), []).append(f)
    out = []
    for cid, fams in enumerate(sorted((sorted(v) for v in clusters.values()), key=lambda x: (-len(x), x))):
        fams = sorted(fams)
        ps = [plans[f] for f in fams]
        out.append({
            "cluster_id": f"nd-{cid:02d}",
            "families": fams,
            "units": sum(p.units for p in ps),
            "c_units": sum(p.c_units for p in ps),
            "cpp_units": sum(p.cpp_units for p in ps),
            "groups": sum(p.k for p in ps),
            "categories": sorted({p.category for p in ps}),
        })
    return {"threshold": threshold, "clusters": out}


MECHANISMS = ("malloc", "calloc", "realloc", "malloc_realloc", "new", "new_array", "strdup", "destructor")


def mechanism(family: str) -> str:
    if "destructor" in family:
        return "destructor"
    if "strdup" in family:
        return "strdup"
    if "malloc_realloc" in family:
        return "malloc_realloc"
    if family.startswith("new_array"):
        return "new_array"
    if family.startswith("new_"):
        return "new"
    if family.endswith("_calloc"):
        return "calloc"
    if family.endswith("_malloc"):
        return "malloc"
    if family.endswith("_realloc"):
        return "realloc"
    return "other"


def assign(plans: dict[str, sl.FamilyPlan], clusters_doc: dict) -> dict:
    clusters = clusters_doc["clusters"]
    if len(clusters) > 22:
        raise SystemExit("too many clusters for exhaustive partition")
    best = None
    for mask in range(1, 1 << len(clusters)):
        subset = tuple(i for i in range(len(clusters)) if mask & (1 << i))
        chosen = [clusters[i] for i in subset]
        units = sum(c["units"] for c in chosen)
        cunits = sum(c["c_units"] for c in chosen)
        nfam = sum(len(c["families"]) for c in chosen)
        cppunits = units - cunits
        if not (56 <= units <= 64 and 10 <= nfam <= 18):
            continue
        if cunits < 24 or cppunits < 24:
            continue
        cats = {c for cl in chosen for c in cl["categories"]}
        if cats != {"dual", "c", "cpp"}:
            continue
        fams = [f for cl in chosen for f in cl["families"]]
        mechs = {mechanism(f) for f in fams}
        has_c_alloc = bool(mechs & {"malloc", "calloc", "realloc"})
        has_new = bool(mechs & {"new", "new_array"})
        if not has_c_alloc or not has_new:
            continue
        score = (
            abs(units - sl.TARGET_DEV_UNITS) * 20
            + abs(cunits - cppunits) * 2
            + abs(nfam - 13)
            + (len(MECHANISMS) - len(mechs & set(MECHANISMS))) * 10
        )
        tie = hashlib.sha256(("clusters:" + ",".join(sorted(fams))).encode()).hexdigest()
        cand = (score, tie, subset)
        if best is None or cand[:2] < best[:2]:
            best = cand
    if best is None:
        raise SystemExit("no feasible cluster-level dev/test partition")

    dev_clusters = set(best[2])
    for i, c in enumerate(clusters):
        c["split"] = "dev" if i in dev_clusters else "test"
    for p in plans.values():
        for c in clusters:
            if p.family in c["families"]:
                p.split = c["split"]
                break
    dev_fams = [f for i in dev_clusters for f in clusters[i]["families"]]
    return {
        "dev_clusters": sorted(clusters[i]["cluster_id"] for i in dev_clusters),
        "test_clusters": sorted(c["cluster_id"] for i, c in enumerate(clusters) if i not in dev_clusters),
        "dev_units": sum(clusters[i]["units"] for i in dev_clusters),
        "dev_families": sum(len(clusters[i]["families"]) for i in dev_clusters),
        "dev_mechanisms": sorted({mechanism(f) for f in dev_fams}),
        "dev_score": best[0],
    }

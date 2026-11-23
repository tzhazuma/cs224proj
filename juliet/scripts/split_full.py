#!/usr/bin/env python3
"""Full Juliet CWE-401 split (v1): frozen dev set + 3-fold evaluation set.

Decided 2026-11-23 (see research/juliet_dataset_adjustment.md).

Rules
- Unit of assignment = flow variant (all groups of a variant go to one side).
- Dev ~20% (course-guide 20/80 protocol): quota per flow category
  02-22: 4, 31-45: 2, 51-68: 2, 71-84: 1; 01 never in dev.
- Dev candidates must contain C++ `new` families; 02-22 candidates must also
  contain malloc_realloc families; variants 01 and 12 stay in evaluation.
- Seeded sampling (SEED); evaluation variants are assigned to 3 folds,
  balanced per flow category by group count.

Output: juliet/full_split_v1.json (+ printed SHA-256).
"""

from __future__ import annotations

import collections
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_juliet as lj  # noqa: E402

SEED = 20261123
QUOTA = {"02-22": 4, "31-45": 2, "51-68": 2, "71-84": 1}
KEEP_IN_EVAL = {"01", "12"}
N_FOLDS = 3
CATS = ["01", "02-22", "31-45", "51-68", "71-84"]
OUT = lj.ROOT / "full_split_v1.json"


def flow_category(variant: str) -> str:
    v = int(variant)
    if v == 1:
        return "01"
    if v <= 22:
        return "02-22"
    if v <= 45:
        return "31-45"
    if v <= 68:
        return "51-68"
    return "71-84"


def mechanism(family: str) -> str:
    if family.startswith("malloc_realloc"):
        return "realloc_fail"
    if family.startswith("new"):
        return "cpp_new"
    if "destructor" in family:
        return "destructor"
    return "c_alloc"


def main() -> int:
    groups = lj.discover_groups()
    bad = [g.group_id for g in groups if g.problems]
    if bad:
        raise SystemExit(f"groups with problems: {bad[:5]}")

    mech_by_variant: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for g in groups:
        mech_by_variant[g.variant][mechanism(g.family)] += 1
    size = {v: sum(c.values()) for v, c in mech_by_variant.items()}

    rng = random.Random(SEED)
    by_cat: dict[str, list[str]] = collections.defaultdict(list)
    for v in sorted(mech_by_variant):
        by_cat[flow_category(v)].append(v)

    dev: list[str] = []
    for cat, k in QUOTA.items():
        pool = [
            v for v in by_cat[cat]
            if v not in KEEP_IN_EVAL
            and mech_by_variant[v]["cpp_new"] > 0
            and (cat != "02-22" or mech_by_variant[v]["realloc_fail"] > 0)
        ]
        dev += sorted(rng.sample(pool, k))

    ev = [v for v in sorted(mech_by_variant) if v not in dev]
    folds: dict[int, list[str]] = {i: [] for i in range(N_FOLDS)}
    load = [0] * N_FOLDS
    for cat in CATS:
        vs = [v for v in ev if flow_category(v) == cat]
        rng.shuffle(vs)
        for v in sorted(vs, key=lambda u: -size[u]):
            cat_load = [sum(size[u] for u in folds[i] if flow_category(u) == cat) for i in range(N_FOLDS)]
            i = min(range(N_FOLDS), key=lambda j: (cat_load[j], load[j]))
            folds[i].append(v)
            load[i] += size[v]
    fold_of = {v: i for i, vs in folds.items() for v in vs}

    rows = []
    for g in sorted(groups, key=lambda x: x.group_id):
        in_dev = g.variant in dev
        rows.append({
            "group_id": g.group_id,
            "family": g.family,
            "variant": g.variant,
            "flow_category": flow_category(g.variant),
            "mechanism": mechanism(g.family),
            "language": g.language,
            "set": "dev" if in_dev else "eval",
            "fold": None if in_dev else fold_of[g.variant],
        })

    def summary(sel):
        return {
            "groups": len(sel),
            "units": 2 * len(sel),
            "by_flow_category": dict(sorted(collections.Counter(r["flow_category"] for r in sel).items())),
            "by_mechanism": dict(sorted(collections.Counter(r["mechanism"] for r in sel).items())),
            "by_language": dict(sorted(collections.Counter(r["language"] for r in sel).items())),
        }

    doc = {
        "schema_version": 1,
        "name": "juliet-cwe401-full-split-v1",
        "decided": "2026-11-23",
        "source": "NIST SARD Juliet C/C++ v1.3, CWE401_Memory_Leak (all groups)",
        "seed": SEED,
        "rules": {
            "assignment_unit": "flow_variant",
            "dev_quota": QUOTA,
            "keep_in_eval": sorted(KEEP_IN_EVAL),
            "dev_candidate_constraints": "contains cpp_new; 02-22 also contains realloc_fail",
            "n_folds": N_FOLDS,
            "fold_balancing": "per flow category by group count",
        },
        "dev_variants": dev,
        "fold_variants": {str(i): sorted(vs) for i, vs in folds.items()},
        "summary": {
            "dev": summary([r for r in rows if r["set"] == "dev"]),
            "eval": summary([r for r in rows if r["set"] == "eval"]),
            **{f"fold_{i}": summary([r for r in rows if r["fold"] == i]) for i in range(N_FOLDS)},
        },
        "groups": rows,
    }
    text = json.dumps(doc, indent=1, sort_keys=False) + "\n"
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    print("sha256", hashlib.sha256(text.encode()).hexdigest())
    print("dev", dev, doc["summary"]["dev"]["groups"])
    for i in range(N_FOLDS):
        print(f"fold {i}", doc["fold_variants"][str(i)], doc["summary"][f"fold_{i}"]["groups"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Independent verification of the frozen Juliet CWE-401 subset.

Checks hashes, macro-gated labels, split disjointness, near-duplicate
guarantees and (with ``--build``) recompiles and re-runs every unit with
AddressSanitizer/LeakSanitizer.  Exits non-zero on the first failed check.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import itertools
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_lib as bl  # noqa: E402
import lib_juliet as lj  # noqa: E402


def fail(msg: str) -> None:
    raise SystemExit(f"FAIL: {msg}")


def check(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


def sha256_file(p: Path) -> str:
    return lj.sha256_file(p)


def unit_testcase(u: dict) -> lj.TestCase:
    sources = [lj.ROOT / s["path"] for s in u["sources"]]
    main_defs = []
    for src in sources:
        funcs, _ = lj.parse_functions(src)
        for fn in funcs:
            if fn.short_name == "main" and fn.included["bad_build"]:
                main_defs.append((src, fn))
    return lj.TestCase(
        group_id=u["group_id"],
        family=u["family"],
        variant=u["variant"],
        language=u["language"],
        sources=sources,
        headers=[lj.ROOT / h["path"] for h in u["headers"]],
        main_defs=main_defs,
    )


def verify_guard(u: dict) -> None:
    label = u["label"]
    ev = u["guard_evidence"]
    for kind in ("bad_entry", "good_entry"):
        entry = ev[kind]
        src = lj.ROOT / entry["source"]
        check(src.exists(), f"{u['unit_id']}: entry source missing {entry['source']}")
        funcs, _ = lj.parse_functions(src)
        matches = [f for f in funcs if f.name == entry["name"] and f.line == entry["line"]]
        check(len(matches) == 1, f"{u['unit_id']}: cannot locate {kind} at {entry['source']}:{entry['line']}")
        fn = matches[0]
        want_bad = kind == "bad_entry"
        check(fn.included["bad_build"] == want_bad, f"{u['unit_id']}: {kind} macro inclusion mismatch")
        check(fn.included["good_build"] != want_bad, f"{u['unit_id']}: {kind} not label-specific")
    # Scan every source of this unit and count entry points included in the
    # build selected by the unit label.
    defines_key = "bad_build" if label == "bad" else "good_build"
    inc_bad = inc_good = 0
    for src in [lj.ROOT / s["path"] for s in u["sources"]]:
        funcs, _ = lj.parse_functions(src)
        for fn in funcs:
            if not fn.included[defines_key]:
                continue
            if lj._is_bad_entry(fn.name):
                inc_bad += 1
            if lj._is_good_entry(fn.name):
                inc_good += 1
    if label == "bad":
        check(inc_bad == 1 and inc_good == 0, f"{u['unit_id']}: bad build includes bad={inc_bad} good={inc_good}")
    else:
        check(inc_good == 1 and inc_bad == 0, f"{u['unit_id']}: good build includes good={inc_good} bad={inc_bad}")
    check(u["main_source"] in [s["path"] for s in u["sources"]],
          f"{u['unit_id']}: main_source not in sources")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", action="store_true", help="recompile and rerun all units")
    ap.add_argument("--jobs", type=int, default=6)
    args = ap.parse_args()

    manifest_path = lj.ROOT / "manifest.json"
    check(manifest_path.exists(), "manifest.json missing")
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    units = man["units"]
    print(f"manifest: {man['dataset_id']}  units={len(units)}")

    # 1. source provenance
    arch = lj.ROOT / "cache" / "juliet-c-cplusplus-v1.3.zip"
    check(arch.exists(), "archive missing")
    check(sha256_file(arch) == man["source"]["archive_sha256"], "archive sha256 mismatch")
    prov = json.loads((lj.ROOT / "provenance.json").read_text(encoding="utf-8"))
    check(prov["archive"]["sha256"] == man["source"]["archive_sha256"], "provenance archive hash mismatch")
    for rel, meta in prov["files"].items():
        p = lj.ROOT / "raw" / rel
        check(p.exists(), f"raw file missing: {rel}")
        check(p.stat().st_size == meta["bytes"] and sha256_file(p) == meta["sha256"], f"raw hash mismatch: {rel}")
    print(f"  provenance: archive + {len(prov['files'])} raw files verified")

    # 2. counts
    check(len(units) == 200, f"expected 200 units, got {len(units)}")
    check(len({u["group_id"] for u in units}) == 100, "expected 100 groups")
    check(sum(u["label"] == "bad" for u in units) == 100, "bad/good imbalance")
    check(sum(u["label"] == "good" for u in units) == 100, "bad/good imbalance")
    for split in ("dev", "test"):
        us = [u for u in units if u["split"] == split]
        check(sum(u["label"] == "bad" for u in us) == sum(u["label"] == "good" for u in us),
              f"{split}: bad/good imbalance")
    check(len({u["family"] for u in units}) == 42, "not all 42 families represented")

    # 3. per-unit files, hashes, guards, split isolation
    families_split = collections.defaultdict(set)
    groups_split = collections.defaultdict(set)
    for u in units:
        for f in u["sources"] + u["headers"]:
            p = lj.ROOT / f["path"]
            check(p.exists(), f"{u['unit_id']}: missing {f['path']}")
            check(p.stat().st_size == f["bytes"], f"{u['unit_id']}: size mismatch {f['path']}")
            check(sha256_file(p) == f["sha256"], f"{u['unit_id']}: hash mismatch {f['path']}")
        check(u["verification"]["compiled_ok"], f"{u['unit_id']}: not compiled")
        check(u["verification"]["symbol_gate_ok"], f"{u['unit_id']}: symbol gate failed")
        check(not u["runtime_check"]["other_asan_error"], f"{u['unit_id']}: ASan error")
        check(not u["runtime_check"]["timed_out"], f"{u['unit_id']}: runtime timeout")
        if u["label"] == "good":
            check(not u["runtime_check"]["leak_detected"], f"{u['unit_id']}: good unit leaked")
            check(u["verification"]["runtime_label_ok"], f"{u['unit_id']}: good runtime flag false")
        verify_guard(u)
        families_split[u["family"]].add(u["split"])
        groups_split[u["group_id"]].add(u["split"])
    for fam, splits in families_split.items():
        check(len(splits) == 1, f"family {fam} spans splits {splits}")
    for gid, splits in groups_split.items():
        check(len(splits) == 1, f"group {gid} spans splits {splits}")
    print(f"  units: files/hashes/guards/split isolation verified ({len(families_split)} families)")

    # 4. split statistics agree with the manifest
    for split in ("dev", "test"):
        us = [u for u in units if u["split"] == split]
        st = man["splits"][split]
        check(len(us) == st["units"], f"{split}: manifest unit count mismatch")
        check(len({u["family"] for u in us}) == st["families"], f"{split}: family count mismatch")
        check(sum(u["language"] == "c" for u in us) == st["c_units"], f"{split}: C count mismatch")
        check(sum(u["language"] == "cpp" for u in us) == st["cpp_units"], f"{split}: C++ count mismatch")
    print(f"  splits: dev={man['splits']['dev']['units']} test={man['splits']['test']['units']}")

    # 5. near-duplicate audit, recomputed from the source files
    by_group = {}
    for u in units:
        by_group.setdefault(u["group_id"], u)
    items = []
    for gid, u in by_group.items():
        tc = unit_testcase(u)
        items.append((u["split"], gid, u["family"], lj.shingles(lj.normalize_code(lj.iter_group_code(tc)))))
    cross = []
    for a, b in itertools.combinations(items, 2):
        if a[0] == b[0]:
            continue
        j = lj.jaccard(a[3], b[3])
        cross.append((j, a[1], b[1]))
    cross.sort(reverse=True)
    threshold = man["near_duplicate_audit"]["threshold"]
    over = [c for c in cross if c[0] >= threshold]
    check(not over, f"near-duplicate leakage: {len(over)} pairs >= {threshold}, top={cross[:3]}")
    check(abs(cross[0][0] - man["near_duplicate_audit"]["cross_split_max"]) < 1e-3,
          "manifest near-duplicate max disagrees")
    print(f"  near-duplicates: cross max={cross[0][0]:.4f} < {threshold} (0 violations)")

    # 6. SHA256SUMS
    sums = lj.ROOT / "SHA256SUMS"
    check(sums.exists(), "SHA256SUMS missing")
    listed = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        h, rel = line.split("  ", 1)
        listed[rel] = h
    check(len(listed) > 2839, f"SHA256SUMS too short: {len(listed)}")
    for rel, h in listed.items():
        p = lj.ROOT / rel
        check(p.exists(), f"SHA256SUMS path missing: {rel}")
        check(sha256_file(p) == h, f"SHA256SUMS mismatch: {rel}")
    for rel in man["per_file_sha256"]:
        check(rel in listed, f"selected file absent from SHA256SUMS: {rel}")
    print(f"  SHA256SUMS: {len(listed)} files verified")

    # 7. JSONL agrees with the manifest
    jsonl = [json.loads(line) for line in (lj.ROOT / "subset_units.jsonl").read_text(encoding="utf-8").splitlines()]
    check(len(jsonl) == len(units), "subset_units.jsonl length mismatch")
    check({j["unit_id"] for j in jsonl} == {u["unit_id"] for u in units}, "subset_units.jsonl ids mismatch")

    # 8. optional independent recompile + ASan run
    if args.build:
        print(f"  rebuilding {len(units)} units independently (jobs={args.jobs})...")
        build_root = lj.ROOT / "build" / "verify"
        objs = bl.support_objects(build_root)
        results = {}
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            fut = {}
            for u in units:
                tc = unit_testcase(u)
                fut[pool.submit(bl.evaluate, tc, u["label"], build_root / "units", objs)] = u
            for f in concurrent.futures.as_completed(fut):
                u = fut[f]
                results[u["unit_id"]] = f.result()
        bad_ok = good_ok = bad_leak = 0
        for u in units:
            r = results[u["unit_id"]]
            check(r["compile"]["ok"], f"{u['unit_id']}: independent compile failed")
            check(r["label_ok"], f"{u['unit_id']}: independent macro/symbol check failed")
            check(not r["run"]["other_asan_error"], f"{u['unit_id']}: independent ASan error")
            if u["label"] == "bad":
                bad_ok += 1
                bad_leak += bool(r["run"]["leak_detected"])
            else:
                check(not r["run"]["leak_detected"], f"{u['unit_id']}: good unit leaked")
                good_ok += 1
        print(f"  independent rebuild: {bad_ok} bad units built, {bad_leak} leaked in default run; "
              f"{good_ok} good units clean")

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

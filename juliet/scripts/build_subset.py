#!/usr/bin/env python3
"""Build and freeze the Juliet CWE-401 evaluation subset.

Steps:
1. verify the SARD archive and extracted-file hashes in ``provenance.json``;
2. select 100 test cases (200 bad/good units) across all 42 filename families;
3. compile every unit with ASan and run LeakSanitizer;
4. backfill any unit that fails to compile or whose runtime label disagrees;
5. partition whole near-duplicate clusters into dev/test;
6. write ``manifest.json``, ``subset_units.jsonl``, ``SHA256SUMS`` and
   ``FREEZE.json``.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_lib as bl  # noqa: E402
import lib_juliet as lj  # noqa: E402
import select_lib as sl  # noqa: E402
import split_clusters as sc  # noqa: E402

EXPECTED_ARCHIVE_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
DATASET_ID = "juliet-cwe401-v1.3-subset-v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    return lj.sha256_file(path)


def run_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (out.stdout or out.stderr).splitlines()[0].strip()
    except Exception as exc:  # pragma: no cover - diagnostic only
        return f"unavailable: {exc}"


def verify_provenance() -> dict:
    prov_path = lj.ROOT / "provenance.json"
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    arch = lj.ROOT / "cache" / "juliet-c-cplusplus-v1.3.zip"
    if not arch.exists():
        raise SystemExit(f"missing archive: {arch}")
    got = sha256_file(arch)
    if got != EXPECTED_ARCHIVE_SHA256:
        raise SystemExit(f"archive sha256 mismatch: {got}")
    if prov["archive"]["sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise SystemExit("provenance.json archive hash mismatch")
    missing, bad = [], []
    for rel, meta in prov["files"].items():
        p = lj.ROOT / "raw" / rel
        if not p.exists():
            missing.append(rel)
            continue
        if p.stat().st_size != meta["bytes"] or sha256_file(p) != meta["sha256"]:
            bad.append(rel)
    if missing or bad:
        raise SystemExit(f"raw file verification failed: missing={missing[:5]} bad={bad[:5]}")
    prov["archive"]["sha256_verified"] = got
    prov["files_verified"] = len(prov["files"])
    prov["provenance_sha256"] = sha256_file(prov_path)
    return prov


def guard_evidence(tc: lj.TestCase) -> dict:
    bad = good = None
    for src in tc.sources:
        funcs, _ = lj.parse_functions(src)
        for fn in funcs:
            if (
                lj._is_bad_entry(fn.name)
                and fn.included["bad_build"]
                and not fn.included["good_build"]
                and bad is None
            ):
                bad = {"name": fn.name, "source": lj.rel(src), "line": fn.line,
                       "guards": [{"expr": e, "at": at} for e, at in fn.guards]}
            if (
                lj._is_good_entry(fn.name)
                and fn.included["good_build"]
                and not fn.included["bad_build"]
                and good is None
            ):
                good = {"name": fn.name, "source": lj.rel(src), "line": fn.line,
                        "guards": [{"expr": e, "at": at} for e, at in fn.guards]}
    if bad is None or good is None:
        raise RuntimeError(f"missing guard evidence for {tc.group_id}")
    return {
        "bad_entry": bad,
        "good_entry": good,
        "included_when": {
            "bad_build_defines": ["INCLUDEMAIN", "OMITGOOD"],
            "good_build_defines": ["INCLUDEMAIN", "OMITBAD"],
            "bad_entry_in_bad_build": True,
            "bad_entry_in_good_build": False,
            "good_entry_in_bad_build": False,
            "good_entry_in_good_build": True,
        },
    }


def compact_result(res: dict, label: str) -> dict:
    comp = res["compile"]
    run = res.get("run", {})
    runtime_supports = res.get("runtime_supports_label")
    if runtime_supports is None:
        runtime_supports = run.get("leak_detected") if label == "bad" else not run.get("leak_detected")
    label_ok = bool(
        comp.get("ok")
        and res.get("symbol_ok")
        and not run.get("other_asan_error")
        and not run.get("timed_out")
        and (label == "bad" or not run.get("leak_detected"))
    )
    return {
        "ok": label_ok,
        "label_ok": label_ok,
        "symbol_ok": res.get("symbol_ok"),
        "runtime_supports_label": bool(runtime_supports),
        "compiler": comp.get("compiler"),
        "compile_ok": comp.get("ok"),
        "compile_returncode": comp.get("returncode"),
        "sources": comp.get("sources", []),
        "defines": comp.get("defines", []),
        "command": comp.get("command", []),
        "executable": comp.get("executable"),
        "symbols": res.get("symbols", {}),
        "run": {
            "leak_detected": run.get("leak_detected"),
            "other_asan_error": run.get("other_asan_error"),
            "timed_out": run.get("timed_out"),
            "returncode": run.get("returncode"),
            "summary": run.get("summary"),
            "stderr_tail": run.get("stderr_tail"),
            "stdout_head": run.get("stdout_head"),
        },
    }


def build_tasks(tasks: list[tuple[lj.TestCase, str]], build_root: Path, objs: dict, jobs: int) -> dict:
    results: dict[tuple[str, str], dict] = {}
    result_dir = build_root / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        fut = {
            pool.submit(bl.evaluate, tc, label, build_root / "units", objs): (tc, label)
            for tc, label in tasks
        }
        for future in concurrent.futures.as_completed(fut):
            tc, label = fut[future]
            res = future.result()
            compact = compact_result(res, label)
            results[(tc.group_id, label)] = compact
            (result_dir / f"{tc.group_id}__{label}.json").write_text(
                json.dumps(compact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            done = len(results)
            status = "OK" if compact["label_ok"] else "FAIL"
            print(f"  [{done}/{len(tasks)}] {tc.group_id} {label}: {status}", flush=True)
    return results


def evaluate_one(tc: lj.TestCase, build_root: Path, objs: dict) -> dict:
    out = {}
    for label in ("bad", "good"):
        res = bl.evaluate(tc, label, build_root / "units", objs)
        out[label] = compact_result(res, label)
        rd = build_root / "results"
        rd.mkdir(parents=True, exist_ok=True)
        (rd / f"{tc.group_id}__{label}.json").write_text(
            json.dumps(out[label], indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return out


def backfill(plans: dict[str, sl.FamilyPlan], groups: list[lj.TestCase], results: dict,
             build_root: Path, objs: dict) -> list[dict]:
    by_fam_lang: dict[tuple[str, str], list[lj.TestCase]] = collections.defaultdict(list)
    for g in groups:
        if not g.problems:
            by_fam_lang[(g.family, g.language)].append(g)
    for v in by_fam_lang.values():
        v.sort(key=lambda g: (int(g.variant), g.variant))
    used = {g.group_id for p in plans.values() for g in p.groups}
    replacements = []

    def ok(gid: str) -> bool:
        return all(results.get((gid, lab), {}).get("label_ok") for lab in ("bad", "good"))

    for fam, plan in sorted(plans.items()):
        for attr, lang in (("c_groups", "c"), ("cpp_groups", "cpp")):
            slots = getattr(plan, attr)
            for idx, old in enumerate(list(slots)):
                if ok(old.group_id):
                    continue
                candidates = by_fam_lang[(fam, lang)]
                old_i = next((i for i, g in enumerate(candidates) if g.group_id == old.group_id), -1)
                ordered = candidates[old_i + 1:] + candidates[:old_i + 1]
                chosen = None
                for cand in ordered:
                    if cand.group_id in used:
                        continue
                    print(f"  backfill {fam}/{lang}: {old.group_id} -> {cand.group_id}", flush=True)
                    if (cand.group_id, "bad") not in results:
                        results.update(evaluate_one(cand, build_root, objs))
                    if ok(cand.group_id):
                        chosen = cand
                        used.add(cand.group_id)
                        replacements.append({
                            "family": fam, "language": lang,
                            "replaced": old.group_id, "replacement": cand.group_id,
                        })
                        break
                if chosen is None:
                    raise SystemExit(f"no valid backfill for {old.group_id}")
                slots[idx] = chosen
                used.discard(old.group_id)
    return replacements


def near_duplicate_audit(selected: list[tuple[str, lj.TestCase]], threshold: float) -> dict:
    items = [(split, tc, lj.shingles(lj.normalize_code(lj.iter_group_code(tc)))) for split, tc in selected]
    cross, within = [], []
    for i in range(len(items)):
        s1, g1, sh1 = items[i]
        for j in range(i + 1, len(items)):
            s2, g2, sh2 = items[j]
            jac = lj.jaccard(sh1, sh2)
            rec = {
                "jaccard": round(jac, 4),
                "a": g1.group_id, "b": g2.group_id,
                "family_a": g1.family, "family_b": g2.family,
            }
            (cross if s1 != s2 else within).append(rec)
    cross.sort(key=lambda r: -r["jaccard"])
    within.sort(key=lambda r: -r["jaccard"])
    return {
        "threshold": threshold,
        "metric": "Jaccard over 5-token shingles of comment/preprocessor-stripped code; "
                  "identifiers masked to <id>, numeric/string literals masked",
        "cross_split_pair_count": len(cross),
        "cross_split_max": cross[0]["jaccard"] if cross else None,
        "cross_split_ge_threshold": sum(r["jaccard"] >= threshold for r in cross),
        "cross_split_ge_0_8": sum(r["jaccard"] >= 0.8 for r in cross),
        "within_split_max": within[0]["jaccard"] if within else None,
        "top_cross_split": cross[:10],
    }


def portable(path: str | Path) -> str:
    s = str(path).replace("\\", "/")
    root = str(lj.ROOT).replace("\\", "/")
    if s.startswith(root + "/"):
        return s[len(root) + 1:]
    return s


def make_unit(tc: lj.TestCase, label: str, split: str, res: dict) -> dict:
    guard = guard_evidence(tc)
    sources = []
    for rel_path in res["sources"]:
        p = lj.ROOT / rel_path
        sources.append({"path": rel_path, "sha256": sha256_file(p), "bytes": p.stat().st_size})
    headers = [
        {"path": lj.rel(p), "sha256": sha256_file(p), "bytes": p.stat().st_size}
        for p in tc.headers
    ]
    main_set = {lj.rel(p) for p, _ in tc.main_defs}
    main_source = next((s for s in res["sources"] if s in main_set), res["sources"][0])
    unit_rel = res["executable"]
    if unit_rel:
        unit_rel = portable(unit_rel)
    return {
        "unit_id": f"{tc.group_id}__{label}",
        "group_id": tc.group_id,
        "family": tc.family,
        "variant": tc.variant,
        "language": tc.language,
        "split": split,
        "label": label,
        "label_semantics": "memory_leak_present" if label == "bad" else "memory_leak_absent",
        "sources": sources,
        "headers": headers,
        "main_source": main_source,
        "defines": res["defines"],
        "include_dirs": ["juliet/raw/testcasesupport"],
        "support_sources": [
            {"path": "juliet/raw/testcasesupport/io.c", "sha256": sha256_file(lj.SUPPORT / "io.c")},
            {"path": "juliet/raw/testcasesupport/std_thread.c", "sha256": sha256_file(lj.SUPPORT / "std_thread.c")},
        ],
        "guard_evidence": guard,
        "compile": {
            "compiler": res["compiler"],
            "ok": res["compile_ok"],
            "returncode": res["compile_returncode"],
            "cwd": "juliet",
            "command": [portable(x) for x in res["command"]],
            "executable": unit_rel,
        },
        "symbol_check": {
            "ok": res["symbol_ok"],
            "bad_symbols": res["symbols"].get("bad_symbols", []),
            "good_symbols": res["symbols"].get("good_symbols", []),
        },
        "runtime_check": {
            "tool": "AddressSanitizer + LeakSanitizer",
            "leak_detected": res["run"]["leak_detected"],
            "other_asan_error": res["run"]["other_asan_error"],
            "timed_out": res["run"]["timed_out"],
            "returncode": res["run"]["returncode"],
            "summary": res["run"]["summary"],
        },
        "verification": {
            "macro_gate_ok": True,
            "compiled_ok": bool(res["compile_ok"]),
            "symbol_gate_ok": bool(res["symbol_ok"]),
            "runtime_label_ok": bool(res["runtime_supports_label"]),
        },
    }


def write_sha256sums() -> Path:
    out = lj.ROOT / "SHA256SUMS"
    roots = [lj.ROOT / "raw", lj.ROOT / "scripts"]
    extras = [lj.ROOT / "manifest.json", lj.ROOT / "subset_units.jsonl", lj.ROOT / "README.md",
              lj.ROOT / "provenance.json", lj.ROOT / "verification.json"]
    files = []
    for r in roots:
        files.extend(
            p for p in r.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        )
    files.extend(p for p in extras if p.exists())
    files = sorted(set(files), key=lambda p: p.relative_to(lj.ROOT).as_posix())
    lines = [f"{sha256_file(p)}  {p.relative_to(lj.ROOT).as_posix()}" for p in files]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--reuse", action="store_true", help="reuse build/results when present")
    args = ap.parse_args()

    started = time.time()
    print("== provenance")
    prov = verify_provenance()
    print(f"  archive sha256 verified: {EXPECTED_ARCHIVE_SHA256}")
    print(f"  raw files verified: {prov['files_verified']}")

    print("== discovery and structural label checks")
    groups = lj.discover_groups()
    by_id = {g.group_id: g for g in groups}
    print(f"  groups={len(groups)} families={len({g.family for g in groups})} "
          f"structural_problems={sum(bool(g.problems) for g in groups)}")

    plans = sl.plan_families(groups)
    selected = [g for p in plans.values() for g in p.groups]
    print(f"  selected groups={len(selected)} units={2*len(selected)}")

    build_root = lj.ROOT / "build"
    objs = bl.support_objects(build_root)
    tasks = [(g, label) for g in selected for label in ("bad", "good")]
    print(f"== building {len(tasks)} units with ASan (jobs={args.jobs})")
    if args.reuse:
        results = {}
        for g, label in tasks:
            p = build_root / "results" / f"{g.group_id}__{label}.json"
            if p.exists():
                d = json.loads(p.read_text(encoding="utf-8"))
                leak = d["run"]["leak_detected"]
                d["runtime_supports_label"] = bool(leak) if label == "bad" else not bool(leak)
                d["label_ok"] = bool(
                    d["compile_ok"] and d["symbol_ok"]
                    and not d["run"]["other_asan_error"] and not d["run"]["timed_out"]
                    and (label == "bad" or not leak)
                )
                d["ok"] = d["label_ok"]
                results[(g.group_id, label)] = d
        tasks = [t for t in tasks if (t[0].group_id, t[1]) not in results]
        print(f"  reused={len(results)} remaining={len(tasks)}")
    else:
        results = {}
    results.update(build_tasks(tasks, build_root, objs, args.jobs))
    failed = [gid for gid in {g.group_id for g in selected}
              if not all(results.get((gid, lab), {}).get("label_ok") for lab in ("bad", "good"))]
    print(f"  initial failures: {len(failed)} {failed[:5]}")
    replacements = backfill(plans, groups, results, build_root, objs) if failed else []

    print("== near-duplicate cluster partition")
    clusters_doc = sc.build_clusters(by_id, plans)
    assign = sc.assign(plans, clusters_doc)
    print(f"  clusters={len(clusters_doc['clusters'])} dev={assign['dev_units']} units "
          f"families={assign['dev_families']} mechanisms={assign['dev_mechanisms']}")

    selected = [(p.split, g) for p in plans.values() for g in p.groups]
    audit = near_duplicate_audit(selected, sc.THRESHOLD)
    if audit["cross_split_ge_threshold"]:
        raise SystemExit(f"near-duplicate leakage: {audit['cross_split_ge_threshold']} pairs")
    print(f"  cross-split max jaccard={audit['cross_split_max']} (threshold {sc.THRESHOLD})")

    print("== manifest")
    units = []
    for split, tc in selected:
        for label in ("bad", "good"):
            res = results[(tc.group_id, label)]
            if not res["label_ok"]:
                raise SystemExit(f"selected unit not verified: {tc.group_id} {label}")
            units.append(make_unit(tc, label, split, res))
    units.sort(key=lambda u: (u["split"], u["family"], u["variant"], u["label"]))

    split_stats = {}
    for split in ("dev", "test"):
        us = [u for u in units if u["split"] == split]
        split_stats[split] = {
            "units": len(us),
            "bad_units": sum(u["label"] == "bad" for u in us),
            "good_units": sum(u["label"] == "good" for u in us),
            "groups": len({u["group_id"] for u in us}),
            "families": len({u["family"] for u in us}),
            "c_units": sum(u["language"] == "c" for u in us),
            "cpp_units": sum(u["language"] == "cpp" for u in us),
            "family_names": sorted({u["family"] for u in us}),
            "clusters": sorted({c["cluster_id"] for c in clusters_doc["clusters"] if c["split"] == split}),
        }
    file_hashes = {}
    for u in units:
        for f in u["sources"] + u["headers"]:
            file_hashes[f["path"]] = f["sha256"]
    for s in ("io.c", "std_thread.c"):
        p = lj.SUPPORT / s
        file_hashes[lj.rel(p)] = sha256_file(p)

    manifest = {
        "schema_version": "juliet-cwe401-subset/1.0",
        "dataset_id": DATASET_ID,
        "created_at_utc": utc_now(),
        "generator": {
            "python": sys.version.split()[0],
            "gcc": run_version(["gcc", "--version"]),
            "g++": run_version(["g++", "--version"]),
            "platform": run_version(["uname", "-srmo"]),
        },
        "source": {
            "dataset": "Juliet Test Suite for C/C++ v1.3",
            "cwe": 401,
            "cwe_name": "Improper Release of Memory Before Removing Last Reference ('Memory Leak')",
            "archive_url": prov["archive"]["url"],
            "archive_sha256": prov["archive"]["sha256"],
            "archive_bytes": prov["archive"]["bytes"],
            "archive_last_modified": prov["archive"].get("last_modified"),
            "archive_etag": prov["archive"].get("etag"),
            "downloaded_at_utc": prov["archive"].get("downloaded_at_utc") or dt.datetime.fromtimestamp(
                (lj.ROOT / "cache" / "juliet-c-cplusplus-v1.3.zip").stat().st_mtime,
                dt.timezone.utc,
            ).isoformat(),
            "archive_file_mtime_utc": dt.datetime.fromtimestamp(
                (lj.ROOT / "cache" / "juliet-c-cplusplus-v1.3.zip").stat().st_mtime,
                dt.timezone.utc,
            ).isoformat(),
            "extracted_at_utc": prov["extraction"]["extracted_at_utc"],
            "archive_member_prefix": prov["extraction"]["member_prefix"],
            "version_evidence": {
                "changelog": "juliet/raw/doc/changelog_Juliet_C_Cpp.txt",
                "changelog_sha256": sha256_file(lj.ROOT / "raw" / "doc" / "changelog_Juliet_C_Cpp.txt"),
                "changelog_line": "Sep 2017 - v1.3",
            },
            "provenance_file": "juliet/provenance.json",
            "provenance_sha256": prov["provenance_sha256"],
            "raw_files_verified": prov["files_verified"],
        },
        "selection": {
            "seed": sl.SEED,
            "target_groups": 100,
            "target_units": 200,
            "family_definition": "filename token between '__' and the numeric flow variant",
            "family_count": len({g.family for g in groups}),
            "candidate_groups": len(groups),
            "structural_rejections": sum(bool(g.problems) for g in groups),
            "selection_rule": "all 42 families; 1-3 test cases per family; one C and one C++ case "
                              "for dual-language families; additional C/C++ flow variants selected "
                              "deterministically to cover baseline, global-flow, recursion and "
                              "two-function templates",
            "variant_distribution": dict(sorted(collections.Counter(
                u["variant"] for u in units if u["label"] == "bad").items())),
            "translation_unit_inclusions": sum(len(u["sources"]) for u in units),
            "replacements": replacements,
            "near_duplicate_clusters": clusters_doc["clusters"],
            "split_rule": "connected components of families at Jaccard >= 0.85 on masked 5-gram "
                          "shingles; every component assigned wholly to dev or test",
            "dev_target_units": sl.TARGET_DEV_UNITS,
        },
        "near_duplicate_audit": audit,
        "splits": split_stats,
        "verification": {
            "units_verified": len(units),
            "units_macro_ok": sum(u["verification"]["macro_gate_ok"] for u in units),
            "units_compiled": sum(u["verification"]["compiled_ok"] for u in units),
            "units_symbol_gate_ok": sum(u["verification"]["symbol_gate_ok"] for u in units),
            "units_runtime_supports_label": sum(
                u["verification"]["runtime_label_ok"] for u in units),
            "bad_units_with_observed_leak": sum(
                u["label"] == "bad" and u["runtime_check"]["leak_detected"] for u in units),
            "bad_units_without_observed_leak": sum(
                u["label"] == "bad" and not u["runtime_check"]["leak_detected"] for u in units),
            "good_units_without_leak": sum(
                u["label"] == "good" and not u["runtime_check"]["leak_detected"] for u in units),
            "runtime_contradictions": sum(
                u["label"] == "good" and u["runtime_check"]["leak_detected"] for u in units),
        },
        "per_file_sha256": dict(sorted(file_hashes.items())),
        "units": units,
    }
    (lj.ROOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (lj.ROOT / "subset_units.jsonl").open("w", encoding="utf-8") as fh:
        for u in units:
            fh.write(json.dumps({
                "unit_id": u["unit_id"],
                "group_id": u["group_id"],
                "family": u["family"],
                "variant": u["variant"],
                "language": u["language"],
                "split": u["split"],
                "label": u["label"],
                "sources": [s["path"] for s in u["sources"]],
                "defines": u["defines"],
            }, sort_keys=True) + "\n")
    print(f"  wrote manifest.json ({len(units)} units) and subset_units.jsonl")

    if not (lj.ROOT / "README.md").exists():
        print("  note: README.md not present yet; SHA256SUMS will include it after it is written")

    sha_path = write_sha256sums()
    freeze = {
        "dataset_id": DATASET_ID,
        "created_at_utc": utc_now(),
        "manifest_sha256": sha256_file(lj.ROOT / "manifest.json"),
        "subset_units_sha256": sha256_file(lj.ROOT / "subset_units.jsonl"),
        "sha256sums_sha256": sha256_file(sha_path),
        "elapsed_seconds": round(time.time() - started, 1),
    }
    (lj.ROOT / "FREEZE.json").write_text(
        json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"  wrote SHA256SUMS ({sum(1 for _ in sha_path.open())} lines) and FREEZE.json")
    print(f"done in {time.time()-started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

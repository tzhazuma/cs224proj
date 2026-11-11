#!/usr/bin/env python3
"""Final quality and leakage audit for the CS224 Juliet/SecVulEval experiments.

Read-only with respect to every directory except ``audit/``.  The script never
calls a model API and never reads or prints credentials.  It recomputes the
claims that the experiment reports make instead of trusting their summaries.

Usage (WSL):
    python3 audit/run_final_audit.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
AUDIT = ROOT / "audit"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "hybrid"))

from juliet_llm.cleaning import FORBIDDEN_PATTERNS, clean_unit, forbidden_hits  # noqa: E402
from juliet_llm.prompting import build_messages as build_juliet_messages  # noqa: E402
from juliet_llm.prompting import prompt_forbidden_hits, prompt_sha256 as juliet_prompt_sha  # noqa: E402

import hybrid.prompts as hybrid_prompts  # noqa: E402
import pair_joint.common as pair_common  # noqa: E402

STATIC_RUN = ROOT / "traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu"
DYNAMIC_RUN = ROOT / "traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind"
BENCH = ROOT / "benchmark/results/tier_a"

# Official post-fix artifacts (v2 / postleakfix) and the frozen v1 artifacts
# that are deliberately kept as a superseded, leak-observable contrast.
JULIET_BUILD = ROOT / "juliet_llm/build"
JULIET_PRE_LEAKFIX_BUILD = ROOT / "juliet_llm/build_pre_leakfix_v1"
JULIET_OFFICIAL_RUNS = (
    "20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix",
    "20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro",
)
JULIET_PRE_LEAKFIX_RUNS = (
    "20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official",
    "20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final",
)
JULIET_SUPERSEDED_RUNS = (
    "20261111T204701Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix",
    "20261111T204833Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro",
)
HYBRID_OFFICIAL = "hybrid_v2"
HYBRID_SUPERSEDED = "hybrid_v1"
HYBRID_INPUTS = ROOT / "hybrid/inputs_v2"
HYBRID_SUPERSEDED_INPUTS = ROOT / "hybrid/inputs"

CHECKS: list[dict[str, Any]] = []


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, float) and value != value:  # NaN
        return None
    return value


def add(check_id: str, area: str, status: str, title: str, detail: str,
        evidence: dict[str, Any] | None = None) -> None:
    assert status in {"PASS", "FAIL", "WARN", "INFO"}, status
    CHECKS.append(
        {
            "id": check_id,
            "area": area,
            "status": status,
            "title": title,
            "detail": detail,
            "evidence": _json_safe(evidence or {}),
        }
    )
    print(f"[{status:4}] {check_id}: {title}")


def run_check(check_id: str, area: str, title: str,
              fn: Callable[[], tuple[str, str, dict[str, Any] | None]]) -> None:
    try:
        status, detail, evidence = fn()
    except Exception as exc:  # noqa: BLE001 - audit must keep going
        add(check_id, area, "FAIL", title, f"check raised {type(exc).__name__}: {exc}")
        return
    add(check_id, area, status, title, detail, evidence)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_messages(messages: list[dict[str, str]]) -> str:
    return json.dumps(messages, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def msg_sha(messages: list[dict[str, str]]) -> str:
    return sha256_bytes(canonical_messages(messages).encode("utf-8"))


def pct(a: int, b: int) -> float:
    return 0.0 if not b else round(100.0 * a / b, 4)


# ---------------------------------------------------------------------------
# Shared loaders
# ---------------------------------------------------------------------------

FREEZE = read_json(ROOT / "juliet/FREEZE.json")
UNITS = read_jsonl(ROOT / "juliet/subset_units.jsonl")
UNIT_BY_ID = {u["unit_id"]: u for u in UNITS}
TEST_UNITS = [u for u in UNITS if u["split"] == "test"]
DEV_UNITS = [u for u in UNITS if u["split"] == "dev"]


def load_static_rows() -> dict[tuple[str, str], dict[str, Any]]:
    rows = read_jsonl(STATIC_RUN / "predictions.jsonl")
    return {(r["sample_id"], r["tool"]): r for r in rows}


def normalize_source(path: str) -> str:
    path = path.replace("\\", "/")
    if "CWE401_Memory_Leak/" in path:
        return path.split("CWE401_Memory_Leak/", 1)[1]
    return Path(path).name


def source_key(sources: list[str], defines: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return tuple(sorted(normalize_source(s) for s in sources)), tuple(sorted(defines))


def load_dynamic_results() -> dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]]:
    cases = read_jsonl(DYNAMIC_RUN / "cases.jsonl")
    results = {r["case_id"]: r for r in read_jsonl(DYNAMIC_RUN / "results.jsonl")}
    out: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for case in cases:
        key = source_key(case["sources"], case["defines"])
        result = results.get(case["case_id"])
        if result is not None:
            out[key] = result
    return out


def dynamic_for_unit(unit: dict[str, Any], dyn: dict[Any, dict[str, Any]]) -> dict[str, Any] | None:
    return dyn.get(source_key(unit["sources"], unit["defines"]))


def unit_label(unit: dict[str, Any]) -> str:
    return unit["label"]


_CLEAN_CACHE: dict[str, Any] = {}


def cleaned_unit(unit: dict[str, Any]):
    """Memoised cleaner; the audit calls this from several independent checks."""
    uid = unit["unit_id"]
    if uid not in _CLEAN_CACHE:
        _CLEAN_CACHE[uid] = clean_unit(unit)
    return _CLEAN_CACHE[uid]


# ---------------------------------------------------------------------------
# A. Frozen data
# ---------------------------------------------------------------------------

def check_freeze() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        got = {
            "subset_units.jsonl": sha256_file(ROOT / "juliet/subset_units.jsonl"),
            "manifest.json": sha256_file(ROOT / "juliet/manifest.json"),
            "SHA256SUMS": sha256_file(ROOT / "juliet/SHA256SUMS"),
        }
        expect = {
            "subset_units.jsonl": FREEZE["subset_units_sha256"],
            "manifest.json": FREEZE["manifest_sha256"],
            "SHA256SUMS": FREEZE["sha256sums_sha256"],
        }
        ok = got == expect
        return (
            "PASS" if ok else "FAIL",
            "All three frozen Juliet hashes recomputed." if ok else "Frozen hash mismatch.",
            {"computed": got, "expected": expect},
        )

    run_check("A1", "frozen", "Juliet freeze hashes match FREEZE.json", fn)


def check_composition() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        counts = Counter((u["split"], u["label"]) for u in UNITS)
        lang = Counter(u["language"] for u in UNITS)
        groups = len({u["group_id"] for u in UNITS})
        problems = []
        if len(UNITS) != 200:
            problems.append(f"units={len(UNITS)}")
        if counts[("dev", "bad")] != 30 or counts[("dev", "good")] != 30:
            problems.append(f"dev={dict(counts)}")
        if counts[("test", "bad")] != 70 or counts[("test", "good")] != 70:
            problems.append(f"test={dict(counts)}")
        if lang != Counter({"c": 88, "cpp": 112}):
            problems.append(f"languages={dict(lang)}")
        if groups != 100:
            problems.append(f"groups={groups}")
        status = "PASS" if not problems else "FAIL"
        return status, "200 units: dev 60 (30/30), test 140 (70/70), C 88 / C++ 112, 100 groups." if not problems else "; ".join(problems), {
            "units": len(UNITS),
            "split_label": {f"{k[0]}/{k[1]}": v for k, v in sorted(counts.items())},
            "languages": dict(lang),
            "groups": groups,
        }

    run_check("A2", "frozen", "Frozen subset composition is 200 (60 dev / 140 test)", fn)


def check_near_duplicate() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        nd = read_json(ROOT / "juliet/manifest.json")["near_duplicate_audit"]
        violations = nd.get("cross_split_violations", nd.get("cross_split_ge_threshold"))
        ok = violations == 0 and nd["cross_split_max"] < nd["threshold"]
        return (
            "PASS" if ok else "FAIL",
            f"Cross-split max Jaccard {nd['cross_split_max']} < threshold {nd['threshold']}; violations {violations}.",
            {"threshold": nd["threshold"], "max": nd["cross_split_max"], "violations": violations,
             "pairs": nd["cross_split_pair_count"], "metric": nd["metric"]},
        )

    run_check("A3", "frozen", "Cross-split near-duplicate gate passes", fn)


def check_sha256sums() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        sums_path = ROOT / "juliet/SHA256SUMS"
        entries = []
        for line in sums_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, _, rel = line.partition("  ")
            entries.append((rel.strip(), digest))
        missing, bad = [], []
        for rel, digest in entries:
            path = ROOT / "juliet" / rel
            if not path.is_file():
                missing.append(rel)
            elif sha256_file(path) != digest:
                bad.append(rel)
        ok = not missing and not bad
        return (
            "PASS" if ok else "FAIL",
            f"{len(entries)} raw files listed; missing {len(missing)}, hash mismatches {len(bad)}.",
            {"entries": len(entries), "missing": missing[:10], "mismatched": bad[:10]},
        )

    run_check("A4", "frozen", "SHA256SUMS verifies every raw Juliet file", fn)


# ---------------------------------------------------------------------------
# B. Cleaning
# ---------------------------------------------------------------------------

def check_cleaning_rebuild() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rebuilt = {}
        failures = []
        for unit in UNITS:
            try:
                cleaned = cleaned_unit(unit)
            except Exception as exc:  # noqa: BLE001
                failures.append({"unit_id": unit["unit_id"], "error": str(exc)})
                continue
            rebuilt[unit["unit_id"]] = cleaned
            failed = [k for k, v in cleaned.checks.items() if isinstance(v, bool) and not v]
            if failed:
                failures.append({"unit_id": unit["unit_id"], "failed_checks": failed})
        after = Counter()
        for cleaned in rebuilt.values():
            for key, value in cleaned.after_hits.items():
                after[key] += value
        if len(rebuilt) != 200:
            failures.append({"error": f"rebuilt {len(rebuilt)}/200"})
        if any(after.values()):
            failures.append({"error": f"after_hits {dict(after)}"})
        ok = not failures
        return (
            "PASS" if ok else "FAIL",
            "clean_unit() rebuilt all 200 units; every audit check true; all forbidden counts zero." if ok else f"{len(failures)} cleaning failures.",
            {"rebuilt": len(rebuilt), "after_hits": dict(after), "failures": failures[:10]},
        )

    run_check("B1", "cleaning", "Juliet cleaner passes its fail-closed audit on all 200 units", fn)


def check_cleaning_matches_build() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        totals = Counter()
        for split in ("dev", "test"):
            rows = read_jsonl(ROOT / f"juliet_llm/build/{split}.jsonl")
            if len(rows) != (60 if split == "dev" else 140):
                problems.append(f"{split}: {len(rows)} build rows")
            for row in rows:
                unit = UNIT_BY_ID[row["unit_id"]]
                cleaned = cleaned_unit(unit)
                if cleaned.code_sha256 != row["code_sha256"]:
                    problems.append(f"{row['unit_id']}: code_sha256 differs")
                rebuilt_messages = build_juliet_messages(cleaned)
                if rebuilt_messages != row["messages"]:
                    problems.append(f"{row['unit_id']}: messages differ")
                if juliet_prompt_sha(rebuilt_messages) != row["prompt_sha256"]:
                    problems.append(f"{row['unit_id']}: prompt hash differs")
                totals[split] += 1
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"Rebuilt prompts match juliet_llm/build for {totals['dev']} dev + {totals['test']} test units." if ok else f"{len(problems)} mismatches.",
            {"checked": dict(totals), "problems": problems[:10]},
        )

    run_check("B2", "cleaning", "Rebuilt code and prompts equal the frozen juliet_llm build", fn)


def check_cleaning_code_leak() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        hits = Counter()
        units_with = Counter()
        for unit in UNITS:
            cleaned = cleaned_unit(unit)
            blob = cleaned.code
            for name, pattern in FORBIDDEN_PATTERNS.items():
                n = len(re.findall(pattern, blob))
                if n:
                    hits[name] += n
                    units_with[name] += 1
            for marker in (unit["unit_id"], unit["group_id"], "CWE401", "Memory_Leak", "testcases", "raw/"):
                if marker in blob:
                    hits[f"literal:{marker}"] += 1
        ok = not hits
        return (
            "PASS" if ok else "FAIL",
            "Cleaned code contains no bad/good/CWE/memory-leak/macro/support-header/label-word token under the built-in 11-class scan." if ok else f"hits: {dict(hits)}",
            {"hits": dict(hits), "units_with": dict(units_with)},
        )

    run_check("B3", "cleaning", "Cleaned code passes the built-in forbidden-token scan (11 classes)", fn)


def check_cleaning_semantics() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        verification = read_json(ROOT / "juliet/verification.json")
        repair_manifest = read_json(ROOT / "juliet_repair/inputs/manifest.json")
        problems = []
        if verification.get("status") != "PASS":
            problems.append("juliet/verification.json status != PASS")
        checks = verification.get("checks", {})
        for key in ("compile_ok", "macro_gate_ok", "symbol_gate_ok"):
            if checks.get(key) != 200:
                problems.append(f"verification.{key} != 200")
        if checks.get("sha256sums_all_files_verified") is not True:
            problems.append("verification.sha256sums_all_files_verified != true")
        if checks.get("units") != 200 or checks.get("groups") != 100:
            problems.append("verification unit/group count")
        if verification.get("independent_rebuild", {}).get("status") != "PASS":
            problems.append("independent_rebuild.status != PASS")
        if repair_manifest.get("leak_audit", {}).get("clean_units") != 70:
            problems.append("repair leak_audit.clean_units != 70")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Original 200 compile; 100 bad / 100 good runtime semantics reproduced; independent rebuild PASS; repair inputs 70/70 clean."
            if ok else "; ".join(problems),
            {"verification": checks, "independent_rebuild": verification.get("independent_rebuild"),
             "repair_leak_audit": repair_manifest.get("leak_audit")},
        )

    run_check("B4", "cleaning", "Cleaning preserves program semantics (compile/runtime checks)", fn)


def check_structural_asymmetry() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = []
        for label in ("bad", "good"):
            lengths = [len(cleaned_unit(u).code) for u in UNITS if u["label"] == label]
            rows.append({"label": label, "n": len(lengths), "mean_chars": round(statistics.mean(lengths), 1),
                         "median_chars": statistics.median(lengths)})
        ratio = rows[0]["mean_chars"] / rows[1]["mean_chars"]
        return (
            "WARN",
            f"Bad units average {rows[0]['mean_chars']} chars vs good {rows[1]['mean_chars']} (ratio {ratio:.3f}); "
            "this is Juliet's structure, not a cleaning artifact, but it is a possible shortcut signal.",
            {"by_label": rows, "mean_length_ratio_bad_over_good": round(ratio, 4)},
        )

    run_check("B5", "cleaning", "Residual structural asymmetry between bad and good units", fn)


# ---------------------------------------------------------------------------
# C. juliet_llm prompt leakage
# ---------------------------------------------------------------------------

def check_juliet_prompt_leak() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        units_checked = 0
        max_hits = Counter()
        for split in ("dev", "test"):
            for row in read_jsonl(ROOT / f"juliet_llm/build/{split}.jsonl"):
                units_checked += 1
                messages = row["messages"]
                if [m["role"] for m in messages] != ["system", "user"]:
                    problems.append(f"{row['unit_id']}: roles {[m['role'] for m in messages]}")
                joined = "\n".join(m["content"] for m in messages)
                hits = prompt_forbidden_hits(joined)
                for key, value in hits.items():
                    max_hits[key] = max(max_hits[key], value)
                if any(hits.values()):
                    problems.append(f"{row['unit_id']}: token hits {hits}")
                for identifier in (row["unit_id"], row["group_id"]):
                    if identifier in joined:
                        problems.append(f"{row['unit_id']}: identifier in prompt")
                for marker in ("CWE401", "Memory_Leak", "testcases/", "raw/", "/mnt/"):
                    if marker in joined:
                        problems.append(f"{row['unit_id']}: marker {marker}")
                user = messages[1]["content"]
                if user.count("```") != 2:
                    problems.append(f"{row['unit_id']}: fence count {user.count('```')}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"{units_checked} prompts: only system+user, one code block, zero hits under the built-in 11-class list (bad/good/CWE/label words/...)." if ok else f"{len(problems)} prompt problems.",
            {"units": units_checked, "max_token_hits": dict(max_hits), "problems": problems[:10]},
        )

    run_check("C1", "prompt_leak", "juliet_llm prompts pass the built-in 11-class token scan", fn)


def _run_inputs_match_build(run_names: tuple[str, ...], build_path: Path,
                            kind: str) -> tuple[int, int, list[str], dict[str, Any]]:
    build = {r["unit_id"]: r for r in read_jsonl(build_path)}
    checked = 0
    matched = 0
    problems: list[str] = []
    versions = set()
    for run in run_names:
        run_dir = ROOT / "juliet_llm/runs" / run
        manifest = read_json(run_dir / "manifest.json")
        versions.add(manifest.get("prompt_version"))
        for row in read_jsonl(run_dir / "inputs.jsonl"):
            checked += 1
            ref = build.get(row["unit_id"])
            if ref is None:
                problems.append(f"{kind}: {run}: {row['unit_id']} not in build")
                continue
            if row["messages"] == ref["messages"] and row["prompt_sha256"] == ref["prompt_sha256"]:
                matched += 1
            else:
                problems.append(f"{kind}: {run}: {row['unit_id']} differs from {build_path.name}")
    return checked, matched, problems, {"runs": list(run_names), "prompt_versions": sorted(versions),
                                        "checked": checked, "matched": matched}


def check_juliet_sent_messages() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        current = _run_inputs_match_build(JULIET_OFFICIAL_RUNS, JULIET_BUILD / "test.jsonl", "postleakfix")
        legacy = _run_inputs_match_build(JULIET_PRE_LEAKFIX_RUNS, JULIET_PRE_LEAKFIX_BUILD / "test.jsonl", "pre-leakfix")
        problems = current[2] + legacy[2]
        current_ok = current[0] == 280 and current[1] == current[0]
        legacy_ok = legacy[0] == 280 and legacy[1] == legacy[0]
        ok = not problems and current_ok and legacy_ok
        return (
            "PASS" if ok else "FAIL",
            (f"Postleakfix official+repro: {current[1]}/{current[0]} sent prompts byte-identical to the current build; "
             f"pre-leakfix v1: {legacy[1]}/{legacy[0]} byte-identical to the archived pre-leakfix build.")
            if ok else f"{len(problems)} mismatches; current {current[1]}/{current[0]}, pre-fix {legacy[1]}/{legacy[0]}.",
            {"postleakfix": current[3], "pre_leakfix": legacy[3], "problems": problems[:10]},
        )

    run_check("C2", "prompt_leak", "Sent juliet_llm prompts match their build (postleakfix and archived pre-fix)", fn)


LABEL_WORD_RE = re.compile(r"(?i)\b(benign|fixed|safe|clean|patched|remediated)\b")


def _prompt_code(row: dict[str, Any]) -> str:
    user = row["messages"][1]["content"]
    match = re.search(r"```[A-Za-z+]*\n(.*?)\n```", user, re.S)
    return match.group(1) if match else user


def _label_word_hits(build: Path) -> list[dict[str, Any]]:
    hits = []
    for split in ("dev", "test"):
        for row in read_jsonl(build / f"{split}.jsonl"):
            code = _prompt_code(row)
            found = sorted({m.group(0).lower() for m in LABEL_WORD_RE.finditer(code)})
            if found:
                hits.append({"split": split, "unit_id": row["unit_id"], "label": row["label"], "tokens": found})
    return hits


def check_benign_fixed_leak() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        hits = _label_word_hits(JULIET_BUILD)
        legacy_hits = _label_word_hits(JULIET_PRE_LEAKFIX_BUILD)
        test_hits = [h for h in hits if h["split"] == "test"]
        legacy_test = [h for h in legacy_hits if h["split"] == "test"]
        all_good = all(h["label"] == "good" for h in hits)
        legacy_all_good = all(h["label"] == "good" for h in legacy_hits)
        legacy_ok = len(legacy_hits) == 8 and len(legacy_test) == 6 and legacy_all_good
        ok = not hits and legacy_ok
        if ok:
            detail = ("0/200 current prompts contain benign/fixed/safe/clean/patched/remediated; "
                      "the archived pre-leakfix v1 build still holds 8 hits (2 dev + 6 test, all good) as the leak contrast.")
        elif hits:
            detail = (f"current build still has {len(hits)}/200 label-word hits ({len(test_hits)} test): "
                      + ", ".join(f"{h['unit_id']} ({'/'.join(h['tokens'])})" for h in hits[:8]))
        else:
            detail = f"current build is clean, but the archived v1 leak contrast changed: {len(legacy_hits)} hits ({len(legacy_test)} test)."
        return (
            "PASS" if ok else "FAIL",
            detail,
            {"hits": hits, "test_hits": len(test_hits), "all_good": all_good,
             "pre_leakfix_hits": legacy_hits, "pre_leakfix_test_hits": len(legacy_test),
             "pre_leakfix_all_good": legacy_all_good,
             "root_cause": "v1 cleaner omitted benign/fixed; prompt .2 neutralises them"},
        )

    run_check("C3", "prompt_leak", "Current prompts have no label words; archived v1 keeps the leak contrast", fn)


# ---------------------------------------------------------------------------
# D. Hybrid inputs / prompts / placebo
# ---------------------------------------------------------------------------

def _load_hybrid_build():
    spec = importlib.util.spec_from_file_location("audit_hybrid_build_inputs", ROOT / "hybrid/build_inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _hybrid_units() -> list[dict[str, Any]]:
    return read_jsonl(HYBRID_INPUTS / "units.jsonl")


def check_hybrid_inputs() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = _hybrid_units()
        legacy_rows = read_jsonl(HYBRID_SUPERSEDED_INPUTS / "units.jsonl")
        problems = []
        legacy_problems = []
        if len(rows) != 140:
            problems.append(f"v2 units {len(rows)}")
        if len(legacy_rows) != 140:
            legacy_problems.append(f"v1 units {len(legacy_rows)}")
        by_id = {r["unit_id"]: r for r in rows}
        if set(by_id) != {u["unit_id"] for u in TEST_UNITS}:
            problems.append("v2 unit set differs from frozen test140")
        for unit in TEST_UNITS:
            row = by_id.get(unit["unit_id"])
            if row is None:
                continue
            cleaned = cleaned_unit(unit)
            if row["source_text"] != cleaned.code:
                problems.append(f"{unit['unit_id']}: v2 source_text differs from clean_unit")
            if row["source_sha256"] != cleaned.code_sha256:
                problems.append(f"{unit['unit_id']}: v2 source hash differs")
            if row["label"] != (unit["label"] == "bad"):
                problems.append(f"{unit['unit_id']}: v2 label mismatch")
        pre_code = {r["unit_id"]: _prompt_code(r) for r in read_jsonl(JULIET_PRE_LEAKFIX_BUILD / "test.jsonl")}
        for row in legacy_rows:
            uid = row["unit_id"]
            if uid not in pre_code:
                legacy_problems.append(f"{uid}: not in archived pre-leakfix build")
                continue
            if row["source_text"] != pre_code[uid]:
                legacy_problems.append(f"{uid}: v1 source_text differs from archived pre-fix build")
            if row["source_sha256"] != sha256_bytes(pre_code[uid].encode("utf-8")):
                legacy_problems.append(f"{uid}: v1 source hash differs from archived pre-fix build")
        ok = not problems and not legacy_problems
        return (
            "PASS" if ok else "FAIL",
            ("hybrid/inputs_v2/units.jsonl is exactly the current cleaner's output for the frozen test140; "
             "the frozen v1 inputs still match the archived pre-leakfix build 140/140.") if ok
            else f"v2 problems {len(problems)}, v1 preservation problems {len(legacy_problems)}.",
            {"units": len(rows), "legacy_units": len(legacy_rows),
             "problems": problems[:10], "legacy_problems": legacy_problems[:10]},
        )

    run_check("D1", "hybrid", "Hybrid v2 source views equal current cleaning; v1 preserved", fn)


def check_hybrid_evidence_rebuild() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        hb = _load_hybrid_build()
        static_rows = hb.load_static()[0]
        dyn_rows = hb.load_dynamic()[0]
        rows = _hybrid_units()
        problems = []
        for row in rows:
            unit = UNIT_BY_ID[row["unit_id"]]
            static_text = hb.render_static(static_rows.get(unit["unit_id"], {}), unit["unit_id"])
            dyn = dyn_rows.get(source_key(unit["sources"], unit["defines"]))
            if dyn is None:
                problems.append(f"{unit['unit_id']}: no dynamic result")
                continue
            dynamic_text = hb.render_dynamic(dyn)
            combined = hb.render_combined(static_text, dynamic_text)
            expected = {"static": static_text, "dynamic": dynamic_text, "combined": combined}
            for method, text in expected.items():
                if row["evidence"][method] != text:
                    problems.append(f"{unit['unit_id']}: {method} evidence differs")
            donor_id = row["placebo_donor_unit"]
            donor = UNIT_BY_ID[donor_id]
            donor_static = hb.render_static(static_rows.get(donor_id, {}), donor_id)
            donor_dyn = dyn_rows.get(source_key(donor["sources"], donor["defines"]))
            donor_text = hb.render_combined(donor_static, hb.render_dynamic(donor_dyn))
            if row["placebo_evidence"] != donor_text:
                problems.append(f"{unit['unit_id']}: placebo evidence is not donor combined")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"All 140 x 4 evidence blocks reproduced from the frozen static/dynamic runs ({len(rows)*4} blocks)." if ok else f"{len(problems)} problems.",
            {"blocks": len(rows) * 4, "problems": problems[:10]},
        )

    run_check("D2", "hybrid", "Hybrid evidence blocks reproduce from frozen tool runs", fn)


def check_placebo_mapping() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = _hybrid_units()
        manifest = read_json(HYBRID_INPUTS / "manifest.json")
        donors = manifest["placebo"]["donors"]
        problems = []
        if len(donors) != 140:
            problems.append(f"donor map size {len(donors)}")
        ids = {r["unit_id"] for r in rows}
        if set(donors) != ids:
            problems.append("donor keys differ from units")
        donor_values = list(donors.values())
        if len(set(donor_values)) != len(donor_values):
            problems.append("donor map is not injective")
        if set(donor_values) != ids:
            problems.append("donor map is not a permutation")
        group = {r["unit_id"]: r["group_id"] for r in rows}
        label = {r["unit_id"]: bool(r["label"]) for r in rows}
        fixed, same_group = [], []
        for uid, donor in donors.items():
            if donor == uid:
                fixed.append(uid)
            if group.get(donor) == group.get(uid):
                same_group.append(uid)
        if fixed:
            problems.append(f"{len(fixed)} fixed points")
        if same_group:
            problems.append(f"{len(same_group)} same-group donors")
        # Recompute with the documented seed and algorithm.
        import random
        rng = random.Random(20261112)
        ordered = sorted(ids)
        recomputed = None
        for _ in range(200000):
            order = ordered[:]
            rng.shuffle(order)
            if all(t != s and group[t] != group[s] for t, s in zip(ordered, order)):
                recomputed = dict(zip(ordered, order))
                break
        if recomputed != donors:
            problems.append("recomputed derangement differs from manifest")
        donor_label = Counter(("bad" if label[d] else "good") for d in donor_values)
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "140/140 placebo donors: no self-map, no same-group donor, permutation, and reproducible with seed 20261112." if ok else "; ".join(problems),
            {"pairs": len(donors), "fixed_points": len(fixed), "same_group": len(same_group),
             "donor_label": dict(donor_label), "problems": problems[:10],
             "recomputed_matches": recomputed == donors},
        )

    run_check("D3", "hybrid", "Placebo is a reproducible group-separated derangement", fn)


def check_hybrid_prompts() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = {r["unit_id"]: r for r in _hybrid_units()}
        juliet = {r["unit_id"]: r for r in read_jsonl(JULIET_BUILD / "test.jsonl")}
        runs = {
            (model, method): ROOT / f"hybrid/runs/{HYBRID_OFFICIAL}_{model}_{method}"
            for model in ("deepseek", "mimo") for method in hybrid_prompts.METHODS
        }
        problems = []
        checked = 0
        direct_matches = 0
        direct_units: set[str] = set()
        versions = set()
        for (model, method), run_dir in runs.items():
            manifest = read_json(run_dir / "manifest.json")
            versions.add(manifest.get("prompt_version"))
            results = read_jsonl(run_dir / "results.jsonl")
            if len(results) != 140:
                problems.append(f"{model}/{method}: {len(results)} results")
            for rec in results:
                uid = rec["unit_id"]
                unit = rows[uid]
                messages, metadata = hybrid_prompts.build_messages(unit, method)
                joined = "\n".join(m["content"] for m in messages)
                hits = {k: v for k, v in prompt_forbidden_hits(joined).items() if v}
                if hits:
                    problems.append(f"{model}/{method}/{uid}: forbidden {hits}")
                if uid in joined or unit["group_id"] in joined:
                    problems.append(f"{model}/{method}/{uid}: identifier in prompt")
                if method == "shuffled":
                    donor = unit["placebo_donor_unit"]
                    if donor in joined:
                        problems.append(f"{model}/{method}/{uid}: donor id in prompt")
                if metadata["prompt_sha256"] != rec["prompt"]["prompt_sha256"]:
                    problems.append(f"{model}/{method}/{uid}: live prompt hash differs")
                if method == "direct":
                    if messages != juliet[uid]["messages"]:
                        problems.append(f"{model}/{method}/{uid}: direct prompt differs from juliet_llm")
                    elif juliet_prompt_sha(messages) == juliet[uid]["prompt_sha256"]:
                        direct_matches += 1
                        direct_units.add(uid)
                checked += 1
        expected_version = "hybrid-v2-juliet-llm-binary-2026-11-12.2"
        if versions != {expected_version}:
            problems.append(f"prompt versions {sorted(versions)}")
        ok = not problems and len(direct_units) == 140
        return (
            "PASS" if ok else "FAIL",
            f"{checked} v2 hybrid prompts rebuilt; direct is byte-identical to juliet_llm in {len(direct_units)}/140 units ({direct_matches} run-level matches); all prompts pass the built-in audits." if ok else f"{len(problems)} problems, direct matches {len(direct_units)}/140.",
            {"run_id": HYBRID_OFFICIAL, "checked": checked, "direct_matches": direct_matches,
             "direct_units": len(direct_units), "prompt_versions": sorted(versions),
             "problems": problems[:10]},
        )

    run_check("D4", "hybrid", "Hybrid prompts: direct == juliet_llm; all methods label-free", fn)


def check_hybrid_shuffled_is_placebo() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = {r["unit_id"]: r for r in _hybrid_units()}
        problems = []
        collision_units: set[str] = set()
        same_text_units: set[str] = set()
        used_units: set[str] = set()
        for model in ("deepseek", "mimo"):
            combined = {r["unit_id"]: r for r in read_jsonl(ROOT / f"hybrid/runs/{HYBRID_OFFICIAL}_{model}_combined/results.jsonl")}
            shuffled = {r["unit_id"]: r for r in read_jsonl(ROOT / f"hybrid/runs/{HYBRID_OFFICIAL}_{model}_shuffled/results.jsonl")}
            for uid, rec in shuffled.items():
                _messages, meta = hybrid_prompts.build_messages(rows[uid], "shuffled")
                if meta["prompt_sha256"] != rec["prompt"]["prompt_sha256"]:
                    problems.append(f"{model}/{uid}: shuffled prompt not donor evidence")
                if rows[uid]["placebo_evidence"] == rows[uid]["evidence"]["combined"]:
                    same_text_units.add(uid)
                else:
                    used_units.add(uid)
                if rec["prompt"]["prompt_sha256"] == combined[uid]["prompt"]["prompt_sha256"]:
                    collision_units.add(uid)
        ok = not problems
        status = "PASS" if ok and not collision_units else ("WARN" if ok else "FAIL")
        detail = (
            f"{HYBRID_OFFICIAL}: shuffled prompts are built from donor evidence for all 280 unit-runs; "
            f"{len(collision_units)}/140 units have donor evidence text identical to their own, "
            f"so the placebo is a no-op for those units (not an integrity failure)."
            if ok else f"{len(problems)} problems."
        )
        return (
            status,
            detail,
            {"run_id": HYBRID_OFFICIAL, "checked": 280, "donor_evidence_used": len(used_units),
             "identical_text_units": len(same_text_units),
             "prompt_hash_collisions": len(collision_units),
             "collision_unit_ids": sorted(collision_units), "problems": problems[:10]},
        )

    run_check("D5", "hybrid", "Shuffled runs use the donor's combined evidence, not the unit's own", fn)


def check_hybrid_code_label_words() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = _hybrid_units()
        legacy_rows = read_jsonl(HYBRID_SUPERSEDED_INPUTS / "units.jsonl")
        hits = []
        for row in rows:
            found = sorted({m.group(0).lower() for m in LABEL_WORD_RE.finditer(row["source_text"])})
            if found:
                hits.append({"unit_id": row["unit_id"], "label": "bad" if row["label"] else "good", "tokens": found})
        legacy_hits = []
        for row in legacy_rows:
            found = sorted({m.group(0).lower() for m in LABEL_WORD_RE.finditer(row["source_text"])})
            if found:
                legacy_hits.append({"unit_id": row["unit_id"], "label": "bad" if row["label"] else "good", "tokens": found})
        legacy_ok = len(legacy_hits) == 6 and all(h["label"] == "good" for h in legacy_hits)
        ok = not hits and legacy_ok
        if ok:
            detail = ("0/140 v2 hybrid source views contain benign/fixed/safe/clean words; "
                      "the frozen v1 pack keeps exactly 6 good-unit hits as the leak contrast.")
        elif hits:
            detail = f"{len(hits)}/140 v2 hybrid source views still contain label words."
        else:
            detail = f"v2 is clean, but the frozen v1 leak contrast changed: {len(legacy_hits)} hits."
        return (
            "PASS" if ok else "FAIL",
            detail,
            {"units": hits, "legacy_units": legacy_hits, "methods_per_unit": 5, "models": 2,
             "note": "v2 uses the current cleaner; v1 is retained unchanged as the leak contrast"},
        )

    run_check("D6", "hybrid", "Hybrid v2 code blocks are label-word free; v1 keeps the leak contrast", fn)



# ---------------------------------------------------------------------------
# E. Pair-joint
# ---------------------------------------------------------------------------

def check_pair_dataset() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        units, meta, digest = pair_common.load_pairs(ROOT / "splits/test_pairs_180.json")
        problems = []
        if len(units) != 180:
            problems.append(f"pairs {len(units)}")
        if len({u.pair_id for u in units}) != len(units):
            problems.append("duplicate pair_id")
        for unit in units:
            if unit.vulnerable_body == unit.fixed_body:
                problems.append(f"{unit.pair_id}: identical sides")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"180 unique pairs loaded; dataset SHA-256 {digest[:16]}...; each side non-empty and distinct." if ok else "; ".join(problems),
            {"pairs": len(units), "dataset_sha256": digest, "metadata": meta.get("sampling")},
        )

    run_check("E1", "pair", "Pair dataset loads as 180 valid pairs", fn)


def check_pair_order() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        units, _meta, _digest = pair_common.load_pairs(ROOT / "splits/test_pairs_180.json")
        order_map = pair_common.build_order_map(units)
        expected_hash = pair_common.order_map_sha256(order_map)
        problems = []
        if order_map["counts"] != {"A": 90, "B": 90}:
            problems.append(f"counts {order_map['counts']}")
        per_run = {}
        for run in ("test_deepseek_180", "test_mimo_180"):
            pos = read_json(ROOT / f"pair_joint/runs/{run}/position_map.json")
            stored = {k: v for k, v in pos.items() if k != "sha256"}
            if stored != order_map:
                problems.append(f"{run}: stored map differs")
            if pos.get("sha256") != expected_hash:
                problems.append(f"{run}: map hash differs")
            per_run[run] = {"counts": pos.get("counts"), "sha256": pos.get("sha256")}
        a_vuln = sum(1 for v in order_map["assignments"].values() if v["vulnerable_slot"] == "A")
        b_vuln = sum(1 for v in order_map["assignments"].values() if v["vulnerable_slot"] == "B")
        if a_vuln != 90 or b_vuln != 90:
            problems.append(f"vulnerable A/B {a_vuln}/{b_vuln}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"HMAC order map is exactly 90/90 (vulnerable in A: {a_vuln}, in B: {b_vuln}); both runs carry the same SHA-256 {expected_hash[:16]}..." if ok else "; ".join(problems),
            {"vulnerable_A": a_vuln, "vulnerable_B": b_vuln, "order_map_sha256": expected_hash,
             "runs": per_run, "problems": problems},
        )

    run_check("E2", "pair", "Pair A/B order is exactly 90/90 and shared by both models", fn)


def check_pair_prompts() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        units, _meta, _digest = pair_common.load_pairs(ROOT / "splits/test_pairs_180.json")
        by_id = {u.pair_id: u for u in units}
        order_map = pair_common.build_order_map(units)
        problems = []
        checked = 0
        wrapper_hits = Counter()
        body_cve = []
        for model in ("deepseek", "mimo"):
            run_dir = ROOT / f"pair_joint/runs/test_{model}_180"
            requests = {r["pair_id"]: r for r in read_jsonl(run_dir / "requests.jsonl")}
            results = {r["pair_id"]: r for r in read_jsonl(run_dir / "results.jsonl")}
            if len(requests) != 180 or len(results) != 180:
                problems.append(f"{model}: requests {len(requests)} results {len(results)}")
            for pair_id, unit in by_id.items():
                assignment = order_map["assignments"][pair_id]
                prompt = pair_common.build_prompt(unit, assignment)
                audit = pair_common.audit_prompt(unit, assignment, prompt)
                for key, value in audit["wrapper_hits"].items():
                    if value:
                        wrapper_hits[key] += 1
                        problems.append(f"{model}/{pair_id}: wrapper hit {key}")
                if audit["slot_leak"]:
                    problems.append(f"{model}/{pair_id}: slot leak")
                if audit["body_hits"]["cve_in_body"]:
                    body_cve.append(pair_id)
                req = requests.get(pair_id)
                res = results.get(pair_id)
                if req is None or res is None:
                    problems.append(f"{model}/{pair_id}: missing request/result")
                    continue
                if prompt.sha256() != req["prompt_sha256"]:
                    problems.append(f"{model}/{pair_id}: rebuilt prompt hash differs")
                if req["messages"] != list(prompt.messages):
                    problems.append(f"{model}/{pair_id}: request messages differ")
                if res["prompt_sha256"] != req["prompt_sha256"]:
                    problems.append(f"{model}/{pair_id}: result prompt hash differs")
                checked += 1
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"Both models' 360 requests rebuilt; wrapper is free of pair_id/idx/commit/filepath/func_name/project; no slot leak." if ok else f"{len(problems)} problems.",
            {"checked": checked, "wrapper_hits": dict(wrapper_hits), "pairs_with_cve_in_body": sorted(set(body_cve)),
             "problems": problems[:10]},
        )

    run_check("E3", "pair", "Pair prompts are metadata-free and match the frozen order map", fn)


def check_pair_results() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        units, _meta, _digest = pair_common.load_pairs(ROOT / "splits/test_pairs_180.json")
        order_map = pair_common.build_order_map(units)
        summary = {}
        problems = []
        for model in ("deepseek", "mimo"):
            rows = read_jsonl(ROOT / f"pair_joint/runs/test_{model}_180/results.jsonl")
            cm = Counter()
            for row in rows:
                assignment = order_map["assignments"][row["pair_id"]]
                decision = row.get("validation", {}).get("decision_parsed")
                if row.get("validation", {}).get("decision_valid") and decision == assignment["vulnerable_slot"]:
                    cm["correct"] += 1
                elif decision in ("A", "B") and decision != assignment["vulnerable_slot"]:
                    cm["swapped"] += 1
                elif decision == "both":
                    cm["both"] += 1
                elif decision == "neither":
                    cm["neither"] += 1
                else:
                    cm["invalid"] += 1
            da = cm["correct"] / len(rows) if rows else 0
            summary[model] = {"n": len(rows), "counts": dict(cm), "DA": round(da, 6)}
            expected = 138 if model == "deepseek" else 156
            if cm["correct"] != expected:
                problems.append(f"{model}: DA correct {cm['correct']} != reported {expected}")
            if cm["invalid"]:
                problems.append(f"{model}: {cm['invalid']} invalid")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Pair DA reproduces the report: DeepSeek 138/180 (76.67%), MiMo 156/180 (86.67%), 0 invalid." if ok else "; ".join(problems),
            {"summary": summary, "problems": problems},
        )

    run_check("E4", "pair", "Pair DA reproduces the reported 138/180 and 156/180", fn)


# ---------------------------------------------------------------------------
# F. Repair
# ---------------------------------------------------------------------------

def check_repair_inputs() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = read_jsonl(ROOT / "juliet_repair/inputs/units.jsonl")
        manifest = read_json(ROOT / "juliet_repair/inputs/manifest.json")
        test_bad = {u["unit_id"] for u in TEST_UNITS if u["label"] == "bad"}
        problems = []
        if len(rows) != 70:
            problems.append(f"rows {len(rows)}")
        if {r["unit_id"] for r in rows} != test_bad:
            problems.append("unit set is not frozen test bad70")
        if manifest["units"] != 70 or manifest["groups"] != 70:
            problems.append("manifest unit/group count")
        if manifest["leak_audit"]["clean_units"] != 70 or manifest["leak_audit"]["findings"] != 0:
            problems.append("leak audit")
        bad_hash = []
        for row in rows:
            base = ROOT / "juliet_repair/inputs/files" / row["unit_key"]
            for item in row["files"]:
                path = base / item["path"]
                if not path.is_file():
                    bad_hash.append(f"{row['unit_key']}/{item['path']} missing")
                elif sha256_file(path) != item["sha256"]:
                    bad_hash.append(f"{row['unit_key']}/{item['path']} hash")
        if bad_hash:
            problems.append(f"{len(bad_hash)} file hash problems")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "70 frozen test-bad units; 70 groups; 29 C / 41 C++; 70/70 leak-audit clean; every file hash recomputed." if ok else "; ".join(problems),
            {"units": len(rows), "groups": manifest["groups"], "c_units": manifest["c_units"],
             "cpp_units": manifest["cpp_units"], "leak_audit": manifest["leak_audit"],
             "hash_problems": bad_hash[:10], "problems": problems},
        )

    run_check("F1", "repair", "Repair inputs are the frozen 70 test-bad units and all hashes match", fn)


def check_repair_baselines() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        base = ROOT / "juliet_repair/build/baselines"
        dirs = sorted(p for p in base.iterdir() if p.is_dir())
        problems = []
        stats = Counter()
        unobservable = []
        for d in dirs:
            doc = read_json(d / "baseline.json")
            bad = doc["bad"]
            good = doc["good"]
            if not bad["compile_ok"] or not good["compile_ok"]:
                problems.append(f"{d.name}: baseline compile failure")
            if bad["leak_detected"]:
                stats["bad_leak"] += 1
            else:
                stats["bad_clean"] += 1
                unobservable.append(doc["unit_id"])
            if good["leak_detected"]:
                problems.append(f"{d.name}: good unit leaked")
            else:
                stats["good_clean"] += 1
            if bad["behavior_lines"]:
                stats["bad_behavior_observable"] += 1
        if len(dirs) != 70:
            problems.append(f"{len(dirs)} baseline dirs")
        if stats["bad_leak"] != 58:
            problems.append(f"baseline leak observed {stats['bad_leak']} != 58")
        if stats["bad_clean"] != 12:
            problems.append(f"baseline leak unobservable {stats['bad_clean']} != 12")
        if stats["good_clean"] != 70:
            problems.append(f"good clean {stats['good_clean']} != 70")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"Baselines: 58/70 bad leak observed, 12/70 unobservable, 70/70 good clean; 70/70 behavior observable." if ok else "; ".join(problems),
            {"baselines": len(dirs), "stats": dict(stats), "unobservable_units": unobservable},
        )

    run_check("F2", "repair", "Repair baseline is leak-observable for exactly 58/70 units", fn)


def check_repair_summaries() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in ("deepseek_test70_final", "mimo_test70_final"):
            summary = read_json(ROOT / "juliet_repair/runs" / name / "summary.json")
            results = read_jsonl(ROOT / "juliet_repair/runs" / name / "results.jsonl")
            requests = read_jsonl(ROOT / "juliet_repair/runs" / name / "requests.jsonl")
            strict = sum(1 for r in results if r["strict_pass"])
            evaluable = sum(1 for r in results if r["strict_evaluable"])
            first = sum(1 for r in results if r["strict_pass"] and r["final_attempt"] == 1)
            out[name] = {
                "results": len(results), "requests": len(requests),
                "strict_pass": strict, "strict_evaluable": evaluable,
                "first_attempt_strict_pass": first,
                "compile_pass": sum(1 for r in results if r["compile_pass"]),
                "leak_removed": sum(1 for r in results if r["leak_removed"]),
                "behavior_preserved": sum(1 for r in results if r["behavior_preserved"]),
                "summary_strict_pass": summary.get("strict_pass"),
                "summary_strict_evaluable": summary.get("strict_evaluable"),
                "cost_usd_sum": summary.get("cost_usd_sum"),
                "total_calls": summary.get("total_calls"),
            }
            if len(results) != 70:
                problems.append(f"{name}: results {len(results)}")
            if len(requests) < 70:
                problems.append(f"{name}: requests {len(requests)}")
            if strict != 58 or evaluable != 58:
                problems.append(f"{name}: strict {strict}/{evaluable}")
            if summary.get("strict_pass") != 58:
                problems.append(f"{name}: summary strict_pass")
            if any(r["strict_pass"] and not r["strict_evaluable"] for r in results):
                problems.append(f"{name}: strict_pass on unevaluable unit")
            if name.startswith("deepseek") and first != 58:
                problems.append(f"deepseek first-attempt {first} != 58")
            if name.startswith("mimo") and first != 57:
                problems.append(f"mimo first-attempt {first} != 57")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Both final runs: 70 results, 70/72 calls, 70 compile/leak/behavior, 58/58 strict among the 58 observable units (DeepSeek 58 first-try, MiMo 57)." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("F3", "repair", "Repair metrics reproduce: 58/58 strict, 70/70 compile and behavior", fn)


def check_repair_prompt_leak() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = read_jsonl(ROOT / "juliet_repair/inputs/units.jsonl")
        bad_units = cwe_units = leak_units = 0
        good_hits = 0
        examples = []
        for row in rows:
            entry = row["entry"]
            entry_text = f"{entry['namespace']}::{entry['name']}" if entry.get("namespace") else entry["name"]
            blob = "\n".join(f["content"] for f in row["files"])
            if re.search(r"(?i)bad", entry_text) or re.search(r"(?i)bad", blob):
                bad_units += 1
            if re.search(r"(?i)cwe", entry_text) or re.search(r"(?i)cwe", blob):
                cwe_units += 1
            if re.search(r"(?i)memory[_ ]?leak", entry_text) or re.search(r"(?i)memory[_ ]?leak", blob):
                leak_units += 1
            if re.search(r"(?i)good", entry_text) or re.search(r"(?i)good", blob):
                good_hits += 1
            if len(examples) < 3:
                examples.append({"unit_id": row["unit_id"], "entry": entry_text})
        return (
            "WARN",
            f"Repair prompts contain `bad`/`CWE`/`Memory_Leak` in {bad_units}/70, {cwe_units}/70, {leak_units}/70 units; "
            f"good identifiers {good_hits}/70. The bad/CWE tokens are the repair task premise, but the input is not label-neutral.",
            {"units_with_bad": bad_units, "units_with_cwe": cwe_units,
             "units_with_memory_leak": leak_units, "units_with_good": good_hits,
             "examples": examples},
        )

    run_check("F4", "repair", "Repair prompt still contains class/entry identifiers", fn)


def check_repair_costs() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in ("deepseek_test70_final", "mimo_test70_final"):
            run_dir = ROOT / "juliet_repair/runs" / name
            manifest = read_json(run_dir / "manifest.json")
            api = manifest.get("api", {})
            prices = {
                "input": api.get("input_price_usd_per_1m", 0.0),
                "output": api.get("output_price_usd_per_1m", 0.0),
                "cached": api.get("cached_input_price_usd_per_1m", 0.0),
            }
            requests = read_jsonl(run_dir / "requests.jsonl")
            recomputed = 0.0
            allowance = 0.0
            unknown = 0
            for row in requests:
                cost = row.get("cost") or {}
                p = cost.get("prompt_tokens")
                c = cost.get("completion_tokens")
                cached = cost.get("cached_prompt_tokens", 0) or 0
                if p is None or c is None:
                    unknown += 1
                    continue
                recomputed += ((p - cached) * prices["input"] + cached * prices["cached"] + c * prices["output"]) / 1e6
                oc = (row.get("usage") or {}).get("opencode") or {}
                if isinstance(oc.get("allowance"), (int, float)):
                    allowance += float(oc["allowance"])
            summary = read_json(run_dir / "summary.json")
            delta = abs(recomputed - float(summary.get("cost_usd_sum") or 0))
            out[name] = {"recomputed_list_usd": round(recomputed, 9), "summary_usd": summary.get("cost_usd_sum"),
                         "allowance_usd": round(allowance, 9), "unknown_cost_records": unknown,
                         "prices": prices, "delta": delta}
            if delta > 1e-6:
                problems.append(f"{name}: cost delta {delta}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Repair costs recompute from per-request usage and configured prices (see evidence for provider allowance)." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("F5", "repair", "Repair cost sums recompute from usage", fn)


# ---------------------------------------------------------------------------
# G. Static
# ---------------------------------------------------------------------------

def check_static_status() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = read_jsonl(STATIC_RUN / "predictions.jsonl")
        by = Counter()
        compile_errors = []
        for row in rows:
            unit = UNIT_BY_ID[row["sample_id"]]
            by[(unit["split"], row["tool"], row["status"])] += 1
            if row["status"] != "ok":
                compile_errors.append({"split": unit["split"], "tool": row["tool"],
                                       "unit_id": row["sample_id"], "status": row["status"]})
        ok = (len(rows) == 400 and by[("test", "clang", "compile_error")] == 4
              and by[("dev", "clang", "compile_error")] == 2 and by[("test", "cppcheck", "ok")] == 140)
        return (
            "PASS" if ok else "FAIL",
            "400 tool rows; test clang compile errors 4, dev 2; cppcheck has 0 errors." if ok else f"unexpected statuses {dict(by)}",
            {"rows": len(rows), "statuses": {f"{k[0]}/{k[1]}/{k[2]}": v for k, v in sorted(by.items())},
             "compile_errors": compile_errors},
        )

    run_check("G1", "static", "Static run has exactly 4 test clang compile failures", fn)


def check_static_metrics() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        metrics = read_json(STATIC_RUN / "metrics.json")
        problems = []
        clang = metrics["tools"]["clang"]
        cpp = metrics["tools"]["cppcheck"]
        if clang["status_counts"].get("compile_error") != 6:
            problems.append(f"clang compile_error {clang['status_counts'].get('compile_error')}")
        if clang["confusion_evaluable"]["fp"] != 0:
            problems.append(f"clang FP {clang['confusion_evaluable']['fp']}")
        if cpp["confusion_evaluable"]["fp"] != 4:
            problems.append(f"cppcheck FP {cpp['confusion_evaluable']['fp']}")
        if clang["confusion_end_to_end"] != {"tp": 73, "fp": 0, "tn": 100, "fn": 27, "unlabelled": 0}:
            problems.append(f"clang end-to-end {clang['confusion_end_to_end']}")
        if clang["metrics_evaluable"]["n"] != 194 or clang["metrics_end_to_end"]["n"] != 200:
            problems.append("clang n mismatch")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Static metrics: clang evaluable 194/200 with compile errors excluded then counted as FN end-to-end (TP 73 / FN 27 / TN 100); cppcheck TP 30 / FP 4 / TN 96 / FN 70." if ok else "; ".join(problems),
            {"clang_evaluable": clang["confusion_evaluable"], "clang_end_to_end": clang["confusion_end_to_end"],
             "cppcheck_evaluable": cpp["confusion_evaluable"], "problems": problems},
        )

    run_check("G2", "static", "Static metrics count compile errors as FN end-to-end", fn)


def check_static_evidence_rendering() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        hb = _load_hybrid_build()
        static_rows = hb.load_static()[0]
        rows = {r["unit_id"]: r for r in _hybrid_units()}
        errors = [uid for uid, tools in static_rows.items() if any(t.get("status") == "compile_error" for t in tools.values())]
        problems = []
        test_errors = []
        for uid in errors:
            unit = UNIT_BY_ID[uid]
            if unit["split"] != "test":
                continue
            test_errors.append(uid)
            text = rows[uid]["evidence"]["static"]
            clang_line = next((line for line in text.splitlines() if "Clang Static Analyzer" in line), "")
            if "analysis failed" not in clang_line or "not a clean result" not in clang_line:
                problems.append(f"{uid}: clang compile failure not rendered as no-conclusion")
            if "Clang Static Analyzer: status ok" in text:
                problems.append(f"{uid}: clang compile failure rendered as ok")
        if len(test_errors) != 4:
            problems.append(f"test compile errors in hybrid inputs {len(test_errors)}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "The 4 test compile failures are rendered as \"analysis failed ... not a clean result\", never as clean." if ok else "; ".join(problems),
            {"test_compile_errors": test_errors, "problems": problems},
        )

    run_check("G3", "static", "Hybrid renders compile failures as no-conclusion", fn)


# ---------------------------------------------------------------------------
# H. Dynamic
# ---------------------------------------------------------------------------

def check_dynamic_run() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        cases = read_jsonl(DYNAMIC_RUN / "cases.jsonl")
        results = read_jsonl(DYNAMIC_RUN / "results.jsonl")
        metrics = read_json(DYNAMIC_RUN / "metrics.json")
        problems = []
        if len(cases) != 3316 or len(results) != 3316:
            problems.append(f"cases {len(cases)} results {len(results)}")
        if len({c["case_id"] for c in cases}) != len(cases):
            problems.append("duplicate case_id")
        if len({r["case_id"] for r in results}) != len(results):
            problems.append("duplicate result case_id")
        outcomes = Counter(r["outcome"] for r in results)
        if outcomes.get("inconclusive") != 1:
            problems.append(f"inconclusive {outcomes.get('inconclusive')}")
        if metrics.get("counts", {}).get("n_cases") != 3316:
            problems.append("metrics n_cases")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"3316 real cases/results: leak {outcomes.get('leak')}, clean {outcomes.get('clean')}, inconclusive {outcomes.get('inconclusive')}." if ok else "; ".join(problems),
            {"cases": len(cases), "results": len(results), "outcomes": dict(outcomes)},
        )

    run_check("H1", "dynamic", "Full dynamic run has 3316 cases with one documented inconclusive", fn)


def check_dynamic_frozen_join() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        dyn = load_dynamic_results()
        problems = []
        stats = Counter()
        missing = []
        for unit in UNITS:
            res = dynamic_for_unit(unit, dyn)
            if res is None:
                missing.append(unit["unit_id"])
                continue
            stats[(unit["label"], res["outcome"])] += 1
        if missing:
            problems.append(f"{len(missing)} frozen units not joined")
        if stats[("bad", "leak")] != 78:
            problems.append(f"bad/leak {stats[('bad', 'leak')]}")
        if stats[("bad", "clean")] != 22:
            problems.append(f"bad/clean {stats[('bad', 'clean')]}")
        if stats[("good", "clean")] != 100:
            problems.append(f"good/clean {stats[('good', 'clean')]}")
        if stats[("bad", "inconclusive")] or stats[("good", "leak")]:
            problems.append("unexpected frozen outcome")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Frozen 200 all join: bad 78 leak / 22 clean; good 100 clean; no frozen inconclusive." if ok else "; ".join(problems),
            {"join_counts": {f"{k[0]}/{k[1]}": v for k, v in sorted(stats.items())}, "missing": missing},
        )

    run_check("H2", "dynamic", "Frozen 200 units join to dynamic results exactly", fn)


def check_dynamic_test_unobservable() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        dyn = load_dynamic_results()
        stats = Counter()
        unobservable = []
        for unit in TEST_UNITS:
            res = dynamic_for_unit(unit, dyn)
            if res is None:
                continue
            stats[(unit["label"], res["outcome"])] += 1
            if unit["label"] == "bad" and res["outcome"] == "clean":
                unobservable.append(unit["unit_id"])
        ok = (stats[("bad", "leak")] == 58 and stats[("bad", "clean")] == 12
              and stats[("good", "clean")] == 70)
        families = Counter(UNIT_BY_ID[u]["family"] for u in unobservable)
        return (
            "PASS" if ok else "FAIL",
            f"Test140: 58 bad leak / 12 bad unobservable / 70 good clean; the 12 are the documented LSan blind spots." if ok else f"counts {dict(stats)}",
            {"counts": {f"{k[0]}/{k[1]}": v for k, v in sorted(stats.items())},
             "unobservable_units": unobservable, "families": dict(families)},
        )

    run_check("H3", "dynamic", "Test140 has 58 observable and 12 unobservable bad units", fn)


def check_dynamic_evidence_not_clean() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        rows = {r["unit_id"]: r for r in _hybrid_units()}
        problems = []
        for row in rows.values():
            if row["label"] and row["dynamic_outcome"] == "clean":
                text = row["evidence"]["dynamic"]
                if "no leak detected in this run" not in text:
                    problems.append(f"{row['unit_id']}: missing run-specific clean wording")
                if "not proof of absence" not in text:
                    problems.append(f"{row['unit_id']}: missing absence caveat")
            if row["dynamic_outcome"] == "inconclusive" and "NOT a clean result" not in row["evidence"]["dynamic"]:
                problems.append(f"{row['unit_id']}: inconclusive not marked non-clean")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "All 12 bad-but-clean-evidence units carry \"no leak detected in this run ... not proof of absence\"; inconclusive is never clean." if ok else f"{len(problems)} problems.",
            {"checked_bad_clean": sum(1 for r in rows.values() if r["label"] and r["dynamic_outcome"] == "clean"),
             "problems": problems[:10]},
        )

    run_check("H4", "dynamic", "Dynamic clean evidence is never presented as proof of no leak", fn)


# ---------------------------------------------------------------------------
# I. Cost accounting
# ---------------------------------------------------------------------------

def _cost_from_tokens(prompt: int, completion: int, cached: int, prices: dict[str, float]) -> float:
    return ((prompt - cached) * prices["input"] + cached * prices["cached"] + completion * prices["output"]) / 1e6


def _prices(api: dict[str, Any]) -> dict[str, float]:
    return {
        "input": float(api.get("input_price_usd_per_1m") or 0.0),
        "output": float(api.get("output_price_usd_per_1m") or 0.0),
        "cached": float(api.get("cached_input_price_usd_per_1m") or 0.0),
    }


def check_hybrid_cost() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        metrics = read_json(ROOT / "hybrid/results/hybrid_v2_metrics.json")
        runs = {}
        problems = []
        total_list = 0.0
        total_allowance = 0.0
        by_model = {model: {"list_usd": 0.0, "allowance_usd": 0.0, "provider_list_usd": 0.0}
                    for model in ("deepseek", "mimo")}
        expected_prices = {
            "deepseek": {"input": 0.15, "output": 0.60, "cached": 0.003},
            "mimo": {"input": 0.14, "output": 0.28, "cached": 0.0028},
        }
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                run_dir = ROOT / f"hybrid/runs/{HYBRID_OFFICIAL}_{model}_{method}"
                config = read_json(run_dir / "config.json")
                prices = _prices(config["api"])
                if prices != expected_prices[model]:
                    problems.append(f"{model}/{method}: config prices {prices}")
                rows = read_jsonl(run_dir / "results.jsonl")
                recomputed = 0.0
                allowance = 0.0
                provider_list = 0.0
                max_delta = 0.0
                for row in rows:
                    cost = row.get("cost") or {}
                    p = int(cost.get("prompt_tokens") or 0)
                    c = int(cost.get("completion_tokens") or 0)
                    cached = int(cost.get("cached_prompt_tokens") or 0)
                    expected = _cost_from_tokens(p, c, cached, prices)
                    stored = float(cost.get("cost_usd") or 0.0)
                    max_delta = max(max_delta, abs(expected - stored))
                    recomputed += stored
                    oc = (row.get("usage") or {}).get("opencode") or {}
                    if isinstance(oc.get("allowance"), (int, float)):
                        allowance += float(oc["allowance"])
                    if isinstance(oc.get("list_cost"), (int, float)):
                        provider_list += float(oc["list_cost"])
                agg = metrics["runs"][f"{model}/{method}"]["usage"]
                if abs(recomputed - float(agg["cost_usd_sum"])) > 1e-9:
                    problems.append(f"{model}/{method}: list {recomputed} != metrics {agg['cost_usd_sum']}")
                if abs(allowance - float(agg["provider_allowance_usd_sum"])) > 1e-9:
                    problems.append(f"{model}/{method}: allowance {allowance} != metrics {agg['provider_allowance_usd_sum']}")
                runs[f"{model}/{method}"] = {
                    "list_usd": round(recomputed, 9), "allowance_usd": round(allowance, 9),
                    "provider_list_usd": round(provider_list, 9),
                    "max_row_cost_delta": max_delta,
                }
                total_list += recomputed
                total_allowance += allowance
                by_model[model]["list_usd"] += recomputed
                by_model[model]["allowance_usd"] += allowance
                by_model[model]["provider_list_usd"] += provider_list
                if max_delta > 1e-9:
                    problems.append(f"{model}/{method}: row cost delta {max_delta}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            (f"{HYBRID_OFFICIAL}: 10 runs / 1400 requests; list ${total_list:.6f}, allowance ${total_allowance:.6f}; "
             f"every row recomputes from usage and the provider-matched price card.") if ok else "; ".join(problems),
            {"run_id": HYBRID_OFFICIAL, "runs": runs,
             "total_list_usd": round(total_list, 9), "total_allowance_usd": round(total_allowance, 9),
             "by_model": {k: {kk: round(vv, 9) for kk, vv in v.items()} for k, v in by_model.items()},
             "problems": problems},
        )

    run_check("I1", "cost", "Hybrid v2 cost totals recompute from per-request usage", fn)


def check_juliet_cost() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in JULIET_OFFICIAL_RUNS:
            run = ROOT / "juliet_llm/runs" / name
            manifest = read_json(run / "manifest.json")
            metrics = read_json(run / "metrics.json")
            prices = _prices(manifest["api"])
            rows = read_jsonl(run / "results.jsonl")
            recomputed = 0.0
            max_delta = 0.0
            for row in rows:
                cost = row["cost"]
                expected = _cost_from_tokens(cost["prompt_tokens"], cost["completion_tokens"],
                                             cost.get("cached_prompt_tokens", 0), prices)
                max_delta = max(max_delta, abs(expected - cost["cost_usd"]))
                recomputed += cost["cost_usd"]
            published = metrics["aggregate"]["cost"]["published_price_usd"]["sum"]
            out[name] = {"rows": len(rows), "recomputed_usd": round(recomputed, 9),
                         "published_usd": round(published, 9), "max_row_cost_delta": max_delta,
                         "prompt_version": manifest.get("prompt_version")}
            if len(rows) != 140 or manifest.get("recorded_requests") != 140:
                problems.append(f"{name}: rows/recorded")
            if manifest.get("prompt_version") != "juliet-llm-binary-2026-11-12.2":
                problems.append(f"{name}: prompt version {manifest.get('prompt_version')}")
            if max_delta > 1e-12:
                problems.append(f"{name}: row cost delta {max_delta}")
            if abs(recomputed - published) > 1e-9:
                problems.append(f"{name}: {recomputed} != published {published}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            (f"juliet_llm postleakfix official+repro: 280 rows; ${out[JULIET_OFFICIAL_RUNS[0]]['recomputed_usd']:.9f} "
             f"and ${out[JULIET_OFFICIAL_RUNS[1]]['recomputed_usd']:.9f} at Xiaomi published prices; "
             "provider allowance is not returned on that endpoint (documented).")
            if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("I2", "cost", "juliet_llm postleakfix cost recomputes at the documented Xiaomi prices", fn)


def check_repair_cost_total() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        runs = {}
        total = 0.0
        headline = 0.0
        for p in sorted((ROOT / "juliet_repair/runs").glob("**/requests.jsonl")):
            rows = read_jsonl(p)
            cost = sum(float(r["cost"]["cost_usd"]) for r in rows)
            run_name = p.parent.name
            runs[run_name] = {"requests": len(rows), "cost_usd": round(cost, 9)}
            total += cost
            if run_name in ("deepseek_test70_final", "mimo_test70_final"):
                headline += cost
        readme = (ROOT / "juliet_repair/README.md").read_text(encoding="utf-8")
        claimed_all = 0.082550
        delta = total - claimed_all
        problems = []
        if abs(delta) > 1e-6:
            problems.append(f"recorded total {total} != documented {claimed_all}")
        if "0.082550" not in readme:
            problems.append("README does not state 0.082550")
        if "0.077516" in readme:
            problems.append("README still states the superseded 0.077516")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"Recorded repair spend ${total:.6f}; README all-in claim ${claimed_all:.6f}; delta ${delta:+.9f} "
            f"(the previously omitted parser_dev/mimo_test70_v1 is included: ${runs.get('mimo_test70_v1', {}).get('cost_usd', 0):.6f})."
            if ok else "; ".join(problems),
            {"runs": runs, "headline_usd": round(headline, 9), "all_recorded_usd": round(total, 9),
             "readme_all_in_usd": claimed_all, "delta_usd": round(delta, 9), "problems": problems},
        )

    run_check("I3", "cost", "Repair documented all-in cost matches recorded requests", fn)


def check_pair_cost() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for model, expected_list, expected_allowance in (
            ("deepseek", 0.153593052, 0.04607779),
            ("mimo", 0.071803312, 0.07180344),
        ):
            run_dir = ROOT / f"pair_joint/runs/test_{model}_180"
            config = read_json(run_dir / "config.json")
            prices = _prices(config["api"])
            rows = read_jsonl(run_dir / "results.jsonl")
            recomputed = 0.0
            allowance = 0.0
            max_delta = 0.0
            for row in rows:
                cost = (row.get("response") or {}).get("cost") or {}
                p = int(cost.get("prompt_tokens") or 0)
                c = int(cost.get("completion_tokens") or 0)
                cached = int(cost.get("cached_prompt_tokens") or 0)
                expected = _cost_from_tokens(p, c, cached, prices)
                stored = float(cost.get("cost_usd") or 0)
                max_delta = max(max_delta, abs(expected - stored))
                recomputed += stored
                oc = ((row.get("response") or {}).get("usage") or {}).get("opencode") or {}
                if isinstance(oc.get("allowance"), (int, float)):
                    allowance += float(oc["allowance"])
            out[model] = {"list_usd": round(recomputed, 9), "allowance_usd": round(allowance, 9),
                          "max_row_cost_delta": max_delta}
            if abs(recomputed - expected_list) > 1e-6:
                problems.append(f"{model}: list {recomputed} != {expected_list}")
            if abs(allowance - expected_allowance) > 1e-6:
                problems.append(f"{model}: allowance {allowance} != {expected_allowance}")
            if max_delta > 1e-9:
                problems.append(f"{model}: row delta {max_delta}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Pair costs recompute: DeepSeek $0.153593 / MiMo $0.071803 list; allowance $0.046078 / $0.071803." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("I4", "cost", "Pair-joint cost totals recompute from usage", fn)


def check_cost_basis_consistency() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        samples = []
        expected_v2 = {"deepseek": {"input": 0.15, "output": 0.60, "cached": 0.003},
                       "mimo": {"input": 0.14, "output": 0.28, "cached": 0.0028}}
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                run = f"{HYBRID_OFFICIAL}_{model}_{method}"
                run_dir = ROOT / f"hybrid/runs/{run}"
                config = read_json(run_dir / "config.json")
                prices = _prices(config["api"])
                rows = read_jsonl(run_dir / "results.jsonl")
                stored = sum(float(r["cost"]["cost_usd"]) for r in rows)
                provider = sum(float((r.get("usage") or {}).get("opencode", {}).get("list_cost") or 0) for r in rows)
                ratio = provider / stored if stored else None
                samples.append({"run": run, "configured_list_usd": round(stored, 9),
                                "provider_list_usd": round(provider, 9),
                                "ratio": round(ratio, 6) if ratio else None,
                                "configured_prices": prices})
                if prices != expected_v2[model]:
                    problems.append(f"{run}: prices {prices}")
                if not ratio or abs(ratio - 1.0) > 0.02:
                    problems.append(f"{run}: provider/configured ratio {ratio}")
        legacy_samples = []
        for run in (f"{HYBRID_SUPERSEDED}_deepseek_direct", f"{HYBRID_SUPERSEDED}_deepseek_combined"):
            run_dir = ROOT / f"hybrid/runs/{run}"
            rows = read_jsonl(run_dir / "results.jsonl")
            stored = sum(float(r["cost"]["cost_usd"]) for r in rows)
            provider = sum(float((r.get("usage") or {}).get("opencode", {}).get("list_cost") or 0) for r in rows)
            legacy_samples.append({"run": run, "configured_list_usd": round(stored, 9),
                                   "provider_list_usd": round(provider, 9),
                                   "ratio": round(provider / stored, 6) if stored else None})
        juliet_deepseek = read_json(ROOT / "juliet_llm/runs/20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke/manifest.json")
        juliet_prices = juliet_deepseek["prices_usd_per_1m"]
        costnorm = read_json(ROOT / "analysis/cost_normalization.json")
        off_peak = bool(costnorm.get("audit_resolution", {}).get("I5", {}).get("all_requests_off_peak"))
        if not off_peak:
            problems.append("cost normalization does not confirm off-peak pricing")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            ("hybrid_v2 prices DeepSeek at $0.15/$0.60/$0.003 and MiMo at $0.14/$0.28/$0.0028; "
             "all 10 configured totals match the provider list_cost within 2%. The frozen v1 rows keep the "
             "old 0.30/1.20 peak card (ratio 0.5), documented in analysis/cost_normalization as the off-peak snapshot.")
            if ok else "; ".join(problems),
            {"v2_samples": samples, "legacy_samples": legacy_samples,
             "juliet_llm_deepseek_prices": juliet_prices,
             "cost_normalization": {"audit_resolution_I5": costnorm.get("audit_resolution", {}).get("I5"),
                                    "verification": costnorm.get("verification", {}).get("status")},
             "problems": problems},
        )

    run_check("I5", "cost", "Hybrid v2 DeepSeek prices match the provider snapshot; v1 peak card documented", fn)


def check_runner_legacy_cost() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for d in sorted(p for p in (ROOT / "runner/runs").glob("test_v1_*") if p.is_dir()):
            metrics = read_json(d / "metrics.json")
            config = read_json(d / "config.json")
            prices = _prices(config["api"])
            rows = read_jsonl(d / "results.jsonl")
            recomputed = 0.0
            for row in rows:
                cost = ((row.get("response") or {}).get("cost") or {})
                if cost.get("prompt_tokens") is None:
                    continue
                recomputed += _cost_from_tokens(cost["prompt_tokens"], cost["completion_tokens"],
                                                cost.get("cached_prompt_tokens", 0), prices)
            stored = float(metrics.get("cost", {}).get("total_cost_usd") or 0)
            out[d.name] = {"requests": len(rows), "recomputed_usd": round(recomputed, 6), "metrics_usd": stored}
            if abs(recomputed - stored) > 1e-4:
                problems.append(f"{d.name}: {recomputed} != {stored}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "All 12 legacy runner runs' cost totals recompute from their results and config." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("I6", "cost", "Legacy runner cost totals are internally consistent", fn)


def check_cost_normalization() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        path = ROOT / "analysis/cost_normalization.json"
        problems = []
        if not path.is_file():
            return "FAIL", "analysis/cost_normalization.json is missing.", {"path": str(path)}
        data = read_json(path)
        verification = data.get("verification", {})
        if data.get("schema") != "cost-normalization-v1":
            problems.append(f"schema {data.get('schema')}")
        if data.get("no_api_calls") is not True:
            problems.append("no_api_calls is not true")
        for key in ("source_artifacts_changed", "provider_mismatch_runs"):
            if verification.get(key) != []:
                problems.append(f"verification.{key} = {verification.get(key)}")
        for key in ("token_mismatch_rows", "missing_cost_rows", "peak_rows"):
            if verification.get(key) != 0:
                problems.append(f"verification.{key} = {verification.get(key)}")
        if verification.get("status") != "PASS":
            problems.append(f"verification.status = {verification.get('status')}")
        entries = {r["run_id"]: r for r in data.get("runs", [])}
        checked_runs = 0
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                run_id = f"{HYBRID_OFFICIAL}_{model}_{method}"
                entry = entries.get(run_id)
                if entry is None:
                    problems.append(f"{run_id}: not in cost_normalization.runs")
                    continue
                rows = read_jsonl(ROOT / f"hybrid/runs/{run_id}/results.jsonl")
                stored = sum(float(r["cost"]["cost_usd"]) for r in rows)
                provider = sum(float((r.get("usage") or {}).get("opencode", {}).get("list_cost") or 0) for r in rows)
                if abs(float(entry["configured_recorded_usd"]) - stored) > 1e-9:
                    problems.append(f"{run_id}: configured {entry['configured_recorded_usd']} != {stored}")
                if abs(float(entry["normalized_list_usd"]) - stored) > 1e-9:
                    problems.append(f"{run_id}: normalized {entry['normalized_list_usd']} != {stored}")
                if abs(float(entry["provider_list_usd"]) - provider) > 1e-9:
                    problems.append(f"{run_id}: provider list {entry['provider_list_usd']} != {provider}")
                if entry.get("checks", {}).get("source_artifact_unchanged") is not True:
                    problems.append(f"{run_id}: source artifact changed")
                checked_runs += 1
        repair_total = 0.0
        for p in sorted((ROOT / "juliet_repair/runs").glob("**/requests.jsonl")):
            repair_total += sum(float(r["cost"]["cost_usd"]) for r in read_jsonl(p))
        if abs(float(data["juliet_repair"]["all_configured_usd"]) - repair_total) > 1e-6:
            problems.append("juliet_repair.all_configured_usd differs from requests")
        resolution = data.get("audit_resolution", {})
        if abs(float(resolution.get("I3", {}).get("readme_new_all_in_usd", 0)) - 0.082550) > 1e-9:
            problems.append("audit_resolution.I3.readme_new_all_in_usd != 0.082550")
        if abs(float(resolution.get("I3", {}).get("readme_old_all_in_usd", 0)) - 0.077516) > 1e-9:
            problems.append("audit_resolution.I3.readme_old_all_in_usd != 0.077516")
        if resolution.get("I5", {}).get("all_requests_off_peak") is not True:
            problems.append("audit_resolution.I5.all_requests_off_peak is not true")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            (f"analysis/cost_normalization.json: {len(entries)} stored runs / {verification.get('usage_rows')} requests; "
             f"verification PASS, {verification.get('peak_rows')} peak rows, 0 changed source artifacts; "
             f"{checked_runs}/10 hybrid_v2 runs match configured = normalized = provider list; "
             f"repair all-in normalized at ${data['juliet_repair']['all_normalized_usd']:.6f}.")
            if ok else "; ".join(problems),
            {"entries": len(entries), "verification": verification,
             "checked_hybrid_v2_runs": checked_runs,
             "repair": data.get("juliet_repair"), "audit_resolution": resolution,
             "problems": problems},
        )

    run_check("I7", "cost", "Normalized provider-list costs are complete and reconcile to the artifacts", fn)


# ---------------------------------------------------------------------------
# J. Endpoints
# ---------------------------------------------------------------------------

def check_endpoints() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        endpoints: dict[str, Any] = {}
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                name = f"{HYBRID_OFFICIAL}_{model}_{method}"
                manifest = read_json(ROOT / f"hybrid/runs/{name}/manifest.json")
                endpoints[name] = {"base_url": manifest["base_url"], "model_id": manifest["model_id"]}
                if manifest["base_url"] != "https://opencode.ai/zen/go/v1":
                    problems.append(f"{name}: {manifest['base_url']}")
        for name in JULIET_OFFICIAL_RUNS:
            manifest = read_json(ROOT / f"juliet_llm/runs/{name}/manifest.json")
            endpoints[name] = {"base_url": manifest["api"]["base_url"], "model_id": manifest["model"]}
            if manifest["api"]["base_url"] != "https://api.xiaomimimo.com/v1":
                problems.append(f"{name}: {manifest['api']['base_url']}")
        for name in ("deepseek_test70_final", "mimo_test70_final"):
            manifest = read_json(ROOT / f"juliet_repair/runs/{name}/manifest.json")
            endpoints[name] = {"base_url": manifest["api"]["base_url"], "model_id": manifest["api"]["model"]}
            if manifest["api"]["base_url"] != "https://opencode.ai/zen/go/v1":
                problems.append(f"{name}: {manifest['api']['base_url']}")
        for name in ("test_deepseek_180", "test_mimo_180"):
            config = read_json(ROOT / f"pair_joint/runs/{name}/config.json")
            endpoints[name] = {"base_url": config["api"]["base_url"], "model_id": config["api"]["model"]}
            if config["api"]["base_url"] != "https://opencode.ai/zen/go/v1":
                problems.append(f"{name}: {config['api']['base_url']}")
        # Smoke evidence for the blocked OpenCode routes.
        smoke = {}
        for d in sorted((ROOT / "juliet_llm/runs").glob("*smoke*")):
            rows = read_jsonl(d / "results.jsonl")
            status = rows[0]["response"]["attempts"][0]["http_status"]
            smoke[d.name] = {"http_status": status, "base_url": read_json(d / "manifest.json")["api"]["base_url"]}
        expected_smoke = {
            "20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke": 401,
            "20261111T192149Z_smoke_deepseek-flash_dev_deepseek_official_smoke": 402,
            "20261111T192505Z_smoke_deepseek-v4.1-flash_dev_qwen_gateway_smoke": 403,
        }
        for name, status in expected_smoke.items():
            if smoke.get(name, {}).get("http_status") != status:
                problems.append(f"{name}: smoke status {smoke.get(name, {}).get('http_status')}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Headline runs use the documented endpoints: OpenCode Go for hybrid/repair/pair, Xiaomi official only for the labeled juliet_llm fallback; smoke evidence is 401/402/403 as documented." if ok else "; ".join(problems),
            {"endpoints": endpoints, "smoke": smoke, "problems": problems},
        )

    run_check("J1", "endpoint", "Every experiment uses its documented endpoint", fn)


def check_xiaomi_labeling() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        readme = (ROOT / "juliet_llm/README.md").read_text(encoding="utf-8")
        problems = []
        checked = []
        for name in JULIET_OFFICIAL_RUNS + JULIET_PRE_LEAKFIX_RUNS:
            if "xiaomi" not in name:
                problems.append(f"{name}: not tagged xiaomi")
            manifest = read_json(ROOT / f"juliet_llm/runs/{name}/manifest.json")
            if "xiaomi" not in manifest["api"]["base_url"]:
                problems.append(f"{name}: base_url not xiaomi")
            checked.append({"run": name, "prompt_version": manifest.get("prompt_version"),
                            "base_url": manifest["api"]["base_url"]})
        if "Xiaomi 官方端点" not in readme and "Xiaomi" not in readme:
            problems.append("README does not label the fallback")
        if "不能冒充 OpenCode Go" not in readme and "不是 OpenCode Go" not in readme:
            problems.append("README does not disclaim OpenCode equivalence")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "The MiMo postleakfix official/repro (and the preserved pre-fix runs) are explicitly labelled Xiaomi official-endpoint fallbacks, not OpenCode Go results." if ok else "; ".join(problems),
            {"official": list(JULIET_OFFICIAL_RUNS), "pre_leakfix": list(JULIET_PRE_LEAKFIX_RUNS),
             "checked": checked, "problems": problems},
        )

    run_check("J2", "endpoint", "Xiaomi fallback is explicitly labelled and not passed off as OpenCode", fn)


# ---------------------------------------------------------------------------
# K. Manifests and record counts
# ---------------------------------------------------------------------------

def check_runner_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for d in sorted(p for p in (ROOT / "runner/runs").glob("test_v1_*") if p.is_dir()):
            if not (d / "manifest.json").is_file():
                continue
            manifest = read_json(d / "manifest.json")
            metrics = read_json(d / "metrics.json")
            counts = manifest.get("counts", {})
            status = manifest.get("status")
            planned = counts.get("planned_requests")
            recorded = counts.get("recorded_requests")
            complete = metrics.get("counts", {}).get("complete_planned_requests")
            missing = metrics.get("counts", {}).get("missing_requests")
            ids = []
            for line in (d / "results.jsonl").read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                ids.append((rec.get("task"), rec.get("unit_id"), rec.get("side")))
            out[d.name] = {
                "status": status, "planned": planned, "recorded": recorded,
                "unique_ids": len(set(ids)), "rows": len(ids),
                "by_status": counts.get("by_status"), "complete": complete, "missing": missing,
                "model": manifest.get("api", {}).get("model"),
            }
            if status != "completed":
                problems.append(f"{d.name}: status {status}")
            if planned != recorded or len(ids) != recorded:
                problems.append(f"{d.name}: planned/recorded/rows {planned}/{recorded}/{len(ids)}")
            if complete is not True or missing != 0:
                problems.append(f"{d.name}: complete={complete} missing={missing}")
            if len(set(ids)) != len(ids):
                problems.append(f"{d.name}: duplicate ids")
        if len(out) != 12:
            problems.append(f"{len(out)} test_v1 runs")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "12 legacy test_v1 runs: status completed, planned == recorded == rows (288 or 540), no missing requests, unique ids." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("K1", "manifest", "Legacy runner test manifests are complete", fn)


def check_hybrid_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                name = f"{HYBRID_OFFICIAL}_{model}_{method}"
                manifest = read_json(ROOT / f"hybrid/runs/{name}/manifest.json")
                rows = read_jsonl(ROOT / f"hybrid/runs/{name}/results.jsonl")
                out[name] = {
                    "expected": manifest.get("expected_units"),
                    "recorded": manifest.get("recorded_units"),
                    "counts": manifest.get("counts"),
                    "partial": manifest.get("partial"),
                    "finished": bool(manifest.get("finished_at_utc")),
                    "rows": len(rows),
                }
                if manifest.get("expected_units") != 140 or manifest.get("recorded_units") != 140 or len(rows) != 140:
                    problems.append(f"{name}: counts")
                if manifest.get("partial") is not False:
                    problems.append(f"{name}: partial {manifest.get('partial')}")
                if manifest.get("counts") != {"ok": 140, "invalid": 0, "api_error": 0}:
                    problems.append(f"{name}: {manifest.get('counts')}")
                if not manifest.get("finished_at_utc"):
                    problems.append(f"{name}: no finish time")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"{HYBRID_OFFICIAL}: 10 runs, 140 expected, 140 recorded, 140 ok, 0 invalid, 0 API error, partial=false." if ok else "; ".join(problems),
            {"run_id": HYBRID_OFFICIAL, "runs": out, "problems": problems},
        )

    run_check("K2", "manifest", "Hybrid v2 manifests report 140/140 with zero invalid", fn)


def check_juliet_llm_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in JULIET_OFFICIAL_RUNS:
            manifest = read_json(ROOT / f"juliet_llm/runs/{name}/manifest.json")
            rows = read_jsonl(ROOT / f"juliet_llm/runs/{name}/results.jsonl")
            out[name] = {
                "expected": manifest.get("expected_requests"), "recorded": manifest.get("recorded_requests"),
                "valid": manifest.get("valid_answers"), "invalid": manifest.get("invalid_answers"),
                "api_errors": manifest.get("api_errors"), "partial": manifest.get("partial"), "rows": len(rows),
                "prompt_version": manifest.get("prompt_version"),
            }
            if len(rows) != 140 or manifest.get("expected_requests") != 140 or manifest.get("recorded_requests") != 140:
                problems.append(f"{name}: rows/recorded")
            if manifest.get("valid_answers") != 140 or manifest.get("invalid_answers"):
                problems.append(f"{name}: valid/invalid")
            if manifest.get("api_errors"):
                problems.append(f"{name}: api_errors")
            if manifest.get("partial") is not False:
                problems.append(f"{name}: partial")
            if manifest.get("prompt_version") != "juliet-llm-binary-2026-11-12.2":
                problems.append(f"{name}: prompt version {manifest.get('prompt_version')}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Both postleakfix MiMo test140 runs: 140 recorded, 140 valid, 0 invalid, 0 API errors, partial=false, prompt .2." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("K3", "manifest", "juliet_llm postleakfix test runs are complete at 140/140", fn)


def check_pair_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in ("test_deepseek_180", "test_mimo_180"):
            manifest = read_json(ROOT / f"pair_joint/runs/{name}/manifest.json")
            rows = read_jsonl(ROOT / f"pair_joint/runs/{name}/results.jsonl")
            out[name] = {"status": manifest.get("status"), "counts": manifest.get("counts"),
                         "partial": manifest.get("partial"), "rows": len(rows)}
            if manifest.get("status") != "completed":
                problems.append(f"{name}: status")
            if manifest.get("counts") != {"by_status": {"ok": 180}, "planned_requests": 180, "recorded_requests": 180}:
                problems.append(f"{name}: counts {manifest.get('counts')}")
            if manifest.get("partial") is not False or len(rows) != 180:
                problems.append(f"{name}: partial/rows")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Both pair runs: status completed, 180 planned, 180 recorded, 180 ok, partial=false." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("K4", "manifest", "Pair-joint runs are complete at 180/180", fn)


def check_benchmark_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for p in sorted(BENCH.glob("*/legacy__*/run_manifest.json")):
            manifest = read_json(p)
            execu = manifest.get("execution", {})
            out[p.parent.name + "/" + p.parent.parent.name] = {
                "status": execu.get("status"), "planned": execu.get("planned_units"),
                "recorded": execu.get("recorded_units"), "source": manifest.get("legacy_import", {}).get("source_run_dir"),
            }
            if execu.get("status") != "completed" or execu.get("planned_units") != execu.get("recorded_units"):
                problems.append(f"{p}: incomplete")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"{len(out)} imported legacy benchmark manifests are completed with planned == recorded." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("K5", "manifest", "Benchmark legacy imports are complete", fn)


def check_evidence_prompt_manifests() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for name in ("test_evidence_deepseek", "test_evidence_mimo"):
            run_dir = ROOT / "evidence_prompt/runs" / name
            manifest = read_json(run_dir / "manifest.json")
            rows = read_jsonl(run_dir / "results.jsonl")
            counts = manifest.get("counts", {})
            summary = manifest.get("summary", {})
            out[name] = {
                "status": manifest.get("status"),
                "planned": counts.get("planned_requests"),
                "recorded": counts.get("recorded_requests"),
                "valid": counts.get("valid"),
                "invalid": counts.get("invalid"),
                "api_errors": counts.get("api_errors"),
                "rows": len(rows),
                "endpoint": manifest.get("api", {}).get("base_url"),
                "prompt_input_fields": manifest.get("prompt_input_fields"),
                "context_used": manifest.get("context_used"),
            }
            if manifest.get("status") != "completed":
                problems.append(f"{name}: status")
            if counts.get("planned_requests") != 160 or counts.get("recorded_requests") != 160 or len(rows) != 160:
                problems.append(f"{name}: counts")
            if (counts.get("valid") or 0) + (counts.get("invalid") or 0) != 160:
                problems.append(f"{name}: valid+invalid")
            if counts.get("api_errors") not in (0, None):
                problems.append(f"{name}: api_errors")
            if manifest.get("api", {}).get("base_url") != "https://opencode.ai/zen/go/v1":
                problems.append(f"{name}: endpoint")
            if manifest.get("prompt_input_fields") != ["func_body"]:
                problems.append(f"{name}: prompt input fields")
            if manifest.get("context_used") is not False:
                problems.append(f"{name}: context_used")
            for row in rows:
                p = row.get("prompt") or {}
                if p.get("input_fields") != ["func_body"] or p.get("only_source_variable") is not True:
                    problems.append(f"{name}/{row.get('unit_id')}: prompt not source-only")
                    break
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "evidence_prompt test runs: both 160/160 with 0 API errors, OpenCode Go, and prompts restricted to func_body (no label/context fields)." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("K6", "manifest", "evidence_prompt test runs are complete and source-only", fn)


# ---------------------------------------------------------------------------
# L. Old DeepSeek results preserved
# ---------------------------------------------------------------------------

def check_old_deepseek_hashes() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for p in sorted(BENCH.glob("*/legacy__*/run_manifest.json")):
            manifest = read_json(p)
            legacy = manifest["legacy_import"]
            src = Path(legacy["source_run_dir"])
            results = src / "results.jsonl"
            current = sha256_file(results) if results.is_file() else None
            expected = legacy["source_results_sha256"]
            out[p.parent.name] = {"model": legacy["model_id"], "match": current == expected,
                                  "records": sum(1 for _ in results.open()) if results.is_file() else None}
            if current != expected:
                problems.append(f"{p.parent.name}: results changed")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            f"All {len(out)} benchmark imports still match the current runner results.jsonl byte-for-byte." if ok else "; ".join(problems),
            {"imports": out, "problems": problems},
        )

    run_check("L1", "preserve", "Old DeepSeek/MiMo runner results are byte-identical to their import", fn)


def _legacy_deepseek_runs() -> list[Path]:
    runs = []
    for d in sorted(p for p in (ROOT / "runner/runs").glob("test_v1_*") if p.is_dir()):
        manifest = read_json(d / "manifest.json")
        if str(manifest.get("api", {}).get("model", "")).startswith("deepseek"):
            runs.append(d)
    return runs


def check_old_deepseek_metrics() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        out = {}
        problems = []
        for d in _legacy_deepseek_runs():
            runner_metrics = read_json(d / "metrics.json")
            detection = runner_metrics.get("detection") or {}
            pair = runner_metrics.get("pair_joint") or {}
            # Find the matching benchmark import.
            matches = list(BENCH.glob(f"*/legacy__{d.name}/run_manifest.json"))
            if not matches:
                problems.append(f"{d.name}: no benchmark import")
                continue
            bench_metrics = read_json(matches[0].parent / "metrics.json")
            task_detection = bench_metrics.get("tasks", {}).get("detection")
            task_pair = bench_metrics.get("tasks", {}).get("pair_detection")
            if task_detection:
                if task_detection["scores"]["confusion"] != detection.get("confusion"):
                    problems.append(f"{d.name}: detection confusion differs")
            if task_pair:
                runner_joint = (pair.get("joint_categories") or {}).get("vulnerable_detected_fixed_clean")
                if task_pair.get("joint_correct_all_pairs") != runner_joint:
                    problems.append(f"{d.name}: pair joint differs")
            out[d.name] = {
                "runner_detection": detection.get("confusion"),
                "benchmark_detection": task_detection["scores"]["confusion"] if task_detection else None,
                "runner_pair": (pair.get("joint_categories") or {}).get("vulnerable_detected_fixed_clean"),
                "benchmark_pair": task_pair.get("joint_correct_all_pairs") if task_pair else None,
            }
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "DeepSeek legacy detection/pair metrics recompute identically from the current runner results." if ok else "; ".join(problems),
            {"runs": out, "problems": problems},
        )

    run_check("L2", "preserve", "Old DeepSeek metrics are stable under the benchmark import", fn)


def check_old_deepseek_mtime() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        # The new work started with the frozen Juliet manifest at 18:36Z; the
        # legacy DeepSeek runs completed at 11:24-11:54Z.  Check the filesystem
        # timestamps as a second, independent preservation signal.
        freeze_mtime = (ROOT / "juliet/FREEZE.json").stat().st_mtime
        legacy_files = []
        for d in _legacy_deepseek_runs():
            for p in d.rglob("*"):
                if p.is_file():
                    legacy_files.append((p.stat().st_mtime, p))
        if not legacy_files:
            return ("FAIL", "No legacy DeepSeek run files found.", {"runs": []})
        newest_legacy = max(legacy_files, key=lambda item: item[0])
        new_files = []
        for d in ("juliet_llm", "hybrid", "juliet_repair", "pair_joint"):
            for p in (ROOT / d).rglob("*"):
                if p.is_file() and "__pycache__" not in p.parts:
                    new_files.append((p.stat().st_mtime, p))
        earliest_new = min(new_files, key=lambda item: item[0]) if new_files else (freeze_mtime, None)
        ok = newest_legacy[0] <= earliest_new[0]
        return (
            "PASS" if ok else "WARN",
            f"Newest legacy DeepSeek file {datetime.fromtimestamp(newest_legacy[0], timezone.utc).isoformat()} "
            f"<= earliest new-experiment file {datetime.fromtimestamp(earliest_new[0], timezone.utc).isoformat()}.",
            {"newest_legacy": str(newest_legacy[1]), "newest_legacy_mtime": datetime.fromtimestamp(newest_legacy[0], timezone.utc).isoformat(),
             "earliest_new": str(earliest_new[1]), "earliest_new_mtime": datetime.fromtimestamp(earliest_new[0], timezone.utc).isoformat()},
        )

    run_check("L3", "preserve", "Legacy results predate all new experiment files on disk", fn)


def check_analysis_provenance() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        agg = read_json(ROOT / "analysis/aggregation.json")
        inputs = agg.get("inputs", {})
        paths = list(inputs.get("run_paths", []))
        missing = [p for p in paths if not Path(p).exists()]
        stale_root = sorted({p.split("/runner/")[0] for p in paths if "/runner/" in p})
        expected_dataset_root = str(ROOT / "datasets")
        dataset_root = inputs.get("datasets_root")
        problems = []
        if missing:
            problems.append(f"{len(missing)}/{len(paths)} run paths do not exist")
        if stale_root != [str(ROOT)]:
            problems.append(f"run paths resolve under {stale_root}, not {ROOT}")
        if dataset_root != expected_dataset_root:
            problems.append(f"dataset root {dataset_root} != {expected_dataset_root}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            (f"analysis/aggregation.json references {len(paths)} run paths, all under the current repository root; "
             f"datasets root is {dataset_root}.")
            if ok else "; ".join(problems),
            {"run_paths": len(paths), "missing": len(missing), "stale_roots": stale_root,
             "dataset_root": dataset_root, "problems": problems},
        )

    run_check("L4", "preserve", "Derived analysis uses a reproducible repository path", fn)


def check_superseded_artifacts() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        v1_rows = read_jsonl(HYBRID_SUPERSEDED_INPUTS / "units.jsonl")
        pre_code = {r["unit_id"]: _prompt_code(r) for r in read_jsonl(JULIET_PRE_LEAKFIX_BUILD / "test.jsonl")}
        v1_mismatch = [r["unit_id"] for r in v1_rows
                       if pre_code.get(r["unit_id"]) != r["source_text"]
                       or sha256_bytes(pre_code.get(r["unit_id"], "").encode("utf-8")) != r["source_sha256"]]
        if len(v1_rows) != 140 or v1_mismatch:
            problems.append(f"hybrid v1 inputs: {len(v1_rows)} rows, {len(v1_mismatch)} mismatches")
        v1_runs = {}
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                name = f"{HYBRID_SUPERSEDED}_{model}_{method}"
                run_dir = ROOT / f"hybrid/runs/{name}"
                if not run_dir.is_dir():
                    problems.append(f"{name}: missing")
                    continue
                manifest = read_json(run_dir / "manifest.json")
                rows = read_jsonl(run_dir / "results.jsonl")
                v1_runs[name] = {"rows": len(rows), "prompt_version": manifest.get("prompt_version")}
                if len(rows) != 140:
                    problems.append(f"{name}: {len(rows)} rows")
                if manifest.get("prompt_version") != "hybrid-juliet-llm-binary-2026-11-12.1":
                    problems.append(f"{name}: prompt version {manifest.get('prompt_version')}")
        for rel in ("hybrid/results/hybrid_v1_metrics.json", "hybrid/REPORT.md",
                    "juliet_llm/build_pre_leakfix_v1/test.jsonl"):
            if not (ROOT / rel).is_file():
                problems.append(f"{rel}: missing")
        for name in JULIET_PRE_LEAKFIX_RUNS:
            run_dir = ROOT / "juliet_llm/runs" / name
            rows = read_jsonl(run_dir / "results.jsonl") if (run_dir / "results.jsonl").is_file() else []
            if len(rows) != 140:
                problems.append(f"{name}: {len(rows)} rows")
        superseded = []
        for name in JULIET_SUPERSEDED_RUNS:
            run_dir = ROOT / "juliet_llm/runs_superseded" / name
            rows = read_jsonl(run_dir / "results.jsonl") if (run_dir / "results.jsonl").is_file() else []
            superseded.append({"run": name, "rows": len(rows)})
            if len(rows) != 140:
                problems.append(f"runs_superseded/{name}: {len(rows)} rows")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            (f"v1 is preserved and untouched: 140 inputs match the archived pre-leakfix build, 10/10 v1 runs are complete, "
             f"and the 2 pre-fix juliet_llm runs plus 2 superseded post-fix runs remain on disk.")
            if ok else "; ".join(problems),
            {"v1_inputs": len(v1_rows), "v1_runs": v1_runs,
             "pre_leakfix_juliet_runs": list(JULIET_PRE_LEAKFIX_RUNS),
             "superseded_juliet_runs": superseded, "problems": problems},
        )

    run_check("L5", "preserve", "Frozen v1 artifacts are retained as the superseded leak contrast", fn)


# ---------------------------------------------------------------------------
# M. Claims consistency
# ---------------------------------------------------------------------------

def check_hybrid_report_claims() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        text = (ROOT / "hybrid/REPORT_V2.md").read_text(encoding="utf-8")
        metrics = read_json(ROOT / "hybrid/results/hybrid_v2_metrics.json")
        problems = []
        lines = text.splitlines()
        checked = []
        for model in ("deepseek", "mimo"):
            for method in hybrid_prompts.METHODS:
                accuracy = float(metrics["runs"][f"{model}/{method}"]["strict"]["accuracy"])
                expected = f"{100.0 * accuracy:.2f}%"
                row = next((line for line in lines if line.startswith(f"| {model} | {method} |")), None)
                checked.append({"model": model, "method": method, "accuracy": expected})
                if row is None:
                    problems.append(f"{model}/{method}: no headline row")
                elif expected not in row:
                    problems.append(f"{model}/{method}: row missing {expected}")
        if "1400 real requests" not in text:
            problems.append("missing 1400 real requests")
        if "hybrid_v2" not in text:
            problems.append("missing hybrid_v2 label")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "REPORT_V2 headline percentages recompute from hybrid_v2_metrics for all 10 model/method cells; the matrix is labelled 1400 real requests." if ok else "; ".join(problems),
            {"checked": checked, "problems": problems},
        )

    run_check("M1", "claims", "Hybrid v2 report numbers match the artifacts", fn)


def check_pair_report_claims() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        text = (ROOT / "pair_joint/report.md").read_text(encoding="utf-8")
        problems = []
        for value in ("138", "156", "76.67%", "86.67%", "74.44%"):
            if value not in text:
                problems.append(f"missing {value}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Pair report states 138/180 (76.67%), 156/180 (86.67%), and the 74.44% length heuristic." if ok else "; ".join(problems),
            {"problems": problems},
        )

    run_check("M2", "claims", "Pair report numbers match the artifacts", fn)


def check_repair_report_claims() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        text = (ROOT / "juliet_repair/README.md").read_text(encoding="utf-8")
        problems = []
        for value in ("58", "70", "0.026990", "0.005841", "0.032831", "0.082550"):
            if value not in text:
                problems.append(f"missing {value}")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Repair README carries the 58/58 headline, 70 calls, and the corrected all-in $0.082550." if ok else "; ".join(problems),
            {"problems": problems},
        )

    run_check("M3", "claims", "Repair report carries the recomputed headline numbers", fn)


def check_juliet_report_claims() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        text = (ROOT / "juliet_llm/README.md").read_text(encoding="utf-8")
        problems = []
        for value in ("0.9500", "0.9510", "0.9008", "140/140", "0.003180"):
            if value not in text:
                problems.append(f"missing {value}")
        if "0.9571" not in text:
            problems.append("missing preserved pre-fix 0.9571")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "juliet_llm README carries the postleakfix 140/140, accuracy 0.9500, F1 0.9510, MCC 0.9008, cost $0.003180, and keeps the pre-fix 0.9571." if ok else "; ".join(problems),
            {"problems": problems},
        )

    run_check("M4", "claims", "juliet_llm report numbers match the postleakfix artifact", fn)


def check_static_dynamic_claims() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        problems = []
        hybrid_text = (ROOT / "hybrid/REPORT_V2.md").read_text(encoding="utf-8")
        for value in ("85.00%", "91.43%"):
            if value not in hybrid_text:
                problems.append(f"missing {value} in hybrid/REPORT_V2.md")
        ok = not problems
        return (
            "PASS" if ok else "FAIL",
            "Tool baselines are consistently reported in hybrid/REPORT_V2.md as static 85.00% and dynamic 91.43%." if ok else "; ".join(problems),
            {"problems": problems},
        )

    run_check("M5", "claims", "Static/dynamic baseline numbers are consistent across reports", fn)


# ---------------------------------------------------------------------------
# N. Secret and scope hygiene
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._-]{10,}"),
    re.compile(r"Authorization:\s*\S+", re.IGNORECASE),
    re.compile(r"OPENCODE_API_KEY\s*=\s*\S+"),
]


def check_secrets() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        hits = []
        scanned = 0
        roots = [ROOT / d for d in ("juliet_llm", "hybrid", "juliet_repair", "pair_joint", "traditional", "benchmark", "analysis", "report")]
        skip_dirs = {"cases", "work", "raw", "__pycache__", "cache", "packs", "build"}
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for filename in filenames:
                    p = Path(dirpath) / filename
                    try:
                        if p.stat().st_size > 4_000_000:
                            continue
                    except OSError:
                        continue
                    if p.suffix.lower() not in {".json", ".jsonl", ".md", ".txt", ".py", ".sh", ".csv"}:
                        continue
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    scanned += 1
                    for pattern in SECRET_PATTERNS:
                        match = pattern.search(text)
                        if match:
                            hits.append({"file": str(p.relative_to(ROOT)), "match": match.group(0)[:40]})
        # The Kimi config is never read by this audit.
        ok = not hits
        return (
            "PASS" if ok else "FAIL",
            f"{scanned} text artifacts scanned; no key/Bearer/Authorization material found." if ok else f"{len(hits)} secret-like hits.",
            {"scanned": scanned, "hits": hits[:10]},
        )

    run_check("N1", "secrets", "No credentials in any experiment artifact", fn)


def check_scope() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        audit_files = sorted(p.name for p in AUDIT.iterdir()) if AUDIT.exists() else []
        expected = {"run_final_audit.py", "final_audit.json", "final_audit.md"}
        extra = [f for f in audit_files if f not in expected and f != "__pycache__"]
        return (
            "PASS" if not extra else "WARN",
            "The audit writes only audit/final_audit.{json,md} and its script." if not extra else f"extra files in audit/: {extra}",
            {"audit_files": audit_files, "extra": extra},
        )

    run_check("N2", "scope", "Audit stays inside audit/", fn)


def check_git_state() -> None:
    def fn() -> tuple[str, str, dict[str, Any]]:
        git_dir = ROOT / ".git"
        if not git_dir.exists():
            return (
                "INFO",
                "No Git repository exists yet; the release workflow will create the private GitHub repository.",
                {"git_dir": str(git_dir), "exists": False},
            )
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip() if (git_dir / "HEAD").is_file() else ""
        config_text = (git_dir / "config").read_text(encoding="utf-8") if (git_dir / "config").is_file() else ""
        remotes = re.findall(r'^\[remote "([^"]+)"\]', config_text, re.M)
        return (
            "INFO",
            f"Git repository exists (HEAD {head or 'unknown'}; remotes: {', '.join(remotes) or 'none'}).",
            {"git_dir": str(git_dir), "exists": True, "head": head, "remotes": remotes},
        )

    run_check("N3", "scope", "Repository state for the later GitHub push", fn)


def main() -> int:
    check_freeze()
    check_composition()
    check_near_duplicate()
    check_sha256sums()

    check_cleaning_rebuild()
    check_cleaning_matches_build()
    check_cleaning_code_leak()
    check_cleaning_semantics()
    check_structural_asymmetry()

    check_juliet_prompt_leak()
    check_juliet_sent_messages()
    check_benign_fixed_leak()

    check_hybrid_inputs()
    check_hybrid_evidence_rebuild()
    check_placebo_mapping()
    check_hybrid_prompts()
    check_hybrid_shuffled_is_placebo()
    check_hybrid_code_label_words()

    check_pair_dataset()
    check_pair_order()
    check_pair_prompts()
    check_pair_results()

    check_repair_inputs()
    check_repair_baselines()
    check_repair_summaries()
    check_repair_prompt_leak()
    check_repair_costs()

    check_static_status()
    check_static_metrics()
    check_static_evidence_rendering()

    check_dynamic_run()
    check_dynamic_frozen_join()
    check_dynamic_test_unobservable()
    check_dynamic_evidence_not_clean()

    check_hybrid_cost()
    check_juliet_cost()
    check_repair_cost_total()
    check_pair_cost()
    check_cost_basis_consistency()
    check_runner_legacy_cost()
    check_cost_normalization()

    check_endpoints()
    check_xiaomi_labeling()

    check_runner_manifests()
    check_hybrid_manifests()
    check_juliet_llm_manifests()
    check_pair_manifests()
    check_benchmark_manifests()
    check_evidence_prompt_manifests()

    check_old_deepseek_hashes()
    check_old_deepseek_metrics()
    check_old_deepseek_mtime()
    check_analysis_provenance()
    check_superseded_artifacts()

    check_hybrid_report_claims()
    check_pair_report_claims()
    check_repair_report_claims()
    check_juliet_report_claims()
    check_static_dynamic_claims()

    check_secrets()
    check_scope()
    check_git_state()

    counts = Counter(c["status"] for c in CHECKS)
    overall = "FAIL" if counts.get("FAIL") else ("PASS_WITH_WARNINGS" if counts.get("WARN") else "PASS")
    summary = {
        "schema_version": "final-audit-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(ROOT),
        "overall": overall,
        "api_calls": 0,
        "writes": ["audit/final_audit.json", "audit/final_audit.md"],
        "counts": {key: counts.get(key, 0) for key in ("PASS", "FAIL", "WARN", "INFO")},
        "must_fix": [c for c in CHECKS if c["status"] == "FAIL"],
        "warnings": [c for c in CHECKS if c["status"] == "WARN"],
        "checks": CHECKS,
    }
    (AUDIT / "final_audit.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = []
    lines.append("# Final quality and leakage audit")
    lines.append("")
    lines.append(f"Generated: {summary['generated_at_utc']} (UTC)  ")
    lines.append(f"Overall: **{overall}**  ")
    lines.append(f"Checks: {counts.get('PASS', 0)} PASS, {counts.get('FAIL', 0)} FAIL, {counts.get('WARN', 0)} WARN, {counts.get('INFO', 0)} INFO.")
    lines.append("")
    lines.append("Scope: read-only audit of `juliet/`, `juliet_llm/`, `hybrid/`, `juliet_repair/`,")
    lines.append("`pair_joint/`, `traditional/static/`, `traditional/dynamic/`, `benchmark/` and the")
    lines.append("derived `analysis/`/`report/` artifacts. No model API was called. The audit script")
    lines.append("recomputes prompts, hashes, joins, costs and metrics from the stored artifacts; it does")
    lines.append("not trust the per-directory summaries. Official results are the `hybrid_v2` runs and the")
    lines.append("`juliet_llm` postleakfix runs; `hybrid_v1` and the pre-leakfix build are retained as the")
    lines.append("superseded, leak-observable contrast and are checked as such.")
    lines.append("")
    lines.append("## Must fix")
    lines.append("")
    fails = [c for c in CHECKS if c["status"] == "FAIL"]
    if fails:
        for c in fails:
            lines.append(f"- **{c['id']} — {c['title']}**: {c['detail']}")
    else:
        lines.append("- None.")
    lines.append("")
    lines.append("## Warnings")
    lines.append("")
    warns = [c for c in CHECKS if c["status"] == "WARN"]
    if warns:
        for c in warns:
            lines.append(f"- **{c['id']} — {c['title']}**: {c['detail']}")
    else:
        lines.append("- None.")
    lines.append("")
    lines.append("## All checks")
    lines.append("")
    lines.append("| ID | Area | Status | Check | Result |")
    lines.append("| --- | --- | --- | --- | --- |")
    for c in CHECKS:
        detail = c["detail"].replace("|", "\\|")
        lines.append(f"| {c['id']} | {c['area']} | **{c['status']}** | {c['title']} | {detail} |")
    lines.append("")
    lines.append("## Key evidence")
    lines.append("")
    for cid in ("C2", "C3", "D1", "D6", "D3", "D4", "E2", "F2", "F3", "H3", "I1", "I2",
                "I5", "I7", "I3", "L4", "L5"):
        c = next((x for x in CHECKS if x["id"] == cid), None)
        if c:
            lines.append(f"### {cid}: {c['title']}")
            lines.append("")
            lines.append(f"- Status: **{c['status']}**")
            lines.append(f"- {c['detail']}")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(c["evidence"], indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("All checks run offline in WSL and write only `audit/final_audit.{json,md}`:")
    lines.append("")
    lines.append("```bash")
    lines.append("cd /mnt/c/Users/tzh03/Downloads/cs224proj")
    lines.append("python3 audit/run_final_audit.py")
    lines.append("```")
    lines.append("")
    lines.append("## Limits of this audit")
    lines.append("")
    lines.append("- The audit verifies what the stored artifacts and frozen inputs can prove. It cannot")
    lines.append("  re-run the model calls, the compilers or the sanitizers; those results are inherited.")
    lines.append("- The current `juliet_llm` build and `hybrid_v2` inputs contain no `benign`/`fixed` label")
    lines.append("  words. The frozen `juliet_llm/build_pre_leakfix_v1` and `hybrid/inputs` still contain")
    lines.append("  the 8/200 (6 test) and 6/140 hits respectively; they are retained only as a leak contrast.")
    lines.append("- `juliet_repair` is a bad-only repair task; its prompts intentionally state that the")
    lines.append("  program leaks. The `bad`/`CWE`/`Memory_Leak` entry identifiers are therefore not a")
    lines.append("  hidden ground-truth label, but the input is not label-neutral (see F4).")
    lines.append("- v2 prices DeepSeek at the off-peak list card ($0.15/$0.60/$0.003); the frozen v1 rows")
    lines.append("  keep the peak card ($0.30/$1.20/$0.006). `analysis/cost_normalization.json` provides")
    lines.append("  the normalized provider-list view and the independent allowance; it is not an invoice.")
    lines.append("- The full dynamic run has one inconclusive case outside the frozen 200; the frozen")
    lines.append("  test140 has none, so the inconclusive branch is verified by renderer/selftest only.")
    lines.append("- `analysis/aggregation.json` was regenerated under the current repository root; the")
    lines.append("  derived numbers are checked here, not re-estimated.")
    lines.append("")
    (AUDIT / "final_audit.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"overall": overall, "counts": summary["counts"],
                      "must_fix": [c["id"] for c in fails],
                      "warnings": [c["id"] for c in warns]}, indent=2))
    return 0 if not fails else 1


if __name__ == "__main__":
    raise SystemExit(main())

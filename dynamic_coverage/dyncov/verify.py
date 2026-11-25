"""Integrity checks for a coverage run.

The checks are deliberately structural: counts, per-mode totals, gcov's own
line totals, archived-verdict agreement, and the selftest.  A failure is
reported as a failure; no metric is "fixed" to make the run pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config
from .link import crosscheck, load_archived
from .units import read_jsonl, sha256_file


def run_verify(run_dir: Path) -> dict:
    problems: list[str] = []
    notes: list[str] = []
    records = read_jsonl(run_dir / "results_units.jsonl")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    if len(records) != 140:
        problems.append(f"expected 140 records, found {len(records)}")
    labels = {
        "bad": sum(1 for record in records if record.get("label") == "bad"),
        "good": sum(1 for record in records if record.get("label") == "good"),
    }
    if labels != {"bad": 70, "good": 70}:
        problems.append(f"expected 70/70 labels, found {labels}")
    if len({record.get("group_id") for record in records}) != 70:
        problems.append("expected 70 distinct groups")

    compile_errors = [
        record["unit_id"]
        for record in records
        if record.get("coverage_tier") == "compile_error"
        or str(record.get("failure_class", "")).startswith("compile_error")
    ]
    notes.append(f"compile_error units: {len(compile_errors)}")

    for record in records:
        if record.get("coverage_tier") == "compile_error":
            continue
        if record.get("decision") not in ("leak", "clean"):
            problems.append(f"{record['unit_id']}: decision {record.get('decision')!r}")
        expected_y = 1 if record.get("decision") == "leak" else 0
        if record.get("y_pred") != expected_y:
            problems.append(f"{record['unit_id']}: y_pred {record.get('y_pred')} != {expected_y}")
        expected_class = (
            "leak"
            if record.get("decision") == "leak"
            else (
                "covered_clean"
                if record.get("coverage_tier_effective") in ("line_complete", "branch_complete")
                and record.get("entry_executed")
                else "uncovered"
            )
        )
        if record.get("coverage_class") != expected_class:
            problems.append(
                f"{record['unit_id']}: coverage_class {record.get('coverage_class')} "
                f"!= {expected_class}"
            )
        modes = record.get("modes") or {}
        for mode in ("default", "nogobal"):
            if mode not in modes:
                problems.append(f"{record['unit_id']}: missing mode {mode}")
            elif not modes[mode].get("coverage"):
                problems.append(f"{record['unit_id']}: {mode} has no coverage summary")
            elif modes[mode].get("coverage_tier") == "coverage_error":
                problems.append(f"{record['unit_id']}: {mode} coverage_error")
        union = record.get("coverage_union") or {}
        if not union:
            problems.append(f"{record['unit_id']}: missing coverage_union")
        elif record.get("coverage_tier") == "coverage_error":
            problems.append(f"{record['unit_id']}: union coverage_error")
        if not record.get("entry_executed"):
            problems.append(f"{record['unit_id']}: entry not executed")

        totals = {}
        for mode, entry in modes.items():
            coverage = entry.get("coverage") or {}
            if coverage.get("lines_total") is not None:
                totals[mode] = (
                    coverage.get("lines_total"),
                    coverage.get("branches_total"),
                )
        if totals:
            distinct = set(totals.values())
            if len(distinct) != 1:
                problems.append(f"{record['unit_id']}: mode totals differ {totals}")
            elif union and (union.get("lines_total"), union.get("branches_total")) not in distinct:
                problems.append(
                    f"{record['unit_id']}: union totals {union.get('lines_total')}/"
                    f"{union.get('branches_total')} not in {sorted(distinct)}"
                )

        for mode, entry in modes.items():
            for check in entry.get("gcov_checks") or []:
                source = Path(check.get("source") or "").name
                if check.get("returncode") != 0:
                    problems.append(
                        f"{record['unit_id']}:{mode}: gcov failed for {source} "
                        f"(rc={check.get('returncode')})"
                    )
                    continue
                if check.get("lines_total") is None:
                    notes.append(
                        f"{record['unit_id']}:{mode}: {source} has no executable lines"
                    )
                    continue
                parsed_total = check.get("lines_total_parsed")
                if parsed_total is None:
                    problems.append(
                        f"{record['unit_id']}:{mode}: no parsed total for {source}"
                    )
                    continue
                if parsed_total != check.get("lines_total"):
                    problems.append(
                        f"{record['unit_id']}:{mode}: {source} gcov LF={check.get('lines_total')} "
                        f"but parsed LF={parsed_total}"
                    )

    archived = load_archived()
    cross = crosscheck(records, archived)
    if cross.get("default_agree") != len(records):
        problems.append(
            f"default verdict agreement {cross.get('default_agree')}/{len(records)}"
        )
    if cross.get("union_agree") != len(records):
        problems.append(
            f"union verdict agreement {cross.get('union_agree')}/{len(records)}"
        )

    default_bad = sum(
        1 for record in records
        if record.get("label") == "bad"
        and ((record.get("modes") or {}).get("default") or {}).get("leak_attributed")
    )
    default_good = sum(
        1 for record in records
        if record.get("label") == "good"
        and ((record.get("modes") or {}).get("default") or {}).get("leak_attributed")
    )
    if default_bad != 58:
        problems.append(f"default bad leaks {default_bad} != 58")
    if default_good != 0:
        problems.append(f"default good leaks {default_good} != 0")
    for mode, expected_bad in (("realloc_fail", 7), ("nogobal", 63)):
        bad = sum(
            1 for record in records
            if record.get("label") == "bad"
            and ((record.get("modes") or {}).get(mode) or {}).get("applicable")
            and ((record.get("modes") or {}).get(mode) or {}).get("leak_attributed")
        )
        good = sum(
            1 for record in records
            if record.get("label") == "good"
            and ((record.get("modes") or {}).get(mode) or {}).get("applicable")
            and ((record.get("modes") or {}).get(mode) or {}).get("leak_attributed")
        )
        if bad != expected_bad:
            problems.append(f"{mode} bad leaks {bad} != {expected_bad}")
        if good != 0:
            problems.append(f"{mode} good leaks {good} != 0")
    applicable = sum(
        1 for record in records
        if ((record.get("modes") or {}).get("realloc_fail") or {}).get("applicable")
    )
    if applicable != 14:
        problems.append(f"realloc_fail applicable units {applicable} != 14")

    union_bad = sum(
        1 for record in records if record.get("label") == "bad" and record.get("decision") == "leak"
    )
    union_good = sum(
        1 for record in records if record.get("label") == "good" and record.get("decision") == "leak"
    )
    if union_bad != 70:
        problems.append(f"union TP {union_bad} != 70")
    if union_good != 0:
        problems.append(f"union FP {union_good} != 0")

    selftest_path = config.ROOT / "selftest/selftest.json"
    selftest = None
    if selftest_path.exists():
        selftest = json.loads(selftest_path.read_text(encoding="utf-8"))
        if selftest.get("status") != "PASS":
            problems.append(f"selftest {selftest.get('status')}")
    else:
        problems.append("selftest/selftest.json missing")

    if manifest.get("results_units_sha256"):
        actual = sha256_file(run_dir / "results_units.jsonl")
        if actual != manifest["results_units_sha256"]:
            problems.append("results_units.jsonl hash mismatch")
    if manifest.get("results_raw_sha256"):
        actual = sha256_file(run_dir / "results_raw.jsonl")
        if actual != manifest["results_raw_sha256"]:
            problems.append("results_raw.jsonl hash mismatch")

    result = {
        "status": "PASS" if not problems else "FAIL",
        "problems": problems,
        "notes": notes,
        "run_id": run_dir.name,
        "units": len(records),
        "labels": labels,
        "compile_error": len(compile_errors),
        "crosscheck": {
            "default_agree": cross.get("default_agree"),
            "union_agree": cross.get("union_agree"),
            "archived_units": cross.get("archived_units"),
        },
        "counts": {
            "default_bad_leaks": default_bad,
            "default_good_leaks": default_good,
            "union_bad_leaks": union_bad,
            "union_good_leaks": union_good,
            "realloc_fail_applicable": applicable,
        },
        "selftest": selftest.get("status") if selftest else None,
    }
    (run_dir / "verify.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result

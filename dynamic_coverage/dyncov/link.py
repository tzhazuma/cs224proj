"""Join coverage records to the archived dynamic and original ASan verdicts.

Two independent archives are read:

* ``dynamic_enhanced/runs/test140_enhanced_v3`` -- the default/enhanced
  verdicts that the paper uses.  The coverage run must reproduce these (same
  compiler, same env, same probe); the join is what makes a coverage tier
  attach to a real verdict instead of to a re-derived label.
* ``traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind`` -- the original
  ASan/Valgrind run, matched by (sources, defines) exactly as
  ``dynamic_enhanced`` does.  Used to label the original path.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config
from .units import read_jsonl, sha256_file

OLD_RUN = config.PROJECT / "traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind"


def _normalize_source(path: str) -> str:
    path = path.replace("\\", "/")
    marker = "CWE401_Memory_Leak/"
    if marker in path:
        return path.split(marker, 1)[1]
    return Path(path).name


def source_key(sources: list[str], defines: list[str]) -> tuple:
    return (
        tuple(sorted(_normalize_source(source) for source in sources)),
        tuple(sorted(defines)),
    )


def load_old_dynamic() -> dict:
    if not OLD_RUN.exists():
        return {"available": False}
    cases = read_jsonl(OLD_RUN / "cases.jsonl")
    results = {row["case_id"]: row for row in read_jsonl(OLD_RUN / "results.jsonl")}
    by_key = {}
    for case in cases:
        result = results.get(case["case_id"])
        if result is None:
            continue
        by_key[source_key(case["sources"], case["defines"])] = result
    return {
        "available": True,
        "path": str(OLD_RUN.relative_to(config.PROJECT)),
        "cases": len(cases),
        "results": len(results),
        "by_key": by_key,
        "cases_sha256": sha256_file(OLD_RUN / "cases.jsonl"),
        "results_sha256": sha256_file(OLD_RUN / "results.jsonl"),
    }


def _detector_status(result: dict, name: str) -> dict:
    entry = (result.get("detectors") or {}).get(name) or {}
    return {
        "status": entry.get("status"),
        "leak_detected": entry.get("leak_detected"),
        "available": entry.get("available"),
    }


def load_archived() -> dict:
    if not config.ARCHIVED_UNITS.exists():
        return {"available": False}
    units = {row["unit_id"]: row for row in read_jsonl(config.ARCHIVED_UNITS)}
    raw: dict[tuple[str, str], dict] = {}
    for row in read_jsonl(config.ARCHIVED_RAW):
        raw[(row["unit_id"], row["mode"])] = row
    metrics = {}
    if config.ARCHIVED_METRICS.exists():
        metrics = json.loads(config.ARCHIVED_METRICS.read_text(encoding="utf-8"))
    old = load_old_dynamic()
    by_id = {}
    old_matches = 0
    for unit_id, row in units.items():
        key = source_key(row["sources"], row["defines"])
        old_result = old.get("by_key", {}).get(key) if old.get("available") else None
        if old_result is not None:
            old_matches += 1
        default_mode = (row.get("modes") or {}).get("default") or {}
        by_id[unit_id] = {
            "archived_decision": row.get("decision"),
            "archived_y_pred": row.get("y_pred"),
            "archived_default_leak": bool(default_mode.get("leak_attributed")),
            "archived_default_decision": default_mode.get("decision"),
            "archived_primary_evidence": row.get("primary_evidence"),
            "archived_evidence_modes": row.get("evidence_modes") or [],
            "archived_default_leak_summary": (raw.get((unit_id, "default")) or {}).get("leak_summary"),
            "old_asan": _detector_status(old_result, "asan") if old_result else None,
            "old_valgrind": _detector_status(old_result, "valgrind") if old_result else None,
        }
    return {
        "available": True,
        "path": str(config.ARCHIVED_RUN.relative_to(config.PROJECT)),
        "units": len(units),
        "raw_rows": len(raw),
        "units_sha256": sha256_file(config.ARCHIVED_UNITS),
        "raw_sha256": sha256_file(config.ARCHIVED_RAW),
        "old_dynamic": {
            "available": old.get("available", False),
            "path": old.get("path"),
            "cases": old.get("cases"),
            "matched_units": old_matches,
            "agreement": (metrics.get("old_comparison") or {}).get("agreements"),
        },
        "by_unit": by_id,
    }


def crosscheck(records: list[dict], archived: dict) -> dict:
    """Compare the coverage-run verdicts with the archived verdicts."""
    if not archived.get("available"):
        return {"available": False}
    by_unit = archived["by_unit"]
    default_agree = default_other = union_agree = union_other = 0
    default_mismatch = []
    union_mismatch = []
    for record in records:
        archived_row = by_unit.get(record["unit_id"])
        if archived_row is None:
            continue
        coverage_default = (record.get("modes") or {}).get("default") or {}
        coverage_default_verdict = (
            "leak" if coverage_default.get("leak_attributed") else coverage_default.get("decision")
        )
        archived_default_verdict = "leak" if archived_row["archived_default_leak"] else "clean"
        if coverage_default_verdict == archived_default_verdict:
            default_agree += 1
        else:
            default_other += 1
            default_mismatch.append(
                {
                    "unit_id": record["unit_id"],
                    "coverage": coverage_default_verdict,
                    "archived": archived_default_verdict,
                }
            )
        coverage_union = record.get("decision")
        archived_union = archived_row["archived_decision"]
        if coverage_union == archived_union:
            union_agree += 1
        else:
            union_other += 1
            union_mismatch.append(
                {
                    "unit_id": record["unit_id"],
                    "coverage": coverage_union,
                    "archived": archived_union,
                }
            )
    return {
        "available": True,
        "default_agree": default_agree,
        "default_other": default_other,
        "default_mismatch": default_mismatch,
        "union_agree": union_agree,
        "union_other": union_other,
        "union_mismatch": union_mismatch,
        "archived_units": len(by_unit),
        "coverage_units": len(records),
    }

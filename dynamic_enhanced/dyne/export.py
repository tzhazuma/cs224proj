"""Export the enhanced run in the shape `hybrid/build_inputs.py` consumes.

The hybrid loader (`load_dynamic`) needs `cases.jsonl` + `results.jsonl` with
the same source/define key as the frozen subset and a `detectors` object with
`status`/`evidence`.  The files written here are drop-in for that loader; the
only required change on the hybrid side is pointing `DYNAMIC_RUN` at this
directory.  Valgrind is not re-run in this pass (it is not installed in the
current WSL image), so the `valgrind` detector is explicitly `unavailable`;
the archived Valgrind result is compared in `metrics.json`, not substituted
here.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config
from .units import sha256_file


def _mode_line(mode: str, entry: dict) -> str:
    if not entry.get("applicable"):
        return f"{mode}: not applicable (injection never reached a non-NULL realloc)"
    if entry.get("leak_attributed"):
        site = (entry.get("attributed_blocks") or [{}])[0].get("deciding_frame") or {}
        location = Path(site.get("file") or "unknown").name
        detail = (
            f"{mode}: attributed leak ({entry.get('attributed_bytes', 0)} byte(s)); "
            f"allocation site {location}:{site.get('line')}"
        )
        injected_at = (entry.get("injection") or {}).get("injected_at_call")
        if injected_at:
            detail += f"; injected NULL at realloc call {injected_at}"
        return detail
    if entry.get("leak_raw"):
        return f"{mode}: only non-unit (runtime/support) leaks; not attributed to the unit"
    return f"{mode}: no leak observed"


def evidence_text(record: dict) -> str:
    lines = [
        "Enhanced dynamic-analysis evidence for this code unit.",
        "Modes: default LSan root set; realloc-failure injection; global roots disabled.",
        "The outcome is an observation on the executed path, not a proof of absence.",
    ]
    for mode in config.MODES:
        lines.append("- " + _mode_line(mode, (record.get("modes") or {}).get(mode, {})))
    if record.get("y_pred") == 1:
        lines.append(
            "Overall dynamic outcome: leak detected in at least one applicable mode "
            f"(primary evidence: {record.get('primary_evidence')})."
        )
    elif record.get("y_pred") == 0:
        lines.append("Overall dynamic outcome: no attributed leak in any applicable mode.")
    else:
        lines.append("Overall dynamic outcome: inconclusive; this is NOT a clean result.")
    return "\n".join(lines)


def export(run_dir: Path) -> dict:
    run_dir = run_dir.resolve()
    records = [
        json.loads(line)
        for line in (run_dir / "results_units.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    out_dir = run_dir / "hybrid"
    out_dir.mkdir(exist_ok=True)
    cases = []
    results = []
    for record in records:
        modes = record.get("modes") or {}
        asan_status = (
            "leak" if record.get("y_pred") == 1
            else ("clean" if record.get("y_pred") == 0 else "inconclusive")
        )
        evidence_modes = record.get("evidence_modes") or []
        primary = record.get("primary_evidence") or "default"
        primary_mode = modes.get(primary) or {}
        attributed_bytes = primary_mode.get("attributed_bytes", 0)
        attributed_records = len(primary_mode.get("attributed_blocks") or [])
        raw_failure = record.get("failure_class")
        harness_failure = (
            raw_failure
            if raw_failure
            and (raw_failure.startswith(("asan_error", "compile_error", "timeout", "harness"))
                 or raw_failure == "no_returncode")
            else None
        )
        evidence = {
            "tool": "asan+lsan+wrap",
            "direct_bytes": attributed_bytes,
            "record_count": attributed_records,
            "leak_detected": record.get("y_pred") == 1,
            "evidence_mode": record.get("primary_evidence"),
            "evidence_modes": evidence_modes,
            "modes": {
                mode: {
                    "applicable": bool((modes.get(mode) or {}).get("applicable")),
                    "leak_attributed": bool((modes.get(mode) or {}).get("leak_attributed")),
                    "attributed_bytes": (modes.get(mode) or {}).get("attributed_bytes", 0),
                    "failure_class": (modes.get(mode) or {}).get("failure_class"),
                    "wall_ms": (modes.get(mode) or {}).get("wall_ms"),
                }
                for mode in config.MODES
            },
            "attribution_rule": "allocation site in the unit's own sources",
        }
        case_id = f"dyne__{record['unit_key']}"
        cases.append(
            {
                "case_id": case_id,
                "cwe": "CWE-401",
                "origin": "juliet",
                "language": record["language"],
                "sources": record["sources"],
                "defines": record["defines"],
                "label_source": "juliet_preprocessor_variant",
                "metadata": {
                    "unit_id": record["unit_id"],
                    "group_id": record["group_id"],
                    "family": record["family"],
                    "variant": record["variant"],
                },
            }
        )
        results.append(
            {
                "case_id": case_id,
                "unit_id": record["unit_id"],
                "outcome": asan_status,
                "failure_class": harness_failure,
                "runtime_ms": record.get("runtime_ms"),
                "detectors": {
                    "asan": {
                        "name": "asan",
                        "available": True,
                        "status": asan_status,
                        "leak_detected": record.get("y_pred") == 1,
                        "evidence": evidence,
                        "execution": {
                            "duration_ms": record.get("runtime_ms"),
                            "timed_out": any(
                                (modes.get(mode) or {}).get("timed_out") for mode in config.MODES
                            ),
                        },
                    },
                    "valgrind": {
                        "name": "valgrind",
                        "available": False,
                        "status": "unavailable",
                        "leak_detected": None,
                        "evidence": {
                            "note": "not re-run in the enhanced pass; see metrics.json old_comparison"
                        },
                    },
                },
                "modes": modes,
                "y_pred": record.get("y_pred"),
                "evidence_text": evidence_text(record),
            }
        )
    dests = [out_dir, config.ROOT / "exports" / "hybrid"]
    run_manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest = {
        "schema": "dynamic-enhanced-hybrid-export-v1",
        "source_run": str(run_dir.relative_to(config.PROJECT)),
        "generated_at": run_manifest.get("finished_at_utc"),
        "cases": len(cases),
        "results": len(results),
        "counts": {
            "units": len(records),
            "bad": sum(1 for record in records if record["label"] == "bad"),
            "good": sum(1 for record in records if record["label"] == "good"),
            "cases": len(cases),
        },
        "loader_contract": (
            "hybrid/build_inputs.py load_dynamic(): key = (sorted sources relative to "
            "CWE401_Memory_Leak/, sorted defines); result fields status/evidence/detectors"
        ),
        "valgrind": "unavailable in this pass; archived result compared in metrics.json",
    }
    for dest in dests:
        dest.mkdir(parents=True, exist_ok=True)
        with (dest / "cases.jsonl").open("w", encoding="utf-8") as handle:
            for row in cases:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        with (dest / "results.jsonl").open("w", encoding="utf-8") as handle:
            for row in results:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        written = {
            **manifest,
            "cases_sha256": sha256_file(dest / "cases.jsonl"),
            "results_sha256": sha256_file(dest / "results.jsonl"),
        }
        (dest / "manifest.json").write_text(
            json.dumps(written, indent=2) + "\n", encoding="utf-8"
        )
    return {
        **manifest,
        "cases_sha256": sha256_file(out_dir / "cases.jsonl"),
        "results_sha256": sha256_file(out_dir / "results.jsonl"),
        "stable_dir": str((config.ROOT / "exports" / "hybrid").relative_to(config.PROJECT)),
    }

"""Build the 140-unit hybrid input pack from frozen Juliet + tool results.

Inputs (read-only):
  juliet/subset_units.jsonl
  juliet/raw/testcases/CWE401_Memory_Leak/...
  traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl
  traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/{cases,results}.jsonl

Outputs (this directory only):
  hybrid/inputs/units.jsonl
  hybrid/inputs/manifest.json

No model is called here and no existing result is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from juliet_llm.cleaning import clean_unit  # noqa: E402
from sanitize import assert_clean, scrub_evidence_text  # noqa: E402

HYBRID = Path(__file__).resolve().parent
JULIET = ROOT / "juliet"
STATIC_RUN = ROOT / "traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu"
DYNAMIC_RUN = ROOT / "traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind"
SEED = 20261112
DYNAMIC_MARKER = "CWE401_Memory_Leak/"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def normalize_source(path: str) -> str:
    path = path.replace("\\", "/")
    if DYNAMIC_MARKER in path:
        return path.split(DYNAMIC_MARKER, 1)[1]
    if "testcases/" in path:
        return path.split("testcases/", 1)[1]
    return Path(path).name


def source_key(sources: list[str], defines: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return tuple(sorted(normalize_source(s) for s in sources)), tuple(sorted(defines))


def load_units() -> list[dict[str, Any]]:
    units = [u for u in read_jsonl(JULIET / "subset_units.jsonl") if u["split"] == "test"]
    if len(units) != 140:
        raise SystemExit(f"expected 140 frozen test units, found {len(units)}")
    if Counter(u["label"] for u in units) != Counter({"bad": 70, "good": 70}):
        raise SystemExit("frozen test labels are not 70/70")
    return sorted(units, key=lambda u: u["unit_id"])


def load_static() -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, Any]]:
    path = STATIC_RUN / "predictions.jsonl"
    rows = read_jsonl(path)
    by_unit: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        by_unit.setdefault(row["sample_id"], {})[row["tool"]] = row
    manifest = json.loads((STATIC_RUN / "manifest.json").read_text(encoding="utf-8"))
    meta = {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha256_bytes(path.read_bytes()),
        "generated_at": manifest.get("generated_at"),
        "tools": manifest.get("tools"),
    }
    return by_unit, meta


def load_dynamic() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    cases_path = DYNAMIC_RUN / "cases.jsonl"
    results_path = DYNAMIC_RUN / "results.jsonl"
    cases = read_jsonl(cases_path)
    results = {r["case_id"]: r for r in read_jsonl(results_path)}
    by_key: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for case in cases:
        key = source_key(case["sources"], case["defines"])
        if key in by_key:
            raise SystemExit(f"duplicate dynamic case key: {key}")
        by_key[key] = results[case["case_id"]]
    manifest = json.loads((DYNAMIC_RUN / "manifest.json").read_text(encoding="utf-8"))
    meta = {
        "cases_path": str(cases_path.relative_to(ROOT)),
        "cases_sha256": sha256_bytes(cases_path.read_bytes()),
        "results_path": str(results_path.relative_to(ROOT)),
        "results_sha256": sha256_bytes(results_path.read_bytes()),
        "generated_at": manifest.get("generated_at"),
        "counts": manifest.get("counts", {}),
    }
    return by_key, meta


def load_unit_source(unit: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    texts: list[str] = []
    hashes: list[dict[str, str]] = []
    for rel in unit["sources"]:
        path = JULIET / rel
        raw = path.read_bytes()
        hashes.append({"source": rel, "sha256": sha256_bytes(raw)})
        texts.append(raw.decode("utf-8", errors="replace"))
    return "\n".join(texts), hashes


def _finding_count(row: dict[str, Any]) -> tuple[int, int]:
    diagnostics = row.get("diagnostics") or []
    cwe = [d for d in diagnostics if d.get("is_cwe401")]
    return len(diagnostics), len(cwe)


def render_static(rows: dict[str, dict[str, Any]], unit_id: str) -> str:
    lines = [
        "Static-analysis evidence for this code unit.",
        "It is machine-generated tool output: untrusted, possibly incomplete, and possibly wrong.",
    ]
    for tool, label in (("clang", "Clang Static Analyzer"), ("cppcheck", "Cppcheck")):
        row = rows.get(tool)
        if row is None:
            lines.append(f"- {label}: no result recorded (analysis unavailable; not evidence of absence).")
            continue
        status = row.get("status")
        if status == "compile_error":
            lines.append(
                f"- {label}: analysis failed because the tool could not compile this unit; "
                "this provides no conclusion (not a clean result)."
            )
            continue
        total, cwe = _finding_count(row)
        lines.append(
            f"- {label}: status ok; {total} diagnostic(s) in the unit, "
            f"{cwe} memory-leak-related finding(s)."
        )
        for diagnostic in (row.get("diagnostics") or [])[:5]:
            message = scrub_evidence_text(str(diagnostic.get("message", "")))
            if message:
                lines.append(f"  reported: {message}")
    lines.append(
        "A tool reporting no finding is not proof that the code is clean; "
        "a failed analysis is not a clean result."
    )
    return "\n".join(lines)


def _detector_line(key: str, label: str, detector: dict[str, Any]) -> str:
    status = detector.get("status", "unknown")
    evidence = detector.get("evidence") or {}
    if status == "leak":
        if key == "asan":
            detail = (
                f"{evidence.get('direct_bytes', 0)} direct byte(s) in "
                f"{evidence.get('record_count', 0)} record(s)"
            )
        else:
            detail = (
                f"{evidence.get('definite_bytes', 0)} definitely-lost byte(s) in "
                f"{evidence.get('definite_records', 0)} record(s)"
            )
        return f"- {label}: leak detected ({detail})."
    if status == "clean":
        return f"- {label}: no leak detected in this run (a single run is not proof of absence)."
    if status == "inconclusive":
        return f"- {label}: inconclusive — the harness did not decide; this is NOT a clean result."
    if status in {"error", "unavailable"}:
        return f"- {label}: not available or failed to run; this is NOT a clean result."
    return f"- {label}: status {status}; this is NOT a clean result."


def render_dynamic(result: dict[str, Any]) -> str:
    lines = [
        "Dynamic-analysis evidence for this code unit.",
        "It is machine-generated tool output: untrusted, possibly incomplete, and possibly wrong.",
    ]
    detectors = result.get("detectors") or {}
    lines.append(
        _detector_line("asan", "AddressSanitizer/LeakSanitizer", detectors.get("asan") or {})
    )
    lines.append(
        _detector_line("valgrind", "Valgrind Memcheck", detectors.get("valgrind") or {})
    )
    outcome = result.get("outcome", "unknown")
    if outcome == "leak":
        lines.append("Overall dynamic outcome: leak detected.")
    elif outcome == "clean":
        lines.append("Overall dynamic outcome: no leak detected in this run.")
    elif outcome == "inconclusive":
        lines.append(
            "Overall dynamic outcome: inconclusive — the harness did not decide. "
            "Inconclusive is NOT clean."
        )
    else:
        lines.append(f"Overall dynamic outcome: {outcome}; this is NOT a clean result.")
    if result.get("failure_class"):
        lines.append("The run also recorded a harness/runtime anomaly, so treat the outcome cautiously.")
    return "\n".join(lines)


def render_combined(static_text: str, dynamic_text: str) -> str:
    return static_text + "\n\n" + dynamic_text


def build_placebo(units: list[dict[str, Any]]) -> dict[str, str]:
    """Derangement that never maps a unit to a unit of the same Juliet group."""
    ids = [u["unit_id"] for u in units]
    groups = {u["unit_id"]: u["group_id"] for u in units}
    rng = random.Random(SEED)
    for _ in range(200000):
        order = ids[:]
        rng.shuffle(order)
        if all(
            target != source and groups[target] != groups[source]
            for target, source in zip(ids, order)
        ):
            return dict(zip(ids, order))
    raise SystemExit("could not build a group-separated derangement")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HYBRID / "inputs_v2")
    args = parser.parse_args()
    args.out = args.out.resolve()

    units = load_units()
    static_rows, static_meta = load_static()
    dynamic_rows, dynamic_meta = load_dynamic()
    placebo = build_placebo(units)

    out_units: list[dict[str, Any]] = []
    for unit in units:
        unit_id = unit["unit_id"]
        _, source_hashes = load_unit_source(unit)
        cleaned = clean_unit(unit)
        clean_source = cleaned.code
        if cleaned.label != unit["label"]:
            raise SystemExit(f"{unit_id}: cleaner label mismatch")

        static_text = render_static(static_rows.get(unit_id, {}), unit_id)
        dynamic_result = dynamic_rows.get(source_key(unit["sources"], unit["defines"]))
        if dynamic_result is None:
            raise SystemExit(f"{unit_id}: no dynamic result")
        dynamic_text = render_dynamic(dynamic_result)
        combined_text = render_combined(static_text, dynamic_text)
        for label, text in (
            ("static", static_text),
            ("dynamic", dynamic_text),
            ("combined", combined_text),
        ):
            assert_clean(text, f"{label} evidence {unit_id}")

        donor_id = placebo[unit_id]
        donor = next(u for u in units if u["unit_id"] == donor_id)
        donor_static = render_static(static_rows.get(donor_id, {}), donor_id)
        donor_dynamic_result = dynamic_rows.get(source_key(donor["sources"], donor["defines"]))
        if donor_dynamic_result is None:
            raise SystemExit(f"{donor_id}: no dynamic result for placebo")
        placebo_text = render_combined(donor_static, render_dynamic(donor_dynamic_result))
        assert_clean(placebo_text, f"placebo evidence {unit_id}")

        out_units.append(
            {
                "unit_id": unit_id,
                "group_id": unit["group_id"],
                "family": unit["family"],
                "variant": unit["variant"],
                "language": unit["language"],
                "label": unit["label"] == "bad",
                "split": unit["split"],
                "defines": unit["defines"],
                "source_hashes": source_hashes,
                "source_chars": len(clean_source),
                "source_text": clean_source,
                "source_sha256": cleaned.code_sha256,
                "renamed_identifiers": len(cleaned.mapping),
                "cleaning_checks": cleaned.checks,
                "evidence": {
                    "static": static_text,
                    "dynamic": dynamic_text,
                    "combined": combined_text,
                },
                "dynamic_outcome": dynamic_result.get("outcome"),
                "dynamic_detectors": {
                    name: (dynamic_result.get("detectors") or {}).get(name, {}).get("status")
                    for name in ("asan", "valgrind")
                },
                "static_findings": {
                    tool: _finding_count(static_rows.get(unit_id, {}).get(tool, {}))
                    for tool in ("clang", "cppcheck")
                },
                "placebo_evidence": placebo_text,
                "placebo_donor_unit": donor_id,
                "placebo_donor_group": donor["group_id"],
            }
        )

    for unit in out_units:
        if not unit["label"]:
            assert unit["dynamic_outcome"] == "clean" or unit["dynamic_outcome"] == "inconclusive"
    noop_collisions = sorted(
        unit["unit_id"]
        for unit in out_units
        if unit["placebo_evidence"] == unit["evidence"]["combined"]
    )
    args.out.mkdir(parents=True, exist_ok=True)
    units_path = args.out / "units.jsonl"
    with units_path.open("w", encoding="utf-8") as handle:
        for unit in out_units:
            handle.write(json.dumps(unit, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": "hybrid-inputs-v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "unit_count": len(out_units),
        "label_counts": dict(Counter("bad" if u["label"] else "good" for u in out_units)),
        "language_counts": dict(Counter(u["language"] for u in out_units)),
        "source_chars": {
            "min": min(u["source_chars"] for u in out_units),
            "median": sorted(u["source_chars"] for u in out_units)[len(out_units) // 2],
            "max": max(u["source_chars"] for u in out_units),
        },
        "dynamic_outcome_counts": dict(Counter(u["dynamic_outcome"] for u in out_units)),
        "dynamic_outcome_by_label": {
            label: dict(
                Counter(
                    u["dynamic_outcome"] for u in out_units if u["label"] == (label == "bad")
                )
            )
            for label in ("bad", "good")
        },
        "placebo": {
            "seed": SEED,
            "constraint": "no fixed point; donor must belong to a different Juliet group",
            "pairs": len(out_units),
            "donors": {u["unit_id"]: u["placebo_donor_unit"] for u in out_units},
            "identical_evidence_pairs": len(noop_collisions),
            "identical_evidence_units": noop_collisions,
        },
        "frozen_units": {
            "path": str((JULIET / "subset_units.jsonl").relative_to(ROOT)),
            "sha256": sha256_bytes((JULIET / "subset_units.jsonl").read_bytes()),
        },
        "static": static_meta,
        "dynamic": dynamic_meta,
        "units_file": str(units_path.relative_to(ROOT)),
        "units_sha256": sha256_bytes(units_path.read_bytes()),
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Self-tests for the hybrid pipeline that do not call a model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
for path in (str(ROOT), str(HYBRID)):
    if path not in sys.path:
        sys.path.insert(0, path)

from build_inputs import render_dynamic  # noqa: E402
from prompts import METHODS, build_messages  # noqa: E402
from sanitize import assert_clean, scrub_evidence_text  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, default=HYBRID / "inputs_v2")
    args = parser.parse_args()
    failures: list[str] = []
    units = [
        json.loads(line)
        for line in (args.inputs_dir / "units.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(units) != 140:
        failures.append(f"expected 140 units, found {len(units)}")
    if sum(1 for u in units if u["label"]) != 70:
        failures.append("label balance is not 70/70")

    for unit in units:
        if unit["placebo_donor_unit"] == unit["unit_id"]:
            failures.append(f"{unit['unit_id']}: placebo self-map")
        if unit["placebo_donor_group"] == unit["group_id"]:
            failures.append(f"{unit['unit_id']}: placebo same-group donor")
        for method in METHODS:
            build_messages(unit, method)

    inconclusive = {
        "outcome": "inconclusive",
        "detectors": {
            "asan": {"status": "inconclusive", "evidence": {}},
            "valgrind": {"status": "inconclusive", "evidence": {}},
        },
    }
    text = render_dynamic(inconclusive)
    if "NOT a clean" not in text or "inconclusive" not in text:
        failures.append("inconclusive dynamic rendering does not say it is not clean")

    dirty = (
        "/mnt/c/Users/x/CWE401_Memory_Leak__char_calloc_01_bad.c:12 "
        "badSink goodG2B CWE-401 OMITBAD"
    )
    cleaned = scrub_evidence_text(dirty)
    try:
        assert_clean(cleaned, "selftest")
    except ValueError as exc:
        failures.append(f"evidence scrub left a marker: {exc}")

    reference_path = ROOT / "juliet_llm/build/test.jsonl"
    reference = {}
    if reference_path.is_file():
        for line in reference_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                reference[record["unit_id"]] = record["prompt_sha256"]
        for unit in units:
            messages, metadata = build_messages(unit, "direct")
            if metadata["prompt_sha256"] != reference.get(unit["unit_id"]):
                failures.append(f"{unit['unit_id']}: direct prompt differs from juliet_llm")
    else:
        failures.append("juliet_llm/build/test.jsonl missing; cannot verify direct alignment")

    result = {
        "units": len(units),
        "methods": list(METHODS),
        "direct_prompt_alignment": not any("direct prompt differs" in f for f in failures),
        "dynamic_inconclusive_not_clean": "NOT a clean" in text,
        "placebo_constraints": not any("placebo" in f for f in failures),
        "failures": failures,
        "ok": not failures,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

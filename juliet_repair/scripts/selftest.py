#!/usr/bin/env python3
"""Self-test the compile/LSan/behaviour harness with hand-built controls."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import repair_lib as rl  # noqa: E402


def main() -> int:
    unit = {item.unit_id: item for item in rl.load_test_units()}["CWE401_Memory_Leak__char_calloc_01__bad"]
    unit_input = rl.build_unit_input(unit)
    baseline = json.loads(
        (rl.BUILD / "baselines" / unit.unit_key / "baseline.json").read_text(encoding="utf-8")
    )
    path = unit_input["files"][0]["path"]
    original = unit_input["files"][0]["content"]
    marker = "    ;\n}"
    if marker not in original:
        raise SystemExit("unexpected control source shape")

    controls = {
        "correct_free": original.replace(marker, "    free(data);\n}"),
        "behaviour_break": original.replace(marker, "    free(data);\n}").replace(
            "    printLine(data);\n", ""
        ),
        "no_fix": original.replace(marker, "    ; /* still leaks */\n}"),
        "double_free": original.replace(marker, "    free(data);\n    free(data);\n}"),
    }
    expected = {
        "correct_free": {"compile_pass": True, "leak_removed": True, "behavior_preserved": True, "strict_pass": True},
        "behaviour_break": {"compile_pass": True, "leak_removed": True, "behavior_preserved": False, "strict_pass": False},
        "no_fix": {"compile_pass": True, "leak_removed": False, "behavior_preserved": False, "strict_pass": False},
        "double_free": {"compile_pass": True, "leak_removed": False, "behavior_preserved": False, "strict_pass": False},
    }
    results = {}
    failures = []
    for name, body in controls.items():
        evaluation = rl.evaluate_attempt(
            unit,
            unit_input,
            {path: body},
            rl.BUILD / "selftest" / name,
            baseline["bad"],
            baseline["good"],
        )
        actual = {
            key: bool(evaluation.get(key))
            for key in ("compile_pass", "leak_removed", "behavior_preserved", "strict_pass")
        }
        ok = actual == expected[name]
        results[name] = {
            "expected": expected[name],
            "actual": actual,
            "run": evaluation.get("run"),
            "baseline_behavior_lines": evaluation.get("baseline_behavior_lines"),
            "fixed_behavior_lines": evaluation.get("fixed_behavior_lines"),
            "ok": ok,
        }
        if not ok:
            failures.append(name)
    report = {"status": "PASS" if not failures else "FAIL", "failures": failures, "controls": results}
    (rl.BUILD / "selftest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "failures": failures}, indent=2))
    for name, row in results.items():
        print(name, row["expected"], "->", row["actual"], "OK" if row["ok"] else "MISMATCH")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

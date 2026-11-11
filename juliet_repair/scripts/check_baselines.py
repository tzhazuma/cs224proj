#!/usr/bin/env python3
"""Build and run evaluator-only baselines for every frozen bad unit.

For each unit this compiles and runs three binaries:
  * the original raw bad unit (the reference leak / behaviour),
  * the original raw good unit (secondary reference only), and
  * the sanitised model-facing input (must behave exactly like the raw bad unit).

The sanitised build is the proof that removing comments and OMITGOOD regions
did not silently fix or change the program before any model saw it.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repair_lib as rl  # noqa: E402


def check_unit(unit: rl.Unit, inputs: dict, force: bool) -> dict:
    base_dir = rl.BUILD / "baselines" / unit.unit_key
    base = rl.build_baselines(unit, base_dir, force=force)
    sanitized_dir = rl.BUILD / "sanitized" / unit.unit_key
    if sanitized_dir.exists():
        import shutil

        shutil.rmtree(sanitized_dir)
    sanitized_dir.mkdir(parents=True)
    files = {item["path"]: item["content"] for item in inputs[unit.unit_key]["files"]}
    exe = sanitized_dir / "sanitized_bad"
    comp = rl.compile_files(
        unit,
        files,
        sanitized_dir / "src",
        exe,
        probe=rl.probe_source(unit, "bad"),
    )
    entry = {
        "unit_key": unit.unit_key,
        "unit_id": unit.unit_id,
        "raw_bad_compile_ok": base["bad"].get("compile_ok"),
        "raw_good_compile_ok": base["good"].get("compile_ok"),
        "sanitized_compile_ok": comp["ok"],
        "sanitized_compile_stderr_tail": comp["stderr_tail"],
    }
    if comp["ok"]:
        run = rl.run_binary(exe)
        entry.update(
            {
                "sanitized_returncode": run["returncode"],
                "sanitized_leak_detected": run["leak_detected"],
                "sanitized_other_asan_error": run["other_asan_error"],
                "sanitized_timed_out": run["timed_out"],
                "sanitized_summary": run["summary"],
                "sanitized_behavior_lines": rl.behavior_lines(run["stdout"]),
                "sanitized_stderr_tail": run["stderr"][-3000:],
            }
        )
    entry["raw_bad_leak_detected"] = base["bad"].get("leak_detected")
    entry["raw_good_leak_detected"] = base["good"].get("leak_detected")
    entry["raw_bad_behavior_lines"] = base["bad"].get("behavior_lines")
    entry["raw_good_behavior_lines"] = base["good"].get("behavior_lines")
    entry["same_leak_as_raw"] = (
        entry.get("sanitized_leak_detected") == base["bad"].get("leak_detected")
    )
    entry["same_behavior_as_raw"] = (
        entry.get("sanitized_behavior_lines") == base["bad"].get("behavior_lines")
    )
    entry["behavior_observable"] = bool(base["bad"].get("behavior_lines"))
    entry["status"] = (
        "PASS"
        if (
            comp["ok"]
            and entry["same_leak_as_raw"]
            and entry["same_behavior_as_raw"]
            and base["good"].get("compile_ok")
            and base["good"].get("leak_detected") is False
        )
        else "FAIL"
    )
    (sanitized_dir / "check.json").write_text(
        json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    units = rl.load_test_units()
    inputs = rl.unit_inputs_by_key()
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(check_unit, unit, inputs, args.force): unit for unit in units}
        for future in concurrent.futures.as_completed(futures):
            unit = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001 - recorded, not hidden
                results.append(
                    {
                        "unit_key": unit.unit_key,
                        "unit_id": unit.unit_id,
                        "status": "ERROR",
                        "error": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(),
                    }
                )
    results.sort(key=lambda item: item["unit_key"])
    summary = {
        "units": len(results),
        "pass": sum(1 for item in results if item["status"] == "PASS"),
        "fail": sum(1 for item in results if item["status"] == "FAIL"),
        "error": sum(1 for item in results if item["status"] == "ERROR"),
        "raw_bad_leaks": sum(1 for item in results if item.get("raw_bad_leak_detected")),
        "raw_good_clean": sum(1 for item in results if item.get("raw_good_leak_detected") is False),
        "behavior_observable": sum(1 for item in results if item.get("behavior_observable")),
        "same_leak_as_raw": sum(1 for item in results if item.get("same_leak_as_raw")),
        "same_behavior_as_raw": sum(1 for item in results if item.get("same_behavior_as_raw")),
        "results": results,
    }
    (rl.BUILD / "baselines_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Sanitised-input baseline check",
        "",
        f"- units: {summary['units']}",
        f"- status PASS/FAIL/ERROR: {summary['pass']}/{summary['fail']}/{summary['error']}",
        f"- raw bad units with an observed LSan leak: {summary['raw_bad_leaks']}",
        f"- raw good units clean: {summary['raw_good_clean']}",
        f"- non-empty behaviour signature: {summary['behavior_observable']}",
        f"- sanitised leak matches raw: {summary['same_leak_as_raw']}",
        f"- sanitised behaviour matches raw: {summary['same_behavior_as_raw']}",
        "",
        "| unit | status | raw leak | sanitised leak | behaviour lines |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for item in results:
        lines.append(
            "| {unit} | {status} | {raw} | {san} | {n} |".format(
                unit=item["unit_key"],
                status=item["status"],
                raw=item.get("raw_bad_leak_detected"),
                san=item.get("sanitized_leak_detected"),
                n=len(item.get("raw_bad_behavior_lines") or []),
            )
        )
    (rl.BUILD / "baselines_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "results"}, indent=2))
    return 0 if summary["fail"] == 0 and summary["error"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

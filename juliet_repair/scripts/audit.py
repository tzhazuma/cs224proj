#!/usr/bin/env python3
"""Audit frozen inputs, run artifacts, and secret hygiene."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import repair_lib as rl  # noqa: E402

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
]
FORBIDDEN_INPUT = re.compile(
    r"\bFIX\b|POTENTIAL\s+FLAW|GoodSink|BadSink|(?<![A-Za-z0-9])good[A-Za-z0-9_]*|/\*|//"
)


def verify_inputs() -> list[str]:
    problems: list[str] = []
    manifest = json.loads((rl.INPUTS / "manifest.json").read_text(encoding="utf-8"))
    rows = rl.load_inputs()
    if len(rows) != 70:
        problems.append(f"inputs: expected 70 rows, got {len(rows)}")
    if len({row["group_id"] for row in rows}) != 70:
        problems.append("inputs: group ids are not unique")
    for row in rows:
        canonical = json.dumps(
            {"unit_key": row["unit_key"], "language": row["language"], "files": row["files"]},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if rl.sha256_text(canonical) != row["input_sha256"]:
            problems.append(f"inputs: hash mismatch for {row['unit_key']}")
        for item in row["files"]:
            for match in FORBIDDEN_INPUT.finditer(item["content"]):
                problems.append(
                    f"inputs: leak marker {match.group(0)!r} in {row['unit_key']}/{item['path']}"
                )
    if manifest.get("leak_audit", {}).get("clean_units") != 70:
        problems.append("inputs: manifest leak audit is not 70/70 clean")
    freeze = json.loads((rl.JULIET / "FREEZE.json").read_text(encoding="utf-8"))
    checks = {
        "manifest.json": freeze["manifest_sha256"],
        "subset_units.jsonl": freeze["subset_units_sha256"],
    }
    for name, expected in checks.items():
        actual = rl.sha256_file(rl.JULIET / name)
        if actual != expected:
            problems.append(f"frozen Juliet file changed: {name}")
    return problems


def verify_run(run_dir: Path) -> tuple[list[str], dict]:
    problems: list[str] = []
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    results = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((run_dir / "units").glob("*/result.json"))
    ]
    if len(results) != 70:
        problems.append(f"{run_dir.name}: expected 70 unit results, got {len(results)}")
    if manifest.get("api", {}).get("api_key_value_stored") is not False:
        problems.append(f"{run_dir.name}: manifest does not deny key storage")
    calls = 0
    for result in results:
        attempts = result.get("attempts") or []
        calls += len(attempts)
        if not attempts:
            problems.append(f"{run_dir.name}/{result['unit_key']}: no attempts")
            continue
        final = attempts[-1]
        if final.get("parse_error"):
            problems.append(f"{run_dir.name}/{result['unit_key']}: final parse error {final['parse_error']}")
        eval_path = run_dir / "units" / result["unit_key"] / f"attempt{final['attempt']}" / "eval.json"
        if not eval_path.exists():
            problems.append(f"{run_dir.name}/{result['unit_key']}: missing eval.json")
        patch_path = run_dir / "units" / result["unit_key"] / f"attempt{final['attempt']}" / "patch.diff"
        if result.get("compile_pass") and (not patch_path.exists() or not patch_path.read_text(encoding="utf-8").strip()):
            problems.append(f"{run_dir.name}/{result['unit_key']}: compile pass without a patch")
        if result.get("strict_pass") and not result.get("strict_evaluable"):
            problems.append(f"{run_dir.name}/{result['unit_key']}: strict pass on a non-evaluable unit")
    request_lines = sum(
        1 for line in (run_dir / "requests.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()
    )
    if request_lines != calls:
        problems.append(
            f"{run_dir.name}: requests.jsonl has {request_lines} rows but results contain {calls} calls"
        )
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    if summary.get("units") != len(results):
        problems.append(f"{run_dir.name}: summary units mismatch")
    return problems, {
        "run": run_dir.name,
        "model": manifest.get("model"),
        "units": len(results),
        "calls": calls,
        "strict_pass": sum(1 for r in results if r.get("strict_pass")),
        "strict_evaluable": sum(1 for r in results if r.get("strict_evaluable")),
        "compile_pass": sum(1 for r in results if r.get("compile_pass")),
        "leak_removed": sum(1 for r in results if r.get("leak_removed")),
        "behavior_preserved": sum(1 for r in results if r.get("behavior_preserved")),
        "cost_usd": summary.get("cost_usd_sum"),
    }


def scan_secrets(root: Path) -> list[str]:
    problems: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() in {".o", ".png", ".jpg", ".pdf"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                problems.append(f"possible secret in {path.relative_to(root)}")
                break
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    args = parser.parse_args()
    problems = verify_inputs()
    runs = []
    for path in args.run:
        run_problems, row = verify_run(path.resolve())
        problems.extend(run_problems)
        runs.append(row)
    problems.extend(scan_secrets(rl.ROOT))
    if (rl.JULIET / "build" / "repair_probe").exists():
        problems.append("stray juliet/build/repair_probe directory exists")
    report = {"status": "PASS" if not problems else "FAIL", "problems": problems, "runs": runs}
    (rl.ROOT / "audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())

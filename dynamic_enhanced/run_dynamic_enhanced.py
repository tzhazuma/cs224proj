#!/usr/bin/env python3
"""CLI for the enhanced dynamic analysis of the Juliet CWE-401 test split.

Commands:
  selftest                      compile and run the synthetic controls
  run --run-id ID [--jobs N]    run 140 test units in all three modes
  report --run-dir DIR          recompute metrics and the Markdown report
  export --run-dir DIR          write the hybrid-compatible cases/results
  verify --run-dir DIR          check run completeness and hashes
  all --run-id ID [--jobs N]    selftest + run + report + export
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dyne import config  # noqa: E402
from dyne.export import export  # noqa: E402
from dyne.metrics import build_metrics  # noqa: E402
from dyne.pipeline import run_all  # noqa: E402
from dyne.report import write as write_report  # noqa: E402
from dyne.selftest import run_selftest  # noqa: E402
from dyne.units import sha256_file  # noqa: E402


def _load_manifest(run_dir: Path) -> dict:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


def cmd_selftest(_: argparse.Namespace) -> int:
    report = run_selftest()
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    return 0 if report["status"] == "PASS" else 1


def cmd_run(args: argparse.Namespace) -> int:
    result = run_all(args.run_id, jobs=args.jobs)
    print(f"run directory: {result['run_dir']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    metrics = build_metrics(run_dir)
    manifest = _load_manifest(run_dir)
    path = write_report(run_dir, metrics, manifest)
    print(f"wrote {path}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    manifest = export(Path(args.run_dir))
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    manifest = _load_manifest(run_dir)
    problems = []
    records = [
        json.loads(line)
        for line in (run_dir / "results_units.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(records) != 140:
        problems.append(f"expected 140 unit records, found {len(records)}")
    if sum(1 for row in records if row["label"] == "bad") != 70:
        problems.append("bad count != 70")
    if sum(1 for row in records if row["label"] == "good") != 70:
        problems.append("good count != 70")
    if len({row["unit_id"] for row in records}) != len(records):
        problems.append("duplicate unit ids")
    if manifest.get("results_units_sha256") != sha256_file(run_dir / "results_units.jsonl"):
        problems.append("results_units.jsonl hash mismatch")
    for record in records:
        if record.get("y_pred") is None:
            problems.append(f"{record['unit_id']}: undecided ({record.get('failure_class')})")
        if not record.get("modes"):
            problems.append(f"{record['unit_id']}: no mode records")
    selftest_path = config.ROOT / "selftest" / "selftest.json"
    if not selftest_path.exists():
        problems.append("selftest has not been run")
    else:
        selftest = json.loads(selftest_path.read_text(encoding="utf-8"))
        if selftest.get("status") != "PASS":
            problems.append("selftest did not pass")
    report = {
        "run_id": run_dir.name,
        "units": len(records),
        "problems": problems,
        "status": "PASS" if not problems else "FAIL",
    }
    (run_dir / "verify.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if not problems else 1


def cmd_all(args: argparse.Namespace) -> int:
    report = run_selftest()
    if report["status"] != "PASS":
        print("selftest failed; refusing to run the experiment", file=sys.stderr)
        return 1
    result = run_all(args.run_id, jobs=args.jobs)
    run_dir = result["run_dir"]
    metrics = build_metrics(run_dir)
    manifest = _load_manifest(run_dir)
    write_report(run_dir, metrics, manifest)
    export(run_dir)
    print(f"run directory: {run_dir}")
    print(json.dumps(metrics["confusion"], indent=2))
    print(f"resolved conditional units: {len(metrics['resolved_conditional'])}")
    print(f"good false positives: {len(metrics['good_false_positives'])}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    selftest = sub.add_parser("selftest")
    selftest.set_defaults(func=cmd_selftest)
    run = sub.add_parser("run")
    run.add_argument("--run-id", default=config.DEFAULT_RUN_ID)
    run.add_argument("--jobs", type=int, default=8)
    run.set_defaults(func=cmd_run)
    for name, func in (("report", cmd_report), ("export", cmd_export), ("verify", cmd_verify)):
        item = sub.add_parser(name)
        item.add_argument("--run-dir", required=True)
        item.set_defaults(func=func)
    all_cmd = sub.add_parser("all")
    all_cmd.add_argument("--run-id", default=config.DEFAULT_RUN_ID)
    all_cmd.add_argument("--jobs", type=int, default=8)
    all_cmd.set_defaults(func=cmd_all)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

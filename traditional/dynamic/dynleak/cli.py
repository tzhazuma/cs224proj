from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from .discover import discover_juliet, load_manifest
from .pipeline import RunOptions, run_evaluation
from .selftest import run_selftest
from .toolchain import check_tools, make_toolchain
from .util import sha256_file, utc_now_iso, write_jsonl


SCRIPT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_RUNS_DIR = SCRIPT_DIR / "runs"


def _default_jobs() -> int:
    return max(1, min(8, os.cpu_count() or 4))


def _detectors(value: str) -> list[str]:
    names = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = sorted(set(names) - {"asan", "valgrind"})
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown detector(s): {', '.join(unknown)}")
    if not names:
        raise argparse.ArgumentTypeError("at least one detector is required")
    return names


def _add_toolchain_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cc", help="C compiler (default: gcc, then clang)")
    parser.add_argument("--cxx", help="C++ compiler (default: g++, then clang++)")
    parser.add_argument("--valgrind-bin", help="explicit valgrind binary (or PATH lookup)")


def _add_juliet_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--juliet-root", required=True, help="CWE401_Memory_Leak testcase directory")
    parser.add_argument("--support-dir", help="Juliet testcasesupport directory (auto-detected)")
    parser.add_argument("--exclude-wchar", action="store_true", help="skip wchar_t testcases")
    parser.add_argument("--exclude", action="append", default=[], help="substring to skip in relative paths")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Traditional dynamic CWE-401 evaluation: compile, execute, parse LeakSanitizer/Valgrind evidence."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run a real dynamic benchmark")
    input_group = run_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--juliet-root", help="CWE401_Memory_Leak testcase directory")
    input_group.add_argument("--manifest", help="JSONL manifest of explicit cases")
    run_parser.add_argument("--support-dir", help="Juliet testcasesupport directory")
    run_parser.add_argument("--out", help="run output directory (must be new/empty)")
    run_parser.add_argument("--run-id", help="stable run id (default: generated)")
    run_parser.add_argument("--jobs", type=int, default=_default_jobs())
    run_parser.add_argument("--detectors", type=_detectors, default=["asan", "valgrind"])
    run_parser.add_argument("--timeout", type=float, default=None, help="override per-case runtime timeout")
    run_parser.add_argument("--compile-timeout", type=float, default=120.0)
    run_parser.add_argument("--valgrind-timeout-factor", type=float, default=3.0)
    run_parser.add_argument("--max-cases", type=int, default=None)
    run_parser.add_argument("--filter", dest="filter_text", default=None)
    run_parser.add_argument("--dry-run", action="store_true", help="write cases/manifest, do not compile")
    run_parser.add_argument("--asan-options-extra", default="")
    run_parser.add_argument("--valgrind-arg", action="append", default=[])
    run_parser.add_argument("--cflag", action="append", default=[])
    run_parser.add_argument("--ldflag", action="append", default=[])
    run_parser.add_argument("--exclude-wchar", action="store_true")
    run_parser.add_argument("--exclude", action="append", default=[])
    _add_toolchain_args(run_parser)

    discover_parser = sub.add_parser("discover", help="write a JSONL manifest for Juliet CWE-401")
    _add_juliet_args(discover_parser)
    discover_parser.add_argument("--out", required=True, help="output JSONL manifest")
    discover_parser.add_argument("--timeout", type=float, default=10.0)
    discover_parser.add_argument("--limit", type=int, default=None)

    check_parser = sub.add_parser("check-tools", help="verify compiler, ASan/LSan and Valgrind availability")
    check_parser.add_argument("--json", action="store_true", dest="as_json")
    _add_toolchain_args(check_parser)

    selftest_parser = sub.add_parser("selftest", help="run real temporary-program self-tests and clean up")
    selftest_parser.add_argument("--keep", action="store_true")
    selftest_parser.add_argument("--jobs", type=int, default=2)
    _add_toolchain_args(selftest_parser)
    return parser


def _run_id(prefix: str) -> str:
    return f"{prefix}_{utc_now_iso().replace('-', '').replace(':', '').replace('T', '_').replace('Z', '')}"


def _cmd_run(args: argparse.Namespace) -> int:
    if args.jobs < 1:
        raise ValueError("--jobs must be at least 1")
    if args.juliet_root:
        root = Path(args.juliet_root)
        support = Path(args.support_dir) if args.support_dir else None
        cases = discover_juliet(
            root,
            support,
            exclude_wchar=args.exclude_wchar,
            exclude_patterns=args.exclude,
            timeout_s=10.0,
        )
        input_metadata: dict[str, Any] = {
            "kind": "juliet",
            "root": str(root.resolve()),
            "support_dir": str((support or (root.resolve().parent.parent / "testcasesupport"))),
            "n_discovered": len(cases),
        }
        provenance = None
        for parent in [root.resolve(), *root.resolve().parents]:
            candidate = parent / "provenance.json"
            if candidate.is_file():
                provenance = candidate
                break
        if provenance is not None:
            input_metadata["provenance_path"] = str(provenance)
            input_metadata["provenance_sha256"] = sha256_file(provenance)
    else:
        manifest_path = Path(args.manifest)
        cases = load_manifest(manifest_path)
        input_metadata = {
            "kind": "manifest",
            "path": str(manifest_path.resolve()),
            "sha256": sha256_file(manifest_path),
            "n_discovered": len(cases),
        }
    if args.timeout is not None:
        for case in cases:
            case.timeout_s = float(args.timeout)
    run_id = args.run_id or _run_id("cwe401")
    out_dir = Path(args.out) if args.out else DEFAULT_RUNS_DIR / run_id
    tc = make_toolchain(args.cc, args.cxx, args.valgrind_bin)
    options = RunOptions(
        detectors=args.detectors,
        jobs=args.jobs,
        compile_timeout_s=args.compile_timeout,
        valgrind_timeout_factor=args.valgrind_timeout_factor,
        asan_options_extra=args.asan_options_extra,
        valgrind_extra_args=args.valgrind_arg,
        extra_cflags=args.cflag,
        extra_ldflags=args.ldflag,
        max_cases=args.max_cases,
        filter_text=args.filter_text,
        dry_run=args.dry_run,
        rel_root=PROJECT_ROOT,
    )
    result = run_evaluation(cases, out_dir, run_id, tc, options, input_metadata=input_metadata)
    print(f"run_dir: {out_dir.resolve()}")
    if args.dry_run:
        print(f"dry run: {len(cases)} cases written")
        return 0
    metrics = result["metrics"]
    counts = metrics["counts"]
    print(f"cases: {counts['n_cases']} labeled: {counts['n_labeled']} decisive: {counts['n_decisive']}")
    print(f"outcomes: {json.dumps(counts['outcomes'], ensure_ascii=False, sort_keys=True)}")
    c = metrics["combined"]
    print(
        "combined: "
        f"TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']} "
        f"recall={c['recall']} fpr={c['fpr']} f1={c['f1']}"
    )
    for name in ("asan", "valgrind"):
        d = metrics["detectors"][name]
        print(
            f"{name}: decisive={d['n_decisive']} TP={d['tp']} FP={d['fp']} "
            f"TN={d['tn']} FN={d['fn']} recall={d['recall']} fpr={d['fpr']}"
        )
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    root = Path(args.juliet_root)
    cases = discover_juliet(
        root,
        Path(args.support_dir) if args.support_dir else None,
        exclude_wchar=args.exclude_wchar,
        exclude_patterns=args.exclude,
        timeout_s=args.timeout,
    )
    if args.limit is not None:
        cases = cases[: max(0, args.limit)]
    rows = [case.to_manifest_row(root=None) for case in cases]
    write_jsonl(Path(args.out), rows)
    labels = {"vulnerable": sum(1 for row in rows if row["expected_label"] == 1), "clean": sum(1 for row in rows if row["expected_label"] == 0)}
    print(f"wrote {len(rows)} cases to {Path(args.out).resolve()}")
    print(f"labels: {json.dumps(labels, sort_keys=True)}")
    return 0


def _cmd_check_tools(args: argparse.Namespace) -> int:
    tc = make_toolchain(args.cc, args.cxx, args.valgrind_bin)
    report = check_tools(tc)
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"python: {report['python']}")
        print(f"cc: {report['cc']['path']} ({report['cc']['version']})")
        print(f"cxx: {report['cxx']['path']} ({report['cxx']['version']})")
        asan = report["asan"]
        print(
            f"asan/lsan: available={asan.get('available')} leak_detected={asan.get('leak_detected')} "
            f"exit_code={asan.get('exit_code')}"
        )
        valgrind = report["valgrind"]
        print(
            f"valgrind: path={valgrind.get('path')} version={valgrind.get('version')} "
            f"available={valgrind.get('available')} leak_detected={valgrind.get('leak_detected')}"
        )
    return 0 if report.get("ok") else 1


def _cmd_selftest(args: argparse.Namespace) -> int:
    return run_selftest(
        cc=args.cc,
        cxx=args.cxx,
        valgrind_bin=args.valgrind_bin,
        keep=args.keep,
        jobs=args.jobs,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "discover":
            return _cmd_discover(args)
        if args.command == "check-tools":
            return _cmd_check_tools(args)
        if args.command == "selftest":
            return _cmd_selftest(args)
        parser.error(f"unknown command: {args.command}")
        return 2
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

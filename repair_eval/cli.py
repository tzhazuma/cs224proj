"""Command-line entry points for repair_eval."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .blind import build_blind_package, load_package, verify_package
from .rubric import DIMENSION_CODES, RUBRIC_VERSION
from .sampling import (
    MAX_PAIRS,
    MIN_PAIRS,
    build_frame,
    load_pairs_dataset,
    load_results,
    sample_cases,
)
from .scoring import finalize, load_rater, validate_scores, write_agreement_outputs
from .util import RepairEvalError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repair_eval",
        description=(
            "Blind human evaluation for SecVulEval repair outputs. Standard library only. "
            "This tool does not compile code or run exploits."
        ),
    )
    parser.add_argument("--version", action="version", version=f"repair_eval 0.1.0 ({RUBRIC_VERSION})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser(
        "build",
        help="build a blind review package from real runner results.jsonl files",
    )
    build.add_argument("--results", nargs="+", required=True, help="one or more real results.jsonl files")
    build.add_argument("--dataset", required=True, help="pairs dataset JSON (vulnerable_fixed_200_pairs.json)")
    build.add_argument("--out-dir", required=True, help="new output directory")
    build.add_argument("--seed", type=int, default=20261111, help="fixed sampling seed")
    build.add_argument(
        "--pairs",
        type=int,
        default=MAX_PAIRS,
        help=f"number of pairs to sample ({MIN_PAIRS}–{MAX_PAIRS}); default {MAX_PAIRS}",
    )
    build.add_argument("--max-function-chars", type=int, default=4000)
    build.add_argument("--max-per-project", type=int, default=2, help="project cap; 0 means unlimited")
    build.add_argument(
        "--min-candidates-per-case",
        type=int,
        default=2,
        help="minimum number of strategies with valid repair output per selected case",
    )
    build.add_argument(
        "--strategies",
        nargs="+",
        choices=("direct", "few-shot", "context"),
        default=None,
        help="strategies to include; default is every strategy with valid output",
    )
    build.add_argument(
        "--hide-reference",
        action="store_true",
        help="omit the upstream fixed version entirely (stricter blinding)",
    )
    build.add_argument(
        "--allow-missing-manifest",
        action="store_true",
        help="allow archived real results without a sibling manifest.json",
    )
    build.add_argument(
        "--allow-incomplete-runs",
        action="store_true",
        help="allow results whose runner manifest is not 'completed'",
    )
    build.add_argument(
        "--allow-multiple-models",
        action="store_true",
        help="allow mixing model IDs across result files (not a fair method comparison)",
    )
    build.add_argument(
        "--allow-local-endpoint",
        action="store_true",
        help="allow a verified local endpoint; never use for mock results",
    )

    agreement = subparsers.add_parser(
        "agreement",
        help="import two raters, compute Cohen's kappa, and write an adjudication template",
    )
    agreement.add_argument("--package", required=True)
    agreement.add_argument("--rater-a", required=True)
    agreement.add_argument("--rater-b", required=True)
    agreement.add_argument("--out-dir", required=True)
    agreement.add_argument("--rater-a-id", default=None)
    agreement.add_argument("--rater-b-id", default=None)
    agreement.add_argument("--seed", type=int, default=None, help="default: package seed")
    agreement.add_argument("--bootstrap", type=int, default=2000, help="bootstrap iterations; 0 disables")

    final = subparsers.add_parser(
        "finalize",
        help="apply adjudication and write the final summary",
    )
    final.add_argument("--package", required=True)
    final.add_argument("--rater-a", required=True)
    final.add_argument("--rater-b", required=True)
    final.add_argument("--adjudication", default=None)
    final.add_argument("--out-dir", required=True)
    final.add_argument("--rater-a-id", default=None)
    final.add_argument("--rater-b-id", default=None)
    final.add_argument("--seed", type=int, default=None, help="default: package seed")
    final.add_argument("--bootstrap", type=int, default=2000, help="bootstrap iterations; 0 disables")

    verify = subparsers.add_parser("verify", help="verify package hashes and blindness checks")
    verify.add_argument("--package", required=True)

    selftest = subparsers.add_parser(
        "selftest",
        help="run a temporary synthetic end-to-end test and delete it",
    )
    selftest.add_argument("--bootstrap", type=int, default=200, help=argparse.SUPPRESS)
    return parser


def _cmd_build(args: argparse.Namespace) -> int:
    if not MIN_PAIRS <= args.pairs <= MAX_PAIRS:
        raise RepairEvalError(f"--pairs must be between {MIN_PAIRS} and {MAX_PAIRS}")
    if args.min_candidates_per_case < 1:
        raise RepairEvalError("--min-candidates-per-case must be at least 1")
    if args.max_per_project < 0:
        raise RepairEvalError("--max-per-project must be 0 or greater")
    if args.max_function_chars <= 0:
        raise RepairEvalError("--max-function-chars must be positive")
    dataset = load_pairs_dataset(args.dataset)
    by_pair, files, excluded, models = load_results(
        args.results,
        dataset,
        allow_missing_manifest=args.allow_missing_manifest,
        allow_incomplete_runs=args.allow_incomplete_runs,
        allow_local_endpoint=args.allow_local_endpoint,
    )
    if len(models) > 1 and not args.allow_multiple_models:
        raise RepairEvalError(
            f"multiple model IDs found: {models}. A fair strategy comparison needs one "
            "fixed base model; use --allow-multiple-models only for an explicitly "
            "labelled sensitivity analysis."
        )
    strategies = tuple(args.strategies) if args.strategies else None
    frame, frame_exclusions, selected_strategies, frame_size = build_frame(
        dataset,
        by_pair,
        strategies=strategies,
        min_candidates_per_case=args.min_candidates_per_case,
        max_function_chars=args.max_function_chars,
    )
    if frame_size < MIN_PAIRS:
        raise RepairEvalError(
            f"only {frame_size} eligible pairs with valid repair output; a blind package "
            f"needs at least {MIN_PAIRS}. The sampling frame excludes: {frame_exclusions}. "
            "Do not use synthetic data to fill this gap."
        )
    sampling = sample_cases(
        frame,
        requested_pairs=args.pairs,
        seed=args.seed,
        max_per_project=args.max_per_project,
    )
    sampling.frame_exclusions = frame_exclusions
    result = build_blind_package(
        dataset=dataset,
        results_files=files,
        sampling=sampling,
        strategies=selected_strategies,
        seed=args.seed,
        out_dir=args.out_dir,
        hide_reference=args.hide_reference,
        frame_exclusions=frame_exclusions,
        guards={
            "manifest_required": not args.allow_missing_manifest,
            "completed_run_required": not args.allow_incomplete_runs,
            "single_model_required": not args.allow_multiple_models,
            "local_endpoint_allowed": args.allow_local_endpoint,
            "http_200_repair_required": True,
        },
    )
    print(f"Built blind package: {result['package_dir']}")
    print(f"Package ID: {result['package_id']}")
    print(f"Cases: {result['cases']}; candidates: {result['candidates']}")
    print(f"Candidates by strategy: {json.dumps(result['by_strategy'], ensure_ascii=False)}")
    print(f"Models: {json.dumps(models, ensure_ascii=False)}")
    print(f"Sampling frame: {frame_size}; exclusions: {json.dumps(frame_exclusions, ensure_ascii=False)}")
    if result["warnings"]:
        print(f"Sampling warnings: {json.dumps(result['warnings'], ensure_ascii=False)}")
    print("Package verification: OK")
    print(
        "Reminder: this package supports human quality review only. It does not prove "
        "compilation, behavior preservation, or exploit removal."
    )
    return 0


def _load_for_scoring(args: argparse.Namespace) -> tuple[dict, dict, Path, int]:
    package, info = load_package(args.package)
    package_dir = info["root"]
    seed = args.seed if args.seed is not None else int(package["seed"])
    return package, info, package_dir, seed


def _cmd_agreement(args: argparse.Namespace) -> int:
    if args.bootstrap < 0:
        raise RepairEvalError("--bootstrap must be non-negative")
    package, info, package_dir, seed = _load_for_scoring(args)
    rater_a = load_rater(args.rater_a, rater_id=args.rater_a_id)
    rater_b = load_rater(args.rater_b, rater_id=args.rater_b_id)
    validate_scores(package, rater_a)
    validate_scores(package, rater_b)
    agreement = write_agreement_outputs(
        package,
        rater_a,
        rater_b,
        out_dir=args.out_dir,
        seed=seed,
        bootstrap=args.bootstrap,
    )
    print(f"Agreement report: {Path(args.out_dir).resolve()}")
    print(f"Candidates: {agreement['n_candidates']}")
    for dimension, item in agreement["by_dimension"].items():
        print(
            f"{dimension}: exact={item['percent_agreement']:.3f} "
            f"kappa={item['unweighted_kappa']} weighted={item['quadratic_weighted_kappa']} "
            f"disagreements={item['disagreement_count']}"
        )
    print(
        "Dimension-level disagreements: "
        f"{agreement['disagreement_summary']['total_dimension_disagreements']}; "
        f"adjudication template: {Path(args.out_dir, 'adjudication.tsv')}"
    )
    return 0


def _cmd_finalize(args: argparse.Namespace) -> int:
    if args.bootstrap < 0:
        raise RepairEvalError("--bootstrap must be non-negative")
    package, info, package_dir, seed = _load_for_scoring(args)
    rater_a = load_rater(args.rater_a, rater_id=args.rater_a_id)
    rater_b = load_rater(args.rater_b, rater_id=args.rater_b_id)
    validate_scores(package, rater_a)
    validate_scores(package, rater_b)
    summary = finalize(
        package,
        package_dir,
        rater_a,
        rater_b,
        adjudication_path=args.adjudication,
        out_dir=args.out_dir,
        seed=seed,
        bootstrap=args.bootstrap,
    )
    overall = summary["final"]["overall"]
    print(f"Final summary: {Path(args.out_dir).resolve()}")
    print(
        f"Primary pass: {overall['primary_pass_count']}/{summary['n_candidates']} "
        f"({overall['primary_pass_rate']:.3f})"
    )
    print(
        f"Strict pass: {overall['strict_pass_count']}/{summary['n_candidates']} "
        f"({overall['strict_pass_rate']:.3f})"
    )
    print(f"Adjudicated dimensions: {summary['adjudication']['adjudicated_count']}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    report = verify_package(args.package)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _cmd_selftest(args: argparse.Namespace) -> int:
    from .selftest import run_selftest

    run_selftest(bootstrap=args.bootstrap)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            return _cmd_build(args)
        if args.command == "agreement":
            return _cmd_agreement(args)
        if args.command == "finalize":
            return _cmd_finalize(args)
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "selftest":
            return _cmd_selftest(args)
        parser.error(f"unknown command {args.command!r}")
    except RepairEvalError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

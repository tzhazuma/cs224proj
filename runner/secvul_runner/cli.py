"""Command-line interface for the SecVulEval experiment runner."""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from . import __version__
from .client import DEFAULT_USER_AGENT, ApiConfig, ApiConfigurationError, normalize_endpoint
from .experiment import (
    DEFAULT_BASE_URL,
    ExperimentError,
    RunOutcome,
    create_settings,
    run_dry_run,
    run_experiment,
)

LOGGER = logging.getLogger("secvul_runner")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_dataset_path(dataset_type: str) -> Path:
    name = "independent_200.json" if dataset_type == "independent" else "vulnerable_fixed_200_pairs.json"
    return _project_root() / "datasets" / name


def _default_out_dir(dataset: str, strategy: str, task: str, dry_run: bool) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = "_dryrun" if dry_run else ""
    base = _project_root() / "runner" / "runs" / f"{stamp}_{dataset}_{strategy}_{task}{suffix}"
    candidate = base
    counter = 2
    while candidate.exists():
        candidate = base.with_name(f"{base.name}_{counter}")
        counter += 1
    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secvul-runner",
        description=(
            "Run resumable SecVulEval LLM experiments against an OpenAI-compatible "
            "Chat Completions endpoint. No model results are fabricated: a dry run never "
            "calls a model, and metrics only summarise recorded API responses."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--dataset",
        required=True,
        choices=("independent", "pairs"),
        help="independent = independent_200.json; pairs = vulnerable_fixed_200_pairs.json",
    )
    parser.add_argument(
        "--dataset-file",
        type=Path,
        default=None,
        help="Override the dataset path (default: project datasets/<canonical name>).",
    )
    parser.add_argument(
        "--strategy",
        required=True,
        choices=("direct", "few-shot", "context"),
        help="Prompting strategy. context uses only sanitised allow-listed context sections.",
    )
    parser.add_argument(
        "--task",
        default="detection",
        choices=("detection", "repair", "both"),
        help="Task(s) to run. repair sends only vulnerable/original functions.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model identifier. No model is hardcoded. Defaults to $SECVUL_MODEL or "
            "$DEEPSEEK_MODEL."
        ),
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            "OpenAI-compatible base URL or full /chat/completions endpoint. Defaults to "
            "$SECVUL_BASE_URL, $DEEPSEEK_BASE_URL, or https://api.deepseek.com/v1."
        ),
    )
    parser.add_argument(
        "--api-key-env",
        default="DEEPSEEK_API_KEY",
        help="Environment variable holding the API key (default: DEEPSEEK_API_KEY).",
    )
    parser.add_argument(
        "--user-agent",
        default=os.environ.get("SECVUL_USER_AGENT") or DEFAULT_USER_AGENT,
        help=(
            "User-Agent sent with every request. Defaults to $SECVUL_USER_AGENT or "
            f"{DEFAULT_USER_AGENT}; OpenCode Go asks clients to identify themselves."
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Run directory. Defaults to runner/runs/<UTC timestamp>_<dataset>_<strategy>_<task>.",
    )
    parser.add_argument(
        "--dev-examples",
        type=Path,
        default=None,
        help="Few-shot examples JSON; only valid with --strategy few-shot. Defaults to bundled synthetic examples.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help=(
            "Run only the first N units (independent samples or pairs). 0 = all. "
            "A limited run is marked partial and must not be reported as full-dataset evidence."
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Concurrent HTTP requests (1-32; default 1 for easiest rate-limit behaviour).",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature (default 0.0; recorded in the manifest).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=8192,
        help="Maximum generated tokens per request (default 8192).",
    )
    parser.add_argument(
        "--max-tokens-field",
        choices=("max_tokens", "max_completion_tokens"),
        default="max_tokens",
        help=(
            "Request field used for the output limit. MiMo's native API uses "
            "max_completion_tokens (reasoning + answer); the default keeps the legacy "
            "max_tokens field."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-request timeout in seconds (default 120).",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="Maximum HTTP attempts per request on retryable failures (default 3).",
    )
    parser.add_argument(
        "--backoff-base",
        type=float,
        default=1.5,
        help="Initial exponential-backoff delay in seconds (default 1.5).",
    )
    parser.add_argument(
        "--backoff-cap",
        type=float,
        default=30.0,
        help="Maximum backoff delay in seconds (default 30).",
    )
    parser.add_argument(
        "--response-format",
        choices=("json_object", "none"),
        default="json_object",
        help="Send response_format={'type':'json_object'} (default) or omit it.",
    )
    parser.add_argument(
        "--thinking",
        choices=("default", "enabled", "disabled"),
        default=None,
        help=(
            "Send thinking={'type': <value>} to providers that support it. Omit to keep the "
            "legacy behaviour: disabled for deepseek-* models, untouched for other models."
        ),
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "minimal", "low", "medium", "high"),
        default=None,
        help=(
            "Send reasoning_effort=<value> when the provider supports it. MiMo on OpenCode Go "
            "honours 'none' (no reasoning tokens) even though top-level thinking is ignored."
        ),
    )
    parser.add_argument(
        "--input-price-usd-per-1m",
        type=float,
        default=None,
        help="Optional supplied input-token price in USD per 1M tokens. Cost stays null if omitted.",
    )
    parser.add_argument(
        "--output-price-usd-per-1m",
        type=float,
        default=None,
        help="Optional supplied output-token price in USD per 1M tokens. Cost stays null if omitted.",
    )
    parser.add_argument(
        "--cached-input-price-usd-per-1m",
        type=float,
        default=None,
        help="Optional supplied cached-input price per 1M tokens; only used when reported by the API.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and validate prompts/requests only. Makes no API call and produces no metrics.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume an existing run directory; the configuration fingerprint must match.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="With --resume, ignore cached responses and call the API again for every request.",
    )
    parser.add_argument(
        "--retry-invalid",
        action="store_true",
        help="With --resume, re-call requests whose cached response was schema-invalid.",
    )
    parser.add_argument(
        "--reuse-cached-errors",
        action="store_true",
        help="With --resume, keep cached API-error records instead of retrying them.",
    )
    parser.add_argument(
        "--run-label",
        default=None,
        help="Optional human-readable label stored in artifacts; does not affect requests.",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Console log level (default INFO).",
    )
    return parser


def _resolve_model(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    model = args.model or os.environ.get("SECVUL_MODEL") or os.environ.get("DEEPSEEK_MODEL")
    if not model:
        parser.error(
            "no model specified; pass --model or set SECVUL_MODEL/DEEPSEEK_MODEL. "
            "The runner does not hardcode a model name."
        )
    return model


def _resolve_base_url(args: argparse.Namespace) -> str:
    if args.base_url:
        return args.base_url
    return (
        os.environ.get("SECVUL_BASE_URL")
        or os.environ.get("DEEPSEEK_BASE_URL")
        or DEFAULT_BASE_URL
    )


def _print_dry_run(outcome: RunOutcome) -> None:
    print(f"DRY RUN completed: {outcome.request_count} request(s) validated.")
    print(f"  request file: {outcome.out_dir / 'dry_run_requests.jsonl'}")
    print(f"  summary:      {outcome.manifest_path}")
    print("  No API call was made. No experimental results or metrics were produced.")


def _print_real_run(outcome: RunOutcome) -> None:
    metrics = outcome.metrics or {}
    print(f"Run {outcome.status}: {outcome.request_count} request(s).")
    if metrics:
        counts = metrics.get("counts", {})
        print(f"  records: {counts.get('records')} (cache hits {counts.get('cache_hits')})")
        detection = metrics.get("detection")
        if detection:
            valid = detection["metrics_valid_only"]
            print(
                "  detection (valid only): "
                f"precision={valid['precision']} recall={valid['recall']} f1={valid['f1']} "
                f"coverage={detection['coverage']}"
            )
        pair_joint = metrics.get("pair_joint")
        if pair_joint:
            print(
                "  pair discrimination (valid pairs)="
                f"{pair_joint['discrimination_accuracy_valid_pairs']}"
            )
        repair = metrics.get("repair")
        if repair:
            print(
                "  repair schema-valid="
                f"{repair['schema_valid']}/{repair['requested']}, "
                "complete-function (schema-valid)="
                f"{repair['complete_function']}/{repair['schema_valid']}"
            )
        cost = metrics.get("cost", {})
        print(f"  total cost USD: {cost.get('total_cost_usd')} (null = unavailable)")
        if metrics.get("run", {}).get("partial"):
            print("  PARTIAL RUN: --limit was used; do not report as full-dataset results.")
    print(f"  metrics: {outcome.metrics_path}")
    print(f"  results: {outcome.results_path}")
    print(f"  manifest: {outcome.manifest_path}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Never let HTTP client debug logging leak the Authorization header.
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    if args.dry_run and args.resume:
        parser.error("--dry-run cannot be combined with --resume")
    if args.dry_run and args.refresh:
        parser.error("--dry-run cannot be combined with --refresh")
    if args.dry_run and (args.retry_invalid or args.reuse_cached_errors):
        parser.error("--dry-run cannot be combined with --retry-invalid or --reuse-cached-errors")
    if args.refresh and not args.resume:
        parser.error("--refresh requires --resume (or choose a new --out-dir)")
    if args.retry_invalid and not args.resume:
        parser.error("--retry-invalid requires --resume")
    if args.reuse_cached_errors and not args.resume:
        parser.error("--reuse-cached-errors requires --resume")
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.concurrency < 1 or args.concurrency > 32:
        parser.error("--concurrency must be between 1 and 32")
    if not args.api_key_env or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.api_key_env) is None:
        parser.error("--api-key-env must look like an environment variable name")

    model = _resolve_model(args, parser)
    base_url = _resolve_base_url(args)
    try:
        endpoint = normalize_endpoint(base_url)
        api_config = ApiConfig(
            base_url=base_url,
            endpoint=endpoint,
            model=model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout_seconds=args.timeout,
            max_attempts=args.max_attempts,
            backoff_base_seconds=args.backoff_base,
            backoff_cap_seconds=args.backoff_cap,
            response_format=args.response_format,
            thinking=args.thinking,
            reasoning_effort=args.reasoning_effort,
            max_tokens_field=args.max_tokens_field,
            user_agent=args.user_agent,
            input_price_usd_per_1m=args.input_price_usd_per_1m,
            output_price_usd_per_1m=args.output_price_usd_per_1m,
            cached_input_price_usd_per_1m=args.cached_input_price_usd_per_1m,
        )
        api_config.validate()
    except (ApiConfigurationError, ValueError) as exc:
        parser.error(str(exc))

    dataset_path = args.dataset_file or _default_dataset_path(args.dataset)
    out_dir = args.out_dir or _default_out_dir(
        args.dataset, args.strategy, args.task, args.dry_run
    )
    try:
        settings = create_settings(
            dataset_type=args.dataset,
            dataset_path=dataset_path,
            strategy=args.strategy,
            task=args.task,
            api_config=api_config,
            api_key_env=args.api_key_env,
            out_dir=out_dir,
            dev_examples_path=args.dev_examples,
            limit=args.limit,
            concurrency=args.concurrency,
            dry_run=args.dry_run,
            resume=args.resume,
            refresh=args.refresh,
            retry_invalid=args.retry_invalid,
            reuse_cached_errors=args.reuse_cached_errors,
            run_label=args.run_label,
        )
        if args.dry_run:
            outcome = run_dry_run(settings)
            _print_dry_run(outcome)
            return 0
        api_key = os.environ.get(settings.api_key_env, "").strip()
        if not api_key:
            print(
                f"ERROR: environment variable {settings.api_key_env} is not set or is empty. "
                "Set it in the environment; do not put the key in a command-line argument.",
                file=sys.stderr,
            )
            return 2
        outcome = run_experiment(settings, api_key)
        _print_real_run(outcome)
        return 0
    except KeyboardInterrupt:
        print(
            "Interrupted. Completed per-request results are cached; rerun the same command with "
            "--resume and the same --out-dir.",
            file=sys.stderr,
        )
        return 130
    except (ExperimentError, ApiConfigurationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        LOGGER.exception("unexpected failure")
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

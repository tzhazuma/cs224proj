#!/usr/bin/env python3
"""Real API runner for the pair-joint A/B prompt.

One request per pair.  The runner is resumable through a per-request cache,
records full request bodies (without Authorization), usage, cost and latency,
and never writes an API key.  It is intentionally independent of the legacy
two-call ``runner`` so no existing artifact is touched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import platform
import sys
import time
import tomllib
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "runner") not in sys.path:
    sys.path.insert(0, str(ROOT / "runner"))

from secvul_runner.cache import RequestCache  # noqa: E402
from secvul_runner.client import (  # noqa: E402
    ApiConfig,
    ChatClient,
    build_body,
    canonical_json,
    compute_cost,
    generate_session_id,
    is_valid_session_id,
    normalize_endpoint,
    request_fingerprint,
    session_id_sha256,
    utc_now_iso,
)
from secvul_runner.util import atomic_write_json, atomic_write_text, sha256_file  # noqa: E402

from .common import (  # noqa: E402
    MAX_EVIDENCE_ITEMS,
    ORDER_SALT,
    PROMPT_VERSION,
    SCHEMA_VERSION,
    PairJointError,
    PairUnit,
    audit_dataset,
    audit_prompt,
    build_order_map,
    build_prompt,
    evaluate_output,
    load_pairs,
    order_map_sha256,
    parse_output,
)

LOGGER = logging.getLogger("pair_joint")
DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
DEFAULT_DATASET = ROOT / "splits" / "test_pairs_180.json"
DEFAULT_PILOT_DATASET = ROOT / "splits" / "pilot_pairs_18.json"
EXPECTED_TEST_SHA256 = "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d"
EXPECTED_PILOT_SHA256 = "e237137718a973af0a1c9cde1fc7ecf594b51feb6ce5600f5a47894f29e54747"


@dataclass(frozen=True)
class RequestSpec:
    index: int
    unit: PairUnit
    assignment: dict[str, Any]
    prompt: Any
    body: dict[str, Any]
    endpoint: str
    fingerprint: str


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _selected_units(units: list[PairUnit], limit: int) -> list[PairUnit]:
    if limit <= 0 or limit >= len(units):
        return list(units)
    return units[:limit]


def _default_out_dir(model: str, limit: int) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_model = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in model)
    suffix = f"_limit{limit}" if limit else "_full"
    return ROOT / "pair_joint" / "runs" / f"{stamp}_{safe_model}{suffix}"


def _build_specs(
    units: list[PairUnit],
    order_map: dict[str, Any],
    api_config: ApiConfig,
) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for index, unit in enumerate(units, start=1):
        assignment = order_map["assignments"][unit.pair_id]
        prompt = build_prompt(unit, assignment)
        body = build_body(list(prompt.messages), api_config)
        fingerprint = request_fingerprint(
            endpoint=api_config.endpoint,
            body=body,
            task="pair_decision",
            strategy="pair_joint",
            prompt_version=PROMPT_VERSION,
        )
        specs.append(
            RequestSpec(
                index=index,
                unit=unit,
                assignment=assignment,
                prompt=prompt,
                body=body,
                endpoint=api_config.endpoint,
                fingerprint=fingerprint,
            )
        )
    return specs


def _request_record(spec: RequestSpec, prompt_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "request_index": spec.index,
        "pair_id": spec.unit.pair_id,
        "prompt": spec.prompt.metadata,
        "prompt_sha256": prompt_sha256,
        "request": {
            "endpoint": spec.endpoint,
            "model": spec.body.get("model"),
            "request_fingerprint": spec.fingerprint,
            "body_sha256": _sha256_text(canonical_json(spec.body)),
            "messages_sha256": _sha256_text(canonical_json(list(spec.prompt.messages))),
        },
        "messages": list(spec.prompt.messages),
        "body": spec.body,
        "authorization_header_omitted": True,
    }


def _response_record(result: Any) -> dict[str, Any]:
    payload = result.to_dict()
    raw_body = payload.pop("raw_body", None)
    payload["raw_body_sha256"] = _sha256_text(raw_body or "")
    payload["attempts"] = [
        {key: value for key, value in attempt.items() if key != "raw_body"}
        for attempt in payload.get("attempts") or []
    ]
    return payload


def _config_fingerprint(
    *,
    api_config: ApiConfig,
    dataset_sha256: str,
    selected_units: int,
    limit: int,
    api_key_env: str,
) -> str:
    identity = {
        "api": api_config.public_dict(),
        "api_key_env": api_key_env,
        "dataset_sha256": dataset_sha256,
        "selected_units": selected_units,
        "limit": limit,
        "order_salt": ORDER_SALT,
        "prompt_version": PROMPT_VERSION,
        "max_evidence_items": MAX_EVIDENCE_ITEMS,
    }
    return _sha256_text(canonical_json(identity))


def _aggregate_usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "recorded": len(records),
        "with_usage": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached_prompt_tokens": 0,
        "reasoning_tokens": 0,
        "reasoning_tokens_known": 0,
        "cost_usd": 0.0,
        "records_with_cost": 0,
    }
    for record in records:
        response = record.get("response") or {}
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else None
        if usage:
            totals["with_usage"] += 1
            for key in ("prompt_tokens", "completion_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    totals[key] += value
            cached = usage.get("prompt_cache_hit_tokens")
            if not isinstance(cached, int):
                details = usage.get("prompt_tokens_details")
                cached = details.get("cached_tokens") if isinstance(details, dict) else None
            if isinstance(cached, int) and not isinstance(cached, bool):
                totals["cached_prompt_tokens"] += cached
            details = usage.get("completion_tokens_details")
            reasoning = details.get("reasoning_tokens") if isinstance(details, dict) else None
            if isinstance(reasoning, int) and not isinstance(reasoning, bool):
                totals["reasoning_tokens"] += reasoning
                totals["reasoning_tokens_known"] += 1
        cost = response.get("cost") if isinstance(response.get("cost"), dict) else None
        value = cost.get("cost_usd") if cost else None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            totals["cost_usd"] += float(value)
            totals["records_with_cost"] += 1
    totals["cost_usd"] = round(totals["cost_usd"], 12) if totals["records_with_cost"] else None
    return totals


def _latency_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    values = []
    for record in records:
        response = record.get("response") or {}
        value = response.get("request_latency_seconds")
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
            values.append(float(value))
    if not values:
        return {"n": 0, "mean": None, "p50": None, "p95": None, "max": None}
    ordered = sorted(values)

    def pct(fraction: float) -> float:
        position = (len(ordered) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return ordered[lower]
        return ordered[lower] * (1 - (position - lower)) + ordered[upper] * (position - lower)

    return {
        "n": len(values),
        "mean": round(sum(values) / len(values), 6),
        "p50": round(pct(0.5), 6),
        "p95": round(pct(0.95), 6),
        "max": round(max(values), 6),
    }


def _metrics(records: list[dict[str, Any]], *, run_id: str, partial: bool, limit: int, settings: dict[str, Any]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    error_codes: dict[str, int] = {}
    for record in records:
        status = str(record.get("status"))
        statuses[status] = statuses.get(status, 0) + 1
        if status != "ok":
            validation = record.get("validation") or {}
            code = str(validation.get("error_code") or status)
            error_codes[code] = error_codes.get(code, 0) + 1
    usage = _aggregate_usage(records)
    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "run_id": run_id,
            "model": settings["api"]["model"],
            "prompt_version": PROMPT_VERSION,
            "partial": partial,
            "limit": limit,
            "selected_units": len(records),
            "started_at": settings.get("started_at"),
            "completed_at": utc_now_iso(),
        },
        "counts": {
            "recorded": len(records),
            "by_status": statuses,
            "error_codes": error_codes,
        },
        "usage": usage,
        "latency_seconds": _latency_summary(records),
        "notes": [
            "Cost is null when the provider did not report token usage or prices were not configured.",
            "A partial run used --limit and must not be reported as full-dataset evidence.",
        ],
    }


def _write_if_absent_or_same(path: Path, text: str) -> None:
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing != text:
            raise PairJointError(
                f"{path} already exists with different content; use a new --out-dir "
                "or the original configuration for --resume"
            )
        return
    atomic_write_text(path, text)


def _resolve_credentials(args: argparse.Namespace) -> tuple[str, str | None]:
    key: str | None = None
    provider_base_url: str | None = None
    if args.kimi_config:
        try:
            with Path(args.kimi_config).open("rb") as stream:
                config = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PairJointError(f"cannot read Kimi config: {exc}") from exc
        provider = config.get("providers", {}).get(args.kimi_provider)
        if not isinstance(provider, dict):
            raise PairJointError(f"provider not found in Kimi config: {args.kimi_provider}")
        candidate = provider.get("api_key")
        if isinstance(candidate, str) and candidate.strip():
            key = candidate.strip()
        candidate_url = provider.get("base_url")
        if isinstance(candidate_url, str) and candidate_url.strip():
            provider_base_url = candidate_url.strip()
    if key is None:
        key = os.environ.get(args.api_key_env, "").strip() or None
    if key is None:
        raise PairJointError(
            f"no API key: set {args.api_key_env} or pass --kimi-config with a provider that has api_key"
        )
    return key, provider_base_url


def _check_no_secret(out_dir: Path, key: str) -> None:
    """Fail loudly if the key somehow reached an artifact."""
    if not key:
        return
    for path in out_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if key in text:
            raise PairJointError(f"API key found in artifact {path}; refusing to continue")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--kimi-config", type=Path, default=None)
    parser.add_argument("--kimi-provider", default="opencode-go")
    parser.add_argument("--api-key-env", default="OPENCODE_API_KEY")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--backoff-base", type=float, default=1.5)
    parser.add_argument("--backoff-cap", type=float, default=30.0)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--max-tokens-field", choices=("max_tokens", "max_completion_tokens"), default="max_tokens")
    parser.add_argument("--thinking", choices=("default", "enabled", "disabled"), default=None)
    parser.add_argument("--reasoning-effort", choices=("none", "minimal", "low", "medium", "high"), default=None)
    parser.add_argument("--response-format", choices=("json_object", "none"), default="json_object")
    parser.add_argument("--input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--output-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--cached-input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--expect-sha256", default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-invalid", action="store_true")
    parser.add_argument("--reuse-cached-errors", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    if args.concurrency < 1 or args.concurrency > 32:
        parser.error("--concurrency must be between 1 and 32")
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.dry_run and args.resume:
        parser.error("--dry-run cannot be combined with --resume")
    if args.resume and not args.out_dir:
        parser.error("--resume requires the original --out-dir")

    try:
        units_all, dataset_metadata, dataset_sha256 = load_pairs(args.dataset)
    except PairJointError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.expect_sha256 and dataset_sha256 != args.expect_sha256:
        print(
            f"ERROR: dataset SHA-256 {dataset_sha256} does not match expected {args.expect_sha256}",
            file=sys.stderr,
        )
        return 2
    units = _selected_units(units_all, args.limit)
    if not units:
        print("ERROR: no pairs selected", file=sys.stderr)
        return 2
    partial = len(units) < len(units_all)
    order_map = build_order_map(units)

    key = ""
    provider_base_url = None
    if not args.dry_run:
        try:
            key, provider_base_url = _resolve_credentials(args)
        except PairJointError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    base_url = args.base_url or provider_base_url or os.environ.get("SECVUL_BASE_URL") or DEFAULT_BASE_URL
    try:
        endpoint = normalize_endpoint(base_url)
        api_config = ApiConfig(
            base_url=base_url,
            endpoint=endpoint,
            model=args.model,
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
            user_agent="secvul-pair-joint/1.0",
            input_price_usd_per_1m=args.input_price_usd_per_1m,
            output_price_usd_per_1m=args.output_price_usd_per_1m,
            cached_input_price_usd_per_1m=args.cached_input_price_usd_per_1m,
        )
        api_config.validate()
    except (ValueError, PairJointError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out_dir = args.out_dir or _default_out_dir(args.model, args.limit)
    if out_dir.exists() and not args.resume and not args.dry_run:
        print(f"ERROR: output directory already exists: {out_dir}; use --resume or a new directory", file=sys.stderr)
        return 2
    if args.resume and not (out_dir / "manifest.json").exists():
        print(f"ERROR: --resume requested but {out_dir}/manifest.json does not exist", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    config_fingerprint = _config_fingerprint(
        api_config=api_config,
        dataset_sha256=dataset_sha256,
        selected_units=len(units),
        limit=args.limit,
        api_key_env=args.api_key_env,
    )
    previous_manifest: dict[str, Any] | None = None
    if (out_dir / "manifest.json").exists():
        try:
            previous_manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: cannot read previous manifest: {exc}", file=sys.stderr)
            return 2
        if args.resume and previous_manifest.get("config_fingerprint") != config_fingerprint:
            print(
                "ERROR: configuration fingerprint changed; refusing to mix results in the same run directory",
                file=sys.stderr,
            )
            return 2

    specs = _build_specs(units, order_map, api_config)
    prompt_sha256 = {spec.unit.pair_id: spec.prompt.sha256() for spec in specs}
    audits = [
        audit_prompt(spec.unit, spec.assignment, spec.prompt)
        for spec in specs
    ]
    bad = [audit for audit in audits if not audit["wrapper_clean"] or audit["slot_leak"]]
    if bad:
        print(f"ERROR: prompt leakage audit failed for {len(bad)} pairs, e.g. {bad[0]}", file=sys.stderr)
        return 2
    dataset_audit = audit_dataset(units)

    session_id = generate_session_id()
    if previous_manifest:
        old_session = (previous_manifest.get("api") or {}).get("session") or {}
        candidate = old_session.get("value")
        if is_valid_session_id(candidate):
            session_id = candidate
    session_info = {
        "header": "x-opencode-session",
        "is_secret": False,
        "source": "generated" if not previous_manifest else "reused",
        "value": session_id,
        "sha256": session_id_sha256(session_id),
        "note": "Random per-run identifier for request routing; it is not an API key.",
    }

    started_at = (previous_manifest or {}).get("started_at") or utc_now_iso()
    config_record = {
        "schema_version": SCHEMA_VERSION,
        "runner": "pair_joint.runner",
        "runner_version": "1.0.0",
        "prompt_version": PROMPT_VERSION,
        "order_salt": ORDER_SALT,
        "max_evidence_items": MAX_EVIDENCE_ITEMS,
        "api": api_config.public_dict(),
        "api_key_env": args.api_key_env,
        "api_key_present": bool(key) or bool(previous_manifest),
        "api_key_value_stored": False,
        "session": session_info,
        "dataset_path": str(args.dataset.relative_to(ROOT)) if args.dataset.is_relative_to(ROOT) else str(args.dataset),
        "dataset_sha256": dataset_sha256,
        "dataset_metadata": {
            key_name: dataset_metadata.get(key_name)
            for key_name in ("schema_version", "split", "source_file", "source_sha256")
            if key_name in dataset_metadata
        },
        "dataset_units_total": len(units_all),
        "selected_units": len(units),
        "limit": args.limit,
        "partial": partial,
        "concurrency": args.concurrency,
        "run_label": args.run_label,
        "config_fingerprint": config_fingerprint,
        "started_at": started_at,
        "out_dir": str(out_dir.relative_to(ROOT)) if out_dir.is_relative_to(ROOT) else str(out_dir),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
    }
    if args.dry_run:
        dry_requests = out_dir / "dry_run_requests.jsonl"
        lines = [
            json.dumps(_request_record(spec, prompt_sha256[spec.unit.pair_id]), ensure_ascii=False)
            for spec in specs
        ]
        atomic_write_text(dry_requests, "\n".join(lines) + "\n")
        manifest = {
            **config_record,
            "dry_run": True,
            "no_api_calls": True,
            "experimental_results": False,
            "counts": {"planned_requests": len(specs)},
            "leakage_audit": {
                "wrapper_clean_all": True,
                "slot_leak_all": False,
                "dataset": dataset_audit,
            },
            "outputs": {"requests": dry_requests.name},
            "created_at": utc_now_iso(),
        }
        atomic_write_json(out_dir / "dry_run_manifest.json", manifest)
        print(f"DRY RUN: {len(specs)} pair request(s) validated; no API call was made.")
        print(f"  requests: {dry_requests}")
        print(f"  manifest: {out_dir / 'dry_run_manifest.json'}")
        return 0

    position_map = {
        "schema_version": SCHEMA_VERSION,
        **order_map,
        "sha256": order_map_sha256(order_map),
    }
    atomic_write_json(out_dir / "position_map.json", position_map)
    atomic_write_json(
        out_dir / "leak_audit.json",
        {
            "schema_version": SCHEMA_VERSION,
            "wrapper_clean_all": True,
            "slot_leak_all": False,
            "dataset": dataset_audit,
            "pairs": audits,
        },
    )
    atomic_write_json(out_dir / "config.json", config_record)
    requests_text = "\n".join(
        json.dumps(_request_record(spec, prompt_sha256[spec.unit.pair_id]), ensure_ascii=False)
        for spec in specs
    ) + "\n"
    _write_if_absent_or_same(out_dir / "requests.jsonl", requests_text)

    manifest = {
        **config_record,
        "run_id": out_dir.name,
        "status": "running",
        "created_at": (previous_manifest or {}).get("created_at") or utc_now_iso(),
        "updated_at": utc_now_iso(),
        "counts": {"planned_requests": len(specs), "recorded_requests": 0},
        "order": {
            "salt": ORDER_SALT,
            "vulnerable_slot_counts": position_map["counts"],
            "position_map_sha256": position_map["sha256"],
        },
        "leakage_audit": {
            "wrapper_clean_all": True,
            "slot_leak_all": False,
            "dataset": dataset_audit,
        },
        "outputs": {
            "requests": "requests.jsonl",
            "results": "results.jsonl",
            "metrics": "metrics.json",
            "position_map": "position_map.json",
            "leak_audit": "leak_audit.json",
            "cache": "cache/",
        },
        "notes": [
            "No API key or Authorization header is stored in any artifact.",
            "The A/B -> vulnerable/fixed mapping is stored only in position_map.json, never in a prompt.",
            "Pair IDs in requests.jsonl are local bookkeeping; the model sees only the rendered messages.",
        ],
    }
    atomic_write_json(out_dir / "manifest.json", manifest)

    cache = RequestCache(out_dir / "cache")
    records: list[dict[str, Any]] = []
    started_monotonic = time.monotonic()

    def execute(spec: RequestSpec) -> dict[str, Any]:
        cached = None
        if not args.dry_run:
            cached = cache.read(
                dataset_type="pairs_joint",
                task="pair_decision",
                key=spec.fingerprint,
                request_fingerprint=spec.fingerprint,
            )
        if cached is not None:
            previous_status = cached.get("status")
            use_cached = previous_status == "ok" or (
                previous_status == "invalid" and not args.retry_invalid
            ) or (previous_status == "error" and args.reuse_cached_errors)
            if use_cached:
                record = dict(cached)
                for name in ("cache_schema_version", "cache_key", "request_fingerprint"):
                    record.pop(name, None)
                record["cache"] = {"hit": True, "previous_status": previous_status}
                record["request_index"] = spec.index
                return record

        try:
            result = client.complete(list(spec.prompt.messages))
            response = _response_record(result)
            parsed, validation = parse_output(result.content if result.status == "ok" else None)
            evaluation = evaluate_output(parsed, validation, spec.unit, spec.assignment)
            validation["evidence"] = evaluation
            validation["compliant"] = evaluation["compliant"]
            if result.status != "ok":
                status = "error"
                validation["error_code"] = "api_error"
            elif validation.get("decision_parsed") is None:
                status = "invalid"
            else:
                status = "ok"
            record = {
                "schema_version": SCHEMA_VERSION,
                "request_index": spec.index,
                "pair_id": spec.unit.pair_id,
                "prompt": spec.prompt.metadata,
                "prompt_sha256": prompt_sha256[spec.unit.pair_id],
                "request": {
                    "endpoint": spec.endpoint,
                    "model": api_config.model,
                    "request_fingerprint": spec.fingerprint,
                    "body_sha256": _sha256_text(canonical_json(spec.body)),
                },
                "response": response,
                "parsed": parsed,
                "validation": validation,
                "status": status,
                "created_at": utc_now_iso(),
                "completed_at": utc_now_iso(),
                "cache": {"hit": False, "previous_status": cached.get("status") if cached else None},
            }
        except Exception as exc:  # keep the run alive; record a real failure
            LOGGER.exception("request failed for %s", spec.unit.pair_id)
            record = {
                "schema_version": SCHEMA_VERSION,
                "request_index": spec.index,
                "pair_id": spec.unit.pair_id,
                "prompt": spec.prompt.metadata,
                "prompt_sha256": prompt_sha256[spec.unit.pair_id],
                "request": {
                    "endpoint": spec.endpoint,
                    "model": api_config.model,
                    "request_fingerprint": spec.fingerprint,
                    "body_sha256": _sha256_text(canonical_json(spec.body)),
                },
                "response": {
                    "status": "error",
                    "error": {"type": "runner_exception", "message": f"{type(exc).__name__}: {exc}"},
                    "usage": None,
                    "cost": {"cost_usd": None},
                    "request_latency_seconds": None,
                },
                "parsed": None,
                "validation": {
                    "json_parse_ok": False,
                    "schema_exact": False,
                    "decision_parsed": None,
                    "decision_valid": False,
                    "confidence_valid": False,
                    "evidence": {},
                    "compliant": False,
                    "error_code": "runner_exception",
                    "errors": [f"{type(exc).__name__}: {exc}"],
                },
                "status": "error",
                "created_at": utc_now_iso(),
                "completed_at": utc_now_iso(),
                "cache": {"hit": False, "previous_status": None},
            }

        cache.write(
            dataset_type="pairs_joint",
            task="pair_decision",
            key=spec.fingerprint,
            request_fingerprint=spec.fingerprint,
            record={key_name: value for key_name, value in record.items() if key_name != "cache"},
        )
        return record

    client = ChatClient(api_config, key, session_id=session_id)
    total = len(specs)
    completed = 0
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(execute, spec): spec for spec in specs}
            for future in as_completed(futures):
                record = future.result()
                records.append(record)
                completed += 1
                if completed % 10 == 0 or completed == total:
                    ok = sum(1 for item in records if item.get("status") == "ok")
                    LOGGER.info("progress %d/%d (ok=%d, elapsed=%.1fs)", completed, total, ok, time.monotonic() - started_monotonic)
    except KeyboardInterrupt:
        LOGGER.warning("interrupted after %d/%d requests; completed requests are cached", completed, total)
    finally:
        client.close()

    records.sort(key=lambda record: int(record.get("request_index") or 0))
    results_text = "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"
    atomic_write_text(out_dir / "results.jsonl", results_text)
    metrics = _metrics(records, run_id=out_dir.name, partial=partial, limit=args.limit, settings=config_record)
    atomic_write_json(out_dir / "metrics.json", metrics)

    statuses: dict[str, int] = {}
    for record in records:
        statuses[str(record.get("status"))] = statuses.get(str(record.get("status")), 0) + 1
    finished = len(records) == total
    manifest.update(
        {
            "status": "completed" if finished and statuses.get("error", 0) == 0 else (
                "completed_with_errors" if finished else "interrupted"
            ),
            "completed_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
            "counts": {
                "planned_requests": total,
                "recorded_requests": len(records),
                "by_status": statuses,
            },
            "metrics": metrics,
        }
    )
    atomic_write_json(out_dir / "manifest.json", manifest)
    _check_no_secret(out_dir, key)
    print(f"Run {manifest['status']}: {len(records)}/{total} pair requests.")
    print(f"  ok={statuses.get('ok', 0)} invalid={statuses.get('invalid', 0)} error={statuses.get('error', 0)}")
    print(f"  usage: {metrics['usage']}")
    print(f"  latency: {metrics['latency_seconds']}")
    print(f"  out: {out_dir}")
    return 0 if finished else 1


if __name__ == "__main__":
    raise SystemExit(main())

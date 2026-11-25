#!/usr/bin/env python3
"""Real API runner for CodeQL alert triage.

Two conditions are run per model:

``direct``
    The frozen ``juliet_llm`` zero-shot prompt, as a control.
``triage``
    A custom prompt that shows the cleaned source view and the CodeQL result
    (or says that the build failed), and asks for an alert verdict plus an
    independent leak verdict, with explicit ownership, alias, global-flow and
    cross-function-release evidence fields.

Requests are cached per unit/condition/prompt, the cache is resumable, and no
Authorization header, API key, or secret value is written to any artefact.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import socket
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from secvul_runner.cache import RequestCache  # noqa: E402
from secvul_runner.client import (  # noqa: E402
    ApiConfig,
    ChatClient,
    build_body,
    canonical_json,
    generate_session_id,
    normalize_endpoint,
    request_fingerprint,
    session_id_sha256,
    utc_now_iso,
)
from secvul_runner.util import atomic_write_json, atomic_write_text  # noqa: E402

from codeql_triage.common import (  # noqa: E402
    DIRECT_PROMPT_VERSION,
    MODEL_PRESETS,
    PRICES,
    PROMPT_VERSION,
    PROMPT_VERSION_V2,
    SCHEMA_VERSION,
    build_direct_messages,
    build_triage_messages,
    cost_for_usage,
    merge_units,
    parse_direct,
    parse_triage,
    sha256_text,
    summarize_latencies,
)

LOGGER = logging.getLogger("codeql_triage")
USER_AGENT = "codeql-triage/1.0"
DEFAULT_BASE_URLS = {
    "xiaomi": "https://api.xiaomimimo.com/v1",
    "deepseek": "https://api.deepseek.com",
    "opencode-go": "https://opencode.ai/zen/go/v1",
    "opencode": "https://opencode.ai/inference/openai/v1",
}
DEFAULT_MODELS = {
    "deepseek": "deepseek-flash",
    "xiaomi": "mimo-v2.6-flash",
    "opencode-go": "deepseek-v4.1-flash",
    "opencode": "deepseek-v4.1-flash-free",
}


@dataclass(frozen=True)
class Spec:
    unit_id: str
    condition: str
    unit: dict[str, Any]
    messages: list[dict[str, str]]
    prompt_sha256: str
    prompt_version: str
    cache_key: str
    request_fingerprint: str
    body: dict[str, Any]


def _drop_unreachable_local_proxies() -> list[str]:
    removed: list[str] = []
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        value = os.environ.get(name, "")
        if value and re.search(r"://(127\.0\.0\.1|localhost)(:\d+)?(/|$)", value):
            os.environ.pop(name, None)
            removed.append(name)
    return removed


def _force_ipv4_dns() -> str:
    original = socket.getaddrinfo
    if getattr(original, "_codeql_triage_ipv4_only", False):
        return "already_installed"

    def ipv4_first(*args: Any, **kwargs: Any) -> Any:
        results = original(*args, **kwargs)
        family = kwargs.get("family", args[2] if len(args) > 2 else 0)
        if family == socket.AF_INET6:
            return results
        ipv4 = [item for item in results if item[0] == socket.AF_INET]
        return ipv4 or results

    ipv4_first._codeql_triage_ipv4_only = True  # type: ignore[attr-defined]
    socket.getaddrinfo = ipv4_first  # type: ignore[assignment]
    return "installed"


def _api_config(args: argparse.Namespace) -> ApiConfig:
    preset = MODEL_PRESETS.get(
        args.model,
        {"thinking": None, "reasoning_effort": None, "max_tokens_field": "max_tokens"},
    )
    base_url = args.base_url or DEFAULT_BASE_URLS.get(args.provider)
    if not base_url:
        raise SystemExit(f"no default base URL for provider {args.provider!r}; pass --base-url")
    prices = PRICES.get(args.model)
    if prices is None:
        raise SystemExit(f"no configured price for model {args.model!r}; add it to common.PRICES")
    return ApiConfig(
        base_url=base_url,
        endpoint=normalize_endpoint(base_url),
        model=args.model,
        temperature=0.0,
        max_tokens=args.max_tokens,
        timeout_seconds=args.timeout,
        max_attempts=args.max_attempts,
        response_format="json_object",
        user_agent=USER_AGENT,
        input_price_usd_per_1m=prices[0],
        output_price_usd_per_1m=prices[1],
        cached_input_price_usd_per_1m=prices[2],
        **preset,
    )


def _build_specs(
    units: list[dict[str, Any]],
    *,
    condition: str,
    api: ApiConfig,
    limit: int,
    prompt_version: str,
) -> list[Spec]:
    selected = units[:limit] if limit else units
    specs: list[Spec] = []
    requested_version = prompt_version
    for unit in selected:
        if condition == "direct":
            messages = build_direct_messages(unit)
            prompt_version = DIRECT_PROMPT_VERSION
        elif condition == "triage":
            messages = build_triage_messages(unit, version=requested_version)
            prompt_version = PROMPT_VERSION_V2 if requested_version == "v2" else PROMPT_VERSION
        else:
            raise ValueError(condition)
        body = build_body(messages, api)
        prompt_hash = sha256_text(canonical_json(messages))
        fingerprint = request_fingerprint(
            endpoint=api.endpoint,
            body=body,
            task="codeql_triage",
            strategy=condition,
            prompt_version=prompt_version,
        )
        cache_key = sha256_text(
            f"{api.model}|{condition}|{unit['unit_id']}|{prompt_hash}|{fingerprint}"
        )
        specs.append(
            Spec(
                unit_id=unit["unit_id"],
                condition=condition,
                unit=unit,
                messages=messages,
                prompt_sha256=prompt_hash,
                prompt_version=prompt_version,
                cache_key=cache_key,
                request_fingerprint=fingerprint,
                body=body,
            )
        )
    return specs


def _request_record(spec: Spec, api: ApiConfig) -> dict[str, Any]:
    return {
        "unit_id": spec.unit_id,
        "condition": spec.condition,
        "prompt_version": spec.prompt_version,
        "prompt_sha256": spec.prompt_sha256,
        "request_fingerprint": spec.request_fingerprint,
        "endpoint": api.endpoint,
        "model": api.model,
        "body": spec.body,
        "authorization_header_omitted": True,
        "note": "unit_id is local bookkeeping; the model sees only body.messages.",
    }


def _parse_record(spec: Spec, content: str | None) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if spec.condition == "direct":
            parsed = parse_direct(content)
        else:
            parsed = parse_triage(content, has_alert=spec.unit["codeql"]["is_alert"])
        return parsed, None
    except Exception as exc:  # noqa: BLE001 - schema validation is intentionally fail-soft
        return None, f"{type(exc).__name__}: {exc}"


def _execute(
    spec: Spec,
    *,
    client: ChatClient,
    cache: RequestCache,
    api: ApiConfig,
    out_dir: Path,
    resume: bool,
) -> dict[str, Any]:
    cached = None
    if resume:
        cached = cache.read(
            dataset_type="juliet_test140",
            task=spec.condition,
            key=spec.cache_key,
            request_fingerprint=spec.request_fingerprint,
        )
    if cached is not None:
        record = dict(cached)
        record.pop("cache_schema_version", None)
        record.pop("cache_key", None)
        parsed, validation_error = _parse_record(spec, record.get("content"))
        if parsed is not None:
            record["parsed"] = parsed
            record["valid"] = True
            record["validation_error"] = None
        record["cache"] = {
            "hit": True,
            "key": spec.cache_key,
            "file": str(
                cache.path_for("juliet_test140", spec.condition, spec.cache_key).relative_to(out_dir)
            ),
        }
        record["unit"] = _unit_summary(spec.unit)
        return record

    started = time.monotonic()
    result = client.complete(spec.messages)
    wall = time.monotonic() - started
    parsed, validation_error = _parse_record(spec, result.content)
    cost = cost_for_usage(result.usage, api.model)
    record: dict[str, Any] = {
        "unit": _unit_summary(spec.unit),
        "unit_id": spec.unit_id,
        "split": "test",
        "condition": spec.condition,
        "model": api.model,
        "prompt_version": spec.prompt_version,
        "prompt_sha256": spec.prompt_sha256,
        "request_fingerprint": spec.request_fingerprint,
        "status": result.status,
        "http_status": result.http_status,
        "content": result.content,
        "usage": result.usage,
        "cost": cost,
        "wall_seconds": wall,
        "request_latency_seconds": result.request_latency_seconds,
        "attempts": result.attempts,
        "error": result.error,
        "response_meta": result.response_meta,
        "parsed": parsed,
        "validation_error": validation_error,
        "valid": parsed is not None,
        "created_at": utc_now_iso(),
        "cache": {"hit": False, "key": spec.cache_key},
    }
    if result.status != "ok" and result.raw_body:
        record["error_body_excerpt"] = result.raw_body[:2000]
    cache.write(
        dataset_type="juliet_test140",
        task=spec.condition,
        key=spec.cache_key,
        request_fingerprint=spec.request_fingerprint,
        record=record,
    )
    return record


def _unit_summary(unit: dict[str, Any]) -> dict[str, Any]:
    codeql = unit["codeql"]
    return {
        "unit_id": unit["unit_id"],
        "group_id": unit["group_id"],
        "family": unit["family"],
        "variant": unit["variant"],
        "language": unit["language"],
        "label": unit["label"],
        "y_true": unit["y_true"],
        "code_chars": len(unit["code"]),
        "codeql_status": codeql["status"],
        "codeql_is_alert": codeql["is_alert"],
        "codeql_by_query": codeql["by_query"],
        "codeql_finding_count": codeql["finding_count"],
    }


def _summary(records: list[dict[str, Any]], *, condition: str, model: str) -> dict[str, Any]:
    valid = [record for record in records if record.get("valid")]
    costs = [record["cost"].get("cost_usd") for record in records if record.get("cost")]
    known_costs = [value for value in costs if isinstance(value, (int, float))]
    usages = [record.get("usage") or {} for record in records]
    prompt_tokens = sum(
        value
        for usage in usages
        for value in [usage.get("prompt_tokens", usage.get("input_tokens"))]
        if isinstance(value, int) and not isinstance(value, bool)
    )
    completion_tokens = sum(
        value
        for usage in usages
        for value in [usage.get("completion_tokens", usage.get("output_tokens"))]
        if isinstance(value, int) and not isinstance(value, bool)
    )
    cached_tokens = 0
    for usage in usages:
        value = usage.get("prompt_cache_hit_tokens")
        if not isinstance(value, int) or isinstance(value, bool):
            value = (usage.get("prompt_tokens_details") or {}).get("cached_tokens")
        if isinstance(value, int) and not isinstance(value, bool):
            cached_tokens += value
    status_counts: dict[str, int] = {}
    for record in records:
        status_counts[record["status"]] = status_counts.get(record["status"], 0) + 1
    return {
        "condition": condition,
        "model": model,
        "n": len(records),
        "valid": len(valid),
        "invalid": len(records) - len(valid),
        "coverage": len(valid) / len(records) if records else None,
        "status_counts": status_counts,
        "cost_usd": sum(known_costs) if known_costs else None,
        "cost_records": len(known_costs),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cached_prompt_tokens": cached_tokens,
        "latency_seconds": summarize_latencies(
            [float(record["wall_seconds"]) for record in records if record.get("wall_seconds") is not None]
        ),
        "cache_hits": sum(1 for record in records if (record.get("cache") or {}).get("hit")),
        "validation_errors": {
            record["unit_id"]: record["validation_error"]
            for record in records
            if record.get("validation_error")
        },
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows)
    atomic_write_text(path, text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, choices=sorted(DEFAULT_BASE_URLS))
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="OPENCODE_API_KEY")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--condition", choices=("direct", "triage", "all"), default="all")
    parser.add_argument("--prompt-version", choices=("v1", "v2"), default="v1")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--resume", action="store_true")
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

    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.concurrency < 1 or args.concurrency > 16:
        parser.error("--concurrency must be between 1 and 16")
    if args.dry_run and args.resume:
        parser.error("--dry-run cannot be combined with --resume")
    if args.out_dir.exists() and any(args.out_dir.iterdir()) and not (args.resume or args.dry_run):
        parser.error(f"{args.out_dir} is not empty; use a new directory or --resume")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    proxy_env_removed = _drop_unreachable_local_proxies()
    ipv4_dns = _force_ipv4_dns()
    api = _api_config(args)
    units = merge_units()
    conditions = ("direct", "triage") if args.condition == "all" else (args.condition,)
    api_key = os.environ.get(args.api_key_env, "").strip()

    if args.dry_run:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "created_at": utc_now_iso(),
            "kind": "dry_run",
            "no_api_calls": True,
            "experimental_results": False,
            "provider": args.provider,
            "api": api.public_dict(),
            "api_key_env": args.api_key_env,
            "api_key_present": bool(api_key),
            "api_key_value_stored": False,
            "conditions": {},
            "network": {
                "proxy_env_removed": proxy_env_removed,
                "ipv4_dns": ipv4_dns,
            },
        }
        for condition in conditions:
            specs = _build_specs(
                units,
                condition=condition,
                api=api,
                limit=args.limit,
                prompt_version=args.prompt_version,
            )
            _write_jsonl(
                args.out_dir / f"dry_run_requests_{condition}.jsonl",
                [_request_record(spec, api) for spec in specs],
            )
            manifest["conditions"][condition] = {
                "planned_requests": len(specs),
                "prompt_version": specs[0].prompt_version if specs else None,
            }
            if specs:
                audit_path = args.out_dir / f"prompt_audit_{condition}.json"
                atomic_write_json(
                    audit_path,
                    {
                        "all_prompts_audited": True,
                        "n": len(specs),
                        "prompt_versions": sorted({spec.prompt_version for spec in specs}),
                        "forbidden_token_hits": 0,
                    },
                )
        atomic_write_json(args.out_dir / "dry_run_manifest.json", manifest)
        print("Dry run only: no API call was made and no experimental result was produced.")
        return 0

    if not api_key:
        raise SystemExit(f"environment variable {args.api_key_env} is empty")

    session_id = generate_session_id()
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now_iso(),
        "provider": args.provider,
        "api": api.public_dict(),
        "api_key_env": args.api_key_env,
        "api_key_present": True,
        "api_key_value_stored": False,
        "session": {
            "header": "x-opencode-session",
            "value": session_id,
            "sha256": session_id_sha256(session_id),
            "is_secret": False,
            "note": "Random routing identifier, not a credential.",
        },
        "dataset": {
            "path": "juliet_llm/build/test.jsonl",
            "n_units": len(units),
            "test_sha256": sha256_text(
                (ROOT / "juliet_llm" / "build" / "test.jsonl").read_text(encoding="utf-8")
            ),
            "codeql_path": "static_extended/runs/codeql_20261114_cwe401_full/predictions.jsonl",
            "codeql_sha256": sha256_text(
                (ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full" / "predictions.jsonl").read_text(
                    encoding="utf-8"
                )
            ),
        },
        "conditions": {},
        "network": {
            "proxy_env_removed": proxy_env_removed,
            "ipv4_dns": ipv4_dns,
            "platform": platform.platform(),
        },
        "limits": {
            "limit": args.limit or None,
            "note": "A nonzero limit is a partial run and must not be reported as full evidence.",
        },
    }

    cache = RequestCache(args.out_dir / "cache")
    started_wall = time.monotonic()
    exit_code = 0
    with ChatClient(api, api_key, session_id=session_id) as client:
        for condition in conditions:
            specs = _build_specs(
                units,
                condition=condition,
                api=api,
                limit=args.limit,
                prompt_version=args.prompt_version,
            )
            request_path = args.out_dir / f"requests_{condition}.jsonl"
            if request_path.exists() and not args.resume:
                raise SystemExit(f"{request_path} exists; use --resume or a new --out-dir")
            _write_jsonl(request_path, [_request_record(spec, api) for spec in specs])
            LOGGER.info("%s: %d requests", condition, len(specs))
            records: list[dict[str, Any]] = []
            failed_auth = False
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                futures = {
                    pool.submit(
                        _execute,
                        spec,
                        client=client,
                        cache=cache,
                        api=api,
                        out_dir=args.out_dir,
                        resume=args.resume,
                    ): spec
                    for spec in specs
                }
                for index, future in enumerate(as_completed(futures), 1):
                    record = future.result()
                    records.append(record)
                    if index % 10 == 0 or index == len(specs):
                        LOGGER.info("%s: %d/%d", condition, index, len(specs))
                    if record["status"] != "ok" and record.get("http_status") in {401, 402, 403}:
                        failed_auth = True
            records.sort(key=lambda item: item["unit_id"])
            _write_jsonl(args.out_dir / f"results_{condition}.jsonl", records)
            predictions = []
            for record in records:
                parsed = record.get("parsed")
                row = {
                    "unit_id": record["unit_id"],
                    "model": api.model,
                    "condition": condition,
                    "y_true": record["unit"]["y_true"],
                    "language": record["unit"]["language"],
                    "variant": record["unit"]["variant"],
                    "codeql_is_alert": record["unit"]["codeql_is_alert"],
                    "codeql_status": record["unit"]["codeql_status"],
                    "valid": record.get("valid", False),
                    "status": record["status"],
                }
                if parsed and condition == "direct":
                    row["y_pred"] = parsed["y_pred"]
                    row["confidence"] = parsed.get("confidence")
                elif parsed and condition == "triage":
                    row["alert_verdict"] = parsed["alert_verdict"]
                    row["leak_present"] = parsed["leak_present"]
                    row["evidence_fields_supported"] = parsed["evidence_fields_supported"]
                    row["unsupported_drop"] = parsed["unsupported_drop"]
                    row["confidence"] = parsed.get("confidence")
                predictions.append(row)
            _write_jsonl(args.out_dir / f"predictions_{condition}.jsonl", predictions)
            summary = _summary(records, condition=condition, model=api.model)
            manifest["conditions"][condition] = summary
            atomic_write_json(args.out_dir / f"metrics_{condition}.json", summary)
            if failed_auth:
                LOGGER.error("%s: an authentication/payment error was observed; stopping", condition)
                exit_code = 2
                break

    manifest["wall_seconds"] = time.monotonic() - started_wall
    manifest["completed_at"] = utc_now_iso()
    atomic_write_json(args.out_dir / "manifest.json", manifest)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

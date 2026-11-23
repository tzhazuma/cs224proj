#!/usr/bin/env python3
"""Second-pass consistency review of the triage answers for CodeQL alerts.

Only the 91 units on which CodeQL raised an alert are verified.  The verifier
sees the same de-identified source, the analyzer report, and the first-pass
JSON, and must re-derive the release status rather than defer to the first
answer.  It is evaluated as a separate policy; it never edits the first-pass
artefacts.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from secvul_runner.cache import RequestCache
from secvul_runner.client import (
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
from secvul_runner.util import atomic_write_json, atomic_write_text

from codeql_triage.common import (
    ALERT_FALSE,
    ALERT_NONE,
    ALERT_TRUE,
    ALERT_UNCERTAIN,
    MODEL_PRESETS,
    PRICES,
    SCHEMA_VERSION,
    TRIAGE_USER_TEMPLATE,
    _extract_json,
    _render_findings,
    audit_prompt,
    cost_for_usage,
    merge_units,
    normalize_alert,
    normalize_leak,
    sha256_text,
    summarize_latencies,
)
from codeql_triage.run_triage import (
    DEFAULT_BASE_URLS,
    _drop_unreachable_local_proxies,
    _force_ipv4_dns,
)

LOGGER = logging.getLogger("codeql_triage.verify")
USER_AGENT = "codeql-triage-verify/1.0"
VERIFY_PROMPT_VERSION = "codeql-triage-verify-2026-11-22.1"

VERIFY_SYSTEM = """You are auditing a previous triage answer for internal consistency and factual correctness. You see the same de-identified source, the analyzer report, and the first-pass JSON. Re-derive the release status from the code; do not defer to the first pass.

Rules:
- An alert is true_positive only if at least one heap allocation has a feasible path to program exit without a release. If every heap allocation is released on every feasible path, the alert is false_positive.
- If the first pass says true_positive but its own reason or fields say every allocation is released, correct it to false_positive.
- `p = realloc(p, n)` that overwrites the only pointer to the old block leaks the old block when realloc returns NULL. Do not dismiss that feasible failure path unless the unit keeps the old pointer.
- Name the allocation and the path that reaches exit without a release in release_gap. If there is no such path, release_gap must be "none".
- Do not use function length, file name, identifier name, formatting, comment text, or analyzer severity as evidence.
- Return one JSON object and nothing else.

Schema:
{"final_leak_present": true | false | "uncertain",
 "final_alert_verdict": "true_positive" | "false_positive" | "uncertain",
 "release_gap": "<allocation and path, or none; at most 50 words>",
 "reason": "<at most 50 words>",
 "confidence": <number from 0 to 1>}"""

VERIFY_USER = """Re-check the first-pass triage for the code unit below.

Analyzer status: {status}
Analyzer alert: yes
{findings}

First-pass answer:
{first_pass}

```{language}
{code}
```

Return only the JSON object."""


def parse_verify(content: str | None) -> dict[str, Any]:
    if not isinstance(content, str) or not content.strip():
        raise ValueError("empty_content")
    value = _extract_json(content)
    if not isinstance(value, dict):
        raise ValueError("not_a_json_object")
    leak = normalize_leak(value.get("final_leak_present"))
    alert = normalize_alert(value.get("final_alert_verdict"))
    if leak is None:
        raise ValueError(f"final_leak_present_invalid: {value.get('final_leak_present')!r}")
    if alert not in {ALERT_TRUE, ALERT_FALSE, ALERT_UNCERTAIN}:
        raise ValueError(f"final_alert_verdict_invalid: {value.get('final_alert_verdict')!r}")
    if leak is False and alert == ALERT_TRUE:
        raise ValueError("contradiction_true_positive_without_leak")
    if leak is True and alert == ALERT_FALSE:
        raise ValueError("contradiction_false_positive_with_leak")
    gap = str(value.get("release_gap") or "").strip()
    if alert == ALERT_TRUE and gap.lower() in {"", "none", "not_applicable"}:
        raise ValueError("true_positive_without_a_named_release_gap")
    confidence = value.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        confidence_value = None
    else:
        confidence_value = float(confidence)
        if not 0.0 <= confidence_value <= 1.0:
            raise ValueError("confidence_out_of_range")
    return {
        "final_leak_present": leak,
        "final_alert_verdict": alert,
        "release_gap": gap,
        "reason": str(value.get("reason") or "").strip(),
        "confidence": confidence_value,
    }


def build_messages(unit: dict[str, Any], first: dict[str, Any]) -> list[dict[str, str]]:
    codeql = unit["codeql"]
    first_pass = {
        "leak_present": first["parsed"]["leak_present"],
        "alert_verdict": first["parsed"]["alert_verdict"],
        "allocation": first["parsed"]["fields"]["allocation"],
        "ownership": first["parsed"]["fields"]["ownership"],
        "aliasing": first["parsed"]["fields"]["aliasing"],
        "global_control_flow": first["parsed"]["fields"]["global_control_flow"],
        "cross_function_release": first["parsed"]["fields"]["cross_function_release"],
        "reason": first["parsed"]["fields"]["reason"],
    }
    user = VERIFY_USER.format(
        status=codeql["status"],
        findings=_render_findings(codeql),
        first_pass=json.dumps(first_pass, ensure_ascii=False, indent=2),
        language="cpp" if unit["language"] == "cpp" else "c",
        code=unit["code"],
    )
    messages = [
        {"role": "system", "content": VERIFY_SYSTEM},
        {"role": "user", "content": user},
    ]
    audit_prompt(messages, unit)
    return messages


def api_config(args: argparse.Namespace) -> ApiConfig:
    preset = MODEL_PRESETS.get(
        args.model,
        {"thinking": None, "reasoning_effort": None, "max_tokens_field": "max_tokens"},
    )
    base_url = args.base_url or DEFAULT_BASE_URLS.get(args.provider)
    if not base_url:
        raise SystemExit(f"no default base URL for provider {args.provider!r}")
    prices = PRICES.get(args.model)
    if prices is None:
        raise SystemExit(f"no configured price for model {args.model!r}")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--provider", required=True, choices=sorted(DEFAULT_BASE_URLS))
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="CODEQL_TRIAGE_API_KEY")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _drop_unreachable_local_proxies()
    _force_ipv4_dns()
    api_key = os.environ.get(args.api_key_env, "").strip()
    if not api_key:
        raise SystemExit(f"environment variable {args.api_key_env} is empty")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    if any(args.out_dir.iterdir()) and not args.resume:
        raise SystemExit(f"{args.out_dir} is not empty; use --resume or a new directory")

    first_rows = {
        row["unit_id"]: row
        for row in (
            json.loads(line)
            for line in (args.run_dir / "results_triage.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    }
    units = {unit["unit_id"]: unit for unit in merge_units()}
    targets = [
        unit_id
        for unit_id, row in first_rows.items()
        if row["unit"]["codeql_is_alert"]
    ]
    targets.sort()
    LOGGER.info("verifying %d alert units", len(targets))

    session_id = generate_session_id()
    cache = RequestCache(args.out_dir / "cache")
    api = api_config(args)
    records: list[dict[str, Any]] = []
    started_wall = time.monotonic()
    with ChatClient(api, api_key, session_id=session_id) as client:
        def execute(unit_id: str) -> dict[str, Any]:
            unit = units[unit_id]
            first = first_rows[unit_id]
            if not first.get("valid"):
                return {
                    "unit_id": unit_id,
                    "status": "skipped_first_pass_invalid",
                    "valid": False,
                    "parsed": None,
                    "validation_error": "first pass invalid",
                }
            messages = build_messages(unit, first)
            body = build_body(messages, api)
            prompt_hash = sha256_text(canonical_json(messages))
            fingerprint = request_fingerprint(
                endpoint=api.endpoint,
                body=body,
                task="codeql_triage_verify",
                strategy="verify",
                prompt_version=VERIFY_PROMPT_VERSION,
            )
            key = sha256_text(f"{api.model}|{unit_id}|{prompt_hash}|{fingerprint}")
            cached = None
            if args.resume:
                cached = cache.read(
                    dataset_type="juliet_test140",
                    task="verify",
                    key=key,
                    request_fingerprint=fingerprint,
                )
            if cached is not None:
                record = dict(cached)
                record.pop("cache_schema_version", None)
                record.pop("cache_key", None)
                record["cache"] = {"hit": True, "key": key}
                record["unit"] = _unit_summary(unit)
                return record
            started = time.monotonic()
            result = client.complete(messages)
            wall = time.monotonic() - started
            try:
                parsed = parse_verify(result.content)
                error = None
            except Exception as exc:  # noqa: BLE001
                parsed = None
                error = f"{type(exc).__name__}: {exc}"
            record = {
                "unit_id": unit_id,
                "unit": _unit_summary(unit),
                "status": result.status,
                "http_status": result.http_status,
                "content": result.content,
                "usage": result.usage,
                "cost": cost_for_usage(result.usage, api.model),
                "wall_seconds": wall,
                "attempts": result.attempts,
                "error": result.error,
                "parsed": parsed,
                "validation_error": error,
                "valid": parsed is not None,
                "prompt_sha256": prompt_hash,
                "request_fingerprint": fingerprint,
                "prompt_version": VERIFY_PROMPT_VERSION,
                "created_at": utc_now_iso(),
                "cache": {"hit": False, "key": key},
            }
            cache.write(
                dataset_type="juliet_test140",
                task="verify",
                key=key,
                request_fingerprint=fingerprint,
                record=record,
            )
            return record

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(execute, unit_id): unit_id for unit_id in targets}
            for index, future in enumerate(as_completed(futures), 1):
                records.append(future.result())
                if index % 10 == 0 or index == len(targets):
                    LOGGER.info("verify: %d/%d", index, len(targets))

    records.sort(key=lambda item: item["unit_id"])
    atomic_write_text(
        args.out_dir / "results_verify.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in records),
    )
    valid = [row for row in records if row.get("valid")]
    costs = [row["cost"]["cost_usd"] for row in records if row.get("cost", {}).get("cost_usd") is not None]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now_iso(),
        "kind": "second_pass_verification",
        "source_run": str(args.run_dir),
        "prompt_version": VERIFY_PROMPT_VERSION,
        "provider": args.provider,
        "api": api.public_dict(),
        "api_key_env": args.api_key_env,
        "api_key_present": True,
        "api_key_value_stored": False,
        "session": {"value": session_id, "sha256": session_id_sha256(session_id), "is_secret": False},
        "n_targets": len(targets),
        "n_records": len(records),
        "n_valid": len(valid),
        "coverage": len(valid) / len(records) if records else None,
        "cost_usd": sum(costs) if costs else None,
        "latency_seconds": summarize_latencies([row["wall_seconds"] for row in records if row.get("wall_seconds")]),
        "cache_hits": sum(1 for row in records if (row.get("cache") or {}).get("hit")),
        "validation_errors": {
            row["unit_id"]: row["validation_error"] for row in records if row.get("validation_error")
        },
    }
    atomic_write_json(args.out_dir / "manifest.json", manifest)
    print(json.dumps({key: manifest[key] for key in ("n_targets", "n_valid", "coverage", "cost_usd")}, indent=2))
    return 0


def _unit_summary(unit: dict[str, Any]) -> dict[str, Any]:
    codeql = unit["codeql"]
    return {
        "unit_id": unit["unit_id"],
        "language": unit["language"],
        "label": unit["label"],
        "y_true": unit["y_true"],
        "variant": unit["variant"],
        "codeql_status": codeql["status"],
        "codeql_is_alert": codeql["is_alert"],
        "codeql_by_query": codeql["by_query"],
    }


if __name__ == "__main__":
    sys.exit(main())

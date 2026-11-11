#!/usr/bin/env python3
"""Audit MiMo (or any) runner output directories: JSON, usage, thinking/reasoning.

Usage:
    python3 mimo/verify_runs.py runner/runs/pilot_v1_mimo_*

Prints one JSON object per run plus a compact table. Exits non-zero when a run is
not complete, has API errors, stores no usage, or does not match the expected
MiMo model / disabled thinking setting.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _cached(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    for key in ("prompt_cache_hit_tokens", "cache_read_input_tokens"):
        value = _int(usage.get(key))
        if value is not None:
            return value
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        return _int(details.get("cached_tokens"))
    return None


def _reasoning(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        return _int(details.get("reasoning_tokens"))
    return None


def audit(run_dir: Path, expect_model: str, expect_token_field: str = "max_completion_tokens") -> dict[str, Any]:
    manifest = _load_json(run_dir / "manifest.json")
    results_path = run_dir / "results.jsonl"
    results = _load_jsonl(results_path) if results_path.exists() else []
    requests = _load_jsonl(run_dir / "requests.jsonl") if (run_dir / "requests.jsonl").exists() else []

    statuses = Counter(str(record.get("status")) for record in results)
    tasks = Counter(str(record.get("task")) for record in results)
    usage_records = [
        record.get("response", {}).get("usage")
        for record in results
        if isinstance(record.get("response"), dict)
    ]
    usage_records = [usage for usage in usage_records if isinstance(usage, dict)]
    prompt_sum = sum(_int(usage.get("prompt_tokens")) or 0 for usage in usage_records)
    completion_sum = sum(_int(usage.get("completion_tokens")) or 0 for usage in usage_records)
    cached_values = [value for value in (_cached(usage) for usage in usage_records) if value is not None]
    reasoning_values = [
        value for value in (_reasoning(usage) for usage in usage_records) if value is not None
    ]
    allowances = []
    billing_sources: Counter[str] = Counter()
    for usage in usage_records:
        opencode = usage.get("opencode")
        if isinstance(opencode, dict):
            allowance = opencode.get("allowance")
            if isinstance(allowance, (int, float)) and not isinstance(allowance, bool):
                allowances.append(float(allowance))
            source = opencode.get("billing_source")
            if isinstance(source, str):
                billing_sources[source] += 1

    reasoning_content_chars = [
        int(record["response"]["response_meta"].get("reasoning_content_chars") or 0)
        + int(record["response"]["response_meta"].get("reasoning_chars") or 0)
        for record in results
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("response_meta"), dict)
    ]
    error_records = [record for record in results if record.get("status") == "error"]
    error_types = Counter(
        str(record.get("response", {}).get("error", {}).get("type"))
        for record in error_records
    )
    invalid_reasons = Counter(
        str(record.get("validation", {}).get("error"))
        for record in results
        if record.get("status") == "invalid"
    )
    costs = [
        record["response"]["cost"]["cost_usd"]
        for record in results
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("cost"), dict)
        and isinstance(record["response"]["cost"].get("cost_usd"), (int, float))
    ]

    request_thinking = Counter(
        json.dumps(request.get("body", {}).get("thinking"), sort_keys=True)
        for request in requests
    )
    request_reasoning_effort = Counter(
        str(request.get("body", {}).get("reasoning_effort")) for request in requests
    )
    request_models = Counter(str(request.get("body", {}).get("model")) for request in requests)
    request_token_fields = Counter(
        key
        for request in requests
        for key in request.get("body", {})
        if key in {"max_tokens", "max_completion_tokens"}
    )
    response_models = Counter(
        str(record.get("response", {}).get("response_meta", {}).get("model"))
        for record in results
    )

    schema_valid = {
        task: sum(
            1
            for record in results
            if record.get("task") == task and record.get("status") == "ok"
        )
        for task in ("detection", "repair")
    }
    expected_requests = int(manifest.get("counts", {}).get("planned_requests", 0) or 0)
    model_ok = request_models == Counter({expect_model: len(requests)}) if requests else False
    thinking_ok = request_thinking == Counter({json.dumps({"type": "disabled"}, sort_keys=True): len(requests)}) if requests else False
    reasoning_effort_ok = request_reasoning_effort == Counter({"none": len(requests)}) if requests else False
    token_field_ok = request_token_fields == Counter({expect_token_field: len(requests)}) if requests else False
    usage_ok = bool(results) and len(usage_records) == len(results)
    reasoning_off = bool(reasoning_values) and all(value == 0 for value in reasoning_values)
    problems: list[str] = []
    if manifest.get("status") != "completed":
        problems.append(f"manifest status is {manifest.get('status')!r}")
    if expected_requests != len(results):
        problems.append(f"expected {expected_requests} results, found {len(results)}")
    if error_records:
        problems.append(f"{len(error_records)} API-error records: {dict(error_types)}")
    if not usage_ok:
        problems.append(f"usage missing on {len(results) - len(usage_records)} records")
    if not model_ok:
        problems.append(f"request model ids are {dict(request_models)}")
    if not thinking_ok:
        problems.append(f"request thinking values are {dict(request_thinking)}")
    if not reasoning_effort_ok:
        problems.append(f"request reasoning_effort values are {dict(request_reasoning_effort)}")
    if not token_field_ok:
        problems.append(f"request token fields are {dict(request_token_fields)}")
    if usage_ok and not reasoning_off:
        problems.append(f"reasoning tokens are not zero: {reasoning_values}")

    return {
        "run_dir": str(run_dir),
        "run_id": manifest.get("run_id"),
        "status": manifest.get("status"),
        "model": manifest.get("api", {}).get("model"),
        "thinking": manifest.get("api", {}).get("thinking"),
        "pricing": {
            "input": manifest.get("api", {}).get("input_price_usd_per_1m"),
            "output": manifest.get("api", {}).get("output_price_usd_per_1m"),
            "cached": manifest.get("api", {}).get("cached_input_price_usd_per_1m"),
        },
        "requests": len(results),
        "tasks": dict(tasks),
        "statuses": dict(statuses),
        "schema_valid": schema_valid,
        "invalid_reasons": dict(invalid_reasons),
        "api_error_types": dict(error_types),
        "usage": {
            "records_with_usage": len(usage_records),
            "prompt_tokens": prompt_sum,
            "completion_tokens": completion_sum,
            "cached_tokens_sum": sum(cached_values) if cached_values else None,
            "reasoning_tokens_sum": sum(reasoning_values) if reasoning_values else None,
            "records_with_reasoning_tokens": sum(1 for value in reasoning_values if value),
            "reasoning_content_records": sum(1 for value in reasoning_content_chars if value),
            "opencode_allowance_sum_usd": sum(allowances) if allowances else None,
            "opencode_billing_sources": dict(billing_sources),
        },
        "cost_usd_sum": sum(costs) if costs else None,
        "request_models": dict(request_models),
        "request_thinking": dict(request_thinking),
        "request_reasoning_effort": dict(request_reasoning_effort),
        "request_token_fields": dict(request_token_fields),
        "response_models": dict(response_models),
        "problems": problems,
        "ok": not problems,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--model", default="mimo-v2.6-flash")
    parser.add_argument("--token-field", default="max_completion_tokens")
    parser.add_argument("--json", action="store_true", help="Only print JSON lines.")
    args = parser.parse_args(argv)

    audits = [audit(path, args.model, args.token_field) for path in args.run_dirs]
    if not args.json:
        print(
            "| Run | Status | Req | OK/Invalid/Error | Det valid | Repair valid "
            "| Usage | Cached tok | Reasoning tok | Allowance USD | Problems |"
        )
        print("| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
        for item in audits:
            statuses = item["statuses"]
            print(
                f"| {item['run_id']} | {item['status']} | {item['requests']} "
                f"| {statuses.get('ok', 0)}/{statuses.get('invalid', 0)}/{statuses.get('error', 0)} "
                f"| {item['schema_valid']['detection']} | {item['schema_valid']['repair']} "
                f"| {item['usage']['records_with_usage']}/{item['requests']} "
                f"| {item['usage']['cached_tokens_sum']} "
                f"| {item['usage']['reasoning_tokens_sum']} "
                f"| {item['usage']['opencode_allowance_sum_usd']} "
                f"| {'; '.join(item['problems']) or '-'} |"
            )
    for item in audits:
        print(json.dumps(item, ensure_ascii=False))
    return 0 if all(item["ok"] for item in audits) else 1


if __name__ == "__main__":
    sys.exit(main())

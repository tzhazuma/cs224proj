#!/usr/bin/env python3
"""Real API runner for the diff-guided pair-evaluation conditions.

One request per pair per condition.  Conditions are defined in
:mod:`pair_diff.common`; the hidden A/B map is derived from the frozen
``pair_joint`` forward map, so the reverse condition is the exact complement of
the published forward assignment.  The runner is resumable through a
per-request cache, records request bodies without ``Authorization``, usage,
cost and latency, and refuses to finish if an API key reached an artifact.

The credential, proxy and secret-scanning helpers are reused from the audited
:mod:`pair_debias.runner`; this module owns only the pair_diff conditions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import platform
import re
import socket
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "runner") not in sys.path:
    sys.path.insert(0, str(ROOT / "runner"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secvul_runner.cache import RequestCache  # noqa: E402
from secvul_runner.client import (  # noqa: E402
    ApiConfig,
    ChatClient,
    build_body,
    canonical_json,
    generate_session_id,
    is_valid_session_id,
    normalize_endpoint,
    request_fingerprint,
    session_id_sha256,
    utc_now_iso,
)
from secvul_runner.util import atomic_write_json, atomic_write_text  # noqa: E402

from pair_debias.runner import (  # noqa: E402
    _aggregate_usage,
    _check_no_secret,
    _drop_unreachable_local_proxies,
    _force_ipv4_dns,
    _latency_summary,
    _resolve_credentials,
    _response_record,
    _sha256_text,
    _write_if_absent_or_same,
)
from pair_diff.common import (  # noqa: E402
    CONDITIONS,
    CONDITION_SPECS,
    MAX_EVIDENCE_ITEMS,
    MAX_SEMANTIC_CHANGES,
    PROMPT_VERSION,
    SCHEMA_VERSION,
    PairJointError,
    PairUnit,
    audit_condition_prompt,
    build_condition_order_map,
    build_prompt,
    condition_mode,
    condition_prompt_version,
    condition_reverses,
    condition_strategy,
    condition_task,
    estimate_tokens,
    load_condition_map,
    load_pairs,
    load_position_map,
    prompt_sha256,
    score_output,
)

LOGGER = logging.getLogger("pair_diff")
DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
DEFAULT_DATASET = ROOT / "splits" / "test_pairs_180.json"
DEFAULT_PILOT_DATASET = ROOT / "splits" / "pilot_pairs_18.json"
DEFAULT_BASE_MAP = ROOT / "pair_joint" / "runs" / "test_deepseek_180" / "position_map.json"
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


def _selected_units(units: list[PairUnit], limit: int) -> list[PairUnit]:
    if limit <= 0 or limit >= len(units):
        return list(units)
    return units[:limit]


def _build_specs(
    units: list[PairUnit],
    position_map: dict[str, Any],
    condition: str,
    api_config: ApiConfig,
) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for index, unit in enumerate(units, start=1):
        assignment = position_map["assignments"][unit.pair_id]
        prompt = build_prompt(unit, assignment, condition)
        body = build_body(list(prompt.messages), api_config)
        fingerprint = request_fingerprint(
            endpoint=api_config.endpoint,
            body=body,
            task=condition_task(condition),
            strategy=condition_strategy(condition),
            prompt_version=condition_prompt_version(condition),
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


def _request_record(spec: RequestSpec, condition: str, prompt_digest: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "condition": condition,
        "request_index": spec.index,
        "pair_id": spec.unit.pair_id,
        "prompt": spec.prompt.metadata,
        "prompt_sha256": prompt_digest,
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


def _config_fingerprint(
    *,
    api_config: ApiConfig,
    dataset_sha256: str,
    base_map_sha256: str,
    position_map_sha256: str,
    condition: str,
    selected_units: int,
    limit: int,
    api_key_env: str,
) -> str:
    identity = {
        "api": api_config.public_dict(),
        "api_key_env": api_key_env,
        "dataset_sha256": dataset_sha256,
        "base_map_sha256": base_map_sha256,
        "position_map_sha256": position_map_sha256,
        "condition": condition,
        "selected_units": selected_units,
        "limit": limit,
        "prompt_version": condition_prompt_version(condition),
        "max_evidence_items": MAX_EVIDENCE_ITEMS,
        "max_semantic_changes": MAX_SEMANTIC_CHANGES,
    }
    return _sha256_text(canonical_json(identity))


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _metrics(
    records: list[dict[str, Any]],
    *,
    run_id: str,
    condition: str,
    partial: bool,
    limit: int,
    settings: dict[str, Any],
) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    decisions: dict[str, int] = {}
    error_codes: dict[str, int] = {}
    json_ok = schema_exact = changes_first = changes_present = changes_valid = 0
    evidence_present = evidence_compliant = 0
    changes_total = grounded_items = cited_lines = grounded_cited = covered_changed = changed_total = 0
    prompt_tokens: list[float] = []
    completion_tokens: list[float] = []
    diff_tokens: list[float] = []
    control_delta: list[float] = []
    parsed_count = 0
    for record in records:
        status = str(record.get("status"))
        statuses[status] = statuses.get(status, 0) + 1
        parsed = record.get("parsed")
        validation = record.get("validation") or {}
        response = record.get("response") or {}
        usage = response.get("usage") if isinstance(response.get("usage"), dict) else None
        if usage:
            if isinstance(usage.get("prompt_tokens"), (int, float)):
                prompt_tokens.append(float(usage["prompt_tokens"]))
            if isinstance(usage.get("completion_tokens"), (int, float)):
                completion_tokens.append(float(usage["completion_tokens"]))
        prompt_meta = record.get("prompt") or {}
        if isinstance(prompt_meta.get("diff_tokens_est"), (int, float)):
            diff_tokens.append(float(prompt_meta["diff_tokens_est"]))
        if isinstance(prompt_meta.get("control_delta_tokens_est"), (int, float)):
            control_delta.append(float(prompt_meta["control_delta_tokens_est"]))
        if parsed is None:
            continue
        parsed_count += 1
        decision = str(parsed.get("vulnerable_version") or "invalid")
        decisions[decision] = decisions.get(decision, 0) + 1
        json_ok += int(bool(validation.get("json_parse_ok")))
        schema_exact += int(bool(validation.get("schema_exact")))
        changes_first += int(bool(validation.get("changes_first")))
        changes_present += int(bool(validation.get("changes_present")))
        changes_valid += int(bool(validation.get("changes_all_valid")))
        evidence = validation.get("evidence") or {}
        changes = validation.get("changes") or {}
        evidence_present += int(bool(evidence.get("evidence_present")))
        evidence_compliant += int(bool(evidence.get("evidence_compliant")))
        changes_total += int(changes.get("changes_count") or 0)
        grounded_items += int(changes.get("grounded_items") or 0)
        cited_lines += int(changes.get("cited_lines") or 0)
        grounded_cited += int(changes.get("grounded_cited_lines") or 0)
        covered_changed += int(changes.get("covered_changed_lines") or 0)
        changed_total += int(changes.get("changed_lines_total") or 0)
        if validation.get("error_code"):
            error_codes[str(validation["error_code"])] = error_codes.get(str(validation["error_code"]), 0) + 1

    def rate(numerator: int, denominator: int) -> float | None:
        return None if denominator == 0 else round(numerator / denominator, 6)

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "condition": condition,
        "mode": condition_mode(condition),
        "reversal": condition_reverses(condition),
        "partial": partial,
        "limit": limit,
        "requests": len(records),
        "status": statuses,
        "parsed_outputs": parsed_count,
        "decisions": decisions,
        "abstention": decisions.get("both", 0) + decisions.get("neither", 0),
        "abstention_rate": rate(decisions.get("both", 0) + decisions.get("neither", 0), len(records)),
        "compliance": {
            "json_parse_ok": json_ok,
            "schema_exact": schema_exact,
            "schema_exact_rate": rate(schema_exact, parsed_count),
            "changes_first": changes_first,
            "changes_first_rate": rate(changes_first, parsed_count),
            "changes_present": changes_present,
            "changes_present_rate": rate(changes_present, parsed_count),
            "changes_all_valid": changes_valid,
            "changes_all_valid_rate": rate(changes_valid, parsed_count),
            "semantic_changes_total": changes_total,
            "grounded_items": grounded_items,
            "grounded_item_rate": rate(grounded_items, changes_total),
            "cited_line_precision": rate(grounded_cited, cited_lines),
            "changed_line_recall": rate(covered_changed, changed_total),
            "evidence_present": evidence_present,
            "evidence_compliant": evidence_compliant,
            "error_codes": error_codes,
        },
        "usage": {
            **_aggregate_usage(records),
            "prompt_tokens_median": _median(prompt_tokens),
            "completion_tokens_median": _median(completion_tokens),
            "prompt_tokens_total_observed": int(sum(prompt_tokens)) if prompt_tokens else None,
            "completion_tokens_total_observed": int(sum(completion_tokens)) if completion_tokens else None,
        },
        "latency_seconds": _latency_summary(records),
        "length": {
            "diff_tokens_est_median": _median(diff_tokens),
            "control_delta_tokens_est_median": _median(control_delta),
            "control_delta_tokens_est_mean": (
                round(sum(control_delta) / len(control_delta), 6) if control_delta else None
            ),
            "control_delta_tokens_est_max_abs": (
                round(max(abs(value) for value in control_delta), 6) if control_delta else None
            ),
        },
        "settings": settings,
        "notes": [
            "Cost uses the configured list prices, not the provider invoice.",
            "A partial run used --limit and must not be reported as full-dataset evidence.",
            "prompt_tokens are provider-reported totals; diff_tokens_est is a tiktoken proxy used for matching only.",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument(
        "--condition",
        required=True,
        choices=CONDITIONS,
        help="diff_fwd, diff_rev, ctrl_fwd or ctrl_rev",
    )
    parser.add_argument("--base-map", type=Path, default=DEFAULT_BASE_MAP)
    parser.add_argument("--expect-base-sha256", default=None)
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--kimi-config", type=Path, default=None)
    parser.add_argument("--kimi-provider", default="opencode-go")
    parser.add_argument("--api-key-env", default="OPENCODE_API_KEY")
    parser.add_argument("--out-dir", type=Path, required=True)
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
    proxy_env_removed = _drop_unreachable_local_proxies()
    ipv4_dns = _force_ipv4_dns()
    if proxy_env_removed:
        LOGGER.warning(
            "ignored localhost proxy variables that cannot work inside WSL: %s",
            ", ".join(proxy_env_removed),
        )
    if args.concurrency < 1 or args.concurrency > 32:
        parser.error("--concurrency must be between 1 and 32")
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.dry_run and args.resume:
        parser.error("--dry-run cannot be combined with --resume")
    if args.resume and not args.out_dir:
        parser.error("--resume requires the original --out-dir")

    condition = args.condition
    try:
        units_all, dataset_metadata, dataset_sha256 = load_pairs(args.dataset)
        base = load_position_map(args.base_map)
        base_sha = str(base.get("sha256") or "")
        if args.expect_base_sha256 and base_sha != args.expect_base_sha256:
            raise PairJointError(
                f"base map SHA-256 {base_sha} does not match expected {args.expect_base_sha256}"
            )
        units = _selected_units(units_all, args.limit)
        if not units:
            raise PairJointError("no pairs selected")
        position_map = build_condition_order_map(base, condition, units)
    except PairJointError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.expect_sha256 and dataset_sha256 != args.expect_sha256:
        print(
            f"ERROR: dataset SHA-256 {dataset_sha256} does not match expected {args.expect_sha256}",
            file=sys.stderr,
        )
        return 2
    partial = len(units) < len(units_all)

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
            user_agent="secvul-pair-diff/1.0",
            input_price_usd_per_1m=args.input_price_usd_per_1m,
            output_price_usd_per_1m=args.output_price_usd_per_1m,
            cached_input_price_usd_per_1m=args.cached_input_price_usd_per_1m,
        )
        api_config.validate()
    except (ValueError, PairJointError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out_dir = args.out_dir
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
        base_map_sha256=base_sha,
        position_map_sha256=str(position_map["sha256"]),
        condition=condition,
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
        if args.resume and (out_dir / "position_map.json").exists():
            try:
                existing_map = load_condition_map(
                    out_dir / "position_map.json",
                    condition,
                    units,
                    require_balance=len(units) == len(units_all),
                )
            except PairJointError as exc:
                print(f"ERROR: existing position map is invalid: {exc}", file=sys.stderr)
                return 2
            if existing_map.get("sha256") != position_map["sha256"]:
                print("ERROR: derived position map changed; refusing to resume", file=sys.stderr)
                return 2

    specs = _build_specs(units, position_map, condition, api_config)
    prompt_digests = {spec.unit.pair_id: prompt_sha256(spec.prompt) for spec in specs}
    audits = [audit_condition_prompt(spec.unit, spec.assignment, spec.prompt) for spec in specs]
    bad = [audit for audit in audits if not audit["wrapper_clean"] or audit["slot_leak"] or not audit["diff_direction_ok"]]
    if bad:
        print(f"ERROR: prompt leakage audit failed for {len(bad)} pairs, e.g. {bad[0]}", file=sys.stderr)
        return 2

    wrapper = specs[0].prompt.wrapper_text
    design_audit = {
        "line_numbered": " | " in specs[0].prompt.messages[1]["content"],
        "wrapper_sha256": _sha256_text(wrapper),
        "wrapper_contains_pair_id": any(unit.pair_id in wrapper for unit in units),
        "wrapper_contains_commit_id": any(unit.commit_id and unit.commit_id in wrapper for unit in units),
        "wrapper_contains_filepath": any(unit.filepath and unit.filepath in wrapper for unit in units),
        "wrapper_contains_func_name": any(unit.func_name and unit.func_name in wrapper for unit in units),
        "open_choice": True,
        "reversed_order": condition_reverses(condition),
        "change_mode": condition_mode(condition),
        "diff_direction": "A_to_B",
        "open_allows_both_neither": ("both" in wrapper and "neither" in wrapper),
        "open_claims_exactly_one": (
            "exactly one revision" in wrapper.lower()
            or "exactly one of the two" in wrapper.lower()
            or "one revision contains the security vulnerability" in wrapper.lower()
        ),
        "changes_first_instruction": 'FIRST key is "semantic_changes"' in wrapper,
        "slot_letter_ground_truth_absent": True,
        "length_matching": {
            "pairs": len(audits),
            "control_match_all": all(
                audit["length_match_ok"] is not False for audit in audits
            ),
            "control_delta_tokens_est_max_abs": max(
                (abs(int(spec.prompt.metadata.get("control_delta_tokens_est") or 0)) for spec in specs),
                default=0,
            )
            if condition_mode(condition) == "ctrl"
            else None,
        },
        "note": (
            "The wrapper is shared by every pair; the A/B -> vulnerable/fixed mapping exists only in "
            "position_map.json and never in a prompt or request body. The diff direction is always A -> B, "
            "so it follows the slot swap instead of revealing the label."
        ),
    }
    if design_audit["wrapper_contains_pair_id"] or design_audit["wrapper_contains_commit_id"]:
        print("ERROR: wrapper leaks a dataset identifier", file=sys.stderr)
        return 2
    if design_audit["open_claims_exactly_one"]:
        print("ERROR: open wrapper still claims exactly one vulnerable revision", file=sys.stderr)
        return 2

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
        "runner": "pair_diff.runner",
        "runner_version": "1.0.0",
        "condition": condition,
        "task": condition_task(condition),
        "strategy": condition_strategy(condition),
        "reversal": condition_reverses(condition),
        "change_mode": condition_mode(condition),
        "open_choice": True,
        "prompt_version": condition_prompt_version(condition),
        "max_evidence_items": MAX_EVIDENCE_ITEMS,
        "max_semantic_changes": MAX_SEMANTIC_CHANGES,
        "api": api_config.public_dict(),
        "api_key_env": args.api_key_env,
        "api_key_present": bool(key) or bool(previous_manifest),
        "api_key_value_stored": False,
        "session": session_info,
        "dataset_path": str(args.dataset.relative_to(ROOT)) if args.dataset.is_relative_to(ROOT) else str(args.dataset),
        "dataset_sha256": dataset_sha256,
        "dataset_metadata": {
            name: dataset_metadata.get(name)
            for name in ("schema_version", "split", "source_file", "source_sha256")
            if name in dataset_metadata
        },
        "dataset_units_total": len(units_all),
        "selected_units": len(units),
        "limit": args.limit,
        "partial": partial,
        "base_map_path": str(args.base_map.relative_to(ROOT)) if args.base_map.is_relative_to(ROOT) else str(args.base_map),
        "base_map_sha256": base_sha,
        "position_map_sha256": position_map["sha256"],
        "vulnerable_slot_counts": position_map["counts"],
        "concurrency": args.concurrency,
        "run_label": args.run_label,
        "network": {
            "localhost_proxy_env_removed": proxy_env_removed,
            "ipv4_dns_preference": ipv4_dns,
            "note": (
                "Proxy variables pointing at 127.0.0.1/localhost are unusable inside WSL and were "
                "removed for the process only; the resolver was also wrapped to prefer A records "
                "because the IPv6 path is blackholed. No proxy value is stored."
            ),
        },
        "config_fingerprint": config_fingerprint,
        "started_at": started_at,
        "out_dir": str(out_dir.relative_to(ROOT)) if out_dir.is_relative_to(ROOT) else str(out_dir),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
    }
    if args.dry_run:
        dry_requests = out_dir / "dry_run_requests.jsonl"
        lines = [
            json.dumps(_request_record(spec, condition, prompt_digests[spec.unit.pair_id]), ensure_ascii=False)
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
                "design": design_audit,
            },
            "outputs": {"requests": dry_requests.name},
            "created_at": utc_now_iso(),
        }
        atomic_write_json(out_dir / "dry_run_manifest.json", manifest)
        print(f"DRY RUN: {len(specs)} {condition} request(s) validated; no API call was made.")
        print(f"  requests: {dry_requests}")
        print(f"  manifest: {out_dir / 'dry_run_manifest.json'}")
        return 0

    atomic_write_json(out_dir / "position_map.json", position_map)
    atomic_write_json(
        out_dir / "leak_audit.json",
        {
            "schema_version": SCHEMA_VERSION,
            "condition": condition,
            "wrapper_clean_all": True,
            "slot_leak_all": False,
            "design": design_audit,
            "pairs": audits,
        },
    )
    atomic_write_json(out_dir / "config.json", config_record)
    requests_text = "\n".join(
        json.dumps(_request_record(spec, condition, prompt_digests[spec.unit.pair_id]), ensure_ascii=False)
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
            "condition": condition,
            "reversal": condition_reverses(condition),
            "vulnerable_slot_counts": position_map["counts"],
            "position_map_sha256": position_map["sha256"],
            "base_map_sha256": base_sha,
        },
        "leakage_audit": {
            "wrapper_clean_all": True,
            "slot_leak_all": False,
            "design": design_audit,
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
        cached = cache.read(
            dataset_type="pairs_diff",
            task=condition_task(condition),
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
            parsed, validation, evaluation = score_output(
                result.content if result.status == "ok" else None,
                spec.unit,
                spec.assignment,
                condition,
            )
            if result.status != "ok":
                status = "error"
                validation["error_code"] = "api_error"
            elif validation.get("decision_parsed") is None:
                status = "invalid"
            else:
                status = "ok"
            record = {
                "schema_version": SCHEMA_VERSION,
                "condition": condition,
                "request_index": spec.index,
                "pair_id": spec.unit.pair_id,
                "prompt": spec.prompt.metadata,
                "prompt_sha256": prompt_digests[spec.unit.pair_id],
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
                "condition": condition,
                "request_index": spec.index,
                "pair_id": spec.unit.pair_id,
                "prompt": spec.prompt.metadata,
                "prompt_sha256": prompt_digests[spec.unit.pair_id],
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
                    "changes": {},
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
            dataset_type="pairs_diff",
            task=condition_task(condition),
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
                    LOGGER.info(
                        "progress %d/%d (ok=%d, elapsed=%.1fs)",
                        completed,
                        total,
                        ok,
                        time.monotonic() - started_monotonic,
                    )
    except KeyboardInterrupt:
        LOGGER.warning("interrupted after %d/%d requests; completed requests are cached", completed, total)
    finally:
        client.close()

    records.sort(key=lambda record: int(record.get("request_index") or 0))
    results_text = "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n"
    atomic_write_text(out_dir / "results.jsonl", results_text)
    metrics = _metrics(
        records,
        run_id=out_dir.name,
        condition=condition,
        partial=partial,
        limit=args.limit,
        settings=config_record,
    )
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
    print(f"Run {manifest['status']}: {len(records)}/{total} {condition} requests.")
    print(f"  ok={statuses.get('ok', 0)} invalid={statuses.get('invalid', 0)} error={statuses.get('error', 0)}")
    print(f"  usage: {metrics['usage']}")
    print(f"  latency: {metrics['latency_seconds']}")
    print(f"  out: {out_dir}")
    return 0 if finished else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the hybrid evidence-guidance matrix on the frozen 140-unit test split.

Every request is real, recorded with usage, USD cost and latency.  Credentials
are read from the local Kimi Code config into process memory only; they are
never printed, logged, or written to any output file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
for path in (str(ROOT), str(ROOT / "runner"), str(HYBRID)):
    if path not in sys.path:
        sys.path.insert(0, path)

from juliet_llm.metrics import SchemaError, parse_verdict  # noqa: E402
from juliet_llm.prompting import PROMPT_VERSION as JULIET_PROMPT_VERSION  # noqa: E402
from secvul_runner.client import ApiConfig, ChatClient, normalize_endpoint  # noqa: E402

from prompts import METHODS, PROMPT_VERSION, build_messages  # noqa: E402

KIMI_CONFIG = Path("/mnt/c/Users/tzh03/.kimi-code/config.toml")
PROVIDER = "opencode-go"

MODEL_CONFIGS: dict[str, dict[str, Any]] = {
    "deepseek": {
        "display_name": "DeepSeek-V4.1-Flash",
        "model": "deepseek-v4.1-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "max_tokens": 8192,
        "timeout_seconds": 180.0,
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
        "input_price_usd_per_1m": 0.15,
        "output_price_usd_per_1m": 0.60,
        "cached_input_price_usd_per_1m": 0.003,
    },
    "mimo": {
        "display_name": "MiMo-V2.6-Flash",
        "model": "mimo-v2.6-flash",
        "base_url": "https://opencode.ai/zen/go/v1",
        "max_tokens": 8192,
        "timeout_seconds": 300.0,
        "thinking": "disabled",
        "reasoning_effort": "none",
        "max_tokens_field": "max_completion_tokens",
        "input_price_usd_per_1m": 0.14,
        "output_price_usd_per_1m": 0.28,
        "cached_input_price_usd_per_1m": 0.0028,
    },
}

_WRITE_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_units(path: Path) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                units.append(json.loads(line))
    return sorted(units, key=lambda unit: unit["unit_id"])


def load_api_key() -> str:
    with KIMI_CONFIG.open("rb") as stream:
        config = tomllib.load(stream)
    provider = config.get("providers", {}).get(PROVIDER)
    if not isinstance(provider, dict):
        raise SystemExit(f"provider {PROVIDER!r} not found in {KIMI_CONFIG}")
    key = provider.get("api_key")
    if not isinstance(key, str) or not key.strip():
        raise SystemExit(f"provider {PROVIDER!r} has no usable API key")
    return key.strip()


def api_config(model_key: str) -> ApiConfig:
    spec = MODEL_CONFIGS[model_key]
    return ApiConfig(
        base_url=spec["base_url"],
        endpoint=normalize_endpoint(spec["base_url"]),
        model=spec["model"],
        temperature=0.0,
        max_tokens=spec["max_tokens"],
        timeout_seconds=spec["timeout_seconds"],
        max_attempts=3,
        backoff_base_seconds=1.5,
        backoff_cap_seconds=30.0,
        response_format="json_object",
        thinking=spec["thinking"],
        reasoning_effort=spec["reasoning_effort"],
        max_tokens_field=spec["max_tokens_field"],
        input_price_usd_per_1m=spec["input_price_usd_per_1m"],
        output_price_usd_per_1m=spec["output_price_usd_per_1m"],
        cached_input_price_usd_per_1m=spec["cached_input_price_usd_per_1m"],
    )


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    with _WRITE_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)


def compact_results(path: Path) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            latest[record["unit_id"]] = record
    ordered = [latest[key] for key in sorted(latest)]
    with path.open("w", encoding="utf-8") as handle:
        for record in ordered:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return ordered


def evaluate_one(
    client: ChatClient,
    unit: dict[str, Any],
    method: str,
    model_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    messages, prompt_meta = build_messages(unit, method)
    call = client.complete(messages)
    record: dict[str, Any] = {
        "unit_id": unit["unit_id"],
        "group_id": unit["group_id"],
        "family": unit["family"],
        "variant": unit["variant"],
        "language": unit["language"],
        "label": unit["label"],
        "y_true": 1 if unit["label"] else 0,
        "split": unit["split"],
        "model": model_key,
        "method": method,
        "status": "api_error",
        "valid": False,
        "predicted_label": None,
        "y_pred": None,
        "confidence": None,
        "reason": None,
        "schema_error": None,
        "content": call.content,
        "usage": call.usage,
        "cost": call.cost,
        "latency_seconds": call.wall_seconds,
        "request_latency_seconds": call.request_latency_seconds,
        "http_status": call.http_status,
        "response_meta": call.response_meta,
        "error": call.error,
        "attempts": len(call.attempts),
        "prompt": prompt_meta,
        "dynamic_outcome": unit.get("dynamic_outcome"),
        "dynamic_detectors": unit.get("dynamic_detectors"),
        "placebo_donor_unit": unit.get("placebo_donor_unit") if method == "shuffled" else None,
    }
    if call.status != "ok":
        record["error_type"] = (call.error or {}).get("type")
        return record, prompt_meta
    try:
        parsed = parse_verdict(call.content)
    except SchemaError as exc:
        record["status"] = "invalid"
        record["schema_error"] = str(exc)
        return record, prompt_meta
    record.update(
        {
            "status": "ok",
            "valid": True,
            "predicted_label": parsed["label"],
            "y_pred": 1 if parsed["label"] == "vulnerable" else 0,
            "confidence": parsed["confidence"],
            "reason": parsed["reason"],
            "schema_error": None,
        }
    )
    return record, prompt_meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["deepseek", "mimo", "all"], required=True)
    parser.add_argument("--methods", default=",".join(METHODS))
    parser.add_argument("--limit", type=int, default=0, help="0 = all 140 units")
    parser.add_argument("--concurrency", type=int, default=12)
    parser.add_argument("--out-root", type=Path, default=HYBRID / "runs")
    parser.add_argument("--run-id", default="hybrid_v2")
    parser.add_argument("--inputs-dir", type=Path, default=HYBRID / "inputs_v2")
    parser.add_argument("--audit-out", type=Path, default=None)
    parser.add_argument("--preflight-report", type=Path, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-invalid", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true", help="build and audit prompts only")
    args = parser.parse_args()

    methods = [item.strip() for item in args.methods.split(",") if item.strip()]
    unknown = sorted(set(methods) - set(METHODS))
    if unknown:
        parser.error(f"unknown methods: {unknown}")
    models = list(MODEL_CONFIGS) if args.model == "all" else [args.model]
    args.out_root = args.out_root.resolve()
    args.inputs_dir = args.inputs_dir.resolve()
    units_path = args.inputs_dir / "units.jsonl"
    manifest_path = args.inputs_dir / "manifest.json"
    if not units_path.is_file() or not manifest_path.is_file():
        parser.error(f"input pack not found under {args.inputs_dir}")

    input_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    units = load_units(units_path)
    preflight_record = None
    if args.preflight_report:
        preflight_path = args.preflight_report.resolve()
        preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
        if not preflight.get("ok"):
            raise SystemExit(f"preflight gate failed: {preflight.get('failures')}")
        if preflight.get("prompt_version") != PROMPT_VERSION:
            raise SystemExit(
                f"preflight prompt version {preflight.get('prompt_version')} != {PROMPT_VERSION}"
            )
        reported_sha = (preflight.get("input_pack") or {}).get("units_sha256")
        if reported_sha != input_manifest.get("units_sha256"):
            raise SystemExit("preflight report does not cover this input pack")
        preflight_record = {
            "path": str(preflight_path.relative_to(ROOT))
            if preflight_path.is_relative_to(ROOT)
            else str(preflight_path),
            "sha256": hashlib.sha256(preflight_path.read_bytes()).hexdigest(),
            "ok": True,
            "noop_collisions": (preflight.get("placebo") or {}).get("noop_collisions"),
        }
        print(f"preflight gate passed: {preflight_record['path']}", flush=True)
    try:
        dataset_rel = str(units_path.relative_to(ROOT))
    except ValueError:
        dataset_rel = str(units_path)
    if args.limit:
        units = units[: args.limit]
    expected = len(units)

    if args.dry_run:
        reference_path = ROOT / "juliet_llm/build/test.jsonl"
        reference_manifest_path = ROOT / "juliet_llm/build/manifest.json"
        reference_version = None
        if reference_manifest_path.is_file():
            reference_version = json.loads(
                reference_manifest_path.read_text(encoding="utf-8")
            ).get("prompt_version")
        reference: dict[str, dict[str, Any]] = {}
        if reference_path.is_file():
            for line in reference_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = json.loads(line)
                    reference[record["unit_id"]] = record
        audit: dict[str, Any] = {
            "generated_at_utc": utc_now(),
            "run_id": args.run_id,
            "prompt_version": PROMPT_VERSION,
            "units": len(units),
            "methods": {},
            "direct_matches_juliet_llm": {
                "reference": str(reference_path.relative_to(ROOT)),
                "reference_prompt_version": reference_version,
                "current_juliet_prompt_version": JULIET_PROMPT_VERSION,
                "reference_units": len(reference),
                "status": "missing",
                "checked": 0,
                "stale_units": 0,
                "mismatches": [],
            },
        }
        for method in methods:
            hashes = []
            chars = []
            for unit in units:
                messages, metadata = build_messages(unit, method)
                hashes.append(metadata["prompt_sha256"])
                chars.append(sum(len(message["content"]) for message in messages))
                if method == "direct" and unit["unit_id"] in reference:
                    reference_row = reference[unit["unit_id"]]
                    if (
                        reference_row.get("code_sha256")
                        and reference_row["code_sha256"] != unit["source_sha256"]
                    ):
                        audit["direct_matches_juliet_llm"]["stale_units"] += 1
                        continue
                    audit["direct_matches_juliet_llm"]["checked"] += 1
                    if metadata["prompt_sha256"] != reference_row.get("prompt_sha256"):
                        audit["direct_matches_juliet_llm"]["mismatches"].append(unit["unit_id"])
            audit["methods"][method] = {
                "prompts": len(hashes),
                "unique_hashes": len(set(hashes)),
                "min_chars": min(chars),
                "max_chars": max(chars),
                "mean_chars": sum(chars) / len(chars),
            }
        detail = audit["direct_matches_juliet_llm"]
        stale = bool(
            detail["stale_units"]
            or (reference_version is not None and reference_version != JULIET_PROMPT_VERSION)
        )
        if stale:
            detail["status"] = "stale_reference"
            audit["reference_note"] = (
                "juliet_llm/build predates the current cleaner/prompt; direct prompts are "
                "still produced by juliet_llm.prompting.build_messages and audited here"
            )
        elif reference:
            detail["status"] = "matched" if not detail["mismatches"] else "mismatch"
        out = args.audit_out or (HYBRID / "results" / f"{args.run_id}_prompt_audit.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        audit["leak_audit"] = (
            "all prompts passed prompt_forbidden_hits, benign/fixed and unit/group "
            "identifier checks"
        )
        out.write_text(json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(audit, indent=2, ensure_ascii=False))
        mismatches = detail["mismatches"]
        if mismatches and not stale:
            print(f"ERROR: {len(mismatches)} direct prompts differ from juliet_llm", file=sys.stderr)
            return 1
        if stale:
            print(
                f"NOTE: juliet_llm/build is stale ({detail['stale_units']} units); "
                "direct prompts were audited against the shared builder",
                file=sys.stderr,
            )
        return 0

    api_key = load_api_key()
    for model_key in models:
        config = api_config(model_key)
        spec = MODEL_CONFIGS[model_key]
        with ChatClient(config, api_key) as client:
            for method in methods:
                run_dir = args.out_root / f"{args.run_id}_{model_key}_{method}"
                run_dir.mkdir(parents=True, exist_ok=True)
                results_path = run_dir / "results.jsonl"
                requests_path = run_dir / "requests.jsonl"
                manifest_path = run_dir / "manifest.json"
                config_path = run_dir / "config.json"

                completed: dict[str, dict[str, Any]] = {}
                if args.resume and results_path.exists():
                    completed = {r["unit_id"]: r for r in compact_results(results_path)}
                remaining = [unit for unit in units if unit["unit_id"] not in completed]
                if args.retry_invalid:
                    remaining = [
                        unit
                        for unit in units
                        if unit["unit_id"] not in completed
                        or completed[unit["unit_id"]]["status"] in {"api_error", "invalid"}
                    ]

                fingerprint_src = json.dumps(
                    {
                        "api": config.public_dict(),
                        "prompt_version": PROMPT_VERSION,
                        "input_units_sha256": input_manifest["units_sha256"],
                        "method": method,
                        "limit": args.limit,
                        "preflight_sha256": (preflight_record or {}).get("sha256"),
                    },
                    sort_keys=True,
                )
                config_record = {
                    "schema_version": "hybrid-run-v1",
                    "run_id": f"{args.run_id}_{model_key}_{method}",
                    "model_key": model_key,
                    "model_display_name": spec["display_name"],
                    "method": method,
                    "prompt_version": PROMPT_VERSION,
                    "api": config.public_dict(),
                    "dataset": {
                        "path": dataset_rel,
                        "sha256": input_manifest["units_sha256"],
                        "units": expected,
                        "partial": bool(args.limit),
                    },
                    "concurrency": args.concurrency,
                    "config_fingerprint": hashlib.sha256(fingerprint_src.encode()).hexdigest(),
                    "preflight": preflight_record,
                    "credentials": "read from local Kimi Code config into process memory; never logged",
                }
                config_path.write_text(
                    json.dumps(config_record, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                manifest = {
                    "schema_version": "hybrid-run-v1",
                    "run_id": f"{args.run_id}_{model_key}_{method}",
                    "started_at_utc": utc_now(),
                    "finished_at_utc": None,
                    "model": spec["display_name"],
                    "model_id": spec["model"],
                    "base_url": spec["base_url"],
                    "method": method,
                    "prompt_version": PROMPT_VERSION,
                    "expected_units": expected,
                    "partial": bool(args.limit),
                    "concurrency": args.concurrency,
                    "results_file": "results.jsonl",
                }
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                if not requests_path.exists():
                    requests_path.touch()

                started = time.monotonic()
                outcomes: list[dict[str, Any]] = []
                if remaining:
                    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                        futures = {
                            pool.submit(evaluate_one, client, unit, method, model_key): unit
                            for unit in remaining
                        }
                        for future in as_completed(futures):
                            unit = futures[future]
                            try:
                                record, prompt_meta = future.result()
                            except Exception as exc:  # noqa: BLE001
                                record = {
                                    "unit_id": unit["unit_id"],
                                    "group_id": unit["group_id"],
                                    "family": unit["family"],
                                    "variant": unit["variant"],
                                    "language": unit["language"],
                                    "label": unit["label"],
                                    "y_true": 1 if unit["label"] else 0,
                                    "split": unit["split"],
                                    "model": model_key,
                                    "method": method,
                                    "status": "api_error",
                                    "valid": False,
                                    "predicted_label": None,
                                    "y_pred": None,
                                    "error": {"type": "client_exception", "message": str(exc)},
                                    "prompt": {"method": method},
                                    "usage": None,
                                    "cost": {"cost_usd": None},
                                    "latency_seconds": None,
                                }
                                prompt_meta = {"method": method}
                            append_jsonl(results_path, record)
                            request_record = {
                                "unit_id": unit["unit_id"],
                                "model": model_key,
                                "method": method,
                                "prompt": prompt_meta,
                                "status": record["status"],
                                "latency_seconds": record.get("latency_seconds"),
                                "usage": record.get("usage"),
                                "cost": record.get("cost"),
                                "error": record.get("error"),
                            }
                            append_jsonl(requests_path, request_record)
                            outcomes.append(record)
                            done = len(outcomes)
                            if done % 10 == 0 or done == len(remaining):
                                print(
                                    f"[{model_key}/{method}] {done}/{len(remaining)} "
                                    f"ok={sum(1 for r in outcomes if r['status']=='ok')} "
                                    f"invalid={sum(1 for r in outcomes if r['status']=='invalid')} "
                                    f"error={sum(1 for r in outcomes if r['status']=='api_error')}",
                                    flush=True,
                                )
                records = compact_results(results_path) if results_path.exists() else []
                manifest.update(
                    {
                        "finished_at_utc": utc_now(),
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "recorded_units": len(records),
                        "counts": {
                            "ok": sum(1 for r in records if r["status"] == "ok"),
                            "invalid": sum(1 for r in records if r["status"] == "invalid"),
                            "api_error": sum(1 for r in records if r["status"] == "api_error"),
                        },
                    }
                )
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                print(
                    f"[{model_key}/{method}] complete: {manifest['counts']} -> {run_dir}",
                    flush=True,
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())

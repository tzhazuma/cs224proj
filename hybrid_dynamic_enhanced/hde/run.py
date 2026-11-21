"""Run the enhanced-dynamic-guided method: 140 real requests per model.

Only the new method is executed.  v2 direct/dynamic/combined runs are frozen
baselines and are never rewritten.  Credentials are read into process memory
and never printed or stored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from juliet_llm.metrics import SchemaError, parse_verdict
from secvul_runner.client import ChatClient

from . import prompts
from .api import api_config, ensure_direct_network, load_api_key
from .config import (
    DIRECT_PROMPT_VERSION,
    EXPECTED_UNITS,
    GUIDED_PROMPT_VERSION,
    INPUTS_DIR,
    METHOD,
    MODEL_CONFIGS,
    MODELS,
    RESULTS_DIR,
    ROOT,
    RUNS_DIR,
    SCHEMA_VERSION,
)
from .evidence import read_jsonl, sha256_bytes

_WRITE_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    model_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    messages, prompt_meta = prompts.build_guided(unit)
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
        "method": METHOD,
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
        "evidence_outcome": unit["enhanced_outcome"],
        "evidence_primary_mode": unit["enhanced_primary_mode"],
        "evidence_sha256": unit["enhanced_evidence_sha256"],
        "tool_verdict": 1 if unit["enhanced_outcome"] == "leak" else 0,
        "old_dynamic_outcome": unit.get("dynamic_outcome"),
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


def totals(records: list[dict[str, Any]]) -> dict[str, Any]:
    def usage_value(record: dict[str, Any], key: str) -> float:
        usage = record.get("usage") or {}
        opencode = usage.get("opencode") or {}
        return float(opencode.get(key) or 0.0)

    configured = sum(float((record.get("cost") or {}).get("cost_usd") or 0.0) for record in records)
    return {
        "records": len(records),
        "ok": sum(1 for record in records if record["status"] == "ok"),
        "invalid": sum(1 for record in records if record["status"] == "invalid"),
        "api_error": sum(1 for record in records if record["status"] == "api_error"),
        "prompt_tokens": sum(int((record.get("usage") or {}).get("prompt_tokens") or 0) for record in records),
        "completion_tokens": sum(int((record.get("usage") or {}).get("completion_tokens") or 0) for record in records),
        "cached_tokens": sum(
            int(((record.get("usage") or {}).get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
            for record in records
        ),
        "configured_usd": configured,
        "provider_list_usd": sum(usage_value(record, "list_cost") for record in records),
        "allowance_usd": sum(usage_value(record, "allowance") for record in records),
        "attempts": sum(int(record.get("attempts") or 0) for record in records),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["deepseek", "mimo", "all"], required=True)
    parser.add_argument("--run-id", default="enhanced_dynamic_v1")
    parser.add_argument("--inputs-dir", type=Path, default=INPUTS_DIR)
    parser.add_argument("--preflight", type=Path, default=RESULTS_DIR / "preflight.json")
    parser.add_argument("--out-root", type=Path, default=RUNS_DIR)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0, help="0 = all 140 units; only for debugging")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-invalid", action="store_true")
    args = parser.parse_args(argv)

    args.inputs_dir = args.inputs_dir.resolve()
    args.preflight = args.preflight.resolve()
    args.out_root = args.out_root.resolve()

    units_path = args.inputs_dir / "units.jsonl"
    manifest_path = args.inputs_dir / "manifest.json"
    if not units_path.is_file() or not manifest_path.is_file():
        parser.error(f"input pack not found under {args.inputs_dir}")
    input_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    units = read_jsonl(units_path)
    units.sort(key=lambda unit: unit["unit_id"])
    if len(units) != EXPECTED_UNITS:
        raise SystemExit(f"expected {EXPECTED_UNITS} units, found {len(units)}")
    if sha256_bytes(units_path.read_bytes()) != input_manifest.get("units_sha256"):
        raise SystemExit("input pack does not match its manifest")

    preflight = json.loads(args.preflight.read_text(encoding="utf-8"))
    if not preflight.get("ok"):
        raise SystemExit(f"preflight gate failed: {preflight.get('failures')}")
    if preflight.get("prompt_version") != GUIDED_PROMPT_VERSION:
        raise SystemExit(
            f"preflight prompt version {preflight.get('prompt_version')} != {GUIDED_PROMPT_VERSION}"
        )
    if (preflight.get("input_pack") or {}).get("units_sha256") != input_manifest.get("units_sha256"):
        raise SystemExit("preflight report does not cover this input pack")
    preflight_record = {
        "path": str(args.preflight.relative_to(ROOT)) if args.preflight.is_relative_to(ROOT) else str(args.preflight),
        "sha256": hashlib.sha256(args.preflight.read_bytes()).hexdigest(),
        "ok": True,
    }
    print(f"preflight gate passed: {preflight_record['path']}", flush=True)

    if args.limit:
        units = units[: args.limit]
    expected = len(units)
    models = list(MODELS) if args.model == "all" else [args.model]
    api_key = load_api_key()

    for model_key in models:
        spec = api_config(model_key)
        network = ensure_direct_network(spec.base_url)
        run_dir = args.out_root / f"{args.run_id}_{model_key}"
        if run_dir.exists() and not args.resume:
            raise SystemExit(f"run directory already exists (use --resume or a new --run-id): {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=True)
        results_path = run_dir / "results.jsonl"
        requests_path = run_dir / "requests.jsonl"
        config_path = run_dir / "config.json"
        manifest_path_run = run_dir / "manifest.json"

        completed: dict[str, dict[str, Any]] = {}
        if args.resume and results_path.exists():
            completed = {record["unit_id"]: record for record in compact_results(results_path)}
        remaining = [unit for unit in units if unit["unit_id"] not in completed]
        if args.retry_invalid:
            remaining = [
                unit
                for unit in units
                if unit["unit_id"] not in completed
                or completed[unit["unit_id"]]["status"] in {"api_error", "invalid"}
            ]

        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "api": spec.public_dict(),
                    "prompt_version": GUIDED_PROMPT_VERSION,
                    "direct_prompt_version": DIRECT_PROMPT_VERSION,
                    "input_units_sha256": input_manifest["units_sha256"],
                    "method": METHOD,
                    "limit": args.limit,
                    "preflight_sha256": preflight_record["sha256"],
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        config_record = {
            "schema_version": SCHEMA_VERSION,
            "run_id": f"{args.run_id}_{model_key}",
            "model_key": model_key,
            "model_display_name": MODEL_CONFIGS[model_key]["display_name"],
            "method": METHOD,
            "prompt_version": GUIDED_PROMPT_VERSION,
            "direct_prompt_version": DIRECT_PROMPT_VERSION,
            "api": spec.public_dict(),
            "dataset": {
                "path": str(units_path.relative_to(ROOT)),
                "sha256": input_manifest["units_sha256"],
                "units": expected,
                "partial": bool(args.limit),
            },
            "concurrency": args.concurrency,
            "config_fingerprint": fingerprint,
            "preflight": preflight_record,
            "network": network,
            "credentials": "read from local Kimi Code config into process memory; never logged",
        }
        config_path.write_text(json.dumps(config_record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        run_manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": f"{args.run_id}_{model_key}",
            "started_at_utc": utc_now(),
            "finished_at_utc": None,
            "model": spec.model,
            "base_url": spec.base_url,
            "method": METHOD,
            "prompt_version": GUIDED_PROMPT_VERSION,
            "expected_units": expected,
            "partial": bool(args.limit),
            "concurrency": args.concurrency,
            "results_file": "results.jsonl",
        }
        manifest_path_run.write_text(json.dumps(run_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if not requests_path.exists():
            requests_path.touch()

        started = time.monotonic()
        outcomes: list[dict[str, Any]] = []
        if remaining:
            with ChatClient(spec, api_key) as client:
                with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                    futures = {
                        pool.submit(evaluate_one, client, unit, model_key): unit for unit in remaining
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
                                "method": METHOD,
                                "status": "api_error",
                                "valid": False,
                                "predicted_label": None,
                                "y_pred": None,
                                "error": {"type": "client_exception", "message": str(exc)},
                                "prompt": {"method": METHOD},
                                "usage": None,
                                "cost": {"cost_usd": None},
                                "latency_seconds": None,
                                "attempts": 0,
                            }
                            prompt_meta = {"method": METHOD}
                        append_jsonl(results_path, record)
                        append_jsonl(
                            requests_path,
                            {
                                "unit_id": unit["unit_id"],
                                "model": model_key,
                                "method": METHOD,
                                "prompt": prompt_meta,
                                "status": record["status"],
                                "latency_seconds": record.get("latency_seconds"),
                                "usage": record.get("usage"),
                                "cost": record.get("cost"),
                                "error": record.get("error"),
                            },
                        )
                        outcomes.append(record)
                        done = len(outcomes)
                        if done % 10 == 0 or done == len(remaining):
                            print(
                                f"[{model_key}] {done}/{len(remaining)} "
                                f"ok={sum(1 for r in outcomes if r['status'] == 'ok')} "
                                f"invalid={sum(1 for r in outcomes if r['status'] == 'invalid')} "
                                f"error={sum(1 for r in outcomes if r['status'] == 'api_error')}",
                                flush=True,
                            )

        records = compact_results(results_path) if results_path.exists() else []
        summary = totals(records)
        run_manifest.update(
            {
                "finished_at_utc": utc_now(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "recorded_units": len(records),
                "counts": {
                    "ok": summary["ok"],
                    "invalid": summary["invalid"],
                    "api_error": summary["api_error"],
                },
                "usage": {
                    "prompt_tokens": summary["prompt_tokens"],
                    "completion_tokens": summary["completion_tokens"],
                    "cached_tokens": summary["cached_tokens"],
                    "attempts": summary["attempts"],
                },
                "cost": {
                    "configured_usd": summary["configured_usd"],
                    "provider_list_usd": summary["provider_list_usd"],
                    "allowance_usd": summary["allowance_usd"],
                },
            }
        )
        manifest_path_run.write_text(json.dumps(run_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[{model_key}] complete: {run_manifest['counts']} cost={summary['configured_usd']:.6f} -> {run_dir}", flush=True)
        if summary["ok"] != expected or summary["invalid"] or summary["api_error"]:
            print(f"[{model_key}] INCOMPLETE run; rerun with --resume --retry-invalid", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

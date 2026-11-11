#!/usr/bin/env python3
"""Import the round-2 real experiments into the unified benchmark schema.

The five source families are read-only:

* ``evidence_prompt/runs/test_evidence_{deepseek,mimo}``  (Tier A detection)
* ``pair_joint/runs/test_{deepseek,mimo}_180``            (Tier A forced-choice pair)
* ``hybrid/runs/hybrid_v2_<model>_<method>``              (Tier B canonical, 2 x 5 x 140)
* ``juliet_llm/runs/...xiaomi_official_postleakfix``      (Tier B MiMo fallback, canonical)
* ``juliet_repair/runs/{deepseek,mimo}_test70_final``      (Tier B repair)

Nothing in those directories is modified. Predictions, labels, usage and
latency are copied record by record. The one derived quantity is the
forced-choice pair representation: one joint request is written as two
canonical side records, with the request cost/wall split evenly and the
token/latency fields assigned once so that run totals are not double-counted.

The adapter deliberately does not read or copy API keys or Authorization
headers. Manifests only record endpoint, model id and safe decoding metadata.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (  # noqa: E402
    PREDICTION_SCHEMA_VERSION,
    PROTOCOL_VERSION,
    RUN_SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    read_json,
    read_jsonl,
    sha256_file,
    sha256_text,
    utc_now,
)
from bench_metrics import compute_run_metrics  # noqa: E402
from bench_validate import validate_run  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[2]
IMPORT_VERSION = "bench-import-round2-1.1.0"

SECVUL_DETECTION_SHA = "bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8"
SECVUL_PAIRS_SHA = "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d"
JULIET_UNITS_SHA = "4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24"
JULIET_MANIFEST_SHA = "8df222f84a4295f3b90ae7cabe165adc04858d91def3fda19a073db6e17cafd6"

MODEL_META = {
    "deepseek-v4.1-flash": {
        "family": "deepseek",
        "display": "DeepSeek V4.1 Flash",
        "provider": "opencode-go",
        "endpoint": "https://opencode.ai/zen/go/v1/chat/completions",
    },
    "mimo-v2.6-flash": {
        "family": "mimo",
        "display": "MiMo-V2.6-Flash",
        "provider": "opencode-go",
        "endpoint": "https://opencode.ai/zen/go/v1/chat/completions",
    },
}
XIAOMI_ENDPOINT = "https://api.xiaomimimo.com/v1/chat/completions"
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _cwes(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        for match in CWE_RE.finditer(item):
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in found:
                found.append(cwe)
    return found


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def _number(value: object, *, integer: bool = False) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0:
        return None
    return int(value) if integer else float(value)


def _bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _int(value: object) -> int | None:
    number = _number(value, integer=True)
    return int(number) if number is not None else None


def _hash(value: object) -> str | None:
    if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return value
    return None


def _iso(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _model_block(
    model_id: str,
    *,
    provider: str | None = None,
    endpoint: str | None = None,
    decoding: Mapping[str, Any] | None = None,
    pricing: Mapping[str, Any] | None = None,
    price_snapshot: str | None = None,
) -> dict[str, Any]:
    meta = MODEL_META.get(model_id, {})
    return {
        "model_id": model_id,
        "family": str(meta.get("family") or "unknown"),
        "provider": provider or str(meta.get("provider") or "unknown"),
        "endpoint": endpoint or meta.get("endpoint"),
        "version": None,
        "context_window": None,
        "tokenizer": None,
        "decoding": dict(decoding or {}),
        "pricing_usd_per_1m": dict(pricing or {}),
        "price_snapshot": price_snapshot,
    }


def _usage(
    prompt_tokens: object = None,
    completion_tokens: object = None,
    cached_prompt_tokens: object = None,
    reasoning_tokens: object = None,
    latency_ms: object = None,
    api_attempts: object = None,
) -> dict[str, Any]:
    return {
        "prompt_tokens": _int(prompt_tokens),
        "completion_tokens": _int(completion_tokens),
        "cached_prompt_tokens": _int(cached_prompt_tokens),
        "reasoning_tokens": _int(reasoning_tokens),
        "latency_ms": _number(latency_ms),
        "api_attempts": (_int(api_attempts) if (_int(api_attempts) or 0) > 0 else None),
    }


def _cost(
    usd: object,
    wall_s: object,
    *,
    basis: str = "api_price",
    note: str | None = None,
    pricing_snapshot: str | None = None,
) -> dict[str, Any]:
    return {
        "usd": _number(usd),
        "wall_s": _number(wall_s),
        "cpu_s": None,
        "peak_rss_mb": None,
        "currency": "USD",
        "cost_basis": basis,
        "pricing_snapshot": pricing_snapshot,
        "note": note,
    }


def _error(kind: str, message: str, *, http_status: object = None, attempt: object = None) -> dict[str, Any]:
    return {
        "type": kind,
        "message": message,
        "retryable": False,
        "attempt": _int(attempt),
        "http_status": _int(http_status),
    }


def _record(
    *,
    run_id: str,
    tier: str,
    track: str,
    task: str,
    unit_id: str,
    cluster_id: str,
    group_id: str | None,
    side: str | None,
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    input_block: Mapping[str, Any],
    label: Mapping[str, Any],
    prediction: Mapping[str, Any],
    status: str,
    error: Mapping[str, Any] | None,
    coverage: Mapping[str, Any] | None,
    usage: Mapping[str, Any] | None,
    cost: Mapping[str, Any] | None,
    provenance: Mapping[str, Any],
    extensions: Mapping[str, Any],
    oracle: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    unit_manifest = dataset.get("unit_manifest") if isinstance(dataset.get("unit_manifest"), dict) else None
    dataset_ref = {
        "dataset_id": dataset.get("dataset_id"),
        "split_id": dataset.get("split_id"),
        "sha256": dataset.get("sha256"),
        "unit_manifest_sha256": unit_manifest.get("sha256") if unit_manifest else None,
    }
    record: dict[str, Any] = {
        "schema_version": PREDICTION_SCHEMA_VERSION,
        "run_id": run_id,
        "tier": tier,
        "track": track,
        "task": task,
        "unit_id": unit_id,
        "cluster_id": cluster_id,
        "group_id": group_id,
        "side": side,
        "dataset": dataset_ref,
        "method": {key: value for key, value in method.items() if key != "prompt_version"},
        "input": dict(input_block),
        "label": dict(label),
        "prediction": dict(prediction),
        "status": status,
        "error": dict(error) if error else None,
        "coverage": dict(coverage) if coverage else None,
        "usage": dict(usage) if usage else None,
        "cost": dict(cost) if cost else None,
        "provenance": dict(provenance),
        "extensions": dict(extensions),
    }
    if oracle is not None:
        record["oracle"] = dict(oracle)
    return record


def _write_run(
    out_dir: Path,
    run_id: str,
    manifest: Mapping[str, Any],
    predictions: Sequence[Mapping[str, Any]],
    *,
    source_paths: Sequence[Path],
    provenance_markdown: Sequence[str],
    force: bool,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if not force and any(out_dir.iterdir()):
        raise FileExistsError(f"{out_dir} is not empty; pass --force to replace derived artifacts")
    predictions_path = out_dir / "predictions.jsonl"
    atomic_write_text(
        predictions_path,
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in predictions),
    )
    payload = dict(manifest)
    payload["run_id"] = run_id
    payload["created_at"] = utc_now()
    payload["artifacts"] = {
        "predictions": "predictions.jsonl",
        "metrics": "metrics.json",
        "validation": "validation.json",
        "log": None,
    }
    hashes = dict(payload.get("hashes") or {})
    hashes["predictions_sha256"] = sha256_file(predictions_path)
    for path in source_paths:
        hashes[f"source_{path.name.replace('.', '_')}_sha256"] = sha256_file(path)
    payload["hashes"] = hashes
    atomic_write_json(out_dir / "run_manifest.json", payload)
    atomic_write_text(
        out_dir / "PROVENANCE.md",
        "\n".join(
            [
                f"# Derived benchmark run: `{run_id}`",
                "",
                f"- conversion tool: `{IMPORT_VERSION}`",
                f"- derived, not re-run; predictions and labels copied from source artifacts",
                f"- records: {len(predictions)}",
                "",
                *provenance_markdown,
                "",
            ]
        ),
    )
    return {
        "run_id": run_id,
        "run_dir": _rel(out_dir),
        "records": len(predictions),
        "predictions_sha256": hashes["predictions_sha256"],
    }


def _dataset(
    *,
    dataset_id: str,
    split_id: str,
    path: str,
    sha256: str,
    unit_count: int,
    group_count: int | None,
    label_counts: Mapping[str, int],
    unit_manifest: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "split_id": split_id,
        "path": path,
        "sha256": sha256,
        "unit_manifest": dict(unit_manifest) if unit_manifest else None,
        "unit_count": unit_count,
        "group_count": group_count,
        "label_counts": dict(label_counts),
    }


def _manifest(
    *,
    run_id: str,
    tier: str,
    track: str,
    tasks: Sequence[str],
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    execution: Mapping[str, Any],
    notes: Sequence[str],
    source_paths: Sequence[Path],
    hashes: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": utc_now(),
        "protocol_version": PROTOCOL_VERSION,
        "tier": tier,
        "track": track,
        "tasks": list(tasks),
        "dataset": dict(dataset),
        "method": dict(method),
        "execution": dict(execution),
        "artifacts": {},
        "hashes": dict(hashes),
        "legacy_import": None,
        "notes": list(notes),
    }


# ---------------------------------------------------------------------------
# Tier A evidence prompt
# ---------------------------------------------------------------------------


def _detection_index() -> dict[str, dict[str, Any]]:
    path = PROJECT_ROOT / "splits" / "test_detection_160.json"
    actual = sha256_file(path)
    if actual != SECVUL_DETECTION_SHA:
        raise ValueError(f"{path}: SHA-256 {actual} does not match frozen split")
    data = read_json(path)
    index: dict[str, dict[str, Any]] = {}
    for sample in data.get("samples") or []:
        index[str(sample["idx"])] = sample
    if len(index) != 160:
        raise ValueError(f"{path}: expected 160 detection samples, found {len(index)}")
    return index


def import_evidence(model_key: str, *, force: bool = False) -> dict[str, Any]:
    source_dir = PROJECT_ROOT / "evidence_prompt" / "runs" / f"test_evidence_{model_key}"
    manifest_path = source_dir / "manifest.json"
    results_path = source_dir / "results.jsonl"
    raw_manifest = read_json(manifest_path)
    records = read_jsonl(results_path)
    api = raw_manifest.get("api") or {}
    config = raw_manifest.get("config") or {}
    model_id = str(api.get("model") or "")
    meta = MODEL_META.get(model_id)
    if meta is None:
        raise ValueError(f"{source_dir}: unknown model id {model_id!r}")
    detection = _detection_index()
    source_sha = sha256_file(results_path)
    run_id = f"tiera_secvuleval_{meta['family']}_evidence_20261112_{source_sha[:8]}"
    out_dir = PROJECT_ROOT / "benchmark" / "results" / "tier_a" / f"{meta['family']}_evidence" / run_id
    prompt_version = str(config.get("prompt_version") or "")
    prompt_template = _hash(config.get("template_sha256"))
    decoding = {
        "temperature": api.get("temperature"),
        "max_tokens": api.get("max_tokens"),
        "max_tokens_field": api.get("max_tokens_field"),
        "thinking": api.get("thinking"),
        "reasoning_effort": api.get("reasoning_effort"),
        "response_format": api.get("response_format"),
        "timeout_seconds": api.get("timeout_seconds"),
    }
    pricing = {
        "input": api.get("input_price_usd_per_1m"),
        "output": api.get("output_price_usd_per_1m"),
        "cached_input": api.get("cached_input_price_usd_per_1m"),
    }
    method = {
        "method_id": f"llm.{meta['family']}.evidence",
        "family": "llm",
        "name": f"{meta['display']} / evidence-lines + counterfactual",
        "strategy": "evidence",
        "prompt_version": prompt_version,
        "config_sha256": _hash(raw_manifest.get("config_fingerprint")),
        "model": _model_block(
            model_id,
            decoding=decoding,
            pricing=pricing,
            price_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
        ),
        "tool": None,
    }
    dataset = _dataset(
        dataset_id="secvul-split-v1",
        split_id="secvul-split-v1",
        path="splits/test_detection_160.json",
        sha256=SECVUL_DETECTION_SHA,
        unit_count=160,
        group_count=None,
        label_counts={"vulnerable": 128, "non_vulnerable": 32},
    )
    predictions: list[dict[str, Any]] = []
    retries = 0
    for index, record in enumerate(records):
        idx = str(record.get("idx"))
        sample = detection.get(idx)
        if sample is None:
            raise ValueError(f"{results_path}: unknown idx {idx!r}")
        raw_status = str(record.get("status") or "not_run")
        parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
        y_pred = parsed.get("is_vulnerable") if isinstance(parsed.get("is_vulnerable"), bool) else None
        status = "ok" if raw_status == "ok" and y_pred is not None else "schema_invalid"
        error = None if status == "ok" else _error("schema_invalid", f"raw status={raw_status}; parsed.is_vulnerable is not a boolean")
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        raw_usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        raw_cost = response.get("cost") if isinstance(response.get("cost"), dict) else {}
        details = raw_usage.get("completion_tokens_details") if isinstance(raw_usage.get("completion_tokens_details"), dict) else {}
        prompt_details = raw_usage.get("prompt_tokens_details") if isinstance(raw_usage.get("prompt_tokens_details"), dict) else {}
        attempts = response.get("attempts") if isinstance(response.get("attempts"), list) else []
        if len(attempts) > 1:
            retries += len(attempts) - 1
        latency_s = response.get("request_latency_seconds")
        if not isinstance(latency_s, (int, float)):
            latency_s = response.get("wall_seconds")
        input_block = {
            "view": "function",
            "source_sha256": _hash((record.get("prompt") or {}).get("function", {}).get("code_sha256")),
            "prompt_sha256": _hash((record.get("request") or {}).get("body_sha256")),
            "context_mode": "none",
            "sanitized": False,
            "sanitizer_version": None,
            "evidence_sha256": None,
        }
        predictions.append(
            _record(
                run_id=run_id,
                tier="A",
                track="secvuleval",
                task="detection",
                unit_id=f"secvul:det:{idx}",
                cluster_id=str(sample.get("project") or "unknown"),
                group_id=None,
                side=None,
                dataset=dataset,
                method=method,
                input_block=input_block,
                label={
                    "y_true": bool(sample.get("is_vulnerable")),
                    "cwe": _cwes(sample.get("cwe_list")),
                    "label_source": "secvuleval",
                    "label_note": None,
                },
                prediction={
                    "y_pred": y_pred if status == "ok" else None,
                    "cwe_pred": [],
                    "confidence": parsed.get("confidence") if status == "ok" else None,
                    "evidence_lines": [
                        value
                        for value in (parsed.get("evidence_lines") or [])
                        if isinstance(value, int) and not isinstance(value, bool) and value >= 1
                    ],
                    "rationale": parsed.get("mechanism") if isinstance(parsed.get("mechanism"), str) else None,
                    "raw_output_sha256": (
                        sha256_text(response["content"])
                        if isinstance(response.get("content"), str)
                        else None
                    ),
                    "fixed_function": None,
                },
                status=status,
                error=error,
                coverage=None,
                usage=_usage(
                    raw_cost.get("prompt_tokens", raw_usage.get("prompt_tokens")),
                    raw_cost.get("completion_tokens", raw_usage.get("completion_tokens")),
                    raw_cost.get("cached_prompt_tokens", prompt_details.get("cached_tokens")),
                    details.get("reasoning_tokens"),
                    float(latency_s) * 1000.0 if isinstance(latency_s, (int, float)) else None,
                    len(attempts),
                ),
                cost=_cost(
                    raw_cost.get("cost_usd"),
                    latency_s,
                    note="API list-price computation; provider allowance may differ",
                    pricing_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
                ),
                provenance={
                    "produced_by": IMPORT_VERSION,
                    "created_at": str(record.get("created_at") or utc_now()),
                    "source_artifact": _rel(results_path),
                    "source_sha256": source_sha,
                    "record_index": index,
                    "command_sha256": None,
                    "legacy_run_id": str(raw_manifest.get("run_id") or source_dir.name),
                    "note": "detection record copied from the evidence-prompt run; prediction not changed",
                },
                extensions={
                    "strategy": "evidence",
                    "request_index": record.get("request_index"),
                    "raw_status": raw_status,
                    "prompt_only_source_variable": (record.get("prompt") or {}).get("only_source_variable"),
                    "source_reconstructed": (record.get("prompt") or {}).get("source_reconstructed"),
                    "counterfactual_confirms": parsed.get("counterfactual_confirms"),
                    "counterfactual_unconfirmed": (record.get("validation") or {}).get("counterfactual_unconfirmed"),
                    "schema_valid": (record.get("validation") or {}).get("schema_valid"),
                },
            )
        )
    execution = {
        "started_at": _iso(raw_manifest.get("started_at")),
        "finished_at": _iso(raw_manifest.get("completed_at")),
        "status": "completed",
        "planned_units": 160,
        "recorded_units": len(predictions),
        "retries": retries,
        "concurrency": config.get("concurrency"),
        "command": None,
        "command_sha256": None,
        "environment": {"source_run": _rel(source_dir), "endpoint": api.get("base_url")},
    }
    manifest = _manifest(
        run_id=run_id,
        tier="A",
        track="secvuleval",
        tasks=["detection"],
        dataset=dataset,
        method=method,
        execution=execution,
        notes=[
            "Derived view over the real evidence-prompt run; no model call and no prediction change.",
            "Input is the numbered function source only; prompt wrapper contains no project/CVE/CWE/label metadata.",
            "Two model runs share the frozen detection split and the same six-field output contract.",
        ],
        source_paths=[results_path, manifest_path],
        hashes={
            "source_results_sha256": source_sha,
            "source_manifest_sha256": sha256_file(manifest_path),
            "dataset_sha256": SECVUL_DETECTION_SHA,
            "prompt_template_sha256": prompt_template,
        },
    )
    return _write_run(
        out_dir,
        run_id,
        manifest,
        predictions,
        source_paths=[results_path, manifest_path],
        provenance_markdown=[
            f"- source run: `{_rel(source_dir)}`",
            f"- source results SHA-256: `{source_sha}`",
            f"- model: `{model_id}` ({meta['family']})",
            f"- prompt version: `{prompt_version}`",
            f"- endpoint: `{api.get('base_url')}`",
        ],
        force=force,
    )


# ---------------------------------------------------------------------------
# Tier A pair-joint forced choice
# ---------------------------------------------------------------------------


def _pair_index() -> dict[str, dict[str, Any]]:
    path = PROJECT_ROOT / "splits" / "test_pairs_180.json"
    actual = sha256_file(path)
    if actual != SECVUL_PAIRS_SHA:
        raise ValueError(f"{path}: SHA-256 {actual} does not match frozen split")
    data = read_json(path)
    index: dict[str, dict[str, Any]] = {}
    for pair in data.get("pairs") or []:
        index[str(pair["pair_id"])] = pair
    if len(index) != 180:
        raise ValueError(f"{path}: expected 180 pairs, found {len(index)}")
    return index


def import_pair_joint(model_key: str, *, force: bool = False) -> dict[str, Any]:
    source_dir = PROJECT_ROOT / "pair_joint" / "runs" / f"test_{model_key}_180"
    manifest_path = source_dir / "manifest.json"
    results_path = source_dir / "results.jsonl"
    positions_path = source_dir / "position_map.json"
    raw_manifest = read_json(manifest_path)
    positions = read_json(positions_path)
    records = read_jsonl(results_path)
    api = raw_manifest.get("api") or {}
    model_id = str(api.get("model") or "")
    meta = MODEL_META.get(model_id)
    if meta is None:
        raise ValueError(f"{source_dir}: unknown model id {model_id!r}")
    pairs = _pair_index()
    source_sha = sha256_file(results_path)
    run_id = f"tiera_secvuleval_{meta['family']}_pair_joint_20261112_{source_sha[:8]}"
    out_dir = PROJECT_ROOT / "benchmark" / "results" / "tier_a" / f"{meta['family']}_pair_joint" / run_id
    prompt_version = str((raw_manifest.get("run") or {}).get("prompt_version") or (raw_manifest.get("metrics") or {}).get("run", {}).get("prompt_version") or "")
    if not prompt_version:
        prompt_version = "pair-joint-2026-11-12.1"
    decoding = {
        "temperature": api.get("temperature"),
        "max_tokens": api.get("max_tokens"),
        "max_tokens_field": api.get("max_tokens_field"),
        "thinking": api.get("thinking"),
        "reasoning_effort": api.get("reasoning_effort"),
        "response_format": api.get("response_format"),
        "timeout_seconds": api.get("timeout_seconds"),
    }
    pricing = {
        "input": api.get("input_price_usd_per_1m"),
        "output": api.get("output_price_usd_per_1m"),
        "cached_input": api.get("cached_input_price_usd_per_1m"),
    }
    method = {
        "method_id": f"llm.{meta['family']}.pair_joint_forced_choice",
        "family": "llm",
        "name": f"{meta['display']} / joint A-B forced choice",
        "strategy": "pair_joint_forced_choice",
        "prompt_version": prompt_version,
        "config_sha256": _hash(raw_manifest.get("config_fingerprint")),
        "model": _model_block(
            model_id,
            decoding=decoding,
            pricing=pricing,
            price_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
        ),
        "tool": None,
    }
    dataset = _dataset(
        dataset_id="secvul-split-v1",
        split_id="secvul-split-v1",
        path="splits/test_pairs_180.json",
        sha256=SECVUL_PAIRS_SHA,
        unit_count=360,
        group_count=180,
        label_counts={"vulnerable": 180, "fixed": 180},
    )
    assignments = positions.get("assignments") or {}
    predictions: list[dict[str, Any]] = []
    retries = 0
    for index, record in enumerate(records):
        pair_id = str(record.get("pair_id") or "")
        pair = pairs.get(pair_id)
        if pair is None:
            raise ValueError(f"{results_path}: unknown pair_id {pair_id!r}")
        assignment = assignments.get(pair_id)
        if not isinstance(assignment, dict):
            raise ValueError(f"{positions_path}: missing assignment for {pair_id!r}")
        vulnerable_slot = str(assignment.get("vulnerable_slot") or "")
        fixed_slot = str(assignment.get("fixed_slot") or "")
        parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
        selected = str(parsed.get("vulnerable_version") or "")
        status = "ok" if record.get("status") == "ok" and selected in ("A", "B") else "schema_invalid"
        selected_side = (
            "vulnerable" if selected == vulnerable_slot else "fixed" if selected == fixed_slot else None
        )
        if status == "ok" and selected_side is None:
            status = "schema_invalid"
        error = None if status == "ok" else _error("schema_invalid", "joint output did not select exactly one A/B version")
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        raw_usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        raw_cost = response.get("cost") if isinstance(response.get("cost"), dict) else {}
        details = raw_usage.get("completion_tokens_details") if isinstance(raw_usage.get("completion_tokens_details"), dict) else {}
        prompt_details = raw_usage.get("prompt_tokens_details") if isinstance(raw_usage.get("prompt_tokens_details"), dict) else {}
        attempts = response.get("attempts") if isinstance(response.get("attempts"), list) else []
        if len(attempts) > 1:
            retries += len(attempts) - 1
        request_latency = response.get("request_latency_seconds")
        if not isinstance(request_latency, (int, float)):
            request_latency = response.get("wall_seconds")
        request_usd = raw_cost.get("cost_usd") if isinstance(raw_cost.get("cost_usd"), (int, float)) else None
        half_usd = request_usd / 2.0 if request_usd is not None else None
        half_wall = float(request_latency) / 2.0 if isinstance(request_latency, (int, float)) else None
        evidence = parsed.get("evidence") if isinstance(parsed.get("evidence"), list) else []
        evidence_lines = [
            int(item["line"])
            for item in evidence
            if isinstance(item, dict) and isinstance(item.get("line"), int) and not isinstance(item.get("line"), bool) and item["line"] >= 1
        ]
        evidence_versions = {
            str(item.get("version")) for item in evidence if isinstance(item, dict)
        }
        for side in ("vulnerable", "fixed"):
            member = pair.get(side) or {}
            y_true = bool(member.get("is_vulnerable"))
            if status == "ok":
                y_pred = 1 if selected_side == side else 0
            else:
                y_pred = None
            predictions.append(
                _record(
                    run_id=run_id,
                    tier="A",
                    track="secvuleval",
                    task="pair_detection",
                    unit_id=f"secvul:pair:{pair_id}:{side}",
                    cluster_id=pair_id,
                    group_id=pair_id,
                    side=side,
                    dataset=dataset,
                    method=method,
                    input_block={
                        "view": "pair",
                        "source_sha256": None,
                        "prompt_sha256": _hash(record.get("prompt_sha256")),
                        "context_mode": "none",
                        "sanitized": False,
                        "sanitizer_version": None,
                        "evidence_sha256": None,
                    },
                    label={
                        "y_true": y_true,
                        "cwe": _cwes(member.get("cwe_list")),
                        "label_source": "secvuleval",
                        "label_note": "forced-choice joint task; one response is represented as two side records",
                    },
                    prediction={
                        "y_pred": y_pred,
                        "cwe_pred": [],
                        "confidence": parsed.get("confidence") if status == "ok" else None,
                        "evidence_lines": evidence_lines if side == selected_side else [],
                        "rationale": parsed.get("rationale") if side == selected_side and isinstance(parsed.get("rationale"), str) else None,
                        "raw_output_sha256": (
                            sha256_text(response["content"])
                            if isinstance(response.get("content"), str)
                            else None
                        ),
                        "fixed_function": None,
                    },
                    status=status,
                    error=error,
                    coverage=None,
                    usage=_usage(
                        raw_cost.get("prompt_tokens") if side == "vulnerable" else None,
                        raw_cost.get("completion_tokens") if side == "vulnerable" else None,
                        raw_cost.get("cached_prompt_tokens") if side == "vulnerable" else None,
                        details.get("reasoning_tokens") if side == "vulnerable" else None,
                        float(request_latency) * 1000.0 if side == "vulnerable" and isinstance(request_latency, (int, float)) else None,
                        len(attempts) if side == "vulnerable" else None,
                    ),
                    cost=_cost(
                        half_usd,
                        half_wall,
                        note="one joint request split evenly across two canonical side records",
                        pricing_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
                    ),
                    provenance={
                        "produced_by": IMPORT_VERSION,
                        "created_at": str(record.get("created_at") or utc_now()),
                        "source_artifact": _rel(results_path),
                        "source_sha256": source_sha,
                        "record_index": index,
                        "command_sha256": None,
                        "legacy_run_id": str(raw_manifest.get("run_id") or source_dir.name),
                        "note": "joint forced-choice response copied and split into two side records; not a side-wise verdict",
                    },
                    extensions={
                        "forced_choice": True,
                        "protocol_variant": "joint_forced_binary",
                        "selected_version": selected,
                        "selected_side": selected_side,
                        "vulnerable_slot": vulnerable_slot,
                        "fixed_slot": fixed_slot,
                        "position_index": assignment.get("order_index"),
                        "evidence_count": len(evidence),
                        "evidence_versions": sorted(evidence_versions),
                        "evidence_compliant": (record.get("validation") or {}).get("evidence", {}).get("evidence_compliant")
                        if isinstance((record.get("validation") or {}).get("evidence"), dict)
                        else None,
                        "joint_request": {
                            "cost_usd": request_usd,
                            "prompt_tokens": raw_cost.get("prompt_tokens"),
                            "completion_tokens": raw_cost.get("completion_tokens"),
                            "cached_prompt_tokens": raw_cost.get("cached_prompt_tokens"),
                            "latency_s": request_latency,
                            "attempts": len(attempts),
                        },
                        "raw_status": record.get("status"),
                    },
                )
            )
    execution = {
        "started_at": _iso(raw_manifest.get("created_at")),
        "finished_at": _iso(raw_manifest.get("completed_at")),
        "status": "completed",
        "planned_units": 360,
        "recorded_units": len(predictions),
        "retries": retries,
        "concurrency": raw_manifest.get("concurrency"),
        "command": None,
        "command_sha256": None,
        "environment": {"source_run": _rel(source_dir), "endpoint": api.get("base_url")},
    }
    manifest = _manifest(
        run_id=run_id,
        tier="A",
        track="secvuleval",
        tasks=["pair_detection"],
        dataset=dataset,
        method=method,
        execution=execution,
        notes=[
            "FORCED-CHOICE JOINT TASK: the model sees both versions once and must choose exactly one as vulnerable.",
            "Do not pool this run with side-wise free-form pair runs; the task and output space differ.",
            "One joint request is represented as two canonical side records; cost/wall is split 50/50 and tokens/latency are assigned once.",
        ],
        source_paths=[results_path, manifest_path, positions_path],
        hashes={
            "source_results_sha256": source_sha,
            "source_manifest_sha256": sha256_file(manifest_path),
            "source_position_map_sha256": sha256_file(positions_path),
            "dataset_sha256": SECVUL_PAIRS_SHA,
        },
    )
    return _write_run(
        out_dir,
        run_id,
        manifest,
        predictions,
        source_paths=[results_path, manifest_path, positions_path],
        provenance_markdown=[
            f"- source run: `{_rel(source_dir)}`",
            f"- source results SHA-256: `{source_sha}`",
            f"- model: `{model_id}` ({meta['family']})",
            f"- task: joint forced choice, 180 pairs",
            f"- endpoint: `{api.get('base_url')}`",
        ],
        force=force,
    )


# ---------------------------------------------------------------------------
# Tier B hybrid evidence suite
# ---------------------------------------------------------------------------

HYBRID_METHOD_LABELS = {
    "direct": "direct (no evidence)",
    "static": "static evidence",
    "dynamic": "dynamic evidence",
    "combined": "static + dynamic evidence",
    "shuffled": "shuffled placebo evidence",
}


def _juliet_units() -> dict[str, dict[str, Any]]:
    path = PROJECT_ROOT / "juliet" / "subset_units.jsonl"
    actual = sha256_file(path)
    if actual != JULIET_UNITS_SHA:
        raise ValueError(f"{path}: SHA-256 {actual} does not match frozen subset")
    units = read_jsonl(path)
    return {str(unit["unit_id"]): unit for unit in units}


def _juliet_manifest_units() -> dict[str, dict[str, Any]]:
    path = PROJECT_ROOT / "juliet" / "manifest.json"
    actual = sha256_file(path)
    if actual != JULIET_MANIFEST_SHA:
        raise ValueError(f"{path}: SHA-256 {actual} does not match frozen manifest")
    data = read_json(path)
    return {str(unit["unit_id"]): unit for unit in data.get("units") or []}


def _oracle_for(unit: Mapping[str, Any]) -> dict[str, Any]:
    runtime = unit.get("runtime_check") if isinstance(unit.get("runtime_check"), dict) else {}
    leak = runtime.get("leak_detected")
    if leak is True:
        consensus = "leak"
    elif leak is False:
        consensus = "clean"
    else:
        consensus = "unknown"
    return {
        "reference": "juliet_intended",
        "dynamic_consensus": consensus,
        "lsan": consensus,
        "valgrind": None,
        "mismatch": False,
        "note": "juliet/manifest.json runtime_check; clean is no observed leak, not a safety proof",
    }


def import_hybrid(model_key: str, method: str, *, version: str = "v2", force: bool = False) -> dict[str, Any]:
    source_dir = PROJECT_ROOT / "hybrid" / "runs" / f"hybrid_{version}_{model_key}_{method}"
    config_path = source_dir / "config.json"
    manifest_path = source_dir / "manifest.json"
    results_path = source_dir / "results.jsonl"
    config = read_json(config_path)
    raw_manifest = read_json(manifest_path)
    records = read_jsonl(results_path)
    api = config.get("api") or {}
    model_id = str(api.get("model") or raw_manifest.get("model_id") or "")
    meta = MODEL_META.get(model_id)
    if meta is None:
        raise ValueError(f"{source_dir}: unknown model id {model_id!r}")
    units = _juliet_units()
    source_sha = sha256_file(results_path)
    input_pack = config.get("dataset") if isinstance(config.get("dataset"), dict) else {}
    input_pack_path = str(input_pack.get("path") or "")
    input_pack_sha = _hash(input_pack.get("sha256"))
    sanitizer_version = f"juliet-llm-cleaning-2026-11-12.{version.lstrip('v')}"
    family = "llm" if method == "direct" else "hybrid"
    method_id = f"llm.{meta['family']}.juliet_direct" if method == "direct" else f"hybrid.{meta['family']}.{method}"
    method_name = f"{meta['display']} / {HYBRID_METHOD_LABELS[method]} (Juliet {version})"
    run_id = f"tierb_juliet_cwe401_hybrid_{version}_{meta['family']}_{method}_20261112_{source_sha[:8]}"
    out_dir = (
        PROJECT_ROOT
        / "benchmark"
        / "results"
        / "tier_b"
        / "juliet_cwe401"
        / f"hybrid_{meta['family']}_{method}"
        / run_id
    )
    decoding = {
        "temperature": api.get("temperature"),
        "max_tokens": api.get("max_tokens"),
        "max_tokens_field": api.get("max_tokens_field"),
        "thinking": api.get("thinking"),
        "reasoning_effort": api.get("reasoning_effort"),
        "response_format": api.get("response_format"),
        "timeout_seconds": api.get("timeout_seconds"),
    }
    pricing = {
        "input": api.get("input_price_usd_per_1m"),
        "output": api.get("output_price_usd_per_1m"),
        "cached_input": api.get("cached_input_price_usd_per_1m"),
    }
    method_block = {
        "method_id": method_id,
        "family": family,
        "name": method_name,
        "strategy": method,
        "prompt_version": config.get("prompt_version"),
        "config_sha256": _hash(config.get("config_fingerprint")),
        "model": _model_block(
            model_id,
            decoding=decoding,
            pricing=pricing,
            price_snapshot="OpenCode Go off-peak list prices; 2026-11-12 snapshot (0.15/0.60/0.003 DeepSeek; 0.14/0.28/0.0028 MiMo)",
        ),
        "tool": None,
    }
    dataset = _dataset(
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id="juliet-cwe401-v1.3-subset-v1",
        path="juliet/subset_units.jsonl",
        sha256=JULIET_UNITS_SHA,
        unit_count=200,
        group_count=100,
        label_counts={"bad": 100, "good": 100},
        unit_manifest={"path": "juliet/manifest.json", "sha256": JULIET_MANIFEST_SHA},
    )
    predictions: list[dict[str, Any]] = []
    retries = 0
    for index, record in enumerate(records):
        raw_unit = units.get(str(record.get("unit_id")))
        if raw_unit is None:
            raise ValueError(f"{results_path}: unknown unit_id {record.get('unit_id')!r}")
        raw_status = str(record.get("status") or "not_run")
        y_pred = record.get("y_pred") if isinstance(record.get("y_pred"), int) else None
        valid = record.get("valid") is True
        status = "ok" if raw_status == "ok" and valid and y_pred in (0, 1) else "schema_invalid"
        error = None if status == "ok" else _error("schema_invalid", f"raw status={raw_status}; valid={valid}")
        response = record.get("response_meta") if isinstance(record.get("response_meta"), dict) else {}
        usage_raw = record.get("usage") if isinstance(record.get("usage"), dict) else {}
        prompt_details = usage_raw.get("prompt_tokens_details") if isinstance(usage_raw.get("prompt_tokens_details"), dict) else {}
        details = usage_raw.get("completion_tokens_details") if isinstance(usage_raw.get("completion_tokens_details"), dict) else {}
        latency_s = record.get("latency_seconds")
        if not isinstance(latency_s, (int, float)):
            latency_s = record.get("request_latency_seconds")
        attempts = record.get("attempts")
        if isinstance(attempts, int) and attempts > 1:
            retries += attempts - 1
        dynamic_outcome = str(record.get("dynamic_outcome") or "unknown")
        runtime_supported = bool(record.get("label") is False or dynamic_outcome == "leak")
        predictions.append(
            _record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=f"juliet:{raw_unit['group_id']}:{raw_unit['label']}",
                cluster_id=str(raw_unit.get("family") or "unknown"),
                group_id=str(raw_unit["group_id"]),
                side=str(raw_unit["label"]),
                dataset=dataset,
                method=method_block,
                input_block={
                    "view": "unit",
                    "source_sha256": None,
                    "prompt_sha256": _hash((record.get("prompt") or {}).get("prompt_sha256")),
                    "context_mode": "none" if method == "direct" else "tool_evidence",
                    "sanitized": True,
                    "sanitizer_version": sanitizer_version,
                    "evidence_sha256": None,
                },
                label={
                    "y_true": record.get("label") is True,
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                prediction={
                    "y_pred": y_pred if status == "ok" else None,
                    "cwe_pred": [],
                    "confidence": record.get("confidence") if status == "ok" else None,
                    "evidence_lines": [],
                    "rationale": record.get("reason") if isinstance(record.get("reason"), str) else None,
                    "raw_output_sha256": (
                        sha256_text(record["content"]) if isinstance(record.get("content"), str) else None
                    ),
                    "fixed_function": None,
                },
                status=status,
                error=error,
                coverage=None,
                usage=_usage(
                    usage_raw.get("prompt_tokens"),
                    usage_raw.get("completion_tokens"),
                    prompt_details.get("cached_tokens"),
                    details.get("reasoning_tokens"),
                    float(latency_s) * 1000.0 if isinstance(latency_s, (int, float)) else None,
                    attempts,
                ),
                cost=_cost(
                    (record.get("cost") or {}).get("cost_usd") if isinstance(record.get("cost"), dict) else None,
                    latency_s,
                    note="API list-price computation; provider allowance may differ",
                    pricing_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
                ),
                provenance={
                    "produced_by": IMPORT_VERSION,
                    "created_at": str(raw_manifest.get("started_at_utc") or utc_now()),
                    "source_artifact": _rel(results_path),
                    "source_sha256": source_sha,
                    "record_index": index,
                    "command_sha256": None,
                    "legacy_run_id": str(raw_manifest.get("run_id") or source_dir.name),
                    "note": "hybrid run record copied; prediction not changed",
                },
                oracle=_oracle_for(raw_unit),
                extensions={
                    "experiment": f"hybrid_{version}",
                    "split": "test",
                    "runtime_supported": runtime_supported,
                    "dynamic_outcome": dynamic_outcome,
                    "method": method,
                    "family": str(raw_unit.get("family") or ""),
                    "language": raw_unit.get("language"),
                    "placebo_donor_unit": record.get("placebo_donor_unit"),
                    "evidence_method": method,
                    "raw_status": raw_status,
                    "input_pack": input_pack_path,
                    "input_pack_sha256": input_pack_sha,
                    "sanitizer_version": sanitizer_version,
                },
            )
        )
    execution = {
        "started_at": _iso(raw_manifest.get("started_at_utc")),
        "finished_at": _iso(raw_manifest.get("finished_at_utc")),
        "status": "completed",
        "planned_units": 140,
        "recorded_units": len(predictions),
        "retries": retries,
        "concurrency": raw_manifest.get("concurrency") or config.get("concurrency"),
        "command": None,
        "command_sha256": None,
        "environment": {"source_run": _rel(source_dir), "endpoint": api.get("base_url")},
    }
    manifest = _manifest(
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        tasks=["leak_detection"],
        dataset=dataset,
        method=method_block,
        execution=execution,
        notes=[
            f"Derived view over the real hybrid {version} run; no model call and no prediction change.",
            "Test split only (140 units, 70 bad / 70 good). dev 60 was not run for this experiment.",
            "Direct is the no-evidence control; static/dynamic/combined add real tool evidence; shuffled is the placebo.",
            "OpenCode Go endpoint for both models; this is not the Xiaomi fallback run.",
            f"Canonical Tier B hybrid version is v2 (leak-fixed inputs, prompt hybrid-v2-juliet-llm-binary-2026-11-12.2). v1 is superseded/leakage-sensitive and excluded from the main leaderboard.",
        ],
        source_paths=[results_path, config_path, manifest_path],
        hashes={
            "source_results_sha256": source_sha,
            "source_config_sha256": sha256_file(config_path),
            "source_manifest_sha256": sha256_file(manifest_path),
            "dataset_sha256": JULIET_UNITS_SHA,
            "input_pack_sha256": input_pack_sha,
        },
    )
    return _write_run(
        out_dir,
        run_id,
        manifest,
        predictions,
        source_paths=[results_path, config_path, manifest_path],
        provenance_markdown=[
            f"- source run: `{_rel(source_dir)}`",
            f"- source results SHA-256: `{source_sha}`",
            f"- model: `{model_id}` ({meta['family']})",
            f"- method: `{method}` ({family})",
            f"- version: `{version}` (canonical = v2; v1 is superseded/leakage-sensitive)",
            f"- prompt: `{config.get('prompt_version')}`",
            f"- input pack: `{input_pack_path}` SHA-256 `{input_pack_sha}`",
            f"- endpoint: `{api.get('base_url')}` (OpenCode Go)",
        ],
        force=force,
    )


# ---------------------------------------------------------------------------
# Tier B Juliet LLM fallback
# ---------------------------------------------------------------------------


def import_juliet_llm(*, force: bool = False) -> dict[str, Any]:
    source_dir = (
        PROJECT_ROOT
        / "juliet_llm"
        / "runs"
        / "20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix"
    )
    manifest_path = source_dir / "manifest.json"
    results_path = source_dir / "results.jsonl"
    raw_manifest = read_json(manifest_path)
    records = read_jsonl(results_path)
    api = raw_manifest.get("api") or {}
    model_id = str(raw_manifest.get("model") or api.get("model") or "")
    meta = MODEL_META.get(model_id)
    if meta is None:
        raise ValueError(f"{source_dir}: unknown model id {model_id!r}")
    units = _juliet_units()
    runtime_units = _juliet_manifest_units()
    source_sha = sha256_file(results_path)
    run_id = f"tierb_juliet_cwe401_llm_mimo_xiaomi_postleakfix_20261112_{source_sha[:8]}"
    out_dir = (
        PROJECT_ROOT
        / "benchmark"
        / "results"
        / "tier_b"
        / "juliet_cwe401"
        / "llm_mimo_xiaomi"
        / run_id
    )
    decoding = {
        "temperature": api.get("temperature"),
        "max_tokens": api.get("max_tokens"),
        "max_tokens_field": api.get("max_tokens_field"),
        "thinking": api.get("thinking"),
        "reasoning_effort": api.get("reasoning_effort"),
        "response_format": api.get("response_format"),
        "timeout_seconds": api.get("timeout_seconds"),
    }
    pricing = raw_manifest.get("prices_usd_per_1m") if isinstance(raw_manifest.get("prices_usd_per_1m"), dict) else {}
    method = {
        "method_id": "llm.mimo.xiaomi_juliet_direct",
        "family": "llm",
        "name": "MiMo-V2.6-Flash / Juliet direct (Xiaomi official, postleakfix)",
        "strategy": "direct",
        "prompt_version": raw_manifest.get("prompt_version"),
        "config_sha256": None,
        "model": _model_block(
            model_id,
            provider="xiaomi-official",
            endpoint=api.get("endpoint") or XIAOMI_ENDPOINT,
            decoding=decoding,
            pricing=pricing,
            price_snapshot="Reference list price from OpenCode Go models snapshot 2026-11-11T20:55:33Z; Xiaomi API returned no billing fields",
        ),
        "tool": None,
    }
    dataset = _dataset(
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id="juliet-cwe401-v1.3-subset-v1",
        path="juliet/subset_units.jsonl",
        sha256=JULIET_UNITS_SHA,
        unit_count=200,
        group_count=100,
        label_counts={"bad": 100, "good": 100},
        unit_manifest={"path": "juliet/manifest.json", "sha256": JULIET_MANIFEST_SHA},
    )
    predictions: list[dict[str, Any]] = []
    retries = 0
    for index, record in enumerate(records):
        raw_unit = units.get(str(record.get("unit_id")))
        if raw_unit is None:
            raise ValueError(f"{results_path}: unknown unit_id {record.get('unit_id')!r}")
        raw_status = str(record.get("status") or "not_run")
        y_pred = record.get("y_pred") if isinstance(record.get("y_pred"), int) else None
        status = "ok" if raw_status == "ok" and record.get("valid") is True and y_pred in (0, 1) else "schema_invalid"
        error = None if status == "ok" else _error("schema_invalid", f"raw status={raw_status}; valid={record.get('valid')}")
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        raw_usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
        raw_cost = response.get("cost") if isinstance(response.get("cost"), dict) else {}
        prompt_details = raw_usage.get("prompt_tokens_details") if isinstance(raw_usage.get("prompt_tokens_details"), dict) else {}
        details = raw_usage.get("completion_tokens_details") if isinstance(raw_usage.get("completion_tokens_details"), dict) else {}
        attempts = response.get("attempts") if isinstance(response.get("attempts"), list) else []
        if len(attempts) > 1:
            retries += len(attempts) - 1
        latency_s = response.get("request_latency_seconds")
        if not isinstance(latency_s, (int, float)):
            latency_s = response.get("wall_seconds")
        predictions.append(
            _record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=f"juliet:{raw_unit['group_id']}:{raw_unit['label']}",
                cluster_id=str(raw_unit.get("family") or "unknown"),
                group_id=str(raw_unit["group_id"]),
                side=str(raw_unit["label"]),
                dataset=dataset,
                method=method,
                input_block={
                    "view": "unit",
                    "source_sha256": _hash(record.get("code_sha256")),
                    "prompt_sha256": _hash(record.get("prompt_sha256")),
                    "context_mode": "none",
                    "sanitized": True,
                    "sanitizer_version": "juliet-llm-cleaning-2026-11-12.2",
                    "evidence_sha256": None,
                },
                label={
                    "y_true": record.get("y_true") == 1,
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                prediction={
                    "y_pred": y_pred if status == "ok" else None,
                    "cwe_pred": [],
                    "confidence": (record.get("parsed") or {}).get("confidence") if status == "ok" else None,
                    "evidence_lines": [],
                    "rationale": (record.get("parsed") or {}).get("reason") if status == "ok" else None,
                    "raw_output_sha256": (
                        sha256_text(record["response"]["content"])
                        if isinstance(record.get("response"), dict) and isinstance(record["response"].get("content"), str)
                        else None
                    ),
                    "fixed_function": None,
                },
                status=status,
                error=error,
                coverage=None,
                usage=_usage(
                    raw_cost.get("prompt_tokens", raw_usage.get("prompt_tokens")),
                    raw_cost.get("completion_tokens", raw_usage.get("completion_tokens")),
                    raw_cost.get("cached_prompt_tokens", prompt_details.get("cached_tokens")),
                    details.get("reasoning_tokens"),
                    float(latency_s) * 1000.0 if isinstance(latency_s, (int, float)) else None,
                    len(attempts),
                ),
                cost=_cost(
                    raw_cost.get("cost_usd"),
                    latency_s,
                    note="Reference-price computation from the declared card; Xiaomi endpoint returned no billing fields",
                    pricing_snapshot="OpenCode Go models snapshot 2026-11-11T20:55:33Z; Xiaomi endpoint n/a",
                ),
                provenance={
                    "produced_by": IMPORT_VERSION,
                    "created_at": str(record.get("created_at") or utc_now()),
                    "source_artifact": _rel(results_path),
                    "source_sha256": source_sha,
                    "record_index": index,
                    "command_sha256": None,
                    "legacy_run_id": str(raw_manifest.get("run_id") or source_dir.name),
                    "note": "Juliet LLM record copied; prediction not changed; Xiaomi official endpoint",
                },
                oracle=_oracle_for(runtime_units.get(str(record.get("unit_id")), {})),
                extensions={
                    "endpoint_note": "Xiaomi official API (used as OpenCode Go fallback); NOT OpenCode Go",
                    "endpoint_is_fallback": True,
                    "split": "test",
                    "runtime_supported": bool(record.get("y_true") == 0 or ((runtime_units.get(str(record.get("unit_id")), {}).get("runtime_check") or {}).get("leak_detected") is True)),
                    "family": str(raw_unit.get("family") or ""),
                    "language": raw_unit.get("language"),
                    "group_id": raw_unit.get("group_id"),
                    "raw_label": raw_unit.get("label"),
                    "valid": record.get("valid"),
                },
            )
        )
    execution = {
        "started_at": _iso(raw_manifest.get("started_at_utc")),
        "finished_at": _iso(raw_manifest.get("completed_at_utc")),
        "status": "completed",
        "planned_units": 140,
        "recorded_units": len(predictions),
        "retries": retries,
        "concurrency": raw_manifest.get("concurrency"),
        "command": None,
        "command_sha256": None,
        "environment": {"source_run": _rel(source_dir), "endpoint": api.get("endpoint") or XIAOMI_ENDPOINT},
    }
    manifest = _manifest(
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        tasks=["leak_detection"],
        dataset=dataset,
        method=method,
        execution=execution,
        notes=[
            "MIMO ENDPOINT: Xiaomi official endpoint, not OpenCode Go (used as the fallback when OpenCode was unavailable). Same model id, different serving stack.",
            "Canonical MiMo Xiaomi 140 run is the postleakfix run (prompt juliet-llm-binary-2026-11-12.2); the earlier 204701Z harness run is superseded and excluded.",
            "DeepSeek has no Juliet LLM test result because OpenCode returned 401 api_key_expired and official DeepSeek returned 402.",
            "Test split only (140 units); dev 60 was not run.",
            "Cost is a reference-price computation (declared card); the Xiaomi endpoint returned no list cost or allowance fields.",
        ],
        source_paths=[results_path, manifest_path],
        hashes={
            "source_results_sha256": source_sha,
            "source_manifest_sha256": sha256_file(manifest_path),
            "dataset_sha256": JULIET_UNITS_SHA,
        },
    )
    return _write_run(
        out_dir,
        run_id,
        manifest,
        predictions,
        source_paths=[results_path, manifest_path],
        provenance_markdown=[
            f"- source run: `{_rel(source_dir)}`",
            f"- source results SHA-256: `{source_sha}`",
            f"- model: `{model_id}` (mimo)",
            f"- endpoint: `{api.get('endpoint') or XIAOMI_ENDPOINT}` (Xiaomi official; fallback from OpenCode Go)",
            "- this is NOT an OpenCode Go result; do not merge it with the hybrid OpenCode runs",
        ],
        force=force,
    )


# ---------------------------------------------------------------------------
# Tier B repair
# ---------------------------------------------------------------------------


def import_repair(model_key: str, *, force: bool = False) -> dict[str, Any]:
    source_dir = PROJECT_ROOT / "juliet_repair" / "runs" / f"{model_key}_test70_final"
    manifest_path = source_dir / "manifest.json"
    summary_path = source_dir / "summary.json"
    results_path = source_dir / "results.jsonl"
    raw_manifest = read_json(manifest_path)
    raw_summary = read_json(summary_path)
    records = read_jsonl(results_path)
    full_results = [
        item for item in (raw_summary.get("results") or []) if isinstance(item, dict)
    ]
    full_by_key = {
        str(item.get("unit_key") or item.get("unit_id")): item for item in full_results
    }
    api = raw_manifest.get("api") or {}
    model_id = str(raw_manifest.get("model") or "")
    meta = MODEL_META.get(model_id)
    if meta is None:
        raise ValueError(f"{source_dir}: unknown model id {model_id!r}")
    units = _juliet_units()
    source_sha = sha256_file(results_path)
    run_id = f"tierb_juliet_cwe401_repair_{meta['family']}_20261112_{source_sha[:8]}"
    out_dir = (
        PROJECT_ROOT
        / "benchmark"
        / "results"
        / "tier_b"
        / "juliet_cwe401_repair"
        / meta["family"]
        / run_id
    )
    decoding = {
        "temperature": api.get("temperature"),
        "max_tokens": api.get("max_tokens"),
        "max_tokens_field": api.get("max_tokens_field"),
        "thinking": api.get("thinking"),
        "reasoning_effort": api.get("reasoning_effort"),
        "response_format": api.get("response_format"),
        "timeout_seconds": api.get("timeout_seconds"),
    }
    pricing = {
        "input": api.get("input_price_usd_per_1m"),
        "output": api.get("output_price_usd_per_1m"),
        "cached_input": api.get("cached_input_price_usd_per_1m"),
    }
    method = {
        "method_id": f"llm.{meta['family']}.repair",
        "family": "llm",
        "name": f"{meta['display']} / repair (compile + LSan + behaviour)",
        "strategy": "repair",
        "prompt_version": raw_manifest.get("prompt_version"),
        "config_sha256": None,
        "model": _model_block(
            model_id,
            decoding=decoding,
            pricing=pricing,
            price_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
        ),
        "tool": None,
    }
    dataset = _dataset(
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id="juliet-cwe401-v1.3-subset-v1",
        path="juliet/subset_units.jsonl",
        sha256=JULIET_UNITS_SHA,
        unit_count=200,
        group_count=100,
        label_counts={"bad": 100, "good": 100},
        unit_manifest={"path": "juliet/manifest.json", "sha256": JULIET_MANIFEST_SHA},
    )
    predictions: list[dict[str, Any]] = []
    retries = 0
    for index, record in enumerate(records):
        raw_unit = units.get(str(record.get("unit_id")))
        if raw_unit is None:
            raise ValueError(f"{results_path}: unknown unit_id {record.get('unit_id')!r}")
        full = full_by_key.get(str(record.get("unit_key") or record.get("unit_id"))) or {}
        strict_evaluable = record.get("strict_evaluable") is True
        strict_pass = record.get("strict_pass") is True
        attempts = full.get("attempts") if isinstance(full.get("attempts"), list) else []
        if len(attempts) > 1:
            retries += len(attempts) - 1
        status = "ok" if strict_evaluable else "not_applicable"
        error = (
            None
            if strict_evaluable
            else _error(
                "not_applicable",
                "baseline leak was not observable under LSan; strict repair pass is undefined and excluded from the denominator",
            )
        )
        elapsed = sum(
            float(attempt["elapsed_seconds"])
            for attempt in attempts
            if isinstance(attempt, dict) and isinstance(attempt.get("elapsed_seconds"), (int, float))
        )
        cost_usd = record.get("cost_usd_sum") if isinstance(record.get("cost_usd_sum"), (int, float)) else None
        predictions.append(
            _record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="repair",
                unit_id=f"juliet:{raw_unit['group_id']}:bad",
                cluster_id=str(raw_unit.get("family") or "unknown"),
                group_id=str(raw_unit["group_id"]),
                side="bad",
                dataset=dataset,
                method=method,
                input_block={
                    "view": "unit",
                    "source_sha256": None,
                    "prompt_sha256": None,
                    "context_mode": "none",
                    "sanitized": True,
                    "sanitizer_version": "juliet-repair-input-cleaning-2026-11-12.1",
                    "evidence_sha256": None,
                },
                label={
                    "y_true": True,
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": "bad-only repair input; y_pred denotes strict repair pass, not a leak prediction",
                },
                prediction={
                    "y_pred": strict_pass if status == "ok" else None,
                    "cwe_pred": [],
                    "confidence": None,
                    "evidence_lines": [],
                    "rationale": None,
                    "raw_output_sha256": None,
                    "fixed_function": None,
                },
                status=status,
                error=error,
                coverage=None,
                usage=_usage(
                    record.get("prompt_tokens_sum"),
                    record.get("completion_tokens_sum"),
                    record.get("cached_prompt_tokens_sum"),
                    None,
                    elapsed * 1000.0 if elapsed else None,
                    len(attempts),
                ),
                cost=_cost(
                    cost_usd,
                    elapsed if attempts else None,
                    note="API list-price computation from per-attempt usage",
                    pricing_snapshot="OpenCode Go list prices; 2026-11-12 snapshot",
                ),
                provenance={
                    "produced_by": IMPORT_VERSION,
                    "created_at": str(raw_manifest.get("started_at_utc") or utc_now()),
                    "source_artifact": _rel(results_path),
                    "source_sha256": source_sha,
                    "record_index": index,
                    "command_sha256": None,
                    "legacy_run_id": str(raw_manifest.get("run_id") or source_dir.name),
                    "note": "repair evaluation copied; not re-run",
                },
                extensions={
                    "split": "test",
                    "unit_key": record.get("unit_key"),
                    "language": raw_unit.get("language"),
                    "strict_evaluable": strict_evaluable,
                    "strict_pass": strict_pass,
                    "compile_pass": record.get("compile_pass") is True,
                    "leak_removed": record.get("leak_removed") is True,
                    "behavior_preserved": record.get("behavior_preserved") is True,
                    "behavior_observable": record.get("behavior_observable") is True,
                    "baseline_leak_observed": strict_evaluable,
                    "first_attempt_strict_pass": bool(strict_pass and len(attempts) == 1),
                    "attempts": len(attempts),
                    "final_attempt": full.get("final_attempt", record.get("final_attempt")),
                    "final_parse_error": full.get("final_parse_error"),
                    "schema_strict": full.get("schema_strict"),
                    "explanation_present": full.get("explanation_present"),
                },
            )
        )
    execution = {
        "started_at": _iso(raw_manifest.get("started_at_utc")),
        "finished_at": _iso(raw_manifest.get("completed_at_utc")),
        "status": "completed",
        "planned_units": 70,
        "recorded_units": len(predictions),
        "retries": retries,
        "concurrency": raw_manifest.get("concurrency"),
        "command": None,
        "command_sha256": None,
        "environment": {"source_run": _rel(source_dir), "endpoint": api.get("base_url")},
    }
    manifest = _manifest(
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        tasks=["repair"],
        dataset=dataset,
        method=method,
        execution=execution,
        notes=[
            "Repair task: strict_pass = compile_pass AND leak_removed AND behavior_preserved AND baseline leak observed.",
            "12 bad units whose baseline leak is not observable under LSan are status=not_applicable and are excluded from the 58-unit denominator.",
            "They still compile, pass LSan and preserve behaviour; that does not prove the leak was removed.",
            "y_pred is the strict repair-pass flag, not a vulnerability prediction.",
        ],
        source_paths=[results_path, manifest_path, summary_path],
        hashes={
            "source_results_sha256": source_sha,
            "source_manifest_sha256": sha256_file(manifest_path),
            "source_summary_sha256": sha256_file(summary_path),
            "dataset_sha256": JULIET_UNITS_SHA,
        },
    )
    return _write_run(
        out_dir,
        run_id,
        manifest,
        predictions,
        source_paths=[results_path, manifest_path, summary_path],
        provenance_markdown=[
            f"- source run: `{_rel(source_dir)}`",
            f"- source results SHA-256: `{source_sha}`",
            f"- model: `{model_id}` ({meta['family']})",
            f"- strict evaluable / planned: {raw_summary.get('strict_evaluable')} / {raw_summary.get('units')}",
            f"- strict pass: {raw_summary.get('strict_pass')}",
        ],
        force=force,
    )


def _measure(run_dir: Path) -> dict[str, Any]:
    report = validate_run(run_dir, use_jsonschema=True)
    atomic_write_json(run_dir / "validation.json", report)
    if report.get("errors"):
        raise RuntimeError(
            f"{run_dir}: validation failed with {len(report['errors'])} errors: "
            + "; ".join(report["errors"][:5])
        )
    metrics = compute_run_metrics(run_dir)
    atomic_write_json(run_dir / "metrics.json", metrics)
    return {"run_dir": _rel(run_dir), "validation_errors": 0, "warnings": len(report.get("warnings", []))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing derived run directories",
    )
    parser.add_argument(
        "--measure",
        action="store_true",
        help="validate each derived run and compute metrics.json",
    )
    args = parser.parse_args(argv)

    created: list[dict[str, Any]] = []
    try:
        for model in ("deepseek", "mimo"):
            created.append(import_evidence(model, force=args.force))
        for model in ("deepseek", "mimo"):
            created.append(import_pair_joint(model, force=args.force))
        for model in ("deepseek", "mimo"):
            for method in ("direct", "static", "dynamic", "combined", "shuffled"):
                created.append(import_hybrid(model, method, version="v2", force=args.force))
        created.append(import_juliet_llm(force=args.force))
        for model in ("deepseek", "mimo"):
            created.append(import_repair(model, force=args.force))
        if args.measure:
            for item in created:
                item["measurement"] = _measure(PROJECT_ROOT / item["run_dir"])
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"import failed: {exc}\n")
        return 2
    sys.stderr.write(json.dumps(created, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

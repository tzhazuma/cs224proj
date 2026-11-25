#!/usr/bin/env python3
"""Import producer raw records into canonical extension runs.

Five subcommands (selected with ``--design``):

* ``position_debiased_pair``: write ``order_ab/`` and/or ``order_ba/`` runs
  under one base directory; each order is a parent-valid pair_detection run.
* ``open_choice_pair``: one pair_detection run; one 4-way response becomes two
  canonical side records.
* ``evidence_verification``: one detection run over frozen claims; a claim is
  one unit, not a token or a line.
* ``fault_injected_dynamic``: one leak_detection run over pre-registered fault
  variants; expected outcomes come from the frozen fault manifest.
* ``new_static_tool``: one leak_detection run; raw diagnostics are normalized
  through the versioned rule registry and recounted before publishing.

Safety properties:

* output is staged in a temporary directory, validated, then moved into place;
* an existing output directory is archived under ``.superseded/`` instead of
  being deleted, and only with ``--force``;
* raw request headers/credentials are never copied; canonical artifacts are
  screened for secret-like keys before writing;
* no network call, no model call, no analyzer invocation.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ext_common import (  # noqa: E402
    DESIGN_REGISTRY_VERSION,
    DESIGNS_PATH,
    EXTENSION_MANIFEST_SCHEMA,
    EXTENSION_VERSION,
    FAULT_TYPES_PATH,
    STATIC_TOOLS_PATH,
    ExtensionError,
    as_bool,
    as_int,
    as_number,
    canonical_claim_unit_id,
    canonical_fault_unit_id,
    canonical_pair_unit_id,
    check_no_secret_fields,
    coverage_sufficient,
    design_spec,
    extract_rule,
    fault_type_spec,
    first_str,
    juliet_unit_index,
    load_claim_manifest,
    load_fault_manifest,
    load_records,
    normalize_cwe_list,
    normalize_diagnostic,
    normalize_status,
    pair_split_index,
    parse_juliet_unit_id,
    pick,
    project_root,
    record_sha256,
    resolve_path,
    sha256_file,
    sha256_text,
    stable_json,
    static_tool_registry,
    static_tool_spec,
    summarize_diagnostics,
    utc_now,
    write_jsonl,
)
from ext_validate import validate_extension_run  # noqa: E402

OPEN_CHOICES = ("A", "B", "both", "neither")
VERDICTS = ("supported", "unsupported", "insufficient")
FAULT_OBSERVED = ("leak", "clean", "inconclusive", "error", "timeout", "crash")
COVERAGE_SOURCES = ("gcov", "llvm-cov", "sanitizer", "instrumentation", "none", "unknown")


# ---------------------------------------------------------------------------
# Config / metadata helpers
# ---------------------------------------------------------------------------


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path).resolve()
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExtensionError(f"cannot read config {config_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExtensionError(f"{config_path}: config must be a JSON object")
    value["_config_path"] = str(config_path)
    return value


def _config_bases(config: Mapping[str, Any]) -> list[Path]:
    bases = [project_root(), Path.cwd()]
    config_path = config.get("_config_path")
    if config_path:
        bases.insert(0, Path(config_path).parent)
    return bases


def _config_path(
    config: Mapping[str, Any],
    key: str,
    *,
    default: str | None = None,
    required: bool = False,
) -> Path | None:
    value = config.get(key, default)
    if value is None:
        if required:
            raise ExtensionError(f"config missing required path {key!r}")
        return None
    return resolve_path(str(value), _config_bases(config))


def _display_path(path: str | Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(project_root()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _require(config: Mapping[str, Any], key: str) -> Any:
    value = config.get(key)
    if value is None or value == "":
        raise ExtensionError(f"config missing required field {key!r}")
    return value


def _tier_track(config: Mapping[str, Any], design: str) -> tuple[str, str]:
    spec = design_spec(design)
    tier = str(config.get("tier") or spec["tiers"][0])
    track = str(config.get("track") or spec["tracks"][0])
    if tier not in spec["tiers"]:
        raise ExtensionError(f"tier {tier!r} not allowed for {design}")
    if track not in spec["tracks"]:
        raise ExtensionError(f"track {track!r} not allowed for {design}")
    return tier, track


def _method_from_config(config: Mapping[str, Any]) -> dict[str, Any]:
    method = config.get("method")
    if not isinstance(method, Mapping):
        raise ExtensionError("config.method must be an object")
    result = json.loads(json.dumps(method))
    if not result.get("method_id"):
        raise ExtensionError("config.method.method_id is required")
    if result.get("family") not in ("llm", "static", "dynamic", "hybrid"):
        raise ExtensionError("config.method.family must be llm|static|dynamic|hybrid")
    result.setdefault("name", result["method_id"])
    result.setdefault("strategy", None)
    if result["family"] == "llm":
        model = result.get("model")
        if not isinstance(model, Mapping):
            raise ExtensionError("config.method.model is required for family=llm")
        for key in ("model_id", "family", "provider"):
            if not model.get(key):
                raise ExtensionError(f"config.method.model.{key} is required")
    if result["family"] in ("static", "dynamic"):
        tool = result.get("tool")
        if not isinstance(tool, Mapping):
            raise ExtensionError(f"config.method.tool is required for family={result['family']}")
        for key in ("name", "version"):
            if not tool.get(key):
                raise ExtensionError(f"config.method.tool.{key} is required")
    if not result.get("config_sha256"):
        result["config_sha256"] = sha256_text(stable_json(result))
    check_no_secret_fields(result)
    return result


def _dataset_meta(
    config: Mapping[str, Any],
    *,
    path: Path,
    dataset_id: str,
    split_id: str,
    unit_count: int,
    group_count: int | None,
    label_counts: Mapping[str, int],
) -> dict[str, Any]:
    configured = config.get("dataset") if isinstance(config.get("dataset"), Mapping) else {}
    sha = configured.get("sha256") or sha256_file(path)
    if configured.get("sha256") and configured["sha256"] != sha256_file(path):
        raise ExtensionError("config.dataset.sha256 does not match the dataset file")
    return {
        "dataset_id": str(configured.get("dataset_id") or dataset_id),
        "split_id": str(configured.get("split_id") or split_id),
        "path": _display_path(path),
        "sha256": sha,
        "unit_manifest": configured.get("unit_manifest"),
        "unit_count": int(unit_count),
        "group_count": group_count,
        "label_counts": {str(key): int(value) for key, value in label_counts.items()},
    }


def _new_run_id(config: Mapping[str, Any], suffix: str | None = None) -> str:
    base = str(_require(config, "run_id"))
    return f"{base}_{suffix}" if suffix else base


def _created_at(config: Mapping[str, Any]) -> str:
    value = config.get("created_at")
    return str(value) if value else utc_now()


# ---------------------------------------------------------------------------
# Record normalization helpers
# ---------------------------------------------------------------------------


def _normalize_usage(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    usage = pick(raw, "usage", "response.usage", "result.usage", default={})
    if not isinstance(usage, Mapping):
        usage = {}
    attempts = pick(raw, "response.attempts", "attempts")
    latency = as_number(pick(usage, "latency_ms"))
    if latency is None:
        attempts = pick(raw, "response.attempts", "attempts")
        latency_s = None
        if isinstance(attempts, list) and attempts:
            last = attempts[-1]
            if isinstance(last, Mapping):
                latency_s = as_number(last.get("latency_seconds"))
        if latency_s is None:
            latency_s = as_number(pick(raw, "latency_seconds"))
        if latency_s is not None:
            latency = latency_s * 1000.0
    result = {
        "prompt_tokens": as_int(pick(usage, "prompt_tokens", "input_tokens")),
        "completion_tokens": as_int(pick(usage, "completion_tokens", "output_tokens")),
        "cached_prompt_tokens": as_int(
            pick(usage, "cached_prompt_tokens", "prompt_tokens_details.cached_tokens", "cache_read_tokens")
        ),
        "reasoning_tokens": as_int(
            pick(usage, "reasoning_tokens", "completion_tokens_details.reasoning_tokens")
        ),
        "latency_ms": latency,
        "api_attempts": len(attempts) if isinstance(attempts, list) else as_int(pick(usage, "api_attempts")),
    }
    return result if any(value is not None for value in result.values()) else None


def _normalize_cost(raw: Mapping[str, Any], family: str, config: Mapping[str, Any]) -> dict[str, Any] | None:
    usd = as_number(
        pick(raw, "cost.cost_usd", "response.cost.cost_usd", "cost_usd", "response.cost.usd")
    )
    wall = as_number(
        pick(
            raw,
            "cost.wall_s",
            "response.wall_seconds",
            "wall_seconds",
            "wall_s",
            "duration_seconds",
            "runtime.duration_seconds",
            "runtime.wall_s",
        )
    )
    cpu = as_number(pick(raw, "cost.cpu_s", "cpu_seconds", "cpu_s"))
    rss = as_number(pick(raw, "cost.peak_rss_mb", "peak_rss_mb"))
    if usd is None and wall is None and cpu is None and rss is None:
        return None
    if usd is not None:
        basis = "api_price"
    elif family in ("static", "dynamic"):
        basis = "local_compute"
    else:
        basis = "unknown"
    return {
        "usd": usd,
        "wall_s": wall,
        "cpu_s": cpu,
        "peak_rss_mb": rss,
        "currency": "USD",
        "cost_basis": basis,
        "pricing_snapshot": config.get("pricing_snapshot"),
        "note": None,
    }


def _normalize_error(raw: Mapping[str, Any], status: str) -> dict[str, Any] | None:
    error = pick(raw, "error", "response.error")
    if isinstance(error, Mapping):
        return {
            "type": str(error.get("type") or error.get("code") or status),
            "message": str(error.get("message") or ""),
            "retryable": bool(error.get("retryable", False)),
            "attempt": as_int(error.get("attempt")),
            "http_status": as_int(error.get("http_status")),
        }
    if isinstance(error, str) and error.strip():
        return {
            "type": status,
            "message": error.strip(),
            "retryable": False,
            "attempt": None,
            "http_status": None,
        }
    if status != "ok":
        return {
            "type": status,
            "message": f"status={status}",
            "retryable": status in ("timeout", "api_error"),
            "attempt": None,
            "http_status": None,
        }
    return None


def _normalize_coverage(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    coverage = pick(raw, "coverage")
    if not isinstance(coverage, Mapping):
        return None
    source = str(coverage.get("coverage_source") or "unknown")
    if source not in COVERAGE_SOURCES:
        source = "unknown"

    def number(value: Any, label: str) -> float | None:
        parsed = as_number(value)
        if parsed is None:
            return None
        if parsed < 0.0 or parsed > 1.0:
            raise ExtensionError(f"coverage.{label} must be in [0,1], got {parsed}")
        return parsed

    return {
        "unit_executed": as_bool(coverage.get("unit_executed")),
        "target_function_entered": as_bool(coverage.get("target_function_entered")),
        "line_coverage": number(coverage.get("line_coverage"), "line_coverage"),
        "branch_coverage": number(coverage.get("branch_coverage"), "branch_coverage"),
        "allocation_site_executed": as_bool(coverage.get("allocation_site_executed")),
        "free_site_executed": as_bool(coverage.get("free_site_executed")),
        "coverage_source": source,
        "notes": coverage.get("notes") if isinstance(coverage.get("notes"), str) else None,
    }


def _unknown_coverage() -> dict[str, Any]:
    return {
        "unit_executed": None,
        "target_function_entered": None,
        "line_coverage": None,
        "branch_coverage": None,
        "allocation_site_executed": None,
        "free_site_executed": None,
        "coverage_source": "unknown",
        "notes": "coverage not reported by the producer",
    }


def _normalize_oracle(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    oracle = pick(raw, "oracle")
    if not isinstance(oracle, Mapping):
        return None
    result: dict[str, Any] = {}
    reference = pick(oracle, "reference")
    if reference in ("julie_intended", "juliet_intended", "dynamic_consensus", "manual"):
        result["reference"] = "juliet_intended" if reference == "julie_intended" else reference
    consensus = pick(oracle, "dynamic_consensus", "consensus")
    if consensus in ("leak", "clean", "disagree", "not_run", "unknown", None):
        result["dynamic_consensus"] = consensus
    for key in ("lsan", "valgrind"):
        value = pick(oracle, key)
        if value in ("leak", "clean", "error", "not_run", "unknown", None):
            result[key] = value
    mismatch = as_bool(oracle.get("mismatch"))
    if mismatch is not None:
        result["mismatch"] = mismatch
    note = pick(oracle, "note")
    if isinstance(note, str):
        result["note"] = note
    return result or None


def _safe_raw_digest(raw: Mapping[str, Any]) -> str:
    safe = {
        "pair_id": pick(raw, "pair_id"),
        "claim_id": pick(raw, "claim_id"),
        "fault_id": pick(raw, "fault_id"),
        "sample_id": pick(raw, "sample_id", "unit_id"),
        "choice": pick(raw, "choice", "open_choice", "parsed.vulnerable_version", "parsed.open_choice"),
        "verdict": pick(raw, "verdict", "parsed.verdict"),
        "observed_outcome": pick(raw, "observed_outcome", "outcome"),
        "status": pick(raw, "status", "response.status"),
        "prompt_sha256": pick(raw, "prompt_sha256", "request.body_sha256"),
        "usage": pick(raw, "usage", "response.usage"),
        "cost": pick(raw, "cost", "response.cost"),
        "validation": pick(raw, "validation"),
        "parsed": pick(raw, "parsed"),
    }
    return record_sha256(safe)


def _status_for_raw(raw: Mapping[str, Any], *, parsed_valid: bool = True) -> str:
    explicit = pick(raw, "status", "result.status", "response.status")
    status = normalize_status(explicit)
    if status is None:
        status = "ok"
    validation = pick(raw, "validation")
    if isinstance(validation, Mapping):
        if validation.get("json_parse_ok") is False:
            return "schema_invalid"
        if validation.get("schema_exact") is False:
            return "schema_invalid"
        if validation.get("decision_valid") is False:
            return "schema_invalid"
    if not parsed_valid and status == "ok":
        return "schema_invalid"
    return status


def _normalize_position_choice(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if text in ("A", "VERSION A", "VULNERABLE_VERSION=A", "1"):
        return "A"
    if text in ("B", "VERSION B", "VULNERABLE_VERSION=B", "2"):
        return "B"
    if text in ("BOTH", "NEITHER", ""):
        return None
    return None


def _normalize_open_choice(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("a", "version a", "vulnerable_version=a", "1"):
        return "A"
    if text in ("b", "version b", "vulnerable_version=b", "2"):
        return "B"
    if text in ("both", "both_vulnerable", "both vulnerable", "ab", "a_and_b"):
        return "both"
    if text in ("neither", "none", "no", "not_vulnerable", "both_clean", "0"):
        return "neither"
    return None


def _normalize_verdict(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("supported", "support", "valid", "supported_claim", "true", "yes", "1"):
        return "supported"
    if text in ("unsupported", "not_supported", "reject", "rejected", "invalid", "false", "no", "0"):
        return "unsupported"
    if text in ("insufficient", "unknown", "uncertain", "abstain", "abstained", "cannot_determine", "n/a"):
        return "insufficient"
    return None


def _position_map_from_raw(
    raw: Mapping[str, Any] | None,
    *,
    order: str,
    pair_id: str,
    position_map_data: Mapping[str, Any] | None,
) -> dict[str, str]:
    if raw is not None:
        value = pick(raw, "position_map")
        if isinstance(value, Mapping):
            if set(value) != {"A", "B"} or set(value.values()) != {"vulnerable", "fixed"}:
                raise ExtensionError(f"pair {pair_id}: position_map must map A/B to vulnerable/fixed")
            return {"A": str(value["A"]), "B": str(value["B"])}
        vulnerable_slot = first_str(raw, "vulnerable_slot", "position.vulnerable_slot")
        if vulnerable_slot in ("A", "B"):
            return {"A": "vulnerable", "B": "fixed"} if vulnerable_slot == "A" else {"A": "fixed", "B": "vulnerable"}
    if position_map_data:
        assignment = position_map_data.get("assignments", position_map_data)
        if isinstance(assignment, Mapping):
            item = assignment.get(pair_id)
            if isinstance(item, Mapping):
                slot = item.get("vulnerable_slot")
                if slot in ("A", "B"):
                    return {"A": "vulnerable", "B": "fixed"} if slot == "A" else {"A": "fixed", "B": "vulnerable"}
    return {"A": "vulnerable", "B": "fixed"} if order in ("AB", "fwd") else {"A": "fixed", "B": "vulnerable"}


def _lengths(pair: Mapping[str, Any], raw: Mapping[str, Any] | None) -> tuple[dict[str, int | None], str | None]:
    value = pick(raw, "length_chars") if raw is not None else None
    if isinstance(value, Mapping):
        vulnerable = as_int(value.get("vulnerable"))
        fixed = as_int(value.get("fixed"))
    else:
        vulnerable_obj = pair.get("vulnerable") or {}
        fixed_obj = pair.get("fixed") or {}
        vulnerable = len(str(vulnerable_obj.get("func_body") or "")) if vulnerable_obj.get("func_body") else None
        fixed = len(str(fixed_obj.get("func_body") or "")) if fixed_obj.get("func_body") else None
    if vulnerable is None or fixed is None:
        return {"vulnerable": vulnerable, "fixed": fixed}, None
    if vulnerable > fixed:
        longer = "vulnerable"
    elif fixed > vulnerable:
        longer = "fixed"
    else:
        longer = "tie"
    return {"vulnerable": vulnerable, "fixed": fixed}, longer


def _input_block(
    *,
    view: str,
    prompt_sha256: str | None,
    context_mode: str | None,
    sanitized: bool,
    sanitizer_version: str | None = None,
    source_sha256: str | None = None,
    evidence_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "view": view,
        "source_sha256": source_sha256,
        "prompt_sha256": prompt_sha256,
        "context_mode": context_mode,
        "sanitized": sanitized,
        "sanitizer_version": sanitizer_version,
        "evidence_sha256": evidence_sha256,
    }


def _base_record(
    *,
    run_id: str,
    tier: str,
    track: str,
    task: str,
    unit_id: str,
    cluster_id: str,
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    input_block: Mapping[str, Any],
    label: Mapping[str, Any],
    status: str,
    provenance: Mapping[str, Any],
    group_id: str | None = None,
    side: str | None = None,
    y_pred: bool | None = None,
    confidence: float | None = None,
    rationale: str | None = None,
    raw_output_sha256: str | None = None,
    coverage: Mapping[str, Any] | None = None,
    oracle: Mapping[str, Any] | None = None,
    usage: Mapping[str, Any] | None = None,
    cost: Mapping[str, Any] | None = None,
    error: Mapping[str, Any] | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    prediction: dict[str, Any] = {
        "y_pred": y_pred if status == "ok" else None,
        "confidence": confidence,
        "evidence_lines": [],
        "rationale": rationale,
        "raw_output_sha256": raw_output_sha256,
    }
    record: dict[str, Any] = {
        "schema_version": "benchmark-prediction-v1",
        "run_id": run_id,
        "tier": tier,
        "track": track,
        "task": task,
        "unit_id": unit_id,
        "cluster_id": cluster_id,
        "group_id": group_id,
        "side": side,
        "dataset": {
            "dataset_id": dataset.get("dataset_id"),
            "split_id": dataset.get("split_id"),
            "sha256": dataset.get("sha256"),
            "unit_manifest_sha256": dataset.get("unit_manifest_sha256"),
        },
        "method": dict(method),
        "input": dict(input_block),
        "label": dict(label),
        "prediction": prediction,
        "status": status,
        "provenance": dict(provenance),
    }
    if coverage is not None:
        record["coverage"] = dict(coverage)
    if oracle is not None:
        record["oracle"] = dict(oracle)
    if usage is not None:
        record["usage"] = dict(usage)
    if cost is not None:
        record["cost"] = dict(cost)
    if error is not None:
        record["error"] = dict(error)
    if extensions is not None:
        record["extensions"] = dict(extensions)
    check_no_secret_fields(record)
    return record


def _provenance(
    *,
    raw_path: Path,
    raw_sha: str,
    record_index: int | None,
    note: str,
) -> dict[str, Any]:
    return {
        "produced_by": "benchmark/extensions/tools/ext_import.py",
        "created_at": utc_now(),
        "source_artifact": _display_path(raw_path),
        "source_sha256": raw_sha,
        "record_index": record_index,
        "command_sha256": None,
        "legacy_run_id": None,
        "note": note,
    }


def _usage_cost(
    raw: Mapping[str, Any] | None,
    family: str,
    config: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if raw is None:
        return None, None
    return _normalize_usage(raw), _normalize_cost(raw, family, config)


# ---------------------------------------------------------------------------
# Manifest / staging
# ---------------------------------------------------------------------------


def _execution(config: Mapping[str, Any], records: Sequence[Mapping[str, Any]], planned: int) -> dict[str, Any]:
    missing = sum(1 for record in records if record.get("status") in ("not_run", "skipped_budget"))
    status = "completed"
    if not records:
        status = "failed"
    elif missing or len(records) != planned:
        status = "partial"
    return {
        "started_at": str(config.get("started_at") or _created_at(config)),
        "finished_at": utc_now(),
        "status": status,
        "planned_units": int(planned),
        "recorded_units": len(records),
        "retries": int(config.get("retries") or 0),
        "concurrency": int(config.get("concurrency") or 1),
        "command": config.get("command"),
        "command_sha256": None,
        "environment": config.get("environment") if isinstance(config.get("environment"), Mapping) else {},
    }


def _manifest(
    *,
    config: Mapping[str, Any],
    run_id: str,
    design: str,
    tier: str,
    track: str,
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    planned: int,
    predictions_sha256: str,
    extension_manifest_sha256: str,
    notes: Sequence[str],
) -> dict[str, Any]:
    spec = design_spec(design)
    return {
        "schema_version": "benchmark-run-v1",
        "run_id": run_id,
        "created_at": _created_at(config),
        "protocol_version": "1.0.0",
        "tier": tier,
        "track": track,
        "tasks": [spec["parent_task"]],
        "dataset": dict(dataset),
        "method": dict(method),
        "execution": _execution(config, records, planned),
        "artifacts": {
            "predictions": "predictions.jsonl",
            "metrics": None,
            "validation": "validation.json",
            "log": None,
        },
        "hashes": {
            "predictions_sha256": predictions_sha256,
            "extension_manifest_sha256": extension_manifest_sha256,
        },
        "legacy_import": None,
        "notes": list(notes),
    }


def _extension_manifest(
    *,
    config: Mapping[str, Any],
    design: str,
    run_role: str,
    presentation_order: str | None,
    pairing_id: str | None,
    sibling_run_id: str | None,
    claim_manifest: Mapping[str, Any] | None,
    fault_manifest: Mapping[str, Any] | None,
    tool_registry: Mapping[str, Any] | None,
    baseline_run: str | None,
) -> dict[str, Any]:
    spec = design_spec(design)
    manifest: dict[str, Any] = {
        "schema_version": EXTENSION_MANIFEST_SCHEMA,
        "extension_id": f"ext.{design}.v1",
        "design": design,
        "design_version": "1.0.0",
        "registry_version": DESIGN_REGISTRY_VERSION,
        "parent_task": spec["parent_task"],
        "aggregation_unit": spec["aggregation_unit"],
        "created_at": _created_at(config),
        "run_role": run_role,
        "presentation_order": presentation_order,
        "pairing_id": pairing_id,
        "sibling_run_id": sibling_run_id,
        "claim_manifest": claim_manifest,
        "fault_manifest": fault_manifest,
        "tool_registry": tool_registry,
        "baseline_run": baseline_run,
        "coverage_threshold": float(config.get("coverage_threshold", 0.8)),
        "options": {
            "extension_version": EXTENSION_VERSION,
            "jsonschema_checked": bool(config.get("jsonschema", False)),
            "split": config.get("split"),
        },
        "notes": list(config.get("notes") or []),
    }
    check_no_secret_fields(manifest)
    return manifest


def _prepare_output(path: Path, force: bool) -> None:
    if not path.exists():
        return
    if not force:
        raise ExtensionError(f"output already exists: {path}; pass --force to archive it")
    archive_dir = path.parent / ".superseded"
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "").replace("Z", "")
    target = archive_dir / f"{path.name}.{stamp}"
    counter = 1
    while target.exists():
        target = archive_dir / f"{path.name}.{stamp}.{counter}"
        counter += 1
    path.rename(target)


def _stage_run(
    *,
    stage_dir: Path,
    config: Mapping[str, Any],
    design: str,
    run_id: str,
    tier: str,
    track: str,
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    planned: int,
    extension_manifest: Mapping[str, Any],
    notes: Sequence[str],
    validate_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    stage_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = stage_dir / "predictions.jsonl"
    predictions_sha = write_jsonl(predictions_path, records)
    extension_path = stage_dir / "extension_manifest.json"
    extension_path.write_text(
        json.dumps(extension_manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    extension_sha = sha256_file(extension_path)
    manifest = _manifest(
        config=config,
        run_id=run_id,
        design=design,
        tier=tier,
        track=track,
        dataset=dataset,
        method=method,
        records=records,
        planned=planned,
        predictions_sha256=predictions_sha,
        extension_manifest_sha256=extension_sha,
        notes=notes,
    )
    check_no_secret_fields(manifest)
    (stage_dir / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    report = validate_extension_run(
        stage_dir,
        use_jsonschema=bool(config.get("jsonschema", False)),
        **dict(validate_kwargs),
    )
    if report.get("errors"):
        raise ExtensionError(
            f"staged run {run_id} failed validation: "
            + "; ".join(str(message) for message in report["errors"][:10])
        )
    return report


def _publish(stage_dir: Path, final_dir: Path, force: bool) -> None:
    _prepare_output(final_dir, force)
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(stage_dir, final_dir)


def _write_validation(run_dir: Path, report: Mapping[str, Any]) -> None:
    path = run_dir / "validation.json"
    text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Position-debiased pair
# ---------------------------------------------------------------------------


def _normalize_order(value: Any) -> str:
    text = str(value).strip()
    upper = text.upper()
    if upper in ("AB", "FWD", "FORWARD"):
        return "fwd" if upper != "AB" else "AB"
    if upper in ("BA", "REV", "REVERSE", "BACKWARD"):
        return "rev" if upper != "BA" else "BA"
    raise ExtensionError(f"invalid presentation order {value!r}; expected AB, BA, fwd or rev")


def _order_dir_name(order: str) -> str:
    return {"AB": "order_ab", "BA": "order_ba", "fwd": "fwd", "rev": "rev"}[order]


def _order_run_role(order: str) -> str:
    return {"AB": "order_ab", "BA": "order_ba", "fwd": "fwd", "rev": "rev"}[order]


def _position_sources(
    config: Mapping[str, Any],
    base_run_id: str,
) -> dict[str, dict[str, Any]] | None:
    raw_spec = config.get("orders")
    if not isinstance(raw_spec, Mapping):
        return None
    bases = _config_bases(config)
    result: dict[str, dict[str, Any]] = {}
    for key, item in raw_spec.items():
        order = _normalize_order(key)
        if isinstance(item, str):
            raw_value = item
            map_value = None
            run_id = None
        elif isinstance(item, Mapping):
            raw_value = item.get("raw")
            map_value = item.get("position_map")
            run_id = item.get("run_id")
        else:
            raise ExtensionError(f"config.orders[{key!r}] must be a path or object")
        if not raw_value:
            raise ExtensionError(f"config.orders[{key!r}].raw is required")
        raw_path = resolve_path(str(raw_value), bases)
        map_path = resolve_path(str(map_value), bases) if map_value else None
        result[order] = {
            "raw": raw_path,
            "position_map": map_path,
            "run_id": str(run_id) if run_id else None,
            "source": _display_path(raw_path),
        }
    if len(result) not in (1, 2):
        raise ExtensionError("config.orders must contain one or two orders")
    return result


def _position_records(
    *,
    run_id: str,
    order: str,
    scheme: str,
    raw_records: Sequence[Mapping[str, Any]],
    pairs: Mapping[str, Mapping[str, Any]],
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    config: Mapping[str, Any],
    raw_path: Path,
    raw_sha: str,
    position_map_data: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    raw_by_pair: dict[str, Mapping[str, Any]] = {}
    raw_index: dict[str, int] = {}
    for index, raw in enumerate(raw_records):
        pair_id = first_str(raw, "pair_id", "group_id", "id")
        if not pair_id:
            raise ExtensionError(f"position raw record {index + 1}: missing pair_id")
        if pair_id in raw_by_pair:
            raise ExtensionError(f"position raw has duplicate pair_id {pair_id!r} for order {order}")
        raw_by_pair[pair_id] = raw
        raw_index[pair_id] = index
    records: list[dict[str, Any]] = []
    family = str((method.get("family") or "llm"))
    for pair_id, pair in pairs.items():
        raw = raw_by_pair.get(pair_id)
        pm = _position_map_from_raw(raw, order=order, pair_id=pair_id, position_map_data=position_map_data)
        if set(pm) != {"A", "B"} or set(pm.values()) != {"vulnerable", "fixed"}:
            raise ExtensionError(
                f"pair {pair_id}: position_map must map A/B bijectively to vulnerable/fixed"
            )
        if scheme == "global_ab":
            expected_map = (
                {"A": "vulnerable", "B": "fixed"}
                if order == "AB"
                else {"A": "fixed", "B": "vulnerable"}
            )
            if pm != expected_map:
                raise ExtensionError(
                    f"pair {pair_id}: position_map {pm} contradicts global order {order} "
                    f"(expected {expected_map})"
                )
        if raw is None:
            status = "not_run"
            choice = None
            selected_side = None
            selected_slot = None
            confidence = None
            prompt_sha = None
            raw_digest = None
            rationale = None
            usage = cost = error = None
            record_index = None
        else:
            choice = _normalize_position_choice(
                pick(raw, "choice", "selected_slot", "parsed.vulnerable_version", "parsed.selected_version", "vulnerable_version", "selected_version", "answer")
            )
            status = _status_for_raw(raw, parsed_valid=choice is not None)
            selected_slot = choice
            selected_side = pm.get(choice) if choice else None
            confidence = as_number(pick(raw, "parsed.confidence", "confidence"))
            prompt_sha = first_str(raw, "prompt_sha256", "request.body_sha256")
            raw_digest = _safe_raw_digest(raw)
            rationale = first_str(raw, "parsed.rationale", "rationale") if config.get("include_rationale", True) else None
            usage, cost = _usage_cost(raw, family, config)
            error = _normalize_error(raw, status)
            record_index = raw_index[pair_id]
        lengths, longer = _lengths(pair, raw)
        project = first_str(pair.get("vulnerable") or {}, "project")
        for side in ("vulnerable", "fixed"):
            y_true = side == "vulnerable"
            y_pred = None
            if status == "ok" and selected_side is not None:
                y_pred = side == selected_side
            provenance = _provenance(
                raw_path=raw_path,
                raw_sha=raw_sha,
                record_index=record_index,
                note="copied from producer raw; not re-run",
            )
            records.append(
                _base_record(
                    run_id=run_id,
                    tier="A",
                    track="secvuleval",
                    task="pair_detection",
                    unit_id=canonical_pair_unit_id(pair_id, side),
                    cluster_id=pair_id,
                    group_id=pair_id,
                    side=side,
                    dataset=dataset,
                    method=method,
                    input_block=_input_block(
                        view="pair",
                        prompt_sha256=prompt_sha,
                        context_mode="none",
                        sanitized=True,
                        sanitizer_version=config.get("sanitizer_version"),
                    ),
                    label={
                        "y_true": y_true,
                        "cwe": normalize_cwe_list((pair.get("vulnerable") or {}).get("cwe_list"))
                        if side == "vulnerable"
                        else [],
                        "label_source": "secvuleval",
                        "label_note": None,
                    },
                    status=status,
                    provenance=provenance,
                    y_pred=y_pred,
                    confidence=confidence,
                    rationale=rationale,
                    raw_output_sha256=raw_digest,
                    usage=usage,
                    cost=cost,
                    error=error,
                    extensions={
                        "pair_design": "position_debiased_pair",
                        "presentation_order": order,
                        "position_map": pm,
                        "forced_choice": True,
                        "choice": choice,
                        "selected_side": selected_side,
                        "selected_slot": selected_slot,
                        "confidence": confidence,
                        "length_chars": lengths,
                        "longer_side": longer,
                        "order_seed": config.get("order_seed"),
                        "raw_record_sha256": raw_digest,
                        "sibling_run_id": config.get("_sibling_run_id"),
                        "pair_project": project,
                        "notes": None,
                    },
                )
            )
    return records


def _position_orders(
    raw_records: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        order = first_str(raw, "presentation_order", "order", "presentation", "version_order", "prompt.order")
        if order is None:
            configured = config.get("order")
            if configured is not None:
                order = configured
            elif len(raw_records) == 1:
                raise ExtensionError(
                    "position raw record has no presentation_order; add it or set config.order to AB/BA/fwd/rev"
                )
            else:
                raise ExtensionError(
                    f"position raw record {index + 1} has no presentation_order; cannot split orders"
                )
        try:
            normalized = _normalize_order(order)
        except ExtensionError as exc:
            raise ExtensionError(f"position raw record {index + 1}: {exc}") from exc
        grouped.setdefault(normalized, []).append(raw)
    return grouped


def import_position(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    out_base: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "position_debiased_pair"
    pair_path = _config_path(config, "pair_split", required=True)
    assert pair_path is not None
    pairs = pair_split_index(pair_path)
    base_run_id = str(_require(config, "run_id"))
    dataset = _dataset_meta(
        config,
        path=pair_path,
        dataset_id="secvul-split-v1",
        split_id=str(config.get("split_id") or "secvul-split-v1"),
        unit_count=2 * len(pairs),
        group_count=len(pairs),
        label_counts={"vulnerable": len(pairs), "fixed": len(pairs)},
    )
    method = _method_from_config(config)
    pairing_id = str(
        config.get("pairing_id")
        or sha256_text(f"position:{dataset['sha256']}:{','.join(sorted(pairs))}")
    )
    order_sources = _position_sources(config, base_run_id)
    if order_sources is not None:
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        source_meta: dict[str, dict[str, Any]] = {}
        for order, source in order_sources.items():
            raw = source["raw"]
            if not raw.exists():
                raise ExtensionError(f"position order {order}: raw not found: {raw}")
            grouped[order] = load_records(raw)
            map_data = None
            map_path = source.get("position_map")
            if map_path is not None:
                if not map_path.exists():
                    raise ExtensionError(f"position order {order}: position_map not found: {map_path}")
                map_data = json.loads(map_path.read_text(encoding="utf-8"))
            source_meta[order] = {
                "raw": raw,
                "raw_sha": sha256_file(raw),
                "position_map_data": map_data,
                "run_id": source.get("run_id"),
            }
    else:
        raw_records = load_records(raw_path)
        raw_sha = sha256_file(raw_path)
        grouped = _position_orders(raw_records, config)
        map_data = None
        map_path = _config_path(config, "position_map")
        if map_path is not None and map_path.exists():
            map_data = json.loads(map_path.read_text(encoding="utf-8"))
        source_meta = {
            order: {
                "raw": raw_path,
                "raw_sha": raw_sha,
                "position_map_data": map_data,
                "run_id": None,
            }
            for order in grouped
        }
    if not grouped:
        raise ExtensionError("position raw has no AB/BA/fwd/rev records")
    if len(grouped) > 2:
        raise ExtensionError("position supports at most two presentation orders")
    run_ids: dict[str, str] = {}
    for order in sorted(grouped):
        configured = source_meta[order].get("run_id")
        run_ids[order] = str(configured) if configured else f"{base_run_id}_{order.lower()}"
    staging_parent = out_base.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    stage_base = Path(tempfile.mkdtemp(prefix=".ext_import_position_", dir=staging_parent))
    reports: dict[str, Any] = {}
    try:
        for order in sorted(grouped):
            run_id = run_ids[order]
            sibling_orders = [item for item in sorted(grouped) if item != order]
            sibling = run_ids[sibling_orders[0]] if sibling_orders else None
            local_config = dict(config)
            local_config["_sibling_run_id"] = sibling
            source = source_meta[order]
            scheme = "global_ab" if order in ("AB", "BA") else "per_pair_swap"
            records = _position_records(
                run_id=run_id,
                order=order,
                scheme=scheme,
                raw_records=grouped[order],
                pairs=pairs,
                dataset=dataset,
                method=method,
                config=local_config,
                raw_path=source["raw"],
                raw_sha=source["raw_sha"],
                position_map_data=source["position_map_data"],
            )
            ext_manifest = _extension_manifest(
                config=config,
                design=design,
                run_role=_order_run_role(order),
                presentation_order=order,
                pairing_id=pairing_id,
                sibling_run_id=sibling,
                claim_manifest=None,
                fault_manifest=None,
                tool_registry=None,
                baseline_run=config.get("baseline_run"),
            )
            stage_run = stage_base / _order_dir_name(order)
            report = _stage_run(
                stage_dir=stage_run,
                config=config,
                design=design,
                run_id=run_id,
                tier="A",
                track="secvuleval",
                dataset=dataset,
                method=method,
                records=records,
                planned=2 * len(pairs),
                extension_manifest=ext_manifest,
                notes=[
                    f"position-debiased pair run, presentation order {order}; pairing_id={pairing_id}",
                    "copied from producer raw; not re-run",
                ],
                validate_kwargs={},
            )
            reports[order] = report
        if len(grouped) == 2:
            for order in sorted(grouped):
                sibling_order = [item for item in sorted(grouped) if item != order][0]
                report = validate_extension_run(
                    stage_base / _order_dir_name(order),
                    sibling_run_dir=stage_base / _order_dir_name(sibling_order),
                    use_jsonschema=bool(config.get("jsonschema", False)),
                )
                if report.get("errors"):
                    raise ExtensionError(
                        "position pairing validation failed: "
                        + "; ".join(str(message) for message in report["errors"][:10])
                    )
                reports[order] = report
        pairing = {
            "schema_version": "benchmark-extension-pairing-v1",
            "design": design,
            "pairing_id": pairing_id,
            "dataset_sha256": dataset["sha256"],
            "pair_count": len(pairs),
            "orders": {order: run_ids[order] for order in sorted(grouped)},
            "sources": {
                order: {
                    "raw": _display_path(source_meta[order]["raw"]),
                    "raw_sha256": source_meta[order]["raw_sha"],
                    "presentation_order": order,
                }
                for order in sorted(grouped)
            },
            "created_at": _created_at(config),
        }
        (stage_base / "pairing.json").write_text(
            json.dumps(pairing, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        summary = {
            "design": design,
            "out_base": str(out_base),
            "pairing_id": pairing_id,
            "orders": {order: run_ids[order] for order in sorted(grouped)},
            "pairs": len(pairs),
            "records": {order: len(grouped[order]) for order in sorted(grouped)},
        }
        if dry_run:
            if grouped:
                first_order = sorted(grouped)[0]
                first_dir = stage_base / _order_dir_name(first_order)
                phase = (
                    json.loads((first_dir / "validation.json").read_text(encoding="utf-8"))
                    if (first_dir / "validation.json").exists()
                    else reports[first_order]
                )
                summary["validation"] = phase
            return summary
        _publish(stage_base, out_base, force)
        for order in sorted(grouped):
            final_run = out_base / _order_dir_name(order)
            report = reports[order]
            report["run_dir"] = str(final_run)
            _write_validation(final_run, report)
        return summary
    finally:
        if stage_base.exists():
            shutil.rmtree(stage_base, ignore_errors=True)


# ---------------------------------------------------------------------------
# Open-choice pair
# ---------------------------------------------------------------------------


def import_open_choice(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "open_choice_pair"
    pair_path = _config_path(config, "pair_split", required=True)
    assert pair_path is not None
    pairs = pair_split_index(pair_path)
    raw_records = load_records(raw_path)
    raw_sha = sha256_file(raw_path)
    raw_by_pair: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        pair_id = first_str(raw, "pair_id", "group_id", "id")
        if not pair_id:
            raise ExtensionError(f"open-choice raw record {index + 1}: missing pair_id")
        if pair_id in raw_by_pair:
            raise ExtensionError(f"open-choice raw has duplicate pair_id {pair_id!r}")
        raw_by_pair[pair_id] = (index, raw)
    dataset = _dataset_meta(
        config,
        path=pair_path,
        dataset_id="secvul-split-v1",
        split_id=str(config.get("split_id") or "secvul-split-v1"),
        unit_count=2 * len(pairs),
        group_count=len(pairs),
        label_counts={"vulnerable": len(pairs), "fixed": len(pairs)},
    )
    method = _method_from_config(config)
    run_id = _new_run_id(config)
    order = str(config.get("order") or "AB")
    if order not in ("AB", "BA", "fwd", "rev"):
        raise ExtensionError("config.order for open_choice_pair must be AB, BA, fwd or rev")
    position_map_data = None
    position_map_path = _config_path(config, "position_map")
    if position_map_path is not None and position_map_path.exists():
        position_map_data = json.loads(position_map_path.read_text(encoding="utf-8"))
    records: list[dict[str, Any]] = []
    for pair_id, pair in pairs.items():
        item = raw_by_pair.get(pair_id)
        raw = item[1] if item else None
        record_index = item[0] if item else None
        pm = _position_map_from_raw(
            raw, order=order, pair_id=pair_id, position_map_data=position_map_data
        )
        if raw is None:
            choice = None
            status = "not_run"
            selected_slots: list[str] = []
            confidence = None
            prompt_sha = None
            raw_digest = None
            rationale = None
            usage = cost = error = None
        else:
            choice = _normalize_open_choice(
                pick(raw, "open_choice", "choice", "parsed.open_choice", "parsed.choice", "parsed.vulnerable_version", "vulnerable_version", "answer")
            )
            status = _status_for_raw(raw, parsed_valid=choice is not None)
            selected_slots = {"A": ["A"], "B": ["B"], "both": ["A", "B"], "neither": []}.get(choice or "", [])
            confidence = as_number(pick(raw, "parsed.confidence", "confidence"))
            prompt_sha = first_str(raw, "prompt_sha256", "request.body_sha256")
            raw_digest = _safe_raw_digest(raw)
            rationale = first_str(raw, "parsed.rationale", "rationale") if config.get("include_rationale", True) else None
            usage, cost = _usage_cost(raw, str(method.get("family")), config)
            error = _normalize_error(raw, status)
        flagged_sides = {pm.get(slot) for slot in selected_slots if pm.get(slot)}
        lengths, longer = _lengths(pair, raw)
        project = first_str(pair.get("vulnerable") or {}, "project")
        for side in ("vulnerable", "fixed"):
            y_true = side == "vulnerable"
            y_pred = None
            if status == "ok":
                y_pred = side in flagged_sides
            provenance = _provenance(
                raw_path=raw_path,
                raw_sha=raw_sha,
                record_index=record_index,
                note="copied from producer raw; not re-run",
            )
            records.append(
                _base_record(
                    run_id=run_id,
                    tier="A",
                    track="secvuleval",
                    task="pair_detection",
                    unit_id=canonical_pair_unit_id(pair_id, side),
                    cluster_id=pair_id,
                    group_id=pair_id,
                    side=side,
                    dataset=dataset,
                    method=method,
                    input_block=_input_block(
                        view="pair",
                        prompt_sha256=prompt_sha,
                        context_mode="none",
                        sanitized=True,
                        sanitizer_version=config.get("sanitizer_version"),
                    ),
                    label={
                        "y_true": y_true,
                        "cwe": normalize_cwe_list((pair.get("vulnerable") or {}).get("cwe_list"))
                        if side == "vulnerable"
                        else [],
                        "label_source": "secvuleval",
                        "label_note": None,
                    },
                    status=status,
                    provenance=provenance,
                    y_pred=y_pred,
                    confidence=confidence,
                    rationale=rationale,
                    raw_output_sha256=raw_digest,
                    usage=usage,
                    cost=cost,
                    error=error,
                    extensions={
                        "pair_design": "open_choice_pair",
                        "open_choice": choice,
                        "selected_slots": selected_slots,
                        "forced_choice": False,
                        "position_map": pm,
                        "confidence": confidence,
                        "length_chars": lengths,
                        "longer_side": longer,
                        "raw_record_sha256": raw_digest,
                        "pair_project": project,
                        "repeat_role": order if order in ("fwd", "rev") else None,
                        "pairing_id": config.get("pairing_id"),
                        "sibling_run_id": config.get("sibling_run_id"),
                        "notes": None,
                    },
                )
            )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="A",
        track="secvuleval",
        dataset=dataset,
        method=method,
        records=records,
        planned=2 * len(pairs),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=["open-choice pair run; one 4-way response encoded as two side records", "copied from producer raw; not re-run"],
    )


# ---------------------------------------------------------------------------
# Evidence verification
# ---------------------------------------------------------------------------


def import_evidence(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    claim_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "evidence_verification"
    claims_doc = load_claim_manifest(claim_path)
    claims = claims_doc["claims"]
    tiers = {str(claim.get("tier")) for claim in claims}
    tracks = {str(claim.get("track")) for claim in claims}
    if len(tiers) != 1 or len(tracks) != 1:
        raise ExtensionError("evidence claim manifest mixes tiers/tracks; split it into separate runs")
    tier = tiers.pop()
    track = tracks.pop()
    if tier != str(config.get("tier") or tier) or track != str(config.get("track") or track):
        raise ExtensionError("config.tier/track disagrees with the claim manifest")
    claim_sha = sha256_file(claim_path)
    dataset = _dataset_meta(
        config,
        path=claim_path,
        dataset_id=str(claims_doc.get("dataset_id") or "evidence-claims-v1"),
        split_id=str(claims_doc.get("split_id") or "test"),
        unit_count=len(claims),
        group_count=None,
        label_counts={
            "supported": sum(1 for claim in claims if claim.get("gold_verdict") == "supported"),
            "unsupported": sum(1 for claim in claims if claim.get("gold_verdict") == "unsupported"),
        },
    )
    method = _method_from_config(config)
    run_id = _new_run_id(config)
    raw_records = load_records(raw_path)
    raw_sha = sha256_file(raw_path)
    raw_by_claim: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        claim_id = first_str(raw, "claim_id", "id", "unit_id")
        if not claim_id:
            raise ExtensionError(f"evidence raw record {index + 1}: missing claim_id")
        if claim_id in raw_by_claim:
            raise ExtensionError(f"evidence raw has duplicate claim_id {claim_id!r}")
        raw_by_claim[claim_id] = (index, raw)
    known_ids = {str(claim.get("claim_id")) for claim in claims}
    extra = set(raw_by_claim) - known_ids
    if extra:
        raise ExtensionError(f"evidence raw has {len(extra)} claim(s) not in the frozen manifest")
    records: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = str(claim["claim_id"])
        item = raw_by_claim.get(claim_id)
        raw = item[1] if item else None
        record_index = item[0] if item else None
        gold = str(claim.get("gold_verdict"))
        if raw is None:
            verdict = None
            status = "not_run"
            confidence = None
            prompt_sha = None
            raw_digest = None
            rationale = None
            cited_lines: list[int] = []
            usage = cost = error = None
        else:
            verdict = _normalize_verdict(
                pick(raw, "verdict", "parsed.verdict", "parsed.label", "label", "decision")
            )
            parsed_valid = verdict is not None
            status = _status_for_raw(raw, parsed_valid=parsed_valid)
            if verdict == "insufficient" and status == "ok":
                status = "inconclusive"
            confidence = as_number(pick(raw, "parsed.confidence", "confidence"))
            prompt_sha = first_str(raw, "prompt_sha256", "request.body_sha256")
            raw_digest = _safe_raw_digest(raw)
            rationale = first_str(raw, "parsed.rationale", "rationale", "parsed.reason") if config.get("include_rationale", True) else None
            cited = pick(raw, "parsed.cited_lines", "cited_lines", "evidence_lines", default=[])
            cited_lines = [int(value) for value in cited if isinstance(value, int) and value >= 1] if isinstance(cited, list) else []
            usage, cost = _usage_cost(raw, str(method.get("family")), config)
            error = _normalize_error(raw, status)
        y_true = gold == "supported"
        y_pred = None
        if status == "ok":
            if verdict == "supported":
                y_pred = True
            elif verdict == "unsupported":
                y_pred = False
        provenance = _provenance(
            raw_path=raw_path,
            raw_sha=raw_sha,
            record_index=record_index,
            note="copied from producer raw; not re-run; gold from frozen claim manifest",
        )
        records.append(
            _base_record(
                run_id=run_id,
                tier=tier,
                track=track,
                task="detection",
                unit_id=canonical_claim_unit_id(tier, claim_id),
                cluster_id=str(claim.get("cluster_id")),
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="other",
                    prompt_sha256=prompt_sha,
                    context_mode="tool_evidence",
                    sanitized=True,
                    sanitizer_version=config.get("sanitizer_version"),
                    source_sha256=claim.get("source_sha256"),
                    evidence_sha256=claim.get("claim_text_sha256"),
                ),
                label={
                    "y_true": y_true,
                    "cwe": normalize_cwe_list(claim.get("cwe")),
                    "label_source": "manual",
                    "label_note": f"claim_type={claim.get('claim_type')}; gold={gold}",
                },
                status=status,
                provenance=provenance,
                y_pred=y_pred,
                confidence=confidence,
                rationale=rationale,
                raw_output_sha256=raw_digest,
                usage=usage,
                cost=cost,
                error=error,
                extensions={
                    "task_design": "evidence_verification",
                    "verification": {
                        "claim_id": claim_id,
                        "claim_type": str(claim.get("claim_type")),
                        "verdict": verdict,
                        "gold_verdict": gold,
                        "abstained": verdict == "insufficient",
                        "claim_text_sha256": claim.get("claim_text_sha256"),
                        "claim_manifest_sha256": claim_sha,
                        "cited_lines": cited_lines,
                        "line_check": None,
                        "raw_record_sha256": raw_digest,
                        "notes": None,
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest={
            "path": _display_path(claim_path),
            "sha256": claim_sha,
            "count": len(claims),
        },
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier=tier,
        track=track,
        dataset=dataset,
        method=method,
        records=records,
        planned=len(claims),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=["evidence verification run; claim gold from a frozen claim manifest", "copied from producer raw; not re-run"],
        validate_kwargs={"claim_manifest": str(claim_path)},
    )


# ---------------------------------------------------------------------------
# Fault-injected dynamic
# ---------------------------------------------------------------------------


def _fault_status(
    expected: str,
    observed: str,
    *,
    coverage_ok: bool,
    raw_status: str | None,
) -> str:
    if expected == "inconclusive":
        return "not_applicable"
    if raw_status in ("not_run", "skipped_budget", "api_error"):
        return raw_status
    if observed == "leak":
        return "ok"
    if observed == "clean":
        return "ok" if coverage_ok else "inconclusive"
    if observed == "inconclusive":
        return "inconclusive"
    if observed == "timeout":
        return "timeout"
    if observed == "crash":
        return "crash"
    if observed == "error":
        return "tool_error"
    return "tool_error"


def import_fault(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    fault_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "fault_injected_dynamic"
    faults_doc = load_fault_manifest(fault_path)
    faults = faults_doc["faults"]
    fault_sha = sha256_file(fault_path)
    dataset = _dataset_meta(
        config,
        path=fault_path,
        dataset_id=str(faults_doc.get("dataset_id") or "juliet-cwe401-fault-v1"),
        split_id=str(faults_doc.get("split_id") or "test"),
        unit_count=len(faults),
        group_count=len({
            parse_juliet_unit_id(str(fault.get("base_unit_id")))[0]
            for fault in faults
        }),
        label_counts={
            "leak": sum(1 for fault in faults if fault.get("expected_outcome") == "leak"),
            "clean": sum(1 for fault in faults if fault.get("expected_outcome") == "clean"),
            "inconclusive": sum(1 for fault in faults if fault.get("expected_outcome") == "inconclusive"),
        },
    )
    method = _method_from_config(config)
    if method.get("family") != "dynamic":
        raise ExtensionError("fault_injected_dynamic requires config.method.family=dynamic")
    run_id = _new_run_id(config)
    raw_records = load_records(raw_path)
    raw_sha = sha256_file(raw_path)
    raw_by_fault: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        fault_id = first_str(raw, "fault_id", "id")
        if not fault_id:
            raise ExtensionError(f"fault raw record {index + 1}: missing fault_id")
        if fault_id in raw_by_fault:
            raise ExtensionError(f"fault raw has duplicate fault_id {fault_id!r}")
        raw_by_fault[fault_id] = (index, raw)
    known_ids = {str(fault.get("fault_id")) for fault in faults}
    extra = set(raw_by_fault) - known_ids
    if extra:
        raise ExtensionError(f"fault raw has {len(extra)} fault(s) not in the frozen manifest")
    threshold = float(config.get("coverage_threshold", 0.8))
    records: list[dict[str, Any]] = []
    for fault in faults:
        fault_id = str(fault["fault_id"])
        item = raw_by_fault.get(fault_id)
        raw = item[1] if item else None
        record_index = item[0] if item else None
        expected = str(fault.get("expected_outcome"))
        base_unit_id = str(fault.get("base_unit_id"))
        try:
            group, side = parse_juliet_unit_id(base_unit_id)
        except ExtensionError as exc:
            raise ExtensionError(f"fault {fault_id}: {exc}") from exc
        if raw is None:
            observed = "inconclusive"
            status = "not_applicable" if expected == "inconclusive" else "not_run"
            coverage = _unknown_coverage()
            oracle = None
            baseline = fault.get("baseline_outcome")
            confidence = None
            prompt_sha = None
            raw_digest = None
            usage = cost = error = None
        else:
            observed = str(
                pick(raw, "observed_outcome", "outcome", "dynamic_outcome", default="inconclusive")
            ).strip().lower()
            if observed not in FAULT_OBSERVED:
                observed = "error"
            raw_expected = pick(raw, "expected_outcome", "expected")
            if raw_expected is not None and str(raw_expected) != expected:
                raise ExtensionError(
                    f"fault {fault_id}: raw expected_outcome disagrees with frozen manifest"
                )
            coverage = _normalize_coverage(raw) or _unknown_coverage()
            coverage_ok = coverage_sufficient({"coverage": coverage}, threshold)
            raw_status = normalize_status(pick(raw, "status", "result.status"))
            status = _fault_status(expected, observed, coverage_ok=coverage_ok, raw_status=raw_status)
            oracle = _normalize_oracle(raw)
            baseline = pick(raw, "baseline_outcome", default=fault.get("baseline_outcome"))
            confidence = as_number(pick(raw, "confidence"))
            prompt_sha = first_str(raw, "prompt_sha256")
            raw_digest = _safe_raw_digest(raw)
            usage, cost = _usage_cost(raw, "dynamic", config)
            error = _normalize_error(raw, status)
        if baseline is not None:
            baseline = str(baseline).strip().lower()
            if baseline not in ("leak", "clean", "inconclusive", "unknown"):
                baseline = "unknown"
        if baseline in ("leak", "clean") and observed in ("leak", "clean"):
            flip = "same" if baseline == observed else (
                "leak_to_clean" if baseline == "leak" else "clean_to_leak"
            )
        else:
            flip = "not_comparable"
        y_true = expected == "leak"
        y_pred = None
        if status == "ok":
            y_pred = observed == "leak"
        coverage_ok = coverage_sufficient({"coverage": coverage}, threshold)
        provenance = _provenance(
            raw_path=raw_path,
            raw_sha=raw_sha,
            record_index=record_index,
            note="copied from producer raw; not re-run; expected outcome from frozen fault manifest",
        )
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=canonical_fault_unit_id(base_unit_id, fault_id),
                cluster_id=str(fault.get("cluster_id")),
                group_id=group,
                side=side,
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=None,
                    context_mode="none",
                    sanitized=False,
                    source_sha256=fault.get("source_sha256"),
                ),
                label={
                    "y_true": y_true,
                    "cwe": ["CWE-401"],
                    "label_source": "manual",
                    "label_note": f"fault_expected={expected}; fault_type={fault.get('fault_type')}",
                },
                status=status,
                provenance=provenance,
                y_pred=y_pred,
                confidence=confidence,
                rationale=None,
                raw_output_sha256=raw_digest,
                coverage=coverage,
                oracle=oracle,
                usage=usage,
                cost=cost,
                error=error,
                extensions={
                    "task_design": "fault_injected_dynamic",
                    "fault_injection": {
                        "fault_id": fault_id,
                        "fault_type": str(fault.get("fault_type")),
                        "base_unit_id": base_unit_id,
                        "expected_outcome": expected,
                        "observed_outcome": observed,
                        "baseline_outcome": baseline,
                        "fault_manifest_sha256": fault_sha,
                        "injection_sha256": fault.get("injection_sha256"),
                        "coverage_sufficient": coverage_ok,
                        "oracle_consensus": (oracle or {}).get("dynamic_consensus"),
                        "flip": flip,
                        "description": fault.get("description"),
                        "seed": fault.get("seed"),
                        "raw_record_sha256": raw_digest,
                        "notes": None,
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest={
            "path": _display_path(fault_path),
            "sha256": fault_sha,
            "count": len(faults),
        },
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(faults),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=["fault-injected dynamic run; expected outcomes frozen before evaluation", "copied from producer raw; not re-run"],
        validate_kwargs={"fault_manifest": str(fault_path)},
    )


# ---------------------------------------------------------------------------
# New static tool
# ---------------------------------------------------------------------------


def _static_target_files(
    unit: Mapping[str, Any],
    raw: Mapping[str, Any] | None,
) -> list[str]:
    files: list[str] = []
    if raw is not None:
        for key in ("target_files", "sample.source_paths", "source_paths", "sample.source_path"):
            value = pick(raw, key)
            if isinstance(value, str):
                files.append(value)
            elif isinstance(value, list):
                files.extend(str(item) for item in value if item)
    for source in unit.get("sources") or []:
        text = str(source)
        if text:
            files.append(str((project_root() / "juliet" / text).resolve()))
            files.append(text)
    return list(dict.fromkeys(files))


def _static_status(raw: Mapping[str, Any] | None) -> str:
    if raw is None:
        return "not_run"
    return normalize_status(pick(raw, "status", "result.status"), default="ok") or "ok"


def import_static(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    unit_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "new_static_tool"
    unit_index = juliet_unit_index(unit_map_path)
    split_filter = config.get("split")
    units = [meta for meta in unit_index.values() if not split_filter or meta.get("split") == split_filter]
    # Deduplicate by canonical unit_id; the index stores several aliases per unit.
    unique_units: dict[str, dict[str, Any]] = {}
    for meta in units:
        unique_units[meta["unit_id"]] = meta
    units = sorted(unique_units.values(), key=lambda item: item["unit_id"])
    if not units:
        raise ExtensionError("no units selected from the unit map")
    unit_map_sha = sha256_file(unit_map_path)
    dataset = _dataset_meta(
        config,
        path=unit_map_path,
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id=str(config.get("split_id") or "juliet-cwe401-v1.3-subset-v1"),
        unit_count=len(units),
        group_count=len({meta["group_id"] for meta in units}),
        label_counts={
            "bad": sum(1 for meta in units if meta["label"] == "bad"),
            "good": sum(1 for meta in units if meta["label"] == "good"),
        },
    )
    method = _method_from_config(config)
    if method.get("family") != "static":
        raise ExtensionError("new_static_tool requires config.method.family=static")
    tool_id = str(config.get("tool_id") or "")
    if not tool_id:
        raise ExtensionError("config.tool_id is required for new_static_tool")
    tool_spec = static_tool_spec(tool_id)
    registry_sha = sha256_file(STATIC_TOOLS_PATH)
    registry_version = str(static_tool_registry().get("registry_version"))
    tool = dict(method.get("tool") or {})
    tool.setdefault("name", tool_spec.get("name"))
    tool.setdefault("command_template", tool_spec.get("command_template"))
    tool.setdefault("rules", sorted(
        rule for rule, spec in (tool_spec.get("rules") or {}).items() if spec.get("counts_for_cwe401")
    ))
    tool.setdefault("license", tool_spec.get("license"))
    if not tool.get("version"):
        raise ExtensionError("config.method.tool.version is required (record the exact analyzer version)")
    method["tool"] = tool
    method["config_sha256"] = sha256_text(
        stable_json({"tool_id": tool_id, "tool": tool, "registry_sha256": registry_sha})
    )
    run_id = _new_run_id(config)
    raw_records = load_records(raw_path)
    raw_sha = sha256_file(raw_path)
    raw_by_unit: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        sample_id = first_str(raw, "unit_id", "sample.unit_id", "sample_id", "sample.sample_id", "id")
        if not sample_id:
            raise ExtensionError(f"static raw record {index + 1}: missing sample_id/unit_id")
        meta = unit_index.get(sample_id)
        if meta is None:
            raise ExtensionError(f"static raw record {index + 1}: unit {sample_id!r} not in the unit map")
        canonical = meta["unit_id"]
        if canonical in raw_by_unit:
            raise ExtensionError(f"static raw has duplicate unit {canonical!r}")
        raw_by_unit[canonical] = (index, raw)
    expected_ids = {meta["unit_id"] for meta in units}
    extra = set(raw_by_unit) - expected_ids
    if extra:
        if split_filter:
            # Raw may contain dev+test; only the selected split is imported.
            pass
        else:
            raise ExtensionError(f"static raw has {len(extra)} unit(s) not selected by the unit map")
    scope_kind = str(config.get("scope_kind") or tool_spec.get("default_scope") or "target_file")
    if scope_kind not in ("target_file", "target_function"):
        raise ExtensionError("config.scope_kind must be target_file or target_function")
    records: list[dict[str, Any]] = []
    for unit in units:
        unit_id = unit["unit_id"]
        item = raw_by_unit.get(unit_id)
        raw = item[1] if item else None
        record_index = item[0] if item else None
        status = _static_status(raw)
        diagnostics_raw = pick(raw, "diagnostics", "findings", "warnings", default=[]) if raw is not None else []
        if not isinstance(diagnostics_raw, list):
            diagnostics_raw = []
        target_files = _static_target_files(unit, raw)
        line_start = as_int(pick(raw, "line_start", "sample.line_start")) if raw is not None else None
        line_end = as_int(pick(raw, "line_end", "sample.line_end")) if raw is not None else None
        default_suppressed = bool(pick(raw, "suppressed", default=False)) if raw is not None else False
        diagnostics = [
            normalize_diagnostic(
                diagnostic if isinstance(diagnostic, Mapping) else {},
                tool_spec=tool_spec,
                target_files=target_files,
                scope_kind=scope_kind,
                line_start=line_start,
                line_end=line_end,
                default_suppressed=default_suppressed,
            )
            for diagnostic in diagnostics_raw
        ]
        counts = summarize_diagnostics(diagnostics)
        y_pred = None
        if status == "ok":
            y_pred = counts["mapped_warning_count"] > 0
        source_sha = None
        if raw is not None:
            source_sha = first_str(raw, "source_sha256", "source.analyzed_sha256", "source.origin_sha256")
        if source_sha and len(source_sha) != 64:
            source_sha = None
        usage, cost = _usage_cost(raw, "static", config)
        command = pick(raw, "command") if raw is not None else None
        command_sha = sha256_text(stable_json(command)) if command is not None else None
        provenance = _provenance(
            raw_path=raw_path,
            raw_sha=raw_sha,
            record_index=record_index,
            note="copied from producer raw; diagnostics re-normalized and recounted; not re-run",
        )
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=unit_id,
                cluster_id=unit["family"],
                group_id=unit["group_id"],
                side=unit["label"],
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=None,
                    context_mode="none",
                    sanitized=False,
                    source_sha256=source_sha,
                ),
                label={
                    "y_true": unit["label"] == "bad",
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                status=status,
                provenance=provenance,
                y_pred=y_pred,
                confidence=None,
                rationale=None,
                raw_output_sha256=None,
                usage=usage,
                cost=cost,
                error=_normalize_error(raw or {}, status),
                extensions={
                    "task_design": "new_static_tool",
                    "static_normalization": {
                        "tool_id": tool_id,
                        "tool_version": str(tool["version"]),
                        "rule_map_version": registry_version,
                        "registry_sha256": registry_sha,
                        "scope_kind": scope_kind,
                        "target_files": target_files,
                        "line_range": {"start": line_start, "end": line_end}
                        if line_start is not None and line_end is not None
                        else None,
                        "diagnostics": diagnostics,
                        "raw_warning_count": counts["raw_warning_count"],
                        "dedup_warning_count": counts["dedup_warning_count"],
                        "mapped_warning_count": counts["mapped_warning_count"],
                        "unmapped_warning_count": counts["unmapped_warning_count"],
                        "out_of_scope_count": counts["out_of_scope_count"],
                        "suppressed_count": counts["suppressed_count"],
                        "severity_policy": tool_spec.get("severity_policy") or {},
                        "main_threshold": "any_mapped_in_scope",
                        "sensitivity_threshold": "high_only",
                        "command_sha256": command_sha,
                        "notes": None,
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry={
            "path": _display_path(STATIC_TOOLS_PATH),
            "sha256": registry_sha,
            "tool_id": tool_id,
        },
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(units),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[f"new static tool canonicalization: {tool_id}", "diagnostics re-normalized and recounted; not re-run"],
        validate_kwargs={"unit_map": str(unit_map_path)},
    )


# ---------------------------------------------------------------------------
# Evidence retraction (real evidence_verify four-arm format)
# ---------------------------------------------------------------------------


def _detection_split_index(path: Path) -> dict[int, Mapping[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data.get("samples") if isinstance(data, dict) else None
    if not isinstance(samples, list):
        raise ExtensionError(f"{path}: expected a detection split object with a samples array")
    index: dict[int, Mapping[str, Any]] = {}
    for sample in samples:
        if not isinstance(sample, Mapping) or not isinstance(sample.get("idx"), int):
            raise ExtensionError(f"{path}: malformed sample")
        index[int(sample["idx"])] = sample
    return index


def _manifest_model(manifest: Mapping[str, Any], key: str = "api") -> str | None:
    api = manifest.get(key)
    if isinstance(api, Mapping) and isinstance(api.get("model"), str):
        return api["model"]
    return None


def import_evidence_retraction(
    config: Mapping[str, Any],
    *,
    first_pass_path: Path,
    verify_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "evidence_retraction"
    split_path = _config_path(config, "detection_split")
    if split_path is None:
        split_path = resolve_path("splits/test_detection_160.json", [project_root(), Path.cwd()])
    if not split_path.exists():
        raise ExtensionError(f"detection split not found: {split_path}")
    split_index = _detection_split_index(split_path)
    first_records = load_records(first_pass_path)
    verify_records = load_records(verify_path)
    first_by_idx: dict[int, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(first_records):
        idx = as_int(pick(raw, "idx", "unit_id"))
        if idx is None:
            raise ExtensionError(f"first-pass record {index + 1}: missing idx")
        if idx in first_by_idx:
            raise ExtensionError(f"first-pass duplicate idx {idx}")
        first_by_idx[idx] = (index, raw)
    verify_by_idx: dict[int, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(verify_records):
        idx = as_int(pick(raw, "idx", "sample_id", "unit_id"))
        if idx is None:
            raise ExtensionError(f"verifier record {index + 1}: missing idx")
        if idx in verify_by_idx:
            raise ExtensionError(f"verifier duplicate idx {idx}")
        verify_by_idx[idx] = (index, raw)
    verify_manifest = {}
    verify_manifest_path = verify_path.parent / "manifest.json"
    if verify_manifest_path.exists():
        verify_manifest = json.loads(verify_manifest_path.read_text(encoding="utf-8"))
    first_manifest = {}
    first_manifest_path = first_pass_path.parent / "manifest.json"
    if first_manifest_path.exists():
        first_manifest = json.loads(first_manifest_path.read_text(encoding="utf-8"))
    first_model = str(
        config.get("first_pass_model")
        or _manifest_model(first_manifest)
        or first_str(first_records[0], "request.model", "response_meta.model", default="unknown")
    )
    verifier_model_id = str(
        config.get("verifier_model")
        or _manifest_model(verify_manifest)
        or first_str(verify_records[0], "request.model", "response_meta.model", default="unknown")
    )
    method = config.get("method")
    if not isinstance(method, Mapping):
        method = {
            "method_id": f"hybrid.evidence_retraction.{first_model}_by_{verifier_model_id}",
            "family": "hybrid",
            "name": f"Evidence retraction: {first_model} first pass verified by {verifier_model_id}",
            "strategy": "verify_positive_claim",
            "model": {
                "model_id": verifier_model_id,
                "family": "llm",
                "provider": str(config.get("verifier_provider") or "opencode-go"),
                "endpoint": (verify_manifest.get("api") or {}).get("endpoint"),
                "version": None,
                "decoding": {
                    "temperature": (verify_manifest.get("api") or {}).get("temperature"),
                    "max_tokens": (verify_manifest.get("api") or {}).get("max_tokens"),
                },
            },
        }
    else:
        method = json.loads(json.dumps(method))
    if not method.get("config_sha256"):
        method["config_sha256"] = sha256_text(stable_json(method))
    analysis_status = str(
        verify_manifest.get("analysis_status")
        or config.get("analysis_status")
        or "exploratory_post_hoc_test_seen"
    )
    dataset = _dataset_meta(
        config,
        path=split_path,
        dataset_id="secvul-split-v1",
        split_id=str(config.get("split_id") or "secvul-split-v1"),
        unit_count=len(split_index),
        group_count=None,
        label_counts={
            "vulnerable": sum(1 for sample in split_index.values() if sample.get("is_vulnerable") is True),
            "non_vulnerable": sum(1 for sample in split_index.values() if sample.get("is_vulnerable") is False),
        },
    )
    run_id = _new_run_id(config)
    records: list[dict[str, Any]] = []
    for idx in sorted(split_index):
        sample = split_index[idx]
        first_item = first_by_idx.get(idx)
        first = first_item[1] if first_item else None
        verify_item = verify_by_idx.get(idx)
        verify = verify_item[1] if verify_item else None
        first_status = _static_status(first) if first is not None else "not_run"
        first_validation = pick(first, "validation") if first is not None else None
        if isinstance(first_validation, Mapping) and first_validation.get("schema_valid") is False:
            first_status = "schema_invalid"
        first_pred = None
        if first is not None and first_status == "ok":
            first_pred = as_bool(pick(first, "parsed.is_vulnerable"))
            if first_pred is None:
                first_status = "schema_invalid"
        first_cost = None
        first_usage = None
        first_prompt_sha = None
        first_digest = None
        if first is not None:
            first_cost_obj = _normalize_cost(first, "llm", config)
            first_cost = first_cost_obj.get("usd") if first_cost_obj else None
            first_usage = _normalize_usage(first)
            first_prompt_sha = first_str(first, "prompt_sha256", "request.body_sha256")
            first_digest = _safe_raw_digest(first)
        verifier_verdict = "not_requested"
        verifier_status = "not_requested"
        verifier_evidence_check = None
        verifier_cost = None
        verifier_usage = None
        verifier_prompt_sha = None
        verifier_digest = None
        rationale = None
        claim_sha = None
        rebuttal_type = None
        fail_closed = False
        post_status = first_status
        post_pred = None
        if first_status == "ok" and first_pred is True:
            if verify is None:
                verifier_status = "missing"
                verifier_verdict = "invalid"
                post_status = "ok"
                post_pred = False
                fail_closed = True
            else:
                verifier_status = _static_status(verify)
                validation = pick(verify, "validation")
                verdict = None
                if isinstance(validation, Mapping):
                    verdict = validation.get("verdict")
                    verifier_evidence_check = validation.get("evidence_check")
                    rebuttal_type = validation.get("rebuttal_type")
                    if validation.get("schema_valid") is False:
                        verifier_status = "schema_invalid"
                if verdict is None:
                    verdict = pick(verify, "parsed.verdict")
                verifier_verdict = str(verdict) if verdict in ("sustain", "retract") else "invalid"
                if verifier_status == "ok" and verifier_verdict in ("sustain", "retract"):
                    post_status = "ok"
                    post_pred = verifier_verdict == "sustain"
                else:
                    verifier_verdict = "invalid"
                    post_status = "ok"
                    post_pred = False
                    fail_closed = True
                verifier_cost_obj = _normalize_cost(verify, "llm", config)
                verifier_cost = verifier_cost_obj.get("usd") if verifier_cost_obj else None
                verifier_usage = _normalize_usage(verify)
                verifier_prompt_sha = first_str(verify, "prompt_sha256", "request.body_sha256")
                verifier_digest = _safe_raw_digest(verify)
                rationale = first_str(verify, "parsed.reason", "parsed.rationale")
                claim = pick(verify, "claim")
                if isinstance(claim, Mapping):
                    claim_sha = first_str(claim, "claim_sha256")
        elif first_status == "ok" and first_pred is False:
            post_status = "ok"
            post_pred = False
        retracted = bool(
            first_pred is True
            and verifier_verdict == "retract"
            and post_pred is False
            and first_status == "ok"
        )
        y_true = sample.get("is_vulnerable")
        if not isinstance(y_true, bool):
            raise ExtensionError(f"{split_path}: sample {idx} has non-boolean is_vulnerable")
        source_sha = sample.get("hash") if isinstance(sample.get("hash"), str) else None
        if source_sha is not None and len(source_sha) != 64:
            source_sha = None
        provenance_path = verify_path if verify is not None and first_pred is True else first_pass_path
        provenance_index = (
            verify_item[0] if verify is not None and first_pred is True else (first_item[0] if first_item else None)
        )
        provenance = _provenance(
            raw_path=provenance_path,
            raw_sha=sha256_file(provenance_path),
            record_index=provenance_index,
            note="copied from producer raw; post-verification prediction recomputed by fail-closed rule",
        )
        cost = None
        if verifier_cost is not None or verifier_usage is not None:
            cost = {
                "usd": verifier_cost,
                "wall_s": as_number(pick(verify or {}, "response.wall_seconds", "wall_seconds")),
                "cpu_s": None,
                "peak_rss_mb": None,
                "currency": "USD",
                "cost_basis": "api_price" if verifier_cost is not None else "unknown",
                "pricing_snapshot": config.get("pricing_snapshot"),
                "note": "verifier request only; first-pass cost is in extensions.retraction.first_pass_cost_usd",
            }
        records.append(
            _base_record(
                run_id=run_id,
                tier="A",
                track="secvuleval",
                task="detection",
                unit_id=f"secvul:det:{idx}",
                cluster_id=str(sample.get("project") or "unknown"),
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="function",
                    prompt_sha256=verifier_prompt_sha or first_prompt_sha,
                    context_mode="tool_evidence",
                    sanitized=True,
                    sanitizer_version=config.get("sanitizer_version"),
                    source_sha256=source_sha,
                    evidence_sha256=claim_sha,
                ),
                label={
                    "y_true": y_true,
                    "cwe": normalize_cwe_list(sample.get("cwe_list")),
                    "label_source": "secvuleval",
                    "label_note": None,
                },
                status=post_status,
                provenance=provenance,
                y_pred=post_pred,
                confidence=as_number(pick(verify or {}, "parsed.confidence", "validation.confidence")),
                rationale=rationale,
                raw_output_sha256=verifier_digest,
                usage=verifier_usage,
                cost=cost,
                error=_normalize_error(verify, post_status) if verify is not None and post_status != "ok" else None,
                extensions={
                    "task_design": "evidence_retraction",
                    "retraction": {
                        "first_pass_run": _display_path(first_pass_path),
                        "verifier_run": _display_path(verify_path),
                        "first_pass_model": first_model,
                        "verifier_model": verifier_model_id,
                        "first_pass_y_pred": first_pred,
                        "first_pass_status": first_status,
                        "verifier_status": verifier_status,
                        "verifier_verdict": verifier_verdict,
                        "verifier_evidence_check": verifier_evidence_check,
                        "retracted": retracted,
                        "fail_closed": fail_closed,
                        "analysis_status": analysis_status,
                        "claim_sha256": claim_sha,
                        "rebuttal_type": rebuttal_type,
                        "first_pass_cost_usd": first_cost,
                        "verifier_cost_usd": verifier_cost,
                        "raw_record_sha256": verifier_digest or first_digest,
                        "notes": None,
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="A",
        track="secvuleval",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(split_index),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[
            "post-hoc evidence retraction on the frozen 160 detection test; analysis_status=exploratory_post_hoc_test_seen",
            "positive first-pass claims only; negatives unchanged; invalid verifier output is fail-closed (retract)",
            "copied from producer raw; post prediction recomputed, not re-run",
        ],
    )


# ---------------------------------------------------------------------------
# Enhanced dynamic (three-mode dynamic run)
# ---------------------------------------------------------------------------


def import_enhanced_dynamic(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    unit_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "enhanced_dynamic"
    unit_index = juliet_unit_index(unit_map_path)
    split_filter = str(config.get("split") or "test")
    units = {
        meta["unit_id"]: meta
        for meta in unit_index.values()
        if meta.get("split") == split_filter
    }
    if not units:
        raise ExtensionError("no units selected from the unit map")
    raw_records = load_records(raw_path)
    raw_by_unit: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        upstream = first_str(raw, "unit_id", "sample_id", "id")
        if not upstream:
            raise ExtensionError(f"enhanced dynamic record {index + 1}: missing unit_id")
        meta = unit_index.get(str(upstream))
        if meta is None:
            raise ExtensionError(f"enhanced dynamic record {index + 1}: unit {upstream!r} not in unit map")
        canonical = meta["unit_id"]
        if canonical in raw_by_unit:
            raise ExtensionError(f"enhanced dynamic duplicate unit {canonical!r}")
        raw_by_unit[canonical] = (index, raw)
    extra = set(raw_by_unit) - set(units)
    if extra:
        raise ExtensionError(f"enhanced dynamic raw has {len(extra)} unit(s) outside split {split_filter}")
    dataset = _dataset_meta(
        config,
        path=unit_map_path,
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id=str(config.get("split_id") or "juliet-cwe401-v1.3-subset-v1"),
        unit_count=len(units),
        group_count=len({meta["group_id"] for meta in units.values()}),
        label_counts={
            "bad": sum(1 for meta in units.values() if meta["label"] == "bad"),
            "good": sum(1 for meta in units.values() if meta["label"] == "good"),
        },
    )
    method = config.get("method")
    if not isinstance(method, Mapping):
        method = {
            "method_id": "dynamic.enhanced.three_mode",
            "family": "dynamic",
            "name": "ASan/LSan + realloc-failure injection + LSan no-globals",
            "tool": {
                "name": "ASan/LSan enhanced harness",
                "version": "gcc 15.3.0 / LSan (three-mode)",
                "command_template": "gcc -fsanitize=address ...; LSan use_globals=0; --wrap=realloc",
                "rules": [],
                "license": "GPL-3.0-or-later (GCC), LLVM sanitizer runtime",
            },
        }
    else:
        method = json.loads(json.dumps(method))
    if not method.get("config_sha256"):
        method["config_sha256"] = sha256_text(stable_json(method))
    source_run_id = str(config.get("source_run_id") or raw_path.parent.name)
    run_id = _new_run_id(config)
    records: list[dict[str, Any]] = []
    for unit_id, meta in sorted(units.items()):
        item = raw_by_unit.get(unit_id)
        raw = item[1] if item else None
        record_index = item[0] if item else None
        source_sha = None
        if raw is not None:
            explicit_sha = first_str(raw, "source_sha256")
            if explicit_sha and len(explicit_sha) == 64:
                source_sha = explicit_sha
        decision = str(pick(raw, "decision", "y_pred", default="not_evaluable")) if raw is not None else "not_evaluable"
        if raw is not None and isinstance(raw.get("y_pred"), int):
            decision = "leak" if raw.get("y_pred") == 1 else "clean"
        modes = raw.get("modes") if raw is not None and isinstance(raw.get("modes"), Mapping) else {}
        evidence_modes = raw.get("evidence_modes") if raw is not None and isinstance(raw.get("evidence_modes"), list) else []
        primary_evidence = pick(raw, "primary_evidence") if raw is not None else None
        unobservable = bool(pick(raw, "unobservable_in_default", default=False)) if raw is not None else False
        conditionally = bool(pick(raw, "conditionally_observable", default=False)) if raw is not None else False
        failure_class = pick(raw, "failure_class") if raw is not None else None
        probe_executed = bool(
            raw is not None
            and all(
                isinstance(modes.get(mode), Mapping)
                and modes.get(mode, {}).get("timed_out") is False
                for mode in ("default", "realloc_fail", "nogobal")
                if isinstance(modes.get(mode), Mapping)
            )
            and isinstance(modes.get("default"), Mapping)
        )
        per_mode = {}
        raw_leaks = {}
        attributed = {}
        for mode in ("default", "realloc_fail", "nogobal"):
            value = modes.get(mode)
            if not isinstance(value, Mapping):
                continue
            per_mode[mode] = {
                "applicable": bool(value.get("applicable")),
                "decision": value.get("decision"),
                "attributed_bytes": value.get("attributed_bytes"),
                "raw_bytes": value.get("raw_bytes"),
                "timed_out": value.get("timed_out"),
            }
            raw_leaks[mode] = bool(value.get("leak_raw"))
            attributed[mode] = bool(value.get("leak_attributed"))
        if raw is None:
            status = "not_run"
            y_pred = None
            operational = None
            coverage = _unknown_coverage()
        elif decision == "leak":
            status = "ok"
            y_pred = True
            operational = True
            coverage = {
                "unit_executed": True,
                "target_function_entered": True,
                "line_coverage": None,
                "branch_coverage": None,
                "allocation_site_executed": None,
                "free_site_executed": None,
                "coverage_source": "none",
                "notes": "three-mode execution; no line/branch coverage instrumentation",
            }
        elif decision == "clean":
            status = "inconclusive"
            y_pred = None
            operational = False
            coverage = {
                "unit_executed": True,
                "target_function_entered": True,
                "line_coverage": None,
                "branch_coverage": None,
                "allocation_site_executed": None,
                "free_site_executed": None,
                "coverage_source": "none",
                "notes": "three-mode execution; clean without line/branch coverage is inconclusive, not TN",
            }
        else:
            status = "harness_error" if decision == "not_evaluable" else str(decision)
            y_pred = None
            operational = None
            coverage = _unknown_coverage()
        cost = None
        if raw is not None and as_number(raw.get("runtime_ms")) is not None:
            cost = {
                "usd": None,
                "wall_s": float(raw["runtime_ms"]) / 1000.0,
                "cpu_s": None,
                "peak_rss_mb": None,
                "currency": "USD",
                "cost_basis": "local_compute",
                "pricing_snapshot": None,
                "note": "unit runtime across three modes; local compute, USD not applicable",
            }
        provenance = _provenance(
            raw_path=raw_path,
            raw_sha=sha256_file(raw_path),
            record_index=record_index,
            note="copied from dynamic_enhanced results_units.jsonl; not re-run",
        )
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=unit_id,
                cluster_id=meta["family"],
                group_id=meta["group_id"],
                side=meta["label"],
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=None,
                    context_mode="none",
                    sanitized=False,
                    source_sha256=source_sha,
                ),
                label={
                    "y_true": meta["label"] == "bad",
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                status=status,
                provenance=provenance,
                y_pred=y_pred,
                confidence=None,
                rationale=None,
                raw_output_sha256=None,
                coverage=coverage,
                usage=None,
                cost=cost,
                error=_normalize_error(raw or {}, status),
                extensions={
                    "task_design": "enhanced_dynamic",
                    "dynamic_enhanced": {
                        "source_run_id": source_run_id,
                        "decision": decision,
                        "evidence_modes": evidence_modes,
                        "primary_evidence": primary_evidence,
                        "unobservable_in_default": unobservable,
                        "conditionally_observable": conditionally,
                        "probe_executed": probe_executed,
                        "coverage_proxy": "three_mode_execution_no_line_coverage",
                        "per_mode": per_mode,
                        "raw_leak_counts": raw_leaks,
                        "attributed_leak_counts": attributed,
                        "operational_y_pred": operational,
                        "protocol_clean_status": "inconclusive" if decision == "clean" else None,
                        "failure_class": failure_class,
                        "raw_record_sha256": _safe_raw_digest(raw) if raw is not None else None,
                        "notes": "protocol clean is inconclusive because no line coverage; operational view is source-only",
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(units),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[
            "enhanced dynamic three-mode run; source verdicts 70 leak / 70 clean",
            "canonical protocol: clean without line coverage is inconclusive, not TN; operational view is separate",
            "copied from producer raw; not re-run",
        ],
        validate_kwargs={"unit_map": str(unit_map_path)},
    )


# ---------------------------------------------------------------------------
# Hybrid guided by enhanced dynamic evidence
# ---------------------------------------------------------------------------


def import_hybrid_enhanced_dynamic(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    unit_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "hybrid_enhanced_dynamic"
    model_filter = str(config.get("model_filter") or "")
    if not model_filter:
        raise ExtensionError("config.model_filter is required for hybrid_enhanced_dynamic")
    unit_index = juliet_unit_index(unit_map_path)
    units = {
        meta["unit_id"]: meta
        for meta in unit_index.values()
        if meta.get("split") == "test"
    }
    raw_records = load_records(raw_path)
    raw_by_unit: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        if str(raw.get("model")) != model_filter:
            continue
        upstream = first_str(raw, "unit_id", "sample_id", "id")
        if not upstream:
            raise ExtensionError(f"hybrid record {index + 1}: missing unit_id")
        meta = unit_index.get(str(upstream))
        if meta is None:
            raise ExtensionError(f"hybrid record {index + 1}: unit {upstream!r} not in unit map")
        canonical = meta["unit_id"]
        if canonical in raw_by_unit:
            raise ExtensionError(f"hybrid duplicate unit {canonical!r}")
        raw_by_unit[canonical] = (index, raw)
    if set(raw_by_unit) != set(units):
        raise ExtensionError(
            f"hybrid model {model_filter} covers {len(raw_by_unit)}/{len(units)} test units"
        )
    dataset = _dataset_meta(
        config,
        path=unit_map_path,
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id="juliet-cwe401-v1.3-subset-v1",
        unit_count=len(units),
        group_count=len({meta["group_id"] for meta in units.values()}),
        label_counts={"bad": 70, "good": 70},
    )
    method = config.get("method")
    if not isinstance(method, Mapping):
        method = {
            "method_id": f"hybrid.enhanced_dynamic.{model_filter}",
            "family": "hybrid",
            "name": f"Enhanced-dynamic-guided LLM ({model_filter})",
            "strategy": "enhanced-dynamic-guided",
            "model": {
                "model_id": "deepseek-v4.1-flash" if model_filter == "deepseek" else "mimo-v2.6-flash",
                "family": model_filter,
                "provider": "opencode-go",
                "endpoint": "https://opencode.ai/zen/go/v1/chat/completions",
                "version": None,
                "decoding": {"temperature": 0.0, "max_tokens": 2048},
            },
        }
    else:
        method = json.loads(json.dumps(method))
    if not method.get("config_sha256"):
        method["config_sha256"] = sha256_text(stable_json(method))
    run_id = _new_run_id(config)
    source_run_id = str(config.get("source_run_id") or "enhanced_dynamic_v1")
    records: list[dict[str, Any]] = []
    for unit_id, meta in sorted(units.items()):
        item = raw_by_unit[unit_id]
        raw = item[1]
        status = normalize_status(raw.get("status"), default="ok") or "ok"
        if raw.get("schema_error"):
            status = "schema_invalid"
        y_pred = as_bool(raw.get("y_pred"))
        if status == "ok" and y_pred is None:
            status = "schema_invalid"
        if status != "ok":
            y_pred = None
        label = as_bool(raw.get("y_true"))
        if label is None:
            label = meta["label"] == "bad"
        cost = _normalize_cost(raw, "llm", config)
        usage = _normalize_usage(raw)
        provenance = _provenance(
            raw_path=raw_path,
            raw_sha=sha256_file(raw_path),
            record_index=item[0],
            note="copied from hybrid_dynamic_enhanced results; not re-run",
        )
        prompt = raw.get("prompt") if isinstance(raw.get("prompt"), Mapping) else {}
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=unit_id,
                cluster_id=meta["family"],
                group_id=meta["group_id"],
                side=meta["label"],
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=first_str(prompt, "prompt_sha256"),
                    context_mode="dynamic_trace",
                    sanitized=True,
                    source_sha256=None,
                    evidence_sha256=first_str(raw, "evidence_sha256"),
                ),
                label={
                    "y_true": label,
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                status=status,
                provenance=provenance,
                y_pred=y_pred,
                confidence=as_number(raw.get("confidence")),
                rationale=first_str(raw, "reason"),
                raw_output_sha256=None,
                usage=usage,
                cost=cost,
                error=_normalize_error(raw, status) if status != "ok" else None,
                extensions={
                    "task_design": "hybrid_enhanced_dynamic",
                    "hybrid_dynamic_enhanced": {
                        "source_run_id": source_run_id,
                        "evidence_outcome": raw.get("evidence_outcome"),
                        "evidence_primary_mode": raw.get("evidence_primary_mode"),
                        "old_dynamic_outcome": raw.get("old_dynamic_outcome"),
                        "tool_verdict": raw.get("tool_verdict"),
                        "prompt_version": first_str(prompt, "prompt_version") or "unknown",
                        "evidence_sha256": first_str(raw, "evidence_sha256"),
                        "prompt_sha256": first_str(prompt, "prompt_sha256"),
                        "model": model_filter,
                        "method": raw.get("method"),
                        "notes": None,
                    },
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(units),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[
            "LLM guided by three-mode enhanced dynamic evidence; real 140-unit run",
            "tool baseline is 140/140; compare LLM to frozen hybrid_v2 direct/combined only descriptively",
            "copied from producer raw; not re-run",
        ],
        validate_kwargs={"unit_map": str(unit_map_path)},
    )


# ---------------------------------------------------------------------------
# Single-run publication
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Next-iteration producers (2026-11-22)
# ---------------------------------------------------------------------------

_ALERT_CONDITION_KEYS = {
    "direct": ("direct_pred", "model"),
    "triage_v1": ("triage_keep", "model"),
    "triage_v2": ("triage_keep", "model"),
    "text_rule": ("rule_text_consistency", "rule"),
    "verified": ("triage_verified", "verifier"),
    "cascade": ("hybrid_cascade_direct", "cascade"),
    "zero_cost_never_freed": ("query_never_only", "codeql"),
    "zero_cost_drop_may_cpp": ("drop_may_cpp", "codeql"),
}

_ALERT_METHOD_FAMILY = {
    "direct": "llm",
    "triage_v1": "llm",
    "triage_v2": "llm",
    "text_rule": "hybrid",
    "verified": "hybrid",
    "cascade": "hybrid",
    "zero_cost_never_freed": "static",
    "zero_cost_drop_may_cpp": "static",
}


def _next_usage_with_latency(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    usage = _normalize_usage(raw)
    latency = as_number(pick(raw, "wall_seconds", "response.request_latency_seconds"))
    if usage is None and latency is None:
        return None
    result = dict(usage or {})
    if result.get("latency_ms") is None and latency is not None:
        result["latency_ms"] = latency * 1000.0
    return result


def _next_pair_usage_cost(raw: Mapping[str, Any], config: Mapping[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    response = raw.get("response") if isinstance(raw.get("response"), Mapping) else {}
    cost_obj = response.get("cost") if isinstance(response.get("cost"), Mapping) else {}
    attempts = response.get("attempts")
    latency = as_number(response.get("request_latency_seconds"))
    usage = {
        "prompt_tokens": as_int(cost_obj.get("prompt_tokens")),
        "completion_tokens": as_int(cost_obj.get("completion_tokens")),
        "cached_prompt_tokens": as_int(cost_obj.get("cached_prompt_tokens")),
        "reasoning_tokens": as_int(pick(response, "response_meta.reasoning_tokens")),
        "latency_ms": latency * 1000.0 if latency is not None else None,
        "api_attempts": len(attempts) if isinstance(attempts, list) and attempts else None,
    }
    if not any(value is not None for value in usage.values()):
        usage = None
    usd = as_number(cost_obj.get("cost_usd"))
    cost = None
    if usd is not None or latency is not None:
        cost = {
            "usd": usd,
            "wall_s": latency,
            "cpu_s": None,
            "peak_rss_mb": None,
            "currency": "USD",
            "cost_basis": "api_price" if usd is not None else "unknown",
            "pricing_snapshot": config.get("pricing_snapshot"),
            "note": "configured list price; not an invoice",
        }
    return usage, cost


def _merge_usage(first: Mapping[str, Any] | None, second: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if first is None and second is None:
        return None
    result: dict[str, Any] = {}
    for key in ("prompt_tokens", "completion_tokens", "cached_prompt_tokens", "reasoning_tokens"):
        values = [
            value
            for value in (
                (first or {}).get(key),
                (second or {}).get(key),
            )
            if isinstance(value, int) and not isinstance(value, bool)
        ]
        result[key] = sum(values) if values else None
    latencies = [
        float(value)
        for value in ((first or {}).get("latency_ms"), (second or {}).get("latency_ms"))
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    result["latency_ms"] = sum(latencies) if latencies else None
    attempts = [
        value
        for value in ((first or {}).get("api_attempts"), (second or {}).get("api_attempts"))
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    result["api_attempts"] = sum(attempts) if attempts else None
    return result


def _merge_cost(first: Mapping[str, Any] | None, second: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if first is None and second is None:
        return None
    usd_values = [
        float(value)
        for value in ((first or {}).get("usd"), (second or {}).get("usd"))
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    wall_values = [
        float(value)
        for value in ((first or {}).get("wall_s"), (second or {}).get("wall_s"))
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    return {
        "usd": sum(usd_values) if usd_values else None,
        "wall_s": sum(wall_values) if wall_values else None,
        "cpu_s": None,
        "peak_rss_mb": None,
        "currency": "USD",
        "cost_basis": "api_price" if usd_values else "unknown",
        "pricing_snapshot": (first or second or {}).get("pricing_snapshot"),
        "note": "pipeline sum of the recorded calls; configured list price",
    }


def import_alert_triage(
    config: Mapping[str, Any],
    *,
    run_dir: Path,
    unit_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "codeql_alert_triage"
    condition = str(config.get("condition") or "")
    if condition not in _ALERT_CONDITION_KEYS:
        raise ExtensionError(f"unknown codeql_alert_triage condition {condition!r}")
    condition_key, decision_source = _ALERT_CONDITION_KEYS[condition]
    method = _method_from_config(config)
    if method.get("family") != _ALERT_METHOD_FAMILY[condition]:
        raise ExtensionError(
            f"{condition} requires config.method.family={_ALERT_METHOD_FAMILY[condition]}"
        )
    split_filter = str(config.get("split") or "test")
    unit_index = juliet_unit_index(unit_map_path)
    units: dict[str, dict[str, Any]] = {}
    for meta in unit_index.values():
        if split_filter and meta.get("split") != split_filter:
            continue
        units[meta["unit_id"]] = meta
    if len(units) != 140:
        raise ExtensionError(f"expected 140 test units, got {len(units)}")
    dataset = _dataset_meta(
        config,
        path=unit_map_path,
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id=f"juliet-cwe401-v1.3-subset-v1/{split_filter}",
        unit_count=len(units),
        group_count=len({meta["group_id"] for meta in units.values()}),
        label_counts={
            "bad": sum(1 for meta in units.values() if meta["label"] == "bad"),
            "good": sum(1 for meta in units.values() if meta["label"] == "good"),
        },
    )

    sys.path.insert(0, str(project_root() / "codeql_triage"))
    try:
        import analyze as codeql_analyze  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise ExtensionError(f"cannot import codeql_triage/analyze.py: {exc}") from exc
    rows = codeql_analyze.build_rows(run_dir)
    rows_by_unit = {str(row["unit_id"]): row for row in rows}
    if set(rows_by_unit) != {meta["upstream_unit_id"] for meta in units.values()}:
        raise ExtensionError("CodeQL triage rows do not match the frozen test-140 unit set")

    def load_raw(name: str) -> dict[str, Mapping[str, Any]]:
        path = run_dir / name
        if not path.exists():
            return {}
        return {str(record.get("unit_id")): record for record in load_records(path)}

    raw_direct = load_raw("results_direct.jsonl")
    raw_triage = load_raw("results_triage.jsonl")
    raw_verify = load_raw("verify/results_verify.jsonl")
    raw_sha = sha256_file(run_dir / "manifest.json") if (run_dir / "manifest.json").exists() else None
    run_id = _new_run_id(config)
    records: list[dict[str, Any]] = []
    for unit_id in sorted(units, key=lambda value: units[value]["upstream_unit_id"]):
        meta = units[unit_id]
        upstream = meta["upstream_unit_id"]
        row = rows_by_unit[upstream]
        y_pred = bool(row[condition_key])
        raw_for_usage: Mapping[str, Any] | None = None
        if condition in ("direct",):
            raw_for_usage = raw_direct.get(upstream)
        elif condition in ("triage_v1", "triage_v2"):
            raw_for_usage = raw_triage.get(upstream)
        usage = _next_usage_with_latency(raw_for_usage) if raw_for_usage else None
        cost_block = _normalize_cost(raw_for_usage, "llm", config) if raw_for_usage else None
        if condition == "verified":
            verify_raw = raw_verify.get(upstream)
            if verify_raw is not None:
                verify_usage, verify_cost = _next_usage_with_latency(verify_raw), _normalize_cost(verify_raw, "llm", config)
                usage = _merge_usage(usage, verify_usage)
                cost_block = _merge_cost(cost_block, verify_cost)
        if condition in ("text_rule", "cascade", "zero_cost_never_freed", "zero_cost_drop_may_cpp"):
            usage = None
            cost_block = None
        raw_triage_row = raw_triage.get(upstream) or {}
        raw_direct_row = raw_direct.get(upstream) or {}
        queries = sorted(
            (pick(raw_direct_row, "unit.codeql_by_query", default={}) or {}).keys()
        )
        reparsed = condition in ("triage_v1", "triage_v2") and not bool(row["raw_triage_valid"])
        notes = {
            "direct": "fresh direct replication on the same frozen test-140 units",
            "triage_v1": "v1 triage prompt; kept unless the model says false_positive",
            "triage_v2": "v2 triage prompt; two absent-alert 'uncertain' answers were re-parsed from stored content without a new API call",
            "text_rule": "deterministic text-consistency rule applied to the v2 triage text; no new API call",
            "verified": "grounded verifier applied to v2 alert decisions; verifier sees the first-pass JSON",
            "cascade": "verified alert decision, direct prediction on no-alert units",
            "zero_cost_never_freed": "CodeQL never-freed query only; zero model cost",
            "zero_cost_drop_may_cpp": "drop C++ may-not-be-freed alerts unless a never-freed alert also fires; zero model cost",
        }[condition]
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=unit_id,
                cluster_id=meta["family"],
                group_id=meta["group_id"],
                side=meta["label"],
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=first_str(raw_for_usage or {}, "prompt_sha256"),
                    context_mode="tool_evidence" if condition not in ("direct",) else "none",
                    sanitized=True,
                    sanitizer_version="juliet-deidentified-view-v1",
                ),
                label={
                    "y_true": meta["label"] == "bad",
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                status="ok",
                provenance=_provenance(
                    raw_path=run_dir,
                    raw_sha=raw_sha or "",
                    record_index=None,
                    note=f"{condition}: copied from producer run; decision recomputed with the producer's own build_rows; not re-run",
                ),
                y_pred=y_pred,
                confidence=as_number(pick(raw_for_usage or {}, "parsed.confidence")) if condition in ("direct", "triage_v1", "triage_v2") else None,
                rationale=first_str(raw_for_usage or {}, "parsed.reason") if condition in ("direct", "triage_v1", "triage_v2") else None,
                raw_output_sha256=sha256_text(str(raw_for_usage.get("content"))) if raw_for_usage and raw_for_usage.get("content") else None,
                usage=usage,
                cost=cost_block,
                extensions={
                    "task_design": design,
                    "condition": condition,
                    "codeql_alert": bool(row["codeql_alert"]),
                    "codeql_status": row.get("codeql_status"),
                    "codeql_queries": queries,
                    "alert_verdict": row.get("alert_verdict"),
                    "leak_present": row.get("leak_present") if isinstance(row.get("leak_present"), bool) else None,
                    "triage_valid": bool(row["triage_valid"]),
                    "reparsed_without_api_call": reparsed,
                    "verify_valid": bool(row["verify_valid"]),
                    "verifier_model": "mimo-v2.6-flash" if row["verify_valid"] else None,
                    "decision_source": decision_source,
                    "prompt_version": first_str(raw_for_usage or {}, "prompt_version"),
                    "verifier_prompt_version": first_str(raw_verify.get(upstream) or {}, "prompt_version"),
                    "notes": notes,
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(units),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[f"CodeQL alert triage condition: {condition}", "decision recomputed from stored producer output; not re-run"],
        validate_kwargs={"unit_map": str(unit_map_path)},
    )


def import_conservative_verification(
    config: Mapping[str, Any],
    *,
    first_pass_path: Path,
    decisions_path: Path,
    verifier_results_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "conservative_verification"
    arm = str(config.get("arm") or "")
    if arm not in ("deepseek_self", "deepseek_cross", "mimo_self", "mimo_cross"):
        raise ExtensionError(f"unknown conservative arm {arm!r}")
    method = _method_from_config(config)
    if method.get("family") != "hybrid":
        raise ExtensionError("conservative_verification requires config.method.family=hybrid")
    first_records = load_records(first_pass_path)
    if len(first_records) != 160:
        raise ExtensionError(f"first-pass run must have 160 records, got {len(first_records)}")
    decisions = {
        int(record["idx"]): record
        for record in load_records(decisions_path)
        if str(record.get("arm")) == arm
    }
    verifier_results = {
        int(record["idx"]): record
        for record in load_records(verifier_results_path)
        if record.get("idx") is not None
    }
    split_path = _config_path(config, "split_path") or (project_root() / "splits" / "test_detection_160.json")
    dataset = _dataset_meta(
        config,
        path=split_path,
        dataset_id="secvul-split-v1",
        split_id="secvul-split-v1/test",
        unit_count=160,
        group_count=40,
        label_counts={"vulnerable": 128, "non_vulnerable": 32},
    )
    run_id = _new_run_id(config)
    records: list[dict[str, Any]] = []
    for first in first_records:
        unit_id = str(first["unit_id"])
        idx = int(unit_id.rsplit(":", 1)[1])
        label = as_bool((first.get("label") or {}).get("y_true"))
        first_status = str(first.get("status"))
        first_pred = as_bool((first.get("prediction") or {}).get("y_pred")) if first_status == "ok" else None
        decision = decisions.get(idx)
        verifier = verifier_results.get(idx)
        verifier_status = "not_sent"
        assessment = None
        rebuttal_kind = None
        decision_name = "keep"
        decision_reason = "negative_unchanged" if first_pred is False else "no_verifier_record"
        retract = False
        grounded = None
        confidence = None
        if first_status == "ok" and first_pred is True and decision is not None:
            verifier_status = str(decision.get("status") or "ok")
            assessment = decision.get("assessment")
            rebuttal_kind = decision.get("rebuttal_kind")
            retract = bool((decision.get("decision") or {}).get("retract"))
            decision_name = "retract" if retract else "keep"
            decision_reason = str((decision.get("decision") or {}).get("reason") or "")
            grounded = (decision.get("audit") or {}).get("rebuttal_grounded")
            confidence = as_number(decision.get("confidence"))
        final_status = first_status
        final_pred = first_pred
        if first_status == "ok" and first_pred is True and decision is not None:
            final_pred = False if retract else bool(first_pred)
        usage = first.get("usage")
        cost = first.get("cost")
        if verifier is not None:
            usage = _merge_usage(usage, _normalize_usage(verifier))
            cost = _merge_cost(cost, _normalize_cost(verifier, "llm", config))
        records.append(
            _base_record(
                run_id=run_id,
                tier="A",
                track="secvuleval",
                task="detection",
                unit_id=unit_id,
                cluster_id=str(first.get("cluster_id")),
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="function",
                    prompt_sha256=first_str(verifier or {}, "prompt_sha256"),
                    context_mode="none",
                    sanitized=True,
                    sanitizer_version="verifier-conservative-2026-11-22",
                ),
                label={
                    "y_true": bool(label),
                    "cwe": list((first.get("label") or {}).get("cwe") or []),
                    "label_source": "secvuleval",
                    "label_note": None,
                },
                status=final_status,
                provenance=_provenance(
                    raw_path=decisions_path,
                    raw_sha=sha256_file(decisions_path),
                    record_index=None,
                    note=f"{arm}: first pass copied from canonical run; verifier decision joined by idx; not re-run",
                ),
                y_pred=final_pred if final_status == "ok" else None,
                confidence=confidence,
                rationale=first_str(decision or {}, "reason") if decision else None,
                usage=usage,
                cost=cost,
                error=_normalize_error(verifier or {}, final_status) if final_status != "ok" else None,
                extensions={
                    "task_design": design,
                    "arm": arm,
                    "claim_model": str(config.get("claim_model") or arm.split("_")[0]),
                    "verifier_model": str(config.get("verifier_model") or arm.split("_")[-1]),
                    "first_pass_status": first_status if first_status in ("ok", "schema_invalid", "api_error", "not_run") else "not_run",
                    "first_pass_y_pred": first_pred,
                    "verifier_status": verifier_status,
                    "assessment": assessment if assessment in ("supported", "unsupported", "insufficient") else None,
                    "rebuttal_kind": rebuttal_kind,
                    "decision": decision_name,
                    "decision_reason": decision_reason,
                    "retract": retract,
                    "grounded": grounded,
                    "confidence": confidence,
                    "analysis_status": "exploratory_post_hoc_test_seen",
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="A",
        track="secvuleval",
        dataset=dataset,
        method=method,
        records=records,
        planned=160,
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[f"conservative verifier arm: {arm}", "exploratory post hoc; test already seen by the first pass"],
    )


def import_diff_pair(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    pair_path: Path,
    position_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "diff_guided_pair"
    method = _method_from_config(config)
    if method.get("family") != "llm":
        raise ExtensionError("diff_guided_pair requires config.method.family=llm")
    condition = str(config.get("condition") or "")
    order = str(config.get("order") or "")
    if condition not in ("diff", "ctrl"):
        raise ExtensionError("config.condition must be diff or ctrl")
    if order not in ("fwd", "rev"):
        raise ExtensionError("config.order must be fwd or rev")
    pairs = pair_split_index(pair_path)
    raw_records = load_records(raw_path)
    raw_sha = sha256_file(raw_path)
    raw_by_pair: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for index, raw in enumerate(raw_records):
        pair_id = first_str(raw, "pair_id")
        if not pair_id:
            raise ExtensionError(f"diff raw record {index + 1}: missing pair_id")
        if pair_id in raw_by_pair:
            raise ExtensionError(f"diff raw has duplicate pair_id {pair_id!r}")
        raw_by_pair[pair_id] = (index, raw)
    position_data = json.loads(position_map_path.read_text(encoding="utf-8"))
    assignments = position_data.get("assignments") or {}
    dataset = _dataset_meta(
        config,
        path=pair_path,
        dataset_id="secvul-split-v1",
        split_id="secvul-split-v1/test-pairs",
        unit_count=2 * len(pairs),
        group_count=len(pairs),
        label_counts={"vulnerable": len(pairs), "fixed": len(pairs)},
    )
    run_id = _new_run_id(config)
    records: list[dict[str, Any]] = []
    for pair_id in sorted(pairs):
        pair = pairs[pair_id]
        item = raw_by_pair.get(pair_id)
        raw = item[1] if item else None
        assignment = assignments.get(pair_id) or {}
        vulnerable_slot = str(assignment.get("vulnerable_slot") or "")
        fixed_slot = str(assignment.get("fixed_slot") or "")
        if {vulnerable_slot, fixed_slot} != {"A", "B"}:
            raise ExtensionError(f"{pair_id}: position map must assign one vulnerable and one fixed slot")
        pm = {"A": "vulnerable" if vulnerable_slot == "A" else "fixed", "B": "vulnerable" if vulnerable_slot == "B" else "fixed"}
        if raw is None:
            choice = None
            status = "not_run"
            selected_slots: list[str] = []
            confidence = None
            rationale = None
            usage = cost = None
            prompt_sha = diff_sha = None
            changes_first = False
            semantic_changes = 0
            security_relevant = 0
        else:
            choice = _normalize_open_choice(pick(raw, "parsed.vulnerable_version", "parsed.open_choice", "vulnerable_version"))
            status = _status_for_raw(raw, parsed_valid=choice is not None)
            selected_slots = {"A": ["A"], "B": ["B"], "both": ["A", "B"], "neither": []}.get(choice or "", [])
            confidence = as_number(pick(raw, "parsed.confidence"))
            rationale = first_str(raw, "parsed.rationale")
            usage, cost = _next_pair_usage_cost(raw, config)
            prompt_sha = first_str(raw, "prompt_sha256")
            diff_sha = first_str(raw, "prompt.diff_sha256")
            changes_first = bool(pick(raw, "validation.changes.changes_first", default=False))
            parsed_changes = pick(raw, "parsed.semantic_changes", default=[])
            semantic_changes = len(parsed_changes) if isinstance(parsed_changes, list) else 0
            security_relevant = sum(
                1 for item_change in (parsed_changes or [])
                if isinstance(item_change, Mapping) and item_change.get("security_relevant") is True
            )
        flagged_sides = {pm[slot] for slot in selected_slots if slot in pm}
        version_chars = pick(raw or {}, "prompt.version_chars", default={}) or {}
        lengths = {
            "vulnerable": as_int(version_chars.get(vulnerable_slot)) if isinstance(version_chars, Mapping) else None,
            "fixed": as_int(version_chars.get(fixed_slot)) if isinstance(version_chars, Mapping) else None,
        }
        if lengths["vulnerable"] is None or lengths["fixed"] is None:
            lengths = {"vulnerable": None, "fixed": None}
            longer = None
        elif lengths["vulnerable"] > lengths["fixed"]:
            longer = "vulnerable"
        elif lengths["fixed"] > lengths["vulnerable"]:
            longer = "fixed"
        else:
            longer = "tie"
        project = first_str(pair.get("vulnerable") or {}, "project")
        for side in ("vulnerable", "fixed"):
            y_true = side == "vulnerable"
            y_pred = None
            if status == "ok":
                y_pred = side in flagged_sides
            records.append(
                _base_record(
                    run_id=run_id,
                    tier="A",
                    track="secvuleval",
                    task="pair_detection",
                    unit_id=canonical_pair_unit_id(pair_id, side),
                    cluster_id=pair_id,
                    group_id=pair_id,
                    side=side,
                    dataset=dataset,
                    method=method,
                    input_block=_input_block(
                        view="pair",
                        prompt_sha256=prompt_sha,
                        context_mode="none",
                        sanitized=True,
                        sanitizer_version="pair-diff-2026-11-22.1",
                    ),
                    label={
                        "y_true": y_true,
                        "cwe": normalize_cwe_list((pair.get("vulnerable") or {}).get("cwe_list")) if side == "vulnerable" else [],
                        "label_source": "secvuleval",
                        "label_note": None,
                    },
                    status=status,
                    provenance=_provenance(
                        raw_path=raw_path,
                        raw_sha=raw_sha,
                        record_index=item[0] if item else None,
                        note=f"{condition}_{order}: one 4-way response encoded as two side records; not re-run",
                    ),
                    y_pred=y_pred,
                    confidence=confidence,
                    rationale=rationale,
                    usage=usage if side == "vulnerable" else None,
                    cost=cost if side == "vulnerable" else None,
                    extensions={
                        "pair_design": design,
                        "condition": condition,
                        "presentation_order": order,
                        "open_choice": choice,
                        "selected_slots": selected_slots,
                        "position_map": pm,
                        "change_mode": "diff" if condition == "diff" else "placeholder",
                        "changes_first": changes_first,
                        "semantic_changes": semantic_changes,
                        "security_relevant_changes": security_relevant,
                        "diff_sha256": diff_sha,
                        "prompt_sha256": prompt_sha,
                        "pair_project": project,
                        "length_chars": lengths,
                        "longer_side": longer,
                        "confidence": confidence,
                        "rationale": rationale,
                        "notes": "usage/cost recorded once on the vulnerable side; one request per pair",
                    },
                )
            )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="A",
        track="secvuleval",
        dataset=dataset,
        method=method,
        records=records,
        planned=2 * len(pairs),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[f"diff-guided pair: {condition}/{order}", "one request per pair encoded as two side records; not re-run"],
    )


def import_coverage_dynamic(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    unit_map_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "coverage_instrumented_dynamic"
    method = _method_from_config(config)
    if method.get("family") != "dynamic":
        raise ExtensionError("coverage_instrumented_dynamic requires config.method.family=dynamic")
    split_filter = str(config.get("split") or "test")
    unit_index = juliet_unit_index(unit_map_path)
    units: dict[str, dict[str, Any]] = {}
    for meta in unit_index.values():
        if split_filter and meta.get("split") != split_filter:
            continue
        units[meta["unit_id"]] = meta
    if len(units) != 140:
        raise ExtensionError(f"expected 140 test units, got {len(units)}")
    raw_records = load_records(raw_path)
    raw_by_unit = {str(record.get("unit_id")): record for record in raw_records}
    if set(raw_by_unit) != {meta["upstream_unit_id"] for meta in units.values()}:
        raise ExtensionError("coverage raw does not match the frozen test-140 unit set")
    dataset = _dataset_meta(
        config,
        path=unit_map_path,
        dataset_id="juliet-cwe401-v1.3-subset-v1",
        split_id=f"juliet-cwe401-v1.3-subset-v1/{split_filter}",
        unit_count=len(units),
        group_count=len({meta["group_id"] for meta in units.values()}),
        label_counts={
            "bad": sum(1 for meta in units.values() if meta["label"] == "bad"),
            "good": sum(1 for meta in units.values() if meta["label"] == "good"),
        },
    )
    run_id = _new_run_id(config)
    raw_sha = sha256_file(raw_path)
    records: list[dict[str, Any]] = []
    for unit_id in sorted(units, key=lambda value: units[value]["upstream_unit_id"]):
        meta = units[unit_id]
        raw = raw_by_unit[meta["upstream_unit_id"]]
        default_mode = (raw.get("modes") or {}).get("default") or {}
        default_decision = str(default_mode.get("decision") or raw.get("decision") or "")
        union_decision = str(raw.get("decision") or "")
        tier = str(raw.get("coverage_tier") or "unknown")
        tier_effective = str(raw.get("coverage_tier_effective") or tier)
        coverage_union = raw.get("coverage_union") or {}
        leak = default_decision == "leak"
        if raw.get("compile_error"):
            status = "compile_error"
        elif leak:
            status = "ok"
        else:
            status = "inconclusive"
        if leak:
            coverage_class = "leak"
        elif raw.get("compile_error"):
            coverage_class = "compile_error"
        elif raw.get("entry_executed"):
            coverage_class = "covered_clean"
        else:
            coverage_class = "uncovered"
        line_pct = as_number(coverage_union.get("line_pct"))
        effective_line_pct = as_number(coverage_union.get("effective_line_pct"))
        branch_pct = as_number(coverage_union.get("branch_pct"))
        runtime_ms = as_number(raw.get("runtime_ms"))
        records.append(
            _base_record(
                run_id=run_id,
                tier="B",
                track="juliet_cwe401",
                task="leak_detection",
                unit_id=unit_id,
                cluster_id=meta["family"],
                group_id=meta["group_id"],
                side=meta["label"],
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="unit",
                    prompt_sha256=None,
                    context_mode="dynamic_trace",
                    sanitized=False,
                    source_sha256=None,
                ),
                label={
                    "y_true": meta["label"] == "bad",
                    "cwe": ["CWE-401"],
                    "label_source": "juliet_intended",
                    "label_note": None,
                },
                status=status,
                provenance=_provenance(
                    raw_path=raw_path,
                    raw_sha=raw_sha,
                    record_index=None,
                    note="coverage-instrumented dynamic run; clean is inconclusive, never TN",
                ),
                y_pred=True if leak else None,
                coverage={
                    "unit_executed": bool(raw.get("entry_executed")),
                    "target_function_entered": bool(raw.get("entry_executed")),
                    "line_coverage": line_pct,
                    "branch_coverage": branch_pct,
                    "allocation_site_executed": None,
                    "free_site_executed": None,
                    "coverage_source": "gcov",
                    "notes": "gcc --coverage + gcov JSON; clean units are line-complete at most and never branch-complete",
                },
                cost={
                    "usd": None,
                    "wall_s": runtime_ms / 1000.0 if runtime_ms is not None else None,
                    "cpu_s": None,
                    "peak_rss_mb": None,
                    "currency": "USD",
                    "cost_basis": "local_compute",
                    "pricing_snapshot": None,
                    "note": "local gcc/gcov run; USD not applicable",
                },
                extensions={
                    "task_design": design,
                    "coverage_tier": tier if tier in ("branch_complete", "line_complete", "partial", "not_executed", "no_coverage", "coverage_error") else "coverage_error",
                    "coverage_tier_effective": tier_effective if tier_effective in ("branch_complete", "line_complete", "partial", "not_executed", "no_coverage", "coverage_error") else "coverage_error",
                    "coverage_class": coverage_class if coverage_class in ("leak", "covered_clean", "uncovered", "compile_error") else "uncovered",
                    "line_pct": line_pct,
                    "effective_line_pct": effective_line_pct,
                    "branch_pct": branch_pct,
                    "lines_hit": as_int(coverage_union.get("lines_hit")),
                    "lines_total": as_int(coverage_union.get("lines_total")),
                    "branches_hit": as_int(coverage_union.get("branches_hit")),
                    "branches_total": as_int(coverage_union.get("branches_total")),
                    "entry_executed": bool(raw.get("entry_executed")),
                    "evidence_modes": list(raw.get("evidence_modes") or []),
                    "primary_evidence": raw.get("primary_evidence"),
                    "operational_y_pred": leak,
                    "clean_proven": False,
                    "mode_outcomes": {
                        str(mode): str((payload or {}).get("outcome") or (payload or {}).get("status") or "")
                        for mode, payload in (raw.get("modes") or {}).items()
                        if isinstance(payload, Mapping)
                    },
                    "notes": f"default-mode decision={default_decision}; union decision={union_decision}; line coverage alone does not prove a clean verdict",
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="B",
        track="juliet_cwe401",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(units),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=["coverage-instrumented dynamic run", "clean imported as inconclusive, not TN"],
        validate_kwargs={"unit_map": str(unit_map_path)},
    )


def import_interpretable_baseline(
    config: Mapping[str, Any],
    *,
    raw_path: Path,
    split_path: Path,
    out_dir: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    design = "interpretable_baseline"
    method = _method_from_config(config)
    if method.get("family") != "static":
        raise ExtensionError("interpretable_baseline requires config.method.family=static")
    method_name = str(config.get("baseline_method") or "")
    if not method_name:
        raise ExtensionError("config.baseline_method is required")
    split = json.loads(split_path.read_text(encoding="utf-8"))
    samples = split.get("samples") if isinstance(split, dict) else None
    if not isinstance(samples, list):
        raise ExtensionError(f"{split_path}: expected a split object with a samples array")
    raw_records = load_records(raw_path)
    raw_by_idx = {
        int(record["idx"]): record
        for record in raw_records
        if str(record.get("method")) == method_name and str(record.get("split")) == "test"
    }
    if len(raw_by_idx) != len(samples):
        raise ExtensionError(f"baseline predictions for {method_name}: {len(raw_by_idx)} records for {len(samples)} samples")
    dataset = _dataset_meta(
        config,
        path=split_path,
        dataset_id="secvul-split-v1",
        split_id="secvul-split-v1/test",
        unit_count=len(samples),
        group_count=len({str(sample.get("project")) for sample in samples}),
        label_counts={
            "vulnerable": sum(1 for sample in samples if sample.get("is_vulnerable")),
            "non_vulnerable": sum(1 for sample in samples if not sample.get("is_vulnerable")),
        },
    )
    run_id = _new_run_id(config)
    raw_sha = sha256_file(raw_path)
    records: list[dict[str, Any]] = []
    for sample in sorted(samples, key=lambda item: int(item["idx"])):
        idx = int(sample["idx"])
        raw = raw_by_idx[idx]
        y_true = bool(sample.get("is_vulnerable"))
        y_pred = as_bool(raw.get("pred"))
        if y_pred is None:
            raise ExtensionError(f"baseline prediction for idx {idx} is not binary")
        records.append(
            _base_record(
                run_id=run_id,
                tier="A",
                track="secvuleval",
                task="detection",
                unit_id=f"secvul:det:{idx}",
                cluster_id=str(sample.get("project")),
                dataset=dataset,
                method=method,
                input_block=_input_block(
                    view="function",
                    prompt_sha256=None,
                    context_mode="none",
                    sanitized=True,
                    sanitizer_version="lexical-features-2026-11-22",
                ),
                label={
                    "y_true": y_true,
                    "cwe": normalize_cwe_list(sample.get("cwe_list")),
                    "label_source": "secvuleval",
                    "label_note": None,
                },
                status="ok",
                provenance=_provenance(
                    raw_path=raw_path,
                    raw_sha=raw_sha,
                    record_index=None,
                    note=f"{method_name}: copied from producer predictions; no API call",
                ),
                y_pred=y_pred,
                confidence=as_number(raw.get("score")),
                cost={
                    "usd": None,
                    "wall_s": None,
                    "cpu_s": None,
                    "peak_rss_mb": None,
                    "currency": "USD",
                    "cost_basis": "local_compute",
                    "pricing_snapshot": None,
                    "note": "no API calls; local compute not measured",
                },
                extensions={
                    "task_design": design,
                    "baseline_family": "logistic_regression" if method_name.startswith("lr_") else "rule",
                    "method": method_name,
                    "features": list(config.get("features") or []),
                    "rule": config.get("rule"),
                    "threshold": config.get("threshold"),
                    "score": as_number(raw.get("score")),
                    "dev_selected": bool(config.get("dev_selected", False)),
                    "test_tuned": False,
                    "cost_usd": 0.0,
                    "note": "lexical baseline; not a static analyzer; no API calls",
                },
            )
        )
    ext_manifest = _extension_manifest(
        config=config,
        design=design,
        run_role="single",
        presentation_order=None,
        pairing_id=None,
        sibling_run_id=None,
        claim_manifest=None,
        fault_manifest=None,
        tool_registry=None,
        baseline_run=config.get("baseline_run"),
    )
    return _import_single(
        config=config,
        design=design,
        run_id=run_id,
        tier="A",
        track="secvuleval",
        dataset=dataset,
        method=method,
        records=records,
        planned=len(samples),
        ext_manifest=ext_manifest,
        out_dir=out_dir,
        force=force,
        dry_run=dry_run,
        notes=[f"interpretable baseline: {method_name}", "no API call; predictions copied"],
    )


def _dispatch_next_design(
    design: str,
    config: Mapping[str, Any],
    *,
    out_path: Path,
    force: bool,
    dry_run: bool,
) -> dict[str, Any]:
    if design == "codeql_alert_triage":
        run_dir = _config_path(config, "analysis_run", required=True)
        unit_map = _config_path(config, "unit_map", required=True)
        assert run_dir is not None and unit_map is not None
        return import_alert_triage(
            config, run_dir=run_dir, unit_map_path=unit_map, out_dir=out_path, force=force, dry_run=dry_run
        )
    if design == "conservative_verification":
        first = _config_path(config, "first_pass", required=True)
        decisions = _config_path(config, "decisions", required=True)
        verifier = _config_path(config, "verifier_results", required=True)
        assert first is not None and decisions is not None and verifier is not None
        return import_conservative_verification(
            config,
            first_pass_path=first,
            decisions_path=decisions,
            verifier_results_path=verifier,
            out_dir=out_path,
            force=force,
            dry_run=dry_run,
        )
    if design == "diff_guided_pair":
        raw = _config_path(config, "raw", required=True)
        pair_path = _config_path(config, "pair_split", required=True)
        position_map = _config_path(config, "position_map", required=True)
        assert raw is not None and pair_path is not None and position_map is not None
        return import_diff_pair(
            config,
            raw_path=raw,
            pair_path=pair_path,
            position_map_path=position_map,
            out_dir=out_path,
            force=force,
            dry_run=dry_run,
        )
    if design == "coverage_instrumented_dynamic":
        raw = _config_path(config, "raw", required=True)
        unit_map = _config_path(config, "unit_map", required=True)
        assert raw is not None and unit_map is not None
        return import_coverage_dynamic(
            config, raw_path=raw, unit_map_path=unit_map, out_dir=out_path, force=force, dry_run=dry_run
        )
    if design == "interpretable_baseline":
        raw = _config_path(config, "raw", required=True)
        split = _config_path(config, "split_path", required=True)
        assert raw is not None and split is not None
        return import_interpretable_baseline(
            config, raw_path=raw, split_path=split, out_dir=out_path, force=force, dry_run=dry_run
        )
    raise ExtensionError(f"design {design!r} is not a next-iteration batch design")


def import_next_batch(
    batch_path: Path,
    *,
    force: bool,
    dry_run: bool,
    jsonschema: bool,
) -> dict[str, Any]:
    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    runs = batch.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ExtensionError(f"{batch_path}: expected a non-empty runs array")
    results: list[dict[str, Any]] = []
    for index, item in enumerate(runs, start=1):
        if not isinstance(item, Mapping):
            raise ExtensionError(f"{batch_path}: runs[{index}] must be an object")
        design = str(item.get("design") or "")
        raw_config = item.get("config")
        if not isinstance(raw_config, Mapping):
            raise ExtensionError(f"{batch_path}: runs[{index}].config must be an object")
        config = json.loads(json.dumps(raw_config))
        config["_config_path"] = str(batch_path)
        config["jsonschema"] = bool(jsonschema)
        out_value = item.get("out") or config.get("out")
        if not out_value:
            raise ExtensionError(f"{batch_path}: runs[{index}] is missing out")
        out_path = resolve_path(str(out_value), [project_root()])
        summary = _dispatch_next_design(
            design, config, out_path=out_path, force=force, dry_run=dry_run
        )
        results.append(summary)
    return {"batch": str(batch_path), "runs": results, "count": len(results)}


def _import_single(
    *,
    config: Mapping[str, Any],
    design: str,
    run_id: str,
    tier: str,
    track: str,
    dataset: Mapping[str, Any],
    method: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    planned: int,
    ext_manifest: Mapping[str, Any],
    out_dir: Path,
    force: bool,
    dry_run: bool,
    notes: Sequence[str],
    validate_kwargs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    staging_parent = out_dir.parent
    staging_parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=".ext_import_", dir=staging_parent))
    try:
        report = _stage_run(
            stage_dir=stage_dir,
            config=config,
            design=design,
            run_id=run_id,
            tier=tier,
            track=track,
            dataset=dataset,
            method=method,
            records=records,
            planned=planned,
            extension_manifest=ext_manifest,
            notes=notes,
            validate_kwargs=validate_kwargs or {},
        )
        summary = {
            "design": design,
            "run_id": run_id,
            "out_dir": str(out_dir),
            "records": len(records),
            "planned": planned,
            "status_counts": {},
            "validation_ok": report.get("ok"),
        }
        from collections import Counter

        summary["status_counts"] = dict(Counter(str(record.get("status")) for record in records))
        if dry_run:
            summary["validation"] = report
            return summary
        _publish(stage_dir, out_dir, force)
        report["run_dir"] = str(out_dir)
        _write_validation(out_dir, report)
        return summary
    finally:
        if stage_dir.exists():
            shutil.rmtree(stage_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", required=True, choices=[
        "position_debiased_pair",
        "open_choice_pair",
        "evidence_verification",
        "evidence_retraction",
        "fault_injected_dynamic",
        "new_static_tool",
        "enhanced_dynamic",
        "hybrid_enhanced_dynamic",
        "codeql_alert_triage",
        "conservative_verification",
        "diff_guided_pair",
        "coverage_instrumented_dynamic",
        "interpretable_baseline",
        "next_iteration_batch",
    ])
    parser.add_argument("--config", required=True, help="JSON import config")
    parser.add_argument("--raw", help="producer raw JSONL (overrides config.raw)")
    parser.add_argument("--out", help="output run directory or position base (overrides config.out)")
    parser.add_argument("--claim-manifest", help="frozen claim manifest (evidence_verification)")
    parser.add_argument("--fault-manifest", help="frozen fault manifest (fault_injected_dynamic)")
    parser.add_argument("--unit-map", help="juliet/subset_units.jsonl (new_static_tool/enhanced_dynamic)")
    parser.add_argument("--pair-split", help="frozen pair split (position/open-choice)")
    parser.add_argument("--first-pass", help="first-pass results (evidence_retraction)")
    parser.add_argument("--verify", help="verifier results (evidence_retraction)")
    parser.add_argument("--force", action="store_true", help="archive an existing output directory instead of refusing")
    parser.add_argument("--dry-run", action="store_true", help="stage and validate, print summary, write nothing")
    parser.add_argument("--jsonschema", action="store_true", help="also validate extension schemas during staging")
    args = parser.parse_args(argv)

    try:
        if args.design == "next_iteration_batch":
            summary = import_next_batch(
                Path(args.config).resolve(),
                force=args.force,
                dry_run=args.dry_run,
                jsonschema=args.jsonschema,
            )
            sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
            if args.dry_run:
                sys.stderr.write("dry run: staged output validated and removed\n")
            else:
                sys.stderr.write(f"wrote {summary.get('count')} run(s)\n")
            return 0
        config = load_config(args.config)
        if args.jsonschema:
            config["jsonschema"] = True
        if args.pair_split:
            config["pair_split"] = args.pair_split
        if args.claim_manifest:
            config["claim_manifest"] = args.claim_manifest
        if args.fault_manifest:
            config["fault_manifest"] = args.fault_manifest
        if args.unit_map:
            config["unit_map"] = args.unit_map
        if args.first_pass:
            config["first_pass_run"] = args.first_pass
        if args.verify:
            config["verify_run"] = args.verify
        out_value = args.out or config.get("out")
        if not out_value:
            raise ExtensionError("missing output path: use --out or config.out")
        out_path = Path(out_value).expanduser()
        if not out_path.is_absolute():
            out_path = (Path(config["_config_path"]).parent / out_path).resolve()

        if args.design in (
            "codeql_alert_triage",
            "conservative_verification",
            "diff_guided_pair",
            "coverage_instrumented_dynamic",
            "interpretable_baseline",
        ):
            summary = _dispatch_next_design(
                args.design, config, out_path=out_path, force=args.force, dry_run=args.dry_run
            )
            sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
            if args.dry_run:
                sys.stderr.write("dry run: staged output validated and removed\n")
            else:
                sys.stderr.write(f"wrote {summary.get('out_dir')}\n")
            return 0

        if args.design == "evidence_retraction":
            first_path = _config_path(config, "first_pass_run", required=True)
            verify_path = _config_path(config, "verify_run", required=True)
            assert first_path is not None and verify_path is not None
            summary = import_evidence_retraction(
                config,
                first_pass_path=first_path,
                verify_path=verify_path,
                out_dir=out_path,
                force=args.force,
                dry_run=args.dry_run,
            )
            sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
            if args.dry_run:
                sys.stderr.write("dry run: staged output validated and removed\n")
            else:
                sys.stderr.write(f"wrote {summary.get('out_dir')}\n")
            return 0

        raw_value = args.raw or config.get("raw")
        if not raw_value and args.design == "position_debiased_pair" and isinstance(config.get("orders"), Mapping):
            raw_path = Path(config["_config_path"]).resolve().parent
        elif not raw_value:
            raise ExtensionError("missing raw path: use --raw or config.raw")
        else:
            raw_path = resolve_path(str(raw_value), _config_bases(config))
            if not raw_path.exists():
                raise ExtensionError(f"raw file not found: {raw_path}")

        if args.design == "position_debiased_pair":
            summary = import_position(
                config, raw_path=raw_path, out_base=out_path, force=args.force, dry_run=args.dry_run
            )
        elif args.design == "open_choice_pair":
            summary = import_open_choice(
                config, raw_path=raw_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        elif args.design == "evidence_verification":
            claim_path = _config_path(config, "claim_manifest", required=True)
            assert claim_path is not None
            summary = import_evidence(
                config, raw_path=raw_path, claim_path=claim_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        elif args.design == "fault_injected_dynamic":
            fault_path = _config_path(config, "fault_manifest", required=True)
            assert fault_path is not None
            summary = import_fault(
                config, raw_path=raw_path, fault_path=fault_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        elif args.design == "enhanced_dynamic":
            unit_map_path = _config_path(config, "unit_map", required=True)
            assert unit_map_path is not None
            summary = import_enhanced_dynamic(
                config, raw_path=raw_path, unit_map_path=unit_map_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        elif args.design == "hybrid_enhanced_dynamic":
            unit_map_path = _config_path(config, "unit_map", required=True)
            assert unit_map_path is not None
            summary = import_hybrid_enhanced_dynamic(
                config, raw_path=raw_path, unit_map_path=unit_map_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        else:
            unit_map_path = _config_path(config, "unit_map", required=True)
            assert unit_map_path is not None
            summary = import_static(
                config, raw_path=raw_path, unit_map_path=unit_map_path, out_dir=out_path, force=args.force, dry_run=args.dry_run
            )
        sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        if args.dry_run:
            sys.stderr.write("dry run: staged output validated and removed\n")
        else:
            sys.stderr.write(f"wrote {summary.get('out_dir') or summary.get('out_base')}\n")
        return 0
    except ExtensionError as exc:
        sys.stderr.write(f"import failed: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

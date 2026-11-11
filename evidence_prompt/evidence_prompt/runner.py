"""Resumable runner for the evidence-grounded detection experiment.

Only detection on the frozen independent SecVulEval split is supported.  The
runner reuses the audited HTTP client, request cache, and dataset loader from
``runner/secvul_runner`` but writes all artifacts under its own ``--out-dir``;
no existing run is read or overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from secvul_runner import __version__ as runner_version
from secvul_runner.cache import RequestCache
from secvul_runner.client import (
    SESSION_HEADER,
    ApiCallResult,
    ApiConfig,
    ApiConfigurationError,
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
from secvul_runner.datasets import (
    DatasetError,
    FunctionSample,
    LoadedDataset,
    dataset_label_counts,
    load_dataset,
)
from secvul_runner.util import atomic_write_json, atomic_write_text, read_json, sha256_file

from . import EVIDENCE_STRATEGY, PROMPT_VERSION, __version__
from .prompt import EvidencePrompt, build_prompt, prompt_bytes, template_sha256
from .validation import EvidenceSchemaError, validate_evidence_output

logger = logging.getLogger("evidence_prompt")

DEFAULT_DATASET = Path(__file__).resolve().parents[2] / "splits" / "test_detection_160.json"
DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_USER_AGENT = "secvul-eval-runner/1.0"
CACHE_SCHEMA_VERSION = 1


class EvidenceRunError(RuntimeError):
    """User-facing configuration or run-state error."""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _httpx_version() -> str | None:
    try:
        import importlib.metadata

        return importlib.metadata.version("httpx")
    except Exception:  # noqa: BLE001 - diagnostic only
        return None


@dataclass(frozen=True)
class RunSettings:
    dataset: LoadedDataset
    full_unit_count: int
    full_label_counts: dict[str, int]
    api_config: ApiConfig
    api_key_env: str
    out_dir: Path
    limit: int
    concurrency: int
    dry_run: bool
    resume: bool
    refresh: bool
    retry_invalid: bool
    reuse_cached_errors: bool
    run_label: str | None
    config_fingerprint: str

    @property
    def partial(self) -> bool:
        return self.dataset.unit_count < self.full_unit_count

    @property
    def expected_requests(self) -> int:
        return self.dataset.unit_count


@dataclass(frozen=True)
class RequestSpec:
    sample: FunctionSample
    prompt: EvidencePrompt
    body: dict[str, Any]
    endpoint: str
    request_fingerprint: str
    cache_key: str
    prompt_sha256: str


@dataclass(frozen=True)
class RunOutcome:
    out_dir: Path
    status: str
    request_count: int
    manifest_path: Path
    results_path: Path | None
    summary: dict[str, Any] | None


def _api_identity(api_config: ApiConfig) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "endpoint": api_config.endpoint,
        "model": api_config.model,
        "temperature": api_config.temperature,
        "max_tokens": api_config.max_tokens,
        "response_format": api_config.response_format,
        "max_tokens_field": api_config.max_tokens_field,
    }
    if api_config.thinking is not None:
        identity["thinking"] = api_config.thinking
    if api_config.reasoning_effort is not None:
        identity["reasoning_effort"] = api_config.reasoning_effort
    return identity


def compute_config_fingerprint(
    *,
    dataset: LoadedDataset,
    api_config: ApiConfig,
    limit: int,
) -> str:
    identity = {
        "package": "evidence_prompt",
        "package_version": __version__,
        "runner_version": runner_version,
        "prompt_version": PROMPT_VERSION,
        "template_sha256": template_sha256(),
        "cache_schema": CACHE_SCHEMA_VERSION,
        "dataset_type": dataset.dataset_type,
        "dataset_sha256": dataset.sha256,
        "strategy": EVIDENCE_STRATEGY,
        "task": "detection",
        "limit": limit,
        "api_identity": _api_identity(api_config),
    }
    return _sha256_text(canonical_json(identity))


def create_settings(
    *,
    dataset_path: str | Path,
    api_config: ApiConfig,
    api_key_env: str,
    out_dir: str | Path,
    limit: int,
    concurrency: int,
    dry_run: bool,
    resume: bool,
    refresh: bool,
    retry_invalid: bool,
    reuse_cached_errors: bool,
    run_label: str | None,
) -> RunSettings:
    if limit < 0:
        raise EvidenceRunError("--limit must be zero or positive")
    if concurrency < 1 or concurrency > 32:
        raise EvidenceRunError("--concurrency must be between 1 and 32")
    api_config.validate()
    path = Path(dataset_path)
    try:
        full_dataset = load_dataset(path, "independent")
    except DatasetError as exc:
        raise EvidenceRunError(str(exc)) from exc
    if full_dataset.is_pairs:
        raise EvidenceRunError("the evidence experiment supports only the independent dataset")
    effective_limit = 0 if limit == 0 or limit >= full_dataset.unit_count else limit
    selected = full_dataset.limited(effective_limit)
    out = Path(out_dir).expanduser().resolve()
    fingerprint = compute_config_fingerprint(
        dataset=selected, api_config=api_config, limit=effective_limit
    )
    return RunSettings(
        dataset=selected,
        full_unit_count=full_dataset.unit_count,
        full_label_counts=dataset_label_counts(full_dataset),
        api_config=api_config,
        api_key_env=api_key_env,
        out_dir=out,
        limit=effective_limit,
        concurrency=concurrency,
        dry_run=dry_run,
        resume=resume,
        refresh=refresh,
        retry_invalid=retry_invalid,
        reuse_cached_errors=reuse_cached_errors,
        run_label=run_label,
        config_fingerprint=fingerprint,
    )


def build_request_specs(settings: RunSettings) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for sample in settings.dataset.units:
        if not isinstance(sample, FunctionSample):
            raise EvidenceRunError("unexpected pair record in independent dataset")
        prompt = build_prompt(sample.func_body)
        body = build_body(list(prompt.messages), settings.api_config)
        fingerprint = request_fingerprint(
            endpoint=settings.api_config.endpoint,
            body=body,
            task="detection",
            strategy=EVIDENCE_STRATEGY,
            prompt_version=PROMPT_VERSION,
        )
        cache_key = _sha256_text(
            canonical_json(
                {
                    "sample_id": sample.sample_id,
                    "task": "detection",
                    "request_fingerprint": fingerprint,
                }
            )
        )
        specs.append(
            RequestSpec(
                sample=sample,
                prompt=prompt,
                body=body,
                endpoint=settings.api_config.endpoint,
                request_fingerprint=fingerprint,
                cache_key=cache_key,
                prompt_sha256=_sha256_text(prompt_bytes(prompt).decode("utf-8")),
            )
        )
    if len(specs) != settings.expected_requests:
        raise EvidenceRunError(
            f"planned {len(specs)} requests but the selected dataset has "
            f"{settings.expected_requests} units"
        )
    return specs


def _request_record(spec: RequestSpec, index: int, *, session_id: str, user_agent: str) -> dict[str, Any]:
    return {
        "request_index": index,
        "sample_id": spec.sample.sample_id,
        "task": "detection",
        "strategy": EVIDENCE_STRATEGY,
        "endpoint": spec.endpoint,
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent,
            SESSION_HEADER: session_id,
        },
        "authorization_header_omitted": True,
        "session_header_is_not_a_secret": True,
        "request_fingerprint": spec.request_fingerprint,
        "cache_key": spec.cache_key,
        "body_sha256": _sha256_text(canonical_json(spec.body)),
        "prompt_sha256": spec.prompt_sha256,
        "prompt": spec.prompt.metadata,
        "body": spec.body,
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    text = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
    )
    atomic_write_text(path, text)


def _prepare_out_dir(settings: RunSettings) -> tuple[dict[str, Any] | None, str | None]:
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "manifest.json"
    if manifest_path.exists():
        if not settings.resume:
            raise EvidenceRunError(
                f"{out} already contains a run manifest; use --resume or choose a new --out-dir"
            )
        try:
            existing = read_json(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceRunError(f"cannot read existing manifest {manifest_path}: {exc}") from exc
        if not isinstance(existing, dict):
            raise EvidenceRunError(f"existing manifest {manifest_path} is not a JSON object")
        if existing.get("config_fingerprint") != settings.config_fingerprint:
            raise EvidenceRunError(
                "cannot resume: the configuration fingerprint does not match the existing "
                "manifest. Use the original dataset/model/prompt/limit or a new --out-dir."
            )
        return existing, existing.get("created_at")
    if settings.resume:
        raise EvidenceRunError(f"cannot resume: {out} has no manifest.json")
    entries = list(out.iterdir())
    if entries:
        raise EvidenceRunError(
            f"{out} is not empty and has no run manifest; choose a new --out-dir"
        )
    return None, None


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    manifest["updated_at"] = utc_now_iso()
    atomic_write_json(path, manifest)


def _resolve_session(existing: dict[str, Any] | None) -> tuple[str, str]:
    if existing:
        api = existing.get("api")
        if isinstance(api, dict):
            session = api.get("session")
            if isinstance(session, dict) and is_valid_session_id(session.get("value")):
                return session["value"], "resumed_manifest"
    return generate_session_id(), "generated"


def _session_record(session_id: str, source: str) -> dict[str, Any]:
    return {
        "header": SESSION_HEADER,
        "value": session_id,
        "sha256": session_id_sha256(session_id),
        "source": source,
        "is_secret": False,
        "note": (
            "Random per-run identifier used only for OpenCode Go request routing and prompt-cache "
            "affinity. It is not an API key; Authorization is never written to run artifacts."
        ),
    }


def _public_config(settings: RunSettings, *, dry_run: bool) -> dict[str, Any]:
    return {
        "package": "evidence_prompt",
        "package_version": __version__,
        "runner_version": runner_version,
        "prompt_version": PROMPT_VERSION,
        "strategy": EVIDENCE_STRATEGY,
        "task": "detection",
        "dataset_type": settings.dataset.dataset_type,
        "dataset_path": str(settings.dataset.path),
        "dataset_sha256": settings.dataset.sha256,
        "selected_units": settings.dataset.unit_count,
        "dataset_units": settings.full_unit_count,
        "limit": settings.limit,
        "partial": settings.partial,
        "expected_requests": settings.expected_requests,
        "concurrency": settings.concurrency,
        "dry_run": dry_run,
        "resume": settings.resume,
        "refresh": settings.refresh,
        "retry_invalid": settings.retry_invalid,
        "reuse_cached_errors": settings.reuse_cached_errors,
        "api_key_env": settings.api_key_env,
        "api": settings.api_config.public_dict(),
        "input_fields": ["func_body"],
        "context_used": False,
        "config_fingerprint": settings.config_fingerprint,
        "template_sha256": template_sha256(),
    }


def _prompt_audit(specs: list[RequestSpec]) -> dict[str, Any]:
    line_counts = [spec.prompt.line_count for spec in specs]
    message_lengths = [
        sum(len(message["content"]) for message in spec.prompt.messages) for spec in specs
    ]
    only_source = all(spec.prompt.metadata.get("only_source_variable") for spec in specs)
    reconstructed = all(spec.prompt.metadata.get("source_reconstructed") for spec in specs)
    forbidden = sorted(
        {
            token
            for spec in specs
            for token in spec.prompt.metadata.get("template_forbidden_tokens_present", [])
        }
    )
    return {
        "requests": len(specs),
        "all_only_source_variable": only_source,
        "all_source_reconstructed": reconstructed,
        "forbidden_template_tokens_present": forbidden,
        "line_count_min": min(line_counts) if line_counts else 0,
        "line_count_max": max(line_counts) if line_counts else 0,
        "line_count_mean": round(sum(line_counts) / len(line_counts), 6) if line_counts else None,
        "prompt_chars_min": min(message_lengths) if message_lengths else 0,
        "prompt_chars_max": max(message_lengths) if message_lengths else 0,
        "prompt_chars_mean": round(sum(message_lengths) / len(message_lengths), 6)
        if message_lengths
        else None,
    }


def run_dry_run(settings: RunSettings) -> RunOutcome:
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    if (out / "manifest.json").exists():
        raise EvidenceRunError(
            f"{out} contains a real run manifest; choose a separate --out-dir for --dry-run"
        )
    allowed = {"dry_run_requests.jsonl", "dry_run_manifest.json"}
    unexpected = [entry.name for entry in out.iterdir() if entry.name not in allowed]
    if unexpected:
        raise EvidenceRunError(
            f"{out} contains files that are not dry-run artifacts: {sorted(unexpected)}"
        )
    specs = build_request_specs(settings)
    session_id = generate_session_id()
    request_records = [
        _request_record(spec, index, session_id=session_id, user_agent=settings.api_config.user_agent)
        for index, spec in enumerate(specs, start=1)
    ]
    request_path = out / "dry_run_requests.jsonl"
    _write_jsonl(request_path, request_records)
    manifest = {
        "schema_version": 1,
        "artifact": "evidence_prompt_dry_run",
        "dry_run": True,
        "no_api_calls": True,
        "experimental_results": False,
        "created_at": utc_now_iso(),
        "out_dir": str(out),
        "config": _public_config(settings, dry_run=True),
        "dataset": {
            "type": settings.dataset.dataset_type,
            "path": str(settings.dataset.path),
            "sha256": settings.dataset.sha256,
            "metadata": settings.dataset.metadata,
            "selected_label_counts": dataset_label_counts(settings.dataset),
            "full_label_counts": settings.full_label_counts,
        },
        "request_count": len(specs),
        "requests_file": request_path.name,
        "requests_sha256": sha256_file(request_path),
        "prompt_audit": _prompt_audit(specs),
        "session": _session_record(session_id, "generated_for_dry_run"),
        "authorization_header_included_in_file": False,
        "api_key_required": False,
        "warnings": [
            "DRY RUN ONLY: no model API was called and no predictions were produced.",
            "The request file contains prompts and source code, but no API key and no labels.",
        ],
    }
    manifest_path = out / "dry_run_manifest.json"
    atomic_write_json(manifest_path, manifest)
    logger.info("dry run planned %d evidence requests; no API calls made", len(specs))
    return RunOutcome(
        out_dir=out,
        status="dry_run",
        request_count=len(specs),
        manifest_path=manifest_path,
        results_path=None,
        summary=None,
    )


def _cache_relative(path: Path, out_dir: Path) -> str:
    try:
        return str(path.relative_to(out_dir))
    except ValueError:
        return str(path)


def _refresh_cached_cost(record: dict[str, Any], config: ApiConfig) -> dict[str, Any]:
    response = record.get("response")
    if isinstance(response, dict):
        response["cost"] = compute_cost(response.get("usage"), config)
    return record


def _execute_spec(
    spec: RequestSpec,
    *,
    cache: RequestCache,
    client: ChatClient,
    settings: RunSettings,
) -> dict[str, Any]:
    cache_path = cache.path_for("independent", "detection", spec.cache_key)
    cached = None
    previous_status = None
    if not settings.refresh:
        cached = cache.read(
            dataset_type="independent",
            task="detection",
            key=spec.cache_key,
            request_fingerprint=spec.request_fingerprint,
        )
    if cached is not None:
        previous_status = cached.get("status")
        use_cached = previous_status == "ok"
        use_cached = use_cached or (previous_status == "invalid" and not settings.retry_invalid)
        use_cached = use_cached or (previous_status == "error" and settings.reuse_cached_errors)
        if use_cached:
            record = _refresh_cached_cost(dict(cached), settings.api_config)
            for key in ("cache_schema_version", "cache_key", "request_fingerprint"):
                record.pop(key, None)
            record["cache"] = {
                "hit": True,
                "key": spec.cache_key,
                "file": _cache_relative(cache_path, settings.out_dir),
                "previous_status": previous_status,
            }
            return record

    try:
        api_result: ApiCallResult = client.complete(list(spec.prompt.messages))
    except Exception as exc:  # noqa: BLE001 - record, do not fabricate
        logger.exception("unexpected client failure for %s", spec.sample.sample_id)
        record = _fallback_error_record(spec, settings, f"{type(exc).__name__}: {exc}")
        cache.write(
            dataset_type="independent",
            task="detection",
            key=spec.cache_key,
            request_fingerprint=spec.request_fingerprint,
            record=record,
        )
        record["cache"] = {
            "hit": False,
            "key": spec.cache_key,
            "file": _cache_relative(cache_path, settings.out_dir),
            "previous_status": previous_status,
        }
        return record

    response = api_result.to_dict()
    parsed: dict[str, Any] | None = None
    if api_result.status == "ok":
        try:
            parsed, checks = validate_evidence_output(
                api_result.content or "", spec.prompt.line_texts
            )
            validation = checks
            status = "ok"
        except EvidenceSchemaError as exc:
            validation = {
                "schema_valid": False,
                "error": str(exc),
                "error_family": exc.family,
                "raw_content_sha256": _sha256_text(api_result.content or ""),
            }
            status = "invalid"
    else:
        validation = {"schema_valid": False, "error": "api_error", "error_family": "api"}
        status = "error"

    record: dict[str, Any] = {
        "dataset_type": "independent",
        "sample_id": spec.sample.sample_id,
        "unit_id": spec.sample.unit_id,
        "idx": spec.sample.idx,
        "label": spec.sample.label,
        "task": "detection",
        "strategy": EVIDENCE_STRATEGY,
        "prompt": spec.prompt.metadata,
        "prompt_sha256": spec.prompt_sha256,
        "request": {
            "endpoint": spec.endpoint,
            "model": settings.api_config.model,
            "request_fingerprint": spec.request_fingerprint,
            "body_sha256": _sha256_text(canonical_json(spec.body)),
        },
        "response": response,
        "status": status,
        "parsed": parsed,
        "validation": validation,
        "created_at": utc_now_iso(),
        "completed_at": utc_now_iso(),
    }
    cache.write(
        dataset_type="independent",
        task="detection",
        key=spec.cache_key,
        request_fingerprint=spec.request_fingerprint,
        record=record,
    )
    record["cache"] = {
        "hit": False,
        "key": spec.cache_key,
        "file": _cache_relative(cache_path, settings.out_dir),
        "previous_status": previous_status,
    }
    return record


def _fallback_error_record(
    spec: RequestSpec, settings: RunSettings, message: str
) -> dict[str, Any]:
    return {
        "dataset_type": "independent",
        "sample_id": spec.sample.sample_id,
        "unit_id": spec.sample.unit_id,
        "idx": spec.sample.idx,
        "label": spec.sample.label,
        "task": "detection",
        "strategy": EVIDENCE_STRATEGY,
        "prompt": spec.prompt.metadata,
        "prompt_sha256": spec.prompt_sha256,
        "request": {
            "endpoint": spec.endpoint,
            "model": settings.api_config.model,
            "request_fingerprint": spec.request_fingerprint,
            "body_sha256": _sha256_text(canonical_json(spec.body)),
        },
        "response": None,
        "status": "error",
        "parsed": None,
        "validation": {
            "schema_valid": False,
            "error": "unexpected_client_exception",
            "error_family": "client",
            "detail": message,
        },
        "created_at": utc_now_iso(),
        "completed_at": utc_now_iso(),
    }


def _ordered_records(
    specs: list[RequestSpec],
    by_id: dict[str, dict[str, Any]],
    settings: RunSettings,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, start=1):
        record = by_id.get(spec.sample.sample_id)
        if record is None:
            record = _fallback_error_record(spec, settings, "missing")
            record["validation"] = {
                "schema_valid": False,
                "error": "request_not_recorded",
                "error_family": "missing",
            }
            record["response"] = None
        record = dict(record)
        record["request_index"] = index
        records.append(record)
    return records


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [
        record
        for record in records
        if record.get("status") == "ok"
        and isinstance(record.get("parsed"), dict)
        and isinstance(record["parsed"].get("is_vulnerable"), bool)
    ]
    tp = fp = tn = fn = 0
    for record in valid:
        predicted = bool(record["parsed"]["is_vulnerable"])
        label = bool(record["label"])
        if label and predicted:
            tp += 1
        elif label and not predicted:
            fn += 1
        elif not label and predicted:
            fp += 1
        else:
            tn += 1
    total = len(records)
    costs = [
        (record.get("response") or {}).get("cost", {}).get("cost_usd")
        for record in records
        if isinstance(record.get("response"), dict)
    ]
    known_costs = [float(value) for value in costs if isinstance(value, (int, float))]
    latencies = sorted(
        float(record["response"]["request_latency_seconds"])
        for record in records
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("request_latency_seconds"), (int, float))
    )

    def percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        if len(values) == 1:
            return values[0]
        position = (len(values) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(values) - 1)
        weight = position - lower
        return values[lower] * (1.0 - weight) + values[upper] * weight

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    by_status: dict[str, int] = {}
    for record in records:
        by_status[str(record.get("status"))] = by_status.get(str(record.get("status")), 0) + 1
    reasons: dict[str, int] = {}
    for record in records:
        if record.get("status") == "invalid":
            family = str((record.get("validation") or {}).get("error_family", "unknown"))
            reasons[family] = reasons.get(family, 0) + 1
    return {
        "records": total,
        "valid": len(valid),
        "coverage": len(valid) / total if total else None,
        "by_status": by_status,
        "invalid_by_family": reasons,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics_valid_only": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": tn / (tn + fp) if tn + fp else None,
            "accuracy": (tp + tn) / len(valid) if valid else None,
        },
        "strict_accuracy_all_samples": (tp + tn) / total if total else None,
        "cost": {
            "total_cost_usd": round(sum(known_costs), 12) if known_costs else None,
            "requests_with_cost": len(known_costs),
        },
        "latency_seconds": {
            "mean": sum(latencies) / len(latencies) if latencies else None,
            "p50": percentile(latencies, 0.5),
            "p95": percentile(latencies, 0.95),
            "max": latencies[-1] if latencies else None,
        },
    }


def _manifest(
    settings: RunSettings,
    *,
    existing: dict[str, Any] | None,
    created_at: str,
    status: str,
    started_at: str,
    session: dict[str, Any],
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = dict(existing) if existing else {}
    manifest.update(
        {
            "schema_version": 1,
            "artifact": "evidence_prompt_run",
            "run_id": manifest.get("run_id", settings.out_dir.name),
            "run_label": settings.run_label,
            "status": status,
            "created_at": created_at,
            "started_at": started_at,
            "updated_at": utc_now_iso(),
            "package_version": __version__,
            "runner_version": runner_version,
            "python_version": sys.version.split()[0],
            "httpx_version": _httpx_version(),
            "platform": platform.platform(),
            "config_fingerprint": settings.config_fingerprint,
            "config": _public_config(settings, dry_run=False),
            "dataset": {
                "type": settings.dataset.dataset_type,
                "path": str(settings.dataset.path),
                "sha256": settings.dataset.sha256,
                "metadata": settings.dataset.metadata,
                "selected_label_counts": dataset_label_counts(settings.dataset),
                "full_label_counts": settings.full_label_counts,
            },
            "api": {
                **settings.api_config.public_dict(),
                "api_key_env": settings.api_key_env,
                "api_key_present": bool(os.environ.get(settings.api_key_env, "").strip()),
                "api_key_value_stored": False,
                "session": session,
            },
            "expected_requests": settings.expected_requests,
            "authorization_header_stored": False,
            "prompt_input_fields": ["func_body"],
            "context_used": False,
            "notes": [
                "No API key or Authorization header is stored in run artifacts.",
                "Prompts contain only the numbered function source; no labels, changed lines, "
                "CVE/CWE metadata, project/filepath, commit message, fixed function, or context.",
                "This is a single run; temperature 0 does not guarantee determinism.",
            ],
        }
    )
    if summary is not None:
        manifest["summary"] = summary
        manifest["counts"] = {
            "planned_requests": settings.expected_requests,
            "recorded_requests": summary["records"],
            "valid": summary["valid"],
            "invalid": summary["by_status"].get("invalid", 0),
            "api_errors": summary["by_status"].get("error", 0),
        }
    return manifest


def run_experiment(settings: RunSettings, api_key: str) -> RunOutcome:
    out = settings.out_dir
    existing, created_at = _prepare_out_dir(settings)
    created_at = created_at or utc_now_iso()
    started_at = utc_now_iso()
    specs = build_request_specs(settings)
    session_id, session_source = _resolve_session(existing)
    session = _session_record(session_id, session_source)
    manifest_path = out / "manifest.json"

    if settings.dry_run:
        raise EvidenceRunError("use run_dry_run for dry runs")

    _write_manifest(
        manifest_path,
        _manifest(
            settings,
            existing=existing,
            created_at=created_at,
            status="running",
            started_at=started_at,
            session=session,
        ),
    )

    if not api_key.strip():
        raise EvidenceRunError(f"environment variable {settings.api_key_env} is empty")

    cache = RequestCache(out / "cache")
    by_id: dict[str, dict[str, Any]] = {}
    logger.info(
        "starting %d evidence requests for %s on %s (concurrency=%d)",
        len(specs),
        settings.api_config.model,
        settings.dataset.path,
        settings.concurrency,
    )
    with ChatClient(settings.api_config, api_key, session_id=session_id) as client:
        if settings.concurrency == 1:
            for spec in specs:
                record = _execute_spec(spec, cache=cache, client=client, settings=settings)
                by_id[spec.sample.sample_id] = record
                logger.info(
                    "recorded %s status=%s", spec.sample.sample_id, record.get("status")
                )
        else:
            with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
                futures = {
                    pool.submit(
                        _execute_spec, spec, cache=cache, client=client, settings=settings
                    ): spec
                    for spec in specs
                }
                completed = 0
                for future in as_completed(futures):
                    spec = futures[future]
                    record = future.result()
                    by_id[spec.sample.sample_id] = record
                    completed += 1
                    if completed % 10 == 0 or completed == len(specs):
                        logger.info("completed %d/%d requests", completed, len(specs))

    records = _ordered_records(specs, by_id, settings)
    results_path = out / "results.jsonl"
    _write_jsonl(results_path, records)
    summary = _summary(records)
    manifest = _manifest(
        settings,
        existing=existing,
        created_at=created_at,
        status="completed",
        started_at=started_at,
        session=session,
        summary=summary,
    )
    manifest["completed_at"] = utc_now_iso()
    manifest["results_file"] = results_path.name
    manifest["results_sha256"] = sha256_file(results_path)
    _write_manifest(manifest_path, manifest)
    logger.info("completed %d records; valid=%d", len(records), summary["valid"])
    return RunOutcome(
        out_dir=out,
        status="completed",
        request_count=len(records),
        manifest_path=manifest_path,
        results_path=results_path,
        summary=summary,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence-prompt-runner",
        description=(
            "Run the evidence-grounded detection prompt on the frozen SecVulEval "
            "independent test split. Dry runs never call a model."
        ),
    )
    parser.add_argument("--dataset-file", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SECVUL_BASE_URL") or DEFAULT_BASE_URL,
    )
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument(
        "--max-tokens-field",
        choices=("max_tokens", "max_completion_tokens"),
        default="max_tokens",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--backoff-base", type=float, default=1.5)
    parser.add_argument("--backoff-cap", type=float, default=30.0)
    parser.add_argument(
        "--response-format", choices=("json_object", "none"), default="json_object"
    )
    parser.add_argument(
        "--thinking", choices=("default", "enabled", "disabled"), default=None
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "minimal", "low", "medium", "high"),
        default=None,
    )
    parser.add_argument("--input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--output-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--cached-input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--retry-invalid", action="store_true")
    parser.add_argument("--reuse-cached-errors", action="store_true")
    parser.add_argument("--run-label", default=None)
    parser.add_argument(
        "--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO"
    )
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

    if args.dry_run and args.resume:
        parser.error("--dry-run cannot be combined with --resume")
    if args.dry_run and args.refresh:
        parser.error("--dry-run cannot be combined with --refresh")
    if args.refresh and not args.resume:
        parser.error("--refresh requires --resume")
    if args.retry_invalid and not args.resume:
        parser.error("--retry-invalid requires --resume")
    if args.reuse_cached_errors and not args.resume:
        parser.error("--reuse-cached-errors requires --resume")
    if not args.api_key_env or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.api_key_env) is None:
        parser.error("--api-key-env must look like an environment variable name")
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.concurrency < 1 or args.concurrency > 32:
        parser.error("--concurrency must be between 1 and 32")

    try:
        endpoint = normalize_endpoint(args.base_url)
        api_config = ApiConfig(
            base_url=args.base_url,
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
            user_agent=args.user_agent,
            input_price_usd_per_1m=args.input_price_usd_per_1m,
            output_price_usd_per_1m=args.output_price_usd_per_1m,
            cached_input_price_usd_per_1m=args.cached_input_price_usd_per_1m,
        )
        api_config.validate()
    except (ApiConfigurationError, ValueError) as exc:
        parser.error(str(exc))

    try:
        settings = create_settings(
            dataset_path=args.dataset_file,
            api_config=api_config,
            api_key_env=args.api_key_env,
            out_dir=args.out_dir,
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
            print(f"DRY RUN completed: {outcome.request_count} evidence request(s) validated.")
            print(f"  request file: {outcome.out_dir / 'dry_run_requests.jsonl'}")
            print(f"  manifest:     {outcome.manifest_path}")
            print("  No API call was made. No predictions or metrics were produced.")
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
        summary = outcome.summary or {}
        print(f"Run {outcome.status}: {outcome.request_count} request(s).")
        print(
            f"  valid {summary.get('valid')}/{summary.get('records')} "
            f"(invalid {summary.get('by_status', {}).get('invalid', 0)}, "
            f"api errors {summary.get('by_status', {}).get('error', 0)})"
        )
        metrics = summary.get("metrics_valid_only", {})
        print(
            "  detection (valid only): "
            f"precision={metrics.get('precision')} recall={metrics.get('recall')} "
            f"f1={metrics.get('f1')}"
        )
        print(f"  strict accuracy (all records): {summary.get('strict_accuracy_all_samples')}")
        print(f"  total cost USD: {summary.get('cost', {}).get('total_cost_usd')}")
        print(f"  results: {outcome.results_path}")
        print(f"  manifest: {outcome.manifest_path}")
        return 0
    except KeyboardInterrupt:
        print(
            "Interrupted. Completed per-request results are cached; rerun the same command "
            "with --resume and the same --out-dir.",
            file=sys.stderr,
        )
        return 130
    except (EvidenceRunError, ApiConfigurationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        logger.exception("unexpected failure")
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

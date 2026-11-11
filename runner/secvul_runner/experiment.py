"""Experiment orchestration: request planning, cache/resume, and artifacts."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import logging
import os
import platform
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .cache import RequestCache
from .client import (
    ApiCallResult,
    ApiConfig,
    ChatClient,
    SESSION_HEADER,
    build_body,
    canonical_json,
    compute_cost,
    generate_session_id,
    is_valid_session_id,
    redact_secrets,
    request_fingerprint,
    session_id_sha256,
    utc_now_iso,
)
from .datasets import (
    DatasetError,
    FunctionSample,
    LoadedDataset,
    dataset_label_counts,
    load_dataset,
)
from .metrics import compute_metrics, render_markdown
from .prompts import (
    PROMPT_VERSION,
    Prompt,
    PromptError,
    build_prompt,
    load_dev_examples,
)
from .util import atomic_write_json, atomic_write_text, read_json, sha256_file
from .validation import (
    OutputSchemaError,
    validate_detection_output,
    validate_repair_output,
)

logger = logging.getLogger("secvul_runner")

DEFAULT_DEV_EXAMPLES = Path(__file__).with_name("dev_examples.json")
DEFAULT_BASE_URL = "https://api.deepseek.com/v1"


class ExperimentError(RuntimeError):
    """A user-facing configuration or run-state error."""


@dataclass(frozen=True)
class ExperimentSettings:
    dataset: LoadedDataset
    full_unit_count: int
    full_label_counts: dict[str, int]
    strategy: str
    task: str
    api_config: ApiConfig
    api_key_env: str
    out_dir: Path
    dev_examples: Any
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

    def expected_requests(self) -> int:
        return int(self.dataset.expected_counts(self.task)["requests"])


@dataclass(frozen=True)
class RunOutcome:
    out_dir: Path
    status: str
    dry_run: bool
    request_count: int
    manifest_path: Path
    results_path: Path | None
    metrics_path: Path | None
    metrics: dict[str, Any] | None


@dataclass(frozen=True)
class RequestSpec:
    sample: FunctionSample
    task: str
    strategy: str
    prompt: Prompt
    body: dict[str, Any]
    endpoint: str
    request_fingerprint: str
    cache_key: str


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _httpx_version() -> str | None:
    try:
        return importlib.metadata.version("httpx")
    except importlib.metadata.PackageNotFoundError:
        return None


def compute_config_fingerprint(
    *,
    dataset: LoadedDataset,
    strategy: str,
    task: str,
    api_config: ApiConfig,
    dev_examples: Any,
    limit: int,
) -> str:
    identity = {
        "runner_version": __version__,
        "prompt_version": PROMPT_VERSION,
        "cache_schema": 1,
        "dataset_type": dataset.dataset_type,
        "dataset_sha256": dataset.sha256,
        "strategy": strategy,
        "task": task,
        "limit": limit,
        "api_identity": {
            "endpoint": api_config.endpoint,
            "model": api_config.model,
            "temperature": api_config.temperature,
            "max_tokens": api_config.max_tokens,
            "response_format": api_config.response_format,
            **({"thinking": api_config.thinking} if api_config.thinking is not None else {}),
            **(
                {"reasoning_effort": api_config.reasoning_effort}
                if api_config.reasoning_effort is not None
                else {}
            ),
            **(
                {"max_tokens_field": api_config.max_tokens_field}
                if api_config.max_tokens_field != "max_tokens"
                else {}
            ),
        },
        "dev_examples_sha256": None if dev_examples is None else dev_examples.sha256,
    }
    return _sha256_text(canonical_json(identity))


def create_settings(
    *,
    dataset_type: str,
    dataset_path: str | Path,
    strategy: str,
    task: str,
    api_config: ApiConfig,
    api_key_env: str,
    out_dir: str | Path,
    dev_examples_path: str | Path | None,
    limit: int,
    concurrency: int,
    dry_run: bool,
    resume: bool,
    refresh: bool,
    retry_invalid: bool,
    reuse_cached_errors: bool,
    run_label: str | None,
) -> ExperimentSettings:
    if task not in {"detection", "repair", "both"}:
        raise ExperimentError(f"unsupported task {task!r}")
    if strategy not in {"direct", "few-shot", "context"}:
        raise ExperimentError(f"unsupported strategy {strategy!r}")
    if limit < 0:
        raise ExperimentError("--limit must be zero or positive")
    if concurrency < 1 or concurrency > 32:
        raise ExperimentError("--concurrency must be between 1 and 32")
    api_config.validate()
    try:
        full_dataset = load_dataset(dataset_path, dataset_type)
    except DatasetError as exc:
        raise ExperimentError(str(exc)) from exc

    effective_limit = 0 if limit == 0 or limit >= full_dataset.unit_count else limit
    selected = full_dataset.limited(effective_limit)

    dev_examples = None
    if strategy == "few-shot":
        path = Path(dev_examples_path) if dev_examples_path else DEFAULT_DEV_EXAMPLES
        try:
            dev_examples = load_dev_examples(path, full_dataset, task)
        except PromptError as exc:
            raise ExperimentError(str(exc)) from exc
    elif dev_examples_path is not None:
        raise ExperimentError("--dev-examples is only meaningful with --strategy few-shot")

    out = Path(out_dir).expanduser().resolve()
    fingerprint = compute_config_fingerprint(
        dataset=selected,
        strategy=strategy,
        task=task,
        api_config=api_config,
        dev_examples=dev_examples,
        limit=effective_limit,
    )
    return ExperimentSettings(
        dataset=selected,
        full_unit_count=full_dataset.unit_count,
        full_label_counts=dataset_label_counts(full_dataset),
        strategy=strategy,
        task=task,
        api_config=api_config,
        api_key_env=api_key_env,
        out_dir=out,
        dev_examples=dev_examples,
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


def build_request_specs(settings: ExperimentSettings) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for sample, task in settings.dataset.units_for_task(settings.task):
        prompt = build_prompt(sample, task, settings.strategy, settings.dev_examples)
        body = build_body(list(prompt.messages), settings.api_config)
        fingerprint = request_fingerprint(
            endpoint=settings.api_config.endpoint,
            body=body,
            task=task,
            strategy=settings.strategy,
            prompt_version=PROMPT_VERSION,
        )
        cache_key = _sha256_text(
            canonical_json(
                {
                    "sample_id": sample.sample_id,
                    "task": task,
                    "request_fingerprint": fingerprint,
                }
            )
        )
        specs.append(
            RequestSpec(
                sample=sample,
                task=task,
                strategy=settings.strategy,
                prompt=prompt,
                body=body,
                endpoint=settings.api_config.endpoint,
                request_fingerprint=fingerprint,
                cache_key=cache_key,
            )
        )
    expected = settings.expected_requests()
    if len(specs) != expected:
        raise ExperimentError(
            f"planned {len(specs)} requests but dataset/task configuration expects {expected}"
        )
    return specs


def _request_record(
    spec: RequestSpec, index: int, *, session_id: str, user_agent: str
) -> dict[str, Any]:
    return {
        "request_index": index,
        "sample_id": spec.sample.sample_id,
        "pair_id": spec.sample.pair_id,
        "side": spec.sample.side,
        "task": spec.task,
        "strategy": spec.strategy,
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
        "prompt": spec.prompt.metadata,
        "body": spec.body,
    }


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    text = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
    )
    atomic_write_text(path, text)


def _dev_public(settings: ExperimentSettings) -> dict[str, Any] | None:
    dev = settings.dev_examples
    if dev is None:
        return None
    return {
        "path": str(dev.path),
        "sha256": dev.sha256,
        "source": dev.source,
        "detection_example_ids": [item.example_id for item in dev.detection],
        "repair_example_ids": [item.example_id for item in dev.repair],
    }


def _run_meta(settings: ExperimentSettings, *, started_at: str, completed_at: str | None) -> dict[str, Any]:
    counts = settings.dataset.expected_counts(settings.task)
    return {
        "run_id": settings.out_dir.name,
        "run_label": settings.run_label,
        "dataset_type": settings.dataset.dataset_type,
        "dataset_path": str(settings.dataset.path),
        "dataset_sha256": settings.dataset.sha256,
        "dataset_metadata": settings.dataset.metadata,
        "dataset_label_counts": settings.full_label_counts,
        "selected_label_counts": dataset_label_counts(settings.dataset),
        "strategy": settings.strategy,
        "task": settings.task,
        "prompt_version": PROMPT_VERSION,
        "model": settings.api_config.model,
        "base_url": settings.api_config.base_url,
        "endpoint": settings.api_config.endpoint,
        "temperature": settings.api_config.temperature,
        "max_tokens": settings.api_config.max_tokens,
        "response_format": settings.api_config.response_format,
        "thinking": settings.api_config.thinking,
        "reasoning_effort": settings.api_config.reasoning_effort,
        "max_tokens_field": settings.api_config.max_tokens_field,
        "pricing_configured": settings.api_config.price_configured(),
        "input_price_usd_per_1m": settings.api_config.input_price_usd_per_1m,
        "output_price_usd_per_1m": settings.api_config.output_price_usd_per_1m,
        "cached_input_price_usd_per_1m": settings.api_config.cached_input_price_usd_per_1m,
        "limit": settings.limit,
        "partial": settings.partial,
        "selected_units": settings.dataset.unit_count,
        "dataset_units": settings.full_unit_count,
        "expected_requests": settings.expected_requests(),
        "expected_by_task": counts,
        "config_fingerprint": settings.config_fingerprint,
        "dev_examples": _dev_public(settings),
        "started_at": started_at,
        "completed_at": completed_at,
        "runner_version": __version__,
        "python_version": sys.version.split()[0],
        "httpx_version": _httpx_version(),
        "notes": [
            "No API key or Authorization header is stored in run artifacts.",
            "Prompts contain function source and, for context strategy, sanitised context only.",
        ],
    }


def _public_config(settings: ExperimentSettings, *, dry_run: bool) -> dict[str, Any]:
    return {
        "runner_version": __version__,
        "prompt_version": PROMPT_VERSION,
        "dataset_type": settings.dataset.dataset_type,
        "dataset_path": str(settings.dataset.path),
        "dataset_sha256": settings.dataset.sha256,
        "strategy": settings.strategy,
        "task": settings.task,
        "limit": settings.limit,
        "partial": settings.partial,
        "selected_units": settings.dataset.unit_count,
        "dataset_units": settings.full_unit_count,
        "expected_requests": settings.expected_requests(),
        "concurrency": settings.concurrency,
        "dry_run": dry_run,
        "refresh": settings.refresh,
        "retry_invalid": settings.retry_invalid,
        "reuse_cached_errors": settings.reuse_cached_errors,
        "api_key_env": settings.api_key_env,
        "api": settings.api_config.public_dict(),
        "dev_examples": _dev_public(settings),
        "config_fingerprint": settings.config_fingerprint,
    }


def _attach_file_logger(out_dir: Path) -> logging.Handler:
    handler = logging.FileHandler(out_dir / "run.log", encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    return handler


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        value = read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        raise ExperimentError(f"cannot read existing manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExperimentError(f"existing manifest {path} is not a JSON object")
    return value


def _prepare_out_dir(settings: ExperimentSettings) -> tuple[dict[str, Any] | None, str | None]:
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "manifest.json"
    if manifest_path.exists():
        if not settings.resume:
            raise ExperimentError(
                f"{out} already contains a run manifest; use --resume or choose a new --out-dir"
            )
        existing = _read_manifest(manifest_path)
        if existing.get("config_fingerprint") != settings.config_fingerprint:
            raise ExperimentError(
                "cannot resume: the current configuration fingerprint does not match the "
                "existing manifest. Use the original dataset/strategy/task/model/limit and "
                "prompt version, or choose a new --out-dir."
            )
        return existing, existing.get("created_at")
    if settings.resume:
        raise ExperimentError(f"cannot resume: {out} has no manifest.json")
    entries = list(out.iterdir())
    if entries:
        raise ExperimentError(
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


def run_dry_run(settings: ExperimentSettings) -> RunOutcome:
    """Validate prompts and request bodies without any network call or key."""
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    if (out / "manifest.json").exists():
        raise ExperimentError(
            f"{out} contains a real run manifest; choose a separate --out-dir for --dry-run"
        )
    allowed = {"dry_run_requests.jsonl", "dry_run_manifest.json"}
    unexpected = [entry.name for entry in out.iterdir() if entry.name not in allowed]
    if unexpected:
        raise ExperimentError(
            f"{out} contains files that are not dry-run artifacts: {sorted(unexpected)}"
        )

    specs = build_request_specs(settings)
    session_id = generate_session_id()
    session = _session_record(session_id, "generated_for_dry_run")
    request_records = [
        _request_record(
            spec,
            index,
            session_id=session_id,
            user_agent=settings.api_config.user_agent,
        )
        for index, spec in enumerate(specs, start=1)
    ]
    request_path = out / "dry_run_requests.jsonl"
    _write_jsonl(request_path, request_records)
    request_sha = sha256_file(request_path)
    context_used = sum(1 for spec in specs if spec.prompt.metadata["context"].get("used"))
    context_parse_failures = sum(
        1
        for spec in specs
        if spec.prompt.metadata["context"].get("used")
        and not spec.prompt.metadata["context"].get("parse_ok", True)
    )
    by_task: dict[str, int] = {}
    for spec in specs:
        by_task[spec.task] = by_task.get(spec.task, 0) + 1
    dry_manifest = {
        "schema_version": 1,
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
        "requests_by_task": by_task,
        "expected_requests": settings.expected_requests(),
        "requests_file": request_path.name,
        "requests_sha256": request_sha,
        "session": session,
        "context_requests": context_used,
        "context_parse_failures": context_parse_failures,
        "authorization_header_included_in_file": False,
        "api_key_required": False,
        "warnings": [
            "DRY RUN ONLY: no model API was called and no detection/repair metrics were produced.",
            "The request file contains prompts and source code, but no API key.",
        ],
    }
    manifest_path = out / "dry_run_manifest.json"
    atomic_write_json(manifest_path, dry_manifest)
    logger.info("dry run planned %d requests; no API calls made", len(specs))
    return RunOutcome(
        out_dir=out,
        status="dry_run",
        dry_run=True,
        request_count=len(specs),
        manifest_path=manifest_path,
        results_path=None,
        metrics_path=None,
        metrics=None,
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
    settings: ExperimentSettings,
) -> dict[str, Any]:
    cache_path = cache.path_for(settings.dataset.dataset_type, spec.task, spec.cache_key)
    cached = None
    previous_status = None
    if not settings.refresh:
        cached = cache.read(
            dataset_type=settings.dataset.dataset_type,
            task=spec.task,
            key=spec.cache_key,
            request_fingerprint=spec.request_fingerprint,
        )
    if cached is not None:
        previous_status = cached.get("status")
        use_cached = previous_status == "ok"
        use_cached = use_cached or (
            previous_status == "invalid" and not settings.retry_invalid
        )
        use_cached = use_cached or (
            previous_status == "error" and settings.reuse_cached_errors
        )
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

    api_result: ApiCallResult = client.complete(list(spec.prompt.messages))
    response = api_result.to_dict()
    parsed: dict[str, Any] | None = None
    validation: dict[str, Any]
    if api_result.status == "ok":
        try:
            if spec.task == "detection":
                parsed, checks = validate_detection_output(api_result.content or "")
            else:
                parsed, checks = validate_repair_output(
                    api_result.content or "", spec.sample.func_body
                )
            validation = {"schema_valid": True, **checks}
            status = "ok"
        except OutputSchemaError as exc:
            validation = {"schema_valid": False, "error": str(exc)}
            status = "invalid"
    else:
        validation = {"schema_valid": False, "error": "api_error"}
        status = "error"

    created_at = utc_now_iso()
    record: dict[str, Any] = {
        "dataset_type": settings.dataset.dataset_type,
        "sample_id": spec.sample.sample_id,
        "unit_id": spec.sample.unit_id,
        "pair_id": spec.sample.pair_id,
        "side": spec.sample.side,
        "idx": spec.sample.idx,
        "label": spec.sample.label,
        "task": spec.task,
        "strategy": spec.strategy,
        "prompt": spec.prompt.metadata,
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
        "created_at": created_at,
        "completed_at": utc_now_iso(),
    }
    cache.write(
        dataset_type=settings.dataset.dataset_type,
        task=spec.task,
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


def _ordered_records(
    settings: ExperimentSettings,
    specs: list[RequestSpec],
    by_key: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, start=1):
        record = by_key.get((spec.task, spec.sample.sample_id))
        if record is None:
            record = {
                "dataset_type": settings.dataset.dataset_type,
                "sample_id": spec.sample.sample_id,
                "unit_id": spec.sample.unit_id,
                "pair_id": spec.sample.pair_id,
                "side": spec.sample.side,
                "idx": spec.sample.idx,
                "label": spec.sample.label,
                "task": spec.task,
                "strategy": spec.strategy,
                "prompt": spec.prompt.metadata,
                "response": None,
                "status": "missing",
                "parsed": None,
                "validation": {"schema_valid": False, "error": "request_not_recorded"},
                "cache": {"hit": False, "key": spec.cache_key, "file": None},
            }
        record = dict(record)
        record["request_index"] = index
        records.append(record)
    return records


def _run_manifest(
    settings: ExperimentSettings,
    *,
    existing: dict[str, Any] | None,
    created_at: str,
    status: str,
    started_at: str,
    dry_run: bool,
    resume_event: bool,
    session: dict[str, Any],
) -> dict[str, Any]:
    now = utc_now_iso()
    manifest: dict[str, Any] = dict(existing) if existing else {}
    manifest.update(
        {
            "schema_version": 1,
            "run_id": manifest.get("run_id", settings.out_dir.name),
            "run_label": settings.run_label,
            "status": status,
            "created_at": created_at,
            "started_at": started_at,
            "updated_at": now,
            "runner_version": __version__,
            "python_version": sys.version.split()[0],
            "httpx_version": _httpx_version(),
            "platform": platform.platform(),
            "config_fingerprint": settings.config_fingerprint,
            "config": _public_config(settings, dry_run=dry_run),
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
            "concurrency": settings.concurrency,
            "resume": {
                "count": int(manifest.get("resume", {}).get("count", 0)) + (1 if resume_event else 0),
                "events": list(manifest.get("resume", {}).get("events", [])),
            },
            "outputs": {
                "config": "config.json",
                "requests": "requests.jsonl",
                "results": "results.jsonl",
                "metrics_json": "metrics.json",
                "metrics_markdown": "metrics.md",
                "cache": "cache/",
                "log": "run.log",
            },
            "notes": [
                "No API key or Authorization header is stored in run artifacts.",
                "Metrics are null for cost when prices are not configured.",
                "Use --resume with the same command and --out-dir to continue an interrupted run.",
            ],
        }
    )
    if resume_event:
        manifest["resume"]["events"].append(
            {
                "at": now,
                "previous_status": None if existing is None else existing.get("status"),
                "session_id": session["value"],
                "session_source": session["source"],
            }
        )
    return manifest


def run_experiment(settings: ExperimentSettings, api_key: str) -> RunOutcome:
    """Run or resume a real experiment. api_key is never written to disk."""
    if not api_key.strip():
        raise ExperimentError(
            f"API key is empty; set the environment variable named by --api-key-env "
            f"({settings.api_key_env})"
        )
    specs = build_request_specs(settings)
    existing, created = _prepare_out_dir(settings)
    started_at = utc_now_iso()
    created_at = created or started_at
    session_id, session_source = _resolve_session(existing)
    session = _session_record(session_id, session_source)
    manifest_path = settings.out_dir / "manifest.json"
    manifest = _run_manifest(
        settings,
        existing=existing,
        created_at=created_at,
        status="running",
        started_at=started_at,
        dry_run=False,
        resume_event=existing is not None,
        session=session,
    )
    cache = RequestCache(settings.out_dir / "cache")
    log_handler: logging.Handler | None = None
    client: ChatClient | None = None
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        _write_manifest(manifest_path, manifest)
        atomic_write_json(settings.out_dir / "config.json", manifest["config"])
        _write_jsonl(
            settings.out_dir / "requests.jsonl",
            [
                _request_record(
                    spec,
                    index,
                    session_id=session_id,
                    user_agent=settings.api_config.user_agent,
                )
                for index, spec in enumerate(specs, start=1)
            ],
        )
        log_handler = _attach_file_logger(settings.out_dir)
        client = ChatClient(settings.api_config, api_key, session_id=session_id)
        logger.info(
            "starting %d requests: dataset=%s strategy=%s task=%s model=%s concurrency=%d "
            "session=%s",
            len(specs),
            settings.dataset.dataset_type,
            settings.strategy,
            settings.task,
            settings.api_config.model,
            settings.concurrency,
            session_id,
        )
        with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
            futures = {
                pool.submit(
                    _execute_spec,
                    spec,
                    cache=cache,
                    client=client,
                    settings=settings,
                ): spec
                for spec in specs
            }
            completed = 0
            cache_hits = 0
            for future in as_completed(futures):
                spec = futures[future]
                record = future.result()
                by_key[(spec.task, spec.sample.sample_id)] = record
                completed += 1
                if record.get("cache", {}).get("hit"):
                    cache_hits += 1
                if completed == 1 or completed % 10 == 0 or completed == len(specs):
                    logger.info(
                        "progress %d/%d (cache hits during this run: %d)",
                        completed,
                        len(specs),
                        cache_hits,
                    )
        records = _ordered_records(settings, specs, by_key)
        missing = [record["sample_id"] for record in records if record.get("status") == "missing"]
        if missing:
            raise ExperimentError(f"internal error: {len(missing)} requests were not recorded")
        _write_jsonl(settings.out_dir / "results.jsonl", records)
        completed_at = utc_now_iso()
        run_meta = _run_meta(settings, started_at=started_at, completed_at=completed_at)
        metrics = compute_metrics(settings.dataset, records, run_meta=run_meta)
        metrics_path = settings.out_dir / "metrics.json"
        atomic_write_json(metrics_path, metrics)
        atomic_write_text(settings.out_dir / "metrics.md", render_markdown(metrics))
        counts = metrics["counts"]
        manifest["status"] = "completed"
        manifest["completed_at"] = completed_at
        manifest["counts"] = {
            "planned_requests": len(specs),
            "recorded_requests": len(records),
            "cache_hits": counts["cache_hits"],
            "by_status": counts["by_status"],
            "detection": counts["by_task"].get("detection", 0),
            "repair": counts["by_task"].get("repair", 0),
        }
        _write_manifest(manifest_path, manifest)
        logger.info("completed: %d records; metrics written to %s", len(records), metrics_path)
        return RunOutcome(
            out_dir=settings.out_dir,
            status="completed",
            dry_run=False,
            request_count=len(specs),
            manifest_path=manifest_path,
            results_path=settings.out_dir / "results.jsonl",
            metrics_path=metrics_path,
            metrics=metrics,
        )
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["interrupted_at"] = utc_now_iso()
        manifest["counts"] = {"recorded_requests": len(by_key), "planned_requests": len(specs)}
        _write_manifest(manifest_path, manifest)
        logger.warning("interrupted after %d/%d requests; resume with --resume", len(by_key), len(specs))
        raise
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["failed_at"] = utc_now_iso()
        manifest["error"] = {
            "type": type(exc).__name__,
            "message": redact_secrets(str(exc), api_key),
        }
        manifest["counts"] = {"recorded_requests": len(by_key), "planned_requests": len(specs)}
        _write_manifest(manifest_path, manifest)
        logger.exception("run failed after %d/%d requests", len(by_key), len(specs))
        raise
    finally:
        if client is not None:
            client.close()
        if log_handler is not None:
            logger.removeHandler(log_handler)
            log_handler.close()

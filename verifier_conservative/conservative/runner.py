"""Resumable runner for the conservative three-way verifier.

Inputs are frozen artifacts: one first-pass run (``results.jsonl`` from
``evidence_prompt``) and one detection dataset.  Only schema-valid positive
predictions are sent; negatives and invalid first-pass records pass through
unchanged in every downstream view.

All writes stay under ``--out-dir`` (``verifier_conservative/runs/...``).  No
existing run directory is modified, and ``evidence_verify/`` is read-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
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
    generate_session_id,
    is_valid_session_id,
    normalize_endpoint,
    request_fingerprint,
    session_id_sha256,
    utc_now_iso,
)
from secvul_runner.datasets import DatasetError, FunctionSample, LoadedDataset, load_dataset
from secvul_runner.util import atomic_write_json, atomic_write_text, read_json, sha256_file

from . import (
    ANALYSIS_STATUS,
    PACKAGE,
    PROMPT_VERSION,
    STRATEGY,
    TASK,
    __version__,
)
from .decision import decide
from .prompt import ConservativePrompt, build_prompt, prompt_bytes, template_sha256
from .schema import ConservativeSchemaError, validate_conservative_output

logger = logging.getLogger("verifier_conservative")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = PROJECT_ROOT / "splits" / "test_detection_160.json"
DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
CACHE_SCHEMA_VERSION = 1


class RunError(RuntimeError):
    """User-facing configuration or run-state error."""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ClaimRecord:
    sample: FunctionSample
    first_pass_status: str
    first_pass_confidence: float | None
    evidence_lines: tuple[int, ...]
    mechanism: str
    first_pass_run: str


@dataclass(frozen=True)
class RunSettings:
    dataset: LoadedDataset
    claims_path: Path
    claims_sha256: str
    claims: tuple[ClaimRecord, ...]
    api_config: ApiConfig
    api_key_env: str
    out_dir: Path
    concurrency: int
    limit: int
    dry_run: bool
    resume: bool
    run_label: str | None
    config_fingerprint: str
    excluded_first_pass_records: dict[str, int]

    @property
    def expected_requests(self) -> int:
        return len(self.claims)


@dataclass(frozen=True)
class RequestSpec:
    claim: ClaimRecord
    prompt: ConservativePrompt
    body: dict[str, Any]
    endpoint: str
    request_fingerprint: str
    cache_key: str
    prompt_sha256: str


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


def _config_fingerprint(
    *,
    dataset: LoadedDataset,
    claims_sha256: str,
    api_config: ApiConfig,
    limit: int,
) -> str:
    identity = {
        "package": PACKAGE,
        "package_version": __version__,
        "runner_version": runner_version,
        "prompt_version": PROMPT_VERSION,
        "template_sha256": template_sha256(),
        "strategy": STRATEGY,
        "task": TASK,
        "cache_schema": CACHE_SCHEMA_VERSION,
        "dataset_sha256": dataset.sha256,
        "claims_sha256": claims_sha256,
        "limit": limit,
        "api_identity": _api_identity(api_config),
    }
    return _sha256_text(canonical_json(identity))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                raise RunError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise RunError(f"{path}:{line_number}: record is not an object")
            records.append(record)
    if not records:
        raise RunError(f"{path}: no records")
    return records


def load_claims(
    claims_path: Path,
    dataset: LoadedDataset,
    *,
    limit: int = 0,
) -> tuple[tuple[ClaimRecord, ...], dict[str, int]]:
    """Select schema-valid positive predictions and join them to the dataset."""
    rows = _read_jsonl(claims_path)
    by_idx = {sample.idx: sample for sample in dataset.units if isinstance(sample, FunctionSample)}
    positives: list[dict[str, Any]] = []
    excluded = {"invalid_or_error": 0, "negative": 0}
    for row in rows:
        parsed = row.get("parsed")
        if row.get("status") != "ok" or not isinstance(parsed, dict):
            excluded["invalid_or_error"] += 1
            continue
        if parsed.get("is_vulnerable") is not True:
            excluded["negative"] += 1
            continue
        positives.append(row)
    if not positives:
        raise RunError(f"{claims_path}: no schema-valid positive predictions")

    claims: list[ClaimRecord] = []
    run_name = claims_path.parent.name
    for row in positives:
        idx = row.get("idx")
        if not isinstance(idx, int) or isinstance(idx, bool):
            raise RunError(f"{claims_path}: record without an integer idx")
        sample = by_idx.get(idx)
        if sample is None:
            raise RunError(f"{claims_path}: idx {idx} is not in the dataset")
        prompt_meta = row.get("prompt") or {}
        function_meta = prompt_meta.get("function") or {}
        claimed_hash = function_meta.get("code_sha256")
        if claimed_hash != sample.code_sha256:
            raise RunError(
                f"idx {idx}: the first-pass function hash {claimed_hash} does not match the "
                f"dataset function hash {sample.code_sha256}"
            )
        parsed = row["parsed"]
        evidence_lines = parsed.get("evidence_lines")
        mechanism = parsed.get("mechanism")
        if not isinstance(evidence_lines, list) or not isinstance(mechanism, str):
            raise RunError(f"idx {idx}: the first-pass claim is not usable")
        confidence = parsed.get("confidence")
        claims.append(
            ClaimRecord(
                sample=sample,
                first_pass_status=str(row.get("status")),
                first_pass_confidence=float(confidence)
                if isinstance(confidence, (int, float)) and not isinstance(confidence, bool)
                else None,
                evidence_lines=tuple(int(x) for x in evidence_lines),
                mechanism=mechanism,
                first_pass_run=run_name,
            )
        )
    claims.sort(key=lambda claim: claim.sample.idx)
    if limit:
        claims = claims[:limit]
    return tuple(claims), excluded


def build_request_specs(settings: RunSettings) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for claim in settings.claims:
        prompt = build_prompt(claim.sample.func_body, claim.evidence_lines, claim.mechanism)
        body = build_body(list(prompt.messages), settings.api_config)
        fingerprint = request_fingerprint(
            endpoint=settings.api_config.endpoint,
            body=body,
            task=TASK,
            strategy=STRATEGY,
            prompt_version=PROMPT_VERSION,
        )
        cache_key = _sha256_text(
            canonical_json(
                {
                    "sample_id": claim.sample.sample_id,
                    "task": TASK,
                    "request_fingerprint": fingerprint,
                }
            )
        )
        specs.append(
            RequestSpec(
                claim=claim,
                prompt=prompt,
                body=body,
                endpoint=settings.api_config.endpoint,
                request_fingerprint=fingerprint,
                cache_key=cache_key,
                prompt_sha256=_sha256_text(prompt_bytes(prompt).decode("utf-8")),
            )
        )
    if len(specs) != settings.expected_requests:
        raise RunError(
            f"planned {len(specs)} requests but {settings.expected_requests} claims were selected"
        )
    return specs


def create_settings(
    *,
    dataset_path: str | Path,
    claims_path: str | Path,
    api_config: ApiConfig,
    api_key_env: str,
    out_dir: str | Path,
    limit: int,
    concurrency: int,
    dry_run: bool,
    resume: bool,
    run_label: str | None,
) -> RunSettings:
    if limit < 0:
        raise RunError("--limit must be zero or positive")
    if concurrency < 1 or concurrency > 32:
        raise RunError("--concurrency must be between 1 and 32")
    api_config.validate()
    dataset_file = Path(dataset_path)
    try:
        dataset = load_dataset(dataset_file, "independent")
    except DatasetError as exc:
        raise RunError(str(exc)) from exc
    claims_file = Path(claims_path)
    if not claims_file.exists():
        raise RunError(f"claims file does not exist: {claims_file}")
    claims, excluded = load_claims(claims_file, dataset, limit=limit)
    fingerprint = _config_fingerprint(
        dataset=dataset,
        claims_sha256=sha256_file(claims_file),
        api_config=api_config,
        limit=limit,
    )
    return RunSettings(
        dataset=dataset,
        claims_path=claims_file.resolve(),
        claims_sha256=sha256_file(claims_file),
        claims=claims,
        api_config=api_config,
        api_key_env=api_key_env,
        out_dir=Path(out_dir).expanduser().resolve(),
        concurrency=concurrency,
        limit=limit,
        dry_run=dry_run,
        resume=resume,
        run_label=run_label,
        config_fingerprint=fingerprint,
        excluded_first_pass_records=excluded,
    )


def _claim_record(claim: ClaimRecord) -> dict[str, Any]:
    return {
        "first_pass_run": claim.first_pass_run,
        "status": claim.first_pass_status,
        "evidence_lines": list(claim.evidence_lines),
        "mechanism": claim.mechanism,
        "confidence": claim.first_pass_confidence,
    }


def _request_record(spec: RequestSpec, index: int, *, session_id: str) -> dict[str, Any]:
    return {
        "request_index": index,
        "sample_id": spec.claim.sample.sample_id,
        "task": TASK,
        "strategy": STRATEGY,
        "endpoint": spec.endpoint,
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "secvul-eval-conservative-verifier/1.0",
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


def _base_record(spec: RequestSpec, settings: RunSettings) -> dict[str, Any]:
    sample = spec.claim.sample
    return {
        "dataset_type": "independent",
        "sample_id": sample.sample_id,
        "unit_id": sample.unit_id,
        "idx": sample.idx,
        "project": sample.project,
        "label": sample.label,
        "task": TASK,
        "strategy": STRATEGY,
        "first_pass": _claim_record(spec.claim),
        "claim": spec.prompt.claim,
        "prompt": spec.prompt.metadata,
        "prompt_sha256": spec.prompt_sha256,
        "request": {
            "endpoint": spec.endpoint,
            "model": settings.api_config.model,
            "request_fingerprint": spec.request_fingerprint,
            "body_sha256": _sha256_text(canonical_json(spec.body)),
        },
    }


def _write_jsonl(path: Path, records: Sequence[dict[str, Any]]) -> None:
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
            raise RunError(
                f"{out} already contains a manifest; use --resume or a new --out-dir"
            )
        try:
            existing = read_json(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            raise RunError(f"cannot read {manifest_path}: {exc}") from exc
        if not isinstance(existing, dict):
            raise RunError(f"{manifest_path} is not a JSON object")
        if existing.get("config_fingerprint") != settings.config_fingerprint:
            raise RunError(
                "cannot resume: configuration fingerprint differs from the existing manifest"
            )
        return existing, existing.get("created_at")
    if settings.resume:
        raise RunError(f"cannot resume: {out} has no manifest.json")
    entries = list(out.iterdir())
    if entries:
        raise RunError(f"{out} is not empty and has no run manifest")
    return None, None


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
        "note": "Random per-run routing identifier; not an API key.",
    }


def _public_config(settings: RunSettings) -> dict[str, Any]:
    return {
        "package": PACKAGE,
        "package_version": __version__,
        "runner_version": runner_version,
        "prompt_version": PROMPT_VERSION,
        "strategy": STRATEGY,
        "task": TASK,
        "template_sha256": template_sha256(),
        "concurrency": settings.concurrency,
        "limit": settings.limit,
        "api": settings.api_config.public_dict(),
        "claims_source": str(settings.claims_path),
        "decision_rule": {
            "retract_only": ["guard_present", "counterexample"],
            "requires_grounded_code_line": True,
            "guard_lexical_check": True,
            "insufficient_or_failure": "keep_first_pass_prediction",
            "fail_closed": False,
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
            "artifact": "verifier_conservative_run",
            "run_id": manifest.get("run_id", settings.out_dir.name),
            "run_label": settings.run_label,
            "status": status,
            "created_at": created_at,
            "started_at": started_at,
            "updated_at": utc_now_iso(),
            "package_version": __version__,
            "runner_version": runner_version,
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "analysis_status": ANALYSIS_STATUS,
            "config_fingerprint": settings.config_fingerprint,
            "config": _public_config(settings),
            "dataset": {
                "type": settings.dataset.dataset_type,
                "path": str(settings.dataset.path),
                "sha256": settings.dataset.sha256,
                "metadata": settings.dataset.metadata,
            },
            "claims": {
                "path": str(settings.claims_path),
                "sha256": settings.claims_sha256,
                "selected_positives": len(settings.claims),
                "excluded_first_pass_records": settings.excluded_first_pass_records,
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
            "network": {
                "ipv4_only_resolution": os.environ.get("SECVUL_IPV4_ONLY") == "1",
                "proxy_env_present": any(
                    os.environ.get(key)
                    for key in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
                ),
            },
            "prompt_input_fields": ["func_body", "claim.evidence_lines", "claim.mechanism"],
            "context_used": False,
            "notes": [
                "No API key or Authorization header is stored in run artifacts.",
                "The verifier sees the numbered function source and one prior positive claim; "
                "it never sees the label, project, changed lines, or first-pass confidence.",
                "Only schema-valid positive first-pass predictions are sent; negatives and "
                "invalid records are untouched.",
                "Retraction requires assessment=unsupported with a grounded guard_present or "
                "counterexample; insufficient and verifier failures keep the first-pass "
                "prediction (no fail-closed).",
                "The 160 test functions were already used to evaluate the first pass and the "
                "original verifier, so this experiment is exploratory and not an independent "
                "confirmation.",
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
            "retracted": summary["retract"],
        }
    return manifest


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    manifest["updated_at"] = utc_now_iso()
    atomic_write_json(path, manifest)


def _execute_spec(
    spec: RequestSpec,
    *,
    cache: RequestCache,
    client: ChatClient,
    settings: RunSettings,
) -> dict[str, Any]:
    cache_path = cache.path_for("independent", TASK, spec.cache_key)
    cached = cache.read(
        dataset_type="independent",
        task=TASK,
        key=spec.cache_key,
        request_fingerprint=spec.request_fingerprint,
    )
    previous_status = None
    if isinstance(cached, dict):
        previous_status = cached.get("status")
        if previous_status in {"ok", "invalid"}:
            record = dict(cached)
            record.pop("cache_schema_version", None)
            record.pop("cache_key", None)
            record.pop("request_fingerprint", None)
            record["cache"] = {
                "hit": True,
                "key": spec.cache_key,
                "file": str(cache_path.relative_to(settings.out_dir)),
                "previous_status": previous_status,
            }
            return record

    record = _base_record(spec, settings)
    try:
        api_result: ApiCallResult = client.complete(list(spec.prompt.messages))
    except Exception as exc:  # noqa: BLE001 - record the failure, do not fabricate
        logger.exception("unexpected client failure for %s", spec.claim.sample.sample_id)
        parsed = None
        validation = {
            "schema_valid": False,
            "error": "unexpected_client_exception",
            "error_family": "client",
            "detail": f"{type(exc).__name__}: {exc}",
        }
        status = "error"
        retract, reason = decide(status, parsed, validation)
        record.update(
            {
                "response": None,
                "status": status,
                "parsed": parsed,
                "validation": validation,
                "decision": {"retract": retract, "reason": reason},
                "created_at": utc_now_iso(),
                "completed_at": utc_now_iso(),
            }
        )
        cache.write(
            dataset_type="independent",
            task=TASK,
            key=spec.cache_key,
            request_fingerprint=spec.request_fingerprint,
            record=record,
        )
        record["cache"] = {
            "hit": False,
            "key": spec.cache_key,
            "file": str(cache_path.relative_to(settings.out_dir)),
            "previous_status": previous_status,
        }
        return record

    response = api_result.to_dict()
    parsed: dict[str, Any] | None = None
    if api_result.status == "ok":
        try:
            parsed, checks = validate_conservative_output(
                api_result.content or "", spec.prompt.line_texts
            )
            validation = checks
            status = "ok"
        except ConservativeSchemaError as exc:
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

    retract, reason = decide(status, parsed, validation)
    record.update(
        {
            "response": response,
            "status": status,
            "parsed": parsed,
            "validation": validation,
            "decision": {"retract": retract, "reason": reason},
            "created_at": utc_now_iso(),
            "completed_at": utc_now_iso(),
        }
    )
    cache.write(
        dataset_type="independent",
        task=TASK,
        key=spec.cache_key,
        request_fingerprint=spec.request_fingerprint,
        record=record,
    )
    record["cache"] = {
        "hit": False,
        "key": spec.cache_key,
        "file": str(cache_path.relative_to(settings.out_dir)),
        "previous_status": previous_status,
    }
    return record


def _ordered_records(
    specs: Sequence[RequestSpec],
    by_id: dict[str, dict[str, Any]],
    settings: RunSettings,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, start=1):
        record = by_id.get(spec.claim.sample.sample_id)
        if record is None:
            record = _base_record(spec, settings)
            record.update(
                {
                    "response": None,
                    "status": "error",
                    "parsed": None,
                    "validation": {
                        "schema_valid": False,
                        "error": "request_not_recorded",
                        "error_family": "missing",
                    },
                    "decision": {"retract": False, "reason": "keep_verifier_failure"},
                    "created_at": utc_now_iso(),
                    "completed_at": utc_now_iso(),
                }
            )
        record = dict(record)
        record["request_index"] = index
        records.append(record)
    return records


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _summary(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    ok = [record for record in records if record.get("status") == "ok"]
    retract_records = [record for record in ok if (record.get("decision") or {}).get("retract")]
    tp_retract = sum(1 for record in retract_records if bool(record.get("label")))
    fp_retract = sum(1 for record in retract_records if not bool(record.get("label")))
    by_status: dict[str, int] = {}
    by_assessment: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_decision: dict[str, int] = {}
    for record in records:
        key = str(record.get("status"))
        by_status[key] = by_status.get(key, 0) + 1
        if record.get("status") == "ok" and isinstance(record.get("parsed"), dict):
            parsed = record["parsed"]
            assessment = str(parsed.get("assessment"))
            kind = str(parsed.get("rebuttal_kind"))
            by_assessment[assessment] = by_assessment.get(assessment, 0) + 1
            by_kind[kind] = by_kind.get(kind, 0) + 1
        decision = str((record.get("decision") or {}).get("reason"))
        by_decision[decision] = by_decision.get(decision, 0) + 1
    costs = [
        (record.get("response") or {}).get("cost", {}).get("cost_usd")
        for record in records
        if isinstance(record.get("response"), dict)
    ]
    known_costs = [float(value) for value in costs if isinstance(value, (int, float))]
    latencies = [
        float(record["response"]["request_latency_seconds"])
        for record in records
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("request_latency_seconds"), (int, float))
    ]
    return {
        "records": len(records),
        "valid": len(ok),
        "coverage": len(ok) / len(records) if records else None,
        "by_status": by_status,
        "by_assessment": by_assessment,
        "by_rebuttal_kind": by_kind,
        "by_decision_reason": by_decision,
        "supported": by_assessment.get("supported", 0),
        "unsupported": by_assessment.get("unsupported", 0),
        "insufficient": by_assessment.get("insufficient", 0),
        "retract": len(retract_records),
        "retract_rate_of_verified": len(retract_records) / len(ok) if ok else None,
        "tp_retracted": tp_retract,
        "fp_retracted": fp_retract,
        "retraction_precision_fp_share": (fp_retract / len(retract_records))
        if retract_records
        else None,
        "cost": {
            "total_cost_usd": round(sum(known_costs), 12) if known_costs else None,
            "requests_with_cost": len(known_costs),
        },
        "latency_seconds": {
            "mean": sum(latencies) / len(latencies) if latencies else None,
            "p50": _percentile(latencies, 0.5),
            "p95": _percentile(latencies, 0.95),
            "max": max(latencies) if latencies else None,
        },
    }


def _fail_manifest(
    settings: RunSettings,
    *,
    existing: dict[str, Any] | None,
    created_at: str,
    started_at: str,
    session: dict[str, Any],
    error: str,
) -> None:
    manifest = _manifest(
        settings,
        existing=existing,
        created_at=created_at,
        status="failed",
        started_at=started_at,
        session=session,
    )
    manifest["error"] = error
    _write_manifest(settings.out_dir / "manifest.json", manifest)


def run_dry_run(settings: RunSettings) -> dict[str, Any]:
    out = settings.out_dir
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise RunError(f"{out} is not empty; choose a new --out-dir for the dry run")
    specs = build_request_specs(settings)
    session = _session_record(generate_session_id(), "generated")
    requests_path = out / "dry_run_requests.jsonl"
    _write_jsonl(
        requests_path,
        [
            _request_record(spec, index, session_id=session["value"])
            for index, spec in enumerate(specs, 1)
        ],
    )
    manifest = _manifest(
        settings,
        existing=None,
        created_at=utc_now_iso(),
        status="dry_run",
        started_at=utc_now_iso(),
        session=session,
    )
    manifest["dry_run_file"] = requests_path.name
    manifest["dry_run_sha256"] = sha256_file(requests_path)
    manifest["api_key_present"] = bool(os.environ.get(settings.api_key_env, "").strip())
    _write_manifest(out / "manifest.json", manifest)
    return {
        "status": "dry_run",
        "requests": len(specs),
        "out_dir": str(out),
        "dry_run_sha256": manifest["dry_run_sha256"],
    }


def run_experiment(settings: RunSettings, api_key: str) -> dict[str, Any]:
    out = settings.out_dir
    existing, created_at = _prepare_out_dir(settings)
    created_at = created_at or utc_now_iso()
    started_at = utc_now_iso()
    specs = build_request_specs(settings)
    session_id, session_source = _resolve_session(existing)
    session = _session_record(session_id, session_source)
    manifest_path = out / "manifest.json"

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
        _fail_manifest(
            settings,
            existing=existing,
            created_at=created_at,
            started_at=started_at,
            session=session,
            error=f"environment variable {settings.api_key_env} is empty",
        )
        raise RunError(f"environment variable {settings.api_key_env} is empty")

    cache = RequestCache(out / "cache")
    by_id: dict[str, dict[str, Any]] = {}
    logger.info(
        "starting %d conservative verifier requests with %s on %s (concurrency=%d)",
        len(specs),
        settings.api_config.model,
        settings.dataset.path,
        settings.concurrency,
    )
    try:
        with ChatClient(settings.api_config, api_key, session_id=session_id) as client:
            if settings.concurrency == 1:
                for spec in specs:
                    record = _execute_spec(spec, cache=cache, client=client, settings=settings)
                    by_id[spec.claim.sample.sample_id] = record
                    logger.info(
                        "recorded %s status=%s decision=%s",
                        spec.claim.sample.sample_id,
                        record.get("status"),
                        (record.get("decision") or {}).get("reason"),
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
                        by_id[spec.claim.sample.sample_id] = future.result()
                        completed += 1
                        if completed % 10 == 0 or completed == len(specs):
                            logger.info("completed %d/%d requests", completed, len(specs))
    except Exception as exc:  # noqa: BLE001 - surface the failure in the manifest
        _fail_manifest(
            settings,
            existing=existing,
            created_at=created_at,
            started_at=started_at,
            session=session,
            error=f"{type(exc).__name__}: {exc}",
        )
        raise

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
    return {"status": "completed", "records": len(records), "summary": summary, "out_dir": str(out)}


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-file", default=str(DEFAULT_DATASET))
    parser.add_argument("--claims-from", required=True, help="first-pass results.jsonl")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--run-label", default=None)
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default=os.environ.get("SECVUL_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-key-env", default="OPENCODE_API_KEY")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument(
        "--max-tokens-field", default="max_tokens", choices=["max_tokens", "max_completion_tokens"]
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--thinking", default=None, choices=[None, "default", "enabled", "disabled"])
    parser.add_argument("--reasoning-effort", default=None)
    parser.add_argument("--input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--output-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--cached-input-price-usd-per-1m", type=float, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        endpoint = normalize_endpoint(args.base_url)
        api_config = ApiConfig(
            base_url=args.base_url,
            endpoint=endpoint,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout_seconds=args.timeout,
            thinking=args.thinking,
            reasoning_effort=args.reasoning_effort,
            max_tokens_field=args.max_tokens_field,
            input_price_usd_per_1m=args.input_price_usd_per_1m,
            output_price_usd_per_1m=args.output_price_usd_per_1m,
            cached_input_price_usd_per_1m=args.cached_input_price_usd_per_1m,
        )
        settings = create_settings(
            dataset_path=args.dataset_file,
            claims_path=args.claims_from,
            api_config=api_config,
            api_key_env=args.api_key_env,
            out_dir=args.out_dir,
            limit=args.limit,
            concurrency=args.concurrency,
            dry_run=args.dry_run,
            resume=args.resume,
            run_label=args.run_label,
        )
    except (RunError, ApiConfigurationError, ValueError) as exc:
        logger.error("%s", exc)
        return 2

    try:
        if settings.dry_run:
            result = run_dry_run(settings)
        else:
            api_key = os.environ.get(settings.api_key_env, "")
            result = run_experiment(settings, api_key)
    except RunError as exc:
        logger.error("%s", exc)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"completed", "dry_run"} else 1


if __name__ == "__main__":
    sys.exit(main())

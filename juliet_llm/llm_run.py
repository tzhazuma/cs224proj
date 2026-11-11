"""Execute real Chat Completions requests for the Juliet binary task.

The API client, retry policy, usage parsing, and secret redaction are imported
from ``runner/secvul_runner``; this module only owns the Juliet-specific request
loop and the run artefacts.  The API key is read from an environment variable
that ``runner/run_with_kimi_config.py`` populates from the Kimi Code config.
The key is never printed, logged, or written to disk.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_DIR = PROJECT_ROOT / "runner"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from secvul_runner.client import (  # noqa: E402
    ApiConfig,
    ChatClient,
    build_body,
    canonical_json,
    generate_session_id,
    normalize_endpoint,
    session_id_sha256,
    utc_now_iso,
)

from .cleaning import sha256_text  # noqa: E402
from .metrics import (  # noqa: E402
    aggregate_run,
    evaluate,
    markdown_report,
    parse_verdict,
    SchemaError,
)
from .prompting import PROMPT_VERSION  # noqa: E402

LOGGER = logging.getLogger("juliet_llm")

DEFAULT_BASE_URL = "https://opencode.ai/zen/go/v1"
CATALOG_URL = "https://opencode.ai/zen/go/v1/models"
DS_USER_AGENT = "juliet-llm-eval/1.0"

PRICE_DEFAULTS: dict[str, tuple[float, float, float | None]] = {
    "deepseek-v4.1-flash": (0.15, 0.60, 0.003),
    "mimo-v2.6-flash": (0.14, 0.28, 0.0028),
}
MODEL_PRESETS: dict[str, dict[str, Any]] = {
    "mimo-v2.6-flash": {
        "thinking": "disabled",
        "reasoning_effort": "none",
        "max_tokens_field": "max_completion_tokens",
    },
    "deepseek-v4.1-flash": {
        "thinking": None,
        "reasoning_effort": None,
        "max_tokens_field": "max_tokens",
    },
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_inputs(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    if not records:
        raise ValueError(f"{path}: no input records")
    if len(records) != len({record["unit_id"] for record in records}):
        raise ValueError(f"{path}: duplicate unit_id")
    return records


def _stratum(record: dict[str, Any]) -> tuple[str, str]:
    return (record["label"], record["language"])


def select_records(
    records: list[dict[str, Any]],
    *,
    split: str | None,
    limit: int | None,
    sample_per_stratum: int | None,
    unit_ids: list[str] | None,
) -> list[dict[str, Any]]:
    selected = [record for record in records if split is None or record["split"] == split]
    if unit_ids:
        wanted = set(unit_ids)
        selected = [record for record in selected if record["unit_id"] in wanted]
        missing = wanted - {record["unit_id"] for record in selected}
        if missing:
            raise ValueError(f"unknown unit ids: {sorted(missing)}")
    selected.sort(key=lambda record: record["unit_id"])
    if sample_per_stratum is not None:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for record in selected:
            groups.setdefault(_stratum(record), []).append(record)
        sampled: list[dict[str, Any]] = []
        for key in sorted(groups):
            group = groups[key]
            count = min(sample_per_stratum, len(group))
            if count:
                step = len(group) / count
                sampled.extend(group[int(index * step)] for index in range(count))
        selected = sorted(sampled, key=lambda record: record["unit_id"])
    if limit is not None:
        selected = selected[:limit]
    if not selected:
        raise ValueError("selection produced no records")
    return selected


def fetch_catalog(model: str) -> dict[str, Any] | None:
    request = urllib.request.Request(
        CATALOG_URL,
        headers={"User-Agent": DS_USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        LOGGER.warning("model catalog unavailable: %s", type(exc).__name__)
        return None
    for entry in payload.get("data", []):
        if isinstance(entry, dict) and entry.get("id") == model:
            return entry
    LOGGER.warning("model %s not present in catalog", model)
    return None


def resolve_prices(
    model: str,
    catalog: dict[str, Any] | None,
    args: argparse.Namespace,
) -> tuple[float, float, float | None, str]:
    if args.input_price is not None or args.output_price is not None:
        if args.input_price is None or args.output_price is None:
            raise ValueError("--input-price and --output-price must be given together")
        return (
            float(args.input_price),
            float(args.output_price),
            float(args.cached_input_price) if args.cached_input_price is not None else None,
            "command_line",
        )
    if catalog:
        try:
            text = catalog["cost"]["text"]
            input_price = float(text["input"]["price"])
            cached = text["input"].get("cache", {}).get("read")
            output_price = float(text["output"]["price"])
            return (
                input_price,
                output_price,
                float(cached) if cached is not None else None,
                f"{CATALOG_URL} snapshot {now_utc()}",
            )
        except (KeyError, TypeError, ValueError):
            LOGGER.warning("catalog entry for %s has no usable price", model)
    if model in PRICE_DEFAULTS:
        input_price, output_price, cached = PRICE_DEFAULTS[model]
        return input_price, output_price, cached, "built_in_default_snapshot_2026-11-12"
    raise ValueError(
        f"no price known for {model}; pass --input-price/--output-price explicitly"
    )


def _preset(model: str) -> dict[str, Any]:
    return MODEL_PRESETS.get(
        model,
        {"thinking": None, "reasoning_effort": None, "max_tokens_field": "max_tokens"},
    )


def build_api_config(
    *,
    model: str,
    base_url: str,
    max_tokens: int,
    timeout: float,
    max_attempts: int,
    thinking: str | None,
    reasoning_effort: str | None,
    max_tokens_field: str,
    prices: tuple[float, float, float | None],
) -> ApiConfig:
    endpoint = normalize_endpoint(base_url)
    config = ApiConfig(
        base_url=base_url,
        endpoint=endpoint,
        model=model,
        temperature=0.0,
        max_tokens=max_tokens,
        timeout_seconds=timeout,
        max_attempts=max_attempts,
        response_format="json_object",
        thinking=thinking,
        reasoning_effort=reasoning_effort,
        max_tokens_field=max_tokens_field,
        user_agent=DS_USER_AGENT,
        input_price_usd_per_1m=prices[0],
        output_price_usd_per_1m=prices[1],
        cached_input_price_usd_per_1m=prices[2],
    )
    config.validate()
    return config


def _api_result_record(
    *,
    index: int,
    input_record: dict[str, Any],
    result: Any,
) -> dict[str, Any]:
    parsed: dict[str, Any] | None = None
    validation: dict[str, Any]
    if result.status == "ok":
        try:
            parsed = parse_verdict(result.content)
            validation = {"schema_valid": True, "error": None}
            status = "ok"
        except SchemaError as exc:
            validation = {"schema_valid": False, "error": str(exc)}
            status = "invalid"
    else:
        validation = {
            "schema_valid": False,
            "error": (result.error or {}).get("type", "api_error"),
        }
        status = "error"

    usage = result.usage or {}
    opencode = usage.get("opencode") if isinstance(usage, dict) else None
    cost = dict(result.cost)
    cost["api_list_cost_usd"] = (
        opencode.get("list_cost") if isinstance(opencode, dict) else None
    )
    cost["api_allowance_usd"] = (
        opencode.get("allowance") if isinstance(opencode, dict) else None
    )
    cost["api_billing_source"] = (
        opencode.get("billing_source") if isinstance(opencode, dict) else None
    )

    y_true = 1 if input_record["label"] == "bad" else 0
    return {
        "request_index": index,
        "unit_id": input_record["unit_id"],
        "group_id": input_record["group_id"],
        "split": input_record["split"],
        "label": input_record["label"],
        "language": input_record["language"],
        "variant": input_record["variant"],
        "y_true": y_true,
        "prompt_sha256": input_record["prompt_sha256"],
        "code_sha256": input_record["code_sha256"],
        "status": status,
        "valid": status == "ok",
        "y_pred": (1 if parsed["label"] == "vulnerable" else 0) if parsed else None,
        "parsed": parsed,
        "validation": validation,
        "response": result.to_dict(),
        "cost": cost,
        "created_at": utc_now_iso(),
    }


def _error_record(
    *,
    index: int,
    input_record: dict[str, Any],
    error: Exception,
) -> dict[str, Any]:
    return {
        "request_index": index,
        "unit_id": input_record["unit_id"],
        "group_id": input_record["group_id"],
        "split": input_record["split"],
        "label": input_record["label"],
        "language": input_record["language"],
        "variant": input_record["variant"],
        "y_true": 1 if input_record["label"] == "bad" else 0,
        "prompt_sha256": input_record["prompt_sha256"],
        "code_sha256": input_record["code_sha256"],
        "status": "error",
        "valid": False,
        "y_pred": None,
        "parsed": None,
        "validation": {"schema_valid": False, "error": "internal_error"},
        "response": {
            "status": "error",
            "http_status": None,
            "content": None,
            "usage": None,
            "raw_body": None,
            "attempts": [],
            "request_latency_seconds": None,
            "wall_seconds": None,
            "error": {"type": "internal_error", "message": type(error).__name__},
            "response_meta": {},
            "cost": {"cost_usd": None, "cost_basis": "internal_error"},
        },
        "cost": {
            "cost_usd": None,
            "api_list_cost_usd": None,
            "api_allowance_usd": None,
            "api_billing_source": None,
        },
        "created_at": utc_now_iso(),
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def execute(
    *,
    inputs_path: Path,
    records: list[dict[str, Any]],
    config: ApiConfig,
    api_key: str,
    out_dir: Path,
    concurrency: int,
    kind: str,
    catalog: dict[str, Any] | None,
    price_source: str,
    extra: dict[str, Any] | None = None,
) -> Path:
    if out_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing run directory: {out_dir}")
    out_dir.mkdir(parents=True)
    log_handler = logging.FileHandler(out_dir / "run.log", encoding="utf-8")
    log_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    LOGGER.addHandler(log_handler)
    LOGGER.setLevel(logging.INFO)

    session_id = generate_session_id()
    client = ChatClient(config, api_key, session_id=session_id)
    started_at = now_utc()
    results: list[dict[str, Any] | None] = [None] * len(records)
    body_hashes: dict[int, str] = {}

    def work(index: int, record: dict[str, Any]) -> dict[str, Any]:
        body = build_body(record["messages"], config)
        body_hashes[index] = sha256_text(canonical_json(body))
        try:
            result = client.complete(record["messages"])
        except Exception as exc:  # noqa: BLE001 - preserve the run, record the error
            LOGGER.exception("request %s failed", record["unit_id"])
            return _error_record(index=index, input_record=record, error=exc)
        return _api_result_record(
            index=index,
            input_record=record,
            result=result,
        )

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(work, index, record): index
            for index, record in enumerate(records)
        }
        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()
            completed += 1
            if completed % 10 == 0 or completed == len(records):
                LOGGER.info("completed %d/%d requests", completed, len(records))
    client.close()

    final = [record for record in results if record is not None]
    if len(final) != len(records):
        raise RuntimeError("internal error: missing request records")
    _write_jsonl(out_dir / "results.jsonl", final)
    _write_jsonl(out_dir / "inputs.jsonl", records)
    selected_payload = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        for record in records
    )
    _write_jsonl(
        out_dir / "predictions.jsonl",
        [
            {
                "unit_id": record["unit_id"],
                "y_true": record["y_true"],
                "y_pred": record["y_pred"],
                "valid": record["valid"],
                "label": record["parsed"]["label"] if record["parsed"] else None,
                "confidence": record["parsed"]["confidence"] if record["parsed"] else None,
            }
            for record in final
        ],
    )

    valid_count = sum(1 for record in final if record["valid"])
    manifest = {
        "run_id": out_dir.name,
        "kind": kind,
        "model": config.model,
        "api": config.public_dict(),
        "prompt_version": PROMPT_VERSION,
        "user_agent": DS_USER_AGENT,
        "inputs": {
            "path": str(inputs_path),
            "sha256": sha256_text(inputs_path.read_text(encoding="utf-8")),
            "selected_sha256": sha256_text(selected_payload),
            "units": len(records),
        },
        "expected_requests": len(records),
        "recorded_requests": len(final),
        "valid_answers": valid_count,
        "invalid_answers": sum(
            1 for record in final if record["status"] == "invalid"
        ),
        "api_errors": sum(1 for record in final if record["status"] == "error"),
        "concurrency": concurrency,
        "session_id_sha256": session_id_sha256(session_id),
        "started_at_utc": started_at,
        "completed_at_utc": now_utc(),
        "price_source": price_source,
        "prices_usd_per_1m": {
            "input": config.input_price_usd_per_1m,
            "output": config.output_price_usd_per_1m,
            "cached_input": config.cached_input_price_usd_per_1m,
        },
        "model_catalog": catalog,
        "code_sha256": {
            "llm_run.py": sha256_text(Path(__file__).read_text(encoding="utf-8")),
            "metrics.py": sha256_text(
                (PROJECT_ROOT / "juliet_llm" / "metrics.py").read_text(encoding="utf-8")
            ),
            "cleaning.py": sha256_text(
                (PROJECT_ROOT / "juliet_llm" / "cleaning.py").read_text(encoding="utf-8")
            ),
            "prompting.py": sha256_text(
                (PROJECT_ROOT / "juliet_llm" / "prompting.py").read_text(encoding="utf-8")
            ),
        },
        "request_body_sha256": {
            record["unit_id"]: body_hashes[index]
            for index, record in enumerate(final)
        },
        "partial": False,
    }
    if extra:
        manifest.update(extra)
    _write_json(out_dir / "manifest.json", manifest)

    evaluation = evaluate(final)
    aggregate = aggregate_run(final)
    _write_json(
        out_dir / "metrics.json",
        {"manifest": manifest, "evaluation": evaluation, "aggregate": aggregate},
    )
    (out_dir / "metrics.md").write_text(
        markdown_report(
            title=f"Juliet LLM binary detection — {config.model}",
            manifest=manifest,
            metrics=evaluation,
            aggregate=aggregate,
        ),
        encoding="utf-8",
    )
    LOGGER.info(
        "run complete: %s valid=%d/%d strict_acc=%s",
        out_dir,
        valid_count,
        len(final),
        evaluation["strict"]["accuracy"],
    )
    LOGGER.removeHandler(log_handler)
    log_handler.close()
    return out_dir


BUILD_DIR = PROJECT_ROOT / "juliet_llm" / "build"
RUNS_DIR = PROJECT_ROOT / "juliet_llm" / "runs"


def resolve_api_key(env_name: str) -> str:
    value = os.environ.get(env_name, "")
    if not value.strip():
        raise SystemExit(
            f"environment variable {env_name} is empty; launch API runs through "
            "runner/run_with_kimi_config.py so the key is loaded without being printed"
        )
    return value.strip()


def default_out_dir(kind: str, model: str, split: str, tag: str | None) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = RUNS_DIR / f"{stamp}_{kind}_{model}_{split}"
    if tag:
        base = base.with_name(f"{base.name}_{tag}")
    candidate = base
    counter = 2
    while candidate.exists():
        candidate = base.with_name(f"{base.name}_{counter}")
        counter += 1
    return candidate


def _selection_info(args: argparse.Namespace, selected: int, total: int) -> dict[str, Any]:
    return {
        "split": args.split,
        "limit": args.limit,
        "sample_per_stratum": args.sample_per_stratum,
        "unit_ids": args.unit_id or None,
        "selected_units": selected,
        "available_units": total,
        "partial": bool(
            args.limit is not None
            or args.sample_per_stratum is not None
            or args.unit_id
        ),
    }


def run_cli(args: argparse.Namespace) -> int:
    if args.inputs:
        inputs_path = Path(args.inputs)
        records = load_inputs(inputs_path)
    else:
        inputs_path = BUILD_DIR / f"{args.split}.jsonl"
        records = load_inputs(inputs_path)
    selected = select_records(
        records,
        split=args.split,
        limit=args.limit,
        sample_per_stratum=args.sample_per_stratum,
        unit_ids=args.unit_id,
    )
    catalog = fetch_catalog(args.model)
    prices = resolve_prices(args.model, catalog, args)
    preset = _preset(args.model)

    thinking = preset["thinking"] if args.thinking == "preset" else (
        None if args.thinking == "omit" else args.thinking
    )
    reasoning = preset["reasoning_effort"] if args.reasoning_effort == "preset" else (
        None if args.reasoning_effort == "omit" else args.reasoning_effort
    )
    field = preset["max_tokens_field"] if args.max_tokens_field == "preset" else args.max_tokens_field

    base_url = args.base_url or os.environ.get("SECVUL_BASE_URL") or DEFAULT_BASE_URL
    config = build_api_config(
        model=args.model,
        base_url=base_url,
        max_tokens=args.max_tokens,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        thinking=thinking,
        reasoning_effort=reasoning,
        max_tokens_field=field,
        prices=(prices[0], prices[1], prices[2]),
    )
    api_key = resolve_api_key(args.api_key_env)
    out_dir = Path(args.out_dir) if args.out_dir else default_out_dir(
        args.kind, args.model, args.split, args.tag
    )
    selection = _selection_info(args, len(selected), len(records))
    extra = {
        "selection": selection,
        "partial": selection["partial"],
        "prices_source": prices[3],
    }
    execute(
        inputs_path=inputs_path,
        records=selected,
        config=config,
        api_key=api_key,
        out_dir=out_dir,
        concurrency=args.concurrency,
        kind=args.kind,
        catalog=catalog,
        price_source=prices[3],
        extra=extra,
    )
    return 0


def _probe_units(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def parts(record: dict[str, Any]) -> int:
        return record["messages"][1]["content"].count("// ---- part")

    chosen: list[dict[str, Any]] = []
    wanted = [
        ("bad", "cpp", True),
        ("bad", "c", False),
        ("good", "cpp", True),
        ("good", "c", False),
    ]
    for label, language, multi in wanted:
        for record in sorted(records, key=lambda item: item["unit_id"]):
            if record["split"] != "dev":
                continue
            if record["label"] != label or record["language"] != language:
                continue
            if (parts(record) > 1) != multi:
                continue
            if record not in chosen:
                chosen.append(record)
                break
    if len(chosen) != 4:
        chosen = sorted(records, key=lambda item: item["unit_id"])[:4]
    return chosen


def _probe_summary(run_dir: Path) -> dict[str, Any]:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    records = [
        json.loads(line)
        for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    samples = []
    for record in records:
        usage = (record.get("response") or {}).get("usage") or {}
        samples.append(
            {
                "unit_id": record["unit_id"],
                "status": record["status"],
                "valid": record["valid"],
                "label": record["parsed"]["label"] if record.get("parsed") else None,
                "content": (record.get("response") or {}).get("content"),
                "reasoning_tokens": (
                    (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
                ),
                "finish_reason": (
                    (record.get("response") or {}).get("response_meta") or {}
                ).get("finish_reason"),
                "latency_seconds": (record.get("response") or {}).get("wall_seconds"),
            }
        )
    return {
        "run_id": manifest["run_id"],
        "run_dir": str(run_dir),
        "model": manifest["model"],
        "api": {
            "base_url": manifest["api"]["base_url"],
            "max_tokens": manifest["api"]["max_tokens"],
            "max_tokens_field": manifest["api"]["max_tokens_field"],
            "thinking": manifest["api"]["thinking"],
            "reasoning_effort": manifest["api"]["reasoning_effort"],
            "timeout_seconds": manifest["api"]["timeout_seconds"],
            "max_attempts": manifest["api"]["max_attempts"],
        },
        "valid": manifest["valid_answers"],
        "records": manifest["recorded_requests"],
        "evaluation": metrics["evaluation"],
        "aggregate": metrics["aggregate"],
        "samples": samples,
    }


def probe_cli(args: argparse.Namespace) -> int:
    inputs_path = BUILD_DIR / "dev.jsonl"
    records = load_inputs(inputs_path)
    selected = _probe_units(records)
    catalog_mimo = fetch_catalog("mimo-v2.6-flash")
    catalog_deepseek = fetch_catalog("deepseek-v4.1-flash")
    api_key = resolve_api_key(args.api_key_env)
    base_url = args.base_url or os.environ.get("SECVUL_BASE_URL") or DEFAULT_BASE_URL
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = RUNS_DIR / f"{stamp}_probe"
    root.mkdir(parents=True)

    specs = [
        {
            "name": "mimo_reasoning_none_max_completion_tokens",
            "model": "mimo-v2.6-flash",
            "catalog": catalog_mimo,
            "thinking": "disabled",
            "reasoning_effort": "none",
            "max_tokens_field": "max_completion_tokens",
            "max_tokens": 8192,
            "timeout": 120,
            "max_attempts": 1,
        },
        {
            "name": "mimo_legacy_max_tokens",
            "model": "mimo-v2.6-flash",
            "catalog": catalog_mimo,
            "thinking": "disabled",
            "reasoning_effort": None,
            "max_tokens_field": "max_tokens",
            "max_tokens": 8192,
            "timeout": 90,
            "max_attempts": 1,
        },
        {
            "name": "deepseek_default_config",
            "model": "deepseek-v4.1-flash",
            "catalog": catalog_deepseek,
            "thinking": None,
            "reasoning_effort": None,
            "max_tokens_field": "max_tokens",
            "max_tokens": 8192,
            "timeout": 120,
            "max_attempts": 1,
        },
    ]
    if args.only != "all":
        specs = [spec for spec in specs if spec["model"].startswith(args.only)]
    if not specs:
        raise SystemExit(f"no probe specs selected for {args.only!r}")
    summaries = []
    for spec in specs:
        prices = resolve_prices(spec["model"], spec["catalog"], args)
        config = build_api_config(
            model=spec["model"],
            base_url=base_url,
            max_tokens=spec["max_tokens"],
            timeout=spec["timeout"],
            max_attempts=spec["max_attempts"],
            thinking=spec["thinking"],
            reasoning_effort=spec["reasoning_effort"],
            max_tokens_field=spec["max_tokens_field"],
            prices=(prices[0], prices[1], prices[2]),
        )
        run_dir = root / spec["name"]
        execute(
            inputs_path=inputs_path,
            records=selected,
            config=config,
            api_key=api_key,
            out_dir=run_dir,
            concurrency=min(args.concurrency, len(selected)),
            kind="probe",
            catalog=spec["catalog"],
            price_source=prices[3],
            extra={
                "probe": spec["name"],
                "selection": {"split": "dev", "unit_ids": [r["unit_id"] for r in selected]},
                "partial": True,
            },
        )
        summaries.append(_probe_summary(run_dir))

    comparison = {
        "generated_at_utc": now_utc(),
        "units": [record["unit_id"] for record in selected],
        "runs": summaries,
    }
    _write_json(root / "probe_comparison.json", comparison)
    lines = [
        "# MiMo / DeepSeek request-configuration probe",
        "",
        f"Units: {', '.join(f'`{record['unit_id']}`' for record in selected)}",
        "",
        "| Config | Model | Field | reasoning_effort | thinking | Valid | Reasoning tokens | p50 latency |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for summary in summaries:
        reasoning_tokens = summary["aggregate"]["usage"]["reasoning_tokens"]["sum"]
        lines.append(
            "| {name} | {model} | {field} | {reasoning} | {thinking} | {valid}/{records} | {tokens} | {p50} |".format(
                name=summary["run_id"],
                model=summary["model"],
                field=summary["api"]["max_tokens_field"],
                reasoning=summary["api"]["reasoning_effort"],
                thinking=summary["api"]["thinking"],
                valid=summary["valid"],
                records=summary["records"],
                tokens="n/a" if reasoning_tokens is None else reasoning_tokens,
                p50="n/a"
                if summary["aggregate"]["latency_seconds"]["p50"] is None
                else f"{summary['aggregate']['latency_seconds']['p50']:.2f}",
            )
        )
    lines.extend(["", "## Per-answer evidence", ""])
    for summary in summaries:
        lines.append(f"### {summary['run_id']}")
        lines.append("")
        for sample in summary["samples"]:
            content = (sample["content"] or "").replace("\n", " ")[:160]
            lines.append(
                f"- `{sample['unit_id']}` status={sample['status']} valid={sample['valid']} "
                f"label={sample['label']} reasoning_tokens={sample['reasoning_tokens']} "
                f"finish={sample['finish_reason']} latency={sample['latency_seconds']}: {content}"
            )
        lines.append("")
    (root / "probe_comparison.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(comparison, ensure_ascii=False, indent=2))
    return 0


def report_cli(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    records = [
        json.loads(line)
        for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    evaluation = evaluate(records)
    aggregate = aggregate_run(records)
    _write_json(
        run_dir / "metrics_recomputed.json",
        {"manifest": manifest, "evaluation": evaluation, "aggregate": aggregate},
    )
    (run_dir / "metrics_recomputed.md").write_text(
        markdown_report(
            title=f"Recomputed Juliet LLM binary detection — {manifest['model']}",
            manifest=manifest,
            metrics=evaluation,
            aggregate=aggregate,
        ),
        encoding="utf-8",
    )
    print(json.dumps(evaluation, ensure_ascii=False, indent=2))
    return 0


def compare_cli(args: argparse.Namespace) -> int:
    summaries = [_probe_summary(Path(run_dir)) for run_dir in args.run]
    payload = {"generated_at_utc": now_utc(), "runs": summaries}
    if args.out:
        Path(args.out).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _add_common_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--inputs",
        default=None,
        help="Input JSONL; defaults to juliet_llm/build/<split>.jsonl",
    )
    parser.add_argument("--split", default="test", choices=("dev", "test"))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--sample-per-stratum", type=int, default=None)
    parser.add_argument("--unit-id", action="append", default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--tag", default=None)
    parser.add_argument("--kind", default="test")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument(
        "--api-key-env",
        default="OPENCODE_API_KEY",
        help="Name of the environment variable holding the key; never the key itself.",
    )
    parser.add_argument("--base-url", default=None)
    parser.add_argument(
        "--thinking",
        default="preset",
        choices=("preset", "omit", "default", "enabled", "disabled"),
    )
    parser.add_argument(
        "--reasoning-effort",
        default="preset",
        choices=("preset", "omit", "none", "minimal", "low", "medium", "high"),
    )
    parser.add_argument(
        "--max-tokens-field",
        default="preset",
        choices=("preset", "max_tokens", "max_completion_tokens"),
    )
    parser.add_argument("--input-price", type=float, default=None)
    parser.add_argument("--output-price", type=float, default=None)
    parser.add_argument("--cached-input-price", type=float, default=None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="juliet-llm", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="run a real model on frozen inputs")
    _add_common_run_args(run_parser)
    run_parser.set_defaults(func=run_cli)

    probe_parser = subparsers.add_parser(
        "probe", help="compare MiMo reasoning/max-token configurations on dev units"
    )
    probe_parser.add_argument("--concurrency", type=int, default=4)
    probe_parser.add_argument("--only", default="all", choices=("all", "mimo", "deepseek"))
    probe_parser.add_argument("--api-key-env", default="OPENCODE_API_KEY")
    probe_parser.add_argument("--base-url", default=None)
    probe_parser.add_argument("--input-price", type=float, default=None)
    probe_parser.add_argument("--output-price", type=float, default=None)
    probe_parser.add_argument("--cached-input-price", type=float, default=None)
    probe_parser.set_defaults(func=probe_cli)

    report_parser = subparsers.add_parser("report", help="recompute metrics for a run")
    report_parser.add_argument("--run-dir", type=Path, required=True)
    report_parser.set_defaults(func=report_cli)

    compare_parser = subparsers.add_parser("compare", help="summarise several runs")
    compare_parser.add_argument("--run", action="append", required=True)
    compare_parser.add_argument("--out", default=None)
    compare_parser.set_defaults(func=compare_cli)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

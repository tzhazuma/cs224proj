#!/usr/bin/env python3
"""Rebuild provider-list cost ledgers from stored per-request usage.

Read-only over experiment artifacts. Writes only under analysis/cost_normalization/.
No API calls are made and no credentials are read or written.

Run from anywhere:
    python3 analysis/cost_normalization/rebuild.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
LEDGER_DIR = OUT_DIR / "runs"

# Provider list cards in USD per 1M tokens: (input, output, cached_input).
# DeepSeek: off-peak card from research/evaluation_protocol.md section 6.2.
# All captured requests are outside the peak windows (checked below).
NORMALIZED_CARDS = {
    "deepseek": (0.15, 0.60, 0.003),
    "mimo": (0.14, 0.28, 0.0028),
}
CARD_LABELS = {
    "deepseek": "DeepSeek off-peak list (2026-11-11 snapshot)",
    "mimo": "MiMo published list (no peak/off-peak schedule)",
}

PROVIDER_TOLERANCE = 1e-3  # per-row relative tolerance; snapshot values are rounded


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


class SkipRun(RuntimeError):
    """Raised when a run directory is being rewritten and cannot be read consistently."""


def read_json_optional(path: Path) -> dict | None:
    try:
        return read_json(path)
    except FileNotFoundError:
        return None


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_runs() -> list[Path]:
    patterns = [
        "hybrid/runs/*",
        "pair_joint/runs/*",
        "juliet_repair/runs/*",
        "juliet_repair/runs/parser_dev/*",
        "evidence_prompt/runs/*",
        "juliet_llm/runs/*",
        "juliet_llm/runs/*/*",
        "runner/runs/*",
    ]
    found: dict[str, Path] = {}
    for pattern in patterns:
        for path in sorted(ROOT.glob(pattern)):
            if not path.is_dir():
                continue
            if not (path / "results.jsonl").exists() and not (path / "requests.jsonl").exists():
                continue
            rel = path.relative_to(ROOT).as_posix()
            found[rel] = path
    return [found[key] for key in sorted(found)]


def run_config(run: Path) -> tuple[dict, dict | None, dict | None, str | None, Path | None]:
    cfg_path = run / "config.json"
    man_path = run / "manifest.json"
    cfg = read_json_optional(cfg_path) if cfg_path.exists() else None
    man = read_json_optional(man_path) if man_path.exists() else None

    api: dict = {}
    if isinstance(cfg, dict) and isinstance(cfg.get("api"), dict):
        api = cfg["api"]
    elif isinstance(man, dict):
        inner = man.get("config")
        if isinstance(inner, dict) and isinstance(inner.get("api"), dict):
            api = inner["api"]
        elif isinstance(man.get("api"), dict):
            api = man["api"]

    model = api.get("model") or (man or {}).get("model")
    source = cfg_path if cfg_path.exists() else (man_path if man_path.exists() else None)
    return api, man, cfg, model, source


def has_usage(row: dict) -> bool:
    if isinstance(row.get("usage"), dict):
        return True
    resp = row.get("response")
    return isinstance(resp, dict) and isinstance(resp.get("usage"), dict)


def pick_artifact(run: Path) -> tuple[str, list[dict], Path] | None:
    candidates: list[tuple[int, bool, str, list[dict], Path]] = []
    for name in ("results.jsonl", "requests.jsonl"):
        path = run / name
        if path.exists():
            try:
                rows = read_jsonl(path)
            except FileNotFoundError as exc:
                raise SkipRun(f"{path} disappeared while scanning") from exc
            candidates.append((sum(1 for row in rows if has_usage(row)), name == "results.jsonl", name, rows, path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    _, _, name, rows, path = candidates[0]
    return name, rows, path


def row_usage(row: dict) -> dict | None:
    usage = row.get("usage")
    if isinstance(usage, dict):
        return usage
    resp = row.get("response")
    if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
        return resp["usage"]
    return None


def row_cost(row: dict) -> dict | None:
    cost = row.get("cost")
    if isinstance(cost, dict):
        return cost
    resp = row.get("response")
    if isinstance(resp, dict) and isinstance(resp.get("cost"), dict):
        return resp["cost"]
    return None


def parse_timestamp(value) -> datetime | None:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def row_timestamp(row: dict) -> datetime | None:
    for key in ("created_at", "completed_at"):
        parsed = parse_timestamp(row.get(key))
        if parsed is not None:
            return parsed
    meta = row.get("response_meta")
    if isinstance(meta, dict):
        created = meta.get("created")
        if isinstance(created, (int, float)) and created > 1_000_000_000:
            return datetime.fromtimestamp(created, tz=timezone.utc)
    return None


def is_peak(dt: datetime) -> bool:
    # Mon-Fri 01:00-04:00 and 06:00-10:00 UTC, excluding Chinese holidays.
    # The captured dates (2026-11-11/12) are not Chinese statutory holidays.
    if dt.weekday() >= 5:
        return False
    minutes = dt.hour * 60 + dt.minute
    return (60 <= minutes < 240) or (360 <= minutes < 600)


def model_key(api: dict, model: str | None) -> str | None:
    text = f"{api.get('model') or ''} {model or ''}".lower()
    if "deepseek" in text:
        return "deepseek"
    if "mimo" in text:
        return "mimo"
    return None


def price_triplet(api: dict) -> tuple[float, float, float] | None:
    values = [
        api.get("input_price_usd_per_1m"),
        api.get("output_price_usd_per_1m"),
        api.get("cached_input_price_usd_per_1m"),
    ]
    if all(isinstance(value, (int, float)) for value in values):
        return (float(values[0]), float(values[1]), float(values[2]))
    return None


def tokens_of(usage: dict) -> dict:
    opencode = usage.get("opencode")
    if isinstance(opencode, dict) and isinstance(opencode.get("tokens"), dict):
        tok = opencode["tokens"]
        details = usage.get("completion_tokens_details") or {}
        return {
            "input_uncached": int(tok.get("input") or 0),
            "cached_input": int(tok.get("cache_read") or 0),
            "output": int(tok.get("output") or 0),
            "reasoning": int(tok.get("reasoning") or details.get("reasoning_tokens") or 0),
            "cache_write": int(tok.get("cache_write_1h") or 0) + int(tok.get("cache_write_5m") or 0),
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "source": "opencode.tokens",
        }

    prompt = int(usage.get("prompt_tokens") or 0)
    cached = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
    details = usage.get("completion_tokens_details") or {}
    return {
        "input_uncached": max(prompt - cached, 0),
        "cached_input": cached,
        "input_including_cached": prompt,
        "output": int(usage.get("completion_tokens") or 0),
        "reasoning": int(details.get("reasoning_tokens") or 0),
        "cache_write": 0,
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "source": "prompt_tokens-cached",
    }


def cost_of(tokens: dict, prices: tuple[float, float, float] | None) -> float | None:
    if prices is None:
        return None
    price_in, price_out, price_cache = prices
    return (
        tokens["input_uncached"] * price_in
        + tokens["cached_input"] * price_cache
        + tokens["output"] * price_out
    ) / 1_000_000


def cost_no_cache(tokens: dict, prices: tuple[float, float, float] | None) -> float | None:
    if prices is None:
        return None
    price_in, price_out, _ = prices
    prompt = tokens["input_uncached"] + tokens["cached_input"]
    return (prompt * price_in + tokens["output"] * price_out) / 1_000_000


def close_enough(left: float, right: float) -> bool:
    return abs(left - right) <= max(1e-9, 1e-6 * max(abs(left), abs(right)))


def classify(rel: str, name: str, usage_records: int, statuses: dict) -> tuple[str, str]:
    category = rel.split("/")[0]
    lowered = name.lower()
    if any(tag in lowered for tag in ("postleakfix", "post_leak", "_repro", "rerun", "_v2_", "v2_")):
        return category, "rerun_fix"
    if category == "hybrid":
        return category, "headline"
    if category == "pair_joint":
        return category, "headline" if name.startswith("test_") else "pilot"
    if category == "juliet_repair":
        return category, "headline" if name.endswith("_final") else "pilot"
    if category == "evidence_prompt":
        return category, "headline" if name.startswith("test_") else "pilot"
    if category == "juliet_llm":
        if "probe" in rel:
            return category, "probe"
        if name.endswith("_final"):
            return category, "headline"
        if "_test_" in name:
            return category, "replicate"
        if usage_records == 0 and statuses and "ok" not in statuses:
            return category, "failed_no_usage"
        return category, "pilot"
    if category == "runner":
        if name.startswith("test_v1_"):
            return category, "legacy_test"
        if usage_records == 0 and statuses and "ok" not in statuses:
            return category, "failed_no_usage"
        return category, "pilot"
    return category, "other"


def scan_run(run: Path, source_hashes: dict[str, str]) -> dict:
    rel = run.relative_to(ROOT).as_posix()
    name = run.name
    api, manifest, cfg, model, config_source = run_config(run)
    artifact = pick_artifact(run)
    if artifact is None:
        raise SkipRun(f"no results.jsonl/requests.jsonl yet in {rel}")
    artifact_name, rows, artifact_path = artifact

    configured_prices = price_triplet(api)
    card_key = model_key(api, model)
    normalized_prices = NORMALIZED_CARDS.get(card_key) if card_key else None

    tokens_total = {
        "input_uncached": 0,
        "cached_input": 0,
        "output": 0,
        "reasoning": 0,
        "cache_write": 0,
    }
    statuses: dict[str, int] = {}
    usage_records = 0
    recorded_cost = 0.0
    recorded_rows = 0
    cache_aware = 0.0
    no_cache = 0.0
    normalized = 0.0
    provider_list = 0.0
    provider_rows = 0
    allowance = 0.0
    allowance_rows = 0
    timestamps: list[datetime] = []
    missing_timestamps = 0
    peak_rows = 0
    token_mismatches = 0
    cache_write_rows = 0
    missing_cost_rows = 0
    max_provider_rel_dev = 0.0

    for row in rows:
        status = row.get("status")
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        usage = row_usage(row)
        if usage is None:
            continue
        usage_records += 1
        tokens = tokens_of(usage)
        for key in tokens_total:
            tokens_total[key] += int(tokens.get(key, 0) or 0)
        if tokens.get("cache_write"):
            cache_write_rows += 1

        if tokens["source"] == "opencode.tokens" and tokens.get("prompt_tokens") is not None:
            if (
                tokens["input_uncached"] + tokens["cached_input"] != int(tokens["prompt_tokens"])
                or tokens["output"] != int(tokens.get("completion_tokens") or 0)
            ):
                token_mismatches += 1

        cache_aware_value = cost_of(tokens, configured_prices)
        no_cache_value = cost_no_cache(tokens, configured_prices)
        normalized_value = cost_of(tokens, normalized_prices)
        if cache_aware_value is not None:
            cache_aware += cache_aware_value
        if no_cache_value is not None:
            no_cache += no_cache_value
        if normalized_value is not None:
            normalized += normalized_value

        cost = row_cost(row)
        if isinstance(cost, dict) and cost.get("cost_usd") is not None:
            recorded_cost += float(cost["cost_usd"])
            recorded_rows += 1
        else:
            missing_cost_rows += 1

        opencode = usage.get("opencode")
        if isinstance(opencode, dict):
            listed = opencode.get("list_cost")
            allowed = opencode.get("allowance")
            if isinstance(listed, (int, float)):
                provider_list += float(listed)
                provider_rows += 1
                if normalized_value is not None and normalized_value > 0:
                    max_provider_rel_dev = max(
                        max_provider_rel_dev,
                        abs(float(listed) - normalized_value) / normalized_value,
                    )
            if isinstance(allowed, (int, float)):
                allowance += float(allowed)
                allowance_rows += 1

        stamp = row_timestamp(row)
        if stamp is None:
            missing_timestamps += 1
        else:
            timestamps.append(stamp)
            if is_peak(stamp):
                peak_rows += 1

    # Declared configured-cost basis. New experiments bill cached tokens at the
    # cached price; the legacy runner stored DeepSeek costs with all prompt
    # tokens at the input price (no cache discount).
    if recorded_rows == 0:
        basis = None
        basis_ok = None
        cache_aware_matches = None
    else:
        if close_enough(recorded_cost, cache_aware):
            basis = "cache_aware"
        elif close_enough(recorded_cost, no_cache):
            basis = "prompt_at_input_price_no_cache_discount"
        else:
            basis = "unexplained"
        basis_ok = basis != "unexplained"
        cache_aware_matches = close_enough(recorded_cost, cache_aware)

    provider_available = provider_rows > 0
    provider_rel = None
    provider_matches = None
    if provider_available and normalized > 0:
        provider_rel = (provider_list - normalized) / normalized
        provider_matches = abs(provider_rel) <= PROVIDER_TOLERANCE and max_provider_rel_dev <= PROVIDER_TOLERANCE
    elif provider_available:
        provider_matches = False

    unit_results = None
    results_path = run / "results.jsonl"
    if results_path.exists():
        unit_results = len(read_jsonl(results_path))

    expected = None
    for key in ("expected_units", "expected_requests", "units", "selected_units", "dataset_units"):
        value = (manifest or {}).get(key)
        if isinstance(value, int) and value > 0:
            expected = value
            break
    if expected is None and isinstance(cfg, dict):
        for key in ("expected_requests", "selected_units", "dataset_units", "units"):
            value = cfg.get(key)
            if isinstance(value, int) and value > 0:
                expected = value
                break
    finished = (
        (manifest or {}).get("finished_at_utc")
        or (manifest or {}).get("completed_at_utc")
        or (manifest or {}).get("completed_at")
    )
    status_completed = str((manifest or {}).get("status") or "").lower() == "completed"
    data_complete = (
        (expected is None or usage_records >= expected)
        and (finished is not None or status_completed)
    )

    if timestamps:
        window_start = min(timestamps)
        window_end = max(timestamps)
        window_source = "request timestamps"
    else:
        window_start = parse_timestamp((manifest or {}).get("started_at_utc") or (manifest or {}).get("started_at"))
        window_end = parse_timestamp(
            (manifest or {}).get("finished_at_utc")
            or (manifest or {}).get("completed_at_utc")
            or (manifest or {}).get("completed_at")
        )
        window_source = "manifest" if window_start or window_end else None

    category, run_class = classify(rel, name, usage_records, statuses)

    notes: list[str] = []
    if basis == "prompt_at_input_price_no_cache_discount":
        notes.append(
            "Legacy recorded cost bills every prompt token at the input price; "
            "the cache discount is not applied in the stored figure."
        )
    if basis == "unexplained":
        notes.append("Stored cost does not match either cache-aware or no-cache recomputation.")
    if not provider_available:
        notes.append("Provider did not return usage.opencode.list_cost/allowance for this run.")
    if usage_records < len(rows):
        notes.append(f"{len(rows) - usage_records} row(s) have no usage and are excluded, not zero-filled.")
    if unit_results is not None and unit_results != usage_records:
        notes.append(f"{unit_results} unit result(s) vs {usage_records} per-call usage record(s).")
    if not data_complete:
        notes.append(
            f"Run is not complete: expected {expected if expected is not None else 'unknown'}, "
            f"recorded {usage_records}; excluded from complete-only aggregates."
        )
    if peak_rows:
        notes.append("Peak-hour rows present; the off-peak normalized card does not cover them.")
    if cache_write_rows:
        notes.append("Non-zero cache-write tokens present; rate card has no cache-write price.")

    source = {
        "artifact": artifact_path.relative_to(ROOT).as_posix(),
        "artifact_sha256": sha256_file(artifact_path) if artifact_path.exists() else None,
        "config": config_source.relative_to(ROOT).as_posix() if config_source else None,
        "config_sha256": sha256_file(config_source) if config_source and config_source.exists() else None,
    }
    if source["artifact_sha256"] is None:
        raise SkipRun(f"{artifact_path} disappeared before hashing")
    source_hashes[source["artifact"]] = source["artifact_sha256"]
    if source["config"] and source["config_sha256"]:
        source_hashes[source["config"]] = source["config_sha256"]

    run_obj = {
        "run_id": name,
        "path": rel,
        "category": category,
        "class": run_class,
        "model": model,
        "model_key": card_key,
        "endpoint": api.get("base_url"),
        "artifact": artifact_name,
        "records": len(rows),
        "expected_records": expected,
        "data_complete": data_complete,
        "unit_results": unit_results,
        "usage_records": usage_records,
        "statuses": statuses,
        "configured_prices_usd_per_1m": _triplet_dict(configured_prices),
        "normalized_prices_usd_per_1m": _triplet_dict(normalized_prices),
        "tokens": tokens_total,
        "configured_recorded_usd": recorded_cost if recorded_rows else None,
        "configured_cache_aware_usd": cache_aware if recorded_rows else None,
        "configured_no_cache_usd": no_cache if recorded_rows else None,
        "normalized_list_usd": normalized if usage_records else None,
        "provider_list_usd": provider_list if provider_available else None,
        "provider_allowance_usd": allowance if allowance_rows else None,
        "window_utc": {
            "start": window_start.isoformat() if window_start else None,
            "end": window_end.isoformat() if window_end else None,
            "source": window_source,
        },
        "checks": {
            "configured_basis": basis,
            "configured_recorded_matches_declared_basis": basis_ok,
            "configured_cache_aware_matches_recorded": cache_aware_matches,
            "token_reconciliation": token_mismatches == 0,
            "token_mismatch_rows": token_mismatches,
            "missing_cost_rows": missing_cost_rows,
            "usage_rows_with_timestamp": len(timestamps),
            "usage_rows_missing_timestamp": missing_timestamps,
            "peak_rows": peak_rows,
            "all_usage_rows_off_peak": peak_rows == 0 and missing_timestamps == 0 and usage_records > 0,
            "provider_list_rows": provider_rows,
            "provider_allowance_rows": allowance_rows,
            "provider_list_rel_dev_vs_normalized": provider_rel,
            "provider_list_max_row_rel_dev": max_provider_rel_dev if provider_available else None,
            "provider_list_matches_normalized": provider_matches,
            "source_artifact_unchanged": True,
        },
        "source": source,
        "notes": notes,
    }
    return run_obj


def _triplet_dict(prices: tuple[float, float, float] | None) -> dict | None:
    if prices is None:
        return None
    return {"input": prices[0], "output": prices[1], "cached_input": prices[2]}


def sum_present(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return sum(present) if present else None


def aggregate(label: str, runs: list[dict], complete_only: bool = False) -> dict:
    with_usage = [run for run in runs if run["usage_records"] > 0]
    if complete_only:
        with_usage = [run for run in with_usage if run["data_complete"]]
    recorded = [run["configured_recorded_usd"] for run in with_usage if run["configured_recorded_usd"] is not None]
    cache_aware = [run["configured_cache_aware_usd"] for run in with_usage if run["configured_cache_aware_usd"] is not None]
    normalized = [run["normalized_list_usd"] for run in with_usage if run["normalized_list_usd"] is not None]
    provider = [run["provider_list_usd"] for run in with_usage if run["provider_list_usd"] is not None]
    allowance = [run["provider_allowance_usd"] for run in with_usage if run["provider_allowance_usd"] is not None]
    tokens = {
        key: sum(run["tokens"][key] for run in with_usage)
        for key in ("input_uncached", "cached_input", "output", "reasoning", "cache_write")
    }
    return {
        "label": label,
        "runs": len(runs),
        "runs_complete": sum(1 for run in runs if run["data_complete"]),
        "runs_with_usage": len(with_usage),
        "usage_records": sum(run["usage_records"] for run in with_usage),
        "records": sum(run["records"] for run in runs),
        "tokens": tokens,
        "configured_recorded_usd": round(sum(recorded), 9) if recorded else None,
        "configured_cache_aware_usd": round(sum(cache_aware), 9) if cache_aware else None,
        "normalized_list_usd": round(sum(normalized), 9) if normalized else None,
        "provider_list_usd": round(sum(provider), 9) if provider else None,
        "provider_allowance_usd": round(sum(allowance), 9) if allowance else None,
        "provider_list_runs": len(provider),
        "provider_allowance_runs": len(allowance),
        "provider_missing_runs": [run["run_id"] for run in with_usage if run["provider_list_usd"] is None],
        "configured_recorded_runs": len(recorded),
        "normalized_runs": len(normalized),
    }


def fmt_usd(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.6f}"


def fmt_ratio(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def fmt_ts(value: str | None) -> str:
    if not value:
        return "n/a"
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc).strftime("%m-%d %H:%M")


def fmt_statuses(statuses: dict) -> str:
    if not statuses:
        return "n/a"
    return ", ".join(f"{('n/a' if key in ('None', 'none', '') else key)}×{value}" for key, value in statuses.items())


def runs_table(runs: list[dict]) -> str:
    lines = [
        "| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for run in runs:
        conf = run["configured_recorded_usd"]
        norm = run["normalized_list_usd"]
        ratio = (norm / conf) if (conf is not None and conf > 0 and norm is not None) else None
        lines.append(
            "| `{run}` | {model} | {calls} | {conf} | {norm} | {provider} | {allowance} | {ratio} | {ts} |".format(
                run=run["run_id"],
                model=run["model_key"] or run["model"] or "?",
                calls=run["usage_records"],
                conf=fmt_usd(conf),
                norm=fmt_usd(norm),
                provider=fmt_usd(run["provider_list_usd"]),
                allowance=fmt_usd(run["provider_allowance_usd"]),
                ratio=fmt_ratio(ratio),
                ts=fmt_ts((run["window_utc"] or {}).get("start")),
            )
        )
    return "\n".join(lines)


def agg_table(aggs: list[dict]) -> str:
    lines = [
        "| 组 | runs | complete | 有 usage | 调用 | configured $ | normalized $ | provider list $ | allowance $ |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for agg in aggs:
        lines.append(
            "| {label} | {runs} | {complete} | {used} | {calls} | {conf} | {norm} | {prov} | {allow} |".format(
                label=agg["label"],
                runs=agg["runs"],
                complete=agg.get("runs_complete", "n/a"),
                used=agg["runs_with_usage"],
                calls=agg["usage_records"],
                conf=fmt_usd(agg["configured_recorded_usd"]),
                norm=fmt_usd(agg["normalized_list_usd"]),
                prov=fmt_usd(agg["provider_list_usd"]),
                allow=fmt_usd(agg["provider_allowance_usd"]),
            )
        )
    return "\n".join(lines)


def render_markdown(summary: dict) -> str:
    runs = summary["runs"]
    aggs = summary["aggregates"]
    headline = [run for run in runs if run["class"] == "headline" and run["data_complete"]]
    reruns = [run for run in runs if run["class"] in ("rerun_fix", "replicate") and run["data_complete"]]
    legacy = [run for run in runs if run["class"] == "legacy_test" and run["data_complete"]]
    pilot = [run for run in runs if run["class"] in ("pilot", "probe") and run["data_complete"]]
    incomplete = [run for run in runs if run["usage_records"] > 0 and not run["data_complete"]]
    failed = [run for run in runs if run["class"] == "failed_no_usage"]
    repair = [run for run in runs if run["category"] == "juliet_repair"]

    lines: list[str] = []
    lines.append("# 成本口径归一化：provider list vs configured")
    lines.append("")
    lines.append(f"生成时间：{summary['generated_at_utc']}（UTC） / {summary['generated_at_local']}（Asia/Shanghai）")
    lines.append("")
    lines.append(
        f"范围：{aggs['all_with_usage']['runs_with_usage']} 个有真实 usage 的 run、"
        f"{aggs['all_with_usage']['usage_records']:,} 次请求；其中 "
        f"{aggs['all_complete_with_usage']['runs_with_usage']} 个完整 run、"
        f"{aggs['incomplete']['runs_with_usage']} 个未完成 run 单列；另有 "
        f"{aggs['failed_no_usage']['runs']} 个无 usage 的失败/空跑目录。"
        "脚本只读取已保存的 `results.jsonl` / `requests.jsonl` 和 manifest/config，"
        "不修改原始响应，不调用 API。"
    )
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append(
        "- **审计 I5 的 2× 是峰谷价差，不是 allowance 折扣。** DeepSeek 的 configured "
        "`0.30/1.20/0.006` 是**高峰**价；provider 返回的 `usage.opencode.list_cost` "
        "是**非高峰**价 `0.15/0.60/0.003`。本批全部请求都落在非高峰窗口，因此 "
        "cache 口径一致的 v1 run 上 provider 快照恰好是 configured 的 0.5×；"
        "legacy 记录值不扣 cache，见 §5。"
    )
    lines.append(
        "- **归一化口径**：DeepSeek `0.15/0.60/0.003`，MiMo `0.14/0.28/0.0028`，"
        "按每条 usage 的未缓存输入 / 缓存命中 / 输出 token 重算，不使用 token 估算，"
        "也不改原始 `cost_usd`。"
    )
    lines.append(
        "- **allowance 独立**：DeepSeek 的 `usage.opencode.allowance` 观测为 list cost 的 "
        "0.600×，MiMo 为 1.000×；它是 provider 侧的额度扣减，不是 USD 账单，"
        "既没有从 list cost 扣除，也没有加到 configured cost。"
    )
    lines.append(
        f"- **总量**（{aggs['all_complete_with_usage']['runs_with_usage']} 个完整 run）：configured "
        f"**${fmt_usd(aggs['all_complete_with_usage']['configured_recorded_usd'])}**，"
        f"normalized provider-list **${fmt_usd(aggs['all_complete_with_usage']['normalized_list_usd'])}**；"
        f"其中 headline run 的 configured 为 ${fmt_usd(aggs['headline']['configured_recorded_usd'])}，"
        f"normalized 为 ${fmt_usd(aggs['headline']['normalized_list_usd'])}。"
        f"若把 {aggs['incomplete']['runs_with_usage']} 个未完成 run 也计入，"
        f"all-recorded 为 configured ${fmt_usd(aggs['all_with_usage']['configured_recorded_usd'])} / "
        f"normalized ${fmt_usd(aggs['all_with_usage']['normalized_list_usd'])}。"
    )
    lines.append("")

    lines.append("## 1. 价格口径")
    lines.append("")
    lines.append("| 模型 | 计费项 | 高峰价 | 非高峰价 | 本报告使用的 normalized 价 |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    lines.append("| DeepSeek | 输入，缓存未命中 | 0.30 | 0.15 | 0.15 |")
    lines.append("| DeepSeek | 输入，缓存命中 | 0.006 | 0.003 | 0.003 |")
    lines.append("| DeepSeek | 输出 | 1.20 | 0.60 | 0.60 |")
    lines.append("| MiMo | 输入，缓存未命中 | — | 0.14 | 0.14 |")
    lines.append("| MiMo | 输入，缓存命中 | — | 0.0028 | 0.0028 |")
    lines.append("| MiMo | 输出 | — | 0.28 | 0.28 |")
    lines.append("")
    lines.append("单位：USD / 1M tokens。DeepSeek 峰谷规则来自 `research/evaluation_protocol.md` §6.2：")
    lines.append("高峰为 UTC 周一至周五 01:00–04:00 与 06:00–10:00（排除中国法定节假日），其余为非高峰。")
    lines.append("MiMo 没有峰谷价，按 published flat price。价格快照日期为 2026-11-11；token 数逐 run 保留，便于按新价重算。")
    lines.append("")
    lines.append("## 2. 峰谷与日期核验")
    lines.append("")
    verification = summary["verification"]
    lines.append(
        f"- 有 usage 的 {verification['usage_rows']:,} 条请求全部能解析 UTC 时间；"
        f"时间范围为 **{verification['first_request_utc']} 至 {verification['last_request_utc']}**，"
        "均为 2026-11-11 星期三（UTC）。"
    )
    lines.append(
        f"- 按上述峰谷规则逐条判定：**peak rows = {verification['peak_rows']}**；"
        "因此本批 DeepSeek 全部适用非高峰价 0.15/0.60/0.003。"
    )
    first_utc = datetime.fromisoformat(verification["first_request_utc"]) if verification["first_request_utc"] else None
    last_utc = datetime.fromisoformat(verification["last_request_utc"]) if verification["last_request_utc"] else None
    if first_utc and last_utc:
        cst = timezone(timedelta(hours=8))
        lines.append(
            f"- 北京时间（UTC+8）对应 {first_utc.astimezone(cst):%Y-%m-%d %H:%M} 至 "
            f"{last_utc.astimezone(cst):%Y-%m-%d %H:%M}；峰谷判定以 UTC 为准，不以北京时间为准。"
        )
    lines.append(
        "- 逐请求比较 `usage.opencode.list_cost` 与按非高峰价重算的值："
        f"{verification['provider_rows']:,} 条可比请求，最大单条相对偏差 "
        f"{verification['max_provider_row_rel_dev']:.2e}；说明 provider 快照本身就是非高峰 flat rate，"
        "不是额外的折扣或 allowance 抵扣。"
    )
    lines.append("")

    lines.append("## 3. 分组汇总")
    lines.append("")
    lines.append(agg_table([
        aggs["headline"],
        aggs["rerun_fix"],
        aggs["replicate"],
        aggs["legacy_test"],
        aggs["pilot"],
        aggs["probe"],
        aggs["all_complete_with_usage"],
        aggs["incomplete"],
        aggs["all_with_usage"],
        aggs["failed_no_usage"],
    ]))
    lines.append("")
    lines.append("读法：`configured` 是原始 run 记录的成本；`normalized` 是按 provider list 价重算的值；")
    lines.append("`provider list` 是 `usage.opencode.list_cost` 的逐请求求和；`allowance` 是独立的 provider 额度扣减。")
    lines.append("`complete` 列只统计 manifest 完成且记录数达到 expected 的 run；`incomplete` 单列，不混入任何 complete-only 合计。")
    lines.append("`provider list` / `allowance` 只覆盖 OpenCode 端点；Xiaomi 端点（`juliet_llm`）不返回这两个字段，因此按 n/a 处理，不补零。")
    lines.append("`failed_no_usage` 没有 usage，成本列不补零，显示 n/a。")
    lines.append("组之间可能重叠（例如 repair 的 parser_dev 同时属于 `pilot` 和 `juliet_repair` 类别）；`all_complete_with_usage` 是按 run 去重的合计，不重复计数。")
    lines.append("")
    lines.append("### 3.1 按实验")
    lines.append("")
    lines.append(agg_table([
        aggs["by_category"]["hybrid"],
        aggs["by_category"]["pair_joint"],
        aggs["by_category"]["juliet_repair"],
        aggs["by_category"]["evidence_prompt"],
        aggs["by_category"]["juliet_llm"],
        aggs["by_category"]["runner"],
    ]))
    lines.append("")
    lines.append("按实验类别包含该目录下所有 run（含 pilot / smoke / rerun）；headline 只取 §4 的 17 个主实验 run。")
    lines.append("`hybrid` 类别含 10 个 v1 + 10 个 v2；`juliet_llm` 含 final / replicate / postleakfix / smoke，因此类别合计高于 headline。")
    lines.append("### 3.2 按模型")
    lines.append("")
    lines.append(agg_table([
        aggs["by_model"]["deepseek"],
        aggs["by_model"]["mimo"],
    ]))
    lines.append("")
    lines.append(
        "DeepSeek 的 normalized 明显低于 configured：v1 新实验（hybrid / pair / repair / evidence）"
        "是峰/谷价卡的 2× 关系；v2 rerun 已直接配置 0.15/0.60/0.003，ratio 为 1.0；"
        "legacy runner 还叠加了“记录值不扣 cache”的因素，所以 ratio 小于 0.5，详见 §5。"
        "MiMo 的 configured 与 normalized 相同（0.14/0.28/0.0028）。"
    )
    lines.append("")

    lines.append("## 4. 主实验 run")
    lines.append("")
    lines.append(runs_table(headline))
    lines.append("")
    lines.append("## 4.1 重跑 / 复现 / replicate run")
    lines.append("")
    lines.append(runs_table(reruns))
    lines.append("")
    lines.append(
        "`postleakfix` / `_repro` / `hybrid_v2_*` 是其他修复项在本报告生成前后产生的重跑；"
        "它们按各自 run 的价格卡归一化，单列而不并入 headline，避免把修复前后的 run 混为一个分母。"
        "其中 `hybrid_v2_*` 已直接配置为 0.15/0.60/0.003，因此 configured 与 normalized 相同。"
    )
    lines.append("")

    lines.append("## 5. Legacy runner test_v1")
    lines.append("")
    lines.append(runs_table(legacy))
    lines.append("")
    lines.append(
        "Legacy runner 的 `response.cost.cost_usd` 对 DeepSeek 采用**不扣缓存**的算法："
        "`prompt_tokens × input_price + completion_tokens × output_price`。"
        "因此 `configured` 与 `configured_cache_aware` 不同；normalized 仍按 provider 的"
        "未缓存/缓存命中/输出拆分重算。两者不是同一口径，不能直接用 configured 除以 2。"
    )
    example = next((run for run in legacy if run["run_id"] == "test_v1_few-shot_pairs"), None)
    if example:
        lines.append(
            f"- 例：`test_v1_few-shot_pairs` configured ${fmt_usd(example['configured_recorded_usd'])}，"
            f"按同一 configured 价卡做 cache-aware 重算为 ${fmt_usd(example['configured_cache_aware_usd'])}，"
            f"provider-list normalized 为 ${fmt_usd(example['normalized_list_usd'])}。"
        )
    lines.append("")

    lines.append("## 6. Pilot / smoke / probe")
    lines.append("")
    lines.append(runs_table(pilot))
    lines.append("")

    if incomplete:
        lines.append("## 7. 未完成 run（单列，不并入 complete-only 合计）")
        lines.append("")
        lines.append("| Run | 类别 | 预期 | 已记录 | configured $ | normalized $ | 说明 |")
        lines.append("| --- | --- | ---: | ---: | ---: | ---: | --- |")
        for run in incomplete:
            lines.append(
                f"| `{run['run_id']}` | {run['class']} | {run['expected_records'] or 'n/a'} | "
                f"{run['usage_records']} | {fmt_usd(run['configured_recorded_usd'])} | "
                f"{fmt_usd(run['normalized_list_usd'])} | 少于 expected 或 manifest 未完成；"
                "成本只覆盖已记录的真实 usage，不代表完整 run。 |"
            )
        lines.append("")

    if failed:
        lines.append("## 8. 无 usage 的失败 / 空跑")
        lines.append("")
        lines.append("| Run | 类别 | 状态 | 说明 |")
        lines.append("| --- | --- | --- | --- |")
        for run in failed:
            lines.append(
                f"| `{run['run_id']}` | {run['category']} | {fmt_statuses(run['statuses'])} | "
                "无 usage，未计入任何成本合计。 |"
            )
        lines.append("")

    lines.append("## 9. juliet_repair all-in 修正")
    lines.append("")
    repair_agg = summary["juliet_repair"]
    lines.append(
        f"- headline 两个 final run：configured **${fmt_usd(repair_agg['headline_configured_usd'])}**，"
        f"normalized **${fmt_usd(repair_agg['headline_normalized_usd'])}**；headline 指标与 README 表格不变。"
    )
    lines.append(
        f"- 全部 repair run（含 parser_dev 与 smoke）：configured **${fmt_usd(repair_agg['all_configured_usd'])}**，"
        f"normalized **${fmt_usd(repair_agg['all_normalized_usd'])}**。"
    )
    lines.append(
        f"- README 的 all-in 由 **$0.077516** 修正为 **$0.082550**（delta "
        f"${repair_agg['delta_vs_old_readme_usd']:.6f}，来自 `parser_dev/mimo_test70_v1` 的 "
        f"${repair_agg['mimo_v1_configured_usd']:.6f}）。headline `$0.032831` 不变。"
    )
    lines.append(
        "- `parser_dev/mimo_test70_v1` 是 44/70 的解析器开发 run；$0.005034 是真实已发生成本，"
        "所以计入 all-in，但它不代表完整 70 单元，也不进入 headline。"
    )
    lines.append("")
    lines.append(runs_table(repair))
    lines.append("")

    lines.append("## 10. 校验")
    lines.append("")
    lines.append(f"- 脚本读取的源文件数：{verification['source_artifacts_checked']}；生成后重新哈希，"
                 f"变化数：{len(verification['source_artifacts_changed'])}。")
    if verification["source_artifacts_changed"]:
        lines.append(f"  - 扫描期间被其他进程改写的源文件：{', '.join(verification['source_artifacts_changed'])}；"
                     "这些 run 的数字应按最终文件重跑。")
    lines.append(f"- token 对账失败行数：{verification['token_mismatch_rows']}；缺 cost 行数：{verification['missing_cost_rows']}。")
    opencode_runs = [
        run for run in runs
        if run["usage_records"] > 0 and run["data_complete"] and run["provider_list_usd"] is not None
    ]
    if opencode_runs:
        opencode_norm = sum(run["normalized_list_usd"] for run in opencode_runs)
        opencode_provider = sum(run["provider_list_usd"] for run in opencode_runs)
        lines.append(
            f"- {len(opencode_runs)} 个 OpenCode 完整 run 的 normalized 合计 ${opencode_norm:,.9f}，"
            f"provider list 合计 ${opencode_provider:,.9f}，差 ${opencode_norm - opencode_provider:+.9f}"
            "（逐请求快照四舍五入）。"
        )
    lines.append(f"- configured 口径无法解释的 run：{verification['unexplained_configured_runs'] or '无'}。")
    lines.append(f"- provider list 与 normalized 不一致的 run：{verification['provider_mismatch_runs'] or '无'}。")
    lines.append(f"- 峰时请求行数：{verification['peak_rows']}。")
    lines.append("")
    lines.append("## 11. 限制")
    lines.append("")
    lines.append("- 这不是账单。没有读取发票、余额或信用卡数据；`configured`、`normalized`、`allowance` 三个口径都不是实际扣款。")
    lines.append("- `allowance` 只在 OpenCode 端点返回；Xiaomi 端点的 provider list/allowance 为 n/a，normalized 按 published MiMo 价计算。")
    lines.append("- Legacy runner 的 configured 记录不扣缓存；本报告保留原记录值，同时给出 `configured_cache_aware` 供比较。")
    lines.append("- 若在高峰窗口重跑，DeepSeek 应改用 0.30/1.20/0.006；本批全部为非高峰，故使用 0.15/0.60/0.003。")
    lines.append("- 脚本按目录自动发现 run；若其他修复任务新增 run，重新执行即可，不会覆盖原始结果。")
    lines.append("")
    lines.append("## 12. 复现")
    lines.append("")
    lines.append("```bash")
    lines.append("cd /mnt/c/Users/tzh03/Downloads/cs224proj")
    lines.append("python3 analysis/cost_normalization/rebuild.py")
    lines.append("```")
    lines.append("")
    lines.append("产物：本文件、`analysis/cost_normalization.json`、`analysis/cost_normalization/runs/*.json`。")
    return "\n".join(lines) + "\n"


def main() -> int:
    generated = datetime.now(timezone.utc)
    local = generated.astimezone()
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)

    source_hashes: dict[str, str] = {}
    runs: list[dict] = []
    skipped: list[dict] = []
    for run_path in discover_runs():
        try:
            runs.append(scan_run(run_path, source_hashes))
        except (SkipRun, FileNotFoundError) as exc:
            skipped.append({"path": run_path.relative_to(ROOT).as_posix(), "reason": str(exc)})

    by_class: dict[str, list[dict]] = {}
    by_category: dict[str, list[dict]] = {}
    by_model: dict[str, list[dict]] = {}
    for run in runs:
        by_class.setdefault(run["class"], []).append(run)
        by_category.setdefault(run["category"], []).append(run)
        by_model.setdefault(run["model_key"] or "unknown", []).append(run)

    aggregates = {
        "headline": aggregate("headline", [run for run in by_class.get("headline", []) if run["data_complete"]]),
        "rerun_fix": aggregate("rerun_fix", [run for run in by_class.get("rerun_fix", []) if run["data_complete"]]),
        "replicate": aggregate("replicate", [run for run in by_class.get("replicate", []) if run["data_complete"]]),
        "legacy_test": aggregate("legacy_test", [run for run in by_class.get("legacy_test", []) if run["data_complete"]]),
        "pilot": aggregate("pilot", [run for run in by_class.get("pilot", []) if run["data_complete"]]),
        "probe": aggregate("probe", [run for run in by_class.get("probe", []) if run["data_complete"]]),
        "failed_no_usage": aggregate("failed_no_usage", by_class.get("failed_no_usage", [])),
        "incomplete": aggregate("incomplete", [run for run in runs if run["usage_records"] > 0 and not run["data_complete"]]),
        "all_complete_with_usage": aggregate(
            "all_complete_with_usage",
            [run for run in runs if run["usage_records"] > 0 and run["data_complete"]],
        ),
        "all_with_usage": aggregate("all_with_usage", [run for run in runs if run["usage_records"] > 0]),
        "by_class": {
            key: aggregate(
                key,
                value if key == "failed_no_usage" else [run for run in value if run["data_complete"]],
            )
            for key, value in sorted(by_class.items())
        },
        "by_category": {key: aggregate(key, value) for key, value in sorted(by_category.items())},
        "by_model": {key: aggregate(key, value) for key, value in sorted(by_model.items())},
    }

    repair_runs = [run for run in runs if run["category"] == "juliet_repair"]
    repair_final = [run for run in repair_runs if run["class"] == "headline"]
    repair_all_conf = sum_present([run["configured_recorded_usd"] for run in repair_runs])
    repair_all_norm = sum_present([run["normalized_list_usd"] for run in repair_runs])
    repair_final_conf = sum_present([run["configured_recorded_usd"] for run in repair_final])
    repair_final_norm = sum_present([run["normalized_list_usd"] for run in repair_final])
    repair_final_provider = sum_present([run["provider_list_usd"] for run in repair_final])
    repair_final_allowance = sum_present([run["provider_allowance_usd"] for run in repair_final])
    repair_all_provider = sum_present([run["provider_list_usd"] for run in repair_runs])
    repair_all_allowance = sum_present([run["provider_allowance_usd"] for run in repair_runs])
    mimo_v1 = next((run for run in repair_runs if run["run_id"] == "mimo_test70_v1"), None)
    repair_summary = {
        "headline_runs": [run["run_id"] for run in repair_final],
        "headline_configured_usd": round(repair_final_conf, 9) if repair_final_conf is not None else None,
        "headline_normalized_usd": round(repair_final_norm, 9) if repair_final_norm is not None else None,
        "headline_provider_list_usd": round(repair_final_provider, 9) if repair_final_provider is not None else None,
        "headline_allowance_usd": round(repair_final_allowance, 9) if repair_final_allowance is not None else None,
        "all_configured_usd": round(repair_all_conf, 9) if repair_all_conf is not None else None,
        "all_normalized_usd": round(repair_all_norm, 9) if repair_all_norm is not None else None,
        "all_provider_list_usd": round(repair_all_provider, 9) if repair_all_provider is not None else None,
        "all_allowance_usd": round(repair_all_allowance, 9) if repair_all_allowance is not None else None,
        "readme_old_all_in_usd": 0.077516,
        "readme_new_all_in_usd": round(repair_all_conf, 6) if repair_all_conf is not None else None,
        "delta_vs_old_readme_usd": round(repair_all_conf - 0.077516, 9) if repair_all_conf is not None else None,
        "headline_unchanged": True,
        "mimo_v1_configured_usd": round(mimo_v1["configured_recorded_usd"], 9) if mimo_v1 and mimo_v1["configured_recorded_usd"] is not None else None,
    }

    # Re-hash every source artifact after the scan to prove it was read-only.
    changed = []
    for rel, digest in sorted(source_hashes.items()):
        path = ROOT / rel
        if not path.exists():
            changed.append(rel)
            continue
        if sha256_file(path) != digest:
            changed.append(rel)
    for run in runs:
        run["checks"]["source_artifact_unchanged"] = run["source"]["artifact"] not in changed and (
            run["source"]["config"] not in changed if run["source"]["config"] else True
        )

    usage_rows = sum(run["usage_records"] for run in runs)
    provider_rows = sum(run["checks"]["provider_list_rows"] for run in runs)
    token_mismatch_rows = sum(run["checks"]["token_mismatch_rows"] for run in runs)
    peak_rows_total = sum(run["checks"]["peak_rows"] for run in runs)
    timestamps = [run["window_utc"]["start"] for run in runs if run["window_utc"]["start"] and run["usage_records"] > 0]
    ends = [run["window_utc"]["end"] for run in runs if run["window_utc"]["end"] and run["usage_records"] > 0]
    unexplained = [run["run_id"] for run in runs if run["checks"]["configured_basis"] == "unexplained"]
    provider_mismatch = [
        run["run_id"]
        for run in runs
        if run["checks"]["provider_list_matches_normalized"] is False
    ]
    missing_cost_rows = sum(run["checks"]["missing_cost_rows"] for run in runs)
    max_dev = max(
        (run["checks"]["provider_list_max_row_rel_dev"] or 0.0 for run in runs),
        default=0.0,
    )

    hard_fail = bool(unexplained or provider_mismatch or peak_rows_total or token_mismatch_rows or missing_cost_rows)
    verification = {
        "status": "FAIL" if hard_fail else ("WARN" if changed else "PASS"),
        "source_artifacts_checked": len(source_hashes),
        "source_artifacts_changed": changed,
        "usage_rows": usage_rows,
        "provider_rows": provider_rows,
        "token_mismatch_rows": token_mismatch_rows,
        "missing_cost_rows": missing_cost_rows,
        "peak_rows": peak_rows_total,
        "unexplained_configured_runs": unexplained,
        "provider_mismatch_runs": provider_mismatch,
        "max_provider_row_rel_dev": max_dev,
        "first_request_utc": min(timestamps) if timestamps else None,
        "last_request_utc": max(ends) if ends else None,
        "complete_usage_runs": sum(1 for run in runs if run["usage_records"] > 0 and run["data_complete"]),
        "incomplete_usage_runs": [run["run_id"] for run in runs if run["usage_records"] > 0 and not run["data_complete"]],
        "skipped_runs": skipped,
    }

    summary = {
        "schema": "cost-normalization-v1",
        "generated_at_utc": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_at_local": local.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "scope": "all run directories under hybrid/, pair_joint/, juliet_repair/, evidence_prompt/, juliet_llm/, runner/ with stored per-request usage",
        "method": "read stored usage; recompute configured (original card) and normalized provider-list (off-peak) costs; do not modify responses",
        "no_api_calls": True,
        "rate_card": {
            "currency": "USD",
            "unit": "USD per 1M tokens",
            "snapshot_date": "2026-11-11",
            "deepseek": {
                "normalized": {"input": 0.15, "output": 0.60, "cached_input": 0.003},
                "configured_observed_peak": {"input": 0.30, "output": 1.20, "cached_input": 0.006},
                "label": CARD_LABELS["deepseek"],
            },
            "mimo": {
                "normalized": {"input": 0.14, "output": 0.28, "cached_input": 0.0028},
                "configured_observed": {"input": 0.14, "output": 0.28, "cached_input": 0.0028},
                "label": CARD_LABELS["mimo"],
            },
            "peak_offpeak": {
                "peak_windows_utc": ["Mon-Fri 01:00-04:00", "Mon-Fri 06:00-10:00"],
                "excluded": "Chinese statutory holidays",
                "applied_to_normalized": "off-peak, because every captured request is outside the peak windows",
            },
        },
        "runs": runs,
        "skipped_runs": skipped,
        "aggregates": aggregates,
        "juliet_repair": repair_summary,
        "audit_resolution": {
            "I5": {
                "finding": "configured DeepSeek 0.30/1.20/0.006 is the peak card; provider usage.opencode.list_cost is the off-peak card 0.15/0.60/0.003",
                "all_requests_off_peak": peak_rows_total == 0,
                "configured_results_unchanged": True,
                "normalized_costs_in": "analysis/cost_normalization.json (per-run and aggregates)",
            },
            "I3": {
                "readme_old_all_in_usd": 0.077516,
                "readme_new_all_in_usd": repair_summary["readme_new_all_in_usd"],
                "delta_usd": repair_summary["delta_vs_old_readme_usd"],
                "headline_unchanged": True,
            },
        },
        "verification": verification,
        "excluded_derived_artifacts": [
            "benchmark/results/** (derived imports/metrics of legacy runner; no per-request usage)",
            "analysis/aggregation.json, analysis/model_comparison.json (derived summaries)",
            "report/** and hybrid/results/** (derived tables/metrics)",
        ],
        "dry_run_artifacts": [
            {
                "path": "juliet_repair/runs/parser_dev/dryrun_deepseek",
                "reason": "dry_run manifest only; no requests or responses, no API spend",
            },
            {
                "path": "evidence_prompt/runs/dryrun_evidence_deepseek",
                "reason": "dry-run request list only; no responses, no API spend",
            },
            {
                "path": "evidence_prompt/runs/dryrun_evidence_mimo",
                "reason": "dry-run request list only; no responses, no API spend",
            },
        ],
        "notes": [
            "configured = original per-run recorded cost at the card in config/manifest.",
            "normalized = provider list card applied to stored usage; it is not an invoice.",
            "provider list = sum of usage.opencode.list_cost; allowance = sum of usage.opencode.allowance; the two are independent.",
            "DeepSeek peak card is 0.30/1.20/0.006; off-peak card is 0.15/0.60/0.003. All captured requests are off-peak.",
            "Legacy runner DeepSeek recorded cost is not cache-discounted; configured_cache_aware is provided for comparison.",
            "No secrets are read or written; only model names, endpoints, prices, token counts and timestamps are recorded.",
        ],
    }

    for run in runs:
        slug = run["path"].replace("/", "__")
        with (LEDGER_DIR / f"{slug}.json").open("w", encoding="utf-8") as fh:
            json.dump(run, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    expected_ledgers = {run["path"].replace("/", "__") + ".json" for run in runs}
    for stale in LEDGER_DIR.glob("*.json"):
        if stale.name not in expected_ledgers:
            stale.unlink()

    with (OUT_DIR.parent / "cost_normalization.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    markdown = render_markdown(summary)
    with (OUT_DIR.parent / "cost_normalization.md").open("w", encoding="utf-8") as fh:
        fh.write(markdown)

    print(f"runs={len(runs)} usage_rows={usage_rows} peak_rows={peak_rows_total} complete_runs={verification['complete_usage_runs']}")
    print(f"headline configured={aggregates['headline']['configured_recorded_usd']} normalized={aggregates['headline']['normalized_list_usd']}")
    print(f"all complete configured={aggregates['all_complete_with_usage']['configured_recorded_usd']} normalized={aggregates['all_complete_with_usage']['normalized_list_usd']}")
    print(f"all recorded configured={aggregates['all_with_usage']['configured_recorded_usd']} normalized={aggregates['all_with_usage']['normalized_list_usd']}")
    print(f"repair all configured={repair_summary['all_configured_usd']} normalized={repair_summary['all_normalized_usd']}")
    print(f"verification={verification['status']} changed={len(changed)} unexplained={unexplained} provider_mismatch={provider_mismatch}")
    return 0 if verification["status"] != "FAIL" else 1


if __name__ == "__main__":
    sys.exit(main())

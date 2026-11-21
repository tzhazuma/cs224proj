#!/usr/bin/env python3
"""Zero-API re-analysis of schema-invalid outputs in the frozen SecVulEval runs.

This script is deliberately read-only with respect to every existing artefact.
It reads the six DeepSeek and six MiMo test runs under ``runner/runs`` and the
two frozen split files, then writes four derived files in this directory:

    schema_recovery.json
    schema_recovery.md
    records.jsonl
    (README.md is maintained by hand and is not generated)

The analysis separates three views that are often conflated:

1. ``official``  - the run's strict schema verdict (status == "ok").
2. ``code-only`` - a declared salvage policy for repair responses that are
   valid JSON with a non-empty ``fixed_function`` but miss ``explanation``.
3. ``usable``    - a structural proxy: complete function + substantive change.
   It is not a correctness oracle.  No compiler, test, PoC, or human review is
   run here.

Nothing in this script calls a model or the network.  All costs are accounting
reconstructions from recorded token usage, not new charges.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "schema-recovery-2026-11-14.1"
ANALYSIS_DATE = "2026-11-14"
DEFAULT_SEED = 42
DEFAULT_BOOTSTRAP_REPS = 10_000
Z_95 = 1.959963984540054

STRATEGIES = ("direct", "few-shot", "context")
TASKS = ("independent", "pairs")
RUNS = tuple((strategy, task) for strategy in STRATEGIES for task in TASKS)
ALIASES = ("is_vulnerability", "is_vulnerative")

# Project-wide off-peak list card from analysis/cost_normalization.md.
# DeepSeek's configured card (0.30/1.20/0.006) is the observed peak card.
OFFPEAK_LIST_CARDS: dict[str, dict[str, float]] = {
    "deepseek": {"input": 0.15, "output": 0.60, "cached_input": 0.003},
    "mimo": {"input": 0.14, "output": 0.28, "cached_input": 0.0028},
}
CONFIGURED_PEAK_LABELS = {
    "deepseek": "DeepSeek configured observed-peak card 0.30/1.20/0.006",
    "mimo": "MiMo published flat card 0.14/0.28/0.0028",
}
OFFPEAK_LIST_LABELS = {
    "deepseek": "DeepSeek off-peak list 0.15/0.60/0.003 (analysis/cost_normalization.md)",
    "mimo": "MiMo published flat 0.14/0.28/0.0028 (same peak/off-peak)",
}

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNNER_ROOT = PROJECT_ROOT / "runner"
if str(RUNNER_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNNER_ROOT))
try:
    from secvul_runner.validation import (  # type: ignore
        analyze_repair,
        collapse_whitespace,
        normalize_code,
        parse_json_object,
    )
except Exception as exc:  # pragma: no cover - only hit outside the repo
    raise SystemExit(f"cannot import runner validator from {RUNNER_ROOT}: {exc}")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def rate(numerator: int | float, denominator: int | float) -> float | None:
    if not denominator:
        return None
    return float(numerator) / float(denominator)


def share(part: float | None, whole: float | None) -> float | None:
    if part is None or not whole:
        return None
    return part / whole


def wilson(k: int, n: int, z: float = Z_95) -> dict[str, Any] | None:
    if n <= 0:
        return None
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    half = z * math.sqrt(max(0.0, p * (1.0 - p) / n + z * z / (4.0 * n * n))) / denom
    return {
        "successes": k,
        "total": n,
        "estimate": p,
        "low": max(0.0, centre - half),
        "high": min(1.0, centre + half),
        "confidence": 0.95,
        "method": "wilson",
    }


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    return rows


def finish_reason(record: dict[str, Any]) -> str | None:
    response = record.get("response") or {}
    direct = response.get("finish_reason")
    if isinstance(direct, str):
        return direct
    for attempt in reversed(response.get("attempts") or []):
        raw = attempt.get("raw_body")
        if not raw:
            continue
        try:
            body = json.loads(raw)
            choices = body.get("choices") or []
            if choices and isinstance(choices[0], dict):
                value = choices[0].get("finish_reason")
                if isinstance(value, str):
                    return value
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def key_error_lists(error: str) -> tuple[list[str], list[str]]:
    def parse(field: str) -> list[str]:
        match = re.search(rf"{field}=\[(.*?)\]", error)
        if not match:
            return []
        return [
            item.strip().strip("'\"")
            for item in match.group(1).split(",")
            if item.strip()
        ]

    return parse("missing"), parse("extra")


# ---------------------------------------------------------------------------
# cost reconstruction
# ---------------------------------------------------------------------------


def model_key_from_config(config: dict[str, Any]) -> str | None:
    text = str(((config.get("api") or {}).get("model") or "")).lower()
    if "deepseek" in text:
        return "deepseek"
    if "mimo" in text:
        return "mimo"
    return None


def _card_cost(prompt: int, completion: int, cached: int, card: dict[str, float]) -> float:
    return (
        (prompt - cached) * card["input"]
        + cached * card["cached_input"]
        + completion * card["output"]
    ) / 1_000_000.0


def configured_peak_cache_aware_cost(record: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Recompute two cache-aware cost views from recorded token usage.

    ``configured_peak_cache_aware_usd`` uses the run's configured card.  For
    DeepSeek that card is the observed peak card 0.30/1.20/0.006; for MiMo it is
    the published flat card 0.14/0.28/0.0028.

    ``offpeak_list_normalized_usd`` uses the project-wide off-peak list card
    from ``analysis/cost_normalization.md``: DeepSeek 0.15/0.60/0.003, MiMo
    0.14/0.28/0.0028.  This is the view comparable with that report's
    ``normalized_list_usd``; the configured-peak view is not.

    ``cached_prompt_tokens`` is a subset of ``prompt_tokens``.  DeepSeek writes
    zero into ``response.cost.cached_prompt_tokens`` even when usage reports a
    cache hit, so the recorded cost is kept separately.
    """

    response = record.get("response") or {}
    usage = response.get("usage") or {}
    reported = (response.get("cost") or {}).get("cost_usd")
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    details = usage.get("prompt_tokens_details") or {}
    cached = details.get("cached_tokens") or 0

    usage_known = (
        isinstance(prompt, int)
        and not isinstance(prompt, bool)
        and prompt >= 0
        and isinstance(completion, int)
        and not isinstance(completion, bool)
        and completion >= 0
    )
    if not usage_known:
        return {
            "usage_known": False,
            "configured_peak_known": False,
            "configured_peak_cache_aware_usd": None,
            "offpeak_known": False,
            "offpeak_list_normalized_usd": None,
            "reported_usd": reported,
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "cached_tokens": cached,
            "model_key": model_key_from_config(config),
            "cost_basis": "missing_or_invalid_usage",
        }

    if not isinstance(cached, int) or isinstance(cached, bool) or cached < 0 or cached > prompt:
        cached = 0

    model_key = model_key_from_config(config)
    api = config.get("api") or {}
    input_price = api.get("input_price_usd_per_1m")
    output_price = api.get("output_price_usd_per_1m")
    cached_price = api.get("cached_input_price_usd_per_1m")
    if cached_price is None:
        cached_price = input_price
    configured_known = all(
        isinstance(value, (int, float)) for value in (input_price, output_price, cached_price)
    )
    configured_card = {
        "input": float(input_price) if configured_known else None,
        "output": float(output_price) if configured_known else None,
        "cached_input": float(cached_price) if configured_known else None,
    }
    configured_cost = (
        _card_cost(prompt, completion, cached, configured_card)  # type: ignore[arg-type]
        if configured_known
        else None
    )

    offpeak_card = OFFPEAK_LIST_CARDS.get(model_key or "")
    offpeak_known = offpeak_card is not None
    offpeak_cost = _card_cost(prompt, completion, cached, offpeak_card) if offpeak_known else None

    return {
        "usage_known": True,
        "configured_peak_known": configured_known,
        "configured_peak_cache_aware_usd": configured_cost,
        "configured_peak_card": configured_card,
        "configured_peak_basis": CONFIGURED_PEAK_LABELS.get(model_key or "", "configured card"),
        "offpeak_known": offpeak_known,
        "offpeak_list_normalized_usd": offpeak_cost,
        "offpeak_list_card": dict(offpeak_card) if offpeak_card else None,
        "offpeak_basis": OFFPEAK_LIST_LABELS.get(model_key or "", "off-peak list card"),
        "reported_usd": reported,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "cached_tokens": cached,
        "model_key": model_key,
        "cost_basis": "configured_peak_cache_aware + offpeak_list_normalized",
    }


def _rollup_view(items: list[dict[str, Any]], value_key: str, known_key: str) -> dict[str, Any]:
    known = [item for item in items if item.get(known_key) and item.get(value_key) is not None]
    values = [float(item[value_key]) for item in known]
    return {
        "known_records": len(known),
        "unknown_records": len(items) - len(known),
        "complete": len(known) == len(items),
        "usd": sum(values),
        "mean_usd": statistics.mean(values) if values else None,
        "median_usd": statistics.median(values) if values else None,
        "p90_usd": percentile(values, 0.90),
        "max_usd": max(values) if values else None,
    }


def cost_rollup(costs: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(costs)
    configured = _rollup_view(
        items, "configured_peak_cache_aware_usd", "configured_peak_known"
    )
    offpeak = _rollup_view(items, "offpeak_list_normalized_usd", "offpeak_known")
    reported = [
        float(item["reported_usd"])
        for item in items
        if item.get("reported_usd") is not None
    ]
    return {
        "records": len(items),
        "reported_usd": sum(reported),
        "reported_known_records": len(reported),
        "configured_peak_cache_aware_usd": configured["usd"],
        "mean_configured_peak_cache_aware_usd": configured["mean_usd"],
        "median_configured_peak_cache_aware_usd": configured["median_usd"],
        "p90_configured_peak_cache_aware_usd": configured["p90_usd"],
        "max_configured_peak_cache_aware_usd": configured["max_usd"],
        "configured_peak_known_records": configured["known_records"],
        "configured_peak_unknown_records": configured["unknown_records"],
        "configured_peak_complete": configured["complete"],
        "offpeak_list_normalized_usd": offpeak["usd"],
        "mean_offpeak_list_normalized_usd": offpeak["mean_usd"],
        "median_offpeak_list_normalized_usd": offpeak["median_usd"],
        "p90_offpeak_list_normalized_usd": offpeak["p90_usd"],
        "max_offpeak_list_normalized_usd": offpeak["max_usd"],
        "offpeak_known_records": offpeak["known_records"],
        "offpeak_unknown_records": offpeak["unknown_records"],
        "offpeak_complete": offpeak["complete"],
        "configured_peak": {
            **configured,
            "total_usd": configured["usd"],
            "basis": "cache-aware at each run's configured card; DeepSeek observed peak 0.30/1.20/0.006",
        },
        "offpeak_list_normalized": {
            **offpeak,
            "total_usd": offpeak["usd"],
            "basis": "cache-aware at DeepSeek off-peak 0.15/0.60/0.003; MiMo flat 0.14/0.28/0.0028; matches analysis/cost_normalization.md",
        },
        "cost_basis": "configured_peak_cache_aware + offpeak_list_normalized",
    }


# ---------------------------------------------------------------------------
# structural and lexical checks
# ---------------------------------------------------------------------------


def strip_comments(code: str) -> str:
    """Remove C/C++ comments while preserving string and character literals."""

    out: list[str] = []
    i = 0
    n = len(code)
    state = "normal"
    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state == "normal":
            if ch == "/" and nxt == "/":
                state = "line"
                i += 2
                out.append(" ")
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                i += 2
                out.append(" ")
                continue
            if ch == '"':
                state = "string"
                out.append(ch)
                i += 1
                continue
            if ch == "'":
                state = "char"
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
        elif state == "line":
            if ch == "\n":
                state = "normal"
                out.append("\n")
            i += 1
        elif state == "block":
            if ch == "*" and nxt == "/":
                state = "normal"
                i += 2
                out.append(" ")
            else:
                i += 1
        else:  # string or char
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(code[i + 1])
                i += 2
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "normal"
            i += 1
    return "".join(out)


TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d[\w.]*|[^\s]')


def tokenize(code: str) -> tuple[str, ...]:
    return tuple(TOKEN_RE.findall(strip_comments(code)))


def line_diff(source: str, fixed: str) -> dict[str, Any]:
    source_lines = normalize_code(source).splitlines()
    fixed_lines = normalize_code(fixed).splitlines()
    matcher = SequenceMatcher(None, source_lines, fixed_lines, autojunk=False)
    added = 0
    removed = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            added += j2 - j1
        if tag in {"replace", "delete"}:
            removed += i2 - i1
    changed = added + removed
    return {
        "source_lines": len(source_lines),
        "fixed_lines": len(fixed_lines),
        "added_lines": added,
        "removed_lines": removed,
        "changed_lines": changed,
        "change_ratio": changed / max(len(source_lines), len(fixed_lines), 1),
    }


def knr_aware_complete(fixed: str, checks: dict[str, Any]) -> bool:
    """Accept old-style K&R definitions that the canonical heuristic rejects.

    ``analyze_repair`` requires the text before the first ``{`` not to end in
    ``;``.  Old-style C parameter declarations do end in ``;``.  This helper is
    a narrow sensitivity check, not a C parser.  It only adds records that are
    balanced, unfenced, not diff-like, end in ``}``, and look like a
    ``name(args)`` header followed by declarations.
    """

    if checks.get("complete_function"):
        return True
    if not (
        checks.get("balanced_delimiters")
        and not checks.get("contains_markdown_fence")
        and not checks.get("starts_like_diff")
    ):
        return False
    text = fixed.strip()
    if not text.endswith("}"):
        return False
    brace = text.find("{")
    if brace < 0:
        return False
    prefix = text[:brace]
    lines = [line.strip() for line in prefix.splitlines() if line.strip()]
    if not lines:
        return False
    first = lines[0]
    return (
        "(" in first
        and ")" in first
        and not first.endswith(";")
        and prefix.rstrip().endswith(";")
    )


def profile_repair(fixed: str, source: str) -> dict[str, Any]:
    checks = analyze_repair(fixed, source)
    text_changed = bool(checks["changed_from_input"])
    substantive = collapse_whitespace(fixed) != collapse_whitespace(source)
    token_changed = tokenize(fixed) != tokenize(source)
    knr = knr_aware_complete(fixed, checks)
    usable_canonical = bool(checks["complete_function"] and substantive and token_changed)
    usable_knr = bool(knr and substantive and token_changed)

    if usable_canonical:
        non_usable_class = "usable_canonical"
    elif usable_knr:
        non_usable_class = "knr_false_negative_but_usable"
    elif not text_changed:
        non_usable_class = "no_change"
    elif not substantive:
        non_usable_class = "whitespace_only"
    elif not token_changed:
        non_usable_class = "comment_only"
    elif not checks["complete_function"]:
        non_usable_class = "structurally_incomplete"
    else:
        non_usable_class = "other"

    return {
        "structural": {
            "canonical_complete": bool(checks["complete_function"]),
            "knr_aware_complete": bool(knr),
            "knr_false_negative": bool(knr and not checks["complete_function"]),
            "balanced_delimiters": bool(checks["balanced_delimiters"]),
            "function_like_prefix": bool(checks["function_like_prefix"]),
            "ends_with_closing_brace": normalize_code(fixed).rstrip().endswith("}"),
            "contains_markdown_fence": bool(checks["contains_markdown_fence"]),
            "starts_like_diff": bool(checks["starts_like_diff"]),
            "fixed_line_count": int(checks["fixed_line_count"]),
            "fixed_char_count": len(fixed),
            "source_char_count": len(source),
        },
        "change": {
            "text_changed": text_changed,
            "substantive_changed": bool(substantive),
            "comment_insensitive_changed": bool(token_changed),
            "no_change": not text_changed,
            "whitespace_only": bool(text_changed and not substantive),
            "comment_only": bool(substantive and not token_changed),
            "line_diff": line_diff(source, fixed),
            "fixed_sha256": checks["fixed_code_sha256"],
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        },
        "usable_canonical": usable_canonical,
        "usable_knr": usable_knr,
        "non_usable_class": non_usable_class,
    }


# ---------------------------------------------------------------------------
# loading and official cross-checks
# ---------------------------------------------------------------------------


def dataset_paths(project_root: Path) -> dict[str, Path]:
    return {
        "independent": project_root / "splits" / "test_detection_160.json",
        "pairs": project_root / "splits" / "test_pairs_180.json",
    }


def load_datasets(project_root: Path) -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}
    for task, path in dataset_paths(project_root).items():
        if not path.exists():
            raise SystemExit(f"missing dataset: {path}")
        raw = path.read_bytes()
        loaded[task] = {
            "path": path,
            "sha256": sha256_bytes(raw),
            "json": json.loads(raw.decode("utf-8")),
        }
    return loaded


def build_source_index(datasets: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    independent = datasets["independent"]["json"]
    for record in independent["samples"]:
        sample_id = f"idx:{record['idx']}"
        index[sample_id] = {
            "sample_id": sample_id,
            "task": "independent",
            "code": record["func_body"],
            "project": record.get("project") or "unknown",
            "cwe_list": record.get("cwe_list") or [],
            "idx": record.get("idx"),
            "pair_id": None,
            "side": None,
            "label": bool(record.get("is_vulnerable")),
        }
    pairs = datasets["pairs"]["json"]
    for pair in pairs["pairs"]:
        for side in ("vulnerable", "fixed"):
            record = pair[side]
            sample_id = f"pair:{pair['pair_id']}:{side}"
            index[sample_id] = {
                "sample_id": sample_id,
                "task": "pairs",
                "code": record["func_body"],
                "project": record.get("project") or "unknown",
                "cwe_list": record.get("cwe_list") or [],
                "idx": record.get("idx"),
                "pair_id": pair["pair_id"],
                "side": side,
                "label": bool(record.get("is_vulnerable")),
            }
    return index


def run_directory(project_root: Path, model: str, strategy: str, task: str) -> Path:
    prefix = "test_v1_mimo" if model == "mimo" else "test_v1"
    return project_root / "runner" / "runs" / f"{prefix}_{strategy}_{task}"


def load_runs(
    project_root: Path,
    model: str,
    datasets: dict[str, dict[str, Any]],
    allow_source_drift: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    runs: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    for strategy, task in RUNS:
        directory = run_directory(project_root, model, strategy, task)
        for name in ("config.json", "metrics.json", "results.jsonl"):
            if not (directory / name).exists():
                raise SystemExit(f"missing {directory / name}")
        config = load_json(directory / "config.json")
        metrics = load_json(directory / "metrics.json")
        records = load_jsonl(directory / "results.jsonl")

        if config.get("strategy") != strategy or config.get("dataset_type") != task:
            raise SystemExit(f"{directory}: config strategy/type mismatch")
        declared_hash = config.get("dataset_sha256")
        actual_hash = datasets[task]["sha256"]
        if declared_hash != actual_hash:
            problem = {
                "run_id": directory.name,
                "dataset": task,
                "declared_sha256": declared_hash,
                "actual_sha256": actual_hash,
            }
            problems.append(problem)
            if not allow_source_drift:
                raise SystemExit(
                    f"{directory}: dataset hash mismatch (declared {declared_hash}, actual {actual_hash}); "
                    "rerun with --allow-source-drift only if this is intentional"
                )
        expected = config.get("expected_requests")
        if isinstance(expected, int) and expected != len(records):
            raise SystemExit(f"{directory}: expected {expected} records, found {len(records)}")

        for record in records:
            record["_cost"] = configured_peak_cache_aware_cost(record, config)
            if record.get("status") != "ok":
                record["_finish_reason"] = finish_reason(record)

        runs.append(
            {
                "model": model,
                "strategy": strategy,
                "task": task,
                "run_id": directory.name,
                "directory": directory,
                "config": config,
                "metrics": metrics,
                "records": records,
            }
        )
    return runs, problems


def crosscheck_run(run: dict[str, Any], source_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records = run["records"]
    repair = [record for record in records if record.get("task") == "repair"]
    detection = [record for record in records if record.get("task") == "detection"]
    metrics = run["metrics"]
    checks: list[dict[str, Any]] = []

    def add(field: str, expected: Any, actual: Any) -> None:
        if expected is None:
            return
        checks.append(
            {
                "run_id": run["run_id"],
                "field": field,
                "metrics": expected,
                "recount": actual,
                "match": expected == actual,
            }
        )

    repair_metrics = metrics.get("repair") or {}
    add("repair.requested", repair_metrics.get("requested"), len(repair))
    add("repair.schema_valid", repair_metrics.get("schema_valid"), sum(1 for record in repair if record.get("status") == "ok"))
    add("repair.schema_invalid", repair_metrics.get("schema_invalid"), sum(1 for record in repair if record.get("status") != "ok"))
    complete_and_changed = 0
    for record in repair:
        if record.get("status") != "ok":
            continue
        parsed = record.get("parsed") or {}
        fixed = parsed.get("fixed_function")
        if not isinstance(fixed, str):
            continue
        source = source_index.get(record.get("sample_id"))
        if not source:
            continue
        profile = profile_repair(fixed, source["code"])
        if profile["structural"]["canonical_complete"] and profile["change"]["text_changed"]:
            complete_and_changed += 1
    add("repair.complete_and_changed", repair_metrics.get("complete_and_changed"), complete_and_changed)

    detection_metrics = metrics.get("detection") or {}
    add("detection.requested", detection_metrics.get("requested"), len(detection))
    add("detection.schema_invalid", detection_metrics.get("schema_invalid"), sum(1 for record in detection if record.get("status") != "ok"))
    add("detection.valid_predictions", detection_metrics.get("valid_predictions"), sum(1 for record in detection if record.get("status") == "ok"))

    cost_metrics = metrics.get("cost") or {}
    reported_sum = sum(
        float((record.get("response") or {}).get("cost", {}).get("cost_usd") or 0.0)
        for record in records
    )
    expected_cost = cost_metrics.get("total_cost_usd")
    if isinstance(expected_cost, (int, float)):
        checks.append(
            {
                "run_id": run["run_id"],
                "field": "cost.total_cost_usd",
                "metrics": float(expected_cost),
                "recount": reported_sum,
                "match": abs(float(expected_cost) - reported_sum) <= 1e-6,
            }
        )
    return checks


def classify_deepseek_repair(record: dict[str, Any]) -> str:
    if record.get("status") == "ok":
        return "ok"
    if record.get("status") == "error":
        return "api_error"
    error = str((record.get("validation") or {}).get("error") or "")
    missing, extra = key_error_lists(error)
    if missing == ["explanation"] and extra == []:
        return "missing_explanation"
    if "Unterminated string" in error and record.get("_finish_reason") == "length":
        return "truncation"
    if "Unterminated string" in error:
        return "truncation_unconfirmed"
    return "other_schema"


def classify_mimo_detection(record: dict[str, Any]) -> str:
    if record.get("status") == "ok":
        return "ok"
    if record.get("status") == "error":
        return "api_error"
    error = str((record.get("validation") or {}).get("error") or "")
    if "detection JSON keys mismatch" not in error:
        return "other_schema"
    missing, extra = key_error_lists(error)
    if missing == ["is_vulnerable"] and extra and all(key in ALIASES for key in extra):
        return "field_drift"
    if not missing and extra and all(key in ALIASES for key in extra):
        return "field_drift_duplicate"
    return "other_schema"


def classify_mimo_repair(record: dict[str, Any]) -> str:
    if record.get("status") == "ok":
        return "ok"
    if record.get("status") == "error":
        return "api_error"
    error = str((record.get("validation") or {}).get("error") or "")
    if "Unterminated string" in error and record.get("_finish_reason") == "length":
        return "truncation"
    if "Unterminated string" in error:
        return "truncation_unconfirmed"
    return "other_schema"


def analyze_repair_record(
    run: dict[str, Any],
    record: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    model: str,
) -> dict[str, Any]:
    source = source_index.get(record.get("sample_id"))
    if not source:
        raise SystemExit(f"{run['run_id']}: no source for {record.get('sample_id')!r}")
    error_class = (
        classify_deepseek_repair(record)
        if model == "deepseek"
        else classify_mimo_repair(record)
    )
    profile = None
    keys: tuple[str, ...] | None = None
    if error_class == "ok":
        fixed = (record.get("parsed") or {}).get("fixed_function")
        if isinstance(fixed, str):
            profile = profile_repair(fixed, source["code"])
    elif error_class == "missing_explanation":
        content = (record.get("response") or {}).get("content")
        if isinstance(content, str):
            try:
                obj = parse_json_object(content)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                keys = tuple(sorted(obj))
                fixed = obj.get("fixed_function")
                if isinstance(fixed, str) and fixed.strip():
                    profile = profile_repair(fixed, source["code"])
    return {
        "run": run,
        "record": record,
        "source": source,
        "class": error_class,
        "profile": profile,
        "keys": keys,
        "finish_reason": record.get("_finish_reason"),
        "cost": record["_cost"],
        "fatal": error_class
        in {"truncation", "truncation_unconfirmed", "other_schema", "api_error"},
    }


def analyze_detection_record(
    run: dict[str, Any],
    record: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    model: str,
) -> dict[str, Any]:
    source = source_index.get(record.get("sample_id"))
    error_class = (
        classify_mimo_detection(record)
        if model == "mimo"
        else ("ok" if record.get("status") == "ok" else "other_schema")
    )
    parsed: dict[str, Any] | None = None
    parse_ok = False
    if error_class != "ok":
        content = (record.get("response") or {}).get("content")
        if isinstance(content, str):
            try:
                value = parse_json_object(content)
                if isinstance(value, dict):
                    parsed = value
                    parse_ok = True
            except Exception:
                parsed = None

    missing: list[str] = []
    extra: list[str] = []
    alias = None
    drift_only = False
    payload_valid = False
    recovered = False
    recovered_value = None
    if parsed is not None:
        expected = {"is_vulnerable", "confidence", "rationale"}
        actual = set(parsed)
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        alias = next((key for key in ALIASES if key in actual), None)
        canonical_present = "is_vulnerable" in actual
        drift_only = bool(
            alias
            and (
                (missing == ["is_vulnerable"] and extra == [alias])
                or (not missing and canonical_present and extra == [alias])
            )
        )
        value = parsed.get("is_vulnerable") if canonical_present else parsed.get(alias)
        confidence = parsed.get("confidence")
        rationale = parsed.get("rationale")
        confidence_ok = (
            isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and math.isfinite(float(confidence))
            and 0.0 <= float(confidence) <= 1.0
        )
        payload_valid = bool(
            isinstance(value, bool)
            and confidence_ok
            and isinstance(rationale, str)
        )
        recovered = bool(drift_only and payload_valid)
        if isinstance(value, bool):
            recovered_value = value

    label = record.get("label")
    label_agreement = bool(
        recovered and isinstance(label, bool) and recovered_value is not None and recovered_value == label
    )
    return {
        "run": run,
        "record": record,
        "source": source,
        "class": error_class,
        "parse_ok": parse_ok,
        "keys": tuple(sorted(parsed)) if parsed is not None else None,
        "missing_keys": missing,
        "extra_keys": extra,
        "alias": alias,
        "drift_only": drift_only,
        "payload_valid": payload_valid,
        "recovered": recovered,
        "recovered_value": recovered_value,
        "gold_label": label if isinstance(label, bool) else None,
        "label_agreement": label_agreement,
        "finish_reason": record.get("_finish_reason"),
        "cost": record["_cost"],
        "fatal": not recovered,
    }


def analyze_runs(
    runs: list[dict[str, Any]],
    source_index: dict[str, dict[str, Any]],
    model: str,
) -> None:
    for run in runs:
        repair_items: list[dict[str, Any]] = []
        detection_items: list[dict[str, Any]] = []
        for record in run["records"]:
            task = record.get("task")
            if task == "repair":
                repair_items.append(analyze_repair_record(run, record, source_index, model))
            elif task == "detection":
                detection_items.append(analyze_detection_record(run, record, source_index, model))
        run["repair_items"] = repair_items
        run["detection_items"] = detection_items
# ---------------------------------------------------------------------------
# summaries
# ---------------------------------------------------------------------------


def primary_cwe(cwe_list: Any) -> str:
    if not cwe_list:
        return "unlabeled"
    text = " ".join(str(item) for item in cwe_list)
    matches = re.findall(r"CWE-\d+", text)
    return matches[0] if matches else "unlabeled"


def profile_counts(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(items)
    usable_c = sum(1 for item in items if item["profile"] and item["profile"]["usable_canonical"])
    usable_k = sum(1 for item in items if item["profile"] and item["profile"]["usable_knr"])
    no_change = sum(1 for item in items if item["profile"] and item["profile"]["change"]["no_change"])
    whitespace = sum(
        1
        for item in items
        if item["profile"] and item["profile"]["change"]["whitespace_only"]
    )
    comment_only = sum(
        1
        for item in items
        if item["profile"] and item["profile"]["change"]["comment_only"]
    )
    canonical_incomplete = sum(
        1
        for item in items
        if item["profile"]
        and not item["profile"]["structural"]["canonical_complete"]
        and item["profile"]["change"]["substantive_changed"]
    )
    knr_false_negative = sum(
        1
        for item in items
        if item["profile"] and item["profile"]["structural"]["knr_false_negative"]
    )
    return {
        "records": len(items),
        "usable_canonical": usable_c,
        "usable_knr": usable_k,
        "no_change": no_change,
        "whitespace_only": whitespace,
        "comment_only": comment_only,
        "canonical_incomplete": canonical_incomplete,
        "knr_false_negative": knr_false_negative,
    }


def cell_metrics(items: list[dict[str, Any]]) -> dict[str, Any]:
    requests = len(items)
    valid = [item for item in items if item["class"] == "ok"]
    missing = [item for item in items if item["class"] == "missing_explanation"]
    official_text = sum(
        1
        for item in valid
        if item["profile"]
        and item["profile"]["structural"]["canonical_complete"]
        and item["profile"]["change"]["text_changed"]
    )
    official_sub = sum(
        1
        for item in valid
        if item["profile"]
        and item["profile"]["structural"]["canonical_complete"]
        and item["profile"]["change"]["substantive_changed"]
    )
    official_sub_knr = sum(
        1
        for item in valid
        if item["profile"]
        and item["profile"]["structural"]["knr_aware_complete"]
        and item["profile"]["change"]["substantive_changed"]
    )
    official_code = sum(
        1
        for item in valid
        if item["profile"] and item["profile"]["usable_canonical"]
    )
    official_code_knr = sum(
        1
        for item in valid
        if item["profile"] and item["profile"]["usable_knr"]
    )
    salvage_text = sum(
        1
        for item in missing
        if item["profile"]
        and item["profile"]["structural"]["canonical_complete"]
        and item["profile"]["change"]["text_changed"]
    )
    salvage_sub = sum(
        1
        for item in missing
        if item["profile"]
        and item["profile"]["structural"]["canonical_complete"]
        and item["profile"]["change"]["substantive_changed"]
    )
    salvage_sub_knr = sum(
        1
        for item in missing
        if item["profile"]
        and item["profile"]["structural"]["knr_aware_complete"]
        and item["profile"]["change"]["substantive_changed"]
    )
    salvage_code = sum(
        1
        for item in missing
        if item["profile"] and item["profile"]["usable_canonical"]
    )
    salvage_code_knr = sum(
        1
        for item in missing
        if item["profile"] and item["profile"]["usable_knr"]
    )
    code_text = official_text + salvage_text
    code_sub = official_sub + salvage_sub
    code_sub_knr = official_sub_knr + salvage_sub_knr
    code_code = official_code + salvage_code
    code_code_knr = official_code_knr + salvage_code_knr
    return {
        "requests": requests,
        "official_schema_valid": len(valid),
        "official_schema_invalid": requests - len(valid),
        "official_schema_valid_rate": rate(len(valid), requests),
        "missing_explanation": len(missing),
        "truncation": sum(1 for item in items if item["class"] in {"truncation", "truncation_unconfirmed"}),
        "other_invalid": sum(
            1
            for item in items
            if item["class"] not in {"ok", "missing_explanation", "truncation", "truncation_unconfirmed"}
        ),
        "code_only_admitted": len(valid) + len(missing),
        "code_only_admission_rate": rate(len(valid) + len(missing), requests),
        "official_usable_text": official_text,
        "official_usable_sub": official_sub,
        "official_usable_sub_knr": official_sub_knr,
        "official_usable_code": official_code,
        "official_usable_code_knr": official_code_knr,
        "salvage_usable_text": salvage_text,
        "salvage_usable_sub": salvage_sub,
        "salvage_usable_sub_knr": salvage_sub_knr,
        "salvage_usable_code": salvage_code,
        "salvage_usable_code_knr": salvage_code_knr,
        "code_usable_text": code_text,
        "code_usable_sub": code_sub,
        "code_usable_sub_knr": code_sub_knr,
        "code_usable_code": code_code,
        "code_usable_code_knr": code_code_knr,
        "official_usable_text_rate": rate(official_text, requests),
        "official_usable_sub_rate": rate(official_sub, requests),
        "official_usable_sub_knr_rate": rate(official_sub_knr, requests),
        "official_usable_code_rate": rate(official_code, requests),
        "official_usable_code_knr_rate": rate(official_code_knr, requests),
        "code_usable_text_rate": rate(code_text, requests),
        "code_usable_sub_rate": rate(code_sub, requests),
        "code_usable_sub_knr_rate": rate(code_sub_knr, requests),
        "code_usable_code_rate": rate(code_code, requests),
        "code_usable_code_knr_rate": rate(code_code_knr, requests),
        "delta_code_text_pp": (rate(code_text - official_text, requests) or 0.0) * 100.0,
        "delta_code_sub_pp": (rate(code_sub - official_sub, requests) or 0.0) * 100.0,
        "delta_code_sub_knr_pp": (rate(code_sub_knr - official_sub_knr, requests) or 0.0) * 100.0,
        "delta_code_code_pp": (rate(code_code - official_code, requests) or 0.0) * 100.0,
        "delta_code_code_knr_pp": (rate(code_code_knr - official_code_knr, requests) or 0.0) * 100.0,
    }


def build_deepseek_summary(
    runs: list[dict[str, Any]],
    source_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    items = [item for run in runs for item in run["repair_items"]]
    valid = [item for item in items if item["class"] == "ok"]
    invalid = [item for item in items if item["class"] != "ok"]
    missing = [item for item in items if item["class"] == "missing_explanation"]
    truncation = [item for item in items if item["class"] in {"truncation", "truncation_unconfirmed"}]

    class_counts = Counter(item["class"] for item in invalid)
    class_costs = defaultdict(list)
    for item in invalid:
        class_costs[item["class"]].append(item["cost"])

    invalid_classes = {}
    for name, count in sorted(class_counts.items()):
        rollup = cost_rollup(class_costs[name])
        invalid_classes[name] = {
            "n": count,
            "share_of_requests": rate(count, len(items)),
            "share_of_invalid": rate(count, len(invalid)),
            "cost": rollup,
            "share_of_invalid_cost": share(rollup["configured_peak_cache_aware_usd"], cost_rollup([item["cost"] for item in invalid])["configured_peak_cache_aware_usd"]),
        }

    structural = {
        "json_parseable": sum(1 for item in missing if item["profile"] is not None),
        "fixed_function_present": sum(1 for item in missing if item["profile"] is not None),
        "canonical_complete": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["canonical_complete"]
        ),
        "knr_aware_complete": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["knr_aware_complete"]
        ),
        "balanced_delimiters": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["balanced_delimiters"]
        ),
        "function_like_prefix": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["function_like_prefix"]
        ),
        "ends_with_closing_brace": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["ends_with_closing_brace"]
        ),
        "no_markdown_fence": sum(
            1 for item in missing if item["profile"] and not item["profile"]["structural"]["contains_markdown_fence"]
        ),
        "not_diff_like": sum(
            1 for item in missing if item["profile"] and not item["profile"]["structural"]["starts_like_diff"]
        ),
        "knr_false_negative": sum(
            1 for item in missing if item["profile"] and item["profile"]["structural"]["knr_false_negative"]
        ),
    }

    change = {
        "text_changed": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["text_changed"]
        ),
        "substantive_changed": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["substantive_changed"]
        ),
        "comment_insensitive_changed": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["comment_insensitive_changed"]
        ),
        "no_change": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["no_change"]
        ),
        "whitespace_only": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["whitespace_only"]
        ),
        "comment_only": sum(
            1 for item in missing if item["profile"] and item["profile"]["change"]["comment_only"]
        ),
    }

    usable_canonical = [item for item in missing if item["profile"] and item["profile"]["usable_canonical"]]
    usable_knr = [item for item in missing if item["profile"] and item["profile"]["usable_knr"]]
    nonusable = [item for item in missing if not (item["profile"] and item["profile"]["usable_canonical"])]
    nonusable_classes = Counter(
        item["profile"]["non_usable_class"] if item["profile"] else "unparseable"
        for item in nonusable
    )

    line_stats = [
        item["profile"]["change"]["line_diff"]
        for item in missing
        if item["profile"] and item["profile"]["change"]["substantive_changed"]
    ]
    line_diff_summary = {
        "n": len(line_stats),
        "changed_lines": {
            "mean": statistics.mean([row["changed_lines"] for row in line_stats]) if line_stats else None,
            "median": statistics.median([row["changed_lines"] for row in line_stats]) if line_stats else None,
            "p25": percentile([row["changed_lines"] for row in line_stats], 0.25),
            "p75": percentile([row["changed_lines"] for row in line_stats], 0.75),
            "max": max((row["changed_lines"] for row in line_stats), default=None),
        },
        "change_ratio": {
            "mean": statistics.mean([row["change_ratio"] for row in line_stats]) if line_stats else None,
            "median": statistics.median([row["change_ratio"] for row in line_stats]) if line_stats else None,
            "p25": percentile([row["change_ratio"] for row in line_stats], 0.25),
            "p75": percentile([row["change_ratio"] for row in line_stats], 0.75),
        },
    }

    def subset(strategy: str | None = None, task: str | None = None) -> list[dict[str, Any]]:
        selected = missing
        if strategy is not None:
            selected = [item for item in selected if item["run"]["strategy"] == strategy]
        if task is not None:
            selected = [item for item in selected if item["run"]["task"] == task]
        return selected

    def subset_summary(selected: list[dict[str, Any]], request_count: int) -> dict[str, Any]:
        counts = profile_counts(selected)
        return {
            "requests": request_count,
            "missing_explanation": len(selected),
            "complete_canonical": sum(
                1
                for item in selected
                if item["profile"] and item["profile"]["structural"]["canonical_complete"]
            ),
            "complete_knr": sum(
                1
                for item in selected
                if item["profile"] and item["profile"]["structural"]["knr_aware_complete"]
            ),
            "substantive_changed": sum(
                1 for item in selected if item["profile"] and item["profile"]["change"]["substantive_changed"]
            ),
            "usable_canonical": counts["usable_canonical"],
            "usable_knr": counts["usable_knr"],
            "no_change": counts["no_change"],
            "whitespace_only": counts["whitespace_only"],
            "knr_false_negative": counts["knr_false_negative"],
            "missing_cost": cost_rollup([item["cost"] for item in selected]),
            "usable_cost_canonical": cost_rollup(
                [item["cost"] for item in selected if item["profile"] and item["profile"]["usable_canonical"]]
            ),
            "usable_cost_knr": cost_rollup(
                [item["cost"] for item in selected if item["profile"] and item["profile"]["usable_knr"]]
            ),
            "usable_rate_canonical": rate(counts["usable_canonical"], len(selected)),
            "usable_rate_knr": rate(counts["usable_knr"], len(selected)),
        }

    by_strategy = {
        strategy: subset_summary(
            subset(strategy=strategy),
            sum(1 for item in items if item["run"]["strategy"] == strategy),
        )
        for strategy in STRATEGIES
    }
    by_task = {
        task: subset_summary(
            subset(task=task),
            sum(1 for item in items if item["run"]["task"] == task),
        )
        for task in TASKS
    }

    by_run = []
    for run in runs:
        selected = [item for item in missing if item["run"] is run]
        summary = subset_summary(selected, len(run["repair_items"]))
        summary.update(
            {
                "run_id": run["run_id"],
                "strategy": run["strategy"],
                "task": run["task"],
            }
        )
        by_run.append(summary)

    cwe_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in missing:
        cwe_groups[primary_cwe(item["source"]["cwe_list"])].append(item)
    by_cwe = []
    for label, group in sorted(cwe_groups.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        counts = profile_counts(group)
        by_cwe.append(
            {
                "cwe": label,
                "n": len(group),
                "share_of_missing": rate(len(group), len(missing)),
                "complete_canonical": sum(
                    1
                    for item in group
                    if item["profile"] and item["profile"]["structural"]["canonical_complete"]
                ),
                "complete_knr": sum(
                    1
                    for item in group
                    if item["profile"] and item["profile"]["structural"]["knr_aware_complete"]
                ),
                "substantive_changed": sum(
                    1 for item in group if item["profile"] and item["profile"]["change"]["substantive_changed"]
                ),
                "usable_canonical": counts["usable_canonical"],
                "usable_knr": counts["usable_knr"],
                "no_change": counts["no_change"],
                "whitespace_only": counts["whitespace_only"],
                "cost": cost_rollup([item["cost"] for item in group]),
            }
        )

    recovery = {
        "format_parse_rate": wilson(len(missing), len(missing)),
        "usable_canonical_rate_of_failure_class": wilson(len(usable_canonical), len(missing)),
        "usable_knr_rate_of_failure_class": wilson(len(usable_knr), len(missing)),
        "usable_canonical_share_of_invalid": rate(len(usable_canonical), len(invalid)),
        "usable_knr_share_of_invalid": rate(len(usable_knr), len(invalid)),
        "usable_canonical_share_of_requests": rate(len(usable_canonical), len(items)),
        "usable_knr_share_of_requests": rate(len(usable_knr), len(items)),
    }

    official_breakdown = profile_counts(valid)

    return {
        "requests": len(items),
        "official_schema_valid": len(valid),
        "official_schema_invalid": len(invalid),
        "official_schema_valid_rate": rate(len(valid), len(items)),
        "invalid_rate": rate(len(invalid), len(items)),
        "invalid_classes": invalid_classes,
        "missing_explanation": {
            "n": len(missing),
            "share_of_requests": rate(len(missing), len(items)),
            "share_of_invalid": rate(len(missing), len(invalid)),
            "finish_reasons": dict(Counter(item["finish_reason"] for item in missing)),
            "key_sets": {
                "|".join(item["keys"] or []): sum(1 for other in missing if other["keys"] == item["keys"])
                for item in missing
            },
            "structural": structural,
            "change": change,
            "line_diff": line_diff_summary,
            "usable_canonical": len(usable_canonical),
            "usable_knr": len(usable_knr),
            "usable_cost_canonical": cost_rollup([item["cost"] for item in usable_canonical]),
            "usable_cost_knr": cost_rollup([item["cost"] for item in usable_knr]),
            "nonusable_count_canonical": len(nonusable),
            "nonusable_classes_canonical": dict(nonusable_classes),
            "recovery": recovery,
            "by_strategy": by_strategy,
            "by_task": by_task,
            "by_run": by_run,
            "by_cwe": by_cwe,
        },
        "truncation": {
            "n": len(truncation),
            "share_of_requests": rate(len(truncation), len(items)),
            "share_of_invalid": rate(len(truncation), len(invalid)),
            "finish_reasons": dict(Counter(item["finish_reason"] for item in truncation)),
            "samples": sorted({item["record"].get("sample_id") for item in truncation}),
            "content_chars": [
                len((item["record"].get("response") or {}).get("content") or "")
                for item in truncation
            ],
            "cost": cost_rollup([item["cost"] for item in truncation]),
            "usable_after_salvage": 0,
        },
        "official_valid": {
            "records": len(valid),
            "usable_canonical": official_breakdown["usable_canonical"],
            "usable_knr": official_breakdown["usable_knr"],
            "no_change": official_breakdown["no_change"],
            "whitespace_only": official_breakdown["whitespace_only"],
            "comment_only": official_breakdown["comment_only"],
            "knr_false_negative": official_breakdown["knr_false_negative"],
            "canonical_incomplete": official_breakdown["canonical_incomplete"],
            "usable_rate_canonical": rate(official_breakdown["usable_canonical"], len(valid)),
            "usable_rate_knr": rate(official_breakdown["usable_knr"], len(valid)),
            "no_change_rate": rate(official_breakdown["no_change"], len(valid)),
            "comment_only_rate": rate(official_breakdown["comment_only"], len(valid)),
            "note": (
                "canonical_incomplete and knr_false_negative refer to the same 4 records; "
                "they are views of the same K&R false negatives, not additive counts."
            ),
        },
    }


def build_official_vs_code(
    runs: list[dict[str, Any]],
    source_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    items = [item for run in runs for item in run["repair_items"]]
    overall = cell_metrics(items)
    by_strategy = {
        strategy: cell_metrics([item for item in items if item["run"]["strategy"] == strategy])
        for strategy in STRATEGIES
    }
    by_task = {
        task: cell_metrics([item for item in items if item["run"]["task"] == task])
        for task in TASKS
    }
    by_run = []
    for run in runs:
        cell = cell_metrics(run["repair_items"])
        cell.update({"run_id": run["run_id"], "strategy": run["strategy"], "task": run["task"]})
        by_run.append(cell)
    return {
        "definition": (
            "official_usable_text/sub/code count schema-valid repairs with canonical "
            "complete_function and text-changed / whitespace-collapsed substantive / "
            "comment-insensitive substantive change respectively. code_* additionally admits "
            "missing-explanation responses that parse with a non-empty fixed_function. "
            "CAC_text = complete+text-changed; CAC_sub = complete+substantive; "
            "CAC_code = complete+comment-insensitive substantive. None is a correctness measure."
        ),
        "overall": overall,
        "by_strategy": by_strategy,
        "by_task": by_task,
        "by_run": by_run,
    }


def build_mimo_detection(runs: list[dict[str, Any]]) -> dict[str, Any]:
    items = [item for run in runs for item in run["detection_items"]]
    invalid = [item for item in items if item["class"] != "ok"]
    drift = [item for item in invalid if item["class"] in {"field_drift", "field_drift_duplicate"}]
    recovered = [item for item in drift if item["recovered"]]
    agreement = [item for item in recovered if item["label_agreement"]]

    key_patterns = Counter(
        "|".join(item["keys"]) if item["keys"] else "<unparseable>" for item in drift
    )
    alias_counts = Counter(item["alias"] for item in drift if item["alias"])
    value_counts = Counter(
        "true" if item["recovered_value"] else "false"
        for item in recovered
        if item["recovered_value"] is not None
    )
    gold_counts = Counter(
        "true" if item["gold_label"] else "false"
        for item in recovered
        if item["gold_label"] is not None
    )

    def subset_summary(selected: list[dict[str, Any]], request_count: int) -> dict[str, Any]:
        recovered_subset = [item for item in selected if item["recovered"]]
        return {
            "detection_requests": request_count,
            "official_schema_invalid": len(selected),
            "field_drift": sum(1 for item in selected if item["class"] in {"field_drift", "field_drift_duplicate"}),
            "recovered": len(recovered_subset),
            "label_agreement": sum(1 for item in recovered_subset if item["label_agreement"]),
            "recovered_true": sum(1 for item in recovered_subset if item["recovered_value"] is True),
            "recovered_false": sum(1 for item in recovered_subset if item["recovered_value"] is False),
            "cost": cost_rollup([item["cost"] for item in selected]),
        }

    by_strategy = {
        strategy: subset_summary(
            [item for item in invalid if item["run"]["strategy"] == strategy],
            sum(1 for item in items if item["run"]["strategy"] == strategy),
        )
        for strategy in STRATEGIES
    }
    by_task = {
        task: subset_summary(
            [item for item in invalid if item["run"]["task"] == task],
            sum(1 for item in items if item["run"]["task"] == task),
        )
        for task in TASKS
    }
    by_run = []
    for run in runs:
        selected = [item for item in invalid if item["run"] is run]
        detection_total = cost_rollup(
            [record["_cost"] for record in run["records"] if record.get("task") == "detection"]
        )
        summary = subset_summary(
            selected,
            len([record for record in run["records"] if record.get("task") == "detection"]),
        )
        summary.update(
            {
                "run_id": run["run_id"],
                "strategy": run["strategy"],
                "task": run["task"],
                "detection_cost": detection_total,
            }
        )
        by_run.append(summary)

    detection_costs = cost_rollup(
        [record["_cost"] for run in runs for record in run["records"] if record.get("task") == "detection"]
    )
    drift_costs = cost_rollup([item["cost"] for item in drift])

    return {
        "requests": len(items),
        "official_schema_valid": len(items) - len(invalid),
        "official_schema_invalid": len(invalid),
        "official_schema_valid_rate": rate(len(items) - len(invalid), len(items)),
        "invalid_rate": rate(len(invalid), len(items)),
        "invalid_classes": dict(Counter(item["class"] for item in invalid)),
        "field_drift": {
            "n": len(drift),
            "share_of_requests": rate(len(drift), len(items)),
            "share_of_invalid": rate(len(drift), len(invalid)),
            "key_patterns": dict(key_patterns),
            "alias_counts": dict(alias_counts),
            "both_keys": sum(1 for item in drift if item["alias"] and "is_vulnerable" in (item["keys"] or ())),
            "parse_ok": sum(1 for item in drift if item["parse_ok"]),
            "recovered": len(recovered),
            "recovery_rate": wilson(len(recovered), len(drift)),
            "recovered_value_counts": dict(value_counts),
            "gold_label_counts": dict(gold_counts),
            "label_agreement_count": len(agreement),
            "label_agreement_share_descriptive": rate(len(agreement), len(recovered)),
            "label_agreement_note": (
                "Descriptive post-hoc agreement with the dataset label; NOT accuracy, "
                "not a benchmark metric, and not used in any headline."
            ),
            "finish_reasons": dict(Counter(item["finish_reason"] for item in drift)),
            "cost": drift_costs,
            "share_of_detection_cost": share(drift_costs["configured_peak_cache_aware_usd"], detection_costs["configured_peak_cache_aware_usd"]),
            "cost_per_recovered": share(drift_costs["configured_peak_cache_aware_usd"], len(recovered)),
            "by_strategy": by_strategy,
            "by_task": by_task,
            "by_run": by_run,
        },
        "detection_cost": detection_costs,
    }


def build_cost_section(
    ds_runs: list[dict[str, Any]],
    mm_runs: list[dict[str, Any]],
    ds_summary: dict[str, Any],
    mm_detection: dict[str, Any],
    ds_official_vs_code: dict[str, Any],
) -> dict[str, Any]:
    ds_costs = [record["_cost"] for run in ds_runs for record in run["records"]]
    mm_costs = [record["_cost"] for run in mm_runs for record in run["records"]]
    ds_repair_costs = [
        record["_cost"] for run in ds_runs for record in run["records"] if record.get("task") == "repair"
    ]
    ds_detection_costs = [
        record["_cost"] for run in ds_runs for record in run["records"] if record.get("task") == "detection"
    ]
    ds_items = [item for run in ds_runs for item in run["repair_items"]]
    ds_invalid = [item for item in ds_items if item["class"] != "ok"]
    ds_missing = [item for item in ds_items if item["class"] == "missing_explanation"]
    ds_trunc = [item for item in ds_invalid if item["class"] in {"truncation", "truncation_unconfirmed"}]
    ds_salvage_c = [item for item in ds_missing if item["profile"] and item["profile"]["usable_canonical"]]
    ds_salvage_k = [item for item in ds_missing if item["profile"] and item["profile"]["usable_knr"]]
    ds_missing_nonusable_c = [
        item for item in ds_missing if not (item["profile"] and item["profile"]["usable_canonical"])
    ]

    ds_all = cost_rollup(ds_costs)
    ds_repair = cost_rollup(ds_repair_costs)
    ds_detection = cost_rollup(ds_detection_costs)
    ds_invalid_cost = cost_rollup([item["cost"] for item in ds_invalid])
    ds_missing_cost = cost_rollup([item["cost"] for item in ds_missing])
    ds_trunc_cost = cost_rollup([item["cost"] for item in ds_trunc])
    ds_salvage_c_cost = cost_rollup([item["cost"] for item in ds_salvage_c])
    ds_salvage_k_cost = cost_rollup([item["cost"] for item in ds_salvage_k])
    ds_nonusable_cost = cost_rollup([item["cost"] for item in ds_missing_nonusable_c])
    mm_all = cost_rollup(mm_costs)
    mm_detection_cost = mm_detection["detection_cost"]
    mm_invalid_items = [
        item
        for run in mm_runs
        for item in run["detection_items"] + run["repair_items"]
        if item["class"] not in {"ok"}
    ]
    mm_invalid_cost = cost_rollup([item["cost"] for item in mm_invalid_items])
    mm_drift_cost = mm_detection["field_drift"]["cost"]
    mm_trunc = [
        item
        for run in mm_runs
        for item in run["repair_items"]
        if item["class"] in {"truncation", "truncation_unconfirmed"}
    ]
    mm_trunc_cost = cost_rollup([item["cost"] for item in mm_trunc])
    combined = cost_rollup(ds_costs + mm_costs)

    overall = ds_official_vs_code["overall"]
    official_usable_sub = overall["official_usable_sub"]
    code_usable_sub = overall["code_usable_sub"]
    official_usable_code = overall["official_usable_code"]
    code_usable_code = overall["code_usable_code"]
    code_usable_code_knr = overall["code_usable_code_knr"]

    def cost_per(total: float | None, count: int) -> float | None:
        if total is None or not count:
            return None
        return total / count

    failure_costs = {
        "deepseek_missing_explanation": {
            "n": len(ds_missing),
            "cost": ds_missing_cost,
            "share_of_deepseek_total": share(ds_missing_cost["configured_peak_cache_aware_usd"], ds_all["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_repair": share(ds_missing_cost["configured_peak_cache_aware_usd"], ds_repair["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_invalid": share(ds_missing_cost["configured_peak_cache_aware_usd"], ds_invalid_cost["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_total_offpeak": share(ds_missing_cost["offpeak_list_normalized"]["total_usd"], ds_all["offpeak_list_normalized"]["total_usd"]),
            "share_of_deepseek_repair_offpeak": share(ds_missing_cost["offpeak_list_normalized"]["total_usd"], ds_repair["offpeak_list_normalized"]["total_usd"]),
            "share_of_deepseek_invalid_offpeak": share(ds_missing_cost["offpeak_list_normalized"]["total_usd"], ds_invalid_cost["offpeak_list_normalized"]["total_usd"]),
        },
        "deepseek_truncation": {
            "n": len(ds_trunc),
            "cost": ds_trunc_cost,
            "share_of_deepseek_total": share(ds_trunc_cost["configured_peak_cache_aware_usd"], ds_all["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_repair": share(ds_trunc_cost["configured_peak_cache_aware_usd"], ds_repair["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_invalid": share(ds_trunc_cost["configured_peak_cache_aware_usd"], ds_invalid_cost["configured_peak_cache_aware_usd"]),
            "share_of_deepseek_total_offpeak": share(ds_trunc_cost["offpeak_list_normalized"]["total_usd"], ds_all["offpeak_list_normalized"]["total_usd"]),
            "share_of_deepseek_repair_offpeak": share(ds_trunc_cost["offpeak_list_normalized"]["total_usd"], ds_repair["offpeak_list_normalized"]["total_usd"]),
            "share_of_deepseek_invalid_offpeak": share(ds_trunc_cost["offpeak_list_normalized"]["total_usd"], ds_invalid_cost["offpeak_list_normalized"]["total_usd"]),
        },
        "mimo_field_drift": {
            "n": mm_detection["field_drift"]["n"],
            "cost": mm_drift_cost,
            "share_of_mimo_total": share(mm_drift_cost["configured_peak_cache_aware_usd"], mm_all["configured_peak_cache_aware_usd"]),
            "share_of_mimo_detection": share(mm_drift_cost["configured_peak_cache_aware_usd"], mm_detection_cost["configured_peak_cache_aware_usd"]),
            "share_of_mimo_invalid": share(mm_drift_cost["configured_peak_cache_aware_usd"], mm_invalid_cost["configured_peak_cache_aware_usd"]),
            "share_of_mimo_total_offpeak": share(mm_drift_cost["offpeak_list_normalized"]["total_usd"], mm_all["offpeak_list_normalized"]["total_usd"]),
            "share_of_mimo_detection_offpeak": share(mm_drift_cost["offpeak_list_normalized"]["total_usd"], mm_detection_cost["offpeak_list_normalized"]["total_usd"]),
            "share_of_mimo_invalid_offpeak": share(mm_drift_cost["offpeak_list_normalized"]["total_usd"], mm_invalid_cost["offpeak_list_normalized"]["total_usd"]),
        },
        "mimo_truncation": {
            "n": len(mm_trunc),
            "cost": mm_trunc_cost,
            "share_of_mimo_total": share(mm_trunc_cost["configured_peak_cache_aware_usd"], mm_all["configured_peak_cache_aware_usd"]),
            "share_of_mimo_invalid": share(mm_trunc_cost["configured_peak_cache_aware_usd"], mm_invalid_cost["configured_peak_cache_aware_usd"]),
            "share_of_mimo_total_offpeak": share(mm_trunc_cost["offpeak_list_normalized"]["total_usd"], mm_all["offpeak_list_normalized"]["total_usd"]),
            "share_of_mimo_invalid_offpeak": share(mm_trunc_cost["offpeak_list_normalized"]["total_usd"], mm_invalid_cost["offpeak_list_normalized"]["total_usd"]),
        },
    }

    sunk = {
        "configured_peak": {
            "invalid_total_usd": ds_invalid_cost["configured_peak_cache_aware_usd"],
            "recoverable_to_usable_canonical_usd": ds_salvage_c_cost["configured_peak_cache_aware_usd"],
            "recoverable_to_usable_knr_usd": ds_salvage_k_cost["configured_peak_cache_aware_usd"],
            "nonusable_missing_canonical_usd": ds_nonusable_cost["configured_peak_cache_aware_usd"],
            "fatal_truncation_usd": ds_trunc_cost["configured_peak_cache_aware_usd"],
            "recoverable_share_canonical": share(ds_salvage_c_cost["configured_peak_cache_aware_usd"], ds_invalid_cost["configured_peak_cache_aware_usd"]),
            "recoverable_share_knr": share(ds_salvage_k_cost["configured_peak_cache_aware_usd"], ds_invalid_cost["configured_peak_cache_aware_usd"]),
            "unrecoverable_share_canonical": share(
                (ds_nonusable_cost["configured_peak_cache_aware_usd"] or 0.0) + (ds_trunc_cost["configured_peak_cache_aware_usd"] or 0.0),
                ds_invalid_cost["configured_peak_cache_aware_usd"],
            ),
        },
        "offpeak_list_normalized": {
            "invalid_total_usd": ds_invalid_cost["offpeak_list_normalized"]["total_usd"],
            "recoverable_to_usable_canonical_usd": ds_salvage_c_cost["offpeak_list_normalized"]["total_usd"],
            "recoverable_to_usable_knr_usd": ds_salvage_k_cost["offpeak_list_normalized"]["total_usd"],
            "nonusable_missing_canonical_usd": ds_nonusable_cost["offpeak_list_normalized"]["total_usd"],
            "fatal_truncation_usd": ds_trunc_cost["offpeak_list_normalized"]["total_usd"],
            "recoverable_share_canonical": share(ds_salvage_c_cost["offpeak_list_normalized"]["total_usd"], ds_invalid_cost["offpeak_list_normalized"]["total_usd"]),
            "recoverable_share_knr": share(ds_salvage_k_cost["offpeak_list_normalized"]["total_usd"], ds_invalid_cost["offpeak_list_normalized"]["total_usd"]),
            "unrecoverable_share_canonical": share(
                (ds_nonusable_cost["offpeak_list_normalized"]["total_usd"] or 0.0) + (ds_trunc_cost["offpeak_list_normalized"]["total_usd"] or 0.0),
                ds_invalid_cost["offpeak_list_normalized"]["total_usd"],
            ),
        },
        "marginal_api_cost_usd": 0.0,
        "note": (
            "The salvage candidates were already generated and paid for. The marginal API cost "
            "of reclassifying them is zero; the amounts above are sunk accounting allocations, "
            "not new spend. The two blocks differ only in the price card, not in record counts."
        ),
    }

    cost_per_usable = {
        "configured_peak": {
            "official_code_canonical": cost_per(ds_repair["configured_peak_cache_aware_usd"], official_usable_code),
            "code_code_canonical": cost_per(ds_repair["configured_peak_cache_aware_usd"], code_usable_code),
            "code_code_knr": cost_per(ds_repair["configured_peak_cache_aware_usd"], code_usable_code_knr),
            "official_sub_canonical_sensitivity": cost_per(ds_repair["configured_peak_cache_aware_usd"], official_usable_sub),
            "code_sub_canonical_sensitivity": cost_per(ds_repair["configured_peak_cache_aware_usd"], code_usable_sub),
            "salvage_canonical": cost_per(ds_salvage_c_cost["configured_peak_cache_aware_usd"], len(ds_salvage_c)),
            "salvage_knr": cost_per(ds_salvage_k_cost["configured_peak_cache_aware_usd"], len(ds_salvage_k)),
            "truncation_per_record": cost_per(ds_trunc_cost["configured_peak_cache_aware_usd"], len(ds_trunc)),
            "mimo_field_drift_per_recovered": cost_per(
                mm_drift_cost["configured_peak_cache_aware_usd"], mm_detection["field_drift"]["recovered"]
            ),
        },
        "offpeak_list_normalized": {
            "official_code_canonical": cost_per(ds_repair["offpeak_list_normalized"]["total_usd"], official_usable_code),
            "code_code_canonical": cost_per(ds_repair["offpeak_list_normalized"]["total_usd"], code_usable_code),
            "code_code_knr": cost_per(ds_repair["offpeak_list_normalized"]["total_usd"], code_usable_code_knr),
            "official_sub_canonical_sensitivity": cost_per(ds_repair["offpeak_list_normalized"]["total_usd"], official_usable_sub),
            "code_sub_canonical_sensitivity": cost_per(ds_repair["offpeak_list_normalized"]["total_usd"], code_usable_sub),
            "salvage_canonical": cost_per(ds_salvage_c_cost["offpeak_list_normalized"]["total_usd"], len(ds_salvage_c)),
            "salvage_knr": cost_per(ds_salvage_k_cost["offpeak_list_normalized"]["total_usd"], len(ds_salvage_k)),
            "truncation_per_record": cost_per(ds_trunc_cost["offpeak_list_normalized"]["total_usd"], len(ds_trunc)),
            "mimo_field_drift_per_recovered": cost_per(
                mm_drift_cost["offpeak_list_normalized"]["total_usd"], mm_detection["field_drift"]["recovered"]
            ),
        },
        "note": (
            "Average accounting cost per structurally usable output, not cost per correct fix. "
            "The primary view is complete + comment-insensitive substantive change; the *_sub_* "
            "entries are the looser whitespace-collapse sensitivity. The numerator is the full "
            "paid cost of the relevant request set. Price cards are shown separately: "
            "configured peak vs project-wide off-peak list."
        ),
    }

    def reported_delta(summary: dict[str, Any]) -> dict[str, Any]:
        reported = summary["reported_usd"]
        configured = summary["configured_peak_cache_aware_usd"]
        offpeak = summary["offpeak_list_normalized_usd"]
        return {
            "reported_usd": reported,
            "configured_peak_cache_aware_usd": configured,
            "offpeak_list_normalized_usd": offpeak,
            "delta_vs_configured_peak_usd": (reported or 0.0) - (configured or 0.0),
            "delta_vs_configured_peak_share": share(
                (reported or 0.0) - (configured or 0.0), configured
            ),
            "delta_vs_offpeak_list_usd": (reported or 0.0) - (offpeak or 0.0),
            "reported_known_records": summary["reported_known_records"],
            "records": summary["records"],
        }

    by_run = []
    for run in ds_runs:
        repair_costs = [record["_cost"] for record in run["records"] if record.get("task") == "repair"]
        invalid = [item for item in run["repair_items"] if item["class"] != "ok"]
        missing = [item for item in run["repair_items"] if item["class"] == "missing_explanation"]
        trunc = [item for item in invalid if item["class"] in {"truncation", "truncation_unconfirmed"}]
        salvage = [item for item in missing if item["profile"] and item["profile"]["usable_canonical"]]
        by_run.append(
            {
                "run_id": run["run_id"],
                "strategy": run["strategy"],
                "task": run["task"],
                "requests": len(repair_costs),
                "repair_cost": cost_rollup(repair_costs),
                "invalid_cost": cost_rollup([item["cost"] for item in invalid]),
                "missing_cost": cost_rollup([item["cost"] for item in missing]),
                "truncation_cost": cost_rollup([item["cost"] for item in trunc]),
                "usable_salvage": len(salvage),
                "usable_salvage_cost": cost_rollup([item["cost"] for item in salvage]),
            }
        )

    mm_by_run = []
    for run in mm_runs:
        detection_costs = [record["_cost"] for record in run["records"] if record.get("task") == "detection"]
        drift = [
            item
            for item in run["detection_items"]
            if item["class"] in {"field_drift", "field_drift_duplicate"}
        ]
        trunc = [
            item
            for item in run["repair_items"]
            if item["class"] in {"truncation", "truncation_unconfirmed"}
        ]
        mm_by_run.append(
            {
                "run_id": run["run_id"],
                "strategy": run["strategy"],
                "task": run["task"],
                "detection_requests": len(detection_costs),
                "detection_cost": cost_rollup(detection_costs),
                "drift_cost": cost_rollup([item["cost"] for item in drift]),
                "repair_truncation_cost": cost_rollup([item["cost"] for item in trunc]),
            }
        )

    return {
        "price_basis": {
            "reported": "response.cost.cost_usd as recorded; DeepSeek legacy records do not deduct cached tokens",
            "configured_peak_cache_aware": (
                "cache-aware recompute at each run's configured card: DeepSeek observed peak "
                "0.30/1.20/0.006; MiMo flat 0.14/0.28/0.0028"
            ),
            "offpeak_list_normalized": (
                "cache-aware recompute at the project-wide off-peak list card: DeepSeek "
                "0.15/0.60/0.003; MiMo flat 0.14/0.28/0.0028"
            ),
            "project_wide_reference": (
                "analysis/cost_normalization.md; its legacy_test group covers the same 12 test_v1 "
                "runs and reports configured_cache_aware_usd=2.521790096 and "
                "normalized_list_usd=1.572472286"
            ),
            "warning": (
                "The $2.521790096 combined total is configured-peak cache-aware for these 12 runs. "
                "It is NOT the project-wide off-peak normalized total; the comparable off-peak "
                "figure is $1.572472286. Do not mix the two bases."
            ),
        },
        "deepseek": {
            "all": ds_all,
            "detection": ds_detection,
            "repair": ds_repair,
            "invalid": ds_invalid_cost,
            "missing_explanation": ds_missing_cost,
            "truncation": ds_trunc_cost,
            "usable_salvage_canonical": ds_salvage_c_cost,
            "usable_salvage_knr": ds_salvage_k_cost,
            "missing_nonusable_canonical": ds_nonusable_cost,
            "by_run": by_run,
        },
        "mimo": {
            "all": mm_all,
            "detection": mm_detection_cost,
            "repair": cost_rollup(
                [record["_cost"] for run in mm_runs for record in run["records"] if record.get("task") == "repair"]
            ),
            "invalid": mm_invalid_cost,
            "field_drift": mm_drift_cost,
            "truncation": mm_trunc_cost,
            "by_run": mm_by_run,
        },
        "combined": {
            "all": combined,
            "invalid": cost_rollup(
                [item["cost"] for item in ds_invalid] + [item["cost"] for item in mm_invalid_items]
            ),
            "invalid_share_configured_peak": share(
                (ds_invalid_cost["configured_peak_cache_aware_usd"] or 0.0) + (mm_invalid_cost["configured_peak_cache_aware_usd"] or 0.0),
                combined["configured_peak_cache_aware_usd"],
            ),
            "invalid_share_offpeak_list_normalized": share(
                (ds_invalid_cost["offpeak_list_normalized"]["total_usd"] or 0.0) + (mm_invalid_cost["offpeak_list_normalized"]["total_usd"] or 0.0),
                combined["offpeak_list_normalized"]["total_usd"],
            ),
            "note": (
                "combined.all.configured_peak_cache_aware_usd is 2.521790096 for these 12 runs; "
                "combined.all.offpeak_list_normalized.total_usd is 1.572472286 and is the figure "
                "comparable with analysis/cost_normalization.md's legacy_test normalized_list_usd. "
                "The two totals use different price cards and must not be presented as one "
                "'project-wide normalized' number."
            ),
        },
        "failure_costs": failure_costs,
        "sunk_cost_reclassification": sunk,
        "cost_per_usable": cost_per_usable,
        "reported_vs_configured_peak": {
            "deepseek_missing_explanation": reported_delta(ds_missing_cost),
            "deepseek_truncation": reported_delta(ds_trunc_cost),
            "mimo_field_drift": reported_delta(mm_drift_cost),
        },
    }
# ---------------------------------------------------------------------------
# model-comparison sensitivity (post-hoc, descriptive)
# ---------------------------------------------------------------------------


def build_cac_cells(runs: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    cells: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for run in runs:
        for item in run["repair_items"]:
            record = item["record"]
            key = (
                str(record.get("sample_id"))
                if run["task"] == "independent"
                else str(record.get("pair_id"))
            )
            profile = item["profile"]
            cells[(run["strategy"], run["task"])][key] = {
                "class": item["class"],
                "status": record.get("status"),
                "complete": bool(profile and profile["structural"]["canonical_complete"]),
                "text": bool(profile and profile["change"]["text_changed"]),
                "sub": bool(profile and profile["change"]["substantive_changed"]),
                "code": bool(profile and profile["change"]["comment_insensitive_changed"]),
                "cluster": item["source"]["project"] if run["task"] == "independent" else str(record.get("pair_id")),
                "missing": item["class"] == "missing_explanation",
            }
    return cells


def cac_success(unit: dict[str, Any], definition: str, mode: str, model: str) -> int:
    eligible = unit["status"] == "ok"
    if model == "deepseek" and mode == "code" and unit["class"] == "missing_explanation":
        eligible = True
    return int(bool(eligible and unit["complete"] and unit[definition]))


def bootstrap_cac_rows(
    ds_cells: dict[tuple[str, str], dict[str, dict[str, Any]]],
    mm_cells: dict[tuple[str, str], dict[str, dict[str, Any]]],
    reps: int,
    seed: int,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    labels = (
        ("official_text", "text", "official"),
        ("code_text", "text", "code"),
        ("official_code", "code", "official"),
        ("code_code", "code", "code"),
    )
    for strategy, task in RUNS:
        ds = ds_cells[(strategy, task)]
        mm = mm_cells[(strategy, task)]
        keys = sorted(ds)
        if set(keys) != set(mm):
            raise SystemExit(f"CAC cell {strategy}/{task}: model units do not match")
        cluster_map: dict[str, list[str]] = defaultdict(list)
        for key in keys:
            cluster_map[ds[key]["cluster"]].append(key)
        cluster_names = sorted(cluster_map)
        index = {key: i for i, key in enumerate(keys)}
        cluster_indices = [[index[key] for key in cluster_map[name]] for name in cluster_names]
        n = len(keys)
        ds_missing = sum(1 for unit in ds.values() if unit["missing"])

        for label, definition, mode in labels:
            ds_values = [cac_success(ds[key], definition, mode, "deepseek") for key in keys]
            mm_values = [cac_success(mm[key], definition, mode, "mimo") for key in keys]
            ds_rate = sum(ds_values) / n if n else None
            mm_rate = sum(mm_values) / n if n else None
            diff = (ds_rate - mm_rate) * 100.0 if ds_rate is not None and mm_rate is not None else None

            ci_low = ci_high = None
            if reps > 0:
                cluster_ds = [sum(ds_values[i] for i in indices) for indices in cluster_indices]
                cluster_mm = [sum(mm_values[i] for i in indices) for indices in cluster_indices]
                cluster_n = [len(indices) for indices in cluster_indices]
                boot: list[float] = []
                for _ in range(reps):
                    total_ds = total_mm = total_n = 0
                    for _ in range(len(cluster_names)):
                        pick = rng.randrange(len(cluster_names))
                        total_ds += cluster_ds[pick]
                        total_mm += cluster_mm[pick]
                        total_n += cluster_n[pick]
                    boot.append((total_ds / total_n - total_mm / total_n) * 100.0)
                boot.sort()
                ci_low = boot[int(0.025 * reps)]
                ci_high = boot[int(0.975 * reps) - 1]

            rows.append(
                {
                    "strategy": strategy,
                    "task": task,
                    "view": label,
                    "definition": "complete + text-changed"
                    if definition == "text"
                    else "complete + comment-insensitive substantive change",
                    "mode": mode,
                    "n": n,
                    "clusters": len(cluster_names),
                    "deepseek_rate": ds_rate,
                    "mimo_rate": mm_rate,
                    "diff_pp": diff,
                    "ci_low_pp": ci_low,
                    "ci_high_pp": ci_high,
                    "excludes_zero": bool(ci_low is not None and (ci_low > 0 or ci_high < 0)),
                    "salvage_applicable": ds_missing > 0,
                }
            )
    return rows


def build_cross_model(
    ds_runs: list[dict[str, Any]],
    mm_runs: list[dict[str, Any]],
    ds_summary: dict[str, Any],
    mm_detection: dict[str, Any],
    ds_official_vs_code: dict[str, Any],
    reps: int,
    seed: int,
) -> dict[str, Any]:
    ds_cells = build_cac_cells(ds_runs)
    mm_cells = build_cac_cells(mm_runs)
    cac_rows = bootstrap_cac_rows(ds_cells, mm_cells, reps, seed)

    no_change_rates = []
    for model, runs in (("deepseek", ds_runs), ("mimo", mm_runs)):
        for strategy in STRATEGIES:
            valid = [
                item
                for run in runs
                if run["strategy"] == strategy
                for item in run["repair_items"]
                if item["class"] == "ok"
            ]
            no_change = sum(
                1 for item in valid if item["profile"] and item["profile"]["change"]["no_change"]
            )
            whitespace = sum(
                1 for item in valid if item["profile"] and item["profile"]["change"]["whitespace_only"]
            )
            no_change_rates.append(
                {
                    "model": model,
                    "strategy": strategy,
                    "official_valid": len(valid),
                    "no_change": no_change,
                    "no_change_rate": rate(no_change, len(valid)),
                    "whitespace_only": whitespace,
                    "whitespace_only_rate": rate(whitespace, len(valid)),
                }
            )

    schema_gap = []
    for strategy, task in RUNS:
        ds_cell = cell_metrics(
            [item for run in ds_runs if (run["strategy"], run["task"]) == (strategy, task) for item in run["repair_items"]]
        )
        mm_cell = cell_metrics(
            [item for run in mm_runs if (run["strategy"], run["task"]) == (strategy, task) for item in run["repair_items"]]
        )
        schema_gap.append(
            {
                "strategy": strategy,
                "task": task,
                "deepseek_schema_valid": ds_cell["official_schema_valid"],
                "deepseek_requests": ds_cell["requests"],
                "deepseek_schema_rate": ds_cell["official_schema_valid_rate"],
                "mimo_schema_valid": mm_cell["official_schema_valid"],
                "mimo_requests": mm_cell["requests"],
                "mimo_schema_rate": mm_cell["official_schema_valid_rate"],
                "diff_pp": (ds_cell["official_schema_valid_rate"] - mm_cell["official_schema_valid_rate"]) * 100.0,
            }
        )

    ds_missing = ds_summary["missing_explanation"]
    mm_drift = mm_detection["field_drift"]
    mm_invalid_total = sum(
        item["cost"]["configured_peak_cache_aware_usd"] or 0.0
        for run in mm_runs
        for item in run["detection_items"] + run["repair_items"]
        if item["class"] != "ok"
    )
    ds_invalid_cost = sum(
        value["cost"]["configured_peak_cache_aware_usd"] or 0.0
        for value in ds_summary["invalid_classes"].values()
    )
    mm_invalid_offpeak = sum(
        item["cost"]["offpeak_list_normalized_usd"] or 0.0
        for run in mm_runs
        for item in run["detection_items"] + run["repair_items"]
        if item["class"] != "ok"
    )
    ds_invalid_offpeak = sum(
        value["cost"]["offpeak_list_normalized"]["total_usd"] or 0.0
        for value in ds_summary["invalid_classes"].values()
    )
    symmetry = [
        {
            "dimension": "failure count",
            "deepseek_repair_missing_explanation": ds_missing["n"],
            "mimo_detection_field_drift": mm_drift["n"],
        },
        {
            "dimension": "denominator",
            "deepseek_repair_missing_explanation": ds_summary["requests"],
            "mimo_detection_field_drift": mm_detection["requests"],
        },
        {
            "dimension": "failure rate",
            "deepseek_repair_missing_explanation": ds_missing["share_of_requests"],
            "mimo_detection_field_drift": mm_drift["share_of_requests"],
        },
        {
            "dimension": "direct / few-shot / context",
            "deepseek_repair_missing_explanation": [
                ds_summary["missing_explanation"]["by_strategy"][strategy]["missing_explanation"]
                for strategy in STRATEGIES
            ],
            "mimo_detection_field_drift": [
                mm_drift["by_strategy"][strategy]["field_drift"] for strategy in STRATEGIES
            ],
        },
        {
            "dimension": "independent / pairs",
            "deepseek_repair_missing_explanation": [
                ds_summary["missing_explanation"]["by_task"][task]["missing_explanation"] for task in TASKS
            ],
            "mimo_detection_field_drift": [
                mm_drift["by_task"][task]["field_drift"] for task in TASKS
            ],
        },
        {
            "dimension": "JSON parse",
            "deepseek_repair_missing_explanation": ds_missing["structural"]["json_parseable"],
            "mimo_detection_field_drift": mm_drift["parse_ok"],
        },
        {
            "dimension": "payload recoverable",
            "deepseek_repair_missing_explanation": ds_missing["structural"]["fixed_function_present"],
            "mimo_detection_field_drift": mm_drift["recovered"],
        },
        {
            "dimension": "structure / usable",
            "deepseek_repair_missing_explanation": {
                "canonical_complete": ds_missing["structural"]["canonical_complete"],
                "knr_aware_complete": ds_missing["structural"]["knr_aware_complete"],
                "usable_canonical": ds_missing["usable_canonical"],
                "usable_knr": ds_missing["usable_knr"],
            },
            "mimo_detection_field_drift": {
                "payload_valid": mm_drift["recovered"],
                "label_agreement_count": mm_drift["label_agreement_count"],
            },
        },
        {
            "dimension": "downstream check",
            "deepseek_repair_missing_explanation": "none; compile/test/PoC not run",
            "mimo_detection_field_drift": "descriptive label agreement only; not accuracy",
        },
        {
            "dimension": "failure-class cost (configured peak)",
            "deepseek_repair_missing_explanation": ds_summary["invalid_classes"]["missing_explanation"]["cost"]["configured_peak_cache_aware_usd"],
            "mimo_detection_field_drift": mm_drift["cost"]["configured_peak_cache_aware_usd"],
        },
        {
            "dimension": "failure-class cost (off-peak list)",
            "deepseek_repair_missing_explanation": ds_summary["invalid_classes"]["missing_explanation"]["cost"]["offpeak_list_normalized"]["total_usd"],
            "mimo_detection_field_drift": mm_drift["cost"]["offpeak_list_normalized"]["total_usd"],
        },
        {
            "dimension": "lenient-admitted cost (configured peak)",
            "deepseek_repair_missing_explanation": ds_missing["usable_cost_canonical"]["configured_peak_cache_aware_usd"],
            "mimo_detection_field_drift": mm_drift["cost"]["configured_peak_cache_aware_usd"],
        },
        {
            "dimension": "lenient-admitted cost (off-peak list)",
            "deepseek_repair_missing_explanation": ds_missing["usable_cost_canonical"]["offpeak_list_normalized"]["total_usd"],
            "mimo_detection_field_drift": mm_drift["cost"]["offpeak_list_normalized"]["total_usd"],
        },
        {
            "dimension": "share of invalid cost (configured peak)",
            "deepseek_repair_missing_explanation": share(
                ds_summary["invalid_classes"]["missing_explanation"]["cost"]["configured_peak_cache_aware_usd"],
                ds_invalid_cost,
            ),
            "mimo_detection_field_drift": share(
                mm_drift["cost"]["configured_peak_cache_aware_usd"], mm_invalid_total
            ),
        },
        {
            "dimension": "share of invalid cost (off-peak list)",
            "deepseek_repair_missing_explanation": share(
                ds_summary["invalid_classes"]["missing_explanation"]["cost"]["offpeak_list_normalized"]["total_usd"],
                ds_invalid_offpeak,
            ),
            "mimo_detection_field_drift": share(
                mm_drift["cost"]["offpeak_list_normalized"]["total_usd"], mm_invalid_offpeak
            ),
        },
    ]

    return {
        "note": (
            "Post-hoc sensitivity only. CIs resample project clusters for independent repair "
            "and pair clusters for pair repair, 10,000 draws, seed 42. No new primary endpoint, "
            "no p-values, no winner claim."
        ),
        "bootstrap_reps": reps,
        "seed": seed,
        "schema_gap": schema_gap,
        "cac_sensitivity": cac_rows,
        "no_change_rates": no_change_rates,
        "symmetry": symmetry,
        "few_shot_note": (
            "Few-shot has zero missing-explanation and zero field-drift failures on both models, "
            "so its CAC difference is not a schema artefact. DeepSeek's few-shot CAC is higher, "
            "but CAC is a structural proxy, not correctness; MiMo also copies the input more often."
        ),
    }
# ---------------------------------------------------------------------------
# result assembly
# ---------------------------------------------------------------------------


def load_cost_normalization(project_root: Path) -> dict[str, Any]:
    path = project_root / "analysis" / "cost_normalization.json"
    if not path.exists():
        return {
            "available": False,
            "path": "analysis/cost_normalization.json",
            "sha256": None,
            "legacy_test": None,
            "note": "reference file not found; off-peak values are still computed from the local card",
        }
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    legacy = ((data.get("aggregates") or {}).get("legacy_test") or {})
    return {
        "available": True,
        "path": path.relative_to(project_root).as_posix(),
        "sha256": sha256_bytes(raw),
        "rate_card": {
            "deepseek": ((data.get("rate_card") or {}).get("deepseek") or {}),
            "mimo": ((data.get("rate_card") or {}).get("mimo") or {}),
        },
        "legacy_test": {
            "runs": legacy.get("runs"),
            "records": legacy.get("records"),
            "configured_cache_aware_usd": legacy.get("configured_cache_aware_usd"),
            "normalized_list_usd": legacy.get("normalized_list_usd"),
            "provider_list_usd": legacy.get("provider_list_usd"),
        },
        "note": (
            "analysis/cost_normalization.md's legacy_test group is the same 12 test_v1 runs. "
            "Its configured_cache_aware_usd and normalized_list_usd are compared below."
        ),
    }


def build_external_cost_basis(cost: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    combined = cost["combined"]["all"]
    configured = combined["configured_peak_cache_aware_usd"]
    offpeak = combined["offpeak_list_normalized"]["total_usd"]
    legacy = reference.get("legacy_test") or {}
    expected_configured = legacy.get("configured_cache_aware_usd")
    expected_offpeak = legacy.get("normalized_list_usd")

    def compare(actual: float | None, expected: float | None) -> dict[str, Any]:
        if actual is None or expected is None:
            return {
                "recomputed_usd": actual,
                "reference_usd": expected,
                "delta_usd": None,
                "match": None,
            }
        delta = actual - expected
        return {
            "recomputed_usd": actual,
            "reference_usd": expected,
            "delta_usd": delta,
            "match": abs(delta) <= 1e-6,
        }

    return {
        **reference,
        "comparison": {
            "configured_peak_cache_aware": compare(configured, expected_configured),
            "offpeak_list_normalized": compare(offpeak, expected_offpeak),
        },
        "note": (
            "The configured-peak comparison checks that our cache-aware configured-card total "
            "equals analysis/cost_normalization.md's configured_cache_aware_usd. The off-peak "
            "comparison checks that our off-peak list total equals its normalized_list_usd. "
            "These are two different price bases; neither is a single project-wide 'normalized' "
            "number for all runs."
        ),
    }


def build_result(
    project_root: Path,
    bootstrap_reps: int,
    seed: int,
    allow_source_drift: bool,
    allow_crosscheck_drift: bool,
) -> dict[str, Any]:
    datasets = load_datasets(project_root)
    source_index = build_source_index(datasets)

    ds_runs, ds_problems = load_runs(project_root, "deepseek", datasets, allow_source_drift)
    mm_runs, mm_problems = load_runs(project_root, "mimo", datasets, allow_source_drift)
    analyze_runs(ds_runs, source_index, "deepseek")
    analyze_runs(mm_runs, source_index, "mimo")

    crosschecks: list[dict[str, Any]] = []
    for run in ds_runs + mm_runs:
        crosschecks.extend(crosscheck_run(run, source_index))
    mismatches = [check for check in crosschecks if not check["match"]]
    if mismatches and not allow_crosscheck_drift:
        lines = [
            f"{item['run_id']} {item['field']}: metrics={item['metrics']} recount={item['recount']}"
            for item in mismatches
        ]
        raise SystemExit(
            "run metrics cross-check failed:\n  " + "\n  ".join(lines) +
            "\nrerun with --allow-crosscheck-drift only if this is intentional"
        )

    ds_summary = build_deepseek_summary(ds_runs, source_index)
    ds_official_vs_code = build_official_vs_code(ds_runs, source_index)
    mm_detection = build_mimo_detection(mm_runs)
    cost = build_cost_section(ds_runs, mm_runs, ds_summary, mm_detection, ds_official_vs_code)
    cost_reference = load_cost_normalization(project_root)
    cost["external_basis"] = build_external_cost_basis(cost, cost_reference)
    cross_model = build_cross_model(
        ds_runs, mm_runs, ds_summary, mm_detection, ds_official_vs_code, bootstrap_reps, seed
    )

    declared_hashes: dict[str, Any] = {}
    for run in ds_runs + mm_runs:
        declared_hashes.setdefault(run["task"], run["config"].get("dataset_sha256"))

    dataset_sources = {}
    for task, data in datasets.items():
        dataset_sources[task] = {
            "path": data["path"].relative_to(project_root).as_posix(),
            "sha256": data["sha256"],
            "declared_sha256": declared_hashes.get(task),
            "match": data["sha256"] == declared_hashes.get(task),
        }

    run_sources = []
    for run in ds_runs + mm_runs:
        directory = run["directory"]
        run_sources.append(
            {
                "run_id": run["run_id"],
                "model": run["model"],
                "strategy": run["strategy"],
                "run_task": run["task"],
                "results_sha256": sha256_file(directory / "results.jsonl"),
                "config_sha256": sha256_file(directory / "config.json"),
                "metrics_sha256": sha256_file(directory / "metrics.json"),
                "records": len(run["records"]),
                "repair_records": sum(1 for record in run["records"] if record.get("task") == "repair"),
                "detection_records": sum(1 for record in run["records"] if record.get("task") == "detection"),
                "expected_requests": run["config"].get("expected_requests"),
                "dataset_sha256": run["config"].get("dataset_sha256"),
                "dataset_match": run["config"].get("dataset_sha256") == datasets[run["task"]]["sha256"],
            }
        )

    validator_path = RUNNER_ROOT / "secvul_runner" / "validation.py"
    sources = {
        "datasets": dataset_sources,
        "runs": run_sources,
        "validator": {
            "path": validator_path.relative_to(project_root).as_posix(),
            "sha256": sha256_file(validator_path),
        },
        "cost_normalization": {
            "path": cost_reference["path"],
            "sha256": cost_reference["sha256"],
            "available": cost_reference["available"],
            "legacy_test": cost_reference.get("legacy_test"),
        },
        "source_problems": ds_problems + mm_problems,
        "crosschecks": {
            "checks": len(crosschecks),
            "mismatches": mismatches,
        },
        "record_counts": {
            "deepseek_repair_requests": ds_summary["requests"],
            "deepseek_repair_invalid": ds_summary["official_schema_invalid"],
            "deepseek_missing_explanation": ds_summary["missing_explanation"]["n"],
            "deepseek_truncation": ds_summary["truncation"]["n"],
            "mimo_detection_requests": mm_detection["requests"],
            "mimo_detection_invalid": mm_detection["official_schema_invalid"],
            "mimo_field_drift": mm_detection["field_drift"]["n"],
            "mimo_repair_truncation": sum(
                1
                for run in mm_runs
                for item in run["repair_items"]
                if item["class"] in {"truncation", "truncation_unconfirmed"}
            ),
        },
        "bootstrap": {"reps": bootstrap_reps, "seed": seed},
        "api_calls": 0,
        "note": (
            "All inputs are frozen run artefacts. No model, network, or API call is made by "
            "this script; the recorded costs are accounting reconstructions, not new charges."
        ),
    }

    result = {
        "schema_version": SCHEMA_VERSION,
        "analysis_date": ANALYSIS_DATE,
        "scope": {
            "question": (
                "What is recoverable from the schema-invalid DeepSeek repair outputs, and how "
                "does that compare with MiMo's detection field drift, without calling any model?"
            ),
            "api_calls": 0,
            "models": {
                "deepseek": "deepseek-v4.1-flash",
                "mimo": "mimo-v2.6-flash",
            },
            "runs": [run["run_id"] for run in ds_runs + mm_runs],
            "denominators": {
                "deepseek_repair_requests": ds_summary["requests"],
                "deepseek_detection_requests": sum(
                    1 for run in ds_runs for record in run["records"] if record.get("task") == "detection"
                ),
                "mimo_repair_requests": sum(
                    1 for run in mm_runs for record in run["records"] if record.get("task") == "repair"
                ),
                "mimo_detection_requests": sum(
                    1 for run in mm_runs for record in run["records"] if record.get("task") == "detection"
                ),
            },
            "split": "secvul-split-v1 test (160 independent functions; 180 pairs)",
        },
        "definitions": {
            "official_schema_valid": (
                "The run's strict parser verdict: record.status == 'ok'. For repair this requires "
                "exactly {'fixed_function','explanation'} with valid types; for detection exactly "
                "{'is_vulnerable','confidence','rationale'}."
            ),
            "code_only_salvage": (
                "A declared lenient view for repair only: the response is valid JSON with a "
                "non-empty fixed_function and no other error, but misses explanation. It admits "
                "the payload; it does not re-run the model and does not make the output correct."
            ),
            "structural_complete_canonical": (
                "runner.secvul_runner.validation.analyze_repair: no fence/diff, balanced "
                "delimiters, function-like prefix. A structural proxy, not a compiler."
            ),
            "structural_complete_knr": (
                "Sensitivity check that additionally accepts old-style K&R definitions whose "
                "parameter declarations end in ';'. It changes six DeepSeek records in this "
                "sample (four schema-valid, two missing-explanation)."
            ),
            "substantive_change": (
                "Whitespace-collapsed text differs from the input (collapse_whitespace). This "
                "matches the 'substantive change' figure in the prior literature note. A second "
                "check compares comment-stripped token streams; comment-only edits do not count."
            ),
            "usable_patch": (
                "Canonical complete_function AND substantive change AND comment-insensitive "
                "token change. A structural usability proxy only; no compile, test, PoC, or "
                "human review is performed. It is not a correctness rate."
            ),
            "recoverable_rate": (
                "The share of a failure class whose payload can be admitted under a stated "
                "lenient policy (format recovery), or the share that also passes the usability "
                "proxy. Always report which denominator is used."
            ),
            "configured_peak_cache_aware": (
                "Cache-aware cost at each run's configured card. DeepSeek's configured card is "
                "the observed peak card 0.30/1.20/0.006; MiMo is flat 0.14/0.28/0.0028. This is "
                "the primary cost view in the old tables and is NOT the project-wide off-peak "
                "normalized view."
            ),
            "offpeak_list_normalized": (
                "Cache-aware cost at the project-wide off-peak list card from "
                "analysis/cost_normalization.md: DeepSeek 0.15/0.60/0.003, MiMo 0.14/0.28/0.0028. "
                "This is the view comparable with that report's normalized_list_usd."
            ),
            "not_accuracy": (
                "No number in this analysis is an accuracy, pass rate, or correctness estimate "
                "for salvaged outputs. MiMo's label agreement count is descriptive only."
            ),
        },
        "deepseek_repair": ds_summary,
        "official_vs_code_only": ds_official_vs_code,
        "cost": cost,
        "mimo_detection": mm_detection,
        "cross_model": cross_model,
        "sources": sources,
        "limitations": [
            "结构检查是词法代理，不是 C/C++ parser 或 compiler。两个 canonical “incomplete” "
            "是有效的 K&R 定义；这是已证实的假阴性，不是补丁本身的属性。",
            "没有编译、单元测试、sanitizer、PoC、patch 应用或人工评审。usable_patch 不表示"
            "漏洞已修、行为保持或代码可编译。",
            "changed_from_input 是文本级检查。本分析额外排除了 whitespace-only、comment-only "
            "和 no-change，但语义 no-op（改了 token 但行为不变）没有 oracle 无法识别。",
            "六个 run 是每个 model × strategy × task 一个观测；CI 是描述性 cluster bootstrap，"
            "不是新的预注册检验；没有赢家 claim。",
            "MiMo label agreement 是 post-hoc 对 dataset label 的描述，不是 accuracy；"
            "label 本身可能有噪声，detection payload 也不是补丁。",
            "成本是 list-price 重算，不是账单核对；DeepSeek reported 未扣 cached token，"
            "两个口径都报但不互相替代。",
            "CWE 标签来自数据集、可多值/拼接/缺失；CWE 表只做探索性分层，不做 CWE 间比较。",
            "成本有两个价格卡：configured peak cache-aware 与 off-peak list normalized。"
            "$2.521790 仅指本目录 12 个 run 的 configured peak 合计；off-peak list 是 "
            "$1.572472，才是与 analysis/cost_normalization.md 的 normalized_list_usd 可比的口径。",
            "只覆盖冻结的 SecVulEval test split；不能外推到其他数据、模型、prompt 或 CWE。",
        ],
    }
    return result, ds_runs, mm_runs


def record_row(item: dict[str, Any], model: str) -> dict[str, Any]:
    run = item["run"]
    record = item["record"]
    source = item["source"]
    response = record.get("response") or {}
    content = response.get("content")
    profile = item.get("profile")
    row: dict[str, Any] = {
        "record_id": "|".join(
            [
                model,
                str(record.get("task")),
                run["strategy"],
                run["task"],
                str(record.get("sample_id")),
            ]
        ),
        "model": model,
        "task": record.get("task"),
        "run_task": run["task"],
        "strategy": run["strategy"],
        "run_id": run["run_id"],
        "sample_id": record.get("sample_id"),
        "unit_id": source.get("idx") if run["task"] == "independent" else source.get("pair_id"),
        "project": source.get("project"),
        "cwe_list": source.get("cwe_list"),
        "status": record.get("status"),
        "error_class": item["class"],
        "official_schema_valid": False,
        "finish_reason": item["finish_reason"],
        "content_chars": len(content) if isinstance(content, str) else 0,
        "fatal": item["fatal"],
        "cost": {
            "configured_peak_known": item["cost"]["configured_peak_known"],
            "configured_peak_cache_aware_usd": item["cost"]["configured_peak_cache_aware_usd"],
            "offpeak_known": item["cost"]["offpeak_known"],
            "offpeak_list_normalized_usd": item["cost"]["offpeak_list_normalized_usd"],
            "model_key": item["cost"]["model_key"],
            "reported_usd": item["cost"]["reported_usd"],
            "prompt_tokens": item["cost"]["prompt_tokens"],
            "completion_tokens": item["cost"]["completion_tokens"],
            "cached_tokens": item["cost"]["cached_tokens"],
        },
    }
    if profile is not None:
        row.update(
            {
                "fixed_function_sha256": profile["change"]["fixed_sha256"],
                "source_sha256": profile["change"]["source_sha256"],
                "structural": profile["structural"],
                "change": profile["change"],
                "usable_patch_canonical": profile["usable_canonical"],
                "usable_patch_knr_aware": profile["usable_knr"],
                "non_usable_class": profile["non_usable_class"],
            }
        )
    else:
        row.update(
            {
                "fixed_function_sha256": None,
                "source_sha256": None,
                "structural": None,
                "change": None,
                "usable_patch_canonical": False,
                "usable_patch_knr_aware": False,
                "non_usable_class": "fatal_truncation" if item["class"].startswith("truncation") else "unparseable",
            }
        )
    if model == "mimo" and record.get("task") == "detection":
        row["mimo_drift"] = {
            "parse_ok": item["parse_ok"],
            "keys": list(item["keys"]) if item["keys"] else None,
            "missing_keys": item["missing_keys"],
            "extra_keys": item["extra_keys"],
            "alias": item["alias"],
            "drift_only": item["drift_only"],
            "payload_valid": item["payload_valid"],
            "recovered": item["recovered"],
            "recovered_value": item["recovered_value"],
            "gold_label": item["gold_label"],
            "label_agreement": item["label_agreement"],
        }
    else:
        row["mimo_drift"] = None
    return row


def build_record_rows(ds_runs: list[dict[str, Any]], mm_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in ds_runs:
        for item in run["repair_items"]:
            if item["class"] != "ok":
                rows.append(record_row(item, "deepseek"))
    for run in mm_runs:
        for item in run["detection_items"]:
            if item["class"] != "ok":
                rows.append(record_row(item, "mimo"))
        for item in run["repair_items"]:
            if item["class"] != "ok":
                rows.append(record_row(item, "mimo"))
    rows.sort(
        key=lambda row: (
            row["model"],
            str(row["task"]),
            row["strategy"],
            row["run_task"],
            str(row["sample_id"]),
        )
    )
    return rows


# ---------------------------------------------------------------------------
# markdown rendering
# ---------------------------------------------------------------------------


def pct(value: float | None, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    return f"{100.0 * value:.{digits}f}%"


def ratio(n: int, d: int, digits: int = 1) -> str:
    return f"{n}/{d} ({pct(rate(n, d), digits)})"


def usd(value: float | None, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    return f"${value:.{digits}f}"


def pp(value: float | None, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    return f"{value:+.{digits}f} pp"


def table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def render_markdown(result: dict[str, Any]) -> str:
    ds = result["deepseek_repair"]
    missing = ds["missing_explanation"]
    structural = missing["structural"]
    change = missing["change"]
    ovc = result["official_vs_code_only"]
    overall = ovc["overall"]
    cost = result["cost"]
    mm = result["mimo_detection"]
    drift = mm["field_drift"]
    cross = result["cross_model"]
    sources = result["sources"]

    lines: list[str] = []
    add = lines.append

    add("# DeepSeek 六 run schema 失败：零 API 复分析")
    add("")
    add(f"**分析版本**：`{result['schema_version']}`  ")
    add(f"**日期**：{result['analysis_date']}  ")
    add("**范围**：`runner/runs/test_v1_*` 六个 DeepSeek run（repair 924 条）与六个 MiMo run"
        "（detection 1,560 条、repair 924 条）；冻结 `secvul-split-v1` test。  ")
    add("**API / 网络调用**：**0**。脚本只读已落盘的 run、split、`runner/secvul_runner/validation.py` 和 "
        "`analysis/cost_normalization.json`，"
        "不调用模型、不访问网络；默认只写本目录（`--out-dir` 可显式改输出目录）。  ")
    add("**脚本**：`analysis/schema_recovery/recover.py`；"
        "**机器可读结果**：`schema_recovery.json`；**逐条审计**：`records.jsonl`。")
    add("")
    add("> **一句话**：DeepSeek 的 102 条 repair invalid 里，93 条只是缺 `explanation`；"
        "这些 payload 大多结构完整、且有实质代码改动。官方 strict schema 与 code-only salvage 是两个视图："
        "前者 822/924，后者 915/924；usable patch 从 552/924 升到 619/924（+7.25 pp）。"
        "**salvage 不是正确率**，也不证明漏洞被修复。")
    add("")

    add("## 0. 结论先行")
    add("")
    add(table(
        ["指标", "计数 / 分母", "值"],
        [
            ["official repair schema valid", ratio(ds["official_schema_valid"], ds["requests"]), pct(ds["official_schema_valid_rate"])],
            ["code-only admitted（official + missing explanation）", ratio(overall["code_only_admitted"], ds["requests"]), pct(overall["code_only_admission_rate"])],
            ["missing explanation", ratio(missing["n"], ds["requests"]), pct(missing["share_of_requests"])],
            ["canonical complete（93 条中）", ratio(structural["canonical_complete"], missing["n"]), pct(rate(structural["canonical_complete"], missing["n"]))],
            ["whitespace-collapsed substantive", ratio(change["substantive_changed"], missing["n"]), pct(rate(change["substantive_changed"], missing["n"]))],
            ["comment-insensitive substantive", ratio(change["comment_insensitive_changed"], missing["n"]), pct(rate(change["comment_insensitive_changed"], missing["n"]))],
            ["usable patch, canonical", ratio(missing["usable_canonical"], missing["n"]), pct(rate(missing["usable_canonical"], missing["n"]))],
            ["usable patch, K&R-aware", ratio(missing["usable_knr"], missing["n"]), pct(rate(missing["usable_knr"], missing["n"]))],
            ["official usable（complete + comment-insensitive change）", ratio(overall["official_usable_code"], ds["requests"]), pct(overall["official_usable_code_rate"])],
            ["code-only usable（same definition, + salvage）", ratio(overall["code_usable_code"], ds["requests"]), pct(overall["code_usable_code_rate"])],
            ["usable gain from salvage", f"{overall['code_usable_code'] - overall['official_usable_code']} 条", pp(overall["delta_code_code_pp"])],
            ["DeepSeek invalid 成本 / 总成本（configured peak / off-peak list）",
             f"{usd(cost['deepseek']['invalid']['configured_peak_cache_aware_usd'])} / "
             f"{usd(cost['deepseek']['invalid']['offpeak_list_normalized']['total_usd'])}",
             f"{pct(share(cost['deepseek']['invalid']['configured_peak_cache_aware_usd'], cost['deepseek']['all']['configured_peak_cache_aware_usd']))} / "
             f"{pct(share(cost['deepseek']['invalid']['offpeak_list_normalized']['total_usd'], cost['deepseek']['all']['offpeak_list_normalized']['total_usd']))}"],
            ["recoverable-to-usable 成本 / invalid 成本（configured peak / off-peak list）",
             f"{usd(cost['sunk_cost_reclassification']['configured_peak']['recoverable_to_usable_canonical_usd'])} / "
             f"{usd(cost['sunk_cost_reclassification']['offpeak_list_normalized']['recoverable_to_usable_canonical_usd'])}",
             f"{pct(cost['sunk_cost_reclassification']['configured_peak']['recoverable_share_canonical'])} / "
             f"{pct(cost['sunk_cost_reclassification']['offpeak_list_normalized']['recoverable_share_canonical'])}"],
            ["MiMo detection field drift", ratio(drift["n"], mm["requests"]), pct(drift["share_of_requests"])],
            ["MiMo alias-remap recovered", ratio(drift["recovered"], drift["n"]), pct(rate(drift["recovered"], drift["n"]))],
            ["MiMo post-hoc label agreement", f"{drift['label_agreement_count']}/{drift['recovered']}", pct(drift["label_agreement_share_descriptive"])],
        ],
    ))
    add("")
    add("最后一行是**描述性**的 label 一致计数，不是 accuracy，也不是任何排行榜指标。"
        "它只说明“格式可回收”与“内容正确”是两件事。")
    add("")

    add("## 1. 数据与口径")
    add("")
    add("### 1.1 十二个 run")
    add("")
    run_rows = []
    for run in sources["runs"]:
        run_rows.append([
            run["model"],
            run["strategy"],
            run["run_task"],
            f"`{run['run_id']}`",
            run["repair_records"],
            run["detection_records"],
            run["records"],
            "yes" if run["dataset_match"] else "**no**",
        ])
    add(table(["模型", "策略", "任务", "run_id", "repair", "detection", "总记录", "dataset hash"], run_rows))
    add("")
    add(f"官方 run 指标与重算交叉检查：{sources['crosschecks']['checks']} 项，"
        f"不匹配 {len(sources['crosschecks']['mismatches'])} 项。检查覆盖 `repair.requested/schema_valid/schema_invalid/"
        f"complete_and_changed`、`detection.requested/schema_invalid/valid_predictions` 和记录成本之和。")
    add("")
    add("### 1.2 三个视图")
    add("")
    add(table(
        ["视图", "定义", "它不是什么"],
        [
            ["official strict", "`record.status == \"ok\"`；repair 要求恰好 `fixed_function` + `explanation`，detection 要求恰好 `is_vulnerable` + `confidence` + `rationale`。", "不是“修复正确”；只是 schema 门槛。"],
            ["code-only salvage", "仅 repair：合法 JSON、非空 `fixed_function`、只缺 `explanation`。把它当作“可接收 payload”，仍保留 official 为 0 分。", "不是 official 分数，不是模型自我修正，不是正确率。"],
            ["usable patch", "canonical complete（或 K&R-aware complete）+ comment-insensitive 实质改动。", "不是编译通过、测试通过、PoC 通过或漏洞已修。"],
        ],
    ))
    add("")
    add("**实质改动的阶梯**（都只做文本/词法检查，不做 AST）：")
    add("")
    add(table(
        ["层级", "定义", "93 条中"],
        [
            ["text changed", "`normalize_code(fixed) != normalize_code(source)`（行尾/行首空白归一后）", change["text_changed"]],
            ["substantive (collapse)", "`collapse_whitespace(fixed) != collapse_whitespace(source)`；文献中的“实质改动”口径", change["substantive_changed"]],
            ["comment-insensitive substantive", "去掉 C/C++ 注释、保留字符串字面量后，token 序列仍不同", change["comment_insensitive_changed"]],
            ["usable canonical", "canonical complete ∩ comment-insensitive substantive", missing["usable_canonical"]],
            ["usable K&R-aware", "K&R-aware complete ∩ comment-insensitive substantive", missing["usable_knr"]],
        ],
    ))
    add("")
    add("`comment-insensitive` 这一层是故意加严的：有 2 条记录只改了注释/注释内空白，"
        "collapse-whitespace 会计为“实质”，但 token 序列不变；它们不应被算作可用补丁。"
        "这正是 format repair 伪装成 content change 的小样本例子。")
    add("")

    add("## 2. 102 条 invalid 的分解")
    add("")
    invalid_rows = []
    for name in ("missing_explanation", "truncation"):
        value = ds["invalid_classes"].get(name)
        if not value:
            continue
        invalid_rows.append([
            f"`{name}`",
            value["n"],
            pct(value["share_of_requests"]),
            pct(value["share_of_invalid"]),
            usd(value["cost"]["configured_peak_cache_aware_usd"]),
            usd(value["cost"]["offpeak_list_normalized"]["total_usd"]),
            pct(value["share_of_invalid_cost"]),
        ])
    invalid_rows.append([
        "**total**",
        ds["official_schema_invalid"],
        pct(ds["invalid_rate"]),
        "100.0%",
        usd(cost["deepseek"]["invalid"]["configured_peak_cache_aware_usd"]),
        usd(cost["deepseek"]["invalid"]["offpeak_list_normalized"]["total_usd"]),
        "100.0%",
    ])
    add(table(
        ["类别", "n", "占 repair 请求", "占 invalid", "configured peak 成本", "off-peak list 成本", "占 invalid 成本（peak）"],
        invalid_rows,
    ))
    add("")
    add("### 2.1 只缺 `explanation` 的 93 条")
    add("")
    add(table(
        ["检查", "n / 93", "说明"],
        [
            ["合法 JSON、可解析", ratio(structural["json_parseable"], 93), "没有语法错误；不是截断。"],
            ["`fixed_function` 存在且非空", ratio(structural["fixed_function_present"], 93), "payload 在。"],
            ["canonical complete", ratio(structural["canonical_complete"], 93), "2 条 K&R 被 canonical 规则误判。"],
            ["K&R-aware complete", ratio(structural["knr_aware_complete"], 93), "修正 K&R 误判后的结构检查。"],
            ["balanced delimiters", ratio(structural["balanced_delimiters"], 93), "圆/方/花括号平衡。"],
            ["ends with `}`", ratio(structural["ends_with_closing_brace"], 93), "归一后最后一个非空字符是 `}`。"],
            ["no markdown fence", ratio(structural["no_markdown_fence"], 93), "没有代码围栏。"],
            ["not diff-like", ratio(structural["not_diff_like"], 93), "不是 diff/patch 文本。"],
            ["function-like prefix", ratio(structural["function_like_prefix"], 93), "canonical 的签名检查；K&R 例外。"],
        ],
    ))
    add("")
    add(f"2 条 canonical incomplete 都是 `zlib` 的 K&R 风格定义（`int ZEXPORT deflatePrime (strm, bits, value)` 后接"
        f"参数声明再 `{{`）。它们平衡、以 `}}` 结束、无围栏/ diff；canonical 规则仅因为 `{{` 前以 `;` 结束而判 false。"
        f"这是结构代理的**已证实假阴性**，不是补丁损坏。")
    add("")
    add("### 2.2 93 条为什么不是“都能用”")
    add("")
    nonusable = missing["nonusable_classes_canonical"]
    add(table(
        ["canonical 视图", "n", "说明"],
        [
            ["usable（canonical）", missing["usable_canonical"], "结构完整 + comment-insensitive 实质改动。"],
            ["no change", nonusable.get("no_change", 0), "与输入在归一文本上完全相同；即使 schema 修好也是空补丁。"],
            ["whitespace only", nonusable.get("whitespace_only", 0), "只改空白/换行，token 不变。"],
            ["comment only", nonusable.get("comment_only", 0), "只改注释或注释内空白，token 不变。"],
            ["K&R false negative", nonusable.get("knr_false_negative_but_usable", 0), "canonical 误判，但 K&R-aware 下可用。"],
            ["**total**", 93, "67 + 18 + 4 + 2 + 2 = 93。"],
        ],
    ))
    add("")
    add("注意最后一行：canonical usable 67，K&R-aware usable 69。文献笔记里的“71 条有实质改动”"
        "是 collapse-whitespace 口径，包含 2 条 comment-only；它不是“71 条可用补丁”。"
        "严格 usable 是 67（canonical）或 69（K&R-aware）。")
    add("")
    add("### 2.3 按策略与 run")
    add("")
    strat_rows = []
    for strategy in ("direct", "few-shot", "context"):
        value = missing["by_strategy"][strategy]
        strat_rows.append([
            strategy,
            value["requests"],
            value["missing_explanation"],
            value["complete_canonical"],
            value["substantive_changed"],
            value["usable_canonical"],
            value["usable_knr"],
            value["no_change"],
            usd(value["missing_cost"]["configured_peak_cache_aware_usd"]),
        ])
    strat_rows.append([
        "**total**",
        ds["requests"],
        missing["n"],
        structural["canonical_complete"],
        change["substantive_changed"],
        missing["usable_canonical"],
        missing["usable_knr"],
        change["no_change"],
        usd(cost["deepseek"]["missing_explanation"]["configured_peak_cache_aware_usd"]),
    ])
    add(table(
        ["策略", "repair 请求", "missing", "complete canonical", "substantive", "usable canonical", "usable K&R", "no change", "missing 成本"],
        strat_rows,
    ))
    add("")
    run_rows = []
    for value in missing["by_run"]:
        run_rows.append([
            f"`{value['run_id']}`",
            value["requests"],
            value["missing_explanation"],
            value["complete_canonical"],
            value["substantive_changed"],
            value["usable_canonical"],
            value["usable_knr"],
            value["no_change"],
            usd(value["missing_cost"]["configured_peak_cache_aware_usd"]),
        ])
    add(table(
        ["run", "repair", "missing", "complete", "substantive", "usable canonical", "usable K&R", "no change", "missing 成本"],
        run_rows,
    ))
    add("")
    add("### 2.4 9 条截断是 fatal，不是可 salvage")
    add("")
    trunc = ds["truncation"]
    add(f"9 条截断全部 `finish_reason=length`，来自 3 个超长样本 × 3 个策略："
        f"`{', '.join(trunc['samples'])}`。content 长度 {min(trunc['content_chars'])}–{max(trunc['content_chars'])} 字符，"
        f"JSON 在字符串中间被切断。这里**不尝试补引号/补括号**：任何闭合都是分析者伪造的，不是模型输出；"
        f"故 0/9 进入 usable。截断成本 {usd(trunc['cost']['configured_peak_cache_aware_usd'])}，"
        f"占 DeepSeek invalid 成本 {pct(ds['invalid_classes']['truncation']['share_of_invalid_cost'])}。")
    add("")

    add("## 3. 官方 strict vs code-only")
    add("")
    ovc_rows = []
    for strategy in ("direct", "few-shot", "context"):
        value = ovc["by_strategy"][strategy]
        ovc_rows.append([
            strategy,
            value["requests"],
            value["official_schema_valid"],
            value["code_only_admitted"],
            value["official_usable_code"],
            value["salvage_usable_code"],
            value["code_usable_code"],
            pp(value["delta_code_code_pp"]),
        ])
    ovc_rows.append([
        "**total**",
        overall["requests"],
        overall["official_schema_valid"],
        overall["code_only_admitted"],
        overall["official_usable_code"],
        overall["salvage_usable_code"],
        overall["code_usable_code"],
        pp(overall["delta_code_code_pp"]),
    ])
    add(table(
        ["策略", "请求", "official valid", "code-only admitted", "official usable", "salvage usable", "code-only usable", "Δ usable"],
        ovc_rows,
    ))
    add("")
    add("`official usable` / `code-only usable` 的主定义是 **canonical complete + comment-insensitive substantive change**。"
        "salvage usable 只来自 93 条 missing-explanation；9 条截断不进入任何 salvage 列。")
    add("")
    add("### 3.1 换一个改动定义，结论怎么变")
    add("")
    add(table(
        ["改动定义", "official", "code-only", "Δ"],
        [
            ["text changed（prior code-only 口径）", ratio(overall["official_usable_text"], 924), ratio(overall["code_usable_text"], 924), pp(overall["delta_code_text_pp"])],
            ["substantive（collapse whitespace）", ratio(overall["official_usable_sub"], 924), ratio(overall["code_usable_sub"], 924), pp(overall["delta_code_sub_pp"])],
            ["comment-insensitive substantive（主口径）", ratio(overall["official_usable_code"], 924), ratio(overall["code_usable_code"], 924), pp(overall["delta_code_code_pp"])],
            ["comment-insensitive + K&R-aware complete", ratio(overall["official_usable_code_knr"], 924), ratio(overall["code_usable_code_knr"], 924), pp(overall["delta_code_code_knr_pp"])],
        ],
    ))
    add("")
    add("schema 门槛本身只解释约 **7.3–7.9 pp** 的 usable 变化；"
        "从 915/924 的 code-only admission 到 619/924 的 usable，仍有约 **32 pp** 落在 no-change / whitespace-only / comment-only / "
        "结构或内容不满足上。**schema 不是修复质量的主矛盾。**")
    add("")
    add("### 3.2 官方 schema 有效的 822 条里，也有大量空补丁")
    add("")
    official_valid = ds["official_valid"]
    add(table(
        ["指标", "n / 822", "率"],
        [
            ["usable（canonical）", ratio(official_valid["usable_canonical"], official_valid["records"]), pct(official_valid["usable_rate_canonical"])],
            ["usable（K&R-aware）", ratio(official_valid["usable_knr"], official_valid["records"]), pct(official_valid["usable_rate_knr"])],
            ["no change", ratio(official_valid["no_change"], official_valid["records"]), pct(official_valid["no_change_rate"])],
            ["whitespace only", ratio(official_valid["whitespace_only"], official_valid["records"]), pct(rate(official_valid["whitespace_only"], official_valid["records"]))],
            ["comment only", ratio(official_valid["comment_only"], official_valid["records"]), pct(official_valid["comment_only_rate"])],
            ["K&R false negative", official_valid["knr_false_negative"], "canonical 误判但 K&R 下可用"],
        ],
    ))
    add("")
    add("no-change 率按策略：DeepSeek direct 19.6%、few-shot 37.4%、context 16.7%；"
        "MiMo direct 23.3%、few-shot 50.2%、context 20.3%。few-shot 提高了 schema 合规，"
        "但也显著提高了“原样返回”的比例。**schema valid ≠ usable patch。**")
    add("")

    add("## 4. 成本")
    add("")
    add("> **口径警告**：本目录有两个 cache-aware 成本视图。`configured_peak_cache_aware` 用每个 run 的配置卡"
        "（DeepSeek 0.30/1.20/0.006；MiMo 0.14/0.28/0.0028）；`offpeak_list_normalized` 用全项目非高峰卡"
        "（DeepSeek 0.15/0.60/0.003；MiMo 同价）。前者是本目录 configured peak 合计；后者才与 "
        "`analysis/cost_normalization.md` 的 `normalized_list_usd` 可比。**$2.521790 是 configured peak 合计，"
        "不是全项目统一 normalized；同一 12 个 run 的 off-peak list 合计是 $1.572472。**")
    add("")
    add(table(
        ["口径", "DeepSeek", "MiMo", "与项目报告的关系"],
        [
            ["reported（原始记录）", "response.cost.cost_usd；DeepSeek legacy 不扣 cache", "response.cost.cost_usd；MiMo 正确带 cached token", "账单原始值，不能直接跨模型比较"],
            ["configured_peak_cache_aware", "0.30 / 1.20 / 0.006", "0.14 / 0.28 / 0.0028", "本目录主表；DeepSeek 是观测到的峰价卡"],
            ["offpeak_list_normalized", "0.15 / 0.60 / 0.003", "0.14 / 0.28 / 0.0028", "与 analysis/cost_normalization.md 的 normalized_list_usd 同口径"],
        ],
    ))
    add("")
    ds_cost = cost["deepseek"]
    add(table(
        ["bucket", "records", "configured peak $", "off-peak list $", "占 DS 总成本（peak）", "占 DS repair（peak）", "占 invalid（peak）"],
        [
            ["DeepSeek all", ds_cost["all"]["records"], usd(ds_cost["all"]["configured_peak_cache_aware_usd"]), usd(ds_cost["all"]["offpeak_list_normalized"]["total_usd"]), "100.0%", "—", "—"],
            ["DeepSeek repair", ds_cost["repair"]["records"], usd(ds_cost["repair"]["configured_peak_cache_aware_usd"]), usd(ds_cost["repair"]["offpeak_list_normalized"]["total_usd"]), pct(share(ds_cost["repair"]["configured_peak_cache_aware_usd"], ds_cost["all"]["configured_peak_cache_aware_usd"])), "100.0%", "—"],
            ["DeepSeek invalid", ds_cost["invalid"]["records"], usd(ds_cost["invalid"]["configured_peak_cache_aware_usd"]), usd(ds_cost["invalid"]["offpeak_list_normalized"]["total_usd"]), pct(share(ds_cost["invalid"]["configured_peak_cache_aware_usd"], ds_cost["all"]["configured_peak_cache_aware_usd"])), pct(share(ds_cost["invalid"]["configured_peak_cache_aware_usd"], ds_cost["repair"]["configured_peak_cache_aware_usd"])), "100.0%"],
            ["  missing explanation", cost["failure_costs"]["deepseek_missing_explanation"]["n"], usd(cost["failure_costs"]["deepseek_missing_explanation"]["cost"]["configured_peak_cache_aware_usd"]), usd(cost["failure_costs"]["deepseek_missing_explanation"]["cost"]["offpeak_list_normalized"]["total_usd"]), pct(cost["failure_costs"]["deepseek_missing_explanation"]["share_of_deepseek_total"]), pct(cost["failure_costs"]["deepseek_missing_explanation"]["share_of_deepseek_repair"]), pct(cost["failure_costs"]["deepseek_missing_explanation"]["share_of_deepseek_invalid"])],
            ["  truncation", cost["failure_costs"]["deepseek_truncation"]["n"], usd(cost["failure_costs"]["deepseek_truncation"]["cost"]["configured_peak_cache_aware_usd"]), usd(cost["failure_costs"]["deepseek_truncation"]["cost"]["offpeak_list_normalized"]["total_usd"]), pct(cost["failure_costs"]["deepseek_truncation"]["share_of_deepseek_total"]), pct(cost["failure_costs"]["deepseek_truncation"]["share_of_deepseek_repair"]), pct(cost["failure_costs"]["deepseek_truncation"]["share_of_deepseek_invalid"])],
            ["  usable salvage（canonical）", missing["usable_canonical"], usd(ds_cost["usable_salvage_canonical"]["configured_peak_cache_aware_usd"]), usd(ds_cost["usable_salvage_canonical"]["offpeak_list_normalized"]["total_usd"]), pct(share(ds_cost["usable_salvage_canonical"]["configured_peak_cache_aware_usd"], ds_cost["all"]["configured_peak_cache_aware_usd"])), pct(share(ds_cost["usable_salvage_canonical"]["configured_peak_cache_aware_usd"], ds_cost["repair"]["configured_peak_cache_aware_usd"])), pct(cost["sunk_cost_reclassification"]["configured_peak"]["recoverable_share_canonical"])],
            ["  missing but non-usable", missing["nonusable_count_canonical"], usd(ds_cost["missing_nonusable_canonical"]["configured_peak_cache_aware_usd"]), usd(ds_cost["missing_nonusable_canonical"]["offpeak_list_normalized"]["total_usd"]), pct(share(ds_cost["missing_nonusable_canonical"]["configured_peak_cache_aware_usd"], ds_cost["all"]["configured_peak_cache_aware_usd"])), pct(share(ds_cost["missing_nonusable_canonical"]["configured_peak_cache_aware_usd"], ds_cost["repair"]["configured_peak_cache_aware_usd"])), pct(share(ds_cost["missing_nonusable_canonical"]["configured_peak_cache_aware_usd"], ds_cost["invalid"]["configured_peak_cache_aware_usd"]))],
        ],
    ))
    add("")
    add("DeepSeek 的 off-peak list 成本是 configured peak 的精确 0.5×，所以上表的占比列在两种口径下相同；"
        "**不要把 DeepSeek 的 0.5× 关系套到 MiMo**（MiMo 没有峰谷价，两口径相同）。")
    add("")
    add("**计数与成本的主矛盾不同**：missing explanation 占 invalid 条数的 91.2%，却只占 invalid 成本的 47.4%；"
        "9 条截断占条数的 8.8%，却占 invalid 成本的 52.6%（单条约 $0.01275，是 missing 单条的 11 倍）。"
        "把“invalid 成本主要是缺 explanation”当成结论，只在按记录数计时成立。")
    add("")
    add("### 4.1  salvage 的成本结构")
    add("")
    sunk = cost["sunk_cost_reclassification"]
    add(table(
        ["项", "configured peak $", "off-peak list $", "占 invalid 成本（peak）"],
        [
            ["invalid total", usd(sunk["configured_peak"]["invalid_total_usd"]), usd(sunk["offpeak_list_normalized"]["invalid_total_usd"]), "100.0%"],
            ["recoverable → usable（canonical）", usd(sunk["configured_peak"]["recoverable_to_usable_canonical_usd"]), usd(sunk["offpeak_list_normalized"]["recoverable_to_usable_canonical_usd"]), pct(sunk["configured_peak"]["recoverable_share_canonical"])],
            ["recoverable → usable（K&R-aware）", usd(sunk["configured_peak"]["recoverable_to_usable_knr_usd"]), usd(sunk["offpeak_list_normalized"]["recoverable_to_usable_knr_usd"]), pct(sunk["configured_peak"]["recoverable_share_knr"])],
            ["missing but non-usable（canonical）", usd(sunk["configured_peak"]["nonusable_missing_canonical_usd"]), usd(sunk["offpeak_list_normalized"]["nonusable_missing_canonical_usd"]), pct(share(sunk["configured_peak"]["nonusable_missing_canonical_usd"], sunk["configured_peak"]["invalid_total_usd"]))],
            ["fatal truncation", usd(sunk["configured_peak"]["fatal_truncation_usd"]), usd(sunk["offpeak_list_normalized"]["fatal_truncation_usd"]), pct(share(sunk["configured_peak"]["fatal_truncation_usd"], sunk["configured_peak"]["invalid_total_usd"]))],
        ],
    ))
    add("")
    add("salvage 的**边际 API 成本是 $0**：这些响应已经生成并付费；复分析只是重新分类已发生的沉没成本。"
        "这不等于“免费获得正确补丁”——67 条 usable 仍要经过编译/测试/PoC 才能谈修复。")
    add("")
    add("### 4.2 每单位结构性可用输出的成本")
    add("")
    cpu = cost["cost_per_usable"]
    add(table(
        ["口径", "configured peak $/unit", "off-peak list $/unit", "分母"],
        [
            ["official usable（canonical）", usd(cpu["configured_peak"]["official_code_canonical"], 6), usd(cpu["offpeak_list_normalized"]["official_code_canonical"], 6), overall["official_usable_code"]],
            ["code-only usable（canonical）", usd(cpu["configured_peak"]["code_code_canonical"], 6), usd(cpu["offpeak_list_normalized"]["code_code_canonical"], 6), overall["code_usable_code"]],
            ["code-only usable（K&R-aware）", usd(cpu["configured_peak"]["code_code_knr"], 6), usd(cpu["offpeak_list_normalized"]["code_code_knr"], 6), overall["code_usable_code_knr"]],
            ["salvage usable（canonical）", usd(cpu["configured_peak"]["salvage_canonical"], 6), usd(cpu["offpeak_list_normalized"]["salvage_canonical"], 6), missing["usable_canonical"]],
            ["salvage usable（K&R-aware）", usd(cpu["configured_peak"]["salvage_knr"], 6), usd(cpu["offpeak_list_normalized"]["salvage_knr"], 6), missing["usable_knr"]],
            ["truncation / record", usd(cpu["configured_peak"]["truncation_per_record"], 6), usd(cpu["offpeak_list_normalized"]["truncation_per_record"], 6), ds["truncation"]["n"]],
            ["MiMo drift / recovered", usd(cpu["configured_peak"]["mimo_field_drift_per_recovered"], 6), usd(cpu["offpeak_list_normalized"]["mimo_field_drift_per_recovered"], 6), drift["recovered"]],
        ],
    ))
    add("")
    add("这是“结构性可用输出”的平均会计成本，不是“每个正确修复”的成本；分母不是正确数。")
    add("")
    add("### 4.3 MiMo 与合计")
    add("")
    mm_cost = cost["mimo"]
    add(table(
        ["bucket", "records", "configured peak $", "off-peak list $", "说明"],
        [
            ["MiMo all", mm_cost["all"]["records"], usd(mm_cost["all"]["configured_peak_cache_aware_usd"]), usd(mm_cost["all"]["offpeak_list_normalized"]["total_usd"]), "六个 run 全部记录"],
            ["MiMo detection", mm_cost["detection"]["records"], usd(mm_cost["detection"]["configured_peak_cache_aware_usd"]), usd(mm_cost["detection"]["offpeak_list_normalized"]["total_usd"]), "1,560 条 detection"],
            ["MiMo repair", mm_cost["repair"]["records"], usd(mm_cost["repair"]["configured_peak_cache_aware_usd"]), usd(mm_cost["repair"]["offpeak_list_normalized"]["total_usd"]), "924 条 repair"],
            ["  field drift", drift["n"], usd(cost["failure_costs"]["mimo_field_drift"]["cost"]["configured_peak_cache_aware_usd"]), usd(cost["failure_costs"]["mimo_field_drift"]["cost"]["offpeak_list_normalized"]["total_usd"]), f"占 detection 成本 {pct(cost['failure_costs']['mimo_field_drift']['share_of_mimo_detection'])}"],
            ["  repair truncation", 9, usd(cost["failure_costs"]["mimo_truncation"]["cost"]["configured_peak_cache_aware_usd"]), usd(cost["failure_costs"]["mimo_truncation"]["cost"]["offpeak_list_normalized"]["total_usd"]), f"占 MiMo invalid 成本 {pct(cost['failure_costs']['mimo_truncation']['share_of_mimo_invalid'])}"],
        ],
    ))
    add("")
    combined = cost["combined"]
    add(f"两模型合计 invalid 成本：configured peak **{usd(combined['invalid']['configured_peak_cache_aware_usd'])}**，"
        f"占 configured peak 总成本 {pct(combined['invalid_share_configured_peak'])}"
        f"（{usd(combined['all']['configured_peak_cache_aware_usd'])}）；"
        f"off-peak list **{usd(combined['invalid']['offpeak_list_normalized']['total_usd'])}**，"
        f"占 off-peak 总成本 {pct(combined['invalid_share_offpeak_list_normalized'])}"
        f"（{usd(combined['all']['offpeak_list_normalized']['total_usd'])}）。")
    add("")
    add("> **$2.521790 的准确定义**：它是本目录 12 个 run 的 **configured peak cache-aware** 合计，"
        "不是全项目统一 normalized。全项目 off-peak list 口径下，同一 12 个 run 是 **$1.572472**；"
        "该值与 `analysis/cost_normalization.md` 的 `legacy_test.normalized_list_usd` 一致。"
        "两个数不能混用或相加到其他实验的 off-peak 总量上。")
    add("")
    rn = cost["reported_vs_configured_peak"]
    add("**reported vs 两种 cache-aware 口径**：")
    add("")
    add(table(
        ["bucket", "reported", "configured peak", "off-peak list", "Δ vs peak", "Δ vs off-peak"],
        [
            ["DS missing explanation", usd(rn["deepseek_missing_explanation"]["reported_usd"]), usd(rn["deepseek_missing_explanation"]["configured_peak_cache_aware_usd"]), usd(rn["deepseek_missing_explanation"]["offpeak_list_normalized_usd"]), usd(rn["deepseek_missing_explanation"]["delta_vs_configured_peak_usd"]), usd(rn["deepseek_missing_explanation"]["delta_vs_offpeak_list_usd"])],
            ["DS truncation", usd(rn["deepseek_truncation"]["reported_usd"]), usd(rn["deepseek_truncation"]["configured_peak_cache_aware_usd"]), usd(rn["deepseek_truncation"]["offpeak_list_normalized_usd"]), usd(rn["deepseek_truncation"]["delta_vs_configured_peak_usd"]), usd(rn["deepseek_truncation"]["delta_vs_offpeak_list_usd"])],
            ["MiMo field drift", usd(rn["mimo_field_drift"]["reported_usd"]), usd(rn["mimo_field_drift"]["configured_peak_cache_aware_usd"]), usd(rn["mimo_field_drift"]["offpeak_list_normalized_usd"]), usd(rn["mimo_field_drift"]["delta_vs_configured_peak_usd"]), usd(rn["mimo_field_drift"]["delta_vs_offpeak_list_usd"])],
        ],
    ))
    add("")
    add("DeepSeek 的 `response.cost` 没有扣 cached token；两种 cache-aware 视图都用 usage 的 cached_tokens 重算，"
        "区别只在价格卡。跨模型比较统一用 off-peak list 口径时，才能与 `analysis/cost_normalization.md` 对齐；"
        "official 账单仍以 reported 为准。")
    add("")
    ext = cost["external_basis"]
    if ext.get("available"):
        comp = ext["comparison"]
        add("**与 `analysis/cost_normalization.md` 的交叉核对**（同一 12 个 test_v1 run，4,968 条记录）：")
        add("")
        add(table(
            ["口径", "本目录重算", "参考值", "Δ", "匹配"],
            [
                ["configured peak cache-aware", usd(comp["configured_peak_cache_aware"]["recomputed_usd"]), usd(comp["configured_peak_cache_aware"]["reference_usd"]), usd(comp["configured_peak_cache_aware"]["delta_usd"]), "yes" if comp["configured_peak_cache_aware"]["match"] else "no"],
                ["off-peak list normalized", usd(comp["offpeak_list_normalized"]["recomputed_usd"]), usd(comp["offpeak_list_normalized"]["reference_usd"]), usd(comp["offpeak_list_normalized"]["delta_usd"]), "yes" if comp["offpeak_list_normalized"]["match"] else "no"],
            ],
        ))
        add("")
        add(f"参考文件：`{ext['path']}`（SHA-256 `{ext['sha256'][:16]}…`）。"
            "参考值的字段名是 `configured_cache_aware_usd` 与 `normalized_list_usd`；"
            "本目录把后者明确标成 off-peak list normalized，避免与 configured peak 混用。")
    else:
        add("未找到 `analysis/cost_normalization.json`；off-peak list 数值仍按本地价格卡计算，但无法做参考交叉核对。")
    add("")

    add("## 5. MiMo 字段漂移对照")
    add("")
    sym = cross["symmetry"]

    def format_symmetry(row: dict[str, Any], value: Any) -> str:
        dimension = row["dimension"]
        if dimension == "failure rate" or dimension.startswith("share of invalid cost"):
            return pct(value)
        if dimension.startswith("failure-class cost") or dimension.startswith("lenient-admitted cost"):
            return usd(value)
        if isinstance(value, list):
            return " / ".join(str(item) for item in value)
        if isinstance(value, dict):
            if "canonical_complete" in value:
                return (
                    f"complete {value['canonical_complete']}/93 canonical, "
                    f"{value['knr_aware_complete']}/93 K&R; usable "
                    f"{value['usable_canonical']} canonical, {value['usable_knr']} K&R"
                )
            return (
                f"payload valid {value['payload_valid']}; "
                f"label agreement {value['label_agreement_count']}"
            )
        return str(value)

    add(table(
        ["维度", "DeepSeek repair: missing explanation", "MiMo detection: field drift"],
        [
            [
                row["dimension"],
                format_symmetry(row, row["deepseek_repair_missing_explanation"]),
                format_symmetry(row, row["mimo_detection_field_drift"]),
            ]
            for row in sym
        ],
    ))
    add("")
    add("`lenient-admitted cost` 两列的口径不同：DeepSeek 是 67 条 usable salvage，MiMo 是 61 条 alias-recovered drift；"
        "看量级请用 `failure-class cost` 行（93 条 missing 的成本 vs 61 条 drift 的成本）。"
        "表中同时给出 configured peak 与 off-peak list 两个价格卡；DeepSeek 的 off-peak 是 peak 的 0.5×，"
        "MiMo 两者相同。**不要把 93 条 missing 的 configured peak 成本与 MiMo 的 off-peak 成本当成同一口径比较。**")
    add("")
    add("**漂移键**：")
    add("")
    add(table(
        ["键模式", "n"],
        [[f"`{key.replace('|', ' + ')}`", value] for key, value in drift["key_patterns"].items()],
    ))
    add("")
    add(f"61 条中 59 条只写 `is_vulnerability`，1 条写 `is_vulnerative`，1 条同时写 `is_vulnerable` 和 `is_vulnerability`。"
        f"61/61 可 alias-remap，61/61 的 `confidence`/`rationale` 也通过类型检查；但 recovered value 是 "
        f"{drift['recovered_value_counts'].get('true', 0)} true / {drift['recovered_value_counts'].get('false', 0)} false，"
        f"gold 是 {drift['gold_label_counts'].get('true', 0)} true / {drift['gold_label_counts'].get('false', 0)} false，"
        f"post-hoc label 一致只有 {drift['label_agreement_count']}/{drift['recovered']}。")
    add("")
    add("这组数字的用途是**反例**：format recovery 可以 100%，但恢复出来的检测大多仍是 false；"
        "把它叫“正确率提升”会掩盖 33/61 的不一致。MiMo 的 61 条也不是随机失败：direct 39、context 22、few-shot 0；"
        "DeepSeek 的 93 条同样是 direct 45、context 48、few-shot 0。两边的格式失败都在 few-shot 消失。")
    add("")
    add("但两边的下游可验证性不同：MiMo 的 payload 里有可直接对 label 的布尔值；"
        "DeepSeek 的 payload 是代码，没有编译/测试/PoC 就只能停在结构代理。因此 **不能**把 28/61 与 67/93 放在同一把尺子上。")
    add("")

    add("## 6. 模型比较敏感性（post-hoc）")
    add("")
    add("这张表只回答“换 schema 口径后，direct/context 的修复 CAC 方向是否稳定”，不是新的主终点，也不产生赢家。"
        "CAC（complete + change）仍是结构代理，不是正确率；`official` 只算 schema-valid，`code-only` 额外接收 missing-explanation。")
    add("")
    cac_rows = []
    for row in cross["cac_sensitivity"]:
        ci = "n/a" if row["ci_low_pp"] is None else f"[{row['ci_low_pp']:+.1f}, {row['ci_high_pp']:+.1f}]"
        cac_rows.append([
            f"{row['strategy']}/{row['task']}",
            row["view"],
            pct(row["deepseek_rate"]),
            pct(row["mimo_rate"]),
            pp(row["diff_pp"]),
            ci,
            "yes" if row["excludes_zero"] else "no",
        ])
    add(table(["cell", "view", "DeepSeek", "MiMo", "Δ", "95% CI (pp)", "CI 排除 0"], cac_rows))
    add("")
    add("- **official text**：direct/context 四个格子的点估计都是 MiMo 更高；direct pairs、context independent、context pairs 的 CI 排除 0，direct independent 不排除。")
    add("- **code-only text**：四个格子的点估计全部翻成 DeepSeek 更高，但所有 CI 都跨 0。")
    add("- **official code**（更严的实质改动）：MiMo 在四个格子仍更高，3/4 的 CI 排除 0。")
    add("- **code-only code**：DeepSeek 在四个格子略高或持平，但所有 CI 都跨 0。")
    add("- **few-shot**：两边都没有 schema 失败；DeepSeek CAC 高 12.5–14.4 pp，CI 排除 0。这是唯一稳健的“内容/行为”差异，但 CAC 只说明“改得更多”，不说明“修得对”。")
    add("")
    add("结论：**official 排名是 schema 口径的产物，但 salvage 后的差异很小且不确定；不能说 DeepSeek 修复更好。**"
        " direct/context 的 MiMo 优势在 code-only 下翻成 DeepSeek 的微弱优势；这个翻转本身依赖改动定义和 CI，不能当成稳定结论。")
    add("")
    add("### 6.1 no-change 率（official valid 内）")
    add("")
    add(table(
        ["模型", "策略", "official valid", "no change", "no-change 率", "whitespace only"],
        [[row["model"], row["strategy"], row["official_valid"], row["no_change"], pct(row["no_change_rate"]), row["whitespace_only"]] for row in cross["no_change_rates"]],
    ))
    add("")
    add("few-shot 的 no-change 率最高（DeepSeek 37.4%，MiMo 50.2%）。"
        "这解释了为什么 few-shot 的 CAC 差异不能直接读成“修复能力”：更少 schema 错误，但更多原样返回。")
    add("")

    add("## 7. CWE 分层（探索性）")
    add("")
    cwe_rows = []
    for row in missing["by_cwe"][:10]:
        cwe_rows.append([
            f"`{row['cwe']}`",
            row["n"],
            pct(row["share_of_missing"]),
            row["complete_canonical"],
            row["substantive_changed"],
            row["usable_canonical"],
            row["usable_knr"],
            row["no_change"],
            usd(row["cost"]["configured_peak_cache_aware_usd"]),
        ])
    add(table(
        ["primary CWE", "n", "占 93", "complete", "substantive", "usable canonical", "usable K&R", "no change", "成本"],
        cwe_rows,
    ))
    add("")
    add("`usable 0` 不一定是计数错误：例如 CWE-399 的 4 条中 2 条是 comment-only、1 条 whitespace-only、1 条 no-change，"
        "token 层都没有改动；这正说明“结构完整”与“可用补丁”是两个门槛。")
    add("")
    add(f"93 条覆盖 {len(missing['by_cwe'])} 个 primary CWE 标签；Top 3 是 CWE-125（18）、CWE-787（14）、CWE-119（11），"
        f"合计 43/93（46.2%），都是内存安全类。CWE 标签来自数据集、可多值、部分拼接或缺失（7 条 unlabeled），"
        f"所以这里只做分层描述，不做 CWE 间比较。")
    add("")

    add("## 8. 这不能证明什么")
    add("")
    for item in result["limitations"]:
        add(f"- {item}")
    add("")

    add("## 9. 复现")
    add("")
    add("```bash")
    add("cd /mnt/c/Users/tzh03/Downloads/cs224proj")
    add("python3 analysis/schema_recovery/recover.py")
    add("python3 analysis/schema_recovery/recover.py --check")
    add("python3 analysis/schema_recovery/recover.py --selftest")
    add("```")
    add("")
    add("`--check` 重新生成并逐字节比较 `schema_recovery.json`、`schema_recovery.md`、`records.jsonl`；"
        "`--selftest` 跑内部断言（tokenizer、K&R、Wilson、成本公式、关键计数）。"
        "默认 bootstrap 10,000 次、seed 42；`--bootstrap-reps 0` 可跳过 CI（此时输出会不同，`--check` 会失败）。")
    add("")
    add("**输出**：")
    add("")
    add("- `schema_recovery.json`：全部点估计、区间、成本、来源 hash、交叉检查。")
    add("- `schema_recovery.md`：本文件。")
    add("- `records.jsonl`：172 条 invalid 的逐条审计（102 DeepSeek repair + 61 MiMo detection + 9 MiMo repair truncation）；不含源码正文，只含 hash、标志、token/成本。")
    add("")
    add("**零 API**：脚本没有 `requests`、`openai`、`httpx` 或任何网络导入；不读取 API key；"
        "所有数字来自 `results.jsonl` 的已记录 usage 与 frozen split。")
    add("")
    add(f"**来源指纹**：`runner/secvul_runner/validation.py` = `{sources['validator']['sha256'][:16]}…`；"
        f"`analysis/cost_normalization.json` = `{sources['cost_normalization']['sha256'][:16] if sources['cost_normalization']['sha256'] else 'n/a'}…`；"
        f"两个 split 的 SHA-256 与 12 个 run config 逐一匹配；run 指标交叉检查 "
        f"{sources['crosschecks']['checks']} 项、0 不匹配。")
    add("")

    return "\n".join(lines).rstrip() + "\n"
# ---------------------------------------------------------------------------
# serialization, self-test, CLI
# ---------------------------------------------------------------------------


def serialize_json(result: dict[str, Any]) -> str:
    return (
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    )


def serialize_records(rows: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
        for row in rows
    )


def write_outputs(out_dir: Path, result: dict[str, Any], markdown: str, rows: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payloads = {
        "schema_recovery.json": serialize_json(result),
        "schema_recovery.md": markdown,
        "records.jsonl": serialize_records(rows),
    }
    for name, text in payloads.items():
        with (out_dir / name).open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)


def check_outputs(out_dir: Path, result: dict[str, Any], markdown: str, rows: list[dict[str, Any]]) -> int:
    expected = {
        "schema_recovery.json": serialize_json(result).encode("utf-8"),
        "schema_recovery.md": markdown.encode("utf-8"),
        "records.jsonl": serialize_records(rows).encode("utf-8"),
    }
    failed = False
    for name, data in expected.items():
        path = out_dir / name
        if not path.exists():
            print(f"MISSING {path}")
            failed = True
            continue
        actual = path.read_bytes()
        if actual == data:
            print(f"OK      {path}")
        else:
            print(f"DIFF    {path} (expected {len(data)} bytes, found {len(actual)})")
            failed = True
    return 1 if failed else 0


def run_selftest(project_root: Path, seed: int) -> None:
    assert tokenize("int a; // comment\n") == tokenize("int a;")
    assert tokenize("/* block */ int a;") == tokenize("int a;")
    assert tokenize('char *s = "// not a comment";') != tokenize('char *s = "";')

    knr_source = "int f(a)\n    int a;\n{\n    return a;\n}\n"
    checks = analyze_repair(knr_source, knr_source)
    assert not checks["complete_function"]
    assert knr_aware_complete(knr_source, checks)

    interval = wilson(67, 93)
    assert interval is not None
    assert 0.60 < interval["low"] < 0.66
    assert 0.78 < interval["high"] < 0.84

    config = {
        "api": {
            "model": "deepseek-v4.1-flash",
            "input_price_usd_per_1m": 1.0,
            "output_price_usd_per_1m": 2.0,
            "cached_input_price_usd_per_1m": 0.1,
        }
    }
    record = {
        "response": {
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 100,
                "prompt_tokens_details": {"cached_tokens": 200},
            },
            "cost": {"cost_usd": 0.1},
        }
    }
    cost = configured_peak_cache_aware_cost(record, config)
    expected = (800 * 1.0 + 200 * 0.1 + 100 * 2.0) / 1_000_000.0
    expected_offpeak = (800 * 0.15 + 200 * 0.003 + 100 * 0.60) / 1_000_000.0
    assert cost["configured_peak_known"] and abs(cost["configured_peak_cache_aware_usd"] - expected) < 1e-12
    assert cost["offpeak_known"] and abs(cost["offpeak_list_normalized_usd"] - expected_offpeak) < 1e-12

    result, ds_runs, mm_runs = build_result(project_root, 200, seed, False, False)
    ds = result["deepseek_repair"]
    missing = ds["missing_explanation"]
    assert ds["requests"] == 924
    assert ds["official_schema_valid"] == 822
    assert ds["official_schema_invalid"] == 102
    assert missing["n"] == 93
    assert ds["truncation"]["n"] == 9
    assert missing["structural"]["canonical_complete"] == 91
    assert missing["structural"]["knr_aware_complete"] == 93
    assert missing["change"]["text_changed"] == 75
    assert missing["change"]["substantive_changed"] == 71
    assert missing["change"]["comment_insensitive_changed"] == 69
    assert missing["change"]["comment_only"] == 2
    assert missing["usable_canonical"] == 67
    assert missing["usable_knr"] == 69
    assert result["official_vs_code_only"]["overall"]["code_only_admitted"] == 915
    assert result["official_vs_code_only"]["overall"]["official_usable_code"] == 552
    assert result["official_vs_code_only"]["overall"]["salvage_usable_code"] == 67
    assert result["official_vs_code_only"]["overall"]["code_usable_code"] == 619
    assert abs(result["cost"]["deepseek"]["all"]["configured_peak_cache_aware_usd"] - 1.89863562) < 1e-8
    assert abs(result["cost"]["deepseek"]["all"]["offpeak_list_normalized"]["total_usd"] - 0.94931781) < 1e-8
    assert abs(result["cost"]["deepseek"]["invalid"]["configured_peak_cache_aware_usd"] - 0.218279592) < 1e-9
    assert abs(result["cost"]["mimo"]["all"]["configured_peak_cache_aware_usd"] - 0.623154) < 1e-6
    assert abs(result["cost"]["mimo"]["invalid"]["configured_peak_cache_aware_usd"] - 0.042045) < 1e-6
    assert abs(result["cost"]["combined"]["all"]["configured_peak_cache_aware_usd"] - 2.521790096) < 1e-8
    assert abs(result["cost"]["combined"]["all"]["offpeak_list_normalized"]["total_usd"] - 1.572472286) < 1e-8
    assert result["cost"]["external_basis"]["comparison"]["configured_peak_cache_aware"]["match"] is True
    assert result["cost"]["external_basis"]["comparison"]["offpeak_list_normalized"]["match"] is True
    mm = result["mimo_detection"]
    assert mm["requests"] == 1560
    assert mm["official_schema_invalid"] == 61
    assert mm["field_drift"]["recovered"] == 61
    assert mm["field_drift"]["label_agreement_count"] == 28
    assert not result["sources"]["crosschecks"]["mismatches"]
    rows = build_record_rows(ds_runs, mm_runs)
    assert len(rows) == 172
    print("selftest: OK (tokenizer, K&R, Wilson, cost formula, key counts, 172 audit rows)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-API re-analysis of schema-invalid DeepSeek repair outputs and MiMo "
            "detection field drift. Reads frozen run artefacts only."
        )
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="data root containing runner/ and splits/ (validator is always imported from this script's repo)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="directory for schema_recovery.json/md and records.jsonl",
    )
    parser.add_argument("--bootstrap-reps", type=int, default=DEFAULT_BOOTSTRAP_REPS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--check", action="store_true", help="regenerate in memory and compare byte-for-byte")
    parser.add_argument("--selftest", action="store_true", help="run internal assertions and exit")
    parser.add_argument("--allow-source-drift", action="store_true", help="do not abort on dataset hash mismatch")
    parser.add_argument(
        "--allow-crosscheck-drift",
        action="store_true",
        help="do not abort when recorded metrics disagree with the recount",
    )
    args = parser.parse_args(argv)

    if args.bootstrap_reps < 0:
        parser.error("--bootstrap-reps must be >= 0")

    if args.selftest:
        run_selftest(args.project_root, args.seed)
        return 0

    result, ds_runs, mm_runs = build_result(
        args.project_root,
        args.bootstrap_reps,
        args.seed,
        args.allow_source_drift,
        args.allow_crosscheck_drift,
    )
    markdown = render_markdown(result)
    rows = build_record_rows(ds_runs, mm_runs)

    if args.check:
        return check_outputs(args.out_dir, result, markdown, rows)

    write_outputs(args.out_dir, result, markdown, rows)
    ds = result["deepseek_repair"]
    missing = ds["missing_explanation"]
    print(f"wrote {args.out_dir / 'schema_recovery.json'}")
    print(f"wrote {args.out_dir / 'schema_recovery.md'}")
    print(f"wrote {args.out_dir / 'records.jsonl'} ({len(rows)} rows)")
    print(
        "DeepSeek repair: "
        f"{ds['official_schema_valid']}/{ds['requests']} official valid; "
        f"{missing['n']} missing explanation; "
        f"{missing['usable_canonical']} usable canonical ({pct(rate(missing['usable_canonical'], missing['n']))}); "
        f"{result['official_vs_code_only']['overall']['code_usable_code']}/{ds['requests']} code-only usable "
        f"({pct(result['official_vs_code_only']['overall']['code_usable_code_rate'])})."
    )
    print(
        "MiMo detection: "
        f"{result['mimo_detection']['official_schema_invalid']}/{result['mimo_detection']['requests']} field drift; "
        f"{result['mimo_detection']['field_drift']['recovered']} alias-recovered; "
        f"{result['mimo_detection']['field_drift']['label_agreement_count']} descriptive label agreement."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

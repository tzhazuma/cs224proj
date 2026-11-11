#!/usr/bin/env python3
"""Render LaTeX table rows or a cost JSON summary from real runner artifacts.

This script only reads artifacts produced by runner/secvul_runner. It never
calls a model, never writes report_zh.tex, and never invents a value: a missing
run, an incomplete run, a partial run, or a model/prompt/dataset mismatch is a
hard error. Output goes to stdout so the rows can be reviewed before they are
pasted into the manuscript.

Usage (from any directory):

    python3 report/scripts/fill_tables.py
    python3 report/scripts/fill_tables.py runner/runs --model deepseek-flash
    python3 report/scripts/fill_tables.py runner/runs/dev_pilot_direct_independent \
        runner/runs/dev_pilot_direct_pairs \
        runner/runs/dev_pilot_few-shot_independent \
        runner/runs/dev_pilot_few-shot_pairs \
        runner/runs/dev_pilot_context_independent \
        runner/runs/dev_pilot_context_pairs \
        --model deepseek-v4.1-flash --validate-only

Expected run layout is whatever the runner writes:

    <run-dir>/manifest.json
    <run-dir>/metrics.json
    <run-dir>/results.jsonl

The formal table mode expects the frozen test split: independent 160 functions
(128 vulnerable + 32 non-vulnerable); pairs 180 pairs / 360 functions. The
repair table is merged across the two datasets: structural rates use
128 + 180 = 308 vulnerable versions, while reference-match rates use the 180
paired vulnerable versions.

Cost aggregation reads each run's results.jsonl and splits records by the
record-level task field. Do not use metrics.json's aggregate usage for the
per-task cost table: metrics.json aggregates across detection and repair. A
cost total is emitted only when every expected record is present and every
record has a numeric response.cost.cost_usd. OpenCode's usage.opencode.allowance
is a Go-plan quota, not a USD cost; it is reported separately and is never
added to cost_usd.

`--validate-only` prints a JSON summary and never emits formal LaTeX rows. It is
meant for pilot/partial runs: scope costs may be visible, but
formal_table_eligible is false whenever a run is partial or does not match the
frozen test counts. `--json` prints the same JSON in formal mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
DATASETS = {
    "independent": ROOT / "splits" / "test_detection_160.json",
    "pairs": ROOT / "splits" / "test_pairs_180.json",
}
EXPECTED = {
    "independent": {"detection": 160, "repair": 128},
    "pairs": {"detection": 360, "repair": 180, "pairs": 180},
}
STRATEGIES = ("direct", "few-shot", "context")
STRATEGY_LABELS = {
    "direct": "M1 零样本直接判定",
    "few-shot": "M2 固定少样本",
    "context": "M3 上下文增强",
}
TOTAL_EVALUATION_UNITS = 340  # 160 independent functions + 180 pairs


class TableError(RuntimeError):
    """Raised when the artifacts cannot support a complete table."""


@dataclass
class Run:
    path: Path
    manifest: dict[str, Any]
    metrics: dict[str, Any]
    results: list[dict[str, Any]]
    results_path: Path | None

    @property
    def dataset(self) -> str:
        return str(self.metrics["run"]["dataset_type"])

    @property
    def strategy(self) -> str:
        return str(self.metrics["run"]["strategy"])

    @property
    def task(self) -> str:
        return str(self.metrics["run"]["task"])

    @property
    def partial(self) -> bool:
        return bool(self.metrics["run"].get("partial"))

    @property
    def expected_by_task(self) -> dict[str, Any]:
        value = self.metrics["run"].get("expected_by_task")
        return value if isinstance(value, dict) else {}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_results(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise TableError(f"{path}:{line_number}: invalid JSON: {error}") from error
            if not isinstance(record, dict):
                raise TableError(f"{path}:{line_number}: record is not an object")
            task = record.get("task")
            if task not in {"detection", "repair"}:
                raise TableError(f"{path}:{line_number}: unsupported task {task!r}")
            identity = str(record.get("sample_id", record.get("request_index", "")))
            key = (str(task), identity, str(record.get("side", "")))
            if key in seen:
                raise TableError(
                    f"{path}:{line_number}: duplicate record for task={key[0]} "
                    f"sample_id={key[1]} side={key[2]}"
                )
            seen.add(key)
            records.append(record)
    return records


def load_run(
    path: Path,
    *,
    allow_partial: bool = False,
    require_results: bool = False,
) -> Run:
    manifest_path = path / "manifest.json"
    metrics_path = path / "metrics.json"
    results_path = path / "results.jsonl"
    if not manifest_path.is_file() or not metrics_path.is_file():
        raise TableError(f"{path}: manifest.json or metrics.json is missing")
    if require_results and not results_path.is_file():
        raise TableError(f"{path}: results.jsonl is missing; cost cannot be aggregated")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    if metrics.get("schema_version") != 1:
        raise TableError(f"{path}: unsupported metrics schema {metrics.get('schema_version')!r}")
    dry_run = manifest.get("dry_run")
    if dry_run is None:
        dry_run = manifest.get("config", {}).get("dry_run")
    if dry_run is not False:
        raise TableError(f"{path}: manifest is not a real (non-dry-run) execution")
    if manifest.get("status") != "completed":
        raise TableError(f"{path}: manifest status is {manifest.get('status')!r}, not 'completed'")
    run = Run(
        path=path,
        manifest=manifest,
        metrics=metrics,
        results=load_results(results_path) if results_path.is_file() else [],
        results_path=results_path if results_path.is_file() else None,
    )
    if run.dataset not in DATASETS:
        raise TableError(f"{path}: unsupported dataset_type {run.dataset!r}")
    if run.strategy not in STRATEGIES:
        raise TableError(f"{path}: unsupported strategy {run.strategy!r}")
    if run.task not in {"detection", "repair", "both"}:
        raise TableError(f"{path}: unsupported task {run.task!r}")
    if not allow_partial:
        counts = metrics.get("counts") or {}
        if metrics["run"].get("partial") is not False:
            raise TableError(f"{path}: run is marked partial; a partial run cannot fill a table")
        if counts.get("complete_planned_requests") is not True:
            raise TableError(f"{path}: planned requests are incomplete")
        if counts.get("missing_requests") != 0:
            raise TableError(f"{path}: {counts.get('missing_requests')} requests are missing")
    return run


def collect(
    paths: Iterable[Path],
    model: str | None,
    *,
    allow_partial: bool = False,
    require_results: bool = False,
) -> list[Run]:
    found: list[Path] = []
    for path in paths:
        if (path / "metrics.json").is_file():
            found.append(path)
            continue
        if not path.is_dir():
            raise TableError(f"{path}: not a directory and not a run directory")
        found.extend(sorted(p.parent for p in path.rglob("metrics.json")))
    if not found:
        raise TableError(
            "no metrics.json found; nothing can be filled. Run the experiment first "
            "and do not substitute estimated values."
        )
    runs = [
        load_run(path, allow_partial=allow_partial, require_results=require_results)
        for path in found
    ]
    if model:
        runs = [run for run in runs if run.metrics["run"].get("model") == model]
        if not runs:
            raise TableError(f"no completed run matches --model {model!r}")
    models = {str(run.metrics["run"].get("model")) for run in runs}
    prompts = {str(run.metrics["run"].get("prompt_version")) for run in runs}
    if len(models) != 1:
        raise TableError(
            "runs use multiple models: " + ", ".join(sorted(models)) + "; pass --model"
        )
    if len(prompts) != 1:
        raise TableError(
            "runs use multiple prompt versions: " + ", ".join(sorted(prompts))
        )
    return runs


def validate_dataset_hashes(runs: list[Run]) -> None:
    for dataset, path in DATASETS.items():
        expected = sha256_file(path)
        for run in runs:
            if run.dataset != dataset:
                continue
            actual = run.metrics["run"].get("dataset_sha256")
            if actual != expected:
                raise TableError(
                    f"{run.path}: dataset SHA-256 does not match {path.name}; "
                    "the run used a different dataset snapshot"
                )


def group_runs(runs: list[Run]) -> dict[tuple[str, str], dict[str, Run]]:
    grouped: dict[tuple[str, str], dict[str, Run]] = {}
    for run in runs:
        bucket = grouped.setdefault((run.dataset, run.strategy), {})
        if run.task == "both":
            slots = ("detection", "repair")
        else:
            slots = (run.task,)
        for slot in slots:
            if slot in bucket:
                raise TableError(
                    f"duplicate {slot} run for dataset={run.dataset} strategy={run.strategy}: "
                    f"{bucket[slot].path} and {run.path}"
                )
            bucket[slot] = run
    missing = [
        f"{dataset}/{strategy}/{task}"
        for dataset in ("independent", "pairs")
        for strategy in STRATEGIES
        for task in ("detection", "repair")
        if task not in grouped.get((dataset, strategy), {})
    ]
    if missing:
        raise TableError("missing runs: " + ", ".join(missing))
    return grouped


def rate(value: Any, digits: int = 3) -> str:
    if value is None:
        return "---"
    return f"{float(value):.{digits}f}"


def pct(value: Any, digits: int = 1) -> str:
    if value is None:
        return "---"
    return f"{float(value) * 100.0:.{digits}f}"


def count(value: Any) -> str:
    if value is None:
        return "---"
    return str(int(value))


def f1_from_counts(tp: int, fp: int, fn: int) -> float | None:
    denominator = 2 * tp + fp + fn
    return None if denominator == 0 else 2 * tp / denominator


def macro_f1(confusion: dict[str, Any]) -> float | None:
    tp = int(confusion["tp"])
    fp = int(confusion["fp"])
    tn = int(confusion["tn"])
    fn = int(confusion["fn"])
    positive = f1_from_counts(tp, fp, fn)
    negative = f1_from_counts(tn, fn, fp)
    if positive is None or negative is None:
        return None
    return (positive + negative) / 2.0


def detection_block(run: Run) -> dict[str, Any]:
    block = run.metrics.get("detection")
    if not isinstance(block, dict):
        raise TableError(f"{run.path}: metrics.detection is missing")
    return block


def repair_block(run: Run) -> dict[str, Any]:
    block = run.metrics.get("repair")
    if not isinstance(block, dict):
        raise TableError(f"{run.path}: metrics.repair is missing")
    return block


def check_requested(run: Run, task: str) -> None:
    expected = EXPECTED[run.dataset][task]
    block = detection_block(run) if task == "detection" else repair_block(run)
    if int(block.get("requested", -1)) != expected:
        raise TableError(
            f"{run.path}: {task} requested {block.get('requested')}, expected {expected}"
        )


def table_independent(grouped: dict[tuple[str, str], dict[str, Run]]) -> list[str]:
    lines = [
        "% --- Table: tab:ind-results (D_ind detection, valid-only) ---",
    ]
    for strategy in STRATEGIES:
        run = grouped[("independent", strategy)]["detection"]
        check_requested(run, "detection")
        block = detection_block(run)
        counts = block["confusion"]
        metrics = block["metrics_valid_only"]
        lines.append(
            f"{STRATEGY_LABELS[strategy]} & {rate(metrics['precision'])} & "
            f"{rate(metrics['recall'])} & {rate(metrics['f1'])} & "
            f"{pct(metrics['accuracy'])} & {pct(metrics['specificity'])} & "
            f"{pct(metrics['balanced_accuracy'])} & {rate(metrics['mcc'])} & "
            f"{rate(macro_f1(counts))} & {pct(block['coverage'])}\\\\"
        )
    return lines


def table_pair_detection(grouped: dict[tuple[str, str], dict[str, Run]]) -> list[str]:
    lines = ["% --- Table: tab:pair-detection (D_pair detection, valid-only) ---"]
    for strategy in STRATEGIES:
        run = grouped[("pairs", strategy)]["detection"]
        check_requested(run, "detection")
        block = detection_block(run)
        metrics = block["metrics_valid_only"]
        by_label = block["by_label"]
        fixed_fpr = by_label["non_vulnerable"]["false_positive_rate"]
        fixed_specificity = None if fixed_fpr is None else 1.0 - float(fixed_fpr)
        vulnerable_recall = by_label["vulnerable"]["detection_rate"]
        precision = metrics["precision"]
        f1 = (
            None
            if precision is None or vulnerable_recall is None or (precision + vulnerable_recall) == 0
            else 2 * precision * vulnerable_recall / (precision + vulnerable_recall)
        )
        lines.append(
            f"{STRATEGY_LABELS[strategy]} & {rate(precision)} & {rate(vulnerable_recall)} & "
            f"{rate(f1)} & {pct(fixed_specificity)} & {pct(fixed_specificity)} & "
            f"{pct(metrics['accuracy'])} & {pct(block['coverage'])}\\\\"
        )
    return lines


def table_pair_joint(grouped: dict[tuple[str, str], dict[str, Run]]) -> list[str]:
    lines = ["% --- Table: tab:pair-joint (D_pair joint discrimination) ---"]
    for strategy in STRATEGIES:
        run = grouped[("pairs", strategy)]["detection"]
        block = run.metrics.get("pair_joint")
        if not isinstance(block, dict):
            raise TableError(f"{run.path}: metrics.pair_joint is missing")
        if int(block.get("pairs_requested", -1)) != EXPECTED["pairs"]["pairs"]:
            raise TableError(f"{run.path}: pair_joint pairs_requested is not 180")
        categories = block["joint_categories"]
        lines.append(
            f"{STRATEGY_LABELS[strategy]} & {count(categories['vulnerable_detected_fixed_clean'])} & "
            f"{count(categories['both_flagged'])} & {count(categories['both_clean'])} & "
            f"{count(categories['vulnerable_missed_fixed_flagged'])} & "
            f"{rate(block['discrimination_accuracy_valid_pairs'])} & "
            f"{rate(block['discrimination_accuracy_all_pairs'])} & "
            f"{count(block['valid_pairs'])}/{count(block['pairs_requested'])} "
            f"({pct(block['coverage'])})\\\\"
        )
    return lines


def table_repair(grouped: dict[tuple[str, str], dict[str, Run]]) -> list[str]:
    lines = [
        "% --- Table: tab:repair (repair structural proxies; merged 308 vulnerable versions) ---",
    ]
    merged: dict[str, dict[str, int]] = {}
    for strategy in STRATEGIES:
        independent = repair_block(grouped[("independent", strategy)]["repair"])
        pairs = repair_block(grouped[("pairs", strategy)]["repair"])
        check_requested(grouped[("independent", strategy)]["repair"], "repair")
        check_requested(grouped[("pairs", strategy)]["repair"], "repair")
        fields = (
            "requested",
            "schema_valid",
            "complete_function",
            "changed_from_input",
            "complete_and_changed",
            "reference_fixed_available",
            "exact_match_reference_fixed",
            "whitespace_collapsed_match_reference_fixed",
        )
        combined = {field: 0 for field in fields}
        for block in (independent, pairs):
            for field in fields:
                value = block.get(field)
                if not isinstance(value, int):
                    raise TableError(
                        f"{strategy}: repair field {field!r} is missing; cannot aggregate"
                    )
                combined[field] += value
        if combined["requested"] != 308:
            raise TableError(f"{strategy}: merged repair requested is not 308")
        combined["reference_fixed_denominator"] = pairs["requested"]
        merged[strategy] = combined

    for strategy in STRATEGIES:
        combined = merged[strategy]
        schema = combined["schema_valid"] / combined["requested"]
        complete = (
            combined["complete_function"] / combined["schema_valid"]
            if combined["schema_valid"]
            else None
        )
        changed = (
            combined["changed_from_input"] / combined["schema_valid"]
            if combined["schema_valid"]
            else None
        )
        both = (
            combined["complete_and_changed"] / combined["schema_valid"]
            if combined["schema_valid"]
            else None
        )
        exact = (
            combined["exact_match_reference_fixed"] / combined["reference_fixed_denominator"]
            if combined["reference_fixed_denominator"]
            else None
        )
        collapsed = (
            combined["whitespace_collapsed_match_reference_fixed"]
            / combined["reference_fixed_denominator"]
            if combined["reference_fixed_denominator"]
            else None
        )
        lines.append(
            f"{STRATEGY_LABELS[strategy]} & {pct(schema)} & {pct(complete)} & "
            f"{pct(changed)} & {pct(both)} & {pct(exact)} & {pct(collapsed)} & "
            f"{count(combined['reference_fixed_denominator'])}\\\\"
        )
    return lines


# --------------------------------------------------------------------------- #
# Cost aggregation from results.jsonl (split by record-level task)
# --------------------------------------------------------------------------- #

def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _value_at(record: dict[str, Any], *path: str) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _percentile(values: list[float], fraction: float) -> float | None:
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


def _all_sum(values: list[Any], expected: int) -> tuple[float | None, int]:
    """Return a sum only when every expected record has a numeric value."""
    numeric = [float(value) for value in values if _number(value) is not None]
    known = len(numeric)
    if expected <= 0 or known != expected:
        return None, known
    return sum(numeric), known


def _latency_values(records: list[dict[str, Any]]) -> list[float]:
    values: list[float] = []
    for record in records:
        value = _number(_value_at(record, "response", "request_latency_seconds"))
        if value is not None:
            values.append(float(value))
    return values


def task_stats(run: Run, task: str) -> dict[str, Any]:
    records = [record for record in run.results if record.get("task") == task]
    expected_value = run.expected_by_task.get(task)
    expected_known = isinstance(expected_value, int) and not isinstance(expected_value, bool)
    expected = int(expected_value) if expected_known else len(records)
    if expected_known and len(records) > expected:
        raise TableError(
            f"{run.path}: task={task} has {len(records)} records but expected {expected}"
        )
    recorded = len(records)
    missing = max(expected - recorded, 0) if expected_known else 0
    statuses = [str(record.get("status")) for record in records]
    ok = statuses.count("ok")
    schema_invalid = statuses.count("invalid")
    api_errors = statuses.count("error")
    other = recorded - ok - schema_invalid - api_errors

    prompt_tokens = [_value_at(record, "response", "usage", "prompt_tokens") for record in records]
    completion_tokens = [
        _value_at(record, "response", "usage", "completion_tokens") for record in records
    ]
    cached_tokens = [
        _value_at(record, "response", "usage", "prompt_tokens_details", "cached_tokens")
        for record in records
    ]
    costs = [_value_at(record, "response", "cost", "cost_usd") for record in records]
    allowances = [_value_at(record, "response", "usage", "opencode", "allowance") for record in records]
    latencies = _latency_values(records)

    complete = expected_known and recorded == expected
    prompt_sum, prompt_known = _all_sum(prompt_tokens, recorded)
    completion_sum, completion_known = _all_sum(completion_tokens, recorded)
    cached_sum, cached_known = _all_sum(cached_tokens, recorded)
    cost_sum, cost_known_count = _all_sum(costs, recorded)
    allowance_sum, allowance_known_count = _all_sum(allowances, recorded)

    usage_complete = complete and prompt_known == recorded and completion_known == recorded
    cached_complete = complete and cached_known == recorded
    cost_complete = complete and cost_known_count == recorded and recorded > 0
    allowance_complete = complete and allowance_known_count == recorded and recorded > 0
    latency_complete = complete and len(latencies) == recorded and recorded > 0

    denominator = expected if expected_known and expected > 0 else recorded
    schema_invalid_rate = schema_invalid / denominator if denominator else None
    api_error_rate = api_errors / denominator if denominator else None
    combined_invalid_rate = (
        (schema_invalid + api_errors) / denominator if denominator else None
    )

    formal_expected = EXPECTED[run.dataset].get(task)
    formal_complete = bool(
        complete
        and formal_expected is not None
        and expected == formal_expected
        and not run.partial
    )
    return {
        "dataset": run.dataset,
        "task": task,
        "path": str(run.path),
        "partial": run.partial,
        "expected": expected,
        "expected_known": expected_known,
        "formal_expected": formal_expected,
        "recorded": recorded,
        "missing": missing,
        "ok": ok,
        "schema_invalid": schema_invalid,
        "api_errors": api_errors,
        "other_status": other,
        "complete": complete,
        "formal_complete": formal_complete,
        "usage_complete": usage_complete,
        "cached_complete": cached_complete,
        "cost_complete": cost_complete,
        "allowance_complete": allowance_complete,
        "latency_complete": latency_complete,
        "prompt_tokens": prompt_sum if usage_complete else None,
        "completion_tokens": completion_sum if usage_complete else None,
        "cached_tokens": cached_sum if cached_complete else None,
        "prompt_tokens_known": prompt_known,
        "completion_tokens_known": completion_known,
        "cached_tokens_known": cached_known,
        "cost_usd": cost_sum if cost_complete else None,
        "cost_records": cost_known_count,
        "cost_unknown_records": recorded - cost_known_count,
        "allowance_quota_usd": allowance_sum if allowance_complete else None,
        "allowance_records": allowance_known_count,
        "allowance_unknown_records": recorded - allowance_known_count,
        "latency_p50": _percentile(latencies, 0.50),
        "latency_p95": _percentile(latencies, 0.95),
        "latency_records": len(latencies),
        "latency_unknown_records": recorded - len(latencies),
        "prompt_unknown_records": recorded - prompt_known,
        "completion_unknown_records": recorded - completion_known,
        "cached_unknown_records": recorded - cached_known,
        "_latencies": latencies,
        "schema_invalid_rate": schema_invalid_rate,
        "api_error_rate": api_error_rate,
        "combined_invalid_rate": combined_invalid_rate,
    }


def task_stats_for_run(run: Run) -> dict[str, dict[str, Any]]:
    tasks = ("detection", "repair") if run.task == "both" else (run.task,)
    return {task: task_stats(run, task) for task in tasks}


def aggregate_task(stats: list[dict[str, Any]], task: str) -> dict[str, Any] | None:
    if not stats:
        return None
    expected = sum(int(stat["expected"]) for stat in stats)
    recorded = sum(int(stat["recorded"]) for stat in stats)
    missing = sum(int(stat["missing"]) for stat in stats)
    ok = sum(int(stat["ok"]) for stat in stats)
    schema_invalid = sum(int(stat["schema_invalid"]) for stat in stats)
    api_errors = sum(int(stat["api_errors"]) for stat in stats)
    complete = all(bool(stat["complete"]) for stat in stats)
    formal_complete = len(stats) == 2 and all(bool(stat["formal_complete"]) for stat in stats)
    usage_complete = complete and all(bool(stat["usage_complete"]) for stat in stats)
    cached_complete = complete and all(bool(stat["cached_complete"]) for stat in stats)
    cost_complete = complete and all(bool(stat["cost_complete"]) for stat in stats)
    allowance_complete = complete and all(bool(stat["allowance_complete"]) for stat in stats)
    latency_complete = complete and all(bool(stat["latency_complete"]) for stat in stats)

    def _sum(key: str, allowed: bool) -> float | None:
        if not allowed:
            return None
        values = [stat.get(key) for stat in stats]
        if any(_number(value) is None for value in values):
            return None
        return sum(float(value) for value in values)

    latencies: list[float] = []
    for stat in stats:
        values = stat.get("_latencies")
        if isinstance(values, list):
            latencies.extend(float(value) for value in values)
    denominator = expected if expected > 0 else recorded
    return {
        "task": task,
        "datasets": [stat["dataset"] for stat in stats],
        "expected": expected,
        "recorded": recorded,
        "missing": missing,
        "ok": ok,
        "schema_invalid": schema_invalid,
        "api_errors": api_errors,
        "complete": complete,
        "formal_complete": formal_complete,
        "usage_complete": usage_complete,
        "cached_complete": cached_complete,
        "cost_complete": cost_complete,
        "allowance_complete": allowance_complete,
        "latency_complete": latency_complete,
        "prompt_tokens": _sum("prompt_tokens", usage_complete),
        "completion_tokens": _sum("completion_tokens", usage_complete),
        "cached_tokens": _sum("cached_tokens", cached_complete),
        "cost_usd": _sum("cost_usd", cost_complete),
        "allowance_quota_usd": _sum("allowance_quota_usd", allowance_complete),
        "cost_unknown_records": sum(int(stat["cost_unknown_records"]) for stat in stats),
        "allowance_unknown_records": sum(int(stat["allowance_unknown_records"]) for stat in stats),
        "latency_unknown_records": sum(int(stat["latency_unknown_records"]) for stat in stats),
        "latency_p50": _percentile(latencies, 0.50) if latencies else None,
        "latency_p95": _percentile(latencies, 0.95) if latencies else None,
        "latency_records": sum(int(stat["latency_records"]) for stat in stats),
        "_latencies": latencies,
        "schema_invalid_rate": schema_invalid / denominator if denominator else None,
        "api_error_rate": api_errors / denominator if denominator else None,
        "combined_invalid_rate": (schema_invalid + api_errors) / denominator if denominator else None,
    }


def aggregate_strategy(detection: dict[str, Any] | None, repair: dict[str, Any] | None) -> dict[str, Any]:
    if detection is None or repair is None:
        return {
            "complete": False,
            "formal_complete": False,
            "cost_complete": False,
            "allowance_complete": False,
            "latency_complete": False,
            "observed_cost_usd": None,
            "cost_usd": None,
            "observed_allowance_quota_usd": None,
            "allowance_quota_usd": None,
            "per_100_usd": None,
            "latency_p50": None,
            "latency_p95": None,
            "schema_invalid": 0,
            "api_errors": 0,
            "cost_unknown_records": 0,
            "allowance_unknown_records": 0,
            "latency_unknown_records": 0,
        }
    complete = bool(detection["complete"] and repair["complete"])
    formal_complete = bool(detection["formal_complete"] and repair["formal_complete"])
    cost_complete = bool(detection["cost_complete"] and repair["cost_complete"])
    allowance_complete = bool(detection["allowance_complete"] and repair["allowance_complete"])
    latency_complete = bool(detection["latency_complete"] and repair["latency_complete"])
    expected = int(detection["expected"]) + int(repair["expected"])
    recorded = int(detection["recorded"]) + int(repair["recorded"])
    schema_invalid = int(detection["schema_invalid"]) + int(repair["schema_invalid"])
    api_errors = int(detection["api_errors"]) + int(repair["api_errors"])
    cost = None
    if cost_complete and complete:
        cost = float(detection["cost_usd"]) + float(repair["cost_usd"])
    allowance = None
    if allowance_complete and complete:
        allowance = float(detection["allowance_quota_usd"]) + float(repair["allowance_quota_usd"])
    prompt = None
    completion = None
    cached = None
    if complete and detection["usage_complete"] and repair["usage_complete"]:
        prompt = float(detection["prompt_tokens"]) + float(repair["prompt_tokens"])
        completion = float(detection["completion_tokens"]) + float(repair["completion_tokens"])
    if complete and detection["cached_complete"] and repair["cached_complete"]:
        cached = float(detection["cached_tokens"]) + float(repair["cached_tokens"])
    latencies = list(detection.get("_latencies", [])) + list(repair.get("_latencies", []))
    denominator = expected if expected else recorded
    return {
        "complete": complete,
        "formal_complete": formal_complete,
        "cost_complete": cost_complete,
        "allowance_complete": allowance_complete,
        "latency_complete": latency_complete,
        "expected": expected,
        "recorded": recorded,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "cached_tokens": cached,
        "observed_cost_usd": cost,
        "cost_usd": cost if formal_complete else None,
        "observed_allowance_quota_usd": allowance,
        "allowance_quota_usd": allowance if formal_complete else None,
        "per_100_usd": (cost / TOTAL_EVALUATION_UNITS * 100.0)
        if (formal_complete and cost is not None)
        else None,
        "latency_p50": _percentile(latencies, 0.50) if latencies else None,
        "latency_p95": _percentile(latencies, 0.95) if latencies else None,
        "latency_records": len(latencies),
        "schema_invalid_rate": (schema_invalid / denominator) if denominator else None,
        "api_error_rate": (api_errors / denominator) if denominator else None,
        "combined_invalid_rate": ((schema_invalid + api_errors) / denominator)
        if denominator
        else None,
        "schema_invalid": schema_invalid,
        "api_errors": api_errors,
        "cost_unknown_records": int(detection.get("cost_unknown_records", 0))
        + int(repair.get("cost_unknown_records", 0)),
        "allowance_unknown_records": int(detection.get("allowance_unknown_records", 0))
        + int(repair.get("allowance_unknown_records", 0)),
        "latency_unknown_records": int(detection.get("latency_unknown_records", 0))
        + int(repair.get("latency_unknown_records", 0)),
    }


def _public(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def build_cost_summary(runs: list[Run], mode: str) -> dict[str, Any]:
    by_task_dataset: dict[tuple[str, str, str], dict[str, Any]] = {}
    reasons: list[str] = []
    for run in runs:
        for task, stats in task_stats_for_run(run).items():
            key = (run.strategy, task, run.dataset)
            if key in by_task_dataset:
                raise TableError(
                    f"duplicate cost task {run.strategy}/{task}/{run.dataset}: "
                    f"{by_task_dataset[key]['path']} and {run.path}"
                )
            by_task_dataset[key] = stats

    strategies: dict[str, Any] = {}
    for strategy in STRATEGIES:
        task_aggregates: dict[str, Any] = {}
        for task in ("detection", "repair"):
            stats = [
                by_task_dataset[(strategy, task, dataset)]
                for dataset in ("independent", "pairs")
                if (strategy, task, dataset) in by_task_dataset
            ]
            task_aggregates[task] = aggregate_task(stats, task) if stats else None
        total = aggregate_strategy(task_aggregates["detection"], task_aggregates["repair"])
        strategies[strategy] = {
            "detection": task_aggregates["detection"],
            "repair": task_aggregates["repair"],
            "total": total,
        }
        if not total.get("formal_complete"):
            reasons.append(f"{strategy}: runs are not a complete frozen-test slice")

    formal_eligible = all(
        bool(strategies[strategy]["total"].get("formal_complete"))
        for strategy in STRATEGIES
    )
    return _public(
        {
            "schema_version": 1,
            "mode": mode,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "formal_table_eligible": formal_eligible,
            "reasons": reasons,
            "model": runs[0].metrics["run"].get("model") if runs else None,
            "prompt_version": runs[0].metrics["run"].get("prompt_version") if runs else None,
            "strategies": strategies,
            "runs": [
                {
                    "path": str(run.path),
                    "dataset": run.dataset,
                    "strategy": run.strategy,
                    "task": run.task,
                    "partial": run.partial,
                    "model": run.metrics["run"].get("model"),
                    "prompt_version": run.metrics["run"].get("prompt_version"),
                    "expected_by_task": run.expected_by_task,
                    "tasks": task_stats_for_run(run),
                }
                for run in runs
            ],
        }
    )


def _cost_token_pair(block: dict[str, Any] | None) -> str:
    if not block or block.get("prompt_tokens") is None or block.get("completion_tokens") is None:
        return "---"
    return f"{int(block['prompt_tokens'])}/{int(block['completion_tokens'])}"


def cost_rows(grouped: dict[tuple[str, str], dict[str, Run]]) -> list[str]:
    runs: dict[Path, Run] = {}
    for (dataset, strategy), bucket in grouped.items():
        for run in bucket.values():
            runs[run.path] = run
    summary = build_cost_summary(list(runs.values()), mode="formal")
    lines = [
        "% --- Table: tab:cost (from results.jsonl, task-level aggregation) ---",
        "% cost_usd comes from response.cost.cost_usd; allowance is usage.opencode.allowance",
        "% (Go-plan quota, NOT USD cost and not included in cost_usd).",
        "% The table's 无效率 column is schema-invalid/API-error percentages.",
    ]
    for strategy in STRATEGIES:
        block = summary["strategies"][strategy]
        total = block["total"]
        detection = block["detection"]
        repair = block["repair"]
        if not total.get("formal_complete"):
            lines.append(
                f"% {STRATEGY_LABELS[strategy]}: no formal cost row; "
                + " / ".join(summary["reasons"])
            )
            continue
        cost = total.get("cost_usd")
        per_100 = total.get("per_100_usd")
        p50 = total.get("latency_p50") if total.get("latency_complete") else None
        p95 = total.get("latency_p95") if total.get("latency_complete") else None
        schema_rate = total.get("schema_invalid_rate")
        api_rate = total.get("api_error_rate")
        allowance = total.get("allowance_quota_usd")
        lines.append(
            f"{STRATEGY_LABELS[strategy]} & {_cost_token_pair(detection)} & "
            f"{_cost_token_pair(repair)} & "
            f"{'---' if cost is None else f'{cost:.6f}'} & "
            f"{'---' if per_100 is None else f'{per_100:.4f}'} & "
            f"{'---' if p50 is None else f'{p50:.2f}'} & "
            f"{'---' if p95 is None else f'{p95:.2f}'} & "
            f"{'---' if schema_rate is None or api_rate is None else f'{schema_rate * 100:.1f}/{api_rate * 100:.1f}'}\\\\"
        )
        lines.append(
            f"% {STRATEGY_LABELS[strategy]} allowance_quota_usd="
            f"{'null' if allowance is None else f'{allowance:.6f}'} (not cost_usd)"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[ROOT / "runner" / "runs"],
        help="run directories or a root to scan (default: runner/runs)",
    )
    parser.add_argument("--model", help="only use completed runs with this model id")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="read partial/pilot runs, print JSON, and never emit formal table rows",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the cost summary JSON instead of LaTeX rows (formal mode)",
    )
    args = parser.parse_args(argv)

    try:
        if args.validate_only:
            runs = collect(
                args.paths,
                args.model,
                allow_partial=True,
                require_results=True,
            )
            summary = build_cost_summary(runs, mode="validate")
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0

        runs = collect(args.paths, args.model, require_results=True)
        validate_dataset_hashes(runs)
        grouped = group_runs(runs)
        summary = build_cost_summary(runs, mode="formal")
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0
        blocks = [
            *table_independent(grouped),
            "",
            *table_pair_detection(grouped),
            "",
            *table_pair_joint(grouped),
            "",
            *table_repair(grouped),
            "",
            *cost_rows(grouped),
        ]
    except TableError as error:
        print(f"fill_tables: {error}", file=sys.stderr)
        return 1

    print("\n".join(blocks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

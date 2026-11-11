"""Detection, paired joint, repair, usage, latency, and cost metrics."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable

from .datasets import LoadedDataset, PairRecord
from .validation import collapse_whitespace, normalize_code

METRICS_SCHEMA_VERSION = 1


def _rate(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if numerator is None or denominator is None or denominator == 0:
        return None
    return float(numerator) / float(denominator)


def _percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _sum_known(values: Iterable[int | None]) -> int | None:
    known = [value for value in values if isinstance(value, int) and not isinstance(value, bool)]
    return sum(known) if known else None


def _usage_for(record: dict[str, Any]) -> dict[str, Any] | None:
    usage = record.get("response", {}).get("usage")
    return usage if isinstance(usage, dict) else None


def _prompt_tokens(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    value = usage.get("prompt_tokens", usage.get("input_tokens"))
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _completion_tokens(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    value = usage.get("completion_tokens", usage.get("output_tokens"))
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _cached_tokens(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    value = usage.get("prompt_cache_hit_tokens", usage.get("cache_read_input_tokens"))
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    details = usage.get("prompt_tokens_details")
    if isinstance(details, dict):
        value = details.get("cached_tokens")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _reasoning_tokens(usage: dict[str, Any] | None) -> int | None:
    if not usage:
        return None
    details = usage.get("completion_tokens_details")
    if isinstance(details, dict):
        value = details.get("reasoning_tokens")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _opencode_usage(usage: dict[str, Any] | None) -> dict[str, Any] | None:
    if not usage:
        return None
    value = usage.get("opencode")
    return value if isinstance(value, dict) else None


def _opencode_allowance(usage: dict[str, Any] | None) -> float | None:
    opencode = _opencode_usage(usage)
    if not opencode:
        return None
    value = opencode.get("allowance")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value >= 0 else None


def _opencode_billing_source(usage: dict[str, Any] | None) -> str | None:
    opencode = _opencode_usage(usage)
    if not opencode:
        return None
    value = opencode.get("billing_source")
    return value if isinstance(value, str) and value else None


def _cost_usd(record: dict[str, Any]) -> float | None:
    cost = record.get("response", {}).get("cost")
    if not isinstance(cost, dict):
        return None
    value = cost.get("cost_usd")
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _detection_block(records: list[dict[str, Any]], dataset: LoadedDataset) -> dict[str, Any]:
    valid_records = [
        record
        for record in records
        if record.get("status") == "ok"
        and isinstance(record.get("parsed"), dict)
        and isinstance(record["parsed"].get("is_vulnerable"), bool)
    ]
    tp = fp = tn = fn = 0
    for record in valid_records:
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
    invalid = sum(1 for record in records if record.get("status") == "invalid")
    api_errors = sum(1 for record in records if record.get("status") == "error")
    total = len(records)
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    specificity = _rate(tn, tn + fp)
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    accuracy = _rate(tp + tn, tp + fp + tn + fn)
    balanced = (
        (recall + specificity) / 2.0
        if recall is not None and specificity is not None
        else None
    )
    mcc_denominator = math.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    mcc = ((tp * tn) - (fp * fn)) / mcc_denominator if mcc_denominator else None
    confidence_values = [
        float(record["parsed"]["confidence"])
        for record in valid_records
        if isinstance(record["parsed"].get("confidence"), (int, float))
        and not isinstance(record["parsed"].get("confidence"), bool)
    ]

    by_label: dict[str, Any] = {}
    for label, name in ((True, "vulnerable"), (False, "non_vulnerable")):
        subset = [record for record in records if bool(record["label"]) is label]
        subset_valid = [
            record
            for record in subset
            if record.get("status") == "ok"
            and isinstance(record.get("parsed"), dict)
            and isinstance(record["parsed"].get("is_vulnerable"), bool)
        ]
        predicted = sum(1 for record in subset_valid if record["parsed"]["is_vulnerable"])
        by_label[name] = {
            "requested": len(subset),
            "valid_predictions": len(subset_valid),
            "schema_invalid": sum(1 for record in subset if record.get("status") == "invalid"),
            "api_errors": sum(1 for record in subset if record.get("status") == "error"),
            "predicted_vulnerable": predicted,
            "predicted_vulnerable_rate": _rate(predicted, len(subset_valid)),
            "detection_rate": _rate(predicted, len(subset_valid)) if label else None,
            "false_positive_rate": _rate(predicted, len(subset_valid)) if not label else None,
        }

    by_side: dict[str, Any] = {}
    if dataset.is_pairs:
        for side in ("vulnerable", "fixed"):
            subset = [record for record in records if record.get("side") == side]
            subset_valid = [
                record
                for record in subset
                if record.get("status") == "ok"
                and isinstance(record.get("parsed"), dict)
                and isinstance(record["parsed"].get("is_vulnerable"), bool)
            ]
            predicted = sum(1 for record in subset_valid if record["parsed"]["is_vulnerable"])
            by_side[side] = {
                "requested": len(subset),
                "valid_predictions": len(subset_valid),
                "schema_invalid": sum(1 for record in subset if record.get("status") == "invalid"),
                "api_errors": sum(1 for record in subset if record.get("status") == "error"),
                "predicted_vulnerable": predicted,
                "predicted_vulnerable_rate": _rate(predicted, len(subset_valid)),
            }

    return {
        "requested": total,
        "valid_predictions": len(valid_records),
        "schema_invalid": invalid,
        "api_errors": api_errors,
        "coverage": _rate(len(valid_records), total),
        "invalid_rate": _rate(invalid, total),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics_valid_only": {
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            "f1": f1,
            "accuracy": accuracy,
            "balanced_accuracy": balanced,
            "mcc": mcc,
            "predicted_positive_rate": _rate(tp + fp, len(valid_records)),
        },
        "strict_accuracy_all_samples": _rate(tp + tn, total),
        "strict_correct_all_samples": tp + tn,
        "average_confidence": round(sum(confidence_values) / len(confidence_values), 12)
        if confidence_values
        else None,
        "by_label": by_label,
        "by_side": by_side,
    }


def _pair_joint_block(
    records: list[dict[str, Any]],
    dataset: LoadedDataset,
) -> dict[str, Any] | None:
    if not dataset.is_pairs:
        return None
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if record.get("task") != "detection" or not record.get("pair_id") or not record.get("side"):
            continue
        by_key[(str(record["pair_id"]), str(record["side"]))] = record

    categories = Counter(
        {
            "vulnerable_detected_fixed_clean": 0,
            "both_flagged": 0,
            "both_clean": 0,
            "vulnerable_missed_fixed_flagged": 0,
        }
    )
    matrix = {
        "vulnerable_side_predicted_vulnerable": {
            "fixed_side_predicted_vulnerable": 0,
            "fixed_side_predicted_clean": 0,
        },
        "vulnerable_side_predicted_clean": {
            "fixed_side_predicted_vulnerable": 0,
            "fixed_side_predicted_clean": 0,
        },
    }
    pair_count = 0
    valid_pairs = 0
    invalid_pairs = 0
    for unit in dataset.units:
        if not isinstance(unit, PairRecord):
            continue
        pair_count += 1
        vuln_record = by_key.get((unit.pair_id, "vulnerable"))
        fixed_record = by_key.get((unit.pair_id, "fixed"))
        if not vuln_record or not fixed_record:
            invalid_pairs += 1
            continue
        if vuln_record.get("status") != "ok" or fixed_record.get("status") != "ok":
            invalid_pairs += 1
            continue
        if not isinstance(vuln_record.get("parsed"), dict) or not isinstance(fixed_record.get("parsed"), dict):
            invalid_pairs += 1
            continue
        vuln_pred = vuln_record["parsed"]["is_vulnerable"]
        fixed_pred = fixed_record["parsed"]["is_vulnerable"]
        valid_pairs += 1
        if vuln_pred and not fixed_pred:
            categories["vulnerable_detected_fixed_clean"] += 1
            matrix["vulnerable_side_predicted_vulnerable"]["fixed_side_predicted_clean"] += 1
        elif vuln_pred and fixed_pred:
            categories["both_flagged"] += 1
            matrix["vulnerable_side_predicted_vulnerable"]["fixed_side_predicted_vulnerable"] += 1
        elif not vuln_pred and not fixed_pred:
            categories["both_clean"] += 1
            matrix["vulnerable_side_predicted_clean"]["fixed_side_predicted_clean"] += 1
        else:
            categories["vulnerable_missed_fixed_flagged"] += 1
            matrix["vulnerable_side_predicted_clean"]["fixed_side_predicted_vulnerable"] += 1

    ideal = categories["vulnerable_detected_fixed_clean"]
    return {
        "pairs_requested": pair_count,
        "valid_pairs": valid_pairs,
        "invalid_pairs": invalid_pairs,
        "coverage": _rate(valid_pairs, pair_count),
        "joint_categories": dict(categories),
        "joint_rates_valid_pairs": {
            key: _rate(value, valid_pairs) for key, value in categories.items()
        },
        "matrix": matrix,
        "discrimination_accuracy_valid_pairs": _rate(ideal, valid_pairs),
        "discrimination_accuracy_all_pairs": _rate(ideal, pair_count),
        "definition": (
            "A pair is handled correctly only when the vulnerable side is predicted vulnerable "
            "and its fixed side is predicted non-vulnerable."
        ),
    }


def _repair_block(
    records: list[dict[str, Any]],
    dataset: LoadedDataset,
) -> dict[str, Any] | None:
    if not records:
        return None
    schema_valid = [record for record in records if record.get("status") == "ok"]
    complete = [
        record
        for record in schema_valid
        if isinstance(record.get("validation"), dict)
        and record["validation"].get("complete_function") is True
    ]
    changed = [
        record
        for record in schema_valid
        if isinstance(record.get("validation"), dict)
        and record["validation"].get("changed_from_input") is True
    ]
    complete_and_changed = [
        record
        for record in complete
        if isinstance(record.get("validation"), dict)
        and record["validation"].get("changed_from_input") is True
    ]
    schema_invalid = sum(1 for record in records if record.get("status") == "invalid")
    api_errors = sum(1 for record in records if record.get("status") == "error")

    pair_fixed_by_id: dict[str, str] = {}
    if dataset.is_pairs:
        for unit in dataset.units:
            if isinstance(unit, PairRecord):
                pair_fixed_by_id[unit.pair_id] = unit.fixed.func_body

    reference_available = 0
    exact_matches = 0
    collapsed_matches = 0
    for record in schema_valid:
        pair_id = record.get("pair_id")
        if not pair_id or pair_id not in pair_fixed_by_id:
            continue
        parsed = record.get("parsed")
        if not isinstance(parsed, dict) or not isinstance(parsed.get("fixed_function"), str):
            continue
        reference_available += 1
        fixed = parsed["fixed_function"]
        reference = pair_fixed_by_id[pair_id]
        if normalize_code(fixed) == normalize_code(reference):
            exact_matches += 1
        if collapse_whitespace(fixed) == collapse_whitespace(reference):
            collapsed_matches += 1

    return {
        "requested": len(records),
        "schema_valid": len(schema_valid),
        "schema_invalid": schema_invalid,
        "api_errors": api_errors,
        "schema_valid_rate": _rate(len(schema_valid), len(records)),
        "complete_function": len(complete),
        "complete_function_rate_of_schema_valid": _rate(len(complete), len(schema_valid)),
        "complete_function_rate_of_all": _rate(len(complete), len(records)),
        "changed_from_input": len(changed),
        "changed_from_input_rate_of_schema_valid": _rate(len(changed), len(schema_valid)),
        "complete_and_changed": len(complete_and_changed),
        "complete_and_changed_rate_of_schema_valid": _rate(
            len(complete_and_changed), len(schema_valid)
        ),
        "reference_fixed_available": reference_available,
        "exact_match_reference_fixed": exact_matches,
        "exact_match_reference_fixed_rate": _rate(exact_matches, reference_available),
        "whitespace_collapsed_match_reference_fixed": collapsed_matches,
        "whitespace_collapsed_match_reference_fixed_rate": _rate(collapsed_matches, reference_available),
        "definition": (
            "complete_function and changed_from_input are structural proxies only. "
            "Reference matches use normalised text equality and are not a correctness or "
            "security-equivalence oracle."
        ),
    }


def _context_summary(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    used = [
        record
        for record in records
        if isinstance(record.get("prompt"), dict)
        and isinstance(record["prompt"].get("context"), dict)
        and record["prompt"]["context"].get("used") is True
    ]
    if not used:
        return None
    nonempty = sum(1 for record in used if record["prompt"]["context"].get("nonempty") is True)
    parse_failures = sum(1 for record in used if record["prompt"]["context"].get("parse_ok") is False)
    section_totals: Counter[str] = Counter()
    for record in used:
        sections = record["prompt"]["context"].get("section_item_counts")
        if isinstance(sections, dict):
            for key, value in sections.items():
                if isinstance(value, int) and not isinstance(value, bool):
                    section_totals[str(key)] += value
    return {
        "requests": len(used),
        "nonempty_requests": nonempty,
        "empty_requests": len(used) - nonempty,
        "parse_failures": parse_failures,
        "section_item_totals": dict(section_totals),
        "warning": (
            "Context availability itself may be correlated with the label in this dataset; "
            "report non-empty/empty subgroups rather than treating L3 as a pure prompt effect."
        ),
    }


def compute_metrics(
    dataset: LoadedDataset,
    records: list[dict[str, Any]],
    *,
    run_meta: dict[str, Any],
) -> dict[str, Any]:
    detection_records = [record for record in records if record.get("task") == "detection"]
    repair_records = [record for record in records if record.get("task") == "repair"]
    detection = _detection_block(detection_records, dataset) if detection_records else None
    pair_joint = _pair_joint_block(detection_records, dataset) if detection_records else None
    repair = _repair_block(repair_records, dataset) if repair_records else None

    status_counts = Counter(str(record.get("status")) for record in records)
    task_counts = Counter(str(record.get("task")) for record in records)
    expected_requests = int(run_meta.get("expected_requests", len(records)))
    missing = max(0, expected_requests - len(records))

    usage_prompt = [_prompt_tokens(_usage_for(record)) for record in records]
    usage_completion = [_completion_tokens(_usage_for(record)) for record in records]
    usage_cached = [_cached_tokens(_usage_for(record)) for record in records]
    usage_reasoning = [_reasoning_tokens(_usage_for(record)) for record in records]
    usage_missing = sum(1 for record in records if _usage_for(record) is None)
    opencode_allowances = [_opencode_allowance(_usage_for(record)) for record in records]
    known_allowances = [value for value in opencode_allowances if value is not None]
    opencode_usage_records = sum(
        1 for record in records if _opencode_usage(_usage_for(record)) is not None
    )
    opencode_billing_sources = Counter(
        source
        for source in (_opencode_billing_source(_usage_for(record)) for record in records)
        if source is not None
    )
    costs = [_cost_usd(record) for record in records]
    known_costs = [cost for cost in costs if cost is not None]
    pricing_configured = bool(run_meta.get("pricing_configured", False))
    total_cost = (
        sum(known_costs)
        if pricing_configured and len(known_costs) == len(costs) and costs
        else None
    )
    cost_bases = sorted(
        {
            str(record.get("response", {}).get("cost", {}).get("cost_basis"))
            for record in records
            if isinstance(record.get("response", {}).get("cost"), dict)
        }
    )

    request_latencies = [
        float(record["response"]["request_latency_seconds"])
        for record in records
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("request_latency_seconds"), (int, float))
        and not isinstance(record["response"].get("request_latency_seconds"), bool)
    ]
    wall_times = [
        float(record["response"]["wall_seconds"])
        for record in records
        if isinstance(record.get("response"), dict)
        and isinstance(record["response"].get("wall_seconds"), (int, float))
        and not isinstance(record["response"].get("wall_seconds"), bool)
    ]
    attempts = sum(
        len(record.get("response", {}).get("attempts", []))
        for record in records
        if isinstance(record.get("response", {}).get("attempts"), list)
    )
    retries = max(0, attempts - len(records))
    error_types = Counter(
        str(record.get("response", {}).get("error", {}).get("type"))
        for record in records
        if isinstance(record.get("response", {}).get("error"), dict)
        and record["response"]["error"].get("type")
    )
    invalid_errors = Counter(
        str(record.get("validation", {}).get("error", "unknown schema error"))
        for record in records
        if record.get("status") == "invalid"
    )
    failure_examples = [
        {
            "sample_id": record.get("sample_id"),
            "task": record.get("task"),
            "status": record.get("status"),
            "error": record.get("validation", {}).get("error")
            if record.get("status") == "invalid"
            else record.get("response", {}).get("error"),
        }
        for record in records
        if record.get("status") != "ok"
    ][:5]
    cache_hits = sum(1 for record in records if record.get("cache", {}).get("hit") is True)

    notes: list[str] = []
    if run_meta.get("partial"):
        notes.append(
            "PARTIAL RUN: --limit selected only part of the dataset. Do not report these values "
            "as full-dataset experimental results."
        )
    if missing:
        notes.append(
            f"INCOMPLETE: {missing} planned request(s) have no record; use --resume before "
            "interpreting metrics."
        )
    if detection and detection["valid_predictions"] == 0:
        notes.append("No valid detection predictions were recorded; all detection metrics are null or zero-coverage.")
    if repair_records and not any(record.get("status") == "ok" for record in repair_records):
        notes.append("No schema-valid repair responses were recorded; repair structural metrics are empty.")
    notes.append(
        "Detection confusion uses only schema-valid predictions. strict_accuracy_all_samples "
        "counts schema-invalid and API-error records as incorrect."
    )
    if repair_records:
        notes.append(
            "Repair scores are structural proxies (complete function and changed text); they do "
            "not prove that a vulnerability was removed or that behaviour was preserved."
        )
    if not pricing_configured:
        notes.append("Cost is null because no token prices were supplied; no official prices are hardcoded.")
    elif total_cost is None:
        notes.append("Cost is null because at least one request lacks a complete cost record.")
    if opencode_usage_records:
        notes.append(
            "usage.opencode from the provider is preserved in each record's usage. "
            "opencode.allowance is Go-plan usage in USD and is summed separately; it is never "
            "used as cost_usd. cost_usd still comes only from explicit price arguments."
        )

    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "run": run_meta,
        "counts": {
            "records": len(records),
            "by_task": dict(task_counts),
            "by_status": dict(status_counts),
            "expected_requests": expected_requests,
            "missing_requests": missing,
            "complete_planned_requests": missing == 0 and len(records) == expected_requests,
            "cache_hits": cache_hits,
            "api_attempts": attempts,
            "retries": retries,
        },
        "detection": detection,
        "pair_joint": pair_joint,
        "repair": repair,
        "context": _context_summary(records),
        "usage": {
            "prompt_tokens_known_sum": _sum_known(usage_prompt),
            "completion_tokens_known_sum": _sum_known(usage_completion),
            "cached_prompt_tokens_known_sum": _sum_known(usage_cached),
            "reasoning_tokens_known_sum": _sum_known(usage_reasoning),
            "total_tokens_known_sum": (
                (_sum_known(usage_prompt) or 0) + (_sum_known(usage_completion) or 0)
                if any(value is not None for value in usage_prompt + usage_completion)
                else None
            ),
            "records_missing_usage": usage_missing,
            "records_with_opencode_usage": opencode_usage_records,
            "opencode_allowance_known_sum_usd": (
                sum(known_allowances) if known_allowances else None
            ),
            "opencode_allowance_records": len(known_allowances),
            "opencode_billing_sources": dict(opencode_billing_sources),
        },
        "cost": {
            "currency": "USD",
            "pricing_configured": pricing_configured,
            "input_price_usd_per_1m": run_meta.get("input_price_usd_per_1m"),
            "output_price_usd_per_1m": run_meta.get("output_price_usd_per_1m"),
            "cached_input_price_usd_per_1m": run_meta.get("cached_input_price_usd_per_1m"),
            "total_cost_usd": total_cost,
            "known_cost_usd": sum(known_costs) if known_costs else None,
            "unknown_cost_records": len(costs) - len(known_costs),
            "cost_bases": cost_bases,
        },
        "latency": {
            "total_request_latency_seconds": sum(request_latencies),
            "mean_request_latency_seconds": (
                sum(request_latencies) / len(request_latencies) if request_latencies else None
            ),
            "p50_request_latency_seconds": _percentile(request_latencies, 0.50),
            "p95_request_latency_seconds": _percentile(request_latencies, 0.95),
            "max_request_latency_seconds": max(request_latencies) if request_latencies else None,
            "total_wall_seconds": sum(wall_times),
            "records_with_latency": len(request_latencies),
        },
        "failures": {
            "error_types": dict(error_types),
            "schema_invalid_reasons": dict(invalid_errors),
            "examples": failure_examples,
        },
        "notes": notes,
    }


def _format_number(value: Any, digits: int = 4) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _format_rate(value: float | None) -> str:
    if value is None:
        return "null"
    return f"{value:.4f} ({value * 100:.2f}%)"


def _format_cost(value: float | None) -> str:
    return "null" if value is None else f"${value:.6f}"


def render_markdown(metrics: dict[str, Any]) -> str:
    run = metrics["run"]
    counts = metrics["counts"]
    lines: list[str] = []
    lines.append(f"# SecVulEval run: {run.get('run_id', 'unknown')}")
    lines.append("")
    lines.append(f"- Dataset: `{run.get('dataset_type')}`")
    lines.append(f"- Strategy: `{run.get('strategy')}`")
    lines.append(f"- Task: `{run.get('task')}`")
    lines.append(f"- Model: `{run.get('model')}`")
    lines.append(f"- Endpoint: `{run.get('endpoint')}`")
    lines.append(f"- Prompt version: `{run.get('prompt_version')}`")
    lines.append(f"- Records: {counts['records']} / expected {counts['expected_requests']}")
    lines.append(f"- Cache hits: {counts['cache_hits']}; API attempts: {counts['api_attempts']}")
    lines.append("")
    if run.get("partial"):
        lines.append(
            "> **PARTIAL RUN.** `--limit` selected only part of the dataset. "
            "These values are not full-dataset experimental results."
        )
        lines.append("")
    if counts["missing_requests"]:
        lines.append(
            f"> **INCOMPLETE.** {counts['missing_requests']} planned request(s) have no record. "
            "Use `--resume` before interpreting metrics."
        )
        lines.append("")

    detection = metrics.get("detection")
    lines.append("## Detection")
    lines.append("")
    if not detection:
        lines.append("Not run.")
    else:
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Requested | {detection['requested']} |")
        lines.append(f"| Valid predictions | {detection['valid_predictions']} |")
        lines.append(f"| Schema invalid | {detection['schema_invalid']} |")
        lines.append(f"| API errors | {detection['api_errors']} |")
        lines.append(f"| Coverage | {_format_rate(detection['coverage'])} |")
        confusion = detection["confusion"]
        lines.append(
            f"| TP / FP / TN / FN | {confusion['tp']} / {confusion['fp']} / "
            f"{confusion['tn']} / {confusion['fn']} |"
        )
        for key, value in detection["metrics_valid_only"].items():
            rendered = _format_number(value) if key == "mcc" else _format_rate(value)
            lines.append(f"| {key} (valid only) | {rendered} |")
        lines.append(
            f"| strict accuracy (all samples) | {_format_rate(detection['strict_accuracy_all_samples'])} |"
        )
        lines.append("")
        lines.append("### Detection by label")
        lines.append("")
        lines.append("| Label | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for name, block in detection["by_label"].items():
            lines.append(
                f"| {name} | {block['requested']} | {block['valid_predictions']} | "
                f"{block['predicted_vulnerable']} | {_format_rate(block['predicted_vulnerable_rate'])} |"
            )
        if detection.get("by_side"):
            lines.append("")
            lines.append("### Detection by pair side")
            lines.append("")
            lines.append("| Side | Requested | Valid | Predicted vulnerable | Predicted-vulnerable rate |")
            lines.append("| --- | ---: | ---: | ---: | ---: |")
            for name, block in detection["by_side"].items():
                lines.append(
                    f"| {name} | {block['requested']} | {block['valid_predictions']} | "
                    f"{block['predicted_vulnerable']} | {_format_rate(block['predicted_vulnerable_rate'])} |"
                )

    pair_joint = metrics.get("pair_joint")
    context = metrics.get("context")
    if context:
        lines.append("")
        lines.append("## Context coverage")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Requests using context | {context['requests']} |")
        lines.append(f"| Non-empty context | {context['nonempty_requests']} |")
        lines.append(f"| Empty context | {context['empty_requests']} |")
        lines.append(f"| Context parse failures | {context['parse_failures']} |")
        lines.append("")
        lines.append(f"> {context['warning']}")
    lines.append("")
    lines.append("## Paired joint results")
    lines.append("")
    if not pair_joint:
        lines.append("Not available (requires the pairs dataset and detection task).")
    else:
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Pairs | {pair_joint['pairs_requested']} |")
        lines.append(f"| Valid pairs | {pair_joint['valid_pairs']} |")
        lines.append(f"| Coverage | {_format_rate(pair_joint['coverage'])} |")
        lines.append(
            f"| Discrimination accuracy (valid pairs) | "
            f"{_format_rate(pair_joint['discrimination_accuracy_valid_pairs'])} |"
        )
        lines.append(
            f"| Discrimination accuracy (all pairs) | "
            f"{_format_rate(pair_joint['discrimination_accuracy_all_pairs'])} |"
        )
        lines.append("")
        lines.append("| Joint category | Count | Share of valid pairs |")
        lines.append("| --- | ---: | ---: |")
        for key, value in pair_joint["joint_categories"].items():
            lines.append(
                f"| {key} | {value} | {_format_rate(pair_joint['joint_rates_valid_pairs'][key])} |"
            )
        lines.append("")
        lines.append(
            "Correct pair handling requires the vulnerable side to be flagged and the fixed side "
            "to be accepted; `both_flagged`, `both_clean`, and "
            "`vulnerable_missed_fixed_flagged` are all failures of pair discrimination."
        )

    repair = metrics.get("repair")
    lines.append("")
    lines.append("## Repair")
    lines.append("")
    if not repair:
        lines.append("Not run.")
    else:
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        for key in (
            "requested",
            "schema_valid",
            "schema_invalid",
            "api_errors",
            "complete_function",
            "changed_from_input",
            "complete_and_changed",
            "reference_fixed_available",
            "exact_match_reference_fixed",
            "whitespace_collapsed_match_reference_fixed",
        ):
            lines.append(f"| {key} | {repair[key]} |")
        for key in (
            "schema_valid_rate",
            "complete_function_rate_of_schema_valid",
            "complete_function_rate_of_all",
            "changed_from_input_rate_of_schema_valid",
            "complete_and_changed_rate_of_schema_valid",
            "exact_match_reference_fixed_rate",
            "whitespace_collapsed_match_reference_fixed_rate",
        ):
            lines.append(f"| {key} | {_format_rate(repair[key])} |")
        lines.append("")
        lines.append(
            "Repair scores are structural proxies; reference matches are text comparisons, not "
            "proof of correctness or security equivalence."
        )

    lines.append("")
    lines.append("## Usage, cost, and latency")
    lines.append("")
    usage = metrics["usage"]
    cost = metrics["cost"]
    latency = metrics["latency"]
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Prompt tokens (known sum) | {_format_number(usage['prompt_tokens_known_sum'])} |")
    lines.append(f"| Completion tokens (known sum) | {_format_number(usage['completion_tokens_known_sum'])} |")
    lines.append(f"| Cached prompt tokens (known sum) | {_format_number(usage['cached_prompt_tokens_known_sum'])} |")
    lines.append(f"| Records missing usage | {usage['records_missing_usage']} |")
    if usage.get("records_with_opencode_usage"):
        lines.append(
            f"| OpenCode allowance consumed (known sum, USD) | "
            f"{_format_cost(usage['opencode_allowance_known_sum_usd'])} |"
        )
        lines.append(
            f"| Records with `usage.opencode` | {usage['records_with_opencode_usage']} |"
        )
        lines.append(
            f"| OpenCode billing sources | `{usage['opencode_billing_sources']}` |"
        )
    lines.append(f"| Total cost (USD) | {_format_cost(cost['total_cost_usd'])} |")
    lines.append(f"| Known cost (USD) | {_format_cost(cost['known_cost_usd'])} |")
    lines.append(f"| Unknown cost records | {cost['unknown_cost_records']} |")
    lines.append(f"| Total request latency (s) | {_format_number(latency['total_request_latency_seconds'])} |")
    lines.append(f"| Mean request latency (s) | {_format_number(latency['mean_request_latency_seconds'])} |")
    lines.append(f"| p50 request latency (s) | {_format_number(latency['p50_request_latency_seconds'])} |")
    lines.append(f"| p95 request latency (s) | {_format_number(latency['p95_request_latency_seconds'])} |")
    lines.append("")
    lines.append(
        "Cost is `null` when token prices were not supplied or when any request lacks a complete "
        "cost record. The runner does not hardcode provider prices."
    )
    if usage.get("records_with_opencode_usage"):
        lines.append(
            "`usage.opencode.allowance` is provider-reported Go-plan usage and is summed "
            "separately; it never populates `total_cost_usd`."
        )

    lines.append("")
    lines.append("## Failures")
    lines.append("")
    if not metrics["failures"]["error_types"] and not metrics["failures"]["schema_invalid_reasons"]:
        lines.append("No API errors or schema-invalid responses.")
    else:
        lines.append(f"- API error types: `{metrics['failures']['error_types']}`")
        lines.append(f"- Schema-invalid reasons: `{metrics['failures']['schema_invalid_reasons']}`")
        lines.append(f"- Examples: `{metrics['failures']['examples']}`")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    for note in metrics["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)

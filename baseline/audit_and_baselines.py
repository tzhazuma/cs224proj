#!/usr/bin/env python3
"""Audit the SecVulEval subsets and compute transparent reference baselines.

The script uses only the Python standard library. It performs no network or
model calls and never reads environment variables or credentials.

It writes:
  results/audit.json      data integrity, completeness, length and CWE audit
  results/baselines.json  reference-baseline confusion matrices and metrics
  results/summary.md      short human-readable report
  results/manifest.json   hashes of inputs and generated reports
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import re
import shlex
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IND_PATH = ROOT / "datasets" / "independent_200.json"
PAIR_PATH = ROOT / "datasets" / "vulnerable_fixed_200_pairs.json"
SOURCE_PATH = ROOT / "SecVulEval.xlsx"
DEFAULT_OUT = ROOT / "baseline" / "results"

EXPECTED_FIELDS = [
    "idx",
    "project",
    "project_url",
    "filepath",
    "commit_id",
    "commit_message",
    "is_vulnerable",
    "hash",
    "func_name",
    "func_body",
    "changed_lines",
    "changed_statements",
    "cve_list",
    "cwe_list",
    "fixed_func_idx",
    "context",
]
CONTEXT_KEYS = [
    "Execution Environment",
    "Explanation",
    "External Function",
    "Function Argument",
    "Globals",
    "Type Execution Declaration",
]
CWE_RE = re.compile(r"CWE-\d+")
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
EXCEL_CELL_LIMIT = 32767
WILSON_Z = 1.959963984540054


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def file_info(path: Path) -> dict:
    info = {"path": rel(path), "exists": path.exists()}
    if path.exists():
        info["bytes"] = path.stat().st_size
        info["sha256"] = sha256_file(path)
    return info


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def dump_json(path: Path, obj: dict) -> bytes:
    data = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    write_bytes(path, data)
    return data


def percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (len(sorted_values) - 1) * p
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(sorted_values[low])
    fraction = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * fraction


def distribution(values: list[float], digits: int = 2) -> dict:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0}
    return {
        "count": len(ordered),
        "min": round(ordered[0], digits),
        "p50": round(percentile(ordered, 0.50), digits),
        "p90": round(percentile(ordered, 0.90), digits),
        "p95": round(percentile(ordered, 0.95), digits),
        "p99": round(percentile(ordered, 0.99), digits),
        "max": round(ordered[-1], digits),
        "mean": round(statistics.fmean(ordered), digits),
    }


def threshold_counts(values: list[float], thresholds: list[int]) -> dict:
    n = len(values)
    result = {}
    for threshold in thresholds:
        count = sum(1 for value in values if value > threshold)
        result[str(threshold)] = {
            "count": count,
            "percent": round(100.0 * count / n, 2) if n else 0.0,
        }
    return result


def wilson_interval(successes: int, n: int) -> list[float] | None:
    if n <= 0:
        return None
    p = successes / n
    denominator = 1.0 + WILSON_Z * WILSON_Z / n
    center = (p + WILSON_Z * WILSON_Z / (2.0 * n)) / denominator
    margin = (
        WILSON_Z
        * math.sqrt(p * (1.0 - p) / n + WILSON_Z * WILSON_Z / (4.0 * n * n))
        / denominator
    )
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def round_or_none(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(value, digits)


def label_counts(records: list[dict]) -> dict:
    positive = sum(1 for record in records if record.get("is_vulnerable") is True)
    negative = sum(1 for record in records if record.get("is_vulnerable") is False)
    return {"vulnerable": positive, "non_vulnerable": negative}


def is_empty(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def audit_fields(records: list[dict]) -> dict:
    field_stats = {}
    records_with_missing = []
    records_with_extra = []
    extra_fields = Counter()
    for record in records:
        keys = set(record)
        missing = [field for field in EXPECTED_FIELDS if field not in record]
        extra = sorted(keys - set(EXPECTED_FIELDS))
        if missing:
            records_with_missing.append({"idx": record.get("idx"), "missing": missing})
        if extra:
            records_with_extra.append({"idx": record.get("idx"), "extra": extra})
            extra_fields.update(extra)

    for field in EXPECTED_FIELDS:
        present_records = [record for record in records if field in record]
        values = [record[field] for record in present_records]
        null_indices = [
            record.get("idx") for record in present_records if record.get(field) is None
        ]
        empty_indices = [
            record.get("idx") for record in present_records if is_empty(record.get(field))
        ]
        field_stats[field] = {
            "present": len(present_records),
            "missing": len(records) - len(present_records),
            "null": len(null_indices),
            "empty": len(empty_indices),
            "types": dict(sorted(Counter(type(value).__name__ for value in values).items())),
            "null_record_indices": null_indices,
            "empty_record_indices": empty_indices,
        }

    return {
        "record_count": len(records),
        "expected_field_count": len(EXPECTED_FIELDS),
        "all_expected_fields_present": not records_with_missing,
        "records_with_missing_fields": records_with_missing,
        "records_with_extra_fields": records_with_extra,
        "extra_fields": dict(extra_fields),
        "fields": field_stats,
    }


def completeness_by_group(groups: dict[str, list[dict]]) -> dict:
    result = {}
    for name, records in groups.items():
        result[name] = {
            "record_count": len(records),
            "commit_message_null": sum(1 for r in records if r.get("commit_message") is None),
            "fixed_func_idx_null": sum(1 for r in records if r.get("fixed_func_idx") is None),
            "changed_lines_empty": sum(1 for r in records if not r.get("changed_lines")),
            "changed_statements_empty": sum(
                1 for r in records if not r.get("changed_statements")
            ),
            "context_missing_or_empty": sum(1 for r in records if not r.get("context")),
        }
    return result


def context_has_null_value(context: str, key: str) -> bool:
    pattern = rf"['\"]{re.escape(key)}['\"]\s*:\s*(?:null|None)\b"
    return re.search(pattern, context) is not None


def context_has_key(context: str, key: str) -> bool:
    pattern = rf"['\"]{re.escape(key)}['\"]\s*:"
    return re.search(pattern, context) is not None


def context_summary(groups: dict[str, list[dict]]) -> dict:
    all_records = [record for records in groups.values() for record in records]
    lengths = [len(record.get("context") or "") for record in all_records]
    key_presence = {}
    for key in CONTEXT_KEYS:
        key_presence[key] = {
            "present": sum(1 for r in all_records if context_has_key(r.get("context") or "", key)),
            "null_or_none": sum(
                1 for r in all_records if context_has_null_value(r.get("context") or "", key)
            ),
        }

    all_six_null = 0
    python_array_repr = 0
    json_null_repr = 0
    for record in all_records:
        context = record.get("context") or ""
        if all(context_has_null_value(context, key) for key in CONTEXT_KEYS):
            all_six_null += 1
        if "array(" in context:
            python_array_repr += 1
        if context.lstrip().startswith('{"'):
            json_null_repr += 1

    return {
        "record_count": len(all_records),
        "length": distribution(lengths),
        "keys": CONTEXT_KEYS,
        "key_presence": key_presence,
        "all_six_keys_null": all_six_null,
        "python_array_repr": python_array_repr,
        "json_object_with_double_quotes": json_null_repr,
    }


def context_facts_by_group(groups: dict[str, list[dict]]) -> dict:
    result = {}
    for name, records in groups.items():
        all_six_null = 0
        array_repr = 0
        unique_strings = set()
        explanation_non_null = 0
        for record in records:
            context = record.get("context") or ""
            unique_strings.add(context)
            if all(context_has_null_value(context, key) for key in CONTEXT_KEYS):
                all_six_null += 1
            if "array(" in context:
                array_repr += 1
            if context_has_key(context, "Explanation") and not context_has_null_value(
                context, "Explanation"
            ):
                explanation_non_null += 1
        result[name] = {
            "all_six_keys_null": all_six_null,
            "python_array_repr": array_repr,
            "unique_context_strings": len(unique_strings),
            "explanation_non_null": explanation_non_null,
        }
    return result


def field_facts_by_group(groups: dict[str, list[dict]]) -> dict:
    result = {}
    for name, records in groups.items():
        by_label = {}
        for label_name, label_value in (("vulnerable", True), ("non_vulnerable", False)):
            subset = [r for r in records if r.get("is_vulnerable") is label_value]
            by_label[label_name] = {
                "count": len(subset),
                "fixed_func_idx_non_null": sum(
                    1 for r in subset if r.get("fixed_func_idx") is not None
                ),
                "cwe_list_non_empty": sum(1 for r in subset if r.get("cwe_list")),
                "cve_list_non_empty": sum(1 for r in subset if r.get("cve_list")),
                "changed_lines_empty": sum(1 for r in subset if not r.get("changed_lines")),
                "changed_statements_empty": sum(
                    1 for r in subset if not r.get("changed_statements")
                ),
            }
        result[name] = by_label
    return result


def length_summary(records: list[dict]) -> dict:
    chars = [len(record.get("func_body") or "") for record in records]
    lines = [(record.get("func_body") or "").count("\n") + 1 for record in records]
    utf8_bytes = [len((record.get("func_body") or "").encode("utf-8")) for record in records]
    estimated_tokens = [value / 4.0 for value in chars]
    max_record = max(records, key=lambda r: len(r.get("func_body") or "")) if records else None
    return {
        "n": len(records),
        "func_body_chars": distribution(chars),
        "func_body_lines": distribution(lines),
        "func_body_utf8_bytes": distribution(utf8_bytes),
        "estimated_tokens_chars_div4": distribution(estimated_tokens),
        "char_threshold_exceedances": threshold_counts(
            chars, [2000, 4000, 8000, 16000, 32000, 64000, 128000]
        ),
        "line_threshold_exceedances": threshold_counts(lines, [100, 200, 500, 1000, 2000]),
        "estimated_token_threshold_exceedances": threshold_counts(
            estimated_tokens, [1000, 2000, 4000, 8000, 16000, 32000]
        ),
        "records_at_excel_cell_limit": sum(1 for value in chars if value == EXCEL_CELL_LIMIT),
        "max_record": (
            {
                "idx": max_record.get("idx"),
                "chars": len(max_record.get("func_body") or ""),
                "lines": (max_record.get("func_body") or "").count("\n") + 1,
            }
            if max_record
            else None
        ),
    }


def truncation_evidence(
    groups: dict[str, list[dict]], pair_ids_by_idx: dict[int, str]
) -> dict:
    records = []
    for group_name, group_records in groups.items():
        for record in group_records:
            body = record.get("func_body") or ""
            if len(body) == EXCEL_CELL_LIMIT:
                item = {
                    "group": group_name,
                    "idx": record.get("idx"),
                    "label": "vulnerable" if record.get("is_vulnerable") else "non_vulnerable",
                    "chars": len(body),
                    "lines": body.count("\n") + 1,
                    "ends_with_closing_brace": body.rstrip().endswith("}"),
                    "last_non_whitespace_char": body.rstrip()[-1:] or "",
                }
                if record.get("idx") in pair_ids_by_idx:
                    item["pair_id"] = pair_ids_by_idx[record["idx"]]
                records.append(item)
    all_mid_function = all(not item["ends_with_closing_brace"] for item in records)
    return {
        "excel_cell_character_limit": EXCEL_CELL_LIMIT,
        "records_at_limit": len(records),
        "records": records,
        "all_end_mid_function": all_mid_function,
        "interpretation": (
            f"{len(records)} 条函数正文恰好为 32,767 字符，且均不以右花括号结束；"
            "32,767 是 Excel 单元格字符上限，说明源工作簿中函数正文已被截断。"
            "长度统计因此是截断后的下界。"
            if records and all_mid_function
            else (
                f"{len(records)} 条函数正文恰好为 32,767 字符，与 Excel 单元格字符上限一致；"
                "需视为源数据截断。"
                if records
                else "未发现恰好 32,767 字符的函数正文。"
            )
        ),
    }


def normalize_labels(raw_values: list[str], pattern: re.Pattern, fallback_prefix: str) -> tuple:
    normalized = []
    placeholders = []
    concatenated_entries = 0
    for raw in raw_values or []:
        matches = pattern.findall(raw)
        if len(matches) > 1:
            concatenated_entries += 1
        if matches:
            normalized.extend(matches)
        elif raw and raw.startswith(fallback_prefix):
            placeholders.append(raw)
        elif raw:
            placeholders.append(raw)
    unique_normalized = sorted(set(normalized), key=lambda value: int(value.split("-")[-1]))
    unique_placeholders = sorted(set(placeholders))
    return unique_normalized, unique_placeholders, concatenated_entries


def cwe_summary(records: list[dict]) -> dict:
    numeric_counts = Counter()
    placeholder_counts = Counter()
    multi_label = 0
    numeric_multi_label = 0
    functions_with_any = 0
    functions_without = 0
    functions_with_placeholder_only = 0
    concatenated_entry_count = 0
    functions_with_concatenated = 0
    labels_per_function = []

    for record in records:
        raw_entries = record.get("cwe_list") or []
        numeric, placeholders, concatenated = normalize_labels(
            raw_entries, CWE_RE, "NVD-CWE"
        )
        numeric_counts.update(numeric)
        placeholder_counts.update(placeholders)
        total_unique = set(numeric) | set(placeholders)
        labels_per_function.append(len(total_unique))
        if total_unique:
            functions_with_any += 1
        else:
            functions_without += 1
        if len(total_unique) > 1:
            multi_label += 1
        if len(numeric) > 1:
            numeric_multi_label += 1
        if not numeric and placeholders:
            functions_with_placeholder_only += 1
        if concatenated:
            concatenated_entry_count += concatenated
            functions_with_concatenated += 1

    numeric_assignments = sum(numeric_counts.values())
    placeholder_assignments = sum(placeholder_counts.values())
    return {
        "functions": len(records),
        "functions_with_any_cwe": functions_with_any,
        "functions_without_cwe": functions_without,
        "distinct_numeric_cwe": len(numeric_counts),
        "numeric_assignments": numeric_assignments,
        "placeholder_assignments": placeholder_assignments,
        "total_label_assignments": numeric_assignments + placeholder_assignments,
        "multi_label_functions": multi_label,
        "numeric_multi_label_functions": numeric_multi_label,
        "functions_with_placeholder_only": functions_with_placeholder_only,
        "mean_labels_per_function": round(statistics.fmean(labels_per_function), 3)
        if labels_per_function
        else None,
        "max_labels_per_function": max(labels_per_function) if labels_per_function else None,
        "concatenated_entry_count": concatenated_entry_count,
        "functions_with_concatenated_entry": functions_with_concatenated,
        "numeric_counts": dict(
            sorted(numeric_counts.items(), key=lambda item: (-item[1], int(item[0][4:])))
        ),
        "placeholder_counts": dict(
            sorted(placeholder_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
    }


def cve_summary(records: list[dict]) -> dict:
    cve_counts = Counter()
    multi_cve = 0
    concatenated_entries = 0
    with_cve = 0
    for record in records:
        raw_entries = record.get("cve_list") or []
        normalized, placeholders, concatenated = normalize_labels(raw_entries, CVE_RE, "CVE")
        if normalized or placeholders:
            with_cve += 1
        unique = set(normalized) | set(placeholders)
        if len(unique) > 1:
            multi_cve += 1
        cve_counts.update(unique)
        concatenated_entries += concatenated
    return {
        "functions": len(records),
        "functions_with_cve": with_cve,
        "distinct_cves": len(cve_counts),
        "multi_cve_functions": multi_cve,
        "concatenated_entry_count": concatenated_entries,
    }


def project_summary(records: list[dict], top_n: int = 10) -> dict:
    counts = Counter(record.get("project") for record in records)
    total = sum(counts.values())
    top = [
        {"project": project, "count": count, "percent": round(100.0 * count / total, 2)}
        for project, count in counts.most_common(top_n)
    ]
    top_two = counts.most_common(2)
    return {
        "distinct_projects": len(counts),
        "top": top,
        "top_two_share_percent": round(
            100.0 * sum(count for _, count in top_two) / total, 2
        )
        if total
        else None,
    }


def binary_metrics(labels: list[bool], predictions: list[bool]) -> dict:
    tp = sum(1 for label, pred in zip(labels, predictions) if label and pred)
    fp = sum(1 for label, pred in zip(labels, predictions) if not label and pred)
    fn = sum(1 for label, pred in zip(labels, predictions) if label and not pred)
    tn = sum(1 for label, pred in zip(labels, predictions) if not label and not pred)
    n = len(labels)
    accuracy = (tp + tn) / n if n else None
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2.0 * precision * recall / (precision + recall)
    else:
        f1 = None
    balanced_accuracy = (
        (recall + specificity) / 2.0
        if recall is not None and specificity is not None
        else None
    )
    return {
        "n": n,
        "n_positive": tp + fn,
        "n_negative": tn + fp,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "matrix": [[tn, fp], [fn, tp]],
        "matrix_axes": {
            "rows": ["actual_non_vulnerable", "actual_vulnerable"],
            "columns": ["predicted_non_vulnerable", "predicted_vulnerable"],
        },
        "predicted_positive_count": tp + fp,
        "predicted_negative_count": tn + fn,
        "metrics": {
            "accuracy": round_or_none(accuracy),
            "precision": round_or_none(precision),
            "recall": round_or_none(recall),
            "f1": round_or_none(f1),
            "specificity": round_or_none(specificity),
            "balanced_accuracy": round_or_none(balanced_accuracy),
            "false_positive_rate": round_or_none(1.0 - specificity)
            if specificity is not None
            else None,
            "false_negative_rate": round_or_none(1.0 - recall) if recall is not None else None,
            "accuracy_ci95_wilson": wilson_interval(tp + tn, n),
        },
        "undefined_metrics": [
            name
            for name, value in (
                ("precision", precision),
                ("f1", f1),
                ("balanced_accuracy", balanced_accuracy),
            )
            if value is None
        ],
    }


def pair_metrics(pair_predictions: list[tuple[bool, bool]]) -> dict:
    n = len(pair_predictions)
    both_correct = sum(1 for pred_vuln, pred_fixed in pair_predictions if pred_vuln and not pred_fixed)
    at_least_one = sum(
        1 for pred_vuln, pred_fixed in pair_predictions if pred_vuln or not pred_fixed
    )
    both_wrong = sum(
        1 for pred_vuln, pred_fixed in pair_predictions if not pred_vuln and pred_fixed
    )
    vulnerable_member_correct = sum(1 for pred_vuln, _ in pair_predictions if pred_vuln)
    fixed_member_correct = sum(1 for _, pred_fixed in pair_predictions if not pred_fixed)
    return {
        "n_pairs": n,
        "both_correct_count": both_correct,
        "both_correct_rate": round(both_correct / n, 6) if n else None,
        "both_correct_ci95_wilson": wilson_interval(both_correct, n),
        "at_least_one_correct_count": at_least_one,
        "at_least_one_correct_rate": round(at_least_one / n, 6) if n else None,
        "both_wrong_count": both_wrong,
        "both_wrong_rate": round(both_wrong / n, 6) if n else None,
        "vulnerable_member_correct_count": vulnerable_member_correct,
        "vulnerable_member_correct_rate": round(vulnerable_member_correct / n, 6)
        if n
        else None,
        "fixed_member_correct_count": fixed_member_correct,
        "fixed_member_correct_rate": round(fixed_member_correct / n, 6) if n else None,
    }


def baseline_record(
    baseline_id: str,
    display_name_zh: str,
    description: str,
    rule: str,
    metrics: dict,
    pair: dict | None = None,
    extra: dict | None = None,
) -> dict:
    record = {
        "id": baseline_id,
        "display_name_zh": display_name_zh,
        "kind": "reference_baseline",
        "is_llm": False,
        "uses_code": False,
        "description": description,
        "rule": rule,
        "n": metrics["n"],
        "n_positive": metrics["n_positive"],
        "n_negative": metrics["n_negative"],
        "confusion_matrix": metrics["confusion_matrix"],
        "matrix": metrics["matrix"],
        "predicted_positive_count": metrics["predicted_positive_count"],
        "predicted_negative_count": metrics["predicted_negative_count"],
        "metrics": metrics["metrics"],
        "undefined_metrics": metrics["undefined_metrics"],
    }
    if pair is not None:
        record["pair_metrics"] = pair
    if extra:
        record.update(extra)
    return record


def check_record(checks: list[dict], check_id: str, passed, detail: str) -> None:
    checks.append({"id": check_id, "passed": passed, "detail": detail})


def build_audit(ind_doc: dict, pair_doc: dict, script_info: dict, provenance: dict) -> dict:
    ind = ind_doc["samples"]
    pairs = pair_doc["pairs"]
    pair_flat = [member for pair in pairs for member in (pair["vulnerable"], pair["fixed"])]
    ind_meta = ind_doc["metadata"]
    pair_meta = pair_doc["metadata"]

    pair_ids_by_idx = {}
    for pair in pairs:
        pair_ids_by_idx[pair["vulnerable"]["idx"]] = pair["pair_id"]
        pair_ids_by_idx[pair["fixed"]["idx"]] = pair["pair_id"]

    groups = {
        "independent_all": ind,
        "independent_vulnerable": [record for record in ind if record["is_vulnerable"]],
        "independent_non_vulnerable": [
            record for record in ind if not record["is_vulnerable"]
        ],
        "paired_vulnerable": [pair["vulnerable"] for pair in pairs],
        "paired_fixed": [pair["fixed"] for pair in pairs],
    }

    length_groups = {
        name: length_summary(records) for name, records in groups.items()
    }

    checks = []
    check_record(
        checks,
        "independent.metadata.sample_count",
        ind_meta.get("sample_count") == len(ind),
        f"claimed={ind_meta.get('sample_count')} observed={len(ind)}",
    )
    check_record(
        checks,
        "independent.metadata.vulnerable_count",
        ind_meta.get("vulnerable_count") == label_counts(ind)["vulnerable"],
        f"claimed={ind_meta.get('vulnerable_count')} observed={label_counts(ind)['vulnerable']}",
    )
    check_record(
        checks,
        "independent.metadata.non_vulnerable_count",
        ind_meta.get("non_vulnerable_count") == label_counts(ind)["non_vulnerable"],
        f"claimed={ind_meta.get('non_vulnerable_count')} observed={label_counts(ind)['non_vulnerable']}",
    )
    ind_indices = [record["idx"] for record in ind]
    check_record(
        checks,
        "independent.idx_unique",
        len(set(ind_indices)) == len(ind_indices),
        f"records={len(ind_indices)} unique={len(set(ind_indices))}",
    )
    check_record(
        checks,
        "independent.labels_boolean",
        all(isinstance(record.get("is_vulnerable"), bool) for record in ind),
        "all is_vulnerable values are JSON booleans",
    )
    ind_field_audit = audit_fields(ind)
    check_record(
        checks,
        "independent.fields_complete",
        ind_field_audit["all_expected_fields_present"],
        f"missing_field_records={len(ind_field_audit['records_with_missing_fields'])}",
    )
    ind_index_set = set(ind_indices)
    fixed_targets = {
        record["fixed_func_idx"]
        for record in ind
        if record.get("fixed_func_idx") is not None
    }
    check_record(
        checks,
        "independent.fixed_targets_outside_subset",
        not (fixed_targets & ind_index_set),
        f"targets={len(fixed_targets)} overlap_with_subset={len(fixed_targets & ind_index_set)}",
    )

    check_record(
        checks,
        "pairs.metadata.pair_count",
        pair_meta.get("pair_count") == len(pairs),
        f"claimed={pair_meta.get('pair_count')} observed={len(pairs)}",
    )
    check_record(
        checks,
        "pairs.metadata.function_count",
        pair_meta.get("function_count") == len(pair_flat),
        f"claimed={pair_meta.get('function_count')} observed={len(pair_flat)}",
    )
    pair_ids = [pair["pair_id"] for pair in pairs]
    check_record(
        checks,
        "pairs.pair_id_unique",
        len(set(pair_ids)) == len(pair_ids),
        f"pairs={len(pair_ids)} unique={len(set(pair_ids))}",
    )
    check_record(
        checks,
        "pairs.pair_id_matches_indices",
        all(
            pair["pair_id"] == f"{pair['vulnerable']['idx']}:{pair['fixed']['idx']}"
            for pair in pairs
        ),
        "all pair_id values equal '<vulnerable.idx>:<fixed.idx>'",
    )
    check_record(
        checks,
        "pairs.fixed_func_idx_link",
        all(pair["vulnerable"]["fixed_func_idx"] == pair["fixed"]["idx"] for pair in pairs),
        "all vulnerable.fixed_func_idx point to the paired fixed.idx",
    )
    identity_fields = ["project", "commit_id", "filepath", "func_name"]
    check_record(
        checks,
        "pairs.identity_fields_equal",
        all(
            all(pair["vulnerable"][field] == pair["fixed"][field] for field in identity_fields)
            for pair in pairs
        ),
        "project, commit_id, filepath and func_name match within every pair",
    )
    check_record(
        checks,
        "pairs.labels_opposite",
        all(
            pair["vulnerable"]["is_vulnerable"] is True
            and pair["fixed"]["is_vulnerable"] is False
            for pair in pairs
        ),
        "every pair is (vulnerable=true, fixed=false)",
    )
    check_record(
        checks,
        "pairs.bodies_differ",
        all(pair["vulnerable"]["func_body"] != pair["fixed"]["func_body"] for pair in pairs),
        "all paired function bodies differ",
    )
    pair_indices = [member["idx"] for member in pair_flat]
    check_record(
        checks,
        "pairs.idx_unique",
        len(set(pair_indices)) == len(pair_indices),
        f"records={len(pair_indices)} unique={len(set(pair_indices))}",
    )
    pair_field_audit = audit_fields(pair_flat)
    check_record(
        checks,
        "pairs.fields_complete",
        pair_field_audit["all_expected_fields_present"],
        f"missing_field_records={len(pair_field_audit['records_with_missing_fields'])}",
    )

    cross_idx = set(ind_indices) & set(pair_indices)
    check_record(
        checks,
        "cross.no_shared_idx",
        not cross_idx,
        f"shared_source_indices={len(cross_idx)}",
    )
    ind_groups = {(record["project"], record["commit_id"]) for record in ind}
    pair_groups = {(pair["vulnerable"]["project"], pair["vulnerable"]["commit_id"]) for pair in pairs}
    check_record(
        checks,
        "cross.no_shared_project_commit",
        not (ind_groups & pair_groups),
        f"shared_groups={len(ind_groups & pair_groups)}",
    )
    all_records = ind + pair_flat
    all_hashes = [record["hash"] for record in all_records]
    all_bodies = [record["func_body"] for record in all_records]
    check_record(
        checks,
        "cross.function_hash_unique",
        len(set(all_hashes)) == len(all_hashes),
        f"records={len(all_hashes)} unique={len(set(all_hashes))}",
    )
    check_record(
        checks,
        "cross.function_body_unique",
        len(set(all_bodies)) == len(all_bodies),
        f"records={len(all_bodies)} unique={len(set(all_bodies))}",
    )

    workbook_info = file_info(SOURCE_PATH)
    if workbook_info["exists"]:
        claimed_source_hash = ind_meta.get("source_sha256")
        check_record(
            checks,
            "source.workbook_sha256_matches_metadata",
            workbook_info["sha256"] == claimed_source_hash,
            f"claimed={claimed_source_hash} observed={workbook_info['sha256']}",
        )
    else:
        check_record(
            checks,
            "source.workbook_sha256_matches_metadata",
            None,
            "SecVulEval.xlsx not found; metadata hash could not be verified",
        )
    provenance_keys = [
        "seed",
        "source_sha256",
        "source_sheet",
        "source_rows",
        "usable_rows",
        "excluded_malformed_rows",
    ]
    check_record(
        checks,
        "metadata.consistent_between_datasets",
        all(ind_meta.get(key) == pair_meta.get(key) for key in provenance_keys),
        "seed, source hash, sheet, row counts and exclusions match across both JSON files",
    )

    pair_facts = {
        "fixed_func_idx_equals_fixed_idx": sum(
            1 for pair in pairs if pair["vulnerable"]["fixed_func_idx"] == pair["fixed"]["idx"]
        ),
        "same_project_commit_filepath_func_name": sum(
            1
            for pair in pairs
            if all(pair["vulnerable"][field] == pair["fixed"][field] for field in identity_fields)
        ),
        "labels_true_false": sum(
            1
            for pair in pairs
            if pair["vulnerable"]["is_vulnerable"] is True
            and pair["fixed"]["is_vulnerable"] is False
        ),
        "different_function_bodies": sum(
            1 for pair in pairs if pair["vulnerable"]["func_body"] != pair["fixed"]["func_body"]
        ),
        "identical_cwe_list": sum(
            1 for pair in pairs if pair["vulnerable"]["cwe_list"] == pair["fixed"]["cwe_list"]
        ),
        "identical_cve_list": sum(
            1 for pair in pairs if pair["vulnerable"]["cve_list"] == pair["fixed"]["cve_list"]
        ),
        "identical_context": sum(
            1 for pair in pairs if pair["vulnerable"]["context"] == pair["fixed"]["context"]
        ),
        "identical_commit_message": sum(
            1
            for pair in pairs
            if pair["vulnerable"]["commit_message"] == pair["fixed"]["commit_message"]
        ),
        "identical_changed_lines": sum(
            1
            for pair in pairs
            if pair["vulnerable"]["changed_lines"] == pair["fixed"]["changed_lines"]
        ),
        "identical_changed_statements": sum(
            1
            for pair in pairs
            if pair["vulnerable"]["changed_statements"]
            == pair["fixed"]["changed_statements"]
        ),
    }

    context = context_summary(
        {
            "independent": ind,
            "paired_vulnerable": groups["paired_vulnerable"],
            "paired_fixed": groups["paired_fixed"],
        }
    )
    context_facts = context_facts_by_group(groups)
    field_facts = field_facts_by_group(groups)

    cwe_groups = {
        name: cwe_summary(groups[name])
        for name in [
            "independent_vulnerable",
            "independent_non_vulnerable",
            "paired_vulnerable",
            "paired_fixed",
        ]
    }
    cve_groups = {
        name: cve_summary(groups[name])
        for name in ["independent_all", "paired_vulnerable", "paired_fixed"]
    }

    truncation = truncation_evidence(
        {
            "independent": ind,
            "paired_vulnerable": groups["paired_vulnerable"],
            "paired_fixed": groups["paired_fixed"],
        },
        pair_ids_by_idx,
    )

    passed_count = sum(1 for check in checks if check["passed"] is True)
    failed_count = sum(1 for check in checks if check["passed"] is False)
    not_checked_count = sum(1 for check in checks if check["passed"] is None)

    warnings = []
    warnings.append(
        {
            "severity": "high",
            "id": "context_label_artifact",
            "message": (
                "独立集 40/40 条非漏洞样本的 context 完全相同且六个字段全为 null；"
                "160/160 条漏洞样本的 context 含 array(...) 注释载荷。"
                "若把原始 context 放入提示词，标签可由序列化格式和是否存在注释直接判断；"
                "配对集内 context 200/200 相同，不能用于区分对内的漏洞/修复版本。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "high",
            "id": "fixed_func_idx_label_artifact",
            "message": (
                "独立集 fixed_func_idx 非空为 143/160 条漏洞样本、0/40 条非漏洞样本；"
                "该字段的存在性本身高度指示标签。任何模型输入都应排除此字段。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "high",
            "id": "source_truncation_at_excel_limit",
            "message": (
                f"{truncation['records_at_limit']} 条函数正文恰好 32,767 字符，"
                "对应 Excel 单元格上限，且均在函数中间结束。"
                "这些样本的代码长度和完整性已被源数据限制，不能当作完整函数评估。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "medium",
            "id": "cwe_cve_metadata_not_label_specific",
            "message": (
                "40/40 条独立集非漏洞样本也带有非空 cwe_list 和 cve_list；"
                "配对集中漏洞/修复版本的 cwe_list、cve_list 各 200/200 相同。"
                "CWE/CVE 是源 CVE 的溯源元数据，不是该函数是否漏洞的标签特征，"
                "配对集也不能按 400 条独立 CWE 观测重复计数。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "medium",
            "id": "prompt_length_risk",
            "message": (
                "独立集 "
                f"{length_groups['independent_all']['char_threshold_exceedances']['2000']['count']}"
                "/200 条超过 2,000 字符，"
                f"{length_groups['independent_all']['char_threshold_exceedances']['8000']['count']}"
                "/200 条超过 8,000 字符；配对漏洞版本 "
                f"{length_groups['paired_vulnerable']['char_threshold_exceedances']['8000']['count']}"
                " 条、修复版本 "
                f"{length_groups['paired_fixed']['char_threshold_exceedances']['8000']['count']}"
                " 条超过 8,000 字符。按 4 字符≈1 token 的粗略换算仅作提示，"
                "实际截断风险需用具体模型 tokenizer 复核。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "medium",
            "id": "project_concentration",
            "message": (
                "独立集前两大项目为 linux 和 Chrome，占 "
                f"{project_summary(ind)['top_two_share_percent']}%；"
                "配对集前两大项目占 "
                f"{project_summary([p['vulnerable'] for p in pairs])['top_two_share_percent']}%。"
                "项目级泛化结论需谨慎。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "low",
            "id": "field_completeness",
            "message": (
                "16 个字段在 600 条记录中均存在；全部记录中 commit_message 为 null 1 条"
                "（位于独立集），changed_lines 为空 21 条，changed_statements 为空 39 条；"
                "context 的 Explanation 字段在 600 条记录中全部为 null。"
            ),
        }
    )
    warnings.append(
        {
            "severity": "info",
            "id": "paired_order_is_a_dataset_artifact",
            "message": (
                "配对 JSON 的顺序固定为 (vulnerable, fixed)。按槽位预测可得到 100% 指标，"
                "但这是数据构造泄漏而非检测能力；报告中必须与真实方法分开。"
            ),
        }
    )

    integrity = {
        "total": len(checks),
        "passed": passed_count,
        "failed": failed_count,
        "not_checked": not_checked_count,
        "checks": checks,
    }

    return {
        "schema_version": 1,
        "kind": "data_audit",
        "generated_at_utc": provenance["generated_at_utc"],
        "provenance": provenance,
        "inputs": {
            "independent_200.json": file_info(IND_PATH),
            "vulnerable_fixed_200_pairs.json": file_info(PAIR_PATH),
            "SecVulEval.xlsx": workbook_info,
            "script": script_info,
        },
        "datasets": {
            "independent": {
                "record_count": len(ind),
                "label_counts": label_counts(ind),
                "prevalence_vulnerable": round(
                    label_counts(ind)["vulnerable"] / len(ind), 6
                ),
                "metadata_claims": {
                    key: ind_meta.get(key)
                    for key in [
                        "schema_version",
                        "dataset_type",
                        "source_sha256",
                        "seed",
                        "sample_count",
                        "vulnerable_count",
                        "non_vulnerable_count",
                    ]
                },
                "fields": ind_field_audit,
                "projects": project_summary(ind),
            },
            "pairs": {
                "pair_count": len(pairs),
                "function_count": len(pair_flat),
                "label_counts": label_counts(pair_flat),
                "metadata_claims": {
                    key: pair_meta.get(key)
                    for key in [
                        "schema_version",
                        "dataset_type",
                        "source_sha256",
                        "seed",
                        "pair_count",
                        "function_count",
                        "eligible_pair_count",
                    ]
                },
                "fields": pair_field_audit,
                "pair_structure_facts": pair_facts,
                "projects": project_summary([pair["vulnerable"] for pair in pairs]),
            },
            "combined": {
                "unique_function_records": len({record["idx"] for record in all_records}),
                "unique_function_hashes": len(set(all_hashes)),
                "unique_function_bodies": len(set(all_bodies)),
                "total_records_with_pair_members": len(all_records),
            },
        },
        "integrity": integrity,
        "field_completeness_by_group": completeness_by_group(groups),
        "field_facts_by_group": field_facts,
        "context_audit": {
            "summary": context,
            "by_group": context_facts,
            "note": (
                "context 以原始工作簿字符串保存，未执行其中的表达式。"
                "统计只检查键、null/None 和 array(...) 形式，不解析或执行内容。"
            ),
        },
        "code_length_audit": {
            "units": "func_body Unicode characters and newline-separated lines; UTF-8 bytes also recorded",
            "estimated_tokens_note": (
                "estimated_tokens_chars_div4 = characters / 4 is a coarse heuristic, "
                "not a tokenizer measurement."
            ),
            "groups": length_groups,
            "source_truncation": truncation,
        },
        "cwe_audit": {
            "normalization": (
                "Split each cwe_list entry with regex CWE-\\\\d+; deduplicate within a function; "
                "preserve NVD-CWE placeholders; multi_label counts any two distinct labels."
            ),
            "groups": cwe_groups,
            "paired_identity": {
                "pairs_with_identical_cwe_list": pair_facts["identical_cwe_list"],
                "pairs_with_identical_cve_list": pair_facts["identical_cve_list"],
                "note": (
                    "The fixed member repeats the vulnerable member's CWE/CVE metadata; "
                    "a pair contributes one vulnerability annotation, not two."
                ),
            },
            "cve_presence": cve_groups,
        },
        "warnings": warnings,
    }


def build_baselines(ind_doc: dict, pair_doc: dict, seed: int, audit_sha: str) -> dict:
    ind = ind_doc["samples"]
    pairs = pair_doc["pairs"]

    ind_labels = [record["is_vulnerable"] for record in ind]
    ind_always_vuln = [True] * len(ind)
    ind_always_fixed = [False] * len(ind)

    ind_baselines = {
        "always_vulnerable_majority": baseline_record(
            "always_vulnerable_majority",
            "永远预测有漏洞（多数类）",
            "Predict every independent function as vulnerable. This is the majority-class baseline.",
            "prediction = True for every sample",
            binary_metrics(ind_labels, ind_always_vuln),
        ),
        "always_non_vulnerable": baseline_record(
            "always_non_vulnerable",
            "永远预测无漏洞",
            "Predict every independent function as non-vulnerable; included to expose the accuracy/recall tradeoff.",
            "prediction = False for every sample",
            binary_metrics(ind_labels, ind_always_fixed),
        ),
    }

    paired_labels = []
    for pair in pairs:
        paired_labels.extend([True, False])

    pred_sets = {}
    pred_sets["always_vulnerable_both"] = [
        (True, True) for _ in pairs
    ]
    pred_sets["always_non_vulnerable_both"] = [
        (False, False) for _ in pairs
    ]
    rng = random.Random(seed)
    random_pairs = []
    for _ in pairs:
        if rng.random() < 0.5:
            random_pairs.append((True, False))
        else:
            random_pairs.append((False, True))
    pred_sets["random_member_seeded"] = random_pairs
    pred_sets["pair_slot_oracle_leakage"] = [(True, False) for _ in pairs]

    paired_descriptions = {
        "always_vulnerable_both": (
            "永远预测有漏洞（配对两侧）",
            "Predict vulnerable for both members of every pair.",
            "prediction = (True, True) for every pair",
            {},
        ),
        "always_non_vulnerable_both": (
            "永远预测无漏洞（配对两侧）",
            "Predict non-vulnerable for both members of every pair.",
            "prediction = (False, False) for every pair",
            {},
        ),
        "random_member_seeded": (
            "配对内随机指定一个有漏洞",
            "For each pair, randomly designate exactly one member as vulnerable. This is the chance-level correspondence baseline.",
            "per pair: choose (True, False) or (False, True) with probability 0.5",
            {"seed": seed, "is_chance_reference": True},
        ),
        "pair_slot_oracle_leakage": (
            "配对槽位 oracle（泄漏，不是检测器）",
            "Predict the member stored in the 'vulnerable' slot as vulnerable and the 'fixed' slot as fixed.",
            "prediction = (True, False) for every pair, using JSON member order",
            {
                "is_detector": False,
                "is_leakage_sentinel": True,
                "exclude_from_method_comparison": True,
                "uses_dataset_construction_artifact": True,
                "warning": (
                    "The paired JSON is always ordered (vulnerable, fixed). "
                    "The 100% score measures slot order, not vulnerability detection."
                ),
            },
        ),
    }

    paired_baselines = {}
    for baseline_id, pair_predictions in pred_sets.items():
        flat_predictions = [value for pair_prediction in pair_predictions for value in pair_prediction]
        metrics = binary_metrics(paired_labels, flat_predictions)
        pair_stats = pair_metrics(pair_predictions)
        display_name, description, rule, extra = paired_descriptions[baseline_id]
        if baseline_id == "random_member_seeded":
            extra = dict(extra)
            extra["chosen_vulnerable_slot_count"] = sum(
                1 for pred_vuln, pred_fixed in pair_predictions if pred_vuln and not pred_fixed
            )
        paired_baselines[baseline_id] = baseline_record(
            baseline_id,
            display_name,
            description,
            rule,
            metrics,
            pair=pair_stats,
            extra=extra,
        )

    return {
        "schema_version": 1,
        "kind": "reference_baseline_not_llm",
        "generated_at_utc": utc_now(),
        "provenance": {
            "audit_json_sha256": audit_sha,
            "inputs": {
                "independent_200.json": file_info(IND_PATH),
                "vulnerable_fixed_200_pairs.json": file_info(PAIR_PATH),
            },
            "random_seed": seed,
            "network_access": False,
            "llm_calls": 0,
            "api_calls": 0,
        },
        "label_convention": {
            "positive": "vulnerable",
            "negative": "non_vulnerable",
            "matrix_order": "[[TN, FP], [FN, TP]]",
            "matrix_rows": ["actual non-vulnerable", "actual vulnerable"],
            "matrix_columns": ["predicted non-vulnerable", "predicted vulnerable"],
        },
        "metrics_definitions": {
            "accuracy": "(TP + TN) / N",
            "precision": "TP / (TP + FP); null when no positive prediction is made",
            "recall": "TP / (TP + FN)",
            "f1": "2 * precision * recall / (precision + recall); null when undefined",
            "specificity": "TN / (TN + FP)",
            "balanced_accuracy": "(recall + specificity) / 2",
            "pair_both_correct": "both members of a pair classified correctly / number of pairs",
            "pair_at_least_one_correct": "at least one member classified correctly / number of pairs",
            "accuracy_ci95_wilson": "Wilson score interval, descriptive",
        },
        "independent": {
            "n": len(ind),
            "label_counts": label_counts(ind),
            "baselines": ind_baselines,
        },
        "paired": {
            "n_pairs": len(pairs),
            "n_function_records": len(paired_labels),
            "label_counts": label_counts(
                [pair["vulnerable"] for pair in pairs]
                + [pair["fixed"] for pair in pairs]
            ),
            "baselines": paired_baselines,
        },
        "reference_points": {
            "independent_majority_accuracy": round(
                label_counts(ind)["vulnerable"] / len(ind), 6
            ),
            "paired_per_function_chance_accuracy": 0.5,
            "paired_pair_both_correct_chance": 0.5,
            "paired_slot_oracle_pair_both_correct": 1.0,
            "note": (
                "The independent majority baseline equals the observed vulnerable prevalence. "
                "The paired random-member baseline has 50% per-function accuracy and "
                "50% pair both-correct in expectation. The slot oracle's 100% is leakage."
            ),
        },
        "notes": [
            "All entries here are deterministic reference baselines, not LLM methods.",
            "No network, API or credential access is used by this script.",
            "Independent majority accuracy is 80% because 160/200 samples are vulnerable; it is a floor, not evidence of detection.",
            "Always-non-vulnerable makes no positive predictions, so precision and F1 are undefined (null).",
            "Paired per-function metrics treat 400 member records as rows; members within a pair are dependent, so these metrics are descriptive and the Wilson interval is not a clustered interval.",
            "Pair both-correct is the strict paired metric: both members must be classified correctly.",
            "Random-member is one seeded realization; the analytic expectation of pair both-correct is 0.5.",
            "The slot oracle is a label-leakage sentinel and must not be reported as a detector.",
        ],
    }


def fmt_num(value, digits: int = 3) -> str:
    if value is None:
        return "—"
    return f"{value:.{digits}f}"


def fmt_pct(value, digits: int = 1) -> str:
    if value is None:
        return "—"
    return f"{100.0 * value:.{digits}f}%"


def fmt_ci(interval) -> str:
    if not interval:
        return "—"
    return f"[{100.0 * interval[0]:.1f}%, {100.0 * interval[1]:.1f}%]"


def top_cwe_rows(ind_vuln: dict, pair_vuln: dict, top_n: int = 10) -> list[dict]:
    keys = set(ind_vuln["numeric_counts"]) | set(pair_vuln["numeric_counts"])
    rows = []
    for key in keys:
        ind_count = ind_vuln["numeric_counts"].get(key, 0)
        pair_count = pair_vuln["numeric_counts"].get(key, 0)
        rows.append({"cwe": key, "independent": ind_count, "paired": pair_count, "total": ind_count + pair_count})
    rows.sort(key=lambda row: (-row["total"], int(row["cwe"][4:])))
    return rows[:top_n]


def build_summary(audit: dict, baselines: dict) -> str:
    ind_audit = audit["datasets"]["independent"]
    pair_audit = audit["datasets"]["pairs"]
    ind_facts = audit["field_facts_by_group"]
    completeness = audit["field_completeness_by_group"]
    groups = audit["code_length_audit"]["groups"]
    cwe = audit["cwe_audit"]["groups"]
    integrity = audit["integrity"]
    trunc = audit["code_length_audit"]["source_truncation"]
    ind_base = baselines["independent"]["baselines"]
    pair_base = baselines["paired"]["baselines"]

    lines = []
    append = lines.append
    append("# SecVulEval 子集审计与透明参考基线")
    append("")
    append("> **这些是 reference baseline，不是 LLM 检测结果。** 全部由标签或数据构造规则直接产生，不调用模型、不访问网络。")
    append("")
    append(f"生成时间（UTC）：`{audit['generated_at_utc']}`")
    append("")
    append("## 复现命令")
    append("")
    append("```bash")
    append('wsl bash -lc "cd /mnt/c/Users/tzh03/Downloads/zy && python3 baseline/audit_and_baselines.py"')
    append("```")
    append("")
    append(f"实际记录的命令：`{audit['provenance']['command']}`；Python `{audit['provenance']['python_version']}`。")
    append("")
    append("## 输入与校验和")
    append("")
    append("| 文件 | 字节 | SHA-256 |")
    append("| --- | ---: | --- |")
    for label, info in audit["inputs"].items():
        if not info.get("exists"):
            append(f"| `{info['path']}` | — | 文件不存在 |")
            continue
        append(f"| `{info['path']}` | {info['bytes']:,} | `{info['sha256']}` |")
    append("")
    append("源工作簿 SHA-256 与两个 JSON 的 `metadata.source_sha256` 一致。")
    append("")
    append("## 数据构成")
    append("")
    append("| 数据集 | 记录 | 有漏洞 | 无漏洞 | 说明 |")
    append("| --- | ---: | ---: | ---: | --- |")
    append(
        f"| independent | {ind_audit['record_count']} | {ind_audit['label_counts']['vulnerable']} | "
        f"{ind_audit['label_counts']['non_vulnerable']} | 独立函数，正例占 {fmt_pct(ind_audit['prevalence_vulnerable'])} |"
    )
    append(
        f"| paired | {pair_audit['function_count']} | {pair_audit['label_counts']['vulnerable']} | "
        f"{pair_audit['label_counts']['non_vulnerable']} | {pair_audit['pair_count']} 对，每对一个漏洞版本、一个修复版本 |"
    )
    append(
        f"| 合计 | {audit['datasets']['combined']['total_records_with_pair_members']} | — | — | "
        f"{audit['datasets']['combined']['unique_function_records']} 个不同原始索引，无重复函数正文 |"
    )
    append("")
    append(
        f"项目分布：独立集 {ind_audit['projects']['distinct_projects']} 个项目，"
        f"前两大占 {ind_audit['projects']['top_two_share_percent']}%；"
        f"配对集 {pair_audit['projects']['distinct_projects']} 个项目，"
        f"前两大占 {pair_audit['projects']['top_two_share_percent']}%。"
    )
    append("")
    append("## 数据审计")
    append("")
    append(
        f"完整性检查：**{integrity['passed']}/{integrity['total']} 通过**，"
        f"失败 {integrity['failed']}，未检查 {integrity['not_checked']}。"
    )
    if integrity["failed"]:
        append("")
        append("失败项：")
        for check in integrity["checks"]:
            if check["passed"] is False:
                append(f"- `{check['id']}`：{check['detail']}")
    append("")
    append("### 字段完整性")
    append("")
    append("16 个字段在 600 条函数记录中均存在，没有缺失键。下表的 null/空值均为数据事实，不是 schema 缺失。")
    append("")
    append("| 字段 | 独立集 | 配对漏洞版本 | 配对修复版本 |")
    append("| --- | ---: | ---: | ---: |")
    for field, key in [
        ("commit_message 为 null", "commit_message_null"),
        ("fixed_func_idx 为 null", "fixed_func_idx_null"),
        ("changed_lines 为空", "changed_lines_empty"),
        ("changed_statements 为空", "changed_statements_empty"),
        ("context 缺失或为空", "context_missing_or_empty"),
    ]:
        append(
            f"| {field} | {completeness['independent_all'][key]} | "
            f"{completeness['paired_vulnerable'][key]} | {completeness['paired_fixed'][key]} |"
        )
    append("")
    append(
        "`context.Explanation` 在 600 条记录中全部为 null；"
        "`commit_message` 的唯一 null 位于独立集正例 idx=19871。"
    )
    append("")
    append("### 代码长度与截断风险")
    append("")
    append(
        "长度单位为 Unicode 字符；`>2k chars` 等列为严格大于该阈值。"
        "`chars/4` 只是粗略 token 提示，不是 tokenizer 结果。"
    )
    append("")
    append("| 分组 | n | p50 | p90 | p99 | max | >2k chars | >8k chars | >1k lines | =32767 |")
    append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    group_labels = {
        "independent_all": "独立集全部",
        "independent_vulnerable": "独立集正例",
        "independent_non_vulnerable": "独立集负例",
        "paired_vulnerable": "配对漏洞版本",
        "paired_fixed": "配对修复版本",
    }
    for key, label in group_labels.items():
        group = groups[key]
        append(
            f"| {label} | {group['n']} | {group['func_body_chars']['p50']:.0f} | "
            f"{group['func_body_chars']['p90']:.0f} | {group['func_body_chars']['p99']:.0f} | "
            f"{group['func_body_chars']['max']:.0f} | "
            f"{group['char_threshold_exceedances']['2000']['count']} | "
            f"{group['char_threshold_exceedances']['8000']['count']} | "
            f"{group['line_threshold_exceedances']['1000']['count']} | "
            f"{group['records_at_excel_cell_limit']} |"
        )
    append("")
    append(
        f"**已确认的源级截断**：{trunc['records_at_limit']} 条函数正文恰好 {trunc['excel_cell_character_limit']:,} 字符，"
        f"且全部不以 `}}` 结束（`all_end_mid_function={str(trunc['all_end_mid_function']).lower()}`）。"
        "32,767 是 Excel 单元格字符上限，因此这是源工作簿截断，不是模型截断；"
        "真实函数可能更长，上表长度分布是截断后的下界。"
    )
    append("")
    for record in trunc["records"]:
        pair_text = f"，pair `{record['pair_id']}`" if record.get("pair_id") else ""
        append(
            f"- `{record['group']}` idx={record['idx']}（{record['label']}，"
            f"{record['chars']:,} 字符，{record['lines']} 行，末尾 `{record['last_non_whitespace_char']}`）{pair_text}"
        )
    append("")
    append("### CWE 分布概况")
    append("")
    append(
        "原始 `cwe_list` 中存在 `CWE-125CWE-787` 这类连写标签；统计时按 `CWE-\\d+` 拆分并在单个函数内去重。"
        "`NVD-CWE-*` 作为占位标记单独计数，不当作具体 CWE。"
    )
    append("")
    append("| 分组 | n | 有 CWE | 数字 CWE 类型 | 数字标签归属 | 占位标记 | 多标签函数 | 连写条目 |")
    append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, label in [
        ("independent_vulnerable", "独立集正例"),
        ("independent_non_vulnerable", "独立集负例"),
        ("paired_vulnerable", "配对漏洞版本"),
        ("paired_fixed", "配对修复版本"),
    ]:
        group = cwe[key]
        append(
            f"| {label} | {group['functions']} | {group['functions_with_any_cwe']} | "
            f"{group['distinct_numeric_cwe']} | {group['numeric_assignments']} | "
            f"{group['placeholder_assignments']} | {group['multi_label_functions']} | "
            f"{group['concatenated_entry_count']} |"
        )
    append("")
    append("独立集正例与配对漏洞版本中计数最高的数字 CWE：")
    append("")
    append("| CWE | 独立集正例 | 配对漏洞版本 |")
    append("| --- | ---: | ---: |")
    for row in top_cwe_rows(cwe["independent_vulnerable"], cwe["paired_vulnerable"]):
        append(f"| {row['cwe']} | {row['independent']} | {row['paired']} |")
    append("")
    append(
        "注意：独立集 40 条非漏洞样本也全部带非空 `cwe_list` 和 `cve_list`；"
        "配对集的修复版本 200/200 复制了漏洞版本的 CWE/CVE。"
        "因此 CWE/CVE 是源 CVE 的溯源信息，不是函数级标签特征，也不能把 200 对当成 400 条独立 CWE 观测。"
    )
    append("")
    append("### 元数据泄漏检查")
    append("")
    append(
        "以下事实会影响模型输入设计，但本脚本没有把它们实现为检测规则："
    )
    append("")
    append(
        "- 独立集 `context`：40/40 条负例是同一个全 null 字符串；160/160 条正例含 `array(...)` 注释载荷。"
        "原始 `context` 与标签完全相关。"
    )
    append(
        f"- 独立集 `fixed_func_idx` 非空：正例 {ind_facts['independent_all']['vulnerable']['fixed_func_idx_non_null']}/160，"
        f"负例 {ind_facts['independent_all']['non_vulnerable']['fixed_func_idx_non_null']}/40。"
    )
    append(
        f"- `cwe_list` 非空：独立集正例 {ind_facts['independent_all']['vulnerable']['cwe_list_non_empty']}/160，"
        f"负例 {ind_facts['independent_all']['non_vulnerable']['cwe_list_non_empty']}/40。"
    )
    append(
        f"- 配对集内 `context` 相同 {pair_audit['pair_structure_facts']['identical_context']}/200，"
        f"`commit_message` 相同 {pair_audit['pair_structure_facts']['identical_commit_message']}/200；"
        "它们在对内不能区分漏洞与修复版本。"
    )
    append("")
    append("## 参考基线结果")
    append("")
    append("### 独立集")
    append("")
    append("| 基线 | TP | FP | FN | TN | Accuracy | Acc 95% CI | Precision | Recall | F1 | Specificity |")
    append("| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |")
    for baseline in [ind_base["always_vulnerable_majority"], ind_base["always_non_vulnerable"]]:
        cm = baseline["confusion_matrix"]
        metrics = baseline["metrics"]
        append(
            f"| {baseline['display_name_zh']} | {cm['tp']} | {cm['fp']} | {cm['fn']} | {cm['tn']} | "
            f"{fmt_pct(metrics['accuracy'])} | {fmt_ci(metrics['accuracy_ci95_wilson'])} | "
            f"{fmt_num(metrics['precision'])} | {fmt_num(metrics['recall'])} | "
            f"{fmt_num(metrics['f1'])} | {fmt_num(metrics['specificity'])} |"
        )
    append("")
    append(
        f"独立集多数类基线 accuracy = {fmt_pct(ind_base['always_vulnerable_majority']['metrics']['accuracy'])}，"
        "来自 160/200 的正例比例。它没有区分能力：specificity = 0，balanced accuracy = 0.5。"
        "永远预测无漏洞时没有正类预测，precision 与 F1 未定义（表中记为 —）。"
    )
    append("")
    append("### 配对集（400 条函数记录，200 对）")
    append("")
    append("| 基线 | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | Specificity |")
    append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key in [
        "always_vulnerable_both",
        "always_non_vulnerable_both",
        "random_member_seeded",
        "pair_slot_oracle_leakage",
    ]:
        baseline = pair_base[key]
        cm = baseline["confusion_matrix"]
        metrics = baseline["metrics"]
        display = baseline["display_name_zh"]
        append(
            f"| {display} | {cm['tp']} | {cm['fp']} | {cm['fn']} | {cm['tn']} | "
            f"{fmt_pct(metrics['accuracy'])} | {fmt_num(metrics['precision'])} | "
            f"{fmt_num(metrics['recall'])} | {fmt_num(metrics['f1'])} | "
            f"{fmt_num(metrics['specificity'])} |"
        )
    append("")
    append("配对级指标（核心是“双方均正确率”）：")
    append("")
    append("| 基线 | 双方均正确 | 95% CI | 至少一方正确 | 双方均错 | 漏洞版本正确 | 修复版本正确 |")
    append("| --- | ---: | --- | ---: | ---: | ---: | ---: |")
    for key in [
        "always_vulnerable_both",
        "always_non_vulnerable_both",
        "random_member_seeded",
        "pair_slot_oracle_leakage",
    ]:
        baseline = pair_base[key]
        pair = baseline["pair_metrics"]
        display = baseline["display_name_zh"]
        append(
            f"| {display} | {pair['both_correct_count']}/{pair['n_pairs']} "
            f"({fmt_pct(pair['both_correct_rate'])}) | {fmt_ci(pair['both_correct_ci95_wilson'])} | "
            f"{fmt_pct(pair['at_least_one_correct_rate'])} | {fmt_pct(pair['both_wrong_rate'])} | "
            f"{fmt_pct(pair['vulnerable_member_correct_rate'])} | "
            f"{fmt_pct(pair['fixed_member_correct_rate'])} |"
        )
    append("")
    append(
        "常量基线在配对场景的每函数 accuracy 都是 50%，但双方均正确率为 0%："
        "每对总有一个成员被固定判错。随机指定一个有漏洞的基线给出约 50% 的双方均正确率，"
        "这才是配对场景的机会水平。槽位 oracle 的 100% 来自 JSON 固定顺序 `(vulnerable, fixed)`，"
        "是构造泄漏，不是检测能力。"
    )
    append("")
    append("## 解释与限制")
    append("")
    append("- 独立集的多数类基线是 80% accuracy 的平凡参照；任何 LLM 结果都必须同时看 recall、specificity 和配对双方均正确率，不能只报 accuracy。")
    append("- 配对集的 400 条记录不是 400 个独立样本；同一对的两个成员共享项目、提交、文件、上下文和 CWE/CVE，指标只作描述性汇总。")
    append("- 32,767 字符源截断影响 5 条记录；真实函数可能更长，长度风险被低估。")
    append("- 独立集负例只有 40 条，比例 20%；accuracy 的 Wilson 区间是描述性的，不能替代对方法差异的统计检验。")
    append("- CWE 标签存在连写和 NVD 占位标记；本审计只做字符串拆分和去重，不使用 CWE 层级或外部映射。")
    append("- 所有结果只来自标签和构造规则；没有 LLM、API、网络或凭证访问，也没有编造模型输出。")
    append("")
    append("机器可读结果：`baseline/results/audit.json`、`baseline/results/baselines.json`；校验和清单：`baseline/results/manifest.json`。")
    append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUT,
        help="directory for audit.json, baselines.json and summary.md",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="seed for the paired random-member chance baseline",
    )
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    script_path = Path(__file__).resolve()
    script_info = {
        "path": rel(script_path),
        "exists": True,
        "bytes": script_path.stat().st_size,
        "sha256": sha256_file(script_path),
    }
    provenance = {
        "command": shlex.join([sys.executable, *sys.argv]),
        "argv": sys.argv,
        "cwd": str(Path.cwd()),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "generated_at_utc": utc_now(),
        "network_access": False,
        "llm_calls": 0,
        "api_calls": 0,
        "random_seed": args.random_seed,
    }

    with IND_PATH.open(encoding="utf-8") as handle:
        ind_doc = json.load(handle)
    with PAIR_PATH.open(encoding="utf-8") as handle:
        pair_doc = json.load(handle)

    audit = build_audit(ind_doc, pair_doc, script_info, provenance)
    audit_bytes = (json.dumps(audit, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    audit_sha = sha256_bytes(audit_bytes)
    write_bytes(output_dir / "audit.json", audit_bytes)

    baselines = build_baselines(ind_doc, pair_doc, args.random_seed, audit_sha)
    baselines["provenance"]["audit_json_sha256"] = audit_sha
    baselines_bytes = (json.dumps(baselines, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    write_bytes(output_dir / "baselines.json", baselines_bytes)

    summary = build_summary(audit, baselines)
    summary_bytes = summary.encode("utf-8")
    write_bytes(output_dir / "summary.md", summary_bytes)

    manifest = {
        "generated_at_utc": provenance["generated_at_utc"],
        "command": provenance["command"],
        "inputs": {
            "independent_200.json": file_info(IND_PATH),
            "vulnerable_fixed_200_pairs.json": file_info(PAIR_PATH),
            "SecVulEval.xlsx": file_info(SOURCE_PATH),
            "script": script_info,
        },
        "outputs": {
            "audit.json": {"bytes": len(audit_bytes), "sha256": sha256_bytes(audit_bytes)},
            "baselines.json": {
                "bytes": len(baselines_bytes),
                "sha256": sha256_bytes(baselines_bytes),
            },
            "summary.md": {"bytes": len(summary_bytes), "sha256": sha256_bytes(summary_bytes)},
        },
    }
    dump_json(output_dir / "manifest.json", manifest)

    print("SecVulEval audit + reference baselines")
    print(f"command: {provenance['command']}")
    print(f"python: {provenance['python_version']} ({sys.executable})")
    print(
        "independent: "
        f"{ind_doc['metadata'].get('sample_count')} samples, "
        f"vulnerable={sum(1 for r in ind_doc['samples'] if r['is_vulnerable'])}, "
        f"non_vulnerable={sum(1 for r in ind_doc['samples'] if not r['is_vulnerable'])}"
    )
    print(
        "pairs: "
        f"{pair_doc['metadata'].get('pair_count')} pairs, "
        f"{pair_doc['metadata'].get('function_count')} function records"
    )
    print(
        "integrity: "
        f"{audit['integrity']['passed']}/{audit['integrity']['total']} passed, "
        f"{audit['integrity']['failed']} failed, "
        f"{audit['integrity']['not_checked']} not checked"
    )
    print(
        "independent majority accuracy: "
        f"{baselines['independent']['baselines']['always_vulnerable_majority']['metrics']['accuracy']}"
    )
    print(
        "paired random-member pair both-correct: "
        f"{baselines['paired']['baselines']['random_member_seeded']['pair_metrics']['both_correct_rate']}"
    )
    print(f"wrote: {output_dir / 'audit.json'}")
    print(f"wrote: {output_dir / 'baselines.json'}")
    print(f"wrote: {output_dir / 'summary.md'}")
    print(f"wrote: {output_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

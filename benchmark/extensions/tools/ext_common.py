#!/usr/bin/env python3
"""Shared definitions for ``benchmark/extensions``.

The extension layer deliberately reuses the parent canonical record schema and
``benchmark/tools/bench_common.py`` arithmetic. This module adds only:

* the design / static-tool / fault-type registries;
* canonical unit-ID and Juliet/SecVulEval lookup helpers;
* raw-record field picking and secret-field screening;
* static-diagnostic normalization (rule -> CWE-401, scope, dedup, severity);
* coverage and agreement helpers used by the extension metrics.

It is standard-library only. Nothing here calls a model, a network endpoint or
an analyzer.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

EXTENSION_DIR = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = EXTENSION_DIR.parent
PROJECT_ROOT = BENCHMARK_DIR.parent
PARENT_TOOLS = BENCHMARK_DIR / "tools"
sys.path.insert(0, str(PARENT_TOOLS))

from bench_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    DEFAULT_CONFIDENCE,
    PROTOCOL_VERSION,
    PREDICTION_SCHEMA_VERSION,
    RUN_SCHEMA_VERSION,
    STATUSES,
    TASKS,
    as_bool,
    atomic_write_json,
    atomic_write_text,
    cluster_bootstrap,
    cost_summary,
    count_by,
    detection_scores,
    holm_adjust,
    mcnemar_exact,
    pair_scores,
    percentile,
    p50_p95,
    read_json,
    read_jsonl,
    sha256_file,
    sha256_text,
    utc_now,
    wilson_interval,
)

EXTENSION_VERSION = "0.3.0"
DESIGN_REGISTRY_VERSION = "2026-11-22.1"
EXTENSION_MANIFEST_SCHEMA = "benchmark-extension-manifest-v1"
EXTENSION_METRICS_SCHEMA = "benchmark-extension-metrics-v1"

DESIGNS_PATH = EXTENSION_DIR / "registry" / "designs.json"
STATIC_TOOLS_PATH = EXTENSION_DIR / "registry" / "static_tools.json"
FAULT_TYPES_PATH = EXTENSION_DIR / "registry" / "fault_types.json"

STATIC_DIAGNOSTIC_SCHEMA_VERSION = "benchmark-static-diagnostic-v1"

DESIGN_IDS = (
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
)

SECRET_KEY_RE = re.compile(
    r"(authorization|api[_-]?key|apikey|x-api-key|secret|password|bearer|"
    r"credential|private[_-]?key|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
BRACKET_RULE_RE = re.compile(r"\[([^\[\]]+)\]\s*$")

_CACHE: dict[str, Any] = {}


class ExtensionError(Exception):
    """Raised when an extension artifact cannot be interpreted unambiguously."""


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


def _load_json_cached(path: Path) -> dict[str, Any]:
    key = str(path)
    if key not in _CACHE:
        try:
            value = read_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            raise ExtensionError(f"cannot read registry {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ExtensionError(f"registry {path} must be a JSON object")
        _CACHE[key] = value
    return _CACHE[key]


def design_registry() -> dict[str, Any]:
    return _load_json_cached(DESIGNS_PATH)


def design_spec(design_id: str) -> dict[str, Any]:
    designs = design_registry().get("designs") or []
    for spec in designs:
        if spec.get("design_id") == design_id:
            return spec
    raise ExtensionError(
        f"unknown design {design_id!r}; expected one of {[d.get('design_id') for d in designs]}"
    )


def design_ids() -> list[str]:
    return [str(d.get("design_id")) for d in design_registry().get("designs") or []]


def static_tool_registry() -> dict[str, Any]:
    return _load_json_cached(STATIC_TOOLS_PATH)


def static_tool_spec(tool_id: str) -> dict[str, Any]:
    tools = static_tool_registry().get("tools") or {}
    if tool_id not in tools:
        raise ExtensionError(
            f"unknown static tool_id {tool_id!r}; expected one of {sorted(tools)}"
        )
    return tools[tool_id]


def fault_type_registry() -> dict[str, Any]:
    return _load_json_cached(FAULT_TYPES_PATH)


def fault_type_spec(fault_type: str) -> dict[str, Any]:
    faults = fault_type_registry().get("fault_types") or {}
    if fault_type not in faults:
        raise ExtensionError(
            f"unknown fault_type {fault_type!r}; expected one of {sorted(faults)}"
        )
    return faults[fault_type]


# ---------------------------------------------------------------------------
# Basic IO / field helpers
# ---------------------------------------------------------------------------


def project_root() -> Path:
    return PROJECT_ROOT


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def record_sha256(record: Mapping[str, Any]) -> str:
    return sha256_text(stable_json(dict(record)))


def resolve_path(value: str | Path, bases: Sequence[str | Path]) -> Path:
    path = Path(value).expanduser()
    candidates = [path] if path.is_absolute() else [Path(base) / path for base in bases]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve()


def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Load JSONL or a JSON array / wrapper object without changing records."""

    target = Path(path)
    if target.suffix.lower() == ".jsonl":
        return read_jsonl(target)
    try:
        data = read_json(target)
    except json.JSONDecodeError as exc:
        raise ExtensionError(f"{target}: invalid JSON: {exc}") from exc
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("records", "results", "predictions", "claims", "faults", "samples", "units"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    raise ExtensionError(f"{target}: expected a JSON array or an object with a records/results list")


def load_claim_manifest(path: str | Path) -> dict[str, Any]:
    data = read_json(path)
    if not isinstance(data, dict):
        raise ExtensionError(f"{path}: claim manifest must be a JSON object")
    claims = data.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ExtensionError(f"{path}: claim manifest needs a non-empty 'claims' array")
    seen: set[str] = set()
    for index, claim in enumerate(claims, start=1):
        if not isinstance(claim, dict):
            raise ExtensionError(f"{path}: claim {index} must be an object")
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id:
            raise ExtensionError(f"{path}: claim {index} missing claim_id")
        if claim_id in seen:
            raise ExtensionError(f"{path}: duplicate claim_id {claim_id!r}")
        seen.add(claim_id)
    return data


def load_fault_manifest(path: str | Path) -> dict[str, Any]:
    data = read_json(path)
    if not isinstance(data, dict):
        raise ExtensionError(f"{path}: fault manifest must be a JSON object")
    faults = data.get("faults")
    if not isinstance(faults, list) or not faults:
        raise ExtensionError(f"{path}: fault manifest needs a non-empty 'faults' array")
    seen: set[str] = set()
    for index, fault in enumerate(faults, start=1):
        if not isinstance(fault, dict):
            raise ExtensionError(f"{path}: fault {index} must be an object")
        fault_id = fault.get("fault_id")
        if not isinstance(fault_id, str) or not fault_id:
            raise ExtensionError(f"{path}: fault {index} missing fault_id")
        if fault_id in seen:
            raise ExtensionError(f"{path}: duplicate fault_id {fault_id!r}")
        seen.add(fault_id)
    return data


def pick(obj: Any, *keys: str, default: Any = None) -> Any:
    """Pick the first present dotted key; None values fall through to the next key."""

    for key in keys:
        if not key:
            continue
        current = obj
        ok = True
        for part in str(key).split("."):
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                ok = False
                break
        if ok and current is not None:
            return current
    return default


def first_str(obj: Any, *keys: str, default: str | None = None) -> str | None:
    value = pick(obj, *keys, default=None)
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip()
        return text or default
    return str(value)


def as_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def as_int(value: Any) -> int | None:
    number = as_number(value)
    if number is None or not math.isfinite(number):
        return None
    return int(number)


def dedupe_strings(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def normalize_cwe_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    found: set[int] = set()
    for item in values:
        if item is None:
            continue
        for match in CWE_RE.findall(str(item)):
            found.add(int(match))
    return [f"CWE-{number}" for number in sorted(found)]


# ---------------------------------------------------------------------------
# Security guard
# ---------------------------------------------------------------------------


def check_no_secret_fields(value: Any, path: str = "$") -> None:
    """Refuse to write secret-like keys anywhere in a canonical artifact.

    Only keys are screened; values are not pattern-matched, so prompt-token
    counters and model IDs are not false positives. The error never echoes the
    value, only its location.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if SECRET_KEY_RE.search(key_text):
                raise ExtensionError(
                    f"secret-like field at {path}.{key_text}; refusing to write canonical output"
                )
            check_no_secret_fields(item, f"{path}.{key_text}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            check_no_secret_fields(item, f"{path}[{index}]")


# ---------------------------------------------------------------------------
# Status / IDs
# ---------------------------------------------------------------------------


_STATUS_ALIASES = {
    "ok": "ok",
    "success": "ok",
    "succeeded": "ok",
    "completed": "ok",
    "valid": "ok",
    "schema_invalid": "schema_invalid",
    "invalid": "schema_invalid",
    "parse_error": "schema_invalid",
    "parse_failed": "schema_invalid",
    "json_invalid": "schema_invalid",
    "api_error": "api_error",
    "http_error": "api_error",
    "network_error": "api_error",
    "timeout": "timeout",
    "timed_out": "timeout",
    "tool_error": "tool_error",
    "internal_error": "tool_error",
    "compile_error": "compile_error",
    "compile_failed": "compile_error",
    "harness_error": "harness_error",
    "crash": "crash",
    "segfault": "crash",
    "unsupported": "unsupported",
    "not_applicable": "not_applicable",
    "unavailable": "not_applicable",
    "inconclusive": "inconclusive",
    "skipped_budget": "skipped_budget",
    "not_run": "not_run",
    "pending": "not_run",
    "missing": "not_run",
}


def normalize_status(value: Any, *, default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in _STATUS_ALIASES:
        return _STATUS_ALIASES[text]
    if text in STATUSES:
        return text
    return default


def canonical_pair_unit_id(pair_id: str, side: str) -> str:
    return f"secvul:pair:{pair_id}:{side}"


def canonical_claim_unit_id(tier: str, claim_id: str) -> str:
    return f"{tier}:claim:{claim_id}"


def canonical_fault_unit_id(base_unit_id: str, fault_id: str) -> str:
    return f"{base_unit_id}:fault:{fault_id}"


def parse_juliet_unit_id(unit_id: str) -> tuple[str, str]:
    """Return ``(group_id, side)`` for canonical or upstream Juliet unit IDs."""

    text = str(unit_id).strip()
    if text.startswith("juliet:"):
        rest = text[len("juliet:") :]
        for side in ("bad", "good"):
            suffix = f":{side}"
            if rest.endswith(suffix):
                group = rest[: -len(suffix)]
                if group:
                    return group, side
        raise ExtensionError(f"cannot parse Juliet unit_id {unit_id!r}")
    for side in ("bad", "good"):
        suffix = f"__{side}"
        if text.endswith(suffix):
            group = text[: -len(suffix)]
            if group:
                return group, side
    raise ExtensionError(f"cannot parse Juliet unit_id {unit_id!r}")


def juliet_unit_index(path: str | Path) -> dict[str, dict[str, Any]]:
    """Index ``juliet/subset_units.jsonl`` by upstream, canonical and group__label IDs."""

    index: dict[str, dict[str, Any]] = {}
    for record in load_records(path):
        upstream = record.get("unit_id")
        group = record.get("group_id")
        label = record.get("label")
        if not isinstance(upstream, str) or not isinstance(group, str) or label not in ("bad", "good"):
            raise ExtensionError(f"{path}: malformed subset unit {upstream!r}")
        canonical = f"juliet:{group}:{label}"
        meta = {
            "unit_id": canonical,
            "upstream_unit_id": upstream,
            "group_id": group,
            "family": record.get("family") or "unknown",
            "split": record.get("split"),
            "label": label,
            "sources": record.get("sources") or [],
            "language": record.get("language"),
        }
        for key in (upstream, canonical, f"{group}__{label}"):
            if key in index and index[key]["unit_id"] != canonical:
                raise ExtensionError(f"{path}: duplicate unit key {key!r}")
            index[key] = meta
    return index


def pair_split_index(path: str | Path) -> dict[str, dict[str, Any]]:
    data = read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("pairs"), list):
        raise ExtensionError(f"{path}: expected a pair split object with a 'pairs' array")
    index: dict[str, dict[str, Any]] = {}
    for pair in data["pairs"]:
        if not isinstance(pair, dict):
            raise ExtensionError(f"{path}: pair entry must be an object")
        pair_id = pair.get("pair_id")
        if not isinstance(pair_id, str) or not pair_id:
            raise ExtensionError(f"{path}: pair entry missing pair_id")
        if pair_id in index:
            raise ExtensionError(f"{path}: duplicate pair_id {pair_id!r}")
        index[pair_id] = pair
    return index


# ---------------------------------------------------------------------------
# Run loading
# ---------------------------------------------------------------------------


def load_extension_run(
    run_dir: str | Path,
) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]], Path]:
    directory = Path(run_dir).resolve()
    manifest_path = directory / "run_manifest.json"
    if not manifest_path.exists():
        raise ExtensionError(f"missing run_manifest.json in {directory}")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ExtensionError(f"{manifest_path}: manifest must be an object")
    extension_path = directory / "extension_manifest.json"
    extension_manifest = read_json(extension_path) if extension_path.exists() else None
    if extension_manifest is not None and not isinstance(extension_manifest, dict):
        raise ExtensionError(f"{extension_path}: extension manifest must be an object")
    predictions_name = (manifest.get("artifacts") or {}).get("predictions") or "predictions.jsonl"
    predictions_path = directory / predictions_name
    if not predictions_path.exists():
        raise ExtensionError(f"missing predictions file: {predictions_path}")
    records = read_jsonl(predictions_path)
    return manifest, extension_manifest, records, predictions_path


def extension_block_design(record: Mapping[str, Any]) -> str | None:
    block = record.get("extensions")
    if not isinstance(block, Mapping):
        return None
    value = block.get("pair_design") or block.get("task_design")
    return str(value) if value else None


def infer_design(
    manifest: Mapping[str, Any],
    extension_manifest: Mapping[str, Any] | None,
    records: Sequence[Mapping[str, Any]],
) -> str:
    if isinstance(extension_manifest, Mapping):
        design = extension_manifest.get("design")
        if isinstance(design, str) and design:
            return design
    for record in records:
        design = extension_block_design(record)
        if design:
            return design
    strategy = (manifest.get("method") or {}).get("strategy")
    if isinstance(strategy, str):
        for candidate in DESIGN_IDS:
            if candidate in strategy:
                return candidate
    raise ExtensionError(
        "cannot infer extension design: add extension_manifest.json or extensions.pair_design/task_design"
    )


def write_jsonl(path: str | Path, records: Sequence[Mapping[str, Any]]) -> str:
    text = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        for record in records
    )
    atomic_write_text(path, text)
    return sha256_text(text)


# ---------------------------------------------------------------------------
# Static diagnostic normalization
# ---------------------------------------------------------------------------


def extract_rule(raw_rule: Any, message: Any) -> str | None:
    if raw_rule is not None and str(raw_rule).strip():
        return str(raw_rule).strip()
    if message is not None:
        match = BRACKET_RULE_RE.search(str(message))
        if match:
            return match.group(1).strip()
    return None


def path_in_targets(candidate: Any, targets: Sequence[str]) -> bool:
    if candidate is None or not targets:
        return False
    text = str(candidate).replace("\\", "/")
    for target in targets:
        if not target:
            continue
        target_text = str(target).replace("\\", "/")
        if text == target_text or text.endswith("/" + target_text) or target_text.endswith("/" + text):
            return True
    return False


def severity_class(severity: Any, policy: Mapping[str, Any] | None) -> str:
    text = str(severity or "unknown").strip().lower()
    policy = policy or {}
    for name in ("high", "medium", "low"):
        values = {str(item).strip().lower() for item in policy.get(name) or []}
        if text in values:
            return name
    return "unknown"


def map_static_rule(
    tool_spec: Mapping[str, Any],
    raw_rule: str | None,
    cwe_values: Sequence[str],
    *,
    allow_cwe_fallback: bool = True,
) -> tuple[str | None, bool, str]:
    """Return ``(mapped_cwe, counts_for_cwe401, mapping_basis)``."""

    rules = tool_spec.get("rules") or {}
    if raw_rule:
        for key, spec in rules.items():
            if raw_rule == key or raw_rule.lower() == str(key).lower():
                cwe = spec.get("cwe")
                counts = bool(spec.get("counts_for_cwe401", cwe == "CWE-401"))
                return (str(cwe) if cwe else None, counts and cwe == "CWE-401", "registry")
        for prefix in tool_spec.get("rule_prefixes") or []:
            if raw_rule.startswith(prefix):
                spec = rules.get(prefix)
                if isinstance(spec, Mapping):
                    cwe = spec.get("cwe")
                    counts = bool(spec.get("counts_for_cwe401", cwe == "CWE-401"))
                    return (str(cwe) if cwe else None, counts and cwe == "CWE-401", "registry")
    if allow_cwe_fallback and tool_spec.get("allow_cwe_fallback") and "CWE-401" in cwe_values:
        return "CWE-401", True, "cwe_field"
    return None, False, "unmapped"


def normalize_diagnostic(
    raw: Mapping[str, Any],
    *,
    tool_spec: Mapping[str, Any],
    target_files: Sequence[str],
    scope_kind: str,
    line_start: int | None = None,
    line_end: int | None = None,
    default_suppressed: bool = False,
) -> dict[str, Any]:
    rule = extract_rule(
        pick(raw, "rule_id", "rule", "check", "checker", "warning", "code", "query_id", "query_name"),
        pick(raw, "message", "text", "description"),
    )
    message = str(pick(raw, "message", "text", "description", default="") or "")
    severity = str(pick(raw, "severity", "level", default="unknown") or "unknown")
    file_value = pick(raw, "file", "path", "location.file", "filename")
    line = as_int(pick(raw, "line", "location.line", "start_line"))
    column = as_int(pick(raw, "column", "col", "location.column", "start_column"))
    cwe_values = normalize_cwe_list(pick(raw, "cwe", "cwe_list", "cwes"))
    if not cwe_values:
        # Only explicit bracketed CWE tags (e.g. GCC's "[CWE-401]"). Do not
        # scan free text: Juliet identifiers such as CWE401_Memory_Leak would
        # otherwise be misread as a CWE assertion.
        cwe_values = [
            f"CWE-{match}"
            for match in re.findall(r"\[CWE-(\d+)\]", message)
        ]
    raw_is_cwe401 = as_bool(pick(raw, "is_cwe401", "is_cwe_401"))
    raw_counts_as_finding = as_bool(pick(raw, "counts_as_finding"))
    allow_fallback = raw_is_cwe401 is not False and raw_counts_as_finding is not False
    mapped_cwe, counts, basis = map_static_rule(
        tool_spec, rule, cwe_values, allow_cwe_fallback=allow_fallback
    )
    policy = tool_spec.get("severity_policy") or {}
    sev_class = severity_class(severity, policy)
    if scope_kind == "target_function":
        in_scope = bool(
            path_in_targets(file_value, target_files)
            and line is not None
            and line_start is not None
            and line_end is not None
            and line_start <= line <= line_end
        )
    else:
        in_scope = path_in_targets(file_value, target_files)
    raw_in_target_file = as_bool(pick(raw, "in_target_file"))
    raw_in_target_region = as_bool(pick(raw, "in_target_region"))
    if raw_in_target_file is not None:
        in_scope = in_scope and raw_in_target_file
    if raw_in_target_region is not None:
        in_scope = in_scope and raw_in_target_region
    if raw_counts_as_finding is False:
        in_scope = False
    suppressed = bool(pick(raw, "suppressed", default=default_suppressed))
    key = sha256_text(
        f"{Path(str(file_value or '')).name}|{line}|{column}|{rule or 'unknown'}"
    )
    trace = pick(raw, "trace", "events", "path", default=[])
    if not isinstance(trace, list):
        trace = []
    return {
        "schema_version": STATIC_DIAGNOSTIC_SCHEMA_VERSION,
        "rule_id": rule or "unknown",
        "raw_rule": rule,
        "severity": severity,
        "severity_class": sev_class,
        "message": message,
        "file": str(file_value) if file_value is not None else None,
        "line": line,
        "column": column,
        "cwe": cwe_values,
        "mapped_cwe": mapped_cwe,
        "counts_for_cwe401": bool(counts),
        "in_scope": bool(in_scope),
        "suppressed": suppressed,
        "dedup_key": key,
        "mapping_basis": basis,
        "trace": trace,
        "notes": None,
    }


def summarize_diagnostics(diagnostics: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    raw_count = len(diagnostics)
    unique: dict[str, Mapping[str, Any]] = {}
    for diagnostic in diagnostics:
        unique.setdefault(str(diagnostic.get("dedup_key")), diagnostic)
    mapped: dict[str, Mapping[str, Any]] = {}
    unmapped: dict[str, Mapping[str, Any]] = {}
    out_of_scope: dict[str, Mapping[str, Any]] = {}
    suppressed: dict[str, Mapping[str, Any]] = {}
    high_mapped: dict[str, Mapping[str, Any]] = {}
    for key, diagnostic in unique.items():
        if diagnostic.get("suppressed"):
            suppressed[key] = diagnostic
            continue
        if not diagnostic.get("counts_for_cwe401"):
            unmapped[key] = diagnostic
            continue
        if not diagnostic.get("in_scope"):
            out_of_scope[key] = diagnostic
            continue
        mapped[key] = diagnostic
        if diagnostic.get("severity_class") == "high":
            high_mapped[key] = diagnostic
    return {
        "raw_warning_count": raw_count,
        "dedup_warning_count": len(unique),
        "mapped_warning_count": len(mapped),
        "unmapped_warning_count": len(unmapped),
        "out_of_scope_count": len(out_of_scope),
        "suppressed_count": len(suppressed),
        "high_mapped_warning_count": len(high_mapped),
        "mapped_rule_ids": sorted({str(d.get("rule_id")) for d in mapped.values()}),
        "severity_counts": count_by(str(d.get("severity_class")) for d in unique.values()),
    }


# ---------------------------------------------------------------------------
# Coverage / agreement helpers
# ---------------------------------------------------------------------------


def coverage_sufficient(record: Mapping[str, Any], threshold: float) -> bool:
    coverage = record.get("coverage")
    if not isinstance(coverage, Mapping):
        return False
    if coverage.get("target_function_entered") is False:
        return False
    value = coverage.get("line_coverage")
    if value is None:
        return False
    try:
        return float(value) >= float(threshold)
    except (TypeError, ValueError):
        return False


def coverage_bucket(record: Mapping[str, Any]) -> str:
    coverage = record.get("coverage")
    if not isinstance(coverage, Mapping):
        return "unknown"
    value = coverage.get("line_coverage")
    if value is None:
        return "unknown"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if number >= 0.9:
        return "ge_0.90"
    if number >= 0.5:
        return "0.50_0.90"
    return "lt_0.50"


def cohen_kappa(a: Sequence[bool], b: Sequence[bool]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    n = len(a)
    observed = sum(1 for x, y in zip(a, b) if x == y) / n
    pa = sum(1 for x in a if x) / n
    pb = sum(1 for y in b if y) / n
    expected = pa * pb + (1.0 - pa) * (1.0 - pb)
    if expected >= 1.0:
        return 1.0 if observed >= 1.0 else 0.0
    return (observed - expected) / (1.0 - expected)


def agreement_counts(a: Sequence[bool], b: Sequence[bool]) -> dict[str, int]:
    both_true = sum(1 for x, y in zip(a, b) if x and y)
    both_false = sum(1 for x, y in zip(a, b) if not x and not y)
    a_only = sum(1 for x, y in zip(a, b) if x and not y)
    b_only = sum(1 for x, y in zip(a, b) if not x and y)
    return {
        "both_true": both_true,
        "both_false": both_false,
        "a_only": a_only,
        "b_only": b_only,
        "agree": both_true + both_false,
        "disagree": a_only + b_only,
        "n": len(a),
    }


def rate(numerator: int | float, denominator: int | float) -> float | None:
    if denominator is None or denominator == 0:
        return None
    return float(numerator) / float(denominator)


def fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)

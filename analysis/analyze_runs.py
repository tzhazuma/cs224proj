#!/usr/bin/env python3
"""Aggregate real SecVulEval runner runs into analysis JSON and Markdown.

The script reads completed runner directories containing ``results.jsonl`` and
``metrics.json``.  It never creates or imputes predictions.  Schema-invalid and
API-error records are reported as invalid; they are not silently replaced.

Only the Python standard library is required.  The runner's context sanitizer
is imported when available so that the context strata use exactly the same
allow-list as the prompts; otherwise a local AST fallback is used.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:  # package import: python3 -m analysis.analyze_runs
    from . import stats
except ImportError:  # direct script execution: python3 analysis/analyze_runs.py
    import stats  # type: ignore

ANALYSIS_VERSION = "1.0.0"
SCHEMA_VERSION = 1
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS_ROOT = PROJECT_ROOT / "runner" / "runs"
DEFAULT_DATASET_ROOT = PROJECT_ROOT / "datasets"
DEFAULT_OUT_JSON = Path(__file__).resolve().parent / "aggregation.json"
DEFAULT_OUT_MD = Path(__file__).resolve().parent / "aggregation.md"
DEFAULT_DATASET_FILES = {
    "independent": "independent_200.json",
    "pairs": "vulnerable_fixed_200_pairs.json",
}
STRATEGIES = ("direct", "few-shot", "context")
STRATEGY_LABELS = {
    "direct": "M1 direct",
    "few-shot": "M2 few-shot",
    "context": "M3 context",
}
CONTEXT_STATES = ("nonempty", "empty", "unparsed", "unknown")
CONTEXT_ALLOWED_KEYS = (
    "Execution Environment",
    "External Function",
    "Function Argument",
    "Globals",
    "Type Execution Declaration",
)
M3_REPORTING_REQUIREMENTS = [
    "报告 M3 时必须同时给出 context 非空/空分层的 n 与指标，不能只报总体值。",
    "不得把 M3 与 M1 的总体差异单独归因于“上下文推理能力”；差异与上下文可用性混杂。",
    "若某个分层是单类别，macro-F1 与 balanced accuracy 不可定义，应报告正类 F1/召回或负类 specificity，而不是填 0。",
    "上下文分层属于预先登记的探索性分析；样本过少的分层必须标注 n，并避免强结论。",
    "更严格的因果比较需要标签无关的上下文构造，并作为新策略单独登记、重新运行。",
]


class AnalysisError(Exception):
    """Raised for invalid analysis inputs or configuration."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: Any) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    atomic_write_text(path, text)


def normalize_idx(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _prompt_context_state(record: Mapping[str, Any]) -> str:
    prompt = record.get("prompt")
    if not isinstance(prompt, Mapping):
        return "unknown"
    context = prompt.get("context")
    if not isinstance(context, Mapping) or context.get("used") is not True:
        return "unknown"
    if context.get("parse_ok") is False:
        return "unparsed"
    return "nonempty" if context.get("nonempty") is True else "empty"


def _extract_prediction(record: Mapping[str, Any]) -> bool | None:
    if record.get("status") != "ok":
        return None
    parsed = record.get("parsed")
    if not isinstance(parsed, Mapping):
        return None
    value = parsed.get("is_vulnerable")
    return value if _is_bool(value) else None


def _constant_strings(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            yield node.value
        elif _is_number(node.value):
            yield str(node.value)
        return
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for child in node.elts:
            yield from _constant_strings(child)
        return
    if isinstance(node, ast.Call):
        if node.args:
            yield from _constant_strings(node.args[0])


def _local_context_state(raw: Any) -> str:
    """Coarse fallback when the runner package is unavailable."""

    if raw is None or not str(raw).strip():
        return "empty"
    try:
        tree = ast.parse(str(raw).strip(), mode="eval")
    except SyntaxError:
        return "unparsed"
    if not isinstance(tree.body, ast.Dict):
        return "unparsed"
    for key_node, value_node in zip(tree.body.keys, tree.body.values):
        if not isinstance(key_node, ast.Constant) or key_node.value not in CONTEXT_ALLOWED_KEYS:
            continue
        for value in _constant_strings(value_node):
            if " ".join(value.split()):
                return "nonempty"
    return "empty"


class ContextClassifier:
    """Classify raw context as nonempty / empty / unparsed using the runner rules."""

    def __init__(self) -> None:
        self._extractor: Any = None
        self.source = "local_ast_fallback"
        try:
            from secvul_runner.context import extract_safe_context  # type: ignore

            self._extractor = extract_safe_context
            self.source = "runner.secvul_runner.context.extract_safe_context"
            return
        except Exception:
            pass
        runner_dir = PROJECT_ROOT / "runner"
        if runner_dir.is_dir():
            sys.path.insert(0, str(runner_dir))
            try:
                from secvul_runner.context import extract_safe_context  # type: ignore

                self._extractor = extract_safe_context
                self.source = "runner.secvul_runner.context.extract_safe_context"
            except Exception:
                self._extractor = None

    def state(self, raw: Any) -> str:
        if raw is not None and not isinstance(raw, str):
            raw = str(raw)
        if self._extractor is not None:
            try:
                safe = self._extractor(raw)
            except Exception:
                return "unparsed"
            if safe.provided and not safe.parse_ok:
                return "unparsed"
            return "nonempty" if safe.sections else "empty"
        return _local_context_state(raw)


# ---------------------------------------------------------------------------
# Dataset indexing
# ---------------------------------------------------------------------------


@dataclass
class DatasetInfo:
    path: Path
    dataset_type: str
    sha256: str
    metadata: dict[str, Any]
    order: list[str]
    records: dict[str, dict[str, Any]]
    pair_info: dict[str, dict[str, Any]]
    label_counts: dict[str, int]
    project_count: int
    context_audit: dict[str, Any]
    context_source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "dataset_type": self.dataset_type,
            "sha256": self.sha256,
            "metadata": {
                key: self.metadata.get(key)
                for key in (
                    "schema_version",
                    "source_file",
                    "source_sha256",
                    "source_sheet",
                    "source_rows",
                    "source_label_counts",
                    "seed",
                    "dataset_type",
                    "pair_count",
                    "function_count",
                )
                if key in self.metadata
            },
            "n_units": len(self.order),
            "n_records": len(self.records),
            "label_counts": self.label_counts,
            "project_count": self.project_count,
            "context_source": self.context_source,
            "context_audit": self.context_audit,
        }


def _context_risk_independent(counts: dict[str, dict[str, int]]) -> dict[str, Any]:
    nonempty = counts.get("nonempty", {"vulnerable": 0, "non_vulnerable": 0})
    empty = counts.get("empty", {"vulnerable": 0, "non_vulnerable": 0})
    n_nonempty = nonempty["vulnerable"] + nonempty["non_vulnerable"]
    n_empty = empty["vulnerable"] + empty["non_vulnerable"]
    p_nonempty = nonempty["vulnerable"] / n_nonempty if n_nonempty else None
    p_empty = empty["vulnerable"] / n_empty if n_empty else None
    gap = abs(p_nonempty - p_empty) if p_nonempty is not None and p_empty is not None else None
    nonempty_single = n_nonempty > 0 and (nonempty["vulnerable"] == 0 or nonempty["non_vulnerable"] == 0)
    empty_single = n_empty > 0 and (empty["vulnerable"] == 0 or empty["non_vulnerable"] == 0)

    reasons: list[str] = []
    flags: list[str] = []
    if nonempty_single:
        reasons.append(
            f"context 非空层 {n_nonempty} 条全部为"
            f"{'漏洞' if nonempty['vulnerable'] else '非漏洞'}样本"
        )
        flags.append("nonempty_stratum_single_class")
    if empty_single:
        reasons.append(
            f"context 空层 {n_empty} 条全部为"
            f"{'漏洞' if empty['vulnerable'] else '非漏洞'}样本"
        )
        flags.append("empty_stratum_single_class")
    if gap is not None and gap >= 0.5:
        reasons.append(f"非空层与空层的漏洞比例相差 {gap:.3f}")
    if counts.get("unparsed", {}).get("vulnerable", 0) + counts.get("unparsed", {}).get("non_vulnerable", 0):
        flags.append("context_parse_failures")

    if n_nonempty == 0 or n_empty == 0:
        risk = "not_assessable"
        reasons.append("至少一个 context 分层为空，无法比较")
    elif nonempty_single or empty_single or (gap is not None and gap >= 0.5):
        risk = "high"
    elif gap is not None and gap >= 0.2:
        risk = "medium"
    else:
        risk = "low"

    return {
        "counts": counts,
        "n_nonempty": n_nonempty,
        "n_empty": n_empty,
        "p_vulnerable_nonempty": p_nonempty,
        "p_vulnerable_empty": p_empty,
        "association_gap": gap,
        "nonempty_single_class": nonempty_single,
        "empty_single_class": empty_single,
        "risk_level": risk,
        "flags": flags,
        "reasons": reasons,
    }


def _context_audit_pairs(pair_states: list[tuple[str, str]]) -> dict[str, Any]:
    combo: dict[str, int] = {}
    side_counts: dict[str, dict[str, int]] = {}
    for vulnerable_state, fixed_state in pair_states:
        key = f"vulnerable={vulnerable_state},fixed={fixed_state}"
        combo[key] = combo.get(key, 0) + 1
        for state, label in ((vulnerable_state, "vulnerable"), (fixed_state, "non_vulnerable")):
            bucket = side_counts.setdefault(state, {"vulnerable": 0, "non_vulnerable": 0})
            bucket[label] += 1

    empty_pairs = sum(1 for v, f in pair_states if v == "empty" and f == "empty")
    nonempty_pairs = sum(1 for v, f in pair_states if v == "nonempty" and f == "nonempty")
    mixed_pairs = len(pair_states) - empty_pairs - nonempty_pairs
    pair_state_counts: dict[str, int] = {}
    for vulnerable_state, _fixed_state in pair_states:
        pair_state_counts[vulnerable_state] = pair_state_counts.get(vulnerable_state, 0) + 1
    small = {state: n for state, n in pair_state_counts.items() if n < 10}
    flags = ["small_stratum"] if small else []
    if any(counts["vulnerable"] == 0 or counts["non_vulnerable"] == 0 for counts in side_counts.values()):
        flags.append("context_stratum_single_class")

    reasons = [
        "配对数据中漏洞侧与修复侧共享同一函数的上下文可用性；context 非空本身不能区分两侧标签。",
        "配对标签由 side 固定（漏洞侧=1，修复侧=0），因此按 side 展开后每个 context 层都同时包含两类。",
    ]
    if small:
        reasons.append(f"以下 context 分层的对数少于 10，分层结果不稳定：{small}")
    risk = "low"
    if "context_stratum_single_class" in flags:
        risk = "medium"

    return {
        "pair_context_combinations": combo,
        "side_label_counts_by_context": side_counts,
        "empty_pairs": empty_pairs,
        "nonempty_pairs": nonempty_pairs,
        "mixed_pairs": mixed_pairs,
        "small_strata": small,
        "risk_level": risk,
        "flags": flags,
        "reasons": reasons,
        "note": "M3 的上下文伪影风险主要针对独立检测集；配对集的标签由 side 固定，风险较低，但空上下文层可能过小。",
    }


def load_dataset(path: Path, classifier: ContextClassifier, dataset_type_hint: str | None = None) -> DatasetInfo:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"cannot read dataset {path}: {exc}") from exc
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"dataset {path} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise AnalysisError(f"dataset {path}: top-level value must be an object")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}

    if isinstance(data.get("samples"), list):
        dataset_type = "independent"
        if dataset_type_hint and dataset_type_hint != dataset_type:
            raise AnalysisError(f"dataset {path} is {dataset_type}, run expects {dataset_type_hint}")
        order: list[str] = []
        records: dict[str, dict[str, Any]] = {}
        labels: dict[str, bool] = {}
        projects: set[str] = set()
        context_counts: dict[str, dict[str, int]] = {
            state: {"vulnerable": 0, "non_vulnerable": 0} for state in CONTEXT_STATES
        }
        for position, sample in enumerate(data["samples"]):
            if not isinstance(sample, dict):
                raise AnalysisError(f"dataset {path}: samples[{position}] must be an object")
            idx = normalize_idx(sample.get("idx"))
            if idx is None:
                raise AnalysisError(f"dataset {path}: samples[{position}] has no usable idx")
            if idx in records:
                raise AnalysisError(f"dataset {path}: duplicate idx {idx}")
            label = sample.get("is_vulnerable")
            if not _is_bool(label):
                raise AnalysisError(f"dataset {path}: idx {idx} has non-boolean is_vulnerable")
            project = sample.get("project")
            if not isinstance(project, str) or not project.strip():
                raise AnalysisError(f"dataset {path}: idx {idx} has no project")
            state = classifier.state(sample.get("context"))
            record = {
                "idx": idx,
                "label": label,
                "project": project,
                "context_state": state,
                "pair_id": None,
                "side": None,
            }
            records[idx] = record
            labels[idx] = label
            projects.add(project)
            order.append(idx)
            key = "vulnerable" if label else "non_vulnerable"
            context_counts[state][key] += 1

        vulnerable = sum(1 for label in labels.values() if label)
        label_counts = {"vulnerable": vulnerable, "non_vulnerable": len(labels) - vulnerable}
        context_audit = _context_risk_independent(context_counts)
        return DatasetInfo(
            path=path,
            dataset_type=dataset_type,
            sha256=digest,
            metadata=metadata,
            order=order,
            records=records,
            pair_info={},
            label_counts=label_counts,
            project_count=len(projects),
            context_audit=context_audit,
            context_source=classifier.source,
        )

    if isinstance(data.get("pairs"), list):
        dataset_type = "pairs"
        if dataset_type_hint and dataset_type_hint != dataset_type:
            raise AnalysisError(f"dataset {path} is {dataset_type}, run expects {dataset_type_hint}")
        order: list[str] = []
        records: dict[str, dict[str, Any]] = {}
        pair_info: dict[str, dict[str, Any]] = {}
        projects: set[str] = set()
        pair_states: list[tuple[str, str]] = []
        labels_count = {"vulnerable": 0, "non_vulnerable": 0}
        for position, pair in enumerate(data["pairs"]):
            if not isinstance(pair, dict):
                raise AnalysisError(f"dataset {path}: pairs[{position}] must be an object")
            pair_id = pair.get("pair_id")
            if not isinstance(pair_id, str) or not pair_id.strip():
                raise AnalysisError(f"dataset {path}: pairs[{position}] has no pair_id")
            if pair_id in pair_info:
                raise AnalysisError(f"dataset {path}: duplicate pair_id {pair_id}")
            vulnerable_raw = pair.get("vulnerable")
            fixed_raw = pair.get("fixed")
            if not isinstance(vulnerable_raw, dict) or not isinstance(fixed_raw, dict):
                raise AnalysisError(f"dataset {path}: pair {pair_id} must have two side objects")
            side_records: dict[str, dict[str, Any]] = {}
            for side_name, side_raw, expected_label in (
                ("vulnerable", vulnerable_raw, True),
                ("fixed", fixed_raw, False),
            ):
                idx = normalize_idx(side_raw.get("idx"))
                if idx is None:
                    raise AnalysisError(f"dataset {path}: pair {pair_id} {side_name} has no idx")
                if idx in records:
                    raise AnalysisError(f"dataset {path}: duplicate idx {idx}")
                label = side_raw.get("is_vulnerable")
                if label is not expected_label:
                    raise AnalysisError(
                        f"dataset {path}: pair {pair_id} {side_name} label must be {expected_label}"
                    )
                project = side_raw.get("project")
                if not isinstance(project, str) or not project.strip():
                    raise AnalysisError(f"dataset {path}: pair {pair_id} {side_name} has no project")
                state = classifier.state(side_raw.get("context"))
                record = {
                    "idx": idx,
                    "label": label,
                    "project": project,
                    "context_state": state,
                    "pair_id": pair_id,
                    "side": side_name,
                }
                records[idx] = record
                side_records[side_name] = record
                projects.add(project)
                labels_count["vulnerable" if label else "non_vulnerable"] += 1
            if side_records["vulnerable"]["project"] != side_records["fixed"]["project"]:
                raise AnalysisError(f"dataset {path}: pair {pair_id} project differs between sides")
            pair_info[pair_id] = {
                "pair_id": pair_id,
                "project": side_records["vulnerable"]["project"],
                "vulnerable_idx": side_records["vulnerable"]["idx"],
                "fixed_idx": side_records["fixed"]["idx"],
                "vulnerable_context_state": side_records["vulnerable"]["context_state"],
                "fixed_context_state": side_records["fixed"]["context_state"],
                "context_state": side_records["vulnerable"]["context_state"],
            }
            pair_states.append(
                (
                    side_records["vulnerable"]["context_state"],
                    side_records["fixed"]["context_state"],
                )
            )
            order.append(pair_id)

        context_audit = _context_audit_pairs(pair_states)
        return DatasetInfo(
            path=path,
            dataset_type=dataset_type,
            sha256=digest,
            metadata=metadata,
            order=order,
            records=records,
            pair_info=pair_info,
            label_counts=labels_count,
            project_count=len(projects),
            context_audit=context_audit,
            context_source=classifier.source,
        )

    raise AnalysisError(f"dataset {path}: expected a top-level 'samples' or 'pairs' list")


class DatasetStore:
    def __init__(self, root: Path, classifier: ContextClassifier) -> None:
        self.root = root
        self.classifier = classifier
        self._cache: dict[Path, DatasetInfo | None] = {}
        self._errors: dict[Path, str] = {}

    def get(self, path: Path) -> DatasetInfo | None:
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key not in self._cache:
            try:
                self._cache[key] = load_dataset(key, self.classifier)
            except AnalysisError as exc:
                self._cache[key] = None
                self._errors[key] = str(exc)
        return self._cache[key]

    def error_for(self, path: Path) -> str | None:
        try:
            key = path.resolve()
        except OSError:
            key = path
        return self._errors.get(key)

    def default_datasets(self) -> list[DatasetInfo]:
        output: list[DatasetInfo] = []
        for dataset_type, filename in DEFAULT_DATASET_FILES.items():
            path = self.root / filename
            if path.exists():
                info = self.get(path)
                if info is not None:
                    output.append(info)
        return output


# ---------------------------------------------------------------------------
# Runner directories
# ---------------------------------------------------------------------------


@dataclass
class RunData:
    path: Path
    run_id: str
    dataset_type: str
    strategy: str
    task: str
    model: str
    run_label: str
    partial: bool
    incomplete: bool
    fixture: bool
    dataset_path: str | None
    dataset_sha256: str | None
    completed_at: str | None
    manifest_status: str | None
    records: list[dict[str, Any]]
    metrics: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


def _skip(path: Path, reason: str, detail: str | None = None) -> dict[str, Any]:
    return {"path": str(path), "reason": reason, "detail": detail}


def discover_run_dirs(root: Path, explicit: Sequence[Path]) -> list[Path]:
    if explicit:
        chosen: set[Path] = set()
        for raw in explicit:
            path = Path(raw).expanduser()
            if path.is_file():
                path = path.parent
            chosen.add(path.resolve())
        return sorted(chosen, key=lambda p: str(p))
    if not root.exists():
        return []
    candidates: set[Path] = set()
    for filename in ("metrics.json", "results.jsonl"):
        for path in root.rglob(filename):
            if any(part in {"cache", "__pycache__", ".git"} for part in path.parts):
                continue
            candidates.add(path.parent.resolve())
    return sorted(candidates, key=lambda p: str(p))


def load_run(
    path: Path,
    *,
    allow_fixture: bool,
    include_partial: bool,
    allow_incomplete: bool,
) -> tuple[RunData | None, dict[str, Any] | None]:
    metrics_path = path / "metrics.json"
    results_path = path / "results.jsonl"
    if not metrics_path.exists():
        return None, _skip(path, "missing_metrics_json")
    if not results_path.exists():
        return None, _skip(path, "missing_results_jsonl")

    try:
        metrics = read_json(metrics_path)
    except (OSError, json.JSONDecodeError) as exc:
        return None, _skip(path, "unreadable_metrics_json", str(exc))
    if not isinstance(metrics, dict) or metrics.get("schema_version") != 1:
        return None, _skip(path, "unsupported_metrics_schema")
    run_meta = metrics.get("run")
    if not isinstance(run_meta, dict):
        return None, _skip(path, "missing_run_metadata")

    dataset_type = run_meta.get("dataset_type")
    strategy = run_meta.get("strategy")
    task = run_meta.get("task")
    model = run_meta.get("model")
    if dataset_type not in {"independent", "pairs"}:
        return None, _skip(path, "unsupported_dataset_type", str(dataset_type))
    if strategy not in STRATEGIES:
        return None, _skip(path, "unsupported_strategy", str(strategy))
    if task not in {"detection", "both"}:
        return None, _skip(path, "no_detection_task", str(task))
    if not isinstance(model, str) or not model.strip():
        return None, _skip(path, "missing_model")

    manifest_status: str | None = None
    manifest_path = path / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = read_json(manifest_path)
            if isinstance(manifest, dict) and isinstance(manifest.get("status"), str):
                manifest_status = manifest["status"]
        except (OSError, json.JSONDecodeError):
            manifest_status = None
    if manifest_status in {"failed", "interrupted"} and not allow_incomplete:
        return None, _skip(path, "manifest_not_completed", manifest_status)

    fixture = bool(run_meta.get("fixture")) or "FIXTURE" in model.upper()
    if isinstance(run_meta.get("run_label"), str) and "fixture" in run_meta["run_label"].lower():
        fixture = True
    if fixture and not allow_fixture:
        return None, _skip(path, "fixture_run_requires_allow_fixture")

    partial = bool(run_meta.get("partial"))
    try:
        if int(run_meta.get("limit") or 0) > 0:
            partial = True
    except (TypeError, ValueError):
        pass
    if partial and not include_partial:
        return None, _skip(path, "partial_run", f"limit={run_meta.get('limit')!r}")

    counts = metrics.get("counts") if isinstance(metrics.get("counts"), dict) else {}
    expected_requests = counts.get("expected_requests")
    recorded_requests = counts.get("records")
    missing_requests = counts.get("missing_requests")
    complete_flag = counts.get("complete_planned_requests")
    incomplete = False
    if complete_flag is False:
        incomplete = True
    if isinstance(missing_requests, int) and not isinstance(missing_requests, bool) and missing_requests > 0:
        incomplete = True
    if (
        isinstance(expected_requests, int)
        and isinstance(recorded_requests, int)
        and recorded_requests < expected_requests
    ):
        incomplete = True
    if incomplete and not allow_incomplete:
        return None, _skip(
            path,
            "incomplete_run",
            f"records={recorded_requests!r}, expected={expected_requests!r}, missing={missing_requests!r}",
        )

    records: list[dict[str, Any]] = []
    try:
        with results_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise AnalysisError(f"{results_path}:{line_number} is not a JSON object")
                records.append(value)
    except (OSError, json.JSONDecodeError, AnalysisError) as exc:
        return None, _skip(path, "unreadable_results_jsonl", str(exc))
    if not records:
        return None, _skip(path, "empty_results_jsonl")

    warnings: list[str] = []
    if manifest_status == "running":
        warnings.append("manifest status is 'running' although metrics.json exists")
    if manifest_status in {"failed", "interrupted"}:
        warnings.append(f"manifest status is {manifest_status!r}; included because --allow-incomplete was set")
    if isinstance(expected_requests, int) and len(records) < expected_requests:
        warnings.append(
            f"results.jsonl has {len(records)} records but metrics expected {expected_requests}"
        )

    return (
        RunData(
            path=path,
            run_id=str(run_meta.get("run_id") or path.name),
            dataset_type=str(dataset_type),
            strategy=str(strategy),
            task=str(task),
            model=model,
            run_label=str(run_meta.get("run_label") or ""),
            partial=partial,
            incomplete=incomplete,
            fixture=fixture,
            dataset_path=str(run_meta["dataset_path"]) if run_meta.get("dataset_path") else None,
            dataset_sha256=str(run_meta["dataset_sha256"]) if run_meta.get("dataset_sha256") else None,
            completed_at=str(run_meta.get("completed_at") or "") or None,
            manifest_status=manifest_status,
            records=records,
            metrics=metrics,
            warnings=warnings,
        ),
        None,
    )


def resolve_dataset_path(run: RunData, dataset_root: Path) -> Path | None:
    candidates: list[Path] = []
    if run.dataset_path:
        raw = Path(run.dataset_path)
        if raw.is_absolute():
            candidates.append(raw)
        else:
            candidates.extend(
                [
                    PROJECT_ROOT / raw,
                    run.path / raw,
                    run.path.parent / raw,
                    dataset_root / raw.name,
                ]
            )
    default_name = DEFAULT_DATASET_FILES.get(run.dataset_type)
    if default_name:
        candidates.append(dataset_root / default_name)
    existing: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        key = str(resolved)
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        existing.append(resolved)
    if not existing:
        return None
    if run.dataset_sha256:
        for candidate in existing:
            try:
                if sha256_file(candidate) == run.dataset_sha256:
                    return candidate
            except OSError:
                continue
    return existing[0]


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


@dataclass
class Unit:
    key: str
    sample_id: str
    idx: str | None
    label: bool
    pred: bool | None
    status: str
    project: str | None
    context_state: str


@dataclass
class PairUnit:
    key: str
    project: str | None
    context_state: str
    fixed_context_state: str
    vulnerable: Unit
    fixed: Unit
    from_dataset: bool


def build_independent_units(run: RunData, dataset: DatasetInfo | None) -> list[Unit]:
    detection_records = [record for record in run.records if record.get("task") == "detection"]
    if not detection_records:
        raise AnalysisError(f"{run.path}: no detection records")
    units: list[Unit] = []
    seen: set[str] = set()
    for position, record in enumerate(detection_records):
        idx = normalize_idx(record.get("idx"))
        sample_id = record.get("sample_id")
        key = idx or (str(sample_id) if sample_id else None)
        if key is None:
            raise AnalysisError(f"{run.path}: detection record {position} has no idx or sample_id")
        if key in seen:
            raise AnalysisError(f"{run.path}: duplicate detection unit {key}")
        seen.add(key)

        label: bool | None = None
        if _is_bool(record.get("label")):
            label = bool(record["label"])
        project: str | None = None
        context_state = _prompt_context_state(record)
        if dataset is not None and idx is not None and idx in dataset.records:
            meta = dataset.records[idx]
            if label is None:
                label = bool(meta["label"])
            elif label is not bool(meta["label"]):
                raise AnalysisError(f"{run.path}: unit {key} label disagrees with dataset")
            project = str(meta["project"])
            context_state = str(meta["context_state"])
        if label is None:
            raise AnalysisError(f"{run.path}: unit {key} has no label in results or dataset")

        units.append(
            Unit(
                key=key,
                sample_id=str(sample_id or key),
                idx=idx,
                label=label,
                pred=_extract_prediction(record),
                status=str(record.get("status") or "unknown"),
                project=project,
                context_state=context_state,
            )
        )
    return units


def _side_unit(
    pair_id: str,
    side: str,
    record: Mapping[str, Any] | None,
    dataset: DatasetInfo | None,
    *,
    idx_fallback: str | None,
    label_expected: bool,
    project_fallback: str | None,
    context_fallback: str,
) -> Unit:
    idx = normalize_idx(record.get("idx")) if record is not None else idx_fallback
    label = label_expected
    project = project_fallback
    context_state = context_fallback
    pred: bool | None = None
    status = "missing"
    sample_id = f"pair:{pair_id}:{side}"
    if record is not None:
        if _is_bool(record.get("label")) and bool(record["label"]) is not label_expected:
            raise AnalysisError(f"pair {pair_id} {side}: side label must be {label_expected}")
        pred = _extract_prediction(record)
        status = str(record.get("status") or "unknown")
        if idx is not None and dataset is not None and idx in dataset.records:
            meta = dataset.records[idx]
            project = str(meta["project"])
            context_state = str(meta["context_state"])
        else:
            context_state = _prompt_context_state(record)
        sample_id = str(record.get("sample_id") or sample_id)
    return Unit(
        key=f"{pair_id}:{side}",
        sample_id=sample_id,
        idx=idx,
        label=label_expected,
        pred=pred,
        status=status,
        project=project,
        context_state=context_state,
    )


def build_pair_units(run: RunData, dataset: DatasetInfo | None) -> list[PairUnit]:
    detection_records = [record for record in run.records if record.get("task") == "detection"]
    if not detection_records:
        raise AnalysisError(f"{run.path}: no detection records")
    by_pair: dict[str, dict[str, dict[str, Any]]] = {}
    first_seen: list[str] = []
    for position, record in enumerate(detection_records):
        pair_id = record.get("pair_id")
        if not isinstance(pair_id, str) or not pair_id.strip():
            raise AnalysisError(f"{run.path}: detection record {position} has no pair_id")
        side = record.get("side")
        if side not in {"vulnerable", "fixed"}:
            raise AnalysisError(f"{run.path}: pair {pair_id} has unsupported side {side!r}")
        if pair_id not in by_pair:
            by_pair[pair_id] = {}
            first_seen.append(pair_id)
        if side in by_pair[pair_id]:
            raise AnalysisError(f"{run.path}: duplicate pair {pair_id} side {side}")
        by_pair[pair_id][side] = record

    ordered_ids: list[str] = []
    if dataset is not None:
        ordered_ids.extend(pair_id for pair_id in dataset.order if pair_id in by_pair)
        ordered_ids.extend(pair_id for pair_id in first_seen if pair_id not in set(ordered_ids))
    else:
        ordered_ids.extend(first_seen)

    units: list[PairUnit] = []
    for pair_id in ordered_ids:
        sides = by_pair[pair_id]
        info = dataset.pair_info.get(pair_id) if dataset is not None else None
        project = str(info["project"]) if info else None
        vulnerable_state = str(info["vulnerable_context_state"]) if info else "unknown"
        fixed_state = str(info["fixed_context_state"]) if info else "unknown"
        vulnerable = _side_unit(
            pair_id,
            "vulnerable",
            sides.get("vulnerable"),
            dataset,
            idx_fallback=str(info["vulnerable_idx"]) if info else None,
            label_expected=True,
            project_fallback=project,
            context_fallback=vulnerable_state,
        )
        fixed = _side_unit(
            pair_id,
            "fixed",
            sides.get("fixed"),
            dataset,
            idx_fallback=str(info["fixed_idx"]) if info else None,
            label_expected=False,
            project_fallback=project,
            context_fallback=fixed_state,
        )
        if project is None:
            project = vulnerable.project or fixed.project
        units.append(
            PairUnit(
                key=pair_id,
                project=project,
                context_state=vulnerable.context_state,
                fixed_context_state=fixed.context_state,
                vulnerable=vulnerable,
                fixed=fixed,
                from_dataset=info is not None,
            )
        )
    return units


# ---------------------------------------------------------------------------
# Cross-checks against metrics.json
# ---------------------------------------------------------------------------


def _compare_mapping(expected: Mapping[str, Any], actual: Mapping[str, Any], prefix: str) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for key, expected_value in expected.items():
        if key not in actual:
            continue
        actual_value = actual[key]
        if expected_value != actual_value:
            mismatches.append(
                {"field": f"{prefix}.{key}", "metrics_json": expected_value, "recomputed": actual_value}
            )
    return mismatches


def cross_check_run(run: RunData, units: list[Unit] | list[PairUnit]) -> dict[str, Any]:
    mismatches: list[dict[str, Any]] = []
    detection = run.metrics.get("detection")
    if not isinstance(detection, dict):
        return {"ok": False, "mismatches": [{"field": "detection", "detail": "missing detection block"}]}

    if run.dataset_type == "independent":
        assert all(isinstance(unit, Unit) for unit in units)
        scores = stats.detection_scores(
            [unit.label for unit in units], [unit.pred for unit in units]  # type: ignore[arg-type]
        )
        expected_confusion = detection.get("confusion")
        if isinstance(expected_confusion, dict):
            mismatches.extend(_compare_mapping(expected_confusion, scores["confusion"], "detection.confusion"))
        for metric_json, metric_actual in (
            ("valid_predictions", scores["valid"]),
            ("schema_invalid", scores["invalid"]),
            ("api_errors", 0),
            ("requested", scores["n"]),
        ):
            if metric_json in detection and detection[metric_json] != metric_actual:
                mismatches.append(
                    {
                        "field": f"detection.{metric_json}",
                        "metrics_json": detection[metric_json],
                        "recomputed": metric_actual,
                    }
                )
        if "schema_invalid" in detection:
            invalid_status = sum(1 for unit in units if unit.status == "invalid")
            if detection["schema_invalid"] != invalid_status:
                mismatches.append(
                    {
                        "field": "detection.schema_invalid(status)",
                        "metrics_json": detection["schema_invalid"],
                        "recomputed": invalid_status,
                    }
                )
        if "api_errors" in detection:
            error_status = sum(1 for unit in units if unit.status in {"error", "missing"})
            if detection["api_errors"] != error_status:
                mismatches.append(
                    {
                        "field": "detection.api_errors(status)",
                        "metrics_json": detection["api_errors"],
                        "recomputed": error_status,
                    }
                )
    else:
        assert all(isinstance(unit, PairUnit) for unit in units)
        scores = stats.pair_scores(
            [unit.vulnerable.pred for unit in units],  # type: ignore[list-item]
            [unit.fixed.pred for unit in units],  # type: ignore[list-item]
        )
        pair_joint = run.metrics.get("pair_joint")
        if isinstance(pair_joint, dict):
            expected_categories = pair_joint.get("joint_categories")
            if isinstance(expected_categories, dict):
                mismatches.extend(
                    _compare_mapping(expected_categories, scores["joint_categories"], "pair_joint.joint_categories")
                )
            for metric_json, metric_actual in (
                ("valid_pairs", scores["valid_pairs"]),
                ("invalid_pairs", scores["invalid_pairs"]),
                ("pairs_requested", scores["n_pairs"]),
            ):
                if metric_json in pair_joint and pair_joint[metric_json] != metric_actual:
                    mismatches.append(
                        {
                            "field": f"pair_joint.{metric_json}",
                            "metrics_json": pair_joint[metric_json],
                            "recomputed": metric_actual,
                        }
                    )
        expected_confusion = detection.get("confusion")
        if isinstance(expected_confusion, dict):
            pooled = stats.detection_scores(
                [True] * len(units) + [False] * len(units),
                [unit.vulnerable.pred for unit in units] + [unit.fixed.pred for unit in units],  # type: ignore[list-item]
            )
            mismatches.extend(_compare_mapping(expected_confusion, pooled["confusion"], "detection.confusion"))

    return {
        "ok": not mismatches,
        "method": "recompute from results.jsonl and compare with metrics.json",
        "mismatches": mismatches,
    }


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


def _independent_scores(units: Sequence[Unit], indices: Sequence[int] | None = None) -> dict[str, Any]:
    return stats.detection_scores(
        [unit.label for unit in units],
        [unit.pred for unit in units],
        indices,
    )


def _pair_scores(units: Sequence[PairUnit], indices: Sequence[int] | None = None) -> dict[str, Any]:
    return stats.pair_scores(
        [unit.vulnerable.pred for unit in units],
        [unit.fixed.pred for unit in units],
        indices,
    )


def _pooled_pair_detection(
    units: Sequence[PairUnit], indices: Sequence[int] | None = None
) -> dict[str, Any]:
    selected = list(range(len(units))) if indices is None else list(indices)
    labels = [True] * len(selected) + [False] * len(selected)
    predictions = [units[i].vulnerable.pred for i in selected] + [units[i].fixed.pred for i in selected]
    return stats.detection_scores(labels, predictions)


def _side_detection(units: Sequence[PairUnit], side: str, indices: Sequence[int] | None = None) -> dict[str, Any]:
    selected = list(range(len(units))) if indices is None else list(indices)
    if side == "vulnerable":
        labels = [True] * len(selected)
        predictions = [units[i].vulnerable.pred for i in selected]
    else:
        labels = [False] * len(selected)
        predictions = [units[i].fixed.pred for i in selected]
    return stats.detection_scores(labels, predictions)


def _side_detection_arrays(
    predictions: Sequence[bool | None],
    side: str,
    indices: Sequence[int] | None = None,
) -> dict[str, Any]:
    selected = list(range(len(predictions))) if indices is None else list(indices)
    labels = [side == "vulnerable"] * len(selected)
    return stats.detection_scores(labels, [predictions[i] for i in selected])


def _pooled_pair_detection_arrays(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    indices: Sequence[int] | None = None,
) -> dict[str, Any]:
    selected = (
        list(range(len(vulnerable_predictions)))
        if indices is None
        else list(indices)
    )
    labels = [True] * len(selected) + [False] * len(selected)
    predictions = [vulnerable_predictions[i] for i in selected] + [
        fixed_predictions[i] for i in selected
    ]
    return stats.detection_scores(labels, predictions)


def _detection_metric_fn(
    labels: Sequence[bool], predictions: Sequence[bool | None], key: str
) -> Any:
    def fn(indices: Sequence[int]) -> float | None:
        return stats.detection_scores(labels, predictions, indices).get(key)  # type: ignore[return-value]

    return fn


def _pair_metric_fn(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    key: str,
) -> Any:
    def fn(indices: Sequence[int]) -> float | None:
        return stats.pair_scores(
            vulnerable_predictions, fixed_predictions, indices
        ).get(key)  # type: ignore[return-value]

    return fn


def _pair_pooled_metric_fn(
    vulnerable_predictions: Sequence[bool | None],
    fixed_predictions: Sequence[bool | None],
    key: str,
) -> Any:
    def fn(indices: Sequence[int]) -> float | None:
        selected = list(indices)
        labels = [True] * len(selected) + [False] * len(selected)
        predictions = [vulnerable_predictions[i] for i in selected] + [
            fixed_predictions[i] for i in selected
        ]
        return stats.detection_scores(labels, predictions).get(key)  # type: ignore[return-value]

    return fn


def _delta_fn(a_fn: Any, b_fn: Any) -> Any:
    def fn(indices: Sequence[int]) -> float | None:
        a_value = a_fn(indices)
        b_value = b_fn(indices)
        if a_value is None or b_value is None:
            return None
        return float(a_value) - float(b_value)

    return fn


def _cluster_ids_for(
    units: Sequence[Unit] | Sequence[PairUnit],
    indices: Sequence[int],
    cluster_unit: str,
) -> list[str] | None:
    output: list[str] = []
    for index in indices:
        unit = units[index]
        if cluster_unit == "project":
            if unit.project is None:
                return None
            output.append(str(unit.project))
        elif cluster_unit == "pair":
            output.append(str(unit.key))
        elif cluster_unit == "unit":
            output.append(f"unit:{unit.key}")
        else:
            raise AnalysisError(f"unsupported cluster unit {cluster_unit!r}")
    return output


def _resolve_cluster_unit(dataset_type: str, requested: str) -> str:
    if requested == "auto":
        return "project" if dataset_type == "independent" else "pair"
    if requested == "pair" and dataset_type == "independent":
        raise AnalysisError("--cluster pair is only valid for the pairs dataset")
    return requested


def _local_index_wrappers(
    indices: Sequence[int],
    metric_fns: Mapping[str, Any],
) -> dict[str, Any]:
    """Map cluster-local resample positions back to original unit indices.

    ``stats.cluster_bootstrap`` receives one cluster id per entry in
    ``indices``; its resample positions are therefore in ``0..len(indices)-1``.
    Metric functions expect indices into the full cohort array, so each
    position must be translated before evaluation.
    """

    original = list(indices)
    wrapped: dict[str, Any] = {}
    for name, fn in metric_fns.items():
        def wrapper(local_indices: Sequence[int], *, _fn=fn) -> float | None:
            return _fn([original[position] for position in local_indices])

        wrapped[name] = wrapper
    return wrapped


def _bootstrap_block(
    *,
    units: Sequence[Unit] | Sequence[PairUnit],
    indices: Sequence[int],
    cluster_unit: str,
    metric_fns: Mapping[str, Any],
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    if resamples <= 0:
        return {
            "enabled": False,
            "reason": "bootstrap disabled by --bootstrap 0",
            "settings": {
                "method": "cluster percentile bootstrap",
                "resamples": 0,
                "seed": seed,
                "confidence": confidence,
                "percentile_method": stats.PERCENTILE_METHOD,
            },
            "metrics": {},
        }
    cluster_ids = _cluster_ids_for(units, indices, cluster_unit)
    if cluster_ids is None:
        return {
            "enabled": False,
            "reason": f"cluster unit {cluster_unit!r} is unavailable for at least one unit",
            "settings": {
                "method": "cluster percentile bootstrap",
                "cluster_unit": cluster_unit,
                "resamples": resamples,
                "seed": seed,
                "confidence": confidence,
                "percentile_method": stats.PERCENTILE_METHOD,
            },
            "metrics": {},
        }
    result = stats.cluster_bootstrap(
        cluster_ids,
        _local_index_wrappers(indices, metric_fns),
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    settings = result.get("settings")
    if isinstance(settings, dict):
        settings["cluster_unit"] = cluster_unit
    return result


def _split_bootstrap_metrics(
    raw: dict[str, Any],
    strategies: Sequence[str],
    deltas: Sequence[tuple[str, str]],
    metric_names: Sequence[str],
    point_lookup: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    raw_metrics = raw.get("metrics") if isinstance(raw.get("metrics"), dict) else {}
    metric_block: dict[str, Any] = {strategy: {} for strategy in strategies}
    delta_block: dict[str, Any] = {f"{a}_vs_{b}": {} for a, b in deltas}
    for key, entry in raw_metrics.items():
        if not isinstance(entry, dict):
            continue
        for strategy in strategies:
            prefix = f"{strategy}|"
            if key.startswith(prefix):
                metric = key[len(prefix) :]
                if metric in metric_names:
                    metric_block[strategy][metric] = dict(entry)
        for a, b in deltas:
            prefix = f"delta|{a}|{b}|"
            if key.startswith(prefix):
                metric = key[len(prefix) :]
                if metric in metric_names:
                    delta_block[f"{a}_vs_{b}"][metric] = dict(entry)
    for strategy in strategies:
        for metric in metric_names:
            entry = metric_block[strategy].get(metric)
            if isinstance(entry, dict):
                entry["point"] = point_lookup.get(strategy, {}).get(metric)
    for a, b in deltas:
        for metric in metric_names:
            entry = delta_block[f"{a}_vs_{b}"].get(metric)
            if isinstance(entry, dict):
                a_value = point_lookup.get(a, {}).get(metric)
                b_value = point_lookup.get(b, {}).get(metric)
                entry["point"] = (
                    float(a_value) - float(b_value)
                    if _is_number(a_value) and _is_number(b_value)
                    else None
                )
    return {"metrics": metric_block, "deltas": delta_block}


# ---------------------------------------------------------------------------
# Group analysis
# ---------------------------------------------------------------------------


def _strategy_sort_key(strategy: str) -> int:
    try:
        return STRATEGIES.index(strategy)
    except ValueError:
        return len(STRATEGIES)


def _group_key(run: RunData, dataset: DatasetInfo | None) -> tuple[str, str, str, str]:
    dataset_key = run.dataset_sha256 or (dataset.sha256 if dataset else None) or run.dataset_path or "unknown"
    return (run.dataset_type, run.task, run.model, dataset_key)


def _build_independent_cohort(runs: Sequence[RunData]) -> tuple[list[Unit], dict[str, Sequence[int]], dict[str, Any]]:
    unit_maps: dict[str, dict[str, Unit]] = {}
    for run in runs:
        if not hasattr(run, "_units"):
            raise AnalysisError("internal error: run units are not attached")
        units = getattr(run, "_units")
        unit_maps[run.strategy] = {unit.key: unit for unit in units}  # type: ignore[attr-defined]
    reference = runs[0]
    reference_units = getattr(reference, "_units")
    strategies = [run.strategy for run in runs]
    cohort_keys = [
        unit.key
        for unit in reference_units  # type: ignore[attr-defined]
        if all(unit.key in unit_maps[strategy] for strategy in strategies)
    ]
    if not cohort_keys:
        raise AnalysisError("no shared detection units across strategies")

    cohort_units: list[Unit] = []
    for key in cohort_keys:
        reference_unit = unit_maps[reference.strategy][key]
        for strategy in strategies:
            other = unit_maps[strategy][key]
            if other.label is not reference_unit.label:
                raise AnalysisError(f"unit {key}: label differs across strategies")
            if other.project != reference_unit.project:
                raise AnalysisError(f"unit {key}: project differs across strategies")
            if other.context_state != reference_unit.context_state:
                raise AnalysisError(f"unit {key}: context state differs across strategies")
        cohort_units.append(reference_unit)

    excluded = {
        run.strategy: len(unit_maps[run.strategy]) - len(cohort_keys) for run in runs
    }
    arrays: dict[str, Sequence[int]] = {}
    labels = [unit.label for unit in cohort_units]
    preds = {
        strategy: [unit_maps[strategy][key].pred for key in cohort_keys]
        for strategy in strategies
    }
    complete = [i for i in range(len(cohort_units)) if all(preds[s][i] is not None for s in strategies)]
    arrays = {
        "labels": labels,  # type: ignore[dict-item]
        "preds": preds,  # type: ignore[dict-item]
        "complete_indices": complete,  # type: ignore[dict-item]
        "projects": [unit.project for unit in cohort_units],  # type: ignore[dict-item]
        "context_states": [unit.context_state for unit in cohort_units],  # type: ignore[dict-item]
    }
    meta = {
        "n": len(cohort_units),
        "complete_case_n": len(complete),
        "excluded": excluded,
        "reference_strategy": reference.strategy,
        "note": "Cohort is the intersection of unit keys across included strategies, in reference run order.",
    }
    return cohort_units, arrays, meta


def _build_pair_cohort(runs: Sequence[RunData]) -> tuple[list[PairUnit], dict[str, Any], dict[str, Any]]:
    pair_maps: dict[str, dict[str, PairUnit]] = {}
    for run in runs:
        units = getattr(run, "_pair_units")
        pair_maps[run.strategy] = {unit.key: unit for unit in units}  # type: ignore[attr-defined]
    reference = runs[0]
    reference_units = getattr(reference, "_pair_units")
    strategies = [run.strategy for run in runs]
    cohort_keys = [
        unit.key
        for unit in reference_units  # type: ignore[attr-defined]
        if all(unit.key in pair_maps[strategy] for strategy in strategies)
    ]
    if not cohort_keys:
        raise AnalysisError("no shared pairs across strategies")

    cohort_units: list[PairUnit] = []
    for key in cohort_keys:
        reference_unit = pair_maps[reference.strategy][key]
        for strategy in strategies:
            other = pair_maps[strategy][key]
            if other.project != reference_unit.project:
                raise AnalysisError(f"pair {key}: project differs across strategies")
            if other.context_state != reference_unit.context_state:
                raise AnalysisError(f"pair {key}: context state differs across strategies")
            if other.fixed_context_state != reference_unit.fixed_context_state:
                raise AnalysisError(f"pair {key}: fixed context state differs across strategies")
        cohort_units.append(reference_unit)

    excluded = {
        run.strategy: len(pair_maps[run.strategy]) - len(cohort_keys) for run in runs
    }
    vulnerable = [unit.vulnerable.pred for unit in cohort_units]
    fixed = [unit.fixed.pred for unit in cohort_units]
    complete = [
        i
        for i in range(len(cohort_units))
        if all(
            pair_maps[strategy][cohort_units[i].key].vulnerable.pred is not None
            and pair_maps[strategy][cohort_units[i].key].fixed.pred is not None
            for strategy in strategies
        )
    ]
    arrays = {
        "vulnerable": vulnerable,  # type: ignore[dict-item]
        "fixed": fixed,  # type: ignore[dict-item]
        "complete_indices": complete,  # type: ignore[dict-item]
        "projects": [unit.project for unit in cohort_units],  # type: ignore[dict-item]
        "context_states": [unit.context_state for unit in cohort_units],  # type: ignore[dict-item]
        "fixed_context_states": [unit.fixed_context_state for unit in cohort_units],  # type: ignore[dict-item]
        "per_strategy": {  # type: ignore[dict-item]
            strategy: {
                "vulnerable": [pair_maps[strategy][unit.key].vulnerable.pred for unit in cohort_units],
                "fixed": [pair_maps[strategy][unit.key].fixed.pred for unit in cohort_units],
            }
            for strategy in strategies
        },
    }
    meta = {
        "n": len(cohort_units),
        "complete_case_n": len(complete),
        "excluded": excluded,
        "reference_strategy": reference.strategy,
        "note": "Cohort is the intersection of pair_id keys across included strategies, in reference run order.",
    }
    return cohort_units, arrays, meta


def _independent_group(runs: Sequence[RunData], dataset: DatasetInfo | None, args: argparse.Namespace) -> dict[str, Any]:
    strategies = [run.strategy for run in runs]
    cohort_units, arrays, cohort_meta = _build_independent_cohort(runs)
    labels = arrays["labels"]  # type: ignore[assignment]
    preds = arrays["preds"]  # type: ignore[assignment]
    complete_indices = arrays["complete_indices"]  # type: ignore[assignment]
    assert isinstance(labels, list) and isinstance(preds, dict) and isinstance(complete_indices, list)

    warnings: list[str] = []
    if any((cohort_meta.get("excluded") or {}).values()):
        warnings.append(
            f"cohort intersection excluded units per strategy: {cohort_meta.get('excluded')}"
        )
    run_level: dict[str, Any] = {}
    for run in runs:
        units = getattr(run, "_units")
        run_level[run.strategy] = {
            "unit_metrics": _independent_scores(units),
            "n_units": len(units),
            "note": "all detection records in this run; valid-only metrics use valid records",
        }

    valid_only: dict[str, Any] = {}
    end_to_end: dict[str, Any] = {}
    for strategy in strategies:
        scores = stats.detection_scores(labels, preds[strategy], complete_indices)
        all_scores = stats.detection_scores(labels, preds[strategy])
        valid_only[strategy] = scores
        end_to_end[strategy] = {
            "n": all_scores["n"],
            "valid": all_scores["valid"],
            "invalid": all_scores["invalid"],
            "coverage": all_scores["coverage"],
            "invalid_rate": all_scores["invalid_rate"],
            "strict_correct": all_scores["strict_correct"],
            "strict_accuracy": all_scores["strict_accuracy"],
            "wilson": {"strict_accuracy": all_scores["wilson"]["strict_accuracy"], "coverage": all_scores["wilson"]["coverage"]},
            "note": "end-to-end view: schema-invalid and API-error records count as incorrect",
        }

    cohort_meta["complete_case_note"] = (
        "Complete-case cohort: units with a valid detection prediction in every included strategy. "
        "Valid-only metrics and their bootstrap intervals use this set."
    )
    if len(complete_indices) < len(cohort_units):
        warnings.append(
            f"complete-case cohort has {len(complete_indices)}/{len(cohort_units)} units; "
            "valid-only metrics exclude units invalid in at least one strategy"
        )

    cluster_unit = _resolve_cluster_unit("independent", args.cluster)
    bootstrap: dict[str, Any] = {"valid_only": {}, "end_to_end": {}}
    metric_names = ("macro_f1", "balanced_accuracy", "mcc", "accuracy", "positive_f1", "precision", "recall", "specificity")
    deltas = [(a, b) for i, a in enumerate(strategies) for b in strategies[i + 1 :]]
    valid_fns: dict[str, Any] = {}
    for strategy in strategies:
        for metric in metric_names:
            valid_fns[f"{strategy}|{metric}"] = _detection_metric_fn(labels, preds[strategy], metric)
    for a, b in deltas:
        for metric in ("macro_f1", "balanced_accuracy", "mcc", "accuracy"):
            valid_fns[f"delta|{a}|{b}|{metric}"] = _delta_fn(
                valid_fns[f"{a}|{metric}"], valid_fns[f"{b}|{metric}"]
            )
    raw_valid = _bootstrap_block(
        units=cohort_units,
        indices=complete_indices,
        cluster_unit=cluster_unit,
        metric_fns=valid_fns,
        resamples=args.bootstrap,
        seed=args.seed,
        confidence=args.confidence,
    )
    point_lookup = {
        strategy: {metric: valid_only[strategy].get(metric) for metric in metric_names}
        for strategy in strategies
    }
    split_valid = _split_bootstrap_metrics(raw_valid, strategies, deltas, metric_names, point_lookup)
    bootstrap["valid_only"] = {
        **{key: raw_valid[key] for key in ("enabled", "reason", "settings", "cluster_count", "cluster_size_summary") if key in raw_valid},
        **split_valid,
    }
    if raw_valid.get("enabled") is False:
        warnings.append(f"valid-only bootstrap unavailable: {raw_valid.get('reason')}")

    end_fns: dict[str, Any] = {}
    for strategy in strategies:
        end_fns[f"{strategy}|strict_accuracy"] = _detection_metric_fn(labels, preds[strategy], "strict_accuracy")
        end_fns[f"{strategy}|coverage"] = _detection_metric_fn(labels, preds[strategy], "coverage")
    for a, b in deltas:
        end_fns[f"delta|{a}|{b}|strict_accuracy"] = _delta_fn(
            end_fns[f"{a}|strict_accuracy"], end_fns[f"{b}|strict_accuracy"]
        )
        end_fns[f"delta|{a}|{b}|coverage"] = _delta_fn(
            end_fns[f"{a}|coverage"], end_fns[f"{b}|coverage"]
        )
    raw_end = _bootstrap_block(
        units=cohort_units,
        indices=list(range(len(cohort_units))),
        cluster_unit=cluster_unit,
        metric_fns=end_fns,
        resamples=args.bootstrap,
        seed=args.seed,
        confidence=args.confidence,
    )
    end_point = {
        strategy: {
            "strict_accuracy": end_to_end[strategy]["strict_accuracy"],
            "coverage": end_to_end[strategy]["coverage"],
        }
        for strategy in strategies
    }
    split_end = _split_bootstrap_metrics(raw_end, strategies, deltas, ("strict_accuracy", "coverage"), end_point)
    bootstrap["end_to_end"] = {
        **{key: raw_end[key] for key in ("enabled", "reason", "settings", "cluster_count", "cluster_size_summary") if key in raw_end},
        **split_end,
    }
    if raw_end.get("enabled") is False:
        warnings.append(f"end-to-end bootstrap unavailable: {raw_end.get('reason')}")

    pairwise = _build_pairwise_independent(
        labels,
        preds,
        strategies,
        complete_indices,
        alpha=0.05,
    )

    context_strata, m3_block = _build_context_strata_independent(
        runs,
        cohort_units,
        arrays,
        strategies,
        dataset,
        args,
        cluster_unit,
    )

    return {
        "group_id": _group_id(runs, dataset),
        "dataset_type": "independent",
        "task": runs[0].task,
        "model": runs[0].model,
        "dataset_path": str(dataset.path) if dataset else runs[0].dataset_path,
        "dataset_sha256": dataset.sha256 if dataset else runs[0].dataset_sha256,
        "strategies": strategies,
        "runs": [
            {"run_id": run.run_id, "path": str(run.path), "strategy": run.strategy}
            for run in runs
        ],
        "cohort": cohort_meta,
        "run_level": run_level,
        "valid_only": valid_only,
        "end_to_end": end_to_end,
        "bootstrap": bootstrap,
        "pairwise": pairwise,
        "context_strata": context_strata,
        "m3_artifact_risk": m3_block,
        "warnings": warnings,
    }


def _pair_group(runs: Sequence[RunData], dataset: DatasetInfo | None, args: argparse.Namespace) -> dict[str, Any]:
    strategies = [run.strategy for run in runs]
    cohort_units, arrays, cohort_meta = _build_pair_cohort(runs)
    complete_indices = arrays["complete_indices"]  # type: ignore[assignment]
    per_strategy = arrays["per_strategy"]  # type: ignore[assignment]
    assert isinstance(complete_indices, list) and isinstance(per_strategy, dict)

    warnings: list[str] = []
    if any((cohort_meta.get("excluded") or {}).values()):
        warnings.append(
            f"cohort intersection excluded pairs per strategy: {cohort_meta.get('excluded')}"
        )
    run_level: dict[str, Any] = {}
    for run in runs:
        units = getattr(run, "_pair_units")
        run_level[run.strategy] = {
            "joint": _pair_scores(units),
            "by_side": {
                "vulnerable": _side_detection(units, "vulnerable"),
                "fixed": _side_detection(units, "fixed"),
                "pooled": _pooled_pair_detection(units),
            },
            "n_pairs": len(units),
            "note": "all detection pairs in this run; side metrics treat each side as a detection record",
        }

    valid_only: dict[str, Any] = {}
    end_to_end: dict[str, Any] = {}
    for strategy in strategies:
        vulnerable = per_strategy[strategy]["vulnerable"]
        fixed = per_strategy[strategy]["fixed"]
        scores = stats.pair_scores(vulnerable, fixed, complete_indices)
        all_scores = stats.pair_scores(vulnerable, fixed)
        valid_only[strategy] = {
            **scores,
            "per_version_valid_only": {
                "vulnerable": _side_detection_arrays(vulnerable, "vulnerable", complete_indices),
                "fixed": _side_detection_arrays(fixed, "fixed", complete_indices),
                "pooled": _pooled_pair_detection_arrays(vulnerable, fixed, complete_indices),
            },
        }
        end_to_end[strategy] = {
            "n_pairs": all_scores["n_pairs"],
            "valid_pairs": all_scores["valid_pairs"],
            "invalid_pairs": all_scores["invalid_pairs"],
            "coverage": all_scores["coverage"],
            "invalid_rate": all_scores["invalid_rate"],
            "joint_correct_all_pairs": all_scores["joint_correct_all_pairs"],
            "joint_accuracy_all_pairs": all_scores["joint_accuracy_all_pairs"],
            "wilson": {
                "joint_accuracy_all_pairs": all_scores["wilson"]["joint_accuracy_all_pairs"],
                "coverage": all_scores["wilson"]["coverage"],
            },
            "note": "end-to-end view: a pair with any invalid side counts as a joint failure",
        }

    cohort_meta["complete_case_note"] = (
        "Complete-case cohort: pairs where both sides are valid in every included strategy. "
        "Joint valid-pair metrics and their bootstrap intervals use this set."
    )
    if len(complete_indices) < len(cohort_units):
        warnings.append(
            f"complete-case cohort has {len(complete_indices)}/{len(cohort_units)} pairs; "
            "joint valid-pair metrics exclude pairs invalid in at least one strategy"
        )

    cluster_unit = _resolve_cluster_unit("pairs", args.cluster)
    deltas = [(a, b) for i, a in enumerate(strategies) for b in strategies[i + 1 :]]
    metric_names = ("joint_accuracy_valid_pairs", "macro_f1", "balanced_accuracy", "mcc")
    valid_fns: dict[str, Any] = {}
    for strategy in strategies:
        vulnerable = per_strategy[strategy]["vulnerable"]
        fixed = per_strategy[strategy]["fixed"]
        valid_fns[f"{strategy}|joint_accuracy_valid_pairs"] = _pair_metric_fn(
            vulnerable, fixed, "joint_accuracy_valid_pairs"
        )
        for metric in ("macro_f1", "balanced_accuracy", "mcc"):
            valid_fns[f"{strategy}|{metric}"] = _pair_pooled_metric_fn(
                vulnerable, fixed, metric
            )
    for a, b in deltas:
        for metric in metric_names:
            valid_fns[f"delta|{a}|{b}|{metric}"] = _delta_fn(
                valid_fns[f"{a}|{metric}"], valid_fns[f"{b}|{metric}"]
            )
    raw_valid = _bootstrap_block(
        units=cohort_units,
        indices=complete_indices,
        cluster_unit=cluster_unit,
        metric_fns=valid_fns,
        resamples=args.bootstrap,
        seed=args.seed,
        confidence=args.confidence,
    )
    point_lookup = {
        strategy: {
            "joint_accuracy_valid_pairs": valid_only[strategy]["joint_accuracy_valid_pairs"],
            **{metric: valid_only[strategy]["per_version_valid_only"]["pooled"].get(metric) for metric in ("macro_f1", "balanced_accuracy", "mcc")},
        }
        for strategy in strategies
    }
    split_valid = _split_bootstrap_metrics(raw_valid, strategies, deltas, metric_names, point_lookup)
    bootstrap: dict[str, Any] = {
        "valid_only": {
            **{key: raw_valid[key] for key in ("enabled", "reason", "settings", "cluster_count", "cluster_size_summary") if key in raw_valid},
            **split_valid,
        }
    }
    if raw_valid.get("enabled") is False:
        warnings.append(f"valid-only bootstrap unavailable: {raw_valid.get('reason')}")

    end_fns: dict[str, Any] = {}
    for strategy in strategies:
        vulnerable = per_strategy[strategy]["vulnerable"]
        fixed = per_strategy[strategy]["fixed"]
        end_fns[f"{strategy}|joint_accuracy_all_pairs"] = _pair_metric_fn(
            vulnerable, fixed, "joint_accuracy_all_pairs"
        )
        end_fns[f"{strategy}|coverage"] = _pair_metric_fn(vulnerable, fixed, "coverage")
    for a, b in deltas:
        end_fns[f"delta|{a}|{b}|joint_accuracy_all_pairs"] = _delta_fn(
            end_fns[f"{a}|joint_accuracy_all_pairs"], end_fns[f"{b}|joint_accuracy_all_pairs"]
        )
        end_fns[f"delta|{a}|{b}|coverage"] = _delta_fn(
            end_fns[f"{a}|coverage"], end_fns[f"{b}|coverage"]
        )
    raw_end = _bootstrap_block(
        units=cohort_units,
        indices=list(range(len(cohort_units))),
        cluster_unit=cluster_unit,
        metric_fns=end_fns,
        resamples=args.bootstrap,
        seed=args.seed,
        confidence=args.confidence,
    )
    end_point = {
        strategy: {
            "joint_accuracy_all_pairs": end_to_end[strategy]["joint_accuracy_all_pairs"],
            "coverage": end_to_end[strategy]["coverage"],
        }
        for strategy in strategies
    }
    split_end = _split_bootstrap_metrics(raw_end, strategies, deltas, ("joint_accuracy_all_pairs", "coverage"), end_point)
    bootstrap["end_to_end"] = {
        **{key: raw_end[key] for key in ("enabled", "reason", "settings", "cluster_count", "cluster_size_summary") if key in raw_end},
        **split_end,
    }
    if raw_end.get("enabled") is False:
        warnings.append(f"end-to-end bootstrap unavailable: {raw_end.get('reason')}")

    pairwise = _build_pairwise_pairs(
        per_strategy,
        strategies,
        complete_indices,
        alpha=0.05,
    )

    context_strata, m3_block = _build_context_strata_pairs(
        runs,
        cohort_units,
        arrays,
        strategies,
        dataset,
        args,
        cluster_unit,
    )

    return {
        "group_id": _group_id(runs, dataset),
        "dataset_type": "pairs",
        "task": runs[0].task,
        "model": runs[0].model,
        "dataset_path": str(dataset.path) if dataset else runs[0].dataset_path,
        "dataset_sha256": dataset.sha256 if dataset else runs[0].dataset_sha256,
        "strategies": strategies,
        "runs": [
            {"run_id": run.run_id, "path": str(run.path), "strategy": run.strategy}
            for run in runs
        ],
        "cohort": cohort_meta,
        "run_level": run_level,
        "valid_only": valid_only,
        "end_to_end": end_to_end,
        "bootstrap": bootstrap,
        "pairwise": pairwise,
        "context_strata": context_strata,
        "m3_artifact_risk": m3_block,
        "warnings": warnings,
    }


def _group_id(runs: Sequence[RunData], dataset: DatasetInfo | None) -> str:
    sha = (dataset.sha256 if dataset else runs[0].dataset_sha256) or "unknown"
    return f"{runs[0].dataset_type}|{runs[0].task}|{runs[0].model}|{sha[:12]}"


# ---------------------------------------------------------------------------
# McNemar / Holm
# ---------------------------------------------------------------------------


def _build_pairwise_independent(
    labels: Sequence[bool],
    preds: Mapping[str, Sequence[bool | None]],
    strategies: Sequence[str],
    complete_indices: Sequence[int],
    *,
    alpha: float,
) -> dict[str, Any]:
    deltas = [(a, b) for i, a in enumerate(strategies) for b in strategies[i + 1 :]]
    if not deltas:
        return {"available": False, "reason": "fewer than two strategies"}

    def correctness(strategy: str) -> list[bool]:
        return [
            pred is not None and pred == label
            for label, pred in zip(labels, preds[strategy])
        ]

    all_correct = {strategy: correctness(strategy) for strategy in strategies}
    both_valid_indices = [
        i
        for i in range(len(labels))
        if all(preds[strategy][i] is not None for strategy in strategies)
    ]
    valid_correct = {
        strategy: [preds[strategy][i] == labels[i] for i in both_valid_indices]
        for strategy in strategies
    }

    def compare(correct_map: Mapping[str, Sequence[bool]], total: int, metric_name: str) -> dict[str, Any]:
        if total == 0:
            return {
                "metric": metric_name,
                "n": 0,
                "comparisons": [],
                "holm": {"method": "Holm", "alpha": alpha, "m": 0},
                "note": "no eligible units for this comparison",
            }
        rows: list[dict[str, Any]] = []
        for a, b in deltas:
            a_correct = correct_map[a]
            b_correct = correct_map[b]
            b_count = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
            c_count = sum(1 for x, y in zip(a_correct, b_correct) if not x and y)
            test = stats.mcnemar_exact(
                a_correct_b_wrong=b_count,
                a_wrong_b_correct=c_count,
                total=total,
                alpha=alpha,
            )
            rows.append(
                {
                    "strategy_a": a,
                    "strategy_b": b,
                    "strategy_a_label": STRATEGY_LABELS.get(a, a),
                    "strategy_b_label": STRATEGY_LABELS.get(b, b),
                    **test,
                }
            )
        adjusted = stats.holm_adjust([row["p_value"] for row in rows])
        for row, adjusted_p in zip(rows, adjusted):
            row["p_holm"] = adjusted_p
            row["reject_holm_0_05"] = adjusted_p < alpha
        return {
            "metric": metric_name,
            "n": total,
            "comparisons": rows,
            "holm": {"method": "Holm", "alpha": alpha, "m": len(rows)},
        }

    return {
        "available": True,
        "primary": compare(all_correct, len(labels), "end_to_end_correctness_all_units"),
        "secondary": compare(valid_correct, len(both_valid_indices), "correctness_on_units_valid_in_both"),
        "notes": [
            "McNemar treats units as independent; units from the same project may be correlated, so this test can be anti-conservative. Use the project-cluster bootstrap delta intervals as the primary uncertainty statement.",
            "The primary table counts schema-invalid/API-error predictions as incorrect (end-to-end view).",
            "The secondary table restricts to units valid in both strategies and is not directly comparable to the primary table.",
        ],
    }


def _build_pairwise_pairs(
    per_strategy: Mapping[str, Mapping[str, Sequence[bool | None]]],
    strategies: Sequence[str],
    complete_indices: Sequence[int],
    *,
    alpha: float,
) -> dict[str, Any]:
    deltas = [(a, b) for i, a in enumerate(strategies) for b in strategies[i + 1 :]]
    if not deltas:
        return {"available": False, "reason": "fewer than two strategies"}

    def joint_correct(strategy: str) -> list[bool]:
        vulnerable = per_strategy[strategy]["vulnerable"]
        fixed = per_strategy[strategy]["fixed"]
        return [
            v is not None and f is not None and bool(v) and not bool(f)
            for v, f in zip(vulnerable, fixed)
        ]

    all_correct = {strategy: joint_correct(strategy) for strategy in strategies}
    valid_indices = [
        i
        for i in range(len(all_correct[strategies[0]]))
        if all(
            per_strategy[strategy]["vulnerable"][i] is not None
            and per_strategy[strategy]["fixed"][i] is not None
            for strategy in strategies
        )
    ]
    valid_correct = {
        strategy: [all_correct[strategy][i] for i in valid_indices] for strategy in strategies
    }

    def compare(correct_map: Mapping[str, Sequence[bool]], total: int, metric_name: str) -> dict[str, Any]:
        if total == 0:
            return {
                "metric": metric_name,
                "n": 0,
                "comparisons": [],
                "holm": {"method": "Holm", "alpha": alpha, "m": 0},
                "note": "no eligible units for this comparison",
            }
        rows: list[dict[str, Any]] = []
        for a, b in deltas:
            a_correct = correct_map[a]
            b_correct = correct_map[b]
            b_count = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
            c_count = sum(1 for x, y in zip(a_correct, b_correct) if not x and y)
            test = stats.mcnemar_exact(
                a_correct_b_wrong=b_count,
                a_wrong_b_correct=c_count,
                total=total,
                alpha=alpha,
            )
            rows.append(
                {
                    "strategy_a": a,
                    "strategy_b": b,
                    "strategy_a_label": STRATEGY_LABELS.get(a, a),
                    "strategy_b_label": STRATEGY_LABELS.get(b, b),
                    **test,
                }
            )
        adjusted = stats.holm_adjust([row["p_value"] for row in rows])
        for row, adjusted_p in zip(rows, adjusted):
            row["p_holm"] = adjusted_p
            row["reject_holm_0_05"] = adjusted_p < alpha
        return {
            "metric": metric_name,
            "n": total,
            "comparisons": rows,
            "holm": {"method": "Holm", "alpha": alpha, "m": len(rows)},
        }

    return {
        "available": True,
        "primary": compare(all_correct, len(all_correct[strategies[0]]), "joint_correct_all_pairs"),
        "secondary": compare(valid_correct, len(valid_indices), "joint_correct_on_pairs_valid_in_both"),
        "notes": [
            "The pair is the unit of analysis; both versions stay together.",
            "McNemar assumes independent pairs. Pairs from the same project may be correlated; use the pair/project cluster bootstrap delta intervals as the primary uncertainty statement.",
        ],
    }


# ---------------------------------------------------------------------------
# Context strata and M3 artifact risk
# ---------------------------------------------------------------------------


def _stratum_label_counts(units: Sequence[Unit], state: str) -> dict[str, int]:
    selected = [unit for unit in units if unit.context_state == state]
    vulnerable = sum(1 for unit in selected if unit.label)
    return {"vulnerable": vulnerable, "non_vulnerable": len(selected) - vulnerable}


def _build_context_strata_independent(
    runs: Sequence[RunData],
    cohort_units: Sequence[Unit],
    arrays: Mapping[str, Any],
    strategies: Sequence[str],
    dataset: DatasetInfo | None,
    args: argparse.Namespace,
    cluster_unit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    labels = arrays["labels"]  # type: ignore[assignment]
    preds = arrays["preds"]  # type: ignore[assignment]
    context_states = arrays["context_states"]  # type: ignore[assignment]
    assert isinstance(labels, list) and isinstance(preds, dict) and isinstance(context_states, list)

    strata: dict[str, Any] = {}
    observed_counts: dict[str, Any] = {}
    for strategy in strategies:
        strategy_block: dict[str, Any] = {}
        counts: dict[str, int] = {}
        for state in CONTEXT_STATES:
            indices = [i for i, value in enumerate(context_states) if value == state]
            if not indices:
                continue
            scores = stats.detection_scores(labels, preds[strategy], indices)
            strategy_block[state] = {
                "n": len(indices),
                "label_counts": _stratum_label_counts(cohort_units, state),
                "valid": scores["valid"],
                "invalid": scores["invalid"],
                "coverage": scores["coverage"],
                "metrics": scores,
            }
            counts[state] = len(indices)
        strata[strategy] = strategy_block
        observed_counts[strategy] = counts

    l3_check = _l3_context_metadata_check(runs, cohort_units)
    m3_vs_m1 = _m3_vs_m1_independent(
        cohort_units,
        labels,
        preds,
        context_states,
        strategies,
        args,
        cluster_unit,
    )
    risk = _group_m3_risk(dataset, observed_counts, m3_vs_m1, l3_check)
    return (
        {
            "definition": (
                "Context state is computed from the dataset's raw context cell with the runner's "
                "allow-list sanitizer when available; nonempty means at least one allow-listed "
                "section has a usable item. unknown means no dataset join and no L3 prompt metadata."
            ),
            "context_source": dataset.context_source if dataset else "prompt_metadata_only",
            "strategies": strata,
            "observed_counts": observed_counts,
            "l3_metadata_check": l3_check,
            "m3_vs_m1": m3_vs_m1,
        },
        risk,
    )


def _build_context_strata_pairs(
    runs: Sequence[RunData],
    cohort_units: Sequence[PairUnit],
    arrays: Mapping[str, Any],
    strategies: Sequence[str],
    dataset: DatasetInfo | None,
    args: argparse.Namespace,
    cluster_unit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    per_strategy = arrays["per_strategy"]  # type: ignore[assignment]
    context_states = arrays["context_states"]  # type: ignore[assignment]
    assert isinstance(per_strategy, dict) and isinstance(context_states, list)

    strata: dict[str, Any] = {}
    observed_counts: dict[str, Any] = {}
    for strategy in strategies:
        strategy_block: dict[str, Any] = {}
        counts: dict[str, int] = {}
        vulnerable = per_strategy[strategy]["vulnerable"]
        fixed = per_strategy[strategy]["fixed"]
        for state in CONTEXT_STATES:
            indices = [i for i, value in enumerate(context_states) if value == state]
            if not indices:
                continue
            scores = stats.pair_scores(vulnerable, fixed, indices)
            side_labels = {"vulnerable": 0, "non_vulnerable": 0}
            for i in indices:
                side_labels["vulnerable"] += 1
                side_labels["non_vulnerable"] += 1
            strategy_block[state] = {
                "n_pairs": len(indices),
                "label_counts": side_labels,
                "valid_pairs": scores["valid_pairs"],
                "coverage": scores["coverage"],
                "metrics": scores,
            }
            counts[state] = len(indices)
        strata[strategy] = strategy_block
        observed_counts[strategy] = counts

    l3_check = _l3_context_metadata_check(runs, cohort_units)
    m3_vs_m1 = _m3_vs_m1_pairs(
        cohort_units,
        per_strategy,
        context_states,
        strategies,
        args,
        cluster_unit,
    )
    risk = _group_m3_risk(dataset, observed_counts, m3_vs_m1, l3_check, is_pairs=True)
    return (
        {
            "definition": (
                "Pair context state uses the vulnerable side's dataset context; both sides usually "
                "share availability. Pair is the resampling unit."
            ),
            "context_source": dataset.context_source if dataset else "prompt_metadata_only",
            "strategies": strata,
            "observed_counts": observed_counts,
            "l3_metadata_check": l3_check,
            "m3_vs_m1": m3_vs_m1,
        },
        risk,
    )


def _l3_context_metadata_check(
    runs: Sequence[RunData], cohort_units: Sequence[Unit] | Sequence[PairUnit]
) -> dict[str, Any]:
    context_run = next((run for run in runs if run.strategy == "context"), None)
    if context_run is None:
        return {"available": False, "reason": "no context strategy run"}
    records_by_sample = {
        str(record.get("sample_id")): record
        for record in context_run.records
        if record.get("task") == "detection"
    }
    checked = 0
    mismatch_count = 0
    mismatches: list[dict[str, Any]] = []
    for unit in cohort_units:
        if isinstance(unit, PairUnit):
            candidates = [unit.vulnerable, unit.fixed]
        else:
            candidates = [unit]
        for side_unit in candidates:
            record = records_by_sample.get(side_unit.sample_id)
            if record is None:
                continue
            recorded = _prompt_context_state(record)
            if recorded == "unknown":
                continue
            checked += 1
            if recorded != side_unit.context_state:
                mismatch_count += 1
                if len(mismatches) < 5:
                    mismatches.append(
                        {
                            "sample_id": side_unit.sample_id,
                            "dataset_context_state": side_unit.context_state,
                            "prompt_context_state": recorded,
                        }
                    )
    return {
        "available": checked > 0,
        "checked": checked,
        "mismatch_count": mismatch_count,
        "examples": mismatches,
        "ok": mismatch_count == 0,
        "note": "Compares the runner's prompt.context.nonempty marker with the dataset-derived context state.",
    }


def _m3_vs_m1_independent(
    units: Sequence[Unit],
    labels: Sequence[bool],
    preds: Mapping[str, Sequence[bool | None]],
    context_states: Sequence[str],
    strategies: Sequence[str],
    args: argparse.Namespace,
    cluster_unit: str,
) -> dict[str, Any]:
    if "direct" not in strategies or "context" not in strategies:
        return {"available": False, "reason": "both direct (M1) and context (M3) runs are required"}

    def block(indices: Sequence[int]) -> dict[str, Any]:
        if not indices:
            return {"n": 0}
        m1 = stats.detection_scores(labels, preds["direct"], indices)
        m3 = stats.detection_scores(labels, preds["context"], indices)
        complete = [
            i
            for i in indices
            if preds["direct"][i] is not None and preds["context"][i] is not None
        ]
        # Local metric functions restricted to this stratum; the generic helper
        # would resample the whole cohort.
        def m1_strict(selected: Sequence[int]) -> float | None:
            return stats.detection_scores(labels, preds["direct"], selected).get("strict_accuracy")

        def m3_strict(selected: Sequence[int]) -> float | None:
            return stats.detection_scores(labels, preds["context"], selected).get("strict_accuracy")

        def delta_strict(selected: Sequence[int]) -> float | None:
            a = m3_strict(selected)
            b = m1_strict(selected)
            return None if a is None or b is None else float(a) - float(b)

        bootstrap = _bootstrap_block(
            units=units,
            indices=indices,
            cluster_unit=cluster_unit,
            metric_fns={
                "m1_strict_accuracy": m1_strict,
                "m3_strict_accuracy": m3_strict,
                "delta_strict_accuracy": delta_strict,
            },
            resamples=args.bootstrap,
            seed=args.seed,
            confidence=args.confidence,
        )
        delta_strict_point = (
            float(m3_strict(indices)) - float(m1_strict(indices))
            if m3_strict(indices) is not None and m1_strict(indices) is not None
            else None
        )
        if isinstance(bootstrap.get("metrics"), dict):
            entry = bootstrap["metrics"].get("delta_strict_accuracy")
            if isinstance(entry, dict):
                entry["point"] = delta_strict_point
        return {
            "n": len(indices),
            "m1": {
                "strict_accuracy": m1["strict_accuracy"],
                "accuracy_valid": m1["accuracy"],
                "macro_f1": m1["macro_f1"],
                "balanced_accuracy": m1["balanced_accuracy"],
                "mcc": m1["mcc"],
            },
            "m3": {
                "strict_accuracy": m3["strict_accuracy"],
                "accuracy_valid": m3["accuracy"],
                "macro_f1": m3["macro_f1"],
                "balanced_accuracy": m3["balanced_accuracy"],
                "mcc": m3["mcc"],
            },
            "delta": {
                "strict_accuracy": (
                    m3["strict_accuracy"] - m1["strict_accuracy"]
                    if m3["strict_accuracy"] is not None and m1["strict_accuracy"] is not None
                    else None
                ),
                "accuracy_valid": (
                    m3["accuracy"] - m1["accuracy"]
                    if m3["accuracy"] is not None and m1["accuracy"] is not None
                    else None
                ),
                "macro_f1": (
                    m3["macro_f1"] - m1["macro_f1"]
                    if m3["macro_f1"] is not None and m1["macro_f1"] is not None
                    else None
                ),
            },
            "complete_case_n": len(complete),
            "bootstrap": bootstrap,
        }

    overall = block(list(range(len(units))))
    by_stratum = {
        state: block([i for i, value in enumerate(context_states) if value == state])
        for state in CONTEXT_STATES
        if any(value == state for value in context_states)
    }
    return {
        "available": True,
        "overall": overall,
        "by_stratum": by_stratum,
        "note": "Exploratory M3-M1 comparison; strict accuracy counts invalid predictions as incorrect.",
    }


def _m3_vs_m1_pairs(
    units: Sequence[PairUnit],
    per_strategy: Mapping[str, Mapping[str, Sequence[bool | None]]],
    context_states: Sequence[str],
    strategies: Sequence[str],
    args: argparse.Namespace,
    cluster_unit: str,
) -> dict[str, Any]:
    if "direct" not in strategies or "context" not in strategies:
        return {"available": False, "reason": "both direct (M1) and context (M3) runs are required"}

    def block(indices: Sequence[int]) -> dict[str, Any]:
        if not indices:
            return {"n_pairs": 0}

        def joint(selected: Sequence[int], strategy: str) -> float | None:
            vulnerable = per_strategy[strategy]["vulnerable"]
            fixed = per_strategy[strategy]["fixed"]
            return stats.pair_scores(vulnerable, fixed, selected).get("joint_accuracy_all_pairs")

        def delta_joint(selected: Sequence[int]) -> float | None:
            a = joint(selected, "context")
            b = joint(selected, "direct")
            return None if a is None or b is None else float(a) - float(b)

        bootstrap = _bootstrap_block(
            units=units,
            indices=indices,
            cluster_unit=cluster_unit,
            metric_fns={
                "m1_joint_accuracy_all_pairs": lambda selected: joint(selected, "direct"),
                "m3_joint_accuracy_all_pairs": lambda selected: joint(selected, "context"),
                "delta_joint_accuracy_all_pairs": delta_joint,
            },
            resamples=args.bootstrap,
            seed=args.seed,
            confidence=args.confidence,
        )
        m1 = joint(indices, "direct")
        m3 = joint(indices, "context")
        if isinstance(bootstrap.get("metrics"), dict):
            entry = bootstrap["metrics"].get("delta_joint_accuracy_all_pairs")
            if isinstance(entry, dict):
                entry["point"] = None if m1 is None or m3 is None else m3 - m1
        return {
            "n_pairs": len(indices),
            "m1_joint_accuracy_all_pairs": m1,
            "m3_joint_accuracy_all_pairs": m3,
            "delta_joint_accuracy_all_pairs": None if m1 is None or m3 is None else m3 - m1,
            "bootstrap": bootstrap,
        }

    overall = block(list(range(len(units))))
    by_stratum = {
        state: block([i for i, value in enumerate(context_states) if value == state])
        for state in CONTEXT_STATES
        if any(value == state for value in context_states)
    }
    return {
        "available": True,
        "overall": overall,
        "by_stratum": by_stratum,
        "note": "Exploratory M3-M1 comparison on paired joint accuracy; invalid pairs count as failures in the all-pairs view.",
    }


def _group_m3_risk(
    dataset: DatasetInfo | None,
    observed_counts: Mapping[str, Mapping[str, int]],
    m3_vs_m1: Mapping[str, Any],
    l3_check: Mapping[str, Any],
    *,
    is_pairs: bool = False,
) -> dict[str, Any]:
    if dataset is not None:
        audit = dataset.context_audit
        risk_level = str(audit.get("risk_level") or "not_assessable")
        reasons = list(audit.get("reasons") or [])
        flags = list(audit.get("flags") or [])
        p_nonempty = audit.get("p_vulnerable_nonempty")
        p_empty = audit.get("p_vulnerable_empty")
        association_gap = audit.get("association_gap")
        pair_evidence = {
            "empty_pairs": audit.get("empty_pairs"),
            "nonempty_pairs": audit.get("nonempty_pairs"),
            "small_strata": audit.get("small_strata"),
        }
    else:
        risk_level = "not_assessable"
        reasons = ["no dataset join; context strata could not be reconstructed"]
        flags = []
        p_nonempty = p_empty = association_gap = None
        pair_evidence = {}

    if l3_check.get("mismatch_count"):
        flags.append("l3_prompt_metadata_mismatch")
        reasons.append("L3 prompt.context.nonempty 与数据集重建的 context 分层存在不一致")
    if m3_vs_m1.get("available") is False:
        reasons.append("M3-M1 分层差值不可用：需要同时存在 direct 与 context 运行")
    else:
        overall_delta = (
            m3_vs_m1.get("overall", {}).get("delta", {}).get("strict_accuracy")
            if not is_pairs
            else m3_vs_m1.get("overall", {}).get("delta_joint_accuracy_all_pairs")
        )
        if overall_delta is not None and abs(float(overall_delta)) > 0.01:
            if is_pairs:
                empty_pairs = pair_evidence.get("empty_pairs")
                reasons.append(
                    f"M3 与 M1 的联合准确率总体差值为 {float(overall_delta):+.4f}；"
                    f"配对集 context 为 pair-level，空上下文层仅 {empty_pairs} 对，分层差值不稳定"
                )
            else:
                reasons.append(
                    f"M3 与 M1 的总体差值为 {float(overall_delta):+.4f}；在 context 与标签相关的数据上不能单独归因于上下文推理"
                )

    dataset_evidence = {
        "p_vulnerable_nonempty": p_nonempty,
        "p_vulnerable_empty": p_empty,
        "association_gap": association_gap,
    }
    if is_pairs:
        dataset_evidence = pair_evidence
        caveat = (
            "配对集的 context 可用性由 pair 共享，不直接编码漏洞侧/修复侧标签；"
            "但空上下文层很小，M3-M1 的总体或分层差值仍不能单独归因于上下文推理。"
        )
    else:
        caveat = (
            "M3 的总体优势不能单独解释为“上下文推理能力”。在本数据中 context 是否非空与标签相关；"
            "必须同时报告非空/空分层、样本数和差值区间。"
        )

    return {
        "applies_to": "M3 (context strategy)",
        "risk_level": risk_level,
        "flags": sorted(set(flags)),
        "reasons": reasons,
        "dataset_evidence": dataset_evidence,
        "observed_context_counts": {strategy: dict(counts) for strategy, counts in observed_counts.items()},
        "l3_run_present": l3_check.get("available", False),
        "l3_metadata_check": dict(l3_check),
        "m3_vs_m1": dict(m3_vs_m1),
        "reporting_requirements": M3_REPORTING_REQUIREMENTS,
        "caveat": caveat,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "n/a"
        return f"{value:.{digits}f}"
    return str(value)


def _fmt_p(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float) and 0.0 <= value < 10 ** (-digits):
        return f"{value:.2e}"
    return _fmt(value, digits)


def _fmt_ci(entry: Mapping[str, Any] | None, digits: int = 4) -> str:
    if not isinstance(entry, Mapping) or entry.get("ci_low") is None or entry.get("ci_high") is None:
        return "n/a"
    point = entry.get("point")
    if point is None:
        return f"n/a [{_fmt(entry['ci_low'], digits)}, {_fmt(entry['ci_high'], digits)}]"
    return f"{_fmt(point, digits)} [{_fmt(entry['ci_low'], digits)}, {_fmt(entry['ci_high'], digits)}]"


def _fmt_wilson(entry: Mapping[str, Any] | None, digits: int = 4) -> str:
    if not isinstance(entry, Mapping) or entry.get("estimate") is None:
        return "n/a"
    return f"{_fmt(entry['estimate'], digits)} [{_fmt(entry['low'], digits)}, {_fmt(entry['high'], digits)}]"


def _score_cell(scores: Mapping[str, Any], key: str, bootstrap: Mapping[str, Any] | None = None) -> str:
    value = scores.get(key)
    if value is None:
        if scores.get("single_class_support") is True:
            return "n/a（单类别）"
        return "n/a"
    if isinstance(bootstrap, Mapping):
        entry = bootstrap.get(key)
        if isinstance(entry, Mapping) and entry.get("ci_low") is not None:
            return _fmt_ci({**entry, "point": value})
    return _fmt(value)


def _macro_cell(scores: Mapping[str, Any], bootstrap: Mapping[str, Any] | None = None) -> str:
    if scores.get("macro_f1") is None:
        if scores.get("single_class_support") is True:
            return "n/a（单类别）"
        return "n/a"
    return _score_cell(scores, "macro_f1", bootstrap)


def _mcc_cell(scores: Mapping[str, Any], bootstrap: Mapping[str, Any] | None = None) -> str:
    value = scores.get("mcc")
    if value is None:
        return "n/a"
    text = _score_cell(scores, "mcc", bootstrap)
    if scores.get("mcc_degenerate"):
        text += "（退化）"
    return text


def _strategy_name(strategy: str) -> str:
    return STRATEGY_LABELS.get(strategy, strategy)


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _render_dataset_audit(aggregation: Mapping[str, Any]) -> list[str]:
    lines: list[str] = ["## 2. 数据集上下文审计（不依赖模型运行）", ""]
    datasets = aggregation.get("datasets") or []
    if not datasets:
        lines.append("未找到默认数据集文件；无法生成数据层面的 context 审计。")
        lines.append("")
        return lines
    for dataset in datasets:
        dataset_type = dataset.get("dataset_type")
        lines.append(f"### {dataset_type} · n={dataset.get('n_units')}")
        lines.append("")
        lines.append(
            f"- 数据文件：`{dataset.get('path')}`  "
            f"(SHA-256 `{dataset.get('sha256')}`)"
        )
        lines.append(f"- 项目数：{dataset.get('project_count')}；标签计数：{dataset.get('label_counts')}")
        audit = dataset.get("context_audit") or {}
        if dataset_type == "independent":
            counts = audit.get("counts") or {}
            rows = []
            for state in CONTEXT_STATES:
                bucket = counts.get(state)
                if not bucket:
                    continue
                n = bucket.get("vulnerable", 0) + bucket.get("non_vulnerable", 0)
                rows.append(
                    [
                        state,
                        n,
                        bucket.get("vulnerable", 0),
                        bucket.get("non_vulnerable", 0),
                        _fmt(
                            (bucket.get("vulnerable", 0) / n) if n else None
                        ),
                    ]
                )
            lines.append("")
            lines.append(_table(["context 分层", "n", "漏洞", "非漏洞", "漏洞比例"], rows))
            lines.append("")
        else:
            combo = audit.get("pair_context_combinations") or {}
            rows = [[key, value] for key, value in sorted(combo.items())]
            lines.append("")
            lines.append(_table(["漏洞侧/修复侧 context", "对数"], rows))
            lines.append("")
        lines.append(
            f"- **数据层面 M3 伪影风险：`{audit.get('risk_level')}`**"
        )
        for reason in audit.get("reasons") or []:
            lines.append(f"  - {reason}")
        if audit.get("flags"):
            lines.append(f"- flags: {', '.join(str(flag) for flag in audit['flags'])}")
        lines.append("")
    m3_summary = aggregation.get("m3_artifact_risk") or {}
    lines.append(f"### M3 总体风险：`{m3_summary.get('risk_level', 'n/a')}`")
    lines.append("")
    if m3_summary.get("summary"):
        lines.append(str(m3_summary["summary"]))
        lines.append("")
    lines.append("### M3 报告要求（与是否有模型运行无关）")
    lines.append("")
    for requirement in M3_REPORTING_REQUIREMENTS:
        lines.append(f"- {requirement}")
    lines.append("")
    return lines


def _render_group_independent(group: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    strategies = group.get("strategies") or []
    valid_only = group.get("valid_only") or {}
    end_to_end = group.get("end_to_end") or {}
    bootstrap = (group.get("bootstrap") or {}).get("valid_only") or {}
    boot_metrics = bootstrap.get("metrics") or {}
    cohort = group.get("cohort") or {}

    lines.append(f"### {group.get('group_id')}")
    lines.append("")
    lines.append(
        f"- cohort n={cohort.get('n')}；complete-case n={cohort.get('complete_case_n')}；"
        f"参考策略={cohort.get('reference_strategy')}"
    )
    excluded = cohort.get("excluded") or {}
    if any(value for value in excluded.values()):
        lines.append(f"- 未进入 cohort 的单元数：{excluded}")
    lines.append("")
    headers = [
        "策略",
        "n",
        "有效",
        "覆盖率",
        "Precision",
        "Recall",
        "Specificity",
        "正类 F1",
        "Accuracy",
        "Balanced Acc",
        "MCC",
        "Macro-F1",
        "严格 Acc（全部）",
    ]
    rows = []
    for strategy in strategies:
        scores = valid_only.get(strategy) or {}
        all_scores = end_to_end.get(strategy) or {}
        boot = boot_metrics.get(strategy) or {}
        rows.append(
            [
                _strategy_name(strategy),
                cohort.get("n", "n/a"),
                scores.get("valid", "n/a"),
                _fmt_wilson((all_scores.get("wilson") or {}).get("coverage")),
                _fmt_wilson((scores.get("wilson") or {}).get("precision")),
                _fmt_wilson((scores.get("wilson") or {}).get("recall")),
                _fmt_wilson((scores.get("wilson") or {}).get("specificity")),
                _fmt(scores.get("positive_f1")),
                _fmt_wilson((scores.get("wilson") or {}).get("accuracy")),
                _score_cell(scores, "balanced_accuracy", boot),
                _mcc_cell(scores, boot),
                _macro_cell(scores, boot),
                _fmt_wilson((all_scores.get("wilson") or {}).get("strict_accuracy")),
            ]
        )
    lines.append(_table(headers, rows))
    lines.append("")
    lines.append(
        "> 表中 n 为 cohort 全部单元数，有效为 complete-case 单元数（在每个策略都有有效预测）；"
        "覆盖率为全部 cohort 单元上的有效比例。Macro-F1、Balanced Acc、MCC 的方括号为 "
        f"{bootstrap.get('settings', {}).get('resamples', 'n/a')} 次 "
        f"{bootstrap.get('settings', {}).get('cluster_unit', 'n/a')} cluster bootstrap 的 95% percentile 区间；"
        "Precision/Recall/Specificity/Accuracy 的方括号为 Wilson 95% 区间。"
    )
    if any((valid_only.get(strategy) or {}).get("single_class_support") for strategy in strategies):
        lines.append("> `n/a（单类别）` 表示该计算层内只有一个类别，macro-F1/balanced accuracy 不可定义；"
                     "不要把该格填成 0。")
    lines.append("")
    return lines


def _render_group_pairs(group: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    strategies = group.get("strategies") or []
    valid_only = group.get("valid_only") or {}
    end_to_end = group.get("end_to_end") or {}
    cohort = group.get("cohort") or {}

    lines.append(f"### {group.get('group_id')}")
    lines.append("")
    lines.append(
        f"- cohort 对数={cohort.get('n')}；complete-case 对数={cohort.get('complete_case_n')}；"
        f"参考策略={cohort.get('reference_strategy')}"
    )
    excluded = cohort.get("excluded") or {}
    if any(value for value in excluded.values()):
        lines.append(f"- 未进入 cohort 的对数：{excluded}")
    lines.append("")
    headers = [
        "策略",
        "对数",
        "有效对",
        "覆盖率",
        "联合 Acc（有效对）",
        "联合 Acc（全部对）",
        "正确区分",
        "双报漏洞",
        "双报安全",
        "判反（漏报+误报）",
    ]
    rows = []
    for strategy in strategies:
        scores = valid_only.get(strategy) or {}
        all_scores = end_to_end.get(strategy) or {}
        categories = scores.get("joint_categories") or {}
        rates = scores.get("joint_rates_valid_pairs") or {}
        rows.append(
            [
                _strategy_name(strategy),
                cohort.get("n", "n/a"),
                scores.get("valid_pairs", "n/a"),
                _fmt_wilson((all_scores.get("wilson") or {}).get("coverage")),
                _fmt_wilson((scores.get("wilson") or {}).get("joint_accuracy_valid_pairs")),
                _fmt_wilson((all_scores.get("wilson") or {}).get("joint_accuracy_all_pairs")),
                f"{categories.get('vulnerable_detected_fixed_clean', 0)} ({_fmt(rates.get('vulnerable_detected_fixed_clean'))})",
                f"{categories.get('both_flagged', 0)} ({_fmt(rates.get('both_flagged'))})",
                f"{categories.get('both_clean', 0)} ({_fmt(rates.get('both_clean'))})",
                f"{scores.get('swapped', 0)} ({_fmt(scores.get('swapped_rate'))})",
            ]
        )
    lines.append(_table(headers, rows))
    lines.append("")
    lines.append(
        "> 表中“对数”为 cohort 全部 pair 数，“有效对”为 complete-case pair 数；覆盖率为全部 cohort "
        "pair 上的有效比例。联合 Acc（有效对）只使用两侧都有效的 pair；联合 Acc（全部对）把任一侧"
        "无效的 pair 计为失败。口径与 `runner/secvul_runner/metrics.py` 的 "
        "`discrimination_accuracy_valid_pairs` / `discrimination_accuracy_all_pairs` 一致。"
    )
    lines.append("")

    lines.append("#### 分侧指标（Table 8 准备）")
    lines.append("")
    headers = [
        "策略",
        "覆盖率",
        "漏洞侧 n",
        "漏洞侧 P",
        "漏洞侧 R",
        "漏洞侧 F1",
        "修复侧 n",
        "修复侧 Accuracy",
        "修复侧 Specificity",
        "总体 Accuracy",
    ]
    rows = []
    for strategy in strategies:
        per_version = (valid_only.get(strategy) or {}).get("per_version_valid_only") or {}
        vulnerable = per_version.get("vulnerable") or {}
        fixed = per_version.get("fixed") or {}
        pooled = per_version.get("pooled") or {}
        all_scores = end_to_end.get(strategy) or {}
        rows.append(
            [
                _strategy_name(strategy),
                _fmt_wilson((all_scores.get("wilson") or {}).get("coverage")),
                vulnerable.get("n", "n/a"),
                _fmt_wilson((vulnerable.get("wilson") or {}).get("precision")),
                _fmt_wilson((vulnerable.get("wilson") or {}).get("recall")),
                _fmt(vulnerable.get("positive_f1")),
                fixed.get("n", "n/a"),
                _fmt_wilson((fixed.get("wilson") or {}).get("accuracy")),
                _fmt_wilson((fixed.get("wilson") or {}).get("specificity")),
                _fmt_wilson((pooled.get("wilson") or {}).get("accuracy")),
            ]
        )
    lines.append(_table(headers, rows))
    lines.append("")
    lines.append("> 分侧指标把每个版本当作一条检测记录，仅作次要描述；配对相关未在 Wilson 区间中校正。")
    lines.append("")
    return lines


def _render_pairwise(group: Mapping[str, Any]) -> list[str]:
    pairwise = group.get("pairwise") or {}
    if not pairwise.get("available"):
        return []
    lines: list[str] = ["#### 逐样本 McNemar 精确检验（Holm 校正）", ""]
    for label, key in (("主分析（全部单元，invalid=错）", "primary"), ("次要分析（两侧均有效）", "secondary")):
        block = pairwise.get(key) or {}
        rows = []
        for row in block.get("comparisons") or []:
            rows.append(
                [
                    f"{_strategy_name(row['strategy_a'])} vs {_strategy_name(row['strategy_b'])}",
                    row.get("total"),
                    row.get("a_correct_b_wrong"),
                    row.get("a_wrong_b_correct"),
                    _fmt_p(row.get("p_value")),
                    _fmt_p(row.get("p_holm")),
                    "是" if row.get("reject_holm_0_05") else "否",
                    _fmt(row.get("risk_difference")),
                    _fmt(row.get("odds_ratio")),
                ]
            )
        if rows:
            lines.append(f"**{label}** · metric=`{block.get('metric')}`")
            lines.append("")
            lines.append(
                _table(
                    ["比较", "n", "A✓B✗", "A✗B✓", "p（原始）", "p（Holm）", "拒绝 H0（α=0.05）", "风险差", "OR"],
                    rows,
                )
            )
            lines.append("")
    lines.extend(
        [
            "> McNemar 假设单元独立；同项目单元相关会使 p 值偏小。主推断应以按 project/pair 聚类的 bootstrap 差值区间为准，McNemar 仅作次要证据。",
            "",
        ]
    )
    return lines


def _render_bootstrap_deltas(group: Mapping[str, Any]) -> list[str]:
    bootstrap = group.get("bootstrap") or {}
    valid = (bootstrap.get("valid_only") or {}).get("deltas") or {}
    end = (bootstrap.get("end_to_end") or {}).get("deltas") or {}
    if not valid and not end:
        return []
    lines: list[str] = ["#### 聚类 bootstrap 差值区间", ""]
    metric_names = (
        ("macro_f1", "Macro-F1"),
        ("balanced_accuracy", "Balanced Acc"),
        ("mcc", "MCC"),
        ("accuracy", "Accuracy"),
        ("joint_accuracy_valid_pairs", "联合 Acc（有效对）"),
        ("joint_accuracy_all_pairs", "联合 Acc（全部对）"),
        ("strict_accuracy", "严格 Acc（全部）"),
    )
    if group.get("dataset_type") == "independent":
        source = valid
    else:
        source = valid
    rows = []
    for comparison, metrics in source.items():
        for metric, label in metric_names:
            entry = metrics.get(metric)
            if isinstance(entry, Mapping):
                rows.append(
                    [
                        comparison.replace("_vs_", " vs "),
                        label,
                        _fmt_ci(entry),
                        entry.get("valid_resamples"),
                    ]
                )
    if rows:
        lines.append(_table(["比较", "指标", "Δ [95% bootstrap CI]", "有效重采样"], rows))
        lines.append("")
    if end:
        rows = []
        for comparison, metrics in end.items():
            for metric, label in (("strict_accuracy", "严格 Acc（全部）"), ("joint_accuracy_all_pairs", "联合 Acc（全部对）"), ("coverage", "覆盖率")):
                entry = metrics.get(metric)
                if isinstance(entry, Mapping):
                    rows.append([comparison.replace("_vs_", " vs "), label, _fmt_ci(entry), entry.get("valid_resamples")])
        if rows:
            lines.append(_table(["比较", "指标（end-to-end）", "Δ [95% bootstrap CI]", "有效重采样"], rows))
            lines.append("")
    lines.append(
        "> 差值方向为 A−B（按策略顺序）；同一 cluster 重采样同时用于两个策略，因此区间是配对差值区间。"
        "有效重采样少于总数 90% 时标记为不稳定。"
    )
    lines.append("")
    return lines


def _render_context_strata(group: Mapping[str, Any]) -> list[str]:
    context = group.get("context_strata") or {}
    strategies_block = context.get("strategies") or {}
    if not strategies_block:
        return []
    lines: list[str] = ["#### context 非空/空分层（M3 伪影检查）", ""]
    is_pairs = group.get("dataset_type") == "pairs"
    if is_pairs:
        headers = ["策略", "context 分层", "对数", "有效对", "覆盖率", "联合 Acc（有效对）", "联合 Acc（全部对）", "双报漏洞", "双报安全"]
    else:
        headers = ["策略", "context 分层", "n", "漏洞/非漏洞", "有效", "覆盖率", "正类 F1", "负类 F1", "Accuracy", "Macro-F1"]
    rows = []
    for strategy, strata in strategies_block.items():
        for state, block in strata.items():
            if is_pairs:
                scores = block.get("metrics") or {}
                rows.append(
                    [
                        _strategy_name(strategy),
                        state,
                        block.get("n_pairs"),
                        block.get("valid_pairs"),
                        _fmt_wilson((scores.get("wilson") or {}).get("coverage")),
                        _fmt_wilson((scores.get("wilson") or {}).get("joint_accuracy_valid_pairs")),
                        _fmt_wilson((scores.get("wilson") or {}).get("joint_accuracy_all_pairs")),
                        _fmt((scores.get("joint_rates_valid_pairs") or {}).get("both_flagged")),
                        _fmt((scores.get("joint_rates_valid_pairs") or {}).get("both_clean")),
                    ]
                )
            else:
                scores = block.get("metrics") or {}
                label_counts = block.get("label_counts") or {}
                rows.append(
                    [
                        _strategy_name(strategy),
                        state,
                        block.get("n"),
                        f"{label_counts.get('vulnerable', 0)}/{label_counts.get('non_vulnerable', 0)}",
                        block.get("valid"),
                        _fmt_wilson((scores.get("wilson") or {}).get("coverage")),
                        _fmt(scores.get("positive_f1")),
                        _fmt(scores.get("negative_f1")),
                        _fmt_wilson((scores.get("wilson") or {}).get("accuracy")),
                        _macro_cell(scores),
                    ]
                )
    lines.append(_table(headers, rows))
    lines.append("")
    l3_check = context.get("l3_metadata_check") or {}
    if l3_check.get("available"):
        lines.append(
            f"- L3 prompt 元数据交叉检查：检查 {l3_check.get('checked')} 条，"
            f"不一致 {l3_check.get('mismatch_count')} 条。"
        )
    m3 = context.get("m3_vs_m1") or {}
    if m3.get("available"):
        lines.append("")
        lines.append("**M3 − M1 分层差值（探索性）**")
        lines.append("")
        if is_pairs:
            rows = []
            for state, block in (m3.get("by_stratum") or {}).items():
                rows.append(
                    [
                        state,
                        block.get("n_pairs"),
                        _fmt(block.get("delta_joint_accuracy_all_pairs")),
                        _fmt_ci((block.get("bootstrap") or {}).get("metrics", {}).get("delta_joint_accuracy_all_pairs")),
                    ]
                )
            lines.append(_table(["分层", "对数", "Δ联合 Acc", "Δ [bootstrap CI]"], rows))
        else:
            rows = []
            for state, block in (m3.get("by_stratum") or {}).items():
                delta = block.get("delta") or {}
                boot = ((block.get("bootstrap") or {}).get("metrics") or {}).get("delta_strict_accuracy")
                rows.append(
                    [
                        state,
                        block.get("n"),
                        _fmt(delta.get("strict_accuracy")),
                        _fmt_ci(boot),
                        _fmt(delta.get("accuracy_valid")),
                        _fmt(delta.get("macro_f1")),
                    ]
                )
            lines.append(_table(["分层", "n", "Δ严格 Acc", "Δ严格 Acc [CI]", "ΔAccuracy（有效）", "ΔMacro-F1"], rows))
        lines.append("")
    lines.append(
        "> `n/a（单类别）` 表示该分层内只有一个类别；此时 macro-F1/balanced accuracy 不可定义。"
        "独立集的 context 非空层全部为漏洞样本（空层以非漏洞样本为主）时，分层 macro-F1 无法估计，"
        "只能报告正类 F1/召回（非空层）或 specificity/负类 F1（空层）。"
    )
    lines.append("")
    return lines


def _render_m3_risk(group: Mapping[str, Any]) -> list[str]:
    risk = group.get("m3_artifact_risk") or {}
    lines: list[str] = ["#### M3 伪影风险评估", ""]
    lines.append(f"- **风险等级：`{risk.get('risk_level', 'n/a')}`**")
    lines.append(f"- 适用对象：{risk.get('applies_to', 'M3 / context')}")
    evidence = risk.get("dataset_evidence") or {}
    if evidence.get("empty_pairs") is not None or evidence.get("nonempty_pairs") is not None:
        lines.append(
            f"- 配对 context：非空 {evidence.get('nonempty_pairs')} 对，"
            f"空 {evidence.get('empty_pairs')} 对，小分层 {evidence.get('small_strata')}"
        )
    else:
        lines.append(
            f"- 数据层面：P(漏洞|context 非空)={_fmt(evidence.get('p_vulnerable_nonempty'))}，"
            f"P(漏洞|context 空)={_fmt(evidence.get('p_vulnerable_empty'))}，"
            f"差值={_fmt(evidence.get('association_gap'))}"
        )
    for reason in risk.get("reasons") or []:
        lines.append(f"- {reason}")
    if risk.get("flags"):
        lines.append(f"- flags: {', '.join(str(flag) for flag in risk['flags'])}")
    lines.append("")
    lines.append("**报告时必须遵守：**")
    for requirement in risk.get("reporting_requirements") or M3_REPORTING_REQUIREMENTS:
        lines.append(f"- {requirement}")
    lines.append("")
    return lines


def _render_groups(aggregation: Mapping[str, Any]) -> list[str]:
    groups = aggregation.get("groups") or []
    lines: list[str] = ["## 3. 模型结果聚合", ""]
    if not groups:
        lines.append("没有可用于聚合的模型结果；未生成任何性能表，也未用 fixture/mock 填充。")
        lines.append("")
        return lines
    for group in groups:
        if group.get("dataset_type") == "independent":
            lines.extend(_render_group_independent(group))
            lines.extend(_render_context_strata(group))
            lines.extend(_render_m3_risk(group))
        else:
            lines.extend(_render_group_pairs(group))
            lines.extend(_render_context_strata(group))
            lines.extend(_render_m3_risk(group))
        lines.extend(_render_pairwise(group))
        lines.extend(_render_bootstrap_deltas(group))
        lines.append("---")
        lines.append("")
    return lines


def render_markdown(aggregation: Mapping[str, Any]) -> str:
    lines: list[str] = ["# SecVulEval 统计分析聚合", ""]
    status = aggregation.get("status")
    fixture_mode = aggregation.get("fixture_mode")
    if fixture_mode:
        if aggregation.get("experimental_results"):
            lines.append(
                "> **本文件包含 SYNTHETIC FIXTURE 运行；fixture 行不是实验结果，不得引用为模型性能。**"
            )
        else:
            lines.append("> **SYNTHETIC FIXTURE — 不是实验结果，不得引用为模型性能。**")
        lines.append("")
    if status == "no_real_runs":
        lines.append("> **没有发现可用于聚合的真实 runner 运行。本文件不包含任何模型性能数值。**")
        lines.append(">")
        lines.append("> 真实 DeepSeek 调用当前因凭证问题返回 401；项目禁止用 mock/fixture 填正式结果表。")
        lines.append("")
    elif status == "input_error":
        lines.append("> **运行输入无法形成可比较的组（例如重复策略运行、缺少文件或配置错误）；本文件不包含模型性能数值。**")
        lines.append("")

    config = aggregation.get("config") or {}
    lines.append("## 0. 分析配置")
    lines.append("")
    lines.append(
        _table(
            ["项目", "值"],
            [
                ["生成时间 (UTC)", aggregation.get("generated_at_utc")],
                ["analysis 版本", aggregation.get("analysis_version")],
                ["状态", status],
                ["是否包含真实实验结果", aggregation.get("experimental_results")],
                ["fixture 模式", fixture_mode],
                ["runs root", config.get("runs_root")],
                ["datasets root", config.get("dataset_root")],
                ["bootstrap 次数", config.get("bootstrap_resamples")],
                ["bootstrap seed", config.get("bootstrap_seed")],
                ["置信水平", config.get("confidence")],
                ["cluster 单位", config.get("cluster_unit")],
                ["percentile 方法", config.get("percentile_method")],
            ],
        )
    )
    lines.append("")

    lines.append("## 1. 运行清单")
    lines.append("")
    runs = aggregation.get("runs") or {}
    included = runs.get("included") or []
    skipped = runs.get("skipped") or []
    if included:
        rows = []
        for run in included:
            rows.append(
                [
                    run.get("run_id"),
                    run.get("dataset_type"),
                    _strategy_name(run.get("strategy")),
                    run.get("task"),
                    run.get("model"),
                    run.get("n_units"),
                    _fmt(run.get("coverage")),
                    "是" if run.get("partial") else "否",
                    "是" if run.get("fixture") else "否",
                    "是" if run.get("aggregated") else "否",
                    "ok" if (run.get("cross_check") or {}).get("ok") else "mismatch",
                ]
            )
        lines.append(
            _table(
                ["run_id", "数据集", "策略", "任务", "模型", "单元数", "覆盖率", "partial", "fixture", "已入组", "metrics 交叉检查"],
                rows,
            )
        )
    else:
        lines.append("未发现已完成的真实运行目录。")
    lines.append("")
    if skipped:
        lines.append("### 跳过的运行")
        lines.append("")
        lines.append(
            _table(
                ["路径", "原因", "细节"],
                [[run.get("path"), run.get("reason"), run.get("detail") or ""] for run in skipped],
            )
        )
        lines.append("")

    dataset_lines = _render_dataset_audit(aggregation)
    if dataset_lines:
        lines.extend(dataset_lines)

    group_lines = _render_groups(aggregation)
    if group_lines:
        lines.extend(group_lines)

    warnings = aggregation.get("warnings") or []
    lines.append("## 4. 警告")
    lines.append("")
    if warnings:
        for warning in warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- 无。")
    lines.append("")

    lines.append("## 5. 复现命令")
    lines.append("")
    lines.append("```bash")
    lines.append("wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \\")
    lines.append("python3 analysis/analyze_runs.py \\")
    lines.append("  --runs-root runner/runs \\")
    lines.append(
        f"  --bootstrap {config.get('bootstrap_resamples', 10000)} "
        f"--seed {config.get('bootstrap_seed', 42)}'"
    )
    lines.append("```")
    lines.append("")
    lines.append("自检（临时合成 fixture，运行后自动删除，不写入正式结果）：")
    lines.append("")
    lines.append("```bash")
    lines.append("wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && python3 analysis/selftest.py'")
    lines.append("```")
    lines.append("")

    lines.append("## 6. 限制")
    lines.append("")
    for limitation in aggregation.get("limitations") or []:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _run_summary(
    run: RunData,
    units: Sequence[Unit] | Sequence[PairUnit],
    cross_check: dict[str, Any],
    *,
    aggregated: bool,
) -> dict[str, Any]:
    if run.dataset_type == "independent":
        assert all(isinstance(unit, Unit) for unit in units)
        valid = sum(1 for unit in units if unit.pred is not None)
        n_units = len(units)
        coverage = valid / n_units if n_units else None
    else:
        assert all(isinstance(unit, PairUnit) for unit in units)
        valid = sum(
            1 for unit in units if unit.vulnerable.pred is not None and unit.fixed.pred is not None
        )
        n_units = len(units)
        coverage = valid / n_units if n_units else None
    return {
        "run_id": run.run_id,
        "path": str(run.path),
        "dataset_type": run.dataset_type,
        "strategy": run.strategy,
        "strategy_label": STRATEGY_LABELS.get(run.strategy, run.strategy),
        "task": run.task,
        "model": run.model,
        "run_label": run.run_label,
        "partial": run.partial,
        "incomplete": run.incomplete,
        "fixture": run.fixture,
        "n_units": n_units,
        "n_valid_units": valid,
        "coverage": coverage,
        "aggregated": aggregated,
        "cross_check": cross_check,
        "warnings": run.warnings,
    }


def _build_report_tables(groups: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    detection_rows: list[dict[str, Any]] = []
    joint_rows: list[dict[str, Any]] = []
    side_rows: list[dict[str, Any]] = []
    pairwise_rows: list[dict[str, Any]] = []
    strata_rows: list[dict[str, Any]] = []

    for group in groups:
        strategies = group.get("strategies") or []
        if group.get("dataset_type") == "independent":
            boot_metrics = ((group.get("bootstrap") or {}).get("valid_only") or {}).get("metrics") or {}
            for strategy in strategies:
                scores = (group.get("valid_only") or {}).get(strategy) or {}
                end = (group.get("end_to_end") or {}).get(strategy) or {}
                boot = boot_metrics.get(strategy) or {}
                detection_rows.append(
                    {
                        "group_id": group.get("group_id"),
                        "dataset_type": "independent",
                        "model": group.get("model"),
                        "strategy": strategy,
                        "strategy_label": STRATEGY_LABELS.get(strategy, strategy),
                        "n": (group.get("cohort") or {}).get("n"),
                        "n_complete_case": scores.get("n"),
                        "valid": scores.get("valid"),
                        "coverage": end.get("coverage"),
                        "precision": scores.get("precision"),
                        "recall": scores.get("recall"),
                        "specificity": scores.get("specificity"),
                        "positive_f1": scores.get("positive_f1"),
                        "accuracy": scores.get("accuracy"),
                        "balanced_accuracy": scores.get("balanced_accuracy"),
                        "mcc": scores.get("mcc"),
                        "macro_f1": scores.get("macro_f1"),
                        "strict_accuracy": end.get("strict_accuracy"),
                        "bootstrap": boot,
                    }
                )
        else:
            for strategy in strategies:
                scores = (group.get("valid_only") or {}).get(strategy) or {}
                end = (group.get("end_to_end") or {}).get(strategy) or {}
                joint_rows.append(
                    {
                        "group_id": group.get("group_id"),
                        "dataset_type": "pairs",
                        "model": group.get("model"),
                        "strategy": strategy,
                        "strategy_label": STRATEGY_LABELS.get(strategy, strategy),
                        "n_pairs": (group.get("cohort") or {}).get("n"),
                        "valid_pairs": scores.get("valid_pairs"),
                        "coverage": end.get("coverage"),
                        "joint_accuracy_valid_pairs": scores.get("joint_accuracy_valid_pairs"),
                        "joint_accuracy_all_pairs": end.get("joint_accuracy_all_pairs"),
                        "joint_categories": scores.get("joint_categories"),
                        "joint_rates_valid_pairs": scores.get("joint_rates_valid_pairs"),
                    }
                )
                per_version = scores.get("per_version_valid_only") or {}
                for side in ("vulnerable", "fixed"):
                    side_scores = per_version.get(side) or {}
                    side_rows.append(
                        {
                            "group_id": group.get("group_id"),
                            "strategy": strategy,
                            "strategy_label": STRATEGY_LABELS.get(strategy, strategy),
                            "side": side,
                            "n": side_scores.get("n"),
                            "valid": side_scores.get("valid"),
                            "coverage": end.get("coverage"),
                            "precision": side_scores.get("precision"),
                            "recall": side_scores.get("recall"),
                            "specificity": side_scores.get("specificity"),
                            "f1": side_scores.get("positive_f1"),
                            "accuracy": side_scores.get("accuracy"),
                        }
                    )
        pairwise = group.get("pairwise") or {}
        for family, key in (("primary", "primary"), ("secondary", "secondary")):
            block = pairwise.get(key) or {}
            for row in block.get("comparisons") or []:
                pairwise_rows.append(
                    {
                        "group_id": group.get("group_id"),
                        "family": family,
                        "metric": block.get("metric"),
                        **row,
                    }
                )
        for strategy, strata in ((group.get("context_strata") or {}).get("strategies") or {}).items():
            for state, block in strata.items():
                strata_rows.append(
                    {
                        "group_id": group.get("group_id"),
                        "dataset_type": group.get("dataset_type"),
                        "strategy": strategy,
                        "context_state": state,
                        "n": block.get("n") or block.get("n_pairs"),
                        "block": block,
                    }
                )

    return {
        "table7_detection": detection_rows,
        "table8_pairs_by_side": side_rows,
        "table9_pairs_joint": joint_rows,
        "mcnemar": pairwise_rows,
        "table_context_strata": strata_rows,
    }


def run_analysis(args: argparse.Namespace) -> dict[str, Any]:
    if args.bootstrap < 0:
        raise AnalysisError("--bootstrap must be >= 0")
    if not 0.0 < args.confidence < 1.0:
        raise AnalysisError("--confidence must be in (0, 1)")

    classifier = ContextClassifier()
    dataset_store = DatasetStore(args.dataset_root, classifier)
    run_dirs = discover_run_dirs(args.runs_root, args.run)
    skipped: list[dict[str, Any]] = []
    loaded: list[RunData] = []

    for path in run_dirs:
        run, skip = load_run(
            path,
            allow_fixture=args.allow_fixture,
            include_partial=args.include_partial,
            allow_incomplete=args.allow_incomplete,
        )
        if skip is not None:
            skipped.append(skip)
            continue
        assert run is not None
        dataset_path = resolve_dataset_path(run, args.dataset_root)
        dataset: DatasetInfo | None = None
        if dataset_path is not None:
            dataset = dataset_store.get(dataset_path)
            if dataset is None:
                skipped.append(
                    _skip(run.path, "dataset_load_failed", dataset_store.error_for(dataset_path))
                )
                continue
            if run.dataset_sha256 and dataset.sha256 != run.dataset_sha256:
                detail = f"run expects {run.dataset_sha256}, file is {dataset.sha256}"
                if not args.allow_dataset_mismatch:
                    skipped.append(_skip(run.path, "dataset_sha256_mismatch", detail))
                    continue
                run.warnings.append(f"dataset SHA-256 mismatch allowed: {detail}")
            if run.dataset_type != dataset.dataset_type:
                skipped.append(
                    _skip(
                        run.path,
                        "dataset_type_mismatch",
                        f"run={run.dataset_type}, file={dataset.dataset_type}",
                    )
                )
                continue
        else:
            run.warnings.append("dataset file not found; project/context join is unavailable")
        try:
            if run.dataset_type == "independent":
                units = build_independent_units(run, dataset)
                run._units = units  # type: ignore[attr-defined]
                cross_check = cross_check_run(run, units)
            else:
                pair_units = build_pair_units(run, dataset)
                run._pair_units = pair_units  # type: ignore[attr-defined]
                cross_check = cross_check_run(run, pair_units)
                units = pair_units
        except AnalysisError as exc:
            skipped.append(_skip(run.path, "unit_build_failed", str(exc)))
            continue
        run._cross_check = cross_check  # type: ignore[attr-defined]
        run._dataset = dataset  # type: ignore[attr-defined]
        if not cross_check.get("ok"):
            run.warnings.append("metrics.json cross-check failed; see run summary")
            if args.strict:
                skipped.append(_skip(run.path, "metrics_cross_check_failed", str(cross_check.get("mismatches"))))
                continue
        loaded.append(run)

    # Group by dataset/model/task and resolve duplicate strategies.
    grouped: dict[tuple[str, str, str, str], list[RunData]] = {}
    for run in loaded:
        dataset = getattr(run, "_dataset", None)
        grouped.setdefault(_group_key(run, dataset), []).append(run)

    groups: list[dict[str, Any]] = []
    warnings: list[str] = []
    for key, runs in sorted(grouped.items(), key=lambda item: str(item[0])):
        by_strategy: dict[str, list[RunData]] = {}
        for run in runs:
            by_strategy.setdefault(run.strategy, []).append(run)
        selected: list[RunData] = []
        for strategy, candidates in by_strategy.items():
            candidates.sort(key=lambda run: (run.completed_at or "", str(run.path)))
            if len(candidates) > 1:
                if args.on_duplicate == "error":
                    detail = ", ".join(str(run.path) for run in candidates)
                    warnings.append(
                        f"group {key}: duplicate runs for strategy {strategy}; group skipped. "
                        f"Use --on-duplicate latest/first or select --run explicitly. Candidates: {detail}"
                    )
                    selected = []
                    break
                chosen = candidates[-1] if args.on_duplicate == "latest" else candidates[0]
                for other in candidates:
                    if other is not chosen:
                        skipped.append(
                            _skip(
                                other.path,
                                "duplicate_strategy_run",
                                f"selected {chosen.path} via --on-duplicate {args.on_duplicate}",
                            )
                        )
                selected.append(chosen)
            else:
                selected.append(candidates[0])
        if not selected:
            continue
        selected.sort(key=lambda run: _strategy_sort_key(run.strategy))
        dataset_shas = {
            getattr(run, "_dataset", None).sha256
            if getattr(run, "_dataset", None) is not None
            else None
            for run in selected
        }
        if len(dataset_shas) > 1:
            warnings.append(f"group {key}: runs reference different datasets; group skipped")
            continue
        dataset = getattr(selected[0], "_dataset", None)
        # Cross-check labels/projects/context state consistency before building metrics.
        try:
            if selected[0].dataset_type == "independent":
                group = _independent_group(selected, dataset, args)
            else:
                group = _pair_group(selected, dataset, args)
        except AnalysisError as exc:
            warnings.append(f"group {key}: analysis failed: {exc}")
            continue
        groups.append(group)

    # Dataset audit: always include the default datasets, plus run datasets.
    datasets: list[DatasetInfo] = []
    seen_sha: set[str] = set()
    for dataset_type, filename in DEFAULT_DATASET_FILES.items():
        path = args.dataset_root / filename
        if not path.exists():
            warnings.append(f"default dataset not found: {path}")
        elif dataset_store.get(path) is None:
            warnings.append(
                f"default dataset could not be loaded: {path}: {dataset_store.error_for(path)}"
            )
    for run in loaded:
        dataset = getattr(run, "_dataset", None)
        if dataset is not None and dataset.sha256 not in seen_sha:
            datasets.append(dataset)
            seen_sha.add(dataset.sha256)
    for dataset in dataset_store.default_datasets():
        if dataset.sha256 not in seen_sha:
            datasets.append(dataset)
            seen_sha.add(dataset.sha256)
    for dataset in datasets:
        if dataset.dataset_type == "independent" and dataset.context_audit.get("risk_level") == "high":
            warnings.append(
                "independent dataset: context availability is strongly associated with the label; "
                "M3 overall comparisons are confounded and must be reported with context strata."
            )

    aggregated_paths = {
        run_info["path"]
        for group in groups
        for run_info in (group.get("runs") or [])
    }
    included_summaries = []
    for run in loaded:
        units = getattr(run, "_units", None) or getattr(run, "_pair_units", None)
        cross_check = getattr(run, "_cross_check", {"ok": False})
        included_summaries.append(
            _run_summary(
                run,
                units,
                cross_check,
                aggregated=str(run.path) in aggregated_paths,
            )
        )
        for warning in run.warnings:
            warnings.append(f"{run.run_id}: {warning}")

    fixture_mode = any(run.fixture for run in loaded)
    experimental_results = any(not run.fixture for run in loaded)
    explicit_input_error = bool(args.run) and not loaded
    if not groups:
        status = "input_error" if (explicit_input_error or loaded) else "no_real_runs"
    else:
        status = "ok"
    if not loaded:
        warnings.append(
            "No completed real runner runs were aggregated. No performance numbers, cost, or "
            "qualitative cases are reported in this file."
        )
    if fixture_mode:
        warnings.append(
            "Fixture runs were included because --allow-fixture was set. Their metrics are synthetic "
            "pipeline checks, not experimental results."
        )

    dataset_level_m3 = {
        "applies_to": "M3 (context strategy)",
        "datasets": [
            {
                "dataset_type": dataset.dataset_type,
                "sha256": dataset.sha256,
                "context_audit": dataset.context_audit,
            }
            for dataset in datasets
        ],
        "reporting_requirements": M3_REPORTING_REQUIREMENTS,
    }
    audit_levels = {
        dataset.dataset_type: str(dataset.context_audit.get("risk_level") or "not_assessable")
        for dataset in datasets
    }
    if "high" in audit_levels.values():
        overall_risk = "high"
    elif "medium" in audit_levels.values():
        overall_risk = "medium"
    elif audit_levels:
        overall_risk = "low"
    else:
        overall_risk = "not_assessable"
    dataset_level_m3["risk_level"] = overall_risk
    independent_audit = next(
        (dataset for dataset in datasets if dataset.dataset_type == "independent"), None
    )
    pairs_audit = next(
        (dataset for dataset in datasets if dataset.dataset_type == "pairs"), None
    )
    if independent_audit is not None and pairs_audit is not None:
        counts = independent_audit.context_audit.get("counts") or {}
        nonempty = counts.get("nonempty") or {"vulnerable": 0, "non_vulnerable": 0}
        empty = counts.get("empty") or {"vulnerable": 0, "non_vulnerable": 0}
        n_nonempty = nonempty.get("vulnerable", 0) + nonempty.get("non_vulnerable", 0)
        n_empty = empty.get("vulnerable", 0) + empty.get("non_vulnerable", 0)
        pair_audit = pairs_audit.context_audit
        nonempty_single = (
            n_nonempty > 0
            and (nonempty.get("vulnerable", 0) == 0 or nonempty.get("non_vulnerable", 0) == 0)
        )
        nonempty_note = (
            "非空层是单类别，macro-F1 不可定义。"
            if nonempty_single
            else "非空层包含两类，macro-F1 可计算，但仍需报告 n 与区间。"
        )
        dataset_level_m3["summary"] = (
            f"独立集 context 非空层 {nonempty.get('vulnerable', 0)}/{n_nonempty} 为漏洞样本，"
            f"空层 {n_empty} 条中 {empty.get('vulnerable', 0)} 条漏洞、"
            f"{empty.get('non_vulnerable', 0)} 条非漏洞；M3 总体差异与 context 可用性混杂，"
            f"{nonempty_note}"
            f"配对集 {pair_audit.get('nonempty_pairs')} 对两侧非空、"
            f"{pair_audit.get('empty_pairs')} 对两侧为空；空层过小，分层结果不稳定。"
        )
    else:
        dataset_level_m3["summary"] = (
            "见 datasets[].context_audit；M3 总体差异不得单独归因于上下文推理。"
        )

    aggregation: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_version": ANALYSIS_VERSION,
        "generated_at_utc": utc_now(),
        "status": status,
        "experimental_results": experimental_results,
        "fixture_mode": fixture_mode,
        "config": {
            "runs_root": str(args.runs_root),
            "dataset_root": str(args.dataset_root),
            "bootstrap_resamples": args.bootstrap,
            "bootstrap_seed": args.seed,
            "confidence": args.confidence,
            "cluster_unit": (
                "auto (independent=project, pairs=pair)"
                if args.cluster == "auto"
                else args.cluster
            ),
            "percentile_method": stats.PERCENTILE_METHOD,
            "mcnemar": "exact two-sided binomial",
            "holm_alpha": 0.05,
            "complete_case": "valid in every included strategy for valid-only metrics",
            "invalid_policy": "schema-invalid/API-error records count as incorrect in end-to-end metrics and are excluded from valid-only metrics",
        },
        "inputs": {
            "runs_root": str(args.runs_root),
            "run_paths": [str(path) for path in run_dirs],
            "datasets_root": str(args.dataset_root),
            "dataset_paths": [str(dataset.path) for dataset in datasets],
            "context_classifier": classifier.source,
        },
        "runs": {"included": included_summaries, "skipped": skipped},
        "datasets": [dataset.as_dict() for dataset in datasets],
        "m3_artifact_risk": dataset_level_m3,
        "groups": groups,
        "report_tables": _build_report_tables(groups),
        "warnings": warnings,
        "limitations": [
            "All model metrics come from results.jsonl of completed runs; this script never imputes or mocks predictions.",
            "Wilson intervals are reported for proportions. macro-F1, balanced accuracy, MCC, and paired differences use the cluster percentile bootstrap.",
            "Project-cluster bootstrap treats projects as independent; this does not guarantee generalization to unseen projects.",
            "McNemar assumes independent units; same-project correlation can make p-values anti-conservative.",
            "Context strata are a data-level stratification. In this dataset context availability is correlated with the label, so M3 overall effects are confounded with context availability.",
            (
                "No real runs were included in this analysis; absence of numbers is not evidence of model performance."
                if not experimental_results
                else "Results reflect the single run per strategy listed above; they are not a multi-seed or multi-model estimate."
            ),
        ],
        "reproduction": {
            "command": (
                f"python3 analysis/analyze_runs.py --runs-root runner/runs "
                f"--bootstrap {args.bootstrap} --seed {args.seed}"
            ),
            "selftest": "python3 analysis/selftest.py",
        },
    }
    return aggregation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate SecVulEval runner results with stdlib statistics.")
    parser.add_argument("--runs-root", type=Path, default=DEFAULT_RUNS_ROOT)
    parser.add_argument("--run", type=Path, action="append", default=[], help="Explicit run directory; repeatable.")
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--bootstrap", type=int, default=stats.DEFAULT_BOOTSTRAP_RESAMPLES)
    parser.add_argument("--seed", type=int, default=stats.DEFAULT_BOOTSTRAP_SEED)
    parser.add_argument("--confidence", type=float, default=stats.DEFAULT_CONFIDENCE)
    parser.add_argument("--cluster", choices=["auto", "project", "pair", "unit"], default="auto")
    parser.add_argument("--include-partial", action="store_true")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--allow-fixture", action="store_true")
    parser.add_argument("--allow-dataset-mismatch", action="store_true")
    parser.add_argument("--on-duplicate", choices=["error", "latest", "first"], default="error")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)
    try:
        aggregation = run_analysis(args)
        atomic_write_json(args.out_json, aggregation)
        atomic_write_text(args.out_md, render_markdown(aggregation))
    except AnalysisError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        if args.debug:
            traceback.print_exc()
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"status: {aggregation['status']}")
        print(f"discovered run directories: {len(aggregation['inputs']['run_paths'])}")
        print(f"included runs: {len(aggregation['runs']['included'])}")
        print(f"groups: {len(aggregation['groups'])}")
        print(f"wrote {args.out_json}")
        print(f"wrote {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

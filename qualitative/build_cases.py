#!/usr/bin/env python3
"""Build a qualitative case export from completed SecVulEval runs.

This script is deliberately standard-library only.  It reads the six frozen
test runs and the two frozen split files, selects cases by fixed rules, and
writes ``cases.json`` / ``cases.md`` (formal mode) or
``cases.partial.json`` / ``cases.partial.md`` (intermediate mode).

It never calls a model API and never writes outside the qualitative directory
by default.

Usage (WSL):
    python3 qualitative/build_cases.py
    python3 qualitative/build_cases.py --check-only
    python3 qualitative/build_cases.py --mode intermediate --strategies direct
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import textwrap
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher, unified_diff
from pathlib import Path
from typing import Any, Sequence

SCRIPT_VERSION = "qualitative-v1"
SCHEMA_VERSION = 1
STRATEGIES: tuple[str, ...] = ("direct", "few-shot", "context")
DATASETS: tuple[str, ...] = ("independent", "pairs")
FORMAL_RUN_COUNT = len(STRATEGIES) * len(DATASETS)

CATEGORY_ORDER: tuple[str, ...] = (
    "independent_false_positive",
    "independent_false_negative",
    "strategy_disagreement",
    "pair_both_flagged",
    "pair_both_clean",
    "pair_reversed",
    "repair_schema_invalid",
    "repair_complete_reference_mismatch",
    "context_high_risk",
    "context_low_risk",
)

CATEGORY_LABELS_ZH: dict[str, str] = {
    "independent_false_positive": "独立集误报（假阳性）",
    "independent_false_negative": "独立集漏报（假阴性）",
    "strategy_disagreement": "策略分歧",
    "pair_both_flagged": "配对 both_flagged（两侧均报漏洞）",
    "pair_both_clean": "配对 both_clean（两侧均判安全）",
    "pair_reversed": "配对判反（漏洞侧判安全、修复侧判漏洞）",
    "repair_schema_invalid": "修复 schema 无效",
    "repair_complete_reference_mismatch": "修复完整且不同，但参考不匹配",
    "context_high_risk": "context 高风险判定",
    "context_low_risk": "context 低风险判定",
}

CATEGORY_RULES: dict[str, str] = {
    "independent_false_positive": (
        "独立集标签为 false，且至少一个可用策略预测 is_vulnerable=true；"
        "按错误预测的策略共识数、平均置信度和代码长度排序。"
    ),
    "independent_false_negative": (
        "独立集标签为 true，且至少一个可用策略预测 is_vulnerable=false；"
        "按错误预测的策略共识数、平均置信度和代码长度排序。"
    ),
    "strategy_disagreement": (
        "独立集同一 idx 上至少两个可用策略给出有效检测且预测不全相同；"
        "按不同预测类别数、置信度跨度和平均置信度排序。"
    ),
    "pair_both_flagged": (
        "配对两侧均被同一策略判为漏洞；按同一联合类别的策略共识数、"
        "两侧平均/最小置信度和代码长度排序。"
    ),
    "pair_both_clean": (
        "配对两侧均被同一策略判为非漏洞；排序规则同 both_flagged。"
    ),
    "pair_reversed": (
        "漏洞侧被判非漏洞且修复侧被判漏洞；排序规则同 both_flagged，"
        "并优先修复侧置信度高于漏洞侧的情形。"
    ),
    "repair_schema_invalid": (
        "修复记录 status=invalid 且 schema_valid=false；优先选择所选运行中"
        "最常见错误类型，并优先有参考修复的配对样本。"
    ),
    "repair_complete_reference_mismatch": (
        "配对修复记录 schema 有效、complete_function=true、"
        "changed_from_input=true，且规范化文本与参考修复不相等；按文本差异度、"
        "改动行数和结构校验排序。"
    ),
    "context_high_risk": (
        "context 策略有效检测且预测 is_vulnerable=true，context.used=true；"
        "按置信度、上下文非空和标签一致性排序。"
    ),
    "context_low_risk": (
        "context 策略有效检测且预测 is_vulnerable=false，context.used=true；"
        "排序规则同 context_high_risk。"
    ),
}

CATEGORY_NOTES: dict[str, str] = {
    "independent_false_positive": (
        "标签来自冻结测试集；本脚本不做人工复核，也不把模型 rationale 当作事实。"
    ),
    "independent_false_negative": (
        "标签来自冻结测试集；漏报不等于函数一定可利用，需结合正文复核。"
    ),
    "strategy_disagreement": (
        "分歧只描述同一记录上的预测差异，不自动归因于提示内容；"
        "如需因果解释，应结合 prompt 长度、示例和上下文覆盖率另行分析。"
    ),
    "pair_both_flagged": (
        "配对两侧来自同一 commit；both_flagged 说明模型没有利用修复差异。"
    ),
    "pair_both_clean": (
        "配对两侧来自同一 commit；both_clean 说明模型漏掉了该对中的漏洞侧。"
    ),
    "pair_reversed": (
        "配对两侧来自同一 commit；判反说明模型方向与参考修复相反。"
    ),
    "repair_schema_invalid": (
        "schema 无效是工程/格式失败，不能与“修复错误”或“修复正确”混为一谈。"
    ),
    "repair_complete_reference_mismatch": (
        "参考不匹配是规范化文本比较的结果，不是修复错误或安全等价性的证明；"
        "完整且不同也可能是另一种有效修复。"
    ),
    "context_high_risk": (
        "数据审计指出 context 是否非空与标签相关；不能把本案例直接归因于"
        "“上下文推理能力”。"
    ),
    "context_low_risk": (
        "数据审计指出 context 是否非空与标签相关；不能把本案例直接归因于"
        "“上下文推理能力”。"
    ),
}

GLOBAL_CAVEATS: tuple[str, ...] = (
    "Project/CWE/CVE/filepath/commit metadata is analysis-only; the runner never sends these fields to the model.",
    "Rationales are verbatim model text, not human audit conclusions.",
    "Reference-fixed matching is a normalized text comparison, not a repair-correctness oracle.",
    "Context non-empty status is correlated with the label in this dataset; context cases must not be read as causal evidence.",
    "Code excerpt line numbers are 1-based within the dedented function body, not source-file line numbers.",
    "No API call is made by this script; all values come from existing run artifacts and frozen split files.",
)


class InputError(RuntimeError):
    """Raised when the requested export cannot be produced without inventing data."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise InputError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path}: {exc}") from exc


def read_jsonl(path: Path, *, strict: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        handle = path.open("r", encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(f"missing JSONL file: {path}") from exc
    with handle:
        for lineno, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append({"line": lineno, "error": str(exc)})
                if strict:
                    raise InputError(f"invalid JSONL at {path}:{lineno}: {exc}") from exc
                continue
            if not isinstance(value, dict):
                errors.append({"line": lineno, "error": "record is not a JSON object"})
                if strict:
                    raise InputError(f"JSONL record is not an object at {path}:{lineno}")
                continue
            records.append(value)
    return records, errors


def normalize_code(code: str) -> str:
    """Match the runner's repair normalisation (line endings/trailing spaces)."""
    text = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def collapse_whitespace(code: str) -> str:
    return re.sub(r"\s+", " ", normalize_code(code)).strip()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def as_str_list(value: Any) -> list[str]:
    return [str(item) for item in as_list(value) if item is not None]


def truncate_text(text: str, limit: int, *, marker: str = "\n… [truncated]") -> tuple[str, bool]:
    if limit <= 0 or len(text) <= limit:
        return text, False
    return text[: max(0, limit - len(marker))] + marker, True


def safe_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def fmt_number(value: Any, digits: int = 3) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "n/a"
    return f"{float(value):.{digits}f}"


def fmt_tristate(value: Any) -> str:
    if value is None:
        return "n/a"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=False)


def md_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def md_code_fence(text: str, language: str = "c") -> str:
    """Choose a fence longer than any backtick run in the payload."""
    longest = 0
    for match in re.finditer(r"`+", text):
        longest = max(longest, len(match.group(0)))
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text.rstrip()}\n{fence}"


def dedent_code(code: str) -> str:
    text = code.replace("\r\n", "\n").replace("\r", "\n")
    text = textwrap.dedent(text)
    return text.strip("\n")


def code_language(filepath: str | None) -> str:
    suffix = Path(filepath or "").suffix.lower()
    if suffix in {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}:
        return "cpp"
    return "c"


def diff_line_numbers(left: str, right: str) -> tuple[list[int], list[int]]:
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    matcher = SequenceMatcher(None, left_lines, right_lines, autojunk=False)
    left_changed: set[int] = set()
    right_changed: set[int] = set()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            # An insertion has no left-side range; include the line at the
            # insertion point so an excerpt can show the surrounding context.
            if left_lines:
                left_changed.add(max(1, min(i1, len(left_lines))))
            right_changed.update(range(j1 + 1, j2 + 1))
        elif tag == "delete":
            left_changed.update(range(i1 + 1, i2 + 1))
            if right_lines:
                right_changed.add(max(1, min(j1, len(right_lines))))
        else:
            left_changed.update(range(i1 + 1, i2 + 1))
            right_changed.update(range(j1 + 1, j2 + 1))
    return sorted(left_changed), sorted(right_changed)


def line_similarity(left: str, right: str) -> float:
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    if not left_lines and not right_lines:
        return 1.0
    return SequenceMatcher(None, left_lines, right_lines, autojunk=False).ratio()


def unified_diff_excerpt(
    left: str,
    right: str,
    *,
    fromfile: str,
    tofile: str,
    max_lines: int = 80,
    max_chars: int = 9000,
) -> dict[str, Any]:
    lines = list(
        unified_diff(
            left.splitlines(),
            right.splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            n=3,
            lineterm="",
        )
    )
    text = "\n".join(lines)
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines]) + f"\n… [diff truncated after {max_lines} lines]"
    text, char_truncated = truncate_text(text, max_chars)
    return {
        "fromfile": fromfile,
        "tofile": tofile,
        "text": text,
        "added_lines": added,
        "removed_lines": removed,
        "truncated": (len(lines) > max_lines) or char_truncated,
        "total_diff_lines": len(lines),
    }


@dataclass
class CodeExcerpt:
    segments: list[dict[str, Any]]
    omitted: list[dict[str, int]]
    total_lines: int
    truncated: bool

    @property
    def text(self) -> str:
        pieces: list[str] = []
        for index, segment in enumerate(self.segments):
            if index:
                omitted = self.omitted[index - 1]
                pieces.append(f"… [{omitted['count']} lines omitted] …")
            pieces.append(segment["text"])
        return "\n".join(pieces)


def build_code_excerpt(
    code: str,
    *,
    focus_lines: Sequence[int] | None = None,
    max_lines: int = 45,
    max_chars: int = 8000,
) -> CodeExcerpt:
    """Return a bounded, line-addressable excerpt.

    With focus lines, the excerpt is a contiguous window around their median.
    Without focus lines, short functions are shown whole; long functions show a
    head and tail with an explicit omission marker.
    """
    normalized = dedent_code(code)
    lines = normalized.splitlines()
    total = len(lines)
    if total == 0:
        return CodeExcerpt(segments=[], omitted=[], total_lines=0, truncated=False)

    selected: list[tuple[int, int]] = []
    if focus_lines:
        valid_focus = sorted({int(line) for line in focus_lines if 1 <= int(line) <= total})
        if valid_focus:
            focus_min = valid_focus[0]
            focus_max = valid_focus[-1]
            span = max(8, max_lines)
            if focus_max - focus_min + 1 <= span:
                center = (focus_min + focus_max) // 2
            else:
                center = focus_min
            start = max(1, center - span // 2)
            end = min(total, start + span - 1)
            start = max(1, end - span + 1)
            if start <= 10:
                # Keep the function signature in view when the focus is near
                # the top; otherwise the excerpt can start mid-declaration.
                start = 1
                end = min(total, max_lines)
            selected = [(start, end)]
    if not selected and total <= max_lines:
        selected = [(1, total)]
    if not selected:
        head = max(6, (max_lines * 2) // 3)
        tail = max(4, max_lines - head)
        head = min(head, total)
        tail = min(tail, total - head)
        if head + tail >= total:
            selected = [(1, total)]
        else:
            selected = [(1, head), (total - tail + 1, total)]

    segments: list[dict[str, Any]] = []
    omitted: list[dict[str, int]] = []
    char_budget = max_chars
    for start, end in selected:
        block = lines[start - 1 : end]
        text = "\n".join(block)
        if char_budget <= 0:
            break
        if len(text) > char_budget:
            kept: list[str] = []
            used = 0
            for line in block:
                cost = len(line) + 1
                if used + cost > char_budget:
                    break
                kept.append(line)
                used += cost
            if not kept:
                break
            block = kept
            end = start + len(kept) - 1
            text = "\n".join(block)
        segments.append({"line_start": start, "line_end": end, "text": text, "line_count": len(block)})
        char_budget -= len(text) + 1

    if not segments:
        segments = [{"line_start": 1, "line_end": 1, "text": lines[0][:max_chars], "line_count": 1}]

    for index in range(len(segments) - 1):
        gap_start = segments[index]["line_end"] + 1
        gap_end = segments[index + 1]["line_start"] - 1
        if gap_end >= gap_start:
            omitted.append({"start": gap_start, "end": gap_end, "count": gap_end - gap_start + 1})

    truncated = len(segments) > 1 or (
        bool(segments)
        and (segments[0]["line_start"] > 1 or segments[-1]["line_end"] < total)
    )
    return CodeExcerpt(
        segments=segments,
        omitted=omitted,
        total_lines=total,
        truncated=truncated,
    )


def render_code_excerpt(excerpt: CodeExcerpt, *, max_line_chars: int = 240) -> str:
    if not excerpt.segments:
        return "(empty)"
    lines: list[str] = []
    for index, segment in enumerate(excerpt.segments):
        if index:
            omitted = excerpt.omitted[index - 1]
            lines.append(f"… [{omitted['count']} lines omitted] …")
        for offset, line in enumerate(segment["text"].splitlines()):
            line_no = segment["line_start"] + offset
            display = line
            if len(display) > max_line_chars:
                display = display[: max_line_chars - 1] + "…"
            lines.append(f"{line_no:5d} | {display}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dataset and run loading
# ---------------------------------------------------------------------------


@dataclass
class SplitData:
    name: str
    path: Path
    sha256: str
    raw: dict[str, Any]
    by_key: dict[str, dict[str, Any]]
    expected_keys: dict[str, set[str]]
    unit_count: int

    def expected_count(self) -> int:
        return sum(len(keys) for keys in self.expected_keys.values())


def load_split(root: Path, dataset: str) -> SplitData:
    relative = {
        "independent": Path("splits/test_detection_160.json"),
        "pairs": Path("splits/test_pairs_180.json"),
    }[dataset]
    path = root / relative
    raw = read_json(path)
    sha = sha256_file(path)
    by_key: dict[str, dict[str, Any]] = {}
    expected: dict[str, set[str]] = {"detection": set(), "repair": set()}

    if dataset == "independent":
        samples = raw.get("samples")
        if not isinstance(samples, list) or not samples:
            raise InputError(f"{path}: expected a non-empty 'samples' list")
        for sample in samples:
            if not isinstance(sample, dict):
                raise InputError(f"{path}: sample is not an object")
            idx = sample.get("idx")
            if not isinstance(idx, int):
                raise InputError(f"{path}: sample has non-integer idx")
            key = str(idx)
            if key in by_key:
                raise InputError(f"{path}: duplicate idx {idx}")
            by_key[key] = sample
            expected["detection"].add(f"idx:{idx}")
            if sample.get("is_vulnerable") is True:
                expected["repair"].add(f"idx:{idx}")
        unit_count = len(samples)
    elif dataset == "pairs":
        pairs = raw.get("pairs")
        if not isinstance(pairs, list) or not pairs:
            raise InputError(f"{path}: expected a non-empty 'pairs' list")
        for pair in pairs:
            if not isinstance(pair, dict):
                raise InputError(f"{path}: pair is not an object")
            pair_id = pair.get("pair_id")
            if not isinstance(pair_id, str) or not pair_id:
                raise InputError(f"{path}: pair has invalid pair_id")
            if pair_id in by_key:
                raise InputError(f"{path}: duplicate pair_id {pair_id}")
            vulnerable = pair.get("vulnerable")
            fixed = pair.get("fixed")
            if not isinstance(vulnerable, dict) or not isinstance(fixed, dict):
                raise InputError(f"{path}: pair {pair_id} is missing a side")
            for side_name, side in (("vulnerable", vulnerable), ("fixed", fixed)):
                idx = side.get("idx")
                if not isinstance(idx, int):
                    raise InputError(f"{path}: pair {pair_id} {side_name} has non-integer idx")
                expected["detection"].add(f"pair:{pair_id}:{side_name}")
            expected["repair"].add(f"pair:{pair_id}:vulnerable")
            by_key[pair_id] = pair
        unit_count = len(pairs)
    else:
        raise ValueError(f"unknown dataset: {dataset}")

    return SplitData(
        name=dataset,
        path=path,
        sha256=sha,
        raw=raw,
        by_key=by_key,
        expected_keys=expected,
        unit_count=unit_count,
    )


@dataclass
class RunCheck:
    strategy: str
    dataset: str
    run_dir: Path
    status: str = "missing"
    complete: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    records: list[dict[str, Any]] = field(default_factory=list)
    results_path: Path | None = None
    results_sha256: str | None = None
    manifest_sha256: str | None = None
    expected_records: int | None = None
    record_count: int | None = None
    missing_keys: list[str] = field(default_factory=list)
    extra_keys: list[str] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)
    task_counts: dict[str, int] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"test_v1_{self.strategy}_{self.dataset}"

    def summary(self) -> dict[str, Any]:
        manifest = self.manifest or {}
        config = manifest.get("config") if isinstance(manifest.get("config"), dict) else {}
        counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
        run_dir_text = self.run_dir.as_posix()
        marker = "/runner/runs/"
        if marker in run_dir_text:
            run_dir_text = "runner/runs/" + run_dir_text.split(marker, 1)[1]
        return {
            "strategy": self.strategy,
            "dataset": self.dataset,
            "run_dir": run_dir_text,
            "status": self.status,
            "complete": self.complete,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "manifest_status": manifest.get("status"),
            "manifest_completed_at": manifest.get("completed_at"),
            "run_id": manifest.get("run_id"),
            "model": (manifest.get("api") or {}).get("model") if isinstance(manifest.get("api"), dict) else None,
            "prompt_version": config.get("prompt_version"),
            "dataset_path": config.get("dataset_path"),
            "dataset_sha256": config.get("dataset_sha256"),
            "expected_requests": self.expected_records,
            "recorded_requests": self.record_count,
            "manifest_counts": counts,
            "status_counts": dict(self.status_counts),
            "task_counts": dict(self.task_counts),
            "results_sha256": self.results_sha256,
            "manifest_sha256": self.manifest_sha256,
            "missing_keys": list(self.missing_keys),
            "extra_keys": list(self.extra_keys),
        }


def inspect_run(root: Path, strategy: str, dataset: str, split: SplitData) -> RunCheck:
    run_dir = root / "runner" / "runs" / f"test_v1_{strategy}_{dataset}"
    check = RunCheck(strategy=strategy, dataset=dataset, run_dir=run_dir)

    if not run_dir.exists():
        check.status = "missing"
        check.errors.append(f"run directory does not exist: {run_dir.relative_to(root)}")
        return check

    manifest_path = run_dir / "manifest.json"
    results_path = run_dir / "results.jsonl"
    check.results_path = results_path
    if not manifest_path.exists():
        check.status = "incomplete"
        check.errors.append(f"manifest.json is missing in {run_dir.relative_to(root)}")
        return check
    check.manifest_sha256 = sha256_file(manifest_path)
    try:
        manifest = read_json(manifest_path)
    except InputError as exc:
        check.status = "invalid"
        check.errors.append(str(exc))
        return check
    if not isinstance(manifest, dict):
        check.status = "invalid"
        check.errors.append(f"{manifest_path}: manifest is not an object")
        return check
    check.manifest = manifest

    manifest_status = manifest.get("status")
    config = manifest.get("config") if isinstance(manifest.get("config"), dict) else {}
    counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
    if config.get("strategy") not in {None, strategy}:
        check.errors.append(
            f"manifest strategy mismatch: expected {strategy!r}, got {config.get('strategy')!r}"
        )
    if config.get("dataset_type") not in {None, dataset}:
        check.errors.append(
            f"manifest dataset_type mismatch: expected {dataset!r}, got {config.get('dataset_type')!r}"
        )
    if config.get("partial") is True:
        check.errors.append("manifest says partial=true; frozen test run must be complete")
    if config.get("limit") not in {None, 0}:
        check.errors.append(f"manifest says limit={config.get('limit')!r}; expected 0 (full split)")
    if config.get("dataset_sha256") not in {None, split.sha256}:
        check.errors.append(
            "manifest dataset_sha256 does not match the frozen split file: "
            f"{config.get('dataset_sha256')!r} vs {split.sha256!r}"
        )
    declared_path = config.get("dataset_path")
    if declared_path is not None:
        declared_ok = False
        if isinstance(declared_path, str):
            candidate = Path(declared_path)
            if not candidate.is_absolute():
                candidate = root / candidate
            try:
                declared_ok = candidate.resolve() == split.path.resolve()
            except OSError:
                declared_ok = False
        if not declared_ok:
            check.errors.append(
                f"manifest dataset_path does not match {split.path.name}: {declared_path!r}"
            )

    if manifest_status != "completed":
        check.errors.append(f"manifest status is {manifest_status!r}, not 'completed'")
    if not manifest.get("completed_at"):
        check.errors.append("manifest has no completed_at timestamp")

    if not results_path.exists():
        check.status = "incomplete" if not check.errors else "invalid"
        check.errors.append("results.jsonl is missing; the runner writes it when the run completes")
        return check
    check.results_sha256 = sha256_file(results_path)

    try:
        records, _ = read_jsonl(results_path, strict=True)
    except InputError as exc:
        check.status = "invalid"
        check.errors.append(str(exc))
        return check
    check.records = records
    check.record_count = len(records)
    check.status_counts = dict(Counter(str(record.get("status")) for record in records))
    check.task_counts = dict(Counter(str(record.get("task")) for record in records))

    expected_records = len(split.expected_keys["detection"]) + len(split.expected_keys["repair"])
    check.expected_records = expected_records
    if len(records) != expected_records:
        check.errors.append(f"results.jsonl has {len(records)} records; expected {expected_records}")
    if isinstance(counts, dict):
        if counts.get("complete_planned_requests") is False:
            check.errors.append("manifest counts.complete_planned_requests is false")
        if counts.get("missing_requests") not in {None, 0}:
            check.errors.append(f"manifest counts.missing_requests={counts.get('missing_requests')!r}")
        for key in ("records", "recorded_requests", "expected_requests", "planned_requests"):
            value = counts.get(key)
            if value is None:
                continue
            if value != expected_records:
                check.errors.append(f"manifest counts.{key}={value!r}; expected {expected_records}")
        for task in ("detection", "repair"):
            value = counts.get(task)
            expected_task = len(split.expected_keys[task])
            if value is not None and value != expected_task:
                check.errors.append(f"manifest counts.{task}={value!r}; expected {expected_task}")
    else:
        check.errors.append("manifest has no counts object")

    actual_keys: set[str] = set()
    duplicate_keys: list[str] = []
    for record in records:
        task = record.get("task")
        sample_id = record.get("sample_id")
        if task not in {"detection", "repair"}:
            check.errors.append(f"record has invalid task: {task!r}")
            continue
        if not isinstance(sample_id, str) or not sample_id:
            check.errors.append(f"record has invalid sample_id: {sample_id!r}")
            continue
        key = f"{task}:{sample_id}"
        if key in actual_keys:
            duplicate_keys.append(key)
        actual_keys.add(key)
        if record.get("strategy") not in {None, strategy}:
            check.errors.append(f"record strategy mismatch for {key}: {record.get('strategy')!r}")
        if record.get("dataset_type") not in {None, dataset}:
            check.errors.append(f"record dataset_type mismatch for {key}: {record.get('dataset_type')!r}")

    expected_keys = {
        f"{task}:{sample_id}"
        for task, sample_ids in split.expected_keys.items()
        for sample_id in sample_ids
    }
    check.missing_keys = sorted(expected_keys - actual_keys)
    check.extra_keys = sorted(actual_keys - expected_keys)
    if duplicate_keys:
        check.errors.append(f"duplicate record keys: {sorted(set(duplicate_keys))[:5]}")
    if check.missing_keys:
        check.errors.append(
            f"missing {len(check.missing_keys)} expected records, e.g. {check.missing_keys[:5]}"
        )
    if check.extra_keys:
        check.errors.append(
            f"found {len(check.extra_keys)} unexpected records, e.g. {check.extra_keys[:5]}"
        )

    if isinstance(counts, dict) and isinstance(counts.get("by_status"), dict):
        declared_status = {str(k): int(v) for k, v in counts["by_status"].items()}
        if declared_status != check.status_counts:
            check.errors.append(
                f"manifest counts.by_status={declared_status!r} does not match results "
                f"{check.status_counts!r}"
            )
    if isinstance(counts, dict) and isinstance(counts.get("by_task"), dict):
        declared_tasks = {str(k): int(v) for k, v in counts["by_task"].items()}
        if declared_tasks != check.task_counts:
            check.errors.append(
                f"manifest counts.by_task={declared_tasks!r} does not match results "
                f"{check.task_counts!r}"
            )

    if check.status_counts.get("error"):
        check.warnings.append(
            f"{check.status_counts['error']} API-error records; run is complete but those samples have no prediction"
        )
    if check.status_counts.get("invalid"):
        check.warnings.append(
            f"{check.status_counts['invalid']} schema-invalid records; these are real model outputs, not missing data"
        )

    check.complete = not check.errors
    check.status = "complete" if check.complete else "incomplete"
    return check


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------


@dataclass
class Unit:
    dataset: str
    key: str
    pair_id: str | None
    sides: tuple[str | None, ...]
    meta: dict[str | None, dict[str, Any]]
    records: dict[tuple[str, str | None, str], dict[str, Any]] = field(default_factory=dict)
    pair_diff: dict[str, Any] | None = None

    @property
    def uid(self) -> str:
        return f"{self.dataset}:{self.key}"

    def sort_key(self) -> tuple[str, str]:
        if self.dataset == "pairs" and self.pair_id:
            return (self.dataset, self.pair_id)
        return (self.dataset, self.key)


def sample_meta(sample: dict[str, Any], side: str | None) -> dict[str, Any]:
    return {
        "idx": sample.get("idx"),
        "label": sample.get("is_vulnerable"),
        "project": sample.get("project"),
        "project_url": sample.get("project_url"),
        "filepath": sample.get("filepath"),
        "commit_id": sample.get("commit_id"),
        "func_name": sample.get("func_name"),
        "fixed_func_idx": sample.get("fixed_func_idx"),
        "cwe_list": as_str_list(sample.get("cwe_list")),
        "cve_list": as_str_list(sample.get("cve_list")),
        "changed_lines": sample.get("changed_lines"),
        "changed_statements": sample.get("changed_statements"),
        "func_body": sample.get("func_body") if isinstance(sample.get("func_body"), str) else "",
        "side": side,
    }


def build_units(split: SplitData) -> dict[str, Unit]:
    units: dict[str, Unit] = {}
    if split.name == "independent":
        for sample in split.by_key.values():
            unit = Unit(
                dataset="independent",
                key=f"idx:{sample['idx']}",
                pair_id=None,
                sides=(None,),
                meta={None: sample_meta(sample, None)},
            )
            units[unit.uid] = unit
    else:
        for pair_id, pair in split.by_key.items():
            vulnerable = sample_meta(pair["vulnerable"], "vulnerable")
            fixed = sample_meta(pair["fixed"], "fixed")
            focus_v, focus_f = diff_line_numbers(vulnerable["func_body"], fixed["func_body"])
            unit = Unit(
                dataset="pairs",
                key=pair_id,
                pair_id=pair_id,
                sides=("vulnerable", "fixed"),
                meta={"vulnerable": vulnerable, "fixed": fixed},
                pair_diff={
                    "similarity": line_similarity(vulnerable["func_body"], fixed["func_body"]),
                    "focus_lines": {"vulnerable": focus_v, "fixed": focus_f},
                    "unified": unified_diff_excerpt(
                        vulnerable["func_body"],
                        fixed["func_body"],
                        fromfile=f"vulnerable idx={vulnerable['idx']}",
                        tofile=f"reference_fixed idx={fixed['idx']}",
                    ),
                },
            )
            units[unit.uid] = unit
    return units


def attach_records(
    units: dict[str, Unit],
    checks: Sequence[RunCheck],
    split: SplitData,
) -> None:
    for check in checks:
        if not check.complete:
            continue
        for record in check.records:
            task = record.get("task")
            side = record.get("side")
            if split.name == "independent":
                idx = record.get("idx")
                if not isinstance(idx, int):
                    raise InputError(f"{check.label}: independent record has non-integer idx")
                uid = f"independent:idx:{idx}"
                side = None
            else:
                pair_id = record.get("pair_id")
                if not isinstance(pair_id, str):
                    raise InputError(f"{check.label}: pair record has no pair_id")
                if side not in {"vulnerable", "fixed"}:
                    raise InputError(f"{check.label}: pair record has invalid side {side!r}")
                uid = f"pairs:{pair_id}"
            unit = units.get(uid)
            if unit is None:
                raise InputError(f"{check.label}: record points to unknown unit {uid}")
            key = (check.strategy, side, str(task))
            if key in unit.records:
                raise InputError(f"{check.label}: duplicate record for {uid} {key}")
            unit.records[key] = record


def available_strategies_by_dataset(checks: Sequence[RunCheck]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {dataset: [] for dataset in DATASETS}
    for check in checks:
        if check.complete and check.strategy not in result[check.dataset]:
            result[check.dataset].append(check.strategy)
    for dataset in result:
        result[dataset].sort(key=lambda value: STRATEGIES.index(value) if value in STRATEGIES else 99)
    return result


# ---------------------------------------------------------------------------
# Predictions and repair facts
# ---------------------------------------------------------------------------


def get_record(
    unit: Unit,
    strategy: str,
    side: str | None,
    task: str,
) -> dict[str, Any] | None:
    return unit.records.get((strategy, side, task))


def detection_prediction(unit: Unit, strategy: str, side: str | None) -> dict[str, Any] | None:
    record = get_record(unit, strategy, side, "detection")
    if not record or record.get("status") != "ok":
        return None
    parsed = record.get("parsed")
    if not isinstance(parsed, dict):
        return None
    vulnerable = parsed.get("is_vulnerable")
    if not isinstance(vulnerable, bool):
        return None
    confidence = safe_float(parsed.get("confidence"))
    if confidence is None:
        return None
    rationale = parsed.get("rationale")
    validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
    return {
        "strategy": strategy,
        "status": record.get("status"),
        "schema_valid": bool(validation.get("schema_valid", True)),
        "is_vulnerable": vulnerable,
        "confidence": confidence,
        "rationale": rationale if isinstance(rationale, str) else "",
        "context": context_meta(record),
        "record": record,
    }


def context_meta(record: dict[str, Any]) -> dict[str, Any]:
    prompt = record.get("prompt")
    if not isinstance(prompt, dict):
        return {"used": False}
    context = prompt.get("context")
    if not isinstance(context, dict):
        return {"used": False}
    return {
        "provided": context.get("provided"),
        "used": context.get("used"),
        "nonempty": context.get("nonempty"),
        "parse_ok": context.get("parse_ok"),
        "section_item_counts": context.get("section_item_counts"),
        "excluded_keys": context.get("excluded_keys"),
    }


def outcome(prediction: bool, label: Any) -> str:
    if label is True:
        return "tp" if prediction else "fn"
    if label is False:
        return "fp" if prediction else "tn"
    return "unknown"


def joint_category(vulnerable_prediction: bool, fixed_prediction: bool) -> str:
    if vulnerable_prediction and fixed_prediction:
        return "both_flagged"
    if not vulnerable_prediction and not fixed_prediction:
        return "both_clean"
    if not vulnerable_prediction and fixed_prediction:
        return "reversed"
    return "vulnerable_detected_fixed_clean"


def classify_repair_error(error: str) -> str:
    lowered = error.lower()
    if "invalid json" in lowered:
        return "invalid_json"
    if "keys mismatch" in lowered:
        return "schema_keys_mismatch"
    if "missing" in lowered and ("key" in lowered or "field" in lowered):
        return "schema_missing_field"
    if "fixed_function" in lowered:
        return "fixed_function_invalid"
    if "schema" in lowered:
        return "other_schema_error"
    return "other"


def extract_code_tokens(values: Sequence[str], prefix: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        tokens.extend(re.findall(rf"{prefix}-\d+(?:-\d+)?", value))
    seen: set[str] = set()
    result: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            result.append(token)
    return result


def analysis_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    cwe = as_str_list(meta.get("cwe_list"))
    cve = as_str_list(meta.get("cve_list"))
    changed_lines = meta.get("changed_lines")
    if isinstance(changed_lines, list):
        changed_lines = changed_lines[:20]
    else:
        changed_lines = []
    changed_statements = meta.get("changed_statements")
    if isinstance(changed_statements, list):
        changed_statements = changed_statements[:20]
    else:
        changed_statements = []
    return {
        "note": (
            "Analysis-only metadata. The runner never sends project, CWE, CVE, "
            "filepath, commit, idx, or fixed_func_idx to the model."
        ),
        "project": meta.get("project"),
        "project_url": meta.get("project_url"),
        "filepath": meta.get("filepath"),
        "func_name": meta.get("func_name"),
        "commit_id": meta.get("commit_id"),
        "cwe_list_raw": cwe,
        "cwe_tokens": extract_code_tokens(cwe, "CWE"),
        "cve_list_raw": cve,
        "cve_tokens": extract_code_tokens(cve, "CVE"),
        "changed_lines_excerpt": changed_lines,
        "changed_statements_excerpt": changed_statements,
    }


def prediction_to_dict(unit: Unit, strategy: str, side: str | None) -> dict[str, Any]:
    record = get_record(unit, strategy, side, "detection")
    if not record:
        return {
            "strategy": strategy,
            "status": "missing",
            "schema_valid": False,
            "is_vulnerable": None,
            "confidence": None,
            "rationale": "",
            "context": {"used": False},
        }
    validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
    parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
    rationale = parsed.get("rationale") if isinstance(parsed.get("rationale"), str) else ""
    rationale, rationale_truncated = truncate_text(rationale, 4000)
    return {
        "strategy": strategy,
        "status": record.get("status"),
        "schema_valid": bool(validation.get("schema_valid", record.get("status") == "ok")),
        "is_vulnerable": parsed.get("is_vulnerable") if isinstance(parsed.get("is_vulnerable"), bool) else None,
        "confidence": safe_float(parsed.get("confidence")),
        "rationale": rationale,
        "rationale_truncated": rationale_truncated,
        "validation_error": validation.get("error"),
        "context": context_meta(record),
    }


def repair_reference(unit: Unit, side: str | None) -> tuple[str | None, dict[str, Any] | None]:
    if unit.dataset != "pairs" or side != "vulnerable":
        return None, None
    fixed_meta = unit.meta.get("fixed")
    if not fixed_meta:
        return None, None
    code = fixed_meta.get("func_body")
    if not isinstance(code, str) or not code:
        return None, None
    return code, fixed_meta


def repair_record_to_dict(
    unit: Unit,
    side: str | None,
    record: dict[str, Any] | None,
    *,
    max_code_lines: int = 45,
    max_code_chars: int = 8000,
) -> dict[str, Any] | None:
    if record is None:
        return None
    validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
    status = record.get("status")
    schema_valid = bool(validation.get("schema_valid", status == "ok"))
    parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
    meta = unit.meta.get(side) or {}
    source_code = meta.get("func_body") if isinstance(meta.get("func_body"), str) else ""
    fixed_code = parsed.get("fixed_function") if isinstance(parsed.get("fixed_function"), str) else None
    explanation = parsed.get("explanation") if isinstance(parsed.get("explanation"), str) else ""
    explanation, explanation_truncated = truncate_text(explanation, 2500)

    result: dict[str, Any] = {
        "strategy": record.get("strategy"),
        "sample_id": record.get("sample_id"),
        "side": side,
        "idx": meta.get("idx"),
        "status": status,
        "schema_valid": schema_valid,
        "validation_error": validation.get("error"),
        "validation": {
            key: validation.get(key)
            for key in (
                "schema_valid",
                "complete_function",
                "balanced_delimiters",
                "function_like_prefix",
                "contains_markdown_fence",
                "starts_like_diff",
                "changed_from_input",
                "whitespace_changed_from_input",
                "fixed_line_count",
                "fixed_code_sha256",
            )
            if key in validation
        },
        "complete_function": validation.get("complete_function"),
        "changed_from_input": validation.get("changed_from_input"),
        "complete_and_changed": bool(
            validation.get("complete_function") is True
            and validation.get("changed_from_input") is True
        ),
        "explanation": explanation,
        "explanation_truncated": explanation_truncated,
        "fixed_function_available": bool(fixed_code),
        "raw_response_excerpt": None,
        "reference": {
            "available": False,
            "reason": "independent split has no reference fixed function",
        },
        "diff_vs_input": None,
        "diff_vs_reference": None,
    }

    if not schema_valid or fixed_code is None:
        content = ""
        response = record.get("response")
        if isinstance(response, dict) and isinstance(response.get("content"), str):
            content = response["content"]
        raw, raw_truncated = truncate_text(content, 3500)
        result["raw_response_excerpt"] = raw
        result["raw_response_truncated"] = raw_truncated
        result["error_category"] = classify_repair_error(str(validation.get("error") or ""))
        fixed_meta = unit.meta.get("fixed") if unit.dataset == "pairs" and side == "vulnerable" else None
        if fixed_meta is not None:
            result["reference"] = {
                "available": True,
                "idx": fixed_meta.get("idx"),
                "func_name": fixed_meta.get("func_name"),
                "comparable": False,
                "reason": "repair output is schema-invalid; reference text cannot be compared",
            }
        else:
            result["reference"] = {
                "available": False,
                "reason": "independent split has no reference fixed function",
            }
        return result

    fixed_excerpt = build_code_excerpt(
        fixed_code,
        focus_lines=diff_line_numbers(source_code, fixed_code)[1],
        max_lines=max_code_lines,
        max_chars=max_code_chars,
    )
    result["fixed_function_excerpt"] = {
        "segments": fixed_excerpt.segments,
        "omitted": fixed_excerpt.omitted,
        "total_lines": fixed_excerpt.total_lines,
        "truncated": fixed_excerpt.truncated,
        "text": fixed_excerpt.text,
        "line_numbering": "1-based within the function body after dedent",
    }
    result["diff_vs_input"] = unified_diff_excerpt(
        source_code,
        fixed_code,
        fromfile="original_vulnerable",
        tofile="model_fixed_function",
    )

    reference_code, fixed_meta = repair_reference(unit, side)
    if reference_code is not None and fixed_meta is not None:
        reference_excerpt = build_code_excerpt(
            reference_code,
            focus_lines=diff_line_numbers(fixed_code, reference_code)[1],
            max_lines=max_code_lines,
            max_chars=max_code_chars,
        )
        result["reference"] = {
            "available": True,
            "idx": fixed_meta.get("idx"),
            "func_name": fixed_meta.get("func_name"),
            "exact_match": normalize_code(fixed_code) == normalize_code(reference_code),
            "whitespace_collapsed_match": collapse_whitespace(fixed_code) == collapse_whitespace(reference_code),
            "line_similarity": line_similarity(fixed_code, reference_code),
            "code_excerpt": {
                "segments": reference_excerpt.segments,
                "omitted": reference_excerpt.omitted,
                "total_lines": reference_excerpt.total_lines,
                "truncated": reference_excerpt.truncated,
                "text": reference_excerpt.text,
                "line_numbering": "1-based within the function body after dedent",
            },
        }
        result["diff_vs_reference"] = unified_diff_excerpt(
            fixed_code,
            reference_code,
            fromfile="model_fixed_function",
            tofile="reference_fixed",
        )
    else:
        result["reference"] = {
            "available": False,
            "reason": "reference fixed function is unavailable for this unit",
        }

    return result


def repair_records_for_unit(unit: Unit, side: str | None, strategies: Sequence[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for strategy in strategies:
        record = get_record(unit, strategy, side, "repair")
        if record is not None:
            result[strategy] = repair_record_to_dict(unit, side, record)
    return result


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    category: str
    unit: Unit
    focus_side: str | None
    score: float
    facts: dict[str, Any]
    score_components: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def sort_key(self) -> tuple[float, str, str]:
        return (-self.score, self.unit.uid, str(self.focus_side))


def length_penalty(length: int) -> float:
    if 300 <= length <= 3000:
        return 0.0
    if length < 300:
        return min(3.0, (300 - length) / 100.0)
    return min(50.0, (length - 3000) / 200.0)


def pair_length_penalty(unit: Unit) -> float:
    values = [len((unit.meta.get(side) or {}).get("func_body") or "") for side in unit.sides]
    return min(60.0, sum(length_penalty(value) for value in values))


def valid_detections(
    unit: Unit,
    side: str | None,
    strategies: Sequence[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for strategy in strategies:
        prediction = detection_prediction(unit, strategy, side)
        if prediction is not None:
            result[strategy] = prediction
    return result


def generate_independent_error_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
    category: str,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for unit in units:
        if unit.dataset != "independent":
            continue
        meta = unit.meta.get(None) or {}
        label = meta.get("label")
        if category == "independent_false_positive" and label is not False:
            continue
        if category == "independent_false_negative" and label is not True:
            continue
        predictions = valid_detections(unit, None, strategies)
        if category == "independent_false_positive":
            wrong = {name: pred for name, pred in predictions.items() if pred["is_vulnerable"] is True}
        else:
            wrong = {name: pred for name, pred in predictions.items() if pred["is_vulnerable"] is False}
        if not wrong:
            continue
        confidences = [pred["confidence"] for pred in wrong.values()]
        consensus = len(wrong)
        mean_conf = mean(confidences) or 0.0
        penalty = length_penalty(len(meta.get("func_body") or ""))
        score = 1000.0 * consensus / max(1, len(strategies)) + 100.0 * mean_conf - penalty
        candidates.append(
            Candidate(
                category=category,
                unit=unit,
                focus_side=None,
                score=score,
                facts={
                    "label": label,
                    "wrong_strategies": list(wrong),
                    "consensus_count": consensus,
                    "available_strategy_count": len(strategies),
                    "mean_confidence": mean_conf,
                    "confidence_range": [min(confidences), max(confidences)],
                    "outcomes": {name: outcome(pred["is_vulnerable"], label) for name, pred in predictions.items()},
                },
                score_components={
                    "consensus_term": 1000.0 * consensus / max(1, len(strategies)),
                    "confidence_term": 100.0 * mean_conf,
                    "length_penalty": penalty,
                },
            )
        )
    return candidates


def generate_disagreement_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    if len(strategies) < 2:
        return candidates
    for unit in units:
        if unit.dataset != "independent":
            continue
        predictions = valid_detections(unit, None, strategies)
        if len(predictions) < 2:
            continue
        values = {pred["is_vulnerable"] for pred in predictions.values()}
        if len(values) < 2:
            continue
        confidences = [pred["confidence"] for pred in predictions.values()]
        distinct = len(values)
        spread = max(confidences) - min(confidences)
        mean_conf = mean(confidences) or 0.0
        penalty = length_penalty(len((unit.meta.get(None) or {}).get("func_body") or ""))
        score = 1000.0 * (distinct - 1) + 100.0 * spread + 10.0 * mean_conf - penalty
        candidates.append(
            Candidate(
                category="strategy_disagreement",
                unit=unit,
                focus_side=None,
                score=score,
                facts={
                    "predictions": {
                        name: {
                            "is_vulnerable": pred["is_vulnerable"],
                            "confidence": pred["confidence"],
                        }
                        for name, pred in predictions.items()
                    },
                    "distinct_prediction_count": distinct,
                    "confidence_span": spread,
                    "available_strategy_count": len(strategies),
                },
                score_components={
                    "distinct_term": 1000.0 * (distinct - 1),
                    "spread_term": 100.0 * spread,
                    "mean_confidence_term": 10.0 * mean_conf,
                    "length_penalty": penalty,
                },
            )
        )
    return candidates


def generate_pair_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
    target: str,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for unit in units:
        if unit.dataset != "pairs":
            continue
        joint_by_strategy: dict[str, str] = {}
        matching: list[str] = []
        confidences: list[float] = []
        vulnerable_confidences: list[float] = []
        fixed_confidences: list[float] = []
        for strategy in strategies:
            vulnerable_pred = detection_prediction(unit, strategy, "vulnerable")
            fixed_pred = detection_prediction(unit, strategy, "fixed")
            if vulnerable_pred is None or fixed_pred is None:
                continue
            joint = joint_category(vulnerable_pred["is_vulnerable"], fixed_pred["is_vulnerable"])
            joint_by_strategy[strategy] = joint
            if joint == target:
                matching.append(strategy)
                confidences.extend([vulnerable_pred["confidence"], fixed_pred["confidence"]])
                vulnerable_confidences.append(vulnerable_pred["confidence"])
                fixed_confidences.append(fixed_pred["confidence"])
        if not matching:
            continue
        consensus = len(matching)
        mean_conf = mean(confidences) or 0.0
        min_conf = min(confidences) if confidences else 0.0
        penalty = pair_length_penalty(unit)
        score = 1000.0 * consensus / max(1, len(strategies)) + 100.0 * mean_conf + 20.0 * min_conf - penalty
        reverse_bonus = 0.0
        if target == "pair_reversed":
            fixed_mean = mean(fixed_confidences) or 0.0
            vulnerable_mean = mean(vulnerable_confidences) or 0.0
            reverse_bonus = 25.0 * max(0.0, fixed_mean - vulnerable_mean)
            score += reverse_bonus
        candidates.append(
            Candidate(
                category=f"pair_{target}",
                unit=unit,
                focus_side=None,
                score=score,
                facts={
                    "joint_by_strategy": joint_by_strategy,
                    "target_joint_category": target,
                    "matching_strategies": matching,
                    "consensus_count": consensus,
                    "available_strategy_count": len(strategies),
                    "mean_confidence": mean_conf,
                    "min_confidence": min_conf,
                    "vulnerable_mean_confidence": mean(vulnerable_confidences),
                    "fixed_mean_confidence": mean(fixed_confidences),
                },
                score_components={
                    "consensus_term": 1000.0 * consensus / max(1, len(strategies)),
                    "mean_confidence_term": 100.0 * mean_conf,
                    "min_confidence_term": 20.0 * min_conf,
                    "reverse_confidence_bonus": reverse_bonus,
                    "length_penalty": penalty,
                },
            )
        )
    return candidates


def generate_repair_invalid_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
) -> list[Candidate]:
    all_invalid: list[tuple[Unit, str | None, str, dict[str, Any]]] = []
    for unit in units:
        for side in unit.sides:
            for strategy in strategies:
                record = get_record(unit, strategy, side, "repair")
                if not record or record.get("status") != "invalid":
                    continue
                validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
                if validation.get("schema_valid") is not False:
                    continue
                error = str(validation.get("error") or "")
                all_invalid.append((unit, side, strategy, record))
    if not all_invalid:
        return []
    error_counts = Counter(
        str(((record.get("validation") or {}).get("error") or ""))
        for _, _, _, record in all_invalid
    )
    candidates: list[Candidate] = []
    seen_units: set[tuple[str, str | None]] = set()
    for unit, side, strategy, record in all_invalid:
        key = (unit.uid, side)
        if key in seen_units:
            continue
        seen_units.add(key)
        validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
        error = str(validation.get("error") or "")
        content = ""
        response = record.get("response")
        if isinstance(response, dict) and isinstance(response.get("content"), str):
            content = response["content"]
        meta = unit.meta.get(side) or {}
        penalty = length_penalty(len(meta.get("func_body") or ""))
        frequency = error_counts[error]
        reference_bonus = 10.0 if unit.dataset == "pairs" and side == "vulnerable" else 0.0
        content_bonus = 20.0 * min(len(content) / 800.0, 5.0)
        score = 100.0 * frequency + content_bonus + reference_bonus - penalty
        candidates.append(
            Candidate(
                category="repair_schema_invalid",
                unit=unit,
                focus_side=side,
                score=score,
                facts={
                    "strategy": strategy,
                    "error": error,
                    "error_category": classify_repair_error(error),
                    "error_occurrences_in_selected_runs": frequency,
                    "response_content_chars": len(content),
                    "reference_available": unit.dataset == "pairs" and side == "vulnerable",
                },
                score_components={
                    "error_frequency_term": 100.0 * frequency,
                    "content_term": content_bonus,
                    "reference_bonus": reference_bonus,
                    "length_penalty": penalty,
                },
                notes=["Schema-invalid output is a format/engineering failure, not a repair-quality label."],
            )
        )
    return candidates


def generate_repair_mismatch_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
) -> list[Candidate]:
    """Select a complete-but-different repair whose text misses the reference.

    A 0.0-similarity candidate is usually an unrelated function rather than an
    alternative repair, so the primary pool keeps candidates with at least 20%
    line similarity and a plausible function size.  Within that pool, ranking
    targets 0.60 similarity: close enough to be a repair of the same function,
    different enough to make the reference mismatch visible.
    """
    target_similarity = 0.60
    min_similarity = 0.20
    all_candidates: list[Candidate] = []
    strict_candidates: list[Candidate] = []
    for unit in units:
        if unit.dataset != "pairs":
            continue
        reference_code, fixed_meta = repair_reference(unit, "vulnerable")
        if reference_code is None or fixed_meta is None:
            continue
        for strategy in strategies:
            record = get_record(unit, strategy, "vulnerable", "repair")
            if not record or record.get("status") != "ok":
                continue
            validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
            parsed = record.get("parsed") if isinstance(record.get("parsed"), dict) else {}
            fixed_code = parsed.get("fixed_function")
            if not isinstance(fixed_code, str):
                continue
            if validation.get("complete_function") is not True:
                continue
            if validation.get("changed_from_input") is not True:
                continue
            if normalize_code(fixed_code) == normalize_code(reference_code):
                continue
            if collapse_whitespace(fixed_code) == collapse_whitespace(reference_code):
                continue
            similarity = line_similarity(fixed_code, reference_code)
            divergence = 1.0 - similarity
            diff = unified_diff_excerpt(
                fixed_code,
                reference_code,
                fromfile="model_fixed_function",
                tofile="reference_fixed",
                max_lines=120,
            )
            changed_lines = diff["added_lines"] + diff["removed_lines"]
            if changed_lines <= 0:
                continue
            fixed_line_count = validation.get("fixed_line_count")
            if not isinstance(fixed_line_count, int):
                fixed_line_count = normalize_code(fixed_code).count("\n") + 1
            penalty = length_penalty(len((unit.meta.get("vulnerable") or {}).get("func_body") or ""))
            structural_bonus = 0.0
            if validation.get("balanced_delimiters") is True and validation.get("function_like_prefix") is True:
                structural_bonus = 10.0
            similarity_distance = abs(similarity - target_similarity)
            score = (
                200.0 * (1.0 - similarity_distance)
                + 1.0 * min(changed_lines, 20)
                + structural_bonus
                - penalty
            )
            strict = (
                similarity >= min_similarity
                and 5 <= fixed_line_count <= 200
                and changed_lines >= 2
            )
            candidate = Candidate(
                category="repair_complete_reference_mismatch",
                unit=unit,
                focus_side="vulnerable",
                score=score,
                facts={
                    "strategy": strategy,
                    "reference_available": True,
                    "reference_idx": fixed_meta.get("idx"),
                    "reference_similarity": similarity,
                    "divergence": divergence,
                    "selection_target_similarity": target_similarity,
                    "candidate_vs_reference_diff_lines": changed_lines,
                    "candidate_fixed_line_count": fixed_line_count,
                    "complete_function": True,
                    "changed_from_input": True,
                    "strict_pool": strict,
                },
                score_components={
                    "similarity_target": target_similarity,
                    "similarity_distance": similarity_distance,
                    "similarity_term": 200.0 * (1.0 - similarity_distance),
                    "diff_line_term": 1.0 * min(changed_lines, 20),
                    "structural_bonus": structural_bonus,
                    "length_penalty": penalty,
                },
                notes=["Reference mismatch is a text comparison, not proof that the repair is incorrect."],
            )
            all_candidates.append(candidate)
            if strict:
                strict_candidates.append(candidate)
    return strict_candidates or all_candidates


def generate_context_risk_candidates(
    units: Sequence[Unit],
    strategies: Sequence[str],
    target: str,
) -> list[Candidate]:
    if "context" not in strategies:
        return []
    candidates: list[Candidate] = []
    for unit in units:
        for side in unit.sides:
            prediction = detection_prediction(unit, "context", side)
            if prediction is None:
                continue
            if prediction["context"].get("used") is not True:
                continue
            if target == "context_high_risk" and prediction["is_vulnerable"] is not True:
                continue
            if target == "context_low_risk" and prediction["is_vulnerable"] is not False:
                continue
            meta = unit.meta.get(side) or {}
            label = meta.get("label")
            nonempty = prediction["context"].get("nonempty") is True
            matches_label = (
                (target == "context_high_risk" and label is True)
                or (target == "context_low_risk" and label is False)
            )
            penalty = length_penalty(len(meta.get("func_body") or ""))
            score = (
                100.0 * prediction["confidence"]
                + (10.0 if nonempty else 0.0)
                + (5.0 if matches_label else 0.0)
                + (2.0 if unit.dataset == "pairs" else 0.0)
                - penalty
            )
            candidates.append(
                Candidate(
                    category=target,
                    unit=unit,
                    focus_side=side,
                    score=score,
                    facts={
                        "strategy": "context",
                        "is_vulnerable": prediction["is_vulnerable"],
                        "confidence": prediction["confidence"],
                        "label": label,
                        "matches_label": matches_label,
                        "context_nonempty": nonempty,
                        "context_section_item_counts": prediction["context"].get("section_item_counts"),
                    },
                    score_components={
                        "confidence_term": 100.0 * prediction["confidence"],
                        "context_nonempty_bonus": 10.0 if nonempty else 0.0,
                        "label_match_bonus": 5.0 if matches_label else 0.0,
                        "pair_bonus": 2.0 if unit.dataset == "pairs" else 0.0,
                        "length_penalty": penalty,
                    },
                )
            )
    return candidates


# ---------------------------------------------------------------------------
# Case assembly
# ---------------------------------------------------------------------------


def build_side_view(
    unit: Unit,
    side: str | None,
    strategies: Sequence[str],
    *,
    max_code_lines: int,
    max_code_chars: int,
) -> dict[str, Any]:
    meta = unit.meta.get(side) or {}
    focus_lines: Sequence[int] = []
    if unit.pair_diff:
        focus_lines = unit.pair_diff["focus_lines"].get(str(side), [])
    excerpt = build_code_excerpt(
        meta.get("func_body") or "",
        focus_lines=focus_lines,
        max_lines=max_code_lines,
        max_chars=max_code_chars,
    )
    predictions = {strategy: prediction_to_dict(unit, strategy, side) for strategy in strategies}
    outcomes = {
        strategy: outcome(pred["is_vulnerable"], meta.get("label"))
        for strategy, pred in predictions.items()
        if pred.get("is_vulnerable") is not None
    }
    repairs = repair_records_for_unit(unit, side, strategies) if side in {"vulnerable", None} else {}
    return {
        "side": side,
        "idx": meta.get("idx"),
        "label": meta.get("label"),
        "predictions": predictions,
        "outcomes": outcomes,
        "analysis_metadata": analysis_metadata(meta),
        "code_excerpt": {
            "segments": excerpt.segments,
            "omitted": excerpt.omitted,
            "total_lines": excerpt.total_lines,
            "truncated": excerpt.truncated,
            "text": excerpt.text,
            "line_numbering": "1-based within the function body after dedent",
        },
        "repair_records": repairs,
    }


def public_facts(facts: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in facts.items() if not str(key).startswith("_")}


def build_case(
    candidate: Candidate,
    case_id: str,
    strategies: Sequence[str],
    *,
    max_code_lines: int,
    max_code_chars: int,
) -> dict[str, Any]:
    unit = candidate.unit
    sides = [
        build_side_view(
            unit,
            side,
            strategies,
            max_code_lines=max_code_lines,
            max_code_chars=max_code_chars,
        )
        for side in unit.sides
    ]
    focus_meta = unit.meta.get(candidate.focus_side) if candidate.focus_side is not None else None
    top_label = focus_meta.get("label") if focus_meta is not None else (
        unit.meta.get(None, {}).get("label") if unit.dataset == "independent" else None
    )
    top_idx = unit.meta.get(None, {}).get("idx") if unit.dataset == "independent" else None

    analysis: dict[str, Any] = {"dataset_type": unit.dataset}
    if unit.dataset == "independent":
        analysis.update(
            {
                "label": top_label,
                "predicted_vulnerable_by_strategy": {
                    strategy: sides[0]["predictions"][strategy]["is_vulnerable"]
                    for strategy in strategies
                },
                "outcomes_by_strategy": {
                    strategy: sides[0]["outcomes"].get(strategy)
                    for strategy in strategies
                },
                "consensus": candidate.facts.get("consensus_count"),
            }
        )
    else:
        joint_by_strategy: dict[str, str] = {}
        for strategy in strategies:
            vulnerable_pred = detection_prediction(unit, strategy, "vulnerable")
            fixed_pred = detection_prediction(unit, strategy, "fixed")
            if vulnerable_pred is not None and fixed_pred is not None:
                joint_by_strategy[strategy] = joint_category(
                    vulnerable_pred["is_vulnerable"], fixed_pred["is_vulnerable"]
                )
        analysis.update(
            {
                "joint_by_strategy": joint_by_strategy,
                "pair_similarity_vulnerable_vs_fixed": (
                    unit.pair_diff.get("similarity") if unit.pair_diff else None
                ),
            }
        )
        if "matching_strategies" in candidate.facts:
            analysis["matching_strategies"] = candidate.facts["matching_strategies"]
    if candidate.category in {"context_high_risk", "context_low_risk"}:
        analysis.update(
            {
                "risk_level": "high" if candidate.category == "context_high_risk" else "low",
                "focus_side": candidate.focus_side,
                "context_risk_facts": public_facts(candidate.facts),
            }
        )
    if candidate.category in {"repair_schema_invalid", "repair_complete_reference_mismatch"}:
        analysis.update({"repair_focus": public_facts(candidate.facts)})

    facts = make_facts(candidate, sides, strategies)
    return {
        "case_id": case_id,
        "category": candidate.category,
        "category_label_zh": CATEGORY_LABELS_ZH.get(candidate.category, candidate.category),
        "dataset_type": unit.dataset,
        "idx": top_idx,
        "pair_id": unit.pair_id,
        "focus_side": candidate.focus_side,
        "focus_repair_strategy": (
            candidate.facts.get("strategy")
            if candidate.category in {"repair_schema_invalid", "repair_complete_reference_mismatch"}
            else None
        ),
        "label": top_label,
        "summary": make_summary(candidate, sides, strategies),
        "facts": facts,
        "analysis": analysis,
        "sides": sides,
        "selection": {
            "rule_id": candidate.category,
            "rule_description": CATEGORY_RULES.get(candidate.category, ""),
            "candidate_pool": candidate.facts.get("_candidate_pool"),
            "selected_rank_in_category": candidate.facts.get("_selected_rank"),
            "score": round(candidate.score, 6),
            "score_components": candidate.score_components,
            "tie_breaker": "score descending, then unit key ascending, then focus side ascending",
            "reused_unit": bool(candidate.facts.get("_reused_unit")),
            "considered_after_dedup": candidate.facts.get("_considered_after_dedup"),
        },
        "notes": list(candidate.notes) + [CATEGORY_NOTES.get(candidate.category, "")],
    }


def make_summary(candidate: Candidate, sides: Sequence[dict[str, Any]], strategies: Sequence[str]) -> str:
    category = candidate.category
    unit = candidate.unit
    if category == "independent_false_positive":
        facts = candidate.facts
        return (
            f"独立集误报：idx={unit.meta[None]['idx']} 标签为非漏洞，"
            f"{facts['consensus_count']}/{facts['available_strategy_count']} 个可用策略预测为漏洞，"
            f"平均置信度 {fmt_number(facts['mean_confidence'])}。"
        )
    if category == "independent_false_negative":
        facts = candidate.facts
        return (
            f"独立集漏报：idx={unit.meta[None]['idx']} 标签为漏洞，"
            f"{facts['consensus_count']}/{facts['available_strategy_count']} 个可用策略预测为非漏洞，"
            f"平均置信度 {fmt_number(facts['mean_confidence'])}。"
        )
    if category == "strategy_disagreement":
        facts = candidate.facts
        parts = []
        for strategy in strategies:
            value = facts["predictions"].get(strategy)
            if value is not None:
                parts.append(
                    f"{strategy}={'漏洞' if value['is_vulnerable'] else '非漏洞'}"
                    f"({fmt_number(value['confidence'])})"
                )
        return f"策略分歧：idx={unit.meta[None]['idx']} 上 " + "，".join(parts) + "。"
    if category.startswith("pair_"):
        facts = candidate.facts
        return (
            f"配对 {category.replace('pair_', '')}：pair_id={unit.pair_id}，"
            f"{facts['consensus_count']}/{facts['available_strategy_count']} 个可用策略给出该联合类别。"
        )
    if category == "repair_schema_invalid":
        facts = candidate.facts
        return (
            f"修复 schema 无效：{unit.key} 的 {facts['strategy']} 输出未通过校验"
            f"（{facts['error_category']}）。"
        )
    if category == "repair_complete_reference_mismatch":
        facts = candidate.facts
        return (
            f"修复完整且不同但参考不匹配：pair_id={unit.pair_id}，"
            f"与参考修复的行级相似度 {fmt_number(facts['reference_similarity'])}，"
            f"差异行数 {facts['candidate_vs_reference_diff_lines']}。"
        )
    if category in {"context_high_risk", "context_low_risk"}:
        facts = candidate.facts
        risk = "高风险" if category == "context_high_risk" else "低风险"
        return (
            f"context {risk}判定：{unit.key} 的 {candidate.focus_side or '唯一'} 侧，"
            f"is_vulnerable={facts['is_vulnerable']}，置信度 {fmt_number(facts['confidence'])}，"
            f"标签={'漏洞' if facts['label'] else '非漏洞'}，上下文非空={facts['context_nonempty']}。"
        )
    return f"{CATEGORY_LABELS_ZH.get(category, category)}：{unit.key}"


def make_facts(candidate: Candidate, sides: Sequence[dict[str, Any]], strategies: Sequence[str]) -> list[str]:
    facts: list[str] = []
    category = candidate.category
    unit = candidate.unit
    if category in {"independent_false_positive", "independent_false_negative"}:
        data = candidate.facts
        facts.append(f"标签：{'漏洞' if data['label'] else '非漏洞'}。")
        facts.append(
            f"错误预测的策略：{', '.join(data['wrong_strategies'])}；"
            f"共识 {data['consensus_count']}/{data['available_strategy_count']}。"
        )
        facts.append(
            f"错误预测置信度：均值 {fmt_number(data['mean_confidence'])}，"
            f"范围 {fmt_number(data['confidence_range'][0])}–{fmt_number(data['confidence_range'][1])}。"
        )
    elif category == "strategy_disagreement":
        data = candidate.facts
        facts.append(
            f"有效预测的策略数：{len(data['predictions'])}；不同预测类别数：{data['distinct_prediction_count']}。"
        )
        facts.append(f"置信度跨度：{fmt_number(data['confidence_span'])}。")
    elif category.startswith("pair_"):
        data = candidate.facts
        facts.append(
            "各策略联合类别："
            + "; ".join(f"{strategy}={value}" for strategy, value in data["joint_by_strategy"].items())
            + "。"
        )
        facts.append(
            f"目标类别 {category.replace('pair_', '')} 的策略数：{data['consensus_count']}/"
            f"{data['available_strategy_count']}。"
        )
        facts.append(
            f"两侧平均置信度 {fmt_number(data['mean_confidence'])}，"
            f"最小置信度 {fmt_number(data['min_confidence'])}。"
        )
    elif category == "repair_schema_invalid":
        data = candidate.facts
        facts.append(f"修复记录策略：{data['strategy']}；状态：invalid；schema_valid=false。")
        facts.append(f"校验错误：{data['error']}。")
        facts.append(
            f"该错误在所选运行的无效修复记录中出现 {data['error_occurrences_in_selected_runs']} 次；"
            f"原始模型响应长度 {data['response_content_chars']} 字符。"
        )
    elif category == "repair_complete_reference_mismatch":
        data = candidate.facts
        facts.append(f"修复策略：{data['strategy']}；complete_function=true；changed_from_input=true。")
        facts.append(
            f"与参考修复的规范化文本不相等；行级相似度 {fmt_number(data['reference_similarity'])}，"
            f"差异行数 {data['candidate_vs_reference_diff_lines']}。"
        )
        facts.append(f"参考修复 idx：{data['reference_idx']}。")
    elif category in {"context_high_risk", "context_low_risk"}:
        data = candidate.facts
        facts.append(
            f"context 预测：is_vulnerable={data['is_vulnerable']}，"
            f"confidence={fmt_number(data['confidence'])}。"
        )
        facts.append(
            f"标签：{'漏洞' if data['label'] else '非漏洞'}；"
            f"预测{'正确' if data['matches_label'] else '错误'}。"
        )
        facts.append(
            f"context.used=true；nonempty={data['context_nonempty']}；"
            f"section_item_counts={json_dump(data['context_section_item_counts'])}。"
        )
    if unit.dataset == "pairs":
        facts.append(
            f"配对两侧 idx：vulnerable={unit.meta['vulnerable']['idx']}, "
            f"fixed={unit.meta['fixed']['idx']}。"
        )
    facts.append("分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。")
    return facts


def select_cases(
    candidates_by_category: dict[str, list[Candidate]],
    *,
    available_categories: Sequence[str],
    strict: bool,
) -> tuple[list[Candidate], list[dict[str, Any]], list[str]]:
    used: set[str] = set()
    selected: list[Candidate] = []
    skipped: list[dict[str, Any]] = []
    warnings: list[str] = []
    empty_categories: list[str] = []

    for category in CATEGORY_ORDER:
        if category not in available_categories:
            continue
        candidates = candidates_by_category.get(category, [])
        pool = len(candidates)
        if not candidates:
            message = f"category {category!r} has no eligible candidates"
            if strict:
                empty_categories.append(category)
                continue
            skipped.append({"category": category, "reason": "no eligible candidates"})
            warnings.append(message)
            continue
        candidates.sort(key=lambda item: item.sort_key())
        chosen: Candidate | None = None
        considered = 0
        for rank, candidate in enumerate(candidates, 1):
            considered = rank
            if candidate.unit.uid in used:
                continue
            chosen = candidate
            break
        reused = False
        if chosen is None:
            chosen = candidates[0]
            reused = True
            warnings.append(
                f"category {category!r}: all candidates reuse an already selected unit; "
                "selected the top-scoring candidate and marked reused_unit=true"
            )
        chosen.facts["_candidate_pool"] = pool
        chosen.facts["_selected_rank"] = considered
        chosen.facts["_reused_unit"] = reused
        chosen.facts["_considered_after_dedup"] = considered
        used.add(chosen.unit.uid)
        selected.append(chosen)
    if empty_categories:
        raise InputError(
            "formal selection has no eligible candidate for: " + ", ".join(empty_categories)
        )
    return selected, skipped, warnings


def category_candidates(
    units: Sequence[Unit],
    strategies_by_dataset: dict[str, list[str]],
    *,
    include_categories: Sequence[str],
) -> dict[str, list[Candidate]]:
    independent_strategies = strategies_by_dataset.get("independent", [])
    pair_strategies = strategies_by_dataset.get("pairs", [])
    result: dict[str, list[Candidate]] = {category: [] for category in CATEGORY_ORDER}

    if "independent_false_positive" in include_categories:
        result["independent_false_positive"] = generate_independent_error_candidates(
            units, independent_strategies, "independent_false_positive"
        )
    if "independent_false_negative" in include_categories:
        result["independent_false_negative"] = generate_independent_error_candidates(
            units, independent_strategies, "independent_false_negative"
        )
    if "strategy_disagreement" in include_categories:
        result["strategy_disagreement"] = generate_disagreement_candidates(units, independent_strategies)
    if "pair_both_flagged" in include_categories:
        result["pair_both_flagged"] = generate_pair_candidates(units, pair_strategies, "both_flagged")
    if "pair_both_clean" in include_categories:
        result["pair_both_clean"] = generate_pair_candidates(units, pair_strategies, "both_clean")
    if "pair_reversed" in include_categories:
        result["pair_reversed"] = generate_pair_candidates(units, pair_strategies, "reversed")
    if "repair_schema_invalid" in include_categories:
        result["repair_schema_invalid"] = generate_repair_invalid_candidates(
            units, list(dict.fromkeys(independent_strategies + pair_strategies))
        )
    if "repair_complete_reference_mismatch" in include_categories:
        result["repair_complete_reference_mismatch"] = generate_repair_mismatch_candidates(
            units, pair_strategies
        )
    if "context_high_risk" in include_categories:
        result["context_high_risk"] = generate_context_risk_candidates(
            units, list(dict.fromkeys(independent_strategies + pair_strategies)), "context_high_risk"
        )
    if "context_low_risk" in include_categories:
        result["context_low_risk"] = generate_context_risk_candidates(
            units, list(dict.fromkeys(independent_strategies + pair_strategies)), "context_low_risk"
        )
    return result


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def render_predictions_table(side_view: dict[str, Any], strategies: Sequence[str]) -> str:
    lines = [
        "| 策略 | 预测 | 置信度 | 判定 | 上下文 |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for strategy in strategies:
        prediction = side_view["predictions"].get(strategy)
        if not prediction:
            continue
        value = prediction.get("is_vulnerable")
        if value is True:
            label = "漏洞"
        elif value is False:
            label = "非漏洞"
        else:
            label = "无效/缺失"
        outcome_value = side_view.get("outcomes", {}).get(strategy, "")
        context = prediction.get("context") or {}
        context_label = "used" if context.get("used") else "unused"
        if context.get("nonempty"):
            context_label += "/nonempty"
        lines.append(
            f"| {strategy} | {label} | {fmt_number(prediction.get('confidence'))} | "
            f"{outcome_value or '—'} | {context_label} |"
        )
    return "\n".join(lines)


def render_rationales(side_view: dict[str, Any], strategies: Sequence[str]) -> str:
    lines: list[str] = []
    for strategy in strategies:
        prediction = side_view["predictions"].get(strategy)
        if not prediction:
            continue
        rationale = prediction.get("rationale") or "(no rationale)"
        rationale, _ = truncate_text(rationale, 900, marker=" … [truncated]")
        value = prediction.get("is_vulnerable")
        label = "漏洞" if value is True else ("非漏洞" if value is False else "无效")
        lines.append(f"- **{strategy}**（{label}，confidence={fmt_number(prediction.get('confidence'))}）：")
        for paragraph in rationale.splitlines():
            if paragraph.strip():
                lines.append(f"  > {paragraph.strip()}")
            else:
                lines.append("  >")
    return "\n".join(lines)


def render_repair_block(repair: dict[str, Any], *, show_raw: bool = True, details: bool = True) -> str:
    if not repair:
        return ""
    lines = [
        f"- 策略：`{repair.get('strategy')}`",
        f"- 状态：`{repair.get('status')}`；schema_valid=`{fmt_tristate(repair.get('schema_valid'))}`",
        f"- complete_function=`{fmt_tristate(repair.get('complete_function'))}`；"
        f"changed_from_input=`{fmt_tristate(repair.get('changed_from_input'))}`；"
        f"complete_and_changed=`{fmt_tristate(repair.get('complete_and_changed'))}`",
    ]
    if repair.get("validation_error"):
        lines.append(f"- 校验错误：`{repair['validation_error']}`")
    validation = repair.get("validation") or {}
    if validation:
        lines.append(
            "- 结构校验："
            + ", ".join(f"`{key}={validation[key]}`" for key in validation if key != "fixed_code_sha256")
        )
    reference = repair.get("reference") or {}
    if reference.get("available") and reference.get("comparable") is False:
        lines.append(
            f"- 参考修复：idx={reference.get('idx')}；不可比较（{reference.get('reason', 'n/a')}）"
        )
    elif reference.get("available"):
        lines.append(
            f"- 参考修复：idx={reference.get('idx')}；"
            f"exact_match=`{reference.get('exact_match')}`；"
            f"whitespace_collapsed_match=`{reference.get('whitespace_collapsed_match')}`；"
            f"line_similarity={fmt_number(reference.get('line_similarity'))}"
        )
    else:
        lines.append(f"- 参考修复：不可用（{reference.get('reason', 'n/a')}）")
    if repair.get("explanation"):
        explanation, _ = truncate_text(repair["explanation"], 1200, marker=" … [truncated]")
        lines.append("- 模型说明：")
        for paragraph in explanation.splitlines():
            if paragraph.strip():
                lines.append(f"  > {paragraph.strip()}")
    if details and show_raw and repair.get("raw_response_excerpt"):
        raw, _ = truncate_text(repair["raw_response_excerpt"], 1600, marker=" … [truncated]")
        lines.append("- 原始响应摘录（未解析）：")
        lines.append("")
        lines.append(md_code_fence(raw, "json"))
        lines.append("")
    if details and repair.get("diff_vs_input") and repair["diff_vs_input"].get("text"):
        diff = repair["diff_vs_input"]
        lines.append(f"- 相对原函数的 diff（+{diff['added_lines']}/-{diff['removed_lines']} 行）：")
        lines.append("")
        lines.append(md_code_fence(diff["text"], "diff"))
        lines.append("")
    if details and repair.get("diff_vs_reference") and repair["diff_vs_reference"].get("text"):
        diff = repair["diff_vs_reference"]
        lines.append(f"- 相对参考修复的 diff（+{diff['added_lines']}/-{diff['removed_lines']} 行）：")
        lines.append("")
        lines.append(md_code_fence(diff["text"], "diff"))
        lines.append("")
    if details and repair.get("fixed_function_excerpt"):
        excerpt = repair["fixed_function_excerpt"]
        lines.append("- 模型修复函数摘录：")
        lines.append("")
        lines.append(
            md_code_fence(
                render_code_excerpt(
                    CodeExcerpt(
                        segments=excerpt["segments"],
                        omitted=excerpt["omitted"],
                        total_lines=excerpt["total_lines"],
                        truncated=excerpt["truncated"],
                    )
                ),
                "c",
            )
        )
        lines.append("")
    return "\n".join(lines).rstrip()


def render_case_markdown(case: dict[str, Any], strategies: Sequence[str]) -> str:
    lines: list[str] = []
    lines.append(f"## {case['case_id']} {case['category_label_zh']}")
    lines.append("")
    id_value = case.get("idx")
    pair_value = case.get("pair_id")
    lines.append(f"- **类别**：`{case['category']}`")
    lines.append(f"- **数据集**：`{case['dataset_type']}`")
    lines.append(f"- **idx**：`{id_value if id_value is not None else '—'}`")
    lines.append(f"- **pair_id**：`{pair_value if pair_value is not None else '—'}`")
    if case.get("focus_side"):
        lines.append(f"- **聚焦侧**：`{case['focus_side']}`")
    lines.append("")
    lines.append(f"**摘要**：{case['summary']}")
    lines.append("")
    lines.append("**关键事实**")
    lines.append("")
    for fact in case.get("facts", []):
        lines.append(f"- {fact}")
    lines.append("")
    repair_details = case.get("category") in {
        "repair_schema_invalid",
        "repair_complete_reference_mismatch",
    }

    for side_view in case["sides"]:
        side = side_view.get("side")
        heading = "唯一函数" if side is None else ("漏洞侧" if side == "vulnerable" else "修复侧")
        lines.append(f"### {heading}（idx={side_view.get('idx')}，label={side_view.get('label')}）")
        lines.append("")
        meta = side_view.get("analysis_metadata") or {}
        lines.append(
            f"**分析元数据（仅用于分析，未进入模型提示）**："
            f"project=`{meta.get('project')}`；CWE=`{', '.join(meta.get('cwe_tokens') or []) or '—'}`；"
            f"CVE=`{', '.join(meta.get('cve_tokens') or []) or '—'}`；"
            f"filepath=`{meta.get('filepath')}`；commit=`{meta.get('commit_id')}`"
        )
        lines.append("")
        lines.append("**策略预测**")
        lines.append("")
        lines.append(render_predictions_table(side_view, strategies))
        lines.append("")
        lines.append("**模型 rationale（原文，已按需截断）**")
        lines.append("")
        lines.append(render_rationales(side_view, strategies))
        lines.append("")
        excerpt = side_view.get("code_excerpt") or {}
        if excerpt.get("segments"):
            lines.append("**代码摘录**")
            lines.append("")
            code = render_code_excerpt(
                CodeExcerpt(
                    segments=excerpt["segments"],
                    omitted=excerpt["omitted"],
                    total_lines=excerpt["total_lines"],
                    truncated=excerpt["truncated"],
                )
            )
            lines.append(md_code_fence(code, code_language(meta.get("filepath"))))
            lines.append("")
        repairs = side_view.get("repair_records") or {}
        if repairs:
            lines.append("**修复记录**")
            lines.append("")
            focus_repair = case.get("focus_repair_strategy")
            for strategy, repair in repairs.items():
                if focus_repair and strategy != focus_repair:
                    continue
                lines.append(f"#### 修复策略 `{strategy}`")
                lines.append("")
                lines.append(render_repair_block(repair, details=repair_details))
                lines.append("")
        lines.append("")

    selection = case.get("selection") or {}
    lines.append("### 选择依据")
    lines.append("")
    lines.append(f"- 规则：`{selection.get('rule_id')}` — {selection.get('rule_description')}")
    lines.append(
        f"- 候选池：{selection.get('candidate_pool')}；"
        f"类别内排名：{selection.get('selected_rank_in_category')}；"
        f"score={fmt_number(selection.get('score'))}"
    )
    lines.append(f"- 评分组成：`{json_dump(selection.get('score_components'))}`")
    lines.append(f"- 去重：`reused_unit={selection.get('reused_unit')}`")
    lines.append("")
    notes = [note for note in case.get("notes", []) if note]
    if notes:
        lines.append("### 备注")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    formal = bool(data.get("formal"))
    lines.append("# SecVulEval 定性案例" + ("（正式导出）" if formal else "（中间导出）"))
    lines.append("")
    if not formal:
        lines.append(
            "> **中间导出，不是正式结果。** 本文件只使用所选策略/数据集的已完成运行；"
            "缺失或跳过的类别见下方。正式结论以 `cases.json` / `cases.md` 为准。"
        )
        lines.append("")
    lines.append(f"- 生成时间（UTC）：`{data.get('generated_at')}`")
    lines.append(f"- 脚本版本：`{data.get('script_version')}`")
    lines.append(f"- 模式：`{data.get('mode')}`；formal=`{formal}`")
    used = data.get("strategies_by_dataset") or {}
    used_text = "；".join(
        f"{dataset}={','.join(strategies) if strategies else '—'}"
        for dataset, strategies in used.items()
    )
    lines.append(f"- 实际使用策略/数据集：`{used_text or '—'}`")
    lines.append(f"- 案例数：{len(data.get('cases', []))}")
    lines.append(f"- 六个运行全部完成：`{data.get('all_inputs_complete')}`")
    lines.append(f"- 选择规则版本：`{data.get('selection_rules_version')}`")
    lines.append("")
    lines.append("**输入运行**")
    lines.append("")
    lines.append("| 策略 | 数据集 | 状态 | 记录/期望 | 完成时间 | run_id |")
    lines.append("| --- | --- | --- | ---: | --- | --- |")
    for run in data.get("inputs", {}).get("runs", []):
        recorded = run.get("recorded_requests")
        expected = run.get("expected_requests")
        counts_text = (
            f"{recorded}/{expected}"
            if recorded is not None and expected is not None
            else "—"
        )
        lines.append(
            f"| {run.get('strategy')} | {run.get('dataset')} | {run.get('status')} | "
            f"{counts_text} | "
            f"{run.get('manifest_completed_at') or '—'} | `{run.get('run_id') or '—'}` |"
        )
    lines.append("")
    if data.get("warnings"):
        lines.append("**警告**")
        lines.append("")
        for warning in data["warnings"]:
            lines.append(f"- {warning}")
        lines.append("")
    if data.get("skipped_categories"):
        lines.append("**跳过的类别**")
        lines.append("")
        for item in data["skipped_categories"]:
            lines.append(f"- `{item['category']}`：{item['reason']}")
        lines.append("")
    lines.append("**总览**")
    lines.append("")
    lines.append("| 编号 | 类别 | 数据集 | idx / pair_id | 项目 | CWE | 摘要 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for case in data.get("cases", []):
        side_meta = (case.get("sides") or [{}])[0].get("analysis_metadata") or {}
        locator = case.get("pair_id") or case.get("idx") or "—"
        lines.append(
            f"| {case.get('case_id')} | {case.get('category_label_zh')} | "
            f"{case.get('dataset_type')} | `{locator}` | {md_cell(side_meta.get('project'))} | "
            f"{md_cell(', '.join(side_meta.get('cwe_tokens') or []))} | "
            f"{md_cell(case.get('summary'))} |"
        )
    lines.append("")
    lines.append("**全局说明**")
    lines.append("")
    for caveat in data.get("caveats", []):
        lines.append(f"- {caveat}")
    lines.append("")
    for case in data.get("cases", []):
        strategies = data.get("strategies_by_dataset", {}).get(case.get("dataset_type"), [])
        lines.append(render_case_markdown(case, strategies))
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select and export qualitative SecVulEval cases from completed runs."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of qualitative/)",
    )
    parser.add_argument(
        "--mode",
        choices=("formal", "intermediate"),
        default="formal",
        help="formal requires all six completed runs; intermediate permits a subset",
    )
    parser.add_argument(
        "--strategies",
        nargs="+",
        choices=STRATEGIES,
        help="intermediate mode only: subset of strategies",
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        choices=DATASETS,
        help="intermediate mode only: subset of datasets",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="output directory (default: qualitative/)",
    )
    parser.add_argument(
        "--max-code-lines",
        type=int,
        default=45,
        help="maximum lines per code excerpt (default: 45)",
    )
    parser.add_argument(
        "--max-code-chars",
        type=int,
        default=8000,
        help="maximum characters per code excerpt (default: 8000)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="check input completeness and exit without writing cases",
    )
    return parser.parse_args(argv)


def check_report(checks: Sequence[RunCheck]) -> str:
    lines = ["Run completeness check:"]
    for check in checks:
        lines.append(
            f"  {check.label}: status={check.status} "
            f"records={check.record_count}/{check.expected_records}"
        )
        for error in check.errors:
            lines.append(f"    ERROR: {error}")
        for warning in check.warnings:
            lines.append(f"    WARN:  {warning}")
    return "\n".join(lines)


def validate_formal_checks(checks: Sequence[RunCheck]) -> None:
    incomplete = [check for check in checks if not check.complete]
    if not incomplete:
        return
    lines = [
        "Formal mode requires all six frozen test runs to be completed. "
        "Refusing to write cases.json/cases.md.",
        "",
    ]
    for check in checks:
        if check.complete:
            continue
        lines.append(f"- {check.label}: status={check.status}")
        for error in check.errors:
            lines.append(f"    - {error}")
        for warning in check.warnings:
            lines.append(f"    - warning: {warning}")
    lines.append("")
    lines.append(
        "Use --check-only to inspect inputs, or --mode intermediate with a "
        "subset of completed strategies for a clearly marked preview."
    )
    raise InputError("\n".join(lines))


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    out_dir = args.out_dir.resolve()

    if args.mode == "formal":
        strategies = list(STRATEGIES)
        datasets = list(DATASETS)
        if args.strategies and set(args.strategies) != set(STRATEGIES):
            print(
                "ERROR: formal mode always uses all three strategies: " + ", ".join(STRATEGIES),
                file=sys.stderr,
            )
            return 2
        if args.datasets and set(args.datasets) != set(DATASETS):
            print(
                "ERROR: formal mode always uses both datasets: " + ", ".join(DATASETS),
                file=sys.stderr,
            )
            return 2
    else:
        strategies = list(args.strategies) if args.strategies else list(STRATEGIES)
        datasets = list(args.datasets) if args.datasets else list(DATASETS)
        strategies = [item for item in STRATEGIES if item in strategies]
        datasets = [item for item in DATASETS if item in datasets]

    try:
        splits = {dataset: load_split(root, dataset) for dataset in DATASETS}
        checks = [
            inspect_run(root, strategy, dataset, splits[dataset])
            for strategy in STRATEGIES
            for dataset in DATASETS
        ]
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.check_only:
        print(check_report(checks))
        all_complete = all(check.complete for check in checks)
        print(f"\nAll six runs complete: {all_complete}")
        return 0 if (all_complete or args.mode == "intermediate") else 2

    if args.mode == "formal":
        try:
            validate_formal_checks(checks)
        except InputError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        selected_checks = checks
        strategies_by_dataset = {dataset: list(STRATEGIES) for dataset in DATASETS}
    else:
        selected_checks = [
            check
            for check in checks
            if check.complete and check.strategy in strategies and check.dataset in datasets
        ]
        if not selected_checks:
            print(
                "ERROR: no requested run is complete; cannot build even an intermediate export.",
                file=sys.stderr,
            )
            print(check_report(checks), file=sys.stderr)
            return 2
        strategies_by_dataset = available_strategies_by_dataset(selected_checks)
        for dataset in strategies_by_dataset:
            strategies_by_dataset[dataset] = [
                strategy for strategy in strategies_by_dataset[dataset] if strategy in strategies
            ]

    units_by_uid: dict[str, Unit] = {}
    for dataset in DATASETS:
        if any(check.dataset == dataset and check.complete for check in selected_checks):
            for uid, unit in build_units(splits[dataset]).items():
                units_by_uid[uid] = unit
    units = sorted(units_by_uid.values(), key=lambda unit: unit.sort_key())
    try:
        for dataset in DATASETS:
            attach_records(
                units_by_uid,
                [check for check in selected_checks if check.complete and check.dataset == dataset],
                splits[dataset],
            )
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    include_categories: list[str] = []
    skipped: list[dict[str, Any]] = []
    warnings: list[str] = []
    for check in selected_checks:
        for warning in check.warnings:
            warnings.append(f"{check.label}: {warning}")
    selected_independent = strategies_by_dataset.get("independent", [])
    selected_pairs = strategies_by_dataset.get("pairs", [])
    complete_independent = any(check.complete and check.dataset == "independent" for check in checks)
    complete_pairs = any(check.complete and check.dataset == "pairs" for check in checks)
    complete_context = any(check.complete and check.strategy == "context" for check in checks)
    if selected_independent:
        include_categories.extend(["independent_false_positive", "independent_false_negative"])
        if len(selected_independent) >= 2:
            include_categories.append("strategy_disagreement")
        else:
            skipped.append(
                {
                    "category": "strategy_disagreement",
                    "reason": "requires at least two selected strategies on independent",
                }
            )
    else:
        independent_reason = (
            "independent dataset not selected for this intermediate export"
            if complete_independent
            else "no complete independent run"
        )
        for category in ("independent_false_positive", "independent_false_negative", "strategy_disagreement"):
            skipped.append({"category": category, "reason": independent_reason})
    if selected_pairs:
        include_categories.extend(["pair_both_flagged", "pair_both_clean", "pair_reversed"])
        include_categories.append("repair_complete_reference_mismatch")
        include_categories.append("repair_schema_invalid")
    else:
        pairs_reason = (
            "pairs dataset not selected for this intermediate export"
            if complete_pairs
            else "no complete pairs run"
        )
        for category in (
            "pair_both_flagged",
            "pair_both_clean",
            "pair_reversed",
            "repair_complete_reference_mismatch",
        ):
            skipped.append({"category": category, "reason": pairs_reason})
        if selected_independent:
            include_categories.append("repair_schema_invalid")
    if "context" in selected_independent or "context" in selected_pairs:
        include_categories.extend(["context_high_risk", "context_low_risk"])
    else:
        context_reason = (
            "context strategy not selected for this intermediate export"
            if complete_context
            else "no completed context run"
        )
        skipped.append({"category": "context_high_risk", "reason": context_reason})
        skipped.append({"category": "context_low_risk", "reason": context_reason})

    include_categories = [category for category in CATEGORY_ORDER if category in set(include_categories)]
    candidates_by_category = category_candidates(
        units, strategies_by_dataset, include_categories=include_categories
    )

    try:
        selected, selection_skips, selection_warnings = select_cases(
            candidates_by_category,
            available_categories=include_categories,
            strict=(args.mode == "formal"),
        )
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "No formal output was written. Use --mode intermediate to inspect "
            "the categories that do exist.",
            file=sys.stderr,
        )
        return 2
    skipped.extend(selection_skips)
    warnings.extend(selection_warnings)

    cases = []
    for index, candidate in enumerate(selected, 1):
        cases.append(
            build_case(
                candidate,
                f"C-{index:02d}",
                strategies_by_dataset.get(candidate.unit.dataset, []),
                max_code_lines=args.max_code_lines,
                max_code_chars=args.max_code_chars,
            )
        )

    run_summaries = [check.summary() for check in checks]
    all_inputs_complete = all(check.complete for check in checks)
    data = {
        "schema_version": SCHEMA_VERSION,
        "script_version": SCRIPT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "formal": args.mode == "formal",
        "all_inputs_complete": all_inputs_complete,
        "selection_rules_version": SCRIPT_VERSION,
        "no_api_calls": True,
        "case_count": len(cases),
        "category_order": list(CATEGORY_ORDER),
        "categories_included": include_categories,
        "skipped_categories": skipped,
        "warnings": warnings,
        "caveats": list(GLOBAL_CAVEATS),
        "inputs": {
            "root": ".",
            "run_count": sum(1 for check in checks if check.complete),
            "expected_run_count": FORMAL_RUN_COUNT,
            "runs": run_summaries,
            "datasets": {
                dataset: {
                    "path": split.path.as_posix().replace(str(root) + "/", ""),
                    "sha256": split.sha256,
                    "unit_count": split.unit_count,
                    "expected_detection_records": len(split.expected_keys["detection"]),
                    "expected_repair_records": len(split.expected_keys["repair"]),
                }
                for dataset, split in splits.items()
            },
        },
        "strategies_by_dataset": strategies_by_dataset,
        "cases": cases,
    }

    if args.mode == "intermediate":
        json_name = "cases.partial.json"
        md_name = "cases.partial.md"
    else:
        json_name = "cases.json"
        md_name = "cases.md"

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        json_text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        md_text = render_markdown(data)
        for name, content in ((json_name, json_text), (md_name, md_text)):
            target = out_dir / name
            temp = out_dir / (name + ".tmp")
            temp.write_text(content, encoding="utf-8")
            os.replace(temp, target)
    except OSError as exc:
        print(f"ERROR: failed to write output in {out_dir}: {exc}", file=sys.stderr)
        return 2

    print(f"Wrote {out_dir / json_name}")
    print(f"Wrote {out_dir / md_name}")
    print(f"Cases: {len(cases)}; formal={args.mode == 'formal'}; all_inputs_complete={all_inputs_complete}")
    if skipped:
        print("Skipped categories: " + ", ".join(item["category"] for item in skipped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

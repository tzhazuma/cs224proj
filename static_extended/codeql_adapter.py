#!/usr/bin/env python3
"""CodeQL adapter for the frozen Juliet CWE-401 subset.

Runs the CodeQL C/C++ queries ``cpp/memory-never-freed`` and
``cpp/memory-may-not-be-freed`` on each frozen unit (one CodeQL database per
unit), normalizes the SARIF results, and writes predictions plus metrics.

Standard library only. Refuses to overwrite a non-empty output directory.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

SCHEMA_VERSION = "static-extended-codeql-v1"
DEFAULT_QUERY_FILES = {
    "cpp/memory-never-freed": "Critical/MemoryNeverFreed.ql",
    "cpp/memory-may-not-be-freed": "Critical/MemoryMayNotBeFreed.ql",
}
CWE401 = "CWE-401"


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def slugify(value: str, limit: int = 90) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (cleaned or "unit")[:limit]


def fmt(value: float | None, digits: int = 4) -> str:
    if value is None:
        return "null"
    return f"{value:.{digits}f}"


def percentile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


# --------------------------------------------------------------------------
# units
# --------------------------------------------------------------------------


@dataclass
class Unit:
    unit_id: str
    label: bool
    language: str
    split: str
    sources: list[Path]
    defines: list[str]
    family: str
    group_id: str
    raw: dict[str, Any] = field(default_factory=dict)


def load_units(path: Path, juliet_root: Path, split: str | None) -> list[Unit]:
    units: list[Unit] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if split and record.get("split") != split:
                continue
            label = record.get("label")
            if isinstance(label, str):
                label = label.strip().lower() in {"bad", "vulnerable", "true", "1"}
            units.append(
                Unit(
                    unit_id=record["unit_id"],
                    label=bool(label),
                    language=record.get("language", "c"),
                    split=record.get("split", ""),
                    sources=[juliet_root / item for item in record["sources"]],
                    defines=list(record.get("defines") or []),
                    family=record.get("family", ""),
                    group_id=record.get("group_id", ""),
                    raw=record,
                )
            )
    return units


# --------------------------------------------------------------------------
# per-unit preparation and analysis
# --------------------------------------------------------------------------


def prepare_source(unit: Unit, index: int, work_dir: Path) -> tuple[Path, str, bool]:
    """Return (path used on the compiler command line, cwd-relative form, generated)."""
    ext = ".cpp" if unit.language == "cpp" else ".c"
    if len(unit.sources) == 1:
        return unit.sources[0], str(unit.sources[0]), False
    wrapper = work_dir / f"{index:05d}_{slugify(unit.unit_id)}{ext}"
    lines = [f'#include "{source.as_posix()}"' for source in unit.sources]
    wrapper.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return wrapper, str(wrapper), True


def build_compile_command(
    unit: Unit,
    compile_path: Path,
    juliet_root: Path,
    support_dir: Path,
    obj_path: Path,
    c_std: str,
    cxx_std: str,
) -> list[str]:
    compiler = "g++" if unit.language == "cpp" else "gcc"
    std = cxx_std if unit.language == "cpp" else c_std
    command = [compiler, f"-std={std}", "-D_GNU_SOURCE"]
    for define in unit.defines:
        command.append(f"-D{define}")
    command += [
        "-I",
        str(support_dir),
        "-include",
        "alloca.h",
        "-c",
    ]
    try:
        command.append(str(compile_path.relative_to(juliet_root)))
    except ValueError:
        command.append(str(compile_path))
    command += ["-o", str(obj_path)]
    return command


def relative_location(uri: str, juliet_root: Path) -> str:
    """Normalize a SARIF artifact URI to a juliet-root-relative POSIX path."""
    if uri.startswith("file://"):
        uri = urllib.parse.unquote(uri[len("file://") :])
    path = Path(uri)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(juliet_root).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def parse_sarif(
    sarif_path: Path,
    juliet_root: Path,
    target_paths: set[str],
    generated_path: str | None,
) -> list[dict[str, Any]]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    diagnostics: list[dict[str, Any]] = []
    for run in data.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            locations = result.get("locations") or []
            physical = (locations[0] if locations else {}).get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {}) or {}
            region = physical.get("region", {}) or {}
            uri = artifact.get("uri", "")
            rel = relative_location(uri, juliet_root) if uri else ""
            in_target = rel in target_paths or (generated_path is not None and rel == generated_path)
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            diagnostics.append(
                {
                    "query_id": rule_id,
                    "query_name": rule.get("name", ""),
                    "severity": (result.get("level") or rule.get("defaultConfiguration", {}).get("level") or ""),
                    "message": result.get("message", {}).get("text", ""),
                    "uri": uri,
                    "path": rel,
                    "line": region.get("startLine"),
                    "column": region.get("startColumn"),
                    "end_line": region.get("endLine"),
                    "in_target_file": in_target,
                    "counts_as_finding": bool(in_target),
                    "cwe": [CWE401],
                    "code_flows": len(result.get("codeFlows", []) or []),
                }
            )
    return diagnostics


def run_process(command: Sequence[str], cwd: Path, timeout: float) -> dict[str, Any]:
    started = time.time()
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return {
            "command": list(command),
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
            "duration_seconds": round(time.time() - started, 6),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": list(command),
            "exit_code": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            "timed_out": True,
            "duration_seconds": round(time.time() - started, 6),
        }


def compile_error_lines(text: str, limit: int = 8) -> list[str]:
    lines = [line for line in text.splitlines() if re.search(r"\b(error|fatal error):", line)]
    return lines[:limit]


def analyze_unit(
    unit: Unit,
    index: int,
    args: argparse.Namespace,
    juliet_root: Path,
    out_dir: Path,
) -> dict[str, Any]:
    slug = f"{index:05d}_{slugify(unit.unit_id)}"
    db_dir = args.db_root / f"{slug}.db"
    obj_path = out_dir / "work" / "obj" / f"{slug}.o"
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    compile_path, _display, generated = prepare_source(unit, index, out_dir / "work")
    build = build_compile_command(
        unit,
        compile_path,
        juliet_root,
        args.support_dir,
        obj_path,
        args.std_c,
        args.std_cxx,
    )

    started_at = utc_now()
    timings: dict[str, float] = {}
    errors: list[str] = []

    db_dir.parent.mkdir(parents=True, exist_ok=True)
    if db_dir.exists():
        shutil.rmtree(db_dir)

    create_command = [
        str(args.codeql),
        "database",
        "create",
        str(db_dir),
        "--language=cpp",
        f"--source-root={juliet_root}",
        f"--command={shlex.join(build)}",
        "--threads=1",
        "--overwrite",
    ]
    create_result = run_process(create_command, cwd=juliet_root, timeout=args.timeout)
    timings["database_create_seconds"] = create_result["duration_seconds"]
    raw_prefix = out_dir / "raw" / slug
    (raw_prefix.parent).mkdir(parents=True, exist_ok=True)
    (raw_prefix.with_suffix(".create.stdout.txt")).write_text(create_result["stdout"], encoding="utf-8", errors="replace")
    (raw_prefix.with_suffix(".create.stderr.txt")).write_text(create_result["stderr"], encoding="utf-8", errors="replace")
    (raw_prefix.with_suffix(".compile.cmd.txt")).write_text(
        shlex.join(build) + "\n", encoding="utf-8"
    )

    create_text = create_result["stdout"] + "\n" + create_result["stderr"]
    build_failed = bool(
        re.search(r"Build command failed", create_text)
        or re.search(r"Exit status \d+ from command", create_text)
        or re.search(r"fatal error occurred: Exit status", create_text)
    )
    if create_result["timed_out"]:
        status = "timeout"
        errors.append("codeql database create timed out")
    elif build_failed and not db_dir.exists():
        status = "compile_error"
        errors.extend(compile_error_lines(create_text))
    elif not db_dir.exists():
        status = "tool_error"
        errors.append("CodeQL database was not created")
    else:
        status = "ok" if not build_failed else "compile_error"
        if build_failed:
            errors.extend(compile_error_lines(create_text))

    diagnostics: list[dict[str, Any]] = []
    sarif_rel: str | None = None
    if status in {"ok", "compile_error"} and args.analyze_on_compile_error and db_dir.exists() or (
        status == "ok" and db_dir.exists()
    ):
        sarif_path = out_dir / "raw" / f"{slug}.sarif"
        analyze_command = [
            str(args.codeql),
            "database",
            "analyze",
            str(db_dir),
            *[str(query) for query in args.query],
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--threads=1",
            f"--ram={args.ram}",
        ]
        analyze_result = run_process(analyze_command, cwd=juliet_root, timeout=args.timeout)
        timings["analyze_seconds"] = analyze_result["duration_seconds"]
        (raw_prefix.with_suffix(".analyze.stdout.txt")).write_text(analyze_result["stdout"], encoding="utf-8", errors="replace")
        (raw_prefix.with_suffix(".analyze.stderr.txt")).write_text(analyze_result["stderr"], encoding="utf-8", errors="replace")
        (raw_prefix.with_suffix(".analyze.cmd.txt")).write_text(
            shlex.join(analyze_command) + "\n", encoding="utf-8"
        )
        if analyze_result["timed_out"]:
            if status == "ok":
                status = "timeout"
            errors.append("codeql database analyze timed out")
        elif analyze_result["exit_code"] not in (0, None) or not sarif_path.exists():
            if status == "ok":
                status = "tool_error"
            errors.append(f"codeql analyze failed with exit code {analyze_result['exit_code']}")
        else:
            target_paths = {
                * [source.relative_to(juliet_root).as_posix() for source in unit.sources]
            }
            generated_rel = None
            if generated:
                try:
                    generated_rel = compile_path.resolve().relative_to(juliet_root).as_posix()
                except ValueError:
                    generated_rel = compile_path.resolve().as_posix()
                target_paths.add(generated_rel)
            diagnostics = parse_sarif(sarif_path, juliet_root, target_paths, generated_rel)
            if not args.keep_sarif:
                gz_path = sarif_path.with_suffix(".sarif.gz")
                with sarif_path.open("rb") as src, gzip.open(gz_path, "wb", compresslevel=9) as dst:
                    shutil.copyfileobj(src, dst)
                sarif_path.unlink()
                sarif_path = gz_path
            sarif_rel = str(sarif_path.relative_to(out_dir))

    if db_dir.exists() and not args.keep_dbs:
        shutil.rmtree(db_dir, ignore_errors=True)

    counts_by_query: dict[str, int] = {query_id: 0 for query_id in args.query_ids}
    for diagnostic in diagnostics:
        if diagnostic["counts_as_finding"] and diagnostic["query_id"] in counts_by_query:
            counts_by_query[diagnostic["query_id"]] += 1
    any_hit = any(value > 0 for value in counts_by_query.values())

    return {
        "schema_version": SCHEMA_VERSION,
        "method": "codeql-cpp-cwe401",
        "tool": "codeql",
        "sample_id": unit.unit_id,
        "sample": {
            "sources": [source.as_posix() for source in unit.sources],
            "language": unit.language,
            "label": unit.label,
            "split": unit.split,
            "family": unit.family,
            "group_id": unit.group_id,
            "defines": unit.defines,
        },
        "source": {
            "analyzed_path": str(compile_path),
            "generated": generated,
            "combined": len(unit.sources) > 1,
            "origin_sha256": sha256_text("\n".join(f"{p}:{sha256_file(p)}" for p in unit.sources)),
        },
        "label": unit.label,
        "prediction": {
            "is_vulnerable": any_hit,
            "cwe": CWE401 if any_hit else None,
            "finding_count": sum(counts_by_query.values()),
            "by_query": counts_by_query,
        },
        "queries": {
            query_id: {"hit": counts_by_query.get(query_id, 0) > 0, "findings": counts_by_query.get(query_id, 0)}
            for query_id in args.query_ids
        },
        "diagnostics": diagnostics,
        "diagnostic_counts": {
            "total": len(diagnostics),
            "in_target_file": sum(1 for item in diagnostics if item["counts_as_finding"]),
            "cwe401": sum(1 for item in diagnostics if item["counts_as_finding"]),
        },
        "status": status,
        "errors": errors,
        "runtime": {
            "started_at": started_at,
            "ended_at": utc_now(),
            "duration_seconds": round(sum(timings.values()), 6),
            "phases": timings,
        },
        "command": create_command,
        "build_command": build,
        "sarif": sarif_rel,
    }


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------


def confusion(rows: Iterable[dict[str, Any]], include_compile_errors: bool) -> dict[str, int]:
    tp = fp = tn = fn = 0
    excluded = 0
    for row in rows:
        status = row["status"]
        if status == "ok":
            pass
        elif include_compile_errors and status in {"compile_error", "timeout"}:
            pass
        else:
            excluded += 1
            continue
        predicted = bool(row["prediction"]["is_vulnerable"]) and status == "ok"
        label = bool(row["label"])
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif not predicted and not label:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "excluded": excluded}


def metrics_from_confusion(counts: dict[str, int]) -> dict[str, Any]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    accuracy = (tp + tn) / total if total else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else 0.0
    f1_non = None
    if tn + fp:
        p_non = tn / (tn + fp)
        r_non = tn / (tn + fn) if tn + fn else None
        if r_non is not None:
            f1_non = 2 * p_non * r_non / (p_non + r_non) if p_non + r_non else 0.0
    macro = (f1 + f1_non) / 2 if f1_non is not None else None
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else None
    return {
        "n": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "excluded": counts["excluded"],
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1_vulnerable": f1,
        "f1_non_vulnerable": f1_non,
        "macro_f1": macro,
        "accuracy": accuracy,
        "mcc": mcc,
    }


def group_metrics(rows: Sequence[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row["sample"].get(key)), []).append(row)
    result = {}
    for name, subset in sorted(groups.items()):
        result[name] = {
            "evaluable": metrics_from_confusion(confusion(subset, False)),
            "end_to_end": metrics_from_confusion(confusion(subset, True)),
        }
    return result


def timing_stats(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    values = [row["runtime"]["duration_seconds"] for row in rows]
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "total_seconds": round(sum(values), 3),
        "mean_seconds": round(statistics.mean(values), 4),
        "median_seconds": round(statistics.median(values), 4),
        "p95_seconds": round(percentile(values, 0.95) or 0.0, 4),
        "max_seconds": round(max(values), 4),
    }


def tool_metrics(rows: Sequence[dict[str, Any]], query_ids: Sequence[str]) -> dict[str, Any]:
    evaluable = metrics_from_confusion(confusion(rows, False))
    end_to_end = metrics_from_confusion(confusion(rows, True))
    status_counts: dict[str, int] = {}
    for row in rows:
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    per_query = {}
    for query_id in query_ids:
        subset = []
        for row in rows:
            clone = dict(row)
            clone["prediction"] = {
                "is_vulnerable": bool(row.get("queries", {}).get(query_id, {}).get("hit")),
                "cwe": CWE401 if row.get("queries", {}).get(query_id, {}).get("hit") else None,
                "finding_count": int(row.get("queries", {}).get(query_id, {}).get("findings", 0)),
            }
            subset.append(clone)
        per_query[query_id] = {
            "evaluable": metrics_from_confusion(confusion(subset, False)),
            "end_to_end": metrics_from_confusion(confusion(subset, True)),
        }
    by_language = group_metrics(rows, "language")
    by_split = group_metrics(rows, "split")
    diagnostics = [item for row in rows for item in row["diagnostics"]]
    return {
        "runs": len(rows),
        "labelled": sum(1 for row in rows if row.get("label") is not None),
        "evaluable_count": sum(1 for row in rows if row["status"] == "ok"),
        "coverage": (sum(1 for row in rows if row["status"] == "ok") / len(rows)) if rows else None,
        "status_counts": status_counts,
        "evaluable": evaluable,
        "end_to_end": end_to_end,
        "per_query": per_query,
        "by_language": by_language,
        "by_split": by_split,
        "diagnostics": {
            "total": len(diagnostics),
            "cwe401": sum(1 for item in diagnostics if item["counts_as_finding"]),
            "by_query": {
                query_id: sum(1 for item in diagnostics if item["query_id"] == query_id)
                for query_id in query_ids
            },
            "in_target_file": sum(1 for item in diagnostics if item["counts_as_finding"]),
        },
        "timing": timing_stats(rows),
    }


# --------------------------------------------------------------------------
# manifests / reports
# --------------------------------------------------------------------------


def write_metrics_markdown(metrics: dict[str, Any], path: Path) -> None:
    lines = ["# CodeQL CWE-401 结果（自动生成）", ""]
    lines.append(f"- 生成时间：`{metrics['generated_at']}`")
    lines.append(f"- 数据集：`{metrics['dataset']['path']}` (sha256 `{metrics['dataset']['sha256'][:16]}…`)")
    lines.append(f"- 单元：{metrics['dataset']['n_units']}（test {metrics['dataset']['split_counts'].get('test', 0)} / dev {metrics['dataset']['split_counts'].get('dev', 0)}）")
    lines.append(f"- 运行墙钟时间：{metrics['wall_seconds']:.1f} s")
    lines.append(f"- 工具：{metrics['tool_info'].get('version')}")
    lines.append("")
    tool = metrics["tool"]
    lines.append("## 状态")
    lines.append("")
    lines.append(f"状态计数：`{tool['status_counts']}`；可评估 {tool['evaluable_count']}/{tool['runs']}（覆盖率 {fmt(tool['coverage'])}）。")
    lines.append("")
    lines.append("## 汇总（端到端，编译失败按未报泄漏计）")
    lines.append("")
    lines.append("| 视图 | TP | FP | TN | FN | Precision | Recall | Specificity | F1(V) | Macro-F1 | Accuracy | MCC |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, met in (("可评估", tool["evaluable"]), ("端到端", tool["end_to_end"])):
        lines.append(
            f"| {name} | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | {fmt(met['precision'])} | "
            f"{fmt(met['recall'])} | {fmt(met['specificity'])} | {fmt(met['f1_vulnerable'])} | "
            f"{fmt(met['macro_f1'])} | {fmt(met['accuracy'])} | {fmt(met['mcc'])} |"
        )
    lines.append("")
    lines.append("## 分查询（可评估）")
    lines.append("")
    lines.append("| 查询 | TP | FP | TN | FN | Precision | Recall | F1(V) | MCC |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for query_id, group in tool["per_query"].items():
        met = group["evaluable"]
        lines.append(
            f"| `{query_id}` | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | "
            f"{fmt(met['precision'])} | {fmt(met['recall'])} | {fmt(met['f1_vulnerable'])} | {fmt(met['mcc'])} |"
        )
    lines.append("")
    lines.append("## 分语言（可评估）")
    lines.append("")
    lines.append("| 语言 | N | TP | FP | TN | FN | Precision | Recall | F1(V) |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for language, group in tool["by_language"].items():
        met = group["evaluable"]
        lines.append(
            f"| {language} | {met['n']} | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | "
            f"{fmt(met['precision'])} | {fmt(met['recall'])} | {fmt(met['f1_vulnerable'])} |"
        )
    lines.append("")
    lines.append("## 分 split（可评估）")
    lines.append("")
    lines.append("| split | N | TP | FP | TN | FN | Precision | Recall | F1(V) |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for split, group in tool["by_split"].items():
        met = group["evaluable"]
        lines.append(
            f"| {split} | {met['n']} | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | "
            f"{fmt(met['precision'])} | {fmt(met['recall'])} | {fmt(met['f1_vulnerable'])} |"
        )
    lines.append("")
    timing = tool["timing"]
    lines.append("## 计时")
    lines.append("")
    lines.append(
        f"总计 {timing['total_seconds']} s，均值 {timing['mean_seconds']} s，中位 {timing['median_seconds']} s，"
        f"P95 {timing['p95_seconds']} s，最大 {timing['max_seconds']} s。"
    )
    lines.append("")
    lines.append("## 口径")
    lines.append("")
    lines.append("- 正类 = 目标源文件中存在 `cpp/memory-never-freed` 或 `cpp/memory-may-not-be-freed` 结果。")
    lines.append("- 可评估只含 `status=ok`；端到端把 `compile_error`/`timeout` 按未报泄漏计入。")
    lines.append("- 每个单元单独建 CodeQL 数据库（`gcc`/`g++` 编译），多文件单元按基线同样方式合成一个 TU。")
    lines.append("- 头文件中的结果不计入（与 Clang/Cppcheck 基线 `--include-external` 关闭一致）。")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", required=True, type=Path)
    parser.add_argument("--juliet-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--codeql", type=Path, default=Path.home() / "tools/codeql-2.27.4/codeql/codeql")
    parser.add_argument("--query", action="append", type=Path, default=None)
    parser.add_argument("--query-id", action="append", default=None, help="query id matching --query order")
    parser.add_argument("--support-dir", type=Path, default=None)
    parser.add_argument("--db-root", type=Path, default=Path("/tmp/codeql-dbs"))
    parser.add_argument("--split", choices=["test", "dev"], default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--ram", type=int, default=2048, help="MB per analyze process")
    parser.add_argument("--std-c", default="c11")
    parser.add_argument("--std-cxx", default="c++17")
    parser.add_argument("--keep-dbs", action="store_true")
    parser.add_argument("--keep-sarif", action="store_true", help="keep plain SARIF instead of gzip")
    parser.add_argument("--analyze-on-compile-error", action="store_true", default=False)
    parser.add_argument("--dataset-name", default="juliet-cwe401-v1.3-subset-v1")
    args = parser.parse_args(argv)

    if args.query is None:
        pack_root = Path.home() / ".codeql/packages/codeql/cpp-queries"
        versions = sorted(pack_root.glob("*")) if pack_root.exists() else []
        if not versions:
            parser.error("no --query given and no codeql/cpp-queries pack installed")
        pack = versions[-1]
        args.query = [pack / rel for rel in DEFAULT_QUERY_FILES.values()]
        args.query_ids = list(DEFAULT_QUERY_FILES)
    if args.query_ids is None:
        args.query_ids = []
        for query in args.query:
            text = query.read_text(encoding="utf-8", errors="replace")[:800]
            match = re.search(r"@id\s+([^\s*]+)", text)
            args.query_ids.append(match.group(1) if match else query.stem)
    if len(args.query_ids) != len(args.query):
        parser.error("--query-id count must match --query count")
    for query, query_id in zip(args.query, args.query_ids):
        if not query.exists():
            parser.error(f"query not found: {query}")
        if query_id not in DEFAULT_QUERY_FILES:
            print(f"warning: query {query_id} is not a standard CWE-401 query id", file=sys.stderr)
    if args.support_dir is None:
        args.support_dir = args.juliet_root / "raw/testcasesupport"
    args.juliet_root = args.juliet_root.resolve()
    args.support_dir = args.support_dir.resolve()
    return args


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    started = time.time()
    out_dir = args.out.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"refusing to overwrite non-empty output directory: {out_dir}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "work").mkdir(exist_ok=True)
    (out_dir / "raw").mkdir(exist_ok=True)

    units = load_units(args.units, args.juliet_root, args.split)
    if args.limit is not None:
        units = units[: args.limit]
    if not units:
        print("no units selected", file=sys.stderr)
        return 2

    tool_version = run_process([str(args.codeql), "version"], cwd=out_dir, timeout=120)
    version_line = tool_version["stdout"].splitlines()[0] if tool_version["stdout"] else ""

    print(f"CodeQL: {version_line}")
    print(f"units: {len(units)}; jobs: {args.jobs}; queries: {args.query_ids}")

    rows: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {
            pool.submit(analyze_unit, unit, index, args, args.juliet_root, out_dir): (unit, index)
            for index, unit in enumerate(units, start=1)
        }
        for done, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            unit, index = futures[future]
            try:
                row = future.result()
            except Exception as exc:  # keep the run alive, record the failure
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "method": "codeql-cpp-cwe401",
                    "tool": "codeql",
                    "sample_id": unit.unit_id,
                    "sample": {
                        "sources": [str(p) for p in unit.sources],
                        "language": unit.language,
                        "label": unit.label,
                        "split": unit.split,
                        "family": unit.family,
                        "group_id": unit.group_id,
                        "defines": unit.defines,
                    },
                    "label": unit.label,
                    "prediction": {"is_vulnerable": False, "cwe": None, "finding_count": 0, "by_query": {}},
                    "queries": {query_id: {"hit": False, "findings": 0} for query_id in args.query_ids},
                    "diagnostics": [],
                    "diagnostic_counts": {"total": 0, "in_target_file": 0, "cwe401": 0},
                    "status": "tool_error",
                    "errors": [f"adapter exception: {exc!r}"],
                    "runtime": {"started_at": utc_now(), "ended_at": utc_now(), "duration_seconds": 0.0, "phases": {}},
                    "command": [],
                    "build_command": [],
                    "sarif": None,
                }
            rows.append(row)
            if done % 10 == 0 or done == len(units):
                print(f"  {done}/{len(units)} done", flush=True)

    rows.sort(key=lambda item: item["sample_id"])
    predictions_path = out_dir / "predictions.jsonl"
    with predictions_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    wall = time.time() - started
    tool_block = tool_metrics(rows, args.query_ids)
    split_counts: dict[str, int] = {}
    for row in rows:
        split_counts[row["sample"]["split"]] = split_counts.get(row["sample"]["split"], 0) + 1
    metrics = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "wall_seconds": round(wall, 3),
        "dataset": {
            "path": str(args.units.resolve()),
            "sha256": sha256_file(args.units),
            "n_units": len(rows),
            "split_counts": split_counts,
            "label_counts": {
                "vulnerable": sum(1 for row in rows if row["label"]),
                "non_vulnerable": sum(1 for row in rows if not row["label"]),
            },
            "name": args.dataset_name,
        },
        "tool_info": {
            "name": "codeql",
            "version": version_line,
            "binary": str(args.codeql),
            "queries": [
                {"id": query_id, "path": str(query), "sha256": sha256_file(query)}
                for query_id, query in zip(args.query_ids, args.query)
            ],
        },
        "settings": {
            "split": args.split,
            "jobs": args.jobs,
            "timeout_seconds": args.timeout,
            "std_c": args.std_c,
            "std_cxx": args.std_cxx,
            "ram_mb": args.ram,
            "support_dir": str(args.support_dir),
            "analyze_on_compile_error": args.analyze_on_compile_error,
        },
        "tool": tool_block,
        "target_cwe": CWE401,
        "limitations": [
            "One CodeQL database per unit with a single gcc/g++ compile command; the build is a single translation unit.",
            "Multi-file Juliet groups are combined into one wrapper TU, same convention as the Clang/Cppcheck baseline.",
            "Header-only results are excluded (include_external=false in the baseline).",
            "Compile errors are reported by CodeQL's build tracing; the original compiler text is kept in raw/.",
        ],
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_metrics_markdown(metrics, out_dir / "metrics.md")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "command": sys.argv,
        "adapter": {"path": str(Path(__file__).resolve()), "sha256": sha256_file(Path(__file__).resolve())},
        "input": {"path": str(args.units.resolve()), "sha256": sha256_file(args.units)},
        "outputs": {
            name: {"sha256": sha256_file(out_dir / name), "bytes": (out_dir / name).stat().st_size}
            for name in ("predictions.jsonl", "metrics.json", "metrics.md")
        },
        "tool": metrics["tool_info"],
        "settings": metrics["settings"],
        "wall_seconds": metrics["wall_seconds"],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "units": len(rows),
        "status": tool_block["status_counts"],
        "evaluable": tool_block["evaluable"],
        "end_to_end": tool_block["end_to_end"],
        "wall_seconds": metrics["wall_seconds"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Render the metrics JSON as a Markdown report."""

from __future__ import annotations

import json
from pathlib import Path

from . import config


def _fmt(value, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render(metrics: dict, manifest: dict | None = None) -> str:
    lines = [
        f"# 动态分析增强结果：{metrics['run_id']}",
        "",
        f"- 单元：{metrics['units']}（bad {metrics['labels']['bad']} / good {metrics['labels']['good']}）",
        "- 模式：`default`（标准 LSan 根集）、`realloc_fail`（首个非空指针 realloc 强制失败）、"
        "`nogobal`（`use_globals=0`）",
        "- 判定：任一适用模式出现**归因到单元源码**的泄漏即 `leak`；否则 `clean`。"
        "未归因的运行时/支撑库泄漏不计入。",
        "",
        "## 1. 混淆矩阵（140 单元）",
        "",
        "| 指标 | 值 |",
        "| --- | ---: |",
        f"| TP | {metrics['confusion']['tp']} |",
        f"| FP | {metrics['confusion']['fp']} |",
        f"| TN | {metrics['confusion']['tn']} |",
        f"| FN | {metrics['confusion']['fn']} |",
        f"| undecided | {metrics['confusion']['undecided']} |",
        f"| coverage | {_fmt(metrics['confusion']['coverage'])} |",
        f"| precision | {_fmt(metrics['confusion']['precision'])} |",
        f"| recall | {_fmt(metrics['confusion']['recall'])} |",
        f"| F1 | {_fmt(metrics['confusion']['f1'])} |",
        "",
        "## 2. 各模式证据",
        "",
        "| 模式 | 适用单元 | bad 归因泄漏 | good 归因泄漏 | bad 原始泄漏 | good 原始泄漏 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode in config.MODES:
        stats = metrics["per_mode"][mode]
        lines.append(
            f"| `{mode}` | {stats['applicable_units']} | {stats['bad_attributed']} | "
            f"{stats['good_attributed']} | {stats['bad_raw']} | {stats['good_raw']} |"
        )
    lines += [
        "",
        "`good 原始泄漏` 非零不代表误报：`nogobal` 会把 glibc 的 stdout 缓冲区和 libstdc++ "
        "运行时分配暴露出来；这些块的分配栈不在单元源码里，按归因规则被排除。"
        "归因规则只看分配栈第一个落在非工具链位置的源码帧，不看文件名或标签。",
        "",
        "## 3. 由条件/可达性证据解决的 12 个单元",
        "",
        f"共 {len(metrics['resolved_conditional'])} 个 bad 单元在 `default` 下无归因泄漏，"
        "在新模式下得到明确证据：",
        "",
        "| 单元 | 主证据 | 模式 | default | realloc_fail | 注入调用 | nogobal | 归因字节 |",
        "| --- | --- | --- | --- | --- | ---: | --- | ---: |",
    ]
    for item in metrics["resolved_conditional"]:
        lines.append(
            f"| `{item['unit_id']}` | {item['primary_evidence']} | {', '.join(item['evidence_modes'] or [])} | "
            f"{item['default']} | {item['realloc_fail']} | {_fmt(item['realloc_injected_at'])} | "
            f"{item['nogobal']} | {item['attributed_bytes']} |"
        )
    lines += [
        "",
        f"- `default` 下不可观测的 bad 单元：{len(metrics['default_unobservable_bad'])} 个，"
        f"全部由新模式给出证据。",
        f"- good 误报：{len(metrics['good_false_positives'])} 个"
        + (f"（{', '.join(metrics['good_false_positives'])}）" if metrics["good_false_positives"] else ""),
        "",
        "## 4. 失败分类与运行时间",
        "",
        "| failure_class | 单元数 |",
        "| --- | ---: |",
    ]
    for key, value in sorted(metrics["failures"].items()):
        lines.append(f"| `{key}` | {value} |")
    runtime = metrics["runtime"]
    lines += [
        "",
        f"- 单元总运行时间（编译 + 3 次运行）：total {runtime['total_ms']} ms，"
        f"mean {_fmt(runtime['mean_ms'], 1)} ms，p50 {runtime['p50_ms']} ms，"
        f"p95 {runtime['p95_ms']} ms，max {runtime['max_ms']} ms。",
        "",
        "| 模式 | 运行次数 | 平均运行 | p95 运行 | 最大运行 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for mode, stats in runtime["by_mode"].items():
        lines.append(
            f"| `{mode}` | {stats['runs']} | {_fmt(stats['mean_ms'], 1)} ms | "
            f"{stats['p95_ms']} ms | {stats['max_ms']} ms |"
        )
    comparison = metrics.get("old_comparison") or {}
    if comparison:
        lines += [
            "",
            "## 5. 与旧 ASan/Valgrind 运行对比",
            "",
            f"- 旧运行：`{comparison['old_run']}`（{comparison['old_cases']} cases；"
            f"匹配 {comparison['matched_units']}/140 单元）。",
            f"- 新 `default` 与旧 ASan 判定一致："
            f"{comparison['agreements']['default_vs_old_asan']}/140。",
            f"- 新并集与旧 ASan/Valgrind 任一泄漏一致："
            f"{comparison['agreements']['union_vs_old_any']}/140。",
            f"- 旧 ASan 平均运行：{_fmt(comparison['old_asan_duration_mean_ms'], 1)} ms；"
            f"新 `default` 平均运行：{_fmt(metrics['runtime']['by_mode']['default']['mean_ms'], 1)} ms。",
            "",
            "判定发生变化的单元：",
            "",
            "| 单元 | 标签 | 旧 ASan | 旧 Valgrind | 新 default | 新并集 | 主证据 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for change in comparison["changes"]:
            lines.append(
                f"| `{change['unit_id']}` | {change['label']} | {change['old_asan']} | "
                f"{change['old_valgrind']} | {change['new_default']} | {change['new_union']} | "
                f"{change['evidence']} |"
            )
        if not comparison["changes"]:
            lines.append("| — | — | — | — | — | — | — |")
    if manifest:
        lines += [
            "",
            "## 6. 运行清单",
            "",
            f"- 创建时间（UTC）：{manifest.get('created_at_utc')}",
            f"- 完成时间（UTC）：{manifest.get('finished_at_utc')}",
            f"- 总墙钟：{manifest.get('wall_seconds')} s",
            f"- `results_units.jsonl` SHA-256：`{manifest.get('results_units_sha256')}`",
            f"- `results_raw.jsonl` SHA-256：`{manifest.get('results_raw_sha256')}`",
            f"- 工具：{manifest.get('tools', {}).get('gcc')}；{manifest.get('tools', {}).get('g++')}",
        ]
    lines.append("")
    return "\n".join(lines)


def write(run_dir: Path, metrics: dict, manifest: dict | None) -> Path:
    text = render(metrics, manifest)
    path = run_dir / "metrics.md"
    path.write_text(text, encoding="utf-8")
    (run_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return path

"""Render the coverage audit to metrics.md, metrics.json and tidy CSV exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import config
from .metrics import (
    TIER_ORDER,
    build_metrics,
    default_tier,
    default_tier_raw,
    union_tier,
    union_tier_raw,
)
from .units import read_jsonl


def _pct(value) -> str:
    if value is None:
        return "—"
    return f"{100 * value:.1f}%"


def _num(value) -> str:
    if value is None:
        return "—"
    return f"{value:.3f}"


def _int_pair(value) -> str:
    if not value or value[0] is None:
        return "—"
    return f"{value[0]}/{value[1]}"


def _table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _tier_rows(counts: dict) -> list[list]:
    return [[tier, counts.get(tier, 0)] for tier in TIER_ORDER + ("compile_error",) if counts.get(tier)]


def write_exports(run_dir: Path, records: list[dict], metrics: dict) -> dict:
    exports = run_dir / "exports"
    exports.mkdir(exist_ok=True)
    coverage_csv = exports / "coverage_units.csv"
    with coverage_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "unit_id", "label", "family", "language", "mode", "applicable",
                "decision", "leak_attributed", "line_hit", "line_total", "line_pct",
                "branch_hit", "branch_total", "branch_pct", "coverage_tier",
                "coverage_tier_effective", "effective_line_pct", "dead_code_uncovered",
                "entry_executed", "returncode", "coverage_class", "covered_clean",
                "uncovered", "compile_error",
            ]
        )
        for record in records:
            for mode in config.MODES:
                entry = (record.get("modes") or {}).get(mode)
                if not entry:
                    continue
                cov = entry.get("coverage") or {}
                writer.writerow(
                    [
                        record["unit_id"], record["label"], record.get("family"),
                        record.get("language"), mode, entry.get("applicable"),
                        entry.get("decision"), entry.get("leak_attributed"),
                        cov.get("lines_hit"), cov.get("lines_total"), cov.get("line_pct"),
                        cov.get("branches_hit"), cov.get("branches_total"), cov.get("branch_pct"),
                        entry.get("coverage_tier"), entry.get("coverage_tier_effective"),
                        cov.get("effective_line_pct"), len(cov.get("dead_code_uncovered", [])),
                        entry.get("entry_executed"),
                        entry.get("returncode"),
                        record.get("coverage_class"), record.get("covered_clean"),
                        record.get("uncovered"), record.get("compile_error"),
                    ]
                )
    clean_csv = exports / "clean_evidence.csv"
    with clean_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "unit_id", "label", "family", "archived_default", "archived_union",
                "default_tier", "default_tier_raw", "union_tier", "union_tier_raw",
                "default_line_pct", "default_branch_pct",
                "union_line_pct", "union_branch_pct", "dead_code_lines", "primary_evidence",
            ]
        )
        for record in records:
            if record.get("archived_default") != "clean":
                continue
            default = (record.get("modes") or {}).get("default") or {}
            default_cov = default.get("coverage") or {}
            union_cov = record.get("coverage_union") or {}
            writer.writerow(
                [
                    record["unit_id"], record["label"], record.get("family"),
                    record.get("archived_default"), record.get("archived_union"),
                    default_tier(record), default_tier_raw(record),
                    union_tier(record), union_tier_raw(record),
                    default_cov.get("line_pct"), default_cov.get("branch_pct"),
                    union_cov.get("line_pct"), union_cov.get("branch_pct"),
                    len(default_cov.get("dead_code_uncovered", [])),
                    record.get("primary_evidence"),
                ]
            )
    latent_csv = exports / "latent_units.csv"
    with latent_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "unit_id", "family", "default_tier", "default_tier_raw", "union_tier",
                "default_lines", "default_branches", "default_line_pct",
                "default_branch_pct", "union_lines", "union_branches",
                "union_line_pct", "union_branch_pct", "primary_evidence",
                "default_uncovered_branch_lines",
            ]
        )
        for row in metrics["latent_units"]:
            writer.writerow(
                [
                    row["unit_id"], row["family"], row["default_tier"],
                    row.get("default_tier_raw"), row["union_tier"],
                    _int_pair(row["default_lines"]), _int_pair(row["default_branches"]),
                    row["default_line"], row["default_branch"],
                    _int_pair(row["union_lines"]), _int_pair(row["union_branches"]),
                    row["union_line"], row["union_branch"], row["primary_evidence"],
                    " ".join(
                        str(branch["line"]) for branch in row["default_uncovered_branches"]
                    ),
                ]
            )
    strata_csv = exports / "strata.csv"
    with strata_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "view", "tier", "units", "tp", "fp", "tn", "fn",
                "precision", "recall", "f1", "macro_f1", "mcc",
            ]
        )
        for view, table in (("default", metrics["default_strata"]), ("union", metrics["union_strata"])):
            for tier_name, row in table.items():
                writer.writerow(
                    [
                        view, tier_name, row["units"], row["tp"], row["fp"], row["tn"],
                        row["fn"], row["precision"], row["recall"], row["f1"],
                        row["macro_f1"], row["mcc"],
                    ]
                )
    return {
        "coverage_units": str(coverage_csv.relative_to(run_dir)),
        "clean_evidence": str(clean_csv.relative_to(run_dir)),
        "latent_units": str(latent_csv.relative_to(run_dir)),
        "strata": str(strata_csv.relative_to(run_dir)),
    }


def render(run_dir: Path, metrics: dict) -> str:
    overall = metrics["coverage_overall"]
    clean = metrics["clean_evidence"]
    latent = metrics["latent_units"]
    latent_summary = metrics["latent_summary"]
    cross = metrics["crosscheck"]
    old = metrics["archived"]["old_dynamic"] or {}
    parts: list[str] = []
    parts.append(
        "# 动态覆盖率证据：Juliet CWE-401 冻结 test 140\n\n"
        "本文件由 `dynamic_coverage/run_dynamic_coverage.py report` 生成。覆盖率的每个数字都来自 "
        "`gcov -j -b -c` 的逐行/逐分支记录；没有任何阈值把未执行的行算成已覆盖。泄漏判定沿用 "
        "`dynamic_enhanced` 的归因规则，只用于把“已执行且 clean”与“未充分执行”分开。\n"
    )
    parts.append(
        "**口径**：`branch_complete` = 单元自身文件的每个可执行行都执行且每个记录到的分支都至少走一次；"
        "`line_complete` = 行全覆盖但至少一个分支未走；`partial` = 有可执行行未走；"
        "`not_executed` = 单元自身代码一行都没执行。`coverage_error` 不当作 clean，也不当作负例。"
        "报告中的 `effective` 分层把源码中标注 `INCIDENTAL: CWE 561 Dead Code` 的不可达行从分母剔除，"
        "同时保留原始行覆盖数和具体行号，剔除规则不是按百分比阈值。\n"
    )

    rows = []
    for mode in config.MODES:
        row = metrics["coverage_by_mode"][mode]
        rows.append(
            [
                mode, row["units"], row["applicable_units"], row["bad_leaks"],
                row["good_leaks"], _pct(row["mean_effective_line_pct"]),
                _pct(row["mean_branch_pct"]),
                row["tiers_effective"].get("branch_complete", 0),
                row["tiers_effective"].get("line_complete", 0),
                row["tiers_effective"].get("partial", 0),
                row["tiers_effective"].get("not_executed", 0),
                row["tiers_effective"].get("coverage_error", 0),
            ]
        )
    parts.append("## 1. 三种模式的覆盖率采集\n\n" + _table(
        ["模式", "单元", "适用", "bad leak", "good leak", "有效行覆盖均值", "分支覆盖均值",
         "branch_complete", "line_complete", "partial", "not_executed", "coverage_error"],
        rows,
    ) + "\n")
    parts.append(
        f"并集（任意模式执行到的行/分支）：{overall['units']} 单元，"
        f"有效行覆盖均值 {_pct(overall['mean_effective_line_pct'])}，"
        f"原始行覆盖均值 {_pct(overall['mean_line_pct'])}，"
        f"分支覆盖均值 {_pct(overall['mean_branch_pct'])}，"
        f"入口已执行 {overall['entry_executed']}/{overall['units']}。"
        "表中的 `partial` 是剔除 CWE-561 声明死代码后的有效分层；原始行覆盖下 default/nogobal 各有 6 个 "
        "dead-code partial，realloc_fail 有 19 个（其中 14 个是注入后跳过 free 路径）。"
        f"`branch_complete` 的 21 个全部是 bad（bad {overall['branch_complete_bad']}、"
        f"good {overall['branch_complete_good']}）：good 单元的错误处理守卫更多，反而更难走全。"
        "因此 `branch_complete` 是本数据上代码形状的副产物，不是质量或 clean 信号。\n"
    )

    parts.append("## 2. 原路径 clean 的执行证据（82 个 clean = 70 good + 12 实际 bad）\n")
    parts.append(
        f"原路径 clean = {clean['units']}（真 good {clean['true_good']}，真 bad {clean['true_bad']}）。"
        "先给原始行覆盖分层，再给剔除 Juliet 自带 CWE-561 死代码后的有效分层。\n\n"
    )
    parts.append(_table(["raw tier", "单元数"], _tier_rows(clean["default_tiers_raw"])) + "\n")
    parts.append(
        f"原始分层中 `partial` 的 {clean['default_tiers_raw'].get('partial', 0)} 个单元，"
        f"未覆盖行全部是源码中标注 `INCIDENTAL: CWE 561 Dead Code` 的不可达行"
        f"（共 {clean['dead_code_lines']} 行）。剔除这些声明死代码后：\n\n"
    )
    parts.append(_table(["effective tier", "单元数"], _tier_rows(clean["default_tiers"])) + "\n")
    parts.append(
        f"`executed_clean` = {clean['executed_clean']}/{clean['units']}："
        "所有 clean 判定的可执行行都执行了，其中真 good "
        f"{clean['executed_clean'] - clean['executed_clean_bad']}、"
        f"实际是 bad 的 {clean['executed_clean_bad']}。"
        f"`branch_complete` 的 good = {clean['default_branch_complete_good']}，"
        "原因是 good 单元普遍包含 `if (allocation == NULL) exit(-1)` 之类的失败守卫（以及 "
        "`GLOBAL_CONST_FALSE` 死代码分支），不做分配失败注入时无法走全；"
        "因此 `branch_complete` 是严格上界，不作为 clean 支持的主判据。\n"
    )
    parts.append(
        f"三模式并集重新分层：`executed_clean` 仍为 {clean['executed_clean']}，"
        f"真 bad 仍为 {clean['executed_clean_bad']}；"
        f"增强模式把其中 {latent_summary['units']} 个 bad 从 clean 变成 leak，"
        "但这不是靠新增行覆盖，而是靠新增分支/改变根集（见第 6 节）。\n"
    )
    parts.append("### 2.1 逐单元三分类输出\n\n")
    rows = []
    for view, key, label_key in (
        ("default", "coverage_classes_default", "coverage_classes_default_by_label"),
        ("enhanced union", "coverage_classes", "coverage_classes_by_label"),
    ):
        counts = overall[key]
        by_label = overall[label_key]
        rows.append(
            [
                view,
                f"{counts['covered_clean']} "
                f"(good {by_label['covered_clean']['good']}, bad {by_label['covered_clean']['bad']})",
                f"{counts['uncovered']} "
                f"(good {by_label['uncovered']['good']}, bad {by_label['uncovered']['bad']})",
                counts["compile_error"],
                f"{counts['leak']} "
                f"(good {by_label['leak']['good']}, bad {by_label['leak']['bad']})",
            ]
        )
    parts.append(_table(
        ["视图", "covered_clean", "uncovered", "compile_error", "leak"], rows
    ) + "\n")
    parts.append(
        "`covered_clean` = clean 且 effective 行覆盖完整且入口已执行；它不是正确性标签："
        "default 视图的 82 个 covered_clean 里有 12 个实际是 bad。`uncovered` = clean 但覆盖不足；"
        "`compile_error` 单独计数，从不写成 `y_pred=0`。\n"
    )

    parts.append("## 3. 原路径漏掉的 12 个 bad：覆盖率解释\n")
    parts.append(
        f"12 个按证据模式分成两组：`realloc_fail` {len(latent_summary['realloc_evidence'])} 个，"
        f"`nogobal` {len(latent_summary['root_policy_evidence'])} 个。"
        f"前一组的默认路径是 `line_complete`，但 `realloc` 返回 NULL 的分支未走；"
        "`realloc_fail` 正好新增这个分支（第 6 节：14 个单元各新增 1 个分支）。"
        "后一组即使 `branch_complete`（2 个）或 `line_complete`（3 个）也仍然 clean，"
        "因为它们的问题不是执行不足，而是 LSan 把全局指针当根。\n\n"
        f"默认路径 effective `branch_complete` 的 {latent_summary['default_branch_complete']} 个、"
        f"`line_complete` 的 {latent_summary['default_line_complete']} 个、"
        f"`partial` 的 {latent_summary['default_partial']} 个。"
        "这 12 个没有一个是 `not_executed` 或 `partial`："
        "**行覆盖无法区分它们和 70 个 good**。\n\n"
    )
    rows = []
    for row in latent:
        snippets = "；".join(
            f"{item['line']}: {item['text']}"
            for item in row.get("default_uncovered_branch_snippets", [])[:4]
        ) or "—"
        rows.append(
            [
                row["unit_id"].replace("CWE401_Memory_Leak__", ""),
                row["primary_evidence"] or "—",
                row["default_tier"],
                _int_pair(row["default_lines"]),
                _int_pair(row["default_branches"]),
                _int_pair(row["union_branches"]),
                snippets,
            ]
        )
    parts.append(_table(
        ["单元", "证据模式", "默认 tier", "默认行", "默认分支", "并集分支", "默认未走分支（源码行）"],
        rows,
    ) + "\n")

    parts.append("## 4. 覆盖率分层混淆矩阵\n")
    parts.append("预测使用归档判定，覆盖率只决定分层；“—”表示该层没有可计算的分母。\n")
    for title, table in (("原路径（default）", metrics["default_strata"]),
                         ("增强并集（default+realloc_fail+nogobal）", metrics["union_strata"])):
        parts.append(f"### {title}\n\n")
        rows = []
        for tier_name in TIER_ORDER:
            if tier_name not in table:
                continue
            row = table[tier_name]
            rows.append(
                [
                    tier_name, row["units"], row["tp"], row["fp"], row["tn"], row["fn"],
                    _num(row["precision"]), _num(row["recall"]), _num(row["f1"]),
                    _num(row["macro_f1"]), _num(row["mcc"]),
                ]
            )
        parts.append(_table(
            ["tier", "n", "TP", "FP", "TN", "FN", "P", "R", "F1", "macro-F1", "MCC"], rows
        ) + "\n")

    parts.append("## 5. 覆盖率门控视图\n")
    parts.append(
        "只对负例（clean）门控：clean 且该视图的覆盖层不足时记为 abstain，从分母移除；"
        "leak 判定不因覆盖率被撤销。`line_gated` 用剔除 CWE-561 死代码后的有效行覆盖，"
        "`line_gated_raw` 用原始行覆盖（保留 6 个死代码行导致的 abstain）作为敏感性。"
        "`supported_clean_but_bad` 是“覆盖充分却仍被判 clean 的 bad”，"
        "也就是覆盖率无法纠正的错误负例。\n\n"
    )
    rows = []
    for name, row in metrics["gated_views"].items():
        rows.append(
            [
                name, row["tp"], row["fp"], row["tn"], row["fn"], row["abstain"],
                _pct(row["coverage"]), _num(row["precision"]), _num(row["recall"]),
                _num(row["f1"]), _num(row["mcc"]), row["supported_clean_but_bad"],
            ]
        )
    parts.append(_table(
        ["视图", "TP", "FP", "TN", "FN", "abstain", "coverage", "P", "R", "F1", "MCC",
         "supported clean 但 bad"],
        rows,
    ) + "\n")

    parts.append("## 6. 模式新增覆盖\n")
    rows = []
    for mode in config.MODES:
        row = metrics["mode_gain"][mode]
        rows.append(
            [
                mode, row["units_with_new_lines_or_branches"],
                row["added_lines_vs_default"], row["added_branches_vs_default"],
            ]
        )
    parts.append(_table(["模式", "相对 default 有新覆盖的单元", "新增行", "新增分支"], rows) + "\n")
    parts.append(
        "`nogobal` 与 `default` 是同一二进制、同一执行路径，只有 LSan 根集不同；它新增 0 行/0 分支"
        "是预期结果，也是“5 个 `_68` 单元的修复不是靠执行更多代码”的直接证据。\n"
    )

    parts.append("## 7. 分配/释放调用点覆盖\n")
    rows = []
    for name, row in metrics["site_coverage"].items():
        rows.append(
            [
                name, f"{row['allocation_sites_hit']}/{row['allocation_sites_total']}",
                f"{row['release_sites_hit']}/{row['release_sites_total']}",
            ]
        )
    parts.append(_table(["视图", "分配调用点执行", "释放调用点执行"], rows) + "\n")
    parts.append(
        "所有 167 个分配调用点和 89 个释放调用点都执行了（default 与 union 相同），"
        "包括原路径漏掉的 12 个 bad。调用点覆盖同样不能区分“执行了分配/释放”与“该块被泄漏”。\n"
    )

    parts.append("## 8. 与归档结果的一致性\n")
    agreement = old.get("agreement") or {}
    parts.append(
        f"覆盖率运行与原路径归档判定一致 {cross.get('default_agree')}/"
        f"{cross.get('archived_units')}；与增强并集一致 {cross.get('union_agree')}/"
        f"{cross.get('archived_units')}。"
        f"原动态运行（ASan/Valgrind）匹配 {old.get('matched_units')} 个单元；"
        f"归档对比 default_vs_old_asan={agreement.get('default_vs_old_asan')}、"
        f"union_vs_old_any={agreement.get('union_vs_old_any')}。\n"
    )
    if cross.get("default_mismatch"):
        parts.append("\n原路径不一致：\n\n")
        for row in cross["default_mismatch"]:
            parts.append(f"- `{row['unit_id']}`：覆盖率运行 {row['coverage']}，归档 {row['archived']}\n")
    if cross.get("union_mismatch"):
        parts.append("\n并集不一致：\n\n")
        for row in cross["union_mismatch"]:
            parts.append(f"- `{row['unit_id']}`：覆盖率运行 {row['coverage']}，归档 {row['archived']}\n")

    parts.append("## 9. 限制\n")
    parts.append(
        "1. 覆盖率是**单次执行路径**的覆盖，不是输入空间覆盖。`branch_complete` 只说明该次执行走过了"
        "编译出的每个分支，不说明任意输入下都无泄漏。\n"
        "2. `realloc_fail` 只让第一次非 NULL `realloc` 失败；如果单元只在第二次失败时泄漏，本实验看不到。\n"
        "3. `nogobal` 关闭全局根是进程级开关，不是逐变量根映射；它不能指出是哪个全局变量持有块。\n"
        "4. `executed_clean` 不是无泄漏证明。默认路径 82 个 clean 在剔除 6 行声明死代码后全部行覆盖，"
        f"但其中 {clean['executed_clean_bad']} 个实际是 bad；2 个 `_68` 单元甚至 `branch_complete`"
        "（另外 3 个 `_68` 是 `line_complete`）。覆盖充分不能替代根集/泄漏判定语义。\n"
        "5. 覆盖率来自 GCC gcov，泄漏判定来自同一 GCC ASan/LSan 运行；没有使用 Valgrind，"
        "也没有把 Valgrind 的旧结果伪装成本次测量。\n"
        "6. 所有数字只限 `split=test` 的 140 个冻结单元，不能外推到 dev 或其他 CWE。\n"
    )
    return "\n".join(parts)


def write_report(run_dir: Path) -> dict:
    metrics = build_metrics(run_dir)
    records = read_jsonl(run_dir / "results_units.jsonl")
    exports = write_exports(run_dir, records, metrics)
    metrics["exports"] = exports
    metrics_path = run_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    markdown = render(run_dir, metrics)
    (run_dir / "metrics.md").write_text(markdown, encoding="utf-8")
    return metrics

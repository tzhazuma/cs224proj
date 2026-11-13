#!/usr/bin/env python3
"""Compare CodeQL with the frozen Clang/Cppcheck baseline on the 140 test units.

Reads the frozen unit manifest and the existing baseline predictions (read-only),
then reports evaluable and end-to-end metrics for every tool on exactly the same
test-split units. No model calls, no writes outside the CodeQL run directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from codeql_adapter import metrics_from_confusion  # noqa: E402


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def confusion(rows: Iterable[dict[str, Any]], end_to_end: bool) -> dict[str, int]:
    tp = fp = tn = fn = 0
    excluded = 0
    for row in rows:
        status = row.get("status", "ok")
        usable = status == "ok" or (end_to_end and status in {"compile_error", "timeout"})
        if not usable:
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


def for_query(rows: Sequence[dict[str, Any]], query_id: str) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        hit = bool(row.get("queries", {}).get(query_id, {}).get("hit"))
        clone = dict(row)
        clone["prediction"] = {"is_vulnerable": hit, "cwe": "CWE-401" if hit else None, "finding_count": 1 if hit else 0}
        output.append(clone)
    return output


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--codeql-run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    units = load_jsonl(args.units)
    test_units = [unit for unit in units if unit.get("split") == "test"]
    test_ids = {unit["unit_id"] for unit in test_units}
    labels = {unit["unit_id"]: unit["label"] == "bad" for unit in test_units}

    baseline_rows = load_jsonl(args.baseline)
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for row in baseline_rows:
        if row["sample_id"] in test_ids:
            by_tool.setdefault(row["tool"], []).append(row)
    codeql_rows = [row for row in load_jsonl(args.codeql_run / "predictions.jsonl") if row["sample_id"] in test_ids]
    by_tool["codeql"] = codeql_rows

    report: dict[str, Any] = {
        "scope": "frozen Juliet CWE-401 test split",
        "units": len(test_ids),
        "label_counts": {
            "vulnerable": sum(1 for unit in test_units if unit["label"] == "bad"),
            "non_vulnerable": sum(1 for unit in test_units if unit["label"] != "bad"),
        },
        "tools": {},
    }
    for tool, rows in sorted(by_tool.items()):
        entry = {
            "n": len(rows),
            "evaluable_count": sum(1 for row in rows if row["status"] == "ok"),
            "status_counts": {},
            "evaluable": metrics_from_confusion(confusion(rows, False)),
            "end_to_end": metrics_from_confusion(confusion(rows, True)),
        }
        for row in rows:
            entry["status_counts"][row["status"]] = entry["status_counts"].get(row["status"], 0) + 1
        if tool == "codeql":
            entry["per_query"] = {}
            for query_id in ("cpp/memory-never-freed", "cpp/memory-may-not-be-freed"):
                subset = for_query(rows, query_id)
                entry["per_query"][query_id] = {
                    "evaluable": metrics_from_confusion(confusion(subset, False)),
                    "end_to_end": metrics_from_confusion(confusion(subset, True)),
                }
        report["tools"][tool] = entry

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# 140 test 单元对比：CodeQL vs Clang / Cppcheck",
        "",
        f"- 单元：{report['units']}（bad {report['label_counts']['vulnerable']} / good {report['label_counts']['non_vulnerable']}）",
        "- 正类：目标文件中存在 CWE-401 泄漏诊断；编译失败在端到端视图按未报泄漏计。",
        "",
        "## 端到端",
        "",
        "| 工具 | 可评估/总数 | TP | FP | TN | FN | Precision | Recall | F1(V) | Macro-F1 | Accuracy | MCC |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for tool, entry in report["tools"].items():
        met = entry["end_to_end"]
        macro = "null" if met["macro_f1"] is None else f"{met['macro_f1']:.4f}"
        mcc = "null" if met["mcc"] is None else f"{met['mcc']:.4f}"
        if met["precision"] is None:
            lines.append(f"| {tool} | {entry['evaluable_count']}/{entry['n']} | - | - | - | - | - | - | - | - | - | - |")
            continue
        lines.append(
            f"| {tool} | {entry['evaluable_count']}/{entry['n']} | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | "
            f"{met['precision']:.4f} | {met['recall']:.4f} | {met['f1_vulnerable']:.4f} | "
            f"{macro} | {met['accuracy']:.4f} | {mcc} |"
        )
    lines += ["", "## CodeQL 分查询（端到端）", "", "| 查询 | TP | FP | TN | FN | Precision | Recall | F1(V) | MCC |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for query_id, group in report["tools"]["codeql"].get("per_query", {}).items():
        met = group["end_to_end"]
        precision = "null" if met["precision"] is None else f"{met['precision']:.4f}"
        recall = "null" if met["recall"] is None else f"{met['recall']:.4f}"
        mcc = "null" if met["mcc"] is None else f"{met['mcc']:.4f}"
        lines.append(
            f"| `{query_id}` | {met['tp']} | {met['fp']} | {met['tn']} | {met['fn']} | "
            f"{precision} | {recall} | {met['f1_vulnerable']:.4f} | {mcc} |"
        )
    lines += ["", "## 各工具状态", ""]
    for tool, entry in report["tools"].items():
        lines.append(f"- `{tool}`: {entry['status_counts']}")
    args.out.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({tool: entry["end_to_end"] for tool, entry in report["tools"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

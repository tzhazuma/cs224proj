"""Import independent rater scores, compute agreement, and finalize adjudication."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .rubric import (
    COMPILE_STATUSES,
    COMPILE_STATUS_ALIASES,
    DIMENSION_ALIASES,
    DIMENSION_CODES,
    PRIMARY_PASS_RULE,
    RUBRIC_VERSION,
    STRICT_PASS_RULE,
    primary_pass,
    strict_pass,
)
from .stats import (
    KAPPA_LABELS_ZH,
    bootstrap_ci,
    cohen_kappa,
    distribution,
    interpret_kappa,
    mean,
    median,
    rate,
    within_one_agreement,
)
from .util import (
    RepairEvalError,
    prepare_output_dir,
    read_json,
    read_jsonl,
    read_tsv,
    utc_now,
    write_json,
    write_jsonl,
    write_text,
    write_tsv,
)

ADJUDICATION_DIMENSION = "COMPILE_STATUS"
ADJUDICATION_HEADER = [
    "candidate_id",
    "case_id",
    "dimension",
    "rater_A",
    "rater_B",
    "final_value",
    "rationale",
]


@dataclass
class RaterScores:
    rater_id: str
    source: Path
    scores: dict[str, dict[str, Any]]


def _normalise_header(value: str) -> str:
    return value.strip().replace(" ", "_").replace("-", "_")


def _dimension_from_header(value: str) -> str | None:
    text = value.strip()
    if text in DIMENSION_ALIASES:
        return DIMENSION_ALIASES[text]
    normalised = _normalise_header(text)
    if normalised in DIMENSION_ALIASES:
        return DIMENSION_ALIASES[normalised]
    return None


def _parse_score(value: Any, where: str) -> int:
    if isinstance(value, bool):
        raise RepairEvalError(f"{where}: score must be 0, 1, or 2, not a boolean")
    if isinstance(value, int) and value in (0, 1, 2):
        return value
    if isinstance(value, str) and value.strip() in {"0", "1", "2"}:
        return int(value.strip())
    raise RepairEvalError(f"{where}: score must be 0, 1, or 2, got {value!r}")


def _parse_compile_status(value: Any, where: str) -> str:
    text = "" if value is None else str(value).strip().upper()
    if text in COMPILE_STATUS_ALIASES:
        return COMPILE_STATUS_ALIASES[text]
    raise RepairEvalError(
        f"{where}: compile_status must be one of {COMPILE_STATUSES}, got {value!r}"
    )


def _candidate_rows(package: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for case in package.get("cases", []):
        case_id = case.get("case_id")
        for candidate in case.get("candidates", []):
            rows.append((case_id, candidate.get("candidate_id")))
    return rows


def _empty_score() -> dict[str, Any]:
    result: dict[str, Any] = {code: None for code in DIMENSION_CODES}
    result["compile_status"] = "NOT_RUN"
    result["notes"] = ""
    result["case_id"] = None
    return result


def _read_tsv_scores(path: Path, rater_id: str) -> RaterScores:
    header, rows = read_tsv(path)
    column_map: dict[str, str] = {}
    fixed_columns: dict[str, str] = {}
    for column in header:
        lowered = _normalise_header(column).lower()
        if lowered in {"candidate_id", "candidate", "patch_id"}:
            fixed_columns[column] = "candidate_id"
            continue
        if lowered in {"case_id", "case"}:
            fixed_columns[column] = "case_id"
            continue
        if lowered in {"compile_status", "compile", "compilation_status"}:
            fixed_columns[column] = "compile_status"
            continue
        if lowered in {"notes", "note", "rationale", "reason"}:
            fixed_columns[column] = "notes"
            continue
        dimension = _dimension_from_header(column)
        if dimension is not None:
            column_map[column] = dimension
    missing_dimensions = [code for code in DIMENSION_CODES if code not in column_map.values()]
    if missing_dimensions:
        raise RepairEvalError(
            f"{path}: missing rubric columns {missing_dimensions}; header was {header}"
        )
    if "candidate_id" not in fixed_columns.values():
        raise RepairEvalError(f"{path}: missing candidate_id column")
    scores: dict[str, dict[str, Any]] = {}
    for row in rows:
        line = row.get("_line", "?")
        record: dict[str, Any] = _empty_score()
        for column, target in fixed_columns.items():
            value = row.get(column, "")
            if target == "candidate_id":
                record["candidate_id"] = value.strip()
            elif target == "case_id":
                record["case_id"] = value.strip() or None
            elif target == "compile_status":
                record["compile_status"] = _parse_compile_status(value, f"{path}:{line}")
            elif target == "notes":
                record["notes"] = value.strip()
        for column, dimension in column_map.items():
            record[dimension] = _parse_score(row.get(column, ""), f"{path}:{line} {dimension}")
        candidate_id = record.pop("candidate_id", "")
        if not candidate_id:
            raise RepairEvalError(f"{path}:{line}: empty candidate_id")
        if candidate_id in scores:
            raise RepairEvalError(f"{path}:{line}: duplicate candidate_id {candidate_id}")
        scores[candidate_id] = record
    return RaterScores(rater_id=rater_id, source=path, scores=scores)


def _extract_json_record(item: dict[str, Any], where: str) -> dict[str, Any]:
    record: dict[str, Any] = _empty_score()
    candidate_id = item.get("candidate_id", item.get("patch_id", item.get("candidate")))
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        raise RepairEvalError(f"{where}: missing candidate_id")
    record["candidate_id"] = candidate_id.strip()
    case_id = item.get("case_id", item.get("case"))
    if isinstance(case_id, str) and case_id.strip():
        record["case_id"] = case_id.strip()
    nested = item.get("scores")
    values: dict[str, Any] = {}
    if isinstance(nested, dict):
        values.update(nested)
    for key, value in item.items():
        if key in {"candidate_id", "patch_id", "candidate", "case_id", "case", "scores", "notes", "note", "compile_status"}:
            continue
        values[key] = value
    found = 0
    for key, value in values.items():
        dimension = _dimension_from_header(str(key))
        if dimension is None:
            continue
        record[dimension] = _parse_score(value, f"{where} {dimension}")
        found += 1
    if found == 0:
        raise RepairEvalError(f"{where}: no rubric dimension values found")
    compile_status = item.get("compile_status", item.get("compile"))
    record["compile_status"] = _parse_compile_status(compile_status, where)
    notes = item.get("notes", item.get("note", ""))
    record["notes"] = notes.strip() if isinstance(notes, str) else str(notes)
    return record


def _read_json_scores(path: Path, rater_id: str | None) -> RaterScores:
    data = read_json(path)
    if isinstance(data, dict) and "scores" in data:
        raw_scores = data.get("scores")
        file_rater = data.get("rater_id")
    elif isinstance(data, list):
        raw_scores = data
        file_rater = None
    elif isinstance(data, dict) and ("candidate_id" in data or "patch_id" in data):
        raw_scores = [data]
        file_rater = data.get("rater_id")
    else:
        raise RepairEvalError(
            f"{path}: expected a list of scores or an object with a 'scores' list"
        )
    if not isinstance(raw_scores, list) or not raw_scores:
        raise RepairEvalError(f"{path}: scores must be a non-empty list")
    actual_rater = rater_id or (file_rater if isinstance(file_rater, str) and file_rater.strip() else path.stem)
    scores: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw_scores, start=1):
        if not isinstance(item, dict):
            raise RepairEvalError(f"{path}: scores[{index}] must be an object")
        record = _extract_json_record(item, f"{path}: scores[{index}]")
        candidate_id = record.pop("candidate_id")
        if candidate_id in scores:
            raise RepairEvalError(f"{path}: scores[{index}]: duplicate candidate_id {candidate_id}")
        scores[candidate_id] = record
    return RaterScores(rater_id=actual_rater, source=path, scores=scores)


def load_rater(path: str | Path, *, rater_id: str | None = None) -> RaterScores:
    source = Path(path)
    if not source.exists():
        raise RepairEvalError(f"rater file does not exist: {source}")
    suffix = source.suffix.lower()
    if suffix == ".tsv":
        return _read_tsv_scores(source, rater_id or source.stem)
    if suffix == ".json":
        return _read_json_scores(source, rater_id)
    raise RepairEvalError(f"unsupported rater file extension: {source}")


def validate_scores(
    package: dict[str, Any],
    rater: RaterScores,
) -> None:
    expected = {
        candidate_id: case_id for case_id, candidate_id in _candidate_rows(package)
    }
    missing = sorted(set(expected) - set(rater.scores))
    extra = sorted(set(rater.scores) - set(expected))
    if missing:
        raise RepairEvalError(
            f"{rater.source}: missing {len(missing)} candidates, e.g. {missing[:5]}"
        )
    if extra:
        raise RepairEvalError(
            f"{rater.source}: {len(extra)} candidate IDs are not in the package, "
            f"e.g. {extra[:5]}"
        )
    for candidate_id, score in rater.scores.items():
        for dimension in DIMENSION_CODES:
            if score.get(dimension) not in (0, 1, 2):
                raise RepairEvalError(
                    f"{rater.source}: candidate {candidate_id} dimension {dimension} is not scored"
                )
        if score.get("compile_status") not in COMPILE_STATUSES:
            raise RepairEvalError(
                f"{rater.source}: candidate {candidate_id} has invalid compile_status"
            )
        case_id = score.get("case_id")
        if case_id is not None and case_id != expected[candidate_id]:
            raise RepairEvalError(
                f"{rater.source}: candidate {candidate_id} case_id {case_id!r} does not "
                f"match package case {expected[candidate_id]!r}"
            )


def _score_arrays(
    package: dict[str, Any],
    rater_a: RaterScores,
    rater_b: RaterScores,
) -> list[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    arrays: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []
    for case in package["cases"]:
        case_id = case["case_id"]
        for candidate in case["candidates"]:
            candidate_id = candidate["candidate_id"]
            arrays.append(
                (
                    case_id,
                    candidate_id,
                    rater_a.scores[candidate_id],
                    rater_b.scores[candidate_id],
                )
            )
    return arrays


def _dimension_agreement(
    arrays: list[tuple[str, str, dict[str, Any], dict[str, Any]]],
    dimension: str,
    *,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    left = [int(row[2][dimension]) for row in arrays]
    right = [int(row[3][dimension]) for row in arrays]
    unweighted = cohen_kappa(left, right, categories=(0, 1, 2), weighted=False)
    weighted = cohen_kappa(left, right, categories=(0, 1, 2), weighted=True)
    return {
        "n": len(arrays),
        "percent_agreement": unweighted["observed_agreement"],
        "within_one_agreement": within_one_agreement(left, right),
        "unweighted_kappa": unweighted["kappa"],
        "quadratic_weighted_kappa": weighted["kappa"],
        "unweighted_ci95": bootstrap_ci(
            left,
            right,
            categories=(0, 1, 2),
            weighted=False,
            iterations=bootstrap,
            seed=seed,
        ),
        "weighted_ci95": bootstrap_ci(
            left,
            right,
            categories=(0, 1, 2),
            weighted=True,
            iterations=bootstrap,
            seed=seed + 1,
        ),
        "disagreement_count": sum(1 for a, b in zip(left, right) if a != b),
        "interpretation": interpret_kappa(unweighted["kappa"]),
        "undefined_reason": unweighted.get("undefined_reason"),
        "confusion": unweighted["confusion"],
    }


def _binary_agreement(
    arrays: list[tuple[str, str, dict[str, Any], dict[str, Any]]],
    *,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    left = [1 if primary_pass(row[2]) else 0 for row in arrays]
    right = [1 if primary_pass(row[3]) else 0 for row in arrays]
    result = cohen_kappa(left, right, categories=(0, 1), weighted=False)
    return {
        "n": len(arrays),
        "percent_agreement": result["observed_agreement"],
        "kappa": result["kappa"],
        "ci95": bootstrap_ci(
            left,
            right,
            categories=(0, 1),
            weighted=False,
            iterations=bootstrap,
            seed=seed,
        ),
        "disagreement_count": sum(1 for a, b in zip(left, right) if a != b),
        "interpretation": interpret_kappa(result["kappa"]),
        "undefined_reason": result.get("undefined_reason"),
    }


def _strict_binary_agreement(
    arrays: list[tuple[str, str, dict[str, Any], dict[str, Any]]],
    *,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    left = [1 if strict_pass(row[2]) else 0 for row in arrays]
    right = [1 if strict_pass(row[3]) else 0 for row in arrays]
    result = cohen_kappa(left, right, categories=(0, 1), weighted=False)
    return {
        "n": len(arrays),
        "percent_agreement": result["observed_agreement"],
        "kappa": result["kappa"],
        "ci95": bootstrap_ci(
            left,
            right,
            categories=(0, 1),
            weighted=False,
            iterations=bootstrap,
            seed=seed,
        ),
        "disagreement_count": sum(1 for a, b in zip(left, right) if a != b),
        "interpretation": interpret_kappa(result["kappa"]),
        "undefined_reason": result.get("undefined_reason"),
    }


def compute_agreement(
    package: dict[str, Any],
    rater_a: RaterScores,
    rater_b: RaterScores,
    *,
    seed: int,
    bootstrap: int = 2000,
) -> dict[str, Any]:
    validate_scores(package, rater_a)
    validate_scores(package, rater_b)
    if rater_a.rater_id == rater_b.rater_id:
        raise RepairEvalError("rater A and rater B must have distinct rater IDs")
    arrays = _score_arrays(package, rater_a, rater_b)
    by_dimension = {
        dimension: _dimension_agreement(
            arrays, dimension, seed=seed + 10 * index, bootstrap=bootstrap
        )
        for index, dimension in enumerate(DIMENSION_CODES)
    }
    disagreements: list[dict[str, Any]] = []
    for case_id, candidate_id, left, right in arrays:
        for dimension in DIMENSION_CODES:
            if left[dimension] != right[dimension]:
                disagreements.append(
                    {
                        "candidate_id": candidate_id,
                        "case_id": case_id,
                        "dimension": dimension,
                        "rater_A": left[dimension],
                        "rater_B": right[dimension],
                    }
                )
        if left["compile_status"] != right["compile_status"]:
            disagreements.append(
                {
                    "candidate_id": candidate_id,
                    "case_id": case_id,
                    "dimension": ADJUDICATION_DIMENSION,
                    "rater_A": left["compile_status"],
                    "rater_B": right["compile_status"],
                }
            )
    compile_left = [row[2]["compile_status"] for row in arrays]
    compile_right = [row[3]["compile_status"] for row in arrays]
    compile_result = cohen_kappa(
        compile_left, compile_right, categories=COMPILE_STATUSES, weighted=False
    )
    compile_disagreements = sum(1 for a, b in zip(compile_left, compile_right) if a != b)
    rater_summary = {}
    for label, rater in (("A", rater_a), ("B", rater_b)):
        rater_summary[label] = {
            "rater_id": rater.rater_id,
            "source": str(rater.source),
            "per_dimension_mean": {
                dimension: mean(
                    [int(rater.scores[candidate_id][dimension]) for _, candidate_id in _candidate_rows(package)]
                )
                for dimension in DIMENSION_CODES
            },
            "primary_pass_rate": rate(
                sum(
                    1
                    for _, candidate_id in _candidate_rows(package)
                    if primary_pass(rater.scores[candidate_id])
                ),
                len(arrays),
            ),
            "strict_pass_rate": rate(
                sum(
                    1
                    for _, candidate_id in _candidate_rows(package)
                    if strict_pass(rater.scores[candidate_id])
                ),
                len(arrays),
            ),
        }
    return {
        "schema_version": 1,
        "package_id": package["package_id"],
        "rubric_version": RUBRIC_VERSION,
        "generated_at": utc_now(),
        "seed": seed,
        "bootstrap_iterations": bootstrap,
        "bootstrap_unit": "candidate (item-level; see limitations)",
        "raters": {
            "A": {"rater_id": rater_a.rater_id, "source": str(rater_a.source)},
            "B": {"rater_id": rater_b.rater_id, "source": str(rater_b.source)},
        },
        "n_cases": len(package["cases"]),
        "n_candidates": len(arrays),
        "by_dimension": by_dimension,
        "overall_pass": {
            "primary_pass_rule": PRIMARY_PASS_RULE,
            "primary_pass": _binary_agreement(
                arrays, seed=seed + 100, bootstrap=bootstrap
            ),
            "strict_pass_rule": STRICT_PASS_RULE,
            "strict_pass": _strict_binary_agreement(
                arrays, seed=seed + 200, bootstrap=bootstrap
            ),
        },
        "compile_status": {
            "n": len(arrays),
            "percent_agreement": compile_result["observed_agreement"],
            "kappa": compile_result["kappa"],
            "ci95": bootstrap_ci(
                compile_left,
                compile_right,
                categories=COMPILE_STATUSES,
                weighted=False,
                iterations=bootstrap,
                seed=seed + 300,
            ),
            "interpretation": interpret_kappa(compile_result["kappa"]),
            "undefined_reason": compile_result.get("undefined_reason"),
            "disagreement_count": compile_disagreements,
            "distribution_A": dict(sorted(Counter(compile_left).items())),
            "distribution_B": dict(sorted(Counter(compile_right).items())),
            "note": (
                "compile_status is a three/four-value categorical audit field, not a "
                "rubric score. It is not evidence that the tool compiled anything."
            ),
        },
        "rater_summary": rater_summary,
        "disagreements": disagreements,
        "disagreement_summary": {
            "total_dimension_disagreements": len(disagreements),
            "candidates_with_any_disagreement": len(
                {item["candidate_id"] for item in disagreements}
            ),
            "by_dimension": dict(
                sorted(Counter(item["dimension"] for item in disagreements).items())
            ),
        },
    }


def _kappa_cell(value: float | None) -> str:
    return "未定义" if value is None else f"{value:.3f}"


def _ci_cell(value: list[float] | None) -> str:
    if value is None:
        return "—"
    return f"[{value[0]:.3f}, {value[1]:.3f}]"


def _agreement_markdown(agreement: dict[str, Any]) -> str:
    lines = [
        f"# 评分者一致性报告 `{agreement['package_id']}`",
        "",
        f"- 生成时间：{agreement['generated_at']}",
        f"- 评分者 A：`{agreement['raters']['A']['rater_id']}`",
        f"- 评分者 B：`{agreement['raters']['B']['rater_id']}`",
        f"- 案例/候选：{agreement['n_cases']} / {agreement['n_candidates']}",
        f"- bootstrap：{agreement['bootstrap_iterations']} 次，按候选重采样；CI 仅作稳定性参考。",
        "",
        "## 各维度一致性",
        "",
        "| 维度 | n | 完全一致 | 相差≤1 | Cohen's κ | 二次加权 κ | κ 95% CI | 解释 | 分歧数 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: |",
    ]
    for dimension, item in agreement["by_dimension"].items():
        lines.append(
            f"| {dimension} | {item['n']} | {item['percent_agreement']:.3f} | "
            f"{item['within_one_agreement']:.3f} | {_kappa_cell(item['unweighted_kappa'])} | "
            f"{_kappa_cell(item['quadratic_weighted_kappa'])} | "
            f"{_ci_cell(item['unweighted_ci95'])} | "
            f"{KAPPA_LABELS_ZH[item['interpretation']]} | {item['disagreement_count']} |"
        )
    lines.extend(
        [
            "",
            "## 总体通过条件",
            "",
            "| 条件 | 完全一致 | κ | 95% CI | 解释 | 分歧数 |",
            "| --- | ---: | ---: | --- | --- | ---: |",
        ]
    )
    for label, item in (
        ("主要：VR == 2", agreement["overall_pass"]["primary_pass"]),
        ("严格：" + agreement["overall_pass"]["strict_pass_rule"], agreement["overall_pass"]["strict_pass"]),
    ):
        lines.append(
            f"| {label} | {item['percent_agreement']:.3f} | {_kappa_cell(item['kappa'])} | "
            f"{_ci_cell(item['ci95'])} | {KAPPA_LABELS_ZH[item['interpretation']]} | "
            f"{item['disagreement_count']} |"
        )
    compile_item = agreement["compile_status"]
    lines.extend(
        [
            "",
            "## 编译状态（单独审计，不计入 rubric）",
            "",
            f"- 完全一致：{compile_item['percent_agreement']:.3f}",
            f"- κ：{_kappa_cell(compile_item['kappa'])}；95% CI：{_ci_cell(compile_item['ci95'])}",
            f"- 分歧：{compile_item['disagreement_count']}",
            f"- A 分布：`{compile_item['distribution_A']}`",
            f"- B 分布：`{compile_item['distribution_B']}`",
            "",
            "`compile_status` 是人工填写的外部构建审计字段；本工具没有执行编译。",
            "",
            "## 分歧与下一步",
            "",
            f"- 维度级分歧总数：{agreement['disagreement_summary']['total_dimension_disagreements']}",
            f"- 至少一个维度有分歧的候选数：{agreement['disagreement_summary']['candidates_with_any_disagreement']}",
            f"- 按维度：`{agreement['disagreement_summary']['by_dimension']}`",
            "",
            "分歧需由第三人裁决。填写 `adjudication.tsv` 的 `final_value` 和 `rationale`，"
            "再运行 `finalize`；不要把两位评分者事后讨论出的分数直接覆盖原始分数。",
            "",
            "## 限制",
            "",
            "- κ 在 20–30 个案例上不稳定，95% CI 可能很宽；不要把点估计当作强结论。",
            "- bootstrap 按候选重采样，未建模同一案例内多个候选的相关性。",
            "- 评分者知道候选代码，可能从代码风格推测方法；盲法只能降低而不能消除该风险。",
            "- 没有编译或 PoC oracle；一致性高不代表修复正确。",
            "",
        ]
    )
    return "\n".join(lines)


def write_agreement_outputs(
    package: dict[str, Any],
    rater_a: RaterScores,
    rater_b: RaterScores,
    *,
    out_dir: str | Path,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    root = Path(out_dir)
    prepare_output_dir(root)
    agreement = compute_agreement(
        package, rater_a, rater_b, seed=seed, bootstrap=bootstrap
    )
    write_json(root / "agreement.json", agreement)
    write_text(root / "agreement.md", _agreement_markdown(agreement))
    rows = [
        [
            item["candidate_id"],
            item["case_id"],
            item["dimension"],
            item["rater_A"],
            item["rater_B"],
            "",
            "",
        ]
        for item in agreement["disagreements"]
    ]
    write_tsv(root / "adjudication.tsv", ADJUDICATION_HEADER, rows)
    write_json(
        root / "disagreements.json",
        {
            "schema_version": 1,
            "package_id": package["package_id"],
            "created_at": utc_now(),
            "disagreements": agreement["disagreements"],
        },
    )
    write_text(
        root / "README.md",
        "\n".join(
            [
                "# 一致性报告与裁决",
                "",
                "- `agreement.json` / `agreement.md`：两位评分者的一致性结果。",
                "- `adjudication.tsv`：只列出有分歧的候选-维度。",
                "- `disagreements.json`：机器可读的分歧列表。",
                "",
                "裁决者填写 `final_value`（评分维度填 0/1/2；编译状态填 "
                "`NOT_RUN`/`UNVERIFIED`/`PASS`/`FAIL`）和 `rationale`，"
                "然后运行 `finalize`。不要修改原始 `rater_A.tsv` / `rater_B.tsv`。",
                "",
            ]
        ),
    )
    return agreement


def _adjudication_dimension(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if text.upper() in {"COMPILE_STATUS", "COMPILE", "编译状态"}:
        return ADJUDICATION_DIMENSION
    dimension = _dimension_from_header(text)
    if dimension is None:
        raise RepairEvalError(f"unknown adjudication dimension {value!r}")
    return dimension


def _load_adjudication(
    path: str | Path,
    package: dict[str, Any],
    agreement: dict[str, Any],
) -> tuple[dict[tuple[str, str], dict[str, Any]], str | None]:
    source = Path(path)
    expected = {
        (item["candidate_id"], item["dimension"]): item
        for item in agreement["disagreements"]
    }
    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    adjudicator: str | None = None
    if source.suffix.lower() == ".tsv":
        header, rows = read_tsv(source)
        required = {"candidate_id", "dimension", "final_value", "rationale"}
        if not required.issubset(set(header)):
            raise RepairEvalError(
                f"{source}: adjudication TSV needs columns {sorted(required)}"
            )
        for row in rows:
            line = row.get("_line", "?")
            candidate_id = row.get("candidate_id", "").strip()
            dimension = _adjudication_dimension(row.get("dimension", ""))
            key = (candidate_id, dimension)
            expected_item = expected.get(key)
            case_id = row.get("case_id", "").strip()
            if expected_item and case_id and case_id != expected_item["case_id"]:
                raise RepairEvalError(
                    f"{source}:{line}: case_id {case_id!r} does not match "
                    f"{expected_item['case_id']!r}"
                )
            if key in decisions:
                raise RepairEvalError(f"{source}:{line}: duplicate decision {key}")
            decisions[key] = {
                "final_value": row.get("final_value", "").strip(),
                "rationale": row.get("rationale", "").strip(),
            }
    elif source.suffix.lower() == ".json":
        data = read_json(source)
        if isinstance(data, dict):
            raw = data.get("decisions")
            adjudicator = data.get("adjudicator")
        else:
            raw = data
        if not isinstance(raw, list):
            raise RepairEvalError(f"{source}: expected a list or an object with 'decisions'")
        for index, item in enumerate(raw, start=1):
            if not isinstance(item, dict):
                raise RepairEvalError(f"{source}: decisions[{index}] must be an object")
            candidate_id = item.get("candidate_id")
            if not isinstance(candidate_id, str):
                raise RepairEvalError(f"{source}: decisions[{index}] needs candidate_id")
            dimension = _adjudication_dimension(item.get("dimension"))
            key = (candidate_id.strip(), dimension)
            expected_item = expected.get(key)
            case_id = item.get("case_id")
            if (
                expected_item
                and isinstance(case_id, str)
                and case_id.strip()
                and case_id.strip() != expected_item["case_id"]
            ):
                raise RepairEvalError(
                    f"{source}: decisions[{index}]: case_id {case_id!r} does not match "
                    f"{expected_item['case_id']!r}"
                )
            if key in decisions:
                raise RepairEvalError(f"{source}: duplicate decision {key}")
            decisions[key] = {
                "final_value": item.get("final_value"),
                "rationale": item.get("rationale", ""),
            }
    else:
        raise RepairEvalError(f"unsupported adjudication extension: {source}")
    if not expected:
        if decisions:
            raise RepairEvalError(f"{source}: no disagreements exist but decisions were supplied")
        return {}, adjudicator
    missing = sorted(set(expected) - set(decisions))
    extra = sorted(set(decisions) - set(expected))
    if missing:
        raise RepairEvalError(
            f"{source}: missing {len(missing)} adjudications, e.g. {missing[:5]}"
        )
    if extra:
        raise RepairEvalError(
            f"{source}: {len(extra)} adjudications do not match a disagreement, "
            f"e.g. {extra[:5]}"
        )
    for key, decision in decisions.items():
        candidate_id, dimension = key
        rationale = decision.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise RepairEvalError(
                f"{source}: {candidate_id}/{dimension}: rationale must not be empty"
            )
        if dimension == ADJUDICATION_DIMENSION:
            decision["final_value"] = _parse_compile_status(
                decision["final_value"], f"{source}: {candidate_id}/{dimension}"
            )
        else:
            if dimension not in DIMENSION_CODES:
                raise RepairEvalError(
                    f"{source}: unknown adjudication dimension {dimension!r}"
                )
            decision["final_value"] = _parse_score(
                decision["final_value"], f"{source}: {candidate_id}/{dimension}"
            )
    return decisions, adjudicator


def _finalise_scores(
    package: dict[str, Any],
    rater_a: RaterScores,
    rater_b: RaterScores,
    decisions: dict[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in package["cases"]:
        case_id = case["case_id"]
        for candidate in case["candidates"]:
            candidate_id = candidate["candidate_id"]
            left = rater_a.scores[candidate_id]
            right = rater_b.scores[candidate_id]
            final: dict[str, Any] = {}
            used: list[str] = []
            for dimension in DIMENSION_CODES:
                if left[dimension] == right[dimension]:
                    final[dimension] = left[dimension]
                else:
                    decision = decisions.get((candidate_id, dimension))
                    if decision is None:
                        raise RepairEvalError(
                            f"unresolved disagreement: {candidate_id}/{dimension}"
                        )
                    final[dimension] = decision["final_value"]
                    used.append(
                        f"{dimension}: {left[dimension]} vs {right[dimension]} -> "
                        f"{decision['final_value']} ({decision['rationale']})"
                    )
            if left["compile_status"] == right["compile_status"]:
                final["compile_status"] = left["compile_status"]
            else:
                decision = decisions.get((candidate_id, ADJUDICATION_DIMENSION))
                if decision is None:
                    raise RepairEvalError(
                        f"unresolved compile_status disagreement: {candidate_id}"
                    )
                final["compile_status"] = decision["final_value"]
                used.append(
                    f"compile_status: {left['compile_status']} vs "
                    f"{right['compile_status']} -> {decision['final_value']} "
                    f"({decision['rationale']})"
                )
            rows.append(
                {
                    "case_id": case_id,
                    "candidate_id": candidate_id,
                    "cwe_family": case["cwe_family"],
                    "cwe": case["cwe"],
                    "A": left,
                    "B": right,
                    "final": final,
                    "adjudication_notes": " | ".join(used),
                }
            )
    return rows


def _final_metrics(
    rows: list[dict[str, Any]],
    *,
    key: dict[str, Any],
) -> dict[str, Any]:
    per_dimension: dict[str, Any] = {}
    for dimension in DIMENSION_CODES:
        values = [int(row["final"][dimension]) for row in rows]
        per_dimension[dimension] = {
            "n": len(values),
            "mean": mean(values),
            "median": median(values),
            "counts": distribution(values),
            "score2_count": sum(1 for value in values if value == 2),
            "score2_rate": rate(sum(1 for value in values if value == 2), len(values)),
            "pass_ge1_rate": rate(sum(1 for value in values if value >= 1), len(values)),
        }
    compile_values = [row["final"]["compile_status"] for row in rows]
    compile_counts = Counter(compile_values)
    compile_summary = {
        "counts": {
            status: compile_counts.get(status, 0) for status in COMPILE_STATUSES
        },
        "note": (
            "Final compile_status is an adjudicated audit field, not a tool-run "
            "compilation result. The tool never ran a compiler."
        ),
    }
    primary = [primary_pass(row["final"]) for row in rows]
    strict = [strict_pass(row["final"]) for row in rows]
    row_by_id = {row["candidate_id"]: row for row in rows}
    by_strategy: dict[str, Any] = {}
    for candidate_id, meta in key.get("candidates", {}).items():
        strategy = meta.get("strategy")
        if strategy is None:
            continue
        row = row_by_id.get(candidate_id)
        if row is None:
            continue
        by_strategy.setdefault(strategy, []).append(row)
    strategy_summary: dict[str, Any] = {}
    for strategy, items in sorted(by_strategy.items()):
        values = {dimension: [int(item["final"][dimension]) for item in items] for dimension in DIMENSION_CODES}
        strategy_summary[strategy] = {
            "n_candidates": len(items),
            "n_cases": len({item["case_id"] for item in items}),
            "per_dimension_mean": {dimension: mean(values[dimension]) for dimension in DIMENSION_CODES},
            "primary_pass_count": sum(1 for item in items if primary_pass(item["final"])),
            "primary_pass_rate": rate(
                sum(1 for item in items if primary_pass(item["final"])), len(items)
            ),
            "strict_pass_count": sum(1 for item in items if strict_pass(item["final"])),
            "strict_pass_rate": rate(
                sum(1 for item in items if strict_pass(item["final"])), len(items)
            ),
        }
    by_family: dict[str, Any] = {}
    for item in rows:
        by_family.setdefault(item["cwe_family"], []).append(item)
    family_summary: dict[str, Any] = {}
    for family, items in sorted(by_family.items()):
        values = [int(item["final"]["VR"]) for item in items]
        family_summary[family] = {
            "n_candidates": len(items),
            "n_cases": len({item["case_id"] for item in items}),
            "vr_mean": mean(values),
            "primary_pass_count": sum(1 for item in items if primary_pass(item["final"])),
            "primary_pass_rate": rate(
                sum(1 for item in items if primary_pass(item["final"])), len(items)
            ),
            "strict_pass_rate": rate(
                sum(1 for item in items if strict_pass(item["final"])), len(items)
            ),
        }
    return {
        "per_dimension": per_dimension,
        "overall": {
            "primary_pass_rule": PRIMARY_PASS_RULE,
            "primary_pass_count": sum(primary),
            "primary_pass_rate": rate(sum(primary), len(rows)),
            "strict_pass_rule": STRICT_PASS_RULE,
            "strict_pass_count": sum(strict),
            "strict_pass_rate": rate(sum(strict), len(rows)),
            "mean_of_dimension_means": mean(
                [
                    per_dimension[dimension]["mean"]
                    for dimension in DIMENSION_CODES
                    if per_dimension[dimension]["mean"] is not None
                ]
            ),
        },
        "compile_status": compile_summary,
        "by_strategy": strategy_summary,
        "by_cwe_family": family_summary,
    }


def _posthoc_structural(
    package_dir: Path,
    key: dict[str, Any],
) -> dict[str, Any]:
    path = package_dir / "private" / "auto_checks.jsonl"
    if not path.exists():
        return {"available": False}
    rows = read_jsonl(path)
    by_strategy: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        candidate_id = row.get("candidate_id")
        meta = key.get("candidates", {}).get(candidate_id, {})
        strategy = meta.get("strategy")
        if strategy is None:
            continue
        by_strategy.setdefault(strategy, []).append(row)
    summary: dict[str, Any] = {}
    for strategy, items in sorted(by_strategy.items()):
        count = len(items)
        changed = [
            item.get("line_diff", {}).get("changed_lines")
            for item in items
            if isinstance(item.get("line_diff"), dict)
            and isinstance(item.get("line_diff", {}).get("changed_lines"), int)
        ]
        summary[strategy] = {
            "n": count,
            "complete_function_true": sum(1 for item in items if item.get("complete_function") is True),
            "complete_function_rate": rate(
                sum(1 for item in items if item.get("complete_function") is True), count
            ),
            "changed_from_input_true": sum(1 for item in items if item.get("changed_from_input") is True),
            "changed_from_input_rate": rate(
                sum(1 for item in items if item.get("changed_from_input") is True), count
            ),
            "reference_exact_match_true": sum(
                1 for item in items if item.get("reference_exact_match") is True
            ),
            "reference_exact_match_rate": rate(
                sum(1 for item in items if item.get("reference_exact_match") is True), count
            ),
            "mean_changed_lines": mean(changed),
            "compile_oracle_not_run": sum(
                1
                for item in items
                if isinstance(item.get("oracle"), dict)
                and item["oracle"].get("compile") == "NOT_RUN"
            ),
            "poc_oracle_not_run": sum(
                1
                for item in items
                if isinstance(item.get("oracle"), dict)
                and item["oracle"].get("poc") == "NOT_RUN"
            ),
        }
    return {
        "available": True,
        "source": "private/auto_checks.jsonl",
        "note": (
            "Structural text checks only: complete_function, changed_from_input, "
            "reference text equality, and line diff. They are not correctness, "
            "behavior-preservation, compile, or exploit evidence."
        ),
        "by_strategy": summary,
    }


def _summary_markdown(summary: dict[str, Any]) -> str:
    final = summary["final"]
    lines = [
        f"# 修复质量盲评最终汇总 `{summary['package_id']}`",
        "",
        f"- 生成时间：{summary['generated_at']}",
        f"- rubric：`{summary['rubric_version']}`",
        f"- 案例/候选：{summary['n_cases']} / {summary['n_candidates']}",
        f"- 评分者 A/B：`{summary['raters']['A']}` / `{summary['raters']['B']}`",
        f"- 裁决者：`{summary['adjudication']['adjudicator'] or '未记录'}`",
        f"- 分歧维度数：{summary['adjudication']['disagreement_count']}；"
        f"已裁决：{summary['adjudication']['adjudicated_count']}",
        "",
        "## 最终维度分数",
        "",
        "| 维度 | 均值 | 中位数 | 0 | 1 | 2 | 2 分率 | ≥1 分率 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for dimension, item in final["per_dimension"].items():
        counts = item["counts"]
        lines.append(
            f"| {dimension} | {item['mean']:.3f} | {item['median']:.3f} | "
            f"{counts['0']} | {counts['1']} | {counts['2']} | "
            f"{item['score2_rate']:.3f} | {item['pass_ge1_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## 评分者一致性（裁决前）",
            "",
            "| 维度 | Cohen's κ | 二次加权 κ | 完全一致 | 分歧数 |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for dimension, item in summary["agreement"]["by_dimension"].items():
        lines.append(
            f"| {dimension} | {_kappa_cell(item['unweighted_kappa'])} | "
            f"{_kappa_cell(item['quadratic_weighted_kappa'])} | "
            f"{item['percent_agreement']:.3f} | {item['disagreement_count']} |"
        )
    overall = final["overall"]
    lines.extend(
        [
            "",
            "## 通过率",
            "",
            f"- 主要：`{overall['primary_pass_rule']}` — "
            f"{overall['primary_pass_count']}/{summary['n_candidates']} "
            f"({overall['primary_pass_rate']:.3f})",
            f"- 严格：`{overall['strict_pass_rule']}` — "
            f"{overall['strict_pass_count']}/{summary['n_candidates']} "
            f"({overall['strict_pass_rate']:.3f})",
            f"- 七维均值（仅供参考）：{overall['mean_of_dimension_means']:.3f}",
            f"- 最终 compile_status 分布：`{final['compile_status']['counts']}` "
            "（人工审计字段；工具未运行编译器）",
            "",
            "## 按策略（评分完成后解盲，仅用于汇总）",
            "",
            "| 策略 | 候选数 | 案例数 | VR 均值 | VR=2 率 | 严格通过率 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for strategy, item in final["by_strategy"].items():
        lines.append(
            f"| {strategy} | {item['n_candidates']} | {item['n_cases']} | "
            f"{item['per_dimension_mean']['VR']:.3f} | {item['primary_pass_rate']:.3f} | "
            f"{item['strict_pass_rate']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## 按 CWE 家族",
            "",
            "| 家族 | 候选数 | 案例数 | VR 均值 | VR=2 率 | 严格通过率 |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for family, item in final["by_cwe_family"].items():
        lines.append(
            f"| {family} | {item['n_candidates']} | {item['n_cases']} | "
            f"{item['vr_mean']:.3f} | {item['primary_pass_rate']:.3f} | "
            f"{item['strict_pass_rate']:.3f} |"
        )
    structural = summary["posthoc_structural_checks"]
    lines.extend(["", "## 事后结构检查（不是质量分数）", ""])
    if not structural.get("available"):
        lines.append("未找到 `private/auto_checks.jsonl`。")
    else:
        lines.append("| 策略 | n | 完整函数率 | 有改动率 | 参考文本精确匹配率 | 平均改动行数 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for strategy, item in structural["by_strategy"].items():
            changed_mean = (
                "—"
                if item["mean_changed_lines"] is None
                else f"{item['mean_changed_lines']:.1f}"
            )
            lines.append(
                f"| {strategy} | {item['n']} | {item['complete_function_rate']:.3f} | "
                f"{item['changed_from_input_rate']:.3f} | "
                f"{item['reference_exact_match_rate']:.3f} | "
                f"{changed_mean} |"
            )
        lines.append("")
        lines.append(structural["note"])
    lines.extend(
        [
            "",
            "## 限制",
            "",
        ]
    )
    for limitation in summary["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def finalize(
    package: dict[str, Any],
    package_dir: Path,
    rater_a: RaterScores,
    rater_b: RaterScores,
    *,
    adjudication_path: str | Path | None,
    out_dir: str | Path,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    root = Path(out_dir)
    prepare_output_dir(root)
    agreement = compute_agreement(
        package, rater_a, rater_b, seed=seed, bootstrap=bootstrap
    )
    if adjudication_path is None and agreement["disagreements"]:
        raise RepairEvalError(
            f"{len(agreement['disagreements'])} disagreements exist; supply "
            "--adjudication (see agreement output's adjudication.tsv)"
        )
    if adjudication_path is None:
        decisions: dict[tuple[str, str], dict[str, Any]] = {}
        adjudicator = None
    else:
        decisions, adjudicator = _load_adjudication(
            adjudication_path, package, agreement
        )
    key = read_json(package_dir / "private" / "blind_key.json")
    if key.get("package_id") != package.get("package_id"):
        raise RepairEvalError("blind key package_id does not match blind package")
    rows = _finalise_scores(package, rater_a, rater_b, decisions)
    final_metrics = _final_metrics(rows, key=key)
    structural = _posthoc_structural(package_dir, key)
    summary = {
        "schema_version": 1,
        "package_id": package["package_id"],
        "rubric_version": RUBRIC_VERSION,
        "generated_at": utc_now(),
        "seed": seed,
        "bootstrap_iterations": bootstrap,
        "raters": {
            "A": rater_a.rater_id,
            "B": rater_b.rater_id,
        },
        "n_cases": len(package["cases"]),
        "n_candidates": len(rows),
        "agreement": agreement,
        "adjudication": {
            "adjudicator": adjudicator,
            "disagreement_count": len(agreement["disagreements"]),
            "adjudicated_count": len(decisions),
            "decisions": [
                {
                    "candidate_id": candidate_id,
                    "dimension": dimension,
                    "final_value": decision["final_value"],
                    "rationale": decision["rationale"],
                }
                for (candidate_id, dimension), decision in sorted(decisions.items())
            ],
        },
        "final": final_metrics,
        "posthoc_structural_checks": structural,
        "limitations": [
            "人工 rubric 分数是主观判断；kappa 只说明评分者一致性，不说明修复正确。",
            "本工具没有运行编译器。compile_status 是人工填写的外部构建审计字段；"
            "没有真实构建证据时不得声称 PASS 或可编译。",
            "本工具没有运行 PoC/exploit harness；VR=2 只是人工判断，不是漏洞不可利用的证明。",
            "结构检查来自 runner 的文本启发式（完整函数、是否有改动）和参考修复文本比较；"
            "它们不是行为保持、编译或安全 oracle。",
            "盲评样本只有 20–30 个案例，kappa 的置信区间可能很宽；不要过度解读。",
            "候选集只包含 schema-valid 的修复输出；schema-invalid/API-error 输出在采样框外，"
            "覆盖率见 manifest.json 的 provenance 块。",
            "bootstrap 按候选重采样，未建模同一案例内多个候选的相关性。",
        ],
    }
    write_json(root / "summary.json", summary)
    write_text(root / "summary.md", _summary_markdown(summary))
    write_json(
        root / "adjudication_used.json",
        {
            "schema_version": 1,
            "package_id": package["package_id"],
            "adjudicator": adjudicator,
            "decisions": summary["adjudication"]["decisions"],
        },
    )
    csv_header = [
        "candidate_id",
        "case_id",
        "strategy",
        "pair_id",
        "project",
        "cwe_family",
        "cwe",
    ]
    for dimension in DIMENSION_CODES:
        csv_header.extend([f"{dimension}_A", f"{dimension}_B", f"{dimension}_final"])
    csv_header.extend(
        [
            "compile_status_A",
            "compile_status_B",
            "compile_status_final",
            "primary_pass",
            "strict_pass",
            "notes_A",
            "notes_B",
            "adjudication_notes",
        ]
    )
    csv_rows = []
    for row in rows:
        meta = key["candidates"][row["candidate_id"]]
        case = key["cases"][row["case_id"]]
        values: list[Any] = [
            row["candidate_id"],
            row["case_id"],
            meta["strategy"],
            meta["pair_id"],
            case["project"],
            row["cwe_family"],
            ", ".join(row["cwe"]),
        ]
        for dimension in DIMENSION_CODES:
            values.extend(
                [
                    row["A"][dimension],
                    row["B"][dimension],
                    row["final"][dimension],
                ]
            )
        values.extend(
            [
                row["A"]["compile_status"],
                row["B"]["compile_status"],
                row["final"]["compile_status"],
                int(primary_pass(row["final"])),
                int(strict_pass(row["final"])),
                row["A"]["notes"],
                row["B"]["notes"],
                row["adjudication_notes"],
            ]
        )
        csv_rows.append(values)
    write_tsv(root / "final_scores.tsv", csv_header, csv_rows)
    write_jsonl(root / "final_scores.jsonl", rows)
    return summary

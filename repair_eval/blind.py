"""Build the blinded human-review package and its private unblinding key."""

from __future__ import annotations

import difflib
import random
import re
import secrets
from collections import Counter
from pathlib import Path
from typing import Any

from .rubric import (
    COMPILE_STATUSES,
    RUBRIC_VERSION,
    dimension_catalog,
    rubric_markdown,
)
from .sampling import (
    CaseInfo,
    DatasetInfo,
    RepairCandidate,
    ResultsFileInfo,
    SamplingResult,
)
from .util import (
    RepairEvalError,
    canonical_json,
    prepare_output_dir,
    read_json,
    read_tsv,
    relative_to,
    salted_id,
    sha256_file,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
    write_text,
    write_tsv,
)

RATER_HEADER = [
    "candidate_id",
    "case_id",
    "VR",
    "SP",
    "MIN",
    "COM",
    "CQ",
    "EF",
    "NS",
    "compile_status",
    "notes",
]

FORBIDDEN_BLIND_KEYS = {
    "strategy",
    "model",
    "pair_id",
    "sample_id",
    "unit_id",
    "idx",
    "label",
    "is_vulnerable",
    "fixed_func_idx",
    "validation",
    "exact_match_reference_fixed",
    "whitespace_collapsed_match_reference_fixed",
    "reference_match",
    "run_id",
    "request",
    "response",
    "status",
    "project",
    "filepath",
    "commit_id",
    "source_results",
    "source_index",
}

ALLOWED_BLIND_TOP_KEYS = {
    "schema_version",
    "package_id",
    "rubric_version",
    "created_at",
    "seed",
    "instructions",
    "scale",
    "dimensions",
    "compile_status_allowed",
    "upstream_fix_visibility",
    "cases",
}

ALLOWED_BLIND_CASE_KEYS = {
    "case_id",
    "cwe",
    "cwe_family",
    "vulnerable_function",
    "upstream_fixed_version",
    "upstream_fixed_note",
    "candidates",
}

ALLOWED_BLIND_CANDIDATE_KEYS = {"candidate_id", "repair", "explanation"}


def _normalise_code(code: str) -> str:
    text = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _collapse_whitespace(code: str) -> str:
    return re.sub(r"\s+", " ", _normalise_code(code)).strip()


def _line_diff(source: str, fixed: str) -> dict[str, Any]:
    left = _normalise_code(source).splitlines()
    right = _normalise_code(fixed).splitlines()
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    added = removed = replaced = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "insert":
            added += j2 - j1
        elif tag == "delete":
            removed += i2 - i1
        elif tag == "replace":
            replaced += max(i2 - i1, j2 - j1)
    changed = added + removed + replaced
    return {
        "source_lines": len(left),
        "fixed_lines": len(right),
        "added_lines": added,
        "removed_lines": removed,
        "replaced_lines": replaced,
        "changed_lines": changed,
        "changed_fraction": changed / len(left) if left else None,
    }


def _structural_checks(candidate: RepairCandidate, pair: Any) -> dict[str, Any]:
    validation = candidate.validation
    flags = {
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
        )
    }
    flags["fixed_code_sha256"] = sha256_text(candidate.fixed_function)
    flags["reference_exact_match"] = _normalise_code(candidate.fixed_function) == _normalise_code(
        pair.fixed_code
    )
    flags["reference_whitespace_collapsed_match"] = _collapse_whitespace(
        candidate.fixed_function
    ) == _collapse_whitespace(pair.fixed_code)
    flags["line_diff"] = _line_diff(pair.vulnerable_code, candidate.fixed_function)
    return flags


def _package_identity(
    dataset: DatasetInfo,
    results_files: list[ResultsFileInfo],
    selected: list[CaseInfo],
    strategies: tuple[str, ...],
    seed: int,
) -> str:
    payload = {
        "seed": seed,
        "dataset_sha256": dataset.sha256,
        "results_sha256": sorted(info.sha256 for info in results_files),
        "pair_ids": sorted(case.pair.pair_id for case in selected),
        "strategies": list(strategies),
        "rubric_version": RUBRIC_VERSION,
    }
    return "PKG-" + sha256_text(canonical_json(payload))[:12].upper()


def _make_ids(
    selected: list[CaseInfo],
    *,
    package_id: str,
    salt: str,
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    case_ids: dict[str, str] = {}
    candidate_ids: dict[tuple[str, str], str] = {}
    used: set[str] = set()
    for case in selected:
        case_id = "CASE-" + salted_id(salt, package_id, "case", case.pair.pair_id)[:10].upper()
        if case_id in used:
            raise RepairEvalError("case ID collision; regenerate the blind salt")
        used.add(case_id)
        case_ids[case.pair.pair_id] = case_id
        for candidate in case.candidates:
            candidate_id = (
                "PATCH-"
                + salted_id(
                    salt,
                    package_id,
                    "candidate",
                    case.pair.pair_id,
                    candidate.strategy,
                    sha256_text(candidate.fixed_function),
                )[:10].upper()
            )
            if candidate_id in used:
                raise RepairEvalError("candidate ID collision; regenerate the blind salt")
            used.add(candidate_id)
            candidate_ids[(case.pair.pair_id, candidate.strategy)] = candidate_id
    return case_ids, candidate_ids


def _candidate_display_order(
    case: CaseInfo,
    *,
    case_id: str,
    seed: int,
) -> list[RepairCandidate]:
    candidates = list(case.candidates)
    rng = random.Random(int(salted_id(str(seed), "candidate-order", case_id)[:16], 16))
    rng.shuffle(candidates)
    return candidates


def _code_block(code: str) -> str:
    fence = "````"
    return f"{fence}c\n{code.rstrip()}\n{fence}"


def _review_markdown(
    package: dict[str, Any],
    show_reference: bool,
) -> str:
    lines = [
        f"# 修复质量盲评包 `{package['package_id']}`",
        "",
        f"- rubric：`{package['rubric_version']}`",
        f"- 候选数：{sum(len(case['candidates']) for case in package['cases'])}",
        f"- 案例数：{len(package['cases'])}",
        "",
        "## 评分前须知",
        "",
        "- 每个候选只按 rubric 独立打分；不要猜测它来自哪种方法。",
        "- 候选顺序已随机化；候选 ID 不包含方法信息。",
        "- 上游修复版本仅用于理解根因，**不是候选，不评分**。"
        if show_reference
        else "- 本包刻意隐藏上游修复版本，避免锚定；请仅依据漏洞函数、CWE 和代码本身评分。",
        "- 不提供编译或 PoC oracle。`compile_status` 没有真实构建证据时填 `NOT_RUN` 或 `UNVERIFIED`。",
        "- 只填写自己的 `rater_*.tsv`；不要查看 `private/`。",
        "",
        "## Rubric",
        "",
        "| 维度 | 0 | 1 | 2 |",
        "| --- | --- | --- | --- |",
    ]
    for dimension in dimension_catalog():
        lines.append(
            f"| **{dimension['code']} {dimension['name_zh']}** | "
            f"{dimension['anchors'][0]} | {dimension['anchors'][1]} | {dimension['anchors'][2]} |"
        )
    lines.extend(
        [
            "",
            "完整评分规则见 `rubric.md`。",
            "",
            "---",
            "",
        ]
    )
    for case in package["cases"]:
        cwe_text = ", ".join(case["cwe"])
        lines.extend(
            [
                f"## {case['case_id']} — {cwe_text} / {case['cwe_family']}",
                "",
                "### 漏洞函数",
                "",
                _code_block(case["vulnerable_function"]),
                "",
            ]
        )
        if show_reference:
            lines.extend(
                [
                    "### 上游修复版本（上下文，不是候选，不评分）",
                    "",
                    _code_block(case["upstream_fixed_version"]),
                    "",
                ]
            )
        lines.extend(["### 候选（顺序已随机化）", ""])
        for candidate in case["candidates"]:
            lines.extend(
                [
                    f"#### {candidate['candidate_id']}",
                    "",
                    _code_block(candidate["repair"]),
                    "",
                    "**模型解释**",
                    "",
                    _code_block(candidate["explanation"]),
                    "",
                ]
            )
        lines.extend(["---", ""])
    return "\n".join(lines)


def _blind_readme(package: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# 盲评包 `{package['package_id']}`",
            "",
            "## 文件",
            "",
            "- `review.md`：漏洞函数、上游修复上下文（若未隐藏）和随机排序的候选。",
            "- `rubric.md`：七维 0/1/2 rubric、通过规则和编译状态说明。",
            "- `rater_A.tsv` / `rater_B.tsv`：两位评分者各自的空评分表。",
            "- `blind_package.json`：机器可读的盲评材料。",
            "",
            "## 流程",
            "",
            "1. 两位评分者独立阅读 `rubric.md` 和 `review.md`，分别填写自己的 TSV。",
            "2. 不要交流分数，不要查看 `private/`，不要尝试推断候选来源。",
            "3. 每维填 0/1/2；`compile_status` 见 rubric；`notes` 写 1–2 句理由。",
            "4. 交回两份 TSV 后运行 `agreement`，生成一致性报告和分歧裁决模板。",
            "5. 分歧由第三人裁决；填 `final_value` 和 `rationale` 后运行 `finalize`。",
            "",
            "## 注意",
            "",
            "- 本包不含策略名、模型名、pair_id 或参考修复匹配标记。",
            "- 上游修复版本（若显示）只是上下文；候选是否与它相同被刻意隐藏。",
            "- 没有编译/PoC oracle；不要把 `COM` 或 `compile_status` 当作漏洞已消除的证明。",
            "",
        ]
    )


def _artifact_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            hashes[relative_to(path, root)] = sha256_file(path)
    return hashes


def _validate_blind_shape(package: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    extra_top = set(package) - ALLOWED_BLIND_TOP_KEYS
    if extra_top:
        problems.append(f"unexpected top-level keys: {sorted(extra_top)}")
    for case in package.get("cases", []):
        extra_case = set(case) - ALLOWED_BLIND_CASE_KEYS
        if extra_case:
            problems.append(f"case {case.get('case_id')}: unexpected keys {sorted(extra_case)}")
        for candidate in case.get("candidates", []):
            extra_candidate = set(candidate) - ALLOWED_BLIND_CANDIDATE_KEYS
            if extra_candidate:
                problems.append(
                    f"candidate {candidate.get('candidate_id')}: unexpected keys "
                    f"{sorted(extra_candidate)}"
                )
    return problems


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def verify_package(package_dir: str | Path) -> dict[str, Any]:
    root = Path(package_dir)
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        raise RepairEvalError(f"not a blind package (missing manifest.json): {root}")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise RepairEvalError(f"{manifest_path}: manifest must be an object")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise RepairEvalError(f"{manifest_path}: artifacts hash table is missing")
    problems: list[str] = []
    for relative, expected in sorted(artifacts.items()):
        path = root / relative
        if not path.exists():
            problems.append(f"missing artifact: {relative}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            problems.append(f"hash mismatch: {relative}")
    listed = set(artifacts)
    actual_files = {
        relative_to(path, root)
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    extra = actual_files - listed
    if extra:
        problems.append(f"unlisted files: {sorted(extra)}")
    blind_path = root / "blind" / "blind_package.json"
    if not blind_path.exists():
        raise RepairEvalError(f"missing blind package: {blind_path}")
    package = read_json(blind_path)
    if not isinstance(package, dict):
        raise RepairEvalError(f"{blind_path}: package must be an object")
    problems.extend(_validate_blind_shape(package))
    leaked = _walk_keys(package) & FORBIDDEN_BLIND_KEYS
    if leaked:
        problems.append(f"blind package contains forbidden keys: {sorted(leaked)}")
    if package.get("package_id") != manifest.get("package_id"):
        problems.append("package_id mismatch between blind package and manifest")
    visibility = package.get("upstream_fix_visibility")
    if visibility == "hidden":
        if any(
            "upstream_fixed_version" in case or "upstream_fixed_note" in case
            for case in package.get("cases", [])
        ):
            problems.append("hidden reference mode still contains upstream fixed context")
    elif visibility == "context_only":
        if any("upstream_fixed_version" not in case for case in package.get("cases", [])):
            problems.append("context_only mode is missing upstream fixed context in some cases")
    else:
        problems.append(f"invalid upstream_fix_visibility {visibility!r}")
    case_ids: set[str] = set()
    candidate_ids: set[str] = set()
    for case in package.get("cases", []):
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            problems.append("case without case_id")
        elif case_id in case_ids:
            problems.append(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        if not isinstance(case.get("candidates"), list) or not case["candidates"]:
            problems.append(f"case {case_id}: no candidates")
        for candidate in case.get("candidates", []):
            candidate_id = candidate.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id:
                problems.append(f"case {case_id}: candidate without candidate_id")
            elif candidate_id in candidate_ids:
                problems.append(f"duplicate candidate_id: {candidate_id}")
            candidate_ids.add(candidate_id)
    for rater in ("A", "B"):
        path = root / "blind" / f"rater_{rater}.tsv"
        if not path.exists():
            problems.append(f"missing rater template: {path.name}")
            continue
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        if first_line.split("\t") != RATER_HEADER:
            problems.append(f"{path.name}: unexpected TSV header")
            continue
        _, rows = read_tsv(path)
        template_ids = [row.get("candidate_id", "") for row in rows]
        template_cases = {row.get("case_id", "") for row in rows}
        if len(template_ids) != len(candidate_ids) or set(template_ids) != candidate_ids:
            problems.append(f"{path.name}: candidate IDs do not match the blind package")
        if template_cases != case_ids:
            problems.append(f"{path.name}: case IDs do not match the blind package")
        if len(template_ids) != len(set(template_ids)):
            problems.append(f"{path.name}: duplicate candidate rows")
    if problems:
        raise RepairEvalError("package verification failed:\n- " + "\n- ".join(problems))
    return {
        "ok": True,
        "package_id": manifest.get("package_id"),
        "artifacts_checked": len(artifacts),
        "cases": len(case_ids),
        "candidates": len(candidate_ids),
        "blindness": manifest.get("blindness", {}),
        "manifest_path": str(manifest_path.resolve()),
    }


def load_package(package_dir: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    report = verify_package(package_dir)
    root = Path(package_dir)
    manifest = read_json(root / "manifest.json")
    package = read_json(root / "blind" / "blind_package.json")
    return package, {"manifest": manifest, "verification": report, "root": root}


def build_blind_package(
    *,
    dataset: DatasetInfo,
    results_files: list[ResultsFileInfo],
    sampling: SamplingResult,
    strategies: tuple[str, ...],
    seed: int,
    out_dir: str | Path,
    hide_reference: bool,
    frame_exclusions: dict[str, int],
    guards: dict[str, Any],
) -> dict[str, Any]:
    root = Path(out_dir)
    prepare_output_dir(root)
    selected = sampling.selected
    package_id = _package_identity(dataset, results_files, selected, strategies, seed)
    salt = secrets.token_hex(32)
    case_ids, candidate_ids = _make_ids(
        selected, package_id=package_id, salt=salt
    )
    blind_cases: list[dict[str, Any]] = []
    key_cases: dict[str, dict[str, Any]] = {}
    key_candidates: dict[str, dict[str, Any]] = {}
    display_order: dict[str, list[str]] = {}
    auto_rows: list[dict[str, Any]] = []
    by_strategy: Counter[str] = Counter()
    by_family: Counter[str] = Counter()

    for case in selected:
        case_id = case_ids[case.pair.pair_id]
        ordered = _candidate_display_order(
            case,
            case_id=case_id,
            seed=seed,
        )
        blind_candidates = []
        ordered_ids = []
        for candidate in ordered:
            candidate_id = candidate_ids[(case.pair.pair_id, candidate.strategy)]
            blind_candidates.append(
                {
                    "candidate_id": candidate_id,
                    "repair": candidate.fixed_function,
                    "explanation": candidate.explanation,
                }
            )
            ordered_ids.append(candidate_id)
            by_strategy[candidate.strategy] += 1
            auto = _structural_checks(candidate, case.pair)
            auto.update(
                {
                    "candidate_id": candidate_id,
                    "case_id": case_id,
                    "oracle": {
                        "compile": "NOT_RUN",
                        "poc": "NOT_RUN",
                        "note": (
                            "No build environment or exploit harness was executed by "
                            "repair_eval. Structural text checks are not correctness, "
                            "behavior, compile, or PoC evidence."
                        ),
                    },
                }
            )
            auto_rows.append(auto)
            key_candidates[candidate_id] = {
                "case_id": case_id,
                "pair_id": case.pair.pair_id,
                "sample_id": candidate.sample_id,
                "strategy": candidate.strategy,
                "model": candidate.model,
                "source_results": str(candidate.source_path),
                "source_index": candidate.source_index,
                "fixed_function_sha256": sha256_text(candidate.fixed_function),
                "explanation_sha256": sha256_text(candidate.explanation),
                "validation": candidate.validation,
            }
        blind_case: dict[str, Any] = {
            "case_id": case_id,
            "cwe": list(case.pair.cwe),
            "cwe_family": case.pair.cwe_family,
            "vulnerable_function": case.pair.vulnerable_code,
            "candidates": blind_candidates,
        }
        if not hide_reference:
            blind_case["upstream_fixed_version"] = case.pair.fixed_code
            blind_case["upstream_fixed_note"] = (
                "Dataset upstream fixed version, shown as context only. It is not a "
                "candidate and must not be scored. Candidate-level reference-match "
                "indicators are intentionally withheld."
            )
        blind_cases.append(blind_case)
        key_cases[case_id] = {
            "pair_id": case.pair.pair_id,
            "project": case.pair.project,
            "filepath": case.pair.filepath,
            "func_name": case.pair.func_name,
            "vulnerable_idx": case.pair.vulnerable_idx,
            "fixed_idx": case.pair.fixed_idx,
            "cwe": list(case.pair.cwe),
            "cwe_family": case.pair.cwe_family,
            "length_bin": case.pair.length_bin,
            "function_chars": case.pair.function_chars,
            "candidate_ids": ordered_ids,
        }
        display_order[case_id] = ordered_ids
        by_family[case.pair.cwe_family] += 1

    package = {
        "schema_version": 1,
        "package_id": package_id,
        "rubric_version": RUBRIC_VERSION,
        "created_at": utc_now(),
        "seed": seed,
        "instructions": [
            "Score every candidate independently on the seven rubric dimensions.",
            "Do not try to infer the prompting strategy or model that produced a candidate.",
            "The upstream fixed version, when shown, is context only and is not a candidate.",
            "No compile or proof-of-concept oracle is provided by this package.",
        ],
        "scale": {
            "min": 0,
            "max": 2,
            "labels": {
                "0": "does not meet the anchor",
                "1": "partially meets the anchor",
                "2": "meets the anchor",
            },
        },
        "dimensions": dimension_catalog(),
        "compile_status_allowed": list(COMPILE_STATUSES),
        "upstream_fix_visibility": "hidden" if hide_reference else "context_only",
        "cases": blind_cases,
    }

    blind_dir = root / "blind"
    private_dir = root / "private"
    blind_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)

    write_json(blind_dir / "blind_package.json", package)
    write_text(blind_dir / "rubric.md", rubric_markdown())
    write_text(blind_dir / "review.md", _review_markdown(package, not hide_reference))
    write_text(blind_dir / "README.md", _blind_readme(package))
    template_rows = [
        [candidate["candidate_id"], case["case_id"], "", "", "", "", "", "", "", "", ""]
        for case in package["cases"]
        for candidate in case["candidates"]
    ]
    write_tsv(blind_dir / "rater_A.tsv", RATER_HEADER, template_rows)
    write_tsv(blind_dir / "rater_B.tsv", RATER_HEADER, template_rows)

    key = {
        "schema_version": 1,
        "package_id": package_id,
        "seed": seed,
        "blind_salt": salt,
        "dataset": {
            "path": str(dataset.path),
            "sha256": dataset.sha256,
        },
        "results": [
            {
                "path": str(info.path),
                "sha256": info.sha256,
                "manifest_path": None if info.manifest_path is None else str(info.manifest_path),
                "manifest_sha256": info.manifest_sha256,
                "run_id": info.run_id,
                "status": info.status,
                "model": info.model,
                "endpoint": info.endpoint,
                "valid_candidates": info.valid_candidates,
                "provenance_unverified": info.provenance_unverified,
            }
            for info in results_files
        ],
        "cases": key_cases,
        "candidates": key_candidates,
        "display_order": display_order,
    }
    write_json(private_dir / "blind_key.json", key)
    write_jsonl(private_dir / "auto_checks.jsonl", auto_rows)
    sampling_payload = {
        "schema_version": 1,
        "seed": seed,
        "requested_pairs": sampling.requested_pairs,
        "target_pairs": sampling.target_pairs,
        "selected_pairs": len(selected),
        "frame_size": sampling.frame_size,
        "frame_exclusions": frame_exclusions,
        "strategies": list(strategies),
        "strata": sampling.strata,
        "allocation": sampling.allocation,
        "project_cap_used": sampling.project_cap_used,
        "warnings": sampling.warnings,
        "selected": [
            {
                "case_id": case_ids[case.pair.pair_id],
                "pair_id": case.pair.pair_id,
                "project": case.pair.project,
                "cwe": list(case.pair.cwe),
                "cwe_family": case.pair.cwe_family,
                "length_bin": case.pair.length_bin,
                "function_chars": case.pair.function_chars,
                "candidate_ids": display_order[case_ids[case.pair.pair_id]],
            }
            for case in selected
        ],
    }
    write_json(private_dir / "sampling.json", sampling_payload)
    artifacts = _artifact_hashes(root)
    manifest = {
        "schema_version": 1,
        "tool": "repair_eval",
        "tool_version": "0.1.0",
        "package_id": package_id,
        "created_at": package["created_at"],
        "seed": seed,
        "rubric_version": RUBRIC_VERSION,
        "dataset": {
            "path": str(dataset.path),
            "sha256": dataset.sha256,
            "metadata": {
                key_name: dataset.metadata.get(key_name)
                for key_name in ("dataset_type", "pair_count", "function_count", "seed")
                if key_name in dataset.metadata
            },
        },
        "provenance": {
            "results": [
                {
                    "path": str(info.path),
                    "sha256": info.sha256,
                    "manifest_path": None if info.manifest_path is None else str(info.manifest_path),
                    "manifest_sha256": info.manifest_sha256,
                    "run_id": info.run_id,
                    "status": info.status,
                    "model": info.model,
                    "endpoint": info.endpoint,
                    "records_total": info.records_total,
                    "repair_records": info.repair_records,
                    "http_200_repair": info.http_200_repair,
                    "valid_candidates": info.valid_candidates,
                    "provenance_unverified": info.provenance_unverified,
                }
                for info in results_files
            ],
            "models": sorted({info.model for info in results_files if info.model}),
            "strategies": list(strategies),
            "guards": guards,
        },
        "counts": {
            "cases": len(package["cases"]),
            "candidates": sum(len(case["candidates"]) for case in package["cases"]),
            "by_strategy": dict(sorted(by_strategy.items())),
            "by_cwe_family": dict(sorted(by_family.items())),
        },
        "sampling": {
            "requested_pairs": sampling.requested_pairs,
            "target_pairs": sampling.target_pairs,
            "selected_pairs": len(selected),
            "frame_size": sampling.frame_size,
            "frame_exclusions": frame_exclusions,
            "strata": sampling.strata,
            "project_cap_used": sampling.project_cap_used,
            "warnings": sampling.warnings,
        },
        "blindness": {
            "strategy_fields_in_blind_package": False,
            "model_fields_in_blind_package": False,
            "pair_or_sample_fields_in_blind_package": False,
            "candidate_reference_match_fields_in_blind_package": False,
            "upstream_fix_visibility": package["upstream_fix_visibility"],
            "candidate_order_randomized": True,
            "blind_ids_keyed_by_private_salt": True,
        },
        "artifacts": artifacts,
    }
    write_json(root / "manifest.json", manifest)
    report = verify_package(root)
    return {
        "package_dir": str(root.resolve()),
        "package_id": package_id,
        "cases": len(package["cases"]),
        "candidates": manifest["counts"]["candidates"],
        "by_strategy": manifest["counts"]["by_strategy"],
        "verification": report,
        "warnings": sampling.warnings,
    }

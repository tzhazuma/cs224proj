"""Coverage-stratified metrics for the frozen test 140.

Every stratum is built from the archived verdicts (the paper's numbers) joined
to the coverage record of the same unit.  Coverage never changes a label and
never turns a missed leak into a true negative: the gated views below only
decide whether a *negative* verdict has enough executed code behind it.
"""

from __future__ import annotations

import json
import math
import statistics
from pathlib import Path

from . import config
from .link import crosscheck, load_archived
from .units import read_jsonl

TIER_ORDER = (
    "branch_complete",
    "line_complete",
    "partial",
    "not_executed",
    "no_coverage",
    "coverage_error",
)


def _f1(tp: int, fp: int, fn: int) -> float | None:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _mcc(tp: int, fp: int, tn: int, fn: int) -> float | None:
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denominator == 0:
        return None
    return (tp * tn - fp * fn) / denominator


def _stats(tp: int, fp: int, tn: int, fn: int) -> dict:
    f1_pos = _f1(tp, fp, fn)
    f1_neg = _f1(tn, fn, fp)
    macro = (
        (f1_pos + f1_neg) / 2
        if f1_pos is not None and f1_neg is not None
        else None
    )
    n = tp + fp + tn + fn
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n": n,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "specificity": tn / (tn + fp) if tn + fp else None,
        "f1": f1_pos,
        "macro_f1": macro,
        "accuracy": (tp + tn) / n if n else None,
        "mcc": _mcc(tp, fp, tn, fn),
    }


def _tier_counts(values: list[str]) -> dict:
    counts = {tier: 0 for tier in TIER_ORDER}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def default_tier(record: dict) -> str:
    entry = (record.get("modes") or {}).get("default") or {}
    return entry.get("coverage_tier_effective") or entry.get("coverage_tier") or "coverage_error"


def default_tier_raw(record: dict) -> str:
    entry = (record.get("modes") or {}).get("default") or {}
    return entry.get("coverage_tier") or "coverage_error"


def union_tier(record: dict) -> str:
    return record.get("coverage_tier_effective") or record.get("coverage_tier") or "coverage_error"


def union_tier_raw(record: dict) -> str:
    return record.get("coverage_tier") or "coverage_error"


def _coverage_json(run_dir: Path, record: dict, mode: str) -> dict | None:
    path = (
        run_dir
        / "cases"
        / f"{record['unit_key']}_{record['label']}"
        / f"run_{mode}"
        / "coverage.json"
    )
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _hit_sets(payload: dict | None) -> dict:
    lines: set[tuple] = set()
    branches: set[tuple] = set()
    if not payload:
        return {"lines": lines, "branches": branches}
    for file_cov in payload.get("files", []):
        path = file_cov["file"]
        for line, count in file_cov.get("lines", {}).items():
            if count > 0:
                lines.add((path, int(line)))
        for branch in file_cov.get("branches", []):
            if branch.get("count", 0) > 0:
                branches.add(
                    (
                        path,
                        branch.get("line"),
                        branch.get("source_block_id"),
                        branch.get("destination_block_id"),
                        branch.get("throw"),
                        branch.get("fallthrough"),
                    )
                )
    return {"lines": lines, "branches": branches}


def build_metrics(run_dir: Path) -> dict:
    records = read_jsonl(run_dir / "results_units.jsonl")
    archived = load_archived()
    join = archived.get("by_unit", {})
    for record in records:
        archived_row = join.get(record["unit_id"], {})
        record["archived_default"] = (
            "leak" if archived_row.get("archived_default_leak") else "clean"
        )
        record["archived_default_decision"] = archived_row.get("archived_default_decision")
        record["archived_union"] = archived_row.get("archived_decision") or "not_evaluable"
        record["archived_primary_evidence"] = archived_row.get("archived_primary_evidence")
        record["old_asan"] = (archived_row.get("old_asan") or {}).get("status")
        record["old_valgrind"] = (archived_row.get("old_valgrind") or {}).get("status")

    cross = crosscheck(records, archived)
    by_id = {record["unit_id"]: record for record in records}

    # Per-mode coverage summaries.
    mode_coverage = {}
    for mode in config.MODES:
        mode_rows = [
            record for record in records if (record.get("modes") or {}).get(mode)
        ]
        summaries = [
            record["modes"][mode].get("coverage") or {} for record in mode_rows
        ]
        mode_coverage[mode] = {
            "units": len(mode_rows),
            "applicable_units": sum(
                1 for record in mode_rows if record["modes"][mode].get("applicable")
            ),
            "bad_leaks": sum(
                1 for record in mode_rows
                if record["label"] == "bad"
                and record["modes"][mode].get("applicable")
                and record["modes"][mode].get("leak_attributed")
            ),
            "good_leaks": sum(
                1 for record in mode_rows
                if record["label"] == "good"
                and record["modes"][mode].get("applicable")
                and record["modes"][mode].get("leak_attributed")
            ),
            "mean_line_pct": _mean(
                [row["line_pct"] for row in summaries if row.get("line_pct") is not None]
            ),
            "mean_effective_line_pct": _mean(
                [row["effective_line_pct"] for row in summaries
                 if row.get("effective_line_pct") is not None]
            ),
            "mean_branch_pct": _mean(
                [row["branch_pct"] for row in summaries if row.get("branch_pct") is not None]
            ),
            "tiers": _tier_counts(
                [record["modes"][mode].get("coverage_tier") or "coverage_error"
                 for record in mode_rows]
            ),
            "tiers_effective": _tier_counts(
                [record["modes"][mode].get("coverage_tier_effective") or "coverage_error"
                 for record in mode_rows]
            ),
        }

    overall = {
        "units": len(records),
        "tiers": _tier_counts([union_tier(record) for record in records]),
        "coverage_classes": {
            name: sum(1 for record in records if record.get("coverage_class") == name)
            for name in ("covered_clean", "uncovered", "compile_error", "leak")
        },
        "coverage_classes_by_label": {
            name: {
                label: sum(
                    1
                    for record in records
                    if record.get("coverage_class") == name and record["label"] == label
                )
                for label in ("bad", "good")
            }
            for name in ("covered_clean", "uncovered", "compile_error", "leak")
        },
        "coverage_classes_default": {
            "covered_clean": sum(
                1 for record in records
                if record.get("archived_default") == "clean"
                and default_tier(record) in ("line_complete", "branch_complete")
                and record.get("entry_executed")
            ),
            "uncovered": sum(
                1 for record in records
                if record.get("archived_default") == "clean"
                and not (
                    default_tier(record) in ("line_complete", "branch_complete")
                    and record.get("entry_executed")
                )
            ),
            "leak": sum(1 for record in records if record.get("archived_default") == "leak"),
            "compile_error": sum(1 for record in records if record.get("compile_error")),
        },
        "coverage_classes_default_by_label": {
            name: {
                label: sum(
                    1
                    for record in records
                    if record["label"] == label
                    and (
                        (name == "leak" and record.get("archived_default") == "leak")
                        or (
                            name == "covered_clean"
                            and record.get("archived_default") == "clean"
                            and default_tier(record) in ("line_complete", "branch_complete")
                            and record.get("entry_executed")
                        )
                        or (
                            name == "uncovered"
                            and record.get("archived_default") == "clean"
                            and not (
                                default_tier(record) in ("line_complete", "branch_complete")
                                and record.get("entry_executed")
                            )
                        )
                        or (name == "compile_error" and record.get("compile_error"))
                    )
                )
                for label in ("bad", "good")
            }
            for name in ("covered_clean", "uncovered", "compile_error", "leak")
        },
        "mean_line_pct": _mean(
            [record["coverage_union"]["line_pct"] for record in records
             if (record.get("coverage_union") or {}).get("line_pct") is not None]
        ),
        "mean_effective_line_pct": _mean(
            [record["coverage_union"]["effective_line_pct"] for record in records
             if (record.get("coverage_union") or {}).get("effective_line_pct") is not None]
        ),
        "mean_branch_pct": _mean(
            [record["coverage_union"]["branch_pct"] for record in records
             if (record.get("coverage_union") or {}).get("branch_pct") is not None]
        ),
        "entry_executed": sum(1 for record in records if record.get("entry_executed")),
        "branch_complete_bad": sum(
            1 for record in records
            if record["label"] == "bad" and union_tier(record) == "branch_complete"
        ),
        "branch_complete_good": sum(
            1 for record in records
            if record["label"] == "good" and union_tier(record) == "branch_complete"
        ),
    }

    # Stratified confusion tables.  Predictions are the archived verdicts;
    # coverage only selects the stratum.
    def strata(pred_key: str, tier_key) -> dict:
        table = {}
        for tier_name in TIER_ORDER:
            rows = [record for record in records if tier_key(record) == tier_name]
            if not rows:
                continue
            decided = [record for record in rows if record[pred_key] in ("leak", "clean")]
            if len(decided) != len(rows):
                rows = decided
                if not rows:
                    continue
            tp = sum(1 for record in rows if record["label"] == "bad" and record[pred_key] == "leak")
            fn = sum(1 for record in rows if record["label"] == "bad" and record[pred_key] == "clean")
            fp = sum(1 for record in rows if record["label"] == "good" and record[pred_key] == "leak")
            tn = sum(1 for record in rows if record["label"] == "good" and record[pred_key] == "clean")
            table[tier_name] = {"units": len(rows), **_stats(tp, fp, tn, fn)}
        return table

    default_strata = strata("archived_default", default_tier)
    union_strata = strata("archived_union", union_tier)

    # Default-path clean evidence: the 70 clean verdicts.
    clean_rows = [record for record in records if record["archived_default"] == "clean"]
    clean_evidence = {
        "units": len(clean_rows),
        "true_good": sum(1 for record in clean_rows if record["label"] == "good"),
        "true_bad": sum(1 for record in clean_rows if record["label"] == "bad"),
        "default_tiers": _tier_counts([default_tier(record) for record in clean_rows]),
        "default_tiers_raw": _tier_counts([default_tier_raw(record) for record in clean_rows]),
        "union_tiers": _tier_counts([union_tier(record) for record in clean_rows]),
        "default_branch_complete_bad": [
            record["unit_id"]
            for record in clean_rows
            if record["label"] == "bad" and default_tier(record) == "branch_complete"
        ],
        "default_not_branch_complete_bad": [
            record["unit_id"]
            for record in clean_rows
            if record["label"] == "bad" and default_tier(record) != "branch_complete"
        ],
        "default_branch_complete_good": sum(
            1 for record in clean_rows
            if record["label"] == "good" and default_tier(record) == "branch_complete"
        ),
        "default_line_complete_good": sum(
            1 for record in clean_rows
            if record["label"] == "good"
            and default_tier(record) in ("line_complete", "branch_complete")
        ),
        "executed_clean": sum(
            1 for record in clean_rows
            if default_tier(record) in ("line_complete", "branch_complete")
        ),
        "executed_clean_bad": sum(
            1 for record in clean_rows
            if record["label"] == "bad"
            and default_tier(record) in ("line_complete", "branch_complete")
        ),
        "unsupported_clean": [
            record["unit_id"]
            for record in clean_rows
            if default_tier(record) not in ("line_complete", "branch_complete")
        ],
        "dead_code_lines": sum(
            len(((record.get("modes") or {}).get("default") or {}).get("coverage", {}).get("dead_code_uncovered", []))
            for record in clean_rows
        ),
    }

    # The 12 units that the original path calls clean although they are bad.
    latent = []
    for record in records:
        if record["label"] != "bad" or record["archived_default"] != "clean":
            continue
        default = (record.get("modes") or {}).get("default") or {}
        default_cov = default.get("coverage") or {}
        union_cov = record.get("coverage_union") or {}
        latent.append(
            {
                "unit_id": record["unit_id"],
                "family": record["family"],
                "variant": record["variant"],
                "language": record["language"],
                "default_tier": default_tier(record),
                "default_tier_raw": default_tier_raw(record),
                "union_tier": union_tier(record),
                "union_tier_raw": union_tier_raw(record),
                "default_line": default_cov.get("line_pct"),
                "default_branch": default_cov.get("branch_pct"),
                "default_lines": [default_cov.get("lines_hit"), default_cov.get("lines_total")],
                "default_branches": [
                    default_cov.get("branches_hit"),
                    default_cov.get("branches_total"),
                ],
                "union_line": union_cov.get("line_pct"),
                "union_branch": union_cov.get("branch_pct"),
                "union_lines": [union_cov.get("lines_hit"), union_cov.get("lines_total")],
                "union_branches": [
                    union_cov.get("branches_hit"),
                    union_cov.get("branches_total"),
                ],
                "default_uncovered_lines": default_cov.get("uncovered_lines", []),
                "default_uncovered_branches": default_cov.get("uncovered_branches", []),
                "primary_evidence": record.get("primary_evidence"),
                "archived_union": record["archived_union"],
            }
        )
    latent.sort(key=lambda row: row["unit_id"])
    for row in latent:
        snippets = []
        by_line: dict[tuple[str, int], str] = {}
        for branch in row["default_uncovered_branches"]:
            key = (branch.get("file"), branch.get("line"))
            if key in by_line:
                continue
            try:
                text = (config.PROJECT / key[0]).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                by_line[key] = text[key[1] - 1].strip() if 0 < key[1] <= len(text) else ""
            except (OSError, TypeError):
                by_line[key] = ""
        for (file_name, line_number), text_value in by_line.items():
            snippets.append(
                {"file": file_name, "line": line_number, "text": text_value}
            )
        row["default_uncovered_branch_snippets"] = snippets
        row["default_uncovered_branch_lines"] = sorted(
            {item["line"] for item in snippets if item["line"] is not None}
        )
        row["default_dead_code_lines"] = (
            by_id[row["unit_id"]]
            .get("modes", {})
            .get("default", {})
            .get("coverage", {})
            .get("dead_code_uncovered", [])
        )
    latent_summary = {
        "units": len(latent),
        "default_branch_complete": sum(
            1 for row in latent if row["default_tier"] == "branch_complete"
        ),
        "default_line_complete": sum(
            1 for row in latent if row["default_tier"] == "line_complete"
        ),
        "default_partial": sum(1 for row in latent if row["default_tier"] == "partial"),
        "default_not_executed": sum(
            1 for row in latent if row["default_tier"] == "not_executed"
        ),
        "union_branch_complete": sum(
            1 for row in latent if row["union_tier"] == "branch_complete"
        ),
        "realloc_evidence": [
            row["unit_id"] for row in latent if row["primary_evidence"] == "realloc_fail"
        ],
        "root_policy_evidence": [
            row["unit_id"] for row in latent if row["primary_evidence"] == "nogobal"
        ],
    }
    latent_summary["coverage_explains_miss"] = len(latent_summary["realloc_evidence"])
    latent_summary["root_policy_only"] = latent_summary["root_policy_evidence"]

    # Coverage-gated views: a clean verdict only counts as TN when the
    # executed code supports it.  Unsupported clean units leave the
    # denominator (abstain) instead of being silently counted as negatives.
    def gated(pred_key: str, tier_key, allowed_tiers: tuple[str, ...]) -> dict:
        tp = fn = fp = tn = abstain = supported_clean_bad = 0
        for record in records:
            if record[pred_key] not in ("leak", "clean"):
                continue
            tier_name = tier_key(record)
            if record["label"] == "bad":
                if record[pred_key] == "leak":
                    tp += 1
                else:
                    fn += 1
                    if tier_name in allowed_tiers:
                        supported_clean_bad += 1
            else:
                if record[pred_key] == "leak":
                    fp += 1
                elif tier_name in allowed_tiers:
                    tn += 1
                else:
                    abstain += 1
        stats = _stats(tp, fp, tn, fn)
        return {
            **stats,
            "abstain": abstain,
            "coverage": (tp + fp + tn + fn) / len(records) if records else None,
            "supported_clean_but_bad": supported_clean_bad,
        }

    gated_views = {
        "default_operational": gated("archived_default", default_tier, TIER_ORDER),
        "default_line_gated_raw": gated(
            "archived_default", default_tier_raw, ("line_complete", "branch_complete")
        ),
        "default_line_gated": gated(
            "archived_default", default_tier, ("line_complete", "branch_complete")
        ),
        "default_branch_gated": gated(
            "archived_default", default_tier, ("branch_complete",)
        ),
        "enhanced_operational": gated("archived_union", union_tier, TIER_ORDER),
        "enhanced_line_gated_raw": gated(
            "archived_union", union_tier_raw, ("line_complete", "branch_complete")
        ),
        "enhanced_line_gated": gated(
            "archived_union", union_tier, ("line_complete", "branch_complete")
        ),
        "enhanced_branch_gated": gated(
            "archived_union", union_tier, ("branch_complete",)
        ),
    }

    # What each enhanced mode adds on top of the original path.
    mode_gain = {}
    for mode in config.MODES:
        added_lines = added_branches = 0
        units_with_gain = []
        for record in records:
            default_payload = _coverage_json(run_dir, record, "default")
            mode_payload = _coverage_json(run_dir, record, mode)
            if default_payload is None or mode_payload is None:
                continue
            default_hits = _hit_sets(default_payload)
            mode_hits = _hit_sets(mode_payload)
            new_lines = mode_hits["lines"] - default_hits["lines"]
            new_branches = mode_hits["branches"] - default_hits["branches"]
            if new_lines or new_branches:
                units_with_gain.append(record["unit_id"])
            added_lines += len(new_lines)
            added_branches += len(new_branches)
        mode_gain[mode] = {
            "units_with_new_lines_or_branches": len(units_with_gain),
            "added_lines_vs_default": added_lines,
            "added_branches_vs_default": added_branches,
            "units": units_with_gain,
        }

    # Allocation/release call-site execution.
    def site_totals(get_sites) -> dict:
        alloc_total = alloc_hit = free_total = free_hit = 0
        for record in records:
            sites = get_sites(record) or {}
            alloc_total += sites.get("allocation_sites_total", 0)
            alloc_hit += sites.get("allocation_sites_hit", 0)
            free_total += sites.get("release_sites_total", 0)
            free_hit += sites.get("release_sites_hit", 0)
        return {
            "allocation_sites_total": alloc_total,
            "allocation_sites_hit": alloc_hit,
            "release_sites_total": free_total,
            "release_sites_hit": free_hit,
        }

    return {
        "run_id": run_dir.name,
        "units": len(records),
        "labels": {
            "bad": sum(1 for record in records if record["label"] == "bad"),
            "good": sum(1 for record in records if record["label"] == "good"),
        },
        "coverage_overall": overall,
        "coverage_by_mode": mode_coverage,
        "crosscheck": cross,
        "archived": {
            "available": archived.get("available"),
            "path": archived.get("path"),
            "old_dynamic": archived.get("old_dynamic"),
        },
        "default_strata": default_strata,
        "union_strata": union_strata,
        "clean_evidence": clean_evidence,
        "latent_units": latent,
        "latent_summary": latent_summary,
        "gated_views": gated_views,
        "mode_gain": mode_gain,
        "site_coverage": {
            "default": site_totals(
                lambda record: (record.get("modes") or {}).get("default", {}).get("site_coverage")
            ),
            "union": site_totals(lambda record: record.get("site_coverage_union")),
        },
    }

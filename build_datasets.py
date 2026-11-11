"""Build independent and vulnerable/fixed JSON datasets from SecVulEval.xlsx.

Run with the pap environment, for example:
    conda run -n pap python build_datasets.py --seed 42

Only openpyxl and the Python standard library are required. The source workbook
is read-only. Structured list columns become JSON arrays; context is preserved
as the original string because its numpy-array representation is not JSON.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from openpyxl import load_workbook


ROOT = Path(__file__).resolve().parent
LIST_FIELDS = ("changed_lines", "changed_statements", "cve_list", "cwe_list")
IDENTITY_FIELDS = ("project", "commit_id", "filepath", "func_name")
Record = dict[str, Any]
CommitGroup = tuple[str, str]


def normalize_record(row: Record) -> Record:
    """Decode arrays without executing the source's serialized context."""
    record = dict(row)
    if type(record["idx"]) is not int:
        raise ValueError("idx must be an integer")
    if type(record["is_vulnerable"]) is not bool:
        raise ValueError("is_vulnerable must be a boolean")
    if record["fixed_func_idx"] is not None and type(record["fixed_func_idx"]) is not int:
        raise ValueError("fixed_func_idx must be an integer or null")
    for field in (*IDENTITY_FIELDS, "func_body"):
        if not isinstance(record[field], str) or not record[field].strip():
            raise ValueError(f"{field} must be nonempty text")
    for field in LIST_FIELDS:
        value = record[field]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                try:
                    value = ast.literal_eval(value)
                except (SyntaxError, ValueError) as exc:
                    raise ValueError(f"{field} is not a valid serialized list") from exc
        if not isinstance(value, list):
            raise ValueError(f"{field} must decode to a list")
        record[field] = value
    return record


def load_records(source: Path) -> tuple[list[Record], set[int], Record]:
    """Read train, excluding malformed records and retaining their source IDs."""
    workbook = load_workbook(source, read_only=True, data_only=True)
    records: list[Record] = []
    fixed_targets: set[int] = set()
    invalid_rows: list[Record] = []
    seen_ids: set[int] = set()
    labels: Counter = Counter()
    try:
        worksheet = workbook["train"]
        iterator = worksheet.iter_rows(values_only=True)
        headers = next(iterator)
        required = {"idx", "is_vulnerable", "fixed_func_idx", "func_body", *IDENTITY_FIELDS, *LIST_FIELDS}
        missing = required - set(headers)
        if missing:
            raise ValueError(f"Missing source columns: {sorted(missing)}")
        for values in iterator:
            if all(value is None for value in values):
                continue
            row = dict(zip(headers, values))
            if row["idx"] in seen_ids:
                raise ValueError(f"Duplicate source idx: {row['idx']}")
            seen_ids.add(row["idx"])
            labels[str(row["is_vulnerable"])] += 1
            # Include references even when another field in this row is malformed.
            if row["is_vulnerable"] is True and row["fixed_func_idx"] is not None:
                fixed_targets.add(row["fixed_func_idx"])
            try:
                records.append(normalize_record(row))
            except ValueError as exc:
                invalid_rows.append({"idx": row["idx"], "reason": str(exc)})
    finally:
        workbook.close()
    info = {
        "source_file": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_sheet": "train",
        "source_rows": sum(labels.values()),
        "source_label_counts": dict(labels),
        "usable_rows": len(records),
        "excluded_malformed_rows": invalid_rows,
    }
    return records, fixed_targets, info


def commit_group(record: Record) -> CommitGroup:
    return record["project"], record["commit_id"]


def select_distinct_commits(
    candidates: list[Record],
    count: int,
    rng: random.Random,
    group_key: Callable[[Record], CommitGroup],
    excluded: set[CommitGroup],
) -> list[Record]:
    if count < 0:
        raise ValueError("Sample counts must be nonnegative")
    shuffled = list(candidates)
    rng.shuffle(shuffled)
    selected: list[Record] = []
    used = set(excluded)
    for candidate in shuffled:
        if len(selected) == count:
            break
        group = group_key(candidate)
        if group in used:
            continue
        selected.append(candidate)
        used.add(group)
    if len(selected) != count:
        raise ValueError(f"Need {count} distinct eligible commits, found only {len(selected)}")
    return selected


def build_datasets(
    records: list[Record],
    fixed_targets: set[int],
    source_info: Record,
    *,
    seed: int = 42,
    vulnerable_count: int = 160,
    non_vulnerable_count: int = 40,
    pair_count: int = 200,
) -> tuple[Record, Record]:
    if min(vulnerable_count, non_vulnerable_count, pair_count) < 0:
        raise ValueError("Sample counts must be nonnegative")
    by_id = {row["idx"]: row for row in records}
    if len(by_id) != len(records):
        raise ValueError("Source IDs must be unique")
    pair_candidates: list[Record] = []
    rejected: Counter = Counter()
    for vulnerable in records:
        if not vulnerable["is_vulnerable"]:
            continue
        fixed = by_id.get(vulnerable["fixed_func_idx"])
        if fixed is None:
            rejected["missing_or_malformed_fixed_version"] += 1
        elif fixed["is_vulnerable"]:
            rejected["fixed_version_has_vulnerable_label"] += 1
        elif any(vulnerable[key] != fixed[key] for key in IDENTITY_FIELDS):
            rejected["function_identity_mismatch"] += 1
        elif vulnerable["func_body"].strip() == fixed["func_body"].strip():
            rejected["unchanged_function_body"] += 1
        else:
            pair_candidates.append({
                "pair_id": f"{vulnerable['idx']}:{fixed['idx']}",
                "vulnerable": vulnerable,
                "fixed": fixed,
            })

    rng = random.Random(seed)
    pairs = select_distinct_commits(
        pair_candidates, pair_count, rng, lambda pair: commit_group(pair["vulnerable"]), set()
    )
    pair_groups = {commit_group(pair["vulnerable"]) for pair in pairs}
    vulnerable_rows = select_distinct_commits(
        [row for row in records if row["is_vulnerable"]],
        vulnerable_count, rng, commit_group, pair_groups,
    )
    used_groups = pair_groups | {commit_group(row) for row in vulnerable_rows}
    negative_rows = select_distinct_commits(
        [row for row in records if not row["is_vulnerable"] and row["idx"] not in fixed_targets],
        non_vulnerable_count, rng, commit_group, used_groups,
    )
    samples = vulnerable_rows + negative_rows
    rng.shuffle(samples)
    common = {
        "schema_version": 1,
        **source_info,
        "seed": seed,
        "sampling": "Shuffle source rows with random.Random(seed); keep at most one item per project+commit. Select pairs first.",
        "cross_dataset_isolation": "No shared source idx or (project, commit_id) group",
        "field_encoding": {"json_arrays": list(LIST_FIELDS), "context": "Original workbook string, not evaluated"},
    }
    independent = {
        "metadata": {
            **common,
            "dataset_type": "independent_functions",
            "sample_count": len(samples),
            "vulnerable_count": vulnerable_count,
            "non_vulnerable_count": non_vulnerable_count,
            "constraints": [
                "At most one function per (project, commit_id)",
                "No vulnerable/fixed pair within samples",
                "Negative samples are not the fixed_func_idx target of any vulnerable source row",
            ],
        },
        "samples": samples,
    }
    paired = {
        "metadata": {
            **common,
            "dataset_type": "vulnerable_fixed_pairs",
            "pair_count": len(pairs),
            "function_count": len(pairs) * 2,
            "eligible_pair_count": len(pair_candidates),
            "rejected_pair_counts": dict(rejected),
            "constraints": [
                "vulnerable.fixed_func_idx == fixed.idx",
                "Same project, commit_id, filepath and func_name within each pair",
                "Vulnerable label true, fixed label false, different function bodies",
                "At most one pair per (project, commit_id)",
            ],
        },
        "pairs": pairs,
    }
    validate_datasets(independent, paired, fixed_targets)
    return independent, paired


def validate_datasets(independent: Record, paired: Record, fixed_targets: set[int]) -> None:
    """Reject incorrect counts, mislabeled pairs and leakage before writing."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    samples, pairs = independent["samples"], paired["pairs"]
    meta = independent["metadata"]
    require(len(samples) == meta["sample_count"] == meta["vulnerable_count"] + meta["non_vulnerable_count"], "Wrong independent sample count")
    require(sum(row["is_vulnerable"] is True for row in samples) == meta["vulnerable_count"], "Wrong vulnerable count")
    require(sum(row["is_vulnerable"] is False for row in samples) == meta["non_vulnerable_count"], "Wrong non-vulnerable count")
    sample_ids = {row["idx"] for row in samples}
    sample_groups = {commit_group(row) for row in samples}
    require(len(sample_ids) == len(sample_groups) == len(samples), "Independent samples share IDs or commits")
    for row in samples:
        require(row["fixed_func_idx"] == row["idx"] or row["fixed_func_idx"] not in sample_ids, "Independent samples include a repair pair")
        require(row["is_vulnerable"] or row["idx"] not in fixed_targets, "Independent negative is a known repaired version")
    require(len(pairs) == paired["metadata"]["pair_count"], "Wrong pair count")
    require(2 * len(pairs) == paired["metadata"]["function_count"], "Wrong paired function count")
    pair_ids: set[int] = set()
    pair_groups: set[CommitGroup] = set()
    for pair in pairs:
        vulnerable, fixed = pair["vulnerable"], pair["fixed"]
        require(vulnerable["is_vulnerable"] is True and fixed["is_vulnerable"] is False, "Incorrect pair labels")
        require(vulnerable["fixed_func_idx"] == fixed["idx"], "Pair does not follow fixed_func_idx")
        require(all(vulnerable[key] == fixed[key] for key in IDENTITY_FIELDS), "Pair function identities differ")
        require(vulnerable["func_body"].strip() != fixed["func_body"].strip(), "Pair has unchanged code")
        require(pair["pair_id"] == f"{vulnerable['idx']}:{fixed['idx']}", "Incorrect pair ID")
        group = commit_group(vulnerable)
        require(group not in pair_groups, "Pairs share a commit")
        require(vulnerable["idx"] not in pair_ids and fixed["idx"] not in pair_ids, "Pairs share a source row")
        pair_groups.add(group)
        pair_ids.update((vulnerable["idx"], fixed["idx"]))
    require(sample_ids.isdisjoint(pair_ids), "Datasets share source rows")
    require(sample_groups.isdisjoint(pair_groups), "Datasets share commits")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "SecVulEval.xlsx")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "datasets")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--vulnerable-count", type=int, default=160)
    parser.add_argument("--non-vulnerable-count", type=int, default=40)
    parser.add_argument("--pair-count", type=int, default=200)
    args = parser.parse_args()
    records, fixed_targets, source_info = load_records(args.source)
    independent, paired = build_datasets(
        records, fixed_targets, source_info, seed=args.seed,
        vulnerable_count=args.vulnerable_count,
        non_vulnerable_count=args.non_vulnerable_count, pair_count=args.pair_count,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    independent_count = args.vulnerable_count + args.non_vulnerable_count
    outputs = [
        (args.output_dir / f"independent_{independent_count}.json", independent),
        (args.output_dir / f"vulnerable_fixed_{args.pair_count}_pairs.json", paired),
    ]
    for path, payload in outputs:
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
    print(json.dumps({
        "python": sys.executable,
        "source_rows": source_info["source_rows"],
        "excluded_malformed_rows": len(source_info["excluded_malformed_rows"]),
        "independent": {"total": independent_count, "vulnerable": args.vulnerable_count, "non_vulnerable": args.non_vulnerable_count},
        "paired": {"pairs": args.pair_count, "functions": args.pair_count * 2},
        "seed": args.seed,
        "files": [str(path.resolve()) for path, _ in outputs],
        "validation": "passed",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

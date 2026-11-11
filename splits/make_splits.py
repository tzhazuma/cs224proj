#!/usr/bin/env python3
"""Freeze the project-level development/test split for SecVulEval.

This script is the single writer of ``splits/``.  It reads the two frozen
dataset snapshots in ``datasets/``, never modifies them, and never calls a
model or the network.

Design (``research/evaluation_protocol.md`` section 4):

* detection: 40 dev (32 vulnerable + 8 non-vulnerable) / 160 test
  (128 vulnerable + 32 non-vulnerable);
* pairs: 20 dev / 180 test, and the two sides of a pair always stay together;
* within each task a project appears in exactly one split; projects that are
  multi-sample in that task are test-only (protocol section 4.2).  The two
  tasks are split independently, so a project can be dev in one and test in
  the other; those intersections are recorded explicitly for audit.
* no shared source ``idx`` and no shared function text between dev and test.

Only the Python standard library is used.  The generated files are
byte-for-byte reproducible; ``verify`` rebuilds in memory and compares.

Usage (run from any directory, inside WSL)::

    python3 splits/make_splits.py preview
    python3 splits/make_splits.py build
    python3 splits/make_splits.py freeze
    python3 splits/make_splits.py verify
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = Path(__file__).resolve()
SPLITS_DIR = ROOT / "splits"
INDEPENDENT_PATH = ROOT / "datasets" / "independent_200.json"
PAIRS_PATH = ROOT / "datasets" / "vulnerable_fixed_200_pairs.json"
NOTES_PATH = SPLITS_DIR / "example_notes.json"
FREEZE_PATH = SPLITS_DIR / "FREEZE.txt"

SPLIT_ID = "secvul-split-v1"
SEED = 42
PROTOCOL_REF = "research/evaluation_protocol.md#4"

DETECTION_DEV_VULNERABLE = 32
DETECTION_DEV_NON_VULNERABLE = 8
DETECTION_TEST_VULNERABLE = 128
DETECTION_TEST_NON_VULNERABLE = 32
PAIR_DEV_COUNT = 20
PAIR_TEST_COUNT = 180

# Ordered CWE-family table from protocol section 4.5.  The order is also the
# deterministic priority for the rare CWEs that appear in two rows (190).
FAMILIES: tuple[tuple[str, frozenset[int]], ...] = (
    ("memory_buffer", frozenset({119, 120, 121, 122, 124, 125, 126, 127, 131, 190, 680, 787, 788})),
    ("lifetime", frozenset({401, 415, 416, 562, 590, 761, 772})),
    ("null_pointer", frozenset({476, 690})),
    ("input_validation", frozenset({20, 22, 74, 77, 78, 79, 88, 89, 90, 91, 94, 99, 116, 129, 133, 134, 185, 186, 601, 611, 918})),
    ("integer", frozenset({189, 191, 194, 195, 196, 197, 369})),
    ("race", frozenset({362, 364, 366, 367, 368, 370, 667})),
    ("resource", frozenset({400, 404, 770, 771, 775})),
)
FAMILY_ORDER = tuple(name for name, _ in FAMILIES) + ("other",)
FAMILY_OF_CWE = {cwe: name for name, members in FAMILIES for cwe in members}

FORBIDDEN_NOTE_PATTERNS = (
    r"CVE-\d",
    r"CWE-\d",
    r"NVD-CWE",
    r"fixed_func_idx",
    r"changed_lines",
    r"changed_statements",
    r"commit_id",
    r"commit message",
)


class SplitError(RuntimeError):
    """Raised when a frozen invariant cannot be satisfied."""


# --------------------------------------------------------------------------- #
# Small deterministic helpers
# --------------------------------------------------------------------------- #

def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def tie_key(prefix: str, ident: str) -> str:
    return sha256_text(f"{prefix}:{ident}")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dump_json(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def read_json(path: Path) -> tuple[Any, bytes, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SplitError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SplitError(f"{path} is not valid UTF-8 JSON: {exc}") from exc
    return data, raw, sha256_bytes(raw)


def cwe_family(record: dict[str, Any]) -> str:
    """First numeric CWE decides the family; non-numeric markers are 'other'."""
    for value in record.get("cwe_list") or []:
        if isinstance(value, str) and value.startswith("CWE-") and value[4:].isdigit():
            return FAMILY_OF_CWE.get(int(value[4:]), "other")
    return "other"


class Quartiles:
    """Inclusive quartile bins (1-4) with a fixed, reproducible boundary rule."""

    def __init__(self, lengths: Iterable[int]) -> None:
        values = sorted(lengths)
        if len(values) < 2:
            raise SplitError("need at least two lengths to compute quartiles")
        self.cuts = statistics.quantiles(values, n=4, method="inclusive")

    def __call__(self, length: int) -> int:
        q1, q2, q3 = self.cuts
        if length <= q1:
            return 1
        if length <= q2:
            return 2
        if length <= q3:
            return 3
        return 4


def code_sha(text: str) -> str:
    return sha256_text(text)


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #

def _group_by_project(records: Iterable[dict[str, Any]], key: Any) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[key(record)].append(record)
    return dict(groups)


def _greedy_cover(
    pool: list[dict[str, Any]],
    *,
    count: int,
    family_of: Any,
    quartile_of: Any,
    tie_of: Any,
    require_families: bool,
    label: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Pick ``count`` items, covering families first, then balancing quartiles.

    Family coverage comes first; after that each pick minimises the number of
    already-selected items in the same (family, quartile) cell, then the
    global quartile count, then the family count, and finally the hash tie
    break.  Returns the picked items and a parallel list of reasons.
    """
    if len(pool) < count:
        raise SplitError(
            f"{label}: need {count} items but the candidate pool has {len(pool)}"
        )
    family_count: Counter[str] = Counter()
    family_quartile_count: Counter[tuple[str, int]] = Counter()
    quartile_count: Counter[int] = Counter()
    picked: list[dict[str, Any]] = []
    reasons: list[str] = []
    used: set[int] = set()

    def take(item: dict[str, Any], reason: str) -> None:
        picked.append(item)
        reasons.append(reason)
        used.add(id(item))
        family_count[family_of(item)] += 1
        family_quartile_count[(family_of(item), quartile_of(item))] += 1
        quartile_count[quartile_of(item)] += 1

    if require_families:
        for family in FAMILY_ORDER:
            candidates = [item for item in pool if family_of(item) == family and id(item) not in used]
            if not candidates:
                continue
            best = min(
                candidates,
                key=lambda item: (
                    family_quartile_count[(family_of(item), quartile_of(item))],
                    quartile_count[quartile_of(item)],
                    tie_of(item),
                ),
            )
            take(best, f"family_coverage:{family}")

    while len(picked) < count:
        candidates = [item for item in pool if id(item) not in used]
        if not candidates:
            raise SplitError(f"{label}: candidate pool exhausted after {len(picked)} picks")
        best = min(
            candidates,
            key=lambda item: (
                family_quartile_count[(family_of(item), quartile_of(item))],
                quartile_count[quartile_of(item)],
                family_count[family_of(item)],
                tie_of(item),
            ),
        )
        take(best, "fill")

    return picked, reasons


def select_detection(
    samples: list[dict[str, Any]],
    *,
    forced_test_projects: set[str],
) -> dict[str, Any]:
    """Project-level detection split (40 dev / 160 test)."""
    groups = _group_by_project(samples, lambda record: record["project"])
    singleton = {project for project, records in groups.items() if len(records) == 1}
    multi = {project for project, records in groups.items() if len(records) > 1}

    quartiles = Quartiles(len(record["func_body"]) for record in samples)
    pool_projects = sorted(singleton - forced_test_projects)
    pool = [groups[project][0] for project in pool_projects]
    vulnerable_pool = [record for record in pool if record["is_vulnerable"] is True]
    non_vulnerable_pool = [record for record in pool if record["is_vulnerable"] is False]
    if len(pool) != len(vulnerable_pool) + len(non_vulnerable_pool):
        raise SplitError("detection pool contains a non-boolean label")

    def family_of(record: dict[str, Any]) -> str:
        return cwe_family(record)

    def quartile_of(record: dict[str, Any]) -> int:
        return quartiles(len(record["func_body"]))

    def tie_of(record: dict[str, Any]) -> str:
        return tie_key("split", str(record["idx"]))

    picked_v, reasons_v = _greedy_cover(
        vulnerable_pool,
        count=DETECTION_DEV_VULNERABLE,
        family_of=family_of,
        quartile_of=quartile_of,
        tie_of=tie_of,
        require_families=True,
        label="detection vulnerable dev",
    )
    picked_nv, reasons_nv = _greedy_cover(
        non_vulnerable_pool,
        count=DETECTION_DEV_NON_VULNERABLE,
        family_of=lambda record: "non_vulnerable",
        quartile_of=quartile_of,
        tie_of=tie_of,
        require_families=False,
        label="detection non-vulnerable dev",
    )

    dev = picked_v + picked_nv
    reasons = reasons_v + reasons_nv
    dev_ids = {record["idx"] for record in dev}
    dev_projects = {record["project"] for record in dev}
    test = [record for record in samples if record["idx"] not in dev_ids]
    test_projects = {record["project"] for record in test}

    if len(dev) != DETECTION_DEV_VULNERABLE + DETECTION_DEV_NON_VULNERABLE:
        raise SplitError("detection dev size mismatch")
    if len(test) != DETECTION_TEST_VULNERABLE + DETECTION_TEST_NON_VULNERABLE:
        raise SplitError("detection test size mismatch")
    if dev_projects & test_projects:
        raise SplitError(f"detection project overlap: {sorted(dev_projects & test_projects)}")
    if len(dev_projects) != len(dev):
        raise SplitError("detection dev must use exactly one sample per project")

    return {
        "quartiles": quartiles,
        "pool_projects": pool_projects,
        "pool": pool,
        "dev": dev,
        "dev_reasons": reasons,
        "dev_projects": dev_projects,
        "test": test,
        "test_projects": test_projects,
        "singleton_projects": singleton,
        "multi_projects": multi,
    }


def select_pairs(
    pairs: list[dict[str, Any]],
    *,
    forced_test_projects: set[str],
) -> dict[str, Any]:
    """Project-level pair split (20 dev / 180 test); both sides stay together."""
    groups = _group_by_project(pairs, lambda pair: pair["vulnerable"]["project"])
    singleton = {project for project, records in groups.items() if len(records) == 1}
    multi = {project for project, records in groups.items() if len(records) > 1}
    quartiles = Quartiles(
        max(len(pair["vulnerable"]["func_body"]), len(pair["fixed"]["func_body"])) for pair in pairs
    )
    pool_projects = sorted(singleton - forced_test_projects)
    pool = [groups[project][0] for project in pool_projects]

    def family_of(pair: dict[str, Any]) -> str:
        return cwe_family(pair["vulnerable"])

    def quartile_of(pair: dict[str, Any]) -> int:
        return quartiles(_pair_length(pair))

    def tie_of(pair: dict[str, Any]) -> str:
        return tie_key("split", pair["pair_id"])

    picked, reasons = _greedy_cover(
        pool,
        count=PAIR_DEV_COUNT,
        family_of=family_of,
        quartile_of=quartile_of,
        tie_of=tie_of,
        require_families=True,
        label="pair dev",
    )
    dev_ids = {pair["pair_id"] for pair in picked}
    dev_projects = {pair["vulnerable"]["project"] for pair in picked}
    test = [pair for pair in pairs if pair["pair_id"] not in dev_ids]
    test_projects = {pair["vulnerable"]["project"] for pair in test}

    if len(dev_ids) != PAIR_DEV_COUNT or len(test) != PAIR_TEST_COUNT:
        raise SplitError("pair dev/test size mismatch")
    if dev_projects & test_projects:
        raise SplitError(f"pair project overlap: {sorted(dev_projects & test_projects)}")
    if len(dev_projects) != len(picked):
        raise SplitError("pair dev must use exactly one pair per project")

    return {
        "quartiles": quartiles,
        "pool_projects": pool_projects,
        "pool": pool,
        "dev": picked,
        "dev_reasons": reasons,
        "dev_projects": dev_projects,
        "test": test,
        "test_projects": test_projects,
        "singleton_projects": singleton,
        "multi_projects": multi,
    }


def _pair_length(pair: dict[str, Any]) -> int:
    return max(len(pair["vulnerable"]["func_body"]), len(pair["fixed"]["func_body"]))


# --------------------------------------------------------------------------- #
# Few-shot example selection
# --------------------------------------------------------------------------- #

def load_example_selection(
    detection_dev: list[dict[str, Any]],
    pair_dev: list[dict[str, Any]],
    detection_quartiles: Quartiles,
    pair_quartiles: Quartiles,
) -> dict[str, Any]:
    """Load the curated few-shot examples and verify every frozen constraint.

    The examples are hand-picked from the dev split (never from test) and
    frozen together with the split.  The file records the selection reason so
    the choice is auditable; the constraints below are enforced, not assumed.
    """
    data, _, _ = read_json(NOTES_PATH)
    if not isinstance(data, dict):
        raise SplitError(f"{NOTES_PATH}: top level must be an object")

    detection_items = data.get("detection")
    repair_items = data.get("repair")
    if not isinstance(detection_items, list) or not isinstance(repair_items, list):
        raise SplitError(f"{NOTES_PATH}: 'detection' and 'repair' must be arrays")
    if len(detection_items) != 4:
        raise SplitError(f"{NOTES_PATH}: exactly four detection examples are required")
    if len(repair_items) != 2:
        raise SplitError(f"{NOTES_PATH}: exactly two repair examples are required")

    det_by_idx = {record["idx"]: record for record in detection_dev}
    pair_by_id = {pair["pair_id"]: pair for pair in pair_dev}
    detection: list[tuple[dict[str, Any], str]] = []
    notes: dict[str, str] = {}
    seen_idx: set[int] = set()
    for position, item in enumerate(detection_items):
        where = f"detection[{position}]"
        if not isinstance(item, dict):
            raise SplitError(f"{NOTES_PATH}: {where} must be an object")
        idx = item.get("idx")
        if not isinstance(idx, int) or isinstance(idx, bool):
            raise SplitError(f"{NOTES_PATH}: {where}.idx must be an integer")
        if idx not in det_by_idx:
            raise SplitError(f"{NOTES_PATH}: {where}.idx={idx} is not in the detection dev split")
        if idx in seen_idx:
            raise SplitError(f"{NOTES_PATH}: duplicate detection example idx={idx}")
        seen_idx.add(idx)
        rationale = item.get("rationale")
        _validate_note(rationale, f"{where}.rationale")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise SplitError(f"{NOTES_PATH}: {where}.reason is required")
        record = det_by_idx[idx]
        detection.append((record, reason))
        notes[f"det:{idx}"] = rationale  # type: ignore[index]

    labels = [record["is_vulnerable"] for record, _ in detection]
    if labels != [True, False, True, False]:
        raise SplitError(
            f"{NOTES_PATH}: detection examples must be ordered V, NV, V, NV; got {labels}"
        )
    if cwe_family(detection[0][0]) == cwe_family(detection[2][0]):
        raise SplitError(f"{NOTES_PATH}: the two vulnerable examples must be from different CWE families")
    if detection_quartiles(len(detection[1][0]["func_body"])) == detection_quartiles(
        len(detection[3][0]["func_body"])
    ):
        raise SplitError(f"{NOTES_PATH}: the two non-vulnerable examples must be from different quartiles")

    repair: list[tuple[dict[str, Any], str]] = []
    seen_pair: set[str] = set()
    for position, item in enumerate(repair_items):
        where = f"repair[{position}]"
        if not isinstance(item, dict):
            raise SplitError(f"{NOTES_PATH}: {where} must be an object")
        pair_id = item.get("pair_id")
        if not isinstance(pair_id, str) or not pair_id:
            raise SplitError(f"{NOTES_PATH}: {where}.pair_id must be a string")
        if pair_id not in pair_by_id:
            raise SplitError(f"{NOTES_PATH}: {where}.pair_id={pair_id} is not in the pair dev split")
        if pair_id in seen_pair:
            raise SplitError(f"{NOTES_PATH}: duplicate repair example pair_id={pair_id}")
        seen_pair.add(pair_id)
        explanation = item.get("explanation")
        _validate_note(explanation, f"{where}.explanation")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise SplitError(f"{NOTES_PATH}: {where}.reason is required")
        pair = pair_by_id[pair_id]
        repair.append((pair, reason))
        notes[f"repair:{pair_id}"] = explanation  # type: ignore[index]

    repair_families = [cwe_family(pair["vulnerable"]) for pair, _ in repair]
    if sorted(repair_families) != ["input_validation", "memory_buffer"]:
        raise SplitError(
            f"{NOTES_PATH}: repair examples must cover memory_buffer and input_validation; got {repair_families}"
        )
    return {"detection": detection, "repair": repair, "notes": notes}


# --------------------------------------------------------------------------- #
# Artifact construction
# --------------------------------------------------------------------------- #

def _detection_record(
    record: dict[str, Any],
    *,
    quartiles: Quartiles,
    reason: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "idx": record["idx"],
        "project": record["project"],
        "label": record["is_vulnerable"],
        "cwe_family": cwe_family(record),
        "length_quartile": quartiles(len(record["func_body"])),
        "function_chars": len(record["func_body"]),
        "code_sha256": code_sha(record["func_body"]),
    }
    if reason is not None:
        entry["selection"] = reason
    return entry


def _pair_record(pair: dict[str, Any], *, quartiles: Quartiles, reason: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "pair_id": pair["pair_id"],
        "project": pair["vulnerable"]["project"],
        "vulnerable_idx": pair["vulnerable"]["idx"],
        "fixed_idx": pair["fixed"]["idx"],
        "cwe_family": cwe_family(pair["vulnerable"]),
        "length_quartile": quartiles(_pair_length(pair)),
        "max_function_chars": _pair_length(pair),
        "vulnerable_code_sha256": code_sha(pair["vulnerable"]["func_body"]),
        "fixed_code_sha256": code_sha(pair["fixed"]["func_body"]),
    }
    if reason is not None:
        entry["selection"] = reason
    return entry


def _distribution(entries: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts = Counter(str(entry[key]) for entry in entries)
    return {name: counts[name] for name in sorted(counts)}


def _dataset_metadata(
    source_metadata: dict[str, Any],
    *,
    source_path: Path,
    source_sha: str,
    role: str,
    task: str,
    metadata_overrides: dict[str, Any],
) -> dict[str, Any]:
    metadata = copy.deepcopy(source_metadata)
    metadata.update(metadata_overrides)
    metadata["split"] = {
        "split_id": SPLIT_ID,
        "role": role,
        "task": task,
        "seed": SEED,
        "source_dataset": str(source_path.relative_to(ROOT)).replace("\\", "/"),
        "source_dataset_sha256": source_sha,
        "manifest": "splits/split_v1.json",
        "protocol": PROTOCOL_REF,
    }
    return metadata


def build_detection_dataset(
    source: dict[str, Any],
    source_path: Path,
    source_sha: str,
    records: list[dict[str, Any]],
    *,
    role: str,
) -> dict[str, Any]:
    vulnerable = sum(1 for record in records if record["is_vulnerable"] is True)
    non_vulnerable = len(records) - vulnerable
    metadata = _dataset_metadata(
        source.get("metadata", {}),
        source_path=source_path,
        source_sha=source_sha,
        role=role,
        task="detection",
        metadata_overrides={
            "sample_count": len(records),
            "vulnerable_count": vulnerable,
            "non_vulnerable_count": non_vulnerable,
        },
    )
    return {"metadata": metadata, "samples": copy.deepcopy(records)}


def build_pair_dataset(
    source: dict[str, Any],
    source_path: Path,
    source_sha: str,
    pairs: list[dict[str, Any]],
    *,
    role: str,
) -> dict[str, Any]:
    metadata = _dataset_metadata(
        source.get("metadata", {}),
        source_path=source_path,
        source_sha=source_sha,
        role=role,
        task="pairs",
        metadata_overrides={
            "pair_count": len(pairs),
            "function_count": len(pairs) * 2,
        },
    )
    return {"metadata": metadata, "pairs": copy.deepcopy(pairs)}


# --------------------------------------------------------------------------- #
# Validation of the hand-written few-shot prose
# --------------------------------------------------------------------------- #

def _validate_note(text: Any, where: str) -> None:
    if not isinstance(text, str) or not text.strip():
        raise SplitError(f"{NOTES_PATH}: {where} must be a non-empty string")
    if len(text) > 500:
        raise SplitError(f"{NOTES_PATH}: {where} is longer than 500 characters")
    if "\n" in text:
        raise SplitError(f"{NOTES_PATH}: {where} must be a single line")
    for pattern in FORBIDDEN_NOTE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            raise SplitError(f"{NOTES_PATH}: {where} matches forbidden marker {pattern!r}")


# --------------------------------------------------------------------------- #
# Bijection / integrity checks
# --------------------------------------------------------------------------- #

def _all_detection_records(selection: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return selection["dev"], selection["test"]


def _all_pair_records(selection: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return selection["dev"], selection["test"]


def _assert_records_equal(source: list[dict[str, Any]], derived: list[dict[str, Any]], label: str) -> None:
    source_by_id = {record["idx"]: record for record in source}
    for record in derived:
        if source_by_id.get(record["idx"]) != record:
            raise SplitError(f"{label}: record idx={record['idx']} differs from the source dataset")


def _assert_pairs_equal(source: list[dict[str, Any]], derived: list[dict[str, Any]], label: str) -> None:
    source_by_id = {pair["pair_id"]: pair for pair in source}
    for pair in derived:
        if source_by_id.get(pair["pair_id"]) != pair:
            raise SplitError(f"{label}: pair {pair['pair_id']} differs from the source dataset")


def check_invariants(
    *,
    detection: dict[str, Any],
    pairs: dict[str, Any],
    source_detection: list[dict[str, Any]],
    source_pairs: list[dict[str, Any]],
    detection_singleton: set[str],
) -> dict[str, Any]:
    dev_det, test_det = _all_detection_records(detection)
    dev_pairs, test_pairs = _all_pair_records(pairs)

    dev_det_ids = [record["idx"] for record in dev_det]
    test_det_ids = [record["idx"] for record in test_det]
    dev_pair_ids = [pair["pair_id"] for pair in dev_pairs]
    test_pair_ids = [pair["pair_id"] for pair in test_pairs]

    if len(set(dev_det_ids)) != len(dev_det_ids) or len(set(test_det_ids)) != len(test_det_ids):
        raise SplitError("duplicate detection idx within a split")
    if set(dev_det_ids) & set(test_det_ids):
        raise SplitError("detection idx overlap between dev and test")
    if set(dev_det_ids) | set(test_det_ids) != {record["idx"] for record in source_detection}:
        raise SplitError("detection split is not a partition of the source dataset")
    if set(dev_pair_ids) & set(test_pair_ids):
        raise SplitError("pair_id overlap between dev and test")
    if set(dev_pair_ids) | set(test_pair_ids) != {pair["pair_id"] for pair in source_pairs}:
        raise SplitError("pair split is not a partition of the source dataset")

    dev_det_projects = {record["project"] for record in dev_det}
    test_det_projects = {record["project"] for record in test_det}
    dev_pair_projects = {pair["vulnerable"]["project"] for pair in dev_pairs}
    test_pair_projects = {pair["vulnerable"]["project"] for pair in test_pairs}
    dev_projects = dev_det_projects | dev_pair_projects
    test_projects = test_det_projects | test_pair_projects
    if dev_det_projects & test_det_projects:
        raise SplitError("detection project overlap")
    if dev_pair_projects & test_pair_projects:
        raise SplitError("pair project overlap")
    cross_a = sorted(dev_det_projects & test_pair_projects)
    cross_b = sorted(dev_pair_projects & test_det_projects)

    dev_codes: set[str] = set()
    for record in dev_det:
        dev_codes.add(code_sha(record["func_body"]))
    for pair in dev_pairs:
        dev_codes.add(code_sha(pair["vulnerable"]["func_body"]))
        dev_codes.add(code_sha(pair["fixed"]["func_body"]))
    test_codes: set[str] = set()
    for record in test_det:
        test_codes.add(code_sha(record["func_body"]))
    for pair in test_pairs:
        test_codes.add(code_sha(pair["vulnerable"]["func_body"]))
        test_codes.add(code_sha(pair["fixed"]["func_body"]))
    shared_code = dev_codes & test_codes
    if shared_code:
        raise SplitError(f"dev/test share {len(shared_code)} identical function bodies")

    dev_idx = set(dev_det_ids)
    test_idx = set(test_det_ids)
    for pair in dev_pairs:
        dev_idx.update((pair["vulnerable"]["idx"], pair["fixed"]["idx"]))
    for pair in test_pairs:
        test_idx.update((pair["vulnerable"]["idx"], pair["fixed"]["idx"]))
    if dev_idx & test_idx:
        raise SplitError(f"source idx overlap across splits: {sorted(dev_idx & test_idx)[:5]}")
    if len(dev_idx) != 40 + 40 or len(test_idx) != 160 + 360:
        raise SplitError("unexpected number of distinct source idx values")

    if len(dev_det) != 40 or sum(1 for r in dev_det if r["is_vulnerable"] is True) != 32:
        raise SplitError("detection dev must be 32 vulnerable + 8 non-vulnerable")
    if len(test_det) != 160 or sum(1 for r in test_det if r["is_vulnerable"] is True) != 128:
        raise SplitError("detection test must be 128 vulnerable + 32 non-vulnerable")
    if len(dev_pairs) != 20 or len(test_pairs) != 180:
        raise SplitError("pairs must be split 20 dev / 180 test")
    for pair in dev_pairs + test_pairs:
        if not (pair["vulnerable"]["is_vulnerable"] is True and pair["fixed"]["is_vulnerable"] is False):
            raise SplitError(f"pair {pair['pair_id']} has wrong labels")
        if pair["vulnerable"]["project"] != pair["fixed"]["project"]:
            raise SplitError(f"pair {pair['pair_id']} spans projects")
        if pair["vulnerable"]["idx"] == pair["fixed"]["idx"]:
            raise SplitError(f"pair {pair['pair_id']} has identical idx")

    for project in dev_det_projects:
        if project not in detection_singleton:
            raise SplitError(f"detection dev project {project!r} is not a singleton project")

    _assert_records_equal(source_detection, dev_det, "detection dev")
    _assert_records_equal(source_detection, test_det, "detection test")
    _assert_pairs_equal(source_pairs, dev_pairs, "pairs dev")
    _assert_pairs_equal(source_pairs, test_pairs, "pairs test")

    return {
        "dev_projects": sorted(dev_projects),
        "test_projects": sorted(test_projects),
        "detection_dev_projects": sorted(dev_det_projects),
        "detection_test_projects": sorted(test_det_projects),
        "pair_dev_projects": sorted(dev_pair_projects),
        "pair_test_projects": sorted(test_pair_projects),
        "detection_dev_vs_pair_test": cross_a,
        "pair_dev_vs_detection_test": cross_b,
        "dev_idx_count": len(dev_idx),
        "test_idx_count": len(test_idx),
        "shared_code_hashes": 0,
        "dev_det_projects": len(dev_det_projects),
        "test_det_projects": len(test_det_projects),
        "dev_pair_projects": len(dev_pair_projects),
        "test_pair_projects": len(test_pair_projects),
    }


# --------------------------------------------------------------------------- #
# Full build
# --------------------------------------------------------------------------- #

def build_bundle(*, preview_only: bool = False) -> dict[str, Any]:
    independent, _, independent_sha = read_json(INDEPENDENT_PATH)
    pairs_source, _, pairs_sha = read_json(PAIRS_PATH)
    if independent.get("metadata", {}).get("seed") != SEED:
        raise SplitError(f"{INDEPENDENT_PATH}: unexpected dataset seed")
    if pairs_source.get("metadata", {}).get("seed") != SEED:
        raise SplitError(f"{PAIRS_PATH}: unexpected dataset seed")
    samples = independent.get("samples")
    pairs = pairs_source.get("pairs")
    if not isinstance(samples, list) or not isinstance(pairs, list):
        raise SplitError("dataset files do not have the expected arrays")

    ind_groups = _group_by_project(samples, lambda record: record["project"])
    pair_groups = _group_by_project(pairs, lambda pair: pair["vulnerable"]["project"])
    ind_multi = {project for project, records in ind_groups.items() if len(records) > 1}
    pair_multi = {project for project, records in pair_groups.items() if len(records) > 1}

    detection = select_detection(samples, forced_test_projects=ind_multi)
    pairs_split = select_pairs(
        pairs,
        forced_test_projects=pair_multi,
    )
    examples = load_example_selection(
        detection["dev"],
        pairs_split["dev"],
        detection["quartiles"],
        pairs_split["quartiles"],
    )
    audit = check_invariants(
        detection=detection,
        pairs=pairs_split,
        source_detection=samples,
        source_pairs=pairs,
        detection_singleton=detection["singleton_projects"],
    )
    if preview_only:
        return {
            "selection": {
                "detection": detection,
                "pairs": pairs_split,
                "examples": examples,
                "audit": audit,
            }
        }

    notes = examples["notes"]

    # ---- dataset artifacts -------------------------------------------------
    test_det_path = INDEPENDENT_PATH
    test_pair_path = PAIRS_PATH
    artifacts: dict[str, bytes] = {}

    artifacts["test_detection_160.json"] = dump_json(
        build_detection_dataset(
            independent, test_det_path, independent_sha, detection["test"], role="test"
        )
    )
    artifacts["test_pairs_180.json"] = dump_json(
        build_pair_dataset(
            pairs_source, test_pair_path, pairs_sha, pairs_split["test"], role="test"
        )
    )
    artifacts["dev_detection_40.json"] = dump_json(
        build_detection_dataset(
            independent, test_det_path, independent_sha, detection["dev"], role="dev"
        )
    )
    artifacts["dev_pairs_20.json"] = dump_json(
        build_pair_dataset(
            pairs_source, test_pair_path, pairs_sha, pairs_split["dev"], role="dev"
        )
    )

    example_records = {record["idx"] for record, _ in examples["detection"]}
    example_pair_ids = {pair["pair_id"] for pair, _ in examples["repair"]}
    pilot_detection = [record for record in detection["dev"] if record["idx"] not in example_records]
    pilot_pairs = [pair for pair in pairs_split["dev"] if pair["pair_id"] not in example_pair_ids]
    artifacts["pilot_detection_36.json"] = dump_json(
        build_detection_dataset(
            independent, test_det_path, independent_sha, pilot_detection, role="dev"
        )
    )
    artifacts["pilot_pairs_18.json"] = dump_json(
        build_pair_dataset(pairs_source, test_pair_path, pairs_sha, pilot_pairs, role="dev")
    )

    # ---- few-shot examples -------------------------------------------------
    detection_examples = []
    for record, reason in examples["detection"]:
        detection_examples.append(
            {
                "example_id": f"det-dev-{record['idx']}",
                "label": record["is_vulnerable"],
                "code": record["func_body"],
                "rationale": notes[f"det:{record['idx']}"],
                "source_idx": record["idx"],
            }
        )
    repair_examples = []
    for pair, reason in examples["repair"]:
        repair_examples.append(
            {
                "example_id": f"repair-dev-{pair['vulnerable']['idx']}-{pair['fixed']['idx']}",
                "vulnerable_code": pair["vulnerable"]["func_body"],
                "fixed_code": pair["fixed"]["func_body"],
                "explanation": notes[f"repair:{pair['pair_id']}"],
                "source_idx": pair["vulnerable"]["idx"],
                "source_fixed_idx": pair["fixed"]["idx"],
            }
        )
    examples_obj = {
        "schema_version": 1,
        "source": (
            "SecVulEval dev split (secvul-split-v1), sampled from "
            "datasets/independent_200.json and datasets/vulnerable_fixed_200_pairs.json"
        ),
        "notes": (
            "Few-shot demonstrations taken only from the frozen dev split. "
            "Code, labels and rationales are frozen in splits/example_notes.json. "
            "They are disjoint from both test files; the runner re-checks isolation."
        ),
        "detection": detection_examples,
        "repair": repair_examples,
    }
    artifacts["dev_examples_fewshot.json"] = dump_json(examples_obj)

    # ---- manifest ----------------------------------------------------------
    detection_dev_entries = [
        _detection_record(record, quartiles=detection["quartiles"], reason=reason)
        for record, reason in zip(detection["dev"], detection["dev_reasons"])
    ]
    detection_test_entries = [
        _detection_record(record, quartiles=detection["quartiles"], reason=None)
        for record in detection["test"]
    ]
    pair_dev_entries = [
        _pair_record(pair, quartiles=pairs_split["quartiles"], reason=reason)
        for pair, reason in zip(pairs_split["dev"], pairs_split["dev_reasons"])
    ]
    pair_test_entries = [
        _pair_record(pair, quartiles=pairs_split["quartiles"], reason=None)
        for pair in pairs_split["test"]
    ]

    artifacts_meta = {
        name: {"sha256": sha256_bytes(payload), "bytes": len(payload), "rows": _artifact_rows(name, payload)}
        for name, payload in sorted(artifacts.items())
    }

    manifest = {
        "schema_version": 1,
        "split_id": SPLIT_ID,
        "protocol": PROTOCOL_REF,
        "generated_by": "splits/make_splits.py",
        "seed": SEED,
        "algorithms": {
            "detection_tiebreak": "sha256('split:' + str(idx))",
            "pair_tiebreak": "sha256('split:' + pair_id)",
            "detection_example_tiebreak": "sha256('example:det:' + str(idx))",
            "repair_example_tiebreak": "sha256('example:repair:' + pair_id)",
            "length_quartiles": (
                "statistics.quantiles(sorted lengths, n=4, method='inclusive'); "
                "bins are <=q1, <=q2, <=q3, >q3"
            ),
            "cwe_family": (
                "first numeric CWE in cwe_list; families from protocol section 4.5; "
                "CWE-190 is memory_buffer by table order; non-numeric or unknown -> other"
            ),
            "project_isolation": (
                "within each task, a project belongs to exactly one split; "
                "projects that are multi-sample in that task are test-only. "
                "The protocol (§4.2) permits a project to be dev in one task and "
                "test in the other; the cross-task intersections are recorded"
            ),
        },
        "source_files": {
            "datasets/independent_200.json": {
                "sha256": independent_sha,
                "bytes": INDEPENDENT_PATH.stat().st_size,
            },
            "datasets/vulnerable_fixed_200_pairs.json": {
                "sha256": pairs_sha,
                "bytes": PAIRS_PATH.stat().st_size,
            },
            "splits/example_notes.json": {
                "sha256": sha256_bytes(NOTES_PATH.read_bytes()),
                "bytes": NOTES_PATH.stat().st_size,
            },
            "splits/make_splits.py": {
                "sha256": sha256_bytes(SCRIPT_PATH.read_bytes()),
                "bytes": SCRIPT_PATH.stat().st_size,
            },
        },
        "constraints": {
            "detection": {
                "dev": {"total": 40, "vulnerable": 32, "non_vulnerable": 8},
                "test": {"total": 160, "vulnerable": 128, "non_vulnerable": 32},
            },
            "pairs": {"dev": 20, "test": 180, "pair_sides_together": True},
            "project_level_isolation": True,
            "cross_task_project_isolation": False,
            "cross_task_policy": (
                "each task splits its projects independently, as in protocol section 4.2; "
                "a project may be dev in one task and test in the other, and the exact "
                "intersection is listed under project_isolation.cross_task"
            ),
            "shared_function_text_between_dev_and_test": False,
        },
        "length_quartiles": {
            "detection_cuts": detection["quartiles"].cuts,
            "pair_cuts": pairs_split["quartiles"].cuts,
        },
        "detection": {
            "counts": {
                "source": len(samples),
                "dev": len(detection["dev"]),
                "test": len(detection["test"]),
                "dev_vulnerable": sum(1 for r in detection["dev"] if r["is_vulnerable"]),
                "dev_non_vulnerable": sum(1 for r in detection["dev"] if not r["is_vulnerable"]),
                "test_vulnerable": sum(1 for r in detection["test"] if r["is_vulnerable"]),
                "test_non_vulnerable": sum(1 for r in detection["test"] if not r["is_vulnerable"]),
                "singleton_projects": len(detection["singleton_projects"]),
                "multi_projects": len(detection["multi_projects"]),
                "dev_candidate_projects": len(detection["pool_projects"]),
            },
            "dev": {
                "projects": sorted(detection["dev_projects"]),
                "records": detection_dev_entries,
                "cwe_family_counts": _distribution(detection_dev_entries, "cwe_family"),
                "length_quartile_counts": _distribution(detection_dev_entries, "length_quartile"),
            },
            "test": {
                "projects": sorted(detection["test_projects"]),
                "records": detection_test_entries,
                "cwe_family_counts": _distribution(detection_test_entries, "cwe_family"),
                "length_quartile_counts": _distribution(detection_test_entries, "length_quartile"),
            },
        },
        "pairs": {
            "counts": {
                "source": len(pairs),
                "dev": len(pairs_split["dev"]),
                "test": len(pairs_split["test"]),
                "singleton_projects": len(pairs_split["singleton_projects"]),
                "multi_projects": len(pairs_split["multi_projects"]),
                "dev_candidate_projects": len(pairs_split["pool_projects"]),
            },
            "dev": {
                "projects": sorted(pairs_split["dev_projects"]),
                "records": pair_dev_entries,
                "cwe_family_counts": _distribution(pair_dev_entries, "cwe_family"),
                "length_quartile_counts": _distribution(pair_dev_entries, "length_quartile"),
            },
            "test": {
                "projects": sorted(pairs_split["test_projects"]),
                "records": pair_test_entries,
                "cwe_family_counts": _distribution(pair_test_entries, "cwe_family"),
                "length_quartile_counts": _distribution(pair_test_entries, "length_quartile"),
            },
        },
        "few_shot": {
            "detection": [
                {
                    "example_id": f"det-dev-{record['idx']}",
                    "source_idx": record["idx"],
                    "project": record["project"],
                    "label": record["is_vulnerable"],
                    "cwe_family": cwe_family(record),
                    "length_quartile": detection["quartiles"](len(record["func_body"])),
                    "selection": reason,
                }
                for record, reason in examples["detection"]
            ],
            "repair": [
                {
                    "example_id": f"repair-dev-{pair['vulnerable']['idx']}-{pair['fixed']['idx']}",
                    "pair_id": pair["pair_id"],
                    "project": pair["vulnerable"]["project"],
                    "cwe_family": cwe_family(pair["vulnerable"]),
                    "length_quartile": pairs_split["quartiles"](_pair_length(pair)),
                    "max_function_chars": _pair_length(pair),
                    "selection": reason,
                }
                for pair, reason in examples["repair"]
            ],
        },
        "project_isolation": {
            "rule": "within each task, a project belongs to exactly one split",
            "detection": {
                "dev": audit["detection_dev_projects"],
                "test": audit["detection_test_projects"],
                "intersection": [],
            },
            "pairs": {
                "dev": audit["pair_dev_projects"],
                "test": audit["pair_test_projects"],
                "intersection": [],
            },
            "cross_task": {
                "note": (
                    "protocol section 4.2 splits each task independently; these projects "
                    "are dev in one task and test in the other and are listed for audit"
                ),
                "detection_dev_and_pair_test": audit["detection_dev_vs_pair_test"],
                "pair_dev_and_detection_test": audit["pair_dev_vs_detection_test"],
            },
            "forced_test_projects": {
                "detection_multi_sample": sorted(ind_multi),
                "pairs_multi_sample": sorted(pair_multi),
            },
            "dev_project_count": len(audit["dev_projects"]),
            "test_project_count": len(audit["test_projects"]),
        },
        "audit": {
            "detection_dev_test_project_intersection": [],
            "pair_dev_test_project_intersection": [],
            "cross_task_detection_dev_and_pair_test": audit["detection_dev_vs_pair_test"],
            "cross_task_pair_dev_and_detection_test": audit["pair_dev_vs_detection_test"],
            "cross_task_source_idx_intersection": [],
            "shared_code_hashes_between_dev_and_test": 0,
            "distinct_dev_source_idx": audit["dev_idx_count"],
            "distinct_test_source_idx": audit["test_idx_count"],
        },
        "artifacts": artifacts_meta,
    }
    artifacts["split_v1.json"] = dump_json(manifest)
    return {"artifacts": artifacts, "manifest": manifest, "selection": {
        "detection": detection,
        "pairs": pairs_split,
        "examples": examples,
        "audit": audit,
    }}


def _artifact_rows(name: str, payload: bytes) -> int:
    data = json.loads(payload.decode("utf-8"))
    if name.endswith("split_v1.json"):
        return 0
    if "samples" in data:
        return len(data["samples"])
    if "pairs" in data:
        return len(data["pairs"])
    return len(data.get("detection", [])) + len(data.get("repair", []))


# --------------------------------------------------------------------------- #
# Runner checks
# --------------------------------------------------------------------------- #

def runner_checks(bundle: dict[str, Any]) -> dict[str, Any]:
    """Validate generated files with the runner's own loaders, in memory."""
    runner_root = ROOT / "runner"
    if str(runner_root) not in sys.path:
        sys.path.insert(0, str(runner_root))
    try:
        from secvul_runner.datasets import load_dataset
        from secvul_runner.prompts import build_prompt, load_dev_examples
    except Exception as exc:  # noqa: BLE001 - verification boundary
        raise SplitError(f"cannot import the runner package: {exc}") from exc

    import tempfile

    report: dict[str, Any] = {}
    artifacts = bundle["artifacts"]
    with tempfile.TemporaryDirectory(prefix="secvul-split-verify-") as tmp:
        tmp_dir = Path(tmp)
        written: dict[str, Path] = {}
        for name in (
            "test_detection_160.json",
            "test_pairs_180.json",
            "dev_detection_40.json",
            "dev_pairs_20.json",
            "pilot_detection_36.json",
            "pilot_pairs_18.json",
            "dev_examples_fewshot.json",
        ):
            path = tmp_dir / name
            path.write_bytes(artifacts[name])
            written[name] = path

        det_ds = load_dataset(written["test_detection_160.json"], "independent")
        pair_ds = load_dataset(written["test_pairs_180.json"], "pairs")
        dev_det_ds = load_dataset(written["dev_detection_40.json"], "independent")
        dev_pair_ds = load_dataset(written["dev_pairs_20.json"], "pairs")
        pilot_det_ds = load_dataset(written["pilot_detection_36.json"], "independent")
        pilot_pair_ds = load_dataset(written["pilot_pairs_18.json"], "pairs")

        report["test_detection"] = {
            "units": det_ds.unit_count,
            "sha256": det_ds.sha256,
            "labels": _label_counts(det_ds),
        }
        report["test_pairs"] = {
            "units": pair_ds.unit_count,
            "sha256": pair_ds.sha256,
            "labels": _label_counts(pair_ds),
        }
        report["dev_detection"] = {"units": dev_det_ds.unit_count, "sha256": dev_det_ds.sha256}
        report["dev_pairs"] = {"units": dev_pair_ds.unit_count, "sha256": dev_pair_ds.sha256}
        report["pilot_detection"] = {"units": pilot_det_ds.unit_count}
        report["pilot_pairs"] = {"units": pilot_pair_ds.unit_count}

        examples_path = written["dev_examples_fewshot.json"]
        for name, dataset in (
            ("test_detection", det_ds),
            ("test_pairs", pair_ds),
        ):
            examples = load_dev_examples(examples_path, dataset, "both")
            report.setdefault("dev_examples_isolation", {})[name] = examples.sha256

        examples = load_dev_examples(examples_path, det_ds, "both")
        det_sample = det_ds.units[0]
        pair_sample = pair_ds.units[0].vulnerable  # type: ignore[union-attr]
        det_prompt = build_prompt(det_sample, "detection", "few-shot", examples)  # type: ignore[arg-type]
        rep_prompt = build_prompt(pair_sample, "repair", "few-shot", examples)  # type: ignore[arg-type]
        report["prompt_messages"] = {
            "detection_few_shot": len(det_prompt.messages),
            "repair_few_shot": len(rep_prompt.messages),
            "detection_example_ids": det_prompt.metadata["dev_example_ids"],
            "repair_example_ids": rep_prompt.metadata["dev_example_ids"],
        }

        # Pilot files must accept the same examples (few-shot smoke tests).
        load_dev_examples(examples_path, pilot_det_ds, "both")
        load_dev_examples(examples_path, pilot_pair_ds, "both")
    return report


def _label_counts(dataset: Any) -> dict[str, int]:
    samples = dataset.all_samples
    vulnerable = sum(1 for sample in samples if sample.label)
    return {"functions": len(samples), "vulnerable": vulnerable, "non_vulnerable": len(samples) - vulnerable}


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def _write_artifacts(bundle: dict[str, Any]) -> None:
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    for name, payload in sorted(bundle["artifacts"].items()):
        (SPLITS_DIR / name).write_bytes(payload)


def cmd_preview() -> int:
    bundle = build_bundle(preview_only=True)
    selection = bundle["selection"]
    det = selection["detection"]
    prs = selection["pairs"]
    print(f"split_id={SPLIT_ID} seed={SEED}")
    print(
        f"detection: dev={len(det['dev'])} "
        f"(V={sum(1 for r in det['dev'] if r['is_vulnerable'])},"
        f"NV={sum(1 for r in det['dev'] if not r['is_vulnerable'])}) "
        f"test={len(det['test'])}"
    )
    print(f"  dev projects={len(det['dev_projects'])} test projects={len(det['test_projects'])}")
    print(f"  detection dev families={dict(sorted(Counter(cwe_family(r) for r in det['dev']).items()))}")
    print(f"  detection quartet={dict(sorted(Counter(det['quartiles'](len(r['func_body'])) for r in det['dev']).items()))}")
    print(f"pairs: dev={len(prs['dev'])} test={len(prs['test'])}")
    print(f"  dev projects={len(prs['dev_projects'])} test projects={len(prs['test_projects'])}")
    print(f"  pair dev families={dict(sorted(Counter(cwe_family(p['vulnerable']) for p in prs['dev']).items()))}")
    print(f"pair dev quartile={dict(sorted(Counter(prs['quartiles'](_pair_length(p)) for p in prs['dev']).items()))}")
    print(f"global dev projects={len(selection['audit']['dev_projects'])}")
    print(f"global test projects={len(selection['audit']['test_projects'])}")
    print(
        "cross-task (allowed by protocol, recorded): "
        f"det-dev&pair-test={selection['audit']['detection_dev_vs_pair_test']} "
        f"pair-dev&det-test={selection['audit']['pair_dev_vs_detection_test']}"
    )

    print("\n=== few-shot detection candidates ===")
    for record, reason in selection["examples"]["detection"]:
        print(
            f"\n-- idx={record['idx']} project={record['project']} "
            f"label={record['is_vulnerable']} family={cwe_family(record)} "
            f"q={det['quartiles'](len(record['func_body']))} reason={reason}"
        )
        print(f"func_name={record['func_name']} chars={len(record['func_body'])}")
        print(record["func_body"])
        if record["is_vulnerable"]:
            print("--- changed_statements (source fix hint) ---")
            print(json.dumps(record.get("changed_statements"), ensure_ascii=False)[:1200])

    print("\n=== few-shot repair candidates ===")
    for pair, reason in selection["examples"]["repair"]:
        print(
            f"\n-- pair_id={pair['pair_id']} project={pair['vulnerable']['project']} "
            f"family={cwe_family(pair['vulnerable'])} "
            f"q={prs['quartiles'](_pair_length(pair))} reason={reason}"
        )
        print("--- vulnerable ---")
        print(pair["vulnerable"]["func_body"])
        print("--- fixed ---")
        print(pair["fixed"]["func_body"])
    return 0


def cmd_build(force: bool) -> int:
    if FREEZE_PATH.exists() and not force:
        raise SplitError(
            f"{FREEZE_PATH} exists; the split is frozen. Re-run with --force only for a new split id."
        )
    bundle = build_bundle()
    runner_report = runner_checks(bundle)
    _write_artifacts(bundle)
    print(f"wrote {len(bundle['artifacts'])} files to {SPLITS_DIR}")
    print(json.dumps(runner_report, indent=2, ensure_ascii=False))
    print("run `python3 splits/make_splits.py freeze` to record the hashes")
    return 0


def _fmt_hash_line(name: str, digest: str) -> str:
    return f"  {name}: {digest}"


def cmd_freeze(force: bool) -> int:
    if FREEZE_PATH.exists() and not force:
        raise SplitError(f"{FREEZE_PATH} exists; refusing to overwrite a freeze record without --force")
    bundle = build_bundle()
    runner_report = runner_checks(bundle)
    for name, payload in bundle["artifacts"].items():
        on_disk = SPLITS_DIR / name
        if not on_disk.exists() or on_disk.read_bytes() != payload:
            raise SplitError(f"{on_disk} is missing or differs from a fresh build; run `build` first")
    lines = [
        "SecVulEval split freeze record",
        f"split_id: {SPLIT_ID}",
        f"seed: {SEED}",
        f"protocol: {PROTOCOL_REF}",
        f"generated_utc: {_utc_now()}",
        "",
        "source_sha256:",
    ]
    for name, info in bundle["manifest"]["source_files"].items():
        lines.append(_fmt_hash_line(name, info["sha256"]))
    lines += [
        "",
        "artifact_sha256:",
    ]
    for name in sorted(bundle["artifacts"]):
        lines.append(_fmt_hash_line(name, sha256_bytes(bundle["artifacts"][name])))
    lines += [
        "",
        "runner_checks: passed",
        f"  test_detection units: {runner_report['test_detection']['units']}",
        f"  test_pairs units: {runner_report['test_pairs']['units']}",
        "",
        "verify_with: python3 splits/make_splits.py verify",
        "Do not edit any frozen file. Any change requires a new split_id and a new freeze record.",
        "",
    ]
    FREEZE_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {FREEZE_PATH}")
    for line in lines:
        print(line)
    return 0


def cmd_verify() -> int:
    bundle = build_bundle()
    failures: list[str] = []
    for name, payload in sorted(bundle["artifacts"].items()):
        path = SPLITS_DIR / name
        if not path.exists():
            failures.append(f"missing {path}")
            continue
        if path.read_bytes() != payload:
            failures.append(f"{path} differs from a fresh build")
    if FREEZE_PATH.exists():
        recorded: dict[str, str] = {}
        source_recorded: dict[str, str] = {}
        for line in FREEZE_PATH.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s{2}([A-Za-z0-9_.\-]+): ([0-9a-f]{64})$", line)
            if match:
                recorded[match.group(1)] = match.group(2)
            source_match = re.match(r"^\s{2}([A-Za-z0-9_./\-]+): ([0-9a-f]{64})$", line)
            if source_match:
                source_recorded[source_match.group(1)] = source_match.group(2)
        for name, payload in sorted(bundle["artifacts"].items()):
            expected = recorded.get(name)
            actual = sha256_bytes(payload)
            if expected is None:
                failures.append(f"FREEZE.txt has no hash for {name}")
            elif expected != actual:
                failures.append(f"FREEZE.txt hash mismatch for {name}")
        for name, info in bundle["manifest"]["source_files"].items():
            expected = source_recorded.get(name)
            if expected is None:
                failures.append(f"FREEZE.txt has no source hash for {name}")
            elif expected != info["sha256"]:
                failures.append(f"FREEZE.txt source hash mismatch for {name}")
    else:
        failures.append(f"{FREEZE_PATH} is missing")

    runner_report = runner_checks(bundle)
    selection = bundle["selection"]
    audit = selection["audit"]
    print("split verification")
    print(f"  artifacts: {len(bundle['artifacts'])}")
    print(
        f"  detection: dev={len(selection['detection']['dev'])} "
        f"test={len(selection['detection']['test'])}; "
        f"projects dev={len(audit['detection_dev_projects'])} "
        f"test={len(audit['detection_test_projects'])} "
        f"intersection={len(set(audit['detection_dev_projects']) & set(audit['detection_test_projects']))}"
    )
    print(
        f"  pairs: dev={len(selection['pairs']['dev'])} "
        f"test={len(selection['pairs']['test'])}; "
        f"projects dev={len(audit['pair_dev_projects'])} "
        f"test={len(audit['pair_test_projects'])} "
        f"intersection={len(set(audit['pair_dev_projects']) & set(audit['pair_test_projects']))}"
    )
    print(
        f"  cross-task project overlap (allowed, recorded): "
        f"det-dev/pair-test={len(audit['detection_dev_vs_pair_test'])}, "
        f"pair-dev/det-test={len(audit['pair_dev_vs_detection_test'])}"
    )
    print(f"  source idx: dev={audit['dev_idx_count']} test={audit['test_idx_count']} overlap=0")
    print(f"  shared function bodies dev/test: {audit['shared_code_hashes']}")
    print(
        f"  runner: test_detection={runner_report['test_detection']['units']} units, "
        f"test_pairs={runner_report['test_pairs']['units']} units"
    )
    if failures:
        print("\nFAILED:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\nOK: artifacts match a fresh build and the freeze record")
    return 0


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preview", help="show the selected split without writing files")
    build_parser = sub.add_parser("build", help="write all split artifacts")
    build_parser.add_argument("--force", action="store_true", help="overwrite an existing freeze")
    freeze_parser = sub.add_parser("freeze", help="hash the artifacts into FREEZE.txt")
    freeze_parser.add_argument("--force", action="store_true", help="overwrite an existing freeze record")
    sub.add_parser("verify", help="rebuild in memory and verify the frozen files")
    args = parser.parse_args(argv)

    try:
        if args.command == "preview":
            return cmd_preview()
        if args.command == "build":
            return cmd_build(args.force)
        if args.command == "freeze":
            return cmd_freeze(args.force)
        if args.command == "verify":
            return cmd_verify()
    except SplitError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Load unit records (README section 3), select a run's units, load L3 evidence."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import JULIET_FULL_DIR, PROJECT_ROOT

SPLIT_PATH = PROJECT_ROOT / "juliet" / "full_split_v1.json"
SUBSETS_PATH = JULIET_FULL_DIR / "data" / "build" / "subsets.json"
CLANG_EVIDENCE_TEMPLATE = JULIET_FULL_DIR / "static" / "results" / "clang_sa" / "{layer}" / "evidence.jsonl"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _old_format_units(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pre-contract file (fields lab, variant, code): rows are bad/good pairs in split order."""
    groups = json.loads(SPLIT_PATH.read_text())["groups"]
    if len(rows) != 2 * len(groups):
        raise ValueError(f"old-format file has {len(rows)} rows, expected {2 * len(groups)}")
    units = []
    for index, row in enumerate(rows):
        group = groups[index // 2]
        if str(row["variant"]) != group["variant"]:
            raise ValueError(f"old-format row {index}: variant mismatch with split")
        label = row["lab"]
        units.append({
            **{k: group[k] for k in ("group_id", "family", "variant", "flow_category", "mechanism",
                                     "language", "set", "fold")},
            "unit_id": f"{group['group_id']}__{label}",
            "label": label,
            "truth": 1 if label == "bad" else 0,
            "good_kind": None,
            "model_text": row["code"],
            "line_map": None,
            "source_format": "old",
        })
    return units


def load_units(path: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if rows and "lab" in rows[0] and "unit_id" not in rows[0]:
        return _old_format_units(rows)
    for row in rows:
        for key in ("unit_id", "group_id", "label", "set", "language", "model_text"):
            if key not in row:
                raise ValueError(f"unit record missing {key!r}: {row.get('unit_id')}")
    return rows


def stratified_order(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic round-robin over (flow_category, mechanism, label) strata, so a
    --limit prefix covers categories and both labels."""
    strata: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for unit in sorted(units, key=lambda u: u["unit_id"]):
        strata[(unit.get("flow_category"), unit.get("mechanism"), unit["label"])].append(unit)
    keys = sorted(strata, key=lambda k: tuple(str(x) for x in k))
    ordered = []
    while any(strata[k] for k in keys):
        for key in keys:
            if strata[key]:
                ordered.append(strata[key].pop(0))
    return ordered


def select_units(
    units: list[dict[str, Any]],
    set_name: str,
    subset: str | None = None,
    subsets_path: Path = SUBSETS_PATH,
    unit_ids: list[str] | None = None,
    limit: int | None = None,
    exclude_unit_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    chosen = [u for u in units if u["set"] == set_name]
    if subset:
        groups = set(json.loads(Path(subsets_path).read_text())[subset])
        chosen = [u for u in chosen if u["group_id"] in groups]
    if unit_ids is not None:
        wanted = set(unit_ids)
        chosen = [u for u in chosen if u["unit_id"] in wanted]
        missing = wanted - {u["unit_id"] for u in chosen}
        if missing:
            raise ValueError(f"{len(missing)} requested unit ids not in set {set_name!r}: {sorted(missing)[:3]}")
    if exclude_unit_ids:
        chosen = [u for u in chosen if u["unit_id"] not in exclude_unit_ids]
    if limit is not None:
        chosen = stratified_order(chosen)[:limit]
    return chosen


def load_evidence(path: Path) -> dict[str, dict[str, Any]]:
    records = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            records[record["unit_id"]] = record
    return records

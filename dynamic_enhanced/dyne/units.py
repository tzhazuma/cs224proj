"""Load the frozen Juliet CWE-401 test split and verify its freeze record."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import config


@dataclass(frozen=True)
class Unit:
    unit_id: str
    unit_key: str
    group_id: str
    family: str
    variant: str
    language: str
    sources: tuple[Path, ...]
    defines: tuple[str, ...]
    label: str          # evaluation-only; never read by compile/run/verdict code
    split: str

    @property
    def compiler(self) -> str:
        return "g++" if self.language == "cpp" else "gcc"

    @property
    def std(self) -> str:
        return "-std=gnu++11" if self.language == "cpp" else "-std=gnu11"

    @property
    def source_names(self) -> frozenset[str]:
        return frozenset(path.name for path in self.sources)

    @property
    def source_paths(self) -> frozenset[str]:
        return frozenset(str(path.resolve()) for path in self.sources)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def freeze_record() -> dict:
    """Verify the subset file against the hash pinned in juliet/FREEZE.json."""
    freeze = json.loads(config.JULIET_FREEZE.read_text(encoding="utf-8"))
    actual = sha256_file(config.SUBSET)
    if freeze.get("subset_units_sha256") != actual:
        raise SystemExit(
            "frozen subset hash mismatch: "
            f"{freeze.get('subset_units_sha256')} != {actual}"
        )
    return {
        "dataset_id": freeze.get("dataset_id"),
        "subset_units": str(config.SUBSET.relative_to(config.PROJECT)),
        "subset_units_sha256": actual,
        "freeze_file": str(config.JULIET_FREEZE.relative_to(config.PROJECT)),
        "freeze_file_sha256": sha256_file(config.JULIET_FREEZE),
    }


def load_test_units() -> list[Unit]:
    rows = [row for row in read_jsonl(config.SUBSET) if row.get("split") == "test"]
    if len(rows) != 140:
        raise SystemExit(f"expected 140 frozen test units, found {len(rows)}")
    bad = sum(1 for row in rows if row["label"] == "bad")
    good = sum(1 for row in rows if row["label"] == "good")
    if (bad, good) != (70, 70):
        raise SystemExit(f"expected 70 bad / 70 good, found {bad}/{good}")
    groups = {row["group_id"] for row in rows}
    if len(groups) != 70:
        raise SystemExit(f"expected 70 groups, found {len(groups)}")
    rows.sort(key=lambda row: row["unit_id"])
    units = []
    for index, row in enumerate(rows, 1):
        sources = tuple(config.JULIET / rel for rel in row["sources"])
        missing = [str(path) for path in sources if not path.is_file()]
        if missing:
            raise SystemExit(f"{row['unit_id']}: missing sources {missing}")
        units.append(
            Unit(
                unit_id=row["unit_id"],
                unit_key=f"d{index:04d}",
                group_id=row["group_id"],
                family=row["family"],
                variant=row["variant"],
                language=row["language"],
                sources=sources,
                defines=tuple(row.get("defines") or ()),
                label=row["label"],
                split=row["split"],
            )
        )
    return units


def unit_input_hashes(units: list[Unit]) -> list[dict]:
    return [
        {
            "unit_id": unit.unit_id,
            "sources": [
                {
                    "path": str(path.relative_to(config.PROJECT)),
                    "sha256": sha256_file(path),
                }
                for path in unit.sources
            ],
        }
        for unit in units
    ]

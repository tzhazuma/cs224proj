"""Load the frozen test split and reuse the dynamic_enhanced probe/parser.

Importing ``dyne`` (read-only) rather than copying it guarantees that the
coverage run calls exactly the same unit entry as the archived run and that
leak blocks are attributed with exactly the same rule.  A copy would be free
to drift; a dependency makes the comparison point explicit.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import config

if str(config.DYNE_ROOT) not in sys.path:
    sys.path.insert(0, str(config.DYNE_ROOT))

from dyne.probe import find_entry, probe_text, write_probe  # noqa: E402
from dyne.parse import classify, summarize_run  # noqa: E402
from dyne.units import (  # noqa: E402
    Unit,
    freeze_record,
    load_test_units,
    read_jsonl,
    sha256_file,
    sha256_text,
    unit_input_hashes,
)

__all__ = [
    "Unit",
    "classify",
    "config",
    "find_entry",
    "freeze_record",
    "load_test_units",
    "probe_text",
    "read_jsonl",
    "sha256_file",
    "sha256_text",
    "summarize_run",
    "unit_input_hashes",
    "write_probe",
    "owned_source_names",
    "owned_paths",
]


def owned_source_names(unit: Unit) -> set[str]:
    """Files whose coverage belongs to the unit: its sources and group headers."""
    names = set(unit.source_names)
    for parent in {path.parent for path in unit.sources}:
        for header in parent.glob(unit.group_id + "*.h"):
            names.add(header.name)
    return names


def owned_paths(unit: Unit) -> set[Path]:
    paths = {path.resolve() for path in unit.sources}
    for parent in {path.parent for path in unit.sources}:
        for header in parent.glob(unit.group_id + "*.h"):
            paths.add(header.resolve())
    return paths


def owned_relative(path: Path, unit: Unit) -> str:
    return str(path.resolve().relative_to(config.PROJECT))

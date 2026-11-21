"""Build the 140-unit input pack with sanitized enhanced-dynamic evidence.

Read-only inputs: ``hybrid/inputs_v2`` and ``dynamic_enhanced/exports/hybrid``.
Output: ``hybrid_dynamic_enhanced/inputs/{units.jsonl,manifest.json}``.
No model is called here.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .config import INPUTS_DIR
from .evidence import build_units, write_units


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=INPUTS_DIR)
    args = parser.parse_args(argv)
    args.out = args.out.resolve()

    units, manifest = build_units()
    manifest["created_at"] = now()
    manifest = write_units(units, manifest, args.out)
    print(
        f"wrote {manifest['unit_count']} units ({manifest['label_counts']}) -> "
        f"{manifest['units_file']} sha256={manifest['units_sha256']}"
    )
    print(f"enhanced tool confusion: {manifest['enhanced_tool']['confusion']}")
    print(f"mode counts: {manifest['enhanced_mode_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

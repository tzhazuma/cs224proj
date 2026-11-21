#!/usr/bin/env python3
"""CLI entry point for the positive-claim refutation runner."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
for path in (HERE, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from evidence_verify.runner import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

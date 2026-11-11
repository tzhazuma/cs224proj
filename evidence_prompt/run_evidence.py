#!/usr/bin/env python3
"""Entry point: python3 evidence_prompt/run_evidence.py ..."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
for path in (SCRIPT_DIR, PROJECT_ROOT, PROJECT_ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from evidence_prompt.runner import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Entry point for the traditional dynamic CWE-401 evaluator."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dynleak.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

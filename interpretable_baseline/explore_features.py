#!/usr/bin/env python3
"""Descriptive per-feature AUC on dev and test.

This is an exploratory appendix, not part of the pre-registered method:
the feature family and rule directions were fixed from the task description
and the project's existing length heuristic, not selected by these AUCs.
Running it prints both splits so a reader can see the covariate shift and how
weak each individual feature is.  It does not write files or change results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_baseline import ROOT, extract_features  # noqa: E402


def auc(values: list[float], labels: list[bool]) -> float:
    pos = [value for value, label in zip(values, labels) if label]
    neg = [value for value, label in zip(values, labels) if not label]
    if not pos or not neg:
        return float("nan")
    concordant = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return concordant / (len(pos) * len(neg))


def main() -> int:
    for split, path in (
        ("dev", ROOT / "splits" / "dev_detection_40.json"),
        ("test", ROOT / "splits" / "test_detection_160.json"),
    ):
        samples = json.loads(path.read_text(encoding="utf-8"))["samples"]
        labels = [bool(sample["is_vulnerable"]) for sample in samples]
        rows = [extract_features(sample.get("func_body") or "") for sample in samples]
        print("== {} n={} pos={}".format(split, len(rows), sum(labels)))
        for name in rows[0]:
            values = [row[name] for row in rows]
            print("  {:18s} AUC {:.3f}".format(name, auc(values, labels)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

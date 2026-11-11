"""Compute transparent reference baselines on the frozen test splits."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "baseline" / "results" / "test_split_baselines.json"


def metrics(rows, predictions):
    tp = sum(row["is_vulnerable"] and pred for row, pred in zip(rows, predictions))
    fp = sum(not row["is_vulnerable"] and pred for row, pred in zip(rows, predictions))
    tn = sum(not row["is_vulnerable"] and not pred for row, pred in zip(rows, predictions))
    fn = sum(row["is_vulnerable"] and not pred for row, pred in zip(rows, predictions))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": (tp + tn) / len(rows),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "specificity": tn / (tn + fp) if tn + fp else None,
    }


def main():
    independent_path = ROOT / "splits" / "test_detection_160.json"
    pairs_path = ROOT / "splits" / "test_pairs_180.json"
    independent = json.loads(independent_path.read_text(encoding="utf-8"))["samples"]
    pairs = json.loads(pairs_path.read_text(encoding="utf-8"))["pairs"]
    pair_rows = [pair[side] for pair in pairs for side in ("vulnerable", "fixed")]
    rng = random.Random(42)
    random_sides = [rng.choice((True, False)) for _ in pairs]
    random_predictions = []
    for pair, vulnerable_first in zip(pairs, random_sides):
        random_predictions.extend((vulnerable_first, not vulnerable_first))
    joint = sum(
        predictions[0] and not predictions[1]
        for predictions in zip(random_predictions[::2], random_predictions[1::2])
    )
    result = {
        "schema_version": 1,
        "reference_baseline": True,
        "is_llm": False,
        "seed": 42,
        "sources": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (independent_path, pairs_path)
        },
        "independent": {
            name: metrics(independent, [value] * len(independent))
            for name, value in (("always_vulnerable", True), ("always_non_vulnerable", False))
        },
        "pairs": {
            "always_vulnerable": metrics(pair_rows, [True] * len(pair_rows)),
            "always_non_vulnerable": metrics(pair_rows, [False] * len(pair_rows)),
            "random_one_vulnerable_per_pair": {
                **metrics(pair_rows, random_predictions),
                "joint_correct": joint,
                "joint_accuracy": joint / len(pairs),
            },
            "constant_joint_accuracy": 0.0,
        },
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["pairs"]["random_one_vulnerable_per_pair"], indent=2))
    print(OUT)


if __name__ == "__main__":
    main()

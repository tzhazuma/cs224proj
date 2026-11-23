"""Dev units for endpoint probes, first source that holds enough distinct units:
data/build/layer1.jsonl (dev set only), data/build/layer1_sample.jsonl (dev), then the pre-plan
dump /tmp/jfull/units_old.jsonl (fields lab/variant/code).
Distinct units matter for timing: repeated texts would hit the vLLM prefix cache."""
from __future__ import annotations

import json
import random
from pathlib import Path

BUILD = Path(__file__).resolve().parents[2] / "data/build"
UNITS_OLD = Path("/tmp/jfull/units_old.jsonl")


def _layer1(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.open()]
    return [{"unit_id": r["unit_id"], "truth": r["truth"], "text": r["model_text"]} for r in rows if r["set"] == "dev"]


def _old() -> list[dict]:
    rows = [json.loads(line) for line in UNITS_OLD.open()]
    return [{"unit_id": f"old{i}__{r['lab']}", "truth": int(r["lab"] == "bad"), "text": r["code"]}
            for i, r in enumerate(rows)]


def load_probe_units(n: int, seed: int = 20261123) -> tuple[str, list[dict]]:
    """Return (source path, n distinct units as {unit_id, truth, text}), sampled reproducibly."""
    for source, loader in ((BUILD / "layer1.jsonl", lambda: _layer1(BUILD / "layer1.jsonl")),
                           (BUILD / "layer1_sample.jsonl", lambda: _layer1(BUILD / "layer1_sample.jsonl")),
                           (UNITS_OLD, _old)):
        units = loader() if source.exists() else []
        if len(units) >= n:
            random.Random(seed).shuffle(units)
            return str(source), units[:n]
    raise SystemExit(f"no probe source with {n} distinct units")

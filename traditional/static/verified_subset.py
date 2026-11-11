#!/usr/bin/env python3
"""Recompute metrics on the runtime-supported Juliet subset.

The frozen Juliet manifest contains 200 units, but only 178 have runtime
evidence that supports the label (bad with an ASan-observed leak, good
without one).  This read-only join keeps that distinction reproducible:

  python3 traditional/static/verified_subset.py \
    --manifest juliet/manifest.json \
    --predictions traditional/static/runs/juliet_formal_.../predictions.jsonl \
    --out traditional/static/runs/juliet_formal_.../metrics_verified.json

It does not modify predictions or the manifest.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from static_adapter import (  # noqa: E402
    confusion_from_rows,
    metrics_from_confusion,
    sha256_file,
    utc_now,
)


def load_units(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("units"), list):
        units = data["units"]
    elif isinstance(data, list):
        units = data
    else:
        raise SystemExit(f"{path}: expected a manifest with a units list")
    return {str(unit["unit_id"]): unit for unit in units}


def supports_label(unit: dict[str, Any]) -> bool:
    runtime = unit.get("runtime_check") or {}
    leak = runtime.get("leak_detected")
    label = unit.get("label")
    if label in (True, "bad", "vulnerable"):
        return leak is True
    if label in (False, "good", "non_vulnerable"):
        return leak is False
    return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest_path = Path(args.manifest).expanduser().resolve()
    predictions_path = Path(args.predictions).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    units = load_units(manifest_path)
    rows = [
        json.loads(line)
        for line in predictions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    supported = {unit_id for unit_id, unit in units.items() if supports_label(unit)}
    selected = [row for row in rows if row.get("sample_id") in supported]
    excluded = [row for row in rows if row.get("sample_id") not in supported]

    tools: dict[str, Any] = {}
    for tool in sorted({row["tool"] for row in selected}):
        subset = [row for row in selected if row["tool"] == tool]
        evaluable = [row for row in subset if row["status"] == "ok"]
        end_to_end = [
            row for row in subset if row["status"] in {"ok", "compile_error", "timeout"}
        ]
        tools[tool] = {
            "rows": len(subset),
            "units": len({row["sample_id"] for row in subset}),
            "status_counts": dict(Counter(row["status"] for row in subset)),
            "confusion_evaluable": confusion_from_rows(evaluable),
            "metrics_evaluable": metrics_from_confusion(
                confusion_from_rows(evaluable)
            ),
            "confusion_end_to_end": confusion_from_rows(end_to_end),
            "metrics_end_to_end": metrics_from_confusion(
                confusion_from_rows(end_to_end)
            ),
        }

    document = {
        "schema_version": "static-cwe401-verified-subset-v1",
        "generated_at": utc_now(),
        "population": {
            "definition": "label=bad with runtime_check.leak_detected=true, or label=good with runtime_check.leak_detected=false",
            "manifest_units": len(units),
            "supported_units": len(supported),
            "excluded_units": len(units) - len(supported),
            "prediction_rows_selected": len(selected),
            "prediction_rows_excluded": len(excluded),
        },
        "manifest": {
            "path": str(manifest_path),
            "sha256": sha256_file(manifest_path),
        },
        "predictions": {
            "path": str(predictions_path),
            "sha256": sha256_file(predictions_path),
        },
        "tools": tools,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "out": str(out_path),
                "supported_units": len(supported),
                "tools": {
                    tool: {
                        "n": item["metrics_evaluable"]["n"],
                        "recall": item["metrics_evaluable"]["recall"],
                        "macro_f1": item["metrics_evaluable"]["macro_f1"],
                    }
                    for tool, item in tools.items()
                },
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

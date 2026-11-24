#!/usr/bin/env python3
"""c1 latency of one dynamic reference method on the DeadFree (stress = layer3) latency300 units.

    python3 dyn_latency.py asan_lsan|dynamic_enhanced      # run under the latency lock (run_latency.py)

Same definition as the data lane's `dynamic_runs.py latency` (lane_reports/2026-11-23_data_stage4.md): units of
subsets.json latency300, concurrency 1, each method compiled and run on its own, latency_s = compile + that method's
executions; uses dynamic_runs.py's own functions (read-only import) and writes
data/results/<method>/stress/lat300_c1.jsonl + .meta.json through its write_outputs. dynamic_runs.latency() itself
is hard-wired to layer1, hence this wrapper.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
from pathlib import Path

JF = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(JF / "data"))
import dynamic_runs as dr  # noqa: E402  (data lane, read-only)

LAYER = "stress"


def main() -> None:
    method = sys.argv[1]
    assert method in dr.LAYERS[LAYER][1], method
    groups = set(json.loads((dr.BUILD / "subsets.json").read_text())["latency300"])
    units = [u for u in dr.load_units(LAYER) if u["group_id"] in groups]
    assert len(units) == 300 and all(u["set"] == "eval" for u in units), len(units)
    meta = {"run_id": "lat300_c1", "host": socket.gethostname(), "concurrency": 1, "start_utc": dr.now(),
            "loadavg_start": os.getloadavg(), "tools": dr.tool_versions(), "subset": "latency300",
            "note": "concurrency 1; method compiled and run on its own (latency_s = compile + its executions); "
                    "DeadFree units, driver analysis/deadfree/dyn_latency.py (dynamic_runs.py functions)"}
    workroot = Path(tempfile.mkdtemp(prefix="dynlat3_", dir="/tmp"))
    hooks = dr.hooks_object(workroot)
    rows = []
    for i, u in enumerate(units):
        rows += dr.unit_rows(u, LAYER, (method,), workroot, hooks)
        if (i + 1) % 50 == 0:
            print(f"{dr.now()} {method} {i + 1}/{len(units)} load {os.getloadavg()[0]:.2f}", flush=True)
    meta.update(end_utc=dr.now(), loadavg_end=os.getloadavg())
    dr.write_outputs("lat300_c1", LAYER, rows, meta)


if __name__ == "__main__":
    main()

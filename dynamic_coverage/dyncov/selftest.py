"""Synthetic control for the gcov reader and the union logic.

The control has exactly one two-way branch and no library calls.  One run
takes the true arm, a second run takes the false arm; the union must be
branch-complete while neither run alone is.  This checks the counting and the
merge direction without touching the Juliet data or any archived result.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from . import config
from .gcov import merge_coverages, run_gcov, summarize, tier


CONTROL = """\
int classify(int x)
{
    int y = 0;
    if (x > 0) {
        y = 1;
    } else {
        y = 2;
    }
    return y;
}

int main(void)
{
    return classify(XVALUE) - 1;
}
"""


def _build_and_run(work: Path, source: Path, value: int, tag: str) -> dict:
    mode_dir = work / tag
    obj_dir = mode_dir / "obj"
    obj_dir.mkdir(parents=True)
    obj = obj_dir / "control.o"
    exe = mode_dir / "control.exe"
    compile_cmd = [
        "gcc", "-O0", "-g", "--coverage", "-w", f"-DXVALUE={value}",
        "-c", str(source), "-o", str(obj),
    ]
    link_cmd = ["gcc", "--coverage", "-o", str(exe), str(obj)]
    compile_run = subprocess.run(compile_cmd, capture_output=True, text=True)
    if compile_run.returncode != 0:
        raise RuntimeError(f"selftest compile failed: {compile_run.stderr[-1000:]}")
    link_run = subprocess.run(link_cmd, capture_output=True, text=True)
    if link_run.returncode != 0:
        raise RuntimeError(f"selftest link failed: {link_run.stderr[-1000:]}")
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=20)
    coverage = run_gcov(mode_dir, [source], obj_dir)
    summary = summarize(coverage)
    return {
        "value": value,
        "returncode": run.returncode,
        "coverage": summary,
        "tier": tier(summary, bool(coverage.errors)),
        "errors": list(coverage.errors),
        "coverage_obj": coverage,
    }


def run_selftest() -> dict:
    work = Path("/tmp/dyncov_selftest")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    source = work / "control.c"
    source.write_text(CONTROL, encoding="utf-8")
    first = _build_and_run(work, source, 1, "positive")
    second = _build_and_run(work, source, -1, "negative")
    union = merge_coverages([first["coverage_obj"], second["coverage_obj"]])
    union_summary = summarize(union)

    def uncovered_lines(result: dict) -> set[int]:
        return {row["line"] for row in result["coverage"]["uncovered_lines"]}

    checks = []
    checks.append(
        {
            "name": "positive run misses the else line",
            "ok": 7 in uncovered_lines(first) and 5 not in uncovered_lines(first),
            "actual": sorted(uncovered_lines(first)),
            "expected": "7 uncovered, 5 covered",
        }
    )
    checks.append(
        {
            "name": "negative run misses the then line",
            "ok": 5 in uncovered_lines(second) and 7 not in uncovered_lines(second),
            "actual": sorted(uncovered_lines(second)),
            "expected": "5 uncovered, 7 covered",
        }
    )
    checks.append(
        {
            "name": "neither single run is branch-complete",
            "ok": first["tier"] != "branch_complete" and second["tier"] != "branch_complete",
            "actual": [first["tier"], second["tier"]],
            "expected": "both != branch_complete",
        }
    )
    checks.append(
        {
            "name": "union is line- and branch-complete",
            "ok": union_summary["line_pct"] == 1.0
            and union_summary["branch_pct"] == 1.0
            and tier(union_summary) == "branch_complete",
            "actual": {
                "line_pct": union_summary["line_pct"],
                "branch_pct": union_summary["branch_pct"],
                "tier": tier(union_summary),
            },
            "expected": "1.0 / 1.0 / branch_complete",
        }
    )
    checks.append(
        {
            "name": "branch totals are two",
            "ok": first["coverage"]["branches_total"] == 2
            and second["coverage"]["branches_total"] == 2
            and union_summary["branches_total"] == 2,
            "actual": [
                first["coverage"]["branches_total"],
                second["coverage"]["branches_total"],
                union_summary["branches_total"],
            ],
            "expected": "2, 2, 2",
        }
    )
    result = {
        "status": "PASS" if all(check["ok"] for check in checks) else "FAIL",
        "control": str(work),
        "checks": checks,
        "runs": {
            "positive": {
                "tier": first["tier"],
                "lines": [first["coverage"]["lines_hit"], first["coverage"]["lines_total"]],
                "branches": [
                    first["coverage"]["branches_hit"],
                    first["coverage"]["branches_total"],
                ],
                "uncovered": sorted(uncovered_lines(first)),
            },
            "negative": {
                "tier": second["tier"],
                "lines": [second["coverage"]["lines_hit"], second["coverage"]["lines_total"]],
                "branches": [
                    second["coverage"]["branches_hit"],
                    second["coverage"]["branches_total"],
                ],
                "uncovered": sorted(uncovered_lines(second)),
            },
            "union": {
                "tier": tier(union_summary),
                "lines": [union_summary["lines_hit"], union_summary["lines_total"]],
                "branches": [
                    union_summary["branches_hit"],
                    union_summary["branches_total"],
                ],
            },
        },
    }
    out = config.ROOT / "selftest"
    out.mkdir(exist_ok=True)
    (out / "selftest.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result

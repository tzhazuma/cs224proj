"""Offline smoke test of the demo: grep v0, Clang SA and dead-free insertion on 2 dev groups (no network).

Run: .venv/bin/python -m pytest -q tests/test_smoke.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

DEMO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO_DIR))

import dead_free  # noqa: E402
import demo  # noqa: E402
import demo_methods as dm  # noqa: E402

DEV_GROUPS = ["CWE401_Memory_Leak__char_malloc_18", "CWE401_Memory_Leak__new_array_int_18"]


@pytest.fixture(scope="module")
def groups() -> dict[str, dict[str, dict]]:
    out: dict[str, dict[str, dict]] = {}
    for unit in demo.load_units():
        if unit["group_id"] in DEV_GROUPS:
            out.setdefault(unit["group_id"], {})[unit["label"]] = unit
    assert sorted(out) == sorted(DEV_GROUPS)
    assert all(u["set"] == "dev" for g in out.values() for u in g.values())
    return out


@pytest.mark.parametrize("group_id", DEV_GROUPS)
def test_grep_and_clang_on_twins(groups, group_id):
    bad, good = groups[group_id]["bad"], groups[group_id]["good"]
    assert dm.run_grep(bad).pred == 1 and dm.run_grep(good).pred == 0
    bad_result, evidence = dm.run_clang(bad)
    good_result, _ = dm.run_clang(good)
    assert (bad_result.status, bad_result.pred) == ("ok", 1)
    assert (good_result.status, good_result.pred) == ("ok", 0)
    assert evidence is not None and evidence["warnings"]


@pytest.mark.parametrize("inserter", ["local", "auto"])
@pytest.mark.parametrize("group_id", DEV_GROUPS)
def test_dead_free_fools_grep_not_clang(groups, group_id, inserter):
    bad = groups[group_id]["bad"]
    used, transform = dead_free.transformer(inserter)
    attacked = transform(bad, kind="stress")
    release = "free(" if bad["language"] == "c" else "delete"
    added = set(attacked["model_text"].split("\n")) - set(bad["model_text"].split("\n"))
    assert any(release in line for line in added), added
    assert Path(attacked["program_dir"]) != Path(bad["program_dir"])
    assert dm.run_grep(attacked).pred == 0  # grep is fooled
    result, _ = dm.run_clang(attacked)
    assert (result.status, result.pred) == ("ok", 1)  # the edited sources compile and still leak
    assert attacked["transform"]["inserter"] in ("local", "stress")


def test_local_inserter_matches_brief_and_line_map(groups):
    bad = groups["CWE401_Memory_Leak__new_array_int_18"]["bad"]
    attacked = dead_free.transform_unit(bad, kind="stress")
    lines = attacked["model_text"].split("\n")
    assert "static const int sym_k = 5;" in lines
    assert any(line.strip() == "if (sym_k != 5) delete [] data;" for line in lines)
    program_dir = Path(attacked["program_dir"])
    for source, source_line, model_line in attacked["line_map"]:
        path = Path(source) if Path(source).is_absolute() else program_dir / source
        if program_dir in path.parents or not Path(source).is_absolute():
            assert path.read_text().split("\n")[source_line - 1].strip() == lines[model_line - 1].strip()


def test_summary_is_built_from_results(groups, tmp_path):
    """--offline run end to end (no pause), recorded and replayed; summary comes from the results."""
    out = tmp_path / "run.json"
    assert demo.main(["--group", DEV_GROUPS[0], "--offline", "--methods", "grep,clang", "--no-pause", "--no-clear",
                      "--record", str(out)]) == 0
    record = json.loads(out.read_text())
    assert record["format"] == demo.RECORD_FORMAT
    assert record["summary"][0] == "grep fooled, Clang SA robust"
    assert record["spent"] == {"deepseek": 0.0, "jev": 0.0}
    assert demo.main(["--replay", str(out), "--no-pause", "--no-clear", "--replay-cap", "0"]) == 0

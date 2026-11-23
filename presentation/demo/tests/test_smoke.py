"""Offline smoke test of the demo on 2 dev groups: grep v0, Clang SA, dead-free insertion, decision-model client
(against a local fake of the :8003 contract), record + replay. No network beyond 127.0.0.1.

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


def test_stress_attack_is_the_stored_layer3_unit(groups):
    """With the default --attack-n-dead (0 = data lane default) the demo's attack equals the stored layer-3 unit."""
    used, _ = dead_free.transformer("auto")
    if used != "auto":
        pytest.skip("juliet_full/data/stress.py not available")
    args = demo.parse_args(["--group", DEV_GROUPS[0], "--offline"])
    attacked = demo.attack_case(args, demo.case("bad", "leaking unit", groups[DEV_GROUPS[0]]["bad"], 1))
    assert attacked["unit"]["transform"]["matches_layer3"] is True


class _FakeDecisionEndpoint:
    """A local stand-in for the :8003 contract (juliet_full/README.md §6); records the /score bodies."""

    def __init__(self) -> None:
        import http.server
        import threading

        self.bodies: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def _send(self, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._send({"ok": True, "models": [f"qwen3.5-4b-lora-{s}-fold{k}" for s in ("L1", "L3")
                                                   for k in (0, 1, 2)]})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.bodies.append(body)
                self._send({"score": -3.5, "threshold": 2.5, "pred": 0, "latency_ms_server": 42.0,
                            "switch_ms": 0.0, "model": body["model"]})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def test_decision_model_uses_fold_adapter_and_clang_evidence(groups):
    fake = _FakeDecisionEndpoint()
    try:
        ctx = dm.DemoContext("demo_test", ft_url=fake.url, intern_url="http://127.0.0.1:9", qwen_url="http://127.0.0.1:9")
        unit = dict(groups[DEV_GROUPS[0]]["bad"], fold=2)
        r1 = dm.run_decision(ctx, unit)
        _, evidence = dm.run_clang(unit)
        r3 = dm.run_decision(ctx, unit, "L3", evidence)
    finally:
        fake.server.shutdown()
    assert [b["model"] for b in fake.bodies] == ["qwen3.5-4b-lora-L1-fold2", "qwen3.5-4b-lora-L3-fold2"]
    assert fake.bodies[0]["evidence"] is None and fake.bodies[1]["evidence"] == evidence["warnings"]
    assert fake.bodies[0]["code"] == unit["model_text"] and fake.bodies[0]["language"] == "c"
    for r, method in ((r1, "ft"), (r3, "ft_l3")):
        assert (r.method, r.status, r.pred, r.score_kind, r.threshold) == (method, "ok", 0, "logit", 2.5)
        assert r.backend.startswith("qwen3.5-4b-lora-") and r.extra["latency_ms_server"] == 42.0
    cell = demo.verdict_cell(r1, 1, None)
    assert "s=-3.50 (thr +2.50)" in cell.plain and "server 42 ms" in cell.plain

#!/usr/bin/env python3
"""Self-checks of the L4-D data tools.  Run: .venv/bin/python tests/test_l4d.py  (exit 0 = pass)."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

L4D_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(L4D_DIR))
from derive import evaluate_unit, souffle_verdicts  # noqa: E402
from oracle import macro_f1  # noqa: E402
from parse_sites import mask_statement, parse_unit  # noqa: E402
from score_facts import auroc  # noqa: E402
from templates import MARKER, TEMPLATE_SHA256  # noqa: E402

FROZEN_TEMPLATE_SHA256 = "316429b266c0258383724c8c9129e2ea17946a9013d72cb61b267261ef827516"


def test_template_hash() -> None:
    assert TEMPLATE_SHA256 == FROZEN_TEMPLATE_SHA256, TEMPLATE_SHA256


def test_auroc_matches_pairwise() -> None:
    rng = random.Random(0)
    for _ in range(200):
        n = rng.randint(2, 30)
        s = [rng.choice([0.1, 0.5, 0.9, rng.random()]) for _ in range(n)]
        y = [rng.randint(0, 1) for _ in range(n)]
        pos = [a for a, b in zip(s, y) if b]
        neg = [a for a, b in zip(s, y) if not b]
        got = auroc(s, y)
        if not pos or not neg:
            assert got is None
            continue
        ref = sum((p > q) + 0.5 * (p == q) for p in pos for q in neg) / (len(pos) * len(neg))
        assert abs(got - ref) < 1e-12, (got, ref)


def test_macro_f1_null_is_wrong() -> None:
    assert macro_f1([(1, 1), (0, 0)])["macro_f1"] == 1.0
    assert macro_f1([(1, None), (0, 0)])["errors"] == 1
    assert macro_f1([(1, 1), (0, None)])["macro_f1"] < 1.0


def test_python_evaluator_equals_souffle_random() -> None:
    rng = random.Random(1)
    units = {}
    for k in range(300):
        n_alloc, n_real, n_rel = rng.randint(0, 3), rng.randint(0, 2), rng.randint(0, 3)
        alloc = [f"a{i}" for i in range(n_alloc)]
        realloc = [f"r{i}" for i in range(n_real)]
        release = [f"f{i}" for i in range(n_rel)]
        p = {}
        for s in alloc + realloc + release:
            p[("exec_any", (s,))] = rng.random()
            p[("exec_all", (s,))] = rng.random()
        for a in alloc:
            p[("heap", (a,))] = rng.random()
        for r in realloc:
            p[("realloc_safe", (r,))] = rng.random()
        for f in release + realloc:
            for a in alloc + realloc:
                if f != a:
                    p[("rel", (f, a))] = rng.random()
        units[f"u{k}"] = ({"alloc": alloc, "realloc": realloc}, p)
    for tau in (0.3, 0.5, 0.8):
        sv = souffle_verdicts(units, tau)
        for uid, (sites, p) in units.items():
            py = {tuple(x) for x in evaluate_unit(sites, p, tau)["leaks"]}
            assert py == sv.get(uid, set()), (uid, tau, py, sv.get(uid))


def test_mask_keeps_lines_and_hides_target() -> None:
    data = L4D_DIR.parent / "data" / "build" / "layer1_sample.jsonl"
    with data.open() as fh:
        units = [json.loads(line) for line in fh]
    for u in units:
        parsed = parse_unit(u["model_text"], u["language"])
        assert parsed["parse_errors"] == 0, u["unit_id"]
        n_lines = u["model_text"].count("\n")
        for s in parsed["sites"]:
            masked = mask_statement(u["model_text"], s["span"], MARKER)
            assert masked.count("\n") == n_lines
            assert masked.split("\n")[s["line"] - 1].count(MARKER) == 1
            assert u["model_text"][s["span"][0]:s["span"][1]] not in masked.split("\n")[s["line"] - 1]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)

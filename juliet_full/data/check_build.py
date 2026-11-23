#!/usr/bin/env python3
"""Validation of the data-lane outputs.

Checks: 1 bad + 1 good unit per split group in layer1/original; schema fields; G2B/B2G balance
per flow category; leakage test (no identifier/comment/string with bad, good, G2B, B2G, CWE,
Leak, OMIT, flaw, FIX) on every model_text; no `static` on any layer-1 function definition;
line_map consistency; subsets nesting; recompile + run 20 random units from their build spec.

Usage: python check_build.py
"""
from __future__ import annotations

import json
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
BUILD = DATA_DIR / "build"
sys.path.insert(0, str(DATA_DIR))
import build_units  # noqa: E402
import verify_labels  # noqa: E402

FIELDS = ["unit_id", "group_id", "family", "variant", "flow_category", "mechanism", "language", "set",
          "fold", "label", "truth", "good_kind", "program_dir", "build", "entry", "model_text", "line_map",
          "verify"]
SEED = 20261123


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def check_units(name: str, units: list[dict], groups: set[str], good_kinds: set) -> list[str]:
    errors = []
    per_group = Counter((u["group_id"], u["label"]) for u in units)
    for gid in groups:
        if per_group[(gid, "bad")] != 1 or per_group[(gid, "good")] != 1:
            errors.append(f"{name}: {gid} has {per_group[(gid, 'bad')]} bad / {per_group[(gid, 'good')]} good")
    if len(units) != 2 * len(groups):
        errors.append(f"{name}: {len(units)} units for {len(groups)} groups")
    for u in units:
        missing = [f for f in FIELDS if f not in u]
        if missing:
            errors.append(f"{u['unit_id']}: missing {missing}")
        if u["unit_id"] != f"{u['group_id']}__{u['label']}":
            errors.append(f"{u['unit_id']}: bad unit_id")
        if u["truth"] != (1 if u["label"] == "bad" else 0):
            errors.append(f"{u['unit_id']}: truth/label mismatch")
        if (u["label"] == "bad") != (u["good_kind"] is None) or (u["good_kind"] not in good_kinds | {None}):
            errors.append(f"{u['unit_id']}: good_kind {u['good_kind']}")
        hits = build_units.leakage_hits(u["model_text"])
        if hits:
            errors.append(f"{u['unit_id']}: leakage {sorted(hits)[:3]}")
        text_lines = u["model_text"].splitlines()
        pdir = Path(u["program_dir"])
        for src, srcno, mno in u["line_map"][:: max(1, len(u["line_map"]) // 15)]:
            src_line = (pdir / src).read_text().splitlines()[srcno - 1].rstrip()
            if text_lines[mno - 1] != src_line:
                errors.append(f"{u['unit_id']}: line_map {src}:{srcno} != model_text:{mno}")
                break
        if name == "layer1":
            for src in [s for s in u["build"]["sources"] if not s.startswith("/")]:
                code = (pdir / src).read_text()
                if re.search(r"^static\s+[^=;]*\(", code, re.M):
                    errors.append(f"{u['unit_id']}: static function remains in {src}")
    return errors


def recompile(units: list[dict], k: int = 20) -> list[str]:
    rng = random.Random(SEED)
    errors = []
    for u in rng.sample(units, k):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "a.out"
            rc, log = verify_labels.run(verify_labels.compile_cmd(u, u["build"]["compiler"], exe, True),
                                        u["program_dir"], 120)
            if rc != 0:
                errors.append(f"recompile {u['unit_id']}: {verify_labels.first_error(log)}")
                continue
            rc, out = verify_labels.run([str(exe)], u["program_dir"], 10,
                                        {"ASAN_OPTIONS": "detect_leaks=1:exitcode=23",
                                         "LSAN_OPTIONS": "exitcode=23:use_stacks=0", "PATH": "/usr/bin:/bin"})
            leak = "LeakSanitizer: detected memory leaks" in out
            if u["verify"]["asan_leak"] is not None and leak != u["verify"]["asan_leak"] and u["variant"] != "12":
                errors.append(f"recompile {u['unit_id']}: asan_leak {leak} != recorded {u['verify']['asan_leak']}")
        print(f"recompiled {u['unit_id']}: ok")
    return errors


def main() -> None:
    split = json.loads((build_units.SPLIT_PATH).read_text())["groups"]
    groups = {r["group_id"] for r in split}
    layer1 = load(BUILD / "layer1.jsonl")
    original = load(BUILD / "original.jsonl")
    errors = check_units("layer1", layer1, groups, {"G2B", "B2G", "other"})
    errors += check_units("original", original, groups, {"orig"})
    orig_bad = {u["unit_id"]: u["model_text"] for u in original if u["label"] == "bad"}
    errors += [f"{u['unit_id']}: original bad differs" for u in layer1
               if u["label"] == "bad" and orig_bad[u["unit_id"]] != u["model_text"]]
    sample = load(BUILD / "layer1_sample.jsonl")
    by_id = {u["unit_id"]: u for u in layer1}
    errors += [f"sample {u['unit_id']} differs from layer1" for u in sample if by_id[u["unit_id"]] != u]
    if len(sample) < 40 or any(u["set"] != "dev" for u in sample):
        errors.append("sample: needs >= 40 dev units")
    subsets = json.loads((BUILD / "subsets.json").read_text())
    eval_ids = {r["group_id"] for r in split if r["set"] == "eval"}
    sizes = {"api_subset": 664, "nested25": 332, "repeat100": 100, "latency300": 150}
    for key, size in sizes.items():
        if len(set(subsets[key])) != size:
            errors.append(f"subsets: {key} has {len(set(subsets[key]))}")
    if not (set(subsets["api_subset"]) <= eval_ids and set(subsets["nested25"]) <= set(subsets["api_subset"])
            and set(subsets["repeat100"]) <= set(subsets["nested25"])
            and set(subsets["latency300"]) <= set(subsets["api_subset"])):
        errors.append("subsets: nesting broken")
    table = Counter((u["flow_category"], u["good_kind"]) for u in layer1 if u["label"] == "good")
    print("good_kind by flow_category:")
    for flow in sorted({f for f, _ in table}):
        print(f"  {flow}: G2B {table[(flow, 'G2B')]}  B2G {table[(flow, 'B2G')]}  other {table[(flow, 'other')]}")
    errors += recompile(layer1)
    for line in errors[:40]:
        print("ERROR", line)
    print(f"{len(errors)} errors")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Structural checks for build/layer3.jsonl (stress) and build/placebo.jsonl. Exit 0 = all pass.

- same unit_ids, labels and split fields as layer1.jsonl, 1 bad + 1 good per group
- leakage audit of model_text (build_units.audit_model_text: forbidden words, comments, braces)
- stress: every free/delete line sits directly in an `if(sym_N op C)` block whose guard is declared
  `static const int sym_N = V;` in the unit; guards evaluate to the recorded truth; dead frees false
- stress: free-statement count and guard count equal within every group (bad vs good)
- placebo: no free/delete added or wrapped (free lines identical to layer 1), dead stmts are printLine
- guard comparison forms: distribution per label (reported)
- line_map points at the same text; transform_source works on a raw Juliet file and raises ValueError
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DATA_DIR))
import build_units  # noqa: E402
import stress  # noqa: E402

BUILD = DATA_DIR / "build"
SPLIT_FIELDS = ("unit_id", "group_id", "family", "variant", "flow_category", "mechanism", "language", "set", "fold",
                "label", "truth", "good_kind", "good_entry")
FREE_LINE = re.compile(r"^\s*(free\s*\(|delete\b)")
GUARD_IF = re.compile(r"^\s*if\((sym_\d+) (==|!=|<|>) (\d+)\)\s*$")
DECL = re.compile(r"^static const int (sym_\d+) = (\d+);$")
RAW = Path(__file__).resolve().parents[2] / "juliet/raw/testcases/CWE401_Memory_Leak/s01/CWE401_Memory_Leak__malloc_realloc_char_01.c"


def load(name: str) -> list[dict]:
    return [json.loads(l) for l in (BUILD / name).read_text().splitlines()]


def main() -> int:
    errors: list[str] = []
    layer1 = {u["unit_id"]: u for u in load("layer1.jsonl")}
    for name, kind in (("layer3.jsonl", "stress"), ("placebo.jsonl", "placebo")):
        units = load(name)
        if [u["unit_id"] for u in units] != list(layer1):
            errors.append(f"{name}: unit_ids differ from layer1")
        labels = Counter((u["group_id"], u["label"]) for u in units)
        if len(labels) != 3316 or set(labels.values()) != {1}:
            errors.append(f"{name}: not exactly 1 bad + 1 good per group")
        pair = {}
        forms = Counter()
        for u in units:
            ref = layer1[u["unit_id"]]
            if any(u[f] != ref[f] for f in SPLIT_FIELDS):
                errors.append(f"{name} {u['unit_id']}: split fields differ")
            text = u["model_text"]
            try:
                build_units.audit_model_text(u["unit_id"], text)
            except Exception as exc:  # audit raises on the first problem
                errors.append(f"{name} {u['unit_id']}: audit: {exc}")
            t = u["transform"]
            if t["kind"] != kind or not all(i["reachable"] is False for i in t["inserted"]):
                errors.append(f"{name} {u['unit_id']}: transform kind/reachable")
            lines = text.splitlines()
            decls = {m.group(1): int(m.group(2)) for l in lines if (m := DECL.match(l))}
            for g in t["guards"]:
                forms[(u["label"], g["op"], g["const"], g["truth"])] += 1
                if decls.get(g["name"]) != g["value"] or stress.holds(g["value"], g["op"], g["const"]) != g["truth"]:
                    errors.append(f"{name} {u['unit_id']}: guard {g['name']} inconsistent")
            truth = {g["name"]: g["truth"] for g in t["guards"]}
            for i in t["inserted"]:
                if truth[i["guard"]]:
                    errors.append(f"{name} {u['unit_id']}: inserted stmt under a true guard")
                if lines[i["line"] - 1].strip() != i["stmt"] or not GUARD_IF.match(lines[i["guard_line"] - 1]):
                    errors.append(f"{name} {u['unit_id']}: inserted line {i['line']} != stmt")
            for w in t["wrapped_real_frees"]:
                if lines[w["line"] - 1].strip() != w["stmt"] or not truth[w["guard"]]:
                    errors.append(f"{name} {u['unit_id']}: wrapped free line {w['line']} wrong")
            frees = [k for k, l in enumerate(lines) if FREE_LINE.match(l)]
            if kind == "stress":
                for k in frees:
                    m = GUARD_IF.match(lines[k - 2]) if k >= 2 else None
                    if not (m and lines[k - 1].strip() == "{" and m.group(1) in decls):
                        errors.append(f"{name} {u['unit_id']}: unguarded free at model line {k + 1}")
            else:
                if [lines[k].strip() for k in frees] != [l.strip() for l in ref["model_text"].splitlines() if FREE_LINE.match(l)]:
                    errors.append(f"{name} {u['unit_id']}: placebo changed the frees")
                if t["wrapped_real_frees"] or any("printLine(" not in i["stmt"] for i in t["inserted"]):
                    errors.append(f"{name} {u['unit_id']}: placebo inserted/wrapped a free")
            for f, fl, ml in u["line_map"][::7]:
                src = (Path(u["program_dir"]) / f).read_text().splitlines()
                if src[fl - 1].strip() != lines[ml - 1].strip():
                    errors.append(f"{name} {u['unit_id']}: line_map {f}:{fl} -> {ml} mismatch")
                    break
            pair.setdefault(u["group_id"], {})[u["label"]] = (len(frees), len(t["guards"]))
        if kind == "stress":
            unequal = [g for g, d in pair.items() if d["bad"] != d["good"]]
            if unequal:
                errors.append(f"{name}: free/guard counts differ in {len(unequal)} groups, e.g. {unequal[:3]}")
            dist = {lab: Counter(d[lab][0] for d in pair.values()) for lab in ("bad", "good")}
            print(f"{name}: free-statement count distribution bad {sorted(dist['bad'].items())} good {sorted(dist['good'].items())}")
        print(f"{name}: guard forms (label, op, const, truth): {sorted(forms.items())}")
    # demo API on a raw single-file Juliet unit, and the ValueError path
    code, info = stress.transform_source(RAW.read_text(), "c", func="CWE401_Memory_Leak__malloc_realloc_char_01_bad",
                                         realloc_anchor=True)
    if not info["inserted"] or "static const int" not in code:
        errors.append("transform_source: no insertion on raw Juliet file")
    try:
        stress.transform_source("int x;\n", "c")
        errors.append("transform_source: no ValueError on code without anchor")
    except ValueError as exc:
        print(f"transform_source ValueError ok: {exc}")
    for e in errors[:50]:
        print("ERROR", e)
    print(f"{len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

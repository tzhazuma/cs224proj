#!/usr/bin/env python3
"""L4-D questions (contract l4d/README.md section 2): one row per question, gold from build/gold_<layer>.jsonl.

    from questions import make_questions
    rows = make_questions(unit_record, layer)        # prediction time: no gold needed (parse + render, ~ms)

Asked: heap for every alloc site; exec_any / exec_all for every site (target masked by templates.MARKER);
rel for every (release-role f, alloc-role a) pair, release role = release | realloc, alloc role = alloc | realloc
(f != a); realloc_safe for every realloc site.

CLI: .venv/bin/python questions.py --layer layer1_sample
  -> build/questions_<layer>.jsonl, build/sites_<layer>.jsonl, build/qcounts_<layer>.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

L4D_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(L4D_DIR))
from parse_sites import BUILD, layer_name, layer_path, mask_statement, parse_unit  # noqa: E402
from templates import MARKER, TEMPLATE_SHA256, code_snippet, number_lines, render  # noqa: E402

ALLOC_ROLE = ("alloc", "realloc")
RELEASE_ROLE = ("release", "realloc")


def make_questions(unit: dict, layer: str, parsed: dict | None = None) -> list[dict]:
    parsed = parsed or parse_unit(unit["model_text"], unit["language"])
    sites = parsed["sites"]
    text = unit["model_text"]
    plain_state = number_lines(text)
    layer = layer_name(layer)
    base = {"unit_id": unit["unit_id"], "layer": layer, "set": unit["set"], "fold": unit["fold"]}
    rows = []

    def add(qtype, ss, state, question):
        rows.append({"qid": f"{layer}/{unit['unit_id']}/{qtype}/{'+'.join(s['site_id'] for s in ss)}", **base,
                     "qtype": qtype, "site_ids": [s["site_id"] for s in ss], "lines": [s["line"] for s in ss],
                     "site_kinds": [s["kind"] for s in ss], "state": state, "question": question})

    for s in sites:
        if s["kind"] == "alloc":
            add("heap", [s], plain_state, render("heap", line=s["line"], code=code_snippet(s["text"])))
    for s in sites:
        masked = number_lines(mask_statement(text, s["span"], MARKER))
        for qt in ("exec_any", "exec_all"):
            add(qt, [s], masked, render(qt, line=s["line"]))
    for f in sites:
        if f["kind"] not in RELEASE_ROLE:
            continue
        for a in sites:
            if a["kind"] not in ALLOC_ROLE or a["site_id"] == f["site_id"]:
                continue
            add("rel", [f, a], plain_state,
                render("rel", line_f=f["line"], code_f=code_snippet(f["text"]), line_a=a["line"],
                       code_a=code_snippet(a["text"])))
    for s in sites:
        if s["kind"] == "realloc":
            add("realloc_safe", [s], plain_state, render("realloc_safe", line=s["line"], code=code_snippet(s["text"])))
    return rows


def attach_gold(rows: list[dict], gold: dict | None) -> None:
    for r in rows:
        if gold is None or gold.get("status") != "ok":
            r["gold"], r["gold_source"] = None, f"gold_{gold.get('status') if gold else 'missing'}"
            continue
        sg = gold["sites"]
        qt = r["qtype"]
        if qt in ("exec_any", "exec_all"):
            g = sg[r["site_ids"][0]]
            r["gold"], r["gold_source"] = g[qt], g["exec_source"] if g[qt] is not None else "not_placed"
        elif qt == "heap":
            g = sg[r["site_ids"][0]]
            r["gold"], r["gold_source"] = g["heap"], g["heap_source"]
        elif qt == "rel":
            v = gold["rel"]["|".join(r["site_ids"])]
            r["gold"], r["gold_source"] = v, "trace" if v is not None else "not_executed"
        elif qt == "realloc_safe":
            g = sg[r["site_ids"][0]]
            r["gold"], r["gold_source"] = g["realloc_safe"], g["realloc_safe_source"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", required=True)
    args = ap.parse_args()
    units = [json.loads(l) for l in layer_path(args.layer).open()]
    gold_path = BUILD / f"gold_{args.layer}.jsonl"
    golds = {}
    if gold_path.exists():
        for l in gold_path.open():
            g = json.loads(l)
            golds[g["unit_id"]] = g
    per_unit = {}
    labels = defaultdict(Counter)
    with (BUILD / f"questions_{args.layer}.jsonl").open("w") as fq, \
            (BUILD / f"sites_{args.layer}.jsonl").open("w") as fs:
        for u in units:
            parsed = parse_unit(u["model_text"], u["language"])
            fs.write(json.dumps({"unit_id": u["unit_id"], "layer": layer_name(args.layer), **parsed}) + "\n")
            rows = make_questions(u, args.layer, parsed)
            attach_gold(rows, golds.get(u["unit_id"]))
            per_unit[u["unit_id"]] = dict(Counter(r["qtype"] for r in rows), total=len(rows))
            for r in rows:
                labels[(u["set"], r["qtype"])][str(r["gold"])] += 1
                fq.write(json.dumps(r) + "\n")
    stats = {"layer": layer_name(args.layer), "source": args.layer, "template_sha256": TEMPLATE_SHA256,
             "units": len(units), "questions": sum(v["total"] for v in per_unit.values()),
             "labels": {f"{s}/{q}": dict(c) for (s, q), c in sorted(labels.items())}, "per_unit": per_unit}
    (BUILD / f"qcounts_{args.layer}.json").write_text(json.dumps(stats, indent=1))
    print(json.dumps({k: v for k, v in stats.items() if k != "per_unit"}, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Select the fixed L2 few-shot examples from DEV units and render prompts/l2_examples.txt.

Selection rule (deterministic, documented in README.md):
  four slots, balanced 2 bad / 2 good, one per dev flow category, both good kinds, both
  allocation families:
    1. bad,            flow 02-22, mechanism c_alloc
    2. good (G2B),     flow 31-45, mechanism cpp_new
    3. bad,            flow 51-68, mechanism cpp_new
    4. good (B2G),     flow 71-84, mechanism c_alloc
  In each slot take the unit with the shortest model_text (ties: unit_id), each slot from a
  different group. If a slot has no candidate, constraints are relaxed in this order: drop
  good_kind, else drop mechanism, else drop both; every relaxation is written to
  l2_examples.json.
Output: prompts/l2_examples.txt (rendered text, part of the L2 system prompt) and
prompts/l2_examples.json (unit ids, rule, source file hash).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import PROMPT_DIR  # noqa: E402
from llmlane.prompts import audit, fence_language, sha256_text  # noqa: E402
from llmlane.units import file_sha256, load_units  # noqa: E402

SLOTS = [
    {"label": "bad", "flow_category": "02-22", "mechanism": "c_alloc", "good_kind": None},
    {"label": "good", "flow_category": "31-45", "mechanism": "cpp_new", "good_kind": "G2B"},
    {"label": "bad", "flow_category": "51-68", "mechanism": "cpp_new", "good_kind": None},
    {"label": "good", "flow_category": "71-84", "mechanism": "c_alloc", "good_kind": "B2G"},
]
VERDICT = {"bad": "vulnerable", "good": "not_vulnerable"}
HEADER = "Reference examples with their verdicts:"


def pick(units: list[dict], slot: dict, used_groups: set[str]) -> tuple[dict | None, list[str]]:
    constraints = ["label", "flow_category", "mechanism", "good_kind"]
    for drop in ([], ["good_kind"], ["mechanism"], ["mechanism", "good_kind"]):
        keys = [k for k in constraints if k not in drop and not (k == "good_kind" and slot["label"] == "bad")]
        pool = [u for u in units if u["set"] == "dev" and u["group_id"] not in used_groups
                and all(u.get(k) == slot[k] for k in keys)]
        if pool:
            return min(pool, key=lambda u: (len(u["model_text"]), u["unit_id"])), drop
    return None, []


def render(examples: list[dict]) -> str:
    blocks = [HEADER]
    for index, unit in enumerate(examples, 1):
        blocks.append(f"Example {index}:\n```{fence_language(unit)}\n{unit['model_text'].rstrip()}\n```\n"
                      f"Verdict: {VERDICT[unit['label']]}")
    return "\n\n".join(blocks) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--units", required=True, type=Path)
    p.add_argument("--out-dir", type=Path, default=PROMPT_DIR)
    args = p.parse_args(argv)
    units = load_units(args.units)
    chosen, notes, used = [], [], set()
    for slot in SLOTS:
        unit, relaxed = pick(units, slot, used)
        if unit is None:
            print(f"no dev unit for slot {slot}")
            return 1
        used.add(unit["group_id"])
        chosen.append(unit)
        notes.append({"slot": slot, "relaxed": relaxed})
    text = render(chosen)
    for unit in chosen:
        audit(text, unit["unit_id"], unit["group_id"])
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "l2_examples.txt").write_text(text, encoding="utf-8")
    meta = {
        "rule": __doc__.split("Selection rule", 1)[1].split("Output:", 1)[0].strip(),
        "units_file": str(args.units.resolve()), "units_sha256": file_sha256(args.units),
        "text_sha256": sha256_text(text.rstrip()),
        "examples": [{"unit_id": u["unit_id"], "group_id": u["group_id"], "label": u["label"],
                      "flow_category": u.get("flow_category"), "mechanism": u.get("mechanism"),
                      "good_kind": u.get("good_kind"), "model_text_chars": len(u["model_text"]),
                      "relaxed": n["relaxed"]} for u, n in zip(chosen, notes)],
    }
    (args.out_dir / "l2_examples.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    for e in meta["examples"]:
        print(e)
    print(f"l2_examples.txt: {len(text)} chars, sha256 {meta['text_sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

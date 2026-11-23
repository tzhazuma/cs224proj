#!/usr/bin/env python3
"""Offline L4 evaluation: re-parse stored DeepSeek answers (raw log) with the current llmlane/l4.py and
l4/leak.dl, and report fact parse rate, grounded share and agreement with truth (dev units only).

    python3 l4_eval.py --raw <raw_logs/.../run.jsonl> [--show-errors]
No API calls: rule or parser changes can be checked against answers already paid for.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmlane import LLM_DIR, l4  # noqa: E402
from llmlane.units import load_units  # noqa: E402

UNITS = LLM_DIR.parent / "data" / "build" / "layer1.jsonl"


def answer(entry: dict) -> str | None:
    return (entry.get("raw") or {}).get("content")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--raw", required=True, type=Path)
    p.add_argument("--units", type=Path, default=UNITS)
    p.add_argument("--show-errors", action="store_true")
    p.add_argument("--json-out", type=Path)
    args = p.parse_args(argv)
    units = {u["unit_id"]: u for u in load_units(args.units)}
    entries = {}
    for line in args.raw.read_text().splitlines():
        e = json.loads(line)
        if e.get("status") == "ok":
            entries[e["unit_id"]] = e  # last attempt wins
    counts = Counter()
    by = Counter()
    errors = []
    for uid, e in sorted(entries.items()):
        unit = units[uid]
        assert unit["set"] == "dev", uid
        parsed = l4.parse_facts(answer(e), unit["model_text"].rstrip())
        counts["n"] += 1
        counts["strict"] += parsed.strict_ok
        counts["facts"] += parsed.n_facts
        counts["ungrounded"] += len(parsed.ungrounded)
        counts["bad_lines"] += len(parsed.bad_lines)
        if parsed.n_facts == 0 and not parsed.said_none:
            pred = None
        else:
            res = l4.run_souffle(parsed)
            pred = (1 if res.leaks else 0) if res.status == "ok" else None
        truth = int(unit["truth"])
        ok = pred == truth
        counts["agree"] += ok
        counts["invalid"] += pred is None
        counts[("tp", "fn", "tn", "fp")[(0 if truth else 2) + (0 if pred == truth else 1)]] += pred is not None
        key = (unit["mechanism"], unit["label"], unit.get("good_kind"))
        by[(key, ok)] += 1
        if not ok:
            errors.append((uid, truth, pred, parsed))
    n = counts["n"]
    print(f"{args.raw.name}: n={n} parse_strict={counts['strict']}/{n} ({counts['strict'] / n:.3f}) "
          f"grounded={counts['facts']}/{counts['facts'] + counts['ungrounded']} bad_lines={counts['bad_lines']} "
          f"agree={counts['agree']}/{n} ({counts['agree'] / n:.3f}) invalid={counts['invalid']} "
          f"tp={counts['tp']} fp={counts['fp']} tn={counts['tn']} fn={counts['fn']}")
    keys = sorted({k for k, _ in by})
    for k in keys:
        print(f"  {k}: agree {by[(k, True)]}/{by[(k, True)] + by[(k, False)]}")
    if args.show_errors:
        for uid, truth, pred, parsed in errors:
            print(f"--- {uid} truth={truth} pred={pred} ungrounded={parsed.ungrounded} bad={parsed.bad_lines}")
            print(answer(entries[uid]))
    if args.json_out:
        args.json_out.write_text(json.dumps({"raw": str(args.raw), **{k: v for k, v in counts.items()},
                                             "errors": [e[0] for e in errors]}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

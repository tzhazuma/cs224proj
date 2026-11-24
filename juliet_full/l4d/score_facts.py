#!/usr/bin/env python3
"""Question-level scores of L4-D answers: accuracy and AUROC per model, layer, set and qtype.

    python3 score_facts.py --answers run1.jsonl [run2.jsonl ...] --questions build/questions_layer1.jsonl [...] \
        [--tau 0.5] [--out scores.json]

Answers rows (contract section 4): {qid, unit_id, qtype, p_yes, logit_diff, model, fold}.  Gold and layer come from
the question files (matched by qid).  Questions with gold null are skipped (counted as n_gold_null); questions
without an answer are counted as n_unanswered and are not scored.  accuracy = mean(1[p_yes >= tau] == gold);
AUROC on p_yes (ties count 1/2), null when only one class is present.  qtype "all" pools every qtype.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def auroc(scores: list[float], labels: list[int]) -> float | None:
    pos = sum(labels)
    neg = len(labels) - pos
    if pos == 0 or neg == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    rank_sum, i = 0.0, 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        mid = (i + j) / 2 + 1  # average 1-based rank of the tie group
        rank_sum += mid * sum(labels[order[k]] for k in range(i, j + 1))
        i = j + 1
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--answers", nargs="+", required=True, type=Path)
    ap.add_argument("--questions", nargs="+", required=True, type=Path)
    ap.add_argument("--tau", type=float, default=0.5)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    gold = {}
    for qp in args.questions:
        with qp.open() as fh:
            for line in fh:
                q = json.loads(line)
                gold[q["qid"]] = (q["gold"], q["layer"], q["set"], q["qtype"])
    cells = defaultdict(lambda: {"p": [], "y": [], "n_gold_null": 0})
    answered = defaultdict(set)
    n_unknown = 0
    for ap_path in args.answers:
        with ap_path.open() as fh:
            for line in fh:
                a = json.loads(line)
                if a["qid"] not in gold:
                    n_unknown += 1
                    continue
                y, layer, st, qt = gold[a["qid"]]
                model = a.get("model")
                answered[(model, layer)].add(a["qid"])
                for qkey in (qt, "all"):
                    c = cells[(model, layer, st, qkey)]
                    if y is None:
                        c["n_gold_null"] += 1
                        continue
                    c["p"].append(float(a["p_yes"]))
                    c["y"].append(int(y))
    n_questions = defaultdict(int)
    for qid, (_, layer, st, qt) in gold.items():
        for qkey in (qt, "all"):
            n_questions[(layer, st, qkey)] += 1
    rows = []
    for (model, layer, st, qt), c in sorted(cells.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        n = len(c["y"])
        correct = sum(int((p >= args.tau) == bool(y)) for p, y in zip(c["p"], c["y"]))
        rows.append({"model": model, "layer": layer, "set": st, "qtype": qt, "n": n, "n_yes": sum(c["y"]),
                     "n_gold_null": c["n_gold_null"],
                     "n_unanswered": n_questions[(layer, st, qt)] - n - c["n_gold_null"],
                     "accuracy": correct / n if n else None, "auroc": auroc(c["p"], c["y"]),
                     "majority_baseline": max(sum(c["y"]), n - sum(c["y"])) / n if n else None})
    res = {"tau": args.tau, "answers": [str(p) for p in args.answers], "questions": [str(p) for p in args.questions],
           "n_answers_unknown_qid": n_unknown, "rows": rows}
    if args.out:
        args.out.write_text(json.dumps(res, indent=1))
    hdr = f"{'model':24} {'layer':9} {'set':4} {'qtype':12} {'n':>6} {'yes':>6} {'acc':>6} {'auroc':>6} {'maj':>6} {'unans':>6}"
    print(hdr)
    for r in rows:
        fmt = lambda v: "  -   " if v is None else f"{v:6.3f}"  # noqa: E731
        print(f"{str(r['model'])[:24]:24} {r['layer']:9} {r['set']:4} {r['qtype']:12} {r['n']:6d} {r['n_yes']:6d} "
              f"{fmt(r['accuracy'])} {fmt(r['auroc'])} {fmt(r['majority_baseline'])} {r['n_unanswered']:6d}")
    if n_unknown:
        print(f"warning: {n_unknown} answers with a qid not in the question files")


if __name__ == "__main__":
    main()

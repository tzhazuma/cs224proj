"""Per-qtype fact accuracy of the L4-D decision models on the pruned layer3 eval questions (REPORT_jev_l4d.md input).

Same questions for all methods: l4d/build/questions_layer3.jsonl (set eval) pruned by l4d_ft/prune.py prune(), scored
against the question's gold field (questions with gold null = not executed are excluded). Answer p_yes >= τ is "Yes".
  jev_l4d         l4d_ft/results/jev_l4d/layer3/eval_r1.jsonl, τ 0.5 (primary) and the FROZEN tau_secondary
  intern_l4d      l4d_ft/results/intern_l4d/layer3/eval_r1.jsonl, τ 0.5 (primary)
  lora_l4d_opt    l4d_ft/results/lora_l4d/layer3/eval_r1.jsonl restricted to the pruned qids, per-fold τ of l4d_ft/FROZEN
Also: questions per unit, Jev input/output tokens and cost. Output: jev_l4d_facts.json (this directory).
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
JF = HERE.parent.parent
sys.path.insert(0, str(JF / "l4d_ft"))
from prune import prune  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> None:
    qs = prune([q for q in read_jsonl(JF / "l4d/build/questions_layer3.jsonl") if q["set"] == "eval"])
    gold = {q["qid"]: q["gold"] for q in qs if q["gold"] is not None}
    qtype = {q["qid"]: q["qtype"] for q in qs}
    jev_frozen = json.loads((JF / "l4d_ft/results/jev_l4d/FROZEN").read_text())
    lora_tau = {int(k): v["tau"] for k, v in json.loads((JF / "l4d_ft/FROZEN").read_text())["folds"].items()}
    jev = {a["qid"]: a for a in read_jsonl(JF / "l4d_ft/results/jev_l4d/layer3/eval_r1.jsonl")}
    intern = {a["qid"]: a for a in read_jsonl(JF / "l4d_ft/results/intern_l4d/layer3/eval_r1.jsonl")}
    lora = {a["qid"]: a for a in read_jsonl(JF / "l4d_ft/results/lora_l4d/layer3/eval_r1.jsonl") if a["qid"] in qtype}
    for name, ans in (("jev", jev), ("intern", intern), ("lora", lora)):
        assert set(ans) == set(qtype), f"{name}: answers do not cover exactly the pruned eval questions"
    methods = {
        f"jev_l4d @0.5": lambda q: jev[q]["p_yes"] >= 0.5,
        f"jev_l4d @dev τ {jev_frozen['tau_secondary']}": lambda q: jev[q]["p_yes"] >= jev_frozen["tau_secondary"],
        "intern_l4d @0.5": lambda q: intern[q]["p_yes"] >= 0.5,
        "lora_l4d_opt (per-fold τ)": lambda q: lora[q]["p_yes"] >= lora_tau[lora[q]["fold"]],
    }
    out = {"n_questions_pruned": len(qs), "n_questions_with_gold": len(gold), "lora_tau_per_fold": lora_tau,
           "jev_tau_secondary": jev_frozen["tau_secondary"], "by_qtype": {}, "overall": {}}
    types = sorted({qtype[q] for q in gold})
    for t in types:
        ids = [q for q in gold if qtype[q] == t]
        row = {"n": len(ids), "n_gold_yes": sum(gold[q] for q in ids)}
        for name, yes in methods.items():
            pred = [int(yes(q)) for q in ids]
            row[name] = {"acc": round(sum(p == gold[q] for p, q in zip(pred, ids)) / len(ids), 4),
                         "fp": sum(p and not gold[q] for p, q in zip(pred, ids)),
                         "fn": sum((not p) and gold[q] for p, q in zip(pred, ids))}
        out["by_qtype"][t] = row
    for name, yes in methods.items():
        out["overall"][name] = round(sum(int(yes(q)) == gold[q] for q in gold) / len(gold), 4)
    per_unit = defaultdict(int)
    for q in qs:
        per_unit[q["unit_id"]] += 1
    n = sorted(per_unit.values())
    out["questions_per_unit"] = {"units": len(n), "mean": round(statistics.mean(n), 3), "median": statistics.median(n),
                                 "max": n[-1]}
    toks_in = [a["input_tokens"] for a in jev.values()]
    toks_out = [a["output_tokens"] or 0 for a in jev.values()]
    out["jev_tokens"] = {"input_total": sum(toks_in), "input_per_question_mean": round(statistics.mean(toks_in), 1),
                         "input_per_question_median": statistics.median(toks_in), "output_total": sum(toks_out),
                         "cost_usd": round(sum(a["cost_usd"] for a in jev.values()), 6)}
    (HERE / "jev_l4d_facts.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()

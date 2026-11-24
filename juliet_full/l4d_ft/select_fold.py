"""Per-fold dev selection and freeze (contract l4d/README.md section 5; lane l4d-train, dell).

  select_fold.py ckpt --fold k [--run fold<k>]
      for every dev_answers/step<N>.jsonl of build/runs/<run>/ (unmerged batched answers written during training;
      step0 = zero-shot, not a candidate): unit macro-F1 on layer1 dev through derive.py's evaluator for every tau
      in TAU_GRID; best (checkpoint, tau) by macro-F1, ties -> higher question AUROC, then tau closest to 0.5,
      then the earlier step. -> build/select/fold<k>_ckpt.json
  select_fold.py tau --fold k --answers <merged dev answers jsonl>
      tau re-chosen on the merged dev answers of the selected checkpoint (the reported model is the merged one).
      -> build/select/fold<k>_tau.json
  select_fold.py readout --answers <readout dev answers jsonl>     tau of qwen_readout_l4d on dev
  select_fold.py freeze --fold k | --readout
      appends that entry (with timestamp and hashes) to l4d_ft/FROZEN (JSON); refuses to overwrite an entry.

derive.py is imported read-only (unit_inputs, evaluate_unit = the evaluator derive.py writes its output with);
the final unit files are written by running derive.py itself (predict pipeline).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
L4D_DIR = JULIET_FULL / "l4d"
sys.path.insert(0, str(L4D_DIR))
sys.path.insert(0, str(HERE / "server"))
import derive  # noqa: E402  (l4d-data lane, read-only)
from l4d_prompt import TEMPLATE_SHA256 as PROMPT_SHA256  # noqa: E402

TAU_GRID = [round(1 / (1 + math.exp(-0.5 * t)), 6) for t in range(-20, 21)]  # sigmoid of logit -10..10, step 0.5
SELECT = HERE / "build" / "select"
FROZEN = HERE / "FROZEN"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def auroc(scores, truth) -> float | None:
    n_pos = sum(truth)
    n_neg = len(truth) - n_pos
    if not n_pos or not n_neg:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return (sum(r for r, t in zip(ranks, truth) if t) - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def macro_f1(pred, truth) -> float:
    f1s = []
    for c in (1, 0):
        tp = sum(p == c and t == c for p, t in zip(pred, truth))
        fp = sum(p == c and t != c for p, t in zip(pred, truth))
        fn = sum(p != c and t == c for p, t in zip(pred, truth))
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0)
    return sum(f1s) / 2


class DevSet:
    """Layer1 dev questions (l4d/build/questions_layer1.jsonl, set == dev) and unit truth (data/build/layer1.jsonl)."""

    def __init__(self, questions: Path):
        self.questions_path = questions.resolve()
        self.by_unit = defaultdict(list)
        for q in read_jsonl(questions):
            if q["set"] == "dev":
                self.by_unit[q["unit_id"]].append(q)
        truth = {u["unit_id"]: u["truth"] for u in read_jsonl(JULIET_FULL / "data/build/layer1.jsonl")}
        self.units = sorted(self.by_unit)
        self.truth = [truth[u] for u in self.units]
        self.sites = {u: derive.unit_inputs(self.by_unit[u]) for u in self.units}
        self.gold = {q["qid"]: q["gold"] for qs in self.by_unit.values() for q in qs}

    def evaluate(self, answers: dict) -> dict:
        missing = [q["qid"] for qs in self.by_unit.values() for q in qs if q["qid"] not in answers]
        assert not missing, f"{len(missing)} dev questions unanswered, e.g. {missing[:3]}"
        p = {u: {(q["qtype"], tuple(q["site_ids"])): answers[q["qid"]] for q in self.by_unit[u]} for u in self.units}
        rows = []
        for tau in TAU_GRID:
            res = [derive.evaluate_unit(self.sites[u], p[u], tau) for u in self.units]
            pred = [r["pred"] for r in res]
            rows.append({"tau": tau, "macro_f1": macro_f1(pred, self.truth),
                         "n_fp": sum(a == 1 and t == 0 for a, t in zip(pred, self.truth)),
                         "n_fn": sum(a == 0 and t == 1 for a, t in zip(pred, self.truth))})
        soft = [derive.evaluate_unit(self.sites[u], p[u], 0.5)["score"] for u in self.units]
        qids = [q for q, g in self.gold.items() if g in (0, 1)]
        q_auroc = auroc([answers[q] for q in qids], [self.gold[q] for q in qids])
        best = max(rows, key=lambda r: (round(r["macro_f1"], 12), -abs(r["tau"] - 0.5)))
        return {"grid": rows, "best_tau": best["tau"], "best_macro_f1": best["macro_f1"], "question_auroc": q_auroc,
                "unit_soft_auroc": auroc(soft, self.truth), "n_units": len(self.units), "n_questions": len(self.gold)}


def load_p(path: Path) -> dict:
    return {r["qid"]: float(r["p_yes"]) for r in read_jsonl(path)}


def cmd_ckpt(args) -> None:
    dev = DevSet(Path(args.questions))
    run_dir = HERE / "build" / "runs" / (args.run or f"fold{args.fold}")
    table = []
    for path in sorted((run_dir / "dev_answers").glob("step*.jsonl"), key=lambda p: int(p.stem[4:])):
        ev = dev.evaluate(load_p(path))
        table.append({"checkpoint": path.stem, "step": int(path.stem[4:]), "answers_sha256": file_sha256(path),
                      **{k: ev[k] for k in ("best_tau", "best_macro_f1", "question_auroc", "unit_soft_auroc",
                                            "n_units", "n_questions")}, "grid": ev["grid"]})
        print(json.dumps({k: v for k, v in table[-1].items() if k != "grid"}))
    candidates = [t for t in table if t["step"] > 0]
    best = max(candidates, key=lambda t: (round(t["best_macro_f1"], 12), t["question_auroc"] or 0,
                                          -abs(t["best_tau"] - 0.5), -t["step"]))
    out = {"fold": args.fold, "run": run_dir.name, "selected": best["checkpoint"], "tau_unmerged": best["best_tau"],
           "rule": "max dev unit macro-F1 over TAU_GRID (derive.py evaluator); ties: question AUROC, |tau-0.5|, "
                   "earlier step; step0 (zero-shot) not a candidate",
           "tau_grid": TAU_GRID, "questions": str(dev.questions_path.relative_to(JULIET_FULL)),
           "questions_sha256": file_sha256(dev.questions_path), "table": table, "utc": utc_now()}
    SELECT.mkdir(parents=True, exist_ok=True)
    (SELECT / f"fold{args.fold}_ckpt.json").write_text(json.dumps(out, indent=1) + "\n")
    print("selected", best["checkpoint"], "tau", best["best_tau"], "dev macro-F1", best["best_macro_f1"])


def cmd_tau(args) -> None:
    dev = DevSet(Path(args.questions))
    ev = dev.evaluate(load_p(Path(args.answers)))
    out = {"fold": args.fold, "readout": args.readout, "answers": str(args.answers),
           "answers_sha256": file_sha256(Path(args.answers)), **ev, "utc": utc_now()}
    SELECT.mkdir(parents=True, exist_ok=True)
    name = "readout_tau.json" if args.readout else f"fold{args.fold}_tau.json"
    (SELECT / name).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "grid"}))


def common_hashes(questions: Path) -> dict:
    sys.path.insert(0, str(L4D_DIR))
    import templates  # noqa: E402  (l4d-data lane, read-only)
    manifest = json.loads((HERE / "data" / "manifest.json").read_text())
    return {"l4d_templates_sha256": templates.TEMPLATE_SHA256,
            "l4d_templates_py_sha256": file_sha256(L4D_DIR / "templates.py"),
            "prompt_template_sha256": PROMPT_SHA256,
            "chat_template_sha256": manifest["q_layer1"]["chat_template_sha256"],
            "derive_py_sha256": file_sha256(L4D_DIR / "derive.py"),
            "rules_l4d_dl_sha256": file_sha256(L4D_DIR / "l4d.dl"),
            "questions_layer1": str(questions.relative_to(JULIET_FULL)),
            "questions_layer1_sha256": file_sha256(questions),
            "rendered_q_layer1_sha256": manifest["q_layer1"]["rendered_sha256"]}


def cmd_freeze(args) -> None:
    frozen = json.loads(FROZEN.read_text()) if FROZEN.exists() else {"folds": {}, "readout": None, "history": []}
    hashes = common_hashes(Path(args.questions).resolve())
    if "common" in frozen:
        diff = {k: (frozen["common"][k], v) for k, v in hashes.items() if frozen["common"].get(k) != v}
        assert not diff, f"inputs changed since the first freeze entry: {diff}"
    else:
        frozen["common"] = hashes
    now = utc_now()
    if args.readout:
        assert frozen["readout"] is None, "readout already frozen"
        sel = json.loads((SELECT / "readout_tau.json").read_text())
        frozen["readout"] = {"method": "qwen_readout_l4d", "model": "qwen3.5-4b-readout", "tau": sel["best_tau"],
                             "dev_macro_f1": sel["best_macro_f1"], "dev_question_auroc": sel["question_auroc"],
                             "dev_answers_sha256": sel["answers_sha256"], "frozen_utc": now}
        frozen["history"].append({"utc": now, "entry": "readout"})
    else:
        key = str(args.fold)
        assert key not in frozen["folds"], f"fold {key} already frozen"
        ck = json.loads((SELECT / f"fold{args.fold}_ckpt.json").read_text())
        tau = json.loads((SELECT / f"fold{args.fold}_tau.json").read_text())
        ckpt_dir = HERE / "build" / "runs" / ck["run"] / "ckpt" / ck["selected"]
        cfg = json.loads((HERE / "build" / "runs" / ck["run"] / "config.json").read_text())
        manifest = json.loads((HERE / "data" / "manifest.json").read_text())
        train_key = Path(cfg["train_file"]).stem
        frozen["folds"][key] = {
            "fold": args.fold, "method": "lora_l4d", "model": f"qwen3.5-4b-lora-l4d-fold{args.fold}",
            "checkpoint": ck["selected"], "checkpoint_dir": f"runs/{ck['run']}/ckpt/{ck['selected']}",
            "adapter_sha256": file_sha256(ckpt_dir / "adapter_model.safetensors"),
            "adapter_config_sha256": file_sha256(ckpt_dir / "adapter_config.json"),
            "head_sha256": file_sha256(ckpt_dir / "head.pt"),
            "tau": tau["best_tau"], "tau_rule": "dev unit macro-F1 on merged dev answers of the selected checkpoint",
            "dev_macro_f1_merged": tau["best_macro_f1"], "dev_question_auroc_merged": tau["question_auroc"],
            "tau_unmerged_at_selection": ck["tau_unmerged"],
            "dev_macro_f1_unmerged": next(t["best_macro_f1"] for t in ck["table"] if t["checkpoint"] == ck["selected"]),
            "dev_answers_merged_sha256": tau["answers_sha256"],
            "train_file": cfg["train_file"], "train_file_sha256": manifest[train_key]["rendered_sha256"],
            "frozen_utc": now}
        frozen["history"].append({"utc": now, "entry": f"fold{args.fold}"})
    tmp = FROZEN.with_suffix(".tmp")
    tmp.write_text(json.dumps(frozen, indent=1) + "\n")
    tmp.replace(FROZEN)
    print(json.dumps(frozen["history"][-1]), "->", FROZEN)


def cmd_record_questions(args) -> None:
    """Adds the sha256 of the layer3/placebo/original question files to FROZEN (once; later calls must match)."""
    frozen = json.loads(FROZEN.read_text())
    shas = {layer: file_sha256(L4D_DIR / "build" / f"questions_{layer}.jsonl") for layer in ("layer3", "placebo", "original")}
    if "questions_other" in frozen:
        assert frozen["questions_other"]["sha256"] == shas, (frozen["questions_other"], shas)
        print("questions_other unchanged")
        return
    now = utc_now()
    frozen["questions_other"] = {"sha256": shas, "recorded_utc": now}
    frozen["history"].append({"utc": now, "entry": "questions_other"})
    tmp = FROZEN.with_suffix(".tmp")
    tmp.write_text(json.dumps(frozen, indent=1) + "\n")
    tmp.replace(FROZEN)
    print(json.dumps(frozen["questions_other"]))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    default_q = str(L4D_DIR / "build" / "questions_layer1.jsonl")
    p = sub.add_parser("ckpt")
    p.add_argument("--fold", type=int, required=True)
    p.add_argument("--run", default="")
    p.add_argument("--questions", default=default_q)
    p = sub.add_parser("tau")
    p.add_argument("--fold", type=int)
    p.add_argument("--readout", action="store_true")
    p.add_argument("--answers", required=True)
    p.add_argument("--questions", default=default_q)
    p = sub.add_parser("freeze")
    p.add_argument("--fold", type=int)
    p.add_argument("--readout", action="store_true")
    p.add_argument("--questions", default=default_q)
    sub.add_parser("record-questions")
    args = ap.parse_args()
    {"ckpt": cmd_ckpt, "tau": cmd_tau, "freeze": cmd_freeze,
     "record-questions": cmd_record_questions}[args.cmd](args)


if __name__ == "__main__":
    main()

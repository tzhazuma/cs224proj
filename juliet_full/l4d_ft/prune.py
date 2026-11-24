"""L4-D (opt.): ask only the questions the v1 rules can read (post-hoc, user-approved 2026-11-24; lane l4d-train).

Static rule, read off the rule bodies of l4d/l4d.dl (and derive.evaluate_unit, its Python twin):
  leak(a) :- heap(a), exec_any(a), !freed(a).      heap blocks a are alloc sites (heap asked) and realloc sites
  freed(a) :- rel(f, a), exec_all(f).              f ranges over the release/realloc sites paired with a by rel
  leak(r) :- realloc(r), exec_any(r), !realloc_safe(r).
so a fact is only read for: heap on alloc sites, exec_any on alloc/realloc sites, exec_all on release/realloc sites,
every rel, every realloc_safe. exec_any/exec_all on stmt sites, exec_all on alloc sites and exec_any on release
sites never enter a rule body or the soft score, so dropping them cannot change pred, score or the leak list.
A unit without a kept question has no heap block -> pred 0, score 0, no model call.
(Same predicate as needed() in juliet_full/analysis/l4d_peek/prune_check.py, parent's check.)

    ../l4d/.venv/bin/python prune.py test            # gold oracle + stored lora_l4d answers: full == pruned
    ../l4d/.venv/bin/python prune.py units --layer L # results/lora_l4d_opt/<L>/eval_r1_units.jsonl from stored answers
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
L4D_DIR = JULIET_FULL / "l4d"
sys.path.insert(0, str(L4D_DIR))
import derive  # noqa: E402  (l4d-data lane, read-only)

LAYERS = ("layer1", "layer3", "placebo", "original")
L4D_PY = L4D_DIR / ".venv" / "bin" / "python"


def needed(q: dict) -> bool:
    """True iff the v1 rules (or the soft score) can read this question's fact."""
    t, kind = q["qtype"], q["site_kinds"][0]
    if t == "heap":
        return kind == "alloc"
    if t == "exec_any":
        return kind in ("alloc", "realloc")
    if t == "exec_all":
        return kind in ("release", "realloc")
    return t in ("rel", "realloc_safe")


def prune(questions: list[dict]) -> list[dict]:
    return [q for q in questions if needed(q)]


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def by_unit(questions: list[dict]) -> dict[str, list[dict]]:
    out = defaultdict(list)
    for q in questions:
        out[q["unit_id"]].append(q)
    return out


def verdict(qs: list[dict], p_of: dict, tau: float) -> dict:
    if not qs:
        return {"pred": 0, "score": 0.0, "leaks": []}
    p = {(q["qtype"], tuple(q["site_ids"])): p_of[q["qid"]] for q in qs}
    return derive.evaluate_unit(derive.unit_inputs(qs), p, tau)


def compare(units: dict[str, list[dict]], p_of: dict, tau_of) -> dict:
    d_pred = d_leaks = 0
    d_score = 0.0
    n_full = n_kept = zero = 0
    for uid, qs in units.items():
        kept = prune(qs)
        a, b = verdict(qs, p_of, tau_of(uid)), verdict(kept, p_of, tau_of(uid))
        d_pred += a["pred"] != b["pred"]
        d_leaks += a["leaks"] != b["leaks"]
        d_score = max(d_score, abs(a["score"] - b["score"]))
        n_full, n_kept, zero = n_full + len(qs), n_kept + len(kept), zero + (not kept)
    return {"n_units": len(units), "n_questions": n_full, "n_kept": n_kept, "kept_frac": n_kept / max(n_full, 1),
            "units_without_kept_question": zero, "pred_diffs": d_pred, "leak_list_diffs": d_leaks,
            "max_abs_score_diff": d_score}


def counts(units: dict[str, list[dict]]) -> dict:
    def s(v):
        v = sorted(v)
        return {"median": statistics.median(v), "p90": v[int(0.9 * (len(v) - 1))], "mean": statistics.fmean(v),
                "max": v[-1]}
    return {"full": s([len(qs) for qs in units.values()]), "pruned": s([len(prune(qs)) for qs in units.values()])}


def cmd_test(args) -> None:
    frozen = json.loads((HERE / "FROZEN").read_text())
    groups = set(json.loads((JULIET_FULL / "data/build/subsets.json").read_text())["latency300"])
    out = {"rule": "see prune.py docstring", "utc": utc_now(), "layers": {}}
    ok = True
    for layer in LAYERS:
        qs = read_jsonl(L4D_DIR / "build" / f"questions_{layer}.jsonl")
        fold_of = {u["unit_id"]: u["fold"] for u in read_jsonl(JULIET_FULL / "data/build" / f"{layer}.jsonl")}
        lat_ids = {u["unit_id"] for u in read_jsonl(JULIET_FULL / "data/build" / f"{layer}.jsonl")
                   if u["group_id"] in groups}
        res = {"gold": {}, "stored_lora_l4d": {}}
        gold_p = {q["qid"]: float(q["gold"] or 0) for q in qs}  # derive.py --gold: null -> 0
        for set_name in ("dev", "eval"):
            units = by_unit([q for q in qs if q["set"] == set_name])
            res["gold"][set_name] = compare(units, gold_p, lambda _u: 0.5)
        ans_file = HERE / "results" / "lora_l4d" / layer / "eval_r1.jsonl"
        if ans_file.exists():
            p = {a["qid"]: a["p_yes"] for a in read_jsonl(ans_file)}
            for k in (0, 1, 2):
                units = by_unit([q for q in qs if q["set"] == "eval" and fold_of[q["unit_id"]] == k])
                tau = frozen["folds"][str(k)]["tau"]
                res["stored_lora_l4d"][f"fold{k}"] = compare(units, p, lambda _u, t=tau: t) | {"tau": tau}
        else:
            res["stored_answers_missing"] = True
        eval_units = by_unit([q for q in qs if q["set"] == "eval"])
        res["questions_per_unit_eval"] = counts(eval_units)
        res["questions_per_unit_latency300"] = counts({u: v for u, v in eval_units.items() if u in lat_ids})
        checks = list(res["gold"].values()) + list(res["stored_lora_l4d"].values())
        res["pass"] = ans_file.exists() and all(c["pred_diffs"] == 0 and c["leak_list_diffs"] == 0 and c["max_abs_score_diff"] == 0.0
                          for c in checks)
        ok &= res["pass"]
        out["layers"][layer] = res
        print(layer, json.dumps({k: res[k] for k in ("gold", "stored_lora_l4d", "pass")}))
    out["pass"] = ok
    dest = HERE / "results" / "scores" / "prune_test.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print("PASS" if ok else "FAIL", dest)
    sys.exit(0 if ok else 1)


def cmd_units(args) -> None:
    """lora_l4d_opt units from the stored lora_l4d answers, derive.py --souffle on the pruned questions per fold."""
    frozen = json.loads((HERE / "FROZEN").read_text())
    layer = args.layer
    units = [u for u in read_jsonl(JULIET_FULL / "data/build" / f"{layer}.jsonl") if u["set"] == "eval"]
    fold_of = {u["unit_id"]: u["fold"] for u in units}
    src_ans = HERE / "results" / "lora_l4d" / layer / "eval_r1.jsonl"
    src_units = HERE / "results" / "lora_l4d" / layer / "eval_r1_units.jsonl"
    answers = {a["qid"]: a for a in read_jsonl(src_ans)}
    full_rows = {r["unit_id"]: r for r in read_jsonl(src_units)}
    qs = [q for q in read_jsonl(L4D_DIR / "build" / f"questions_{layer}.jsonl") if q["set"] == "eval"]
    kept = prune(qs)
    rows = {}
    for k in (0, 1, 2):
        tau = frozen["folds"][str(k)]["tau"]
        kq = [q for q in kept if fold_of[q["unit_id"]] == k]
        model = full_rows[next(u for u in fold_of if fold_of[u] == k)]["model"]
        with tempfile.TemporaryDirectory(prefix="l4dft_opt_") as td:
            qf, af, uf = Path(td, "q.jsonl"), Path(td, "a.jsonl"), Path(td, "u.jsonl")
            qf.write_text("".join(json.dumps(q) + "\n" for q in kq))
            af.write_text("".join(json.dumps(answers[q["qid"]]) + "\n" for q in kq))
            subprocess.run([str(L4D_PY), str(L4D_DIR / "derive.py"), "--questions", str(qf), "--answers", str(af),
                            "--tau", str(tau), "--method", "lora_l4d_opt", "--model", model, "--out", str(uf),
                            "--souffle"], capture_output=True, text=True, check=True)
            for r in read_jsonl(uf):
                rows[r["unit_id"]] = r
        for uid in (u for u in fold_of if fold_of[u] == k and u not in rows):
            rows[uid] = {"unit_id": uid, "method": "lora_l4d_opt", "strategy": "L4D", "model": model,
                         "layer": full_rows[uid]["layer"], "pred": 0, "score": 0.0, "latency_s": None,
                         "status": "ok", "extra": {"leaks": [], "no_kept_question": True}}
    n_kept = defaultdict(int)
    for q in kept:
        n_kept[q["unit_id"]] += 1
    out_rows = []
    diffs = 0
    for u in units:
        r = rows[u["unit_id"]]
        r["latency_s"] = None
        r["extra"].update({"fold": fold_of[u["unit_id"]], "n_questions_kept": n_kept[u["unit_id"]],
                           "derived_from": str(src_ans.relative_to(JULIET_FULL)),
                           "latency_note": "model time of the pruned question set is measured in the latency300 runs"})
        diffs += r["pred"] != full_rows[u["unit_id"]]["pred"]
        out_rows.append(r)
    out_dir = HERE / "results" / "lora_l4d_opt" / layer
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "eval_r1_units.jsonl"
    dest.write_text("".join(json.dumps(r) + "\n" for r in out_rows))
    meta = {"method": "lora_l4d_opt", "label": "L4-D (opt.)", "post_hoc": "user-approved 2026-11-24",
            "layer": layer, "n_units": len(out_rows), "n_questions_kept": len(kept), "n_questions_full": len(qs),
            "derived_from": str(src_ans.relative_to(JULIET_FULL)), "derived_from_sha256": file_sha256(src_ans),
            "pred_diffs_vs_lora_l4d": diffs, "tau": {str(k): frozen["folds"][str(k)]["tau"] for k in (0, 1, 2)},
            "frozen_sha256": file_sha256(HERE / "FROZEN"), "units_sha256": file_sha256(dest), "utc": utc_now()}
    dest.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(json.dumps(meta))
    assert diffs == 0, diffs


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test")
    p = sub.add_parser("units")
    p.add_argument("--layer", choices=LAYERS, required=True)
    args = ap.parse_args()
    {"test": cmd_test, "units": cmd_units}[args.cmd](args)


if __name__ == "__main__":
    main()

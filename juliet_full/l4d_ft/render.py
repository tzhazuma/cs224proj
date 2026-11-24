"""Render L4-D fact questions to model inputs on dell (lane l4d-train).

  render.py questions --layer layer1 [--sample]
      l4d/build/questions_<layer>[_sample].jsonl -> data/q_<layer>[_sample].jsonl, one row per question:
      {qid, unit_id, layer, set, fold, qtype, gold, text, n_tokens}; text = server/l4d_prompt.render(state, question)
  render.py train --fold k --target-questions N [--layer layer1] [--sample]
      training subsample of data/q_layer1.jsonl for fold k: set == eval and fold != k only. Per (qtype, label) cell
      keep min(n_cell, cap) questions (uniform, seed SEED + k); cap = largest value with total <= N.
      Adds weight = n_kept / (n_cells * n_kept_cell) (class-balanced CE per (qtype, label); mean weight 1).
      -> data/train_fold<k>.jsonl
data/manifest.json records sha256 of every source/rendered file, the template hash, the chat template hash and the
Yes/No token ids. Layer3/placebo/original are refused unless ../l4d_ft/FROZEN exists (freeze rule).

Run: PYTHONPYCACHEPREFIX=/tmp/l4dft-pycache ../decision_ft/.venv/bin/python render.py ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
L4D_BUILD = JULIET_FULL / "l4d" / "build"
DATA = HERE / "data"
MODEL_DIR = Path("/home/barton/tools/cs224/models/Qwen3.5-4B")
SEED = 20261123
sys.path.insert(0, str(HERE / "server"))
from l4d_prompt import TEMPLATE_SHA256, render  # noqa: E402

KEEP = ("qid", "unit_id", "layer", "set", "fold", "qtype", "gold")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    tmp.replace(path)


def update_manifest(key: str, entry: dict) -> None:
    path = DATA / "manifest.json"
    manifest = json.loads(path.read_text()) if path.exists() else {}
    manifest[key] = {**entry, "written_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def cmd_questions(args) -> None:
    from transformers import AutoTokenizer
    if args.layer != "layer1" and not (HERE / "FROZEN").exists():
        raise SystemExit(f"freeze rule: {args.layer} may only be rendered after l4d_ft/FROZEN is written")
    src = L4D_BUILD / f"questions_{args.layer}{'_sample' if args.sample else ''}.jsonl"
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    yes = tokenizer.encode("Yes", add_special_tokens=False)
    no = tokenizer.encode("No", add_special_tokens=False)
    rows = read_jsonl(src)
    assert len({r["qid"] for r in rows}) == len(rows), "duplicate qid"
    out = []
    for r in rows:
        text = render(tokenizer, r["state"], r["question"])
        n = len(tokenizer(text, add_special_tokens=False)["input_ids"])
        out.append({**{k: r.get(k) for k in KEEP}, "text": text, "n_tokens": n})
    name = f"q_{args.layer}{'_sample' if args.sample else ''}"
    dst = DATA / f"{name}.jsonl"
    write_jsonl(dst, out)
    tok = [r["n_tokens"] for r in out]
    per_unit = Counter(r["unit_id"] for r in out)
    entry = {"source": str(src.relative_to(JULIET_FULL)), "source_sha256": file_sha256(src),
             "rendered": str(dst.relative_to(HERE)), "rendered_sha256": file_sha256(dst),
             "template_sha256": TEMPLATE_SHA256,
             "chat_template_sha256": hashlib.sha256(tokenizer.chat_template.encode()).hexdigest(),
             "yes_token_id": yes, "no_token_id": no, "n_questions": len(out), "n_units": len(per_unit),
             "qtype_label_counts": {f"{q}/{g}": c for (q, g), c in
                                    sorted(Counter((r["qtype"], r["gold"]) for r in out).items(), key=str)},
             "n_tokens_total": sum(tok), "n_tokens_median": sorted(tok)[len(tok) // 2], "n_tokens_max": max(tok),
             "questions_per_unit_median": sorted(per_unit.values())[len(per_unit) // 2],
             "questions_per_unit_max": max(per_unit.values())}
    update_manifest(name, entry)
    print(json.dumps(entry, indent=1))


def cmd_train(args) -> None:
    name = f"q_layer1{'_sample' if args.sample else ''}"
    rows = read_jsonl(DATA / f"{name}.jsonl")
    if args.sample:  # pipeline test only: the sample may hold dev units only
        pool = [r for r in rows if r["gold"] in (0, 1)]
    else:
        pool = [r for r in rows if r["set"] == "eval" and r["fold"] != args.fold and r["gold"] in (0, 1)]
    cells: dict[tuple, list[dict]] = defaultdict(list)
    for r in pool:
        cells[(r["qtype"], r["gold"])].append(r)
    sizes = sorted(len(v) for v in cells.values())
    cap = max(sizes)
    if sum(sizes) > args.target_questions:  # largest cap with sum(min(n, cap)) <= target
        lo, hi = 1, max(sizes)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if sum(min(n, mid) for n in sizes) <= args.target_questions:
                lo = mid
            else:
                hi = mid - 1
        cap = lo
    rng = random.Random(SEED + args.fold)
    kept = []
    for key in sorted(cells, key=str):
        group = sorted(cells[key], key=lambda r: r["qid"])
        kept += group if len(group) <= cap else rng.sample(group, cap)
    counts = Counter((r["qtype"], r["gold"]) for r in kept)
    for r in kept:
        r["weight"] = len(kept) / (len(counts) * counts[(r["qtype"], r["gold"])])
    kept.sort(key=lambda r: r["qid"])
    dst = DATA / f"train_fold{args.fold}{'_sample' if args.sample else ''}.jsonl"
    write_jsonl(dst, kept)
    entry = {"source": f"data/{name}.jsonl", "source_sha256": file_sha256(DATA / f"{name}.jsonl"),
             "rendered": str(dst.relative_to(HERE)), "rendered_sha256": file_sha256(dst), "fold": args.fold,
             "rule": "set == eval and fold != k (layer1); per (qtype, gold) cell min(n, cap), seed SEED + fold",
             "target_questions": args.target_questions, "cap": cap, "n_pool": len(pool), "n_kept": len(kept),
             "n_units": len({r["unit_id"] for r in kept}), "n_tokens_total": sum(r["n_tokens"] for r in kept),
             "cells": {f"{q}/{g}": {"pool": len(cells[(q, g)]), "kept": counts[(q, g)],
                                    "weight": len(kept) / (len(counts) * counts[(q, g)])}
                       for (q, g) in sorted(cells, key=str)}}
    update_manifest(dst.stem, entry)
    print(json.dumps(entry, indent=1))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("questions")
    p.add_argument("--layer", choices=("layer1", "layer3", "placebo", "original"), required=True)
    p.add_argument("--sample", action="store_true")
    p = sub.add_parser("train")
    p.add_argument("--fold", type=int, choices=(0, 1, 2), required=True)
    p.add_argument("--target-questions", type=int, required=True)
    p.add_argument("--sample", action="store_true")
    args = parser.parse_args()
    {"questions": cmd_questions, "train": cmd_train}[args.cmd](args)


if __name__ == "__main__":
    main()

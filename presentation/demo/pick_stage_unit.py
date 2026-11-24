#!/usr/bin/env python3
"""Rank eval groups for the stage demo from the stored predictions (read-only; prints, writes nothing).

A candidate group: on layer 1 Clang SA, DeepSeek L1/L3, the fine-tuned decision model (L1 and L3, held-out
fold) and L4-D (lora_l4d_opt, held-out fold) are correct on the bad unit and its good twin; on layer 3 (the same
dead-free transform the demo inserts) the bad unit is still flagged by Clang SA and L4-D while grep v0 and the
decision model L1 say "no leak". DeepSeek has
layer-3 predictions only on the API subsets (api_rest332 + nested25), so a candidate must be in them. Ranked
by: grep v0 also correct on the good twin (B2G twins, so grep is right before the attack), Jev also correct on
layer 1, DeepSeek L1/L3 correct on layer 3, then by short model_text.

    python3 pick_stage_unit.py [--top 10] [--group GROUP_ID]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

JULIET_FULL = Path(__file__).resolve().parents[2] / "juliet_full"
STATIC = JULIET_FULL / "static" / "results"
FT = JULIET_FULL / "decision_ft" / "results" / "decision_ft"
L4D = JULIET_FULL / "l4d_ft" / "results" / "lora_l4d_opt"
LLM = JULIET_FULL / "llm" / "results"

# method -> {layer: [files]} (several files = union of disjoint subsets)
SOURCES = {
    "grep": {"layer1": [STATIC / "grep_v0/layer1/full_v1.jsonl"], "layer3": [STATIC / "grep_v0/layer3/full_v1.jsonl"]},
    "clang": {"layer1": [STATIC / "clang_sa/layer1/full_v2.jsonl"], "layer3": [STATIC / "clang_sa/layer3/full_v1.jsonl"]},
    "ft_l1": {"layer1": [FT / "layer1/L1_cv_v1.jsonl"], "layer3": [FT / "layer3/L1_cv_v1.jsonl"]},
    "ft_l3": {"layer1": [FT / "layer1/L3_cv_v1.jsonl"], "layer3": [FT / "layer3/L3_cv_v1.jsonl"]},
    "l4d": {"layer1": [L4D / "layer1/eval_r1_units.jsonl"], "layer3": [L4D / "layer3/eval_r1_units.jsonl"]},
    "ds_l1": {"layer1": [LLM / "deepseek_flash/layer1/eval_L1_r1.jsonl"],
              "layer3": [LLM / "deepseek_flash/layer3/l3_apirest_L1_r1.jsonl",
                         LLM / "deepseek_flash/layer3/l3_n25_L1_r1.jsonl"]},
    "ds_l3": {"layer1": [LLM / "deepseek_flash/layer1/eval_L3_r1.jsonl"],
              "layer3": [LLM / "deepseek_flash/layer3/l3_apirest_L3_r1.jsonl",
                         LLM / "deepseek_flash/layer3/l3_n25_L3_r1.jsonl"]},
    "jev": {"layer1": [LLM / "jev/layer1/eval_L1_r1.jsonl"], "layer3": [LLM / "jev/layer3/l3_eval_L1_r1.jsonl"]},
}
LAYER1_CORRECT = ("clang", "ds_l1", "ds_l3", "ft_l1", "ft_l3", "l4d")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_predictions() -> dict[tuple[str, str], dict[str, dict]]:
    """(method, layer) -> unit_id -> prediction row (status ok only)."""
    out: dict[tuple[str, str], dict[str, dict]] = {}
    for method, layers in SOURCES.items():
        for layer, files in layers.items():
            rows = out.setdefault((method, layer), {})
            for path in files:
                for row in read_jsonl(path):
                    if row.get("status", "ok") == "ok" and row.get("pred") is not None:
                        rows[row["unit_id"]] = row
    return out


def pred(preds: dict, method: str, layer: str, unit_id: str) -> int | None:
    row = preds[(method, layer)].get(unit_id)
    return None if row is None else int(row["pred"])


def pred_text(preds: dict, method: str, layer: str, unit_id: str) -> str:
    row = preds[(method, layer)].get(unit_id)
    if row is None:
        return "–"
    s = row.get("score")
    if not isinstance(s, (int, float)) or method in ("grep", "clang"):
        return str(row["pred"])
    if method == "l4d":  # derive.py soft score; questions asked after pruning
        return f"{row['pred']} ({s:.2f}, {row['extra']['n_questions_kept']}q)"
    return f"{row['pred']} ({s:+.2f})" if method.startswith("ft") else f"{row['pred']} ({s:.2f})"


def candidates(units: list[dict], preds: dict) -> list[tuple[tuple, dict, dict]]:
    by_group: dict[str, dict[str, dict]] = {}
    for u in units:
        if u["set"] == "eval":
            by_group.setdefault(u["group_id"], {})[u["label"]] = u
    found = []
    for pair in by_group.values():
        bad, good = pair.get("bad"), pair.get("good")
        if bad is None or good is None:
            continue
        b, g = bad["unit_id"], good["unit_id"]
        if not all(pred(preds, m, "layer1", b) == 1 and pred(preds, m, "layer1", g) == 0 for m in LAYER1_CORRECT):
            continue
        if (pred(preds, "clang", "layer3", b) != 1 or pred(preds, "l4d", "layer3", b) != 1
                or pred(preds, "grep", "layer3", b) != 0 or pred(preds, "ft_l1", "layer3", b) != 0):
            continue
        if pred(preds, "ds_l1", "layer3", b) is None or pred(preds, "ds_l3", "layer3", b) is None:
            continue
        jev_ok = pred(preds, "jev", "layer1", b) == 1 and pred(preds, "jev", "layer1", g) == 0
        grep_good_ok = pred(preds, "grep", "layer1", g) == 0  # B2G twins: grep right on layer 1, then fooled
        ds3_ok = (pred(preds, "ds_l1", "layer3", b) == 1) + (pred(preds, "ds_l3", "layer3", b) == 1)
        n_lines = max(len(bad["model_text"].splitlines()), len(good["model_text"].splitlines()))
        found.append(((not grep_good_ok, not jev_ok, -ds3_ok, n_lines, bad["group_id"]), bad, good))
    return sorted(found, key=lambda x: x[0])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--group", help="show this group only (whether or not it qualifies)")
    args = parser.parse_args()
    units = read_jsonl(JULIET_FULL / "data" / "build" / "layer1.jsonl")
    preds = load_predictions()
    if args.group:
        pair = {u["label"]: u for u in units if u["group_id"] == args.group}
        n_lines = max(len(u["model_text"].splitlines()) for u in pair.values())
        shown = [((n_lines, args.group), pair["bad"], pair["good"])]
    else:
        shown = candidates(units, preds)
        print(f"{len(shown)} candidate groups")
    for key, bad, good in shown[: args.top]:
        b, g = bad["unit_id"], good["unit_id"]
        print(f"\n{bad['group_id']}  flow {bad['flow_category']} · {bad['mechanism']} · fold {bad['fold']} · "
              f"good {good['good_kind']} · {key[-2]} lines")
        for tag, layer, uid in (("layer1 bad ", "layer1", b), ("layer1 good", "layer1", g),
                                ("layer3 bad ", "layer3", b)):
            print(f"  {tag}: " + "  ".join(f"{m}={pred_text(preds, m, layer, uid)}" for m in SOURCES))


if __name__ == "__main__":
    main()

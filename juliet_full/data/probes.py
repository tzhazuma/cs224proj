#!/usr/bin/env python3
"""Shortcut probes (PLAN 2.6): original.jsonl vs layer1.jsonl on the eval set.

Probes (thresholds/directions picked on dev, scored on eval):
  static_void     "contains `static void` -> good";
  func_count      number of function definitions in model_text, best threshold rule;
  length_lines    non-blank model_text lines, best threshold rule;
  length_tokens   Qwen3.5-4B tokenizer tokens, best threshold rule (if the tokenizer loads);
  grep_v0         "no `free(` and no `delete` -> leak" (no training), overall / B2G / G2B;
  bow_lr          uni+bigram bag-of-words logistic regression trained on dev: AUROC and
                  macro-F1 overall / B2G / G2B.
B2G/G2B subsets = all units of the groups whose layer-1 good unit is B2G/G2B (same groups in
both files). Acceptance (PLAN 2.6, layer 1): static_void, func_count, length macro-F1 <= 0.60.

Run with the lane venv: .venv/bin/python probes.py
Writes build/probes.json and build/probes_report.md.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score

DATA_DIR = Path(__file__).resolve().parent
BUILD = DATA_DIR / "build"
TOKENIZER = Path("/home/barton/tools/cs224/models/Qwen3.5-4B/tokenizer.json")
FORMAT_LIMIT = 0.60
FUNC_DEF_RE = re.compile(r"^[A-Za-z_][^;{}()]*\([^;{}]*\)\s*(const)?\s*\n\{", re.M)
CODE_TOKEN = r"[A-Za-z_]\w*|\d+|==|!=|<=|>=|->|::|&&|\|\||[^\s\w]"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def macro_f1(y: list[int], pred: list[int]) -> float:
    return float(f1_score(y, pred, average="macro", labels=[0, 1], zero_division=0))


def func_count(text: str) -> int:
    return len(FUNC_DEF_RE.findall(text))


def nonblank_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip() and not line.startswith("// ---- part"))


def has_free(text: str) -> bool:
    return "free(" in text or re.search(r"\bdelete\b", text) is not None


def fit_threshold(values: list[float], y: list[int]) -> tuple[float, str, float]:
    """Best rule `value >= t -> leak` or `value < t -> leak` on dev by macro-F1."""
    best = (0.0, ">=", -1.0)
    for t in sorted(set(values)) + [max(values) + 1]:
        for direction in (">=", "<"):
            pred = [int(v >= t) if direction == ">=" else int(v < t) for v in values]
            score = macro_f1(y, pred)
            if score > best[2]:
                best = (float(t), direction, score)
    return best


def apply_threshold(values: list[float], t: float, direction: str) -> list[int]:
    return [int(v >= t) if direction == ">=" else int(v < t) for v in values]


def subsets(units: list[dict], kinds: dict[str, str]) -> dict[str, list[int]]:
    idx = {"all": list(range(len(units)))}
    for kind in ("B2G", "G2B"):
        idx[kind] = [i for i, u in enumerate(units) if kinds[u["group_id"]] == kind]
    return idx


def score_rule(y: list[int], pred: list[int], idx: dict[str, list[int]]) -> dict[str, float]:
    return {name: round(macro_f1([y[i] for i in ids], [pred[i] for i in ids]), 4) for name, ids in idx.items()}


def load_tokenizer():
    try:
        from tokenizers import Tokenizer
        return Tokenizer.from_file(str(TOKENIZER))
    except Exception as exc:  # optional probe
        print(f"tokenizer unavailable: {exc}")
        return None


def probe_layer(units: list[dict], kinds: dict[str, str], tokenizer) -> dict:
    dev = [u for u in units if u["set"] == "dev"]
    ev = [u for u in units if u["set"] == "eval"]
    y_dev = [u["truth"] for u in dev]
    y_ev = [u["truth"] for u in ev]
    idx = subsets(ev, kinds)
    out: dict = {"n_eval": len(ev), "n_dev": len(dev)}

    pred = [0 if "static void" in u["model_text"] else 1 for u in ev]
    out["static_void"] = {"rule": "contains 'static void' -> good", "macro_f1": score_rule(y_ev, pred, idx),
                          "rate_good": round(np.mean([("static void" in u["model_text"]) for u in ev if u["truth"] == 0]), 4),
                          "rate_bad": round(np.mean([("static void" in u["model_text"]) for u in ev if u["truth"] == 1]), 4)}

    features = {
        "func_count": func_count,
        "length_lines": nonblank_lines,
    }
    if tokenizer is not None:
        features["length_tokens"] = lambda text: len(tokenizer.encode(text).ids)
    for name, fn in features.items():
        v_dev = [fn(u["model_text"]) for u in dev]
        v_ev = [fn(u["model_text"]) for u in ev]
        t, direction, dev_f1 = fit_threshold(v_dev, y_dev)
        pred = apply_threshold(v_ev, t, direction)
        out[name] = {
            "rule": f"{name} {direction} {t:g} -> leak",
            "dev_macro_f1": round(dev_f1, 4),
            "macro_f1": score_rule(y_ev, pred, idx),
            "mean_bad": round(float(np.mean([v for v, y in zip(v_ev, y_ev) if y == 1])), 2),
            "mean_good": round(float(np.mean([v for v, y in zip(v_ev, y_ev) if y == 0])), 2),
        }

    pred = [0 if has_free(u["model_text"]) else 1 for u in ev]
    out["grep_v0"] = {"rule": "no free( and no delete -> leak", "macro_f1": score_rule(y_ev, pred, idx)}

    vec = CountVectorizer(token_pattern=CODE_TOKEN, lowercase=False, ngram_range=(1, 2), binary=True, min_df=2)
    x_dev = vec.fit_transform([u["model_text"] for u in dev])
    x_ev = vec.transform([u["model_text"] for u in ev])
    model = LogisticRegression(C=1.0, max_iter=5000)
    model.fit(x_dev, y_dev)
    prob = model.predict_proba(x_ev)[:, 1]
    pred = [int(p >= 0.5) for p in prob]
    auroc = {name: round(float(roc_auc_score([y_ev[i] for i in ids], [prob[i] for i in ids])), 4)
             for name, ids in idx.items()}
    names = vec.get_feature_names_out()
    order = np.argsort(model.coef_[0])
    out["bow_lr"] = {
        "auroc": auroc,
        "macro_f1": score_rule(y_ev, pred, idx),
        "top_leak_features": [str(names[i]) for i in order[::-1][:10]],
        "top_noleak_features": [str(names[i]) for i in order[:10]],
    }
    return out


def report(result: dict) -> str:
    rows = [
        ("static `static void` -> good", "static_void", "macro_f1"),
        ("function-count rule", "func_count", "macro_f1"),
        ("length rule (non-blank lines)", "length_lines", "macro_f1"),
        ("length rule (Qwen tokens)", "length_tokens", "macro_f1"),
        ("grep v0 (no free/delete -> leak)", "grep_v0", "macro_f1"),
        ("BoW LR macro-F1 (dev-trained)", "bow_lr", "macro_f1"),
        ("BoW LR AUROC (dev-trained)", "bow_lr", "auroc"),
    ]
    lines = ["# Shortcut probes: original Juliet vs layer 1 (eval set)", "",
             "Generated by `juliet_full/data/probes.py`. Thresholds and the BoW model are fit on dev "
             "(330 groups) separately per layer and scored on eval (1,328 groups, 2,656 units). "
             "B2G/G2B = all units of the groups whose layer-1 good unit is B2G/G2B.", "",
             "| probe | original all | original B2G | original G2B | layer1 all | layer1 B2G | layer1 G2B |",
             "|---|---|---|---|---|---|---|"]
    for label, key, metric in rows:
        if key not in result["original"]:
            continue
        cells = []
        for layer in ("original", "layer1"):
            vals = result[layer][key][metric]
            cells += [f"{vals['all']:.3f}", f"{vals['B2G']:.3f}", f"{vals['G2B']:.3f}"]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += ["", "Rules picked on dev:", ""]
    for layer in ("original", "layer1"):
        for key in ("func_count", "length_lines", "length_tokens"):
            if key in result[layer]:
                r = result[layer][key]
                lines.append(f"- {layer} {key}: `{r['rule']}` (dev macro-F1 {r['dev_macro_f1']:.3f}; "
                             f"eval mean bad {r['mean_bad']}, good {r['mean_good']})")
        sv = result[layer]["static_void"]
        lines.append(f"- {layer} `static void` present: good {sv['rate_good']:.1%}, bad {sv['rate_bad']:.1%}")
    lines += ["", "## Acceptance (PLAN 2.6, layer 1: format probes macro-F1 <= 0.60)", ""]
    for key, ok in result["acceptance"]["checks"].items():
        lines.append(f"- {key}: {result['layer1'][key]['macro_f1']['all']:.3f} -> {'PASS' if ok else 'FAIL'}")
    lines.append(f"- overall: {'PASS' if result['acceptance']['pass'] else 'FAIL'}")
    lines += ["", "## BoW top features (layer 1)", "",
              "- leak: " + ", ".join(f"`{f}`" for f in result["layer1"]["bow_lr"]["top_leak_features"]),
              "- no leak: " + ", ".join(f"`{f}`" for f in result["layer1"]["bow_lr"]["top_noleak_features"]),
              "", "## BoW top features (original)", "",
              "- leak: " + ", ".join(f"`{f}`" for f in result["original"]["bow_lr"]["top_leak_features"]),
              "- no leak: " + ", ".join(f"`{f}`" for f in result["original"]["bow_lr"]["top_noleak_features"])]
    return "\n".join(lines) + "\n"


def main() -> None:
    layer1 = load(BUILD / "layer1.jsonl")
    original = load(BUILD / "original.jsonl")
    kinds = {u["group_id"]: u["good_kind"] for u in layer1 if u["label"] == "good"}
    tokenizer = load_tokenizer()
    result = {"original": probe_layer(original, kinds, tokenizer), "layer1": probe_layer(layer1, kinds, tokenizer)}
    format_keys = [k for k in ("static_void", "func_count", "length_lines", "length_tokens") if k in result["layer1"]]
    checks = {k: result["layer1"][k]["macro_f1"]["all"] <= FORMAT_LIMIT for k in format_keys}
    result["acceptance"] = {"limit": FORMAT_LIMIT, "checks": checks, "pass": all(checks.values())}
    (BUILD / "probes.json").write_text(json.dumps(result, indent=1) + "\n")
    text = report(result)
    (BUILD / "probes_report.md").write_text(text)
    print(text)


if __name__ == "__main__":
    main()

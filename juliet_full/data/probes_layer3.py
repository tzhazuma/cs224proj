#!/usr/bin/env python3
"""Shortcut probes for layer 3 (stress) and placebo (PLAN 2.6), next to original and layer 1.

Probes, thresholds/directions/BoW fit on dev, scored on eval (2,656 units):
  static_void, func_count, length_lines, length_tokens   format probes (as in probes.py)
  grep_v0   no `free(`/`delete` -> leak                  (acceptance on the B2G subset)
  grep_v1   a free/delete NOT directly inside an if-block -> good, else leak
  grep_v2   number of free/delete statements, best threshold rule from dev
  bow_lr    uni+bigram BoW logistic regression trained on dev (AUROC; acceptance on B2G)
Acceptance on layer 3 (stress): every probe above <= 0.60 macro-F1 (grep_v0 on B2G),
BoW AUROC on B2G <= 0.65. Placebo keeps the real frees unwrapped and has no dead frees, so
the grep probes stay at their layer-1 values by design; only the format probes are checked.

--dev-check FILE...: design check on dev only (rules in-sample on dev, BoW by 5-fold
variant CV on dev) for construction variants, without looking at eval.

Run with the lane venv: .venv/bin/python probes_layer3.py
Writes build/probes_layer3.json and build/probes_layer3_report.md.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

DATA_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DATA_DIR))
import probes  # noqa: E402

BUILD = DATA_DIR / "build"
FREE_LINE_RE = re.compile(r"^\s*(free\s*\(|delete\b)")
LIMIT_F1 = 0.60
LIMIT_AUROC = 0.65
LAYERS = {"original": "original.jsonl", "layer1": "layer1.jsonl", "layer3": "layer3.jsonl", "placebo": "placebo.jsonl"}


def free_lines(text: str) -> list[int]:
    return [i for i, line in enumerate(text.splitlines()) if FREE_LINE_RE.match(line)]


def free_count(text: str) -> int:
    return len(free_lines(text))


def has_unguarded_free(text: str) -> bool:
    lines = text.splitlines()
    for i in free_lines(text):
        prev = [l.strip() for l in lines[max(0, i - 3):i] if l.strip()]
        guarded = len(prev) >= 2 and prev[-1] == "{" and re.match(r"(else\s+)?if\s*\(", prev[-2])
        if not guarded:
            return True
    return False


def vectorizer() -> CountVectorizer:
    return CountVectorizer(token_pattern=probes.CODE_TOKEN, lowercase=False, ngram_range=(1, 2), binary=True,
                           min_df=2)


def rule_probes(dev: list[dict], ev: list[dict], idx: dict, tokenizer) -> dict:
    y_dev = [u["truth"] for u in dev]
    y_ev = [u["truth"] for u in ev]
    out = {}
    pred = [0 if "static void" in u["model_text"] else 1 for u in ev]
    out["static_void"] = {"rule": "contains 'static void' -> good", "macro_f1": probes.score_rule(y_ev, pred, idx)}
    features = {"func_count": probes.func_count, "length_lines": probes.nonblank_lines, "grep_v2": free_count}
    if tokenizer is not None:
        features["length_tokens"] = lambda text: len(tokenizer.encode(text).ids)
    for name, fn in features.items():
        v_dev = [fn(u["model_text"]) for u in dev]
        v_ev = [fn(u["model_text"]) for u in ev]
        t, direction, dev_f1 = probes.fit_threshold(v_dev, y_dev)
        out[name] = {"rule": f"{name} {direction} {t:g} -> leak", "dev_macro_f1": round(dev_f1, 4),
                     "macro_f1": probes.score_rule(y_ev, probes.apply_threshold(v_ev, t, direction), idx),
                     "mean_bad": round(float(np.mean([v for v, y in zip(v_ev, y_ev) if y == 1])), 2),
                     "mean_good": round(float(np.mean([v for v, y in zip(v_ev, y_ev) if y == 0])), 2)}
    pred = [0 if probes.has_free(u["model_text"]) else 1 for u in ev]
    out["grep_v0"] = {"rule": "no free( and no delete -> leak", "macro_f1": probes.score_rule(y_ev, pred, idx)}
    pred = [0 if has_unguarded_free(u["model_text"]) else 1 for u in ev]
    out["grep_v1"] = {"rule": "free/delete not directly in an if-block -> good", "macro_f1": probes.score_rule(y_ev, pred, idx)}
    return out


def bow(dev: list[dict], ev: list[dict], idx: dict) -> dict:
    vec = vectorizer()
    x_dev = vec.fit_transform([u["model_text"] for u in dev])
    model = LogisticRegression(C=1.0, max_iter=5000).fit(x_dev, [u["truth"] for u in dev])
    prob = model.predict_proba(vec.transform([u["model_text"] for u in ev]))[:, 1]
    y = [u["truth"] for u in ev]
    names = vec.get_feature_names_out()
    order = np.argsort(model.coef_[0])
    return {"auroc": {k: round(float(roc_auc_score([y[i] for i in ids], [prob[i] for i in ids])), 4) for k, ids in idx.items()},
            "macro_f1": probes.score_rule(y, [int(p >= 0.5) for p in prob], idx),
            "top_leak_features": [str(names[i]) for i in order[::-1][:10]],
            "top_noleak_features": [str(names[i]) for i in order[:10]]}


def acceptance(layer: str, r: dict) -> dict:
    checks = {k: r[k]["macro_f1"]["all"] <= LIMIT_F1 for k in ("static_void", "func_count", "length_lines", "length_tokens") if k in r}
    if layer == "layer3":
        checks["grep_v0 (B2G)"] = r["grep_v0"]["macro_f1"]["B2G"] <= LIMIT_F1
        checks["grep_v1"] = r["grep_v1"]["macro_f1"]["all"] <= LIMIT_F1
        checks["grep_v2"] = r["grep_v2"]["macro_f1"]["all"] <= LIMIT_F1
        checks["bow_lr AUROC (B2G)"] = r["bow_lr"]["auroc"]["B2G"] <= LIMIT_AUROC
    return {"checks": checks, "pass": all(checks.values())}


def dev_check(paths: list[str], kinds: dict) -> None:
    from sklearn.model_selection import GroupKFold
    for path in paths:
        units = [u for u in probes.load(Path(path)) if u["set"] == "dev"]
        idx = probes.subsets(units, kinds)
        r = rule_probes(units, units, idx, None)
        x = vectorizer().fit_transform([u["model_text"] for u in units])
        y = np.array([u["truth"] for u in units])
        prob = np.zeros(len(units))
        groups = [u["variant"] for u in units]  # leave-variant-out: eval has other variants
        for tr, te in GroupKFold(n_splits=len(set(groups))).split(x, y, groups):
            vec = vectorizer()
            xtr = vec.fit_transform([units[i]["model_text"] for i in tr])
            m = LogisticRegression(C=1.0, max_iter=5000).fit(xtr, y[tr])
            prob[te] = m.predict_proba(vec.transform([units[i]["model_text"] for i in te]))[:, 1]
        auroc = {k: round(float(roc_auc_score(y[ids], prob[ids])), 3) for k, ids in idx.items()}
        vec = vectorizer()
        m = LogisticRegression(C=1.0, max_iter=5000).fit(vec.fit_transform([u["model_text"] for u in units]), y)
        names = vec.get_feature_names_out()
        order = np.argsort(m.coef_[0])
        print(Path(path).name, "dev in-sample macro-F1:",
              {k: v["macro_f1"]["all"] for k, v in r.items()}, "grep_v0 B2G", r["grep_v0"]["macro_f1"]["B2G"])
        print("   BoW leave-variant-out AUROC", auroc)
        print("   leak:", [str(names[i]) for i in order[::-1][:12]])
        print("   noleak:", [str(names[i]) for i in order[:12]])


def report(res: dict) -> str:
    rows = [("static `static void` -> good", "static_void", "macro_f1"), ("function-count rule", "func_count", "macro_f1"),
            ("length rule (lines)", "length_lines", "macro_f1"), ("length rule (Qwen tokens)", "length_tokens", "macro_f1"),
            ("grep v0 (no free -> leak)", "grep_v0", "macro_f1"), ("grep v1 (unguarded free -> good)", "grep_v1", "macro_f1"),
            ("grep v2 (free-count rule)", "grep_v2", "macro_f1"), ("BoW LR macro-F1", "bow_lr", "macro_f1"),
            ("BoW LR AUROC", "bow_lr", "auroc")]
    layers = [l for l in LAYERS if l in res]
    head = " | ".join(f"{l} all | {l} B2G" for l in layers)
    lines = ["# Shortcut probes: original -> layer 1 -> layer 3 (stress) / placebo (eval set)", "",
             "Generated by `juliet_full/data/probes_layer3.py`. Rules and BoW fit on dev per layer, scored on eval "
             "(2,656 units). B2G = units of the groups whose layer-1 good is B2G (G2B in probes_layer3.json).", "",
             f"| probe | {head} |", "|---|" + "---|" * (2 * len(layers))]
    for label, key, metric in rows:
        if key not in res[layers[0]]:
            continue
        cells = []
        for l in layers:
            v = res[l][key][metric]
            cells += [f"{v['all']:.3f}", f"{v['B2G']:.3f}"]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += ["", "Rules picked on dev:", ""]
    for l in layers:
        for key in ("func_count", "length_lines", "length_tokens", "grep_v2"):
            if key in res[l]:
                r = res[l][key]
                lines.append(f"- {l} {key}: `{r['rule']}` (dev {r['dev_macro_f1']:.3f}; eval mean bad {r['mean_bad']}, good {r['mean_good']})")
    lines += ["", "## Acceptance (PLAN 2.6)", ""]
    for l in ("layer3", "placebo"):
        if l in res:
            acc = res[l]["acceptance"]
            lines.append(f"- {l}: " + ", ".join(f"{k} {'PASS' if ok else 'FAIL'}" for k, ok in acc["checks"].items())
                         + f" -> {'PASS' if acc['pass'] else 'FAIL'}")
    lines.append("- placebo grep probes are not checked: placebo keeps real frees unwrapped and inserts no frees (by design).")
    for l in ("layer3", "placebo"):
        if l in res:
            lines += ["", f"## BoW top features ({l})", "",
                      "- leak: " + ", ".join(f"`{f}`" for f in res[l]["bow_lr"]["top_leak_features"]),
                      "- no leak: " + ", ".join(f"`{f}`" for f in res[l]["bow_lr"]["top_noleak_features"])]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev-check", nargs="*", default=None)
    args = parser.parse_args()
    layer1 = probes.load(BUILD / "layer1.jsonl")
    kinds = {u["group_id"]: u["good_kind"] for u in layer1 if u["label"] == "good"}
    if args.dev_check is not None:
        dev_check(args.dev_check, kinds)
        return
    tokenizer = probes.load_tokenizer()
    res = {}
    for layer, name in LAYERS.items():
        units = probes.load(BUILD / name)
        dev = [u for u in units if u["set"] == "dev"]
        ev = [u for u in units if u["set"] == "eval"]
        idx = probes.subsets(ev, kinds)
        res[layer] = rule_probes(dev, ev, idx, tokenizer)
        res[layer]["bow_lr"] = bow(dev, ev, idx)
        if layer in ("layer3", "placebo"):
            res[layer]["acceptance"] = acceptance(layer, res[layer])
    (BUILD / "probes_layer3.json").write_text(json.dumps(res, indent=1) + "\n")
    text = report(res)
    (BUILD / "probes_layer3_report.md").write_text(text)
    print(text)


if __name__ == "__main__":
    main()

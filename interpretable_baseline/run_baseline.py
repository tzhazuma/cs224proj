#!/usr/bin/env python3
"""Interpretable non-LLM baselines for Tier A detection (SecVulEval split v1).

The script fits only on ``splits/dev_detection_40.json`` and evaluates once on
``splits/test_detection_160.json``.  It never reads a credential, never calls a
model, and never writes outside the chosen output directory.

Design (frozen before the test run; see README.md):

* seven fixed binary rules: label prior, short length, high call count,
  allocation/free imbalance, memory/string API use, and two combinations;
* two small L2 logistic regressions (5 features, standard-library IRLS),
  unweighted and class-balanced, threshold fixed at 0.5;
* the "selected on dev" rule is the rule with the best dev macro-F1, with a
  pre-declared tie-break (higher MCC, then lower complexity);
* test-tuned oracle thresholds and a test-fitted LR are reported only as
  upper bounds, never as methods.

Usage:
    python3 interpretable_baseline/run_baseline.py
    python3 interpretable_baseline/run_baseline.py --out-dir interpretable_baseline/results/smoke
    python3 interpretable_baseline/run_baseline.py --resamples 2000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEV_PATH = ROOT / "splits" / "dev_detection_40.json"
TEST_PATH = ROOT / "splits" / "test_detection_160.json"
LLM_GLOB = "benchmark/results/tier_a/*/*/predictions.jsonl"
DEFAULT_OUT = ROOT / "interpretable_baseline" / "results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
BOOTSTRAP_SEED = 42
DEFAULT_RESAMPLES = 10000
CI = 0.95

FEATURE_NAMES = [
    "chars",
    "lines",
    "tokens",
    "calls",
    "call_density",
    "alloc",
    "realloc",
    "free",
    "alloc_minus_free",
    "mem_api",
    "branches",
    "branch_density",
    "ptr_arrow",
    "nulls",
    "returns",
]

LR_FEATURES = ["log_chars", "calls", "alloc_minus_free", "mem_api", "branch_density"]

CALL_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "do", "else",
    "case", "defined", "__attribute__", "decltype", "alignof", "static_assert",
}

MEM_API_RE = re.compile(
    r"\b(memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|snprintf|gets|"
    r"scanf|sscanf|alloca)\b"
)
ALLOC_RE = re.compile(r"\b(malloc|calloc|strdup|strndup|new)\b")
REALLOC_RE = re.compile(r"\brealloc\b")
FREE_RE = re.compile(r"\bfree\b|\bdelete\b")
BRANCH_RE = re.compile(r"\b(if|for|while|switch|case)\b")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IDENT_RE = re.compile(r"[A-Za-z_]\w*")
NULL_RE = re.compile(r"\bNULL\b|\bnullptr\b")
RETURN_RE = re.compile(r"\breturn\b")


# ---------------------------------------------------------------------------
# feature extraction


def strip_comments_strings(src: str) -> str:
    """Remove C/C++ comments and string/char literals, preserving newlines.

    Raw string literals are not handled specially; the extractor is a lexical
    screen, not a parser.  This is documented as a limitation.
    """

    out: list[str] = []
    i = 0
    n = len(src)
    state = "code"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"
                i += 2
                out.append(" ")
            elif c == "/" and nxt == "*":
                state = "block"
                i += 2
                out.append(" ")
            elif c == '"':
                state = "string"
                i += 1
                out.append(" ")
            elif c == "'":
                state = "char"
                i += 1
                out.append(" ")
            else:
                out.append(c)
                i += 1
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append("\n")
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
                out.append(" ")
            else:
                if c == "\n":
                    out.append("\n")
                i += 1
        else:  # string or char
            if c == "\\":
                i += 2
            elif (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = "code"
                i += 1
                out.append(" ")
            else:
                i += 1
    return "".join(out)


def extract_features(body: str) -> dict[str, float]:
    raw = body or ""
    stripped = strip_comments_strings(raw)
    brace = stripped.find("{")
    code = stripped[brace + 1:] if brace >= 0 else stripped

    tokens = IDENT_RE.findall(code)
    calls = [m for m in CALL_RE.findall(code) if m not in CALL_KEYWORDS]
    lines = raw.count("\n") + 1
    alloc = len(ALLOC_RE.findall(code))
    free = len(FREE_RE.findall(code))
    branches = len(BRANCH_RE.findall(code))

    return {
        "chars": float(len(raw)),
        "lines": float(lines),
        "tokens": float(len(tokens)),
        "calls": float(len(calls)),
        "call_density": float(len(calls)) / max(lines, 1),
        "alloc": float(alloc),
        "realloc": float(len(REALLOC_RE.findall(code))),
        "free": float(free),
        "alloc_minus_free": float(alloc - free),
        "mem_api": float(len(MEM_API_RE.findall(code))),
        "branches": float(branches),
        "branch_density": float(branches) / max(lines, 1),
        "ptr_arrow": float(code.count("->")),
        "nulls": float(len(NULL_RE.findall(code))),
        "returns": float(len(RETURN_RE.findall(code))),
    }


def lr_vector(features: dict[str, float]) -> list[float]:
    return [
        math.log1p(features["chars"]),
        features["calls"],
        features["alloc_minus_free"],
        features["mem_api"],
        features["branch_density"],
    ]


# ---------------------------------------------------------------------------
# split loading and isolation checks


def load_split(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data["samples"]
    out = []
    for sample in samples:
        body = sample.get("func_body") or ""
        out.append(
            {
                "idx": int(sample["idx"]),
                "project": str(sample["project"]),
                "label": bool(sample["is_vulnerable"]),
                "body": body,
                "features": extract_features(body),
            }
        )
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def isolate(dev: list[dict], test: list[dict]) -> dict:
    dev_idx = {row["idx"] for row in dev}
    test_idx = {row["idx"] for row in test}
    dev_proj = {row["project"] for row in dev}
    test_proj = {row["project"] for row in test}
    dev_hash = {hashlib.md5(row["body"].encode("utf-8")).hexdigest() for row in dev}
    test_hash = {hashlib.md5(row["body"].encode("utf-8")).hexdigest() for row in test}
    report = {
        "dev_n": len(dev),
        "test_n": len(test),
        "idx_overlap": len(dev_idx & test_idx),
        "project_overlap": sorted(dev_proj & test_proj),
        "exact_body_md5_overlap": len(dev_hash & test_hash),
        "test_projects": len(test_proj),
    }
    if report["idx_overlap"] or report["project_overlap"] or report["exact_body_md5_overlap"]:
        raise SystemExit("split isolation violated: {}".format(report))
    return report


# ---------------------------------------------------------------------------
# metrics (re-implemented to match benchmark/tools/bench_common.py)


def _safe_ratio(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def detection_scores(labels: list[bool], predictions: list[bool | None]) -> dict:
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal length")
    tp = fp = tn = fn = invalid = 0
    for label, pred in zip(labels, predictions):
        if pred is None:
            invalid += 1
            continue
        if label and pred:
            tp += 1
        elif label and not pred:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    n = len(labels)
    valid = tp + fp + tn + fn
    pos = tp + fn
    neg = tn + fp
    pred_pos = tp + fp
    precision = _safe_ratio(tp, pred_pos)
    recall = _safe_ratio(tp, pos)
    specificity = _safe_ratio(tn, neg)
    if pos == 0:
        positive_f1 = None
    elif pred_pos == 0:
        positive_f1 = 0.0
    else:
        positive_f1 = 2.0 * tp / (2.0 * tp + fp + fn)
    if neg == 0:
        negative_f1 = None
    elif tn + fn == 0:
        negative_f1 = 0.0
    else:
        negative_f1 = 2.0 * tn / (2.0 * tn + fn + fp)
    macro_f1 = None if positive_f1 is None or negative_f1 is None else (positive_f1 + negative_f1) / 2.0
    ba = None if recall is None or specificity is None else (recall + specificity) / 2.0
    accuracy = _safe_ratio(tp + tn, valid)
    strict = _safe_ratio(tp + tn, n)
    coverage = _safe_ratio(valid, n)
    denom = math.sqrt(float(pred_pos * pos * neg * (tn + fn)))
    if denom == 0:
        mcc = 0.0 if valid > 0 else None
        mcc_degenerate = True
    else:
        mcc = (tp * tn - fp * fn) / denom
        mcc_degenerate = False
    return {
        "n": n,
        "valid": valid,
        "invalid": invalid,
        "coverage": coverage,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "label_counts": {"vulnerable": pos, "non_vulnerable": neg},
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": positive_f1,
        "negative_f1": negative_f1,
        "macro_f1": macro_f1,
        "balanced_accuracy": ba,
        "accuracy": accuracy,
        "strict_accuracy": strict,
        "mcc": mcc,
        "mcc_degenerate": mcc_degenerate,
        "predicted_positive_rate": _safe_ratio(pred_pos, valid),
        "wilson": {
            "precision": wilson_interval(tp, pred_pos),
            "recall": wilson_interval(tp, pos),
            "specificity": wilson_interval(tn, neg),
            "accuracy": wilson_interval(tp + tn, valid),
            "strict_accuracy": wilson_interval(tp + tn, n),
            "coverage": wilson_interval(valid, n),
        },
    }


def wilson_interval(k: int, n: int, z: float = 1.959963984540054) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / denom
    margin = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    pos = (len(values) - 1) * q
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(values) - 1)
    frac = pos - lo
    return values[lo] * (1.0 - frac) + values[hi] * frac


def bootstrap_metrics(
    labels: list[bool],
    predictions: list[bool | None],
    clusters: list[str],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict:
    grouped: dict[str, list[int]] = defaultdict(list)
    for i, cluster in enumerate(clusters):
        grouped[cluster].append(i)
    keys = sorted(grouped)
    rng = random.Random(seed)
    macro: list[float] = []
    mccs: list[float] = []
    accs: list[float] = []
    bas: list[float] = []
    for _ in range(resamples):
        sampled = [rng.choice(keys) for _ in keys]
        idxs: list[int] = []
        for key in sampled:
            idxs.extend(grouped[key])
        scores = detection_scores([labels[i] for i in idxs], [predictions[i] for i in idxs])
        if scores["macro_f1"] is not None:
            macro.append(scores["macro_f1"])
        if scores["mcc"] is not None:
            mccs.append(scores["mcc"])
        if scores["accuracy"] is not None:
            accs.append(scores["accuracy"])
        if scores["balanced_accuracy"] is not None:
            bas.append(scores["balanced_accuracy"])
    alpha = (1.0 - CI) / 2.0
    return {
        "resamples": resamples,
        "seed": seed,
        "cluster_unit": "project",
        "cluster_count": len(keys),
        "usable_macro_f1": len(macro),
        "macro_f1_ci95": [percentile(macro, alpha), percentile(macro, 1.0 - alpha)],
        "mcc_ci95": [percentile(mccs, alpha), percentile(mccs, 1.0 - alpha)],
        "accuracy_ci95": [percentile(accs, alpha), percentile(accs, 1.0 - alpha)],
        "balanced_accuracy_ci95": [percentile(bas, alpha), percentile(bas, 1.0 - alpha)],
    }


def bootstrap_diff(
    labels: list[bool],
    pred_a: list[bool | None],
    pred_b: list[bool | None],
    clusters: list[str],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict:
    grouped: dict[str, list[int]] = defaultdict(list)
    for i, cluster in enumerate(clusters):
        grouped[cluster].append(i)
    keys = sorted(grouped)
    rng = random.Random(seed)
    diffs: list[float] = []
    for _ in range(resamples):
        sampled = [rng.choice(keys) for _ in keys]
        idxs: list[int] = []
        for key in sampled:
            idxs.extend(grouped[key])
        y = [labels[i] for i in idxs]
        a = detection_scores(y, [pred_a[i] for i in idxs])["macro_f1"]
        b = detection_scores(y, [pred_b[i] for i in idxs])["macro_f1"]
        if a is not None and b is not None:
            diffs.append(a - b)
    alpha = (1.0 - CI) / 2.0
    return {
        "delta_macro_f1": _delta_macro_f1(labels, pred_a, pred_b),
        "ci95": [percentile(diffs, alpha), percentile(diffs, 1.0 - alpha)],
        "resamples": resamples,
        "usable": len(diffs),
    }


def _delta_macro_f1(labels: list[bool], pred_a: list[bool | None], pred_b: list[bool | None]) -> float | None:
    a = detection_scores(labels, pred_a)["macro_f1"]
    b = detection_scores(labels, pred_b)["macro_f1"]
    if a is None or b is None:
        return None
    return a - b


def mcnemar_exact(b: int, c: int) -> float:
    discordant = b + c
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, i) for i in range(min(b, c) + 1)) / (2.0 ** discordant)
    return min(1.0, 2.0 * tail)


def holm_adjust(pvalues: list[float]) -> list[float]:
    if not pvalues:
        return []
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: (pvalues[i], i))
    adjusted = [1.0] * m
    running = 0.0
    for rank, index in enumerate(order):
        candidate = (m - rank) * pvalues[index]
        running = max(running, candidate)
        adjusted[index] = min(1.0, running)
    return adjusted


# ---------------------------------------------------------------------------
# logistic regression (IRLS, standard library only)


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _log1pexp(x: float) -> float:
    if x > 0:
        return x + math.log1p(math.exp(-x))
    return math.log1p(math.exp(x))


def _solve_linear(a: list[list[float]], b: list[float]) -> list[float] | None:
    n = len(b)
    m = [list(a[i]) + [b[i]] for i in range(n)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[pivot][col]) < 1e-12:
            return None
        m[col], m[pivot] = m[pivot], m[col]
        pv = m[col][col]
        for j in range(col, n + 1):
            m[col][j] /= pv
        for r in range(n):
            if r != col and m[r][col] != 0.0:
                factor = m[r][col]
                for j in range(col, n + 1):
                    m[r][j] -= factor * m[col][j]
    return [m[i][n] for i in range(n)]


def fit_logreg(
    x: list[list[float]],
    y: list[bool],
    *,
    l2: float = 1.0,
    balanced: bool = False,
) -> dict:
    n = len(y)
    d = len(x[0])
    mean = [sum(row[j] for row in x) / n for j in range(d)]
    scale = []
    for j in range(d):
        var = sum((row[j] - mean[j]) ** 2 for row in x) / n
        scale.append(math.sqrt(var) if var > 0 else 1.0)
    z = [[(row[j] - mean[j]) / scale[j] for j in range(d)] + [1.0] for row in x]
    n_pos = sum(1 for label in y if label)
    n_neg = n - n_pos
    if balanced:
        w_pos = n / (2.0 * max(n_pos, 1))
        w_neg = n / (2.0 * max(n_neg, 1))
    else:
        w_pos = w_neg = 1.0
    weights = [w_pos if label else w_neg for label in y]

    beta = [0.0] * (d + 1)

    def objective(vec: list[float]) -> float:
        total = 0.0
        for i in range(n):
            eta = sum(vec[j] * z[i][j] for j in range(d + 1))
            total += weights[i] * (_log1pexp(eta) - (1.0 if y[i] else 0.0) * eta)
        return total + 0.5 * l2 * sum(vec[j] * vec[j] for j in range(d))

    current = objective(beta)
    iterations = 0
    converged = False
    for iterations in range(1, 101):
        probs = [_sigmoid(sum(beta[j] * z[i][j] for j in range(d + 1))) for i in range(n)]
        grad = [0.0] * (d + 1)
        for j in range(d + 1):
            grad[j] = sum(weights[i] * (probs[i] - (1.0 if y[i] else 0.0)) * z[i][j] for i in range(n))
            if j < d:
                grad[j] += l2 * beta[j]
        hess = [[0.0] * (d + 1) for _ in range(d + 1)]
        for j in range(d + 1):
            for k in range(d + 1):
                value = sum(
                    weights[i] * probs[i] * (1.0 - probs[i]) * z[i][j] * z[i][k]
                    for i in range(n)
                )
                if j == k and j < d:
                    value += l2
                hess[j][k] = value
        for j in range(d + 1):
            hess[j][j] += 1e-10
        step = _solve_linear(hess, grad)
        if step is None:
            break
        max_step = max(abs(value) for value in step)
        if max_step > 10.0:
            step = [value * 10.0 / max_step for value in step]
        t = 1.0
        candidate = [beta[j] - t * step[j] for j in range(d + 1)]
        while t > 1e-8:
            candidate = [beta[j] - t * step[j] for j in range(d + 1)]
            value = objective(candidate)
            if value <= current + 1e-12:
                break
            t *= 0.5
        delta = max(abs(candidate[j] - beta[j]) for j in range(d + 1))
        beta = candidate
        current = objective(beta)
        if delta < 1e-9:
            converged = True
            break

    return {
        "feature_names": LR_FEATURES,
        "mean": mean,
        "scale": scale,
        "beta_standardized": beta[:d],
        "intercept": beta[d],
        "l2": l2,
        "balanced": balanced,
        "class_weights": {"positive": w_pos, "negative": w_neg},
        "iterations": iterations,
        "converged": converged,
    }


def predict_logreg(model: dict, rows: list[dict]) -> list[float]:
    out = []
    for row in rows:
        vec = lr_vector(row["features"])
        eta = model["intercept"]
        for j, value in enumerate(vec):
            eta += model["beta_standardized"][j] * (value - model["mean"][j]) / model["scale"][j]
        out.append(_sigmoid(eta))
    return out


def loo_logreg(rows: list[dict], *, balanced: bool) -> list[bool]:
    preds: list[bool] = []
    for i in range(len(rows)):
        train = rows[:i] + rows[i + 1:]
        model = fit_logreg(
            [lr_vector(row["features"]) for row in train],
            [row["label"] for row in train],
            balanced=balanced,
        )
        score = predict_logreg(model, [rows[i]])[0]
        preds.append(score >= 0.5)
    return preds


# ---------------------------------------------------------------------------
# rules


def rule_predictions(rows: list[dict], thresholds: dict) -> dict[str, list[bool]]:
    preds: dict[str, list[bool]] = {}
    for name in RULE_NAMES:
        values: list[bool] = []
        for row in rows:
            f = row["features"]
            if name == "prior_majority":
                values.append(thresholds["prior_positive"])
            elif name == "length_short":
                values.append(f["chars"] <= thresholds["chars"])
            elif name == "calls_high":
                values.append(f["calls"] >= thresholds["calls"])
            elif name == "alloc_unbalanced":
                values.append(f["alloc_minus_free"] > 0)
            elif name == "mem_api_present":
                values.append(f["mem_api"] >= 1)
            elif name == "alloc_or_mem":
                values.append(f["alloc_minus_free"] > 0 or f["mem_api"] >= 1)
            elif name == "short_and_alloc_or_mem":
                values.append(
                    f["chars"] <= thresholds["chars"]
                    and (f["alloc_minus_free"] > 0 or f["mem_api"] >= 1)
                )
            else:
                raise ValueError(name)
        preds[name] = values
    return preds


RULE_NAMES = [
    "prior_majority",
    "length_short",
    "calls_high",
    "alloc_unbalanced",
    "mem_api_present",
    "alloc_or_mem",
    "short_and_alloc_or_mem",
]

RULE_COMPLEXITY = {
    "prior_majority": 0,
    "length_short": 1,
    "calls_high": 1,
    "alloc_unbalanced": 1,
    "mem_api_present": 1,
    "alloc_or_mem": 2,
    "short_and_alloc_or_mem": 3,
}

RULE_DESCRIPTION = {
    "prior_majority": "always vulnerable (dev prevalence 0.8 > 0.5)",
    "length_short": "chars <= dev median",
    "calls_high": "call sites >= dev median",
    "alloc_unbalanced": "allocation sites > free/delete sites",
    "mem_api_present": "at least one memory/string API call",
    "alloc_or_mem": "alloc_unbalanced OR mem_api_present",
    "short_and_alloc_or_mem": "length_short AND (alloc_unbalanced OR mem_api_present)",
}


def build_thresholds(dev: list[dict]) -> dict:
    chars = [row["features"]["chars"] for row in dev]
    calls = [row["features"]["calls"] for row in dev]
    pos_rate = sum(1 for row in dev if row["label"]) / len(dev)
    return {
        "chars": statistics.median(chars),
        "calls": statistics.median(calls),
        "prior_positive": pos_rate >= 0.5,
        "dev_positive_rate": pos_rate,
    }


# ---------------------------------------------------------------------------
# LLM runs


def load_llm_runs(test: list[dict]) -> tuple[list[dict], list[dict]]:
    test_idx = {row["idx"] for row in test}
    runs = []
    verifications = []
    for path in sorted(ROOT.glob(LLM_GLOB)):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        det = [row for row in rows if row.get("task") == "detection"]
        if not det:
            continue
        by_idx: dict[int, dict] = {}
        for row in det:
            idx = int(str(row["unit_id"]).split(":")[-1])
            if idx in by_idx:
                raise SystemExit("duplicate unit in {}: {}".format(path, idx))
            by_idx[idx] = row
        if set(by_idx) != test_idx:
            raise SystemExit(
                "LLM run {} does not cover the frozen test split: missing {}, extra {}".format(
                    path, len(test_idx - set(by_idx)), len(set(by_idx) - test_idx)
                )
            )
        labels: list[bool] = []
        preds: list[bool | None] = []
        clusters: list[str] = []
        rationales: dict[int, str] = {}
        confidences: dict[int, float | None] = {}
        for row in test:
            record = by_idx[row["idx"]]
            label = bool(record["label"]["y_true"])
            if label != row["label"]:
                raise SystemExit("label mismatch in {} unit {}".format(path, row["idx"]))
            labels.append(label)
            if record.get("status") == "ok":
                pred = record.get("prediction", {}).get("y_pred")
                preds.append(bool(pred) if pred is not None else None)
            else:
                preds.append(None)
            clusters.append(row["project"])
            rationales[row["idx"]] = str(record.get("prediction", {}).get("rationale") or "")
            conf = record.get("prediction", {}).get("confidence")
            confidences[row["idx"]] = float(conf) if isinstance(conf, (int, float)) else None

        scores = detection_scores(labels, preds)
        metrics_path = path.parent / "metrics.json"
        verification = {"run_id": path.parent.name, "metrics_path": str(metrics_path), "match": None, "deltas": {}}
        if metrics_path.exists():
            published = json.loads(metrics_path.read_text(encoding="utf-8"))["tasks"]["detection"]["scores"]
            checks = {
                "macro_f1": scores["macro_f1"],
                "mcc": scores["mcc"],
                "accuracy": scores["accuracy"],
                "valid": scores["valid"],
                "tp": scores["confusion"]["tp"],
                "fp": scores["confusion"]["fp"],
                "tn": scores["confusion"]["tn"],
                "fn": scores["confusion"]["fn"],
            }
            match = True
            for key, value in checks.items():
                published_value = published.get(key) if key in published else published.get("confusion", {}).get(key)
                if isinstance(value, float) or isinstance(published_value, float):
                    delta = abs(float(value) - float(published_value)) if published_value is not None else None
                    verification["deltas"][key] = delta
                    if delta is None or delta > 1e-9:
                        match = False
                else:
                    verification["deltas"][key] = None if value == published_value else "mismatch"
                    if value != published_value:
                        match = False
            verification["match"] = match
            if not match:
                raise SystemExit("metric parity failed for {}: {}".format(path, verification["deltas"]))
        else:
            verification["match"] = "no metrics.json"
        verifications.append(verification)

        method = det[0].get("method", {})
        runs.append(
            {
                "run_id": path.parent.name,
                "method_id": method.get("method_id"),
                "name": method.get("name"),
                "strategy": method.get("strategy"),
                "model_id": (method.get("model") or {}).get("model_id"),
                "path": str(path.relative_to(ROOT)),
                "labels": labels,
                "predictions": preds,
                "clusters": clusters,
                "scores": scores,
                "bootstrap": bootstrap_metrics(labels, preds, clusters),
                "rationales": rationales,
                "confidences": confidences,
            }
        )
    if not runs:
        raise SystemExit("no LLM detection runs found")
    return runs, verifications


# ---------------------------------------------------------------------------
# test-tuned upper bounds


def oracle_single_feature(rows: list[dict], feature: str) -> dict:
    labels = [row["label"] for row in rows]
    values = [row["features"][feature] for row in rows]
    best = None
    for direction in ("<=", ">="):
        for threshold in sorted(set(values)):
            preds = [(value <= threshold) if direction == "<=" else (value >= threshold) for value in values]
            scores = detection_scores(labels, preds)
            if scores["macro_f1"] is None:
                continue
            key = (scores["macro_f1"], scores["mcc"] or 0.0)
            if best is None or key > best["key"]:
                best = {
                    "key": key,
                    "feature": feature,
                    "direction": direction,
                    "threshold": threshold,
                    "macro_f1": scores["macro_f1"],
                    "mcc": scores["mcc"],
                    "confusion": scores["confusion"],
                    "precision": scores["precision"],
                    "recall": scores["recall"],
                    "specificity": scores["specificity"],
                }
    if best is None:
        return {"feature": feature, "macro_f1": None}
    best.pop("key", None)
    return best


def stratified_folds(labels: list[bool], k: int, seed: int) -> list[list[int]]:
    rng = random.Random(seed)
    pos = [i for i, label in enumerate(labels) if label]
    neg = [i for i, label in enumerate(labels) if not label]
    rng.shuffle(pos)
    rng.shuffle(neg)
    folds: list[list[int]] = [[] for _ in range(k)]
    for i, index in enumerate(pos):
        folds[i % k].append(index)
    for i, index in enumerate(neg):
        folds[i % k].append(index)
    return folds


def confidence_oracle(rows: list[dict], run: dict) -> dict | None:
    """Best macro-F1 from thresholding an LLM's self-reported confidence on test.

    This uses test labels for threshold selection, so it is an upper bound,
    not a method.
    """

    pairs = []
    for i, row in enumerate(rows):
        conf = run["confidences"].get(row["idx"])
        pred = run["predictions"][i]
        if conf is None or pred is None:
            continue
        pairs.append((row["label"], conf))
    if not pairs:
        return None
    labels = [label for label, _ in pairs]
    best = None
    for threshold in sorted({conf for _, conf in pairs}):
        preds = [conf >= threshold for _, conf in pairs]
        scores = detection_scores(labels, preds)
        if scores["macro_f1"] is None:
            continue
        key = (scores["macro_f1"], scores["mcc"] or 0.0)
        if best is None or key > best["key"]:
            best = {
                "key": key,
                "threshold": threshold,
                "macro_f1": scores["macro_f1"],
                "mcc": scores["mcc"],
                "precision": scores["precision"],
                "recall": scores["recall"],
                "specificity": scores["specificity"],
                "predicted_positive_rate": scores["predicted_positive_rate"],
                "n_scored": len(pairs),
            }
    if best is None:
        return None
    best.pop("key", None)
    return best


def test_tuned_lr(rows: list[dict], k: int = 5) -> dict:
    x = [lr_vector(row["features"]) for row in rows]
    y = [row["label"] for row in rows]
    in_model = fit_logreg(x, y, balanced=False)
    in_preds = [score >= 0.5 for score in predict_logreg(in_model, rows)]
    in_scores = detection_scores(y, in_preds)
    bal_model = fit_logreg(x, y, balanced=True)
    bal_preds = [score >= 0.5 for score in predict_logreg(bal_model, rows)]
    bal_scores = detection_scores(y, bal_preds)
    folds = stratified_folds(y, k, BOOTSTRAP_SEED)
    cv_preds: list[bool | None] = [None] * len(rows)
    for fold in folds:
        held = set(fold)
        train = [i for i in range(len(rows)) if i not in held]
        model = fit_logreg([x[i] for i in train], [y[i] for i in train], balanced=True)
        for i in fold:
            cv_preds[i] = predict_logreg(model, [rows[i]])[0] >= 0.5
    cv_scores = detection_scores(y, cv_preds)
    return {
        "in_sample_unweighted": {"model": in_model, "scores": in_scores},
        "in_sample_balanced": {"model": bal_model, "scores": bal_scores},
        "cv_balanced": {"folds": k, "seed": BOOTSTRAP_SEED, "scores": cv_scores},
    }


# ---------------------------------------------------------------------------
# error analysis


def quartile_bins(rows: list[dict]) -> list[float]:
    values = [row["features"]["chars"] for row in rows]
    return statistics.quantiles(values, n=4, method="inclusive")


def quartile_name(value: float, qs: list[float]) -> str:
    if value <= qs[0]:
        return "Q1_shortest"
    if value <= qs[1]:
        return "Q2"
    if value <= qs[2]:
        return "Q3"
    return "Q4_longest"


def stratified_scores(labels: list[bool], preds: list[bool | None], groups: list[str]) -> list[dict]:
    out = []
    counts = Counter(groups)
    for group in sorted(counts, key=lambda g: (-counts[g], g)):
        idxs = [i for i, g in enumerate(groups) if g == group]
        scores = detection_scores([labels[i] for i in idxs], [preds[i] for i in idxs])
        out.append(
            {
                "group": group,
                "n": scores["n"],
                "pos": scores["label_counts"]["vulnerable"],
                "recall": scores["recall"],
                "specificity": scores["specificity"],
                "macro_f1": scores["macro_f1"],
                "mcc": scores["mcc"],
                "confusion": scores["confusion"],
            }
        )
    return out


RATIONALE_PATTERNS = {
    "no_clear_evidence": re.compile(
        r"no (clear|obvious|evident)|not (clear|evident)|insufficient|unclear|"
        r"cannot (determine|tell)|no evidence|not enough|ambiguous",
        re.I,
    ),
    "memory_safety": re.compile(
        r"memory|buffer|overflow|out[- ]of[- ]bounds|use[- ]after[- ]free|"
        r"leak|bounds|integer overflow|double free",
        re.I,
    ),
    "validation": re.compile(r"validat|sanitiz|check|guard|input|untrusted", re.I),
    "safe_claim": re.compile(r"\bsafe\b|\bcorrect\b|properly|no issue|benign|not vulnerable", re.I),
}


def rationale_keywords(run: dict, labels: list[bool]) -> dict:
    buckets = {}
    for name, pattern in RATIONALE_PATTERNS.items():
        tp_hit = tp_total = fn_hit = fn_total = 0
        for i, idx in enumerate(run["rationales"]):
            text = run["rationales"][idx]
            if not text:
                continue
            pred = run["predictions"][i]
            label = labels[i]
            if pred is None:
                continue
            if label and pred:
                tp_total += 1
                tp_hit += 1 if pattern.search(text) else 0
            elif label and not pred:
                fn_total += 1
                fn_hit += 1 if pattern.search(text) else 0
        buckets[name] = {
            "tp_with_keyword": tp_hit,
            "tp_total": tp_total,
            "tp_rate": _safe_ratio(tp_hit, tp_total),
            "fn_with_keyword": fn_hit,
            "fn_total": fn_total,
            "fn_rate": _safe_ratio(fn_hit, fn_total),
        }
    return buckets


def error_analysis(
    rows: list[dict],
    methods: dict[str, dict],
    llm_runs: list[dict],
) -> dict:
    labels = [row["label"] for row in rows]
    clusters = [row["project"] for row in rows]
    qs = quartile_bins(rows)
    qnames = [quartile_name(row["features"]["chars"], qs) for row in rows]

    by_method_quartile = {}
    by_method_project = {}
    for name, method in methods.items():
        by_method_quartile[name] = stratified_scores(labels, method["preds"], qnames)
        by_method_project[name] = stratified_scores(labels, method["preds"], clusters)
    for run in llm_runs:
        key = "__llm_" + run["run_id"]
        by_method_quartile[key] = stratified_scores(labels, run["predictions"], qnames)
        by_method_project[key] = stratified_scores(labels, run["predictions"], clusters)

    llm_fn_overlap = {}
    llm_fp_overlap = {}
    for run in llm_runs:
        name = run["run_id"]
        fn_idx = [i for i, (label, pred) in enumerate(zip(labels, run["predictions"])) if label and pred is False]
        fp_idx = [i for i, (label, pred) in enumerate(zip(labels, run["predictions"])) if (not label) and pred is True]
        llm_fn_overlap[name] = {}
        llm_fp_overlap[name] = {}
        for method_name, method in methods.items():
            caught = sum(1 for i in fn_idx if method["preds"][i])
            avoided = sum(1 for i in fp_idx if not method["preds"][i])
            llm_fn_overlap[name][method_name] = {
                "llm_fn": len(fn_idx),
                "rule_positive": caught,
                "rate": _safe_ratio(caught, len(fn_idx)),
            }
            llm_fp_overlap[name][method_name] = {
                "llm_fp": len(fp_idx),
                "rule_negative": avoided,
                "rate": _safe_ratio(avoided, len(fp_idx)),
            }

    rationale = {
        run["run_id"]: rationale_keywords(run, labels)
        for run in llm_runs
        if any(run["rationales"].values())
    }

    return {
        "length_quartile_thresholds": qs,
        "length_quartile_counts": dict(Counter(qnames)),
        "by_method_quartile": by_method_quartile,
        "by_method_project": by_method_project,
        "llm_fn_overlap": llm_fn_overlap,
        "llm_fp_overlap": llm_fp_overlap,
        "rationale_keywords": rationale,
        "labels": labels,
        "projects": clusters,
        "quartiles": qnames,
    }


def select_cases(rows: list[dict], llm_run: dict, baseline: dict, qnames: list[str]) -> list[dict]:
    labels = [row["label"] for row in rows]
    cases = []
    for kind, wanted in (("FN", 2), ("FP", 2)):
        for quartile in ("Q1_shortest", "Q2", "Q3", "Q4_longest"):
            picked = 0
            for i, row in enumerate(rows):
                if picked >= wanted:
                    break
                pred = llm_run["predictions"][i]
                if pred is None:
                    continue
                is_target = (row["label"] and pred is False) if kind == "FN" else ((not row["label"]) and pred is True)
                if not is_target or qnames[i] != quartile:
                    continue
                cases.append(
                    {
                        "kind": kind,
                        "quartile": quartile,
                        "idx": row["idx"],
                        "project": row["project"],
                        "label": row["label"],
                        "llm_pred": pred,
                        "baseline_pred": baseline["preds"][i],
                        "features": row["features"],
                        "rationale": llm_run["rationales"].get(row["idx"], ""),
                        "code": row["body"][:1200],
                    }
                )
                picked += 1
    return cases


# ---------------------------------------------------------------------------
# markdown helpers


def fmt(value, digits: int = 3) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return ("{:.%df}" % digits).format(value)


def fmt_pct(value, digits: int = 2) -> str:
    if value is None:
        return "—"
    return ("{:.%df}%%" % digits).format(100.0 * value)


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--no-bootstrap", action="store_true")
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit("refusing to overwrite non-empty output directory: {}".format(out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    dev = load_split(DEV_PATH)
    test = load_split(TEST_PATH)
    isolation = isolate(dev, test)
    if len(dev) != 40 or len(test) != 160:
        raise SystemExit("unexpected split sizes: {} / {}".format(len(dev), len(test)))

    thresholds = build_thresholds(dev)
    dev_rules = rule_predictions(dev, thresholds)
    test_rules = rule_predictions(test, thresholds)

    dev_labels = [row["label"] for row in dev]
    test_labels = [row["label"] for row in test]
    dev_clusters = [row["project"] for row in dev]
    test_clusters = [row["project"] for row in test]

    dev_rule_scores = {name: detection_scores(dev_labels, preds) for name, preds in dev_rules.items()}
    selected_rule = sorted(
        RULE_NAMES,
        key=lambda name: (
            -(dev_rule_scores[name]["macro_f1"] or -1.0),
            -(dev_rule_scores[name]["mcc"] or -1.0),
            RULE_COMPLEXITY[name],
            name,
        ),
    )[0]

    methods: dict[str, dict] = {}
    for name in RULE_NAMES:
        methods["rule:" + name] = {
            "name": "rule:" + name,
            "family": "rule",
            "description": RULE_DESCRIPTION[name],
            "preds": test_rules[name],
            "dev_preds": dev_rules[name],
            "scores": detection_scores(test_labels, test_rules[name]),
            "dev_scores": dev_rule_scores[name],
        }

    x_dev = [lr_vector(row["features"]) for row in dev]
    y_dev = [row["label"] for row in dev]
    for name, balanced in (("lr_unweighted", False), ("lr_balanced", True)):
        model = fit_logreg(x_dev, y_dev, balanced=balanced)
        dev_scores_raw = predict_logreg(model, dev)
        dev_preds = [score >= 0.5 for score in dev_scores_raw]
        test_scores_raw = predict_logreg(model, test)
        test_preds = [score >= 0.5 for score in test_scores_raw]
        loo_preds = loo_logreg(dev, balanced=balanced)
        methods[name] = {
            "name": name,
            "family": "logreg",
            "description": "L2 logistic regression on {} features ({}), threshold 0.5".format(
                len(LR_FEATURES), "class-balanced" if balanced else "unweighted"
            ),
            "preds": test_preds,
            "dev_preds": dev_preds,
            "scores": detection_scores(test_labels, test_preds),
            "dev_scores": detection_scores(dev_labels, dev_preds),
            "dev_loo_scores": detection_scores(dev_labels, loo_preds),
            "model": model,
            "test_scores_raw": test_scores_raw,
            "dev_scores_raw": dev_scores_raw,
        }

    selected_method = methods["rule:" + selected_rule]
    # The selected method is used as the primary interpretable baseline.
    primary_name = selected_method["name"]

    # Bootstraps (skip if requested; otherwise 10k by default).
    for method in methods.values():
        if args.no_bootstrap:
            method["bootstrap"] = {"enabled": False}
        else:
            method["bootstrap"] = bootstrap_metrics(
                test_labels, method["preds"], test_clusters, resamples=args.resamples
            )

    llm_runs, verifications = load_llm_runs(test)
    llm_by_id = {run["run_id"]: run for run in llm_runs}
    reference_ids = []
    for wanted in ("legacy__test_v1_direct_independent", "tiera_secvuleval_deepseek_evidence_20261112_0e09037d"):
        if wanted in llm_by_id:
            reference_ids.append(wanted)
    if "legacy__test_v1_mimo_direct_independent" in llm_by_id:
        reference_ids.append("legacy__test_v1_mimo_direct_independent")
    best_llm = max(llm_runs, key=lambda run: (run["scores"]["macro_f1"] or -1.0, run["scores"]["mcc"] or -1.0))
    if best_llm["run_id"] not in reference_ids:
        reference_ids.append(best_llm["run_id"])

    # Paired comparisons: all baseline methods vs the reference LLM runs.
    comparisons = []
    comparison_families: dict[str, list[dict]] = defaultdict(list)
    for method in methods.values():
        for ref_id in reference_ids:
            ref = llm_by_id[ref_id]
            common = [
                i
                for i in range(len(test))
                if method["preds"][i] is not None and ref["predictions"][i] is not None
            ]
            labels = [test_labels[i] for i in common]
            a = [method["preds"][i] for i in common]
            b = [ref["predictions"][i] for i in common]
            clusters = [test_clusters[i] for i in common]
            a_correct = [pred == label for pred, label in zip(a, labels)]
            b_correct = [pred == label for pred, label in zip(b, labels)]
            b_count = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
            c_count = sum(1 for x, y in zip(a_correct, b_correct) if (not x) and y)
            p = mcnemar_exact(b_count, c_count)
            diff = bootstrap_diff(
                labels, a, b, clusters, resamples=args.resamples
            ) if not args.no_bootstrap else {"delta_macro_f1": _delta_macro_f1(labels, a, b), "ci95": [None, None]}
            row = {
                "method": method["name"],
                "llm_run": ref_id,
                "llm_name": ref["name"],
                "n_common": len(common),
                "delta_macro_f1": diff["delta_macro_f1"],
                "delta_ci95": diff["ci95"],
                "b_method_correct_llm_wrong": b_count,
                "c_method_wrong_llm_correct": c_count,
                "mcnemar_p": p,
                "family": "vs:" + ref_id,
            }
            comparisons.append(row)
            comparison_families["vs:" + ref_id].append(row)

    for family_rows in comparison_families.values():
        adjusted = holm_adjust([row["mcnemar_p"] for row in family_rows])
        for row, value in zip(family_rows, adjusted):
            row["holm_p"] = value

    # Test-tuned upper bounds.
    oracle_features = ["chars", "calls", "alloc_minus_free", "mem_api", "branch_density", "call_density"]
    oracle = {feature: oracle_single_feature(test, feature) for feature in oracle_features}
    rule_oracle = max(
        ({"method": "rule:" + name, "macro_f1": methods["rule:" + name]["scores"]["macro_f1"],
          "mcc": methods["rule:" + name]["scores"]["mcc"]} for name in RULE_NAMES),
        key=lambda row: (row["macro_f1"] or -1.0, row["mcc"] or -1.0),
    )
    lr_upper = test_tuned_lr(test, k=5)
    confidence_oracles = {
        run["run_id"]: confidence_oracle(test, run)
        for run in llm_runs
    }

    # Error analysis.
    analysis = error_analysis(test, methods, llm_runs)
    selected_llm = llm_by_id.get("legacy__test_v1_direct_independent", llm_runs[0])
    cases = select_cases(test, selected_llm, selected_method, analysis["quartiles"])

    # ---- write artifacts -------------------------------------------------
    config = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "script": str(Path(__file__).relative_to(ROOT)),
        "script_sha256": sha256_file(Path(__file__)),
        "dev_path": str(DEV_PATH.relative_to(ROOT)),
        "dev_sha256": sha256_file(DEV_PATH),
        "test_path": str(TEST_PATH.relative_to(ROOT)),
        "test_sha256": sha256_file(TEST_PATH),
        "bootstrap_resamples": args.resamples,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "ci": CI,
        "isolation": isolation,
        "thresholds": thresholds,
        "selected_rule_on_dev": selected_rule,
        "primary_method": primary_name,
        "llm_runs": [run["path"] for run in llm_runs],
    }

    features_rows = []
    for split_name, rows in (("dev", dev), ("test", test)):
        for row in rows:
            features_rows.append(
                {
                    "split": split_name,
                    "idx": row["idx"],
                    "project": row["project"],
                    "label": row["label"],
                    "features": row["features"],
                }
            )

    predictions_rows = []
    for split_name, rows in (("dev", dev), ("test", test)):
        labels = [row["label"] for row in rows]
        for method in methods.values():
            preds = method["dev_preds"] if split_name == "dev" else method["preds"]
            raw = method.get("dev_scores_raw" if split_name == "dev" else "test_scores_raw")
            for i, row in enumerate(rows):
                predictions_rows.append(
                    {
                        "split": split_name,
                        "method": method["name"],
                        "family": method["family"],
                        "idx": row["idx"],
                        "project": row["project"],
                        "label": labels[i],
                        "pred": preds[i],
                        "score": raw[i] if raw is not None else None,
                    }
                )

    metrics_payload = {
        "config": config,
        "methods": {
            name: {
                "family": method["family"],
                "description": method["description"],
                "dev": method["dev_scores"],
                "test": method["scores"],
                "bootstrap": method["bootstrap"],
                **(
                    {"dev_loo": method["dev_loo_scores"], "model": method["model"]}
                    if "model" in method
                    else {}
                ),
            }
            for name, method in methods.items()
        },
        "llm": {
            run["run_id"]: {
                "name": run["name"],
                "method_id": run["method_id"],
                "strategy": run["strategy"],
                "model_id": run["model_id"],
                "scores": run["scores"],
                "bootstrap": run["bootstrap"],
                "path": run["path"],
            }
            for run in llm_runs
        },
        "llm_metric_verification": verifications,
        "comparisons": comparisons,
        "test_tuned_upper_bound": {
            "single_feature_oracle": oracle,
            "rule_family_oracle": rule_oracle,
            "lr_in_sample_unweighted": lr_upper["in_sample_unweighted"]["scores"],
            "lr_in_sample_balanced": lr_upper["in_sample_balanced"]["scores"],
            "lr_5fold_balanced": lr_upper["cv_balanced"]["scores"],
            "llm_confidence_oracle": confidence_oracles,
            "caveat": "Uses test labels for threshold/model selection; not a valid method, only an upper bound.",
        },
        "dev_rule_table": {
            name: {"scores": dev_rule_scores[name], "description": RULE_DESCRIPTION[name]}
            for name in RULE_NAMES
        },
        "best_llm_posthoc": {
            "run_id": best_llm["run_id"],
            "name": best_llm["name"],
            "macro_f1": best_llm["scores"]["macro_f1"],
            "mcc": best_llm["scores"]["mcc"],
        },
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "features.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in features_rows) + "\n", encoding="utf-8"
    )
    (out_dir / "predictions.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in predictions_rows) + "\n", encoding="utf-8"
    )
    (out_dir / "error_analysis.json").write_text(
        json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "cases.json").write_text(json.dumps(cases, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- machine report --------------------------------------------------
    report_lines = []
    report_lines.append("# Interpretable non-LLM baselines — Tier A detection (dev40 → test160)")
    report_lines.append("")
    report_lines.append("Generated: `{}`  ".format(config["generated_utc"]))
    report_lines.append("Primary (selected on dev): `{}`  ".format(primary_name))
    report_lines.append("Test-tuned numbers are upper bounds, not methods.")
    report_lines.append("")
    report_lines.append("## Split isolation")
    report_lines.append("")
    report_lines.append("```json")
    report_lines.append(json.dumps(isolation, indent=2))
    report_lines.append("```")
    report_lines.append("")
    report_lines.append("## Dev-fitted thresholds")
    report_lines.append("")
    report_lines.append("```json")
    report_lines.append(json.dumps(thresholds, indent=2))
    report_lines.append("```")
    report_lines.append("")
    report_lines.append("## Dev rule table (selection only)")
    report_lines.append("")
    rows = []
    for name in RULE_NAMES:
        s = dev_rule_scores[name]
        rows.append([
            name, fmt(s["confusion"]["tp"]), fmt(s["confusion"]["fp"]), fmt(s["confusion"]["tn"]), fmt(s["confusion"]["fn"]),
            fmt(s["precision"]), fmt(s["recall"]), fmt(s["specificity"]), fmt(s["macro_f1"]), fmt(s["mcc"]),
        ])
    report_lines.append(md_table(["rule", "TP", "FP", "TN", "FN", "P", "R", "Spec", "macro-F1", "MCC"], rows))
    report_lines.append("")
    report_lines.append("## Test 160 (valid-only; all baselines have coverage 1.0)")
    report_lines.append("")
    rows = []
    for name, method in methods.items():
        s = method["scores"]
        ci = method["bootstrap"].get("macro_f1_ci95") if isinstance(method["bootstrap"], dict) else None
        rows.append([
            name, str(s["confusion"]["tp"]), str(s["confusion"]["fp"]), str(s["confusion"]["tn"]), str(s["confusion"]["fn"]),
            fmt(s["precision"]), fmt(s["recall"]), fmt(s["specificity"]),
            "{} [{}, {}]".format(fmt(s["macro_f1"]), fmt(ci[0]) if ci else "—", fmt(ci[1]) if ci else "—"),
            fmt(s["mcc"]), fmt(s["balanced_accuracy"]), fmt(s["predicted_positive_rate"]),
        ])
    report_lines.append(md_table(
        ["method", "TP", "FP", "TN", "FN", "P", "R", "Spec", "macro-F1 [95% CI]", "MCC", "BA", "pred+"],
        rows,
    ))
    report_lines.append("")
    report_lines.append("## LLM reference runs (recomputed; parity with published metrics.json checked)")
    report_lines.append("")
    rows = []
    for run in llm_runs:
        s = run["scores"]
        rows.append([
            run["run_id"], run["name"], str(s["valid"]), fmt(s["coverage"]),
            fmt(s["macro_f1"]), fmt(s["mcc"]), fmt(s["precision"]), fmt(s["recall"]), fmt(s["specificity"]),
        ])
    report_lines.append(md_table(["run", "method", "valid", "coverage", "macro-F1", "MCC", "P", "R", "Spec"], rows))
    report_lines.append("")
    report_lines.append("## Paired comparisons (common-valid; exact McNemar; Holm within each LLM family)")
    report_lines.append("")
    rows = []
    for row in comparisons:
        ci = row["delta_ci95"]
        rows.append([
            row["method"], row["llm_run"], str(row["n_common"]),
            "{} [{}, {}]".format(fmt(row["delta_macro_f1"]), fmt(ci[0]) if ci else "—", fmt(ci[1]) if ci else "—"),
            "{}/{}".format(row["b_method_correct_llm_wrong"], row["c_method_wrong_llm_correct"]),
            fmt(row["mcnemar_p"], 4), fmt(row["holm_p"], 4),
        ])
    report_lines.append(md_table(["baseline", "LLM", "n", "Δmacro-F1 [95% CI]", "b/c", "p", "Holm p"], rows))
    report_lines.append("")
    report_lines.append("## Test-tuned upper bound (NOT a method)")
    report_lines.append("")
    rows = []
    for feature, info in oracle.items():
        rows.append([
            feature, info.get("direction", "—"), fmt(info.get("threshold"), 1),
            fmt(info.get("macro_f1")), fmt(info.get("mcc")), fmt(info.get("recall")), fmt(info.get("specificity")),
        ])
    report_lines.append(md_table(["feature", "direction", "threshold", "macro-F1", "MCC", "R", "Spec"], rows))
    report_lines.append("")
    report_lines.append("Rule-family oracle: `{}` macro-F1 = {} (MCC {}).".format(
        rule_oracle["method"], fmt(rule_oracle["macro_f1"]), fmt(rule_oracle["mcc"])
    ))
    report_lines.append("")
    report_lines.append("LR upper bounds: in-sample unweighted macro-F1 = {}, in-sample balanced = {}, 5-fold CV balanced = {}.".format(
        fmt(lr_upper["in_sample_unweighted"]["scores"]["macro_f1"]),
        fmt(lr_upper["in_sample_balanced"]["scores"]["macro_f1"]),
        fmt(lr_upper["cv_balanced"]["scores"]["macro_f1"]),
    ))
    report_lines.append("")
    report_lines.append("LLM confidence-threshold oracle (test-tuned; upper bound only):")
    report_lines.append("")
    rows = []
    for run_id, info in confidence_oracles.items():
        if info is None:
            rows.append([run_id, "—", "—", "—", "—", "—", "—"])
            continue
        rows.append([
            run_id, fmt(info["threshold"], 2), fmt(info["macro_f1"]), fmt(info["mcc"]),
            fmt(info["recall"]), fmt(info["specificity"]), str(info["n_scored"]),
        ])
    report_lines.append(md_table(["run", "threshold", "macro-F1", "MCC", "R", "Spec", "n scored"], rows))
    report_lines.append("")
    report_lines.append("## Error analysis")
    report_lines.append("")
    report_lines.append("Length quartile thresholds: `{}`.".format(analysis["length_quartile_thresholds"]))
    report_lines.append("")
    report_lines.append("Primary baseline vs DeepSeek direct by length quartile:")
    report_lines.append("")
    rows = []
    primary_rows = analysis["by_method_quartile"][primary_name]
    llm_rows = analysis["by_method_quartile"]["__llm_legacy__test_v1_direct_independent"]
    for left, right in zip(primary_rows, llm_rows):
        rows.append([
            left["group"], str(left["n"]), str(left["pos"]),
            fmt(left["recall"]), fmt(left["specificity"]), fmt(left["macro_f1"]),
            fmt(right["recall"]), fmt(right["specificity"]), fmt(right["macro_f1"]),
        ])
    report_lines.append(md_table(
        ["quartile", "n", "pos", "rule R", "rule Spec", "rule macro-F1", "LLM R", "LLM Spec", "LLM macro-F1"],
        rows,
    ))
    report_lines.append("")
    report_lines.append("Top projects by test count (descriptive; n is small):")
    report_lines.append("")
    project_counts = Counter(analysis["projects"])
    top_projects = [name for name, _ in project_counts.most_common(5)]
    primary_projects = {row["group"]: row for row in analysis["by_method_project"][primary_name]}
    llm_projects = {row["group"]: row for row in analysis["by_method_project"]["__llm_legacy__test_v1_direct_independent"]}
    rows = []
    for project in top_projects:
        left = primary_projects.get(project, {})
        right = llm_projects.get(project, {})
        rows.append([
            project, str(project_counts[project]), str(left.get("pos", "—")),
            fmt(left.get("recall")), fmt(left.get("specificity")),
            fmt(right.get("recall")), fmt(right.get("specificity")),
        ])
    report_lines.append(md_table(["project", "n", "pos", "rule R", "rule Spec", "LLM R", "LLM Spec"], rows))
    report_lines.append("")
    report_lines.append("LLM FN caught by each rule (DeepSeek direct):")
    report_lines.append("")
    rows = []
    for method_name, info in analysis["llm_fn_overlap"].get("legacy__test_v1_direct_independent", {}).items():
        rows.append([method_name, str(info["llm_fn"]), str(info["rule_positive"]), fmt_pct(info["rate"])])
    report_lines.append(md_table(["rule", "LLM FN", "rule positive", "caught"], rows))
    report_lines.append("")
    report_lines.append("Rationale keyword rates (DeepSeek direct):")
    report_lines.append("")
    rows = []
    for key, info in analysis["rationale_keywords"].get("legacy__test_v1_direct_independent", {}).items():
        rows.append([key, fmt_pct(info["tp_rate"]), fmt_pct(info["fn_rate"]), str(info["tp_total"]), str(info["fn_total"])])
    report_lines.append(md_table(["keyword", "TP rate", "FN rate", "TP n", "FN n"], rows))
    report_lines.append("")
    (out_dir / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    manifest = {
        "generated_utc": config["generated_utc"],
        "script_sha256": config["script_sha256"],
        "python": sys.version,
        "inputs": {
            "dev": {"path": config["dev_path"], "sha256": config["dev_sha256"]},
            "test": {"path": config["test_path"], "sha256": config["test_sha256"]},
            "llm": {run["run_id"]: {"path": run["path"], "sha256": sha256_file(ROOT / run["path"])} for run in llm_runs},
        },
        "outputs": {
            name: {"sha256": sha256_file(out_dir / name)}
            for name in ("metrics.json", "features.jsonl", "predictions.jsonl", "error_analysis.json", "cases.json", "report.md")
        },
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("wrote", out_dir)
    print("primary:", primary_name)
    print("selected rule on dev:", selected_rule)
    print("test macro-F1:", fmt(selected_method["scores"]["macro_f1"]), "MCC:", fmt(selected_method["scores"]["mcc"]))
    for name in ("lr_unweighted", "lr_balanced"):
        print(name, "dev macro-F1", fmt(methods[name]["dev_scores"]["macro_f1"]),
              "dev LOO", fmt(methods[name]["dev_loo_scores"]["macro_f1"]),
              "test macro-F1", fmt(methods[name]["scores"]["macro_f1"]),
              "test MCC", fmt(methods[name]["scores"]["mcc"]))
    print("LLM parity:", all(v["match"] is True for v in verifications))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

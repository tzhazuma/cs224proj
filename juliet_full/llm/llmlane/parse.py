"""Parse the compact verdict {"label": ..., "confidence": ...} returned by generative models."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

LABEL_TO_PRED = {"vulnerable": 1, "not_vulnerable": 0}
_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.I)
_OBJECT_RE = re.compile(r"\{.*?\}", re.S)


@dataclass(frozen=True)
class Verdict:
    status: str  # "ok" or "invalid"
    pred: int | None
    score: float | None  # P(leak): confidence for "vulnerable", 1 - confidence otherwise
    label: str | None
    confidence: float | None
    note: str | None = None


def parse_verdict(text: str | None) -> Verdict:
    """Strict on the label, lenient on wrapping (code fences, surrounding prose).

    A valid label with a missing or out-of-range confidence still yields a
    prediction (status ok) but no score.
    """
    if not text or not text.strip():
        return Verdict("invalid", None, None, None, None, "empty output")
    body = _FENCE_RE.sub("", text.strip())
    candidates = [body] + _OBJECT_RE.findall(body)
    obj = None
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            obj = value
            break
    if obj is None:
        return Verdict("invalid", None, None, None, None, "no JSON object")
    label = obj.get("label")
    if not isinstance(label, str) or label.strip().lower() not in LABEL_TO_PRED:
        return Verdict("invalid", None, None, None, None, f"bad label: {label!r}")
    label = label.strip().lower()
    pred = LABEL_TO_PRED[label]
    conf = obj.get("confidence")
    if isinstance(conf, str):
        try:
            conf = float(conf)
        except ValueError:
            conf = None
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not math.isfinite(conf) \
            or not 0.0 <= conf <= 1.0:
        return Verdict("ok", pred, None, label, None, f"bad confidence: {obj.get('confidence')!r}")
    conf = float(conf)
    score = conf if pred == 1 else 1.0 - conf
    return Verdict("ok", pred, score, label, conf)

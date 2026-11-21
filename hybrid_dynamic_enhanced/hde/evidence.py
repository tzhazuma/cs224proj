"""Turn the dynamic_enhanced export into a label-free evidence block.

The export (``dynamic_enhanced/exports/hybrid``) is the only source of the
enhanced evidence.  Every string sent to a model is rendered from numeric
fields and fixed wording; no path, file name, unit id, CWE id or label token is
copied from the export.  A fail-closed scan runs on every rendered block.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DYNE_EXPORT, ROOT, V2_INPUTS

MODES = ("default", "realloc_fail", "nogobal")
MODE_LABEL = {
    "default": (
        "default configuration (standard leak-detector root set)"
    ),
    "realloc_fail": (
        "realloc-failure configuration (the first realloc that receives a "
        "non-null pointer is forced to fail)"
    ),
    "nogobal": (
        "global-roots-disabled configuration (global and static variables are "
        "not treated as leak roots)"
    ),
}
MODE_SHORT = {
    "default": "default configuration",
    "realloc_fail": "realloc-failure configuration",
    "nogobal": "global-roots-disabled configuration",
}

# Markers that would turn the evidence block into a label or a pointer to the
# unit's identity.  The shared prompt audit covers the rest of the prompt.
FORBIDDEN_EVIDENCE = {
    "cwe": re.compile(r"(?i)\bcwe\s*-?\s*\d*"),
    "label_bad_good": re.compile(r"(?i)\b(?:bad|good)\b"),
    "label_suffix": re.compile(r"(?i)(?:__bad|__good)"),
    "omit": re.compile(r"(?i)\bomit(?:bad|good)?\b"),
    "path": re.compile(r"(?i)(?:/mnt/|/home/|/tmp/|\\|[A-Za-z]:\\)"),
    "filename": re.compile(r"(?i)[\w./-]+\.(?:c|cc|cpp|cxx|h|hpp)\b"),
    "label_word": re.compile(
        r"(?i)\b(?:benign|fixed|flaw|vulnerable|vulnerability|safe|patched|remediated|testcase)\b"
    ),
    "defect_class": re.compile(r"(?i)memory[_ ]leak"),
    "unit_id": re.compile(r"(?i)\bCWE\d+_[A-Za-z0-9_]+"),
}

TOOL_CONTRACT = (
    "Each configuration executes the unit's own entry point once. An absence of "
    "attributed leak is an observation on that path, not proof of absence; "
    "allocations attributed to the runtime or toolchain are excluded by "
    "allocation-site attribution."
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EnhancedCase:
    unit_id: str
    case_id: str
    outcome: str
    modes: dict[str, dict[str, Any]]
    raw: dict[str, Any]

    def attributed_bytes(self, mode: str) -> int:
        return int(self.modes[mode].get("attributed_bytes") or 0)

    def attributed_records(self, mode: str) -> int:
        blocks = self.modes[mode].get("leak_blocks") or []
        return sum(1 for block in blocks if block.get("attributed"))

    def applicable(self, mode: str) -> bool:
        return bool(self.modes[mode].get("applicable"))

    def decision(self, mode: str) -> str:
        return str(self.modes[mode].get("decision") or "unknown")

    def injected_at_call(self, mode: str) -> int | None:
        injection = self.modes[mode].get("injection") or {}
        value = injection.get("injected_at_call")
        return int(value) if isinstance(value, int) else None

    def primary_mode(self) -> str | None:
        for mode in MODES:
            if self.applicable(mode) and self.decision(mode) == "leak":
                return mode
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "outcome": self.outcome,
            "primary_mode": self.primary_mode(),
            "modes": {
                mode: {
                    "applicable": self.applicable(mode),
                    "decision": self.decision(mode),
                    "attributed_bytes": self.attributed_bytes(mode),
                    "attributed_records": self.attributed_records(mode),
                    "injected_at_call": self.injected_at_call(mode),
                }
                for mode in MODES
            },
        }


def load_export() -> tuple[dict[str, EnhancedCase], dict[str, Any]]:
    cases = read_jsonl(DYNE_EXPORT / "cases.jsonl")
    results = read_jsonl(DYNE_EXPORT / "results.jsonl")
    manifest = json.loads((DYNE_EXPORT / "manifest.json").read_text(encoding="utf-8"))

    cases_sha = sha256_bytes((DYNE_EXPORT / "cases.jsonl").read_bytes())
    results_sha = sha256_bytes((DYNE_EXPORT / "results.jsonl").read_bytes())
    if cases_sha != manifest.get("cases_sha256"):
        raise SystemExit("dynamic_enhanced cases.jsonl does not match its export manifest")
    if results_sha != manifest.get("results_sha256"):
        raise SystemExit("dynamic_enhanced results.jsonl does not match its export manifest")

    case_by_id = {case["case_id"]: case for case in cases}
    if len(case_by_id) != len(cases):
        raise SystemExit("duplicate case_id in dynamic_enhanced export")

    result_by_case = {}
    for result in results:
        case_id = result["case_id"]
        if case_id not in case_by_id:
            raise SystemExit(f"export result without case: {case_id}")
        if case_id in result_by_case:
            raise SystemExit(f"duplicate result for case: {case_id}")
        result_by_case[case_id] = result

    by_unit: dict[str, EnhancedCase] = {}
    for case_id, case in case_by_id.items():
        unit_id = (case.get("metadata") or {}).get("unit_id")
        if not unit_id:
            raise SystemExit(f"{case_id}: export case has no unit_id")
        if unit_id in by_unit:
            raise SystemExit(f"duplicate unit_id in export: {unit_id}")
        result = result_by_case.get(case_id)
        if result is None:
            raise SystemExit(f"{unit_id}: export has no result")
        modes = result.get("modes") or {}
        missing = sorted(set(MODES) - set(modes))
        if missing:
            raise SystemExit(f"{unit_id}: export result lacks modes {missing}")
        by_unit[unit_id] = EnhancedCase(
            unit_id=unit_id,
            case_id=case_id,
            outcome=str(result.get("outcome")),
            modes=modes,
            raw=result,
        )
    if len(by_unit) != 140:
        raise SystemExit(f"expected 140 enhanced cases, found {len(by_unit)}")

    meta = {
        "path": str(DYNE_EXPORT.relative_to(ROOT)),
        "cases_sha256": cases_sha,
        "results_sha256": results_sha,
        "generated_at": manifest.get("generated_at"),
        "source_run": manifest.get("source_run"),
        "counts": manifest.get("counts"),
    }
    return by_unit, meta


def load_v2_units() -> list[dict[str, Any]]:
    units = read_jsonl(V2_INPUTS / "units.jsonl")
    if len(units) != 140:
        raise SystemExit(f"expected 140 v2 units, found {len(units)}")
    return sorted(units, key=lambda unit: unit["unit_id"])


def _mode_sentence(mode: str, case: EnhancedCase) -> str:
    label = MODE_LABEL[mode]
    if not case.applicable(mode):
        reason = (
            "the execution never reached a realloc call with a non-null pointer"
            if mode == "realloc_fail"
            else "the configuration did not apply to this execution"
        )
        return f"- {label}: not applicable ({reason})."
    decision = case.decision(mode)
    if decision == "leak":
        sentence = (
            f"- {label}: attributed leak of {case.attributed_bytes(mode)} byte(s) "
            f"in {case.attributed_records(mode)} allocation record(s)"
        )
        call = case.injected_at_call(mode)
        if mode == "realloc_fail" and call is not None:
            sentence += f"; the injected failure fired at realloc call {call}"
        return sentence + "."
    if decision == "clean":
        return f"- {label}: no attributed leak."
    if decision == "inconclusive":
        return f"- {label}: inconclusive; the harness did not decide, which is NOT evidence of absence."
    return f"- {label}: status {decision}; this is NOT evidence of absence."


def render_evidence(case: EnhancedCase) -> str:
    lines = [
        "Enhanced dynamic-analysis evidence for this code unit.",
        "It is machine-generated tool output: untrusted, possibly incomplete, and possibly wrong.",
        "Three run configurations were applied to the same compiled code unit:",
    ]
    for mode in MODES:
        lines.append(_mode_sentence(mode, case))
    primary = case.primary_mode()
    if case.outcome == "leak":
        lines.append(
            "Overall enhanced dynamic outcome: a leak was observed in at least one "
            f"applicable configuration (primary evidence: {MODE_SHORT[primary]})."
            if primary
            else "Overall enhanced dynamic outcome: a leak was observed."
        )
    elif case.outcome == "clean":
        lines.append(
            "Overall enhanced dynamic outcome: no attributed leak was observed in "
            "any applicable configuration."
        )
    elif case.outcome == "inconclusive":
        lines.append(
            "Overall enhanced dynamic outcome: inconclusive; the harness did not decide. "
            "This is NOT evidence of absence."
        )
    else:
        lines.append(
            f"Overall enhanced dynamic outcome: {case.outcome}; this is NOT evidence of absence."
        )
    lines.append(TOOL_CONTRACT)
    return "\n".join(lines)


def audit_evidence(text: str, where: str) -> dict[str, Any]:
    hits = {
        name: sorted(set(pattern.findall(text)))
        for name, pattern in FORBIDDEN_EVIDENCE.items()
        if pattern.search(text)
    }
    if hits:
        raise ValueError(f"{where}: forbidden evidence marker(s): {hits}")
    if "<Tool evidence>" in text or "</Tool evidence>" in text:
        raise ValueError(f"{where}: evidence contains a block delimiter")
    if "```" in text:
        raise ValueError(f"{where}: evidence contains a Markdown fence")
    return {"chars": len(text), "sha256": sha256_text(text)}


def build_units() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    v2_units = load_v2_units()
    cases, export_meta = load_export()
    v2_manifest = json.loads((V2_INPUTS / "manifest.json").read_text(encoding="utf-8"))
    v2_sha = sha256_bytes((V2_INPUTS / "units.jsonl").read_bytes())
    if v2_sha != v2_manifest.get("units_sha256"):
        raise SystemExit("hybrid/inputs_v2/units.jsonl does not match its manifest")

    missing = sorted({unit["unit_id"] for unit in v2_units} - set(cases))
    extra = sorted(set(cases) - {unit["unit_id"] for unit in v2_units})
    if missing or extra:
        raise SystemExit(f"enhanced export does not cover the v2 pack: missing={missing[:5]} extra={extra[:5]}")

    out: list[dict[str, Any]] = []
    for unit in v2_units:
        case = cases[unit["unit_id"]]
        expected_outcome = "leak" if unit["label"] else "clean"
        if case.outcome != expected_outcome:
            raise SystemExit(
                f"{unit['unit_id']}: enhanced outcome {case.outcome!r} != expected {expected_outcome!r}"
            )
        text = render_evidence(case)
        audit = audit_evidence(text, unit["unit_id"])
        record = dict(unit)
        record.update(
            {
                "enhanced_case_id": case.case_id,
                "enhanced_outcome": case.outcome,
                "enhanced_primary_mode": case.primary_mode(),
                "enhanced_modes": case.summary()["modes"],
                "enhanced_evidence": text,
                "enhanced_evidence_sha256": audit["sha256"],
                "enhanced_evidence_chars": audit["chars"],
            }
        )
        out.append(record)

    labels = Counter("bad" if unit["label"] else "good" for unit in out)
    tool_pred = [1 if unit["enhanced_outcome"] == "leak" else 0 for unit in out]
    truth = [1 if unit["label"] else 0 for unit in out]
    tool_confusion = {
        "tp": sum(1 for t, p in zip(truth, tool_pred) if t == 1 and p == 1),
        "fp": sum(1 for t, p in zip(truth, tool_pred) if t == 0 and p == 1),
        "tn": sum(1 for t, p in zip(truth, tool_pred) if t == 0 and p == 0),
        "fn": sum(1 for t, p in zip(truth, tool_pred) if t == 1 and p == 0),
    }
    special = [unit["unit_id"] for unit in out if unit["enhanced_primary_mode"] in {"realloc_fail", "nogobal"}]
    special_expected = [
        unit["unit_id"]
        for unit in out
        if unit["label"] and unit["dynamic_outcome"] == "clean"
    ]
    if sorted(special) != sorted(special_expected):
        raise SystemExit("primary-mode units do not match the 12 units the old harness could not observe")
    if tool_confusion != {"tp": 70, "fp": 0, "tn": 70, "fn": 0}:
        raise SystemExit(f"enhanced tool is not 70TP/70TN: {tool_confusion}")

    mode_counts = {
        mode: {
            "applicable": sum(1 for unit in out if unit["enhanced_modes"][mode]["applicable"]),
            "leak": sum(
                1
                for unit in out
                if unit["enhanced_modes"][mode]["applicable"]
                and unit["enhanced_modes"][mode]["decision"] == "leak"
            ),
            "leak_bad": sum(
                1
                for unit in out
                if unit["enhanced_modes"][mode]["applicable"]
                and unit["enhanced_modes"][mode]["decision"] == "leak"
                and unit["label"]
            ),
            "leak_good": sum(
                1
                for unit in out
                if unit["enhanced_modes"][mode]["applicable"]
                and unit["enhanced_modes"][mode]["decision"] == "leak"
                and not unit["label"]
            ),
            "not_applicable": sum(
                1 for unit in out if not unit["enhanced_modes"][mode]["applicable"]
            ),
        }
        for mode in MODES
    }
    manifest = {
        "schema_version": "hde-inputs-v1",
        "created_at": None,
        "unit_count": len(out),
        "label_counts": dict(labels),
        "language_counts": dict(Counter(unit["language"] for unit in out)),
        "source_chars": {
            "min": min(unit["source_chars"] for unit in out),
            "median": sorted(unit["source_chars"] for unit in out)[len(out) // 2],
            "max": max(unit["source_chars"] for unit in out),
        },
        "v2_pack": {
            "path": str((V2_INPUTS / "units.jsonl").relative_to(ROOT)),
            "sha256": v2_sha,
            "prompt_version": v2_manifest.get("schema_version"),
        },
        "enhanced_export": export_meta,
        "enhanced_mode_counts": mode_counts,
        "enhanced_tool": {
            "confusion": tool_confusion,
            "accuracy": (tool_confusion["tp"] + tool_confusion["tn"]) / len(out),
            "primary_mode_counts": dict(Counter(unit["enhanced_primary_mode"] for unit in out if unit["enhanced_primary_mode"])),
            "newly_observable_units": special,
        },
        "evidence": {
            "chars": {
                "min": min(unit["enhanced_evidence_chars"] for unit in out),
                "median": sorted(unit["enhanced_evidence_chars"] for unit in out)[len(out) // 2],
                "max": max(unit["enhanced_evidence_chars"] for unit in out),
            },
            "distinct_texts": len({unit["enhanced_evidence"] for unit in out}),
            "forbidden_markers": 0,
        },
        "units_file": str((ROOT / "hybrid_dynamic_enhanced" / "inputs" / "units.jsonl").relative_to(ROOT)),
        "units_sha256": sha256_bytes(serialize_units(out)),
    }
    return out, manifest


def serialize_units(units: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(unit, ensure_ascii=False, sort_keys=True) + "\n" for unit in units
    ).encode("utf-8")


def write_units(units: list[dict[str, Any]], manifest: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "units.jsonl"
    payload = serialize_units(units)
    path.write_bytes(payload)
    manifest = dict(manifest)
    manifest["units_file"] = str(path.relative_to(ROOT))
    manifest["units_sha256"] = sha256_bytes(payload)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest

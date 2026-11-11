"""Fail-closed preflight gate for the hybrid v2 rerun.

The gate answers one question before any paid request is sent: does every one
of the 140 frozen test inputs, and every prompt built from it, still carry a
label-bearing word?  The shared ``juliet_llm`` cleaner is the only cleaner
used here; this script never rewrites a source view.  It rebuilds the cleaned
units in memory, compares them byte for byte with the v2 input pack, rebuilds
all 1,400 prompts, and audits the placebo mapping.

A single surviving ``benign``/``fixed``/``safe``/``clean`` token, a stale input
pack, a changed placebo donor, or a lost no-op collision fails the gate.  The
run script is only allowed to call a model after this script exits 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
for path in (str(ROOT), str(HYBRID)):
    if path not in sys.path:
        sys.path.insert(0, path)

from juliet_llm.cleaning import (  # noqa: E402
    CleanError,
    clean_unit,
    forbidden_hits,
    prompt_forbidden_hits,
)
from juliet_llm.prompting import PROMPT_VERSION as JULIET_PROMPT_VERSION  # noqa: E402

from build_inputs import SEED, build_placebo  # noqa: E402
from prompts import METHODS, PROMPT_VERSION, build_messages  # noqa: E402
from sanitize import assert_clean  # noqa: E402

EXPECTED_UNITS = 140
EXPECTED_LABELS = {"bad": 70, "good": 70}
EXPECTED_LANGUAGES = {"c": 58, "cpp": 82}
EXPECTED_DYNAMIC = {"leak": 58, "clean": 82}
EXPECTED_NOOP_COLLISIONS = 14

# Words that name the answer rather than the program.  ``benign``/``fixed``
# are the two the release audit found in the v1 views; the rest keep the gate
# from drifting if another Juliet string literal is reintroduced.
SOURCE_LABEL_PATTERNS = {
    "benign": r"(?i)\bbenign\w*",
    "fixed": r"(?i)\bfixed\b",
    "safe": r"(?i)\bsafe\b",
    "clean": r"(?i)\bclean\b",
    "vulnerable": r"(?i)\bvulnerab\w*",
    "flaw": r"(?i)\bflaw\w*",
    "secure": r"(?i)\bsecure\w*",
}
# The prompt template legitimately says a failed analysis is not "clean", so
# only the two literal Juliet label words are scanned over the whole prompt.
PROMPT_LABEL_PATTERNS = {
    "benign": r"(?i)\bbenign\w*",
    "fixed": r"(?i)\bfixed\b",
}


def scan(text: str, patterns: dict[str, str]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for name, pattern in patterns.items():
        count = len(re.findall(pattern, text))
        if count:
            hits[name] = count
    return hits


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_frozen_test_units() -> list[dict[str, Any]]:
    units = [unit for unit in read_jsonl(ROOT / "juliet/subset_units.jsonl") if unit["split"] == "test"]
    return sorted(units, key=lambda unit: unit["unit_id"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, default=HYBRID / "inputs_v2")
    parser.add_argument("--run-id", default="hybrid_v2")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--v1-inputs", type=Path, default=HYBRID / "inputs")
    parser.add_argument(
        "--expected-noop-collisions",
        type=int,
        default=EXPECTED_NOOP_COLLISIONS,
        help="fail if the number of donor==own evidence units changes",
    )
    args = parser.parse_args()
    args.inputs_dir = args.inputs_dir.resolve()
    out_path = args.out or (HYBRID / "results" / f"{args.run_id}_preflight.json")

    failures: list[str] = []
    warnings: list[str] = []
    report: dict[str, Any] = {
        "schema_version": "hybrid-preflight-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": args.run_id,
        "prompt_version": PROMPT_VERSION,
        "juliet_prompt_version": JULIET_PROMPT_VERSION,
        "inputs_dir": str(args.inputs_dir.relative_to(ROOT)),
        "expected_units": EXPECTED_UNITS,
        "failures": failures,
        "warnings": warnings,
    }

    frozen = load_frozen_test_units()
    frozen_ids = {unit["unit_id"] for unit in frozen}
    labels = Counter(unit["label"] for unit in frozen)
    report["frozen"] = {
        "units": len(frozen),
        "unique_units": len(frozen_ids),
        "labels": dict(labels),
        "languages": dict(Counter(unit["language"] for unit in frozen)),
    }
    if len(frozen) != EXPECTED_UNITS:
        failures.append(f"frozen test split has {len(frozen)} units, expected {EXPECTED_UNITS}")
    if dict(labels) != EXPECTED_LABELS:
        failures.append(f"frozen labels are {dict(labels)}, expected {EXPECTED_LABELS}")

    rebuilt: dict[str, dict[str, Any]] = {}
    source_failures: list[dict[str, Any]] = []
    for unit in frozen:
        entry: dict[str, Any] = {"unit_id": unit["unit_id"], "label": unit["label"]}
        try:
            cleaned = clean_unit(unit)
        except CleanError as exc:
            failures.append(f"{unit['unit_id']}: cleaner refused the unit: {exc}")
            entry["error"] = str(exc)
            source_failures.append(entry)
            continue
        base_hits = {name: count for name, count in forbidden_hits(cleaned.code).items() if count}
        label_hits = scan(cleaned.code, SOURCE_LABEL_PATTERNS)
        entry.update(
            {
                "code_sha256": cleaned.code_sha256,
                "code_chars": len(cleaned.code),
                "base_hits": base_hits,
                "label_hits": label_hits,
                "checks": cleaned.checks,
            }
        )
        if cleaned.label != unit["label"]:
            failures.append(f"{unit['unit_id']}: cleaned label {cleaned.label} != {unit['label']}")
        if base_hits:
            failures.append(f"{unit['unit_id']}: forbidden token survived cleaning: {base_hits}")
        if label_hits:
            failures.append(f"{unit['unit_id']}: label word survived cleaning: {label_hits}")
            source_failures.append(entry)
        rebuilt[unit["unit_id"]] = {
            "cleaned": cleaned,
            "entry": entry,
        }
    report["sources"] = {
        "rebuilt": len(rebuilt),
        "label_word_failures": len(source_failures),
        "failures": source_failures,
    }

    pack_units: dict[str, dict[str, Any]] = {}
    units_path = args.inputs_dir / "units.jsonl"
    manifest_path = args.inputs_dir / "manifest.json"
    if not units_path.is_file() or not manifest_path.is_file():
        failures.append(f"input pack missing: {units_path} / {manifest_path}")
    else:
        pack_rows = read_jsonl(units_path)
        pack_ids = [row["unit_id"] for row in pack_rows]
        if len(pack_rows) != EXPECTED_UNITS or len(set(pack_ids)) != EXPECTED_UNITS:
            failures.append(f"input pack has {len(pack_rows)} rows / {len(set(pack_ids))} unique ids")
        if set(pack_ids) != frozen_ids:
            failures.append("input pack unit ids differ from the frozen test split")
        pack_units = {row["unit_id"]: row for row in pack_rows}
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        units_sha = hashlib.sha256(units_path.read_bytes()).hexdigest()
        if manifest.get("units_sha256") != units_sha:
            failures.append("input manifest units_sha256 does not match units.jsonl")
        if manifest.get("unit_count") != EXPECTED_UNITS:
            failures.append(f"input manifest unit_count={manifest.get('unit_count')}")
        if manifest.get("label_counts") != EXPECTED_LABELS:
            failures.append(f"input manifest label_counts={manifest.get('label_counts')}")
        if manifest.get("placebo", {}).get("seed") != SEED:
            failures.append(f"input manifest placebo seed={manifest.get('placebo', {}).get('seed')}")
        report["input_pack"] = {
            "path": str(units_path.relative_to(ROOT)),
            "units_sha256": units_sha,
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "rows": len(pack_rows),
            "manifest_unit_count": manifest.get("unit_count"),
            "placebo_seed": manifest.get("placebo", {}).get("seed"),
            "placebo_collisions": manifest.get("placebo", {}).get("identical_evidence_pairs"),
        }

        for unit_id, item in rebuilt.items():
            row = pack_units.get(unit_id)
            if row is None:
                continue
            if row.get("source_text") != item["cleaned"].code:
                failures.append(f"{unit_id}: input pack source_text is stale (differs from cleaner)")
            if row.get("source_sha256") != item["cleaned"].code_sha256:
                failures.append(f"{unit_id}: input pack source_sha256 is stale")

        delivered_labels = Counter(
            "bad" if row["label"] else "good" for row in pack_rows
        )
        delivered_languages = Counter(row["language"] for row in pack_rows)
        delivered_dynamic = Counter(row["dynamic_outcome"] for row in pack_rows)
        report["input_pack"].update(
            {
                "labels": dict(delivered_labels),
                "languages": dict(delivered_languages),
                "dynamic_outcomes": dict(delivered_dynamic),
                "bad_with_clean_evidence": sum(
                    1 for row in pack_rows if row["label"] and row["dynamic_outcome"] == "clean"
                ),
                "good_with_leak_evidence": sum(
                    1 for row in pack_rows if not row["label"] and row["dynamic_outcome"] == "leak"
                ),
            }
        )
        if dict(delivered_labels) != EXPECTED_LABELS:
            failures.append(f"input pack labels are {dict(delivered_labels)}")
        if dict(delivered_languages) != EXPECTED_LANGUAGES:
            failures.append(f"input pack languages are {dict(delivered_languages)}")
        if dict(delivered_dynamic) != EXPECTED_DYNAMIC:
            failures.append(f"input pack dynamic outcomes are {dict(delivered_dynamic)}")

        # Every evidence and placebo block must pass the hybrid sanitizer.
        for row in pack_rows:
            for name in ("static", "dynamic", "combined", "placebo"):
                key = "placebo_evidence" if name == "placebo" else "evidence"
                text = row[key] if name == "placebo" else row["evidence"][name]
                try:
                    assert_clean(text, f"{row['unit_id']} {name}")
                except ValueError as exc:
                    failures.append(str(exc))

        # Rebuild all prompts from the delivered pack, not from a cached copy.
        prompt_report: dict[str, Any] = {}
        prompt_failures = 0
        for method in METHODS:
            hashes: set[str] = set()
            extra_hits: list[dict[str, Any]] = []
            base_prompt_hits: list[dict[str, Any]] = []
            for unit_id in sorted(pack_units):
                try:
                    messages, metadata = build_messages(pack_units[unit_id], method)
                except ValueError as exc:
                    failures.append(f"{unit_id}/{method}: prompt build/audit failed: {exc}")
                    prompt_failures += 1
                    continue
                hashes.add(metadata["prompt_sha256"])
                joined = "\n".join(message["content"] for message in messages)
                hits = scan(joined, PROMPT_LABEL_PATTERNS)
                if hits:
                    extra_hits.append({"unit_id": unit_id, "hits": hits})
                base = {name: count for name, count in prompt_forbidden_hits(joined).items() if count}
                if base:
                    base_prompt_hits.append({"unit_id": unit_id, "hits": base})
            if extra_hits:
                prompt_failures += len(extra_hits)
                failures.append(f"{method}: {len(extra_hits)} prompts contain benign/fixed")
            if base_prompt_hits:
                prompt_failures += len(base_prompt_hits)
                failures.append(f"{method}: {len(base_prompt_hits)} prompts fail the base scan")
            prompt_report[method] = {
                "prompts": len(pack_units),
                "unique_hashes": len(hashes),
                "label_word_hits": extra_hits,
                "base_hits": base_prompt_hits,
            }
            if len(pack_units) == EXPECTED_UNITS and len(hashes) != EXPECTED_UNITS:
                failures.append(f"{method}: only {len(hashes)} unique prompt hashes")
        report["prompts"] = {"failures": prompt_failures, "by_method": prompt_report}

        # Direct must still equal the shared juliet_llm builder.  A stale
        # frozen build is reported, not treated as a hybrid failure.
        reference_dir = ROOT / "juliet_llm/build"
        reference_path = reference_dir / "test.jsonl"
        reference_manifest = reference_dir / "manifest.json"
        reference_status = "missing"
        reference_detail: dict[str, Any] = {"path": str(reference_path.relative_to(ROOT))}
        if reference_path.is_file() and reference_manifest.is_file():
            ref_meta = json.loads(reference_manifest.read_text(encoding="utf-8"))
            reference_detail["prompt_version"] = ref_meta.get("prompt_version")
            reference = {row["unit_id"]: row for row in read_jsonl(reference_path)}
            mismatches: list[str] = []
            code_mismatches: list[str] = []
            checked = 0
            for unit_id, row in pack_units.items():
                ref = reference.get(unit_id)
                if ref is None:
                    continue
                checked += 1
                if ref.get("code_sha256") != row["source_sha256"]:
                    code_mismatches.append(unit_id)
                elif ref.get("prompt_sha256") != build_messages(row, "direct")[1]["prompt_sha256"]:
                    mismatches.append(unit_id)
            reference_detail.update(
                {
                    "checked": checked,
                    "code_mismatches": len(code_mismatches),
                    "prompt_mismatches": len(mismatches),
                }
            )
            if code_mismatches:
                reference_status = "stale_reference"
                warnings.append(
                    f"juliet_llm/build is stale for {len(code_mismatches)} units; "
                    "direct alignment is verified against the shared builder instead"
                )
            elif mismatches:
                reference_status = "mismatch"
                failures.append(
                    f"direct prompt differs from juliet_llm/build for {len(mismatches)} units"
                )
            else:
                reference_status = "matched"
        reference_detail["status"] = reference_status
        report["direct_reference"] = reference_detail

        # Placebo: same seed, same derangement, same 14 no-op collisions.
        placebo = manifest.get("placebo", {})
        donors = {row["unit_id"]: row["placebo_donor_unit"] for row in pack_rows}
        expected_donors = build_placebo(
            [{"unit_id": row["unit_id"], "group_id": row["group_id"]} for row in pack_rows]
        )
        if donors != expected_donors:
            failures.append("placebo mapping is not the seed-20261112 derangement")
        groups = {row["unit_id"]: row["group_id"] for row in pack_rows}
        invalid = [
            unit_id
            for unit_id, donor in donors.items()
            if donor == unit_id or groups.get(donor) == groups.get(unit_id)
        ]
        if invalid:
            failures.append(f"placebo mapping violates constraints for {len(invalid)} units")
        if sorted(donors.values()) != sorted(donors):
            failures.append("placebo mapping is not a permutation")
        collisions = [
            row["unit_id"]
            for row in pack_rows
            if row["placebo_evidence"] == row["evidence"]["combined"]
        ]
        donor_text_mismatch = [
            row["unit_id"]
            for row in pack_rows
            if row["placebo_evidence"] != pack_units[row["placebo_donor_unit"]]["evidence"]["combined"]
        ]
        if donor_text_mismatch:
            failures.append(f"{len(donor_text_mismatch)} placebo blocks do not match their donor")
        v1_collisions: list[str] | None = None
        v1_units_path = args.v1_inputs / "units.jsonl"
        if v1_units_path.is_file():
            v1_rows = {row["unit_id"]: row for row in read_jsonl(v1_units_path)}
            v1_collisions = sorted(
                unit_id
                for unit_id, row in v1_rows.items()
                if row["placebo_evidence"] == row["evidence"]["combined"]
            )
            if sorted(collisions) != v1_collisions:
                failures.append("no-op collision set differs from the v1 input pack")
        if len(collisions) != args.expected_noop_collisions:
            failures.append(
                f"placebo no-op collisions={len(collisions)}, "
                f"expected {args.expected_noop_collisions}"
            )
        for unit_id in collisions:
            warnings.append(
                f"placebo no-op collision: {unit_id} has donor evidence identical to its own"
            )
        report["placebo"] = {
            "seed": SEED,
            "pairs": len(donors),
            "invalid_pairs": len(invalid),
            "noop_collisions": len(collisions),
            "noop_units": sorted(collisions),
            "v1_noop_units": v1_collisions,
            "donor_text_mismatches": len(donor_text_mismatch),
        }

    report["ok"] = not failures
    report["summary"] = {
        "units": len(pack_units),
        "methods": list(METHODS),
        "prompts_rebuilt": len(pack_units) * len(METHODS),
        "label_word_hits_in_sources": len(source_failures),
        "failures": len(failures),
        "warnings": len(warnings),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

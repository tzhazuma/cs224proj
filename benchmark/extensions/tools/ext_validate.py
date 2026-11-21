#!/usr/bin/env python3
"""Validate one extension run (or a paired position-debiased base directory).

Validation is layered:

1. the parent ``bench_validate.validate_run`` checks the canonical
   ``run_manifest.json`` / ``predictions.jsonl`` contract;
2. ``extension_manifest.json`` and each record's ``extensions`` block are
   checked against the extension schemas when ``--jsonschema`` is available;
3. design-specific invariants are checked in pure Python (choice encoding,
   coverage policy, fault labels, static diagnostic recount, paired order
   completeness).

The validator never rewrites predictions and never calls a model or tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ext_common import (  # noqa: E402
    DESIGNS_PATH,
    FAULT_TYPES_PATH,
    STATIC_TOOLS_PATH,
    ExtensionError,
    as_bool,
    check_no_secret_fields,
    coverage_bucket,
    coverage_sufficient,
    design_ids,
    design_spec,
    extension_block_design,
    fault_type_registry,
    fault_type_spec,
    infer_design,
    load_claim_manifest,
    load_extension_run,
    load_fault_manifest,
    normalize_cwe_list,
    parse_juliet_unit_id,
    project_root,
    read_json,
    resolve_path,
    sha256_file,
    static_tool_registry,
    static_tool_spec,
    summarize_diagnostics,
    utc_now,
)
from bench_common import atomic_write_text  # noqa: E402
from bench_validate import validate_run  # noqa: E402

VALIDATION_SCHEMA_VERSION = "benchmark-extension-validation-v1"
EXTENSION_BLOCKS_SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "extension_blocks.schema.json"
)
EXTENSION_MANIFEST_SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "extension_manifest.schema.json"
)

POSITION_MAP_AB = {"A": "vulnerable", "B": "fixed"}
POSITION_MAP_BA = {"A": "fixed", "B": "vulnerable"}
OPEN_CHOICES = ("A", "B", "both", "neither")
VERDICTS = ("supported", "unsupported", "insufficient")
EXPECTED_OUTCOMES = ("leak", "clean", "inconclusive")
OBSERVED_OUTCOMES = ("leak", "clean", "inconclusive", "error", "timeout", "crash")


def _error(report: dict[str, Any], message: str) -> None:
    report["errors"].append(message)


def _warning(report: dict[str, Any], message: str) -> None:
    report["warnings"].append(message)


def _merge(report: dict[str, Any], other: Mapping[str, Any], prefix: str = "") -> None:
    for message in other.get("errors") or []:
        _error(report, f"{prefix}{message}")
    for message in other.get("warnings") or []:
        _warning(report, f"{prefix}{message}")


def _jsonschema_validate(
    report: dict[str, Any],
    instance: Any,
    schema: Mapping[str, Any],
    label: str,
) -> None:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        _warning(report, "jsonschema is not installed; skipped extension schema validation")
        return
    try:
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
    except Exception as exc:  # noqa: BLE001 - schema errors are reported, not raised
        _warning(report, f"cannot run jsonschema for {label}: {exc}")
        return
    for error in errors:
        location = "/".join(str(part) for part in error.path) or "<root>"
        _error(report, f"{label} at {location}: {error.message}")


def _load_jsonschema_file(path: Path) -> dict[str, Any] | None:
    try:
        value = read_json(path)
    except OSError:
        return None
    return value if isinstance(value, dict) else None


def _check_extension_schema(
    report: dict[str, Any],
    extension_manifest: Mapping[str, Any] | None,
    records: Sequence[Mapping[str, Any]],
    design: str,
) -> None:
    schema = _load_jsonschema_file(EXTENSION_MANIFEST_SCHEMA)
    if schema is not None and extension_manifest is not None:
        _jsonschema_validate(report, extension_manifest, schema, "extension_manifest")
    blocks_schema = _load_jsonschema_file(EXTENSION_BLOCKS_SCHEMA)
    if blocks_schema is None:
        _warning(report, f"missing extension block schema: {EXTENSION_BLOCKS_SCHEMA}")
        return
    block_schema = (blocks_schema.get("$defs") or {}).get(design)
    if not isinstance(block_schema, Mapping):
        _error(report, f"no extension block schema for design {design!r}")
        return
    # Validate the design block through a wrapper that keeps the document-level
    # $defs available, so nested refs such as static_diagnostic resolve.
    wrapper = {"$defs": blocks_schema.get("$defs") or {}, "$ref": f"#/$defs/{design}"}
    for index, record in enumerate(records, start=1):
        block = record.get("extensions")
        if not isinstance(block, Mapping):
            _error(report, f"record {index}: extensions must be an object")
            continue
        _jsonschema_validate(report, block, wrapper, f"record {index} extensions")


def _check_common(
    report: dict[str, Any],
    manifest: Mapping[str, Any],
    extension_manifest: Mapping[str, Any] | None,
    records: Sequence[Mapping[str, Any]],
    design: str,
) -> None:
    spec = design_spec(design)
    if extension_manifest is None:
        _error(report, "missing extension_manifest.json sidecar")
    else:
        if extension_manifest.get("schema_version") != "benchmark-extension-manifest-v1":
            _error(report, "extension_manifest.schema_version must be benchmark-extension-manifest-v1")
        if extension_manifest.get("design") != design:
            _error(report, "extension_manifest.design does not match records")
        if extension_manifest.get("parent_task") != spec["parent_task"]:
            _error(report, "extension_manifest.parent_task does not match design registry")
        if extension_manifest.get("aggregation_unit") != spec["aggregation_unit"]:
            _error(report, "extension_manifest.aggregation_unit does not match design registry")
        if extension_manifest.get("run_role") not in ("single", "order_ab", "order_ba", "fwd", "rev"):
            _error(report, "extension_manifest.run_role is invalid")
        if extension_manifest.get("run_role") == "single" and design == "position_debiased_pair":
            _error(report, "position_debiased_pair needs order_ab / order_ba runs, not run_role=single")
        if extension_manifest.get("run_role") != "single" and design != "position_debiased_pair":
            _error(report, f"{design} must use run_role=single")

    for index, record in enumerate(records, start=1):
        unit_id = record.get("unit_id", f"<record {index}>")
        if record.get("task") != spec["parent_task"]:
            _error(report, f"{unit_id}: task must be {spec['parent_task']!r}")
        if record.get("tier") not in spec["tiers"]:
            _error(report, f"{unit_id}: tier {record.get('tier')!r} not allowed for {design}")
        if record.get("track") not in spec["tracks"]:
            _error(report, f"{unit_id}: track {record.get('track')!r} not allowed for {design}")
        if extension_block_design(record) != design:
            _error(report, f"{unit_id}: extensions design marker must be {design!r}")
        dataset = record.get("dataset") or {}
        manifest_dataset = manifest.get("dataset") or {}
        if dataset.get("sha256") != manifest_dataset.get("sha256"):
            _error(report, f"{unit_id}: dataset.sha256 does not match manifest")


def _check_pair_groups(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Mapping[str, Any]]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for record in records:
        group_id = str(record.get("group_id") or "")
        side = str(record.get("side") or "")
        if not group_id:
            _error(report, f"{record.get('unit_id')}: missing group_id")
            continue
        if side not in ("vulnerable", "fixed"):
            _error(report, f"{record.get('unit_id')}: side must be vulnerable or fixed")
            continue
        if side in groups[group_id]:
            _error(report, f"{record.get('unit_id')}: duplicate side {group_id}:{side}")
        groups[group_id][side] = record
    for group_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            _error(report, f"group {group_id!r} has sides {sorted(sides)}, expected both sides")
    return dict(groups)


def _expected_pair_unit_id(group_id: str, side: str) -> str:
    return f"secvul:pair:{group_id}:{side}"


def _check_position(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
) -> None:
    role = extension_manifest.get("run_role")
    order = extension_manifest.get("presentation_order")
    role_to_order = {"order_ab": "AB", "order_ba": "BA", "fwd": "fwd", "rev": "rev"}
    if role not in role_to_order:
        _error(report, "position_debiased_pair run_role must be order_ab, order_ba, fwd or rev")
    if order not in ("AB", "BA", "fwd", "rev"):
        _error(report, "position_debiased_pair presentation_order must be AB, BA, fwd or rev")
    if role in role_to_order and order != role_to_order[role]:
        _error(report, f"run_role={role} requires presentation_order={role_to_order[role]}")
    if not extension_manifest.get("pairing_id"):
        _error(report, "position_debiased_pair requires extension_manifest.pairing_id")

    groups = _check_pair_groups(report, records)
    global_map = {"AB": POSITION_MAP_AB, "BA": POSITION_MAP_BA}.get(str(order))
    for group_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        sample = next(iter(sides.values()))
        block = sample.get("extensions") or {}
        if block.get("pair_design") != "position_debiased_pair":
            _error(report, f"{group_id}: pair_design must be position_debiased_pair")
        if block.get("presentation_order") != order:
            _error(report, f"{group_id}: presentation_order does not match extension_manifest")
        pm = block.get("position_map")
        if (
            not isinstance(pm, Mapping)
            or set(pm) != {"A", "B"}
            or set(pm.values()) != {"vulnerable", "fixed"}
        ):
            _error(report, f"{group_id}: position_map must map A/B bijectively to vulnerable/fixed")
            pm = {}
        elif global_map is not None and pm != global_map:
            _error(report, f"{group_id}: position_map must be {global_map} for global order {order}")
        if block.get("forced_choice") is not True:
            _error(report, f"{group_id}: forced_choice must be true")
        choice = block.get("choice")
        selected_slot = block.get("selected_slot")
        selected_side = block.get("selected_side")
        if choice not in ("A", "B", None):
            _error(report, f"{group_id}: choice must be A, B or null")
        if selected_slot not in ("A", "B", None):
            _error(report, f"{group_id}: selected_slot must be A, B or null")
        if selected_side not in ("vulnerable", "fixed", None):
            _error(report, f"{group_id}: selected_side must be vulnerable, fixed or null")
        if choice is not None:
            if choice != selected_slot:
                _error(report, f"{group_id}: choice and selected_slot disagree")
            if pm.get(str(choice)) != selected_side:
                _error(report, f"{group_id}: selected_side does not match position_map[choice]")
        for side, record in sides.items():
            unit_id = record.get("unit_id")
            if unit_id != _expected_pair_unit_id(group_id, side):
                _error(report, f"{unit_id}: expected unit_id {_expected_pair_unit_id(group_id, side)}")
            block_side = record.get("extensions") or {}
            if block_side.get("choice") != choice:
                _error(report, f"{unit_id}: both sides must carry the same choice")
            if block_side.get("selected_side") != selected_side:
                _error(report, f"{unit_id}: both sides must carry the same selected_side")
            if block_side.get("position_map") != pm:
                _error(report, f"{unit_id}: both sides must carry the same position_map")
            status = record.get("status")
            y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
            if status == "ok":
                if selected_side is None:
                    _error(report, f"{unit_id}: status=ok requires a selected side")
                    continue
                expected = 1 if side == selected_side else 0
                if y_pred != bool(expected):
                    _error(report, f"{unit_id}: y_pred={y_pred} but expected {bool(expected)}")
            elif y_pred is not None:
                _error(report, f"{unit_id}: non-ok status must have y_pred=null")
        label = sides["vulnerable"].get("label") or {}
        if as_bool(label.get("y_true")) is not True:
            _warning(report, f"{group_id}: vulnerable side label.y_true is not true")
        fixed_label = sides["fixed"].get("label") or {}
        if as_bool(fixed_label.get("y_true")) is not False:
            _warning(report, f"{group_id}: fixed side label.y_true is not false")


def _check_open_choice(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "open_choice_pair requires run_role=single")
    groups = _check_pair_groups(report, records)
    for group_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        sample = next(iter(sides.values()))
        block = sample.get("extensions") or {}
        if block.get("pair_design") != "open_choice_pair":
            _error(report, f"{group_id}: pair_design must be open_choice_pair")
        if block.get("forced_choice") is not False:
            _error(report, f"{group_id}: forced_choice must be false for open-choice")
        choice = block.get("open_choice")
        if choice not in OPEN_CHOICES + (None,):
            _error(report, f"{group_id}: open_choice must be A, B, both, neither or null")
        selected_slots = block.get("selected_slots")
        if not isinstance(selected_slots, list):
            _error(report, f"{group_id}: selected_slots must be a list")
            selected_slots = []
        if len(set(selected_slots)) != len(selected_slots):
            _error(report, f"{group_id}: selected_slots contains duplicates")
        position_map = block.get("position_map")
        if not isinstance(position_map, Mapping) or set(position_map) != {"A", "B"}:
            _error(report, f"{group_id}: position_map must contain A and B")
            position_map = {}
        expected_slots = {
            "A": ["A"],
            "B": ["B"],
            "both": ["A", "B"],
            "neither": [],
        }.get(str(choice), None)
        if expected_slots is not None and sorted(expected_slots) != sorted(selected_slots):
            _error(report, f"{group_id}: selected_slots does not match open_choice")
        flagged_sides = {
            position_map.get(slot) for slot in selected_slots if position_map.get(slot)
        }
        for side, record in sides.items():
            unit_id = record.get("unit_id")
            if unit_id != _expected_pair_unit_id(group_id, side):
                _error(report, f"{unit_id}: expected unit_id {_expected_pair_unit_id(group_id, side)}")
            block_side = record.get("extensions") or {}
            if block_side.get("open_choice") != choice:
                _error(report, f"{unit_id}: both sides must carry the same open_choice")
            if block_side.get("position_map") != position_map:
                _error(report, f"{unit_id}: both sides must carry the same position_map")
            status = record.get("status")
            y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
            if status == "ok":
                expected = 1 if side in flagged_sides else 0
                if y_pred != bool(expected):
                    _error(report, f"{unit_id}: y_pred={y_pred} but expected {bool(expected)}")
            elif y_pred is not None:
                _error(report, f"{unit_id}: non-ok status must have y_pred=null")


def _check_evidence(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
    claim_manifest_path: str | None,
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "evidence_verification requires run_role=single")
    manifest_sha = None
    claims = None
    sidecar = extension_manifest.get("claim_manifest")
    candidate_path = claim_manifest_path
    if candidate_path is None and isinstance(sidecar, Mapping):
        candidate_path = sidecar.get("path")
    if candidate_path:
        path = resolve_path(candidate_path, [extension_manifest.get("_run_dir") or ".", project_root()])
        if path.exists():
            claims = load_claim_manifest(path)
            manifest_sha = sha256_file(path)
            if isinstance(sidecar, Mapping) and sidecar.get("sha256") and sidecar["sha256"] != manifest_sha:
                _error(report, "extension_manifest.claim_manifest.sha256 does not match the file")
        else:
            _warning(report, f"claim manifest not found at {path}; skipped claim-set check")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        block = record.get("extensions") or {}
        verification = block.get("verification")
        if not isinstance(verification, Mapping):
            _error(report, f"{unit_id}: missing extensions.verification")
            continue
        claim_id = verification.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id:
            _error(report, f"{unit_id}: verification.claim_id is required")
            continue
        if claim_id in seen:
            _error(report, f"{unit_id}: duplicate claim_id {claim_id!r}")
        seen.add(claim_id)
        tier = record.get("tier")
        if unit_id != f"{tier}:claim:{claim_id}":
            _error(report, f"{unit_id}: expected unit_id {tier}:claim:{claim_id}")
        if record.get("group_id") not in (None, ""):
            _error(report, f"{unit_id}: evidence verification must not have group_id")
        if record.get("side") not in (None, ""):
            _error(report, f"{unit_id}: evidence verification must not have side")
        gold = verification.get("gold_verdict")
        verdict = verification.get("verdict")
        if gold not in ("supported", "unsupported"):
            _error(report, f"{unit_id}: gold_verdict must be supported or unsupported")
        if verdict not in VERDICTS + (None,):
            _error(report, f"{unit_id}: verdict is invalid")
        label = record.get("label") or {}
        y_true = as_bool(label.get("y_true"))
        expected_true = True if gold == "supported" else False if gold == "unsupported" else None
        if expected_true is not None and y_true != expected_true:
            _error(report, f"{unit_id}: label.y_true does not match gold_verdict")
        if label.get("label_source") not in ("manual", "secvuleval", "juliet_intended"):
            _error(report, f"{unit_id}: label.label_source is invalid for evidence verification")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        abstained = verification.get("abstained")
        if verdict == "supported":
            if status != "ok" or y_pred is not True:
                _error(report, f"{unit_id}: supported verdict requires status=ok and y_pred=true")
        elif verdict == "unsupported":
            if status != "ok" or y_pred is not False:
                _error(report, f"{unit_id}: unsupported verdict requires status=ok and y_pred=false")
        elif verdict == "insufficient":
            if status != "inconclusive" or y_pred is not None:
                _error(report, f"{unit_id}: insufficient verdict requires status=inconclusive and y_pred=null")
            if abstained is not True:
                _error(report, f"{unit_id}: insufficient verdict requires abstained=true")
        else:
            if status == "ok":
                _error(report, f"{unit_id}: status=ok requires a decisive verdict")
        if abstained is not None and abstained != (verdict == "insufficient"):
            _error(report, f"{unit_id}: abstained must be true iff verdict=insufficient")
        input_block = record.get("input") or {}
        if input_block.get("view") == "pair":
            _error(report, f"{unit_id}: evidence verification input view must not be 'pair'")
        if input_block.get("sanitized") is not True:
            _warning(report, f"{unit_id}: evidence verification input is not marked sanitized")
        if claims is not None:
            claim_index = {str(c.get("claim_id")): c for c in claims.get("claims") or []}
            claim = claim_index.get(claim_id)
            if claim is None:
                _error(report, f"{unit_id}: claim_id not present in frozen claim manifest")
            else:
                for key in ("tier", "track"):
                    if claim.get(key) != record.get(key):
                        _error(report, f"{unit_id}: {key} does not match claim manifest")
                if claim.get("cluster_id") != record.get("cluster_id"):
                    _error(report, f"{unit_id}: cluster_id does not match claim manifest")
                if claim.get("gold_verdict") != gold:
                    _error(report, f"{unit_id}: gold_verdict does not match claim manifest")
                if verification.get("claim_text_sha256") != claim.get("claim_text_sha256"):
                    _error(report, f"{unit_id}: claim_text_sha256 does not match claim manifest")
                if manifest_sha and verification.get("claim_manifest_sha256") != manifest_sha:
                    _error(report, f"{unit_id}: claim_manifest_sha256 does not match the file")
    if claims is not None:
        manifest_ids = {str(c.get("claim_id")) for c in claims.get("claims") or []}
        missing = manifest_ids - seen
        extra = seen - manifest_ids
        if missing:
            _error(report, f"claim manifest has {len(missing)} claim(s) without predictions")
        if extra:
            _error(report, f"predictions contain {len(extra)} claim(s) not in the manifest")


def _check_fault(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    extension_manifest: Mapping[str, Any],
    fault_manifest_path: str | None,
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "fault_injected_dynamic requires run_role=single")
    threshold = extension_manifest.get("coverage_threshold")
    threshold = 0.8 if threshold is None else float(threshold)
    faults = None
    fault_sha = None
    sidecar = extension_manifest.get("fault_manifest")
    candidate_path = fault_manifest_path
    if candidate_path is None and isinstance(sidecar, Mapping):
        candidate_path = sidecar.get("path")
    if candidate_path:
        path = resolve_path(candidate_path, [extension_manifest.get("_run_dir") or ".", project_root()])
        if path.exists():
            faults = load_fault_manifest(path)
            fault_sha = sha256_file(path)
            if isinstance(sidecar, Mapping) and sidecar.get("sha256") and sidecar["sha256"] != fault_sha:
                _error(report, "extension_manifest.fault_manifest.sha256 does not match the file")
        else:
            _warning(report, f"fault manifest not found at {path}; skipped fault-set check")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        block = record.get("extensions") or {}
        injection = block.get("fault_injection")
        if not isinstance(injection, Mapping):
            _error(report, f"{unit_id}: missing extensions.fault_injection")
            continue
        fault_id = injection.get("fault_id")
        if not isinstance(fault_id, str) or not fault_id:
            _error(report, f"{unit_id}: fault_id is required")
            continue
        if fault_id in seen:
            _error(report, f"{unit_id}: duplicate fault_id {fault_id!r}")
        seen.add(fault_id)
        fault_type = injection.get("fault_type")
        try:
            fault_spec = fault_type_spec(str(fault_type))
        except ExtensionError as exc:
            _error(report, f"{unit_id}: {exc}")
            fault_spec = {}
        expected = injection.get("expected_outcome")
        observed = injection.get("observed_outcome")
        if expected not in EXPECTED_OUTCOMES:
            _error(report, f"{unit_id}: expected_outcome is invalid")
        if observed not in OBSERVED_OUTCOMES:
            _error(report, f"{unit_id}: observed_outcome is invalid")
        allowed = set(fault_spec.get("allowed_expected_outcomes") or [])
        if expected not in allowed:
            _error(report, f"{unit_id}: expected_outcome {expected!r} not allowed for {fault_type!r}")
        base_unit_id = injection.get("base_unit_id")
        if not isinstance(base_unit_id, str) or not base_unit_id:
            _error(report, f"{unit_id}: base_unit_id is required")
            continue
        if unit_id != f"{base_unit_id}:fault:{fault_id}":
            _error(report, f"{unit_id}: expected unit_id {base_unit_id}:fault:{fault_id}")
        try:
            group, side = parse_juliet_unit_id(base_unit_id)
        except ExtensionError as exc:
            _error(report, f"{unit_id}: {exc}")
            group, side = "", ""
        if record.get("group_id") != group:
            _error(report, f"{unit_id}: group_id must be {group!r} (base case)")
        if record.get("side") != side:
            _error(report, f"{unit_id}: side must be {side!r} (base variant)")
        method = record.get("method") or {}
        if method.get("family") != "dynamic":
            _error(report, f"{unit_id}: fault_injected_dynamic requires method.family=dynamic")
        coverage = record.get("coverage")
        if not isinstance(coverage, Mapping):
            _error(report, f"{unit_id}: dynamic fault record requires coverage")
        label = record.get("label") or {}
        y_true = as_bool(label.get("y_true"))
        expected_true = True if expected == "leak" else False
        if expected in ("leak", "clean") and y_true != expected_true:
            _error(report, f"{unit_id}: label.y_true does not match expected_outcome")
        if expected == "inconclusive":
            if record.get("status") != "not_applicable":
                _error(report, f"{unit_id}: expected_outcome=inconclusive requires status=not_applicable")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        sufficient = coverage_sufficient(record, threshold)
        declared_sufficient = injection.get("coverage_sufficient")
        if declared_sufficient is not None and bool(declared_sufficient) != bool(sufficient):
            _error(report, f"{unit_id}: coverage_sufficient does not match coverage/threshold")
        if expected in ("leak", "clean") and status in ("not_run", "skipped_budget"):
            # A missing variant is retained as not_run/skipped, never silently
            # treated as a clean observation.
            continue
        if expected in ("leak", "clean"):
            if observed == "leak":
                if status != "ok" or y_pred is not True:
                    _error(report, f"{unit_id}: observed leak requires status=ok and y_pred=true")
            elif observed == "clean":
                if not sufficient:
                    if status != "inconclusive":
                        _error(report, f"{unit_id}: clean without adequate coverage requires inconclusive")
                elif status != "ok" or y_pred is not False:
                    _error(report, f"{unit_id}: clean with adequate coverage requires status=ok and y_pred=false")
            elif observed == "inconclusive":
                if status != "inconclusive":
                    _error(report, f"{unit_id}: observed inconclusive requires status=inconclusive")
            elif observed == "timeout":
                if status != "timeout":
                    _error(report, f"{unit_id}: observed timeout requires status=timeout")
            elif observed == "crash":
                if status != "crash":
                    _error(report, f"{unit_id}: observed crash requires status=crash")
            elif observed == "error":
                if status not in ("tool_error", "harness_error", "api_error"):
                    _error(report, f"{unit_id}: observed error requires a tool/harness/api error status")
        if status != "ok" and y_pred is not None:
            _error(report, f"{unit_id}: non-ok status must have y_pred=null")
        baseline = injection.get("baseline_outcome")
        flip = injection.get("flip")
        expected_flip = "not_comparable"
        if baseline in ("leak", "clean") and observed in ("leak", "clean"):
            expected_flip = "same" if baseline == observed else (
                "leak_to_clean" if baseline == "leak" else "clean_to_leak"
            )
        if flip is not None and flip != expected_flip:
            _error(report, f"{unit_id}: flip={flip!r} but expected {expected_flip!r}")
        oracle = record.get("oracle")
        if isinstance(oracle, Mapping) and oracle.get("mismatch") is True:
            _warning(report, f"{unit_id}: oracle mismatch; excluded from primary fault metrics")
        if faults is not None:
            fault_index = {str(f.get("fault_id")): f for f in faults.get("faults") or []}
            fault = fault_index.get(fault_id)
            if fault is None:
                _error(report, f"{unit_id}: fault_id not present in frozen fault manifest")
            else:
                for key in ("base_unit_id", "fault_type", "expected_outcome"):
                    if fault.get(key) != injection.get(key):
                        _error(report, f"{unit_id}: {key} does not match fault manifest")
                if fault.get("cluster_id") != record.get("cluster_id"):
                    _error(report, f"{unit_id}: cluster_id does not match fault manifest")
                if fault_sha and injection.get("fault_manifest_sha256") != fault_sha:
                    _error(report, f"{unit_id}: fault_manifest_sha256 does not match the file")
    if faults is not None:
        manifest_ids = {str(f.get("fault_id")) for f in faults.get("faults") or []}
        missing = manifest_ids - seen
        extra = seen - manifest_ids
        if missing:
            _error(report, f"fault manifest has {len(missing)} fault(s) without predictions")
        if extra:
            _error(report, f"predictions contain {len(extra)} fault(s) not in the manifest")


def _check_static(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
    unit_map_path: str | None,
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "new_static_tool requires run_role=single")
    sidecar = extension_manifest.get("tool_registry")
    tool_id = sidecar.get("tool_id") if isinstance(sidecar, Mapping) else None
    if not tool_id:
        _error(report, "new_static_tool requires extension_manifest.tool_registry.tool_id")
        return
    try:
        tool_spec = static_tool_spec(str(tool_id))
    except ExtensionError as exc:
        _error(report, str(exc))
        return
    registry_sha = sha256_file(STATIC_TOOLS_PATH)
    if isinstance(sidecar, Mapping) and sidecar.get("sha256") and sidecar["sha256"] != registry_sha:
        _error(report, "extension_manifest.tool_registry.sha256 does not match the registry file")
    expected_rules = {
        rule for rule, spec in (tool_spec.get("rules") or {}).items()
        if spec.get("counts_for_cwe401")
    }
    unit_index = None
    if unit_map_path:
        from ext_common import juliet_unit_index

        path = resolve_path(unit_map_path, [extension_manifest.get("_run_dir") or ".", project_root()])
        if path.exists():
            unit_index = juliet_unit_index(path)
        else:
            _warning(report, f"unit map not found at {path}; skipped unit-set check")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        if record.get("tier") != "B":
            _error(report, f"{unit_id}: new_static_tool is Tier B only")
        if record.get("task") != "leak_detection":
            _error(report, f"{unit_id}: new_static_tool requires task=leak_detection")
        method = record.get("method") or {}
        if method.get("family") != "static":
            _error(report, f"{unit_id}: method.family must be static")
        tool = method.get("tool")
        if not isinstance(tool, Mapping):
            _error(report, f"{unit_id}: method.tool is required")
            tool = {}
        block = record.get("extensions") or {}
        normalization = block.get("static_normalization")
        if not isinstance(normalization, Mapping):
            _error(report, f"{unit_id}: missing extensions.static_normalization")
            continue
        if normalization.get("tool_id") != tool_id:
            _error(report, f"{unit_id}: static_normalization.tool_id does not match manifest")
        if normalization.get("tool_version") != tool.get("version"):
            _error(report, f"{unit_id}: static_normalization.tool_version does not match method.tool.version")
        if normalization.get("registry_sha256") != registry_sha:
            _error(report, f"{unit_id}: registry_sha256 does not match benchmark/extensions/registry/static_tools.json")
        if normalization.get("rule_map_version") != static_tool_registry().get("registry_version"):
            _error(report, f"{unit_id}: rule_map_version does not match registry_version")
        if normalization.get("scope_kind") not in ("target_file", "target_function"):
            _error(report, f"{unit_id}: scope_kind is invalid")
        diagnostics = normalization.get("diagnostics")
        if not isinstance(diagnostics, list):
            _error(report, f"{unit_id}: diagnostics must be a list")
            continue
        counts = summarize_diagnostics(diagnostics)
        for key in (
            "raw_warning_count",
            "dedup_warning_count",
            "mapped_warning_count",
            "unmapped_warning_count",
            "out_of_scope_count",
            "suppressed_count",
        ):
            if normalization.get(key) != counts[key]:
                _error(
                    report,
                    f"{unit_id}: {key}={normalization.get(key)!r} but recount gives {counts[key]!r}",
                )
        for index, diagnostic in enumerate(diagnostics, start=1):
            if not isinstance(diagnostic, Mapping):
                _error(report, f"{unit_id}: diagnostic {index} must be an object")
                continue
            for key in ("rule_id", "severity", "severity_class", "dedup_key", "mapping_basis"):
                if key not in diagnostic:
                    _error(report, f"{unit_id}: diagnostic {index} missing {key}")
            if diagnostic.get("dedup_key") and not (
                isinstance(diagnostic["dedup_key"], str) and len(diagnostic["dedup_key"]) == 64
            ):
                _error(report, f"{unit_id}: diagnostic {index} dedup_key must be 64 hex characters")
            if diagnostic.get("counts_for_cwe401") and diagnostic.get("mapped_cwe") != "CWE-401":
                _error(report, f"{unit_id}: diagnostic {index} counts_for_cwe401 without mapped_cwe=CWE-401")
            if diagnostic.get("mapping_basis") == "registry" and diagnostic.get("rule_id") not in (tool_spec.get("rules") or {}):
                _error(report, f"{unit_id}: diagnostic {index} rule_id not in registry")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        if status == "ok":
            expected = 1 if counts["mapped_warning_count"] > 0 else 0
            if y_pred != bool(expected):
                _error(
                    report,
                    f"{unit_id}: y_pred={y_pred} but recount gives {bool(expected)} "
                    f"({counts['mapped_warning_count']} mapped in-scope warning(s))",
                )
        elif y_pred is not None:
            _error(report, f"{unit_id}: non-ok status must have y_pred=null")
        declared_rules = set(tool.get("rules") or [])
        unknown_declared = declared_rules - set((tool_spec.get("rules") or {}))
        if unknown_declared:
            _warning(
                report,
                f"{unit_id}: method.tool.rules contains unregistered rule(s) {sorted(unknown_declared)}",
            )
        if record.get("coverage") is not None:
            _warning(report, f"{unit_id}: static tool should not have a dynamic coverage block")
        if unit_index is not None:
            meta = unit_index.get(unit_id) or unit_index.get(str(record.get("unit_id")))
            if meta is None:
                _error(report, f"{unit_id}: unit_id not in the frozen unit map")
            else:
                if record.get("group_id") != meta["group_id"]:
                    _error(report, f"{unit_id}: group_id does not match unit map")
                if record.get("side") != meta["label"]:
                    _error(report, f"{unit_id}: side does not match unit map")
                if record.get("cluster_id") != meta["family"]:
                    _error(report, f"{unit_id}: cluster_id does not match unit map family")
                if as_bool((record.get("label") or {}).get("y_true")) != (meta["label"] == "bad"):
                    _error(report, f"{unit_id}: label.y_true does not match unit map")
        seen.add(unit_id)
    if unit_index is not None:
        split_filter = (extension_manifest.get("options") or {}).get("split")
        expected = {
            meta["unit_id"]
            for meta in unit_index.values()
            if not split_filter or meta.get("split") == split_filter
        }
        missing = expected - seen
        extra = seen - expected
        if missing:
            _error(report, f"unit map has {len(missing)} unit(s) without predictions")
        if extra:
            _error(report, f"predictions contain {len(extra)} unit(s) not in the unit map")


def _check_position_pairing(
    report: dict[str, Any],
    run_dir: Path,
    sibling_dir: Path | None,
) -> None:
    if sibling_dir is None:
        return
    try:
        manifest_a, ext_a, records_a, _ = load_extension_run(run_dir)
        manifest_b, ext_b, records_b, _ = load_extension_run(sibling_dir)
    except ExtensionError as exc:
        _error(report, f"sibling run cannot be loaded: {exc}")
        return
    if not ext_a or not ext_b:
        _error(report, "position pairing requires extension_manifest.json in both runs")
        return
    if ext_a.get("design") != "position_debiased_pair" or ext_b.get("design") != "position_debiased_pair":
        _error(report, "sibling run is not a position_debiased_pair run")
        return
    if ext_a.get("presentation_order") == ext_b.get("presentation_order"):
        _error(report, "sibling runs must have opposite presentation_order")
    if ext_a.get("pairing_id") != ext_b.get("pairing_id"):
        _error(report, "sibling runs have different pairing_id")
    if (manifest_a.get("dataset") or {}).get("sha256") != (manifest_b.get("dataset") or {}).get("sha256"):
        _error(report, "sibling runs have different dataset.sha256")
    method_a = manifest_a.get("method") or {}
    method_b = manifest_b.get("method") or {}
    if method_a.get("method_id") != method_b.get("method_id"):
        _error(report, "sibling runs have different method_id")
    if method_a.get("config_sha256") != method_b.get("config_sha256"):
        _warning(report, "sibling runs have different method.config_sha256")
    pairs_a = {str(r.get("group_id")) for r in records_a}
    pairs_b = {str(r.get("group_id")) for r in records_b}
    if pairs_a != pairs_b:
        _error(
            report,
            f"sibling runs cover different pairs: only A={len(pairs_a - pairs_b)}, only B={len(pairs_b - pairs_a)}",
        )
    if len(records_a) != 2 * len(pairs_a):
        _error(report, "run A does not have exactly two side records per pair")
    if len(records_b) != 2 * len(pairs_b):
        _error(report, "run B does not have exactly two side records per pair")
    order_a = ext_a.get("presentation_order")
    order_b = ext_b.get("presentation_order")
    if {order_a, order_b} == {"fwd", "rev"}:
        maps_a: dict[str, Mapping[str, Any]] = {}
        maps_b: dict[str, Mapping[str, Any]] = {}
        for record in records_a:
            block = record.get("extensions") or {}
            if record.get("side") == "vulnerable":
                maps_a[str(record.get("group_id"))] = block.get("position_map") or {}
        for record in records_b:
            block = record.get("extensions") or {}
            if record.get("side") == "vulnerable":
                maps_b[str(record.get("group_id"))] = block.get("position_map") or {}
        for pair_id in sorted(set(maps_a) & set(maps_b)):
            expected = {
                "A": maps_a[pair_id].get("B"),
                "B": maps_a[pair_id].get("A"),
            }
            if maps_b[pair_id] != expected:
                _error(
                    report,
                    f"pair {pair_id}: rev position_map is not the exact slot swap of fwd",
                )



def _check_evidence_retraction(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "evidence_retraction requires run_role=single")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        if record.get("task") != "detection":
            _error(report, f"{unit_id}: evidence_retraction requires task=detection")
        if record.get("group_id") not in (None, ""):
            _error(report, f"{unit_id}: evidence_retraction must not have group_id")
        if record.get("side") not in (None, ""):
            _error(report, f"{unit_id}: evidence_retraction must not have side")
        if unit_id in seen:
            _error(report, f"{unit_id}: duplicate unit_id")
        seen.add(unit_id)
        block = record.get("extensions") or {}
        retraction = block.get("retraction")
        if not isinstance(retraction, Mapping):
            _error(report, f"{unit_id}: missing extensions.retraction")
            continue
        required = (
            "first_pass_y_pred",
            "first_pass_status",
            "verifier_status",
            "verifier_verdict",
            "retracted",
            "fail_closed",
        )
        for key in required:
            if key not in retraction:
                _error(report, f"{unit_id}: retraction.{key} is required")
        first_pred = as_bool(retraction.get("first_pass_y_pred"))
        first_status = str(retraction.get("first_pass_status"))
        verdict = retraction.get("verifier_verdict")
        if verdict not in ("sustain", "retract", "not_requested", "invalid", None):
            _error(report, f"{unit_id}: invalid verifier_verdict")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        if first_status != "ok":
            if status != "schema_invalid" or y_pred is not None:
                _error(report, f"{unit_id}: invalid first pass must remain schema_invalid with y_pred=null")
            if retraction.get("first_pass_y_pred") is not None:
                _error(report, f"{unit_id}: invalid first pass must have first_pass_y_pred=null")
            continue
        if first_pred is True:
            if verdict == "sustain" and retraction.get("fail_closed") is not True:
                if status != "ok" or y_pred is not True:
                    _error(report, f"{unit_id}: sustained first pass requires status=ok and y_pred=true")
            else:
                if status != "ok" or y_pred is not False:
                    _error(report, f"{unit_id}: retracted/fail-closed first pass requires status=ok and y_pred=false")
        elif first_pred is False:
            if status != "ok" or y_pred is not False:
                _error(report, f"{unit_id}: negative first pass must remain status=ok and y_pred=false")
            if verdict != "not_requested":
                _error(report, f"{unit_id}: negative first pass must have verifier_verdict=not_requested")
        else:
            _error(report, f"{unit_id}: status=ok requires first_pass_y_pred boolean")
        expected_retracted = bool(first_pred is True and verdict == "retract" and y_pred is False)
        if bool(retraction.get("retracted")) != expected_retracted:
            _error(report, f"{unit_id}: retracted does not match first_pass_y_pred/post prediction")
        if retraction.get("fail_closed") is True and first_pred is not True:
            _error(report, f"{unit_id}: fail_closed requires a positive first pass")
        if retraction.get("verifier_status") == "ok" and verdict == "invalid":
            _error(report, f"{unit_id}: verifier_status=ok cannot have verdict=invalid")
        input_block = record.get("input") or {}
        if input_block.get("view") != "function":
            _error(report, f"{unit_id}: evidence_retraction input.view must be function")
        if input_block.get("sanitized") is not True:
            _warning(report, f"{unit_id}: evidence_retraction input is not marked sanitized")
        analysis_status = str(retraction.get("analysis_status") or "")
        if analysis_status != "exploratory_post_hoc_test_seen":
            _warning(report, f"{unit_id}: analysis_status is {analysis_status!r}, expected exploratory_post_hoc_test_seen")


def _check_enhanced_dynamic(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    extension_manifest: Mapping[str, Any],
    unit_map_path: str | None,
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "enhanced_dynamic requires run_role=single")
    unit_index = None
    if unit_map_path:
        from ext_common import juliet_unit_index

        path = resolve_path(unit_map_path, [extension_manifest.get("_run_dir") or ".", project_root()])
        if path.exists():
            unit_index = juliet_unit_index(path)
        else:
            _warning(report, f"unit map not found at {path}; skipped unit-set check")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        block = record.get("extensions") or {}
        enhanced = block.get("dynamic_enhanced")
        if not isinstance(enhanced, Mapping):
            _error(report, f"{unit_id}: missing extensions.dynamic_enhanced")
            continue
        for key in (
            "source_run_id",
            "decision",
            "evidence_modes",
            "unobservable_in_default",
            "conditionally_observable",
            "probe_executed",
            "coverage_proxy",
            "operational_y_pred",
        ):
            if key not in enhanced:
                _error(report, f"{unit_id}: dynamic_enhanced.{key} is required")
        decision = enhanced.get("decision")
        if decision not in ("leak", "clean", "build_error", "run_error", "timeout", "crash", "not_evaluable"):
            _error(report, f"{unit_id}: invalid dynamic_enhanced.decision")
        if record.get("task") != "leak_detection":
            _error(report, f"{unit_id}: enhanced_dynamic requires task=leak_detection")
        method = record.get("method") or {}
        if method.get("family") != "dynamic":
            _error(report, f"{unit_id}: enhanced_dynamic requires method.family=dynamic")
        coverage = record.get("coverage")
        if not isinstance(coverage, Mapping):
            _error(report, f"{unit_id}: enhanced_dynamic requires coverage")
        try:
            group, side = parse_juliet_unit_id(unit_id)
        except ExtensionError as exc:
            _error(report, f"{unit_id}: {exc}")
            continue
        if record.get("group_id") != group or record.get("side") != side:
            _error(report, f"{unit_id}: group_id/side do not match unit_id")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        operational = as_bool(enhanced.get("operational_y_pred"))
        if decision == "leak":
            if status != "ok" or y_pred is not True:
                _error(report, f"{unit_id}: decision=leak requires status=ok and y_pred=true")
            if operational is not True:
                _error(report, f"{unit_id}: decision=leak requires operational_y_pred=true")
        elif decision == "clean":
            if status != "inconclusive" or y_pred is not None:
                _error(report, f"{unit_id}: decision=clean requires status=inconclusive and y_pred=null")
            if operational is not False:
                _error(report, f"{unit_id}: decision=clean requires operational_y_pred=false")
            if coverage.get("line_coverage") is not None:
                _error(report, f"{unit_id}: coverage-unverified clean must not claim line_coverage")
        else:
            if status == "ok" or y_pred is not None:
                _error(report, f"{unit_id}: non-leak/clean decision must be non-ok with y_pred=null")
        if unit_index is not None:
            meta = unit_index.get(unit_id)
            if meta is None:
                _error(report, f"{unit_id}: unit_id not in unit map")
            else:
                if record.get("cluster_id") != meta["family"]:
                    _error(report, f"{unit_id}: cluster_id does not match unit map family")
                if as_bool((record.get("label") or {}).get("y_true")) != (meta["label"] == "bad"):
                    _error(report, f"{unit_id}: label.y_true does not match unit map")
        seen.add(unit_id)
    if unit_index is not None:
        split_filter = (extension_manifest.get("options") or {}).get("split") or "test"
        expected = {
            meta["unit_id"]
            for meta in unit_index.values()
            if meta.get("split") == split_filter
        }
        if expected - seen:
            _error(report, f"unit map has {len(expected - seen)} unit(s) without predictions")
        if seen - expected:
            _error(report, f"predictions contain {len(seen - expected)} unit(s) outside split {split_filter}")


def _check_hybrid_enhanced_dynamic(
    report: dict[str, Any],
    records: Sequence[Mapping[str, Any]],
    extension_manifest: Mapping[str, Any],
    unit_map_path: str | None,
) -> None:
    if extension_manifest.get("run_role") != "single":
        _error(report, "hybrid_enhanced_dynamic requires run_role=single")
    unit_index = None
    if unit_map_path:
        from ext_common import juliet_unit_index

        path = resolve_path(unit_map_path, [extension_manifest.get("_run_dir") or ".", project_root()])
        if path.exists():
            unit_index = juliet_unit_index(path)
        else:
            _warning(report, f"unit map not found at {path}; skipped unit-set check")
    seen: set[str] = set()
    for record in records:
        unit_id = str(record.get("unit_id"))
        block = record.get("extensions") or {}
        enhanced = block.get("hybrid_dynamic_enhanced")
        if not isinstance(enhanced, Mapping):
            _error(report, f"{unit_id}: missing extensions.hybrid_dynamic_enhanced")
            continue
        for key in ("source_run_id", "evidence_outcome", "tool_verdict", "prompt_version"):
            if key not in enhanced:
                _error(report, f"{unit_id}: hybrid_dynamic_enhanced.{key} is required")
        if record.get("task") != "leak_detection":
            _error(report, f"{unit_id}: hybrid_enhanced_dynamic requires task=leak_detection")
        method = record.get("method") or {}
        if method.get("family") != "hybrid":
            _error(report, f"{unit_id}: hybrid_enhanced_dynamic requires method.family=hybrid")
        try:
            group, side = parse_juliet_unit_id(unit_id)
        except ExtensionError as exc:
            _error(report, f"{unit_id}: {exc}")
            continue
        if record.get("group_id") != group or record.get("side") != side:
            _error(report, f"{unit_id}: group_id/side do not match unit_id")
        status = record.get("status")
        y_pred = as_bool((record.get("prediction") or {}).get("y_pred"))
        if status == "ok" and y_pred is None:
            _error(report, f"{unit_id}: status=ok requires y_pred")
        if status != "ok" and y_pred is not None:
            _error(report, f"{unit_id}: non-ok status requires y_pred=null")
        if unit_index is not None:
            meta = unit_index.get(unit_id)
            if meta is None:
                _error(report, f"{unit_id}: unit_id not in unit map")
            else:
                if record.get("cluster_id") != meta["family"]:
                    _error(report, f"{unit_id}: cluster_id does not match unit map family")
                if as_bool((record.get("label") or {}).get("y_true")) != (meta["label"] == "bad"):
                    _error(report, f"{unit_id}: label.y_true does not match unit map")
        seen.add(unit_id)
    if unit_index is not None:
        expected = {meta["unit_id"] for meta in unit_index.values() if meta.get("split") == "test"}
        if expected - seen:
            _error(report, f"unit map has {len(expected - seen)} test unit(s) without predictions")
        if seen - expected:
            _error(report, f"predictions contain {len(seen - expected)} unit(s) outside test split")

def validate_extension_run(
    run_dir: str | Path,
    *,
    sibling_run_dir: str | Path | None = None,
    claim_manifest: str | None = None,
    fault_manifest: str | None = None,
    unit_map: str | None = None,
    use_jsonschema: bool = False,
    strict: bool = False,
) -> dict[str, Any]:
    directory = Path(run_dir).resolve()
    report: dict[str, Any] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "checked_at": utc_now(),
        "run_dir": str(directory),
        "design": None,
        "ok": False,
        "errors": [],
        "warnings": [],
        "counts": {},
        "hashes": {},
    }
    parent_report = validate_run(
        directory,
        strict=strict,
        use_jsonschema=use_jsonschema,
    )
    _merge(report, parent_report)
    if parent_report.get("errors"):
        # Still try extension checks if the files are readable; this gives a
        # complete diagnosis in one pass.
        pass
    try:
        manifest, extension_manifest, records, predictions_path = load_extension_run(directory)
    except ExtensionError as exc:
        _error(report, str(exc))
        return report
    report["hashes"]["run_manifest_sha256"] = sha256_file(directory / "run_manifest.json")
    report["hashes"]["predictions_sha256"] = sha256_file(predictions_path)
    if extension_manifest is not None:
        _check_extension_schema(report, extension_manifest, records, str(extension_manifest.get("design")))
        report["hashes"]["extension_manifest_sha256"] = sha256_file(
            directory / "extension_manifest.json"
        )
    try:
        design = infer_design(manifest, extension_manifest, records)
    except ExtensionError as exc:
        _error(report, str(exc))
        return report
    report["design"] = design
    if extension_manifest is not None:
        extension_manifest = dict(extension_manifest)
        extension_manifest["_run_dir"] = str(directory)
    try:
        check_no_secret_fields(manifest)
        if extension_manifest is not None:
            check_no_secret_fields(extension_manifest)
        check_no_secret_fields(records)
    except ExtensionError as exc:
        _error(report, str(exc))
    _check_common(report, manifest, extension_manifest, records, design)
    if extension_manifest is not None:
        if design == "position_debiased_pair":
            _check_position(report, records, extension_manifest)
        elif design == "open_choice_pair":
            _check_open_choice(report, records, extension_manifest)
        elif design == "evidence_verification":
            _check_evidence(report, records, extension_manifest, claim_manifest)
        elif design == "fault_injected_dynamic":
            _check_fault(report, records, manifest, extension_manifest, fault_manifest)
        elif design == "new_static_tool":
            _check_static(report, records, extension_manifest, unit_map)
        elif design == "evidence_retraction":
            _check_evidence_retraction(report, records, extension_manifest)
        elif design == "enhanced_dynamic":
            _check_enhanced_dynamic(report, records, manifest, extension_manifest, unit_map)
        elif design == "hybrid_enhanced_dynamic":
            _check_hybrid_enhanced_dynamic(report, records, extension_manifest, unit_map)
    _check_position_pairing(report, directory, Path(sibling_run_dir).resolve() if sibling_run_dir else None)
    execution = manifest.get("execution") or {}
    groups = {str(r.get("group_id")) for r in records if r.get("group_id")}
    report["counts"] = {
        "records": len(records),
        "unique_units": len({str(r.get("unit_id")) for r in records}),
        "planned_units": execution.get("planned_units"),
        "recorded_units": execution.get("recorded_units"),
        "groups": len(groups),
        "by_status": {},
        "by_task": {},
    }
    from collections import Counter

    report["counts"]["by_status"] = dict(Counter(str(r.get("status")) for r in records))
    report["counts"]["by_task"] = dict(Counter(str(r.get("task")) for r in records))
    if isinstance(execution.get("planned_units"), int) and execution["planned_units"] != len(records):
        message = (
            f"manifest.planned_units={execution['planned_units']} but predictions has "
            f"{len(records)} records"
        )
        if strict and execution.get("status") == "completed":
            _error(report, message)
        else:
            _warning(report, message)
    report["ok"] = not report["errors"]
    return report


def _merge_reports(reports: Sequence[Mapping[str, Any]], base: dict[str, Any]) -> dict[str, Any]:
    for child in reports:
        _merge(base, child)
        counts = child.get("counts") or {}
        for key, value in counts.items():
            if key in ("by_status", "by_task") and isinstance(value, Mapping):
                target = base["counts"].setdefault(key, {})
                for name, number in value.items():
                    target[name] = target.get(name, 0) + int(number)
            elif isinstance(value, int):
                base["counts"][key] = base["counts"].get(key, 0) + value
    base["ok"] = not base["errors"]
    return base


def check_registries() -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "benchmark-extension-registry-check-v1",
        "checked_at": utc_now(),
        "ok": False,
        "errors": [],
        "warnings": [],
        "counts": {},
    }
    try:
        designs = read_json(DESIGNS_PATH)
        tools = read_json(STATIC_TOOLS_PATH)
        faults = read_json(FAULT_TYPES_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        _error(report, str(exc))
        return report
    for label, path, schema_name in (
        ("designs", DESIGNS_PATH, None),
        ("static_tools", STATIC_TOOLS_PATH, "static_tool_registry.schema.json"),
        ("fault_types", FAULT_TYPES_PATH, None),
    ):
        if schema_name:
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / schema_name
            schema = _load_jsonschema_file(schema_path)
            if schema is not None:
                _jsonschema_validate(report, read_json(path), schema, label)
    design_list = designs.get("designs") or []
    seen: set[str] = set()
    for spec in design_list:
        design_id = spec.get("design_id")
        if design_id in seen:
            _error(report, f"duplicate design_id {design_id!r}")
        seen.add(design_id)
        if spec.get("parent_task") not in ("detection", "pair_detection", "leak_detection"):
            _error(report, f"{design_id}: invalid parent_task")
        if spec.get("design_id") not in design_ids():
            _error(report, f"{design_id}: not in design_ids()")
    if set(design_ids()) != seen:
        _error(report, "design registry and design_ids() disagree")
    tool_map = tools.get("tools") or {}
    for tool_id, spec in tool_map.items():
        if spec.get("family") != "static":
            _error(report, f"{tool_id}: family must be static")
        rules = spec.get("rules") or {}
        for rule, rule_spec in rules.items():
            cwe = rule_spec.get("cwe")
            if normalize_cwe_list(cwe) != [cwe]:
                _error(report, f"{tool_id}: rule {rule!r} has invalid cwe {cwe!r}")
            if rule_spec.get("counts_for_cwe401") and cwe != "CWE-401":
                _error(report, f"{tool_id}: rule {rule!r} counts for CWE-401 but maps to {cwe}")
        if not rules:
            _warning(report, f"{tool_id}: no rules registered")
    fault_map = faults.get("fault_types") or {}
    for fault_type, spec in fault_map.items():
        allowed = spec.get("allowed_expected_outcomes") or []
        if not allowed or any(value not in EXPECTED_OUTCOMES for value in allowed):
            _error(report, f"{fault_type}: invalid allowed_expected_outcomes")
        if spec.get("binary_label") and set(allowed) - {"leak", "clean"}:
            _error(report, f"{fault_type}: binary_label=true requires leak/clean only")
    report["counts"] = {
        "designs": len(design_list),
        "static_tools": len(tool_map),
        "static_rules": sum(len(spec.get("rules") or {}) for spec in tool_map.values()),
        "fault_types": len(fault_map),
    }
    report["ok"] = not report["errors"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", help="extension run directory, or a position base with order_ab/order_ba")
    parser.add_argument("--sibling-run-dir", help="the opposite order run for position_debiased_pair")
    parser.add_argument("--claim-manifest", help="optional frozen claim manifest to join")
    parser.add_argument("--fault-manifest", help="optional frozen fault manifest to join")
    parser.add_argument("--unit-map", help="optional Juliet subset_units.jsonl to join")
    parser.add_argument("--jsonschema", action="store_true", help="validate extension schemas with jsonschema")
    parser.add_argument("--strict", action="store_true", help="promote count/group anomalies to errors")
    parser.add_argument("--json-out", help="write the report here (default: stdout)")
    parser.add_argument("--force", action="store_true", help="overwrite an existing --json-out file")
    parser.add_argument("--check-registries", action="store_true", help="validate the extension registries and exit")
    args = parser.parse_args(argv)

    if args.check_registries:
        report = check_registries()
        text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if args.json_out:
            path = Path(args.json_out)
            if path.exists() and not args.force:
                sys.stderr.write(f"refusing to overwrite {path}; pass --force\n")
                return 2
            atomic_write_text(path, text)
        else:
            sys.stdout.write(text)
        if report["errors"]:
            sys.stderr.write(f"registry check failed: {len(report['errors'])} error(s)\n")
            return 2
        sys.stderr.write(
            f"registry check ok: {report['counts'].get('designs', 0)} designs, "
            f"{report['counts'].get('static_tools', 0)} tools, "
            f"{report['counts'].get('fault_types', 0)} fault types\n"
        )
        return 0

    if not args.run_dir:
        parser.error("--run-dir is required unless --check-registries is used")
    run_dir = Path(args.run_dir).resolve()
    reports: list[dict[str, Any]] = []
    if (run_dir / "run_manifest.json").exists():
        reports.append(
            validate_extension_run(
                run_dir,
                sibling_run_dir=args.sibling_run_dir,
                claim_manifest=args.claim_manifest,
                fault_manifest=args.fault_manifest,
                unit_map=args.unit_map,
                use_jsonschema=args.jsonschema,
                strict=args.strict,
            )
        )
        base = reports[0]
    elif any(
        (run_dir / name_a).exists() and (run_dir / name_b).exists()
        for name_a, name_b in (("order_ab", "order_ba"), ("fwd", "rev"), ("order_fwd", "order_rev"))
    ):
        if (run_dir / "order_ab").exists():
            dirs_pair = (run_dir / "order_ab", run_dir / "order_ba")
        elif (run_dir / "fwd").exists():
            dirs_pair = (run_dir / "fwd", run_dir / "rev")
        else:
            dirs_pair = (run_dir / "order_fwd", run_dir / "order_rev")
        child_a = validate_extension_run(
            dirs_pair[0],
            sibling_run_dir=dirs_pair[1],
            use_jsonschema=args.jsonschema,
            strict=args.strict,
        )
        child_b = validate_extension_run(
            dirs_pair[1],
            sibling_run_dir=dirs_pair[0],
            use_jsonschema=args.jsonschema,
            strict=args.strict,
        )
        reports.extend([child_a, child_b])
        base = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "checked_at": utc_now(),
            "run_dir": str(run_dir),
            "design": "position_debiased_pair",
            "ok": False,
            "errors": [],
            "warnings": [],
            "counts": {},
            "hashes": {},
            "runs": [str(dirs_pair[0]), str(dirs_pair[1])],
        }
        _merge_reports(reports, base)
        pair_groups: set[str] = set()
        for child_dir in dirs_pair:
            try:
                _, _, child_records, _ = load_extension_run(child_dir)
            except ExtensionError:
                continue
            pair_groups.update(str(record.get("group_id")) for record in child_records if record.get("group_id"))
        base["counts"]["groups"] = len(pair_groups)
    else:
        sys.stderr.write(f"no run_manifest.json or order_ab/order_ba pair under {run_dir}\n")
        return 2

    text = json.dumps(base, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.json_out:
        path = Path(args.json_out)
        if path.exists() and not args.force:
            sys.stderr.write(f"refusing to overwrite {path}; pass --force\n")
            return 2
        atomic_write_text(path, text)
    else:
        sys.stdout.write(text)
    if base["errors"]:
        sys.stderr.write(f"validation failed: {len(base['errors'])} error(s)\n")
        return 2
    sys.stderr.write(
        f"validation ok: {base['counts'].get('records', 0)} records, "
        f"{len(base['warnings'])} warning(s)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

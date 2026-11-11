#!/usr/bin/env python3
"""Validate a benchmark dataset card against the files it references.

For Tier B this checks the frozen Juliet card against
``juliet/subset_units.jsonl`` and the raw archive. It never modifies them.
Optional provenance hashes are checked when the card pins them; the upstream
``juliet/manifest.json`` is allowed to be regenerated during dataset builds and
is therefore not required to be pinned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import atomic_write_json, read_json, utc_now  # noqa: E402

SCHEMA_VERSION = "benchmark-dataset-validation-v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_units(path: Path) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: unit must be an object")
            units.append(value)
    return units


def validate_dataset_card(
    manifest_path: Path,
    *,
    project_root: Path,
    use_jsonschema: bool = False,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "checked_at": utc_now(),
        "manifest_path": str(manifest_path.resolve()),
        "ok": False,
        "errors": [],
        "warnings": [],
        "counts": {},
        "hashes": {},
    }
    if not manifest_path.exists():
        report["errors"].append(f"missing dataset manifest: {manifest_path}")
        return report
    card = read_json(manifest_path)
    if use_jsonschema:
        try:
            import jsonschema  # type: ignore
        except ImportError:
            report["warnings"].append("jsonschema not installed; skipped schema validation")
        else:
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / "dataset_manifest.schema.json"
            try:
                jsonschema.validate(card, read_json(schema_path))
            except jsonschema.ValidationError as exc:
                report["errors"].append(f"schema: {exc.message}")
    if card.get("schema_version") != "benchmark-dataset-v1":
        report["errors"].append("schema_version must be benchmark-dataset-v1")
    for key in ("dataset_id", "tier", "track", "version", "license", "frozen"):
        if key not in card:
            report["errors"].append(f"missing {key}")
    if card.get("tier") != "B" or card.get("track") != "juliet_cwe401":
        report["errors"].append("this validator currently checks Tier B Juliet cards")
    if card.get("frozen") is not True:
        report["errors"].append("dataset card is not frozen")

    units_info = card.get("units") or {}
    units_path = project_root / str(units_info.get("path") or "")
    if not units_info.get("path"):
        report["errors"].append("units.path is required")
        return report
    if not units_path.exists():
        report["errors"].append(f"units file missing: {units_path}")
        return report
    units = _read_units(units_path)
    report["hashes"]["units_sha256"] = _sha256(units_path)
    if report["hashes"]["units_sha256"] != units_info.get("sha256"):
        report["errors"].append("units.sha256 mismatch")
    if int(units_info.get("count", -1)) != len(units):
        report["errors"].append(f"units.count {units_info.get('count')} != actual {len(units)}")
    labels: dict[str, int] = {}
    groups = set()
    families = set()
    splits: dict[str, dict[str, Any]] = {}
    for index, unit in enumerate(units, start=1):
        for key in ("unit_id", "group_id", "family", "label", "split"):
            if key not in unit:
                report["errors"].append(f"unit {index}: missing {key}")
        label = str(unit.get("label"))
        labels[label] = labels.get(label, 0) + 1
        groups.add(str(unit.get("group_id")))
        families.add(str(unit.get("family")))
        split = str(unit.get("split"))
        bucket = splits.setdefault(split, {"units": 0, "groups": set(), "families": set()})
        bucket["units"] += 1
        bucket["groups"].add(str(unit.get("group_id")))
        bucket["families"].add(str(unit.get("family")))
    expected_labels = units_info.get("label_counts") or {}
    for label, actual in labels.items():
        if int(expected_labels.get(label, -1)) != actual:
            report["errors"].append(f"units.label_counts[{label!r}] != actual {actual}")
    if int(units_info.get("cluster_count", -1)) != len(families):
        report["errors"].append(
            f"units.cluster_count {units_info.get('cluster_count')} != actual {len(families)}"
        )
    report["counts"] = {
        "units": len(units),
        "labels": labels,
        "groups": len(groups),
        "families": len(families),
        "splits": {
            name: {
                "units": value["units"],
                "groups": len(value["groups"]),
                "families": len(value["families"]),
            }
            for name, value in sorted(splits.items())
        },
    }

    card_splits = card.get("splits") or {}
    for split_name in ("dev", "test"):
        split_info = card_splits.get(split_name) or {}
        actual = report["counts"]["splits"].get(split_name)
        if not actual:
            report["errors"].append(f"units have no split {split_name!r}")
            continue
        if int(split_info.get("unit_count", -1)) != actual["units"]:
            report["errors"].append(f"splits.{split_name}.unit_count mismatch")
        if int(split_info.get("cluster_count", -1)) != actual["families"]:
            report["errors"].append(f"splits.{split_name}.cluster_count mismatch")
        split_path = project_root / str(split_info.get("path") or "")
        if split_path.exists():
            split_hash = _sha256(split_path)
            report["hashes"][f"splits_{split_name}_sha256"] = split_hash
            expected_split_hash = split_info.get("sha256")
            if expected_split_hash is not None and split_hash != expected_split_hash:
                report["errors"].append(f"splits.{split_name}.sha256 mismatch")
        else:
            report["warnings"].append(f"split path missing (counts still checked): {split_path}")

    provenance = card.get("provenance") or {}
    for key, path_key, hash_key in (
        ("upstream_manifest", "upstream_manifest", "upstream_manifest_sha256"),
        ("freeze", "freeze", "freeze_sha256"),
    ):
        relative = provenance.get(path_key)
        if not relative:
            continue
        if provenance.get(hash_key) is None:
            report["warnings"].append(f"provenance.{hash_key} not pinned; path hash not compared")
            continue
        path = project_root / str(relative)
        if not path.exists():
            report["errors"].append(f"provenance path missing: {path}")
            continue
        actual_hash = _sha256(path)
        report["hashes"][f"{key}_sha256"] = actual_hash
        if actual_hash != provenance.get(hash_key):
            report["errors"].append(f"provenance.{hash_key} mismatch")

    source = card.get("source") or {}
    archive_value = source.get("archive_sha256")
    archive_path = provenance.get("raw_archive")
    if archive_path:
        archive = project_root / str(archive_path)
        if archive.exists():
            actual = _sha256(archive)
            report["hashes"]["archive_sha256"] = actual
            if actual != archive_value:
                report["errors"].append("source.archive_sha256 mismatch")
        else:
            report["warnings"].append(f"raw archive not present: {archive}")

    report["ok"] = not report["errors"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-manifest",
        default="benchmark/datasets/juliet_cwe401_v1/dataset_manifest.json",
    )
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--jsonschema", action="store_true")
    parser.add_argument("--json-out")
    args = parser.parse_args(argv)

    report = validate_dataset_card(
        Path(args.dataset_manifest),
        project_root=Path(args.project_root).resolve(),
        use_jsonschema=args.jsonschema,
    )
    text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.json_out:
        atomic_write_json(args.json_out, report)
    else:
        sys.stdout.write(text)
    if report["errors"]:
        sys.stderr.write(f"dataset validation failed: {len(report['errors'])} error(s)\n")
        return 2
    sys.stderr.write(
        f"dataset validation ok: {report['counts'].get('units')} units, "
        f"{report['counts'].get('groups')} groups, {report['counts'].get('families')} families\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Audit the hybrid run artifacts without modifying them.

Checks: 140 unique units per run, no unexpected statuses, no credential or
label markers in outputs, request/prediction counts, cost arithmetic, and the
placebo mapping constraints.  Prints a JSON summary; exits nonzero on failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
HYBRID = Path(__file__).resolve().parent
for path in (str(ROOT), str(HYBRID)):
    if path not in sys.path:
        sys.path.insert(0, path)

from prompts import PROMPT_VERSION, build_messages  # noqa: E402

KIMI_CONFIG = Path("/mnt/c/Users/tzh03/.kimi-code/config.toml")
MODELS = ("deepseek", "mimo")
METHODS = ("direct", "static", "dynamic", "combined", "shuffled")
SECRET_MARKERS = ("sk-", "api_key", "Bearer ", "OPENCODE_API_KEY")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_secret() -> str | None:
    try:
        with KIMI_CONFIG.open("rb") as handle:
            config = tomllib.load(handle)
        key = config.get("providers", {}).get("opencode-go", {}).get("api_key")
        return key.strip() if isinstance(key, str) else None
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-root", type=Path, default=HYBRID / "runs")
    parser.add_argument("--run-id", default="hybrid_v2")
    parser.add_argument("--inputs-dir", type=Path, default=HYBRID / "inputs_v2")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    args.inputs_dir = args.inputs_dir.resolve()

    units = read_jsonl(args.inputs_dir / "units.jsonl")
    input_manifest = json.loads((args.inputs_dir / "manifest.json").read_text(encoding="utf-8"))
    expected_ids = {unit["unit_id"] for unit in units}
    unit_by_id = {unit["unit_id"]: unit for unit in units}
    secret = load_secret()
    failures: list[str] = []
    summary: dict[str, Any] = {"runs": {}, "failures": failures}

    for model in MODELS:
        for method in METHODS:
            run_dir = args.runs_root / f"{args.run_id}_{model}_{method}"
            if not (run_dir / "results.jsonl").is_file():
                failures.append(f"missing run {run_dir.name}")
                continue
            records = read_jsonl(run_dir / "results.jsonl")
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            run_version = manifest.get("prompt_version")
            ids = [record["unit_id"] for record in records]
            entry: dict[str, Any] = {
                "records": len(records),
                "unique_units": len(set(ids)),
                "statuses": {},
                "cost_usd_sum": 0.0,
                "provider_list_cost_usd_sum": 0.0,
                "list_cost_records": 0,
                "allowance_usd_sum": 0.0,
                "invalid_units": [],
                "api_error_units": [],
            }
            if set(ids) != expected_ids or len(ids) != len(expected_ids):
                failures.append(f"{run_dir.name}: unit set mismatch")
            versions = {
                (record.get("prompt") or {}).get("prompt_version") for record in records
            }
            prompt_methods = {
                (record.get("prompt") or {}).get("method") for record in records
            }
            entry["prompt_version"] = sorted(str(item) for item in versions)
            entry["legacy_prompt_version"] = run_version != PROMPT_VERSION
            if versions != {run_version}:
                failures.append(
                    f"{run_dir.name}: prompt versions {sorted(str(v) for v in versions)} "
                    f"!= manifest {run_version}"
                )
            if prompt_methods != {method}:
                failures.append(f"{run_dir.name}: prompt methods {prompt_methods} != {method}")
            if run_version == PROMPT_VERSION:
                rebuild_mismatches = []
                for record in records:
                    expected_hash = build_messages(unit_by_id[record["unit_id"]], method)[1][
                        "prompt_sha256"
                    ]
                    if (record.get("prompt") or {}).get("prompt_sha256") != expected_hash:
                        rebuild_mismatches.append(record["unit_id"])
                entry["prompt_rebuild_mismatches"] = len(rebuild_mismatches)
                if rebuild_mismatches:
                    failures.append(
                        f"{run_dir.name}: {len(rebuild_mismatches)} prompts do not rebuild "
                        "from the current builder"
                    )
            else:
                entry["prompt_rebuild_mismatches"] = None
            config_record = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
            if config_record.get("dataset", {}).get("sha256") != input_manifest.get("units_sha256"):
                failures.append(f"{run_dir.name}: dataset hash does not match the input pack")
            preflight_record = config_record.get("preflight") or {}
            if not preflight_record:
                if not entry["legacy_prompt_version"]:
                    failures.append(f"{run_dir.name}: no preflight record in config")
            else:
                preflight_path = Path(preflight_record.get("path", ""))
                if not preflight_path.is_absolute():
                    preflight_path = ROOT / preflight_path
                if not preflight_path.is_file():
                    failures.append(f"{run_dir.name}: preflight report is missing")
                elif hashlib.sha256(preflight_path.read_bytes()).hexdigest() != preflight_record.get(
                    "sha256"
                ):
                    failures.append(f"{run_dir.name}: preflight report hash mismatch")
            for record in records:
                status = record["status"]
                entry["statuses"][status] = entry["statuses"].get(status, 0) + 1
                if status == "invalid":
                    entry["invalid_units"].append(record["unit_id"])
                if status == "api_error":
                    entry["api_error_units"].append(record["unit_id"])
                cost = record.get("cost") or {}
                if isinstance(cost.get("cost_usd"), (int, float)):
                    entry["cost_usd_sum"] += float(cost["cost_usd"])
                usage = record.get("usage") or {}
                opencode = usage.get("opencode") if isinstance(usage, dict) else None
                if isinstance(opencode, dict) and isinstance(opencode.get("allowance"), (int, float)):
                    entry["allowance_usd_sum"] += float(opencode["allowance"])
                if isinstance(opencode, dict) and isinstance(opencode.get("list_cost"), (int, float)):
                    entry["provider_list_cost_usd_sum"] += float(opencode["list_cost"])
                    entry["list_cost_records"] += 1
            if entry["list_cost_records"] and entry["provider_list_cost_usd_sum"]:
                entry["cost_basis_ratio"] = (
                    entry["cost_usd_sum"] / entry["provider_list_cost_usd_sum"]
                )
                if abs(entry["cost_basis_ratio"] - 1.0) > 0.02:
                    failures.append(
                        f"{run_dir.name}: configured list cost is "
                        f"{entry['cost_basis_ratio']:.3f}x the provider snapshot"
                    )
            else:
                entry["cost_basis_ratio"] = None
            text = (run_dir / "results.jsonl").read_text(encoding="utf-8")
            for marker in SECRET_MARKERS:
                if marker in text:
                    failures.append(f"{run_dir.name}: secret marker {marker!r}")
            if secret and secret in text:
                failures.append(f"{run_dir.name}: API key found in results")
            requests = read_jsonl(run_dir / "requests.jsonl")
            entry["requests"] = len(requests)
            entry["manifest"] = {
                "expected_units": manifest.get("expected_units"),
                "recorded_units": manifest.get("recorded_units"),
                "counts": manifest.get("counts"),
                "prompt_version": manifest.get("prompt_version"),
            }
            if manifest.get("expected_units") != 140:
                failures.append(f"{run_dir.name}: expected_units != 140")
            if manifest.get("recorded_units") != 140:
                failures.append(f"{run_dir.name}: recorded_units != 140")
            if (manifest.get("counts") or {}).get("ok") != 140:
                failures.append(f"{run_dir.name}: manifest ok count != 140")
            if not run_version:
                failures.append(f"{run_dir.name}: manifest has no prompt_version")
            if len(requests) != 140 or len({r["unit_id"] for r in requests}) != 140:
                failures.append(f"{run_dir.name}: requests.jsonl is not 140 unique units")
            entry["partial"] = manifest.get("partial")
            if manifest.get("partial"):
                failures.append(f"{run_dir.name}: partial run")
            summary["runs"][run_dir.name] = entry

    # Placebo integrity
    placebo_pairs = {
        unit["unit_id"]: (unit["placebo_donor_unit"], unit["placebo_donor_group"]) for unit in units
    }
    bad_pairs = [
        unit_id
        for unit_id, (donor, donor_group) in placebo_pairs.items()
        if donor == unit_id or donor_group == next(u["group_id"] for u in units if u["unit_id"] == unit_id)
    ]
    if bad_pairs:
        failures.append(f"placebo mapping invalid for {len(bad_pairs)} units")
    noop_collisions = [
        unit["unit_id"]
        for unit in units
        if unit["placebo_evidence"] == unit["evidence"]["combined"]
    ]
    expected_collisions = input_manifest.get("placebo", {}).get("identical_evidence_pairs")
    if expected_collisions is not None and expected_collisions != len(noop_collisions):
        failures.append(
            f"manifest no-op collisions {expected_collisions} != recomputed {len(noop_collisions)}"
        )
    summary["placebo"] = {
        "pairs": len(placebo_pairs),
        "invalid": len(bad_pairs),
        "noop_collisions": len(noop_collisions),
        "noop_units": sorted(noop_collisions),
        "manifest_noop_collisions": expected_collisions,
    }
    summary["input_pack"] = {
        "path": str((args.inputs_dir / "units.jsonl").relative_to(ROOT)),
        "units_sha256": input_manifest.get("units_sha256"),
        "unit_count": input_manifest.get("unit_count"),
    }

    # Dynamic evidence is never silently treated as clean.
    inconclusive = [u for u in units if u["dynamic_outcome"] == "inconclusive"]
    summary["dynamic_evidence"] = {
        "inconclusive_units": [u["unit_id"] for u in inconclusive],
        "inconclusive_note": "inconclusive is rendered as NOT clean in every prompt",
        "bad_with_clean_evidence": sum(
            1 for u in units if u["label"] and u["dynamic_outcome"] == "clean"
        ),
        "good_with_leak_evidence": sum(
            1 for u in units if not u["label"] and u["dynamic_outcome"] == "leak"
        ),
    }
    summary["provenance"] = {
        "prompt_version": PROMPT_VERSION,
        "juliet_llm_cleaning_sha256": hashlib.sha256(
            (ROOT / "juliet_llm/cleaning.py").read_bytes()
        ).hexdigest(),
        "juliet_llm_prompting_sha256": hashlib.sha256(
            (ROOT / "juliet_llm/prompting.py").read_bytes()
        ).hexdigest(),
        "inputs_units_sha256": hashlib.sha256(
            (args.inputs_dir / "units.jsonl").read_bytes()
        ).hexdigest(),
    }
    summary["ok"] = not failures
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

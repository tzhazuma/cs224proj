"""Fail-closed preflight gate for the enhanced-dynamic-guidance run.

Nothing is sent to a paid endpoint until this script exits 0.  It verifies the
frozen Juliet split, the v2 input pack, the dynamic_enhanced export, the
tool's 70TP/70TN confusion matrix, both prompt builders, the six frozen v2
baseline runs, and (with ``--smoke``) one live JSON-mode request per model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from juliet_llm.cleaning import clean_unit
from juliet_llm.metrics import SchemaError, parse_verdict
from juliet_llm.prompting import SYSTEM_PROMPT

import prompts as v2_prompts  # type: ignore[import-not-found]

from . import prompts as hde_prompts
from .api import api_config, ensure_direct_network, load_api_key
from .config import (
    DIRECT_PROMPT_VERSION,
    EXPECTED_LABELS,
    EXPECTED_TOOL_CONFUSION,
    EXPECTED_UNITS,
    GUIDED_PROMPT_VERSION,
    INPUTS_DIR,
    JULIET,
    METHOD,
    MODELS,
    RESULTS_DIR,
    ROOT,
    RUNS_DIR,
    V2_INPUTS,
    V2_METHODS,
    V2_RUNS,
)
from .evidence import MODES, build_units, read_jsonl, sha256_bytes


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def check(checks: list[dict[str, Any]], name: str, ok: bool, detail: Any) -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok:
        print(f"FAIL {name}: {detail}", file=sys.stderr)
    return bool(ok)


def load_frozen() -> dict[str, dict[str, Any]]:
    units = [u for u in read_jsonl(JULIET / "subset_units.jsonl") if u["split"] == "test"]
    return {u["unit_id"]: u for u in units}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-dir", type=Path, default=INPUTS_DIR)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "preflight.json")
    parser.add_argument("--smoke", action="store_true", help="send one tiny live request per model")
    parser.add_argument("--run-id", default=None, help="also assert this run id is unused")
    args = parser.parse_args(argv)
    args.inputs_dir = args.inputs_dir.resolve()
    args.out = args.out.resolve()

    checks: list[dict[str, Any]] = []
    failures: list[str] = []

    def gate(name: str, ok: bool, detail: Any) -> None:
        if not check(checks, name, ok, detail):
            failures.append(name)

    # 1. Frozen Juliet test split.
    freeze = json.loads((JULIET / "FREEZE.json").read_text(encoding="utf-8"))
    subset_path = JULIET / "subset_units.jsonl"
    subset_sha = sha256_bytes(subset_path.read_bytes())
    frozen = load_frozen()
    frozen_counts = Counter(u["label"] for u in frozen.values())
    gate(
        "frozen_split",
        subset_sha == freeze.get("subset_units_sha256")
        and len(frozen) == EXPECTED_UNITS
        and dict(frozen_counts) == EXPECTED_LABELS,
        {
            "subset_sha256": subset_sha,
            "freeze_sha256": freeze.get("subset_units_sha256"),
            "units": len(frozen),
            "labels": dict(frozen_counts),
        },
    )

    # 2. v2 input pack, byte-identical source views.
    v2_units = {u["unit_id"]: u for u in read_jsonl(V2_INPUTS / "units.jsonl")}
    v2_manifest = json.loads((V2_INPUTS / "manifest.json").read_text(encoding="utf-8"))
    v2_sha = sha256_bytes((V2_INPUTS / "units.jsonl").read_bytes())
    source_mismatch: list[str] = []
    clean_mismatch: list[str] = []
    for unit_id, unit in v2_units.items():
        raw = unit["source_text"].encode("utf-8")
        if sha256_bytes(raw) != unit.get("source_sha256"):
            source_mismatch.append(unit_id)
            continue
        if unit_id not in frozen:
            clean_mismatch.append(unit_id)
            continue
        cleaned = clean_unit(frozen[unit_id])
        if cleaned.code != unit["source_text"]:
            clean_mismatch.append(unit_id)
    gate(
        "v2_input_pack",
        v2_sha == v2_manifest.get("units_sha256")
        and len(v2_units) == EXPECTED_UNITS
        and Counter("bad" if u["label"] else "good" for u in v2_units.values()) == Counter(EXPECTED_LABELS)
        and not source_mismatch
        and not clean_mismatch,
        {
            "sha256": v2_sha,
            "manifest_sha256": v2_manifest.get("units_sha256"),
            "units": len(v2_units),
            "source_sha_mismatch": source_mismatch,
            "cleaner_mismatch": clean_mismatch,
        },
    )

    # 3. Build the enhanced pack in memory; this audits every evidence block.
    build_error: str | None = None
    units: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {}
    try:
        units, manifest = build_units()
    except Exception as exc:  # noqa: BLE001
        build_error = f"{type(exc).__name__}: {exc}"
    gate("enhanced_inputs_build", build_error is None, {"error": build_error, "units": len(units)})
    if build_error:
        report = {
            "ok": False,
            "generated_at": utc_now(),
            "failures": failures + ["enhanced_inputs_build"],
            "checks": checks,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return 1

    # The on-disk pack must be exactly what this code rebuilds.
    disk_units_path = args.inputs_dir / "units.jsonl"
    disk_manifest_path = args.inputs_dir / "manifest.json"
    disk_sha = None
    disk_ok = False
    disk_detail: dict[str, Any] = {"path": str(disk_units_path)}
    if disk_units_path.is_file() and disk_manifest_path.is_file():
        disk_sha = sha256_bytes(disk_units_path.read_bytes())
        disk_manifest = json.loads(disk_manifest_path.read_text(encoding="utf-8"))
        disk_units = read_jsonl(disk_units_path)
        disk_ok = (
            disk_sha == disk_manifest.get("units_sha256") == manifest["units_sha256"]
            and disk_units == units
        )
        disk_detail.update(
            {
                "sha256": disk_sha,
                "manifest_sha256": disk_manifest.get("units_sha256"),
                "rebuilt_sha256": manifest["units_sha256"],
                "units_equal": disk_units == units,
            }
        )
    gate("inputs_pack_on_disk", disk_ok, disk_detail)

    mode_counts = manifest["enhanced_mode_counts"]
    tool = manifest["enhanced_tool"]
    gate(
        "enhanced_tool_confusion",
        tool["confusion"] == EXPECTED_TOOL_CONFUSION
        and tool["newly_observable_units"]
        and len(tool["newly_observable_units"]) == 12
        and mode_counts["default"]["applicable"] == 140
        and mode_counts["default"]["leak"] == 58
        and mode_counts["realloc_fail"]["applicable"] == 14
        and mode_counts["realloc_fail"]["leak"] == 7
        and mode_counts["realloc_fail"]["not_applicable"] == 126
        and mode_counts["nogobal"]["applicable"] == 140
        and mode_counts["nogobal"]["leak"] == 63
        and mode_counts["nogobal"]["leak_good"] == 0,
        {
            "confusion": tool["confusion"],
            "mode_counts": mode_counts,
            "newly_observable": len(tool["newly_observable_units"]),
        },
    )
    gate(
        "enhanced_evidence_audit",
        manifest["evidence"]["distinct_texts"] > 0
        and manifest["evidence"]["forbidden_markers"] == 0
        and all(u["enhanced_evidence_chars"] > 200 for u in units),
        manifest["evidence"],
    )

    # 4. Direct prompts reproduce the frozen v2 prompts exactly.
    v2_direct = {}
    for model in MODELS:
        path = V2_RUNS / f"hybrid_v2_{model}_direct" / "results.jsonl"
        v2_direct[model] = {r["unit_id"]: r for r in read_jsonl(path)}
    direct_mismatch = []
    direct_version_mismatch = []
    for unit in units:
        messages, meta = hde_prompts.build_direct(unit)
        for model in MODELS:
            stored = v2_direct[model].get(unit["unit_id"])
            if stored is None or stored["prompt"]["prompt_sha256"] != meta["prompt_sha256"]:
                direct_mismatch.append([unit["unit_id"], model])
            if stored is not None and stored["prompt"].get("prompt_version") != DIRECT_PROMPT_VERSION:
                direct_version_mismatch.append([unit["unit_id"], model, stored["prompt"].get("prompt_version")])
    gate(
        "direct_prompt_identity",
        not direct_mismatch and not direct_version_mismatch,
        {
            "checked": len(units) * len(MODELS),
            "mismatch": direct_mismatch[:5],
            "version_mismatch": direct_version_mismatch[:5],
        },
    )

    template_equal = hde_prompts.EVIDENCE_TEMPLATE == getattr(v2_prompts, "_EVIDENCE_TEMPLATE", None)
    gate(
        "evidence_template_identity",
        template_equal,
        {"hde_template_sha256": hashlib.sha256(hde_prompts.EVIDENCE_TEMPLATE.encode()).hexdigest()},
    )

    # 5. Guided prompts: 140 unique, evidence present once, no forbidden token.
    guided_hashes = []
    guided_chars = []
    guided_errors: list[str] = []
    for unit in units:
        try:
            messages, meta = hde_prompts.build_guided(unit)
        except Exception as exc:  # noqa: BLE001
            guided_errors.append(f"{unit['unit_id']}: {type(exc).__name__}: {exc}")
            continue
        if meta["prompt_version"] != GUIDED_PROMPT_VERSION or meta["method"] != METHOD:
            guided_errors.append(f"{unit['unit_id']}: bad prompt metadata")
        guided_hashes.append(meta["prompt_sha256"])
        guided_chars.append(sum(len(m["content"]) for m in messages))
    gate(
        "guided_prompt_audit",
        not guided_errors and len(guided_hashes) == EXPECTED_UNITS and len(set(guided_hashes)) == EXPECTED_UNITS,
        {
            "prompts": len(guided_hashes),
            "unique": len(set(guided_hashes)),
            "chars_min": min(guided_chars) if guided_chars else None,
            "chars_max": max(guided_chars) if guided_chars else None,
            "errors": guided_errors[:5],
        },
    )

    # 6. Frozen v2 baselines used for every comparison.
    baseline_detail: dict[str, Any] = {}
    baseline_ok = True
    for model in MODELS:
        for method in V2_METHODS:
            run_dir = V2_RUNS / f"hybrid_v2_{model}_{method}"
            results_path = run_dir / "results.jsonl"
            manifest_path = run_dir / "manifest.json"
            config_path = run_dir / "config.json"
            if not results_path.is_file():
                baseline_ok = False
                baseline_detail[f"{model}/{method}"] = "missing"
                continue
            records = read_jsonl(results_path)
            run_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            run_config = json.loads(config_path.read_text(encoding="utf-8"))
            entry = {
                "records": len(records),
                "unique": len({r["unit_id"] for r in records}),
                "ok": sum(1 for r in records if r["status"] == "ok"),
                "prompt_version": run_config.get("prompt_version"),
                "input_sha": (run_config.get("dataset") or {}).get("sha256"),
            }
            baseline_detail[f"{model}/{method}"] = entry
            if (
                entry["records"] != EXPECTED_UNITS
                or entry["unique"] != EXPECTED_UNITS
                or entry["ok"] != EXPECTED_UNITS
                or entry["prompt_version"] != DIRECT_PROMPT_VERSION
                or entry["input_sha"] != v2_sha
            ):
                baseline_ok = False
    gate("v2_baselines", baseline_ok, baseline_detail)

    # 7. Credential presence and optional live smoke.
    key_ok = False
    key_error = None
    try:
        key = load_api_key()
        key_ok = bool(key)
    except SystemExit as exc:
        key_error = str(exc)
    gate("credentials", key_ok, {"provider": "opencode-go", "present": key_ok, "error": key_error})

    smoke_detail: dict[str, Any] = {}
    if args.smoke:
        smoke_messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Audit the code unit below and return the verdict.\n\n"
                    "```c\nint main(void) { return 0; }\n```\n\n"
                    "Return only the JSON object."
                ),
            },
        ]
        smoke_ok = True
        for model in MODELS:
            spec = api_config(model)
            network = ensure_direct_network(spec.base_url)
            try:
                from secvul_runner.client import ChatClient

                with ChatClient(spec, key) as client:
                    call = client.complete(smoke_messages)
                try:
                    parsed = parse_verdict(call.content)
                    schema_ok = True
                except SchemaError as exc:
                    parsed = {"error": str(exc)}
                    schema_ok = False
                smoke_detail[model] = {
                    "status": call.status,
                    "http_status": call.http_status,
                    "schema_ok": schema_ok,
                    "label": parsed.get("label"),
                    "attempts": len(call.attempts),
                    "latency_seconds": round(call.wall_seconds, 3),
                    "usage": call.usage,
                    "cost_usd": (call.cost or {}).get("cost_usd"),
                    "network": network,
                }
                smoke_ok = smoke_ok and call.status == "ok" and schema_ok
            except Exception as exc:  # noqa: BLE001
                smoke_detail[model] = {"error": f"{type(exc).__name__}: {exc}"}
                smoke_ok = False
        gate("live_smoke", smoke_ok, smoke_detail)

    if args.run_id:
        collisions = sorted(
            str(path.relative_to(ROOT))
            for path in RUNS_DIR.glob(f"{args.run_id}_*")
        ) if RUNS_DIR.is_dir() else []
        gate("run_id_free", not collisions, {"run_id": args.run_id, "collisions": collisions})

    report = {
        "ok": not failures,
        "generated_at": utc_now(),
        "method": METHOD,
        "prompt_version": GUIDED_PROMPT_VERSION,
        "direct_prompt_version": DIRECT_PROMPT_VERSION,
        "input_pack": {
            "path": str((args.inputs_dir / "units.jsonl").relative_to(ROOT)),
            "units_sha256": disk_sha,
            "units": len(units),
        },
        "evidence": manifest["evidence"],
        "enhanced_tool": tool,
        "enhanced_mode_counts": mode_counts,
        "guided_prompts": {
            "prompts": len(guided_hashes),
            "unique": len(set(guided_hashes)),
            "chars_min": min(guided_chars) if guided_chars else None,
            "chars_max": max(guided_chars) if guided_chars else None,
        },
        "checks": checks,
        "failures": failures,
        "smoke": smoke_detail,
        "credentials": "presence checked; value never read into the report",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("ok", "failures", "prompt_version", "enhanced_tool")}, indent=2))
    print(f"wrote {args.out.relative_to(ROOT)}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

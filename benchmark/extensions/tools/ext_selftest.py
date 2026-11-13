#!/usr/bin/env python3
"""Self-test for the extension layer.

All fixtures are synthetic and are created under a temporary directory. The
test exercises the real CLI functions end-to-end:

    raw -> ext_import -> canonical run(s) -> ext_validate -> ext_metrics

It also checks parent compatibility with ``bench_validate.validate_run`` and
the secret-field guard. It never calls a model, network or analyzer and writes
nothing under ``benchmark/results``.
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))

from ext_common import (  # noqa: E402
    ExtensionError,
    check_no_secret_fields,
    sha256_text,
)
from ext_import import main as import_main  # noqa: E402
from ext_metrics import main as metrics_main  # noqa: E402
from ext_validate import main as validate_main  # noqa: E402
from bench_validate import validate_run  # noqa: E402


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )


def _close(actual: Any, expected: float, label: str, tolerance: float = 1e-9) -> None:
    if actual is None or not isinstance(actual, (int, float)) or math.isnan(float(actual)):
        raise AssertionError(f"{label}: expected {expected}, got {actual}")
    if abs(float(actual) - expected) > tolerance:
        raise AssertionError(f"{label}: expected {expected}, got {actual}")


def _approx(actual: Any, expected: float, label: str, tolerance: float = 1e-9) -> None:
    _close(actual, expected, label, tolerance)


def _model_method() -> dict[str, Any]:
    return {
        "method_id": "llm.selftest.direct",
        "family": "llm",
        "name": "Synthetic selftest LLM / direct",
        "strategy": "direct",
        "model": {
            "model_id": "selftest-model",
            "family": "selftest",
            "provider": "synthetic",
            "endpoint": None,
            "version": "0",
            "decoding": {"temperature": 0.0, "max_tokens": 128},
        },
    }


def _dynamic_method() -> dict[str, Any]:
    return {
        "method_id": "dynamic.selftest.asan",
        "family": "dynamic",
        "name": "Synthetic selftest ASan/LSan",
        "tool": {
            "name": "ASan+LSan",
            "version": "selftest-0",
            "command_template": "cc -fsanitize=address ...",
            "rules": [],
            "license": "synthetic",
        },
    }


def _static_method() -> dict[str, Any]:
    return {
        "method_id": "static.selftest.cppcheck",
        "family": "static",
        "name": "Synthetic selftest Cppcheck",
        "tool": {
            "name": "Cppcheck",
            "version": "2.21.0",
            "command_template": "cppcheck --enable=warning ...",
            "rules": ["memleak"],
            "license": "GPL-3.0-or-later",
        },
    }


def _pair_split(path: Path) -> None:
    lengths = {
        "p1": (100, 50),
        "p2": (50, 100),
        "p3": (60, 60),
        "p4": (100, 50),
    }
    pairs = []
    for pair_id, (v_len, f_len) in lengths.items():
        pairs.append(
            {
                "pair_id": pair_id,
                "vulnerable": {
                    "idx": int(pair_id[1:]),
                    "project": f"proj-{pair_id}",
                    "func_body": "v" * v_len,
                    "cwe_list": ["CWE-401"],
                },
                "fixed": {
                    "idx": 100 + int(pair_id[1:]),
                    "project": f"proj-{pair_id}",
                    "func_body": "f" * f_len,
                },
            }
        )
    _write_json(path, {"metadata": {"dataset_type": "pairs", "pair_count": len(pairs)}, "pairs": pairs})


def _position_raw(path: Path) -> None:
    pm_ab = {"A": "vulnerable", "B": "fixed"}
    pm_ba = {"A": "fixed", "B": "vulnerable"}
    rows = []

    def add(pair_id: str, order: str, choice: str) -> None:
        rows.append(
            {
                "design": "position_debiased_pair",
                "pair_id": pair_id,
                "presentation_order": order,
                "choice": choice,
                "position_map": pm_ab if order == "AB" else pm_ba,
                "status": "ok",
                "confidence": 0.7,
                "prompt_sha256": sha256_text(f"{pair_id}:{order}"),
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "latency_ms": 12.0},
                "cost": {"cost_usd": 0.0001, "cost_basis": "input_output_prices"},
                "parsed": {"confidence": 0.7, "rationale": "synthetic selftest"},
            }
        )

    add("p1", "AB", "A")
    add("p1", "BA", "B")
    add("p2", "AB", "A")
    add("p2", "BA", "A")
    add("p3", "AB", "B")
    add("p3", "BA", "B")
    add("p4", "AB", "B")
    add("p4", "BA", "A")
    _write_jsonl(path, rows)


def _open_raw(path: Path) -> None:
    rows = []
    choices = {"p1": "A", "p2": "B", "p3": "both", "p4": "neither"}
    for pair_id, choice in choices.items():
        rows.append(
            {
                "design": "open_choice_pair",
                "pair_id": pair_id,
                "open_choice": choice,
                "position_map": {"A": "vulnerable", "B": "fixed"},
                "status": "ok",
                "confidence": 0.6,
                "prompt_sha256": sha256_text(f"open:{pair_id}"),
                "usage": {"prompt_tokens": 100, "completion_tokens": 10},
                "cost": {"cost_usd": 0.0001, "cost_basis": "input_output_prices"},
                "parsed": {"open_choice": choice, "confidence": 0.6, "rationale": "synthetic selftest"},
            }
        )
    _write_jsonl(path, rows)


def _evidence_fixture(claims_path: Path, raw_path: Path) -> None:
    definitions = [
        ("c1", "supported", "genuine", "proj-1"),
        ("c2", "supported", "genuine", "proj-1"),
        ("c3", "unsupported", "counterfactual", "proj-2"),
        ("c4", "unsupported", "counterfactual", "proj-2"),
    ]
    claims = []
    for claim_id, gold, claim_type, cluster in definitions:
        text = f"Synthetic claim {claim_id}: the cited line is the allocation site."
        claims.append(
            {
                "claim_id": claim_id,
                "tier": "A",
                "track": "secvuleval",
                "split": "test",
                "source_unit_id": f"secvul:det:{claim_id}",
                "cluster_id": cluster,
                "gold_verdict": gold,
                "claim_type": claim_type,
                "claim_text": text,
                "claim_text_sha256": sha256_text(text),
                "source_sha256": sha256_text(f"source:{claim_id}"),
                "cwe": ["CWE-401"],
                "cited_lines": [10, 11],
                "mechanism": "synthetic",
                "notes": "synthetic selftest claim; not an experimental claim set",
            }
        )
    _write_json(
        claims_path,
        {
            "schema_version": "benchmark-evidence-claims-v1",
            "dataset_id": "selftest-evidence-claims",
            "split_id": "test",
            "created_at": "2026-11-13T00:00:00Z",
            "frozen": True,
            "construction_rule": "Synthetic selftest only; positives and counterfactuals are declared, not sampled.",
            "label_source": "manual",
            "claims": claims,
        },
    )
    verdicts = {
        "c1": "supported",
        "c2": "unsupported",
        "c3": "unsupported",
        "c4": "insufficient",
    }
    rows = []
    for claim_id, verdict in verdicts.items():
        rows.append(
            {
                "design": "evidence_verification",
                "claim_id": claim_id,
                "verdict": verdict,
                "confidence": 0.8 if verdict != "insufficient" else 0.2,
                "status": "ok",
                "prompt_sha256": sha256_text(f"verify:{claim_id}"),
                "usage": {"prompt_tokens": 80, "completion_tokens": 8},
                "cost": {"cost_usd": 0.00005, "cost_basis": "input_output_prices"},
                "parsed": {"verdict": verdict, "confidence": 0.8, "rationale": "synthetic selftest"},
            }
        )
    _write_jsonl(raw_path, rows)


def _fault_fixture(fault_path: Path, raw_path: Path) -> None:
    faults = [
        ("f1", "juliet:g1:bad", "inject_leak_good_path", "leak", "fam-1"),
        ("f2", "juliet:g2:bad", "inject_leak_good_path", "leak", "fam-2"),
        ("f3", "juliet:g3:good", "mask_leak_early_exit", "clean", "fam-3"),
        ("f4", "juliet:g4:good", "still_reachable_global", "clean", "fam-4"),
        ("f5", "juliet:g5:good", "mask_leak_early_exit", "clean", "fam-5"),
        ("f6", "juliet:g6:good", "harness_early_exit", "inconclusive", "fam-6"),
    ]
    fault_records = []
    for fault_id, base, fault_type, expected, cluster in faults:
        fault_records.append(
            {
                "fault_id": fault_id,
                "base_unit_id": base,
                "fault_type": fault_type,
                "expected_outcome": expected,
                "cluster_id": cluster,
                "split": "test",
                "description": "synthetic selftest fault",
                "injection_sha256": sha256_text(f"injection:{fault_id}"),
                "source_sha256": sha256_text(f"source:{fault_id}"),
                "baseline_outcome": "leak" if expected == "leak" else "clean",
                "oracle_required": True,
                "seed": "selftest",
                "notes": "synthetic selftest",
            }
        )
    _write_json(
        fault_path,
        {
            "schema_version": "benchmark-fault-injection-v1",
            "dataset_id": "selftest-fault-injection",
            "split_id": "test",
            "created_at": "2026-11-13T00:00:00Z",
            "frozen": True,
            "injection_protocol": "Synthetic selftest only; each injection is declared in this manifest before observation.",
            "faults": fault_records,
        },
    )
    observed = {
        "f1": ("leak", 1.0, "ok"),
        "f2": ("clean", 0.9, "ok"),
        "f3": ("clean", 0.9, "ok"),
        "f4": ("leak", 1.0, "ok"),
        "f5": ("clean", 0.2, "ok"),
        "f6": ("inconclusive", 0.0, "ok"),
    }
    rows = []
    for fault_id, (outcome, coverage, status) in observed.items():
        rows.append(
            {
                "design": "fault_injected_dynamic",
                "fault_id": fault_id,
                "observed_outcome": outcome,
                "status": status,
                "coverage": {
                    "unit_executed": True,
                    "target_function_entered": True,
                    "line_coverage": coverage,
                    "coverage_source": "gcov",
                },
                "oracle": {
                    "dynamic_consensus": "leak" if outcome == "leak" else "clean",
                    "lsan": "leak" if outcome == "leak" else "clean",
                    "valgrind": "leak" if outcome == "leak" else "clean",
                    "mismatch": False,
                },
                "baseline_outcome": "leak" if fault_id in ("f1", "f2") else "clean",
                "usage": {"latency_ms": 5.0},
                "cost": {"wall_s": 0.01, "cost_basis": "local_compute"},
                "parsed": {},
            }
        )
    _write_jsonl(raw_path, rows)


def _static_fixture(unit_map: Path, raw_path: Path) -> None:
    units = [
        ("CWE401_Memory_Leak__u1", "bad", "fam-1", "u1_bad.c"),
        ("CWE401_Memory_Leak__u2", "bad", "fam-2", "u2_bad.c"),
        ("CWE401_Memory_Leak__u3", "good", "fam-3", "u3_good.c"),
        ("CWE401_Memory_Leak__u4", "good", "fam-4", "u4_good.c"),
    ]
    unit_records = []
    for group, label, family, filename in units:
        unit_records.append(
            {
                "unit_id": f"{group}__{label}",
                "group_id": group,
                "label": label,
                "variant": "01",
                "family": family,
                "split": "test",
                "language": "c",
                "defines": ["INCLUDEMAIN", "OMITGOOD" if label == "bad" else "OMITBAD"],
                "sources": [f"raw/testcases/CWE401_Memory_Leak/{filename}"],
            }
        )
    _write_jsonl(unit_map, unit_records)

    def diagnostic(rule: str, severity: str, filename: str, line: int, cwe: list[str]) -> dict[str, Any]:
        return {
            "rule_id": rule,
            "severity": severity,
            "message": f"synthetic {rule}",
            "file": f"raw/testcases/CWE401_Memory_Leak/{filename}",
            "line": line,
            "column": 5,
            "cwe": cwe,
        }

    rows = [
        {
            "design": "new_static_tool",
            "sample_id": "CWE401_Memory_Leak__u1__bad",
            "status": "ok",
            "diagnostics": [diagnostic("memleak", "error", "u1_bad.c", 10, ["CWE-401"])],
            "duration_seconds": 0.1,
        },
        {
            "design": "new_static_tool",
            "sample_id": "CWE401_Memory_Leak__u2__bad",
            "status": "ok",
            "diagnostics": [diagnostic("memleak", "note", "u2_bad.c", 11, ["CWE-401"])],
            "duration_seconds": 0.1,
        },
        {
            "design": "new_static_tool",
            "sample_id": "CWE401_Memory_Leak__u3__good",
            "status": "ok",
            "diagnostics": [],
            "duration_seconds": 0.1,
        },
        {
            "design": "new_static_tool",
            "sample_id": "CWE401_Memory_Leak__u4__good",
            "status": "ok",
            "diagnostics": [diagnostic("unrelated-rule", "warning", "u4_good.c", 12, [])],
            "duration_seconds": 0.1,
        },
    ]
    _write_jsonl(raw_path, rows)


def _load_metrics(path: Path) -> dict[str, Any]:
    return json.loads((path / "metrics.json").read_text(encoding="utf-8"))


def _expect_ok(code: int, label: str) -> None:
    if code != 0:
        raise AssertionError(f"{label}: CLI returned {code}")


def run(temp: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    pair_split = temp / "pairs.json"
    _pair_split(pair_split)

    # --- position-debiased pair -------------------------------------------
    position_raw = temp / "raw_position.jsonl"
    _position_raw(position_raw)
    position_out = temp / "position"
    position_config = {
        "run_id": "selftest_position",
        "tier": "A",
        "track": "secvuleval",
        "pair_split": str(pair_split),
        "method": _model_method(),
        "raw": str(position_raw),
        "out": str(position_out),
        "include_rationale": True,
    }
    position_config_path = temp / "config_position.json"
    _write_json(position_config_path, position_config)
    _expect_ok(
        import_main(["--design", "position_debiased_pair", "--config", str(position_config_path), "--jsonschema"]),
        "position import",
    )
    retry = import_main(
        ["--design", "position_debiased_pair", "--config", str(position_config_path), "--jsonschema"]
    )
    if retry == 0:
        raise AssertionError("position import overwrote an existing output without --force")
    _expect_ok(validate_main(["--run-dir", str(position_out), "--jsonschema"]), "position validate")
    _expect_ok(metrics_main(["--run-dir", str(position_out), "--bootstrap", "200"]), "position metrics")
    position_metrics = _load_metrics(position_out)
    _approx(position_metrics["primary"]["value"], 0.5, "position position_avg_pair_da")
    _approx(position_metrics["metrics"]["order_consensus_pair_da"]["value"], 0.25, "position consensus")
    _approx(position_metrics["metrics"]["order_consistency"]["value"], 0.5, "position consistency")
    _approx(position_metrics["metrics"]["slot_accuracy_A"]["value"], 0.5, "position slot A")
    _approx(position_metrics["metrics"]["slot_accuracy_B"]["value"], 0.5, "position slot B")
    _approx(position_metrics["metrics"]["position_bias_index"]["value"], 0.0, "position bias")
    _approx(position_metrics["metrics"]["flip_to_correct"]["value"], 0.25, "position flip to correct")
    _approx(position_metrics["metrics"]["flip_to_wrong"]["value"], 0.25, "position flip to wrong")
    _approx(position_metrics["metrics"]["length_audit"]["length_only_da"]["value"], 0.6666666666666666, "position length heuristic")
    _expect_ok(validate_main(["--run-dir", str(position_out / "order_ab"), "--jsonschema"]), "position AB validate")
    parent = validate_run(position_out / "order_ab")
    if parent["errors"]:
        raise AssertionError(f"parent validator errors: {parent['errors'][:3]}")
    results["position"] = position_metrics["primary"]

    # --- open-choice pair ---------------------------------------------------
    open_raw = temp / "raw_open.jsonl"
    _open_raw(open_raw)
    open_out = temp / "open"
    open_config = {
        "run_id": "selftest_open",
        "tier": "A",
        "track": "secvuleval",
        "pair_split": str(pair_split),
        "method": _model_method(),
        "raw": str(open_raw),
        "out": str(open_out),
        "include_rationale": True,
    }
    open_config_path = temp / "config_open.json"
    _write_json(open_config_path, open_config)
    _expect_ok(
        import_main(["--design", "open_choice_pair", "--config", str(open_config_path), "--jsonschema"]),
        "open import",
    )
    _expect_ok(validate_main(["--run-dir", str(open_out), "--jsonschema"]), "open validate")
    _expect_ok(metrics_main(["--run-dir", str(open_out), "--bootstrap", "200"]), "open metrics")
    open_metrics = _load_metrics(open_out)
    _approx(open_metrics["primary"]["value"], 0.25, "open pair_da")
    _approx(open_metrics["metrics"]["decisive_rate"]["value"], 0.5, "open decisive_rate")
    _approx(open_metrics["metrics"]["pair_da_decisive"]["value"], 0.5, "open pair_da_decisive")
    _approx(open_metrics["metrics"]["both_rate"]["value"], 0.25, "open both_rate")
    _approx(open_metrics["metrics"]["neither_rate"]["value"], 0.25, "open neither_rate")
    results["open"] = open_metrics["primary"]

    # --- evidence verification ---------------------------------------------
    claims_path = temp / "claims.json"
    evidence_raw = temp / "raw_evidence.jsonl"
    _evidence_fixture(claims_path, evidence_raw)
    evidence_out = temp / "evidence"
    evidence_config = {
        "run_id": "selftest_evidence",
        "tier": "A",
        "track": "secvuleval",
        "claim_manifest": str(claims_path),
        "method": _model_method(),
        "raw": str(evidence_raw),
        "out": str(evidence_out),
    }
    evidence_config_path = temp / "config_evidence.json"
    _write_json(evidence_config_path, evidence_config)
    _expect_ok(
        import_main(["--design", "evidence_verification", "--config", str(evidence_config_path), "--jsonschema"]),
        "evidence import",
    )
    _expect_ok(validate_main(["--run-dir", str(evidence_out), "--jsonschema"]), "evidence validate")
    _expect_ok(metrics_main(["--run-dir", str(evidence_out), "--bootstrap", "200"]), "evidence metrics")
    evidence_metrics = _load_metrics(evidence_out)
    scores = evidence_metrics["metrics"]["detection"]["scores"]
    _approx(scores["precision"], 1.0, "evidence precision")
    _approx(scores["recall"], 0.5, "evidence recall")
    _approx(scores["specificity"], 1.0, "evidence specificity")
    _approx(scores["coverage"], 0.75, "evidence coverage")
    _approx(scores["strict_accuracy"], 0.5, "evidence strict accuracy")
    _approx(evidence_metrics["metrics"]["false_support_rate"]["value"], 0.0, "evidence false support")
    _approx(evidence_metrics["metrics"]["false_reject_rate"]["value"], 0.5, "evidence false reject")
    _approx(evidence_metrics["metrics"]["abstention_rate"]["value"], 0.25, "evidence abstention")
    results["evidence"] = evidence_metrics["primary"]

    # --- fault-injected dynamic --------------------------------------------
    fault_path = temp / "faults.json"
    fault_raw = temp / "raw_fault.jsonl"
    _fault_fixture(fault_path, fault_raw)
    fault_out = temp / "fault"
    fault_config = {
        "run_id": "selftest_fault",
        "tier": "B",
        "track": "juliet_cwe401",
        "fault_manifest": str(fault_path),
        "method": _dynamic_method(),
        "raw": str(fault_raw),
        "out": str(fault_out),
        "coverage_threshold": 0.8,
    }
    fault_config_path = temp / "config_fault.json"
    _write_json(fault_config_path, fault_config)
    _expect_ok(
        import_main(["--design", "fault_injected_dynamic", "--config", str(fault_config_path), "--jsonschema"]),
        "fault import",
    )
    _expect_ok(validate_main(["--run-dir", str(fault_out), "--jsonschema"]), "fault validate")
    _expect_ok(metrics_main(["--run-dir", str(fault_out), "--bootstrap", "200"]), "fault metrics")
    fault_metrics = _load_metrics(fault_out)
    _approx(fault_metrics["primary"]["value"], 0.5, "fault balanced accuracy")
    _approx(fault_metrics["metrics"]["fault_sensitivity"]["value"], 0.5, "fault sensitivity")
    _approx(fault_metrics["metrics"]["fault_specificity"]["value"], 0.5, "fault specificity")
    _approx(fault_metrics["metrics"]["fault_macro_f1"]["value"], 0.5, "fault macro f1")
    # Strict accuracy counts the low-coverage clean variant (f5) as an error,
    # so its denominator is 5 (expected leak/clean variants), not 4 valid.
    _approx(fault_metrics["metrics"]["strict_accuracy"]["value"], 0.4, "fault strict accuracy")
    if fault_metrics["counts"]["oracle_mismatch"] != 0:
        raise AssertionError("fault oracle mismatch should be 0 in the fixture")
    results["fault"] = fault_metrics["primary"]

    # --- new static tool ----------------------------------------------------
    unit_map = temp / "units.jsonl"
    static_raw = temp / "raw_static.jsonl"
    _static_fixture(unit_map, static_raw)
    static_out = temp / "static"
    static_config = {
        "run_id": "selftest_static",
        "tier": "B",
        "track": "juliet_cwe401",
        "unit_map": str(unit_map),
        "split": "test",
        "tool_id": "cppcheck",
        "method": _static_method(),
        "raw": str(static_raw),
        "out": str(static_out),
        "scope_kind": "target_file",
    }
    static_config_path = temp / "config_static.json"
    _write_json(static_config_path, static_config)
    _expect_ok(
        import_main(["--design", "new_static_tool", "--config", str(static_config_path), "--jsonschema"]),
        "static import",
    )
    _expect_ok(validate_main(["--run-dir", str(static_out), "--jsonschema"]), "static validate")
    _expect_ok(metrics_main(["--run-dir", str(static_out), "--bootstrap", "200"]), "static metrics")
    static_metrics = _load_metrics(static_out)
    scores = static_metrics["metrics"]["detection"]["scores"]
    _approx(scores["macro_f1"], 1.0, "static default macro f1")
    high = static_metrics["metrics"]["high_severity_sensitivity"]
    if not high["available"]:
        raise AssertionError("static high-severity view should be available")
    _approx(high["scores"]["macro_f1"], 0.7333333333333334, "static high macro f1")
    _approx(high["delta_macro_f1_vs_default"], -0.2666666666666666, "static high delta")
    results["static"] = static_metrics["primary"]

    # --- security guard -----------------------------------------------------
    try:
        check_no_secret_fields({"method": {"api_key": "should-not-be-saved"}})
    except ExtensionError:
        pass
    else:
        raise AssertionError("secret-field guard did not reject api_key")

    return results


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ext_selftest_") as directory:
        temp = Path(directory)
        try:
            results = run(temp)
        except Exception as exc:  # noqa: BLE001 - selftest should show the first failure
            sys.stderr.write(f"SELFTEST FAILED: {exc}\n")
            return 1
    sys.stdout.write("SELFTEST PASS\n")
    sys.stdout.write(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

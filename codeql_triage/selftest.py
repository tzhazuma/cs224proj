#!/usr/bin/env python3
"""No-network self-check for the CodeQL triage contract."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "runner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from codeql_triage.common import (  # noqa: E402
    ALERT_FALSE,
    ALERT_NONE,
    ALERT_TRUE,
    ALERT_UNCERTAIN,
    build_direct_messages,
    build_triage_messages,
    metrics,
    merge_units,
    parse_direct,
    parse_triage,
    sha256_text,
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    units = merge_units()
    check(len(units) == 140, "expected 140 test units")
    check(sum(unit["y_true"] for unit in units) == 70, "expected 70 bad units")
    codeql_tp = [unit for unit in units if unit["codeql"]["is_alert"] and unit["y_true"]]
    codeql_fp = [unit for unit in units if unit["codeql"]["is_alert"] and not unit["y_true"]]
    compile_errors = [unit for unit in units if unit["codeql"]["status"] != "ok"]
    codeql_fn = [unit for unit in units if not unit["codeql"]["is_alert"] and unit["y_true"]]
    check(len(codeql_tp) == 68, f"expected 68 CodeQL TPs, found {len(codeql_tp)}")
    check(len(codeql_fp) == 23, f"expected 23 CodeQL FPs, found {len(codeql_fp)}")
    check(len(compile_errors) == 4, f"expected 4 compile errors, found {len(compile_errors)}")
    check(len(codeql_fn) == 2, f"expected 2 CodeQL FNs, found {len(codeql_fn)}")
    check(
        all(unit["language"] == "cpp" for unit in codeql_fp),
        "all 23 CodeQL FPs should be C++",
    )
    check(
        all(unit["codeql"]["by_query"].get("cpp/memory-may-not-be-freed", 0) > 0 for unit in codeql_fp),
        "all 23 CodeQL FPs should carry the may-not-be-freed query",
    )

    prompt_hashes = set()
    for unit in units:
        for messages in (
            build_triage_messages(unit),
            build_triage_messages(unit, version="v2"),
            build_direct_messages(unit),
        ):
            joined = "\n".join(item["content"] for item in messages)
            check(unit["unit_id"] not in joined, f"{unit['unit_id']}: unit id in prompt")
            check(unit["group_id"] not in joined, f"{unit['unit_id']}: group id in prompt")
            check("CWE-401" not in joined, f"{unit['unit_id']}: defect id in prompt")
            prompt_hashes.add(sha256_text(joined))
    check(len(prompt_hashes) == 420, "v1, v2 and direct prompts should all be distinct")

    # The triage prompt must not expose the label through a path or the query's
    # family name; only the two generic query ids and line numbers are allowed.
    for unit in units:
        joined = "\n".join(item["content"] for item in build_triage_messages(unit))
        check("raw/testcases" not in joined, "path leaked")
        check("/mnt/" not in joined, "absolute path leaked")
        check("juliet/" not in joined, "dataset path leaked")

    # Parsing and evidence handling.
    good = parse_triage(
        json.dumps(
            {
                "alert_verdict": "false_positive",
                "leak_present": False,
                "allocation": "calloc at the only allocation is freed on every path",
                "ownership": "owner is the local pointer; no transfer",
                "aliasing": "reference aliases the same local pointer",
                "global_control_flow": "not_applicable",
                "cross_function_release": "free in the callee",
                "reason": "the reference is freed before return",
                "confidence": 0.9,
            }
        ),
        has_alert=True,
    )
    check(good["alert_verdict"] == ALERT_FALSE, "false_positive parse")
    check(good["leak_present"] is False, "leak_present parse")
    check(good["evidence_fields_supported"] == 4, "evidence count should ignore not_applicable")
    check(good["unsupported_drop"] is False, "supported drop should not be flagged")

    unsupported = parse_triage(
        json.dumps(
            {
                "alert_verdict": "false_positive",
                "leak_present": "uncertain",
                "allocation": "unsupported",
                "ownership": "unsupported",
                "aliasing": "unsupported",
                "global_control_flow": "unsupported",
                "cross_function_release": "unsupported",
                "reason": "cannot tell",
                "confidence": 0.2,
            }
        ),
        has_alert=True,
    )
    check(unsupported["unsupported_drop"] is True, "unsupported drop must be flagged")

    for bad_payload in (
        {"alert_verdict": "no_alert", "leak_present": True},
        {"alert_verdict": "true_positive", "leak_present": "maybe"},
    ):
        try:
            parse_triage(json.dumps(bad_payload), has_alert=True)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid payload accepted: {bad_payload}")

    try:
        parse_triage(json.dumps({"alert_verdict": "true_positive", "leak_present": True}), has_alert=False)
    except ValueError:
        pass
    else:
        raise AssertionError("alert verdict on a non-alerted unit should fail")

    no_alert_uncertain = parse_triage(
        json.dumps({"alert_verdict": "uncertain", "leak_present": True}), has_alert=False
    )
    check(no_alert_uncertain["alert_verdict"] == ALERT_UNCERTAIN, "uncertain on absent alert")

    no_alert = parse_triage(
        json.dumps(
            {
                "alert_verdict": "no_alert",
                "leak_present": "uncertain",
                "allocation": "new int",
                "ownership": "unsupported",
                "aliasing": "not_applicable",
                "global_control_flow": "not_applicable",
                "cross_function_release": "unsupported",
                "reason": "no release visible",
                "confidence": 0.5,
            }
        ),
        has_alert=False,
    )
    check(no_alert["alert_verdict"] == ALERT_NONE, "no_alert parse")

    direct = parse_direct(
        json.dumps({"label": "vulnerable", "confidence": 0.8, "reason": "not freed"})
    )
    check(direct["y_pred"] == 1, "direct positive parse")

    # Metrics sanity: a perfect classifier has macro-F1 1 and MCC 1; a constant
    # positive classifier on the frozen balance has MCC 0.
    perfect = metrics([0, 1, 0, 1], [0, 1, 0, 1])
    check(abs(perfect["macro_f1"] - 1.0) < 1e-12, "perfect macro-F1")
    check(abs(perfect["mcc"] - 1.0) < 1e-12, "perfect MCC")
    constant = metrics([0, 1, 0, 1], [1, 1, 1, 1])
    check(abs(constant["mcc"]) < 1e-12, "constant MCC")
    check(constant["precision"] == 0.5, "constant precision")

    # A synthetic policy trace: keep alert unless explicit false positive.
    synthetic = [
        {"y_true": 1, "codeql_alert": 1, "alert_verdict": ALERT_TRUE, "valid": True},
        {"y_true": 1, "codeql_alert": 1, "alert_verdict": ALERT_FALSE, "valid": True},
        {"y_true": 0, "codeql_alert": 1, "alert_verdict": ALERT_FALSE, "valid": True},
        {"y_true": 0, "codeql_alert": 1, "alert_verdict": ALERT_UNCERTAIN, "valid": True},
        {"y_true": 1, "codeql_alert": 0, "alert_verdict": ALERT_NONE, "valid": True},
    ]
    keep = [
        int(row["codeql_alert"])
        if not row["valid"]
        else (int(row["alert_verdict"] != ALERT_FALSE) if row["codeql_alert"] else 0)
        for row in synthetic
    ]
    check(keep == [1, 0, 0, 1, 0], f"policy trace mismatch: {keep}")

    # No secret-looking strings in the static prompt.
    all_prompts = "\n".join(
        item["content"] for unit in units for item in build_triage_messages(unit)
    )
    check("sk-" not in all_prompts, "secret-like token in prompt")
    check("Bearer " not in all_prompts, "authorization token in prompt")

    print(
        f"all checks passed: {len(units)} units, "
        f"{len(codeql_tp)} CodeQL TP, {len(codeql_fp)} CodeQL FP, "
        f"{len(compile_errors)} compile_error, {len(prompt_hashes)} distinct prompts"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

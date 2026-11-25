#!/usr/bin/env python3
"""Read-only release audit of the 2026-11-22 next-iteration results.

Covers codeql_triage (test 140, 23 FP, TP-deletion audit), pair_diff
(8 full runs / 1,440 records), verifier_conservative (236 requests),
dynamic_coverage (140 units x 3 modes) and interpretable_baseline
(dev40 -> test160 isolation), plus prompt leakage, cost accounting,
preservation of the older results and report/benchmark consistency.

No model or network call is made.  Only audit/next_iteration_audit.json and
audit/next_iteration_audit.md are written.
"""

from __future__ import annotations

import argparse
import ast
import collections
import datetime as _dt
import hashlib
import json
import math
import os
import re
import statistics
import sys
from pathlib import Path

sys.dont_write_bytecode = True

SCHEMA_VERSION = "next-iteration-audit-2026-11-22.1"
ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "audit"
JSON_PATH = AUDIT_DIR / "next_iteration_audit.json"
MD_PATH = AUDIT_DIR / "next_iteration_audit.md"

# Frozen paths.
JULIET_TEST = "juliet_llm/build/test.jsonl"
JULIET_SUBSET = "juliet/subset_units.jsonl"
JULIET_FREEZE = "juliet/FREEZE.json"
CODEQL_PRED = "static_extended/runs/codeql_20261114_cwe401_full/predictions.jsonl"
CODEQL_RUN_V1 = "codeql_triage/runs/test140_mimo_xiaomi_v1"
CODEQL_RUN_V2 = "codeql_triage/runs/test140_mimo_xiaomi_v2"
CODEQL_EXPORT = "codeql_triage/benchmark_export.json"
PAIR_DATASET = "splits/test_pairs_180.json"
PAIR_RUNS = "pair_diff/runs"
PAIR_EXPORT = "pair_diff/results/benchmark_export.json"
CONS_RUNS = "verifier_conservative/runs"
COV_RUN = "dynamic_coverage/runs/test140_coverage_v1"
INT_RUN = "interpretable_baseline/results/main_20261122c"
REPORT_MD = "report/next_results_summary.md"
REPORT_TEX = "report/report_next_zh.tex"
REPORT_PDF = "report/report_next_zh.pdf"

# Published next-iteration aggregate (written by the benchmark pass).
BENCH_SUMMARY = "benchmark/results/next_iteration_summary.json"
BENCH_NEXT_MD = "benchmark/results/NEXT_ITERATION.md"
PAIR_REPORT = "pair_diff/results/report.md"
PUBLICATION_PATHS = (
    "audit/next_iteration_audit.md",
    "audit/next_iteration_audit.json",
    BENCH_NEXT_MD,
    BENCH_SUMMARY,
    PAIR_REPORT,
)


class AuditFailure(Exception):
    pass


def req(condition, message):
    if not condition:
        raise AuditFailure(str(message))


def eq(actual, expected, label):
    if actual != expected:
        raise AuditFailure(f"{label}: {actual!r} != {expected!r}")


def close(actual, expected, label, tol=1e-6):
    try:
        a, b = float(actual), float(expected)
    except (TypeError, ValueError) as exc:
        raise AuditFailure(f"{label}: non-numeric {actual!r}/{expected!r}") from exc
    if abs(a - b) > tol * max(1.0, abs(a), abs(b)):
        raise AuditFailure(f"{label}: {a!r} != {b!r}")


def jload(path):
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def jlines(path):
    rows = []
    with (ROOT / path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def text(path):
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def sha_file(path):
    digest = hashlib.sha256()
    with (ROOT / path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now_utc():
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def utc(ts):
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()


def metric(tp, fp, tn, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1p = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    neg_p = tn / (tn + fn) if tn + fn else 0.0
    f1n = 2 * neg_p * specificity / (neg_p + specificity) if neg_p + specificity else 0.0
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = (tp * tn - fp * fn) / math.sqrt(denom) if denom else 0.0
    n = tp + fp + tn + fn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": n,
        "precision": precision, "recall": recall, "specificity": specificity,
        "f1_positive": f1p, "f1_negative": f1n,
        "macro_f1": (f1p + f1n) / 2.0,
        "accuracy": (tp + tn) / n if n else 0.0,
        "balanced_accuracy": (recall + specificity) / 2.0,
        "mcc": mcc,
    }


def confusion(rows, key, label_key="y_true"):
    tp = fp = tn = fn = 0
    for row in rows:
        y = row[label_key]
        pred = bool(row[key])
        if y and pred:
            tp += 1
        elif y and not pred:
            fn += 1
        elif not y and pred:
            fp += 1
        else:
            tn += 1
    return metric(tp, fp, tn, fn)


def check(checks, cid, area, title, fn, warn_must_fix=False):
    try:
        status, detail, evidence = fn()
        req(status in {"PASS", "WARN", "FAIL", "INFO"}, f"bad status {status}")
    except AuditFailure as exc:
        status, detail, evidence = "FAIL", str(exc), {}
    except Exception as exc:  # noqa: BLE001
        status, detail, evidence = "FAIL", f"audit error: {type(exc).__name__}: {exc}", {}
    checks.append({
        "id": cid, "area": area, "title": title, "status": status,
        "detail": detail, "evidence": evidence,
        "must_fix": status == "FAIL" or (status == "WARN" and warn_must_fix),
    })


def ok(detail, **ev):
    return "PASS", detail, ev


def warn(detail, **ev):
    return "WARN", detail, ev


def info(detail, **ev):
    return "INFO", detail, ev


def pct(value, digits=4):
    return f"{value * 100:.{digits}f}%"


# ---------------------------------------------------------------------------
# Shared loaders
# ---------------------------------------------------------------------------

def codeql_units(version):
    return jlines(f"codeql_triage/runs/test140_mimo_xiaomi_v{version}/analysis/per_unit.jsonl")


def codeql_results(version, condition):
    return jlines(f"codeql_triage/runs/test140_mimo_xiaomi_v{version}/results_{condition}.jsonl")


def pair_runs():
    return sorted(p.name for p in (ROOT / PAIR_RUNS).glob("test_*") if p.is_dir())


def pair_rows(run):
    return jlines(f"{PAIR_RUNS}/{run}/results.jsonl")


def pair_manifest(run):
    return jload(f"{PAIR_RUNS}/{run}/manifest.json")


def pair_map(run):
    return jload(f"{PAIR_RUNS}/{run}/position_map.json")


def pair_correct(run):
    assignments = pair_map(run)["assignments"]
    decisions = {row["pair_id"]: (row.get("parsed") or {}).get("vulnerable_version")
                 for row in pair_rows(run)}
    return {pid for pid, item in assignments.items()
            if decisions.get(pid) == item["vulnerable_slot"]}


def cons_runs():
    return sorted(p.name for p in (ROOT / CONS_RUNS).glob("test_*") if p.is_dir())


def cons_rows(run):
    return jlines(f"{CONS_RUNS}/{run}/results.jsonl")


def codeql_cost(rows, input_price, output_price, cached_price):
    total = 0.0
    for row in rows:
        usage = row.get("usage") or {}
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        details = usage.get("prompt_tokens_details") or {}
        cached = int(details.get("cached_tokens") or 0)
        total += ((prompt - cached) * input_price + cached * cached_price
                  + completion * output_price) / 1_000_000.0
    return total


# ---------------------------------------------------------------------------
# A. codeql_triage
# ---------------------------------------------------------------------------

def audit_codeql(checks):
    def a1():
        manifest = jload(f"{CODEQL_RUN_V2}/manifest.json")
        rows = jlines(JULIET_TEST)
        eq(len(rows), 140, "juliet test units")
        labels = collections.Counter(row["label"] for row in rows)
        eq(dict(labels), {"bad": 70, "good": 70}, "juliet labels")
        languages = collections.Counter(row["language"] for row in rows)
        eq(dict(languages), {"c": 58, "cpp": 82}, "juliet languages")
        eq(sha_file(JULIET_TEST), manifest["dataset"]["test_sha256"], "juliet test hash")
        eq(sha_file(CODEQL_PRED), manifest["dataset"]["codeql_sha256"], "codeql predictions hash")
        eq(sha_file(JULIET_SUBSET), jload(JULIET_FREEZE)["subset_units_sha256"], "juliet subset hash")
        static = jlines(CODEQL_PRED)
        eq(len(static), 200, "static_extended units")
        test = [row for row in static if row["sample"]["split"] == "test"]
        eq(len(test), 140, "static test units")
        eq(dict(collections.Counter(row["label"] for row in test)), {True: 70, False: 70}, "static labels")
        status = collections.Counter(row["status"] for row in test)
        eq(dict(status), {"ok": 136, "compile_error": 4}, "codeql status")
        compile_ids = {row["sample_id"] for row in test if row["status"] == "compile_error"}
        expected = {
            "CWE401_Memory_Leak__new_twoIntsStruct_82__bad",
            "CWE401_Memory_Leak__new_twoIntsStruct_82__good",
            "CWE401_Memory_Leak__new_wchar_t_82__bad",
            "CWE401_Memory_Leak__new_wchar_t_82__good",
        }
        eq(compile_ids, expected, "compile_error units")
        return ok(
            "140 frozen units (70 bad / 70 good; C 58 / C++ 82); 136 analyzable, 4 _82 compile errors; hashes match.",
            units=140, labels={"bad": 70, "good": 70}, languages={"c": 58, "cpp": 82},
            compile_errors=sorted(compile_ids),
        )

    def a2():
        rows = codeql_units(2)
        m = confusion(rows, "codeql_alert")
        eq((m["tp"], m["fp"], m["tn"], m["fn"]), (68, 23, 47, 2), "codeql confusion")
        close(m["macro_f1"], 0.8173182316404822, "codeql macro-F1")
        close(m["mcc"], 0.6738973950355189, "codeql MCC")
        export = jload(CODEQL_EXPORT)
        eq(export["dataset"]["codeql_confusion"], {"tp": 68, "fp": 23, "tn": 47, "fn": 2}, "export confusion")
        for key in ("tp", "fp", "tn", "fn"):
            eq(export["conditions"]["codeql"]["metrics"][key], m[key], f"export {key}")
        close(export["conditions"]["codeql"]["metrics"]["macro_f1"], m["macro_f1"], "export macro-F1")
        close(export["conditions"]["codeql"]["metrics"]["mcc"], m["mcc"], "export MCC")
        eq(export["dataset"]["codeql_analyzable"], 136, "export analyzable")
        return ok(
            "CodeQL test140 confusion 68 TP / 23 FP / 47 TN / 2 FN; macro-F1 0.8173, MCC 0.6739; export matches.",
            confusion={"tp": 68, "fp": 23, "tn": 47, "fn": 2},
            macro_f1=m["macro_f1"], mcc=m["mcc"], coverage=136 / 140,
        )

    def a3():
        rows = codeql_units(2)
        fps = [row for row in rows if row["y_true"] == 0 and row["codeql_alert"]]
        eq(len(fps), 23, "codeql FP count")
        eq(dict(collections.Counter(row["language"] for row in fps)), {"cpp": 23}, "FP languages")
        eq(dict(collections.Counter(row["variant"] for row in fps)),
           {"33": 15, "22": 3, "72": 3, "54": 2}, "FP variants")
        req(all(row["codeql_may"] == 1 and row["codeql_never"] == 0 for row in fps),
            "a CodeQL FP is not a may-not-be-freed hit")
        triage = codeql_results(2, "triage")
        may_units = {
            row["unit_id"] for row in triage
            if (row.get("unit") or {}).get("codeql_by_query", {}).get("cpp/memory-may-not-be-freed", 0) > 0
        }
        req({row["unit_id"] for row in fps} <= may_units, "FP outside the may query")
        never_units = {
            row["unit_id"] for row in triage
            if (row.get("unit") or {}).get("codeql_by_query", {}).get("cpp/memory-never-freed", 0) > 0
        }
        eq(len(never_units & {row["unit_id"] for row in fps}), 0, "never-freed FP")
        export = jload(CODEQL_EXPORT)["fp23"]
        eq(export["n"], 23, "export fp23 n")
        eq({key: value["n"] for key, value in export["by_variant"].items()},
           {"22": 3, "33": 15, "54": 2, "72": 3}, "export fp23 variants")
        return ok(
            "All 23 CodeQL FPs are C++ good units on cpp/memory-may-not-be-freed (33:15, 22:3, 72:3, 54:2); never-freed has 0 FP.",
            variants={"33": 15, "22": 3, "72": 3, "54": 2}, language="cpp", query="cpp/memory-may-not-be-freed",
        )

    def a4():
        v1 = codeql_units(1)
        v2 = codeql_units(2)
        deleted_v1 = [row for row in v1 if row["y_true"] == 1 and row["codeql_alert"] and not row["triage_keep"]]
        eq(len(deleted_v1), 7, "v1 deleted TP")
        req(all("malloc_realloc" in row["unit_id"] for row in deleted_v1), "v1 deleted a non-realloc TP")
        req(all(row["codeql_may"] == 1 for row in deleted_v1), "v1 deleted a non-may TP")
        deleted_v2 = [row for row in v2 if row["y_true"] == 1 and row["codeql_alert"] and not row["triage_keep"]]
        eq(len(deleted_v2), 0, "v2 deleted TP")
        verified_deleted = [row for row in v2 if row["y_true"] == 1 and row["codeql_alert"] and not row["triage_verified"]]
        eq(len(verified_deleted), 0, "verified deleted TP")
        export = jload(CODEQL_EXPORT)["tp_deleted"]
        eq(export["codeql_tp"], 68, "export codeql TP")
        eq(export["v1_deleted"], 7, "export v1 deleted")
        eq(export["v2_deleted"], 0, "export v2 deleted")
        eq(export["verified_deleted"], 0, "export verified deleted")
        return ok(
            "v1 deleted 7 CodeQL TPs, all malloc_realloc may-query units; v2 and the verifier deleted 0/68.",
            v1_deleted=[row["unit_id"] for row in deleted_v1], v2_deleted=0, verified_deleted=0,
        )

    def a5():
        rows = codeql_units(2)
        keep = confusion(rows, "triage_keep")
        verified = confusion(rows, "triage_verified")
        text_rule = confusion(rows, "rule_text_consistency")
        eq((keep["tp"], keep["fp"], keep["tn"], keep["fn"]), (68, 3, 67, 2), "v2 one-shot")
        eq((verified["tp"], verified["fp"], verified["tn"], verified["fn"]), (68, 0, 70, 2), "v2 verified")
        eq((text_rule["tp"], text_rule["fp"], text_rule["tn"], text_rule["fn"]), (68, 0, 70, 2), "text rule")
        close(keep["macro_f1"], 0.9642838920353078, "one-shot macro-F1")
        close(verified["macro_f1"], 0.985711369667279, "verified macro-F1")
        close(verified["mcc"], 0.97182531580755, "verified MCC")
        flips = [row for row in rows if bool(row["triage_keep"]) != bool(row["triage_verified"])]
        eq(len(flips), 3, "verify flips")
        req(all(row["variant"] == "22" and row["y_true"] == 0 for row in flips), "verify flip outside _22 good")
        summary = jload(f"{CODEQL_RUN_V2}/analysis/summary.json")
        eq(summary["verify"]["flips"] and len(summary["verify"]["flips"]), 3, "summary flips")
        eq(summary["verify"]["broken_tp"], 0, "summary broken TP")
        eq(summary["verify"]["new_fp"], 0, "summary new FP")
        export = jload(CODEQL_EXPORT)["conditions"]
        close(export["triage_v2_oneshot"]["metrics"]["macro_f1"], keep["macro_f1"], "export one-shot")
        close(export["triage_v2_verified"]["metrics"]["macro_f1"], verified["macro_f1"], "export verified")
        return ok(
            "v2 one-shot 68/3/67/2 (0.9643); verifier flips exactly 3 _22 goods to 68/0/70/2 (0.9857, MCC 0.9718); no TP broken.",
            one_shot={"tp": 68, "fp": 3, "tn": 67, "fn": 2},
            verified={"tp": 68, "fp": 0, "tn": 70, "fn": 2},
            flips=[row["unit_id"] for row in flips],
        )

    def a6():
        direct = codeql_results(2, "direct")
        triage = codeql_results(2, "triage")
        verify = jlines(f"{CODEQL_RUN_V2}/verify/results_verify.jsonl")
        eq((len(direct), len(triage), len(verify)), (140, 140, 91), "request counts")
        eq(dict(collections.Counter(row["status"] for row in direct)), {"ok": 140}, "direct status")
        eq(dict(collections.Counter(row["status"] for row in triage)), {"ok": 140}, "triage status")
        eq(dict(collections.Counter(row["status"] for row in verify)), {"ok": 91}, "verify status")
        direct_ids = {row["unit_id"] for row in direct}
        triage_ids = {row["unit_id"] for row in triage}
        verify_ids = {row["unit_id"] for row in verify}
        eq(len(direct_ids), 140, "direct unique units")
        eq(direct_ids, triage_ids, "direct/triage unit sets")
        rows = codeql_units(2)
        alert_ids = {row["unit_id"] for row in rows if row["codeql_alert"]}
        eq(len(alert_ids), 91, "alert units")
        eq(verify_ids, alert_ids, "verify unit set")
        raw = collections.Counter(row["raw_triage_valid"] for row in rows)
        eq(dict(raw), {0: 2, 1: 138}, "raw triage validity")
        reparsed = {row["unit_id"] for row in rows if not row["raw_triage_valid"]}
        eq(reparsed, {
            "CWE401_Memory_Leak__new_twoIntsStruct_82__bad",
            "CWE401_Memory_Leak__new_wchar_t_82__bad",
        }, "reparsed units")
        eq(all(row["triage_valid"] for row in rows), True, "final triage validity")
        manifest = jload(f"{CODEQL_RUN_V2}/manifest.json")
        eq(manifest["conditions"]["direct"]["valid"], 140, "manifest direct valid")
        eq(manifest["conditions"]["triage"]["valid"], 138, "manifest triage valid")
        return ok(
            "140 direct + 140 triage + 91 verify requests; 2 triage outputs re-parsed under the clarified schema; final coverage 140/140.",
            direct=140, triage=140, verify=91, reparsed=sorted(reparsed),
        )

    def a7():
        forbidden = {
            "bad": r"(?i)bad", "good": r"(?i)good", "cwe": r"(?i)cwe",
            "memory_leak": r"(?i)memory[_ ]leak", "omit": r"(?i)omit",
            "flaw": r"(?i)flaw", "std_testcase": r"(?i)std_testcase",
            "path": r"(?i)(raw/testcases|/mnt/|juliet/)",
            "benign": r"(?i)benign", "fixed": r"(?i)fixed",
        }
        units = {row["unit_id"]: row for row in jlines(JULIET_TEST)}
        scanned = 0
        for name in ("direct", "triage"):
            for row in jlines(f"{CODEQL_RUN_V2}/requests_{name}.jsonl"):
                unit = units[row["unit_id"]]
                joined = "\n".join(item["content"] for item in row["body"]["messages"])
                req(unit["unit_id"] not in joined, f"{name}: unit_id leaked")
                req(unit["group_id"] not in joined, f"{name}: group_id leaked")
                for key, pattern in forbidden.items():
                    req(not re.search(pattern, joined), f"{name}: {key} leaked")
                req(row.get("authorization_header_omitted") is True, f"{name}: auth header stored")
                scanned += 1
        verify = jlines(f"{CODEQL_RUN_V2}/verify/results_verify.jsonl")
        eq(len({row["prompt_sha256"] for row in verify}), 91, "verify prompt hashes")
        eq({row["prompt_version"] for row in verify}, {"codeql-triage-verify-2026-11-22.1"}, "verify prompt version")
        for path in (f"{CODEQL_RUN_V2}/manifest.json", f"{CODEQL_RUN_V2}/verify/manifest.json"):
            manifest = jload(path)
            eq(manifest["api_key_value_stored"], False, f"{path}: key stored")
        return ok(
            "280 stored first-pass prompt bodies contain no unit_id/group_id/CWE/label/path token; 91 verify prompts are distinct and the builder applies the same audit_prompt (verify bodies were not retained).",
            scanned=scanned, verify_prompts=91,
        )

    def a8():
        direct = codeql_results(2, "direct")
        triage = codeql_results(2, "triage")
        verify = jlines(f"{CODEQL_RUN_V2}/verify/results_verify.jsonl")
        direct_cost = codeql_cost(direct, 0.14, 0.28, 0.0028)
        triage_cost = codeql_cost(triage, 0.14, 0.28, 0.0028)
        verify_cost = codeql_cost(verify, 0.14, 0.28, 0.0028)
        export = jload(CODEQL_EXPORT)["cost"]
        close(direct_cost, export["direct_usd"], "direct cost")
        close(triage_cost, export["triage_v2_usd"], "triage cost")
        close(verify_cost, export["verify_usd"], "verify cost")
        close(direct_cost + triage_cost, export["triage_v2_plus_text_rule_usd"], "text-rule total")
        close(direct_cost + triage_cost + verify_cost, export["triage_v2_plus_verify_usd"], "verify total")
        close(direct_cost + triage_cost + verify_cost, 0.0457946776, "all-in cost")
        eq(sum(1 for row in direct if row.get("cost")), 140, "direct cost records")
        eq(sum(1 for row in triage if row.get("cost")), 140, "triage cost records")
        eq(sum(1 for row in verify if row.get("cost")), 91, "verify cost records")
        return ok(
            f"Configured-price cost: direct ${direct_cost:.6f} + triage ${triage_cost:.6f} + verify ${verify_cost:.6f} = ${direct_cost + triage_cost + verify_cost:.6f}.",
            direct_usd=direct_cost, triage_usd=triage_cost, verify_usd=verify_cost,
            total_usd=direct_cost + triage_cost + verify_cost,
        )

    def a9():
        export = jload(CODEQL_EXPORT)
        eq(export["schema_version"], "codeql-triage-export-v1", "export schema")
        eq(export["model"]["name"], "mimo-v2.6-flash", "export model")
        eq(export["dataset"]["n"], 140, "export n")
        eq(export["dataset"]["bad"], 70, "export bad")
        eq(export["dataset"]["good"], 70, "export good")
        eq(export["dataset"]["language"], {"c": 58, "cpp": 82}, "export language")
        v2 = codeql_units(2)
        v1 = codeql_units(1)
        pairs = [
            ("codeql", v2, "codeql_alert"),
            ("direct", v2, "direct_pred"),
            ("triage_v1_oneshot", v1, "triage_keep"),
            ("triage_v2_oneshot", v2, "triage_keep"),
            ("triage_v2_verified", v2, "triage_verified"),
            ("triage_v2_text_rule", v2, "rule_text_consistency"),
            ("cascade_verified_alert_direct_noalert", v2, "hybrid_cascade_direct"),
            ("zero_cost_drop_cpp_may_not_be_freed", v2, "drop_may_cpp"),
            ("zero_cost_never_freed_only", v2, "query_never_only"),
        ]
        compared = []
        for condition, rows, key in pairs:
            m = confusion(rows, key)
            ex = export["conditions"][condition]["metrics"]
            for field in ("tp", "fp", "tn", "fn"):
                eq(ex[field], m[field], f"{condition}.{field}")
            for field in ("precision", "recall", "macro_f1", "mcc"):
                close(ex[field], m[field], f"{condition}.{field}")
            compared.append(condition)
        report = text("codeql_triage/REPORT.md")
        for needle in ("68", "23", "0.9857", "0.8173", "0.9571", "0.04579"):
            req(needle in report, f"REPORT.md missing {needle}")
        return ok(
            "Export reproduces all 9 conditions from per-unit records; REPORT.md carries the same key numbers.",
            conditions=compared,
        )

    check(checks, "A1", "codeql_triage", "Frozen test140 dataset and CodeQL status", a1)
    check(checks, "A2", "codeql_triage", "CodeQL confusion and metrics", a2)
    check(checks, "A3", "codeql_triage", "23 FPs are one query and four C++ variants", a3)
    check(checks, "A4", "codeql_triage", "TP deletion: v1 7, v2/verified 0", a4)
    check(checks, "A5", "codeql_triage", "v2 and verifier metrics reproduce", a5)
    check(checks, "A6", "codeql_triage", "Request counts, statuses and re-parsed units", a6)
    check(checks, "A7", "codeql_triage", "Prompt leakage and credential hygiene", a7)
    check(checks, "A8", "codeql_triage", "Configured-price cost recomputes", a8)
    check(checks, "A9", "codeql_triage", "benchmark_export matches per-unit records", a9)

# ---------------------------------------------------------------------------
# B. pair_diff
# ---------------------------------------------------------------------------

def audit_pair_diff(checks):
    expected_runs = {
        "test_deepseek_diff_fwd", "test_deepseek_diff_rev",
        "test_deepseek_ctrl_fwd", "test_deepseek_ctrl_rev",
        "test_mimo_diff_fwd", "test_mimo_diff_rev",
        "test_mimo_ctrl_fwd", "test_mimo_ctrl_rev",
    }

    def b1():
        data = jload(PAIR_DATASET)
        pairs = data["pairs"]
        eq(len(pairs), 180, "pair units")
        eq(len({item["pair_id"] for item in pairs}), 180, "unique pair ids")
        req(all(item.get("vulnerable") and item.get("fixed") for item in pairs), "pair without both versions")
        eq(sha_file(PAIR_DATASET), "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d", "pair hash")
        manifest = pair_manifest("test_deepseek_diff_fwd")
        eq(manifest["dataset_sha256"], sha_file(PAIR_DATASET), "manifest dataset hash")
        eq(manifest["dataset_units_total"], 180, "manifest units")
        return ok(
            "Frozen 180-pair test split; SHA-256 matches every manifest; 180 unique pair ids with both versions.",
            units=180, sha256=sha_file(PAIR_DATASET),
        )

    def b2():
        runs = pair_runs()
        eq(set(runs), expected_runs, "full run set")
        eq(len(runs), 8, "full run count")
        total = 0
        details = {}
        for run in runs:
            rows = pair_rows(run)
            manifest = pair_manifest(run)
            eq(len(rows), 180, f"{run} records")
            eq(dict(collections.Counter(row["status"] for row in rows)), {"ok": 180}, f"{run} status")
            eq(manifest["counts"], {"by_status": {"ok": 180}, "planned_requests": 180, "recorded_requests": 180},
               f"{run} counts")
            eq(manifest["partial"], False, f"{run} partial")
            eq(manifest["limit"], 0, f"{run} limit")
            total += len(rows)
            details[run] = len(rows)
        eq(total, 1440, "full records")
        pilot = sorted(p.name for p in (ROOT / PAIR_RUNS).glob("pilot_*") if p.is_dir())
        eq(len(pilot), 8, "pilot run count")
        pilot_records = sum(len(pair_rows(run)) for run in pilot)
        eq(pilot_records, 64, "pilot records")
        return ok(
            "8 full runs x 180 = 1,440 records, all ok, no partial/limit; 8 pilot runs (64 records) kept separate.",
            full_runs=details, total=1440, pilot_runs=8, pilot_records=64,
        )

    def b3():
        runs = pair_runs()
        rows = [row for run in runs for row in pair_rows(run)]
        eq(len(rows), 1440, "records")
        eq(sum(1 for row in rows if row["validation"]["decision_valid"]), 1440, "decision-valid records")
        eq(sum(1 for row in rows if row["validation"]["json_parse_ok"]), 1440, "json-parse-ok records")
        eq(sum(1 for row in rows if row["validation"]["errors"]), 0, "records with validation errors")
        eq(sum(1 for row in rows if row["status"] != "ok"), 0, "non-ok records")
        inexact = [row for row in rows if not row["validation"]["schema_exact"]]
        eq(len(inexact), 2, "schema-inexact records")
        extras = {tuple(sorted(row["validation"].get("extra_keys") or [])) for row in inexact}
        eq(extras, {("confidence_note",), ("rationale_note",)}, "extra keys")
        report = text("pair_diff/results/report.md")
        req("99.44%" in report, "report does not disclose 99.44% schema-exact")
        return ok(
            "0 invalid by decision validity (1,440/1,440 valid, 0 parse errors, 0 status errors); 2 outputs have an extra note key and are disclosed as 99.44% schema-exact.",
            invalid=0, schema_exact=1438, schema_inexact=2,
            extra_keys=sorted(str(item) for item in extras),
        )

    def b4():
        runs = pair_runs()
        for run in runs:
            pm = pair_map(run)
            eq(len(pm["assignments"]), 180, f"{run} assignments")
            slots = collections.Counter(item["vulnerable_slot"] for item in pm["assignments"].values())
            eq(dict(slots), {"A": 90, "B": 90}, f"{run} slots")
            manifest = pair_manifest(run)
            eq(manifest["position_map_sha256"], pm["sha256"], f"{run} map digest")
            payload = {key: value for key, value in pm.items() if key != "sha256"}
            digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                               separators=(",", ":")).encode("utf-8")).hexdigest()
            eq(digest, pm["sha256"], f"{run} map content digest")
            eq(pm["base_map_sha256"], manifest["base_map_sha256"], f"{run} base digest")
            eq(jload(manifest["base_map_path"])["sha256"], manifest["base_map_sha256"], f"{run} base file digest")
        for model in ("deepseek", "mimo"):
            for cond in ("diff", "ctrl"):
                fwd = pair_map(f"test_{model}_{cond}_fwd")["assignments"]
                rev = pair_map(f"test_{model}_{cond}_rev")["assignments"]
                eq(sum(1 for pid in fwd if fwd[pid]["vulnerable_slot"] == rev[pid]["vulnerable_slot"]), 0,
                   f"{model}/{cond} not complemented")
        return ok(
            "Every run has 180 assignments with 90/90 slot balance; reverse maps are exact complements; map and base hashes match.",
            runs=8, assignments_per_run=180,
        )

    def b5():
        export = jload(PAIR_EXPORT)["conditions"]
        details = {}
        for run in pair_runs():
            correct = pair_correct(run)
            n = len(pair_rows(run))
            manifest = pair_manifest(run)
            model, rest = run.split("_", 1)[1].split("_", 1)
            ex = export[model][rest]
            eq(ex["correct"], len(correct), f"{run} export correct")
            close(ex["da"], len(correct) / n, f"{run} export DA")
            details[run] = len(correct)
        return ok(
            "Per-run DA reproduces for all 8 runs (DeepSeek 68.33/70.56/68.89/69.44; MiMo 68.33/66.67/66.11/69.44).",
            correct=details,
        )

    def b6():
        export = jload(PAIR_EXPORT)["exchange"]
        details = {}
        for model in ("deepseek", "mimo"):
            for cond in ("diff", "ctrl"):
                fwd = pair_correct(f"test_{model}_{cond}_fwd")
                rev = pair_correct(f"test_{model}_{cond}_rev")
                both = len(fwd & rev)
                close(both / 180, export[model][cond]["da_both_orders"], f"{model}/{cond} exchange")
                details[f"{model}/{cond}"] = both
        eq(details, {"deepseek/diff": 112, "deepseek/ctrl": 108,
                     "mimo/diff": 109, "mimo/ctrl": 112}, "exchange counts")
        return ok(
            "Exchange-consistent DA reproduces: DeepSeek diff 62.22% / ctrl 60.00%; MiMo diff 60.56% / ctrl 62.22%.",
            counts=details,
        )

    def b7():
        leaks = {}
        for run in pair_runs():
            audit = jload(f"{PAIR_RUNS}/{run}/leak_audit.json")
            eq(audit["wrapper_clean_all"], True, f"{run} wrapper clean")
            eq(audit["slot_leak_all"], False, f"{run} slot leak")
            eq(len(audit["pairs"]), 180, f"{run} leak pairs")
            req(all(item["diff_direction_ok"] for item in audit["pairs"]), f"{run} diff direction")
            for item in audit["pairs"]:
                req(all(value is False for key, value in item["wrapper_hits"].items()
                        if isinstance(value, bool)), f"{run} wrapper hit")
            cve = sum(1 for item in audit["pairs"] if item["body_hits"]["cve_in_body"])
            fields = sum(1 for item in audit["pairs"] if item["body_hits"]["field_markers_in_body"])
            leaks[run] = {"cve_body": cve, "field_body": fields}
        req(all(item == {"cve_body": 1, "field_body": 1} for item in leaks.values()), "body hit count")
        # Stored request bodies: only source-level CVE/func_name may appear; no metadata.
        for run in pair_runs():
            for row in jlines(f"{PAIR_RUNS}/{run}/requests.jsonl"):
                joined = "\n".join(item["content"] for item in row["body"]["messages"])
                req(row["pair_id"] not in joined, f"{run} pair_id leaked")
                for pattern in (r"commit_id", r"filepath", r"vulnerable_slot", r"fixed_slot"):
                    req(not re.search(pattern, joined, re.I), f"{run} {pattern} leaked")
        readme = text("pair_diff/README.md")
        report = text("pair_diff/results/report.md")
        req("CVE-2017-17969" in readme and "CVE-2017-17969" in report, "CVE residue not disclosed")
        return ok(
            "All 8 leak audits are wrapper-clean and slot-clean; 180/180 diff directions A->B. The only body hits are source content: a CVE-2017-17969 comment (disclosed) and the identifier __func_name_from_ord, not the dataset func_name field.",
            body_hits=leaks,
        )

    def b8():
        export = jload(PAIR_EXPORT)["cost"]
        total = 0.0
        prompt_total = 0
        completion_total = 0
        by_arm = collections.defaultdict(float)
        for run in pair_runs():
            manifest = pair_manifest(run)
            usage = manifest["metrics"]["usage"]
            cost = usage["cost_usd"]
            total += cost
            prompt_total += usage["prompt_tokens"]
            completion_total += usage["completion_tokens"]
            model, rest = run.split("_", 1)[1].split("_", 1)
            arm = rest.split("_")[0]
            by_arm[f"{model}/{arm}"] += cost
        close(total, 1.156871, "new pair cost")
        eq(prompt_total, 4366678, "prompt tokens")
        eq(completion_total, 453037, "completion tokens")
        for model in ("deepseek", "mimo"):
            for arm in ("diff", "ctrl"):
                close(by_arm[f"{model}/{arm}"], export[model][arm]["cost_usd"], f"{model}/{arm} cost")
                eq(export[model][arm]["requests"], 360, f"{model}/{arm} requests")
        open_costs = {}
        for model in ("deepseek", "mimo"):
            cost = 0.0
            for cond in ("open_fwd", "open_rev"):
                manifest = jload(f"pair_debias/runs/test_{model}_{cond}/manifest.json")
                cost += manifest["metrics"]["usage"]["cost_usd"]
            open_costs[model] = cost
            close(cost, export[model]["open"]["cost_usd"], f"{model} open cost")
            eq(export[model]["open"]["requests"], 360, f"{model} open requests")
        return ok(
            f"New runs cost ${total:.6f} (4,366,678 prompt / 453,037 completion tokens); open baseline reuses 720 pair_debias records (${open_costs['deepseek']:.6f} + ${open_costs['mimo']:.6f}).",
            new_usd=total, prompt_tokens=prompt_total, completion_tokens=completion_total,
            open_usd=open_costs,
        )

    def b9():
        export = jload(PAIR_EXPORT)
        eq(export["method"], "pair_diff", "export method")
        eq(export["phase"], "test", "export phase")
        eq(export["dataset_units"], 180, "export units")
        eq(export["dataset_sha256"], sha_file(PAIR_DATASET), "export dataset hash")
        eq(set(export["conditions"]), {"deepseek", "mimo"}, "export models")
        eq(set(export["conditions"]["deepseek"]),
           {"diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev", "open_fwd", "open_rev"}, "export conditions")
        for model in ("deepseek", "mimo"):
            for cond in ("diff_fwd", "diff_rev", "ctrl_fwd", "ctrl_rev", "open_fwd", "open_rev"):
                ex = export["conditions"][model][cond]
                if cond.startswith("open"):
                    rows = jlines(f"pair_debias/runs/test_{model}_{cond}/results.jsonl")
                    pm = jload(f"pair_debias/runs/test_{model}_{cond}/position_map.json")
                else:
                    rows = pair_rows(f"test_{model}_{cond}")
                    pm = pair_map(f"test_{model}_{cond}")
                decisions = {row["pair_id"]: (row.get("parsed") or {}).get("vulnerable_version") for row in rows}
                correct = sum(1 for pid, item in pm["assignments"].items()
                              if decisions.get(pid) == item["vulnerable_slot"])
                abstain = sum(1 for value in decisions.values() if value in ("both", "neither"))
                eq(ex["n"], len(rows), f"{model}/{cond} n")
                eq(ex["correct"], correct, f"{model}/{cond} correct")
                close(ex["da"], correct / len(rows), f"{model}/{cond} DA")
                close(ex["abstention_rate"], abstain / len(rows), f"{model}/{cond} abstention")
                close(ex["committed_da"], correct / (len(rows) - abstain), f"{model}/{cond} committed DA")
        report = text("report/next_results_summary.md")
        rows = [
            "| DeepSeek | 62.22% | 60.00% | 55.56% | +2.22 pp（1.0000） | +6.67 pp（0.0855） |",
            "| MiMo | 60.56% | 62.22% | 58.33% | −1.67 pp（0.9053） | +2.22 pp（1.0000） |",
        ]
        for row in rows:
            req(row in report, f"report missing row: {row}")
        return ok(
            "benchmark_export reproduces all 12 conditions (DA, committed DA, abstention, cost); the unified report table matches.",
            conditions=12,
        )

    check(checks, "B1", "pair_diff", "Frozen 180-pair dataset", b1)
    check(checks, "B2", "pair_diff", "8 full runs x 180 = 1,440 records", b2)
    check(checks, "B3", "pair_diff", "0 invalid; 2 schema-inexact disclosed", b3)
    check(checks, "B4", "pair_diff", "Position maps are balanced and complemented", b4)
    check(checks, "B5", "pair_diff", "Per-run DA reproduces", b5)
    check(checks, "B6", "pair_diff", "Exchange-consistent DA reproduces", b6)
    check(checks, "B7", "pair_diff", "Prompt/slot leakage audit", b7)
    check(checks, "B8", "pair_diff", "Cost and token totals recompute", b8)
    check(checks, "B9", "pair_diff", "benchmark_export matches all conditions", b9)


# ---------------------------------------------------------------------------
# C. verifier_conservative
# ---------------------------------------------------------------------------

def audit_conservative(checks):
    expected_runs = {
        "test_conservative_deepseek_self", "test_conservative_deepseek_by_mimo",
        "test_conservative_mimo_self", "test_conservative_mimo_by_deepseek",
    }

    def c1():
        runs = cons_runs()
        eq(set(runs), expected_runs, "conservative run set")
        eq(len(runs), 4, "conservative run count")
        counts = {}
        label_counts = {}
        total = 0
        for run in runs:
            rows = cons_rows(run)
            manifest = jload(f"{CONS_RUNS}/{run}/manifest.json")
            eq(manifest["counts"]["planned_requests"], len(rows), f"{run} planned")
            eq(manifest["counts"]["recorded_requests"], len(rows), f"{run} recorded")
            eq(manifest["claims"]["selected_positives"], len(rows), f"{run} selected positives")
            req(all(row["first_pass"]["status"] == "ok" for row in rows), f"{run} non-ok first pass")
            req(all(row["first_pass"]["evidence_lines"] for row in rows), f"{run} empty evidence lines")
            label_counts[run] = dict(collections.Counter(row["label"] for row in rows))
            counts[run] = len(rows)
            total += len(rows)
        eq(counts, {
            "test_conservative_deepseek_self": 60,
            "test_conservative_deepseek_by_mimo": 60,
            "test_conservative_mimo_self": 58,
            "test_conservative_mimo_by_deepseek": 58,
        }, "arm sizes")
        eq(label_counts["test_conservative_deepseek_self"], {True: 49, False: 11}, "deepseek label mix")
        eq(label_counts["test_conservative_mimo_self"], {True: 47, False: 11}, "mimo label mix")
        eq(total, 236, "total requests")
        return ok(
            "Four arms on first-pass positives: 60/60/58/58 = 236 requests; labels are 49 V / 11 NV per 60 arm and 47 V / 11 NV per 58 arm.",
            arms=counts, labels=label_counts, total=236,
        )

    def c2():
        runs = cons_runs()
        status = collections.Counter()
        valid = 0
        failures = []
        for run in runs:
            rows = cons_rows(run)
            manifest = jload(f"{CONS_RUNS}/{run}/manifest.json")
            for row in rows:
                status[row["status"]] += 1
                valid += int(row["status"] == "ok")
                if row["status"] != "ok":
                    failures.append((run, row["sample_id"], row["status"], row["decision"]))
            eq(manifest["counts"]["api_errors"], sum(1 for row in rows if row["status"] == "error"), f"{run} errors")
            eq(manifest["counts"]["invalid"], sum(1 for row in rows if row["status"] == "invalid"), f"{run} invalid")
        eq(dict(status), {"ok": 233, "invalid": 2, "error": 1}, "status counts")
        eq(valid, 233, "valid records")
        eq(len(failures), 3, "failure records")
        req(all(item[3]["retract"] is False for item in failures), "failure not kept fail-open")
        return ok(
            "233 ok / 2 invalid / 1 API error; all three failures keep the first-pass prediction (fail-open), not retract.",
            status=dict(status), valid=233, failures=[{"arm": a, "sample": b, "status": c} for a, b, c, _ in failures],
        )

    def c3():
        decisions = jlines("verifier_conservative/analysis/decisions.jsonl")
        eq(len(decisions), 236, "decision rows")
        total = 0
        tp = 0
        fp = 0
        per_arm = {arm: 0 for arm in ("deepseek_self", "deepseek_cross", "mimo_self", "mimo_cross")}
        for row in decisions:
            arm = row["arm"]
            if row["decision"]["retract"]:
                per_arm[arm] += 1
                total += 1
                if row["label"]:
                    tp += 1
                else:
                    fp += 1
                req(row["decision"]["reason"].startswith("retract_"), f"{arm} retract reason")
                req(row["assessment"] == "unsupported", f"{arm} retract without unsupported")
                req(row["audit"].get("rebuttal_grounded") is True, f"{arm} ungrounded retract")
            if row["assessment"] == "insufficient":
                req(row["decision"]["retract"] is False, f"{arm} insufficient retracted")
        eq(dict(per_arm), {
            "deepseek_self": 1,
            "deepseek_cross": 0,
            "mimo_self": 0,
            "mimo_cross": 3,
        }, "per-arm retractions")
        eq(total, 4, "total retractions")
        eq((tp, fp), (3, 1), "retraction composition")
        close(fp / total, 0.25, "retraction precision")
        metrics = jload("verifier_conservative/analysis/metrics.json")
        for arm, item in metrics["arms"].items():
            retraction = item["strategies"]["conservative"]["retraction"]
            eq(retraction["retracted"], per_arm[arm], f"{arm} metrics retracted")
            eq(retraction["tp_retracted"], 1 if arm == "deepseek_self" else (2 if arm == "mimo_cross" else 0),
               f"{arm} metrics TP retracted")
            eq(retraction["fp_retracted"], 1 if arm == "mimo_cross" else 0, f"{arm} metrics FP retracted")
        return ok(
            "4/236 retractions (TP 3 / FP 1), precision 25.0%; all are grounded unsupported decisions; insufficient never retracts.",
            per_arm=dict(per_arm), tp=tp, fp=fp, precision=0.25,
        )

    def c4():
        total = 0.0
        per_arm = {}
        missing = 0
        for run in cons_runs():
            cost = 0.0
            for row in cons_rows(run):
                value = ((row.get("response") or {}).get("cost") or {}).get("cost_usd")
                if value is None:
                    missing += 1
                else:
                    cost += value
            per_arm[run] = cost
            total += cost
        close(total, 0.151758112, "conservative total cost")
        eq(missing, 1, "missing cost records")
        metrics = jload("verifier_conservative/analysis/metrics.json")
        run_by_arm = {
            "deepseek_self": "test_conservative_deepseek_self",
            "deepseek_cross": "test_conservative_deepseek_by_mimo",
            "mimo_self": "test_conservative_mimo_self",
            "mimo_cross": "test_conservative_mimo_by_deepseek",
        }
        for arm, item in metrics["arms"].items():
            close(item["cost"]["conservative_verifier"]["total_cost_usd"],
                  per_arm[run_by_arm[arm]], f"{arm} cost")
        return ok(
            "Verifier cost recomputes to $0.151758 across 235 priced requests; the single API error has no usage and is not imputed.",
            total_usd=total, missing_cost_records=missing, per_arm=per_arm,
        )

    def c5():
        metrics = jload("verifier_conservative/analysis/metrics.json")
        compared = 0
        for run in cons_runs():
            test = cons_rows(run)
            dry_path = f"verifier_conservative/runs/dryrun_conservative_{run.replace('test_conservative_', '')}/dry_run_requests.jsonl"
            dry = jlines(dry_path)
            eq(len(dry), len(test), f"{run} dry-run count")
            test_hashes = {row["sample_id"]: row["request"]["body_sha256"] for row in test}
            dry_hashes = {row["sample_id"]: row["body_sha256"] for row in dry}
            eq(test_hashes, dry_hashes, f"{run} body hashes")
            compared += len(test_hashes)
        eq(compared, 236, "compared bodies")
        for arm, item in metrics["arms"].items():
            eq(item["audit"]["all_bodies_match_dry_run"], True, f"{arm} audit")
            eq(item["audit"]["isolation_violations"], 0, f"{arm} isolation")
            eq(item["audit"]["api_key_value_stored"], False, f"{arm} key")
            eq(item["audit"]["authorization_header_stored"], False, f"{arm} auth")
        return ok(
            "All 236 real request bodies hash-match their dry runs; isolation violations 0; keys and Authorization never stored.",
            bodies=compared,
        )

    def c6():
        scanned = 0
        for run in cons_runs():
            dry_path = f"verifier_conservative/runs/dryrun_conservative_{run.replace('test_conservative_', '')}/dry_run_requests.jsonl"
            for row in jlines(dry_path):
                joined = "\n".join(item["content"] for item in row["body"]["messages"])
                prompt = row.get("prompt") or {}
                for token in (row.get("sample_id"), row.get("project"), row.get("commit_id"),
                              row.get("filepath"), row.get("idx")):
                    if token is None or str(token).strip() in ("", "None"):
                        continue
                    req(str(token) not in joined, f"{run}: metadata leaked")
                req(prompt.get("template_forbidden_tokens_present") == [], f"{run}: template token")
                eq(prompt.get("only_source_and_claim_variable"), True, f"{run}: extra variables")
                eq(prompt.get("input_fields"), ["func_body", "claim.evidence_lines", "claim.mechanism"],
                   f"{run}: input fields")
                scanned += 1
        eq(scanned, 236, "scanned prompts")
        return ok(
            "236 verifier prompts expose only func_body + claim evidence lines/mechanism; no sample id, commit or path; template forbidden-token list is empty.",
            scanned=scanned,
        )

    def c7():
        metrics = jload("verifier_conservative/analysis/metrics.json")
        eq(metrics["analysis_status"], "exploratory_post_hoc_test_seen", "analysis status")
        total_original = 0
        for arm, item in metrics["arms"].items():
            total_original += item["strategies"]["original_fail_closed"]["retraction"]["retracted"]
        eq(total_original, 155, "original fail-closed retractions")
        report = text("verifier_conservative/analysis/report.md")
        for needle in ("236", "4", "0.151758", "155", "25.0%", "探索性", "事后"):
            req(needle in report, f"report missing {needle}")
        unified = text("report/next_results_summary.md")
        for row in (
            "| `deepseek_self` | 1 | 1 | 0 | 0.0% | −0.0052 | −0.0064 |",
            "| `deepseek_cross` | 0 | 0 | 0 | — | 0.0000 | 0.0000 |",
            "| `mimo_self` | 0 | 0 | 0 | — | 0.0000 | 0.0000 |",
            "| `mimo_cross` | 3 | 2 | 1 | 33.3% | −0.0028 | +0.0139 |",
        ):
            req(row in unified, f"unified report missing: {row}")
        return ok(
            "Report matches metrics: 4/236, precision 25.0%, macro-F1 deltas 0 to -0.0052, MCC +0.0139 only on mimo_cross; post-hoc/test-seen status explicit.",
            original_retractions=155,
        )

    check(checks, "C1", "verifier_conservative", "Four arms, 236 first-pass positives", c1)
    check(checks, "C2", "verifier_conservative", "Statuses and fail-open handling", c2)
    check(checks, "C3", "verifier_conservative", "Retraction count and composition", c3)
    check(checks, "C4", "verifier_conservative", "Verifier cost recomputes", c4)
    check(checks, "C5", "verifier_conservative", "Dry-run body hashes and isolation audit", c5)
    check(checks, "C6", "verifier_conservative", "Prompt exposes only source and claim", c6)
    check(checks, "C7", "verifier_conservative", "Report and metrics agree", c7)

# ---------------------------------------------------------------------------
# D. dynamic_coverage
# ---------------------------------------------------------------------------

def audit_dynamic_coverage(checks):
    def d1():
        metrics = jload(f"{COV_RUN}/metrics.json")
        raw = jlines(f"{COV_RUN}/results_raw.jsonl")
        units = jlines(f"{COV_RUN}/results_units.jsonl")
        eq(metrics["units"], 140, "coverage units")
        eq(metrics["labels"], {"bad": 70, "good": 70}, "coverage labels")
        eq(len(units), 140, "unit records")
        eq(len(raw), 420, "raw records")
        eq(dict(collections.Counter(row["mode"] for row in raw)),
           {"default": 140, "realloc_fail": 140, "nogobal": 140}, "mode counts")
        eq(dict(collections.Counter(row["label"] for row in raw)), {"bad": 210, "good": 210}, "raw labels")
        eq(sum(1 for row in raw if row["coverage_error"]), 0, "coverage errors")
        eq(sum(1 for row in raw if row["entry_executed"]), 420, "entry executed")
        eq(sum(1 for row in units if row["compile_error"]), 0, "compile errors")
        return ok(
            "140 units x 3 modes = 420 runs; 70/70 labels; 0 compile/coverage errors; entry executed 140/140.",
            units=140, raw=420, modes=3,
        )

    def d2():
        metrics = jload(f"{COV_RUN}/metrics.json")
        raw = jlines(f"{COV_RUN}/results_raw.jsonl")
        units = jlines(f"{COV_RUN}/results_units.jsonl")
        default = [row for row in raw if row["mode"] == "default"]
        eq(sum(1 for row in default if row["label"] == "bad" and row["decision"] == "leak"), 58, "default bad leaks")
        eq(sum(1 for row in default if row["label"] == "good" and row["decision"] == "leak"), 0, "default good leaks")
        eq(sum(1 for row in units if row["label"] == "bad" and row["y_pred"] == 1), 70, "union TP")
        eq(sum(1 for row in units if row["label"] == "good" and row["y_pred"] == 1), 0, "union FP")
        overall = metrics["coverage_overall"]
        eq(overall["coverage_classes"], {"covered_clean": 70, "uncovered": 0, "compile_error": 0, "leak": 70},
           "union classes")
        eq(overall["coverage_classes_default"]["covered_clean"], 82, "default covered_clean")
        eq(overall["coverage_classes_default_by_label"]["covered_clean"],
           {"bad": 12, "good": 70}, "default covered_clean by label")
        eq(overall["coverage_classes_default"]["leak"], 58, "default leak")
        return ok(
            "Default path 58 TP / 0 FP / 70 TN / 12 FN; three-mode union 70 TP / 0 FP / 70 TN / 0 FN; 12 default cleans are bad.",
            default={"tp": 58, "fp": 0, "tn": 70, "fn": 12},
            union={"tp": 70, "fp": 0, "tn": 70, "fn": 0},
        )

    def d3():
        overall = jload(f"{COV_RUN}/metrics.json")["coverage_overall"]
        close(overall["mean_effective_line_pct"], 1.0, "effective line coverage")
        close(overall["mean_branch_pct"], 0.5273109243697479, "branch coverage")
        eq(overall["tiers"]["branch_complete"], 21, "branch_complete")
        eq(overall["tiers"]["partial"], 0, "effective partial")
        eq(overall["branch_complete_bad"], 21, "branch_complete bad")
        eq(overall["branch_complete_good"], 0, "branch_complete good")
        units = jlines(f"{COV_RUN}/results_units.jsonl")
        latent = [row for row in units if row["label"] == "bad" and row["modes"]["default"]["decision"] == "clean"]
        eq(len(latent), 12, "latent bad units")
        eq(dict(collections.Counter(row["primary_evidence"] for row in latent)),
           {"realloc_fail": 7, "nogobal": 5}, "latent evidence")
        eq(dict(collections.Counter(row["coverage_tier_effective"] for row in latent)),
           {"line_complete": 10, "branch_complete": 2}, "latent tiers")
        return ok(
            "Effective line coverage 100%, branch 52.7%, 21 branch-complete units all bad; the 12 default FNs split 7 realloc_fail + 5 nogobal and are all line-complete.",
            line=1.0, branch=0.5273109243697479, branch_complete=21, latent=12,
        )

    def d4():
        verify = jload(f"{COV_RUN}/verify.json")
        eq(verify["status"], "PASS", "verify status")
        eq(verify["problems"], [], "verify problems")
        eq(verify["selftest"], "PASS", "selftest")
        eq(verify["crosscheck"]["default_agree"], 140, "default agree")
        eq(verify["crosscheck"]["union_agree"], 140, "union agree")
        eq(verify["crosscheck"]["archived_units"], 140, "archived units")
        archived = {row["unit_id"]: row for row in jlines("dynamic_enhanced/runs/test140_enhanced_v3/results_units.jsonl")}
        units = jlines(f"{COV_RUN}/results_units.jsonl")
        eq(len(archived), 140, "archived units count")
        default_agree = 0
        union_agree = 0
        for row in units:
            old = archived[row["unit_id"]]
            if row["modes"]["default"]["decision"] == old["modes"]["default"]["decision"]:
                default_agree += 1
            if row["y_pred"] == old["y_pred"]:
                union_agree += 1
        eq(default_agree, 140, "default agreement")
        eq(union_agree, 140, "union agreement")
        return ok(
            "verify.json PASS, 0 problems, selftest PASS; default and union decisions agree with dynamic_enhanced 140/140.",
            default_agree=140, union_agree=140,
        )

    def d5():
        network_modules = {"requests", "httpx", "urllib", "urllib3", "http", "socket", "openai", "anthropic", "aiohttp"}
        files = sorted((ROOT / "dynamic_coverage/dyncov").glob("*.py")) + [ROOT / "dynamic_coverage/run_dynamic_coverage.py"]
        imported = set()
        for path in files:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
        eq(imported & network_modules, set(), "network imports")
        for row in jlines(f"{COV_RUN}/results_raw.jsonl"):
            req("model" not in row and "api_key" not in row, "model/api field in coverage record")
        return ok(
            "Coverage tool imports no network/model client; raw records contain no model or API-key field.",
            imports=sorted(imported),
        )

    check(checks, "D1", "dynamic_coverage", "140 units x 3 modes, no coverage errors", d1)
    check(checks, "D2", "dynamic_coverage", "Default vs union confusion and classes", d2)
    check(checks, "D3", "dynamic_coverage", "Line/branch coverage and latent FNs", d3)
    check(checks, "D4", "dynamic_coverage", "verify.json and archived agreement", d4)
    check(checks, "D5", "dynamic_coverage", "No model/API usage", d5)


# ---------------------------------------------------------------------------
# E. interpretable_baseline
# ---------------------------------------------------------------------------

def audit_interpretable(checks):
    def e1():
        dev = jload("splits/dev_detection_40.json")["samples"]
        test = jload("splits/test_detection_160.json")["samples"]
        eq(len(dev), 40, "dev units")
        eq(len(test), 160, "test units")
        eq(sum(1 for row in dev if row["is_vulnerable"]), 32, "dev positives")
        eq(sum(1 for row in test if row["is_vulnerable"]), 128, "test positives")
        eq(len({row["project"] for row in dev}), 40, "dev projects")
        eq(len({row["project"] for row in test}), 40, "test projects")
        eq(len({row["idx"] for row in dev} & {row["idx"] for row in test}), 0, "idx overlap")
        eq(len({row["project"] for row in dev} & {row["project"] for row in test}), 0, "project overlap")
        body = lambda row: hashlib.md5(row["func_body"].encode("utf-8")).hexdigest()
        eq(len({body(row) for row in dev} & {body(row) for row in test}), 0, "body md5 overlap")
        eq(len({(row["project"], row["commit_id"]) for row in dev}
               & {(row["project"], row["commit_id"]) for row in test}), 0, "project+commit overlap")
        config = jload(f"{INT_RUN}/metrics.json")["config"]
        eq(config["dev_sha256"], sha_file("splits/dev_detection_40.json"), "dev hash")
        eq(config["test_sha256"], sha_file("splits/test_detection_160.json"), "test hash")
        eq(config["isolation"], {"dev_n": 40, "test_n": 160, "idx_overlap": 0, "project_overlap": [],
                                 "exact_body_md5_overlap": 0, "test_projects": 40}, "isolation block")
        return ok(
            "dev40/test160 isolation: idx, project, function-body MD5 and project+commit overlap all 0; both split hashes match.",
            dev=40, test=160, idx_overlap=0, project_overlap=0, body_md5_overlap=0,
        )

    def e2():
        features = jlines(f"{INT_RUN}/features.jsonl")
        predictions = jlines(f"{INT_RUN}/predictions.jsonl")
        eq(len(features), 200, "feature rows")
        eq(dict(collections.Counter(row["split"] for row in features)), {"dev": 40, "test": 160}, "feature splits")
        eq(len(predictions), 1800, "prediction rows")
        methods = sorted({row["method"] for row in predictions})
        eq(len(methods), 9, "method count")
        for method in methods:
            rows = [row for row in predictions if row["method"] == method]
            eq(len(rows), 200, f"{method} rows")
            eq(sum(1 for row in rows if row["split"] == "test"), 160, f"{method} test rows")
            req(all(row["pred"] in (0, 1) for row in rows), f"{method} non-binary prediction")
        feature_keys = set(features[0]["features"])
        eq(feature_keys, {"chars", "lines", "tokens", "calls", "call_density", "alloc", "realloc", "free",
                          "alloc_minus_free", "mem_api", "branches", "branch_density", "ptr_arrow", "nulls",
                          "returns"}, "feature keys")
        return ok(
            "200 feature rows (40 dev / 160 test) and 1,800 predictions (9 methods x 200); all predictions binary.",
            features=200, predictions=1800, methods=methods,
        )

    def e3():
        features = jlines(f"{INT_RUN}/features.jsonl")
        dev = [row for row in features if row["split"] == "dev"]
        chars = statistics.median(row["features"]["chars"] for row in dev)
        calls = statistics.median(row["features"]["calls"] for row in dev)
        positive_rate = sum(1 for row in dev if row["label"]) / len(dev)
        close(chars, 1504.0, "dev chars median")
        close(calls, 16.0, "dev calls median")
        close(positive_rate, 0.8, "dev positive rate")
        metrics = jload(f"{INT_RUN}/metrics.json")
        config = metrics["config"]
        eq(config["thresholds"], {"chars": 1504.0, "calls": 16.0, "prior_positive": True,
                                  "dev_positive_rate": 0.8}, "thresholds")
        eq(config["selected_rule_on_dev"], "length_short", "selected rule")
        eq(config["primary_method"], "rule:length_short", "primary method")
        rules = {name: item["scores"]["macro_f1"] for name, item in metrics["dev_rule_table"].items()}
        eq(len(rules), 7, "dev rule count")
        best = max(rules, key=rules.get)
        eq(best, "length_short", "dev-best rule")
        close(rules["length_short"], 0.45054945054945056, "length_short dev")
        close(rules["prior_majority"], 0.4444444444444444, "prior dev")
        return ok(
            "Thresholds are dev-only (chars 1504, calls 16, positive rate 0.8); length_short is the best of 7 rules on dev (0.4505 vs 0.4444).",
            chars=chars, calls=calls, positive_rate=positive_rate, best_rule=best,
        )

    def e4():
        metrics = jload(f"{INT_RUN}/metrics.json")
        length = metrics["methods"]["rule:length_short"]["test"]
        majority = metrics["methods"]["rule:prior_majority"]["test"]
        alloc = metrics["methods"]["rule:alloc_or_mem"]["test"]
        eq((length["confusion"]["tp"], length["confusion"]["fp"], length["confusion"]["tn"], length["confusion"]["fn"]),
           (75, 15, 17, 53), "length_short confusion")
        close(length["macro_f1"], 0.5107033639143731, "length_short macro-F1")
        close(length["mcc"], 0.09449111825230681, "length_short MCC")
        close(majority["macro_f1"], 0.4444444444444444, "majority macro-F1")
        close(alloc["macro_f1"], 0.38740428191904985, "alloc_or_mem macro-F1")
        close(alloc["mcc"], 0.18333969940564226, "alloc_or_mem MCC")
        llm = [item["scores"]["macro_f1"] for item in metrics["llm"].values()]
        close(min(llm), 0.3456196581196581, "LLM min")
        close(max(llm), 0.4223374290729477, "LLM max")
        report = text("report/next_results_summary.md")
        for row in (
            "| `length_short` | **0.511 [0.422, 0.562]** | 0.094 | 0.833 | 0.586 | 0.531 |",
            "| `prior_majority` | 0.444 [0.412, 0.460] | 0.000 | 0.800 | 1.000 | 0.000 |",
            "| `alloc_or_mem` | 0.387 [0.324, 0.530] | **0.183** | 0.941 | 0.250 | 0.938 |",
        ):
            req(row in report, f"report missing: {row}")
        return ok(
            "test160: length_short 75/15/17/53, macro-F1 0.5107, MCC 0.0945; majority 0.4444; alloc_or_mem MCC 0.1833; 8 LLM runs 0.3456-0.4223.",
            length_short={"tp": 75, "fp": 15, "tn": 17, "fn": 53, "macro_f1": length["macro_f1"], "mcc": length["mcc"]},
            majority_macro_f1=majority["macro_f1"], alloc_or_mem_mcc=alloc["mcc"],
        )

    def e5():
        readme = ROOT / "interpretable_baseline/README.md"
        metrics = ROOT / INT_RUN / "metrics.json"
        readme_mtime = readme.stat().st_mtime
        metrics_mtime = metrics.stat().st_mtime
        delta = readme_mtime - metrics_mtime
        return warn(
            "README claims the method was pre-registered before the test run, but its mtime is "
            f"{delta:.1f}s after metrics.json; pre-registration cannot be verified from the artifacts. "
            "The selected rule and thresholds are nevertheless dev-only.",
            readme_mtime=utc(readme_mtime), metrics_mtime=utc(metrics_mtime), delta_seconds=delta,
        )

    def e6():
        network_modules = {"requests", "httpx", "urllib", "urllib3", "http", "socket", "openai", "anthropic", "aiohttp"}
        path = ROOT / "interpretable_baseline/run_baseline.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        eq(imported & network_modules, set(), "network imports")
        source = path.read_text(encoding="utf-8")
        req("api_key" not in source.lower(), "api_key reference")
        req("openai" not in source.lower() and "anthropic" not in source.lower(), "model client reference")
        return ok(
            "run_baseline.py imports no network/model client and contains no api_key/model-client reference.",
            imports=sorted(imported),
        )

    check(checks, "E1", "interpretable_baseline", "dev40/test160 isolation is exact", e1)
    check(checks, "E2", "interpretable_baseline", "Feature and prediction record counts", e2)
    check(checks, "E3", "interpretable_baseline", "Thresholds and rule selection are dev-only", e3)
    check(checks, "E4", "interpretable_baseline", "test160 metrics reproduce", e4)
    check(checks, "E5", "interpretable_baseline", "Pre-registration timestamp is not verifiable", e5)
    check(checks, "E6", "interpretable_baseline", "No model/API usage", e6)


# ---------------------------------------------------------------------------
# F. Cross-cutting
# ---------------------------------------------------------------------------

def audit_cross(checks):
    def f1():
        expected = {
            "audit/final_audit.json": "2026-11-11",
            "audit/final_audit.md": "2026-11-11",
            "audit/latest_audit.json": "2026-11-13",
            "audit/latest_audit.md": "2026-11-13",
        }
        for path, day in expected.items():
            actual = utc((ROOT / path).stat().st_mtime)[:10]
            eq(actual, day, f"{path} mtime")
        final = jload("audit/final_audit.json")
        latest = jload("audit/latest_audit.json")
        eq(final["counts"], {"PASS": 58, "FAIL": 0, "WARN": 3, "INFO": 1}, "final audit counts")
        eq(latest["counts"], {"total": 56, "pass": 56, "warn": 0, "fail": 0, "info": 0}, "latest audit counts")
        eq(final["overall"], "PASS_WITH_WARNINGS", "final overall")
        eq(latest["overall"], "PASS", "latest overall")
        pair_counts = {run: len(jlines(f"pair_debias/runs/{run}/results.jsonl"))
                       for run in sorted(p.name for p in (ROOT / "pair_debias/runs").glob("test_*") if p.is_dir())}
        eq(len(pair_counts), 6, "pair_debias full runs")
        eq(sum(pair_counts.values()), 1080, "pair_debias records")
        evidence = sorted((ROOT / "evidence_verify/runs").glob("test_verify_*"))
        eq(len(evidence), 4, "evidence arms")
        eq(sum(len(jlines(str((path / "results.jsonl").relative_to(ROOT)))) for path in evidence), 236, "evidence records")
        eq(len(jlines("dynamic_enhanced/runs/test140_enhanced_v3/results_units.jsonl")), 140, "dynamic records")
        hybrid = sorted((ROOT / "hybrid_dynamic_enhanced/runs").glob("*/results.jsonl"))
        eq(len(hybrid), 2, "hybrid runs")
        eq(sum(len(jlines(str(path.relative_to(ROOT)))) for path in hybrid), 280, "hybrid records")
        eq(len(jlines(CODEQL_PRED)), 200, "static records")
        frozen = {
            PAIR_DATASET: "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d",
            "splits/dev_detection_40.json": "b378f250a3c7eddde24ebca4a5636de7c88d895dc3089436b8266ce298fdcc3e",
            "splits/test_detection_160.json": "bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8",
            JULIET_TEST: "8322692d4f155d81a8464acec987528d5739250a684dbdfb9a05e3f7bc86f073",
            JULIET_SUBSET: "4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24",
            CODEQL_PRED: "ed54cfeaca86e2edc7b76928d741dae2a3b2605c829013e40aa112d65775c4cc",
        }
        for path, digest in frozen.items():
            eq(sha_file(path), digest, f"{path} hash")
        old_files = [
            "pair_debias/results/comparison.json",
            "evidence_verify/analysis/metrics.json",
            "dynamic_enhanced/runs/test140_enhanced_v3/metrics.json",
            "static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.json",
            "benchmark/results/extension_summary.json",
            "report/report_latest_zh.pdf",
        ]
        for path in old_files:
            actual = utc((ROOT / path).stat().st_mtime)[:10]
            req(actual < "2026-11-22", f"{path} modified on {actual}")
        return ok(
            "Old audit files and six frozen hashes are unchanged; old result counts still 1,080 pair_debias / 236 evidence / 140 dynamic / 280 hybrid / 200 static; the sampled old artifacts predate 2026-11-22.",
            pair_debias=1080, evidence=236, dynamic=140, hybrid=280, static=200,
        )

    def f2():
        report = text(REPORT_MD)
        required = [
            "68/0/70/2", "0.9857", "0.8173", "0.9571",
            "236", "4/236", "0.151758", "0.045795",
            "1,440", "1.156871", "4,366,678", "453,037",
            "| DeepSeek | 62.22% | 60.00% | 55.56% | +2.22 pp（1.0000） | +6.67 pp（0.0855） |",
            "| MiMo | 60.56% | 62.22% | 58.33% | −1.67 pp（0.9053） | +2.22 pp（1.0000） |",
            "| v2 + 复核/文本规则 | **68** | **0** | **70** | **2** | **0.9857** | **0.9718** | **0/68** |",
            "| `length_short` | **0.511 [0.422, 0.562]** | 0.094 | 0.833 | 0.586 | 0.531 |",
            "| default | 140 | 58 | 0 | 100.0% | 50.0% | 21（全 bad） |",
            "| `deepseek_self` | 1 | 1 | 0 | 0.0% | −0.0052 | −0.0064 |",
            "| `mimo_cross` | 3 | 2 | 1 | 33.3% | −0.0028 | +0.0139 |",
        ]
        missing = [needle for needle in required if needle not in report]
        eq(missing, [], "report missing values")
        tex = text(REPORT_TEX)
        for needle in ("68/0/70/2", "236", "0.9857", "62.22"):
            req(needle in tex, f"TeX missing {needle}")
        pdf = ROOT / REPORT_PDF
        req(pdf.exists() and pdf.stat().st_size > 100_000, "report PDF missing or too small")
        return ok(
            "Unified report and TeX carry the audited CodeQL, pair, conservative, coverage and interpretable numbers; the PDF exists.",
            report=REPORT_MD, tex=REPORT_TEX, pdf_bytes=pdf.stat().st_size,
        )

    def f3():
        batch_path = "benchmark/extensions/configs/next_iteration_batch.json"
        batch = jload(batch_path)
        eq(len(batch["runs"]), 30, "batch runs")
        present = [item for item in batch["runs"] if (ROOT / item["out"]).is_dir()]
        summary_path = BENCH_SUMMARY
        next_md_path = BENCH_NEXT_MD
        summary_exists = (ROOT / summary_path).exists()
        next_md = (ROOT / next_md_path).exists()
        if not summary_exists or not next_md:
            missing = [path for path, exists in ((summary_path, summary_exists), (next_md_path, next_md))
                       if not exists]
            return warn(
                f"{len(present)}/30 batch output dirs exist, but the aggregate layer is not published: "
                f"missing {', '.join(missing)}. This is a WARN, not a FAIL: the per-run artifacts are present "
                "and the missing files can be regenerated without re-running the models.",
                batch_runs=len(batch["runs"]), imported=len(present),
                missing=missing, summary_present=summary_exists, next_iteration_md=next_md,
            )
        summary = jload(summary_path)
        eq(summary["scope"]["canonical_runs"], 30, "summary canonical runs")
        eq(summary["validation"]["runs_checked"], 30, "summary runs checked")
        problems = []
        if len(present) != len(batch["runs"]):
            problems.append(f"only {len(present)}/30 output dirs exist")
        if not summary["validation"]["schema_ok"]:
            problems.append("summary reports schema_ok=false")
        if not summary["validation"]["parent_metrics_ok"]:
            problems.append("summary reports parent_metrics_ok=false")
        if summary["validation"]["design_checks_failed"]:
            problems.append(f"summary reports {summary['validation']['design_checks_failed']} failed design checks")
        if summary["scope"]["main_tables_modified"]:
            problems.append("summary reports main_tables_modified=true")
        if summary["generated_at"][:10] < "2026-11-22":
            problems.append(f"summary is stale ({summary['generated_at']})")
        md_text = text(next_md_path)
        for needle in ("30", "0.9857", "62.22"):
            if needle not in md_text:
                problems.append(f"{next_md_path} does not carry {needle}")
        if problems:
            return warn(
                f"benchmark/results/{Path(summary_path).name} exists ({summary['generated_at']}) but is inconsistent: "
                + "; ".join(problems) + ".",
                batch_runs=len(batch["runs"]), imported=len(present),
                summary_generated_at=summary["generated_at"], problems=problems,
            )
        return ok(
            f"All {len(present)} batch outputs exist; {summary_path} ({summary['generated_at']}) validates "
            f"30/30 runs with 0 failed design checks and {next_md_path} carries the headline numbers.",
            batch_runs=len(batch["runs"]), imported=len(present),
            summary_generated_at=summary["generated_at"],
            design_checks_total=summary["validation"]["design_checks_total"],
        )

    def f4():
        eq((MD_PATH.name, JSON_PATH.name), ("next_iteration_audit.md", "next_iteration_audit.json"),
           "assigned audit filenames")
        missing = [path for path in PUBLICATION_PATHS
                   if not (ROOT / path).exists()
                   and (ROOT / path).resolve() not in {JSON_PATH, MD_PATH}]
        report = text(REPORT_MD)
        tex = text(REPORT_TEX)
        wrong = [name for name, body in ((REPORT_MD, report), (REPORT_TEX, tex))
                 if "pair_diff/report.md" in body]
        parts = []
        if missing:
            parts.append("Publication docs reference paths that do not exist: " + ", ".join(missing))
        if wrong:
            parts.append("the report/TeX product map points to pair_diff/report.md instead of "
                         "pair_diff/results/report.md")
        if not parts:
            return ok(
                "Publication paths resolve, the audit uses the assigned filenames, and the report/TeX "
                "product map points to pair_diff/results/report.md.",
                paths=list(PUBLICATION_PATHS),
            )
        return warn(
            "; ".join(parts)
            + f". The assigned audit artifacts are audit/{JSON_PATH.name} and audit/{MD_PATH.name}.",
            missing=missing, stale_pair_path=wrong,
        )

    def f5():
        path = Path(__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        forbidden = {"requests", "httpx", "urllib", "urllib3", "http", "socket", "openai", "anthropic", "subprocess"}
        eq(imported & forbidden, set(), "network/process imports")
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name)
                        and node.func.value.id in {"os", "subprocess"}
                        and node.func.attr in {"system", "popen", "run", "call", "check_output", "check_call"}):
                    raise AuditFailure("process call in audit source")
        return ok(
            "Audit script uses only the standard library, makes no network/model call and runs no git/gh command; it writes only the two audit files.",
            imports=sorted(imported), writes=["audit/next_iteration_audit.json", "audit/next_iteration_audit.md"],
        )

    check(checks, "F1", "cross", "Old results and frozen hashes are preserved", f1)
    check(checks, "F2", "cross", "Unified report matches the audited numbers", f2)
    check(checks, "F3", "cross", "Benchmark aggregate/README refreshed", f3, warn_must_fix=True)
    check(checks, "F4", "cross", "Publication paths and audit filename", f4, warn_must_fix=True)
    check(checks, "F5", "cross", "Audit is read-only and offline", f5)

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def publication_note(overall, counts):
    missing = [path for path in ("audit/next_iteration_audit.md", "audit/next_iteration_audit.json", "benchmark/results/NEXT_ITERATION.md")
               if not (ROOT / path).exists()]
    wrong = ("pair_diff/report.md" in text(REPORT_MD)
             or "pair_diff/report.md" in text(ROOT / "report" / "report_next_zh.tex"))
    if not missing and not wrong:
        return {"status": "CURRENT", "detail": "Publication paths resolve."}
    parts = []
    if missing:
        parts.append("missing: " + ", ".join(f"`{path}`" for path in missing))
    if wrong:
        parts.append("the report/TeX product map points to `pair_diff/report.md` instead of `pair_diff/results/report.md`")
    return {
        "status": "STALE",
        "detail": (
            "Publication docs reference paths that do not resolve: " + "; ".join(parts)
            + f". The assigned audit artifacts are `audit/{JSON_PATH.name}` and `audit/{MD_PATH.name}`. "
            "The publication pass must reconcile the names before release; this audit does not edit README.md or docs/."
        ),
        "files": missing,
        "wrong_pair_path": wrong,
    }


def build_doc(checks, old_audit_before):
    counts = collections.Counter(item["status"] for item in checks)
    must = [item for item in checks if item["must_fix"]]
    warnings = [item for item in checks if item["status"] == "WARN"]
    overall = "FAIL" if counts["FAIL"] else ("PASS_WITH_WARNINGS" if counts["WARN"] else "PASS")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "root": str(ROOT),
        "overall": overall,
        "api_calls": 0,
        "network": "none",
        "publication_note": publication_note(overall, counts),
        "writes": ["audit/next_iteration_audit.json", "audit/next_iteration_audit.md"],
        "scope": {
            "groups": [
                "codeql_triage (test 140, 23 FP, TP-deletion audit)",
                "pair_diff (8 full runs, 1,440 records; 8 pilot runs, 64 records)",
                "verifier_conservative (4 arms, 236 requests)",
                "dynamic_coverage (140 units x 3 modes)",
                "interpretable_baseline (dev40 -> test160 isolation)",
                "research/next_iteration_rationale.md (read-only context)",
            ],
            "out_of_scope": [
                "benchmark/extensions aggregate/README refresh (30 canonical outputs are checked, not regenerated)",
                "report/PDF/README edits",
                "git/gh operations",
            ],
            "method": "Read stored artifacts only; recompute prompts, joins, hashes, costs and metrics from raw records where possible.",
        },
        "counts": {"total": len(checks), "pass": counts["PASS"], "warn": counts["WARN"],
                   "fail": counts["FAIL"], "info": counts["INFO"]},
        "must_fix": [{"id": item["id"], "area": item["area"], "status": item["status"],
                      "title": item["title"], "detail": item["detail"]} for item in must],
        "warnings": [{"id": item["id"], "area": item["area"], "title": item["title"],
                      "detail": item["detail"]} for item in warnings],
        "checks": checks,
        "preserved_old_audit": {name: utc(mtime) for name, mtime in sorted(old_audit_before.items())},
    }


def cell(value, limit=360):
    body = " ".join(str(value).split())
    if len(body) > limit:
        body = body[: limit - 1] + "…"
    return body.replace("|", "\\|")


def render(doc):
    lines = [
        "# Next-iteration release audit (2026-11-22)",
        "",
        f"Generated: {doc['generated_at_utc']}  ",
        f"Overall: **{doc['overall']}**  ",
        f"Checks: {doc['counts']['pass']} PASS, {doc['counts']['fail']} FAIL, "
        f"{doc['counts']['warn']} WARN, {doc['counts']['info']} INFO ({doc['counts']['total']} total).",
        "",
        "Scope: read-only audit of the 2026-11-22 next-iteration results — `codeql_triage` "
        "(test 140, 23 CodeQL FPs, TP-deletion audit), `pair_diff` (8 full runs / 1,440 records), "
        "`verifier_conservative` (4 arms / 236 requests), `dynamic_coverage` (140 units x 3 modes) "
        "and `interpretable_baseline` (dev40 -> test160 isolation), plus prompt leakage, cost, "
        "preservation of the older results and report/benchmark consistency. No model API was called; "
        "prompts, joins, hashes, costs and metrics were recomputed from stored artifacts.",
        "",
        "## Must fix",
        "",
    ]
    if doc["must_fix"]:
        lines += [f"- **{item['id']} ({item['status']}) — {item['title']}**: {item['detail']}"
                  for item in doc["must_fix"]]
    else:
        lines.append("- None.")
    lines += ["", "## Warnings", ""]
    if doc["warnings"]:
        lines += [f"- **{item['id']} — {item['title']}**: {item['detail']}" for item in doc["warnings"]]
    else:
        lines.append("- None.")
    note = doc.get("publication_note") or {}
    if note.get("status") == "STALE":
        lines += ["", "## Publication note", "", note["detail"]]
        for path in note.get("files", []):
            lines.append(f"- missing `{path}`")
    lines += ["", "## All checks", "", "| ID | Area | Status | Check | Result |",
              "| --- | --- | --- | --- | --- |"]
    for item in doc["checks"]:
        lines.append(f"| {item['id']} | {item['area']} | **{item['status']}** | "
                     f"{cell(item['title'], 150)} | {cell(item['detail'])} |")
    lines += [
        "",
        "## Reading notes",
        "",
        "- **CodeQL triage.** 140 frozen test units, 70/70; CodeQL is 68 TP / 23 FP / 47 TN / 2 FN. "
        "All 23 FPs are C++ good units on `cpp/memory-may-not-be-freed` (15 `_33`, 3 `_22`, 3 `_72`, 2 `_54`). "
        "v1 deletes 7 TPs, all `malloc_realloc_*`; v2 and the verifier delete 0/68. The final 68/0/70/2 "
        "depends on the 3 `_22` consistency flips, which the report states explicitly.",
        "- **Pair diff.** 8 full runs x 180 = 1,440 records, all `ok`; 0 invalid by decision validity. "
        "Two MiMo outputs add a `confidence_note`/`rationale_note` key, so schema-exact is 1,438/1,440 "
        "(99.44%); the report discloses this. The open baseline is the published `pair_debias` 720 records, "
        "not a new run.",
        "- **Conservative verifier.** 236 real requests (60/60/58/58), 233 ok / 2 invalid / 1 API error; "
        "4 retractions (TP 3 / FP 1), precision 25.0%. All failures keep the first-pass prediction (fail-open); "
        "`insufficient` never retracts.",
        "- **Coverage.** 140 units x 3 modes = 420 runs, 0 compile/coverage errors. Default 58/0/70/12; "
        "three-mode union 70/0/70/0. Effective line coverage is 100%, branch coverage 52.7%, and the 21 "
        "`branch_complete` units are all bad. The 12 default FNs are line-complete: coverage explains "
        "execution, not leak absence.",
        "- **Interpretable baseline.** dev40/test160 idx, project, body-MD5 and project+commit overlaps are "
        "all 0. Thresholds (chars 1504, calls 16, positive rate 0.8) and the selected rule are dev-only. "
        "The README's pre-registration timestamp is not verifiable (README mtime is after metrics.json).",
        "- **Report/benchmark.** `codeql_triage/benchmark_export.json` and `pair_diff/results/benchmark_export.json` "
        "reproduce from raw records and agree with `report/next_results_summary.md`. The benchmark import batch "
        "(`benchmark/extensions/configs/next_iteration_batch.json`, 30 runs) has 30/30 output directories, but "
        "`benchmark/results/extension_summary.json` is still 2026-11-13 and `benchmark/NEXT_ITERATION.md` is absent. "
        "Publication docs also reference `audit/next_audit.md`/`.json`, while this audit is assigned "
        "`audit/next_iteration_audit.md`/`.json`.",
        "- **Out of scope.** No git/gh operation, no API call and no edit outside `audit/` were made by this audit. "
        "The older `pair_debias`, `evidence_verify`, `dynamic_enhanced`, `hybrid_dynamic_enhanced`, "
        "`static_extended` and `benchmark/results` artifacts keep their pre-2026-11-22 mtimes and record counts.",
        "",
        "## Files written",
        "",
        "- `audit/next_iteration_audit.json`",
        "- `audit/next_iteration_audit.md`",
        "",
        "Reproduce with `python3 audit/run_next_iteration_audit.py` (read-only; no network).",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    global ROOT, AUDIT_DIR, JSON_PATH, MD_PATH
    parser = argparse.ArgumentParser(description="Read-only audit of the 2026-11-22 next-iteration results")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    args = parser.parse_args(argv)
    ROOT = args.root.resolve()
    AUDIT_DIR = ROOT / "audit"
    JSON_PATH = (args.json or (AUDIT_DIR / "next_iteration_audit.json")).resolve()
    MD_PATH = (args.md or (AUDIT_DIR / "next_iteration_audit.md")).resolve()
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    old_before = {}
    for name in ("final_audit.json", "final_audit.md", "latest_audit.json", "latest_audit.md"):
        path = AUDIT_DIR / name
        if path.exists():
            old_before[name] = path.stat().st_mtime

    checks = []
    audit_codeql(checks)
    audit_pair_diff(checks)
    audit_conservative(checks)
    audit_dynamic_coverage(checks)
    audit_interpretable(checks)
    audit_cross(checks)

    doc = build_doc(checks, old_before)
    JSON_PATH.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MD_PATH.write_text(render(doc), encoding="utf-8")
    print(f"{doc['overall']}: {doc['counts']['pass']} PASS, {doc['counts']['fail']} FAIL, "
          f"{doc['counts']['warn']} WARN, {doc['counts']['info']} INFO ({doc['counts']['total']} checks)")
    for item in doc["must_fix"]:
        print(f"  must fix {item['id']}: {item['title']} — {item['detail']}")
    return 0 if doc["overall"] != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())

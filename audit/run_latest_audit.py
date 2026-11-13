#!/usr/bin/env python3
"""Read-only audit of the 2026-11-14 result additions.

Covers pair_debias (6 runs / 1,080 records), evidence_verify (4 arms),
dynamic_enhanced (test 140), hybrid_dynamic_enhanced (280 requests),
static_extended CodeQL (200 units / test 140) and analysis/schema_recovery
(102 invalid repair records), plus the latest literature files and preservation
of the old results.

No model or network call is made.  Only audit/latest_audit.json and
audit/latest_audit.md are written.
"""

from __future__ import annotations

import argparse
import collections
import datetime as _dt
import hashlib
import importlib
import json
import math
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

SCHEMA_VERSION = "latest-audit-2026-11-14.2"
ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "audit"
JSON_PATH = AUDIT_DIR / "latest_audit.json"
MD_PATH = AUDIT_DIR / "latest_audit.md"


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
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def jlines(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def text(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
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


def mcnemar(b, c):
    n = int(b) + int(c)
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(int(b), int(c)) + 1))
    return min(1.0, 2.0 * tail / float(2 ** n))


def cost(usage, prices):
    inp, outp, cachedp = prices
    prompt = usage["prompt_tokens"]
    completion = usage["completion_tokens"]
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
    if not isinstance(cached, int) or cached < 0 or cached > prompt:
        cached = 0
    return ((prompt - cached) * inp + cached * cachedp + completion * outp) / 1_000_000.0


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


# ---------------------------------------------------------------------------
# Frozen inputs and shared loaders
# ---------------------------------------------------------------------------

PAIR_MODELS = ("deepseek", "mimo")
PAIR_NEW = ("forced_rev", "open_fwd", "open_rev")
PAIR_ALL = ("forced_fwd",) + PAIR_NEW
PRICES_PAIR = {"deepseek-v4.1-flash": (0.3, 1.2, 0.006), "mimo-v2.6-flash": (0.14, 0.28, 0.0028)}

EVIDENCE_ARMS = {
    "deepseek_self": ("deepseek", "test_verify_deepseek_self"),
    "deepseek_cross": ("deepseek", "test_verify_deepseek_by_mimo"),
    "mimo_self": ("mimo", "test_verify_mimo_self"),
    "mimo_cross": ("mimo", "test_verify_mimo_by_deepseek"),
}

DEEPSEEK_RUNS = (
    "test_v1_direct_independent", "test_v1_direct_pairs",
    "test_v1_few-shot_independent", "test_v1_few-shot_pairs",
    "test_v1_context_independent", "test_v1_context_pairs",
)
MIMO_RUNS = tuple("test_v1_mimo_" + run.split("test_v1_", 1)[1] for run in DEEPSEEK_RUNS)


def pair_dir(model, cond):
    if cond == "forced_fwd":
        return ROOT / "pair_joint" / "runs" / f"test_{model}_180"
    return ROOT / "pair_debias" / "runs" / f"test_{model}_{cond}"


def pair_map(model, cond):
    return jload(pair_dir(model, cond) / "position_map.json")["assignments"]


def pair_analysis(model):
    return jload(ROOT / "pair_debias" / "results" / f"analysis_{model}.json")


def dynamic_units():
    return {row["unit_id"]: row for row in jlines(ROOT / "juliet" / "subset_units.jsonl")}


def dynamic_rows():
    return jlines(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "results_units.jsonl")


def hde_units():
    return {row["unit_id"]: row for row in jlines(ROOT / "hybrid_dynamic_enhanced" / "inputs" / "units.jsonl")}


def hde_rows(model):
    return jlines(ROOT / "hybrid_dynamic_enhanced" / "runs" / f"enhanced_dynamic_v1_{model}" / "results.jsonl")


def v2_rows(model, method):
    return {row["unit_id"]: row for row in jlines(ROOT / "hybrid" / "runs" / f"hybrid_v2_{model}_{method}" / "results.jsonl")}


def schema_doc():
    return jload(ROOT / "analysis" / "schema_recovery" / "schema_recovery.json")


def schema_records():
    return jlines(ROOT / "analysis" / "schema_recovery" / "records.jsonl")


# ---------------------------------------------------------------------------
# A. pair_debias
# ---------------------------------------------------------------------------


def audit_pair(checks):
    def a1():
        total = 0
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                d = pair_dir(model, cond)
                rows = jlines(d / "results.jsonl")
                eq(len(rows), 180, f"{d.name} rows")
                eq(len({r["pair_id"] for r in rows}), 180, f"{d.name} pairs")
                eq(dict(collections.Counter(r["status"] for r in rows)), {"ok": 180}, f"{d.name} statuses")
                man = jload(d / "manifest.json")
                eq(man["status"], "completed", f"{d.name} status")
                eq(man["partial"], False, f"{d.name} partial")
                eq(man["counts"]["recorded_requests"], 180, f"{d.name} recorded")
                total += len(rows)
        eq(total, 1080, "new records")
        return ok("Six runs x 180 = 1,080 records, all ok, no partial run.")

    def a2():
        base = pair_map("deepseek", "forced_fwd")
        eq(base, pair_map("mimo", "forced_fwd"), "base map differs by model")
        eq(dict(collections.Counter(v["vulnerable_slot"] for v in base.values())), {"A": 90, "B": 90}, "base balance")
        n = 0
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                mapping = pair_map(model, cond)
                eq(len(mapping), 180, f"{model}/{cond} pairs")
                for pid, entry in base.items():
                    got = mapping[pid]
                    eq(got["order_index"], entry["order_index"], f"{pid} order")
                    eq(got["digest"], entry["digest"], f"{pid} digest")
                    if cond.endswith("_rev"):
                        req(got["vulnerable_slot"] != entry["vulnerable_slot"], f"{pid} not reversed")
                    else:
                        eq(got["vulnerable_slot"], entry["vulnerable_slot"], f"{pid} changed")
                    n += 1
        eq(n, 1080, "slot checks")
        return ok("Forward maps equal the pair_joint base; reverse maps are exact complements; 90/90.")

    def a3():
        expected = {
            ("deepseek", "forced_fwd"): 138, ("deepseek", "forced_rev"): 140,
            ("deepseek", "open_fwd"): 119, ("deepseek", "open_rev"): 115,
            ("mimo", "forced_fwd"): 156, ("mimo", "forced_rev"): 147,
            ("mimo", "open_fwd"): 119, ("mimo", "open_rev"): 118,
        }
        values = {}
        for model in PAIR_MODELS:
            analysis = pair_analysis(model)
            for cond in PAIR_ALL:
                mapping = pair_map(model, cond)
                rows = jlines(pair_dir(model, cond) / "results.jsonl")
                correct = invalid = abstain = 0
                for row in rows:
                    choice = (row.get("parsed") or {}).get("vulnerable_version")
                    if row["status"] != "ok" or choice not in {"A", "B", "both", "neither"}:
                        invalid += 1
                    elif choice in {"both", "neither"}:
                        abstain += 1
                    else:
                        correct += choice == mapping[row["pair_id"]]["vulnerable_slot"]
                eq(correct, expected[(model, cond)], f"{model}/{cond} correct")
                eq(invalid, 0, f"{model}/{cond} invalid")
                eq(analysis["conditions"][cond]["counts"]["categories"]["correct"], correct, f"{model}/{cond} JSON")
                close(analysis["conditions"][cond]["accuracy"]["all_pairs"], correct / 180, f"{model}/{cond} DA")
                values[f"{model}/{cond}"] = {"correct": correct, "abstain": abstain}
        summary = text(ROOT / "pair_debias" / "results" / "summary.md")
        for v in ("76.67%", "77.78%", "66.11%", "63.89%", "86.67%", "81.67%", "65.56%"):
            req(v in summary, f"summary missing {v}")
        report = text(ROOT / "pair_debias" / "report.md")
        for v in ("61.67%", "55.56%", "74.44%", "58.33%"):
            req(v in report, f"report missing {v}")
        return ok("DA reproduces per condition, analysis JSON, summary and report.", values=values)

    def a4():
        out = {}
        for model in PAIR_MODELS:
            analysis = pair_analysis(model)
            for task in ("forced", "open"):
                fwd = {r["pair_id"]: r for r in jlines(pair_dir(model, f"{task}_fwd") / "results.jsonl")}
                rev = {r["pair_id"]: r for r in jlines(pair_dir(model, f"{task}_rev") / "results.jsonl")}
                fmap, rmap = pair_map(model, f"{task}_fwd"), pair_map(model, f"{task}_rev")

                def sem(choice, pid, m):
                    slot = m[pid]["vulnerable_slot"]
                    if choice in {"A", "B"}:
                        return "vulnerable" if choice == slot else "fixed"
                    return choice

                both = same = agree = ab = 0
                for pid, left in fwd.items():
                    lc = (left.get("parsed") or {}).get("vulnerable_version")
                    rc = (rev[pid].get("parsed") or {}).get("vulnerable_version")
                    ls, rs = sem(lc, pid, fmap), sem(rc, pid, rmap)
                    agree += ls == rs
                    both += ls == rs == "vulnerable"
                    if lc in {"A", "B"} and rc in {"A", "B"}:
                        ab += 1
                        same += lc == rc
                exp = analysis["exchange"][task]
                eq(both, int(round(exp["da_both_orders"] * 180)), f"{model}/{task} exchange DA")
                eq(agree, exp["semantic_agreement"], f"{model}/{task} agreement")
                eq(same, exp["same_letter"], f"{model}/{task} same letter")
                out[f"{model}/{task}"] = {"both": both, "agree": agree, "same": same, "same_rate": same / ab if ab else None}
        eq(out["deepseek/forced"]["both"], 111, "DS forced exchange")
        eq(out["deepseek/open"]["both"], 100, "DS open exchange")
        eq(out["mimo/forced"]["both"], 134, "MiMo forced exchange")
        eq(out["mimo/open"]["both"], 105, "MiMo open exchange")
        pairs = jload(ROOT / "splits" / "test_pairs_180.json")["pairs"]
        base = pair_map("deepseek", "forced_fwd")
        forward = semantic = 0
        for pair in pairs:
            slot = base[pair["pair_id"]]["vulnerable_slot"]
            lv = len(pair["vulnerable"]["func_body"])
            lf = len(pair["fixed"]["func_body"])
            la, lb = (lv, lf) if slot == "A" else (lf, lv)
            forward += ("A" if la <= lb else "B") == slot
            semantic += lv < lf
        eq(forward, 134, "single-order length heuristic")
        eq(semantic, 130, "same-semantic length heuristic")
        close(forward / 180, 0.7444444444444445, "74.44%")
        close(semantic / 180, 0.7222222222222222, "72.22%")
        for doc in ("README.md", "report.md"):
            body = text(ROOT / "pair_debias" / doc)
            req("74.44%" in body and "72.22%" in body, f"{doc} length baseline missing")
        return ok("Exchange-consistency DA, semantic agreement, same-letter rate and the 74.44% / 72.22% length baselines all reproduce.", values=out)

    def a5():
        meta_re = re.compile(r"(pair_id|request_index|commit_id|commit_message|filepath|func_name|fixed_func_idx|changed_lines|changed_statements|cve_list|cwe_list|is_vulnerable|project_url)")
        slot_re = re.compile(r"vulnerable_slot|fixed_slot")
        cve_re = re.compile(r"\bCVE-\d{4}-\d+\b|\bCWE-\d+\b")
        wrapper_sets = collections.defaultdict(set)
        scanned = 0
        cves = set()
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                d = pair_dir(model, cond)
                audit = jload(d / "leak_audit.json")
                eq(audit["wrapper_clean_all"], True, f"{d.name} wrapper")
                eq(audit["slot_leak_all"], False, f"{d.name} slot")
                eq(len(audit["pairs"]), 180, f"{d.name} audit pairs")
                for request in jlines(d / "requests.jsonl"):
                    system, user = (m["content"] for m in request["messages"])
                    stripped = re.sub(r"<VERSION_A>.*?</VERSION_A>", "<CODE>", user, flags=re.S)
                    stripped = re.sub(r"<VERSION_B>.*?</VERSION_B>", "<CODE>", stripped, flags=re.S)
                    for body, where in ((system, "system"), (stripped, "wrapper")):
                        req(meta_re.search(body) is None, f"{d.name} {where} metadata leak")
                        req(slot_re.search(body) is None, f"{d.name} {where} slot leak")
                        req(not cve_re.search(body), f"{d.name} {where} CVE/CWE outside code")
                    wrapper_sets[cond].add(sha_text(system + "\n" + stripped))
                    cves.update(cve_re.findall(user))
                    scanned += 1
        eq(len(cves), 1, "CVE/CWE in body")
        eq(next(iter(cves)), "CVE-2017-17969", "unexpected CVE")
        for cond, hashes in wrapper_sets.items():
            eq(len(hashes), 1, f"{cond} wrapper not constant")
        return ok("All 1,080 prompts are metadata/slot-free outside code; only the documented CVE-2017-17969 comment remains in one pair's body.", scanned=scanned, body_cve=sorted(cves))

    def a6():
        hits = 0
        calls = 0
        per_run = {}
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                d = pair_dir(model, cond)
                rows = jlines(d / "results.jsonl")
                keys = {r["request"]["request_fingerprint"] for r in rows}
                files = list((d / "cache").rglob("*.json"))
                eq({p.stem for p in files}, keys, f"{d.name} cache keys")
                eq(len(files), 180, f"{d.name} cache files")
                run_hits = [r for r in rows if (r.get("cache") or {}).get("hit")]
                hits += len(run_hits)
                calls += len(rows) - len(run_hits)
                for row in run_hits:
                    key = row["request"]["request_fingerprint"]
                    cached = jload(next(p for p in (d / "cache").rglob(key + ".json")))
                    eq(cached["cache_key"], key, f"{d.name} cached key")
                    eq(cached["prompt_sha256"], row["prompt_sha256"], f"{d.name} cached prompt")
                    eq(cached["status"], "ok", f"{d.name} cached status")
                per_run[d.name] = {"records": len(rows), "hits": len(run_hits)}
        eq(hits, 51, "cache hits")
        eq(calls, 1029, "new API calls")
        readme = text(ROOT / "pair_debias" / "README.md")
        report = text(ROOT / "pair_debias" / "report.md")
        for name, body in (("README.md", readme), ("report.md", report)):
            req("1,080 条记录" in body or "1,080 records" in body, f"{name} lacks the 1,080 records statement")
            req("1,029" in body, f"{name} lacks 1,029 new requests")
            req("51" in body, f"{name} lacks the 51 cached records")
            req(not re.search(r"1,080\s*(?:条)?\s*新请求", body), f"{name} still says 1,080 new requests")
        req("129" in report, "report.md lacks the 129 newly issued requests")
        req("test_mimo_open_rev" in readme and "test_mimo_open_rev" in report, "resumed run not named")
        req("第 51" in report or "51 条缓存" in report, "report.md does not identify the 51 cached records")
        detail = ("1,080 stored records = 1,029 newly issued requests + 51 cached responses from "
                  "test_mimo_open_rev; cache keys equal request fingerprints and README/report both "
                  "state the split (129 newly issued requests for the resumed run).")
        return ok(detail, per_run=per_run, hits=hits, new_calls=calls)

    def a7():
        total = 0.0
        per = {}
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                d = pair_dir(model, cond)
                cfg = jload(d / "config.json")
                prices = PRICES_PAIR[cfg["api"]["model"]]
                close(cfg["api"]["input_price_usd_per_1m"], prices[0], f"{d.name} input price")
                rows = jlines(d / "results.jsonl")
                value = sum(cost(r["response"]["usage"], prices) for r in rows)
                close(value, jload(d / "metrics.json")["usage"]["cost_usd"], f"{d.name} metrics cost")
                for row in rows:
                    close(row["response"]["cost"]["cost_usd"], cost(row["response"]["usage"], prices), f"{d.name} row cost")
                per[d.name] = round(value, 9)
                total += value
        reused = 0.0
        for model in PAIR_MODELS:
            d = pair_dir(model, "forced_fwd")
            prices = PRICES_PAIR[jload(d / "config.json")["api"]["model"]]
            reused += sum(cost(r["response"]["usage"], prices) for r in jlines(d / "results.jsonl"))
        close(total, 0.676604818, "new cost")
        close(reused, 0.225396364, "reused cost")
        close(total + reused, 0.902001182, "all-in")
        for doc in ("README.md", "report.md"):
            body = text(ROOT / "pair_debias" / doc)
            req("0.676605" in body and "0.902001" in body, f"{doc} cost missing")
        return ok(f"New ${total:.6f}; reused ${reused:.6f}; all-in ${total + reused:.6f}.", per_run=per, reused=round(reused, 9))

    def a8():
        for model in PAIR_MODELS:
            for cond in PAIR_NEW:
                d = pair_dir(model, cond)
                cfg, man = jload(d / "config.json"), jload(d / "manifest.json")
                eq(cfg["api_key_value_stored"], False, f"{d.name} key stored")
                eq(man["partial"], False, f"{d.name} partial")
                eq(man["status"], "completed", f"{d.name} status")
                eq(man["dataset_sha256"], "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d", f"{d.name} dataset")
                eq(cfg["dataset_sha256"], man["dataset_sha256"], f"{d.name} config dataset")
                eq(cfg["selected_units"], 180, f"{d.name} units")
                for row in jlines(d / "requests.jsonl"):
                    eq(row["authorization_header_omitted"], True, f"{d.name} auth header")
        return ok("Six manifests complete/unpartial; dataset hash frozen; keys never stored; Authorization omitted.")

    check(checks, "A1", "pair_debias", "Six complete runs, 1,080 records", a1)
    check(checks, "A2", "pair_debias", "Forward/reverse maps exact, 90/90", a2)
    check(checks, "A3", "pair_debias", "DA reproduces per condition", a3)
    check(checks, "A4", "pair_debias", "Exchange consistency reproduces", a4)
    check(checks, "A5", "pair_debias", "Prompts are metadata/slot-free", a5)
    check(checks, "A6", "pair_debias", "Cache/checkpoint and resume are consistent", a6)
    check(checks, "A7", "pair_debias", "Configured cost recomputes", a7)
    check(checks, "A8", "pair_debias", "Manifests, hashes and credentials are clean", a8)


# ---------------------------------------------------------------------------
# B. evidence_verify
# ---------------------------------------------------------------------------


def audit_evidence(checks):
    first_cache = {model: {r["idx"]: r for r in jlines(ROOT / "evidence_prompt" / "runs" / f"test_evidence_{model}" / "results.jsonl")} for model in ("deepseek", "mimo")}
    verify_cache = {arm: {r["idx"]: r for r in jlines(ROOT / "evidence_verify" / "runs" / run / "results.jsonl")} for arm, (_, run) in EVIDENCE_ARMS.items()}

    def pre(row):
        if row["status"] != "ok":
            return None
        return bool((row.get("parsed") or {}).get("is_vulnerable") is True)

    def post(row, verifier):
        p = pre(row)
        if p is None or p is False:
            return p
        if verifier is None or verifier.get("status") != "ok":
            return False
        if not (verifier.get("validation") or {}).get("schema_valid"):
            return False
        return (verifier.get("parsed") or {}).get("verdict") == "sustain"

    def counts(pairs):
        c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        invalid = 0
        for pred, label in pairs:
            if pred is None:
                invalid += 1
            elif label and pred:
                c["tp"] += 1
            elif label:
                c["fn"] += 1
            elif pred:
                c["fp"] += 1
            else:
                c["tn"] += 1
        return c, invalid

    def b1():
        expected = {"deepseek_self": 60, "deepseek_cross": 60, "mimo_self": 58, "mimo_cross": 58}
        for arm, (_, run) in EVIDENCE_ARMS.items():
            d = ROOT / "evidence_verify" / "runs" / run
            rows = jlines(d / "results.jsonl")
            eq(len(rows), expected[arm], f"{arm} rows")
            man = jload(d / "manifest.json")
            eq(man["status"], "completed", f"{arm} status")
            eq(man["counts"]["api_errors"], 0, f"{arm} api errors")
            eq(man["counts"]["recorded_requests"], expected[arm], f"{arm} recorded")
            eq(man["counts"]["valid"], sum(1 for r in rows if r["status"] == "ok"), f"{arm} valid")
            eq(man["counts"]["invalid"], sum(1 for r in rows if r["status"] != "ok"), f"{arm} invalid")
        return ok("Arms complete at 60/60/58/58 planned records; verifier-invalid records are 0/2/1/0 and are handled fail-closed.")

    def b2():
        metrics = jload(ROOT / "evidence_verify" / "analysis" / "metrics.json")
        out = {}
        for model in ("deepseek", "mimo"):
            rows = first_cache[model]
            eq(len(rows), 160, f"{model} rows")
            c, invalid = counts([(pre(r), bool(r["label"])) for r in rows.values()])
            m = metric(**c)
            strict = sum(1 for r in rows.values() if pre(r) is not None and pre(r) == bool(r["label"]))
            exp = metrics["first_pass"][model]["scores"]
            for k in ("tp", "fp", "tn", "fn"):
                eq(c[k], exp["confusion"][k], f"{model} pre {k}")
            eq(invalid, exp["invalid"], f"{model} pre invalid")
            for k in ("precision", "recall", "macro_f1", "mcc", "accuracy"):
                close(m[k], exp[k], f"{model} pre {k}")
            close(strict / 160, exp["strict_accuracy"], f"{model} pre strict")
            out[model] = {"confusion": c, "invalid": invalid, "strict": strict}
        return ok("First-pass metrics reproduce (DeepSeek 159 valid + 1 invalid, MiMo 158 + 2).", values=out)

    def b3():
        metrics = jload(ROOT / "evidence_verify" / "analysis" / "metrics.json")
        out = {}
        for arm, (model, _) in EVIDENCE_ARMS.items():
            rows = first_cache[model]
            ver = verify_cache[arm]
            c, invalid = counts([(post(r, ver.get(idx)), bool(r["label"])) for idx, r in rows.items()])
            m = metric(**c)
            strict = sum(1 for idx, r in rows.items() if post(r, ver.get(idx)) is not None and post(r, ver.get(idx)) == bool(r["label"]))
            exp = metrics["arms"][arm]["scores"]["post_fail_closed"]
            for k in ("tp", "fp", "tn", "fn"):
                eq(c[k], exp["confusion"][k], f"{arm} post {k}")
            eq(invalid, exp["invalid"], f"{arm} post invalid")
            for k in ("precision", "recall", "macro_f1", "mcc"):
                close(m[k], exp[k], f"{arm} post {k}")
            close(strict / 160, exp["strict_accuracy"], f"{arm} post strict")
            counts_doc = metrics["arms"][arm]["prediction_counts"]["fail_closed"]
            eq(sum(1 for r in rows.values() if pre(r) is False), counts_doc["untouched_negative"], f"{arm} negatives")
            eq(sum(1 for r in rows.values() if pre(r) is None), counts_doc["untouched_invalid"], f"{arm} invalid untouched")
            retracted = []
            for idx, row in rows.items():
                if pre(row) is not True:
                    continue
                verifier = ver.get(idx)
                if verifier and verifier.get("status") == "ok" and (verifier.get("validation") or {}).get("schema_valid") and (verifier.get("parsed") or {}).get("verdict") == "retract":
                    retracted.append(row)
            exp_ret = metrics["arms"][arm]["retraction"]
            tp_ret = sum(1 for row in retracted if row["label"])
            fp_ret = len(retracted) - tp_ret
            eq(len(retracted), exp_ret["retracted"], f"{arm} retracted")
            eq(tp_ret, exp_ret["tp_retracted"], f"{arm} TP retracted")
            eq(fp_ret, exp_ret["fp_retracted"], f"{arm} FP retracted")
            close(fp_ret / len(retracted), exp_ret["retraction_precision"], f"{arm} retraction precision")
            out[arm] = {"confusion": c, "invalid": invalid, "retracted": len(retracted), "tp_retracted": tp_ret, "fp_retracted": fp_ret}
        return ok("Fail-closed post metrics and retraction precision reproduce; negatives and pre-invalid rows are untouched.", values=out)

    def b4():
        metrics = jload(ROOT / "evidence_verify" / "analysis" / "metrics.json")
        out = {}
        for arm, (model, _) in EVIDENCE_ARMS.items():
            rows = first_cache[model]
            ver = verify_cache[arm]
            pre_ok = post_ok = up = down = 0
            for idx, r in rows.items():
                label = bool(r["label"])
                a, b = pre(r), post(r, ver.get(idx))
                a_ok = a is not None and a == label
                b_ok = b is not None and b == label
                pre_ok += a_ok
                post_ok += b_ok
                up += (not a_ok) and b_ok
                down += a_ok and (not b_ok)
            exp = metrics["arms"][arm]["mcnemar_pre_vs_post_fail_closed"]
            eq(pre_ok, exp["pre_correct"], f"{arm} pre correct")
            eq(post_ok, exp["post_correct"], f"{arm} post correct")
            eq(up, exp["pre_wrong_post_correct"], f"{arm} up")
            eq(down, exp["pre_correct_post_wrong"], f"{arm} down")
            close(mcnemar(up, down), exp["p_value_exact_two_sided"], f"{arm} p")
            out[arm] = {"pre": pre_ok, "post": post_ok, "p": mcnemar(up, down)}
        return ok("Exact McNemar pre-vs-post reproduces for all four arms.", values=out)

    def b5():
        sys.path.insert(0, str(ROOT))
        module = importlib.import_module("evidence_verify.evidence_verify.verifier_prompt")
        dataset = {s["idx"]: s for s in jload(ROOT / "splits" / "test_detection_160.json")["samples"]}
        meta_re = re.compile(r"(fixed_func_idx|changed_lines|changed_statements|cve_list|cwe_list|commit_id|commit_message|func_name|project_url|is_vulnerable|filepath)")
        rebuilt = 0
        for arm, (_, run) in EVIDENCE_ARMS.items():
            for row in jlines(ROOT / "evidence_verify" / "runs" / run / "results.jsonl"):
                sample = dataset[row["idx"]]
                meta = row["prompt"]
                eq(meta["input_fields"], ["func_body", "claim.evidence_lines", "claim.mechanism"], f"{arm} fields")
                eq(meta["only_source_and_claim_variable"], True, f"{arm} isolation")
                eq(meta["template_forbidden_tokens_present"], [], f"{arm} template")
                prompt = module.build_prompt(sample["func_body"], row["claim"]["evidence_lines"], row["claim"]["mechanism"])
                eq(hashlib.sha256(module.prompt_bytes(prompt)).hexdigest(), row["prompt_sha256"], f"{arm} prompt hash")
                eq(meta["claim"]["claim_sha256"], sha_text(",".join(str(x) for x in row["claim"]["evidence_lines"]) + "\x00" + row["claim"]["mechanism"].strip()), f"{arm} claim hash")
                eq(meta["function"]["code_sha256"], sha_text(sample["func_body"]), f"{arm} source hash")
                outside = re.sub(r"<FUNCTION_SOURCE[^>]*>.*?</FUNCTION_SOURCE>", "<SOURCE>", prompt.messages[1]["content"], flags=re.S)
                outside = re.sub(r"<CLAIM[^>]*>.*?</CLAIM>", "<CLAIM>", outside, flags=re.S)
                req(meta_re.search(outside) is None, f"{arm} metadata in wrapper")
                for field in ("project", "filepath", "commit_id", "func_name"):
                    value = sample.get(field)
                    if isinstance(value, str) and len(value) >= 4:
                        req(value not in outside, f"{arm} {field} leaked")
                rebuilt += 1
        eq(rebuilt, 236, "rebuilt prompts")
        return ok("All 236 verifier prompts rebuild byte-identically; wrapper has no label/project/path field.")

    def b6():
        hits = files = 0
        key_sets = {}
        for arm, (_, run) in EVIDENCE_ARMS.items():
            d = ROOT / "evidence_verify" / "runs" / run
            rows = jlines(d / "results.jsonl")
            keys = set()
            for row in rows:
                cache = row["cache"]
                eq(cache["hit"], False, f"{arm} hit")
                eq(cache["previous_status"], None, f"{arm} previous")
                req((d / cache["file"]).exists(), f"{arm} cache file missing")
                keys.add(cache["key"])
            eq(len(keys), len(rows), f"{arm} unique keys")
            count = len(list((d / "cache").rglob("*.json")))
            eq(count, len(rows), f"{arm} cache files")
            files += count
            key_sets[arm] = keys
            hits += sum(1 for r in rows if r["cache"]["hit"])
        eq(hits, 0, "hits")
        overlap = sum(len(key_sets[a] & key_sets[b]) for i, a in enumerate(key_sets) for b in list(key_sets)[i + 1:])
        eq(overlap, 0, "cross-arm keys")
        return ok("All 236 records have their own cache entry, zero hits and no cross-arm key reuse.")

    def b7():
        metrics = jload(ROOT / "evidence_verify" / "analysis" / "metrics.json")
        total = 0.0
        per = {}
        for arm, (_, run) in EVIDENCE_ARMS.items():
            d = ROOT / "evidence_verify" / "runs" / run
            api = jload(d / "manifest.json")["api"]
            prices = (api["input_price_usd_per_1m"], api["output_price_usd_per_1m"], api["cached_input_price_usd_per_1m"])
            value = sum(cost(r["response"]["usage"], prices) for r in jlines(d / "results.jsonl"))
            close(value, metrics["arms"][arm]["cost"]["verifier"]["total_cost_usd"], f"{arm} cost")
            per[arm] = round(value, 9)
            total += value
        close(total, 0.154333486, "verifier total")
        return ok(f"Verifier cost totals ${total:.6f}.", per_arm=per, total=round(total, 9))

    def b8():
        metrics = jload(ROOT / "evidence_verify" / "analysis" / "metrics.json")
        eq(metrics["analysis_status"], "exploratory_post_hoc_test_seen", "analysis status")
        report = text(ROOT / "evidence_verify" / "analysis" / "report.md")
        for phrase in ("探索性", "不是独立确认", "fail-closed", "fail-open", "post-hoc"):
            req(phrase in report, f"report missing {phrase}")
        return ok("Exploratory/post-hoc status and fail-closed/fail-open policies are explicit.")

    check(checks, "B1", "evidence", "Four arms complete at 60/60/58/58", b1)
    check(checks, "B2", "evidence", "First-pass metrics reproduce", b2)
    check(checks, "B3", "evidence", "Fail-closed post metrics reproduce", b3)
    check(checks, "B4", "evidence", "Exact McNemar reproduces", b4)
    check(checks, "B5", "evidence", "Prompts rebuild and stay label-free", b5)
    check(checks, "B6", "evidence", "Cache has no hits or cross-arm reuse", b6)
    check(checks, "B7", "evidence", "Verifier cost recomputes", b7)
    check(checks, "B8", "evidence", "Post-hoc status is disclosed", b8)


# ---------------------------------------------------------------------------
# C. dynamic_enhanced
# ---------------------------------------------------------------------------


def audit_dynamic(checks):
    def c1():
        frozen = dynamic_units()
        test = {uid: row for uid, row in frozen.items() if row["split"] == "test"}
        rows = dynamic_rows()
        eq(len(rows), 140, "rows")
        eq(len({r["unit_id"] for r in rows}), 140, "unique")
        eq({r["unit_id"] for r in rows}, set(test), "unit set")
        for row in rows:
            eq(row["label"], test[row["unit_id"]]["label"], f"{row['unit_id']} label")
        eq(dict(collections.Counter(r["label"] for r in rows)), {"bad": 70, "good": 70}, "labels")
        return ok("140 frozen test units, 70/70, exactly matching juliet/subset_units.jsonl.")

    def c2():
        rows = dynamic_rows()
        tp = sum(1 for r in rows if r["label"] == "bad" and r["y_pred"] == 1)
        fp = sum(1 for r in rows if r["label"] == "good" and r["y_pred"] == 1)
        tn = sum(1 for r in rows if r["label"] == "good" and r["y_pred"] == 0)
        fn = sum(1 for r in rows if r["label"] == "bad" and r["y_pred"] == 0)
        exp = jload(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "metrics.json")["confusion"]
        eq((tp, fp, tn, fn), (exp["tp"], exp["fp"], exp["tn"], exp["fn"]), "confusion")
        eq(exp["undecided"], 0, "undecided")
        close(exp["coverage"], 1.0, "coverage")
        return ok("70 TP / 0 FP / 70 TN / 0 FN; coverage 1.000 and no undecided unit.")

    def c3():
        rows = dynamic_rows()
        modes = {}
        for mode in ("default", "realloc_fail", "nogobal"):
            app = bad = good = 0
            for row in rows:
                block = row["modes"][mode]
                if block["applicable"]:
                    app += 1
                    if block["decision"] == "leak":
                        if row["label"] == "bad":
                            bad += 1
                        else:
                            good += 1
            modes[mode] = {"applicable": app, "bad_leak": bad, "good_leak": good}
        eq(modes["default"], {"applicable": 140, "bad_leak": 58, "good_leak": 0}, "default")
        eq(modes["realloc_fail"], {"applicable": 14, "bad_leak": 7, "good_leak": 0}, "realloc")
        eq(modes["nogobal"], {"applicable": 140, "bad_leak": 63, "good_leak": 0}, "nogobal")
        newly = [r for r in rows if r["unobservable_in_default"]]
        eq(len(newly), 12, "newly observable")
        eq(dict(collections.Counter(r["primary_evidence"] for r in newly)), {"realloc_fail": 7, "nogobal": 5}, "new modes")
        for row in newly:
            req(row["y_pred"] == 1, f"{row['unit_id']} not predicted")
            if row["primary_evidence"] == "realloc_fail":
                inj = row["modes"]["realloc_fail"]["injection"]
                eq(inj["injected"], True, f"{row['unit_id']} injection")
                eq(inj["injected_at_call"], 1, f"{row['unit_id']} injection index")
            # attribution must stay inside this unit's own source family
            own = {Path(s).stem for s in row["sources"]}
            for block in row["modes"].values():
                for item in block.get("attributed_blocks") or []:
                    if item.get("attributed"):
                        frame = Path((item.get("deciding_frame") or {}).get("file", "")).stem
                        req(frame in own, f"{row['unit_id']} attributed to {frame}")
        return ok("Mode counts 58/7/63; the 12 newly observable units are exactly 7 realloc-fail + 5 no-global and attribute to their own sources.", modes=modes)

    def c4():
        rows = dynamic_rows()
        problems = []
        for row in rows:
            for name, block in row["modes"].items():
                build = block.get("build") or {}
                if build and (not build.get("ok") or build.get("timed_out")):
                    problems.append(f"{row['unit_id']}/{name}")
        metrics = jload(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "metrics.json")
        verify = jload(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "verify.json")
        eq(verify["status"], "PASS", "verify status")
        eq(verify["problems"], [], "verify problems")
        req(set(metrics["failures"]) <= {"leak", "clean"}, "unexpected failure class")
        eq(problems, [], "build/run problems")
        raw = jlines(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "results_raw.jsonl")
        eq(len(raw), 420, "raw rows (140 units x 3 modes)")
        eq(len({row["unit_id"] for row in raw}), 140, "raw unique units")
        return ok("No compile failure, timeout or undecided unit; verify.json and the build/run checks are clean (the failure map only contains leak/clean decisions).")

    def c5():
        rows = {r["unit_id"]: r for r in dynamic_rows()}
        old_path = ROOT / "traditional" / "dynamic" / "runs" / "cwe401_juliet_v1_3_asan_valgrind" / "results.jsonl"
        index = collections.defaultdict(list)
        for row in jlines(old_path):
            index[(frozenset(row["sources"]), int(row["expected_label"]))].append(row)
        agree = 0
        old_bad = 0
        for row in rows.values():
            cand = index[(frozenset(row["sources"]), 1 if row["label"] == "bad" else 0)]
            eq(len(cand), 1, f"{row['unit_id']} join")
            old_leak = bool(cand[0]["detectors"]["asan"]["leak_detected"])
            eq(old_leak, row["modes"]["default"]["decision"] == "leak", f"{row['unit_id']} default vs old")
            agree += 1
            old_bad += row["label"] == "bad" and old_leak
        eq(agree, 140, "agreement")
        eq(old_bad, 58, "old observable bad")
        req(old_path.stat().st_mtime < (ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3").stat().st_mtime, "old results newer")
        return ok("Default mode agrees with the frozen old ASan run 140/140; old observable bad units remain 58/70.")

    def c6():
        forbidden = re.compile(r"(^|\n)\s*(import|from)\s+(requests|urllib|http|socket|openai|anthropic|httpx|aiohttp)\b")
        paths = list((ROOT / "dynamic_enhanced" / "dyne").glob("*.py")) + [ROOT / "dynamic_enhanced" / "run_dynamic_enhanced.py"]
        hits = [p.name for p in paths if forbidden.search(text(p))]
        eq(hits, [], "network imports")
        rows = dynamic_rows()
        req(all("model" not in row for row in rows), "model field in dynamic rows")
        return ok("Local tool run: no network/API client import and no model field in the results.")

    def c7():
        readme = text(ROOT / "dynamic_enhanced" / "README.md")
        for phrase in ("70 / 0 / 70 / 0", "12 / 12", "0 / 70", "140（bad 70 / good 70）"):
            req(phrase in readme, f"README missing {phrase}")
        metrics = jload(ROOT / "dynamic_enhanced" / "runs" / "test140_enhanced_v3" / "metrics.json")
        eq(len(metrics["good_false_positives"]), 0, "good FP")
        eq(len(metrics["good_undecided"]) + len(metrics["bad_undecided"]), 0, "undecided")
        return ok("README ceiling 70/0/70/0, 12/12 new evidence and 0/70 good FPs match the rows.")

    check(checks, "C1", "dynamic", "Test140 units and labels match the freeze", c1)
    check(checks, "C2", "dynamic", "Confusion is 70/0/70/0", c2)
    check(checks, "C3", "dynamic", "Per-mode evidence and 12 new units are exact", c3)
    check(checks, "C4", "dynamic", "No failures or undecided units", c4)
    check(checks, "C5", "dynamic", "Default mode reproduces old ASan", c5)
    check(checks, "C6", "dynamic", "No API/model usage", c6)
    check(checks, "C7", "dynamic", "README ceiling claims match rows", c7)


# ---------------------------------------------------------------------------
# D. hybrid_dynamic_enhanced
# ---------------------------------------------------------------------------


def audit_hybrid(checks):
    def d1():
        units = hde_units()
        eq(len(units), 140, "units")
        for model in ("deepseek", "mimo"):
            rows = hde_rows(model)
            eq(len(rows), 140, f"{model} rows")
            eq({r["unit_id"] for r in rows}, set(units), f"{model} unit set")
            eq(dict(collections.Counter(r["status"] for r in rows)), {"ok": 140}, f"{model} statuses")
            eq(dict(collections.Counter(r["valid"] for r in rows)), {True: 140}, f"{model} valid")
            eq(sum(1 for r in rows if r["error"]), 0, f"{model} errors")
            man = jload(ROOT / "hybrid_dynamic_enhanced" / "runs" / f"enhanced_dynamic_v1_{model}" / "manifest.json")
            eq(man["partial"], False, f"{model} partial")
            eq(man["counts"], {"ok": 140, "invalid": 0, "api_error": 0}, f"{model} counts")
        return ok("Two complete 140-unit runs, all ok/valid, zero API errors (280 requests).")

    def d2():
        metrics = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "enhanced_dynamic_metrics.json")
        out = {}
        for model in ("deepseek", "mimo"):
            rows = hde_rows(model)
            tp = sum(1 for r in rows if r["label"] and r["y_pred"] == 1)
            fp = sum(1 for r in rows if not r["label"] and r["y_pred"] == 1)
            tn = sum(1 for r in rows if not r["label"] and r["y_pred"] == 0)
            fn = sum(1 for r in rows if r["label"] and r["y_pred"] == 0)
            m = metric(tp, fp, tn, fn)
            exp = metrics["models"][model]["methods"]["hde-guided"]
            eq((tp, fp, tn, fn), (exp["tp"], exp["fp"], exp["tn"], exp["fn"]), f"{model} confusion")
            close(m["accuracy"], exp["accuracy"], f"{model} accuracy")
            close(m["mcc"], exp["mcc"], f"{model} mcc")
            out[model] = {"confusion": [tp, fp, tn, fn], "accuracy": m["accuracy"]}
        close(out["deepseek"]["accuracy"], 137 / 140, "DS accuracy")
        close(out["mimo"]["accuracy"], 136 / 140, "MiMo accuracy")
        report = text(ROOT / "hybrid_dynamic_enhanced" / "REPORT.md")
        for phrase in ("97.86% (137/140)", "97.14% (136/140)", "96.43% (135/140)"):
            req(phrase in report, f"REPORT missing {phrase}")
        return ok("HDE confusion and accuracy reproduce (DeepSeek 137/140, MiMo 136/140).", values=out)

    def d3():
        metrics = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "enhanced_dynamic_metrics.json")
        for model in ("deepseek", "mimo"):
            hde = {r["unit_id"]: r for r in hde_rows(model)}
            tool = {uid: int(r["tool_verdict"]) for uid, r in hde.items()}
            base = {method: {uid: r["y_pred"] for uid, r in v2_rows(model, method).items()} for method in ("direct", "dynamic", "combined")}
            base["tool"] = tool
            for entry in metrics["models"][model]["mcnemar"]:
                name = entry["b"]
                b = base[name.replace("v2-", "")] if name != "tool" else tool
                up = down = 0
                for uid, row in hde.items():
                    new_ok = row["y_pred"] == int(row["label"])
                    old_ok = b[uid] == int(row["label"])
                    up += new_ok and not old_ok
                    down += old_ok and not new_ok
                eq(up, entry["a_right_b_wrong"], f"{model}/{name} up")
                eq(down, entry["a_wrong_b_right"], f"{model}/{name} down")
                close(mcnemar(up, down), entry["p_value_exact"], f"{model}/{name} p")
                close(entry["delta_accuracy"], (up - down) / 140, f"{model}/{name} delta")
        eq(metrics["models"]["deepseek"]["mcnemar"][0]["p_value_exact"], 0.5, "DS direct p")
        eq(metrics["models"]["mimo"]["mcnemar"][0]["p_value_exact"], 1.0, "MiMo direct p")
        return ok("Paired counts, exact p-values and deltas reproduce for all four baselines.")

    def d4():
        sys.path.insert(0, str(ROOT / "hybrid_dynamic_enhanced"))
        sys.path.insert(0, str(ROOT / "hybrid"))
        sys.path.insert(0, str(ROOT))
        module = importlib.import_module("hde.prompts")
        units = hde_units()
        bad = re.compile(r"(?i)\b(benign|fixed)\b|CWE-?\d|Memory_Leak|juliet/|/mnt/|\.c(?:pp)?\b")
        hashes = set()
        rebuilt = direct = 0
        for model in ("deepseek", "mimo"):
            v2 = v2_rows(model, "direct")
            for row in hde_rows(model):
                unit = units[row["unit_id"]]
                messages, meta = module.build_guided(unit)
                eq(meta["prompt_sha256"], row["prompt"]["prompt_sha256"], f"{model}/{row['unit_id']} guided")
                hashes.add(meta["prompt_sha256"])
                user = messages[1]["content"]
                match = re.search(r"<Tool evidence>\n(.*?)\n</Tool evidence>", user, flags=re.S)
                req(match is not None, f"{model}/{row['unit_id']} evidence block")
                evidence = match.group(1)
                req(bad.search(evidence) is None, f"{model}/{row['unit_id']} evidence token {bad.search(evidence).group(0) if bad.search(evidence) else ''}")
                for token in (row["unit_id"], unit["group_id"], "vulnerable_slot", "gold_label"):
                    req(token not in evidence, f"{model}/{row['unit_id']} evidence leaks {token}")
                code_match = re.search(r"```(?:c|cpp)\n(.*?)```", user, flags=re.S)
                req(code_match is not None, f"{model}/{row['unit_id']} code block missing")
                req(bad.search(code_match.group(1)) is None, f"{model}/{row['unit_id']} code leaks a label token")
                wrapper = user.replace(evidence, "").replace(code_match.group(1), "")
                for token in (row["unit_id"], unit["group_id"], "is_vulnerable", "gold_label"):
                    req(token not in wrapper, f"{model}/{row['unit_id']} wrapper leaks {token}")
                _, dmeta = module.build_direct(unit)
                eq(dmeta["prompt_sha256"], v2[row["unit_id"]]["prompt"]["prompt_sha256"], f"{model}/{row['unit_id']} direct")
                direct += 1
                rebuilt += 1
        eq(len(hashes), 140, "unique prompts")
        eq(rebuilt, 280, "rebuilt")
        eq(direct, 280, "direct matches")
        pre = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "preflight.json")
        eq(pre["guided_prompts"]["unique"], 140, "preflight unique")
        return ok("All 280 guided prompts rebuild byte-identically (140 unique); direct equals hybrid v2; evidence blocks are label/path/CWE-free.")

    def d5():
        units = hde_units()
        dyn = {r["unit_id"]: r for r in dynamic_rows()}
        eq(len({u["enhanced_evidence"] for u in units.values()}), 13, "distinct evidence")
        for uid, unit in units.items():
            row = dyn[uid]
            eq(unit["enhanced_outcome"], "leak" if row["y_pred"] == 1 else "clean", f"{uid} outcome")
            eq(unit["enhanced_primary_mode"], row["primary_evidence"], f"{uid} primary")
            for mode in ("default", "realloc_fail", "nogobal"):
                eq(bool(unit["enhanced_modes"][mode]["applicable"]), bool(row["modes"][mode]["applicable"]), f"{uid}/{mode} applicable")
                eq(unit["enhanced_modes"][mode]["decision"], row["modes"][mode]["decision"], f"{uid}/{mode} decision")
            eq(unit["enhanced_evidence_sha256"], sha_text(unit["enhanced_evidence"]), f"{uid} evidence hash")
            if row["primary_evidence"] == "realloc_fail":
                req("realloc" in unit["enhanced_evidence"].lower(), f"{uid} realloc missing")
            if row["primary_evidence"] == "nogobal":
                req("global" in unit["enhanced_evidence"].lower(), f"{uid} global missing")
        pre = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "preflight.json")
        eq(pre["enhanced_tool"]["confusion"], {"tp": 70, "fp": 0, "tn": 70, "fn": 0}, "tool confusion")
        eq(len(pre["enhanced_tool"]["newly_observable_units"]), 12, "newly observable")
        return ok("Enhanced evidence matches the dynamic mode decisions, has 13 distinct texts and covers the 12 new units.")

    def d6():
        prices = {"deepseek": (0.15, 0.6, 0.003), "mimo": (0.14, 0.28, 0.0028)}
        total = 0.0
        per = {}
        for model in ("deepseek", "mimo"):
            d = ROOT / "hybrid_dynamic_enhanced" / "runs" / f"enhanced_dynamic_v1_{model}"
            value = sum(cost(r["usage"], prices[model]) for r in hde_rows(model))
            close(value, jload(d / "manifest.json")["cost"]["configured_usd"], f"{model} cost")
            per[model] = round(value, 9)
            total += value
        close(total, 0.023560544, "new cost")
        doc = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "cost.json")
        eq(doc["totals"]["new_requests"], 280, "new requests")
        close(doc["totals"]["new_configured_usd"], total, "cost json")
        close(doc["totals"]["all_in_usd"], total + 0.000087716, "all-in")
        req("$0.023561" in text(ROOT / "hybrid_dynamic_enhanced" / "REPORT.md"), "REPORT cost missing")
        return ok(f"280 requests cost ${total:.6f}; two smoke calls add $0.000087716 (all-in $0.023648).", per_model=per, total=round(total, 9))

    def d7():
        start = (ROOT / "hybrid_dynamic_enhanced" / "runs" / "enhanced_dynamic_v1_deepseek").stat().st_mtime
        newest = max((ROOT / "hybrid" / "runs" / f"hybrid_v2_{m}_{x}" / "results.jsonl").stat().st_mtime for m in ("deepseek", "mimo") for x in ("direct", "dynamic", "combined"))
        req(newest < start, "v2 baseline modified")
        man = jload(ROOT / "hybrid" / "inputs_v2" / "manifest.json")
        eq(sha_file(ROOT / "hybrid" / "inputs_v2" / "units.jsonl"), man["units_sha256"], "v2 pack")
        pre = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "preflight.json")
        eq(pre["checks"][1]["detail"]["sha256"], man["units_sha256"], "preflight pack")
        return ok("Frozen v2 baselines predate the new run; the v2 input pack hash still matches 1ec51f57...")

    def d8():
        cons = jload(ROOT / "hybrid_dynamic_enhanced" / "results" / "consistency.json")
        for model in ("deepseek", "mimo"):
            rows = hde_rows(model)
            agree = sum(1 for r in rows if r["y_pred"] == int(r["tool_verdict"]))
            eq(agree, int(round(cons["models"][model]["agreement_with_tool"] * 140)), f"{model} agreement")
            direct = v2_rows(model, "direct")
            flips = cons["models"][model]["flips_vs_baselines"]["v2-direct"]
            up = down = 0
            for row in rows:
                new_ok = row["y_pred"] == int(row["label"])
                old_ok = direct[row["unit_id"]]["y_pred"] == int(row["label"])
                up += new_ok and not old_ok
                down += old_ok and not new_ok
            eq(up, flips["new_right_base_wrong"], f"{model} fixed")
            eq(down, flips["new_wrong_base_right"], f"{model} broken")
        report = text(ROOT / "hybrid_dynamic_enhanced" / "REPORT.md")
        req("No semantic-reasoning improvement is claimed" in report, "caveat missing")
        return ok("Tool agreement and flips vs v2 direct reproduce; the report refuses a semantic-reasoning claim.")

    check(checks, "D1", "hybrid", "Two complete 140-unit runs", d1)
    check(checks, "D2", "hybrid", "HDE accuracy reproduces", d2)
    check(checks, "D3", "hybrid", "Paired McNemar contrasts reproduce", d3)
    check(checks, "D4", "hybrid", "Prompts rebuild and stay sanitized", d4)
    check(checks, "D5", "hybrid", "Evidence matches the dynamic modes", d5)
    check(checks, "D6", "hybrid", "280-request cost and smoke split", d6)
    check(checks, "D7", "hybrid", "Frozen v2 baselines are read-only", d7)
    check(checks, "D8", "hybrid", "Copying caveat and flips reproduce", d8)


# ---------------------------------------------------------------------------
# E. static_extended (CodeQL)
# ---------------------------------------------------------------------------


def codeql_rows():
    return jlines(ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full" / "predictions.jsonl")


def audit_codeql(checks):
    run_dir = ROOT / "static_extended" / "runs" / "codeql_20261114_cwe401_full"

    def e1():
        rows = codeql_rows()
        frozen = dynamic_units()
        eq(len(rows), 200, "rows")
        eq({r["sample_id"] for r in rows}, set(frozen), "unit set")
        for row in rows:
            eq(row["label"], frozen[row["sample_id"]]["label"] == "bad", f"{row['sample_id']} label")
            eq(row["sample"]["split"], frozen[row["sample_id"]]["split"], f"{row['sample_id']} split")
        eq(dict(collections.Counter(r["sample"]["split"] for r in rows)), {"test": 140, "dev": 60}, "splits")
        eq(sum(1 for r in rows if r["label"]), 100, "labels")
        eq(jload(run_dir / "manifest.json")["input"]["sha256"], "4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24", "input hash")
        return ok("200 unique frozen units (100/100; test 140 / dev 60); input hash matches the Juliet freeze.")

    def e2():
        rows = codeql_rows()
        eq(dict(collections.Counter(r["status"] for r in rows)), {"ok": 194, "compile_error": 6}, "statuses")
        errors = [r for r in rows if r["status"] != "ok"]
        eq(len(errors), 6, "errors")
        eq(sum(1 for r in errors if r["sample"]["split"] == "test"), 4, "test errors")
        for row in errors:
            req("_82" in row["sample_id"], f"{row['sample_id']} not _82")
        eq(sum(1 for r in rows if r["status"] == "timeout"), 0, "timeouts")
        eq(sum(1 for r in rows if r["status"] == "tool_error"), 0, "tool errors")
        return ok("194 ok / 6 compile_error; all six are _82 (4 test, 2 dev); no timeout or tool error.")

    def e3():
        test = [r for r in codeql_rows() if r["sample"]["split"] == "test"]

        def conf(view):
            c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
            for row in test:
                if view == "evaluable" and row["status"] != "ok":
                    continue
                pred = bool(row["prediction"]["is_vulnerable"]) if row["status"] == "ok" else False
                if row["label"] and pred:
                    c["tp"] += 1
                elif row["label"]:
                    c["fn"] += 1
                elif pred:
                    c["fp"] += 1
                else:
                    c["tn"] += 1
            return c

        metrics = jload(run_dir / "metrics.json")["tool"]["by_split"]["test"]
        for view in ("end_to_end", "evaluable"):
            c = conf("evaluable" if view == "evaluable" else "end")
            m = metric(**c)
            for key in ("tp", "fp", "tn", "fn"):
                eq(c[key], metrics[view][key], f"{view} {key}")
            for key in ("precision", "recall", "macro_f1", "accuracy", "mcc"):
                close(m[key], metrics[view][key], f"{view} {key}")
        close(metric(**conf("end"))["f1_positive"], 0.8447204968944099, "F1(V)")
        close(metric(**conf("end"))["macro_f1"], 0.8173182316404822, "macro-F1")
        return ok("Test140 end-to-end 68/23/47/2, evaluable 68/23/45/0; F1(V) 0.8447, macro-F1 0.8173, MCC 0.6739.")

    def e4():
        test = [r for r in codeql_rows() if r["sample"]["split"] == "test"]
        metrics = jload(run_dir / "comparison_test140.json")["tools"]["codeql"]["per_query"]
        for query in ("cpp/memory-never-freed", "cpp/memory-may-not-be-freed"):
            c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
            for row in test:
                pred = row["status"] == "ok" and bool(row["prediction"]["by_query"].get(query, 0))
                if row["label"] and pred:
                    c["tp"] += 1
                elif row["label"]:
                    c["fn"] += 1
                elif pred:
                    c["fp"] += 1
                else:
                    c["tn"] += 1
            m = metric(**c)
            for key in ("tp", "fp", "tn", "fn", "precision", "recall", "macro_f1", "mcc"):
                close(m[key], metrics[query]["end_to_end"][key], f"{query} {key}")
        eq(sum(len(r.get("diagnostics") or []) for r in codeql_rows()), 132, "diagnostics")
        outside = [(r["sample_id"], d.get("path")) for r in codeql_rows() for d in (r.get("diagnostics") or []) if not d.get("in_target_file")]
        eq(outside, [], "out-of-target diagnostics")
        return ok("Per-query counts reproduce; 132 raw diagnostics, all in target files.")

    def e5():
        man = jload(run_dir / "manifest.json")
        for name, meta in man["outputs"].items():
            path = run_dir / name
            req(path.exists(), f"missing {name}")
            eq(sha_file(path), meta["sha256"], f"{name} hash")
            eq(path.stat().st_size, meta["bytes"], f"{name} bytes")
        missing = [
            r["sample_id"]
            for r in codeql_rows()
            if r["status"] == "ok" and not list((run_dir / "raw").glob(f"*{r['sample_id']}.sarif.gz"))
        ]
        eq(missing, [], "missing SARIF")
        for row in codeql_rows():
            if row["status"] != "ok":
                req(list((run_dir / "raw").glob(f"*{row['sample_id']}.create.stderr.txt")), f"{row['sample_id']} stderr")
        return ok("Manifest output hashes match; 194 SARIF files and 6 compile-error stderr logs are present.")

    def e6():
        comp = jload(run_dir / "comparison_test140.json")["tools"]
        static = jlines(ROOT / "traditional" / "static" / "runs" / "juliet_formal_20261112_clang_cppcheck_gnu" / "predictions.jsonl")
        for tool in ("clang", "cppcheck"):
            test = [r for r in static if r["tool"] == tool and r["sample"]["split"] == "test"]
            for view in ("evaluable", "end_to_end"):
                c = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
                for row in test:
                    if view == "evaluable" and row["status"] != "ok":
                        continue
                    pred = bool(row["prediction"]["is_vulnerable"]) if row["status"] == "ok" else False
                    if row["label"] and pred:
                        c["tp"] += 1
                    elif row["label"]:
                        c["fn"] += 1
                    elif pred:
                        c["fp"] += 1
                    else:
                        c["tn"] += 1
                m = metric(**c)
                for key in ("tp", "fp", "tn", "fn", "precision", "recall", "macro_f1", "mcc"):
                    close(m[key], comp[tool][view][key], f"{tool}/{view}/{key}")
        clang_pos = {r["sample_id"] for r in static if r["tool"] == "clang" and r["sample"]["split"] == "test" and r["status"] == "ok" and r["prediction"]["is_vulnerable"]}
        cq_pos = {r["sample_id"] for r in codeql_rows() if r["sample"]["split"] == "test" and r["status"] == "ok" and r["prediction"]["is_vulnerable"]}
        cq_bad = {r["sample_id"] for r in codeql_rows() if r["sample"]["split"] == "test" and r["status"] == "ok" and r["prediction"]["is_vulnerable"] and r["label"]}
        eq(clang_pos - cq_pos, set(), "CodeQL misses a Clang positive")
        eq(len(cq_bad - clang_pos), 15, "CodeQL adds 15 bad")
        fps = {r["sample"]["language"] for r in codeql_rows() if r["sample"]["split"] == "test" and r["status"] == "ok" and r["prediction"]["is_vulnerable"] and not r["label"]}
        eq(fps, {"cpp"}, "FP language")
        readme = text(ROOT / "static_extended" / "README.md")
        for value in ("0.7473", "0.9714", "0.8447", "0.6739", "0.8173", "0.8618", "0.8768", "0.5879", "0.4583"):
            req(value in readme, f"README missing {value}")
        for label in ("F1(V) 0.8447", "Macro-F1 0.8173", "F1(V) 0.8618", "Macro-F1 0.8768"):
            req(label in readme, f"README missing explicit label {label!r}")
        req("项目主指标" in readme, "README does not call Macro-F1 the project metric")
        req("项目汇总主指标是 Macro-F1" in readme, "README lacks the primary-endpoint statement")
        req("两者不可混用或互相替代" in readme, "README lacks the non-interchangeability warning")
        req("| F1(V) | Macro-F1 |" in readme, "README tables do not carry both columns")
        stray = re.search(r"(?<![\w-])F1\s*(?:=|为|:)?\s*0\.(?:8447|845|8618|862)\b", readme)
        req(stray is None, f"README contains an unlabeled F1 value: {stray.group(0) if stray else ''}")
        return (
            "PASS",
            "Baselines and coverage gains reproduce (15 Clang-missed bad units recovered, no Clang positive "
            "missed, all 23 FP are C++). static_extended/README.md now labels both positive-class F1(V) "
            "(0.8447 vs Clang 0.8618) and Macro-F1 (0.8173 vs 0.8768), names Macro-F1 as the project primary "
            "endpoint and states the two are not interchangeable.",
            {"added_bad": 15, "clang_missed": 0, "fp_languages": sorted(fps), "f1_v": 0.8447, "macro_f1": 0.8173},
        )

    def e7():
        freeze = jload(ROOT / "juliet" / "FREEZE.json")
        eq(freeze["subset_units_sha256"], "4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24", "freeze")
        eq(sha_file(ROOT / "juliet" / "subset_units.jsonl"), freeze["subset_units_sha256"], "subset")
        man = jload(run_dir / "manifest.json")
        eq(man["input"]["sha256"], freeze["subset_units_sha256"], "input")
        forbidden = re.compile(r"(^|\n)\s*(import|from)\s+(requests|urllib\.request|http\.client|socket|openai|anthropic|httpx|aiohttp)\b")
        req(forbidden.search(text(ROOT / "static_extended" / "codeql_adapter.py")) is None, "network import")
        req("api_key" not in man, "api key field")
        return ok("Local CodeQL run; the Juliet subset hash is unchanged and no model/API field is present.")

    def e8():
        readme = text(ROOT / "static_extended" / "README.md")
        for phrase in ("单文件单元", "编译器", "compile_error", "不修改 Juliet", "Semgrep", "Infer"):
            req(phrase in readme, f"README missing {phrase}")
        req("limitations" in jload(run_dir / "metrics.json"), "metrics limitations")
        return ok("README documents single-TU databases, compiler differences, compile errors and tools not run.")

    check(checks, "E1", "codeql", "200 units/splits/labels match the freeze", e1)
    check(checks, "E2", "codeql", "194 ok / 6 compile_error, all documented", e2)
    check(checks, "E3", "codeql", "Test140 confusion and metrics reproduce", e3)
    check(checks, "E4", "codeql", "Per-query counts and 132 diagnostics", e4)
    check(checks, "E5", "codeql", "Output hashes and raw artifacts intact", e5)
    check(checks, "E6", "codeql", "Clang/Cppcheck comparison; F1 caveat", e6, warn_must_fix=True)
    check(checks, "E7", "codeql", "No API use and no Juliet modification", e7)
    check(checks, "E8", "codeql", "Limitations are disclosed", e8)


# ---------------------------------------------------------------------------
# F. analysis/schema_recovery
# ---------------------------------------------------------------------------


def audit_schema(checks):
    def f1():
        doc = schema_doc()
        eq(doc["scope"]["api_calls"], 0, "scope api")
        eq(doc["sources"]["api_calls"], 0, "sources api")
        eq(len(doc["sources"]["runs"]), 12, "runs")
        n = 0
        for row in doc["sources"]["runs"]:
            d = ROOT / "runner" / "runs" / row["run_id"]
            for key, name in (("results_sha256", "results.jsonl"), ("config_sha256", "config.json"), ("metrics_sha256", "metrics.json")):
                eq(sha_file(d / name), row[key], f"{row['run_id']}/{name}")
                n += 1
            eq(row["records"], row["detection_records"] + row["repair_records"], f"{row['run_id']} split")
            eq(row["detection_records"], 160 if row["run_task"] == "independent" else 360, f"{row['run_id']} detection")
            eq(row["repair_records"], 128 if row["run_task"] == "independent" else 180, f"{row['run_id']} repair")
        eq(n, 36, "hashes")
        return ok("All 12 legacy result/config/metrics hashes match; 36 hashes verified, no old run rewritten.")

    def f2():
        missing, trunc, other = [], [], []
        for run in DEEPSEEK_RUNS:
            for row in jlines(ROOT / "runner" / "runs" / run / "results.jsonl"):
                if row.get("task") != "repair" or row.get("status") != "invalid":
                    continue
                response = row.get("response") or {}
                finish = (response.get("response_meta") or {}).get("finish_reason")
                err = (row.get("validation") or {}).get("error", "")
                content = response.get("content") or ""
                try:
                    parsed = json.loads(content)
                except (TypeError, json.JSONDecodeError):
                    parsed = None
                if finish == "length":
                    trunc.append((row, content, parsed))
                elif "explanation" in err and "missing" in err:
                    missing.append((row, parsed))
                else:
                    other.append((run, err, finish))
        eq(other, [], "unclassified")
        eq(len(missing), 93, "missing")
        eq(len(trunc), 9, "truncation")
        for row, parsed in missing:
            eq(row["response"]["response_meta"]["finish_reason"], "stop", "missing finish")
            req(isinstance(parsed, dict), "missing parsed")
            req(isinstance(parsed.get("fixed_function"), str) and parsed["fixed_function"].strip(), "missing fixed_function")
            eq(set(parsed), {"fixed_function"}, "missing keys")
        for row, content, parsed in trunc:
            eq(row["response"]["response_meta"]["finish_reason"], "length", "trunc finish")
            eq(parsed, None, "trunc parsed")
            req(21876 <= len(content) <= 27473, "trunc length")
        return ok("102 invalid split exactly into 93 missing-explanation (stop, fixed_function present) and 9 truncations (length, unparseable).")

    def f3():
        doc = schema_doc()
        o = doc["official_vs_code_only"]["overall"]
        eq(o["requests"], 924, "requests")
        eq(o["official_schema_valid"], 822, "official valid")
        eq(o["official_schema_invalid"], 102, "official invalid")
        close(o["official_schema_valid_rate"], 822 / 924, "official rate")
        eq(o["code_only_admitted"], 915, "code-only")
        close(o["code_only_admission_rate"], 915 / 924, "code-only rate")
        eq(o["official_usable_code"], 552, "official usable")
        eq(o["code_usable_code"], 619, "salvage usable")
        eq(o["salvage_usable_code"], 67, "salvage canonical")
        eq(o["salvage_usable_code_knr"], 69, "salvage knr")
        eq(o["official_usable_code"] + o["salvage_usable_code"], o["code_usable_code"], "552+67")
        rows = [r for r in schema_records() if r["model"] == "deepseek"]
        eq(len(rows), 102, "records")
        eq(sum(1 for r in rows if r["error_class"] == "missing_explanation"), 93, "missing records")
        eq(sum(1 for r in rows if r["error_class"] == "truncation"), 9, "trunc records")
        eq(sum(1 for r in rows if r["usable_patch_canonical"]), 67, "usable canonical")
        eq(sum(1 for r in rows if r["usable_patch_knr_aware"]), 69, "usable knr")
        eq(sum(1 for r in rows if r["fatal"]), 9, "fatal")
        readme = text(ROOT / "analysis" / "schema_recovery" / "README.md")
        for value in ("822/924", "915/924", "552/924", "619/924", "67/93", "69/93"):
            req(value in readme, f"README missing {value}")
        return ok("Official 822/924 (88.96%), code-only 915/924 (99.03%), usable 552→619 (+7.25 pp); salvage 67/69.")

    def f4():
        doc = schema_doc()
        total = doc["cost"]["combined"]["all"]
        eq(total["configured_peak_cache_aware_usd"], 2.521790096, "configured-peak total")
        eq(total["offpeak_list_normalized_usd"], 1.572472286, "off-peak total")
        eq(total["configured_peak"]["total_usd"], 2.521790096, "configured-peak block")
        eq(total["offpeak_list_normalized"]["total_usd"], 1.572472286, "off-peak block")
        eq(total["records"], 4968, "cost records")
        eq(total["configured_peak_complete"], True, "configured peak complete")
        eq(total["offpeak_complete"], True, "off-peak complete")
        eq(total["cost_basis"], "configured_peak_cache_aware + offpeak_list_normalized", "cost basis")
        basis = doc["cost"]["price_basis"]
        req("DeepSeek observed peak 0.30/1.20/0.006" in basis["configured_peak_cache_aware"], "peak card text")
        req("DeepSeek 0.15/0.60/0.003" in basis["offpeak_list_normalized"], "off-peak card text")
        req("NOT the project-wide off-peak normalized total" in basis["warning"], "price-basis warning")

        cn_path = ROOT / "analysis" / "cost_normalization.json"
        cn = jload(cn_path)
        legacy = cn["aggregates"]["legacy_test"]
        eq(legacy["configured_cache_aware_usd"], 2.521790096, "cost_normalization configured")
        eq(legacy["normalized_list_usd"], 1.572472286, "cost_normalization off-peak")
        eq(legacy["records"], 4968, "cost_normalization records")
        eq(legacy["runs"], 12, "cost_normalization runs")
        eq(cn["verification"]["status"], "PASS", "cost_normalization verification")
        eq(cn["verification"]["source_artifacts_changed"], [], "cost_normalization changed artifacts")
        eq(cn["verification"]["token_mismatch_rows"], 0, "cost_normalization token mismatches")
        eq(cn["verification"]["missing_cost_rows"], 0, "cost_normalization missing costs")
        eq(cn["no_api_calls"], True, "cost_normalization no API calls")
        eq(sha_file(cn_path), doc["sources"]["cost_normalization"]["sha256"], "cost_normalization sha")
        ref = doc["sources"]["cost_normalization"]["legacy_test"]
        eq(ref["configured_cache_aware_usd"], legacy["configured_cache_aware_usd"], "source configured")
        eq(ref["normalized_list_usd"], legacy["normalized_list_usd"], "source off-peak")
        eq(ref["records"], legacy["records"], "source records")
        eq(ref["runs"], legacy["runs"], "source runs")
        ext = doc["cost"]["external_basis"]
        eq(ext["comparison"]["configured_peak_cache_aware"]["match"], True, "external configured match")
        eq(ext["comparison"]["offpeak_list_normalized"]["match"], True, "external off-peak match")
        close(ext["comparison"]["configured_peak_cache_aware"]["delta_usd"], 0.0, "external configured delta")
        close(ext["comparison"]["offpeak_list_normalized"]["delta_usd"], 0.0, "external off-peak delta")

        rows = [r for r in schema_records() if r["model"] == "deepseek"]
        peak = offpeak = 0.0
        missing_peak = missing_offpeak = trunc_peak = trunc_offpeak = 0.0
        for row in rows:
            c = row["cost"]
            eq(c["model_key"], "deepseek", f"{row['record_id']} model key")
            prompt, completion, cached = c["prompt_tokens"], c["completion_tokens"], c["cached_tokens"]
            expected_peak = ((prompt - cached) * 0.30 + cached * 0.006 + completion * 1.20) / 1_000_000.0
            expected_offpeak = ((prompt - cached) * 0.15 + cached * 0.003 + completion * 0.60) / 1_000_000.0
            close(c["configured_peak_cache_aware_usd"], expected_peak, f"{row['record_id']} peak cost")
            close(c["offpeak_list_normalized_usd"], expected_offpeak, f"{row['record_id']} off-peak cost")
            peak += expected_peak
            offpeak += expected_offpeak
            if row["error_class"] == "missing_explanation":
                missing_peak += expected_peak
                missing_offpeak += expected_offpeak
            elif row["error_class"] == "truncation":
                trunc_peak += expected_peak
                trunc_offpeak += expected_offpeak
        close(peak, 0.218279592, "invalid peak cost")
        close(offpeak, 0.109139796, "invalid off-peak cost")
        close(missing_peak, 0.1035642, "missing peak cost")
        close(missing_offpeak, 0.0517821, "missing off-peak cost")
        close(trunc_peak, 0.114715392, "truncation peak cost")
        close(trunc_offpeak, 0.057357696, "truncation off-peak cost")
        exp = doc["cost"]["reported_vs_configured_peak"]
        close(exp["deepseek_missing_explanation"]["configured_peak_cache_aware_usd"], missing_peak, "JSON missing peak")
        close(exp["deepseek_missing_explanation"]["offpeak_list_normalized_usd"], missing_offpeak, "JSON missing off-peak")
        close(exp["deepseek_truncation"]["configured_peak_cache_aware_usd"], trunc_peak, "JSON truncation peak")
        close(exp["deepseek_truncation"]["offpeak_list_normalized_usd"], trunc_offpeak, "JSON truncation off-peak")
        close(doc["cost"]["sunk_cost_reclassification"]["offpeak_list_normalized"]["invalid_total_usd"], offpeak, "sunk off-peak invalid")

        readme = text(ROOT / "analysis" / "schema_recovery" / "README.md")
        for value in ("$2.521790096", "$1.572472286", "configured peak", "off-peak list", "Δ 均为 $0.000000", "10.32%", "9.61%"):
            req(value in readme, f"README missing {value}")
        req("不是" in readme and "normalized" in readme, "README does not disambiguate normalized")
        return (
            "PASS",
            "Both schema cost bases are present and reconcile exactly with analysis/cost_normalization.json: "
            "configured-peak cache-aware $2.521790096 (4,968 records) = legacy_test.configured_cache_aware_usd; "
            "off-peak list $1.572472286 = legacy_test.normalized_list_usd, delta $0 on both. The 102 invalid "
            "records also recompute at $0.218280 (peak) and $0.109140 (off-peak); README states the two bases "
            "and the 10.32% / 9.61% invalid shares.",
            {
                "configured_peak_usd": 2.521790096,
                "offpeak_list_usd": 1.572472286,
                "invalid_peak_usd": round(peak, 9),
                "invalid_offpeak_usd": round(offpeak, 9),
                "records": total["records"],
            },
        )

    def f5():
        doc = schema_doc()
        drift = []
        invalid = total = 0
        for run in MIMO_RUNS:
            for row in jlines(ROOT / "runner" / "runs" / run / "results.jsonl"):
                if row.get("task") != "detection":
                    continue
                total += 1
                if row.get("status") != "invalid":
                    continue
                invalid += 1
                try:
                    parsed = json.loads((row.get("response") or {}).get("content") or "")
                except (TypeError, json.JSONDecodeError):
                    parsed = {}
                if "is_vulnerability" in parsed or "is_vulnerative" in parsed:
                    drift.append((row, parsed))
        eq(total, 1560, "detection")
        eq(invalid, 61, "invalid")
        eq(len(drift), 61, "drift")
        values = [p.get("is_vulnerability", p.get("is_vulnerative")) for _, p in drift]
        eq(sum(1 for v in values if v is True), 5, "true")
        eq(sum(1 for v in values if v is False), 56, "false")
        eq(sum(1 for row, p in drift if p.get("is_vulnerability", p.get("is_vulnerative")) == row["label"]), 28, "agreement")
        exp = doc["mimo_detection"]["field_drift"]
        eq(exp["n"], 61, "JSON drift n")
        eq(exp["recovered_value_counts"], {"false": 56, "true": 5}, "JSON drift values")
        eq(exp["label_agreement_count"], 28, "JSON drift agreement")
        eq(exp["alias_counts"], {"is_vulnerability": 60, "is_vulnerative": 1}, "aliases")
        eq(exp["both_keys"], 1, "both keys")
        return ok("61/61 drift remappable; 5 true / 56 false; 28/61 label agreement; 60+1 alias split with one both-key record.")

    def f6():
        body = text(ROOT / "analysis" / "schema_recovery" / "recover.py")
        forbidden = re.compile(r"(^|\n)\s*(import|from)\s+(requests|urllib|http|socket|openai|anthropic|httpx|aiohttp)\b")
        req(forbidden.search(body) is None, "network import")
        eq(schema_doc()["scope"]["api_calls"], 0, "api calls")
        req("No model, network, or API call" in schema_doc()["sources"]["note"], "no-api note")
        return ok("Read-only replay: no network import and api_calls=0 in scope and sources.")

    def f7():
        readme = text(ROOT / "analysis" / "schema_recovery" / "README.md")
        for phrase in ("不是正确率", "L0", "truncation", "不是 official 分数", "没有编译"):
            req(phrase in readme or phrase.lower() in readme.lower(), f"README missing {phrase}")
        req("102" in readme, "missing 102")
        return ok("README states L0 (no compile/test/PoC), separates official/code-only and treats truncation as fatal.")

    def f8():
        readme = text(ROOT / "analysis" / "schema_recovery" / "README.md")
        for value in ("822/924 = 88.96%", "915/924 = 99.03%", "552/924 = 59.74%", "619/924 = 66.99%", "+7.25 pp", "67/93 = 72.0%", "69/93 = 74.2%"):
            req(value in readme, f"README missing {value}")
        o = schema_doc()["official_vs_code_only"]["overall"]
        close(o["code_usable_code_rate"], 619 / 924, "619 rate")
        close(o["official_usable_code_rate"], 552 / 924, "552 rate")
        return ok("All headline schema rates/denominators match the JSON and 924/102/93/9 counts.")

    check(checks, "F1", "schema", "12 old runs are hash-identical", f1)
    check(checks, "F2", "schema", "102 invalid split 93 + 9", f2)
    check(checks, "F3", "schema", "Strict/code-only/usable totals reproduce", f3)
    check(checks, "F4", "schema", "Invalid costs recompute; price basis flagged", f4, warn_must_fix=True)
    check(checks, "F5", "schema", "MiMo 61/61 field drift reproduces", f5)
    check(checks, "F6", "schema", "Zero API/network calls", f6)
    check(checks, "F7", "schema", "L0/non-accuracy caveats present", f7)
    check(checks, "F8", "schema", "README rates match the JSON", f8)


# ---------------------------------------------------------------------------
# G. latest literature
# ---------------------------------------------------------------------------


def audit_literature(checks):
    files = {
        "llm": ROOT / "research" / "latest_llm_methods_2026.md",
        "eval": ROOT / "research" / "latest_evaluation_repair_2026.md",
        "memory": ROOT / "research" / "latest_memory_tools_2026.md",
        "index": ROOT / "docs" / "LITERATURE.md",
    }

    def g1():
        sizes = {}
        for name, path in files.items():
            req(path.exists(), f"missing {path.relative_to(ROOT)}")
            sizes[name] = path.stat().st_size
            req(sizes[name] > 8000, f"{path.name} too small")
        return ok("Three research/latest_*.md files and docs/LITERATURE.md exist and are non-trivial.", sizes=sizes)

    def g2():
        llm = text(files["llm"])
        evaluation = text(files["eval"])
        memory = text(files["memory"])
        req("## 10. 参考文献核验表" in llm, "llm §10")
        req("## 16. 参考文献" in evaluation, "eval §16")
        req("## 7. 参考文献" in memory, "memory §7")
        schema = text(ROOT / "analysis" / "schema_recovery" / "README.md")
        ids = sorted(set(re.findall(r"\[([A-Z]\d+)\]", schema)))
        req(ids, "no letter-numbered citations")
        missing = [cid for cid in ids if f"[{cid}]" not in llm]
        eq(missing, [], "unresolved citations")
        return ok("Reference sections exist and every schema_recovery letter-numbered citation resolves in latest_llm_methods.", ids=ids)

    def g3():
        required = ("schema recovery", "pair_debias", "evidence_verify", "dynamic_enhanced", "hybrid_dynamic_enhanced", "CodeQL")
        checked = {}
        for name, path in (("latest_llm_methods_2026.md", files["llm"]), ("latest_evaluation_repair_2026.md", files["eval"])):
            head = "\n".join(text(path).splitlines()[:40])
            req("日期化状态注记（2026-11-14）" in head, f"{name} lacks the dated 2026-11-14 status note")
            req("写作时状态（2026-11-13）" in head, f"{name} does not scope the original 2026-11-13 state")
            req("截至 2026-11-14 已完成" in head, f"{name} lacks the completed-by-2026-11-14 list")
            missing = [item for item in required if item not in head]
            eq(missing, [], f"{name} status note misses {missing}")
            req("正文" in head and "保持不变" in head, f"{name} does not say the historical body is unchanged")
            checked[name] = {"dated_note": True, "completed_items": list(required)}
        return (
            "PASS",
            "Both research/latest_*.md files carry the 2026-11-14 dated status note. It scopes the original "
            "2026-11-13 text as writing-time, lists schema recovery, pair_debias, evidence_verify, "
            "dynamic_enhanced, hybrid_dynamic_enhanced and CodeQL as completed, and says the historical body "
            "is intentionally unchanged (so the old '未实现' lines are explicitly historical, not current claims).",
            {"documents": checked},
        )

    def g4():
        index = text(files["index"])
        for path in ("pair_debias/", "evidence_verify/", "dynamic_enhanced/", "hybrid_dynamic_enhanced/", "static_extended/", "analysis/schema_recovery/"):
            req(path in index, f"index missing {path}")
        return ok("docs/LITERATURE.md maps all six new result groups to their literature basis and limitations.")

    check(checks, "G1", "literature", "Latest literature files and index exist", g1)
    check(checks, "G2", "literature", "Reference sections and schema citations resolve", g2)
    check(checks, "G3", "literature", "Snapshots are stale on the new experiments", g3, warn_must_fix=True)
    check(checks, "G4", "literature", "Index maps the new groups", g4)


# ---------------------------------------------------------------------------
# H. Preservation and credentials
# ---------------------------------------------------------------------------

OLD_GLOBS = (
    "runner/runs/*/results.jsonl",
    "runner/runs/*/metrics.json",
    "pair_joint/runs/*/results.jsonl",
    "pair_joint/runs/*/metrics.json",
    "pair_joint/runs/*/position_map.json",
    "hybrid/runs/*/results.jsonl",
    "hybrid/runs/*/metrics.json",
    "evidence_prompt/runs/*/results.jsonl",
    "juliet_llm/runs/**/results.jsonl",
    "traditional/static/runs/*/predictions.jsonl",
    "traditional/static/runs/*/metrics.json",
    "traditional/dynamic/runs/*/results.jsonl",
    "traditional/dynamic/runs/*/metrics.json",
    "traditional/dynamic/runs/*/cases.jsonl",
    "juliet/FREEZE.json",
    "juliet/subset_units.jsonl",
    "splits/*.json",
    "audit/final_audit.md",
    "audit/final_audit.json",
)

NEW_DIRS = ("pair_debias", "evidence_verify", "dynamic_enhanced", "hybrid_dynamic_enhanced", "static_extended", "analysis/schema_recovery")


def audit_preservation(checks, old_audit_before):
    def h1():
        threshold = _dt.datetime(2026, 11, 12, 16, 40, tzinfo=_dt.timezone.utc).timestamp()
        newest = (0.0, None)
        for pattern in OLD_GLOBS:
            for path in ROOT.glob(pattern):
                if path.is_file() and path.stat().st_mtime > newest[0]:
                    newest = (path.stat().st_mtime, path)
        req(newest[1] is not None, "no old files")
        req(newest[0] < threshold, f"old result modified: {newest[1]} at {utc(newest[0])}")
        req((ROOT / "audit" / "final_audit.json").stat().st_mtime < threshold, "old audit modified")
        return ok(f"Newest legacy artifact {newest[1].relative_to(ROOT)} at {utc(newest[0])} predates the first new run; final_audit.* untouched.",
                  newest=str(newest[1].relative_to(ROOT)), mtime=utc(newest[0]))

    def h2():
        freeze = jload(ROOT / "juliet" / "FREEZE.json")
        eq(sha_file(ROOT / "juliet" / "subset_units.jsonl"), freeze["subset_units_sha256"], "juliet")
        eq(sha_file(ROOT / "splits" / "test_pairs_180.json"), "21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d", "pairs")
        eq(sha_file(ROOT / "splits" / "test_detection_160.json"), "bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8", "detection")
        man = jload(ROOT / "hybrid" / "inputs_v2" / "manifest.json")
        eq(sha_file(ROOT / "hybrid" / "inputs_v2" / "units.jsonl"), man["units_sha256"], "hybrid pack")
        for row in schema_doc()["sources"]["runs"]:
            eq(sha_file(ROOT / "runner" / "runs" / row["run_id"] / "results.jsonl"), row["results_sha256"], f"{row['run_id']} results")
        return ok("Frozen Juliet, both splits, the hybrid v2 pack and all 12 legacy result files still match their recorded hashes.")

    def h3():
        patterns = (re.compile(r"sk-[A-Za-z0-9]{20,}"), re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}"), re.compile(r"\"api_key\"\s*:\s*\"[A-Za-z0-9._\-]{8,}\""))
        hits = []
        scanned = 0
        for directory in NEW_DIRS:
            for path in (ROOT / directory).rglob("*"):
                if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".gz", ".pyc", ".png", ".jpg", ".pdf", ".zip"}:
                    continue
                if path.stat().st_size > 8 * 1024 * 1024:
                    continue
                try:
                    body = text(path)
                except OSError:
                    continue
                scanned += 1
                for pattern in patterns:
                    match = pattern.search(body)
                    if match:
                        hits.append(f"{path.relative_to(ROOT)}: {match.group(0)[:20]}")
        eq(hits, [], "credential-like strings")
        return ok(f"Scanned {scanned} text artifacts in the six new directories; no credential-like string found.", scanned=scanned)

    def h4():
        req(JSON_PATH.name == "latest_audit.json" and MD_PATH.name == "latest_audit.md", "unexpected output names")
        eq(sorted(old_audit_before), ["final_audit.json", "final_audit.md"], "old audit files")
        for name, mtime in old_audit_before.items():
            eq((ROOT / "audit" / name).stat().st_mtime, mtime, f"{name} modified")
        return ok("Only audit/latest_audit.json and audit/latest_audit.md are written; final_audit.* is untouched.")

    def h5():
        body = text(Path(__file__))
        forbidden = re.compile(r"(^|\n)\s*(import|from)\s+(requests|urllib|socket|openai|anthropic|httpx|aiohttp)\b")
        req(forbidden.search(body) is None, "network import")
        return ok("The audit script is offline; it only reads stored artifacts.")

    check(checks, "H1", "preserve", "Legacy results predate all new experiments", h1)
    check(checks, "H2", "preserve", "Frozen inputs and legacy hashes unchanged", h2)
    check(checks, "H3", "preserve", "New artifacts contain no credentials", h3)
    check(checks, "H4", "preserve", "Only the two latest_audit files are written", h4)
    check(checks, "H5", "preserve", "Audit itself is offline", h5)


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def publication_note(overall, counts):
    """Record stale publication summaries without turning them into result checks."""
    targets = ("README.md", "docs/GITHUB_RELEASE.md", "docs/REPRODUCIBILITY.md")
    stale = []
    for name in targets:
        path = ROOT / name
        if not path.exists():
            continue
        for number, line in enumerate(text(path).splitlines(), 1):
            if "latest_audit" not in line:
                continue
            if "52 PASS" in line or "4 WARN" in line or "A6/E6/F4/G3" in line:
                stale.append({"path": name, "line": number, "text": line.strip()[:220]})
    if not stale:
        return {"status": "CURRENT", "detail": "Publication summaries do not cite the pre-fix audit counts."}
    return {
        "status": "STALE",
        "detail": (
            "These publication summaries still cite the pre-fix 52 PASS / 4 WARN audit (A6/E6/F4/G3). "
            f"This run reports {overall} with {counts['PASS']} PASS / {counts['WARN']} WARN / "
            f"{counts['FAIL']} FAIL; the publication pass must refresh these lines. The audit itself "
            "does not edit README.md or docs/."
        ),
        "files": stale,
    }


def build_doc(checks, old_audit_before):
    counts = collections.Counter(c["status"] for c in checks)
    must = [c for c in checks if c["must_fix"]]
    warnings = [c for c in checks if c["status"] == "WARN"]
    overall = "FAIL" if counts["FAIL"] else ("PASS_WITH_WARNINGS" if counts["WARN"] else "PASS")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": now_utc(),
        "root": str(ROOT),
        "overall": overall,
        "api_calls": 0,
        "network": "none",
        "publication_note": publication_note(overall, counts),
        "writes": ["audit/latest_audit.json", "audit/latest_audit.md"],
        "scope": {
            "groups": [
                "pair_debias (6 runs, 1,080 records)",
                "evidence_verify (4 arms)",
                "dynamic_enhanced (test 140)",
                "hybrid_dynamic_enhanced (280 requests)",
                "static_extended CodeQL (200 units / test 140)",
                "analysis/schema_recovery (102 invalid repair records)",
            ],
            "literature": [
                "research/latest_llm_methods_2026.md",
                "research/latest_evaluation_repair_2026.md",
                "research/latest_memory_tools_2026.md",
                "docs/LITERATURE.md",
            ],
            "out_of_scope": [
                "benchmark/extensions aggregation (unification pass)",
                "report/ and README publication edits",
                "git/gh operations",
            ],
            "method": "Read stored artifacts only; recompute prompts, joins, hashes, costs and metrics from raw records where possible.",
        },
        "counts": {"total": len(checks), "pass": counts["PASS"], "warn": counts["WARN"], "fail": counts["FAIL"], "info": counts["INFO"]},
        "must_fix": [{"id": c["id"], "area": c["area"], "status": c["status"], "title": c["title"], "detail": c["detail"]} for c in must],
        "warnings": [{"id": c["id"], "area": c["area"], "title": c["title"], "detail": c["detail"]} for c in warnings],
        "checks": checks,
        "preserved_old_audit": {name: utc(mtime) for name, mtime in sorted(old_audit_before.items())},
    }


def cell(value, limit=320):
    body = " ".join(str(value).split())
    if len(body) > limit:
        body = body[: limit - 1] + "…"
    return body.replace("|", "\\|")


def render(doc):
    lines = [
        "# Latest result release audit",
        "",
        f"Generated: {doc['generated_at_utc']}  ",
        f"Overall: **{doc['overall']}**  ",
        f"Checks: {doc['counts']['pass']} PASS, {doc['counts']['fail']} FAIL, {doc['counts']['warn']} WARN, {doc['counts']['info']} INFO ({doc['counts']['total']} total).",
        "",
        "Scope: read-only audit of the 2026-11-14 additions — `pair_debias` (6 runs, 1,080 records), "
        "`evidence_verify` (4 arms), `dynamic_enhanced` (test 140), `hybrid_dynamic_enhanced` (280 requests), "
        "`static_extended` CodeQL (200 units, test 140), `analysis/schema_recovery` (102 invalid repair records), "
        "the latest literature files and preservation of the old results. No model API was called; prompts, "
        "joins, hashes, costs and metrics were recomputed from stored artifacts.",
        "",
        "## Must fix",
        "",
    ]
    if doc["must_fix"]:
        lines += [f"- **{m['id']} ({m['status']}) — {m['title']}**: {m['detail']}" for m in doc["must_fix"]]
    else:
        lines.append("- None.")
    lines += ["", "## Warnings", ""]
    if doc["warnings"]:
        lines += [f"- **{w['id']} — {w['title']}**: {w['detail']}" for w in doc["warnings"]]
    else:
        lines.append("- None.")
    note = doc.get("publication_note") or {}
    if note.get("status") == "STALE":
        lines += ["", "## Publication note", "", note["detail"], ""]
        for item in note.get("files", []):
            lines.append(f"- `{item['path']}:{item['line']}` — {item['text']}")
    lines += ["", "## All checks", "", "| ID | Area | Status | Check | Result |", "| --- | --- | --- | --- | --- |"]
    for c in doc["checks"]:
        lines.append(f"| {c['id']} | {c['area']} | **{c['status']}** | {cell(c['title'], 150)} | {cell(c['detail'])} |")
    lines += [
        "",
        "## Reading notes",
        "",
        "- **Cost bases differ.** `pair_debias`/`evidence_verify` use configured DeepSeek $0.30/$1.20/$0.006 and MiMo $0.14/$0.28/$0.0028; `hybrid_dynamic_enhanced` uses $0.15/$0.60/$0.003 for DeepSeek; `schema_recovery` calls its cache-aware configured-card number `normalized`, which is not the off-peak `normalized` card in `analysis/cost_normalization.md` (F4).",
        "- **Records vs new calls.** `pair_debias` stores 1,080 records but issued 1,029 new API calls: `test_mimo_open_rev` resumed from 51 cached responses after an interrupted first attempt. `report.md` discloses the 51/129 split; A6 keeps it visible.",
        "- **Tool ceilings are not model results.** `dynamic_enhanced` and the HDE tool are 70/0/70/0; the model rows are 137/140 and 136/140 and no semantic-reasoning improvement is claimed.",
        "- **Post-hoc is not confirmation.** `evidence_verify` is exploratory on a test split already seen; `pair_debias` length matching is a post-hoc subset; `schema_recovery` salvage is an L0 structural proxy.",
        "- **Out of scope.** `benchmark/extensions`, `report/`, `README.md` and git/gh operations are owned by the publication pass and were not modified.",
        "",
        "## Files written",
        "",
        "- `audit/latest_audit.json`",
        "- `audit/latest_audit.md`",
        "",
        "Reproduce with `python3 audit/run_latest_audit.py` (read-only; no network).",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    global ROOT, AUDIT_DIR, JSON_PATH, MD_PATH
    parser = argparse.ArgumentParser(description="Read-only audit of the 2026-11-14 result additions")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    args = parser.parse_args(argv)
    ROOT = args.root.resolve()
    AUDIT_DIR = ROOT / "audit"
    JSON_PATH = (args.json or (AUDIT_DIR / "latest_audit.json")).resolve()
    MD_PATH = (args.md or (AUDIT_DIR / "latest_audit.md")).resolve()
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    old_before = {}
    for name in ("final_audit.json", "final_audit.md"):
        path = AUDIT_DIR / name
        if path.exists():
            old_before[name] = path.stat().st_mtime

    checks = []
    for name, fn in (
        ("pair_debias", audit_pair),
        ("evidence_verify", audit_evidence),
        ("dynamic_enhanced", audit_dynamic),
        ("hybrid_dynamic_enhanced", audit_hybrid),
        ("static_extended", audit_codeql),
        ("schema_recovery", audit_schema),
        ("literature", audit_literature),
    ):
        try:
            fn(checks)
        except Exception as exc:  # noqa: BLE001
            checks.append({"id": f"{name[:1].upper()}0", "area": name, "title": "Audit group completed", "status": "FAIL",
                           "detail": f"group crashed: {type(exc).__name__}: {exc}", "evidence": {}, "must_fix": True})
    audit_preservation(checks, old_before)

    doc = build_doc(checks, old_before)
    JSON_PATH.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    MD_PATH.write_text(render(doc), encoding="utf-8")
    counts = doc["counts"]
    print(f"{doc['overall']}: {counts['pass']} PASS / {counts['fail']} FAIL / {counts['warn']} WARN / {counts['info']} INFO ({counts['total']} checks)")
    for item in doc["must_fix"]:
        print(f"  must-fix {item['id']} [{item['status']}] {item['title']}")
    print(f"Wrote {JSON_PATH}")
    print(f"Wrote {MD_PATH}")
    return 1 if counts["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

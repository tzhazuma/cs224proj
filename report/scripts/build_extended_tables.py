#!/usr/bin/env python3
"""Build the extended report's LaTeX tables and headline macros from frozen results.

Reads only existing result artefacts; writes report/extended_tables.tex and
report/extended_numbers.tex.  No number in the generated files is hand-typed.

Sources
-------
benchmark/results/tier_a_summary.json
benchmark/results/tier_b_summary.json
pair_joint/results/comparison.json
evidence_prompt/analysis/metrics.json
hybrid/results/hybrid_v2_metrics.json   (main hybrid results, leak-fixed)
hybrid/results/hybrid_v1_metrics.json   (audit only; pre-fix)
hybrid/results/hybrid_v2_vs_hybrid_v1.json
juliet_llm/runs/*postleakfix*/metrics.json
juliet_repair/report/comparison.json
analysis/cost_normalization.json
"""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "report"


def load(rel: str):
    with (ROOT / rel).open(encoding="utf-8") as fh:
        return json.load(fh)


def f(x: float, n: int = 3) -> str:
    return f"{x:.{n}f}"


def pct(x: float, n: int = 1) -> str:
    return f"{100.0 * x:.{n}f}"


def ci(d: dict, n: int = 3) -> str:
    return f"[{d['ci_low']:.{n}f}, {d['ci_high']:.{n}f}]"


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def sci(x: float) -> str:
    if x == 0:
        return "1.000"
    if x < 0.001:
        mant, exp = f"{x:.2e}".split("e")
        return f"\\ensuremath{{{mant}\\times10^{{{int(exp)}}}}}"
    return f"{x:.4f}"


TA = load("benchmark/results/tier_a_summary.json")
TB = load("benchmark/results/tier_b_summary.json")
PJ = load("pair_joint/results/comparison.json")
EV = load("evidence_prompt/analysis/metrics.json")
HY = load("hybrid/results/hybrid_v2_metrics.json")
HY1 = load("hybrid/results/hybrid_v1_metrics.json")
HYV = load("hybrid/results/hybrid_v2_vs_hybrid_v1.json")
RP = load("juliet_repair/report/comparison.json")
COST = load("analysis/cost_normalization.json")

JL = load(
    "juliet_llm/runs/20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix/metrics.json"
)
JL_REP = load(
    "juliet_llm/runs/20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro/metrics.json"
)
JL_PRE = load(
    "juliet_llm/runs/20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final/metrics.json"
)

# ---------------------------------------------------------------- Tier A
ta_runs = {(r["model_family"], r["task"], r["strategy"]): r for r in TA["runs"]}
models = {"deepseek": "DeepSeek", "mimo": "MiMo"}


def ta_det_rows() -> str:
    rows = []
    for model in ("deepseek", "mimo"):
        for strategy in ("direct", "few-shot", "context"):
            r = ta_runs[(model, "detection", strategy)]
            s = r["scores"]
            rows.append(
                " & ".join(
                    [
                        models[model],
                        strategy,
                        f"{s['valid']}/160",
                        f(s["precision"]),
                        f(s["recall"]),
                        f"{f(s['macro_f1'])} {ci(r['bootstrap']['macro_f1'])}",
                        f(s["mcc"]),
                        f(s["strict_accuracy"]),
                        f(r["cost"]["task_usd"], 6),
                        f(r["cost"]["latency_ms_p95"] / 1000, 2),
                    ]
                )
                + r" \\"
            )
    return "\n".join(rows)


def ta_pair_rows() -> str:
    rows = []
    for model in ("deepseek", "mimo"):
        for strategy in ("direct", "few-shot", "context"):
            r = ta_runs[(model, "pair", strategy)]
            s = r["scores"]
            jc = s["joint_categories"]
            lo, hi = s["wilson"]["joint_accuracy_valid_pairs"]["low"], s["wilson"]["joint_accuracy_valid_pairs"]["high"]
            rows.append(
                " & ".join(
                    [
                        models[model],
                        strategy,
                        str(jc["vulnerable_detected_fixed_clean"]),
                        f"{pct(s['joint_accuracy_valid_pairs'])} [{pct(lo)}, {pct(hi)}]",
                        pct(s["joint_accuracy_all_pairs"]),
                        str(jc["both_flagged"]),
                        str(jc["both_clean"]),
                        str(jc["vulnerable_missed_fixed_flagged"]),
                        f"{s['valid_pairs']}/180",
                        f(r["cost"]["task_usd"], 6),
                    ]
                )
                + r" \\"
            )
    return "\n".join(rows)


def ta_modelcmp_rows() -> str:
    rows = []
    for e in TA["comparisons"]["model"]["entries"]:
        rows.append(
            " & ".join(
                [
                    "检测" if e["task"] == "detection" else "配对",
                    e["strategy_a"],
                    f(e["delta"]),
                    ci(e["delta_ci"]),
                    str(e["alignment"].get("common_valid_units", e["alignment"].get("common_valid_pairs"))),
                    f"{e['mcnemar']['a_correct_b_wrong']}/{e['mcnemar']['a_wrong_b_correct']}",
                    sci(e["raw_p"]),
                    f(e["holm_p"], 4),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


def ta_cost_rows() -> str:
    rows = []
    for model in ("deepseek", "mimo"):
        m = TA["models"][model]
        rows.append(
            " & ".join(
                [
                    models[model],
                    f"{f(m['detection']['macro_f1_mean'])} ({f(m['detection']['macro_f1_min'])}--{f(m['detection']['macro_f1_max'])})",
                    f"{f(m['pair']['pair_da_mean'])} ({f(m['pair']['pair_da_min'])}--{f(m['pair']['pair_da_max'])})",
                    f(m["coverage_mean"]),
                    f(m["full_run_usd"], 6),
                    f(m["usd_per_100_requests"], 6),
                    f"{f(m['latency_ms_p50'] / 1000, 2)}/{f(m['latency_ms_p95'] / 1000, 2)}",
                    str(m["requests"]),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- pair joint
pj_runs = {r["model"]: r for r in PJ["runs"]}


def pj_rows() -> str:
    rows = []
    for model in ("deepseek-v4.1-flash", "mimo-v2.6-flash"):
        r = pj_runs[model]
        c = r["categories"]
        lo, hi = wilson(c["correct"], 180)
        pos = r["position"]
        ev = r["evidence"]
        rows.append(
            " & ".join(
                [
                    "DeepSeek" if model.startswith("deepseek") else "MiMo",
                    f"{c['correct']}/180",
                    f"{pct(r['joint_accuracy_all'])} [{pct(lo)}, {pct(hi)}]",
                    str(c["swapped"]),
                    pct(pos["by_vulnerable_slot"]["A"]["accuracy_all"]),
                    pct(pos["by_vulnerable_slot"]["B"]["accuracy_all"]),
                    pct(pos["difference_da_A_minus_da_B_all"]),
                    sci(pos["fisher_exact_p_all"]),
                    pct(ev["evidence_compliance_rate"]),
                    pct(ev["localization_hit_rate_correct"]),
                    f(r["cost"]["total_cost_usd"], 6),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- evidence prompt
EV_LABEL = {"deepseek": "DeepSeek", "mimo": "MiMo"}


def ev_rows() -> str:
    rows = []
    for model in ("deepseek", "mimo"):
        c = EV["models"][model]["comparison"]
        for prompt in ("direct", "evidence"):
            s = c[f"{prompt}_all"]
            cl = c[f"cost_latency_{prompt}"]
            rows.append(
                " & ".join(
                    [
                        EV_LABEL[model],
                        prompt,
                        f"{s['valid']}/160",
                        f(s["precision"]),
                        f(s["recall"]),
                        f(s["positive_f1"]),
                        f(s["macro_f1"]),
                        f(s["strict_accuracy"]),
                        f(s["predicted_positive_rate"]),
                        f(cl["total_cost_usd"], 6),
                        f(cl["latency_seconds"]["p95"], 2),
                    ]
                )
                + r" \\"
            )
    return "\n".join(rows)


def ev_cmp_rows() -> str:
    rows = []
    holm = {
        "deepseek:recall": EV["holm_family"]["holm_adjusted_p_values"][0],
        "deepseek:fpr": EV["holm_family"]["holm_adjusted_p_values"][1],
        "mimo:recall": EV["holm_family"]["holm_adjusted_p_values"][2],
        "mimo:fpr": EV["holm_family"]["holm_adjusted_p_values"][3],
    }
    for model in ("deepseek", "mimo"):
        c = EV["models"][model]["comparison"]
        for endpoint, key in (("recall", "recall_positive_subset"), ("fpr", "fpr_negative_subset")):
            m = c["mcnemar"][key]
            label = "召回" if endpoint == "recall" else "FPR"
            delta = c["deltas"][endpoint]
            rows.append(
                " & ".join(
                    [
                        EV_LABEL[model],
                        label,
                        pct(delta),
                        f"{m['a_correct_b_wrong']}/{m['a_wrong_b_correct']}",
                        sci(m["p_value"]),
                        f(holm[f"{model}:{endpoint}"], 4),
                    ]
                )
                + r" \\"
            )
    return "\n".join(rows)


# ---------------------------------------------------------------- Juliet static/dynamic
TB_METHODS = [
    ("static.clang.sa", "Clang SA 22.1.8"),
    ("static.cppcheck", "Cppcheck 2.21.0"),
    ("dynamic.asan_lsan", "ASan+LSan"),
    ("dynamic.combined", "ASan+LSan+Valgrind"),
    ("dynamic.valgrind", "Valgrind 3.27.1"),
]


def jb_static_rows() -> str:
    rows = []
    for mid, label in TB_METHODS:
        m = TB["views"]["test_all"]["methods"][mid]
        s = m["scores"]
        cf = s["confusion"]
        rows.append(
            " & ".join(
                [
                    label,
                    f"{s['valid']}/140",
                    f(s["coverage"]),
                    f"{cf['tp']}/{cf['fp']}/{cf['tn']}/{cf['fn']}",
                    f(s["precision"]),
                    f(s["recall"]),
                    f(s["specificity"]),
                    f"{f(s['macro_f1'])} {ci(m['bootstrap']['macro_f1'])}",
                    f(s["mcc"]),
                    f(s["strict_accuracy"]),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


def jb_dyn_rows() -> str:
    rows = []
    for mid in ("dynamic.asan_lsan", "dynamic.combined", "dynamic.valgrind"):
        m = TB["views"]["test_all"]["methods"][mid]
        c = m["conservative"]["scores"]
        rows.append(
            " & ".join(
                [
                    dict((k, v) for k, v in TB_METHODS)[mid],
                    f"{c['valid']}/{c['n']}",
                    f(c["coverage"]),
                    str(c["confusion"]["tp"]),
                    str(c["confusion"]["fp"]),
                    str(c["confusion"]["fn"]),
                    str(c["invalid"]),
                    f(c["recall"]),
                    f(c["precision"]),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


def jb_llm_rows() -> str:
    rows = []
    for label, d in (("修复后正式", JL), ("修复后复现", JL_REP), ("修复前（仅审计）", JL_PRE)):
        e = d["evaluation"]["strict"]
        a = d["aggregate"]
        rows.append(
            " & ".join(
                [
                    label,
                    f"{d['evaluation']['n_valid']}/140",
                    str(e["tp"]),
                    str(e["fp"]),
                    str(e["tn"]),
                    str(e["fn"]),
                    pct(e["accuracy"]),
                    f(e["f1"]),
                    f(e["mcc"]),
                    f(a["cost"]["published_price_usd"]["sum"], 6),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- hybrid
HY_METHODS = ("direct", "static", "dynamic", "combined", "shuffled")


def hybrid_rows() -> str:
    rows = []
    for model in ("deepseek", "mimo"):
        for method in HY_METHODS:
            r = HY["runs"][f"{model}/{method}"]
            s = r["strict"]
            u = r["usage"]
            rows.append(
                " & ".join(
                    [
                        EV_LABEL[model],
                        method,
                        f"{s['tp'] + s['tn']}/140",
                        pct(s["accuracy"], 2),
                        f(s["precision"]),
                        f(s["recall"]),
                        f(s["f1"]),
                        f(s["specificity"]),
                        f(s["mcc"]),
                        f(u["cost_usd_sum"], 6),
                    ]
                )
                + r" \\"
            )
    return "\n".join(rows)


def hybrid_cmp_rows() -> str:
    rows = []
    wanted = [
        ("deepseek", "direct", "dynamic"),
        ("deepseek", "direct", "combined"),
        ("deepseek", "direct", "shuffled"),
        ("deepseek", "combined", "shuffled"),
        ("mimo", "direct", "static"),
        ("mimo", "direct", "dynamic"),
        ("mimo", "direct", "combined"),
        ("mimo", "direct", "shuffled"),
        ("mimo", "combined", "shuffled"),
    ]
    for model, base, method in wanted:
        c = next(
            x for x in HY["comparisons"] if x["model"] == model and x["baseline"] == base and x["method"] == method
        )
        m = c["mcnemar"]
        rows.append(
            " & ".join(
                [
                    EV_LABEL[model],
                    f"{base}$\\to${method}",
                    f"{pct(c['accuracy_difference'], 2)} [{pct(c['accuracy_difference_ci95'][0], 2)}, {pct(c['accuracy_difference_ci95'][1], 2)}]",
                    f"{m['a_right_b_wrong']}/{m['a_wrong_b_right']}",
                    f(m["p_value_exact"], 4),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


def hybrid_audit_rows() -> str:
    rows = []
    for r in HYV["rows"]:
        rows.append(
            " & ".join(
                [
                    EV_LABEL[r["model"]],
                    r["method"],
                    f"{r['v1_correct']}/140",
                    f"{r['v2_correct']}/140",
                    f"{100.0 * r['delta']:+.2f} [{100.0 * r['delta_ci95'][0]:+.2f}, {100.0 * r['delta_ci95'][1]:+.2f}]",
                    f"{r['v1_right_v2_wrong']}/{r['v1_wrong_v2_right']}",
                    f(r["mcnemar"]["p_value_exact"], 4),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- cost basis
def cost_rows() -> str:
    runs = COST["runs"]

    def agg(pred) -> tuple[int, int, float, float, float, float]:
        sel = [r for r in runs if pred(r)]
        rec = sum(r["records"] for r in sel)
        conf = sum(r["configured_recorded_usd"] or 0.0 for r in sel)
        norm = sum(r["normalized_list_usd"] or 0.0 for r in sel)
        pl = sum(r["provider_list_usd"] or 0.0 for r in sel)
        al = sum(r["provider_allowance_usd"] or 0.0 for r in sel)
        return len(sel), rec, conf, norm, pl, al

    groups = [
        (
            "全部完整 run",
            agg(lambda r: r["data_complete"]),
        ),
        (
            "headline 17 run",
            agg(lambda r: r["class"] == "headline"),
        ),
        (
            "hybrid v1（审计）",
            agg(lambda r: r["run_id"].startswith("hybrid_v1")),
        ),
        (
            "hybrid v2（主结果）",
            agg(lambda r: r["run_id"].startswith("hybrid_v2")),
        ),
        (
            "juliet\\_llm 修复后两次",
            agg(lambda r: "postleakfix" in r["run_id"]),
        ),
        (
            "修复 headline",
            agg(lambda r: r["run_id"] in set(COST["juliet_repair"]["headline_runs"])),
        ),
        (
            "修复 all-in",
            agg(lambda r: r["category"] == "juliet_repair"),
        ),
    ]
    rows = []
    for label, (n, rec, conf, norm, pl, al) in groups:
        pl_cell = "---" if pl == 0 else f(pl, 6)
        al_cell = "---" if al == 0 else f(al, 6)
        rows.append(
            " & ".join(
                [
                    label,
                    str(n),
                    f"{rec:,}",
                    f(conf, 6),
                    f(norm, 6),
                    pl_cell,
                    al_cell,
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- repair
rp_runs = {r["model"]: r for r in RP["runs"]}


def repair_rows() -> str:
    rows = []
    for model in ("deepseek-v4.1-flash", "mimo-v2.6-flash"):
        r = rp_runs[model]
        rows.append(
            " & ".join(
                [
                    "DeepSeek" if model.startswith("deepseek") else "MiMo",
                    f"{r['compile_pass']}/70",
                    f"{r['leak_removed']}/70",
                    f"{r['behavior_preserved']}/70",
                    f"{r['strict_pass_observable']}/58",
                    f"{r['strict_pass_first_observable']}/58",
                    str(r["iterated_units"]),
                    str(r["calls"]),
                    f(r["cost_usd"], 6),
                ]
            )
            + r" \\"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------- macros
def macros() -> str:
    ds = {s: ta_runs[("deepseek", "detection", s)]["scores"]["macro_f1"] for s in ("direct", "few-shot", "context")}
    mi = {s: ta_runs[("mimo", "detection", s)]["scores"]["macro_f1"] for s in ("direct", "few-shot", "context")}
    ds_ci = {s: ta_runs[("deepseek", "detection", s)]["bootstrap"]["macro_f1"] for s in ds}
    mi_ci = {s: ta_runs[("mimo", "detection", s)]["bootstrap"]["macro_f1"] for s in mi}
    ds_pair = {s: ta_runs[("deepseek", "pair", s)]["scores"]["joint_accuracy_valid_pairs"] for s in ds}
    mi_pair = {s: ta_runs[("mimo", "pair", s)]["scores"]["joint_accuracy_valid_pairs"] for s in mi}

    lines = ["% Auto-generated by report/scripts/build_extended_tables.py. Do not edit."]

    def add(name: str, value: str):
        lines.append(rf"\newcommand{{\Num{name}}}{{{value}}}")

    for tag, d in (("DS", ds), ("Mi", mi)):
        for s, tag2 in (("direct", "Dir"), ("few-shot", "Few"), ("context", "Con")):
            add(f"TA{tag}{tag2}MF", f(d[s]))
    for tag, d in (("DS", ds_ci), ("Mi", mi_ci)):
        for s, tag2 in (("direct", "Dir"), ("few-shot", "Few"), ("context", "Con")):
            add(f"TA{tag}{tag2}CILo", f(d[s]["ci_low"]))
            add(f"TA{tag}{tag2}CIHi", f(d[s]["ci_high"]))
    for tag, d in (("DS", ds_pair), ("Mi", mi_pair)):
        for s, tag2 in (("direct", "Dir"), ("few-shot", "Few"), ("context", "Con")):
            add(f"TA{tag}Pair{tag2}", f(d[s]))

    mc = {e["strategy_a"]: e for e in TA["comparisons"]["model"]["entries"] if e["task"] == "detection"}
    e = mc["few-shot"]
    add("TAModelFewDelta", f(e["delta"]))
    add("TAModelFewCILo", f(e["delta_ci"]["ci_low"]))
    add("TAModelFewCIHi", f(e["delta_ci"]["ci_high"]))
    add("TAModelFewRawP", f(e["raw_p"], 4))
    add("TAModelFewHolmP", f(e["holm_p"], 4))
    add("TADSCoverage", f(TA["models"]["deepseek"]["coverage_mean"]))
    add("TAMiCoverage", f(TA["models"]["mimo"]["coverage_mean"]))
    add("TADSFullUSD", f(TA["models"]["deepseek"]["full_run_usd"], 6))
    add("TAMiFullUSD", f(TA["models"]["mimo"]["full_run_usd"], 6))
    add("TADSUSDPerHundred", f(TA["models"]["deepseek"]["usd_per_100_requests"], 6))
    add("TAMiUSDPerHundred", f(TA["models"]["mimo"]["usd_per_100_requests"], 6))

    pjr = pj_runs
    add("PJDSDA", pct(pjr["deepseek-v4.1-flash"]["joint_accuracy_all"], 2))
    add("PJMiDA", pct(pjr["mimo-v2.6-flash"]["joint_accuracy_all"], 2))
    add("PJDSA", pct(pjr["deepseek-v4.1-flash"]["position"]["by_vulnerable_slot"]["A"]["accuracy_all"], 2))
    add("PJDSB", pct(pjr["deepseek-v4.1-flash"]["position"]["by_vulnerable_slot"]["B"]["accuracy_all"], 2))
    add("PJMiA", pct(pjr["mimo-v2.6-flash"]["position"]["by_vulnerable_slot"]["A"]["accuracy_all"], 2))
    add("PJMiB", pct(pjr["mimo-v2.6-flash"]["position"]["by_vulnerable_slot"]["B"]["accuracy_all"], 2))
    add("PJDSFishP", sci(pjr["deepseek-v4.1-flash"]["position"]["fisher_exact_p_all"]))
    add("PJMiFishP", f(pjr["mimo-v2.6-flash"]["position"]["fisher_exact_p_all"], 4))
    add("PJHeur", pct(pjr["deepseek-v4.1-flash"]["length_confound"]["shorter_body_heuristic"]["characters_tie_A"], 2))
    add("PJDSLenP", f(pjr["deepseek-v4.1-flash"]["length_confound"]["mcnemar_joint_vs_shorter_characters"]["p_value"], 4))
    add("PJMiLenP", sci(pjr["mimo-v2.6-flash"]["length_confound"]["mcnemar_joint_vs_shorter_characters"]["p_value"]))
    add("PJDSUSD", f(pjr["deepseek-v4.1-flash"]["cost"]["total_cost_usd"], 6))
    add("PJMiUSD", f(pjr["mimo-v2.6-flash"]["cost"]["total_cost_usd"], 6))

    ev = EV["models"]
    for model, tag in (("deepseek", "DS"), ("mimo", "Mi")):
        c = ev[model]["comparison"]
        add(f"Ev{tag}RecBase", pct(c["direct_common"]["recall"]))
        add(f"Ev{tag}Rec", pct(c["evidence_common"]["recall"]))
        add(f"Ev{tag}DeltaRec", pct(c["deltas"]["recall"]))
        add(f"Ev{tag}FPRBase", pct(1.0 - c["direct_common"]["specificity"]))
        add(f"Ev{tag}FPR", pct(1.0 - c["evidence_common"]["specificity"]))
        add(f"Ev{tag}DeltaFPR", pct(c["deltas"]["fpr"]))
        add(f"Ev{tag}StrictBase", pct(c["direct_all"]["strict_accuracy"]))
        add(f"Ev{tag}Strict", pct(c["evidence_all"]["strict_accuracy"]))
        add(f"Ev{tag}PPRBase", pct(c["direct_common"]["predicted_positive_rate"]))
        add(f"Ev{tag}PPR", pct(c["evidence_common"]["predicted_positive_rate"]))
        add(f"Ev{tag}USDBase", f(c["cost_latency_direct"]["total_cost_usd"], 6))
        add(f"Ev{tag}USD", f(c["cost_latency_evidence"]["total_cost_usd"], 6))
    add("EvDSHolmRec", f(EV["holm_family"]["holm_adjusted_p_values"][0], 4))
    add("EvDSHolmFPR", f(EV["holm_family"]["holm_adjusted_p_values"][1], 4))
    add("EvMiHolmRec", f(EV["holm_family"]["holm_adjusted_p_values"][2], 4))
    add("EvMiHolmFPR", f(EV["holm_family"]["holm_adjusted_p_values"][3], 4))
    add("EvDSExact", f(ev["deepseek"]["comparison"]["evidence_audit"]["tp_exact_hit_rate"]))
    add("EvDSChance", f(ev["deepseek"]["comparison"]["evidence_audit"]["tp_exact_chance_mean"]))
    add("EvMiExact", f(ev["mimo"]["comparison"]["evidence_audit"]["tp_exact_hit_rate"]))
    add("EvMiChance", f(ev["mimo"]["comparison"]["evidence_audit"]["tp_exact_chance_mean"]))

    for mid, tag in (("static.clang.sa", "Clang"), ("static.cppcheck", "Cpp"), ("dynamic.asan_lsan", "Dyn")):
        m = TB["views"]["test_all"]["methods"][mid]
        s = m["scores"]
        add(f"Jb{tag}MF", f(s["macro_f1"]))
        add(f"Jb{tag}CILo", f(m["bootstrap"]["macro_f1"]["ci_low"]))
        add(f"Jb{tag}CIHi", f(m["bootstrap"]["macro_f1"]["ci_high"]))
        add(f"Jb{tag}MCC", f(s["mcc"]))
        add(f"Jb{tag}Cov", f(s["coverage"]))
        add(f"Jb{tag}Strict", f(s["strict_accuracy"]))
    cons = TB["views"]["test_all"]["methods"]["dynamic.asan_lsan"]["conservative"]["scores"]
    add("JbDynConsN", str(cons["valid"]))
    add("JbDynConsCov", f(cons["coverage"]))
    add("JbDynConsAbstain", str(cons["invalid"]))
    add("JlAcc", pct(JL["evaluation"]["strict"]["accuracy"], 2))
    add("JlF", f(JL["evaluation"]["strict"]["f1"]))
    add("JlMCC", f(JL["evaluation"]["strict"]["mcc"]))
    add("JlRepAcc", pct(JL_REP["evaluation"]["strict"]["accuracy"], 2))
    add("JlRepF", f(JL_REP["evaluation"]["strict"]["f1"]))
    add("JlCost", f(JL["aggregate"]["cost"]["published_price_usd"]["sum"], 6))
    add("JlPreAcc", pct(JL_PRE["evaluation"]["strict"]["accuracy"], 2))
    add("JlPreF", f(JL_PRE["evaluation"]["strict"]["f1"]))
    add("JlCAcc", pct(JL["evaluation"]["by_language"]["c"]["strict"]["accuracy"], 2))
    add("JlCppAcc", pct(JL["evaluation"]["by_language"]["cpp"]["strict"]["accuracy"], 2))

    hy = HY["runs"]
    add("HyDSDir", pct(hy["deepseek/direct"]["strict"]["accuracy"], 2))
    add("HyDSDyn", pct(hy["deepseek/dynamic"]["strict"]["accuracy"], 2))
    add("HyDSComb", pct(hy["deepseek/combined"]["strict"]["accuracy"], 2))
    add("HyDSDelta", pct(hy["deepseek/combined"]["strict"]["accuracy"] - hy["deepseek/direct"]["strict"]["accuracy"], 2))
    add("HyMiDir", pct(hy["mimo/direct"]["strict"]["accuracy"], 2))
    add("HyMiStatic", pct(hy["mimo/static"]["strict"]["accuracy"], 2))
    add("HyMiComb", pct(hy["mimo/combined"]["strict"]["accuracy"], 2))
    add("HyMiDelta", pct(hy["mimo/combined"]["strict"]["accuracy"] - hy["mimo/direct"]["strict"]["accuracy"], 2))
    add("HyDSCombP", f(next(c for c in HY["comparisons"] if c["model"] == "deepseek" and c["baseline"] == "direct" and c["method"] == "combined")["mcnemar"]["p_value_exact"], 4))
    add("HyMiCombP", f(next(c for c in HY["comparisons"] if c["model"] == "mimo" and c["baseline"] == "direct" and c["method"] == "combined")["mcnemar"]["p_value_exact"], 4))
    add("HyTotalUSD", f(sum(hy[k]["usage"]["cost_usd_sum"] for k in hy), 6))
    add("HyTotalCalls", str(sum(hy[k]["manifest"]["recorded_units"] for k in hy)))
    add("HyChangedUnits", str(HYV["changed_source_count"]))
    add("HyFlipRightWrong", str(HYV["flip_counts"]["v1_right_v2_wrong"]))
    add("HyFlipWrongRight", str(HYV["flip_counts"]["v1_wrong_v2_right"]))
    add("HyVoneDSComb", pct(HY1["runs"]["deepseek/combined"]["strict"]["accuracy"], 2))
    add("HyVoneDyn", pct(HY1["runs"]["deepseek/dynamic"]["strict"]["accuracy"], 2))
    add("HyPooledVone", pct(HYV["pooled"][2]["v1_accuracy"], 2))
    add("HyPooledVtwo", pct(HYV["pooled"][2]["v2_accuracy"], 2))

    jr = COST["juliet_repair"]
    add("CostHeadlineConf", f(COST["aggregates"]["headline"]["configured_recorded_usd"], 6))
    add("CostHeadlineNorm", f(COST["aggregates"]["headline"]["normalized_list_usd"], 6))
    add("CostAllConf", f(COST["aggregates"]["all_complete_with_usage"]["configured_recorded_usd"], 6))
    add("CostAllNorm", f(COST["aggregates"]["all_complete_with_usage"]["normalized_list_usd"], 6))
    add("CostAllRuns", str(COST["aggregates"]["all_complete_with_usage"]["runs"]))
    add("CostAllCalls", f"{COST['aggregates']['all_complete_with_usage']['usage_records']:,}")
    add("CostRepairHeadConf", f(jr["headline_configured_usd"], 6))
    add("CostRepairHeadNorm", f(jr["headline_normalized_usd"], 6))
    add("CostRepairAllConf", f(jr["all_configured_usd"], 6))
    add("CostRepairAllNorm", f(jr["all_normalized_usd"], 6))
    add("CostRepairOld", f(jr["readme_old_all_in_usd"], 6))
    add("CostRepairDelta", f(jr["delta_vs_old_readme_usd"], 6))

    add("RepObs", str(RP["leak_observable"]))
    add("RepUnits", "70")
    for model, tag in (("deepseek-v4.1-flash", "DS"), ("mimo-v2.6-flash", "Mi")):
        r = rp_runs[model]
        add(f"Rep{tag}Strict", str(r["strict_pass_observable"]))
        add(f"Rep{tag}First", str(r["strict_pass_first_observable"]))
        add(f"Rep{tag}Calls", str(r["calls"]))
        add(f"Rep{tag}Cost", f(r["cost_usd"], 6))
    add("RepTotalCost", f(sum(r["cost_usd"] for r in RP["runs"]), 6))

    return "\n".join(lines) + "\n"


TABLES = r"""
% Auto-generated by report/scripts/build_extended_tables.py. Do not edit.
\begin{table*}[t]
\caption{统一分层基准的两个层级与不可合并的原因}
\label{tab:bench-contract}
\centering
\scriptsize
\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}p{1.3cm}p{4.0cm}p{4.6cm}p{2.7cm}p{4.2cm}@{}}
\toprule
层级 & 数据与单元 & 方法 & 主终点 & 明确不外推\\
\midrule
Tier A & SecVulEval 冻结测试集；160 条函数、180 对版本；C/C++ 真实项目抽取片段 & DeepSeek/MiMo $\times$ direct / few-shot / context；配对联合提示；证据提示 & 检测 macro-F1；配对 DA & 不能外推到 Juliet 的合成单 CWE；不报告 Tier A 静态 F1\\
Tier B & Juliet CWE-401 v1.3 冻结子集；200 单元（dev 60 / test 140），100 组、42 家族 & Clang SA、Cppcheck、ASan/LSan、Valgrind、LLM、静态/动态证据混合 & 泄漏 macro-F1 + MCC，强制 coverage/strict & 不能外推到真实项目；动态 clean 不是 TN；单 CWE、模板化\\
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Tier A 检测：DeepSeek 与 MiMo 的三策略结果（160 条：128 正 / 32 负）}
\label{tab:ea-det}
\centering
\scriptsize
\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}llrrrrrrrr@{}}
\toprule
模型 & 策略 & 有效 & P & R & Macro-F1 [95\% CI] & MCC & Strict & 任务 USD & p95 (s)\\
\midrule
__TA_DET__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Tier A 配对联合判别：同一 180 对上的分侧调用结果}
\label{tab:ea-pair}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}llrrrrrrrr@{}}
\toprule
模型 & 策略 & 正确/180 & DA(valid) [95\% CI] & DA(all) & 双报漏洞 & 双报安全 & 判反 & 有效/180 & 任务 USD\\
\midrule
__TA_PAIR__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Tier A 同策略、同任务的模型比较（DeepSeek $-$ MiMo；McNemar + Holm）}
\label{tab:ea-modelcmp}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}llrrrrrr@{}}
\toprule
任务 & 策略 & $\Delta$ & 95\% CI & $n$ & $b/c$ & 原始 $p$ & Holm $p$\\
\midrule
__TA_MODELCMP__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Tier A 模型汇总（configured 口径；描述性；不跨策略池化单元）}
\label{tab:ea-cost}
\centering
\scriptsize
\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}lrrrrrrr@{}}
\toprule
模型 & 检测 macro-F1 均值（范围） & 配对 DA 均值（范围） & 平均覆盖 & 六 run USD & USD/100 请求 & p50/p95 (s) & 请求\\
\midrule
__TA_COST__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Pair-joint 强制二选一结果（180 对；每对一次请求）}
\label{tab:pj}
\centering
\scriptsize
\setlength{\tabcolsep}{3.2pt}
\begin{tabular}{@{}lrrrrrrrrrr@{}}
\toprule
模型 & 正确 & DA [95\% CI] & 判反 & DA(A) & DA(B) & $\Delta$(A$-$B) & Fisher $p$ & 证据合规 & 定位命中 & USD\\
\midrule
__PJ__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{结构化证据提示与 direct 基线（SecVulEval 160 条；valid-only 指标与 strict 全样本）}
\label{tab:ev}
\centering
\scriptsize
\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}llrrrrrrrrr@{}}
\toprule
模型 & 提示 & 有效 & P & R & F1+ & Macro-F1 & Strict & 预测正类率 & USD & p95 (s)\\
\midrule
__EV__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{证据提示相对 direct 的配对检验（共同 valid；2 模型 $\times$ 2 终点 Holm）}
\label{tab:ev-cmp}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}llrrrr@{}}
\toprule
模型 & 终点 & $\Delta$ (pp) & 不一致（新/旧） & 原始 $p$ & Holm $p$\\
\midrule
__EV_CMP__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet CWE-401 静态/动态结果（test 140：70 bad / 70 good；valid-only macro-F1）}
\label{tab:jb-static}
\centering
\scriptsize
\setlength{\tabcolsep}{3.2pt}
\begin{tabular}{@{}lrrrrrrrrr@{}}
\toprule
方法 & 有效 & 覆盖 & TP/FP/TN/FN & P & R & Spec & Macro-F1 [95\% CI] & MCC & Strict\\
\midrule
__JB_STATIC__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{动态保守视图：clean 弃权（test 140）}
\label{tab:jb-dyncons}
\centering
\scriptsize
\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}lrrrrrrrr@{}}
\toprule
方法 & 有效 & 覆盖 & TP & FP & FN & 弃权 & 召回 & 精确率\\
\midrule
__JB_DYN__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet CWE-401 LLM 直接检测（MiMo，test 140；Xiaomi 官方端点 fallback；修复前运行仅作审计）}
\label{tab:jb-llm}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}lrrrrrrrrr@{}}
\toprule
运行 & 有效 & TP & FP & TN & FN & Acc (\%) & F1 & MCC & 参考 USD\\
\midrule
__JB_LLM__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet 证据混合 v2（泄漏修复后）：2 模型 $\times$ 5 方法（test 140；strict 全样本；1{,}400/1{,}400 请求成功）}
\label{tab:hybrid}
\centering
\scriptsize
\setlength{\tabcolsep}{3.2pt}
\begin{tabular}{@{}llrrrrrrrr@{}}
\toprule
模型 & 方法 & 正确/140 & Acc (\%) & P & R & F1 & Spec & MCC & 列表 USD\\
\midrule
__HYBRID__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet 混合的配对比较（v2；pp；新对/旧对为方法对基线）}
\label{tab:hybrid-cmp}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}llrrr@{}}
\toprule
模型 & 对比 & $\Delta$ pp [95\% CI] & 新对/旧对 & McNemar $p$\\
\midrule
__HYBRID_CMP__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet 混合 v1$\to$v2 审计（v1 为清洗前；v2 为主结果；$\Delta$ = v2$-$v1）}
\label{tab:hybrid-audit}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}llrrrrr@{}}
\toprule
模型 & 方法 & v1 正确/140 & v2 正确/140 & $\Delta$ pp [95\% CI] & 翻转（对→错/错→对） & McNemar $p$\\
\midrule
__HYBRID_AUDIT__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{成本口径：configured 与 normalized provider-list 分列（USD；allowance 为额度扣减，不相加）}
\label{tab:cost-basis}
\centering
\scriptsize
\setlength{\tabcolsep}{3.6pt}
\begin{tabular}{@{}lrrrrrr@{}}
\toprule
组 & run & 调用 & configured & normalized & provider list & allowance\\
\midrule
__COST__
\bottomrule
\end{tabular}
\end{table*}

\begin{table*}[t]
\caption{Juliet 修复闭环：编译 + LSan + 行为差分（70 个 test bad 单元）}
\label{tab:repair-close}
\centering
\scriptsize
\setlength{\tabcolsep}{4pt}
\begin{tabular}{@{}lrrrrrrrr@{}}
\toprule
模型 & 编译/70 & LSan 干净/70 & 行为保持/70 & 严格通过/58 & 首次/58 & 迭代单元 & 调用 & USD\\
\midrule
__REPAIR__
\bottomrule
\end{tabular}
\end{table*}
"""


def main() -> None:
    table_text = TABLES
    table_text = table_text.replace("__TA_DET__", ta_det_rows())
    table_text = table_text.replace("__TA_PAIR__", ta_pair_rows())
    table_text = table_text.replace("__TA_MODELCMP__", ta_modelcmp_rows())
    table_text = table_text.replace("__TA_COST__", ta_cost_rows())
    table_text = table_text.replace("__PJ__", pj_rows())
    table_text = table_text.replace("__EV__", ev_rows())
    table_text = table_text.replace("__EV_CMP__", ev_cmp_rows())
    table_text = table_text.replace("__JB_STATIC__", jb_static_rows())
    table_text = table_text.replace("__JB_DYN__", jb_dyn_rows())
    table_text = table_text.replace("__JB_LLM__", jb_llm_rows())
    table_text = table_text.replace("__HYBRID__", hybrid_rows())
    table_text = table_text.replace("__HYBRID_CMP__", hybrid_cmp_rows())
    table_text = table_text.replace("__HYBRID_AUDIT__", hybrid_audit_rows())
    table_text = table_text.replace("__COST__", cost_rows())
    table_text = table_text.replace("__REPAIR__", repair_rows())

    (REPORT / "extended_tables.tex").write_text(table_text, encoding="utf-8")

    # Split the generated float blocks so each section can place its own tables.
    groups = {
        "extended_tables_tier_a.tex": ("tab:bench-contract", "tab:ea-det", "tab:ea-pair", "tab:ea-modelcmp", "tab:ea-cost"),
        "extended_tables_pj.tex": ("tab:pj", "tab:ev", "tab:ev-cmp"),
        "extended_tables_juliet.tex": ("tab:jb-static", "tab:jb-dyncons", "tab:jb-llm", "tab:hybrid", "tab:hybrid-cmp", "tab:hybrid-audit"),
        "extended_tables_cost.tex": ("tab:cost-basis",),
        "extended_tables_repair.tex": ("tab:repair-close",),
    }
    blocks = table_text.split("\\begin{table*}[t]")
    header = blocks[0]
    parsed = ["\\begin{table*}[t]" + b for b in blocks[1:]]
    for filename, labels in groups.items():
        chosen = [b for b in parsed if any(f"\\label{{{lab}}}" in b for lab in labels)]
        (REPORT / filename).write_text(header + "\n" + "\n".join(chosen), encoding="utf-8")

    (REPORT / "extended_numbers.tex").write_text(macros(), encoding="utf-8")
    print("wrote report/extended_tables*.tex and report/extended_numbers.tex")


if __name__ == "__main__":
    main()

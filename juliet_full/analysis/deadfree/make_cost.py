"""DeadFree (layer3, eval 2,656 units) cost comparison: our LoRA L4-D (opt.) on one RTX 3090 vs the cloud APIs.

  python3 make_cost.py   -> cost_deadfree.{json,csv,md}

Read-only on every input. No network: the public prices below were fetched once (2026-11-25) and are constants.

CLOUD  = what we were actually billed: sum of `cost` over the ledger call rows (llm/ledger.jsonl, kind == "call") of
         the layer3 eval runs, per 1,000 eval units. DeepSeek also recomputed from the logged token usage with
         llm/llmlane/pricing.py at the logged peak flag (check), all at peak, and all off-peak.
LOCAL  = GPU-seconds per unit x an hourly price.
         c1    = mean server_forward_s of the primary (fallback-kernel) latency300 c1 run (run_file in
                 latency_deadfree.csv).
         batch = GPU-seconds actually spent in the stored DeadFree eval predictions. L4-D: unit_forward_s (one forward
                 batch of all the unit's FULL questions), deduplicated per unit, from the three fold files; the opt.
                 equivalent scales each unit by its own n_questions_kept / unit_n_questions. Old LoRA L1/L3:
                 latency_s of the CV prediction files (server-side, batch size 1).
         Prices: rental (RunPod on-demand RTX 3090), electricity only (350 W board power x China business tariff).
ONE-OFF = training wall x world_size of the three L4-D folds (build/status/fold<k>.json); labelling = summed per-unit
          `seconds` of the layer1 gold run (the training labels).
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
JF = HERE.parents[1]  # juliet_full/
sys.dont_write_bytecode = True  # read-only outside this directory
sys.path.insert(0, str(JF / "llm"))
from llmlane.pricing import deepseek_cost_cny, jev_cost_usd  # noqa: E402

LEDGER = JF / "llm/ledger.jsonl"
UNITS = JF / "data/build/layer3.jsonl"
QUALITY = HERE / "deadfree_quality.json"
LATENCY = HERE / "latency_deadfree.csv"
L4D_FOLDS = [JF / f"l4d_ft/build/remote_results/lora_l4d/layer3/eval_r1_fold{k}.jsonl" for k in (0, 1, 2)]
L4D_MERGED = JF / "l4d_ft/results/lora_l4d/layer3/eval_r1.jsonl"
L4D_OPT_UNITS = JF / "l4d_ft/results/lora_l4d_opt/layer3/eval_r1_units.jsonl"
L4D_FULL_LAT300 = JF / "l4d_ft/results/lora_l4d/layer3/lat300_c1_fallback.jsonl"
JEV_L4D_UNITS = JF / "l4d_ft/results/jev_l4d/layer3/eval_r1_units.jsonl"
OLD_LORA_CV = {k: JF / f"decision_ft/results/decision_ft/layer3/{k[-2:]}_cv_v1.jsonl" for k in ("lora_L1", "lora_L3")}
TRAIN_STATUS = [JF / f"l4d_ft/build/status/fold{k}.json" for k in (0, 1, 2)]
GOLD_LAYER1 = JF / "l4d/build/gold_layer1.jsonl"
GOLD_LAYER1_LOG = JF / "l4d/raw_logs/gold_layer1.log"

ACCESS_DATE = "2026-11-25"
FX = {"usd_per_cny": 0.15005, "source_url": "https://api.frankfurter.app/latest?from=CNY&to=USD",
      "source": "Frankfurter API = ECB euro foreign exchange reference rates (cross rate CNY->USD), ECB date 2026-11-24",
      "date": ACCESS_DATE,
      "cross_check": "https://open.er-api.com/v6/latest/CNY gave 0.149742 (updated 2026-11-25 00:02 UTC); difference 0.2 %"}
RENTAL_USD_PER_H = 0.50
RENTAL_COMMUNITY_USD_PER_H = 0.22
RENTAL_SOURCE = ("https://www.runpod.io/pricing (RTX 3090, 24 GB VRAM: Secure Cloud $0.50/h on-demand = used here; "
                 "Community Cloud $0.22/h = sensitivity). Page HTML: data-secure=\"0.5\" data-community=\"0.22\".")
POWER_W = 350
POWER_SOURCE = ("https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3090-3090ti/ "
                "(Founders Edition specs: Graphics Card Power (W) RTX 3090 = 350)")
ELEC_CNY_PER_KWH = 0.791
ELEC_SOURCE = ("https://www.globalpetrolprices.com/China/electricity_prices/ (China, business tariff CNY 0.791/kWh, "
               "collected March 2026, incl. distribution, transmission, taxes), converted at fx.usd_per_cny")
ELEC_US_COMMERCIAL_USD_PER_KWH = 0.1427
ELEC_US_SOURCE = ("https://www.eia.gov/electricity/monthly/epm_table_grapher.php?t=epmt_5_6_a (EIA Table 5.6.A, "
                  "U.S. Total commercial, September 2026: 14.27 cents/kWh) - sensitivity only")

DS_RUNS = {f"deepseek_L{k}": {f"l3_n25_L{k}_r1", f"l3_apirest_L{k}_r1", f"l3_rest_L{k}_r1"} for k in (1, 2, 3)}
DS_RUNS["deepseek_L4"] = {"l3_n25_L4_r1", "l3_rest75_L4_r1"}
CLOUD = (
    [(key, "deepseek", f"L{key[-1]}", runs) for key, runs in DS_RUNS.items()]
    + [(f"jev_L{k}", "jev", f"L{k}", {f"l3_eval_L{k}_r1"}) for k in (1, 2, 3)]
    + [("jev_l4d", "jev", "L4D", {"eval_r1"})]
)
LOCAL = ("lora_l4d_opt", "lora_L1", "lora_L3")
BREAK_EVEN_VS = ("deepseek_L1", "deepseek_L4", "jev_L3", "jev_l4d")


def read_jsonl(path: Path) -> list[dict]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def rel(path: Path) -> str:
    return str(path.relative_to(JF))


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs)


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def eval_units() -> set[str]:
    units = {u["unit_id"] for u in read_jsonl(UNITS) if u["set"] == "eval"}
    assert len(units) == 2656, len(units)
    return units


def cloud_rows(ledger: list[dict], provider: str, strategy: str, runs: set[str]) -> list[dict]:
    return [r for r in ledger if r["provider"] == provider and r.get("layer") == "layer3"
            and r.get("strategy") == strategy and r["run_id"] in runs]


def coverage(key: str, rows: list[dict], units: set[str]) -> dict:
    """Each eval unit exactly once (per-unit methods) / each kept question exactly once (jev_l4d)."""
    bad_status = sum(r["status"] != "ok" for r in rows)
    if key == "jev_l4d":
        qids = Counter(r["qid"] for r in rows)
        per_unit = Counter(r["unit_id"] for r in rows)
        kept = {u["unit_id"]: u["extra"]["n_questions_kept"] for u in read_jsonl(JEV_L4D_UNITS)}
        ok = (max(qids.values()) == 1 and set(kept) == units
              and all(per_unit.get(u, 0) == kept[u] for u in units) and set(per_unit) <= units)
        return {"ok": ok and bad_status == 0, "n_calls": len(rows), "n_units_with_calls": len(per_unit),
                "n_units_without_kept_question": sum(v == 0 for v in kept.values()), "duplicate_qids": sum(
                    v > 1 for v in qids.values()), "non_ok_calls": bad_status,
                "check": f"qid unique; per-unit call count == n_questions_kept of {rel(JEV_L4D_UNITS)}"}
    per_unit = Counter(r["unit_id"] for r in rows)
    ok = set(per_unit) == units and max(per_unit.values()) == 1
    return {"ok": ok and bad_status == 0, "n_calls": len(rows), "n_units": len(per_unit),
            "duplicates": sum(v > 1 for v in per_unit.values()), "missing": len(units - set(per_unit)),
            "non_ok_calls": bad_status, "check": "unit_id set == layer3 eval units, each exactly once"}


def cloud_method(key: str, provider: str, strategy: str, runs: set[str], ledger: list[dict], units: set[str]) -> dict:
    rows = cloud_rows(ledger, provider, strategy, runs)
    cov = coverage(key, rows, units)
    assert cov["ok"], (key, cov)
    n = len(units)
    currency = {r["currency"] for r in rows}
    assert len(currency) == 1, currency
    currency = currency.pop()
    billed = sum(r["cost"] for r in rows)
    out = {"key": key, "where": "cloud", "provider": provider, "run_ids": sorted(runs), "n_calls": len(rows),
           "coverage": cov, "currency": currency, "billed_total": round(billed, 6),
           "billed_per_1k": round(billed / n * 1000, 6)}
    usage = [r.get("usage") or {} for r in rows]
    if provider == "deepseek":
        hit = sum(int(u.get("prompt_cache_hit_tokens") or 0) for u in usage)
        miss = sum(int(u.get("prompt_cache_miss_tokens") or 0) for u in usage)
        comp = sum(int(u.get("completion_tokens") or 0) for u in usage)
        n_peak = sum(bool(r.get("peak_price")) for r in rows)
        logged = sum(deepseek_cost_cny(r.get("usage"), bool(r.get("peak_price"))) for r in rows)
        peak = sum(deepseek_cost_cny(r.get("usage"), True) for r in rows)
        off = sum(deepseek_cost_cny(r.get("usage"), False) for r in rows)
        out.update({
            "tokens_per_unit": {"input": round((hit + miss) / n, 1), "input_cached": round(hit / n, 1),
                                "input_uncached": round(miss / n, 1), "output": round(comp / n, 1)},
            "cache_hit_share_of_input": round(hit / (hit + miss), 4),
            "peak_share_of_calls": round(n_peak / len(rows), 4), "n_peak_calls": n_peak,
            "recomputed_cny_at_logged_peak_flag": round(logged, 6),
            "recompute_rel_diff_vs_billed": round(logged / billed - 1, 6),
            "cny_per_1k_peak": round(peak / n * 1000, 6), "cny_per_1k_offpeak": round(off / n * 1000, 6),
        })
    else:
        inp = sum(int(u.get("input_tokens") or 0) for u in usage)
        outp = sum(int(u.get("output_tokens") or 0) for u in usage)
        recomputed = sum(jev_cost_usd(r.get("usage")) for r in rows)
        out.update({
            "tokens_per_unit": {"input": round(inp / n, 1), "input_cached": None, "output": round(outp / n, 1)},
            "calls_per_unit": round(len(rows) / n, 3),
            "peak_share_of_calls": None,
            "recomputed_usd": round(recomputed, 6), "recompute_rel_diff_vs_billed": round(recomputed / billed - 1, 6),
        })
    return out


def side_runs(ledger: list[dict]) -> list[dict]:
    """layer3 non-eval runs (latency300 c1, smoke): reported separately, never in the per-1k numbers."""
    agg: dict[tuple, list] = defaultdict(list)
    for r in ledger:
        if r.get("layer") == "layer3" and (r["run_id"].startswith("lat300_c1") or "smoke" in r["run_id"]):
            agg[(r["provider"], r.get("strategy"), r["run_id"], r["currency"])].append(r)
    return [{"provider": p, "strategy": s, "run_id": run, "currency": c, "n_calls": len(rs),
             "n_units": len({r["unit_id"] for r in rs}), "billed_total": round(sum(r["cost"] for r in rs), 6),
             "billed_per_1k_units": round(sum(r["cost"] for r in rs) / len({r["unit_id"] for r in rs}) * 1000, 6)}
            for (p, s, run, c), rs in sorted(agg.items())]


def latency_csv() -> dict[str, dict]:
    with open(LATENCY) as fh:
        return {r["quality_key"]: r for r in csv.DictReader(fh) if r["role"] == "primary"}


def c1_forward(run_file: str) -> dict:
    rows = [r for r in read_jsonl(JF / run_file) if r["status"] == "ok"]
    fw = [r["extra"]["server_forward_s"] for r in rows]
    return {"file": run_file, "n": len(rows), "mean_server_forward_s": mean(fw)}


def l4d_batch(units: set[str]) -> dict:
    per_unit: dict[str, tuple[float, int]] = {}
    n_rows = 0
    for path in L4D_FOLDS:
        for r in read_jsonl(path):
            n_rows += 1
            prev = per_unit.setdefault(r["unit_id"], (r["unit_forward_s"], r["unit_n_questions"]))
            assert prev == (r["unit_forward_s"], r["unit_n_questions"]), r["unit_id"]
    assert set(per_unit) == units, len(per_unit)
    assert n_rows == len(read_jsonl(L4D_MERGED)) == sum(nq for _, nq in per_unit.values())
    kept = {u["unit_id"]: u["extra"]["n_questions_kept"] for u in read_jsonl(L4D_OPT_UNITS)}
    assert set(kept) == units
    full_s = sum(s for s, _ in per_unit.values())
    opt_s = sum(s * kept[u] / nq for u, (s, nq) in per_unit.items())
    n_full = sum(nq for _, nq in per_unit.values())
    n_kept = sum(kept.values())
    # cross-check of the linear-in-questions scaling: same 300 units, measured pruned vs full server forward
    opt_lat = {r["unit_id"]: r["extra"] for r in read_jsonl(JF / latency_csv()["lora_l4d_opt"]["run_file"])}
    full_lat = {r["unit_id"]: r["extra"] for r in read_jsonl(L4D_FULL_LAT300)}
    common = sorted(set(opt_lat) & set(full_lat))
    fw_ratio = sum(opt_lat[u]["server_forward_s"] for u in common) / sum(full_lat[u]["server_forward_s"] for u in common)
    q_ratio = sum(opt_lat[u]["n_questions"] for u in common) / sum(full_lat[u]["n_questions"] for u in common)
    n = len(units)
    return {
        "files": [rel(p) for p in L4D_FOLDS], "opt_counts": rel(L4D_OPT_UNITS),
        "n_units": n, "n_questions_full": n_full, "n_questions_kept": n_kept,
        "gpu_s_per_unit_full": full_s / n,
        "gpu_s_per_unit_opt_scaled": opt_s / n,
        "method": "per unit: unit_forward_s x n_questions_kept / unit_n_questions, summed, / 2,656",
        "lat300_check": {"n_units": len(common), "forward_ratio_opt_over_full": round(fw_ratio, 4),
                         "question_ratio_opt_over_full": round(q_ratio, 4),
                         "gpu_s_per_unit_opt_by_forward_ratio": round(full_s / n * fw_ratio, 4),
                         "files": [latency_csv()["lora_l4d_opt"]["run_file"], rel(L4D_FULL_LAT300)]},
        "wall_s_eval_runs_incl_model_load": wall_of_fold_runs(),
    }


def wall_of_fold_runs() -> dict:
    out = {}
    for path in L4D_FOLDS:
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        out[path.name] = round((utc(meta["end_utc"]) - utc(meta["start_utc"])).total_seconds(), 1)
    return out


def old_lora_batch(key: str) -> dict:
    rows = read_jsonl(OLD_LORA_CV[key])
    assert len({r["unit_id"] for r in rows}) == len(rows) == 2656
    return {"file": rel(OLD_LORA_CV[key]), "n_units": len(rows),
            "gpu_s_per_unit": mean([r["latency_s"] for r in rows]),
            "method": "mean latency_s (server-side time per unit at batch size 1, one RTX 3090; meta latency_note)"}


def training() -> dict:
    folds = []
    for path in TRAIN_STATUS:
        st = json.loads(path.read_text())
        wall = (utc(st["finished_utc"]) - utc(st["started_utc"])).total_seconds()
        folds.append({"file": rel(path), "fold": st["job"], "world_size": st["world_size"], "wall_s": wall,
                      "train_s": st["train_s"], "gpu_h": wall * st["world_size"] / 3600})
    return {"folds": folds, "one_model": max(folds, key=lambda f: f["gpu_h"]),
            "cv_total_gpu_h": sum(f["gpu_h"] for f in folds)}


def labelling() -> dict:
    rows = read_jsonl(GOLD_LAYER1)
    last = GOLD_LAYER1_LOG.read_text().strip().splitlines()[-1]
    return {"file": rel(GOLD_LAYER1), "log": rel(GOLD_LAYER1_LOG), "n_units": len(rows),
            "sum_unit_seconds": sum(r["seconds"] for r in rows), "log_last_line": last}


def per_1k_usd(gpu_s_per_unit: float, usd_per_h: float) -> float:
    return gpu_s_per_unit * 1000 / 3600 * usd_per_h


def break_even(one_off_usd: float, ours_per_unit: float, cloud_per_unit: float) -> int | str:
    if cloud_per_unit <= ours_per_unit:
        return "never"
    return int(-(-one_off_usd // (cloud_per_unit - ours_per_unit)))  # ceil


def main() -> None:
    units = eval_units()
    ledger = [r for r in read_jsonl(LEDGER) if r.get("kind") == "call"]
    quality = {m["key"]: m for m in json.loads(QUALITY.read_text())["methods"]}
    lat = latency_csv()
    fx = FX["usd_per_cny"]
    elec_usd_per_kwh = ELEC_CNY_PER_KWH * fx
    elec_usd_per_gpu_h = POWER_W / 1000 * elec_usd_per_kwh

    methods = []
    for key, provider, strategy, runs in CLOUD:
        c = cloud_method(key, provider, strategy, runs, ledger, units)
        to_usd = fx if c["currency"] == "CNY" else 1.0
        m = {"key": key, "label": quality[key]["label"], "where": "cloud",
             "track": "generative" if provider == "deepseek" else "decision",
             "macro_f1": quality[key]["macro_f1"], "macro_f1_ci": quality[key]["macro_f1_ci"],
             "latency_s": float(lat[key]["median_s"]), "latency_basis": "c1 e2e median, latency_deadfree.csv",
             "usd_per_1k": round(c["billed_per_1k"] * to_usd, 6),
             "native_currency": c["currency"], "native_per_1k": c["billed_per_1k"], "native_total": c["billed_total"],
             "usd_total": round(c["billed_total"] * to_usd, 6)}
        if provider == "deepseek":
            m["cny_per_1k_peak"] = c["cny_per_1k_peak"]
            m["cny_per_1k_offpeak"] = c["cny_per_1k_offpeak"]
            m["usd_per_1k_peak"] = round(c["cny_per_1k_peak"] * fx, 6)
            m["usd_per_1k_offpeak"] = round(c["cny_per_1k_offpeak"] * fx, 6)
        m.update({"tokens_per_unit": c["tokens_per_unit"], "peak_share_of_calls": c["peak_share_of_calls"],
                  "n_calls": c["n_calls"], "coverage": c["coverage"],
                  "recompute_rel_diff_vs_billed": c["recompute_rel_diff_vs_billed"],
                  "basis": f"{rel(LEDGER)} kind=call provider={provider} layer=layer3 strategy={strategy} "
                           f"run_id in {sorted(runs)}; sum(cost)/2656*1000"})
        if "calls_per_unit" in c:
            m["calls_per_unit"] = c["calls_per_unit"]
        if "cache_hit_share_of_input" in c:
            m["cache_hit_share_of_input"] = c["cache_hit_share_of_input"]
        methods.append(m)

    l4d = l4d_batch(units)
    for key in LOCAL:
        c1 = c1_forward(lat[key]["run_file"])
        if key == "lora_l4d_opt":
            batch_s = l4d["gpu_s_per_unit_opt_scaled"]
            basis = (f"c1: mean extra.server_forward_s of {c1['file']} (n={c1['n']}, fallback kernel = prediction "
                     f"config). batch: {l4d['method']} over {', '.join(l4d['files'])}; kept counts from "
                     f"{l4d['opt_counts']}")
            secondary = False
        else:
            ob = old_lora_batch(key)
            batch_s = ob["gpu_s_per_unit"]
            basis = (f"c1: mean extra.server_forward_s of {c1['file']} (n={c1['n']}). batch: {ob['method']} of "
                     f"{ob['file']}")
            secondary = True
        m = {"key": key, "label": quality[key]["label"], "where": "local", "track": "decision",
             "secondary": secondary,
             "macro_f1": quality[key]["macro_f1"], "macro_f1_ci": quality[key]["macro_f1_ci"],
             "latency_s": float(lat[key]["median_s"]), "latency_basis": "c1 e2e median, latency_deadfree.csv",
             "gpu_s_per_unit_c1": round(c1["mean_server_forward_s"], 4),
             "gpu_s_per_unit_batch": round(batch_s, 4),
             "usd_per_1k": round(per_1k_usd(batch_s, RENTAL_USD_PER_H), 6),
             "usd_per_1k_batch_rental": round(per_1k_usd(batch_s, RENTAL_USD_PER_H), 6),
             "usd_per_1k_c1_rental": round(per_1k_usd(c1["mean_server_forward_s"], RENTAL_USD_PER_H), 6),
             "usd_per_1k_batch_rental_community": round(per_1k_usd(batch_s, RENTAL_COMMUNITY_USD_PER_H), 6),
             "usd_per_1k_electricity": round(per_1k_usd(batch_s, elec_usd_per_gpu_h), 6),
             "usd_per_1k_c1_electricity": round(per_1k_usd(c1["mean_server_forward_s"], elec_usd_per_gpu_h), 6),
             "basis": basis}
        methods.append(m)

    tr = training()
    lab = labelling()
    one = tr["one_model"]
    lab_h = lab["sum_unit_seconds"] / 3600
    one_off_usd = one["gpu_h"] * RENTAL_USD_PER_H + lab_h * RENTAL_USD_PER_H
    one_off = {
        "train_gpu_h_one_model": round(one["gpu_h"], 3),
        "train_gpu_h_cv_total": round(tr["cv_total_gpu_h"], 3),
        "train_folds": [{k: (round(v, 3) if isinstance(v, float) else v) for k, v in f.items()} for f in tr["folds"]],
        "usd_rental_one_model": round(one["gpu_h"] * RENTAL_USD_PER_H, 4),
        "usd_rental_cv_total": round(tr["cv_total_gpu_h"] * RENTAL_USD_PER_H, 4),
        "labeling_cpu_h": round(lab_h, 4),
        "labeling_wall_s": lab["log_last_line"],
        "usd_rental_labeling": round(lab_h * RENTAL_USD_PER_H, 5),
        "usd_one_off_total_used_for_break_even": round(one_off_usd, 4),
        "notes": [
            "one model = the largest of the three folds (fold0, 2 GPUs DDP): GPU-h = (finished_utc - started_utc) x "
            "world_size from l4d_ft/build/status/fold<k>.json; includes model load and 4 dev evals per fold. Pure "
            "train_s x 2 would be lower (train_s field).",
            "A real deployment model trained on all three folds' data would see ~1.5x the questions; not measured.",
            "Not counted: smoke/speed tests, dev re-selection runs, the layer1/placebo/original eval predictions, "
            "the old-LoRA (decision_ft) training, engineering time.",
            f"labelling = sum of per-unit `seconds` in {lab['file']} (dynamic gold: compile + traced runs + fault "
            f"injection, dell i5-12500 CPU, 8 threads; per-unit wall time inside a worker thread, so ~CPU-thread "
            f"time). Priced at the GPU rental rate as a deliberate upper bound. layer3 gold is eval-only and not "
            f"part of the deployment cost.",
        ],
    }

    by_key = {m["key"]: m for m in methods}
    ours = by_key["lora_l4d_opt"]
    ours_unit = ours["usd_per_1k_batch_rental"] / 1000
    ours_unit_c1 = ours["usd_per_1k_c1_rental"] / 1000
    be = {k: break_even(one_off_usd, ours_unit, by_key[k]["usd_per_1k"] / 1000) for k in BREAK_EVEN_VS}
    be_sens = {
        "c1_rental": {k: break_even(one_off_usd, ours_unit_c1, by_key[k]["usd_per_1k"] / 1000) for k in BREAK_EVEN_VS},
        "community_rental_batch": {k: break_even(
            one["gpu_h"] * RENTAL_COMMUNITY_USD_PER_H + lab_h * RENTAL_COMMUNITY_USD_PER_H,
            ours["usd_per_1k_batch_rental_community"] / 1000, by_key[k]["usd_per_1k"] / 1000) for k in BREAK_EVEN_VS},
        "owned_electricity_only": {k: break_even(
            (one["gpu_h"] + lab_h) * elec_usd_per_gpu_h,  # labelling CPU-h at 350 W too: generous upper bound
            ours["usd_per_1k_electricity"] / 1000, by_key[k]["usd_per_1k"] / 1000) for k in BREAK_EVEN_VS},
        "deepseek_all_offpeak": {k: break_even(one_off_usd, ours_unit, by_key[k]["usd_per_1k_offpeak"] / 1000)
                                 for k in ("deepseek_L1", "deepseek_L4")},
        "deepseek_all_peak": {k: break_even(one_off_usd, ours_unit, by_key[k]["usd_per_1k_peak"] / 1000)
                              for k in ("deepseek_L1", "deepseek_L4")},
    }

    result = {
        "eval_set": "layer3 (DeadFree) eval", "n_units": len(units), "units_file": rel(UNITS),
        "fx": FX,
        "gpu_prices": {
            "rental_usd_per_h": RENTAL_USD_PER_H, "rental_source": RENTAL_SOURCE, "rental_date": ACCESS_DATE,
            "rental_community_usd_per_h": RENTAL_COMMUNITY_USD_PER_H,
            "power_w": POWER_W, "power_source": POWER_SOURCE,
            "electricity_cny_per_kwh": ELEC_CNY_PER_KWH,
            "electricity_usd_per_kwh": round(elec_usd_per_kwh, 5), "electricity_source": ELEC_SOURCE,
            "electricity_date": ACCESS_DATE,
            "electricity_usd_per_gpu_h": round(elec_usd_per_gpu_h, 5),
            "electricity_us_commercial_usd_per_kwh": ELEC_US_COMMERCIAL_USD_PER_KWH,
            "electricity_us_source": ELEC_US_SOURCE,
            "electricity_note": "lower bound: board power at full 350 W for the GPU-seconds only; excludes host "
                                "CPU/PSU losses, idle time and the hardware purchase",
            "amortized": "not included: no readable public RTX 3090 street-price page was found with our tools "
                         "(bestvaluegpu.com returned 403; the Tom's Hardware price tracker no longer lists the 3090)",
        },
        "methods": methods,
        "l4d_batch_detail": l4d,
        "one_off": one_off,
        "break_even_units": be,
        "break_even_basis": "ours = one_off.usd_one_off_total_used_for_break_even + N x lora_l4d_opt batch rental "
                            "per unit; cloud = N x billed per unit; N = ceil(one_off / (cloud - ours)); 'never' when "
                            "ours per unit >= cloud per unit",
        "break_even_sensitivity": be_sens,
        "side_runs_not_in_per_1k": side_runs(ledger),
        "notes": [
            "Cloud = what we were billed, with DeepSeek prefix caching and off-peak scheduling (peak gate in "
            "llm/llmlane/pricing.py); Jev bills input tokens only (output free).",
            "Local = GPU time only; excludes engineering time, the host machine, storage, idle GPU time between "
            "requests, and hardware purchase (rental rate already includes it implicitly).",
            "Local batch for L4-D (opt.) is an estimate: the stored eval predictions asked the FULL question set; "
            "each unit's forward time is scaled by its kept/full question ratio (42 % kept). The latency300 "
            "pruned-vs-full forward ratio is given as a cross-check in l4d_batch_detail.lat300_check.",
            "Local units are processed one unit per forward batch (as in eval and latency300). Batching several "
            "units per forward would lower GPU-s per unit; not measured.",
            "Old LoRA L1/L3 rows are secondary (much lower macro-F1).",
            "macro_f1 from deadfree_quality.json; latency_s = c1 e2e median from latency_deadfree.csv (primary rows).",
        ],
    }
    (HERE / "cost_deadfree.json").write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
    write_tables(result)


def fmt(x, nd=4):
    return "–" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


def write_tables(res: dict) -> None:
    cols = ["key", "label", "where", "track", "macro_f1", "latency_s", "usd_per_1k", "native_currency",
            "native_per_1k", "usd_per_1k_peak", "usd_per_1k_offpeak", "usd_per_1k_batch_rental",
            "usd_per_1k_c1_rental", "usd_per_1k_electricity", "gpu_s_per_unit_batch", "gpu_s_per_unit_c1",
            "tok_in_per_unit", "tok_cached_per_unit", "tok_out_per_unit", "peak_share_of_calls", "n_calls"]
    with open(HERE / "cost_deadfree.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for m in res["methods"]:
            tok = m.get("tokens_per_unit") or {}
            vals = {**m, "tok_in_per_unit": tok.get("input"), "tok_cached_per_unit": tok.get("input_cached"),
                    "tok_out_per_unit": tok.get("output")}
            w.writerow(["" if vals.get(c) is None else vals.get(c) for c in cols])

    g, o, be = res["gpu_prices"], res["one_off"], res["break_even_units"]
    lines = [
        "# DeadFree (layer3 eval, 2,656 units) — cost per 1,000 units",
        "",
        f"FX {res['fx']['usd_per_cny']} USD/CNY ({res['fx']['source']}, fetched {res['fx']['date']}). "
        f"RTX 3090 rental ${g['rental_usd_per_h']}/h (RunPod Secure Cloud, {g['rental_date']}); electricity "
        f"{g['power_w']} W × ${g['electricity_usd_per_kwh']}/kWh = ${g['electricity_usd_per_gpu_h']}/GPU-h.",
        "",
        "| method | where | macro-F1 | c1 median s | $ / 1k units | native / 1k | notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for m in res["methods"]:
        if m["where"] == "cloud":
            native = f"{'¥' if m['native_currency'] == 'CNY' else '$'}{m['native_per_1k']:.4f}"
            note = (f"peak ${m['usd_per_1k_peak']:.4f} / off-peak ${m['usd_per_1k_offpeak']:.4f}; "
                    f"{m['peak_share_of_calls']:.0%} calls at peak" if "usd_per_1k_peak" in m
                    else f"{m['tokens_per_unit']['input']:.0f} input tok/unit")
        else:
            native = "–"
            note = (f"batch {m['gpu_s_per_unit_batch']:.3f} GPU-s/unit; c1 ${m['usd_per_1k_c1_rental']:.4f}; "
                    f"electricity ${m['usd_per_1k_electricity']:.4f}" + (" (secondary)" if m["secondary"] else ""))
        lines.append(f"| {m['label']} | {m['where']} | {m['macro_f1']:.3f} | {m['latency_s']:.3f} | "
                     f"${m['usd_per_1k']:.4f} | {native} | {note} |")
    lines += [
        "",
        f"One-off (ours): training {o['train_gpu_h_one_model']} GPU-h for one fold model "
        f"(${o['usd_rental_one_model']:.2f} at rental), 3-fold CV total {o['train_gpu_h_cv_total']} GPU-h "
        f"(${o['usd_rental_cv_total']:.2f}); labelling {o['labeling_cpu_h']} CPU-h (${o['usd_rental_labeling']:.4f}).",
        "",
        "Break-even (units after which ours = one-off + batch rental per unit is cheaper):",
        "",
        "| vs | units |",
        "|---|---|",
    ] + [f"| {k} | {v if isinstance(v, str) else f'{v:,}'} |" for k, v in be.items()]
    sens = res["break_even_sensitivity"]
    lines += ["", "Break-even sensitivity:", "", "| scenario | " + " | ".join(BREAK_EVEN_VS) + " |",
              "|---|" + "---|" * len(BREAK_EVEN_VS)]
    for name, vals in sens.items():
        cells = [vals.get(k, "–") for k in BREAK_EVEN_VS]
        lines.append(f"| {name} | " + " | ".join(c if isinstance(c, str) else f"{c:,}" for c in cells) + " |")
    (HERE / "cost_deadfree.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

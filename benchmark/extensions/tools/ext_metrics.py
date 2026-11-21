#!/usr/bin/env python3
"""Compute design-specific metrics for extension runs.

The parent ``bench_metrics.compute_run_metrics`` block is embedded where it
applies, so detection/pair/leak arithmetic is identical to the main benchmark.
On top of it this tool adds only the endpoints that the parent task cannot
express:

* position-debiased pair: position-average DA, order-consensus DA, order
  consistency, slot position bias, and a length audit;
* open-choice pair: the four-way distribution, decisiveness, conditional DA and
  slot bias;
* evidence verification: claim-level detection plus abstention, false-support
  and false-reject rates;
* fault-injected dynamic: fault sensitivity/specificity, masking/false-alarm,
  inconclusive rate and flips against the no-fault baseline;
* new static tool: warning counts, severity sensitivity and optional agreement
  with an existing static baseline.

All intervals use Wilson for proportions and cluster percentile bootstrap for
F1/MCC/BA and paired contrasts. The two presentations of a position pair are
never treated as independent pairs.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ext_common import (  # noqa: E402
    DEFAULT_BOOTSTRAP_RESAMPLES,
    DEFAULT_BOOTSTRAP_SEED,
    DEFAULT_CONFIDENCE,
    DESIGNS_PATH,
    EXTENSION_METRICS_SCHEMA,
    EXTENSION_VERSION,
    ExtensionError,
    agreement_counts,
    as_bool,
    as_number,
    cluster_bootstrap,
    cohen_kappa,
    cost_summary,
    coverage_bucket,
    coverage_sufficient,
    count_by,
    detection_scores,
    fmt,
    infer_design,
    load_extension_run,
    pair_scores,
    percentile,
    rate,
    resolve_path,
    sha256_file,
    summarize_diagnostics,
    utc_now,
    wilson_interval,
    atomic_write_json,
    atomic_write_text,
)
from ext_validate import validate_extension_run  # noqa: E402
from bench_common import bootstrap_detection, mcnemar_exact  # noqa: E402
from bench_metrics import compute_run_metrics  # noqa: E402


# ---------------------------------------------------------------------------
# Small metric helpers
# ---------------------------------------------------------------------------


def _metric(
    value: Any,
    n: int | None,
    *,
    ci: Mapping[str, Any] | None = None,
    method: str = "point estimate",
    note: str | None = None,
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "value": value,
        "n": n,
        "ci_low": None if ci is None else ci.get("ci_low"),
        "ci_high": None if ci is None else ci.get("ci_high"),
        "method": method,
        "note": note,
    }
    return block


def _boot_ci(bootstrap: Mapping[str, Any], name: str) -> dict[str, Any]:
    item = (bootstrap.get("metrics") or {}).get(name) or {}
    return {
        "ci_low": item.get("ci_low"),
        "ci_high": item.get("ci_high"),
        "valid_resamples": item.get("valid_resamples"),
        "unstable": item.get("unstable"),
    }


def _wilson(successes: int, total: int) -> dict[str, Any] | None:
    return wilson_interval(successes, total, confidence=DEFAULT_CONFIDENCE)


def _proportion(successes: int, total: int, *, method: str = "wilson") -> dict[str, Any]:
    ci = _wilson(successes, total)
    return _metric(
        rate(successes, total),
        total,
        ci=ci,
        method=method,
        note=f"{successes}/{total}",
    )


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _sum_known(values: Sequence[float | None]) -> tuple[float | None, int]:
    known = [float(value) for value in values if value is not None]
    return (sum(known) if known else None, len(known))


def _merge_cost(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return cost_summary(records)


def _run_hashes(run_dir: Path) -> dict[str, Any]:
    hashes: dict[str, Any] = {
        "run_manifest_sha256": sha256_file(run_dir / "run_manifest.json"),
    }
    manifest, _, records, predictions_path = load_extension_run(run_dir)
    hashes["predictions_sha256"] = sha256_file(predictions_path)
    if (run_dir / "extension_manifest.json").exists():
        hashes["extension_manifest_sha256"] = sha256_file(run_dir / "extension_manifest.json")
    hashes["design_registry_sha256"] = sha256_file(DESIGNS_PATH)
    hashes["records"] = len(records)
    return hashes


def _pair_groups(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Mapping[str, Any]]]:
    groups: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for record in records:
        group_id = record.get("group_id")
        side = record.get("side")
        if group_id and side in ("vulnerable", "fixed"):
            groups[str(group_id)][str(side)] = record
    return dict(groups)


def _selected_side(record: Mapping[str, Any]) -> str | None:
    block = record.get("extensions") or {}
    value = block.get("selected_side")
    return value if value in ("vulnerable", "fixed") else None


def _position_view(run_dir: Path) -> dict[str, Any]:
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    if not ext_manifest or ext_manifest.get("design") != "position_debiased_pair":
        raise ExtensionError(f"{run_dir}: not a position_debiased_pair run")
    order = ext_manifest.get("presentation_order")
    if order not in ("AB", "BA", "fwd", "rev"):
        raise ExtensionError(f"{run_dir}: invalid presentation_order")
    groups = _pair_groups(records)
    view: dict[str, Any] = {}
    for pair_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        sample = sides["vulnerable"]
        block = sample.get("extensions") or {}
        pm = block.get("position_map") or {}
        vulnerable_slot = "A" if pm.get("A") == "vulnerable" else ("B" if pm.get("B") == "vulnerable" else None)
        valid = (
            sides["vulnerable"].get("status") == "ok"
            and sides["fixed"].get("status") == "ok"
            and block.get("selected_side") in ("vulnerable", "fixed")
            and block.get("choice") in ("A", "B")
        )
        view[pair_id] = {
            "pair_id": pair_id,
            "order": order,
            "choice": block.get("choice"),
            "selected_side": block.get("selected_side"),
            "vulnerable_slot": vulnerable_slot,
            "valid": valid,
            "correct": valid and block.get("selected_side") == "vulnerable",
            "lengths": block.get("length_chars"),
            "longer_side": block.get("longer_side"),
            "project": block.get("pair_project"),
            "statuses": {side: record.get("status") for side, record in sides.items()},
            "records": sides,
        }
    return {
        "manifest": manifest,
        "extension_manifest": ext_manifest,
        "records": records,
        "order": order,
        "pairs": view,
        "run_dir": run_dir,
    }


def _pair_correct_map(run_dir: Path) -> dict[str, bool]:
    _, _, records, _ = load_extension_run(run_dir)
    groups = _pair_groups(records)
    result: dict[str, bool] = {}
    for pair_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        v = sides["vulnerable"]
        f = sides["fixed"]
        if v.get("status") != "ok" or f.get("status") != "ok":
            continue
        y_v = as_bool((v.get("prediction") or {}).get("y_pred"))
        y_f = as_bool((f.get("prediction") or {}).get("y_pred"))
        if y_v is None or y_f is None:
            continue
        result[pair_id] = bool(y_v and not y_f)
    return result


# ---------------------------------------------------------------------------
# Position-debiased pair
# ---------------------------------------------------------------------------


def position_metrics(
    ab_dir: Path,
    ba_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    report_a = validate_extension_run(ab_dir, sibling_run_dir=ba_dir, use_jsonschema=False)
    report_b = validate_extension_run(ba_dir, sibling_run_dir=ab_dir, use_jsonschema=False)
    if report_a.get("errors") or report_b.get("errors"):
        raise ExtensionError(
            "position runs failed validation: "
            + "; ".join((report_a.get("errors") or [])[:3] + (report_b.get("errors") or [])[:3])
        )
    ab = _position_view(ab_dir)
    ba = _position_view(ba_dir)
    if ab["extension_manifest"].get("pairing_id") != ba["extension_manifest"].get("pairing_id"):
        raise ExtensionError("position runs have different pairing_id")
    all_pairs = sorted(set(ab["pairs"]) | set(ba["pairs"]))
    both_pairs = sorted(set(ab["pairs"]) & set(ba["pairs"]))
    valid_pairs: list[str] = []
    rows: list[dict[str, Any]] = []
    for pair_id in both_pairs:
        a = ab["pairs"][pair_id]
        b = ba["pairs"][pair_id]
        if not (a["valid"] and b["valid"]):
            continue
        correct_ab = bool(a["correct"])
        correct_ba = bool(b["correct"])
        selected_ab = a["selected_side"]
        selected_ba = b["selected_side"]
        consistent = selected_ab == selected_ba
        both_correct = correct_ab and correct_ba
        rows.append(
            {
                "pair_id": pair_id,
                "correct_ab": correct_ab,
                "correct_ba": correct_ba,
                "both_correct": both_correct,
                "consistent": consistent,
                "selected_ab": selected_ab,
                "selected_ba": selected_ba,
                "choice_ab": a["choice"],
                "choice_ba": b["choice"],
                "vulnerable_slot_ab": a["vulnerable_slot"],
                "vulnerable_slot_ba": b["vulnerable_slot"],
                "longer_side": a["longer_side"],
                "lengths": a["lengths"],
                "project": a["project"],
            }
        )
        valid_pairs.append(pair_id)
    n_valid = len(rows)
    if n_valid == 0:
        raise ExtensionError("position runs have no valid pair with both presentations")

    def arrays(indices: Sequence[int]) -> dict[str, Any]:
        subset = [rows[i] for i in indices]
        correct_ab = [row["correct_ab"] for row in subset]
        correct_ba = [row["correct_ba"] for row in subset]
        consistent = [row["consistent"] for row in subset]
        both = [row["both_correct"] for row in subset]
        return {
            "correct_ab": correct_ab,
            "correct_ba": correct_ba,
            "consistent": consistent,
            "both": both,
            "n": len(subset),
        }

    def mean_metric(indices: Sequence[int], key: str) -> float | None:
        data = arrays(indices)
        values = data[key]
        return _mean([1.0 if value else 0.0 for value in values])

    def position_avg(indices: Sequence[int]) -> float | None:
        data = arrays(indices)
        return _mean(
            [
                (1.0 if a else 0.0) * 0.5 + (1.0 if b else 0.0) * 0.5
                for a, b in zip(data["correct_ab"], data["correct_ba"])
            ]
        )

    def slot_values(subset: Sequence[Mapping[str, Any]], slot: str) -> list[float]:
        values: list[float] = []
        for row in subset:
            if row["vulnerable_slot_ab"] == slot:
                values.append(1.0 if row["correct_ab"] else 0.0)
            if row["vulnerable_slot_ba"] == slot:
                values.append(1.0 if row["correct_ba"] else 0.0)
        return values

    def slot_a(indices: Sequence[int]) -> float | None:
        return _mean(slot_values([rows[i] for i in indices], "A"))

    def slot_b(indices: Sequence[int]) -> float | None:
        return _mean(slot_values([rows[i] for i in indices], "B"))

    def position_bias(indices: Sequence[int]) -> float | None:
        a = slot_a(indices)
        b = slot_b(indices)
        return None if a is None or b is None else a - b

    def flip_rate(indices: Sequence[int]) -> float | None:
        data = arrays(indices)
        return _mean(
            [
                0.0 if a == b else 1.0
                for a, b in zip(data["correct_ab"], data["correct_ba"])
            ]
        )

    def length_heuristic(indices: Sequence[int]) -> float | None:
        subset = [rows[i] for i in indices]
        values = [
            1.0 if row["longer_side"] == "vulnerable" else 0.0
            for row in subset
            if row["longer_side"] in ("vulnerable", "fixed")
        ]
        return _mean(values)

    bootstrap = cluster_bootstrap(
        valid_pairs,
        {
            "position_avg_pair_da": position_avg,
            "order_consensus_pair_da": lambda idx: mean_metric(idx, "both"),
            "order_consistency": lambda idx: mean_metric(idx, "consistent"),
            "slot_accuracy_A": slot_a,
            "slot_accuracy_B": slot_b,
            "position_bias_index": position_bias,
            "order_flip_rate": flip_rate,
            "length_heuristic_da": length_heuristic,
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    correct_ab = sum(1 for row in rows if row["correct_ab"])
    correct_ba = sum(1 for row in rows if row["correct_ba"])
    both_correct = sum(1 for row in rows if row["both_correct"])
    consistent = sum(1 for row in rows if row["consistent"])
    flip_to_correct = sum(1 for row in rows if not row["correct_ab"] and row["correct_ba"])
    flip_to_wrong = sum(1 for row in rows if row["correct_ab"] and not row["correct_ba"])
    position_avg_value = (correct_ab + correct_ba) / (2.0 * n_valid)
    consensus_value = both_correct / n_valid
    consistency_value = consistent / n_valid
    slot_a_values = slot_values(rows, "A")
    slot_b_values = slot_values(rows, "B")
    slot_a_value = _mean(slot_a_values)
    slot_b_value = _mean(slot_b_values)
    bias_value = (
        None if slot_a_value is None or slot_b_value is None else slot_a_value - slot_b_value
    )

    # Length audit over both presentations.
    length_rows: list[dict[str, Any]] = []
    for row in rows:
        if row["longer_side"] not in ("vulnerable", "fixed"):
            continue
        for order_key, correct_key, selected_key in (
            ("AB", "correct_ab", "selected_ab"),
            ("BA", "correct_ba", "selected_ba"),
        ):
            length_rows.append(
                {
                    "order": order_key,
                    "correct": row[correct_key],
                    "selected": row[selected_key],
                    "longer": row["longer_side"],
                    "lengths": row["lengths"],
                }
            )
    non_tie = [item for item in length_rows if item["longer"] in ("vulnerable", "fixed")]
    choose_longer = [item for item in non_tie if item["selected"] == item["longer"]]
    choose_shorter = [item for item in non_tie if item["selected"] != item["longer"]]
    length_audit = {
        "available": bool(non_tie),
        "presentations": len(length_rows),
        "ties": len(length_rows) - len(non_tie),
        "length_only_da": _proportion(
            sum(1 for item in non_tie if item["longer"] == "vulnerable"), len(non_tie)
        )
        if non_tie
        else None,
        "choose_longer_rate": _proportion(len(choose_longer), len(non_tie)) if non_tie else None,
        "da_when_choose_longer": _proportion(
            sum(1 for item in choose_longer if item["correct"]), len(choose_longer)
        )
        if choose_longer
        else None,
        "da_when_choose_shorter": _proportion(
            sum(1 for item in choose_shorter if item["correct"]), len(choose_shorter)
        )
        if choose_shorter
        else None,
        "note": "Order swap cannot remove a length difference; report this audit before claiming a pure position effect.",
    }

    mcnemar = mcnemar_exact(
        a_correct_b_wrong=flip_to_wrong,
        a_wrong_b_correct=flip_to_correct,
        total=n_valid,
    )
    parent_ab = compute_run_metrics(
        ab_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    parent_ba = compute_run_metrics(
        ba_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    all_records = list(ab["records"]) + list(ba["records"])
    cost = cost_summary(all_records)
    cost["cost_per_100_pairs_usd"] = (
        cost["usd_known_sum"] / len(all_pairs) * 100.0
        if cost.get("usd_known_sum") is not None and all_pairs
        else None
    )
    cost["wall_s_per_100_pairs"] = (
        cost["wall_s_sum"] / len(all_pairs) * 100.0
        if cost.get("wall_s_sum") is not None and all_pairs
        else None
    )
    cost["note"] = "Two presentations per pair; per-100-pair cost includes both requests."

    metrics = {
        "position_avg_pair_da": _metric(
            position_avg_value,
            n_valid,
            ci=_boot_ci(bootstrap, "position_avg_pair_da"),
            method="cluster percentile bootstrap",
            note="Primary; mean of the two presentations' pair DA on common valid pairs.",
        ),
        "order_consensus_pair_da": _metric(
            consensus_value,
            n_valid,
            ci=_boot_ci(bootstrap, "order_consensus_pair_da"),
            method="cluster percentile bootstrap",
            note="Strict: both presentations correct.",
        ),
        "order_consistency": _metric(
            consistency_value,
            n_valid,
            ci=_boot_ci(bootstrap, "order_consistency"),
            method="cluster percentile bootstrap",
            note=f"{consistent}/{n_valid} pairs choose the same semantic side.",
        ),
        "slot_accuracy_A": _metric(
            slot_a_value,
            len(slot_a_values),
            ci=_boot_ci(bootstrap, "slot_accuracy_A"),
            method="cluster percentile bootstrap",
            note="Across both presentations: correct rate when the vulnerable version is in slot A.",
        ),
        "slot_accuracy_B": _metric(
            slot_b_value,
            len(slot_b_values),
            ci=_boot_ci(bootstrap, "slot_accuracy_B"),
            method="cluster percentile bootstrap",
            note="Across both presentations: correct rate when the vulnerable version is in slot B.",
        ),
        "position_bias_index": _metric(
            bias_value,
            n_valid,
            ci=_boot_ci(bootstrap, "position_bias_index"),
            method="cluster percentile bootstrap",
            note="slot_accuracy_A - slot_accuracy_B; positive = A-favouring.",
        ),
        "order_flip_rate": _metric(
            (flip_to_correct + flip_to_wrong) / n_valid,
            n_valid,
            ci=_boot_ci(bootstrap, "order_flip_rate"),
            method="cluster percentile bootstrap",
        ),
        "flip_to_correct": _proportion(flip_to_correct, n_valid),
        "flip_to_wrong": _proportion(flip_to_wrong, n_valid),
        f"order_da_{str(ab['order']).lower()}": _proportion(correct_ab, n_valid),
        f"order_da_{str(ba['order']).lower()}": _proportion(correct_ba, n_valid),
        "debiased_minus_order_avg": _metric(
            consensus_value - position_avg_value,
            n_valid,
            method="derived",
            note="Always <= 0; equals -0.5 * order_flip_rate because the two presentations are averaged.",
        ),
        "length_audit": length_audit,
        "mcnemar_order_effect": mcnemar,
    }
    counts = {
        "pairs_all": len(all_pairs),
        "pairs_in_both_orders": len(both_pairs),
        "pairs_valid_both_orders": n_valid,
        "pairs_only_ab": len(set(ab["pairs"]) - set(ba["pairs"])),
        "pairs_only_ba": len(set(ba["pairs"]) - set(ab["pairs"])),
        f"records_{str(ab['order']).lower()}": len(ab["records"]),
        f"records_{str(ba['order']).lower()}": len(ba["records"]),
        f"by_status_{str(ab['order']).lower()}": count_by(str(record.get("status")) for record in ab["records"]),
        f"by_status_{str(ba['order']).lower()}": count_by(str(record.get("status")) for record in ba["records"]),
    }
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.position_debiased_pair.v1",
        "design": "position_debiased_pair",
        "generated_at": utc_now(),
        "run_ids": {
            str(ab["order"]): str(ab["manifest"].get("run_id")),
            str(ba["order"]): str(ba["manifest"].get("run_id")),
        },
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "pair_id",
            "pairing_id": ab["extension_manifest"].get("pairing_id"),
            "design_version": ab["extension_manifest"].get("design_version"),
        },
        "counts": counts,
        "primary": {
            "name": "position_avg_pair_da",
            "value": position_avg_value,
            "n": n_valid,
            "ci_low": _boot_ci(bootstrap, "position_avg_pair_da").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "position_avg_pair_da").get("ci_high"),
            "method": "cluster percentile bootstrap (pair_id)",
            "note": "Mean of the two presentations' pair DA; the two presentations are not independent.",
        },
        "metrics": metrics,
        "strata": {
            "by_project": {
                project: {
                    "pairs": len([row for row in rows if row["project"] == project]),
                    "position_avg_pair_da": _mean(
                        [
                            (1.0 if row["correct_ab"] else 0.0) * 0.5
                            + (1.0 if row["correct_ba"] else 0.0) * 0.5
                            for row in rows
                            if row["project"] == project
                        ]
                    ),
                }
                for project in sorted({str(row["project"]) for row in rows if row["project"]})
            },
            "by_longer_side": {
                side: {
                    "pairs": len([row for row in rows if row["longer_side"] == side]),
                    "position_avg_pair_da": _mean(
                        [
                            (1.0 if row["correct_ab"] else 0.0) * 0.5
                            + (1.0 if row["correct_ba"] else 0.0) * 0.5
                            for row in rows
                            if row["longer_side"] == side
                        ]
                    ),
                }
                for side in ("vulnerable", "fixed", "tie")
                if any(row["longer_side"] == side for row in rows)
            },
        },
        "comparisons": {
            "order_effect_mcnemar": mcnemar,
            "position_avg_minus_order_consensus": consensus_value - position_avg_value,
            "length_audit_available": length_audit["available"],
        },
        "parent_metrics": {str(ab["order"]): parent_ab, str(ba["order"]): parent_ba},
        "cost": cost,
        "limitations": [
            "Each pair is presented twice; pair_id is the resampling unit, not the presentation.",
            "Order swap removes slot bias but not length bias; inspect length_audit before claiming a pure position effect.",
            "position_avg_pair_da estimates expected accuracy under a random presentation order; order_consensus_pair_da is a stricter stability endpoint and is always <= position_avg_pair_da.",
            "Both presentations come from one model configuration; run-to-run variance is not estimated.",
            "The paired runs are not independent of the single-order runs used in earlier pair-joint reports.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": {
                "order_ab": _run_hashes(ab_dir),
                "order_ba": _run_hashes(ba_dir),
            },
            "source": "canonical extension runs; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Open-choice pair
# ---------------------------------------------------------------------------


def _open_view(run_dir: Path) -> dict[str, Any]:
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    if not ext_manifest or ext_manifest.get("design") != "open_choice_pair":
        raise ExtensionError(f"{run_dir}: not an open_choice_pair run")
    groups = _pair_groups(records)
    view: dict[str, Any] = {}
    for pair_id, sides in groups.items():
        if set(sides) != {"vulnerable", "fixed"}:
            continue
        sample = sides["vulnerable"]
        block = sample.get("extensions") or {}
        choice = block.get("open_choice")
        pm = block.get("position_map") or {}
        vulnerable_slot = "A" if pm.get("A") == "vulnerable" else ("B" if pm.get("B") == "vulnerable" else None)
        selected_slots = block.get("selected_slots") if isinstance(block.get("selected_slots"), list) else []
        flagged = {pm.get(slot) for slot in selected_slots if pm.get(slot)}
        valid = (
            sides["vulnerable"].get("status") == "ok"
            and sides["fixed"].get("status") == "ok"
            and choice in ("A", "B", "both", "neither")
        )
        decisive = choice in ("A", "B")
        correct = valid and decisive and flagged == {"vulnerable"}
        view[pair_id] = {
            "pair_id": pair_id,
            "choice": choice,
            "selected_slots": selected_slots,
            "flagged": flagged,
            "valid": valid,
            "decisive": decisive,
            "correct": correct,
            "vulnerable_slot": vulnerable_slot,
            "records": sides,
        }
    return {
        "manifest": manifest,
        "extension_manifest": ext_manifest,
        "records": records,
        "pairs": view,
        "run_dir": run_dir,
    }


def open_choice_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
    baseline_run: str | None = None,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "open-choice run failed validation: " + "; ".join(report["errors"][:5])
        )
    view = _open_view(run_dir)
    pairs = view["pairs"]
    pair_ids = sorted(pairs)
    valid_ids = [pair_id for pair_id in pair_ids if pairs[pair_id]["valid"]]
    decisive_ids = [pair_id for pair_id in valid_ids if pairs[pair_id]["decisive"]]
    correct_ids = [pair_id for pair_id in valid_ids if pairs[pair_id]["correct"]]
    n_all = len(pair_ids)
    n_valid = len(valid_ids)
    n_decisive = len(decisive_ids)
    n_correct = len(correct_ids)
    distribution = Counter(pairs[pair_id]["choice"] for pair_id in valid_ids)
    both_count = distribution.get("both", 0)
    neither_count = distribution.get("neither", 0)

    def arrays(indices: Sequence[int]) -> dict[str, Any]:
        subset = [pairs[valid_ids[i]] for i in indices]
        return {
            "valid": [item["valid"] for item in subset],
            "decisive": [item["decisive"] for item in subset],
            "correct": [item["correct"] for item in subset],
            "both": [item["choice"] == "both" for item in subset],
            "neither": [item["choice"] == "neither" for item in subset],
            "slot_a": [item["vulnerable_slot"] == "A" for item in subset],
        }

    def mean_bool(indices: Sequence[int], key: str) -> float | None:
        values = arrays(indices)[key]
        return _mean([1.0 if value else 0.0 for value in values])

    def pair_da(indices: Sequence[int]) -> float | None:
        return mean_bool(indices, "correct")

    def pair_da_decisive(indices: Sequence[int]) -> float | None:
        data = arrays(indices)
        values = [
            1.0 if correct else 0.0
            for correct, decisive in zip(data["correct"], data["decisive"])
            if decisive
        ]
        return _mean(values)

    def decisive_rate(indices: Sequence[int]) -> float | None:
        return mean_bool(indices, "decisive")

    def both_rate(indices: Sequence[int]) -> float | None:
        return mean_bool(indices, "both")

    def neither_rate(indices: Sequence[int]) -> float | None:
        return mean_bool(indices, "neither")

    def slot_accuracy(indices: Sequence[int], slot: str) -> float | None:
        data = arrays(indices)
        values = [
            1.0 if correct else 0.0
            for correct, decisive, is_slot in zip(data["correct"], data["decisive"], data["slot_a"])
            if decisive and is_slot == (slot == "A")
        ]
        return _mean(values)

    def position_bias(indices: Sequence[int]) -> float | None:
        a = slot_accuracy(indices, "A")
        b = slot_accuracy(indices, "B")
        return None if a is None or b is None else a - b

    bootstrap = cluster_bootstrap(
        valid_ids,
        {
            "pair_da": pair_da,
            "pair_da_decisive": pair_da_decisive,
            "decisive_rate": decisive_rate,
            "both_rate": both_rate,
            "neither_rate": neither_rate,
            "slot_accuracy_A": lambda idx: slot_accuracy(idx, "A"),
            "slot_accuracy_B": lambda idx: slot_accuracy(idx, "B"),
            "position_bias_index": position_bias,
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    parent = compute_run_metrics(
        run_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    metrics = {
        "pair_da": _metric(
            rate(n_correct, n_valid),
            n_valid,
            ci=_boot_ci(bootstrap, "pair_da"),
            method="cluster percentile bootstrap",
            note=f"{n_correct}/{n_valid} valid pairs; both/neither count as pair errors.",
        ),
        "pair_da_all": _proportion(n_correct, n_all),
        "pair_da_decisive": _metric(
            rate(n_correct, n_decisive),
            n_decisive,
            ci=_boot_ci(bootstrap, "pair_da_decisive"),
            method="cluster percentile bootstrap",
            note=f"{n_correct}/{n_decisive} decisive pairs.",
        ),
        "decisive_rate": _metric(
            rate(n_decisive, n_valid),
            n_valid,
            ci=_boot_ci(bootstrap, "decisive_rate"),
            method="cluster percentile bootstrap",
            note=f"{n_decisive}/{n_valid} valid pairs chose A or B.",
        ),
        "decisive_rate_all": _proportion(n_decisive, n_all),
        "both_rate": _metric(
            rate(both_count, n_valid),
            n_valid,
            ci=_boot_ci(bootstrap, "both_rate"),
            method="cluster percentile bootstrap",
            note=f"{both_count}/{n_valid}.",
        ),
        "neither_rate": _metric(
            rate(neither_count, n_valid),
            n_valid,
            ci=_boot_ci(bootstrap, "neither_rate"),
            method="cluster percentile bootstrap",
            note=f"{neither_count}/{n_valid}.",
        ),
        "slot_accuracy_A": _metric(
            _mean(
                [
                    1.0 if pairs[pair_id]["correct"] else 0.0
                    for pair_id in decisive_ids
                    if pairs[pair_id]["vulnerable_slot"] == "A"
                ]
            ),
            len([pair_id for pair_id in decisive_ids if pairs[pair_id]["vulnerable_slot"] == "A"]),
            ci=_boot_ci(bootstrap, "slot_accuracy_A"),
            method="cluster percentile bootstrap",
            note="Correct rate when the vulnerable version is in slot A, among decisive pairs.",
        ),
        "slot_accuracy_B": _metric(
            _mean(
                [
                    1.0 if pairs[pair_id]["correct"] else 0.0
                    for pair_id in decisive_ids
                    if pairs[pair_id]["vulnerable_slot"] == "B"
                ]
            ),
            len([pair_id for pair_id in decisive_ids if pairs[pair_id]["vulnerable_slot"] == "B"]),
            ci=_boot_ci(bootstrap, "slot_accuracy_B"),
            method="cluster percentile bootstrap",
            note="Correct rate when the vulnerable version is in slot B, among decisive pairs.",
        ),
        "position_bias_index": _metric(
            None,
            n_decisive,
            ci=_boot_ci(bootstrap, "position_bias_index"),
            method="cluster percentile bootstrap",
            note="slot_accuracy_A - slot_accuracy_B.",
        ),
        "open_choice_distribution": {
            key: {
                "count": distribution.get(key, 0),
                "rate_valid": rate(distribution.get(key, 0), n_valid),
                "rate_all": rate(distribution.get(key, 0), n_all),
            }
            for key in ("A", "B", "both", "neither")
        },
    }
    # Fill the position-bias point estimate from the same definition used in bootstrap.
    slot_a_ids = [pair_id for pair_id in decisive_ids if pairs[pair_id]["vulnerable_slot"] == "A"]
    slot_b_ids = [pair_id for pair_id in decisive_ids if pairs[pair_id]["vulnerable_slot"] == "B"]
    slot_a_value = _mean([1.0 if pairs[pair_id]["correct"] else 0.0 for pair_id in slot_a_ids])
    slot_b_value = _mean([1.0 if pairs[pair_id]["correct"] else 0.0 for pair_id in slot_b_ids])
    metrics["position_bias_index"]["value"] = (
        None if slot_a_value is None or slot_b_value is None else slot_a_value - slot_b_value
    )

    comparisons: dict[str, Any] = {}
    baseline_path_value = baseline_run or view["extension_manifest"].get("baseline_run")
    if baseline_path_value:
        baseline_path = resolve_path(
            str(baseline_path_value),
            [run_dir, run_dir.parent, Path(__file__).resolve().parents[3]],
        )
        if baseline_path.exists() and (baseline_path / "run_manifest.json").exists():
            baseline_correct = _pair_correct_map(baseline_path)
            common = sorted(set(pair_ids) & set(baseline_correct))
            if common:
                open_values = [1.0 if pairs[pair_id]["correct"] else 0.0 for pair_id in common]
                base_values = [1.0 if baseline_correct[pair_id] else 0.0 for pair_id in common]
                diffs = [a - b for a, b in zip(open_values, base_values)]
                open_correct = sum(1 for value in open_values if value)
                base_correct = sum(1 for value in base_values if value)
                b_count = sum(1 for a, b in zip(open_values, base_values) if a and not b)
                c_count = sum(1 for a, b in zip(open_values, base_values) if not a and b)
                comparisons["baseline"] = {
                    "path": str(baseline_path),
                    "n_common_pairs": len(common),
                    "open_pair_da": rate(open_correct, len(common)),
                    "baseline_pair_da": rate(base_correct, len(common)),
                    "delta_pair_da": _mean(diffs),
                    "mcnemar": mcnemar_exact(
                        a_correct_b_wrong=b_count,
                        a_wrong_b_correct=c_count,
                        total=len(common),
                    ),
                    "note": "Descriptive only: open-choice allows both/neither and is not the same task as forced choice.",
                }
        else:
            comparisons["baseline"] = {"error": "baseline run not found", "path": str(baseline_path_value)}

    cost = cost_summary(view["records"])
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.open_choice_pair.v1",
        "design": "open_choice_pair",
        "generated_at": utc_now(),
        "run_ids": {"run": str(view["manifest"].get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "pair_id",
            "design_version": view["extension_manifest"].get("design_version"),
        },
        "counts": {
            "pairs": n_all,
            "valid_pairs": n_valid,
            "decisive_pairs": n_decisive,
            "correct_pairs": n_correct,
            "records": len(view["records"]),
            "choice_counts_valid": dict(distribution),
            "by_status": count_by(str(record.get("status")) for record in view["records"]),
        },
        "primary": {
            "name": "pair_da",
            "value": rate(n_correct, n_valid),
            "n": n_valid,
            "ci_low": _boot_ci(bootstrap, "pair_da").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "pair_da").get("ci_high"),
            "method": "cluster percentile bootstrap (pair_id)",
            "note": "Open-choice is a different task from forced choice; both/neither count as pair errors.",
        },
        "metrics": metrics,
        "strata": {
            "by_choice": {
                key: {"count": distribution.get(key, 0)}
                for key in ("A", "B", "both", "neither")
            },
            "by_vulnerable_slot": {
                slot: {
                    "decisive_pairs": len(
                        [pair_id for pair_id in decisive_ids if pairs[pair_id]["vulnerable_slot"] == slot]
                    ),
                    "accuracy": slot_a_value if slot == "A" else slot_b_value,
                }
                for slot in ("A", "B")
            },
        },
        "comparisons": comparisons,
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "Open-choice is a different task: forced choice has no both/neither answer. Do not subtract open-choice pair_da from forced-choice DA without stating the task change.",
            "Both and neither are substantive answers counted as pair errors; report decisive_rate and pair_da_decisive next to pair_da.",
            "The four-way distribution is design- and prompt-dependent; it is not an estimate of the natural prevalence of both/neither.",
            "One run per model/configuration; run-to-run variance is not estimated.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Evidence verification
# ---------------------------------------------------------------------------


def evidence_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "evidence run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    verdicts: list[str] = []
    golds: list[str] = []
    claim_types: list[str] = []
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ExtensionError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        pred = as_bool((record.get("prediction") or {}).get("y_pred")) if record.get("status") == "ok" else None
        predictions.append(pred)
        clusters.append(str(record.get("cluster_id")))
        verification = (record.get("extensions") or {}).get("verification") or {}
        verdict = verification.get("verdict")
        verdicts.append(str(verdict) if verdict in ("supported", "unsupported", "insufficient") else "missing")
        golds.append(str(verification.get("gold_verdict")))
        claim_types.append(str(verification.get("claim_type") or "other"))

    scores = detection_scores(labels, predictions, confidence=confidence)
    bootstrap = bootstrap_detection(
        labels, predictions, clusters, resamples=resamples, seed=seed, confidence=confidence
    )
    n = len(records)
    valid = scores["valid"]
    tp = scores["confusion"]["tp"]
    fp = scores["confusion"]["fp"]
    tn = scores["confusion"]["tn"]
    fn = scores["confusion"]["fn"]
    insufficient = sum(1 for verdict in verdicts if verdict == "insufficient")
    decisive = valid

    def metric_subset(indices: Sequence[int], name: str) -> float | None:
        subset_labels = [labels[i] for i in indices]
        subset_predictions = [predictions[i] for i in indices]
        subset_scores = detection_scores(subset_labels, subset_predictions, confidence=confidence)
        value = subset_scores.get(name)
        return None if value is None else float(value)

    def false_support(indices: Sequence[int]) -> float | None:
        # P(pred=supported | gold=unsupported, valid)
        num = 0
        den = 0
        for i in indices:
            if labels[i] is False and predictions[i] is not None:
                den += 1
                if predictions[i] is True:
                    num += 1
        return rate(num, den)

    def false_reject(indices: Sequence[int]) -> float | None:
        num = 0
        den = 0
        for i in indices:
            if labels[i] is True and predictions[i] is not None:
                den += 1
                if predictions[i] is False:
                    num += 1
        return rate(num, den)

    def abstention(indices: Sequence[int]) -> float | None:
        return rate(sum(1 for i in indices if verdicts[i] == "insufficient"), len(indices))

    custom = cluster_bootstrap(
        clusters,
        {
            "macro_f1": lambda idx: metric_subset(idx, "macro_f1"),
            "balanced_accuracy": lambda idx: metric_subset(idx, "balanced_accuracy"),
            "false_support_rate": false_support,
            "false_reject_rate": false_reject,
            "abstention_rate": abstention,
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    false_support_value = rate(fp, fp + tn)
    false_reject_value = rate(fn, tp + fn)
    confusion = {
        "gold_supported": {
            "pred_supported": tp,
            "pred_unsupported": fn,
            "pred_insufficient": sum(
                1 for i in range(n) if labels[i] and verdicts[i] == "insufficient"
            ),
        },
        "gold_unsupported": {
            "pred_supported": fp,
            "pred_unsupported": tn,
            "pred_insufficient": sum(
                1 for i in range(n) if not labels[i] and verdicts[i] == "insufficient"
            ),
        },
    }
    by_type: dict[str, Any] = {}
    for claim_type in sorted(set(claim_types)):
        indices = [i for i, value in enumerate(claim_types) if value == claim_type]
        sub_labels = [labels[i] for i in indices]
        sub_preds = [predictions[i] for i in indices]
        by_type[claim_type] = {
            "n": len(indices),
            **detection_scores(sub_labels, sub_preds, confidence=confidence),
        }
    parent = compute_run_metrics(
        run_dir, resamples=resamples, seed=seed, confidence=confidence
    )
    cost = cost_summary(records)
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.evidence_verification.v1",
        "design": "evidence_verification",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "claim_source_cluster",
            "design_version": (ext_manifest or {}).get("design_version"),
        },
        "counts": {
            "claims": n,
            "valid_decisive": valid,
            "abstained": insufficient,
            "coverage": scores["coverage"],
            "by_status": count_by(str(record.get("status")) for record in records),
            "by_verdict": count_by(verdicts),
            "by_gold": count_by(golds),
            "by_claim_type": count_by(claim_types),
        },
        "primary": {
            "name": "macro_f1",
            "value": scores["macro_f1"],
            "n": valid,
            "ci_low": _boot_ci(bootstrap, "macro_f1").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "macro_f1").get("ci_high"),
            "method": "cluster percentile bootstrap (source cluster)",
            "note": "Valid-only claim-level macro-F1; insufficient is an abstention, not a class.",
        },
        "metrics": {
            "detection": {
                "scores": scores,
                "bootstrap": bootstrap.get("metrics", {}),
                "cluster_count": bootstrap.get("cluster_count"),
            },
            "decisive_coverage": _metric(
                scores["coverage"], n, method="wilson", note=f"{valid}/{n} decisive claims."
            ),
            "abstention_rate": _metric(
                rate(insufficient, n),
                n,
                ci=_boot_ci(custom, "abstention_rate"),
                method="cluster percentile bootstrap",
                note=f"{insufficient}/{n} insufficient verdicts.",
            ),
            "false_support_rate": _metric(
                false_support_value,
                fp + tn,
                ci=_boot_ci(custom, "false_support_rate"),
                method="cluster percentile bootstrap",
                note="P(pred supported | gold unsupported), valid claims.",
            ),
            "false_reject_rate": _metric(
                false_reject_value,
                tp + fn,
                ci=_boot_ci(custom, "false_reject_rate"),
                method="cluster percentile bootstrap",
                note="P(pred unsupported | gold supported), valid claims.",
            ),
            "supported_precision": scores["precision"],
            "unsupported_recall": scores["specificity"],
            "balanced_accuracy": _metric(
                scores["balanced_accuracy"],
                valid,
                ci=_boot_ci(custom, "balanced_accuracy"),
                method="cluster percentile bootstrap",
            ),
            "confusion_2x3": confusion,
            "by_claim_type": by_type,
        },
        "strata": {
            "by_claim_type": by_type,
            "by_gold": {
                gold: {
                    "n": len([i for i in range(n) if golds[i] == gold]),
                    "decisive": len(
                        [i for i in range(n) if golds[i] == gold and predictions[i] is not None]
                    ),
                }
                for gold in ("supported", "unsupported")
            },
        },
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "Claims are the evaluation unit; lines/tokens are not independent samples.",
            "Gold claims come from a frozen construction rule. If that rule correlates with surface form, the verifier can exploit it; report the rule and any length/format audit.",
            "Insufficient is an abstention: excluded from valid-only and counted wrong in strict accuracy.",
            "A verifier that rejects every claim can have high unsupported specificity but zero genuine acceptance; read the 2x3 confusion.",
            "Single run per model/configuration; run-to-run variance is not estimated.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Fault-injected dynamic
# ---------------------------------------------------------------------------


def _fault_effective(record: Mapping[str, Any], threshold: float) -> bool | None:
    injection = (record.get("extensions") or {}).get("fault_injection") or {}
    expected = injection.get("expected_outcome")
    if expected not in ("leak", "clean"):
        return None
    status = record.get("status")
    observed = injection.get("observed_outcome")
    if status != "ok":
        return None
    if observed == "leak":
        return True
    if observed == "clean":
        return False
    return None


def _fault_eval(records: Sequence[Mapping[str, Any]], *, threshold: float, exclude_mismatch: bool) -> dict[str, Any]:
    selected: list[Mapping[str, Any]] = []
    for record in records:
        injection = (record.get("extensions") or {}).get("fault_injection") or {}
        if injection.get("expected_outcome") not in ("leak", "clean"):
            continue
        if exclude_mismatch:
            oracle = record.get("oracle") or {}
            if isinstance(oracle, Mapping) and oracle.get("mismatch") is True:
                continue
        selected.append(record)
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    strict_correct = 0
    for record in selected:
        injection = (record.get("extensions") or {}).get("fault_injection") or {}
        label = injection.get("expected_outcome") == "leak"
        pred = _fault_effective(record, threshold)
        labels.append(label)
        predictions.append(pred)
        clusters.append(str(record.get("cluster_id")))
        if pred is not None and pred == label:
            strict_correct += 1
    scores = detection_scores(labels, predictions)
    tp = scores["confusion"]["tp"]
    fp = scores["confusion"]["fp"]
    tn = scores["confusion"]["tn"]
    fn = scores["confusion"]["fn"]
    return {
        "n": len(selected),
        "valid": scores["valid"],
        "coverage": scores["coverage"],
        "scores": scores,
        "sensitivity": rate(tp, tp + fn),
        "specificity": rate(tn, tn + fp),
        "masking_rate": rate(fn, tp + fn),
        "false_alarm_rate": rate(fp, tn + fp),
        "balanced_accuracy": scores["balanced_accuracy"],
        "macro_f1": scores["macro_f1"],
        "mcc": scores["mcc"],
        "strict_correct": strict_correct,
        "strict_accuracy": rate(strict_correct, len(selected)),
        "labels": labels,
        "predictions": predictions,
        "clusters": clusters,
    }


def fault_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
    coverage_threshold: float,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "fault run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    primary = _fault_eval(records, threshold=coverage_threshold, exclude_mismatch=True)
    all_eval = _fault_eval(records, threshold=coverage_threshold, exclude_mismatch=False)

    def metric_subset(indices: Sequence[int], key: str) -> float | None:
        labels = [primary["labels"][i] for i in indices]
        preds = [primary["predictions"][i] for i in indices]
        scores = detection_scores(labels, preds)
        if key == "balanced_accuracy":
            return scores["balanced_accuracy"]
        if key == "macro_f1":
            return scores["macro_f1"]
        if key == "sensitivity":
            tp = scores["confusion"]["tp"]
            fn = scores["confusion"]["fn"]
            return rate(tp, tp + fn)
        if key == "specificity":
            tn = scores["confusion"]["tn"]
            fp = scores["confusion"]["fp"]
            return rate(tn, tn + fp)
        return None

    bootstrap = cluster_bootstrap(
        primary["clusters"],
        {
            "balanced_accuracy": lambda idx: metric_subset(idx, "balanced_accuracy"),
            "macro_f1": lambda idx: metric_subset(idx, "macro_f1"),
            "sensitivity": lambda idx: metric_subset(idx, "sensitivity"),
            "specificity": lambda idx: metric_subset(idx, "specificity"),
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    expected_counts = Counter(
        (record.get("extensions") or {}).get("fault_injection", {}).get("expected_outcome")
        for record in records
    )
    observed_counts = Counter(
        (record.get("extensions") or {}).get("fault_injection", {}).get("observed_outcome")
        for record in records
    )
    status_counts = Counter(str(record.get("status")) for record in records)
    primary_records = [
        record for record in records
        if (record.get("extensions") or {}).get("fault_injection", {}).get("expected_outcome") in ("leak", "clean")
        and not (
            isinstance(record.get("oracle"), Mapping)
            and record["oracle"].get("mismatch") is True
        )
    ]
    primary_status_counts = Counter(str(record.get("status")) for record in primary_records)
    flip_counts = Counter(
        (record.get("extensions") or {}).get("fault_injection", {}).get("flip")
        for record in records
    )
    by_type: dict[str, Any] = {}
    for fault_type in sorted({
        str((record.get("extensions") or {}).get("fault_injection", {}).get("fault_type"))
        for record in records
    }):
        subset = [
            record for record in records
            if (record.get("extensions") or {}).get("fault_injection", {}).get("fault_type") == fault_type
        ]
        evaluation = _fault_eval(subset, threshold=coverage_threshold, exclude_mismatch=True)
        by_type[fault_type or "unknown"] = {
            "n": evaluation["n"],
            "valid": evaluation["valid"],
            "coverage": evaluation["coverage"],
            "sensitivity": evaluation["sensitivity"],
            "specificity": evaluation["specificity"],
            "balanced_accuracy": evaluation["balanced_accuracy"],
            "strict_accuracy": evaluation["strict_accuracy"],
        }
    strata: dict[str, Any] = {}
    for bucket in ("ge_0.90", "0.50_0.90", "lt_0.50", "unknown"):
        subset = [
            record for record in records
            if coverage_bucket(record) == bucket
            and (record.get("extensions") or {}).get("fault_injection", {}).get("expected_outcome") in ("leak", "clean")
        ]
        if not subset:
            strata[bucket] = None
            continue
        evaluation = _fault_eval(subset, threshold=coverage_threshold, exclude_mismatch=True)
        strata[bucket] = {
            "n": evaluation["n"],
            "valid": evaluation["valid"],
            "sensitivity": evaluation["sensitivity"],
            "specificity": evaluation["specificity"],
            "balanced_accuracy": evaluation["balanced_accuracy"],
        }
    parent = compute_run_metrics(
        run_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
        coverage_threshold=coverage_threshold,
    )
    cost = cost_summary(records)
    primary_value = primary["balanced_accuracy"]
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.fault_injected_dynamic.v1",
        "design": "fault_injected_dynamic",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "base_case_family",
            "coverage_threshold": coverage_threshold,
            "design_version": (ext_manifest or {}).get("design_version"),
        },
        "counts": {
            "faults": len(records),
            "expected": dict(expected_counts),
            "observed": dict(observed_counts),
            "by_status": dict(status_counts),
            "oracle_mismatch": sum(
                1 for record in records if (record.get("oracle") or {}).get("mismatch") is True
            ),
            "flips": dict(flip_counts),
        },
        "primary": {
            "name": "fault_balanced_accuracy",
            "value": primary_value,
            "n": primary["valid"],
            "ci_low": _boot_ci(bootstrap, "balanced_accuracy").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "balanced_accuracy").get("ci_high"),
            "method": "cluster percentile bootstrap (base_case_family)",
            "note": "Valid fault variants with expected leak/clean, excluding oracle mismatches.",
        },
        "metrics": {
            "fault_sensitivity": _metric(
                primary["sensitivity"],
                primary["scores"]["confusion"]["tp"] + primary["scores"]["confusion"]["fn"],
                ci=_boot_ci(bootstrap, "sensitivity"),
                method="cluster percentile bootstrap",
                note="P(observed leak | expected leak), valid variants.",
            ),
            "fault_specificity": _metric(
                primary["specificity"],
                primary["scores"]["confusion"]["tn"] + primary["scores"]["confusion"]["fp"],
                ci=_boot_ci(bootstrap, "specificity"),
                method="cluster percentile bootstrap",
                note="P(observed clean | expected clean), valid variants.",
            ),
            "fault_balanced_accuracy": _metric(
                primary["balanced_accuracy"],
                primary["valid"],
                ci=_boot_ci(bootstrap, "balanced_accuracy"),
                method="cluster percentile bootstrap",
            ),
            "fault_macro_f1": _metric(
                primary["macro_f1"],
                primary["valid"],
                ci=_boot_ci(bootstrap, "macro_f1"),
                method="cluster percentile bootstrap",
            ),
            "masking_rate": _proportion(
                primary["scores"]["confusion"]["fn"],
                primary["scores"]["confusion"]["tp"] + primary["scores"]["confusion"]["fn"],
            ),
            "false_alarm_rate": _proportion(
                primary["scores"]["confusion"]["fp"],
                primary["scores"]["confusion"]["tn"] + primary["scores"]["confusion"]["fp"],
            ),
            "strict_accuracy": _metric(
                primary["strict_accuracy"],
                primary["n"],
                method="strict",
                note="Inconclusive/error/timeout count as errors; expected-inconclusive faults excluded.",
            ),
            "inconclusive_rate": _metric(
                rate(primary_status_counts.get("inconclusive", 0), len(primary_records)),
                len(primary_records),
                method="count",
                note="Observed inconclusive / expected leak+clean variants in the primary denominator.",
            ),
            "error_rate": _metric(
                rate(
                    sum(
                        primary_status_counts.get(status, 0)
                        for status in ("tool_error", "harness_error", "api_error", "timeout", "crash")
                    ),
                    len(primary_records),
                ),
                len(primary_records),
                method="count",
            ),
            "coverage_sufficient_rate": _metric(
                rate(primary["valid"], primary["n"]),
                primary["n"],
                method="count",
            ),
            "all_variants_including_mismatch": {
                "balanced_accuracy": all_eval["balanced_accuracy"],
                "sensitivity": all_eval["sensitivity"],
                "specificity": all_eval["specificity"],
                "strict_accuracy": all_eval["strict_accuracy"],
                "n": all_eval["n"],
                "valid": all_eval["valid"],
            },
        },
        "strata": {
            "by_fault_type": by_type,
            "by_coverage": strata,
        },
        "comparisons": {
            "flip_vs_baseline": dict(flip_counts),
            "net_clean_to_leak_minus_leak_to_clean": (
                flip_counts.get("clean_to_leak", 0) - flip_counts.get("leak_to_clean", 0)
            ),
        },
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "Fault variants are constructed, not natural cases; sensitivity/specificity describe robustness of the dynamic method under this injection suite, not CWE-401 prevalence.",
            "Expected outcomes are pre-registered design labels; oracle mismatch variants are excluded from the primary estimate and reported separately.",
            "Clean observations without adequate coverage are inconclusive, never true negatives; observed leaks remain positive even at low coverage.",
            "Multiple fault variants of one base case are correlated; the bootstrap resamples base_case_family clusters, not individual variants.",
            "Never pool these variants with the canonical 140-unit dynamic run or with Juliet intended-label metrics.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# New static tool
# ---------------------------------------------------------------------------


def _static_high_prediction(record: Mapping[str, Any]) -> bool | None:
    block = (record.get("extensions") or {}).get("static_normalization") or {}
    diagnostics = block.get("diagnostics")
    if not isinstance(diagnostics, list):
        return None
    if record.get("status") != "ok":
        return None
    return any(
        diagnostic.get("counts_for_cwe401")
        and diagnostic.get("in_scope")
        and not diagnostic.get("suppressed")
        and diagnostic.get("severity_class") == "high"
        for diagnostic in diagnostics
        if isinstance(diagnostic, Mapping)
    )


def static_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
    coverage_threshold: float,
    baseline_run: str | None = None,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "static run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    labels: list[bool] = []
    predictions: list[bool | None] = []
    clusters: list[str] = []
    high_predictions: list[bool | None] = []
    diagnostics_total: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    status_counts = Counter(str(record.get("status")) for record in records)
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ExtensionError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        pred = as_bool((record.get("prediction") or {}).get("y_pred")) if record.get("status") == "ok" else None
        predictions.append(pred)
        clusters.append(str(record.get("cluster_id")))
        high_predictions.append(_static_high_prediction(record))
        block = (record.get("extensions") or {}).get("static_normalization") or {}
        diagnostics = block.get("diagnostics") if isinstance(block.get("diagnostics"), list) else []
        counts = summarize_diagnostics(diagnostics)
        for key in (
            "raw_warning_count",
            "dedup_warning_count",
            "mapped_warning_count",
            "unmapped_warning_count",
            "out_of_scope_count",
            "suppressed_count",
        ):
            diagnostics_total[key] += int(counts.get(key, 0))
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, Mapping):
                continue
            rule_counts[str(diagnostic.get("rule_id"))] += 1
            severity_counts[str(diagnostic.get("severity_class"))] += 1
    scores = detection_scores(labels, predictions, confidence=confidence)
    bootstrap = bootstrap_detection(
        labels, predictions, clusters, resamples=resamples, seed=seed, confidence=confidence
    )
    high_available = any(value is not None for value in high_predictions)
    high_scores = detection_scores(labels, high_predictions, confidence=confidence) if high_available else None
    high_bootstrap = (
        bootstrap_detection(labels, high_predictions, clusters, resamples=resamples, seed=seed, confidence=confidence)
        if high_available
        else None
    )
    delta_macro = None
    mcnemar_high = None
    if high_scores is not None and scores.get("macro_f1") is not None and high_scores.get("macro_f1") is not None:
        delta_macro = high_scores["macro_f1"] - scores["macro_f1"]
        common = [
            index for index, (base, high) in enumerate(zip(predictions, high_predictions))
            if base is not None and high is not None
        ]
        b = sum(
            1 for index in common
            if high_predictions[index] == labels[index] and predictions[index] != labels[index]
        )
        c = sum(
            1 for index in common
            if predictions[index] == labels[index] and high_predictions[index] != labels[index]
        )
        mcnemar_high = mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=len(common)) if common else None
    parent = compute_run_metrics(
        run_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
        coverage_threshold=coverage_threshold,
    )
    comparisons: dict[str, Any] = {}
    baseline_value = baseline_run or (ext_manifest or {}).get("baseline_run")
    if baseline_value:
        baseline_path = resolve_path(
            str(baseline_value),
            [run_dir, run_dir.parent, Path(__file__).resolve().parents[3]],
        )
        if baseline_path.exists() and (baseline_path / "run_manifest.json").exists():
            _, _, baseline_records, _ = load_extension_run(baseline_path)
            baseline_map: dict[str, bool | None] = {}
            for record in baseline_records:
                if record.get("task") != "leak_detection":
                    continue
                baseline_map[str(record.get("unit_id"))] = (
                    as_bool((record.get("prediction") or {}).get("y_pred"))
                    if record.get("status") == "ok"
                    else None
                )
            common_ids = [
                str(record.get("unit_id")) for record in records
                if str(record.get("unit_id")) in baseline_map
                and baseline_map[str(record.get("unit_id"))] is not None
                and as_bool((record.get("prediction") or {}).get("y_pred")) is not None
            ]
            if common_ids:
                ours = [
                    bool(as_bool((next(
                        record for record in records if str(record.get("unit_id")) == unit_id
                    ).get("prediction") or {}).get("y_pred")))
                    for unit_id in common_ids
                ]
                theirs = [bool(baseline_map[unit_id]) for unit_id in common_ids]
                agreement = agreement_counts(ours, theirs)
                comparisons["baseline"] = {
                    "path": str(baseline_path),
                    "n_common_units": len(common_ids),
                    "agreement": agreement,
                    "cohen_kappa": cohen_kappa(ours, theirs),
                    "mcnemar": mcnemar_exact(
                        a_correct_b_wrong=agreement["a_only"],
                        a_wrong_b_correct=agreement["b_only"],
                        total=len(common_ids),
                    ),
                    "note": "Agreement is descriptive; two static tools are not independent ground truth.",
                }
        else:
            comparisons["baseline"] = {"error": "baseline run not found", "path": str(baseline_value)}

    cost = cost_summary(records)
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.new_static_tool.v1",
        "design": "new_static_tool",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "case_family",
            "coverage_threshold": coverage_threshold,
            "design_version": (ext_manifest or {}).get("design_version"),
        },
        "counts": {
            "units": len(records),
            "valid": scores["valid"],
            "by_status": dict(status_counts),
            "diagnostics": dict(diagnostics_total),
            "rules": dict(rule_counts.most_common()),
            "severity": dict(severity_counts),
        },
        "primary": {
            "name": "macro_f1",
            "value": scores["macro_f1"],
            "n": scores["valid"],
            "ci_low": _boot_ci(bootstrap, "macro_f1").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "macro_f1").get("ci_high"),
            "method": "cluster percentile bootstrap (case_family)",
            "note": "Valid-only static leak detection at the pre-registered any-mapped-in-scope threshold.",
        },
        "metrics": {
            "detection": {
                "scores": scores,
                "bootstrap": bootstrap.get("metrics", {}),
                "cluster_count": bootstrap.get("cluster_count"),
            },
            "mcc": scores["mcc"],
            "strict_accuracy": scores["strict_accuracy"],
            "high_severity_sensitivity": {
                "available": high_available,
                "scores": high_scores,
                "bootstrap": (high_bootstrap or {}).get("metrics", {}),
                "delta_macro_f1_vs_default": delta_macro,
                "mcnemar_vs_default": mcnemar_high,
                "note": "High-only is a pre-registered sensitivity view; severity is tool-specific.",
            },
            "warning_counts": dict(diagnostics_total),
            "agreement_with_baseline": comparisons.get("baseline"),
        },
        "strata": {
            "by_rule": dict(rule_counts.most_common()),
            "by_severity": dict(severity_counts),
            "by_status": dict(status_counts),
        },
        "comparisons": comparisons,
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "A warning counts only if its rule maps to CWE-401 and its line is in the target scope; file-level warnings are not assigned to every function.",
            "compile_error/timeout/tool_error remain non-ok and are never y_pred=0.",
            "Severity is tool-specific; high-only is a within-tool sensitivity view, not a cross-tool severity comparison.",
            "Clang-tidy/clang-sa share an analysis engine; agreement between them is not independent validation.",
            "Static tools are evaluated on whole Juliet variants, not on incomplete Tier A snippets; do not compute Tier A static F1.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Markdown / CLI
# ---------------------------------------------------------------------------


def _write_markdown(path: Path, metrics: Mapping[str, Any]) -> None:
    lines = [
        f"# Extension metrics: `{metrics.get('design')}`",
        "",
        f"- generated: `{metrics.get('generated_at')}`",
        f"- extension: `{metrics.get('extension_id')}`",
        f"- runs: `{metrics.get('run_ids')}`",
        "",
        "## Counts",
        "",
        "| field | value |",
        "| --- | --- |",
    ]
    for key, value in (metrics.get("counts") or {}).items():
        lines.append(f"| `{key}` | {json.dumps(value, ensure_ascii=False)} |")
    primary = metrics.get("primary") or {}
    lines += [
        "",
        "## Primary",
        "",
        f"- **{primary.get('name')}**: {fmt(primary.get('value'))} "
        f"(n={primary.get('n')}, CI {fmt(primary.get('ci_low'))}–{fmt(primary.get('ci_high'))}, "
        f"{primary.get('method')})",
        f"- note: {primary.get('note')}",
        "",
        "## Metrics",
        "",
        "| metric | value | n | CI low | CI high | method |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    metric_block = metrics.get("metrics") or {}
    for name, value in metric_block.items():
        if isinstance(value, Mapping) and "value" in value:
            lines.append(
                f"| `{name}` | {fmt(value.get('value'))} | {value.get('n')} | "
                f"{fmt(value.get('ci_low'))} | {fmt(value.get('ci_high'))} | {value.get('method')} |"
            )
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            lines.append(f"| `{name}` | {fmt(value)} | — | — | — | point estimate |")
    detection = metric_block.get("detection")
    if isinstance(detection, Mapping) and isinstance(detection.get("scores"), Mapping):
        scores = detection["scores"]
        lines += [
            "",
            "### Detection scores",
            "",
            "| metric | value |",
            "| --- | ---: |",
        ]
        for name in (
            "n",
            "valid",
            "invalid",
            "coverage",
            "precision",
            "recall",
            "specificity",
            "f1",
            "macro_f1",
            "balanced_accuracy",
            "mcc",
            "strict_accuracy",
        ):
            if name in scores:
                lines.append(f"| `{name}` | {fmt(scores.get(name))} |")
        confusion = scores.get("confusion") or {}
        if confusion:
            lines.append(
                "| `confusion` | "
                f"TP {confusion.get('tp')} / FP {confusion.get('fp')} / TN {confusion.get('tn')} / FN {confusion.get('fn')} |"
            )
    lines += ["", "## Limitations", ""]
    for note in metrics.get("limitations") or []:
        lines.append(f"- {note}")
    lines.append("")
    atomic_write_text(path, "\n".join(lines))



# ---------------------------------------------------------------------------
# Evidence retraction
# ---------------------------------------------------------------------------


def evidence_retraction_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "evidence retraction run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    labels: list[bool] = []
    post_preds: list[bool | None] = []
    pre_preds: list[bool | None] = []
    clusters: list[str] = []
    first_positive = 0
    retracted = 0
    verifier_invalid = 0
    fail_closed = 0
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ExtensionError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        ext = (record.get("extensions") or {}).get("retraction") or {}
        first_pred = as_bool(ext.get("first_pass_y_pred"))
        first_status = ext.get("first_pass_status")
        pre_preds.append(first_pred if first_status == "ok" else None)
        post_preds.append(
            as_bool((record.get("prediction") or {}).get("y_pred"))
            if record.get("status") == "ok"
            else None
        )
        clusters.append(str(record.get("cluster_id")))
        if first_pred is True:
            first_positive += 1
        if ext.get("retracted") is True:
            retracted += 1
        if ext.get("verifier_verdict") == "invalid":
            verifier_invalid += 1
        if ext.get("fail_closed") is True:
            fail_closed += 1
    post_scores = detection_scores(labels, post_preds, confidence=confidence)
    pre_scores = detection_scores(labels, pre_preds, confidence=confidence)
    n = len(records)
    pre_correct = sum(
        1 for label, pred in zip(labels, pre_preds) if pred is not None and pred == label
    )
    post_correct = sum(
        1 for label, pred in zip(labels, post_preds) if pred is not None and pred == label
    )
    pre_strict = rate(pre_correct, n)
    post_strict = rate(post_correct, n)
    pre_tp = pre_scores["confusion"]["tp"]
    pre_fp = pre_scores["confusion"]["fp"]
    post_tp = post_scores["confusion"]["tp"]
    post_fp = post_scores["confusion"]["fp"]
    retracted_tp = 0
    retracted_fp = 0
    sustained = 0
    for record in records:
        ext = (record.get("extensions") or {}).get("retraction") or {}
        if ext.get("first_pass_y_pred") is not True:
            continue
        label = as_bool((record.get("label") or {}).get("y_true"))
        if ext.get("retracted") is True:
            if label:
                retracted_tp += 1
            else:
                retracted_fp += 1
        elif ext.get("verifier_verdict") == "sustain":
            sustained += 1
    retraction_precision = rate(retracted_fp, retracted_tp + retracted_fp)
    tp_loss_rate = rate(retracted_tp, pre_tp)
    fp_correction_rate = rate(retracted_fp, pre_fp)
    delta_macro = (
        None
        if pre_scores.get("macro_f1") is None or post_scores.get("macro_f1") is None
        else post_scores["macro_f1"] - pre_scores["macro_f1"]
    )
    delta_mcc = (
        None
        if pre_scores.get("mcc") is None or post_scores.get("mcc") is None
        else post_scores["mcc"] - pre_scores["mcc"]
    )
    b = sum(
        1
        for label, pre, post in zip(labels, pre_preds, post_preds)
        if pre is not None and pre == label and not (post is not None and post == label)
    )
    c = sum(
        1
        for label, pre, post in zip(labels, pre_preds, post_preds)
        if not (pre is not None and pre == label) and post is not None and post == label
    )
    mcnemar = mcnemar_exact(a_correct_b_wrong=b, a_wrong_b_correct=c, total=n)

    def metric_subset(indices: Sequence[int], which: str) -> float | None:
        subset_labels = [labels[i] for i in indices]
        subset_preds = [(pre_preds if which == "pre" else post_preds)[i] for i in indices]
        scores = detection_scores(subset_labels, subset_preds)
        return None if scores.get("macro_f1") is None else float(scores["macro_f1"])

    def delta_metric(indices: Sequence[int]) -> float | None:
        pre = metric_subset(indices, "pre")
        post = metric_subset(indices, "post")
        return None if pre is None or post is None else post - pre

    bootstrap = cluster_bootstrap(
        clusters,
        {
            "post_macro_f1": lambda idx: metric_subset(idx, "post"),
            "pre_macro_f1": lambda idx: metric_subset(idx, "pre"),
            "delta_macro_f1": delta_metric,
        },
        resamples=resamples,
        seed=seed,
        confidence=confidence,
    )
    parent = compute_run_metrics(
        run_dir, resamples=resamples, seed=seed, confidence=confidence
    )
    cost = cost_summary(records)
    first_pass_cost_values = [
        as_number(((record.get("extensions") or {}).get("retraction") or {}).get("first_pass_cost_usd"))
        for record in records
    ]
    first_pass_cost, first_known = _sum_known(first_pass_cost_values)
    verifier_known = cost.get("usd_known_sum")
    total_known = (
        None
        if verifier_known is None and first_pass_cost is None
        else float(verifier_known or 0.0) + float(first_pass_cost or 0.0)
    )
    cost["first_pass_usd_known_sum"] = first_pass_cost
    cost["first_pass_usd_known_records"] = first_known
    cost["verifier_usd_known_sum"] = verifier_known
    cost["total_usd_known_sum"] = total_known
    cost["cost_per_100_units_total_usd"] = (
        total_known / n * 100.0 if total_known is not None and n else None
    )
    analysis_status = str(
        ((ext_manifest or {}).get("options") or {}).get("analysis_status")
        or (records[0].get("extensions") or {}).get("retraction", {}).get("analysis_status")
        or "exploratory_post_hoc_test_seen"
    )
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.evidence_retraction.v1",
        "design": "evidence_retraction",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "project",
            "design_version": (ext_manifest or {}).get("design_version"),
            "analysis_status": analysis_status,
            "fail_policy": "fail-closed: invalid/missing verifier output retracts a positive first pass",
        },
        "counts": {
            "units": n,
            "first_pass_positive": first_positive,
            "retracted": retracted,
            "sustained": sustained,
            "verifier_invalid": verifier_invalid,
            "fail_closed": fail_closed,
            "by_status": count_by(str(record.get("status")) for record in records),
        },
        "primary": {
            "name": "macro_f1",
            "value": post_scores["macro_f1"],
            "n": post_scores["valid"],
            "ci_low": _boot_ci(bootstrap, "post_macro_f1").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "post_macro_f1").get("ci_high"),
            "method": "cluster percentile bootstrap (project)",
            "note": "Post-verification valid-only macro-F1; exploratory post-hoc, test seen.",
        },
        "metrics": {
            "post": post_scores,
            "pre": pre_scores,
            "delta_macro_f1": _metric(
                delta_macro,
                n,
                ci=_boot_ci(bootstrap, "delta_macro_f1"),
                method="cluster percentile bootstrap",
            ),
            "delta_mcc": delta_mcc,
            "pre_strict_accuracy": pre_strict,
            "post_strict_accuracy": post_strict,
            "retraction": {
                "retracted": retracted,
                "sustained": sustained,
                "retracted_true_positive": retracted_tp,
                "retracted_false_positive": retracted_fp,
                "retraction_precision": retraction_precision,
                "tp_loss_rate": tp_loss_rate,
                "fp_correction_rate": fp_correction_rate,
                "verifier_invalid": verifier_invalid,
                "fail_closed": fail_closed,
            },
            "mcnemar_pre_vs_post_strict": mcnemar,
        },
        "strata": {
            "confusion": {
                "pre": pre_scores["confusion"],
                "post": post_scores["confusion"],
            },
        },
        "comparisons": {
            "pre_vs_post": {
                "delta_macro_f1": delta_macro,
                "delta_mcc": delta_mcc,
                "delta_strict_accuracy": (
                    None
                    if pre_strict is None or post_strict is None
                    else post_strict - pre_strict
                ),
                "mcnemar": mcnemar,
            }
        },
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "Exploratory post-hoc: the 160 test functions were already used for the first-pass evidence run; this is not an independent confirmation.",
            "Only positive first-pass predictions are verified; negatives are unchanged by construction.",
            "Invalid/missing verifier output is fail-closed (retract), so a verifier API failure can look like a correct false-positive removal. The count is reported.",
            "The verifier sees source plus the first-pass claim, not the dataset label; claim construction and prompt are fixed per arm.",
            "Four arms are correlated (same 160 units); do not pool them as independent samples.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Enhanced dynamic
# ---------------------------------------------------------------------------


def enhanced_dynamic_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
    coverage_threshold: float,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "enhanced dynamic run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    labels: list[bool] = []
    protocol_preds: list[bool | None] = []
    operational_preds: list[bool | None] = []
    clusters: list[str] = []
    evidence_modes: Counter[str] = Counter()
    mode_counts: dict[str, Counter[str]] = defaultdict(Counter)
    unobservable = 0
    resolved = 0
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ExtensionError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        protocol_preds.append(
            as_bool((record.get("prediction") or {}).get("y_pred"))
            if record.get("status") == "ok"
            else None
        )
        ext = (record.get("extensions") or {}).get("dynamic_enhanced") or {}
        operational_preds.append(as_bool(ext.get("operational_y_pred")))
        clusters.append(str(record.get("cluster_id")))
        for mode in ext.get("evidence_modes") or []:
            evidence_modes[str(mode)] += 1
        if ext.get("unobservable_in_default") is True:
            unobservable += 1
            if ext.get("decision") == "leak":
                resolved += 1
        for mode, value in (ext.get("per_mode") or {}).items():
            if isinstance(value, Mapping):
                if value.get("applicable") is False:
                    mode_counts[str(mode)]["not_applicable"] += 1
                    continue
                mode_counts[str(mode)]["applicable"] += 1
                mode_counts[str(mode)][str(value.get("decision"))] += 1
    protocol_scores = detection_scores(labels, protocol_preds, confidence=confidence)
    operational_scores = detection_scores(labels, operational_preds, confidence=confidence)
    protocol_bootstrap = bootstrap_detection(
        labels, protocol_preds, clusters, resamples=resamples, seed=seed, confidence=confidence
    )
    operational_bootstrap = bootstrap_detection(
        labels, operational_preds, clusters, resamples=resamples, seed=seed, confidence=confidence
    )
    clean_count = sum(1 for record in records if (record.get("extensions") or {}).get("dynamic_enhanced", {}).get("decision") == "clean")
    clean_abstained = sum(
        1
        for record in records
        if (record.get("extensions") or {}).get("dynamic_enhanced", {}).get("decision") == "clean"
        and record.get("status") == "inconclusive"
    )
    parent = compute_run_metrics(
        run_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
        coverage_threshold=coverage_threshold,
    )
    cost = cost_summary(records)
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.enhanced_dynamic.v1",
        "design": "enhanced_dynamic",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "case_family",
            "coverage_threshold": coverage_threshold,
            "design_version": (ext_manifest or {}).get("design_version"),
            "protocol_rule": "clean without line coverage is inconclusive, not TN",
        },
        "counts": {
            "units": len(records),
            "bad": sum(1 for label in labels if label),
            "good": sum(1 for label in labels if not label),
            "leak": sum(1 for pred in protocol_preds if pred is True),
            "clean_inconclusive": clean_abstained,
            "clean_total": clean_count,
            "unobservable_in_default": unobservable,
            "resolved_by_enhanced_modes": resolved,
            "evidence_modes": dict(evidence_modes),
            "by_status": count_by(str(record.get("status")) for record in records),
        },
        "primary": {
            "name": "operational_macro_f1",
            "value": operational_scores["macro_f1"],
            "n": operational_scores["valid"],
            "ci_low": _boot_ci(operational_bootstrap, "macro_f1").get("ci_low"),
            "ci_high": _boot_ci(operational_bootstrap, "macro_f1").get("ci_high"),
            "method": "cluster percentile bootstrap (case_family)",
            "note": "Operational view treats source clean as negative; coverage-unverified and not a protocol-valid TN.",
        },
        "metrics": {
            "protocol": protocol_scores,
            "protocol_macro_f1": _metric(
                protocol_scores["macro_f1"],
                protocol_scores["valid"],
                ci=_boot_ci(protocol_bootstrap, "macro_f1"),
                method="cluster percentile bootstrap",
                note="Protocol view: clean is inconclusive; macro-F1 undefined when no valid negative exists.",
            ),
            "operational": operational_scores,
            "operational_macro_f1": _metric(
                operational_scores["macro_f1"],
                operational_scores["valid"],
                ci=_boot_ci(operational_bootstrap, "macro_f1"),
                method="cluster percentile bootstrap",
                note="Source-level operational view only; do not report as protocol-valid TN.",
            ),
            "leak_recall": _metric(
                protocol_scores["recall"],
                protocol_scores["confusion"]["tp"] + protocol_scores["confusion"]["fn"],
                method="count",
            ),
            "clean_abstention": _metric(
                rate(clean_abstained, clean_count),
                clean_count,
                method="count",
                note="Clean units without line coverage are inconclusive; this is the protocol-valid abstention rate.",
            ),
            "protocol_coverage": protocol_scores["coverage"],
            "operational_coverage": operational_scores["coverage"],
            "per_mode": {mode: dict(counts) for mode, counts in mode_counts.items()},
        },
        "strata": {
            "by_mode": {mode: dict(counts) for mode, counts in mode_counts.items()},
            "by_unobservable": {
                "unobservable_in_default": unobservable,
                "resolved_by_enhanced_modes": resolved,
            },
        },
        "comparisons": {
            "protocol_vs_operational_macro_f1": (
                None
                if protocol_scores.get("macro_f1") is None
                else operational_scores["macro_f1"] - protocol_scores["macro_f1"]
            ),
        },
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "The run has no line/branch coverage instrumentation; protocol-valid clean is inconclusive, not TN.",
            "The 70/70 leak/clean is the producer operational view, not a protocol-valid confusion matrix. It must be labelled coverage-unverified.",
            "Fault injection is a realloc-failure wrapper and a global-root switch, not a fault-variant suite; do not pool with fault_injected_dynamic.",
            "Single run, single path per mode; no fuzzing or run-to-run variance.",
            "Never pool with the canonical 140-unit dynamic run or with other dynamic methods.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }


# ---------------------------------------------------------------------------
# Hybrid guided by enhanced dynamic evidence
# ---------------------------------------------------------------------------


def hybrid_enhanced_dynamic_metrics(
    run_dir: Path,
    *,
    resamples: int,
    seed: int,
    confidence: float,
    coverage_threshold: float,
) -> dict[str, Any]:
    report = validate_extension_run(run_dir, use_jsonschema=False)
    if report.get("errors"):
        raise ExtensionError(
            "hybrid enhanced dynamic run failed validation: " + "; ".join(report["errors"][:5])
        )
    manifest, ext_manifest, records, _ = load_extension_run(run_dir)
    labels: list[bool] = []
    preds: list[bool | None] = []
    clusters: list[str] = []
    tool_verdicts: list[bool | None] = []
    evidence_outcomes: Counter[str] = Counter()
    for record in records:
        label = as_bool((record.get("label") or {}).get("y_true"))
        if label is None:
            raise ExtensionError(f"{record.get('unit_id')}: label.y_true is not binary")
        labels.append(label)
        preds.append(
            as_bool((record.get("prediction") or {}).get("y_pred"))
            if record.get("status") == "ok"
            else None
        )
        clusters.append(str(record.get("cluster_id")))
        ext = (record.get("extensions") or {}).get("hybrid_dynamic_enhanced") or {}
        tool_value = ext.get("tool_verdict")
        tool_verdicts.append(bool(tool_value) if tool_value in (0, 1, True, False) else None)
        evidence_outcomes[str(ext.get("evidence_outcome"))] += 1
    scores = detection_scores(labels, preds, confidence=confidence)
    bootstrap = bootstrap_detection(
        labels, preds, clusters, resamples=resamples, seed=seed, confidence=confidence
    )
    agreement = agreement_counts(
        [bool(value) for value in preds if value is not None],
        [bool(value) for value in tool_verdicts if value is not None],
    )
    tool_pairs = [
        (pred, tool)
        for pred, tool in zip(preds, tool_verdicts)
        if pred is not None and tool is not None
    ]
    tool_agreement = (
        sum(1 for pred, tool in tool_pairs if pred == tool) / len(tool_pairs)
        if tool_pairs
        else None
    )
    overcall = sum(1 for pred, tool in tool_pairs if pred and not tool)
    undercall = sum(1 for pred, tool in tool_pairs if not pred and tool)
    tool_correct = sum(
        1
        for label, tool in zip(labels, tool_verdicts)
        if tool is not None and tool == label
    )
    tool_n = sum(1 for tool in tool_verdicts if tool is not None)
    parent = compute_run_metrics(
        run_dir,
        resamples=resamples,
        seed=seed,
        confidence=confidence,
        coverage_threshold=coverage_threshold,
    )
    cost = cost_summary(records)
    return {
        "schema_version": EXTENSION_METRICS_SCHEMA,
        "extension_id": "ext.hybrid_enhanced_dynamic.v1",
        "design": "hybrid_enhanced_dynamic",
        "generated_at": utc_now(),
        "run_ids": {"run": str(manifest.get("run_id"))},
        "settings": {
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "confidence": confidence,
            "cluster_unit": "case_family",
            "design_version": (ext_manifest or {}).get("design_version"),
        },
        "counts": {
            "units": len(records),
            "valid": scores["valid"],
            "by_status": count_by(str(record.get("status")) for record in records),
            "evidence_outcomes": dict(evidence_outcomes),
            "tool_verdicts": count_by(str(value) for value in tool_verdicts),
            "overcall_vs_tool": overcall,
            "undercall_vs_tool": undercall,
        },
        "primary": {
            "name": "macro_f1",
            "value": scores["macro_f1"],
            "n": scores["valid"],
            "ci_low": _boot_ci(bootstrap, "macro_f1").get("ci_low"),
            "ci_high": _boot_ci(bootstrap, "macro_f1").get("ci_high"),
            "method": "cluster percentile bootstrap (case_family)",
            "note": "Valid-only LLM leak detection with enhanced dynamic evidence.",
        },
        "metrics": {
            "detection": {
                "scores": scores,
                "bootstrap": bootstrap.get("metrics", {}),
                "cluster_count": bootstrap.get("cluster_count"),
            },
            "mcc": scores["mcc"],
            "strict_accuracy": scores["strict_accuracy"],
            "tool_agreement": _metric(
                tool_agreement,
                len(tool_pairs),
                method="count",
                note=f"{agreement['agree']}/{len(tool_pairs)} LLM-tool agreement.",
            ),
            "tool_accuracy": _metric(
                rate(tool_correct, tool_n), tool_n, method="count"
            ),
            "overcall_vs_tool": _metric(overcall, len(tool_pairs), method="count"),
            "undercall_vs_tool": _metric(undercall, len(tool_pairs), method="count"),
        },
        "strata": {
            "by_evidence_outcome": dict(evidence_outcomes),
        },
        "comparisons": {
            "tool_agreement": agreement,
            "note": "Tool baseline is 140/140; agreement equals accuracy here, so it cannot separate copying from independent judgement. Compare to frozen hybrid_v2 direct/combined only descriptively.",
        },
        "parent_metrics": parent,
        "cost": cost,
        "limitations": [
            "The 140/140 tool baseline makes LLM-tool agreement equal to accuracy; it is not an independent measure of evidence use.",
            "Enhanced dynamic evidence is sanitized but may still induce anchoring; the producer reports reason-level byte copying, not causal use.",
            "Frozen hybrid_v2 direct/combined baselines are from a different date/harness; compare descriptively, not as a controlled rerun.",
            "Single run per model; no seed/run-to-run variance.",
            "Do not pool with dynamic_enhanced tool metrics or canonical 140 dynamic runs.",
        ],
        "provenance": {
            "extension_version": EXTENSION_VERSION,
            "hashes": _run_hashes(run_dir),
            "source": "canonical extension run; metrics recomputed, not copied",
        },
    }

def _resolve_run_dirs(run_dir: Path) -> tuple[str, list[Path]]:
    if (run_dir / "run_manifest.json").exists():
        manifest, ext_manifest, records, _ = load_extension_run(run_dir)
        design = infer_design(manifest, ext_manifest, records)
        return design, [run_dir]
    if (run_dir / "order_ab").exists() and (run_dir / "order_ba").exists():
        return "position_debiased_pair", [run_dir / "order_ab", run_dir / "order_ba"]
    if (run_dir / "fwd").exists() and (run_dir / "rev").exists():
        return "position_debiased_pair", [run_dir / "fwd", run_dir / "rev"]
    if (run_dir / "order_fwd").exists() and (run_dir / "order_rev").exists():
        return "position_debiased_pair", [run_dir / "order_fwd", run_dir / "order_rev"]
    raise ExtensionError(
        f"{run_dir}: expected run_manifest.json or order_ab/order_ba under a position base"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="extension run or position base directory")
    parser.add_argument("--design", help="override/infer design")
    parser.add_argument("--out-dir", help="output directory (default: run directory / position base)")
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_BOOTSTRAP_SEED)
    parser.add_argument("--coverage-threshold", type=float, default=0.8)
    parser.add_argument("--baseline-run", help="optional baseline run for descriptive comparison")
    parser.add_argument("--force", action="store_true", help="overwrite existing metrics files")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    try:
        design, dirs = _resolve_run_dirs(run_dir)
        if args.design and args.design != design:
            raise ExtensionError(f"design {args.design!r} does not match run design {design!r}")
        if design == "position_debiased_pair":
            if len(dirs) != 2:
                raise ExtensionError("position metrics require both order_ab and order_ba")
            metrics = position_metrics(
                dirs[0], dirs[1], resamples=args.bootstrap, seed=args.seed, confidence=DEFAULT_CONFIDENCE
            )
            default_out = run_dir
        elif design == "open_choice_pair":
            metrics = open_choice_metrics(
                dirs[0],
                resamples=args.bootstrap,
                seed=args.seed,
                confidence=DEFAULT_CONFIDENCE,
                baseline_run=args.baseline_run,
            )
            default_out = dirs[0]
        elif design == "evidence_verification":
            metrics = evidence_metrics(
                dirs[0], resamples=args.bootstrap, seed=args.seed, confidence=DEFAULT_CONFIDENCE
            )
            default_out = dirs[0]
        elif design == "fault_injected_dynamic":
            metrics = fault_metrics(
                dirs[0],
                resamples=args.bootstrap,
                seed=args.seed,
                confidence=DEFAULT_CONFIDENCE,
                coverage_threshold=args.coverage_threshold,
            )
            default_out = dirs[0]
        elif design == "evidence_retraction":
            metrics = evidence_retraction_metrics(
                dirs[0], resamples=args.bootstrap, seed=args.seed, confidence=DEFAULT_CONFIDENCE
            )
            default_out = dirs[0]
        elif design == "hybrid_enhanced_dynamic":
            metrics = hybrid_enhanced_dynamic_metrics(
                dirs[0],
                resamples=args.bootstrap,
                seed=args.seed,
                confidence=DEFAULT_CONFIDENCE,
                coverage_threshold=args.coverage_threshold,
            )
            default_out = dirs[0]
        elif design == "enhanced_dynamic":
            metrics = enhanced_dynamic_metrics(
                dirs[0],
                resamples=args.bootstrap,
                seed=args.seed,
                confidence=DEFAULT_CONFIDENCE,
                coverage_threshold=args.coverage_threshold,
            )
            default_out = dirs[0]
        else:
            metrics = static_metrics(
                dirs[0],
                resamples=args.bootstrap,
                seed=args.seed,
                confidence=DEFAULT_CONFIDENCE,
                coverage_threshold=args.coverage_threshold,
                baseline_run=args.baseline_run,
            )
            default_out = dirs[0]
        out_dir = Path(args.out_dir).resolve() if args.out_dir else default_out
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "metrics.json"
        md_path = out_dir / "metrics.md"
        if not args.force and (json_path.exists() or md_path.exists()):
            sys.stderr.write(f"refusing to overwrite {json_path} / {md_path}; pass --force\n")
            return 2
        atomic_write_json(json_path, metrics)
        _write_markdown(md_path, metrics)
        sys.stderr.write(f"wrote {json_path} and {md_path}\n")
        sys.stdout.write(
            json.dumps(
                {
                    "design": design,
                    "primary": metrics.get("primary"),
                    "counts": metrics.get("counts"),
                },
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        )
        return 0
    except ExtensionError as exc:
        sys.stderr.write(f"metrics failed: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

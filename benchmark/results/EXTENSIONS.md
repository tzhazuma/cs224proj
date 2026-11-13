# Extension layer — final benchmark extension summary

- generated: `2026-11-13T18:31:09Z`; protocol `1.0.0`; extension layer `0.2.0`
- registry: `2026-11-14.3`
- **This file is the only index for extension designs. `LEADERBOARD.md` links here and imports no number from it.**
- **No pooling across designs, tiers or tasks.** Each design has its own denominator and primary endpoint.

## 0. TL;DR

| design | units | primary endpoint | result | status |
| --- | --- | --- | --- | --- |
| position-debiased pair (deepseek) | 180 pairs × 2 orders | position-average pair DA | 77.22% | imported |
| position-debiased pair (mimo) | 180 pairs × 2 orders | position-average pair DA | 84.17% | imported |
| open-choice pair (deepseek/fwd) | 180 valid pairs | pair DA | 66.11% | imported |
| open-choice pair (deepseek/rev) | 180 valid pairs | pair DA | 63.89% | imported |
| open-choice pair (mimo/fwd) | 180 valid pairs | pair DA | 66.11% | imported |
| open-choice pair (mimo/rev) | 178 valid pairs | pair DA | 65.73% | imported |
| evidence retraction (deepseek_self) | 159/160 valid | post macro-F1 | 0.2181 | exploratory |
| evidence retraction (deepseek_by_mimo) | 159/160 valid | post macro-F1 | 0.3522 | exploratory |
| evidence retraction (mimo_self) | 158/160 valid | post macro-F1 | 0.3221 | exploratory |
| evidence retraction (mimo_by_deepseek) | 158/160 valid | post macro-F1 | 0.2226 | exploratory |
| enhanced dynamic | 140 | protocol macro-F1 | undefined (valid 70, coverage 50%) | imported |
| hybrid enhanced dynamic (deepseek) | 140 | macro-F1 | 0.9786 | imported |
| hybrid enhanced dynamic (mimo) | 140 | macro-F1 | 0.9714 | imported |
| CodeQL new static tool | 140 (136 valid) | macro-F1 | 0.8259 | imported |
| schema recovery | 924 repair + 1,560 detection | official vs code-only usable | 552/924 → 619/924 (+7.25 pp) | audit |

The schema-recovery analysis makes **0 API calls**; it recomputes format validity from already stored payloads and is not a new model result.

## 1. Scope and non-pooling rules

1. **Designs are variants of a parent task, not a new task enum.** Position/open-choice map to `pair_detection`; evidence retraction maps to `detection`; dynamic/static/hybrid map to `leak_detection`.
2. **One denominator per design.** Pair designs use `pair_id`; evidence uses the 160 functions; dynamic/static/hybrid use the 140 test units; schema recovery uses the 924 repair and 1,560 detection requests.
3. **Failures are never negative labels.** `status != "ok"` keeps `prediction.y_pred = null`; compile errors and invalid verifier output are counted wrong in strict, excluded from valid-only.
4. **No composite score.** The result designs are not added, averaged, ranked or resampled together.

`evidence_verification` (claim-level support/reject) and `fault_injected_dynamic` (fault-variant suite) remain
`design_ready_no_results`: they have no canonical run and are not part of any table below. The six result
designs are pair_debias, open-choice pair, evidence retraction, enhanced dynamic, hybrid enhanced dynamic and
the CodeQL static tool; schema recovery is a separate audit.

## 2. Canonical runs and validation

Fresh structural validation (`ext_validate.py --jsonschema`) was run on **16 canonical runs**: **16/16 ok**, 0 errors, 0 warnings. Parent metrics were recomputed from `predictions.jsonl` and compared with the stored `parent_metrics` on n/valid/confusion/macro-F1/MCC/DA: **16 checks, 0 mismatches**. Design-level arithmetic: **37 checks, 0 mismatches**.

| canonical run | design | records | validation |
| --- | --- | ---: | --- |
| `benchmark/extensions/runs/pair_debias/deepseek/forced/fwd` | `position_debiased_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/deepseek/forced/rev` | `position_debiased_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/deepseek/open_fwd` | `open_choice_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/deepseek/open_rev` | `open_choice_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/mimo/forced/fwd` | `position_debiased_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/mimo/forced/rev` | `position_debiased_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/mimo/open_fwd` | `open_choice_pair` | 360 | ok |
| `benchmark/extensions/runs/pair_debias/mimo/open_rev` | `open_choice_pair` | 360 | ok |
| `benchmark/extensions/runs/evidence_verify/deepseek_self` | `evidence_retraction` | 160 | ok |
| `benchmark/extensions/runs/evidence_verify/deepseek_by_mimo` | `evidence_retraction` | 160 | ok |
| `benchmark/extensions/runs/evidence_verify/mimo_self` | `evidence_retraction` | 160 | ok |
| `benchmark/extensions/runs/evidence_verify/mimo_by_deepseek` | `evidence_retraction` | 160 | ok |
| `benchmark/extensions/runs/dynamic_enhanced/test140_enhanced_v3` | `enhanced_dynamic` | 140 | ok |
| `benchmark/extensions/runs/hybrid_dynamic_enhanced/deepseek` | `hybrid_enhanced_dynamic` | 140 | ok |
| `benchmark/extensions/runs/hybrid_dynamic_enhanced/mimo` | `hybrid_enhanced_dynamic` | 140 | ok |
| `benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114` | `new_static_tool` | 140 | ok |

The position-debiased `forced` directory is a paired base (`fwd/` + `rev/`); both orders were validated against each other, and the design metrics were recomputed on the pair level.

## 3. Pair debiasing (`pair_debias`)

### 3.1 Forced choice with fwd/rev slot swap

| model | pairs | position-average DA | order-consensus DA | order consistency | position bias (A−B) | length-only DA | chose longer |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | 180 | 77.22% [0.728, 0.814] | 61.67% | 68.89% | 31.11% | 25.29% | 25.57% |
| mimo | 180 | 84.17% [0.797, 0.881] | 74.44% | 80.56% | 12.78% | 25.29% | 21.84% |

The position-average DA averages the two presentations; the consensus DA requires both to be correct. The gap is exactly half the flip rate and is a stability penalty, not a score to maximise. DeepSeek keeps a large A-slot advantage (31.1 pp); MiMo is smaller (12.8 pp). The length-only heuristic is 25.29% for both models, so neither result can be explained by length alone.

**Do not compare this table with the pair-joint 76.67% / 86.67%.** The tasks differ (single forced A/B vs two independent side verdicts).

### 3.2 Open choice (A / B / both / neither)

| model | order | valid pairs | correct | pair DA | 95% CI | decisive rate | conditional DA | both | neither |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| deepseek | fwd | 180/180 | 119 | 66.11% | [0.594, 0.733] | 78.89% | 83.80% | 7.22% | 13.89% |
| deepseek | rev | 180/180 | 115 | 63.89% | [0.567, 0.711] | 82.78% | 77.18% | 3.89% | 13.33% |
| mimo | fwd | 180/180 | 119 | 66.11% | [0.594, 0.728] | 78.33% | 84.40% | 4.44% | 17.22% |
| mimo | rev | 178/180 | 117 | 65.73% | [0.590, 0.725] | 77.53% | 84.78% | 3.93% | 18.54% |

`both`/`neither` are substantive answers and count as pair errors; `conditional DA` is computed only over decisive A/B answers. The two orders are correlated presentations of the same 180 pairs, not independent samples.

## 4. Evidence verification by retraction (`evidence_verify`)

| arm | valid | post TP/FP/TN/FN | post macro-F1 | pre macro-F1 | Δ | retracted (TP/FP) | retraction precision | TP loss | FP correction | invalid / fail-closed |
| --- | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |
| deepseek_self | 159/160 | 6/0/32/121 | 0.2181 | 0.4223 | -0.2043 | 54 (43/11) | 20.37% | 87.76% | 100.00% | 0 / 0 |
| deepseek_by_mimo | 159/160 | 28/4/28/99 | 0.3522 | 0.4223 | -0.0701 | 26 (20/6) | 23.08% | 40.82% | 54.55% | 2 / 2 |
| mimo_self | 158/160 | 28/8/23/99 | 0.3221 | 0.4067 | -0.0846 | 21 (18/3) | 14.29% | 38.30% | 27.27% | 1 / 1 |
| mimo_by_deepseek | 158/160 | 7/0/31/120 | 0.2226 | 0.4067 | -0.1842 | 51 (40/11) | 21.57% | 85.11% | 100.00% | 0 / 0 |

All four arms use the same 160 test functions and the same first-pass positives. This is **post-hoc and test-seen**: the test set was already used by the first pass. The arms are correlated; invalid verifier output is fail-closed (treated as retract) and must be read with the invalid/fail-closed counts. The retraction step lowers macro-F1 in every arm; it is not a gain.

## 5. Enhanced dynamic (`dynamic_enhanced`)

| view | valid | coverage | recall | specificity | macro-F1 | strict |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| protocol (clean = inconclusive) | 70/140 | 50.00% | 100.00% | undefined | undefined | 50.00% |
| operational (source clean = 0, coverage-unverified) | 140/140 | 100.00% | 100.00% | 100.00% | 1.0000 | 100.00% |

The three modes resolve **12/12** bad units that the default LSan root set cannot observe: 7 by realloc-failure injection, 5 by dropping global roots. The 70/70 operational view is the producer's source-level count, **not a protocol-valid confusion matrix**: there is no line/branch coverage instrumentation, so a clean observation is `inconclusive`, not TN.

**Never report the operational 1.0 as protocol dynamic detection.** It may not be pooled with the canonical 140-unit ASan/LSan/Valgrind runs.

## 6. Hybrid enhanced dynamic (`hybrid_dynamic_enhanced`)

| model | valid | TP/FP/TN/FN | macro-F1 | 95% CI | MCC | strict | agreement with 140/140 tool |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: |
| deepseek | 140/140 | 70/3/67/0 | 0.9786 | [0.954, 1.000] | 0.9580 | 97.86% | 97.86% |
| mimo | 140/140 | 70/4/66/0 | 0.9714 | [0.943, 0.993] | 0.9444 | 97.14% | 97.14% |

The enhanced-dynamic tool is 140/140 on this set, so tool agreement equals accuracy; it is not independent evidence that the model understood the evidence. Against the frozen hybrid v2 direct runs the producer reports +2/−0 (DeepSeek, McNemar p=0.5) and 0/0 (MiMo), not significant after Holm. No headroom remains for the 12 previously unobservable bad units because v2 direct already handles them.

## 7. CodeQL new static tool (`new_static_tool`)

CodeQL **2.27.4** (`codeql/cpp-queries` 1.10.0, `cpp-all` 12.4.0) ran on the frozen Juliet CWE-401 test split. Two pinned queries: `cpp/memory-never-freed` and `cpp/memory-may-not-be-freed`; only findings in the unit's own source file count. **136/140 units are evaluable; 4 compile errors** (the `_82` C++ group, same as Clang).

| view | n | TP | FP | TN | FN | precision | recall | specificity | macro-F1 | MCC | strict |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| valid-only | 136 | 68 | 23 | 45 | 0 | 0.7473 | 1.0000 | 0.6618 | 0.8259 | 0.7032 | 80.71% |
| end-to-end (compile = no finding) | 140 | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.6714 | 0.8173 | 0.6739 | — |

The canonical statement is: **valid TP 68 / FP 23 / TN 45 / FN 0; end-to-end TP 68 / FP 23 / TN 47 / FN 2**, with the two extra TN/FN coming from the 4 compile errors (2 good, 2 bad). The producer cross-check in `static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.json` matches these cells exactly. The valid **positive-class F1 is 0.855**, while the **macro-F1 is 0.826**; do not quote one as the other.

| query | TP | FP | TN | FN | precision | recall | macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `cpp/memory-never-freed` | 46 | 0 | 68 | 22 | 1.0000 | 0.6765 | 0.8339 |
| `cpp/memory-may-not-be-freed` | 22 | 23 | 45 | 46 | 0.4889 | 0.3235 | 0.4777 |

Against the canonical Clang run on the 136 common-valid units: CodeQL catches **38** units Clang misses and misses **0** that Clang catches; Cohen's κ is 0.4800. The McNemar p is 7.28e-12 (descriptive; the tools are not independent ground truth).

### Time cost

| measure | CodeQL | Clang SA | ratio |
| --- | ---: | ---: | ---: |
| 200-unit run wall (6 jobs) | 1434.7 s | 23.59 s | 60.8× throughput |
| per-unit serial compute (test 140) | 43.30 s | 0.1179 s | 367× |
| test-140 summed unit time | 6061.8 s | 16.50 s | 367× |

CodeQL creates one database per unit (build + query): mean 42.5 s, median 43.0 s, P95 51.7 s per unit; the 6-job wall is 1,434.7 s for 200 units (about 7.17 s/unit throughput). Clang is ~0.118 s/unit. CodeQL is roughly **61× slower in wall throughput** and **~367× slower in serial per-unit compute**. Local compute only; USD is not applicable.

## 8. Schema recovery (`analysis/schema_recovery`)

| metric | value |
| --- | ---: |
| API calls | 0 |
| DeepSeek repair official valid | 822/924 (89.0%) |
| DeepSeek repair invalid | 102 (11.0%) |
| invalid = missing `explanation` only | 93 (91.2% of invalid) |
| invalid = truncation | 9 (8.8% of invalid) |
| official usable patch | 552/924 (59.7%) |
| code-only usable patch | 619/924 (67.0%) |
| usable gain from salvage | 67 (+7.25 pp) |
| MiMo detection field drift recovered | 61/61 (100%) |
| MiMo recovered label agreement (descriptive) | 28/61 (45.9%) |

The 93 missing-`explanation` payloads are structurally complete (91/93 canonical, 93/93 K&R-aware), but only 67 are usable canonical patches; 18 are unchanged, 4 whitespace-only and 2 comment-only. The 9 truncations are fatal and are **not** repaired by adding brackets or quotes. **Salvage is a format admission, not correctness**; 28/61 label agreement is descriptive and is not accuracy.

## 9. What cannot be claimed

- No cross-design, cross-tier or cross-task pooling. The result designs answer different questions with different denominators.
- Pair-debiased forced DA and pair-joint forced-choice DA are different tasks; the two numbers must not be subtracted or ranked together.
- Open-choice pair DA includes both/neither as errors; it is not comparable to forced-choice DA.
- Evidence retraction is post-hoc and test-seen; the four arms are correlated and exploratory.
- Enhanced dynamic has no line-coverage instrumentation: protocol clean is inconclusive, not TN. The 70/70 operational view is coverage-unverified.
- Hybrid enhanced dynamic meets a 140/140 tool; agreement equals accuracy and is not independent evidence of reasoning.
- CodeQL valid-only macro-F1 (0.826) differs from the positive-class F1 (0.855); compile errors are counted wrong in strict and end-to-end.
- CodeQL timing is local compute, not a cloud bill; the 6-job wall is throughput, not per-unit latency.
- Schema recovery is a format/audit analysis with zero API calls; salvage is not correctness and label agreement is descriptive only.
- Single run per cell; no seed or run-to-run variance.

## 10. Reproduction

```bash
# WSL, project root
python3 benchmark/extensions/tools/ext_validate.py --check-registries
python3 benchmark/extensions/tools/ext_validate.py --run-dir benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114 --jsonschema --unit-map juliet/subset_units.jsonl
python3 benchmark/extensions/tools/ext_metrics.py --run-dir benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114 --baseline-run benchmark/results/tier_b/juliet_cwe401/static_clang/tierb_juliet_cwe401_static_clang_20261112_4c5800c4
python3 benchmark/tools/bench_ext_summary.py
```

## 11. Artifacts

| path | content |
| --- | --- |
| `benchmark/results/EXTENSIONS.md` | this document |
| `benchmark/results/extension_summary.json` | machine-readable summary, validation and statistics check |
| `benchmark/extensions/runs/new_static_tool/codeql_cwe401_test140_20261114/` | canonical CodeQL run (140 records) |
| `static_extended/runs/codeql_20261114_cwe401_full/` | producer run (read-only source) |
| `analysis/schema_recovery/schema_recovery.json` | schema-recovery source (read-only) |

`EXTENSIONS.md` and `extension_summary.json` are generated by `benchmark/tools/bench_ext_summary.py`; rerunning it rewrites only these two files.

# Unified benchmark leaderboard — final integration

- generated: `2026-11-11T21:39:28Z`
- protocol: `1.0.0`; builder: `bench_final_summary.py`
- runs: 34 canonical runs (Tier A 16, Tier B 18); 11 superseded historical runs excluded
- **Canonical Tier B hybrid = `hybrid_v2` (leak-fixed inputs).** `hybrid_v1` is leakage-sensitive and does not appear in any main table.
- **Tier A and Tier B are not pooled. Pair-joint is not pooled with side-wise pair. Repair is separate.**

## 0. TL;DR

- **Tier A detection (160)**: evidence prompt raises macro-F1 from 0.3828 to 0.4223 for DeepSeek and from 0.3456 to 0.4067 for MiMo; the gain is mostly recall/operating-point shift, not a proven discrimination gain.
- **Tier A pair-joint (180 forced choices)**: DeepSeek 76.67% (95% CI [0.706, 0.822]), MiMo 86.67% (95% CI [0.817, 0.917]). This is a forced binary task; do not compare it directly with side-wise DA.
- **Tier B test 140**: best traditional tools are ASan/LSan and Valgrind at 0.9137 macro-F1; Clang SA is 0.8883 (4 compile errors); MiMo Xiaomi postleakfix LLM is 0.9500. Hybrid v2 combined reaches 0.9714 (DeepSeek, 136/140) and 0.9714 (MiMo, 136/140); the gain over direct is at most one unit and is not significant after Holm. The old v1 perfect score is withdrawn as leakage-sensitive.
- **Repair**: both models pass 58/58 observable units; the 12 LSan-unobservable units are excluded from the denominator.

## 1. Scope, datasets and denominators

| tier | dataset | primary view | units | labels |
| --- | --- | --- | ---: | --- |
| A | SecVulEval `secvul-split-v1` | detection 160 functions | 160 | 128 vulnerable / 32 non-vulnerable |
| A | SecVulEval `secvul-split-v1` | pair 180 pairs (side-wise and joint) | 180 pairs / 360 sides | vulnerable / fixed |
| B | Juliet CWE-401 `juliet-cwe401-v1.3-subset-v1` | test 140 | 140 (70 bad / 70 good) | Juliet intended |
| B | Juliet repair | test 70 bad units | 70 (58 baseline-observable) | all bad |

Tier B test 140 is the only primary comparison set. The dev 60 split exists for the frozen static/dynamic runs but is reference-only; LLM/hybrid/repair runs are test-only.

## 2. Tier A — SecVulEval

### 2.1 Detection (160 functions; valid-only with strict view)

| method | family | n | valid | coverage | macro-F1 | 95% CI | MCC | strict | P | R | spec | USD | norm $/100u | p50/p95 s |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| DeepSeek V4.1 Flash / direct | llm | 160 | 160 | 100.00% | 0.3828 | [0.305, 0.552] | 0.041 | 38.75% | 0.826 | 0.297 | 0.750 | $0.066988 | $0.020934 | 5.65/10.83 |
| DeepSeek V4.1 Flash / few-shot | llm | 160 | 160 | 100.00% | 0.3995 | [0.305, 0.593] | 0.061 | 40.62% | 0.837 | 0.320 | 0.750 | $0.136741 | $0.042731 | 5.33/9.69 |
| DeepSeek V4.1 Flash / context | llm | 160 | 160 | 100.00% | 0.3813 | [0.286, 0.560] | 0.020 | 38.75% | 0.812 | 0.305 | 0.719 | $0.070308 | $0.021971 | 5.63/10.71 |
| DeepSeek V4.1 Flash / evidence-lines + counterfactual | llm | 160 | 159 | 99.38% | 0.4223 | [0.323, 0.590] | 0.035 | 43.75% | 0.817 | 0.386 | 0.656 | $0.085622 | $0.026757 | 6.04/12.06 |
| MiMo-V2.6-Flash / direct | llm | 160 | 150 | 93.75% | 0.3456 | [0.264, 0.528] | 0.008 | 32.50% | 0.806 | 0.242 | 0.767 | $0.024397 | $0.015248 | 4.59/12.00 |
| MiMo-V2.6-Flash / few-shot | llm | 160 | 160 | 100.00% | 0.3463 | [0.262, 0.512] | -0.042 | 35.00% | 0.773 | 0.266 | 0.688 | $0.034011 | $0.021257 | 4.51/11.03 |
| MiMo-V2.6-Flash / context | llm | 160 | 153 | 95.62% | 0.3650 | [0.278, 0.571] | 0.080 | 35.00% | 0.861 | 0.252 | 0.833 | $0.025568 | $0.015980 | 4.31/8.38 |
| MiMo-V2.6-Flash / evidence-lines + counterfactual | llm | 160 | 158 | 98.75% | 0.4067 | [0.306, 0.596] | 0.013 | 41.88% | 0.810 | 0.370 | 0.645 | $0.035933 | $0.022458 | 4.05/10.87 |

`evidence` is the new six-field evidence-line/counterfactual prompt. The legacy direct/few-shot/context rows are read-only derived views. `strict` counts schema-invalid/API failures wrong; valid-only excludes them and coverage is shown.

### 2.2 Detection paired comparisons

Direction: `run_a - run_b`; positive means the first named method has higher macro-F1. McNemar is exact two-sided on common-valid units; Holm is applied inside each pre-registered family.

| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |
| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |
| detection direct: DeepSeek - MiMo | 150 | 0.0310 | [-0.0178, 0.0771] | +3.33 pp | 11/6 | 0.3323 | 0.6646 | `A-MODEL-DETECTION` (m=3) |
| detection few-shot: DeepSeek - MiMo | 160 | 0.0531 | [0.0101, 0.1286] | +5.63 pp | 15/6 | 0.0784 | 0.2351 | `A-MODEL-DETECTION` (m=3) |
| detection context: DeepSeek - MiMo | 153 | 0.0088 | [-0.0699, 0.0584] | +1.31 pp | 10/8 | 0.8145 | 0.8145 | `A-MODEL-DETECTION` (m=3) |
| evidence vs direct: DeepSeek | 159 | 0.0428 | [-0.0193, 0.0948] | +5.66 pp | 13/4 | 0.0490 | 0.0490 | `A-EVIDENCE-DEEPSEEK` (m=1) |
| evidence vs direct: MiMo | 148 | 0.0473 | [0.0005, 0.0882] | +6.08 pp | 13/4 | 0.0490 | 0.0490 | `A-EVIDENCE-MIMO` (m=1) |
| evidence: DeepSeek - MiMo | 157 | 0.0184 | [-0.0116, 0.0350] | +1.91 pp | 9/6 | 0.6072 | 0.6072 | `A-EVIDENCE-MODEL` (m=1) |

The evidence-vs-direct rows are paired on common-valid units (DeepSeek 159, MiMo 148); the raw McNemar is on paired correctness, not on the macro-F1 difference. The recall gain is larger than the F1 gain because false positives also rise.

Evidence-prompt endpoint decomposition (pre-specified: recall on vulnerable functions, FPR on non-vulnerable functions):

| model | recall n | recall direct → evidence | Δrecall | recall p (Holm) | FPR n | FPR direct → evidence | ΔFPR | FPR p (Holm) | overall common-valid p | strict p (all 160) |
| --- | ---: | --- | ---: | --- | ---: | --- | ---: | --- | ---: | ---: |
| deepseek | 127 | 29.13% → 38.58% | +9.45 pp | 0.0018 (0.0055) | 32 | 25.00% → 34.38% | +9.38 pp | 0.2500 (0.2500) | 0.0490 | 0.0963 |
| mimo | 119 | 24.37% → 35.29% | +10.92 pp | 2.441e-04 (9.766e-04) | 29 | 20.69% → 34.48% | +13.79 pp | 0.1250 (0.2500) | 0.0490 | 0.0026 |

Recall rises significantly for both models after Holm; FPR also rises in point estimate but the test has only 32/29 negative functions and is underpowered. The overall common-valid McNemar is borderline (p≈0.049); the all-160 strict McNemar, which counts the one evidence invalid output wrong, is p≈0.096 for DeepSeek and p≈0.0026 for MiMo.
- deepseek common-valid: Δbalanced accuracy +0.04 pp, ΔMCC -0.0020 (MCC 0.037 → 0.035).
- mimo common-valid: Δbalanced accuracy -1.43 pp, ΔMCC -0.0276 (MCC 0.034 → 0.007).

The correct reading is an operating-point shift, not a consistent gain in balanced discrimination: recall/F1 rise, FPR also rises, and balanced accuracy/MCC are flat or slightly lower.

### 2.3 Pair discrimination: side-wise vs joint forced choice

**Side-wise free-form** (two independent verdicts per pair):

| model | strategy | pairs | valid | coverage | pair DA | 95% CI | both flagged | both clean | swapped | USD | p50/p95 s |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |
| DeepSeek V4.1 Flash / direct | direct | 180 | 180 | 100.00% | 11.67% | [0.072, 0.167] | 44 | 113 | 2 | $0.138323 | 5.72/13.82 |
| DeepSeek V4.1 Flash / few-shot | few-shot | 180 | 180 | 100.00% | 8.89% | [0.050, 0.133] | 49 | 113 | 2 | $0.294895 | 5.31/8.38 |
| DeepSeek V4.1 Flash / context | context | 180 | 180 | 100.00% | 12.22% | [0.078, 0.172] | 49 | 108 | 1 | $0.144837 | 5.62/13.13 |
| MiMo-V2.6-Flash / direct | direct | 180 | 154 | 85.56% | 9.09% | [0.049, 0.139] | 27 | 108 | 5 | $0.048290 | 4.44/10.31 |
| MiMo-V2.6-Flash / few-shot | few-shot | 180 | 180 | 100.00% | 9.44% | [0.056, 0.139] | 40 | 117 | 6 | $0.067880 | 4.41/8.55 |
| MiMo-V2.6-Flash / context | context | 180 | 166 | 92.22% | 11.45% | [0.067, 0.165] | 38 | 106 | 3 | $0.049967 | 4.29/9.99 |

**Joint A/B forced binary** (one request per pair; exactly one version must be chosen):

| model | task | pairs | valid | pair DA | 95% CI | correct | swapped | both flagged/clean | USD | p50/p95 s |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| DeepSeek V4.1 Flash / joint A-B forced choice | forced binary | 180 | 180 | 76.67% | [0.706, 0.822] | 138 | 42 | 0 / 0 | $0.153593 | 6.28/8.03 |
| MiMo-V2.6-Flash / joint A-B forced choice | forced binary | 180 | 180 | 86.67% | [0.817, 0.917] | 156 | 24 | 0 / 0 | $0.071803 | 6.11/12.92 |

> **Do not mix the two tables.** The side-wise task allows both/neither and is scored as two independent verdicts.
> The joint task asks for a single A/B choice; its `both`/`neither` categories are structurally impossible.
> A higher joint DA is therefore not evidence that the model is better at the side-wise task.

### 2.4 Pair-joint paired comparisons and audit

These comparisons are **task-change comparisons** and are descriptive only. Direction is `joint - side-wise` or `DeepSeek - MiMo`.

| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |
| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |
| pair joint vs side-wise direct: deepseek | 180 | +65.00 pp | [+57.78, +72.22] pp | +65.00 pp | 118/1 | 3.611e-34 | 7.222e-34 | `A-PAIRJOINT-DEEPSEEK` (m=2) |
| pair joint vs side-wise context: deepseek | 180 | +64.44 pp | [+57.22, +71.67] pp | +64.44 pp | 117/1 | 7.162e-34 | 7.222e-34 | `A-PAIRJOINT-DEEPSEEK` (m=2) |
| pair joint vs side-wise direct: mimo | 154 | +77.27 pp | [+70.78, +83.77] pp | +77.27 pp | 119/0 | 3.009e-36 | 3.009e-36 | `A-PAIRJOINT-MIMO` (m=2) |
| pair joint vs side-wise context: mimo | 166 | +74.10 pp | [+67.47, +80.72] pp | +74.10 pp | 123/0 | 1.881e-37 | 3.762e-37 | `A-PAIRJOINT-MIMO` (m=2) |
| pair joint: DeepSeek - MiMo | 180 | -10.00 pp | [-15.56, -4.44] pp | -10.00 pp | 5/23 | 9.122e-04 | 9.122e-04 | `A-PAIRJOINT-MODEL` (m=1) |

| model | joint DA | length-heuristic DA | vulnerable-in-A DA | vulnerable-in-B DA | selected A |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash / joint A-B forced choice | 76.67% | 74.44% | 92.22% | 61.11% | 65.56% |
| MiMo-V2.6-Flash / joint A-B forced choice | 86.67% | 74.44% | 88.89% | 84.44% | 52.22% |

The length heuristic chooses the shorter function body (tie -> A) without looking at code semantics. If a model is close to this heuristic, its joint DA is not evidence of semantic vulnerability reasoning. DeepSeek's strong A-position bias is visible as a large A-vs-B gap; MiMo's bias is small.

### 2.5 Tier A cost and limitations

- Legacy Tier A runs are derived from `runner/runs/test_v1_*`; they are not new calls. The task cost shown is the detection or pair task only, not the full 2,484-request run (which also includes repair).
- Evidence runs use 160 independent detection requests per model; pair-joint uses 180 joint requests per model.
- Context rows retain the known context artifact: the non-empty context stratum is single-class, so the overall difference cannot be attributed to context reasoning alone.
- Single run per cell; no seed/run-to-run variance.

## 3. Tier B — Juliet CWE-401 (test 140)

All rows below use the same 140 test units (70 bad / 70 good). Static/dynamic rows are traditional tools; LLM and hybrid rows are real API runs. `macro-F1` is valid-only; `strict` counts every non-ok record as wrong. Hybrid rows are **v2** (leak-fixed inputs); v1 is superseded/leakage-sensitive and is not in this table.

### 3.1 Main test-140 table

| method | family | n | valid | coverage | macro-F1 | 95% CI | MCC | strict | P | R | spec | USD | norm $/100u | p50/p95 s |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 140 | 136 | 97.14% | 0.8883 | [0.818, 0.948] | 0.799 | 86.43% | 1.000 | 0.779 | 1.000 | — (local) | — | 0.10/0.14 |
| Cppcheck (Cppcheck 2.21.0) | static | 140 | 140 | 100.00% | 0.5879 | [0.497, 0.671] | 0.331 | 62.86% | 0.846 | 0.314 | 0.943 | — (local) | — | 0.04/0.06 |
| ASan+LSan | dynamic | 140 | 140 | 100.00% | 0.9137 | [0.850, 0.966] | 0.841 | 91.43% | 1.000 | 0.829 | 1.000 | — (local) | — | 2.02/3.42 |
| ASan+LSan+Valgrind (any leak) | dynamic | 140 | 140 | 100.00% | 0.9137 | [0.850, 0.966] | 0.841 | 91.43% | 1.000 | 0.829 | 1.000 | — (local) | — | 2.02/3.42 |
| Valgrind Memcheck | dynamic | 140 | 140 | 100.00% | 0.9137 | [0.850, 0.966] | 0.841 | 91.43% | 1.000 | 0.829 | 1.000 | — (local) | — | 2.02/3.42 |
| DeepSeek V4.1 Flash / direct (no evidence) (Juliet v2) | llm | 140 | 140 | 100.00% | 0.9642 | [0.933, 0.992] | 0.931 | 96.43% | 0.933 | 1.000 | 0.929 | $0.010185 | $0.007275 | 1.72/2.15 |
| MiMo-V2.6-Flash / direct (no evidence) (Juliet v2) | llm | 140 | 140 | 100.00% | 0.9714 | [0.942, 0.993] | 0.944 | 97.14% | 0.946 | 1.000 | 0.943 | $0.004718 | $0.003370 | 3.49/7.62 |
| MiMo-V2.6-Flash / Juliet direct (Xiaomi official, postleakfix) | llm | 140 | 140 | 100.00% | 0.9500 | [0.910, 0.985] | 0.901 | 95.00% | 0.932 | 0.971 | 0.929 | $0.003180 | $0.002272 | 2.57/9.40 |
| DeepSeek V4.1 Flash / static evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9642 | [0.933, 0.992] | 0.931 | 96.43% | 0.933 | 1.000 | 0.929 | $0.011730 | $0.008379 | 1.67/2.07 |
| DeepSeek V4.1 Flash / dynamic evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9714 | [0.942, 0.993] | 0.944 | 97.14% | 0.946 | 1.000 | 0.943 | $0.011471 | $0.008194 | 1.68/2.19 |
| DeepSeek V4.1 Flash / static + dynamic evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9714 | [0.943, 0.993] | 0.944 | 97.14% | 0.946 | 1.000 | 0.943 | $0.011891 | $0.008494 | 1.84/2.25 |
| DeepSeek V4.1 Flash / shuffled placebo evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9571 | [0.925, 0.986] | 0.918 | 95.71% | 0.921 | 1.000 | 0.914 | $0.010860 | $0.007757 | 2.07/2.50 |
| MiMo-V2.6-Flash / static evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9642 | [0.933, 0.992] | 0.931 | 96.43% | 0.933 | 1.000 | 0.929 | $0.006287 | $0.004491 | 3.24/8.90 |
| MiMo-V2.6-Flash / dynamic evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9500 | [0.908, 0.985] | 0.901 | 95.00% | 0.932 | 0.971 | 0.929 | $0.005735 | $0.004096 | 3.33/13.39 |
| MiMo-V2.6-Flash / static + dynamic evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9714 | [0.942, 0.993] | 0.944 | 97.14% | 0.946 | 1.000 | 0.943 | $0.004813 | $0.003438 | 3.41/8.09 |
| MiMo-V2.6-Flash / shuffled placebo evidence (Juliet v2) | hybrid | 140 | 140 | 100.00% | 0.9499 | [0.916, 0.979] | 0.902 | 95.00% | 0.920 | 0.986 | 0.914 | $0.004645 | $0.003318 | 3.49/6.53 |

`macro-F1` here is the two-class macro average, not the positive-class F1 printed in some upstream reports; they can differ by ~0.001–0.002. Local static/dynamic tools have `usd=null` (not zero). Their wall time is local compute; it is not a cloud bill. `Clang SA` has 4 compile errors; they are excluded from valid-only macro-F1 and counted wrong in strict. Dynamic clean means `NO_LEAK_OBSERVED`, not verified safety; the conservative view abstains on clean.

**Dynamic conservative view** (clean is not a true negative):

| dynamic method | clean abstained | valid | coverage | recall | specificity | macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ASan+LSan | 82 | 58 | 41.43% | 100.00% | — | — |
| ASan+LSan+Valgrind (any leak) | 82 | 58 | 41.43% | 100.00% | — | — |
| Valgrind Memcheck | 82 | 58 | 41.43% | 100.00% | — | — |

Abstaining on every clean prediction leaves only the 58 observed-leak bad units, so specificity and macro-F1 are undefined; the operational 0.914 is not a verified safety score.

### 3.2 Hybrid evidence vs direct (same 140 units)

Direction: `method - direct`; positive means the evidence condition is higher. Holm is applied inside each model's four-comparison family.

| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |
| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |
| static - direct: deepseek | 140 | 0.0000 | [0.0000, 0.0000] | +0.00 pp | 0/0 | 1.0000 | 1.0000 | `B-HYBRID-DEEPSEEK` (m=4) |
| dynamic - direct: deepseek | 140 | 0.0072 | [0.0000, 0.0219] | +0.71 pp | 1/0 | 1.0000 | 1.0000 | `B-HYBRID-DEEPSEEK` (m=4) |
| combined - direct: deepseek | 140 | 0.0072 | [0.0000, 0.0221] | +0.71 pp | 1/0 | 1.0000 | 1.0000 | `B-HYBRID-DEEPSEEK` (m=4) |
| shuffled - direct: deepseek | 140 | -0.0072 | [-0.0219, 0.0000] | -0.71 pp | 0/1 | 1.0000 | 1.0000 | `B-HYBRID-DEEPSEEK` (m=4) |
| static - direct: mimo | 140 | -0.0072 | [-0.0219, 0.0000] | -0.71 pp | 0/1 | 1.0000 | 1.0000 | `B-HYBRID-MIMO` (m=4) |
| dynamic - direct: mimo | 140 | -0.0214 | [-0.0573, 0.0000] | -2.14 pp | 0/3 | 0.2500 | 1.0000 | `B-HYBRID-MIMO` (m=4) |
| combined - direct: mimo | 140 | 0.0000 | [-0.0209, 0.0211] | +0.00 pp | 1/1 | 1.0000 | 1.0000 | `B-HYBRID-MIMO` (m=4) |
| shuffled - direct: mimo | 140 | -0.0215 | [-0.0454, 0.0000] | -2.14 pp | 0/3 | 0.2500 | 1.0000 | `B-HYBRID-MIMO` (m=4) |

The combined condition adds one unit over direct for DeepSeek (136 vs 135) and zero for MiMo (136 vs 136); no evidence row survives Holm. The shuffled placebo is the content/length control: it changes aggregate accuracy by at most one unit and flips individual predictions in both directions.

### 3.3 Hybrid combined vs static/dynamic tools

Direction: `combined - tool`; positive means the hybrid is higher. The common-valid cohort excludes static compile errors; strict values include them.

| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |
| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |
| combined - static.clang.sa: deepseek | 136 | 0.0822 | [0.0163, 0.1552] | +8.09 pp | 15/4 | 0.0192 | 0.0768 | `B-HYBRID-VS-TOOLS-DEEPSEEK` (m=5) |
| combined - static.cppcheck: deepseek | 140 | 0.3835 | [0.2952, 0.4827] | +34.29 pp | 52/4 | 1.101e-11 | 5.504e-11 | `B-HYBRID-VS-TOOLS-DEEPSEEK` (m=5) |
| combined - dynamic.asan_lsan: deepseek | 140 | 0.0578 | [-0.0073, 0.1309] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-DEEPSEEK` (m=5) |
| combined - dynamic.valgrind: deepseek | 140 | 0.0578 | [-0.0073, 0.1309] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-DEEPSEEK` (m=5) |
| combined - dynamic.combined: deepseek | 140 | 0.0578 | [-0.0073, 0.1309] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-DEEPSEEK` (m=5) |
| combined - static.clang.sa: mimo | 136 | 0.0822 | [0.0148, 0.1576] | +8.09 pp | 15/4 | 0.0192 | 0.0768 | `B-HYBRID-VS-TOOLS-MIMO` (m=5) |
| combined - static.cppcheck: mimo | 140 | 0.3835 | [0.2976, 0.4792] | +34.29 pp | 52/4 | 1.101e-11 | 5.504e-11 | `B-HYBRID-VS-TOOLS-MIMO` (m=5) |
| combined - dynamic.asan_lsan: mimo | 140 | 0.0578 | [-0.0074, 0.1315] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-MIMO` (m=5) |
| combined - dynamic.valgrind: mimo | 140 | 0.0578 | [-0.0074, 0.1315] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-MIMO` (m=5) |
| combined - dynamic.combined: mimo | 140 | 0.0578 | [-0.0074, 0.1315] | +5.71 pp | 12/4 | 0.0768 | 0.2304 | `B-HYBRID-VS-TOOLS-MIMO` (m=5) |

The hybrid is higher than the tools on macro-F1, but this is a comparison of a 140-unit LLM run against a deterministic tool with 4 compile errors. The static Clang comparison is on 136 common-valid units; the dynamic comparison is on 140.

### 3.4 Placebo and endpoint sensitivity

| comparison | n common | Δ primary | 95% CI | Δ accuracy | b/c | raw p | Holm p | family (m) |
| --- | ---: | ---: | --- | ---: | --- | ---: | ---: | --- |
| MiMo endpoint: Xiaomi official (postleakfix) - OpenCode Go v2 direct | 140 | -0.0214 | [-0.0548, 0.0000] | -2.14 pp | 0/3 | 0.2500 | 0.2500 | `B-ENDPOINT-MIMO` (m=1) |

- `deepseek` placebo: direct 96.43% vs shuffled 95.71%; 1 individual predictions flipped (1 toward vulnerable, 0 toward clean); net accuracy change -0.71 pp.
- `mimo` placebo: direct 97.14% vs shuffled 95.00%; 3 individual predictions flipped (2 toward vulnerable, 1 toward clean); net accuracy change -2.14 pp.

The endpoint row is not a model comparison: both runs use `mimo-v2.6-flash`, but one is Xiaomi official and the other OpenCode Go. It is included to make the serving-stack sensitivity visible; do not read it as a capability difference.

### 3.5 Denominator and coverage ledger

| method | planned | recorded | valid | invalid | coverage | note |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | 140 | 200 | 136 | 4 | 97.14% | 4 compile_error |
| Cppcheck (Cppcheck 2.21.0) | 140 | 200 | 140 | 0 | 100.00% | 0 compile_error |
| ASan+LSan | 140 | 200 | 140 | 0 | 100.00% | operational clean = no leak observed |
| ASan+LSan+Valgrind (any leak) | 140 | 200 | 140 | 0 | 100.00% | operational clean = no leak observed |
| Valgrind Memcheck | 140 | 200 | 140 | 0 | 100.00% | operational clean = no leak observed |
| DeepSeek V4.1 Flash / direct (no evidence) (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / direct (no evidence) (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / Juliet direct (Xiaomi official, postleakfix) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| DeepSeek V4.1 Flash / static evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| DeepSeek V4.1 Flash / dynamic evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| DeepSeek V4.1 Flash / static + dynamic evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| DeepSeek V4.1 Flash / shuffled placebo evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / static evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / dynamic evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / static + dynamic evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |
| MiMo-V2.6-Flash / shuffled placebo evidence (Juliet v2) | 140 | 140 | 140 | 0 | 100.00% | all records valid |

Test-140 denominator: 140 units (70 bad / 70 good). Static Clang's 4 compile errors are non-ok; dynamic clean is operational only; hybrid/LLM have full coverage. The 12 test bad units with no observed LSan leak remain in the primary 140 but are excluded from the runtime-supported 128 sensitivity view.

### 3.6 Tier B cost and limitations

- The hybrid suite is 2 models × 5 methods × 140 = 1,400 real requests; the v2 list-price total is $0.082335 (normalized card equals the configured v2 card).
- MiMo Xiaomi postleakfix is 140 requests; its reference-price total is $0.003180. The Xiaomi endpoint returned no list-cost/allowance fields, so this is a declared-card reference value, not a Xiaomi bill.
- DeepSeek Juliet LLM has no result: OpenCode returned 401 `api_key_expired`, official DeepSeek returned 402 `Insufficient Balance`.
- The test set has a ceiling: v2 direct is already 135/140 (DeepSeek) and 136/140 (MiMo), so the maximum evidence gain is 5/4 units; with 5 discordant pairs the minimum exact McNemar p is 0.0625.
- Juliet is synthetic, single-CWE and template-based; these numbers do not extrapolate to real projects.

## 4. Repair — Juliet CWE-401 bad-only test 70

`strict_pass = compile_pass AND leak_removed AND behavior_preserved AND baseline leak observed`. The denominator is **58 observable units**; the 12 units whose baseline leak was not observable under LSan are excluded, not counted as passes or failures.

| model | planned | observable | strict pass | pass rate | all-70 compile | all-70 leak removed | all-70 behavior | first-attempt | requests | USD | p50/p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| DeepSeek V4.1 Flash / repair (compile + LSan + behaviour) | 70 | 58 | 58 | 100.00% | 70/70 | 70/70 | 70/70 | 58/58 | 70 | $0.026990 | 7.06/13.77 |
| MiMo-V2.6-Flash / repair (compile + LSan + behaviour) | 70 | 58 | 58 | 100.00% | 70/70 | 70/70 | 70/70 | 57/58 | 72 | $0.005841 | 6.93/13.01 |

The 12 excluded units still compile, run LSan-clean and preserve behaviour, but their baseline leak was not observable (7 `malloc_realloc` latent paths and 5 `..._68` still-reachable allocations). They cannot prove leak removal, so they are not in the denominator.

## 5. Unified cost and latency

Two cost bases are reported side by side:

- **recorded list USD** (`cost.usd_known_sum`): the value stored in each run, computed at that run's configured price card.
- **normalized USD** (`cost.normalized.usd_sum`): recomputed from per-record prompt/completion/cached tokens with a fixed provider card (DeepSeek `0.15/0.60/0.003`, MiMo `0.14/0.28/0.0028` USD per 1M input/output/cached tokens). The recorded value is never reused. Unknown usage stays unknown; local tools have no card and therefore `null`, not zero.

| group | runs | requests | known USD | normalized USD | norm $/100u | notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Tier A detection | 8 | 1280 | $0.479568 | $0.299739 | $0.023417 | 160-unit detection rows; normalized card is lower than the legacy 2x configured card |
| Tier A pair side-wise | 6 | 2160 | $0.744192 | $0.455165 | $0.042145 | 180 pairs / 360 side records; each side is a separate request |
| Tier A pair-joint | 2 | 360 | $0.225396 | $0.148600 | $0.041278 | 180 joint requests; one request stored as two side records, token/latency assigned once |
| Tier B hybrid v2 + Xiaomi LLM | 11 | 1540 | $0.085515 | $0.085515 | $0.005553 | 11 API runs; v2 configured card equals the normalized card |
| Tier B local tools | 5 | 700 | — | — | — | local static/dynamic are unpriced, not free |
| Tier B repair | 2 | 142 | $0.032831 | — | — | normalized n/a: no cached-token detail; recorded list USD kept |

### 5.1 Tier B normalized cost per run

| run | requests | recorded USD | normalized USD | norm $/100u | norm $/1000 req | norm $/correct | norm $/TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `tierb_juliet_cwe401_static_clang_20261112_4c5800c4` | 140 | — | — | — | — | — | — |
| `tierb_juliet_cwe401_static_cppcheck_20261112_111a6069` | 140 | — | — | — | — | — | — |
| `tierb_juliet_cwe401_dynamic_asan_20261111_a1390639` | 140 | — | — | — | — | — | — |
| `tierb_juliet_cwe401_dynamic_combined_20261111_81c38b9b` | 140 | — | — | — | — | — | — |
| `tierb_juliet_cwe401_dynamic_valgrind_20261111_50ce3fc9` | 140 | — | — | — | — | — | — |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_direct_20261112_afa34bfd` | 140 | $0.010185 | $0.010185 | $0.007275 | $0.072752 | $0.000075 | $0.000146 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_direct_20261112_4e7c69e0` | 140 | $0.004718 | $0.004718 | $0.003370 | $0.033700 | $0.000035 | $0.000067 |
| `tierb_juliet_cwe401_llm_mimo_xiaomi_postleakfix_20261112_b1ff6e35` | 140 | $0.003180 | $0.003180 | $0.002272 | $0.022716 | $0.000024 | $0.000047 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_combined_20261112_d87c28d0` | 140 | $0.011891 | $0.011891 | $0.008494 | $0.084936 | $0.000087 | $0.000170 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_dynamic_20261112_37f1d982` | 140 | $0.011471 | $0.011471 | $0.008194 | $0.081937 | $0.000084 | $0.000164 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_shuffled_20261112_67d38de4` | 140 | $0.010860 | $0.010860 | $0.007757 | $0.077570 | $0.000081 | $0.000155 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_static_20261112_89356928` | 140 | $0.011730 | $0.011730 | $0.008379 | $0.083786 | $0.000087 | $0.000168 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_combined_20261112_24938148` | 140 | $0.004813 | $0.004813 | $0.003438 | $0.034379 | $0.000035 | $0.000069 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_dynamic_20261112_700e250e` | 140 | $0.005735 | $0.005735 | $0.004096 | $0.040964 | $0.000043 | $0.000084 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_shuffled_20261112_f84d561a` | 140 | $0.004645 | $0.004645 | $0.003318 | $0.033177 | $0.000035 | $0.000067 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_static_20261112_37ee92a6` | 140 | $0.006287 | $0.006287 | $0.004491 | $0.044907 | $0.000047 | $0.000090 |
| `tierb_juliet_cwe401_repair_deepseek_20261112_b78292cf` | 70 | $0.026990 | — | — | — | — | — |
| `tierb_juliet_cwe401_repair_mimo_20261112_e10a522f` | 72 | $0.005841 | — | — | — | — | — |

Cost is a vector, not a score: API list price, local wall time, and peak RSS are not interchangeable. Local static/dynamic `usd=null` means not priced, not free. Each main table gives p50/p95 request latency; legacy Tier A task rows exclude the repair requests that are included in the original full-run cost. For the MiMo Xiaomi run, normalized USD is a reference-price value: the endpoint returned no list-cost or allowance fields. Repair normalized cost is n/a because the source rows expose aggregate tokens without per-record cached-token detail; its recorded list USD is still shown and is not included in the Tier B normalized total.

## 6. Validation performed

- Canonical runs discovered: **34**; structural validation errors: **0**; superseded runs excluded: **11**.
- All 17 round-2 derived runs were re-imported with `bench_validate.py --jsonschema` and `bench_metrics.py`; each has `validation.json` and `metrics.json`.
- The 10 hybrid runs were replaced by `hybrid_v2` (136/140 combined for both models); the 10 v1 directories and the pre-postleakfix MiMo run were moved to `results/superseded/` without editing their files.
- The 12 original Tier A runs and 5 original Tier B tool runs were re-read, not modified; their validation artifacts are unchanged.
- Paired comparisons use `bench_compare.py` on common-valid units: exact McNemar plus cluster-bootstrap 95% intervals, seed 42, 10,000 resamples.
- The pair-joint runs are stored as two side records per joint request; costs/wall are split 50/50 and tokens/latency are assigned once, so run totals are not double-counted.

## 7. What cannot be claimed

- Tier A and Tier B use different datasets, labels and unit structures; no cross-tier ranking or overall score.
- Pair-joint is a forced binary task; its DA cannot be compared directly with side-wise free-form four-category DA.
- Tier A evidence prompt raises recall but also raises false positives; the FPR test is underpowered (32 negatives).
- Pair-joint length is a strong confound: a character-length heuristic alone reaches 74.44%; DeepSeek is not significantly above it.
- DeepSeek has a strong A-position bias in pair-joint; MiMo does not. The A/B map is balanced but not repeated in reverse order.
- Tier B static Clang has 4 compile errors in test 140; valid-only macro-F1 excludes them and strict counts them wrong.
- Dynamic clean is NO_LEAK_OBSERVED, not a verified true negative; the conservative view abstains on clean.
- Hybrid v2 evidence gains over direct are at most one unit per model and are not significant after Holm; the shuffled placebo is used as the length/content control.
- Hybrid v1 is leakage-sensitive (six good units still showed the literal 'Benign, fixed string') and is excluded from every main table; only v2 is canonical.
- The Juliet MiMo LLM result uses the Xiaomi official endpoint (the OpenCode Go fallback), not OpenCode Go; DeepSeek Juliet LLM is unavailable (401/402). Its cost is a reference-price computation because the endpoint returned no billing fields.
- Repair passes are reported only on 58 baseline-observable units; the 12 unobservable units cannot prove leak removal.
- Single run per cell; no seed/run-to-run variance. Cost is list-price computation, not necessarily the actual bill.

## 8. Reproduction

```bash
# WSL, project root
python3 benchmark/tools/selftest.py
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
python3 benchmark/tools/bench_import_round2.py --measure --force
python3 benchmark/tools/bench_final_summary.py
```

## Appendix: run inventory

| run_id | tier | task | method | n | valid | coverage | primary |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| `legacy__test_v1_direct_independent` | A | detection | `llm.deepseek.direct` | 160 | 160 | 100.00% | macro-F1 0.3828 |
| `legacy__test_v1_few-shot_independent` | A | detection | `llm.deepseek.few-shot` | 160 | 160 | 100.00% | macro-F1 0.3995 |
| `legacy__test_v1_context_independent` | A | detection | `llm.deepseek.context` | 160 | 160 | 100.00% | macro-F1 0.3813 |
| `tiera_secvuleval_deepseek_evidence_20261112_0e09037d` | A | detection | `llm.deepseek.evidence` | 160 | 159 | 99.38% | macro-F1 0.4223 |
| `legacy__test_v1_mimo_direct_independent` | A | detection | `llm.mimo.direct` | 160 | 150 | 93.75% | macro-F1 0.3456 |
| `legacy__test_v1_mimo_few-shot_independent` | A | detection | `llm.mimo.few-shot` | 160 | 160 | 100.00% | macro-F1 0.3463 |
| `legacy__test_v1_mimo_context_independent` | A | detection | `llm.mimo.context` | 160 | 153 | 95.62% | macro-F1 0.3650 |
| `tiera_secvuleval_mimo_evidence_20261112_c68dfa50` | A | detection | `llm.mimo.evidence` | 160 | 158 | 98.75% | macro-F1 0.4067 |
| `tiera_secvuleval_deepseek_pair_joint_20261112_8a10a65c` | A | pair_detection | `llm.deepseek.pair_joint_forced_choice` | 180 | 180 | 100.00% | DA 76.67% |
| `tiera_secvuleval_mimo_pair_joint_20261112_9ac69067` | A | pair_detection | `llm.mimo.pair_joint_forced_choice` | 180 | 180 | 100.00% | DA 86.67% |
| `legacy__test_v1_direct_pairs` | A | pair_detection | `llm.deepseek.direct` | 180 | 180 | 100.00% | DA 11.67% |
| `legacy__test_v1_few-shot_pairs` | A | pair_detection | `llm.deepseek.few-shot` | 180 | 180 | 100.00% | DA 8.89% |
| `legacy__test_v1_context_pairs` | A | pair_detection | `llm.deepseek.context` | 180 | 180 | 100.00% | DA 12.22% |
| `legacy__test_v1_mimo_direct_pairs` | A | pair_detection | `llm.mimo.direct` | 180 | 154 | 85.56% | DA 9.09% |
| `legacy__test_v1_mimo_few-shot_pairs` | A | pair_detection | `llm.mimo.few-shot` | 180 | 180 | 100.00% | DA 9.44% |
| `legacy__test_v1_mimo_context_pairs` | A | pair_detection | `llm.mimo.context` | 180 | 166 | 92.22% | DA 11.45% |
| `tierb_juliet_cwe401_static_clang_20261112_4c5800c4` | B | leak_detection | `static.clang.sa` | 140 | 136 | 97.14% | macro-F1 0.8883 |
| `tierb_juliet_cwe401_static_cppcheck_20261112_111a6069` | B | leak_detection | `static.cppcheck` | 140 | 140 | 100.00% | macro-F1 0.5879 |
| `tierb_juliet_cwe401_dynamic_asan_20261111_a1390639` | B | leak_detection | `dynamic.asan_lsan` | 140 | 140 | 100.00% | macro-F1 0.9137 |
| `tierb_juliet_cwe401_dynamic_combined_20261111_81c38b9b` | B | leak_detection | `dynamic.combined` | 140 | 140 | 100.00% | macro-F1 0.9137 |
| `tierb_juliet_cwe401_dynamic_valgrind_20261111_50ce3fc9` | B | leak_detection | `dynamic.valgrind` | 140 | 140 | 100.00% | macro-F1 0.9137 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_direct_20261112_afa34bfd` | B | leak_detection | `llm.deepseek.juliet_direct` | 140 | 140 | 100.00% | macro-F1 0.9642 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_direct_20261112_4e7c69e0` | B | leak_detection | `llm.mimo.juliet_direct` | 140 | 140 | 100.00% | macro-F1 0.9714 |
| `tierb_juliet_cwe401_llm_mimo_xiaomi_postleakfix_20261112_b1ff6e35` | B | leak_detection | `llm.mimo.xiaomi_juliet_direct` | 140 | 140 | 100.00% | macro-F1 0.9500 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_combined_20261112_d87c28d0` | B | leak_detection | `hybrid.deepseek.combined` | 140 | 140 | 100.00% | macro-F1 0.9714 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_dynamic_20261112_37f1d982` | B | leak_detection | `hybrid.deepseek.dynamic` | 140 | 140 | 100.00% | macro-F1 0.9714 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_shuffled_20261112_67d38de4` | B | leak_detection | `hybrid.deepseek.shuffled` | 140 | 140 | 100.00% | macro-F1 0.9571 |
| `tierb_juliet_cwe401_hybrid_v2_deepseek_static_20261112_89356928` | B | leak_detection | `hybrid.deepseek.static` | 140 | 140 | 100.00% | macro-F1 0.9642 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_combined_20261112_24938148` | B | leak_detection | `hybrid.mimo.combined` | 140 | 140 | 100.00% | macro-F1 0.9714 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_dynamic_20261112_700e250e` | B | leak_detection | `hybrid.mimo.dynamic` | 140 | 140 | 100.00% | macro-F1 0.9500 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_shuffled_20261112_f84d561a` | B | leak_detection | `hybrid.mimo.shuffled` | 140 | 140 | 100.00% | macro-F1 0.9499 |
| `tierb_juliet_cwe401_hybrid_v2_mimo_static_20261112_37ee92a6` | B | leak_detection | `hybrid.mimo.static` | 140 | 140 | 100.00% | macro-F1 0.9642 |
| `tierb_juliet_cwe401_repair_deepseek_20261112_b78292cf` | B | repair | `llm.deepseek.repair` | 70 | 58 | 82.86% | strict 58/58 |
| `tierb_juliet_cwe401_repair_mimo_20261112_e10a522f` | B | repair | `llm.mimo.repair` | 70 | 58 | 82.86% | strict 58/58 |

## Appendix B: superseded historical runs (excluded from every main table)

Policy: historical only; never enters a main table, comparison or pooled statistic. Files were moved, not edited; `discover_runs()` skips the whole `superseded/` subtree. Metrics are deliberately withheld here so no retired value can be quoted as a current result.

| run_id | group | method | records | reason |
| --- | --- | --- | ---: | --- |
| `tierb_juliet_cwe401_hybrid_deepseek_combined_20261112_af810db1` | `leakage_sensitive_v1` | DeepSeek V4.1 Flash / static + dynamic evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_deepseek_direct_20261112_5b6df1b7` | `leakage_sensitive_v1` | DeepSeek V4.1 Flash / direct (no evidence) (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_deepseek_dynamic_20261112_c291d723` | `leakage_sensitive_v1` | DeepSeek V4.1 Flash / dynamic evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_deepseek_shuffled_20261112_8675ed5a` | `leakage_sensitive_v1` | DeepSeek V4.1 Flash / shuffled placebo evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_deepseek_static_20261112_4fc5047e` | `leakage_sensitive_v1` | DeepSeek V4.1 Flash / static evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_mimo_combined_20261112_4cdbc26a` | `leakage_sensitive_v1` | MiMo-V2.6-Flash / static + dynamic evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_mimo_direct_20261112_ac7aed7a` | `leakage_sensitive_v1` | MiMo-V2.6-Flash / direct (no evidence) (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_mimo_dynamic_20261112_57314119` | `leakage_sensitive_v1` | MiMo-V2.6-Flash / dynamic evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_mimo_shuffled_20261112_1e33dcfa` | `leakage_sensitive_v1` | MiMo-V2.6-Flash / shuffled placebo evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_hybrid_mimo_static_20261112_45f88228` | `leakage_sensitive_v1` | MiMo-V2.6-Flash / static evidence (Juliet) | 140 | leakage-sensitive v1 inputs: six good units still contained the Juliet label phrase |
| `tierb_juliet_cwe401_llm_mimo_xiaomi_20261112_b41c1d0e` | `pre_postleakfix_harness` | MiMo-V2.6-Flash / Juliet direct (Xiaomi official fallback) | 140 | superseded harness: prompting.py changed before the formal postleakfix run |

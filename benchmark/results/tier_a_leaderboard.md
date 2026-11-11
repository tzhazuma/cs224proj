# Tier A leaderboard: SecVulEval

> **Historical detailed view (12 legacy runs).** The current integrated leaderboard, including evidence and pair-joint, is [`LEADERBOARD.md`](LEADERBOARD.md); machine-readable integrated results are in [`final_summary.json`](final_summary.json).

- dataset: `secvul-split-v1`
- detection SHA-256: `bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8`
- pair SHA-256: `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`
- detection: 160 functions (128 vulnerable / 32 non-vulnerable); pair: 180 pairs / 360 sides
- runs: 12 (DeepSeek and MiMo x direct / few-shot / context x detection / pair)

> Tier A only. These rows are not comparable to Tier B (Juliet). Derived views over frozen `runner/runs/test_v1_*`; no model was re-run and no prediction changed.

## 1. Detection (valid-only, cluster bootstrap by project)

| model | strategy | n | valid | cov | macro-F1 | 95% CI | MCC | strict | recall | spec | task USD | full run USD | p50/p95 s |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| deepseek | direct | 160 | 160 | 1.000 | 0.383 | [0.305, 0.552] | 0.041 | 0.388 | 0.297 | 0.750 | 0.066988 | 0.253340 | 5.65/10.83 |
| deepseek | few-shot | 160 | 160 | 1.000 | 0.399 | [0.305, 0.593] | 0.061 | 0.406 | 0.320 | 0.750 | 0.136741 | 0.429938 | 5.33/9.69 |
| deepseek | context | 160 | 160 | 1.000 | 0.381 | [0.286, 0.560] | 0.020 | 0.388 | 0.305 | 0.719 | 0.070308 | 0.259777 | 5.63/10.71 |
| mimo | direct | 160 | 150 | 0.938 | 0.346 | [0.264, 0.528] | 0.008 | 0.325 | 0.242 | 0.767 | 0.024397 | 0.072601 | 4.59/12.00 |
| mimo | few-shot | 160 | 160 | 1.000 | 0.346 | [0.262, 0.512] | -0.042 | 0.350 | 0.266 | 0.688 | 0.034011 | 0.093808 | 4.51/11.03 |
| mimo | context | 160 | 153 | 0.956 | 0.365 | [0.278, 0.571] | 0.080 | 0.350 | 0.252 | 0.833 | 0.025568 | 0.074962 | 4.31/8.38 |

`task USD` covers the 160 detection requests only; `full run USD` covers all 288 requests including repair. Detection valid-only excludes schema-invalid outputs; `strict` counts them wrong.

## 2. Pair discrimination (valid-only, cluster bootstrap by pair_id)

| model | strategy | pairs | valid | cov | pair DA | 95% CI | DA all | both flagged | both clean | swapped | task USD | p50/p95 s |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| deepseek | direct | 180 | 180 | 1.000 | 0.117 | [0.072, 0.167] | 0.117 | 44 | 113 | 2 | 0.138323 | 5.72/13.82 |
| deepseek | few-shot | 180 | 180 | 1.000 | 0.089 | [0.050, 0.133] | 0.089 | 49 | 113 | 2 | 0.294895 | 5.31/8.38 |
| deepseek | context | 180 | 180 | 1.000 | 0.122 | [0.078, 0.172] | 0.122 | 49 | 108 | 1 | 0.144837 | 5.62/13.13 |
| mimo | direct | 180 | 154 | 0.856 | 0.091 | [0.049, 0.139] | 0.078 | 27 | 108 | 5 | 0.048290 | 4.44/10.31 |
| mimo | few-shot | 180 | 180 | 1.000 | 0.094 | [0.056, 0.139] | 0.094 | 40 | 117 | 6 | 0.067880 | 4.41/8.55 |
| mimo | context | 180 | 166 | 0.922 | 0.114 | [0.067, 0.165] | 0.106 | 38 | 106 | 3 | 0.049967 | 4.29/9.99 |

`pair DA` is the fraction of pairs where the vulnerable side is flagged and the fixed side is clean. `DA all` includes pairs with an invalid side as failures. `swapped` is the reversed-error category.

### 2b. Wilson 95% intervals for proportions

| task | model | strategy | coverage | recall | specificity | pair DA |
| --- | --- | --- | --- | --- | --- | --- |
| detection | deepseek | direct | [0.977, 1.000] | [0.225, 0.381] | [0.579, 0.867] | — |
| detection | deepseek | few-shot | [0.977, 1.000] | [0.246, 0.405] | [0.579, 0.867] | — |
| detection | deepseek | context | [0.977, 1.000] | [0.232, 0.389] | [0.546, 0.844] | — |
| pair | deepseek | direct | [0.979, 1.000] | — | — | [0.078, 0.172] |
| pair | deepseek | few-shot | [0.979, 1.000] | — | — | [0.055, 0.140] |
| pair | deepseek | context | [0.979, 1.000] | — | — | [0.082, 0.178] |
| detection | mimo | direct | [0.889, 0.966] | [0.174, 0.326] | [0.591, 0.882] | — |
| detection | mimo | few-shot | [0.977, 1.000] | [0.197, 0.348] | [0.514, 0.820] | — |
| detection | mimo | context | [0.912, 0.979] | [0.184, 0.335] | [0.664, 0.927] | — |
| pair | mimo | direct | [0.797, 0.899] | — | — | [0.055, 0.147] |
| pair | mimo | few-shot | [0.979, 1.000] | — | — | [0.060, 0.146] |
| pair | mimo | context | [0.874, 0.953] | — | — | [0.075, 0.172] |

Wilson intervals use valid predictions; pair-side recall/specificity are not reported here because the pair run is scored jointly by design.

## 3. Model comparison: DeepSeek vs MiMo (same strategy, same task)

| task | strategy | Δ (DeepSeek − MiMo) | 95% CI | n common | McNemar b/c | raw p | Holm p | Holm family |
| --- | --- | ---: | --- | ---: | --- | ---: | ---: | --- |
| detection | direct | Δ macro-F1 0.031 | [-0.018, 0.077] | 150 | 11/6 | 0.3323 | 0.6646 | `A-MODEL-DETECTION` |
| detection | few-shot | Δ macro-F1 0.053 | [0.010, 0.129] | 160 | 15/6 | 0.0784 | 0.2351 | `A-MODEL-DETECTION` |
| detection | context | Δ macro-F1 0.009 | [-0.070, 0.058] | 153 | 10/8 | 0.8145 | 0.8145 | `A-MODEL-DETECTION` |
| pair | direct | Δ pair DA 0.032 | [-0.013, 0.078] | 154 | 9/4 | 0.2668 | 0.8005 | `A-MODEL-PAIR` |
| pair | few-shot | Δ pair DA -0.006 | [-0.039, 0.028] | 180 | 4/5 | 1.0000 | 1.0000 | `A-MODEL-PAIR` |
| pair | context | Δ pair DA 0.000 | [-0.042, 0.042] | 166 | 6/6 | 1.0000 | 1.0000 | `A-MODEL-PAIR` |

`b/c` are the discordant counts (DeepSeek correct / MiMo correct). Holm is applied inside each task family (m=3). No model difference survives Holm on McNemar. The few-shot detection macro-F1 interval excludes zero, but the secondary McNemar test does not, and this is one run per cell; treat it as suggestive, not a confirmed ranking.

## 4. Within-model strategy comparisons (secondary)

| model | task | comparison | Δ | 95% CI | raw p | Holm p | Holm family |
| --- | --- | --- | ---: | --- | ---: | ---: | --- |
| deepseek | detection | direct vs few-shot | -0.017 | [-0.058, 0.012] | 0.5488 | 1.0000 | `A-STRATEGY-DEEPSEEK-DETECTION` |
| deepseek | detection | direct vs context | 0.001 | [-0.033, 0.036] | 1.0000 | 1.0000 | `A-STRATEGY-DEEPSEEK-DETECTION` |
| deepseek | detection | few-shot vs context | 0.018 | [-0.010, 0.066] | 0.5078 | 1.0000 | `A-STRATEGY-DEEPSEEK-DETECTION` |
| deepseek | pair | direct vs few-shot | 0.028 | [-0.006, 0.067] | 0.2266 | 0.4531 | `A-STRATEGY-DEEPSEEK-PAIR` |
| deepseek | pair | direct vs context | -0.006 | [-0.039, 0.028] | 1.0000 | 1.0000 | `A-STRATEGY-DEEPSEEK-PAIR` |
| deepseek | pair | few-shot vs context | -0.033 | [-0.072, 0.006] | 0.1460 | 0.4380 | `A-STRATEGY-DEEPSEEK-PAIR` |
| mimo | detection | direct vs few-shot | 0.008 | [-0.016, 0.048] | 1.0000 | 1.0000 | `A-STRATEGY-MIMO-DETECTION` |
| mimo | detection | direct vs context | -0.021 | [-0.087, 0.016] | 0.5078 | 1.0000 | `A-STRATEGY-MIMO-DETECTION` |
| mimo | detection | few-shot vs context | -0.028 | [-0.108, 0.014] | 0.4240 | 1.0000 | `A-STRATEGY-MIMO-DETECTION` |
| mimo | pair | direct vs few-shot | -0.013 | [-0.052, 0.019] | 0.7266 | 1.0000 | `A-STRATEGY-MIMO-PAIR` |
| mimo | pair | direct vs context | -0.028 | [-0.069, 0.014] | 0.3438 | 1.0000 | `A-STRATEGY-MIMO-PAIR` |
| mimo | pair | few-shot vs context | -0.018 | [-0.048, 0.006] | 0.3750 | 1.0000 | `A-STRATEGY-MIMO-PAIR` |

These are exploratory/secondary; the pre-registered primary model comparison is §3.

## 5. Model aggregate (descriptive, no pooled unit metric)

| model | detection mean macro-F1 (range) | pair mean DA (range) | mean coverage | full USD | USD / 100 requests | p50/p95 s | requests |
| --- | --- | --- | ---: | ---: | ---: | --- | ---: |
| deepseek | 0.388 (0.381–0.399) | 0.109 (0.089–0.122) | 1.000 | 2.439219 | 0.098197 | 5.50/10.55 | 2484 |
| mimo | 0.352 (0.346–0.365) | 0.100 (0.091–0.114) | 0.945 | 0.623154 | 0.025087 | 4.41/10.13 | 2484 |

Means are across the three strategies, not pooled over units. USD is the sum of the six full runs (2,484 requests including repair); `task USD` in the run tables excludes repair.

## 6. Explicitly not reported

- **Tier A static F1**: pending. The 160 SecVulEval functions are fragments; static tools cannot parse most of them. No compile failure is converted to a zero prediction. A4 remains planned.
- **Round-2 evidence/pair-joint**: not in this historical 12-run file; see `LEADERBOARD.md` §2.
- **Juliet LLM / hybrid / repair**: out of scope for this Tier A historical file; see `LEADERBOARD.md` §3–§4.

## 7. Limitations

- Single run per model/strategy; run-to-run variance is not estimated.
- MiMo uses reasoning_effort=none with max_completion_tokens on OpenCode Go; its decoding/transport differs from DeepSeek's non-thinking max_tokens setup.
- Detection negatives are source-unlabelled, not proven safe; pair fixed sides are also unlabelled.
- CWE-401 has only 3 test functions; no per-CWE claim is made.
- McNemar assumes independent units; project/pair clustering can make p-values anti-conservative, so cluster-bootstrap intervals are the primary evidence.
- Derived runs are read-only views over runner/runs/test_v1_*; they are not new model calls.
- Price snapshots are not identical: DeepSeek prices come from the runner config, MiMo prices were verified on the OpenCode Go page on 2026-11-12.

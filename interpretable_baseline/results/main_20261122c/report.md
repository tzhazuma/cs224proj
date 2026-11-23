# Interpretable non-LLM baselines — Tier A detection (dev40 → test160)

Generated: `2026-11-22T10:42:33.646188+00:00`  
Primary (selected on dev): `rule:length_short`  
Test-tuned numbers are upper bounds, not methods.

## Split isolation

```json
{
  "dev_n": 40,
  "test_n": 160,
  "idx_overlap": 0,
  "project_overlap": [],
  "exact_body_md5_overlap": 0,
  "test_projects": 40
}
```

## Dev-fitted thresholds

```json
{
  "chars": 1504.0,
  "calls": 16.0,
  "prior_positive": true,
  "dev_positive_rate": 0.8
}
```

## Dev rule table (selection only)

| rule | TP | FP | TN | FN | P | R | Spec | macro-F1 | MCC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| prior_majority | 32 | 8 | 0 | 0 | 0.800 | 1.000 | 0.000 | 0.444 | 0.000 |
| length_short | 16 | 4 | 4 | 16 | 0.800 | 0.500 | 0.500 | 0.451 | 0.000 |
| calls_high | 15 | 6 | 2 | 17 | 0.714 | 0.469 | 0.250 | 0.357 | -0.225 |
| alloc_unbalanced | 2 | 1 | 7 | 30 | 0.667 | 0.062 | 0.875 | 0.213 | -0.095 |
| mem_api_present | 10 | 2 | 6 | 22 | 0.833 | 0.312 | 0.750 | 0.394 | 0.055 |
| alloc_or_mem | 10 | 3 | 5 | 22 | 0.769 | 0.312 | 0.625 | 0.365 | -0.053 |
| short_and_alloc_or_mem | 3 | 0 | 8 | 29 | 1.000 | 0.094 | 1.000 | 0.263 | 0.142 |

## Test 160 (valid-only; all baselines have coverage 1.0)

| method | TP | FP | TN | FN | P | R | Spec | macro-F1 [95% CI] | MCC | BA | pred+ |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| rule:prior_majority | 128 | 32 | 0 | 0 | 0.800 | 1.000 | 0.000 | 0.444 [0.412, 0.460] | 0.000 | 0.500 | 1.000 |
| rule:length_short | 75 | 15 | 17 | 53 | 0.833 | 0.586 | 0.531 | 0.511 [0.422, 0.562] | 0.094 | 0.559 | 0.562 |
| rule:calls_high | 53 | 14 | 18 | 75 | 0.791 | 0.414 | 0.562 | 0.416 [0.360, 0.491] | -0.019 | 0.488 | 0.419 |
| rule:alloc_unbalanced | 12 | 0 | 32 | 116 | 1.000 | 0.094 | 1.000 | 0.263 [0.205, 0.352] | 0.142 | 0.547 | 0.075 |
| rule:mem_api_present | 23 | 2 | 30 | 105 | 0.920 | 0.180 | 0.938 | 0.330 [0.250, 0.497] | 0.129 | 0.559 | 0.156 |
| rule:alloc_or_mem | 32 | 2 | 30 | 96 | 0.941 | 0.250 | 0.938 | 0.387 [0.324, 0.530] | 0.183 | 0.594 | 0.212 |
| rule:short_and_alloc_or_mem | 11 | 0 | 32 | 117 | 1.000 | 0.086 | 1.000 | 0.256 [0.208, 0.323] | 0.136 | 0.543 | 0.069 |
| lr_unweighted | 127 | 32 | 0 | 1 | 0.799 | 0.992 | 0.000 | 0.443 [0.411, 0.459] | -0.040 | 0.496 | 0.994 |
| lr_balanced | 59 | 20 | 12 | 69 | 0.747 | 0.461 | 0.375 | 0.391 [0.343, 0.466] | -0.131 | 0.418 | 0.494 |

## LLM reference runs (recomputed; parity with published metrics.json checked)

| run | method | valid | coverage | macro-F1 | MCC | P | R | Spec |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| legacy__test_v1_context_independent | DeepSeek V4.1 Flash / context | 160 | 1.000 | 0.381 | 0.020 | 0.812 | 0.305 | 0.719 |
| legacy__test_v1_direct_independent | DeepSeek V4.1 Flash / direct | 160 | 1.000 | 0.383 | 0.041 | 0.826 | 0.297 | 0.750 |
| tiera_secvuleval_deepseek_evidence_20261112_0e09037d | DeepSeek V4.1 Flash / evidence-lines + counterfactual | 159 | 0.994 | 0.422 | 0.035 | 0.817 | 0.386 | 0.656 |
| legacy__test_v1_few-shot_independent | DeepSeek V4.1 Flash / few-shot | 160 | 1.000 | 0.399 | 0.061 | 0.837 | 0.320 | 0.750 |
| legacy__test_v1_mimo_context_independent | MiMo-V2.6-Flash / context | 153 | 0.956 | 0.365 | 0.080 | 0.861 | 0.252 | 0.833 |
| legacy__test_v1_mimo_direct_independent | MiMo-V2.6-Flash / direct | 150 | 0.938 | 0.346 | 0.008 | 0.806 | 0.242 | 0.767 |
| tiera_secvuleval_mimo_evidence_20261112_c68dfa50 | MiMo-V2.6-Flash / evidence-lines + counterfactual | 158 | 0.988 | 0.407 | 0.013 | 0.810 | 0.370 | 0.645 |
| legacy__test_v1_mimo_few-shot_independent | MiMo-V2.6-Flash / few-shot | 160 | 1.000 | 0.346 | -0.042 | 0.773 | 0.266 | 0.688 |

## Paired comparisons (common-valid; exact McNemar; Holm within each LLM family)

| baseline | LLM | n | Δmacro-F1 [95% CI] | b/c | p | Holm p |
| --- | --- | --- | --- | --- | --- | --- |
| rule:prior_majority | legacy__test_v1_direct_independent | 160 | 0.062 [-0.133, 0.151] | 90/24 | 0.0000 | 0.0000 |
| rule:prior_majority | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | 0.022 [-0.171, 0.133] | 78/21 | 0.0000 | 0.0000 |
| rule:prior_majority | legacy__test_v1_mimo_direct_independent | 150 | 0.099 [-0.113, 0.191] | 91/23 | 0.0000 | 0.0000 |
| rule:length_short | legacy__test_v1_direct_independent | 160 | 0.128 [-0.107, 0.224] | 70/40 | 0.0054 | 0.0381 |
| rule:length_short | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | 0.092 [-0.134, 0.202] | 69/47 | 0.0507 | 0.2029 |
| rule:length_short | legacy__test_v1_mimo_direct_independent | 150 | 0.179 [-0.055, 0.267] | 69/32 | 0.0003 | 0.0021 |
| rule:calls_high | legacy__test_v1_direct_independent | 160 | 0.033 [-0.113, 0.100] | 37/28 | 0.3211 | 0.9633 |
| rule:calls_high | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.009 [-0.161, 0.078] | 31/31 | 1.0000 | 1.0000 |
| rule:calls_high | legacy__test_v1_mimo_direct_independent | 150 | 0.068 [-0.078, 0.138] | 38/24 | 0.0980 | 0.3818 |
| rule:alloc_unbalanced | legacy__test_v1_direct_independent | 160 | -0.119 [-0.269, -0.027] | 16/34 | 0.0153 | 0.0767 |
| rule:alloc_unbalanced | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.157 [-0.311, -0.033] | 18/44 | 0.0013 | 0.0078 |
| rule:alloc_unbalanced | legacy__test_v1_mimo_direct_independent | 150 | -0.100 [-0.233, -0.020] | 14/27 | 0.0596 | 0.3575 |
| rule:mem_api_present | legacy__test_v1_direct_independent | 160 | -0.053 [-0.121, 0.026] | 16/25 | 0.2110 | 0.8441 |
| rule:mem_api_present | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.090 [-0.150, -0.012] | 15/32 | 0.0186 | 0.0931 |
| rule:mem_api_present | legacy__test_v1_mimo_direct_independent | 150 | -0.021 [-0.073, 0.042] | 12/15 | 0.7011 | 1.0000 |
| rule:alloc_or_mem | legacy__test_v1_direct_independent | 160 | 0.005 [-0.075, 0.076] | 23/23 | 1.0000 | 1.0000 |
| rule:alloc_or_mem | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.032 [-0.115, 0.058] | 21/29 | 0.3222 | 0.9667 |
| rule:alloc_or_mem | legacy__test_v1_mimo_direct_independent | 150 | 0.028 [-0.030, 0.083] | 19/15 | 0.6076 | 1.0000 |
| rule:short_and_alloc_or_mem | legacy__test_v1_direct_independent | 160 | -0.127 [-0.276, -0.055] | 15/34 | 0.0094 | 0.0564 |
| rule:short_and_alloc_or_mem | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.165 [-0.312, -0.074] | 18/45 | 0.0009 | 0.0063 |
| rule:short_and_alloc_or_mem | legacy__test_v1_mimo_direct_independent | 150 | -0.092 [-0.234, -0.029] | 14/26 | 0.0807 | 0.3818 |
| lr_unweighted | legacy__test_v1_direct_independent | 160 | 0.060 [-0.133, 0.150] | 89/24 | 0.0000 | 0.0000 |
| lr_unweighted | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | 0.020 [-0.171, 0.132] | 78/22 | 0.0000 | 0.0000 |
| lr_unweighted | legacy__test_v1_mimo_direct_independent | 150 | 0.097 [-0.113, 0.190] | 90/23 | 0.0000 | 0.0000 |
| lr_balanced | legacy__test_v1_direct_independent | 160 | 0.008 [-0.149, 0.088] | 40/31 | 0.3425 | 0.9633 |
| lr_balanced | tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 159 | -0.033 [-0.191, 0.062] | 36/36 | 1.0000 | 1.0000 |
| lr_balanced | legacy__test_v1_mimo_direct_independent | 150 | 0.056 [-0.113, 0.138] | 44/28 | 0.0764 | 0.3818 |

## Test-tuned upper bound (NOT a method)

| feature | direction | threshold | macro-F1 | MCC | R | Spec |
| --- | --- | --- | --- | --- | --- | --- |
| chars | <= | 3973.0 | 0.565 | 0.130 | 0.844 | 0.281 |
| calls | <= | 29.0 | 0.552 | 0.105 | 0.797 | 0.312 |
| alloc_minus_free | >= | 0.0 | 0.462 | -0.016 | 0.961 | 0.031 |
| mem_api | <= | 4.0 | 0.471 | 0.046 | 0.984 | 0.031 |
| branch_density | <= | 0.2 | 0.575 | 0.150 | 0.836 | 0.312 |
| call_density | >= | 0.2 | 0.598 | 0.209 | 0.766 | 0.469 |

Rule-family oracle: `rule:length_short` macro-F1 = 0.511 (MCC 0.094).

LR upper bounds: in-sample unweighted macro-F1 = 0.444, in-sample balanced = 0.538, 5-fold CV balanced = 0.502.

LLM confidence-threshold oracle (test-tuned; upper bound only):

| run | threshold | macro-F1 | MCC | R | Spec | n scored |
| --- | --- | --- | --- | --- | --- | --- |
| legacy__test_v1_context_independent | 0.60 | 0.526 | 0.180 | 0.984 | 0.094 | 160 |
| legacy__test_v1_direct_independent | 0.70 | 0.455 | 0.019 | 0.492 | 0.531 | 160 |
| tiera_secvuleval_deepseek_evidence_20261112_0e09037d | 0.70 | 0.445 | -0.073 | 0.598 | 0.312 | 159 |
| legacy__test_v1_few-shot_independent | 0.75 | 0.522 | 0.148 | 0.977 | 0.094 | 160 |
| legacy__test_v1_mimo_context_independent | 0.75 | 0.513 | 0.155 | 0.528 | 0.667 | 153 |
| legacy__test_v1_mimo_direct_independent | 0.75 | 0.493 | 0.000 | 0.700 | 0.300 | 150 |
| tiera_secvuleval_mimo_evidence_20261112_c68dfa50 | 0.75 | 0.496 | 0.027 | 0.646 | 0.387 | 158 |
| legacy__test_v1_mimo_few-shot_independent | 0.90 | 0.503 | 0.150 | 0.500 | 0.688 | 160 |

## Error analysis

Length quartile thresholds: `[560.75, 1329.0, 2844.75]`.

Primary baseline vs DeepSeek direct by length quartile:

| quartile | n | pos | rule R | rule Spec | rule macro-F1 | LLM R | LLM Spec | LLM macro-F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Q1_shortest | 40 | 33 | 1.000 | 0.000 | 0.452 | 0.091 | 1.000 | 0.242 |
| Q2 | 40 | 32 | 1.000 | 0.000 | 0.444 | 0.250 | 1.000 | 0.400 |
| Q3 | 40 | 34 | 0.294 | 1.000 | 0.394 | 0.324 | 0.500 | 0.323 |
| Q4_longest | 40 | 29 | 0.000 | 1.000 | 0.216 | 0.552 | 0.545 | 0.520 |

Top projects by test count (descriptive; n is small):

| project | n | pos | rule R | rule Spec | LLM R | LLM Spec |
| --- | --- | --- | --- | --- | --- | --- |
| linux | 52 | 43 | 0.721 | 0.333 | 0.209 | 0.778 |
| Chrome | 31 | 28 | 0.714 | 0.333 | 0.107 | 1.000 |
| tensorflow | 7 | 5 | 0.400 | 0.500 | 0.200 | 1.000 |
| Android | 6 | 4 | 0.250 | 1.000 | 0.500 | 1.000 |
| vim | 5 | 2 | 0.500 | 0.667 | 0.000 | 1.000 |

LLM FN caught by each rule (DeepSeek direct):

| rule | LLM FN | rule positive | caught |
| --- | --- | --- | --- |
| rule:prior_majority | 90 | 90 | 100.00% |
| rule:length_short | 90 | 62 | 68.89% |
| rule:calls_high | 90 | 34 | 37.78% |
| rule:alloc_unbalanced | 90 | 8 | 8.89% |
| rule:mem_api_present | 90 | 9 | 10.00% |
| rule:alloc_or_mem | 90 | 16 | 17.78% |
| rule:short_and_alloc_or_mem | 90 | 7 | 7.78% |
| lr_unweighted | 90 | 89 | 98.89% |
| lr_balanced | 90 | 38 | 42.22% |

Rationale keyword rates (DeepSeek direct):

| keyword | TP rate | FN rate | TP n | FN n |
| --- | --- | --- | --- | --- |
| no_clear_evidence | 7.89% | 76.67% | 38 | 90 |
| memory_safety | 81.58% | 97.78% | 38 | 90 |
| validation | 76.32% | 66.67% | 38 | 90 |
| safe_claim | 0.00% | 8.89% | 38 | 90 |


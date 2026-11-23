# CodeQL triage comparison — mimo-v2.6-flash-xiaomi-v1

Run: `codeql_triage/runs/test140_mimo_xiaomi_v1`  
Units: 140 (bad 70 / good 70)  
Primary policy: keep a CodeQL alert unless the model explicitly says `false_positive`; `uncertain` and invalid output fall back to keeping/CodeQL.

## Main table (all 140, strict)

| policy | TP | FP | TN | FN | P | R | F1(V) | macro-F1 | MCC | accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8447 | 0.8173 | 0.6739 | 0.8214 |
| direct (strict) | 69 | 5 | 65 | 1 | 0.9324 | 0.9857 | 0.9583 | 0.9571 | 0.9158 | 0.9571 |
| triage keep (primary) | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8971 | 0.8999 | 0.8013 | 0.9000 |
| triage keep + evidence gate | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8971 | 0.8999 | 0.8013 | 0.9000 |
| triage drop uncertain | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8971 | 0.8999 | 0.8013 | 0.9000 |
| triage v2 + consistency verify | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8971 | 0.8999 | 0.8013 | 0.9000 |
| triage v2 + text consistency rule | 61 | 1 | 69 | 9 | 0.9839 | 0.8714 | 0.9242 | 0.9283 | 0.8628 | 0.9286 |
| cascade: verified alert + direct on no-alert | 63 | 7 | 63 | 7 | 0.9000 | 0.9000 | 0.9000 | 0.9000 | 0.8000 | 0.9000 |
| verified leak-present | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8971 | 0.8999 | 0.8013 | 0.9000 |
| hybrid leak-present | 63 | 5 | 65 | 7 | 0.9265 | 0.9000 | 0.9130 | 0.9143 | 0.8289 | 0.9143 |
| hybrid OR | 63 | 6 | 64 | 7 | 0.9130 | 0.9000 | 0.9065 | 0.9071 | 0.8144 | 0.9071 |
| hybrid AND | 61 | 4 | 66 | 9 | 0.9385 | 0.8714 | 0.9037 | 0.9070 | 0.8164 | 0.9071 |
| query: never-freed only | 46 | 0 | 70 | 24 | 1.0000 | 0.6571 | 0.7931 | 0.8234 | 0.6995 | 0.8286 |
| rule: drop C++ may-not-be-freed | 60 | 0 | 70 | 10 | 1.0000 | 0.8571 | 0.9231 | 0.9282 | 0.8660 | 0.9286 |

`triage drop uncertain` is a sensitivity analysis, not the primary policy. `query: never-freed only` and `rule: drop C++ may-not-be-freed` are zero-cost baselines.

## Coverage and subsets

- CodeQL analyzable: 136/140 (0.9714)
- Triage API valid: 140/140 (1.0000)
- Decisive triage verdicts among the 91 CodeQL alerts: 1.0000
- Direct API valid: 1.0000

| subset | n | CodeQL TP/FP | direct correct | triage keep TP/FP | triage dropped TP | triage dropped FP |
| --- | ---: | --- | ---: | --- | ---: | ---: |
| all test | 140 | 68/23 | 134/140 | 61/5 | 7 | 18 |
| CodeQL compile_error | 4 | 0/0 | 4/4 | 0/0 | 0 | 0 |
| CodeQL ok | 136 | 68/23 | 130/136 | 61/5 | 7 | 18 |
| CodeQL FP (23) | 23 | 0/23 | 20/23 | 0/5 | 0 | 18 |
| CodeQL TP (68) | 68 | 68/0 | 67/68 | 61/0 | 7 | 0 |
| CodeQL FN (2) | 2 | 0/0 | 2/2 | 0/0 | 0 | 0 |

## Paired tests

| comparison | left macro-F1 | right macro-F1 | delta | bootstrap 95% CI | McNemar p |
| --- | ---: | ---: | ---: | --- | ---: |
| triage_vs_codeql | 0.8173 | 0.8999 | +0.0826 | [+0.0158, +0.1531] | 0.043285 |
| triage_vs_direct | 0.9571 | 0.8999 | -0.0572 | [-0.1071, -0.0141] | 0.038574 |
| verified_vs_codeql | 0.8173 | 0.8999 | +0.0826 | [+0.0158, +0.1531] | 0.043285 |
| verified_vs_direct | 0.9571 | 0.8999 | -0.0572 | [-0.1071, -0.0141] | 0.038574 |
| verified_vs_triage | 0.8999 | 0.8999 | +0.0000 | [+0.0000, +0.0000] | 1.000000 |
| text_rule_vs_verified | 0.8999 | 0.9283 | +0.0284 | [+0.0071, +0.0576] | 0.125000 |
| cascade_vs_verified | 0.8999 | 0.9000 | +0.0001 | [-0.0285, +0.0285] | 1.000000 |
| direct_vs_codeql | 0.8173 | 0.9571 | +0.1398 | [+0.0738, +0.2110] | 0.000157 |
| drop_may_cpp_vs_direct | 0.9571 | 0.9282 | -0.0289 | [-0.0857, +0.0280] | 0.454498 |
| hybrid_vs_direct | 0.9571 | 0.9143 | -0.0428 | [-0.0854, -0.0071] | 0.070312 |

## CodeQL confusion (end-to-end, all 140)

TP/FP/TN/FN = 68/23/47/2; P=0.7473, R=0.9714, macro-F1=0.8173, MCC=0.6739.

# CodeQL triage comparison — mimo-v2.6-flash-xiaomi-v2

Run: `codeql_triage/runs/test140_mimo_xiaomi_v2`  
Units: 140 (bad 70 / good 70)  
Primary policy: keep a CodeQL alert unless the model explicitly says `false_positive`; `uncertain` and invalid output fall back to keeping/CodeQL.

## Main table (all 140, strict)

| policy | TP | FP | TN | FN | P | R | F1(V) | macro-F1 | MCC | accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8447 | 0.8173 | 0.6739 | 0.8214 |
| direct (strict) | 69 | 5 | 65 | 1 | 0.9324 | 0.9857 | 0.9583 | 0.9571 | 0.9158 | 0.9571 |
| triage keep (primary) | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9645 | 0.9643 | 0.9287 | 0.9643 |
| triage keep + evidence gate | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9645 | 0.9643 | 0.9287 | 0.9643 |
| triage drop uncertain | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9645 | 0.9643 | 0.9287 | 0.9643 |
| triage v2 + consistency verify | 68 | 0 | 70 | 2 | 1.0000 | 0.9714 | 0.9855 | 0.9857 | 0.9718 | 0.9857 |
| triage v2 + text consistency rule | 68 | 0 | 70 | 2 | 1.0000 | 0.9714 | 0.9855 | 0.9857 | 0.9718 | 0.9857 |
| cascade: verified alert + direct on no-alert | 70 | 2 | 68 | 0 | 0.9722 | 1.0000 | 0.9859 | 0.9857 | 0.9718 | 0.9857 |
| verified leak-present | 68 | 0 | 70 | 2 | 1.0000 | 0.9714 | 0.9855 | 0.9857 | 0.9718 | 0.9857 |
| hybrid leak-present | 70 | 10 | 60 | 0 | 0.8750 | 1.0000 | 0.9333 | 0.9282 | 0.8660 | 0.9286 |
| hybrid OR | 70 | 10 | 60 | 0 | 0.8750 | 1.0000 | 0.9333 | 0.9282 | 0.8660 | 0.9286 |
| hybrid AND | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9645 | 0.9643 | 0.9287 | 0.9643 |
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
| all test | 140 | 68/23 | 134/140 | 68/3 | 0 | 20 |
| CodeQL compile_error | 4 | 0/0 | 4/4 | 0/0 | 0 | 0 |
| CodeQL ok | 136 | 68/23 | 130/136 | 68/3 | 0 | 20 |
| CodeQL FP (23) | 23 | 0/23 | 20/23 | 0/3 | 0 | 20 |
| CodeQL TP (68) | 68 | 68/0 | 67/68 | 68/0 | 0 | 0 |
| CodeQL FN (2) | 2 | 0/0 | 2/2 | 0/0 | 0 | 0 |

## Paired tests

| comparison | left macro-F1 | right macro-F1 | delta | bootstrap 95% CI | McNemar p |
| --- | ---: | ---: | ---: | --- | ---: |
| triage_vs_codeql | 0.8173 | 0.9643 | +0.1470 | [+0.0908, +0.2097] | 0.000002 |
| triage_vs_direct | 0.9571 | 0.9643 | +0.0072 | [-0.0217, +0.0375] | 1.000000 |
| verified_vs_codeql | 0.8173 | 0.9857 | +0.1684 | [+0.1084, +0.2349] | 0.000000 |
| verified_vs_direct | 0.9571 | 0.9857 | +0.0286 | [-0.0072, +0.0714] | 0.289062 |
| verified_vs_triage | 0.9643 | 0.9857 | +0.0214 | [+0.0000, +0.0500] | 0.250000 |
| text_rule_vs_verified | 0.9857 | 0.9857 | +0.0000 | [+0.0000, +0.0000] | 1.000000 |
| cascade_vs_verified | 0.9857 | 0.9857 | +0.0000 | [-0.0287, +0.0287] | 1.000000 |
| direct_vs_codeql | 0.8173 | 0.9571 | +0.1398 | [+0.0738, +0.2110] | 0.000157 |
| drop_may_cpp_vs_direct | 0.9571 | 0.9282 | -0.0289 | [-0.0857, +0.0280] | 0.454498 |
| hybrid_vs_direct | 0.9571 | 0.9282 | -0.0289 | [-0.0713, +0.0073] | 0.289062 |

## CodeQL confusion (end-to-end, all 140)

TP/FP/TN/FN = 68/23/47/2; P=0.7473, R=0.9714, macro-F1=0.8173, MCC=0.6739.

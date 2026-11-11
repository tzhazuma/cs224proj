# Tier B leaderboard: Juliet CWE-401

> **Historical detailed view (5 traditional-tool runs).** The current integrated leaderboard, including the Juliet LLM postleakfix run, the 1,400-request hybrid v2 suite and repair, is [`LEADERBOARD.md`](LEADERBOARD.md); machine-readable integrated results are in [`final_summary.json`](final_summary.json).

- dataset: `juliet-cwe401-v1.3-subset-v1`
- units SHA-256: `4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24`
- frozen units: 200 (dev 60 / test 140), 100 groups, 42 families
- primary view: `test_all` (test 140, frozen labels)
- primary runtime view: `test_runtime` (test 128)
- generated: `2026-11-11T20:26:36Z`

> Tier B only. Do not pool these rows with Tier A (SecVulEval) or rank across tiers.

## 1. Primary: test 140, frozen Juliet labels

| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 140 | 136 | 0.971 | 53 | 0 | 68 | 15 | 1.000 | 0.779 | 1.000 | 0.888 | [0.818, 0.948] | 0.799 | 0.864 | 4/0 | 0.1179 | 102.4/139.5 |
| Cppcheck (Cppcheck 2.21.0) | static | 140 | 140 | 1.000 | 22 | 4 | 66 | 48 | 0.846 | 0.314 | 0.943 | 0.588 | [0.497, 0.671] | 0.331 | 0.629 | 0/0 | 0.0457 | 44.8/61.8 |
| ASan+LSan | dynamic | 140 | 140 | 1.000 | 58 | 0 | 70 | 12 | 1.000 | 0.829 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0/0 | 2.1982 | 2018.0/3418.5 |
| ASan+LSan+Valgrind (any leak) | dynamic | 140 | 140 | 1.000 | 58 | 0 | 70 | 12 | 1.000 | 0.829 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0/0 | 2.1982 | 2018.0/3418.5 |
| Valgrind Memcheck | dynamic | 140 | 140 | 1.000 | 58 | 0 | 70 | 12 | 1.000 | 0.829 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 | 0/0 | 2.1982 | 2018.0/3418.5 |

`compile/inconcl` is the count of `compile_error` / `inconclusive` records in the view.
`macro-F1` is valid-only; `strict` counts every non-ok record as wrong. Static compile failures are in the denominator of `strict` but not of `macro-F1`, and are never rewritten as `y_pred=0`.
Dynamic rows use the operational reading `clean = NO_LEAK_OBSERVED`; §3 gives the conservative view where clean is abstained.
The static adapter's raw `end_to_end` view counts compile errors as 'no leak observed'; canonical `strict` counts them wrong. They are different views and must not be compared directly.

### 1b. Wilson 95% intervals for proportions (test 140)

| method | coverage | recall | specificity |
| --- | --- | --- | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | [0.929, 0.989] | [0.667, 0.862] | [0.947, 1.000] |
| Cppcheck (Cppcheck 2.21.0) | [0.973, 1.000] | [0.218, 0.430] | [0.862, 0.978] |
| ASan+LSan | [0.973, 1.000] | [0.724, 0.899] | [0.948, 1.000] |
| ASan+LSan+Valgrind (any leak) | [0.973, 1.000] | [0.724, 0.899] | [0.948, 1.000] |
| Valgrind Memcheck | [0.973, 1.000] | [0.724, 0.899] | [0.948, 1.000] |

Wilson intervals use valid predictions; specificity is undefined when no negative-class unit is valid.

## 2. Primary sensitivity: test 128, runtime-supported labels

Runtime-supported means bad units with an observed LSan leak, plus good units with no observed leak. The 12 test bad units without an observed leak are excluded here but remain in the primary table.

| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 128 | 124 | 0.969 | 46 | 0 | 68 | 10 | 1.000 | 0.821 | 1.000 | 0.917 | [0.842, 0.975] | 0.846 | 0.891 | 4/0 | 0.1196 | 102.6/142.7 |
| Cppcheck (Cppcheck 2.21.0) | static | 128 | 128 | 1.000 | 15 | 4 | 66 | 43 | 0.789 | 0.259 | 0.943 | 0.564 | [0.481, 0.635] | 0.282 | 0.633 | 0/0 | 0.0458 | 44.1/63.3 |
| ASan+LSan | dynamic | 128 | 128 | 1.000 | 58 | 0 | 70 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 0/0 | 2.2084 | 2018.0/3424.5 |
| ASan+LSan+Valgrind (any leak) | dynamic | 128 | 128 | 1.000 | 58 | 0 | 70 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 0/0 | 2.2084 | 2018.0/3424.5 |
| Valgrind Memcheck | dynamic | 128 | 128 | 1.000 | 58 | 0 | 70 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | [1.000, 1.000] | 1.000 | 1.000 | 0/0 | 2.2084 | 2018.0/3424.5 |

> The runtime-supported population is defined by an LSan preflight. ASan/LSan scores on this subset are largely circular; Valgrind and static numbers are the informative ones.

## 3. Dynamic conservative view (clean abstained)

The dynamic run has no line/branch coverage instrumentation. A clean prediction is `NO_LEAK_OBSERVED`, not proof of safety. This view abstains on every clean prediction; negative-class units leave the valid set, so macro-F1 is undefined. Recall and precision remain detection-only, not a safety score.

| method | view | n | valid | cov | TP | FP | FN | recall | precision | clean abstained | macro-F1 | policy |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| ASan+LSan | `test_all` | 140 | 58 | 0.414 | 58 | 0 | 0 | 1.000 | 1.000 | 82 | — | clean=no-leak-observed, not TN |
| ASan+LSan+Valgrind (any leak) | `test_all` | 140 | 58 | 0.414 | 58 | 0 | 0 | 1.000 | 1.000 | 82 | — | clean=no-leak-observed, not TN |
| Valgrind Memcheck | `test_all` | 140 | 58 | 0.414 | 58 | 0 | 0 | 1.000 | 1.000 | 82 | — | clean=no-leak-observed, not TN |
| ASan+LSan | `test_runtime` | 128 | 58 | 0.453 | 58 | 0 | 0 | 1.000 | 1.000 | 70 | — | clean=no-leak-observed, not TN |
| ASan+LSan+Valgrind (any leak) | `test_runtime` | 128 | 58 | 0.453 | 58 | 0 | 0 | 1.000 | 1.000 | 70 | — | clean=no-leak-observed, not TN |
| Valgrind Memcheck | `test_runtime` | 128 | 58 | 0.453 | 58 | 0 | 0 | 1.000 | 1.000 | 70 | — | clean=no-leak-observed, not TN |

## 4. Reference: all 200 frozen units

| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 200 | 194 | 0.970 | 73 | 0 | 97 | 24 | 1.000 | 0.753 | 1.000 | 0.874 | — | 0.777 | 0.850 | 6/0 | 0.1180 | 103.5/139.4 |
| Cppcheck (Cppcheck 2.21.0) | static | 200 | 200 | 1.000 | 30 | 4 | 96 | 70 | 0.882 | 0.300 | 0.960 | 0.585 | — | 0.346 | 0.630 | 0/0 | 0.0448 | 43.6/61.1 |
| ASan+LSan | dynamic | 200 | 199 | 0.995 | 77 | 0 | 100 | 22 | 1.000 | 0.778 | 1.000 | 0.888 | — | 0.798 | 0.885 | 0/1 | 2.1935 | 2036.0/3432.9 |
| ASan+LSan+Valgrind (any leak) | dynamic | 200 | 200 | 1.000 | 78 | 0 | 100 | 22 | 1.000 | 0.780 | 1.000 | 0.889 | — | 0.800 | 0.890 | 0/0 | 2.1935 | 2036.0/3432.9 |
| Valgrind Memcheck | dynamic | 200 | 200 | 1.000 | 78 | 0 | 100 | 22 | 1.000 | 0.780 | 1.000 | 0.889 | — | 0.800 | 0.890 | 0/0 | 2.1935 | 2036.0/3432.9 |

## 5. Reference: all 178 runtime-supported units

| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 178 | 172 | 0.966 | 58 | 0 | 97 | 17 | 1.000 | 0.773 | 1.000 | 0.896 | — | 0.811 | 0.871 | 6/0 | 0.1208 | 104.0/142.5 |
| Cppcheck (Cppcheck 2.21.0) | static | 178 | 178 | 1.000 | 15 | 4 | 96 | 63 | 0.789 | 0.192 | 0.960 | 0.525 | — | 0.245 | 0.624 | 0/0 | 0.0449 | 43.1/61.2 |
| ASan+LSan | dynamic | 178 | 177 | 0.994 | 77 | 0 | 100 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | — | 1.000 | 0.994 | 0/1 | 2.2225 | 2047.5/3543.4 |
| ASan+LSan+Valgrind (any leak) | dynamic | 178 | 178 | 1.000 | 78 | 0 | 100 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | — | 1.000 | 1.000 | 0/0 | 2.2225 | 2047.5/3543.4 |
| Valgrind Memcheck | dynamic | 178 | 178 | 1.000 | 78 | 0 | 100 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | — | 1.000 | 1.000 | 0/0 | 2.2225 | 2047.5/3543.4 |

## 6. Reference: dev 60 (not a test set)

| method | family | n | valid | cov | TP | FP | TN | FN | P | R | spec | macro-F1 | 95% CI | MCC | strict | compile/inconcl | wall/unit s | p50/p95 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- | ---: | --- |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | static | 60 | 58 | 0.967 | 20 | 0 | 29 | 9 | 1.000 | 0.690 | 1.000 | 0.841 | — | 0.725 | 0.817 | 2/0 | 0.1182 | 107.7/138.6 |
| Cppcheck (Cppcheck 2.21.0) | static | 60 | 60 | 1.000 | 8 | 0 | 30 | 22 | 1.000 | 0.267 | 1.000 | 0.576 | — | 0.392 | 0.633 | 0/0 | 0.0427 | 41.9/54.9 |
| ASan+LSan | dynamic | 60 | 59 | 0.983 | 19 | 0 | 30 | 10 | 1.000 | 0.655 | 1.000 | 0.824 | — | 0.701 | 0.817 | 0/1 | 2.1827 | 2057.5/3673.8 |
| ASan+LSan+Valgrind (any leak) | dynamic | 60 | 60 | 1.000 | 20 | 0 | 30 | 10 | 1.000 | 0.667 | 1.000 | 0.829 | — | 0.707 | 0.833 | 0/0 | 2.1827 | 2057.5/3673.8 |
| Valgrind Memcheck | dynamic | 60 | 60 | 1.000 | 20 | 0 | 30 | 10 | 1.000 | 0.667 | 1.000 | 0.829 | — | 0.707 | 0.833 | 0/0 | 2.1827 | 2057.5/3673.8 |

## 7. Exclusions and denominators

| method | test n | valid | compile_error | inconclusive | timeout | tool_error | coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | 140 | 136 | 4 | 0 | 0 | 0 | 0.971 |
| Cppcheck (Cppcheck 2.21.0) | 140 | 140 | 0 | 0 | 0 | 0 | 1.000 |
| ASan+LSan | 140 | 140 | 0 | 0 | 0 | 0 | 1.000 |
| ASan+LSan+Valgrind (any leak) | 140 | 140 | 0 | 0 | 0 | 0 | 1.000 |
| Valgrind Memcheck | 140 | 140 | 0 | 0 | 0 | 0 | 1.000 |

## 8. Cost and latency

Local static/dynamic tools have `usd=null` and `cost_basis=local_compute`; they are not priced at zero. Wall time is per analysed unit from the source run, not a cloud bill.

| method | view | wall total s | wall/unit s | p50 ms | p95 ms |
| --- | --- | ---: | ---: | ---: | ---: |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | `test_all` | 16.50 | 0.1179 | 102.4 | 139.5 |
| Clang Static Analyzer (Ubuntu clang version 22.1.8 (1ubuntu1)) | `test_runtime` | 15.31 | 0.1196 | 102.6 | 142.7 |
| Cppcheck (Cppcheck 2.21.0) | `test_all` | 6.40 | 0.0457 | 44.8 | 61.8 |
| Cppcheck (Cppcheck 2.21.0) | `test_runtime` | 5.86 | 0.0458 | 44.1 | 63.3 |
| ASan+LSan | `test_all` | 307.75 | 2.1982 | 2018.0 | 3418.5 |
| ASan+LSan | `test_runtime` | 282.67 | 2.2084 | 2018.0 | 3424.5 |
| ASan+LSan+Valgrind (any leak) | `test_all` | 307.75 | 2.1982 | 2018.0 | 3418.5 |
| ASan+LSan+Valgrind (any leak) | `test_runtime` | 282.67 | 2.2084 | 2018.0 | 3424.5 |
| Valgrind Memcheck | `test_all` | 307.75 | 2.1982 | 2018.0 | 3418.5 |
| Valgrind Memcheck | `test_runtime` | 282.67 | 2.2084 | 2018.0 | 3424.5 |

## 9. Pending methods (no numbers)

| slot | method | status | reason |
| --- | --- | --- | --- |
| B4 | DeepSeek sanitized function view | `blocked_gate` | OpenCode 401 / official 402; no result |
| B5 | MiMo sanitized function view | `out_of_scope_here` | Xiaomi official postleakfix result is in the final summary |
| B6 | H1 static evidence + LLM | `out_of_scope_here` | done in final summary |
| B7 | H2 dynamic evidence + LLM | `out_of_scope_here` | done in final summary |
| B8 | H3 static -> dynamic -> LLM cascade | `planned` | not run |
| B9 | leakage audit | `partial` | sanitizer/prompt audit passed; label-only baseline not run |
| A4 | Tier A static feasibility | `planned` | 160 fragment functions; existing 3-snippet smoke is not a benchmark |

## 10. What is not here

- This historical tool does not include round-2 LLM/hybrid/repair runs. See `LEADERBOARD.md` §3–§4 and `final_summary.json`.
- No Tier A static F1 is reported. The existing SecVulEval static activity is a 3-snippet feasibility smoke, not a benchmark.
- No cross-tier pooled score, and no claim that Juliet performance transfers to real projects.

## 11. Limitations

- Juliet is synthetic, single-CWE and template-based; these numbers do not extrapolate to real projects.
- Static compile errors are retained as non-ok; they are not scored as zero, and valid-only coverage is reported.
- The dynamic run has no line/branch coverage instrumentation; a clean result is not a verified true negative.
- The runtime-supported 178/128 population was defined with an LSan preflight, so ASan scores on that subset are largely circular; Valgrind and static are the informative comparisons.
- Only 29 test families; cluster bootstrap is descriptive, not a high-power inference.
- This historical view excludes round-2 LLM/hybrid/repair; see LEADERBOARD.md and final_summary.json for those runs.

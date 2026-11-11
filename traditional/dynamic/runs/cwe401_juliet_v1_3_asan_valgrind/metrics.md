# Dynamic CWE-401 evaluation metrics

- Run ID: `cwe401_juliet_v1_3_asan_valgrind`
- Generated (UTC): `2026-11-11T18:13:31Z`
- Cases: 3316 (labeled: 3316)
- Decisive / inconclusive: 3315 / 1

## Outcomes

| outcome | count |
|---|---:|
| clean | 1848 |
| inconclusive | 1 |
| leak | 1467 |

## Combined detector (leak if any detector reports a leak)

| TP | FP | TN | FN | precision | recall | FPR | specificity | F1 | accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1467 | 0 | 1658 | 190 | 1.0000 | 0.8853 | 0.0000 | 1.0000 | 0.9392 | 0.9427 |

Recall 95% Wilson CI: [0.869, 0.900]; FPR 95% Wilson CI: [0.000, 0.002]

## Per-detector results

| detector | decisive | TP | FP | TN | FN | precision | recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| asan | 3310 | 1442 | 0 | 1658 | 210 | 1.0000 | 0.8729 | 0.0000 | 0.9321 |
| valgrind | 3305 | 1459 | 0 | 1658 | 188 | 1.0000 | 0.8859 | 0.0000 | 0.9395 |

## Failure classes

| class | count |
|---|---:|
| runtime.asan_error:bad-free | 1 |

## Breakdown by language

| language | cases | labeled | decisive | TP | FP | TN | FN | recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| c | 1736 | 1736 | 1736 | 712 | 0 | 868 | 156 | 0.8203 | 0.0000 |
| cpp | 1580 | 1580 | 1579 | 755 | 0 | 790 | 34 | 0.9569 | 0.0000 |

## Breakdown by feature (top 20 by cases)

| feature | cases | labeled | decisive | recall | FPR |
|---|---:|---:|---:|---:|---:|
| char_calloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| char_malloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| char_realloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| int64_t_calloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| int64_t_malloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| int64_t_realloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| int_calloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| int_malloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| int_realloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| strdup_char | 96 | 96 | 96 | 0.9583 | 0.0000 |
| strdup_wchar_t | 96 | 96 | 96 | 0.9583 | 0.0000 |
| struct_twoIntsStruct_calloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| struct_twoIntsStruct_malloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| struct_twoIntsStruct_realloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| twoIntsStruct_calloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| twoIntsStruct_malloc | 96 | 96 | 96 | 0.9375 | 0.0000 |
| twoIntsStruct_realloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| wchar_t_calloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| wchar_t_malloc | 96 | 96 | 96 | 0.9583 | 0.0000 |
| wchar_t_realloc | 96 | 96 | 96 | 0.9583 | 0.0000 |

## Notes

- TP/FP/TN/FN are computed only on labeled cases with a decisive outcome.
- `inconclusive`, `timeout`, `build_failed`, and `unavailable` are excluded from the confusion matrix.
- A combined `clean` means at least one detector completed a normal no-leak run and no detector reported a leak.
- Detection evidence comes from LeakSanitizer/Valgrind output; function names are never used as labels.

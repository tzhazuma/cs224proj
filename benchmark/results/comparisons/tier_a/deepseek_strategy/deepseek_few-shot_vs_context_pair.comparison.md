# Paired comparison: `legacy__test_v1_few-shot_pairs` vs `legacy__test_v1_context_pairs`

- task: `pair_detection`
- dataset SHA-256: `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`
- generated: `2026-11-11T19:21:05Z`

## Alignment

| field | value |
| --- | ---: |
| `pairs_a` | 180 |
| `pairs_b` | 180 |
| `common_pairs` | 180 |
| `common_valid_pairs` | 180 |
| `only_a` | 0 |
| `only_b` | 0 |

## Metrics

| field | value |
| --- | ---: |
| `a` | {'valid_only_joint_accuracy': 0.08888888888888889, 'strict_joint_accuracy': 0.08888888888888889, 'valid_pairs': 180} |
| `b` | {'valid_only_joint_accuracy': 0.12222222222222222, 'strict_joint_accuracy': 0.12222222222222222, 'valid_pairs': 180} |
| `delta_joint_accuracy` | -0.033333333333333326 |
| `delta_joint_accuracy` CI | [-0.07222222222222223, 0.00555555555555555] |
| `mcnemar.a_correct_b_wrong` | 3 |
| `mcnemar.a_wrong_b_correct` | 9 |
| `mcnemar.p_value` | 0.14599609375 |

## Notes

- Pair DA is the proportion of pairs where vulnerable is flagged and fixed is clean; it is not per-function accuracy.

# Paired comparison: `legacy__test_v1_few-shot_pairs` vs `legacy__test_v1_mimo_few-shot_pairs`

- task: `pair_detection`
- dataset SHA-256: `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`
- generated: `2026-11-11T19:20:58Z`

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
| `b` | {'valid_only_joint_accuracy': 0.09444444444444444, 'strict_joint_accuracy': 0.09444444444444444, 'valid_pairs': 180} |
| `delta_joint_accuracy` | -0.00555555555555555 |
| `delta_joint_accuracy` CI | [-0.03888888888888889, 0.027777777777777776] |
| `mcnemar.a_correct_b_wrong` | 4 |
| `mcnemar.a_wrong_b_correct` | 5 |
| `mcnemar.p_value` | 1.0 |

## Notes

- Pair DA is the proportion of pairs where vulnerable is flagged and fixed is clean; it is not per-function accuracy.

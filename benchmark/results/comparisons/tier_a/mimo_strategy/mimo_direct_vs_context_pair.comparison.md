# Paired comparison: `legacy__test_v1_mimo_direct_pairs` vs `legacy__test_v1_mimo_context_pairs`

- task: `pair_detection`
- dataset SHA-256: `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`
- generated: `2026-11-11T19:21:10Z`

## Alignment

| field | value |
| --- | ---: |
| `pairs_a` | 180 |
| `pairs_b` | 180 |
| `common_pairs` | 180 |
| `common_valid_pairs` | 145 |
| `only_a` | 0 |
| `only_b` | 0 |

## Metrics

| field | value |
| --- | ---: |
| `a` | {'valid_only_joint_accuracy': 0.0896551724137931, 'strict_joint_accuracy': 0.07777777777777778, 'valid_pairs': 145} |
| `b` | {'valid_only_joint_accuracy': 0.11724137931034483, 'strict_joint_accuracy': 0.10555555555555556, 'valid_pairs': 145} |
| `delta_joint_accuracy` | -0.027586206896551724 |
| `delta_joint_accuracy` CI | [-0.06896551724137932, 0.013793103448275862] |
| `mcnemar.a_correct_b_wrong` | 3 |
| `mcnemar.a_wrong_b_correct` | 7 |
| `mcnemar.p_value` | 0.34375 |

## Notes

- Pair DA is the proportion of pairs where vulnerable is flagged and fixed is clean; it is not per-function accuracy.

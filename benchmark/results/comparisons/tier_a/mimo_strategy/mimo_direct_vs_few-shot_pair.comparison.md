# Paired comparison: `legacy__test_v1_mimo_direct_pairs` vs `legacy__test_v1_mimo_few-shot_pairs`

- task: `pair_detection`
- dataset SHA-256: `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`
- generated: `2026-11-11T19:21:09Z`

## Alignment

| field | value |
| --- | ---: |
| `pairs_a` | 180 |
| `pairs_b` | 180 |
| `common_pairs` | 180 |
| `common_valid_pairs` | 154 |
| `only_a` | 0 |
| `only_b` | 0 |

## Metrics

| field | value |
| --- | ---: |
| `a` | {'valid_only_joint_accuracy': 0.09090909090909091, 'strict_joint_accuracy': 0.07777777777777778, 'valid_pairs': 154} |
| `b` | {'valid_only_joint_accuracy': 0.1038961038961039, 'strict_joint_accuracy': 0.09444444444444444, 'valid_pairs': 154} |
| `delta_joint_accuracy` | -0.012987012987012991 |
| `delta_joint_accuracy` CI | [-0.05194805194805194, 0.019480519480519487] |
| `mcnemar.a_correct_b_wrong` | 3 |
| `mcnemar.a_wrong_b_correct` | 5 |
| `mcnemar.p_value` | 0.7265625 |

## Notes

- Pair DA is the proportion of pairs where vulnerable is flagged and fixed is clean; it is not per-function accuracy.

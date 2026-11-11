# Pair-joint：DeepSeek V4.1 Flash vs MiMo V2.6 Flash

同一 180 对冻结测试集、同一 prompt 版本、同一 A/B 平衡顺序；每对一次请求。

| 模型 | DA（全部） | 长度启发式 DA | DA（可解析） | swapped | both | neither | invalid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 76.67% | 74.44% | 76.67% | 42 | 0 | 0 | 0 |
| mimo-v2.6-flash | 86.67% | 74.44% | 86.67% | 24 | 0 | 0 | 0 |

| 模型 | DA(A) | DA(B) | 差值 | Fisher p | 证据合规 | 定位命中 | 成本 USD | p95 延迟 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 92.22% | 61.11% | 31.11% | 1.000e-06 | 98.33% | 93.02% | 0.153593 | 8.0319 |
| mimo-v2.6-flash | 88.89% | 84.44% | 4.44% | 0.5114 | 97.78% | 95.89% | 0.071803 | 12.9217 |

## 统计对比

- **deepseek-v4.1-flash** vs `test_v1_direct_pairs`（direct）：joint DA=76.67%，baseline DA=11.67%，ΔDA=65.00%，McNemar p=3.611e-34，项目聚类 ΔDA 95% CI [0.5865, 0.7791]。
- **deepseek-v4.1-flash** vs `test_v1_context_pairs`（context）：joint DA=76.67%，baseline DA=12.22%，ΔDA=64.44%，McNemar p=7.162e-34，项目聚类 ΔDA 95% CI [0.5689, 0.7961]。
- **mimo-v2.6-flash** vs `test_v1_mimo_direct_pairs`（direct）：joint DA=86.67%，baseline DA=7.78%，ΔDA=78.89%，McNemar p=3.587e-43，项目聚类 ΔDA 95% CI [0.7415, 0.8762]。
- **mimo-v2.6-flash** vs `test_v1_mimo_context_pairs`（context）：joint DA=86.67%，baseline DA=10.56%，ΔDA=76.11%，McNemar p=1.148e-41，项目聚类 ΔDA 95% CI [0.7134, 0.8488]。

## 跨模型对比（同一批对）

- `deepseek-v4.1-flash` vs `mimo-v2.6-flash`：138 vs 156 对正确；ΔDA=-10.00%。
- 2×2：both correct=133，A-only=5，B-only=23，both wrong=19。
- McNemar p=0.0009；项目聚类 ΔDA 95% CI [-0.1458, -0.0455]；配对级 95% CI [-0.1556, -0.0444]。

说明：`both` / `neither` 是模型违反“恰好一个”指令的输出；`invalid` 为不可解析/API 错误。所有数字均来自对应运行目录的 `results.jsonl`，未手工改写。


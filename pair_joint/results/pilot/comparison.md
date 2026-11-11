# Pair-joint：DeepSeek V4.1 Flash vs MiMo V2.6 Flash

同一 180 对冻结测试集、同一 prompt 版本、同一 A/B 平衡顺序；每对一次请求。

| 模型 | DA（全部） | 长度启发式 DA | DA（可解析） | swapped | both | neither | invalid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 75.00% | 87.50% | 75.00% | 2 | 0 | 0 | 0 |
| mimo-v2.6-flash | 62.50% | 87.50% | 62.50% | 3 | 0 | 0 | 0 |

| 模型 | DA(A) | DA(B) | 差值 | Fisher p | 证据合规 | 定位命中 | 成本 USD | p95 延迟 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek-v4.1-flash | 100.00% | 50.00% | 50.00% | 0.4286 | 100.00% | 83.33% | 0.009343 | 5.8053 |
| mimo-v2.6-flash | 75.00% | 50.00% | 25.00% | 1.0000 | 87.50% | 100.00% | 0.004282 | 8.5718 |

## 统计对比


## 跨模型对比（同一批对）

- `deepseek-v4.1-flash` vs `mimo-v2.6-flash`：6 vs 5 对正确；ΔDA=12.50%。
- 2×2：both correct=5，A-only=1，B-only=0，both wrong=2。
- McNemar p=1.0000；项目聚类 ΔDA 95% CI [0.0000, 0.3750]；配对级 95% CI [0.0000, 0.3750]。

说明：`both` / `neither` 是模型违反“恰好一个”指令的输出；`invalid` 为不可解析/API 错误。所有数字均来自对应运行目录的 `results.jsonl`，未手工改写。


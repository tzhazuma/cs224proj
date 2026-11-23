# pair_diff 结果摘要

数据集：`splits/pilot_pairs_18.json`（8 对，SHA-256 `e237137718a973af0a1c9cde1fc7ecf594b51feb6ce5600f5a47894f29e54747`）。

## 主表

| 模型 | 条件 | DA | 交换一致 DA | both+neither | 选较短比例 | 成本 USD |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 62.50% | 50.00% | 25.00% | 100.00% | 0.011118 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 62.50% | 50.00% | 12.50% | 85.71% | 0.011194 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 75.00% | 50.00% | 25.00% | 83.33% | 0.010750 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 62.50% | 50.00% | 12.50% | 85.71% | 0.007185 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 75.00% | 37.50% | 25.00% | 83.33% | 0.008826 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 37.50% | 37.50% | 25.00% | 66.67% | 0.008929 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 62.50% | 50.00% | 25.00% | 100.00% | 0.005257 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 50.00% | 50.00% | 25.00% | 83.33% | 0.005286 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 62.50% | 62.50% | 25.00% | 100.00% | 0.005340 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 62.50% | 62.50% | 25.00% | 100.00% | 0.005385 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 62.50% | 50.00% | 25.00% | 66.67% | 0.004315 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 50.00% | 50.00% | 25.00% | 83.33% | 0.004182 |

## 关键比较

| 模型 | diff−ctrl（交换一致） | p | diff−open（交换一致） | p | ctrl−open（交换一致） | p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | +0.00 pp | 1.0000 | +12.50 pp | 1.0000 | +12.50 pp | 1.0000 |
| MiMo V2.6 Flash | -12.50 pp | 1.0000 | +0.00 pp | 1.0000 | +12.50 pp | 1.0000 |

完整表、长度分层、合规、成本与限制见 `analysis_<model>.md`、`comparison.md`。

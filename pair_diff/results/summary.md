# pair_diff 结果摘要

数据集：`splits/test_pairs_180.json`（180 对，SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`）。

## 主表

| 模型 | 条件 | DA | 交换一致 DA | both+neither | 选较短比例 | 成本 USD |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 68.33% | 62.22% | 23.33% | 80.43% | 0.198567 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 70.56% | 62.22% | 20.00% | 77.08% | 0.196426 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 68.89% | 60.00% | 18.89% | 80.82% | 0.196572 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 69.44% | 60.00% | 19.44% | 75.17% | 0.184486 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 66.11% | 55.56% | 21.11% | 76.06% | 0.152318 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 63.89% | 55.56% | 17.22% | 73.15% | 0.152284 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 68.33% | 60.56% | 24.44% | 80.88% | 0.094832 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 66.67% | 60.56% | 23.33% | 78.26% | 0.095017 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 66.11% | 62.22% | 26.11% | 81.20% | 0.095571 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 69.44% | 62.22% | 20.00% | 77.78% | 0.095398 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 66.11% | 58.33% | 21.67% | 80.14% | 0.073852 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 65.56% | 58.33% | 22.22% | 76.43% | 0.071734 |

## 关键比较

| 模型 | diff−ctrl（交换一致） | p | diff−open（交换一致） | p | ctrl−open（交换一致） | p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | +2.22 pp | 0.3438 | +6.67 pp | 0.0428 | +4.44 pp | 0.1849 |
| MiMo V2.6 Flash | -1.67 pp | 0.6291 | +2.22 pp | 0.5413 | +3.89 pp | 0.1671 |

完整表、长度分层、合规、成本与限制见 `analysis_<model>.md`、`comparison.md`。

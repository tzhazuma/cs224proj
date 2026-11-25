# pair_diff：跨模型与关键比较

数据集：`splits/test_pairs_180.json`（180 对）；条件：diff + changes-first、token 长度匹配对照、pair_debias 开放四分类。

## 1. 跨模型（同一配对上）

| 任务 | DeepSeek DA | MiMo DA | Δ(DS−MiMo) | McNemar p | Holm p | 项目聚类 Δ 95% CI |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| diff + changes-first（正向） | 68.33% | 68.33% | +0.00 pp | 1.0000 | 1.0000 | [-5.88, +5.26] pp |
| diff + changes-first（反向） | 70.56% | 66.67% | +3.89 pp | 0.1435 | 0.4304 | [-1.44, +8.90] pp |
| diff + changes-first（交换一致） | 62.22% | 60.56% | +1.67 pp | 0.6476 | 1.0000 | [-3.60, +6.87] pp |
| 长度匹配对照（正向） | 68.89% | 66.11% | +2.78 pp | 0.4244 | — | [-2.48, +9.09] pp |
| 长度匹配对照（反向） | 69.44% | 69.44% | +0.00 pp | 1.0000 | — | [-6.90, +4.71] pp |
| 长度匹配对照（交换一致） | 60.00% | 62.22% | -2.22 pp | 0.5034 | — | [-8.25, +2.10] pp |
| pair_debias 开放四分类（正向） | 66.11% | 66.11% | +0.00 pp | 1.0000 | — | [-6.09, +4.84] pp |
| pair_debias 开放四分类（反向） | 63.89% | 65.56% | -1.67 pp | 0.6900 | — | [-8.80, +3.24] pp |
| pair_debias 开放四分类（交换一致） | 55.56% | 58.33% | -2.78 pp | 0.4583 | — | [-9.16, +2.41] pp |

## 2. 每个模型的关键分解

### DeepSeek V4.1 Flash

| 指标 | 值 |
| --- | ---: |
| 交换一致 DA（diff + changes-first） | 62.22% |
| 交换一致 DA（长度匹配对照） | 60.00% |
| 交换一致 DA（pair_debias 开放四分类） | 55.56% |
| diff_minus_ctrl Δcorrect（180 对 × 2 序） | +1 |
| diff_minus_open Δcorrect（180 对 × 2 序） | +16 |
| ctrl_minus_open Δcorrect（180 对 × 2 序） | +15 |

### MiMo V2.6 Flash

| 指标 | 值 |
| --- | ---: |
| 交换一致 DA（diff + changes-first） | 60.56% |
| 交换一致 DA（长度匹配对照） | 62.22% |
| 交换一致 DA（pair_debias 开放四分类） | 58.33% |
| diff_minus_ctrl Δcorrect（180 对 × 2 序） | -1 |
| diff_minus_open Δcorrect（180 对 × 2 序） | +6 |
| ctrl_minus_open Δcorrect（180 对 × 2 序） | +7 |

## 3. 结论模板（只填真实数字）

- diff 相对长度对照的交换一致 DA 差与 McNemar/Holm 见上表；只有 Holm 后显著才写成“改善”。
- 若 diff 相对 open 的提升与 ctrl 相对 open 的提升相近，则主要是提示变长/变更清单指令，而不是 diff 内容。
- 若 diff 在 H 错误子集的准确率高于 ctrl，且选较短比例不升，才支持“diff 减少了长度捷径”。
- 成本以配置价计，增量成本/额外正确对只在 Δcorrect>0 时有定义。

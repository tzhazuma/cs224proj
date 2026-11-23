# pair_diff：跨模型与关键比较

数据集：`splits/pilot_pairs_18.json`（8 对）；条件：diff + changes-first、token 长度匹配对照、pair_debias 开放四分类。

## 1. 跨模型（同一配对上）

| 任务 | DeepSeek DA | MiMo DA | Δ(DS−MiMo) | McNemar p | Holm p | 项目聚类 Δ 95% CI |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| diff + changes-first（正向） | 62.50% | 62.50% | +0.00 pp | 1.0000 | 1.0000 | [+0.00, +0.00] pp |
| diff + changes-first（反向） | 62.50% | 50.00% | +12.50 pp | 1.0000 | 1.0000 | [+0.00, +37.50] pp |
| diff + changes-first（交换一致） | 50.00% | 50.00% | +0.00 pp | 1.0000 | 1.0000 | [+0.00, +0.00] pp |
| 长度匹配对照（正向） | 75.00% | 62.50% | +12.50 pp | 1.0000 | — | [+0.00, +37.50] pp |
| 长度匹配对照（反向） | 62.50% | 62.50% | +0.00 pp | 1.0000 | — | [-37.50, +37.50] pp |
| 长度匹配对照（交换一致） | 50.00% | 62.50% | -12.50 pp | 1.0000 | — | [-37.50, +0.00] pp |
| pair_debias 开放四分类（正向） | 75.00% | 62.50% | +12.50 pp | 1.0000 | — | [+0.00, +37.50] pp |
| pair_debias 开放四分类（反向） | 37.50% | 50.00% | -12.50 pp | 1.0000 | — | [-37.50, +0.00] pp |
| pair_debias 开放四分类（交换一致） | 37.50% | 50.00% | -12.50 pp | 1.0000 | — | [-37.50, +0.00] pp |

## 2. 每个模型的关键分解

### DeepSeek V4.1 Flash

| 指标 | 值 |
| --- | ---: |
| 交换一致 DA（diff + changes-first） | 50.00% |
| 交换一致 DA（长度匹配对照） | 50.00% |
| 交换一致 DA（pair_debias 开放四分类） | 37.50% |
| diff_minus_ctrl Δcorrect（180 对 × 2 序） | -1 |
| diff_minus_open Δcorrect（180 对 × 2 序） | +1 |
| ctrl_minus_open Δcorrect（180 对 × 2 序） | +2 |

### MiMo V2.6 Flash

| 指标 | 值 |
| --- | ---: |
| 交换一致 DA（diff + changes-first） | 50.00% |
| 交换一致 DA（长度匹配对照） | 62.50% |
| 交换一致 DA（pair_debias 开放四分类） | 50.00% |
| diff_minus_ctrl Δcorrect（180 对 × 2 序） | -1 |
| diff_minus_open Δcorrect（180 对 × 2 序） | +0 |
| ctrl_minus_open Δcorrect（180 对 × 2 序） | +1 |

## 3. 结论模板（只填真实数字）

- diff 相对长度对照的交换一致 DA 差与 McNemar/Holm 见上表；只有 Holm 后显著才写成“改善”。
- 若 diff 相对 open 的提升与 ctrl 相对 open 的提升相近，则主要是提示变长/变更清单指令，而不是 diff 内容。
- 若 diff 在 H 错误子集的准确率高于 ctrl，且选较短比例不升，才支持“diff 减少了长度捷径”。
- 成本以配置价计，增量成本/额外正确对只在 Δcorrect>0 时有定义。

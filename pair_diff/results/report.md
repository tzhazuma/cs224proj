# Pair-diff：差分引导、先列变更、位置去偏的配对评估

数据集：`splits/test_pairs_180.json`（180 对，SHA-256 `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d`）。

## 0. 一句话结论

- **DeepSeek V4.1 Flash**：正向 DA diff 68.33% / ctrl 68.89% / open 66.11%；交换一致 DA 62.22% / 60.00% / 55.56%。diff−ctrl 交换一致 Δ +2.22 pp（McNemar p=0.3438，Holm p=1.0000）；diff−open Δ +6.67 pp（p=0.0428，Holm p=0.0855）。正向 H-gap：diff +36.3 pp / ctrl +40.0 pp / open +33.3 pp。变更清单无安全相关项的 20/180 对全部判错（neither 95.00%），有安全相关项的 160 对 DA 76.88%。
- **MiMo V2.6 Flash**：正向 DA diff 68.33% / ctrl 66.11% / open 66.11%；交换一致 DA 60.56% / 62.22% / 58.33%。diff−ctrl 交换一致 Δ -1.67 pp（McNemar p=0.6291，Holm p=0.9053）；diff−open Δ +2.22 pp（p=0.5413，Holm p=1.0000）。正向 H-gap：diff +33.4 pp / ctrl +36.2 pp / open +36.2 pp。变更清单无安全相关项的 36/180 对全部判错（neither 100.00%），有安全相关项的 144 对 DA 85.42%。

结论只按上表的显著性写：**没有 Holm 后显著的 diff 优势时，不写成“diff 有效”；H-gap 没有下降时，不写成“diff 减少长度捷径”。**

## 1. 设计

在 180 个冻结 SecVulEval pair 上运行三种开放四分类（A/B/both/neither）呈现：

- `diff`：两份完整代码 + 从 A 到 B 的 unified diff + 要求先列 `semantic_changes` 再判定；
- `ctrl`：两份完整代码 + 与 diff 块 token 长度匹配、内容为空的占位块 + 同样的先列变更要求；
- `open`：`pair_debias` 已发布的开放四分类（无 diff、无变更清单），只读复用。

每个条件都跑 A/B 正反两序；`diff−ctrl` 分离 diff 内容，`ctrl−open` 分离提示变长/变更清单指令，`diff−open` 是总效应。diff 方向固定 A→B，跟随槽位交换，因此不能直接泄漏标签；把 target 当已修复会表现为位置偏差。

## 2. 完整性与合规

| 模型 | 条件 | 记录 | ok | invalid | error | changes-first | schema exact | 条目接地率 | 引用行精确率 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 99.66% | 78.82% |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 99.65% | 76.11% |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 98.94% | 75.51% |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 99.64% | 72.24% |
| MiMo V2.6 Flash | diff + changes-first（正向） | 180 | 180 | 0 | 0 | 100.00% | 99.44% | 100.00% | 82.94% |
| MiMo V2.6 Flash | diff + changes-first（反向） | 180 | 180 | 0 | 0 | 100.00% | 99.44% | 100.00% | 81.67% |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 98.80% | 79.51% |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 180 | 180 | 0 | 0 | 100.00% | 100.00% | 99.22% | 75.95% |

### 2b. 实际提示长度匹配

| 模型 | 比较 | 中位 diff tokens | 中位 ctrl tokens | 中位 ctrl/diff | ≤5% 对数 | 匹配子集 n |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff_fwd_vs_ctrl_fwd | 2050.0 | 2025.0 | 0.9928 | 179/180 | 179 |
| DeepSeek V4.1 Flash | diff_rev_vs_ctrl_rev | 2050.0 | 2025.0 | 0.9928 | 179/180 | 179 |
| MiMo V2.6 Flash | diff_fwd_vs_ctrl_fwd | 2065.0 | 2087.0 | 1.0077 | 180/180 | 180 |
| MiMo V2.6 Flash | diff_rev_vs_ctrl_rev | 2065.0 | 2090.0 | 1.0077 | 180/180 | 180 |

- DeepSeek V4.1 Flash / diff_fwd_vs_ctrl_fwd：在 179 对 ≤5% token 匹配子集上，diff−ctrl Δ -0.56 pp，McNemar p=1.0000。
- DeepSeek V4.1 Flash / diff_rev_vs_ctrl_rev：在 179 对 ≤5% token 匹配子集上，diff−ctrl Δ +1.12 pp，McNemar p=0.7266。
- MiMo V2.6 Flash / diff_fwd_vs_ctrl_fwd：在 180 对 ≤5% token 匹配子集上，diff−ctrl Δ +2.22 pp，McNemar p=0.3438。
- MiMo V2.6 Flash / diff_rev_vs_ctrl_rev：在 180 对 ≤5% token 匹配子集上，diff−ctrl Δ -2.78 pp，McNemar p=0.3018。

`中位 ctrl/diff` 是 180 个逐对比值的中位数，不是两个中位数之比；`≤5%` 指逐对 |ctrl/diff−1|≤0.05。

## 3. 主结果

### DeepSeek V4.1 Flash

| 条件 | DA | committed DA | 交换一致 DA | both | neither | 弃权率 | ΔA−B | Fisher p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first（正向） | 68.33% | 89.13% | 62.22% | 4 | 38 | 23.33% | -12.22 pp | 0.1087 |
| diff + changes-first（反向） | 70.56% | 88.19% | 62.22% | 3 | 33 | 20.00% | -7.78 pp | 0.3265 |
| 长度匹配对照（正向） | 68.89% | 84.93% | 60.00% | 3 | 31 | 18.89% | -8.89 pp | 0.2597 |
| 长度匹配对照（反向） | 69.44% | 86.21% | 60.00% | 4 | 31 | 19.44% | -3.33 pp | 0.7464 |
| pair_debias 开放四分类（正向） | 66.11% | 83.80% | 55.56% | 13 | 25 | 21.11% | +3.33 pp | 0.7530 |
| pair_debias 开放四分类（反向） | 63.89% | 77.18% | 55.56% | 7 | 24 | 17.22% | +12.22 pp | 0.1204 |

### MiMo V2.6 Flash

| 条件 | DA | committed DA | 交换一致 DA | both | neither | 弃权率 | ΔA−B | Fisher p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first（正向） | 68.33% | 90.44% | 60.56% | 0 | 44 | 24.44% | -14.44 pp | 0.0540 |
| diff + changes-first（反向） | 66.67% | 86.96% | 60.56% | 0 | 42 | 23.33% | -8.89 pp | 0.2683 |
| 长度匹配对照（正向） | 66.11% | 89.47% | 62.22% | 1 | 46 | 26.11% | -12.22 pp | 0.1150 |
| 长度匹配对照（反向） | 69.44% | 86.81% | 62.22% | 1 | 35 | 20.00% | -1.11 pp | 1.0000 |
| pair_debias 开放四分类（正向） | 66.11% | 84.40% | 58.33% | 8 | 31 | 21.67% | -12.22 pp | 0.1150 |
| pair_debias 开放四分类（反向） | 65.56% | 84.29% | 58.33% | 7 | 33 | 22.22% | +4.44 pp | 0.6381 |

**both/neither 的移动：** diff 的 both 只有 0–4 个（open 7–13），neither 为 33–44 个（open 24–33）；ctrl 的 both 1–4、neither 31–46。总弃权率 diff 20.00%–24.44%、ctrl 18.89%–26.11%、open 17.22%–22.22%。也就是说，diff/ctrl 基本消除了 `both`，但把一部分转成了 `neither`，总弃权没有下降。

### 3b. 跨模型（交换一致 DA）

| 任务 | DeepSeek | MiMo | Δ(DS−MiMo) | McNemar p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first | 62.22% | 60.56% | +1.67 pp | 0.6476 | 1.0000 |
| 长度匹配对照 | 60.00% | 62.22% | -2.22 pp | 0.5034 | — |
| pair_debias 开放四分类 | 55.56% | 58.33% | -2.78 pp | 0.4583 | — |

位置偏差：六个条件中没有任何一个 A/B 分侧 Fisher p<0.05；diff 在两个模型、两个顺序上都是负的 ΔA−B（B 侧更高），MiMo 正向 p=0.054 最接近显著，但正反两序未给出一致的显著偏差。同字母率 diff 6.35%–7.03%，ctrl 5.43%–7.58%，open 8.59%–14.50%，说明 diff/ctrl 的选择主要由内容而非字母驱动。

## 4. 关键比较与长度捷径

| 模型 | 比较 | Δ | McNemar p | Holm p | 项目聚类 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| DeepSeek V4.1 Flash | diff_stable_vs_ctrl_stable | +2.22 pp | 0.3438 | 1.0000 | [-0.99, +4.76] pp |
| DeepSeek V4.1 Flash | diff_stable_vs_open_stable | +6.67 pp | 0.0428 | 0.0855 | [+1.15, +12.22] pp |
| DeepSeek V4.1 Flash | ctrl_stable_vs_open_stable | +4.44 pp | 0.1849 | 0.3699 | [-0.78, +11.61] pp |
| MiMo V2.6 Flash | diff_stable_vs_ctrl_stable | -1.67 pp | 0.6291 | 0.9053 | [-8.06, +2.34] pp |
| MiMo V2.6 Flash | diff_stable_vs_open_stable | +2.22 pp | 0.5413 | 1.0000 | [-2.92, +7.14] pp |
| MiMo V2.6 Flash | ctrl_stable_vs_open_stable | +3.89 pp | 0.1671 | 0.5012 | [+0.00, +10.96] pp |

### 4b. 长度捷径（正向）

| 模型 | 条件 | H 正确子集 DA | H 错误子集 DA | gap | 选较短比例 | H 错误子集 n |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 77.61% | 41.30% | +36.31 pp | 80.43% | 46 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 79.10% | 39.13% | +39.97 pp | 80.82% | 46 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 74.63% | 41.30% | +33.32 pp | 76.06% | 46 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 77.27% | 52.08% | +25.19 pp | 77.08% | 48 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 75.00% | 54.17% | +20.83 pp | 75.17% | 48 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 71.21% | 43.75% | +27.46 pp | 73.15% | 48 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 76.87% | 43.48% | +33.39 pp | 80.88% | 46 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 75.37% | 39.13% | +36.24 pp | 81.20% | 46 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 75.37% | 39.13% | +36.24 pp | 80.14% | 46 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 75.00% | 43.75% | +31.25 pp | 78.26% | 48 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 77.27% | 47.92% | +29.36 pp | 77.78% | 48 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 71.97% | 47.92% | +24.05 pp | 76.43% | 48 |

### 4c. “较短侧是错误答案”的子集

| 模型 | 子集 | n | diff−ctrl Δ | p | diff−open Δ | p |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | vulnerable_longer | 44 | +2.27 pp | 1.0000 | +2.27 pp | 1.0000 |
| DeepSeek V4.1 Flash | vulnerable_shorter | 130 | -1.54 pp | 0.7266 | +3.08 pp | 0.5034 |
| DeepSeek V4.1 Flash | tie | 6 | +0.00 pp | 1.0000 | -16.67 pp | 1.0000 |
| MiMo V2.6 Flash | vulnerable_longer | 44 | +2.27 pp | 1.0000 | +4.55 pp | 0.7266 |
| MiMo V2.6 Flash | vulnerable_shorter | 130 | +0.77 pp | 1.0000 | +0.77 pp | 1.0000 |
| MiMo V2.6 Flash | tie | 6 | +33.33 pp | 0.5000 | +16.67 pp | 1.0000 |

### 4d. 只在 committed 子集上比长度启发式

| 模型 | 条件 | committed n | 模型 DA | 启发式 DA | Δ | McNemar p |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 138 | 89.13% | 81.16% | +7.97 pp | 0.0522 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 146 | 84.93% | 79.45% | +5.48 pp | 0.1849 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 142 | 83.80% | 80.99% | +2.82 pp | 0.6076 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 144 | 88.19% | 76.39% | +11.81 pp | 0.0046 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 145 | 86.21% | 75.17% | +11.03 pp | 0.0113 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 149 | 77.18% | 75.84% | +1.34 pp | 0.8746 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 136 | 90.44% | 80.15% | +10.29 pp | 0.0094 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 133 | 89.47% | 81.20% | +8.27 pp | 0.0433 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 141 | 84.40% | 78.72% | +5.67 pp | 0.1849 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 138 | 86.96% | 78.26% | +8.70 pp | 0.0428 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 144 | 86.81% | 77.08% | +9.72 pp | 0.0201 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 140 | 84.29% | 75.00% | +9.29 pp | 0.0351 |

这张表回答“模型一旦承诺 A/B，是否比‘选较短’更强”；它不受弃权惩罚。主 DA 仍然按 180 对计，不能把 committed 子集的优势直接当成总体优势。

## 5. both/neither 与变更范围捷径

| 模型 | 条件 | any security_relevant n | DA | neither | no security_relevant n | DA | neither |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 160 | 76.88% | 11.88% | 20 | 0.00% | 95.00% |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 157 | 80.89% | 7.64% | 23 | 0.00% | 91.30% |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 159 | 77.99% | 7.55% | 21 | 0.00% | 90.48% |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 159 | 78.62% | 8.18% | 21 | 0.00% | 85.71% |
| MiMo V2.6 Flash | diff + changes-first（正向） | 144 | 85.42% | 5.56% | 36 | 0.00% | 100.00% |
| MiMo V2.6 Flash | diff + changes-first（反向） | 145 | 82.76% | 4.83% | 35 | 0.00% | 100.00% |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 142 | 83.80% | 5.63% | 38 | 0.00% | 100.00% |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 148 | 83.78% | 3.38% | 32 | 3.12% | 93.75% |

读法：`no_security_relevant` 组是模型自己在变更清单里没有标出任何 `security_relevant=true` 的 pair；它全部判 `neither` 时 DA 必为 0。该组不是随机分组，而是 changes-first 的一种失败模式：模型把“变更不涉及安全”当成“两个版本都安全”，忽略了漏洞可能在两版共享的未变更代码里。

### 5b. 同一批 pair 上的其他条件（参考，不是随机对照）

| 模型 | 子集 | n | diff DA | ctrl DA | open DA |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | any_security_relevant | 160 | 76.88% | 76.88% | 72.50% |
| DeepSeek V4.1 Flash | no_security_relevant | 20 | 0.00% | 5.00% | 15.00% |
| MiMo V2.6 Flash | any_security_relevant | 144 | 85.42% | 81.25% | 79.86% |
| MiMo V2.6 Flash | no_security_relevant | 36 | 0.00% | 5.56% | 11.11% |

这张表把变化拆成两部分；净 DA 是这两部分的和，不能只看其中一边。在 any-security 子集上 diff/ctrl 与 open 的差、在 no-security 子集上的门控损失，必须一起读。

## 6. 成本

| 模型 | 臂 | 请求 | prompt tokens | completion tokens | USD（配置价） | USD/100 pair-order | 正确 pair-order | USD/正确 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | open | 360 | 893410 | 60149 | 0.304602 | 0.084612 | 234 | 0.001302 |
| DeepSeek V4.1 Flash | ctrl | 360 | 1060198 | 104651 | 0.381058 | 0.105849 | 249 | 0.001530 |
| DeepSeek V4.1 Flash | diff | 360 | 1068084 | 103410 | 0.394993 | 0.109720 | 250 | 0.001580 |
| MiMo V2.6 Flash | open | 360 | 946480 | 66529 | 0.145586 | 0.040441 | 237 | 0.000614 |
| MiMo V2.6 Flash | ctrl | 360 | 1123368 | 123767 | 0.190969 | 0.053047 | 244 | 0.000783 |
| MiMo V2.6 Flash | diff | 360 | 1115028 | 121209 | 0.189849 | 0.052736 | 243 | 0.000781 |

- DeepSeek V4.1 Flash：diff 成本是 open 的 1.30×，ctrl 是 open 的 1.25×；正确 pair-order diff 250 / ctrl 249 / open 234。
- MiMo V2.6 Flash：diff 成本是 open 的 1.30×，ctrl 是 open 的 1.31×；正确 pair-order diff 243 / ctrl 244 / open 237。

## 7. 解释与结论

1. **diff 内容没有建立优势。** 交换一致 DA 上，diff−ctrl 为 DeepSeek +2.22 pp（Holm 1.0000）、MiMo −1.67 pp（Holm 0.9053）；diff−open 为 DeepSeek +6.67 pp（raw p=0.0428，Holm 0.0855）、MiMo +2.22 pp（Holm 1.0000）。没有任何一个模型在 Holm 后显著优于对照或 open。
2. **committed 子集有内容信号，但被弃权抵消。** 在模型实际给出 A/B 的子集上，diff 比“选较短”高 +7.97 pp（DeepSeek 正向，p=0.0522）、+11.81 pp（DeepSeek 反向，p=0.0046）、+10.29 pp（MiMo 正向，p=0.0094）、+8.70 pp（MiMo 反向，p=0.0428）；open 的同口径优势只有 +1.34 到 +9.29 pp。主 DA 仍按 180 对计，不能把 committed 优势当成总体优势。
3. **没有一致证据表明 diff 减少了长度捷径；长度捷径仍然存在。** diff/ctrl 的“选较短”比例（75.17%–81.20%）不低于 open（73.15%–80.14%）；在“较短侧必错”的 44 对上，diff−ctrl 只有 +2.27 pp（两个模型 p=1.0000），diff−open 为 +2.27/+4.55 pp（p=1.0000/0.7266）；长度匹配 ≤10% 子集上模型仍低于启发式（约 67% vs 72.9%）。MiMo 的 H-gap 比 open 低约 2.9 pp，但选较短比例更高，H 错误子集仅 +4.55 pp（p=0.7266），因此不能把这一点当成稳健的长度去偏。
4. **changes-first 的一个突出新失败模式是变更范围门控。** 模型在变更清单里没有标出安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全部判 neither，DA 为 0；open 在同一批 pair 上也只有 15.00%/11.11%，说明该子集本身难，但 diff/ctrl 的门控把少数可能答对的 pair 也丢掉了。ctrl 出现同样的门控，说明它主要由“先列变更”指令驱动，而不是 diff 内容。
5. **成本效率没有改善。** diff 成本约为 open 的 1.30×；相对 ctrl 的正确 pair-order 为 +1/−1，相对 open 为 +16/+6（DeepSeek 250 vs 234，MiMo 243 vs 237）；USD/正确 pair-order 仍高于 open。

## 8. 逐对例子（自动选取，未手改）

### DeepSeek V4.1 Flash

**diff_only_correct**（共 3 对，列前 3 对）

- `20228:20229`（tcpdump）：diff=A / ctrl=neither / open=both；changes: In the non-verbose MESSAGE_UPDATE branch, the length check before accessing message[3] changed from len < 1 to len < 10, so the truncated-message guard now requires a longer TLV before reading message[3].；rationale: In VERSION_A the non-verbose MESSAGE_UPDATE path only checks len < 1 before reading message[3], but message[3] is at offset 3 within the TLV, so a TLV with len 1 or 2 causes an out-of-bounds read. VERSION_B's len < 10 check ensures message[3] is within the TLV before accessing it.
- `7919:7920`（hhvm）：diff=B / ctrl=A / open=A；changes: Replaced assertx(salt) with a null check in the condition (salt && salt[0] == '\0'), so a null salt no longer triggers an assertion but is passed through to string_crypt.；rationale: Version A asserts salt is non-null before dereferencing and passing it on, enforcing the API contract. Version B silently accepts a null salt and forwards it to string_crypt, which may dereference it (null-pointer crash) or behave unexpectedly; the null check only guards the notice, not the crypt call.
- `2044:2045`（linux）：diff=B / ctrl=A / open=A；changes: In the SIOCGIFADDR case, the copy_to_user failure path now breaks out before calling ipxitf_put(ipxif), whereas previously ipxitf_put was always called after copy_to_user regardless of failure. This introduces a reference leak on copy_to_us；rationale: Version B skips ipxitf_put(ipxif) when copy_to_user fails, leaking the ipx_interface reference (and its net_device reference) on each failed SIOCGIFADDR call, which can be triggered repeatedly by an unprivileged user to exhaust resources. Version A always releases the reference.

**diff_neither_ctrl_ab**（共 9 对，列前 3 对）

- `5512:5513`（linux）：diff=neither / ctrl=B / open=A；changes: The condition guarding create_flush_cmd_control() changed from requiring both the FLUSH_MERGE mount option and a writable filesystem to only requiring a writable filesystem, so flush command control is now created even when FLUSH_MERGE is n；rationale: The change only broadens when flush command control is allocated; it does not introduce an obvious memory-safety or privilege issue, and both revisions otherwise handle allocation and error paths identically. No clear vulnerability is present in either revision.
- `7565:7568`（quassel）：diff=neither / ctrl=B / open=A；changes: Encoding is deferred into a lambda passed to putPrivmsg instead of pre-encoding the message with channelEncode before the call.; The target passed to putPrivmsg is no longer serverEncode()'d; the raw buffer name is passed and encoding is delegated to the callback.；rationale: The change refactors encoding into a callback and moves serverEncode into putPrivmsg; assuming putPrivmsg applies the callback to the target and message as intended, there is no clear injection or memory-safety vulnerability in either revision. The refactor is security-relevant in that encoding responsibility moved, bu
- `18396:18397`（unrar）：diff=neither / ctrl=B / open=B；changes: In the escape branch, VERSION_B decrements pps before the loop and increments it at the top of the loop body, whereas VERSION_A keeps pps unchanged and increments it after the CharMask write. Both iterate over the same ps[0..i-1] entries, b；rationale: Both revisions perform the same number of iterations (i = NumStats-NumMasked) over the same ps array entries and both retain the bounds check before dereferencing (*pps). VERSION_B's pps--/pps++ restructuring is equivalent to VERSION_A's post-increment form; the pre-decrement is immediately undone by the increment at t

**diff_and_ctrl_wrong_open_correct**（共 12 对，列前 3 对）

- `5512:5513`（linux）：diff=neither / ctrl=B / open=A；changes: The condition guarding create_flush_cmd_control() changed from requiring both the FLUSH_MERGE mount option and a writable filesystem to only requiring a writable filesystem, so flush command control is now created even when FLUSH_MERGE is n；rationale: The change only broadens when flush command control is allocated; it does not introduce an obvious memory-safety or privilege issue, and both revisions otherwise handle allocation and error paths identically. No clear vulnerability is present in either revision.
- `21213:21218`（Chrome）：diff=neither / ctrl=neither / open=A；changes: Replaced direct web_ui_->CallJavascriptFunction call with a call to SendDeviceNotification(device, NULL), changing how the device notification is dispatched.；rationale: Both versions dereference device after only a DCHECK (debug-only) guard, but that pattern is unchanged between revisions and the diff only refactors the notification dispatch into a helper; no new security-relevant flaw is introduced by the change itself.
- `7565:7568`（quassel）：diff=neither / ctrl=B / open=A；changes: Encoding is deferred into a lambda passed to putPrivmsg instead of pre-encoding the message with channelEncode before the call.; The target passed to putPrivmsg is no longer serverEncode()'d; the raw buffer name is passed and encoding is delegated to the callback.；rationale: The change refactors encoding into a callback and moves serverEncode into putPrivmsg; assuming putPrivmsg applies the callback to the target and message as intended, there is no clear injection or memory-safety vulnerability in either revision. The refactor is security-relevant in that encoding responsibility moved, bu

### MiMo V2.6 Flash

**diff_only_correct**（共 4 对，列前 3 对）

- `10290:10289`（selinux）：diff=A / ctrl=B / open=B；changes: The reset function now destroys the classperms list in place (setting perm->classperms to NULL) instead of recursively resetting the elements of the list, leaving the list pointer dangling/unchanged in VERSION_A.；rationale: VERSION_A only resets the contents of the classperms list but leaves perm->classperms pointing at the (now reset) list, so a subsequent reset or use can operate on stale/partially-reset data; VERSION_B properly destroys and NULLs the list pointer, which is the correct reset semantics. The dangling/stale pointer in A ri
- `2627:2628`（linux）：diff=A / ctrl=neither / open=B；changes: Reorders the two operations inside the link_substream block: VERSION_A calls hda_link_dma_cleanup() first and then ops->post_trigger(SNDRV_PCM_TRIGGER_SUSPEND); VERSION_B calls ops->post_trigger() first and then hda_link_dma_cleanup().；rationale: The only change is the ordering of hda_link_dma_cleanup() versus ops->post_trigger(). In VERSION_A, DMA cleanup runs before post_trigger(SUSPEND), so post_trigger operates on already-torn-down DMA state; if post_trigger (or a subsequent resume path) touches the freed/invalidated DMA buffers or descriptors, this is a us
- `10089:10097`（389-ds-base）：diff=B / ctrl=neither / open=neither；changes: VERSION_B removes the `int *rc` output parameter from find_entry2modify_only_ext and no longer passes it to find_entry_internal; VERSION_A passes `rc` through so the caller receives the lookup result code.；rationale: VERSION_B drops the `rc` out-parameter, so callers of find_entry2modify_only_ext can no longer learn whether the entry lookup succeeded, failed, or was not found. Callers that previously relied on `rc` to decide whether to proceed with a modify operation may act on an uninitialized/stale status, potentially allowing op

**diff_neither_ctrl_ab**（共 4 对，列前 3 对）

- `5512:5513`（linux）：diff=neither / ctrl=B / open=B；changes: The condition guarding create_flush_cmd_control changed: VERSION_A requires both the FLUSH_MERGE mount option and a non-readonly filesystem, while VERSION_B only requires a non-readonly filesystem, so flush cmd control is now created uncond；rationale: The only change is relaxing the FLUSH_MERGE option check when creating the flush command control. This alters behavior (flush merge machinery is initialized even without the option) but does not by itself introduce a memory-safety or privilege vulnerability; both revisions handle allocation failures and error paths ide
- `7565:7568`（quassel）：diff=neither / ctrl=B / open=B；changes: Refactors message encoding: instead of pre-encoding the message with channelEncode and pre-encoding the target with serverEncode before calling putPrivmsg, version B passes a std::function encodeFunc (wrapping channelEncode) and the raw buf；rationale: The change moves encoding responsibility into putPrivmsg via a callback. Without the definition of the new putPrivmsg overload, we cannot confirm a vulnerability: if putPrivmsg applies serverEncode to the target and channelEncode via encodeFunc, behavior is equivalent to A. If it fails to serverEncode the target or dou
- `2255:2256`（linux）：diff=neither / ctrl=A / open=A；changes: Reordered the device-registration block (usb_set_intfdata/usb_register_dev/dev->minor assignment and the 'now attached' dev_info log) to occur after the GET_VERSION control transfer instead of before it; the control transfer and its error h；rationale: The only change is the ordering of usb_register_dev relative to the GET_VERSION usb_control_msg. In both revisions, any failure path (control transfer failure or registration failure) jumps to error -> tower_delete(dev), which cleans up all allocated resources; usb_set_intfdata is only set immediately before usb_regist

**diff_and_ctrl_wrong_open_correct**（共 7 对，列前 3 对）

- `4597:4598`（linux）：diff=A / ctrl=A / open=B；changes: The default value of vm_flags is changed from VM_READ | VM_WRITE | VM_EXEC in VERSION_A to VM_READ | VM_WRITE in VERSION_B (VM_EXEC removed from the initial default).；rationale: The only change is the default vm_flags value. In VERSION_A the default includes VM_EXEC, meaning a fault that is neither an execute fault nor a write fault (e.g., a read fault) is handled with VM_EXEC set, which can cause the fault handler to treat a read fault as an execute fault and potentially grant/validate execut
- `18396:18397`（unrar）：diff=neither / ctrl=neither / open=B；changes: In the escape branch (count >= HiCnt), VERSION_B restores a `pps--` before the do-loop and moves `pps++` to the top of the loop body, while VERSION_A removes the `pps--` and keeps `pps++` at the end of the loop body (with a comment explaini；rationale: Both revisions retain the bounds check `pps>=ps+ASIZE(ps)` before dereferencing `*pps` in the escape branch, so neither allows an out-of-bounds write/read of the `ps[256]` array under the stated invariant. VERSION_A's reordering (check before increment) and VERSION_B's reordering (increment before check) are behavioral
- `17004:17005`（open62541）：diff=neither / ctrl=neither / open=A；changes: The dummy connection buffer size passed to createDummyConnection changes from the hardcoded literal 65535 to UA_ConnectionConfig_default.sendBufferSize, aligning the test connection buffer with the channel's configured send buffer size；rationale: This is test setup code (setup_secureChannel) using a dummy connection and dummy policy. The only change is the buffer size argument to createDummyConnection: a hardcoded 65535 in A versus UA_ConnectionConfig_default.sendBufferSize in B. Both are plausible test configurations; neither introduces a security vulnerabilit

## 9. 限制

- 单次贪心解码（temperature=0）；交换一致 DA 是主终点，但没有重复采样方差。
- 开放任务在构造上恰好一个版本含漏洞；both/neither 在 DA 中记错，因此必须同时读 committed DA 与弃权率。
- diff 方向固定 A→B；它跟随槽位交换，不泄漏标签，但会引入 target 侧方向先验；正反交换只能检测、不能完全消除。
- 长度对照是内容为空的占位块；它匹配 token 长度和格式位置，但“没有注释”的提示可能改变谨慎程度。diff 若胜出，该比较对 diff 保守；ctrl 若胜出，不能直接归因于“长度”。
- token 匹配先用 tiktoken 代理，再用 provider 的 prompt_tokens 复核；中位比例接近 1，但总 token 仍有长尾差异，≤5% 匹配子集是敏感性分析。
- changes-first 由 JSON 首键和原文顺序代理，不是两阶段协议；主 DA 不以合规为门槛。
- 变更接地只按行号对齐 difflib 变更行，不评价摘要的自然语言正确性，也不区分安全相关/无关变更的语义质量。
- `security_relevant` 分组是模型自报的探索性切分，不是随机对照。
- 长度分层、匹配子集和例子选择都是事后诊断，不是预注册基线。
- 项目聚类 bootstrap 是 95% 未校正区间；多重比较以预声明 Holm 族为准，不能把单个 CI 不跨 0 当成显著。
- 项目不平衡（linux 占比较大）；bootstrap 主区间按 project 聚类，pair 级为敏感性。
- diff 由冻结函数体生成，不是上游 commit patch；格式化、重命名、注释变化也会进入变更清单。
- 源码中 1/180 对的注释含 CVE-2017-17969（两侧相同，不指示槽位）；diff 可能带入该注释，但不是注入标签。

## 10. 产物

- `pair_diff/results/analysis_<model>.json/.md`：逐对结果、条件指标、交换一致性、长度、合规、成本。
- `pair_diff/results/comparison.json/.md`：跨模型与关键分解。
- `pair_diff/results/benchmark_export.json`：供上层汇总的紧凑导出。
- `pair_diff/runs/test_*`：原始 requests/results/cache/position_map/leak_audit。

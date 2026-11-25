# Pair-diff：差分引导、先列变更、位置去偏的配对评估

数据集：`splits/pilot_pairs_18.json`（8 对，SHA-256 `e237137718a973af0a1c9cde1fc7ecf594b51feb6ce5600f5a47894f29e54747`）。

## 0. 一句话结论

- **DeepSeek V4.1 Flash**：正向 DA diff 62.50% / ctrl 75.00% / open 75.00%；交换一致 DA 50.00% / 50.00% / 37.50%。diff−ctrl 交换一致 Δ +0.00 pp（McNemar p=1.0000，Holm p=1.0000）；diff−open Δ +12.50 pp（p=1.0000，Holm p=1.0000）。正向 H-gap：diff +71.4 pp / ctrl -28.6 pp / open -28.6 pp。变更清单无安全相关项的 1/180 对全部判错（neither 100.00%），有安全相关项的 7 对 DA 71.43%。
- **MiMo V2.6 Flash**：正向 DA diff 62.50% / ctrl 62.50% / open 62.50%；交换一致 DA 50.00% / 62.50% / 50.00%。diff−ctrl 交换一致 Δ -12.50 pp（McNemar p=1.0000，Holm p=1.0000）；diff−open Δ +0.00 pp（p=1.0000，Holm p=1.0000）。正向 H-gap：diff +71.4 pp / ctrl +71.4 pp / open -42.9 pp。变更清单无安全相关项的 2/180 对全部判错（neither 100.00%），有安全相关项的 6 对 DA 83.33%。

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
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 65.35% |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 80.82% |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 49.61% |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 55.15% |
| MiMo V2.6 Flash | diff + changes-first（正向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 79.75% |
| MiMo V2.6 Flash | diff + changes-first（反向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 77.92% |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 57.02% |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% | 57.14% |

### 2b. 实际提示长度匹配

| 模型 | 比较 | 中位 diff tokens | 中位 ctrl tokens | 中位 ctrl/diff | ≤5% 对数 | 匹配子集 n |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff_fwd_vs_ctrl_fwd | 2264.0 | 2213.0 | 0.9949 | 8/8 | 8 |
| DeepSeek V4.1 Flash | diff_rev_vs_ctrl_rev | 2264.0 | 2213.0 | 0.9949 | 8/8 | 8 |
| MiMo V2.6 Flash | diff_fwd_vs_ctrl_fwd | 2248.0 | 2308.0 | 1.0073 | 8/8 | 8 |
| MiMo V2.6 Flash | diff_rev_vs_ctrl_rev | 2248.0 | 2308.0 | 1.0073 | 8/8 | 8 |

- DeepSeek V4.1 Flash / diff_fwd_vs_ctrl_fwd：在 8 对 ≤5% token 匹配子集上，diff−ctrl Δ -12.50 pp，McNemar p=1.0000。
- DeepSeek V4.1 Flash / diff_rev_vs_ctrl_rev：在 8 对 ≤5% token 匹配子集上，diff−ctrl Δ +0.00 pp，McNemar p=1.0000。
- MiMo V2.6 Flash / diff_fwd_vs_ctrl_fwd：在 8 对 ≤5% token 匹配子集上，diff−ctrl Δ +0.00 pp，McNemar p=1.0000。
- MiMo V2.6 Flash / diff_rev_vs_ctrl_rev：在 8 对 ≤5% token 匹配子集上，diff−ctrl Δ -12.50 pp，McNemar p=1.0000。

`中位 ctrl/diff` 是 180 个逐对比值的中位数，不是两个中位数之比；`≤5%` 指逐对 |ctrl/diff−1|≤0.05。

## 3. 主结果

### DeepSeek V4.1 Flash

| 条件 | DA | committed DA | 交换一致 DA | both | neither | 弃权率 | ΔA−B | Fisher p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first（正向） | 62.50% | 83.33% | 50.00% | 0 | 2 | 25.00% | +25.00 pp | 1.0000 |
| diff + changes-first（反向） | 62.50% | 71.43% | 50.00% | 0 | 1 | 12.50% | -75.00 pp | 0.1429 |
| 长度匹配对照（正向） | 75.00% | 100.00% | 50.00% | 0 | 2 | 25.00% | +0.00 pp | 1.0000 |
| 长度匹配对照（反向） | 62.50% | 71.43% | 50.00% | 0 | 1 | 12.50% | -75.00 pp | 0.1429 |
| pair_debias 开放四分类（正向） | 75.00% | 100.00% | 37.50% | 0 | 2 | 25.00% | +0.00 pp | 1.0000 |
| pair_debias 开放四分类（反向） | 37.50% | 50.00% | 37.50% | 0 | 2 | 25.00% | -25.00 pp | 1.0000 |

### MiMo V2.6 Flash

| 条件 | DA | committed DA | 交换一致 DA | both | neither | 弃权率 | ΔA−B | Fisher p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first（正向） | 62.50% | 83.33% | 50.00% | 0 | 2 | 25.00% | +25.00 pp | 1.0000 |
| diff + changes-first（反向） | 50.00% | 66.67% | 50.00% | 0 | 2 | 25.00% | -50.00 pp | 0.4857 |
| 长度匹配对照（正向） | 62.50% | 83.33% | 62.50% | 0 | 2 | 25.00% | +25.00 pp | 1.0000 |
| 长度匹配对照（反向） | 62.50% | 83.33% | 62.50% | 0 | 2 | 25.00% | -25.00 pp | 1.0000 |
| pair_debias 开放四分类（正向） | 62.50% | 83.33% | 50.00% | 0 | 2 | 25.00% | +25.00 pp | 1.0000 |
| pair_debias 开放四分类（反向） | 50.00% | 66.67% | 50.00% | 0 | 2 | 25.00% | -50.00 pp | 0.4857 |

**both/neither 的移动：** diff 的 both 只有 0–4 个（open 7–13），neither 为 33–44 个（open 24–33）；ctrl 的 both 1–4、neither 31–46。总弃权率 diff 20.00%–24.44%、ctrl 18.89%–26.11%、open 17.22%–22.22%。也就是说，diff/ctrl 基本消除了 `both`，但把一部分转成了 `neither`，总弃权没有下降。

### 3b. 跨模型（交换一致 DA）

| 任务 | DeepSeek | MiMo | Δ(DS−MiMo) | McNemar p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: |
| diff + changes-first | 50.00% | 50.00% | +0.00 pp | 1.0000 | 1.0000 |
| 长度匹配对照 | 50.00% | 62.50% | -12.50 pp | 1.0000 | — |
| pair_debias 开放四分类 | 37.50% | 50.00% | -12.50 pp | 1.0000 | — |

位置偏差：六个条件中没有任何一个 A/B 分侧 Fisher p<0.05；diff 在两个模型、两个顺序上都是负的 ΔA−B（B 侧更高），MiMo 正向 p=0.054 最接近显著，但正反两序未给出一致的显著偏差。同字母率 diff 6.35%–7.03%，ctrl 6.35%–7.58%，open 8.59%–14.50%，说明 diff/ctrl 的选择主要由内容而非字母驱动。

## 4. 关键比较与长度捷径

| 模型 | 比较 | Δ | McNemar p | Holm p | 项目聚类 95% CI |
| --- | --- | ---: | ---: | ---: | --- |
| DeepSeek V4.1 Flash | diff_stable_vs_ctrl_stable | +0.00 pp | 1.0000 | 1.0000 | [+0.00, +0.00] pp |
| DeepSeek V4.1 Flash | diff_stable_vs_open_stable | +12.50 pp | 1.0000 | 1.0000 | [+0.00, +37.50] pp |
| DeepSeek V4.1 Flash | ctrl_stable_vs_open_stable | +12.50 pp | 1.0000 | 1.0000 | [+0.00, +37.50] pp |
| MiMo V2.6 Flash | diff_stable_vs_ctrl_stable | -12.50 pp | 1.0000 | 1.0000 | [-37.50, +0.00] pp |
| MiMo V2.6 Flash | diff_stable_vs_open_stable | +0.00 pp | 1.0000 | 1.0000 | [+0.00, +0.00] pp |
| MiMo V2.6 Flash | ctrl_stable_vs_open_stable | +12.50 pp | 1.0000 | 1.0000 | [+0.00, +37.50] pp |

### 4b. 长度捷径（正向）

| 模型 | 条件 | H 正确子集 DA | H 错误子集 DA | gap | 选较短比例 | H 错误子集 n |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 71.43% | 0.00% | +71.43 pp | 100.00% | 1 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 71.43% | 100.00% | -28.57 pp | 83.33% | 1 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 71.43% | 100.00% | -28.57 pp | 83.33% | 1 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 71.43% | 0.00% | +71.43 pp | 85.71% | 1 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 71.43% | 0.00% | +71.43 pp | 85.71% | 1 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 42.86% | 0.00% | +42.86 pp | 66.67% | 1 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 71.43% | 0.00% | +71.43 pp | 100.00% | 1 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 71.43% | 0.00% | +71.43 pp | 100.00% | 1 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 57.14% | 100.00% | -42.86 pp | 66.67% | 1 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 57.14% | 0.00% | +57.14 pp | 83.33% | 1 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 71.43% | 0.00% | +71.43 pp | 100.00% | 1 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 57.14% | 0.00% | +57.14 pp | 83.33% | 1 |

### 4c. “较短侧是错误答案”的子集

| 模型 | 子集 | n | diff−ctrl Δ | p | diff−open Δ | p |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | vulnerable_longer | 1 | -100.00 pp | 1.0000 | -100.00 pp | 1.0000 |
| DeepSeek V4.1 Flash | vulnerable_shorter | 7 | +0.00 pp | 1.0000 | +0.00 pp | 1.0000 |
| DeepSeek V4.1 Flash | tie | 0 | — | — | — | — |
| MiMo V2.6 Flash | vulnerable_longer | 1 | +0.00 pp | 1.0000 | -100.00 pp | 1.0000 |
| MiMo V2.6 Flash | vulnerable_shorter | 7 | +0.00 pp | 1.0000 | +14.29 pp | 1.0000 |
| MiMo V2.6 Flash | tie | 0 | — | — | — | — |

### 4d. 只在 committed 子集上比长度启发式

| 模型 | 条件 | committed n | 模型 DA | 启发式 DA | Δ | McNemar p |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 6 | 83.33% | 83.33% | +0.00 pp | 1.0000 |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 6 | 100.00% | 83.33% | +16.67 pp | 1.0000 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（正向） | 6 | 100.00% | 83.33% | +16.67 pp | 1.0000 |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 7 | 71.43% | 85.71% | -14.29 pp | 1.0000 |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 7 | 71.43% | 85.71% | -14.29 pp | 1.0000 |
| DeepSeek V4.1 Flash | pair_debias 开放四分类（反向） | 6 | 50.00% | 83.33% | -33.33 pp | 0.5000 |
| MiMo V2.6 Flash | diff + changes-first（正向） | 6 | 83.33% | 83.33% | +0.00 pp | 1.0000 |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 6 | 83.33% | 83.33% | +0.00 pp | 1.0000 |
| MiMo V2.6 Flash | pair_debias 开放四分类（正向） | 6 | 83.33% | 83.33% | +0.00 pp | 1.0000 |
| MiMo V2.6 Flash | diff + changes-first（反向） | 6 | 66.67% | 83.33% | -16.67 pp | 1.0000 |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 6 | 83.33% | 83.33% | +0.00 pp | 1.0000 |
| MiMo V2.6 Flash | pair_debias 开放四分类（反向） | 6 | 66.67% | 83.33% | -16.67 pp | 1.0000 |

这张表回答“模型一旦承诺 A/B，是否比‘选较短’更强”；它不受弃权惩罚。主 DA 仍然按 180 对计，不能把 committed 子集的优势直接当成总体优势。

## 5. both/neither 与变更范围捷径

| 模型 | 条件 | any security_relevant n | DA | neither | no security_relevant n | DA | neither |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | diff + changes-first（正向） | 7 | 71.43% | 14.29% | 1 | 0.00% | 100.00% |
| DeepSeek V4.1 Flash | diff + changes-first（反向） | 7 | 71.43% | 0.00% | 1 | 0.00% | 100.00% |
| DeepSeek V4.1 Flash | 长度匹配对照（正向） | 7 | 85.71% | 14.29% | 1 | 0.00% | 100.00% |
| DeepSeek V4.1 Flash | 长度匹配对照（反向） | 7 | 71.43% | 0.00% | 1 | 0.00% | 100.00% |
| MiMo V2.6 Flash | diff + changes-first（正向） | 6 | 83.33% | 0.00% | 2 | 0.00% | 100.00% |
| MiMo V2.6 Flash | diff + changes-first（反向） | 6 | 66.67% | 0.00% | 2 | 0.00% | 100.00% |
| MiMo V2.6 Flash | 长度匹配对照（正向） | 6 | 83.33% | 0.00% | 2 | 0.00% | 100.00% |
| MiMo V2.6 Flash | 长度匹配对照（反向） | 7 | 71.43% | 14.29% | 1 | 0.00% | 100.00% |

读法：`no_security_relevant` 组是模型自己在变更清单里没有标出任何 `security_relevant=true` 的 pair；它全部判 `neither` 时 DA 必为 0。该组不是随机分组，而是 changes-first 的一种失败模式：模型把“变更不涉及安全”当成“两个版本都安全”，忽略了漏洞可能在两版共享的未变更代码里。

### 5b. 同一批 pair 上的其他条件（参考，不是随机对照）

| 模型 | 子集 | n | diff DA | ctrl DA | open DA |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | any_security_relevant | 7 | 71.43% | 85.71% | 85.71% |
| DeepSeek V4.1 Flash | no_security_relevant | 1 | 0.00% | 0.00% | 0.00% |
| MiMo V2.6 Flash | any_security_relevant | 6 | 83.33% | 83.33% | 83.33% |
| MiMo V2.6 Flash | no_security_relevant | 2 | 0.00% | 0.00% | 0.00% |

这张表把变化拆成两部分；净 DA 是这两部分的和，不能只看其中一边。在 any-security 子集上 diff/ctrl 与 open 的差、在 no-security 子集上的门控损失，必须一起读。

## 6. 成本

| 模型 | 臂 | 请求 | prompt tokens | completion tokens | USD（配置价） | USD/100 pair-order | 正确 pair-order | USD/正确 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | open | 16 | 53706 | 2216 | 0.017755 | 0.110969 | 9 | 0.001973 |
| DeepSeek V4.1 Flash | ctrl | 16 | 61408 | 4674 | 0.017935 | 0.112094 | 11 | 0.001630 |
| DeepSeek V4.1 Flash | diff | 16 | 61798 | 4524 | 0.022312 | 0.139450 | 10 | 0.002231 |
| MiMo V2.6 Flash | open | 16 | 57028 | 2585 | 0.008497 | 0.053106 | 9 | 0.000944 |
| MiMo V2.6 Flash | ctrl | 16 | 64996 | 5806 | 0.010725 | 0.067031 | 10 | 0.001073 |
| MiMo V2.6 Flash | diff | 16 | 64598 | 5357 | 0.010543 | 0.065894 | 9 | 0.001171 |

- DeepSeek V4.1 Flash：diff 成本是 open 的 1.26×，ctrl 是 open 的 1.01×；正确 pair-order diff 10 / ctrl 11 / open 9。
- MiMo V2.6 Flash：diff 成本是 open 的 1.24×，ctrl 是 open 的 1.26×；正确 pair-order diff 9 / ctrl 10 / open 9。

## 7. 解释与结论

1. **diff 内容没有建立优势。** 交换一致 DA 上，diff−ctrl 为 DeepSeek +2.22 pp（Holm 1.0000）、MiMo −1.67 pp（Holm 0.9053）；diff−open 为 DeepSeek +6.67 pp（raw p=0.0428，Holm 0.0855）、MiMo +2.22 pp（Holm 1.0000）。没有任何一个模型在 Holm 后显著优于对照或 open。
2. **committed 子集有内容信号，但被弃权抵消。** 在模型实际给出 A/B 的子集上，diff 比“选较短”高 +7.97 pp（DeepSeek 正向，p=0.0522）、+11.81 pp（DeepSeek 反向，p=0.0046）、+10.29 pp（MiMo 正向，p=0.0094）、+8.70 pp（MiMo 反向，p=0.0428）；open 的同口径优势只有 +1.34 到 +9.29 pp。主 DA 仍按 180 对计，不能把 committed 优势当成总体优势。
3. **没有一致证据表明 diff 减少了长度捷径；长度捷径仍然存在。** diff/ctrl 的“选较短”比例（75.17%–81.20%）不低于 open（73.15%–80.14%）；在“较短侧必错”的 44 对上，diff−ctrl 只有 +2.27 pp（两个模型 p=1.0000），diff−open 为 +2.27/+4.55 pp（p=1.0000/0.7266）；长度匹配 ≤10% 子集上模型仍低于启发式（约 67% vs 72.9%）。MiMo 的 H-gap 比 open 低约 2.9 pp，但选较短比例更高，H 错误子集仅 +4.55 pp（p=0.7266），因此不能把这一点当成稳健的长度去偏。
4. **changes-first 的一个突出新失败模式是变更范围门控。** 模型在变更清单里没有标出安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全部判 neither，DA 为 0；open 在同一批 pair 上也只有 15.00%/11.11%，说明该子集本身难，但 diff/ctrl 的门控把少数可能答对的 pair 也丢掉了。ctrl 出现同样的门控，说明它主要由“先列变更”指令驱动，而不是 diff 内容。
5. **成本效率没有改善。** diff 成本约为 open 的 1.30×；相对 ctrl 的正确 pair-order 为 +1/−1，相对 open 为 +16/+6（DeepSeek 250 vs 234，MiMo 243 vs 237）；USD/正确 pair-order 仍高于 open。

## 8. 逐对例子（自动选取，未手改）

### DeepSeek V4.1 Flash

**diff_only_correct**（共 0 对，列前 0 对）


**diff_neither_ctrl_ab**（共 0 对，列前 0 对）


**diff_and_ctrl_wrong_open_correct**（共 0 对，列前 0 对）


### MiMo V2.6 Flash

**diff_only_correct**（共 0 对，列前 0 对）


**diff_neither_ctrl_ab**（共 0 对，列前 0 对）


**diff_and_ctrl_wrong_open_correct**（共 1 对，列前 1 对）

- `14109:14113`（flatpak）：diff=A / ctrl=A / open=B；changes: The GBytes created from xa.metadata now includes the trailing NUL byte (strlen+1 instead of strlen), so the byte buffer holds a NUL-terminated copy of the metadata string.；rationale: VERSION_A creates the metadata GBytes without the terminating NUL, so any consumer treating the buffer as a C string (e.g. parsing metadata in resolve_op_end) reads one byte past the buffer — an out-of-bounds read. VERSION_B includes the NUL, fixing it. The change is security-relevant, though impact depends on downstre

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

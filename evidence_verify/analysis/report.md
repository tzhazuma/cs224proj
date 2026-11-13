# 证据提示的二次验证 / 保守操作点（SecVulEval 160 测试，探索性）

> **状态：探索性、事后分析（post-hoc），不是独立确认。** 这 160 个函数已经用于
> 评估第一遍 evidence 提示；验证器提示是在看到该结果之后设计的。任何数字都不能
> 当作“在新测试集上确认了检测能力”。

## 1. 做了什么

第一遍 evidence 提示提高召回，但假阳性点估计上升（DeepSeek +3 / MiMo +4），且证据行
定位接近随机。本实验只处理**正例**：对每个 schema-valid 的“有漏洞”预测，再发一次
独立上下文的模型调用，要求它尝试**反驳**该判断（检查证据是否支持、函数内是否有守卫、
构造一个不触发的反例），并允许它**撤销**证据不足的正例。负例一律不动。

四个实验臂（同一批 160 条测试函数）：

| 臂 | 第一遍正例来源 | 验证器 | 独立性 |
| --- | --- | --- | --- |
| `deepseek_self` | DeepSeek | DeepSeek | 同模型、新上下文（自审） |
| `deepseek_cross` | DeepSeek | MiMo | 跨模型（主分析） |
| `mimo_self` | MiMo | MiMo | 同模型、新上下文（自审） |
| `mimo_cross` | MiMo | DeepSeek | 跨模型（主分析） |

验证器的输入只有：带行号的函数源码 + 第一遍的 `evidence_lines` + `mechanism`。
没有标签、项目、文件路径、commit、`changed_lines`、第一遍 confidence，也没有第一遍的
修复建议。输出被严格校验（7 个键、行号范围、verdict/证据一致性）；不合格记 invalid，
不修复。验证器失败的替换策略：主口径 **fail-closed**（未获 sustain 即撤销），
敏感性口径 fail-open（保留第一遍判断）。

## 2. 主结果

第一遍（pre）与二次验证后（post, fail-closed）的二分类指标。`strict` 为 160 条全记录，
第一遍 invalid 记录在两侧都算错；P/R/F1 为 valid-only。

| 臂 | TP | FP | TN | FN | P | R | F1+ | macro-F1 | MCC | pos-rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self · pre | 49 | 11 | 21 | 78 | 0.8167 | 0.3858 | 0.5241 | 0.4223 | 0.0348 | 37.7% |
| deepseek_cross · pre | 49 | 11 | 21 | 78 | 0.8167 | 0.3858 | 0.5241 | 0.4223 | 0.0348 | 37.7% |
| mimo_self · pre | 47 | 11 | 20 | 80 | 0.8103 | 0.3701 | 0.5081 | 0.4067 | 0.0126 | 36.7% |
| mimo_cross · pre | 47 | 11 | 20 | 80 | 0.8103 | 0.3701 | 0.5081 | 0.4067 | 0.0126 | 36.7% |
| deepseek_self · post | 6 | 0 | 32 | 121 | 1.0000 | 0.0472 | 0.0902 | 0.2181 | 0.0994 | 3.8% |
| deepseek_cross · post | 28 | 4 | 28 | 99 | 0.8750 | 0.2205 | 0.3522 | 0.3522 | 0.0955 | 20.1% |
| mimo_self · post | 28 | 8 | 23 | 99 | 0.7778 | 0.2205 | 0.3436 | 0.3221 | -0.0356 | 22.8% |
| mimo_cross · post | 7 | 0 | 31 | 120 | 1.0000 | 0.0551 | 0.1045 | 0.2226 | 0.1064 | 4.4% |

### 2.1 撤销了什么

| 臂 | 可验证正例 | 其中 TP/FP | 撤销总数 | 撤销 TP | 撤销 FP | 撤销精确率 | TP 损失率 | FP 纠正率 | 随机期望 FP | 超几何 p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 60 | 49/11 | 54 | 43 | 11 | 20.4% | 87.8% | 100.0% | 9.90 | 0.2793 | 0.8380 |
| deepseek_cross | 60 | 49/11 | 26 | 20 | 6 | 23.1% | 40.8% | 54.5% | 4.77 | 0.3089 | 0.8380 |
| mimo_self | 58 | 47/11 | 21 | 18 | 3 | 14.3% | 38.3% | 27.3% | 3.98 | 0.8494 | 0.8494 |
| mimo_cross | 58 | 47/11 | 51 | 40 | 11 | 21.6% | 85.1% | 100.0% | 9.67 | 0.2092 | 0.8367 |

撤销精确率 = 被撤销正例中真正是 FP 的比例；超几何检验的零假设是“从正例中随机抽 k 个”，
单侧检验 FP 是否被过度撤销。Holm 校正覆盖 4 个臂。

### 2.2 指标变化与配对检验

| 臂 | ΔP | ΔR | ΔF1+ | Δmacro-F1 | ΔMCC | Δstrict acc | McNemar p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 0.1833 | -0.3386 | -0.4338 | -0.2043 | 0.0646 | -0.2000 | 0.0000 | 0.0001 |
| deepseek_cross | 0.0583 | -0.1654 | -0.1719 | -0.0701 | 0.0607 | -0.0875 | 0.0125 | 0.0125 |
| mimo_self | -0.0326 | -0.1496 | -0.1645 | -0.0846 | -0.0481 | -0.1000 | 0.0009 | 0.0017 |
| mimo_cross | 0.1897 | -0.3150 | -0.4036 | -0.1842 | 0.0938 | -0.1813 | 0.0001 | 0.0002 |

McNemar 比较 pre 与 post 在 160 条上的 strict 正确性；由于只撤销正例，discordant 只可能
是“TP→FN”和“FP→TN”，因此它与“撤销是否更偏向 FP”是同一个方向的检验（零假设不同：
McNemar 用二项，超几何用无放回抽样）。

### 2.3 fail-open 敏感性（验证器失败时保留第一遍判断）

主口径 fail-closed 把“验证器没有给出有效 sustain”的正例一律撤销。fail-open 则保留它们，
因此两者的差别只来自 invalid/缺失的验证记录。

| 臂 | 验证无效正例 | post macro-F1 (closed) | post macro-F1 (open) | post MCC (closed) | post MCC (open) |
| --- | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 0 | 0.2181 | 0.2181 | 0.0994 | 0.0994 |
| deepseek_cross | 2 | 0.3522 | 0.3521 | 0.0955 | 0.0705 |
| mimo_self | 1 | 0.3221 | 0.3281 | -0.0356 | -0.0279 |
| mimo_cross | 0 | 0.2226 | 0.2226 | 0.1064 | 0.1064 |

### 2.4 按项目聚类的 bootstrap（Δ = post − pre）

| 臂 | Δmacro-F1 [95%] | ΔMCC [95%] | ΔF1+ [95%] | Δrecall [95%] | Δspecificity [95%] | 聚类数 |
| --- | --- | --- | --- | --- | --- | ---: |
| deepseek_self | [-0.3241, -0.1387] | [-0.1339, +0.2092] | [-0.6209, -0.3305] | [-0.5918, -0.2299] | [+0.1852, +0.5910] | 40 |
| deepseek_cross | [-0.1319, +0.0342] | [-0.0751, +0.2846] | [-0.2513, -0.0752] | [-0.2833, -0.0921] | [+0.0769, +0.4800] | 40 |
| mimo_self | [-0.1376, -0.0430] | [-0.1533, +0.0311] | [-0.2406, -0.0978] | [-0.2679, -0.0870] | [+0.0000, +0.2083] | 40 |
| mimo_cross | [-0.3210, -0.1186] | [-0.1372, +0.2264] | [-0.6114, -0.2960] | [-0.5735, -0.2030] | [+0.1818, +0.5714] | 40 |

### 2.5 事后决策规则：只撤销“有具体反证”的正例

主规则把 `insufficient_evidence`（“函数内看不出攻击者控制，所以不足以成立”）也算作撤销。
这在逻辑上把“函数体无法证明可达”与“缺陷不存在”混为一谈，是主规则几乎撤销全部正例的
直接原因。下面是一条**事后**决策规则，不再调用模型，只对同一批已记录输出重新打分：
`verdict=retract` 且 `rebuttal_type != insufficient_evidence` 才撤销；其余保持第一遍判断。
它没有在运行前登记，只能作为敏感性分析。

| 臂 | 撤销总数 | 撤销 TP | 撤销 FP | 撤销精确率 | TP 损失率 | FP 纠正率 | 超几何 p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 18 | 14 | 4 | 22.2% | 28.6% | 36.4% | 0.4301 | 1.0000 |
| deepseek_cross | 8 | 6 | 2 | 25.0% | 12.2% | 18.2% | 0.4544 | 1.0000 |
| mimo_self | 6 | 6 | 0 | 0.0% | 12.8% | 0.0% | 1.0000 | 1.0000 |
| mimo_cross | 17 | 13 | 4 | 23.5% | 27.7% | 36.4% | 0.4078 | 1.0000 |

| 臂 | post macro-F1 | post MCC | post F1+ | post P | post R | post strict acc | Δmacro-F1 | ΔMCC | McNemar Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 0.3749 | 0.0517 | 0.4142 | 0.8333 | 0.2756 | 0.3750 | -0.0475 | +0.0169 | 0.0927 |
| deepseek_cross | 0.4075 | 0.0697 | 0.4746 | 0.8400 | 0.3307 | 0.4125 | -0.0148 | +0.0349 | 0.3438 |
| mimo_self | 0.3696 | -0.0339 | 0.4494 | 0.7843 | 0.3150 | 0.3750 | -0.0371 | -0.0464 | 0.0625 |
| mimo_cross | 0.3645 | 0.0380 | 0.4048 | 0.8293 | 0.2677 | 0.3625 | -0.0422 | +0.0254 | 0.0981 |

同预算对照（k 改为该规则实际撤销数）：

| 臂 | 规则 | 撤销 TP | 撤销 FP | macro-F1 | MCC |
| --- | --- | ---: | ---: | ---: | ---: |
| deepseek_self | 验证器（k=18） | 14 | 4 | 0.3749 | 0.0517 |
| deepseek_self | confidence_lowest | 16 | 2 | 0.3496 | -0.0195 |
| deepseek_self | evidence_lines_fewest | 16 | 2 | 0.3496 | -0.0195 |
| deepseek_self | lines_shortest | 17 | 1 | 0.3370 | -0.0550 |
| deepseek_self | call_count_fewest | 15 | 3 | 0.3623 | 0.0161 |
| deepseek_self | random（期望） | 14.70 | 3.30 | 0.3658 | 0.0262 |
| deepseek_cross | 验证器（k=8） | 6 | 2 | 0.4075 | 0.0697 |
| deepseek_cross | confidence_lowest | 7 | 1 | 0.3929 | 0.0156 |
| deepseek_cross | evidence_lines_fewest | 7 | 1 | 0.3929 | 0.0156 |
| deepseek_cross | lines_shortest | 7 | 1 | 0.3929 | 0.0156 |
| deepseek_cross | call_count_fewest | 6 | 2 | 0.4057 | 0.0490 |
| deepseek_cross | random（期望） | 6.53 | 1.47 | 0.3988 | 0.0309 |
| mimo_self | 验证器（k=6） | 6 | 0 | 0.3696 | -0.0339 |
| mimo_self | confidence_lowest | 5 | 1 | 0.3879 | 0.0069 |
| mimo_self | evidence_lines_fewest | 3 | 3 | 0.4137 | 0.0747 |
| mimo_self | lines_shortest | 6 | 0 | 0.3750 | -0.0270 |
| mimo_self | call_count_fewest | 6 | 0 | 0.3750 | -0.0270 |
| mimo_self | random（期望） | 4.86 | 1.14 | 0.3896 | 0.0112 |
| mimo_cross | 验证器（k=17） | 13 | 4 | 0.3645 | 0.0380 |
| mimo_cross | confidence_lowest | 14 | 3 | 0.3518 | 0.0016 |
| mimo_cross | evidence_lines_fewest | 12 | 5 | 0.3773 | 0.0743 |
| mimo_cross | lines_shortest | 16 | 1 | 0.3264 | -0.0711 |
| mimo_cross | call_count_fewest | 15 | 2 | 0.3391 | -0.0347 |
| mimo_cross | random（期望） | 13.78 | 3.22 | 0.3547 | 0.0098 |

## 3. 成本

| 臂 | 验证请求 | 验证器 USD | 第一遍 USD | 合计 USD | 验证器增量（相对第一遍） | 每 100 单元 USD | 每个保留 TP USD | 撤销 1 个 FP 的验证成本 | p50 延迟 | p95 延迟 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 60 | 0.064580 | 0.085622 | 0.150202 | +75.4% | 0.093876 | 0.025034 | 0.005871 | 6.56 s | 9.14 s |
| deepseek_cross | 60 | 0.022693 | 0.085622 | 0.108314 | +26.5% | 0.067696 | 0.003868 | 0.003782 | 7.07 s | 11.80 s |
| mimo_self | 58 | 0.015100 | 0.035933 | 0.051033 | +42.0% | 0.031896 | 0.001823 | 0.005033 | 6.83 s | 14.97 s |
| mimo_cross | 58 | 0.051960 | 0.035933 | 0.087893 | +144.6% | 0.054933 | 0.012556 | 0.004724 | 3.63 s | 5.53 s |

只有正例子集（60 / 58 条）会发验证请求，但每次都要重发带行号源码，输入 token 接近
一次完整检测；因此验证器的增量成本实际为第一遍检测成本的 +26.5%–+144.6%，不是可以
忽略的零头。“每 100 单元”按 160 条全测试集摊销；价格沿用第一遍 run 的配置，未重新核对
官方页面。

## 4. 两个验证器是否一致

| 正例集合 | n | 一致率 | Cohen κ | 都撤销 | 都保留 | 仅 self 撤销 | 仅 cross 撤销 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek 正例 | 58 | 48.3% | 0.0440 | 24 | 4 | 28 | 2 |
| MiMo 正例 | 57 | 49.1% | 0.1510 | 21 | 7 | 0 | 29 |

## 5. 捷径基线

### 5.1 label-only 与单特征阈值（阈值在 dev 40 上拟合，再原样用于 test 160）

| 规则 | TP | FP | TN | FN | P | R | F1+ | macro-F1 | MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| always vulnerable | 128 | 32 | 0 | 0 | 0.8000 | 1.0000 | 0.8889 | 0.4444 | 0.0000 |
| always safe | 0 | 0 | 32 | 128 | — | 0.0000 | 0.0000 | 0.1667 | 0.0000 |
| lines_threshold (low 110.0) | 106 | 22 | 10 | 22 | 0.8281 | 0.8281 | 0.8281 | 0.5703 | 0.1406 |
| chars_threshold (low 3227.0) | 101 | 23 | 9 | 27 | 0.8145 | 0.7891 | 0.8016 | 0.5331 | 0.0674 |
| code_lines_threshold (low 100.0) | 106 | 22 | 10 | 22 | 0.8281 | 0.8281 | 0.8281 | 0.5703 | 0.1406 |
| call_count_threshold (low 32.0) | 102 | 23 | 9 | 26 | 0.8160 | 0.7969 | 0.8063 | 0.5375 | 0.0756 |

dev 只有 8 个非漏洞样本，拟合出的阈值不稳定；作为上界，下表给出“在 test 上挑最优阈值”
能达到的水平（明确是 test-tuned，只用于说明单特征捷径的上限）：

| 特征 | 方向 | 阈值 | macro-F1 | MCC |
| --- | --- | ---: | ---: | ---: |
| lines | low | 116.0 | 0.5848 | 0.1704 |
| chars | low | 3973.0 | 0.5645 | 0.1298 |
| code_lines | low | 109.0 | 0.5948 | 0.1919 |
| call_count | low | 30.0 | 0.5518 | 0.1048 |

### 5.2 同预算撤销基线（每个臂撤销同样多的正例）

| 臂 | 规则 | 撤销 TP | 撤销 FP | macro-F1 | MCC | F1+ |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 验证器（k=54） | 43 | 11 | 0.2181 | 0.0994 | 0.0902 |
| deepseek_self | confidence_lowest | 44 | 10 | 0.2052 | 0.0171 | 0.0752 |
| deepseek_self | confidence_highest | 44 | 10 | 0.2052 | 0.0171 | 0.0752 |
| deepseek_self | evidence_lines_fewest | 44 | 10 | 0.2052 | 0.0171 | 0.0752 |
| deepseek_self | evidence_lines_most | 43 | 11 | 0.2181 | 0.0994 | 0.0902 |
| deepseek_self | lines_shortest | 44 | 10 | 0.2052 | 0.0171 | 0.0752 |
| deepseek_self | lines_longest | 43 | 11 | 0.2181 | 0.0994 | 0.0902 |
| deepseek_self | call_count_fewest | 46 | 8 | 0.1793 | -0.1476 | 0.0451 |
| deepseek_self | call_count_most | 45 | 9 | 0.1922 | -0.0652 | 0.0602 |
| deepseek_self | random（期望） | 44.10 | 9.90 | 0.2039 | 0.0092 | 0.0738 |
| deepseek_cross | 验证器（k=26） | 20 | 6 | 0.3522 | 0.0955 | 0.3522 |
| deepseek_cross | confidence_lowest | 21 | 5 | 0.3395 | 0.0322 | 0.3478 |
| deepseek_cross | confidence_highest | 24 | 2 | 0.3018 | -0.0825 | 0.3106 |
| deepseek_cross | evidence_lines_fewest | 22 | 4 | 0.3269 | -0.0060 | 0.3354 |
| deepseek_cross | evidence_lines_most | 21 | 5 | 0.3395 | 0.0322 | 0.3478 |
| deepseek_cross | lines_shortest | 23 | 3 | 0.3144 | -0.0443 | 0.3230 |
| deepseek_cross | lines_longest | 20 | 6 | 0.3521 | 0.0705 | 0.3602 |
| deepseek_cross | call_count_fewest | 23 | 3 | 0.3144 | -0.0443 | 0.3230 |
| deepseek_cross | call_count_most | 20 | 6 | 0.3521 | 0.0705 | 0.3602 |
| deepseek_cross | random（期望） | 21.23 | 4.77 | 0.3364 | 0.0228 | 0.3448 |
| mimo_self | 验证器（k=21） | 18 | 3 | 0.3221 | -0.0356 | 0.3436 |
| mimo_self | confidence_lowest | 18 | 3 | 0.3281 | -0.0279 | 0.3537 |
| mimo_self | confidence_highest | 18 | 3 | 0.3281 | -0.0279 | 0.3537 |
| mimo_self | evidence_lines_fewest | 15 | 6 | 0.3662 | 0.0850 | 0.3902 |
| mimo_self | evidence_lines_most | 18 | 3 | 0.3281 | -0.0279 | 0.3537 |
| mimo_self | lines_shortest | 20 | 1 | 0.3028 | -0.1031 | 0.3293 |
| mimo_self | lines_longest | 15 | 6 | 0.3662 | 0.0850 | 0.3902 |
| mimo_self | call_count_fewest | 18 | 3 | 0.3281 | -0.0279 | 0.3537 |
| mimo_self | call_count_most | 14 | 7 | 0.3789 | 0.1227 | 0.4024 |
| mimo_self | random（期望） | 17.02 | 3.98 | 0.3405 | 0.0088 | 0.3655 |
| mimo_cross | 验证器（k=51） | 40 | 11 | 0.2226 | 0.1064 | 0.1045 |
| mimo_cross | confidence_lowest | 41 | 10 | 0.2096 | 0.0289 | 0.0896 |
| mimo_cross | confidence_highest | 42 | 9 | 0.1967 | -0.0485 | 0.0746 |
| mimo_cross | evidence_lines_fewest | 42 | 9 | 0.1967 | -0.0485 | 0.0746 |
| mimo_cross | evidence_lines_most | 43 | 8 | 0.1837 | -0.1260 | 0.0597 |
| mimo_cross | lines_shortest | 42 | 9 | 0.1967 | -0.0485 | 0.0746 |
| mimo_cross | lines_longest | 40 | 11 | 0.2226 | 0.1064 | 0.1045 |
| mimo_cross | call_count_fewest | 43 | 8 | 0.1837 | -0.1260 | 0.0597 |
| mimo_cross | call_count_most | 42 | 9 | 0.1967 | -0.0485 | 0.0746 |
| mimo_cross | random（期望） | 41.33 | 9.67 | 0.2055 | 0.0041 | 0.0848 |

这些规则全部固定、不看标签，也不调 k；k 由验证器决定。随机行是 10,000 次均匀抽样的
期望值。若验证器与随机/廉价启发式在同预算下没有差别，就不能说它“识别出了假阳性”。

## 6. 验证器输出结构与失败

| 臂 | 请求 | ok | invalid | error | 撤销类型分布 | 撤销总数 | 带行号撤销 | 带行号且 grounded | 无行号撤销（insufficient_evidence） | 撤销给反例 |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 60 | 60 | 0 | 0 | guard_present=11, insufficient_evidence=36, no_reachable_flow=3, none=6, not_security_relevant=4 | 54 | 18 | 18/18 | 36 | 54 |
| deepseek_cross | 60 | 58 | 2 | 0 | evidence_mislocated=1, guard_present=5, insufficient_evidence=18, no_reachable_flow=1, none=32, not_security_relevant=1 | 26 | 8 | 8/8 | 18 | 19 |
| mimo_self | 58 | 57 | 1 | 0 | evidence_mislocated=1, guard_present=3, insufficient_evidence=15, no_reachable_flow=1, none=36, not_security_relevant=1 | 21 | 6 | 6/6 | 15 | 15 |
| mimo_cross | 58 | 58 | 0 | 0 | evidence_mislocated=1, guard_present=11, insufficient_evidence=34, no_reachable_flow=2, none=7, not_security_relevant=3 | 51 | 17 | 17/17 | 34 | 51 |

“带行号撤销 + 无行号撤销 = 撤销总数”。`insufficient_evidence` 按契约不允许给行号，
因此单独列一列；它不能被读成“有行号支撑”。

按标签拆分的撤销类型（TP / FP）：

| 臂 | 类型 | TP | FP | 合计 |
| --- | --- | ---: | ---: | ---: |
| deepseek_self | guard_present | 8 | 3 | 11 |
| deepseek_self | insufficient_evidence | 29 | 7 | 36 |
| deepseek_self | no_reachable_flow | 3 | 0 | 3 |
| deepseek_self | not_security_relevant | 3 | 1 | 4 |
| deepseek_cross | evidence_mislocated | 1 | 0 | 1 |
| deepseek_cross | guard_present | 3 | 2 | 5 |
| deepseek_cross | insufficient_evidence | 14 | 4 | 18 |
| deepseek_cross | no_reachable_flow | 1 | 0 | 1 |
| deepseek_cross | not_security_relevant | 1 | 0 | 1 |
| mimo_self | evidence_mislocated | 1 | 0 | 1 |
| mimo_self | guard_present | 3 | 0 | 3 |
| mimo_self | insufficient_evidence | 12 | 3 | 15 |
| mimo_self | no_reachable_flow | 1 | 0 | 1 |
| mimo_self | not_security_relevant | 1 | 0 | 1 |
| mimo_cross | evidence_mislocated | 0 | 1 | 1 |
| mimo_cross | guard_present | 9 | 2 | 11 |
| mimo_cross | insufficient_evidence | 27 | 7 | 34 |
| mimo_cross | no_reachable_flow | 1 | 1 | 2 |
| mimo_cross | not_security_relevant | 3 | 0 | 3 |

撤销置信度均值 / 保留置信度均值：

| 臂 | 撤销 | 保留 |
| --- | ---: | ---: |
| deepseek_self | 0.7446 | 0.7667 |
| deepseek_cross | 0.7481 | 0.7500 |
| mimo_self | 0.7529 | 0.7669 |
| mimo_cross | 0.7614 | 0.7571 |

## 7. 描述性诊断（不是因果）

撤销率按第一遍 confidence / 函数行数 / 证据行数的四分位分桶。如果撤销主要由这些
表面特征驱动，说明验证器更可能在利用捷径，而不是检查证据。

### deepseek_self

| 分位 | 第一遍 confidence 区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 0.60–0.60 | 15 | 100.0% | 13/2 |
| Q2 | 0.60–0.80 | 15 | 100.0% | 10/5 |
| Q3 | 0.80–0.85 | 15 | 93.3% | 12/3 |
| Q4 | 0.85–0.95 | 15 | 66.7% | 14/1 |

| 分位 | 函数行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 10–45 | 15 | 73.3% | 14/1 |
| Q2 | 45–79 | 15 | 100.0% | 12/3 |
| Q3 | 82–171 | 15 | 86.7% | 12/3 |
| Q4 | 175–978 | 15 | 100.0% | 11/4 |

| 分位 | 证据行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 1–4 | 15 | 73.3% | 14/1 |
| Q2 | 4–6 | 15 | 93.3% | 10/5 |
| Q3 | 6–9 | 15 | 100.0% | 13/2 |
| Q4 | 10–22 | 15 | 93.3% | 12/3 |

### deepseek_cross

| 分位 | 第一遍 confidence 区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 0.60–0.60 | 15 | 60.0% | 13/2 |
| Q2 | 0.60–0.80 | 15 | 60.0% | 11/4 |
| Q3 | 0.80–0.85 | 15 | 33.3% | 12/3 |
| Q4 | 0.85–0.95 | 13 | 23.1% | 12/1 |

| 分位 | 函数行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 10–46 | 15 | 33.3% | 15/0 |
| Q2 | 56–86 | 15 | 26.7% | 12/3 |
| Q3 | 89–175 | 15 | 60.0% | 12/3 |
| Q4 | 177–978 | 13 | 61.5% | 9/4 |

| 分位 | 证据行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 2–4 | 15 | 53.3% | 14/1 |
| Q2 | 4–6 | 15 | 26.7% | 11/4 |
| Q3 | 6–10 | 15 | 53.3% | 13/2 |
| Q4 | 10–22 | 13 | 46.2% | 10/3 |

### mimo_self

| 分位 | 第一遍 confidence 区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 0.70–0.70 | 15 | 46.7% | 13/2 |
| Q2 | 0.70–0.75 | 15 | 46.7% | 11/4 |
| Q3 | 0.75–0.85 | 15 | 26.7% | 11/4 |
| Q4 | 0.85–0.95 | 12 | 25.0% | 11/1 |

| 分位 | 函数行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 4–46 | 15 | 46.7% | 14/1 |
| Q2 | 52–94 | 15 | 33.3% | 11/4 |
| Q3 | 95–177 | 15 | 26.7% | 13/2 |
| Q4 | 187–978 | 12 | 41.7% | 8/4 |

| 分位 | 证据行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 1–3 | 15 | 46.7% | 10/5 |
| Q2 | 3–5 | 15 | 40.0% | 13/2 |
| Q3 | 5–7 | 15 | 33.3% | 14/1 |
| Q4 | 7–12 | 12 | 25.0% | 9/3 |

### mimo_cross

| 分位 | 第一遍 confidence 区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 0.70–0.70 | 15 | 93.3% | 13/2 |
| Q2 | 0.70–0.75 | 15 | 100.0% | 11/4 |
| Q3 | 0.75–0.85 | 15 | 86.7% | 11/4 |
| Q4 | 0.85–0.95 | 13 | 69.2% | 12/1 |

| 分位 | 函数行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 4–45 | 15 | 80.0% | 14/1 |
| Q2 | 46–86 | 15 | 93.3% | 12/3 |
| Q3 | 94–175 | 15 | 80.0% | 12/3 |
| Q4 | 177–978 | 13 | 100.0% | 9/4 |

| 分位 | 证据行数区间 | n | 撤销率 | TP/FP |
| --- | --- | ---: | ---: | ---: |
| Q1 | 1–3 | 15 | 86.7% | 10/5 |
| Q2 | 3–5 | 15 | 86.7% | 13/2 |
| Q3 | 5–7 | 15 | 86.7% | 14/1 |
| Q4 | 7–12 | 13 | 92.3% | 10/3 |

### 7.1 置信度阈值扫描（test 上调，仅描述）

| 臂 | 阈值 | 撤销 TP | 撤销 FP | macro-F1 | MCC | F1+ | strict acc |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek_self | 0.0 | 43 | 11 | 0.2181 | 0.0994 | 0.0902 | 0.2375 |
| deepseek_self | 0.5 | 43 | 11 | 0.2181 | 0.0994 | 0.0902 | 0.2375 |
| deepseek_self | 0.6 | 43 | 11 | 0.2181 | 0.0994 | 0.0902 | 0.2375 |
| deepseek_self | 0.7 | 43 | 11 | 0.2181 | 0.0994 | 0.0902 | 0.2375 |
| deepseek_self | 0.8 | 46 | 11 | 0.1933 | 0.0696 | 0.0462 | 0.2188 |
| deepseek_self | 0.9 | 49 | 11 | 0.1675 | 0.0000 | 0.0000 | 0.2000 |
| deepseek_cross | 0.0 | 20 | 6 | 0.3522 | 0.0955 | 0.3522 | 0.3500 |
| deepseek_cross | 0.5 | 20 | 6 | 0.3522 | 0.0955 | 0.3522 | 0.3500 |
| deepseek_cross | 0.6 | 20 | 6 | 0.3522 | 0.0955 | 0.3522 | 0.3500 |
| deepseek_cross | 0.7 | 20 | 6 | 0.3522 | 0.0955 | 0.3522 | 0.3500 |
| deepseek_cross | 0.8 | 41 | 9 | 0.2213 | 0.0438 | 0.1037 | 0.2375 |
| deepseek_cross | 0.9 | 47 | 10 | 0.1762 | 0.0399 | 0.0156 | 0.2062 |
| mimo_self | 0.0 | 18 | 3 | 0.3221 | -0.0356 | 0.3436 | 0.3187 |
| mimo_self | 0.5 | 18 | 3 | 0.3221 | -0.0356 | 0.3436 | 0.3187 |
| mimo_self | 0.6 | 18 | 3 | 0.3221 | -0.0356 | 0.3436 | 0.3187 |
| mimo_self | 0.7 | 18 | 3 | 0.3221 | -0.0356 | 0.3436 | 0.3187 |
| mimo_self | 0.8 | 33 | 10 | 0.2636 | 0.0980 | 0.1844 | 0.2687 |
| mimo_self | 0.9 | 44 | 11 | 0.1813 | 0.0559 | 0.0310 | 0.2062 |
| mimo_cross | 0.0 | 40 | 11 | 0.2226 | 0.1064 | 0.1045 | 0.2375 |
| mimo_cross | 0.5 | 40 | 11 | 0.2226 | 0.1064 | 0.1045 | 0.2375 |
| mimo_cross | 0.6 | 40 | 11 | 0.2226 | 0.1064 | 0.1045 | 0.2375 |
| mimo_cross | 0.7 | 40 | 11 | 0.2226 | 0.1064 | 0.1045 | 0.2375 |
| mimo_cross | 0.8 | 45 | 11 | 0.1813 | 0.0559 | 0.0310 | 0.2062 |
| mimo_cross | 0.9 | 46 | 11 | 0.1727 | 0.0394 | 0.0156 | 0.2000 |

## 8. 输入隔离与审计

| 臂 | 请求 body 与 dry-run 一致 | 隔离违规 | 模板 SHA-256 | 结果 SHA-256 |
| --- | --- | ---: | --- | --- |
| deepseek_self | 60/60 | 0 | 4bcf7a4807065fc1… | 9c3ec81d120869b8… |
| deepseek_cross | 60/60 | 0 | 4bcf7a4807065fc1… | 885d27773dd5a3cb… |
| mimo_self | 58/58 | 0 | 4bcf7a4807065fc1… | 814e93f3f6fadc7e… |
| mimo_cross | 58/58 | 0 | 4bcf7a4807065fc1… | 057708eac0afa99f… |

`api_key_value_stored=false`、`authorization_header_stored=false` 在四份 manifest 中均已核对；
运行产物不含 API key 或 Authorization 头。

## 9. 结论

以四个臂的实际结果为准（不预设方向）：

1. **撤销的 FP/TP 构成**：
   - `deepseek_self`：撤销 54 个正例，其中 FP 11、TP 43；撤销精确率 20.4%（正例中 FP 基准率 18.3%），超几何 Holm p=0.8380。
   - `deepseek_cross`：撤销 26 个正例，其中 FP 6、TP 20；撤销精确率 23.1%（正例中 FP 基准率 18.3%），超几何 Holm p=0.8380。
   - `mimo_self`：撤销 21 个正例，其中 FP 3、TP 18；撤销精确率 14.3%（正例中 FP 基准率 19.0%），超几何 Holm p=0.8494。
   - `mimo_cross`：撤销 51 个正例，其中 FP 11、TP 40；撤销精确率 21.6%（正例中 FP 基准率 19.0%），超几何 Holm p=0.8367。
2. **指标方向（主规则）**：
   - `deepseek_self`：Δmacro-F1 -0.2043，ΔMCC +0.0646，Δrecall -0.3386，Δprecision +0.1833，Δstrict acc -0.2000。
   - `deepseek_cross`：Δmacro-F1 -0.0701，ΔMCC +0.0607，Δrecall -0.1654，Δprecision +0.0583，Δstrict acc -0.0875。
   - `mimo_self`：Δmacro-F1 -0.0846，ΔMCC -0.0481，Δrecall -0.1496，Δprecision -0.0326，Δstrict acc -0.1000。
   - `mimo_cross`：Δmacro-F1 -0.1842，ΔMCC +0.0938，Δrecall -0.3150，Δprecision +0.1897，Δstrict acc -0.1813。
3. **事后 refutation-only 规则**：
   - `deepseek_self`：撤销数从 54 降到 18（TP 14 / FP 4），macro-F1=0.3749，MCC=0.0517；撤销精确率 22.2%，Holm p=1.0000。
   - `deepseek_cross`：撤销数从 26 降到 8（TP 6 / FP 2），macro-F1=0.4075，MCC=0.0697；撤销精确率 25.0%，Holm p=1.0000。
   - `mimo_self`：撤销数从 21 降到 6（TP 6 / FP 0），macro-F1=0.3696，MCC=-0.0339；撤销精确率 0.0%，Holm p=1.0000。
   - `mimo_cross`：撤销数从 51 降到 17（TP 13 / FP 4），macro-F1=0.3645，MCC=0.0380；撤销精确率 23.5%，Holm p=1.0000。
4. **成本**：验证只跑正例（60 / 58 条），但增量成本为第一遍检测成本的 +26.5%–+144.6%（见 §3）；若撤销没有显著偏向 FP，这笔钱只是把操作点变保守，而不是提升判别力。
5. **捷径**：把同预算的随机撤销、第一遍 confidence、证据行数、函数长度/调用数放进
   同一张表后，验证器是否真的优于这些廉价规则，见 §5.2 与 §2.5；优于随机才谈得上
   “证据检查”。
6. **探索性**：以上全部是 test 上的一次运行，没有多 seed、没有独立复现，且验证器提示
   是在已知 test 现象后写的。不能写成“独立确认”或“新方法在测试集上验证有效”。

## 10. 限制

- 单次运行、temperature=0 不保证确定性；没有多 seed 方差。
- 只有 160 条测试函数、32 个非漏洞样本；32 条里的 11 个正例 FP 支撑不起精确的 FPR 结论。
- 验证器只看正例，因此对 FN 没有任何作用；召回只会下降或不变。
- 第一遍有 1（DeepSeek）/2（MiMo）条 schema-invalid 记录，其中包含正例，但没有可验证的
  claim，二次验证无法处理；它们在 strict 口径里始终算错。
- 跨模型验证器不是“独立的人工标注”，只是不同模型的另一次判断；两模型共享同一批
  预训练语料与同一份测试函数，一致性高不代表正确。
- 验证器只看到函数体，无法证明跨函数/调用者约束；它撤销的“缺陷”里可能包含真实的、
  需要上下文才能成立的漏洞。
- 反例是模型生成的文本，没有编译或执行验证。
- 阈值/捷径基线在 dev 上拟合，但 dev 只有 8 个负例；test-tuned 上界仅作描述。
- 所有结果都是探索性、事后分析，不是独立确认。

## 11. 复现

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 evidence_verify/selftest.py
bash evidence_verify/run_verify.sh deepseek_self dryrun
bash evidence_verify/run_verify.sh deepseek_self test
bash evidence_verify/run_verify.sh deepseek_cross test
bash evidence_verify/run_verify.sh mimo_self test
bash evidence_verify/run_verify.sh mimo_cross test
python3 evidence_verify/analyze.py
```

`run_verify.sh` 在目标目录已有 manifest 时自动加 `--resume`；请求按内容哈希缓存在 run 目录。
脚本不写 `evidence_prompt/`、`runner/runs/`、`splits/` 或任何旧结果。


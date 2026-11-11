# 证据行 / 反事实提示：SecVulEval 冻结 160 检测测试

生成时间（UTC）：`2026-11-11T19:32:21+00:00`

## 1. 运行身份与输入隔离

| 模型 | 新证据提示 run | 直接提示基线 run | 模型输入 | 请求数 | 数据集 SHA-256 |
| --- | --- | --- | --- | ---: | --- |
| deepseek | `/mnt/c/Users/tzh03/Downloads/cs224proj/evidence_prompt/runs/test_evidence_deepseek` | `/mnt/c/Users/tzh03/Downloads/cs224proj/runner/runs/test_v1_direct_independent` | 仅 `func_body`（带行号） | 160 | `bc83af63329963cb…` |
| mimo | `/mnt/c/Users/tzh03/Downloads/cs224proj/evidence_prompt/runs/test_evidence_mimo` | `/mnt/c/Users/tzh03/Downloads/cs224proj/runner/runs/test_v1_mimo_direct_independent` | 仅 `func_body`（带行号） | 160 | `bc83af63329963cb…` |

两个新 run 都只把函数源码放进 `FUNCTION_SOURCE`，不含 `context`、标签、`changed_lines`、CVE/CWE、项目/文件路径、commit 信息、修复函数或 `fixed_func_idx`。逐样本的 `only_source_variable` 与 `source_reconstructed` 在分析前被强制校验。

请求体审计：deepseek 160/160（全部一致）；mimo 160/160（全部一致） 的 `body_sha256` 与 dry-run 请求逐条比对。

### 关键结果（先看这里）

- **deepseek**（共同 valid）：recall 0.2913 → 0.3858（Δ 0.0945，Holm p=0.0055）；FPR 0.2500 → 0.3438（Δ 0.0938，Holm p=0.2500）；strict acc（全 160）0.3875 → 0.4375。
- **mimo**（共同 valid）：recall 0.2437 → 0.3529（Δ 0.1092，Holm p=0.0010）；FPR 0.2069 → 0.3448（Δ 0.1379，Holm p=0.2500）；strict acc（全 160）0.3250 → 0.4188。

结论先行：两个模型的召回都显著提高（Holm 校正后仍显著），但假阳性点估计也上升；FPR 的配对检验不显著，主要受 32 个非漏洞样本的限制。因此**不能声称“提高召回而不增加假阳性”已经实现**。

## 2. 主要检测指标

分母：每个模型 160 个冻结测试函数（128 漏洞 / 32 非漏洞）。`valid` 是 schema-valid 且成功返回的预测；`strict` 把所有 invalid/API error 算错。

| 模型/提示 | valid | coverage | P | R | F1+ | macro-F1 | strict acc |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek / direct | 160/160 | 1.0000 | 0.8261 | 0.2969 | 0.4368 | 0.3828 | 0.3875 |
| deepseek / evidence | 159/160 | 0.9938 | 0.8167 | 0.3858 | 0.5241 | 0.4223 | 0.4375 |
| mimo / direct | 150/160 | 0.9375 | 0.8056 | 0.2417 | 0.3718 | 0.3456 | 0.3250 |
| mimo / evidence | 158/160 | 0.9875 | 0.8103 | 0.3701 | 0.5081 | 0.4067 | 0.4188 |

召回率与 FPR 的 Wilson 95% 区间（valid-only）：

| 模型/提示 | recall [95% CI] | FPR [95% CI] |
| --- | --- | --- |
| deepseek / direct | 0.2969 [0.2246, 0.3810] | 0.2500 [0.1325, 0.4211] |
| deepseek / evidence | 0.3858 [0.3057, 0.4727] | 0.3438 [0.2041, 0.5169] |
| mimo / direct | 0.2417 [0.1739, 0.3255] | 0.2333 [0.1179, 0.4093] |
| mimo / evidence | 0.3701 [0.2911, 0.4567] | 0.3548 [0.2112, 0.5305] |

## 3. 与原 direct 的逐样本配对检验

主检验：在共同 valid 的样本上，用精确 McNemar 检验配对正确性；召回检验只用漏洞样本，FPR 检验只用非漏洞样本。四个主检验做 Holm 校正（2 模型 × 2 终点）。共同 valid 与子集规模：deepseek 共同 159，召回 n=127，FPR n=32；mimo 共同 148，召回 n=119，FPR n=29（invalid 记录被排除）。

| 模型 | n 共同 valid | Δrecall | 召回 McNemar p | Holm p | ΔFPR | FPR McNemar p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | 159 | 0.0945 | 0.0018 | 0.0055 | 0.0938 | 0.2500 | 0.2500 |
| mimo | 148 | 0.1092 | 0.0002 | 0.0010 | 0.1379 | 0.1250 | 0.2500 |


配对 discordant 计数（evidence 相对 direct）：

| 模型 | 召回 新增 TP / 丢失 TP | FPR 新增 FP / 修复 FP |
| --- | ---: | ---: |
| deepseek | +13 / −1 | +3 / −0 |
| mimo | +13 / −0 | +4 / −0 |

两个模型都是“新增 TP 远多于丢失 TP”，但新增 FP 没有任何修复；这正是召回上升、FPR 也上升的来源。

配对 cluster bootstrap（10,000 次，seed 42，按项目聚类；95% 百分位区间）：

| 模型 | Δrecall [95% CI] | ΔFPR [95% CI] | ΔF1+ [95% CI] | Δmacro-F1 [95% CI] |
| --- | --- | --- | --- | --- |
| deepseek | 0.0288 … 0.1810 | 0.0000 … 0.2821 | 0.0254 … 0.1546 | -0.0193 … 0.0948 |
| mimo | 0.0515 … 0.1923 | 0.0385 … 0.2727 | 0.0543 … 0.1653 | 0.0005 … 0.0882 |

严格口径（160 个记录，invalid/error 算错）的配对检验：

| 模型 | direct strict acc | evidence strict acc | Δstrict | McNemar p | Δcoverage |
| --- | ---: | ---: | ---: | ---: | ---: |
| deepseek | 0.3875 | 0.4375 | 0.0500 | 0.0963 | -0.0062 |
| mimo | 0.3250 | 0.4188 | 0.0938 | 0.0026 | 0.0500 |

严格口径的构成（strict 把 invalid 算错，因此混入格式合规差异）：

| 模型 | direct invalid (V/N) | evidence invalid (V/N) | 共同 valid Δaccuracy | strict Δaccuracy |
| --- | ---: | ---: | ---: | ---: |
| deepseek | 0 (0/0) | 1 (1/0) | 0.0566 | 0.0500 |
| mimo | 10 (8/2) | 2 (1/1) | 0.0608 | 0.0938 |

MiMo 的 strict 提升大于共同 valid 的 accuracy 提升，部分来自 schema 合规：direct 的 10 条 invalid 中有 8 条漏洞样本和 2 条非漏洞样本，evidence 只有 2 条 invalid。因此 MiMo 的 strict 数字不能全部解释为检测能力提升。

### 操作点偏移与判别力

- deepseek（共同 valid）：predicted positive rate 0.2830 → 0.3774；Δbalanced accuracy 0.0004；ΔMCC -0.0020。
- mimo（共同 valid）：predicted positive rate 0.2365 → 0.3514；Δbalanced accuracy -0.0143；ΔMCC -0.0276。

证据提示明显提高了“报正例”的比例；balanced accuracy 和 MCC 在共同 valid 上没有提升（DeepSeek 基本持平，MiMo 略降）。因此召回/F1 的上升主要来自操作点向“多报”移动，而不是判别力提升。

## 4. 证据行可审计性

证据行按提示中打印的 1-based 行号审计。`grounded` 表示所引行都不是空行。漏洞样本的 `changed_lines` 被映射回函数体行号（文件级行号减去函数起始偏移）；映射只用于评估，不进入提示。`随机基线` 是：在同一个函数里随机抽同样多的行，至少碰到一个修复行的期望概率（按超几何分布计算，再对 TP 取平均）。

| 模型 | valid 正例 | 平均引用行数 | grounded | 反事实确认 | TP | TP 映射样本 | exact hit | ±3 hit | 文本命中 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | 60 | 6.9500 | 1.0000 | 1.0000 | 49 | 43 | 0.4884 | 0.6279 | 0.4884 |
| mimo | 58 | 5.0345 | 1.0000 | 0.9828 | 47 | 44 | 0.4545 | 0.6364 | 0.4773 |

与随机引用基线对比（仅 TP 且 `changed_lines` 可映射的样本）：

| 模型 | exact hit | exact 随机基线 | ±3 hit | ±3 随机基线 | 引用行精确率 | 引用行 ±3 精确率 | 修复行 exact 召回 | 修复行 ±3 召回 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | 0.4884 | 0.3446 | 0.6279 | 0.6250 | 0.2189 | 0.3434 | 0.1633 | 0.3568 |
| mimo | 0.4545 | 0.3159 | 0.6364 | 0.5966 | 0.2555 | 0.3965 | 0.1461 | 0.3123 |

映射质量（全部 128 个漏洞样本）：

- deepseek: full=108, partial=9, none=11, 修复行条目 683/716 可映射。
- mimo: full=108, partial=9, none=11, 修复行条目 683/716 可映射。

真阳性与假阳性的证据质量对比：

| 模型 | TP grounded | FP grounded | TP counterfactual | FP counterfactual |
| --- | ---: | ---: | ---: | ---: |
| deepseek | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| mimo | 1.0000 | 1.0000 | 0.9787 | 1.0000 |

事后敏感性分析（不是主终点）：把“未 grounded 或反事实未确认”的正例改判为负例，或直接视为 abstain（invalid），重新计算指标：

| 模型 | 策略 | valid | P | R | F1+ | strict acc |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| deepseek | conservative | 159/160 | 0.8167 | 0.3858 | 0.5241 | 0.4375 |
| deepseek | abstain | 159/160 | 0.8167 | 0.3858 | 0.5241 | 0.4375 |
| mimo | conservative | 158/160 | 0.8070 | 0.3622 | 0.5000 | 0.4125 |
| mimo | abstain | 157/160 | 0.8070 | 0.3651 | 0.5027 | 0.4125 |

## 5. 成本与延迟

成本按原 baseline 的价格配置计算（DeepSeek 0.30/1.20/0.006，MiMo 0.14/0.28/0.0028 USD/1M）。直接基线的 run 同时包含 detection+repair，因此其总成本/总 wall 不可与新 run 直接相加比较；这里只比较 detection 记录的逐请求成本与延迟。

| 模型/提示 | 总 USD | 每 100 单元 USD | 每 TP USD | prompt tokens 均值 | completion tokens 均值 | 延迟 p50 s | 延迟 p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek / direct | 0.066988 | 0.041868 | 0.001763 | 1032.8 | 90.7 | 5.65 | 10.83 |
| deepseek / evidence | 0.085622 | 0.053514 | 0.001747 | 1750.9 | 122.7 | 6.04 | 12.06 |
| mimo / direct | 0.024397 | 0.015248 | 0.000841 | 960.4 | 78.1 | 4.59 | 12.00 |
| mimo / evidence | 0.035933 | 0.022458 | 0.000765 | 1835.5 | 116.4 | 4.05 | 10.87 |

## 6. 失败分类

| 模型/提示 | ok | invalid | API error | invalid 家族 |
| --- | ---: | ---: | ---: | --- |
| deepseek / direct | 160 | 0 | 0 | `{}` |
| deepseek / evidence | 159 | 1 | 0 | `{'semantic': 1}` |
| mimo / direct | 150 | 10 | 0 | `{'unknown': 10}` |
| mimo / evidence | 158 | 2 | 0 | `{'semantic': 2}` |

MiMo direct 的 10 条 invalid 都是把 `is_vulnerable` 写成 `is_vulnerability`；旧 runner 没有 `error_family` 字段，因此表中显示为 `unknown`。

## 7. 结论与限制

- 这是**单模型、单次运行**；temperature=0 不保证确定性。所有 p 值和区间只描述这 160 个冻结样本。
- 主终点是 recall 与 FPR 的配对 McNemar；Holm 只覆盖四个主检验。F1/macro-F1 的 bootstrap 区间是探索性的。
- 非漏洞样本只有 32 个，FPR 的区间很宽；不能据此声称稳定的假阳性率。
- `changed_lines` 到函数体行号的映射不是 100% 完整；exact/±3 hit 只在可映射的 TP 上计算，分母已列出。
- 证据行是模型自报，不是执行证明；反事实修复没有编译或测试，只是模型自检。
- 操作点分析：证据提示的 predicted positive rate 明显上升（共同 valid：DeepSeek 28.3%→37.7%，MiMo 23.7%→35.1%）；Δbalanced accuracy 为 +0.0004 / −0.0143，ΔMCC 为 −0.0020 / −0.0276。召回/F1 的上升主要来自操作点向“多报”移动，而不是判别力提升。
- 结构审计通过不等于定位正确：引用行全部在范围内且非空，但与 `changed_lines` 的 ±3 重合率接近同样引用行数下的随机基线；精确重合略高于随机基线。不能把证据行当作可靠的漏洞定位。
- 反事实确认率在 TP 和 FP 上都接近 1，未表现出区分真伪正例的能力；它不能替代独立验证。
- 两个模型的结果不可直接横比：DeepSeek 为 non-thinking，MiMo 在该端点上需要 `reasoning_effort=none` 才关闭推理；模型、价格和延迟口径不同。
- 直接基线 run 还包含 repair 请求；本报告只取其中的 detection 记录，未改写任何旧结果。


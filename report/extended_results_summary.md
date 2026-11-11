# SecVulEval 扩展实验结果摘要（2026-11-12，v2 同步版）

本文件汇总 `report/report_extended_zh.tex` / `report_extended_zh.pdf` 使用的真实扩展结果。所有数值来自冻结产物，未使用估计值、文献值或 mock。旧版 `report_zh.tex` / `report_zh.pdf` 未修改；本文件与扩展版报告只新增内容。

本轮同步的三项变化：（1）Juliet 证据混合以泄漏修复后的 v2 为主结果，v1 只作审计；（2）Juliet LLM 改用 postleakfix 运行（95.0%），修复前 95.7% 只作审计；（3）成本按 `analysis/cost_normalization.json` 分列 configured 与 normalized provider-list，修复 all-in 修正为 0.082550 美元。

## 0. 范围与来源

| 部分 | 数据 / 运行 | 来源 |
| --- | --- | --- |
| Tier A 检测/配对 | SecVulEval 冻结测试集：160 条检测函数（128 正/32 负）、180 对（360 条函数） | `runner/runs/test_v1_*`、`runner/runs/test_v1_mimo_*`、`benchmark/results/tier_a_summary.json` |
| Tier A 模型比较 | 2 模型 × 3 策略 × 2 任务；每模型 2{,}484 请求 | `benchmark/results/tier_a_leaderboard.md`、`benchmark/results/comparisons/tier_a/` |
| Pair-joint | 180 对，每对 1 次请求，强制 A/B | `pair_joint/results/comparison.json` |
| 证据提示 | 160 条检测函数 × 2 模型 | `evidence_prompt/analysis/metrics.json` |
| Juliet 静态/动态 | Juliet CWE-401 test 140（70 bad/70 good） | `benchmark/results/tier_b_summary.json` |
| Juliet LLM | test 140，MiMo，Xiaomi 官方端点 fallback；修复后正式 + 复现，修复前仅审计 | `juliet_llm/runs/*postleakfix*/metrics.json`、`juliet_llm/runs/*official_final/metrics.json` |
| Juliet 证据混合 | 2 模型 × 5 方法 × 140 单元 = 1{,}400 请求；v2 主结果，v1 审计 | `hybrid/results/hybrid_v2_metrics.json`、`hybrid_v2_vs_hybrid_v1.json`、`hybrid_v1_metrics.json` |
| Juliet 修复闭环 | 70 个 test bad 单元；58 个 LSan 可观测 | `juliet_repair/report/comparison.json` |
| 成本归一化 | 73 个有 usage 的 run、9,584 次请求 | `analysis/cost_normalization.json`、`analysis/cost_normalization.md` |

**分层原则**：Tier A（真实项目函数片段）与 Tier B（Juliet 合成单 CWE-401）不池化、不横比。两层的标签来源、单元结构、类别先验、分母和成本口径不同；本文只分别回答各自的问题。

## 1. Tier A 检测（160 条：128 正 / 32 负）

| 模型 | 策略 | 有效 | P | R | Macro-F1 [95% CI] | MCC | strict Acc | 任务 USD | p95 (s) |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 160/160 | 0.826 | 0.297 | 0.383 [0.305, 0.552] | 0.041 | 0.388 | 0.066988 | 10.83 |
| DeepSeek | few-shot | 160/160 | 0.837 | 0.320 | 0.399 [0.305, 0.593] | 0.061 | 0.406 | 0.136741 | 9.69 |
| DeepSeek | context | 160/160 | 0.812 | 0.305 | 0.381 [0.286, 0.560] | 0.020 | 0.388 | 0.070308 | 10.71 |
| MiMo | direct | 150/160 | 0.806 | 0.242 | 0.346 [0.264, 0.528] | 0.008 | 0.325 | 0.024397 | 12.00 |
| MiMo | few-shot | 160/160 | 0.773 | 0.266 | 0.346 [0.262, 0.512] | −0.042 | 0.350 | 0.034011 | 11.03 |
| MiMo | context | 153/160 | 0.861 | 0.252 | 0.365 [0.278, 0.571] | 0.080 | 0.350 | 0.025568 | 8.38 |

- DeepSeek 的 few-shot 0.399 只是数值最高；三个区间高度重叠，两两差值区间全部跨 0（M1−M2 = −0.017 [−0.058, 0.012]；M1−M3 = 0.001 [−0.033, 0.036]；M2−M3 = 0.018 [−0.010, 0.066]）。
- MiMo 的 coverage 不是 1.000：direct 10 条 invalid、context 7 条、few-shot 0 条；strict accuracy 0.325–0.350。
- 多数类基线（全判漏洞）Accuracy 80.0%、Specificity 0、MCC 0；不能把接近 80% 的准确率当作检测能力。

## 2. Tier A 配对（180 对 / 360 条函数）

| 模型 | 策略 | 正确/180 | DA(valid) [95% CI] | DA(all) | 双报漏洞 | 双报安全 | 判反 | 有效/180 | 任务 USD |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 21 | 11.7 [7.8, 17.2] | 11.7 | 44 | 113 | 2 | 180/180 | 0.138323 |
| DeepSeek | few-shot | 16 | 8.9 [5.5, 14.0] | 8.9 | 49 | 113 | 2 | 180/180 | 0.294895 |
| DeepSeek | context | 22 | 12.2 [8.2, 17.8] | 12.2 | 49 | 108 | 1 | 180/180 | 0.144837 |
| MiMo | direct | 14 | 9.1 [5.5, 14.7] | 7.8 | 27 | 108 | 5 | 154/180 | 0.048290 |
| MiMo | few-shot | 17 | 9.4 [6.0, 14.6] | 9.4 | 40 | 117 | 6 | 180/180 | 0.067880 |
| MiMo | context | 19 | 11.4 [7.5, 17.2] | 10.6 | 38 | 106 | 3 | 166/180 | 0.049967 |

- 测试集随机指定一侧的双方均正确率为 56.1%（101/180，解析期望 50%）；所有策略都远低于机会水平。
- 主要失败是双报安全（108–117 对）和双报漏洞（27–49 对），不是判反（1–6 对）。

## 3. Tier A 模型比较（DeepSeek − MiMo，同策略/同任务）

| 任务 | 策略 | Δ | 95% CI | n common | b/c | 原始 p | Holm p |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| 检测 | direct | 0.031 | [−0.018, 0.077] | 150 | 11/6 | 0.3323 | 0.6646 |
| 检测 | few-shot | 0.053 | [0.010, 0.129] | 160 | 15/6 | 0.0784 | 0.2351 |
| 检测 | context | 0.009 | [−0.070, 0.058] | 153 | 10/8 | 0.8145 | 0.8145 |
| 配对 | direct | 0.032 | [−0.013, 0.078] | 154 | 9/4 | 0.2668 | 0.8005 |
| 配对 | few-shot | −0.006 | [−0.039, 0.028] | 180 | 4/5 | 1.0000 | 1.0000 |
| 配对 | context | 0.000 | [−0.042, 0.042] | 166 | 6/6 | 1.0000 | 1.0000 |

- 6 个比较经 Holm 后均不显著。
- few-shot 检测的 bootstrap 区间排除 0，但 McNemar Holm p=0.2351；报告同时给出两者，不把任一单独结果当排名依据。
- 模型内 12 组策略比较也全部不显著；MiMo 复制了“没有稳定策略优胜者”的结论。

## 4. Tier A 成本（configured 口径）

| 模型 | 检测 macro-F1 均值（范围） | 配对 DA 均值（范围） | 平均覆盖 | 六 run USD | USD/100 请求 | p50/p95 (s) | 请求 |
| --- | --- | --- | ---: | ---: | ---: | --- | ---: |
| DeepSeek | 0.388 (0.381–0.399) | 0.109 (0.089–0.122) | 1.000 | 2.439219 | 0.098197 | 5.50/10.55 | 2{,}484 |
| MiMo | 0.352 (0.346–0.365) | 0.100 (0.091–0.114) | 0.945 | 0.623154 | 0.025087 | 4.41/10.13 | 2{,}484 |

- 表中 USD 是 run 记录的 configured 口径：DeepSeek 0.30/1.20/0.006（高峰价），MiMo 0.14/0.28/0.0028。按 provider-list 非高峰价 0.15/0.60/0.003 归一化后，direct/context 约为 0.49–0.50 倍，few-shot 因 legacy 记录不扣缓存为 0.26–0.29 倍；MiMo 不变。两列不得混用，见 §11。
- MiMo 更便宜、略快，但平均 coverage 0.945；按“每有效预测”计，差距会缩小。
- MiMo 还需 `reasoning_effort=none` + `max_completion_tokens` 才与非思考模式语义对齐。因此这是“模型 + 配置”比较。

## 5. Pair-joint 强制二选一（180 对）

| 模型 | 正确 | DA [95% CI] | 判反 | DA(A) | DA(B) | Δ(A−B) | Fisher p | 证据合规 | 定位命中 | USD |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 138/180 | 76.7 [70.0, 82.2] | 42 | 92.2 | 61.1 | 31.1 | 1.00×10⁻⁶ | 98.3 | 93.0 | 0.153593 |
| MiMo | 156/180 | 86.7 [80.9, 90.9] | 24 | 88.9 | 84.4 | 4.4 | 0.5114 | 97.8 | 95.9 | 0.071803 |

- 与分侧 direct 相比：DeepSeek DA 11.7%→76.7%（+65.0 pp，项目聚类 CI [58.6, 77.9]，McNemar p=3.6×10⁻³⁴）；MiMo 7.8%→86.7%（+78.9 pp，CI [74.1, 87.6]，p=3.6×10⁻⁴³）。
- 但强制二选一改变了任务：分侧 both-safe 113/108 对被消除，DA 提升不能单独归因于“看到另一版本”。
- 长度启发式“选字符较短版本，等长选 A”单独 134/180 = 74.4%；DeepSeek 76.7% 与它不可区分（McNemar b=25,c=21,p=0.6587），MiMo 86.7% 显著高于它（b=29,c=7,p=0.0003）。
- 分长度层：DeepSeek 漏洞更短 109/130=83.8%、漏洞更长 25/44=56.8%、等长 4/6；MiMo 123/130=94.6%、28/44=63.6%、5/6。
- DeepSeek A/B 位置差 31.1 pp（Fisher p=1.0×10⁻⁶，选 A 118/180=65.6%）；MiMo 4.4 pp（p=0.511，选 A 94/180=52.2%）。该审计是测试后诊断，不是预注册基线。

## 6. 结构化证据提示（SecVulEval 160 条）

| 模型 | 提示 | 有效 | P | R | F1+ | Macro-F1 | strict Acc | 预测正类率 | USD | p95 (s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 160/160 | 0.826 | 0.297 | 0.437 | 0.383 | 0.388 | 0.287 | 0.066988 | 10.83 |
| DeepSeek | evidence | 159/160 | 0.817 | 0.386 | 0.524 | 0.422 | 0.438 | 0.377 | 0.085622 | 12.06 |
| MiMo | direct | 150/160 | 0.806 | 0.242 | 0.372 | 0.346 | 0.325 | 0.240 | 0.024397 | 12.00 |
| MiMo | evidence | 158/160 | 0.810 | 0.370 | 0.508 | 0.407 | 0.419 | 0.367 | 0.035933 | 10.87 |

配对检验（共同 valid；2 模型 × 2 终点 Holm）：

| 模型 | 终点 | Δ (pp) | 不一致（新/旧） | 原始 p | Holm p |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek | 召回 | +9.4 | 13/1 | 0.0018 | 0.0055 |
| DeepSeek | FPR | +9.4 | 3/0 | 0.2500 | 0.2500 |
| MiMo | 召回 | +10.9 | 13/0 | 2.44×10⁻⁴ | 0.0010 |
| MiMo | FPR | +13.8 | 4/0 | 0.1250 | 0.2500 |

- 召回提升在两个模型上都通过 Holm；FPR 点估计上升，但 32/29 个负例的功效不足以判显著。不能声称“未增加假阳性”。
- 操作点移动：预测正类率 28.3%→37.7%（DeepSeek）、23.7%→35.1%（MiMo）；Δbalanced accuracy +0.0004/−0.0143，ΔMCC −0.0020/−0.0276。F1 的上升主要来自“更敢报正例”，不是判别力提升。
- MiMo 的 strict +9.4 pp 部分来自格式合规恢复：direct 10 条 invalid（8 正/2 负），evidence 2 条；共同 valid accuracy 提升 +6.1 pp。
- 证据行审计：DeepSeek exact 48.8% vs 随机 34.5%，±3 62.8% vs 62.5%；MiMo 45.5% vs 31.6%，±3 63.6% vs 59.7%。引用行 exact 精确率 21.9%/25.6%，修复行 exact 召回 16.3%/14.6%。反事实自检在 TP 和 FP 上都接近 1，不能当独立 oracle。

## 7. Juliet CWE-401 静态/动态（test 140：70 bad / 70 good）

| 方法 | 有效 | 覆盖 | TP/FP/TN/FN | P | R | Spec | Macro-F1 [95% CI] | MCC | strict |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: |
| Clang SA 22.1.8 | 136/140 | 0.971 | 53/0/68/15 | 1.000 | 0.779 | 1.000 | 0.888 [0.818, 0.948] | 0.799 | 0.864 |
| Cppcheck 2.21.0 | 140/140 | 1.000 | 22/4/66/48 | 0.846 | 0.314 | 0.943 | 0.588 [0.497, 0.671] | 0.331 | 0.629 |
| ASan+LSan | 140/140 | 1.000 | 58/0/70/12 | 1.000 | 0.829 | 1.000 | 0.914 [0.850, 0.966] | 0.841 | 0.914 |
| ASan+LSan+Valgrind | 140/140 | 1.000 | 58/0/70/12 | 1.000 | 0.829 | 1.000 | 0.914 [0.850, 0.966] | 0.841 | 0.914 |
| Valgrind 3.27.1 | 140/140 | 1.000 | 58/0/70/12 | 1.000 | 0.829 | 1.000 | 0.914 [0.850, 0.966] | 0.841 | 0.914 |

- Clang 的 4 个 `compile_error` 保留在 strict 分母，valid-only macro-F1 排除；从未写成 `y_pred=0`。
- 动态 conservative 视图：58/140 有效、coverage 0.414、82 个 clean 弃权、macro-F1 未定义；在可观测 58 个单元上 recall=precision=1.000。clean 只表示“执行路径上未观察到 leak”，不是 TN。
- runtime-supported 128：ASan/Valgrind 1.000，但该子群由 LSan preflight 定义，存在循环性；Clang 0.917、Cppcheck 0.564。Valgrind/静态更有信息量。

## 8. Juliet LLM 直接检测（MiMo，test 140，Xiaomi 官方端点）

| 运行 | 有效 | TP | FP | TN | FN | Acc (%) | F1 | MCC | 参考 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 修复后正式 | 140/140 | 68 | 5 | 65 | 2 | 95.00 | 0.951 | 0.901 | 0.003180 |
| 修复后复现 | 140/140 | 68 | 5 | 65 | 2 | 95.00 | 0.951 | 0.901 | 0.003081 |
| 修复前（仅审计） | 140/140 | 68 | 4 | 66 | 2 | 95.71 | 0.958 | 0.915 | 0.004426 |

- 主结果：修复后 95.0% / F1 0.951 / MCC 0.901；两次运行混淆矩阵完全相同，说明该结果在该端点上可重复。
- 修复前 95.7% 只作审计；修复后只多 1 个 FP，方向与清洗掉 6 个 good 单元的标签字面量一致，但只有 1 个单元变化，不能把差值单独归因于清洗。
- 端点：Xiaomi 官方 OpenAI 兼容端点（`https://api.xiaomimimo.com/v1`），不是 OpenCode Go；相同模型 ID 不等于相同服务栈。
- 分语言：C 58 单元 93.10%，C++ 82 单元 96.34%；7 个错误为 5 FP + 2 FN。评分按实际 label 字段。
- DeepSeek 在 Juliet 上没有结果：OpenCode Go 401 `api_key_expired`、DeepSeek 官方 402 `Insufficient Balance`、qwen 网关 403 `AccessDenied.Unpurchased`。
- `benchmark/results/tier_b_summary.json` 仍把 B4–B8 标为 `blocked_gate`；本运行是独立 `juliet_llm/` 工作流，不登记为 Tier B B4/B5，也不与 Tier A 的 0.383 macro-F1 比较。

## 9. Juliet 证据混合 v2（2 模型 × 5 方法 × 140；1,400/1,400 成功）

| 模型 | 方法 | 正确/140 | Acc (%) | P | R | F1 | Spec | MCC | 列表 USD |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 135/140 | 96.43 | 0.933 | 1.000 | 0.966 | 0.929 | 0.931 | 0.010185 |
| DeepSeek | static | 135/140 | 96.43 | 0.933 | 1.000 | 0.966 | 0.929 | 0.931 | 0.011730 |
| DeepSeek | dynamic | 136/140 | 97.14 | 0.946 | 1.000 | 0.972 | 0.943 | 0.944 | 0.011471 |
| DeepSeek | combined | 136/140 | 97.14 | 0.946 | 1.000 | 0.972 | 0.943 | 0.944 | 0.011891 |
| DeepSeek | shuffled | 134/140 | 95.71 | 0.921 | 1.000 | 0.959 | 0.914 | 0.918 | 0.010860 |
| MiMo | direct | 136/140 | 97.14 | 0.946 | 1.000 | 0.972 | 0.943 | 0.944 | 0.004718 |
| MiMo | static | 135/140 | 96.43 | 0.933 | 1.000 | 0.966 | 0.929 | 0.931 | 0.006287 |
| MiMo | dynamic | 133/140 | 95.00 | 0.932 | 0.971 | 0.951 | 0.929 | 0.901 | 0.005735 |
| MiMo | combined | 136/140 | 97.14 | 0.946 | 1.000 | 0.972 | 0.943 | 0.944 | 0.004813 |
| MiMo | shuffled | 133/140 | 95.00 | 0.920 | 0.986 | 0.952 | 0.914 | 0.902 | 0.004645 |

| 模型 | 对比 | Δ pp [95% CI] | 新对/旧对 | McNemar p |
| --- | --- | --- | ---: | ---: |
| DeepSeek | direct→dynamic | 0.71 [0.00, 2.14] | 1/0 | 1.0000 |
| DeepSeek | direct→combined | 0.71 [0.00, 2.14] | 1/0 | 1.0000 |
| DeepSeek | direct→shuffled | −0.71 [−2.14, 0.00] | 0/1 | 1.0000 |
| DeepSeek | combined→shuffled | −1.43 [−3.57, 0.00] | 0/2 | 0.5000 |
| MiMo | direct→static | −0.71 [−2.14, 0.00] | 0/1 | 1.0000 |
| MiMo | direct→dynamic | −2.14 [−5.00, 0.00] | 0/3 | 0.2500 |
| MiMo | direct→combined | 0.00 [−2.14, 2.14] | 1/1 | 1.0000 |
| MiMo | direct→shuffled | −2.14 [−5.00, 0.00] | 0/3 | 0.2500 |
| MiMo | combined→shuffled | −2.14 [−5.00, 0.00] | 0/3 | 0.2500 |

v1→v2 审计（v1 为清洗前，只作对照）：

| 模型 | 方法 | v1 正确/140 | v2 正确/140 | Δ pp [95% CI] | v1 对→v2 错 / v1 错→v2 对 | McNemar p |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| DeepSeek | direct | 135 | 135 | +0.00 [+0.00, +0.00] | 0/0 | 1.0000 |
| DeepSeek | static | 135 | 135 | +0.00 [+0.00, +0.00] | 0/0 | 1.0000 |
| DeepSeek | dynamic | 139 | 136 | −2.14 [−5.00, +0.00] | 3/0 | 0.2500 |
| DeepSeek | combined | 140 | 136 | −2.86 [−5.71, −0.71] | 4/0 | 0.1250 |
| DeepSeek | shuffled | 135 | 134 | −0.71 [−3.57, +1.43] | 2/1 | 1.0000 |
| MiMo | direct | 135 | 136 | +0.71 [+0.00, +2.14] | 0/1 | 1.0000 |
| MiMo | static | 136 | 135 | −0.71 [−2.14, +0.00] | 1/0 | 1.0000 |
| MiMo | dynamic | 135 | 133 | −1.43 [−3.57, +0.00] | 2/0 | 0.5000 |
| MiMo | combined | 138 | 136 | −1.43 [−3.57, +0.00] | 2/0 | 0.5000 |
| MiMo | shuffled | 135 | 133 | −1.43 [−3.57, +0.00] | 2/0 | 0.5000 |

- v2 中没有任何方法相对 direct 显著；最大单元格差异 2.14 pp，combined 相对 direct 为 +0.71（DeepSeek）和 0.00（MiMo）。
- 6 个被清洗的 good 单元共引起 17 次标签翻转：16 次由对变错、1 次由错变对；134 个未变单元只有 1 次端点噪声翻转。五方法池化准确率从 97.36% 降到 96.36%。
- v1 的 DeepSeek combined 100% 是标签捷径下的上界；v2 为 97.14%，只能作审计案例，不作主结论。
- 安慰剂没有聚合收益：DeepSeek shuffled 134/140、MiMo 133/140，均不高于 direct；相对 direct 只有 1/3 个预测翻转，且全部由对变错。按供体标签，DeepSeek 供体 bad/good 判 vulnerable 为 57.1%/51.4%，MiMo 为 55.7%/51.4%。14 个单元存在 no-op collision。
- 错误集中在 `_22` good：DeepSeek direct 5 个 FP 全是 `_22` good，dynamic/combined 各纠正 1 个；MiMo direct/combined 的 4 个 FP 也全是 `_22` good，dynamic 另有 2 个 FN。
- 动态证据单独 91.43%（58/70 bad 观察到 leak，0 FP），静态任一工具 85.00%，LLM direct 96.43%；证据收益受天花板限制。
- `benchmark/results/tier_b_summary.json` 仍把 B6–B8 标为 `blocked_gate`；本实验是独立 `hybrid/` 工作流，不登记为 B6–B8。

## 10. Juliet 修复闭环（70 个 test bad 单元）

| 模型 | 编译/70 | LSan 干净/70 | 行为保持/70 | 严格通过/58 | 首次/58 | 迭代单元 | 调用 | USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 70 | 70 | 70 | 58 | 58 | 0 | 70 | 0.026990 |
| MiMo | 70 | 70 | 70 | 58 | 57 | 2 | 72 | 0.005841 |

- 严格通过 = 编译通过 + LSan 干净 + 行为保持 + baseline 确实观察到泄漏；12 个不可观测单元不计入（7 个 `malloc_realloc` latent + 5 个 `_68` 全局 reachable）。
- 两个 headline run 合计 configured 0.032831 USD（normalized 0.019336）；configured all-in 为 0.082550 USD（normalized 0.052549），不是旧 README 的 0.077516。差额 0.005034 来自 `parser_dev/mimo_test70_v1`（44/70 单元）。
- 行为只覆盖 stdout 数据行；没有故障注入、没有人类评审；58/58 是“在该 harness 下的严格通过”，不是通用修复正确率。

## 11. 成本口径（configured vs normalized provider-list）

| 组 | run | 调用 | configured $ | normalized $ | provider list $ | allowance $ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 全部完整 run | 71 | 9,532 | 3.886970 | 2.146513 | 2.123231 | 1.624966 |
| headline 17 run | 17 | 2,362 | 0.558073 | 0.365704 | 0.361279 | 0.284329 |
| hybrid v1（审计） | 10 | 1,400 | 0.173865 | 0.114598 | 0.114599 | 0.090891 |
| hybrid v2（主结果） | 10 | 1,400 | 0.082335 | 0.082335 | 0.082335 | 0.059878 |
| juliet_llm 修复后两次 | 2 | 280 | 0.006262 | 0.006262 | n/a | n/a |
| 修复 headline | 2 | 142 | 0.032831 | 0.019336 | 0.019336 | 0.013938 |
| 修复 all-in | 7 | 355 | 0.082550 | 0.052549 | 0.052549 | 0.040550 |

- configured 是 run 记录值；normalized 是按 provider 非高峰 list 价（DeepSeek 0.15/0.60/0.003，MiMo 0.14/0.28/0.0028 USD per 1M）逐条 usage 重算；provider list 是 `usage.opencode.list_cost` 的逐请求求和；allowance 是额度扣减，不与前三列相加。
- DeepSeek configured 0.30/1.20/0.006 是高峰价；本批 9,584 条请求全部落在非高峰窗口（peak rows = 0），所以 v1 的 configured 恰为 normalized 的 2 倍；v2 已直接配置非高峰价，两列相同。MiMo 无峰谷价。
- 另有 2 个未完成 run（52 次请求）configured/normalized 均为 0.008197，单列、不并入 complete-only 合计；6 个无 usage 的失败/空跑不补零。
- Xiaomi 端点不返回 provider list/allowance，按 n/a 处理，不补零；它不是 USD 账单，也不是实际扣款。
- hybrid v1 与 v2 的请求数和 prompt 几乎相同，USD 差异来自价格口径而非工作量。

## 12. 编译与检查（WSL，Tectonic 0.17.0）

- 二进制：Tectonic 0.17.0 x86_64-unknown-linux-musl，SHA-256 `8533d07f9ccbd7a65824b9e0459041bca34af1eb33daba48f59215593753a3b7`，`sha256sum -c` 通过。
- 命令：`/tmp/secvul-tectonic/tectonic -X compile report/report_extended_zh.tex --outdir report --keep-intermediates`。
- `pdfinfo`：27 页，letter 612×792 pt，PDF 1.5，约 843 KiB。
- `pdffonts`：NimbusRoman/NimbusSans/NimbusMonoPS 与 FandolSong/FandolKai 均已嵌入；数学符号使用 CM 字体；无 Type 3。
- 引擎日志：0 个 unresolved reference/citation，0 个 `Missing character`，0 个 `Overfull \hbox`；仅 1 个 0.8 pt 的 `Overfull \vbox`（末页 column balancing，低于 10 pt）。
- `pdftotext`：0 个 `??`，0 个 `[?]`。

## 13. 不能声称的事

1. 不能声称某策略或某模型在所有任务上更优：Tier A 每个单元只有一次运行，6 个模型比较经 Holm 后均不显著；few-shot 检测的区间排除 0 但 McNemar 不显著。
2. 不能把 pair-joint 的 76.7%/86.7% 全部读作“跨版本漏洞推理”：强制二选一改变了任务，长度启发式单独 74.4%，DeepSeek 与它不可区分，且有 31.1 pp 的 A 位置偏差。
3. 不能声称证据提示“提高召回且不增加假阳性”：召回提升通过 Holm，但 FPR 点估计 +9.4/+13.8 pp；BA/MCC 基本持平。证据行 ±3 重合接近随机，反事实自检在 FP 上也接近 1。
4. 不能把 Juliet 的 0.888/0.914/95.0% 与 Tier A 的 0.383 比较：不同数据、标签、先验、分母；Tier B 不能外推到真实项目。
5. 不能声称动态 clean 是安全：没有覆盖率 instrumentation，clean 只是 `NO_LEAK_OBSERVED`；conservative 视图下 macro-F1 未定义。
6. 不能声称修复 58/58 等于补丁语义正确：只有 58/70 可观测，行为只覆盖 stdout，没有故障注入/人类评审。
7. 不能声称 `benchmark/results/tier_b_summary.json` 已登记 Juliet LLM/hybrid：B4–B8 仍为 `blocked_gate`；本摘要把它们写成独立工作流的探索性证据。
8. 不能把 v1 的 DeepSeek combined 100% 当作主结论：它含标签捷径，修复 6 个 good 单元后为 97.14%；v1 只作审计。
9. 不能把 configured、normalized、provider list、allowance 四个成本口径混用或相加：它们不是同一本账。

## 14. 文件与复现

| 文件 | 用途 |
| --- | --- |
| `report/report_extended_zh.tex` | 扩展版中文 IEEE 双栏源稿 |
| `report/report_extended_zh.pdf` | 已编译 PDF（27 页） |
| `report/references_extended.bib` | 扩展版参考文献（28 条） |
| `report/extended_results_summary.md` | 本文件 |
| `report/extended_tables*.tex` | 由 JSON 生成的表 |
| `report/extended_numbers.tex` | 由 JSON 生成的关键数值宏 |
| `report/scripts/build_extended_tables.py` | 只读结果 → LaTeX 表/宏生成器 |
| `report/report_zh.tex` / `.pdf` | 旧版，未修改 |

复现：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 report/scripts/build_extended_tables.py
/tmp/secvul-tectonic/tectonic -X compile \
  report/report_extended_zh.tex --outdir report --keep-intermediates
pdfinfo report/report_extended_zh.pdf
pdffonts report/report_extended_zh.pdf
```

依赖的原始结果目录：`runner/runs/test_v1_*`、`benchmark/results/`、`pair_joint/results/`、`evidence_prompt/analysis/`、`juliet_llm/runs/`、`hybrid/results/`、`juliet_repair/report/`、`analysis/cost_normalization.json`。

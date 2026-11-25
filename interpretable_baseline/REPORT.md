# 可解释非 LLM 基线：Tier A 检测（dev40 → test160）

> 运行：WSL，Python 3.14.8，仅标准库；不联网、不读密钥、不改旧结果。
> 正式结果目录：`interpretable_baseline/results/main_20261122c/`（10,000 次按 project 聚类 bootstrap，seed 42）。
> 预注册与方法定义：`interpretable_baseline/README.md`（在 test 评估前写入）。
> 输入：`splits/dev_detection_40.json`（40 条，32 V / 8 NV）、`splits/test_detection_160.json`（160 条，128 V / 32 NV）。

---

## 0. 结论先行

1. **在 test160 的 macro-F1 点估计上，dev 选出的长度规则确实高于全部 8 个 LLM run**：`length_short` = **0.511**，8 个 LLM 为 0.346–0.422（最好的 DeepSeek evidence = 0.422）。差值为 +8.9 到 +16.5 pp。
2. **但这不是“简单规则更会检测漏洞”的证据。** 长度规则的 MCC 只有 **0.094**，只比 DeepSeek direct 的 0.041 高一点；它的收益主要来自操作点：在 80% 正例的 test 上多报，换取正类 F1 从 0.437 升到 0.688，而负类 F1 几乎不变（0.329 → 0.333）。
3. **多数类基线（恒判 vulnerable）macro-F1 = 0.444，高于全部 8 个 LLM 的点估计**，但 MCC = 0、specificity = 0、accuracy = 0.800。它证明的不是“多数类会检测”，而是**在 80% 正例的 split 上，macro-F1 会把“多报”误当成能力**。`lr_unweighted` 在 dev 上退化成这个基线（test macro-F1 0.443，MCC −0.040）。
4. **换一个指标，排名会翻转。** 按 MCC：`alloc_or_mem` = **0.183**（P 0.941 / R 0.250 / Spec 0.938）> `alloc_unbalanced` 0.142 > `mem_api_present` 0.129 > `length_short` 0.094 > 最好的 LLM（MiMo context）0.080 > DeepSeek direct 0.041 > 多数类 0.000。按 macro-F1，`alloc_or_mem` 只有 0.387，排在多数类后面。**“简单规则优于 LLM”是否成立，取决于把 macro-F1 还是 MCC 当主指标。**
5. **统计上只能说到“单元级正确数更多”，不能说“macro-F1 显著更高”。** `length_short` vs DeepSeek direct：McNemar b/c = 70/40，p = 0.0054，Holm = 0.038；vs MiMo direct：69/32，p = 0.0003，Holm = 0.002；**vs DeepSeek evidence：69/47，p = 0.0507，Holm = 0.203，不显著**。而 Δmacro-F1 的聚类 bootstrap 95% CI 全部跨 0（vs direct [−0.107, +0.224]）。两个检验回答不同问题，不能混写。
6. **test-tuned 上界也只有 ~0.60 macro-F1 / 0.21 MCC。** 最好的单特征阈值是 `call_density >= 0.2`：macro-F1 0.598、MCC 0.209；LR 在 test 上 5 折 CV 是 0.502；最好的 LLM confidence 阈值 oracle 是 DeepSeek context 0.526 / MCC 0.180。即使允许在 test 上选阈值/训练，这些表面特征也没有出现强检测器。
7. **错误分析给出的解释是“任务标签不可由函数文本单独判定”，不是“LLM 不会看代码”。** 90 个 DeepSeek FN 中，76.7% 的 rationale 含 “no clear/insufficient/unclear” 类措辞；最短四分位（Q1）LLM 召回只有 0.091，长度规则在该层全判正（召回 1.0、特异度 0）。案例里的 FN 多是短 wrapper、Linux 标准辅助函数；FP 多是“看起来可能有问题”的整数溢出/未校验输入/未转义字符串，而标签是“这次 CVE 修复涉及的函数”，不是“函数里一定有一个可见缺陷”。

---

## 1. 任务、数据与隔离

### 1.1 数据

| split | n | V | NV | 项目数 | 说明 |
| --- | ---: | ---: | ---: | ---: | --- |
| dev | 40 | 32 | 8 | 40 | 每个项目 1 条，全部是单例小项目 |
| test | 160 | 128 | 32 | 40 | `linux` 52、`Chrome` 31、`tensorflow` 7 等 |

test 的正例率是 **80.0%**。这不是上游 SecVulEval 的 43.2%，而是本项目 200 条子集（160 V / 40 NV）的构造比例；引用时必须带这个口径，不能把它当成真实项目分布。

### 1.2 隔离检查（脚本启动时强制）

```
dev_n = 40, test_n = 160
idx_overlap = 0
project_overlap = []
exact_body_md5_overlap = 0
test_projects = 40
```

- dev/test 的项目、idx、函数体 MD5 交集都是 0；本目录没有重新抽样、没有改写 `splits/`。
- Tier A 的冻结协议只保证**任务内项目级隔离**，不保证 5-gram 近重复隔离；本目录没有新增或放宽任何隔离，也不声称做了近重复控制。
- 跨任务的项目重叠（检测 dev 与配对 test 等）是协议已知限制，与本目录无关。

### 1.3 预先固定的方法

**7 条规则**（阈值只由 dev 计算：`chars` 中位数 = 1504，`calls` 中位数 = 16，dev 正例率 0.8）：

| 规则 | 条件 | dev macro-F1 |
| --- | --- | ---: |
| `prior_majority` | 恒判 1 | 0.444 |
| `length_short` | `chars <= 1504` | **0.451** |
| `calls_high` | `calls >= 16` | 0.357 |
| `alloc_unbalanced` | `alloc > free` | 0.213 |
| `mem_api_present` | `mem_api >= 1` | 0.394 |
| `alloc_or_mem` | 上两条任一 | 0.365 |
| `short_and_alloc_or_mem` | `length_short` 且 `alloc_or_mem` | 0.263 |

**dev 选择规则**：dev macro-F1 最高者；并列时 MCC 高者，再复杂度低者。选中 `length_short`。注意它与 `prior_majority` 的 dev 差距只有 **0.0061**，远小于 40 条样本的噪声；这个选择本身不稳定。

**2 个小型逻辑回归**（标准库 IRLS，5 个特征：`log1p(chars)`、`calls`、`alloc_minus_free`、`mem_api`、`branch_density`；L2 λ=1.0；阈值固定 0.5，不在 test 上调）：

| 变体 | dev macro-F1 | dev LOO | test macro-F1 | test MCC |
| --- | ---: | ---: | ---: | ---: |
| `lr_unweighted` | 0.444 | 0.437 | 0.443 | −0.040 |
| `lr_balanced` | 0.564 | 0.298 | 0.391 | −0.131 |

- `lr_unweighted` 在 32 V / 8 NV 的 dev 上几乎退化为“全判正”（test：127 TP / 32 FP / 1 FN / 0 TN）。
- `lr_balanced` 在 dev 上看起来最好（0.564），但 LOO 掉到 0.298，test 掉到 0.391、MCC −0.131。这是 **dev40 过拟合 + dev/test 协变量偏移** 的直接证据。

LR 的标准化系数（`beta`；`OR(1SD)=exp(beta)`）：

| 特征 | `lr_unweighted` beta | OR | `lr_balanced` beta | OR |
| --- | ---: | ---: | ---: | ---: |
| `log_chars` | +0.007 | 1.007 | +0.012 | 1.012 |
| `calls` | +0.157 | 1.170 | +0.220 | 1.246 |
| `alloc_minus_free` | −0.202 | 0.817 | −0.387 | 0.679 |
| `mem_api` | −0.158 | 0.854 | −0.153 | 0.858 |
| `branch_density` | +0.206 | 1.228 | +0.192 | 1.211 |

注意 `alloc_minus_free` 的符号是**负**的：在 dev 上“分配多于释放”反而略微降低预测概率。这与泄漏直觉相反，但不是规则错了，而是 dev40 里 `alloc > free` 只有 3 条（2 TP / 1 FP），无法稳定估计方向；test 上 `alloc_unbalanced` 的 MCC 0.142 反而是所有 dev 规则里第二高。**这正是“不要在 8 个负例上拟合 5 个特征”的直观证据。**

特征只来自 `func_body`；先去掉注释、字符串、字符字面量，再统计。不使用 `context`、`changed_lines`、`changed_statements`、`cwe_list`、`cve_list`、`fixed_func_idx`、项目名或文件名。

---

## 2. 主结果（test 160，coverage 全部 1.0）

### 2.1 全部方法

| 方法 | TP | FP | TN | FN | P | R | Spec | pos-F1 | neg-F1 | macro-F1 [95% CI] | MCC | pred+ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| `rule:length_short` | 75 | 15 | 17 | 53 | 0.833 | 0.586 | 0.531 | 0.688 | 0.333 | **0.511 [0.422, 0.562]** | 0.094 | 0.562 |
| `rule:prior_majority` | 128 | 32 | 0 | 0 | 0.800 | 1.000 | 0.000 | 0.889 | 0.000 | 0.444 [0.412, 0.460] | 0.000 | 1.000 |
| `lr_unweighted` | 127 | 32 | 0 | 1 | 0.799 | 0.992 | 0.000 | 0.885 | 0.000 | 0.443 [0.411, 0.459] | −0.040 | 0.994 |
| `lr_balanced` | 59 | 20 | 12 | 69 | 0.747 | 0.461 | 0.375 | 0.570 | 0.212 | 0.391 [0.343, 0.466] | −0.131 | 0.494 |
| `rule:calls_high` | 53 | 14 | 18 | 75 | 0.791 | 0.414 | 0.562 | 0.545 | 0.287 | 0.416 [0.360, 0.491] | −0.019 | 0.419 |
| `rule:alloc_or_mem` | 32 | 2 | 30 | 96 | 0.941 | 0.250 | 0.938 | 0.395 | 0.380 | 0.387 [0.324, 0.530] | **0.183** | 0.212 |
| `rule:mem_api_present` | 23 | 2 | 30 | 105 | 0.920 | 0.180 | 0.938 | 0.311 | 0.359 | 0.330 [0.250, 0.497] | 0.129 | 0.156 |
| `rule:alloc_unbalanced` | 12 | 0 | 32 | 116 | 1.000 | 0.094 | 1.000 | 0.171 | 0.356 | 0.263 [0.205, 0.352] | 0.142 | 0.075 |
| `rule:short_and_alloc_or_mem` | 11 | 0 | 32 | 117 | 1.000 | 0.086 | 1.000 | 0.158 | 0.354 | 0.256 [0.208, 0.323] | 0.136 | 0.069 |

**LLM 参照**（重新计算并与各自 `metrics.json` 逐项对齐；8/8 通过，容差 1e-9）：

| run | 方法 | valid | macro-F1 | MCC | P | R | Spec | pred+ |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek / evidence | `tiera_...0e09037d` | 159 | **0.422** | 0.035 | 0.817 | 0.386 | 0.656 | 0.377 |
| MiMo / evidence | `tiera_...c68dfa50` | 158 | 0.407 | 0.013 | 0.810 | 0.370 | 0.645 | 0.367 |
| DeepSeek / few-shot | `legacy__test_v1_few-shot` | 160 | 0.399 | 0.061 | 0.837 | 0.320 | 0.750 | 0.306 |
| DeepSeek / direct | `legacy__test_v1_direct` | 160 | 0.383 | 0.041 | 0.826 | 0.297 | 0.750 | 0.287 |
| DeepSeek / context | `legacy__test_v1_context` | 160 | 0.381 | 0.020 | 0.812 | 0.305 | 0.719 | 0.300 |
| MiMo / context | `legacy__test_v1_mimo_context` | 153 | 0.365 | **0.080** | 0.861 | 0.252 | 0.833 | 0.235 |
| MiMo / direct | `legacy__test_v1_mimo_direct` | 150 | 0.346 | 0.008 | 0.806 | 0.242 | 0.767 | 0.240 |
| MiMo / few-shot | `legacy__test_v1_mimo_few-shot` | 160 | 0.346 | −0.042 | 0.773 | 0.266 | 0.688 | 0.275 |

完整 run_id：DeepSeek evidence = `tiera_secvuleval_deepseek_evidence_20261112_0e09037d`；MiMo evidence = `tiera_secvuleval_mimo_evidence_20261112_c68dfa50`；其余为 `legacy__test_v1_{deepseek,mimo}_{direct,few-shot,context}_independent`。完整字段见 `results/main_20261122c/metrics.json` 的 `llm` 块。

### 2.2 两种排名

**按 macro-F1**：

1. `length_short` 0.511
2. `prior_majority` 0.444
3. `lr_unweighted` 0.443
4. DeepSeek evidence 0.422
5. `calls_high` 0.416
6. MiMo evidence 0.407
7. DeepSeek few-shot 0.399
8. `lr_balanced` 0.391
9. `alloc_or_mem` 0.387
10. DeepSeek direct 0.383
11. DeepSeek context 0.381
12. MiMo context 0.365
13. MiMo few-shot 0.346
14. MiMo direct 0.346
15. `mem_api_present` 0.330
16. `alloc_unbalanced` 0.263
17. `short_and_alloc_or_mem` 0.256

**按 MCC**：

1. `alloc_or_mem` 0.183
2. `alloc_unbalanced` 0.142
3. `short_and_alloc_or_mem` 0.136
4. `mem_api_present` 0.129
5. `length_short` 0.094
6. MiMo context 0.080
7. DeepSeek few-shot 0.061
8. DeepSeek direct 0.041
9. DeepSeek evidence 0.035
10. DeepSeek context 0.020
11. MiMo evidence 0.013
12. MiMo direct 0.008
13. `prior_majority` 0.000
14. `calls_high` −0.019
15. `lr_unweighted` −0.040
16. MiMo few-shot −0.042
17. `lr_balanced` −0.131

这个翻转是本文最重要的诊断：**在 80% 正例上，macro-F1 主要奖励“多报正类”；MCC 才同时惩罚两类错误。** 多数类、`lr_unweighted`、`calls_high` 在 macro-F1 上排在 LLM 前面，但 MCC 为 0 或负；`alloc_or_mem` 在 MCC 上第一，macro-F1 却只有 0.387。把“简单规则优于 LLM”写成单一结论会掩盖这个矛盾。

### 2.3 与 LLM 的配对比较（common-valid，exact McNemar）

| baseline | LLM | n | Δmacro-F1 [95% CI] | b/c（正确性） | p | Holm p |
| --- | --- | ---: | --- | --- | ---: | ---: |
| `length_short` | DeepSeek direct | 160 | +0.128 [−0.107, +0.224] | 70/40 | 0.0054 | **0.038** |
| `length_short` | DeepSeek evidence | 159 | +0.092 [−0.134, +0.202] | 69/47 | 0.0507 | 0.203 |
| `length_short` | MiMo direct | 150 | +0.179 [−0.055, +0.267] | 69/32 | 0.0003 | **0.002** |
| `prior_majority` | DeepSeek direct | 160 | +0.062 [−0.133, +0.151] | 90/24 | 3.6e−10 | **3.2e−9** |
| `alloc_or_mem` | DeepSeek direct | 160 | +0.005 [−0.075, +0.076] | 23/23 | 1.000 | 1.000 |
| `lr_balanced` | DeepSeek direct | 160 | +0.008 [−0.149, +0.088] | 40/31 | 0.343 | 0.963 |

读法：

- **McNemar 检验的是“逐单元是否正确”**。`length_short` 正确 92/160，DeepSeek direct 62/160；在 70 个单元上规则对而 LLM 错，40 个反过来。这个差异在 direct 和 MiMo direct 上经 Holm 仍显著。
- **Δmacro-F1 的 cluster bootstrap CI 全部跨 0**。macro-F1 是类加权指标，差异集中在少数项目；40 个 project 的聚类 bootstrap 方差很大。不能把 +0.128 写成“显著提高 macro-F1”。
- **对 DeepSeek evidence 不显著**（Holm 0.203）。evidence 是 8 个 LLM 里 macro-F1 最高的，也是更公平的强参照。
- **`prior_majority` 的 McNemar 也显著**（90/24），但它 MCC=0、specificity=0；这再次说明“逐单元正确数/accuracy”与“判别力”不是一回事。

### 2.4 现有 leaderboard 的欠缺（由本结果反推）

1. **没有多数类/长度/调用数基线。** 当前主表从 LLM 开始；读者看不到 0.444 的多数类 macro-F1，也看不到 0.511 的长度规则。缺少这两个参照，0.38–0.42 会被误读为“接近可用”。
2. **主指标只有 macro-F1。** 在 80% 正例上，macro-F1 与 MCC 的排名会翻转（§2.2）；只报 macro-F1 会把恒判正例排在 8 个 LLM 前面，也会把 `alloc_or_mem`（MCC 0.183）埋到第 9 名。
3. **LLM 的 predicted positive rate 不在主表。** DeepSeek direct 只报 28.7% 为正，而 test 正例率 80%；这个操作点差异是 macro-F1 落后的直接原因，但主表没有这一列。
4. **没有按长度分层。** 总体 macro-F1 掩盖了 Q1 召回 0.091、Q4 召回 0.552 的结构性差异；长度规则与 LLM 的优劣完全取决于层。
5. **dev40 被当成可调参的开发集。** 8 条负例、40 个单例项目，`length_short` 只比多数类高 0.0061；任何在 dev 上选阈值/模型的做法都不稳。主表没有报告这种选择不确定性。
6. **没有 matched operating point 比较。** 直接比宏平均，会把 calibration 差异（LLM 保守）与 discrimination 差异（MCC 都接近 0）混在一起。
7. **test-tuned 上界没有单列。** 若允许在 test 上选阈值，单特征可到 0.598 macro-F1；这个数字不能进主表，但应该作为“还有多少信号”的附录，否则读者无法判断 0.42 是模型极限还是操作点问题。

---

## 3. test-tuned 上界（明确不是方法）

这些数字使用了 test 标签做阈值/模型选择，只能回答“还有多少信号”，不能进 leaderboard。

| 特征 | 方向 | 阈值 | macro-F1 | MCC | R | Spec |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `call_density` | ≥ | 0.2 | **0.598** | **0.209** | 0.766 | 0.469 |
| `branch_density` | ≤ | 0.2 | 0.575 | 0.150 | 0.836 | 0.312 |
| `chars` | ≤ | 3973 | 0.565 | 0.130 | 0.844 | 0.281 |
| `calls` | ≤ | 29 | 0.552 | 0.105 | 0.797 | 0.312 |
| `mem_api` | ≤ | 4 | 0.471 | 0.046 | 0.984 | 0.031 |
| `alloc_minus_free` | ≥ | 0 | 0.462 | −0.016 | 0.961 | 0.031 |

- 规则族在 test 上的最好者仍是 `length_short` 0.511；dev 阈值 1504 明显偏低，test-tuned 的 `chars <= 3973` 能到 0.565，说明 **dev/test 长度分布偏移**。
- LR 在 test 上同数据拟合：unweighted 0.444、balanced 0.538；5 折 CV balanced **0.502**。即使允许 test 标签训练，5 折 CV 也只和 dev 长度规则相当。该 CV 只按标签分层，不按项目分层；linux/Chrome 的集中会让它偏乐观。
- 最好的 LLM confidence 阈值 oracle：DeepSeek context 0.526 / MCC 0.180；DeepSeek few-shot 0.522 / 0.148；MiMo context 0.513 / 0.155；DeepSeek direct 0.455 / 0.019。**即使允许在 test 上重新校准 LLM 的操作点，最好的 confidence oracle 仍低于单特征 oracle 0.598，且 MCC 低于 `alloc_or_mem` 的 0.183。** 注意 confidence oracle 的 `n_scored` 是“有有效预测且带 confidence”的单元（150–160），无效单元被排除；不同 run 的 n 不同，不能直接横比。
- 结论：这些表面特征的上界大约在 **0.60 macro-F1 / 0.21 MCC**；不是一个强检测器，但足以和当前 LLM 的点估计打平或略高。

---

## 4. 错误原因分析

### 4.1 长度分层（test 四分位，阈值 [560.75, 1329.0, 2844.75]）

| 四分位 | n | 正例 | 长度规则 R | 长度规则 Spec | 长度规则 macro-F1 | DeepSeek direct R | Spec | macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Q1 最短 | 40 | 33 | 1.000 | 0.000 | 0.452 | 0.091 | 1.000 | 0.242 |
| Q2 | 40 | 32 | 1.000 | 0.000 | 0.444 | 0.250 | 1.000 | 0.400 |
| Q3 | 40 | 34 | 0.294 | 1.000 | 0.394 | 0.324 | 0.500 | 0.323 |
| Q4 最长 | 40 | 29 | 0.000 | 1.000 | 0.216 | 0.552 | 0.545 | 0.520 |

这是“长度规则为什么能赢”的最直接机制：

- 在最短的 Q1/Q2，长度规则全判正（召回 1.0、特异度 0），macro-F1 约 0.45；LLM 在 Q1 只召回 0.091，几乎全判负，macro-F1 0.242。
- 在 Q3/Q4，长度规则开始全判负或只抓一小部分；LLM 在 Q4 反而更好（macro-F1 0.520 vs 0.216）。
- 总 macro-F1 是四层混合：长度规则用“最短半区全报”换取了足够的正类 F1，LLM 的保守操作点在 Q1/Q2 丢了太多正例。**这不是 LLM 在长函数上更差，而是它在短函数上几乎不报。**

### 4.2 LLM 的 FN/FP 与规则重叠

DeepSeek direct：90 FN、8 FP。

| 规则 | 抓回 90 个 FN（规则判正） | 比例 | 避开 8 个 FP（规则判负） | 比例 |
| --- | ---: | ---: | ---: | ---: |
| `prior_majority` | 90 | 100.0% | 0 | 0.0% |
| `length_short` | 62 | 68.9% | 7 | 87.5% |
| `calls_high` | 34 | 37.8% | 6 | 75.0% |
| `alloc_or_mem` | 16 | 17.8% | 6 | 75.0% |
| `alloc_unbalanced` | 8 | 8.9% | 8 | 100.0% |
| `mem_api_present` | 9 | 10.0% | 8 | 100.0% |
| `lr_unweighted` | 89 | 98.9% | 0 | 0.0% |
| `lr_balanced` | 38 | 42.2% | 5 | 62.5% |

- 长度规则抓回了 DeepSeek 2/3 的 FN（62/90），代价是 15 个 FP（其中 7 个是 DeepSeek 判对的负例被规则误报）。
- 分配/内存规则只抓回 8–16 个 FN，但几乎不误报 FP；它们是“高精确率、低召回”的另一端。
- `prior_majority` 和 `lr_unweighted` 抓回 100%/98.9% 的 FN，但代价是把所有负例都报掉；这不是检测，是先验。

### 4.3 rationale 关键词（DeepSeek direct；正则计数，不是人工编码）

| 关键词类 | TP 中出现率 (n=38) | FN 中出现率 (n=90) |
| --- | ---: | ---: |
| “no clear / insufficient / unclear / no evidence” | 7.9% | **76.7%** |
| memory safety（memory/buffer/overflow/OOB/UAF/leak） | 81.6% | 97.8% |
| validation（validate/sanitize/check/guard/input） | 76.3% | 66.7% |
| safe claim（safe/correct/properly/no issue/benign） | 0.0% | 8.9% |

解释：

- FN 的典型措辞是“**函数本身没有明显的内存安全问题；漏洞取决于调用者/未提供的上下文**”。这不是解析失败，而是模型认为证据不足。
- TP 也大量提 memory safety（81.6%），说明关键词本身不能区分对错；区别在 FN 更常出现“no clear evidence”和“safe claim”。
- 这与项目已有的失败诊断一致：LLM 的漏报集中在短函数和生命周期/访问控制类 CWE；它的 precision 高、recall 低，是保守操作点。

### 4.4 典型案例（来自 `cases.json`，按长度四分位抽取；完整 12 条见该文件）

**FN（label = vulnerable，DeepSeek 判 0，长度规则判 1）**

| idx | 项目 | 长度 | 代码/理由摘要 | 解释 |
| ---: | --- | ---: | --- | --- |
| 1777 | linux | 95 chars / 6 行 | `fastrpc_map_get()`：`if (map) kref_get(&map->refcount);`；LLM 说“standard kref_get wrapper... no vulnerability”。 | 函数本身是标准引用计数 wrapper；漏洞取决于调用者是否在错误时机调用。长度规则因“短”判正，碰巧对。 |
| 1830 | linux | 387 / 14 | `vgic_its_check_cache()`：spinlock + 调用未提供的 helper；LLM 说“any vulnerability would depend on the unseen implementation”。 | 函数文本没有可见缺陷；标签来自该 CVE 修复对的漏洞侧。 |
| 7898 | hhvm | 1015 / 33 | `apc_add()`：参数校验、`apc_store().add`；LLM 说“no clear security vulnerability”。 | 逻辑/输入校验类问题，不是内存安全；分配/释放规则完全无信号（alloc=free=mem=0）。 |
| 20380 | ImageMagick | 1059 / 44 | `SkipDXTMipmaps()`：size_t 算术、`SeekBlob` 返回值忽略；LLM 说“no obvious overflow”。 | 需要 DDS 文件格式和调用上下文才能判定；单函数不可判定。 |
| 23966 | Chrome | 2165 / 54 | `PerformNextQueuedGlobalMemoryDump()`：`base::Unretained(this)` 生命周期风险；LLM 说“no clear exploitable bug”。 | 生命周期问题跨回调/对象；函数内看不到完整所有权。 |
| 10391 | ChakraCore | 24794 / 555 | `EmitOneFunction()`：大量 assert 和内部状态；LLM 说“no obvious memory-safety flaw”。 | 超长函数，长度规则判负（>1504），LLM 也判负；两者都错过。 |

**FP（label = non-vulnerable，DeepSeek 判 1，长度规则判 0）**

| idx | 项目 | 长度 | LLM 的理由 | 解释 |
| ---: | --- | ---: | --- | --- |
| 10457 | radare2 | 1977 / 79 | `pos + len` 无符号溢出，`len = filesize - pos` 可能下溢。 | 这是“看起来可能溢出”的模式；标签是修复版本/非漏洞，说明该模式在此处已被处理或不是目标 CVE。 |
| 210 | linux | 2393 / 64 | `logi_dj_raw_event()` 把 HID  buffer 直接 cast 成 `struct dj_report`，未校验 `size`。 | 真实的防御性编程问题，但不是该样本的标签漏洞；LLM 在做“代码审查”，不是“复现特定 CVE”。 |
| 17218 | htmldoc | 5878 / 212 | `fprintf(out, "/Lang(%s)", lang)` 未转义 PDF 特殊字符。 | 注入类问题；标签为 NV，可能是因为输入可信或不是该 commit 的漏洞。 |
| 8632 | ImageMagick | 4050 / 155 | eXIf 分支分配 `chunk->size+6`，读未初始化 `*p`。 | 未初始化读是合理怀疑；但标签是 NV，说明不是目标缺陷。 |

这组案例说明：

- **LLM 的 FN 不是“看不懂代码”，而是“函数文本不足以判定”**；很多函数是 wrapper、helper、标准内核代码。
- **LLM 的 FP 是“合理但不对题”**：它找的是“这段代码可能有什么问题”，而标签是“这个函数属于修复前漏洞侧还是修复后侧”。两者不是同一个任务。
- 长度规则既不看语义也不看上下文；它在短函数上“全报”，在长函数上“全不报”。它赢了 macro-F1，但没有解决任务。

### 4.5 项目集中

| 项目 | n | 正例 | 长度规则 R | Spec | DeepSeek direct R | Spec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| linux | 52 | 43 | 0.721 | 0.333 | 0.209 | 0.778 |
| Chrome | 31 | 28 | 0.714 | 0.333 | 0.107 | 1.000 |
| tensorflow | 7 | 5 | 0.400 | 0.500 | 0.200 | 1.000 |
| Android | 6 | 4 | 0.250 | 1.000 | 0.500 | 1.000 |
| vim | 5 | 2 | 0.500 | 0.667 | 0.000 | 1.000 |

linux + Chrome 占 83/160（51.9%）。长度规则在两大项目上召回 0.71–0.72、特异度 0.33；LLM 召回 0.11–0.21、特异度 0.78–1.00。这不是“规则更懂 Linux”，而是“规则在 linux/Chrome 的短函数上多报”。n 很小，不能做项目级泛化结论。

### 4.6 分配/释放特征为何弱

- **144/160** 条 test 函数 `alloc = 0`；**151/160** 条 `free = 0`；**140/160** 条两者都为 0；**135/160** 条 `mem_api = 0`；**122/160** 条三者全为 0。
- 32/32 条非漏洞样本 `alloc = 0`；112/128 条漏洞样本 `alloc = 0`。
- `alloc > free` 只命中 **12/160**，但 12 个全是 TP（precision 1.000），所以 `alloc_unbalanced` 的 MCC 0.142、macro-F1 0.263。
- 这不是 CWE-401/内存泄漏基准。SecVulEval 是跨 CWE 的真实 CVE 函数；大多数函数没有堆分配。把 Juliet 的分配/释放直觉搬到 Tier A，召回必然很低。

---

## 5. 为什么简单规则可能优于 LLM（机制拆解）

把上面的证据压缩成 5 条机制：

1. **正例率 80% + macro-F1 的二类平均**：恒判正例时 TP=128、FP=32、FN=0、TN=0；positive F1 = 2·128/(2·128+0+32) = **0.889**，negative F1 = 0，macro = **0.444**。任何“多报但不太离谱”的方法都能接近这个数；LLM 只报 28.7% 为正，positive F1 0.437，macro 0.383。**macro-F1 在这个 prevalence 下奖励 recall，惩罚保守。**
2. **LLM 的操作点是高精确率/低召回**：P 0.826、R 0.297、Spec 0.750。它不是不会排，而是把阈值放得很高；在 128 个正例上漏 90 个。简单长度规则把阈值放低（pred+ 0.562），P 仍有 0.833，R 0.586，macro 0.511。**差的不是 ranking，是 calibration/operating point。**
3. **LLM 的 ranking 也很弱**：MCC 0.041（DeepSeek direct），最好的 MiMo context 0.080。简单规则 `alloc_or_mem` 的 MCC 0.183，是它的 2.3–4.5 倍。**所以不能反过来说“LLM 只要调阈值就能赢”；它的 confidence oracle 在 test 上也只有 0.445–0.526 macro-F1。**
4. **标签是“修复前漏洞侧 vs 修复后版本”，不是“函数文本里有可见 bug”**：FN 案例里 LLM 的“no clear evidence”往往是对的——函数本身确实看不出；漏洞在调用者、生命周期、未提供的 helper 或输入路径里。长度规则在短函数上全报，恰好拟合了“短函数在这个子集里更常被标为正例”这个数据集偏差。**这是 shortcut，不是理解。**
5. **dev/test 偏移让“拟合”与“选择”都不稳**：dev 全是单例小项目，test 由 linux/Chrome 主导；`lr_balanced` dev 0.564 → LOO 0.298 → test 0.391，MCC −0.131。dev 选出的长度规则只比多数类高 0.0061；它能赢 test，有很大运气成分。**任何“dev 拟合的小模型”在这个划分上都不应被当成稳定方法。**

一句话：**简单规则在 macro-F1 上“优于”LLM，主要是因为它们更愿意报正例，而 test 的 80% 正例率让“多报”变得划算；不是因为它们更能识别漏洞。换 MCC 看，`alloc_or_mem` 是唯一明显优于 LLM 的简单规则（0.183 vs 0.080），但它召回只有 0.250，macro-F1 只有 0.387。**

---

## 6. 局限（必须与结果一起读）

1. **dev 太小、太不平衡**：40 条、8 条负例、40 个项目各 1 条。`length_short` 与 `prior_majority` 的 dev 差距只有 0.0061；`lr_balanced` 的 LOO 0.298 说明 dev 选择不可靠。
2. **dev/test 协变量偏移**：dev 是单例小项目；test 由 linux/Chrome/tensorflow 主导。长度、调用密度、代码风格都不同；test-tuned `chars <= 3973` 与 dev 阈值 1504 的差距就是证据。
3. **标签语义**：`is_vulnerable` = 该函数是 CVE 修复前的漏洞版本（false = 修复后版本），不是“函数文本中一定存在可静态识别的缺陷”。FN/FP 案例显示很多标签依赖调用上下文/未提供的代码。
4. **词法特征不是静态分析**：去掉注释/字符串，但不处理 C++ raw string、宏、`#if 0`、函数指针、`free` 变量名、`new` 的 placement 形式；`calls` 只数第一个 `{` 之后、排除关键字，仍可能把宏/声明算进去。
5. **test-tuned 上界不是可部署结果**：所有 oracle/5-fold CV/LLM confidence threshold 都用了 test 标签；只能作为“还有多少信号”的上界。
6. **单次 split、无种子方差**：规则/LR 确定性；bootstrap 只给抽样不确定性，不给标签噪声/数据构造/项目选择的不确定性。LLM run 是单次运行，服务端还有非确定性（项目 README 已记录 2 个 bad 单元不同）。
7. **多重比较**：9 个基线 × 4 个 LLM 参照；只在每个 LLM 参照族内做 Holm，其他配对只作描述。`length_short` vs evidence 的 Holm 0.203 就是不显著的直接例子。
8. **长度截断**：test 中有函数体恰好 32,767 字符（Excel 单元格上限），长度是截断后的下界；这些样本影响 `length_short` 和 LR。
9. **近重复**：Tier A 只保证项目级隔离；本目录没有做 5-gram 近重复检查，也不声称做了。若上游存在跨项目复制代码，本项目无法排除。
10. **不支持因果结论**：不能从“长度规则 macro-F1 更高”推出“长度是漏洞原因”；它只是这个 split 上的相关/捷径。

---

## 7. 对项目的建议

1. **leaderboard 加一行多数类基线**（macro-F1 0.444、MCC 0、Spec 0、accuracy 0.800），并把它放在所有 LLM 行旁边。当前主表没有这一行，读者会误以为 0.38–0.42 是“接近可用”。
2. **主指标同时报 MCC 和 balanced accuracy**，或者至少给“macro-F1 − 多数类 macro-F1”和“macro-F1 − 长度规则”两个 delta。单看 macro-F1 会把恒判正例排在 8 个 LLM 前面。
3. **所有 LLM 结果加“predicted positive rate”**。DeepSeek direct 只报 28.7% 为正，而 test 正例率 80%；这个差距比 macro-F1 更能解释失败。
4. **按长度分层报告**（至少 Q1/Q4）。LLM 在 Q1 的召回 0.091，在 Q4 的召回 0.552；总体数字掩盖了这个结构性失败。
5. **dev 设计要改**：40 条、8 负例不足以选择阈值/模型。要么扩大 dev 负例（按项目分层），要么用嵌套 CV/多 split，且不要把 dev 选择当成稳定结论。
6. **区分“检测”与“校准”**：如果目标是 macro-F1，LLM 需要降低阈值；如果目标是 precision，保持保守。两者不能都用同一个 0.5/默认 prompt。报告应给出 cost curve 或至少 P-R 点，而不是单一阈值。
7. **对“函数文本不可判定”的样本单独建层**：例如 LLM rationale 明确说“depends on caller/unseen helper”的 FN；这些样本应标为 `underdetermined`，不进入主分母，或单独报告 abstention。当前把它们算作 LLM 错误，会低估模型。
8. **下一步实验**（按性价比）：
   - 用同一套规则/LR 在 **pair 任务** 上做长度基线（项目已有 74.44% 的 joint 长度启发式），比较 side-wise 与 joint；
   - 在 dev 上做 **40 条负例的扩充**（从完整 SecVulEval 抽同项目/同长度档的 NV），再重跑 `length_short` 与 LR；
   - 对 LLM 做 **matched pred+** 比较：把 LLM 的阈值调到与长度规则相同的 pred+（0.562），再比 macro-F1/MCC，分离 calibration 与 discrimination；
   - 给 `alloc_or_mem` 加一个 **长度/项目分层的高精确率路由**，看能否在保持 P>0.9 的同时把 R 从 0.25 提到 0.35–0.40；
   - 用 **CWE 家族**（n≥10）做描述性分层，但不要做逐 CWE 排名。

---

## 8. 复现与产物

```bash
wsl bash -lc "cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
  python3 interpretable_baseline/run_baseline.py --resamples 10000 \
    --out-dir interpretable_baseline/results/main_20261122c"
```

本次运行的产物（`results/main_20261122c/`）：

| 文件 | 内容 |
| --- | --- |
| `metrics.json` | 全部指标、bootstrap、LLM 校验、配对比较、test-tuned 上界 |
| `features.jsonl` | dev/test 每条样本的 15 个特征 |
| `predictions.jsonl` | 每个方法在 dev/test 上的逐条预测（LR 带概率） |
| `error_analysis.json` | 长度四分位、项目分层、LLM FN/FP 重叠、rationale 关键词 |
| `cases.json` | 12 个案例（FN/FP × 四分位） |
| `report.md` | 机器生成的英文表格报告 |
| `manifest.json` | 输入/输出 SHA-256、脚本哈希、Python 版本 |
| `../results_main_20261122c.log` | 本次运行的 stdout |

校验：

- 8/8 个 LLM run 的 macro-F1、MCC、accuracy、valid、TP/FP/TN/FN 与各自 `metrics.json` 一致（容差 1e-9）。
- 隔离检查：idx/project/body-MD5 交集均为 0。
- 输出目录非空时脚本拒绝运行；没有覆盖任何旧结果。
- 没有读取环境变量/密钥，没有网络调用。

成本：**0 次 API 请求、$0**。本地标准库运行，10,000 次聚类 bootstrap 在 WSL 下是分钟级；没有 token/延迟记录，因此不与 LLM 的 USD/延迟做换算。

---

## 9. 文献与改进建议（只列已核验条目）

| # | 文献 | 与本结果的关系 | 不能拿它说什么 |
| --- | --- | --- | --- |
| [1] | M. B. U. Ahmed, N. S. Harzevili, J. Shin, H. V. Pham, S. Wang. *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection.* AIware 2026, pp. 388–396. DOI 10.1145/3805760.3814932 | 数据来源；上游 25,440 函数、43.2% 正例、语句级标注 + 上下文 | 本项目的 200 条子集是 80% 正例，不是上游分布；本结果不能外推到 SecVulEval 全表 |
| [2] | Y. Ding et al. *Vulnerability Detection with Code Language Models: How Far are We?* ICSE 2025, pp. 1729–1741. DOI 10.1109/ICSE55347.2025.00038 | 标签噪声、配对评估、时间切分；支持“函数级标签不牢” | 不能把 PrimeVul 的 3.09% F1 直接搬到本数据 |
| [7] | N. Risse, M. Böhme. *Uncovering the Limits of Machine Learning for Automatic Vulnerability Detection.* USENIX Security 2024 |  ML4VD 的极限；支持“表面特征/数据偏差”诊断 | 不是本数据的实测结果 |
| [8] | N. Risse, J. Liu, M. Böhme. *Top Score on the Wrong Exam: On Benchmarking in Machine Learning for Vulnerability Detection.* PACMSE 2(ISSTA), pp. 388–410, 2025. DOI 10.1145/3728887 | 直接动机：函数级标签在缺上下文时不可判定；表面特征基线可高分 | 该文的数字不在本数据上复现；本目录只借用其诊断框架 |
| [12] | B. Steenhoek, M. M. Rahman, S. Sharmin, W. Le. *Do Language Models Learn Semantics of Code? A Case Study in Vulnerability Detection.* arXiv:2311.04109, 2023 | 模型对 buggy path 的语义对齐弱；支持“rationale 关键词 ≠ 理解” | 预印本，未同行评审；不能当定论 |

**改进 idea（按优先级）**：

1. **把“超过多数类/超过长度规则”作为新方法的准入线**，而不是只看绝对 macro-F1。任何新 prompt/模型至少要在 MCC 上超过 `alloc_or_mem` 的 0.183，或在 matched pred+ 下超过长度规则。
2. **matched operating point 比较**：把 LLM 阈值调到与基线相同 pred+（0.562），再比 macro-F1/MCC；这能把“校准差异”和“判别差异”分开。
3. **underdetermined 分层**：用 LLM rationale + 人工抽样建立“函数文本不足”子集，单独报告 abstention/coverage；不要把不可判定样本算成纯 FN。
4. **dev 扩充与嵌套 CV**：从完整 SecVulEval 抽同项目/同长度档的负例，把 dev 从 8 NV 扩到至少 40 NV；用项目级 nested CV 选规则，避免单次 dev 选择。
5. **成本感知的规则路由**：`alloc_or_mem` 高精确率 + 长度规则高召回，做二段式；报告 P-R 曲线和每 TP 成本，而不是单一阈值。
6. **跨任务验证**：同一套规则在 pair-joint 的 180 对上复算长度启发式（项目已有 74.44%），比较 side-wise/joint 的操作点差异；这能检验“长度 shortcut”是否跨任务稳定。

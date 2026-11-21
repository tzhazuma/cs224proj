# 最新评估与修复验证文献（2025–2026）

**面向 SecVulEval 项目的可检验改进：position bias、length shortcut、paired benchmark、placebo、LLM-as-judge、patch overfitting、compile/test/PoC、fault injection、differential testing**

| 项目 | 内容 |
| --- | --- |
| 文档版本 | `1.0` |
| 日期 | 2026-11-13 |
| 范围 | 2025–2026 年评估方法学、代码 LLM 评判、配对漏洞基准、补丁正确性与可执行验证；辅以 2015–2024 年奠基工作 |
| 证据分级 | **A** = 正式发表且 DOI/页码/ACL Anthology 已核对；**B** = arXiv 预印本，元数据已核对但未必同行评审；**C** = 厂商文档/工件/博客 |
| 关联产物 | `pair_joint/report.md`、`hybrid/REPORT.md`、`juliet_repair/report/comparison.md`、`repair_eval/analysis/repair_blind_v1/final/summary.md`、`benchmark/PROTOCOL.md`、`research/evaluation_protocol.md`、`research/improvement_opportunities.md` |
| 本次改动 | **只新增本文件**；未修改旧结果、脚本、数据、`report/`、`runner/`、`splits/` |
| 重要声明 | 本文是**文献调研与方法映射**，不是新实验。文中项目数字均为对现有产物的**只读引用**，未重新调用模型、未重新计算、未覆盖任何旧结果。所有“建议验收线”都是待验证的设计目标，不是实测结论。 |

> **日期化状态注记（2026-11-14）**
>
> **写作时状态（2026-11-13）**：**P0–P7 / E1–E9 均为建议与实验设计，不是当时的结果**。P0–P7 见 `research/latest_llm_methods_2026.md` §9；E1–E9 见本文 §12。§14 的 P0–P3 只是执行优先级，不是实测结论。写作时没有运行这些实验，也没有修改旧结果。
>
> **截至 2026-11-14 已完成**（以下为后续目录；不回填或改写本文历史建议与数字）：
>
> - **schema recovery**：[`analysis/schema_recovery/`](../analysis/schema_recovery/README.md) — 零 API 复分析 102 条 repair invalid 的可回收性。
> - **pair_debias 双序/open**：[`pair_debias/`](../pair_debias/report.md) — A/B 反向重复、open both/neither、长度匹配。
> - **evidence_verify**：[`evidence_verify/`](../evidence_verify/analysis/report.md) — 证据/裁决验证。
> - **dynamic_enhanced**：[`dynamic_enhanced/`](../dynamic_enhanced/README.md) — realloc 失败注入 + LSan 全局根。
> - **hybrid_dynamic_enhanced**：[`hybrid_dynamic_enhanced/`](../hybrid_dynamic_enhanced/README.md) — 增强动态证据引导。
> - **CodeQL**：[`static_extended/runs/codeql_20261114_cwe401_full/`](../static_extended/runs/codeql_20261114_cwe401_full/metrics.md) — Juliet CWE-401 全量。
>
> 以上只更新执行状态；正文的 E1–E9 建议、引用与 2026-11-13 的数字保持不变。

> **阅读约定**
>
> - “检测”指 Task A：单函数二分类。
> - “配对”指 Task B1：同一函数漏洞版本与修复版本的判别。
> - “修复”指 Task B2：生成补丁并用编译/测试/PoC 等 oracle 验证。
> - “评判”指 LLM-as-a-judge 或人工 rubric 对补丁/解释的质量评分。
> - 文中 `[n]` 对应 §16 参考文献；每个条目都给出 URL 或 DOI。
> - 文中“建议验收线”“规划成本”不是实验结果；旧结果一律以现有报告为准。

---

## 0. 一页结论

1. **2025–2026 年评估文献的共同结论是：分数对协议选择的敏感度，往往不小于模型差异。** Cichoń 与 Dmitruk 在固定模型输出的条件下发现，模型可让基准分数变化 0.18，基准可让模型分数变化 0.16；函数级 F1 与“两侧都报”的 flag rate 相关 `+0.86`，与配对正确率只有 `+0.16` `[16]`。这意味着“同一个模型换一个基准就换个故事”不一定是模型变了，而可能是协议变了。
2. **本项目的 pair-joint 是最接近“配对推理”的产物，但 76.67% 不能直接解释为跨版本推理。** 一个不看代码内容的“选较短版本”启发式已有 **74.44%** DA；DeepSeek 的 76.67% 与它差异不显著（McNemar `p=0.6587`）。MiMo 的 86.67% 显著高于长度启发式（`p=0.0003`），但在“漏洞更短”的 130 对上仍低于 100% 的启发式 `[项目 pair_joint §7]`。
3. **位置偏差是当前最大的未控制变量。** DeepSeek 在“漏洞在 A”时 DA 为 92.22%，在“漏洞在 B”时为 61.11%，差 **31.11 pp**（Fisher `p=1.0e-06`），选 A 的比例为 65.56%。MiMo 的位置差只有 4.44 pp（`p=0.5114`）。单顺序实验不能区分“位置偏好”和“内容×位置交互” `[项目 pair_joint §4]`。
4. **强制二选一把 4 类配对结果压成 2 类，DA 与 open 4-way 的 P-C 不可比。** 现有 split-side 配对（两次独立单函数调用）DA 只有 0.089–0.122，both_clean 108–113/180；joint 强制二选一 DA 为 76.67%/86.67%。这两个数字的差异同时包含“联合输入”“强制选择”“任务先验”三个因素，不能归因于“模型会不会配对推理” `[项目 pair_joint §6；17, 16]`。
5. **Placebo 需要分布，不是一次 derangement。** 现有 `shuffled` 与 `direct` 同为 135/140，个体层面各有 4 个翻转；但只抽了一个固定 seed，无法估计 placebo 的抽样分布，且 14/140 是 no-op donor（供体证据与自身证据文本相同）`[项目 hybrid §4、§限制]`。
6. **LLM-as-judge 的可靠性要分开报告 intra-rater、inter-rater、校准与扰动敏感性。** 单一 Cohen's κ 在高一致、偏斜边际下会失真：现有盲评 COM 维度 98.8% 完全一致，但 κ=0.000；这是典型的 kappa paradox，不是“评审者完全不可靠” `[53, 54]`。
7. **补丁过拟合在 LLM 时代没有消失。** 2026 年 FSE Companion 的研究报告：不做 refinement 时 test overfitting 为 21.8%（Claude-3.7）与 33.0%（GPT-4o）；做 test-based refinement 后升到 25.5%；即使揭示 golden tests，仍有 5.8%/11.3% 的补丁通过 golden tests 但破坏回归测试 `[35]`。PVBench 中 **>40%** 被基础测试判为正确的补丁在 PoC+ 下失败 `[36]`。
8. **编译/测试/PoC 是证据阶梯，不是二值。** 本项目的 Juliet 修复已到“编译 + LSan + 行为差分”层：70/70 编译、70/70 LSan 干净、70/70 行为保持，58 个可观测单元 strict pass 58/58。但这是 ceiling，12 个 LSan 不可观测单元被排除，且没有 PoC+、mutation 或 held-out tests `[项目 juliet_repair]`。
9. **最便宜的补强不是新提示，而是 fault injection + differential testing。** 它们能在不增加 API 成本的情况下检验 oracle 强度，并暴露“通过测试但语义已变”的补丁；2026 年的差分 fuzzing 研究发现 19–35% 的 LLM 重构在语义上不等价，其中约 21% 未被现有测试套件发现 `[50]`。
10. **建议顺序：P0 只读复分析 → P1 小规模 API → P2 工程 oracle → P3 外部 Tier C。** 先做长度基线、position 重算、judge 可靠性重算、oracle 阶梯审计；再做 joint-open、双顺序、placebo K、judge 重复；最后做 mutation、差分 fuzz、stress set。所有新实验用新 run ID，不改旧结果。

---

## 1. 证据边界、检索方法与项目基线

### 1.1 本文做了什么、没做什么

| 项目 | 状态 |
| --- | --- |
| 检索并核对文献元数据（标题、作者、venue、年份、DOI/URL） | 已做；以 arXiv abs/HTML、ACL Anthology、DOI landing page、ACM DL、USENIX、OpenReview 为准 |
| 引用文献中的具体数字 | 只引用摘要或已读 HTML 中出现的数字；不根据二手博客补数字 |
| 读取本项目现有产物 | 已做；只读 `pair_joint/report.md`、`hybrid/REPORT.md`、`juliet_repair/README.md`、`repair_eval/.../summary.md`、`benchmark/README.md` 等 |
| 重新运行本项目实验 | **未做**；没有 API 调用，没有改 prompt，没有重算旧指标 |
| 修改旧结果/脚本/数据 | **未做**；本文只新增 `research/latest_evaluation_repair_2026.md` |
| 读取/打印 API key | **未做**；本文不涉及凭证 |

**证据分级**：

- **A**：正式发表，DOI/页码/ACL Anthology 可核对。用于支撑方法论与主要结论。
- **B**：arXiv 预印本，元数据已核对，但可能未同行评审或后续会改版。2026 年的新工作多属此类；引用时保留“preprint”标注。
- **C**：厂商文档、基准博客、工件说明。只用于工程事实，不作为独立研究结论。

**检索日期**：2026-11-13。2025–2026 年的预印本可能在此后更新；若正文数字与新版冲突，以新版为准，并在报告中记录访问日期。

### 1.2 只读引用的项目基线

下表是本文用到的项目数字。它们来自现有报告，**不是本文重新计算的**；若与报告冲突，以报告为准。

| 产物 | 关键数字 | 本文用途 |
| --- | --- | --- |
| `pair_joint/report.md` | DeepSeek DA 138/180 = **76.67%**（Wilson [69.97, 82.25]）；MiMo 156/180 = **86.67%**（[80.93, 90.87]） | 配对基准的主结果 |
| 同上 §7 | 字符长度“选较短”启发式 **134/180 = 74.44%**；行数版 133/180 = 73.89% | 长度 shortcut 基线 |
| 同上 §7 | DeepSeek vs 长度启发式 McNemar `b=25, c=21, p=0.6587`；MiMo `b=29, c=7, p=0.0003` | 模型增益是否超过长度 |
| 同上 §4 | DeepSeek 漏洞在 A：83/90 = **92.22%**；在 B：55/90 = **61.11%**；差 **31.11 pp**，Fisher `p=1.0e-06`；选 A 118/180 = 65.56% | position bias |
| 同上 §4 | MiMo 80/90 = 88.89%；76/90 = 84.44%；差 4.44 pp，`p=0.5114`；选 A 94/180 = 52.22% | position bias 的对照 |
| 同上 §7 | 漏洞更短 130 对、漏洞更长 44 对、等长 6 对；DeepSeek 109/130、25/44、4/6；MiMo 123/130、28/44、5/6 | 长度分层 |
| `research/improvement_opportunities.md` §2.2 | split-side 配对 DA 0.089–0.122；both_clean 108–113/180；both_flagged 44–49/180；三策略全失败 151/180 | 原“配对”实现不是联合任务 |
| `hybrid/REPORT.md` §4 | `shuffled` 安慰剂 135/140（两模型），与 `direct` 相同；`combined` DeepSeek 140/140、MiMo 138/140；个体翻转各 4 个 | placebo 设计 |
| `hybrid/REPORT.md` §限制 | 单一 derangement seed `20261112`；14/140 no-op collision | placebo 局限 |
| `juliet_repair/README.md` | 70/70 编译、70/70 LSan 干净、70/70 行为保持；58 个可观测单元 strict pass **58/58**；12 个不可观测单元排除 | 修复 oracle 的强度与 ceiling |
| `repair_eval/.../summary.md` | 30 案例 / 81 候选；VR=2 **17/81 = 21.0%**；κ：VR 0.759、SP 0.345、MIN 0.015、COM 0.000、CQ 0.654、EF 0.487、NS 0.376；COM 完全一致 0.988；compile `NOT_RUN` 81/81 | LLM/人工 rubric 可靠性 |
| `benchmark/README.md` | Tier A（SecVulEval）与 Tier B（Juliet CWE-401）分层，不跨层池化 | 评估单元与外推边界 |

### 1.3 一个简单的分解

把任何一次评估的观测分数写成：

```text
observed_score = task_signal + protocol_effect + judge_effect + sampling_noise
```

本文的九个主题分别对应这四项：

| 主题 | 主要作用项 | 典型问题 |
| --- | --- | --- |
| position bias | protocol + judge | 同一内容换槽位，结论是否翻转 |
| length shortcut | protocol + task | 不看语义的长度规则是否已经接近模型 |
| paired benchmark | protocol | 配对构造、强制选择、统计单位是否可比 |
| placebo | protocol | 观察到的是“内容效应”还是“有块东西”的格式效应 |
| LLM-as-judge | judge | 评分者自身是否稳定、是否与人一致、是否被风格左右 |
| patch overfitting | task + oracle | 通过现有测试是否等于修好 |
| compile/test/PoC | oracle | 证据强度到哪一层 |
| fault injection | oracle | oracle 能否杀死已知错误变体 |
| differential testing | oracle | 补丁是否改变了可观测行为 |

> **一句话**：如果协议效应和 judge 效应没有被测量，模型效应就不能被识别。本文建议的“测量修复”优先于“再换一种提示”。

---

## 2. 概念框架：四个评估对象、四种分数

### 2.1 四个对象

| 对象 | 输入 | 输出 | 本项目对应 |
| --- | --- | --- | --- |
| 检测器 | 单个函数 | `vulnerable/not_vulnerable` | Tier A detection（direct/few-shot/context/evidence） |
| 配对判别器 | 同一函数的两个版本 | `A/B/both/neither` 或两个 verdict | Tier A pair-joint、split-side pair |
| 修复生成器 | 漏洞函数（可选上下文） | 完整补丁 | B2 repair、Juliet repair |
| 评判器 | 代码 + 补丁 + rubric | 0/1/2 分或偏好 | repair blind eval、LLM judge |

### 2.2 四种分数不能互相替代

| 分数 | 定义 | 能回答 | 不能回答 |
| --- | --- | --- | --- |
| 函数级检测分 | P/R/F1/macro-F1（单函数） | 模型是否倾向报漏洞 | 是否理解修复差异 |
| 配对分 | P-C/P-V/P-B/P-R、DA、joint accuracy | 模型能否区分同一函数的两个版本 | 补丁是否真的修好 |
| Oracle 分 | compile/test/PoC/mutation 通过率 | 补丁在给定 oracle 下是否可用 | 语义是否等价、是否可部署 |
| Judge 分 | rubric 0/1/2、偏好 | 质量维度的主观判断 | 漏洞是否消除、行为是否保持 |

**本项目已经出现“同一模型、四种分数”的典型情况**：

- 检测 macro-F1 0.381–0.400（低召回）；
- split-side 配对 DA 0.089–0.122（两次独立调用的联合正确率）；
- joint 强制二选一 DA 0.7667/0.8667（任务形式改变后）；
- Juliet 修复 strict pass 58/58（强 oracle、ceiling）。

这些数字并不矛盾，因为它们测的不是同一件事。报告必须把“分数名称 + 任务形式 + 分母 + oracle”写全，否则读者会把它们当成同一个“能力”。

### 2.3 评估单元与外推边界

| 层级 | 单元 | 标签来源 | 可外推到 |
| --- | --- | --- | --- |
| Tier A 检测 | 函数 | SecVulEval 函数级标签 | 同数据分布的函数；不能外推到真实项目部署 |
| Tier A 配对 | 对（同一函数两版本） | `fixed_func_idx` 关联 | 同数据的“修复差异辨识”；不能外推到补丁正确性 |
| Tier B Juliet | case variant（bad/good） | Juliet 合成标签 | 同一 CWE 的合成用例；不能外推到真实项目 |
| Tier B repair | bad unit | Juliet bad + 可执行 harness | 同一 CWE 的可执行修复；不能外推到其他 CWE |
| Tier C（建议） | 真实 CVE + PoC | ARVO/Vul4Py 等 | 特定 CVE 的可执行修复；样本小，不能外推 |

---

## 3. Position bias：位置不是噪声，是变量

### 3.1 三种 position bias 要分开

| 类型 | 定义 | 例子 | 本项目位置 |
| --- | --- | --- | --- |
| **Judge position bias** | 评判者偏好 A 槽或 B 槽，与内容无关 | LLM judge 在 pairwise 评分中偏好第一个回答 | repair blind eval 的 A/B 候选顺序 |
| **Subject position bias** | 被评估模型在 A/B 任务中偏好某一槽 | pair-joint 中模型更常选 A | pair-joint 的 A/B 顺序 |
| **Prompt-order bias** | 代码、证据、指令的先后顺序影响判断 | 证据放在代码前 vs 后 | context/evidence prompt 的块顺序 |

这三类 bias 的干预不同：judge bias 用 swap + 聚合；subject bias 用双顺序重复 + 位置分层；prompt-order bias 用随机化块顺序 + 消融。**不能用一个“position bias”数字概括三者。**

### 3.2 文献证据

- Zheng 等（NeurIPS 2023）在 MT-Bench/Chatbot Arena 中系统记录了 position、verbosity、self-enhancement 三类偏差，并提出 swap 等缓解方法 `[1]`。
- Wang 等（ACL 2024）证明只需改变回答顺序，就能让 Vicuna-13B 在 80 条查询中的 66 条上“击败”ChatGPT（以 ChatGPT 为评判者）；他们提出 Balanced Position Calibration，即跨多个顺序聚合 `[2]`。
- Shi 等（IJCNLP-AACL 2025）用 15 个 judge、22 个任务、约 40 个生成模型、15 万+ 评估实例，提出三个指标：**repetition stability、position consistency、preference fairness**；结论是 position bias 不是随机噪声，随 judge、任务和“两个候选的质量差”系统变化 `[3]`。
- CodeJudgeBench（ACL 2026）在代码生成、代码修复、单元测试生成三类任务上评估 26 个 judge，发现“只改变呈现顺序”就能显著影响准确率；thinking 模型优于非 thinking，但仍有明显随机性 `[7]`。
- “Bias in the Loop”（2026）进一步显示，prompt 引起的偏差足以改变任务级结论和模型相对排名；他们主张把 **bias sensitivity** 与 accuracy 一起报告 `[9]`。

### 3.3 本项目证据：31 pp 的槽位差

`pair_joint/report.md` §4：

| 模型 | 漏洞在 A：DA | 漏洞在 B：DA | 差值 | Fisher p | 选 A / 选 B | A 占比 | 二项 p |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | 83/90 = **92.22%** | 55/90 = **61.11%** | **31.11 pp** | 1.0e-06 | 118 / 62 | **65.56%** | 3.6e-05 |
| MiMo V2.6 Flash | 80/90 = 88.89% | 76/90 = 84.44% | 4.44 pp | 0.5114 | 94 / 86 | 52.22% | 0.6020 |

**读法**：

1. A/B 顺序由 HMAC 随机产生，位置与标签在期望上独立；因此总体 DA 76.67% 是“两个位置 regime 的平均”，不是“模型稳定的配对能力”。
2. DeepSeek 的 31 pp 差不能由“两组难度不同”解释：报告用同样的 A/B 分组跑了分侧 direct 基线，DA 为 13.33% vs 10.00%，两组难度接近。
3. 但这仍是**单顺序**证据：每个 pair 只出现一次。它不能区分“模型偏好 A 槽”与“A 槽中的代码恰好更容易判”的交互。要分离，必须对同一 pair 跑 A/B 与 B/A 两次。
4. MiMo 的位置差小且不显著，提示位置偏差可能是模型特定的，而不是任务固有的；这反过来支持“position bias 是 subject 属性，不是 benchmark 常数”的假设，但当前样本量不足以证明零偏差。

### 3.4 度量：从“差值”到“可复现的指标”

| 指标 | 定义 | 需要的设计 | 解释 |
| --- | --- | --- | --- |
| `slot_flip_rate` | 同一 pair 在 A/B 与 B/A 两次运行中，预测的漏洞侧发生翻转的比例 | 双顺序 | 越高越不稳定 |
| `position_consistency` | 两次运行都选同一“内容侧”的比例（即 1 − flip） | 双顺序 | Shi 等的核心指标之一 `[3]` |
| `preference_fairness` | `abs(P(choose A) − 0.5)` | 双顺序或平衡单顺序 | 0 表示无槽位偏好 |
| `conditional_DA` | `DA` 在“漏洞在 A”与“漏洞在 B”两个条件下的值 | 单顺序即可 | 差值大表示位置×内容交互 |
| `first_position_rate` | 选 A 的比例 | 单顺序 | 只能作描述，不能单独证明 bias |
| `slot_OR` | 混合效应 logistic 回归中 `slot` 的 odds ratio | 双顺序 + 随机截距 | 控制 pair/模型差异后的位置效应 |

**建议模型**：

```text
correct_ij ~ Bernoulli(p_ij)
logit(p_ij) = beta0 + beta_slot * slot_ij + beta_len * delta_len_ij
              + beta_model * model_j + u_i + v_j
u_i ~ Normal(0, sigma_pair^2)      # pair 随机截距
v_j ~ Normal(0, sigma_model^2)     # model 随机截距（多模型时）
```

- `slot_ij`：漏洞版本是否在 A。
- `delta_len_ij`：两版本长度差（标准化）。
- 若 `beta_slot` 显著且 `exp(beta_slot)` 远离 1，报告“位置调整后 DA”，而不是单顺序 DA。
- 若样本太小，至少报告 `conditional_DA` 与 `slot_flip_rate`，不要跑过度参数化的模型。
- 若不能引入 `statsmodels`/`lme4`（本项目偏好 stdlib + `httpx`），不要硬上混合模型；改用分层 `conditional_DA` + 按 pair 的置换检验，并在报告中说明这一替代。

### 3.5 最小可检验改进 E3：双顺序审计

| 项 | 设计 |
| --- | --- |
| 数据 | `splits/test_pairs_180.json`；先做 90 对（按 hash 取前 90），或全 180 对 |
| 条件 | 每对两次：原始顺序 + 交换顺序；prompt 除槽位外逐字相同 |
| 模型 | 先 DeepSeek，再 MiMo（同 prompt、同参数） |
| 主指标 | `slot_flip_rate`、`position_consistency`、`conditional_DA`、`slot_OR` |
| 次指标 | DA（两顺序平均）、P-C/P-V/P-B/P-R、长度分层 |
| 建议验收线 | 若 `slot_OR` 的 95% CI 不包含 1，或 `conditional_DA` 差 > 10 pp，则所有主表必须报告“位置调整后 DA”；单顺序 DA 只能作附录 |
| 停止规则 | 若位置调整后 DA 的 95% CI 与长度启发式重叠，停止“跨版本推理” claim，转为“长度 + 位置的可解释基线” |
| 成本 | 90 对 × 2 顺序 × 1 模型 = 180 次请求；全 180 对 = 360 次；按 pair-joint 单次成本量级估算，量级为 USD 0.15–0.30/模型（规划，不是实测） |
| 风险 | prompt 顺序本身可能引入新的 order 效应；两顺序的请求时间不同，需交错；缓存可能影响成本 |

### 3.6 不能说的话

- 不能说“DeepSeek 的配对能力是 76.67%”——它是“在随机槽位下的平均 DA，且与长度启发式不可区分”。
- 不能说“MiMo 没有位置偏差”——4.44 pp 不显著只说明当前 180 对没有足够功效，不证明零偏差。
- 不能把 judge position bias 的数字直接套到 subject position bias；两者是不同对象。

---

## 4. Length shortcut：长度是最便宜的反例

### 4.1 三种 length effect

| 类型 | 机制 | 例子 | 本项目 |
| --- | --- | --- | --- |
| **Judge verbosity bias** | 评判者偏好更长/更详细的输出 | LLM judge 给长解释更高分 | repair rubric 的 EF/解释长度 |
| **Pair length confound** | 修复通常增加检查/代码，漏洞版本更短 | “选较短”启发式 | pair-joint 的 74.44% |
| **Detector length prior** | 函数长度与标签相关，模型利用长度 | 短函数被漏报 | 检测 FN 中位 35 行 vs TP 76–78 行 |

这三种 effect 的补救不同：judge 用长度控制回归；pair 用长度分层/匹配；detector 用长度基线/分层。**不能只报一个“长度偏差”结论。**

### 4.2 文献证据

- Dubois 等（COLM 2024）提出 Length-Controlled AlpacaEval：用广义线性模型控制“模型输出与基线输出的长度差”，回答反事实问题“如果两者长度相同，偏好会是什么”；控制后与 Chatbot Arena 的 Spearman 相关从 0.94 升到 0.98 `[13]`。
- Saito 等（2023）发现 GPT-4 在质量相近时仍偏好更长回答，并提出 verbosity bias 的度量 `[14]`。
- Risse、Liu、Böhme（PACMSE/ISSTA 2025）报告称，仅用词频/长度等表面特征就能在多个漏洞数据集上取得高分；函数级二分类的标签在脱离调用上下文时并不可判定 `[15]`。
- Cichoń 与 Dmitruk（2026）在配对基准上做了更直接的拆解：函数级 F1 与“两侧都报”的 flag rate 相关 `+0.86`，与配对正确率只有 `+0.16`；对 64/68 个模型，“同一对的两个函数得到同一答案”的频率高于独立预测；在长度匹配的 pair 上，激活线性探针的 within-pair ranking 为 0.78，tf-idf 为 0.64，长度基线为 0.5 `[16]`。
- Moon 等（Findings EACL 2026）显示，代码 judge 对变量名、注释、格式等“语义不变”的表面变化也会系统性改变评分 `[10]`。这既是 judge bias，也是“长度/风格 shortcut”的邻近现象。

### 4.3 本项目证据：74.44% 的长度启发式

`pair_joint/report.md` §7：

| 启发式 | 正确 | DA |
| --- | ---: | ---: |
| 选较短版本（字符，tie=A） | 134 | **74.44%** |
| 选较短版本（行数，tie=A） | 133 | 73.89% |

分长度层：

| 模型 | 漏洞更短（130 对） | 漏洞更长（44 对） | 等长（6 对） | vs 字符启发式 McNemar |
| --- | ---: | ---: | ---: | --- |
| DeepSeek | 109/130 = 83.85% | 25/44 = **56.82%** | 4/6 = 66.67% | `b=25, c=21, p=0.6587` |
| MiMo | 123/130 = **94.62%** | 28/44 = **63.64%** | 5/6 = 83.33% | `b=29, c=7, p=0.0003` |

**读法**：

1. 在这个 benchmark 上，“漏洞版本更短”是多数情况（130/180 = 72.2%）。一个不看语义的规则就能得到 74.44%，这给出了一个必须报告的**下界基线**。
2. DeepSeek 的 76.67% 只比长度启发式高 2.23 pp，McNemar 不显著；它的“净增益”来自“漏洞更长”的 44 对（56.82% vs 启发式的 0%），但在“漏洞更短”的 130 对上反而低于启发式（83.85% vs 100%）。这提示它同时使用了长度信号和非长度信号，但总体被长度分布掩盖。
3. MiMo 的 86.67% 显著高于启发式（+12.23 pp），且在“漏洞更长”的 44 对上达到 63.64%，说明它有超出长度的信号；但它在“漏洞更短”的 130 对上仍低于 100%，总体仍受长度分布影响。
4. 这个诊断是**测试后**加入的，不是预注册基线。新实验必须把长度基线写进预注册，否则会被质疑为事后解释。

### 4.4 度量：从“分层”到“长度控制”

| 方法 | 做法 | 优点 | 局限 |
| --- | --- | --- | --- |
| 长度基线 | 规则“选较短；等长选 A” | 零成本、可复现 | 只适用于配对；检测任务要另设阈值基线 |
| 长度分层 | 按 `Δlen` 分位数分层报告 DA | 直观 | 每层样本少，CI 宽 |
| 长度匹配子集 | 只保留 `abs(Δchars)/max ≤ 5%` 且 `abs(Δlines) ≤ 1` 的 pair | 直接控制 | n 可能很小；改变任务分布 |
| 回归控制 | `correct ~ Δlen + model`，报告 model 的调整效应 | 利用全部样本 | 函数形式假设；`Δlen` 与标签机制相关 |
| 反事实长度 | 用 GLM 预测“若长度差为 0”的偏好（AlpacaEval LC） | 与 judge 文献接轨 | 需要足够重叠；外推风险 |
| 长度匹配探针 | 在长度匹配 pair 上做 within-pair ranking | 可区分“长度”与“内容” | 需要模型内部表示，API 模型不可用 |

**建议主指标**：

```text
excess_DA = DA_model − DA_length_baseline
```

- 用 paired bootstrap（按 pair 重采样）给 `excess_DA` 的 95% CI。
- 若 CI 下界 ≤ 0，报告“不能区分于长度启发式”，不要写“模型学会了配对推理”。
- 同时报告 `DA_model` 与 `DA_length`，让读者看到绝对水平。

### 4.5 最小可检验改进 E2：长度控制审计

| 项 | 设计 |
| --- | --- |
| 数据 | 现有 180 对；预注册三个层：`vuln shorter`、`vuln longer`、`equal`；再做 5% 匹配子集 |
| 条件 | 不新增 API 即可完成分层/基线；若要长度匹配子集，直接用现有输出重算（同一 pair 的输出可复用） |
| 主指标 | `excess_DA`、分层 DA、长度基线 DA、匹配子集 DA |
| 建议验收线 | `excess_DA` 的 95% CI 下界 > 0 且 > 5 pp，才可声称“超出长度的信号”；否则写“与长度基线不可区分” |
| 停止规则 | 若匹配子集 n < 30，CI 会很宽；此时只报告点估计与“功效不足”，不做显著性 claim |
| 成本 | 零 API（复用现有输出）；工程时间约 0.5–1 天 |
| 风险 | 5% 匹配可能只剩很少 pair；`Δlen` 与 CWE/项目相关，匹配后分布偏移 |

### 4.6 检测任务也要长度基线

现有检测结果有一个明显的长度结构：FN 中位 35 行，TP 中位 76–78 行。这不能直接证明“模型用长度”，但足以要求一个长度基线：

- 在 160 条测试集上，用“函数行数 > 阈值 → vulnerable”的规则，扫阈值，报告最佳 macro-F1 / MCC。
- 用逻辑回归（仅长度 + 是否为 test path + 是否有 `memcpy/free` 等少量表面特征）作为“表面特征基线”。
- 若 LLM 的 macro-F1 不显著高于该基线，检测结论必须加限定。

这与 `[15]` 的“Top Score on the Wrong Exam”直接对应：如果一个简单特征就能拿高分，函数级分数就不能证明漏洞语义理解。

---

## 5. Paired benchmark：配对不是“两次单函数分类”

### 5.1 文献中的配对设计

- PrimeVul（ICSE 2025）把配对定义为“同一漏洞函数与其修复版本”，要求两者字符串相似度至少 80%，并报告四类结果：**P-C**（两个都判对）、**P-V**（两个都判漏洞）、**P-B**（两个都判良性）、**P-R**（判反）`[17]`。
- VulnPatchPairs / Risse & Böhme（USENIX Security 2024）从真实补丁构造 13.1k 对，发现六种 ML4VD 技术在“训练于常规数据、测试于配对数据”时无法区分漏洞与补丁 `[18]`。
- Cichoń 与 Dmitruk（2026）进一步把“配对分数”拆成协议选择：metric（函数级 F1 vs 配对四类）、verdict extraction（严格解析 vs LLM judge）、output budget（1k vs 16k–32k）；在固定模型输出时，这些选择本身就能改变结论 `[16]`。

### 5.2 四种配对协议

| 协议 | 输入 | 输出空间 | 主要测量 | 本项目 |
| --- | --- | --- | --- | --- |
| **Independent split-side** | 每次一个版本 | 每个版本 V/NV | 两次独立分类的联合正确率 | 原始 `test_v1_*_pairs`（360 次调用/策略） |
| **Joint forced-choice** | 同一 prompt 两个版本 | A/B（恰好一个） | 强制二选一的 DA | `pair_joint`（180 次调用/模型） |
| **Joint open 4-way** | 同一 prompt 两个版本 | A/B/both/neither | P-C/P-V/P-B/P-R | **未实现** |
| **Joint + diff** | 两版本 + unified diff | A/B 或四类 | 显式差异提示的上限 | **未实现** |

**关键点**：`Joint forced-choice` 把输出空间从 4 类压成 2 类，P-V/P-B 被构造排除；因此它的 DA 不能与 `Independent split-side` 的联合正确率直接比较，也不能与 `Joint open 4-way` 的 P-C 直接比较。

### 5.3 本项目证据：两个数字，两种任务

| 实现 | 调用/策略 | DA / 联合正确率 | both_clean | both_flagged | 说明 |
| --- | ---: | ---: | ---: | ---: | --- |
| split-side direct | 360 | 0.117 | 113/180 | 44/180 | 两次独立单函数分类 |
| split-side few-shot | 360 | 0.089 | 113/180 | 49/180 | 同上 |
| split-side context | 360 | 0.122 | 108/180 | 49/180 | 同上 |
| joint forced-choice DeepSeek | 180 | **0.7667** | 0（无违反指令） | 0（无违反指令） | 同一 prompt 两版本；prompt 要求恰好一个 |
| joint forced-choice MiMo | 180 | **0.8667** | 0（无违反指令） | 0（无违反指令） | 同上 |

**读法**：

1. 从 0.117 到 0.7667 的跃升，不能全部归因于“模型看到了另一侧”。它同时改变了：输入（联合 vs 独立）、输出空间（2 类 vs 4 类）、任务先验（“恰好一个” vs 不告诉）、以及可能的长度/位置利用。
2. `both_clean` 108–113/180 说明：在独立分类下，模型对同一对的两个版本几乎都给“安全”；这不是“配对能力低”，而是“模型没有被告知要比较”，且两侧高度相似（行相似度中位 0.926）。
3. 需要一个 `joint open 4-way` 条件，才能测量“联合输入”本身的价值；否则 forced-choice 的 DA 会被高估为“配对推理”。

### 5.4 统计：单元是 pair，不是 function

| 事项 | 做法 | 原因 |
| --- | --- | --- |
| 重采样单位 | pair（配对任务）/ function（检测任务） | 同一对的两个版本相关，不能当独立样本 |
| 聚类 | 按 `project` 做 cluster bootstrap | 同项目代码风格/宏/命名相关 |
| 配对检验 | McNemar 精确检验（同一 pair 上 A 对 B 错） | 二值、配对 |
| 多重比较 | 任务内 Holm | 三策略两两比较 |
| 区间 | Wilson（比例）/ bootstrap（F1、DA、差值） | 小样本、非正态 |
| 最小可检测差异 | 用 Wilson 半宽或模拟功效 | 180 对的 DA 95% CI 约 ±6–7 pp；小于 10 pp 的差异通常不可靠 |

Dror 等（ACL 2018）系统讨论了 NLP 中显著性检验的选择；Bouthillier 等（MLSys 2021）说明数据采样、初始化、超参等方差会让“单次比较”误判；两者都支持“配对设计 + 多种子/多顺序 + 区间”而不是单点 p 值 `[19, 20]`。

### 5.5 最小可检验改进 E1：2×2 协议

| 项 | 设计 |
| --- | --- |
| 因子 A | `independent`（两次单函数调用）vs `joint`（一次双版本调用） |
| 因子 B | `forced`（A/B 二选一）vs `open`（A/B/both/neither） |
| 数据 | 180 对；先做 90 对 pilot，再全量 |
| 主指标 | P-C、P-V、P-B、P-R、DA、joint accuracy |
| 次指标 | 位置分层、长度分层、证据行命中、invalid rate |
| 建议验收线 | 四格都报告；若 `joint-open` 的 P-C 比 `joint-forced` 低 > 10 pp，则 forced-choice 的“膨胀”被量化，旧 DA 必须加限定 |
| 停止规则 | 若 `joint-open` 的 P-V/P-B 很高（例如 > 40%），说明模型仍不能稳定区分；此时不应把 forced-choice 的高 DA 当作能力 |
| 成本 | independent 360 + joint 180 = 540 次/模型；若只在 90 对上做，270 次/模型（规划） |
| 风险 | open 4-way 的 schema 更复杂，invalid rate 可能上升；需要在 dev 上校准 |

### 5.6 配对 benchmark 的效度威胁

| 威胁 | 本项目表现 | 缓解 |
| --- | --- | --- |
| 标签继承 | `fixed` 只表示“对应修复”，不证明无其他漏洞 | 报告“与标签一致”，不写“补丁正确” |
| 两侧高度相似 | 行相似度中位 0.926；66 对 ≥ 0.95 | 报告相似度分层；构造“困难对”子集 |
| 两侧都可能漏洞 | 修复版本可能有其他缺陷 | open 4-way 允许 both；不要强制二选一 |
| 修复不唯一 | 同一漏洞有多种正确修法 | 不把“与参考修复不同”判错；用行为/oracle |
| 污染/记忆 | 真实开源项目可能出现在预训练数据 | 时间切分不可行；承认限制；用新数据/合成数据做敏感性 |
| 项目不平衡 | `linux` 53/180 | 项目 cluster bootstrap；报告项目分布 |

---

## 6. Placebo：没有安慰剂，就没有“内容效应”

### 6.1 什么是 placebo / negative control

在实验科学中，**negative control** 是“去掉假设中的有效成分、但保留其他条件”的对照：如果对照也产生效应，说明观测到的效应不是由假设机制引起的 `[26]`。在 LLM 评估里，常见的 placebo 有：

| Placebo 类型 | 干预 | 应该是什么结果 | 若不符合说明什么 |
| --- | --- | --- | --- |
| **Shuffled evidence** | 给另一个单元的同类证据 | 不应优于 direct；若优于，说明“有证据块”本身有用 | 证据内容不是原因 |
| **No-op patch** | 返回原函数 | VR 应低；若高，judge/oracle 坏了 | 评分器或 oracle 失效 |
| **Label permutation** | 打乱标签 | 检测应接近 chance；若高，泄漏 | 数据/提示泄漏 |
| **Format-only perturbation** | 改变量名、注释、缩进 | 评分不应显著变化；若变化，judge 被风格左右 | judge 不可靠 |
| **Inactive tool** | 给“工具已运行”的占位，不给真实发现 | 不应优于 direct；若优于，是安慰剂效应 | 工具内容的因果性不成立 |

### 6.2 文献证据

- Lipsitch 等（Epidemiology 2010）给出 negative control 的定义与选择条件：对照应共享混杂结构，但不经过假设的因果路径；对照“失败”（出现非零关联）提示偏差，但不能直接量化偏差大小 `[26]`。
- Adebayo 等（NeurIPS 2018）用“模型参数随机化”作为 sanity check：如果解释方法在随机化模型上仍然给出相似解释，说明它没有依赖模型参数 `[27]`。
- Hewitt 与 Liang（EMNLP-IJCNLP 2019）用 **control task** 校准 probe：控制任务保留输入/输出的统计结构，但去掉语言结构；如果 probe 在控制任务上也有高分，说明它学到的不是语言知识 `[28]`。
- Moon 等（Findings EACL 2026）用“语义不变的表面变化”（变量名、注释、格式）作为 code judge 的扰动对照，发现所有被测 judge 都受影响 `[10]`。
- Kosch 等（ACM TOCHI 2023）研究“AI 标签”本身如何改变用户对系统的评价，是 HCI 侧的 placebo effect 证据 `[29]`；它提醒我们，“被告知有 AI/证据”本身可能就是干预。

### 6.3 本项目证据：shuffled 与 direct 同为 135/140

`hybrid/REPORT.md` §4：

| 模型 | direct | shuffled（placebo） | combined | 个体翻转（direct→shuffled） |
| --- | ---: | ---: | ---: | ---: |
| DeepSeek | 135/140 = 96.43% | 135/140 = 96.43% | 140/140 = 100% | 4（2 个 0→1，2 个 1→0） |
| MiMo | 135/140 = 96.43% | 135/140 = 96.43% | 138/140 = 98.57% | 4（2 个 0→1，2 个 1→0） |

**读法**：

1. 两个模型的 shuffled 与 direct 聚合结果完全相同；个体层面各有 4 个翻转，方向大致对称（供体为 bad 时更容易判 vulnerable，供体为 good 时更容易判 clean）。这说明模型确实“读了”证据块的某些内容，但聚合上没有净收益。
2. combined 的 +5（DeepSeek）对应 McNemar `p=0.0625`；在 5 个 discordant 样本下不可能达到 `p<0.05`。所以“combined 100%”不能当作显著优于 direct。
3. **单一 placebo 抽样**：只抽了一个 derangement（seed `20261112`），无法估计 placebo 的抽样分布；报告自己已把这一点列为限制。
4. **no-op collision 14/140**：供体证据与自身证据文本相同，placebo 对这些单元没有实际干预；它们应被排除或单独分层。
5. **天花板效应**：direct 已经 135/140，只剩 5 个错误单元；证据最多只能修复这 5 个。这不是“证据无效”，而是“任务太容易，没有区分空间”。

### 6.4 正确的 placebo 设计

| 设计项 | 建议 |
| --- | --- |
| 抽样数 | 每个单元抽 K 个 derangement（K=10–20），而不是 1 个；至少报告 K=3 的 pilot |
| 供体匹配 | 同 CWE 家族/同长度档/同 bad-good 类型；至少禁止自身与同 group 供体（现有约束已做到后者） |
| 干预检查 | 确认 placebo prompt 与 treatment prompt 只差证据内容；长度、格式、块位置一致；记录 token 数差 |
| no-op 处理 | 计算 `placebo_effective_rate = 1 − no_op_collision_rate`；no-op 单元排除或分层 |
| 主指标 | `placebo_response = metric(shuffled) − metric(direct)`；`placebo_adjusted_effect = metric(treatment) − metric(shuffled)` |
| 区间 | 对 K 个 placebo 取均值与 95% 区间；或对单元做 bootstrap |
| 操纵检查 | 若 `placebo_response` ≈ 0，说明 placebo 太弱（模型没读）；若 `placebo_response` ≈ treatment，说明效应非特异 |
| 报告 | 同时报告 direct、treatment、placebo 三行；不要只报 treatment−direct |

**建议验收线**：

```text
|placebo_adjusted_effect| > 2 × |placebo_response|   # 内容效应大于格式效应
```

若做不到，结论应写成“证据块的格式/注意力效应不能排除”，而不是“证据内容有效”。

### 6.5 最小可检验改进 E4：placebo 分布

| 项 | 设计 |
| --- | --- |
| 数据 | Juliet test140；先 1 个模型（DeepSeek） |
| 干预 | K=10 个 derangement；供体匹配同 CWE 家族/长度档；禁止自身/同 group |
| 主指标 | `placebo_response`、`placebo_adjusted_effect`、`no_op_collision_rate` |
| 次指标 | 个体翻转方向、token 长度差、按 CWE 分层 |
| 建议验收线 | `placebo_adjusted_effect` 的 95% CI 下界 > 0，且 > 2× placebo 响应；否则判“无内容特异效应” |
| 成本 | 10 × 140 = 1,400 次请求/模型；按 hybrid 单次成本量级，规划约 USD 0.3–0.6（不是实测） |
| 风险 | 成本高；K=10 仍不足以估计极端分位；derangement 可能破坏长度匹配 |

### 6.6 不能说的话

- 不能说“shuffled 与 direct 相同，所以证据没用”——placebo 太弱或 ceiling 都会导致相同。
- 不能说“combined 100%，所以证据有效”——n=5 discordant，`p=0.0625`，且没有 placebo 分布。
- 不能把 no-op collision 当作“placebo 成功”；它是干预失败。

---

## 7. LLM-as-judge：可靠性不是 accuracy

### 7.1 四个要分开的问题

| 问题 | 定义 | 指标 | 本项目 |
| --- | --- | --- | --- |
| **Intra-rater reliability** | 同一 judge、同一 item、重复评分是否一致 | test-retest κ/ICC、exact agreement | 未测 |
| **Inter-rater reliability** | 两个 judge（人或 LLM）是否一致 | Cohen κ、Gwet AC1、ICC、Krippendorff α | 有 rater_A/B，但未记录类型/重复 |
| **Validity** | judge 分数是否反映真实质量 | 与 compile/test/PoC 的一致性、与人类专家的一致性 | 只有 rubric，没有 oracle 对照 |
| **Robustness** | 对顺序、长度、风格、prompt 扰动是否稳定 | swap consistency、score delta under perturbation | 未测 |

### 7.2 文献证据

- Zheng 等（2023）报告强 judge 与人类偏好可达 80%+ 一致，但同时记录 position/verbosity/self-enhancement bias `[1]`。
- Ye 等（ICLR 2025）识别 12 类 judge 偏差，并用 CALM 框架自动量化；即使强模型在特定任务上仍有显著偏差 `[4]`。
- G-Eval（EMNLP 2023）用 CoT + form-filling 提升与人类的 Spearman 相关，但也指出 judge 可能偏好 LLM 生成的文本 `[5]`。
- JudgeBench（ICLR 2025）构造跨知识、推理、数学、代码的困难 response pair，专门评估 LLM judge 在难例上的判别能力 `[6]`。
- CodeJudgeBench（ACL 2026）评估 26 个 code judge，发现 thinking 模型更好，但所有模型仍有显著随机性；pairwise 顺序改变会显著影响准确率 `[7]`。
- Rating Roulette（Findings of EMNLP 2025）专门测 **intra-rater reliability**：同一 judge 在不同运行中给出的分数一致性低，最坏情况下接近任意 `[8]`。
- “Bias in the Loop”（2026）用“一次只改变一个 presentation cue”的受控干预，发现 judge 决策对 prompt bias 高度敏感，甚至改变任务级结论 `[9]`。
- Moon 等（Findings EACL 2026）发现 code judge 对变量名、注释、格式等表面变化有系统性偏差 `[10]`。
- Panickssery 等（NeurIPS 2024）证明 LLM 有 self-recognition，且 self-recognition 与 self-preference 线性相关；用 LLM 评判自己的输出会引入偏差 `[11]`。
- Trust or Escalate（ICLR 2025）把 judge 的置信度与“升级到人类”结合，给出可证明的人类一致率保证；这提供了“judge 不作 oracle，而作过滤器”的设计 `[12]`。

### 7.3 指标：不要只报 Cohen's κ

| 指标 | 适用 | 说明 |
| --- | --- | --- |
| Cohen's κ | 两个评分者、名义类别 | 受边际分布影响；高一致低 κ 是常见 paradox |
| Gwet's AC1 | 两个/多个评分者、偏斜边际 | 在“高一致、类别不平衡”时比 κ 稳定 `[54]` |
| ICC(2,k) | 有序/连续分数、多个评分者 | 同时考虑评分者与 item 方差 `[55]` |
| Krippendorff's α | 任意评分者数、缺失数据 | 通用但计算复杂 |
| Exact agreement | 任何 | 直观，但不校正 chance |
| PABAK | 二分类、偏斜 | 校正 prevalence，但解释性弱 |
| ECE / Brier | judge 输出概率 | 校准，不是一致性 |
| AUC | judge 置信度→正确 | 排序能力 |
| Coverage-risk | 选择性预测 | 高置信子集的准确率/覆盖率 |

**kappa paradox**：Feinstein 与 Cicchetti（1990）指出，当两个评分者的边际分布高度偏斜时，即使 observed agreement 很高，κ 也可能接近 0 `[53]`。本项目的 COM 维度就是例子：81/81 都给 2 分，完全一致 0.988，但 κ=0.000。此时应报告 AC1/ICC 或直接说“该维度无方差，无法估计一致性”，而不是“评审者完全不一致”。

### 7.4 本项目证据：VR 可靠，MIN/SP/NS 不稳定

`repair_eval/analysis/repair_blind_v1/final/summary.md`：

| 维度 | 均值 | 2 分率 | Cohen's κ | 二次加权 κ | 完全一致 | 读法 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| VR | 0.481 | 0.210 | **0.759** | 0.902 | 0.901 | 可靠，可作为主终点 |
| SP | 1.765 | 0.778 | 0.345 | 0.409 | 0.802 | 中等偏低；边界案例多 |
| MIN | 1.593 | 0.593 | **0.015** | 0.015 | 0.580 | 差；最小性定义不清 |
| COM | 2.000 | 1.000 | **0.000** | 0.000 | 0.988 | 无方差；κ paradox，不是“不一致” |
| CQ | 1.963 | 0.963 | 0.654 | 0.654 | 0.975 | 可接受 |
| EF | 1.148 | 0.259 | 0.487 | 0.658 | 0.679 | 中等；解释忠实性难评 |
| NS | 1.877 | 0.914 | 0.376 | 0.621 | 0.926 | 中等偏低；高一致但边际偏斜 |

**读法**：

1. VR 的 κ=0.759 支持“根因是否消除”这一维度相对可靠；但 VR=2 只有 17/81，且没有 compile/PoC 对照，所以它仍是“rubric 判断”，不是“补丁正确”。
2. MIN 的 κ=0.015 说明“最小性”几乎不可复现；要么锚点不清，要么评审者对“最小”理解不同。继续把它当主指标会引入噪声。
3. COM 的 κ=0.000 是统计 artifact：所有候选都是 2 分，没有方差；应报告“该维度在本次样本中无区分度”，而不是“评审者不一致”。
4. 现有 summary 没有记录评审者类型（人/LLM）、模型版本、prompt、重复次数、评分顺序；`improvement_opportunities.md` 将其描述为“LLM 辅助评审”。无论哪种，都必须补齐这些元数据，否则无法复现。
5. `compile_status` 81/81 为 `NOT_RUN`；这意味着 rubric 的 CV/CQ 维度没有外部 oracle 对照，不能用来声称“可编译”或“行为保持”。

### 7.5 最小可检验改进 E5：judge 可靠性审计

| 项 | 设计 |
| --- | --- |
| 样本 | 现有 30 案例 × 81 候选；分层抽 20 案例做重复 |
| 设计 | 2 个 judge × 2 次重复 × 2 种顺序（A/B, B/A）；20% 由人类双评分 |
| 主指标 | 每维度 Cohen κ、Gwet AC1、ICC(2,k)、exact agreement；judge 间/内 |
| 次指标 | ECE/Brier（若输出置信度）、与 compile/LSan/behavior 的一致性 |
| 建议验收线 | VR/NS 的 AC1 ≥ 0.6；MIN/EF/SP ≥ 0.4；低于阈值的维度只作探索性报告 |
| 停止规则 | 若某维度 AC1 < 0.4，停止把它作为主指标；改为定性案例或合并维度 |
| 成本 | 若 judge 是 LLM：20 × 2 × 2 × 2 = 160 次 judge 调用（一次评分覆盖多个维度）；若人类：约 10–15 人时（规划） |
| 风险 | 人类评分成本高；LLM judge 可能共享同一偏差；顺序效应本身需要平衡 |

### 7.6 Judge 的正确用法

- **不要**把 LLM judge 当作补丁正确性的唯一 oracle；它只能评“解释是否忠实”“改动是否最小”“风格是否可读”等软维度。
- **要**把 compile/test/PoC 作为硬 oracle；judge 只用于硬 oracle 无法覆盖的维度，并报告其可靠性。
- **要**在 judge prompt 中随机化候选顺序、隐藏策略/模型名、固定 rubric 锚点、记录 prompt hash。
- **要**报告 judge 的模型版本、温度、重复次数、顺序、是否人类校准；否则数字不可复现。
- **要**使用 abstention/ escalate：当 judge 置信度低或维度不可靠时，转人工，而不是强行给分 `[12]`。

---

## 8. Patch overfitting：通过测试不等于修好

### 8.1 定义与分类

| 概念 | 定义 | 与本项目的关系 |
| --- | --- | --- |
| **Plausible patch** | 通过现有测试/ harness 的补丁 | Juliet strict pass 58/58 是比 plausible 更强的证据（编译 + LSan + 行为） |
| **Correct patch** | 真正修复根因、保持语义、符合开发者意图 | 需要 PoC+ / 差分 / 人工审查 |
| **Test overfitting** | 通过 observed tests，但在 held-out tests 上失败 | 本项目没有 held-out tests |
| **Symptom-only patch** | 只消除症状（如把泄漏改成 exit），不修根因 | 可能通过 LSan，但行为改变 |
| **Semantic drift** | 补丁改变了未覆盖路径的行为 | 行为差分只覆盖固定输入 |
| **Reward hacking** | 利用 oracle 的漏洞（禁用测试、伪造输出） | 需要防篡改/独立 oracle |

### 8.2 文献证据

- Smith 等（ESEC/FSE 2015）提出 APR 的 overfitting 问题：用同一套测试生成和验证补丁会系统性高估修复率；“cure worse than disease” `[30]`。
- Qi 等（ISSTA 2015）对 GenProg 的补丁做人工分析，发现大量“plausible”补丁并不正确，强调需要语义级验证 `[31]`。
- Ye 等（EMSE 2021）在大规模 APR 补丁上做自动正确性评估，说明“自动评估”本身可以作为研究对象 `[32]`。
- Fei 等（TOSEM 2025）系统综述 patch correctness assessment，结论是没有单一 oracle 足够，通常需要组合证据 `[33]`。
- Yang 等（2025）的 LLM-based APR 综述把 66 个修复系统按微调/提示/流程/agent 分类，并指出不同基准的协议差异使结果难以直接比较 `[38]`；Hu 等的 SoK 把自动漏洞修复拆成漏洞分析、补丁生成、补丁验证，并用 Vul4C 评估 7 个 C/C++ 工具 `[39]`。
- Poracle（TOSEM 2023）用 **preservation conditions** 检验补丁：在“补丁前后都应保持相同行为”的上下文里，如果行为不同，就拒绝补丁 `[34]`。这与本项目的“行为差分”最接近。
- Ahmed 等（FSE Companion 2026）给出 LLM 时代的最新数字：
  - 不做 refinement：Claude-3.7 的 test overfitting **21.8%**（50/229），GPT-4o **33.0%**；
  - 做 test-based refinement：Claude-3.7 升到 **25.5%**（64/251），其中 22 个 refined patch 有 14 个过拟合；
  - 即使揭示 golden tests，仍有 **5.8%**（Claude）与 **11.3%**（GPT-4o）的补丁通过 golden tests 但破坏回归测试；
  - 过拟合补丁的覆盖率中位数 <0.8，未过拟合补丁为 1；覆盖率可以作为早期警告 `[35]`。
- PVBench（2026）构造 209 个案例、20 个项目，每个案例含基础测试（功能测试 + PoC exploit）与 **PoC+**（开发者新增测试）；三个 SOTA AVR 系统中，**>40%** 被基础测试判为正确的补丁在 PoC+ 下失败 `[36]`。
- Vul4Py（2026）为 100 个 Python 漏洞、60 个项目、60 个 CWE 提供 **paired oracle**：exploit oracle 必须在漏洞版本失败、在修复版本通过；pytest 功能 oracle 必须在两者都通过。仅用 exploit oracle 会接受 119 个补丁，paired oracle 拒绝其中 15 个；通过的 104 个中有 98 个被人工确认与开发者补丁语义等价 `[37]`。
- SWE-bench+（2024）人工筛查发现：32.67% 的“成功”补丁存在 solution leakage，31.08% 的通过补丁因测试过弱而可疑；过滤后 SWE-Agent+GPT-4 的解决率从 12.47% 降到 3.97% `[25]`。
- PatchGuru（2026）从 PR 的自然语言工件推断 patch oracle；论文报告，在其 fault injection campaign 中，推断 oracle 的 mutation score 为 **0.70**，现有回归测试为 **0.58** `[52]`。

**这些数字的共同含义**：测试通过是一个**弱 oracle**；在 LLM 生成补丁的场景里，它既会漏掉语义回归，也会被“看起来对”的补丁欺骗。需要 held-out tests、PoC+、mutation、differential testing 或人工审查来补强。

### 8.3 本项目证据：强 oracle，但 ceiling

`juliet_repair/README.md`：

| 指标 | DeepSeek V4.1 Flash | MiMo V2.6 Flash |
| --- | ---: | ---: |
| 编译通过 / 70 | 70 | 70 |
| LSan 干净 / 70 | 70 | 70 |
| 行为保持 / 70 | 70 | 70 |
| strict pass / 58 个可观测单元 | **58** | **58** |
| 首次回答即 strict pass / 58 | 58 | 57 |
| 反馈迭代次数 | 0 | 2 |
| 真实 API 调用 | 70 | 72 |
| 成本 USD | 0.026990 | 0.005841 |

**这个 oracle 比 Tier A 强很多**：它不是“与标签一致”，而是“编译 + LSan 不报泄漏 + 可观测行为逐行一致”。它对 CWE-401 是合适的，且 `check_baselines.py` 证明了净化后的输入与原始 bad 单元行为一致（70/70）。

**但它仍不是“补丁正确”**：

1. **12 个 LSan 不可观测单元被排除**：其中 7 个 `malloc_realloc` latent、5 个 `..._68` 全局 reachable。这些单元编译通过、行为保持，但不能证明泄漏被移除。排除是诚实的，但也意味着 strict pass 的分母不是 70。
2. **只有一个 CWE、一个 harness、一个输入路径**：CWE-401 的泄漏通常发生在固定路径；补丁可能通过“改走另一条路径”或“提前 exit”来消除可观测泄漏，而行为差分只比较固定输入。
3. **没有 PoC+**：没有“开发者新增的语义测试”来检查补丁是否保持分配/释放契约、错误路径、所有权转移。
4. **没有 mutation/fault injection**：无法知道 oracle 能否杀死“已知错误但通过测试”的补丁。
5. **ceiling 效应**：58/58 意味着任务对这两个模型太容易，无法区分模型/提示；它不能支持“修复能力强”的比较结论，只能支持“在这个 CWE 上，这些补丁通过了这个 oracle”。

### 8.4 过拟合风险的具体场景

以下都是**假设性反例**，用于设计 stress set，不是对现有补丁的指控：

| 反例 | 如何通过现有 oracle | 为什么仍可能错 | 需要什么 oracle |
| --- | --- | --- | --- |
| 删除分配 | 不分配就不泄漏；编译通过；行为可能在某些输入下不同 | 功能缺失 | 功能测试 / 行为差分（覆盖分配路径） |
| 提前 `exit(0)` | LSan 不报泄漏；退出码可能“正常” | 程序提前终止 | 行为差分（stdout/exit code/后续逻辑） |
| 只 `free` 不置空 | LSan 干净；后续 use-after-free 未触发 | 生命周期错误仍在 | ASan/UAF 测试 / PoC |
| 改小分配尺寸 | 泄漏字节数变 0 或变小 | 缓冲区溢出/截断 | 边界测试 / ASan |
| 关闭 sanitizer | LSan 不报 | 掩盖问题 | 独立 oracle / 防篡改 |
| 返回原文但改注释 | 行为完全一致；编译通过 | 漏洞仍在 | 漏洞复现 / PoC |
| 只修一条错误路径 | 固定 harness 走不到另一条路径 | 其他路径仍泄漏 | 多路径 harness / 差分 fuzz |

### 8.5 最小可检验改进 E6：oracle 阶梯 + stress set

| 项 | 设计 |
| --- | --- |
| 数据 | 现有 30 个 repair 案例（或 58 个可观测单元中的 20 个） |
| Oracle 阶梯 | L2 编译 → L3 现有测试 → L4 行为差分 → L5 PoC exploit → L6 PoC+（新增语义测试）→ L7 mutation |
| Stress set | 手写/离线生成 20 个 plausible-but-wrong 补丁：no-op、symptom-only、semantic drift、delete-allocation、early-exit、double-free 等 |
| 主指标 | 每一级的 strict pass；stress set 的 **false accept rate**（被 oracle 判为通过的比例） |
| 次指标 | 每级 relative to L2 的“oracle gain”；按 CWE/长度分层 |
| 建议验收线 | stress set false accept ≤ 10%；若 > 20%，oracle 太弱，不能用于新方法比较 |
| 停止规则 | 若 L4 与 L2 的通过率几乎相同，说明行为差分没有增加信息；应直接上 L5/L6，而不是继续堆 L4 |
| 成本 | 工程时间为主；stress patches 可离线生成，不需要 API；PoC+ 需要人工设计 20 个测试（约 1–2 人日） |
| 风险 | stress patches 可能过于人工；需要专家确认“这些确实是错误补丁”；PoC+ 可能引入新的偏差 |

### 8.6 不能说的话

- 不能说“58/58 = 100% 修复正确率”——它只是 58 个可观测单元、一个 CWE、一个 harness 上的 strict pass。
- 不能说“LSan 干净 = 没有泄漏”——12 个不可观测单元没有证据。
- 不能说“行为保持 = 语义等价”——只比较了固定输入的可观测输出。
- 不能说“编译通过 = 补丁可用”——编译只证明语法/类型/链接的基本正确性。

---

## 9. Compile / test / PoC：证据阶梯

### 9.1 八级证据

| 级别 | 证据 | 能证明 | 不能证明 | 本项目状态 | 成本 |
| ---: | --- | --- | --- | --- | --- |
| L0 | 数据集标签 | 与标注一致 | 真实漏洞/修复正确性 | Tier A 检测、Tier A 配对 | 低 |
| L1 | 语法检查（`clang -fsyntax-only`） | 语法可解析 | 类型/链接/行为 | 协议试点 0/20 通过（片段缺头文件） | 低 |
| L2 | 项目/stub 编译 | 语法/类型/链接基本正确 | 行为正确、漏洞已修 | Juliet repair 70/70 | 中 |
| L3 | 现有回归测试 | 在测试覆盖范围内行为正确 | 未覆盖输入、语义等价 | Juliet 行为检查接近此级 | 中 |
| L4 | 行为差分（pre/post 同输入） | 可观测行为未变 | 未观测路径、语义等价 | Juliet 70/70 行为保持 | 中 |
| L5 | PoC exploit 失败 | 原始攻击路径被阻断 | 其他攻击路径、功能回归 | **未做** | 高 |
| L6 | PoC+（开发者新增测试） | 修复满足更多语义意图 | 所有可能行为 | **未做** | 高 |
| L7 | Mutation / fault injection | oracle 能杀死已知错误变体 | 真实漏洞是否消除 | **未做** | 中高 |
| L8 | 语义等价/形式化/人工审查 | 最接近“正确” | 规格本身的正确性 | 仅 rubric 人工/LLM 评分 | 很高 |

### 9.2 每一级的“可声称/不可声称”

| 级别 | 可以写 | 不能写 |
| --- | --- | --- |
| L2 | “补丁在给定 stub/项目配置下编译通过” | “补丁可编译”（若只是 stub）、“漏洞已修” |
| L3 | “补丁通过现有测试” | “补丁正确” |
| L4 | “在观测输入上，补丁与原始版本行为一致” | “语义等价” |
| L5 | “原始 PoC 在补丁上不再成功” | “漏洞已消除”（可能有其他 PoC） |
| L6 | “补丁通过开发者新增测试” | “补丁符合开发者意图”（测试仍不完整） |
| L7 | “oracle 能杀死 X% 的非等价 mutant” | “补丁正确” |
| L8 | “在给定规格/审查下等价/正确” | “绝对正确” |

### 9.3 外部基准的尺度

| 基准 | 规模 | 关键数字 | 对本文的用途 |
| --- | --- | --- | --- |
| ARVO | 6,100+ 漏洞、311 项目 | 81% 可复现；89.4% 补丁定位准确 | 说明“可复现 + PoC”是大规模评估的基础 `[40]` |
| CyberGym | 1,507 漏洞、188 项目 | 顶级组合 PoC 成功率约 20%；发现 34 个 0-day、18 个历史不完整补丁 | 说明真实漏洞 PoC 很难，且能发现“已修但未修好” `[41]` |
| VulnRepairEval | 23 个 Python CVE、12 个 LLM | 最佳模型 5/23（21.7%） | 说明 exploit-based 评估会大幅压低“修复率” `[42]` |
| PVBench | 209 案例、20 项目 | >40% 基础测试正确的补丁在 PoC+ 失败 | 说明“测试通过”高估修复 `[36]` |
| Vul4Py | 100 漏洞、60 项目、60 CWE | paired oracle 拒绝 15/119 个 exploit-only 接受的补丁 | 说明 exploit + functional 双 oracle 的必要性 `[37]` |
| AutoPatchBench | 136 个 fuzzing 发现的 C/C++ 漏洞、11 种 crash | 双容器 + fuzzing + 白盒差分 | 说明差分/ fuzz 是可执行的补丁验证路径 `[43]` |
| SecVulEval | 25,440 函数、5,867 CVE | 语句级 F1 23.83%（最佳） | 本项目的数据源；不是修复 oracle `[44]` |

### 9.4 本项目应处的层级

- **Tier A 检测/配对**：L0。它们的结论是“与标签一致/配对判别”，不是“漏洞可利用性”。
- **Tier B Juliet 修复**：L2–L4。强于 L0，但仍不是 L5–L7。
- **Tier B 静态/动态**：静态是 L1–L2（工具能否解析/编译），动态是 L4 的运行时证据（ASan/LSan/Valgrind），但“clean”不等于“无漏洞”。
- **建议 Tier C**：L5–L6。若时间允许，从 ARVO/Vul4Py 选 10–20 个 C/C++ 案例，做“编译 → PoC 失败 → 回归测试通过”的最小闭环；不要把这部分强加到现有 200 对 JSON 上。

### 9.5 不能跨层池化

把 Tier A 的 160 个函数、Tier B 的 140 个 Juliet 单元、Tier C 的 20 个 CVE 池化成一个“平均 F1”没有解释力：标签来源、单元结构、类别先验、代码形态、分母和成本口径都不同。`benchmark/PROTOCOL.md` 已经明确“统一契约、分层比较”；本文支持这一原则，并建议在报告中把“层级”作为一等字段。

---

## 10. Fault injection：用已知错误检验 oracle

### 10.1 四个概念

| 概念 | 做法 | 回答的问题 | 典型指标 |
| --- | --- | --- | --- |
| **Mutation testing** | 对程序做小修改（mutant），看测试是否失败 | 测试套件有多强 | mutation score |
| **Fault injection** | 向程序/环境注入故障（分配失败、I/O 错误、时序） | 系统能否处理异常 | fault detection rate |
| **Mutation-based consistency testing (MCT)** | 对代码做语义变异，看 LLM 判断是否一致变化 | LLM 是否真的理解代码 | consistency rate |
| **Differential fault injection** | 对原始版本和补丁版本注入相同故障 | 补丁是否改变故障响应 | paired agreement / divergence |

### 10.2 文献证据

- Jia 与 Harman（IEEE TSE 2011）系统综述 mutation testing：mutation score = killed / (total − equivalent)，是测试强度的经典度量 `[45]`。
- Hsueh 等（Computer 1997）综述 fault injection 的技术与工具：硬件/软件故障注入、错误传播、覆盖率 `[46]`。
- Li 与 Shin（CAIN 2024）提出 MCT：对代码做变异，检查 LLM 的判断是否随语义变化而一致变化；该工作把 MCT 作为评估代码理解（尤其是代码与自然语言语义细微不一致）的方法 `[47]`。
- PatchGuru（2026）在 fault injection campaign 中比较“推断 oracle”与“现有回归测试”：论文报告 mutation score 0.70 vs 0.58，说明更好的 oracle 能杀死更多 mutant `[52]`。
- Coleman 等（2026）做 differential fault injection：在 GAMESS 的 12 个位置注入相同、确定性的故障，比较原始与 LLM 现代化版本的响应；2,200+ 次运行，200 对注入全部一致 `[51]`。这是“同一故障、两个版本”的直接模板。

### 10.3 本项目的 fault operators

针对 CWE-401（内存泄漏）与一般 C/C++ 补丁，建议至少覆盖：

| 算子 | 示例 | 预期 oracle 反应 |
| --- | --- | --- |
| 删除清理 | 删除 `free(p)` | LSan 应报泄漏 |
| 删除空检查 | 删除 `if (p != NULL)` | ASan 应报空指针/崩溃 |
| 悬空指针 | `free(p); p = NULL;` → `free(p);` | 后续使用应被 ASan 捕获 |
| 双重释放 | 增加第二次 `free(p)` | ASan 应报 double-free |
| 分配失败未处理 | 删除 `if (p == NULL) return` | 故障注入（malloc fail）应触发 |
| 边界改变 | `i < n` → `i <= n` | ASan 应报越界 |
| 提前退出 | 在清理前 `return` | LSan 应报泄漏 |
| 错误路径跳过 | 删除 error label 的清理 | 多路径 harness 应报泄漏 |

### 10.4 设计：先验证 oracle，再验证模型

**关键原则**：fault injection 的对象是 **oracle**，不是模型。先用已知错误变体验证“oracle 能不能抓住”，再谈“模型修得好不好”。

| 步骤 | 做法 | 产物 |
| --- | --- | --- |
| 1. 基线 | 对每个原始 bad 单元，确认 harness 能观测到泄漏/故障 | `baseline_detected` |
| 2. 正向对照 | 人工注入一个已知泄漏/双 free，确认 oracle 报错 | `positive_control_pass` |
| 3. 补丁 mutant | 对每个补丁生成 20 个 mutant；编译并运行 oracle | `mutant_kill_matrix` |
| 4. 等价 mutant | 人工/编译器判定等价 mutant；从分母排除 | `equivalent_rate` |
| 5. 指标 | mutation score、fault detection rate、false kill rate | `oracle_strength.json` |
| 6. 报告 | 按 CWE/算子/模型分层；报告未决 mutant | 报告表 |

### 10.5 指标

```text
mutation_score = killed_mutants / (total_mutants − equivalent_mutants)
fault_detection_rate = detected_security_faults / total_security_faults
false_kill_rate = killed_behavior_preserving_mutants / total_behavior_preserving_mutants
```

- **mutation score** 高，说明 oracle 对语法/语义变化敏感；但它不直接等于“能发现真实漏洞”。
- **fault detection rate** 只看安全相关故障（泄漏、UAF、越界、double-free）。
- **false kill rate** 衡量 oracle 是否过于激进（把行为保持的 mutant 也判错）；太高会误伤正确补丁。
- **等价 mutant** 必须排除；否则 mutation score 会被低估。

### 10.6 最小可检验改进 E7：mutation + differential fault injection

| 项 | 设计 |
| --- | --- |
| 数据 | Juliet CWE-401 的 10 个可观测单元 × 每个 20 个 mutant = 200 个 mutant |
| 模型 | 不影响 oracle 强度；先用一个模型的补丁集，再用另一个模型的补丁集重复；oracle 强度按补丁集分层 |
| 主指标 | mutation score、fault detection rate、false kill rate |
| 次指标 | 按算子/长度/CWE 分层；与人工审查的一致性 |
| 建议验收线 | mutation score ≥ 0.80；security fault detection ≥ 0.90；false kill ≤ 0.10 |
| 停止规则 | 若 mutation score < 0.60，oracle 太弱，先修 oracle，不要用它比较新方法 |
| 成本 | 计算为主；200 个 mutant × 编译/运行，预计数小时；无 API |
| 风险 | mutant 可能不真实；等价 mutant 判定主观；编译器优化可能消除 mutant |

### 10.7 与 differential testing 的关系

- Mutation testing 是“人工制造错误”，看测试是否发现。
- Differential testing 是“同一输入跑两个版本”，看输出是否不同。
- Differential fault injection 是“同一故障注入两个版本”，看响应是否不同。
- 三者可以组合：对每个故障，同时注入原始/补丁，比较“谁报警、谁不报警”；这比单独 mutation score 更能区分“oracle 强”与“补丁改变了行为”。

---

## 11. Differential testing：不需要预期输出，也能发现语义变化

### 11.1 定义与 oracle

Differential testing（McKeeman 1998）把同一输入喂给两个版本/实现，任何输出差异都是待调查的信号 `[49]`。它不需要“预期输出”，因此适合：

- 补丁前后行为比较；
- 两个模型生成的补丁比较；
- 编译器/解释器/重构工具的比较；
- 同一程序在不同优化/配置下的比较。

Le 等（PLDI 2014）的 EMI（equivalence modulo inputs）进一步说明：如果两个版本在“所有相关输入”上一致，才可认为等价；实际测试只能覆盖有限输入 `[48]`。

### 11.2 四种差分

| 类型 | 对比对象 | 用途 | 本项目 |
| --- | --- | --- | --- |
| Cross-version | 漏洞版本 vs 补丁版本 | 补丁是否改变行为 | Juliet 已有“固定输入行为一致”检查 |
| Cross-implementation | 模型 A 补丁 vs 模型 B 补丁 | 哪个补丁更保守/更接近参考 | 可对 70 个单元做 |
| Cross-input | 同一版本在不同输入下 | 发现边界/错误路径 | 需要 harness 参数化 |
| Cross-fault | 同一版本在故障注入下 | 补丁是否改变故障响应 | 见 §10 |

### 11.3 文献证据

- Dristi 与 Dwyer（2026）用 differential fuzzing 检查 LLM 生成的重构：6 个 LLM、3 个数据集、2 种重构类型；19–35% 的重构在语义上不等价；约 21% 的不等价重构未被现有测试套件发现。结论是“依赖现有测试会高估功能等价性” `[50]`。
- Vul4Py（2026）用 paired oracle（exploit + functional）拒绝 15/119 个仅通过 exploit 的补丁；这本质上是“跨 oracle 的差分” `[37]`。
- Coleman 等（2026）用 differential fault injection 比较原始/现代化版本在相同故障下的响应；200 对注入全部一致，说明该方法可以验证“现代化没有改变故障行为” `[51]`。
- Poracle（2023）用 preservation conditions 指定“哪些上下文下补丁前后应一致”，是差分测试的规格化版本 `[34]`。

### 11.4 本项目的 differential harness

**目标**：对每个 Juliet 单元，比较原始 bad 程序与补丁程序在相同输入下的可观测行为。

| 组件 | 做法 | 注意 |
| --- | --- | --- |
| 输入 | 优先用 harness 的 argv/env/stdin；若固定，用编译期宏生成多个变体 | 不要只跑默认路径 |
| 观测 | stdout、stderr、exit code、ASan/LSan 状态、泄漏字节数 | 分别记录，不要合并成一个“pass” |
| 分类 | 预期差异（exploit 输入）、回归（benign 输入）、无差异 | 预期差异需要人工/规格标注 |
| 覆盖 | 记录每个输入是否到达分配/释放/错误路径 | 没有覆盖的差异不可解释 |
| 重复 | 每个输入跑 3 次，排除非确定性 | 时间/随机种子固定 |
| 报告 | 差异率、回归率、sanitizer delta、未覆盖路径 | 不把“无差异”当“等价” |

### 11.5 指标

```text
divergence_rate = divergent_inputs / total_inputs
regression_rate = benign_divergent_inputs / total_benign_inputs
sanitizer_delta = P(sanitizer_error | patched) − P(sanitizer_error | original)
test_blind_spot = divergent_inputs not covered by existing tests / divergent_inputs
```

- `divergence_rate` 高不一定是坏事：修复本来就会改变 exploit 输入的行为。
- `regression_rate` 才是关键：在 benign 输入上不应有差异。
- `test_blind_spot` 衡量现有测试漏掉了多少差异；这正是 `[50]` 的 21% 所对应的量。

### 11.6 最小可检验改进 E8：差分 fuzz

| 项 | 设计 |
| --- | --- |
| 数据 | 20 个 Juliet CWE-401 单元（bad + 补丁） |
| 输入 | 每个单元 1,000 个输入：边界值、随机长度、错误路径触发、分配失败注入 |
| 主指标 | regression_rate、divergence_rate、sanitizer_delta、test_blind_spot |
| 次指标 | 首个差异输入、覆盖路径、按算子分层 |
| 建议验收线 | benign 输入 regression_rate = 0（或报告具体案例）；exploit 输入至少 1 个差异；test_blind_spot 单独报告 |
| 停止规则 | 若 harness 无法参数化（输入固定），不要伪造“fuzz”；改为 source-level 变体或明确写“未做” |
| 成本 | 工程为主；20 × 1,000 × 2 版本 = 40,000 次运行，可在 WSL 本地完成；无 API |
| 风险 | 输入生成可能不真实；非确定性；ASan/LSan 的开销；等价但输出不同的合法差异 |

### 11.7 限制

- **等价不可判定**：没有差异只说明“在测试输入上无差异”，不证明语义等价。
- **输入分布**：fuzz 输入可能偏离真实使用；需要报告生成策略与覆盖。
- **规格缺失**：某些差异是允许的（修复本来就会改变 exploit 行为）；需要人工/规格标注“预期差异”。
- **harness 偏差**：harness 本身可能改变程序行为；需要用基线对照。
- **非确定性**：时间、随机数、并发可能导致假差异；固定种子/重复运行。

---

## 12. 方法映射：九个可检验改进

> 下表中的“建议验收线”都是**设计目标**，不是实测结果。每个实验都必须先写预注册（主指标、停止规则、样本量），再运行；不得在看到 test 结果后改主指标。

### 12.1 配对、位置与长度（E1–E3）

| ID | 文献依据 | 本项目现状 | 可检验假设 | 最小实验 | 主指标 | 建议验收线 | 停止/反例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **E1** 2×2 配对协议 | PrimeVul 四类 `[17]`；协议效应 `[16]` | split-side DA 0.089–0.122；joint forced 0.767/0.867；无 joint-open | 强制二选一会抬高 P-C；joint-open 会恢复 P-V/P-B | 90/180 对 × {independent, joint} × {forced, open} | P-C、P-V、P-B、P-R、DA、joint accuracy | 四格全报；若 joint-open 的 P-C 比 joint-forced 低 >10 pp，旧 DA 必须加“forced-choice”限定 | 若 joint-open 的 P-V/P-B >40%，不能声称“配对推理”；只能声称“强制选择下的判别” |
| **E2** 长度控制 | AlpacaEval LC `[13]`；Top Score `[15]`；协议效应 `[16]` | 长度启发式 74.44%；DeepSeek 76.67% 不显著；MiMo 86.67% 显著 | DeepSeek 的 excess≈0；MiMo 的 excess>0 | 复用 180 对输出；分层 + 5% 匹配子集；`excess_DA` bootstrap | `excess_DA`、分层 DA、匹配子集 DA | `excess_DA` 的 95% CI 下界 >0 且 >5 pp | 若匹配子集 n<30，只报点估计与“功效不足”，不做显著性 claim |
| **E3** 双顺序位置审计 | MT-Bench `[1]`；Balanced Position `[2]`；Shi 三指标 `[3]`；CodeJudgeBench `[7]`；Bias in the Loop `[9]` | DeepSeek 92.22% vs 61.11%（31.11 pp）；MiMo 4.44 pp；单顺序 | slot 效应在 DeepSeek 上持续；MiMo 小 | 90 对 × 2 顺序；同 prompt 除槽位外逐字相同 | `slot_flip_rate`、`position_consistency`、`conditional_DA`、`slot_OR` | `slot_OR` 的 95% CI 不含 1，或条件 DA 差 >10 pp → 主表报位置调整后 DA | 若位置调整后 DA 与长度基线 CI 重叠，停止“跨版本推理” claim |

### 12.2 Placebo 与 judge（E4–E5）

| ID | 文献依据 | 本项目现状 | 可检验假设 | 最小实验 | 主指标 | 建议验收线 | 停止/反例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **E4** Placebo 分布 | Negative controls `[26]`；sanity checks `[27]`；control tasks `[28]`；HCI placebo `[29]`；风格扰动 `[10]` | shuffled=direct=135/140；单一 seed；14/140 no-op | placebo response 小；treatment−placebo 也小 | K=10 derangement，1 个模型；供体匹配 CWE/长度 | `placebo_response`、`placebo_adjusted_effect`、`no_op_rate` | adjusted 的 95% CI 下界 >0，且 >2× placebo response | 若 adjusted≈0，写“无内容特异效应”，不写“证据无效” |
| **E5** Judge 可靠性 | MT-Bench `[1]`；G-Eval `[5]`；JudgeBench `[6]`；CodeJudgeBench `[7]`；Rating Roulette `[8]`；Bias in the Loop `[9]`；风格偏差 `[10]`；self-preference `[11]`；Trust or Escalate `[12]`；κ paradox `[53,54]`；ICC `[55]`；Cohen `[56]` | VR κ=0.759；MIN 0.015；COM 0.000 但 98.8% 一致；无 test-retest | VR 可靠；MIN/SP/NS 不稳定；COM 无方差 | 20 案例 × 2 judge × 2 重复 × 2 顺序；20% 人类双评 | 每维度 AC1、ICC(2,k)、exact agreement；ECE/Brier | VR/NS AC1 ≥0.6；MIN/EF/SP ≥0.4 | AC1<0.4 的维度只作探索性，不作主指标 |

### 12.3 Oracle、fault injection、differential testing（E6–E9）

| ID | 文献依据 | 本项目现状 | 可检验假设 | 最小实验 | 主指标 | 建议验收线 | 停止/反例 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **E6** Oracle 阶梯 + stress set | APR overfitting `[30–35]`；PVBench `[36]`；Vul4Py `[37]`；PatchGuru `[52]` | 70/70 编译、70/70 LSan、70/70 行为、58/58 strict；无 PoC+/mutation | 更强 oracle 会降低通过率；stress set 会暴露 false accept | 20 案例 × L2–L7；20 个 plausible-but-wrong 补丁 | 每级 strict pass；false accept rate | false accept ≤10%；若 >20%，oracle 太弱 | 若 L4≈L2，说明行为差分无信息；直接上 L6/L7 |
| **E7** Mutation + differential fault injection | Mutation survey `[45]`；fault injection `[46]`；MCT `[47]`；differential fault injection `[51]`；PatchGuru `[52]` | 无 mutation/fault injection | oracle 能杀死多数非等价 mutant；部分安全 mutant 会存活 | 10 单元 × 20 mutant；正向对照 + 等价判定 | mutation score、fault detection、false kill | ≥0.80、≥0.90、≤0.10 | 若 mutation score<0.60，先修 oracle，不用它比较方法 |
| **E8** 差分 fuzz | McKeeman `[49]`；EMI `[48]`；差分 fuzz `[50]`；Vul4Py `[37]`；Poracle `[34]` | 只有固定输入行为检查 | benign 回归低；exploit 输入有差异；test blind spot>0 | 20 单元 × 1,000 输入 × 2 版本 | regression_rate、divergence_rate、test_blind_spot | benign regression=0（或逐例报告）；exploit divergence≥1 | 若 harness 无法参数化，明确写“未做”，不要伪造 fuzz |
| **E9** 协议敏感性 | 协议效应 `[16]`；SWE-bench+ `[25]`；Dror `[19]`；Bouthillier `[20]` | 单一 metric/extraction/budget | metric/extraction/budget 会改变分数/排名 | 复用现有输出重算；budget 需小规模重跑 | Δscore、排名变化 | 报告敏感性表；跨论文比较必须同协议 | 若排名翻转，不宣布单一“赢家” |

### 12.4 优先级与依赖

| 优先级 | 实验 | API 成本 | 工程时间 | 依赖 | 建议产物（未来） |
| --- | --- | --- | --- | --- | --- |
| **P0** | E2 长度复分析、E9 指标/抽取复分析、E5 现有 judge 数据重算、E6 oracle 阶梯审计 | 0 | 1–2 天 | 现有 `pair_joint`/`hybrid`/`juliet_repair`/`repair_eval` 产物 | `research/measurement_audit.md`（未来） |
| **P1** | E1 joint-open（90 对）、E3 双顺序（90 对）、E4 K=3 pilot、E5 重复评分 | 小（约 1,000–1,500 次请求/模型） | 2–3 天 | P0 的协议冻结 | `pair_joint_v2_*`、`judge_v2_*` |
| **P2** | E6 stress set、E7 mutation、E8 差分 fuzz | 0（本地计算） | 1–2 周 | Juliet harness、编译器/sanitizer | `juliet_repair_v2_*` |
| **P3** | Tier C：ARVO/Vul4Py 10–20 个 C/C++ 案例 | 中 | 2–4 周 | 外部数据、容器/构建 | `tier_c/*`（未来） |

**依赖关系**：

- E1 依赖“joint-open”的 schema 与 dev 校准；E3 依赖双顺序 prompt；E4 依赖 derangement 生成器；E5 依赖 judge prompt 与人类锚点。
- E6/E7/E8 依赖 Juliet 的可编译 harness；现有 `juliet_repair` 已有 70/70 编译与行为检查，可直接复用。
- E9 依赖现有 outputs；不需要新 API，但需要确保 extraction 规则与旧结果一致。

---

## 13. 统计与报告规范

### 13.1 统计单位与检验

| 任务 | 单元 | 区间 | 配对检验 | 多重比较 | 备注 |
| --- | --- | --- | --- | --- | --- |
| 检测 | 函数 | Wilson（比例）/ cluster bootstrap（F1、macro-F1） | McNemar（同一函数上 A 对 B 错） | 任务内 Holm | 同项目相关；主推断用 cluster bootstrap |
| 配对 | pair | Wilson（DA）/ paired bootstrap（ΔDA） | McNemar（同一 pair 上 A 对 B 错） | 任务内 Holm | 不能把 360 个版本当独立样本 |
| 修复 | pair | Wilson（pass rate）/ bootstrap | McNemar（同一 pair 上方法 A/B） | 任务内 Holm | 分母是“可观测单元”，要写清排除 |
| Judge | item | bootstrap（κ/AC1/ICC） | 不需要；报告一致性 | 维度内 Holm（若做多维度比较） | 报告 CI；小样本 κ 不稳定 |

**公式与实现**：

- Wilson 区间：`[22]`；协议要求用 stdlib 实现，避免 scipy 依赖。
- McNemar 精确检验：`[21]`；`b+c=0` 时 p=1。
- Holm：`[23]`；任务内 family，不跨任务合并。
- Bootstrap：`[24]`；按 project/pair 聚类，10,000 次，seed 42。
- 等价性检验（TOST）：若要说“没有差异”，必须预注册 margin（例如 DA ±5 pp），用两单侧检验或 bootstrap CI 落在 margin 内；不能只用 `p>0.05` 证明“无差异”。

### 13.2 最小可检测差异（规划）

| 场景 | n | 95% CI 半宽（p≈0.8） | 95% CI 半宽（p≈0.5） | 结论 |
| --- | ---: | ---: | ---: | --- |
| 检测 accuracy | 160 | ±6.2 pp | ±7.7 pp | 小于 ~8 pp 的差异通常不可靠 |
| 检测 recall | 128 | ±7.0 pp | — | 同上 |
| 检测 specificity | 32 | ±13–14 pp | — | 负样本太少，不要做强结论 |
| 配对 DA | 180 | ±5.8 pp | ±7.3 pp | 小于 ~7 pp 的差异通常不可靠 |
| 修复 strict pass | 58 | ±10–12 pp | — | ceiling 时无区分度 |
| Judge κ | 30–81 | 很宽 | 很宽 | 只报点估计 + CI，不做强结论 |

> 这些是近似值，不是功效分析；正式实验前应用模拟/公式计算 MDE，并写进预注册。

### 13.3 报告清单

| 项 | 必须写 | 不能写 |
| --- | --- | --- |
| 任务形式 | independent/joint；forced/open；单/双顺序 | 只写“配对准确率” |
| 分母 | N_all、N_valid、N_invalid、排除原因 | 只写百分比，不写 n |
| 区间 | 每个主指标 95% CI | 只写点估计 |
| 检验 | 检验名、单/双侧、校正方法、family | 只写 p 值 |
| 长度 | 长度基线、分层、`excess_DA` | 只写“模型优于基线” |
| 位置 | 条件 DA、slot 检验、是否双顺序 | 只写总体 DA |
| Placebo | direct/treatment/placebo 三行；K；no-op | 只写 treatment−direct |
| Judge | 评审者类型/模型/版本/prompt/重复/顺序/一致性 | 只写“人工评分”或“LLM 评分” |
| Oracle | 级别（L0–L8）、工具/版本、排除单元 | 把 compile PASS 写成“修复正确” |
| 成本 | token、USD、缓存口径、重试 | 只写“成本很低” |

### 13.4 Judge 报告模板

```text
Judge: <model/version or human>
Prompt hash: <sha256>
Temperature / decoding: <...>
Items: N = <...>; dimensions = <...>
Order: <A/B randomized; both orders? >
Repeats: k = <...>
Human anchor: <n items, % of sample>
Agreement:
  - Cohen's kappa: <...> [95% CI]
  - Gwet's AC1: <...> [95% CI]
  - ICC(2,k): <...> [95% CI]
  - Exact agreement: <...>
Calibration (if probabilistic): ECE = <...>; Brier = <...>
Sensitivity: position delta = <...>; style delta = <...>; length delta = <...>
Decision: <which dimensions are primary; which are exploratory>
```

### 13.5 Placebo 报告模板

```text
Design: K = <...> derangements; donor matching = <...>; no-op rate = <...>
Metrics:
  direct: <...> [95% CI]
  treatment: <...> [95% CI]
  placebo (mean over K): <...> [95% CI]
  placebo_response = placebo - direct: <...> [95% CI]
  placebo_adjusted_effect = treatment - placebo: <...> [95% CI]
Manipulation check: <did the model read the evidence? token/length/attention proxy>
Conclusion: <content-specific / format-only / underpowered>
```

### 13.6 Oracle 报告模板

```text
Oracle level: L2 compile / L3 tests / L4 behavior diff / L5 PoC / L6 PoC+ / L7 mutation
Tool + version: <...>
Units: N = <...>; excluded = <...> (reason)
Pass rate per level: <...> [95% CI]
Stress set: N = <...>; false accept = <...>
Mutation: mutants = <...>; equivalent = <...>; score = <...>
Claim boundary: <what can/cannot be claimed>
```

### 13.7 预注册与多重宇宙

- 在看 test 前写：主指标、次指标、停止规则、样本量、排除规则、长度/位置分层、judge 维度。
- 看 test 后新增的分析标 `post-hoc`；不能改写主指标。
- 对关键选择（metric、extraction、budget、prompt 版本）做 **multiverse analysis**：报告所有合理选择的分布，而不是只报一个“显著”的组合 `[16, 20]`。
- 负结果也报告；不要把“不显著”写成“无差异”，除非做了等价性检验。

---

## 14. 落地路线（不改旧结果）

### 14.1 阶段

| 阶段 | 时间 | 内容 | 产物 | API |
| --- | --- | --- | --- | --- |
| **P0 只读审计** | 1–2 天 | E2 长度分层/基线；E9 metric/extraction 重算；E5 现有 judge 数据重算；E6 oracle 阶梯审计 | `research/measurement_audit.md`（未来）；表/图 | 0 |
| **P1 小规模 API** | 2–3 天 | E1 joint-open 90 对；E3 双顺序 90 对；E4 K=3 placebo pilot；E5 重复评分 | `pair_joint_v2_*`、`judge_v2_*` | 约 1,000–1,500 次/模型 |
| **P2 工程 oracle** | 1–2 周 | E6 stress set；E7 mutation；E8 差分 fuzz | `juliet_repair_v2_*`、`oracle_strength.json` | 0（本地计算） |
| **P3 外部 Tier C** | 2–4 周 | ARVO/Vul4Py 10–20 个 C/C++ 案例；编译 + PoC + 回归 | `tier_c/*` | 中 |

### 14.2 运行约定

| 约定 | 要求 |
| --- | --- |
| Run ID | 新实验用 `*_v2_*` 或 `*_20261113_*`；**绝不覆盖** `test_v1_*`、`hybrid_v1_*`、`juliet_repair/runs/*_final` |
| 冻结 | 新 prompt/schema/split 先写 hash；test 前冻结；看 test 后不改 |
| 凭证 | 只从环境变量读取；不打印、不落盘、不写入 prompt/日志 |
| 执行 | 项目路径用 `/mnt/c/Users/tzh03/Downloads/cs224proj`；所有 Python/编译/测试在 WSL 内执行；不用 Windows Python 跑实验 |
| 依赖 | 优先标准库 + `httpx`；不引入 pandas/numpy/scipy，除非明确记录 |
| 成本 | 每个 run 设 `max_usd`；按 task 记账；报告缓存调整与全未命中两种口径 |
| 结果 | 所有表由 `runs/parsed/` 或原始 JSONL 生成；不手填数字 |
| 负结果 | 保留；不删失败 run；在报告中单列 |

### 14.3 规划成本（不是实测）

| 阶段 | 估算请求数 | 估算成本 | 说明 |
| --- | ---: | ---: | --- |
| P1 E1 joint-open（90 对，只算新增臂） | 90 × 1 模型 = 90 | 约 USD 0.08–0.15 | 单次输入约 2×，按 pair-joint 量级 |
| P1 E3 双顺序（90 对） | 180 × 1 模型 = 180 | 约 USD 0.15–0.30 | 两次顺序 |
| P1 E4 K=3 placebo（140 单元） | 420 × 1 模型 | 约 USD 0.10–0.20 | 只做 pilot |
| P1 E5 judge 重复（20 案例） | 160–320 | 约 USD 0.05–0.15 | 取决于 judge 调用次数 |
| P2 E6–E8 | 0 API | 0 | 本地编译/运行 |
| P3 Tier C | 10–20 案例 × 多次 | 约 USD 1–3 | 取决于模型与重试 |

> 上述成本是按现有单次成本量级的外推，**不是报价**；实际以 `usage`/账单为准。不要用估算替代实测。

### 14.4 建议的第一个 PR/提交（未来）

1. 只加 `research/measurement_audit.md`：E2/E9/E5/E6 的只读复算结果。
2. 只加 `pair_joint/analyze_protocol.py`：2×2 协议的离线分析（不调用 API）。
3. 只加 `juliet_repair/oracle_ladder.py`：L2–L4 的离线审计 + stress set 评分。
4. 不修改旧 run、不修改 `report/`、不修改 `benchmark/results/`。

---

## 15. 效度威胁与不声明

### 15.1 本文的效度威胁

| 威胁 | 说明 | 缓解 |
| --- | --- | --- |
| 预印本证据 | 2026 年多篇为 arXiv，可能未同行评审/会改版 | 标注 B；引用时给 URL/日期；不把预印本数字当定论 |
| 二手数字 | 部分数字来自摘要/HTML，不是全文复现 | 只引用已读页面；不补未读表格；关键数字保留原文表述 |
| 项目数字未重算 | 本文只读引用现有报告 | 报告中以原报告为准；若要进论文，需用原始 JSONL 复算 |
| 选择偏差 | 检索的是作者熟悉的方向，不是 PRISMA 系统综述 | 明确“定向调研”；不声称覆盖全部文献 |
| 时间偏差 | 2026-11-13 快照；之后可能有新工作 | 记录访问日期；后续更新 |

### 15.2 项目的效度威胁（与本文建议相关）

| 威胁 | 表现 | 影响 |
| --- | --- | --- |
| 单模型/单端点 | DeepSeek/MiMo 各一个版本；端点可能漂移 | 结果不可跨时间复现；需记录 `model`/`system_fingerprint` |
| 小样本 | 160 检测、180 配对、58 修复、30 judge 案例 | CI 宽；小差异不可靠 |
| 标签噪声 | SecVulEval 标签继承；Juliet 合成 | 绝对性能可能高估/低估 |
| 配对相似度高 | 行相似度中位 0.926 | 独立分类容易给出相同答案；joint 也可能利用长度 |
| Ceiling | Juliet 58/58 | 无法区分模型/提示 |
| Judge 身份不明 | summary 未记录评审者类型/版本 | 不可复现；无法判断偏差来源 |
| 污染 | 真实开源代码可能出现在预训练 | 绝对性能不可外推 |
| 协议效应 | forced-choice、单顺序、单 placebo | 可能高估“配对推理”“证据效应” |

### 15.3 明确不声明

- 不声明“DeepSeek/MiMo 的配对能力是 76.67%/86.67%”；只声明“在该协议下的 DA，且受长度/位置影响”。
- 不声明“context/evidence 有效或无效”；现有 placebo 与 ceiling 不足以判定。
- 不声明“58/58 表示补丁正确”；只声明“在 58 个可观测单元上通过了 compile/LSan/behavior oracle”。
- 不声明“LLM judge 可以替代人工/编译/PoC”；只声明“在报告可靠性的前提下，可用于软维度”。
- 不声明“本文的建议一定提升指标”；它们是待验证的假设。
- 不声明“Tier A 与 Tier B 可以池化”；两层不可合并。

---

## 16. 参考文献

> 说明：以下条目在 2026-11-13 核对过标题/venue/年份/DOI 或 URL；**A** = 正式发表，**B** = arXiv 预印本，**C** = 厂商/工件。2026 年的 B 级条目可能更新；引用时保留访问日期。

### 16.1 Position bias、LLM-as-judge 与代码评判

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 1 | L. Zheng, W.-L. Chiang, Y. Sheng, et al. *Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena.* | NeurIPS 2023 (D&B) | A | https://arxiv.org/abs/2306.05685 |
| 2 | P. Wang, L. Li, L. Chen, et al. *Large Language Models are not Fair Evaluators.* | ACL 2024 | A | https://arxiv.org/abs/2305.17926 |
| 3 | L. Shi, C. Ma, W. Liang, X. Diao, W. Ma, S. Vosoughi. *Judging the Judges: A Systematic Study of Position Bias in LLM-as-a-Judge.* | IJCNLP-AACL 2025, pp. 292–314 | A | https://aclanthology.org/2025.ijcnlp-long.18/ |
| 4 | J. Ye, Y. Wang, Y. Huang, et al. *Justice or Prejudice? Quantifying Biases in LLM-as-a-Judge.* | ICLR 2025 | A | https://arxiv.org/abs/2410.02736 |
| 5 | Y. Liu, D. Iter, Y. Xu, S. Wang, R. Xu, C. Zhu. *G-Eval: NLG Evaluation using GPT-4 with Better Human Alignment.* | EMNLP 2023, pp. 2511–2522 | A | https://doi.org/10.18653/v1/2023.emnlp-main.153 |
| 6 | S. Tan, S. Zhuang, K. Montgomery, W. Y. Tang, A. Cuadron, C. Wang, R. A. Popa, I. Stoica. *JudgeBench: A Benchmark for Evaluating LLM-based Judges.* | ICLR 2025 | A | https://arxiv.org/abs/2410.12784 |
| 7 | H. Jiang, Y. Chen, Y. Cao, H.-y. Lee, R. T. Tan. *CodeJudgeBench: Benchmarking LLM-as-a-Judge for Coding Tasks.* | ACL 2026 | A | https://aclanthology.org/2026.acl-long.888/ ；https://arxiv.org/abs/2507.10535 |
| 8 | R. Haldar, J. Hockenmaier. *Rating Roulette: Self-Inconsistency in LLM-As-A-Judge Frameworks.* | Findings of EMNLP 2025 | A | https://doi.org/10.18653/v1/2025.findings-emnlp.1361 |
| 9 | Z. Zhao, et al. *Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering.* | arXiv 2026 | B | https://arxiv.org/abs/2604.16790 |
| 10 | J. Moon, Y. Hwang, D. Lee, T. Kang, Y. Kim, K. Jung. *Don't Judge Code by Its Cover: Exploring Biases in LLM Judges for Code Evaluation.* | Findings of EACL 2026, pp. 1364–1389 | A | https://doi.org/10.18653/v1/2026.findings-eacl.70 |
| 11 | A. Panickssery, S. R. Bowman, S. Feng. *LLM Evaluators Recognize and Favor Their Own Generations.* | NeurIPS 2024 | A | https://arxiv.org/abs/2404.13076 |
| 12 | J. Jung, F. Brahman, Y. Choi. *Trust or Escalate: LLM Judges with Provable Guarantees for Human Agreement.* | ICLR 2025 | A | https://openreview.net/forum?id=UHPnqSTBPO |

### 16.2 Length、benchmark validity 与配对协议

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 13 | Y. Dubois, B. Galambosi, P. Liang, T. B. Hashimoto. *Length-Controlled AlpacaEval: A Simple Way to Debias Automatic Evaluators.* | COLM 2024 | A | https://arxiv.org/abs/2404.04475 |
| 14 | K. Saito, A. Wachi, K. Wataoka, Y. Akimoto. *Verbosity Bias in Preference Labeling by Large Language Models.* | arXiv 2023 | B | https://arxiv.org/abs/2310.10076 |
| 15 | N. Risse, J. Liu, M. Böhme. *Top Score on the Wrong Exam: On Benchmarking in Machine Learning for Vulnerability Detection.* | PACMSE 2(ISSTA), 2025 | A | https://doi.org/10.1145/3728887 |
| 16 | M. Cichoń, B. Dmitruk. *A Function-Level Vulnerability Score Measures Flag Rate More Than the Model: Protocol Effects on Paired Benchmarks.* | arXiv 2026 | B | https://arxiv.org/abs/2609.32890 |
| 17 | Y. Ding, Y. Fu, O. Ibrahim, et al. *Vulnerability Detection with Code Language Models: How Far Are We?* | ICSE 2025, pp. 1729–1741 | A | https://doi.org/10.1109/ICSE55347.2025.00038 |
| 18 | N. Risse, M. Böhme. *Uncovering the Limits of Machine Learning for Automatic Vulnerability Detection.* | USENIX Security 2024 | A | https://www.usenix.org/conference/usenixsecurity24/presentation/risse |
| 19 | R. Dror, G. Baumer, S. Shlomov, R. Reichart. *The Hitchhiker's Guide to Testing Statistical Significance in Natural Language Processing.* | ACL 2018, pp. 1383–1392 | A | https://doi.org/10.18653/v1/P18-1128 |
| 20 | X. Bouthillier, P. Delaunay, M. Bronzi, et al. *Accounting for Variance in Machine Learning Benchmarks.* | MLSys 2021 | A | https://arxiv.org/abs/2103.03098 |
| 21 | Q. McNemar. *Note on the Sampling Error of the Difference Between Correlated Proportions or Percentages.* | Psychometrika 12(2):153–157, 1947 | A | https://doi.org/10.1007/BF02295996 |
| 22 | E. B. Wilson. *Probable Inference, the Law of Succession, and Statistical Inference.* | JASA 22(158):209–212, 1927 | A | https://doi.org/10.1080/01621459.1927.10502953 |
| 23 | S. Holm. *A Simple Sequentially Rejective Multiple Test Procedure.* | Scand. J. Stat. 6(2):65–70, 1979 | A | https://www.jstor.org/stable/4615733 |
| 24 | B. Efron, R. J. Tibshirani. *An Introduction to the Bootstrap.* | Chapman & Hall, 1993 | A | https://doi.org/10.1201/9780429246593 |
| 25 | R. Aleithan, H. Xue, M. M. Mohajer, E. Nnorom, G. Uddin, S. Wang. *SWE-Bench+: Enhanced Coding Benchmark for LLMs.* | arXiv 2024 | B | https://arxiv.org/abs/2410.06992 |

### 16.3 Placebo 与 negative controls

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 26 | M. Lipsitch, E. J. Tchetgen Tchetgen, T. Cohen. *Negative Controls: A Tool for Detecting Confounding and Bias in Observational Studies.* | Epidemiology 21(3):383–388, 2010 | A | https://doi.org/10.1097/EDE.0b013e3181d61eeb |
| 27 | J. Adebayo, J. Gilmer, M. Muelly, I. Goodfellow, M. Hardt, B. Kim. *Sanity Checks for Saliency Maps.* | NeurIPS 2018 | A | https://arxiv.org/abs/1810.03292 |
| 28 | J. Hewitt, P. Liang. *Designing and Interpreting Probes with Control Tasks.* | EMNLP-IJCNLP 2019, pp. 2733–2743 | A | https://doi.org/10.18653/v1/D19-1275 |
| 29 | T. Kosch, R. Welsch, L. Chuang, A. Schmidt. *The Placebo Effect of Artificial Intelligence in Human–Computer Interaction.* | ACM TOCHI 29(6), 2023 | A | https://doi.org/10.1145/3529225 |

### 16.4 Patch overfitting 与自动程序修复

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 30 | E. K. Smith, E. T. Barr, C. Le Goues, Y. Brun. *Is the Cure Worse Than the Disease? Overfitting in Automated Program Repair.* | ESEC/FSE 2015, pp. 532–543 | A | https://doi.org/10.1145/2786805.2786825 |
| 31 | Z. Qi, F. Long, S. Achour, M. Rinard. *An Analysis of Patch Plausibility and Correctness for Generate-and-Validate Patch Generation Systems.* | ISSTA 2015, pp. 24–36 | A | https://doi.org/10.1145/2771783.2771791 |
| 32 | H. Ye, M. Martinez, M. Monperrus. *Automated Patch Assessment for Program Repair at Scale.* | EMSE 26(2):20, 2021 | A | https://doi.org/10.1007/s10664-020-09920-w |
| 33 | Z. Fei, J. Ge, C. Li, et al. *Patch Correctness Assessment: A Survey.* | TOSEM 34(2):55:1–55:50, 2025 | A | https://doi.org/10.1145/3702972 |
| 34 | E. Ismayilzada, et al. *Poracle: Testing Patches under Preservation Conditions to Combat the Overfitting Problem of Program Repair.* | TOSEM, 2023 | A | https://doi.org/10.1145/3625293 |
| 35 | T. Ahmed, J. Ganhotra, A. Shinnar, M. Hirzel. *Is the Cure Still Worse Than the Disease? Test Overfitting by LLMs in Automated Program Repair.* | FSE Companion 2026 | A | https://doi.org/10.1145/3803437.3805574 ；https://arxiv.org/abs/2511.16858 |
| 36 | Z. Yu, W. Shi, X. Sun, Z. Feng, M. Xu, X. Xing. *Patch Validation in Automated Vulnerability Repair* (PVBench). | arXiv 2026 | B | https://arxiv.org/abs/2603.06858 |
| 37 | T. Bui, et al. *Vul4Py: Benchmarking Automated Vulnerability Repair in Python with Paired Exploit and Functional Oracles.* | arXiv 2026 | B | https://arxiv.org/abs/2608.00692 |
| 38 | B. Yang, et al. *A Survey of LLM-based Automated Program Repair: Taxonomies, Design Paradigms, and Applications.* | arXiv 2025 | B | https://arxiv.org/abs/2506.23749 |
| 39 | Y. Hu, et al. *SoK: Automated Vulnerability Repair: Methods, Tools, and Assessments.* | USENIX Security 2025 | A | https://arxiv.org/abs/2506.11697 |

### 16.5 可执行验证、PoC 与安全基准

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 40 | X. Mei, J. Del Castillo, P. Singh Singaria, et al. *ARVO: Atlas of Reproducible Vulnerabilities for Open-Source Software.* | arXiv 2024 | B | https://arxiv.org/abs/2408.02153 |
| 41 | Z. Wang, et al. *CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale.* | arXiv 2025 | B | https://arxiv.org/abs/2506.02548 |
| 42 | W. Wang, et al. *VulnRepairEval: An Exploit-Based Evaluation Framework for Assessing Large Language Model Vulnerability Repair Capabilities.* | arXiv 2025 | B | https://arxiv.org/abs/2509.03331 |
| 43 | T. J. Byun, et al. *Introducing AutoPatchBench: A Benchmark for AI-Powered Security Fixes.* | Meta Engineering, 2025 | C | https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/ |
| 44 | M. B. U. Ahmed, N. Shiri Harzevili, J. Shin, H. V. Pham, S. Wang. *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection.* | AIware 2026, pp. 388–396 | A | https://doi.org/10.1145/3805760.3814932 |

### 16.6 Fault injection、mutation 与 differential testing

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 45 | Y. Jia, M. Harman. *An Analysis and Survey of the Development of Mutation Testing.* | IEEE TSE 37(5):649–678, 2011 | A | https://doi.org/10.1109/TSE.2010.62 |
| 46 | M.-C. Hsueh, T. K. Tsai, R. K. Iyer. *Fault Injection Techniques and Tools.* | Computer 30(4):75–82, 1997 | A | https://doi.org/10.1109/2.585151 |
| 47 | Z. Li, D. Shin. *Mutation-based Consistency Testing for Evaluating the Code Understanding Capability of LLMs.* | CAIN 2024 | A | https://doi.org/10.1145/3644815.3644946 ；https://arxiv.org/abs/2401.05940 |
| 48 | V. Le, M. Afshari, Z. Su. *Compiler Validation via Equivalence Modulo Inputs.* | PLDI 2014, pp. 216–226 | A | https://doi.org/10.1145/2594291.2594334 |
| 49 | W. M. McKeeman. *Differential Testing for Software.* | Digital Technical Journal 10(1):100–107, 1998 | A | https://www.cs.swarthmore.edu/~bylvisa1/cs97/f13/Papers/DifferentialTestingForSoftware.pdf |
| 50 | S. B. Dristi, M. B. Dwyer. *A Differential Fuzzing-Based Evaluation of Functional Equivalence in LLM-Generated Code Refactorings.* | arXiv 2026 | B | https://arxiv.org/abs/2602.15761 |
| 51 | E. Coleman, et al. *Validating LLM-Modernized Scientific Software Through Differential Fault Injection.* | arXiv 2026 | B | https://arxiv.org/abs/2608.14527 |
| 52 | T. Le-Cong, B. Le, T. Murray, M. Pradel, C. Cadar. *PatchGuru: Patch Oracle Inference from Natural Language Artifacts.* | arXiv 2026 | B | https://arxiv.org/abs/2602.05270 |

### 16.7 一致性与统计方法

| # | 文献 | 年份/venue | 级别 | DOI/URL |
| ---: | --- | --- | --- | --- |
| 53 | A. R. Feinstein, D. V. Cicchetti. *High Agreement but Low Kappa: I. The Problems of Two Paradoxes.* | J. Clin. Epidemiol. 43(6):543–549, 1990 | A | https://doi.org/10.1016/0895-4356(90)90158-L |
| 54 | K. L. Gwet. *Computing Inter-rater Reliability and Its Variance in the Presence of High Agreement.* | Br. J. Math. Stat. Psychol. 61(1):29–48, 2008 | A | https://doi.org/10.1348/000711006X126600 |
| 55 | P. E. Shrout, J. L. Fleiss. *Intraclass Correlations: Uses in Assessing Rater Reliability.* | Psychol. Bull. 86(2):420–428, 1979 | A | https://doi.org/10.1037/0033-2909.86.2.420 |
| 56 | J. Cohen. *A Coefficient of Agreement for Nominal Scales.* | Educ. Psychol. Meas. 20(1):37–46, 1960 | A | https://doi.org/10.1177/001316446002000104 |

---

## 附录 A：指标与实现要点

### A.1 位置指标

```text
# 需要同一 pair 的两个顺序
flip_i = 1[pred_vuln_side(A/B) != pred_vuln_side(B/A)]
slot_flip_rate = mean(flip_i)
position_consistency = 1 - slot_flip_rate
preference_fairness = abs(P(choose A) - 0.5)
conditional_DA_A = DA | vulnerable_side == A
conditional_DA_B = DA | vulnerable_side == B
```

### A.2 长度控制

```text
excess_DA = DA_model - DA_length_baseline
# paired bootstrap: resample pairs with replacement; recompute both; take 2.5/97.5 percentiles

# 回归版本（可选）
logit(P(correct_i)) = b0 + b_len * z(delta_len_i) + b_model * model_i
# 报告 b_model 的调整后 odds ratio / marginal effect
```

### A.3 Placebo

```text
placebo_response = mean_k(metric(shuffled_k)) - metric(direct)
placebo_adjusted_effect = metric(treatment) - mean_k(metric(shuffled_k))
no_op_rate = #(donor evidence == own evidence) / N
```

### A.4 Mutation score

```text
mutation_score = killed / (total - equivalent)
fault_detection_rate = detected_security_faults / total_security_faults
false_kill_rate = killed_behavior_preserving / total_behavior_preserving
```

### A.5 Differential testing

```text
divergence_rate = divergent_inputs / total_inputs
regression_rate = benign_divergent_inputs / total_benign_inputs
test_blind_spot = divergent_inputs_not_covered_by_tests / divergent_inputs
```

### A.6 Gwet's AC1（概念）

AC1 用“偶然一致”的另一种估计（基于边际概率与类别数）替代 κ 的 chance agreement；在类别高度偏斜时更稳定。实现时报告与 κ 并列，不要只报 AC1；两者回答的问题略有不同 `[54]`。

---

## 附录 B：运行前检查清单（可打印）

- [ ] 预注册写了：主指标、次指标、停止规则、样本量、排除规则、长度/位置分层、judge 维度。
- [ ] 任务形式写清：independent/joint；forced/open；单/双顺序。
- [ ] 长度基线已算：配对用“选较短”；检测用“长度阈值/表面特征”。
- [ ] 位置设计已定：至少报告条件 DA；最好双顺序。
- [ ] Placebo 设计已定：K≥3 pilot；供体匹配；no-op rate。
- [ ] Judge 设计已定：类型/模型/版本/prompt/重复/顺序/人类锚点。
- [ ] Oracle 级别已定：L0–L8；报告排除单元与原因。
- [ ] 新 run ID 已分配；不会覆盖 `test_v1_*`、`hybrid_v1_*`、`juliet_repair/runs/*_final`。
- [ ] 凭证只从环境变量读取；日志无 key。
- [ ] 成本上限已设；缓存口径已定。
- [ ] 分析脚本只用 `runs/parsed/` 或原始 JSONL；不手填数字。
- [ ] 负结果/失败 run 保留。
- [ ] 报告了 CI、exact counts、invalid rate、排除原因。
- [ ] 没有把 compile PASS 写成“修复正确”；没有把 judge 分数写成“正确率”。
- [ ] 没有跨 Tier 池化；没有用单 placebo draw 下结论。

---

## 附录 C：与现有文档的关系

| 文档 | 本文如何衔接 | 不做什么 |
| --- | --- | --- |
| `research/evaluation_protocol.md` | 在其指标/统计之上，补“协议效应、位置、长度、placebo、judge 可靠性、oracle 阶梯” | 不修改其冻结的 split/prompt/指标定义 |
| `research/improvement_opportunities.md` | 把 P1（pair joint）、P2（evidence/CWE）、P5（repair self-check）、P6（calibration）映射到 E1–E8 | 不重复其失败诊断；不覆盖其数字 |
| `benchmark/PROTOCOL.md` | 支持 Tier A/B 分层；补 judge/placebo/oracle 的报告字段 | 不改变 leaderboard 口径 |
| `pair_joint/report.md` | 把 §4 位置偏差、§7 长度混淆扩展为 E2/E3 | 不重跑/不改其 180 对结果 |
| `hybrid/REPORT.md` | 把 §4 安慰剂与 §限制扩展为 E4 | 不重跑/不改其 1,400 请求 |
| `juliet_repair/README.md` | 把 58/58 的 ceiling 与 12 个不可观测单元扩展为 E6–E8 | 不重跑/不改其 70 个单元 |
| `repair_eval/.../summary.md` | 把 κ 的维度差异扩展为 E5 | 不重跑/不改其 81 个候选 |
| `research/evaluation_protocol.md` §16 | 其效度威胁清单仍然有效；本文补充“协议效应/位置/长度/placebo/judge”五项 | 不替代其威胁清单 |

---

## 附录 D：一句话总结

**2025–2026 年的评估文献给出的最重要教训不是“再换一个更强的模型”，而是“先把测量工具校准”：配对任务要区分 independent/joint 与 forced/open，长度要有基线，位置要双顺序，placebo 要有分布，judge 要报可靠性，补丁要有比“测试通过”更强的 oracle。本项目的现有产物已经具备做这些校准的原材料；下一步应优先做 E1–E8 的测量修复，而不是在未校准的协议上继续堆新方法。**

---

## 附录 E：给主代理的交接要点

1. **本文只新增 `research/latest_evaluation_repair_2026.md`**；没有改 `runner/`、`splits/`、`datasets/`、`report/`、`analysis/`、`qualitative/`、`benchmark/results/`，也没有覆盖任何 `test_v1_*`、`hybrid_v1_*`、`juliet_repair/runs/*_final`。文中项目数字均为只读引用，未重新计算。
2. **可直接用于论文/报告的结论**：
   - 评估协议本身是主要变量；函数级 F1 与配对正确率不是一回事 `[16, 17]`。
   - 本项目的 pair-joint 受长度（74.44% 启发式）与位置（DeepSeek 31.11 pp）影响，不能把 76.67% 直接写成“配对推理能力”。
   - 强制二选一与 open 4-way 不可比；需要 2×2 协议 `[16]`。
   - Placebo 需要分布；单次 shuffled 只能作操纵检查，不能估计 placebo 效应。
   - LLM judge 的 κ 会受边际偏斜影响；COM 的 0.000 是 paradox，不是“评审者完全不一致” `[53, 54]`。
   - 补丁过拟合在 LLM 时代仍严重；PVBench 的 >40% 与 Vul4Py 的 15/119 是最直接的外部证据 `[36, 37]`。
   - 本项目 Juliet 修复到 L2–L4；58/58 是强 oracle 下的 ceiling，不是“补丁正确率”。
3. **不能直接写的话**：
   - “DeepSeek/MiMo 的配对能力是 76.67%/86.67%”——必须带“forced-choice、单顺序、长度未控制”的限定。
   - “combined 100% 证明证据有效”——n=5 discordant，`p=0.0625`，且 placebo 只抽了一个 seed。
   - “17/81 = 21% 修复正确率”——这是 rubric 的 VR=2，不是 compile/PoC 正确率。
   - “58/58 = 100% 修复正确率”——分母是 58 个可观测单元，不是 70，也不是所有 CWE。
   - “context/evidence 无效”——现有操纵太弱/ceiling，不能得出这个结论。
4. **建议的下一步**：先做 P0（E2 长度、E9 协议敏感性、E5 judge 重算、E6 oracle 审计），再做 P1（E1 joint-open、E3 双顺序、E4 K=3 placebo、E5 重复评分）。P2 的 mutation/差分 fuzz 不需要 API，但需要工程时间；P3 的外部 Tier C 只在时间允许时做。
5. **仍未验证/需要后续确认**：
   - 2026 年的 arXiv 预印本可能更新；引用时保留 URL 与访问日期。
   - 本文没有重算项目数字；若要进论文，必须用原始 JSONL 复算，并保留旧报告作为对照。
   - `repair_eval` 的评审者类型（人/LLM）、模型版本、prompt、重复次数未记录；E5 必须先补齐这些元数据。
   - 本项目的 `pair_joint` 没有 open 4-way、双顺序、长度匹配子集；这些是 E1–E3 的新实验，不是现有结果。
6. **写作映射建议**：
   - Related Work：§3–§11 的文献段落 + §16 的引用。
   - Methodology：§2 的四种分数 + §13 的报告规范。
   - Experiment Plan：§12 的 E1–E9 + §14 的 P0–P3。
   - Threats to Validity：§15 + `research/evaluation_protocol.md` §16。
   - 附录：§13.4–§13.6 的模板可直接改成论文表格的脚注/说明。

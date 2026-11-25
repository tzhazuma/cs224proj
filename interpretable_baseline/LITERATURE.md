# 文献与改进 idea：可解释基线在 Tier A detection 上的位置

本文件只列与本目录直接相关的、已在项目 `research/related_work.md` 中核对过 DOI/会议/页码的条目；没有新增未核验引用。文献只用于解释“为什么要在 LLM 结果旁边放长度/调用/分配基线”，不用于给本目录的数字背书。

## 1. 直接动机

### 1.1 Risse, Liu & Böhme (ISSTA/PACMSE 2025)

N. Risse, J. Liu, M. Böhme. *Top Score on the Wrong Exam: On Benchmarking in Machine Learning for Vulnerability Detection.* PACMSE 2(ISSTA), pp. 388–410, 2025. DOI [10.1145/3728887](https://doi.org/10.1145/3728887).

**它支持什么**

- 函数级“有漏洞/无漏洞”标签在缺少调用上下文时经常不可判定；很多样本的标签来自“这个函数在修复 commit 中被改过”，而不是“函数文本里有一个可定位的缺陷”。
- 仅用词频、长度等表面特征就能在一些 ML4VD 数据集上取得高分；高分可能来自数据集偏差/ shortcut，而不是漏洞语义。

**它怎样约束本目录**

- 本目录把“长度规则”当作**诊断工具**，不是“检测器”。`length_short` 在 test 上 macro-F1 0.511，但 MCC 只有 0.094；它在最短四分位全判正（召回 1.0、特异度 0），在最长四分位全判负。这正是“表面特征高分”的形态。
- 本目录不把 LLM 的 FN 一律当成“模型失败”：案例里很多 FN 的 rationale 明确说“函数本身没有可见缺陷，取决于调用者/未提供的 helper”。按 [8] 的框架，这些应标为 **underdetermined**，而不是纯错误。
- 本目录不建议用“函数级 F1”单独给方法排名；建议同时报 MCC、balanced accuracy、predicted positive rate，并按长度/项目分层。

**不能拿它说什么**

- 不能把该文的结论当成“所有 LLM 都没有检测能力”；本目录的 LLM 仍有 P 0.81–0.86、Spec 0.65–0.83，说明它们在“保守报警”这个操作点上有一定精度。
- 不能把该文的数字直接搬到本数据；本目录的数字只来自 `secvul-split-v1` 的 dev40/test160。

### 1.2 Risse & Böhme (USENIX Security 2024)

N. Risse, M. Böhme. *Uncovering the Limits of Machine Learning for Automatic Vulnerability Detection.* USENIX Security 2024. [官方页面](https://www.usenix.org/conference/usenixsecurity24/presentation/risse).

**它支持什么**

- ML4VD 的“极限”问题：在真实漏洞检测上，模型可能依赖数据集构造/表面特征；需要更严格的评估设计。

**它怎样约束本目录**

- 本目录用 dev40 只做阈值/规则选择，test160 只评估一次；test-tuned 上界单独标注，不混入主结果。
- 本目录明确区分“逐单元正确数”（McNemar）和“类加权 macro-F1”（cluster bootstrap）；两者结论不一致时，不强行合成一个“显著”。

## 2. 数据与标签

### 2.1 Ahmed et al. (AIware 2026) — SecVulEval

M. B. U. Ahmed, N. S. Harzevili, J. Shin, H. V. Pham, S. Wang. *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection.* AIware 2026, pp. 388–396. DOI [10.1145/3805760.3814932](https://doi.org/10.1145/3805760.3814932).

**它支持什么**

- 上游 25,440 个函数、10,998 V / 14,442 NV（43.2% 正例）、5,867 CVE、707 项目、145 CWE；函数级/语句级标签与五类上下文。
- 上游的上下文由 GPT-4.1 自动抽取，人工抽查 100 条准确率 83.16%。

**它怎样约束本目录**

- 本项目的 `independent_200.json` 是 160 V / 40 NV（**80% 正例**），不是上游分布。test160 的 80% 正例率是子集构造的结果，不是真实项目分布；因此多数类基线 0.444 的 macro-F1 不能外推为“上游的多数类也有 0.444”。
- 本目录不使用 `context` 字段，也不把 context 伪影（非空 ⇒ 漏洞）当成特征；这是有意为之，避免重复项目已经量化过的泄漏。
- 上游论文的 23.83% 是**语句级、多代理、理由正确**的口径，不是本目录的函数级二分类；不能把 0.511 与 23.83% 直接比较。

### 2.2 Ding et al. (ICSE 2025) — PrimeVul

Y. Ding, Y. Fu, O. Ibrahim, C. Sitawarin, X. Chen, B. Alomair, D. Wagner, B. Ray, Y. Chen. *Vulnerability Detection with Code Language Models: How Far are We?* ICSE 2025, pp. 1729–1741. DOI [10.1109/ICSE55347.2025.00038](https://doi.org/10.1109/ICSE55347.2025.00038).

**它支持什么**

- 漏洞标签噪声是跨数据集的系统性问题（BigVul/CodeXGLUE/VulnPatchPairs 的人工抽查准确率远低于 100%）；需要配对/时间切分/更严格的评估。
- 模型在配对任务上可能接近随机；单函数分类的高分不等于“理解修复差异”。

**它怎样约束本目录**

- 本目录的标签继承 SecVulEval 的 CVE/commit 关联；`is_vulnerable` 只表示“修复前版本”，不证明函数文本中一定有可见 bug。FN 案例（Linux wrapper、HHVM `apc_add`、ImageMagick `SkipDXTMipmaps`）都体现这一点。
- 本目录不做“配对任务”的结论；长度规则只在 detection 上评估。若要把“长度 shortcut”外推到 pair，需要单独跑 pair-joint 的 180 对（项目已有 74.44% 的长度启发式，可作为对照）。

## 3. 语义与 shortcut

### 3.1 Steenhoek et al. (arXiv 2023)

B. Steenhoek, M. M. Rahman, S. Sharmin, W. Le. *Do Language Models Learn Semantics of Code? A Case Study in Vulnerability Detection.* arXiv:2311.04109, 2023. [arXiv](https://arxiv.org/abs/2311.04109).（预印本，未同行评审。）

**它支持什么**

- 模型对 buggy path 的语义对齐可能很弱；提供 bug 语义标注/更强的监督才可能改善。
- 高 F1 不一定意味着模型学到了漏洞语义，可能只是学到了表面模式。

**它怎样约束本目录**

- 本目录用 rationale 关键词做描述性诊断：DeepSeek FN 中 76.7% 出现 “no clear/insufficient/unclear”，TP 中只有 7.9%；这说明 FN 更像是“证据不足/保守”，而不是“解析失败”。
- 但关键词计数不是语义理解证明；本目录只把它当 error analysis 的线索，不当因果结论。

## 4. 本目录相对文献的增量

| 文献已经说了 | 本目录新增的实测 |
| --- | --- |
| 表面特征可能高分；函数级标签可能不可判定 | 在 `secvul-split-v1` 的 dev40/test160 上，给出 7 条规则的 dev→test 真实指标；长度规则 0.511 macro-F1 / 0.094 MCC |
| 多数类/不平衡会扭曲指标 | 给出多数类 0.444 macro-F1 / 0 MCC / 0 specificity，并证明它高于全部 8 个 LLM 的点估计 |
| 需要同时看多个指标 | 给出 macro-F1 与 MCC 的排名翻转：`alloc_or_mem` MCC 0.183 第一、macro-F1 0.387 第九；多数类 macro-F1 第二、MCC 第十三 |
| 配对/上下文很重要 | 给出 12 个 FN/FP 案例，显示 FN 多为“函数文本不足”，FP 多为“合理但不对题”的代码审查式报警 |
| test tuning 会高估 | 给出 test-tuned 单特征上界 0.598 macro-F1 / 0.209 MCC；LR 5 折 CV 0.502；LLM confidence oracle 最高 0.526 / 0.180 |

## 5. 改进 idea（可执行、可证伪）

1. **多数类/长度规则准入门槛**：任何新方法在 test160 上必须同时报告 `macro-F1 − 0.444`（多数类）与 `MCC − 0.183`（`alloc_or_mem`）。只超过 0.444 不算新能力。
2. **matched pred+ 比较**：把 LLM 阈值调到与 `length_short` 相同的 predicted positive rate（0.562），再比 macro-F1/MCC；如果差距消失，说明差异主要是 calibration，不是 discrimination。
3. **underdetermined 分层**：用 LLM rationale 的 “no clear/insufficient” + 人工抽样建立“函数文本不足”子集；在这些样本上报告 abstention/coverage，而不是算成 FN。
4. **dev 扩充**：从完整 SecVulEval 抽同项目/同长度档的负例，把检测 dev 从 8 NV 扩到 ≥40 NV；用项目级 nested CV 选规则，报告选择稳定性（不同 fold 选中的规则是否一致）。
5. **二段式规则路由**：`alloc_or_mem`（P 0.941 / R 0.250）作为高精确率第一段，长度规则作为高召回第二段；报告 P-R 曲线、每 TP 成本、人工复核预算，而不是单一阈值。
6. **跨任务检验**：把同一套规则搬到 pair-joint 的 180 对，复算长度启发式（项目已有 74.44%），比较 side-wise/joint 的操作点；如果长度 shortcut 在 joint 上消失，说明它依赖 side-wise 的 prevalence/长度分布。
7. **标签审计**：对 12 个 `alloc_unbalanced` TP 和 12 个 `length_short` 的边界样本做人工核对，确认它们是“真实漏洞”还是“CVE commit 关联”；这能直接检验 [8] 的“标签不可判定”假设。

## 6. 引用边界

- 以上条目均来自项目 `research/related_work.md` 已核验的引用表；本文件没有新增 DOI/页码未核验的文献。
- [12] 是 arXiv 预印本，引用时必须注明“预印本，未同行评审”。
- [1] 的 23.83% 是语句级/多代理/理由正确口径，不能与本目录的函数级 macro-F1 直接比较。
- [8] 的“表面特征可高分”是文献结论/项目转述，不是本目录在 test160 上的实测；本目录的实测是 0.511/0.094，两者要分开写。

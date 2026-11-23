# 文献与定位（CodeQL + LLM 告警分流）

只列与本实验直接相关的文献；每条给出可核验链接、核心结论、与本目录的关系。不是完整综述，也不把摘要之外的内容写成事实。

## A. LLM 辅助静态分析 / 告警裁决

### A1. IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities

- 作者/年份：Ziyang Li 等，2024（v3 2025）。
- 链接：https://arxiv.org/abs/2405.17238
- 结论（摘要）：LLM 推断 taint 规格并做上下文分析，与静态分析结合做 whole-repository Java 漏洞检测；新数据集 CWE-Bench-Java 120 个漏洞，CodeQL 检出 27 个，IRIS+GPT-4 检出 55 个，平均 false discovery rate 改善 5 个百分点，并发现 4 个此前未知漏洞。
- 与本实验：支持“LLM 补静态分析的规格/上下文”，但任务是全仓库 Java 检测，不是 C++ 单 TU 告警后分流；不能直接类比我们的 23 FP 撤销率。

### A2. The Hitchhiker’s Guide to Program Analysis: A Journey with Large Language Models（LLift）

- 作者/年份：Haonan Li 等，2023。
- 链接：https://arxiv.org/abs/2308.00245
- 结论（摘要）：以 use-before-initialization 为案例，LLM 与静态分析工具接口，处理 bug-specific modeling、大搜索范围、非确定性；在近 1000 条静态告警上 precision 约 50%，看起来没有漏报，并在 Linux kernel 发现 13 个新 UBI bug。
- 与本实验：最接近“告警后 LLM 过滤”的早期工作；它强调 LLM 是辅助角色，与我们把 LLM 放在 CodeQL 之后一致。

### A3. Reducing False Positives in Static Bug Detection with LLMs: An Empirical Study in Industry（LLMPFA）

- 作者/年份：Xueying Du 等，2026。
- 链接：https://arxiv.org/abs/2601.18844
- 结论（摘要）：Tencent 工业 SAT 的 433 条告警（328 FP / 105 TP，3 类 bug）；LLM/混合技术消除 94–98% FP 且保持高召回；每条告警 2.1–109.5 秒、$0.0011–$0.12；并总结工业场景的限制。
- 与本实验：给出成本量级；我们的 triage 约 $0.00037/告警、$0.00146/撤销 FP，低于其区间下限，但任务/模型/数据不同，不能直接比。

### A4. Using LLMs to Adjudicate Static-Analysis Alerts with Error Reduction Techniques

- 作者/年份：William Klieber 等，2026。
- 链接：https://arxiv.org/abs/2607.09979
- 结论（摘要）：在 Juliet、FormAI、SV-COMP 上研究 LLM 告警裁决；用 consistency check（多次采样一致性）和 reasoning evaluation；中端 reasoning 模型在三个套件上达到 ≥98% recall、≥94.8% specificity；并发现 o4-mini 能重建清洗后的 Juliet 原始身份，因此把泛化主张主要放在 FormAI；用 LLM 合成触发程序作为独立证据时，所有针对 false alarm 的触发都被有效性检查拒绝。
- 与本实验：直接对应“Juliet 记忆化”限制；也说明“一致性检查”是有效但可能只是纠错，不是新增判别力。我们的二次复核/文本规则与它的 consistency check 同源。

### A5. The Hitchhiker’s Guide to Program Analysis, Part III: Mostly Harmless LLMs（Evident）

- 作者/年份：Haonan Li 等，2026。
- 链接：https://arxiv.org/abs/2606.15122
- 结论（摘要）：让 LLM 识别相关代码并构造 harness，交给 Frama-C/Eva 做精确、targeted 静态分析；在 200 个真实 Android kernel-driver 告警（含 40 个 confirmed bug）上，过滤 48.8–63.8% 的 160 个 false alarm，且不漏 confirmed bug；而“让 LLM 做最终裁决”的 baseline 在每个模型上都漏 confirmed bug（27.5–45.0%），虽然总体 accuracy 高 2.0–5.5 个百分点。
- 与本实验：**最重要的外部依据**。我们的 v1 正是“LLM 最终裁决”失败模式（7/68 TP 误删）；v2 用任务定义约束修掉，但仍应把“不能撤销”的硬约束/外部见证作为目标，而不是只靠提示。

### A6. Finding Memory Leaks in C/C++ Programs via Neuro-Symbolic Augmented Static Analysis（MemHint）

- 作者/年份：Huihui Huang 等，2026。
- 链接：https://arxiv.org/abs/2603.27224
- 结论（摘要）：LLM 把每个函数分类为 allocator/deallocator/neither，生成“哪个参数/返回值携带所有权”的 summary；Z3 检查 summary 在 CFG 上是否可达；注入 CodeQL/Infer；在 8 个真实 C/C++ 项目、3.6M LOC 上检出 54 个泄漏（全部确认/修复，约 $1.76/bug），vanilla CodeQL 19 个、Infer 3 个。
- 与本实验：直接对应 `_22`/`_54`/`_72` 的跨函数所有权；说明更根本的修法是把 owner/transfer summary 注入分析器，而不是告警后文本 triage。

## B. 内存泄漏 / 所有权静态分析

### B1. A Practical Flow-Sensitive and Context-Sensitive C and C++ Memory Leak Detector

- 作者/年份：David L. Heine, Monica S. Lam，PLDI 2003。
- 链接：https://dl.acm.org/doi/10.1145/781131.781150
- 结论：flow-sensitive、context-sensitive 的 C/C++ 泄漏检测，基于所有权模型，能处理 alias/ownership transfer；是后续泄漏检测的经典基线。
- 与本实验：`_33` 的 15 个 FP 正是“引用 + 同名遮蔽 + 栈 ALLOCA + 堆 free”场景；说明这不是“模型笨”，而是别名/所有权分析的经典难点。

### B2. Static Memory Leak Detection Using Full-Sparse Value-Flow Analysis

- 作者/年份：Yulei Sui, Ding Ye, Jingling Xue，ISSTA 2012。
- 链接：https://yuleisui.github.io/publications/issta12.pdf
- 结论：用 full-sparse value-flow 做静态泄漏检测，跨函数追踪指针值流；在精度/可扩展性之间取平衡。
- 与本实验：`_54`/`_72` 需要跨函数/容器元素的值流；CodeQL 的 `may-not-be-freed` 保守性正来自这类跨函数不确定性。

### B3. QL: Object-oriented Queries on Relational Data（CodeQL）

- 作者/年份：Pavel Avgustinov, Oege de Moor, Michael Peyton Jones, Max Schäfer，ECOOP 2016。
- 链接：https://doi.org/10.4230/LIPIcs.ECOOP.2016.2
- 结论：QL 把程序数据库当关系数据查询，类/继承/虚调用都被解释为逻辑属性；CodeQL 是其工业实现。
- 与本实验：`cpp/memory-never-freed` 与 `cpp/memory-may-not-be-freed` 是两条保守程度不同的查询；23 FP 全部来自后者，说明“query 先验”是必须报告的基线。

### B4. Juliet 1.3 / NIST SARD CWE-401

- 链接：https://samate.nist.gov/SARD/test-suites/112
- 说明：NIST Juliet C/C++ 1.3 测试套件，CWE-401 Memory Leak 用例；标签由 `OMITBAD`/`OMITGOOD` 宏门控；NIST TN 1995 记录了 Juliet 1.3 的已知问题（含“thousands of cases have memory leaks”）。
- 与本实验：数据来源；合成、短小、模式化，适合受控比较，不适合直接外推真实项目。NIST TN 1995：https://nvlpubs.nist.gov/nistpubs/TechnicalNotes/NIST.TN.1995.pdf

### B5. SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection

- 作者/年份：Md Basim Uddin Ahmed 等，2025。
- 链接：https://arxiv.org/abs/2505.19828
- 结论（摘要）：真实 C/C++、5,867 CVE、25,440 函数样本，语句级标签与上下文；SOTA LLM 的语句级 F1 仍低（最佳 Claude-3.7-Sonnet 23.83%）。
- 与本实验：与本项目 Tier A 对应；提醒 Juliet 的结论不能替代真实项目。我们的 0.9857 只属于 Juliet CWE-401 test 140。

### B6. Project-Level Resource Leak Detection through Agent-based Ownership Analysis（AROP，ICSE 2026）

- 链接：https://conf.researchr.org/details/icse-2026/icse-2026-research-track/201/Project-Level-Resource-Leak-Detection-through-Agent-based-Ownership-Analysis-and-Repa
- 说明：项目级资源泄漏检测，LLM agent + ownership analysis + repair pattern verification；摘要页可核验标题/作者/会场。
- 与本实验：与 `_22`/`_54` 的“跨函数所有权”方向一致；本实验没有实现 agent/项目级分析，只做单单元告警后分流。

### B7. SafeMD: Ownership-Based Safe Memory Deallocation for C Programs

- 作者/年份：2024，MDPI Electronics。
- 链接：https://www.mdpi.com/2079-9292/13/21/4307
- 结论（摘要/正文）：基于所有权的安全释放，讨论 exclusive ownership、alias 与 inter-procedural 分析的取舍。
- 与本实验：`_33`/`_54` 的 free 路径需要 ownership 推理；可作为“为什么不能只看函数长度/文件名”的旁证。

## C. 与本实验的直接关系（一段话）

我们的结果位于 A2/A3/A4 的“LLM 过滤告警”传统与 A5 的“LLM 不能做最终裁决”警告之间：v1 复现了 A5 的失败（7/68 TP 误删），v2 用任务定义把失败压到 0，但这只是提示层修复；A4 的 Juliet 记忆化警告和 B4 的合成数据限制仍然成立。A6/B1/B2 说明 `_22`/`_54`/`_72` 的根本修法在分析器层的 ownership/value-flow summary，而不是告警后的文本理由。A1/A3 提供“LLM+静态分析有收益”的正向证据，但任务/语言/数据都不同，不能把我们的 0.9857 外推为真实项目 SOTA。

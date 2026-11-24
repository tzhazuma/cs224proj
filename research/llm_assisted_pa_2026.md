# LLM 辅助程序分析：2025–2026 进展，以及和本项目的关系

检索时间：2026-11-23 PST。数字来自摘要页、HTML 全文或会议页面。预印本标“预印本”，作者自报的数字不当作独立复现。更早的工作见 `hybrid_ai_memory.md` §3 和 `latest_memory_tools_2026.md` §2.7。

## 1. 和 L4 / L4-D 最接近：LLM 抽取事实，再用 Datalog 推导

| 工作 | 出处 | 做法 | 和本项目的关系 |
|---|---|---|---|
| **NeuroLog**: "Reasoning You Can Audit — Neuro-Symbolic Vulnerability Discovery via LLM Facts, Datalog, and SMT" | arXiv 2606.00669，v2 2026-10-12；技术报告，单作者（匿名） | tree-sitter 给出语法事实（Call、CFGEdge、Dominates…）；**DeepSeek V4-Flash** 逐函数抽取 12 类数据流事实（Def/Use/Guard/MemRead…）；Soufflé 推导；Z3 过滤不可行路径；LLM 生成崩溃输入，ASan 确认 | 几乎就是我们 L4 的设计，连模型都相同（deepseek-flash）。没有报告事实级准确率，也没有 P/R/F1；原规则集不含泄漏，后来加的 lifecycle 规则找到 3 个资源泄漏；代码说会发布，但没有给 URL |
| LLMSA / NESA | arXiv 2412.14399 | LLM 回答 Datalog 风格的子问题，符号部分组合答案 | L4 的方法来源之一 |
| LLMDFA | NeurIPS 2024 | 把数据流分析拆成 source/sink 识别、摘要、路径可行性；LLM 写代码调用解析器和 Z3 | 同上 |
| IRIS | ICLR 2025 | LLM 推断 taint 规格，交给 CodeQL | 规格生成路线；Java |

**结论**：这些工作的抽取器都是生成式大模型，评价都在发现 bug 的层面。**没有一项做过以下任何一件事：事实级准确率、用动态分析给事实打标签、训练小 decision model 来回答事实题、在 DeadFree 这类语义保持扰动下评测。** L4-D 正好填这个空白。

## 2. LLM 裁决静态分析告警（triage / adjudication）

| 工作 | 出处 | 要点 |
|---|---|---|
| **LASAA**: "Using LLMs to Adjudicate Static-Analysis Alerts with Error Reduction Techniques"，Klieber、Svoboda、Flynn、Martins（CMU SEI/CERT） | arXiv 2607.09979，2026 预印本 | 测试集：Juliet 100 个用例（40 个 CWE，**含 CWE-401 的 3 个用例**；bad/good 各算一条告警）、FormAI、SV-COMP。告警直接来自基准标签，**不是真实分析器的输出**。纠错手段：一致性检查（N=10 次运行，80% 阈值）、LLM reasoning evaluation（LRE）。o4-mini、gpt-oss 在三个测试集上召回 ≥98%、特异度 ≥94.8%。**记忆化**：o4-mini 能从清洗后的 Juliet 代码还原出具体功能变体，准确率 68%，大体正确 91%，流变体编号还原 48% → 作者的泛化结论主要依据 FormAI。没有测语义保持扰动 |
| Tencent 工业实证 | ICSE 2026 SEIP（arXiv 2601.18844） | 433 条企业 SAST 告警（328 FP）；LLM 与静态分析混合方法剔除 94–98% 的 FP；每条告警 2.1–109.5 s、$0.0011–0.12 |
| LLM4PFA | arXiv 2506.10322（2025） | LLM agent 做路径可行性约束推理；过滤 72–96% 的 FP；45 个真 bug 漏 3 个 |
| MemHint | arXiv 2603.27224（预印本） | 泄漏专用：LLM 识别自定义内存管理函数，Z3 验证，再注入 CodeQL/Infer；Juliet 只用标准分配器，用不上 |
| LLM4SA | TOSEM 2024 | 对 Cppcheck、CSA、Infer 的告警做分流，Juliet 在测试集之内；召回不会超过工具本身 |

## 3. LLM 合成检查器或规格；agent 加验证

- **KNighter**（SOSP 2025）：从补丁合成 Clang SA checker，在 Linux 内核找到 92 个新 bug。
- **InferROI**（ICSE 2025）：LLM 推断资源意图，再做静态路径分析；对象是 Java/Android。
- **MoCQ**：LLM 生成漏洞模式 DSL，再做符号验证。
- **RepoAudit**：agent 维护数据流事实，配合 validator。
- **Revelio**（arXiv 2606.22263）：廉价 LLM 提出漏洞想法并生成 PoV，由 sanitizer 确认；7 个项目找到 19 个新内存安全漏洞，约 $300。
- 这些都在仓库级找真实 bug，而且需要构建或补丁历史，和我们的单元级二分类基准对不上。

## 4. 评测类工作（支撑我们的发现，或给出预期）

| 工作 | 出处 | 和本项目的关系 |
|---|---|---|
| **SemBench**: "How well do LLMs understand code?"，Xu … Cong（UCLA） | Commun. AI Comput. 1, 13（2026） | 1000 个真实 C 程序上的是/否静态语义题，标准答案由 AST/LLVM 自动生成（死代码语句、数据依赖、函数可达、支配、死循环、活跃性）。最好的模型总分 80.42%，常用模型 40–65%；死代码语句最容易（GPT-5 91.15%）；活跃性最难；7–14B 模型较弱；CoT 几乎无帮助。→ 形式与 L4-D 的“是/否 + 自动标签”很像；说明零样本小模型回答执行类问题会很吃力 |
| **DexBench**: "The Path Not Taken: Duality in Reasoning about Program Execution" | ACL 2026 long | 预测语句覆盖（执行过哪些行），以及反事实地改输入去覆盖某个分支。**<10B 小模型的覆盖预测接近 0**；reasoning 版本反而更差。→ 支持 L4-D 需要微调，而不是零样本 |
| **CASTLE** | TASE 2025（Dubniczky … Cordeiro） | 250 个手写 C 程序，25 个 CWE（**含 401**），比较 13 个 SAST、ESBMC/CBMC、10 个 LLM；不用 Juliet，理由是 Juliet 已在 LLM 训练数据中。o3-mini 召回 81%、精确率 63%；ESBMC 召回 35%、精确率 82% |
| **Familiar Pattern Attack**: "Trust Me, I Know This Function: Hijacking LLM Static Analysis using Bias"，Bernstein … Mirsky | NDSS 2026 | 不改变运行行为的微小改动就能劫持 LLM 对代码的理解，跨模型、跨语言都有效，提示词里提前警告也挡不住。→ 和 DeadFree 的发现同一类（插入的死 free 让 DeepSeek 和 LoRA 被骗） |
| "How much model does warning triage need? A cost-aware comparison from rules to locally run language models"，Sullivan & Mikhaylov | American Impact Review 2026 | 告警分流：原 AW4C 数据集上，“代码上下文行数”这一捷径就能达到 MCC 0.91（CodeBERT 0.81），统一窗口后降到 0.12 / 0.30；本地 LLM 的处理时间约为微调编码器的 47 倍。→ 与我们“格式捷径 + 小模型更快”的结论吻合 |
| Risse & Böhme；Germano et al. | USENIX Sec 2024 / ICAART 2025 | 已在 `juliet_dataset_adjustment.md` 中引用 |

## 5. decision model 路线（见 `decision_models_2026.md`）

- Look Here, Then Decide（arXiv 2611.16565）
- Cyber-JEV（arXiv 2611.02957）
- Intern-Decision、Jev、AnyJev
- 它们都只输出整体判定，没有拆成事实来回答。

## 6. 能否作为对比对象

| 候选 | 能否直接对比 | 理由 | 本项目里的对应物 |
|---|---|---|---|
| NeuroLog | 不能直接跑 | 没有代码 URL；规则针对溢出/UAF；仓库级找 bug，没有 P/R | 我们的 L4（DeepSeek 抽取事实 + Soufflé）就是它在 CWE-401 单元上的受控版本；论文里写作 “NeuroLog-style” |
| LASAA（SEI） | 方法可以复现，但预算不够 | 一致性检查每个单元要 10 次调用；DeepSeek 剩约 ¥1.8，不够；Qwen 本地可以跑（等 GPU 空出来） | 对应 L3（LLM + 工具告警）；它的记忆化结果可以直接引用来支撑我们的污染讨论 |
| LLM4SA / LLM4PFA / Tencent | 可以“风格化复现” | 让 LLM 裁决 Clang 告警：召回最多到 Clang 的 0.771；DeepSeek 大约只需调用约 1,100 个单元，约 ¥0.45 | L3 已经给了 Clang 告警作为证据；单独做裁决的信息增量小 |
| MemHint / LAMeD | 不适用 | Juliet 只用标准分配器，自定义分配器注解帮不上 | — |
| KNighter / IRIS / Revelio / RepoAudit | 不适用 | 需要补丁历史、仓库构建或 PoV；仓库级 | — |
| SemBench / DexBench | 不是检测器 | 它们是题目式基准 | 可以把 L4-D 的事实级准确率与之并列讨论 |
| VulnLLM-R-7B | 可以（计划在附录） | 有公开模型；CWE-401 对它是分布外（见 PLAN 附录） | 尚未运行 |

**定位**：最近的研究主要集中在两条线上，一是“大模型加符号验证去找真实 bug”，二是“大模型裁决告警”。本项目的差异有四点：
1. 受控基准：去掉格式捷径，加入 DeadFree 扰动；
2. 同一任务上并排比较生成式 LLM、decision model 和传统分析器；
3. 速度和成本放进主线；
4. L4-D 用动态分析自动给事实打标签，并训练小 decision model 来回答事实题。

这四点在上面的文献里都没有出现。

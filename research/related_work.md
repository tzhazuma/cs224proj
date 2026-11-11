# 相关工作调研：LLM C/C++ 漏洞检测、漏洞/修复配对评估与补丁质量评估

**项目**：SecVulEval 课程项目（C/C++；200 条独立函数，160 漏洞 + 40 非漏洞；200 对漏洞/修复版本）  
**调研日期**：2026-11-11  
**范围**：2023–2026 年 LLM/C/C++ 漏洞检测、buggy/fixed 配对评估、自动程序修复（APR）质量评估，以及 DeepSeek 代码模型与 API 官方资料。  
**证据分级**：A = 正式发表，DOI/页码或官方会议页面已核对；B = arXiv 预印本，元数据已核对但未必同行评审；C = 官方厂商文档/模型卡/工件，非独立研究。  
**重要声明**：本文件不包含本项目实测结果；本次调研没有调用任何模型，没有读取或输出任何密钥，也没有修改 `proposal/references.bib`。

---

## 0. 结论摘要

1. **PrimeVul 的正式出处已核实**：Ding 等，*Vulnerability Detection with Code Language Models: How Far Are We?*，ICSE 2025，pp. 1729–1741，DOI `10.1109/ICSE55347.2025.00038`；arXiv 为 `2403.18624`。它不是“只有 arXiv 的传闻工作”。
2. **PrimeVul 的规模与评估设置已核实**：6,968 个漏洞函数、228,800 个良性函数、140 个 CWE；5,480 对漏洞/修复函数；时间切分；提出 VD-S 与 P-C/P-V/P-B/P-R 四种配对结果。论文报告 StarCoder2 在 BigVul 上 F1 68.26%，在 PrimeVul 上仅 3.09%；GPT-4 的配对判断在严格设置下不优于随机猜测。
3. **SecVulEval 的正式出处已核实**：Ahmed 等，*SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection*，AIware 2026，pp. 388–396，DOI `10.1145/3805760.3814932`；arXiv 为 `2505.19828`。注意：arXiv 标题与正式标题不同。
4. **SecVulEval 的核心数字**：25,440 个函数、5,867 个 CVE、707 个项目、145 个 CWE、10,998 个漏洞函数、14,442 个非漏洞函数；语句级标注与五类上下文；五个 LLM；最佳 Claude-3.7-Sonnet 的语句级 F1 为 23.83%（定位正确且理由正确）。
5. **配对评估不是新想法，但“在 SecVulEval 上系统比较多种 LLM prompting 方法”仍是空白**：PrimeVul 在自有数据上做配对评估，VulnPatchPairs 在 CodeXGLUE/FFmpeg/QEMU 上做 13.1k 对，Vul-RAG 报告 LLM 在“漏洞 vs 相似补丁”上仅 0.06–0.14 准确率。SecVulEval 论文本身主要评估语句级检测与上下文识别，没有把 200 对级别的配对判别作为主实验。
6. **APR 质量评估的强 oracle 不能直接用于本项目的函数片段**：编译、测试、PoC、PoC+、fuzzing/differential testing、语义等价/人工审查，都是比“数据集标签”更强的证据；但本地 JSON 只有函数文本，没有完整构建环境、测试或 PoC。因此本项目只能声称“标签一致性/配对判别”，不能声称“补丁正确性”。
7. **DeepSeek 当前官方 API 已进入 V4 系列**：截至 2026-11-11，官方定价页列出 `deepseek-flash`（DeepSeek-V4.1-Flash-1017）与 `deepseek-v4-pro`（DeepSeek-V4-Pro-0813），1M 上下文、384K 最大输出、JSON Output、Thinking Mode。V4 是通用模型，不是“DeepSeek-Coder-V4”；代码专用模型仍是 2024 年的 DeepSeek-Coder / Coder-V2。
8. **本项目最合适的方法矩阵**：M1 直接零样本分类；M2 结构化推理（thinking + 证据字段）；M3 成对差分提示（同一对两版本，随机 A/B 顺序）。三者共用同一模型、同一数据、同一解析与统计流程，满足课程“同一数据集比较 2–3 种 LLM 方法”的要求。成本按官方价格估算为个位数到几十美元量级，取决于 thinking token 与重复次数。

---

## 1. 事实核验：PrimeVul 与 SecVulEval 的真实出处

### 1.1 PrimeVul

| 核验项 | 结果 | 证据 |
|---|---|---|
| 正式标题 | *Vulnerability Detection with Code Language Models: How Far are We?* | DOI 元数据；arXiv v2 标题为 *How Far Are We?*，仅大小写/标点差异 |
| 作者 | Yangruibo Ding, Yanjun Fu, Omniyyah Ibrahim, Chawin Sitawarin, Xinyun Chen, Basel Alomair, David Wagner, Baishakhi Ray, Yizheng Chen | DOI/Crossref |
| 正式出处 | ICSE 2025（47th IEEE/ACM International Conference on Software Engineering），pp. 1729–1741 | DOI `10.1109/ICSE55347.2025.00038` |
| arXiv | `2403.18624`；v1 2024-03-27，v2 2024-07-10；v2 备注“Accepted for ICSE 2025; Camera-ready Work in Progress” | arXiv abs 页 |
| 数据规模 | 6,968 个漏洞函数 + 228,800 个良性函数；140 个 CWE | 论文摘要/第 III 节 |
| 配对规模 | 5,480 对；按时间切分：train 4,354 对、dev 562 对、test 564 对 | 论文 Table III |
| 配对筛选 | 只保留漏洞版本与修复版本字符串相似度至少 80% 的“困难对” | 论文第 IV-B2 节 |
| 评估指标 | VD-S（固定 FPR 预算下的 FNR）；配对结果 P-C/P-V/P-B/P-R | 论文第 IV 节 |
| 标签准确率 | PrimeVul-NVDCheck 92%，PrimeVul-OneFunc 86%；SVEN 94%，DiverseVul 60%，CVEfixes 51.7%，CrossVul 47.8%，VulnPatchPairs 36%，BigVul 25%，CodeXGLUE 24% | 论文 Table I；其中 BigVul/CrossVul/CVEfixes/DiverseVul 的数字转引自 Chen et al.，其余为本文人工抽查 |
| 主要实证结果 | StarCoder2 在 BigVul 上 F1 68.26%，在 PrimeVul 上 3.09%；GPT-4 + CoT 在配对评估中不优于随机猜测 | 论文摘要/第 V 节 |
| 工件 | `https://github.com/DLVulDet/PrimeVul` | 论文第 I 节 |

**需要特别说明的三点**：

- **“3.09% F1”不是所有模型在 PrimeVul 上的普遍成绩**，而是论文中 StarCoder2 这一 7B 模型在特定设置下的结果。引用时必须带模型名和设置，不能写成“LLM 在 PrimeVul 上只有 3% F1”。
- **配对评估的“随机猜测”不是指二分类的 50% 准确率**，而是指在“必须同时判断一对中的两个版本”时，模型没有表现出可用的判别能力；论文报告 GPT-4 + CoT 在该设置下不优于随机。
- **PrimeVul 的标签准确率来自人工抽查**，不是对所有 6,968 条的全量人工复核；引用时要保留“抽查 50 条/数据集”的口径。

### 1.2 SecVulEval

| 核验项 | 结果 | 证据 |
|---|---|---|
| 正式标题 | *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection* | ACM DOI 页 |
| arXiv 标题 | *SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection* | arXiv `2505.19828`（标题与正式版不同，引用时用正式标题） |
| 作者 | Md Basim Uddin Ahmed, Nima Shiri Harzevili, Jiho Shin, Hung Viet Pham, Song Wang | DOI/arXiv |
| 正式出处 | AIware '26（3rd ACM International Conference on AI-Powered Software），pp. 388–396 | DOI `10.1145/3805760.3814932` |
| arXiv | `2505.19828`，v1 2025-05-26 | arXiv abs 页 |
| 数据规模 | 25,440 个函数；5,867 个唯一 CVE；707 个项目；145 个 CWE；10,998 个漏洞函数；14,442 个非漏洞函数；CVE 时间跨度 1999–2024 | 论文摘要/Table 2 |
| 标注粒度 | 语句级漏洞标注；变更语句（deleted/added）；CVE/CWE/commit/文件/函数元数据 | 论文第 3 节 |
| 上下文 | 五类：Function Arguments、External Functions、Type Execution Declarations、Globals、Execution Environments；用 GPT-4.1 自动提取，人工抽查 100 条，准确率 82.98% | 论文第 3.4/4.2 节 |
| 检测流程 | 五代理：Normalization（tree-sitter）→ Planning → Context → Detection → Validation；后四个由 LLM 驱动；Validation 与 Detection 最多迭代 3 次 | 论文第 4.1 节 |
| 评估模型 | Qwen2.5-Coder-32B、DeepSeek-Coder-33B、Codestral-22B、GPT-4.1、Claude-3.7-Sonnet | 论文第 4.4 节 |
| 主要结果 | 最佳 Claude-3.7-Sonnet 语句级 F1 23.83%（precision 15.35%，recall 53.23%）；GPT-4.1 语句级 F1 22.38%；DeepSeek-Coder-33B 函数级 F1 45.71%、语句级 F1 7.14% | 论文 Table 3 |
| 人工评估口径 | 从 Top-25 CWE 随机抽 300 条；语句级 TP 要求“定位正确 + 理由正确”，允许至多 2 条无关语句；sink/source 均可接受 | 论文第 5.1 节 |
| 工件 | `https://huggingface.co/datasets/arag0rn/SecVulEval`；`https://github.com/basimbd/SecVulEval` | 论文第 1 节；数据卡 [38] |

**与本项目直接相关的三点**：

- 项目 README 与数据构建说明中的 25,440 条记录、10,998/14,442 标签分布与论文一致；本项目的 200 条独立子集和 200 对子集是从该表按固定种子抽出的评估子集，不是新的数据源。
- SecVulEval 论文的 23.83% 是**语句级、多代理、理由正确**的口径，不是函数级二分类，也不是本项目的预期结果。引用时必须写清“statement-level / with correct reasoning / multi-agent”。
- 论文的上下文由 GPT-4.1 生成；本项目若把 `context` 字段放进 prompt，属于“使用数据集提供的上下文”，应作为单独的 context ablation，不应与“纯函数输入”的主实验混在一起。

### 1.3 容易被误传的说法（建议在报告中主动纠正）

| 说法 | 事实 | 处理建议 |
|---|---|---|
| “PrimeVul 只是 arXiv 预印本” | 已发表于 ICSE 2025，有 DOI 和页码 | 引用正式版；可同时给 arXiv 号 |
| “PrimeVul 有 7,768 对” | 论文报告 **5,480 对**（train 4,354 / dev 562 / test 564） | 不要使用来历不明的 7,768 |
| “SecVulEval 只有 arXiv” | 已发表于 AIware 2026，pp. 388–396 | 引用正式版；注意正式标题与 arXiv 标题不同 |
| “SecVulEval 最佳 F1 23.83% 是函数级” | 是**语句级 + 正确理由 + 多代理** | 必须带口径 |
| “VulnPatchPairs 是 2023 年 FSE 论文” | 是 Risse & Böhme，USENIX Security 2024；26.2k 函数、13.1k 对 | 引用 USENIX 页面；不要编造 DOI |
| “DeepSeek-Coder-V4” | 不存在这个官方模型名；当前是通用 DeepSeek-V4 系列，代码专用是 DeepSeek-Coder / Coder-V2 | 写作时区分“通用 V4”与“代码专用 Coder-V2” |
| “DeepSeek-V4 已在漏洞检测上 SOTA” | 官方资料只给通用/编码/agent benchmark，没有漏洞检测结论 | 不要把厂商编码分数外推为漏洞检测能力 |
| “fixed 版本一定没有漏洞” | 数据集标签只表示“该修复版本对应某次修复”，不证明不存在其他缺陷 | 报告中明确标签继承与限制 |

---

## 2. 2023–2026 年 LLM C/C++ 漏洞检测

### 2.1 数据集与基准的演进

| 数据集/基准 | 年份 | 规模与特点 | 标签/配对 | 与本项目的关系 |
|---|---|---|---|---|
| BigVul [4] | 2020 | 约 3.7k 漏洞函数，348 个项目；从修复提交自动标注 | 函数级/行级；无配对评估 | 经典但标签噪声高（PrimeVul 抽查 25% 准确率），仅作历史背景 |
| CVEfixes [5] | 2021 | 5,365 个 CVE 记录、1,754 个项目；多层级抽象；含修复提交 | 函数/行级；有修复版本 | 说明“漏洞-修复”数据可从 CVE 构建；C/C++ 子集标签准确率约 51.7% |
| DiverseVul | 2023 | 18,945 个漏洞函数、330,492 个非漏洞函数、150 个 CWE、7,514 个提交 | 函数级；无配对评估 | 规模大但标签准确率约 60%；说明“大”不等于“可靠” |
| SVEN | 2023 | 约 1.6k 函数、803 个漏洞、9 个 CWE；人工标注 | 函数级；安全 hardening | 小但标签准确率高（94%）；说明人工标注的成本 |
| VulnPatchPairs | 2024 | 26.2k 个 C 函数、13.1k 对；来自 CodeXGLUE/Devign 的 FFmpeg、QEMU | 漏洞/补丁成对 | **配对评估的直接先例**；但标签继承 CodeXGLUE，PrimeVul 抽查仅 36% |
| PrimeVul | 2025 | 6,968 漏洞 + 228,800 良性、140 CWE、5,480 对 | 函数级 + 配对；时间切分 | 配对指标与“标签质量”论证的主要来源 |
| SecVulEval | 2026 | 25,440 函数、5,867 CVE、707 项目、145 CWE、10,998 漏洞 + 14,442 非漏洞 | 语句级 + 上下文；含修复前后版本 | 本项目的数据源；提供比函数标签更细的元数据 |
| ARVO | 2024 | 6,100+ 可复现漏洞、311 个项目；每个漏洞可重建、触发、分析 | 可执行 PoC + 开发者补丁 | 说明“可复现”是比“函数文本”更强的评估基础；本项目不具备 |
| Vul4C（SoK AVR） | 2025 | 144 个 C/C++ 漏洞，含 exploit 与 patch | 可执行修复评估 | 若课程要求 APR 质量，应另做该基准，而不是用本项目 200 对 |

**要点**：

- 数据规模从 BigVul 的千级，发展到 DiverseVul 的万级、PrimeVul/SecVulEval 的万级函数；但**标签质量并没有随规模同步提高**。
- PrimeVul 的核心贡献不是“又一个大数据集”，而是把**标签审计、去重、时间切分、配对评估、VD-S** 组合成一套更严格的评估协议。
- SecVulEval 的核心贡献是**语句级标注 + 上下文**，而不是配对评估；它的 25,440 条记录包含修复前后版本，但论文主实验是语句级检测与上下文识别。

### 2.2 方法谱系

更完整的分类与文献地图可参考 Sheng 等的综述 [16]。

| 方法家族 | 代表工作 | 核心想法 | 已知证据 | 对本项目的可用性 |
|---|---|---|---|---|
| 直接零样本/少样本提示 | VulBench [9]、LLM4Vuln [10]、Outside the Comfort Zone [13] | 把函数放进 prompt，让 LLM 输出 vulnerable/not | LLM 可超过部分传统模型，但受 prompt、模型、数据影响大 | 作为 M1 基线，成本最低 |
| 结构化推理 / CoT | LLM4Vuln [10]、SecVulEval 多代理 [1] | 分解为知识、上下文、推理、验证等步骤 | 分解有帮助，但语句级定位仍很难；多代理可能混杂模型能力与编排收益 | 作为 M2；建议单调用结构化输出，避免多代理成本 |
| 知识级 RAG | Vul-RAG [11] | 从历史漏洞/修复中抽取多维知识，检索后逐条推理 | LLM 在“漏洞 vs 相似补丁”上仅 0.06–0.14 准确率；RAG 提升 16–24% | 可作为可选 M4；但知识库若来自同一数据，存在泄漏风险 |
| 神经符号 / 静态分析辅助 | IRIS [14]、RepoAudit [15] | LLM 推断 taint 规格/数据流事实，静态分析验证 | IRIS 在 Java 上把 CodeQL 的 27/120 提升到 55/120；RepoAudit 在仓库级达到 78.43% precision | 需要仓库/构建上下文；本项目的孤立函数不适用 |
| 成对/差分判断 | PrimeVul [2]、VulnPatchPairs [7]、Vul-RAG [11] | 给漏洞版本与修复版本，判断哪一个有漏洞 | 多种模型在配对任务上接近随机；说明模型依赖表面特征 | **M3 的直接依据** |
| 微调小型代码模型 | PrimeVul [2]、SVEN [6]、DiverseVul [3] | 在漏洞数据上监督微调 | 受标签噪声与数据泄漏影响；跨数据集泛化差 | 课程时间/算力下不建议；可作为未来工作 |

### 2.3 关键实证发现

1. **函数级二分类的定义本身不充分**。Risse、Liu、Böhme 调查发现，近五年 9/10 的 ML4VD 论文把任务定义为“给定函数，判断是否有安全缺陷”；但很多函数只有在调用上下文存在时才能判断，脱离上下文时标签并不可判定 [8]。他们还发现，仅用词频/长度等表面特征就能在这些数据集上取得高分，说明高分可能来自虚假相关，而不是漏洞语义。Steenhoek 等也发现模型对 buggy path 的对齐很弱，提供 bug 语义标注可在部分设置提升 F1 [12]。
2. **配对判别比独立分类更接近“是否理解修复”**。PrimeVul 的配对评估要求模型同时判断一对中的漏洞版本与修复版本；多种模型表现接近随机 [2]。VulnPatchPairs 发现六种 ML4VD 技术无法区分漏洞函数与对应补丁 [7]。Vul-RAG 进一步报告 LLM 在“漏洞 vs 相似但良性补丁”上只有 0.06–0.14 准确率 [11]。
3. **语句级比函数级更难**。SecVulEval 的最佳模型语句级 F1 仅 23.83%，而同一模型/流程的函数级 F1 可到 53.89%（Claude-3.7-Sonnet）；DeepSeek-Coder-33B 的函数级 F1 45.71%、语句级仅 7.14% [1]。这说明“判断函数有问题”与“指出哪条语句、为什么”是不同能力。
4. **标签噪声是跨数据集的系统性问题**。PrimeVul 汇总/抽查的漏洞标签准确率为：BigVul 25%、CodeXGLUE 24%、VulnPatchPairs 36%、DiverseVul 60%、CVEfixes 51.7%、CrossVul 47.8%、SVEN 94%、PrimeVul-NVDCheck 92% [2]。这直接支持“不能把不同数据集的 F1 直接横比”。
5. **领域微调只在域内有效**。Outside the Comfort Zone 比较 6 个漏洞专用模型与 6 个通用 LLM，发现小型专用模型微调后在训练场景内很强，但跨基准泛化有限；同时指出基准标签错误会放大结论偏差 [13]。
6. **知识/上下文增强有收益，但不是万能药**。Vul-RAG 用知识级 RAG 把“漏洞 vs 补丁”准确率提升 16–24%，并在 Linux 内核发现 10 个新 bug（6 个 CVE）[11]；LLM4Vuln 把知识、上下文、prompt 方案解耦，发现三者影响不同，不能把“模型能力”与“外部辅助”混为一谈 [10]。
7. **多代理/工具化能提升召回，但成本与可解释性是代价**。SecVulEval 的五代理流程把函数级召回推到 75% 左右（Claude/GPT-4.1），但 precision 只有 40% 左右；语句级 F1 仍低 [1]。RepoAudit 通过数据流事实与 validator 把仓库级 precision 提到 78.43%，但需要仓库与工具链 [15]。

### 2.4 对本项目的直接含义

- 本项目的独立子集只有函数文本，没有调用上下文；按 [8] 的观点，这更接近“数据集标签一致性测试”，而不是“真实世界漏洞检测”。报告中应明确这一外部效度限制。
- 本项目的配对子集至少提供了“同一函数的漏洞/修复两个版本”，比单函数更接近“模型是否理解修复差异”；但仍缺少调用上下文、构建环境和测试。
- 如果要在有限成本下做出有意义的比较，**方法差异应体现在输入/推理/任务形式**，而不是只换模型；否则很难把差异归因于方法。
- 建议在报告中加入**长度/词频等平凡基线**，用来检验模型是否只是学到了表面特征；这是 [8] 的直接方法借鉴。

---

## 3. Buggy/fixed 配对评估

### 3.1 为什么配对评估重要

配对评估的核心不是“再做一个二分类”，而是控制**同一函数、同一项目、同一漏洞家族**的混淆因素，让模型必须依赖修复带来的语义差异，而不是项目名、函数名、代码风格或长度。PrimeVul 把配对定义为“同一漏洞函数与其修复版本”，并要求两者字符串相似度至少 80%，以提高难度、减少表面差异 [2]。VulnPatchPairs 则从 CodeXGLUE/Devign 的漏洞函数出发，回原始仓库提取对应补丁，构造 13.1k 对 [7]。

### 3.2 PrimeVul 的四种配对结果

| 结果 | 含义 | 诊断价值 |
|---|---|---|
| P-C（Pair-wise Correct） | 两个版本都判对 | 真正的“修复差异辨识” |
| P-V（Pair-wise Vulnerable） | 两个版本都判为漏洞 | 过度报警/无法识别修复 |
| P-B（Pair-wise Benign） | 两个版本都判为良性 | 漏报/对漏洞不敏感 |
| P-R（Pair-wise Reversed） | 两个版本都判反 | 可能被“修复版本更像漏洞”的表面特征误导 |

这四种结果比单一 accuracy 更有解释力：P-V 高说明模型“见代码就报漏洞”；P-B 高说明模型“看不出问题”；P-R 高说明模型可能在利用错误的方向性特征。PrimeVul 报告 GPT-4 + CoT 在配对任务上不优于随机，说明即使是强模型也没有稳定掌握“修复差异” [2]。

### 3.3 其他配对证据

- **VulnPatchPairs**：26.2k 个 C 函数、13.1k 对；六种 ML4VD 技术在“训练于常规数据、测试于配对数据”时无法区分漏洞与补丁 [7]。但该数据集的标签继承 CodeXGLUE，PrimeVul 抽查其漏洞标签准确率仅 36% [2]，所以它更适合说明“任务很难”，不适合作为高质量标签基准。
- **Vul-RAG**：在“漏洞 vs 相似但良性补丁”上，LLM 的准确率仅 0.06–0.14；加入知识级 RAG 后提升 16–24% [11]。这说明配对任务不仅是“分类器”问题，还需要漏洞根因知识。
- **SecVulEval**：数据包含修复前后版本与语句级变更，但论文主实验是语句级检测/上下文识别，没有报告 P-C/P-V/P-B/P-R 式的配对指标 [1]。这正是本项目可以补上的一个小缺口。

### 3.4 本项目可采用的配对指标

建议同时报告：

1. **Pair Accuracy (P-C)**：200 对中两个版本都判对的比例。
2. **P-V / P-B / P-R**：三类错误的比例；特别关注 P-V（“都报漏洞”）和 P-R（“判反”）。
3. **Vulnerable-version recall**：漏洞版本被判为 vulnerable 的比例。
4. **Fixed-version specificity**：修复版本被判为 non-vulnerable 的比例。
5. **Paired consistency**：同一对中“一个 vulnerable、一个 non-vulnerable”的比例，不要求方向正确；用来区分“有区分能力但方向错”和“完全不区分”。
6. **Bootstrap 95% CI（按对重采样）**：200 对的区间较宽，不能只看点估计。
7. **McNemar 检验**：比较两种方法在同一对上的胜负差异；不要用独立样本检验。
8. **顺序稳健性**：同一对以 A/B 与 B/A 两种顺序各跑一次，报告顺序一致性；若差异大，说明位置偏差。

### 3.5 本项目配对子集能支持/不能支持的结论

| 可以支持 | 不能支持 |
|---|---|
| 模型是否更倾向把修复版本也判为漏洞（P-V） | 补丁是否真的修复了漏洞（需要 PoC/测试） |
| 模型是否对“同一函数的两个版本”给出不同判断 | 补丁是否语义等价于开发者意图 |
| 不同 prompting 方法在配对任务上的相对差异 | 模型在真实项目中的部署 precision/recall |
| 模型是否被 A/B 顺序影响 | 模型是否理解调用上下文/跨过程数据流 |
| 错误是否集中在某些 CWE/项目 | 对未见项目的泛化（样本量/项目隔离不足） |

> 关键限制：本项目的 `fixed` 标签来自 SecVulEval 的 `fixed_func_idx` 关联，表示“这是该漏洞记录的修复版本”，不表示“该函数不存在任何其他漏洞”。因此，报告中的正确说法是“与数据集标签一致”，不是“补丁正确”。

---

## 4. 自动程序修复（APR）质量评估：编译、测试、语义等价与补丁正确性

### 4.1 基本概念

APR 评估通常区分：

- **Plausible patch**：能通过现有测试套件的补丁；测试可能是开发者写的、也可能是自动生成的。
- **Correct patch**：真正修复了缺陷、符合开发者意图/规格的补丁；通常需要比现有测试更强的 oracle。
- **Overfitting patch**：只针对现有测试过拟合、在未见输入上仍然出错的补丁；是 plausible-but-incorrect 的主要来源。
- **Semantic equivalence**：补丁与开发者补丁在行为上等价（或对给定规格等价）；比“文本相同”宽，比“通过测试”强。

Gazzola 等的 APR 综述把流程概括为故障定位、补丁生成、补丁验证三段；验证阶段的核心问题就是“用什么 oracle 判断补丁是否正确” [17]。Zhang 等的学习型 APR 综述进一步按技术族整理了该流程 [28]；Java 侧的 Vul4J 也采用“可复现漏洞 + 修复”的设计 [29]。Smith 等指出，用同一套测试既生成又验证补丁会系统性高估 repair 成功率，很多“修复”只是过拟合测试 [18]。Qi 等对 GenProg 的重新评估发现，大量被原论文视为正确的补丁实际上是错误的/不安全的 [19]。这些工作奠定了“plausible ≠ correct”的共识。

### 4.2 证据强度阶梯

| Oracle | 能证明什么 | 不能证明什么 | 成本 | 本项目 600 条记录是否可用 |
|---|---|---|---|---|
| 数据集标签 | 与标注一致 | 真实漏洞/修复正确性 | 低 | 可用（唯一可用） |
| 编译通过 | 语法/类型/链接基本正确 | 行为正确、漏洞已修复 | 中 | 不可用：函数片段无完整构建环境 |
| 现有测试通过 | 在测试覆盖范围内行为正确 | 未覆盖输入、语义等价 | 中 | 不可用：无测试 |
| 开发者新增测试（PoC+） | 修复满足开发者补充的语义 | 所有可能行为 | 高 | 不可用：无测试 |
| PoC exploit 失败 | 原始攻击路径被阻断 | 其他攻击路径、功能回归 | 高 | 不可用：无 PoC/可执行环境 |
| Fuzzing + differential testing | 修复版本在大量输入上与预期一致、未引入新崩溃 | 语义等价、所有规格 | 高 | 不可用 |
| 语义等价/形式化/人工审查 | 最接近“正确” | 规格本身的正确性 | 很高 | 不可用（可对少量样本做人工审查，但不是执行验证） |

### 4.3 代表性工作与可借鉴点

1. **Smith 等（ESEC/FSE 2015）**：提出“补丁过拟合”问题，说明测试套件作为唯一 oracle 会高估 APR；并讨论用 held-out 测试、人工审查等更强验证来减少过拟合 [18]。
2. **Qi 等（ISSTA 2015）**：对 GenProg 的补丁做人工分析，发现许多“plausible”补丁并不正确；强调需要语义级验证，而不是只看测试通过 [19]。
3. **Ye 等（EMSE 2021）**：在大规模 APR 补丁上做自动正确性评估；用人工标注训练分类器，区分正确/过拟合补丁；说明“自动评估”本身可以作为研究对象 [20]。
4. **Fei 等（TOSEM 2025）**：系统综述 patch correctness assessment，覆盖动态/静态/学习型方法；指出没有单一 oracle 足够，通常需要组合证据 [21]。
5. **SoK AVR（2025）**：把自动漏洞修复（AVR）拆成漏洞分析、补丁生成、补丁验证；构建 Vul4C（144 个 C/C++ 漏洞，含 exploit 与 patch），并评估 7 个 C/C++ AVR 工具 [22]。这是“C/C++ + 可执行验证”的直接参考。
6. **PVBench（2026）**：209 个案例、20 个项目；每个案例包含基础测试（修复前功能测试 + PoC exploit）和开发者新增的 PoC+ 测试；三个 SOTA AVR 系统中，**超过 40% 被基础测试判为正确的补丁在 PoC+ 下失败** [23]。这说明“测试通过”仍会显著高估修复质量。
7. **VulnRepairEval（2025）**：以功能性 PoC exploit 为锚，要求修复后原始 exploit 失效；23 个 Python CVE、12 个 LLM，最佳模型仅修复 5/23（约 21.7%）；提示增强/多代理提升有限 [24]。这是“exploit-based”评估的代表；语言是 Python，不是 C/C++，但方法论可借鉴。
8. **ARVO（2024）**：6,100+ 个可复现漏洞、311 个项目；每个漏洞可重建、触发、分析；81% 可复现，89.4% 的补丁定位准确 [25]。它说明“可复现构建 + PoC”是大规模 C/C++ 评估的基础。
9. **AutoPatchBench（Meta, 2025）**：136 个 fuzzing 发现的 C/C++ 漏洞、11 种 crash 类型；双容器（漏洞/修复）构建；用 fuzzing + 白盒差分测试验证补丁；是 CyberSecEval 4 的一部分 [26]。
10. **SWE-bench（ICLR 2024）**：用真实 GitHub issue + 测试（FAIL_TO_PASS / PASS_TO_PASS）评估补丁；把“测试通过”作为主要信号，但也承认测试不完整 [27]。

### 4.4 对本项目的含义

- **不能把“fixed 版本被判为 non-vulnerable”称为“补丁正确”**。这只是“与数据集标签一致”；真正的补丁正确性需要编译、测试、PoC 或语义等价证据。
- **本项目的函数片段不具备编译/测试条件**：JSON 中只有函数体、文件路径、项目名等元数据，没有头文件、依赖、构建脚本、测试用例、PoC。即使函数本身语法完整，也无法独立编译成可执行程序。
- **如果课程要求 APR 质量评估**，建议单独做一个小型可执行实验：从 ARVO / Vul4C / AutoPatchBench 选 10–20 个 C/C++ 案例，跑“生成补丁 → 编译 → PoC 失败 → 回归测试”的 pipeline；不要把这部分强加到 200 对 JSON 上。
- **如果只能做标签级评估**，应在报告中明确“这是 patch discrimination，不是 patch correctness”，并把 APR 的强 oracle 作为 future work/威胁到效度讨论。

---

## 5. DeepSeek 代码模型与 API 官方资料

### 5.1 模型谱系

| 模型 | 发布时间/类型 | 规模 | 上下文 | 代码相关特点 | 来源 |
|---|---|---|---|---|---|
| DeepSeek-Coder | 2024-01，代码专用 | 1.3B–33B | 16K | 2T tokens；项目级代码语料；FIM（fill-in-the-middle）；宽松许可证 | arXiv `2401.14196` [30] |
| DeepSeek-Coder-V2 | 2024-06，代码专用 MoE | 16B/236B 总参，2.4B/21B 激活 | 128K | 在 DeepSeek-V2 中间 checkpoint 上继续预训练 6T tokens；338 种语言；代码任务可比 GPT-4-Turbo | arXiv `2406.11931` [31]；HF 模型卡 [37] |
| DeepSeek-V4-Flash | 2026，通用 MoE | 284B 总参，13B 激活 | 1M | 通用模型；官方称支持 1M 上下文；三种推理模式 | arXiv `2606.19348` [32]；HF 模型卡 [36] |
| DeepSeek-V4-Pro | 2026，通用 MoE | 1.6T 总参，49B 激活 | 1M | 通用模型；官方报告强 coding/agentic benchmark（如 LiveCodeBench 93.5、SWE-bench Verified 80.6，V4-Pro-Max，厂商数据） | 同上 |

**命名注意**：

- **没有 “DeepSeek-Coder-V4” 这个官方模型**。当前官方 API 提供的是通用 `DeepSeek-V4` 系列；代码专用模型仍停留在 `DeepSeek-Coder` / `DeepSeek-Coder-V2`（2024）。
- 截至 2026-11-11，API 定价页的模型别名是 `deepseek-flash` 与 `deepseek-v4-pro`；底层版本分别是 `DeepSeek-V4.1-Flash-1017` 与 `DeepSeek-V4-Pro-0813`。`deepseek-v4-flash` 等旧名已退役，请求会由 V4.1-Flash 服务 [33]。
- SecVulEval 论文使用的是 **DeepSeek-Coder-33B-Instruct**（2024 年的开源代码模型），不是当前 API 的 V4；其函数级 F1 45.71%、语句级 F1 7.14% 不能外推到 V4 [1]。

### 5.2 当前 API 能力与价格（官方页面快照）

| 别名 | 底层版本 | 上下文 | 最大输出 | JSON Output | Thinking | FIM | 输入（cache miss，off-peak/peak，每 1M） | 输出（off-peak/peak，每 1M） |
|---|---|---|---|---|---|---|---|---|
| `deepseek-flash` | DeepSeek-V4.1-Flash-1017 | 1M | 384K | ✓ | ✓（默认开启） | ✓（仅非 thinking） | $0.15 / $0.30 | $0.60 / $1.20 |
| `deepseek-v4-pro` | DeepSeek-V4-Pro-0813 | 1M | 384K | ✓ | ✓（默认开启） | ✓（仅非 thinking） | $0.66 / $1.32 | $1.98 / $3.96 |

补充：

- 缓存命中价格低得多：Flash $0.003/$0.006，Pro $0.022/$0.044（每 1M，off-peak/peak）[33]。系统提示固定时，prefix caching 可能显著降低输入成本，但需要实测命中率。
- Peak 时段为 UTC 周一至周五 01:00–04:00 与 06:00–10:00（不含中国法定节假日）；其余为 off-peak [33]。
- 价格与模型别名可能变化；实验前必须重新核对官方页面，并在报告中记录访问日期与版本。

**模型选择建议**：主实验用 `deepseek-flash` 跑完 M1–M3，理由是成本低、上下文足够、JSON/thinking 能力齐全；若预算允许，用 `deepseek-v4-pro` 在 50 条独立 + 50 对上做模型稳健性检查。不要把“Flash vs Pro”当成两种方法；它是模型消融，应与 prompting 方法分开报告。

### 5.3 对实验设计有影响的官方行为

1. **Thinking Mode 默认开启，默认 effort 为 high**。如果不显式关闭，所有请求都会先产生 `reasoning_content`，输出 token 和延迟都会显著增加 [35]。
2. **Thinking Mode 下 `temperature`、`presence_penalty`、`frequency_penalty` 不生效**（设置不会报错，但被忽略）；`top_p` 的行为也因模型而异 [35]。因此：
   - M1 直接分类若要可复现，建议显式 `thinking: disabled`，并使用非 thinking 的采样参数；
   - M2/M3 若要 reasoning，固定 `reasoning_effort`（如 `high`），不要同时指望 temperature 控制随机性。
3. **JSON Output** 需要：
   - `response_format={"type": "json_object"}`；
   - prompt 中出现 "json" 并给出示例；
   - 合理设置 `max_tokens`，避免 JSON 被截断；
   - 如果模型输出无法识别为 JSON，API 可能用空格替换非 JSON 内容，返回内容可能为空；代码要处理空内容并重试 [34]。
4. **FIM Completion 目前仅非 thinking 模式**；本项目的分类任务不需要 FIM，但若要做“补丁生成”实验，需要另选模式 [33]。
5. **API 是 OpenAI 兼容格式**：base URL `https://api.deepseek.com`，可用 `httpx` 直接 POST `/chat/completions`，不必安装 `openai` 包。当前 WSL 有 `httpx`，适合这种轻量调用方式。

### 5.4 成本估算（仅为计划值，不是实测）

数据侧：独立集函数中位 1,345.5 字符，p90 5,878，最大 32,767；配对集函数中位 1,275，p90 5,218，最大 32,767（本次用 WSL 只读统计）。按 3.5 字符/token 粗估，中位约 360–385 tokens，p90 约 1,490–1,680 tokens。

假设每次调用：

- M1（200 独立 + 400 配对函数）= 600 次；输入约 800 tokens/次，输出约 100–200 tokens/次。
- M2（同上）= 600 次；输入约 800–1,400 tokens/次，输出（含 thinking）约 300–5,000 tokens/次。
- M3（200 对 × 2 种顺序）= 400 次；输入约 1,600–2,000 tokens/次，输出约 400–4,000 tokens/次。

| 情景 | 每轮输入 tokens | 每轮输出 tokens | Flash off-peak/轮 | Pro off-peak/轮 | 3 轮 Flash | 3 轮 Pro |
|---|---:|---:|---:|---:|---:|---:|
| Lean（短输出） | 1.60M | 0.40M | ~$0.48 | ~$1.85 | ~$1.44 | ~$5.54 |
| Typical（中等 thinking） | 1.92M | 1.47M | ~$1.17 | ~$4.18 | ~$3.51 | ~$12.53 |
| Heavy（长 thinking） | 2.18M | 4.72M | ~$3.16 | ~$10.78 | ~$9.48 | ~$32.35 |

**使用方式**：这只是一个上界/量级估算，不是报价。实际成本应以 API 返回的 `usage` 字段（prompt_tokens、completion_tokens、reasoning_tokens 等）逐次累计；报告里应给出总 tokens、总费用、平均延迟、重试次数。若使用 cache hit 或只跑 1 轮，成本会低于表中数字。

### 5.5 当前环境约束

- 本次调研未检测到 `DEEPSEEK_API_KEY` 等凭证；WSL 有 `httpx`，但没有 `openai`/`pandas`/`openpyxl`。
- 因此**当前不能运行任何 API 实验**；本文件不包含本项目模型结果。
- 正式实验前需要：提供密钥（只通过环境变量，不写入文件/日志）、冻结模型版本、跑 5–10 条 pilot 检查 JSON 解析与成本、再全量运行。

---

## 6. 方法借鉴、差异点与建议的实验矩阵

### 6.1 建议的三种 LLM 方法

| ID | 方法 | 输入 | 推理设置 | 输出 | 主要回答 | 调用量 |
|---|---|---|---|---|---|---|
| M1 | 直接零样本分类 | 单个函数体 + 任务说明 | thinking disabled；固定采样参数 | `is_vulnerable`、`confidence`、`cwe`、`evidence` | RQ1/RQ3 基线 | 200 独立 + 400 配对函数 = 600 |
| M2 | 结构化推理 | 单个函数体 + 任务说明 + 输出 schema | thinking enabled，`reasoning_effort=high` | 摘要、敏感操作、数据流/边界推理、verdict、证据 | RQ1：推理是否提升 | 600 |
| M3 | 成对差分提示 | 同一对的 A/B 两个版本（随机顺序） | thinking enabled，`reasoning_effort=high` | `more_vulnerable: A/B/both/neither`、变更行为、证据 | RQ2：修复差异辨识 | 200 对 × 2 顺序 = 400 |

**为什么是这三种**：

- 三者覆盖了“直接判断”“结构化推理”“成对比较”三种典型 LLM 使用方式，且都可以用同一模型、同一数据、同一解析器实现。
- M1 是低成本基线；M2 检验“更多推理/证据”是否真的有用；M3 直接针对配对子集，回答“模型能否利用修复差异”。
- 不把“多代理”作为主方法：SecVulEval 的五代理流程成本高、编排复杂，且其收益与模型能力混杂 [1]；课程时间下，单调用结构化提示更可控。若时间允许，可把多代理作为 M2 的一个消融，而不是独立方法。
- M1/M2 在配对子集上**逐版本独立分类**（每个版本一次调用）；M3 把一对两个版本**联合输入**。因此 M3 的 400 次调用对应 200 对 × 2 种顺序，而 M1/M2 的 600 次调用对应 200 个独立函数 + 400 个配对函数。

**建议的平凡基线（不计入 LLM 方法数）**：

- 多数类（全判 vulnerable / 全判 non-vulnerable）；
- 仅用函数长度/词频的逻辑回归或阈值规则；
- 随机基线（配对任务用 1/4 或按类别比例）。
这些基线可以直接检验 [8] 的“表面特征”警告。

### 6.2 可借鉴的具体做法

| 来源 | 借鉴什么 | 在本项目怎么用 | 不照搬什么 |
|---|---|---|---|
| SecVulEval [1] | 语句级证据、五类上下文、多代理分解 | M2 要求模型输出“敏感操作/数据流/证据”；可做 context ablation | 不跑五代理；不把 23.83% 当成本项目预期 |
| PrimeVul [2] | 配对设计、P-C/P-V/P-B/P-R、VD-S 思想 | M3 用四种配对结果；报告 P-V/P-B/P-R | 不训练、不做时间切分；200 对不足以谈 VD-S |
| VulnPatchPairs [7] | 配对构造、近重复控制 | 只使用现有 200 对；检查两版本差异是否过小 | 不重新构造 13.1k 对 |
| Vul-RAG [11] | 知识级检索、根因解释 | 可选 M4：用通用 CWE 卡片做轻量 RAG；不要用同一数据的 CVE 描述 | 不构建大规模知识库；避免同源泄漏 |
| LLM4Vuln [10] | 知识/上下文/prompt 解耦 | 若时间允许，做 2×2 消融：有无 CWE 说明 × 有无 context | 不跑 3,528 个场景 |
| Top Score [8] | 上下文必要性、表面特征基线 | 加长度/词频基线；做 context ablation；报告“不可判定”比例 | 不把函数级标签当真实漏洞真值 |
| APR 评估 [17]–[26] | plausible vs correct、强 oracle | 明确本项目只能做标签一致性；APR 质量另做可执行实验 | 不在函数片段上假装编译/测试 |
| DeepSeek 官方 [33]–[35] | JSON mode、thinking 开关、价格 | 固定模型版本；显式 thinking；记录 usage | 不依赖默认 thinking；不使用退役别名 |

### 6.3 与代表性工作的差异

| 维度 | SecVulEval [1] | PrimeVul [2] | VulnPatchPairs [7] | 本项目 |
|---|---|---|---|---|
| 数据源 | NVD + GitHub 修复提交，25,440 函数 | CVE/修复提交，6,968 漏洞 + 228,800 良性 | CodeXGLUE/Devign（FFmpeg、QEMU），26.2k 函数 | 本地 SecVulEval 子集：200 独立 + 200 对 |
| 评估单元 | 函数 + 语句 | 函数 + 配对 | 函数 + 配对 | 函数 + 配对 |
| 标签 | 语句级、上下文、CVE/CWE | 函数级、人工审计 | 函数级、继承 CodeXGLUE | 继承 SecVulEval；不重新标注 |
| 配对规模 | 数据含前后版本，但主实验非配对 | 5,480 对 | 13.1k 对 | 200 对 |
| 上下文 | 五类上下文，GPT-4.1 提取 | 无（函数级） | 无 | 函数体为主；`context` 仅做 ablation |
| 模型 | 5 个 LLM + 多代理 | 7 个代码 LM + GPT-3.5/4 | 6 个 ML4VD 技术 | 2–3 种 prompting 方法；DeepSeek V4 Flash/Pro |
| 训练 | 无（评估） | 有微调/训练 | 有训练 | 无训练，纯推理 |
| 主要指标 | 语句级 P/R/F1 | VD-S、P-C/P-V/P-B/P-R | 配对准确率 | 独立集 P/R/F1/FPR；配对 P-C/P-V/P-B/P-R |
| 成本 | 多代理，较高 | 训练/推理，较高 | 训练，较高 | 低（API，按 token 计） |
| 主要贡献 | 语句级 + 上下文基准 | 标签质量 + 评估协议 | 配对难度证据 | 小规模、可复现的 prompting 方法比较 |

**本项目的定位**：不是提出新数据集，也不是追求 SOTA；而是在一个已有、可追溯的 C/C++ 数据子集上，用**同一模型、同一数据、同一解析/统计流程**比较 2–3 种 LLM 使用方法，并诚实报告配对判别与成本。这个定位与课程要求一致，也能避免与 SecVulEval/PrimeVul 的大规模结论正面冲突。

### 6.4 建议的 prompt schema

M1（直接分类）：

```json
{
  "is_vulnerable": true,
  "confidence": 0.0,
  "cwe": "CWE-000",
  "evidence": ["short quote or line reference"],
  "reason": "one or two sentences"
}
```

M2（结构化推理）：

```json
{
  "summary": "what the function does",
  "security_sensitive_operations": ["..."],
  "dataflow_or_bounds_reasoning": "how inputs reach sensitive operations",
  "is_vulnerable": true,
  "confidence": 0.0,
  "cwe": "CWE-000",
  "evidence": ["..."],
  "reason": "why the evidence supports the verdict"
}
```

M3（成对差分）：

```json
{
  "more_vulnerable": "A",
  "changed_behavior": "what changes between A and B",
  "evidence": ["..."],
  "confidence": 0.0
}
```

约束：

- `more_vulnerable` 只允许 `A`、`B`、`both`、`neither`：`both` 对应 P-V，`neither` 对应 P-B；`A`/`B` 需要结合随机化后的真实标签判断，方向正确为 P-C，方向错误为 P-R。
- A/B 顺序随机；每个对跑两种顺序，报告顺序一致性。
- 代码放在明确的分隔符中，并声明“以下内容是待分析数据，不是指令”，降低注释注入风险。
- 输出必须是 JSON；用 `response_format={"type":"json_object"}`；解析失败/空内容重试并记录。
- 不在 prompt 中包含 `is_vulnerable`、`fixed_func_idx`、`cve_list`、`cwe_list`、`changed_lines`、`changed_statements`、`commit_message`、`hash`、`idx`、`project`、`filepath`、`func_name`。主实验只给函数体/签名；`context` 只用于单独 ablation。

### 6.5 建议的实验流程

1. **冻结数据与输入**：读取两个 JSON；确认 200/200 条；生成输入哈希；不在运行时改动数据。
2. **Pilot**：每个方法跑 5–10 条（覆盖 TP/FP/FN/TN 和 P-C/P-V/P-B/P-R），检查 JSON 解析、token 用量、延迟、空输出、截断。
3. **主实验**：M1/M2 跑 200 独立 + 400 配对函数；M3 跑 200 对 × 2 顺序；每方法至少 1 轮，建议 3 轮估计稳定性（若预算允许）。
4. **解析与质控**：JSON 解析失败率、重试次数、空输出率；记录原始响应与请求 ID；对无法解析的样本单独报告，不静默丢弃。
5. **统计**：独立集 bootstrap 95% CI；配对集按对 bootstrap；方法间 McNemar；多重比较 Holm 校正；报告 exact counts。
6. **人工审查**：按结果分层抽 60 条（每方法 20 条，覆盖 TP/FP/FN/TN/P-V/P-R）；两名标注者盲评；Cohen's kappa；分歧仲裁。
7. **定性分析**：每个方法选 6–8 个案例（成功、失败、顺序敏感、高置信错误、解析失败）；引用短代码片段；对照 `changed_statements` 做 post-hoc 分析（不作为输入）。
8. **成本**：记录 prompt/completion/reasoning tokens、总费用、平均延迟、重试次数；按官方价格计算，不凭估算写“实际成本”。
9. **报告**：方法、数据、prompt、模型版本、解码参数、所有结果（含失败）、限制、伦理/泄漏检查。

### 6.6 报告表格建议

| 表 | 内容 |
|---|---|
| 表 1 | 数据集组成（独立集/配对集；标签、项目、CWE 分布） |
| 表 2 | 三种方法的输入/推理/输出/调用量/成本 |
| 表 3 | 独立集：P/R/F1/FPR/MCC + 95% CI |
| 表 4 | 配对集：P-C/P-V/P-B/P-R + 95% CI |
| 表 5 | 方法间 McNemar p 值 / 效应量 |
| 表 6 | 按 CWE/项目的描述性 breakdown（仅 n≥10 的类别） |
| 表 7 | 成本：tokens、美元、延迟、重试 |
| 表 8 | 定性案例：输入摘要、模型输出、错误类型、人工判断 |

### 6.7 统计与解释注意事项

- **不要把 400 条配对函数当 400 个独立样本**；它们来自 200 对，必须按对聚类/重采样。
- **不要用 VD-S**：本项目的独立集是人为 80% 漏洞比例，不是真实低 prevalence；VD-S 的 FPR 预算假设不成立。报告 FPR/TPR 和配对指标更合适。
- **不要只报 accuracy**：80/20 不平衡下，全判 vulnerable 就有 80% accuracy；必须报 precision/recall/F1/FPR/MCC。
- **不要忽略解析失败**：JSON 空输出/截断如果被当作 negative，会系统性改变结果；必须单独报告并做敏感性分析。
- **不要过度解读小差异**：200 条独立样本、40 条负样本、200 对，置信区间较宽；方法间差异小于 CI 时不要宣称优劣。
- **不要隐藏提示/模型版本**：API 模型会更新；必须记录 `model` 返回字段、调用日期、thinking 设置、max_tokens、重试策略。

---

## 7. 引用清单

> 说明：以下条目均在 2026-11-11 核对过 DOI/arXiv/官方页面；A/B/C 为证据级别。建议的 BibTeX key 仅供父代理合并 `references.bib` 时参考；本文件未修改该文件。

| # | 引用 | 级别 | DOI/URL | 建议 key |
|---|---|---|---|---|
| [1] | M. B. U. Ahmed, N. S. Harzevili, J. Shin, H. V. Pham, S. Wang. *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection.* AIware 2026, pp. 388–396. | A | https://doi.org/10.1145/3805760.3814932 | `ahmed2026secvuleval` |
| [2] | Y. Ding, Y. Fu, O. Ibrahim, C. Sitawarin, X. Chen, B. Alomair, D. Wagner, B. Ray, Y. Chen. *Vulnerability Detection with Code Language Models: How Far are We?* ICSE 2025, pp. 1729–1741. | A | https://doi.org/10.1109/ICSE55347.2025.00038 | `ding2025primevul` |
| [3] | Y. Chen, Z. Ding, L. Alowain, X. Chen, D. Wagner. *DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection.* RAID 2023, pp. 654–668. | A | https://doi.org/10.1145/3607199.3607242 | `chen2023diversevul` |
| [4] | J. Fan, Y. Li, S. Wang, T. N. Nguyen. *A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries.* MSR 2020, pp. 508–512. | A | https://doi.org/10.1145/3379597.3387501 | `fan2020bigvul` |
| [5] | G. Bhandari, A. Naseer, L. Moonen. *CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software.* PROMISE 2021, pp. 30–39. | A | https://doi.org/10.1145/3475960.3475985 | `bhandari2021cvefixes` |
| [6] | J. He, M. Vechev. *Large Language Models for Code: Security Hardening and Adversarial Testing.* CCS 2023, pp. 1865–1879. | A | https://doi.org/10.1145/3576915.3623175 | `he2023sven` |
| [7] | N. Risse, M. Böhme. *Uncovering the Limits of Machine Learning for Automatic Vulnerability Detection.* USENIX Security 2024. | A | https://www.usenix.org/conference/usenixsecurity24/presentation/risse | `risse2024limits` |
| [8] | N. Risse, J. Liu, M. Böhme. *Top Score on the Wrong Exam: On Benchmarking in Machine Learning for Vulnerability Detection.* PACMSE 2(ISSTA), pp. 388–410, 2025. | A | https://doi.org/10.1145/3728887 | `risse2025topscore` |
| [9] | Z. Gao, H. Wang, Y. Zhou, W. Zhu, C. Zhang. *How Far Have We Gone in Vulnerability Detection Using Large Language Models.* arXiv:2311.12420, 2023. | B | https://arxiv.org/abs/2311.12420 | `gao2023vulbench` |
| [10] | Y. Sun, D. Wu, Y. Xue, H. Liu, W. Ma, L. Zhang, Y. Liu, Y. Li. *LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs' Vulnerability Reasoning.* arXiv:2401.16185, 2024 (v4 2025). | B | https://arxiv.org/abs/2401.16185 | `sun2024llm4vuln` |
| [11] | X. Du, G. Zheng, K. Wang, Y. Zou, Y. Wang, W. Deng, J. Feng, M. Liu, B. Chen, X. Peng, T. Ma, Y. Lou. *Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG.* TOSEM 35(10):1–25, 2026. | A | https://doi.org/10.1145/3797277 | `du2026vulrag` |
| [12] | B. Steenhoek, M. M. Rahman, S. Sharmin, W. Le. *Do Language Models Learn Semantics of Code? A Case Study in Vulnerability Detection.* arXiv:2311.04109, 2023. | B | https://arxiv.org/abs/2311.04109 | `steenhoek2023semantics` |
| [13] | Y. Guo, C. Patsakis, Q. Hu, Q. Tang, F. Casino. *Outside the Comfort Zone: Analysing LLM Capabilities in Software Vulnerability Detection.* ESORICS 2024, LNCS, pp. 271–289. | A | https://doi.org/10.1007/978-3-031-70879-4_14 | `guo2024outside` |
| [14] | Z. Li, S. Dutta, M. Naik. *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities.* ICLR 2025. | B | https://arxiv.org/abs/2405.17238 | `li2025iris` |
| [15] | J. Guo, C. Wang, X. Xu, Z. Su, X. Zhang. *RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing.* ICML 2025. | B | https://arxiv.org/abs/2501.18160 | `guo2025repoaudit` |
| [16] | Z. Sheng, Z. G. Chen, S. Gu, H. Huang, G. Gu, J. Huang. *LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights.* ACM CSUR 58(5):1–35, 2025. | A | https://doi.org/10.1145/3769082 | `sheng2025llmsec` |
| [17] | L. Gazzola, D. Micucci, L. Mariani. *Automatic Software Repair: A Survey.* IEEE TSE 45(1):34–67, 2019. | A | https://doi.org/10.1109/TSE.2017.2755013 | `gazzola2019apr` |
| [18] | E. K. Smith, E. T. Barr, C. Le Goues, Y. Brun. *Is the Cure Worse Than the Disease? Overfitting in Automated Program Repair.* ESEC/FSE 2015, pp. 532–543. | A | https://doi.org/10.1145/2786805.2786825 | `smith2015overfitting` |
| [19] | Z. Qi, F. Long, S. Achour, M. Rinard. *An Analysis of Patch Plausibility and Correctness for Generate-and-Validate Patch Generation Systems.* ISSTA 2015, pp. 24–36. | A | https://doi.org/10.1145/2771783.2771791 | `qi2015plausibility` |
| [20] | H. Ye, M. Martinez, M. Monperrus. *Automated Patch Assessment for Program Repair at Scale.* EMSE 26(2):20, 2021. | A | https://doi.org/10.1007/s10664-020-09920-w | `ye2021patchassessment` |
| [21] | Z. Fei, J. Ge, C. Li, T. Wang, Y. Li, H. Zhang, L. Huang, B. Luo. *Patch Correctness Assessment: A Survey.* TOSEM 34(2):55:1–55:50, 2025. | A | https://doi.org/10.1145/3702972 | `fei2025patchsurvey` |
| [22] | Y. Hu, Z. Li, K. Shu, S. Guan, D. Zou, S. Xu, B. Yuan, H. Jin. *SoK: Automated Vulnerability Repair: Methods, Tools, and Assessments.* arXiv:2506.11697, 2025. | B | https://arxiv.org/abs/2506.11697 | `hu2025sokavr` |
| [23] | Z. Yu, W. Shi, X. Sun, Z. Feng, M. Xu, X. Xing. *Patch Validation in Automated Vulnerability Repair.* arXiv:2603.06858, 2026. | B | https://arxiv.org/abs/2603.06858 | `yu2026pvbench` |
| [24] | W. Wang, W. Ma, Q. Hu, Y. Zhang, J. Sun, B. Wu, Y. Liu, G. Xu, L. Jiang. *VulnRepairEval: An Exploit-Based Evaluation Framework for Assessing Large Language Model Vulnerability Repair Capabilities.* arXiv:2509.03331, 2025. | B | https://arxiv.org/abs/2509.03331 | `wang2025vulnrepaireval` |
| [25] | X. Mei, J. Del Castillo, P. S. Singaria, H. Xi, A. Benchikh, T. Bao, R. Wang, Y. Shoshitaishvili, A. Doupé, H. Pearce, B. Dolan-Gavitt. *ARVO: Atlas of Reproducible Vulnerabilities for Open-Source Software.* arXiv:2408.02153, 2024. | B | https://arxiv.org/abs/2408.02153 | `mei2024arvo` |
| [26] | T. J. Byun, C. Aschermann, K. Y. Thng, W. Zhou, Y. Yang, L. Deason, J. Saxe. *Introducing AutoPatchBench: A Benchmark for AI-Powered Security Fixes.* Meta Engineering, Apr. 2025. | C | https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/ | `byun2025autopatchbench` |
| [27] | C. E. Jimenez, J. Yang, A. Wettig, S. Yao, K. Pei, O. Press, K. Narasimhan. *SWE-bench: Can Language Models Resolve Real-World GitHub Issues?* ICLR 2024. | B | https://arxiv.org/abs/2310.06770 | `jimenez2024swebench` |
| [28] | Q. Zhang, C. Fang, Y. Ma, W. Sun, Z. Chen. *A Survey of Learning-based Automated Program Repair.* TOSEM 33(2):1–69, 2023. | A | https://doi.org/10.1145/3631974 | `zhang2023aprsurvey` |
| [29] | Q.-C. Bui, R. Scandariato, N. E. Díaz Ferreyra. *Vul4J: A Dataset of Reproducible Java Vulnerabilities Geared Towards the Study of Program Repair Techniques.* MSR 2022, pp. 464–468. | A | https://doi.org/10.1145/3524842.3528482 | `bui2022vul4j` |
| [30] | DeepSeek-AI. *DeepSeek-Coder: When the Large Language Model Meets Programming — The Rise of Code Intelligence.* arXiv:2401.14196, 2024. | B | https://arxiv.org/abs/2401.14196 | `deepseek2024coder` |
| [31] | DeepSeek-AI. *DeepSeek-Coder-V2: Breaking the Barrier of Closed-Source Models in Code Intelligence.* arXiv:2406.11931, 2024. | B | https://arxiv.org/abs/2406.11931 | `deepseek2024coderv2` |
| [32] | DeepSeek-AI. *DeepSeek-V4: Towards Highly Efficient Million-Token Context Intelligence.* arXiv:2606.19348, 2026. | B | https://arxiv.org/abs/2606.19348 | `deepseek2026v4` |
| [33] | DeepSeek. *Models & Pricing.* DeepSeek API Docs, accessed 2026-11-11. | C | https://api-docs.deepseek.com/quick_start/pricing/ | `deepseek2026pricing` |
| [34] | DeepSeek. *JSON Output.* DeepSeek API Docs, accessed 2026-11-11. | C | https://api-docs.deepseek.com/guides/json_mode | `deepseek2026json` |
| [35] | DeepSeek. *Thinking Mode.* DeepSeek API Docs, accessed 2026-11-11. | C | https://api-docs.deepseek.com/guides/thinking_mode | `deepseek2026thinking` |
| [36] | DeepSeek. *DeepSeek-V4-Pro Model Card.* Hugging Face, 2026. | C | https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro | `deepseek2026v4card` |
| [37] | DeepSeek. *DeepSeek-Coder-V2-Instruct Model Card.* Hugging Face, 2024. | C | https://huggingface.co/deepseek-ai/DeepSeek-Coder-V2-Instruct | `deepseek2024coderv2card` |
| [38] | arag0rn. *SecVulEval Dataset Card.* Hugging Face, 2026. | C | https://huggingface.co/datasets/arag0rn/SecVulEval | `secvulevaldata` |

### 7.1 建议在正文中使用的引用组合

- **数据与基准**：[1], [2], [3], [7], [25]。
- **LLM 方法**：[9], [10], [11], [13], [14], [15]。
- **评估有效性/标签质量**：[2], [8], [12], [13]。
- **配对评估**：[2], [7], [11]。
- **APR 质量**：[17]–[26], [28]。
- **DeepSeek**：[30]–[37]。

### 7.2 不建议引用的内容

- 没有 DOI/正式出处的博客、二手总结、模型排行榜截图，除非作为 C 级厂商资料并明确标注。
- 声称“某模型在 SecVulEval 上达到 X%”但未给出模型版本、prompt、指标口径的二手数字。
- 把 DeepSeek-V4 的通用编码 benchmark 说成“漏洞检测性能”。
- 把 VulnPatchPairs 的 26.2k 函数说成 26.2k 对（实际 13.1k 对）。
- 把 PrimeVul 的 5,480 对说成 7,768 对（后者不是该论文的数字）。

---

## 8. 检索与核验记录

### 8.1 主要检索来源

- arXiv：摘要/HTML 全文（SecVulEval、PrimeVul、Vul-RAG、LLM4Vuln、VulBench、ARVO、PVBench、VulnRepairEval、DeepSeek 系列）。
- ACM Digital Library / DOI：SecVulEval、PrimeVul、DiverseVul、BigVul、CVEfixes、SVEN、Top Score、Vul-RAG、Fei 等。
- USENIX：Risse & Böhme 2024。
- OpenAlex / Crossref：DOI、页码、卷期、作者核对。
- 官方模型卡/文档：DeepSeek API pricing、JSON Output、Thinking Mode、DeepSeek-V4-Pro、DeepSeek-Coder-V2-Instruct。
- 官方工件：SecVulEval HF/GitHub、PrimeVul GitHub、VPP GitHub、RepoAudit GitHub。

### 8.2 关键数字的二次核对

| 数字 | 来源 | 核对结果 |
|---|---|---|
| PrimeVul 6,968 / 228,800 / 140 CWE | 论文摘要 + Table III | 一致 |
| PrimeVul 5,480 对（4,354/562/564） | 论文 Table III + 第 IV-B2 节 | 一致 |
| PrimeVul ICSE 2025 pp. 1729–1741 | Crossref DOI | 一致 |
| SecVulEval 25,440 / 5,867 / 707 / 145 | 论文摘要 + Table 2 | 一致 |
| SecVulEval 10,998 / 14,442 | 论文 Table 2 + 项目 README | 一致 |
| SecVulEval 23.83% 语句级 F1 | 论文 Table 3 + 摘要 | 一致 |
| SecVulEval AIware 2026 pp. 388–396 | ACM DOI / Crossref | 一致 |
| VulnPatchPairs 26.2k 函数 / 13.1k 对 | arXiv HTML 第 4 节 | 一致 |
| DeepSeek V4 1.6T/49B、284B/13B、1M | 官方模型卡 + arXiv | 一致 |
| DeepSeek API 价格/版本 | 官方 pricing 页 | 一致（2026-11-11 快照） |

### 8.3 不确定/需要后续确认的点

1. **SecVulEval 正式版与 arXiv v1 的差异**：正式标题不同；正式版可能补充了实验/附录。本文件的方法细节取自 arXiv v1，引用正式版 DOI；若报告需要精确到正式版页码，建议再读 ACM PDF。
2. **PrimeVul 正式版与 arXiv v2 的差异**：arXiv v2 备注“camera-ready work in progress”；正式版可能有小幅修订。本文件使用 arXiv v2 的数字，均与摘要/Table III 一致。
3. **ARVO 的数字随版本变化**：arXiv v2 摘要说 6,100+ 漏洞、311 个项目、81% 复现、89.4% 补丁定位；部分二手资料说 5,651/5,001。引用时以 arXiv v2 为准并注明版本。
4. **DeepSeek V4.1-Flash 没有单独论文**：官方模型卡覆盖 V4 系列；API 版本号来自 pricing 页。报告应写“API 别名 + 底层版本”，不要写“V4.1 论文”。
5. **AutoPatchBench 是厂商博客/基准文档**：136 个案例、11 种 crash 类型来自 Meta 官方博客；若需要同行评审细节，应查 CyberSecEval 4 文档/代码。
6. **2026 年预印本可能更新**：PVBench、SoK AVR、VulnRepairEval 等均为 arXiv；引用时标注“preprint”，不要写成正式发表。

### 8.4 本调研没有做的事

- 没有运行任何模型/API；没有本项目实验结果。
- 没有复现 PrimeVul/SecVulEval/Vul-RAG 的实验。
- 没有做系统综述式的全量筛选（PRISMA）；这是定向调研。
- 没有覆盖中文文献、专利、工业报告。
- 没有修改 `proposal/references.bib`、数据文件、脚本或其他共享文件。

---

## 9. 建议的下一步

1. **父代理确认方法矩阵**：优先 M1/M2/M3；若时间不足，至少 M1 + M3（直接分类 + 配对差分），仍满足“2 种方法”。
2. **准备 API 凭证**：通过环境变量提供；不要写入仓库/日志；先跑 5–10 条 pilot，确认 JSON 解析、thinking token、成本。
3. **冻结 prompt 与模型版本**：把 prompt、模型别名、底层版本、thinking 设置、max_tokens、重试策略写入配置；所有方法共用。
4. **先做小规模人工审查**：20–30 条，确认“漏洞/非漏洞”的判断标准与数据集标签一致；如果人工与标签分歧大，先讨论标签口径，不要直接跑全量。
5. **全量运行与统计**：按第 6.5 节流程；报告 exact counts、CI、McNemar、成本、失败率。
6. **写作**：把第 2–4 节的引用与方法借鉴写进 related work；把第 6 节写成 methods；把第 8 节的限制写进 threats to validity。
7. **如果课程要求 APR 质量**：另开一个小节/小实验，用 ARVO/Vul4C/AutoPatchBench 的 10–20 个可执行案例；不要把本项目 200 对 JSON 说成 APR 评估。

---

## 10. 一句话总结

**SecVulEval 提供的是“语句级 + 上下文”的 C/C++ 漏洞数据；PrimeVul 提供的是“高质量标签 + 配对评估 + VD-S”的评估范式；VulnPatchPairs/Vul-RAG 证明“漏洞 vs 修复”对 LLM 仍然很难；APR 社区则证明“测试通过”远不等于“补丁正确”。本项目最有价值且可执行的定位，是在 SecVulEval 的 600 条记录上，用同一模型比较直接分类、结构化推理、成对差分三种 prompting 方法，并诚实报告配对指标、成本与“不能声称补丁正确”的限制。**

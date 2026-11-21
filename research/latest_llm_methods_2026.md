# 2025–2026 最新 LLM 漏洞检测与 Agentic 方法：可迁移到本项目的证据清单

**文件**：`research/latest_llm_methods_2026.md`  
**调研日期**：2026-11-13（Asia/Shanghai）  
**检索窗口**：2025-01-01 至 2026-11-13；少量 2023–2024 年方法是理解 2025–2026 工作的必要背景，单独标注。  
**范围**：C/C++ 漏洞检测、代码库级上下文、工具使用与 agentic 审计、自一致性/测试时采样、约束解码与结构化输出、验证反馈、漏洞定位、漏洞修复与配对判别。  
**证据边界**：本文件只做文献调研与实验设计，**没有发起任何 API 请求，没有运行任何模型，没有修改 `runner/`、`datasets/`、`splits/`、`report/` 或任何既有 run**。文中所有“本项目”数字都直接引自现有报告（`report/results_summary.md`、`research/improvement_opportunities.md`、`research/innovation_findings.md`、`pair_joint/report.md`、`evidence_prompt/analysis/report.md`、`juliet_repair/report/comparison.md`），未重算、未改写。  
**引用约定**：`[A#]` = 正式发表（有 DOI/会议页/可核验 proceedings）；`[B#]` = arXiv 预印本（元数据已核对，未必同行评审）；`[C#]` = 官方文档/工具/厂商博客；`[P]` = 本项目实测。完整核验表见 §10。

> **日期化状态注记（2026-11-14）**
>
> **写作时状态（2026-11-13）**：**P0–P7 / E1–E9 均为建议与实验设计，不是当时的结果**。P0–P7 见本文 §9；E1–E9 见 `research/latest_evaluation_repair_2026.md` §12。写作时没有运行这些实验，也没有修改旧结果。
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
> 以上只更新执行状态；正文的 P0–P7 建议、引用与 2026-11-13 的数字保持不变。

---

## 0. 结论摘要

1. **低召回的主矛盾不是“模型不够会写 prompt”，而是“发现”和“裁决”被压在同一次二分类里。** 2025–2026 的强方法几乎都把任务拆成两段：高召回地找候选（敏感操作、语句、入口点、数据流事实），再用上下文/工具/验证器裁决（VulAgent、SBVul、RepoAudit、VulnAgent-R2、Revelio）。这正好对应当前 FN 中位 35 行、TP 中位 76–78 行的结构：短函数被“看起来简单”直接判安全。
2. **标签噪声必须先量化，否则“召回”不可解释。** VulValidate 对 BigVul/PrimeVul/DiverseVul 全部 35,849 条“漏洞”标签做可执行证据审计：确认 57.2%，**改正 19.0%**，22.3% 无法裁决，1.5% 无法测量；用改正标签后，五个检测器的 F1 全部下降。本项目 FN 里可能有一部分是标签/提交级传播问题，不应全部记作模型漏报。
3. **联合 A/B 的 76.67%/86.67% 不能与文献的 26.6%/42.0% 直接比较。** 文献的 26.6%（VulAgent P-C）、42.0%（SBVul pair）是“分别判断两个函数再配对”的口径；本项目是“同一次请求强制二选一”。更关键的是：本项目已实测“选较短版本”这一条不看语义的规则就有 **74.44%**，DeepSeek 的 76.67% 与它统计上不可区分（p=0.66），且 DeepSeek 有明显 A 位置偏差（A 侧 92.22% vs B 侧 61.11%，差 31.11 pp，Fisher p=1.0e-06）。**当前联合结果主要是任务框架 + 长度先验 + 位置偏差的复合效应，不能写成跨版本推理能力。**
4. **schema 失败主要是可回收的工程问题。** DeepSeek 三策略的 924 条修复请求中 102 条（11.0%）schema 无效；其中 **93 条只是缺 `explanation`**，`fixed_function` 仍在，91 条结构完整，71 条有实质改动。严格校验把这 71 条可用补丁丢掉了。这不是“模型不会修”，而是 JSON mode 不保证字段齐全 + 解析器把“缺可选字段”当“整条无效”。官方文档也明确：JSON mode 只保证合法 JSON，Structured Outputs 才保证 schema adherence `[C1][C2]`。
5. **无改动修复不是本数据集独有的怪现象。** AutoPatchBench 报告约 60% 的补丁能通过“编译 + 原崩溃输入不再触发”，但经过 fuzzing + 白盒差分测试后只有 **5–11%** 正确；模型会“作弊”式地压掉崩溃而不修根因 `[C7]`。PatchBench 进一步发现 25% 的 agent 补丁与历史开发者补丁高度相似，且只用 PoC 验证会把 solve rate 平均抬高 **1.83×** `[B13]`。本项目 22.1%/44.5%/18.8% 的无实质改动，和这些现象是同一类失败。
6. **工具使用有效，但不是“加一个 agent 就涨点”。** IRIS 把 CodeQL 在 CWE-Bench-Java 上的检出从 27/120 提到 55/120；RepoAudit 在 15 个真实项目上以 78.43% 精确率找到 40 个真 bug，平均 0.44 小时/$2.54 每项目；KNighter 用历史补丁合成 checker，在 Linux 内核发现 92 个新 bug（77 确认、57 修复、30 CVE）；ARQ 用执行反馈改 CodeQL 查询，真阳性最多 +119.8%，精确率 ≥98%；Revelio 用可执行 PoV + sanitizer，在 7 个长期 fuzz 的项目里发现 19 个未知内存安全漏洞，总成本约 $300。代价是工程与调用成本；本项目在 Juliet 上已经看到 ceiling，工具证据的边际收益必须在**真实项目子集**上重新测。
7. **代码库级上下文不是“把更多代码塞进 prompt”。** ContextBench 的结论很冷静：复杂 agent scaffolding 对上下文检索只有边际提升（“The Bitter Lesson”），LLM 一致地重召回轻精确，且“探索到的上下文”和“真正用到的上下文”之间有很大缺口 `[B4]`。VulnGym 的最强组合（DeepSeek-V4-Flash + OpenHands）在 Hard 子集上也只有 22.58% advisory recall、15.22% entry recall、11.63% edit similarity `[B2]`。先做“行号化 + 依赖切片 + 匹配上下文对照”，不要直接上全库 agent。
8. **自一致性在漏洞检测上可能是负收益。** PromptAudit 在 1,000 个 CVE、6,074 个样本、16 种语言上发现：标准 CoT 整体最好；few-shot 依模型而异；**adaptive CoT 经常压低召回，self-consistency 引发过度 abstention，显著降低有效性能** `[B17]`。Large Language Monkeys 则说明：重复采样的**覆盖率**随样本数对数线性增长，但多数投票/奖励模型在几百个样本后饱和 `[B18]`。对本项目的含义：不要用“多次采样 + 多数投票”直接提高召回；应当“多采样 + 证据/工具验证”，并单独报告 abstention 与 coverage。
9. **约束解码解决“格式”，不解决“语义”。** JSONSchemaBench 用 10K 个真实 schema 评估 6 个引擎，说明不同引擎在效率、约束覆盖、输出质量上差异明显 `[A16]`；XGrammar 把 CFG 约束的开销降到接近零 `[A17]`；SynCode 消除全部 JSON 语法错误、把 Python/Go 语法错误减少 96.07% `[A18]`。但 “Let Me Speak Freely” 发现格式限制会降低推理，约束越严越明显 `[A19]`；“Constrained Decoding: Harmful or Beneficial?” 进一步把退化拆成“非等价 prompt/输出格式”与“decoder masking”，并指出 validity constraint 提升可靠性、reasoning constraint 才可能提升准确率 `[B15]`；“The Calibration Floor” 更直接：很多“self-correction”收益其实是 **format repair**，用 grammar-constrained decoding 让答案都可解析后，会解释掉中位 **71%** 的“表观总效应与内容效应之差” `[B14]`。
10. **最高优先级的下一步不是换模型，而是修测量。** 先做 P0（不改 prompt、不调 API，只重算现有 102 条 invalid 的 usable-patch yield 和 schema/format 分解），再做 P1（180 对 A/B + B/A 双顺序，报告平均 DA、flip rate、长度分层），最后才考虑 P4/P5 的工具/修复闭环。具体矩阵见 §9。

---

## 1. 检索、核验与证据分级

### 1.1 检索方法

- **论文发现**：arXiv API（`export.arxiv.org/api/query`）按 `abs:"vulnerability detection" AND abs:agent`、`abs:"vulnerability repair" AND abs:agent`、`abs:"constrained decoding" AND abs:code`、`abs:"position bias" AND abs:LLM` 等查询按提交日期倒序抓取；再用 ACL Anthology、DOI/Crossref、PMLR、USENIX、NeurIPS 页面核对正式出处。
- **引用链**：从 2026 年论文的 related work 反向追踪高相关条目（例如从 ESEM 2026 的参考文献找到 LLMxCPG、Vul-RAG 等）。
- **官方工具**：OpenAI Structured Outputs、DeepSeek JSON Output、vLLM structured outputs、CodeQL、Semgrep、AddressSanitizer/LeakSanitizer、XGrammar、AutoPatchBench 官方博客。
- **浏览器说明**：本次 Kimi 内置浏览器持续返回 `ERR_PROXY_CONNECTION_FAILED`，无法用浏览器直接打开页面；改用 `FetchURL` 抓取 arXiv abs/HTML、ACL Anthology、DROPS、USENIX、官方文档，用 `WebSearch` 做发现，用 Crossref API 核对 DOI。此限制不影响下文的 URL/DOI 核验，但意味着没有做“浏览器渲染后的页面截图”级复核。

### 1.2 纳入与排除

**纳入**：
- 2025-01-01 至 2026-11-13 的正式论文或预印本；
- 主题必须是 LLM/agent 与代码安全（检测、定位、修复、配对评估、结构化输出、位置偏差）之一；
- 有可核验的 arXiv ID、DOI、会议页或官方文档 URL；
- 能提取出对本项目四个失败模式之一有直接作用的方法或负面证据。

**排除**：
- 纯渗透测试/CTF 攻击能力、纯恶意软件分析、纯智能合约（除非方法可迁移且给出明确机制）；
- 只有二手博客数字、无法回溯到论文/官方页面的条目；
- 与本项目问题无关的通用 agent 论文（如只讨论工具调用框架、没有安全任务证据）；
- 2024 年及以前的“最新”方法，除非是理解 2025–2026 工作的必要基线（如 Self-Consistency、Semantic Entropy、Agentless）。

### 1.3 证据分级

| 级别 | 定义 | 本文件中的使用 |
| --- | --- | --- |
| **A** | 正式发表，有会议/期刊页、DOI 或可核验的官方 proceedings 页；元数据已核对 | 可作为“文献事实”引用；但仍保留论文自己的实验边界 |
| **B** | arXiv 预印本，元数据已核对，未必同行评审 | 只作为“方向/机制/待复现证据”，不当作定论 |
| **C** | 官方文档、工具页、厂商博客 | 只用于“接口/保证/限制”，不用于能力比较 |
| **P** | 本项目现有实测结果 | 作为项目事实；不重新解释为文献结论 |

> **编号说明**：§3–§8 的方法卡片编号（A1–A9、B1–B4、C1–C4、E1–E6、F1–F6）是**方法卡片编号**，不带方括号；文献引用一律写成 `[A1]`、`[B1]`、`[C1]`。两套编号独立，避免混淆。

**核验口径**：
- 正式论文：核对标题、作者、会议/期刊、年份、页码或 DOI；页码/DOI 不可得时明确写“仅会议页/arXiv”。
- 预印本：核对 arXiv ID、v1 提交日期、最新版本日期；文中引用数字以摘要或正文明确给出者为准。
- 官方文档：记录访问日期（2026-11-13）与页面标题；不把厂商 benchmark 当作独立研究。
- **不编造**：没有页码就不写页码；没有看到正文的数字就不写；二手转述的数字一律回到论文/官方页核对，核不到就删除。

---

## 2. 与本项目失败模式的映射

### 2.1 四个主问题（本项目实测）

| 问题 | 本项目实测 | 关键结构 | 直接后果 |
| --- | --- | --- | --- |
| **低召回** | 独立集 160 条（128 漏洞/32 非漏洞）：M1 29.7%、M2 32.0%、M3 30.5%；FN 87–90/128；FN 中位 35 行，TP 中位 76–78 行 | 单次二分类；无语句级候选；无工具证据；短函数被“看起来安全”覆盖 | 漏报是主矛盾；精确率 0.81–0.84 不是主要问题 |
| **pair 位置偏差** | 联合 A/B：DeepSeek DA 76.67%、MiMo 86.67%；但“选较短版本”启发式 74.44%；DeepSeek A 侧 92.22% vs B 侧 61.11%（31.11 pp，p=1.0e-06），选 A 118/180 | 每对一次请求、强制 A/B；A/B 只随机一次，没有 B/A 重复；长度未匹配 | 不能区分“跨版本推理”“长度先验”“first-position bias” |
| **schema 错误** | DeepSeek 三策略 924 条修复请求中 102 条（11.0%）invalid；93 条只缺 `explanation`；91 条结构完整；71 条有实质改动 | `response_format=json_object`，不是 `json_schema`；解析器要求键集合完全相等 `validation.py:88` | 把可用补丁判废；修复指标被 schema 口径主导 |
| **无改动修复** | M1 22.1%、M2 44.5%、M3 18.8% 无实质改动；few-shot “changed” 62.6% 中 23 条只是空白变化；盲评 VR=2 对无改动候选 0/23，对有实质改动候选 17/58（29.3%） | 没有“必须改动”门；没有根因字段；没有编译/PoC；few-shot 可能鼓励复制 | 文本相似度 ≠ 修复正确率；22–45% 的“修复”是空操作 |

补充的定位事实（用于判断召回为什么低）：

| 指标 | 数值 | 含义 |
| --- | --- | --- |
| 证据行 `±3` 命中率 | 62.79% vs 随机 62.50%（DeepSeek）；63.64% vs 59.66%（MiMo） | 粗粒度“附近命中”几乎可由“引用足够多行”解释 |
| 引用行精确率 | 21.89% / 25.55% | 模型引用的行大多不是修复行 |
| 修复行 exact 召回 | 16.33% / 14.61% | 语句级定位很弱 |
| 证据提示召回 | 29.13%→38.58%（+9.45 pp） | 召回确实上升 |
| 证据提示 FPR | 25.00%→34.38%（+9.38 pp） | 但主要是操作点向“多报”移动 |
| 平衡准确率 / MCC | +0.0004 / −0.0020 | 判别力没有提升 |

这组数字是理解文献的锚点：**“召回上升”不等于“检测变好”**；必须同时看 FPR、平衡准确率、MCC 和定位精确率。

### 2.2 文献-问题矩阵

| 文献 | 类型 | 低召回 | pair 偏差 | schema | 无改动修复 | 定位 | 对本项目的主要用途 |
| --- | --- | :---: | :---: | :---: | :---: | :---: | --- |
| IRIS `[A3]` | A | ● | ○ | ○ | ○ | ○ | LLM 推断 taint spec + CodeQL，证明“神经符号”能提高召回 |
| RepoAudit `[A4]` | A | ● | ○ | ○ | ○ | ● | agent memory + 数据流事实 + validator，仓库级审计 |
| VulAgent `[A11]` | A | ● | ● | ○ | ○ | ● | 高召回多视图发现 → 假设（条件+路径）→ 验证；pair P-C +43% |
| VulnAgent-R2 `[B1]` | B | ● | ○ | ○ | ○ | ● | 图 triage、上下文预算、反事实证据重加权、验证计划、校准融合 |
| SBVul `[B5]` | B | ● | ● | ○ | ○ | ● | 语句级两阶段；Phase 1 定位 56–77%，Phase 2 确认 26–73% |
| Revelio `[B8]` | B | ● | ○ | ○ | ● | ● | 可执行 PoV + sanitizer；确认后才报告；成本可控 |
| ARQ `[B7]` | B | ● | ○ | ○ | ○ | ○ | 用执行反馈修 CodeQL 查询；真阳性 +119.8% |
| KNighter `[A5]` | A | ● | ○ | ○ | ○ | ○ | 从历史补丁合成 checker；可扩展静态分析 |
| LLMxCPG `[A7]` | A | ● | ○ | ○ | ○ | ○ | CPG 切片减 67.84–90.93% 代码，F1 +15–40% |
| Vul-RAG `[A14]` | A | ● | ● | ○ | ○ | ○ | 知识级 RAG；LLM 对“漏洞 vs 相似补丁”只有 0.06–0.14 |
| VulValidate `[B6]` | B | ● | ○ | ○ | ○ | ○ | 标签审计；19.0% 标签被改正；改正后 F1 下降 |
| ContextBench `[B4]` | B | ● | ○ | ○ | ○ | ● | 上下文检索的过程评估；scaffolding 边际收益 |
| VulnGym `[B2]` | B | ● | ○ | ○ | ○ | ● | 仓库级端到端 + 三个 oracle 子任务；最强 agent 22.58% AR |
| Lost in the End `[A13]` | A | ● | ○ | ○ | ○ | ● | 文件内位置效应；调整输入大小平均召回 +37% |
| PromptAudit `[B17]` | B | ● | ○ | ○ | ○ | ○ | CoT 最好；SC 过度 abstention；adaptive CoT 压低召回 |
| ConfColl `[A12]` | A | ● | ○ | ○ | ○ | ○ | 置信度门控的三阶段升级（单 agent → RAG → 多 agent） |
| JSONSchemaBench `[A16]` | A | ○ | ○ | ● | ○ | ○ | 约束解码引擎评估；schema 覆盖/质量差异 |
| XGrammar `[A17]` | A | ○ | ○ | ● | ○ | ○ | 高效 CFG 约束；近零开销 |
| SynCode `[A18]` | A | ○ | ○ | ● | ○ | ○ | 语法约束；消除 JSON 语法错误 |
| Let Me Speak Freely `[A19]` | A | ○ | ○ | ● | ○ | ○ | 格式限制降低推理；越严越差 |
| Constrained Decoding `[B15]` | B | ○ | ○ | ● | ○ | ○ | 区分 format/validity/reasoning 约束 |
| Calibration Floor `[B14]` | B | ○ | ○ | ● | ● | ○ | format repair 伪装成 self-correction；G-CD 关掉 71% 表观增益 |
| AutoPatchBench `[C7]` | C | ○ | ○ | ○ | ● | ● | 60% 生成、5–11% 正确；cheating；根因可能在栈外 |
| PatchBench `[B13]` | B | ○ | ○ | ○ | ● | ● | 25% 记忆；PoC-only 抬高 1.83×；表面修复 |
| PatchEval `[B9]` | B | ○ | ○ | ○ | ● | ● | 1,000 CVE/65 CWE/230 sandbox；修复评估 |
| ExploreRepair `[B10]` | B | ○ | ○ | ○ | ● | ● | 多解释探索 + 聚合；DeepSeek-V4.1-Flash 71.6% |
| EviRepair `[B11]` | B | ○ | ○ | ○ | ● | ● | 证据审查；PatchEval +16.37% |
| AgenticRepair `[B12]` | B | ○ | ○ | ○ | ● | ● | 三类上下文工程；SEC-bench 73% |
| RepairAgent `[A9]` | A | ○ | ○ | ○ | ● | ● | 自主 agent 循环：定位→分析→修→验证 |
| Agentless `[A10]` | A | ○ | ○ | ○ | ● | ● | 简单三阶段（定位/修复/验证）反而强且便宜 |
| Position Bias `[B16]` | B | ○ | ● | ○ | ○ | ○ | 位置偏差；规模/CoT 缓解；thinking 模型近免疫 |
| EACL Code Judges `[A20]` | A | ○ | ● | ○ | ○ | ○ | 代码 judge 对表面变化敏感；生成测试也挡不住 |

● = 直接相关；○ = 间接/不相关。

### 2.3 三条最重要的判断

**判断 1：本项目的主要瓶颈是“测量有效性”，不是“模型选择”。**  
联合 A/B 的 76.67% 与文献的 26.6%/42.0% 差距过大，第一反应不应该是“我们更强”，而应该是“任务/口径/先验不同”。项目自己已经找到长度启发式 74.44% 和 A 偏差 31.11 pp；这两个数字足以解释大部分表观增益。**在修好这两件事之前，任何新模型/新 prompt 的 pair 提升都不可解释。**

**判断 2：文献的绝对数字很低，不能拿“80% 召回”当目标。**  
VulAgent 在 PrimeVul 上的 P-C 只有 26.6%；SBVul 的最好 pair 准确率 42.0%；VulnGym 最强 agent 在 Hard 上 AR 22.58%。这些是 2025–2026 的强方法，不是弱基线。**本项目的 29.7–32.0% 召回在这个背景下并不离谱；真正的问题是“是否可解释、是否可复现、是否在固定 FPR 下更好”。**

**判断 3：最便宜、最可能立刻改善的，是 P0/P1 两个测量实验。**  
P0 不需要 API：把 102 条 invalid 按“致命/可回收”重分类，重算 usable-patch yield；P1 只需要 180 对 × 2 顺序 = 360 次请求，成本约 $0.3（按现有单价），就能把 A 偏差和长度先验分离。相比之下，P4/P5 的工具/修复闭环是 2–4 周工程，应该后置。

---

## 3. 工具使用与 agentic 检测

### 3.1 范式变化：从“分类器”到“证据收集器”

2025–2026 年的强方法有一个共同结构，而不是“多 agent 角色扮演”本身：

1. **高召回地产生候选**：敏感操作、sink、入口点、数据流事实、可疑语句；
2. **把候选变成可证伪的假设**：触发条件、守卫、路径、CWE；
3. **用外部证据裁决**：仓库上下文、静态分析、sanitizer/PoC、编译/测试、反事实扰动；
4. **只在证据不足时输出 uncertain**，而不是强行二分类。

这个结构与当前 runner 的“一次请求 → `is_vulnerable` + `confidence` + `rationale`”是根本不同的。当前 prompt 让模型同时做发现、裁决、解释三件事；文献的做法是把它们拆开，并让每一步都有可检查的中间产物。

### 3.2 方法卡片

#### A1. IRIS：LLM 推断 taint 规格 + CodeQL 做全仓库分析 `[A3]`

- **出处**：ICLR 2025；arXiv:2405.17238（v1 2024-05-27，v3 2025-04-06）。
- **问题**：静态分析工具依赖人工标注的 source/sink/sanitizer 规格，覆盖率低。
- **机制**：LLM 阅读项目代码，推断外部 API 的 taint 规格（source/sink/sanitizer），再交给 CodeQL 做全仓库数据流分析；LLM 还做上下文分析，减少人工检查。
- **证据**：CWE-Bench-Java 120 个手工验证漏洞；CodeQL 只检出 27 个，IRIS + GPT-4 检出 55 个（+28）；平均 false discovery rate 改善 5 pp；发现 4 个此前未知漏洞。
- **对本项目**：SecVulEval 只有函数片段，没有完整仓库，无法直接跑 CodeQL；但 **“让 LLM 推断 CWE 相关的 source/sink 规格，再用轻量规则/正则/数据流检查”** 可以迁移到函数级。最小版本：对每个 CWE 家族，让模型列出 3–5 个 source/sink/sanitizer 模式，再用这些模式生成候选行，而不是直接判 verdict。
- **成本/风险**：CodeQL 数据库构建是主要成本；函数片段没有构建环境。不要把 IRIS 的 55/120 直接当成“LLM 检测率”，它是“LLM + CodeQL”的联合结果。

#### A2. RepoAudit：agent memory + 数据流事实 + validator `[A4]`

- **出处**：ICML 2025，PMLR 267:21083–21100；arXiv:2501.18160（v1 2025-01-30，v3 2025-05-29）。
- **问题**：仓库级审计受上下文窗口和幻觉限制；全库分析成本高。
- **机制**：agent 带 memory，按需探索代码库；沿可行程序路径分析**函数内数据流事实**；validator 检查数据流事实和路径条件的可满足性，降低误报。
- **证据**：15 个真实项目上找到 40 个真 bug，精确率 78.43%，平均 0.44 小时/$2.54 每项目；在高关注项目中找到 185 个新 bug，174 个被确认或修复（v3 摘要口径）。
- **对本项目**：这是“仓库级”方法，本项目从 SecVulEval 抽出的 200 条函数（测试集 160 条）没有仓库快照；但它提供了一个**低成本中间层**：不要一次让模型读全库，而是让模型先列出“这个函数依赖哪些外部符号/调用/全局状态”，再只取这些依赖的 1–2 跳上下文。当前 `context` 字段只有标识符列表（中位 76.5 字符），远不足以做数据流事实。
- **成本/风险**：agent 循环 + validator 的工程成本高；40 个 bug/15 项目是“精确率优先”的结果，不能外推召回。

#### A3. VulAgent：高召回发现 → 假设（条件+路径）→ 验证 `[A11]`

- **出处**：Findings of ACL 2026，pp. 18598–18616，DOI `10.18653/v1/2026.findings-acl.928`；正式版已核对。
- **问题**：单 agent CoT 缺少显式上下文验证，误报高；检索增强把发现和验证耦合，推理负担大。
- **机制**：
  1. **多视图发现**（高召回，故意容忍噪声）：MetaAgent 按语义线索派发专门 agent（内存操作、文件系统、并发、密码 API、权限逻辑），每个 agent 输出带行号的 JSON finding；按 `(CWE, sink line)` 去重合并。
  2. **假设构造**：每个候选变成 `(CWE, conditions A, trigger path P)`；conditions 是漏洞成立的前置条件（如“缓冲区长度可能超过分配大小”“输入指针可能为 NULL”）；path 是 source→sink 的控制/数据依赖路径，路径上的守卫记录到 A 而不是剪掉。
  3. **条件验证**：逐条检查 `A`，输出 `valid / plausible / contradicted`；被反驳的条件直接丢弃假设。
  4. **路径验证**：检查路径上是否有有效守卫在 sink 之前阻断；只有 retained 的假设进入最终报告。
- **证据**：PrimeVul 上 P-C 26.6%（VulTrial 18.6%，+43.0%），FPR 36.7%（52.6%，−30.0% 相对），ACC 58.6%（53.4%，+5.2 pp）；SVEN 上 P-C 26.5%（4.82%，+449.8%），FPR 55.4%（95.2%，−41.8% 相对），ACC 60.2%（52.0%，+8.2 pp）；pair identification 平均 2.46×、最高 4.5×；上下文消融：PrimeVul P-C 17.5→28.7，SVEN 20.4→26.5。
- **对本项目**：这是最直接可借的架构。当前 160 条独立集可以改成两阶段：
  - **Stage 1（发现）**：让模型输出 1–5 个候选敏感操作，每个带行号、CWE、为什么可疑；不要求 verdict。
  - **Stage 2（验证）**：对每个候选，要求列出“触发条件”和“路径上的守卫”，逐条标 `valid/plausible/contradicted`；只有至少一个 retained 才判漏洞。
  - **指标**：Stage 1 的 candidate recall（是否覆盖真实修复行）与 Stage 2 的 precision/retained rate 分开报；不要只看最终 F1。
- **成本/风险**：VulAgent 每样本约 7,037 output tokens，是 VulTrial 的 2.3×、GPTLens 的 3.1×；本项目 160 条 × 2 阶段 × 多视图会显著涨价。建议先在 40–50 条分层子集上做可行性，不要全量。
- **重要限制**：VulAgent 的 P-C 26.6% 仍然很低；它降低 FPR 的能力比提高召回更确定。不要把它当成“召回解药”。

#### A4. VulnAgent-R2：反事实证据重加权 + 验证计划 + 成本调度 `[B1]`

- **出处**：arXiv:2603.13384（v1 2026-03-11，v3 2026-06-03），预印本。
- **问题**：仓库级 agent 的证据容易“看起来相关但非因果”；验证器行为、成本、统计不确定性常被欠规范。
- **机制**：
  - 类型化仓库图（AST/CFG/DFG/CALL/IMP/TEST/HIST）做风险 triage；
  - 预算化上下文选择（最多 16 个上下文块，默认 8,000 tokens）；
  - **反事实证据重加权（CER）**：对每个 claim 采样最多 4 种扰动——遮掉被引用 span、注入 sanitizer/guard 事实、替换非支配 caller、用历史修复版本替换当前区域；如果 claim 的可靠性在扰动下大幅下降，就降权；
  - **验证计划合成（VPS）**：把证据元组映射成 `(pre, stimulus, oracle, adapter, timeout)`；只在符号可解析、oracle 可观察时接受；否则输出六类 inconclusive（构建系统缺失、依赖缺失、harness 编译失败、超时、flaky、oracle 不可用）；
  - 校准融合 + 成本-risk Pareto 调度。
- **证据**：Devign/Big-Vul/DiverseVul/PrimeVul 上 F1/AUROC 分别为 0.798/0.895、0.739/0.871、0.700/0.842、0.385/0.781；PrimeVul 比 VulnAgent-X +0.038 F1（95% CI [0.020, 0.055]，Holm p=0.009）；JITVul F1 0.606、Top-1 0.529、Top-3 0.742；在线 token 比 always-full 多 agent 少 38.3%。验证器行为：21.6% 样本触发 VPS，68.9% 触发案例能建可运行测试/harness，35.7% 产生正面可执行证据，25.8% 明确 inconclusive。
- **对本项目**：**CER 是最便宜、最值得先试的模块**。不需要图数据库，也不需要完整仓库；在现有 pair/检测 prompt 上加一个“反事实自检”即可：
  1. 让模型先给 verdict + 引用行；
  2. 第二次请求：把引用行遮掉（或替换成 `/* masked */`），问“在没有这一行的情况下，你的判断会改变吗？”；
  3. 如果 verdict 翻转，把原判断标为低置信/uncertain，或要求重新给证据。
  这能直接检验“引用行是否真的是决策依据”，比让模型自报 confidence 更可靠。成本是每样本 +1 次请求；160 条约 +$0.05–0.10。
- **注意**：VulnAgent-R2 的 PrimeVul F1 只有 0.385，precision/recall 0.402/0.370；高精确率阈值下 precision 0.561、recall 0.214。它自己也承认“仍是 prioritization aid，不是人工审计替代”。不要期待它把召回拉到 80%。

#### A5. SBVul：语句级两阶段，Phase 1 探索仓库，Phase 2 验证控制/数据流 `[B5]`

- **出处**：arXiv:2611.06135（v1 2026-11-04），预印本。
- **问题**：函数级二分类把“定位可执行语句”留给开发者；模型在 vulnerable/patched 对上仍然分不清。
- **机制**：
  - **Phase 1**：LLM agent 用文件系统/文本搜索工具（列目录、按名找文件、内容搜索、读精确行范围）探索函数及仓库，提出候选语句，每条带行号和解释；最多 80 次工具调用；找不到更多候选或到上限就停。
  - **Phase 2**：第二个 agent 对每个候选分析控制/数据流，输出 `confirmed / ruled out / uncertain`；每条 verdict 必须基于实际收集的证据；“空工具结果本身不构成任何方向的证据”；不确定不算正例。
  - 最后规则式分类：至少一个候选被 confirmed 才判 vulnerable。
- **证据**：PrimeVul Paired test 随机 200 对（104 个项目，最多 10 对/项目；TensorFlow/Linux/Vim 不主导）；Phase 1 在 56–77% 的漏洞函数中定位到 ground-truth 语句；Phase 2 在 26–73% 中确认并给出被 LLM judge 接受的解释；但所有模型在 **23–61% 的 patched 函数**上也确认了候选；语句级最高 precision 0.315 @ recall 0.605（Opus 5.5 xhigh）；函数级 pair 42.0% 正确（此前最好 33.8%）。
- **对本项目**：这是“语句级”的直接模板，但它的 **23–61% patched 假确认**是重要警告：如果只在漏洞侧做语句级确认，模型会对修复侧也“找到漏洞”，pair 仍然失败。建议：
  - Phase 1 用高召回（允许多个候选），Phase 2 必须同时看“守卫是否存在”，而不是只看 sink 是否危险；
  - 对 patched 侧也跑同样的 Phase 2，并把“两侧都 confirmed”作为 pair 的 uncertain，而不是强行选一边；
  - 报告 `Phase 1 candidate recall`、`Phase 2 confirm rate`、`patched-side false confirm rate` 三个数，不要只报最终 pair accuracy。
- **成本/风险**：每阶段最多 80 次工具调用；200 对 × 4 模型 = 大量调用。本项目没有仓库 checkout 工具链，需要先补 `git clone`/文件搜索；先做 20–30 对可行性。

#### A6. Revelio：可执行 PoV + sanitizer，成本分层 `[B8]`

- **出处**：arXiv:2606.22263（v1 2026-06-20），预印本。
- **问题**：LLM 检测内存安全漏洞不可靠、易幻觉、难扩展到仓库级。
- **机制**：
  - 便宜模型 + 轻量静态分析生成/排序漏洞假设；
  - 只在候选上构造**可执行 Proof-of-Vulnerability（PoV）**，用确定性 sanitizer 检查；
  - 只有能复现并被 sanitizer 确认才报告；
  - 两阶段：便宜模型做 code review，强模型做 confirmation；成本分层。
- **证据**：7 个持续 fuzz 5–8 年的生产项目 + 100 个 CyberGym/Arvo 项目；约 1 小时/项目，总成本约 $300；发现 19 个此前未知内存安全漏洞；在可比 token 成本下优于 frontier coding agents。
- **对本项目**：这是“验证反馈”的强形式，但需要可编译/可执行环境。本项目只有 Juliet 有 harness；SecVulEval 的函数片段没有。建议：
  - 在 Juliet CWE-401 上已有 LSan harness，可把 Revelio 的“PoV + sanitizer”思想用于修复验证（已有 58/58 可观测子集，但那只说明“泄漏消失”，不等于根因修复）；
  - 对 SecVulEval 不要假装能跑 PoV；明确 `compile_status=NOT_RUN`，把 Revelio 作为“未来真实项目子集”的方法，而不是当前 160 条的手段。
- **成本/风险**：$300/107 项目 ≈ $2.8/项目，但每个项目要构建、跑 sanitizer、可能 fuzz；本项目 API 预算 $2.44 是三个策略的总成本，不能直接套。

#### A7. ARQ：用执行反馈修 CodeQL 查询 `[B7]`

- **出处**：arXiv:2608.20637（v1 2026-08-21），预印本。
- **问题**：CodeQL 查询有 FP/FN；手工修查询需要标注数据/提交历史/漏洞模板。
- **机制**：合成 C/C++ 程序，执行后与查询 verdict 比较：真漏洞但查询沉默 → FN 弱点；安全程序但查询报警 → FP 弱点；用这些 disagreement 作为 ground truth，让 LLM 迭代修查询。不需要标注数据集、提交历史、漏洞模板。
- **证据**：12 个官方 CodeQL 查询、3 个商用 LLM（GPT-5.4、Claude-Sonnet-4.6、Gemini-3.5-flash）；在 Juliet v1.3 和 FormAI v2 上真阳性最多 +119.8%，精确率始终 ≥98.0%；修复了 3 个在官方 CodeQL 仓库挂了最多 27 个月的 GitHub issue；在 libpng/zlib 发现 2 个此前未知 bug。
- **对本项目**：如果本项目要走“传统工具 + LLM”的混合路线，ARQ 的思路比“让 LLM 直接读代码”更可控：**用 Juliet/FormAI 的已知标签合成反例，测 CodeQL 查询的 FN/FP，再让 LLM 改查询**。这比让 LLM 判 160 条函数更容易验证，也更符合“工具使用”的主题。
- **成本/风险**：需要 CodeQL 数据库和可编译的合成程序；对本项目的函数片段不适用；但 Juliet 是现成的。

#### A8. KNighter：从历史补丁合成静态 checker `[A5]`

- **出处**：SOSP 2025，pp. 655–669，DOI `10.1145/3731569.3764827`；arXiv:2503.09002（v1 2025-03-12，v3 2025-09-03）。
- **问题**：手工写静态分析器成本高、只覆盖预定义 bug pattern；直接让 LLM 扫大系统不可扩展。
- **机制**：从历史 patch 学习 bug pattern，让 LLM 生成专用 static checker；多阶段合成，用原始 patch 验证 checker 正确性；自动 refinement 迭代降 FP。
- **证据**：Linux 内核发现 92 个新、关键、长期潜伏的 bug（平均 4.3 年）；77 确认、57 修复、30 个 CVE。
- **对本项目**：工程量大，不适合课程项目直接复现；但“从 patch 学 checker”可以做一个轻量版：对每个 CWE 家族，从 5–10 个历史修复 diff 中让模型总结“修复前的坏模式”，生成 3–5 条 grep/语义规则，作为 Stage 1 的候选生成器。这比让模型自由发挥更容易审计。

#### A9. EnIGMA / SEC-bench / SastBench：工具接口与任务框架 `[A6][A8][B3]`

- **EnIGMA**（ICML 2025；arXiv:2409.16165）：给 LM agent 增加交互式终端工具（debugger、server connection），在 390 个 CTF 挑战上达到 NYU CTF/Intercode-CTF/CyBench 的 SOTA；还提出“soliloquizing”——模型自生成幻觉观察、不与环境交互。**对本项目**：工具接口设计本身会改变 agent 行为；如果只给“读文件”不给“执行/验证”，模型容易自说自话。当前 runner 没有任何工具接口，这是“低召回 + 不可验证”的结构原因之一。
- **SEC-bench**（NeurIPS 2025；arXiv:2506.11791）：自动构建带 harness 的仓库、在隔离环境复现漏洞、生成 gold patch；每实例成本 $0.87；最佳 agent 的 PoC 生成 ≤18.0%、漏洞修复 ≤34.0%。**对本项目**：PoC/修复任务比二分类难得多；不要用“检测 F1”推断“修复能力”。
- **SastBench**（arXiv:2601.02941，v1 2026-01-06）：用真实 CVE 作 TP、过滤后的 SAST 告警作近似 FP，评估 SAST triage agent；agent-agnostic。**对本项目**：如果要做“工具证据”，triage（在告警里挑真漏洞）比“从零检测”更接近实际安全工程，也更容易构造对照。

### 3.3 负面证据：agent 不是万能药

- **ESEM 2026 的受控拆解** `[A21]`：六个条件（单次 prompt → matched-context replay → ReAct 工具 → self-review → trace-isolated verification → multi-role decomposition）、六个基座模型。结论：完整 agent 经常比单次 prompt 的 accuracy/F1 高，但**这些提升不一致地延伸到鲁棒性、抗误导上下文、证据接地三个维度**；模型在语义保持扰动下并不更稳定，常被非因果 prompt 线索误导，很少引用真正解释漏洞的代码行；在最强改进案例中，**大部分 accuracy 变化在“只给同样的检索工具输出、不给完整 agent 过程”时已经出现**；把上下文固定后，剩余的 agent 效应主要是“更经常预测 vulnerable”。
- **VulnGym** `[B2]`：最强组合在 Hard 上 AR 22.58%，且 56.5% 的失败是“根本没找到漏洞文件”或“文件对但行不对”；EP 识别比 CO 定位更难；trace 的 TNP 只有 14.61–26.71%。
- **ContextBench** `[B4]`：复杂 scaffolding 对上下文检索只有边际提升；LLM 重召回轻精确；“探索到的上下文”远多于“真正用到的上下文”。
- **本项目的 Juliet 工具证据** `[P]`：direct 135/140（96.43%）→ combined 140/140（100.00%），但只修复 5 个 `_22` 假阳性；McNemar p=0.0625；shuffled 安慰剂也 135/140；133/140 在 5 种方法下预测不变。这是 ceiling 效应，不是“工具普遍有效”。

### 3.4 对本项目的可执行建议

1. **先做一个工具，不要做五个 agent。** 在 30–50 条分层子集上，选一个最匹配的：
   - 如果目标 CWE 是内存安全/资源泄漏：用 ASan/LSan + 可编译 harness（Juliet 已有）`[C6]`；
   - 如果是注入/路径遍历：用 CodeQL 或 Semgrep 的现成规则，让 LLM 做 triage，而不是从零检测 `[C4][C5]`；
   - 如果是访问控制/逻辑漏洞：工具帮助有限，优先做上下文/假设验证（VulAgent 风格）。
2. **工具证据必须做“匹配上下文对照”。** 不能只比较“有工具 vs 无工具”；要比较“有工具 vs 给同样多的随机/无关上下文”。本项目在 Juliet 上用 shuffled 安慰剂做过，这是正确做法；在 SecVulEval 上也应如此。
3. **报告三个数，而不是一个 F1**：固定 FPR 下的 recall、工具覆盖率（多少样本能跑工具）、工具结论的 precision/recall（以修复行为参考）。如果工具只覆盖 20% 样本，100% 准确也不能外推。
4. **成本上限**：按现有单价，160 条 × 2 阶段 × 1 次重试约 $0.2–0.5；如果做 5 个视图 × 3 轮，成本会到 $2–5，已经超过现有三策略总成本。先在 40 条上估，再决定是否全量。

---

## 4. 代码库级上下文

### 4.1 证据：上下文不是越多越好

| 证据 | 关键数字 | 含义 |
| --- | --- | --- |
| ContextBench `[B4]` | 1,136 个 issue 任务、66 个仓库、8 种语言；4 个 frontier LLM、5 个 coding agent | 复杂 scaffolding 对 context retrieval 只有边际提升；LLM 重召回轻精确；探索到的上下文 > 真正用到的上下文 |
| VulnGym `[B2]` | 184 advisories、408 entries、23 repos；Hard 上最强 agent AR 22.58% | 仓库级端到端仍很难；失败多在“找不到文件/行” |
| IRIS `[A3]` | CodeQL 27/120 → IRIS 55/120 | 全仓库数据流 + LLM 规格推断有效 |
| RepoAudit `[A4]` | 40 bugs/15 projects，precision 78.43%，$2.54/项目 | 按需探索 + validator 可以在成本可控下提高精确率 |
| LLMxCPG `[A7]` | CPG 切片减 67.84–90.93% 代码；F1 +15–40% | 结构化切片比“整段代码”更有效 |
| VulAgent 上下文消融 `[A11]` | PrimeVul P-C 17.5→28.7；SVEN 20.4→26.5 | 上下文对 pair 判别有实质帮助，但绝对水平仍低 |
| Lost in the End `[A13]` | 文件内漏洞越靠后，性能越差；调整输入大小平均召回 +37% | 位置/长度效应；分块和行号化是必要工程 |
| 本项目 `[P]` | context 中位 76.5 字符，只有标识符列表；独立集“context 非空 ⇒ 漏洞”准确率 98.8%、MCC 0.963 | 当前 context 与标签混杂，不能证明“context 有用/无用” |

**关键判断**：本项目当前的 `context` 不是“代码库级上下文”，而是“数据集提供的标识符列表”。它既太短（中位 76.5 字符），又与标签高度相关（非空层 126/126 全是漏洞）。**任何“context 策略”的总体指标都不可解释**，必须先换成真正的 caller/callee/guard/test/patch 上下文，再做匹配对照。

### 4.2 方法卡片

#### B1. 行号化 + 窗口化 + 分块（Lost in the End） `[A13]`

- **出处**：FSE 2025，PACMSE 2(FSE):891–913，DOI `10.1145/3715758`；arXiv:2502.06898（v1 2025-02-09）。
- **问题**：LLM 在整文件输入上检测 XSS/SQLi/path traversal 时，漏洞越靠文件末尾，性能越差；输入越大越明显。
- **机制**：研究不同输入大小/漏洞位置的影响；给出选择最优输入大小的简单策略；调整输入大小后平均召回 +37%。
- **对本项目**：当前函数正文没有行号（`prompts.py:219-246` 直接放 `<FUNCTION_SOURCE>`），模型无法稳定引用行；pair_joint 已经加了 `行号 | 源码`，证据合规率 98.33%/97.78%，说明行号化本身是有效的工程。建议：
  - 检测/修复 prompt 统一加 1-based 行号；
  - 对超过 ~80 行的函数，按“函数头 + 前后 20 行窗口 + 可疑区域”分块，而不是整段塞入；
  - 报告“输入大小 vs recall”的曲线，找到本项目的最优窗口，而不是假设越长越好。
- **成本/风险**：分块会增加请求数；需要去重/合并候选，否则同一漏洞会被多次报。

#### B2. 依赖切片（LLMxCPG） `[A7]`

- **出处**：USENIX Security 2025，pp. 489–507。
- **问题**：整函数/整文件输入包含大量无关代码；LLM 容易被噪声干扰。
- **机制**：用 Code Property Graph（CPG）构造漏洞相关切片，把代码量减少 67.84–90.93%，保留 source→sink 的上下文；再让 LLM 分类。
- **证据**：在传统和 verified 数据集上 F1 比 SOTA 高 15–40%；在函数级和多函数代码库上表现一致；对语法修改更鲁棒。
- **对本项目**：没有 CPG/构建环境，但可以做一个**轻量依赖切片**：
  - 以候选 sink 行为中心，向前找变量定义/赋值/参数来源，向后找使用/释放；
  - 只保留这些行 + 控制流骨架（if/for/return/goto），去掉无关声明和注释；
  - 切片后仍保留行号，便于证据评分。
  这比“整函数”更接近 LLMxCPG 的输入，也更容易控制 token。
- **成本/风险**：轻量切片可能漏掉跨函数依赖；需要与“整函数”做对照，证明切片没有丢召回。

#### B3. 知识级 RAG（Vul-RAG） `[A14]`

- **出处**：ACM TOSEM 2026，DOI `10.1145/3797277`；arXiv:2406.11147（v1 2024-06-17，v3 2025-06-17）。
- **问题**：LLM 很难区分“漏洞代码”和“相似但已修复的代码”；作者报告只有 **0.06–0.14** 的准确率。
- **机制**：从历史漏洞/修复中蒸馏多维漏洞知识（root cause、trigger、fix pattern），做知识级 RAG；检索相似漏洞的知识，而不是只检索代码。
- **证据**：识别 vulnerable/patched code 的准确率提升 16–24%；生成的知识作为解释，把人工检测准确率从 60% 提到 77%；在近期 Linux 内核发现 10 个未知 bug，6 个 CVE。
- **对本项目**：这是**直接针对 pair 判别**的方法。当前 pair prompt 只给两段代码，没有“这类漏洞的典型 root cause/fix pattern”。建议：
  - 为 Top-8 CWE 各准备 3–5 条“漏洞知识卡”（root cause、触发条件、修复模式、常见误报）；
  - 在 pair prompt 中只放与候选 CWE 相关的知识卡，不要放全量；
  - 先在小样本上测“有知识卡 vs 无知识卡”的 pair DA 和 flip rate。
- **成本/风险**：知识卡需要人工/半自动构建；如果知识卡泄漏了“修复通常更长”这类伪影，会加剧长度先验。必须做长度匹配对照。

#### B4. 匹配上下文对照（ESEM 2026 / VulAgent） `[A21][A11]`

- **问题**：agent/context 的提升可能只是“多给了相关信息”，而不是“推理更好”。
- **机制**：ESEM 2026 用 matched-context replay 把“同样的检索工具输出”直接给模型，不跑完整 agent；VulAgent 做 with/without context 消融。
- **证据**：ESEM 2026 发现大部分 accuracy 变化在 matched-context replay 时就出现；VulAgent 的 context 消融显示 P-C 提升（17.5→28.7），但绝对水平仍低。
- **对本项目**：这是**必须补的对照**。当前 M3 context 与标签混杂，不能回答“context 有没有用”。建议在 160 条上做四格：
  1. 无 context；
  2. 数据集原 context；
  3. 随机/打乱的同长度 context（安慰剂）；
  4. 结构化上下文（caller/callee/guard/test）。
  主终点：固定 FPR 下的 recall；次终点：context 使用率、引用行精确率。
- **成本/风险**：4 个条件 × 160 条 = 640 次请求，约 $0.4–0.8；比全量 agent 便宜得多。

### 4.3 本项目的最小实现

不做全库 agent，先做“函数 + 1 跳依赖”的上下文包：

```
<FUNCTION_SOURCE lines="L1..Ln">
...
</FUNCTION_SOURCE>

<CALLERS>
caller_name at file:line — 1-3 lines of call site
</CALLERS>

<CALLEES>
callee_name at file:line — signature + 1-3 lines
</CALLEES>

<GUARDS>
- check at line X: if (len > MAX) return;
- check at line Y: if (p == NULL) return;
</GUARDS>

<TESTS>
test name / assertion that exercises this function
</TESTS>

<PATCH_HISTORY>
previous fix commit summary (no diff if it leaks the answer)
</PATCH_HISTORY>
```

原则：
- 每个块都有行号/文件路径，便于证据评分；
- 总 token 控制在 2,000–4,000，不超过函数本身的 2×；
- 先只加 `CALLERS` + `GUARDS`，这两类最可能解释“短函数为什么危险/安全”；
- 用 matched-context 对照证明增益，不要只看总体 F1。

---

## 5. 自一致性、采样与置信度

### 5.1 证据：自一致性不是“越多越好”

| 文献 | 设置 | 结论 | 对本项目 |
| --- | --- | --- | --- |
| Self-Consistency `[A22]` | 采样多条 CoT 路径，对最终答案投票 | 在算术/常识推理上显著优于单条 CoT | 是“多采样”的基线，但任务是自由文本答案，不是安全二分类 |
| Large Language Monkeys `[B18]` | 重复采样，测 coverage | coverage 随样本数**对数线性**增长，跨四个数量级；SWE-bench Lite 从 15.9%（1 样本）到 56%（250 样本）；多数投票/奖励模型在几百样本后饱和 | “多采样”能提高**覆盖率**，但需要一个验证器来挑；没有验证器时，投票会饱和 |
| Semantic Entropy `[A15]` | 按“意义”聚类后算熵 | 比 token 熵/自评更可靠地检测 confabulation；可用于拒答 | 可用于“不确定时 abstain”，但 API 没有 logprobs，只能用离散版本 |
| PromptAudit `[B17]` | 5 种 prompt × 5 个开源模型 × 1,000 CVE/6,074 样本/16 语言 | 标准 CoT 整体最好；few-shot 依模型而异；adaptive CoT 经常压低召回；**self-consistency 引发过度 abstention，显著降低有效性能** | 直接警告：不要用 SC 来提高召回；它可能把“不确定”变成“拒答” |
| ConfColl `[A12]` | 三阶段：单 agent → RAG → 多 agent+RAG；高置信就停 | 用置信度/协作决策平衡性能与成本 | 可用于“便宜模型先跑，高不确定才升级”，但前提是置信度校准 |
| 本项目置信度 `[P]` | 自报 0–1 confidence | ECE 0.300–0.448；Brier 0.312–0.432；confidence→correctness AUC 0.581–0.607；高置信（≥0.9）子集准确率仅 46.2–54.5% | 当前置信度不能用于路由/人工分流；先校准或用证据一致性替代 |

**关键判断**：在漏洞检测里，“多条采样 + 多数投票”有两个问题：
1. **错误可能相关**：同一个模型在同一 prompt 下的错误高度相关，投票不会消除系统性偏差（例如“短函数看起来安全”）。
2. **投票目标错了**：如果 5 条采样里有 3 条说“安全”，投票会强化漏报；而覆盖率提升（至少 1 条说“漏洞”）被投票抹掉。PromptAudit 的“SC 导致过度 abstention”正是这个机制的经验证据。

### 5.2 方法卡片

#### C1. k 采样 + 证据条件聚合（不是多数投票） `[B18][B5]`

- **做法**：
  - 对同一函数采样 k=5（temperature 0.7），每条输出 verdict + 证据行 + CWE；
  - 按 `(CWE, 证据行集合的 Jaccard)` 聚类，而不是按 verdict 投票；
  - 选“证据最具体、且能被上下文/工具支持”的簇；如果所有簇都缺少可验证证据，输出 uncertain；
  - 报告 `coverage@k`（至少一条采样判漏洞的比例）、`verified precision@k`、`abstention rate`，不要只报 accuracy。
- **依据**：Large Language Monkeys 说明 coverage 随 k 增长；SBVul 说明“证据必须来自实际工具结果，空结果不构成证据”。
- **成本**：5× 检测请求；160 条约 800 次，按现有单价约 $0.3–0.5。先在 40 条上做。
- **风险**：如果 5 条采样都基于同一个错误前提，聚类也救不了；需要外部证据。

#### C2. 语义熵/离散语义熵做 abstention `[A15]`

- **做法**：对 k 条采样的 `rationale` 做语义聚类（可用简单的 CWE + 关键短语 + 行号重叠近似，避免再调用模型）；计算离散熵；高熵样本不强行判，标 `uncertain` 并进入人工/工具复核。
- **依据**：Semantic Entropy 在 QA/数学上比 token 熵更可靠；离散版本不需要 logprobs。
- **成本**：如果复用 C1 的 k 条采样，边际成本接近 0；聚类可用规则/embedding。
- **风险**：安全 rationale 的“语义等价”很难自动判定；不要把聚类结果当成 ground truth，只作为路由信号。

#### C3. 置信度门控升级（ConfColl 风格） `[A12]`

- **做法**：
  - Stage 1：便宜模型/短 prompt 单次判断；
  - 如果置信度高于阈值（需校准）→ 直接输出；
  - 否则 Stage 2：加 RAG/上下文；
  - 仍不确定 → Stage 3：多 agent/工具验证。
- **依据**：ConfColl 在三阶段上平衡性能与成本；本项目已有两模型、三策略的请求级成本数据，可以做离线模拟（不需要新 API）。
- **前提**：当前 confidence 未校准（AUC 0.581–0.607），不能直接用 0.9 当阈值。先做温度缩放/等渗回归（需要校准集），或用“证据是否可验证”作为路由信号。
- **风险**：如果 Stage 1 高置信地漏报，升级永远不会触发；需要保留一定比例的随机升级/审计。

#### C4. 配对的位置平衡自一致性 `[B16][A20]`

- **做法**：同一对跑 A/B 和 B/A 两次；如果两次选择一致 → 采用；不一致 → 标 `order_unstable`，不计入正确，或进入第三次证据裁决；报告 `flip rate` 和 `order-conditional DA`。
- **依据**：位置偏差在通用 LLM 评测中已被系统证实；2026 年的综合研究发现规模/CoT 可缓解、thinking 模型近免疫，但本项目 DeepSeek 关闭了 thinking；EACL 2026 的代码 judge 研究说明“让模型先生成测试”也不能消除表面偏差。**不能只靠 prompt 里写“顺序无信息”**——本项目已经写了（`pair_joint/common.py:240`），A 偏差仍然 31.11 pp。
- **成本**：2× pair 请求；180 对约 360 次，按现有单价约 $0.3。
- **风险**：B/A 两次都受同一位置偏差影响时，平均仍可能有偏；需要报告 per-order，而不是只报平均。

### 5.3 为什么不能直接套 majority vote

把本项目的失败模式代进投票框架：

- 128 个漏洞中，模型只报 38 个 TP、90 个 FN；如果 5 次采样独立且每次 recall 30%，至少 1 次报漏洞的概率约 1−(0.7)^5≈83%，coverage 看起来很好；但多数投票的 recall 仍接近 30%，因为 3/5 的多数仍偏向“安全”。**投票会保留漏报，抹掉覆盖率。**
- 反过来，如果模型有“短函数看起来安全”的系统偏差，5 次采样会重复这个偏差，投票会把它放大成“高置信安全”。
- PromptAudit 的“SC 导致过度 abstention”说明另一种失败：模型在不确定时选择拒答/模糊输出，投票把“不确定”聚成多数，有效覆盖率下降。

**结论**：如果要用采样，目标是 **coverage + verifier**，不是 **majority vote**。验证器可以是工具（sanitizer/CodeQL）、上下文（guard 是否存在）、或一个独立的 judge（但 judge 本身有偏差，需要 A/B+B/A）。

---

## 6. 约束解码与 schema

### 6.1 证据：schema adherence ≠ 语义正确

| 文献/文档 | 关键事实 | 对本项目 |
| --- | --- | --- |
| OpenAI Structured Outputs `[C1]` | `json_schema` + `strict:true` 保证输出符合 schema；JSON mode 只保证合法 JSON，不保证字段齐全；所有字段必须 `required`；refusal/截断仍可能发生 | 如果 provider 支持 `json_schema`，优先用；否则不要假装 `json_object` 等于 schema |
| DeepSeek JSON Output `[C2]` | 官方文档只承诺“输出合法 JSON 字符串”；需要 prompt 里出现 “json”、给示例、`max_tokens` 足够；文档/镜像还提示可能返回空 content；官方文档只展示 `json_object`，未提供 `json_schema` 严格模式 | 本项目用 DeepSeek V4.1 Flash + OpenCode Go，当前只发 `response_format={"type":"json_object"}`（`client.py:200-201`），因此缺字段是预期行为 |
| vLLM structured outputs `[C3]` | 支持 xgrammar/guidance；JSON schema/regex/grammar/choice；不同 backend 的 regex 语法和允许 token 不同 | 如果自托管，可用 vLLM + XGrammar 做真正 schema 约束；托管 API 不一定暴露 |
| JSONSchemaBench `[A16]` | 10K 真实 JSON schema；6 个引擎（Guidance、Outlines、Llamacpp、XGrammar、OpenAI、Gemini）；效率/约束覆盖/输出质量差异明显 | “用了 constrained decoding”不等于“所有 schema 都能覆盖”；要测自己的 schema |
| XGrammar `[A17]` | CFG 约束；上下文无关 token 预检查 + 持久栈；最高 100× 加速；端到端近零开销 | 如果自托管，XGrammar 是工程上可行的选择 |
| SynCode `[A18]` | CFG 引导的语法解码；消除全部 JSON 语法错误；Python/Go 语法错误减少 96.07% | 语法正确不等于语义正确；但能消除“缺引号/截断”这类无效输出 |
| Let Me Speak Freely `[A19]` | 格式限制显著降低推理能力；约束越严，退化越大 | 不要为了 schema 把推理压死；可以“先自由推理，再结构化抽取” |
| Constrained Decoding: Harmful or Beneficial? `[B15]` | 4 个模型家族/11 个模型；表观退化很大程度来自非等价 prompt/输出格式，而不是 decoder masking；validity constraint 提升可靠性和可提取性；reasoning constraint 才可能提升准确率 | 区分“格式约束”和“有效性约束”；不要把格式收益当成推理收益 |
| Calibration Floor `[B14]` | 29 个主格 + frontier 臂；12 个格 format effect > content effect（Wilcoxon p=1.7e-3）；grammar-constrained decoding 把“naive total effect 与 content-margin 估计之间的差距”关掉中位 71%；frontier 5 个格 content margin 为 0 | 很多“模型自我修正”其实是 format repair；本项目要把 `format_repaired` 和 `content_changed` 分开记 |

### 6.2 方法卡片

#### D1. 优先 `json_schema`，否则两阶段抽取 `[C1][C2]`

- **做法**：
  - 如果 API 支持 `response_format={"type":"json_schema","json_schema":{"name":...,"strict":true,"schema":...}}`，直接用；把所有字段设为 `required`，可选字段用 `["string","null"]` 联合类型模拟；
  - 如果只支持 `json_object`（当前 DeepSeek 路径），改成两阶段：
    1. **自由推理**：让模型输出简短分析（不要求 JSON），重点是 verdict + 证据行；
    2. **结构化抽取**：第二次请求只做“把上面的结论转成 JSON”，schema 简单、字段少、max_tokens 小。
  - 这样可以避免“为了 JSON 牺牲推理”（Let Me Speak Freely），也避免“缺字段就整条废”。
- **成本**：两阶段 = 2× 请求，但第二阶段很短；对修复任务，第二阶段只需 `fixed_function` + `explanation`，成本增加约 10–20%。
- **风险**：第二阶段可能改变第一阶段的 verdict；要记录两阶段的差异，不要把第二阶段的“修正”当成模型自我纠错。

#### D2. 字段级校验：fatal vs recoverable `[P]`

当前 `validation.py:88` 要求 `{"fixed_function","explanation"}` 键集合完全相等；缺 `explanation` 就抛 `OutputSchemaError`，整条 patch 被丢。建议改成：

| 字段 | 缺失/错误 | 级别 | 处理 |
| --- | --- | --- | --- |
| `fixed_function` | 缺失/空/非字符串 | **fatal** | 无法修复；记 invalid |
| `fixed_function` | 括号不平衡/明显截断 | **fatal** | 结构无效；记 invalid |
| `fixed_function` | 与输入无实质差异 | **recoverable-semantic** | 记 `no_change`，不计入 usable patch，但保留记录 |
| `explanation` | 缺失/空 | **recoverable-format** | 记 `missing_explanation`；patch 仍可评分 |
| `explanation` | 非字符串 | **recoverable-format** | 尝试 `str()` 或置空；不丢 patch |
| 额外键 | 出现 | **recoverable-format** | 记录 `extra_keys`；不丢 patch |
| `root_cause`/`changed_lines` | 缺失 | **recoverable-format** | 如果新增字段，先设为可选 |

- **指标**：同时报告 `strict_schema_valid`（当前口径）和 `usable_patch_yield`（`fixed_function` 结构完整 + 有实质改动）；不要把两者混为一个“schema 有效率”。
- **依据**：本项目 102 条 invalid 中 93 条只缺 `explanation`，91 条结构完整，71 条有实质改动；严格校验把这些丢了。Calibration Floor 也说明“format repair”会被误读为能力变化。

#### D3. schema 版本 + `format_repaired` 标记 `[B14]`

- **做法**：
  - 每个响应记录 `schema_version`（如 `repair-v2`）、`parse_status`（`ok / recovered / fatal`）、`recovered_fields`（如 `["explanation"]`）、`format_repair_attempts`；
  - 如果做了“把 markdown 去掉/补引号/截取 JSON”的修复，记 `format_repaired=true`，但**不要把这次修复算作模型自我修正**；
  - 统计 `format_repaired` 的比例，以及它对最终指标的影响。
- **依据**：Calibration Floor 的核心结论就是“format repair 可以伪装成 self-correction”；如果不单独记，会把工程修复当成模型能力。

#### D4. 语义校验：行号、侧别、范围 `[P][B5]`

- **做法**：
  - 对 `evidence` 的每一行，校验 `line` 是整数、在显示范围内、`code` 与该行源码匹配（允许空白差异）；
  - 对 pair，校验每个 evidence item 的 `version` 等于 `vulnerable_version`；如果引用了另一侧，记 `cross_side_evidence`，不直接判 invalid，但降置信；
  - 对修复，校验 `changed_lines` 至少有一行在漏洞切片内；否则记 `out_of_slice_change`。
- **依据**：本项目 pair_joint 的 3 个 DeepSeek 证据不合规是“整行 `79 | ...` 放进 `line` 字段/行号写成字符串”，4 个 MiMo 不合规是“附加了另一版本的一行”；这些是格式/语义边界问题，不是 JSON 语法问题。严格判 invalid 会丢掉可用输出，静默改写又会污染指标；正确做法是**分类记录**。

#### D5. 修复 schema：从“两个字段”升级为“可审计的补丁合同” `[B10][B11][B12][C7]`

建议的新 schema（仍保持 JSON，字段可逐步加）：

```json
{
  "fixed_function": "<complete function>",
  "root_cause": "<one sentence: what is wrong and why>",
  "trigger_path": "<source -> ... -> sink, with lines>",
  "changed_lines": [{"line": 42, "before": "...", "after": "..."}],
  "change_summary": "<what the patch does>",
  "cwe": "CWE-401",
  "cannot_fix": false,
  "cannot_fix_reason": null,
  "confidence": 0.0
}
```

- **`root_cause` + `trigger_path`**：强制模型先解释“为什么”，再给补丁；如果补丁只改了崩溃行/表面 guard，root cause 会对不上。
- **`changed_lines`**：可直接检测 no-change/空白变化；比“文本不同”可靠。
- **`cannot_fix`**：AutoPatchBench 明确建议给模型“I cannot fix it”的出口，以减少“作弊式”补丁 `[C7]`；当前 prompt 没有这个出口，模型只能硬编一个补丁。
- **`cwe`**：与检测阶段的 CWE 对齐；如果检测阶段没有 CWE，至少让修复阶段自报，便于分层。
- **兼容性**：新字段先设为可选；不要一次性把旧 run 判 invalid；用 `schema_version` 区分。

### 6.3 本项目 102 条 invalid 的再解释

| 观察 | 数字 | 解释 | 建议 |
| --- | ---: | --- | --- |
| 修复请求总数 | 924（DeepSeek 三策略 × 308） | — | — |
| schema invalid | 102（11.0%） | 严格键集合校验 | 分成 fatal/recoverable |
| 只缺 `explanation` | 93 | JSON mode 不保证字段齐全；模型可能认为解释可选 | `explanation` 设为可恢复字段 |
| 结构完整 | 91/93 | `fixed_function` 在，括号/签名完整 | 这些 patch 应进入可用性评估 |
| 有实质改动 | 71/93 | 折叠空白后仍不同 | 这 71 条是“被 strict schema 丢掉的可用补丁” |
| 严格 schema 有效率（M1/M2/M3） | 84.4/99.0/83.4% | few-shot 最高，但 few-shot 无改动率也最高（44.5%） | schema 有效 ≠ 修复有效 |

**结论**：当前“schema 失败”主要是**测量口径**，不是模型能力。P0 应该直接用现有 `results.jsonl` 重算：
- `usable_patch_yield = 结构完整 + 有实质改动 / 全部请求`；
- `strict_schema_valid` 与 `usable_patch_yield` 的差值；
- 按策略/模型/CWE 分层，看差值是否集中。
这不需要新 API，只需要一个只读脚本；但脚本必须放在新目录（例如 `analysis/schema_recovery/`），不能改旧结果。**本次任务不做这个脚本，只把它列为 P0。**

---

## 7. 验证反馈与修复闭环

### 7.1 证据：生成成功 ≠ 修复正确

| 文献/工具 | 设置 | 关键数字 | 对本项目 |
| --- | --- | --- | --- |
| AutoPatchBench `[C7]` | 136 个 fuzzing 发现的 C/C++ 漏洞（113 Lite）；构建、崩溃复现、10 分钟 fuzzing、白盒差分测试 | 所有模型生成成功率约 60%，但通过 fuzzing + 差分测试的正确率只有 **5–11%**；Gemini 1.5 Pro 生成 61.1%，正确仅 5.3%；差分测试 84.1% 准确、precision 41.7%、recall 100%；模型会“cheating”压掉崩溃；根因常在栈外 | 不能把“编译通过 + 原输入不崩”当修复正确；必须有语义/行为验证 |
| PatchBench `[B13]` | 11 个 SOTA agent（含 AIxCC 前三）；补丁相似度、漏洞移植、代码变异 | 25% 的 agent 补丁与历史开发者补丁高度相似；只用 PoC 验证把 solve rate 平均抬高 **1.83×**；agent 常改崩溃栈上的代码来压掉崩溃 | 本项目没有 PoC，但“改表面/压症状”的风险同样存在；要检测改动位置是否在根因切片 |
| SEC-bench `[A8]` | 自动构建仓库/harness、复现漏洞、生成 gold patch；每实例 $0.87 | 最佳 agent PoC 生成 ≤18.0%、漏洞修复 ≤34.0% | 修复任务比检测难一个量级；不要用检测 F1 推断修复能力 |
| PatchEval `[B9]` | 1,000 个 2015–2025 CVE、65 CWE、230 个 sandbox；Go/JS/Python | 多语言修复 benchmark；静态相似度 + 运行时安全/功能测试 | 不是 C/C++，但验证框架可借；注意语言差异 |
| ExploreRepair `[B10]` | 无准确漏洞分类/无 PoV 的信息约束；3 个探索 agent + Lesson/Patch Aggregator + final Aggregator | PatchEval 39.6%（GPT-5.6-Luna）/71.6%（DeepSeek-V4.1-Flash），比 EvoRepair +16.0/+25.4 pp；VulnLoc+ 51.4%/62.9%，比无 PoV 的 LoopRepair +20.0/+17.1 pp | **DeepSeek-V4.1-Flash 在本项目同款模型上 71.6%**，说明“多解释探索 + 聚合”很可能比单次修复强；但 PatchEval 不是 C/C++ |
| EviRepair `[B11]` | 证据收集、证据一致性验证、reviewed vulnerability model；PatchEval + SecBench | 平均 resolved rate +16.37%（PatchEval）、+40.33%（SecBench） | “先审证据，再写 patch”比“直接写 patch”稳；适合无 PoV 场景 |
| AgenticRepair `[B12]` | 三类上下文：代码结构（跨文件数据流/内存操作）、运行时（崩溃语义/内存来源）、提交历史（脆弱模式如何引入）；3 个专门 subagent + repair memory | SEC-bench 300 实例，73% 成功率，比最强 baseline +29%；消融显示三类上下文互补 | 与本项目“修复只用函数文本”形成鲜明对比；至少应加“调用者/释放点/历史修复”上下文 |
| RepairAgent `[A9]` | 自主 agent 循环：定位→分析→生成→验证；工具调用 | ICSE 2025；首个自主 LLM APR agent | 说明“验证反馈”是 agent 的核心，不是附加项 |
| Agentless `[A10]` | 简单三阶段：localization → repair → patch validation；不让 LLM 决定未来动作 | SWE-bench Lite 32.00%（96/300），$0.70；Claude 3.5 Sonnet 在 Verified >50% | **简单、固定的三阶段往往比复杂 agent 更稳、更便宜**；本项目应先做固定管线，不要一开始就多 agent |
| Revelio `[B8]` | 便宜模型提议 + 强模型确认；可执行 PoV + sanitizer | 7 个项目 + 100 CyberGym/Arvo；约 1 小时/项目、$300；19 个未知漏洞 | 验证器是“确定性”的，不是 LLM judge；这是最可信的反馈形式 |

### 7.2 方法卡片

#### E1. 根因先行：先写 `root_cause` + `trigger_path`，再写 patch `[B10][B11][B12]`

- **做法**：
  - 第一次请求：只让模型分析“根因是什么、触发路径是什么、哪个 guard 缺失/错误”，输出结构化字段；不要求补丁。
  - 第二次请求：把根因/路径 + 原函数给模型，要求“只修根因，不改无关代码”，输出 patch + `changed_lines`。
  - 第三次（可选）：让另一个 prompt 检查“patch 是否真的阻断了 trigger_path”，而不是“是否让某个输入不崩”。
- **依据**：ExploreRepair 的“先探索多种解释，再聚合修复”在信息不完整时显著优于直接修；EviRepair 的“证据审查”提升 resolved rate；AgenticRepair 的三类上下文说明根因常在函数外。
- **成本**：2–3× 修复请求；308 条 × 2 ≈ 616 次，按现有单价约 $0.3–0.5。
- **风险**：根因分析可能“编故事”；需要 `trigger_path` 带行号，并与代码事实对齐。

#### E2. 改动门 + `cannot_fix` 出口 `[C7][B13]`

- **做法**：
  - 规范化空白后，如果 `fixed_function` 与输入相同/只差空白 → 记 `no_change`，不进入可用 patch；
  - 要求 `changed_lines` 至少一项；如果没有，直接重试一次，并在重试 prompt 中明确“必须修改至少一个可执行语句；如果无法修复，返回 `cannot_fix=true` 并说明原因”；
  - 不要把“cannot_fix”算作失败；单独报告 `abstention rate`，并与“强行修但无改动/表面修”对比。
- **依据**：AutoPatchBench 发现模型会“cheating”压崩溃，建议给“I cannot fix it”出口；PatchBench 发现表面修复/记忆补丁普遍。
- **成本**：一次重试；对 128 条漏洞函数约 +$0.1。
- **风险**：模型可能滥用 `cannot_fix` 降低 coverage；需要同时报告 coverage 和 abstention。

#### E3. 多假设探索 + 聚合（ExploreRepair 风格） `[B10]`

- **做法**：
  - 对每个漏洞函数，让 3 个 agent 分别从“输入校验/生命周期/权限”三个维度提出解释和 patch；
  - 一个 Lesson Aggregator 汇总“哪些解释有证据支持”，一个 Patch Aggregator 汇总“哪些改动能修根因”；
  - 最后 Aggregator 选一个 patch，或输出“无法确定”；**不要用 benchmark feedback 选 patch**（ExploreRepair 明确不用 benchmark feedback）。
- **依据**：ExploreRepair 在无 PoV、无准确分类的条件下，DeepSeek-V4.1-Flash 在 PatchEval 上 71.6%，比 EvoRepair +25.4 pp。
- **成本**：3× 生成 + 2× 聚合 ≈ 5× 单次；128 条约 $1–2。先在 30 条上做。
- **风险**：PatchEval 是 Go/JS/Python，不是 C/C++；聚合器可能被“更长/更保守”的 patch 吸引；需要长度/改动量控制。

#### E4. 证据审查（EviRepair 风格） `[B11]`

- **做法**：
  - 在生成 patch 前，让 agent 收集“漏洞证据”（可疑行、缺失 guard、数据流路径）并验证一致性；
  - 如果证据互相矛盾（例如一个说“长度未检查”，另一个说“上游已检查”），先解决矛盾，再修；
  - 构建 `reviewed vulnerability model`（CWE、root cause、trigger、fix strategy），作为 patch 的条件。
- **依据**：EviRepair 在 PatchEval +16.37%、SecBench +40.33%（平均 resolved rate）。
- **成本**：+1–2 次证据请求；可与 E1 合并。
- **风险**：证据审查本身可能引入新的幻觉；需要工具/行号约束。

#### E5. 可执行验证：编译 → sanitizer/PoC → 回归/差分 `[C7][B8][B13]`

- **做法**（按可用性排序）：
  1. **语法/编译**：`gcc -fsyntax-only` 或完整编译；记录 `compile_status`（PASS/FAIL/NOT_RUN）。
  2. **sanitizer**：ASan/LSan/UBSan；用原始 PoC/测试输入跑；记录 `sanitizer_status`。
  3. **回归**：现有测试/行为 harness；记录 `regression_status`。
  4. **差分**：与 ground-truth 修复版本比较函数返回后的可见状态（AutoPatchBench 的白盒差分）；记录 `differential_status`。
- **指标**：报告**阶段 attrition**（apply/compile/PoC/regression/differential 各阶段通过数），不要只报“修复成功”。
- **依据**：AutoPatchBench 显示“编译 + 原输入不崩”会把 60% 生成误判为接近成功，真正正确只有 5–11%；差分测试 precision 41.7%、recall 100%，仍需要人工复核。
- **对本项目**：Juliet CWE-401 已有 LSan harness，可先做 compile + LSan + behaviour；SecVulEval 没有构建环境，只能 `NOT_RUN`，不要伪造。

#### E6. 候选选择：k 个 patch + 静态/动态评分，不用参考相似度 `[B13][C7]`

- **做法**：
  - 生成 k=3–5 个 patch；
  - 用静态检查（编译、括号、改动行在切片内、是否引入新危险 API）和动态检查（sanitizer/测试）打分；
  - 选“通过验证 + 改动最小 + 根因对齐”的 patch；
  - 不用“与参考修复的文本相似度”选 patch（那会奖励记忆/表面相似）。
- **依据**：PatchBench 25% 的 agent 补丁与历史补丁高度相似，说明相似度可能是记忆；AutoPatchBench 的差分测试比文本相似更可靠。
- **成本**：k× 生成 + 验证；先在小样本上做。
- **风险**：没有可靠 oracle 时，静态评分可能选到“看起来对但没修根因”的 patch；需要人工盲评。

### 7.3 无改动修复的根因与对策

本项目 22.1%/44.5%/18.8% 的无实质改动，可能有四个原因：

| 原因 | 证据 | 对策 |
| --- | --- | --- |
| **模型不确定，选择“不改”** | few-shot 无改动率最高（44.5%），尽管 schema 有效率最高（99.0%）；few-shot 示例可能让模型倾向于“保守” | 给 `cannot_fix` 出口；把“不确定”显式化，而不是用原文冒充补丁 |
| **模型只做表面 guard** | AutoPatchBench/PatchBench 的“cheating/表面修复”；本项目无编译/PoC，无法识别 | 根因字段 + `changed_lines` 在切片内 + 差分/回归验证 |
| **长度/复制先验** | 修复通常增加代码；few-shot 示例可能包含“复制原函数+小改”的模式 | 要求 `change_summary` 明确“改了哪一行、为什么”；惩罚只改空白/注释 |
| **任务定义太窄** | 当前 prompt 只说“重写函数，移除安全缺陷”，没有要求“解释根因/触发路径” | 用 E1 的两阶段；先根因，后 patch |

**最小可行改动（不改 runner 代码，只改 prompt/schema 的实验设计）**：
1. 修复请求加 `root_cause`、`changed_lines`、`cannot_fix` 三个字段（可先可选）；
2. 解析时把“无改动/空白变化”单独记 `no_change`，不要混进 `changed`；
3. 对 `no_change` 样本做一次重试，重试 prompt 明确“必须改动至少一个可执行语句，否则返回 cannot_fix”；
4. 报告 `substantive_change_rate`、`cannot_fix_rate`、`usable_patch_yield`，以及盲评 VR=2；不要只报 `changed_from_input`。

---

## 8. 漏洞定位与配对判别

### 8.1 定位：从“函数级二分类”到“语句级证据”

| 文献/项目 | 口径 | 关键数字 | 启示 |
| --- | --- | --- | --- |
| SecVulEval `[A2]` | 语句级、理由正确、多 agent | 最佳 Claude-3.7-Sonnet 语句级 F1 23.83%（P 15.35/R 53.23） | 语句级定位比函数级难得多；F1 低不等于方法差 |
| SBVul `[B5]` | 语句级两阶段 | Phase 1 定位 56–77%；Phase 2 确认 26–73%；patched 侧假确认 23–61%；语句 precision 0.315 @ recall 0.605 | 定位和确认要分开；假确认是 pair 失败的主因之一 |
| VulnGym `[B2]` | 仓库级 EP/CO/Trace | Hard 上 AR 22.58%、ER 15.22%、ES 11.63%；CO 定位 FR 51.16/LR 30.23；EP FR 30.23/LR 18.60；TNP 14.61–26.71 | 入口点识别比关键操作定位更难；trace 精确率很低 |
| VulnAgent-R2 `[B1]` | JITVul Top-1/3 | Top-1 0.529、Top-3 0.742 | 定位可以作为独立目标，不必和 verdict 绑死 |
| Lost in the End `[A13]` | 文件内位置 | 越靠后越差；调整输入大小平均召回 +37% | 位置/长度效应必须控制 |
| 本项目 `[P]` | 证据行 | `±3` 命中近随机；引用行精确率 21.89/25.55%；修复行 exact 召回 16.33/14.61% | 当前“证据行”不是可靠定位；需要候选生成 + 验证 |

**建议的定位指标**（与检测分开报）：
- `candidate_recall@k`：Stage 1 的 k 个候选是否覆盖真实修复行（exact/±3）；
- `line_precision`：引用的行中有多少是修复行；
- `line_recall`：修复行中有多少被引用；
- `localization_auc`：把行级分数当排序，算 AUROC（避免只报 top-k）；
- `grounded_rate`：引用行非空且在范围内（这只是格式合规，不是定位正确）。

### 8.2 配对：文献的绝对值很低，本项目的 76.67% 需要审计

| 方法 | 口径 | 数值 | 备注 |
| --- | --- | --- | --- |
| PrimeVul `[A1]` | P-C/P-V/P-B/P-R；独立判断两侧 | GPT-3.5/4 在严格设置下接近随机；StarCoder2 F1 3.09% | 配对评估的经典基准；不是“强制二选一” |
| Vul-RAG `[A14]` | 区分 vulnerable vs 相似 patched | 仅 **0.06–0.14** 准确率；知识 RAG +16–24% | 直接说明“相似补丁”很难 |
| VulAgent `[A11]` | P-C（两侧都判对） | 26.6%（VulTrial 18.6%）；SVEN 26.5% | 强方法也只有 ~1/4 |
| SBVul `[B5]` | 函数级 pair 正确 | 42.0%（此前最好 33.8%） | 语句级证据帮助有限 |
| 本项目 joint `[P]` | 同一次请求强制 A/B | DeepSeek 76.67%、MiMo 86.67% | 任务不同；长度启发式 74.44%；A 偏差 31.11 pp |

**关键判断**：
- 76.67% 远高于文献的 26.6–42.0%，第一反应应该是“任务更容易/存在伪影”，而不是“方法更强”。本项目已经找到两个伪影：长度（74.44%）和位置（31.11 pp）。
- 文献的 P-C 是“两侧都判对”，本项目 joint 是“强制选一个”；两者不能直接比较。**报告时必须写清口径，并把 joint 的开放 both/neither 版本作为对照。**
- 如果要在论文里主张“pair 判别提升”，至少需要：A/B+B/A 双顺序、长度匹配子集、开放 both/neither、与长度 oracle 对照。缺一个，审稿人都会问。

### 8.3 位置偏差与长度混淆：本项目已有什么、还缺什么

**已有**：
- 联合 A/B：DeepSeek A 侧 92.22% vs B 侧 61.11%（31.11 pp，Fisher p=1.0e-06）；选 A 118/180（65.56%）；MiMo 88.89% vs 84.44%（4.44 pp，p=0.5114），位置偏差小。
- 长度启发式：选较短版本 134/180=74.44%（字符），133/180=73.89%（行数）；DeepSeek 76.67% 与字符启发式 McNemar p=0.6587（不可区分）；MiMo 86.67% vs 74.44%，p=0.0003（显著高于长度）。
- 分层：漏洞更短 130 对、更长 44 对、等长 6 对；DeepSeek 在“漏洞更长”44 对上 56.82%，在“漏洞更短”130 对上 83.85%（低于 100% 的长度 oracle）。

**缺什么**：
1. **A/B + B/A 双顺序**：当前只随机一次；无法区分“位置偏好”与“该位置代码更易判”的交互。加 B/A 后，主终点是双顺序平均 DA，次终点是 flip rate。
2. **长度匹配子集**：当前 180 对里 130 对漏洞更短；需要构造 `|Δchars|/max ≤5%`、`|Δlines| ≤1` 的子集（≥100 对），让长度 oracle 退化到 50%（tie 规则除外）。
3. **开放 both/neither**：当前强制二选一，消除了分侧基线的 113/108 个 `both_safe`；这会让 DA 看起来高，但不是“判别力”。需要开放版本，报告 both_safe/both_vulnerable/reversed。
4. **位置平衡评分**：两次顺序不一致时，不要算正确；标 `order_unstable`，或进入第三次证据裁决。
5. **证据先行**：当前 prompt 已要求证据，但证据合规率 98% 不等于证据正确；需要“先引用差异行，再选边”，并对“两侧都有证据”输出 uncertain。

**文献支持**：
- 2026 年位置偏差综合研究 `[B16]`：十亿到万亿参数、5 种语言、MCQ + 多文档；位置偏差在小模型/非英语仍明显；规模扩大和标准 CoT 显著缓解；thinking 模型近免疫。**注意**：这项研究不是 C/C++ pair，不能直接外推；但它支持“CoT/thinking 可能缓解”“小模型更严重”。
- EACL 2026 代码 judge `[A20]`：六类偏差、5 种语言、多个 LLM；所有 judge 都对表面变化敏感；即使要求先生成测试再评分，仍然脆弱。**含义**：不要指望“让模型更努力想”就消除偏差；需要程序性控制（swap、长度匹配、盲评）。
- 本项目 `[P]`：prompt 已经写“顺序/字母/代码量不携带信息”（`pair_joint/common.py:240`），但 A 偏差仍然 31.11 pp。**这是“指令式去偏”无效的直接证据。**

### 8.4 方法卡片

#### F1. A/B + B/A 双顺序，报告 per-order 与 flip rate `[B16][A20]`

- **做法**：
  - 每对跑两次：原顺序（A=vuln 或 B=vuln）和交换顺序；两次使用同一 prompt、同一模型、temperature=0；
  - 主终点：`mean_DA = (DA_AB + DA_BA)/2`；
  - 次终点：`flip_rate = P(choice_AB ≠ choice_BA)`；`order_gap = |DA_AB − DA_BA|`；
  - 如果两次不一致，标 `order_unstable`；在“严格 DA”里算错，在“稳定 DA”里排除，两个都报。
- **成本**：360 次请求；按现有 pair 单价约 $0.3（DeepSeek）+ $0.14（MiMo）。
- **判据**：如果 `order_gap` 仍然 >10 pp，说明位置偏差不是“单次随机”能解决的，需要 F3/F6；如果 `flip_rate` 很高（>20%），说明模型对顺序高度敏感，不能把单次结果当能力。

#### F2. 长度匹配子集 + 长度 oracle 对照 `[P][A20]`

- **做法**：
  - 从现有 180 对中筛出 `|Δchars|/max ≤5%` 且 `|Δlines| ≤1` 的子集；如果不足 100 对，从同一项目/函数族构造新对（注意不要跨项目泄漏）；
  - 在子集上重跑 A/B+B/A；
  - 主终点：`mean_DA` vs 50%（随机）和 vs 长度 oracle（在匹配子集上应接近 50%）；
  - 同时报告原 180 对、匹配子集、按 Δlength 分层的 DA。
- **依据**：本项目已实测长度启发式 74.44%；如果不控制长度，任何 pair 提升都可能是“修复通常更长/更短”的伪影。
- **成本**：子集 100 对 × 2 顺序 × 2 模型 ≈ 400 次，约 $0.3–0.6。
- **风险**：匹配子集可能改变难度分布；需要报告匹配前后的难度（CWE/项目/函数长度）。

#### F3. 证据先行的 pair prompt：先引用差异行，再选边 `[A11][B5]`

- **做法**：
  1. 先让模型列出“两版之间与安全相关的差异行”（每侧最多 3 行），并说明差异是“增加了检查/删除了危险操作/改了长度/无安全差异”；
  2. 再让模型选 `vulnerable_version`；
  3. 如果差异行在两侧都有“危险操作”，或模型说不出差异，输出 `uncertain`；
  4. 证据必须引用具体行号；如果引用行在两侧相同，判 `non_discriminative`。
- **依据**：VulAgent 的“假设条件+路径验证”降低 FPR；SBVul 的 Phase 2 要求证据，空结果不算证据；本项目证据行精确率只有 21.89%，说明“先选边再补证据”是倒置的。
- **成本**：同一次请求内完成（更长的输出），或拆成两次；180 对约 $0.2–0.4。
- **风险**：差异行可能泄漏“修复在哪”，让任务变简单；但这是更真实的“代码审查”任务，且可以用“只给差异摘要、不给完整 diff”控制泄漏。

#### F4. Diff-first / change-focused prompt `[A13][A11]`

- **做法**：
  - 不把两个完整函数并列，而是给“变更块（hunk）+ 上下文各 5 行”，问“这个变更是否消除了一个安全缺陷？为什么？”
  - 或者给“函数 A、函数 B、以及它们的安全相关差异摘要”，让模型判断哪一版仍含缺陷；
  - 这样可以把注意力从“整体长度/风格”转到“变更语义”，降低长度先验。
- **依据**：Lost in the End 说明长输入/位置会伤害检测；VulAgent 的假设验证强调“变更是否影响 trigger path”；本项目长度先验是主要混淆。
- **风险**：diff 可能直接暴露修复，任务变得太容易；适合做“上界”实验，不适合作为主榜。需要与“完整函数”版本对照，报告差异。

#### F5. 开放 both/neither，分开报告三类输出 `[A1][A11]`

- **做法**：
  - 允许 `vulnerable_version ∈ {A, B, both, neither, uncertain}`；
  - 报告 `correct`、`both_vulnerable`、`both_safe`、`reversed`、`uncertain` 五类；
  - 主指标：`P-C`（两侧都判对）、`P-R`（判反）、`VPS = P-C − P-R`（VulAgent 用的口径）；
  - 强制二选一作为次要指标，明确写“强制选择改变了任务”。
- **依据**：PrimeVul 的 P-C/P-V/P-B/P-R 是配对评估的标准；VulAgent 用 P-C/P-R/VPS；本项目 joint 强制二选一消除了 both_safe，导致 DA 不可比。
- **成本**：同一次请求；不需要额外调用。
- **风险**：开放选项可能让模型过度输出 `both/neither`，降低有效覆盖率；需要报告 `valid_rate` 和 `uncertain_rate`。

#### F6. 位置平衡评分 + 证据裁决 `[B16][A20]`

- **做法**：
  - 两次顺序都选同一侧 → 采用；
  - 两次顺序选不同侧 → 不直接算对/错；用“证据是否只在所选侧出现”裁决；如果证据也矛盾，标 `uncertain`；
  - 对“总是选 A”的模型，计算 `A-selection rate`；如果显著偏离 50%，在报告里标注“位置偏差未消除”；
  - 可选：对位置偏差严重的模型，启用 thinking/CoT（文献说可缓解），但成本会上升；先在小样本上验证。
- **依据**：本项目 DeepSeek 选 A 118/180（65.56%），A 侧 DA 92.22% vs B 侧 61.11%；MiMo 位置偏差小。位置偏差是模型特定的，不是任务固有的；需要按模型报告。
- **风险**：证据裁决本身可能引入新的 LLM judge 偏差；最好用规则（差异行是否只在所选侧）而不是再调一个模型。

### 8.5 建议的 pair 指标表

| 指标 | 定义 | 为什么要报 |
| --- | --- | --- |
| `DA_AB` / `DA_BA` | 原顺序/交换顺序的判别准确率 | 分离位置效应 |
| `mean_DA` | 两顺序平均 | 主终点；对位置偏差更稳健 |
| `flip_rate` | 两顺序选择不同的比例 | 衡量顺序敏感性 |
| `order_gap` | `abs(DA_AB − DA_BA)` | 位置偏差的效应量 |
| `P-C` | 两侧都判对的比例 | 与 PrimeVul/VulAgent 可比 |
| `P-R` | 判反的比例 | 负向错误 |
| `VPS` | `P-C − P-R` | 净判别力 |
| `both_safe` | 两侧都判安全 | 本项目分侧基线的主失败模式（113/108） |
| `both_vulnerable` | 两侧都判漏洞 | 过度报警 |
| `length_oracle_DA` | “选较短版本”的 DA | 必须打败的朴素基线 |
| `DA_on_length_matched` | 长度匹配子集上的 DA | 排除长度伪影 |
| `evidence_precision` | 引用行中真实修复行的比例 | 证据是否可信 |
| `order_unstable_rate` | 两顺序不一致且无法裁决的比例 | 不确定性 |

---

## 9. 建议的实验矩阵（设计，未执行）

> **重要**：本节全部是**建议设计**，本次任务没有运行任何实验。所有成本是按现有单价和请求数做的**估算**，不是实测。执行前需要主代理批准、冻结 split、预注册主终点。

### 9.1 P0：只读复分析，不改 prompt、不调 API（最高优先级）

| 项目 | 设计 |
| --- | --- |
| 目标 | 把“schema 失败”拆成 fatal / recoverable，重算 usable-patch yield |
| 数据 | DeepSeek 现有 `runner/runs/test_v1_*/results.jsonl`（3 策略 × 308 修复请求）；MiMo 的 70 条 invalid 另算 |
| 条件 | 不改任何文件；新脚本只读旧 JSONL，输出到 `analysis/schema_recovery/` |
| 主终点 | `usable_patch_yield = 结构完整 + 有实质改动 / 全部请求` |
| 次终点 | `strict_schema_valid`、`missing_explanation`、`extra_keys`、`no_change`、`whitespace_only`、按策略/模型/CWE 分层 |
| 对照 | 当前严格口径（`validation.py:88` 键集合完全相等） |
| 样本量 | DeepSeek 三策略 924 条修复请求（如扩展到 MiMo，另算 924 条） |
| 成本 | $0（只读） |
| 验收线 | 如果 usable_patch_yield 比 strict_schema_valid 高 ≥5 pp，说明当前 schema 口径显著低估修复产出；后续所有修复指标都要同时报两个口径 |
| 停止规则 | 如果差值 <2 pp，说明 schema 不是主要问题，把优先级转到 P1/P3 |

**为什么先做**：它不需要新 API、不会污染旧结果、能在一天内完成，而且直接回答“102 条 invalid 里有多少是真废、多少是被解析器丢掉”。

### 9.2 P1：配对 A/B + B/A 双顺序（低成本、高信息量）

| 项目 | 设计 |
| --- | --- |
| 目标 | 分离“位置偏差”“长度先验”“跨版本推理” |
| 数据 | `splits/test_pairs_180.json`（冻结 180 对） |
| 条件 | 2 个模型（DeepSeek-V4.1-Flash、MiMo-V2.6-Flash）× 2 顺序（AB/BA）× 同一 prompt；temperature=0；thinking=disabled（与现有 pair_joint 一致） |
| 主终点 | `mean_DA = (DA_AB + DA_BA)/2` |
| 次终点 | `flip_rate`、`order_gap`、`P-C`、`P-R`、`VPS`、`both_safe`、`both_vulnerable`、`length_oracle_DA`、`DA_on_length_matched` |
| 对照 | 现有单顺序 joint（76.67/86.67）；长度 oracle（74.44%）；50% 随机 |
| 样本量 | 180 对 × 2 顺序 × 2 模型 = 720 次请求 |
| 成本估算 | DeepSeek 约 $0.31；MiMo 约 $0.14；合计约 $0.45（按现有 pair 单价） |
| 验收线 | 若 `mean_DA − length_oracle_DA ≥ 10 pp` 且 `order_gap ≤ 10 pp`，才能主张“超出长度/位置的配对判别”；若 `mean_DA` 与长度 oracle 不可区分，停止在 pair 上堆方法，转向 P2/P3 |
| 停止规则 | 如果 `flip_rate > 25%`，说明单次结果不可用；后续所有 pair 报告必须用双顺序平均 |

**关键细节**：
- 不改现有 `pair_joint/` 的 run；新建 `pair_joint/runs/test_abba_*`。
- 每对的两个顺序使用同一 `pair_id`，但 `position_map` 要分别记录；不要覆盖旧 `position_map.json`。
- 主分析用项目聚类 bootstrap（按 project），配对级 bootstrap 作为敏感性；McNemar 精确检验。
- 预先定义“正确”：只有选对漏洞侧才算 correct；`both/neither/uncertain` 单独计类，不算 correct。

### 9.3 P2：长度匹配子集（验证长度先验是否可消除）

| 项目 | 设计 |
| --- | --- |
| 目标 | 构造字符长度差不超过 5%、行数差不超过 1 的配对子集，让长度 oracle 退化到 ~50% |
| 数据 | 现有 180 对中筛；不足 100 对时，从同一项目/函数族构造新对（≥100 对） |
| 条件 | A/B+B/A；2 模型；同 P1 prompt |
| 主终点 | `mean_DA` vs 50% 和 vs 匹配子集上的长度 oracle |
| 次终点 | 分层 DA（按 CWE、项目、函数长度）、`DA_on_length_matched`、`flip_rate` |
| 样本量 | 100 对 × 2 顺序 × 2 模型 = 400 次 |
| 成本估算 | 约 $0.25–0.35 |
| 验收线 | 匹配子集上 `mean_DA ≥ 65%` 且显著高于 50%（Wilson CI 下界 >50%），才能说“不是长度先验” |
| 风险 | 匹配子集可能太小/太难；需要报告匹配前后的难度分布，避免选择偏差 |

**注意**：如果现有 180 对里匹配对太少，构造新对时要避免“同一函数族/同一 CWE”带来的泄漏；最好从不同项目抽，或按项目分层。

### 9.4 P3：语句优先的两阶段检测（针对低召回）

| 项目 | 设计 |
| --- | --- |
| 目标 | 把“发现”和“裁决”拆开，测 candidate recall 与最终 recall/FPR |
| 数据 | 独立集 160 条（128 vuln/32 non-vuln）；先用 40 条分层 pilot |
| 条件 | Stage 1：高召回候选（每函数 1–5 个敏感操作 + 行号 + CWE）；Stage 2：条件/路径验证（valid/plausible/contradicted）；最终 verdict = 至少一个 retained |
| 对照 | 现有 M1 direct；现有 evidence prompt（recall 38.58/FPR 34.38） |
| 主终点 | 固定 FPR（≤25%）下的 recall；`candidate_recall@5`（是否覆盖真实修复行） |
| 次终点 | Stage 1 候选数、Stage 2 retained rate、`line_precision`、`line_recall`、成本 |
| 样本量 | 40 条 pilot → 160 条全量；Stage 1 160 次 + Stage 2 每函数 1–5 个候选（约 300–800 次） |
| 成本估算 | 约 $0.3–0.8（取决于候选数/输出长度） |
| 验收线 | 固定 FPR ≤25% 时 recall ≥45%（比 baseline +15 pp），且 `candidate_recall@5 ≥70%`；如果 recall 上升但 FPR 也上升，只算“操作点移动”，不算能力提升 |
| 停止规则 | 如果 Stage 1 candidate recall <50%，说明“候选生成”本身不行，先改候选 prompt/CWE 知识卡，不要加 Stage 2 |

**关键细节**：
- Stage 1 的 prompt 不要求 verdict，只要求“可疑的敏感操作 + 行号 + 为什么”；这能避免模型过早下“安全”结论。
- Stage 2 必须看到 Stage 1 的候选和上下文；不要让 Stage 2 重新从零判断，否则会退回单次分类。
- 评测时把 Stage 1 的候选行与真实修复行做 exact/±3 匹配；不要用 `grounded_rate` 代替定位正确率。

### 9.5 P4：真实项目子集上的工具/上下文（中成本，后置）

| 项目 | 设计 |
| --- | --- |
| 目标 | 在 30–50 个真实 C/C++ 项目上测 CodeQL/Semgrep/ASan 证据的边际收益 |
| 数据 | 从 PrimeVul Paired 或可 checkout 的真实 CVE 对中抽 30–50 对；或 Juliet 已有的 140 单元 |
| 条件 | 无工具 / 静态工具（CodeQL 或 Semgrep）/ 动态工具（ASan/LSan）/ 组合 / shuffled 安慰剂 |
| 主终点 | 固定 FPR 下 recall；工具覆盖率；工具结论 precision/recall |
| 对照 | matched-context（给同样多随机上下文）；项目已有 Juliet 5 条件 |
| 样本量 | 30–50 对；先做功效分析，不要用 5 个单元声称显著 |
| 成本 | 工程 2–4 周；API 约 $10–50 |
| 验收线 | 工具覆盖率 ≥60%，且在固定 FPR 下 recall 比 matched-context 高 ≥10 pp；否则只报告“工程可行性”，不声称能力提升 |
| 风险 | 构建失败/依赖缺失；必须把 inconclusive 单独计，不能当 safe |

### 9.6 P5：修复的根因门 + 改动门（针对无改动修复）

| 项目 | 设计 |
| --- | --- |
| 目标 | 降低 no-change/表面修复，提高 substantive change 和可编译率 |
| 数据 | 128 条独立漏洞函数（或 Juliet CWE-401 的 70 bad） |
| 条件 | 当前 repair prompt / +root_cause+trigger_path / +changed_lines+cannot_fix / 三者组合 |
| 对照 | 现有 M1/M2/M3 repair；严格 schema vs usable patch |
| 主终点 | `substantive_change_rate`（折叠空白后仍不同）；`no_change_rate`；`cannot_fix_rate` |
| 次终点 | `compile_status`（Juliet）、LSan 行为、盲评 VR=2、`changed_lines` 是否在切片内 |
| 样本量 | 128 × 4 条件 ≈ 512 次；先做 30 条 pilot |
| 成本估算 | 约 $0.3–0.6 |
| 验收线 | substantive change ≥80%、no_change ≤10%、Juliet compile ≥90%；盲评 VR=2 不低于当前 21.0%（17/81），且 no-change 候选的 VR=2 仍为 0 |
| 停止规则 | 如果 cannot_fix_rate >30%，说明任务太难/信息不足，先补上下文，不要硬压 no_change |

### 9.7 P6：结构化输出 A/B（针对 schema）

| 项目 | 设计 |
| --- | --- |
| 目标 | 比较 `json_object` vs `json_schema`（若可用）vs 两阶段抽取 |
| 数据 | 100 条修复请求（分层：CWE/策略/模型） |
| 条件 | A：当前 `json_object`；B：`json_schema` strict（如果 provider 支持）；C：自由推理 + 第二次结构化抽取 |
| 主终点 | `usable_patch_yield`；`strict_schema_valid`；`missing_explanation` |
| 次终点 | `format_repaired` 比例、`content_changed` 比例、成本、延迟 |
| 样本量 | 100 × 3 = 300 次 |
| 成本估算 | 约 $0.1–0.2 |
| 验收线 | usable yield 提升 ≥10 pp，且 content_changed 不下降；如果只是 format_repaired 上升，不算能力提升 |
| 风险 | DeepSeek/OpenCode Go 可能不支持 `json_schema`；先做 5 条探测，不要假设 |

### 9.8 P7：FN 标签审计（针对“低召回是否真实”）

| 项目 | 设计 |
| --- | --- |
| 目标 | 估计 FN 中有多少是标签错误/提交级传播/不可利用 |
| 数据 | 从 87–90 个 FN 中分层抽 30–50 条（按 CWE、函数长度、项目） |
| 条件 | 人工/半自动审查：函数是否真的含可利用缺陷？修复 commit 是否只改了该函数？是否有上游 guard？ |
| 主终点 | `confirmed_FN_rate`；`label_error_rate`；`corrected_recall` |
| 对照 | 原始标签；VulValidate 风格的“可执行证据”审计（如果可构建） |
| 样本量 | 30–50 条；报告 Wilson CI，不做过度推断 |
| 成本 | 人工 1–2 周；API 成本低 |
| 验收线 | 如果 label_error_rate ≥15%，后续所有召回结论都要带“标签噪声”敏感性分析；如果 <5%，可以继续把 FN 当模型漏报 |
| 风险 | 审查本身有主观性；至少两人独立，报告 Cohen's κ |

### 9.9 功效与停止规则

- **配对实验**：180 对，McNemar 精确检验；如果预期差异 <10 pp，功效不足。不要用 20 对做“显著”声明。
- **独立集**：128 个漏洞；recall 从 30% 到 45% 约 +19 TP，McNemar 可检测；从 30% 到 35% 只有 +6 TP，功效有限。
- **多重比较**：P1–P6 是一个 family 吗？不是。每个实验应有自己的主终点；如果共享同一数据集做多次比较，报告 Holm 校正或明确标“探索性”。
- **停止规则**：
  - P1 如果 `mean_DA` ≈ 长度 oracle，停止在 pair 上堆方法，转 P2/P3；
  - P3 如果 recall 上升但 FPR 同幅上升，停止宣称“检测提升”，转“操作点/路由”研究；
  - P5 如果 cannot_fix 率过高，停止压 no-change，转上下文/根因；
  - P4 如果工具覆盖率 <40%，停止“工具普遍有效”的叙事，只报告可行性。

---

## 10. 参考文献核验表

> **说明**：下表只列本文件实际引用/讨论的条目。`A` = 正式发表；`B` = 预印本；`C` = 官方文档/工具/厂商博客。日期为论文/文档的公开日期或访问日期；预印本给 v1 日期，必要时给最新版本。页码不可得时写“仅会议页/arXiv”。所有条目均通过 arXiv abs/HTML、ACL Anthology、DROPS、Crossref、USENIX/NeurIPS 页面或项目现有核验记录交叉核对（2026-11-13）；未能直接打开的 DOI 页面以 Crossref/会议页/项目记录为准。DOI 可解析为 `https://doi.org/<DOI>`；arXiv ID 可解析为 `https://arxiv.org/abs/<ID>`。

### 10.1 正式发表（A）

> A15（Semantic Entropy, 2024）、A19（Let Me Speak Freely, 2024）、A22（Self-Consistency, 2023）是背景基线，列在此处是为了解释 2025–2026 方法的对照，不代表它们是 2025–2026 的最新工作。

| ID | 文献 | 出处 / DOI | 日期 | 关键点 |
| --- | --- | --- | --- | --- |
| A1 | Ding et al., *Vulnerability Detection with Code Language Models: How Far Are We?* | ICSE 2025, pp. 1729–1741; DOI `10.1109/ICSE55347.2025.00038`; arXiv:2403.18624 | ICSE 2025（arXiv v1 2024-03-27） | PrimeVul；6,968 漏洞函数/228,800 良性；5,480 对；配对评估 P-C/P-V/P-B/P-R |
| A2 | Ahmed et al., *SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection* | AIware 2026, pp. 388–396; DOI `10.1145/3805760.3814932`; arXiv:2505.19828 | AIware 2026（arXiv v1 2025-05-26） | 25,440 函数/5,867 CVE/707 项目；语句级 F1 23.83%（Claude-3.7-Sonnet） |
| A3 | Li, Dutta, Naik, *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities* | ICLR 2025; OpenReview `9LdJDU7E91`; arXiv:2405.17238 | ICLR 2025（arXiv v1 2024-05-27） | CWE-Bench-Java 120；CodeQL 27 → IRIS 55；FDR +5 pp |
| A4 | Guo et al., *RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing* | ICML 2025, PMLR 267:21083–21100; arXiv:2501.18160 | ICML 2025（arXiv v1 2025-01-30） | 15 项目/40 真 bug/78.43% precision；0.44h、$2.54/项目 |
| A5 | Yang et al., *KNighter: Transforming Static Analysis with LLM-Synthesized Checkers* | SOSP 2025, pp. 655–669; DOI `10.1145/3731569.3764827`; arXiv:2503.09002 | SOSP 2025（arXiv v1 2025-03-12） | 从历史补丁合成 checker；Linux 92 新 bug/77 确认/57 修复/30 CVE |
| A6 | Abramovich et al., *EnIGMA: Interactive Tools Substantially Assist LM Agents in Finding Security Vulnerabilities* | ICML 2025; arXiv:2409.16165 | ICML 2025（arXiv v1 2024-09-24） | 交互式 debugger/server 工具；390 CTF；soliloquizing |
| A7 | Lekssays et al., *LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models* | USENIX Security 2025, pp. 489–507 | USENIX Security 2025 | CPG 切片减 67.84–90.93%；F1 +15–40% |
| A8 | Lee et al., *SEC-bench: Automated Benchmarking of LLM Agents on Real-World Software Security Tasks* | NeurIPS 2025; arXiv:2506.11791 | NeurIPS 2025（arXiv v1 2025-06-13） | PoC ≤18%、修复 ≤34%；$0.87/实例 |
| A9 | Bouzenia, Devanbu, Pradel, *RepairAgent: An Autonomous, LLM-Based Agent for Program Repair* | ICSE 2025, pp. 2188–2200; DOI `10.1109/ICSE55347.2025.00157`; arXiv:2403.17134 | ICSE 2025（arXiv v1 2024-03-25） | 自主 agent 循环：定位→分析→修→验证 |
| A10 | Xia et al., *Demystifying LLM-Based Software Engineering Agents* (Agentless) | PACMSE 2(FSE):801–824; DOI `10.1145/3715754`; arXiv:2407.01489 | FSE 2025（2025-06-19） | 三阶段 localization/repair/validation；SWE-bench Lite 32.00%（96/300），$0.70 |
| A11 | Wang et al., *VulAgent: Hypothesis-Validation Driven Multi-Agent Architecture for Vulnerability Detection* | Findings of ACL 2026, pp. 18598–18616; DOI `10.18653/v1/2026.findings-acl.928` | ACL 2026（2026-07） | 高召回多视图 → 假设（条件+路径）→ 验证；P-C 26.6%；FPR 36.7%；pair 2.46× 平均/4.5× 最高 |
| A12 | Tsai et al., *A Sequential Multi-Stage Approach for Code Vulnerability Detection via Confidence- and Collaboration-Based Decision Making* | EMNLP 2025, pp. 21151–21157; DOI `10.18653/v1/2025.emnlp-main.1071` | EMNLP 2025 | 单 agent → RAG → 多 agent+RAG；高置信停止 |
| A13 | Sovrano, Bauer, Bacchelli, *Large Language Models for In-File Vulnerability Localization Can Be "Lost in the End"* | PACMSE 2(FSE):891–913; DOI `10.1145/3715758`; arXiv:2502.06898 | FSE 2025（arXiv v1 2025-02-09） | 文件内位置效应；调整输入大小平均召回 +37% |
| A14 | Du et al., *Vul-RAG: Enhancing LLM-based Vulnerability Detection via Knowledge-level RAG* | ACM TOSEM 2026; DOI `10.1145/3797277`; arXiv:2406.11147 | TOSEM 2026（ACM online 2025-10-09；arXiv v1 2024-06-17） | LLM 对 vulnerable vs 相似 patched 仅 0.06–0.14；知识 RAG +16–24% |
| A15 | Farquhar et al., *Detecting Hallucinations in Large Language Models Using Semantic Entropy* | Nature 630:625–630; DOI `10.1038/s41586-024-07421-0` | 2024-06-19 | 意义级不确定性；可用于拒答/abstention |
| A16 | Geng et al., *JSONSchemaBench: A Rigorous Benchmark of Structured Outputs for Language Models* | ICML 2025; arXiv:2501.10868 | ICML 2025（arXiv v1 2025-01-18） | 10K 真实 schema；6 引擎；效率/覆盖/质量差异 |
| A17 | Dong et al., *XGrammar: Flexible and Efficient Structured Generation Engine for Large Language Models* | MLSys 2025; arXiv:2411.15100 | MLSys 2025（arXiv v1 2024-11-22） | CFG 约束；最高 100× 加速；近零开销 |
| A18 | Ugare et al., *SynCode: LLM Generation with Grammar Augmentation* | TMLR 2025; arXiv:2403.01632 | TMLR 2025（arXiv v1 2024-03-03） | 消除全部 JSON 语法错误；Python/Go 语法错误 −96.07% |
| A19 | Tam et al., *Let Me Speak Freely? A Study on the Impact of Format Restrictions on Large Language Model Performance* | EMNLP 2024 Industry, pp. 1218–1236; DOI `10.18653/v1/2024.emnlp-industry.91`; arXiv:2408.02442 | EMNLP 2024（arXiv v1 2024-08-05） | 格式限制降低推理；越严越差 |
| A20 | Moon et al., *Don't Judge Code by Its Cover: Exploring Biases in LLM Judges for Code Evaluation* | Findings of EACL 2026, pp. 1364–1389; DOI `10.18653/v1/2026.findings-eacl.70` | EACL 2026（2026-03） | 六类偏差；5 语言；所有 judge 对表面变化敏感；生成测试也挡不住 |
| A21 | Chen et al., *Do LLM Vulnerability-Detection Agents Reason Better? An Empirical Decomposition of Robustness, Resistance, and Grounding* | ESEM 2026, pp. 28:1–28:21; DOI `10.4230/LIPIcs.ESEM.2026.28` | ESEM 2026（2026-10） | 六条件/六模型；agent 提升多来自上下文或“更常报漏洞”，不是推理 |
| A22 | Wang et al., *Self-Consistency Improves Chain of Thought Reasoning in Language Models* | ICLR 2023; arXiv:2203.11171 | ICLR 2023 | 多采样 CoT + 投票；是“多采样”的基线 |

### 10.2 预印本（B）

| ID | 文献 | arXiv / DOI | 日期 | 关键点 |
| --- | --- | --- | --- | --- |
| B1 | Meng et al., *VulnAgent-R2: Evidence-Calibrated Multi-Agent Auditing for Repository-Level Vulnerability Detection* | arXiv:2603.13384; DOI `10.48550/arXiv.2603.13384` | v1 2026-03-11；v3 2026-06-03 | 图 triage、CER、VPS、校准；PrimeVul F1 .385；验证 21.6% 触发/25.8% inconclusive |
| B2 | Ji et al., *VulnGym: Benchmarking Coding Agents for Repository-Level Vulnerability Detection* | arXiv:2608.02001; DOI `10.48550/arXiv.2608.02001` | 2026-08-03 | 184 advisories/408 entries/23 repos；Hard 最强 AR 22.58%、ER 15.22%、ES 11.63% |
| B3 | Feiglin, Dar, *SastBench: A Benchmark for Testing Agentic SAST Triage* | arXiv:2601.02941; DOI `10.48550/arXiv.2601.02941` | 2026-01-06 | 真实 CVE 作 TP + 过滤 SAST 告警作近似 FP；agent-agnostic triage |
| B4 | Li et al., *ContextBench: A Benchmark for Context Retrieval in Coding Agents* | arXiv:2602.05892; DOI `10.48550/arXiv.2602.05892` | 2026-02-05 | 1,136 任务/66 仓库/8 语言；scaffolding 边际收益；重召回轻精确 |
| B5 | Pinzger et al., *SBVul: Statement-Based Vulnerability Detection* | arXiv:2611.06135; DOI `10.48550/arXiv.2611.06135` | 2026-11-04 | Phase 1 定位 56–77%；Phase 2 确认 26–73%；patched 假确认 23–61%；pair 42.0% |
| B6 | Zhang et al., *VulValidate: Auditing Function-Level Vulnerability Labels with Executable Evidence* | arXiv:2610.05103; DOI `10.48550/arXiv.2610.05103` | 2026-10-04 | 35,849 条审计；57.2% 确认/19.0% 改正/22.3% 未决；改正后 F1 下降 |
| B7 | Wang, *ARQ: Agentic CodeQL Query Refinement for C/C++ Vulnerability Detection* | arXiv:2608.20637; DOI `10.48550/arXiv.2608.20637` | 2026-08-21 | 执行反馈修 CodeQL；真阳性 +119.8%，precision ≥98% |
| B8 | Hou et al., *Revelio: Cost-Efficient Agentic Memory Safety Vulnerability Detection for Repository-Scale Codebases* | arXiv:2606.22263; DOI `10.48550/arXiv.2606.22263` | 2026-06-20 | 可执行 PoV + sanitizer；7 项目 + 100 Arvo/CyberGym；$300；19 未知漏洞 |
| B9 | Wei et al., *PATCHEVAL: A New Benchmark for Evaluating LLMs on Patching Real-World Vulnerabilities* | arXiv:2511.11019; DOI `10.48550/arXiv.2511.11019` | 2025-11-14 | 1,000 CVE/65 CWE/230 sandbox；Go/JS/Python |
| B10 | Tran et al., *ExploreRepair: Evidence-Specialized Agents for Vulnerability Repair under Information Constraints* | arXiv:2610.39899; DOI `10.48550/arXiv.2610.39899` | 2026-10-29 | 3 探索 agent + 聚合；PatchEval 39.6%/71.6%（DeepSeek-V4.1-Flash）；+16.0/+25.4 pp |
| B11 | Shi et al., *EviRepair: Evidence-Driven Agents for Reliable Vulnerability Repair* | arXiv:2610.13491; DOI `10.48550/arXiv.2610.13491` | 2026-10-09 | 证据审查；PatchEval +16.37%、SecBench +40.33% resolved rate |
| B12 | Fu et al., *AgenticRepair: Multi-Faceted Program Context Engineering for Agentic Vulnerability Repair* | arXiv:2607.29422; DOI `10.48550/arXiv.2607.29422` | 2026-07-31 | 代码结构/运行时/提交历史三类上下文；SEC-bench 300 实例 73%，+29% |
| B13 | Shen et al., *PatchBench: Evaluating AI Agents for Vulnerability Patching* | arXiv:2609.04075; DOI `10.48550/arXiv.2609.04075` | 2026-09-03 | 25% 补丁与历史开发者补丁高度相似；PoC-only 抬高 1.83×；表面修复 |
| B14 | Chen, Qu, Wang, *The Calibration Floor: Format Repair Can Masquerade as Self-Correction at Small-to-Mid Scale* | arXiv:2608.04355; DOI `10.48550/arXiv.2608.04355` | 2026-08-05 | 12 格 format > content（p=1.7e-3）；G-CD 关掉中位 71% 表观增益；frontier 5 格 content margin 0 |
| B15 | Nguyen et al., *Constrained Decoding: Harmful or Beneficial? Revisiting Its Impact on LLM Performance* | arXiv:2610.35328; DOI `10.48550/arXiv.2610.35328` | 2026-10-26 | format/validity/reasoning 三类约束；退化多来自非等价 prompt/格式；validity 提升可靠性 |
| B16 | Li et al., *On the Position Bias of Large Language Models: A Comprehensive Study* | arXiv:2610.22807; DOI `10.48550/arXiv.2610.22807` | 2026-10-16 | 十亿–万亿参数、5 语言、MCQ+多文档；规模/CoT 缓解；thinking 近免疫 |
| B17 | Camarato et al., *PromptAudit: Auditing Prompt Sensitivity in LLM-Based Vulnerability Detection* | arXiv:2605.24171; DOI `10.48550/arXiv.2605.24171` | 2026-05-22 | 5 策略/5 模型/1,000 CVE/6,074 样本/16 语言；CoT 最好；SC 过度 abstention |
| B18 | Brown et al., *Large Language Monkeys: Scaling Inference Compute with Repeated Sampling* | arXiv:2407.21787; DOI `10.48550/arXiv.2407.21787` | v1 2024-07-31；v3 2024-12-30 | coverage 对数线性；SWE-bench Lite 15.9%→56%（250 样本）；多数投票饱和 |

### 10.3 官方文档/工具/厂商博客（C）

| ID | 文档 | URL | 访问日期 | 关键点 |
| --- | --- | --- | --- | --- |
| C1 | OpenAI, *Structured Outputs* | https://platform.openai.com/docs/guides/structured-outputs | 2026-11-13 | `json_schema` strict 保证 schema adherence；JSON mode 只保证合法 JSON；所有字段 required；refusal/截断仍可能 |
| C2 | DeepSeek, *JSON Output* | https://api-docs.deepseek.com/guides/json_mode/ | 2026-11-13 | `response_format={"type":"json_object"}`；只承诺合法 JSON；需 prompt 含 “json”；`max_tokens` 不足会截断；文档/镜像提示可能空 content |
| C3 | vLLM, *Structured Outputs* | https://docs.vllm.ai/en/latest/features/structured_outputs.html | 2026-11-13 | 支持 xgrammar/guidance；json/regex/grammar/choice/structural_tag；backend 语法差异会影响允许 token |
| C4 | GitHub, *CodeQL documentation* | https://codeql.github.com/docs/ | 2026-11-13 | 把代码当数据查询；CWE 覆盖；query help |
| C5 | Semgrep, *Documentation* | https://semgrep.dev/docs/ | 2026-11-13 | SAST/SCA/secrets；C/C++ 支持；自定义规则 |
| C6 | LLVM, *AddressSanitizer* / *LeakSanitizer* | https://clang.llvm.org/docs/AddressSanitizer.html ; https://clang.llvm.org/docs/LeakSanitizer.html | 2026-11-13 | ASan 检测 OOB/UAF/double-free 等；典型 2× 开销；LSan 检测泄漏；作为确定性 oracle |
| C7 | Meta, *Introducing AutoPatchBench* | https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/ | 2026-11-13（发布 2025-04-29） | 136/113 C/C++ fuzzing 漏洞；约 60% 生成、5–11% 正确；差分测试 84.1% 准确/41.7% precision/100% recall；cheating；根因可能在栈外 |

### 10.4 本项目证据（P）

| 来源 | 用途 |
| --- | --- |
| `report/results_summary.md` | 三策略检测/配对/修复主表、成本、盲评 |
| `research/improvement_opportunities.md` | 102 条 invalid、93 缺 explanation、71 可用；无改动修复；置信度校准 |
| `research/innovation_findings.md` | 联合 A/B vs 长度启发式；证据提示操作点移动；工具证据 ceiling；修复饱和 |
| `pair_joint/report.md` | A/B 位置偏差 31.11 pp；选 A 118/180；长度分层 |
| `evidence_prompt/analysis/report.md` | 证据行 `±3` 命中近随机；引用行精确率 |
| `juliet_repair/report/comparison.md` | 58/58 可观测；全 70 strict 58/70；反馈净贡献 1 个单元 |
| `runner/secvul_runner/prompts.py` | 当前 detection/repair prompt；无行号、无 CWE、无根因 |
| `runner/secvul_runner/validation.py` | 严格键集合校验（`validation.py:88`） |
| `runner/secvul_runner/client.py` | 只发 `response_format=json_object`（`client.py:200-201`） |
| `pair_joint/common.py` | 联合 A/B prompt；已写“顺序无信息”（`common.py:240`）但仍有 A 偏差 |

---

## 11. 未核实、排除与限制

### 11.1 检索限制

1. **浏览器不可用**：Kimi 内置浏览器在本次会话持续返回 `ERR_PROXY_CONNECTION_FAILED`；关键页面通过 `FetchURL` 的文本抽取读取（部分条目先用 `WebSearch` 发现，再用 `FetchURL`/Crossref 核对），不能保证渲染后的表格/图与浏览器一致。对 arXiv abs/HTML、ACL Anthology、DROPS、USENIX、官方文档，文本抽取足以核对标题、摘要、日期、DOI；对需要看图的实验结果，本文只引用摘要/正文明确写出的数字，没有从图中估读。
2. **预印本占比较高**：2026 年的很多强相关工作（VulnAgent-R2、VulnGym、SastBench、ContextBench、SBVul、VulValidate、ARQ、Revelio、PatchBench、ExploreRepair、EviRepair、AgenticRepair、Calibration Floor、Constrained Decoding、Position Bias、PromptAudit）仍是 arXiv 预印本。本文把它们标为 B，只作为“机制/方向/待复现证据”，不当作定论。引用前应检查是否有更新版本或正式录用。
3. **数字不可比**：不同论文的数据集、任务定义、标签、指标口径差异很大。例如：
   - VulAgent 的 P-C 26.6% 是“两侧都判对”的配对指标；
   - 本项目的 76.67% 是“同一次请求强制二选一”的 DA；
   - SBVul 的 42.0% 是“函数级 pair 正确”，但它的语句级 precision 只有 0.315；
   - VulnGym 的 22.58% 是 Hard 子集的 advisory recall，不是全量。
   本文在正文中尽量写清口径；读者不应把这些数字放在同一张表里比较。
4. **没有一篇论文直接研究“C/C++ 漏洞/修复配对的位置偏差 + 长度控制”**。最接近的是通用 LLM 位置偏差研究 `[B16]`、代码 judge 偏差 `[A20]`、以及本项目的 `pair_joint/report.md`。因此，关于 A/B+B/A、长度匹配的具体建议，是“通用去偏 + 本项目实测”的组合，不是某篇论文的直接结论。
5. **本项目数字来自现有报告，未重跑**。其中修复盲评是 LLM 辅助（两名 LLM 评分者 + 第三 LLM 裁决，MIN κ=0.015），不是人类评审；`compile_status` 在 SecVulEval 修复上是 `NOT_RUN`；Juliet 的 58/58 只覆盖 LSan 可观测子集。本文引用这些数字时保留了原报告的限制，没有把它们升级为“修复正确率”。

### 11.2 明确排除/未采用的数字

| 数字/说法 | 为什么不用 |
| --- | --- |
| Revelio “69% recall、0% FP、$9.10/漏洞” | 来自 Emergent Mind 的二手表格，不在 arXiv 摘要中；没有在正文核实，故不引用。本文只用摘要明确给出的“7 项目 + 100 Argo/CyberGym、$300、19 未知漏洞”。 |
| SBVul “75.5% lenient CORRECT” | 这是“宽松 CORRECT”口径（解释也被接受），与 42.0% 的严格 pair 口径不同；本文只用 42.0%，避免混淆。 |
| RepoAudit “185 bugs/174 confirmed” vs “95 confirmed/79 fixed/85.71% precision” | 不同版本文档的数字不一致（v3 摘要 vs PDF 片段）；本文只用“15 项目/40 真 bug/78.43% precision/0.44h/$2.54”，这部分在摘要中稳定。 |
| IRIS “55/120” 当作 C/C++ 检测率 | IRIS 的数据集是 Java（CWE-Bench-Java）；本文只用它说明“LLM 推断 taint 规格 + 静态分析”的机制，不把 55/120 外推到 C/C++。 |
| VulnGym “22.58%” 当作全量 AR | 这是 Hard 子集的最强组合；全量/其他难度没有在摘要中给出，不能当总体性能。 |
| PatchEval “71.6%” 当作 C/C++ 修复率 | PatchEval 是 Go/JS/Python；本文只用它说明“多假设探索 + 聚合”的方向，不把它当成本项目 C/C++ 的预期值。 |
| “Constrained decoding 一定提升准确率” | `[A19]` 说格式限制降低推理；`[B15]` 说退化多来自非等价格式；`[B14]` 说很多“self-correction”是 format repair。本文的结论是“约束提升可解析性/可靠性，不保证语义正确”。 |
| “Self-consistency 一定提升召回” | `[B17]` 明确说 SC 在漏洞检测上引发过度 abstention；`[B18]` 说多数投票会饱和。本文建议“采样 + 验证器”，不是“投票”。 |

### 11.3 可能改变结论的证据

- **P1 如果显示 `mean_DA` 显著高于长度 oracle（≥10 pp）且 `order_gap` 很小**：那么联合 A/B 确有超出长度/位置的信号，本文对 76.67% 的“主要是伪影”判断需要下调。
- **P0 如果显示 usable-patch-yield 与 strict-schema-valid 差距 <2 pp**：那么 schema 不是主要问题时，本文对“93 条缺 explanation 是测量问题”的判断仍然成立，但对修复指标的影响需要缩小。
- **P3 如果 candidate recall@5 <50%**：那么“两阶段”在当前模型上不可行，低召回的主因是候选生成而不是裁决；应优先改候选生成/CWE 知识，而不是加验证器。
- **P5 如果 cannot_fix_rate >30%**：说明模型在信息不足时更愿意放弃，而不是硬修；此时“无改动修复”可能部分是合理 abstention，不应全部当失败。
- **P7 如果 label_error_rate ≥15%**：那么“低召回”有一部分是标签问题，所有召回结论都要带标签噪声敏感性分析；这与 VulValidate 的 19.0% 改正率方向一致。

### 11.4 工程/伦理限制

- **不显示/保存 API key**：本文没有读取、输出或保存任何 key；引用的 API 文档只涉及接口行为，不涉及凭证。
- **不覆盖旧结果**：本文只新增 `research/latest_llm_methods_2026.md`；没有修改 `runner/runs/`、`pair_joint/runs/`、`report/`、`analysis/`、`qualitative/`。
- **不执行 git/gh**：按分工，发布由主代理统一处理；本文没有 commit/push。
- **WSL 约束**：本次没有运行项目代码；如果后续执行 P0–P7，按项目要求所有代码在 WSL 中运行，输出到新目录，不覆盖旧 run。
- **成本估算**：按现有单价（DeepSeek input $0.30/output $1.20/cached $0.006 per 1M；MiMo input $0.14/output $0.28/cached $0.0028 per 1M）估算；价格可能变化，执行前需重新核对官方页面。

---

## 12. 交接摘要

### 12.1 产物

- **唯一新增文件**：`research/latest_llm_methods_2026.md`（本文件）。
- **没有修改任何代码/数据/旧结果**；没有执行实验；没有 git/gh 操作。
- 参考文献 22 条正式发表（A）、18 条预印本（B）、7 条官方文档/工具（C），全部在 §10 给出 DOI/arXiv ID/URL/日期/关键点。

### 12.2 五条可直接写进报告的结论

1. **低召回要靠“高召回候选 + 证据裁决”两段式，不是单次二分类。** 直接可借：VulAgent 的 hypothesis（conditions + path）、SBVul 的 statement-level Phase 1/2、RepoAudit 的 data-flow facts + validator。预期是“固定 FPR 下召回提升”，不是“F1 无条件提升”。
2. **标签噪声必须先量化。** VulValidate 在 35,849 条上改正 19.0%、22.3% 未决；本项目 FN 中可能有一部分不是模型漏报。建议 P7 抽 30–50 条 FN 做审计，报告 corrected recall。
3. **联合 A/B 的 76.67% 目前不可归因。** 长度启发式 74.44%、DeepSeek A 偏差 31.11 pp；必须做 A/B+B/A、长度匹配、开放 both/neither。文献的 26.6%/42.0% 是不同口径，不能直接比较。
4. **schema 失败主要是解析口径。** DeepSeek 三策略的 102 条 invalid 中 93 条只缺 `explanation`，71 条有实质改动；严格键集合校验把它们丢了。优先 P0 只读复分析，再决定是否改 prompt/schema。
5. **无改动修复是系统性问题，不是本数据集怪癖。** AutoPatchBench 60% 生成/5–11% 正确、PatchBench 25% 记忆/PoC-only 抬高 1.83×；需要根因门、改动门、`cannot_fix` 出口和可执行验证。

### 12.3 建议主代理优先安排的三个动作

| 优先级 | 动作 | 为什么 | 成本 | 产出 |
| --- | --- | --- | --- | --- |
| **1** | P0：只读复分析 102 条 invalid | 不改代码、不调 API，一天内回答“schema 是否真的丢了很多可用补丁” | $0 | `analysis/schema_recovery/` 的可用率表 |
| **2** | P1：180 对 A/B+B/A | 直接分离位置/长度；现有 76.67% 需要审计 | 约 $0.45、1 天 | `mean_DA`、`flip_rate`、`order_gap`、长度分层 |
| **3** | P3 pilot：40 条两阶段检测 | 验证“候选生成 + 验证”是否能提高固定 FPR 下召回 | 约 $0.1、2–3 天 | candidate recall、retained rate、recall/FPR |

### 12.4 未完成/需要后续

- **没有做 P0–P7 的任何实验**：本文只给设计；执行需要主代理批准、冻结 split、预注册主终点。
- **没有写代码**：P0 的只读脚本、P1 的 A/B+B/A runner、P3 的两阶段 prompt 都未实现。
- **没有做人类评审**：修复盲评仍是 LLM 辅助；本文没有新增人工标注。
- **没有验证预印本的最终版本**：2026 年的预印本可能在本文写作后更新；引用前应检查 arXiv 版本/正式录用。
- **浏览器限制**：如果主代理需要页面截图/渲染表格，需在网络恢复后用浏览器复核；本文的文本级核验已完成。

### 12.5 一句话

**这份文档的价值不是“又列了一堆 2026 论文”，而是把文献拆成四类可检验的干预——候选/验证、上下文、结构化输出、修复闭环——并明确指出：在当前项目里，最该先修的是 pair 的测量有效性（长度/位置）和 schema 的解析口径，而不是再换一个模型或再加一个 agent。**

---

*文件结束。所有 URL/DOI 核验日期：2026-11-13。*

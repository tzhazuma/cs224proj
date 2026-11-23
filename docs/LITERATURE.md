# 文献索引（LITERATURE）

本文是 `research/` 与报告参考文献的**入口索引**，不是新的文献综述，也不是实验结果。它回答三个问题：哪份文档覆盖什么、每条证据属于哪一级、写报告时应该引用哪一节。

> 文献中的数字（如某工具在外部基准上的 F1）**不能**与本项目的 Tier A/Tier B 数字合并。本项目的数字只来自已落盘的 run；文献数字只用于方法动机、对照和效度威胁。

---

## 1. 阅读顺序

| 目的 | 先读 | 再读 |
| --- | --- | --- |
| 写最终报告的“相关工作/有效性威胁” | [`research/related_work.md`](../research/related_work.md) | [`research/latest_llm_methods_2026.md`](../research/latest_llm_methods_2026.md) §2、§10 |
| 解释位置/长度/配对/placebo/judge/修复 oracle | [`research/latest_evaluation_repair_2026.md`](../research/latest_evaluation_repair_2026.md) §3–§12 | [`pair_debias/report.md`](../pair_debias/report.md)、[`hybrid/REPORT_V2.md`](../hybrid/REPORT_V2.md) |
| 解释 CWE-401、条件分配失败、still reachable、CodeQL/LSan/Valgrind | [`research/latest_memory_tools_2026.md`](../research/latest_memory_tools_2026.md) §1–§4 | [`dynamic_enhanced/README.md`](../dynamic_enhanced/README.md)、[`static_extended/README.md`](../static_extended/README.md) |
| 解释 schema invalid、格式修复、usable patch | [`research/latest_llm_methods_2026.md`](../research/latest_llm_methods_2026.md) §6 | [`analysis/schema_recovery/README.md`](../analysis/schema_recovery/README.md) |
| 解释本项目的创新点边界 | [`research/innovation_findings.md`](../research/innovation_findings.md) | [`research/improvement_opportunities.md`](../research/improvement_opportunities.md) |

---

## 2. 最新一轮调研（2026-11-13）

| 文档 | 覆盖范围 | 证据规模 | 与本项目的关系 |
| --- | --- | --- | --- |
| [`latest_llm_methods_2026.md`](../research/latest_llm_methods_2026.md) | 2025–2026 LLM/agentic 漏洞检测、代码库级上下文、自一致性、约束解码、验证反馈、修复、配对判别 | 22 条正式发表（A）+ 18 条预印本（B）+ 7 条官方文档/博客（C），§10 逐条核验 | 解释“发现/裁决分离”、schema 失败、无改动修复、A/B 位置偏差；§9 给出 P0–P7 实验矩阵 |
| [`latest_evaluation_repair_2026.md`](../research/latest_evaluation_repair_2026.md) | 评估方法学：position bias、length shortcut、paired benchmark、placebo、LLM-as-judge、patch overfitting、compile/test/PoC、fault injection、differential testing | 56 条编号参考文献，A/B/C 分级；§13 报告规范、§16 参考文献 | 给 `pair_debias`、`evidence_verify`、`hybrid_dynamic_enhanced`、`juliet_repair`、`repair_eval` 提供设计依据与“不能声称”的边界；E1–E9 是可检验改进 |
| [`latest_memory_tools_2026.md`](../research/latest_memory_tools_2026.md) | 2024–2026 内存泄漏工具：CodeQL、Semgrep、Infer/Pulse、SVF/Saber/SMOKE、Clang SA、LSan/Valgrind；条件分配失败、still reachable、路径覆盖、真实项目迁移 | 47 条 `[R#]` 参考文献，A/B/C/D 分级；§5 有 WSL 最小语义验证 | 直接支撑 `dynamic_enhanced` 的 `realloc_fail`/`nogobal` 设计和 `static_extended` 的 CodeQL 选择；§6 列出未核实事项 |

> **时效声明（2026-11-14）**：下面三份文档是 2026-11-13 的调研快照，其中“P0–P7 未执行”“开放四分类/双顺序未实现”等状态早于 2026-11-14 的实验；当前结果以 [`report/latest_results_summary.md`](../report/latest_results_summary.md)、[`benchmark/results/EXTENSIONS.md`](../benchmark/results/EXTENSIONS.md) 与各实验目录为准。

### 2.1 三条最常用的结论

1. **格式合规不等于语义正确。** JSON mode 只保证合法 JSON，Structured Outputs 才保证字段齐全；很多“self-correction”收益可由 format repair 解释。对应本项目的 93 条 missing-explanation 与 67–69 条 usable salvage（L0）。
2. **配对分数对协议高度敏感。** 位置偏差、长度先验和强制二选一都能单独抬高 DA；单序结果必须配交换一致 DA 与两序长度基线。对应 `pair_debias` 的 61.67%/74.44% vs 72.22%。
3. **动态 `clean` 是路径观测，不是安全证明。** 条件分配失败、still reachable 和路径覆盖必须分开记录；这正是 `dynamic_enhanced` 用故障注入与全局根控制补 12 个不可观测单元的理由。

### 2.2 引用分级

| 级别 | 含义 | 使用规则 |
| --- | --- | --- |
| **A** | 正式发表，DOI/会议页/ACL Anthology 已核对 | 可作为方法依据；外部数字仍需注明基准与配置 |
| **B** | arXiv 预印本，元数据已核对但未必同行评审 | 只写“机制/方向/待复现证据”，不写成定论 |
| **C** | 官方文档、工具发布说明、厂商博客 | 只用于工具行为与接口，不用于性能排名 |
| **P** | 本项目已落盘产物 | 必须给 run 路径、分母、coverage、审计状态；不能与文献数字池化 |
| **D** | 博客/二手解读 | `latest_memory_tools_2026.md` 明确不用于事实性断言 |

---

## 3. 既有文献与协议文档

| 文档 | 内容 | 什么时候用 |
| --- | --- | --- |
| [`research/related_work.md`](../research/related_work.md) | 早期相关工作：漏洞检测、修复、LLM 评测 | 报告“相关工作”章节的背景 |
| [`research/evaluation_protocol.md`](../research/evaluation_protocol.md) | 评测协议：标签、指标、失败、统计、成本 | 解释为什么 strict/valid-only/coverage 要分开 |
| [`research/cwe401_scope.md`](../research/cwe401_scope.md) | CWE-401 的范围、Juliet 结构、标签语义 | Tier B 数据卡与范围限定 |
| [`research/secvuleval_review.md`](../research/secvuleval_review.md) | SecVulEval 数据集的审计与使用边界 | Tier A 数据来源与许可 |
| [`research/static_dynamic_memory.md`](../research/static_dynamic_memory.md) | 静态/动态内存泄漏工具与项目基线 | `traditional/` 与 `dynamic_enhanced/` 的方法背景 |
| [`research/hybrid_ai_memory.md`](../research/hybrid_ai_memory.md) | AI + 传统工具的证据条件化 | `hybrid/`、`hybrid_dynamic_enhanced/` 的设计背景 |
| [`research/improvement_opportunities.md`](../research/improvement_opportunities.md) | 102 条 invalid、无改动修复、置信度校准等改进机会 | schema/修复章节的动机 |
| [`research/innovation_findings.md`](../research/innovation_findings.md) | 创新点的证据分级：能写/不能写 | 报告结论与答辩边界 |
| [`research/next_iteration_rationale.md`](../research/next_iteration_rationale.md) | 2026-11-22 五个最弱环节的定量复核、N1–N4 成功线、失败解释与 2024–2026 文献映射 | 下一轮实验设计与“为什么先做这些” |
| [`interpretable_baseline/LITERATURE.md`](../interpretable_baseline/LITERATURE.md) | 平凡基线、长度/复杂度捷径、类不平衡与 MCC/macro-F1 | 解释 Tier A 0.383 是否低于“不看代码”的基线 |
| [`codeql_triage/LITERATURE.md`](../codeql_triage/LITERATURE.md) | CodeQL 误报模式、LLM 告警分流、SAST+LLM 级联 | 23 个 C++ FP 的机制与分流设计 |
| [`verifier_conservative/README.md`](../verifier_conservative/README.md) §定位与文献 | selective prediction、弃权、自我纠错、cascade 成本 | 解释为什么“三路验证器”是负结果 |
| [`dynamic_coverage/README.md`](../dynamic_coverage/README.md) §4 | 覆盖率充分性、gcov/LLVM coverage、LSan 根集 | 解释 100% 行覆盖与 12 个漏报为何能同时成立 |

---

## 4. 文献到实验的映射

| 项目实验 | 直接依据 | 关键限制 |
| --- | --- | --- |
| `pair_joint/` 强制 A/B | 配对判别、PrimeVul/SecVulEval 的配对协议 | 单序、位置偏差、长度先验 |
| `pair_debias/` 反向 + 开放 | position bias、length shortcut、paired benchmark（E1–E3） | 单次运行；开放弃权记错；长度匹配是事后诊断 |
| `evidence_prompt/` 证据行 | 语句级定位、证据提示、操作点移动 | 召回上升伴随 FPR 上升；±3 命中近随机 |
| `evidence_verify/` 二次验证 | 验证反馈、claim verification、abstention | post-hoc、test seen；只处理正例；撤销不偏向 FP |
| `hybrid/` 工具证据 + placebo | 工具证据、negative control、ceiling effect | 单 derangement；v2 清洗后增益消失 |
| `dynamic_enhanced/` 故障注入 | 条件分配失败、still reachable、路径覆盖 | 单路径；只注入第一次非 NULL `realloc`；`nogobal` 是总开关 |
| `hybrid_dynamic_enhanced/` | 证据条件化、工具天花板、copying 诊断 | 工具 140/140，准确率无法分离照抄与推理 |
| `static_extended/` CodeQL | CodeQL CWE-401 查询、SAST 对比 | 单 TU/每单元建库；编译器与基线不同；版本固定 |
| `juliet_repair/` 编译/LSan/行为 | compile/test/PoC 证据阶梯、patch overfitting | 58 个可观测单元；无真实项目/PoC |
| `repair_eval/` 盲评 | LLM-as-judge 可靠性、κ paradox | LLM 辅助、非人类；无编译/PoC |
| `analysis/schema_recovery/` | JSON mode vs Structured Outputs、format repair | L0 结构代理；无编译/测试/PoC |
| `interpretable_baseline/` | 平凡基线、长度/复杂度捷径、macro-F1 vs MCC | dev40 仅 8 个负例；test 80% 正例；test-tuned 上界不是方法 |
| `pair_diff/` | diff-guided review、position bias、length shortcut | diff−ctrl 不显著；changes-first 门控；长度匹配是代理 tokenizer |
| `codeql_triage/` | CodeQL FP 模式、LLM triage、SAST+LLM cascade | 只有 MiMo；vs direct 不显著；91 告警复核非盲审 |
| `verifier_conservative/` | selective prediction、abstention、self-correction、cascade | test-seen/post-hoc；4/236 撤销；无编译/执行验证 |
| `dynamic_coverage/` | coverage adequacy、gcov/LLVM coverage、LSan 根集 | 100% 行覆盖≠无泄漏；branch gate 弃权全部 good；单输入 |

---

## 5. 引用与维护规则

1. **先核对再引用。** A 级条目必须有 DOI/会议页；B 级必须给 arXiv ID 与版本日期；C 级给 URL 与访问日期。`latest_llm_methods_2026.md` §10 与 `latest_evaluation_repair_2026.md` §16 是逐条核验表。
2. **不把预印本写成定论。** 2026 年的很多强相关工作仍是 B 级；引用时写“作者报告/预印本”，不写“已被证明”。
3. **不跨基准比较。** 文献的 F1/召回只在它自己的数据集、配置和分母下成立；不能与 Juliet 140 或 SecVulEval 160 直接比。
4. **不把本索引当结果。** 本文件只做导航；实验数字以对应 run 的 `metrics.json`、`summary.json` 或报告为准。
5. **新增文献的落点。** 新调研写入 `research/latest_*.md`，同时更新本文件的第 2 节和根 README §9；不要改旧调研的数字或结论。
6. **未核实事项要保留。** `latest_llm_methods_2026.md` §11、`latest_memory_tools_2026.md` §6.2 已列出检索限制与未核实项；更新时不要删除，除非有新的核验证据。

---

## 6. 已知缺口

- **浏览器渲染复核缺失。** `latest_llm_methods_2026.md` 记录本次会话内置浏览器持续 `ERR_PROXY_CONNECTION_FAILED`，关键页面用 `FetchURL` 文本抽取与 Crossref/arXiv API 核对；没有做渲染后截图级复核。
- **预印本比例高。** 2026 年的 agentic 检测、位置偏差、format repair、fault injection 等主题大量仍是 arXiv；正式录用状态可能变化。
- **外部数字按作者自报。** 文献中的工具召回/精确率、成本、bug 数均按作者口径引用，未在本项目重跑。
- **中文报告引用。** `report/references_extended.bib` 只覆盖扩展版实际引用的 28 条；本索引中的最新调研不自动进入 `.bib`，写进报告前需手动补条目并核对。

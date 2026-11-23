# 改进 idea（可检验，不空喊）

按“先用便宜实验排除，再做贵的”排序。每条给：假设、最小实验、主指标、预期、风险。所有实验都应保持 140 test 冻结，先在小集（23 FP + 68 TP）上 pilot，再全量。

## 1. 单字段 schema + 派生告警判决（P0，最便宜）

**问题**：v2 的 3 个残留 `_22` FP 不是推理错，而是字段自相矛盾：`reason` 说“all heap allocations released”，`alert_verdict=true_positive`、`leak_present=true`。

**设计**：让模型只输出：
```json
{"leak_present": true|false|"uncertain",
 "release_gap": "<分配 + 到达 exit 无释放的路径，或 none>",
 "reason": "..."}
```
`alert_verdict` 由代码派生：
- CodeQL 有告警且 `leak_present=true` → `true_positive`
- 有告警且 `leak_present=false` → `false_positive`
- `uncertain` → `uncertain`（保留）
- 无告警 → `no_alert`

**最小实验**：140 条 v3，与 v2 同模型/同数据；比较 TP 误删、FP 撤销、macro-F1、MCC。成本 ~$0.03。

**主指标**：TP deleted / 68；FP removed / 23；macro-F1；`release_gap` 为 none 却 `leak_present=true` 的矛盾率。

**预期**：3 个 `_22` 消失，TP 误删仍 0；`release_gap` 矛盾率从 3/91 降到 0。若 TP 误删上升，说明模型在“无字段可甩锅”时更保守，需保留 `uncertain`。

**风险**：`leak_present` 在 v2 的 hybrid 里只有 68/10（10 个 FP），比 `alert_verdict` 差；单字段可能把 3 个 `_22` 修好但引入新的 FP。必须同时报告 `alert_verdict` 派生版和 `leak_present` 版。

## 2. Release-witness gating（P0，便宜）

**问题**：模型可以写 `false_positive` 但只给“unsupported”/空证据；v1 的 7 个 TP 误删都有 4–5 个“supported”字段，说明“字段数量”不等于“证据正确”。

**设计**：撤销告警必须满足：
- `release_gap == "none"`；
- `ownership`/`cross_function_release` 至少一个字段给出**具体表达式**（`free(data)`、`delete[] dataVector[2]`、`delete data`）和**到达它的调用/分支**；
- 否则一律 `uncertain`/保留。

**最小实验**：对 v2 的 91 个告警做规则重放（不需要新 API）：用正则/结构化字段判断是否满足 witness；比较 `triage_keep` vs `triage_witness`。

**主指标**：TP deleted、FP removed、macro-F1；人工抽查 10 条 witness 的事实正确率。

**预期**：3 个 `_22` 的 `reason` 有具体 delete，但 `cross_function_release` 只说“sym_4/sym_6 contain delete”，可能不满足“路径”；需要模型补路径。若规则太严，FP 撤销率会下降。

**风险**：正则规则脆弱；应把 witness 作为模型输出字段（`release_site`、`release_path`），而不是从自由文本抽。

## 3. Query-aware / language-aware stacking（P0，零 API）

**问题**：23 FP 全是 C++ `may-not-be-freed`；零成本规则 `drop C++ may-not-be-freed` 已有 P=1.0、R=0.857。

**设计**：按 `(language, query)` 分层：
- `never-freed`：高精度，默认保留；
- `may-not-be-freed` + C++：低精度，默认丢弃或送 LLM；
- `may-not-be-freed` + C：中间，送 LLM。

**最小实验**：在 140 上做分层表，比较：
- 纯规则；
- 规则 + LLM 只在“规则不确定”层；
- 全量 LLM。

**主指标**：每层 TP/FP、调用数、成本、TP deleted；整体 macro-F1/MCC。

**预期**：用 40–60 次调用达到接近全量 140 的效果；但 `_22` 的 3 个 TP 会被规则误丢（它们是 C++ may），所以需要 LLM 只在这些“规则想丢但可能有跨函数 free”的单元上复核。

**风险**：分层是数据集特定的；真实项目上 query/language 先验可能反转。

## 4. Cascade：CodeQL 告警 → triage；无告警 → direct/动态（P1）

**现状**：本实验 cascade 得到 70 TP/2 FP/68 TN/0 FN，macro-F1 0.9857、MCC 0.9718，与 triage 最终同分但操作点不同。

**设计**：把 cascade 作为独立方法登记：
- 有 CodeQL 告警：`triage_verified`（或文本规则）；
- 无告警：direct LLM；可选再用 LSan 验证 direct 的正例。

**最小实验**：已有数据可离线算；无需新 API。下一步在真实项目上验证“无告警 direct”的 FP 率是否仍只有 2/49。

**主指标**：TP/FP/TN/FN、macro-F1、MCC、成本；单独报告“cascade 相对 triage 多 2 TP/多 2 FP”的交换。

**预期**：在 Juliet 上与 triage 同分；在真实项目上 direct 的 FP 可能更多，cascade 不一定划算。

**风险**：cascade 不是纯 triage；不能把它混进“告警分流”主表。

## 5. 动态见证：LSan + 故障注入（P1，较贵）

**问题**：v1 的 7 个 TP 误删都是 realloc 失败路径；文本推理说“不可行”，但定义说“可行路径上的泄漏就算”。仅靠提示约束能修，但没有外部证据。

**设计**：对模型想撤销的告警：
- 编译单元（Juliet 已有 build 脚本）；
- 跑 LSan/Valgrind；
- 对 realloc 做故障注入（`dynamic_enhanced` 已有 `realloc_fail` + `nogobal` 模式）；
- 只有“观察到无泄漏”才撤销；观察到泄漏则保留。

**最小实验**：23 FP + 7 个 v1 误删 TP，共 30 个；每个编译+运行 1–2 次；成本是机器时间，不是 API。

**主指标**：撤销的 FP 中“动态确认无泄漏”的比例；保留的 TP 中“动态确认泄漏”的比例；TP deleted。

**预期**：23 FP 的 `_33`/`_72`/`_54` 大概率动态 clean；`_22` 的全局路径需要正确的编译定义；7 个 realloc TP 在故障注入下应观察到泄漏。这样可以把“文本理由”升级为“可复核证据”。

**风险**：动态 clean 不是安全证明；只覆盖执行的路径；编译错误单元无法跑。

## 6. Ownership summary + Z3 路径可行性（P2，研究型）

**问题**：`_22`/`_54`/`_72` 的根因是 CodeQL 看不到跨函数 free/ownership transfer；告警后 triage 只是补救。

**设计**（MemHint 式）：
- LLM 为每个函数生成 `alloc/free/transfer` summary（哪个参数/返回值携带 ownership）；
- Z3 检查 summary 在 CFG 上是否可达；
- 把 summary 注入 CodeQL 查询（或作为后处理，把 `may-not-be-freed` 的告警按 summary 过滤）。

**最小实验**：在 200 个单元上，先只做“summary 后处理”，不修改 CodeQL 查询；比较 CodeQL vs CodeQL+summary 的 P/R/MCC。

**主指标**：`_22`/`_54`/`_72` 的 FP 撤销率；TP 误删；summary 的事实正确率（人工抽查）。

**预期**：能从分析器层修掉 3 个 `_22`，而不是靠 LLM 二次复核；但 summary 生成成本高于告警 triage。

**风险**：Z3/CFG 工程量；Juliet 的 `_82` 编译错误会阻断。

## 7. 记忆化对照（P0，必须做）

**问题**：91/91 复核、68/0/70/2 可能来自 Juliet 模板记忆；清洗只去标签，不改结构。

**设计**：
- 结构变异：交换 `if/else` 分支、改 wrapper 深度（3/5/7 层）、把 vector 换成 list/array、改 `ALLOCA`/`malloc` 组合、改全局 flag 初值；
- 用同一 v2 提示重跑；
- 比较原始 vs 变异的 TP 误删/FP 撤销/macro-F1。

**主指标**：变异前后的 Δmacro-F1、TP deleted、FP removed；模型理由中“模板词”的比例。

**预期**：如果记忆化强，变异后 `_33`/`_72` 仍容易，`_22`/`_54` 的准确率下降；如果方法真在推理，变异后应保持。

**风险**：变异可能改变标签语义；需要重新用 ASan/LSan 确认标签。

## 8. 跨模型集成（P1，等 DeepSeek）

**设计**：DeepSeek + MiMo 各自 v2；一致时采纳，不一致时 `uncertain`/人审；或按置信度加权。

**最小实验**：DeepSeek 凭证恢复后，140×2；比较单模型 vs 集成。

**主指标**：一致率、集成 macro-F1、TP deleted、成本（2×）。

**预期**：极性错误（`_22`）可能被另一个模型纠正；但两个模型可能共享 Juliet 记忆，增益有限。

**风险**：DeepSeek 当前 401/402；不能伪造。

## 9. 成本感知 utility（P1，零 API）

**设计**：
```
U = λ_FP * FP_removed - λ_TP * TP_deleted - cost
```
报告 λ_FP/λ_TP 从 1:1 到 100:1 的最优策略；用 LLMPFA 的 10–20 min/告警做外部时间参照，但不伪造人评。

**最小实验**：用现有 140 的逐样本结果离线重算；不需要新 API。

**主指标**：不同 λ 下的最优策略、TP deleted、成本；break-even λ。

**预期**：当 λ_TP 高（不能误删）时，`triage_verified`/文本规则最优；当 λ_FP 高（宁可多删）时，`drop C++ may-not-be-freed` 或 v1 更便宜。

## 10. 人审模拟 / selective prediction（P2）

**设计**：把 `uncertain`、字段矛盾、低置信度样本路由给人；统计“减少多少告警、增加多少误删、节省多少分钟”。

**最小实验**：用现有 91 个告警的 `confidence` 和矛盾标记，模拟不同覆盖率下的人审量；不实际雇人。

**主指标**：人审覆盖率、剩余 FP、TP deleted、预计节省时间（用外部 10–20 min/告警，明确标注是外部参照）。

**预期**：3 个 `_22` 矛盾样本正好会被路由；人审量从 91 降到 3–10，TP deleted 0。

---

## 建议的执行顺序

1. **#1 单字段 schema**（140 条，$0.03）——直接验证 3 个 `_22` 是否由字段冗余导致。
2. **#2 witness gating**（离线规则 + 10 条人工抽查）——把“证据”变成硬约束。
3. **#3 query/language stacking**（离线）——证明 LLM 超过零成本规则。
4. **#7 记忆化对照**（结构变异，140 条）——决定 0.9857 是否可信。
5. **#5 动态见证**（30 条，机器时间）——把文本理由升级为可复核证据。
6. **#8 DeepSeek 集成**（等凭证）——跨模型一致性。
7. **#6 ownership summary**（研究型，工程量最大）。

前 4 项都不需要新数据/新模型，适合在课程项目时间内完成；#5 需要现有 `dynamic_enhanced` 的故障注入脚本；#6 是论文级扩展。

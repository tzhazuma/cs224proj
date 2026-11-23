# 现有 benchmark 的欠缺（CodeQL 告警分流视角）

本文件只谈“与本目录实验直接相关”的欠缺。每条给出证据、影响、可检验的补法。不是对父项目的全面审计。

## 1. 没有“告警分流”这一行

**现状**：父层主表和扩展层比较了 CodeQL、Clang、Cppcheck、direct LLM、动态、混合，但没有“CodeQL 告警 + LLM 分流”的独立行。

**证据**：`static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.md` 只有工具端到端；`juliet_llm` 只有 direct；`hybrid_*` 是证据提示，不是告警后分流。

**影响**：
- 无法回答“LLM 能否在不误删 TP 的前提下撤销 CodeQL FP”。
- 无法报告 TP 误删、FP 撤销率、每告警成本。
- 23 个 FP 只能被当作 CodeQL 的缺点，不能被当作可修复对象。

**补法**：本目录的 `triage_keep` / `triage_verified` / `rule_text_consistency`；至少报告 TP/FP/TN/FN、P/R/macro-F1/MCC、coverage、TP deleted、cost。

## 2. compile_error 在端到端里容易被误读

**现状**：CodeQL test 140 有 4 个 `compile_error`（`_82` 的 `new_twoIntsStruct` / `new_wchar_t`，bad+good 各 2）。端到端把它们按“未报泄漏”计，所以 CodeQL 的 2 个 FN 正好是 2 个 `_82__bad`。

**证据**：`static_extended/.../metrics.md` 状态计数 `{'ok': 136, 'compile_error': 4}`；`comparison_test140.md` 端到端 CodeQL FN=2。

**影响**：
- 如果不单列，读者会把“工具不能建库”与“工具判断错误”混在一起。
- 任何 triage 都无法从“没有告警”里恢复这 2 个 bad；只有 direct/动态/人工能读源码。
- 召回 0.9714 的上限不是 1.0，而是 136/140 可分析 + 2 个 bad 可读。

**补法**：本目录 `compile_errors.md` 单列 4 个；端到端仍按未报泄漏计；cascade 单独展示“direct 补回 2 个 TP、引入 2 个 FP”。

## 3. 23 个 FP 的结构先验太强

**现状**：23 个 CodeQL FP 全部是 C++ good，全部来自 `cpp/memory-may-not-be-freed`；`cpp/memory-never-freed` 在 test 140 上 0 FP。

**证据**：`static_extended/.../comparison_test140.md` 分查询表；本目录 `fp23.md` 逐条。

**影响**：
- 一个零成本规则“C++ 且只有 may-not-be-freed 就丢弃”就有 P=1.0、R=0.857、macro-F1 0.9282、MCC 0.8660。
- 任何 LLM triage 如果不先打这个基线，0.96 的 macro-F1 可能只是“学会了 query/language 先验”，不是所有权推理。
- 23 个 FP 的模式分布（15 个 `_33`、3 个 `_22`、3 个 `_72`、2 个 `_54`）是 Juliet 变体结构，不是真实项目的 FP 分布。

**补法**：报告 `drop C++ may-not-be-freed` 与 `never-freed only`；在真实项目上重估 FP 的 query/language 分布。

## 4. Juliet 记忆化

**现状**：`juliet_llm` 清洗去掉了标签、路径、CWE、`bad/good` 标识符、注释、`Benign, fixed string`，但保留了控制流结构、宏展开后的 `printLine` 序列、变量形状。

**证据**：`juliet_llm/build/audit_report.md` 的 11 类 token 计数；`juliet_llm/README.md` 的清洗管线。

**影响**：
- 2026 的告警裁决研究（arXiv 2607.09979）报告 o4-mini 能重建清洗后的 Juliet 原始身份，因此把泛化主张放在 FormAI。
- 我们的 91/91 复核、68/0/70/2 可能包含“见过这个 Juliet 变体”的成分；不能当作真实项目泛化。
- 23 个 FP 的 `_33`/`_22`/`_72`/`_54` 是固定模板；模型可能记住“这个模板的 good 版本会 free”。

**补法**：结构变异（交换分支、改调用深度、改容器类型、改宏展开）、FormAI/SV-COMP、真实项目；报告变异前后的 TP 误删/FP 撤销变化。

## 5. 标签是宏标签，不是人评

**现状**：Juliet 的 `bad/good` 由 `OMITBAD`/`OMITGOOD` 宏门控唯一决定；`juliet_llm` 用 ASan/LSan 佐证，但没有独立的人对“所有权/释放路径”做 ground truth。

**影响**：
- 模型说“free 在 alias 上”可能是对的，但标签只告诉你 bad/good；无法区分“模型理由对、标签对”“模型理由错、标签对”。
- 23 个 FP 的“正确撤销”是按标签判的，不是按真实释放路径判的；如果 Juliet 的 good 版本自身有隐藏泄漏（NIST TN 1995 说 Juliet 1.3 有已知问题），标签也可能不完美。

**补法**：对 23 FP + 7 个 v1 误删 TP 做人工/半自动的释放路径核验；报告理由正确率，而不只是标签一致率。

## 6. 单次采样、无校准

**现状**：所有 LLM 结果 temperature 0、单次请求；没有重复采样、没有置信区间覆盖模型方差；`confidence` 字段没有做 ECE/reliability。

**证据**：`results_*.jsonl` 每单元一条；`metrics_*.json` 没有方差分量。

**影响**：
- 无法区分“方法稳定”与“这一次采样恰好”。
- 置信度 0.9/0.95 是否可信未知；不能用它做 selective triage。
- 复核的 91/91 可能是一次性运气；重复 3 次才能估计翻转率。

**补法**：每单元 3–5 次采样（temperature 0.2–0.7），报告决策翻转率、macro-F1 均值/方差、置信度校准；或至少对 23 FP + 68 TP 做重复。

## 7. 成本口径不完整

**现状**：父层有 token/价格/延迟，但没有“每撤销 FP 的成本”“每保留 TP 的成本”“人审节省时间”；CodeQL 建库算力没有折成钱。

**证据**：本目录 `cost.md` 是配置价；`static_extended/.../metrics.md` 只有墙钟。

**影响**：
- 不能回答“花 $0.03 省多少人工分钟”。
- 不能比较“LLM triage”与“直接人审 23 个 FP”的性价比。
- CodeQL 的 6,061.8 s（test 140 逐单元之和）与 LLM 264 s 墙钟不是同一口径，不能直接说“LLM 更便宜”。

**补法**：定义 utility（λ_FP × 撤销 FP − λ_TP × 误删 TP − cost），报告不同 λ 下的最优策略；用 LLMPFA 的 10–20 min/告警做外部参照，但不伪造人评。

## 8. 没有真实项目 / 跨 CWE

**现状**：只 CWE-401、只 Juliet 200 单元、test 140；CodeQL 每单元单独建库、单 TU 近似。

**影响**：
- `_33`/`_22`/`_72`/`_54` 是 Juliet 变体；真实项目的 FP 可能来自宏、模板、第三方库、跨 TU，单 TU 近似会改变 FP 结构。
- 0.9857 不能外推到 CWE-416/415/476 或真实 C/C++ 项目。
- `may-not-be-freed` 在真实项目上的 FP 率可能更高/更低；query prior 会变。

**补法**：在 SecVulEval 或真实 C/C++ 项目上抽 CWE-401 告警，做人评；至少报告 20–50 个真实告警的 TP/FP、TP 误删、成本。

## 9. 提示/任务定义的可复现性

**现状**：v1 → v2 只改了提示（字段顺序、realloc 规则、自检），TP 误删从 7 降到 0、FP 撤销从 18 升到 20。说明结果对提示非常敏感。

**影响**：
- 单一提示的 0.9857 不是“方法”的稳定性能；换一种措辞可能回到 0.90。
- 没有提示消融（只改一个因素）就无法知道哪个因素有效。

**补法**：2×2×2 消融：字段顺序（leak 先/alert 先）× realloc 规则（有/无）× 自检（有/无）；每格 140 条，报告 TP 误删/FP 撤销。成本约 8 × $0.03 = $0.24，可接受。

## 10. 告警分流的“适用边界”没有定义

**现状**：本实验的 triage 只对 91 个 CodeQL 告警生效；49 个无告警单元（含 4 个 compile_error、2 个 CodeQL FN）不进入分流。

**影响**：
- 读者可能把 68/0/70/2 误读为“端到端检测 0 FP”，但它仍然是 CodeQL 的召回上限（2 FN）。
- 也不能说“triage 修复了 compile_error”；它没有。
- cascade 用 direct 补回 2 个 TP，但引入 2 个 FP；这是检测器组合，不是 triage。

**补法**：在报告中明确“triage 的输入域是 CodeQL 告警；无告警单元不适用”；把 cascade/检测器组合单列，不混入 triage 主表。

---

## 优先级

| 优先级 | 欠缺 | 理由 |
| --- | --- | --- |
| P0 | 没有 triage 行、没有 TP 误删、没有 query/language 基线 | 直接影响结论可信度 |
| P0 | Juliet 记忆化、单次采样 | 直接影响泛化/方差 |
| P1 | compile_error 单列、成本 utility | 影响读者对召回/性价比的理解 |
| P1 | 人评释放路径 | 影响“理由正确率” |
| P2 | 真实项目/跨 CWE | 影响外推，但成本高 |

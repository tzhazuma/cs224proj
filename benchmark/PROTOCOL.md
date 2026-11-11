# 统一漏洞检测 Benchmark 协议

**版本：`1.0.0`** · **日期：2026-11-12** · **适用：CS224 项目；`benchmark/` 独占**

> 本文件是规范。机器可读契约在 `schemas/`，计划表在 `matrix/`，可执行工具在 `tools/`。
> 本协议不产生任何模型或工具结果；现有数值只来自已冻结的 `runner/runs/test_v1_*`，并明确标注来源。

---

## 0. 一页结论

1. **统一但分层。** 只有一个结果 schema、一个指标词典、一个失败分类和一个成本模型；但有 **两个独立层级**，不共享 leaderboard、不共享分母、不做跨层池化。
2. **Tier A（SecVulEval）** 回答：跨 CWE 的真实项目函数上，不同 LLM（DeepSeek V4.1 Flash、MiMo）与提示策略（direct / few-shot / context / evidence）的检测与配对判别如何。测试集固定为 160 函数 + 180 对；DeepSeek/MiMo 的六个 legacy 格、两个 evidence run 和两个 pair-joint run 都已产生。pair-joint 是强制二选一的独立任务，不能与分侧四分类合并。
3. **Tier B（Juliet CWE-401）** 回答：同一批合成内存泄漏用例上，静态、动态、LLM、AI+传统四种范式如何。所有方法必须在**同一 core set、同一 bad/good 标签、同一排除账本**上比较；静态和动态工具只在完整可编译的 Juliet 单元上运行。
4. **不允许把静态工具直接跑 Tier A 的不完整 CVE 函数。** 这些函数是项目片段，缺头文件/宏/类型；已有试点 `clang -fsyntax-only` 为 0/20。Tier A 的静态部分只做**可行性审计**，报告 `not_applicable`/compile rate，不报告 F1。
5. **动态 oracle 只覆盖已执行路径。** `NO_LEAK_OBSERVED` 不是“安全”；低覆盖率下的 clean 必须标 `inconclusive`，不能算 TN。Tier B 的 clean 只有在覆盖率达标且 oracle 一致时才算有效负例。
6. **Juliet 合成结果不能外推到真实项目，也不能与 SecVulEval 合并。** Juliet 是单 CWE、模板化、成对构造的测试集；Tier A 是跨 CWE、真实 CVE、函数片段。两者只能并列展示，不能互相校准或声称迁移。
7. **主终点。** Tier A 检测：`macro_f1`（二类宏平均）；Tier A 配对：`pair_da`（双方都判对）；Tier B 泄漏：`macro_f1` 与 `mcc`，并强制同时报告 `coverage`、覆盖率分层和 strict 视图。
8. **统一定义。** P/R/F1/MCC/macro-F1、coverage、pair DA、成本/延迟、失败处理、Wilson/聚类 bootstrap/McNemar/Holm 在本文件定义一次，所有轨道复用 `tools/bench_common.py`。
9. **诚实状态（2026-11-12 整合后）。** 已有真实结果：Tier A 12 个 legacy run、2 个 evidence run、2 个 pair-joint run；Tier B 5 个传统工具 run、1 个 MiMo LLM（Xiaomi 官方端点，postleakfix）、10 个 canonical hybrid v2 run（1,400 请求）、2 个 repair run。Tier B hybrid v1 与 postleakfix 之前的 LLM harness run 已移到 `results/superseded/`，不进入任何主表。DeepSeek 的 Juliet LLM 仍无结果（401/402）；B9 的 label-only baseline 仍未跑，B4/B8/B10 仍不是结果。任何 `planned`/`blocked`/`partial` 行都不能当作完整结论。
10. **产物。** `PROTOCOL.md`（本文件）、`README.md`、`schemas/`、`matrix/`、`tools/`、`examples/`、`datasets/`、`results/`；最终汇总为 `results/LEADERBOARD.md` + `results/final_summary.json`。

---

## 1. 范围、目标与非目标

### 1.1 两个层级

| 层级 | 数据集 | 评估单元 | 方法 | 主问题 | 允许的比较 |
| --- | --- | --- | --- | --- | --- |
| **A** | SecVulEval `secvul-split-v1` | 函数；漏洞/修复对 | LLM（DeepSeek、MiMo）× 策略 | 跨 CWE 的 LLM 检测与配对判别；模型/策略差异 | 同 split、同 task、同 prompt 语义下的模型/策略比较 |
| **B** | Juliet CWE-401 `juliet-cwe401-v1.3-subset-v1` | case variant（bad/good）；case family 为 cluster | 静态、动态、LLM、混合 | 单 CWE 内存泄漏上四种范式的同集比较 | 同 core set、同标签、同排除账本下的范式比较 |

**共同层**：字段命名、标签归一、指标公式、失败状态、成本向量、统计方法、结果目录、校验工具。

**不同层**：数据集、单元、标签来源、分母、主终点、成本口径、有效性边界。**任何跨层数字都不得进入同一个排名或同一个“总分”。**

### 1.2 非目标

- 不评估修复补丁的正确性/可编译性；现有 `repair_eval/` 是独立工作流。Tier A 的 repair 记录可保留在旧 run 中，但不进入 v1 指标。
- 不做训练/微调、RAG、多轮 agent、工具调用策略的通用排名；混合方法只在 Tier B 的预注册槽位内比较。
- 不把 CWE-401 的 3 条测试集案例升级为 CWE-401 专项结论，也不做逐 CWE 排名（n 不足）。
- 不重新抽样、不覆盖 `splits/`、不覆盖 `runner/runs/test_v1_*`。
- 不把 mock/dry-run/fixture 当结果；`examples/` 明确是合成 schema 样例。
- 不声称“通过 Juliet 就能预测真实项目”或“动态 clean 就是无泄漏”。

### 1.3 与现有资产的关系

| 资产 | 角色 | 本协议如何处理 |
| --- | --- | --- |
| `runner/runs/test_v1_*` | DeepSeek 三策略真实结果（2026-11-11） | **只读**；作为 Tier A 的 `done_frozen` 参考；需要统一 schema 时用 `bench_import_legacy.py` 派生，不改原文件 |
| `splits/test_detection_160.json` | Tier A 检测测试集 | 冻结；哈希 `bc83af…bf8` |
| `splits/test_pairs_180.json` | Tier A 配对测试集 | 冻结；哈希 `21218f…b47d` |
| `analysis/` | 旧统计管线 | 可参考其 Wilson/bootstrap/McNemar 定义；本协议工具不依赖它 |
| `repair_eval/` | 修复盲评 | 独立；v1 不重评 |
| `evidence_prompt/` | Tier A evidence-lines + counterfactual 真实 run | 只读导入；2×160；不覆盖 |
| `pair_joint/` | Tier A pair-joint 强制二选一真实 run | 只读导入；2×180；独立任务，不与分侧合并 |
| `hybrid/` | Tier B H1/H2 混合证据真实 run | 只读导入；2×5×140；canonical = v2（leak-fixed），OpenCode Go |
| `juliet_llm/` | Tier B MiMo LLM 真实 run | 只读导入；canonical = postleakfix；Xiaomi 官方端点，不是 OpenCode Go |
| `juliet_repair/` | Tier B 修复真实 run | 只读导入；70 bad，58 可观测 strict 口径 |
| `research/cwe401_scope.md` | CWE-401 范围核查 | 本协议引用其事实：测试集 CWE-401 仅 3 条，严格 C++ 单标签 0 |
| `benchmark/` | 本协议、schema、矩阵、工具 | 新增；不修改其他目录 |

### 1.4 现有真实结果的边界（必须随协议一起读）

来自 `report/results_summary.md`（2026-11-11，DeepSeek V4.1 Flash，thinking disabled，temperature 0）：

| 项目 | 数值 |
| --- | --- |
| 测试集 | 检测 160（128 V / 32 NV）；配对 180 对；修复 308 请求 |
| 每策略请求 | 828；三策略合计 **2,484** |
| 检测 macro-F1 | direct 0.383；few-shot 0.399；context 0.381 |
| 配对 DA | direct 0.117；few-shot 0.089；context 0.122 |
| 总 USD（每策略） | direct 0.645585；few-shot 1.131383；context 0.662251 |
| 统计结论 | 三策略两两 CI 全部跨 0；McNemar 经 Holm 均不显著；**不能宣称某策略更优** |
| 范围 | 单模型、单次运行；CWE-401 测试集 3 条；无 Juliet；无静态/动态 |

这些数字只用于校准新实验的对照，不是本协议的“预期结果”。新实验必须独立产生自己的 run，不得复制旧预测或把旧模型名改写成 MiMo。

### 1.5 2026-11-12 整合新增（只读导入）

| 实验 | 数据 | 请求/单元 | 产物 | 口径 |
| --- | --- | ---: | --- | --- |
| Tier A evidence prompt | `test_detection_160` | 2 × 160 | `tier_a/<model>_evidence/` | 只输入带行号源码；六字段输出；invalid 计入 strict |
| Tier A pair-joint | `test_pairs_180` | 2 × 180 | `tier_a/<model>_pair_joint/` | **强制二选一**；一个请求落成两条 side 记录；不与分侧混排 |
| Tier B LLM（MiMo） | Juliet test 140 | 1 × 140 | `tier_b/juliet_cwe401/llm_mimo_xiaomi/` | **Xiaomi 官方端点**（postleakfix canonical），不是 OpenCode Go；DeepSeek 无结果 |
| Tier B hybrid | Juliet test 140 | 2 × 5 × 140 = 1,400 | `tier_b/juliet_cwe401/hybrid_*` | canonical **v2**；direct / static / dynamic / combined / shuffled；OpenCode Go |
| Tier B repair | Juliet test bad 70 | 2 × 70（另 2 次反馈） | `tier_b/juliet_cwe401_repair/` | 58 个 baseline 可观测单元 strict pass；12 个 `not_applicable` 不入分母 |

这些 run 都是真实调用的只读派生，不是重新运行。汇总工具 `bench_final_summary.py` 从 canonical run 重算指标，不手抄源报告。

---

## 2. 术语、单元与分母

### 2.1 评估单元

| 层级/任务 | `unit_id` | `group_id` | `side` | `cluster_id` | `label.y_true` |
| --- | --- | --- | --- | --- | --- |
| A 检测 | `secvul:det:<idx>` | null | null | `project` | 1=V，0=NV |
| A 配对 | `secvul:pair:<pair_id>:<vulnerable|fixed>` | `pair_id` | `vulnerable`/`fixed` | `pair_id` | 1 / 0 |
| B 泄漏 | `juliet:<case_id>:<bad|good>` | `case_id` | `bad`/`good` | `case_family` | 1 / 0 |

- **一个函数/一个变体 = 一个记录**；配对任务仍是“一对 = 一个分析单元”，但落盘为两条记录（两侧各一条）。`pair_da` 在 `group_id` 上计算。
- **cluster 是统计重采样单位，不是标签**。Tier A 检测按 `project` 聚类；配对按 `pair_id`；Tier B 按 `case_family`。敏感性分析可换 cluster，但必须标注。
- `planned_units` 是冻结清单中的单元数；`recorded_units` 是实际落盘记录数；`valid` 是 `status="ok"` 且预测非空；`coverage = valid / recorded`。三者不可混用。

### 2.2 标签语义

- Tier A：`is_vulnerable=true` 表示数据源标注该函数含漏洞；`false` 表示**数据源未标注**，不证明绝对安全。修复版本也可能是“未标注为漏洞”，不是安全证明。
- Tier B：`bad`=Juliet 设计的泄漏变体，`good`=设计的非泄漏变体。动态工具是**方法**；标签来源写在 `label.label_source="juliet_intended"`。若动态 oracle 与设计标签矛盾，记 `oracle.mismatch=true`，不得静默改标签。
- 多 CWE：Tier A `cwe_list` 可能是连写（如 `CWE-415CWE-401`）。统一用正则 `CWE[-_ ]?(\d+)` 拆分、单条去重；只对 `is_vulnerable=true` 的记录做正例 CWE 统计。修复版本保留的 CWE 不是漏洞标签。
- 二值化：所有主指标只使用 `y_true ∈ {0,1}`；CWE 预测是次要字段，不参与主 F1。

---

## 3. 数据集与冻结

### 3.1 Tier A：SecVulEval `secvul-split-v1`

| 文件 | SHA-256 | 单元 | 用途 |
| --- | --- | --- | --- |
| `splits/test_detection_160.json` | `bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8` | 160（128 V / 32 NV） | 最终检测测试 |
| `splits/test_pairs_180.json` | `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d` | 180 对 / 360 函数 | 最终配对测试 |
| `splits/dev_detection_40.json` | 见 `FREEZE.txt` | 40（32 V / 8 NV） | 提示/校准；不进测试 |
| `splits/dev_pairs_20.json` | 见 `FREEZE.txt` | 20 对 | 提示/校准；不进测试 |
| `splits/dev_examples_fewshot.json` | 见 `FREEZE.txt` | 4 检测 + 2 修复示例 | few-shot；只来自 dev |

规则：

1. 不重新抽样、不按测试表现挑子集；测试集一次冻结。
2. 不把测试样本放进 few-shot 示例、阈值拟合、错误分析后的再训练。
3. context 策略存在已知伪影：测试集非空层 126/126 为漏洞，空层 34 条中 2 条漏洞；因此 context 结果必须按空/非空分层，不得把总体差异单独归因于“上下文推理”。
4. 5 条源级 32,767 字符截断（全部落在测试集）使长度结果是下界；超长函数单独标注。
5. CWE-401 在测试集只有 3 条（`5896`、`5886`、`8675`），严格“C++ 扩展名且单一 CWE-401”为 0；只作案例系列。逐 CWE 指标只对 `n≥10` 的 CWE 报告，其余标 `insufficient_n`。

### 3.2 Tier B：Juliet CWE-401 `juliet-cwe401-v1.3-subset-v1`

**当前状态：数据卡与正式结果均已产生。** `juliet/manifest.json` 与 `benchmark/datasets/juliet_cwe401_v1/dataset_manifest.json` 已发布：200 units / 100 groups / 42 families；dev 60 units/13 families，test 140 units/29 families。上游验证 22 个 bad unit 没有观察到 LSan leak，动态方法必须把这些 clean 视为 `inconclusive`。B9 是 **partial**：sanitizer/prompt 审计 200/200 通过，label-only baseline 未跑；LLM/hybrid 结果可以报告但必须带此 caveat，B4/B8 仍无结果。Tier B 的 canonical hybrid 是 v2（leak-fixed），v1 是 leakage-sensitive 历史；canonical MiMo Xiaomi 是 postleakfix run。Tier B run 的 `dataset.sha256` 应使用数据集卡的 `units.sha256`（稳定的 `subset_units.jsonl` 哈希），不要使用会随上游重建变化的 `juliet/manifest.json` 哈希。数据准备详见 `datasets/README.md`。

冻结数据卡必须包含：

- `source`：Juliet release/commit、URL、`archive_sha256`、许可、检索时间；
- `units`：`subset_units.jsonl` 路径 + SHA-256 + count + id_format；每行至少 `unit_id, group_id, variant, family, label, split, sources`；
- `splits`：dev/test 的 path/hash/count/cluster_count，以及 `split_policy="family-disjoint"`；
- `build`：编译器/版本、flags、`compile_commands`、`-DOMITGOOD`/`-DOMITBAD`、harness、timeout；
- `sanitization`：版本、删除项、identifier map 哈希、label-only 审计结果；
- `oracle`：LSan/Valgrind 版本、覆盖率阈值、consensus policy、mismatch 计数。

**Core set（主分析）**：单文件、可编译、目标函数可执行、动态 oracle 可判定、标签不矛盾。**Extended set**：多文件/特殊变体，只作次要/案例。两个集合分开报告，不合并 F1。

**Dev/test**：按 `case_family` 族级互斥；test 覆盖至少 70% 族，dev 至多 30%。族数不足 10 时用 5-fold family cross-validation，只报告 out-of-fold 预测，不声称单次冻结测试。所有提示、阈值、融合规则只在 dev 上定。

### 3.3 冻结与不可覆盖

- Tier A 的 `splits/FREEZE.txt` 是唯一冻结记录；任何改动需要新 `split_id`。
- Tier B 的 `dataset_manifest.json` 一旦 `frozen=true` 只读；改动必须新建 `juliet-cwe401-v2`。
- 旧 `runner/runs/test_v1_*` 只读；新 run 使用新目录/新 `run_id`。
- 任何结果文件包含 `dataset.sha256`；与 manifest 不一致的 run 不得进入主表。

---

## 4. 标签、输入与泄漏控制

### 4.1 Tier A 输入白名单

模型请求不得包含：`is_vulnerable`、`fixed_func_idx`、`changed_lines`、`changed_statements`、`cve_list`、`cwe_list`、`commit_message`、`commit_id`、`project_url`、`hash`、`idx`、`project`、`filepath`、`func_name`。context 策略只允许 `Execution Environment`、`External Function`、`Function Argument`、`Globals`、`Type Execution Declaration`，并逐项过滤 CVE/CWE/fixed_idx/vulnerab*/patch 等标记。

必须记录：`input.view`、`input.source_sha256`、`input.prompt_sha256`、`input.context_mode`、`input.sanitized=true`、`sanitizer_version`。`prompt_sha256` 是请求体或规范化 prompt 的哈希；同一模型/策略跨 run 必须一致，否则不可比。

### 4.2 Tier B 输入消毒（强制）

Juliet 的标签会通过多种通道泄漏：

| 通道 | 例子 | 处理 |
| --- | --- | --- |
| 文件名/路径 | `CWE401_Memory_Leak__..._bad.c` | LLM 输入不传路径；manifest 只用于映射 |
| 注释 | `/* FLAW */`、`/* FIX */`、`memory leak` | 删除或替换为中性注释 |
| 函数名 | `bad()`、`good()`、`badSink()` | 用 AST/token 级映射改为中性名（如 `target_fn`），映射哈希入 manifest |
| 宏 | `OMITBAD`、`OMITGOOD`、`CWE401` | LLM 输入用预处理后的变体，不传宏名；静态/动态构建记录宏 |
| 字符串/日志 | `"CWE401"`、`"bad"` | 删除/中性化 |
| 目录/项目名 | `CWE401_Memory_Leak` | 不传路径/项目名 |

**审计 gate**：训练一个 label-only baseline（只看文件名/注释/标识符，不看代码逻辑）。若其准确率显著高于机会水平（例如 95% CI 下限 > 0.60，或相对多数类提升 > 10 个百分点），停止 LLM/混合实验，修好 sanitizer。审计结果写入 `dataset_manifest.sanitization.audit` 和 `B9-LEAKAGE-AUDIT`。

### 4.3 工具输入

- 静态工具：只允许 `unit`/`file` 视图；命令行、版本、severity 阈值、warning 去重规则必须记录；工具不得读取被测标签或文件名中的 `bad/good` 作为特征。
- 动态工具：只允许预注册 harness/输入；suppression 文件必须哈希；不得按测试结果改 harness。
- 混合：工具证据可以进入 LLM prompt，但必须序列化一致；证据里不得包含 `y_true`、路径、`bad/good` 名称。

---

## 5. 方法轨道

### 5.1 LLM（Tier A 与 Tier B）

| 字段 | 要求 |
| --- | --- |
| 模型 | 精确 API ID、provider、endpoint、版本/日期；MiMo 的已核验 ID 为 `mimo-v2.6-flash`（OpenCode Go，2026-11-12），以 manifest 为准 |
| 策略 | Tier A：`direct` / `few-shot` / `context`；Tier B：`function` / `unit` 视图（可加 `few-shot`，必须来自 dev） |
| 解码 | temperature、top_p、max_tokens、thinking/reasoning 开关、response_format、seed（若支持）；DeepSeek 旧 run 为 temperature 0、thinking disabled、max 8192 |
| Prompt | `prompt_version` + `prompt_sha256`；跨模型比较必须使用**同一语义 prompt**；若 MiMo 需要不同 chat template，记录 template 哈希，并把它视为模型配置差异 |
| 输入 | 不得含标签；Tier B 必须 `sanitized=true`；记录 `source_sha256` |
| 输出 | JSON schema；检测/泄漏为 `is_vulnerable` 或 `has_leak` + confidence + evidence；解析失败记 `schema_invalid`，不修补 |

**模型比较规则**：同一策略下比较 DeepSeek vs MiMo；同一模型内比较三策略。不要在一个比较里同时改变模型和策略。2×3 交互只作探索性，样本量不足以支撑“通用最佳策略”。

**MiMo 配置混淆（必须记录）**：MiMo 工作组 pilot 显示 `mimo-v2.6-flash` 在 OpenCode Go 上即使请求 `thinking=disabled` 仍可能产生 reasoning token，且输出预算需用 `max_completion_tokens`；因此 MiMo 应标为“默认 reasoning 模式”，不能与 DeepSeek 的 non-thinking 等同。详见 `mimo/README.md`。这是模型/配置差异，不是策略差异；报告中必须写清楚。

### 5.2 静态工具（仅 Tier B；Tier A 仅可行性）

候选：Cppcheck、Clang Static Analyzer（`scan-build`/`clang --analyze`）、GCC `-fanalyzer`、Infer、CodeQL（可选）。每个工具必须记录 `name/version/command_template/rules/license`。

统一映射到 CWE-401 的规则（示例，实际以工具版本为准）：

| 工具 | 规则/消息 | 映射 |
| --- | --- | --- |
| Cppcheck | `memleak` | CWE-401 |
| Clang SA | `unix.Malloc` / `unix.MallocSizeof` | CWE-401 |
| GCC `-fanalyzer` | `-Wanalyzer-malloc-leak` | CWE-401 |
| Infer | `MEMORY_LEAK` | CWE-401 |
| CodeQL | `cpp/memory-leak` | CWE-401 |

**单元预测**：在目标变体函数范围内出现至少一条映射 warning → `y_pred=1`；否则 `y_pred=0`。warning 行号必须映射到函数范围；文件级 warning 不得直接算到所有函数。去重后记录 raw warning 数、severity、规则。

**主分析**使用预注册的默认阈值（任意映射 warning）；**敏感性**使用 high severity only。不得看完测试结果再选阈值。

**Tier A 静态可行性**：对 160 个函数尝试 `clang -fsyntax-only`/`-fanalyzer`；编译失败记 `compile_error`/`not_applicable`，不能记 `y_pred=0`。主输出是 `applicability_rate`、`compile_success_rate`、失败原因，不是 F1。已有试点 0/20 通过，说明不完整 CVE 函数不能直接跑静态工具。

### 5.3 动态工具（Tier B）

- **LSan/ASan**：`-fsanitize=address -fno-omit-frame-pointer -g`；`ASAN_OPTIONS=detect_leaks=1`；记录 exit code/stderr。
- **Valgrind Memcheck**：`--leak-check=full --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite,indirect --error-exitcode=<n>`；记录版本。
- **泄漏判定**：`definite` / `indirect` 计为 leak；`possible` / `still reachable` 单独报告，不进入主正例。`NO_LEAK_OBSERVED` 只表示执行路径上未观察到 definite/indirect leak。
- **覆盖率**：`gcov`/`llvm-cov`/instrumentation；记录 `unit_executed`、`target_function_entered`、`line_coverage`、`branch_coverage`（可选）、`allocation_site_executed`/`free_site_executed`（若可定位）。主分析阈值 `line_coverage >= 0.80` 且目标函数已进入；clean 低于阈值 → `inconclusive`。敏感性：0.50、any。
- **重复**：每个变体至少 3 次（若泄漏非确定）；任一次观察到 leak 即 leak；clean 需所有重复 clean 且覆盖率达标；记录 seed/输入。
- **harness**：Juliet 用 `-DOMITGOOD`（只编译 bad）和 `-DOMITBAD`（只编译 good）；同一编译器/flags/harness，只改变体宏。多文件变体记录 support files。

### 5.4 混合（AI+传统，Tier B）

| ID | 模式 | 定义 | 主要对照 |
| --- | --- | --- | --- |
| H1 | 静态证据 + LLM 裁决 | LLM 看 sanitized 代码 + 规范化 static warnings | static-only、LLM-only |
| H2 | 动态证据 + LLM | LLM 看代码 + 执行/覆盖率/泄漏栈 | dynamic-only、LLM-only |
| H3 | 固定级联 | static → dynamic → LLM；预注册路由/预算 | 单方法、any-warning |
| H4 | 证据融合 | 简单规则/逻辑回归/决策树，dev 拟合 | 单方法、多数投票 |
| H5 | 选择性预测 | 置信度/弃权阈值；risk-coverage | always-answer |

规则：

- 融合权重/阈值只在 dev family 上拟合；test 不调参。
- 级联必须报告每一级的 routing 数量、耗时、成本；不能只报最终 F1。
- 混合方法不得把动态 `NO_LEAK_OBSERVED` 直接当作标签；它只是 evidence。
- 如果 hybrid 的输入包含 static warning，必须序列化 warning 文本、规则、行号；不同 case 格式一致。
- 当前实现覆盖 H1（static evidence）与 H2（dynamic evidence）及其 combined；direct 是无证据对照，shuffled 是**同长度、错配 group 的安慰剂**。H3 级联尚未实现。证据只作为 prompt 内容，不作为标签；测试后不得用 test 结果调 prompt。

### 5.5 适用性矩阵

| 方法 | Tier A 检测 | Tier A 配对 | Tier B 泄漏 |
| --- | --- | --- | --- |
| LLM | 是 | 是（逐侧） | 是（sanitized function/unit） |
| 静态 | **仅可行性**（不完整函数） | 不适用 | 是（core set） |
| 动态 | 不适用（无完整可执行程序） | 不适用 | 是（core set） |
| 混合 | 不适用（无工具信号） | 不适用 | 是（预注册 H1–H5） |

`not_applicable` 不进入该方法的分母，也不写成 0；报告 `applicable_units`/`applicability_rate`。

---

## 6. 实验设计矩阵

### 6.1 Tier A 单元

| 单元 | 内容 | 状态 |
| --- | --- | --- |
| A0 | DeepSeek × {direct, few-shot, context} × {detection, pair} | `done_frozen`（6 run） |
| A1 | MiMo × 同上 6 格 | `done_frozen`（6 run） |
| A2 | 同策略 DeepSeek vs MiMo（3 个比较） | `done_frozen` |
| A3 | 2×3 交互（探索性） | `planned` |
| A4 | 静态可行性审计（不跑 F1） | `planned` |
| A5 | 修复（旧 run） | `out_of_scope` |
| A6 | Evidence-lines + counterfactual（2 模型 × 160） | `done_frozen` |
| A7 | Pair-joint 强制二选一（2 模型 × 180 对） | `done_frozen`，独立任务 |

**样本量**：检测 160（128/32），配对 180。配对比较以 pair 为单元；不要把 360 条函数当 360 个独立样本。单次运行的 run-to-run 方差不可估；若条件允许，至少对子集做 2–3 次重复并报告方差，否则明确“单次运行”。

### 6.2 Tier B 单元

| 单元 | 内容 | 状态 |
| --- | --- | --- |
| B0 | Juliet 获取、manifest、core/extended、build、oracle preflight | `done_frozen`（数据卡） |
| B1 | 静态工具套件（Cppcheck/Clang SA/GCC；可选 Infer/CodeQL） | `done_frozen`（Clang/Cppcheck） |
| B2 | LSan/ASan | `done_frozen` |
| B3 | Valgrind（交叉验证） | `done_frozen`（3.27.1，/tmp 解包） |
| B4 | DeepSeek sanitized function view | `blocked_gate`（OpenCode 401 / 官方 402；无结果） |
| B5 | MiMo sanitized function view | `done_frozen`（Xiaomi 官方端点，postleakfix） |
| B6 | H1 静态+LLM | `done_frozen`（2 模型） |
| B7 | H2 动态+LLM | `done_frozen`（2 模型） |
| B8 | H3 级联 | `planned`（未做） |
| B9 | 泄漏审计/label-only | `partial`（sanitizer/prompt 审计 200/200；label-only baseline 未跑） |
| B10 | 稳健性（阈值/种子/severity） | `planned` |
| B11 | Repair（70 bad；58 可观测） | `done_frozen`（2 模型） |
| B12 | Hybrid evidence suite（2×5×140） | `done_frozen`（canonical v2；v1 superseded） |

**同集原则**：B1–B8 必须使用同一 `test` core set 的同一 `unit_id` 列表、同一标签、同一排除账本。任何 case 被排除（编译失败、harness 失败、oracle mismatch、sanitizer 失败）必须在所有方法的结果中一致排除，并在 `exclusion_ledger` 中计数。不能“静态跑得少就用自己的分母”。

### 6.3 机器可读矩阵

- `matrix/experiment_matrix.csv`：核心单元、依赖、输出路径、状态；
- `matrix/innovation_matrix.csv`：创新槽位；
- `matrix/README.md`：状态词表和比较族。

矩阵是计划，不是结果。状态只能在真实产物通过 `bench_validate.py` 后改为 `done_frozen`；`partial` 表示只完成了预注册子集，不能把子集结果当作整个槽位的结论。

---

## 7. 指标定义

### 7.1 二分类检测

正类 = `vulnerable`/`bad`（`y_true=1`）。混淆矩阵 TP/FP/TN/FN 只对有效预测（`status="ok"` 且 `y_pred` 非空）计算：

```text
precision   = TP / (TP + FP)        # 分母 0 → null
recall      = TP / (TP + FN)
specificity = TN / (TN + FP)
F1          = 2TP / (2TP + FP + FN) # 正类 F1
negative_F1 = 2TN / (2TN + FN + FP)
macro_F1    = (F1 + negative_F1) / 2
balanced_acc= (recall + specificity) / 2
accuracy    = (TP + TN) / valid
MCC         = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
strict_acc  = (TP + TN) / n_recorded   # 非 ok 记录算错
coverage    = valid / n_recorded
```

规则：

- `macro_f1` 是**二类宏平均**，不是逐 CWE 宏平均。逐 CWE 的指标单独命名 `cwe_macro_f1`，且只对 `n≥10` 的 CWE 报告；CWE-401 标 `insufficient_n`，只作案例。
- 某一类在标签中不存在 → 该类 F1/macro-F1/BA 为 `null`，不填 0；某一类存在但从未被预测 → 该类 F1=0，并标 `*_class_not_predicted`。
- MCC 分母 0 → 按项目旧口径记 0.0 并 `mcc_degenerate=true`；同时报告 n。
- 只报 accuracy 是禁止的：Tier A 多数类基线 accuracy 80%、specificity 0、MCC 0；必须同时报 macro-F1/MCC/coverage。
- `strict_accuracy` 的分母是**已落盘记录**；缺失记录另报 `missing_units`，不得悄悄补零。

### 7.2 配对判别（Tier A）

每对的两个版本都判对才算正确：

| 类别 | 定义 |
| --- | --- |
| `vulnerable_detected_fixed_clean` | V 判 1，F 判 0（正确区分） |
| `both_flagged` | 两侧都判 1 |
| `both_clean` | 两侧都判 0 |
| `vulnerable_missed_fixed_flagged` | V 判 0，F 判 1（判反） |

```text
pair_da_valid = joint_correct / valid_pairs
pair_da_all   = joint_correct / recorded_pairs   # 任一侧无效 → 该对失败
coverage      = valid_pairs / recorded_pairs
```

必须同时报告 `both_flagged`/`both_clean`/`swapped` 比例；只报每函数 accuracy 会把“每对一个对一个错”的常量基线算成 50%，掩盖配对失败。Tier A 随机指定一侧的机会水平约 50%；旧测试集固定 seed 42 的单次随机基线为 56.1%（101/180），只作参照。

**强制二选一（pair-joint）是独立任务。** 模型每对只发一次请求，必须选 A 或 B；一个响应落成两条 canonical side 记录（选中侧 `y_pred=1`，另一侧 `0`），`extensions.forced_choice=true`。它没有 `both`/`neither` 类别，不能与分侧自由判定直接相减或合并；报告必须单列，并同时给长度启发式和位置偏差审计。

### 7.3 泄漏检测（Tier B）

- 主指标：`macro_f1`、`mcc`、`recall`（bad）、`specificity`（good）、`coverage`。
- 动态 clean 且 `line_coverage < threshold` 或 `target_function_entered=false` → **effective prediction = null**（inconclusive）。在 valid-only 中排除；在 strict 中算错。
- 正例（观察到 leak）即使覆盖率低也保留为 1；不能因为覆盖率低把已观察到的 leak 抹掉。
- 必须报告覆盖率分层：`ge_0.90`、`0.50_0.90`、`lt_0.50`、`unknown` 的 n/recall/specificity/macro-F1。
- `oracle_consistency`：设计标签 vs LSan vs Valgrind 的 consensus；`mismatch` case 计数并从主分母排除（排除账本）。
- 不能把 `NO_LEAK_OBSERVED` 写成 `safe`；只能写“在给定 harness/输入/覆盖率下未观察到 definite/indirect leak”。

### 7.4 成本与延迟

见 §10。所有结果必须报告：USD 已知和 + 未知记录数（不得补零）、wall/CPU/peak RSS、token、p50/p95 延迟、每 100 单元成本、每 TP 成本（有定义时）。成本不是“总分”的一部分；不得用单一标量把 USD、秒、MB 混合。

### 7.5 主/次终点

| 层级/任务 | 主终点 | 必须同时报告 | 次要 |
| --- | --- | --- | --- |
| A 检测 | `macro_f1` | P/R/F1/MCC/BA/coverage/strict_acc | 逐 CWE（n≥10）、context 分层、成本 |
| A 配对 | `pair_da` | 四类计数、coverage、per-side P/R | 位置/顺序、成本 |
| B 泄漏 | `macro_f1` + `mcc` | recall/specificity/coverage/strata/strict | 工具 agreement、案例、成本 |
| B 混合 | 对应任务主终点 | 与单方法基线差值 + CI | routing、成本、弃权 |

### 7.6 不允许的指标做法

- 不把 detection 与 pair 的样本池化成一个 micro-F1；
- 不把 Tier A 与 Tier B 池化；
- 不把 360 条配对函数当 360 个独立样本；
- 不用 accuracy 单独排名；
- 不给 F1/MCC 造 Wilson 区间（比例才用 Wilson；F1/MCC 用 bootstrap）；
- 不把 `not_applicable` 当 0 或当负例；
- 不把 schema-invalid/API-error 静默删除后只报 valid-only；
- 不把成本换算成未经验证的“云价格”后与 API USD 相加。

### 7.7 修复（Tier B，条件口径）

修复不是二分类检测；`y_pred` 在 `task=repair` 中表示 **strict repair pass**，不是“有漏洞”。判定：

```text
strict_pass = compile_pass
              AND leak_removed
              AND behavior_preserved
              AND baseline_leak_observed
```

- `strict_evaluable = baseline_leak_observed`；只有可观测单元进入分母（当前 58/70）。
- 12 个 baseline 在 LSan 下不可观测的单元记为 `status=not_applicable`，不当作 pass 或 fail，不用 0 填充。
- 这些单元仍可报告 compile/LSan/behavior 三项，但不能声称“泄漏已移除”。
- 报告必须同时给 58 可观测分母与 70 全量工程指标，不能把 58/58 写成 70/70。

---

## 8. 覆盖率、失败与分母

### 8.1 状态词表

| `status` | 含义 | valid-only | strict |
| --- | --- | --- | --- |
| `ok` | 有合法预测 | 计入 | 计入 |
| `schema_invalid` | 输出无法解析/字段不符 | 排除 | 算错 |
| `api_error` | 网络/鉴权/服务错误 | 排除 | 算错 |
| `timeout` | 请求/工具/执行超时 | 排除 | 算错 |
| `tool_error` | 静态/动态工具内部错误 | 排除 | 算错 |
| `compile_error` | 编译/预处理失败 | 排除 | 算错（若该方法声称支持） |
| `harness_error` | 动态 harness 失败 | 排除 | 算错 |
| `crash` | 被测程序崩溃 | 排除 | 算错 |
| `unsupported` | 方法明确不支持该语言/特性 | 排除 | 算错（若方法声称支持） |
| `not_applicable` | 方法不适用于该单元（如静态跑 Tier A 不完整函数） | **不计入该方法分母** | 不计入 |
| `inconclusive` | 动态 clean 但覆盖不足/oracle 不一致 | 排除 | 算错 |
| `skipped_budget` | 预算/配额跳过 | 排除 | 算错 |
| `not_run` | 计划但未执行 | 排除 | 算错 |

### 8.2 三种视图

1. **valid-only**：`status="ok"` 的单元；用于能力描述。必须同时给 `n_valid`、`coverage`、`invalid`。
2. **strict / end-to-end**：所有已落盘单元，非 ok 算错；用于部署视图。缺失记录另报，不补。
3. **common-valid**：两个被比较方法都有效的单元；用于配对 McNemar/bootstrap。必须报告 `n_common`、两侧 coverage；若 coverage 差异 > 5 个百分点，附加 strict 敏感性分析。

**主表使用哪个？** 排名/部署用 strict + coverage；方法能力用 valid-only；显著性用 common-valid。三者不能混在一张“赢家”表里。旧 DeepSeek 表是 valid-only（且 coverage=1），因此新表必须同时给 strict 才能与未来失败率不同的方法公平比较。

### 8.3 缺失与不完整 run

- `planned_units` 来自冻结清单；`recorded_units` 是落盘数；`missing = planned − recorded`。
- 若 `missing > 0`，run 标 `partial`，不得进入主比较；只能作 pilot/敏感性。
- 若一个 pair 只有一侧记录，该 pair 在 `pair_da_all` 中算失败；`valid_pairs` 不含它；不能把缺失侧补成 0。
- 若一个 Juliet case 只有 bad 或只有 good，不能计算该 case 的配对指标；记 `missing_side`，从 core set 排除并计入 `exclusion_ledger`。
- 修复：`baseline_leak_observed=false` 的单元是 `not_applicable`，从 strict 分母排除；不得把它们记成通过，也不得记成失败。当前 12/70 属于此类。

### 8.4 重试与预算

- LLM：最多 3 次尝试；记录 `api_attempts`；401/403 不重试；超时/5xx 可重试；重试的 token/延迟/成本都计入。
- 静态：单 TU 超时 600 s（可预注册调整）；超时记 `timeout`，不是“无 warning”。
- 动态：单 case 编译/运行超时 120 s（可预注册调整）；超时记 `timeout`/`inconclusive`，不是 clean。
- 预算跳过记 `skipped_budget`，不得从分母删除；报告剩余预算。
- 任何重试/跳过策略在运行前写入 manifest；不得看完结果再改。

---

## 9. 统计推断

### 9.1 比例区间

- 比例（precision/recall/specificity/accuracy/coverage/pair DA/类别比例）用 **Wilson 95%**；precision 的 Wilson 只是近似，优先看 bootstrap。
- F1、macro-F1、MCC、BA 不用 Wilson；用 **cluster percentile bootstrap 95%**。
- 报告 `successes/total`、point estimate、CI、method。

### 9.2 聚类 bootstrap

- 重采样单位：Tier A 检测 `project`；Tier A 配对 `pair_id`；Tier B `case_family`。
- 默认 10,000 次，seed 42，percentile 2.5/97.5，linear interpolation。
- 同一重采样同时计算两个方法的指标差值（paired difference）；不能对两个独立 bootstrap 的区间做“重叠即不显著”的判断。
- 报告 `cluster_count`、cluster 大小摘要、有效重采样数；有效 < 90% 标 `unstable=true`。
- 敏感性：换 cluster（如 project vs `(project, commit_id)`）必须标注，不能冒充主分析。

### 9.3 McNemar 与 Holm

- 配对二值正确性（检测单元正确/错误；pair 正确/错误）用 **exact two-sided McNemar**；报告 b/c、discordant、p、OR、risk difference。
- 主推断用 cluster bootstrap 差值 CI；McNemar 是次要证据（它假设单元独立，同项目/同族相关会使 p 偏小）。
- 多重比较：在每个**预注册 family** 内做 Holm；不同 family 不合并。
  - `A-STRATEGY-DS`：3 个策略两两比较，Holm m=3；
  - `A-MODEL`：每个策略一个模型比较（或预注册合并族）；
  - `B-PARADIGM`：预注册的方法对，Holm 在族内；
  - `B-HYBRID`：混合 vs 单方法基线，Holm 在族内。
- 报告 raw p 和 adjusted p；不能只报“显著/不显著”。

### 9.4 最小 n 与分层

- 逐 CWE 指标仅 `n≥10`；`n<10` 只列计数，标 `insufficient_n`，不做排名/检验。
- 单类别分层（如 context 非空层全为漏洞）不能算 macro-F1/BA；改报正类 F1/recall 或 specificity，并标 `single_class`。
- Tier B 的 cluster 数 < 30 时，bootstrap 只作描述；报告 cluster 数，避免把模板变体当独立样本。
- 交互/亚组分析一律标 `exploratory`，不进入主结论。

### 9.5 重复与不确定性

- 单次运行不能估计 run-to-run 方差；不能声称“稳定”。
- 若做重复：同一配置、不同 seed/时间，报告均值/区间和每次 run；不能只挑最好一次。
- API 在 temperature 0 下仍可能非确定；重复子集用于估计，不改变主表定义。
- 不做 p-hacking：主终点、比较族、排除规则、阈值在看 test 前冻结；事后分析标 `post_hoc`。

---

## 10. 成本模型

### 10.1 成本向量

统一记录，不强行合成一个标量：

```json
{
  "usd": 0.0123,
  "wall_s": 12.4,
  "cpu_s": 10.1,
  "peak_rss_mb": 512,
  "currency": "USD",
  "cost_basis": "api_price|local_compute|license|mixed|unknown",
  "pricing_snapshot": "2026-11-11"
}
```

- **LLM**：`usd` 按运行当天价格快照，从 `usage` 计算；分别记录 input/output/cached/reasoning tokens；缓存命中价与未命中价都记录；`opencode.allowance` 不是 USD 成本，不能填入 `usd`。
- **静态**：本地 OSS 的 `usd=null`（不是 0），`cost_basis="local_compute"`；记录 wall/CPU/RSS；商业工具若有 license 价格，单独列 `license_usd`，不与 API USD 混。
- **动态**：`usd=null`（本地），记录编译+运行+分析 wall/CPU/RSS、执行次数、覆盖率；云上运行若有真实账单，填 `usd` 并标 `cost_basis="local_compute"` 或 `"mixed"`。
- **混合**：各组件成本相加，但复用缓存/一次构建要单独说明，避免重复计费；记录 routing 数量。

### 10.2 归一化

- `cost_per_100_units_usd = usd_known_sum / n_units * 100`，仅当 `usd_complete=true`；否则给 known sum + unknown count，不补。
- `cost_per_true_positive_usd = usd_known_sum / TP`（TP>0；USD 不完整时标 `lower_bound`）。
- `wall_s_per_100_units` 同理；静态/动态的构建时间单独列 `setup_wall_s`，不摊进每单元而不说明。
- **normalized 成本口径**：固定 provider 价卡，DeepSeek `0.15/0.60/0.003`、MiMo `0.14/0.28/0.0028`（USD / 1M input / output / cached input tokens），逐条按 `(prompt - cached) * input + cached * cached_input + completion * output` 重算。字段：`cost.normalized.usd_sum`、`cost_per_100_units_usd`、`cost_per_1000_requests_usd`、`cost_per_correct_usd`、`cost_per_true_positive_usd`。不得用记录的 `cost_usd` 回填；缺 usage 的记录保持 unknown；本地工具的 normalized 为 `null`，不是 0。
- 两套口径必须并列：记录值反映各 run 当时的配置价（legacy DeepSeek 是 2× 峰价，v2 是 0.5× 非峰价），normalized 用于跨 run 可比；不得只报其中一个而不说明。
- Tier B 的 repair 源记录只有聚合 token、不含逐条 cached token，因此不计算 normalized（保持 `null`）；其 recorded list USD 仍可报告。
- Tier A 的“单元”是函数或 pair；Tier B 是 case variant。不同层的 per-100 不能直接比较。
- 报告 Pareto 前沿（成本 vs 主指标），不要造加权总分；若必须固定预算，预算和权重在看 test 前预注册。

### 10.3 延迟

- LLM：每次请求 wall latency（含重试则记录每次和总）；p50/p95；并发数。
- 静态：每 TU 分析时间；构建/预处理单独。
- 动态：每 case 编译+运行+分析；重复取总/中位；超时计入。
- 混合：各段相加 + 融合开销；缓存命中要标注。

---

## 11. Tier A 执行协议（SecVulEval）

### 11.1 检测

1. 输入：`splits/test_detection_160.json` 的 160 个函数；direct 只给函数；context 给白名单上下文；few-shot 给 dev 示例；evidence 只给带行号源码并要求证据行/机制/反事实，不注入标签或元数据。
2. 输出：`{"is_vulnerable": bool, "confidence": 0..1, "rationale": str}`；evidence 用六字段 schema；解析失败 `schema_invalid`。
3. 单元：`secvul:det:<idx>`；cluster `project`；标签 `is_vulnerable`。
4. 主指标：`macro_f1`；同时 P/R/F1/BA/MCC/coverage/strict_acc。
5. 分层：context empty/nonempty；CWE n≥10；长度档；截断样本。
6. 成本：tokens/USD/延迟；不把旧 run 的成本复制给新模型。

### 11.2 配对

1. 输入：`splits/test_pairs_180.json` 的 180 对；逐侧请求，不告诉模型哪侧是漏洞；不提供 diff/CWE/commit。
2. 输出：每侧一个 verdict；落盘两条记录，`group_id=pair_id`，`side` 明确。
3. 主指标：`pair_da`；同时四类计数、coverage、per-side P/R。
4. 顺序：新 run 对每对的呈现顺序用固定 seed 随机化并记录；旧 run 的顺序作为已知配置，不改写。
5. 不能把两侧当独立样本做 McNemar；McNemar 的单位是 pair 的正确/错误。
6. **Pair-joint 变体**：每对一次请求，强制 A/B 二选一；一个响应落成两条 side 记录，`extensions.forced_choice=true`。必须单列报告，并给长度启发式/位置偏差；不得与分侧四分类合并。

### 11.3 修复（Tier B B11，条件口径）

旧 Tier A repair 记录仍在 `runner/runs`，由 `repair_eval/` 负责，不进入 v1 主表。Tier B 新增 B11：70 个 test bad，strict_pass 见 §7.7；只报告 58 个 baseline 可观测单元的分母，12 个 `not_applicable` 不入分母。不得把文本相似度/精确匹配写成修复正确率。

### 11.4 静态可行性（Tier A 唯一允许的静态活动）

- 对 160 个函数尝试生成 `compile_commands`/`clang -fsyntax-only`；记录成功/失败原因。
- 输出：`applicability_rate`、`compile_success_rate`、失败类别（缺头文件/宏/类型/语法）。
- 不计算 F1；不把失败当负例；不把 0/160 写成“静态工具 F1=0”。
- 如果未来构造出 compile-ready 子集，必须作为新数据集/新 run，不得混入 `secvul-split-v1` 主表。

### 11.5 MiMo 对比规则

1. 使用同一 `test_detection_160`/`test_pairs_180`、同一 prompt 语义、同一 few-shot 示例、同一解码（temperature 0、输出上限 8192）。`mimo-v2.6-flash` 使用 `thinking=disabled` + `reasoning_effort=none` + `max_completion_tokens`；DeepSeek 使用 non-thinking + `max_tokens`。必须记录为配置差异，不能伪称完全相同解码。
2. 模型 ID/版本/端点/价格快照写入 manifest；`model.family="mimo"`，`method_id` 独立。
3. 若 MiMo 的 chat template/思考模式无法与 DeepSeek 完全一致，记录差异；该比较是“模型+配置”比较，不是纯模型能力；不得只改 prompt 后与旧 DeepSeek 比。
4. 每个策略/任务独立 run；不能用一次 run 的 detection 预测复用为 pair 预测。
5. 比较用 `bench_compare.py`：common-valid、delta macro-F1/DA、paired bootstrap、McNemar；报告 raw/ Holm p。
6. 旧 DeepSeek 结果不重跑、不覆盖；若需要完全同 prompt 的新基线，另建 run，不改旧 run。

---

## 12. Tier B 执行协议（Juliet CWE-401）

### 12.1 数据准备

- 获取 Juliet C/C++（固定 release/commit），只取 `CWE401_Memory_Leak`；记录归档 SHA-256/许可。
- 枚举 `case`，生成 `units.jsonl`：`unit_id, case_id, variant, family, cluster_id, y_true, source_path, source_sha256`。
- 识别单文件 core set；多文件 `_51`–`_54` 进 extended set。
- 生成 `compile_commands`/构建脚本；分别用 `-DOMITGOOD`/`-DOMITBAD` 构建 bad/good 变体。
- 运行动态 preflight（LSan，可选 Valgrind）：确认 bad 观察到 leak、good clean 且覆盖率达标；不一致 case 记 `oracle_mismatch`。
- 跑 sanitizer 审计 + label-only baseline；未通过不进入 LLM/混合。
- 冻结 `dataset_manifest.json`，生成 family-disjoint dev/test。

### 12.2 静态 pipeline

1. 每个 variant 单独预处理/编译，生成 TU（只含目标变体）。
2. 运行动态/静态工具；命令、版本、flags、severity 记录。
3. 解析 warning：规则→CWE-401 映射；行号→目标函数范围；去重；记录 raw warning 数。
4. 单元预测：目标函数内至少一条映射 warning → 1，否则 0；工具崩溃/超时 → `tool_error`/`timeout`，不是 0。
5. 同一 case 的 bad/good 使用同一命令/flags；只改变体宏。
6. 主分析默认阈值；high-severity 只作敏感性。

### 12.3 动态 pipeline

1. 用预注册编译器/flags 构建 bad/good 可执行文件；记录 build log。
2. 运行 LSan（和/或 Valgrind）；记录 exit code、stderr、leak kind/bytes。
3. 运行覆盖率（同一 executable 或单独 instrumented build）；计算目标函数 entered/line coverage。
4. 每个变体重复 3 次（可预注册更多）；leak 任一命中即 1；clean 需全部 clean 且 coverage ≥ 0.80；否则 `inconclusive`。
5. 记录 `coverage` 块、`oracle` 块、输入/种子、超时。
6. 不把 `still reachable`/`possible` 当主正例；单独表。

### 12.4 LLM pipeline

1. 输入 view：
   - `function`：sanitized 目标函数（bad 或 good）——主分析，和 Tier A 的函数级输入可比；
   - `unit`：只含目标变体的 sanitized TU——次要，和静态/动态 whole-unit 可比。
2. 消毒：路径/文件名/注释/`bad|good` 标识符/`CWE401`/`OMIT*` 宏全部移除或中性化；记录 sanitizer 版本/哈希。
3. 输出：`{"label": "vulnerable"|"not_vulnerable", "confidence": 0..1, "reason": "..."}`（当前 Juliet LLM/hybrid 契约）；解析失败 `schema_invalid`。Tier A 的 evidence prompt 使用六字段 schema，见 §11.1。
4. 单元：`juliet:<case_id>:<bad|good>`；cluster `case_family`；标签 Juliet intended。
5. 主指标 macro-F1/MCC；同时 recall/specificity/coverage/strict；低覆盖/不一致按 §7.3。
6. 端点必须写进 manifest 和报告：当前 MiMo 140 test 的 canonical run 是 **Xiaomi 官方 API** 的 postleakfix run，不是 OpenCode Go；同模型 ID 不等于同服务栈。旧 harness run（`20261111T204701Z...`）已 superseded，不能引用其数字。DeepSeek 140 因 401/402 无结果，不能从 MiMo 推断。
7. Canonical 选择：`juliet_llm/runs/20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix`；`_repro` run 与它同分，用作复现证据，不另立一行。

### 12.5 混合 pipeline

- H1/H2/H3/H4/H5 见 §5.4。
- 融合规则/阈值只在 dev family 拟合；test 只评估。
- 报告每个组件的贡献（ablation）：static-only、dynamic-only、LLM-only、hybrid；同一 test 集。
- 级联报告 routing 数量、每级耗时/成本、最终指标；不能只报最终 F1。
- 证据序列化必须一致；不得把 `y_true`/路径/`bad|good` 写进 prompt。
- 已实现：direct / static / dynamic / combined / shuffled（安慰剂），2 模型 × 5 方法 × 140。`combined` 是 static+dynamic 证据；`shuffled` 使用另一 group 的 combined 证据，固定 seed，非自身。报告必须同时给 direct 与 shuffled 的聚合和逐单元翻转数；若真实证据不优于安慰剂，不能声称证据内容有效。
- **Canonical 版本是 v2**（`hybrid/runs/hybrid_v2_*`，输入包 `hybrid/inputs_v2/units.jsonl`，prompt `hybrid-v2-juliet-llm-binary-2026-11-12.2`）。v1 的 6 个 good 单元仍含字面量 `"Benign, fixed string"`，是 label shortcut；v1 全部标为 leakage-sensitive historical，放在 `results/superseded/`，不进入任何主表、比较或 pooled 统计。主表只允许 v2 的 10 个 run。

### 12.6 同集对齐检查清单

- [ ] 所有方法使用同一 `test` core set 的 `unit_id` 集合；
- [ ] 所有方法使用同一 `y_true`（`label_source="juliet_intended"`）；
- [ ] 排除账本一致（编译失败、harness 失败、oracle mismatch、sanitizer 失败）；
- [ ] 每个 case 的 bad/good 都在同一方法中评估（不能只跑 bad）；
- [ ] 静态/动态/LLM 的 `unit_id` 可由同一 manifest 连接；
- [ ] 没有方法使用文件名/路径/注释作为特征；
- [ ] 所有失败都有 `status`，没有被静默删除；
- [ ] 同一 case family 不跨 dev/test；
- [ ] 报告 n、cluster 数、coverage、排除计数。

### 12.7 Oracle 与标签

- `label_source="juliet_intended"` 是主标签。当前数据卡记录 200/200 编译/宏/符号 gate 通过，但 178/200 有 runtime label 支持；22 个 bad unit 无 observed leak，动态 clean 对这些 unit 必须 `inconclusive`。
- LSan/Valgrind 是方法 + 一致性检查；不能用同一个工具同时当方法和唯一 ground truth。
- `oracle.dynamic_consensus`：`leak`/`clean`/`disagree`/`not_run`；`mismatch=true` 的 case 从主分母排除，计数报告。
- 动态 clean 低覆盖 → `inconclusive`，不是 `good`；不能进入 TN。
- 如果设计标签与两个动态工具都矛盾，标 `dataset_or_harness_defect`，排除并审计；不得改标签。

### 12.8 外推限制

- Juliet 是合成的、模板化的、单 CWE；结果不能外推到真实项目、其他 CWE 或 SecVulEval。
- 即使 Juliet 上某方法最好，也不能声称它在真实代码上最好；只能作为“受控条件下的机制证据”。
- 跨层迁移（I7）只做可行性/描述性，不把 Juliet F1 与 SecVulEval F1 放同一张表比较。

---

## 13. 结果 schema、目录与工具

### 13.1 目录

```text
benchmark/
├── PROTOCOL.md
├── README.md
├── VERSION
├── schemas/                 # prediction/run/metrics/dataset JSON Schema
├── matrix/                  # 实验矩阵 CSV/Markdown
├── tools/
│   ├── bench_common.py      # 指标/统计/成本原语
│   ├── bench_validate.py    # run 校验
│   ├── bench_validate_dataset.py # 数据卡/哈希/计数校验
│   ├── bench_metrics.py     # 单 run 指标
│   ├── bench_compare.py     # 两 run 配对比较
│   ├── bench_import_legacy.py
│   ├── bench_import_round2.py # evidence/pair-joint/hybrid/LLM/repair 只读导入
│   ├── bench_final_summary.py # 最终 LEADERBOARD.md + final_summary.json
│   └── selftest.py
├── examples/                # 合成 schema 样例（不是结果）
├── datasets/                # 数据卡（Tier A 引用；Tier B 已冻结）
└── results/                 # 不可变 run 目录
    ├── tier_a/              # 12 legacy + 2 evidence + 2 pair-joint
    ├── tier_b/juliet_cwe401/ # 5 传统 + 1 LLM postleakfix + 10 hybrid v2
    ├── tier_b/juliet_cwe401_repair/ # 2 repair
    ├── LEADERBOARD.md
    └── final_summary.json
```

每个 run：

```text
<run_dir>/
├── run_manifest.json
├── predictions.jsonl
├── metrics.json
├── metrics.md
├── validation.json
├── run.log
└── PROVENANCE.md
```

### 13.2 `prediction` 必填字段

| 字段 | 说明 |
| --- | --- |
| `schema_version` | `benchmark-prediction-v1` |
| `run_id` | 与 manifest 一致 |
| `tier`/`track`/`task` | A/B；secvuleval/juliet_cwe401；detection/pair_detection/leak_detection/repair |
| `unit_id`/`cluster_id`/`group_id`/`side` | §2.1 |
| `dataset` | dataset_id/split_id/sha256 |
| `method` | method_id/family/name/strategy/model/tool/config_sha256 |
| `input` | view/source_sha256/prompt_sha256/context_mode/sanitized/sanitizer_version |
| `label` | y_true/cwe/label_source |
| `prediction` | y_pred/cwe_pred/confidence/evidence_lines/rationale/raw_output_sha256 |
| `status`/`error` | §8.1 |
| `coverage` | 动态必填；unit_executed/target_function_entered/line_coverage/coverage_source |
| `oracle` | Tier B 可选/建议；consensus/mismatch |
| `usage`/`cost` | token/延迟/USD/wall/CPU/RSS/cost_basis |
| `provenance` | produced_by/created_at/source_artifact/source_sha256/record_index |

`extensions` 是方法/任务特有字段的容器：pair-joint 用 `forced_choice=true`、`selected_version`、`vulnerable_slot`、`selected_side`；repair 用 `strict_evaluable`、`strict_pass`、`compile_pass`、`leak_removed`、`behavior_preserved`、`first_attempt_strict_pass`。这些字段不改变必填字段的语义，但 `task=repair` 时 `prediction.y_pred` 表示 strict repair pass，不是漏洞预测。

### 13.3 `run_manifest` 必填

`run_id, created_at, protocol_version, tier, track, dataset{id,split,path,sha256,unit_count,group_count}, method, execution{started_at,status,planned_units,recorded_units}, artifacts{predictions}, hashes`。

`unit_count` 是**预测记录数**（配对为两侧之和，Juliet 为 bad+good）；`group_count` 是 pair/case 数。两者不同时，指标以 `planned_units`（记录数）和 `group_count`（配对/案例数）分别报告。

### 13.4 命名

`<tier>_<track>_<model_or_tool>_<strategy>_<split>_<yyyymmdd>_<short_hash>`；不要 `latest/final/new`。同一配置重跑 = 新 run；不覆盖。

### 13.5 工具

```bash
# 校验
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
python3 benchmark/tools/bench_validate.py --run-dir <run> --jsonschema
# 指标
python3 benchmark/tools/bench_metrics.py --run-dir <run>
# 比较
python3 benchmark/tools/bench_compare.py --run-a <runA> --run-b <runB>
# 旧 run 派生（不改原文件）
python3 benchmark/tools/bench_import_legacy.py --run-dir runner/runs/test_v1_direct_independent
# round-2 只读导入 + 校验 + 指标
python3 benchmark/tools/bench_import_round2.py --measure --force
# 最终统一汇总
python3 benchmark/tools/bench_final_summary.py
# 工具自检（合成 fixture）
python3 benchmark/tools/selftest.py
```

工具只依赖 Python 标准库；`--jsonschema` 可选依赖 `jsonschema`。

### 13.6 旧结果派生

`bench_import_legacy.py` 将 `runner/runs/test_v1_*` 的 detection 记录复制为统一 schema；repair 记录只计数、不写入。manifest 标 `legacy_import.derived_not_rerun=true`，`PROVENANCE.md` 记录源哈希。派生视图不是新实验，不能改预测。

`bench_import_round2.py` 以同样方式只读导入 evidence/pair-joint/hybrid/LLM/repair；新 run 的 `provenance.note` 明确“copied, not re-run”。pair-joint 的联合响应不是分侧判定，必须保留 `extensions.forced_choice=true`。Tier B hybrid 导入固定 `version="v2"`；v1 不再导入为 canonical，历史目录只从 `results/superseded/` 读取。

---

## 14. 有效性威胁与外推限制

### 14.1 构造效度

- **标签**：Tier A 的 negative 是“未标注”，不是安全；Tier B 的 good 是设计非泄漏，不是所有缺陷的证明。
- **静态映射**：工具规则→CWE-401 的映射可能漏报/误报；不同版本规则不同；必须记录版本/命令。
- **动态 oracle**：只覆盖执行路径/输入；低覆盖 clean 不是安全；`still reachable` 不进入主正例。
- **合成数据**：Juliet 模板化、单 CWE、成对构造；真实代码的分布、规模、依赖不同。
- **LLM 污染**：公开 CVE 可能出现在预训练；不能排除记忆；结果解释为“当前模型/当前数据”。
- **上下文伪影**：Tier A context nonempty 与标签强相关；不能把 context 差异当因果能力。
- **截断**：5 条 32,767 字符截断使长度/超长函数结果是下界。

### 14.2 内部效度

- 数据泄漏：Tier A 禁止字段；Tier B 文件名/注释/标识符/宏；label-only 审计。
- 工具版本/阈值：必须冻结；不能看 test 后调 severity。
- 单次运行：不能估计 run-to-run 方差；不能声称稳定。
- 多重比较：预注册 family + Holm；交互/亚组标探索性。
- 排除偏差：排除账本必须跨方法一致；不能“某方法编译失败就换分母”。

### 14.3 外部效度

- Tier A 测试集 160/180、项目有限；不能代表所有 C/C++ 项目。
- Tier B 只覆盖 CWE-401；不能外推到其他 CWE。
- 成本价格随日期/地区/provider 变化；必须带价格快照。
- 模型版本会漂移；run 必须记录版本/日期/端点。

### 14.4 统计效度

- 小 n/少 cluster 使 CI 很宽；不能把“不显著”当“无差异”，也不能把“数值最高”当“更好”。
- McNemar 假设单元独立；同项目/同族相关会使 p 偏小；主推断用 cluster bootstrap。
- 不能做事后选种子/选阈值/选指标；不能只报显著结果。

### 14.5 可以写 / 不能写

| 可以写 | 不能写 |
| --- | --- |
| “在 160 条测试函数上，A 的 macro-F1 为 x（95% CI …），B 为 y；差值 CI 跨 0。” | “A 比 B 更好”而没有 CI/校正 |
| “在 Juliet CWE-401 core set 上，静态/动态/LLM/混合的同集比较为 …” | “Juliet 上最好 = 真实项目最好” |
| “动态在给定 harness/覆盖率下未观察到 definite/indirect leak。” | “动态证明无泄漏/函数安全” |
| “静态工具在不完整 CVE 函数上 0/20 可编译，故不适用。” | “静态工具 F1=0” |
| “Pair-joint 强制二选一 DA 为 x；该任务与分侧 DA 不同。” | “联合 DA 高，所以分侧配对能力也高” |
| “长度启发式单独达到 74.44%；DeepSeek 不显著高于它。” | “Pair-joint DA 证明了跨版本语义推理” |
| “修复在 58 个 baseline 可观测单元上 58/58 strict pass。” | “70/70 修复成功”或“12 个不可观测单元也修好了” |
| “混合 v2 combined 相对 direct 多修 0–1 个单元，Holm 后不显著。” | “证据引导显著提升检测”；或引用 v1 的满分/旧值 |
| “MiMo Juliet 140 是 Xiaomi 官方端点结果。” | “OpenCode Go 的 MiMo Juliet 结果”；或把旧 pre-postleakfix harness 数字当正式值 |
| “CWE-401 测试集只有 3 条，只作案例。” | “CWE-401 召回率/F1 为 …” |
| “MiMo 与 DeepSeek 在同一策略/数据上差值为 …” | “MiMo 全面优于 DeepSeek” |
| “单次运行，未估计 seed 方差。” | “结果稳定/可复现”而没有重复 |

---

## 15. 报告与复现检查清单

### 15.1 每个结果表必须带

- [ ] 数据集/ split / SHA-256 / 单元数 / 标签计数；
- [ ] 方法（模型/工具、版本、prompt/tool config 哈希）；
- [ ] n（planned/recorded/valid）、coverage、失败状态分布；
- [ ] 主指标 + 95% CI + 统计方法；
- [ ] strict 与 valid-only（或明确只报一种并说明）；
- [ ] 成本向量（USD 已知/未知、wall/CPU/RSS、p50/p95）；
- [ ] 分层（Tier A context/CWE/长度；Tier B coverage strata）；
- [ ] 排除账本（编译失败、oracle mismatch、inconclusive）；
- [ ] 限制与外推边界。

### 15.2 运行前

- [ ] 数据集哈希与 manifest 一致；
- [ ] prompt/tool config 哈希冻结；
- [ ] 主终点、比较族、排除规则、阈值、预算预注册；
- [ ] Tier B：B0 数据卡冻结；B9 的 sanitizer/prompt 审计通过并记录 label-only baseline 是否完成；core set/exclusion ledger 冻结；
- [ ] 旧结果只读，输出目录为新 run。

### 15.3 运行后

- [ ] `bench_validate_dataset.py` 无 errors（Tier B）；`bench_validate.py` 无 errors；
- [ ] `bench_metrics.py` 的 counts 与 manifest 一致；
- [ ] `bench_compare.py` 只在同数据集/同 task 上运行；
- [ ] 报告同时给 strict/valid-only、coverage、CI；
- [ ] 没有把 mock/example/derived 当新实验；
- [ ] 没有覆盖旧 run。

### 15.4 复现命令

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/selftest.py'

wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
python3 benchmark/tools/bench_validate.py --run-dir <run> --jsonschema'

wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_metrics.py --run-dir <run>'

wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_compare.py --run-a <runA> --run-b <runB>'

# round-2 imports + final integrated leaderboard
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_import_round2.py --measure --force && \
python3 benchmark/tools/bench_final_summary.py'
```

---

## 附录 A：公式速查

```text
TP/FP/TN/FN 只在 status=ok 且 y_pred 非空上累计。
precision = TP/(TP+FP)
recall = TP/(TP+FN)
specificity = TN/(TN+FP)
F1 = 2TP/(2TP+FP+FN)
negative_F1 = 2TN/(2TN+FN+FP)
macro_F1 = (F1+negative_F1)/2
BA = (recall+specificity)/2
accuracy = (TP+TN)/(TP+FP+TN+FN)
MCC = (TP*TN-FP*FN)/sqrt((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN))
strict_accuracy = (TP+TN)/n_recorded
coverage = (TP+FP+TN+FN)/n_recorded
pair_da_valid = joint_correct/valid_pairs
pair_da_all = joint_correct/recorded_pairs
```

## 附录 B：状态判定树

```text
方法是否适用于该单元？
  否 → not_applicable（不计入该方法分母）
  是 → 是否产生输出？
        否 → 运行前跳过：skipped_budget/not_run；运行失败：api_error/timeout/tool_error/compile_error/harness_error/crash
        是 → 输出能否解析为合法 schema？
              否 → schema_invalid
              是 → 动态 clean 且覆盖率不足/oracle 不一致？
                    是 → inconclusive（valid-only 排除，strict 算错）
                    否 → ok
```

## 附录 C：静态工具映射表（最小集）

| 工具 | 规则 | CWE | 备注 |
| --- | --- | --- | --- |
| Cppcheck | `memleak` | CWE-401 | `--enable=warning` 或预注册配置 |
| Clang SA | `unix.Malloc` | CWE-401 | `--analyze`/scan-build |
| Clang SA | `unix.MallocSizeof` | CWE-401 | 视版本 |
| GCC | `-Wanalyzer-malloc-leak` | CWE-401 | `-fanalyzer` |
| Infer | `MEMORY_LEAK` | CWE-401 | 版本/规则记录 |
| CodeQL | `cpp/memory-leak` | CWE-401 | 可选 |

映射只用于“把 warning 归到 CWE-401”；不改变工具原始消息。新增工具/规则必须先在 dev 上冻结映射，再跑 test。

## 附录 D：Juliet 构建/harness 模板

```bash
# bad 变体：只保留 bad()
cc -g -O0 -DOMITGOOD -I<testcases> case.c -o case_bad
# good 变体：只保留 good()
cc -g -O0 -DOMITBAD  -I<testcases> case.c -o case_good
# LSan
ASAN_OPTIONS=detect_leaks=1:exitcode=23 ./case_bad
# Valgrind
valgrind --leak-check=full --show-leak-kinds=definite,indirect \
  --errors-for-leak-kinds=definite,indirect --error-exitcode=24 ./case_bad
```

实际 flags/编译器以数据卡为准；以上只是模板，不是唯一正确答案。多文件 case 需列出 support files 并保持同序编译。

## 附录 E：Schema 与示例

- `schemas/prediction.schema.json`：单条记录；
- `schemas/run_manifest.schema.json`：run 身份；
- `schemas/metrics.schema.json`：指标输出；
- `schemas/dataset_manifest.schema.json`：数据卡；
- `examples/run_detection|run_pair|run_leak/`：合成样例（不是结果）。

## 附录 F：版本变更

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| 1.0.0 | 2026-11-12 | 初版：Tier A/B 分层、统一 schema/指标/失败/成本/统计、矩阵、校验/指标/比较工具 |
| 1.0.0 + integration | 2026-11-12 | 增加 round-2 只读导入（evidence / pair-joint / hybrid / MiMo Xiaomi 官方端点 / repair）与最终汇总；schema 未变，新增 `extensions` 约定、pair-joint 独立任务、repair 58 可观测口径；B9 标 `partial` |
| 1.0.0 + v2 sync | 2026-11-12 | Tier B hybrid 切换到 leak-fixed **v2** canonical（10 run × 140），v1 与 pre-postleakfix harness 移入 `results/superseded/` 且不进入主表；MiMo Xiaomi 改为 postleakfix 正式 run；新增 normalized 成本口径与每 100 单元/每 1000 请求/每 correct/每 TP 字段；schema 与 run 协议版本保持 1.0.0 |

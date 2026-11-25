# `benchmark/extensions/` — 新方法设计与 canonical 接入

**版本：`0.3.0`** · **日期：2026-11-22** · **范围：`benchmark/extensions/` 独占**

> 本目录是统一 benchmark 的**扩展层**：定义新方法实验的 canonical 输入/输出映射、校验规则和统计口径，并提供可执行的导入器、校验器、指标工具与自检。
>
> **已有真实产物接入。** `pair_debias` 的 forced fwd/rev（2 模型）与 open fwd/rev（2 模型）、`evidence_verify` 四臂、`dynamic_enhanced/test140_enhanced_v3`、`hybrid_dynamic_enhanced` 两模型，以及 `static_extended` 的 CodeQL 2.27.4 正式 run 已导入为 canonical run 并通过校验。本目录**没有重新调用模型或分析器**；canonical run 都是 producer 真实产物的只读导入（`provenance.note` 明确 `copied, not re-run`）。
>
> 本目录同时提供最终扩展汇总：`benchmark/results/EXTENSIONS.md`（人读）与 `benchmark/results/extension_summary.json`（机器读），由 `benchmark/tools/bench_ext_summary.py` 从 canonical run 重算并复核。主 leaderboard（`benchmark/results/LEADERBOARD.md`、`final_summary.json`）和父协议（`benchmark/PROTOCOL.md`、`benchmark/schemas/`）**没有导入扩展数字**；LEADERBOARD 只加了一条指向 `EXTENSIONS.md` 的链接，不做跨设计池化。
>
> **2026-11-22 新增。** 本轮五个弱点实验已作为独立 design 接入：`codeql_alert_triage`（8 run）、`conservative_verification`（4 run）、`diff_guided_pair`（8 run）、`coverage_instrumented_dynamic`（1 run）、`interpretable_baseline`（9 run），共 30 个 canonical run。汇总见 [`benchmark/results/NEXT_ITERATION.md`](../results/NEXT_ITERATION.md) 与 [`next_iteration_summary.json`](../results/next_iteration_summary.json)；主表仍未修改。

---

## 0. 一页结论

| 项 | 状态 |
| --- | --- |
| 8 个 design 的 registry / canonical 映射 / 统计口径 | **定义完成** |
| `ext_import.py`：raw → parent-valid canonical run | **可用**；已有 8 类设计路径（含 real producer 格式） |
| `ext_validate.py`：父结构 + 扩展块 + 设计不变量 | **可用**；已接入 run 全部通过 |
| `ext_metrics.py`：设计专用端点 | **可用**；pair/evidence/dynamic/hybrid/static 真实 run 已重算 |
| 真实结果 | **已导入**：pair_debias 8 run、evidence_verify 4 run、dynamic_enhanced 1 run、hybrid_dynamic_enhanced 2 run、new_static_tool（CodeQL）1 run |
| 最终汇总 | **已生成**：`benchmark/results/EXTENSIONS.md` + `extension_summary.json`；16 个 canonical run 校验通过，16 项父指标与 37 项设计算术重算 0 不一致 |
| 主 leaderboard / 父 schema / `PROTOCOL.md` | **父表未改**；LEADERBOARD 只增加指向 `EXTENSIONS.md` 的链接 |

三个不能违反的规则：

1. **复用父 task，不新增 task 枚举。** 八个设计是父任务的 design variant：position/open-choice → `pair_detection`；evidence verification / evidence retraction → `detection`；fault-injected dynamic / new static tool / enhanced dynamic / hybrid enhanced dynamic → `leak_detection`。设计元数据放 `extension_manifest.json` sidecar，设计特有字段放 `prediction.extensions`。
2. **不跨设计、不跨层池化。** position-debiased、open-choice、forced-choice、evidence verification、evidence retraction、fault-injected dynamic、new static tool、enhanced dynamic 各有自己的主终点和分母；不能合成一个“总分”。
3. **失败不是负例。** `status != "ok"` 的 `y_pred` 必须为 `null`；动态 clean 无覆盖率 = `inconclusive`，不是 TN；`not_applicable` 不进分母；不把 `compile_error` 写成 `y_pred=0`。

---

## 1. 与父协议的关系

### 1.1 继承

扩展层完全继承 `benchmark/PROTOCOL.md` 与 `benchmark/tools/bench_common.py` 的以下定义：

- 状态词表（`ok`、`schema_invalid`、`api_error`、`timeout`、`tool_error`、`compile_error`、`harness_error`、`crash`、`unsupported`、`not_applicable`、`inconclusive`、`skipped_budget`、`not_run`）；
- valid-only / strict / common-valid 三种视图；
- P/R/F1/macro-F1/MCC/BA/coverage/strict accuracy；
- Wilson 比例区间、cluster percentile bootstrap、exact McNemar、Holm；
- 成本向量（USD / wall / CPU / RSS / token / latency），本地工具 `usd=null` 不是 0；
- 失败、缺失、排除账本和“不能声称”的边界。

扩展层只增加**任务结构**和**专用端点**，不改变父字段语义。

### 1.2 设计变体，不是新 task

| design | 父 task | 层级 | 单元 | cluster | 状态 |
| --- | --- | --- | --- | --- | --- |
| `position_debiased_pair` | `pair_detection` | A / secvuleval | pair side | `pair_id` | `result_imported`（forced fwd/rev，2 模型） |
| `open_choice_pair` | `pair_detection` | A / secvuleval | pair side | `pair_id` | `result_imported`（open fwd/rev，2 模型） |
| `evidence_verification` | `detection` | A 或 B | claim | source project / case family | `design_ready_no_results` |
| `evidence_retraction` | `detection` | A / secvuleval | function | project | `result_imported_exploratory`（四臂） |
| `fault_injected_dynamic` | `leak_detection` | B / juliet_cwe401 | fault variant | base case family | `design_ready_no_results` |
| `new_static_tool` | `leak_detection` | B / juliet_cwe401 | case variant | case family | `result_imported`（CodeQL test 140） |
| `enhanced_dynamic` | `leak_detection` | B / juliet_cwe401 | case variant | case family | `result_imported` |
| `hybrid_enhanced_dynamic` | `leak_detection` | B / juliet_cwe401 | case variant | case family | `result_imported` |

`extension_blocks.schema.json` 为每个 design 定义必需的 `extensions` 块；父 `prediction.schema.json` 仍负责整条记录。

### 1.3 不做什么

- 不修改 `benchmark/schemas/*.json` 的父契约；
- 不修改 `benchmark/PROTOCOL.md` 的语义；
- 不修改 `benchmark/results/LEADERBOARD.md` / `final_summary.json`；
- 不把新设计并入 Tier A/B 的现有主表；
- 不把八个 design 互相池化；
- 不调用模型/网络/新分析器；不生成“预期结果”；真实 run 由 producer 目录产生，本目录只读导入；
- 不用 `git`/`gh`；发布由主流程统一执行。

---

## 2. 目录

```text
benchmark/extensions/
├── README.md                 # 本文件
├── VERSION                   # 0.2.0
├── registry/
│   ├── designs.json          # 8 个 design 的机器可读 registry
│   ├── static_tools.json     # 新静态工具规则→CWE-401 映射
│   └── fault_types.json      # fault-injection 分类与允许的 expected outcome
├── schemas/
│   ├── README.md             # schema 说明
│   ├── extension_manifest.schema.json
│   ├── extension_blocks.schema.json
│   ├── extension_metrics.schema.json
│   ├── producer_raw.schema.json
│   ├── claim_manifest.schema.json
│   ├── fault_manifest.schema.json
│   └── static_tool_registry.schema.json
├── configs/                  # 本轮真实导入配置（无凭证）
├── tools/
│   ├── ext_common.py         # registry / ID / 诊断归一化 / 统计原语
│   ├── ext_import.py         # 八类 raw → canonical run
│   ├── ext_validate.py       # 父结构 + 设计不变量 + registry 检查
│   ├── ext_metrics.py        # 设计专用指标
│   └── ext_selftest.py       # 合成 fixture 端到端自检
└── runs/                     # 已导入的真实 canonical runs（见 §9）
    ├── pair_debias/{deepseek,mimo}/{forced,open_fwd,open_rev}/
    ├── evidence_verify/{deepseek_self,deepseek_by_mimo,mimo_self,mimo_by_deepseek}/
    ├── dynamic_enhanced/test140_enhanced_v3/
    ├── hybrid_dynamic_enhanced/{deepseek,mimo}/
    └── new_static_tool/codeql_cwe401_test140_20261114/
```

`runs/` 只包含已通过 `ext_validate.py` 的 canonical 导入，不是新实验；原始 producer 目录仍是只读来源。

---

## 3. 八个 design

### 3.1 Position-debiased pair

**问题。** 现有 pair-joint 强制二选一有明显位置偏差（DeepSeek A 92.22% vs B 61.11%），而且长度启发式单独可达 74.44%。单次随机位置的 joint DA 无法区分“跨版本语义判别”和“选 A/选长”。

**设计。** 每一对构造两次 presentation：

- **全局顺序**：`order_ab`：vulnerable 在 slot A，fixed 在 slot B；`order_ba`：相反。用于纯 AB/BA 交换实验。
- **逐对交换**：`fwd` / `rev`：每对使用自己的 `position_map`（来自 pair_joint/pair_debias），`rev` 必须逐对精确交换 `fwd` 的 A/B 槽位。用于 `pair_debias` 的 forced_fwd/forced_rev。

两次是**两个独立 canonical run**，共享 `pairing_id`、同一 pair_id 集合、同一模型/配置、同一 prompt 语义（只交换顺序）。每对共 2 次请求。不能把两次 presentation 当作 2 个独立 pair。

**输入。** pair 视图；不传 `fixed_func_idx`、diff、CWE、commit、路径、`bad/good` 标识。允许行号，但两次 presentation 必须使用同一行号规则。`input.view="pair"`，`input.sanitized=true`，`input.prompt_sha256` 记录请求哈希。

**raw → canonical。**

| raw 字段 | canonical |
| --- | --- |
| `pair_id` | `group_id`；`cluster_id`；`unit_id=secvul:pair:<pair_id>:<side>` |
| `presentation_order`（`AB`/`BA`/`fwd`/`rev`） | `extensions.presentation_order`；`run_role` 同名 |
| `position_map`（A/B → vulnerable/fixed） | `extensions.position_map`；全局序必须是 AB/BA 固定映射；fwd/rev 允许逐对不同，但 rev 必须是 fwd 的精确交换 |
| `choice`（`A`/`B`） | `extensions.choice` / `selected_slot`；`selected_side=position_map[choice]` |
| 选中侧 | 该 side `y_pred=1`，另一侧 `y_pred=0`；非 ok 两侧 `y_pred=null` |
| `confidence` / `rationale` / usage / cost | 两侧复制；成本按两次请求计 |
| 未出现的 pair | 两侧 `status="not_run"`，不补 0 |

两个 order run 的 `run_manifest.json` 都是父 `benchmark-run-v1`；`extension_manifest.json` 记录 `run_role=order_ab|order_ba`、`presentation_order`、`pairing_id`、`sibling_run_id`。

**统计口径。** 设 `P` 为两个 order 都有效的 pair 集合；对 `p∈P`：

```text
correct_ab(p) = 1  若 AB 选择 vulnerable，否则 0
correct_ba(p) = 1  若 BA 选择 vulnerable，否则 0
consistent(p) = 1  若两次选择同一 semantic side
both_correct(p) = correct_ab(p) ∧ correct_ba(p)

position_avg_pair_da = mean_p [ (correct_ab(p) + correct_ba(p)) / 2 ]   # 主终点
order_consensus_pair_da = mean_p both_correct(p)                        # 严格稳定性
order_consistency = mean_p consistent(p)
order_flip_rate = 1 - order_consistency
slot_accuracy_A = mean over both presentations with vulnerable in slot A
slot_accuracy_B = mean over both presentations with vulnerable in slot B
position_bias_index = slot_accuracy_A - slot_accuracy_B
```

恒等式：`position_avg_pair_da - order_consensus_pair_da = 0.5 × order_flip_rate`。这不是“提升”，只是把 flip 惩罚显式化。

**主/次终点。** 主终点 `position_avg_pair_da`（随机呈现顺序下的无偏估计）；必须同时报告 `order_consensus_pair_da`、`order_consistency`、`position_bias_index`、`flip_to_correct`/`flip_to_wrong`、`length_audit`。bootstrap 以 `pair_id` 为重采样单位，同时使用两次 presentation；比例用 Wilson。

**长度审计。** 对每个 pair 记录两侧字符数：

```text
length_only_da = P(较长侧 == vulnerable)（ties 单独计数）
choose_longer_rate = P(选中侧 == 较长侧)
da_when_choose_longer / da_when_choose_shorter
```

order swap **不能**消除长度差；如果 `length_audit.available=false`，不能声称“纯位置效应”。如果长度差与标签强相关，必须把 `length_only_da` 作为对照，并报告 position-debiased 指标相对它的差值。

**不能声称。**

- 不能把两次 presentation 当独立样本做 McNemar/ bootstrap；
- 不能把 `position_avg_pair_da` 与 forced-choice pair-joint DA 直接相减；
- 不能在无长度审计时声称“去除了长度混淆”；
- 不能把 `order_consensus_pair_da` 当“更高”的指标；它更严格，数值必然 ≤ `position_avg_pair_da`。

---

### 3.2 Open-choice pair

**问题。** 强制二选一迫使模型在 A/B 中选一个，即使两侧都像漏洞或都不像。Open-choice 允许 `A`/`B`/`both`/`neither`，把“无法判别/双报/双清”变成显式答案。

**设计。** 每对一个请求，四选一。一个响应落成两条 canonical side 记录：

| open_choice | vulnerable side `y_pred` | fixed side `y_pred` |
| --- | ---: | ---: |
| `A` | 1 | 0 |
| `B` | 0 | 1 |
| `both` | 1 | 1 |
| `neither` | 0 | 0 |

`both`/`neither` 是**实质答案**，不是 invalid；它们在 pair DA 中算错，但必须单独报告比例。

**已导入的真实条件。** `pair_debias` 的 `open_fwd` / `open_rev` 各是一个独立 canonical open-choice run（同一 180 对、逐对 position_map、正/反序）；本目录分别导入为 `runs/pair_debias/<model>/open_fwd|open_rev`，暂不把两个序合并成一个“去偏”指标。`open_fwd` 与 `open_rev` 不是独立 pair；跨序比较必须按 pair_id 配对，且只能描述顺序效应。

**输入。** 与 position 相同 pair 视图；prompt 必须明确允许四个答案；不能只给 A/B 两个选项再要求 `both/neither`。

**raw → canonical。**

| raw | canonical |
| --- | --- |
| `pair_id` | `group_id` / `cluster_id` / `unit_id` |
| `open_choice` | `extensions.open_choice`；`selected_slots` 由 choice 派生 |
| `position_map` | `extensions.position_map` |
| `status="ok"` + 合法 choice | 两侧 `y_pred` 按上表；否则两侧 `y_pred=null` |
| 缺失 pair | 两侧 `status="not_run"` |

**统计口径。**

```text
pair_da = correct / valid_pairs                  # 主终点；both/neither 算错
pair_da_all = correct / all_planned_pairs        # 缺失/无效也算错
decisive_rate = (n_A + n_B) / valid_pairs
pair_da_decisive = correct / (n_A + n_B)         # 条件 DA
both_rate = n_both / valid_pairs
neither_rate = n_neither / valid_pairs
slot_accuracy_A/B = 在 decisive pairs 中，vulnerable 在 A/B 时的正确率
position_bias_index = slot_accuracy_A - slot_accuracy_B
```

bootstrap 以 `pair_id` 为单位；四类分布用计数与比例，不用 macro-F1（四类不是标签类别）。

**与 forced-choice 的关系。** 两者是不同任务：forced-choice 没有 both/neither。可以在同一 pair 集合上做描述性对比，但必须写“task changed”，不能把 DA 差值当成“开放选项的收益”。`both`/`neither` 的比例是任务行为，不是自然 prevalence。

**不能声称。**

- 不能把 open-choice 的 `pair_da` 与 forced-choice DA 放在同一排名；
- 不能把 `both`/`neither` 当 schema-invalid 删除；
- 不能只报 `pair_da` 而不报 `decisive_rate` 与 `pair_da_decisive`；一个“全选 both”的模型会有很低的 DA，但这不是同一能力维度。

---

### 3.3 Evidence verification

**问题。** Evidence prompt 让模型引用证据行，但引用可能不存在、落在 fixed 侧、或机制不成立。需要一个**独立 verifier**判断 claim 是否被源码支持，而不是再让生成器自评。

**任务。** 输入 sanitized source + 一条 claim（引用行和/或机制），输出：

- `supported`：claim 被源码支持；
- `unsupported`：claim 被源码反驳/引用错位/机制不成立；
- `insufficient`：无法判定（弃权）。

> 本 design 是 claim 级 support/reject，**目前没有真实 run**。真实 `evidence_verify` 实验是对第一遍正例做“撤销/保留”的事后验证，编码为独立的 `evidence_retraction` design（§3.6），不能把两者混为一谈。

**Claim 构造与冻结。** 必须在使用前冻结 `claim_manifest.json`：

- positive（`genuine`）：来自真实 evidence run 的 claim，且经人工/规则核对；
- negative（`counterfactual` / `perturbed`）：同一 claim 的受控扰动（换行、换侧、换机制），保持长度/格式尽量匹配；
- `construction_rule` 必须写清如何生成正负例、如何避免 verifier 看到生成器标签或路径；
- claim 是独立单元；一行/一个 token 不是独立样本；
- 不能把测试集 claim 用于阈值/提示拟合。

**输入。** `input.view="other"`（source + claim），`input.context_mode="tool_evidence"`，`input.sanitized=true`，`input.evidence_sha256=claim_text_sha256`，`input.source_sha256` 记录源码哈希。prompt 不得包含 `gold_verdict`、数据集标签、路径、`bad/good`、claim_type（除非 claim_type 是任务定义的一部分且不泄漏答案）。

**raw → canonical。**

| raw | canonical |
| --- | --- |
| `claim_id` | `unit_id=<tier>:claim:<claim_id>`；`group_id=null`；`side=null` |
| `verdict=supported` | `status=ok`，`y_pred=1` |
| `verdict=unsupported` | `status=ok`，`y_pred=0` |
| `verdict=insufficient` | `status=inconclusive`，`y_pred=null`，`extensions.verification.abstained=true` |
| `gold_verdict=supported` | `label.y_true=1`；`label_source="manual"` |
| `gold_verdict=unsupported` | `label.y_true=0`；`label_source="manual"` |
| 缺失 claim | `status="not_run"`，不补 0 |

`cluster_id` 来自 claim manifest 的 source project / case family；不能按 claim_id 聚类（同一 source 的多条 claim 相关）。

**统计口径。**

```text
valid-only: P/R/F1/macro-F1/MCC/BA（只含 supported/unsupported 的 decisive 预测）
coverage = decisive / all claims
abstention_rate = insufficient / all claims
false_support_rate = P(pred=supported | gold=unsupported)   # 在 valid 上
false_reject_rate  = P(pred=unsupported | gold=supported)   # 在 valid 上
strict_accuracy = 所有 claim 中判对 / all claims；insufficient 算错
```

必须同时给 `gold supported × pred {supported, unsupported, insufficient}` 和 `gold unsupported × ...` 的 2×3 混淆；不能只报一个 macro-F1。`claim_type` 分层（genuine/counterfactual/perturbed）必须报告。

**主终点。** `macro_f1`（valid-only，claim 级二分类）；同时给 `balanced_accuracy`、`decisive_coverage`、`abstention_rate`、`false_support_rate`、`false_reject_rate`、`strict_accuracy`。bootstrap 以 source cluster 为单位；比例用 Wilson。

**不能声称。**

- 不能把 claim 当独立样本做 token 级显著性；
- 不能把“拒绝所有 claim”的高 specificity 当作 verifier 能力强；必须看 genuine acceptance；
- 不能把 `insufficient` 当负例或删掉；它在 strict 中算错，在 valid-only 中弃权；
- 如果 claim 构造与表面形式（长度、模板、措辞）相关，不能声称“语义验证能力”。

---

### 3.4 Fault-injected dynamic

**问题。** 动态工具在“设计好的”Juliet 用例上可能看起来稳定，但对 harness/路径/分配器边界敏感。Fault injection 通过预注册的受控扰动测试动态 oracle 的**鲁棒性**：注入泄漏、掩盖泄漏、制造非泄漏缺陷、破坏 harness/覆盖率。

> 本 design 是 **fault-variant 套件**，目前没有冻结 fault manifest 的真实 run。`dynamic_enhanced` 是另一种东西：在 canonical 140 单元上跑三种模式（default / realloc-failure / no-globals），编码为独立的 `enhanced_dynamic` design（§3.7）；不能把它的 140 单元当 fault 变体池化。

**Fault taxonomy。** `registry/fault_types.json` 预注册 10 类：

| fault_type | 预期效果 | 用途 |
| --- | --- | --- |
| `inject_leak_good_path` | leak | 在 good 路径注入泄漏，测试灵敏度 |
| `mask_leak_early_exit` | clean | 提前退出使泄漏路径不再执行，测试漏报/覆盖不足 |
| `conditional_free_one_path` | leak | 只在一条路径 free，测试路径敏感性 |
| `realloc_without_free` | leak | realloc/所有权转移后不 free |
| `allocation_size_zero` | leak/clean/inconclusive | 分配器边界；必须 preflight，不能假定 |
| `harness_early_exit` | inconclusive | 目标函数未执行；clean 是错误结论 |
| `sanitizer_suppression` | inconclusive | 关闭/抑制泄漏检测；clean 是工具完整性失败 |
| `timeout_injection` | inconclusive | 超时不能被写成 clean |
| `double_free_injection` | clean/inconclusive | 非泄漏缺陷；不应算 leak |
| `still_reachable_global` | clean | definite/indirect 边界；不应算 leak |

`expected_outcome` 必须写在冻结的 `fault_manifest.json`，不能看工具输出后补；`injection_sha256`/`source_sha256` 记录每个变体。

**输入。** 动态方法只允许预注册 harness/输入/flags；fault manifest 记录 injection diff、seed、coverage 阈值、oracle 要求。静态/动态工具不得读取 `expected_outcome` 作为特征；fault manifest 只用于评估映射。

**raw → canonical。**

| raw | canonical |
| --- | --- |
| `fault_id` + `base_unit_id` | `unit_id=<base_unit_id>:fault:<fault_id>`；`group_id=<case_id>`；`side=bad/good` |
| `expected_outcome=leak` | `label.y_true=1`；`label_source="manual"` |
| `expected_outcome=clean` | `label.y_true=0` |
| `expected_outcome=inconclusive` | `status="not_applicable"`，`y_pred=null`；不进标签分母 |
| `observed_outcome=leak` | `status=ok`，`y_pred=1`（即使覆盖率低也保留正例） |
| `observed_outcome=clean` + 覆盖达标 | `status=ok`，`y_pred=0` |
| `observed_outcome=clean` + 覆盖不足/未知 | `status="inconclusive"`，`y_pred=null` |
| `timeout`/`crash`/`error` | `status=timeout/crash/tool_error`，`y_pred=null` |
| oracle mismatch | 保留 `oracle.mismatch=true`；主估计排除，计数报告 |

**统计口径。** 主分析只含 `expected_outcome ∈ {leak, clean}`，并排除 `oracle.mismatch=true`：

```text
fault_sensitivity = P(observed leak | expected leak, valid)
fault_specificity = P(observed clean | expected clean, valid)
fault_balanced_accuracy = (sensitivity + specificity) / 2     # 主终点
fault_macro_f1 = 二类 macro-F1（valid-only）
masking_rate = 1 - sensitivity
false_alarm_rate = 1 - specificity
strict_accuracy = 判对 / 所有 expected leak+clean；inconclusive/error 算错
inconclusive_rate = inconclusive / expected leak+clean
flip_vs_baseline = same / leak_to_clean / clean_to_leak / not_comparable
```

必须给 per-fault-type 表和覆盖率分层（`ge_0.90`、`0.50_0.90`、`lt_0.50`、`unknown`）的 sensitivity/specificity/BA。bootstrap 以 `base_case_family` 为单位；同一 base case 的多个 fault 变异相关，不能按 variant 独立重采样。

**不能声称。**

- fault 变体是构造的，不是自然 prevalence；`fault_balanced_accuracy` 不是 CWE-401 检测质量；
- 不能把 fault 变体与 canonical 140 单元动态 run 池化；
- 不能把低覆盖 clean 当 TN；不能把 timeout/suppression 后的 clean 当“无泄漏”；
- `expected_outcome=inconclusive` 的变体不进 sens/spec 分母，但必须报告其 observed 结果和原因；
- 不能把 oracle mismatch 静默删除；必须给排除账本。

---

### 3.5 New static tool

**问题。** 新增静态分析器（clang-tidy、GCC `-fanalyzer`、Infer、CodeQL、pinned Cppcheck 等）的原始 warning 规则/severity/scope 不同。需要版本化规则映射，保证同一 unit 的 `y_pred` 可审计、可复算。

**工具 registry。** `registry/static_tools.json` 固定：

```json
{
  "tool_id": "gcc-analyzer",
  "name": "GCC -fanalyzer",
  "version_probe": "gcc -dumpfullversion -dumpversion",
  "command_template": "gcc ... -fanalyzer -Wanalyzer-malloc-leak ...",
  "severity_policy": {"high": ["error", "warning"], ...},
  "rules": {
    "-Wanalyzer-malloc-leak": {"cwe": "CWE-401", "counts_for_cwe401": true},
    "-Wanalyzer-double-free": {"cwe": "CWE-415", "counts_for_cwe401": false}
  },
  "allow_cwe_fallback": true
}
```

当前 registry 含 6 个工具：`clang-sa`、`clang-tidy`、`gcc-analyzer`、`cppcheck`、`infer`、`codeql`。`codeql` 已安装并完成正式 run（CodeQL 2.27.4 / `cpp-queries` 1.10.0），registry 状态为 `run_recorded`，规则固定为 `cpp/memory-never-freed` 与 `cpp/memory-may-not-be-freed`；`infer` 仍未安装，标 `documented_not_installed`，没有真实 run 前不得报告其数字。

**输入。** 只允许 compile-ready Juliet 单元（Tier B core set）。Tier A 的不完整 CVE 函数不适用；本设计**只支持 Tier B**。静态工具不得读取文件名/路径/`bad/good` 作为特征；scope 和命令必须记录。

**raw → canonical。**

| raw | canonical |
| --- | --- |
| `sample_id`（upstream `...__bad`） | 经 `juliet/subset_units.jsonl` 映射到 `unit_id=juliet:<group>:<bad|good>` |
| `status` | 父状态词表；`unavailable → not_applicable`；`compile_error`/`timeout`/`tool_error` 保留 |
| `diagnostics[].checker/rule` | `rule_id`；经 registry 映射到 `mapped_cwe` |
| `diagnostics[].severity` | `severity`；按工具 `severity_policy` 归为 high/medium/low |
| `diagnostics[].file/line/column` | `in_scope`：`target_file` 或 `target_function`（需 line range） |
| `diagnostics[].cwe` | 仅在 registry 未命中且 `allow_cwe_fallback=true` 时作为 fallback；**不从自由文本/标识符解析 CWE** |
| `in_target_file` / `in_target_region` / `counts_as_finding` | 与计算值合并；`false` 不得计数 |
| `prediction.is_vulnerable` | **不直接复制**；由 `mapped_warning_count > 0` 重算 |
| `runtime.duration_seconds` | `cost.wall_s`，`cost_basis="local_compute"`，`usd=null` |

`extensions.static_normalization` 保存：tool_id/version、registry hash/version、scope_kind、target_files、line_range、完整 diagnostics、raw/dedup/mapped/unmapped/out_of_scope/suppressed 计数、severity_policy、main/sensitivity threshold、command hash。

**计数与预测。**

```text
raw_warning_count      = 原始 diagnostics 条数
dedup_warning_count    = 按 (file basename, line, column, rule_id) 去重
mapped_warning_count   = 去重后，rule 映射 CWE-401 ∧ in_scope ∧ 非 suppressed
unmapped_warning_count = 去重后，rule 未映射 CWE-401
out_of_scope_count     = 映射 CWE-401 但不在 target scope
suppressed_count       = suppression 命中
y_pred = 1  iff mapped_warning_count > 0（status=ok）
```

**统计口径。**

- 主分析：any-mapped-in-scope（预注册阈值）；`macro_f1` + `mcc` + `strict_accuracy` + `coverage`；
- 敏感性：high-only（工具特定 severity policy），必须报告 `delta_macro_f1_vs_default` 和 McNemar；
- 诊断审计：rule 分布、severity 分布、raw/dedup/mapped/unmapped/out-of-scope/suppressed、warnings per unit/KLOC；
- 与既有静态基线（Clang SA/Cppcheck）在 common-valid 上做 agreement（Cohen's κ）和给定 `--baseline-run` 的差异；两个静态工具不是独立 ground truth；
- bootstrap 以 `case_family` 为单位；`compile_error` 算 strict 错误，valid-only 排除。

**不能声称。**

- 不能把 Tier A 静态可行性写成 F1；
- 不能把 `compile_error` 当 `y_pred=0`；
- 不能跨工具比较 severity（severity 是工具特定的）；
- 不能把 clang-tidy 与 clang-sa 的一致性当独立验证（同一分析引擎）；
- 不能在没有 dev 集冻结规则映射时直接跑 test；新规则/新工具必须先 bump registry version 并在 dev 上冻结。

---

### 3.6 Evidence retraction（真实 `evidence_verify` 四臂）

**问题。** 第一遍 evidence prompt 提高召回，但也产生假阳性。对每个“有漏洞”的正例再发一次独立上下文调用，要求验证器尝试**反驳**该 claim，并允许 `sustain` / `retract`；负例不动。

**设计。** 四个臂，同一 160 条测试函数：

| 臂 | 第一遍正例来源 | 验证器 | 独立性 |
| --- | --- | --- | --- |
| `deepseek_self` | DeepSeek | DeepSeek | 同模型、新上下文 |
| `deepseek_by_mimo` | DeepSeek | MiMo | 跨模型 |
| `mimo_self` | MiMo | MiMo | 同模型、新上下文 |
| `mimo_by_deepseek` | MiMo | DeepSeek | 跨模型 |

验证器只看到带行号源码 + 第一遍的 evidence_lines/mechanism；不看标签、项目、路径、commit、第一遍 confidence。输出 `sustain`/`retract`；invalid/缺失按 **fail-closed** 撤销。

**raw → canonical。** 第一遍 160 条 + 验证器正例结果合并成 160 条 `detection` 记录：

- 第一遍 negative → post `y_pred=0`，`verifier_verdict="not_requested"`；
- 第一遍 positive + verifier `sustain` → post `y_pred=1`；
- 第一遍 positive + verifier `retract` → post `y_pred=0`，`retracted=true`；
- 第一遍 positive + verifier invalid/missing → post `y_pred=0`，`retracted=false`，`fail_closed=true`；
- 第一遍 invalid → `status=schema_invalid`，post `y_pred=null`；strict 算错，valid-only 排除。

`extensions.retraction` 保存 first_pass_y_pred/status、verifier_status/verdict、retracted、fail_closed、analysis_status、claim_sha256、rebuttal_type 与两段成本。

**统计口径。** 主终点是 **post macro-F1**（valid-only）；必须同时报告 pre macro-F1、delta、MCC、strict accuracy、retraction precision、TP loss rate、FP correction rate、verifier invalid/fail-closed 计数。bootstrap 以 `project` 为单位；pre/post 配对 McNemar 是次要证据。

**真实结果（canonical 重算，匹配 producer 报告）：**

| 臂 | post TP/FP/TN/FN | post macro-F1 | pre macro-F1 | Δmacro-F1 | retracted (TP/FP) | 撤销精确率 | TP 损失率 | FP 纠正率 | invalid |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| deepseek_self | 6/0/32/121 | 0.2181 | 0.4223 | -0.2043 | 54 (43/11) | 20.37% | 87.76% | 100% | 0 |
| deepseek_by_mimo | 28/4/28/99 | 0.3522 | 0.4223 | -0.0701 | 26 (20/6) | 23.08% | 40.82% | 54.55% | 2 |
| mimo_self | 28/8/23/99 | 0.3221 | 0.4067 | -0.0846 | 21 (18/3) | 14.29% | 38.30% | 27.27% | 1 |
| mimo_by_deepseek | 7/0/31/120 | 0.2226 | 0.4067 | -0.1842 | 51 (40/11) | 21.57% | 85.11% | 100% | 0 |

**不能声称。**

- 这是 **post-hoc、test seen** 的探索性分析；160 条测试函数已用于第一遍 evidence run，不是独立确认。
- 四个臂相关（同一 160 单元），不能当独立样本或池化。
- fail-closed 会把验证器 API 失败变成“撤销”，必须同时看 invalid/fail-closed 计数；不能把撤销精确率单独当验证能力。
- 只处理正例；负例未变，不能声称 verifier 能发现负例中的假阴性。

---

### 3.7 Enhanced dynamic（三模式动态，`dynamic_enhanced`）

**问题。** 旧 ASan/LSan 在 test 140 上有 12 个 bad 不可观测：7 个 `malloc_realloc_*`（只有 realloc 失败才泄漏）和 5 个 `_68`（全局根使块仍 reachable）。`dynamic_enhanced` 用三种模式补证据：

- `default`：复现旧 ASan 根集；
- `realloc_fail`：链接期 `--wrap=realloc`，让第一次非 NULL realloc 真实失败；
- `nogobal`：`LSAN_OPTIONS=...:use_globals=0`，去掉全局根后看块是否不可达。

每个单元还做分配栈归因，排除 glibc/libstdc++ 噪声；只有分配点属于本单元源码的块才算泄漏。

**raw → canonical。** `results_units.jsonl` 140 行 → 140 条 `leak_detection` 记录：

- `decision=leak` → `status=ok`，`y_pred=1`；
- `decision=clean` → `status=inconclusive`，`y_pred=null`，`extensions.dynamic_enhanced.operational_y_pred=false`；
- 编译/运行失败 → 对应非 ok 状态，不写 0；
- 每条记录保存 modes/evidence_modes/primary_evidence/unobservable_in_default/conditionally_observable/per_mode/raw/attributed leak counts。

**为什么 clean 不是 TN。** 该 run 没有行/分支覆盖率 instrumentation；protocol 规定动态 clean 无覆盖率 = `inconclusive`，不是 TN。canonical 主视图因此是：

| 视图 | valid | coverage | recall | specificity | macro-F1 | strict |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| protocol（clean=inconclusive） | 70 | 0.500 | 1.000 | 未定义 | 未定义 | 0.500 |
| operational（source clean=0） | 140 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

operational 视图只是 producer 的 70/70 口径，**必须标 coverage-unverified，不能当 protocol-valid TN**。canonical `counts` 另报：12 个旧不可观测 bad 全部由新模式给出证据（7 realloc + 5 nogobal），70 good 的原始 nogobal 噪声经归因后 0。

**不能声称。**

- 不能把 operational 70/70 写成“protocol 动态检测 100%”；
- 不能把本 run 与 canonical 140 动态 run、fault_injected_dynamic 或其他动态方法池化；
- 不能外推到 dev 60、其他 CWE、其他编译器/分配器；
- clean 仍不是“无泄漏证明”；只是三模式执行路径上未观察到归因泄漏。

---

### 3.8 Hybrid enhanced-dynamic（LLM + 三模式动态证据）

**问题。** 把 `dynamic_enhanced` 的三模式证据（default / realloc_fail / nogobal）去标签后交给 LLM，是否比 v2 direct / 旧 dynamic / combined 更好。

**设计。** 140 个冻结 test 单元 × 2 模型（DeepSeek、MiMo）。输入是 sanitized code + 证据块；证据只含模式是否适用、归因字节/记录数、注入调用序号、最终 outcome；不含路径、文件名、函数名、unit id、CWE、bad/good、vulnerable/memory_leak。证据块过 forbidden-token 扫描；prompt SHA 与 v2 direct 对比预检。

**raw → canonical。** `enhanced_dynamic_results.jsonl` 280 行（2 模型 × 140）→ 每个模型各 140 条 `leak_detection` canonical 记录：

- `y_pred=1`/`0` 来自 `parsed.label` / `y_pred`；
- `status` 来自结果状态；schema error → `schema_invalid`；
- `label.y_true` 来自 unit map；`cluster_id=family`；`group_id/side` 来自 unit_id；
- `extensions.hybrid_dynamic_enhanced` 保存 evidence_outcome/primary_mode/old_dynamic_outcome/tool_verdict/prompt/evidence hash；
- `input.context_mode="dynamic_trace"`，`sanitized=true`。

**真实结果（canonical 重算）：**

| 模型 | TP/FP/TN/FN | macro-F1 | 与 140/140 工具的一致 | over-call / under-call |
| --- | --- | ---: | ---: | --- |
| DeepSeek | 70/3/67/0 | 0.9786 | 137/140 | 3 / 0 |
| MiMo | 70/4/66/0 | 0.9714 | 136/140 | 4 / 0 |

producer 报告：DeepSeek 相对 v2 direct +2/−0（McNemar p=0.5），MiMo 0/0；Holm 后均不显著；工具本身 140/140，且 12 个旧不可观测 bad 在 direct 下已 12/12，因此新证据没有提升空间；模型理由复述归因字节数的比例上升，但 over-call 仍存在，不能声称语义推理提升。

**不能声称。**

- 工具 140/140 使“与工具一致率”等于准确率，不能用来证明证据被独立理解；
- v2 direct/combined 是冻结的旧运行，不是同日重跑；比较是描述性的；
- 单模型单次运行；不能外推到其他 CWE / 真实项目；
- 不能把本 run 与 `dynamic_enhanced` 工具指标或 canonical 140 动态 run 池化。

---

## 4. Canonical 记录约定

### 4.1 单元 ID / group / side / cluster

| design | `unit_id` | `group_id` | `side` | `cluster_id` |
| --- | --- | --- | --- | --- |
| position | `secvul:pair:<pair_id>:<vulnerable|fixed>` | `pair_id` | `vulnerable`/`fixed` | `pair_id` |
| open-choice | 同上 | `pair_id` | `vulnerable`/`fixed` | `pair_id` |
| evidence | `<A|B>:claim:<claim_id>` | `null` | `null` | source project / case family |
| evidence retraction | `secvul:det:<idx>` | `null` | `null` | project |
| fault | `juliet:<case>:<bad|good>:fault:<fault_id>` | `<case>` | `bad`/`good` | base case family |
| static | `juliet:<case>:<bad|good>` | `<case>` | `bad`/`good` | case family |
| enhanced dynamic | `juliet:<case>:<bad|good>` | `<case>` | `bad`/`good` | case family |
| hybrid enhanced dynamic | `juliet:<case>:<bad|good>` | `<case>` | `bad`/`good` | case family |

`planned_units` 是冻结清单中的**记录数**；`recorded_units` 是实际落盘数；`valid` 是 `status="ok"` 且 `y_pred` 非空；`coverage=valid/recorded`。三者不能混用。

### 4.2 `run_manifest.json`

保持父 `benchmark-run-v1`，字段与 `benchmark/schemas/run_manifest.schema.json` 一致。关键点：

- `tasks` 只放父 task（`pair_detection` / `detection` / `leak_detection`）；
- `dataset.sha256` 必须与 records 的 `dataset.sha256` 一致；
- `dataset.unit_count` 是预测记录数（pair 为两侧之和）；
- `dataset.group_count` 是 pair/case/base 数；
- `execution.status` 在有 `not_run`/`skipped_budget` 时为 `partial`；
- `hashes` 至少含 `predictions_sha256` 与 `extension_manifest_sha256`；
- 不写 `latest/final/new` 之类的 run_id。

### 4.3 `extension_manifest.json` sidecar

字段：`schema_version=benchmark-extension-manifest-v1`、`extension_id`、`design`、`design_version`、`registry_version`、`parent_task`、`aggregation_unit`、`created_at`、`run_role`、`presentation_order`、`pairing_id`、`sibling_run_id`、`claim_manifest`/`fault_manifest`/`tool_registry`、`baseline_run`、`coverage_threshold`、`options`、`notes`。

父 `run_manifest` 的 `additionalProperties=false` 不允许新增顶层字段，所以设计元数据**必须**放在 sidecar，不能塞进父 manifest。

### 4.4 状态映射

| 情况 | canonical `status` | `y_pred` | valid-only | strict |
| --- | --- | --- | --- | --- |
| 合法预测 | `ok` | 0/1 | 计入 | 计入 |
| raw 输出无法解析 | `schema_invalid` | null | 排除 | 算错 |
| API/网络 | `api_error` | null | 排除 | 算错 |
| 静态/动态超时 | `timeout` | null | 排除 | 算错 |
| 工具内部错误 | `tool_error` | null | 排除 | 算错 |
| 编译失败 | `compile_error` | null | 排除 | 算错 |
| harness 失败 | `harness_error` | null | 排除 | 算错 |
| 崩溃 | `crash` | null | 排除 | 算错 |
| 方法不适用 | `not_applicable` | null | **不进分母** | 不计入 |
| 动态 clean 覆盖不足/oracle 不一致 | `inconclusive` | null | 排除 | 算错 |
| 预算跳过 | `skipped_budget` | null | 排除 | 算错 |
| 计划未执行 | `not_run` | null | 排除 | 算错 |

**evidence 的 `insufficient` 不是新状态**：映射到 `inconclusive`；父 schema 禁止 `status=ok` 且 `y_pred=null`。

**fault 的 `expected_outcome=inconclusive`**：映射到 `not_applicable`；`label.y_true` 仅为满足父 schema 填 0，`label_note` 和 `extensions.fault_injection.expected_outcome` 说明它不进入标签分母。真正进入 sens/spec 的是 expected leak/clean。

**evidence retraction**：第一遍 invalid → `schema_invalid`、post `y_pred=null`；正例 verifier invalid/missing → post `y_pred=0`、`status=ok`、`extensions.retraction.fail_closed=true`；`retracted` 只在 verifier 明确 `retract` 时为 true，fail-closed 不算 `retracted`。

**enhanced dynamic**：`decision=clean` → `status=inconclusive`、`y_pred=null`；operational 0 只放 `extensions.dynamic_enhanced.operational_y_pred`。`decision=leak` → `ok`/1；失败 → 非 ok/`null`。

### 4.5 安全与泄漏控制

- canonical 记录不保存 `Authorization`、API key、cookie、私钥；`ext_import.py` 只复制白名单字段，`ext_validate.py` 扫描 secret-like key 并报错；
- LLM 输入不含 `gold_verdict`、数据集标签、路径、`bad/good`、fault expected outcome；
- 静态诊断保留原始 rule/message，但不把路径写进 prompt；
- `input.sanitized` 对 LLM 必须为 true；静态工具为 false（工具看源码）；动态工具为 false；
- `input.prompt_sha256` / `input.source_sha256` / `input.evidence_sha256` 用于跨 run 可比性；
- 不把 raw request headers 复制到 canonical；不显示/保存 API key。

---

## 5. 生产者 raw 契约

`ext_import.py` 接受 JSONL、JSON 数组，或带 `records`/`results`/`predictions`/`claims`/`faults` 的对象。参考 schema 见 `schemas/producer_raw.schema.json`。字段名按优先级读取，常用别名：

| 概念 | 可用字段 |
| --- | --- |
| pair/claim/fault 标识 | `pair_id`/`group_id`/`id`、`claim_id`、`fault_id` |
| 选择 | `choice`、`selected_slot`、`parsed.vulnerable_version`、`open_choice`、`parsed.open_choice` |
| verdict | `verdict`、`parsed.verdict`、`parsed.label`、`decision` |
| 状态 | `status`、`result.status`、`response.status`；`validation.json_parse_ok/schema_exact/decision_valid` |
| 置信度 | `confidence`、`parsed.confidence` |
| prompt 哈希 | `prompt_sha256`、`request.body_sha256` |
| usage | `usage`、`response.usage`；`prompt_tokens`/`input_tokens`、`completion_tokens`/`output_tokens`、`prompt_tokens_details.cached_tokens`、`completion_tokens_details.reasoning_tokens`、`attempts[-1].latency_seconds` |
| cost | `cost.cost_usd`、`response.cost.cost_usd`、`cost_usd`；`cost.wall_s`/`response.wall_seconds` |
| static diagnostics | `diagnostics`、`findings`、`warnings`；`rule_id`/`rule`/`check`/`checker`/`warning` |

**状态别名。** `success/completed/valid → ok`；`invalid/parse_error → schema_invalid`；`unavailable → not_applicable`；`timed_out → timeout`；`compile_failed → compile_error`；`missing/pending → not_run`。无法识别的状态不会被猜成 `ok`。

**缺失单元。** 冻结清单中的 pair/claim/fault/unit 如果没有 raw 记录，导入器写 `status="not_run"`，保留 `planned_units` 与 `recorded_units` 的差异；不补 0、不删除。

**raw 文件哈希。** 每个 canonical record 的 `provenance.source_artifact` 是 raw 文件路径，`provenance.source_sha256` 是 raw 文件哈希，`provenance.record_index` 是 raw 行号（0-based）。canonical run 不重新推理。

**输出目录。** 单 run 设计写 `<out>/run_manifest.json` + `predictions.jsonl` + `extension_manifest.json` + `validation.json`。position 写 `<out>/order_ab/`、`<out>/order_ba/`、`<out>/pairing.json`。已存在输出默认拒绝；`--force` 会把旧目录移到 `<out parent>/.superseded/<name>.<timestamp>`，**不删除**。

---

## 6. 工具与命令（全部 WSL）

### 6.1 配置模板

`ext_import.py` 需要一个 JSON config。最小示例（position）：

```json
{
  "run_id": "pos_deepseek_v1",
  "tier": "A",
  "track": "secvuleval",
  "pair_split": "splits/test_pairs_180.json",
  "method": {
    "method_id": "llm.deepseek.position_debiased",
    "family": "llm",
    "name": "DeepSeek V4.1 Flash / position-debiased A-B",
    "strategy": "position_debiased",
    "model": {
      "model_id": "deepseek-v4.1-flash",
      "family": "deepseek",
      "provider": "opencode-go",
      "endpoint": "https://opencode.ai/zen/go/v1/chat/completions",
      "version": null,
      "decoding": {"temperature": 0.0, "max_tokens": 8192}
    }
  },
  "raw": "pair_position/runs/test_deepseek_ab_ba/results.jsonl",
  "out": "../runs/position/pos_deepseek_v1"
}
```

`method` 的必填：

- `family=llm`：`method.model.{model_id,family,provider}`；`name`、`method_id`；
- `family=static|dynamic`：`method.tool.{name,version}`；
- `config_sha256` 可省略，导入器会按 method 内容计算。

`dataset` 可省略：position/open 从 `pair_split` 推导；evidence/fault 从 claim/fault manifest 推导；static 从 `unit_map` 推导。若提供 `dataset.sha256`，必须与文件哈希一致。

### 6.2 导入

```bash
# position-debiased：一个 raw 文件可含 AB/BA，导入器拆成两个 order run
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design position_debiased_pair --config benchmark/extensions/configs/pair_forced_deepseek.json --jsonschema'

# open-choice
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design open_choice_pair --config benchmark/extensions/configs/pair_open_deepseek_fwd.json --jsonschema'

# evidence verification
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design evidence_verification --config configs/evidence.json --jsonschema'

# fault-injected dynamic
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design fault_injected_dynamic --config configs/fault.json --jsonschema'

# new static tool
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design new_static_tool --config configs/static_gcc.json --jsonschema'

# evidence retraction（真实 evidence_verify 四臂格式）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design evidence_retraction --config benchmark/extensions/configs/evidence_retraction_deepseek_self.json \
  --out benchmark/extensions/runs/evidence_verify/deepseek_self --jsonschema'

# enhanced dynamic（三模式结果）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design enhanced_dynamic --config benchmark/extensions/configs/dynamic_enhanced.json \
  --out benchmark/extensions/runs/dynamic_enhanced/test140_enhanced_v3 --jsonschema'

# hybrid enhanced dynamic（LLM + 三模式证据）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_import.py \
  --design hybrid_enhanced_dynamic --config benchmark/extensions/configs/hybrid_enhanced_dynamic_deepseek.json --jsonschema'
```

`--dry-run` 会 staging、校验、打印 summary，然后删除临时目录，不写最终输出。`--force` 只用于明确要归档旧输出；默认拒绝覆盖。`benchmark/extensions/configs/` 提供本轮 14 个真实导入配置（无凭证）；其中 evidence_verification/fault 的命令仍是格式占位，因为这两类尚无真实 run；static 配置 `codeql_static_extended.json` 对应真实 CodeQL run。

position 的 `config.orders` 形式（pair_debias forced fwd/rev）示例：

```json
{
  "pair_split": "splits/test_pairs_180.json",
  "pairing_id": "pairset-deepseek-forced-v1",
  "orders": {
    "fwd": {"raw": "pair_joint/runs/test_deepseek_180/results.jsonl",
            "position_map": "pair_joint/runs/test_deepseek_180/position_map.json",
            "run_id": "ext_pair_debias_deepseek_forced_fwd"},
    "rev": {"raw": "pair_debias/runs/test_deepseek_forced_rev/results.jsonl",
            "position_map": "pair_debias/runs/test_deepseek_forced_rev/position_map.json",
            "run_id": "ext_pair_debias_deepseek_forced_rev"}
  }
}
```

两个 order 的 `position_map` 必须逐对交换；`fwd`/`rev` 允许逐对不同，`AB`/`BA` 要求全局固定映射。

### 6.3 校验

```bash
# 单 run
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py \
  --run-dir benchmark/extensions/runs/static/static_gcc_v1 --jsonschema'

# position：base 目录（order_ab/order_ba 或 fwd/rev）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py \
  --run-dir benchmark/extensions/runs/pair_debias/deepseek/forced --jsonschema'

# 冻结清单 join（可重复校验）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py --run-dir <run> \
  --claim-manifest <claims.json> --fault-manifest <faults.json> \
  --unit-map juliet/subset_units.jsonl --jsonschema'

# registries
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py --check-registries'
```

校验器同时运行父 `bench_validate.validate_run`，所以 canonical run 也必须通过父结构。`--json-out <path>` 写报告；默认 stdout。已有报告默认拒绝覆盖，`--force` 才覆盖。

### 6.4 指标

```bash
# position：--run-dir 指向 base（含 order_ab/order_ba）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_metrics.py \
  --run-dir benchmark/extensions/runs/position/pos_v1 --bootstrap 10000'

# open / evidence / fault / static
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_metrics.py \
  --run-dir <run> --bootstrap 10000 --coverage-threshold 0.8'
```

输出：`metrics.json` + `metrics.md`。默认写到 run 目录（position 写到 base）；已有文件默认拒绝覆盖，`--force` 才覆盖。`--baseline-run` 只用于描述性比较（open-choice vs forced-choice、static vs 既有静态基线），不能把两个任务/工具当同一排名。

### 6.5 自检

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_selftest.py'
```

自检在临时目录中创建五类合成 fixture，走完整 CLI 链路，手算断言，不写 `benchmark/results`、不调用模型/网络。

---

## 7. Schema

| 文件 | 作用 |
| --- | --- |
| `extension_manifest.schema.json` | sidecar：design、run_role、pairing、claim/fault/tool registry、baseline |
| `extension_blocks.schema.json` | 每个 design 的 `prediction.extensions` 必需块；含 static diagnostic 子 schema |
| `extension_metrics.schema.json` | `ext_metrics.py` 的 `metrics.json` |
| `producer_raw.schema.json` | 生产者 raw JSONL 参考格式（`$defs` + design discriminator） |
| `claim_manifest.schema.json` | 冻结 evidence claim 清单 |
| `fault_manifest.schema.json` | 冻结 fault 变体清单 |
| `static_tool_registry.schema.json` | 静态工具规则→CWE-401 registry |

版本与兼容：

- 扩展 schema 版本：`benchmark-extension-manifest-v1`、`benchmark-extension-metrics-v1`、`benchmark-evidence-claims-v1`、`benchmark-fault-injection-v1`、`benchmark-static-diagnostic-v1`；
- 父 schema 版本不变：`benchmark-prediction-v1`、`benchmark-run-v1`、`benchmark-metrics-v1`；
- 破坏兼容的字段变更必须 bump `design_version`，新建 run，不得就地改旧 run；
- 父 `run_manifest` 不允许顶层扩展字段，所以设计元数据只放 sidecar；
- `--jsonschema` 需要 `jsonschema`（本机 WSL 4.19.2）；没有该包时只跑标准库不变量检查并给 warning，不静默假装通过。

---

## 8. 统计口径

### 8.1 三种视图

| 视图 | 定义 | 用途 |
| --- | --- | --- |
| valid-only | `status="ok"` 且 `y_pred` 非空 | 方法能力；必须同时给 `n_valid`、coverage、invalid |
| strict | 所有已落盘记录；非 ok 算错 | 部署视图；必须与 valid-only 并列 |
| common-valid | 两个被比较方法都有效的单元 | McNemar / paired bootstrap |

排名/部署用 strict + coverage；能力描述用 valid-only；显著性用 common-valid。三者不能混在一张“赢家”表里。

### 8.2 区间与检验

- 比例（precision/recall/specificity/accuracy/coverage/pair DA/decisive rate/false support/false reject/sensitivity/specificity）用 **Wilson 95%**；
- F1、macro-F1、MCC、BA、position_avg_pair_da、order_consensus_pair_da、fault_BA 用 **cluster percentile bootstrap 95%**，默认 10,000 次，seed 42；
- 重采样单位：position/open `pair_id`；evidence source project / case family；fault base case family；static case family；
- 同一重采样同时计算两个方法的差值；不能对两个独立 bootstrap 的区间做“重叠即不显著”判断；
- 配对二值正确性用 **exact two-sided McNemar**；McNemar 是次要证据，主推断用 cluster bootstrap 差值 CI；
- 多重比较在每个预注册 family 内 Holm（见 8.3）；不同 family 不合并。

### 8.3 比较族

| family | 包含 | 不能混入 |
| --- | --- | --- |
| `EXT-POSITION` | position-debiased 的 position_avg/consensus/slot/length 对比；模型间同配置对比 | forced-choice 旧 DA、open-choice |
| `EXT-OPEN-CHOICE` | open-choice 的 DA/decisive/conditional DA；与 forced-choice 的描述性对比单独标 | position-debiased 主表 |
| `EXT-EVIDENCE-VERIFY` | verifier vs 生成器/基线；claim_type 分层；evidence_retraction 的 pre/post 与撤销审计 | 检测任务 F1 |
| `EXT-FAULT` | fault sensitivity/specificity/BA vs no-fault baseline；per fault type | canonical 140 动态表 |
| `EXT-DYNAMIC-ENHANCED` | enhanced_dynamic 的 protocol vs operational 视图、mode evidence、resolved unobservable；hybrid enhanced-dynamic vs 冻结 direct/combined/tool | canonical 140 动态表、fault 变体 |
| `EXT-STATIC` | 新静态工具 vs Clang SA/Cppcheck；severity 敏感性 | Tier A 静态可行性 |

同一 family 内 Holm；raw p 和 adjusted p 都报告。交互/亚组标 `exploratory`。

### 8.4 最小 n 与不稳定性

- cluster 数 < 30 时，bootstrap 只作描述，必须报告 `cluster_count`，不能声称稳定；
- 单类别分层不能算 macro-F1/BA；改报正类 F1/recall 或 specificity，标 `single_class`；
- 单个 design 的 run 少于 2 次时，不能估计 run-to-run 方差；`temperature=0` 不保证服务端确定性；
- fault 变体、claim、pair 的构造数量不是自然样本量；不能把构造 n 当 prevalence 的置信度。

### 8.5 成本

- LLM：按运行当天价格快照从 usage 计算 USD；记录 prompt/completion/cached/reasoning tokens、p50/p95 latency；`opencode.allowance` 不是 USD；
- 静态/动态：`usd=null`（不是 0），`cost_basis="local_compute"`；记录 wall/CPU/RSS；
- position：成本按 2 次请求/对计；报告 `cost_per_100_pairs_usd`；
- evidence：成本按 claim 计；`cost_per_100_claims_usd`；
- fault：成本按 variant 计；`cost_per_100_variants_usd`；
- static：成本按 unit 计；`cost_per_100_units_usd`；
- 不做单一“性价比”总分；USD、秒、MB 不混合。

### 8.6 排除账本

每个 design 必须报告：

- `planned_units` / `recorded_units` / `valid` / `missing`；
- `by_status` 分布；
- 排除原因计数：`compile_error`、`harness_error`、`oracle mismatch`、`inconclusive`、`not_applicable`、`schema_invalid`、`api_error`、`timeout`；
- fault：expected inconclusive、oracle mismatch、coverage 不足分别计数；
- static：compile_error、out-of-scope、unmapped、suppressed 分别计数；
- 不能“某方法失败就换分母”；同一 unit 集合的排除必须跨方法一致。

---

## 9. 已做的验证（真实执行）

| 验证 | 结果 |
| --- | --- |
| `ext_validate.py --check-registries` | PASS：8 designs / 6 tools / 17 rules / 10 fault types |
| `ext_selftest.py` | PASS：position / open-choice / evidence-claim / fault / static 五类合成 fixture 的 import → validate → metrics；evidence_retraction / enhanced_dynamic / hybrid 由真实 producer 格式导入验证 |
| 父 validator 兼容 | pair/evidence/dynamic/hybrid canonical run 的 `bench_validate.validate_run` errors=[] |
| 真实 Cppcheck 重导入 | test 140：macro-F1 **0.5878623**，TP22/FP4/TN66/FN48，valid 140；与父 canonical `static_cppcheck` 一致 |
| 真实 Clang SA 重导入 | test 140：macro-F1 **0.88834765**，TP53/FP0/TN68/FN15，valid 136，compile_error 4；与父 canonical `static_clang` 一致 |
| 安全 | `check_no_secret_fields` 拒绝 `api_key`；canonical 输出不含请求头/凭证 |
| 真实 CodeQL 2.27.4 导入 | test 140：canonical valid 136（compile_error 4），TP68/FP23/TN45/FN0，macro-F1 0.8259；end-to-end TN47/FN2；与 `static_extended` producer 的 140 对比逐格一致 |
| 全 canonical run 重校验 | 14 个 run（pair forced 2 base + open 4 + evidence 4 + dynamic 1 + hybrid 2 + CodeQL 1）全部 `--jsonschema` PASS；16 项父指标重算 0 不一致 |

**真实 pair_debias（canonical 重算）**

| 条件 | n pairs | position-avg DA | 95% CI | order-consensus DA | 语义一致率 | slot A / B | position bias |
| --- | ---: | ---: | --- | ---: | ---: | --- | ---: |
| DeepSeek forced fwd/rev | 180 | 0.7722 | [0.7278, 0.8139] | 0.6167 | 0.6889 (124/180) | 0.9278 / 0.6167 | +0.3111 |
| MiMo forced fwd/rev | 180 | 0.8417 | [0.7972, 0.8806] | 0.7444 | 0.8056 (145/180) | 0.9056 / 0.7778 | +0.1278 |

长度审计（两序合计 348 个有效 presentation）：较长侧=vulnerable 仅 25.29%，choose-longer 25.57%/21.84%；说明“选较短”仍是强基线，position-avg 不能单独解释为语义能力。

**真实 pair_debias open-choice（每个条件独立 run）**

| 条件 | pair DA | decisive rate | conditional DA | both / neither |
| --- | ---: | ---: | ---: | --- |
| DeepSeek open_fwd | 0.6611 | 0.7889 | 0.8380 | 13 / 25 |
| DeepSeek open_rev | 0.6389 | 0.8278 | 0.7718 | 7 / 24 |
| MiMo open_fwd | 0.6611 | 0.7833 | 0.8440 | 8 / 31 |
| MiMo open_rev | 0.6573 | 0.7753 | 0.8478 | 7 / 33 |

这两组 open run 没有被合并成“去偏”主指标；fwd/rev 相关，不能当独立样本。

**真实 evidence_verify 四臂**：见 §3.6（post macro-F1 0.2181 / 0.3522 / 0.3221 / 0.2226；均为 post-hoc、test seen）。

**真实 dynamic_enhanced**：见 §3.7（protocol valid 70/140、coverage 0.5、macro-F1 未定义；operational 70/70 仅作 coverage-unverified 视图；12 个旧不可观测 bad 全部补到证据）。

**真实 hybrid_dynamic_enhanced**：见 §3.8（DeepSeek 137/140、macro-F1 0.9786；MiMo 136/140、0.9714；工具 140/140，增益不显著）。

selftest 的手算值（**合成，不是实验结论**）：

| design | 关键值 |
| --- | --- |
| position | `position_avg_pair_da=0.5`、`order_consensus_pair_da=0.25`、`order_consistency=0.5`、`slot_accuracy_A/B=0.5`、`position_bias_index=0`、`flip_to_correct/wrong=0.25/0.25`、`length_only_da=0.6667` |
| open | `pair_da=0.25`、`decisive_rate=0.5`、`pair_da_decisive=0.5`、`both_rate=neither_rate=0.25` |
| evidence claim | P=1.0、R=0.5、specificity=1.0、macro-F1=0.6667、coverage=0.75、strict=0.5、false support=0、false reject=0.5、abstention=0.25 |
| fault | BA=0.5、sensitivity=0.5、specificity=0.5、macro-F1=0.5、strict=0.4（低覆盖 clean 在 strict 算错） |
| static | default macro-F1=1.0；high-only macro-F1=0.7333；delta=-0.2667 |

**真实 Cppcheck/Clang 重导入是对既有 `traditional/static` raw 的只读适配器验证，不是新实验，也不是新静态工具结果。** 它证明 rule→CWE-401、scope、dedup、compile_error 的处理与父 canonical 一致。

---

## 10. 与主 leaderboard 的集成（已执行：只加链接，不池化）

最终扩展汇总已生成：`benchmark/results/EXTENSIONS.md` + `benchmark/results/extension_summary.json`，由 `benchmark/tools/bench_ext_summary.py` 从 canonical run 重算并复核。`benchmark/results/LEADERBOARD.md` **只增加了一条指向 `EXTENSIONS.md` 的链接**，`final_summary.json` 未被改写，扩展 run 不进入 Tier A/B 主表。汇总遵循以下规则：

1. 生产者写 raw，运行 `ext_import.py` 生成 canonical run；
2. 运行 `ext_validate.py --jsonschema`（position 要 `--sibling-run-dir`；有冻结清单就 join）；
3. 运行 `ext_metrics.py` 生成 `metrics.json` / `metrics.md`；
4. 只把 **validated** run 交给主流程；主流程重新跑 `ext_validate`/`ext_metrics`，不手抄数字；
5. 最终汇总文件提供**独立的 extension 区块**，每行带 `design`、`design_version`、parent task、n/coverage、primary、status 分布、成本、限制；主 leaderboard 只链接，不复制这些行；
6. 不在主表里把 extension DA 与 forced-choice DA 相减；不把八个 design 池化；不把 fault 变体与 canonical 140 池化；dynamic_enhanced 的 operational 70/70 必须带 coverage-unverified 标注；evidence_retraction 必须标 post-hoc、test seen。

建议主流程在 extension 表中显式列：

```text
design | method_id | run_id | parent_task | n_planned | n_recorded | n_valid | coverage |
primary_metric | value | 95% CI | strict | status_counts | cost | design_version | notes
```

**Canonical run 选择。** 每个 design 可以有多个 run（不同模型/配置/工具）；主流程必须列出所有 canonical run，不能只挑最好的一个。`--force` 归档的旧 run 在 `.superseded/`，不进入主表。

---

## 11. 限制与不能声称

1. **已导入真实产物，但不是本目录的新实验。** pair/evidence/dynamic/hybrid/static canonical run 是 producer 真实结果的只读导入；本目录没有重新调用模型/分析器。不要把 selftest 或重导入数值当成本目录的新实验。
2. **Position 的长度混淆不能被 order swap 消除。** 必须看 `length_audit`；pair_debias 的较长侧=vulnerable 仅 25.29%，position_avg 不能单独解释为语义能力。
3. **Open-choice 与 forced-choice 是不同任务。** 不能把 DA 直接相减；both/neither 是任务行为，不是自然 prevalence；open_fwd/open_rev 相关，不能当独立样本。
4. **Evidence verification 的 claim 构造是效度核心。** 如果正负例在长度/模板/措辞上有系统差异，verifier 可以走捷径；必须冻结 `construction_rule` 并做表面形式审计。
5. **Evidence retraction 是 post-hoc、test seen。** 四臂共享同一 160 单元，不能当独立确认；fail-closed 会把验证器 API 失败变成撤销，必须同时报告 invalid/fail-closed。
6. **Fault injection 是构造的压力测试。** `fault_balanced_accuracy` 不是 CWE-401 检测质量，也不是自然分布；fault 变体之间相关，不能按 variant 独立检验。
7. **Enhanced dynamic 的 clean 不是 protocol TN。** 无行/分支覆盖率，canonical clean=inconclusive；operational 70/70 只是 producer 口径，必须标 coverage-unverified。
8. **Hybrid enhanced-dynamic 受工具天花板约束。** 工具 140/140，LLM 与工具一致率等于准确率；v2 direct 已覆盖 12 个旧不可观测 bad，增益不显著；不能声称证据带来语义提升。
9. **新静态工具版本/规则会漂移。** 必须记录 tool version、command、registry version/hash；`codeql` 已完成正式 run 并有 canonical 导入（valid TP68/FP23/TN45/FN0；end-to-end TN47/FN2，4 compile），`infer` 仍未安装且没有结果，不能报告其数字。
10. **单次运行。** pair/evidence/dynamic/hybrid 都是一次 run；没有 seed/run-to-run 方差；不能声称“稳定/可复现”。
11. **不能跨层。** Tier A 真实函数与 Tier B Juliet 不能合并；Juliet 结果不能外推到真实项目；Tier A 静态只做可行性，不做 F1。
12. **不能把 schema-invalid/api_error/timeout 静默删掉后只报 valid-only。** 必须给 strict、coverage、失败分布。
13. **不能把 `not_applicable` 当 0 或负例。**
14. **不能把成本换算成未经验证的云价格后与 API USD 相加。**
15. **不能用 `--force` 掩盖旧结果。** 旧输出移到 `.superseded/`；主表只读 canonical run；本次重导入产生的中间 canonical run 已删除并重建；最终只保留通过校验的版本，producer 原始结果未被修改。

---

## 12. 归属与并行规则

- 本目录由 benchmark/extensions 负责人维护；其他 agent 在自己的分配目录写 raw/方法代码，不直接改本目录的 schema/registry/tools。
- 新方法实验必须通过 `ext_import.py` 接入；不要手写 canonical prediction 或修改已发布的 canonical run。
- 不覆盖旧结果：新的 run_id/新目录；`--force` 只归档不删除。
- 所有代码在 WSL 运行；不执行 `git`/`gh`；不显示/保存 API key；发布由主流程统一执行。
- 若某个 producer 需要新字段：先在 `producer_raw.schema.json`/`extension_blocks.schema.json` 提版本变更，再实现 importer；不要用未知字符串滥用父 `status`/`task`。

---

## 13. 参考

- 父协议：[`../PROTOCOL.md`](../PROTOCOL.md)
- 父 schema：[`../schemas/README.md`](../schemas/README.md)
- 父工具：[`../tools/ADAPTERS.md`](../tools/ADAPTERS.md)
- 旧静态适配器：`traditional/static/README.md`
- 旧动态适配器：`traditional/dynamic/README.md`
- pair-joint 位置/长度背景：`pair_joint/report.md`
- evidence prompt 背景：`evidence_prompt/README.md`
- hybrid v2 / 泄漏修复：`hybrid/REPORT_V2.md`
- Juliet 数据卡：`benchmark/datasets/juliet_cwe401_v1/dataset_manifest.json`

---

## 14. 2026-11-22 下一轮：五个弱点实验（已导入）

本轮新增 5 个 design、30 个 canonical run。原始产物在 `codeql_triage/`、`verifier_conservative/`、`pair_diff/`、`dynamic_coverage/`、`interpretable_baseline/`，本目录只读导入，未重新调用模型/分析器。

| design | run 数 | 主终点 | 真实结果（摘要） |
| --- | ---: | --- | --- |
| `codeql_alert_triage` | 8 | `macro_f1` | verified 68/0/70/2（0.9857）；direct 69/5/65/1（0.9571）；McNemar p=0.2891，不显著；text rule 与 verified 逐条同判 |
| `conservative_verification` | 4 | `macro_f1` | 4/236 撤销（TP3/FP1）；Δmacro-F1 0 到 -0.0052；MCC 仅 mimo_cross +0.0139（CI 跨 0） |
| `diff_guided_pair` | 8 | `pair_da` | 交换一致 DA：DS diff 62.22% vs ctrl 60.00%（Holm 1.0000）；MiMo 60.56% vs 62.22%（Holm 0.9053） |
| `coverage_instrumented_dynamic` | 1 | `branch_complete_rate` | 21/140 branch-complete，全部 bad；clean 0 branch-complete；default 58 leak / 82 inconclusive |
| `interpretable_baseline` | 9 | `macro_f1` | length 0.511（MCC 0.094）；majority 0.444（MCC 0）；alloc_or_mem MCC 0.183；LLM 0.346–0.422 |

汇总文件：`benchmark/results/NEXT_ITERATION.md` + `benchmark/results/next_iteration_summary.json`，由 `benchmark/tools/bench_next_iteration_summary.py` 从 canonical predictions 重算。

不能违反的规则（本轮新增）：

1. **CodeQL triage 不是独立盲审。** verifier 看到第一遍 JSON；text rule 与 verified 同判，说明该 split 上的“干净”可由零成本规则复现。不能把 68/0/70/2 写成 triage 的独立贡献。
2. **pair diff 没有 Holm 显著优势。** 不能写“diff 有效”或“diff 减少长度捷径”；长度 H-gap 仍有 33–40 pp，选较短比例 75–81%。
3. **conservative verifier 是负结果。** 判定规则修对了（不再 fail-closed），但撤销太少、macro-F1 不升；不能当提分组件。
4. **coverage clean 不是 TN。** 行覆盖 99.9% 但分支覆盖约 52.7%；没有 clean 单元 branch-complete。canonical clean 一律 `inconclusive`，operational 视图另列。
5. **interpretable baseline 不是“规则更会检测漏洞”。** 长度规则赢 macro-F1 主要因为 80% 正例下多报；MCC 排名翻转；vs DeepSeek evidence 的 Holm p=0.203，不显著。
6. **不跨设计池化。** 五个 design 各有自己的分母；CodeQL/coverage 是 Tier B Juliet，interpretable 是 Tier A SecVulEval，不能合并。
7. **主表未改。** `LEADERBOARD.md`、`final_summary.json`、`tier_a_*`、`tier_b_*` 保持原样；本轮只新增扩展层 run 和两份汇总文件。

# 最新扩展结果统一汇总（2026-11-14）

**范围**：本文件汇总 2026-11-13 至 2026-11-14 新增的六组真实实验与三份文献调研，作为 `report/report_latest_zh.tex` / `report/report_latest_zh.pdf` 的配套结果摘要。所有数字来自已落盘的结果 JSON/MD；没有重新调用模型、没有修改旧 run、没有执行 git。

**一句话结论**：最新实验整体上是**负结果居多**：单序强制二选一的 86.7% 在交换一致口径下降到 74.44%，与长度启发式不可区分；二次验证降低 macro-F1；动态增强做到 140/140 但没有覆盖率 instrumentation；增强动态证据混合不显著；CodeQL 用 23 个假阳性和 42.5 s/单元换取 97.1% 召回；schema 修复只回收约 7.25 pp 的结构可用产出。

---

## 0. 总表

| 实验 | 规模 | 主结果 | 判定 | 产物 |
| --- | --- | --- | --- | --- |
| 配对顺序去偏 | 180 对 × 2 顺序 × 2 任务 × 2 模型；新增 1,080 请求 | 交换一致 DA：DeepSeek 61.67%（强制）/55.56%（开放）；MiMo 74.44%/58.33% | **单序 86.7% 不能作为最终能力**；DeepSeek 低于长度启发式 | `pair_debias/results/` |
| 证据二次验证 | 160 条 × 4 臂；236 次验证请求 | $\Delta$macro-F1：$-0.2043$ / $-0.0701$ / $-0.0846$ / $-0.1842$ | **降低 macro-F1**；撤销不偏向 FP | `evidence_verify/analysis/` |
| 动态分析增强 | 140 单元 × 3 模式；420 次运行 | TP 70 / FP 0 / TN 70 / FN 0；12/12 旧不可观测 bad 有证据 | **可操作性 140/140，不是检测能力** | `dynamic_enhanced/runs/test140_enhanced_v3/` |
| 增强动态证据混合 | 2 模型 × 140；280 请求 | DeepSeek 137/140（+2，$p=0.5$）；MiMo 136/140（0，$p=1.0$） | **不显著**；无法区分抄证据与推理 | `hybrid_dynamic_enhanced/results/` |
| CodeQL 对照 | 200 单元（test 140） | test：TP 68 / FP 23 / FN 2；P 0.747 / R 0.971 / MCC 0.674；42.5 s/单元 | **高召回、低精确、高成本**，MCC 低于 Clang | `static_extended/runs/codeql_20261114_cwe401_full/` |
| schema 复分析 | 12 个 run；924 条 repair + 1,560 条 detection；0 API | 102 条 invalid 中 93 条只缺 `explanation`；usable 552/924 → 619/924（+7.25 pp） | **schema 不是修复质量的主矛盾** | `analysis/schema_recovery/` |

---

## 1. 配对顺序去偏（pair_debias）

### 1.1 设计

同一批 180 对测试版本，每个模型跑四个条件：强制二选一正向（复用已发布的 `pair_joint` 运行）、强制二选一反向、开放四分类正向、开放四分类反向。每个模型新增 540 次请求；新增 configured 成本 DeepSeek $0.460274、MiMo $0.216331（不含已发布的 forced 正向）。完整性检查：同一数据集 SHA-256（`21218fd8…`）、反向映射精确、无泄漏审计问题、槽位平衡。

**交换一致 DA**：正向和反向都把漏洞版本判对才算对。它不随槽位偏好漂移，是本节的主指标。

### 1.2 主表

| 模型 | 任务 | 正向 DA | 反向 DA | 交换一致 DA | 语义一致率 | 同字母率 | 顺序 McNemar $p$ |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 强制 | 76.67% (138/180) | 77.78% (140/180) | **61.67%** (111/180) | 68.89% (124/180) | 31.11% (56/180) | 0.8939 |
| DeepSeek | 开放 | 66.11% (119/180) | 63.89% (115/180) | **55.56%** (100/180) | 72.78% (131/180) | 14.50% (19/131) | 0.6076 |
| MiMo | 强制 | 86.67% (156/180) | 81.67% (147/180) | **74.44%** (134/180) | 80.56% (145/180) | 19.44% (35/180) | 0.1755 |
| MiMo | 开放 | 66.11% (119/180) | 65.56% (118/180) | **58.33%** (105/180) | 79.44% (143/180) | 8.59% (11/128) | 1.0000 |

交换一致 DA 的 Wilson 95% CI：DeepSeek forced [54.39, 68.46]、MiMo forced [67.61, 80.26]。

同字母率的分母是两序都给出 A/B 的对（强制 180；开放 DeepSeek 131、MiMo 128），不是 180。

### 1.3 与长度启发式的比较

长度启发式 = “选较短版本，等长时选 A”；两序同语义版本为 72.22%（130/180）。

| 模型 | 任务 | 交换一致 DA | 启发式 DA | $\Delta$ | McNemar $p$ | Holm $p$ |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 强制 | 61.67% | 72.22% | $-10.56$ | 0.0145 | 0.0289 |
| DeepSeek | 开放 | 55.56% | 72.22% | $-16.67$ | 0.0002 | 0.0007 |
| MiMo | 强制 | 74.44% | 72.22% | $+2.22$ | 0.6440 | 0.6440 |
| MiMo | 开放 | 58.33% | 72.22% | $-13.89$ | 0.0015 | 0.0046 |

长度匹配子集（相对字符差 ≤10%，$n=144$，单序）：DeepSeek 强制正向 75.69% vs 72.92%（$p=0.644$）、反向 75.69% vs 71.53%（$p=0.441$）；DeepSeek 开放正向 62.50% vs 72.92%（$p=0.044$）、反向 59.03% vs 71.53%（$p=0.020$）；MiMo 强制正向 86.81% vs 72.92%（$p=0.0005$）、反向 79.17% vs 71.53%（$p=0.108$）；MiMo 开放正向 64.58% vs 72.92%（$p=0.111$）、反向 61.11% vs 71.53%（$p=0.053$）。MiMo 在强制正向上的优势在反向与两序合并后消失。

### 1.4 位置偏差

| 模型/顺序 | 漏洞在 A | 漏洞在 B | 差值（pp） |
| --- | ---: | ---: | ---: |
| DeepSeek 正向 | 92.22% (83/90) | 61.11% (55/90) | 31.11 |
| DeepSeek 反向 | 93.33% (84/90) | 62.22% (56/90) | 31.11 |
| MiMo 正向 | 88.89% (80/90) | 84.44% (76/90) | 4.44 |
| MiMo 反向 | 92.22% (83/90) | 71.11% (64/90) | 21.11 |

DeepSeek 的偏差跟着 A 槽走，两个顺序都约 31.11 pp；这不是“先呈现”效应，而是槽位偏好。

### 1.5 任务效应

开放四分类比强制二选一低 10.56–20.56 pp（Holm $p\le0.0034$）。开放条件中 both/neither 按定义算错：DeepSeek 正向 13 both / 25 neither，MiMo 正向 8 both / 31 neither。强制 DA 与开放 DA 不能直接相减。

### 1.6 结论

- 单序强制二选一 86.7% **不能作为最终能力**；位置无关的交换一致 DA 为 74.44%，与长度规则不可区分。
- DeepSeek 的交换一致 DA 为 61.67%（强制）、55.56%（开放），显著低于不看代码的长度启发式。
- 联合提示的主要收益来自任务框架、长度先验和槽位偏好，不是可靠的跨版本推理。

---

## 2. 证据提示的二次验证（evidence_verify）

### 2.1 设计

对第一遍证据提示的每个 schema-valid 正例再发一次独立上下文请求，要求模型尝试反驳（检查证据、守卫、反例），允许撤销；负例不动。四个臂：DeepSeek 自审、MiMo 审 DeepSeek、MiMo 自审、DeepSeek 审 MiMo。验证器看不到标签、项目、路径、commit、`changed_lines`、第一遍 confidence 或修复建议。主口径 fail-closed（未明确 sustain 即撤销）。**这是事后探索性分析**：160 条已用于第一遍评估，验证器提示是在看到结果后设计的。

### 2.2 主结果

| 臂 | TP | FP | TN | FN | P | R | macro-F1 | $\Delta$macro-F1 | $\Delta$MCC | McNemar Holm $p$ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek 自审 pre | 49 | 11 | 21 | 78 | 0.8167 | 0.3858 | 0.4223 | — | — | — |
| DeepSeek 自审 post | 6 | 0 | 32 | 121 | 1.0000 | 0.0472 | 0.2181 | $-0.2043$ | $+0.0646$ | 0.0001 |
| DeepSeek 跨模型 pre | 49 | 11 | 21 | 78 | 0.8167 | 0.3858 | 0.4223 | — | — | — |
| DeepSeek 跨模型 post | 28 | 4 | 28 | 99 | 0.8750 | 0.2205 | 0.3522 | $-0.0701$ | $+0.0607$ | 0.0125 |
| MiMo 自审 pre | 47 | 11 | 20 | 80 | 0.8103 | 0.3701 | 0.4067 | — | — | — |
| MiMo 自审 post | 28 | 8 | 23 | 99 | 0.7778 | 0.2205 | 0.3221 | $-0.0846$ | $-0.0481$ | 0.0017 |
| MiMo 跨模型 pre | 47 | 11 | 20 | 80 | 0.8103 | 0.3701 | 0.4067 | — | — | — |
| MiMo 跨模型 post | 7 | 0 | 31 | 120 | 1.0000 | 0.0551 | 0.2226 | $-0.1842$ | $+0.0938$ | 0.0002 |

表中 TP/FP/TN/FN 为 valid-only；strict 160 口径把第一遍 invalid 记录在两侧都算错，因此四臂的行和分别为 159/159/158/158。

### 2.3 撤销是否偏向假阳性

| 臂 | 撤销总数 | 撤销 TP | 撤销 FP | 撤销精确率 | 正例 FP 基准率 | 超几何 Holm $p$ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek 自审 | 54 | 43 | 11 | 20.4% | 18.3% | 0.8380 |
| DeepSeek 跨模型 | 26 | 20 | 6 | 23.1% | 18.3% | 0.8380 |
| MiMo 自审 | 21 | 18 | 3 | 14.3% | 19.0% | 0.8494 |
| MiMo 跨模型 | 51 | 40 | 11 | 21.6% | 19.0% | 0.8367 |

没有任何一个臂显示撤销显著偏向 FP。同预算随机撤销的 macro-F1 期望为 0.4176 / 0.4201 / 0.4067 / 0.4067，全部高于验证器的 0.2181 / 0.3522 / 0.3221 / 0.2226。

### 2.4 事后 refutation-only 规则

只撤销 `verdict=retract` 且 `rebuttal_type != insufficient_evidence` 的正例（不调用模型，事后打分）：撤销数 18/8/6/17，macro-F1 仍下降 0.0475/0.0148/0.0371/0.0422，McNemar Holm $p$ 0.0927/0.3438/0.0625/0.0981。方向一致为负，只是幅度变小。两个验证器的一致性很低：Cohen $\kappa$ 0.044（DeepSeek 正例）、0.151（MiMo 正例）。

### 2.5 成本

每臂验证请求 60/60/58/58，验证器 USD 0.064580/0.022693/0.015100/0.051960，合计（含第一遍）0.150202/0.108314/0.051033/0.087893。

### 2.6 结论

**二次验证降低 macro-F1**；召回大幅下降；撤销不偏向假阳性；同预算下不如随机撤销。它最多是一种保守操作点，不是检测能力提升。

---

## 3. 动态分析增强（dynamic_enhanced）

### 3.1 设计

对 Juliet CWE-401 test 140 的 140 个冻结单元，用三种模式各运行一次：

- `default`：复现旧 ASan/LSan（`use_stacks=0:use_registers=0`）。
- `realloc_fail`：链接期 `-Wl,--wrap=realloc`，只让第一个收到非 NULL 指针的 `realloc` 返回 NULL；注入是运行事实，不是配置假设。
- `nogobal`：`LSAN_OPTIONS=use_globals=0`，关闭全局根。

判定规则：任一适用模式出现“归因到本单元源文件”的泄漏即 leak；未归因的 glibc/libstdc++ 泄漏不计入。

### 3.2 结果

| 模式 | 适用单元 | bad 归因泄漏 | good 归因泄漏 | bad 原始泄漏 | good 原始泄漏 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `default` | 140 | 58 | 0 | 58 | 0 |
| `realloc_fail` | 14 | 7 | 0 | 7 | 0 |
| `nogobal` | 140 | 63 | 0 | 70 | 70 |
| 并集 | — | **70** | **0** | — | — |

混淆矩阵：TP 70 / FP 0 / TN 70 / FN 0；coverage 1.000；precision/recall/F1 均为 1.000。12 个旧不可观测 bad（7 个 `malloc_realloc` + 5 个 `_68` 全局指针）全部有可复核证据：分配栈、源码行、注入调用序号、归因字节数。`nogobal` 的 70/70 good 原始泄漏全部是运行时噪声，归因后为 0；若直接以“有泄漏”为预测会产生 70 个误报。

### 3.3 与旧结果对比

- 新 `default` vs 旧 ASan：140/140 判定一致。
- 新并集 vs 旧 ASan/Valgrind 任一：128/140；差异恰好是 12 个 bad，全部由 `realloc_fail`/`nogobal` 解释。
- good 判定变化：0。

### 3.4 运行时间

140 单元 × 3 模式（每单元 2 次编译 + 3 次运行）总 315,596 ms；单元均值 2,254 ms，p50 2,062 ms，p95 3,746 ms，max 4,977 ms。单次运行均值：`default` 62.6 ms、`realloc_fail` 68.9 ms、`nogobal` 147.9 ms。

### 3.5 限制

- **无覆盖率 instrumentation**：每个模式只执行 probe 的一条路径，没有 fuzzing、输入生成或路径探索。`clean` 只表示“执行到的路径上没有归因泄漏”，不是“无泄漏证明”。
- `realloc_fail` 只让第一次非 NULL `realloc` 失败；本 test 集的 7 个单元都只有一次非 NULL `realloc`。
- `nogobal` 是全局根总开关，不是逐变量根映射；不能指出是哪一个全局变量持有块。
- Valgrind 未重跑（WSL 未安装），导出中 `valgrind.status=unavailable`，不能冒充 clean。
- 归因依赖 `-g -O0`；换优化级别或 strip 后需要重新验证。
- 140/140 只限 `split=test` 的冻结 140 单元，不能外推到其他 split、CWE 或编译器。

---

## 4. 增强动态证据混合（hybrid_dynamic_enhanced）

### 4.1 设计

把动态增强的数值证据（逐模式适用性、归因字节、分配记录数、注入调用序号）渲染进混合提示；系统提示与证据包装与 v2 逐字节一致，唯一差别是证据正文。2 模型 × 140 = 280 次新请求，0 invalid、0 API 错误。

### 4.2 结果

| 模型 | 方法 | TP/FP/FN/TN | 准确率 | 95% CI | 不一致（新/旧） | McNemar $p$ | Holm $p$ |
| --- | --- | --- | ---: | --- | ---: | ---: | ---: |
| DeepSeek | direct（v2） | 70/5/0/65 | 96.43% | [91.91, 98.47] | — | — | — |
| DeepSeek | 增强动态 | 70/3/0/67 | **97.86%** | [93.89, 99.27] | 2/0 | 0.5000 | 1.0000 |
| MiMo | direct（v2） | 70/4/0/66 | 97.14% | [92.88, 98.88] | — | — | — |
| MiMo | 增强动态 | 70/4/0/66 | **97.14%** | [92.88, 98.88] | 0/0 | 1.0000 | 1.0000 |
| 动态工具 | 三模式并集 | 70/0/0/70 | 100.00% | [97.33, 100.00] | — | — | — |

### 4.3 解释

- 12 个旧不可观测单元：两个模型的 direct 已经是 12/12，新证据没有额外 headroom。
- 剩余过度报警集中在 `new_array_char_22__good`、`new_array_int_22__good`、`new_int_22__good`（MiMo 还有 `twoIntsStruct_realloc_22__good`）。
- 理由中重复归因字节数的比例：DeepSeek 92.86%、MiMo 88.57%；direct 为 11.43%/22.86%。证据被读取和引用，但判定不总跟随证据。
- 工具在 140 单元上满分，准确率无法区分“抄证据”和“独立推理”；只能说证据被部分采纳，语义推理增益未被证明。

### 4.4 成本

280 请求：224,028 prompt tokens、13,904 completion tokens、configured $0.023561（DeepSeek $0.011165、MiMo $0.012395），预检冒烟另加 $0.000088。MiMo 新方法是 direct 的 2.63 倍（$0.012395 vs $0.004718）。

### 4.5 限制

- 基线 direct/dynamic/combined 是 2026-11-11 的冻结运行，与新方法不是同一天，模型漂移与服务端非确定性未分离。
- 工具证据是条件性的：`realloc_fail` 只覆盖 14 个单元，`nogobal` 是全局开关，clean 只是单路径观测。
- 只有 140 个单元，$+2/0$ 的功效很低。

---

## 5. CodeQL 工具对照（static_extended）

### 5.1 设计

CodeQL CLI 2.27.4 + `cpp-queries` 1.10.0，两条 CWE-401 查询：`cpp/memory-never-freed` 与 `cpp/memory-may-not-be-freed`。每单元单独建库，编译命令与 Clang/Cppcheck 基线对齐；多文件单元用同样的 `#include` 包装 TU。200 单元中 194 可分析（97.0%），6 个 `_82` 编译失败与 Clang 基线一致。

### 5.2 test 140 结果

| 工具 | 可评估/总数 | TP | FP | TN | FN | P | R | F1(V) | MCC |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Clang 22.1.8 | 136/140 | 53 | 0 | 70 | 17 | 1.0000 | 0.7571 | 0.8618 | 0.7805 |
| CodeQL 2.27.4 | 136/140 | 68 | 23 | 47 | 2 | 0.7473 | **0.9714** | 0.8447 | 0.6739 |
| Cppcheck 2.21.0 | 140/140 | 22 | 4 | 66 | 48 | 0.8462 | 0.3143 | 0.4583 | 0.3306 |

### 5.3 分查询与互补性

| 查询 | TP | FP | TN | FN | P | R | F1(V) | MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `cpp/memory-never-freed` | 46 | 0 | 70 | 24 | 1.0000 | 0.6571 | 0.7931 | 0.6995 |
| `cpp/memory-may-not-be-freed` | 22 | 23 | 47 | 48 | 0.4889 | 0.3143 | 0.3826 | $-0.0153$ |
| 并集 | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8447 | 0.6739 |

70 个 test bad：CodeQL 与 Clang 都报 53，仅 CodeQL 报 15，仅 Clang 报 0，两者都不报 2（`_82` 编译失败）。23 个 FP 全部是 C++ good：`_33` 15、`_22` 3、`_72` 3、`_54` 2；全部来自 `may-not-be-freed`。C 单元 58/58 全对，无 C 误报。

### 5.4 运行时间

200 单元总墙钟 1,434.7 s（6 并发）；单单元均值 42.5 s（建库 22.5 s + 查询 20.6 s），P95 51.7 s，最大 60.5 s；test 成功单元均值 44.1 s。对比基线 0.118 s/单元（Clang）与 0.045 s/单元（Cppcheck），约慢 360×/940×。

### 5.5 限制

- 每单元单独建库，42.5 s 包含建库、TRAP 导入与并发争用，不是查询内核纯计算时间。
- 查询版本固定；升级 `cpp-queries` 会改变召回/误报。
- CodeQL 用 gcc/g++ 15.3 建库，Clang/Cppcheck 用 clang 22.1.8；编译器不同。
- 按冻结标签计分，包含 22 个“静态认为泄漏、运行时未触发”的 bad；不能直接与动态召回并列。
- Semgrep 与 Infer 未产出结果，不报告数字。

---

## 6. schema 失败的可回收性（analysis/schema_recovery）

### 6.1 设计与口径

零 API 复分析 12 个 Tier A run（DeepSeek 6 个 repair 924 条；MiMo 6 个 detection 1,560 条、repair 924 条）。三个视图：

- **official strict**：`record.status == "ok"`，repair 恰好 `fixed_function` + `explanation`。
- **code-only salvage**：合法 JSON、非空 `fixed_function`、只缺 `explanation`。
- **usable patch**：结构完整 + comment-insensitive 实质改动；**不是**编译/测试/PoC 通过（oracle 级别 L0）。

### 6.2 结果

| 指标 | 计数/分母 | 值 |
| --- | --- | ---: |
| official repair schema valid | 822/924 | 89.0% |
| code-only 接纳 | 915/924 | 99.0% |
| `missing_explanation` | 93/924 | 10.1% |
| 截断（fatal） | 9/924 | 1.0% |
| 93 条中 canonical complete | 91/93 | 97.8% |
| 93 条中 K&R-aware complete | 93/93 | 100.0% |
| 93 条中 comment-insensitive substantive | 69/93 | 74.2% |
| usable canonical | 67/93 | 72.0% |
| usable K&R-aware | 69/93 | 74.2% |
| official usable | 552/924 | 59.7% |
| code-only usable | 619/924 | 67.0% |
| salvage 增益 | 67 条 | $+7.25$ pp |

93 条缺 `explanation` 中，26 条（canonical）不可用：18 条 no change、4 条 whitespace only、2 条 comment only、2 条 K&R 假阴性。官方 schema 有效的 822 条里，usable 只有 552（67.2%），no change 208（25.3%），whitespace only 55（6.7%）。

### 6.3 MiMo 字段漂移反例

MiMo 61 条 detection 字段漂移（61/1560，3.91%）：61/61 可 alias-remap，但恢复值 5 true / 56 false，与 gold 事后一致只有 28/61。格式可回收 ≠ 内容正确。

### 6.4 成本

DeepSeek invalid normalized 成本 $0.218280，占其总成本 11.50%、repair 成本 16.50%。其中 93 条 missing 占 invalid 条数 91.18%，但只占 invalid 成本 47.44%；9 条截断占条数 8.82%，却占 invalid 成本 52.56%（单条约 $0.01275，是 missing 单条的约 11.4 倍）。

### 6.5 结论

- schema 修复带来 +7.25 pp 的结构可用产出，边际 API 成本为 0。
- 从 915/924 的 code-only 接纳到 619/924 的 usable，仍有约 32 pp 落在空补丁、空白/注释改动或结构不满足上。
- **schema 不是修复质量的主矛盾**；usable 仍不是编译、测试或 PoC 通过。

---

## 7. 三份最新文献（2025--2026）

| 文件 | 覆盖 | 与本项目最相关的结论 |
| --- | --- | --- |
| `research/latest_llm_methods_2026.md` | 检测、agentic 审计、结构化输出、自一致性、约束解码 | 强方法把“发现”和“裁决”拆开；标签噪声显著（VulValidate 仅 57.2% 确认）；self-consistency 可能引发过度弃权 |
| `research/latest_evaluation_repair_2026.md` | 位置偏差、长度控制、配对协议、placebo、judge 可靠性、补丁过拟合、fault injection | 协议效应可与模型差异同量级；单序配对受长度/位置混杂；补丁过拟合仍严重（>40% 基础测试通过的补丁在 PoC+ 下失败）；oracle 要分级 |
| `research/latest_memory_tools_2026.md` | CWE-401 语义、realloc 失败、still reachable、CodeQL/Infer/Semgrep、LeakGuard/MemHint/LAMeD | `p=realloc(p,n)` 是独立反模式；still reachable 不是 leak 也不能当 TN；动态 clean 只覆盖执行路径；真实项目瓶颈是构建/所有权/告警治理 |

这些文献只用于校准解释边界，不是新实验。完整条目与核验表见三份文件；`report/references_latest.bib` 中的新增条目已通过 arXiv API、Crossref 与 DROPS 核验标题/作者/venue/DOI。

---

## 8. 与扩展版（27 页）相比被收紧的表述

| 扩展版表述 | 最新结果 | 处理 |
| --- | --- | --- |
| 强制二选一 DA 76.7%/86.7% | 交换一致 DA 61.67%/74.44%；开放 55.56%/58.33% | 单序数字保留为“单序”，主指标改为交换一致 DA；86.7% 不再作为最终能力 |
| MiMo 显著高于长度启发式（$p=0.0003$） | 两序一致口径 74.44% vs 72.22%，$p=0.644$ | 只在“单序 + 长度匹配正向”保留方向性观察，不再作为稳定优势 |
| 证据提示提高召回 | 二次验证后 macro-F1 全面下降 | 召回提升仍成立，但“二次验证能补救 FPR”被否定 |
| 动态 12 个单元不可观测 | 故障注入 + `nogobal` 使 12/12 有证据，140/140 可操作 | 修复闭环的“不可观测”限制被部分解除；仍无覆盖率 instrumentation |
| 证据混合 97.1% | 增强动态证据 97.86%/97.14%，$+2/0$ 不显著 | 不作为证据有效的证据；工具满分使“抄证据”不可排除 |
| schema invalid 11.0% 是限制 | 93/102 只缺 explanation；usable +7.25 pp | 保留限制，但明确 schema 不是修复质量主矛盾 |
| 静态基线只有 Clang/Cppcheck | CodeQL 召回 97.1%、23 FP、42.5 s/单元 | 新增工具对照；MCC 0.674 低于 Clang 0.781，不是替代品 |

---

## 9. 复现

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 1) 配对去偏：结果已落盘；重跑必须使用新 run 目录
cat pair_debias/results/summary.md

# 2) 二次验证
python3 evidence_verify/selftest.py
bash evidence_verify/run_verify.sh deepseek_self test
bash evidence_verify/run_verify.sh deepseek_cross test
bash evidence_verify/run_verify.sh mimo_self test
bash evidence_verify/run_verify.sh mimo_cross test
python3 evidence_verify/analyze.py

# 3) 动态增强
cd dynamic_enhanced
python3 run_dynamic_enhanced.py selftest
python3 run_dynamic_enhanced.py run --run-id <new_run_id> --jobs 8
python3 run_dynamic_enhanced.py report --run-dir runs/<new_run_id>
python3 run_dynamic_enhanced.py verify --run-dir runs/<new_run_id>
cd ..

# 4) 增强混合
cat hybrid_dynamic_enhanced/REPORT.md

# 5) CodeQL（需要 ~/tools/codeql-2.27.4）
python3 static_extended/codeql_adapter.py \
  --units juliet/subset_units.jsonl --juliet-root juliet \
  --out static_extended/runs/<new_run_id> \
  --codeql ~/tools/codeql-2.27.4/codeql/codeql --jobs 6 --timeout 600
python3 static_extended/compare_test140.py \
  --units juliet/subset_units.jsonl \
  --baseline traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl \
  --codeql-run static_extended/runs/<new_run_id> \
  --out static_extended/runs/<new_run_id>/comparison_test140.json

# 6) schema 复分析（零 API）
python3 analysis/schema_recovery/recover.py --check
python3 analysis/schema_recovery/recover.py --selftest

# 7) 报告编译与检查
~/tools/tectonic/tectonic -X compile report/report_latest_zh.tex \
  --outdir report --keep-logs
pdfinfo report/report_latest_zh.pdf
pdffonts report/report_latest_zh.pdf
```

编译检查结果见 `report/README.md`。

---

## 10. 限制与不能声称的事

1. **全部为单次运行**：没有多 seed，不能估计 run-to-run 方差；除明确说明的 Holm 族外，没有全局多重比较校正。
2. **配对去偏**：长度匹配与位置检验是事后诊断；开放与强制是不同任务；交换一致 DA 只覆盖两个顺序，不能排除更复杂的顺序×内容交互。
3. **二次验证**：事后设计，不是独立确认；只有 32 个负例；验证器只看函数体；`refutation-only` 规则没有预注册。
4. **动态增强**：单路径、无覆盖率、`realloc_fail` 只覆盖第一次非 NULL 失败、`nogobal` 是全局开关、Valgrind 未重跑；`clean` 不是无泄漏证明。
5. **增强混合**：工具满分使准确率无法区分“抄证据”与“推理”；基线是历史运行；只有 140 单元。
6. **CodeQL**：每单元单独建库，时间含建库开销；查询版本与编译器口径固定；按冻结标签计分。
7. **schema**：结构检查是词法代理，不是 parser/compiler；usable 是 L0，没有编译、测试、PoC 或人工评审。
8. **不能写**：“配对能力 86.7%”“二次验证提升检测”“动态检测 100%”“证据混合显著提升”“schema 修复解决修复质量”“CodeQL 优于 Clang”。这些都不被数据支持。

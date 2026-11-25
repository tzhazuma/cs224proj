# CodeQL + LLM 告警分流：主报告

**范围**：`codeql_triage/`。冻结 Juliet CWE-401 test 140；CodeQL 200 结果中的 test 部分；`juliet_llm` 清洗视图。  
**日期**：2026-11-22。**模型**：MiMo `mimo-v2.6-flash`（Xiaomi 官方端点）完成；DeepSeek 因凭证/余额阻塞，无结果。  
**合规**：WSL、真实 API、逐样本落盘、缓存、无 git/gh、密钥不入库。

---

## 1. 一句话结论

在 140 个单元上，**CodeQL 的 23 个 FP 可以靠“所有权/释放路径”提示被 LLM 撤销，但一次性提示很脆弱**：v1 撤销 18 个 FP 的同时误删 7 个 TP；把 `realloc` 失败路径和字段极性写清楚后，v2 做到 **0 TP 误删、20/23 FP 撤销**；再用模型自己的理由做一致性检查，达到 **68 TP / 0 FP / 70 TN / 2 FN，macro-F1 0.9857、MCC 0.9718**。  
但**这不是对 direct LLM 的显著胜利**：vs direct 的 macro-F1 只 +0.0286，95% CI 跨 0（p=0.289）。显著优势是对 CodeQL（+0.1684，p<1e-6）。DeepSeek 没有可用凭证，不能给出对应数字。

---

## 2. 实验设计

### 2.1 数据

| 项 | 值 |
| --- | --- |
| 单元 | 140（70 bad / 70 good；C 58 / C++ 82） |
| CodeQL 可分析 | 136/140 |
| CodeQL 混淆 | 68 TP / 23 FP / 47 TN / 2 FN |
| 23 FP | 全部 C++ good，全部 `cpp/memory-may-not-be-freed` |
| 4 compile_error | `_82` 的 `new_twoIntsStruct` / `new_wchar_t`，bad+good 各 2 |
| 2 CodeQL FN | 正是其中 2 个 `_82__bad` |

### 2.2 三种提示

1. **direct**：`juliet_llm` 的原始 zero-shot 提示（只给清洗源码，输出 `vulnerable/not_vulnerable`）。
2. **triage v1**：给 CodeQL 状态/告警行 + 清洗源码；要求输出 `alert_verdict`、`leak_present` 和 5 个证据字段（allocation、ownership、aliasing、global_control_flow、cross_function_release）。
3. **triage v2**：同 v1，但：
   - 先判 `leak_present`，再判 `alert_verdict`；
   - 显式规定 `p = realloc(p, n)` 失败会丢失旧块，是可行路径上的泄漏；
   - 显式禁止“有告警就 `true_positive`”；
   - 要求“若所有堆分配在每条可行路径都被释放，`leak_present` 必须为 false”；
   - 返回前自检两个字段的一致性。

### 2.3 策略

- **`triage_keep`**：有告警时，只有显式 `false_positive` 才撤销；`uncertain`/无效/无告警保留 CodeQL。
- **`triage_verified`**：在 91 个告警上做二次复核，只有复核说 `false_positive` 才撤销。
- **`rule_text_consistency`**：零额外 API，用首轮理由中的“no heap leak / released on every path / false positive”等标记修正自相矛盾。
- **`hybrid_cascade_direct`**：有告警走复核，无告警走 direct；只用于操作点对照。
- 所有指标在 140 上端到端计算；compile_error 按“未报泄漏”计，但单列。

### 2.4 统计

- 10,000 次 percentile bootstrap（配对、种子 42）给 macro-F1 差的 95% CI。
- 精确 McNemar（双侧）比较配对二分类。
- 报告 P/R/F1(V)/macro-F1/MCC/coverage；不把 positive-class F1 和 macro-F1 混用。

---

## 3. 主结果

| 策略 | TP | FP | TN | FN | P | R | macro-F1 | MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 68 | 23 | 47 | 2 | 0.7473 | 0.9714 | 0.8173 | 0.6739 |
| direct LLM | 69 | 5 | 65 | 1 | 0.9324 | 0.9857 | 0.9571 | 0.9158 |
| triage v1 一次性 | 61 | 5 | 65 | 9 | 0.9242 | 0.8714 | 0.8999 | 0.8013 |
| triage v2 一次性 | 68 | 3 | 67 | 2 | 0.9577 | 0.9714 | 0.9643 | 0.9287 |
| **v2 + 复核（最终）** | **68** | **0** | **70** | **2** | **1.0000** | **0.9714** | **0.9857** | **0.9718** |
| v2 + 文本一致性（零额外 API） | 68 | 0 | 70 | 2 | 1.0000 | 0.9714 | 0.9857 | 0.9718 |
| cascade（告警复核 + 无告警 direct） | 70 | 2 | 68 | 0 | 0.9722 | 1.0000 | 0.9857 | 0.9718 |
| 丢弃 C++ `may-not-be-freed` | 60 | 0 | 70 | 10 | 1.0000 | 0.8571 | 0.9282 | 0.8660 |
| 只保留 `never-freed` | 46 | 0 | 70 | 24 | 1.0000 | 0.6571 | 0.8234 | 0.6995 |

### 3.1 显著性

| 比较 | Δmacro-F1 | bootstrap 95% CI | McNemar p |
| --- | ---: | --- | ---: |
| 最终 vs CodeQL | +0.1684 | [+0.1084, +0.2349] | <1e-6 |
| 最终 vs direct | +0.0286 | [-0.0072, +0.0714] | 0.289 |
| 最终 vs v2 一次性 | +0.0214 | [0.0000, +0.0500] | 0.25 |
| v2 一次性 vs CodeQL | +0.1470 | [+0.0908, +0.2097] | 2e-6 |
| direct vs CodeQL | +0.1398 | [+0.0738, +0.2110] | 1.57e-4 |

**读法**：v2/最终相对 CodeQL 的提升是稳健的；相对 direct 的提升只有 3 个样本的差别，不显著。任何“LLM triage 优于 direct”的强结论都不成立。

### 3.1.1 direct 复现差异（必须披露）

本次 fresh direct 是 **69 TP / 5 FP / 65 TN / 1 FN**（macro-F1 0.9571、MCC 0.9158）；既有 `juliet_llm` postleakfix MiMo 是 **68 / 5 / 65 / 2**（macro-F1 0.9500、MCC 0.9008）。唯一差异是 `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad` 本次被判为泄漏。  
同模型 ID、同 Xiaomi 官方端点，仍可能因 provider 版本/路由或单次采样产生 1 个样本的漂移；不能把这点归因于本目录的提示。主表用同一 run 的 fresh direct 作对照，既有 run 仅作复现参考。严格估计方差需要重复采样。

### 3.2 覆盖

- CodeQL 136/140（0.9714）。
- triage API 140/140（其中 2 条原始输出把“无告警”写成 `uncertain`，按澄清规则重解析；原始有效 138/140）。
- direct 140/140。
- 91 个告警的复核 91/91。

---

## 4. 23 个 CodeQL FP：逐类分析

| 模式 | 数量 | 机制 | v1 撤销 | v2 撤销 | 最终撤销 | direct 正确 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| `_33` | 15 | 引用 + 内层同名遮蔽；`dataRef` 指向堆；另一个函数用 `ALLOCA` 栈路径；free 在 alias 上 | 14 | 15 | 15 | 15 |
| `_22` | 3 | 全局 `sym_1/sym_2` 在调用前赋值，callee 的 `if` 决定 `delete`；需要跨函数全局控制流 | 0 | 0 | 3 | 0 |
| `_72` | 3 | `new` 指针插入 `vector`，在另一个文件的 callee 取 `dataVector[2]` 后 `delete` | 3 | 3 | 3 | 3 |
| `_54` | 2 | 五层 wrapper 链，最终 `delete` 在最后一层 | 1 | 2 | 2 | 2 |
| 合计 | 23 | | 18 | 20 | 23 | 20 |

### 4.1 v1 为什么只撤销 18 个

- 15 个 `_33` 里撤销 14 个；`char_realloc_33__good` 被标 `true_positive`，但理由又说 `ALLOCA` 是栈、`realloc` 被 alias free——字段矛盾。
- `_54` 的 `new_twoIntsStruct_54__good` 同样：理由说“released via delete in sym_12”，但 `alert_verdict=true_positive`。
- 3 个 `_22` 全部保留：模型能把 `sym_1=0 → sym_4 delete`、`sym_2=1 → sym_6 delete` 推对，但 `leak_present=true` / `alert_verdict=true_positive` 与理由相反。

### 4.2 v2 为什么是 20/23

- v2 的字段顺序和自检修掉了 `_33` 的 1 个、`_54` 的 1 个矛盾，`_33`/`_72`/`_54` 全部撤销。
- 3 个 `_22` 仍然自相矛盾：理由明确写“all heap allocations released / alerts are false positives”，字段却是 `true_positive/true`。
- 这不是所有权推理失败，而是**输出极性错误**。二次复核或文本一致性规则都能修掉，且不碰任何 TP。

### 4.3 与 direct 的关系

- direct 在 23 个 FP 上对 20 个；错 3 个，正好是 3 个 `_22`。
- direct 另有 2 个 FP 不在 CodeQL 告警里：`int_malloc_22__good`、`twoIntsStruct_realloc_22__good`。
- 所以 direct 的 5 个 FP = 3 个 CodeQL FP + 2 个 CodeQL TN；triage 最终把这 5 个都处理掉了（3 个靠撤销，2 个本来就不在告警里）。

---

## 5. TP 误删

| 版本 | 删除的 CodeQL TP | 比例 | 具体 |
| --- | ---: | ---: | --- |
| v1 | 7/68 | 10.29% | 全部 `malloc_realloc_*` 的 `may-not-be-freed` |
| v2 | 0/68 | 0% | — |
| 最终 | 0/68 | 0% | — |

v1 的 7 条理由都把 `realloc` 失败路径判为“不可行/非正常路径”，例如：

> “If realloc fails, original block is leaked, but realloc failure is not a feasible normal path here.”

这与 `juliet_llm` 原始定义（“memory that leaks only on some paths, for example when a reallocation fails” 也算泄漏）直接冲突。v2 显式加入 `p = realloc(p, n)` 失败语义后，7 条全部保留，0 误删。

**这是本实验最重要的方法学结果**：TP 误删不是“模型不够聪明”，而是提示没有把任务定义中的边界条件说清楚；用函数长度/文件名当然也不行，但仅禁这两项还不够。

---

## 6. 与 direct LLM 的关系

| 维度 | direct | triage 最终 |
| --- | --- | --- |
| 68 个 CodeQL TP | 67 保留（漏 `malloc_realloc_int64_t_18__bad`） | 68 保留 |
| 23 个 CodeQL FP | 20 正确拒绝，3 个 `_22` 误报 | 23 全部撤销 |
| CodeQL TN 中的 direct FP | 2 个（`int_malloc_22`、`twoIntsStruct_realloc_22`） | 0 |
| 2 个 compile_error bad | 2 个都抓到 | 0（没有告警可分流） |
| 其余 2 个 compile_error good | 2 个都拒绝 | 2 个都拒绝 |
| macro-F1 / MCC | 0.9571 / 0.9158 | 0.9857 / 0.9718 |

**互补性**：
- CodeQL 的 2 个 FN 是 compile_error，triage 看不见；direct 能读源码，所以抓到。
- direct 的 1 个 FN 是 realloc bad，triage 有 CodeQL 告警，所以保留。
- 两者错误集合不同；cascade（告警走 triage，无告警走 direct）得到 70 TP/2 FP/68 TN/0 FN，macro-F1 仍 0.9857，MCC 0.9718，与 triage 最终同分但操作点不同（多 2 TP、多 2 FP）。

**不能说的**：
- 不能说“triage 比 direct 强 2.9 个点”——p=0.289。
- 不能说“CodeQL+LLM 解决了 compile_error”——triage 没解决，cascade 只是绕过。
- 不能说“91/91 复核证明模型会做所有权分析”——复核看得到首轮答案，存在锚定；文本规则同样 91/91，说明它主要在修矛盾。

---

## 7. 成本

配置价，非发票：

| 条件 | 请求 | 成本 USD | p50 / p95 |
| --- | ---: | ---: | --- |
| direct | 140 | 0.00302 | 2.83 / 5.73 s |
| triage v2 | 140 | 0.03054 | 6.91 / 14.20 s |
| verify（可选） | 91 | 0.01223 | 3.80 / 6.49 s |

- direct + triage v2 + 文本规则：**$0.03356 / 140**（$0.00024/单元；$0.00037/告警；$0.00146/撤销 FP；$0.00049/保留 TP）。
- direct + triage v2 + 二次复核：**$0.04579**；多花 $0.01223，最终决策与文本规则**完全相同**。
- CodeQL：test 140 逐单元时长之和 6,061.8 s，均值 43.3 s；无 API 费，但有建库/算力成本。
- 端到端墙钟：v2 280 条请求并发 6，264.0 s；v1 253.1 s。

**成本结论**：如果只看“撤销 FP”，二次 LLM 复核的边际收益为 0；真正值钱的是首轮的证据字段 + 一个零成本一致性检查。若要把复核用于审计/可解释性，才值得多花 $0.0122。

---

## 8. 文献定位

### 8.1 LLM + 静态分析

- **IRIS**（Li et al., arXiv 2405.17238）：LLM 推断 taint 规格 + 静态分析做 whole-repo Java；CodeQL 27/120 → IRIS 55/120，FDR 改善 5pp。说明“LLM 补静态分析的规格/上下文”可行，但对象是 Java 全仓库，不是 C++ 单 TU 告警分流。
- **LLift**（Li et al., arXiv 2308.00245）：LLM 作为 use-before-init 告警的过滤器，~1000 条告警上 precision 50%、无明显漏报；强调 LLM 适合“辅助”而不是替代静态分析。
- **LLMPFA**（Du et al., arXiv 2601.18844）：Tencent 工业 433 条告警，LLM/混合方法消除 94–98% FP，$0.0011–$0.12/告警、2.1–109.5 s；给出成本量级。我们的 $0.00037/告警、$0.00146/撤销 FP 与之一致。
- **Alert adjudication**（Klieber et al., arXiv 2607.09979）：在 Juliet/FormAI/SV-COMP 上做 LLM 告警裁决；一致性检查后 ≥98% recall、≥94.8% specificity；同时警告 o4-mini 能重建清洗后的 Juliet 身份，泛化结论应主要看 FormAI。这直接支持我们的“Juliet 记忆化”限制。
- **Evident**（Li et al., arXiv 2606.15122）：LLM 生成 harness + Frama-C/Eva 精确排除；LLM 直接做最终裁决的 baseline 会漏 27.5–45.0% confirmed bug，而 harness 方法在 200 个 Android kernel-driver 告警上过滤 48.8–63.8% FP 且不漏 confirmed bug。**这是“TP 误删”最重要的外部证据**：LLM 最终裁决不安全，必须给“不能撤销”的硬约束或外部见证。
- **MemHint**（Huang et al., arXiv 2603.27224）：LLM 识别 allocator/deallocator + 所有权参数，Z3 验证路径可行性，注入 CodeQL/Infer；3.6M LOC 上 54 个泄漏 vs CodeQL 19。说明 `_22`/`_54`/`_72` 这类跨函数所有权，最好在分析器层补 summary，而不是只在告警后做文本 triage。

### 8.2 内存泄漏/所有权静态分析

- **Heine & Lam, PLDI 2003**：flow/context-sensitive 的 C/C++ 泄漏检测，所有权模型；正是 `_33` 的 alias/shadow 场景。
- **Sui et al., ISSTA 2012**：full-sparse value-flow 泄漏检测；跨函数 value-flow 是 `_54`/`_72` 的核心。
- **QL/CodeQL**（Avgustinov et al., ECOOP 2016）：QL 是 Datalog 风格的关系查询；`may-not-be-freed` 是保守查询，FP 是设计代价，不是 bug。
- **Juliet 1.3 / NIST SARD**：合成 CWE-401；标签由 `OMITBAD`/`OMITGOOD` 宏门控；NIST TN 1995 也说明 Juliet 自身有已知问题。合成集适合受控比较，不适合直接外推真实项目。
- **SecVulEval**（Ahmed et al., arXiv 2505.19828）：真实 C/C++ 函数级/语句级 benchmark；与本项目 Tier A 对应。它的存在提醒我们：Juliet 的结论不能替代真实项目。

### 8.3 与本实验的关系

- 我们的“所有权/别名/全局/跨函数”四类证据，对应 IRIS/LLift 的“让 LLM 补上下文”，但对象是**告警后分流**，不是全仓库检测。
- 我们的 TP 误删结果，与 Evident 的“LLM 最终裁决会漏 confirmed bug”一致；我们的 v1 就是这种失败模式，v2 用任务定义约束把它修掉。
- 我们的 `_22` 残留，说明仅靠告警后文本推理不够；MemHint 式的函数 summary/路径可行性是更根本的修法。
- 我们的 23 FP 全是 C++ `may-not-be-freed`，说明 query-aware prior 很强；LLM 必须先超过零成本规则，才有资格谈“推理”。

---

## 9. 现有 benchmark 的欠缺

详见 `GAP_ANALYSIS.md`，这里列最关键的 8 条：

1. **没有 triage 基线**：父层比较了 CodeQL、Clang、Cppcheck、direct LLM，但没有“CodeQL 告警 + LLM 分流”这一行；也没有 TP 误删、FP 撤销率、每告警成本。
2. **compile_error 处理不够显式**：CodeQL 4 个 compile_error 在端到端被计为负例；如果不单列，会把“工具不能分析”误读成“工具判对/判错”。本目录单列了 4 个，并指出 2 个 bad 是 CodeQL FN、LLM 能读。
3. **23 FP 的结构先验太强**：全是 C++ good、全是 `may-not-be-freed`；`drop C++ may-not-be-freed` 就有 P=1.0、R=0.857。任何 LLM 方法不先打这个基线，数字没有解释力。
4. **Juliet 记忆化**：清洗去掉标签/路径/名字，但结构、宏展开后的控制流、`printLine` 序列仍在；文献已报告 LLM 能重建身份。91/91 的复核不能当作真实泛化。
5. **标签是宏标签，不是人评**：`bad/good` 由 Juliet 的 `OMITBAD`/`OMITGOOD` 唯一决定；没有独立的人对“所有权/释放路径”做 ground truth。
6. **单次采样、temperature 0**：没有重复采样、没有置信区间覆盖模型方差；置信度字段没有校准（ECE）。
7. **成本口径**：父层有 token/价格，但没有“每撤销一个 FP 的成本”“每保留一个 TP 的成本”“人类复核节省的时间”；CodeQL 算力也没有折成钱。
8. **没有真实项目/CWE 泛化**：只 CWE-401、只 Juliet；`_22`/`_54`/`_72` 的模式在真实代码里长得多，单 TU 近似会改变 FP 结构。

---

## 10. 改进 idea（可检验）

详见 `IDEAS.md`。按“性价比”排序：

1. **单字段 schema + 派生告警判决**（最高优先级）
   只让模型输出 `leak_present` + `release_gap`（具体分配/路径），`alert_verdict` 由代码派生：有告警且 leak=true → TP；leak=false → FP；uncertain → uncertain。这样从结构上消灭 `_22` 的“理由说无泄漏、字段说 TP”矛盾。预期：v2 的 3 个残留 FP 直接消失，不需要第二次 API。实验：140 条，成本 ~$0.03，比较 TP 误删/FP 撤销。

2. **Release-witness gating**
   只有模型给出“具体 free/delete 表达式 + 到达它的路径”时才允许撤销；否则 `uncertain`/保留。把“unsupported”从软提示变成硬门控。预期：进一步降低 TP 误删；代价是 FP 撤销率下降。实验：在 23 FP + 68 TP 上做 2×2（有/无门控）。

3. **Query-aware / language-aware prior**
   把 `never-freed` 当高精度、`may-not-be-freed` 当低精度；在 C++ 上先验更保守。与 LLM 做 stacking：LLM 只在“query prior 不确定”的子集上调用。预期：用更少调用达到同样 P/R；实验：按 query/language 分层，报告每层成本和 TP 误删。

4. **Cascade：CodeQL 告警 → triage；无告警 → direct/动态**
   本实验已做：70 TP/2 FP/68 TN/0 FN，macro-F1 与 68/0/70/2 相同，但操作点不同。下一步：无告警时用 LSan/Valgrind 或 direct，量化“补召回”的 FP 代价；在真实项目上验证是否仍成立。

5. **动态见证（LSan + 故障注入）**
   对模型想撤销的告警，编译并跑 LSan；只有“观察到无泄漏”才撤销。对 `realloc` 失败路径做故障注入（本项目的 `dynamic_enhanced` 已有基础）。预期：把“文本推理”变成“可复核证据”；成本是编译/运行时间。

6. **Ownership summary + Z3 路径可行性（MemHint 式）**
   让 LLM 为每个函数生成 alloc/free/ownership-transfer summary，Z3 检查 CFG 可行性，再注入 CodeQL 查询。预期：从分析器层修 `_22`/`_54`/`_72`，而不是告警后补救；实验：在 200 单元上比较 CodeQL vs CodeQL+summary 的 P/R/MCC。

7. **记忆化对照**
   对 Juliet 做结构变异（交换分支、改调用深度、改容器类型、改宏展开），或用 FormAI/SV-COMP/真实项目；比较 v2 的增益是否消失。预期：如果 91/91 主要来自记忆，变异后 TP 误删/FP 撤销会显著变化。

8. **跨模型集成**
   DeepSeek + MiMo 各自 triage；一致时采纳，不一致时 `uncertain`/人审。DeepSeek 当前阻塞，代码已支持；凭证恢复后直接跑同一 v2。预期：降低单模型极性错误；代价是 2× 成本。

9. **成本感知的 utility**
   定义 `U = λ_FP * 撤销FP数 - λ_TP * 误删TP数 - cost`；报告不同 λ 下的最优策略/操作点。当前数据可离线重算，不需要新 API。

10. **人审模拟**
    把 `uncertain`/矛盾样本路由给人，统计“减少多少告警、增加多少误删、节省多少分钟”；用 LLMPFA 的 10–20 min/告警做外部参照，但不伪造人评。

---

## 11. 限制（必须与结果一起读）

1. **DeepSeek 无结果**：401/402/403 全部记录在 `runs/blocked_*`；不能用 MiMo 数字代替。
2. **最终 vs direct 不显著**：+0.0286，CI 跨 0，p=0.289；只有 vs CodeQL 显著。
3. **复核有锚定**：看得到首轮 JSON；91/91 不是独立盲审。文本规则同分，说明复核主要在修矛盾。
4. **顺序消融**：v2 的 realloc 规则是在 v1 看到 7 个误删后加的；verify/text rule 是在 v2 看到 3 个残留后加的。应作为错误分析驱动的提示迭代报告，不是预注册的单一方法。
5. **Juliet 记忆化**：清洗不改变结构；文献已警告。
6. **23 FP 先验强**：全 C++ `may-not-be-freed`；零成本规则已很强。
7. **2 个 FN 是 compile_error**：triage 无法恢复；cascade 只是绕过，且引入 2 FP。
8. **单模型/单采样/无校准**：没有方差、ECE、人评。
9. **成本是配置价**：不是发票；无人类复核成本、无 CodeQL 算力折价。
10. **证据字段未逐条人工核验**：只有最终标签可核。
11. **只一个 CWE、只 Juliet**：不能外推到真实项目或其它 CWE。

---

## 12. 交付物

- 代码：`common.py`、`run_triage.py`、`verify.py`、`analyze.py`、`selftest.py`、两个 credential wrapper。
- 结果：`runs/test140_mimo_xiaomi_v1/`、`runs/test140_mimo_xiaomi_v2/`、`runs/blocked_deepseek_*`。
- 报告：`README.md`、`REPORT.md`、`LITERATURE.md`、`GAP_ANALYSIS.md`、`IDEAS.md`、`HANDOFF.md`。
- 机器可读：`benchmark_export.json`。

没有执行 git/gh，没有 push；父层可只读导入 `benchmark_export.json` 或直接引用 `runs/*/analysis/summary.json`。

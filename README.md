# SecVulEval + Juliet：分层漏洞检测与修复评测

本仓库是 CS224 课程项目的**真实实验产物、评测协议与复现材料**。项目把两类漏洞评测放在同一套契约下，但**分层报告、绝不跨层合并**：

| 层级 | 数据集 | 评什么 | 主终点 |
| --- | --- | --- | --- |
| **Tier A** | SecVulEval 真实项目 C/C++ 函数 | LLM 在跨 CWE 真实代码上的检测与配对判别 | 检测 `macro-F1`；配对 `DA` |
| **Tier B** | Juliet CWE-401 合成用例 | 静态、动态、LLM、AI+传统工具在同一 CWE 上的比较 | 泄漏 `macro-F1` + `MCC`，强制报告 coverage |

两层的数据来源、标签语义、单元结构、类别先验和成本口径都不同。把 160 个真实函数和 Juliet 变体池化成一个“平均 F1”没有解释力，因此本项目只做**统一契约下的分层比较**。

> 所有报告数字都来自已落盘的运行产物；没有用 mock、fixture 或估计值填充正式结果表。`selftest` 和临时 fixture 只用于工具自检，不是实验结果。
>
> 最终只读审计：[`audit/final_audit.md`](audit/final_audit.md)，**2026-11-11T21:45:48Z 重跑：58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`**。5 个 must-fix 均已关闭：C3/D6 由清洗器 prompt `.2` 与 `hybrid_v2` 修复，I3 的 repair all-in 改为 `$0.082550`，I5 按峰谷价 + `normalized` 口径解释，L4 的 `analysis/aggregation.json` 已用仓库内路径重生成；新增的 L5（v1 泄漏对照保留）与 I7（normalized 成本账）也通过。3 个 WARN（B5/D5/F4）见 §8。

---

## 1. 项目解决什么问题

漏洞检测论文里的数字经常不可比：同一模型在不同论文中使用不同的测试集、不同的分母、不同的失败处理方式；LLM 的“修复”常常只检查 JSON 是否能解析，传统工具的“clean”也常被当成安全证明。本项目的工作分为三部分：

1. **建立可审计的评测契约**：冻结 split、标签泄漏审计、strict / valid-only 双口径、coverage、失败保留、cluster bootstrap、McNemar + Holm、成本与延迟分开报告。
2. **在两层数据上做真实实验**：Tier A 比较 2 个模型 × 3 种提示策略 × 2 个任务；Tier B 比较 Clang/Cppcheck、ASan/LSan、Valgrind，以及独立的 LLM/混合/修复实验。
3. **把“看起来很大的收益”拆成可检验的成分**：联合 A/B 的增益有多少来自强制二选一和长度？证据行提示是提高判别力还是只移动操作点？工具证据在 96% 天花板下还有多少空间？修复的 100% 是否只是“可观测子集”的上限？

第 3 部分是本项目最有区分度的部分：它给出的是**收益分解与负结果**，不是又一个 SOTA 声明。

### 一句话结论

- Tier A 上，DeepSeek V4.1 Flash 的检测 `macro-F1` 点估计高于 MiMo-V2.6-Flash（0.383/0.399/0.381 vs 0.346/0.346/0.365），但**所有模型比较经 Holm 校正后都不显著**；配对 `DA` 只有 8.9%–12.2%，远低于随机指定一侧的 56.1%。
- Tier B test 140 上，Clang SA 的 `macro-F1` 为 0.888、ASan/Valgrind 为 0.914、Cppcheck 为 0.588；**动态 clean 不是 TN**，Clang 的 4 个编译失败也从未写成 `y_pred=0`。
- 联合 A/B 把配对 `DA` 从 11.67%/7.78% 提升到 76.67%/86.67%，但“选较短版本”的长度启发式单独就有 74.44%；DeepSeek 与长度启发式不可区分（p=0.6587），只有 MiMo 显著高于它（p=0.0003）。
- 证据行提示显著提高召回（+9.45/+10.92 pp，Holm p=0.0055/0.0010），但 FPR 同向上升、BA/MCC 不升；证据行的 ±3 命中率接近随机。
- 工具证据在泄漏修复后的 `hybrid_v2` 上没有复现 v1 的提升：DeepSeek direct 135/140 → combined 136/140（+1，McNemar p=1），MiMo 136/140 → 136/140（0，p=1）；v1 的 140/140 在 v2 回落到 136/140。**不能宣称工具证据有效**。
- 修复在 58 个 LSan 可观测 bad 单元上 58/58；全 70 的 strict 是 58/70，12 个单元是“不可评估”，不是“通过”。

---

## 2. 两个层级与数据

### 2.1 Tier A：SecVulEval

上游 `SecVulEval.xlsx` 包含 5,867 个 CVE、10,998 个漏洞函数和 14,442 个非漏洞函数，带语句级修复信息和上下文。本项目从 `train` 工作表抽取并冻结：

- `datasets/independent_200.json`：200 条函数（160 漏洞 + 40 非漏洞），用于独立检测。
- `datasets/vulnerable_fixed_200_pairs.json`：200 对漏洞/修复版本，用于配对判别与修复。
- `splits/`：按项目、CWE 家族和长度分层的冻结划分。测试集为 **160 条检测函数**（128 V / 32 NV，40 个项目）和 **180 对**（360 个函数，60 个项目）；开发集只用于固定示例和 pilot，不进入测试结论。

三种提示策略：

| 策略 | 模型输入 | 作用 |
| --- | --- | --- |
| `direct` | 仅函数源码 | 零样本基线 |
| `few-shot` | 开发集示例 + 函数源码 | 少样本基线 |
| `context` | 函数源码 + 白名单清洗后的上下文 | 上下文增强（存在数据伪影，见 §8） |

两个任务：`detection` 输出 `is_vulnerable`；`repair` 输出完整替换函数。`both` 在同一 run 中同时做检测和修复。模型请求不包含标签、`fixed_func_idx`、`changed_lines`、CWE/CVE、项目/文件/函数名等字段。

### 2.2 Tier B：Juliet CWE-401

从 NIST SARD 官方 Juliet Test Suite for C/C++ v1.3 中提取 CWE-401（Memory Leak），构建 **`juliet-cwe401-v1.3-subset-v1`**：

- 200 个冻结单元（100 bad / 100 good），100 个测试用例组，42 个功能家族。
- dev 60 / test 140；C 88 / C++ 112。
- 标签由 Juliet 的 `OMITBAD`/`OMITGOOD` 宏门控唯一决定，并用符号门控和 ASan/LSan 运行佐证；**没有因为运行时观察不到泄漏而改标签**。
- 近重复控制：按 5-gram Jaccard 的连通分量整簇划分，跨 split 最大 Jaccard 0.8231，≥0.85 的违规为 0。
- 上游归档 SHA-256：`ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`；归档和逐文件哈希在 `juliet/provenance.json`、`juliet/SHA256SUMS`、`juliet/FREEZE.json` 中。

Tier B 的传统方法：

- **静态**：Clang Static Analyzer 22.1.8、Cppcheck 2.21.0；`compile_error` 保留为非 ok，不写成负例。
- **动态**：ASan/LSan + Valgrind 3.27.1，全量 3,316 个 case；`clean` 只表示“执行路径上未观察到 definite/indirect leak”，不是安全证明。
- **LLM/混合**：`juliet_llm/`、`hybrid/`、`juliet_repair/` 是独立探索性实验。`benchmark/` 当前状态：B5（MiMo Juliet LLM，Xiaomi fallback）、B6（static evidence）、B7（dynamic evidence）、B11/B12 已 `done_frozen`；B4（DeepSeek Juliet LLM）无结果，B8（cascade）未做，B9 仍为 `partial`（sanitizer/prompt 审计 200/200 通过，label-only baseline 未跑）。`benchmark/results/LEADERBOARD.md`（2026-11-11T21:31:43Z）已把 **hybrid_v2** 与 **juliet_llm postleakfix** 作为 Tier B 主行，`hybrid_v1` / pre-leakfix 只作为泄漏对照、不出现在主表；LLM/混合数字仍必须带 B9 caveat。

### 2.3 创新与诊断实验

| 目录 | 实验 | 回答的问题 |
| --- | --- | --- |
| `pair_joint/` | 联合 A/B 强制二选一 | 把两个版本放在一次请求里，配对判别能提升多少？多少来自长度/位置？ |
| `evidence_prompt/` | 证据行 + 机制 + 反事实修复 | 结构化提示提高的是判别力，还是只把操作点推向“多报”？证据行能定位吗？ |
| `hybrid/`（v2 主结果） | 静态/动态/组合/安慰剂证据 | 工具证据在 Juliet 140 上有没有超出格式/长度安慰剂的边际收益？ |
| `juliet_repair/` | 编译 + LSan + 行为差分 | 模型补丁是否真的编译、消除泄漏、保持可观测行为？ |
| `juliet_llm/` | Juliet LLM 直接二分类 | 在去标签、去路径、去 CWE 的源码视图上，LLM 能检测 CWE-401 吗？ |
| `repair_eval/` | 修复质量盲评 | 在固定 rubric 下，LLM 辅助评审认为补丁处理了根因吗？ |

---

## 3. 核心结果

### 3.1 Tier A：SecVulEval 检测与配对

来源：`runner/runs/test_v1_*`（DeepSeek）与 `runner/runs/test_v1_mimo_*`（MiMo），每个模型 6 个 run、2,484 次请求（含 308 次 repair 请求，repair 不计入检测分数）。统一指标由 `benchmark/tools/bench_metrics.py` 重算，比较由 `bench_compare.py` 生成。

| 模型 | 策略 | 检测 macro-F1 | 配对 DA | 检测 coverage | 两 run 总 USD（configured，含 repair） |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek V4.1 Flash | direct | 0.383 | 0.117 | 1.000 | 0.645585 |
| DeepSeek V4.1 Flash | few-shot | 0.399 | 0.089 | 1.000 | 1.131383 |
| DeepSeek V4.1 Flash | context | 0.381 | 0.122 | 1.000 | 0.662251 |
| MiMo-V2.6-Flash | direct | 0.346 | 0.091 | 0.938 | 0.186884 |
| MiMo-V2.6-Flash | few-shot | 0.346 | 0.094 | 1.000 | 0.244105 |
| MiMo-V2.6-Flash | context | 0.365 | 0.114 | 0.956 | 0.192166 |

检测分母 160（128 V / 32 NV）；配对分母 180。读法：

- **没有稳健的模型赢家。** 6 个同策略/同任务比较经 Holm 后，McNemar 均不显著。few-shot 的 `Δmacro-F1` 为 +5.3 pp，bootstrap CI `[+1.0, +12.9]` pp，但原始 McNemar p=0.078、Holm p=0.235；不能据此宣称 DeepSeek 稳定更好。
- **MiMo 的 coverage 损失主要来自字段漂移。** direct/context 检测 coverage 为 93.8%/95.6%，61 条 `is_vulnerability` 键名漂移；DeepSeek 三个检测 run 的 coverage 都是 100%。
- **成本差异主要是单价，不是 token 效率。** 运行记录为 DeepSeek $2.439219、MiMo $0.623154；按 cache-aware 公式、同一 configured 价卡重算为 $1.899 vs $0.623（3.05×），token 总量只差 7.4%。记录值与重算值的差异部分来自 DeepSeek 的 cached token 未扣减。DeepSeek 的 $0.30/$1.20 是**高峰价**，provider `list_cost` 的 $0.15/$0.60 是**非高峰价**；本批请求全部落在非高峰窗口，0.5× 是峰谷价差而不是 allowance 折扣（详见 §3.1.1）。USD 列不是账单，allowance 是 provider 额度扣减，单独记录。
- **配对 DA 很低。** 主要失败不是“判反”，而是两侧都判安全（DeepSeek direct 113/180，MiMo direct 108/180）。测试集随机指定一侧的双方均正确率为 56.1%（101/180；解析期望 50%）。

#### 3.1.1 成本口径：峰谷价与 normalized

DeepSeek 有两套 list price：`$0.30/$1.20/$0.006`（高峰价，也是 `runner`、`hybrid_v1`、`pair_joint`、`evidence_prompt`、`juliet_repair` 的 configured 价）和 `$0.15/$0.60/$0.003`（非高峰价，provider `usage.opencode.list_cost` 快照）。2026-11-11 的 9,584 条请求全部落在 UTC 非高峰窗口（peak rows = 0），所以 provider 快照恰好是 configured 的 0.5×；**这是峰谷价差，不是 allowance 折扣**。

`analysis/cost_normalization.md` 对 73 个有 usage 的 run 逐条重算（不修改原始 `cost_usd`）：

| 口径 | runs | configured USD | normalized USD | 说明 |
| --- | ---: | ---: | ---: | --- |
| 71 个完整 run | 71 | 3.886970 | 2.146513 | complete-only |
| 73 个 all-recorded | 73 | 3.895167 | 2.154710 | 含 2 个未完成 run |

- normalized 价卡：DeepSeek `$0.15/$0.60/$0.003`，MiMo `$0.14/$0.28/$0.0028` per 1M tokens（输入未缓存 / 输出 / 缓存命中）。
- allowance 是 provider 侧额度扣减（DeepSeek 观测为 list 的 0.600×，MiMo 为 1.000×），不是 USD 账单；它既没有从 list 扣除，也没有加到 configured。
- `hybrid_v2` 及之后的修复重跑已直接配置非高峰价，configured 与 normalized 相同；legacy runner 的 configured 还不扣 cache，不能直接除以 2。
- 引用成本时必须写清口径：`configured`（run 记录值）、`normalized`（统一非高峰价重算）或 `allowance`（provider 额度）。三者不能混用，也不能跨模型直接比 list。

### 3.2 Tier B：Juliet CWE-401 test 140

主分析取冻结 test 140（dev 60 只作参考）。`macro-F1` 是 valid-only；`strict` 把非 ok 记录算错；静态 `compile_error` 从未写成 `y_pred=0`。

| 方法 | 家族 | valid/140 | coverage | macro-F1 | 95% CI | MCC | strict |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: |
| Clang SA 22.1.8 | static | 136 | 0.971 | 0.888 | [0.818, 0.948] | 0.799 | 0.864 |
| Cppcheck 2.21.0 | static | 140 | 1.000 | 0.588 | [0.497, 0.671] | 0.331 | 0.629 |
| ASan+LSan | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 |
| Valgrind 3.27.1 | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 |
| ASan+Valgrind (any) | dynamic | 140 | 1.000 | 0.914 | [0.850, 0.966] | 0.841 | 0.914 |

关键事实：

- **动态 clean 不是 TN。** 该动态 run 没有行/分支覆盖率 instrumentation；clean 只表示“执行路径上未观察到 definite/indirect leak”。leaderboard 同时给 operational（clean 当 TN）和 conservative（clean 弃权，macro-F1 未定义）两个视图。
- **runtime-supported 128（test）**：排除 12 个“标签 bad 但 LSan 未观察到 leak”的 test 单元；ASan 在该子群接近满分有选择效应（子群由 LSan preflight 定义），Valgrind/静态更有信息量。
- **静态有真实编译失败。** Clang 在 test 140 中有 4 个 `_82` 组因共享无 include-guard 头而 `compile_error`；valid-only 排除它们，strict 算错，coverage 单独报告。
- **全量动态 3,316 case**：1,467 TP / 0 FP / 1,658 TN / 190 FN，precision 1.000、recall 0.8853、accuracy 0.9427；190 个 FN 全部可解释（108 个 `malloc_realloc` 需 `realloc` 失败、68 个全局指针 still reachable、14 个随机分支）。
- **Juliet LLM/混合的数字单列，不与静态/动态合并排名。** `benchmark/` 的 B5/B6/B7/B11/B12 已 `done_frozen`，B4（DeepSeek Juliet LLM）无结果，B8 未做，B9 仍为 `partial`（label-only baseline 未跑）。`benchmark/results/LEADERBOARD.md` 已用 **hybrid_v2** 与 **postleakfix** 作为 Tier B 主行；v1/pre-leakfix 仅作泄漏对照，不进入主表。引用时必须带 B9 caveat，不要把 LLM/混合与静态/动态合成一个总排名。

### 3.3 创新与诊断实验（探索性）

| 实验 | 主数字 | 诚实结论 |
| --- | --- | --- |
| 联合 A/B（`pair_joint`） | DeepSeek 138/180 = 76.67%；MiMo 156/180 = 86.67%；长度启发式 134/180 = 74.44% | DeepSeek 与长度启发式不可区分（p=0.6587）；MiMo 显著高于它（p=0.0003）。DeepSeek 还有 31.11 pp 的 A 位置偏差（p=1e-6）。不能写“模型会做跨版本推理”。 |
| 证据行提示（`evidence_prompt`） | 召回 +9.45 pp（Holm p=0.0055）/ +10.92 pp（Holm p=0.0010）；FPR +9.38/+13.79 pp（Holm p=0.25）；BA +0.0004/−0.0143；MCC −0.0020/−0.0276 | 召回显著提高，但主要是操作点向“多报”移动；不能写“判别力提升”或“不增加假阳性”。证据行 ±3 命中率 62.79%/63.64%，随机基线 62.50%/59.66%。 |
| 工具证据（`hybrid`，v2） | DeepSeek direct 135/140 → combined 136/140（+1，McNemar p=1）；MiMo direct 136/140 → combined 136/140（0，p=1）；shuffled 134/140（DeepSeek）、133/140（MiMo） | 泄漏修复后，v1 的 140/140 / 138/140 没有复现；DeepSeek 的 +1 只来自 1 个不一致样本，MiMo 是 1 对 1 互换。不能写“显著提升”或“工具证据有效”。 |
| 修复（`juliet_repair`） | 两个模型 compile 70/70、LSan clean 70/70、behavior 70/70；strict 58/58 可观测；全 70 为 58/70；headline 成本 $0.032831，all-in $0.082550 | 12 个单元在 harness 根集配置下不可观测，不是“修复成功”。没有真实项目编译/PoC，不能写“修复成功率 100%”。 |
| Juliet LLM（`juliet_llm`） | MiMo 140/140 有效，accuracy 0.9500、F1 0.9510、MCC 0.9008（修复后正式/复现相同）；修复前 0.9571 保留 | MiMo 走 Xiaomi 官方端点 fallback，不是 OpenCode Go；修复只改变 1 条预测（`int_malloc_22__good` 由 TN 变 FP）。正式/复现有 2 个 bad 单元不同、混淆矩阵相同，说明服务端非确定性。DeepSeek 因 401/402/403 **没有** Juliet LLM 结果。 |
| 修复盲评（`repair_eval`） | 30 案例 / 81 候选；VR=2 为 17/81（21.0%）；MIN 二次加权 κ=0.015；compile_status 81/81 `NOT_RUN` | LLM 辅助评审，不是人类评审；没有编译/PoC；只能写“在该 rubric 下 17/81 被认为处理了根因”。 |

### 3.4 不能声称的事

- 不能把 Tier A 与 Tier B 的数字放在同一张排行榜，或计算“总体 F1”。
- 不能把 `hybrid_v1` 的 140/140、`juliet_repair` 的 58/58、`juliet_llm` 的 0.9500 直接写成“检测/修复达到 SOTA”。
- 不能引用 `hybrid_v1` 的 100% 作为当前混合主结果；泄漏修复后的 v2 已回落到 136/140。
- 不能把动态 `clean` 当成已验证的负例，或把静态 `compile_error` 当成 `y_pred=0`。
- 不能把联合 A/B 的增益全部归因于“跨版本推理”；长度、强制二选一和位置偏差都是已量化的混淆。
- 不能把证据行提示的召回提升写成“判别力提升”或“没有增加假阳性”。
- 不能宣称某个模型总体更强：12 个 run 的模型轴是 post-hoc，所有模型比较经 Holm 后都不显著。

---

## 4. 目录结构

```text
cs224proj/
├── README.md                     # 本文件
├── .gitignore                    # 发布忽略规则（原始归档/缓存/逐 case 二进制/密钥）
├── .gitattributes                # LF 与二进制文件属性
├── docs/
│   ├── REPRODUCIBILITY.md        # 环境、数据恢复、分层复现命令、验收清单
│   ├── SECURITY.md               # 凭证处理、发布前检查、残余风险
│   └── GITHUB_RELEASE.md         # GitHub 私有仓库发布步骤、门禁与推送验证
├── audit/                        # 最终质量/泄漏审计（PASS_WITH_WARNINGS；0 FAIL，3 WARN）
├── SecVulEval.xlsx               # 上游数据集（18.8 MB，保留）
├── build_datasets.py             # 从 Excel 抽样生成 datasets/
├── datasets/                     # 200 独立函数 + 200 对（JSON）
├── splits/                       # secvul-split-v1 冻结划分与 few-shot 示例
├── runner/                       # SecVulEval LLM runner（direct/few-shot/context）
├── mimo/                         # MiMo 兼容性排查与 12-run test 结果
├── analysis/                     # 三策略统计、bootstrap、McNemar、模型比较、成本归一化
├── baseline/                     # 数据审计与无需模型的透明基线
├── juliet/                       # Juliet CWE-401 冻结子集与构建脚本
│   ├── raw/                      # [ignored] 上游 CWE-401 源码（58 MB）
│   ├── cache/                    # [ignored] 146 MB 官方归档
│   └── build/                    # [ignored] ASan 可执行文件
├── traditional/
│   ├── static/                   # Clang / Cppcheck 适配器与正式结果
│   └── dynamic/                  # ASan/LSan + Valgrind 全量结果
│       └── runs/*/cases/         # [ignored] 逐 case 二进制与日志（326 MB）
├── benchmark/                    # 统一协议、schema、validator、分层 leaderboard
├── juliet_llm/                   # Juliet LLM 直接检测（含 Xiaomi fallback）
├── hybrid/                       # 静态/动态/组合/安慰剂证据实验（v2 主结果）
├── evidence_prompt/              # 证据行/反事实提示（Tier A）
├── pair_joint/                   # 联合 A/B 配对判别
├── juliet_repair/                # 编译/LSan/行为闭环修复评测
├── repair_eval/                  # 修复质量盲评工具与最终汇总
├── qualitative/                  # 10 个定性案例
├── report/                       # 中文 IEEE 报告源稿、PDF、结果摘要
├── research/                     # 协议、相关工作、创新结论与限制
├── proposal/                     # 课程 proposal 源稿与图
└── output/                       # 预留输出目录
```

每个子目录有自己的 `README.md`，包含该模块的方法、产物、验证命令和限制。根目录只负责总览与发布边界。

---

## 5. 在 WSL 中复现

所有代码都在 **WSL Ubuntu** 中运行；Windows 侧只读写同一份文件。已验证环境：

| 组件 | 版本 |
| --- | --- |
| WSL | Ubuntu，Linux 6.18.x-microsoft-standard-WSL2 |
| Python | 3.14.8 |
| GCC / G++ | 15.3.0 |
| Clang / Clang++ | 22.1.8 |
| Cppcheck | 2.21.0（本机未装系统包；正式 run 用解包二进制） |
| Valgrind | 3.27.1（本机未装系统包；正式 run 用 `/tmp` 解包） |
| `httpx` | 0.28.1（runner 依赖） |
| `openpyxl` | 3.1.5（仅 `build_datasets.py` 需要） |

下文以本机路径为例；换机器时请替换成你的 clone 路径。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj'
```

### 5.1 无网络自检（推荐先跑）

```bash
export PYTHONDONTWRITEBYTECODE=1

python3 benchmark/tools/selftest.py                 # 指标/校验器算术
python3 analysis/selftest.py                        # 统计与聚合管线
python3 -m juliet_llm.selfcheck                     # 冻结哈希、清洗审计、密钥扫描
python3 hybrid/selftest.py                          # prompt 对齐、inconclusive、安慰剂
python3 pair_joint/selftest.py                      # A/B 映射、泄漏审计、解析
python3 juliet_repair/scripts/selftest.py           # 编译/LSan/行为 control
python3 evidence_prompt/selftest.py                 # 输入隔离、校验、证据映射
python3 -m repair_eval selftest                     # 盲评包/评分/kappa
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
```

这些命令只读冻结产物或在临时目录创建 fixture；不会调用模型，也不会覆盖正式结果。

### 5.2 恢复 Juliet 原始数据并校验

`juliet/raw/` 与 `juliet/cache/` 因体积被 `.gitignore` 排除。首次复现需要下载官方归档（约 146 MB）：

```bash
python3 juliet/scripts/fetch_juliet.py        # 下载/复用归档，提取 CWE-401 + 依赖
python3 juliet/scripts/verify.py              # 哈希、宏门控、split 隔离、近重复
```

`verify.py` 会校验归档 SHA-256、2,839 个 raw 文件、200 个单元的编译/符号/宏门控、dev/test 隔离和近重复阈值。若只想检查数据卡而不恢复 raw：

```bash
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
```

### 5.3 从已冻结 run 重算指标

不重新调用模型，只重算统一指标到临时目录（不会覆盖原始结果）：

```bash
python3 benchmark/tools/bench_metrics.py \
  --run-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent \
  --out-dir /tmp/secvul_metrics_check

python3 benchmark/tools/bench_metrics.py \
  --run-dir benchmark/results/tier_b/juliet_cwe401/static_clang/tierb_juliet_cwe401_static_clang_20261112_4c5800c4 \
  --out-dir /tmp/secvul_metrics_check_tierb
```

读取已冻结的分层 leaderboard：`benchmark/results/tier_a_leaderboard.md`、`tier_b_leaderboard.md`、`LEADERBOARD.md`。

> **当前已知不一致（2026-11-12）**：`benchmark/results/` 已包含 16 个 Tier A run（12 个正式矩阵 + 4 个创新导入），而 `bench_tier_a_summary.py` 仍断言 12 个，直接运行会失败。`bench_tier_b_summary.py` 是历史 5-tool 视图，主动排除 round-2 LLM/hybrid/repair，不再因 `hybrid_*` 报 `KeyError`；Tier B 的完整 v2 结果看 `benchmark/results/final_summary.json` 与 `LEADERBOARD.md`。复现时请以已冻结的 `tier_*_leaderboard.md` 为准；如果必须重算 Tier A，先把 12 个 canonical run **复制**（不要用符号链接，汇总脚本不跟随 symlink）到临时 `--runs-root`，不要覆盖 `benchmark/results/`。

要重跑 Tier A 的三策略统计：

```bash
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --out-json /tmp/aggregation.json --out-md /tmp/aggregation.md \
  --bootstrap 10000 --seed 42
```

### 5.4 重跑传统静态/动态

静态主结果（需要 Clang；Cppcheck 需自行安装或用 `--cppcheck-bin` 指定；若系统已安装可把 `/path/to/cppcheck` 换成 `$(command -v cppcheck)`）：

```bash
python3 traditional/static/static_adapter.py \
  --input juliet/subset_units.jsonl \
  --out traditional/static/runs/repro_clang_cppcheck \
  --tool both \
  --cppcheck-bin /path/to/cppcheck \
  --include-dir juliet/raw/testcasesupport \
  --assume-cwe CWE-401 --define _GNU_SOURCE \
  --clang-arg=-include --clang-arg=alloca.h \
  --timeout 120 --jobs 8 \
  --dataset-name juliet-cwe401-v1.3-subset-v1
```

动态全量（需要 ASan/LSan；Valgrind 可选）：

```bash
cd traditional/dynamic
python3 run_dynamic_eval.py check-tools --json
python3 run_dynamic_eval.py run \
  --juliet-root ../juliet/raw/testcases/CWE401_Memory_Leak \
  --support-dir ../juliet/raw/testcasesupport \
  --out runs/repro_asan_valgrind --run-id repro_asan_valgrind \
  --detectors asan,valgrind --jobs 8
```

若系统没有 Valgrind，可按 `traditional/dynamic/README.md` §1.2 解包到 `/tmp`，并用 `--valgrind-bin` + `VALGRIND_LIB` 指定；没有 Valgrind 时 `detectors.valgrind.status=unavailable`，不会被当成 clean。全量 3,316 case 约 16.5 分钟（8 workers，本机）。

### 5.5 重跑 LLM 实验

LLM 请求需要有效的 provider 凭证。**不要把 key 写进命令、脚本或文件**；使用环境变量或 `runner/run_with_kimi_config.py` 从本地 Kimi Code TOML 读入进程内存。部分脚本（`pair_joint/run_pair_joint.sh`、`hybrid/run_hybrid.py`、`juliet_repair/scripts/run_repair.py` 默认值）把 config 路径写死为 `/mnt/c/Users/tzh03/.kimi-code/config.toml`；换机器/用户名时先改脚本顶部或传 `--kimi-config`（支持该参数的工具）。

```bash
# 例：Tier A 单策略（模型 ID 必须显式指定）
export SECVUL_MODEL="<provider-model-id>"
export OPENCODE_API_KEY   # 值由当前 shell 环境提供，不要写在这里

python3 runner/run_experiment.py \
  --dataset independent --dataset-file splits/test_detection_160.json \
  --strategy direct --task both \
  --model "$SECVUL_MODEL" \
  --base-url https://opencode.ai/zen/go/v1 \
  --api-key-env OPENCODE_API_KEY \
  --out-dir runner/runs/repro_direct_independent
```

其他实验：

```bash
# Juliet LLM：泄漏修复后的正式/复现标签（主结果）
KIMI_PROVIDER=xiaomi bash juliet_llm/run.sh run \
  --model mimo-v2.6-flash --split test --kind test \
  --tag xiaomi_official_postleakfix --concurrency 8

python3 juliet_repair/scripts/run_repair.py --model deepseek --concurrency 8 \
  --out-dir juliet_repair/runs/repro_deepseek

# Hybrid v2（当前主结果；v1 只读保留）
python3 hybrid/build_inputs.py --out hybrid/inputs_v2
python3 hybrid/preflight.py --inputs-dir hybrid/inputs_v2 --run-id hybrid_v2
python3 hybrid/run_hybrid.py --model all --inputs-dir hybrid/inputs_v2 \
  --run-id hybrid_v2 --concurrency 12 \
  --preflight-report hybrid/results/hybrid_v2_preflight.json
python3 hybrid/analyze.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2
python3 hybrid/verify_outputs.py --runs-root hybrid/runs --run-id hybrid_v2 \
  --inputs-dir hybrid/inputs_v2 --out hybrid/results/hybrid_v2_audit.json

python3 pair_joint/selftest.py
bash pair_joint/run_pair_joint.sh full

python3 evidence_prompt/analyze.py

# 成本归一化（只读原始 results，重写 analysis/cost_normalization*）
python3 analysis/cost_normalization/rebuild.py
```

注意：OpenCode Go 的 `deepseek-v4.1-flash` 在 2026-11-12 实验期间返回 `401 api_key_expired`；DeepSeek 官方返回 `402 Insufficient Balance`，qwen 网关返回 `403 AccessDenied.Unpurchased`。因此 `juliet_llm` 的 DeepSeek 140 test **没有**结果；MiMo 140 是 Xiaomi 官方端点 fallback，不能冒充 OpenCode Go。重跑前先确认凭证与端点，不要用过期 key 跑全量。

### 5.6 报告与定性产物

```bash
python3 report/scripts/fill_tables.py \
  runner/runs/test_v1_direct_independent runner/runs/test_v1_direct_pairs \
  runner/runs/test_v1_few-shot_independent runner/runs/test_v1_few-shot_pairs \
  runner/runs/test_v1_context_independent runner/runs/test_v1_context_pairs \
  --model deepseek-v4.1-flash

python3 qualitative/build_cases.py --check-only
# 完整本地工作区才有 private blind key；公开仓库不包含该文件，
# 因此 verify 只应在保留 private/ 的原始工作区运行。
python3 -m repair_eval verify --package repair_eval/packages/repair_blind_v1

cd report && /tmp/secvul-tectonic/tectonic -X compile report_extended_zh.tex --outdir .
cd report && /tmp/secvul-tectonic/tectonic -X compile report_zh.tex --outdir .
```

报告 PDF 已提交：扩展版 `report/report_extended_zh.pdf`（27 页，Tectonic 0.17.0，`pdfinfo` 实测）与基础版 `report/report_zh.pdf`（17 页，保留未改）。重新编译需要 Tectonic 或 TeX Live。

更多环境细节、数据哈希、验收清单和已知坑见 [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)。

---

## 6. 凭证与发布安全

- 所有 API key 只从环境变量或本地 Kimi Code TOML 读入**进程内存**；不打印、不写日志、不写 `manifest.json`、不写 `results.jsonl`。运行产物记录 `api_key_value_stored: false`。
- `runner` 和 `juliet_llm` 对响应体做 `sk-...` / `Bearer ...` 脱敏；`api.session` 记录非敏感的 `x-opencode-session` 随机值及其 SHA-256，不是密钥。
- `.gitignore` 排除 `.env`、`creds/`、`credentials/`、`secrets/`、`*.key`、`*.pem`、`auth.json`、`opencode.json`、`*_api_key.json`、`repair_eval/packages/*/private/` 等。
- 发布前请按 [`docs/SECURITY.md`](docs/SECURITY.md) 的清单做一次 secret scan 和文件体积检查。**不要把任何 key 粘进 issue、PR、commit message 或截图。**
- GitHub 私有仓库已创建并推送：<https://github.com/tzhazuma/cs224proj>（PRIVATE）。发布/重建步骤仍见 [`docs/GITHUB_RELEASE.md`](docs/GITHUB_RELEASE.md)：包含 `gh` 安装/校验、`git init`、暂存区体积与密钥扫描、`gh repo create cs224proj --private --source=. --remote=origin --push` 以及推送后验证；当前仓库不要重复执行 `gh repo create`。发布门禁是 `audit/final_audit.md` 的 FAIL=0（当前 58 PASS / 0 FAIL / 3 WARN / 1 INFO，`PASS_WITH_WARNINGS`）。
- 本仓库不包含个人账号、cookie、SSH key 或云凭证；如果发现疑似泄漏，先轮换凭证，再清理历史。

---

## 7. 数据来源、许可与边界

- **SecVulEval**：根目录 `SecVulEval.xlsx` 为课程提供的上游数据集；`datasets/` 与 `splits/` 是从该工作簿抽样、冻结的派生数据。上游数据的引用与许可请遵循其原始发布页面。
- **Juliet**：NIST SARD 的 Juliet Test Suite for C/C++ v1.3，官方归档 URL 与 SHA-256 见 `juliet/README.md`。`juliet/raw/` 不随仓库分发（体积原因），用 `fetch_juliet.py` 从官方来源恢复。
- **模型输出**：`runner/runs/`、`juliet_llm/runs/`、`hybrid/runs/`、`pair_joint/runs/`、`juliet_repair/runs/` 保存真实模型响应与 usage；它们是研究产物，不构成对代码安全性或补丁正确性的保证。
- **许可**：本仓库目前没有附 LICENSE 文件；在重新分发或用于课程之外之前，请先核对上游数据集条款并补充合适的许可证。
- **单文件体积**：GitHub 单文件上限 100 MB。按 `.gitignore` 估算，当前最大的待提交文件是 `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl`（约 40.5 MB）；146 MB 的 Juliet 归档和 326 MB 的逐 case 二进制已被忽略。发布前仍建议用 `find` 检查一次。

---

## 8. 已知限制（必须与结果一起读）

1. **Tier A 样本小、单次运行。** 160 个检测函数、180 对；每个 (model, strategy) 只有一个 run，没有多 seed/run-to-run 方差。`temperature=0` 不保证服务端逐字节确定性。
2. **模型比较不是纯模型比较。** DeepSeek 用 non-thinking + `max_tokens`；MiMo 用 `reasoning_effort=none` + `max_completion_tokens`。这是“模型 + 配置”比较。
3. **context 伪影。** 检测 test 的非空上下文层 126/126 全是漏洞，空层 34 条中只有 2 条漏洞；`context` 策略的总体差异与“上下文是否可用”混杂，不能单独归因于上下文推理。
4. **Tier B 是合成、单 CWE。** Juliet 模板化、单元小、单缺陷；42 个家族，test 29 个家族；不能外推到真实项目或其他 CWE。
5. **动态 clean 不是 TN。** 动态 run 没有覆盖率 instrumentation；clean 只表示“本次执行未观察到 definite/indirect leak”。conservative 视图把 clean 弃权，macro-F1 未定义。
6. **22 个 bad 单元没有观察到 LSan 泄漏。** 15 个 `malloc_realloc` 需要 `realloc` 失败，7 个 `_68` 全局指针 still reachable；标签未改，但它们不能支持“动态工具漏报”的强结论。
7. **静态编译失败不是零。** Clang 全量 200 有 6 个 `compile_error`（test 140 有 4 个），Cppcheck 有 4 个 FP；主表同时给 valid-only 和 strict，不能只读一个。
8. **Tier B LLM/混合仍带 B9 caveat。** B5/B6/B7/B11/B12 已 `done_frozen`，但 B4（DeepSeek Juliet LLM）无结果、B8 未做、B9 的 label-only baseline 未跑（整体 `partial`）；`juliet_llm/` 与 `hybrid/` 的数字在 leaderboard 中单列，不能与静态/动态合并成一个总排名。
9. **修复没有真实项目编译/PoC。** `juliet_repair` 的 compile/LSan/behavior 是 Juliet harness 内的闭环；`repair_eval` 的盲评是 LLM 辅助、无编译/PoC，κ 很低。
10. **成本不可跨范式相加。** API USD 与本地 CPU/Valgrind 时间分开；本地工具的 `usd=null` 不是 0；不做单一“性价比”总分。
11. **派生视图不是新实验。** `benchmark/results/tier_a/` 的 12 个正式矩阵 run 是 `runner/runs/test_v1_*` 的只读派生，另有 4 个创新导入来自 `evidence_prompt/`/`pair_joint/`；`benchmark/results/tier_b/` 的 5 个传统工具 run、10 个 `hybrid_v2` run 与 1 个 `llm_mimo_xiaomi_postleakfix` 是 `traditional/*`、`hybrid/*`、`juliet_llm/*` 的只读映射，repair 单列。v1/pre-leakfix 只作为泄漏对照保留，不进入主表。
12. **标签与理由可能不一致。** 多个 LLM run 出现 `reason` 与 `label` 矛盾；评分按 `label`，没有事后按理由改写。
13. **成本列是 configured，不是账单；DeepSeek 的 2× 是峰谷价差（审计 I5 已通过）。** 配置价 `$0.30/$1.20` 是高峰价，provider `list_cost` 的 `$0.15/$0.60` 是非高峰价；本批 9,584 条请求 peak rows=0。统一重算的 normalized 与 allowance 见 §3.1.1 和 `analysis/cost_normalization.md`；不能把 USD 列当实际扣费，也不能跨模型直接比 list。
14. **`analysis/aggregation.json` 已用仓库内路径重生成（审计 L4 已修复）。** 2026-11-12 04:48 版本的 14 个 run 路径均存在；重算仍建议 `--runs-root runner/runs --out-json /tmp/...`，不要覆盖冻结产物。
15. **hybrid 安慰剂只有一个 derangement（审计 D5 WARN）。** v2 仍是 14/140 个单元的 donor 文本与自身相同，placebo 对这些单元是 no-op；单次抽样不能估计 placebo 分布。
16. **Juliet bad/good 存在长度不对称（审计 B5 WARN）。** bad 平均 600.4 字符、good 937.9（ratio 0.640），来自 Juliet 原始结构而非清洗；这是潜在捷径信号。
17. **Repair prompt 不是完全 label-neutral（审计 F4 WARN）。** 70/70 个 repair prompt 仍含 `bad`/`CWE`/`Memory_Leak` 任务前提 token（good 标识符 0/70）；这是任务语义所需，但模型可利用该前缀。
18. **Repair all-in 成本已统一为 `$0.082550`（审计 I3 已修复）。** headline 两个 final run 为 `$0.032831`；all-in 含 `parser_dev/mimo_test70_v1` 的 `$0.005034` 与 smoke，configured `$0.082550`、normalized `$0.052549`。引用时用 run 目录的 `summary.json`，不要用旧汇总。
19. **`hybrid_v2` 是单次重跑。** 6 个被清洗单元的 17 条预测变化中 16 条由对变错；134 个未变单元仍有 1 条端点波动。v2 的小幅下降不能全部归因于清洗，也不能把单次 v2 当成稳定估计。

---

## 9. 文档索引

| 文档 | 内容 |
| --- | --- |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | 环境、数据恢复、分层复现命令、产物哈希、验收清单、常见坑 |
| [`docs/SECURITY.md`](docs/SECURITY.md) | 凭证处理、忽略规则、发布前 secret scan、残余风险、事件响应 |
| [`docs/GITHUB_RELEASE.md`](docs/GITHUB_RELEASE.md) | GitHub 私有仓库发布：`gh` 安装、git 初始化、门禁、推送与验证 |
| [`audit/final_audit.md`](audit/final_audit.md) | 最终质量/泄漏审计：58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`；审计时间与发布门禁见 [`docs/GITHUB_RELEASE.md`](docs/GITHUB_RELEASE.md) §2.1 |
| [`benchmark/PROTOCOL.md`](benchmark/PROTOCOL.md) | 统一评测协议：标签、指标、失败、统计、成本、Tier A/B |
| [`benchmark/results/LEADERBOARD.md`](benchmark/results/LEADERBOARD.md) | 两层 leaderboard 索引（不跨层排名；Tier B 主行为 hybrid_v2 / postleakfix） |
| [`juliet/README.md`](juliet/README.md) | Juliet 子集来源、宏门控、dev/test、近重复、复现 |
| [`traditional/static/README.md`](traditional/static/README.md) | Clang/Cppcheck 适配器、CWE-401 规则、200 单元结果 |
| [`traditional/dynamic/README.md`](traditional/dynamic/README.md) | ASan/LSan + Valgrind 全量结果与 190 个 FN 归因 |
| [`report/results_summary.md`](report/results_summary.md) | Tier A 三策略结果、成本、修复结构、盲评摘要 |
| [`research/innovation_findings.md`](research/innovation_findings.md) | 创新点的证据分级：哪些能写、哪些不能写 |
| [`pair_joint/report.md`](pair_joint/report.md) | 联合 A/B 的完整结果、长度/位置混淆 |
| [`evidence_prompt/README.md`](evidence_prompt/README.md) | 证据行/反事实提示的协议与结果 |
| [`hybrid/REPORT_V2.md`](hybrid/REPORT_V2.md) | 泄漏修复后 hybrid v2 的完整结果、v1 对照与限制 |
| [`analysis/cost_normalization.md`](analysis/cost_normalization.md) | 峰谷价、normalized 与 allowance 的逐 run 成本口径 |
| [`juliet_repair/README.md`](juliet_repair/README.md) | 编译/LSan/行为闭环与 58/58 的口径 |
| [`juliet_llm/README.md`](juliet_llm/README.md) | Juliet LLM 清洗、审计、MiMo fallback、DeepSeek 阻塞证据 |
| [`repair_eval/README.md`](repair_eval/README.md) | 修复盲评 rubric、κ、裁决与限制 |

---

## 10. English abstract

This repository contains the artefacts of a CS224 course project that evaluates vulnerability detection and repair under one auditable contract while keeping two tiers separate. **Tier A** uses frozen SecVulEval splits (160 real-project C/C++ functions for detection; 180 vulnerable/fixed pairs) and compares two models across three prompt strategies. **Tier B** uses a frozen 200-unit Juliet CWE-401 subset and compares Clang Static Analyzer, Cppcheck, ASan/LSan and Valgrind. The project also contains diagnostic studies on joint A/B pair discrimination, evidence-line prompting, tool-evidence conditioning with a placebo, compile/LSan/behaviour repair evaluation, and an LLM-assisted repair rubric.

The main methodological claim is negative and reproducible: several apparently large gains are explained by task framing, length, position, operating-point shifts or ceiling effects. No model comparison survives Holm correction; joint A/B gains are inseparable from forced choice and length; dynamic “clean” is not a verified true negative; the original hybrid 140/140 did not survive the label-leak fix (v2 combined is 136/140); and the repair 58/58 is limited to 58 observable synthetic units. All reported numbers come from recorded runs; no mock or estimated values are used in the result tables.

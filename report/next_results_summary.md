# 下一轮统一结果摘要（2026-11-22）

本文件汇总本轮五个真实实验的结果、口径、复现命令和限制。它对应 `report/report_next_zh.tex` / `report_next_zh.pdf`，不修改任何旧 PDF 与旧结果目录。

- 范围：`codeql_triage/`、`dynamic_coverage/`、`interpretable_baseline/`、`pair_diff/`、`verifier_conservative/`、`research/next_iteration_rationale.md`。
- 证据：所有数字来自各目录已落盘的 `results.jsonl` / `metrics.json` / `summary.json`，本轮在 WSL 只读复核；没有 mock、fixture 或手填结果。
- 成本：按配置价与 provider 报告的 token 计算，不是发票。
- 统计：配对比较用 exact McNemar；多重比较在预注册检验族内做 Holm；区间用 Wilson 或 10,000 次按 project 聚类 bootstrap（seed 42），另有说明除外。
- 诚实性：本轮的五个主结论中，四个是负结果或“有条件的正结果”；不得把它们写成全面改进。

---

## 0. 五条必须原样保留的诚实结论

| # | 结论 | 关键数字 | 不能写成 |
| --- | --- | --- | --- |
| H1 | **CodeQL triage 强，但对 direct 不显著，且最终行依赖规则后处理** | 最终 68/0/70/2，macro-F1 0.9857；vs CodeQL 0.8173，+0.1684，Holm $p<10^{-6}$；vs direct 0.9571，+0.0286，95% CI [−0.0072, +0.0714]，$p=0.289$；3 个 `_22` 翻转让 FP 从 3 到 0 | “LLM triage 显著优于 direct”“端到端 0 FP 是 LLM 的功劳” |
| H2 | **Pair diff 没有显著收益** | 交换一致 DA：DeepSeek diff 62.22% vs ctrl 60.00%（+2.22 pp，Holm 1.0000）vs open 55.56%（+6.67 pp，原始 $p=0.0428$，Holm 0.0855）；MiMo diff 60.56% vs ctrl 62.22%（−1.67 pp，Holm 0.9053） | “diff 让配对判别显著提升” |
| H3 | **保守验证器几乎不撤，但没有收益** | 236 条请求只撤 4 条（TP 3 / FP 1），撤销精确率 25.0%；macro-F1 四臂 0 到 −0.0052；MCC 只在 `mimo_cross` +0.0139（95% CI 跨 0），代价是 2 TP 换 1 FP | “保守规则修好了验证器” |
| H4 | **100% 行覆盖不是无泄漏** | 原路径 82 个 clean 在剔除 CWE-561 声明死代码后全部 100% 行覆盖，其中 12 个实际是 bad；分支覆盖 52.7%，21 个 `branch_complete` 全是 bad、0 个 good | “行覆盖 100% 所以 clean 可信”“动态 140/140 是无泄漏证明” |
| H5 | **简单长度规则点估计高于 LLM** | `length_short` macro-F1 0.511 [0.422, 0.562]，MCC 0.094；8 个 LLM run 为 0.346–0.422，最好的 DeepSeek evidence 0.422；多数类 0.444 | “简单规则是更好的检测器” |

补充两条同样必须保留的口径：

- H5 的“高于”只在 macro-F1 点估计上成立；MCC 上 `alloc_or_mem` 0.183 高于 LLM，但 `length_short` 0.094 与最好的 MiMo context 0.080 几乎同档；Δmacro-F1 的聚类 bootstrap 95% CI 全部跨 0，逐单元 McNemar 只在 direct / MiMo direct 上经 Holm 显著，对 DeepSeek evidence 不显著（Holm 0.203）。
- H1 的最终行 `68/0/70/2` 由三部分组成：v2 triage 的 `68/3/67/2`、91 条告警的二次一致性复核（翻转 3 个 `_22`）、以及同分的文本一致性规则；去掉后处理，LLM triage 单独是 `68/3/67/2`（0.9643）。

---

## 1. 口径与数据

| 项 | 值 |
| --- | --- |
| Tier A 检测 | `splits/test_detection_160.json`，160 条，128 V / 32 NV，正例率 80.0%，40 个项目 |
| Tier A 开发 | `splits/dev_detection_40.json`，40 条，32 V / 8 NV，40 个项目，每项目 1 条 |
| Pair | `splits/test_pairs_180.json`，180 对，每对一个 vulnerable、一个 fixed |
| Tier B | Juliet CWE-401 `split=test` 140 单元，70 bad / 70 good，70 组 |
| 隔离 | dev/test 的 idx、project、函数体 MD5 交集均为 0；Tier A/Tier B 不池化、不横比 |
| 模型 | DeepSeek V4.1 Flash、MiMo V2.6 Flash；本轮 triage 为 MiMo（Xiaomi 通道） |
| 单次运行 | 除特别说明外，每单元一条记录，temperature 0；无多 seed 方差 |

指标：

- `macro-F1`：正类 F1 与负类 F1 的宏平均；在 80% 正例上奖励“多报”。
- `MCC`：同时惩罚两类错误，是本轮检测实验的并列主终点。
- `DA`：配对准确率，invalid 记错。
- `交换一致 DA`：正序和反序都判对的比例；对位置偏差不敏感，是配对主终点。
- `TP 误删`：triage 把 CodeQL 的 TP 告警撤销的数量；必须与 FP 撤销一起报。
- `covered_clean`：clean 且单元自身可达行全部执行；不是正确性标签。

---

## 2. 五个欠缺与量化原因

### 2.1 检测：低于常量基线和单参数长度规则

| 方法 | TP | FP | TN | FN | P | R | macro-F1 | MCC | pred+ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 常量：恒判漏洞 | 128 | 32 | 0 | 0 | 0.800 | 1.000 | 0.444 | 0.000 | 1.000 |
| 常量：恒判安全 | 0 | 0 | 32 | 128 | — | 0.000 | 0.167 | 0.000 | 0.000 |
| `length_short`（dev 中位数 1504，预注册） | 75 | 15 | 17 | 53 | 0.833 | 0.586 | **0.511** | 0.094 | 0.562 |
| `length_short`（dev 调阈值 3227，敏感性） | 101 | 23 | 9 | 27 | 0.815 | 0.789 | **0.533** | 0.067 | 0.775 |
| `alloc_or_mem` | 32 | 2 | 30 | 96 | 0.941 | 0.250 | 0.387 | **0.183** | 0.212 |
| DeepSeek direct | 38 | 8 | 24 | 90 | 0.826 | 0.297 | 0.383 | 0.041 | 0.288 |
| DeepSeek evidence | 49 | 11 | 21 | 78 | 0.817 | 0.386 | **0.422** | 0.035 | 0.377 |
| MiMo direct | 35 | 7 | 25 | 93 | 0.806 | 0.242 | 0.346 | 0.008 | 0.240 |
| MiMo context | 38 | 6 | 27 | 90 | 0.861 | 0.252 | 0.365 | **0.080** | 0.235 |

量化原因：

1. **操作点错配**：DeepSeek direct 只报 46/160 为正（28.75%），真实正例率 80%；accuracy 38.75% 低于多数类的 80%。precision 0.826 只比基准率 0.80 高 2.6 pp，是基准率的影子。
2. **置信度几乎无排序**：DeepSeek direct 的 `confidence` 对“是否漏洞”的 AUROC 约 0.540；事后阈值 0.3 能把 macro-F1 抬到 0.528、accuracy 到 73.13%，但 MCC 只到 0.062。这证明“调操作点”能抬 macro-F1，不能抬排序能力。
3. **CWE 结构**：CWE-416 召回 0.05（1/20）、CWE-20 0.125（1/8）、CWE-264/200 为 0；CWE-190 0.83、CWE-125 0.62、CWE-787 0.64。生命周期/契约类几乎全漏。
4. **长度方向相反**：FN 中位长度 971.5 字符，TP 1,967.5；最短四分位正例率 82.5%，DeepSeek accuracy 只有 25.0%，即它在最短、最该报的片段上默认“安全”。长度规则的方向是“短→漏洞”，正好与数据集先验一致。
5. **标签是“修复前漏洞侧 vs 修复后侧”**，不是“函数文本里有可见 bug”；90 个 FN 中 76.7% 的 rationale 含 “no clear / insufficient / unclear”，多数是 wrapper、helper、标准内核代码。

### 2.2 配对：长度方向与槽位偏好

| 模型 | 任务 | 正向 DA | 反向 DA | 交换一致 DA | 同字母率 | 槽位差 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | forced | 76.67% | 77.78% | **61.67%** | 31.11% | 31.11 pp |
| DeepSeek | open | 66.11% | 63.89% | **55.56%** | 14.50% | n.s. |
| MiMo | forced | 86.67% | 81.67% | **74.44%** | 19.44% | 4.44/21.11 pp |
| MiMo | open | 66.11% | 65.56% | **58.33%** | 8.59% | n.s. |

量化原因：

- 180 对中 **130 对漏洞版本更短**、44 对修复版本更短、6 对等长。“选较短版本”单向 74.44%，两序同语义 72.22%。DeepSeek 的交换一致 61.67% 显著低于 72.22%（Holm $p=0.0289$）；MiMo 74.44% 只高 2.22 pp（$p=0.644$）。
- 唯一能区分“语义判断”和“选较短”的子集是 44 个 fshorter 对。两序都对：DeepSeek 15/44 = 34.1%（随机基线 25%，$p=0.166$），MiMo 20/44 = 45.5%（$p=0.0045$，但仍低于 50%）。
- 方向平衡 88 对（44 fshorter + 44 最近邻 vshorter）：DeepSeek 42/88 = 47.7%（$p=0.749$，随机），MiMo 56/88 = 63.6%（$p=0.0138$，弱信号）。
- 10% 长度匹配无效：匹配子集仍是 101 vshorter : 37 fshorter，长度启发式 72.92%。**控制方向，不是控制幅度。**

### 2.3 CodeQL：23 个 FP 全部来自一个查询、四个 C++ 模式

| 方案 | TP | FP | FN | TN | P | R | macro-F1 | MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL 并集 | 68 | 23 | 2 | 47 | 0.747 | 0.971 | 0.817 | 0.674 |
| `never-freed` only | 46 | 0 | 24 | 70 | 1.000 | 0.657 | 0.823 | 0.700 |
| `never` + may 仅 C | 60 | 0 | 10 | 70 | 1.000 | 0.857 | 0.928 | 0.866 |
| 理想证人过滤（上界） | 68 | 0 | 2 | 70 | 1.000 | 0.971 | 0.986 | 0.972 |

- 23/23 FP 来自 `cpp/memory-may-not-be-freed`，23/23 是 C++ good；`cpp/memory-never-freed` 在 test 140 上 0 FP。
- 变体：`_33` 15 个（引用别名 + 变量遮蔽）、`_22` 3 个（sink 内释放）、`_72` 3 个（STL 容器逃逸）、`_54` 2 个（sink）。
- 45 个 may hit 的 `code_flows` 全部为 0；词法 `free/delete` 计数无法区分 TP/FP（`_33` 的 good 与 bad 都有 2 个 `free(`）。
- 语言过滤是部分成功：may 仅在 C 上 14 TP / 0 FP，加 never 后 60/0/10/70。
- 任何 LLM triage 必须先打“drop C++ may-not-be-freed”这个零成本基线（0.9282）；否则 0.96 可能只是学会了 query/language 先验。

### 2.4 验证器：fail-closed 把“未证明”当“已反驳”，且没有排序信号

| 臂 | 撤销 | TP 撤销 | FP 撤销 | 撤销精确率 | 正例 FP 基准率 | Δmacro-F1 | 置信度 AUROC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek 自审 | 54 | 43 | 11 | 20.4% | 18.3% | −0.2043 | 0.400 |
| DeepSeek 跨模型 | 26 | 20 | 6 | 23.1% | 18.3% | −0.0701 | 0.455 |
| MiMo 自审 | 21 | 18 | 3 | 14.3% | 19.0% | −0.0846 | 0.282 |
| MiMo 跨模型 | 51 | 40 | 11 | 21.6% | 19.0% | −0.1842 | 0.304 |

- `insufficient_evidence` 占撤销的 66.7%–71.4%；语义是“函数体内看不出攻击者控制”，但第一遍本来就是函数级输入，调用者/攻击者控制通常不在函数内。
- 两个臂把 11/11 个 FP 都撤了，同时撤了 40–43 个 TP；撤销精确率只是 FP 基准率的影子，超几何检验 Holm $p \ge 0.8367$。
- 置信度 AUROC 0.28–0.46，**低于随机**；即使改成阈值扫描也救不回来，必须换证据来源。

### 2.5 动态：`coverage=1.000` 是判定覆盖率，不是代码覆盖率

- `dynamic_enhanced/dyne/metrics.py` 的 `coverage = (len(rows) - undecided) / len(rows)`：140 个单元中给出 leak/clean 判定的比例。
- 编译参数没有 `--coverage` / `-fprofile-instr-generate`；140 个单元 0 行覆盖率、0 分支覆盖率；每模式只跑 1 个输入。
- `nogobal` 下 70/70 good 都有**原始**泄漏，0 个被归因到单元源码；0 FP 是“0 attributed FP”，不是工具本身 0 FP。
- 全量 3,316 的 190 个 FN：108 个 `malloc_realloc_*`（只有 realloc 失败才泄漏）、68 个 `_45`/`_68`（全局指针，LSan 默认 still reachable）、14 个 `_12`（随机分支，单输入走到非泄漏路径）。

---

## 3. 本轮实验：设计、真实结果、判定

### 3.1 G0 动态覆盖率门禁（`dynamic_coverage/`）

设计：对冻结 test 140 逐单元编译原始 Juliet 源文件，`gcc/g++ -O0 -g -fsanitize=address --coverage`；三模式 `default` / `realloc_fail` / `nogobal`；`gcov -j -b -c` 解析逐行/逐分支；只统计单元自身 `.c/.cpp` 与同组头文件；CWE-561 声明死代码单列，同时保留 raw 与 effective 两个口径。

结果：

| 模式 | 适用 | bad leak | good leak | 有效行覆盖 | 分支覆盖 | `branch_complete` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| default | 140 | 58 | 0 | 100.0% | 50.0% | 21（全 bad） |
| realloc_fail | 14 | 7 | 0 | 97.8% | 50.0% | 21 |
| nogobal | 140 | 63 | 0 | 100.0% | 50.0% | 21 |
| 并集 | 140 | 70 | 0 | 100.0% | 52.7% | 21（全 bad） |

| 视图 | TP | FP | TN | FN | abstain | macro-F1 | supported clean 但 bad |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default operational | 58 | 0 | 70 | 12 | 0 | 0.914 | 12 |
| default line-gated（effective） | 58 | 0 | 70 | 12 | 0 | 0.914 | 12 |
| default branch-gated | 58 | 0 | 0 | 12 | 70 | — | 2 |
| enhanced operational | 70 | 0 | 70 | 0 | 0 | 1.000 | 0 |
| enhanced line-gated | 70 | 0 | 70 | 0 | 0 | 1.000 | 0 |
| enhanced branch-gated | 70 | 0 | 0 | 0 | 70 | — | 0 |

判定：

- **测量成功**：140/140 采集成功，0 compile_error、0 coverage_error；default 与归档 140/140 一致；12 个漏报拆成 7 个 realloc 分支 + 5 个 LSan 根集。
- **门禁失败**：line gate 对 12 个漏报零纠错（它们全是 line-complete）；branch gate 把 70 个 good 全部弃权；`supported_clean_but_bad = 12` 是覆盖率证据最危险的失败模式。
- 并集 1.000 的前提是三种定向模式都跑；`realloc_fail` 只适用 14 个单元，`nogobal` 新增 0 行/0 分支。不能写成“通用动态检测 100%”。

### 3.2 B1 可解释非 LLM 基线（`interpretable_baseline/`）

设计：7 条规则 + 2 个 LR，全部只用 `func_body` 的表面特征；阈值只在 dev 40 上选；test 160 只看一次；主指标同时报 macro-F1 与 MCC。

结果（test 160）：

| 方法 | macro-F1 [95% CI] | MCC | P | R | Spec |
| --- | --- | ---: | ---: | ---: | ---: |
| `length_short` | **0.511 [0.422, 0.562]** | 0.094 | 0.833 | 0.586 | 0.531 |
| `prior_majority` | 0.444 [0.412, 0.460] | 0.000 | 0.800 | 1.000 | 0.000 |
| `alloc_or_mem` | 0.387 [0.324, 0.530] | **0.183** | 0.941 | 0.250 | 0.938 |
| `lr_balanced` | 0.391 [0.343, 0.466] | −0.131 | 0.747 | 0.461 | 0.375 |
| DeepSeek evidence | 0.422 | 0.035 | 0.817 | 0.386 | 0.656 |
| DeepSeek direct | 0.383 | 0.041 | 0.826 | 0.297 | 0.750 |
| MiMo context | 0.365 | 0.080 | 0.861 | 0.252 | 0.833 |

配对比较：

| baseline | LLM | n | Δmacro-F1 [95% CI] | b/c | p | Holm p |
| --- | --- | ---: | --- | --- | ---: | ---: |
| `length_short` | DeepSeek direct | 160 | +0.128 [−0.107, +0.224] | 70/40 | 0.0054 | **0.038** |
| `length_short` | DeepSeek evidence | 159 | +0.092 [−0.134, +0.202] | 69/47 | 0.0507 | 0.203 |
| `length_short` | MiMo direct | 150 | +0.179 [−0.055, +0.267] | 69/32 | 0.0003 | **0.002** |
| `alloc_or_mem` | DeepSeek direct | 160 | +0.005 [−0.075, +0.076] | 23/23 | 1.000 | 1.000 |

判定：

- **点估计成功、统计上有限**：`length_short` 的 macro-F1 0.511 高于全部 8 个 LLM run（0.346–0.422），逐单元正确数在 direct 上经 Holm 显著；但 Δmacro-F1 的聚类 bootstrap CI 全部跨 0，对最强的 DeepSeek evidence 不显著（Holm 0.203）。
- **指标翻转**：按 MCC，`alloc_or_mem` 0.183 第一，`length_short` 0.094 第五，最好的 LLM（MiMo context）0.080；按 macro-F1，多数类 0.444 排在 8 个 LLM 前面。只报 macro-F1 会把“多报”误当能力。
- **机制**：长度规则在 Q1/Q2 全判正（召回 1.0、特异度 0），LLM 在 Q1 召回 0.091；Q4 LLM 反而更好（0.520 vs 0.216）。不是 LLM 在长函数上更差，而是它在短函数上几乎不报。
- **test-tuned 上界**：`call_density >= 0.2` 0.598 macro-F1 / 0.209 MCC；LR 5 折 CV 0.502。允许 test 调阈值也没有强检测器。

### 3.3 P1 差分引导、长度对照、位置去偏（`pair_diff/`）

设计：180 对 × 2 模型 × 4 个新条件（`diff_fwd` / `diff_rev` / `ctrl_fwd` / `ctrl_rev`）= 1,440 条新记录；`open_fwd` / `open_rev` 只读复用 `pair_debias`。`ctrl` 用 `tiktoken cl100k_base` 生成与 diff 等长、内容为空的占位块；diff 方向始终 A→B；主终点是交换一致 DA。

结果：

| 模型 | diff | ctrl | open | diff−ctrl（Holm p） | diff−open（Holm p） |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 62.22% | 60.00% | 55.56% | +2.22 pp（1.0000） | +6.67 pp（0.0855） |
| MiMo | 60.56% | 62.22% | 58.33% | −1.67 pp（0.9053） | +2.22 pp（1.0000） |

补充：

- DeepSeek 的 +6.67 pp 原始 $p=0.0428$，Holm 后 0.0855；MiMo 原始 $p=0.5413$。两个模型的 diff−ctrl 都不显著。
- committed 子集上 diff 比“选较短”高 +7.97 到 +11.81 pp（DeepSeek）、+8.70 到 +10.29 pp（MiMo），但 diff 的弃权率 20.00%–24.44%，高于 open 的 17.22%–22.22%；主 DA 按 180 对计，弃权抵消了内容信号。
- “选较短”比例 75.17%–81.20%，不低于 open 的 73.15%–80.14%；在“较短侧必错”的 44 对上，diff−ctrl 仅 +2.27 pp（$p=1.0000$）。
- changes-first 的新失败模式是“变更范围门控”：变更清单无安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全判 `neither`，DA=0；ctrl 有同样门控，说明它由指令驱动，不是 diff 内容。
- 成本 $1.156871，4,366,678 prompt / 453,037 completion tokens；diff 约为 open 的 1.30×，USD/正确 pair-order 更高。

判定：**没有 Holm 后显著的 diff 优势**；“diff 减少长度捷径”不成立；只在 committed 子集有内容信号，且被弃权抵消。

### 3.4 C1 CodeQL 告警 triage（`codeql_triage/`）

设计：MiMo `mimo-v2.6-flash`，test 140 全量 direct + triage v1 + triage v2 + 91 条告警二次复核；主策略是“除非模型明确说 `false_positive`，否则保留告警”；`uncertain`/invalid 回退到保留。报告 TP 误删、FP 撤销、macro-F1/MCC、成本。

结果：

| 策略 | TP | FP | TN | FN | macro-F1 | MCC | TP 误删 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 68 | 23 | 47 | 2 | 0.8173 | 0.6739 | — |
| direct | 69 | 5 | 65 | 1 | 0.9571 | 0.9158 | — |
| triage v1 | 61 | 5 | 65 | 9 | 0.8999 | 0.8013 | 7/68 |
| triage v2 | 68 | 3 | 67 | 2 | 0.9643 | 0.9287 | 0/68 |
| v2 + 复核/文本规则 | **68** | **0** | **70** | **2** | **0.9857** | **0.9718** | **0/68** |
| cascade（告警复核 + 无告警 direct） | 70 | 2 | 68 | 0 | 0.9857 | 0.9718 | 0/68 |

- 最终 vs CodeQL：+0.1684 macro-F1，95% CI [+0.1084, +0.2349]，$p<10^{-6}$。
- 最终 vs direct：+0.0286，95% CI [−0.0072, +0.0714]，$p=0.289$，**不显著**。
- v1 的 7 个 TP 误删全是 `malloc_realloc_*`；v2 显式 realloc 失败规则后 0 误删；FP 撤销 18 → 20 → 23。
- 3 个 `_22` 的翻转为 `_22` 字段自相矛盾（`leak_present` 与 `release_gap` 冲突），由二次复核/文本规则修正，不是所有权推理。
- 2 个 CodeQL FN 是 `_82` compile_error；triage 无法恢复；cascade 用 direct 补回 2 个 TP，但引入 2 个 FP。
- 成本：direct $0.003021 + triage $0.030545 + verify $0.012229 = $0.045795；triage p50 6.91 s、p95 14.20 s；CodeQL 建库约 42.5 s/单元。
- 零成本基线：`never-freed only` 46/0/70/24（macro 0.8234）；`drop C++ may-not-be-freed` 60/0/70/10（0.9282）。

判定：**相对 CodeQL 强且显著；相对 direct 不显著；最终行依赖规则后处理；不能写成端到端 0 FP 或全面 SOTA。**

### 3.5 V1 保守三路验证器（`verifier_conservative/`）

设计：只验证第一遍的正例；三路 `supported` / `unsupported` / `insufficient`；只有 `unsupported` + 具体 `guard_present` 或 `counterexample` 才撤销；`insufficient`、schema-invalid、API error 一律保留（fail-open）。四臂：DeepSeek 正例 × {DeepSeek, MiMo}、MiMo 正例 × {DeepSeek, MiMo}；236 条真实请求。

结果：

| 臂 | 撤销 | TP 损失 | FP 纠正 | 撤销精确率 | Δmacro-F1 | ΔMCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 1 | 1 | 0 | 0.0% | −0.0052 | −0.0064 |
| `deepseek_cross` | 0 | 0 | 0 | — | 0.0000 | 0.0000 |
| `mimo_self` | 0 | 0 | 0 | — | 0.0000 | 0.0000 |
| `mimo_cross` | 3 | 2 | 1 | 33.3% | −0.0028 | +0.0139 |

- 合计撤销 4/236（TP 3 / FP 1），撤销精确率 25.0%；正例 FP 基准率 18.3%–19.0%；超几何检验不显著（Holm $p=1.0$）。
- `insufficient` 106/236，`unsupported` 只有 4 条；模型很少给出可用的具体反证。
- 原验证器主口径在同一批正例上撤销 155 条；两者相差约 39 倍。
- 成本 $0.151758；与原验证器同一量级；随机/低置信基线增量成本为 0。

判定：**判定语义修对了（不再把“无法证明”当“已反驳”），但检测收益为负结果；验证器退化为惰性步骤。**

---

## 4. 成功/失败解释（压缩版）

| 实验 | 表面结果 | 机制解释 | 应写成的结论 |
| --- | --- | --- | --- |
| G0 | 覆盖率采集 140/140，并集 70/0/70/0 | 行覆盖只排除“没执行”，不能排除“执行了但泄漏”；12 个漏报全是 line-complete；branch gate 把代码形状当质量信号 | 测量成功，门禁失败；`clean` 只能写成“该次执行的可达行走完”，不是“无泄漏” |
| B1 | 长度规则 0.511 > LLM 0.422 | 80% 正例 + macro-F1 奖励多报；LLM 操作点保守（pred+ 28.8%）；长度规则在短函数全报；MCC 只有 0.094 | 简单规则是诊断基线，不是检测器；macro-F1 与 MCC 必须并列 |
| P1 | diff 62.22/60.56，ctrl 60.00/62.22 | 修复版本系统性更长（130/180）；diff 增加 token 但不改变长度方向；changes-first 门控丢 pair；弃权抵消 committed 信号 | diff 无显著收益；单序/强制 DA 不能作为跨版本推理证据 |
| C1 | 0.9857 vs CodeQL 0.8173，vs direct 0.9571 | v2 修掉 realloc 误删；3 个 `_22` 靠字段一致性规则；direct 本身已 0.9571；Juliet 变体可记忆 | 相对 CodeQL 强，相对 direct 不显著；最终行是“CodeQL + 规则 + LLM”的组合，不是纯 LLM |
| V1 | 4/236 撤销，macro-F1 不升 | 具体反证覆盖率极低（4/236）；模型倾向 `insufficient`；没有 FP/TP 排序信号（AUROC 0.28–0.46） | 语义修正正确，但没有检测收益；不要再用“二次验证提升检测”的框架 |

跨实验共同机制：

1. **函数级标签缺上下文**：检测、配对、验证器都反复出现“取决于调用者/未提供的实现”。
2. **操作点与排序混淆**：macro-F1 在 80% 正例上奖励多报；MCC/AUROC 才暴露排序弱。
3. **证据不可检查**：LLM 的“守卫/反例”没有编译/执行验证；CodeQL 的 may 查询没有 `code_flows`；diff 的变更清单没有安全语义。
4. **小样本 + 单次运行**：40 个项目、23 个 FP、4 个撤销，CI 很宽；不能把点估计当稳定优势。

---

## 5. 下一阶段优先级

| 优先级 | 动作 | 成功线 | 停止规则 | 成本 |
| --- | --- | --- | --- | --- |
| **P0** | 冻结本轮口径：所有检测表并列 macro-F1 + MCC + pred+；所有配对表报交换一致 DA + 方向平衡；所有动态 `clean` 带行/分支覆盖与 free 站点；所有 triage 报 TP 误删 | 报告不再出现单指标“提升” | — | 0 |
| **P0** | 把“长度/常量基线”加入主表；把 `alloc_or_mem` 作为 MCC 参照 | 读者能看到 0.444/0.511/0.183 | — | 0 |
| **P1** | 预注册的长度中性化 pair 复现（新 holdout，非 test-seen）：填充空白/注释到 ≤2% 长度差，方向平衡 88 对作为敏感性 | MiMo ≥60% 且 >50% 至少 10 pp；DeepSeek ≥55% | MiMo fshorter 两序都对 <40% 则停止 | 约 $2–3 |
| **P1** | CodeQL `_33` 的 must-free 支配证人：先做 20 个 `_33` 单元，要求“所有路径上的 free”而不是“存在 free” | 删 15 FP、留 5 TP；全量 P≥0.90/R≥0.90 | 不能同时保住 5 个 `_33` TP 则停止 | 本地，0 API |
| **P1** | 外部 oracle 替代 LLM 验证器：编译 + LSan/Valgrind + 最小 PoC；验证器只做“触发人工复核” | 固定预算撤销精确率 ≥40% 且 TP 损失 ≤10% | 仍无排序信号则放弃二次验证 | <$1 + 本地 |
| **P2** | 检测任务改造：语句级/差异行，或真实调用者/被调用者上下文 | MCC ≥0.15 且 macro-F1 ≥0.53 | dev pilot MCC <0.10 则停 | $0.4–0.6 |
| **P2** | 真实项目/跨 CWE 的 CodeQL 告警人评 20–50 条 | 报告 TP/FP、TP 误删、成本 | 无法获得人评则只写 Juliet | 中 |
| **P2** | 多 seed / 多温度重复，报决策翻转率与方差 | 翻转率与主结论方向一致 | — | 3–5× |

**如果只能做一个**：先做 P0 的口径冻结 + P1 的零 API `_33` 证人。理由：它们不需要新模型调用，且直接决定“pair 86.67%”和“CodeQL 0.9857”能不能继续写。

---

## 6. 复现命令（WSL，项目根目录）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# G0 动态覆盖率
python3 dynamic_coverage/run_dynamic_coverage.py --help   # 入口；已有 runs/test140_coverage_v1
python3 - <<'PY'
import json; d=json.load(open('dynamic_coverage/runs/test140_coverage_v1/metrics.json'))
print(d['coverage_overall'])
PY

# B1 可解释基线
python3 interpretable_baseline/run_baseline.py --help
# 结果：interpretable_baseline/results/main_20261122c/metrics.json

# P1 差分配对
python3 pair_diff/selftest.py
bash pair_diff/run_pair_diff.sh analyze
# 结果：pair_diff/results/comparison.json / summary.md

# C1 CodeQL triage
python3 codeql_triage/selftest.py
python3 codeql_triage/analyze.py \
  --run-dir codeql_triage/runs/test140_mimo_xiaomi_v2 \
  --out codeql_triage/runs/test140_mimo_xiaomi_v2/analysis \
  --label mimo-v2.6-flash-xiaomi-v2

# V1 保守验证器
python3 verifier_conservative/selftest.py
python3 verifier_conservative/analyze_conservative.py
```

编译报告：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
~/tools/tectonic/tectonic -X compile report/report_next_zh.tex --outdir report --keep-logs
pdfinfo report/report_next_zh.pdf
pdffonts report/report_next_zh.pdf
```

---

## 7. 限制（必须与结果一起读）

1. **Juliet 记忆化**：清洗去掉了标签/路径/CWE/`bad|good` 标识符，但保留控制流结构、宏展开后的 `printLine` 序列；2026 的告警裁决研究报告 o4-mini 能重建清洗后的 Juliet 原始身份。0.9857 可能含“见过这个变体”的成分。
2. **单次采样**：没有多 seed/多温度；不能区分“方法稳定”与“这次采样恰好”。
3. **test-seen**：验证器的三路提示与判定规则是在看到 test 160 结果后设计的；`analysis_status=exploratory_post_hoc_test_seen`，不是独立确认。
4. **提示敏感**：CodeQL triage v1 → v2 只改提示，TP 误删从 7 降到 0、FP 撤销从 18 升到 20；0.9857 不是“方法”的稳定性能。
5. **成本是配置价**：不是发票；无人类复核成本；CodeQL 建库算力没有折成钱。
6. **无真实项目/跨 CWE**：只 CWE-401、只 Juliet；不能外推到 CWE-416/415/476 或真实 C/C++ 项目。
7. **无人工标签审计**：Juliet 的 bad/good 由宏门控唯一决定；23 个 FP 的“正确撤销”按标签判，不是按真实释放路径判。
8. **小样本**：40 个项目、23 个 FP、4 个撤销；Wilson/聚类 bootstrap CI 很宽，不能把点估计当稳定优势。

---

## 8. 产物地图

| 路径 | 内容 |
| --- | --- |
| `codeql_triage/REPORT.md` / `HANDOFF.md` / `benchmark_export.json` | CodeQL triage 全量报告、交接、可导入导出 |
| `dynamic_coverage/README.md` / `runs/test140_coverage_v1/metrics.json` | 覆盖率方法、逐模式/并集指标、门控视图 |
| `interpretable_baseline/REPORT.md` / `results/main_20261122c/metrics.json` | 规则/LR 主表、McNemar、test-tuned 上界、错误分析 |
| `pair_diff/results/report.md` / `results/comparison.json` | 六条件主表、Holm、长度分层、变更接地、成本 |
| `verifier_conservative/analysis/report.md` / `metrics.json` | 四臂判定、撤销构成、AUROC、成本 |
| `research/next_iteration_rationale.md` | 五个欠缺的只读复核、N1–N4/G0 设计、2024–2026 文献 |
| `report/report_next_zh.tex` / `.pdf` | 本报告 |
| `report/references_next.bib` | 本报告参考文献 |

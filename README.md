# SecVulEval + Juliet：分层漏洞检测与修复评测

本仓库是 CS224 课程项目的**真实实验产物、评测协议与复现材料**。项目把两类漏洞评测放在同一套契约下，但**分层报告、绝不跨层合并**：

| 层级 | 数据集 | 评什么 | 主终点 |
| --- | --- | --- | --- |
| **Tier A** | SecVulEval 真实项目 C/C++ 函数 | LLM 在跨 CWE 真实代码上的检测与配对判别 | 检测 `macro-F1`；配对 `DA` |
| **Tier B** | Juliet CWE-401 合成用例 | 静态、动态、LLM、AI+传统工具在同一 CWE 上的比较 | 泄漏 `macro-F1` + `MCC`，强制报告 coverage |

两层的数据来源、标签语义、单元结构、类别先验和成本口径都不同。把 160 个真实函数和 Juliet 变体池化成一个“平均 F1”没有解释力，因此本项目只做**统一契约下的分层比较**。

> 所有报告数字都来自已落盘的运行产物；没有用 mock、fixture 或估计值填充正式结果表。`selftest` 和临时 fixture 只用于工具自检，不是实验结果。
>
> **审计状态分三代，不能混用。** 旧一轮只读审计 [`audit/final_audit.md`](audit/final_audit.md)（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`**，覆盖 v2/postleakfix 工作树；它**早于** 2026-11-13/14 的 `pair_debias`、`evidence_verify`、`dynamic_enhanced`、`hybrid_dynamic_enhanced`、CodeQL、`analysis/schema_recovery` 与 `benchmark/extensions`，**不覆盖**这些新产物。
>
> **2026-11-14 审计：** [`audit/latest_audit.md`](audit/latest_audit.md)，**Overall `PASS`：56 PASS / 0 FAIL / 0 WARN（56 checks）**，覆盖 11-13/14 六个新结果组；先前的 A6（缓存复用披露）、E6（F1(V) 标注）、F4（schema 成本价卡）、G3（文献快照时效）已修复。旧审计的 3 个 WARN（B5/D5/F4）仍见 §8。
>
> **2026-11-22 下一轮审计：** [`audit/next_iteration_audit.md`](audit/next_iteration_audit.md)，覆盖本轮五个新目录（`interpretable_baseline`、`pair_diff`、`codeql_triage`、`verifier_conservative`、`dynamic_coverage`）与 `research/next_iteration_rationale.md`；当前为 **Overall `PASS_WITH_WARNINGS`：40 PASS / 0 FAIL / 1 WARN（41 checks）**。当前仅剩 E5 方法学 WARN（预注册时间戳不可从产物验证）；F3/F4 已修复；本 README 已改用 `audit/next_iteration_audit.md` 与 `benchmark/results/NEXT_ITERATION.md`）。发布门禁 FAIL=0，但 WARN 必须与结果一起读；审计重跑后以文件 `Overall:` / `Checks:` 行为准。本轮数字均为**单次运行**；`verifier_conservative` 是 post-hoc/test-seen，`codeql_triage` 只有 MiMo 有结果，不能当作独立确认。


## 0. 2026-11 主线：Juliet CWE-401 全集 — *Near-Cloud Quality on a Local Device?*

> 2026-11-23/24 起，课程展示与最终报告的主线是 **Juliet v1.3 CWE-401 全集（1,658 组 / 3,316 单元）上的内存泄漏检测**：
> 同一任务上比较云端模型（DeepSeek-flash、Jev）、本地模型（Qwen3.5-4B 生成式 / 读出、Intern-Decision-4B、我们微调的 Qwen3.5-4B LoRA）、静态分析器与动态参考线。
> 下文 §1–§8 是此前 SecVulEval + Juliet test140 的分层评测，仍保留；SecVulEval 只进附录。

| 想看什么 | 位置 |
| --- | --- |
| 计划、全部已定决策与理由 | [`PLAN.md`](PLAN.md) |
| 进度与决策日志（最新在上）、产物哈希、预算 | [`juliet_full/STATUS.md`](juliet_full/STATUS.md) |
| 数据格式与各子目录分工契约 | [`juliet_full/README.md`](juliet_full/README.md)，各 lane 报告 [`juliet_full/lane_reports/`](juliet_full/lane_reports/) |
| 切分（dev 9 个流变体 + eval 3 折，按流变体分组） | [`juliet/full_split_v1.json`](juliet/full_split_v1.json)，[`juliet/scripts/split_full.py`](juliet/scripts/split_full.py) |
| 四层数据：Original / Debiased / DeadFree / Placebo | [`juliet_full/data/`](juliet_full/data/)（`build/{original,layer1,layer3,placebo}.jsonl`，`build/subsets.json`，`build/SHA256SUMS`） |
| 静态（Clang SA、CodeQL、Infer、Cppcheck、grep）与动态（ASan/LSan、Valgrind、增强动态）结果 | [`juliet_full/static/`](juliet_full/static/)，[`juliet_full/data/results/`](juliet_full/data/results/) |
| 云端与生成式模型 L1–L4（提示、调用账本、结果） | [`juliet_full/llm/`](juliet_full/llm/) |
| 本地服务、Intern-Decision、LineVul、VulnLLM-R-7B | [`juliet_full/gpu/`](juliet_full/gpu/)，[`juliet_full/vulnllmr/`](juliet_full/vulnllmr/) |
| 旧 LoRA（L1/L3，单元标签）与 L4-D LoRA（事实标签 + Datalog） | [`juliet_full/decision_ft/`](juliet_full/decision_ft/)，[`juliet_full/l4d/`](juliet_full/l4d/)（站点、问题、动态金标、`l4d.dl`），[`juliet_full/l4d_ft/`](juliet_full/l4d_ft/) |
| DeadFree 质量 / c1 延迟 / 成本表 | [`juliet_full/analysis/deadfree/`](juliet_full/analysis/deadfree/)（`deadfree_quality.*`，`latency_deadfree.csv`，`cost_deadfree.*`） |
| 课程展示（Beamer，英文）与现场演示 | [`presentation/pre/main.pdf`](presentation/pre/main.pdf)（讲稿 `notes.md`），[`presentation/demo/`](presentation/demo/)（录屏 `recordings/stage_final_v2.*`） |
| 论文（IEEE conference）与新版 proposal | [`report/final_en/`](report/final_en/)，[`proposal/v2/`](proposal/v2/) —— 二者尚未同步到新标题与 DeadFree 主线，以 slides 为准 |

**DeadFree eval（2,656 单元）主要结果**（macro-F1；并发 1 的中位延迟；每 1,000 单元成本）：

| 方法 | macro-F1 | 延迟 | $/1k |
| --- | --- | --- | --- |
| DeepSeek-flash L1 / L4（云） | 0.863 / 0.900 | 0.895 s / 1.008 s | 0.065 / 0.110 |
| Jev L3（云，最佳） | 0.949 | 0.923 s | 0.039 |
| Qwen3.5-4B 生成式 L1（本地，未调） | 0.533 | 0.347 s | — |
| Qwen3.5-4B 读出 L4-D（本地，未调） | 0.752 | — | — |
| **FT L4-D（ours，Qwen3.5-4B + LoRA，单张 RTX 3090）** | **0.826** | **0.472 s** | 0.070（租用）/ 0.006（仅电费） |
| Clang SA（静态） | 0.855 | 0.019 s | — |

FT L4-D 弥合了本地基线到 DeepSeek L1 差距的 89%，比 DeepSeek L1 快 1.9×，代码不出本机；但按预注册标准（≥ DeepSeek L1 − 0.02）**尚未达到 near-cloud**。

**不在仓库中的内容**（体积大或可再生成）：Juliet 原始压缩包与解压目录（`juliet/scripts/fetch_juliet.py` 下载，SHA-256 `ada9d7e1…f38eb`）、编译后的程序目录 `juliet_full/data/build/programs*/`、L4-D 问题/站点文件 `juliet_full/l4d/build/{questions,sites}_*.jsonl`、训练数据渲染与检查点、各 `.venv/`、`raw_logs/`、`scratch/`；LoRA 适配器（每折约 130 MB）只保存在训练服务器上。API 密钥放在被忽略的 `.env`（`DEEPSEEK_API_KEY`、`TYPESAFE_API_KEY`），不入库。

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
- **单序 A/B 的 76.67%/86.67% 不是稳定的跨版本推理。** 反向重复后，交换一致 DA 只剩 61.67%（DeepSeek）/74.44%（MiMo）；两序“选较短版本”启发式为 72.22%，DeepSeek 显著低于它（p=0.0145），MiMo 仅高 2.22 pp（p=0.644，不显著）。开放四分类把位置偏差压到不显著，但 17.22%–22.22% 的输出是 `both`/`neither`，总体 DA 只有 63.89%–66.11%。
- **动态增强把 12 个旧 ASan 不可观测的 bad 变成了可复核证据。** `realloc_fail` + `nogobal` 与 `default` 的并集在 test 140 上为 70 TP / 0 FP / 70 TN / 0 FN；但把这份证据交给 LLM 只到 137/140（DeepSeek）和 136/140（MiMo），相对 direct +2/0，Holm 后均不显著。
- **二次验证没有选择性撤销假阳性。** 四个臂的撤销精确率仅 14.3%–23.1%（正例中 FP 基准率 18.3%–19.0%），Holm p≥0.8367；post macro-F1 低于 pre。它把操作点变保守，不是判别力提升。
- **CodeQL 用召回换精确率。** test 140 端到端 68 TP / 23 FP / 47 TN / 2 FN（P 0.747、R 0.971、macro-F1 0.817、MCC 0.674），Clang 为 53/0/70/17（macro-F1 0.877、MCC 0.781）；23 个误报全部是 C++ good 单元。
- **schema 失败主要是可回收的格式问题，不是修复能力。** DeepSeek 102 条 invalid 中 93 条只缺 `explanation`；code-only admission 把 usable patch 从 552/924 提到 619/924（+7.25 pp），但 usable 只是结构代理（L0），不是编译/测试/PoC 正确率。
- **2026-11-22 的下一轮把“弱点是模型不够强”改写成“指标与证据口径”。** 可解释基线 `length_short` 的 macro-F1 0.511 高于全部 8 个 LLM，但 MCC 只有 0.094；换 MCC 后 `alloc_or_mem` 0.183 最高，仍没有可用检测器。`pair_diff` 的 diff−ctrl 只有 +2.22/−1.67 pp（Holm 后不显著），没有降低“选较短”。CodeQL 分流在 MiMo 上做到 68/0/70/2，但相对 direct 不显著，且 DeepSeek 无结果。
- **验证器与覆盖率都给出负结果。** 保守三路验证器 236 条只撤 4 条（精确率 25.0%，与 FP 基准率不可区分）；动态覆盖率显示原路径 12 个漏报全部是 `supported_clean_but_bad`，100% 行覆盖不能给 clean 背书，只有三模式并集到 70/0/70/0。

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

2026-11-14 的扩展层（pair_debias、evidence_verify、dynamic_enhanced、hybrid_dynamic_enhanced、CodeQL、schema_recovery）在 `benchmark/results/EXTENSIONS.md` 与 `extension_summary.json` 中单独汇总；主 leaderboard 只加链接，不导入其数字，也不与 Tier A/B 池化。

2026-11-22 的五个新目录（`interpretable_baseline`、`pair_diff`、`codeql_triage`、`verifier_conservative`、`dynamic_coverage`）通过 `benchmark/extensions` 的 `next_iteration_batch` 只读导入，汇总与成功线见 [`benchmark/results/NEXT_ITERATION.md`](benchmark/results/NEXT_ITERATION.md)；同样不进入父主表，不与 Tier A/B 池化。

### 2.3 创新与诊断实验

| 目录 | 实验 | 回答的问题 |
| --- | --- | --- |
| `pair_joint/` | 联合 A/B 强制二选一 | 把两个版本放在一次请求里，配对判别能提升多少？多少来自长度/位置？ |
| `evidence_prompt/` | 证据行 + 机制 + 反事实修复 | 结构化提示提高的是判别力，还是只把操作点推向“多报”？证据行能定位吗？ |
| `hybrid/`（v2 主结果） | 静态/动态/组合/安慰剂证据 | 工具证据在 Juliet 140 上有没有超出格式/长度安慰剂的边际收益？ |
| `juliet_repair/` | 编译 + LSan + 行为差分 | 模型补丁是否真的编译、消除泄漏、保持可观测行为？ |
| `juliet_llm/` | Juliet LLM 直接二分类 | 在去标签、去路径、去 CWE 的源码视图上，LLM 能检测 CWE-401 吗？ |
| `repair_eval/` | 修复质量盲评 | 在固定 rubric 下，LLM 辅助评审认为补丁处理了根因吗？ |
| `pair_debias/` | A/B 反向重复 + 开放四分类 + 长度匹配 | 单序 DA 有多少来自位置？控制位置后还超过长度启发式吗？ |
| `evidence_verify/` | 正例二次验证/撤销（4 臂） | 验证器能选择性撤销假阳性吗，还是只是把操作点变保守？ |
| `dynamic_enhanced/` | `realloc` 故障注入 + LSan 全局根控制 | 旧 ASan 看不到的 12 个 bad 能否变成可复核证据？ |
| `hybrid_dynamic_enhanced/` | 增强动态证据 + LLM（两模型） | 新证据提升判定，还是只被复述？ |
| `static_extended/` | CodeQL CWE-401 扩展静态基线 | 新静态工具的召回/误报与 Clang/Cppcheck 如何？ |
| `analysis/schema_recovery/` | 零 API schema 复分析 | 102 条 invalid 里有多少只是可回收的格式问题？ |
| `benchmark/extensions/` | 8 个 design 的 canonical 接入层 | 新方法如何在不改父协议的前提下汇总？ |
| `interpretable_baseline/` | 可解释非 LLM 基线（dev40 → test160） | LLM 的 0.383 是否低于“不看代码”的长度/内存 API 规则？macro-F1 与 MCC 会不会给出相反排名？ |
| `pair_diff/` | 差分 + changes-first + 长度匹配对照（两序） | 把实际 diff 摆出来，能否把配对判别从“选字母/选较短”中分离出来？ |
| `codeql_triage/` | CodeQL 告警的 LLM 所有权/释放路径分流 | 23 个 C++ FP 能否在不误删 TP 的前提下撤销？相对 direct 是否显著？ |
| `verifier_conservative/` | 保守三路验证器（supported / unsupported / insufficient） | 把“未证明”与“已反驳”分开，能否救回验证器的选择性？ |
| `dynamic_coverage/` | gcov 行/分支覆盖 + 三模式对齐 | 140/140 的 `clean` 到底执行了多少？覆盖率能否给 clean 背书？ |

2026-11-22 的下一轮由 [`research/next_iteration_rationale.md`](research/next_iteration_rationale.md) 预先定义五个最弱环节与成功线；实验汇总见 [`report/report_next_zh.pdf`](report/report_next_zh.pdf)（源稿 [`report/report_next_zh.tex`](report/report_next_zh.tex)），benchmark 接入层见 [`benchmark/results/NEXT_ITERATION.md`](benchmark/results/NEXT_ITERATION.md)。这些结果不进入父 leaderboard 的主行，也不与 Tier A/B 池化。

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

### 3.4 2026-11-13/14 一轮（新增，尚未进入主 leaderboard）

这一轮补的是“收益是不是真的”，而不是再换模型：位置/长度、验证器选择性、动态不可观测单元、证据被复制、静态工具召回、schema 可回收性。全部为单次运行；除 `analysis/schema_recovery` 外都调用过真实模型或工具。

| 实验 | 主数字 | 诚实结论 |
| --- | --- | --- |
| A/B 反向重复（`pair_debias`） | DeepSeek 正/反序 76.67%/77.78%，交换一致 61.67%；MiMo 86.67%/81.67%，交换一致 74.44%；两序长度启发式 72.22%；DeepSeek vs 启发式 p=0.0145（Holm 0.0289），MiMo p=0.644；开放 DA 63.89%–66.11%，弃权 17.22%–22.22%，committed 77.18%–84.40%；1,080 条记录（1,029 新请求 + 51 缓存复用）$0.676605，合计 1,440 请求 $0.902001 | 单序 DA 的增量主要来自位置：强制条件下“只对一序”的配对全部是两序同字母（DeepSeek 56/56，MiMo 35/35）。控制位置后 DeepSeek 显著低于长度启发式，MiMo 不显著高于它。开放格式降低位置偏差，但用弃权换覆盖。 |
| 正例二次验证（`evidence_verify`，4 臂） | post macro-F1 0.2181/0.3522/0.3221/0.2226；撤销精确率 20.4%/23.1%/14.3%/21.6%；超几何 Holm p=0.8380/0.8380/0.8494/0.8367；事后 refutation-only 规则 macro-F1 0.3645–0.4075 | 验证器撤销的 TP 远多于 FP，未显示“识别假阳性”。主规则几乎撤销全部正例是 `insufficient_evidence` 语义所致；事后规则没有预注册，只能作敏感性。 |
| 动态增强（`dynamic_enhanced`） | test 140：70 TP / 0 FP / 70 TN / 0 FN；12 个旧不可观测 bad 全部有证据；`default` 与旧 ASan 判定 140/140 一致；新模式并集 vs 旧 128/140，差异恰好 12 个 bad；140 单元 × 3 模式 315.6 s | 7 个 `malloc_realloc` 由真实 `realloc` 失败注入、5 个 `_68` 由关闭 LSan 全局根解决；good 0 FP。`clean` 仍只是单路径观测，不是无泄漏证明。 |
| 增强证据 + LLM（`hybrid_dynamic_enhanced`） | DeepSeek 135→137/140（97.86%，p=0.5）；MiMo 136→136/140（97.14%，p=1.0）；工具 140/140；280 请求 $0.023561；字节数复述率 92.86%/88.57% | 工具满分使“照抄”与“独立判断”不可分；增益不显著；证据被读取和引用，但没有语义推理提升。 |
| CodeQL 扩展静态（`static_extended`） | test 140 端到端：68 TP / 23 FP / 47 TN / 2 FN；P 0.7473、R 0.9714、macro-F1 0.8173、MCC 0.6739（canonical 导入 valid-only macro-F1 0.8259）；Clang：53/0/70/17，macro-F1 0.8768、MCC 0.7805；200 单元 194 ok、6 compile_error；墙钟 1,434.7 s | CodeQL 补回 15 个 Clang 漏掉的 bad、未漏 Clang 检出的 bad；代价是 23 个 C++ good 误报。召回更高、精确率和 MCC 更低，不能写成“更好的工具”。 |
| schema 复分析（`analysis/schema_recovery`） | DeepSeek repair 924 请求：official 822（88.96%）、code-only 915（99.03%）、usable 552→619（+7.25 pp）；102 invalid = 93 missing explanation + 9 truncation；salvage usable 67（canonical）/69（K&R-aware）；MiMo 61 条 field drift，label 一致仅 28/61；0 API | 格式门槛只解释 7.3–7.9 pp；从 code-only 到 usable 仍有约 32 pp 是 no-change/空白/注释/结构问题。salvage 不是正确率，oracle 级别 L0。 |
| canonical 扩展层（`benchmark/extensions`） | 8 个 design、16 个 canonical run：pair_debias 8、evidence_verify 4、dynamic_enhanced 1、hybrid_dynamic_enhanced 2、CodeQL 1；16/16 校验通过，16 项父指标 + 37 项设计算术 0 不一致；汇总在 `benchmark/results/EXTENSIONS.md` / `extension_summary.json` | 只读导入，不是新实验；八个 design 各有主终点，不能池化；父 schema/PROTOCOL 未改，LEADERBOARD 只加链接不导数字。 |

读法：这一轮的主结论是**负结果和口径修正**，不是新的 SOTA。特别是 (1) 单序 A/B 必须同时给交换一致 DA 与两序长度基线；(2) 验证器的“撤销”必须与同预算随机/廉价规则比较；(3) 动态 `clean` 的 70/70 只成立于三种条件模式的并集；(4) 工具 140/140 时 LLM 准确率无法区分照抄与推理；(5) CodeQL 的高召回伴随 23 个 C++ 误报；(6) schema salvage 只到结构代理。

来源：`pair_debias/report.md`、`evidence_verify/analysis/report.md`、`dynamic_enhanced/runs/test140_enhanced_v3/metrics.md`、`hybrid_dynamic_enhanced/REPORT.md`、`static_extended/runs/codeql_20261114_cwe401_full/comparison_test140.md`、`analysis/schema_recovery/schema_recovery.md`、`benchmark/extensions/README.md`。

### 3.5 2026-11-22 下一轮：五个弱点的复核、四个实验与一个覆盖率门禁

这一轮不再换模型，而是对 §3.4 暴露的五个最弱环节逐条做“先写成功线、再跑”的复核。设计、失败解释与文献映射在 [`research/next_iteration_rationale.md`](research/next_iteration_rationale.md)（N1–N4 + G0 的原始成功线）；本轮实际落地为 `interpretable_baseline`、`pair_diff`、`codeql_triage`、`verifier_conservative`、`dynamic_coverage` 五个目录，其中 N1 的 LLM 先验校准臂没有跑，改做非 LLM 基线诊断。实验汇总在 [`report/report_next_zh.pdf`](report/report_next_zh.pdf)（12 页；源稿 [`report/report_next_zh.tex`](report/report_next_zh.tex)，统一摘要 [`report/next_results_summary.md`](report/next_results_summary.md)）；benchmark 只读接入层在 [`benchmark/results/NEXT_ITERATION.md`](benchmark/results/NEXT_ITERATION.md)；发布审计在 [`audit/next_iteration_audit.md`](audit/next_iteration_audit.md)。全部为单次运行；`verifier_conservative` 是 test-seen 的事后实验，`codeql_triage` 只有 MiMo 有结果。

| 弱点（旧数字） | 复核后的原因 | Idea / 本轮实验 | 结果（单次运行；括号内为判定） |
| --- | --- | --- | --- |
| **1. Tier A 检测低于平凡基线。** DeepSeek direct macro-F1 0.3828、MCC 0.0414；只报 46/160 为正，低于“全判漏洞”的 0.4444。 | 主要是操作点/先验（test 80% 正例）与函数级标签缺上下文；长度伪相关；置信度对排序几乎没有信息（AUROC 0.540）。 | `interpretable_baseline/`：dev40 固定 7 条规则 + 2 个 LR，test160 只评一次；另报 test-tuned 上界。 | `length_short` macro-F1 **0.511**（高于 8 个 LLM 的 0.346–0.422），但 MCC 仅 **0.094**；`alloc_or_mem` MCC **0.183**（F1 0.387）最高；多数类 0.444；`lr_balanced` 0.391 / MCC −0.131；test-tuned 上界约 0.60 F1 / 0.21 MCC。（**未达预注册的 Tier A 组合成功线（MCC≥0.15 且 F1≥0.53）；“简单规则优于 LLM”只在 macro-F1 口径成立，换 MCC 排名翻转；没有强检测器。**） |
| **2. 单序配对 DA 被位置/长度抬高。** forced 76.67%/86.67%，交换一致仅 61.67%/74.44%，两序长度启发式 72.22%。 | 修复版本通常更长，长度方向决定答案；DeepSeek 有明显槽位偏好；开放四分类仍有 17%–22% 弃权。 | `pair_diff/`：完整 diff + changes-first，配 token 长度匹配的空占位块对照；A/B 两序；只读复用 `pair_debias` open。 | 交换一致 DA：DeepSeek diff **62.22%** / ctrl 60.00% / open 55.56%；MiMo **60.56%** / 62.22% / 58.33%。diff−ctrl **+2.22/−1.67 pp**（Holm p=1.000/0.905），diff−open +6.67/+2.22 pp（Holm 0.0855/1.000）。选较短比例 75.17%–81.20%，不低于 open；changes-first 门控在 20/180、36/180 对几乎全部判 `neither`（DA=0）。（**点估计高于 60%/55% 门槛，但 diff−ctrl 为 0；不能把过线归因于 diff，也不能写“diff 减少长度捷径”。**） |
| **3. CodeQL 高召回换精确率。** 68 TP / 23 FP / 2 FN，P 0.7473、R 0.9714、MCC 0.6739；23 FP 全是 C++ good。 | 23 FP 不是随机噪声，而是 4 个可命名模式（`_33` 别名/遮蔽、`_22` 全局+跨函数 delete、`_72` vector、`_54` wrapper）；全部来自 `cpp/memory-may-not-be-freed`。 | `codeql_triage/`：LLM 按所有权/别名/全局/跨函数释放分流；v1 一次性、v2 先判 `leak_present` 并写明 realloc 失败路径，再做一致性复核。 | 最终 **68 TP / 0 FP / 70 TN / 2 FN**，P **1.0000**、R 0.9714、macro-F1 **0.9857**、MCC **0.9718**；vs CodeQL +0.1684（p<1e-6），vs direct +0.0286（95% CI 跨 0，p=0.289，**不显著**）。v2 一次性是 68/3/67/2，3 个 `_22` 由二次一致性复核翻转；零成本文本一致性规则与复核同判，说明第二次 API 不是必需的。v1 误删 7/68 TP，v2/最终 0/68。（**预注册的 CodeQL 分流成功线通过（MiMo）；只能写“对 CodeQL 显著、对 direct 不显著”，且 DeepSeek 因 402/401 无结果。**） |
| **4. 验证器把 TP 和 FP 一起撤。** 四臂撤销精确率 20.4%/23.1%/14.3%/21.6%，post macro-F1 下降 0.070–0.204；`insufficient_evidence` 占撤销 67%–71%。 | fail-closed 把“未证明”当成“已反驳”；验证器置信度对 FP/TP 的 AUROC 只有 0.28–0.46（低于随机）。 | `verifier_conservative/`：三路 `supported/unsupported/insufficient`；只有带行号的 `guard_present` 或 `counterexample` 才撤销；失败保留第一遍。 | 236 条请求只撤销 **4 条**（TP 3 / FP 1），撤销精确率 **25.0%**（正例 FP 基准率 18.3%–19.0%，Holm p=1.0）；Δmacro-F1 0 到 −0.0052；MCC 仅 `mimo_cross` +0.0139（CI 跨 0）；`insufficient` 106/236。（**预注册的验证器成功线失败：没有选择性排序信号；验证器退化为惰性步骤，需外部 oracle/CFG/执行反例。**） |
| **5. 动态 `clean` 没有覆盖率。** 140/140 的 clean 无行/分支覆盖；每模式单输入；`nogobal` 下 70/70 good 都有原始泄漏；14 个随机分支 FN。 | 无插桩；LSan 全局根语义；单输入不足；归因规则把工具链/运行时帧过滤掉，`clean` 只是单路径观测。 | `dynamic_coverage/`：gcov 行/分支覆盖，default + `realloc_fail` + `nogobal` 三模式逐单元对齐；raw/effective 行覆盖与归因分离。 | 覆盖采集 140/140；effective 行覆盖 **100%**、raw 99.9%、分支 **52.7%**、`branch_complete` 21/140（**0 good**）。default 58/0/70/12；三模式并集 **70/0/70/0**。12 个漏报全部是 `supported_clean_but_bad`；line gate 不纠错，branch gate 弃权全部 70 good；`realloc_fail` 新增 14 分支、`nogobal` 新增 0 行/0 分支；分配/释放站点 167/167、89/89。（**G0 形式过线、语义失败：`clean` 只能写 `executed_clean`，不能写 TN；100% 行覆盖不等于无泄漏。**） |

读法：这一轮的主结论仍是**负结果与口径修正**，不是新的 SOTA。(1) 在 80% 正例的 test 上，macro-F1 会把“多报”奖励成能力；`length_short` 的 0.511 只在 macro-F1 上“赢” LLM，MCC 0.094 仅比最好的 LLM（MiMo context 0.080）高 1.4 pp，远低于 `alloc_or_mem` 的 0.183；真正的结论是**没有方法超过 0.21 MCC**。(2) 把 diff 直接摆出来并没有降低长度捷径；交换一致 DA 相对长度匹配对照的差异为 +2.22/−1.67 pp，Holm 后都不显著。(3) CodeQL 的 23 个 FP 可被撤销，但一次性提示会误删 7/68 TP；最终 0 FP 可由零成本文本规则复现，代价是只有 MiMo、且相对 direct 不显著。(4) 保守三路验证器在语义上修正了 fail-closed，但 236 条只撤 4 条，检测收益为负；这说明“二次验证”缺少可排序的外部信号。(5) 覆盖率能解释 7 个 `malloc_realloc` 漏报（分支未走），但不能解释 5 个 `_68`（LSan 根集）；行覆盖 100% 与 12 个 `supported_clean_but_bad` 同时成立，是“clean 不是 TN”的最直接证据。

来源：[`interpretable_baseline/REPORT.md`](interpretable_baseline/REPORT.md)、[`pair_diff/results/report.md`](pair_diff/results/report.md)、[`codeql_triage/REPORT.md`](codeql_triage/REPORT.md)、[`verifier_conservative/analysis/report.md`](verifier_conservative/analysis/report.md)、[`dynamic_coverage/README.md`](dynamic_coverage/README.md)、[`research/next_iteration_rationale.md`](research/next_iteration_rationale.md)。

### 3.6 不能声称的事

- 不能把 Tier A 与 Tier B 的数字放在同一张排行榜，或计算“总体 F1”。
- 不能把 `hybrid_v1` 的 140/140、`juliet_repair` 的 58/58、`juliet_llm` 的 0.9500 直接写成“检测/修复达到 SOTA”。
- 不能引用 `hybrid_v1` 的 100% 作为当前混合主结果；泄漏修复后的 v2 已回落到 136/140。
- 不能把动态 `clean` 当成已验证的负例，或把静态 `compile_error` 当成 `y_pred=0`。
- 不能把联合 A/B 的增益全部归因于“跨版本推理”；长度、强制二选一和位置偏差都是已量化的混淆。
- 不能把证据行提示的召回提升写成“判别力提升”或“没有增加假阳性”。
- 不能宣称某个模型总体更强：12 个 run 的模型轴是 post-hoc，所有模型比较经 Holm 后都不显著。
- 不能把单序 `pair_joint` / `pair_debias` 的 76.67%/86.67% 写成跨版本推理；必须同时报告交换一致 DA 和两序长度启发式。
- 不能因为开放四分类 DA 更低就说模型“更差”；必须同时给弃权率和 committed 准确率。
- 不能把 `dynamic_enhanced` 的 70/70 外推为“动态检测 100%”；它是单 test split、三种条件模式的并集。
- 不能把 `hybrid_dynamic_enhanced` 的 +2 写成证据带来的语义提升；工具满分、增益不显著。
- 不能把 CodeQL 的高召回写成“优于 Clang”；它的精确率/MCC 更低，23 个 FP 全是 C++ good。
- 不能把 `schema_recovery` 的 usable 当作修复正确率；它没有编译/测试/PoC。
- 不能把 `interpretable_baseline` 的 `length_short` 0.511 写成“简单规则比 LLM 更会检测”；它只在 macro-F1 上高于 LLM，MCC 0.094，且 test 正例率是 80%。换 MCC 后 `alloc_or_mem` 0.183 最高，但仍远不是可用检测器。
- 不能把 `pair_diff` 的 diff 写成“减少长度捷径”或“恢复跨版本推理”；diff−ctrl 的交换一致差异 +2.22/−1.67 pp，Holm 后不显著，选较短比例没有下降。
- 不能把 `codeql_triage` 的 68/0/70/2 写成“LLM triage 全面优于 direct”；相对 direct 的 +0.0286 不显著，且只有 MiMo、没有 DeepSeek 结果。必须同时报告 v1 的 7/68 TP 误删，并说明 0 FP 可由零成本文本一致性规则复现。
- 不能把 `verifier_conservative` 的 4/236 撤销写成“验证器有效”；撤销精确率 25.0% 与 FP 基准率 18.3%–19.0% 不可区分，macro-F1 不升。
- 不能把 `dynamic_coverage` 的 100% 行覆盖写成“无泄漏证明”；原路径 12 个 `supported_clean_but_bad` 全部是 effective-line-complete，只有三模式并集才到 70/70。

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
│   ├── LITERATURE.md             # 文献索引：2025–2026 最新调研与引用分级
│   └── GITHUB_RELEASE.md         # GitHub 私有仓库发布步骤、门禁与推送验证
├── audit/                        # 三代只读审计（旧一轮 / 2026-11-14 / 2026-11-22）
├── SecVulEval.xlsx               # 上游数据集（18.8 MB，保留）
├── build_datasets.py             # 从 Excel 抽样生成 datasets/
├── datasets/                     # 200 独立函数 + 200 对（JSON）
├── splits/                       # secvul-split-v1 冻结划分与 few-shot 示例
├── runner/                       # SecVulEval LLM runner（direct/few-shot/context）
├── mimo/                         # MiMo 兼容性排查与 12-run test 结果
├── analysis/                     # 三策略统计、bootstrap、McNemar、成本归一化、schema 复分析
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
│   ├── results/NEXT_ITERATION.md # 2026-11-22 五个弱点的只读接入与成功线
│   └── extensions/               # 8 个新 design 的 canonical 接入层（不改父协议）
├── juliet_llm/                   # Juliet LLM 直接检测（含 Xiaomi fallback）
├── hybrid/                       # 静态/动态/组合/安慰剂证据实验（v2 主结果）
├── hybrid_dynamic_enhanced/      # 增强动态证据 + LLM（test 140，两模型）
├── dynamic_enhanced/             # realloc 故障注入 + LSan 全局根控制（test 140）
├── evidence_prompt/              # 证据行/反事实提示（Tier A）
├── evidence_verify/              # 正例二次验证/撤销（4 臂，post-hoc）
├── pair_joint/                   # 联合 A/B 配对判别
├── pair_debias/                  # A/B 反向重复、开放四分类、长度匹配
├── static_extended/              # CodeQL CWE-401 扩展静态基线
├── interpretable_baseline/       # 长度/内存 API 等可解释非 LLM 基线（dev40 → test160）
├── pair_diff/                    # 差分 + changes-first + 长度匹配对照（两序）
├── codeql_triage/                # CodeQL 告警的 LLM 所有权/释放路径分流
├── verifier_conservative/        # 保守三路验证器（supported/unsupported/insufficient）
├── dynamic_coverage/             # gcov 行/分支覆盖 + 三模式对齐
├── juliet_repair/                # 编译/LSan/行为闭环修复评测
├── repair_eval/                  # 修复质量盲评工具与最终汇总
├── qualitative/                  # 10 个定性案例
├── report/                       # 中文 IEEE 报告源稿、PDF、结果摘要（含 report_next）
├── research/                     # 协议、相关工作、最新文献、创新结论与限制
├── proposal/                     # 课程 proposal 源稿与图
└── output/                       # 预留输出目录
```

每个模块目录都有 README 或分析报告，包含该模块的方法、产物、验证命令和限制（`evidence_verify/` 的主报告在 `analysis/report.md`）。根目录只负责总览与发布边界。

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
| CodeQL | 2.27.4（用户目录 bundle；`cpp-queries` 1.10.0；不进入仓库） |
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
python3 dynamic_enhanced/run_dynamic_enhanced.py selftest  # 故障注入/全局根 6 control
python3 pair_debias/selftest.py                     # 反向映射、开放解析、长度审计
python3 evidence_verify/selftest.py                 # 验证器 prompt、schema、撤销统计
python3 benchmark/extensions/tools/ext_selftest.py  # 8 design 合成 fixture
python3 analysis/schema_recovery/recover.py --selftest  # K&R/成本/计数断言
python3 -m repair_eval selftest                     # 盲评包/评分/kappa
python3 interpretable_baseline/run_baseline.py --resamples 2000 --out-dir /tmp/secvul_ib_check  # 本地基线，写 /tmp
python3 pair_diff/selftest.py                       # diff/ctrl 长度匹配、两序映射、解析
python3 codeql_triage/selftest.py                   # 140 单元、68 TP/23 FP、提示隔离
python3 verifier_conservative/selftest.py           # 三路提示、schema、判定真值表
python3 dynamic_coverage/run_dynamic_coverage.py selftest  # gcov 读取/并集 control
python3 benchmark/tools/bench_validate_dataset.py --jsonschema
```

这些命令只读冻结产物或在临时目录创建 fixture；不会调用模型，也不会覆盖正式结果。`interpretable_baseline/run_baseline.py` 会写一个新的 `results/` 子目录（默认拒绝覆盖），如果只想检查可以用 `--out-dir /tmp/...`。**注意：`evidence_verify/selftest.py` 当前在 `matched_budget_table` 处有 `NameError: valid_indices`（`evidence_verify/evidence_verify/baselines.py:458`）；在修复前不要把它当验收门禁。**

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

schema 复分析不调用模型，只读 12 个冻结 run；默认写本目录，复核时写到 `/tmp`：

```bash
python3 analysis/schema_recovery/recover.py --out-dir /tmp/secvul_schema_check
python3 analysis/schema_recovery/recover.py --check
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

#### 5.4.1 扩展静态：CodeQL（新增，需本地 418 MB bundle）

CodeQL CLI **2.27.4** + `codeql/cpp-queries` **1.10.0** 已对 200 个冻结单元完成真实运行（test 136/140 可分析，4 个 `_82` 与 Clang 同样 `compile_error`）。工具装在用户目录，不进入仓库；WSL 内 GitHub 直连可能被阻断，本机通过镜像下载并用官方 SHA-256 `393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d` 校验。安装与查询包下载步骤见 `static_extended/README.md` §2。

```bash
python3 static_extended/codeql_adapter.py \
  --units juliet/subset_units.jsonl \
  --juliet-root juliet \
  --out static_extended/runs/repro_codeql_cwe401 \
  --codeql ~/tools/codeql-2.27.4/codeql/codeql \
  --jobs 6 --timeout 600

python3 static_extended/compare_test140.py \
  --units juliet/subset_units.jsonl \
  --baseline traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl \
  --codeql-run static_extended/runs/repro_codeql_cwe401 \
  --out static_extended/runs/repro_codeql_cwe401/comparison_test140.json
```

`bash static_extended/run_codeql.sh` 会自动选新目录；适配器拒绝覆盖非空目录。本机 200 单元墙钟 1,434.7 s（6 并发），单单元均值 42.5 s；换机器会变。

#### 5.4.2 动态增强：故障注入 + 全局根（无网络）

```bash
cd dynamic_enhanced
python3 run_dynamic_enhanced.py selftest
python3 run_dynamic_enhanced.py run --run-id repro_enhanced --jobs 8
python3 run_dynamic_enhanced.py report --run-dir runs/repro_enhanced
python3 run_dynamic_enhanced.py export --run-dir runs/repro_enhanced
python3 run_dynamic_enhanced.py verify --run-dir runs/repro_enhanced
```

140 单元 × 3 模式；`realloc_fail` 只让第一次非 NULL `realloc` 失败，`nogobal` 关闭 LSan 全局根。`run` 拒绝写入已存在的目录，必须用新 `--run-id`。本机总耗时 315.6 s。

### 5.5 重跑 LLM 实验

LLM 请求需要有效的 provider 凭证。**不要把 key 写进命令、脚本或文件**；使用环境变量或 `runner/run_with_kimi_config.py` 从本地 Kimi Code TOML 读入进程内存。部分脚本（`pair_joint/run_pair_joint.sh`、`pair_debias/run_pair_debias.sh`、`evidence_verify/run_verify.sh`、`hybrid/run_hybrid.py`、`hybrid_dynamic_enhanced/run_hde.py`、`juliet_repair/scripts/run_repair.py` 的默认值）把 config 路径写死为 `/mnt/c/Users/tzh03/.kimi-code/config.toml`；换机器/用户名时先改脚本顶部或传 `--kimi-config`（支持该参数的工具）。

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

# Pair-debias：反向 + 开放四分类（需凭证；复用 pair_joint 正序，不重复计费）
python3 pair_debias/selftest.py
bash pair_debias/run_pair_debias.sh full
bash pair_debias/run_pair_debias.sh analyze

# 正例二次验证：4 臂（需凭证；只对 schema-valid 正例各发一次验证请求）
python3 evidence_verify/selftest.py  # 当前有 valid_indices NameError，修复后再跑
bash evidence_verify/run_verify.sh deepseek_self test
bash evidence_verify/run_verify.sh deepseek_cross test
bash evidence_verify/run_verify.sh mimo_self test
bash evidence_verify/run_verify.sh mimo_cross test
python3 evidence_verify/analyze.py

# 增强动态证据 + LLM（需凭证；2 模型 × 140）
cd hybrid_dynamic_enhanced
python3 run_hde.py build
python3 run_hde.py preflight --smoke --run-id repro_hde
python3 run_hde.py run --model all --run-id repro_hde --concurrency 10
python3 run_hde.py analyze && python3 run_hde.py report && python3 run_hde.py verify
cd ..

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

/tmp/secvul-tectonic/tectonic -X compile report/report_extended_zh.tex --outdir report
/tmp/secvul-tectonic/tectonic -X compile report/report_zh.tex --outdir report
# 最新版报告（2026-11-14）
/tmp/secvul-tectonic/tectonic -X compile report/report_latest_zh.tex --outdir report
```

报告 PDF 已提交：扩展版 `report/report_extended_zh.pdf`（27 页，Tectonic 0.17.0，`pdfinfo` 实测）与基础版 `report/report_zh.pdf`（17 页，保留未改）。**2026-11-14 报告是 [`report/report_latest_zh.pdf`](report/report_latest_zh.pdf)**（35 页，2026-11-14 02:12 CST，`pdfinfo` 实测），源稿为 [`report/report_latest_zh.tex`](report/report_latest_zh.tex)。**2026-11-22 下一轮报告是 [`report/report_next_zh.pdf`](report/report_next_zh.pdf)**（12 页，2026-11-22 20:35 CST，`pdfinfo` 实测），源稿为 [`report/report_next_zh.tex`](report/report_next_zh.tex)，统一摘要在 [`report/next_results_summary.md`](report/next_results_summary.md)。重新编译需要 Tectonic 或 TeX Live。

### 5.7 2026-11-22 下一轮：五个弱点的复现

这一轮的设计与成功线在 `research/next_iteration_rationale.md`，结果汇总在 `report/report_next_zh.pdf`（12 页）与 `report/next_results_summary.md`；benchmark 只读接入在 `benchmark/results/NEXT_ITERATION.md`。所有命令都在 WSL 中运行，默认写入新目录；不要覆盖已有 `results/` 或 `runs/`。

```bash
# 1) 可解释非 LLM 基线（无网络；dev40 拟合，test160 只评一次）
python3 interpretable_baseline/run_baseline.py \
  --out-dir /tmp/secvul_interpretable_check --resamples 10000

# 2) Pair-diff（需凭证；先 pilot 再 full；ctrl 是 token 长度匹配的空占位块）
python3 pair_diff/selftest.py
bash pair_diff/run_pair_diff.sh pilot
bash pair_diff/run_pair_diff.sh full
bash pair_diff/run_pair_diff.sh analyze

# 3) CodeQL 告警分流（需凭证；MiMo 走 Xiaomi 官方端点；DeepSeek 当前 402/401）
python3 codeql_triage/selftest.py
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider xiaomi -- \
  --provider xiaomi --model mimo-v2.6-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/repro_mimo_v2 --concurrency 6
python3 codeql_triage/analyze.py \
  --run-dir codeql_triage/runs/repro_mimo_v2 \
  --out codeql_triage/runs/repro_mimo_v2/analysis --label repro-mimo-v2

# 4) 保守三路验证器（需凭证；先 dryrun 再 test；四臂）
python3 verifier_conservative/selftest.py
bash verifier_conservative/run_conservative.sh deepseek_self dryrun
bash verifier_conservative/run_conservative.sh deepseek_self test
# 其余三臂：deepseek_cross / mimo_self / mimo_cross
python3 verifier_conservative/analyze_conservative.py

# 5) 动态覆盖率（无网络；需要 gcc/gcov 15.3）
python3 dynamic_coverage/run_dynamic_coverage.py selftest
python3 dynamic_coverage/run_dynamic_coverage.py run --run-id repro_coverage --jobs 8
python3 dynamic_coverage/run_dynamic_coverage.py report --run-dir dynamic_coverage/runs/repro_coverage
python3 dynamic_coverage/run_dynamic_coverage.py verify --run-dir dynamic_coverage/runs/repro_coverage
```

预期（本机正式产物）：`interpretable_baseline` 8/8 LLM 指标回归一致、`length_short` 0.511/0.094；`pair_diff` 1,440/1,440 ok、0 invalid、成本 `$1.156871`；`codeql_triage` 140/140 direct + 140/140 v2、最终 68/0/70/2；`verifier_conservative` 236 请求、4 撤销；`dynamic_coverage` 140 单元 × 3 模式、default 58/0/70/12、并集 70/0/70/0。这些是单次运行的点估计，不是重复实验的置信区间。

更多环境细节、数据哈希、验收清单和已知坑见 [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md)。

---

## 6. 凭证与发布安全

- 所有 API key 只从环境变量或本地 Kimi Code TOML 读入**进程内存**；不打印、不写日志、不写 `manifest.json`、不写 `results.jsonl`。运行产物记录 `api_key_value_stored: false`。
- `runner` 和 `juliet_llm` 对响应体做 `sk-...` / `Bearer ...` 脱敏；`api.session` 记录非敏感的 `x-opencode-session` 随机值及其 SHA-256，不是密钥。
- `.gitignore` 排除 `.env`、`creds/`、`credentials/`、`secrets/`、`*.key`、`*.pem`、`auth.json`、`opencode.json`、`*_api_key.json`、`repair_eval/packages/*/private/` 等。
- 发布前请按 [`docs/SECURITY.md`](docs/SECURITY.md) 的清单做一次 secret scan 和文件体积检查。**不要把任何 key 粘进 issue、PR、commit message 或截图。**
- GitHub 私有仓库已创建并推送：<https://github.com/tzhazuma/cs224proj>（PRIVATE）。发布/重建步骤仍见 [`docs/GITHUB_RELEASE.md`](docs/GITHUB_RELEASE.md)：包含 `gh` 安装/校验、`git init`、暂存区体积与密钥扫描、`gh repo create cs224proj --private --source=. --remote=origin --push` 以及推送后验证；当前仓库不要重复执行 `gh repo create`。发布门禁是**当前轮次**审计的 FAIL=0：2026-11-14 审计为 56 PASS / 0 FAIL / 0 WARN（Overall `PASS`）；2026-11-22 审计为 **40 PASS / 0 FAIL / 1 WARN（Overall `PASS_WITH_WARNINGS`）**，3 个 WARN 见 §8.35。旧一轮 `audit/final_audit.md`（58 PASS / 0 FAIL / 1 WARN / 1 INFO）只覆盖 v2/postleakfix 工作树，不能给 2026-11-13/14 或 2026-11-22 的新目录背书。
- 2026-11-22 工作树按 `.gitignore` 估算在 2026-11-14 的 **10,836 个文件 / 333.3 MiB** 基础上新增约 **170 MB**（`du` 粗估：`pair_diff` 65 MB、`dynamic_coverage` 52 MB、`benchmark/extensions/runs` 33 MB、`codeql_triage` 10 MB、`verifier_conservative` 8 MB、`interpretable_baseline` 0.85 MB；`dynamic_coverage/runs/*/build/` 等可再生产物被 `.gitignore` 排除）。最大单文件仍是 `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl`（40.55 MB），没有 ≥100 MB 文件。最终以暂存区 `git ls-files` 为准。
- 本仓库不包含个人账号、cookie、SSH key 或云凭证；如果发现疑似泄漏，先轮换凭证，再清理历史。

---

## 7. 数据来源、许可与边界

- **SecVulEval**：根目录 `SecVulEval.xlsx` 为课程提供的上游数据集；`datasets/` 与 `splits/` 是从该工作簿抽样、冻结的派生数据。上游数据的引用与许可请遵循其原始发布页面。
- **Juliet**：NIST SARD 的 Juliet Test Suite for C/C++ v1.3，官方归档 URL 与 SHA-256 见 `juliet/README.md`。`juliet/raw/` 不随仓库分发（体积原因），用 `fetch_juliet.py` 从官方来源恢复。
- **模型输出**：`runner/runs/`、`juliet_llm/runs/`、`hybrid/runs/`、`pair_joint/runs/`、`juliet_repair/runs/`、`pair_debias/runs/`、`evidence_verify/runs/`、`hybrid_dynamic_enhanced/runs/`、`pair_diff/runs/`、`codeql_triage/runs/`、`verifier_conservative/runs/` 保存真实模型响应与 usage；`dynamic_enhanced/runs/`、`dynamic_coverage/runs/`、`static_extended/runs/` 保存本地工具证据；`interpretable_baseline/results/` 保存无 API 的规则/LR 结果。它们是研究产物，不构成对代码安全性或补丁正确性的保证。
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
17. **Repair prompt 不是完全 label-neutral（旧一轮审计 F4，WARN）。** 70/70 个 repair prompt 仍含 `bad`/`CWE`/`Memory_Leak` 任务前提 token（good 标识符 0/70）；这是任务语义所需，但模型可利用该前缀。
18. **Repair all-in 成本已统一为 `$0.082550`（审计 I3 已修复）。** headline 两个 final run 为 `$0.032831`；all-in 含 `parser_dev/mimo_test70_v1` 的 `$0.005034` 与 smoke，configured `$0.082550`、normalized `$0.052549`。引用时用 run 目录的 `summary.json`，不要用旧汇总。
19. **`hybrid_v2` 是单次重跑。** 6 个被清洗单元的 17 条预测变化中 16 条由对变错；134 个未变单元仍有 1 条端点波动。v2 的小幅下降不能全部归因于清洗，也不能把单次 v2 当成稳定估计。
20. **单序 A/B 受位置信号抬高。** `pair_joint`/`pair_debias` 的正向 DA 不能单独引用：DeepSeek 交换一致只有 61.67%，且 31.11 pp 的 A 偏好反向复现；MiMo 交换一致 74.44%，与两序长度启发式 72.22% 差异不显著。强制格式下“只对一序”的配对全部是两序同字母，说明增量来自槽位。
21. **开放四分类的 DA 把弃权记为错误。** `both`/`neither` 占 17.22%–22.22%，总体 DA 63.89%–66.11%，但 committed 准确率 77.18%–84.40%。committed 是“愿意表态”的后处理子集，不是随机对照；不能把弃权一律算对或算错。
22. **`dynamic_enhanced` 仍是单路径观测。** `realloc_fail` 只让第一次非 NULL `realloc` 失败；`nogobal` 是全局根总开关，不是逐变量根映射；Valgrind 未重跑。`clean` 只表示该执行路径没有归因泄漏，不是无泄漏证明；70/70 只适用于冻结 test 140。
23. **增强证据的 LLM 结果受工具天花板限制。** `hybrid_dynamic_enhanced` 的工具是 140/140，因此“与工具一致率”等于准确率，无法区分照抄与独立判断；DeepSeek 137/140、MiMo 136/140，相对 direct +2/0，Holm 后不显著。理由分析是词法的（字节数复述），不是因果。
24. **CodeQL 不是全面更优。** 每个单元单独建库、单 TU 近似，用 gcc/g++ 15.3 建库而 Clang/Cppcheck 用 clang 22.1.8；查询版本固定为 2.27.4 + `cpp-queries` 1.10.0。test 140 的 23 个 FP 全是 C++ good；高召回（0.971）伴随低精确率（0.747）和更低 MCC（0.674）。
25. **`schema_recovery` 只到 L0。** 结构检查是词法代理，不是 C/C++ parser/compiler；有 2 条 K&R 定义被 canonical 规则误判。`usable_patch` 没有编译、测试、sanitizer、PoC 或人工评审，不能叫修复正确率。
26. **`benchmark/extensions` 是只读导入层，不是新实验。** 16 个 canonical run 来自 producer 的真实产物；八个 design 各有主终点，不能池化，也不能与父 Tier A/B 主表直接相减。CodeQL 已导入为 `new_static_tool`，但父 schema/PROTOCOL 未被修改，LEADERBOARD 只加了指向 `EXTENSIONS.md` 的链接。
27. **2026-11-13/14 与 2026-11-22 两轮都尚未进入主 leaderboard。** 两轮实验默认都是单次运行；除 `schema_recovery`、`interpretable_baseline`、`dynamic_coverage` 外都有 API/工具调用。`benchmark/results/` 的主表仍只覆盖 v2/postleakfix 工作树；2026-11-14 审计（[`audit/latest_audit.md`](audit/latest_audit.md)）为 56 PASS / 0 FAIL / 0 WARN，2026-11-22 审计见 [`audit/next_iteration_audit.md`](audit/next_iteration_audit.md)。本轮 `benchmark/results/NEXT_ITERATION.md` 只做只读接入与成功线记录，不改父协议。
28. **2026-11-14 审计先前的 A6/E6/F4/G3 告警已修复（历史说明）。** A6 曾要求披露 `pair_debias` 的 1,080 条记录含 51 条缓存复用（1,029 次新请求）；E6 曾要求 CodeQL 区分 positive-class F1(V) 0.8447 与主终点 macro-F1 0.8173；F4 曾要求注明 `schema_recovery` 的 “normalized” 是 configured `$0.30/$1.20` 的 cache-aware 重算，不是 off-peak `$0.15/$0.60`；G3 曾指出 2026-11-13 文献快照的“未实现”状态已过时。当前审计已清零这 4 项。
29. **`interpretable_baseline` 的 dev40 只有 8 个负例。** dev 选择 `length_short` 只比多数类高 0.0061；`lr_balanced` 在 dev 上 0.564、test 上 0.391（MCC −0.131），是协变量偏移/过拟合的直接证据。test 正例率 80% 是 200 条子集的构造比例，不是真实项目分布；`length_short` 的 0.511 不能写成“规则更会检测”。test-tuned 上界（`call_density` 0.598/0.209）使用了 test 标签，不是方法结果；Tier A 仍只保证项目级隔离，没有 5-gram 近重复控制。
30. **`pair_diff` 仍是单次运行，且 diff−ctrl 为零。** 1,440 条新记录（8 runs × 180）全部 ok，但 diff 相对 token 长度匹配对照的交换一致差异只有 +2.22/−1.67 pp（Holm 后不显著）；选较短比例没有下降，changes-first 在无安全相关变更的 20/180、36/180 对上把答案门控成 `neither`。长度匹配用 `cl100k_base` 代理 tokenizer，不是 provider tokenizer；分析阶段虽用 `prompt_tokens` 复核（179/180、180/180 在 5% 内），仍不能排除 token 计费口径差异。成本约为 open 的 1.30×，USD/正确 pair-order 更高。
31. **`codeql_triage` 只有 MiMo 有结果，且相对 direct 不显著。** DeepSeek 官方端点 402 `Insufficient Balance`、OpenCode Go 401 `api_key_expired`、Qwen 403；失败证据保留在 `runs/blocked_*`，没有伪造数字。最终 68/0/70/2 相对 CodeQL +0.1684（p<1e-6），相对 direct 仅 +0.0286（95% CI 跨 0，p=0.289）。2 个 FN 是 `_82` compile_error，triage 无法恢复；cascade 只是用 direct 补回并引入 2 FP。91 个告警的二次复核不是盲审，零成本文本一致性规则得到完全相同的结果；单次采样，没有方差。
32. **`verifier_conservative` 是 test-seen 的事后实验。** 160 个测试函数已用于第一遍 evidence 和原验证器；三路提示与判定规则是在看到那些结果之后设计的，不能当作独立确认。236 条请求只撤销 4 条（TP 3 / FP 1），撤销精确率 25.0% 与正例 FP 基准率 18.3%–19.0% 不可区分（Holm p=1.0）；macro-F1 不升。守卫/反例的语义支配关系没有编译或执行验证；只改正例，32 个负例支撑不起 FPR 结论；跨模型验证器不是人工标注。
33. **`dynamic_coverage` 的 100% 行覆盖不是无泄漏证明。** 覆盖率用 GCC 15.3 gcov，只统计单元自身文件；default 的 82 个 clean 全部 effective-line-complete，其中 12 个实际是 bad（`supported_clean_but_bad=12`）。7 个 `malloc_realloc` 漏报可由 `realloc` 失败分支解释，5 个 `_68` 是 LSan 全局根语义，不是执行不足；`nogobal` 新增 0 行/0 分支。分支覆盖 52.7%，`branch_complete` 21/140 且 0 个 good——通用分支覆盖把“守卫多少”当成覆盖高低，不能给 clean 背书。每模式仍只跑 1 个输入；clang + `--wrap=realloc` + LSan 在本机挂起，未采用 llvm-cov。
34. **本轮 `report_next` / `NEXT_ITERATION` 是单次运行的汇总，不是重复实验。** `report/report_next_zh.pdf` 与 `benchmark/results/NEXT_ITERATION.md` 只整理已落盘产物；成功线是预注册门槛，不是“预期结果”。审计只核对产物、口径与可复现命令，不把单次运行变成多 seed 估计；任何“显著提升”仍以各自的 McNemar/Holm 结果为准。
35. **2026-11-22 审计是 `PASS_WITH_WARNINGS`，不是纯 PASS。** 当前 `audit/next_iteration_audit.md` 为 **40 PASS / 0 FAIL / 1 WARN（41 checks）**。3 个 WARN：(E5) `interpretable_baseline` 的预注册时间戳不能从产物证明，只能确认规则/阈值是 dev-only；(F3) `benchmark/results/extension_summary.json` 仍是 2026-11-13 的旧汇总，且审计按根路径 `benchmark/NEXT_ITERATION.md` 检查，而实际汇总写在 `benchmark/results/NEXT_ITERATION.md`；(F4) 审计脚本仍按旧文件名检查发布文档（`audit/next_audit.*`、`benchmark/NEXT_ITERATION.md`），而本 README/docs 已改用 `audit/next_iteration_audit.*` 与 `benchmark/results/NEXT_ITERATION.md`；报告产物图仍把 `pair_diff` 写成 `pair_diff/report.md`（实际为 `pair_diff/results/report.md`，属于 report/ 范围）。发布门禁 FAIL=0，但这些 WARN 必须保留；审计重跑后以文件为准。

---

## 9. 文档索引

| 文档 | 内容 |
| --- | --- |
| [`docs/LITERATURE.md`](docs/LITERATURE.md) | 文献索引：2025–2026 最新 LLM/评估/内存工具调研、引用分级与阅读顺序 |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | 环境、数据恢复、分层复现命令、产物哈希、验收清单、常见坑 |
| [`docs/SECURITY.md`](docs/SECURITY.md) | 凭证处理、忽略规则、发布前 secret scan、残余风险、事件响应 |
| [`docs/GITHUB_RELEASE.md`](docs/GITHUB_RELEASE.md) | GitHub 私有仓库发布：`gh` 安装、git 初始化、门禁、推送与验证 |
| [`audit/final_audit.md`](audit/final_audit.md) | 旧一轮只读审计：58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`；**只覆盖 v2/postleakfix，不含 2026-11-13/14 新目录** |
| [`audit/latest_audit.md`](audit/latest_audit.md) | **2026-11-14 审计：Overall `PASS`，56 PASS / 0 FAIL / 0 WARN**。先前的 A6/E6/F4/G3 已修复（见 §8.28） |
| [`audit/next_iteration_audit.md`](audit/next_iteration_audit.md) | **2026-11-22 下一轮审计**：覆盖 `interpretable_baseline`、`pair_diff`、`codeql_triage`、`verifier_conservative`、`dynamic_coverage` 与 `research/next_iteration_rationale.md`；`Overall`/`Checks` 以文件为准 |
| [`benchmark/PROTOCOL.md`](benchmark/PROTOCOL.md) | 统一评测协议：标签、指标、失败、统计、成本、Tier A/B |
| [`benchmark/results/NEXT_ITERATION.md`](benchmark/results/NEXT_ITERATION.md) | 2026-11-22 五个弱点的只读接入：成功线、主终点、限制与不进入父主表的边界 |
| [`benchmark/results/LEADERBOARD.md`](benchmark/results/LEADERBOARD.md) | 两层 leaderboard 索引（不跨层排名；Tier B 主行为 hybrid_v2 / postleakfix；末尾链接扩展汇总） |
| [`juliet/README.md`](juliet/README.md) | Juliet 子集来源、宏门控、dev/test、近重复、复现 |
| [`traditional/static/README.md`](traditional/static/README.md) | Clang/Cppcheck 适配器、CWE-401 规则、200 单元结果 |
| [`traditional/dynamic/README.md`](traditional/dynamic/README.md) | ASan/LSan + Valgrind 全量结果与 190 个 FN 归因 |
| [`report/report_latest_zh.pdf`](report/report_latest_zh.pdf) | 2026-11-14 报告（35 页）：配对去偏、二次验证、动态增强、CodeQL、schema 复分析；源稿为 [`report_latest_zh.tex`](report/report_latest_zh.tex) |
| [`report/report_next_zh.pdf`](report/report_next_zh.pdf) | **2026-11-22 下一轮报告（12 页）**：五个弱点的复核、四个实验与覆盖率门禁；源稿为 [`report_next_zh.tex`](report/report_next_zh.tex) |
| [`report/next_results_summary.md`](report/next_results_summary.md) | 2026-11-22 五个实验的统一结果摘要、口径、复现命令与限制；对应 `report_next_zh.tex` |
| [`report/latest_results_summary.md`](report/latest_results_summary.md) | 2026-11-14 最新六组实验的统一结果摘要（配对去偏、二次验证、动态增强、增强混合、CodeQL、schema） |
| [`benchmark/results/EXTENSIONS.md`](benchmark/results/EXTENSIONS.md) | 扩展层最终汇总：16 个 canonical run、各 design 主终点与限制；机器可读版 `extension_summary.json` |
| [`report/results_summary.md`](report/results_summary.md) | Tier A 三策略结果、成本、修复结构、盲评摘要 |
| [`research/innovation_findings.md`](research/innovation_findings.md) | 创新点的证据分级：哪些能写、哪些不能写 |
| [`pair_joint/report.md`](pair_joint/report.md) | 联合 A/B 的完整结果、长度/位置混淆 |
| [`evidence_prompt/README.md`](evidence_prompt/README.md) | 证据行/反事实提示的协议与结果 |
| [`hybrid/REPORT_V2.md`](hybrid/REPORT_V2.md) | 泄漏修复后 hybrid v2 的完整结果、v1 对照与限制 |
| [`analysis/cost_normalization.md`](analysis/cost_normalization.md) | 峰谷价、normalized 与 allowance 的逐 run 成本口径 |
| [`juliet_repair/README.md`](juliet_repair/README.md) | 编译/LSan/行为闭环与 58/58 的口径 |
| [`juliet_llm/README.md`](juliet_llm/README.md) | Juliet LLM 清洗、审计、MiMo fallback、DeepSeek 阻塞证据 |
| [`repair_eval/README.md`](repair_eval/README.md) | 修复盲评 rubric、κ、裁决与限制 |
| [`pair_debias/report.md`](pair_debias/report.md) | A/B 反向重复、开放四分类、长度匹配与交换一致 DA |
| [`evidence_verify/analysis/report.md`](evidence_verify/analysis/report.md) | 正例二次验证/撤销的 4 臂、同预算基线与事后规则 |
| [`dynamic_enhanced/README.md`](dynamic_enhanced/README.md) | `realloc` 故障注入 + LSan 全局根控制、12 个不可观测单元的逐条证据 |
| [`hybrid_dynamic_enhanced/REPORT.md`](hybrid_dynamic_enhanced/REPORT.md) | 增强动态证据 + 两模型 LLM 的准确率、成本与一致性诊断 |
| [`static_extended/README.md`](static_extended/README.md) | CodeQL 2.27.4 CWE-401 扩展静态基线与 test 140 对比 |
| [`analysis/schema_recovery/schema_recovery.md`](analysis/schema_recovery/schema_recovery.md) | 102 条 invalid 的零 API schema 复分析与 usable 阶梯 |
| [`benchmark/extensions/README.md`](benchmark/extensions/README.md) | 8 个 design 的 canonical 映射、校验、指标与已导入 run |
| [`interpretable_baseline/REPORT.md`](interpretable_baseline/REPORT.md) | 可解释非 LLM 基线：7 规则 + 2 LR、macro-F1/MCC 排名翻转、test-tuned 上界 |
| [`pair_diff/results/report.md`](pair_diff/results/report.md) | 差分 + changes-first + 长度匹配对照：交换一致 DA、diff−ctrl、弃权与成本 |
| [`codeql_triage/REPORT.md`](codeql_triage/REPORT.md) | CodeQL 23 FP 的 LLM 分流：v1/v2、TP 误删、最终 68/0/70/2 与 DeepSeek 阻塞 |
| [`verifier_conservative/analysis/report.md`](verifier_conservative/analysis/report.md) | 保守三路验证器：4/236 撤销、25.0% 精确率、macro-F1 不升 |
| [`dynamic_coverage/README.md`](dynamic_coverage/README.md) | gcov 行/分支覆盖 + 三模式：12 个 `supported_clean_but_bad`、并集 70/0/70/0 |
| [`research/next_iteration_rationale.md`](research/next_iteration_rationale.md) | 2026-11-22 五个最弱环节的定量复核、N1–N4 成功线与失败解释 |
| [`research/latest_llm_methods_2026.md`](research/latest_llm_methods_2026.md) | 2025–2026 LLM/agentic 检测、结构化输出、验证反馈文献（22 A + 18 B + 7 C） |
| [`research/latest_evaluation_repair_2026.md`](research/latest_evaluation_repair_2026.md) | 位置/长度/配对/placebo/judge/补丁过拟合/故障注入/差分测试文献（56 条） |
| [`research/latest_memory_tools_2026.md`](research/latest_memory_tools_2026.md) | CodeQL/Semgrep/Infer/SVF/Clang/LSan/Valgrind 与条件分配失败、still reachable（47 条） |

---

## 10. English abstract

This repository contains the artefacts of a CS224 course project that evaluates vulnerability detection and repair under one auditable contract while keeping two tiers separate. **Tier A** uses frozen SecVulEval splits (160 real-project C/C++ functions for detection; 180 vulnerable/fixed pairs) and compares two models across three prompt strategies. **Tier B** uses a frozen 200-unit Juliet CWE-401 subset and compares Clang Static Analyzer, Cppcheck, ASan/LSan and Valgrind. The project also contains diagnostic studies on joint A/B pair discrimination, evidence-line prompting, tool-evidence conditioning with a placebo, compile/LSan/behaviour repair evaluation, and an LLM-assisted repair rubric.

The main methodological claim is negative and reproducible: several apparently large gains are explained by task framing, length, position, operating-point shifts or ceiling effects. No model comparison survives Holm correction; joint A/B gains are inseparable from forced choice and length; dynamic “clean” is not a verified true negative; the original hybrid 140/140 did not survive the label-leak fix (v2 combined is 136/140); and the repair 58/58 is limited to 58 observable synthetic units. All reported numbers come from recorded runs; no mock or estimated values are used in the result tables.

The 2026-11-13/14 round adds a position-debiased A/B replication (swap-consistent DA 61.67% for DeepSeek and 74.44% for MiMo against a 72.22% two-order length heuristic), fault-injected plus global-root LSan runs that make all 12 previously unobservable bad units observable (70/70 with 0 false positives), enhanced-evidence LLM reruns with no significant gain, a CodeQL baseline with higher recall but lower precision and MCC than Clang, and a zero-API schema salvage analysis (67–69 structurally usable patches out of 102 invalid responses, L0 only). These results are recorded and covered by the latest release audit (56 PASS / 0 FAIL / 0 WARN), but are not yet merged into the main leaderboard.

The 2026-11-22 round targets the five weakest links rather than another model. An interpretable non-LLM baseline shows that a single length rule reaches macro-F1 0.511 (above all eight LLM runs) but only MCC 0.094, while a memory-API rule reaches MCC 0.183 with F1 0.387; on this 80%-positive test split macro-F1 rewards over-reporting, and no method exceeds 0.21 MCC. A diff-guided pair experiment with a token-length-matched control finds no significant diff-specific gain (swap-consistent DA 62.22%/60.56% vs 60.00%/62.22% for the control), and the “choose the shorter version” rate does not fall. CodeQL alert triage removes all 23 C++ false positives without deleting any of 68 true positives on MiMo (macro-F1 0.9857, MCC 0.9718), but is not significantly better than the direct LLM and has no DeepSeek result. A conservative three-way verifier retracts only 4 of 236 claims (precision 25.0%, not above the 18.3%–19.0% false-positive base rate) and does not improve macro-F1. Finally, gcov coverage shows that all 12 false-negative bad units are fully line-covered (`supported_clean_but_bad`), so 100% line coverage cannot certify a clean verdict; only the union of the default, realloc-failure and no-global-root modes reaches 70/70. These are single-run, partly post-hoc results and are recorded in `report/report_next_zh.pdf` and `benchmark/results/NEXT_ITERATION.md`, not in the main leaderboard.

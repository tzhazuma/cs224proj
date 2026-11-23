# 下一轮弱点实验：统一汇总（2026-11-22）

> 本文件只汇总 `benchmark/extensions/runs/` 下本轮 30 个 canonical run；五个 design 各自独立，**不跨设计池化**，**不覆盖主表** `LEADERBOARD.md` / `final_summary.json`。机器可读版本见 [`next_iteration_summary.json`](next_iteration_summary.json)。

## 0. 一页结论

| 设计 | 主终点 | 本轮数字 | 读法 |
| --- | --- | --- | --- |
| CodeQL alert triage | macro-F1 | 0.9857（68/0/70/2） | 不显著优于 direct（69/5/65/1；McNemar p=0.2891）；与零成本文本规则完全同判 |
| Diff-guided pair | 交换一致 DA | DS 62.22% vs ctrl 60.00%；MiMo 60.56% vs 62.22% | Holm 后无显著优势（1.0000 / 0.9053） |
| Conservative verifier | macro-F1 | 撤销 4/236（TP3/FP1） | macro-F1 Δ 0 到 -0.0052；撤销精确率 25%，不高于 FP 基准率 |
| Coverage dynamic | branch-complete | 21/140（全部 bad） | 行覆盖 99.9% 但不能证明 clean；clean 全部 inconclusive |
| Interpretable baseline | macro-F1 | length 0.5107；majority 0.4444 | 高于 8 个 LLM（0.346–0.422），但 MCC 仅 0.0945，排名随指标翻转 |

**一句话**：本轮没有出现可以改写主表的强新方法。CodeQL triage 的干净混淆矩阵被一个零成本文本规则完全复现；pair diff 的内容优势被弃权和长度捷径抵消；保守验证器修对了判定规则但几乎没有撤销；行覆盖不能把 clean 变成 TN；长度基线在 macro-F1 上领先 LLM，但在 MCC 上并不领先。

## 1. 范围与不可违反的边界

- 只读导入：`codeql_triage/`、`verifier_conservative/`、`pair_diff/`、`dynamic_coverage/`、`interpretable_baseline/` 的原始目录均未改写。
- canonical run 共 30 个：CodeQL 8、conservative 4、pair diff 8、coverage 1、interpretable 9。
- 每个 run 都通过 `ext_validate.py --jsonschema` 与 `bench_metrics.py`；本文件由 `bench_next_iteration_summary.py` 从 predictions 重算，不手抄数字。
- 五个 design 的主终点、分母和 cluster 不同；没有“总分”，也没有跨层/跨设计合并。
- 主 leaderboard、Tier A/B 主表、父 schema 和 `PROTOCOL.md` 均未修改。

## 2. CodeQL alert triage（Tier B，test-140）

设计：CodeQL 先产生 CWE-401 alert，MiMo 只对 alert 做 ownership/leak 判定；`direct` 是不看 alert 的直接检测复制。条件之间是独立 run，不合并。

| 条件 | TP | FP | TN | FN | macro-F1 | MCC | 说明 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `direct` | 69 | 5 | 65 | 1 | 0.9571 | 0.9158 | 直接检测复制 |
| `triage_v1` | 61 | 5 | 65 | 9 | 0.8999 | 0.8013 | v1 triage |
| `triage_v2` | 68 | 3 | 67 | 2 | 0.9643 | 0.9287 | v2 triage |
| `text_rule` | 68 | 0 | 70 | 2 | 0.9857 | 0.9718 | v2 + 文本一致性规则 |
| `verified` | 68 | 0 | 70 | 2 | 0.9857 | 0.9718 | v2 + grounded verifier |
| `cascade` | 70 | 2 | 68 | 0 | 0.9857 | 0.9718 | verified alert + no-alert direct |
| `zero_cost_never_freed` | 46 | 0 | 70 | 24 | 0.8234 | 0.6995 | 零成本：仅 never-freed |
| `zero_cost_drop_may_cpp` | 60 | 0 | 70 | 10 | 0.9282 | 0.8660 | 零成本：丢弃 C++ may-not-be-freed |

- **主结果**：verified = 68 TP / 0 FP / 70 TN / 2 FN，macro-F1 0.9857、MCC 0.9718。
- **对 direct 不显著**：direct = 69/5/65/1，macro-F1 0.9571；Δ = +0.0286，95% bootstrap CI [-0.0072, 0.0714] 跨 0；McNemar b/c = 2/6，p = 0.2891。
- **与零成本文本规则同判**：`text_rule` 与 `verified` 的 140 条预测逐条相同（discordant=0）。也就是说，这个 68/0/70/2 不需要 verifier，甚至不需要第二次模型调用。
- **零成本规则本身**：`never_freed_only` = 46/0/70/24（macro-F1 0.8234）；`drop_may_cpp` = 60/0/70/10（0.9282）。它们证明 23 个 FP 全部来自 C++ `may-not-be-freed`，但也会丢掉 10–24 个 TP。
- **CodeQL 单独**：68/23/47/2（macro-F1 0.8173）；triage 修掉 23 个 FP 中的 23 个，代价是 2 个 TP 变成 FN（这 2 个是 compile_error 单元，triage 无法恢复）。
- **不能声称**：verifier 看到了第一遍 JSON，不是独立盲审；DeepSeek 没有结果（402/401），不能把 MiMo 数字移植过去；单次 temperature 0。

## 3. Conservative verifier（Tier A，探索性）

| 臂 | pre macro-F1 | post macro-F1 | Δ | pre MCC | post MCC | 撤销 | TP 损失 | FP 纠正 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 0.4223 | 0.4172 | -0.0052 | 0.0348 | 0.0284 | 1 | 1 | 0 |
| `deepseek_cross` | 0.4223 | 0.4223 | 0.0000 | 0.0348 | 0.0348 | 0 | 0 | 0 |
| `mimo_self` | 0.4067 | 0.4067 | 0.0000 | 0.0126 | 0.0126 | 0 | 0 | 0 |
| `mimo_cross` | 0.4067 | 0.4040 | -0.0028 | 0.0126 | 0.0265 | 3 | 2 | 1 |

- **总量**：236 条验证请求，只有 4 条撤销（TP 3 / FP 1）。撤销精确率 25.0%，不显著高于正例中的 FP 基准率（约 18–19%）。
- **macro-F1 不升**：四个臂的 Δ 为 -0.0052 / 0 / 0 / -0.0028；MCC 只在 `mimo_cross` 上升 +0.0139，95% CI 跨 0，代价是 2 个 TP 损失换 1 个 FP 纠正。
- **原验证器对比**：原 fail-closed 规则在同一批正例上撤销 155 条，保守规则撤销 4 条，相差约 39 倍。随机/低置信同预算基线没有显示保守规则更优（多个臂上随机基线 macro-F1 更高）。
- **判定规则修对了，但收益是负的**：把 `insufficient` 与 `unsupported` 分开、取消 fail-closed，避免了大规模误撤销；但模型很少给出可用的具体反证，验证器退化为惰性步骤。
- **不能声称**：这是 test-seen、事后分析，不是独立确认；4 条撤销不足以估计精确率；grounding 只检查行号，不检查语义支配关系（报告里两个反例都通过了机械检查）。

## 4. Diff-guided pair（Tier A，180 对）

| 模型 | 条件 | 正向 DA | 交换一致 DA | 弃权率 | 选较短比例 | H-gap |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| deepseek | diff | 68.33% | 62.22% | 23.33% | 80.43% | +36.31% |
| deepseek | ctrl | 68.89% | 60.00% | 18.89% | 80.82% | +39.97% |
| mimo | diff | 68.33% | 60.56% | 24.44% | 80.88% | +33.39% |
| mimo | ctrl | 66.11% | 62.22% | 26.11% | 81.20% | +36.24% |

注：MiMo 的 diff_fwd / diff_rev 各有 1 对 schema-invalid；表中正向 DA 用 180 对全分母（与 producer 一致），canonical `metrics.json` 的 valid-only DA 以 179 对为分母。

| 模型 | 比较 | Δ 交换一致 DA | McNemar p | Holm p |
| --- | --- | ---: | ---: | ---: |
| deepseek | diff − ctrl | 2.22% | 0.3438 | 1.0000 |
| mimo | diff − ctrl | -1.67% | 0.6291 | 0.9053 |

- **没有 Holm 显著优势**：DeepSeek +2.22 pp（p=0.3438，Holm=1.0000），MiMo -1.67 pp（p=0.6291，Holm=0.9053）。
- **跨设计参考（不池化）**：diff 对 open 的交换一致 DA，DeepSeek +6.67 pp（producer p=0.0428，Holm=0.0855），MiMo +2.22 pp（producer p=0.5413，Holm=1.0000）。
- **长度捷径仍在**：H 正确子集 DA 比 H 错误子集高 33–40 pp；diff/ctrl 的“选较短”比例（75–81%）不低于 open（73–80%）。diff 没有减少长度依赖。
- **changes-first 的新失败模式**：变更清单里没有安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全部判 neither，DA=0；ctrl 也一样，说明这是“先列变更”指令驱动，不是 diff 内容。
- **不能声称**：diff 有效、diff 减少长度捷径、或 diff 优于 open。committed 子集上的优势不能当成总体优势。

## 5. Coverage-instrumented dynamic（Tier B，test-140）

| 指标 | 数字 |
| --- | --- |
| 单元 | 140（70 bad / 70 good） |
| raw line-complete 或更好 | 134/140 |
| effective line-complete 或更好（去 dead code） | 140/140 |
| branch-complete | 21/140 |
| branch-complete 中的 bad/good | 21 / 0 |
| 平均行覆盖 | 99.89% |
| 平均分支覆盖 | 52.73% |
| clean 的 tier | 64 line-complete + 6 partial，0 branch-complete |
| operational macro-F1（clean 当负例） | 0.9137 |
| conservative recall（clean 弃权） | 58/70 = 82.86%；specificity/macro-F1 未定义 |

- **行覆盖不能证明 clean**：effective 行覆盖 140/140（raw 134/140，6 个 partial 由 dead-code 排除后补齐），但只有 21 个单元达到 branch-complete，且 21 个全是 bad。没有 clean 单元达到 branch-complete，所以 clean 只能是 `inconclusive`，不能写成 TN。
- **默认模式漏掉的 12 个 bad**：7 个由 realloc-failure 分支解释，5 个只能由 root policy（`use_globals=0`）解释。行覆盖对这 12 个没有帮助。
- **operational vs conservative 必须同时读**：operational 把 clean 当负例，得到 0.9137 macro-F1；conservative 只报告 recall 0.8286，不报告 specificity/macro-F1。
- **不能声称**：覆盖率提高了检测、clean 是安全、或行覆盖足以支持 TN。

## 6. Interpretable baselines（Tier A，test-160）

| 方法 | TP | FP | TN | FN | macro-F1 | MCC | pred+ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rule:length_short` | 75 | 15 | 17 | 53 | 0.5107 | 0.0945 | 56.25% |
| `rule:prior_majority` | 128 | 32 | 0 | 0 | 0.4444 | 0.0000 | 100.00% |
| `rule:calls_high` | 53 | 14 | 18 | 75 | 0.4158 | -0.0190 | 41.88% |
| `rule:alloc_or_mem` | 32 | 2 | 30 | 96 | 0.3874 | 0.1833 | 21.25% |
| `rule:mem_api_present` | 23 | 2 | 30 | 105 | 0.3300 | 0.1291 | 15.62% |
| `rule:alloc_unbalanced` | 12 | 0 | 32 | 116 | 0.2635 | 0.1424 | 7.50% |
| `rule:short_and_alloc_or_mem` | 11 | 0 | 32 | 117 | 0.2559 | 0.1359 | 6.88% |
| `lr_unweighted` | 127 | 32 | 0 | 1 | 0.4425 | -0.0397 | 99.38% |
| `lr_balanced` | 59 | 20 | 12 | 69 | 0.3912 | -0.1313 | 49.38% |

**LLM 参照（8 个 run）**：macro-F1 0.346–0.422，最好的 DeepSeek evidence 0.422；MCC 最高的是 MiMo context 0.080，DeepSeek direct 0.041。

| 比较 | n | b/c | McNemar p | Holm p |
| --- | ---: | --- | ---: | ---: |
| length vs deepseek_direct | 160 | 70/40 | 0.0054 | 0.0381 |
| length vs deepseek_evidence | 159 | 69/47 | 0.0507 | 0.2029 |
| length vs mimo_direct | 150 | 69/32 | 0.0003 | 0.0021 |

- **macro-F1 上长度规则确实高于全部 8 个 LLM**：0.511 vs 0.346–0.422；多数类也有 0.444，高于全部 LLM。
- **但这不是检测能力**：长度规则 MCC 0.094，只比最好的 LLM MCC 0.080 高一点；多数类 MCC=0、specificity=0。按 MCC 排名，`alloc_or_mem` 0.183 第一，长度规则第五。
- **统计上只能说到单元级正确数更多**：length vs DeepSeek direct 70/40，p=0.0054，Holm=0.038；vs MiMo direct 69/32，Holm=0.002；**vs DeepSeek evidence 69/47，p=0.0507，Holm=0.203，不显著**。Δmacro-F1 的聚类 bootstrap CI 全部跨 0。
- **机制**：test 正例率 80%，macro-F1 奖励“多报”；长度规则在最短半区全报正例，在最长半区全报负例。LLM 的操作点是高精确率/低召回（DeepSeek direct pred+ 28.7%，recall 29.7%）。
- **不能声称**：简单规则“更会检测漏洞”、或 LLM 不如长度规则。换 MCC/操作点后结论翻转；dev40 只有 8 个负例，选择本身不稳。

## 7. 验证（真实执行）

| 检查 | 结果 |
| --- | --- |
| canonical run 数 | 30 |
| `ext_validate.py --jsonschema` | 全部 errors=[] |
| 父指标重算（confusion/macro-F1/MCC/valid/coverage/strict） | 全部一致 |
| 设计算术检查 | 71 项，失败 0 项 |
| CodeQL 8 个条件混淆矩阵 vs producer export | 全部一致 |
| conservative 4 臂 post macro-F1/撤销数 vs producer | 全部一致 |
| pair diff 8 个 run 的 DA vs producer | 全部一致 |
| coverage tier 计数 vs producer | 全部一致 |
| interpretable 9 个方法的 macro-F1/MCC vs producer | 全部一致 |

复现命令（WSL，项目根目录）：

```bash
python3 benchmark/extensions/tools/ext_import.py \
  --design next_iteration_batch \
  --config benchmark/extensions/configs/next_iteration_batch.json \
  --jsonschema
python3 benchmark/extensions/tools/ext_validate.py --check-registries
python3 benchmark/tools/bench_next_iteration_summary.py
```

## 8. 不能声称的事

- 不跨设计池化：每个 design 保留自己的单元、分母和主终点。
- 不修改 LEADERBOARD.md、final_summary.json、tier_a_* 或 tier_b_*；主表保持冻结。
- CodeQL triage 是 Tier B Juliet test-140；interpretable baseline 是 Tier A SecVulEval test-160；两者不可跨层比较。
- Conservative verifier 是探索性、事后分析；test split 已被第一遍和原验证器看过。
- Coverage dynamic 的 clean 是 inconclusive，不是 TN；operational 视图不是证明。
- Pair diff 的 open 臂是跨设计参考，不是池化臂。
- 单次运行、temperature 0；没有 seed 或 run-to-run 方差。

## 9. 文件

- canonical runs：`benchmark/extensions/runs/{codeql_alert_triage,conservative_verification,diff_guided_pair,coverage_instrumented_dynamic,interpretable_baseline}/`
- 导入配置：`benchmark/extensions/configs/next_iteration_batch.json`
- 汇总工具：`benchmark/tools/bench_next_iteration_summary.py`
- 机器可读：`benchmark/results/next_iteration_summary.json`
- 主表未改：`benchmark/results/LEADERBOARD.md`、`final_summary.json`、`tier_a_*`、`tier_b_*`


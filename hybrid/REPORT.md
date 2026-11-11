# AI + 传统证据引导实验报告（Juliet CWE-401，冻结 test 140）

日期：2026-11-12（Asia/Shanghai）。全部代码在 WSL Ubuntu 中运行；只写入 `hybrid/`，
未修改 `juliet/`、`traditional/`、`juliet_llm/` 或任何旧结果。

## 0. 结论

- **1400/1400 请求全部成功**：2 个模型 × 5 种方法 × 140 个冻结 test 单元，
  `ok=1400`，`invalid=0`，`api_error=0`，所有 prompt 通过泄漏审计。
- **DeepSeek-V4.1-Flash**：direct 135/140（96.43%）；static 135/140（无变化）；
  dynamic 139/140（99.29%）；combined **140/140（100%）**；shuffled placebo 135/140。
- **MiMo-V2.6-Flash**：direct 135/140（96.43%）；static 136/140（97.14%）；
  dynamic 135/140；combined **138/140（98.57%）**；shuffled placebo 135/140。
- **证据收益很小，且未达统计显著**。DeepSeek direct→combined 提高 3.57 个百分点
  （5 个单元，全部是 direct 错、combined 对），精确 McNemar 双侧 `p=0.0625`
  （5 个不一致样本时可能达到的最小 p 值），配对 bootstrap 95% CI
  `[+0.71, +7.14]` 个百分点。MiMo direct→combined 提高 2.14 个百分点
  （4 对 1），`p=0.375`，CI `[-0.71, +5.71]`。**不能宣称显著改进。**
- **安慰剂没有带来聚合收益**：两个模型的 shuffled 与 direct 都是 135/140，
  混淆矩阵完全相同；但 4/140 的个体预测被供体证据方向翻动（每个模型各 2 个
  向“有漏洞”、2 个向“无漏洞”），净收益为零。说明模型会读取证据方向，
  但代码本身仍是主导信号。
- **错误高度集中**：direct 的错误几乎都在 `_22`（全局变量控制流）good 单元。
  DeepSeek 的 5 个 FP 全是 `_22` good，combined 全部纠正；MiMo 的 4 个 FP 中
  3 个被 combined 纠正，另有 1 个 FN 被纠正，但 combined 新增 1 个 FP
  （`int_malloc_22__good`），净 +3 个单元。
- **传统工具基线低于 LLM 单独判断**：动态证据本身 91.43%（12 个 bad 未观察到
  泄漏，0 FP），静态任一工具 85.00%。DeepSeek/MiMo direct 均为 96.43%。
- **动态 inconclusive 明确按“非 clean”处理**：prompt、渲染器和分析都区分
  `leak`/`clean`/`inconclusive`。冻结 test140 恰好没有 inconclusive；
  全量 3,316 个动态 case 中有 1 个（不在冻结子集内），由渲染器自检验证。

## 1. 实验设置

### 1.1 冻结输入

| 输入 | 路径 | SHA-256 |
| --- | --- | --- |
| 200 单元冻结清单 | `juliet/subset_units.jsonl` | `4827d1da6a1966759d66989dfb16678bc3e14d8f0588f9fe59d92a08ae4aac24` |
| 静态真实结果 | `traditional/static/runs/juliet_formal_20261112_clang_cppcheck_gnu/predictions.jsonl` | `f9d2f59af172dd3b68af5ee84bc17ac784f53a95a3f07d61c2441bda66e26fa5` |
| 动态 cases | `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/cases.jsonl` | `cc8db43b84f5eb106461cea6d86ac2b9934173c7ea5fe4abfb36690af1a7bc42` |
| 动态 results | 同目录 `results.jsonl` | `405381672467c146ac9e183f427be27fbff677be26844b6782d28a0f02218f64` |

test 140 单元：70 bad / 70 good，58 C / 82 C++。动态结果按
`(排序后的 sources, 排序后的 defines)` 精确连接，140/140 命中，无重复键。
静态结果本身就以 `unit_id` 为键，140/140 覆盖。

### 1.2 源码清洗

源码使用 `juliet_llm.cleaning.clean_unit`（共享清洗器），而不是另写一份：

- 去除注释；
- 用单元 defines 解析 `OMITBAD`/`OMITGOOD`，只保留实际编译分支；
- 内联单元局部头文件，丢弃 `std_testcase.h`；
- 将含 `bad`/`good`/`CWE`/`Memory_Leak` 的标识符统一重命名为 `sym_N`；
- 清洗含标签词的字符串；
- 审计失败即抛错。

`hybrid/inputs/prompt_audit.json` 记录：140 个 direct prompt 的 SHA-256 与
`juliet_llm/build/test.jsonl` **逐条完全一致**（140/140，0 mismatch）；
5 种方法共 700 个 prompt 全部通过 `prompt_forbidden_hits` 与 unit-id 检查。

### 1.3 证据构造

- **static**：来自真实 Clang Static Analyzer 与 Cppcheck 行，包含
  `status`、诊断数、与内存泄漏相关的 finding 数、最多 5 条清洗后的 message。
  `compile_error` 渲染为“分析失败、无结论”，绝不当作 clean。
- **dynamic**：来自真实 ASan/LSan 与 Valgrind，包含每个检测器状态、泄漏字节数、
  总体 outcome。`inconclusive` 渲染为“harness 未判定，**不是 clean**”。
- 证据文本清除绝对路径、文件名、行号、`CWE` 标识、`OMIT*` 宏、
  `bad`/`good` 标识符；`sanitize.assert_clean` 在构造时强制失败关闭。
- **combined** = static + dynamic。
- **shuffled（安慰剂）**：使用另一个单元（不同 Juliet group，且非自身）的
  combined 证据。固定 seed `20261112`，140 对全部满足“非自身 + 不同 group”。
  供体 id 只记录在输入清单中，不进入 prompt。

### 1.4 Prompt 与输出格式

- `direct` 直接调用 `juliet_llm.prompting.build_messages`，与 Juliet LLM baseline
  字节级一致。
- 其余方法沿用同一个 system prompt、同一个泄漏定义和同一个输出 schema，
  只在 user message 中插入 `<Tool evidence>` 块。
- 输出 schema：`{"label": "vulnerable"|"not_vulnerable", "confidence": ..., "reason": ...}`。
- temperature 0，`response_format=json_object`，输出上限 8192。
- DeepSeek：`deepseek-v4.1-flash`，非 thinking，价格 $0.30/$1.20/$0.006 per 1M。
- MiMo：`mimo-v2.6-flash`，`thinking=disabled`、`reasoning_effort=none`、
  `max_completion_tokens=8192`，价格 $0.14/$0.28/$0.0028 per 1M。
- 凭据从 `/mnt/c/Users/tzh03/.kimi-code/config.toml` 读入进程内存，未打印、
  未写入 `config.json`/`results.jsonl`/日志；`verify_outputs.py` 对结果文件
  做了密钥与常见密钥标记扫描。

## 2. 主结果

严格评分：140 个计划单元全部计入；invalid/失败记为错误，绝不算正确负例。
本次没有 invalid，因此 strict 与 valid-only 相同。

| 模型 | 方法 | 正确/140 | 准确率 | Precision | Recall | F1 | Specificity | MCC | 列表成本 USD | 实际额度 USD |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 135 | 96.43% | 93.33% | 100.00% | 0.9655 | 92.86% | 0.9309 | 0.020570 | 0.006171 |
| DeepSeek | static | 135 | 96.43% | 93.33% | 100.00% | 0.9655 | 92.86% | 0.9309 | 0.023492 | 0.007048 |
| DeepSeek | dynamic | 139 | 99.29% | 98.59% | 100.00% | 0.9929 | 98.57% | 0.9858 | 0.022894 | 0.006868 |
| DeepSeek | combined | **140** | **100.00%** | 100.00% | 100.00% | 1.0000 | 100.00% | 1.0000 | 0.029260 | 0.008778 |
| DeepSeek | shuffled | 135 | 96.43% | 93.33% | 100.00% | 0.9655 | 92.86% | 0.9309 | 0.022316 | 0.006695 |
| MiMo | direct | 135 | 96.43% | 94.52% | 98.57% | 0.9650 | 94.29% | 0.9294 | 0.006470 | 0.006470 |
| MiMo | static | 136 | 97.14% | 94.59% | 100.00% | 0.9722 | 94.29% | 0.9444 | 0.014098 | 0.014099 |
| MiMo | dynamic | 135 | 96.43% | 95.77% | 97.14% | 0.9645 | 95.71% | 0.9287 | 0.013544 | 0.013544 |
| MiMo | combined | **138** | **98.57%** | 97.22% | 100.00% | 0.9859 | 97.14% | 0.9718 | 0.011963 | 0.011963 |
| MiMo | shuffled | 135 | 96.43% | 94.52% | 98.57% | 0.9650 | 94.29% | 0.9294 | 0.009256 | 0.009256 |

说明：OpenCode Go 的 DeepSeek 实际 `usage.opencode.allowance` 明显低于按
$0.30/$1.20 计算的列表成本；MiMo 两者一致。报告同时保留两个口径，避免把
列表价格当作实际扣费。

延迟（每请求 wall time）：

| 模型 | 方法 | mean s | p50 s | p95 s | max s |
| --- | --- | ---: | ---: | ---: | ---: |
| DeepSeek | direct | 4.85 | 4.78 | 6.09 | 7.20 |
| DeepSeek | static | 4.80 | 4.79 | 6.27 | 7.44 |
| DeepSeek | dynamic | 5.04 | 4.93 | 6.28 | 10.74 |
| DeepSeek | combined | 6.05 | 5.16 | 15.65 | 16.13 |
| DeepSeek | shuffled | 5.44 | 4.97 | 6.95 | 23.07 |
| MiMo | direct | 6.78 | 3.56 | 37.94 | 43.48 |
| MiMo | static | 3.17 | 2.90 | 6.25 | 13.63 |
| MiMo | dynamic | 3.96 | 3.34 | 8.02 | 12.56 |
| MiMo | combined | 4.21 | 2.81 | 7.95 | 37.60 |
| MiMo | shuffled | 3.65 | 3.20 | 7.14 | 10.77 |

DeepSeek combined 的 p95 被一个 16.1 s 请求抬高；MiMo direct 的 p95 被一个
43.5 s 请求抬高。1400 个请求中 1399 个一次成功，1 个 MiMo dynamic 请求
（`CWE401_Memory_Leak__char_calloc_01__good`）因空 content 自动重试一次后成功，
最终仍为 `ok`。

## 3. 配对统计

严格正确性逐单元配对；p 值为精确双侧 McNemar；CI 为配对 bootstrap
（10,000 次，seed `20261112`）。

| 模型 | 对比 | Δ准确率 | 95% CI | 不一致数（新对/旧对） | McNemar p |
| --- | --- | ---: | --- | ---: | ---: |
| DeepSeek | direct → static | 0.00 pp | [0.00, 0.00] | 0 / 0 | 1.000 |
| DeepSeek | direct → dynamic | +2.86 pp | [+0.71, +5.71] | 4 / 0 | 0.125 |
| DeepSeek | direct → combined | +3.57 pp | [+0.71, +7.14] | 5 / 0 | **0.0625** |
| DeepSeek | direct → shuffled | 0.00 pp | [-2.86, +2.86] | 2 / 2 | 1.000 |
| DeepSeek | combined → shuffled | -3.57 pp | — | 0 / 5 | **0.0625** |
| MiMo | direct → static | +0.71 pp | [-1.43, +2.87] | 2 / 1 | 1.000 |
| MiMo | direct → dynamic | 0.00 pp | [-2.14, +2.14] | 1 / 1 | 1.000 |
| MiMo | direct → combined | +2.14 pp | [-0.71, +5.71] | 4 / 1 | 0.375 |
| MiMo | direct → shuffled | 0.00 pp | [-2.86, +2.86] | 2 / 2 | 1.000 |
| MiMo | combined → shuffled | -2.14 pp | — | 0 / 3 | 0.250 |

关键事实：

- DeepSeek 的 5 个改进单元全部是 direct 错、combined 对；没有反向翻转。
  但 5 个不一致样本的精确 McNemar 最小可能 p 就是 0.0625，因此该实验
  **没有足够功效**在 0.05 水平上宣称显著。
- MiMo 的 combined 相对 direct 是 4 对 1，净 +3 单元，p=0.375。
- 所有“证据方法 vs 安慰剂”的差异都不显著。
- DeepSeek 的 static 与 direct 预测 **逐单元完全相同**（0 个翻转）；
  MiMo static 有 3 个翻转（2 对 1 错），净 +1。
- DeepSeek dynamic 有 4 个翻转（全对），combined 有 5 个翻转（全对）；
  MiMo combined 有 5 个翻转（4 对 1 错）。

## 4. 安慰剂检验

两个模型的 shuffled 与 direct 聚合结果完全相同（均 135/140），但个体层面
并非完全不动：

| 模型 | 被翻动的单元 | direct → shuffled | 供体证据方向 |
| --- | --- | --- | --- |
| DeepSeek | `malloc_realloc_int64_t_09__good` | 0 → 1 | bad |
| DeepSeek | `new_array_wchar_t_72__good` | 0 → 1 | bad |
| DeepSeek | `new_array_int_22__good` | 1 → 0 | good |
| DeepSeek | `twoIntsStruct_realloc_22__good` | 1 → 0 | good |
| MiMo | `int_calloc_54__good` | 0 → 1 | bad |
| MiMo | `int_malloc_22__good` | 0 → 1 | bad |
| MiMo | `new_array_char_22__good` | 1 → 0 | good |
| MiMo | `new_array_int_22__good` | 1 → 0 | good |

按供体标签统计预测为 vulnerable 的比例：

| 模型 | 供体 bad（n=70） | 供体 good（n=70） |
| --- | ---: | ---: |
| DeepSeek | 41/70 = 58.6% | 34/70 = 48.6% |
| MiMo | 39/70 = 55.7% | 34/70 = 48.6% |

解释：

- 错配证据确实会按供体方向轻微推动边界样本：供体是 bad 时更倾向判 vulnerable，
  供体是 good 时更倾向判 not_vulnerable。
- 但推动幅度只有约 7–10 个百分点，且方向对称，净准确率恰好不变。
- 因此 combined 相对 direct 的 +5/+3 个单元不能简单归因于“多了一段证据文本”：
  同样长度、同样格式的错配证据没有带来收益。但受样本量限制，这仍只能作为
  方向性证据，不能作为显著因果结论。

## 5. 错误结构：`_22` good 单元

direct 的错误高度集中在一个流变体：

- DeepSeek direct 的 5 个错误全部是 FP，且全部是 `_22` good：
  `int_malloc_22`、`new_array_char_22`、`new_array_int_22`、`new_int_22`、
  `twoIntsStruct_realloc_22`。combined 全部纠正。
- MiMo direct 有 4 个 FP（同样是 `_22` good 中的 4 个）和 1 个 FN
  （`malloc_realloc_int_01__bad`）。combined 纠正了 3 个 `_22` FP 和该 FN，
  但新增 `int_malloc_22__good` 这个 FP，并保留
  `twoIntsStruct_realloc_22__good`，净错误数从 5 降到 2。
- `_22` 变体通过全局变量在多个 sink 之间传递控制流，good 版本在“另一条”分支
  释放内存；direct 容易只看到当前分支未释放而误报。动态 clean 证据和组合证据
  能帮助模型重新检查全局标志，但 MiMo combined 仍有 2 个 FP。
- DeepSeek direct 中有 2 个 FP 的 `reason` 明确写“No leak”，但 `label` 仍是
  vulnerable（`new_array_int_22__good`、`new_int_22__good`），属于标签/理由
  不一致，而不是证据误判。combined 纠正了这两处。

- MiMo combined 的 2 个残留 FP 都是 C 单元（`int_malloc_22__good`、
  `twoIntsStruct_realloc_22__good`）；其 82 个 C++ 单元全部正确。
- 两个模型都有 133/140 个单元在 5 种方法下预测完全一致；方法间差异集中在
  其余 7 个边界单元。

## 6. 动态证据与 inconclusive

test140 的动态证据分布：

| 真实标签 | 动态 leak | 动态 clean | 动态 inconclusive |
| --- | ---: | ---: | ---: |
| bad (70) | 58 | 12 | 0 |
| good (70) | 0 | 70 | 0 |

动态工具单独作为分类器：准确率 91.43%，precision 100%，recall 82.86%，
specificity 100%。12 个 bad 单元在默认运行中没有观察到泄漏，这是工具 FN，
不是“clean 标签”。

模型在动态证据条件下的表现：

| 模型/方法 | 证据 leak（n=58） | 证据 clean（n=82） |
| --- | --- | --- |
| DeepSeek/dynamic | 判 vulnerable 100%，准确率 100% | 判 vulnerable 16%，准确率 99% |
| DeepSeek/combined | 100%，100% | 15%，100% |
| MiMo/dynamic | 100%，100% | 16%，准确率 94% |
| MiMo/combined | 100%，100% | 17%，准确率 98% |

也就是说：leak 证据几乎被完全采纳；clean 证据没有被盲目当作标签，12 个
“bad 但 clean 证据”的单元大多仍被模型从代码中识别出来（DeepSeek 全部识别，
MiMo 仍有 2 个 FN）。这符合“动态 clean 不是证明不存在”的设定。

inconclusive 处理：

- prompt 中明确写“a dynamic result marked inconclusive is NOT a clean result”；
- 渲染器对 `inconclusive` 输出“the harness did not decide; this is NOT a clean result”；
- `selftest.py` 用合成的 inconclusive 记录验证了该文本；
- 冻结 test140 没有 inconclusive，不能声称在真实 test 样本上观察到了该分支；
  全量 3,316 个动态 case 中唯一一个 inconclusive 不在冻结子集内。

## 7. 成本与用量

| 模型 | 请求数 | 列表成本 USD | 实际额度 USD | 输入 token | 输出 token |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 700 | 0.118533 | 0.035559 | 511,242 | 35,349 |
| MiMo | 700 | 0.055332 | 0.055332 | 506,455 | 33,135 |
| 合计 | 1400 | **0.173865** | **0.090891** | **1,017,697** | **68,484** |

缓存命中：DeepSeek 262,784 prompt tokens，MiMo 181,120，合计 443,904。
两个模型 `reasoning_tokens` 均为 0（MiMo 已用 `reasoning_effort=none` 关闭推理）。

## 8. 限制

1. **样本量与功效**：140 个单元，direct 已经 96.43%，只剩 5 个错误单元。
   DeepSeek combined 的 +5 个单元对应精确 McNemar p=0.0625；在 5 个不一致
   样本下不可能达到 p<0.05。不能把“100%”当作显著优于 direct。
2. **天花板效应**：两个模型 direct 都是 135/140，证据最多只能修复 5 个单元；
   实验结果对这几个 `_22` 单元非常敏感。
3. **单一安慰剂抽样**：固定 seed 只抽了一个 derangement。虽然它满足非自身、
   不同 group，且 4 个翻转方向对称，但不能估计 placebo 的抽样分布。
4. **工具误差继承**：静态/动态证据来自既有冻结运行；4 个 test 单元 clang
   编译失败，动态有 12 个 bad 未观察到泄漏。证据方法继承这些错误。
5. **inconclusive 无真实 test 样本**：test140 没有 inconclusive，只有渲染器
   自检；全量中唯一的 inconclusive 在子集外。
6. **Juliet 合成数据**：单元小、单缺陷、由模板生成；不能外推到真实项目。
7. **标签/理由不一致**：观察到模型偶尔给出与 `reason` 相反的 `label`；
   本报告按 `label` 评分，未把 `reason` 纳入自动评分。
8. **端点噪声**：`juliet_llm` 自己的 MiMo direct（Xiaomi 官方端点）在同样 140
   个单元上是 134/140（95.71%），本实验用 OpenCode Go 是 135/140；同一模型
   换端点就差 1 个单元。这个量级与 combined 的 +3/+5 个单元接近，进一步说明
   不能把少量单元差异夸大为稳定改进。

## 9. 产物

- 输入包：`hybrid/inputs/units.jsonl`、`hybrid/inputs/manifest.json`
  （140 单元、证据、安慰剂映射、输入哈希）。
- Prompt 审计：`hybrid/inputs/prompt_audit.json`（140/140 direct 与
  `juliet_llm` 一致，5 种方法全部通过泄漏检查）。
- 运行目录：`hybrid/runs/hybrid_v1_<model>_<method>/`
  （`config.json`、`manifest.json`、`requests.jsonl`、`results.jsonl`、
  `metrics.json`）。
- 汇总：`hybrid/results/hybrid_v1_metrics.json`、
  `hybrid/results/hybrid_v1_tables.md`、
  `hybrid/results/hybrid_v1_predictions.csv`（1400 行逐单元预测）。
- 审计：`hybrid/verify_outputs.py`（140/140、状态、成本、密钥扫描、
  placebo 约束）；`hybrid/selftest.py`（清洗、prompt、inconclusive 文本）。

## 10. 复现

```bash
python3 hybrid/build_inputs.py --out hybrid/inputs
python3 hybrid/run_hybrid.py --model all --dry-run          # 只审计，不发请求
python3 hybrid/run_hybrid.py --model all --concurrency 12 \
  --out-root hybrid/runs --run-id hybrid_v1
python3 hybrid/analyze.py --run-id hybrid_v1
python3 hybrid/verify_outputs.py --run-id hybrid_v1
python3 hybrid/selftest.py
```

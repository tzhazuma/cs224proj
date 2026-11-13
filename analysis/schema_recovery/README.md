# `analysis/schema_recovery`：DeepSeek 六 run 的零 API schema 复分析

**版本**：`schema-recovery-2026-11-14.1`  
**日期**：2026-11-14  
**范围**：`runner/runs/test_v1_*` 六个 DeepSeek run（924 条 repair 请求）与六个 MiMo run（1,560 条 detection、924 条 repair）；冻结 `secvul-split-v1` test。  
**API / 网络调用**：**0**。只读已落盘的 `results.jsonl`、`config.json`、`metrics.json`、两个 split、`runner/secvul_runner/validation.py` 和 `analysis/cost_normalization.json`；不调用模型、不访问网络；默认只写本目录（`--out-dir` 可显式改输出目录）。  
**产物**：`recover.py`、`schema_recovery.json`、`schema_recovery.md`、`records.jsonl`、本 README。  
**No git**：本目录没有执行任何 git 操作；旧 run、旧脚本、旧报告均未修改。

---

## 0. 一句话结论

DeepSeek 的 **102 条 repair invalid** 中，**93 条只是缺 `explanation`**；这 93 条全部是合法 JSON、全部有非空 `fixed_function`、全部 `finish_reason=stop`。按项目的 canonical 结构代理，91 条结构完整；按 K&R-aware 检查，93 条都完整。93 条中 71 条在 collapse-whitespace 口径下有实质改动，69 条在 comment-insensitive token 口径下仍有改动；结构完整 ∩ 后者的 **usable patch 是 67 条（canonical）或 69 条（K&R-aware）**。

官方 strict schema 有效率 **822/924 = 88.96%**；只把“缺 explanation”当作可接收字段的 code-only admission 是 **915/924 = 99.03%**。usable patch 从 **552/924 = 59.74%** 升到 **619/924 = 66.99%**，即 **+7.25 pp**。以 93 条 missing 为分母，usable 率是 **67/93 = 72.0%**（canonical）或 **69/93 = 74.2%**（K&R-aware）；以 102 条 invalid 为分母是 **65.7% / 67.6%**；以 924 条 repair 请求为分母是 **7.25% / 7.47%**。salvage 的边际 API 成本是 **$0**，但 **salvage 不是正确率**：67 条 usable 仍没有编译、测试、PoC 或人工评审。

MiMo 的 61 条 detection field drift 是镜像但不同任务的失败：**61/61 可 alias-remap**，但 recovered value 只有 **5 true / 56 false**，与 gold label 的 post-hoc 一致只有 **28/61**。这正好说明“格式可回收”与“内容正确”是两件事。

---

## 1. 为什么做这个复分析（文献依据）

本项目已有 `research/latest_llm_methods_2026.md` 的 P0 建议和 `research/latest_evaluation_repair_2026.md` 的报告清单。本目录把 P0 落成一个只读脚本，遵循以下几条：

| 文献/项目建议 | 本目录的实现 | 它不能证明什么 |
| --- | --- | --- |
| **JSON mode 只保证合法 JSON，不保证 schema adherence**；Structured Outputs 才保证字段齐全 `[C1][C2]` | 同时报告 **official strict**（`status == "ok"`）与 **code-only admission**（只缺 `explanation`）；两者不合并成一个“schema 有效率” | 不能把 code-only 说成 official 分数 |
| **format repair 会伪装成 self-correction**；grammar-constrained decoding 可解释掉中位 71% 的“表观增益” `[B14]` | 单独标记 `missing_explanation` / `field_drift`；报告 `format_repaired` 式的 salvage，但**从不**把它叫 accuracy 或 self-correction | 不能把 salvage 当成模型能力提升 |
| **validity constraint 提升可靠性，reasoning constraint 才可能提升准确率** `[B15]` | 把“结构完整”“文本改动”“comment-insensitive 实质改动”“usable patch”拆成四级；分别报告 | 不能从格式合规推断修复正确 |
| **schema 覆盖/语法约束有差异**；SynCode 消除 JSON 语法错误，但不解决语义 `[A16][A18]` | 截断判 **fatal**（不补引号/括号）；字段重命名判 **recoverable-format**；两者分开 | 不能把“可解析”当成“可用” |
| **plausible patch ≠ correct patch**；AutoPatchBench 约 60% 可生成、5–11% 正确 `[C7]` | 统计 no-change / whitespace-only / comment-only；明确 usable 只是结构代理，没有 oracle | 不能把 usable patch 叫“修复正确率” |
| **报告 N_all / N_valid / N_invalid、排除原因、成本口径、oracle 级别** `[P]` | 每个表都给分母；成本同时给 reported、configured peak cache-aware 与 off-peak list normalized；oracle 级别明确为 **L0（无编译/测试）** | 不能把 L0 结果写成 L2/L3 |

参考文献条目沿用 `research/latest_llm_methods_2026.md` §10 的编号；`[P]` 指本项目实测/报告规范。

---

## 2. 数据与口径

### 2.1 十二个 run

| 模型 | 策略 | 任务 | run_id | repair | detection |
| --- | --- | --- | --- | ---: | ---: |
| DeepSeek | direct | independent | `test_v1_direct_independent` | 128 | 160 |
| DeepSeek | direct | pairs | `test_v1_direct_pairs` | 180 | 360 |
| DeepSeek | few-shot | independent | `test_v1_few-shot_independent` | 128 | 160 |
| DeepSeek | few-shot | pairs | `test_v1_few-shot_pairs` | 180 | 360 |
| DeepSeek | context | independent | `test_v1_context_independent` | 128 | 160 |
| DeepSeek | context | pairs | `test_v1_context_pairs` | 180 | 360 |
| MiMo | direct | independent | `test_v1_mimo_direct_independent` | 128 | 160 |
| MiMo | direct | pairs | `test_v1_mimo_direct_pairs` | 180 | 360 |
| MiMo | few-shot | independent | `test_v1_mimo_few-shot_independent` | 128 | 160 |
| MiMo | few-shot | pairs | `test_v1_mimo_few-shot_pairs` | 180 | 360 |
| MiMo | context | independent | `test_v1_mimo_context_independent` | 128 | 160 |
| MiMo | context | pairs | `test_v1_mimo_context_pairs` | 180 | 360 |

脚本对 12 个 run 做 **96 项** `metrics.json` 与 `results.jsonl` 重算的交叉检查（requested、schema_valid/invalid、complete_and_changed、detection valid_predictions、成本之和），**0 不匹配**；两个 split 的 SHA-256 与 12 个 config 的 `dataset_sha256` 全部匹配。

### 2.2 三个视图（不要混）

| 视图 | 定义 | 不是什么 |
| --- | --- | --- |
| **official strict** | `record.status == "ok"`；repair 恰好 `fixed_function` + `explanation`；detection 恰好 `is_vulnerable` + `confidence` + `rationale` | 不是修复正确率，只是 schema 门槛 |
| **code-only salvage** | 仅 repair：合法 JSON、非空 `fixed_function`、只缺 `explanation`；仍保留 official 为 0 分 | 不是 official 分数，不是模型自我修正 |
| **usable patch** | canonical complete（或 K&R-aware complete）+ **comment-insensitive** 实质改动 | 不是编译通过、测试通过、PoC 通过、漏洞已修 |

**实质改动的四级阶梯**（93 条 missing-explanation）：

| 层级 | 定义 | n/93 |
| --- | --- | ---: |
| text changed | `normalize_code` 后文本不同 | 75 |
| substantive（collapse） | `collapse_whitespace` 后仍不同；文献里的“实质改动”口径 | 71 |
| comment-insensitive substantive | 去掉注释、保留字符串字面量后 token 序列仍不同 | 69 |
| usable canonical | canonical complete ∩ comment-insensitive substantive | **67** |
| usable K&R-aware | K&R-aware complete ∩ comment-insensitive substantive | **69** |

为什么加 comment-insensitive 这一层：有 **2 条**记录只改了注释/注释内空白；`collapse_whitespace` 会把它们算作“实质”，但 token 序列不变。它们不应被算作可用补丁。这正是 Calibration Floor 所说的“format repair 伪装成 content change”的小样本例子。

---

## 3. 发现

### 3.1 102 条 invalid 的构成

| 类别 | n | 占 924 条 repair | 占 102 条 invalid | configured peak 成本 | off-peak list 成本 | 占 invalid 成本（peak） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `missing_explanation` | 93 | 10.06% | 91.18% | $0.103564 | $0.051782 | 47.44% |
| `truncation` | 9 | 0.97% | 8.82% | $0.114715 | $0.057358 | 52.56% |
| **total** | **102** | **11.04%** | **100%** | **$0.218280** | **$0.109140** | **100%** |

- 93 条全部 `finish_reason=stop`，key set 恰好是 `{fixed_function}`；没有 JSON 语法错误，不是截断。
- 9 条截断全部 `finish_reason=length`，来自 3 个超长样本 × 3 个策略（`idx:7018`、`pair:8675:8676:vulnerable`、`pair:9912:9913:vulnerable`），content 21,876–27,473 字符。**截断是 fatal**：不补引号/括号，不把分析者伪造的闭合算成模型输出；0/9 进入 usable。

### 3.2 93 条 missing-explanation 的结构与改动

| 检查 | n/93 | 说明 |
| --- | ---: | --- |
| 合法 JSON、可解析 | 93 | 没有语法错误 |
| `fixed_function` 存在且非空 | 93 | payload 在 |
| canonical complete | 91 | 2 条 K&R 被 canonical 规则误判 |
| K&R-aware complete | 93 | 修正 K&R 误判 |
| balanced delimiters | 93 | 圆/方/花括号平衡 |
| ends with `}` | 93 | 归一后最后非空字符是 `}` |
| no markdown fence | 93 | 没有代码围栏 |
| not diff-like | 93 | 不是 diff/patch 文本 |
| text changed | 75 | 归一文本不同 |
| collapse-substantive | 71 | 文献口径 |
| comment-insensitive substantive | 69 | 去掉注释后 token 仍不同 |
| usable canonical | **67** | 结构完整 ∩ comment-insensitive 改动 |
| usable K&R-aware | **69** | K&R-aware 结构完整 ∩ comment-insensitive 改动 |

**非 usable 的 26 条（canonical）**：

| 类别 | n | 说明 |
| --- | ---: | --- |
| no change | 18 | 与输入归一文本完全相同；即使 schema 修好也是空补丁 |
| whitespace only | 4 | 只改空白/换行，token 不变 |
| comment only | 2 | 只改注释或注释内空白，token 不变 |
| K&R false negative | 2 | canonical 误判，但 K&R-aware 下可用 |
| **total** | **26** | 67 + 18 + 4 + 2 + 2 = 93 |

2 条 canonical incomplete 是 `zlib` 的 K&R 风格定义：`int ZEXPORT deflatePrime (strm, bits, value)` 后接 `z_streamp strm; int bits; int value;` 再 `{`。它们平衡、以 `}` 结束、无围栏/ diff；canonical 规则仅因为 `{` 前以 `;` 结束而判 false。**这是结构代理的已证实假阴性**，不是补丁损坏。

### 3.3 官方 strict vs code-only

| 策略 | 请求 | official valid | code-only admitted | official usable | salvage usable | code-only usable | Δ usable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| direct | 308 | 260 | 305 | 190 | 33 | 223 | +10.71 pp |
| few-shot | 308 | 305 | 305 | 165 | 0 | 165 | +0.00 pp |
| context | 308 | 257 | 305 | 197 | 34 | 231 | +11.04 pp |
| **total** | **924** | **822** | **915** | **552** | **67** | **619** | **+7.25 pp** |

- `official usable` / `code-only usable` 的主定义是 **canonical complete + comment-insensitive substantive change**。
- direct/context 的 salvage gain 约 **10.7–11.0 pp**；few-shot 已经 schema 对齐（305/308，3 条截断），gain 为 0。
- 换定义后的 sensitivity：

| 改动定义 | official | code-only | Δ |
| --- | ---: | ---: | ---: |
| text changed（prior code-only 口径） | 610/924 = 66.02% | 683/924 = 73.92% | +7.90 pp |
| collapse-substantive | 555/924 = 60.06% | 624/924 = 67.53% | +7.47 pp |
| **comment-insensitive substantive（主口径）** | **552/924 = 59.74%** | **619/924 = 66.99%** | **+7.25 pp** |
| comment-insensitive + K&R-aware complete | 556/924 = 60.17% | 625/924 = 67.64% | +7.47 pp |

**关键读法**：schema 门槛本身只解释约 **7.3–7.9 pp** 的 usable 变化；从 915/924 的 code-only admission 到 619/924 的 usable，仍有约 **32 pp** 落在 no-change / whitespace-only / comment-only / 结构或内容不满足上。**schema 不是修复质量的主矛盾。**

官方 schema 有效的 822 条里，usable 只有 552（67.15%），no change 208（25.30%），whitespace only 55（6.69%），comment only 3（0.36%），K&R false negative 4。few-shot 的 no-change 率最高：DeepSeek 37.4%，MiMo 50.2%。**schema valid ≠ usable patch。**

### 3.4 成本

> **两个 cache-aware 口径，不能混用。** `configured_peak_cache_aware` 用每个 run 的配置卡（DeepSeek 0.30/1.20/0.006；MiMo 0.14/0.28/0.0028）；`offpeak_list_normalized` 用全项目非高峰卡（DeepSeek 0.15/0.60/0.003；MiMo 同价）。**本目录的 `$2.521790` 是 configured peak 合计，不是全项目统一 normalized；同一 12 个 run 的 off-peak list 是 `$1.572472`。**

| 口径 | DeepSeek | MiMo | 与项目报告的关系 |
| --- | --- | --- | --- |
| reported | `response.cost.cost_usd`；DeepSeek legacy 不扣 cache | `response.cost.cost_usd`；MiMo 正确带 cached token | 原始账单值，不能直接跨模型比较 |
| configured_peak_cache_aware | 0.30 / 1.20 / 0.006 | 0.14 / 0.28 / 0.0028 | 本目录主表；DeepSeek 是观测到的峰价卡 |
| offpeak_list_normalized | 0.15 / 0.60 / 0.003 | 0.14 / 0.28 / 0.0028 | 与 `analysis/cost_normalization.md` 的 `normalized_list_usd` 同口径 |

| bucket | records | configured peak $ | off-peak list $ | 占 DS 总成本（peak） | 占 DS repair（peak） | 占 invalid（peak） |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DeepSeek all | 2,484 | $1.898636 | $0.949318 | 100.0% | — | — |
| DeepSeek repair | 924 | $1.323252 | $0.661626 | 69.70% | 100.0% | — |
| DeepSeek invalid | 102 | $0.218280 | $0.109140 | 11.50% | 16.50% | 100.0% |
|   missing explanation | 93 | $0.103564 | $0.051782 | 5.45% | 7.83% | 47.44% |
|   truncation | 9 | $0.114715 | $0.057358 | 6.04% | 8.67% | 52.56% |
|   usable salvage（canonical） | 67 | $0.083341 | $0.041671 | 4.39% | 6.30% | 38.18% |
|   missing but non-usable | 26 | $0.020223 | $0.010112 | 1.07% | 1.53% | 9.26% |

DeepSeek 的 off-peak list 成本是 configured peak 的精确 0.5×，所以占比列在两种口径下相同；**不要把 0.5× 套到 MiMo**（MiMo 没有峰谷价，两口径相同）。

**计数与成本的主矛盾不同**：missing explanation 占 invalid 条数的 91.18%，但只占 invalid 成本的 47.44%；9 条截断占条数的 8.82%，却占 invalid 成本的 52.56%（单条约 $0.01275，是 missing 单条的约 11.4 倍）。把“invalid 成本主要是缺 explanation”当成结论，只在按记录数计时成立。

**salvage 的成本结构**：

| 项 | configured peak $ | off-peak list $ | 占 invalid 成本（peak） |
| --- | ---: | ---: | ---: |
| invalid total | $0.218280 | $0.109140 | 100.0% |
| recoverable → usable（canonical） | $0.083341 | $0.041671 | 38.18% |
| recoverable → usable（K&R-aware） | $0.084200 | $0.042100 | 38.57% |
| missing but non-usable（canonical） | $0.020223 | $0.010112 | 9.26% |
| fatal truncation | $0.114715 | $0.057358 | 52.56% |

salvage 的**边际 API 成本是 $0**：响应已经生成并付费，复分析只是重新分类已发生的沉没成本。这不等于“免费获得正确补丁”。

**每单位结构性可用输出的平均成本**：

| 口径 | configured peak $/unit | off-peak list $/unit | 分母 |
| --- | ---: | ---: | ---: |
| official usable（canonical） | $0.002397 | $0.001199 | 552 |
| code-only usable（canonical） | $0.002138 | $0.001069 | 619 |
| code-only usable（K&R-aware） | $0.002117 | $0.001059 | 625 |
| salvage usable（canonical） | $0.001244 | $0.000622 | 67 |
| salvage usable（K&R-aware） | $0.001220 | $0.000610 | 69 |
| truncation / record | $0.012746 | $0.006373 | 9 |
| MiMo field drift / recovered | $0.000163 | $0.000163 | 61 |

**MiMo 与合计**：MiMo detection $0.250113（两口径相同）；field drift 61 条 $0.009920（占 detection 3.97%）；repair truncation 9 条 $0.032125（占 MiMo invalid 76.41%）；MiMo total $0.623154。两模型合计 invalid：configured peak **$0.260325 / $2.521790 = 10.32%**；off-peak list **$0.151185 / $1.572472 = 9.61%**。

**reported vs 两种 cache-aware 口径**：DeepSeek 的 `response.cost` 没有扣 cached token；两种 cache-aware 视图都用 usage 的 cached_tokens 重算，区别只在价格卡。DS 93 条 missing 的 reported 与 configured peak 恰好相同（$0.103564），off-peak list 是 $0.051782；9 条截断 reported $0.117312 vs peak $0.114715、off-peak $0.057358。official 账单仍以 reported 为准。

**与 `analysis/cost_normalization.md` 的交叉核对**（同一 12 个 test_v1 run、4,968 条记录）：本目录 configured peak 重算 **$2.521790096** = 参考 `legacy_test.configured_cache_aware_usd`；off-peak list 重算 **$1.572472286** = 参考 `legacy_test.normalized_list_usd`，两者 Δ 均为 $0.000000。参考文件 SHA-256 记录在 `schema_recovery.json` 的 `sources.cost_normalization`。

### 3.5 MiMo field drift 对照

| 维度 | DeepSeek repair: missing explanation | MiMo detection: field drift |
| --- | --- | --- |
| failure count | 93 | 61 |
| denominator | 924 repair | 1,560 detection |
| failure rate | 10.06% | 3.91% |
| direct / few-shot / context | 45 / 0 / 48 | 39 / 0 / 22 |
| independent / pairs | 37 / 56 | 17 / 44 |
| JSON parse | 93/93 | 61/61 |
| payload recoverable | 93/93 | 61/61 |
| structural / usable | canonical 91/93; K&R 93/93; usable 67 canonical / 69 K&R | payload valid 61; label agreement 28 |
| downstream check | none; compile/test/PoC not run | descriptive label agreement only; not accuracy |
| failure-class cost (configured peak) | $0.103564 | $0.009920 |
| failure-class cost (off-peak list) | $0.051782 | $0.009920 |
| share of invalid cost (configured peak) | 47.44% | 23.59% |
| share of invalid cost (off-peak list) | 47.44% | 23.59% |

**漂移键**：59 条只写 `is_vulnerability`，1 条写 `is_vulnerative`，1 条同时写 `is_vulnerable` + `is_vulnerability`。61/61 可 alias-remap；61/61 的 `confidence`/`rationale` 通过类型检查。但 recovered value 是 **5 true / 56 false**，gold 是 **36 true / 25 false**，post-hoc label 一致只有 **28/61**（33 条不一致）。

这组数字的用途是**反例**：format recovery 可以 100%，但恢复出来的检测大多仍是 false；把它叫“正确率提升”会掩盖 33/61 的不一致。MiMo 的 61 条不是随机失败：direct 39、context 22、few-shot 0；DeepSeek 的 93 条同样是 direct 45、context 48、few-shot 0。两边的格式失败都在 few-shot 消失。

但两边的下游可验证性不同：MiMo 的 payload 里有可直接对 label 的布尔值；DeepSeek 的 payload 是代码，没有编译/测试/PoC 就只能停在结构代理。因此 **不能**把 28/61 与 67/93 放在同一把尺子上。

### 3.6 模型比较敏感性（post-hoc，不是新主终点）

这里的 CAC（complete + change）是结构代理，不是正确率；`official` 只算 schema-valid，`code-only` 额外接收 missing-explanation。下表只回答“换 schema 口径后，direct/context 的修复 CAC 方向是否稳定”，不产生赢家。

| cell | view | DeepSeek | MiMo | Δ | 95% CI (pp) | CI 排除 0 |
| --- | --- | ---: | ---: | ---: | --- | --- |
| direct/independent | official text | 65.6% | 70.3% | −4.7 | [−17.9, +6.5] | no |
| direct/independent | code-only text | 75.0% | 70.3% | +4.7 | [−6.5, +18.4] | no |
| direct/independent | official code | 57.8% | 63.3% | −5.5 | [−17.3, +3.4] | no |
| direct/independent | code-only code | 65.6% | 63.3% | +2.3 | [−5.0, +14.0] | no |
| direct/pairs | official text | 68.9% | 77.8% | −8.9 | [−16.7, −1.1] | yes |
| direct/pairs | code-only text | 81.7% | 77.8% | +3.9 | [−3.3, +10.6] | no |
| direct/pairs | official code | 64.4% | 73.9% | −9.4 | [−17.2, −1.7] | yes |
| direct/pairs | code-only code | 77.2% | 73.9% | +3.3 | [−3.9, +10.6] | no |
| context/independent | official text | 66.4% | 75.8% | −9.4 | [−28.8, −2.1] | yes |
| context/independent | code-only text | 78.9% | 75.8% | +3.1 | [−7.3, +10.5] | no |
| context/independent | official code | 61.7% | 71.1% | −9.4 | [−28.8, −2.0] | yes |
| context/independent | code-only code | 71.9% | 71.1% | +0.8 | [−7.7, +5.1] | no |
| context/pairs | official text | 71.1% | 79.4% | −8.3 | [−15.6, −0.6] | yes |
| context/pairs | code-only text | 83.3% | 79.4% | +3.9 | [−2.2, +10.6] | no |
| context/pairs | official code | 65.6% | 75.6% | −10.0 | [−17.8, −2.2] | yes |
| context/pairs | code-only code | 77.2% | 75.6% | +1.7 | [−4.4, +7.8] | no |
| few-shot/independent | official/code code | 46.9% | 33.6% | +13.3 | [+6.6, +25.0] | yes |
| few-shot/pairs | official/code code | 58.3% | 43.9% | +14.4 | [+6.7, +22.2] | yes |

读法：

- **official**：direct/context 四个格子的点估计都是 MiMo 更高；direct pairs、context independent、context pairs 的 CI 排除 0，direct independent 不排除。
- **code-only**：四个格子的点估计全部翻成 DeepSeek 更高，但所有 CI 都跨 0。翻转幅度只有 0.8–3.3 pp（严格口径），不是稳定优势。
- **few-shot**：两边都没有 schema 失败；DeepSeek CAC 高 12.5–14.4 pp，CI 排除 0。这是唯一稳健的“内容/行为”差异，但 CAC 只说明“改得更多”，不说明“修得对”；MiMo few-shot 的 no-change 率 50.2% 也提示它更常原样返回。
- **结论**：official 排名是 schema 口径的产物，但 salvage 后的差异很小且不确定；**不能说 DeepSeek 修复更好**，也不能说 MiMo 更好。没有总体赢家。

---

## 4. 与旧报告的关系（以及需要修正的地方）

本节只读引用 `analysis/model_comparison.md` 和 `research/latest_llm_methods_2026.md`；没有修改它们。

| 旧表述 | 本次精确复算 | 说明 |
| --- | --- | --- |
| “91 条结构完整、71 条有实质改动” | 91 canonical complete、93 K&R-aware complete；71 collapse-substantive、69 comment-insensitive substantive | 71 是 collapse-substantive，不是 usable |
| “71 条 usable patch / strict schema 丢掉了 71 条可用补丁” | canonical complete ∩ collapse-substantive = 69；K&R-aware complete ∩ collapse-substantive = 71；canonical complete ∩ comment-insensitive substantive = **67**；K&R-aware = **69** | “71”是最宽松的 K&R-aware + collapse 口径，包含 2 条 comment-only；保守 usable 是 67，K&R-aware 是 69 |
| “code-only CAC 75.0/81.7/78.9/83.3%” | 这是 complete + **text-changed**（73 条 salvage）；严格 comment-insensitive usable 是 **65.6/77.2/71.9/77.2%**（67 条 salvage） | 换定义后 code-only CAC 下降约 4–9 pp；方向仍翻，但幅度更小 |
| “code-only 后 direct/context 的 CAC 方向反转” | 严格口径下仍然点估计反转（DeepSeek 高 0.8–3.3 pp），但四个 CI 全部跨 0 | 点估计反转不等于稳健优势；不能据此宣称 DeepSeek 修复更好 |
| “invalid 成本主要来自缺 explanation” | 按**记录数**是（93/102 = 91.18%）；按**configured peak 成本**不是（47.44%）；9 条截断占 52.56% | 两种口径要分开写；off-peak 下比例相同（DeepSeek 全部 0.5×） |
| “DeepSeek invalid 成本 11.5%、93 条占 91.2%” | 11.50%（configured peak）、91.18% | 与旧报告一致；off-peak 下 DeepSeek 总量与 invalid 同比减半，占比不变 |
| “MiMo 61 条 drift、56 条 false” | 61 条 drift、56 条 false；但 label 一致只有 28/61 | 56 false 不等于 56 个正确负例；33 条与 gold 不一致 |

**最重要的修正**：旧报告的 code-only 反事实用的是 `complete + changed`（text），会把 whitespace-only 和 comment-only 也算成改动；本目录主口径改为 `complete + comment-insensitive substantive`。在这个更严的口径下，salvage 的 usable 数从 73（text）降到 69（collapse）再降到 67（comment-insensitive canonical）；“schema 解释一切”不成立，但“salvage 后 DeepSeek 更好”也不成立。

---

## 5. 复现

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj

# 生成/覆盖本目录的 3 个结果文件
python3 analysis/schema_recovery/recover.py

# 只读校验：重新生成到内存，逐字节比较已有文件
python3 analysis/schema_recovery/recover.py --check

# 内部断言：tokenizer、K&R、Wilson、成本公式、关键计数、172 条审计行
python3 analysis/schema_recovery/recover.py --selftest
```

- 运行环境：WSL Ubuntu，Python 3.14.8；只用标准库，无第三方依赖。
- 默认 bootstrap：10,000 次，seed 42；CI 为按 project（independent）或 pair（pairs）聚类的 percentile bootstrap。
- `--bootstrap-reps 0` 可跳过 CI，但输出会不同，`--check` 会失败。
- `--project-root` 可指向另一个数据副本；validator 始终从本脚本所在仓库的 `runner/` 导入，输出会记录其 SHA-256。`--out-dir` 可改输出目录。
- 默认对 dataset hash 与 run metrics 交叉检查失败即退出；只有显式 `--allow-source-drift` / `--allow-crosscheck-drift` 才继续。

**本目录文件**：

| 文件 | 说明 |
| --- | --- |
| `recover.py` | 唯一脚本；只读 run/split/validator/cost_normalization，生成 JSON/MD/JSONL |
| `schema_recovery.json` | 机器可读：全部点估计、CI、成本、来源 hash、交叉检查 |
| `schema_recovery.md` | 人类可读结果；由脚本生成 |
| `records.jsonl` | 172 条 invalid 的逐条审计（102 DS repair + 61 MiMo detection + 9 MiMo repair truncation）；不含源码正文，只含 hash、结构/改动标志、token/成本 |
| `README.md` | 本文件 |

---

## 6. 限制（必须一起读）

- **结构检查是词法代理，不是 C/C++ parser/compiler**。两个 canonical “incomplete” 是有效 K&R 定义，已证实是假阴性；K&R-aware 检查也只是窄启发式。
- **没有编译、单元测试、sanitizer、PoC、patch 应用或人工评审**。`usable_patch` 不表示漏洞已修、行为保持或代码可编译；oracle 级别是 **L0**。
- `changed_from_input` 是文本级；本目录额外排除了 whitespace-only、comment-only、no-change，但**语义 no-op**（改了 token 但行为不变）没有 oracle 无法识别。
- 六个 run 是每个 model × strategy × task 一个观测；CI 是描述性 cluster bootstrap，不是新的预注册检验；没有赢家 claim。
- MiMo label agreement 是 post-hoc 对 dataset label 的描述，不是 accuracy；label 本身可能有噪声，detection payload 也不是补丁。
- 成本是 list-price 重算，不是账单核对；DeepSeek reported 未扣 cached token。成本有两个价格卡：`configured_peak_cache_aware` 与 `offpeak_list_normalized`。**$2.521790 只是本目录 12 个 run 的 configured peak 合计，不是全项目统一 normalized；off-peak list 是 $1.572472，才是与 `analysis/cost_normalization.md` 的 `normalized_list_usd` 可比的口径。**
- CWE 标签来自数据集、可多值/拼接/缺失；CWE 表只做探索性分层，不做 CWE 间比较。
- 只覆盖冻结 SecVulEval test split；不能外推到其他数据、模型、prompt 或 CWE。

---

## 7. 引用（沿用 `research/latest_llm_methods_2026.md` §10）

- `[A16]` Geng et al., *JSONSchemaBench: A Rigorous Benchmark of Structured Outputs for Language Models*, ICML 2025; arXiv:2501.10868.
- `[A18]` Ugare et al., *SynCode: LLM Generation with Grammar Augmentation*, TMLR 2025; arXiv:2403.01632.
- `[B14]` Chen, Qu, Wang, *The Calibration Floor: Format Repair Can Masquerade as Self-Correction at Small-to-Mid Scale*, arXiv:2608.04355; DOI `10.48550/arXiv.2608.04355`.
- `[B15]` Nguyen et al., *Constrained Decoding: Harmful or Beneficial? Revisiting Its Impact on LLM Performance*, arXiv:2610.35328; DOI `10.48550/arXiv.2610.35328`.
- `[C1]` OpenAI, *Structured Outputs*, https://platform.openai.com/docs/guides/structured-outputs.
- `[C2]` DeepSeek, *JSON Output*, https://api-docs.deepseek.com/guides/json_mode/.
- `[C7]` Meta, *Introducing AutoPatchBench*, https://engineering.fb.com/2025/04/29/ai-research/autopatchbench-benchmark-ai-powered-security-fixes/.
- `[P]` `research/latest_evaluation_repair_2026.md` §13.3（报告清单）、§13.6（oracle 模板）；`research/latest_llm_methods_2026.md` §6.2（D2 字段级 fatal/recoverable）、§6.3（102 条 invalid 再解释）。

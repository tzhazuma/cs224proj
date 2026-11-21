# DeepSeek 六 run schema 失败：零 API 复分析

**分析版本**：`schema-recovery-2026-11-14.1`  
**日期**：2026-11-14  
**范围**：`runner/runs/test_v1_*` 六个 DeepSeek run（repair 924 条）与六个 MiMo run（detection 1,560 条、repair 924 条）；冻结 `secvul-split-v1` test。  
**API / 网络调用**：**0**。脚本只读已落盘的 run、split、`runner/secvul_runner/validation.py` 和 `analysis/cost_normalization.json`，不调用模型、不访问网络；默认只写本目录（`--out-dir` 可显式改输出目录）。  
**脚本**：`analysis/schema_recovery/recover.py`；**机器可读结果**：`schema_recovery.json`；**逐条审计**：`records.jsonl`。

> **一句话**：DeepSeek 的 102 条 repair invalid 里，93 条只是缺 `explanation`；这些 payload 大多结构完整、且有实质代码改动。官方 strict schema 与 code-only salvage 是两个视图：前者 822/924，后者 915/924；usable patch 从 552/924 升到 619/924（+7.25 pp）。**salvage 不是正确率**，也不证明漏洞被修复。

## 0. 结论先行

| 指标 | 计数 / 分母 | 值 |
| --- | --- | --- |
| official repair schema valid | 822/924 (89.0%) | 89.0% |
| code-only admitted（official + missing explanation） | 915/924 (99.0%) | 99.0% |
| missing explanation | 93/924 (10.1%) | 10.1% |
| canonical complete（93 条中） | 91/93 (97.8%) | 97.8% |
| whitespace-collapsed substantive | 71/93 (76.3%) | 76.3% |
| comment-insensitive substantive | 69/93 (74.2%) | 74.2% |
| usable patch, canonical | 67/93 (72.0%) | 72.0% |
| usable patch, K&R-aware | 69/93 (74.2%) | 74.2% |
| official usable（complete + comment-insensitive change） | 552/924 (59.7%) | 59.7% |
| code-only usable（same definition, + salvage） | 619/924 (67.0%) | 67.0% |
| usable gain from salvage | 67 条 | +7.3 pp |
| DeepSeek invalid 成本 / 总成本（configured peak / off-peak list） | $0.2183 / $0.1091 | 11.5% / 11.5% |
| recoverable-to-usable 成本 / invalid 成本（configured peak / off-peak list） | $0.0833 / $0.0417 | 38.2% / 38.2% |
| MiMo detection field drift | 61/1560 (3.9%) | 3.9% |
| MiMo alias-remap recovered | 61/61 (100.0%) | 100.0% |
| MiMo post-hoc label agreement | 28/61 | 45.9% |

最后一行是**描述性**的 label 一致计数，不是 accuracy，也不是任何排行榜指标。它只说明“格式可回收”与“内容正确”是两件事。

## 1. 数据与口径

### 1.1 十二个 run

| 模型 | 策略 | 任务 | run_id | repair | detection | 总记录 | dataset hash |
| --- | --- | --- | --- | --- | --- | --- | --- |
| deepseek | direct | independent | `test_v1_direct_independent` | 128 | 160 | 288 | yes |
| deepseek | direct | pairs | `test_v1_direct_pairs` | 180 | 360 | 540 | yes |
| deepseek | few-shot | independent | `test_v1_few-shot_independent` | 128 | 160 | 288 | yes |
| deepseek | few-shot | pairs | `test_v1_few-shot_pairs` | 180 | 360 | 540 | yes |
| deepseek | context | independent | `test_v1_context_independent` | 128 | 160 | 288 | yes |
| deepseek | context | pairs | `test_v1_context_pairs` | 180 | 360 | 540 | yes |
| mimo | direct | independent | `test_v1_mimo_direct_independent` | 128 | 160 | 288 | yes |
| mimo | direct | pairs | `test_v1_mimo_direct_pairs` | 180 | 360 | 540 | yes |
| mimo | few-shot | independent | `test_v1_mimo_few-shot_independent` | 128 | 160 | 288 | yes |
| mimo | few-shot | pairs | `test_v1_mimo_few-shot_pairs` | 180 | 360 | 540 | yes |
| mimo | context | independent | `test_v1_mimo_context_independent` | 128 | 160 | 288 | yes |
| mimo | context | pairs | `test_v1_mimo_context_pairs` | 180 | 360 | 540 | yes |

官方 run 指标与重算交叉检查：96 项，不匹配 0 项。检查覆盖 `repair.requested/schema_valid/schema_invalid/complete_and_changed`、`detection.requested/schema_invalid/valid_predictions` 和记录成本之和。

### 1.2 三个视图

| 视图 | 定义 | 它不是什么 |
| --- | --- | --- |
| official strict | `record.status == "ok"`；repair 要求恰好 `fixed_function` + `explanation`，detection 要求恰好 `is_vulnerable` + `confidence` + `rationale`。 | 不是“修复正确”；只是 schema 门槛。 |
| code-only salvage | 仅 repair：合法 JSON、非空 `fixed_function`、只缺 `explanation`。把它当作“可接收 payload”，仍保留 official 为 0 分。 | 不是 official 分数，不是模型自我修正，不是正确率。 |
| usable patch | canonical complete（或 K&R-aware complete）+ comment-insensitive 实质改动。 | 不是编译通过、测试通过、PoC 通过或漏洞已修。 |

**实质改动的阶梯**（都只做文本/词法检查，不做 AST）：

| 层级 | 定义 | 93 条中 |
| --- | --- | --- |
| text changed | `normalize_code(fixed) != normalize_code(source)`（行尾/行首空白归一后） | 75 |
| substantive (collapse) | `collapse_whitespace(fixed) != collapse_whitespace(source)`；文献中的“实质改动”口径 | 71 |
| comment-insensitive substantive | 去掉 C/C++ 注释、保留字符串字面量后，token 序列仍不同 | 69 |
| usable canonical | canonical complete ∩ comment-insensitive substantive | 67 |
| usable K&R-aware | K&R-aware complete ∩ comment-insensitive substantive | 69 |

`comment-insensitive` 这一层是故意加严的：有 2 条记录只改了注释/注释内空白，collapse-whitespace 会计为“实质”，但 token 序列不变；它们不应被算作可用补丁。这正是 format repair 伪装成 content change 的小样本例子。

## 2. 102 条 invalid 的分解

| 类别 | n | 占 repair 请求 | 占 invalid | configured peak 成本 | off-peak list 成本 | 占 invalid 成本（peak） |
| --- | --- | --- | --- | --- | --- | --- |
| `missing_explanation` | 93 | 10.1% | 91.2% | $0.1036 | $0.0518 | 47.4% |
| `truncation` | 9 | 1.0% | 8.8% | $0.1147 | $0.0574 | 52.6% |
| **total** | 102 | 11.0% | 100.0% | $0.2183 | $0.1091 | 100.0% |

### 2.1 只缺 `explanation` 的 93 条

| 检查 | n / 93 | 说明 |
| --- | --- | --- |
| 合法 JSON、可解析 | 93/93 (100.0%) | 没有语法错误；不是截断。 |
| `fixed_function` 存在且非空 | 93/93 (100.0%) | payload 在。 |
| canonical complete | 91/93 (97.8%) | 2 条 K&R 被 canonical 规则误判。 |
| K&R-aware complete | 93/93 (100.0%) | 修正 K&R 误判后的结构检查。 |
| balanced delimiters | 93/93 (100.0%) | 圆/方/花括号平衡。 |
| ends with `}` | 93/93 (100.0%) | 归一后最后一个非空字符是 `}`。 |
| no markdown fence | 93/93 (100.0%) | 没有代码围栏。 |
| not diff-like | 93/93 (100.0%) | 不是 diff/patch 文本。 |
| function-like prefix | 91/93 (97.8%) | canonical 的签名检查；K&R 例外。 |

2 条 canonical incomplete 都是 `zlib` 的 K&R 风格定义（`int ZEXPORT deflatePrime (strm, bits, value)` 后接参数声明再 `{`）。它们平衡、以 `}` 结束、无围栏/ diff；canonical 规则仅因为 `{` 前以 `;` 结束而判 false。这是结构代理的**已证实假阴性**，不是补丁损坏。

### 2.2 93 条为什么不是“都能用”

| canonical 视图 | n | 说明 |
| --- | --- | --- |
| usable（canonical） | 67 | 结构完整 + comment-insensitive 实质改动。 |
| no change | 18 | 与输入在归一文本上完全相同；即使 schema 修好也是空补丁。 |
| whitespace only | 4 | 只改空白/换行，token 不变。 |
| comment only | 2 | 只改注释或注释内空白，token 不变。 |
| K&R false negative | 2 | canonical 误判，但 K&R-aware 下可用。 |
| **total** | 93 | 67 + 18 + 4 + 2 + 2 = 93。 |

注意最后一行：canonical usable 67，K&R-aware usable 69。文献笔记里的“71 条有实质改动”是 collapse-whitespace 口径，包含 2 条 comment-only；它不是“71 条可用补丁”。严格 usable 是 67（canonical）或 69（K&R-aware）。

### 2.3 按策略与 run

| 策略 | repair 请求 | missing | complete canonical | substantive | usable canonical | usable K&R | no change | missing 成本 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| direct | 308 | 45 | 44 | 35 | 33 | 34 | 9 | $0.0478 |
| few-shot | 308 | 0 | 0 | 0 | 0 | 0 | 0 | $0.0000 |
| context | 308 | 48 | 47 | 36 | 34 | 35 | 9 | $0.0558 |
| **total** | 924 | 93 | 91 | 71 | 67 | 69 | 18 | $0.1036 |

| run | repair | missing | complete | substantive | usable canonical | usable K&R | no change | missing 成本 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | 128 | 18 | 17 | 12 | 10 | 11 | 5 | $0.0187 |
| `test_v1_direct_pairs` | 180 | 27 | 27 | 23 | 23 | 23 | 4 | $0.0292 |
| `test_v1_few-shot_independent` | 128 | 0 | 0 | 0 | 0 | 0 | 0 | $0.0000 |
| `test_v1_few-shot_pairs` | 180 | 0 | 0 | 0 | 0 | 0 | 0 | $0.0000 |
| `test_v1_context_independent` | 128 | 19 | 18 | 15 | 13 | 14 | 2 | $0.0219 |
| `test_v1_context_pairs` | 180 | 29 | 29 | 21 | 21 | 21 | 7 | $0.0338 |

### 2.4 9 条截断是 fatal，不是可 salvage

9 条截断全部 `finish_reason=length`，来自 3 个超长样本 × 3 个策略：`idx:7018, pair:8675:8676:vulnerable, pair:9912:9913:vulnerable`。content 长度 21876–27473 字符，JSON 在字符串中间被切断。这里**不尝试补引号/补括号**：任何闭合都是分析者伪造的，不是模型输出；故 0/9 进入 usable。截断成本 $0.1147，占 DeepSeek invalid 成本 52.6%。

## 3. 官方 strict vs code-only

| 策略 | 请求 | official valid | code-only admitted | official usable | salvage usable | code-only usable | Δ usable |
| --- | --- | --- | --- | --- | --- | --- | --- |
| direct | 308 | 260 | 305 | 190 | 33 | 223 | +10.7 pp |
| few-shot | 308 | 305 | 305 | 165 | 0 | 165 | +0.0 pp |
| context | 308 | 257 | 305 | 197 | 34 | 231 | +11.0 pp |
| **total** | 924 | 822 | 915 | 552 | 67 | 619 | +7.3 pp |

`official usable` / `code-only usable` 的主定义是 **canonical complete + comment-insensitive substantive change**。salvage usable 只来自 93 条 missing-explanation；9 条截断不进入任何 salvage 列。

### 3.1 换一个改动定义，结论怎么变

| 改动定义 | official | code-only | Δ |
| --- | --- | --- | --- |
| text changed（prior code-only 口径） | 610/924 (66.0%) | 683/924 (73.9%) | +7.9 pp |
| substantive（collapse whitespace） | 555/924 (60.1%) | 624/924 (67.5%) | +7.5 pp |
| comment-insensitive substantive（主口径） | 552/924 (59.7%) | 619/924 (67.0%) | +7.3 pp |
| comment-insensitive + K&R-aware complete | 556/924 (60.2%) | 625/924 (67.6%) | +7.5 pp |

schema 门槛本身只解释约 **7.3–7.9 pp** 的 usable 变化；从 915/924 的 code-only admission 到 619/924 的 usable，仍有约 **32 pp** 落在 no-change / whitespace-only / comment-only / 结构或内容不满足上。**schema 不是修复质量的主矛盾。**

### 3.2 官方 schema 有效的 822 条里，也有大量空补丁

| 指标 | n / 822 | 率 |
| --- | --- | --- |
| usable（canonical） | 552/822 (67.2%) | 67.2% |
| usable（K&R-aware） | 556/822 (67.6%) | 67.6% |
| no change | 208/822 (25.3%) | 25.3% |
| whitespace only | 55/822 (6.7%) | 6.7% |
| comment only | 3/822 (0.4%) | 0.4% |
| K&R false negative | 4 | canonical 误判但 K&R 下可用 |

no-change 率按策略：DeepSeek direct 19.6%、few-shot 37.4%、context 16.7%；MiMo direct 23.3%、few-shot 50.2%、context 20.3%。few-shot 提高了 schema 合规，但也显著提高了“原样返回”的比例。**schema valid ≠ usable patch。**

## 4. 成本

> **口径警告**：本目录有两个 cache-aware 成本视图。`configured_peak_cache_aware` 用每个 run 的配置卡（DeepSeek 0.30/1.20/0.006；MiMo 0.14/0.28/0.0028）；`offpeak_list_normalized` 用全项目非高峰卡（DeepSeek 0.15/0.60/0.003；MiMo 同价）。前者是本目录 configured peak 合计；后者才与 `analysis/cost_normalization.md` 的 `normalized_list_usd` 可比。**$2.521790 是 configured peak 合计，不是全项目统一 normalized；同一 12 个 run 的 off-peak list 合计是 $1.572472。**

| 口径 | DeepSeek | MiMo | 与项目报告的关系 |
| --- | --- | --- | --- |
| reported（原始记录） | response.cost.cost_usd；DeepSeek legacy 不扣 cache | response.cost.cost_usd；MiMo 正确带 cached token | 账单原始值，不能直接跨模型比较 |
| configured_peak_cache_aware | 0.30 / 1.20 / 0.006 | 0.14 / 0.28 / 0.0028 | 本目录主表；DeepSeek 是观测到的峰价卡 |
| offpeak_list_normalized | 0.15 / 0.60 / 0.003 | 0.14 / 0.28 / 0.0028 | 与 analysis/cost_normalization.md 的 normalized_list_usd 同口径 |

| bucket | records | configured peak $ | off-peak list $ | 占 DS 总成本（peak） | 占 DS repair（peak） | 占 invalid（peak） |
| --- | --- | --- | --- | --- | --- | --- |
| DeepSeek all | 2484 | $1.8986 | $0.9493 | 100.0% | — | — |
| DeepSeek repair | 924 | $1.3233 | $0.6616 | 69.7% | 100.0% | — |
| DeepSeek invalid | 102 | $0.2183 | $0.1091 | 11.5% | 16.5% | 100.0% |
|   missing explanation | 93 | $0.1036 | $0.0518 | 5.5% | 7.8% | 47.4% |
|   truncation | 9 | $0.1147 | $0.0574 | 6.0% | 8.7% | 52.6% |
|   usable salvage（canonical） | 67 | $0.0833 | $0.0417 | 4.4% | 6.3% | 38.2% |
|   missing but non-usable | 26 | $0.0202 | $0.0101 | 1.1% | 1.5% | 9.3% |

DeepSeek 的 off-peak list 成本是 configured peak 的精确 0.5×，所以上表的占比列在两种口径下相同；**不要把 DeepSeek 的 0.5× 关系套到 MiMo**（MiMo 没有峰谷价，两口径相同）。

**计数与成本的主矛盾不同**：missing explanation 占 invalid 条数的 91.2%，却只占 invalid 成本的 47.4%；9 条截断占条数的 8.8%，却占 invalid 成本的 52.6%（单条约 $0.01275，是 missing 单条的 11 倍）。把“invalid 成本主要是缺 explanation”当成结论，只在按记录数计时成立。

### 4.1  salvage 的成本结构

| 项 | configured peak $ | off-peak list $ | 占 invalid 成本（peak） |
| --- | --- | --- | --- |
| invalid total | $0.2183 | $0.1091 | 100.0% |
| recoverable → usable（canonical） | $0.0833 | $0.0417 | 38.2% |
| recoverable → usable（K&R-aware） | $0.0842 | $0.0421 | 38.6% |
| missing but non-usable（canonical） | $0.0202 | $0.0101 | 9.3% |
| fatal truncation | $0.1147 | $0.0574 | 52.6% |

salvage 的**边际 API 成本是 $0**：这些响应已经生成并付费；复分析只是重新分类已发生的沉没成本。这不等于“免费获得正确补丁”——67 条 usable 仍要经过编译/测试/PoC 才能谈修复。

### 4.2 每单位结构性可用输出的成本

| 口径 | configured peak $/unit | off-peak list $/unit | 分母 |
| --- | --- | --- | --- |
| official usable（canonical） | $0.002397 | $0.001199 | 552 |
| code-only usable（canonical） | $0.002138 | $0.001069 | 619 |
| code-only usable（K&R-aware） | $0.002117 | $0.001059 | 625 |
| salvage usable（canonical） | $0.001244 | $0.000622 | 67 |
| salvage usable（K&R-aware） | $0.001220 | $0.000610 | 69 |
| truncation / record | $0.012746 | $0.006373 | 9 |
| MiMo drift / recovered | $0.000163 | $0.000163 | 61 |

这是“结构性可用输出”的平均会计成本，不是“每个正确修复”的成本；分母不是正确数。

### 4.3 MiMo 与合计

| bucket | records | configured peak $ | off-peak list $ | 说明 |
| --- | --- | --- | --- | --- |
| MiMo all | 2484 | $0.6232 | $0.6232 | 六个 run 全部记录 |
| MiMo detection | 1560 | $0.2501 | $0.2501 | 1,560 条 detection |
| MiMo repair | 924 | $0.3730 | $0.3730 | 924 条 repair |
|   field drift | 61 | $0.0099 | $0.0099 | 占 detection 成本 4.0% |
|   repair truncation | 9 | $0.0321 | $0.0321 | 占 MiMo invalid 成本 76.4% |

两模型合计 invalid 成本：configured peak **$0.2603**，占 configured peak 总成本 10.3%（$2.5218）；off-peak list **$0.1512**，占 off-peak 总成本 9.6%（$1.5725）。

> **$2.521790 的准确定义**：它是本目录 12 个 run 的 **configured peak cache-aware** 合计，不是全项目统一 normalized。全项目 off-peak list 口径下，同一 12 个 run 是 **$1.572472**；该值与 `analysis/cost_normalization.md` 的 `legacy_test.normalized_list_usd` 一致。两个数不能混用或相加到其他实验的 off-peak 总量上。

**reported vs 两种 cache-aware 口径**：

| bucket | reported | configured peak | off-peak list | Δ vs peak | Δ vs off-peak |
| --- | --- | --- | --- | --- | --- |
| DS missing explanation | $0.1036 | $0.1036 | $0.0518 | $0.0000 | $0.0518 |
| DS truncation | $0.1173 | $0.1147 | $0.0574 | $0.0026 | $0.0600 |
| MiMo field drift | $0.0099 | $0.0099 | $0.0099 | $0.0000 | $0.0000 |

DeepSeek 的 `response.cost` 没有扣 cached token；两种 cache-aware 视图都用 usage 的 cached_tokens 重算，区别只在价格卡。跨模型比较统一用 off-peak list 口径时，才能与 `analysis/cost_normalization.md` 对齐；official 账单仍以 reported 为准。

**与 `analysis/cost_normalization.md` 的交叉核对**（同一 12 个 test_v1 run，4,968 条记录）：

| 口径 | 本目录重算 | 参考值 | Δ | 匹配 |
| --- | --- | --- | --- | --- |
| configured peak cache-aware | $2.5218 | $2.5218 | $0.0000 | yes |
| off-peak list normalized | $1.5725 | $1.5725 | $0.0000 | yes |

参考文件：`analysis/cost_normalization.json`（SHA-256 `8a3ec0b75cab2e98…`）。参考值的字段名是 `configured_cache_aware_usd` 与 `normalized_list_usd`；本目录把后者明确标成 off-peak list normalized，避免与 configured peak 混用。

## 5. MiMo 字段漂移对照

| 维度 | DeepSeek repair: missing explanation | MiMo detection: field drift |
| --- | --- | --- |
| failure count | 93 | 61 |
| denominator | 924 | 1560 |
| failure rate | 10.1% | 3.9% |
| direct / few-shot / context | 45 / 0 / 48 | 39 / 0 / 22 |
| independent / pairs | 37 / 56 | 17 / 44 |
| JSON parse | 93 | 61 |
| payload recoverable | 93 | 61 |
| structure / usable | complete 91/93 canonical, 93/93 K&R; usable 67 canonical, 69 K&R | payload valid 61; label agreement 28 |
| downstream check | none; compile/test/PoC not run | descriptive label agreement only; not accuracy |
| failure-class cost (configured peak) | $0.1036 | $0.0099 |
| failure-class cost (off-peak list) | $0.0518 | $0.0099 |
| lenient-admitted cost (configured peak) | $0.0833 | $0.0099 |
| lenient-admitted cost (off-peak list) | $0.0417 | $0.0099 |
| share of invalid cost (configured peak) | 47.4% | 23.6% |
| share of invalid cost (off-peak list) | 47.4% | 23.6% |

`lenient-admitted cost` 两列的口径不同：DeepSeek 是 67 条 usable salvage，MiMo 是 61 条 alias-recovered drift；看量级请用 `failure-class cost` 行（93 条 missing 的成本 vs 61 条 drift 的成本）。表中同时给出 configured peak 与 off-peak list 两个价格卡；DeepSeek 的 off-peak 是 peak 的 0.5×，MiMo 两者相同。**不要把 93 条 missing 的 configured peak 成本与 MiMo 的 off-peak 成本当成同一口径比较。**

**漂移键**：

| 键模式 | n |
| --- | --- |
| `confidence + is_vulnerability + rationale` | 59 |
| `confidence + is_vulnerability + is_vulnerable + rationale` | 1 |
| `confidence + is_vulnerative + rationale` | 1 |

61 条中 59 条只写 `is_vulnerability`，1 条写 `is_vulnerative`，1 条同时写 `is_vulnerable` 和 `is_vulnerability`。61/61 可 alias-remap，61/61 的 `confidence`/`rationale` 也通过类型检查；但 recovered value 是 5 true / 56 false，gold 是 36 true / 25 false，post-hoc label 一致只有 28/61。

这组数字的用途是**反例**：format recovery 可以 100%，但恢复出来的检测大多仍是 false；把它叫“正确率提升”会掩盖 33/61 的不一致。MiMo 的 61 条也不是随机失败：direct 39、context 22、few-shot 0；DeepSeek 的 93 条同样是 direct 45、context 48、few-shot 0。两边的格式失败都在 few-shot 消失。

但两边的下游可验证性不同：MiMo 的 payload 里有可直接对 label 的布尔值；DeepSeek 的 payload 是代码，没有编译/测试/PoC 就只能停在结构代理。因此 **不能**把 28/61 与 67/93 放在同一把尺子上。

## 6. 模型比较敏感性（post-hoc）

这张表只回答“换 schema 口径后，direct/context 的修复 CAC 方向是否稳定”，不是新的主终点，也不产生赢家。CAC（complete + change）仍是结构代理，不是正确率；`official` 只算 schema-valid，`code-only` 额外接收 missing-explanation。

| cell | view | DeepSeek | MiMo | Δ | 95% CI (pp) | CI 排除 0 |
| --- | --- | --- | --- | --- | --- | --- |
| direct/independent | official_text | 65.6% | 70.3% | -4.7 pp | [-17.9, +6.5] | no |
| direct/independent | code_text | 75.0% | 70.3% | +4.7 pp | [-6.5, +18.4] | no |
| direct/independent | official_code | 57.8% | 63.3% | -5.5 pp | [-17.3, +3.4] | no |
| direct/independent | code_code | 65.6% | 63.3% | +2.3 pp | [-5.0, +14.0] | no |
| direct/pairs | official_text | 68.9% | 77.8% | -8.9 pp | [-16.7, -1.1] | yes |
| direct/pairs | code_text | 81.7% | 77.8% | +3.9 pp | [-3.3, +10.6] | no |
| direct/pairs | official_code | 64.4% | 73.9% | -9.4 pp | [-17.2, -1.7] | yes |
| direct/pairs | code_code | 77.2% | 73.9% | +3.3 pp | [-3.9, +10.6] | no |
| few-shot/independent | official_text | 57.0% | 44.5% | +12.5 pp | [+5.6, +26.3] | yes |
| few-shot/independent | code_text | 57.0% | 44.5% | +12.5 pp | [+5.6, +26.2] | yes |
| few-shot/independent | official_code | 46.9% | 33.6% | +13.3 pp | [+6.6, +25.0] | yes |
| few-shot/independent | code_code | 46.9% | 33.6% | +13.3 pp | [+6.6, +24.6] | yes |
| few-shot/pairs | official_text | 64.4% | 51.1% | +13.3 pp | [+6.1, +20.6] | yes |
| few-shot/pairs | code_text | 64.4% | 51.1% | +13.3 pp | [+6.1, +20.6] | yes |
| few-shot/pairs | official_code | 58.3% | 43.9% | +14.4 pp | [+6.7, +22.2] | yes |
| few-shot/pairs | code_code | 58.3% | 43.9% | +14.4 pp | [+7.2, +22.2] | yes |
| context/independent | official_text | 66.4% | 75.8% | -9.4 pp | [-28.8, -2.1] | yes |
| context/independent | code_text | 78.9% | 75.8% | +3.1 pp | [-7.3, +10.5] | no |
| context/independent | official_code | 61.7% | 71.1% | -9.4 pp | [-28.8, -2.0] | yes |
| context/independent | code_code | 71.9% | 71.1% | +0.8 pp | [-7.7, +5.1] | no |
| context/pairs | official_text | 71.1% | 79.4% | -8.3 pp | [-15.6, -0.6] | yes |
| context/pairs | code_text | 83.3% | 79.4% | +3.9 pp | [-2.2, +10.6] | no |
| context/pairs | official_code | 65.6% | 75.6% | -10.0 pp | [-17.8, -2.2] | yes |
| context/pairs | code_code | 77.2% | 75.6% | +1.7 pp | [-4.4, +7.8] | no |

- **official text**：direct/context 四个格子的点估计都是 MiMo 更高；direct pairs、context independent、context pairs 的 CI 排除 0，direct independent 不排除。
- **code-only text**：四个格子的点估计全部翻成 DeepSeek 更高，但所有 CI 都跨 0。
- **official code**（更严的实质改动）：MiMo 在四个格子仍更高，3/4 的 CI 排除 0。
- **code-only code**：DeepSeek 在四个格子略高或持平，但所有 CI 都跨 0。
- **few-shot**：两边都没有 schema 失败；DeepSeek CAC 高 12.5–14.4 pp，CI 排除 0。这是唯一稳健的“内容/行为”差异，但 CAC 只说明“改得更多”，不说明“修得对”。

结论：**official 排名是 schema 口径的产物，但 salvage 后的差异很小且不确定；不能说 DeepSeek 修复更好。** direct/context 的 MiMo 优势在 code-only 下翻成 DeepSeek 的微弱优势；这个翻转本身依赖改动定义和 CI，不能当成稳定结论。

### 6.1 no-change 率（official valid 内）

| 模型 | 策略 | official valid | no change | no-change 率 | whitespace only |
| --- | --- | --- | --- | --- | --- |
| deepseek | direct | 260 | 51 | 19.6% | 17 |
| deepseek | few-shot | 305 | 114 | 37.4% | 23 |
| deepseek | context | 257 | 43 | 16.7% | 15 |
| mimo | direct | 305 | 71 | 23.3% | 13 |
| mimo | few-shot | 305 | 153 | 50.2% | 26 |
| mimo | context | 305 | 62 | 20.3% | 11 |

few-shot 的 no-change 率最高（DeepSeek 37.4%，MiMo 50.2%）。这解释了为什么 few-shot 的 CAC 差异不能直接读成“修复能力”：更少 schema 错误，但更多原样返回。

## 7. CWE 分层（探索性）

| primary CWE | n | 占 93 | complete | substantive | usable canonical | usable K&R | no change | 成本 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CWE-125` | 18 | 19.4% | 18 | 17 | 17 | 17 | 1 | $0.0295 |
| `CWE-787` | 14 | 15.1% | 12 | 14 | 12 | 14 | 0 | $0.0123 |
| `CWE-119` | 11 | 11.8% | 11 | 6 | 6 | 6 | 4 | $0.0096 |
| `CWE-20` | 7 | 7.5% | 7 | 5 | 5 | 5 | 2 | $0.0080 |
| `unlabeled` | 7 | 7.5% | 7 | 5 | 5 | 5 | 2 | $0.0037 |
| `CWE-264` | 5 | 5.4% | 5 | 3 | 3 | 3 | 2 | $0.0041 |
| `CWE-476` | 5 | 5.4% | 5 | 4 | 4 | 4 | 1 | $0.0046 |
| `CWE-190` | 4 | 4.3% | 4 | 2 | 2 | 2 | 2 | $0.0027 |
| `CWE-399` | 4 | 4.3% | 4 | 2 | 0 | 0 | 1 | $0.0037 |
| `CWE-120` | 3 | 3.2% | 3 | 2 | 2 | 2 | 1 | $0.0048 |

`usable 0` 不一定是计数错误：例如 CWE-399 的 4 条中 2 条是 comment-only、1 条 whitespace-only、1 条 no-change，token 层都没有改动；这正说明“结构完整”与“可用补丁”是两个门槛。

93 条覆盖 22 个 primary CWE 标签；Top 3 是 CWE-125（18）、CWE-787（14）、CWE-119（11），合计 43/93（46.2%），都是内存安全类。CWE 标签来自数据集、可多值、部分拼接或缺失（7 条 unlabeled），所以这里只做分层描述，不做 CWE 间比较。

## 8. 这不能证明什么

- 结构检查是词法代理，不是 C/C++ parser 或 compiler。两个 canonical “incomplete” 是有效的 K&R 定义；这是已证实的假阴性，不是补丁本身的属性。
- 没有编译、单元测试、sanitizer、PoC、patch 应用或人工评审。usable_patch 不表示漏洞已修、行为保持或代码可编译。
- changed_from_input 是文本级检查。本分析额外排除了 whitespace-only、comment-only 和 no-change，但语义 no-op（改了 token 但行为不变）没有 oracle 无法识别。
- 六个 run 是每个 model × strategy × task 一个观测；CI 是描述性 cluster bootstrap，不是新的预注册检验；没有赢家 claim。
- MiMo label agreement 是 post-hoc 对 dataset label 的描述，不是 accuracy；label 本身可能有噪声，detection payload 也不是补丁。
- 成本是 list-price 重算，不是账单核对；DeepSeek reported 未扣 cached token，两个口径都报但不互相替代。
- CWE 标签来自数据集、可多值/拼接/缺失；CWE 表只做探索性分层，不做 CWE 间比较。
- 成本有两个价格卡：configured peak cache-aware 与 off-peak list normalized。$2.521790 仅指本目录 12 个 run 的 configured peak 合计；off-peak list 是 $1.572472，才是与 analysis/cost_normalization.md 的 normalized_list_usd 可比的口径。
- 只覆盖冻结的 SecVulEval test split；不能外推到其他数据、模型、prompt 或 CWE。

## 9. 复现

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 analysis/schema_recovery/recover.py
python3 analysis/schema_recovery/recover.py --check
python3 analysis/schema_recovery/recover.py --selftest
```

`--check` 重新生成并逐字节比较 `schema_recovery.json`、`schema_recovery.md`、`records.jsonl`；`--selftest` 跑内部断言（tokenizer、K&R、Wilson、成本公式、关键计数）。默认 bootstrap 10,000 次、seed 42；`--bootstrap-reps 0` 可跳过 CI（此时输出会不同，`--check` 会失败）。

**输出**：

- `schema_recovery.json`：全部点估计、区间、成本、来源 hash、交叉检查。
- `schema_recovery.md`：本文件。
- `records.jsonl`：172 条 invalid 的逐条审计（102 DeepSeek repair + 61 MiMo detection + 9 MiMo repair truncation）；不含源码正文，只含 hash、标志、token/成本。

**零 API**：脚本没有 `requests`、`openai`、`httpx` 或任何网络导入；不读取 API key；所有数字来自 `results.jsonl` 的已记录 usage 与 frozen split。

**来源指纹**：`runner/secvul_runner/validation.py` = `5e0f1d8dd3146bb9…`；`analysis/cost_normalization.json` = `8a3ec0b75cab2e98…`；两个 split 的 SHA-256 与 12 个 run config 逐一匹配；run 指标交叉检查 96 项、0 不匹配。

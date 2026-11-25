# 保守三路验证器：正例二次审查（SecVulEval 160，探索性）

> **状态：探索性、事后分析（post-hoc），test-seen，不是独立确认。** 这 160 个函数
> 已经用于评估第一遍 evidence 提示和 `evidence_verify` 的原始验证器；本实验的
> 三路提示与判定规则是在看到那些结果之后设计的。任何数字都不能当作“在新测试集上
> 确认了检测能力”。本目录不修改 `evidence_verify/`、`evidence_prompt/`、`splits/`
> 或 `runner/runs/` 中的任何旧产物。

## 0. 一句话结论

在 236 条真实验证请求中，保守规则只撤销了 **4 条**（TP 3 / FP 1）。它确实消除了原验证器“把 insufficient 也当撤销” 的大规模误撤销，但代价是几乎不再纠正假阳性：撤销精确率没有显著高于正例中的 FP 基准率；macro-F1 在四个臂上都不升（0 到 -0.0052），MCC 只在 `mimo_cross` 上升 +0.0139（95% CI 跨 0），而这条臂同时损失 2 个 TP、只纠正 1 个 FP。原验证器主口径在同一批正例上撤销了 155 条；两者相差约 39 倍。

因此，这个“改进”在**判定有效性**上是正确的（不再把‘无法证明’当成‘已被反驳’），
但在**检测收益**上是负结果：严格到只接受具体守卫/反例时，模型很少给出可用输出，
验证器退化为惰性步骤。

## 1. 改了什么

原 `evidence_verify` 的两处结构性问题：

1. 提示要求“Retraction is the conservative action”，且主口径 **fail-closed**：
   验证器没有给出有效 sustain 时就撤销。于是 `insufficient_evidence`（“函数体内看不出
   可达性/攻击者控制”）也被当成撤销理由。
2. 事后 `refutation_only` 规则虽然保留 `insufficient_evidence`，但它仍把
   `no_reachable_flow` / `evidence_mislocated` / `not_security_relevant` 当作撤销；
   这些类型并不一定给出函数内的具体守卫或反例。

本目录的改法：

| 维度 | 原验证器 | 保守三路验证器 |
| --- | --- | --- |
| 输出 | `sustain` / `retract` + 5 类 rebuttal | `supported` / `unsupported` / `insufficient` |
| 撤销条件 | 任意 `retract`；主口径连 invalid 也撤销 | 仅 `unsupported` + 具体 `guard_present` 或 `counterexample` |
| 证据不足 | 可撤销（`insufficient_evidence`） | 保留第一遍预测 |
| 验证器失败 | fail-closed 撤销 | 保留第一遍预测（fail-open） |
| 行号校验 | 范围 + 非空 | 范围 + 非空 + 至少一行非注释/非括号代码；guard 还需守卫词法匹配 |
| 多场景 claim | 未要求 | 守卫必须覆盖 claim 描述的每一条路径，否则必须选 insufficient |

判定表（机械执行，不由模型自行决定是否撤销）：

| assessment | rebuttal_kind | 行号有效性 | 动作 |
| --- | --- | --- | --- |
| supported | none | — | 保留 |
| insufficient | none | — | 保留 |
| unsupported | guard_present | 至少一行有效代码且含守卫词法 | 撤销 |
| unsupported | guard_present | 空白/注释/括号/无守卫词法 | 保留（ungrounded） |
| unsupported | counterexample | 至少一行有效代码 + 具体反例文本 | 撤销 |
| unsupported | counterexample | 缺反例文本或行号无效 | 保留 |
| invalid / error | — | — | 保留（不采用 fail-closed） |

“行号有效”是可机械检查的部分：行号在 `1..N`、不重复、至少一行既非空白也非纯注释/
纯括号；`guard_present` 还要求该行含 `if/return/&&/比较/边界函数` 等守卫词法。
**语义上的支配关系（守卫是否真的覆盖所有路径、反例是否真的不触发）没有被编译或
执行验证**，仍由模型断言。第 8.1 节给出两个反例。

## 2. 真实运行

四个臂，每个臂只对第一遍的 schema-valid 正例发一次请求；负例与第一遍 invalid 记录
原样保留。所有调用均为真实 API 调用，temperature=0，单次运行。

| 臂 | 第一遍正例来源 | 验证器 | 请求 | ok | invalid | error | 撤销 | 验证器 USD | p50 / p95 延迟 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `deepseek_self` | deepseek | deepseek | 60 | 60 | 0 | 0 | 1 | 0.049598 | 2.67 s / 4.21 s |
| `deepseek_cross` | deepseek | mimo | 60 | 60 | 0 | 0 | 0 | 0.028040 | 6.74 s / 16.53 s |
| `mimo_self` | mimo | mimo | 58 | 56 | 2 | 0 | 0 | 0.027066 | 6.06 s / 16.37 s |
| `mimo_cross` | mimo | deepseek | 58 | 57 | 0 | 1 | 3 | 0.047054 | 3.30 s / 4.88 s |

合计 **236** 条请求，invalid 2、API error 1，
验证器总成本 **0.151758 USD**（按第一遍 run 的价格快照估算，未重新
核对官方页面）。`deepseek_self` / `deepseek_cross` 使用 DeepSeek 第一遍的 60 个正例，
`mimo_self` / `mimo_cross` 使用 MiMo 第一遍的 58 个正例。cross 臂是主分析臂（验证器
与被审模型不同）；self 臂是同模型新上下文，只作补充。

输入隔离：验证器只看到带行号函数源码 + 第一遍 `evidence_lines` / `mechanism`；
没有标签、项目、文件路径、commit、`changed_lines`、第一遍 confidence 或修复建议。
四份 dry-run 请求体与真实请求体逐条哈希一致，隔离审计 0 违规；manifest 记录
`api_key_value_stored=false`、`authorization_header_stored=false`。

## 3. 主结果（逐臂）

`pre` 为第一遍；`original` 为原验证器主口径 fail-closed；`original refutation-only`
为原目录的事后规则；`original guard-only replay` 是把原记录按本实验的严格规则重放
（只接受 grounded `guard_present`，invalid 保留）；`conservative` 是本实验的真实运行。
所有 post 行只改正例，负例与第一遍 invalid 不变；P/R/F1 为 valid-only，strict 正确数见 §6.1。
k 括号内为 schema-valid 的撤销数；TP 损失/FP 纠正为端到端（含 fail-closed 强制撤销
的 invalid）；撤销精确率按 schema-valid 撤销计算，与原目录口径一致。

### `deepseek_self`（deepseek 正例 → deepseek 验证器）

| 策略 | 撤销 k（有效） | TP 损失 | TP 损失率 | FP 纠正 | FP 纠正率 | 撤销精确率 | macro-F1 | Δmacro-F1 | MCC | ΔMCC | TP/FP/TN/FN | 流水线 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| first pass (pre) | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4223 | +0.0000 | 0.0348 | +0.0000 | 49/11/21/78 | 0.085622 |
| original verifier (fail-closed) | 54 | 43 | 87.8% | 11 | 100.0% | 20.4% | 0.2181 | -0.2043 | 0.0994 | +0.0646 | 6/0/32/121 | 0.150202 |
| original verifier (refutation-only, post hoc) | 18 | 14 | 28.6% | 4 | 36.4% | 22.2% | 0.3749 | -0.0475 | 0.0517 | +0.0169 | 35/7/25/92 | 0.150202 |
| original records, strict guard-only replay | 11 | 8 | 16.3% | 3 | 27.3% | 27.3% | 0.4020 | -0.0204 | 0.0632 | +0.0284 | 41/8/24/86 | 0.150202 |
| conservative three-way verifier | 1 | 1 | 2.0% | 0 | 0.0% | 0.0% | 0.4172 | -0.0052 | 0.0284 | -0.0064 | 48/11/21/79 | 0.135220 |

### `deepseek_cross`（deepseek 正例 → mimo 验证器）

| 策略 | 撤销 k（有效） | TP 损失 | TP 损失率 | FP 纠正 | FP 纠正率 | 撤销精确率 | macro-F1 | Δmacro-F1 | MCC | ΔMCC | TP/FP/TN/FN | 流水线 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| first pass (pre) | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4223 | +0.0000 | 0.0348 | +0.0000 | 49/11/21/78 | 0.085622 |
| original verifier (fail-closed) | 28 (26) | 21 | 42.9% | 7 | 63.6% | 23.1% | 0.3522 | -0.0701 | 0.0955 | +0.0607 | 28/4/28/99 | 0.108314 |
| original verifier (refutation-only, post hoc) | 10 (8) | 7 | 14.3% | 3 | 27.3% | 25.0% | 0.4075 | -0.0148 | 0.0697 | +0.0349 | 42/8/24/85 | 0.108314 |
| original records, strict guard-only replay | 5 | 3 | 6.1% | 2 | 18.2% | 40.0% | 0.4219 | -0.0005 | 0.0682 | +0.0334 | 46/9/23/81 | 0.108314 |
| conservative three-way verifier | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4223 | +0.0000 | 0.0348 | +0.0000 | 49/11/21/78 | 0.113662 |

### `mimo_self`（mimo 正例 → mimo 验证器）

| 策略 | 撤销 k（有效） | TP 损失 | TP 损失率 | FP 纠正 | FP 纠正率 | 撤销精确率 | macro-F1 | Δmacro-F1 | MCC | ΔMCC | TP/FP/TN/FN | 流水线 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| first pass (pre) | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4067 | +0.0000 | 0.0126 | +0.0000 | 47/11/20/80 | 0.035933 |
| original verifier (fail-closed) | 22 (21) | 19 | 40.4% | 3 | 27.3% | 14.3% | 0.3221 | -0.0846 | -0.0356 | -0.0481 | 28/8/23/99 | 0.051033 |
| original verifier (refutation-only, post hoc) | 7 (6) | 7 | 14.9% | 0 | 0.0% | 0.0% | 0.3696 | -0.0371 | -0.0339 | -0.0464 | 40/11/20/87 | 0.051033 |
| original records, strict guard-only replay | 3 | 3 | 6.4% | 0 | 0.0% | 0.0% | 0.3910 | -0.0157 | -0.0070 | -0.0195 | 44/11/20/83 | 0.051033 |
| conservative three-way verifier | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4067 | +0.0000 | 0.0126 | +0.0000 | 47/11/20/80 | 0.062999 |

### `mimo_cross`（mimo 正例 → deepseek 验证器）

| 策略 | 撤销 k（有效） | TP 损失 | TP 损失率 | FP 纠正 | FP 纠正率 | 撤销精确率 | macro-F1 | Δmacro-F1 | MCC | ΔMCC | TP/FP/TN/FN | 流水线 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| first pass (pre) | 0 | 0 | 0.0% | 0 | 0.0% | — | 0.4067 | +0.0000 | 0.0126 | +0.0000 | 47/11/20/80 | 0.035933 |
| original verifier (fail-closed) | 51 | 40 | 85.1% | 11 | 100.0% | 21.6% | 0.2226 | -0.1842 | 0.1064 | +0.0938 | 7/0/31/120 | 0.087893 |
| original verifier (refutation-only, post hoc) | 17 | 13 | 27.7% | 4 | 36.4% | 23.5% | 0.3645 | -0.0422 | 0.0380 | +0.0254 | 34/7/24/93 | 0.087893 |
| original records, strict guard-only replay | 11 | 9 | 19.1% | 2 | 18.2% | 18.2% | 0.3733 | -0.0334 | 0.0077 | -0.0048 | 38/9/22/89 | 0.087893 |
| conservative three-way verifier | 3 | 2 | 4.3% | 1 | 9.1% | 33.3% | 0.4040 | -0.0028 | 0.0265 | +0.0139 | 45/10/21/82 | 0.082987 |

### 3.1 跨臂摘要

| 臂 | pre macro-F1 | 原 post | 保守 post | Δ原 | Δ保守 | pre MCC | 原 MCC | 保守 MCC | 原 k | 保守 k |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 0.4223 | 0.2181 | 0.4172 | -0.2043 | -0.0052 | 0.0348 | 0.0994 | 0.0284 | 54 | 1 |
| `deepseek_cross` | 0.4223 | 0.3522 | 0.4223 | -0.0701 | +0.0000 | 0.0348 | 0.0955 | 0.0348 | 28 | 0 |
| `mimo_self` | 0.4067 | 0.3221 | 0.4067 | -0.0846 | +0.0000 | 0.0126 | -0.0356 | 0.0126 | 22 | 0 |
| `mimo_cross` | 0.4067 | 0.2226 | 0.4040 | -0.1842 | -0.0028 | 0.0126 | 0.1064 | 0.0265 | 51 | 3 |

原验证器在四个臂上都把操作点大幅推向保守：撤销数远大于保守规则，macro-F1
一致下降（-0.0701 到 -0.2043）。MCC 在 3/4 臂上升，但这是 FP 被大量移除的
操作点副产物：撤销并没有显著偏向 FP（第 6.2 节，超几何 p=0.21–1.00），
同时 recall 显著下降。保守规则撤销数接近零，指标几乎不动；两个臂
（`deepseek_cross`、`mimo_self`）完全不动，另外两个臂各撤销 1–3 条。

### 3.2 fail-open 敏感性

原验证器主口径在验证失败时撤销。下表把同一批原记录改为失败保留（fail-open），
用来分离“失败处理”与“模型真的给出 retract”的影响。

| 臂 | 原 fail-closed k | 原 fail-closed macro-F1 | 原 fail-open k | 原 fail-open macro-F1 | 保守 k | 保守 macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 54 | 0.2181 | 54 | 0.2181 | 1 | 0.4172 |
| `deepseek_cross` | 28 | 0.3522 | 26 | 0.3521 | 0 | 0.4223 |
| `mimo_self` | 22 | 0.3221 | 21 | 0.3281 | 0 | 0.4067 |
| `mimo_cross` | 51 | 0.2226 | 51 | 0.2226 | 3 | 0.4040 |

## 4. 与原验证器的决策差异

把“撤销/保留”作为二分类决策，在正例集合上比较原验证器主口径与本实验：

| 臂 | n | 都撤销 | 都保留 | 仅原撤销 | 仅保守撤销 | 一致率 | Cohen κ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 60 | 1 | 6 | 53 | 0 | 11.7% | 0.0038 |
| `deepseek_cross` | 60 | 0 | 32 | 28 | 0 | 53.3% | 0.0000 |
| `mimo_self` | 58 | 0 | 36 | 22 | 0 | 62.1% | 0.0000 |
| `mimo_cross` | 58 | 3 | 7 | 48 | 0 | 17.2% | 0.0149 |

原验证器的撤销类型分布（括号内为 TP/FP）：

| 臂 | 撤销总数 | guard_present | insufficient_evidence | no_reachable_flow | evidence_mislocated | not_security_relevant |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 54 | 11 (8/3) | 36 (29/7) | 3 (3/0) | 0 (0/0) | 4 (3/1) |
| `deepseek_cross` | 26 | 5 (3/2) | 18 (14/4) | 1 (1/0) | 1 (1/0) | 1 (1/0) |
| `mimo_self` | 21 | 3 (3/0) | 15 (12/3) | 1 (1/0) | 1 (1/0) | 1 (1/0) |
| `mimo_cross` | 51 | 11 (9/2) | 34 (27/7) | 2 (1/1) | 1 (0/1) | 3 (3/0) |

`insufficient_evidence` 在原目录中占撤销的多数；它按契约不允许给行号，本来就不是
“函数内存在具体守卫或反例”。保守规则把它全部保留，是撤销数骤降的主要原因。
上表只统计 schema-valid 的 retract；原主口径 fail-closed 还把 3 条 invalid 验证
记录直接撤销（DeepSeek cross 2 条、MiMo self 1 条），所以原主口径总撤销数为
155，比上表各类型合计多 3 条。

## 5. 随机 / 低置信同预算基线

每个策略的 k 固定为它自己的撤销数；随机基线从同一批正例中均匀抽 k 个（10,000 次，
seed=42），低置信基线撤销第一遍 confidence 最低的 k 个正例。两者都不调用模型，
增量成本为 0。若验证器与这些廉价规则在同预算下没有差别，就不能说它“识别出了 FP”。
原验证器行的撤销精确率按 schema-valid 撤销计算（与 §3 一致）；TP/FP 为端到端，
所以 `deepseek_cross` 的 23.1% 不等于 7/28：其中 2 条 invalid 被 fail-closed 强制撤销。

### `deepseek_self`

| 策略 | k（有效） | TP 损失 | FP 纠正 | 撤销精确率 | macro-F1 | MCC | 增量 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| conservative three-way verifier | 1 | 1 | 0 | 0.0% | 0.4172 | 0.0284 | 0.049598 |
| ↳ random (k=1) | 1 | 0.82 | 0.18 | — | 0.4196 [0.4172, 0.4301] | 0.0344 [0.0284, 0.0609] | 0 |
| ↳ 低置信 (k=1) | 1 | 1 | 0 | 0.0% | 0.4172 | 0.0284 | 0 |
| original verifier (fail-closed) | 54 | 43 | 11 | 20.4% | 0.2181 | 0.0994 | 0.064580 |
| ↳ random (k=54) | 54 | 44.10 | 9.90 | — | 0.2039 [0.1793, 0.2181] | 0.0092 [-0.1476, 0.0994] | 0 |
| ↳ 低置信 (k=54) | 54 | 44 | 10 | 18.5% | 0.2052 | 0.0171 | 0 |

### `deepseek_cross`

| 策略 | k（有效） | TP 损失 | FP 纠正 | 撤销精确率 | macro-F1 | MCC | 增量 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| conservative three-way verifier | 0 | 0 | 0 | — | 0.4223 | 0.0348 | 0.028040 |
| ↳ random (k=0) | 0 | 0.00 | 0.00 | — | 0.4223 [0.4223, 0.4223] | 0.0348 [0.0348, 0.0348] | 0 |
| ↳ 低置信 (k=0) | 0 | 0 | 0 | — | 0.4223 | 0.0348 | 0 |
| original verifier (fail-closed) | 28 (26) | 21 | 7 | 23.1% | 0.3522 | 0.0955 | 0.022693 |
| ↳ random (k=28) | 28 | 22.87 | 5.13 | — | 0.3287 [0.2893, 0.3648] | 0.0224 [-0.1001, 0.1346] | 0 |
| ↳ 低置信 (k=28) | 28 | 21 | 7 | 25.0% | 0.3522 | 0.0955 | 0 |

### `mimo_self`

| 策略 | k（有效） | TP 损失 | FP 纠正 | 撤销精确率 | macro-F1 | MCC | 增量 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| conservative three-way verifier | 0 | 0 | 0 | — | 0.4067 | 0.0126 | 0.027066 |
| ↳ random (k=0) | 0 | 0.00 | 0.00 | — | 0.4067 [0.4067, 0.4067] | 0.0126 [0.0126, 0.0126] | 0 |
| ↳ 低置信 (k=0) | 0 | 0 | 0 | — | 0.4067 | 0.0126 | 0 |
| original verifier (fail-closed) | 22 (21) | 19 | 3 | 14.3% | 0.3221 | -0.0356 | 0.015100 |
| ↳ random (k=22) | 22 | 17.83 | 4.17 | — | 0.3366 [0.2968, 0.3728] | 0.0080 [-0.1116, 0.1164] | 0 |
| ↳ 低置信 (k=22) | 22 | 18 | 4 | 18.2% | 0.3348 | 0.0024 | 0 |

### `mimo_cross`

| 策略 | k（有效） | TP 损失 | FP 纠正 | 撤销精确率 | macro-F1 | MCC | 增量 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| conservative three-way verifier | 3 | 2 | 1 | 33.3% | 0.4040 | 0.0265 | 0.047054 |
| ↳ random (k=3) | 3 | 2.43 | 0.57 | — | 0.3983 [0.3910, 0.4169] | 0.0118 [-0.0070, 0.0599] | 0 |
| ↳ 低置信 (k=3) | 3 | 3 | 0 | 0.0% | 0.3910 | -0.0070 | 0 |
| original verifier (fail-closed) | 51 | 40 | 11 | 21.6% | 0.2226 | 0.1064 | 0.051960 |
| ↳ random (k=51) | 51 | 41.33 | 9.67 | — | 0.2055 [0.1837, 0.2226] | 0.0041 [-0.1260, 0.1064] | 0 |
| ↳ 低置信 (k=51) | 51 | 41 | 10 | 19.6% | 0.2096 | 0.0289 | 0 |

## 6. 统计检验

### 6.1 McNemar（pre vs post，strict 正确性）

| 臂 | 策略 | pre 正确 | post 正确 | TP→FN | FP→TN | 双侧 p | Holm p |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | original verifier (fail-closed) | 70 | 38 | 43 | 11 | 0.0000 | 0.0001 |
| `deepseek_self` | original verifier (refutation-only, post hoc) | 70 | 60 | 14 | 4 | 0.0309 | 0.0927 |
| `deepseek_self` | original records, strict guard-only replay | 70 | 65 | 8 | 3 | 0.2266 | 0.6797 |
| `deepseek_self` | conservative three-way verifier | 70 | 69 | 1 | 0 | 1.0000 | 1.0000 |
| `deepseek_cross` | original verifier (fail-closed) | 70 | 56 | 21 | 7 | 0.0125 | 0.0125 |
| `deepseek_cross` | original verifier (refutation-only, post hoc) | 70 | 66 | 7 | 3 | 0.3438 | 0.3438 |
| `deepseek_cross` | original records, strict guard-only replay | 70 | 69 | 3 | 2 | 1.0000 | 1.0000 |
| `deepseek_cross` | conservative three-way verifier | 70 | 70 | 0 | 0 | 1.0000 | 1.0000 |
| `mimo_self` | original verifier (fail-closed) | 67 | 51 | 19 | 3 | 0.0009 | 0.0017 |
| `mimo_self` | original verifier (refutation-only, post hoc) | 67 | 60 | 7 | 0 | 0.0156 | 0.0625 |
| `mimo_self` | original records, strict guard-only replay | 67 | 64 | 3 | 0 | 0.2500 | 0.6797 |
| `mimo_self` | conservative three-way verifier | 67 | 67 | 0 | 0 | 1.0000 | 1.0000 |
| `mimo_cross` | original verifier (fail-closed) | 67 | 38 | 40 | 11 | 0.0001 | 0.0002 |
| `mimo_cross` | original verifier (refutation-only, post hoc) | 67 | 58 | 13 | 4 | 0.0490 | 0.0981 |
| `mimo_cross` | original records, strict guard-only replay | 67 | 60 | 9 | 2 | 0.0654 | 0.2617 |
| `mimo_cross` | conservative three-way verifier | 67 | 66 | 2 | 1 | 1.0000 | 1.0000 |

Holm 校正覆盖同一策略下的 4 个臂。结果分三组：原验证器主口径在 4 个臂上全部
显著变差（p=0.0000–0.0125，Holm 后仍显著），因为它大量撤销 TP；原 refutation-only
在 2 个臂边缘显著（未校正 p=0.0309/0.0490，Holm 后不显著）；strict guard-only
重放与保守规则在所有臂上都不显著。也就是说，本实验没有证明保守规则“更好”，
只证明了它没有像原主口径那样显著破坏 strict 正确性。

### 6.2 撤销是否偏向 FP（超几何检验）

| 臂 | 策略 | 有效撤销 k | 其中 invalid 强制 | 撤销 FP | 随机期望 FP | 撤销精确率 | FP 基准率 | p | Holm p |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | original verifier (fail-closed) | 54 | 0 | 11 | 9.90 | 20.4% | 18.3% | 0.2793 | 0.8380 |
| `deepseek_self` | original records, strict guard-only replay | 11 | 0 | 3 | 2.02 | 27.3% | 18.3% | 0.3215 | 0.9645 |
| `deepseek_self` | conservative three-way verifier | 1 | 0 | 0 | 0.18 | 0.0% | 18.3% | 1.0000 | 1.0000 |
| `deepseek_cross` | original verifier (fail-closed) | 26 | 2 | 6 | 4.77 | 23.1% | 18.3% | 0.3089 | 0.8380 |
| `deepseek_cross` | original records, strict guard-only replay | 5 | 0 | 2 | 0.92 | 40.0% | 18.3% | 0.2241 | 0.8964 |
| `deepseek_cross` | conservative three-way verifier | 0 | 0 | 0 | 0.00 | — | 18.3% | 1.0000 | 1.0000 |
| `mimo_self` | original verifier (fail-closed) | 21 | 1 | 3 | 3.98 | 14.3% | 19.0% | 0.8494 | 0.8494 |
| `mimo_self` | original records, strict guard-only replay | 3 | 0 | 0 | 0.57 | 0.0% | 19.0% | 1.0000 | 1.0000 |
| `mimo_self` | conservative three-way verifier | 0 | 0 | 0 | 0.00 | — | 19.0% | 1.0000 | 1.0000 |
| `mimo_cross` | original verifier (fail-closed) | 51 | 0 | 11 | 9.67 | 21.6% | 19.0% | 0.2092 | 0.8367 |
| `mimo_cross` | original records, strict guard-only replay | 11 | 0 | 2 | 2.09 | 18.2% | 19.0% | 0.6733 | 1.0000 |
| `mimo_cross` | conservative three-way verifier | 3 | 0 | 1 | 0.57 | 33.3% | 19.0% | 0.4745 | 1.0000 |

零假设是“从正例中均匀抽 k 个”。保守规则的撤销精确率没有显著高于基准率；
原验证器的主口径同样没有。也就是说，撤销并没有选择性地命中假阳性。

### 6.3 按项目聚类的 bootstrap（Δ = post − pre）

| 臂 | 策略 | Δmacro-F1 [95%] | ΔMCC [95%] | Δrecall [95%] | Δspecificity [95%] | 聚类数 |
| --- | --- | --- | --- | --- | --- | ---: |
| `deepseek_self` | original verifier (fail-closed) | [-0.3241, -0.1387] | [-0.1339, +0.2092] | [-0.5918, -0.2299] | [+0.1852, +0.5910] | 40 |
| `deepseek_self` | conservative three-way verifier | [-0.0219, +0.0000] | [-0.0307, +0.0000] | [-0.0351, +0.0000] | [+0.0000, +0.0000] | 40 |
| `deepseek_cross` | original verifier (fail-closed) | [-0.1319, +0.0342] | [-0.0751, +0.2846] | [-0.2833, -0.0921] | [+0.0769, +0.4800] | 40 |
| `deepseek_cross` | conservative three-way verifier | [+0.0000, +0.0000] | [+0.0000, +0.0000] | [+0.0000, +0.0000] | [+0.0000, +0.0000] | 40 |
| `mimo_self` | original verifier (fail-closed) | [-0.1376, -0.0430] | [-0.1533, +0.0311] | [-0.2679, -0.0870] | [+0.0000, +0.2083] | 40 |
| `mimo_self` | conservative three-way verifier | [+0.0000, +0.0000] | [+0.0000, +0.0000] | [+0.0000, +0.0000] | [+0.0000, +0.0000] | 40 |
| `mimo_cross` | original verifier (fail-closed) | [-0.3210, -0.1186] | [-0.1372, +0.2264] | [-0.5735, -0.2030] | [+0.1818, +0.5714] | 40 |
| `mimo_cross` | conservative three-way verifier | [-0.0348, +0.0134] | [-0.0476, +0.0514] | [-0.0556, +0.0000] | [+0.0000, +0.0698] | 40 |

原验证器的 Δmacro-F1 区间整体为负；保守规则的区间以 0 为中心或仅轻微为负
（`mimo_cross` 的 ΔMCC 区间 [-0.0476, +0.0514] 跨 0）。两者的差别主要是
“撤销多少”，不是“撤销得更准”。

## 7. 成本

| 臂 | 第一遍 USD | 原验证器 USD | 保守验证器 USD | 原流水线 USD | 保守流水线 USD | 保守增量 | 保守/100 单元 | 每个 FP 纠正 USD | 每个 TP 损失 USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deepseek_self` | 0.085622 | 0.064580 | 0.049598 | 0.150202 | 0.135220 | +57.9% | 0.030999 | — | 0.049598 |
| `deepseek_cross` | 0.085622 | 0.022693 | 0.028040 | 0.108314 | 0.113662 | +32.7% | 0.017525 | — | — |
| `mimo_self` | 0.035933 | 0.015100 | 0.027066 | 0.051033 | 0.062999 | +75.3% | 0.016916 | — | — |
| `mimo_cross` | 0.035933 | 0.051960 | 0.047054 | 0.087893 | 0.082987 | +130.9% | 0.029409 | 0.047054 | 0.023527 |

保守验证器每次请求都要重发带行号源码，输入 token 接近一次完整检测；它的成本与
原验证器同一量级，但因为几乎不撤销，分摊到“每个 FP 纠正”上极贵（只有
`mimo_cross` 有 1 个 FP 纠正，其余臂没有）。随机/低置信基线只读第一遍输出，
增量成本为 0。

## 8. 验证器输出结构与失败

| 臂 | supported | unsupported | insufficient | invalid | error | 撤销 | 其中 TP/FP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `deepseek_self` | 19 | 1 | 40 | 0 | 0 | 1 | 1/0 |
| `deepseek_cross` | 44 | 0 | 16 | 0 | 0 | 0 | 0/0 |
| `mimo_self` | 45 | 0 | 11 | 2 | 0 | 0 | 0/0 |
| `mimo_cross` | 15 | 3 | 39 | 0 | 1 | 3 | 2/1 |

`insufficient` 占多数（40/60、16/60、11/58、39/58），`unsupported` 很少
（0–3 条）。这正是三路提示的设计目标：把“函数体内无法证明”与“有具体反证”分开。

失败记录（schema-invalid / API error）全部**保留第一遍预测**，没有 fail-closed：

| 臂 | idx | label | status | family | HTTP / 错误 | 决策 |
| --- | ---: | --- | --- | --- | --- | --- |
| `mimo_self` | 7458 | True | invalid | keys | HTTP 200 / schema invalid (verifier JSON keys mismatch (missing=[], extra=['reason_note'])) | keep_verifier_failure |
| `mimo_self` | 17502 | False | invalid | keys | HTTP 200 / schema invalid (verifier JSON keys mismatch (missing=[], extra=['rebuttal_kind_note'])) | keep_verifier_failure |
| `mimo_cross` | 11143 | True | error | api | HTTP 429 (http_429) | keep_verifier_failure |

### 8.1 全部撤销案例（逐条审计）

| 臂 | idx | label | kind | 引用行 | 行号审计 | reason（节选） |
| --- | ---: | --- | --- | --- | --- | --- |
| `deepseek_self` | 24867 | True | counterexample | [10, 11, 16] | grounded=True, code=True, guard_lex=True, ce=True | The claim's own text concedes strncmp is bounded by the memset, and the %s scenario is real: a 64-byte read with no NUL leaves buf unterminated and li |
| `mimo_cross` | 24867 | True | guard_present | [10] | grounded=True, code=True, guard_lex=True, ce=False | Line 10 performs memset(buf, 0, sizeof(buf)) before the read at line 11, so the entire 64-byte buffer is zero-initialized; even if read() fills all 64 |
| `mimo_cross` | 5541 | False | counterexample | [53, 58, 98] | grounded=True, code=True, guard_lex=True, ce=True | The key struct is zero-allocated at line 53, so key->description is NULL and line 98 frees NULL rather than an uninitialized or stale pointer, defeati |
| `mimo_cross` | 7163 | True | counterexample | [124, 127, 135] | grounded=True, code=True, guard_lex=False, ce=True | The cited lengths p2-p1+1 and endp-p1+1 are not reads past the buffer: estrndup at line 124 allocates exactly p2-p1+1 bytes (content plus NUL), and th |

两个需要人工注意的案例：

1. `deepseek_self` 的 idx 24867：模型选择 `counterexample`，但它的 `reason` 明确说
   “%s scenario is real ... reads out of bounds”，即它描述的是**触发**缺陷的输入，
   不是不触发的反例。行号审计全部通过，说明**机械 grounding 不能替代语义校验**。
2. `mimo_cross` 的 idx 24867：模型把 `memset(buf, 0, sizeof(buf))` 当作守卫。
   memset 只做零初始化；如果后续 `read()` 填满缓冲区且没有 NUL，它并不阻止越界读。
   这是“具体代码行 + 守卫词法”通过、但支配关系不成立的例子。

## 9. 结论

1. **判定规则修对了，但收益是负的。** 把 `insufficient` 与 `unsupported` 分开、
   取消 fail-closed 后，撤销数从原验证器的
   155 条降到 4 条；但撤销精确率仍只有
   25.0%，没有显著高于正例中
   的 FP 基准率；macro-F1 在四个臂上都不升，MCC 只在 `mimo_cross` 上升 +0.0139
   （95% CI 跨 0），代价是 2 个 TP 损失换 1 个 FP 纠正。
2. **模型很少给出可用的具体反证。** 236 条里只有 4 条通过“具体 + grounded”门槛，
   其中 2 条记录（同一 idx 24867 出现在 `deepseek_self` 与 `mimo_cross`）语义上
   站不住：一条把触发缺陷的输入当反例，一条把 memset 零初始化当守卫。提示已经把
   标准写得很窄；继续调提示的边际收益有限。
3. **成本不低。** 保守验证器与原验证器同一量级（每臂约 0.03–0.05 USD），但因为
   几乎不撤销，分摊到每个 FP 纠正上的成本极高。随机/低置信基线为 0 成本，
   在本数据上没有证据表明模型验证优于它们。
4. **真正有价值的改进方向不是“更严格的提示”，而是外部证据。** 例如用静态分析/
   符号执行抽取守卫与可达性，把“守卫是否支配”变成可检查的图性质；或者用
   选择性预测/弃权校准而不是让 LLM 自己判断“是否足够”。在这些外部信号到位前，
   本实验的保守验证器应作为**审计工具/负结果**，不应作为提分组件。

## 10. 限制

- **test-seen / 事后**：160 条测试函数已用于第一遍与原始验证器；本提示在看到那些
  结果后设计，没有预注册。所有数字只是探索性证据。
- 单次运行、temperature=0 不保证确定性；没有多 seed 方差。
- 只处理 schema-valid 正例；第一遍 invalid 记录（DeepSeek 1、MiMo 2）没有可验证
  claim，在 strict 口径里始终算错。
- 只改正例，召回只会下降或不变；32 个非漏洞样本支撑不起精确的 FPR 结论。
- 验证器只看函数体，无法证明跨函数/调用者约束；被撤销的“缺陷”可能包含真实的、
  需要上下文才能成立的漏洞。
- `counterexample` 是模型生成的文本，没有编译、执行或 PoC 验证；`guard_present`
  的支配关系也没有数据流/控制流验证。第 8.1 节给出两个反例。
- 守卫词法检查是启发式：它可能拒绝合法的边界函数写法，也可能接受 `memset` 这类
  非守卫行；它只用于降低盲信，不是语义证明。行号/注释检查还偏保守：以 `*` 开头的
  指针赋值行会被当作注释续行，短于 12 字符的反例会被 schema 拒绝；这两类都会
  导致保留而不是误撤销，因此可能低估撤销数。
- 跨模型验证器不是人工标注；两个模型共享预训练语料与同一批测试函数，一致率高
  不代表正确。
- 成本按第一遍 run 的价格快照估算，未重新核对官方页面；随机/低置信基线的 0 成本
  只指“没有新增 API 调用”，不包含工程与标注成本。
- 四个臂共享两个 claim 集合，不是四个独立样本；Holm 校正只覆盖臂内策略，
  不覆盖跨策略的事后比较。

## 11. 复现（WSL，项目根目录）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 verifier_conservative/selftest.py
bash verifier_conservative/run_conservative.sh deepseek_self dryrun
bash verifier_conservative/run_conservative.sh deepseek_self test
bash verifier_conservative/run_conservative.sh deepseek_cross test
bash verifier_conservative/run_conservative.sh mimo_self test
bash verifier_conservative/run_conservative.sh mimo_cross test
python3 verifier_conservative/analyze_conservative.py
```

`run_conservative.sh` 在目标目录已有 manifest 时自动加 `--resume`；请求按内容哈希
缓存在 run 目录。脚本不写 `evidence_verify/`、`evidence_prompt/`、`splits/` 或
`runner/runs/`。凭证由 `run_with_kimi_config.py` 从 Kimi Code 配置读入进程内存，
不打印、不落盘。


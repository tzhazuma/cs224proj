# MiMo-V2.6-Flash 与 DeepSeek-V4.1-Flash：专项统计与错误分析

**范围**：同一冻结 split-v1 测试集上的 12 个完整真实 run（2 个模型 × 3 个策略 × 2 个任务）。
本文件只回答两件事：**同策略跨模型**的差异，以及**同模型跨策略**的差异。两者是不同比较轴，不合并成总排行榜。

**产物**：`analysis/model_comparison.json`（机器可读，含全部点估计、区间、检验与失败记录）与 `analysis/model_comparison.md`（本文件）。
**分析版本**：`model-comparison-2026-11-12.1`；生成时间 `2026-11-11T19:36:26.026714+00:00`。
所有数值来自 `runner/runs/` 下的真实 `metrics.json` / `results.jsonl`；未使用 mock、fixture 或估计值。
运行产物中没有保存任何 API key；本分析也未读取或写入密钥。

> **阅读约定**：`valid-only` 只在有效输出上计算；`end-to-end` 把 invalid/error 计为错误。本文件每个表都同时给出分母或 coverage，**invalid 不会被静默丢弃**。`DA` 指配对判别准确率（漏洞侧判漏洞且修复侧判安全）；`CAC` 指 `complete_function and changed_from_input`。

## 0. 结论摘要

1. **12/12 个 run 完整，0 个缺失请求，0 个 API error。** 两个模型各 2,484 次请求；DeepSeek 有 102 次 invalid（4.11%），MiMo 有 70 次（2.82%）。失败位置几乎相反：DeepSeek 全部在修复任务（93 次缺 `explanation` + 9 次截断），MiMo 主要在检测任务（61 次 `is_vulnerability` 字段漂移 + 9 次修复截断）。
2. **独立检测上 DeepSeek 的 macro-F1 三个策略都更高，但统计证据不均衡。** 逐 run macro-F1：DeepSeek 0.383/0.400/0.381，MiMo 0.346/0.346/0.365（direct/few-shot/context）。配对 bootstrap 的 Δmacro-F1（DeepSeek−MiMo）为 +3.1 pp [−2.0, +7.7]、+5.3 pp [+1.0, +12.9]、+0.9 pp [−7.1, +5.9]；只有 few-shot 的名义区间排除 0。strict accuracy 的 McNemar 原始 p 分别为 0.052/0.078/0.286，经 Holm 后均不显著（0.157/0.157/0.286）。
3. **覆盖率差异是模型轴上最稳健的差异。** MiMo 的检测 coverage 在 direct/context 分别降到 93.8%/95.6%，few-shot 为 100%；DeepSeek 的三个独立检测 run 和三个配对分侧检测 run 都是 100%。direct Δcoverage=+6.25 pp [3.2, 12.5]，McNemar Holm p=0.0059；context Δcoverage=+4.38 pp [2.0, 9.3]，Holm p=0.0313；few-shot 无差异。
4. **MiMo 的字段漂移主要是格式问题，但不能用它解释全部 macro-F1 差距。** 61 次漂移中 56 次输出 `false`；按漂移键容忍解析后，direct/context 的 strict accuracy 分别从 32.5%→34.4%、35.0%→37.5%，配对 DA（all pairs）从 7.8%→11.1%、10.6%→12.2%，模型差距明显收窄。但 macro-F1 在 direct 从 0.3456 略降到 0.3431（恢复的多为假阴性），context 从 0.3650 升到 0.3741。因此“格式解释一切”只对 end-to-end accuracy/DA 成立，对 macro-F1 不成立。
5. **配对 DA 没有稳健的模型差异。** all-pairs DA：DeepSeek 11.7/8.9/12.2%，MiMo 7.8/9.4/10.6%；ΔDA=+3.9 pp [0.0, +8.3]（p=0.118，Holm=0.355）、−0.6 pp（p=1.0）、+1.7 pp（p=0.607）。direct 的表观差距主要来自 MiMo 的 26 个无效 pair；在两侧都有效的 154 对上差距为 +3.25 pp [−1.3, +7.9]，容忍解析后 all-pairs DA 差距只剩 0.56 pp。
6. **修复结构的关键不是“谁更好”，而是“按什么 schema 计分”。** MiMo 的 schema 有效率 98.9–99.2%，DeepSeek 为 82.8–99.2%；direct/context 的 14–16 pp schema 差距经 Holm 显著。official CAC（complete+changed）在 direct/context 看似 MiMo 更高（DeepSeek 65.6–71.1% vs MiMo 70.3–79.4%），但把 DeepSeek 缺 `explanation` 的代码按 code-only 计分后，DeepSeek CAC 变为 75–83%，方向反转。few-shot 两边 schema 都约 99%，DeepSeek CAC 高 12.5–13.3 pp（pairs Holm=0.0028），这是唯一不能用 schema 解释的内容差异；但 `changed` 只是结构代理，不是修复正确率。
7. **成本差异主要是单价，不是 token 效率。** 用同一 cache-aware 公式重算，DeepSeek $1.899 vs MiMo $0.623（3.05×）；run 记录值 $2.439 vs $0.623（3.91×）。两者 token 总量只差 7.4%，而 input/output 单价分别是 2.14×/4.29×。DeepSeek 的 `response.cost` 未扣 cached token，相对重算值多报 $0.541（28.5%）。
8. **尾部延迟是 MiMo 的短板，但不能解读为“模型更慢”。** p50 都在 5.0–6.8 s；MiMo p95 29.8–53.9 s、max 305.5 s，DeepSeek p95 16.7–20.2 s、max 77.8 s。18 次截断全部是同样的 3 个超长修复函数（966–1,011 行；25–33k 字符），与输入长度/8192 输出预算一致，而不是随机模型失败。
9. **两个轴不能互相替代。** 模型轴固定策略、比较同单元的两个模型；策略轴固定模型、比较同单元的三个提示。模型轴是 post-hoc（原协议固定 DeepSeek 比较策略），策略轴是预注册。交互 DiD 的所有区间都跨 0，只能作为探索性证据；没有“总体赢家”。

## 1. 数据、设计与可比性

### 1.1 12 个 run 的矩阵

设计是完整的 2×3×2 网格：每个模型 × 每个策略 × 每个任务各一个 run。独立检测 160 条函数（128 漏洞 + 32 非漏洞，40 个项目）；配对任务 180 对（360 个版本，60 个项目）。每个 run 包含检测请求和修复请求：独立集 160+128=288，配对集 360+180=540。

| run_id | 模型 | 策略 | 任务 | records/planned | missing | partial |
| --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | DeepSeek | direct | independent | 288/288 | 0 | no |
| `test_v1_direct_pairs` | DeepSeek | direct | pairs | 540/540 | 0 | no |
| `test_v1_few-shot_independent` | DeepSeek | few-shot | independent | 288/288 | 0 | no |
| `test_v1_few-shot_pairs` | DeepSeek | few-shot | pairs | 540/540 | 0 | no |
| `test_v1_context_independent` | DeepSeek | context | independent | 288/288 | 0 | no |
| `test_v1_context_pairs` | DeepSeek | context | pairs | 540/540 | 0 | no |
| `test_v1_mimo_direct_independent` | MiMo | direct | independent | 288/288 | 0 | no |
| `test_v1_mimo_direct_pairs` | MiMo | direct | pairs | 540/540 | 0 | no |
| `test_v1_mimo_few-shot_independent` | MiMo | few-shot | independent | 288/288 | 0 | no |
| `test_v1_mimo_few-shot_pairs` | MiMo | few-shot | pairs | 540/540 | 0 | no |
| `test_v1_mimo_context_independent` | MiMo | context | independent | 288/288 | 0 | no |
| `test_v1_mimo_context_pairs` | MiMo | context | pairs | 540/540 | 0 | no |

共同配置：模型版本分别为 `deepseek-v4.1-flash` / `mimo-v2.6-flash`；prompt version `secvul-prompt-2026-11-11.1`；temperature 0；max output 8192；`response_format=json_object`；同一 OpenCode Go 端点。MiMo 额外使用 `max_completion_tokens` 与 `reasoning_effort=none`，DeepSeek 走非思考路径；两者都意图对齐到“非推理”设置，但服务端 tokenizer/chat template 仍可能不同。

### 1.2 完整性与同一性检查

- 完整性检查：68 项中 68 项通过，0 项失败。
- 12 个 run 的 `partial=false`、`missing_requests=0`、`complete_planned_requests=true`，records 与 expected 一致；无 API error。
- 两个数据集文件的 SHA-256 与每个 `metrics.run.dataset_sha256` 逐一匹配；独立集 40 个项目、配对集 60 个项目。
- prompt version、temperature、max_tokens、response_format 在 12 个 run 中一致。
- 与 `analysis/aggregation.json` 的 DeepSeek 数值交叉核对：最大绝对差 `0.0`（6 个 DeepSeek run 的 macro-F1、strict accuracy、MCC、DA 全部逐位一致）。

**唯一不完全对称的配置**：DeepSeek 的 `response.cost.cached_prompt_tokens` 在全部记录中为 0，即使 usage 的 `prompt_tokens_details.cached_tokens` 大于 0；MiMo 的记录正确带 cached token。这影响成本口径，见 §6。DeepSeek `direct_independent` 还复用了 105 条缓存响应；MiMo `few-shot_independent` 有 2 次重试（290 次 API attempt / 288 条记录）。

### 1.3 配对键、聚类与统计口径

| 任务 | 单元 | 配对键 | 聚类单位 | cluster 数 | 分母 |
| --- | --- | --- | --- | --- | --- |
| 独立检测 | 函数 | `idx` | project | 40 | 160 |
| 配对检测（分侧） | 版本（函数） | `pair_id`+`side` | pair | 180 | 360 |
| 配对联合（DA） | pair | `pair_id` | pair | 180 | 180 |
| 修复 | 漏洞函数 / pair | `idx` / `pair_id` | project / pair | 40 / 180 | 128 / 180 |

主要终点与口径：

- **独立检测**：主终点是 macro-F1（valid-only，且在两个模型都有效的 complete-case cohort 上比较）与 end-to-end strict accuracy（全部 160 条，invalid 计错）。MCC、balanced accuracy、coverage 为并列报告。
- **配对任务**：主终点是 DA（all pairs，invalid pair 计错）；DA（两侧都有效的 cohort）与 per-version macro-F1/MCC 为次要。
- **修复**：schema-valid rate 与 complete+changed rate（全部计划请求，invalid 计失败）；schema-valid-only 的 changed rate 为次要。`complete_function` 与 `changed_from_input` 只是结构代理，不证明漏洞被消除、行为被保留、代码可编译。
- **区间**：10,000 次 percentile cluster bootstrap，seed 42，95%，线性插值；独立检测按 project 重采样（40 个），配对按 pair 重采样（180 个）。F1/macro-F1/MCC/BA 与差值不用 Wilson；比例类另给 Wilson 仅作描述。
- **检验**：McNemar 精确双侧，用于二值正确性/覆盖率/schema/CAC；主分析用全部单元（invalid 计错），修复的 changed 另在 both-schema-valid cohort 上做次要 McNemar。valid-only 的 macro-F1/MCC/DA 差值用配对 cluster bootstrap，不用 McNemar。Holm 在每个 dataset×endpoint family 内校正（模型轴 3 个策略；策略轴 2 个对比）。主推断看 cluster bootstrap 差值区间，McNemar 是次要证据。

## 2. 无效输出审计：invalid 没有被丢弃

### 2.1 失败分类

| 模型 | 任务 | 类别 | 数量 | 占该任务请求 | 按策略 |
| --- | --- | --- | --- | --- | --- |
| DeepSeek | repair | missing_explanation | 93 | 10.06% | direct 45 / few-shot 0 / context 48 |
| DeepSeek | repair | truncation | 9 | 0.97% | direct 3 / few-shot 3 / context 3 |
| MiMo | detection | field_drift | 61 | 3.91% | direct 39 / few-shot 0 / context 22 |
| MiMo | repair | truncation | 9 | 0.97% | direct 3 / few-shot 3 / context 3 |

分类规则：`field_drift` = 检测 JSON 键不是 `is_vulnerable`（`is_vulnerability` / `is_vulnerative`，或同时含两个键）；`missing_explanation` = 修复 JSON 缺 `explanation`；`truncation` = `invalid JSON: Unterminated string` 且 `finish_reason=length`。所有 invalid 都保留了 `sample_id`、原始 content、finish_reason、延迟与 usage；下面的每个指标都同时报分母。

### 2.2 每个 run 的 invalid 与 coverage

| run_id | 模型 | 策略 | 任务 | 检测 invalid | 修复 invalid | 检测 coverage | pair coverage | 失败类别 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | DeepSeek | direct | independent | 0 | 19 | 100.0% | — | repair:missing_explanation:18, repair:truncation:1 |
| `test_v1_direct_pairs` | DeepSeek | direct | pairs | 0 | 29 | 100.0% | 100.0% | repair:missing_explanation:27, repair:truncation:2 |
| `test_v1_few-shot_independent` | DeepSeek | few-shot | independent | 0 | 1 | 100.0% | — | repair:truncation:1 |
| `test_v1_few-shot_pairs` | DeepSeek | few-shot | pairs | 0 | 2 | 100.0% | 100.0% | repair:truncation:2 |
| `test_v1_context_independent` | DeepSeek | context | independent | 0 | 20 | 100.0% | — | repair:missing_explanation:19, repair:truncation:1 |
| `test_v1_context_pairs` | DeepSeek | context | pairs | 0 | 31 | 100.0% | 100.0% | repair:missing_explanation:29, repair:truncation:2 |
| `test_v1_mimo_direct_independent` | MiMo | direct | independent | 10 | 1 | 93.8% | — | detection:field_drift:10, repair:truncation:1 |
| `test_v1_mimo_direct_pairs` | MiMo | direct | pairs | 29 | 2 | 91.9% | 85.6% | detection:field_drift:29, repair:truncation:2 |
| `test_v1_mimo_few-shot_independent` | MiMo | few-shot | independent | 0 | 1 | 100.0% | — | repair:truncation:1 |
| `test_v1_mimo_few-shot_pairs` | MiMo | few-shot | pairs | 0 | 2 | 100.0% | 100.0% | repair:truncation:2 |
| `test_v1_mimo_context_independent` | MiMo | context | independent | 7 | 1 | 95.6% | — | detection:field_drift:7, repair:truncation:1 |
| `test_v1_mimo_context_pairs` | MiMo | context | pairs | 15 | 2 | 95.8% | 92.2% | detection:field_drift:15, repair:truncation:2 |

读法：DeepSeek 的检测 coverage 全部为 100%，所以它的检测指标没有 invalid 损失；它的损失集中在修复（schema 或截断）。MiMo 反过来：修复 schema 几乎总是有效，但检测在 direct/context 有 7–29 条字段漂移（独立 7–10，配对 15–29），导致检测 coverage 降到 91.9–95.8%、direct 配对 coverage 降到 85.6%。这就是为什么本文件同时给 valid-only 与 end-to-end：只看 valid-only 会掩盖 MiMo 的格式成本，只看 end-to-end 会把 DeepSeek 的修复 schema 失败误读为修复内容差。

## 3. 独立检测（160 条函数）

### 3.1 逐 run 指标

| 模型 | 策略 | valid/160 | coverage | P | R | 正类 F1 | macro-F1 [95% CI] | MCC [95% CI] | BA | strict acc |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | direct | 160/160 | 100.0% | 0.826 | 0.297 | 0.437 | 0.383 [0.305, 0.552] | +0.041 [-0.100, +0.248] | 0.523 | 38.8% |
| DeepSeek | few-shot | 160/160 | 100.0% | 0.837 | 0.320 | 0.463 | 0.399 [0.305, 0.593] | +0.061 [-0.087, +0.294] | 0.535 | 40.6% |
| DeepSeek | context | 160/160 | 100.0% | 0.812 | 0.305 | 0.443 | 0.381 [0.286, 0.560] | +0.020 [-0.127, +0.234] | 0.512 | 38.8% |
| MiMo | direct | 150/160 | 93.8% | 0.806 | 0.242 | 0.372 | 0.346 [0.264, 0.528] | +0.008 [-0.114, +0.217] | 0.504 | 32.5% |
| MiMo | few-shot | 160/160 | 100.0% | 0.773 | 0.266 | 0.395 | 0.346 [0.262, 0.512] | -0.042 [-0.199, +0.162] | 0.477 | 35.0% |
| MiMo | context | 153/160 | 95.6% | 0.861 | 0.252 | 0.390 | 0.365 [0.278, 0.571] | +0.080 [-0.037, +0.301] | 0.543 | 35.0% |

CI 为按 project 聚类的 10,000 次 bootstrap（40 个项目）；macro-F1/MCC 不用 Wilson。`strict acc` 把 invalid 计错；这里 DeepSeek 的 coverage=100%，所以 strict 与 valid-only accuracy 相同。MiMo 的 valid/160 与 coverage 不同，strict acc 低于 valid-only accuracy。

### 3.2 同策略跨模型比较（DeepSeek − MiMo）

| 策略 | cohort n | Δmacro-F1 [95% CI] | ΔMCC [95% CI] | ΔBA [95% CI] | Δstrict acc [95% CI] |
| --- | --- | --- | --- | --- | --- |
| direct | 150 | +3.1 pp [-2.0, +7.7] | +0.037 [-0.078, +0.144] | +2.1 pp [-4.1, +8.0] | +6.2 pp [+1.8, +12.2] |
| few-shot | 160 | +5.3 pp [+1.0, +12.9] | +0.103 [+0.014, +0.280] | +5.9 pp [+0.8, +16.0] | +5.6 pp [+1.0, +13.0] |
| context | 153 | +0.9 pp [-7.1, +5.9] | -0.057 [-0.199, +0.030] | -3.0 pp [-11.2, +2.0] | +3.8 pp [-4.3, +9.9] |

| 策略 | Δcoverage [95% CI] | coverage McNemar p (Holm) | strict McNemar p (Holm) | strict discordant b/c |
| --- | --- | --- | --- | --- |
| direct | +6.2 pp [+3.2, +12.5] | 0.0020 (0.0059) | 0.0525 (0.1574) | 16/6 |
| few-shot | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) | 0.0784 (0.1574) | 15/6 |
| context | +4.4 pp [+2.0, +9.3] | 0.0156 (0.0312) | 0.2863 (0.2863) | 14/8 |

**怎么读**：

- 三个策略的 macro-F1 点估计都是 DeepSeek 更高，但只有 few-shot 的 Δmacro-F1 名义区间排除 0（+5.3 pp [+1.0, +12.9]）；direct 的区间跨 0，context 几乎为 0。McNemar 的 strict accuracy 在三个策略都没有通过 Holm（0.157/0.157/0.286），所以不能写“DeepSeek 检测显著更好”。
- 边缘证据要标清楚：direct 的 Δstrict 的 cluster 区间 [+1.8, +12.2] 排除 0，但 McNemar p=0.052、Holm=0.157；few-shot 的 Δmacro 区间 [+1.0, +12.9] 排除 0，但 strict McNemar p=0.078、Holm=0.157。两种方法在边缘处不一致；按协议主推断看 cluster 区间、McNemar 是次要证据，因此只能写成“suggestive/方向一致”，不能写成“确证显著”。
- 覆盖率的差异是稳健的：direct +6.25 pp、context +4.38 pp，Holm p 分别为 0.0059/0.0313；few-shot 没有差异。原因不是模型“看不见”这些函数，而是 MiMo 把键写成了 `is_vulnerability`，runner 按 schema 判 invalid（§7.1）。
- direct 的 Δmacro-F1 在 complete-case cohort（n=150）上是 +3.1 pp，而逐 run 的全 valid 差是 +3.7 pp；cohort 排除了 10 条 MiMo invalid，所以比较的是同一批 150 条。context cohort n=153，few-shot n=160。
- 不是所有指标都同向：context 的 ΔMCC=−0.057 [−0.199, +0.030]、ΔBA=−3.0 pp [−11.2, +2.0]，点估计反而是 MiMo 更高；MiMo context 的 MCC=+0.080、BA=0.543，DeepSeek 为 +0.020、0.512。所以“DeepSeek 更好”只对 macro-F1 与 strict accuracy 成立，不能推广到所有指标；context 的 macro-F1 差距也只有 0.9 pp，基本是平手。

### 3.3 容忍字段漂移的敏感性（diagnostic，不是 official）

把 MiMo 的 `is_vulnerability` / `is_vulnerative` 映射回 `is_vulnerable`，只对能解析出布尔值的漂移记录生效；截断仍然算 invalid。下表同时给 official 与 tolerant 的 MiMo 值，以及 DeepSeek 的同一指标。**这不是正式分数**，只用于估计“格式损失”占模型差距的比例。

| 策略 | MiMo strict official | MiMo strict tolerant | DeepSeek strict | strict gap official | strict gap tolerant | MiMo macro official | MiMo macro tolerant | DeepSeek macro | macro gap official | macro gap tolerant |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| direct | 32.5% | 34.4% | 38.8% | +6.2 pp | +4.4 pp | 0.346 | 0.343 | 0.383 | +3.7 pp | +4.0 pp |
| few-shot | 35.0% | 35.0% | 40.6% | +5.6 pp | +5.6 pp | 0.346 | 0.346 | 0.399 | +5.3 pp | +5.3 pp |
| context | 35.0% | 37.5% | 38.8% | +3.8 pp | +1.3 pp | 0.365 | 0.374 | 0.381 | +1.6 pp | +0.7 pp |

注意：这里的 macro 是每个 run 自己的 valid-only 值（MiMo direct 的 valid n=150、context n=153），不是 §3.2 的 complete-case cohort；所以 direct 的 macro gap 是 +3.7 pp，而 §3.2 的 cohort 差是 +3.1 pp。strict 是全部 160 条（invalid 计错），与 §3.2 的 strict 行一致。

关键细节：61 条漂移里有 56 条输出 `false`。按标签拆：漏洞标签 36 条中 32 条为 `false`（假阴性）、4 条为 `true`；非漏洞标签 25 条中 24 条为 `false`（真阴性）、1 条为 `true`（假阳性）。所以容忍解析主要把“被 invalid 掩盖的真阴性”变成正确，strict accuracy 上升；但它同时把 32 个假阴性放进 valid-only 分母，macro-F1 不一定上升（direct 甚至略降）。这就是为什么不能用 tolerant 值替换 official macro-F1。

## 4. 配对判别（180 对）

### 4.1 逐 run 的 DA 与联合类别

| 模型 | 策略 | valid pairs/180 | pair coverage | DA valid [95% Wilson] | DA all [95% Wilson] | both_clean | both_flagged | swapped |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | direct | 180/180 | 100.0% | 11.7% [7.8%, 17.2%] | 11.7% [7.8%, 17.2%] | 113 | 44 | 2 |
| DeepSeek | few-shot | 180/180 | 100.0% | 8.9% [5.5%, 14.0%] | 8.9% [5.5%, 14.0%] | 113 | 49 | 2 |
| DeepSeek | context | 180/180 | 100.0% | 12.2% [8.2%, 17.8%] | 12.2% [8.2%, 17.8%] | 108 | 49 | 1 |
| MiMo | direct | 154/180 | 85.6% | 9.1% [5.5%, 14.7%] | 7.8% [4.7%, 12.6%] | 108 | 27 | 5 |
| MiMo | few-shot | 180/180 | 100.0% | 9.4% [6.0%, 14.6%] | 9.4% [6.0%, 14.6%] | 117 | 40 | 6 |
| MiMo | context | 166/180 | 92.2% | 11.4% [7.5%, 17.2%] | 10.6% [6.9%, 15.9%] | 106 | 38 | 3 |

`DA valid` 的分母是 valid pairs；`DA all` 的分母是 180，invalid pair 计错。`both_clean` / `both_flagged` / `swapped` 是 valid pairs 上的计数；`swapped` 指漏洞侧判安全且修复侧判漏洞。所有 DA 都远低于项目报告的 56.1%（101/180）位置先验基线；这个任务本质上是两次独立的单函数分类，不是联合 A/B 推理。

### 4.2 同策略跨模型比较（DeepSeek − MiMo）

| 策略 | ΔDA all [95% CI] | DA McNemar p (Holm) | ΔDA both-valid [95% CI] | both-valid pairs | Δpair coverage [95% CI] | coverage McNemar p (Holm) |
| --- | --- | --- | --- | --- | --- | --- |
| direct | +3.9 pp [+0.0, +8.3] | 0.1185 (0.3554) | +3.2 pp [-1.3, +7.9] | 154 | +14.4 pp [+9.4, +20.0] | 3.0e-08 (8.9e-08) |
| few-shot | -0.6 pp [-3.9, +2.8] | 1.0000 (1.0000) | -0.6 pp [-3.9, +2.8] | 180 | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) |
| context | +1.7 pp [-2.2, +6.1] | 0.6072 (1.0000) | +0.0 pp [-4.2, +4.1] | 166 | +7.8 pp [+3.9, +11.7] | 0.0001 (0.0002) |

**怎么读**：

- 三个策略的 DA 差异都不显著。direct 的 all-pairs 差距 3.9 pp 的下界正好是 0，McNemar p=0.118、Holm=0.355；few-shot 是 −0.6 pp（p=1.0）；context 是 +1.7 pp（p=0.607）。
- direct 的表观差距主要是 coverage：MiMo 有 26 个 invalid pair（29 个 invalid 侧；16 个漏洞侧 + 13 个修复侧，其中 3 对两侧都 invalid），all-pairs DA 被计为 7.8%；在 154 对两侧都有效的 cohort 上，MiMo DA=9.1%、DeepSeek=12.3%，Δ=+3.25 pp [−1.3, +7.9]。
- context 的 pair coverage 差 +7.8 pp（Holm=0.0002），但 166 对两侧都有效的 cohort 上两边 DA 都是 11.45%，coverage 差异没有转化为 DA 差异；这正是“invalid 影响 all-pairs 视图、但不影响 both-valid 视图”的例子。
- 容忍解析后，MiMo direct DA all 从 7.8% 升到 11.1%，与 DeepSeek 的 11.7% 只差 0.56 pp；context 从 10.6% 升到 12.2%，与 DeepSeek 持平。也就是说，**DA 的模型差距基本可以由格式/覆盖率解释**，不像 macro-F1 那样还留有内容差距。
- context 的 both-valid cohort 两侧 DA 都是 11.45%，完全相同；few-shot 是 MiMo 9.4% vs DeepSeek 8.9%，方向与 direct 相反。没有“谁在配对任务上更强”的稳定结论。

### 4.3 分版本检测（次要）

| 模型 | 策略 | macro-F1 | MCC | strict acc | coverage |
| --- | --- | --- | --- | --- | --- |
| DeepSeek | direct | 0.536 | +0.114 | 55.3% | 100.0% |
| DeepSeek | few-shot | 0.524 | +0.083 | 53.9% | 100.0% |
| DeepSeek | context | 0.546 | +0.123 | 55.8% | 100.0% |
| MiMo | direct | 0.504 | +0.075 | 49.2% | 91.9% |
| MiMo | few-shot | 0.508 | +0.068 | 53.1% | 100.0% |
| MiMo | context | 0.527 | +0.099 | 52.2% | 95.8% |

这是把 360 个版本当观测的次要描述；点估计没有对 pair 内相关做校正，不能替代 DA。它显示 DeepSeek 的分版本 macro-F1 在三个策略都略高（0.536/0.524/0.546 vs 0.504/0.508/0.527），但 strict accuracy 的差距更小，且 DA 没有显著差异——这正是“分侧检测”和“联合判别”不是同一能力的例子。

## 5. 修复结构（每个策略 308 条请求 = 128 独立 + 180 配对）

### 5.1 逐 run 结构指标

| 模型 | 策略 | 任务 | schema valid | complete (all) | changed (all) | complete+changed (all) | exact match 参考 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | direct | independent | 85.2% (109/128) | 84.4% (108/128) | 66.4% (85/128) | 65.6% (84/128) | —（无参考） |
| DeepSeek | direct | pairs | 83.9% (151/180) | 83.9% (151/180) | 68.9% (124/180) | 68.9% (124/180) | 3/151 |
| DeepSeek | few-shot | independent | 99.2% (127/128) | 97.7% (125/128) | 58.6% (75/128) | 57.0% (73/128) | —（无参考） |
| DeepSeek | few-shot | pairs | 98.9% (178/180) | 98.3% (177/180) | 64.4% (116/180) | 64.4% (116/180) | 9/178 |
| DeepSeek | context | independent | 84.4% (108/128) | 83.6% (107/128) | 67.2% (86/128) | 66.4% (85/128) | —（无参考） |
| DeepSeek | context | pairs | 82.8% (149/180) | 82.8% (149/180) | 71.1% (128/180) | 71.1% (128/180) | 4/149 |
| MiMo | direct | independent | 99.2% (127/128) | 96.9% (124/128) | 72.7% (93/128) | 70.3% (90/128) | —（无参考） |
| MiMo | direct | pairs | 98.9% (178/180) | 98.3% (177/180) | 78.3% (141/180) | 77.8% (140/180) | 3/178 |
| MiMo | few-shot | independent | 99.2% (127/128) | 96.9% (124/128) | 46.1% (59/128) | 44.5% (57/128) | —（无参考） |
| MiMo | few-shot | pairs | 98.9% (178/180) | 98.3% (177/180) | 51.7% (93/180) | 51.1% (92/180) | 4/178 |
| MiMo | context | independent | 99.2% (127/128) | 97.7% (125/128) | 77.3% (99/128) | 75.8% (97/128) | —（无参考） |
| MiMo | context | pairs | 98.9% (178/180) | 98.3% (177/180) | 80.0% (144/180) | 79.4% (143/180) | 5/178 |

`all` 分母是该任务的全部计划修复请求；invalid 计为失败。`exact match 参考` 只在配对集有参考修复，是规范化文本相等，不是修复正确率；数值在 1.7–5.1%，不能据此声称补丁正确。independent 没有参考修复，所以是 `—`。在 schema-valid 子集上，两个模型的 complete 率都在 97.6–100%；DeepSeek 的 all-rate 低（83–98%）主要是 invalid，而不是代码结构不完整。

### 5.2 同策略跨模型比较（DeepSeek − MiMo）

| 任务 | 策略 | schema DeepSeek | schema MiMo | Δschema [95% CI] | schema McNemar p (Holm) |
| --- | --- | --- | --- | --- | --- |
| independent | direct | 85.2% | 99.2% | -14.1 pp [-25.6, -9.4] | 7.6e-06 (1.5e-05) |
| independent | few-shot | 99.2% | 99.2% | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) |
| independent | context | 84.4% | 99.2% | -14.8 pp [-25.5, -9.7] | 3.8e-06 (1.1e-05) |
| pairs | direct | 83.9% | 98.9% | -15.0 pp [-21.8, -10.9] | 1.5e-08 (3.0e-08) |
| pairs | few-shot | 98.9% | 98.9% | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) |
| pairs | context | 82.8% | 98.9% | -16.1 pp [-23.8, -11.4] | 3.7e-09 (1.1e-08) |

| 任务 | 策略 | CAC DeepSeek | CAC MiMo | ΔCAC [95% CI] | CAC McNemar p (Holm) | changed both-valid DS | changed both-valid MiMo | Δchanged [95% CI] | n |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| independent | direct | 65.6% | 70.3% | -4.7 pp [-17.9, +6.5] | 0.4614 (0.4614) | 78.0% | 71.6% | +6.4 pp [-5.1, +21.7] | 109 |
| independent | few-shot | 57.0% | 44.5% | +12.5 pp [+5.6, +26.2] | 0.0195 (0.0586) | 59.1% | 46.5% | +12.6 pp [+5.9, +26.7] | 127 |
| independent | context | 66.4% | 75.8% | -9.4 pp [-28.6, -2.2] | 0.0884 (0.1769) | 79.6% | 75.9% | +3.7 pp [-10.0, +10.8] | 108 |
| pairs | direct | 68.9% | 77.8% | -8.9 pp [-16.6, +0.8] | 0.0440 (0.0881) | 82.1% | 78.8% | +3.3 pp [-3.3, +13.3] | 151 |
| pairs | few-shot | 64.4% | 51.1% | +13.3 pp [+7.1, +22.2] | 0.0009 (0.0028) | 65.2% | 52.2% | +12.9 pp [+6.4, +22.0] | 178 |
| pairs | context | 71.1% | 79.4% | -8.3 pp [-16.7, +1.2] | 0.0444 (0.0881) | 85.9% | 80.5% | +5.4 pp [-1.1, +14.9] | 149 |

**怎么读**：

- schema 的 14–16 pp 差距集中在 direct/context，Holm 全部显著；few-shot 两边都约 99%，无差异。这不是“修复内容”差异，而是 DeepSeek 在 direct/context 经常不写 `explanation` 键（§7.3）。
- official CAC 在 direct/context 看似 MiMo 更高（DeepSeek 65.6–71.1% vs MiMo 70.3–79.4%），但 Holm 后只有 few-shot pairs 稳健（DeepSeek +13.3 pp，Holm=0.0028）；direct/context 的 CAC 差异在 Holm 后跨 0 或边缘。注意在 both-valid cohort 上，direct/context 的 changed rate 反而是 DeepSeek 更高（例如 pairs direct 82.1% vs 78.8%）；official CAC 的差距来自 schema 失败，不是“DeepSeek 更少改动”。
- few-shot 是唯一 schema 对齐、且 CAC 有稳健差异的格子：DeepSeek 57.0/64.4%，MiMo 44.5/51.1%；DeepSeek 更常返回“与输入不同”的完整函数。但这只说明“改动更多”，不说明“修得对”；MiMo 的 few-shot 可能更保守地复制输入，既可能是安全，也可能是无效修复。没有编译/测试/PoC/人工评审，不能判定。

### 5.3 DeepSeek 缺 `explanation` 的 code-only 反事实（diagnostic）

官方 schema 要求 `fixed_function` + `explanation`。DeepSeek 的 93 条 direct/context 修复只缺 `explanation`，`fixed_function` 全部存在。把 `explanation` 视为可选，并对返回的代码重跑 `complete_function` / `changed_from_input` 检查，可估计“schema 门槛”对修复排名的影响。**这不是 official 分数。**

| 任务 | 策略 | 缺 explanation | DS schema official | DS schema code-only | DS CAC official | DS CAC code-only | MiMo CAC official | 方向是否反转 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| independent | direct | 18 | 85.2% | 99.2% | 65.6% | 75.0% | 70.3% | 是 |
| independent | few-shot | 0 | — | — | — | — | 44.5% | — |
| independent | context | 19 | 84.4% | 99.2% | 66.4% | 78.9% | 75.8% | 是 |
| pairs | direct | 27 | 83.9% | 98.9% | 68.9% | 81.7% | 77.8% | 是 |
| pairs | few-shot | 0 | — | — | — | — | 51.1% | — |
| pairs | context | 29 | 82.8% | 98.9% | 71.1% | 83.3% | 79.4% | 是 |

四个 direct/context 格子的 CAC 方向全部反转：official 是 MiMo 更高，code-only 是 DeepSeek 更高。因此 **direct/context 的修复结构排名是 schema 口径的产物，不是修复内容差异**。few-shot 没有缺 explanation 的记录，不受这个反事实影响；它的 CAC 差异才是内容/行为差异。即便如此，code-only 仍然只是结构代理：它不能证明修复正确、可编译或行为保持。

## 6. 成本与延迟

### 6.1 成本口径

项目 run 的 `metrics.cost.total_cost_usd` 是逐记录 `response.cost.cost_usd` 的和。DeepSeek 的记录在 `response.cost.cached_prompt_tokens` 中写 0，即使 usage 的 `prompt_tokens_details.cached_tokens` 大于 0；MiMo 的记录正确带 cached token。为了跨模型可比，本文件另算 **usage-normalized** 成本：`(prompt−cached)×input_price + cached×cached_price + completion×output_price`，逐记录用该 run 自己的价格。**两者都报；official 仍以 run 记录值为准。**

| run_id | reported $ | normalized $ | Δ (reported−normalized) | invalid $ | invalid 占比 | $/100 单元 | $/correct |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | $0.253340 | $0.251722 | $+0.001618 | $0.031956 | 12.7% | $0.1573 | $0.00406 |
| `test_v1_direct_pairs` | $0.392245 | $0.386036 | $+0.006209 | $0.054056 | 14.0% | $0.2145 | $0.01838 |
| `test_v1_few-shot_independent` | $0.429938 | $0.245089 | $+0.184848 | $0.013304 | 5.4% | $0.1532 | $0.00377 |
| `test_v1_few-shot_pairs` | $0.701446 | $0.364263 | $+0.337183 | $0.024903 | 6.8% | $0.2024 | $0.02277 |
| `test_v1_context_independent` | $0.259777 | $0.259777 | $-0.000000 | $0.035287 | 13.6% | $0.1624 | $0.00419 |
| `test_v1_context_pairs` | $0.402474 | $0.391749 | $+0.010725 | $0.058773 | 15.0% | $0.2176 | $0.01781 |
| `test_v1_mimo_direct_independent` | $0.072601 | $0.072601 | $+0.000000 | $0.005613 | 7.7% | $0.0454 | $0.00140 |
| `test_v1_mimo_direct_pairs` | $0.114282 | $0.114282 | $+0.000000 | $0.011799 | 10.3% | $0.0635 | $0.00816 |
| `test_v1_mimo_few-shot_independent` | $0.093808 | $0.093808 | $+0.000000 | $0.003877 | 4.1% | $0.0586 | $0.00168 |
| `test_v1_mimo_few-shot_pairs` | $0.150298 | $0.150298 | $-0.000000 | $0.007032 | 4.7% | $0.0835 | $0.00884 |
| `test_v1_mimo_context_independent` | $0.074962 | $0.074962 | $-0.000000 | $0.005121 | 6.8% | $0.0469 | $0.00134 |
| `test_v1_mimo_context_pairs` | $0.117203 | $0.117203 | $-0.000000 | $0.008603 | 7.3% | $0.0651 | $0.00617 |

`$/correct`：独立检测的分母是 end-to-end strict correct（TP+TN），配对的分母是 all-pairs 的 joint correct（DA 的分子）。配对分母只有 14–22，所以这个数很不稳定，只作成本量级参考。

### 6.2 延迟（仅真实 API 调用）

| run_id | p50 (s) | p95 (s) | p99 (s) | max (s) | wall (s) | req/min | cache | retries | API attempts |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | 6.27 | 16.70 | 31.57 | 57.00 | 2404 | 7.19 | 105 | 0 | 288 |
| `test_v1_direct_pairs` | 6.16 | 19.34 | 34.89 | 62.58 | 4534 | 7.15 | 0 | 0 | 540 |
| `test_v1_few-shot_independent` | 6.05 | 18.63 | 31.89 | 57.48 | 2360 | 7.32 | 0 | 0 | 288 |
| `test_v1_few-shot_pairs` | 5.71 | 17.74 | 34.01 | 59.88 | 4069 | 7.96 | 0 | 0 | 540 |
| `test_v1_context_independent` | 6.60 | 19.72 | 47.63 | 62.50 | 2532 | 6.83 | 0 | 0 | 288 |
| `test_v1_context_pairs` | 6.13 | 20.18 | 35.68 | 77.78 | 4468 | 7.25 | 0 | 0 | 540 |
| `test_v1_mimo_direct_independent` | 6.76 | 37.30 | 81.33 | 192.50 | 3621 | 4.77 | 0 | 0 | 288 |
| `test_v1_mimo_direct_pairs` | 5.46 | 33.46 | 85.70 | 178.01 | 5529 | 5.86 | 0 | 0 | 540 |
| `test_v1_mimo_few-shot_independent` | 6.63 | 53.93 | 155.58 | 305.50 | 4584 | 3.77 | 0 | 2 | 290 |
| `test_v1_mimo_few-shot_pairs` | 5.35 | 40.93 | 105.74 | 218.80 | 6542 | 4.95 | 0 | 0 | 540 |
| `test_v1_mimo_context_independent` | 5.96 | 35.11 | 55.66 | 161.29 | 3132 | 5.52 | 0 | 0 | 288 |
| `test_v1_mimo_context_pairs` | 5.02 | 29.80 | 62.96 | 165.40 | 5077 | 6.38 | 0 | 0 | 540 |

延迟统计排除了 `cache.hit=true` 的重放记录；DeepSeek `direct_independent` 有 105 条这样的记录，其余 run 为 0。wall/req-min 受并发度影响（DeepSeek concurrency=8，MiMo concurrency=16），不能直接拿来比较吞吐；这里报告是为了交代运行背景。

### 6.3 模型总量与价格

| 模型 | requests | prompt tokens | completion tokens | reported $ | normalized $ | invalid requests | invalid $ | normalized $/M tokens |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | 2484 | 4,082,895 | 1,011,959 | $2.439219 | $1.898636 | 102 | $0.218280 | $0.3727 |
| MiMo | 2484 | 3,799,489 | 944,540 | $0.623154 | $0.623154 | 70 | $0.042045 | $0.1314 |

- 价格（USD / 1M tokens）：DeepSeek input 0.30 / output 1.20 / cached 0.006；MiMo input 0.14 / output 0.28 / cached 0.0028。DeepSeek/MiMo 单价比：input 0.30/0.14=2.14×、output 1.20/0.28=4.29×、cached 0.006/0.0028=2.14×。
- token 总量：DeepSeek 5,094,854，MiMo 4,744,029，DeepSeek/MiMo=1.074×。
- 成本比：reported 为 3.914×，cache-aware normalized 为 3.047×。DeepSeek reported 相对重算多报 $0.5406（28.5%）。
- invalid 成本：DeepSeek $0.2183（11.5%），MiMo $0.0420（6.7%）。两模型合计 invalid 成本 $0.2603，占合计 normalized 成本的 10.3%。

**解释**：DeepSeek 贵的主要原因是单价，不是更啰嗦——token 总量只高 7.4%，而 normalized 成本高 3.05×；有效 $/M tokens 为 $0.3727 vs $0.1314。reported 的 3.91× 里还混入了 cached-token 记账差异，所以不能直接用 reported 做模型效率比较。

## 7. 失败分析

### 7.1 MiMo 的 `is_vulnerability` 字段漂移

共 **61** 条，占 MiMo 检测请求的 3.91%（61/1,560）；按策略 direct 39 / few-shot 0 / context 22，按任务 independent 17 / pairs 44。键的形态：`is_vulnerability` 60 条、`is_vulnerative` 1 条；其中 1 条同时含 `is_vulnerable` 与 `is_vulnerability`，因“多一个键”被严格相等判 invalid。

| run_id | 漂移数 | 漏洞侧 | 修复侧 | 漏洞标签 | 非漏洞标签 | 输出 false | 输出 true | 错误键 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_mimo_direct_independent` | 10 | 0 | 0 | 8 | 2 | 9 | 1 | is_vulnerability |
| `test_v1_mimo_direct_pairs` | 29 | 16 | 13 | 16 | 13 | 28 | 1 | is_vulnerability |
| `test_v1_mimo_context_independent` | 7 | 0 | 0 | 5 | 2 | 5 | 2 | is_vulnerability |
| `test_v1_mimo_context_pairs` | 15 | 7 | 8 | 7 | 8 | 14 | 1 | is_vulnerability, is_vulnerative |

按标签/侧计算的发生率：independent 17/480（3.54%），其中漏洞 13/128（10.2%）、非漏洞 4/32（12.5%）；pairs 44/1,080（4.07%），其中漏洞侧 23/180（12.8%）、修复侧 21/180（11.7%）。**漂移没有明显偏向漏洞标签或某一侧**；它明显偏向策略：direct 39 条、context 22 条、few-shot 0 条。因此 valid-only 的标签分布不会被强烈扭曲，但 coverage 仍然是一个真实的部署成本。

漂移记录的 `finish_reason` 全部是 `stop`，content 长度 72–518 字符，延迟 2.0–9.5 s；它们不是截断，也不是网络错误，而是模型输出了**结构正确、键名错误**的 JSON。三种策略的 system prompt 相同，明确写了“exactly these keys”与 `is_vulnerable`；few-shot 另有 assistant 示例逐字展示该键。最一致的解释是 few-shot 示例锚定了 schema，而 direct/context 只依赖指令遵循；这是关联证据，不是因果证明。

| sample | project | 标签/侧 | 实际键 | 模型值 | content chars | 延迟 (s) |
| --- | --- | --- | --- | --- | --- | --- |
| `idx:22421` | Chrome | label=True, side=— | `is_vulnerability` | false | 268 | 4.65 |
| `idx:13806` | tensorflow | label=True, side=— | `is_vulnerability` | false | 74 | 3.36 |
| `idx:23559` | Chrome | label=True, side=— | `is_vulnerability` | false | 277 | 3.36 |
| `idx:7275` | FreeRDP | label=True, side=— | `is_vulnerability` | false | 74 | 2.74 |
| `idx:17502` | openoffice | label=False, side=— | `is_vulnerability` | false | 518 | 5.00 |
| `idx:10365` | zlib | label=True, side=— | `is_vulnerability` | false | 394 | 4.15 |

漂移恢复的 2×2 混淆（把 `is_vulnerability` 的布尔值当作预测）：

|  | 预测 true | 预测 false |
| --- | --- | --- |
| 标签 true（漏洞） | 4 | 32 |
| 标签 false（非漏洞） | 1 | 24 |

即：32 个假阴性、4 个真阳性、24 个真阴性、1 个假阳性。这解释了 tolerant 解析的方向：strict accuracy 会因 24 个真阴性变正确而上升；macro-F1 会因 32 个假阴性进入 valid-only 分母而承压，direct 甚至略降。所以 tolerant 值只能作为“格式损失”的诊断，不能当作正式能力估计。

### 7.2 截断：同样的 3 个超长函数，18/18 命中

截断共 **18** 条，DeepSeek 9 条、MiMo 9 条；每个策略 6 条（3 个样本 × 2 个模型）；**全部是 repair 请求**，`finish_reason=length`，content 21,876–29,837 字符。没有检测截断。

| sample | project | function chars | function lines | 命中 run 数 | content chars | 延迟范围 (s) |
| --- | --- | --- | --- | --- | --- | --- |
| `idx:7018` | clamav | 32,767 | 978 | 6 | 21,876–24,782 | 28.6–192.5 |
| `pair:8675:8676:vulnerable` | ImageMagick | 32,767 | 966 | 6 | 27,471–29,837 | 31.5–189.1 |
| `pair:9912:9913:vulnerable` | vim | 25,369 | 1011 | 6 | 22,420–24,363 | 39.7–218.8 |

三个样本是 `idx:7018`（clamav，978 行，32,767 字符，已到数据集字段上限）、`pair:9912:9913:vulnerable`（vim，1,011 行，25,369 字符）、`pair:8675:8676:vulnerable`（ImageMagick，966 行，32,767 字符）。它们在同一模型的所有三个策略、以及两个模型上都截断；这与**输入长度 + 8192 输出预算**一致；由于 3 个样本在所有模型/所有策略都截断，它不是某个模型的随机错误。DeepSeek 的截断 content 为 21.9–27.5k，MiMo 为 24.4–29.8k；MiMo 的截断延迟更高（最高 218.8 s vs DeepSeek 77.8 s），但这是服务端/输出长度混合的结果，不能单独归因于模型速度。

### 7.3 DeepSeek 的 `explanation` 缺失

共 **93** 条，占 DeepSeek 修复请求的 10.06%（93/924）；按策略 direct 45 / few-shot 0 / context 48，按任务 independent 37 / pairs 56。所有记录 `finish_reason=stop`，`fixed_function` 都存在；其中 91 条代码结构完整、75 条与输入不同、73 条两者兼具。

| run_id | 缺 explanation | fixed_function 存在 | recovered complete | recovered changed | recovered CAC | official CAC | code-only CAC |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `test_v1_direct_independent` | 18 | 18 | 17 | 13 | 12 | 65.6% | 75.0% |
| `test_v1_direct_pairs` | 27 | 27 | 27 | 23 | 23 | 68.9% | 81.7% |
| `test_v1_context_independent` | 19 | 19 | 18 | 17 | 16 | 66.4% | 78.9% |
| `test_v1_context_pairs` | 29 | 29 | 29 | 22 | 22 | 71.1% | 83.3% |

这不是截断：content 是合法 JSON，只是少了 `explanation` 键；system prompt 在三种策略中相同，要求恰好两个键，few-shot 的 assistant 修复示例逐字包含 `explanation`，direct/context 没有示例。93 条占 DeepSeek 全部 102 条 invalid 的 91.2%；DeepSeek 的 invalid 成本占总 normalized 成本 11.5%，按记录数看，这类缺失是 invalid 成本的主要来源。官方评分必须拒绝它们；但 code-only 反事实显示，代码本身大多完整，因此把 DeepSeek 的 official CAC 直接读成“修复内容更差”是不公平的（§5.3）。

### 7.4 其他失败与运行异常

- API error：两个模型 12 个 run 均为 0；HTTP 200；没有超时/重试耗尽。
- MiMo `few-shot_independent` 有 2 次重试（290 API attempts / 288 records），其余 run 为 0。
- DeepSeek `direct_independent` 有 105 条 cache hit；其余 run 为 0。缓存重放影响成本与延迟口径，见 §6。
- 没有发现其他 schema 错误类型：检测错误只有字段漂移（没有检测截断）；修复错误只有缺 explanation 或截断。

## 8. 模型比较与策略比较：两个轴怎么读

### 8.1 两个轴的定义

| 轴 | 固定 | 变化 | 配对键 | 聚类 | 回答的问题 | 不能回答的问题 |
| --- | --- | --- | --- | --- | --- | --- |
| 模型轴 | dataset + strategy | model | unit | project / pair | 同一提示策略下，MiMo 与 DeepSeek 的差异 | 哪个模型“整体更强”；不能把价格/格式/服务差异归因于权重 |
| 策略轴 | dataset + model | strategy | unit | project / pair | 同一模型下，direct/few-shot/context 是否改变行为 | 能否外推到另一个模型；不能把格式效应当成推理能力 |

模型轴是 **post-hoc**：`research/evaluation_protocol.md` 预注册的是“固定 DeepSeek、比较三种提示策略”；MiMo arm 是后来加的，所以模型轴没有预注册的主要终点，应按探索性结果读。策略轴是预注册的；DeepSeek 的策略轴数值与 `analysis/aggregation.json` 完全一致，可作为管线校验。

两个轴的估计量不同：模型轴是 `metric(DeepSeek, s) − metric(MiMo, s)`，策略轴是 `metric(m, s) − metric(m, direct)`。它们共享同一批单元，所以可以做配对 bootstrap，但不能把两个轴的差值相加，也不能用模型轴的“赢家”去替代策略轴的结论。12 个 run 是 2×3×2 的一个观测，每个格子只有一次运行；交互只能探索。

### 8.2 策略轴：检测与 DA

| 模型 | 对比 | Δmacro-F1 [95% CI] | Δstrict acc [95% CI] | Δcoverage [95% CI] | coverage p (Holm) | strict p (Holm) |
| --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | few-shot vs direct | +1.7 pp [-1.2, +5.8] | +1.9 pp [-1.4, +6.6] | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) | 0.5488 (1.0000) |
| DeepSeek | context vs direct | -0.1 pp [-3.6, +3.3] | +0.0 pp [-3.6, +3.9] | +0.0 pp [+0.0, +0.0] | 1.0000 (1.0000) | 1.0000 (1.0000) |
| MiMo | few-shot vs direct | -0.8 pp [-4.8, +1.7] | +2.5 pp [-1.0, +7.3] | +6.2 pp [+3.2, +12.5] | 0.0020 (0.0039) | 0.4240 (0.7754) |
| MiMo | context vs direct | +2.1 pp [-1.7, +8.9] | +2.5 pp [-1.6, +9.9] | +1.9 pp [-0.8, +5.8] | 0.5078 (0.5078) | 0.3877 (0.7754) |

| 模型 | 对比 | ΔDA all [95% CI] | DA p (Holm) |
| --- | --- | --- | --- |
| DeepSeek | few-shot vs direct | -2.8 pp [-6.7, +0.6] | 0.2266 (0.4531) |
| DeepSeek | context vs direct | +0.6 pp [-2.8, +3.9] | 1.0000 (1.0000) |
| MiMo | few-shot vs direct | +1.7 pp [-1.7, +5.0] | 0.5078 (0.5337) |
| MiMo | context vs direct | +2.8 pp [-1.1, +6.7] | 0.2668 (0.5337) |

**DeepSeek 的策略轴**：macro-F1、strict accuracy、DA 的差值都很小，所有区间跨 0，与 `aggregation.json` 的结论一致；few-shot 的 DA 反而低 2.8 pp（p=0.227），context 基本持平。也就是说，在 DeepSeek 上，提示策略主要没有改变检测/配对能力。

**MiMo 的策略轴**：macro-F1/DA 的差值同样都不显著；但 few-shot 把检测 coverage 从 93.75% 提到 100%（+6.25 pp，Holm=0.0039），并消除了 61 条字段漂移。context 的 coverage 只提升 +1.9 pp（p=0.508，不显著），只减少了一部分漂移（direct 10 条 → context 7 条）。因此 MiMo 的策略效应主要是**格式合规**，不是检测准确率。

### 8.3 策略轴：修复行为

| 模型 | 任务 | CAC direct | CAC few-shot | CAC context | schema direct | schema few-shot | schema context |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek | independent | 65.6% | 57.0% | 66.4% | 85.2% | 99.2% | 84.4% |
| DeepSeek | pairs | 68.9% | 64.4% | 71.1% | 83.9% | 98.9% | 82.8% |
| MiMo | independent | 70.3% | 44.5% | 75.8% | 99.2% | 99.2% | 99.2% |
| MiMo | pairs | 77.8% | 51.1% | 79.4% | 98.9% | 98.9% | 98.9% |

MiMo 的 few-shot 是“schema 保持 99%、改动最少”的组合：schema 99%，但 CAC 从 direct 的 70.3%/77.8% 降到 44.5%/51.1%；DeepSeek 也下降（65.6%/68.9% → 57.0%/64.4%），但幅度小得多。few-shot 的 assistant 示例会把输出锚定成完整函数，也可能让模型更倾向于“复述输入”。这再次说明：schema 合规 ≠ 修复内容更好；changed 只是结构代理。

### 8.4 交互（探索性）

DiD 定义为 `(MiMo_s − MiMo_direct) − (DeepSeek_s − DeepSeek_direct)`；正数表示 MiMo 在策略 s 下相对 direct 的增益更大（或损失更小）。所有区间都跨 0，因此没有稳健证据表明模型排名随策略改变。

| 任务 | 终点 | 对比 | DiD [95% CI] | cohort |
| --- | --- | --- | --- | --- |
| independent | strict_accuracy | few-shot vs direct | +0.6 pp [-5.8, +6.1] | 160 |
| independent | strict_accuracy | context vs direct | +2.5 pp [-3.5, +10.8] | 160 |
| pairs | da_all | few-shot vs direct | +4.4 pp [-0.6, +9.4] | 180 |
| pairs | da_all | context vs direct | +2.2 pp [-2.8, +7.2] | 180 |
| independent | macro_f1 | few-shot vs direct | -2.7 pp [-10.3, +1.6] | 147 |
| independent | macro_f1 | context vs direct | +2.2 pp [-3.5, +10.5] | 147 |

最接近边界的是 pairs 的 few-shot DA DiD：+4.4 pp [−0.6, +9.4]，方向上表示“few-shot 下 DeepSeek 的 DA 优势变成 MiMo 的微弱优势”；但下界跨 0，而且 direct 的 DA 差距本身主要由 invalid pair 驱动，所以只能标为探索性。macro-F1 的 DiD 使用六个 independent run 都为 valid 的 147 条共同 cohort，与 §3 的逐策略 cohort 不同，不能把它的点估计和 §3 的 Δmacro-F1 直接相减。

**两个轴的合读**：

- 模型轴：DeepSeek 在检测 macro-F1 上有小幅优势（few-shot 名义显著），但覆盖率优势是稳健的；配对 DA 没有稳健差异；修复排名被 schema 口径主导。
- 策略轴：DeepSeek 的策略几乎不改变检测/DA；MiMo 的 few-shot 消除格式失败，但让修复更保守。
- 因此，**不能写“MiMo 不如 DeepSeek”或“DeepSeek 更好”作为总体结论**；能写的是“在 direct/context 检测上，MiMo 的 end-to-end 损失主要来自字段漂移；在 few-shot 检测上，DeepSeek 的 macro-F1 略高但 McNemar 未通过 Holm；在配对 DA 上没有稳健差异；在 direct/context 修复上，schema 口径决定排名；在 few-shot 修复上，DeepSeek 的 changed 率更高，但那只是结构代理”。

## 9. 限制

1. **单次运行、单快照。** 每个 (model, strategy, dataset) 只有一个 run；temperature=0，但没有多 seed、多服务副本或重复调用。所有区间反映单元/项目抽样，不反映 API 服务端非确定性。模型版本可能随供应商更新，复现时必须锁定 run 目录与配置指纹。
2. **模型轴是 post-hoc。** 原协议预注册的是固定 DeepSeek 的策略比较；MiMo arm 是后加的，没有预注册的模型主要终点。模型轴的 p 值/区间应按探索性结果读，不能当成确证性检验。
3. **比较的是部署端点，不是纯权重。** 两端都走 OpenCode Go，但 MiMo 使用 `max_completion_tokens` + `reasoning_effort=none`，DeepSeek 使用 `max_tokens` + 非思考路径；tokenizer、chat template、服务端路由/限流可能不同。不能把全部差异归因于模型权重。
4. **成本记账不完全对称。** DeepSeek 的 `response.cost` 未扣 cached token；本文件的 normalized 成本是从 usage 重算的，不是账单核对结果。official 仍以 run 记录值为准；两种口径都报，避免把记账差异误读为模型效率差异。
5. **缓存/重试影响口径。** DeepSeek `direct_independent` 有 105 条 cache hit，MiMo `few-shot_independent` 有 2 次重试；延迟统计已排除 cache 重放，但成本/延迟仍受运行历史影响。
6. **修复结构只是代理。** `complete_function`（括号/函数形似）与 `changed_from_input`（规范化文本不等）不证明漏洞被消除、行为保持、代码可编译或通过测试。没有编译、测试、PoC；MiMo 没有人工/LLM 修复评审。`exact_match_reference_fixed` 是文本相似度，不是正确率。
7. **检测集不平衡。** 128 漏洞 + 32 非漏洞；specificity 与 MCC 的区间很宽，macro-F1 对少量负例预测敏感。不能只报 accuracy；本文件同时报 P/R/F1/BA/MCC/macro-F1/coverage。
8. **配对任务不是联合推理。** 每对仍是两次独立的单函数分类，prompt 不含另一侧；DA 低是任务实现的结果，不应解释为“模型不会配对推理”。56.1% 是位置先验基线，不是配对能力的机会水平。本文件没有做 position bias 分析。
9. **聚类与检验假设。** 独立检测按 40 个项目做 cluster bootstrap；配对按 180 个 pair 重采样，不是 60 个项目。McNemar 假设单元独立；同项目相关可能让 p 偏小。Holm 只在 dataset×endpoint family 内校正，没有跨全部 12 个 run 做全局校正。主推断看 bootstrap 区间，McNemar 是次要证据。
10. **没有分层分析。** CWE family、context 非空/空、函数长度、项目类型、position bias 都不在本文件；这些在 `analysis/aggregation.*` 或其他专项文件中。不能把本文件的总体差异归因于某一层。
11. **容忍解析/反事实是诊断。** MiMo 的 tolerant 解析和 DeepSeek 的 code-only 反事实都是 post-hoc，不是 official 分数；它们用于量化“格式门槛”，不能替代预注册的 schema 评分。
12. **外部效度。** 只有一个冻结测试集、一个时间点、两个模型版本；不能外推到其他数据集、语言、CWE 分布或未来模型版本。

## 10. 复现与审计

### 10.1 输入与方法

- **输入**：`runner/runs/` 下 12 个目录（§1.1）。每个目录的 `metrics.json` 提供 run 元数据、confusion、pair_joint、repair、cost、latency；`results.jsonl` 提供逐记录 `status`、`parsed`、`validation`、`response.usage`、`response.cost`、`response.response_meta`。
- **指标库**：`analysis/stats.py` 的 `detection_scores`、`pair_scores`、`mcnemar_exact`、`holm_adjust`、`cluster_bootstrap`；只使用标准库。
- **bootstrap**：10,000 次，seed 42，95% percentile，线性插值；独立检测 cluster=project（40），配对 cluster=pair（180）；同一重采样同时计算两个模型/策略，差值区间是配对的。
- **McNemar**：精确双侧，用于二值正确性/覆盖率/schema/CAC；主分析全部单元（invalid 计错），修复的 changed 另在 both-schema-valid cohort 上做次要检验；效应量报 discordant b/c、risk difference、odds ratio（c=0 时为 n/a）。
- **Holm**：模型轴每个 dataset×endpoint 有 3 个策略比较；策略轴每个 model×dataset×endpoint 有 2 个（few-shot/context vs direct）；修复轴同样按 dataset×endpoint 分组。
- **成本**：`normalized = (prompt−cached)×input + cached×cached_input + completion×output`，价格取每个 run 的 `metrics.cost` 字段；`reported` 取 `metrics.cost.total_cost_usd`。
- **容忍解析**：仅对 `invalid_category=field_drift` 的记录，把 `is_vulnerability`/`is_vulnerative` 的布尔值映射为 `is_vulnerable`；截断不恢复。
- **code-only 反事实**：仅对 `missing_explanation` 的 DeepSeek 修复记录，取 `fixed_function`，用 `secvul_runner.validation.analyze_repair` 重跑结构检查；official 指标不变。

### 10.2 最小核对片段（WSL）

以下片段只核对一个 run 的检测 macro-F1；完整 12-run 结果在 JSON 中逐项可查。

```bash
# 在 WSL 中执行：
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 - <<'PY'
import json, sys
sys.path.insert(0, "analysis")
import stats as S
run = "runner/runs/test_v1_direct_independent"
m = json.load(open(run + "/metrics.json"))
recs = [json.loads(line) for line in open(run + "/results.jsonl")]
det = sorted((r for r in recs if r["task"] == "detection"), key=lambda r: r["idx"])
labels = [bool(r["label"]) for r in det]
preds = [
    r["parsed"]["is_vulnerable"]
    if r["status"] == "ok" and isinstance((r.get("parsed") or {}).get("is_vulnerable"), bool)
    else None
    for r in det
]
scores = S.detection_scores(labels, preds)
print(scores["macro_f1"], scores["mcc"], scores["coverage"], scores["strict_accuracy"])
print(m["detection"]["metrics_valid_only"]["f1"])  # 正类 F1，不是 macro-F1
PY
```

### 10.3 复现命令与脚本位置

完整分析在 WSL Python 3.14.8 下执行，命令形态：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && python3 <analysis-script>'
```

**限制**：本任务的范围只允许写 `analysis/model_comparison.json` 与 `analysis/model_comparison.md`，所以分析脚本没有作为第三个仓库文件提交；它是一次性 WSL 脚本，运行后只落这两个产物。为了可审计，JSON 保留了每个 run 的点估计、bootstrap 区间、McNemar 的 b/c、Holm 调整值、失败记录的 sample_id/键/值/延迟/字符数，以及成本分解；MD 记录了全部固定参数与算法。如果要把分析变成仓库内可一键复现的工具，应新增一个 `analysis/compare_models.py`（不在本任务范围）。

### 10.4 产物路径

- `analysis/model_comparison.json`：机器可读；顶层含 `scope`、`design`、`inputs`、`integrity`、`detection_independent`、`detection_pairs`、`repair`、`cost_latency`、`failures`、`interaction`、`warnings`、`limitations`、`reproduction`。
- `analysis/model_comparison.md`：本文件。
- 未修改 `analysis/aggregation.json`、`analysis/aggregation.md`、`runner/runs/` 或任何旧结果。

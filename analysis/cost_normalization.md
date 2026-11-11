# 成本口径归一化：provider list vs configured

生成时间：2026-11-11T21:08:05Z（UTC） / 2026-11-12 05:08:05 CST（Asia/Shanghai）

范围：73 个有真实 usage 的 run、9,584 次请求；其中 71 个完整 run、2 个未完成 run 单列；另有 6 个无 usage 的失败/空跑目录。脚本只读取已保存的 `results.jsonl` / `requests.jsonl` 和 manifest/config，不修改原始响应，不调用 API。

## 结论

- **审计 I5 的 2× 是峰谷价差，不是 allowance 折扣。** DeepSeek 的 configured `0.30/1.20/0.006` 是**高峰**价；provider 返回的 `usage.opencode.list_cost` 是**非高峰**价 `0.15/0.60/0.003`。本批全部请求都落在非高峰窗口，因此 cache 口径一致的 v1 run 上 provider 快照恰好是 configured 的 0.5×；legacy 记录值不扣 cache，见 §5。
- **归一化口径**：DeepSeek `0.15/0.60/0.003`，MiMo `0.14/0.28/0.0028`，按每条 usage 的未缓存输入 / 缓存命中 / 输出 token 重算，不使用 token 估算，也不改原始 `cost_usd`。
- **allowance 独立**：DeepSeek 的 `usage.opencode.allowance` 观测为 list cost 的 0.600×，MiMo 为 1.000×；它是 provider 侧的额度扣减，不是 USD 账单，既没有从 list cost 扣除，也没有加到 configured cost。
- **总量**（71 个完整 run）：configured **$3.886970**，normalized provider-list **$2.146513**；其中 headline run 的 configured 为 $0.558073，normalized 为 $0.365704。若把 2 个未完成 run 也计入，all-recorded 为 configured $3.895167 / normalized $2.154710。

## 1. 价格口径

| 模型 | 计费项 | 高峰价 | 非高峰价 | 本报告使用的 normalized 价 |
| --- | --- | ---: | ---: | ---: |
| DeepSeek | 输入，缓存未命中 | 0.30 | 0.15 | 0.15 |
| DeepSeek | 输入，缓存命中 | 0.006 | 0.003 | 0.003 |
| DeepSeek | 输出 | 1.20 | 0.60 | 0.60 |
| MiMo | 输入，缓存未命中 | — | 0.14 | 0.14 |
| MiMo | 输入，缓存命中 | — | 0.0028 | 0.0028 |
| MiMo | 输出 | — | 0.28 | 0.28 |

单位：USD / 1M tokens。DeepSeek 峰谷规则来自 `research/evaluation_protocol.md` §6.2：
高峰为 UTC 周一至周五 01:00–04:00 与 06:00–10:00（排除中国法定节假日），其余为非高峰。
MiMo 没有峰谷价，按 published flat price。价格快照日期为 2026-11-11；token 数逐 run 保留，便于按新价重算。

## 2. 峰谷与日期核验

- 有 usage 的 9,584 条请求全部能解析 UTC 时间；时间范围为 **2026-11-11T11:12:13.447000+00:00 至 2026-11-11T20:58:21.952000+00:00**，均为 2026-11-11 星期三（UTC）。
- 按上述峰谷规则逐条判定：**peak rows = 0**；因此本批 DeepSeek 全部适用非高峰价 0.15/0.60/0.003。
- 北京时间（UTC+8）对应 2026-11-11 19:12 至 2026-11-12 04:58；峰谷判定以 UTC 为准，不以北京时间为准。
- 逐请求比较 `usage.opencode.list_cost` 与按非高峰价重算的值：9,007 条可比请求，最大单条相对偏差 3.79e-04；说明 provider 快照本身就是非高峰 flat rate，不是额外的折扣或 allowance 抵扣。

## 3. 分组汇总

| 组 | runs | complete | 有 usage | 调用 | configured $ | normalized $ | provider list $ | allowance $ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| headline | 17 | 17 | 17 | 2362 | 0.558073 | 0.365704 | 0.361279 | 0.284329 |
| rerun_fix | 12 | 12 | 12 | 1680 | 0.088597 | 0.088597 | 0.082335 | 0.059878 |
| replicate | 1 | 1 | 1 | 140 | 0.011553 | 0.011553 | n/a | n/a |
| legacy_test | 12 | 12 | 12 | 4968 | 3.062374 | 1.572472 | 1.572472 | 1.192748 |
| pilot | 27 | 27 | 27 | 374 | 0.165868 | 0.107681 | 0.107145 | 0.088010 |
| probe | 2 | 2 | 2 | 8 | 0.000506 | 0.000506 | n/a | n/a |
| all_complete_with_usage | 71 | 71 | 71 | 9532 | 3.886970 | 2.146513 | 2.123231 | 1.624966 |
| incomplete | 2 | 0 | 2 | 52 | 0.008197 | 0.008197 | 0.008197 | 0.008197 |
| all_with_usage | 73 | 71 | 73 | 9584 | 3.895167 | 2.154710 | 2.131427 | 1.633163 |
| failed_no_usage | 6 | 0 | 0 | 0 | n/a | n/a | n/a | n/a |

读法：`configured` 是原始 run 记录的成本；`normalized` 是按 provider list 价重算的值；
`provider list` 是 `usage.opencode.list_cost` 的逐请求求和；`allowance` 是独立的 provider 额度扣减。
`complete` 列只统计 manifest 完成且记录数达到 expected 的 run；`incomplete` 单列，不混入任何 complete-only 合计。
`provider list` / `allowance` 只覆盖 OpenCode 端点；Xiaomi 端点（`juliet_llm`）不返回这两个字段，因此按 n/a 处理，不补零。
`failed_no_usage` 没有 usage，成本列不补零，显示 n/a。
组之间可能重叠（例如 repair 的 parser_dev 同时属于 `pilot` 和 `juliet_repair` 类别）；`all_complete_with_usage` 是按 run 去重的合计，不重复计数。

### 3.1 按实验

| 组 | runs | complete | 有 usage | 调用 | configured $ | normalized $ | provider list $ | allowance $ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| hybrid | 20 | 20 | 20 | 2800 | 0.256200 | 0.196933 | 0.196933 | 0.150769 |
| pair_joint | 4 | 4 | 4 | 376 | 0.239022 | 0.157554 | 0.157554 | 0.124967 |
| juliet_repair | 7 | 6 | 7 | 355 | 0.082550 | 0.052549 | 0.052549 | 0.040550 |
| evidence_prompt | 4 | 4 | 4 | 328 | 0.125001 | 0.080938 | 0.080938 | 0.063312 |
| juliet_llm | 11 | 8 | 8 | 577 | 0.023283 | 0.023283 | n/a | n/a |
| runner | 33 | 29 | 30 | 5148 | 3.169112 | 1.643453 | 1.643453 | 1.253566 |

按实验类别包含该目录下所有 run（含 pilot / smoke / rerun）；headline 只取 §4 的 17 个主实验 run。
`hybrid` 类别含 10 个 v1 + 10 个 v2；`juliet_llm` 含 final / replicate / postleakfix / smoke，因此类别合计高于 headline。
### 3.2 按模型

| 组 | runs | complete | 有 usage | 调用 | configured $ | normalized $ | provider list $ | allowance $ |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deepseek | 34 | 30 | 30 | 4452 | 2.986119 | 1.245662 | 1.245662 | 0.747398 |
| mimo | 45 | 41 | 43 | 5132 | 0.909048 | 0.909048 | 0.885765 | 0.885765 |

DeepSeek 的 normalized 明显低于 configured：v1 新实验（hybrid / pair / repair / evidence）是峰/谷价卡的 2× 关系；v2 rerun 已直接配置 0.15/0.60/0.003，ratio 为 1.0；legacy runner 还叠加了“记录值不扣 cache”的因素，所以 ratio 小于 0.5，详见 §5。MiMo 的 configured 与 normalized 相同（0.14/0.28/0.0028）。

## 4. 主实验 run

| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `test_evidence_deepseek` | deepseek | 160 | 0.085622 | 0.042811 | 0.042811 | 0.025686 | 0.500 | 11-11 19:15 |
| `test_evidence_mimo` | mimo | 160 | 0.035933 | 0.035933 | 0.035932 | 0.035932 | 1.000 | 11-11 19:17 |
| `hybrid_v1_deepseek_combined` | deepseek | 140 | 0.029260 | 0.014630 | 0.014630 | 0.008778 | 0.500 | 11-11 19:24 |
| `hybrid_v1_deepseek_direct` | deepseek | 140 | 0.020570 | 0.010285 | 0.010285 | 0.006171 | 0.500 | 11-11 19:21 |
| `hybrid_v1_deepseek_dynamic` | deepseek | 140 | 0.022894 | 0.011447 | 0.011447 | 0.006868 | 0.500 | 11-11 19:23 |
| `hybrid_v1_deepseek_shuffled` | deepseek | 140 | 0.022316 | 0.011158 | 0.011158 | 0.006695 | 0.500 | 11-11 19:25 |
| `hybrid_v1_deepseek_static` | deepseek | 140 | 0.023492 | 0.011746 | 0.011746 | 0.007048 | 0.500 | 11-11 19:22 |
| `hybrid_v1_mimo_combined` | mimo | 140 | 0.011963 | 0.011963 | 0.011963 | 0.011963 | 1.000 | 11-11 19:29 |
| `hybrid_v1_mimo_direct` | mimo | 140 | 0.006470 | 0.006470 | 0.006470 | 0.006470 | 1.000 | 11-11 19:26 |
| `hybrid_v1_mimo_dynamic` | mimo | 140 | 0.013544 | 0.013544 | 0.013544 | 0.013544 | 1.000 | 11-11 19:28 |
| `hybrid_v1_mimo_shuffled` | mimo | 140 | 0.009256 | 0.009256 | 0.009256 | 0.009256 | 1.000 | 11-11 19:30 |
| `hybrid_v1_mimo_static` | mimo | 140 | 0.014098 | 0.014098 | 0.014099 | 0.014099 | 1.000 | 11-11 19:27 |
| `20261111T192747Z_test_mimo-v2.6-flash_test_xiaomi_official_final` | mimo | 140 | 0.004426 | 0.004426 | n/a | n/a | 1.000 | 11-11 19:27 |
| `deepseek_test70_final` | deepseek | 70 | 0.026990 | 0.013495 | 0.013495 | 0.008097 | 0.500 | 11-11 19:29 |
| `mimo_test70_final` | mimo | 72 | 0.005841 | 0.005841 | 0.005841 | 0.005841 | 1.000 | 11-11 19:29 |
| `test_deepseek_180` | deepseek | 180 | 0.153593 | 0.076797 | 0.076797 | 0.046078 | 0.500 | 11-11 19:18 |
| `test_mimo_180` | mimo | 180 | 0.071803 | 0.071803 | 0.071803 | 0.071803 | 1.000 | 11-11 19:20 |

## 4.1 重跑 / 复现 / replicate run

| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `hybrid_v2_deepseek_combined` | deepseek | 140 | 0.011891 | 0.011891 | 0.011891 | 0.007134 | 1.000 | 11-11 20:50 |
| `hybrid_v2_deepseek_direct` | deepseek | 140 | 0.010185 | 0.010185 | 0.010185 | 0.006111 | 1.000 | 11-11 20:49 |
| `hybrid_v2_deepseek_dynamic` | deepseek | 140 | 0.011471 | 0.011471 | 0.011471 | 0.006883 | 1.000 | 11-11 20:50 |
| `hybrid_v2_deepseek_shuffled` | deepseek | 140 | 0.010860 | 0.010860 | 0.010860 | 0.006516 | 1.000 | 11-11 20:50 |
| `hybrid_v2_deepseek_static` | deepseek | 140 | 0.011730 | 0.011730 | 0.011730 | 0.007038 | 1.000 | 11-11 20:49 |
| `hybrid_v2_mimo_combined` | mimo | 140 | 0.004813 | 0.004813 | 0.004813 | 0.004813 | 1.000 | 11-11 20:53 |
| `hybrid_v2_mimo_direct` | mimo | 140 | 0.004718 | 0.004718 | 0.004718 | 0.004718 | 1.000 | 11-11 20:51 |
| `hybrid_v2_mimo_dynamic` | mimo | 140 | 0.005735 | 0.005735 | 0.005735 | 0.005735 | 1.000 | 11-11 20:52 |
| `hybrid_v2_mimo_shuffled` | mimo | 140 | 0.004645 | 0.004645 | 0.004645 | 0.004645 | 1.000 | 11-11 20:54 |
| `hybrid_v2_mimo_static` | mimo | 140 | 0.006287 | 0.006287 | 0.006287 | 0.006287 | 1.000 | 11-11 20:51 |
| `20261111T192252Z_test_mimo-v2.6-flash_test_xiaomi_official` | mimo | 140 | 0.011553 | 0.011553 | n/a | n/a | 1.000 | 11-11 19:22 |
| `20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix` | mimo | 140 | 0.003180 | 0.003180 | n/a | n/a | 1.000 | 11-11 20:55 |
| `20261111T205722Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix_repro` | mimo | 140 | 0.003081 | 0.003081 | n/a | n/a | 1.000 | 11-11 20:57 |

`postleakfix` / `_repro` / `hybrid_v2_*` 是其他修复项在本报告生成前后产生的重跑；它们按各自 run 的价格卡归一化，单列而不并入 headline，避免把修复前后的 run 混为一个分母。其中 `hybrid_v2_*` 已直接配置为 0.15/0.60/0.003，因此 configured 与 normalized 相同。

## 5. Legacy runner test_v1

| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `test_v1_context_independent` | deepseek | 288 | 0.259777 | 0.129888 | 0.129888 | 0.077933 | 0.500 | 11-11 11:49 |
| `test_v1_context_pairs` | deepseek | 540 | 0.402474 | 0.195875 | 0.195875 | 0.117525 | 0.487 | 11-11 11:54 |
| `test_v1_direct_independent` | deepseek | 288 | 0.253340 | 0.125861 | 0.125861 | 0.075516 | 0.497 | 11-11 11:16 |
| `test_v1_direct_pairs` | deepseek | 540 | 0.392245 | 0.193018 | 0.193018 | 0.115811 | 0.492 | 11-11 11:24 |
| `test_v1_few-shot_independent` | deepseek | 288 | 0.429938 | 0.122545 | 0.122544 | 0.073528 | 0.285 | 11-11 11:34 |
| `test_v1_few-shot_pairs` | deepseek | 540 | 0.701446 | 0.182131 | 0.182131 | 0.109281 | 0.260 | 11-11 11:39 |
| `test_v1_mimo_context_independent` | mimo | 288 | 0.074962 | 0.074962 | 0.074962 | 0.074962 | 1.000 | 11-11 18:50 |
| `test_v1_mimo_context_pairs` | mimo | 540 | 0.117203 | 0.117203 | 0.117204 | 0.117204 | 1.000 | 11-11 18:54 |
| `test_v1_mimo_direct_independent` | mimo | 288 | 0.072601 | 0.072601 | 0.072601 | 0.072601 | 1.000 | 11-11 18:20 |
| `test_v1_mimo_direct_pairs` | mimo | 540 | 0.114282 | 0.114282 | 0.114283 | 0.114283 | 1.000 | 11-11 18:27 |
| `test_v1_mimo_few-shot_independent` | mimo | 288 | 0.093808 | 0.093808 | 0.093808 | 0.093808 | 1.000 | 11-11 18:33 |
| `test_v1_mimo_few-shot_pairs` | mimo | 540 | 0.150298 | 0.150298 | 0.150298 | 0.150298 | 1.000 | 11-11 18:40 |

Legacy runner 的 `response.cost.cost_usd` 对 DeepSeek 采用**不扣缓存**的算法：`prompt_tokens × input_price + completion_tokens × output_price`。因此 `configured` 与 `configured_cache_aware` 不同；normalized 仍按 provider 的未缓存/缓存命中/输出拆分重算。两者不是同一口径，不能直接用 configured 除以 2。
- 例：`test_v1_few-shot_pairs` configured $0.701446，按同一 configured 价卡做 cache-aware 重算为 $0.364263，provider-list normalized 为 $0.182131。

## 6. Pilot / smoke / probe

| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `smoke_dev_evidence_deepseek` | deepseek | 4 | 0.002505 | 0.001253 | 0.001253 | 0.000752 | 0.500 | 11-11 19:14 |
| `smoke_dev_evidence_mimo` | mimo | 4 | 0.000941 | 0.000941 | 0.000941 | 0.000941 | 1.000 | 11-11 19:14 |
| `20261111T192121Z_smoke_mimo-v2.6-flash_dev_xiaomi_smoke` | mimo | 1 | 0.000103 | 0.000103 | n/a | n/a | 1.000 | 11-11 19:21 |
| `mimo_legacy_max_tokens` | mimo | 4 | 0.000084 | 0.000084 | n/a | n/a | 1.000 | 11-11 19:22 |
| `mimo_reasoning_none_max_completion_tokens` | mimo | 4 | 0.000423 | 0.000423 | n/a | n/a | 1.000 | 11-11 19:22 |
| `20261111T192557Z_pilot_mimo-v2.6-flash_dev_xiaomi_official` | mimo | 8 | 0.000433 | 0.000433 | n/a | n/a | 1.000 | 11-11 19:26 |
| `deepseek_test70_v1` | deepseek | 81 | 0.032690 | 0.016345 | 0.016345 | 0.009807 | 0.500 | 11-11 19:20 |
| `mimo_test70_v2` | mimo | 86 | 0.011578 | 0.011578 | 0.011578 | 0.011578 | 1.000 | 11-11 19:21 |
| `smoke_deepseek_u0001` | deepseek | 1 | 0.000321 | 0.000160 | 0.000160 | 0.000096 | 0.500 | 11-11 19:19 |
| `smoke_mimo_u0001` | mimo | 1 | 0.000096 | 0.000096 | 0.000096 | 0.000096 | 1.000 | 11-11 19:19 |
| `pilot_deepseek_8` | deepseek | 8 | 0.009343 | 0.004672 | 0.004672 | 0.002803 | 0.500 | 11-11 19:17 |
| `pilot_mimo_8` | mimo | 8 | 0.004282 | 0.004282 | 0.004282 | 0.004282 | 1.000 | 11-11 19:17 |
| `dev_pilot_context_independent` | deepseek | 12 | 0.008399 | 0.004200 | 0.004200 | 0.002520 | 0.500 | 11-11 11:15 |
| `dev_pilot_context_pairs` | deepseek | 9 | 0.007828 | 0.003876 | 0.003876 | 0.002326 | 0.495 | 11-11 11:16 |
| `dev_pilot_direct_independent` | deepseek | 12 | 0.008165 | 0.004082 | 0.004082 | 0.002449 | 0.500 | 11-11 11:13 |
| `dev_pilot_direct_pairs` | deepseek | 9 | 0.007627 | 0.003813 | 0.003813 | 0.002288 | 0.500 | 11-11 11:13 |
| `dev_pilot_few-shot_independent` | deepseek | 12 | 0.015939 | 0.004959 | 0.004959 | 0.002975 | 0.311 | 11-11 11:14 |
| `dev_pilot_few-shot_pairs` | deepseek | 9 | 0.012907 | 0.004327 | 0.004327 | 0.002596 | 0.335 | 11-11 11:15 |
| `pilot_direct_detection_nothink_1` | deepseek | 1 | 0.000301 | 0.000151 | 0.000151 | 0.000090 | 0.500 | 11-11 11:12 |
| `pilot_v1_mimo_attempt2_reasoning_context_independent` | mimo | 12 | 0.010146 | 0.010146 | 0.010146 | 0.010146 | 1.000 | 11-11 17:54 |
| `pilot_v1_mimo_attempt2_reasoning_direct_independent` | mimo | 12 | 0.006813 | 0.006813 | 0.006813 | 0.006813 | 1.000 | 11-11 17:43 |
| `pilot_v1_mimo_attempt2_reasoning_few-shot_independent` | mimo | 12 | 0.007928 | 0.007928 | 0.007928 | 0.007928 | 1.000 | 11-11 17:51 |
| `pilot_v1_mimo_attempt2_reasoning_few-shot_pairs` | mimo | 9 | 0.007376 | 0.007376 | 0.007376 | 0.007376 | 1.000 | 11-11 17:52 |
| `pilot_v1_mimo_context_independent` | mimo | 12 | 0.001730 | 0.001730 | 0.001730 | 0.001730 | 1.000 | 11-11 18:16 |
| `pilot_v1_mimo_context_pairs` | mimo | 9 | 0.002085 | 0.002085 | 0.002085 | 0.002085 | 1.000 | 11-11 18:17 |
| `pilot_v1_mimo_direct_independent` | mimo | 12 | 0.001443 | 0.001443 | 0.001443 | 0.001443 | 1.000 | 11-11 18:14 |
| `pilot_v1_mimo_direct_pairs` | mimo | 9 | 0.001542 | 0.001542 | 0.001542 | 0.001542 | 1.000 | 11-11 18:14 |
| `pilot_v1_mimo_few-shot_independent` | mimo | 12 | 0.001789 | 0.001789 | 0.001789 | 0.001789 | 1.000 | 11-11 18:15 |
| `pilot_v1_mimo_few-shot_pairs` | mimo | 9 | 0.001559 | 0.001559 | 0.001559 | 0.001559 | 1.000 | 11-11 18:16 |

## 7. 未完成 run（单列，不并入 complete-only 合计）

| Run | 类别 | 预期 | 已记录 | configured $ | normalized $ | 说明 |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `mimo_test70_v1` | pilot | 70 | 44 | 0.005034 | 0.005034 | 少于 expected 或 manifest 未完成；成本只覆盖已记录的真实 usage，不代表完整 run。 |
| `pilot_v1_mimo_attempt2_reasoning_direct_pairs` | pilot | 9 | 8 | 0.003163 | 0.003163 | 少于 expected 或 manifest 未完成；成本只覆盖已记录的真实 usage，不代表完整 run。 |

## 8. 无 usage 的失败 / 空跑

| Run | 类别 | 状态 | 说明 |
| --- | --- | --- | --- |
| `20261111T191954Z_smoke_deepseek-v4.1-flash_dev_smoke` | juliet_llm | error×1 | 无 usage，未计入任何成本合计。 |
| `20261111T192149Z_smoke_deepseek-flash_dev_deepseek_official_smoke` | juliet_llm | error×1 | 无 usage，未计入任何成本合计。 |
| `20261111T192505Z_smoke_deepseek-v4.1-flash_dev_qwen_gateway_smoke` | juliet_llm | error×1 | 无 usage，未计入任何成本合计。 |
| `pilot_direct_detection_1` | runner | error×1 | 无 usage，未计入任何成本合计。 |
| `pilot_v1_mimo_attempt1_direct_independent_stuck` | runner | n/a×12 | 无 usage，未计入任何成本合计。 |
| `pilot_v1_mimo_attempt2_reasoning_context_pairs_interrupted` | runner | n/a×9 | 无 usage，未计入任何成本合计。 |

## 9. juliet_repair all-in 修正

- headline 两个 final run：configured **$0.032831**，normalized **$0.019336**；headline 指标与 README 表格不变。
- 全部 repair run（含 parser_dev 与 smoke）：configured **$0.082550**，normalized **$0.052549**。
- README 的 all-in 由 **$0.077516** 修正为 **$0.082550**（delta $0.005034，来自 `parser_dev/mimo_test70_v1` 的 $0.005034）。headline `$0.032831` 不变。
- `parser_dev/mimo_test70_v1` 是 44/70 的解析器开发 run；$0.005034 是真实已发生成本，所以计入 all-in，但它不代表完整 70 单元，也不进入 headline。

| Run | 模型 | 调用 | configured $ | normalized $ | provider list $ | allowance $ | norm/conf | UTC 开始 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `deepseek_test70_final` | deepseek | 70 | 0.026990 | 0.013495 | 0.013495 | 0.008097 | 0.500 | 11-11 19:29 |
| `mimo_test70_final` | mimo | 72 | 0.005841 | 0.005841 | 0.005841 | 0.005841 | 1.000 | 11-11 19:29 |
| `deepseek_test70_v1` | deepseek | 81 | 0.032690 | 0.016345 | 0.016345 | 0.009807 | 0.500 | 11-11 19:20 |
| `mimo_test70_v1` | mimo | 44 | 0.005034 | 0.005034 | 0.005034 | 0.005034 | 1.000 | 11-11 19:20 |
| `mimo_test70_v2` | mimo | 86 | 0.011578 | 0.011578 | 0.011578 | 0.011578 | 1.000 | 11-11 19:21 |
| `smoke_deepseek_u0001` | deepseek | 1 | 0.000321 | 0.000160 | 0.000160 | 0.000096 | 0.500 | 11-11 19:19 |
| `smoke_mimo_u0001` | mimo | 1 | 0.000096 | 0.000096 | 0.000096 | 0.000096 | 1.000 | 11-11 19:19 |

## 10. 校验

- 脚本读取的源文件数：158；生成后重新哈希，变化数：0。
- token 对账失败行数：0；缺 cost 行数：0。
- 63 个 OpenCode 完整 run 的 normalized 合计 $2.123230586，provider list 合计 $2.123230570，差 $+0.000000016（逐请求快照四舍五入）。
- configured 口径无法解释的 run：无。
- provider list 与 normalized 不一致的 run：无。
- 峰时请求行数：0。

## 11. 限制

- 这不是账单。没有读取发票、余额或信用卡数据；`configured`、`normalized`、`allowance` 三个口径都不是实际扣款。
- `allowance` 只在 OpenCode 端点返回；Xiaomi 端点的 provider list/allowance 为 n/a，normalized 按 published MiMo 价计算。
- Legacy runner 的 configured 记录不扣缓存；本报告保留原记录值，同时给出 `configured_cache_aware` 供比较。
- 若在高峰窗口重跑，DeepSeek 应改用 0.30/1.20/0.006；本批全部为非高峰，故使用 0.15/0.60/0.003。
- 脚本按目录自动发现 run；若其他修复任务新增 run，重新执行即可，不会覆盖原始结果。

## 12. 复现

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 analysis/cost_normalization/rebuild.py
```

产物：本文件、`analysis/cost_normalization.json`、`analysis/cost_normalization/runs/*.json`。

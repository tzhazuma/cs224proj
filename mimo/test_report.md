# MiMo-V2.6-Flash 完整 test 对比报告

日期：2026-11-12。运行环境：WSL（Python 3.14.8、httpx 0.28.1）。
数据：冻结的 `splits/test_detection_160.json`（160 函数）和
`splits/test_pairs_180.json`（180 对）。每策略 288 + 540 = 828 请求，三策略共
2484 请求。所有请求均由 OpenCode Go 真实执行，未复用或改写 DeepSeek 结果。

## 1. 最终配置

| 项 | MiMo | DeepSeek（已有基线） |
| --- | --- | --- |
| 模型 | `mimo-v2.6-flash` | `deepseek-v4.1-flash` |
| 端点 | `https://opencode.ai/zen/go/v1` | 同左 |
| Prompt 版本 | `secvul-prompt-2026-11-11.1` | 同左 |
| 策略 | direct / few-shot / context | 同左 |
| 任务 | both | both |
| thinking | 请求 `disabled`，但网关忽略；实际用 `reasoning_effort="none"` 关闭推理 | `thinking={"type":"disabled"}` |
| 输出上限 | `max_completion_tokens=8192` | `max_tokens=8192` |
| temperature | 0.0 | 0.0 |
| 并发/超时 | 16 / 300s | 8 / 180s |
| 价格 | input $0.14、output $0.28、cached $0.0028 /1M | $0.30 / $1.20 / $0.006 |

MiMo 的 `reasoning_effort=none` 经真实 probe 验证：`reasoning_tokens=0`，与
DeepSeek 的 non-thinking 设置语义对齐。pilot 的排查过程见 `pilot_report.md`。

## 2. 完整性与兼容性验证

`python3 mimo/verify_runs.py runner/runs/test_v1_mimo_*` 对 6 个 run 的结论：

| Run | 状态 | 请求 | ok/invalid/error | usage | reasoning tokens | 成本 vs allowance |
| --- | --- | ---: | --- | ---: | ---: | --- |
| direct_independent | completed | 288 | 277/11/0 | 288/288 | 0 | $0.07260122 / $0.07260132 |
| direct_pairs | completed | 540 | 509/31/0 | 540/540 | 0 | $0.11428228 / $0.11428252 |
| few-shot_independent | completed | 288 | 287/1/0 | 288/288 | 0 | $0.09380775 / $0.09380764 |
| few-shot_pairs | completed | 540 | 538/2/0 | 540/540 | 0 | $0.15029769 / $0.15029779 |
| context_independent | completed | 288 | 280/8/0 | 288/288 | 0 | $0.07496204 / $0.07496216 |
| context_pairs | completed | 540 | 523/17/0 | 540/540 | 0 | $0.11720297 / $0.11720381 |

- 2484/2484 记录完成，**0 个最终 API error**。内部重试共 2 次，均在
  few-shot independent：1 次 `missing_choices`、1 次 timeout，第二次尝试成功；
  其余 2482 个请求一次成功。
- 每个请求都实际发送了 `reasoning_effort="none"`、`max_completion_tokens`、
  `thinking={"type":"disabled"}`；响应 `reasoning_tokens` 全部为 0。
- 逐请求 `cost_usd` 之和与 provider 的 `opencode.allowance` 一致（差异 < 1e-9，
  仅为浮点舍入）。总成本 **$0.623154**。
- 数据集 SHA-256、prompt 版本和 dev-example SHA-256 与 DeepSeek run 完全一致。

## 3. 主结果

检测指标只在 schema-valid 预测上计算；invalid 会降低 coverage，并在 strict
accuracy 中按错误计。完整逐行表见 `test_comparison.md`。

| Run | Det valid | Coverage | F1 | Pair disc. | Repair valid | Complete | Changed | 成本 USD | p95 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MiMo direct independent | 150/160 | 0.9375 | 0.3718 | n/a | 127/128 | 124 | 90 | 0.072601 | 37.3 |
| MiMo direct pairs | 331/360 | 0.9194 | 0.3790 | 0.0909 | 178/180 | 177 | 140 | 0.114282 | 33.5 |
| MiMo few-shot independent | 160/160 | 1.0000 | 0.3953 | n/a | 127/128 | 124 | 57 | 0.093808 | 53.9 |
| MiMo few-shot pairs | 360/360 | 1.0000 | 0.4028 | 0.0944 | 178/180 | 177 | 92 | 0.150298 | 40.9 |
| MiMo context independent | 153/160 | 0.9563 | 0.3899 | n/a | 127/128 | 125 | 97 | 0.074962 | 35.1 |
| MiMo context pairs | 345/360 | 0.9583 | 0.4332 | 0.1145 | 178/180 | 177 | 143 | 0.117203 | 29.8 |
| DeepSeek direct independent | 160/160 | 1.0000 | 0.4368 | n/a | 109/128 | 108 | 84 | 0.253340 | 18.3 |
| DeepSeek direct pairs | 360/360 | 1.0000 | 0.4467 | 0.1167 | 151/180 | 151 | 124 | 0.392245 | 19.3 |
| DeepSeek few-shot independent | 160/160 | 1.0000 | 0.4633 | n/a | 127/128 | 125 | 73 | 0.429938 | 18.6 |
| DeepSeek few-shot pairs | 360/360 | 1.0000 | 0.4392 | 0.0889 | 178/180 | 177 | 116 | 0.701446 | 17.7 |
| DeepSeek context independent | 160/160 | 1.0000 | 0.4432 | n/a | 108/128 | 107 | 85 | 0.259777 | 19.7 |
| DeepSeek context pairs | 360/360 | 1.0000 | 0.4718 | 0.1222 | 149/180 | 149 | 128 | 0.402474 | 20.2 |

聚合（6 个 run）：

| 指标 | MiMo | DeepSeek |
| --- | ---: | ---: |
| Detection valid | 1499/1560 (96.1%) | 1560/1560 (100%) |
| Detection mean F1（valid only） | 0.3954 | 0.4502 |
| Detection strict accuracy（invalid 计错） | 0.325–0.531 | 0.388–0.558 |
| Pair discrimination（valid pairs） | 0.091–0.115 | 0.089–0.122 |
| Repair valid | 915/924 (99.0%) | 822/924 (89.0%) |
| Repair complete | 904 | 817 |
| Repair changed | 619 | 610 |
| 总成本 | **$0.623154** | $2.439219 |
| p95 延迟范围 | 29.8–53.9s | 17.7–20.2s |

## 4. 失败模式

MiMo 的 70 个 schema-invalid 记录（61 detection + 9 repair）：

- 59 条 detection 输出 `is_vulnerability` 而不是 `is_vulnerable`；
- 1 条 detection 输出 `is_vulnerative`；
- 1 条 detection 同时缺少 `is_vulnerable`、只给出 `is_vulnerability`；
- 9 条 repair 输出在 `max_completion_tokens=8192` 处被截断
  （`finish_reason=length`，JSON 字符串未闭合）。

按策略看，few-shot 的 detection 完全没有 key drift（160/160、360/360），说明
示例能约束字段名；direct/context 仍会出现。所有 invalid 记录都保留在
`results.jsonl`，没有做别名修正或静默丢弃。

## 5. 结论

- **成本**：MiMo 完成同一 2484 请求矩阵花费 $0.623，DeepSeek 为 $2.439，
  约 **3.9× 便宜**。
- **检测能力**：MiMo 的 valid-only F1 平均低约 0.055（0.395 vs 0.450），
  主要来自更低的 recall（0.24–0.35 vs 0.30–0.39）和 3.9% 的 detection
  schema 失败。few-shot 能消除 key drift，但 F1 仍低于 DeepSeek。
- **配对判别**：两者都很低（MiMo 9.1–11.5%，DeepSeek 8.9–12.2%），MiMo 在
  context pairs 上略高（11.45% vs 12.22% 仍略低），差异在 180 对样本上不足以
  声称优劣。
- **修复**：MiMo 的 schema 有效率更高（99.0% vs 89.0%），complete function
  更多（904 vs 817）；但 changed_from_input 只略高（619 vs 610），说明“返回了
  结构完整的函数”不等于“真的改了漏洞”。修复指标仍是结构代理，不是安全正确性。
- **延迟**：MiMo p95 更高（30–54s vs 18–20s），但成本低得多；两者是明确的
  成本/延迟权衡。

## 6. 限制

- 单一 prompt 版本、单一 temperature 0、单一 seed 的 frozen split；没有重复采样，
  不能给出置信区间。
- MiMo 的“关闭推理”依赖 OpenCode Go 网关对 `reasoning_effort` 的实现，官方模型
  文档只写了 `thinking`；网关策略变化会改变结果，复用前必须重跑 probe。
- `max_completion_tokens=8192` 对 9 条 repair 不足以输出完整函数；未提高预算，
  以保持与 DeepSeek 的 8192 输出预算可比。若提高预算，repair coverage 会上升，
  但成本和延迟也会上升。
- 成本只统计成功响应的 usage；失败 attempt 的 provider 扣费未计入
  （本次 0 API error，invalid 都是 200 + 可解析/截断内容，usage 已记录）。
- 检测 precision/recall/F1 是 valid-only；strict accuracy 把 invalid 计错。
  两种口径都已给出，不能只引用较高的那个。
- DeepSeek 运行使用 concurrency 8 / timeout 180，MiMo 使用 16 / 300；并发和超时
  不影响请求内容，但会影响延迟分布。

## 7. 复现

```bash
bash mimo/run_mimo.sh test
python3 mimo/verify_runs.py runner/runs/test_v1_mimo_*
python3 runner/compare_runs.py \
  runner/runs/test_v1_mimo_* runner/runs/test_v1_{direct,few-shot,context}_{independent,pairs} \
  --out mimo/test_comparison.md
```

产物：`runner/runs/test_v1_mimo_{direct,few-shot,context}_{independent,pairs}/`
（每个目录含 `manifest.json`、`config.json`、`requests.jsonl`、`results.jsonl`、
`metrics.json`、`metrics.md`、`cache/`、`run.log`）。

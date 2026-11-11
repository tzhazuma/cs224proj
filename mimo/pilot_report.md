# MiMo-V2.6-Flash 真实 pilot 报告

日期：2026-11-12（Asia/Shanghai）。所有命令在 WSL 中执行，凭证由
`runner/run_with_kimi_config.py` 从 `/mnt/c/Users/tzh03/.kimi-code/config.toml`
的 `opencode-go` provider 读入进程内存，未打印、未落盘。

## 1. 结论

- 接入成功：最终配置 63/63 请求全部 `ok`，JSON schema 全部有效，usage 完整，
  成本与 OpenCode `opencode.allowance` 逐 run 一致（差异 < 1e-9 USD）。
- 关键兼容性：OpenCode Go 上 MiMo **忽略** `thinking={"type":"disabled"}`；
  必须用 `reasoning_effort="none"` 才能真正关闭推理。关闭后 `reasoning_tokens=0`，
  与 DeepSeek non-thinking 运行语义对齐。
- 输出上限必须用 MiMo 原生字段 `max_completion_tokens`；传 `max_tokens` 会被忽略，
  首次 pilot 中一个 repair 请求因此无上限推理，超过 10 分钟未返回。
- 最终 pilot：每策略 independent `limit 6` + pairs `limit 3`，`both` 任务。
  6 个 run 共 63 请求，全部完成，总成本约 **$0.0101**，p95 延迟 17.7–38.4 秒。

## 2. 最终配置

| 项 | 值 |
| --- | --- |
| 模型 ID | `mimo-v2.6-flash` |
| 端点 | `https://opencode.ai/zen/go/v1/chat/completions` |
| 请求体 | `thinking={"type":"disabled"}`（记录探测）、`reasoning_effort="none"`、`max_completion_tokens=8192` |
| 策略 | `direct` / `few-shot` / `context`（冻结 prompt，未改） |
| 任务 | `both`（detection + 对漏洞侧的 repair） |
| 数据 | `splits/pilot_detection_36.json` limit 6；`splits/pilot_pairs_18.json` limit 3 |
| 采样 | temperature 0.0，concurrency 16，timeout 300s，max attempts 3 |
| 价格 | input $0.14 / output $0.28 / cached read $0.0028 per 1M（2026-11-12 官方文档 + models 接口核验） |

## 3. Pilot 指标（partial，不可当作全量证据）

| Run | 请求 | ok/invalid/error | Det valid | Precision | Recall | F1 | Pair disc. | Repair valid/complete | 成本 USD | p95 s |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| pilot_v1_mimo_direct_independent | 12 | 12/0/0 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | 0.001443 | 31.5 |
| pilot_v1_mimo_direct_pairs | 9 | 9/0/0 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | 0.001542 | 38.4 |
| pilot_v1_mimo_few-shot_independent | 12 | 12/0/0 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | 0.001789 | 25.8 |
| pilot_v1_mimo_few-shot_pairs | 9 | 9/0/0 | 6 | 1.0000 | 0.3333 | 0.5000 | 0.3333 | 3/3 | 0.001559 | 17.7 |
| pilot_v1_mimo_context_independent | 12 | 12/0/0 | 6 | 1.0000 | 0.3333 | 0.5000 | n/a | 6/6 | 0.001730 | 32.0 |
| pilot_v1_mimo_context_pairs | 9 | 9/0/0 | 6 | 0.5000 | 0.3333 | 0.4000 | 0.0000 | 3/3 | 0.002085 | 18.8 |

检测指标只在 schema-valid 预测上计算；pilot 的 6 个 independent 样本全为漏洞样本，
没有非漏洞样本，precision 不能外推。pair discrimination 只有 3 对，噪声很大。
完整 160/180 测试集运行才可报告为实验结论。

同配置的 DeepSeek pilot（`dev_pilot_*`，12/9 请求）成本为 $0.0076–$0.0159，
MiMo 为 $0.0014–$0.0021；p95 延迟两者相近（DeepSeek 11.9–27.5s，
MiMo 17.7–38.4s）。逐行对比见 `pilot_comparison.md`。

## 4. 兼容性排查过程（真实失败与修正）

1. **attempt1**（`pilot_v1_mimo_attempt1_direct_independent_stuck`）：请求体用
   `max_tokens=8192`、`thinking=disabled`。12 个请求中 10 个在 1–3 分钟内完成，
   1 个 repair（`idx:11521`）超过 10 分钟仍在生成，手动终止。原因：MiMo 忽略
   `max_tokens`，输出上限实际为 131072，推理无界。
2. **max_completion_tokens 验证**：同一 repair 样本改用
   `max_completion_tokens=8192` 后，第一次尝试 284s 因推理耗尽预算返回空 content
   （`empty_content`，runner 自动重试），第二次 52s 返回合法 JSON。
3. **thinking 验证**：即使 `thinking=disabled`，usage 仍报告
   `reasoning_tokens=669…7544`；推理文本在 `message.reasoning`（不是
   `reasoning_content`）。说明该参数在 OpenCode Go 上被忽略。
4. **attempt2**（`pilot_v1_mimo_attempt2_reasoning_*`）：`max_completion_tokens=8192`
   且推理开启。5 个 run 完成，但 hard repair 出现 `finish_reason=length`、
   `content=null` 或截断 JSON；direct pairs 有 1 个 API error、2 个 detection
   schema invalid（模型把 `is_vulnerable` 写成 `is_vulnerability`）。
5. **reasoning_effort 验证**：同一 hard repair 加 `reasoning_effort="none"` 后
   11.8s 返回 schema-valid JSON，`reasoning_tokens=0`。另用
   `max_completion_tokens=16384` + 推理开启做过对照：596s 才完成，
   `reasoning_tokens=12280`，说明大预算可救但代价高。
6. **最终 pilot**：`reasoning_effort=none`，63/63 ok，0 invalid，0 API error，
   `reasoning_tokens` 总和 0。

## 5. 成本核验

`mimo/verify_runs.py` 对每个 run 比较逐请求 `cost_usd` 之和与
`usage.opencode.allowance`：

| Run | cost_usd sum | allowance USD | 差异 |
| --- | ---: | ---: | ---: |
| direct_independent | 0.0014427728 | 0.00144278 | < 1e-9 |
| direct_pairs | 0.0015417304 | 0.00154174 | < 1e-9 |
| few-shot_independent | 0.0017887744 | 0.00178877 | < 1e-9 |
| few-shot_pairs | 0.0015586816 | 0.00155868 | < 1e-9 |
| context_independent | 0.0017303776 | 0.00173038 | < 1e-9 |
| context_pairs | 0.0020845160 | 0.00208452 | < 1e-9 |

这同时验证了 `prompt_tokens_details.cached_tokens` 的回退解析：pilot 中共有
6,976（direct independent）、29,248（few-shot independent）等缓存命中 token，
若忽略缓存价，成本会明显高于 provider 的 allowance。最终成本与 allowance 一致。

## 6. 限制

- 所有 pilot run 都是 `partial: true`，不能作为全量实验结论。
- 6 个 independent 样本全为漏洞样本；检测 precision 不具有代表性。
- 关闭推理是 OpenCode Go 网关行为，不是 MiMo 官方文档的显式承诺；
  如果网关策略变化，需要用同一个 probe 重新核验。
- runner 只记录最后一次成功 attempt 的 usage；`empty_content`/timeout 的失败
  attempt 不进入 `cost_usd`，因此成本是“成功响应成本”，不是账户实际扣费。
  attempt2 的失败请求就是这种情况；最终配置下 63/63 一次成功，不存在该偏差。
- 已有 DeepSeek 产物未改动：运行前后对 `runner/runs/` 下 2635 个
  JSON/JSONL/MD 文件做 SHA-256 比对，全部一致。

## 7. 复现

```bash
bash mimo/run_mimo.sh pilot
python3 mimo/verify_runs.py \
  runner/runs/pilot_v1_mimo_{direct,few-shot,context}_{independent,pairs}
python3 runner/compare_runs.py \
  runner/runs/pilot_v1_mimo_{direct,few-shot,context}_{independent,pairs} \
  runner/runs/dev_pilot_* \
  --out mimo/pilot_comparison.md
```

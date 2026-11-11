# MiMo-V2.6-Flash 对比实验（SecVulEval）

本目录负责 MiMo-V2.6-Flash 在冻结 splits 上的真实 pilot 与完整 test 运行，复用
`runner/` 的三种策略（`direct` / `few-shot` / `context`）和 `both` 任务，不修改
DeepSeek V4.1 Flash 已有的任何运行产物。

状态（2026-11-12）：pilot 63/63 请求完成；完整 test 2484/2484 请求完成，
0 API error，总成本 $0.623154。结果见 `test_report.md`。

## 1. 接入方式

- OpenCode Go 端点：`https://opencode.ai/zen/go/v1`（`--kimi-provider opencode-go`）。
- 模型 ID：`mimo-v2.6-flash`（OpenCode Go 官方模型列表中的 ID）。
- 凭证：`runner/run_with_kimi_config.py` 从
  `/mnt/c/Users/tzh03/.kimi-code/config.toml` 的 `opencode-go` provider 读取
  `api_key`，只放入进程内存和环境变量；脚本不打印、不落盘密钥。
- 请求头沿用 runner 自带实现：`User-Agent: secvul-eval-runner/1.0` 和
  `x-opencode-session: ses_<32 hex>`（非敏感随机 ID）。

## 2. 价格（2026-11-12 核验）

官方页面：<https://opencode.ai/v2/docs/console/go/>（2026-11-12 抓取）。

| 模型 | Input / 1M | Output / 1M | Cached read / 1M | 月度额度 |
| --- | ---: | ---: | ---: | ---: |
| MiMo-V2.6-Flash | $0.14 | $0.28 | $0.0028 | $60 |

同页的模型元数据接口
<https://opencode.ai/zen/go/v1/models> 也返回 `cost.text.input.price=0.14`、
`cost.text.input.cache.read=0.0028`、`cost.text.output.price=0.28`，与文档一致。
`run_mimo.sh` 显式传入这三个价格；价格会随官方页面调整，复用前必须重新核对。

## 3. 运行

```bash
# pilot：每策略 independent limit 6 + pairs limit 3（partial，仅用于接入检查）
bash mimo/run_mimo.sh pilot

# test：每策略 288 + 540 = 828 请求（三个策略共 2484）
bash mimo/run_mimo.sh test
```

输出目录：

| 模式 | 目录 |
| --- | --- |
| pilot | `runner/runs/pilot_v1_mimo_{direct,few-shot,context}_{independent,pairs}` |
| test | `runner/runs/test_v1_mimo_{direct,few-shot,context}_{independent,pairs}` |

兼容性排查保留的真实尝试：

- `runner/runs/pilot_v1_mimo_attempt1_direct_independent_stuck`：`max_tokens` 被忽略、
  推理无界导致请求挂起，手动终止。
- `runner/runs/pilot_v1_mimo_attempt2_reasoning_*`：`max_completion_tokens` + 推理开启，
  用于证明截断/空 content 与 schema 漂移。

最终 pilot 的指标、成本和排查结论见 `mimo/pilot_report.md`；与 DeepSeek pilot 的
逐行对比见 `mimo/pilot_comparison.md`。完整 2484 请求 test 的结果见
`mimo/test_report.md` 和 `mimo/test_comparison.md`。

脚本对已存在 `manifest.json` 的目录自动加 `--resume`。`--limit` 运行会在
`manifest.json` / `metrics.json` 中标记 `partial: true`，不能当作全量结果。

审计脚本（JSON、usage、thinking/reasoning 兼容性）：

```bash
python3 mimo/verify_runs.py \
  runner/runs/pilot_v1_mimo_{direct,few-shot,context}_{independent,pairs}
```

## 4. thinking / reasoning 兼容性（真实 probe 结论）

- MiMo 官方 OpenAI 兼容文档支持 `thinking: {"type": "enabled"|"disabled"}`，默认
  `enabled`；但 OpenCode Go 的模型元数据标记 `capabilities.effort_updates: false`。
- **`thinking: {"type":"disabled"}` 在该端点上被忽略**：pilot 中请求体带该字段时，
  响应 `usage.completion_tokens_details.reasoning_tokens` 仍为 600–7500+，修复任务
  的推理会耗尽 8192 输出预算，返回空 content 或截断 JSON。
- **`reasoning_effort: "none"` 有效**：同一 hard repair 样本（`idx:11521`）在
  `thinking=disabled` 下 284 秒耗尽 8192 预算仍失败；加上
  `reasoning_effort=none` 后 11.8 秒返回 schema-valid JSON，
  `reasoning_tokens=0`。因此最终运行同时发送 `thinking=disabled`（记录兼容性探测）
  和 `reasoning_effort=none`（真正关闭推理）。
- 响应把推理文本放在 `message.reasoning` / `message.reasoning_details`（AI SDK 风格），
  而不是 `message.reasoning_content`；最终 JSON 答案仍在 `message.content`。
  runner 已记录 `reasoning_chars`、`reasoning_content_chars` 和
  `reasoning_tokens` 作为诊断字段。
- **输出预算字段是 `max_completion_tokens`**：MiMo 原生 API 用该字段
  （包含 reasoning + 答案），传 `max_tokens` 会被忽略。首次 pilot 中一个 repair
  请求因此无上限推理，超过 10 分钟仍未返回。`run_mimo.sh` 固定传
  `--max-tokens-field max_completion_tokens`；关闭推理后 8192 足够输出完整函数。
- 最终配置因此是“MiMo 非推理模式”，与 DeepSeek 的 non-thinking 运行语义对齐；
  8192 输出预算、temperature 0、同一批 frozen splits 和三种 prompt 策略。

## 5. 对 runner 的通用兼容改动（不改变 DeepSeek 语义）

- `--thinking {default,enabled,disabled}`：显式控制请求体 `thinking` 字段。省略时保持
  旧行为（`deepseek-*` 发送 `disabled`，其他模型不发送）。DeepSeek 已有运行的
  config fingerprint 经逐目录复核完全不变，请求体逐字节一致。
- `--reasoning-effort {none,minimal,low,medium,high}`：发送 `reasoning_effort`；
  MiMo 用 `none` 真正关闭推理。
- `--max-tokens-field {max_tokens,max_completion_tokens}`：MiMo 用
  `max_completion_tokens`；默认值保持旧行为。
- 成本与 usage 解析支持 `prompt_tokens_details.cached_tokens`
  （MiMo/OpenAI 风格）作为 `prompt_cache_hit_tokens` /
  `cache_read_input_tokens` 之后的回退。
- `metrics.json` 的 `usage` 增加 `reasoning_tokens_known_sum`。
- 响应元数据增加 `content_chars`、`reasoning_content_chars`、`reasoning_chars`、
  `reasoning_tokens`，仅用于诊断，不参与评分。

已有 DeepSeek 产物未覆盖：运行前后对 `runner/runs/` 下 2635 个 JSON/JSONL/MD 文件做了
SHA-256 快照比对。

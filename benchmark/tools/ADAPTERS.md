# 生产者适配器约定（raw → 统一 schema）

并行工作流可以保留自己的原始输出格式；**不要为了统一 benchmark 改写原始文件**。统一层只接受一个适配器产出的 canonical run：

```text
raw producer dir (static / dynamic / mimo / ...)
        │  adapter (read-only)
        ▼
benchmark/results/.../<run_id>/
  run_manifest.json
  predictions.jsonl
```

适配器必须：

1. 逐条复制原始预测/标签/状态，不重新推理、不改标签；
2. 在 `provenance.source_artifact`/`source_sha256` 记录 raw 文件；
3. 用 `bench_validate.py` 校验通过；
4. 用 `bench_metrics.py` 重算指标，**不要**直接抄 raw 的 metrics 当统一结果；
5. 在 `run_manifest.notes` 写清 raw schema 与映射版本。

## 静态工具（`traditional/static/`）

原始 `predictions.jsonl` 的 `schema_version=static-cwe401-v1`，一行是（样本，工具）。映射：

| raw 字段 | canonical 字段 | 说明 |
| --- | --- | --- |
| `sample.sample_id` 或 `sample_id` | `unit_id` | 加前缀，如 `juliet:<case_id>:<bad|good>`；必须与数据集 manifest 对齐 |
| `sample.label` / `label` | `label.y_true` | bool |
| `sample.cwe` | `label.cwe` | 统一 `CWE-401` |
| `prediction.is_vulnerable` | `prediction.y_pred` | bool |
| `diagnostics[]` | `extensions.raw_diagnostics` | 保留原始 warning；可选 |
| `status` | `status` | 见下表 |
| `runtime.duration_seconds` | `cost.wall_s` | 每（样本，工具） |
| `tool` / `command` | `method.tool` / `provenance` | 记录版本/命令 |
| `sample.source_paths` | `input.source_sha256` / `provenance` | 原始源文件哈希；不要写路径进 prompt |

状态映射：

| raw | canonical | 说明 |
| --- | --- | --- |
| `ok` | `ok` | 有合法诊断 |
| `compile_error` | `compile_error` | 不是“无泄漏” |
| `timeout` | `timeout` | 不是“无泄漏” |
| `tool_error` | `tool_error` | 诊断不可信 |
| `unavailable` | `not_applicable` | 仅当该方法不适用；若方法声称支持，应记 `unsupported`/`tool_error` |

指标映射的陷阱：

- raw 的 **evaluable** = 只含 `status=ok` 且有标签 → 对应 canonical **valid-only**。
- raw 的 **end_to_end** 把 `compile_error`/`timeout` 当作“未报泄漏”，但 **排除** `tool_error`/`unavailable`；canonical **strict** 把所有非 ok（含 tool_error）算错。两者**不等价**，不能把 raw end_to_end 标成 canonical strict。
- 统一层应从 canonical predictions 重算 strict/valid-only，并在 notes 说明 raw 视图的差异。

## 动态工具（`traditional/dynamic/`）

原始输出尚未冻结为公共 schema。适配器至少映射：

| raw 概念 | canonical | 说明 |
| --- | --- | --- |
| LSan `leak` / Valgrind definite/indirect | `prediction.y_pred=1` | 观察到泄漏 |
| `clean` + 覆盖达标 | `prediction.y_pred=0`, `status=ok` | `NO_LEAK_OBSERVED`，不是安全证明 |
| `clean` + 覆盖不足 | `prediction.y_pred=null`, `status=inconclusive` | 不能算 TN |
| `compile_error`/`timeout`/harness error | `status=compile_error`/`timeout`/`harness_error` | 保留 |
| `coverage.line_coverage` | `coverage.line_coverage` | 0–1 |
| `target_function_entered` | `coverage.target_function_entered` | bool |
| LSan/Valgrind 原始 stderr | `provenance.source_artifact`/`extensions` | 不写进 prompt |

动态 clean 的 `line_coverage < 0.80` 必须标 `inconclusive`（见 `PROTOCOL.md` §7.3/§12.3）。

如果源 run **没有覆盖率 instrumentation**（`line_coverage=null`），`bench_collect_tier_b.py` 保留 operational 的 clean 预测，但必须在 summary 中同时给出 conservative 视图：clean 一律弃权，macro-F1 未定义，只报告 recall/precision。不得把 operational clean 写成“已验证 TN”。

## LLM（`runner/`、`mimo/`）

`bench_import_legacy.py` 已实现 DeepSeek 与 MiMo run 的只读转换。新 LLM run 使用同一字段映射：

- `prompt.function.code_sha256` → `input.source_sha256`
- `request.body_sha256` → `input.prompt_sha256`
- `response.content` 的解析结果 → `prediction.y_pred` / `confidence`
- `response.cost.cost_usd` → `cost.usd`
- `response.attempts[-1].latency_seconds` → `usage.latency_ms` / `cost.wall_s`
- `status`/`invalid` → canonical `status`
- `strategy` → `method.strategy`；`model` → `method.model.model_id`

`bench_import_legacy.py` 只复制 Tier A detection/pair；旧 Tier A repair 记录只计数，不进入 v1 detection 主表。Tier B repair（B11）是独立 `task=repair`，见下。

## Round-2 真实运行（`evidence_prompt/`、`pair_joint/`、`hybrid/`、`juliet_llm/`、`juliet_repair/`）

`bench_import_round2.py` 只读导入这五类源目录；不重跑、不改源文件。

| 源 | canonical task | 关键映射 |
| --- | --- | --- |
| `evidence_prompt/runs/test_evidence_*` | `detection` | `idx→secvul:det:<idx>`；`parsed.is_vulnerable→y_pred`；`response.cost.cost_usd→cost.usd` |
| `pair_joint/runs/test_*_180` | `pair_detection` | 一个 joint 请求→两条 side 记录；`parsed.vulnerable_version` + `position_map`→选中侧；`extensions.forced_choice=true`；成本/墙钟 50/50，token/latency 只记一次 |
| `hybrid/runs/hybrid_v2_*` | `leak_detection` | canonical v2；`unit_id→juliet:<group>:<side>`；`status/valid/y_pred`；`cost.cost_usd`；`extensions.method/split/dynamic_outcome/input_pack_sha256` |
| `juliet_llm/runs/...xiaomi_official_postleakfix` | `leak_detection` | canonical 140 test；`method.model.provider=xiaomi-official`；manifest/notes/报告都标 Xiaomi 官方端点（不是 OpenCode Go） |
| `juliet_repair/runs/*_final` | `repair` | `strict_evaluable=false→status=not_applicable`；`strict_pass→y_pred`；attempts/cost 从 `summary.json` 的完整 results 读取 |

Pair-joint 的 canonical 记录仍然满足 `pair_detection` 的 side 结构，但语义是强制二选一；任何汇总必须用 `extensions.forced_choice` 分流，不能把它并入分侧表。

## 适配器验收

```bash
python3 benchmark/tools/bench_validate.py --run-dir <canonical_run> --jsonschema
python3 benchmark/tools/bench_metrics.py --run-dir <canonical_run>
```

- `validation.json.errors=[]`；
- `counts.by_status` 与 raw 的失败数一致；
- `metrics.json` 的 valid-only 与 raw `evaluable` 在**同一标签集合**上一致（允许浮点误差）；strict 视图允许不同，但必须在 notes 解释；
- 不允许静默删除 raw 的 `compile_error`/`timeout`/`tool_error`。

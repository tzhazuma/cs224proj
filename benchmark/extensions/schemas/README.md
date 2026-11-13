# `benchmark/extensions/schemas/` — 扩展契约

本目录只定义**新方法接入层**的机器可读契约。核心原则：

1. **父协议不变。** `benchmark/schemas/prediction.schema.json`、`run_manifest.schema.json`、`metrics.schema.json` 和 `PROTOCOL.md` 的语义不动。扩展 run 的 `run_manifest.json` / `predictions.jsonl` 仍然通过父 schema；设计元数据放在 sidecar `extension_manifest.json`，设计特有字段放在每条记录的 `extensions` 里。
2. **新增字段不改变父字段语义。** `label.y_true`、`prediction.y_pred`、`status`、`coverage`、`oracle`、`cost` 的含义与父协议完全一致；扩展块只增加任务结构、审计信息和聚合口径。
3. **版本化。** 扩展 schema 版本是 `benchmark-extension-*` / `benchmark-*-v1`；任何破坏兼容的字段变更都必须提升 `design_version`，并新建 run，不得改写旧 run。

## 文件

| 文件 | 用途 | 使用方 |
| --- | --- | --- |
| `extension_manifest.schema.json` | 每个扩展 run 的 `extension_manifest.json` sidecar：design、pairing、claim/fault/tool registry、baseline、options | `ext_import.py`、`ext_validate.py`、`ext_metrics.py` |
| `extension_blocks.schema.json` | 每种 design 在 `prediction.extensions` 中必需的块；含静态诊断子 schema | `ext_validate.py`（`--jsonschema`） |
| `extension_metrics.schema.json` | `ext_metrics.py` 写出的 `metrics.json` | 汇总/报告 |
| `claim_manifest.schema.json` | 冻结的 evidence-verification claim 清单 | `ext_import.py evidence`、`ext_validate.py` |
| `fault_manifest.schema.json` | 冻结的 fault-injection 变体清单 | `ext_import.py fault`、`ext_validate.py` |
| `static_tool_registry.schema.json` | 新静态工具的规则→CWE-401 映射注册表 | `ext_import.py static`、`ext_validate.py --check-registries` |
| `producer_raw.schema.json` | 生产者 raw JSONL 的参考格式（`$defs` + discriminator `design`） | 新方法实验的生产者；`ext_import.py` 读取同一组键 |

## 父 schema 兼容性

扩展 run 的 `run_manifest.json` 必须是 `benchmark-run-v1`，`predictions.jsonl` 每行必须是 `benchmark-prediction-v1`。因此：

- 父 `run_manifest.schema.json` 的 `additionalProperties=false` 不包含 `extensions`，所以扩展设计信息**不能**放在 `run_manifest` 顶层；必须放 `extension_manifest.json`。
- 父 `prediction.schema.json` 允许 `extensions` 为任意对象；扩展块的严格要求由 `extension_blocks.schema.json` 追加。
- `task` 仍是父枚举 `detection|pair_detection|leak_detection|repair`；八种新设计是这些任务的**设计变体**，不是新 task：
  - position-debiased / open-choice → `pair_detection`
  - evidence verification / evidence retraction → `detection`
  - fault-injected dynamic / new static tool / enhanced dynamic / hybrid enhanced dynamic → `leak_detection`
- 这样父 `bench_validate.py`、`bench_metrics.py` 可以在不修改的情况下读取扩展 run；扩展工具只在这个基础上增加设计特有统计。

## 状态与标签

- 状态词表完全继承父协议 `PROTOCOL.md` §8.1。扩展不得新增 `status` 字符串。
- `not_applicable` 不进分母；`inconclusive` 在 valid-only 排除、strict 算错；`schema_invalid` / `api_error` / `timeout` / `tool_error` / `compile_error` / `harness_error` / `crash` 同样保留。
- `insufficient`（evidence verification 的弃权）编码为 `status="inconclusive"`，不是 `ok` + `y_pred=null`；父 schema 禁止 `status=ok` 且 `y_pred=null`。
- `evidence_retraction` 的 post 预测：sustain=1、retract=0；invalid/missing verifier 按 fail-closed 置 0，并在 `extensions.retraction.fail_closed=true` 记录；第一遍 invalid 保留 `schema_invalid`。
- `enhanced_dynamic` 的 clean 无行覆盖率时必须是 `status="inconclusive"`、`y_pred=null`；operational 0 只放 `extensions.dynamic_enhanced.operational_y_pred`，不能当 protocol TN。
- fault-injected dynamic 的 `expected_outcome="inconclusive"` 变体编码为 `status="not_applicable"`，`label.y_true` 仅为满足父 schema 填 0，并在 `label_note` 和 `extensions.fault_injection.expected_outcome` 说明它不进入标签分母。真正参与敏感性/特异性的是 `expected_outcome` 为 leak/clean 的变体。

## 校验

```bash
# 扩展 run：父结构 + 扩展块 + 设计不变量
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py \
  --run-dir benchmark/extensions/runs/<design>/<run> --jsonschema'

# position-debiased：base 目录（order_ab/order_ba 或 fwd/rev）自动检查配对一致性
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py \
  --run-dir benchmark/extensions/runs/pair_debias/deepseek/forced --jsonschema'

# 注册表自检
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/extensions/tools/ext_validate.py --check-registries'
```

`--jsonschema` 需要 `jsonschema`（本机 WSL 已装 4.19.2）；没有该包时只跑标准库不变量检查，并在 `validation.json` 里给出 warning，不静默跳过。

## 生产者最小要求

生产者在 raw 记录里至少提供：

- 身份：`pair_id` / `claim_id` / `fault_id` / `sample_id`；
- 观察：`choice` / `open_choice` / `verdict` / `observed_outcome` / `diagnostics`；
- 运行元数据：`status`、`usage`、`cost`（可空）、`prompt_sha256` 或 `raw_output_sha256`；
- 不得把 `Authorization`、API key、cookie、私钥写进 raw 或 canonical 输出。`ext_import.py` 只复制白名单字段；`ext_validate.py` 会扫描输出中的敏感键并报错。

完整字段映射、统计口径和“不能声称什么”见 [`../README.md`](../README.md)。

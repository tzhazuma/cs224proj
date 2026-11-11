# `benchmark/schemas/` — 结果契约

本目录是统一 benchmark 的**规范 JSON Schema（2020-12）**。协议文字见 `../PROTOCOL.md`；这里是机器可读契约。

| 文件 | 对应产物 | 使用方 |
| --- | --- | --- |
| `prediction.schema.json` | 每个评估单元一行 `predictions.jsonl` | 所有方法（LLM/静态/动态/混合） |
| `run_manifest.schema.json` | 每个 run 一个 `run_manifest.json` | 运行器、汇总器 |
| `metrics.schema.json` | 每个 run 一个 `metrics.json` | `bench_metrics.py`、报告 |
| `dataset_manifest.schema.json` | 每个冻结数据集一个 `dataset_manifest.json` | Tier B 数据准备、审计 |

## 版本

- Schema 版本：`benchmark-prediction-v1`、`benchmark-run-v1`、`benchmark-metrics-v1`、`benchmark-dataset-v1`
- 协议版本：`1.0.0`（见 `../VERSION`）
- 任何破坏兼容的字段变更都必须提升 schema 版本，并新增 `benchmark/results/` 目录，不得就地改旧 run。

## 规范字段的三个原则

1. **原始预测不可变。** `prediction.y_pred` 只由方法输出产生；汇总脚本不得为了让指标好看而改写它。
2. **失败不是负例。** `status != "ok"` 时 `y_pred` 必须为 `null`；是否计入 strict 分母由指标层决定，不能把 API 错误伪装成“安全”。
3. **覆盖率和成本分开。** `coverage` 描述动态执行覆盖；`cost` 描述金钱/算力/延迟。不得用一个“总分”把两者混在一起。

## 校验

```bash
# 结构/一致性校验（不依赖第三方包）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_validate.py --run-dir <run_dir>'

# 用 jsonschema 校验示例（本机 WSL 已装 jsonschema 4.19.2）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 - <<"PY"
import json, jsonschema
schema=json.load(open("benchmark/schemas/prediction.schema.json"))
rec=json.loads(open("benchmark/examples/run_detection/predictions.jsonl").readline())
jsonschema.validate(rec, schema)
print("ok")
PY'
```

`bench_validate.py` 的核心检查不依赖 `jsonschema`，因此在没有该包的环境中也能运行；Schema 文件本身用于交换和外部审计。

## 扩展字段

- 顶层的 `extensions` 可以放方法特定字段（例如静态工具的原始 warning 列表），但不得改变必填字段语义。
- `method.model` 和 `method.tool` 允许额外字段，用于记录 provider、版本、解码参数、命令行和 license。
- 若某个方法需要新的 `status`、`task` 或 `family`，先改协议和 Schema 版本，再运行；不要用字符串滥用现有枚举。

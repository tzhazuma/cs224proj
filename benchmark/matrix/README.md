# `benchmark/matrix/` — 实验矩阵与创新实验槽位

本目录是**计划/状态表**，不是结果表。数字来自协议或已有冻结 run；没有运行的行标 `planned` / `blocked_*`，只完成部分预注册子集的行标 `partial`。

| 文件 | 用途 |
| --- | --- |
| `experiment_matrix.csv` | 核心比较：Tier A 的 DeepSeek/MiMo × 策略；Tier B 的静态/动态/LLM/混合 |
| `experiment_matrix.md` | 同一内容的人读视图 |
| `innovation_matrix.csv` | 创新实验槽位（证据融合、选择性预测、成本级联、泄漏压力测试等） |
| `innovation_matrix.md` | 同一内容的人读视图 |
| `make_matrix.py` | 生成 CSV + Markdown，并检查 ID 唯一/状态合法 |

## 状态词表

| 状态 | 含义 |
| --- | --- |
| `done_frozen` | 已有真实运行或冻结数据卡；只读；不得覆盖或重跑后替换 |
| `partial` | 预注册槽位只完成了一部分（如 B9 sanitizer 审计已过、label-only baseline 未跑；I1/I2 只做了部分对照）；不能把子集结果当作整个槽位结论 |
| `planned` | 协议已定义，尚未产生真实结果 |
| `blocked_dataset` | 依赖尚未冻结的数据/清单（当前 B 数据已冻结，此状态留给未来新数据） |
| `blocked_gate` | 依赖 gate 未过，或外部端点不可用（B4 的 401/402） |
| `blocked_tool` | 依赖本机不可用/未冻结的外部工具（历史状态；B3 已用 /tmp 解包的 Valgrind 3.27.1 完成） |
| `out_of_scope` | 明确不属于 v1 benchmark 主表（如旧 repair 记录） |

## 使用规则

1. **一行一个可运行单元**，不要在一行里混入多个模型/多个数据集的结果。
2. `output_path` 是计划路径；真实产物必须带 `run_manifest.json` 与 `predictions.jsonl`，通过 `bench_validate.py`。
3. `status` 只能在真实产物存在且校验通过后从 `planned` 改为 `done_frozen`；不能因为“跑完了”就改状态，必须有 manifest 和 metrics。
4. `done_frozen` 行不得改写数值或输出路径；新结果另起 `exp_id`/run 目录。
5. 不要用 `A0-*` 的旧结果去填 `A1-*`；MiMo 必须有自己的真实 run。
6. `A4` 静态可行性只报告 applicability/compile rate，**不得**把 0 条可编译样本写成 F1=0。
7. `B0` 数据卡已冻结。`B9` 是 **partial**：sanitizer/prompt 审计 200/200 通过，但 label-only baseline 未跑；Juliet LLM/混合结果可以报告，但必须带此 caveat，不能写成 B9 已完全通过。
8. `B11` 修复只在 58 个 baseline 可观测单元上报告 strict pass；12 个不可观测单元是 `not_applicable`，不得写成 70/70。
9. `A7` pair-joint 是强制二选一独立任务，不能与分侧 pair 合并或直接比较。
10. `B12` 的 canonical 版本是 **hybrid v2**；v1 标 `superseded` / leakage-sensitive，只作历史，不进入主 leaderboard。`B5` 的 canonical 是 postleakfix Xiaomi 官方端点 run，不是旧 harness run。

## 与创新调研 H1–H7 的映射

创新调研（`research/hybrid_ai_memory.md`）提出 H1–H7；本矩阵提供对应槽位：

| 调研假设 | 矩阵槽位 | 说明 |
| --- | --- | --- |
| H1 SAST 证据条件化 | `I1-EVIDENCE-FORMAT` + `I1B-PLACEBO-CONTROL` | 真实证据 vs 安慰剂，分离内容效应与长度效应 |
| H2 Agent 反馈 | `I1B-PLACEBO-CONTROL` + `I9-AGENT-ROUNDS` | 多轮/工具调用必须与安慰剂/单轮对照 |
| H3 动态确认 | `I2-DYNAMIC-TRACE` | 覆盖率分层；clean 不是安全 |
| H4 路径验证 | `I2B-PATH-VALIDATION` | 验证 vs 仅写路径的格式对照 |
| H5 选择性混合 | `I3-ABSTENTION` | risk–coverage/AURC，dev 拟合 |
| H6 Juliet 迁移/清洗 | `I6-SANITIZATION-STRESS` + `I7-CROSS-TIER-TRANSFER` | 排名不可迁移；清洗消融 |
| H7 轮数饱和 | `I9-AGENT-ROUNDS` | 1/2/3/6 轮边际收益与成本 |

## 比较族（multiplicity family）

- `A-STRATEGY-DS`：DeepSeek 内部 3 策略两两比较；Holm 校正 3 个 p。
- `A-MODEL`：同一策略下 DeepSeek vs MiMo；每个策略一个 family，或按预注册合并。
- `A-INTERACTION`：2×3 交互，探索性；不进入“最佳策略”主结论。
- `A-STATIC-FEASIBILITY`：描述性，不做 F1 检验。
- `B-PARADIGM`：同集静态/动态/LLM 两两比较；Holm 在预注册方法对内。
- `B-HYBRID`：混合 vs 其单方法基线；Holm 在混合族内（direct→每个 evidence 条件 m=4；combined vs 工具 m=5）。
- `B-REPAIR`：修复在 58 个可观测单元上的 strict pass；不是检测排名。
- `B-GATE` / `B-SENSITIVITY`：门禁/敏感性，不产生“赢家”。

## 维护

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/matrix/make_matrix.py'
```

该命令只重写本目录的 CSV/Markdown，不读写实验结果。若手动编辑 CSV，请保持列名和状态词表；重新运行会覆盖手改内容。

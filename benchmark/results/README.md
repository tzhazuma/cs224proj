# `benchmark/results/` — 不可变 run 目录

所有结果以**一个 run 一个目录**存放，目录一旦生成不再修改。原始模型/工具产物可以留在各自工作目录；汇总时用 `--run-dir` 显式引用，不复制、不改写。

分层索引见 [`LEADERBOARD.md`](LEADERBOARD.md)；Tier A 与 Tier B 的详细表分别在 [`tier_a_leaderboard.md`](tier_a_leaderboard.md) 与 [`tier_b_leaderboard.md`](tier_b_leaderboard.md)。

## 目录布局

```text
benchmark/results/<tier>/<track>/<run_id>/
├── run_manifest.json      # benchmark-run-v1；Run 的身份、数据哈希、方法、执行状态
├── predictions.jsonl      # benchmark-prediction-v1；每个评估单元一行
├── metrics.json           # bench_metrics.py 生成；benchmark-metrics-v1
├── metrics.md             # 同内容的人读摘要
├── validation.json        # bench_validate.py 输出（可选但建议）
├── run.log                # 原始日志（可选；不得含密钥）
└── PROVENANCE.md          # 来源、命令、是否 derived
```

Tier A 路径：`benchmark/results/tier_a/<model>_<strategy>/<run_id>/`
Tier B 路径：`benchmark/results/tier_b/juliet_cwe401/<method>/<run_id>/`
历史路径：`benchmark/results/superseded/<group>/tier_b/.../<run_id>/`（冻结文件只移动不改写；最终汇总跳过）

Tier A 的 `legacy__*` 目录是 `bench_import_legacy.py` 生成的**派生**视图，必须保留 `legacy_import.derived_not_rerun=true`；它不是新实验。早期预留的 `legacy_secvuleval/` 名称不再使用。

## 命名

- `run_id` 必须唯一、稳定、可读：`<tier>_<track>_<model_or_tool>_<strategy>_<split>_<yyyymmdd>_<short_hash>`。
- 不要用 `latest`、`final`、`new`、`fixed` 这类会随后续运行漂移的名字。
- 同一配置重复运行 = 新 `run_id`；不能覆盖旧目录来“更新”结果。
- `legacy__<old_run_id>` 仅用于派生导入，不与新 run 混排。

## 不可变规则

1. `run_manifest.json` 与 `predictions.jsonl` 生成后只读；修正错误必须新建 run，并在 `notes` 说明。
2. `metrics.json` 可以由 `bench_metrics.py` 重算（`--force`），但它只是派生视图；原始预测不变。
3. 不允许把 mock、fixture、dry-run 写入 `results/`。`examples/` 的合成样例不是结果。
4. 不允许为了指标好看而删除失败记录；失败必须保留 `status != "ok"` 和 `error`。
5. 不允许把不同数据集、不同 tier、不同 task 的行拼成一个 leaderboard。

## 最小校验流程

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_validate.py \
  --run-dir benchmark/results/tier_a/mimo_direct/<run_id> \
  --jsonschema --json-out benchmark/results/tier_a/mimo_direct/<run_id>/validation.json'

wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_metrics.py \
  --run-dir benchmark/results/tier_a/mimo_direct/<run_id>'
```

只有 `validation.json` 的 `errors` 为空、`metrics.json` 的 `counts` 与 manifest 一致，run 才能登记为 `done_frozen`。

## 已有结果（真实派生）

| 层级 | 目录 | 内容 |
| --- | --- | --- |
| Tier A | `tier_a/<model>_<strategy>/legacy__<run>/` | 12 个派生 run：DeepSeek 与 MiMo × direct/few-shot/context × detection/pair |
| Tier A 新结果 | `tier_a/<model>_evidence/<run_id>/` | 2 个真实 run：DeepSeek / MiMo × evidence-lines + counterfactual；各 160 请求 |
| Tier A 新结果 | `tier_a/<model>_pair_joint/<run_id>/` | 2 个真实 run：180 对联合强制二选一；一个请求落成两条 side 记录，单独任务，不与分侧混排 |
| Tier A 比较 | `comparisons/tier_a/` | 18 个 `bench_compare.py` 输出：6 个模型间 + 12 个模型内策略比较 |
| Tier B | `tier_b/juliet_cwe401/<method>/<run_id>/` | 5 个传统 run：`static_clang`、`static_cppcheck`、`dynamic_asan`、`dynamic_valgrind`、`dynamic_combined` |
| Tier B 新结果 | `tier_b/juliet_cwe401/llm_mimo_xiaomi/<run_id>/` | MiMo 140 test 的正式 **postleakfix** run，**Xiaomi 官方端点**；不是 OpenCode Go |
| Tier B 新结果 | `tier_b/juliet_cwe401/hybrid_<model>_<method>/<run_id>/` | 10 个 canonical **hybrid v2** run：2 模型 × {direct, static, dynamic, combined, shuffled} × 140；共 1,400 请求 |
| Tier B 新结果 | `tier_b/juliet_cwe401_repair/<model>/<run_id>/` | 2 个真实 run：70 bad 修复；58 可观测单元 strict pass，12 不可观测不入分母 |
| 历史（排除） | `superseded/leakage_sensitive_v1/...`、`superseded/pre_postleakfix_harness/...` | 11 个被取代的 run（10 hybrid v1 + 1 旧 harness LLM）；冻结文件只移动不改写，`discover_runs()` 跳过，不进入主 leaderboard |
| 汇总 | `LEADERBOARD.md` / `final_summary.json` | **最终统一汇总**：Tier A/B 分层、evidence、pair-joint、LLM/hybrid、repair、成本/延迟/配对统计 |
| 历史汇总 | `tier_a_summary.json` / `tier_a_leaderboard.md` | 整合前 12-run Tier A 视图（保留，不是最终索引） |
| 历史汇总 | `tier_b_summary.json` / `tier_b_leaderboard.md` | 整合前 5-tool Tier B 视图（保留，不是最终索引） |

Tier A 的原始 run 仍在 `runner/runs/test_v1_*`，本目录不复制、不覆盖；派生只复制预测与标签，不调用模型。Tier B 的原始产物仍在 `traditional/static/runs/` 与 `traditional/dynamic/runs/`，`bench_collect_tier_b.py` 只读映射。所有 run 的 `PROVENANCE.md` 记录源文件哈希。

Round-2 新结果由 `benchmark/tools/bench_import_round2.py` 只读导入：`evidence_prompt/`、`pair_joint/`、`hybrid/`、`juliet_llm/`、`juliet_repair/` 的原始目录均未改写。导入共生成 17 个派生 canonical run；每个 run 都经过 `bench_validate.py --jsonschema` 与 `bench_metrics.py`。Tier B 的 canonical hybrid 是 **v2**（`hybrid/runs/hybrid_v2_*`，leak-fixed 输入包 `hybrid/inputs_v2/units.jsonl`）；v1 的 10 个派生 run 以及 postleakfix 之前的旧 harness LLM run 已移动到 `superseded/`，文件未改写，且被最终汇总跳过。`pair_joint` 的一个联合请求落成两条 canonical side 记录，成本/墙钟各 50%，token/latency 只记一次，避免重复计数；其任务标签为 `extensions.forced_choice=true`，不得与分侧 pair 合并。

最终汇总同时报告两种成本口径：`cost.usd_known_sum`（各 run 记录值）与 `cost.normalized.usd_sum`（按固定 provider 价卡从逐条 usage 重算：DeepSeek `0.15/0.60/0.003`、MiMo `0.14/0.28/0.0028` USD/1M tokens）。normalized 不使用记录值回填；本地工具的 `null` 不是 0；MiMo Xiaomi 端点没有返回计费字段，其 normalized 是 reference-price 计算。

最终汇总由 `benchmark/tools/bench_final_summary.py` 生成 `LEADERBOARD.md` 与 `final_summary.json`。它重新计算 valid-only/strict、coverage、成本/延迟、McNemar/Holm 与 cluster bootstrap，不依赖手抄数字。

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
python3 benchmark/tools/bench_import_legacy.py \
  --run-dir runner/runs/test_v1_direct_independent \
  --out-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent'
```

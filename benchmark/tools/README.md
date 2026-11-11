# `benchmark/tools/` — 可执行工具

所有工具只依赖 Python 3 标准库；`bench_validate.py --jsonschema` 额外使用 `jsonschema`（可选）。所有命令在 WSL 中执行。

| 工具 | 作用 | 退出码 |
| --- | --- | --- |
| `bench_validate.py` | 校验 `run_manifest.json` + `predictions.jsonl` 的结构/一致性；可选 JSON Schema | 0=通过；2=有 errors |
| `bench_validate_dataset.py` | 校验数据集卡与实际文件/哈希/计数一致（当前为 Juliet Tier B） | 0=通过；2=有 errors |
| `bench_metrics.py` | 计算 detection/pair/leak 指标、bootstrap、成本；写 `metrics.json/.md` | 0=成功；2=校验失败/拒绝覆盖 |
| `bench_compare.py` | 两个同数据集、同 task 的 run 做 common-valid 配对比较 + bootstrap + McNemar | 0=成功；2=不可比/拒绝覆盖 |
| `bench_import_legacy.py` | 只读转换 `runner/runs/test_v1_*`（DeepSeek 或 MiMo）到统一 schema；不改原文件 | 0=成功；2=导入失败 |
| `bench_import_round2.py` | 只读导入 evidence/pair-joint/hybrid/LLM/repair；`--measure` 同时校验 + 写 metrics | 0=成功；2=导入/校验失败 |
| `bench_collect_tier_b.py` | 只读映射 `traditional/static` 与 `traditional/dynamic` 到冻结 Juliet 200 单元；写统一 run | 0=成功；2=映射失败/拒绝覆盖 |
| `bench_tier_a_summary.py` | 读旧 12 个 Tier A run + 18 个 comparison；写历史 `tier_a_summary.json` / leaderboard | 0=成功；2=结构/数据不符 |
| `bench_tier_b_summary.py` | 读旧 5 个 Tier B run；写历史 test/all/runtime/coverage 视图 | 0=成功；2=结构/数据不符 |
| `bench_final_summary.py` | 读 34 个 canonical run；重算统一指标与配对统计；写 `LEADERBOARD.md` / `final_summary.json` | 0=成功；2=结构/数据不符 |
| `selftest.py` | 用临时合成 fixture 验证 validator + 指标算术 | 0=PASS；非 0=断言失败 |
| `bench_common.py` | 共享指标/统计/成本原语；不作为 CLI | — |

生产者 raw → canonical 的字段映射见 [`ADAPTERS.md`](ADAPTERS.md)。

## 常用命令

```bash
# 1) 自检
python3 benchmark/tools/selftest.py

# 2) 校验数据集卡（Tier B）
python3 benchmark/tools/bench_validate_dataset.py --jsonschema

# 3) 校验（建议把报告写进 run 目录）
python3 benchmark/tools/bench_validate.py \
  --run-dir <run> --jsonschema --json-out <run>/validation.json

# 4) 指标（默认写 <run>/metrics.json 与 metrics.md）
python3 benchmark/tools/bench_metrics.py --run-dir <run>

# 5) 两个 run 比较（必须同 dataset.sha256 / task）
python3 benchmark/tools/bench_compare.py \
  --run-a <runA> --run-b <runB> --out <comparison.json>

# 6) 旧 run 派生（不改 runner/runs）
python3 benchmark/tools/bench_import_legacy.py \
  --run-dir runner/runs/test_v1_direct_independent \
  --out-dir benchmark/results/tier_a/deepseek_direct/legacy__test_v1_direct_independent

# 7) Tier B 静态/动态 → 冻结 200 单元
python3 benchmark/tools/bench_collect_tier_b.py
for d in benchmark/results/tier_b/juliet_cwe401/*/*/; do
  python3 benchmark/tools/bench_validate.py --run-dir "$d" --jsonschema --json-out "$d/validation.json"
  python3 benchmark/tools/bench_metrics.py --run-dir "$d" --bootstrap 10000
done

# 8) round-2 导入 + 校验 + 指标
python3 benchmark/tools/bench_import_round2.py --measure

# 9) 最终统一 leaderboard（推荐入口）
python3 benchmark/tools/bench_final_summary.py

# 10) 历史分层 leaderboard（不是最终索引）
python3 benchmark/tools/bench_tier_a_summary.py
python3 benchmark/tools/bench_tier_b_summary.py
```

## 保证

- **不编造缺失值**：`status != "ok"` 的 `y_pred` 为 null；指标里没有 imputation。
- **不覆盖旧结果**：`bench_metrics`/`bench_compare` 默认拒绝覆盖已有输出；`bench_import_legacy` 默认拒绝非空目录。
- **不跨数据集比较**：`bench_compare` 在 dataset SHA-256 或 task 不同时直接失败。
- **不隐藏失败**：`metrics.json` 的 `counts.by_status`、`invalid`、`coverage`、`missing_units` 都保留；strict 与 valid-only 分开。
- **可复现**：bootstrap 默认 10,000 次、seed 42；结果 JSON 记录 settings、输入哈希。

## 指标口径

严格按 `benchmark/PROTOCOL.md` §7–§10：

- 比例 → Wilson 95%；
- F1/macro-F1/MCC/BA → cluster percentile bootstrap；
- 配对二值正确性 → exact McNemar；
- 成本 → known sum + unknown records，不补零；
- Tier B 动态 clean + 低覆盖 → `inconclusive`，不是 TN。

## 修改工具时

- 先改 `PROTOCOL.md` 语义和 schema 版本，再改代码；
- 跑 `selftest.py`；
- 用旧 run 导入做回归（P/R/F1/DA 应与旧 `metrics.json` 一致）；
- 不要为了新结果改旧指标定义；新增指标必须另起字段并在协议登记。

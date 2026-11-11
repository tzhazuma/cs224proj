# `benchmark/results/superseded/` — 历史 run（不进入主 leaderboard）

这里保存**曾经导入过、但已被正式 canonical run 取代**的派生 run。文件本身没有改动：run 目录只是从
`benchmark/results/tier_b/...` 原样移动到这里，`run_manifest.json`、`predictions.jsonl`、`metrics.json`、
`validation.json` 都保持冻结。

`bench_final_summary.py` 的 `discover_runs()` 明确跳过 `results/superseded/` 下的任何 manifest，所以这些
run 不会进入 `LEADERBOARD.md`、`final_summary.json` 或任何 Tier B 比较/配对统计。

## 1. `leakage_sensitive_v1/` — hybrid v1

- 源实验：`hybrid/runs/hybrid_v1_<model>_<method>/`（10 个 run × 140 = 1,400 请求）。
- 取代者：`hybrid/runs/hybrid_v2_<model>_<method>/`，导入为
  `tier_b/juliet_cwe401/hybrid_<model>_<method>/`。
- 原因：v1 的 6 个 good 单元源码里仍有字面量 `"Benign, fixed string"`。该短语是 Juliet 的标签提示词，
  会让模型走“看到 benign/fixed 就判安全”的捷径。v2 的 cleaner 把它中和为
  `"unit, unit string"`，并换用新 prompt 版本 `hybrid-v2-juliet-llm-binary-2026-11-12.2` 和独立输入包
  `hybrid/inputs_v2/units.jsonl`。因此 v1 属于 **leakage-sensitive historical**，只能作为修复前对照，
  不能与 v2 混排成同一个主表。
- 影响：v1 的 DeepSeek combined 曾录得满分，该值直接受这 6 个 shortcut 单元影响；v2 为 136/140（97.14%）。
  旧满分不得进入任何主表、摘要或报告结论。正式数字以 `LEADERBOARD.md` / `final_summary.json` 的 v2 行为准。
- 旧逐 run 数字仅保留在各自目录的 `metrics.json` / `predictions.jsonl` 中，本 README 和主 leaderboard 不重述。

## 2. `pre_postleakfix_harness/` — MiMo Xiaomi 旧 harness run

- 源 run：`juliet_llm/runs_superseded/20261111T204701Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix`。
- 取代者：`juliet_llm/runs/20261111T205533Z_test_mimo-v2.6-flash_test_xiaomi_official_postleakfix`
  （正式 postleakfix Xiaomi 140；`_repro` 同分复现）。
- 原因：204701Z 使用的是旧 `prompting.py`（SHA-256 `58caf768...`）；正式 run 使用修复后的
  `prompting.py`（`2fe5f818...`），prompt 契约已变化。该 run 不是正式 Xiaomi 140，故标 superseded，
  不是“模型能力”结果。
- 旧值（仅审计用，不在主表重述）：131/140（93.57%）；正式 postleakfix 为 133/140（95.00%）。
- 端点提醒：正式 MiMo Xiaomi run 的 endpoint 是 `https://api.xiaomimimo.com/v1/chat/completions`，
  不是 OpenCode Go；报告必须标注。

## 3. 为什么移动而不是删除

审计需要能追溯“旧数字从哪里来、为什么被替换”。删除会丢失 provenance；保留在主目录又会被
`discover_runs()` 扫描成重复 `method_id`。移动到 `superseded/` 同时满足可追溯和主表唯一性。

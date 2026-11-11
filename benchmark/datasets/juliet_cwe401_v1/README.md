# `juliet_cwe401_v1/` — 冻结数据卡

本目录只放数据卡，不放 Juliet 原始源码或编译产物。上游数据在 `juliet/`（另一工作流）；本卡片通过哈希引用它。

| 字段 | 值 |
| --- | --- |
| dataset_id | `juliet-cwe401-v1.3-subset-v1` |
| units | 200（100 bad / 100 good） |
| groups | 100 |
| families（cluster） | 42 |
| dev / test | 60 units / 13 families；140 units / 29 families |
| units manifest | `juliet/subset_units.jsonl`，SHA-256 `4827d1…ac24` |
| upstream manifest | `juliet/manifest.json`；上游会重新生成，不在数据卡中固定哈希；用 `juliet/FREEZE.json` 核对 |
| freeze | `juliet/FREEZE.json` |
| archive | Juliet C/C++ v1.3，SHA-256 `ada9d7…38eb` |

**动态 oracle 注意**：上游验证 200/200 编译/宏/符号 gate 通过，但 178/200 有 runtime label 支持；22 个 bad unit 没有观察到 LSan leak。动态方法必须把这些 clean 当作 `inconclusive`，不能算 TN。数据集标签仍是 `juliet_intended` 的 bad。

**B9 状态（2026-11-12）**：`partial`。sanitizer/prompt 审计 200/200 通过；label-only baseline 尚未跑。LLM/混合结果可以报告，但必须带此 caveat；B4（DeepSeek Juliet LLM）与 B8（cascade）仍无结果。

更新规则：不得就地改本文件；新数据/新清洗必须新建 `juliet-cwe401-v2` 并重写数据卡与哈希。

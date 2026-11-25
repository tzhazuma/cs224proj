# HANDOFF — `codeql_triage/`

## 1. 交付摘要

- **范围**：CodeQL 告警的所有权/逃逸分流；只改 `codeql_triage/`。
- **完成**：MiMo `mimo-v2.6-flash` 的 test 140 全量 direct + triage v1 + triage v2 + 91 告警复核；23 FP 逐条分析；TP 误删；成本；与 direct 的关系。
- **未完成**：DeepSeek。官方 402、OpenCode Go 401、Qwen Token Plan 403；已保留真实失败证据，没有伪造数字。凭证恢复后可直接复跑（见 §4）。
- **未执行**：`git` / `gh` / push。父层可只读导入 `benchmark_export.json`。

## 2. 关键结果（MiMo，140）

| 策略 | TP/FP/TN/FN | macro-F1 | MCC | TP 误删 |
| --- | --- | ---: | ---: | ---: |
| CodeQL | 68/23/47/2 | 0.8173 | 0.6739 | — |
| direct | 69/5/65/1 | 0.9571 | 0.9158 | — |
| triage v1 | 61/5/65/9 | 0.8999 | 0.8013 | 7/68 |
| triage v2 | 68/3/67/2 | 0.9643 | 0.9287 | 0/68 |
| v2 + 复核/文本规则 | **68/0/70/2** | **0.9857** | **0.9718** | **0/68** |
| cascade（告警复核 + 无告警 direct） | 70/2/68/0 | 0.9857 | 0.9718 | 0/68 |

- 最终 vs CodeQL：+0.1684 macro-F1，95% CI `[+0.1084, +0.2349]`，p<1e-6。
- 最终 vs direct：+0.0286，95% CI `[-0.0072, +0.0714]`，p=0.289，**不显著**。
- 23 FP：v1 撤销 18，v2 撤销 20，最终撤销 23；剩 3 个 `_22` 是字段自相矛盾，不是所有权推理失败。
- 7 个 v1 误删 TP 全是 `malloc_realloc_*`；v2 显式 realloc 失败规则后 0 误删。
- 2 个 CodeQL FN 是 `_82` compile_error；triage 无法恢复，cascade 用 direct 补回但引入 2 FP。

## 3. 产物地图

```text
codeql_triage/
├── README.md / REPORT.md / LITERATURE.md / GAP_ANALYSIS.md / IDEAS.md
├── benchmark_export.json
├── common.py / run_triage.py / verify.py / analyze.py / selftest.py
├── run_with_kimi_config.py / verify_with_kimi_config.py
└── runs/
    ├── test140_mimo_xiaomi_v1/        # v1 + direct + analysis
    ├── test140_mimo_xiaomi_v2/        # v2 + direct + verify + analysis
    ├── blocked_deepseek_official_v1/  # 402 evidence
    └── blocked_deepseek_opencode_go_v1/ # 401 evidence
```

优先看：

- `runs/test140_mimo_xiaomi_v2/analysis/comparison.md` — 主表 + 统计。
- `runs/test140_mimo_xiaomi_v2/analysis/fp23.md` — 23 个 FP 逐条。
- `runs/test140_mimo_xiaomi_v2/analysis/tp_deleted.md` — 0 误删。
- `runs/test140_mimo_xiaomi_v1/analysis/tp_deleted.md` — v1 的 7 个误删及理由。
- `runs/test140_mimo_xiaomi_v2/analysis/verification.md` — 3 个翻转为 `_22`。
- `runs/test140_mimo_xiaomi_v2/analysis/cost.md` — 成本/延迟。
- `runs/test140_mimo_xiaomi_v2/analysis/compile_errors.md` — 4 个编译失败单列。

## 4. DeepSeek 复跑（凭证恢复后）

官方 DeepSeek（充值后）：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider deepseek -- \
  --provider deepseek --model deepseek-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/test140_deepseek_official_v2 --concurrency 6
python3 codeql_triage/analyze.py \
  --run-dir codeql_triage/runs/test140_deepseek_official_v2 \
  --out codeql_triage/runs/test140_deepseek_official_v2/analysis \
  --label deepseek-flash-official-v2
```

OpenCode Go（新 key 后）：

```bash
python3 codeql_triage/run_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider opencode-go -- \
  --provider opencode-go --model deepseek-v4.1-flash \
  --condition all --prompt-version v2 \
  --out-dir codeql_triage/runs/test140_deepseek_opencode_v2 --concurrency 6
```

注意：

- 现在跑会在第一条请求处返回 402/401；`run_triage.py` 会停止并写 `manifest.json`，不会生成 140 条伪结果。
- `--prompt-version v2` 是当前最佳一次性提示；v1 会复现 7 个 TP 误删，不建议作为最终。
- 若要复核：

```bash
python3 codeql_triage/verify_with_kimi_config.py \
  --kimi-config ~/.kimi-code/config.toml --kimi-provider deepseek -- \
  --run-dir codeql_triage/runs/test140_deepseek_official_v2 \
  --provider deepseek --model deepseek-flash \
  --out-dir codeql_triage/runs/test140_deepseek_official_v2/verify --concurrency 6
```

## 5. 自检与合规

- `python3 codeql_triage/selftest.py` → `all checks passed: 140 units, 68 CodeQL TP, 23 CodeQL FP, 4 compile_error, 420 distinct prompts`。
- 提示审计：`juliet_llm.cleaning.PROMPT_FORBIDDEN_PATTERNS`，11 类 token 0 命中；unit_id/group_id/CWE-401 不入 prompt。
- 请求文件不含 Authorization；manifest 只有 `api_key_present` / `api_key_value_stored=false`。
- 已扫描 `codeql_triage/` 产物中的 `sk-`、`Bearer`、`Authorization:`、`api_key` 值：**0 个文件包含任何已配置的 key**；`requests_*.jsonl` 中没有 `Authorization` 头；`results` 中没有 `Bearer` token。
- 未修改父目录已有结果；只新增 `codeql_triage/`。
- WSL Ubuntu，Python 3.14；`httpx` 由 `runner/secvul_runner` 提供。

## 6. 已知遗留

1. **DeepSeek 无结果**：必须等凭证；不能把 MiMo 的数字写成 DeepSeek。
2. **最终 vs direct 不显著**：不要把 +0.0286 写成“显著更好”。
3. **复核有锚定**：91/91 不是独立盲审；文本规则同分。
4. **Juliet 记忆化**：需要结构变异/真实项目验证。
5. **2 个 FN 是 compile_error**：triage 不能恢复；cascade 只是绕过。
6. **单次采样**：没有方差/校准；建议 3 次重复。
7. **证据字段未逐条人评**：只有最终标签可核。
8. **成本是配置价**：不是发票；无人类复核成本。
9. **只 CWE-401/Juliet**：不能外推到真实项目或其它 CWE。
10. **direct 复现差异**：本次 69/5/65/1，既有 `juliet_llm` 68/5/65/2；差 1 个 `malloc_realloc_int64_t_18__bad`，不能归因于提示。

## 7. 建议父层如何“推送”

- 不要改 `benchmark/results/LEADERBOARD.md` 的主表；本目录是 Tier B 扩展，不是父协议的新主行。
- 若要导入 `benchmark/extensions`，使用 `benchmark_export.json`，并保留 `limitations` 字段；DeepSeek 行必须标 `blocked`，不能填数。
- 报告中最值得引用的三句话：
  1. v1 的 7/68 TP 误删说明“LLM 告警裁决”必须报告 TP deletion，不能只看 FP 撤销。
  2. v2 的 0/68 与 20/23 说明提示中的 realloc 失败/字段极性是主要因素，不是模型规模。
  3. 最终 68/0/70/2 显著优于 CodeQL，但不显著优于 direct；“CodeQL+LLM”是操作点选择，不是全面 SOTA。

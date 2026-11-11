# qualitative：定性案例筛选与导出

本目录只负责**从已完成的 SecVulEval 运行中筛选并导出真实定性案例**。它不调用任何模型 API，不重新跑实验，不修改 `runner/`、`splits/`、`analysis/`、`report/` 或其他目录。

- 脚本：`qualitative/build_cases.py`（仅 Python 标准库）
- 正式输出：`qualitative/cases.json`、`qualitative/cases.md`
- 中间预览：`qualitative/cases.partial.json`、`qualitative/cases.partial.md`

## 1. 输入

正式模式读取以下六个冻结测试运行：

```text
runner/runs/test_v1_direct_independent/results.jsonl
runner/runs/test_v1_direct_pairs/results.jsonl
runner/runs/test_v1_few-shot_independent/results.jsonl
runner/runs/test_v1_few-shot_pairs/results.jsonl
runner/runs/test_v1_context_independent/results.jsonl
runner/runs/test_v1_context_pairs/results.jsonl
```

同时读取冻结划分：

```text
splits/test_detection_160.json
splits/test_pairs_180.json
```

### 完成性检查

正式模式只有在**六个运行全部 completed** 时才写出 `cases.json` / `cases.md`。对每个运行同时检查：

- `manifest.json` 存在、`status == "completed"`、`completed_at` 非空；
- `config.strategy`、`config.dataset_type` 与运行目录一致；
- `config.partial == false`、`config.limit == 0`；
- `manifest.counts` 的 expected/recorded/planned、detection/repair、by_status、by_task 与实际 `results.jsonl` 一致；
- `results.jsonl` 的记录数与冻结划分期望一致；
- `(task, sample_id)` 集合与划分完全一致，无缺失、无多余、无重复；
- `manifest.config.dataset_sha256` 与冻结划分文件的 SHA-256 一致。

只要任一运行缺失、仍在 running、`results.jsonl` 尚未写出、记录数不足或键集合不匹配，正式模式返回非零退出码并打印具体原因，**不会写正式输出**。这保证不会把半成品运行或编造的案例写进正式结果。

## 2. 运行方式

所有命令在 WSL 中执行：

```bash
cd /mnt/c/Users/tzh03/Downloads/zy

# 正式模式：六个运行全部完成后才会写 cases.json / cases.md
python3 qualitative/build_cases.py

# 只检查输入完整性，不写文件
python3 qualitative/build_cases.py --check-only

# 中间预览：只用已完成的 direct 运行，输出 cases.partial.*
python3 qualitative/build_cases.py --mode intermediate --strategies direct

# 中间预览：指定策略/数据集
python3 qualitative/build_cases.py --mode intermediate \
  --strategies direct few-shot --datasets independent pairs
```

可选参数：

| 参数 | 说明 |
| --- | --- |
| `--root` | 仓库根目录，默认 `qualitative/` 的上一级 |
| `--mode formal\|intermediate` | 默认 `formal` |
| `--strategies` | 仅中间模式；默认全部策略 |
| `--datasets` | 仅中间模式；默认两个数据集 |
| `--out-dir` | 输出目录，默认 `qualitative/` |
| `--max-code-lines` | 代码摘录最大行数，默认 45 |
| `--max-code-chars` | 代码摘录最大字符数，默认 8000 |
| `--check-only` | 只打印输入检查结果 |

中间模式会明确标注 `formal=false`，并在 Markdown 顶部写“中间导出，不是正式结果”。`all_inputs_complete` 只表示六个运行是否都已 complete，不表示本文件使用了全部运行；中间文件是否正式仍以 `formal` 和顶部横幅为准。它只写 `cases.partial.json` / `cases.partial.md`，不会覆盖正式输出。

## 3. 案例类别与筛选规则

正式模式按固定顺序生成以下 10 个类别。每个类别先构造全部候选，再按分数降序、`unit key` 升序、`focus_side` 升序排序；已选过的单元会被跳过，避免同一案例重复。若某类别没有任何候选，正式模式报错并拒绝写输出，而不是编造案例。

| 编号顺序 | 类别 | 候选条件 | 排序要点 |
| ---: | --- | --- | --- |
| 1 | `independent_false_positive` | 独立集 `label=false`，至少一个可用策略预测 `is_vulnerable=true` | 同一错误预测的策略共识数、平均置信度、代码长度惩罚 |
| 2 | `independent_false_negative` | 独立集 `label=true`，至少一个可用策略预测 `is_vulnerable=false` | 同上 |
| 3 | `strategy_disagreement` | 同一独立 idx 至少两个可用策略有效且预测不全相同 | 不同预测类别数、置信度跨度、平均置信度 |
| 4 | `pair_both_flagged` | 同一策略对配对两侧均预测漏洞 | 同联合类别的策略共识数、两侧平均/最小置信度 |
| 5 | `pair_both_clean` | 同一策略对配对两侧均预测非漏洞 | 同上 |
| 6 | `pair_reversed` | 同一策略把漏洞侧判非漏洞、修复侧判漏洞 | 同上，并加修复侧置信度高于漏洞侧的奖励 |
| 7 | `repair_schema_invalid` | 修复记录 `status=invalid` 且 `schema_valid=false` | 所选运行中最常见的错误类型、响应长度、是否有参考修复 |
| 8 | `repair_complete_reference_mismatch` | 配对修复 `schema` 有效、`complete_function=true`、`changed_from_input=true`，且规范化文本不等于参考修复 | 目标行级相似度 0.60（避免 0.0 的无关函数和 1.0 的近似复制）、差异行数、结构校验 |
| 9 | `context_high_risk` | context 策略有效检测、`context.used=true`、预测 `is_vulnerable=true` | 置信度、上下文非空、标签一致 |
| 10 | `context_low_risk` | context 策略有效检测、`context.used=true`、预测 `is_vulnerable=false` | 同上 |

### 评分与去重

分数由可复核的固定项组成，例如：

```text
误报/漏报 = 1000 * 错误策略共识比例 + 100 * 平均置信度 - 代码长度惩罚
策略分歧 = 1000 * (不同预测类别数 - 1) + 100 * 置信度跨度 + 10 * 平均置信度 - 长度惩罚
配对失败 = 1000 * 同类策略比例 + 100 * 平均置信度 + 20 * 最小置信度 - 长度惩罚
修复无效 = 100 * 该错误出现次数 + 响应长度奖励 + 参考修复奖励 - 长度惩罚
修复不匹配 = 200 * (1 - |相似度 - 0.60|) + 差异行数奖励 + 结构奖励 - 长度惩罚
context 风险 = 100 * 置信度 + 非空奖励 + 标签一致奖励 + 配对奖励 - 长度惩罚
```

`cases.json` 的每个案例都保存 `selection.candidate_pool`、`selection.selected_rank_in_category`、`selection.score` 和 `selection.score_components`，用于说明该案例不是手工挑的“好看”样本。

### 明确不做的事

- 不把 `project`、`CWE`、`CVE`、`filepath`、`commit`、`idx` 等元数据发给模型；这些字段只出现在导出文件的分析元数据中。
- 不把模型 rationale 当作人工结论；`rationale` 原样保留并标注截断。
- 不声称参考不匹配等于修复错误；参考匹配只是规范化文本比较。
- 不声称 context 高风险/低风险案例证明了上下文推理能力；本数据集里 context 是否非空与标签相关。

## 4. 输出结构

### `cases.json`

顶层主要字段：

```json
{
  "schema_version": 1,
  "script_version": "qualitative-v1",
  "generated_at": "…",
  "mode": "formal",
  "formal": true,
  "all_inputs_complete": true,
  "no_api_calls": true,
  "case_count": 10,
  "categories_included": ["…"],
  "skipped_categories": [],
  "warnings": [],
  "caveats": ["…"],
  "inputs": {
    "run_count": 6,
    "expected_run_count": 6,
    "runs": ["每个运行的路径、状态、记录数、SHA-256、dataset SHA-256、completed_at、run_id、模型、prompt_version"],
    "datasets": {"independent": {"path": "…", "sha256": "…", "unit_count": 160}, "pairs": {"…": "…"}}
  },
  "strategies_by_dataset": {"independent": ["direct", "few-shot", "context"], "pairs": ["…"]},
  "cases": ["…"]
}
```

每个案例的主要字段：

```json
{
  "case_id": "C-01",
  "category": "independent_false_positive",
  "category_label_zh": "独立集误报（假阳性）",
  "dataset_type": "independent",
  "idx": 8632,
  "pair_id": null,
  "focus_side": null,
  "focus_repair_strategy": null,
  "label": false,
  "summary": "…",
  "facts": ["…"],
  "analysis": {"…": "类别相关的机械事实，例如 joint_by_strategy、outcomes_by_strategy"},
  "selection": {
    "rule_id": "independent_false_positive",
    "rule_description": "…",
    "candidate_pool": 8,
    "selected_rank_in_category": 1,
    "score": 1087.25,
    "score_components": {"…": "…"},
    "reused_unit": false
  },
  "sides": [
    {
      "side": null,
      "idx": 8632,
      "label": false,
      "predictions": {
        "direct": {
          "status": "ok",
          "schema_valid": true,
          "is_vulnerable": true,
          "confidence": 0.9,
          "rationale": "模型原文",
          "context": {"used": false}
        }
      },
      "outcomes": {"direct": "fp"},
      "analysis_metadata": {
        "project": "ImageMagick",
        "cwe_tokens": ["CWE-772"],
        "cve_tokens": ["CVE-2017-11310"],
        "filepath": "coders/png.c",
        "commit_id": "…",
        "note": "Analysis-only metadata. …"
      },
      "code_excerpt": {
        "segments": [{"line_start": 1, "line_end": 45, "text": "…"}],
        "omitted": [{"start": 46, "end": 155, "count": 110}],
        "total_lines": 155,
        "truncated": true,
        "text": "…"
      },
      "repair_records": {
        "direct": {
          "status": "invalid|ok",
          "schema_valid": true,
          "complete_function": true,
          "changed_from_input": true,
          "complete_and_changed": true,
          "validation": {"…": "…"},
          "fixed_function_excerpt": {"…": "…"},
          "diff_vs_input": {"text": "…", "added_lines": 3, "removed_lines": 2},
          "diff_vs_reference": {"text": "…", "added_lines": 0, "removed_lines": 0},
          "reference": {"available": true, "idx": 20782, "exact_match": false, "whitespace_collapsed_match": false, "line_similarity": 0.6},
          "raw_response_excerpt": "仅 schema 无效时保留"
        }
      }
    }
  ],
  "notes": ["…"]
}
```

配对案例的 `sides` 同时包含 `vulnerable` 和 `fixed` 两侧；独立案例只有一侧且 `side=null`。修复记录只出现在漏洞侧（独立集为唯一侧）；修复侧没有修复请求。

### `cases.md`

与 JSON 内容对应，包含：

- 运行清单与完成性；
- 案例总览表；
- 每个案例的摘要、关键事实、策略预测表、模型 rationale 原文、代码摘录、修复验证/diff、选择依据和备注。

代码摘录带行号；行号是**函数正文去缩进后的 1-based 行号**，不是源文件行号。过长函数使用头尾摘录并标注省略行数；修复 diff 使用统一 diff 格式。

## 5. 修复验证口径

修复记录保留运行器已有的结构校验字段：

- `schema_valid`：输出是否符合修复 JSON schema；
- `complete_function`：是否是完整函数、分隔符是否平衡、是否不是 diff/Markdown；
- `changed_from_input`：规范化后是否与输入不同；
- `complete_and_changed`：以上两者同时成立；
- `fixed_line_count`、`balanced_delimiters`、`function_like_prefix`、`contains_markdown_fence`、`starts_like_diff` 等。

参考匹配只对配对集的漏洞侧计算：

- `exact_match`：`normalize_code(fixed_function) == normalize_code(reference_fixed)`；
- `whitespace_collapsed_match`：折叠空白后是否相等；
- `line_similarity`：行级 `difflib.SequenceMatcher` 比率。

这些字段是**结构/文本代理**，不是修复正确率，也不是行为等价性验证。`complete_and_changed` 只说明输出可用且有改动；`reference mismatch` 只说明文本不同，不能推出修复错误。本目录不做人工复核，也不把模型说明当作事实。

## 6. 中间导出

中间模式用于在正式六运行未齐时检查脚本和单策略导出：

```bash
python3 qualitative/build_cases.py --mode intermediate --strategies direct
```

- 只使用已 complete 的指定运行；
- 缺少的策略/数据集会写入 `skipped_categories` 和 `warnings`；
- 需要至少两个策略的“策略分歧”会跳过；
- 没有 context 运行时不生成 context 高低风险案例；
- 输出固定为 `cases.partial.json` / `cases.partial.md`，不会覆盖 `cases.json` / `cases.md`。

中间导出中的案例仍然是真实运行结果，但它不是正式六运行对比结果，不能当作最终结论。

## 7. 失败与“不编造”保证

- 正式模式在输入不齐时返回退出码 2，并列出缺失/未完成/不一致的运行和字段。
- 正式模式在任一类别没有候选时返回退出码 2，并列出空类别；不会用近似样本冒充。
- 所有案例都来自 `results.jsonl` 的真实记录；`rationale`、`fixed_function`、错误信息均为原始字段或原始字段的截断。
- 代码和 diff 只做摘录/截断，不做改写；截断处有显式标记。
- 没有 API 调用，没有 mock 数据，没有手工填写的模型输出。

## 8. 验证记录

已执行（WSL，Python 3 标准库）：

```bash
python3 -m py_compile qualitative/build_cases.py
python3 qualitative/build_cases.py --check-only
python3 qualitative/build_cases.py --mode intermediate --strategies direct
python3 qualitative/build_cases.py --mode intermediate --strategies direct few-shot
python3 qualitative/build_cases.py
```

验证结果：

- `py_compile` 通过；
- 六个运行的 `inspect_run` 均通过记录数、键集合、manifest counts、dataset SHA-256 检查：direct 288/540、few-shot 288/540、context 288/540，全部 `complete`；
- direct-only 中间导出生成 7 个案例（缺少策略分歧和 context 两类）；
- direct+few-shot 中间导出生成 8 个案例（缺少 context 两类）；
- 正式模式在 context 运行未完成时按预期拒绝写 `cases.json` / `cases.md`；
- 六个运行完成后，正式导出生成 10 个案例，覆盖全部 10 个类别，无空类别；
- 用独立脚本逐案例回查 `results.jsonl` 与冻结划分：idx/pair_id、project/CWE、各策略预测/置信度/rationale、修复 validation、参考匹配、代码摘录行号均一致，0 个错误；
- 同一输入下重复运行（输出到 `/tmp`）的 `cases` 数组与 `selection` 完全一致，选择是确定性的。

## 9. 当前状态

正式 `cases.json` / `cases.md` 已由六个 completed 运行生成：

- `all_inputs_complete=true`、`inputs.run_count=6`；
- 10 个案例：C-01 误报、C-02 漏报、C-03 策略分歧、C-04 both_flagged、C-05 both_clean、C-06 判反、C-07 修复 schema 无效、C-08 完整且不同但参考不匹配、C-09 context 高风险、C-10 context 低风险；
- 所有案例均来自真实 `results.jsonl`，没有 API 调用、mock 或手工填写的模型输出；
- 六个运行共有 102 条 schema-invalid 记录（direct 19+29、few-shot 1+2、context 20+31），已作为运行警告保留；这些是真实模型输出，不是缺失数据。

`cases.partial.*` 是 direct-only 中间预览，只用于验证单策略导出流程；正式结论以 `cases.json` / `cases.md` 为准。

## 10. 文件清单

| 文件 | 说明 |
| --- | --- |
| `build_cases.py` | 筛选、校验、导出脚本（仅标准库） |
| `cases.json` | 正式案例数据（六运行全部完成后生成） |
| `cases.md` | 正式案例报告（六运行全部完成后生成） |
| `cases.partial.json` | 中间预览数据（明确标注非正式） |
| `cases.partial.md` | 中间预览报告（明确标注非正式） |
| `README.md` | 本说明 |

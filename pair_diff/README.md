# Pair-diff：差分引导、先列变更、位置去偏的配对评估

本目录回答 `pair_debias` 留下的一个问题：**开放四分类的 66% 已经不算高，但把两个版本的实际差异直接摆出来、并要求模型先列出语义变化，能否把“跨版本推理”从“选字母/选较短”里分离出来？** 同时它要排除一个平凡解释：diff 只是让提示变长。

在冻结的 180 对 SecVulEval 测试集上，本目录新增两个条件族，每族都跑 A/B 正反两序：

| 条件 | 输入 | 作用 |
| --- | --- | --- |
| `diff_fwd` / `diff_rev` | 两份完整代码 + 从 A 到 B 的 unified diff + 变更清单要求 | 处理组 |
| `ctrl_fwd` / `ctrl_rev` | 两份完整代码 + **token 长度匹配、内容为空**的占位块 + 同样的变更清单要求 | 长度/格式对照 |
| `open_fwd` / `open_rev` | 已发布的 `pair_debias` 开放四分类（无 diff、无变更清单） | 外部基线，只读复用 |

三个条件共用同一套开放判定（`A` / `B` / `both` / `neither`）、同一套证据规则和同一个位置映射。`diff − ctrl` 是 diff 内容效应；`ctrl − open` 是“提示变长 + 变更清单指令”的效应；`diff − open` 是总效应。只有 `diff > ctrl` 且 `diff` 在“较短版本是错误答案”的子集上更好，才支持“diff 减少了长度捷径，而不是只增加提示长度”。

所有数字来自真实 provider 调用和落盘的 `results.jsonl`；没有 mock、fixture 或手填结果。本目录**没有修改** `pair_joint/`、`pair_debias/`、`runner/`、`splits/` 或任何既有 run；只读导入了它们的冻结数据、位置映射、统计函数和凭证/代理处理。

## 1. 设计

### 1.1 两序与位置

- `*_fwd`：直接复用 `pair_joint` 的冻结 `position_map.json`（90/90）。
- `*_rev`：逐对交换 `vulnerable_slot` 与 `fixed_slot`，仍是 90/90。
- 映射只写入运行目录的 `position_map.json`；prompt 不含 pair_id、idx、commit、filepath、func_name、CVE/CWE 列表或槽位标签。
- diff 的方向**始终是 A → B**。正向时它是 vulnerable→fixed，反向时它是 fixed→vulnerable；方向跟随槽位交换，因此不能直接泄漏标签。若模型把 diff 的 `+++` 侧当成“已修复”，会表现为可测量的位置/方向偏差，而不是数据泄漏。
- system prompt 明确说明方向任意、target 侧不一定更新/已修复/更安全；交换重复用于检测这一点。

### 1.2 变更清单（changes-first）

输出 schema：

```json
{
  "semantic_changes": [
    {"summary": "...", "a_lines": [12], "b_lines": [12], "security_relevant": true}
  ],
  "vulnerable_version": "A",
  "confidence": 0.8,
  "evidence": [{"version": "A", "line": 12, "code": "..."}],
  "rationale": "..."
}
```

- `semantic_changes` 必须是**第一个键**、非空数组；每个条目要有摘要、A/B 行号（可为空数组）、`security_relevant` 布尔。
- 只允许格式/空白/注释/无行为重构时，用一个 `security_relevant=false` 的条目说明；不要求编造漏洞。
- 判定仍允许 `A`/`B`/`both`/`neither`；证据规则与 `pair_debias` 相同。
- 合规性是**单独指标**，不进入主 DA：`changes_first`（JSON 首键）、`changes_before_verdict_raw`（原文顺序）、`schema_exact`、`grounded_item_rate`、`cited_line_precision`、`changed_line_recall`。
- 接地以 difflib 的实际变更行集合为参考：条目至少引用一条真实变更行才算接地；引用行精确率 = 真实变更行引用数 / 全部引用行数；召回率 = 被覆盖的真实变更行 / 全部真实变更行。它评价“是否真的列出了变化”，不评价自然语言摘要的语义质量。

### 1.3 长度对照

- 先生成 diff 块 `<DIFF>...</DIFF>`。
- 用 `tiktoken` 的 `cl100k_base` 作为代理 tokenizer，生成 `<CHANGE_NOTES>` 占位块，目标 token 数与 diff 块一致；占位块内容为“no information about either revision”的重复行，不含任何代码或安全提示。
- 两条件的 system prompt、两份完整代码、user template 的其余部分逐字节相同；只有 `{change_block}` 不同。因此总提示长度差 = 两个块的 token 差。
- 代理不是 provider tokenizer；分析阶段用 API 返回的 `prompt_tokens` 复核每对的实际差异，并给出 `|ctrl−diff|/diff ≤5%` 的匹配子集，在该子集上重做 diff−ctrl。
- 占位块会明确告诉模型“没有机器生成的变更注释，请直接比较两个版本”。这可能改变模型的谨慎程度；如果 diff 仍然胜出，这个比较对 diff 是保守的。反过来，如果 ctrl 的弃权率明显更高，必须把 DA 与 committed DA、H 错误子集一起读。

### 1.4 条件与运行

| 条件 | 模型 | 每模型记录 | 来源 |
| --- | --- | ---: | --- |
| `diff_fwd` / `diff_rev` | DeepSeek V4.1 Flash, MiMo V2.6 Flash | 360 | 本目录新跑 |
| `ctrl_fwd` / `ctrl_rev` | 同上 | 360 | 本目录新跑 |
| `open_fwd` / `open_rev` | 同上 | 360 | `pair_debias` 已发布，只读 |

全量 4 个新条件 × 2 模型 × 180 = **1,440 条新记录**；加 `pair_debias` 的 720 条开放记录用于比较，共 2,160 条记录。pilot 为 8 对 × 4 条件 × 2 模型 = 64 条新记录。

### 1.5 状态与关键结果（2026-11-22）

| 项目 | 结果 |
| --- | --- |
| 自检 | `python3 pair_diff/selftest.py` → `all checks passed (6385 assertions)` |
| 全量记录 | **1,440 条 = 8 runs × 180**；全部 `ok`，0 invalid，0 error |
| 完整性 | 8 个 run 的 `leak_audit.json` 全部 `wrapper_clean_all=true`、`slot_leak_all=false`；180/180 diff 方向 A→B |
| 长度匹配 | 中位 ctrl/diff prompt tokens：DeepSeek 0.9928（179/180 对 ≤5%），MiMo 1.0077（180/180） |
| 成本 | 配置价 **$1.156871**；4,366,678 prompt tokens / 453,037 completion tokens |
| 结果 | `results/`；中文报告 `report.md` |

主结果（180 对；交换一致 DA 要求正反两序都判对）：

| 模型 | diff | ctrl | open | diff−ctrl（Holm p） | diff−open（Holm p） |
| --- | ---: | ---: | ---: | ---: | ---: |
| DeepSeek | 62.22% | 60.00% | 55.56% | +2.22 pp（1.0000） | +6.67 pp（0.0855） |
| MiMo | 60.56% | 62.22% | 58.33% | −1.67 pp（0.9053） | +2.22 pp（1.0000） |

读法：

- **没有 Holm 后显著的 diff 优势。** diff 相对长度匹配对照、相对 `pair_debias` open 的交换一致 DA 差都没有通过 Holm；DeepSeek 的 +6.67 pp 原始 p=0.0428，但 Holm 后 0.0855。
- **committed 子集有内容信号，但被弃权抵消。** diff 在 committed 子集上比“选较短”高 +7.97 到 +11.81 pp（DeepSeek）、+8.70 到 +10.29 pp（MiMo）；但主 DA 按 180 对计，diff 的弃权率 20.00%–24.44%，整体高于 open 的 17.22%–22.22%。
- **没有一致证据表明 diff 减少了长度捷径。** diff/ctrl 的“选较短”比例 75.17%–81.20%，不低于 open 的 73.15%–80.14%；在“较短侧必错”的 44 对上，diff−ctrl 仅 +2.27 pp（两个模型 p=1.0000）；长度匹配 ≤10% 子集上模型仍低于启发式（约 67% vs 72.9%）。
- **changes-first 的新失败模式是变更范围门控。** 变更清单没有安全相关项时，DeepSeek 20/180、MiMo 36/180 对几乎全部判 `neither`，DA=0；open 在同一批 pair 上也只有 15.00%/11.11%，说明子集本身难，但门控丢掉了少数可能答对的 pair。ctrl 有同样门控，说明它主要由“先列变更”指令驱动，而不是 diff 内容。
- **成本效率没有改善。** diff 成本约为 open 的 1.30×；相对 ctrl 正确 pair-order 仅 +1/−1，相对 open +16/+6（DeepSeek 250 vs 234，MiMo 243 vs 237）；USD/正确 pair-order 更高。

详见 `report.md`、`results/comparison.md` 与 `results/analysis_<model>.md`。

## 2. 指标

| 指标 | 定义 |
| --- | --- |
| `DA` | `correct / n`，invalid 记错；开放条件下 `both`/`neither` 属于错误（真实标签恰好一个版本有漏洞）。 |
| `committed DA` | 只以实际给出 A/B 的输出为分母的准确率。 |
| `交换一致 DA` | 正序和反序都把漏洞版本判对的比例；对位置偏差不敏感，是主终点。 |
| `语义一致率` | 两序映射到 vulnerable/fixed/both/neither 后相同的比例。 |
| `同字母率` | 两序都给出 A/B 时选择同一字母的比例；内容驱动接近 0，位置驱动接近 1，随机约 0.5。 |
| `位置偏差` | 漏洞版本在 A 与在 B 时的 DA 差；Fisher 精确检验；选 A 比例的二项检验；另报 committed 中选 B（diff target）的比例。 |
| `H 正确 / H 错误子集` | `H` = 选较短版本（等长选 A）。H 错误子集就是“较短版本不是漏洞版本”的 pair；长度捷径模型在这里接近 0。 |
| `gap` | H 正确子集准确率 − H 错误子集准确率；纯长度策略 100 pp，内容驱动且误差均匀接近 0。 |
| `选较短比例` | committed A/B 输出中选择较短版本的比例。 |
| `both+neither` | 开放弃权率，必须与 DA 一起读。 |
| `变更接地` | 见 §1.2；行号对齐 difflib 变更行。 |
| `成本` | 配置价 × provider 报告的 token；另列 provider list/allowance 快照；增量成本/额外正确对只在 Δcorrect>0 时有定义。 |

统计：

- Wilson 95% 区间；
- 精确 McNemar（配对二分类）；
- Fisher 精确检验（A/B 分侧 DA）；
- 二项检验（选 A 比例、同字母率）；
- 10,000 次 percentile bootstrap，种子 42；主区间按 `project` 聚类，配对级为敏感性；
- Holm 校正在预先声明的检验族内进行：
  - `diff_vs_ctrl`：正向、反向、交换一致（3 个）；
  - `diff_vs_open`：正向、反向、交换一致（3 个）；
  - `ctrl_vs_open`：正向、反向、交换一致（3 个）；
  - 跨模型：diff 正向、反向、交换一致（3 个）。

## 3. 文件

| 路径 | 作用 |
| --- | --- |
| `common.py` | 条件定义、unified diff、token 长度匹配占位块、开放 prompt、changes-first 解析、变更接地、证据评分、长度特征、位置映射。 |
| `runner.py` | 可恢复的真实 API runner；每对每条件一次请求；写 requests/results/metrics/position_map/leak_audit；拒绝把 API key 写入产物。 |
| `analyze.py` | 六条件指标、交换一致性、位置偏差、长度分层、H 子集、token 匹配子集、变更合规、成本、跨模型与 Holm；只读复用 `pair_debias.analyze` 的核心定义。 |
| `selftest.py` | 无网络自检：映射互补、diff 方向、占位块 token 匹配、prompt 泄漏、解析、接地、统计。 |
| `run_pair_diff.sh` | `pilot` / `full` / `analyze` / `analyze-pilot` / `selftest`。 |
| `runs/pilot_*` | 8 对开发集 pilot（4 条件 × 2 模型）。 |
| `runs/test_*` | 180 对冻结测试集（4 条件 × 2 模型）。 |
| `results/` | 全量分析 JSON/Markdown、跨模型对比、`benchmark_export.json`。 |
| `results/pilot/` | pilot 分析（仅验证接入/解析/长度匹配，不作效果证据）。 |
| `report.md` | 中文结果报告。 |

每个运行目录包含：

- `config.json`、`manifest.json`：条件、模型、prompt 版本、数据集哈希、base/position map 哈希、计数、状态、`api_key_value_stored: false`。
- `requests.jsonl`：完整 messages/body，不含 `Authorization`。
- `results.jsonl`：响应、usage、成本、延迟、解析、变更接地与证据检查。
- `position_map.json`、`leak_audit.json`、`metrics.json`、`cache/`。

## 4. 运行

凭证由 `--kimi-config` 从 `/mnt/c/Users/tzh03/.kimi-code/config.toml` 的 `opencode-go` provider 读入进程内存；不打印、不写入任何产物。也可使用环境变量 `OPENCODE_API_KEY`。

```bash
# 自检（无网络）
python3 pair_diff/selftest.py

# pilot：开发集 8 对，4 条件 × 2 模型
bash pair_diff/run_pair_diff.sh pilot

# 全量：冻结测试集 180 对，4 条件 × 2 模型
bash pair_diff/run_pair_diff.sh full

# 分析
bash pair_diff/run_pair_diff.sh analyze
bash pair_diff/run_pair_diff.sh analyze-pilot
```

`--resume` 仅在原目录/原配置指纹一致时复用缓存；`--limit` 会在 manifest/metrics 标记 `partial: true`。runner 在每次写完后扫描产物，若发现 API key 会立即报错。

价格（与既有 `pair_joint` / `pair_debias` 运行一致，2026-11-12 检查）：

| 模型 | input / 1M | output / 1M | cached input / 1M |
| --- | ---: | ---: | ---: |
| `deepseek-v4.1-flash` | $0.30 | $1.20 | $0.006 |
| `mimo-v2.6-flash` | $0.14 | $0.28 | $0.0028 |

成本按配置价与报告 token 计算；provider 的 `usage.opencode.list_cost` 快照可能处于峰谷价，报告中单列，不与配置价混用。

### WSL 网络说明

凭证、localhost 代理移除和 IPv4 优先逻辑复用 `pair_debias.runner`：只在进程内移除指向 `127.0.0.1`/`localhost` 的代理变量，只在进程内让 `socket.getaddrinfo` 优先返回 A 记录；不修改系统配置，不持久化，不记录代理值。换到网络正常的机器可删掉这两个兼容层。

## 5. 主要限制

1. **单次贪心解码**：temperature=0，没有重复采样；交换一致 DA 仍受模型输出随机性以外的因素影响。
2. **开放任务在构造上恰好一个版本含漏洞**：`both`/`neither` 在 DA 中记错；它们可能表达不确定性，因此弃权率、committed DA 与 DA 必须一起读。
3. **diff 方向固定 A→B**：方向跟随槽位交换，不能泄漏标签，但会引入“target 侧=已修复”的方向先验；正反交换检测它，不能完全消除它。
4. **长度对照是内容为空的占位块**：它匹配 token 长度和格式位置，但“没有注释”的提示可能改变谨慎程度；如果 diff 仍胜出，该比较对 diff 保守。若 ctrl 的弃权率更高，需要把 H 错误子集和 committed DA 放在主表旁边读。
5. **token 匹配是代理匹配**：`cl100k_base` 不是 provider tokenizer；分析用实际 `prompt_tokens` 复核，并给出 ≤5% 匹配子集。两者不一致时以 API 口径为准。
6. **changes-first 是单请求内的顺序约束**：用 JSON 首键和原文顺序代理“先列后判”，不是两阶段协议；合规率单独报告，主 DA 不以合规为门槛。
7. **变更接地只按行号**：它不评价摘要是否“正确理解了漏洞”，也不区分安全相关/无关变更的语义质量；只回答“有没有引用真实变更行”。
8. **长度分层/匹配子集是事后诊断**：样本量下降、统计功效降低；不是预注册基线。
9. **项目不平衡**：180 对中 `linux` 占比较大；项目聚类 bootstrap 受少数大项目影响，配对级区间作为敏感性。
10. **diff 由冻结函数体生成**：不是上游 commit patch；格式化、重命名、注释变化也会进入 `semantic_changes`，可能与“语义变化”的字面要求有张力。
11. **源码残留**：1/180 对的函数体注释含 `CVE-2017-17969`（两侧相同，不指示槽位）；未改写源码。diff 可能把该注释带入 `-`/`+` 行，但两侧相同，不构成槽位泄漏。

## 6. 结果

全量结果、逐对数据与限制见：

- `report.md`：中文报告；
- `results/summary.md`：主表；
- `results/comparison.md`：跨模型、关键分解与成本；
- `results/analysis_<model>.json`：逐对结果与完整指标；
- `results/benchmark_export.json`：供上层汇总的紧凑导出。

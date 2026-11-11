# SecVulEval 统计分析（analysis/）

本目录负责 CS224 SecVulEval 项目的**统计分析与自动填表准备**：读取 `runner/` 产出的真实运行目录，计算检测与配对指标、区间、McNemar/Holm 检验和 context 分层，并生成机器可读的 `aggregation.json` 与供报告使用的 `aggregation.md`。

> **当前状态：没有真实模型运行结果。**
>
> 真实 DeepSeek 调用因用户 OpenCode Go key 过期返回 401；本项目禁止用 mock、fixture 或估计值填充正式结果表。当前 `analysis/aggregation.json` 的 `status` 为 `no_real_runs`，包含分析配置、空运行清单、数据集上下文审计、M3 伪影风险与限制，不包含任何模型性能数值。
>
> 临时合成 fixture 只用于验证管线，运行后自动删除，不进入正式 aggregation，也不得引用为模型结果。

## 1. 文件

| 文件 | 用途 |
| --- | --- |
| `analyze_runs.py` | 主分析脚本；发现运行目录、连接数据集、计算指标/区间/检验、生成 JSON+Markdown |
| `stats.py` | 仅标准库的统计函数：Wilson、混淆矩阵、macro-F1、balanced accuracy、MCC、配对联合指标、精确 McNemar、Holm、cluster bootstrap |
| `selftest.py` | 临时合成 fixture 的端到端自检；运行后清理临时目录 |
| `aggregation.json` | 最近一次正式聚合结果；当前为 `no_real_runs` |
| `aggregation.md` | 同一结果的中文可读版本；当前无性能表 |
| `README.md` | 本文件 |

脚本只使用 Python 标准库，不依赖 numpy/scipy/pandas；已在 WSL Python `3.14.8` 下验证。所有命令都应在 WSL 中执行，不要用 Windows Python 代替。

## 2. 输入约定

### 2.1 运行目录

分析器扫描 `runner/runs/`（可用 `--runs-root` 改）下同时包含 `metrics.json` 和 `results.jsonl` 的目录。也支持 `--run PATH` 显式指定，可重复。

必需条件：

- `metrics.json` 的 `schema_version == 1`；
- `metrics.run` 含 `dataset_type`（`independent` / `pairs`）、`strategy`（`direct` / `few-shot` / `context`）、`task`（`detection` / `both`）、`model`；
- `results.jsonl` 每行一个 JSON 对象，检测记录含 `task="detection"`、`label`、`status`、`parsed.is_vulnerable`；
- 配对记录还含 `pair_id` 与 `side`（`vulnerable` / `fixed`）。

默认排除：

| 情况 | 默认行为 | 放行参数 |
| --- | --- | --- |
| `run.partial` 或 `limit > 0` | 跳过，列入 `runs.skipped` | `--include-partial` |
| `missing_requests > 0` / `complete_planned_requests=false` / manifest `failed`/`interrupted` | 跳过 | `--allow-incomplete` |
| 模型名或 `run_label` 含 fixture 标记 | 跳过，防止合成结果进正式表 | `--allow-fixture` |
| 同一 `(dataset, task, model, strategy)` 有多个运行 | 整组跳过并警告 | `--on-duplicate latest` 或 `first` |
| 数据集 SHA-256 与 `metrics.run.dataset_sha256` 不一致 | 跳过 | `--allow-dataset-mismatch` |
| `task="repair"`（无检测记录） | 跳过；本目录不做修复结构指标 | — |

`results.jsonl` 与 `metrics.json` 会做交叉检查：重新计算混淆矩阵、`valid_predictions`、`schema_invalid`、`api_errors`，以及配对 `joint_categories`/`valid_pairs`/`invalid_pairs`，与 `metrics.json` 对比。默认不一致时保留运行但警告；`--strict` 下跳过该运行。

### 2.2 数据集连接

`project` 与 context 分层不在 `results.jsonl` 中，分析器按 `idx` 连接 `metrics.run.dataset_path` 指向的数据集（或 `datasets/` 下的默认文件）：

- 优先使用 SHA-256 匹配的文件；不匹配默认拒绝；
- 独立集 schema：`samples[]`，每项 `idx`、`project`、`is_vulnerable`、`context`；
- 配对集 schema：`pairs[]`，每项 `pair_id`、`vulnerable`、`fixed`；
- 支持同 schema 的冻结子集/拆分文件，不硬编码 200/160/180；
- 找不到数据集时仍可计算检测指标，但 project cluster bootstrap 会不可用并明确警告；配对的 pair cluster 仍可用。

## 3. 指标口径

### 3.1 独立检测（Task A）

阳性类 = `is_vulnerable=True`。对**有效预测**（`status="ok"` 且 `parsed.is_vulnerable` 为 bool）计算：

- Precision、Recall、Specificity、正类 F1、Accuracy；
- **Macro-F1** = `(F1_vuln + F1_nonvuln) / 2`，主终点；
- **Balanced accuracy** = `(Recall + Specificity) / 2`；
- **MCC** = `(TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))`；
- Coverage / invalid rate。

约定：

- Precision 分母为 0 → `n/a`；
- 某类在数据中不存在 → 该类 F1 / macro-F1 / balanced accuracy 为 `n/a`，不填 0；
- 某类存在但从未被预测 → 该类 F1 记 0，并标记 `*_class_not_predicted`；
- MCC 分母为 0 → 按项目协议记 0，并置 `mcc_degenerate=true`（表中标注“退化”）；
- schema-invalid / API-error **不计入 valid-only 分母**；
- 另报 **end-to-end strict accuracy**：invalid/error 计为错误，分母为全部规划单元；这是部署视图。

### 3.2 配对任务（B1）

每个 pair 同时有漏洞侧与修复侧：

- `joint_correct`：漏洞侧判为漏洞且修复侧判为安全；
- `joint_accuracy_valid_pairs`：只在两侧都有效的 pair 上计算；
- `joint_accuracy_all_pairs`：任一侧无效的 pair 计为失败；
- 类别计数/比例：正确区分、双报漏洞、双报安全、判反（漏报+误报）；
- 分侧指标：漏洞侧 P/R/F1，修复侧 Accuracy/Specificity，总体 Accuracy；
- 恒等式检查：`consistent = 1 − both_vuln − both_safe`，`joint = consistent − swapped`。

分侧指标把每个版本当作一条检测记录，仅作次要描述；Wilson 区间未校正 pair 内相关。

### 3.3 区间

- **Wilson 95%**：用于比例（accuracy、recall、specificity、precision、coverage、joint accuracy、类别比例）。对 precision 只是近似，因为分母是预测阳性数；优先参考 bootstrap。
- **Cluster percentile bootstrap 95%**：用于 macro-F1、balanced accuracy、MCC、F1，以及策略差值。**不用 Wilson 给 F1/MCC 造区间。**
- 表中方括号：比例类为 Wilson，macro-F1/BA/MCC 为 bootstrap；JSON 同时保留两者。

### 3.4 Complete-case cohort 与 end-to-end

为了让策略比较使用同一批单元：

- `valid_only`：只保留**在所有被比较策略中都有有效预测**的单元（complete-case）；macro-F1/BA/MCC 与 bootstrap 差值都在这个 cohort 上；
- `end_to_end`：使用全部 cohort 单元，invalid/error 计为错误；报告 strict accuracy、joint accuracy all、coverage、invalid rate。

如果某策略有 invalid 记录，两个视图的 n 会不同，表中会同时给出 cohort n、有效 n、覆盖率与严格准确率。不能把 valid-only 和 all-samples 的数字混在一张“赢家”表里。

## 4. 统计方法

### 4.1 Bootstrap

- 重采样单位：
  - 独立检测：**project**（按项目有放回抽项目，项目内全部单元一起进入样本）；
  - 配对：**pair**（一对的两个版本始终一起进入样本）；
  - `--cluster unit` 仅作为敏感性/无 project 时的备选，JSON 会标明，不能冒充主分析。
- 重复次数：默认 **10,000**（`--bootstrap` 可改）；固定 seed **42**（`--seed` 可改）。
- 区间：percentile 2.5/97.5，线性插值（与 numpy 默认 `linear` 一致），不强制对称，不报 BCa。
- 每次重采样同时计算所有指标；策略差值在同一重采样上计算 `A − B`，因此是配对差值区间。
- 指标返回 `None` 的重采样会被跳过；`valid_resamples < 90%` 标记 `unstable=true`。
- 记录 `cluster_count`、cluster 大小摘要、`resamples`、`seed`、`confidence`、`percentile_method`，便于复现。

### 4.2 McNemar 精确检验

对两个策略在同一单元上的正确/错误：

|  | B 正确 | B 错误 |
| --- | --- | --- |
| A 正确 | a | b |
| A 错误 | c | d |

- 双侧精确 p：`2 * min(P(X <= min(b,c)), 0.5)`，`X ~ Binomial(b+c, 0.5)`；`b+c=0` 时 p=1；
- 效应量：风险差 `(b-c)/n`、OR `b/c`（c=0 时 OR 为 `n/a`）；
- **主分析**：全部 cohort 单元，invalid 计为错误（end-to-end）；
- **次要分析**：两侧都有效的单元；
- 三策略 → 每个 family 3 个两两比较，Holm 校正（`p_adj = min(1, max_{j<=i}(m-j+1)p_(j))`），α=0.05；
- McNemar 假设单元独立；同项目相关会使 p 偏小。因此**主推断用 project/pair cluster bootstrap 差值区间**，McNemar 作为次要证据，两者都报告。

### 4.3 没有实现的内容

- 没有分层 unit bootstrap（协议中的敏感性分析）；主区间是 project/pair cluster bootstrap。
- 没有 BCa、没有有限样本校正、没有多重比较以外的事后检验。
- 没有跨任务池化；独立检测与配对任务分开。
- 没有修复结构指标、成本/延迟或定性案例；这些由其他目录负责。

## 5. Context 分层与 M3 伪影风险

### 5.1 分层定义

分析器用与 runner 相同的 allow-list（`Execution Environment`、`External Function`、`Function Argument`、`Globals`、`Type Execution Declaration`）和清洗逻辑，把原始 `context` 分为：

- `nonempty`：至少一个 allow-listed 小节有可用条目；
- `empty`：没有可用条目（原始为空、全 null、或只有 `Explanation` 等非白名单内容）；
- `unparsed`：原始字符串无法按字典解析；
- `unknown`：没有数据集连接，也不是 L3 prompt 元数据。

如果 runner 包可导入，直接使用 `secvul_runner.context.extract_safe_context`；否则使用本地 AST fallback（更粗，不应用 forbidden 过滤，会在 JSON 的 `context_source` 标注）。L3 运行的 `prompt.context.nonempty` 会与数据集重建的分层交叉检查，不一致会计数并警告。

### 5.2 本数据的实际审计结果

独立集 `independent_200.json`（200 条，160 漏洞 + 40 非漏洞）：

| context 分层 | n | 漏洞 | 非漏洞 | P(漏洞\|分层) |
| --- | ---: | ---: | ---: | ---: |
| nonempty | 156 | 156 | 0 | 1.0000 |
| empty | 44 | 4 | 40 | 0.0909 |

- 非空层 **156/156 全是漏洞样本**；空层 44 条中 4 条漏洞、40 条非漏洞；
- 因此 **P(漏洞|context 非空)=1.0，P(漏洞|context 空)=0.0909**，差值 0.909；
- 数据层面 M3 伪影风险：**high**，flag `nonempty_stratum_single_class`；
- 非空层是单类别，**macro-F1/balanced accuracy 在该层不可定义**；只能报告正类 F1/召回。空层虽有两类，但只有 4 条正例，macro-F1 也很不稳定；
- 这与 runner README 中“40 条负例 context 全空”一致，但正例并非 160 条都可形成非空 prompt context：4 条正例的原始 context 没有可用的白名单条目，因此 sanitized nonempty 为 156，而不是 160。

配对集 `vulnerable_fixed_200_pairs.json`（200 对）：

| 漏洞侧 / 修复侧 context | 对数 |
| --- | ---: |
| nonempty / nonempty | 195 |
| empty / empty | 5 |

- 配对两侧共享同一函数的上下文可用性；标签由 side 固定（漏洞侧=1，修复侧=0），所以 context 非空**不直接编码 side 标签**；
- 数据层面风险标为 **low**，但空上下文只有 **5 对**，flag `small_stratum`；该分层任何差值都不稳定。

### 5.3 报告时必须怎么写

1. M3（context 策略）必须同时报告 context 非空/空分层的 n 与指标，不能只报总体值；
2. 不得把 M3 与 M1 的总体差异单独归因于“上下文推理能力”；差异与 context 可用性混杂；
3. 单类别分层不要填 0：macro-F1/BA 写 `n/a`，改报正类 F1/召回（非空层）或 specificity/负类 F1（空层）；
4. 分层差异标记为**探索性**，报告 n 与区间，不堆 p 值；
5. 更严格的因果比较需要标签无关的上下文构造，并作为新策略重新登记、重新运行。

`aggregation.json` 顶层 `m3_artifact_risk` 带 `risk_level`、`summary`、`datasets[].context_audit`（内含 `flags`/`reasons`）和 `reporting_requirements`；每个 group 的 `m3_artifact_risk` 还带 `caveat` 与该 group 的 `m3_vs_m1` 证据。Markdown 中也有对应小节。即使没有任何真实 runs，数据层面的 M3 审计仍会生成（这不是模型结果）。

## 6. 输出

### 6.1 `aggregation.json`

顶层：

| 键 | 内容 |
| --- | --- |
| `schema_version` / `analysis_version` | 产物版本 |
| `generated_at_utc` | 生成时间；固定 seed 下不影响统计量 |
| `status` | `ok` / `no_real_runs` / `input_error` |
| `experimental_results` | 是否包含真实（非 fixture）运行 |
| `fixture_mode` | 是否包含 `--allow-fixture` 的合成运行 |
| `config` | runs root、dataset root、bootstrap 次数/seed/置信水平/cluster 单位/percentile 方法 |
| `inputs` | 扫描到的路径、数据集、context 分类器来源 |
| `runs.included` / `runs.skipped` | 已加载运行摘要；跳过原因 |
| `datasets` | 数据集审计：SHA-256、标签计数、项目数、context 审计 |
| `m3_artifact_risk` | 数据层面 M3 风险 |
| `groups` | 每个 `(dataset, task, model)` 的聚合结果 |
| `report_tables` | 自动填表行：`table7_detection`、`table8_pairs_by_side`、`table9_pairs_joint`、`mcnemar`、`table_context_strata` |
| `warnings` / `limitations` | 警告与限制 |
| `reproduction` | 复现命令 |

`groups[]` 主要键：

- `cohort`：`n`、`complete_case_n`、`excluded`、`reference_strategy`；
- `run_level`：每个策略在本运行全部单元上的指标；
- `valid_only`：complete-case cohort 上的 valid-only 指标（独立集含 P/R/F1/BA/MCC/macro-F1；配对含 joint/categories/per-version）；
- `end_to_end`：全部 cohort 单元，invalid 计错；
- `bootstrap.valid_only` / `bootstrap.end_to_end`：`settings`、`metrics`（每个策略）、`deltas`（每个策略对）、`cluster_count`、`cluster_size_summary`；
- `pairwise.primary` / `pairwise.secondary`：McNemar 比较、原始 p、Holm p、拒绝标记；
- `context_strata`：每个策略的 nonempty/empty/unparsed/unknown 指标、L3 元数据检查、M3−M1 分层差值；
- `m3_artifact_risk`：该 group 的 M3 风险与报告要求。

`bootstrap.metrics[strategy][metric]` 含 `point`、`ci_low`、`ci_high`、`bootstrap_median`、`bootstrap_mean`、`valid_resamples`、`resamples`、`unstable`。`deltas[strategy_a_vs_strategy_b][metric]` 同结构，方向为 A−B。

### 6.2 `aggregation.md`

中文可读版本，包含：

- 配置与运行清单（含 partial/fixture/已入组/交叉检查）；
- 数据集 context 审计与 M3 风险；
- 独立检测表（Table 7 准备）：P/R/F1/Accuracy/Specificity/BA/MCC/Macro-F1/coverage；
- 配对联合表（Table 9 准备）与分侧表（Table 8 准备）；
- context 分层表与 M3−M1 差值；
- McNemar/Holm 表与 bootstrap 差值表；
- 警告、复现命令、限制。

当前 `aggregation.md` 没有性能表，因为 `status=no_real_runs`。

## 7. 用法

### 7.1 对真实运行目录生成正式聚合

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --bootstrap 10000 --seed 42'
```

默认输出：

```text
analysis/aggregation.json
analysis/aggregation.md
```

指定运行目录（可重复）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/analyze_runs.py \
  --run runner/runs/independent_direct_both \
  --run runner/runs/independent_few-shot_both \
  --run runner/runs/independent_context_both \
  --bootstrap 10000 --seed 42'
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--runs-root PATH` | 扫描根目录，默认 `runner/runs` |
| `--run PATH` | 显式运行目录；可重复；与 `--runs-root` 二选一 |
| `--dataset-root PATH` | 数据集根目录，默认 `datasets/` |
| `--out-json PATH` / `--out-md PATH` | 输出路径 |
| `--bootstrap N` | 重采样次数，默认 10000；0 表示关闭 |
| `--seed N` | bootstrap seed，默认 42 |
| `--confidence F` | 区间置信水平，默认 0.95 |
| `--cluster {auto,project,pair,unit}` | 重采样单位；auto：独立→project，配对→pair |
| `--include-partial` | 纳入 `--limit` 运行（仍标记 partial） |
| `--allow-incomplete` | 纳入缺失请求/manifest 未完成的运行 |
| `--allow-fixture` | 纳入合成 fixture；**仅用于自检，不得进正式表** |
| `--allow-dataset-mismatch` | 允许 SHA-256 不一致（危险，仅调试） |
| `--on-duplicate {error,latest,first}` | 同策略多运行的处置；默认报错并跳过该组 |
| `--strict` | metrics 交叉检查失败时跳过运行 |
| `--quiet` / `--debug` | 减少 stdout / 打印异常堆栈 |

### 7.2 自检（临时 fixture，自动清理）

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && python3 analysis/selftest.py'
```

自检在系统临时目录创建 6 个合成运行（独立/配对 × direct/few-shot/context），在 `finally` 中删除；不会写 `analysis/aggregation.*`。它验证：

- Wilson、macro-F1、BA、MCC、McNemar、Holm、percentile 的手算对照；
- 独立集 all-positive 基线 macro-F1=4/9、BA=0.5、MCC=0；perfect=1.0；
- one invalid record → coverage 0.995、complete-case 199/200；
- 配对 joint valid/all、类别计数、分侧指标；
- 三策略 McNemar + Holm；
- project/pair cluster bootstrap 的 settings、cluster 数、区间顺序、固定 seed 复现；
- context 分层 156/44、M3 high、配对 195/5、small stratum；
- fixture guard（不加 `--allow-fixture` 时全部跳过）；
- partial/incomplete 默认跳过；
- 运行后临时目录不存在、正式 aggregation 未被 fixture 写入。

最近的验证输出：

```text
[ok] stats: Wilson, macro-F1, balanced accuracy, MCC, McNemar, Holm, percentile
[ok] end-to-end aggregation: independent + pairs, cohort, bootstrap, McNemar/Holm
[ok] context strata and M3 risk flags
[ok] fixture guard: refuses to treat synthetic runs as real results
[ok] partial and incomplete runs are skipped unless explicitly allowed
[ok] bootstrap and McNemar results are deterministic for a fixed seed
[ok] no fixture output was written into analysis/
All analysis self-tests passed; temporary fixtures were removed.
```

## 8. 本次实际验证与限制

### 8.1 已验证

在 WSL `Python 3.14.8` 下执行：

- `python3 -m compileall -q analysis`：通过；
- `python3 analysis/selftest.py`：通过（见上）；
- `python3 analysis/analyze_runs.py`：在无真实 runs 时正常退出，生成 `status=no_real_runs` 的 JSON/Markdown；数据集审计显示独立集 context 风险 `high`、配对集 `low`，无任何模型性能数值；
- `aggregation.json` 经 `json.load` 可解析；`aggregation.md` 的 3 个表格块列数一致；fixture 输出经 19 个表格块检查，0 个列数错误；
- 正式 `aggregation.json` 中没有 `macro_f1`、`balanced_accuracy`、`mcc`、`joint_accuracy` 等性能键（已用 grep 核对），确认未被 fixture/mock 填充；
- 额外用 6 个合成运行以正式默认 `--bootstrap 10000 --seed 42` 跑通：耗时约 24 秒，`valid_resamples=10000`，无异常，验证了完整重采样次数下的运行时间与稳定性；
- 自检临时目录、`analysis/__pycache__` 与 `runner/secvul_runner/__pycache__` 均已清理。

### 8.2 限制

- **没有真实模型结果**：DeepSeek 调用因 key 过期返回 401；`aggregation.json` 当前不包含性能、成本或案例。不能把 fixture 数值写进报告。
- **M3 混杂**：独立集 context 非空与标签高度相关；非空层单类别导致 macro-F1 不可定义。任何 M3 总体优势都不能单独归因于上下文推理。
- **配对空分层很小**：只有 5 对空 context，分层差值不稳定；不要据此做强结论。
- **Bootstrap 假设**：project cluster 把项目视为独立重采样单位；不保证对未见项目泛化；没有分层 unit bootstrap/BCa。
- **McNemar 独立性**：同项目单元相关会使 p 偏小；以 cluster bootstrap 差值区间为主。
- **数据连接**：按 `idx` 连接；如果运行使用了不同 schema 或缺失数据集，project/context 分层会不可用，分析器会警告并禁用相应 bootstrap。
- **分组口径**：同一组按 `dataset_type`、`task`、`model`、数据集 SHA-256 分组；不同 task/model 不会互相比较，也不会自动把 `detection` 与 `both` 合并。
- **只做检测/配对联合**：修复结构指标、成本、延迟、定性案例不在本目录范围。
- **没有多 seed/多次运行**：同一策略通常只有一个真实运行；区间反映单元/项目抽样不确定性，不反映模型服务端非确定性。

## 9. 复现命令汇总

```bash
# 1) 无真实 runs 时生成空聚合（当前状态）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/analyze_runs.py'

# 2) 有真实 runs 后生成正式聚合
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/analyze_runs.py \
  --runs-root runner/runs \
  --bootstrap 10000 --seed 42'

# 3) 自检（临时 fixture，自动清理）
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && \
python3 analysis/selftest.py'
```

# CS224 最终报告（中文 IEEE 格式）

本目录保存最终报告的中文源稿、参考文献、结果摘要和辅助脚本。报告按 CS224 课程指南组织：在同一数据集上比较三种 LLM 提示策略，报告检测、配对联合判别、修复结构指标、成本、统计检验和定性案例。

**当前状态：六个真实完整运行（`test_v1_*`）已完成，检测/配对/修复/成本/统计/10 个案例/LLM 辅助盲评均已写入报告，结果表中不再有 `TBD`。** 唯一保留的 `TODO` 是作者/单位补充。报告已用 Tectonic 0.17.0 在 WSL 编译为 `report/report_zh.pdf`（17 页，Nimbus 字体）；无 unresolved、无缺字，目标 overfull 已消除。

## 扩展版（2026-11-12）

在旧报告之上新增独立的扩展版，旧 `report_zh.tex` / `report_zh.pdf` 保持原样、未被覆盖：

| 项目 | 内容 |
| --- | --- |
| 源稿 / PDF | `report_extended_zh.tex` / `report_extended_zh.pdf` |
| 页数 / 版式 | 27 页，IEEEtran conference 双栏，letter |
| 参考文献 | `references_extended.bib`（28 条，含 Juliet、ASan、LSan、Valgrind、Clang SA、Cppcheck、McNemar、Holm、Wilson、Efron） |
| 结果摘要 | `extended_results_summary.md` |
| 生成表 / 宏 | `extended_tables*.tex`、`extended_numbers.tex`（数值注册表） |
| 表生成脚本 | `scripts/build_extended_tables.py`（只读结果 JSON，不手抄数值） |
| 旧版 | `report_zh.tex`、`report_zh.pdf`（17 页，未修改） |

扩展内容与关键结果：

- **Tier A 双模型**：DeepSeek 与 MiMo × direct/few-shot/context × detection/pair，共 12 个只读派生 run、每模型 2,484 请求。检测 macro-F1 为 DeepSeek 0.383/0.399/0.381、MiMo 0.346/0.346/0.365；6 个同策略模型比较经 Holm 后均不显著。
- **Pair-joint**：180 对强制二选一，DeepSeek/MiMo DA 76.7%/86.7%；长度启发式单独 74.4%，DeepSeek 与它不可区分（p=0.659），MiMo 显著高于它（p=0.0003）；DeepSeek A/B 位置差 31.1 pp。
- **证据提示**：160 条函数 × 2 模型；召回 +9.4/+10.9 pp（Holm p=0.0055/0.0010），FPR 同时 +9.4/+13.8 pp，BA/MCC 基本持平。
- **Juliet Tier B**：test 140 上 Clang SA macro-F1 0.888、Cppcheck 0.588、ASan/Valgrind 0.914；动态 clean 不是 TN；MiMo LLM 修复后 95.0%（F1 0.951，Xiaomi fallback，非 OpenCode Go），修复前 95.7% 仅作审计。
- **证据混合 v2**：2 模型 × 5 方法 × 140 = 1,400 请求（泄漏修复后重跑）；DeepSeek/MiMo 最好为 97.14%/97.14%，相对 direct 为 +1/0 个单元、McNemar 不显著，安慰剂无聚合收益；v1 的 DeepSeek combined 100% 只作审计，修复 6 个 good 单元后为 97.14%。
- **成本口径**：`analysis/cost_normalization.json` 分列 configured 与 normalized provider-list；71 个完整 run 为 3.886970/2.146513 USD，修复 all-in 修正为 0.082550（normalized 0.052549），headline 0.032831 不变。
- **修复闭环**：70 个 Juliet test bad 单元，58 个 LSan 可观测；DeepSeek/MiMo 均 58/58 严格通过（编译 + LSan + 行为）；12 个不可观测单元不计入。

编译与检查（WSL，Tectonic 0.17.0 musl，SHA-256 `8533d07f9ccbd7a65824b9e0459041bca34af1eb33daba48f59215593753a3b7` 已核验）：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
python3 report/scripts/build_extended_tables.py
/tmp/secvul-tectonic/tectonic -X compile \
  report/report_extended_zh.tex --outdir report --keep-intermediates
pdfinfo report/report_extended_zh.pdf
pdffonts report/report_extended_zh.pdf
```

检查结果：27 页；NimbusRoman/NimbusSans/NimbusMonoPS 与 FandolSong/FandolKai 均已嵌入；0 个 unresolved reference/citation、0 个 `Missing character`、0 个 `Overfull \hbox`；仅 1 个 0.8 pt 的 `Overfull \vbox`（末页 column balancing，低于 10 pt）；`pdftotext` 中 0 个 `TBD`、0 个 `TODO`、0 个 `??`。字体 shape 警告 `TU/NimbusRoman(0)/m/sc` 与 `TU/NimbusMonoPS(0)/m/sc` 是 small-caps 形状缺失后的自动替换，不是缺字。静态检查 `python3 report/scripts/check_extended.py` 报告 59 个 label、41 个 ref、28 个 cite、28 个 bib 键，missing refs/cites 均为空。

**登记口径提醒**：`benchmark/results/tier_b_summary.json` 仍把 Juliet LLM/hybrid 的 B4–B8 标为 `blocked_gate`；`juliet_llm/` 与 `hybrid/` 是独立工作流，扩展版把它们写成“未纳入统一 leaderboard 的探索性证据”，不写成 B4–B8 的正式登记结果。Tier A 与 Tier B 不池化、不横比。

## 核心结果

| 任务 | 结果 |
| --- | --- |
| 独立检测（160） | few-shot macro-F1 0.399 数值最高，direct 0.383、context 0.381；95% cluster bootstrap 差值均跨 0，McNemar Holm 后均不显著 |
| 配对联合（180 对） | DA 8.9%–12.2%，远低于测试集随机指定一侧的 56.1%（期望 50%）；主要失败为双报安全/双报漏洞 |
| 修复结构（308） | schema：direct 84.4%、few-shot 99.0%、context 83.4%；完整且不同：80.0%/62.0%/82.9%；精确匹配 1.7%/5.0%/2.2%，不是正确率 |
| 成本（每策略 828 请求） | direct $0.645585、few-shot $1.131383、context $0.662251；allowance 单独记录，不并入 USD |
| 修复盲评 | LLM 辅助（非人类），81 候选/30 案例，VR=2 17/81（21.0%）；direct 7/26、context 6/25、few-shot 4/30；MIN κ=0.015，未编译/PoC |

完整数值、区间和产物链接见 `results_summary.md`。

## 文件

| 文件 | 用途 |
| --- | --- |
| `report_zh.tex` | 中文 IEEE 会议格式报告源稿，Tectonic/XeLaTeX 编译 |
| `report_zh.pdf` | 已编译 PDF（17 页，Tectonic 0.17.0，Nimbus 字体） |
| `report_extended_zh.tex` | 扩展版中文 IEEE 双栏源稿（27 页） |
| `report_extended_zh.pdf` | 扩展版已编译 PDF（27 页，Tectonic 0.17.0） |
| `references.bib` | 旧版专用参考文献，IEEEtran 样式 |
| `references_extended.bib` | 扩展版参考文献（28 条，含工具/统计/Juliet） |
| `extended_results_summary.md` | 扩展版结果摘要、限制与编译检查 |
| `extended_tables*.tex` / `extended_numbers.tex` | 从冻结结果 JSON 生成的表和数值宏 |
| `scripts/build_extended_tables.py` | 扩展表生成器（只读结果，不手抄） |
| `scripts/check_extended.py` | 扩展版静态检查：label/ref、cite/bib 键 |
| `results_summary.md` | 中文结果摘要：检测、配对、修复、成本、盲评和限制 |
| `generated_tables.txt` | 六次运行生成的检测/配对/修复/成本 LaTeX 行 |
| `generated_costs.json` | 按 task 汇总的 token、cost、allowance、延迟、无效输出 JSON |
| `scripts/data_summary.py` | 只读源数据集，输出描述统计 |
| `scripts/fill_tables.py` | 从 `metrics.json` 生成结果行，从 `results.jsonl` 生成成本行/JSON |
| `scripts/check_tex.py` | 非编译静态检查：环境、花括号、label/ref、cite/bib、tabular 列数、无 TBD |
| `README.md` | 本说明 |

## 实验配置

- 模型 / API ID：`deepseek-v4.1-flash` / `deepseek-v4.1-flash`
- 端点：OpenCode Go，`https://opencode.ai/zen/go/v1/chat/completions`
- 思考模式 disabled（请求体显式设置），temperature 0，max_tokens 8192，并发 8
- 价格快照：输入 0.30、输出 1.20、缓存输入 0.006 USD 每 1M token
- 六次运行：`runner/runs/test_v1_{direct,few-shot,context}_{independent,pairs}`，全部 completed；每策略 828 请求，三策略合计 2,484
- 提示版本：`secvul-prompt-2026-11-11.1`；运行器版本 1.0.0

## 数据与基线

- 冻结测试集：检测 160 条（128 正/32 负），配对 180 对（360 条函数）；开发集 40 条检测 + 20 对配对，只用于固定示例和 pilot。
- `baseline/results/test_split_baselines.json`：
  - 独立多数类 Accuracy 80.0%（Spec 0、MCC 0），永远无漏洞 Accuracy 20.0%；
  - 配对常量基线双方均正确 0/180；随机指定一侧 101/180 = 56.1%（解析期望 50%）。
- context 审计：检测测试集非空层 126/126 为漏洞，空层 34 条中 2 条漏洞、32 条非漏洞；非空层是单类别。源独立集非空 156/156，空 44 条中 4 条漏洞。M3 总体差异与 context 可用性混杂，不能作因果解释。
- 5 条 32,767 字符源截断（独立 3 条 + 配对 1 对）全部落在测试集。
- CWE-401：源子集 4/360、测试集 3/308，严格“C++ 扩展名且单一 CWE-401”为 0 条；只作案例系列，主定位为全 CWE。

## 报告结构

1. 摘要、关键词
2. 引言：问题、RQ1–RQ5、全 CWE 定位
3. 相关工作
4. 数据：源子集、冻结划分、描述统计、审计、CWE-401 范围、示例与字段可见性
5. 方法：任务边界、共享控制、M1/M2/M3
6. 实验设置：实际规模、模型配置、指标、统计、日志
7. 结果：测试集基线、独立检测（`tab:ind-results`）、context 分层（`tab:m3-strata`）、配对分侧（`tab:pair-detection`）、联合判别（`tab:pair-joint`）、修复结构（`tab:repair`）、McNemar（`tab:mcnemar`）、RQ 回答
8. 成本：按 task 汇总的成本与无效输出（`tab:cost`）、成本—效果
9. 定性分析与误差案例：10 个案例（`tab:cases`）、LLM 辅助盲评（`tab:blind`）
10. 讨论、有效性威胁
11. 局限性
12. 可复现性：产物清单（`tab:artifacts`）、环境、命令、记录要求
13. 结论
14. 附录：提示模板、输出 schema

扩展版保留以上结构，并在“讨论”之后新增：统一分层基准与双模型比较；联合提示与结构化证据；Juliet CWE-401 分层基准；修复的编译--LSan--行为闭环；创新点；扩展实验的附加限制；以及扩展协议附录。扩展版共 27 页，表号改为阿拉伯数字以便引用。

## 复现命令

在 WSL 项目根目录执行：

```bash
# 1) 结果表：六个完整 run 的 metrics.json
python3 report/scripts/fill_tables.py \
  runner/runs/test_v1_direct_independent runner/runs/test_v1_direct_pairs \
  runner/runs/test_v1_few-shot_independent runner/runs/test_v1_few-shot_pairs \
  runner/runs/test_v1_context_independent runner/runs/test_v1_context_pairs \
  --model deepseek-v4.1-flash

# 2) 成本 JSON（同一命令加 --json；成本来自 results.jsonl）
python3 report/scripts/fill_tables.py \
  runner/runs/test_v1_direct_independent runner/runs/test_v1_direct_pairs \
  runner/runs/test_v1_few-shot_independent runner/runs/test_v1_few-shot_pairs \
  runner/runs/test_v1_context_independent runner/runs/test_v1_context_pairs \
  --model deepseek-v4.1-flash --json

# 3) 统计聚合（10,000 次 cluster bootstrap + McNemar/Holm）
python3 analysis/analyze_runs.py --runs-root runner/runs --bootstrap 10000 --seed 42

# 4) 数据描述统计
python3 report/scripts/data_summary.py

# 5) 定性案例与修复盲评
python3 qualitative/build_cases.py
python3 qualitative/build_cases.py --check-only
python3 -m repair_eval verify --package repair_eval/packages/repair_blind_v1

# 6) 静态检查（无 TeX 时的结构检查）
python3 report/scripts/check_tex.py
```

`fill_tables.py` 的正式模式要求六个 run 完整、非 partial、测试文件 SHA-256 匹配、请求数 160/360 与 128/180；partial/pilot 只能加 `--validate-only` 输出 JSON，不能填正式表。成本总值只在所有记录存在且每条记录有数值 `cost_usd` 时给出；`allowance` 是 OpenCode Go 套餐额度，不是 USD 成本，不并入总 USD。

## 统计口径

- 区间：比例类用 Wilson 95%；macro-F1、balanced accuracy、MCC 和策略差值用 10,000 次 project/pair cluster percentile bootstrap（seed 42）。
- McNemar：双侧精确检验，任务内 3 组比较用 Holm 校正；仅作次要证据，主推断用 cluster bootstrap 差值区间。
- 检测/配对只报告一次完整运行，不是多 seed 或多模型估计；差值区间跨 0 时不能宣称优劣。
- 修复结构指标不是正确率；精确匹配参考修复是规范化文本相等，不是语义等价或安全 oracle。
- 修复盲评是两名 LLM 辅助评审加第三 LLM 裁决，不是人类评审；81 个候选都未编译/PoC，MIN 一致性极低，结论探索性。

## 已做的静态检查

由于 WSL 无 TeX Live，使用 `scripts/check_tex.py` 做非编译检查：

- `\begin`/`\end` 环境配对；
- 花括号深度；
- `\label` 无重复，所有 `\ref`/`\eqref` 有定义；
- `\cite` 键与 `references.bib` 对应；
- 每个 `tabular` 列数与每行 `&` 数一致；
- 全稿不再含 `\TBD` 占位。

另用 `fill_tables.py` 对六个 run 重新生成 `generated_tables.txt` 并与报告表行逐行比对，五张主表（独立、配对分侧、联合、修复、成本）一致。

当前检查结果为 `STATIC_OK`，并已用 Tectonic 0.17.0 实际编译为 17 页 PDF；详见下方“编译”。

## 编译

本机 WSL **没有安装 TeX Live**（`xelatex`、`bibtex` 不可用），但已有独立 Tectonic 0.17.0 二进制 `/tmp/secvul-tectonic/tectonic`。在项目根目录执行：

```bash
/tmp/secvul-tectonic/tectonic -X compile \
  report/report_zh.tex --outdir report --keep-intermediates
```

当前编译结果：

- `report/report_zh.pdf`：17 页，letter 页面；正文 ≥10 页；
- 字体：NimbusRoman（正文/等宽）与 FandolSong/FandolKai（中文）已嵌入；`pdffonts` 显示 `NimbusRoman-Regular/Bold/Italic`、`NimbusMonoPS` 等；
- 无 unresolved references/citations，无 `Missing character`/缺字；
- 目标 overfull 已消除：data-stats、MCC 公式、m3-strata、McNemar 均不再有 >10pt overfull；仅剩一处 3.8pt 的非目标 overfull（itemize 长标识符），低于 10pt；
- `pdfinfo`：`Pages: 17`，PDF 版本 1.5。

清理中间文件（保留 PDF、tex、bbl）：

```bash
rm -f report/preview_contact_*.png report/_preview*.png \
      report/report_zh.aux report/report_zh.log report/report_zh.out
```

如需改用 TeX Live，可执行 XeLaTeX → BibTeX → XeLaTeX ×2；但本次已验证 Tectonic 流程，不应再声称“未编译”。

## 写作与数据完整性约定

- 不编造模型输出、指标、费用、案例或盲评分数；所有数值来自 `runner/runs/test_v1_*`、`analysis/aggregation.json`、`qualitative/cases.json`、`repair_eval/.../summary.json` 和 `baseline/results/test_split_baselines.json`。
- 结果表数值由 `fill_tables.py` 生成；本报告已用 `generated_tables.txt` 交叉核对，不手工抄写。
- 成本按 `results.jsonl` 的 task 汇总；`allowance` 与 USD 成本分开。
- 修复结构指标只写“结构代理”；盲评只写“LLM 辅助 rubric 下的通过计数”，不写修复正确率。
- 不把 CWE-401 写成专项目标；不把 M3 的总体差异写成上下文因果效应。
- 不读取、不输出 API 密钥；报告和日志中不出现密钥、请求头或账户信息。
- 本目录之外的文件（`runner/`、`analysis/`、`splits/`、`baseline/`、`qualitative/`、`repair_eval/`）未修改；`references.bib` 为本报告专用副本。

## 剩余工作

1. 已完成 Tectonic 编译与 17 页检查；如需切换 XeLaTeX，需重新核对页数、字体和 overfull。
2. 补充作者、单位、课程分组和提交信息（`report_zh.tex` 中 `TODO`）。
3. 若需要，按教师要求把 PDF 归档到 `output/pdf/`。

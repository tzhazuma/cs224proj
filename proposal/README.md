# C/C++ 漏洞检测研究计划

本目录保存中英文研究计划、可编辑的 LaTeX 源码、共享参考文献和 CWE 分布图。两版采用 IEEE 会议双栏格式，中文稿使用 `ctex`；当前中文 PDF 为 4 页，英文 PDF 为 5 页。

研究计划围绕三个问题展开：单函数漏洞识别、漏洞版本与修复版本的差异辨识，以及两类评估任务的互补性。正文包含研究背景、研究问题、数据构建、有效性限制、评估计划和拟比较的 LLM 策略与模型六个部分。

本文保留研究计划的时态和范围，不作为已完成实验的结果报告。项目当前实现与实验结果见[项目总览](../README.md)、[统一评测协议](../benchmark/PROTOCOL.md)和[扩展结果摘要](../report/extended_results_summary.md)。

## 文件说明

| 文件 | 用途 |
| --- | --- |
| [proposal_zh.pdf](proposal_zh.pdf) / [proposal_en.pdf](proposal_en.pdf) | 最新中英文阅读版 |
| [proposal_zh.tex](proposal_zh.tex) / [proposal_en.tex](proposal_en.tex) | 中英文可编辑源码 |
| [references.bib](references.bib) | 两版共用的参考文献，采用 IEEEtran BibTeX 样式 |
| [ieee_proposal_sources.zip](ieee_proposal_sources.zip) | 可上传 Overleaf 的源码包 |
| [build_cwe_figures.py](build_cwe_figures.py) | 读取项目数据集，统计 CWE 并生成图形源码 |
| [figures/cwe_counts.json](figures/cwe_counts.json) | CWE 计数、统计口径及来源哈希 |
| `figures/cwe_distribution_zh.*` / `figures/cwe_distribution_en.*` | 中英文矢量图 PDF 与对应 LaTeX 源码 |
| [.gitignore](.gitignore) | 本目录的编译中间文件及构建目录忽略规则 |

源码 ZIP 包含两版主 `.tex`、参考文献、README、绘图脚本，以及完整的 `figures/` 图形材料；不包含主文档 PDF、原始数据集或编译中间文件。更新源码或本说明后，应同步重建 ZIP。

## 作者

作者顺序与两版正文、PDF 元数据一致。单位均为 ShanghaiTech University，地址均为 Shanghai, China。

| 作者 | 邮箱 |
| --- | --- |
| Yu Zhang | [Zhangyu12026@shanghaitech.edu.cn](mailto:Zhangyu12026@shanghaitech.edu.cn) |
| MingDong Wu | [wumd2024@shanghaitech.edu.cn](mailto:wumd2024@shanghaitech.edu.cn) |
| Zhixiong Zhang | [zhangzhx2026@shanghaitech.edu.cn](mailto:zhangzhx2026@shanghaitech.edu.cn) |
| Zhihao Tang | [tangzhh2026@shanghaitech.edu.cn](mailto:tangzhh2026@shanghaitech.edu.cn) |

## 数据与评估设计

两个层级分别报告，不能合并为总体分数或统一排名。

| 层级 | 构建规模 | Dev | 冻结 Test |
| --- | --- | --- | --- |
| Tier A：SecVulEval 独立检测 | 200 函数，160 漏洞 / 40 非漏洞 | 40 函数，32 / 8 | 160 函数，128 / 32 |
| Tier A：SecVulEval 配对判别 | 200 对，400 函数记录 | 20 对 | 180 对，360 函数记录 |
| Tier B：Juliet CWE-401 | 200 单元，100 bad / 100 good | 60 单元 | 140 单元 |

Tier A 的两个构建子集共含 600 条不同记录，不共享原始索引或 `(project, commit_id)` 分组。检测和配对任务各自的 dev/test 按项目隔离，但存在跨任务项目重叠，不能声称全局项目互斥。

主比较固定同一模型，对照 `direct`、`few-shot` 和 `context` 三种提示策略；候选模型为 DeepSeek V4.1 Flash 和 MiMo-V2.6-Flash。Tier B 单独比较静态工具、动态工具与 LLM / 混合策略。计划同时报告主指标、coverage、valid-only 与 strict 口径，并控制输入泄漏、成本口径和多重比较。

## 本地编译

使用 TeX Live 或 MiKTeX 提供的 XeLaTeX 和 BibTeX；不要求特定 Conda 环境。两版所需资源包括 `IEEEtran`、`fontspec`、`cite`、`amsmath`、`amssymb`、`booktabs`、`graphicx`、`balance`、`xurl`、`tabularx`、`array`、`hyperref` 和 TeX Gyre 字体；中文稿还需 `ctex` 与 Fandol 字体。

在本目录打开 PowerShell 执行下列命令。中间文件集中到 `.build/`，完成后仅将阅读版 PDF 复制回本目录：

```powershell
New-Item -ItemType Directory -Force .build | Out-Null

foreach ($name in @('proposal_zh', 'proposal_en')) {
    xelatex -interaction=nonstopmode -halt-on-error -output-directory=.build "$name.tex"
    if ($LASTEXITCODE -ne 0) { throw "XeLaTeX failed: $name" }
    bibtex ".build/$name"
    if ($LASTEXITCODE -ne 0) { throw "BibTeX failed: $name" }
    xelatex -interaction=nonstopmode -halt-on-error -output-directory=.build "$name.tex"
    if ($LASTEXITCODE -ne 0) { throw "XeLaTeX failed: $name" }
    xelatex -interaction=nonstopmode -halt-on-error -output-directory=.build "$name.tex"
    if ($LASTEXITCODE -ne 0) { throw "XeLaTeX failed: $name" }
    Copy-Item -LiteralPath ".build/$name.pdf" -Destination "$name.pdf"
}
```

在 Overleaf 中上传源码 ZIP，选择 XeLaTeX，并将 `proposal_zh.tex` 或 `proposal_en.tex` 设为主文档。须保留共享参考文献及 `figures/`；直接编译现有文档不需要原始 JSON 数据集。

## CWE 图形

图形统计独立集的 160 条漏洞函数和配对集的 200 条漏洞版本；不计入独立集负样本及修复版本，每条函数对同一 CWE 最多计数一次。连写的 CWE 编号在统计时拆分并在函数内去重，原始数据不变。

图中包含合计 57 种数字 CWE 和两种 NVD 占位标记，共 59 类，分为三个采用相同横轴刻度的面板。多标签使标签归属总数大于函数数，不能将两者混用。详细计数见 `figures/cwe_counts.json`。

仅在数据或图形需要更新时，从本目录执行：

```powershell
python build_cwe_figures.py
xelatex -interaction=nonstopmode -halt-on-error -output-directory=figures figures/cwe_distribution_zh.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=figures figures/cwe_distribution_en.tex
```

统计脚本只使用 Python 标准库，并通过相对路径读取 `../datasets/`。图形编译还需 `standalone`、`pgfplots` 和 `fix-cm`。

## 文件维护

保留主文档与图形的 `.tex` / `.pdf`、`references.bib`、统计 JSON、绘图脚本、README、忽略规则和源码 ZIP。`.aux`、`.log`、`.out`、`.synctex.gz`、`.bbl`、`.blg` 等均可通过编译再生，不纳入源码包；`.build/` 可在编译完成后清理。

更新文档后应检查四位作者及邮箱、数据分母、参考文献和交叉引用，并逐页检查标题、双栏、表格及图形是否越界。仅检查编译退出码不能替代排版检查。

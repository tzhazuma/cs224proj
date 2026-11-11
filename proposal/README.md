# IEEE 格式研究计划：中文与英文

- `proposal_zh.tex`：中文版本，使用 `IEEEtran` 会议双栏布局和 `ctex` 中文支持。
- `proposal_en.tex`：英文版本，与中文版本的研究设计相对应。
- `references.bib`：两版共用的参考文献，采用 `IEEEtran` BibTeX 样式。
- `figures/cwe_distribution_zh.pdf` 和 `figures/cwe_distribution_en.pdf`：已嵌入正文的中英文 CWE 数量柱状图，使用矢量格式。
- `figures/cwe_counts.json`：完整分类数量、统计口径、来源哈希及拆分标签涉及的原始索引。
- `build_cwe_figures.py`：使用 Python 标准库统计 JSON 并生成 PGFPlots 图形源码。
- 编译预览位于项目根目录的 `output/pdf/proposal_zh.pdf` 和 `output/pdf/proposal_en.pdf`。
- `ieee_proposal_sources.zip`：包含两版 `.tex`、共享参考文献、图形及其源码、统计结果、绘图脚本和本说明，可直接上传 Overleaf。

## 写作范围

两版均已填写摘要、研究背景、研究问题、数据构建、研究限制及预期贡献。实验方法、实验模型、实验结果仅保留章节标题，填写提示位于 LaTeX 注释中，不出现在 PDF 正文。

两版作者信息均为 Yu Zhang，单位为 ShanghaiTech University，城市与国家为 Shanghai, China，邮箱为 [Zhangyu12026@shanghaitech.edu.cn](mailto:Zhangyu12026@shanghaitech.edu.cn)。PDF 作者元数据亦为 Yu Zhang。研究对象是漏洞检测器，尚未锁定特定算法或模型，也未编造性能数值。

两组数据的统计单位分别为 200 条独立函数（160 条有漏洞、40 条无漏洞）和 200 对漏洞／修复版本（400 条函数记录），合计 600 条不同的函数记录。正文使用现有 JSON 元数据与 `datasets/README.md` 中已实现的构建约束；没有将两个评估子集解释为训练集与测试集。

## 模板与来源

使用 `\documentclass[conference]{IEEEtran}`，保留类文件默认双栏布局、字号和页边距；未使用 `geometry`、手动缩放或修改行距。西文字体显式选用与 Times、Helvetica 和 Courier 兼容的 TeX Gyre Termes、Heros 和 Cursor，以支持 XeLaTeX；中文使用 Fandol 字体。模板选择依据：

- [IEEE Author Center：Authoring Tools and Templates](https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/)
- [IEEE 官方会议 LaTeX 模板](https://www.overleaf.com/latex/templates/ieee-conference-template/grfzhhncsfqn)

中文稿是适配中文阅读的 IEEE 布局版本。正式投稿应以目标会议或期刊指定模板、语言和页数要求为准；这里没有指定投稿 venue，也不宣称已经通过 IEEE PDF eXpress 检查。

研究背景文献已经核对：

1. [SecVulEval 正式会议论文](https://doi.org/10.1145/3805760.3814932)：Md Basim Uddin Ahmed 等，*SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection*，发表于 *Proceedings of the 3rd ACM International Conference on AI-Powered Software (AIware '26)*，2026 年，第 388–396 页，ACM。正文引用及 BibTeX 均采用正式发表版本。题名、作者、会议和 DOI 已与 [AIware 2026 官方论文页面](https://2026.aiwareconf.org/details/aiware-2026-benchmark---dataset-track/11/SecVulEval-Context-Aware-Benchmarking-of-LLMs-for-Vulnerability-Detection) 核对，页码亦见作者在约克大学存档的学位论文前言。
2. [PrimeVul 正式会议论文](https://doi.org/10.1109/ICSE55347.2025.00038)，发表于 ICSE 2025。
3. [SecVulEval 数据卡](https://huggingface.co/datasets/arag0rn/SecVulEval/blob/main/README.md)。

## 编译

LaTeX 编译依赖 TeX Live 或 MiKTeX，不依赖 Conda 的 `pap` 环境。需要 XeLaTeX、BibTeX，以及 `IEEEtran`、`ctex`、`fontspec`、Fandol 和 TeX Gyre 字体、`cite`、`amsmath`、`amssymb`、`booktabs`、`graphicx`、`balance`、`xurl` 和 `hyperref`。重新生成图形还需要 `standalone`、`pgfplots` 和 `fix-cm`。本机使用 TeX Live 2025。

在 `proposal` 目录中执行：

```powershell
xelatex -interaction=nonstopmode -halt-on-error proposal_zh.tex
bibtex proposal_zh
xelatex -interaction=nonstopmode -halt-on-error proposal_zh.tex
xelatex -interaction=nonstopmode -halt-on-error proposal_zh.tex

xelatex -interaction=nonstopmode -halt-on-error proposal_en.tex
bibtex proposal_en
xelatex -interaction=nonstopmode -halt-on-error proposal_en.tex
xelatex -interaction=nonstopmode -halt-on-error proposal_en.tex
```

也可以直接上传源码 ZIP 到 Overleaf，选择 XeLaTeX 编译器，并将希望编译的语言版本设为 Main document。手动上传时，须同时保留 `figures` 文件夹中的两张 PDF，不能仅上传主 `.tex` 和参考文献。

原始的源文件索引、标签、修复关联和漏洞说明用于数据追溯；正文已提示，后续实验应另行确定模型输入字段，避免标签泄露。

## CWE 柱状图的统计口径

图中蓝色为独立集的 160 条有漏洞函数，橙色为配对集的 200 条漏洞版本。40 条独立集无漏洞函数和全部 200 条修复版本均不计入漏洞数量。每条漏洞函数对其每个 CWE 类型最多贡献一次计数。

源记录包含 `CWE-125CWE-787` 这样的连写标签，绘图时按编号拆分并在单个函数内去重，保留原始 JSON 不变。两组各覆盖 39 种数字 CWE，合并为 57 种；另将 `NVD-CWE-noinfo`、`NVD-CWE-Other` 两类占位标记单独展示，图中分别简写为 `NVD-noinfo`、`NVD-Other`。占位标记不是具体漏洞类型。

图中展示全部 59 个观测类别，没有省略长尾类别；按两组计数之和降序排列，分为三个面板，横轴刻度保持一致。独立集和配对集分别有 10 条和 11 条多标签漏洞函数。计入 NVD 占位标记的标签归属总数分别为 173 和 213，其中数字 CWE 归属分别为 163 和 198，因此标签归属总数不能等同于漏洞函数数量。

在 `proposal` 目录中重新统计并生成矢量图：

```powershell
conda run -n pap python build_cwe_figures.py
xelatex -interaction=nonstopmode -halt-on-error -output-directory=figures figures/cwe_distribution_zh.tex
xelatex -interaction=nonstopmode -halt-on-error -output-directory=figures figures/cwe_distribution_en.tex
```

统计脚本通过相对路径读取项目中的两份数据集，使用 Python 标准库；绘图由 PGFPlots 完成，不需要额外安装 Python 绘图库。ZIP 已包含编译好的图形，仅编译 proposal 时无需重新统计或提供原始 JSON。图表属于数据描述，实验方法、实验模型和实验结果章节仍保持空白。

## 本机验证

加入柱状图后，两版均已通过 XeLaTeX 与 BibTeX 编译，每版 3 页、Letter 纸张、双栏排版，图形跨双栏放置。已逐页检查渲染预览，确认没有文字溢出、缺字或未解析引用，PDF 字体均已嵌入。三个实验章节的可见正文为空，仅保留标题；数据数量与现有 JSON 元数据一致。

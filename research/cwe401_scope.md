# CWE-401 范围核查：原始“C++ 内存泄漏 / Juliet CWE-401”目标与当前 SecVulEval 子集

**结论：不一致，当前两个固定子集不足以支持 CWE-401 专项定量结论。** 当前子集是跨 CWE 的真实项目 C/C++ 抽样，不是 CWE-401 专项集；CWE-401 漏洞函数只有 4 条（独立集 2/160，配对集 2/200），其中按扩展名仅 1 条是 C++ 文件，且该条同时带有 CWE-415 标签。建议把主研究定位为“全 CWE、真实项目 C/C++ 函数级漏洞检测 + 漏洞/修复判别”，CWE-401 只作为 4 条函数的定性案例和长尾覆盖限制。若必须做 CWE-401 专项，需要重新抽样或改用 Juliet 等专用基准，不能复用当前 200/200 子集。

- 核查日期：2026-11-11
- 核查范围：只读 `datasets/independent_200.json` 与 `datasets/vulnerable_fixed_200_pairs.json`
- 未读取 `SecVulEval.xlsx`，未调用任何模型，未修改数据集
- 运行环境：WSL + Python 3 标准库；Windows 路径 `C:\Users\tzh03\Downloads\zy`，WSL 路径 `/mnt/c/Users/tzh03/Downloads/zy`

---

## 1. 数据与计数口径

### 1.1 文件与一致性

| 文件 | 结构 | 数量 | SHA-256 |
| --- | --- | --- | --- |
| `datasets/independent_200.json` | `metadata` + `samples` | 200 条（160 漏洞 + 40 非漏洞） | `055eccc29f640d47653f5289e6b7a9468fead248c05b137aec8779ba7461dc3d` |
| `datasets/vulnerable_fixed_200_pairs.json` | `metadata` + `pairs` | 200 对（400 条函数记录） | `7028b98d6f2c13b960bd08dd2e737e2ba61732b89dba03e3f173fe44c27214d5` |

两个哈希与 `proposal/figures/cwe_counts.json` 中记录的源文件哈希一致，说明本次核查使用的是提案统计所用的同一份数据快照。

### 1.2 CWE 计数规则

- `cwe_list` 是 JSON 数组，但元素可能是连写标签，例如 `CWE-415CWE-401`、`CWE-125CWE-787`。本报告用正则 `CWE[-_ ]?(\d+)` 拆分，并在单条记录内去重。
- 一条记录只要任一 CWE 标签为 CWE-401，就计为一条“CWE-401 记录”；多标签记录同时也会出现在其他 CWE 的计数中，因此各 CWE 计数之和大于记录数。
- “漏洞记录”只指 `is_vulnerable == true` 的记录。修复版本和独立集负样本的 `is_vulnerable == false`，即使 `cwe_list` 保留 CWE-401，也不计入漏洞分子。
- 百分比分母分别为独立集 160、配对集 200、合计 360 条漏洞记录。
- 抽样规则没有 CWE 配额（`datasets/README.md` 第 5 条；提案第 114 行）。因此 CWE-401 的数量是随机抽样的结果，不是为 CWE-401 设计的统计层。

### 1.3 元数据与实际数量核对

| 集合 | metadata 声明 | 实际读取 | 结论 |
| --- | --- | --- | --- |
| 独立集 | 200 条；160 漏洞；40 非漏洞 | 200 条；160 `true`；40 `false` | 一致 |
| 配对集 | 200 对；400 条函数 | 200 对；400 条函数 | 一致 |

两个集合的 `idx` 互不重叠：独立集与配对集漏洞版本重叠 0 条，与配对集修复版本重叠 0 条，配对集内部漏洞/修复索引重叠 0 条。合计 600 条不同记录。

---

## 2. 核心计数

### 2.1 CWE-401 在漏洞记录中的数量

| 集合 | 记录数 | 漏洞记录 | CWE-401 漏洞记录 | 占该集漏洞记录 | 其中单一 CWE-401 标签 | 其中多标签含 CWE-401 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 独立集 | 200 | 160 | 2（idx 17743、5896） | 1.25% | 1（5896） | 1（17743） |
| 配对集 | 400（200 对） | 200 | 2（idx 5886、8675） | 1.00% | 2（5886、8675） | 0 |
| **合计** | **600** | **360** | **4** | **1.11%** | **3** | **1** |

### 2.2 非漏洞/修复记录中的 CWE-401 元数据

| 集合 | 非漏洞/修复记录 | 其中 `cwe_list` 含 CWE-401 | 说明 |
| --- | ---: | ---: | --- |
| 独立集 | 40 | 1（idx 17507） | SDL 修复提交中的函数，`is_vulnerable=false` |
| 配对集 | 200 | 2（idx 5887、8676） | 两条 CWE-401 配对的修复版本 |
| **合计** | **240** | **3** | 只是元数据，不能算作 CWE-401 漏洞样本 |

**重要口径问题：** 修复版本会保留其对应 CVE 的 `cwe_list`。例如 idx 17507 的提交信息是 “Fix potential memory leak in GLES_CreateTexture”，它本身是修复版本，不是有漏洞函数。若直接对 `cwe_list` 过滤 CWE-401 而不先按 `is_vulnerable` 分层，独立集会得到 3 条而不是 2 条，并把一条负样本混进“CWE-401 漏洞组”。后续任何 CWE 分层都必须先固定 `is_vulnerable=true` 的条件。

### 2.3 CWE-401 漏洞记录明细

| 集合 | idx / pair_id | 项目 | 文件（扩展名） | 函数 | 原始 `cwe_list` | `cve_list` | `fixed_func_idx` | `func_body` 字符数 |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: |
| 独立集 | 17743 | dcmtk | `dcmnet/libsrc/dulfsm.cc`（.cc） | `destroyPresentationContextList` | `["CWE-415CWE-401"]` | `["CVE-2021-41688CVE-2021-41687CVE-2021-41690"]` | `null` | 640 |
| 独立集 | 5896 | linux | `drivers/spi/spi-fsl-lpspi.c`（.c） | `fsl_lpspi_probe` | `["CWE-401"]` | `["CVE-2019-19064"]` | 5895（不在当前子集） | 3,636 |
| 配对集 | 5886:5887 | linux | `drivers/scsi/bfa/bfad_attr.c`（.c） | `bfad_im_get_stats` | `["CWE-401"]` | `["CVE-2019-19066"]` | 5887 | 1,595 |
| 配对集 | 8675:8676 | ImageMagick | `coders/tiff.c`（.c） | `ReadTIFFImage` | `["CWE-401"]` | `["CVE-2021-3574"]` | 8676 | 32,767（疑似截断） |

补充说明：

- **17743 不是干净的“泄漏”样本。** 原始标签是连写的 `CWE-415CWE-401`，提交信息为 “Fixed poss. NULL pointer dereference/double free”；CWE-415 是 double free，提交信息强调的是空指针/双重释放。把 17743 当作 CWE-401 单一案例会混淆弱点类型。其 `cve_list` 也是三个 CVE 的连写字符串，直接按字符串计数会把 3 个 CVE 算成 1 个。
- **8675/8676 的正文恰好为 32,767 字符**，末尾停在半个条件表达式（`if ((photometric == `），左右花括号计数为 94/92，正文不完整，疑似源表单元格截断（Excel 单元格上限为 32,767 字符）。这对 LLM 输入和定性分析都是硬限制；如果选它作案例，必须注明截断，并单独规定截断/分块策略。
- 5896 的 `fixed_func_idx=5895` 不在当前两个子集中；配对集和独立集的隔离约束仍然成立。
- 5887、8676 两条修复记录也带有 `cwe_list=["CWE-401"]`，但 `is_vulnerable=false`，不能计入漏洞样本。

### 2.4 CWE 多样性与 CWE-401 的位置

| 指标 | 独立集漏洞 | 配对集漏洞 | 合并 |
| --- | ---: | ---: | ---: |
| 数字 CWE 类型数 | 39 | 39 | 57 |
| 数字 CWE 标签归属数 | 163 | 198 | — |
| CWE-401 归属数 | 2 | 2 | 4 |
| CWE-401 在数字 CWE 中的合并排名 | — | — | 第 16 / 57 |
| 数字 CWE 多标签漏洞函数数 | 10 | 11 | — |
| 单一记录最大标签数 | 5 | 4 | — |
| CWE 计数 ≥10 的类型数 | 6 | 7 | — |
| 单例 CWE（只出现 1 次）类型数 | 23 | 18 | — |

合并计数最高的类别是 CWE-119（48）、CWE-125（44）、CWE-416（34）、CWE-20（31）、CWE-787（31）、CWE-476（28）。CWE-401 合并只有 4 条，排在第 16 位，属于明显的长尾类别。独立集只有 6 种 CWE 达到 10 条，配对集只有 7 种；大多数 CWE 类型本身也不足以做逐类推断。

这些数字与 `proposal/figures/cwe_counts.json` 的口径一致：两组各 39 种数字 CWE、合并 57 种、数字标签归属 163/198、多标签函数 10/11。该文件还把 17743 列为连写标签来源之一，可作为交叉核对。

---

## 3. 语言与项目证据

### 3.1 语言分布

数据集没有 `language` 字段，只能用文件扩展名做代理：

| 集合 | 漏洞记录 | `.c` | C++ 扩展名（`.cc`/`.cpp`/`.cxx`） | CWE-401 漏洞 `.c` | CWE-401 漏洞 C++ |
| --- | ---: | ---: | ---: | ---: | ---: |
| 独立集 | 160 | 111（69.4%） | 49（30.6%） | 1（5896） | 1（17743，.cc） |
| 配对集 | 200 | 150（75.0%） | 50（25.0%） | 2（5886、8675） | 0 |
| **合计** | **360** | **261（72.5%）** | **99（27.5%）** | **3** | **1** |

按扩展名推断：

- 全部 360 条漏洞函数中，`.c` 占 72.5%，C++ 扩展名占 27.5%；数据整体以 C 为主，不是“C++ 专项”数据集。
- 4 条 CWE-401 漏洞函数中，3 条是 `.c`（Linux 两条、ImageMagick 一条），1 条是 `.cc`（DCMTK）。C++ 占比 1/4。
- 若把条件收紧为“C++ 文件 + 单一 CWE-401 标签”，满足条件的记录是 **0 条**；唯一一条 C++ 记录 17743 同时带 CWE-415。
- `.c` 也可能在少数项目中以 C++ 方式编译，但 Linux、ImageMagick、SDL 的上述文件按惯例是 C；这不影响“C++ 样本至多 1 条、干净 C++ CWE-401 为 0”的结论。

### 3.2 项目分布

- 600 条记录覆盖 134 个不同项目，全部 600 条都有非空 `cve_list`。
- 漏洞记录中，独立集最大的项目是 linux（43 条）和 Chrome（28 条）；配对集是 linux（53 条）和 Chrome（25 条）。项目高度不均衡。
- 4 条 CWE-401 漏洞记录只来自 3 个项目：dcmtk（1）、linux（2）、ImageMagick（1）。其中 Linux 占一半。
- 这意味着即使把 4 条都做定性分析，项目层面的有效样本也只有 3 个聚类；任何按项目聚类的置信区间都会很宽。

### 3.3 定性线索

从提交信息和改动语句看，4 条中有 3 条是比较明确的错误路径资源释放问题：

- 5896：提交信息 “spi: lpspi: fix memory leak in fsl_lpspi_probe”；改动是在 `pm_runtime_get_sync` 失败时转到错误处理路径，避免 SPI controller 泄漏。
- 5886：提交信息 “scsi: bfa: release allocated memory in case of error”；改动是在 `bfa_port_get_stats` 失败时释放已分配内存。
- 8675：改动在 `samples_per_pixel > MaxPixelChannels` 分支加入 `TIFFClose(tiff)` 后抛错，避免 TIFF 句柄泄漏；但正文被截断。
- 17743：提交信息强调 NULL pointer dereference/double free，原始标签同时有 CWE-415 和 CWE-401，不能当作纯泄漏案例。

这 3 条“较干净”的泄漏案例全部是 C 文件，且总数只有 3 条；它们可以支撑“模型是否会指出错误路径缺少释放”的定性观察，但不能支撑 CWE-401 的定量召回率/F1。

---

## 4. 与“Juliet CWE-401”的一致性

**结论：不是同一类基准，不能直接对应。**

1. **来源不同。** Juliet 是合成的、按 CWE 组织的测试套件，CWE-401 用例是为该弱点专门构造的；SecVulEval 是真实 CVE/提交数据集，当前 600 条记录全部带 CVE，覆盖 134 个真实项目。两个 JSON 中大小写不敏感地搜索 `juliet`，命中数为 **0**；项目名、文件路径、提交信息中也没有 Juliet 痕迹。
2. **标签语义不同。** Juliet 的 CWE-401 用例有明确的“泄漏/修复”构造和预期标签；SecVulEval 的 `cwe_list` 来自 NVD/CVE 与提交关联，可能是多标签、连写标签，修复版本还保留原 CVE 的 CWE 元数据。17743 的 `CWE-415CWE-401` 和 17507 的“修复版本仍带 CWE-401”就是例子。
3. **语言与代码形态不同。** Juliet 可以为 C/C++ 分别生成成组的 CWE-401 用例；当前子集 72.5% 是 `.c`，CWE-401 漏洞中 75% 是 C，且函数长度从 640 到 32,767 字符不等，其中一条还被截断。
4. **规模不同。** 当前 CWE-401 漏洞只有 4 条；Juliet 的 CWE-401 是专门成组构造的测试集。即使不讨论具体条数，两者的抽样单位和统计功效完全不在一个量级。

因此，不能把当前子集称为“Juliet CWE-401”或“C++ 内存泄漏”基准；也不能把在 Juliet CWE-401 上得到的结论外推到 SecVulEval，反之亦然。

---

## 5. 是否足以支持 CWE-401 专项结论

**不足以支持任何 CWE-401 专项的定量结论。** 具体理由：

1. **样本量太小。** 独立集 2/160（1.25%），配对集 2/200（1.00%），合计 4/360（1.11%）。在 2 条样本的子组里，一条预测翻转就会让子组 recall 变化 50 个百分点；在 4 条样本里也会变化 25 个百分点。作为不确定性示意，2/160 的 Wilson 95% 区间约为 0.34%–4.44%，2/200 约为 0.27%–3.57%（该区间只作数量级示意，因为抽样是带约束的，不是简单随机样本）。这样的子组无法稳定估计 precision/recall/F1，也无法据此给 2–3 种方法排名称。
2. **“C++”条件几乎为空。** 4 条中只有 1 条 `.cc`，且是 CWE-415+CWE-401 双标签；严格“C++ + 单一 CWE-401”为 0 条。原始目标里的“C++ 内存泄漏”在当前子集上没有可用的 C++ 正样本。
3. **不是 Juliet。** 0 条 Juliet 记录，600/600 是带 CVE 的真实项目；来源、标签语义、代码分布都不同，无法回答 Juliet CWE-401 的问题。
4. **CWE-401 组不干净。** 10/160 和 11/200 的漏洞函数带有多个数字 CWE 标签；17743 同时是 CWE-415；独立集负样本中还有 1 条 CWE-401 元数据（17507）。直接按 `cwe_list` 过滤会把负样本混入，或把 double free 当成纯泄漏。
5. **有效聚类很少。** 4 条记录只来自 3 个项目，Linux 占 2 条；按项目/提交聚类后，有效样本更小。任何 CWE-401 子组结论都会被 1–2 个项目主导。
6. **没有跨子集的 CWE-401 对照。** 两个子集的 `idx` 完全不重叠（交集 0），因此无法做“同一 CWE-401 函数在独立集 vs 配对集”的 RQ3 式比较。
7. **缺少泄漏专用标注。** `changed_statements` 给出修复行，但没有分配/释放配对、泄漏点或资源所有权标注；要评估“泄漏检测”本身，需要额外代码审计，不能只靠 CWE 标签。
8. **一条案例输入不完整。** 8675/8676 的正文 32,767 字符且被截断，不能作为完整函数输入；这会直接影响定性案例的可解释性。

### 可以支持的表述

- 描述性事实：“在 160 条独立漏洞函数中 CWE-401 有 2 条（1.25%）；在 200 条配对漏洞函数中有 2 条（1.00%）；合计 4/360（1.11%）。”
- 定性案例：“对 4 条 CWE-401 漏洞函数（含 2 对配对）做案例观察，看模型是否提到错误路径上的释放/资源生命周期。”
- 有效性限制：“当前子集的 CWE-401 样本不足以做逐 CWE 定量分层；这是长尾覆盖限制。”

### 不能支持的表述

- CWE-401 的 precision/recall/F1、AUC、方法排名。
- “C++ 内存泄漏检测”性能。
- 与 Juliet CWE-401 的可比性或迁移结论。
- 任何把 4 条案例外推为总体 CWE-401 表现的结论。

---

## 6. 不重新抽样下的主研究定位

在不改变 200/200 子集的前提下，建议把论文/课程项目的主问题锁定为：

> **在 SecVulEval 的跨 CWE、真实项目 C/C++ 子集上，比较 2–3 种 LLM 方法的函数级漏洞检测能力，以及漏洞版本/修复版本的判别能力；CWE 只作为描述性和探索性分层，不作为 CWE-401 专项结论。**

这一定位与课程要求一致：同一数据集、2–3 种 LLM 方法、定量结果、成本和定性案例；同时避免用 4 条样本编造 CWE-401 性能。

### 6.1 建议的研究问题

- **RQ1（独立函数检测）**：在 160 漏洞 + 40 非漏洞的独立集上，各方法的 precision、recall、F1、accuracy、balanced accuracy、MCC 如何？按项目/提交聚类给出 bootstrap 置信区间。
- **RQ2（漏洞/修复判别）**：在 200 对上，方法能否同时把漏洞版本判为有漏洞、修复版本判为无漏洞？报告 pair-level both-correct rate、漏洞版本 recall、修复版本 specificity；以“对”为分析单位，不把 400 条当作 400 个独立观测。
- **RQ3（两个子集的互补性）**：独立函数上的表现与配对判别上的表现是否一致？配对差异用按项目/提交聚类的 bootstrap；不要假设两个子集独立同分布。
- **CWE 分层（描述性）**：只对样本量足够的类别报告逐类结果；建议预先设定最小 n（例如 n≥10），低于阈值的类别只列计数并标注“insufficient n”。CWE-401 明确标为 n=4 的案例系列，不进入逐类排名。
- **成本**：每种方法的 token 数、延迟、API 费用/1,000 条函数或 1,000 对、失败/重试率；成本按子集和方法分别报告。
- **定性案例**：4 条 CWE-401 函数 + 高样本量类别的典型错误；展示模型理由、漏报/误报模式；不把 CWE-401 案例升级为定量结论。

### 6.2 分析单位与统计口径

- 独立集：200 条函数，标签比例 160:40；不要把它解释为真实世界漏洞 prevalence。
- 配对集：200 对；同一对的两个版本是相关观测，不能当 400 条独立样本。配对分析应使用 pair-level 指标或按对聚类的 bootstrap。
- 两个子集共享 0 个 `idx`、0 个 `(project, commit_id)` 组；这是抽样隔离，不是统计独立性。配对集内部每个 pair 的两个版本共享同一 `(project, commit_id)`，这是配对定义；分析时应按 pair 或按该组聚类，不能把两个版本拆成独立组。
- 逐 CWE 结果必须同时报告 n；CWE-401、CWE-415 等长尾类别只做案例/描述。
- 任何 CWE 过滤都先固定 `is_vulnerable=true`；修复版本的 `cwe_list` 不能当正样本。

### 6.3 方法与输入（仅定位，不代替方法选型）

方法选型属于另一个工作流；这里只锁定评估对象和分层口径。无论选哪 2–3 种方法，建议：

- 使用同一输入字段、同一输出 schema、同一解码参数；避免把 `cwe_list`、`cve_list`、`commit_message`、`changed_statements` 等标签/答案线索放进 prompt。
- 对超长函数（如 8675 的 32,767 字符）统一截断/分块策略，并把它作为上下文长度消融或限制报告，而不是静默截断。
- 对 2–3 种方法报告相同的 aggregate 指标、pair-level 指标和成本；定性案例从同一批预测中抽取，避免只挑成功案例。

### 6.4 建议的论文定位措辞

可以使用类似：

> “A Multi-CWE Evaluation of LLM-Based Vulnerability Detection and Vulnerable–Fixed Discrimination on SecVulEval”

避免：

> “CWE-401 Memory Leak Detection with LLMs”  
> “Juliet CWE-401 Benchmark Evaluation”

后者与数据不符，审稿人/课程评估很容易用 2/160 的计数质疑。

---

## 7. 可选扩展（不重新抽样）

| 扩展 | 可用样本（漏洞记录） | 可行性 | 说明 |
| --- | --- | --- | --- |
| A. 资源生命周期家族：CWE-401/404/415/772 | 独立集 5/160（3.1%）；配对集 9/200（4.5%） | 低–中 | 比 CWE-401 大 2.5–4.5 倍，但仍小；只能做家族级描述，不能做 CWE-401 专项推断 |
| B. 内存安全家族：CWE-119/125/787/416/415/401 | 独立集 74/160（46.2%）；配对集 83/200（41.5%） | 中–高 | 可做家族级分层/错误分析；类别异质，包含 UAF、越界、双重释放等，不能替代“泄漏”结论 |
| C. CWE-401 定性案例 | 4 条漏洞函数 / 2 对 | 高 | 最稳妥的 CWE-401 用法；注意 17743 双标签、8675 截断 |
| D. 长尾覆盖与标签噪声分析 | 39 种/组；单例 23/18；负样本 CWE-401 3 条 | 高 | 可量化“多少 CWE 类型可评估”、连写标签/多标签/修复版本继承标签的影响，作为方法学贡献 |
| E. 真正的 CWE-401 专项 | 需新抽样 | 需新数据 | 从完整 SecVulEval 重新分层抽样，或改用 Juliet CWE-401；需要新数据卡、重新冻结哈希，不能复用当前 200/200 |

### 7.1 家族级扩展的具体口径

- A 的计数是“并集去重”：一条函数只要带 CWE-401/404/415/772 中任一标签就计一次，不重复计。独立集 5 条、配对集 9 条。
- B 的计数同样是并集去重；它适合回答“模型在内存安全大类上是否更差”，不适合回答“模型是否能发现内存泄漏”。如果课程/导师真正关心的是内存安全而非泄漏，CWE-416（use-after-free）在独立集有 23 条、配对集有 11 条，是比 CWE-401 更可支撑的邻近类别；但这是研究问题变更，需要明确确认，不能偷偷替换。
- C 是唯一不需要新抽样、又能保留“CWE-401”字样的做法；建议在报告中用“case series”而不是“evaluation”措辞。
- D 可以直接从现有 JSON 统计：23/39 和 18/39 的 CWE 类型是单例；只有 6/39 和 7/39 达到 n≥10。这个结果本身就能支撑“当前子集不适合逐 CWE 推断”的方法学论点。
- E 需要读取 `SecVulEval.xlsx`（`openpyxl`）或引入 Juliet；本次任务明确不读 Excel、不重抽样，因此只作为后续选项，不在本文件实施。

---

## 8. 限制

1. **只看了两个 JSON。** 未读取 `SecVulEval.xlsx`，因此无法给出全语料（10,998 条漏洞函数）的 CWE-401 总数或占比；4/360 只描述当前子集，不能外推为 SecVulEval 全体的 CWE-401 prevalence。
2. **语言是扩展名代理。** 数据集没有 `language` 字段；`.c` 在少数项目中可能按 C++ 编译，`.cc/.cpp` 一般视为 C++。结论“C++ 至多 1 条、干净 C++ CWE-401 为 0”不受这个代理的不确定性影响，因为唯一的 C++ 候选 17743 本身就是双标签。
3. **CWE 标签是元数据，不是代码审计。** `cwe_list` 可能连写、多标签、含 NVD 占位符（`NVD-CWE-noinfo`、`NVD-CWE-Other`），修复版本还会继承原 CVE 的标签；本报告没有逐条验证 4 条 CWE-401 的代码语义。
4. **抽样是带约束的随机抽样。** 固定种子 42、每个 `(project, commit_id)` 最多一条、先选配对再选独立集、无 CWE 配额；百分比是描述性的，Wilson 区间只作数量级示意。
5. **没有模型运行。** 本文件不包含任何模型性能数字；所有关于“能否支持结论”的判断都是基于数据计数和标签语义，不是基于实验结果。
6. **个别记录有质量问题。** 17743 的 CWE/CVE 都是连写字符串；8675/8676 的正文 32,767 字符且截断；17507 是带 CWE-401 元数据的负样本。这些都会影响 CWE-401 子组的解释。
7. **跨子集没有 CWE-401 对照。** 两个子集 `idx` 交集为 0，无法做同一 CWE-401 函数的独立/配对比较。
8. **项目聚类很少。** CWE-401 只来自 3 个项目，Linux 占 2 条；按项目聚类的有效样本远小于 4。

---

## 9. 可复核命令与输出

在 WSL 中执行（只读两个 JSON，不读 Excel，不写文件）：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && python3 - <<"PY"
import json, re, collections
CWE = re.compile(r"CWE[-_ ]?(\d+)")
def labels(r):
    raw = r.get("cwe_list") or []
    return {"CWE-" + m for m in CWE.findall(" ".join(map(str, raw)))}
def ext(p):
    return "." + p.rsplit(".", 1)[-1].lower() if "." in p else "<none>"

ind = json.load(open("datasets/independent_200.json", encoding="utf-8"))
pr = json.load(open("datasets/vulnerable_fixed_200_pairs.json", encoding="utf-8"))
print("meta ind:", ind["metadata"]["sample_count"], ind["metadata"]["vulnerable_count"], ind["metadata"]["non_vulnerable_count"])
print("meta pair:", pr["metadata"]["pair_count"], pr["metadata"]["function_count"])

groups = [
    ("independent", ind["samples"], [s for s in ind["samples"] if s["is_vulnerable"]]),
    ("pairs", [x for p in pr["pairs"] for x in (p["vulnerable"], p["fixed"])], [p["vulnerable"] for p in pr["pairs"]]),
]
for name, recs, vuln in groups:
    c401 = [r["idx"] for r in vuln if "CWE-401" in labels(r)]
    neg401 = [r["idx"] for r in recs if not r["is_vulnerable"] and "CWE-401" in labels(r)]
    multi = sum(1 for r in vuln if len(labels(r)) > 1)
    ec = collections.Counter(ext(r["filepath"]) for r in vuln)
    cpp = sum(v for k, v in ec.items() if k in {".cc", ".cpp", ".cxx"})
    pct = len(c401) / len(vuln) * 100
    print(f"{name}: records={len(recs)} vuln={len(vuln)} c401_vuln={len(c401)} {c401} "
          f"pct={pct:.2f}% neg401={len(neg401)} {neg401} multi={multi} ext={dict(ec)} cpp={cpp}")

for r in ind["samples"] + [p["vulnerable"] for p in pr["pairs"]] + [p["fixed"] for p in pr["pairs"]]:
    if "CWE-401" in labels(r):
        print("401rec:", r["idx"], r["project"], r["filepath"], r["func_name"], r["cwe_list"],
              r["cve_list"], r["fixed_func_idx"], r["is_vulnerable"], len(r["func_body"]))

I = {s["idx"] for s in ind["samples"]}
Pv = {p["vulnerable"]["idx"] for p in pr["pairs"]}
Pf = {p["fixed"]["idx"] for p in pr["pairs"]}
print("overlap:", len(I & Pv), len(I & Pf), len(Pv & Pf))
Ig = {(s["project"], s["commit_id"]) for s in ind["samples"]}
Pg = {(p["vulnerable"]["project"], p["vulnerable"]["commit_id"]) for p in pr["pairs"]}
print("group overlap:", len(Ig & Pg))
blob = json.dumps(ind, ensure_ascii=False) + json.dumps(pr, ensure_ascii=False)
print("juliet hits:", len(re.findall("juliet", blob, re.I)))
allrecs = ind["samples"] + [x for p in pr["pairs"] for x in (p["vulnerable"], p["fixed"])]
print("projects:", len({r["project"] for r in allrecs}), "cve_nonempty:", sum(bool(r.get("cve_list")) for r in allrecs), "/", len(allrecs))
PY'
```

本次运行的关键输出：

```text
meta ind: 200 160 40
meta pair: 200 400
independent: records=200 vuln=160 c401_vuln=2 [17743, 5896] pct=1.25% neg401=1 [17507] multi=10 ext={'.cpp': 23, '.cc': 26, '.c': 111} cpp=49
pairs: records=400 vuln=200 c401_vuln=2 [5886, 8675] pct=1.00% neg401=2 [5887, 8676] multi=11 ext={'.cpp': 26, '.c': 150, '.cc': 23, '.cxx': 1} cpp=50
401rec: 17743 dcmtk dcmnet/libsrc/dulfsm.cc destroyPresentationContextList ['CWE-415CWE-401'] ['CVE-2021-41688CVE-2021-41687CVE-2021-41690'] None True 640
401rec: 17507 SDL src/render/opengles/SDL_render_gles.c GLES_CreateTexture ['CWE-401'] ['CVE-2022-4743'] None False 3146
401rec: 5896 linux drivers/spi/spi-fsl-lpspi.c fsl_lpspi_probe ['CWE-401'] ['CVE-2019-19064'] 5895 True 3636
401rec: 5886 linux drivers/scsi/bfa/bfad_attr.c bfad_im_get_stats ['CWE-401'] ['CVE-2019-19066'] 5887 True 1595
401rec: 8675 ImageMagick coders/tiff.c ReadTIFFImage ['CWE-401'] ['CVE-2021-3574'] 8676 True 32767
401rec: 5887 linux drivers/scsi/bfa/bfad_attr.c bfad_im_get_stats ['CWE-401'] ['CVE-2019-19066'] 5887 False 1618
401rec: 8676 ImageMagick coders/tiff.c ReadTIFFImage ['CWE-401'] ['CVE-2021-3574'] 8676 False 32767
overlap: 0 0 0
group overlap: 0
juliet hits: 0
projects: 134 cve_nonempty: 600 / 600
```

如需核对文件哈希：

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/zy && sha256sum datasets/independent_200.json datasets/vulnerable_fixed_200_pairs.json'
```

预期输出与第 1.1 节的两个 SHA-256 一致。

---

## 10. 建议的下一步

1. **明确弃用“CWE-401 / Juliet CWE-401 专项”作为主研究目标。** 当前数据不支持；继续按这个目标写会迫使报告用 4 条样本编造性能，违反“不编造结果”的要求。
2. **把主研究锁定为全 CWE 的 C/C++ 函数级检测 + 漏洞/修复判别。** 采用 RQ1–RQ3，2–3 种 LLM 方法，报告 aggregate、pair-level、成本和定性案例；CWE 只做描述性分层。
3. **预先注册逐 CWE 最小 n。** 建议 n≥10；CWE-401（n=4）固定为 case series，不参与逐类排名。汇报时同时给出 n 和“insufficient n”标记。
4. **CWE-401 案例只选完整、干净的样本。** 优先 5896、5886；17743 必须标注 CWE-415 双标签；8675 必须标注 32,767 字符截断。不要把 4 条案例写成 4 条“C++ 泄漏”样本。
5. **如果课程/导师仍要求 CWE-401 专项，另立数据任务。** 从完整 SecVulEval 做 CWE-401 分层抽样，或改用 Juliet CWE-401；重新冻结哈希、重新写数据卡，并明确不能与当前 200/200 的结果直接比较。

# SecVulEval 原始论文与官方工件复核

> 复核日期：2026-11-11
> 复核对象：AIware '26 正式论文（ACM DL，CC BY 4.0）、arXiv v1、GitHub 仓库 `basimbd/SecVulEval`、Hugging Face 数据集 `arag0rn/SecVulEval`、Crossref / Semantic Scholar 元数据
> 复核方式：正式版 PDF 逐页阅读（Table 3/4/5、§7、§8、§9 逐格核对）；arXiv v1 HTML 全文；仓库 `git clone` 后逐文件审计；本地 `datasets/*.json` 与论文口径交叉核对
> 范围说明：本文只做文献与工件复核，不包含任何模型实测结果；文中所有性能数字均标注了来源版本，未标注的数字一律视为未复现

---

## 0. 结论摘要

1. **正式发表信息已核实**：论文发表于 *AIware '26*（第 3 届 ACM International Conference on AI-Powered Software），2026 年 7 月 6–7 日，Montreal, QC, Canada；页码 388–396，共 9 页；DOI `10.1145/3805760.3814932`；CC BY 4.0 开放获取。正式版标题为 **“SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection”**，与 arXiv v1 的标题不同。
2. **数据规模**：25,440 个函数（10,998 漏洞 + 14,442 非漏洞），5,867 个 CVE，707 个项目，145 种 CWE，覆盖 1999–2024；按函数体 MD5 去重，重复率 0.0%。语句级标签来自修复 commit 的增删语句，上下文由 GPT-4.1 按 Risse & Böhme 的五类定义抽取。
3. **方法**：五智能体流水线（Normalization → Planning → Context → Detection → Validation），其中四个由 LLM 驱动；正式版新增了 **standalone 四示例（four-shot）基线**，因此形成“单模型 vs 多智能体”两组可比设置。
4. **主要结果（正式版逐格核对）**：多智能体设置下最好的 Claude-3.7-Sonnet 语句级 F1 = **23.83%**（P 15.35 / R 53.23），GPT-4.1 为 22.38%；函数级 F1 最高 53.89%。standalone 设置下最好的 Qwen2.5-Coder-32B 语句级 F1 仅 **4.07%**（P 2.24 / R 22.33）。两组差距说明“智能体+上下文”带来数量级提升，但仍是低水平。
5. **上下文识别很弱**：arXiv v1 的分项实验显示，各模型对 Function Argument 的识别准确率仅 0–5.31%，对 Globals/Type Definition 多在 7–41%，**没有任何模型识别出 Environment-level 上下文**（正式版结论仍保留“Claude 在上下文识别上更好”的说法，但分项数字本文仅取自 arXiv v1）。
6. **复现接口存在但不可开箱即用**：仓库有完整五智能体实现、提示词、`orchestrator.ipynb` 和 300 条子集，但**没有评测/指标代码**，指标靠人工看 Excel；**没有 LICENSE**；本地模型输入被 tokenizer 截断到 6,144 token，而 API 模型按字符上限截断，**跨模型输入预算不对等**；`load_llm.py` 还硬编码了作者机器的 HF 缓存路径。
7. **对课程项目的关键含义**：论文的 300 条评测子集（官方文件实际 301 条）是 120 漏洞 + 181 非漏洞（阳性率 39.9%），本项目的 `independent_200.json` 是 160/40（阳性率 80%），两者的 precision 不可直接比较；负样本全部是“修复后版本”，不是自然良性代码，任务本质是近重复判别。课程实验若要做 2–3 种方法对比，最干净的设计是 **standalone → 上下文增强单模型 → 多智能体** 三档，并固定同一模型与同一输入预算。

---

## 1. 正式发表信息核对

### 1.1 书目信息

| 字段 | 值 | 来源 |
|---|---|---|
| 正式标题 | SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection | ACM DL 页面、Crossref、PDF 首页 |
| 作者 | Md Basim Uddin Ahmed；Nima Shiri Harzevili；Jiho Shin；Hung Viet Pham；Song Wang | 同上 |
| 单位 | York University（Ahmed、Harzevili、Pham、Wang）；Queen's University（Shin） | PDF 首页、Crossref affiliation |
| 会议 | AIware '26: 3rd ACM International Conference on AI-Powered Software | ACM DL |
| 发表轨道 | Benchmark & Dataset Track | AIware 2026 程序页 |
| 会议时间/地点 | 2026-07-06 至 2026-07-07，Montreal, QC, Canada | ACM DL、PDF 页眉 |
| 论文集 | Proceedings of the 3rd ACM International Conference on AI-Powered Software | Crossref |
| 页码 | 388–396（9 页） | ACM DL、PDF 页码 |
| 出版日期 | 2026-07-05（在线/印刷同日） | ACM DL、Crossref |
| 投稿/接收 | Received 2026-02-15；accepted 2026-03-28 | 正式版第 396 页脚注 |
| DOI | 10.1145/3805760.3814932 | ACM DL、Crossref |
| 论文集 DOI / ISBN | 10.1145/3805760 / 9798400726019 | ACM DL “Published In” |
| 许可 | CC BY 4.0（Open Access） | ACM DL、PDF 首页 |
| 引用量（易变） | 5 citations / 386 downloads（统计至 2026-11-07） | ACM DL 页面 |
| DBLP key | `conf/aiware/AhmedHSPW26` | Semantic Scholar externalIds |
| arXiv | arXiv:2505.19828v1，2025-05-26，cs.SE，DOI 10.48550/arXiv.2505.19828 | arXiv abs 页 |

### 1.2 正式版与 arXiv v1 的差异（引用时必须注意）

| 项目 | arXiv v1（2025-05-26） | 正式版（2026-07-05） | 影响 |
|---|---|---|---|
| 标题 | SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection | SecVulEval: Context-Aware Benchmarking of LLMs for Vulnerability Detection | 引用题名必须用正式版 |
| Jiho Shin 单位 | York University | Queen's University | 正式版为准 |
| 实验组织 | Experiment 1（检测）+ Experiment 2（上下文识别） | RQ1（standalone 检测）+ RQ2（agentic 检测）+ Failure Analysis + Threats to Validity | 正式版新增 standalone 对照 |
| 检测基线 | 只有五智能体结果 | 新增 Table 3：four-shot 单模型语句级结果 | 课程项目可直接引用“单模型 vs 多智能体”差距 |
| 表格编号 | Table 3 = agentic；Table 4 = context identification；Table 6 = runtime | Table 3 = standalone；Table 4 = agentic；Table 5 = per-CWE | 同一数字在不同版本表号不同，引用需带版本 |
| 函数长度中位数 | 44 行（全体函数） | 48 行（明确写“vulnerable functions”） | 统计口径可能不同，不可当作矛盾 |
| 上下文抽取准确率 | 82.98 ± 9.68%（99% CI，100 样本，4 条 N/A） | 83.16 ± 6.93%（100 样本） | 两版数字不同，引用以正式版为准 |
| 对多智能体的措辞 | “first time … applied”“models still far” | 摘要改为 “modest but promising improvements” | 正式版措辞更保守 |
| 上下文识别分项表 | 有（Table 4，五类上下文） | 我在正式版第 6–9 页未见到该分项表；结论仍保留相关论断 | 分项数字只能标注为 arXiv v1 |

> **引用策略建议**：venue、页码、DOI、总体结论用正式版；提示词全文、runtime 表、上下文识别分项数字用 arXiv v1，并在正文注明 “(arXiv:2505.19828v1)”。不要把两个版本的表格编号混用。

### 1.3 与已有 `proposal/references.bib` 的关系

现有条目 `ahmed2026secvuleval` 的题名、作者、booktitle、series、年份、页码、DOI 与 Crossref 一致，**无需修改**。可选补充：`month = jul`、`address = {New York, NY, USA}`（已有）、`isbn = {9798400726019}`。若正文引用 arXiv 的提示词或 runtime，另加一条 `@misc` 预印本条目，避免把预印本内容归到正式版页码上。

---

## 2. 数据构造

### 2.1 采集流程（arXiv v1 §3.1–3.2）

1. **CVE 来源**：NVD。NVD 不按语言分类，因此复用 BigVul、CVEFixes、PrimeVul 中已认定为 C/C++ 的项目名，把项目名当作 NVD 的 `product` 过滤；同时用 NVD API 关键词检索（`C++`、`C language`、`.cpp` 等），再按文件类型筛掉非 C/C++ 文件。
2. **只保留有补丁的 CVE**：使用 NVD Developers API 的 `Patch` 标签；CVE 状态不能是 `REJECTED`；引用中至少有一个 patch commit 链接；丢弃 fork 仓库的 commit，只保留原仓库。
3. **commit 采集**：GitHub REST API 获取 commit message 与变更文件；清洗 commit message 中的致谢/邮箱行；对每个变更文件抽取 added/deleted lines 与包含这些行的函数；**每个文件、行、函数都保存修复前（vulnerable）与修复后（fixed）两份**。
4. **上下文抽取**：用 GPT-4.1，输入 CWE-ID + CWE 描述、完整函数体、patch（删除/新增行）、commit message、CVE 描述；让模型按五类输出所需外部符号及解释。五类定义来自 Risse & Böhme（Top Score on the Wrong Exam, arXiv:2408.12986）：
   - Function Argument（函数参数）
   - External Function（被调用函数）
   - Type Execution Declaration（struct/enum/typedef 等类型定义）
   - Globals（全局变量、宏）
   - Execution Environment（如某路径下存在特定文件）

### 2.2 过滤与去噪（arXiv v1 §3.3）

| 步骤 | 规则 | 论文给出的量 |
|---|---|---|
| ① 非 C/C++ 文件 | 去掉 `.S`、`.rst`、配置等 | 未给具体数量 |
| ② 多 commit 修复 | 只保留单 commit 修复 | 仅丢弃 43 个 CVE |
| ③ 无函数变更 | 只改原型、注释、enum/struct 字段的 commit 丢弃 | 未给具体数量 |
| ④ tangled change | 只保留“文件中唯一被修改的函数”或“CVE/commit message 明确引用的函数”，去掉重命名/格式化连带修改 | 未给具体数量 |
| ⑤ 去重 | 函数去首尾空白与 `\n`/`\t` 后取 MD5，冲突只留一份 | 最终重复率 0.0% |

### 2.3 最终规模

| 指标 | 数值 | 来源 |
|---|---:|---|
| 函数总数 | 25,440 | 正式版摘要、arXiv §3.3、HF 数据卡 |
| 漏洞函数 | 10,998（43.23%） | 同上 |
| 非漏洞函数 | 14,442（56.77%） | 同上 |
| 唯一 CVE | 5,867 | 同上 |
| 项目数 | 707 | arXiv §3.3、Table 2 |
| CWE 类型 | 145 | 同上 |
| 年份范围 | 1999–2024 | 正式版摘要 |
| 函数长度 | 4–541 行（2.5–97.5 分位） | arXiv §3.3 |
| 长度中位数 | 44 行（全体）/ 48 行（漏洞函数） | arXiv §3.3 / 正式版 §7 |
| 平均变更语句 | 约 4 条删除、6 条新增 | arXiv §3.3 |
| 重复率 | 0.0% | Table 1 |
| 上下文抽取准确率 | 83.16 ± 6.93%（正式版 §8） | 100 随机样本人工核验 |

**Top-10 项目（arXiv v1 Table 2）**

| 项目 | CWE 数 | CVE 数 | 漏洞函数 | 非漏洞函数 |
|---|---:|---:|---:|---:|
| Linux | 69 | 1,920 | 2,793 | 3,288 |
| Chrome | 35 | 526 | 1,748 | 1,940 |
| TensorFlow | 34 | 355 | 547 | 959 |
| Android | 23 | 209 | 551 | 749 |
| ImageMagick | 27 | 172 | 208 | 354 |
| vim | 21 | 162 | 182 | 290 |
| gpac | 22 | 138 | 151 | 215 |
| tcpdump | 8 | 109 | 145 | 206 |
| radare2 | 16 | 103 | 168 | 214 |
| FFmpeg | 20 | 99 | 110 | 152 |
| **合计（707 项目）** | **145** | **5,867** | **10,998** | **14,442** |

> 分布高度集中：Linux + Chrome 占漏洞函数的 41.3%。任何按项目划分的泛化结论都要谨慎。

### 2.4 数据字段（HF 数据卡 + 本地 JSON 核对）

发布表共 **16 列**（数据卡文字称 “15 different fields”，与实际列数不符，属文档小错）：

| 字段 | 类型 | 含义 / 备注 |
|---|---|---|
| `idx` | int64 | 全表唯一索引，`fixed_func_idx` 指向它 |
| `project` | string | 707 个取值 |
| `project_url` | string | 735+ 个取值；`Android` 对应多个仓库 |
| `filepath` | string | 仓库内相对路径 |
| `commit_id` | string | 修复 commit |
| `commit_message` | string | 已清洗致谢/邮箱行 |
| `is_vulnerable` | bool | true=修复前，false=修复后 |
| `hash` | string | 函数体 MD5（32 位） |
| `func_name` | string | 函数名 |
| `func_body` | string | 完整函数源码 |
| `changed_lines` | JSON 字符串 | `(line, code)` 列表；漏洞函数为删除行，非漏洞函数为新增行 |
| `changed_statements` | JSON 字符串 | `(line, statement)` 列表，语句级标签 |
| `cve_list` | list[string] | 可多值 |
| `cwe_list` | list[string] | 可多值；含 `NVD-CWE-noinfo`、`NVD-CWE-Other` 占位符 |
| `fixed_func_idx` | float64 / null | 漏洞函数指向对应修复版本；**非漏洞行在 Excel 中为 null** |
| `context` | struct | 六键：五类上下文 + `Explanation`；**非漏洞行六键全为 null** |

### 2.5 与本项目 600 条子集的关系（本地实测核对）

| 核对项 | 结果 | 说明 |
|---|---|---|
| 源表行数 | 25,440 | 与论文一致 |
| 标签计数 | 10,998 / 14,442 | 与论文一致 |
| 无法解析 `changed_statements` | 7 行（idx 3510, 9418, 9578, 10195, 10196, 16033, 18071） | 本地构建时排除；占 0.03%，不影响结论 |
| 独立集负样本 | 40/40 都有 CVE ID；39/40 有非空 `changed_statements`（新增的修复行）；40/40 的 `context` 六键全 null | **负样本是“修复后版本”，不是自然良性代码** |
| 独立集负样本与配对集 fixed 版本 | 函数体 hash 重合 0/40 | 构建时已隔离，符合 `datasets/README.md` 的约束 |
| 独立集正样本 | 160 条，全部有 context；143 条有 `fixed_func_idx` | 17 条漏洞函数没有对应修复版本 |
| 配对集 | 200 对，400 条；`pair_id` 形如 `20780:20782` | 每对 project/commit/filepath/func_name 一致，标签相反 |

**对课程实验的直接含义**：`independent_200.json` 的阳性率是 80%，论文评测子集是 39.9%（120/301，见 §5），在相同 TPR/FPR 下，前者的 precision 会显著更高。**不能把本项目的 P/R/F1 与论文表 4 直接相减或排名比较**。

---

## 3. 检测方法与提示策略

### 3.1 五智能体流水线（正式版 Figure 4；arXiv §4.1）

| 智能体 | 是否用 LLM | 输入 | 输出 | 约束 |
|---|---|---|---|---|
| Normalization | 否 | 原始函数、文件类型（c/cpp） | 规范化源码 + 紧凑 AST（JSON）+ 行号映射 | tree-sitter 解析；保留注释；可选 clang `-E` / clang-format |
| Planning | 是 | 源码 + 紧凑 AST | `summary`（≤3 句）+ `checklist`（≤8 条） | JSON only；“不要发明代码里没有的符号” |
| Context | 是 | （截断后的）源码 + 已收集符号名 + checklist | `need_more` + `new_symbols`（≤6 个/轮） | 最多 3 轮；符号种类限 function/macro/global/typedef/struct/enum |
| Detection | 是 | 带行号源码 + AST + summary + checklist + 外部上下文 | `is_vulnerable` + `vuln_statements[{line, statement, reason}]` | JSON only；0-based 行号；解析失败重试 1 次，再失败则判非漏洞 |
| Validation | 是 | 同 Detection + Detection 输出 | `agree` + 自己的 `is_vulnerable` / `vuln_statements` | 不同意则 Detection 重跑；最多 3 轮，最后一轮以 Validation 为准 |

**关键实现细节（代码审计）**

- `ContextAgent` 只把函数**截断到 800 字符**（`textwrap.shorten(clean_code, width=800)`）送给 LLM，且**完全忽略传入的 `compact_ast`**。论文文字描述是“given the function”，代码实际是“前 800 字符预览”。这会影响上下文抽取结果的可复现性。
- `ValidationAgent` 的默认模型写的是 `gpt-4o`，但 `orchestrator.ipynb` 总是传入 `args.model_id`，所以实际不会用到默认值。
- `DetectionAgent.max_code_lines = 400` 定义了但**从未使用**；长函数不会被按行截断。
- 三个 JSON 解析器在失败时的兜底不一致：Planning 抛异常（外层重试 3 次后跳过该样本）；Detection 重试 1 次后返回“非漏洞”；Validation 解析失败则直接沿用 Detection 结果并标 `agree=True`。
- 所有输出 JSONL 以 **append 模式**写入；重跑同一模型会在文件末尾追加重复记录，必须先清空输出目录。

### 3.2 提示词（Appendix D + 代码）

四个 LLM 智能体的系统提示都强调 **defensive security research**。论文明确提到：初版提示被模型误判为“利用漏洞的请求”而拒绝，改成防御性表述后才稳定。课程项目复现时若遇到拒答，这是直接可用的修正。

**Planning Agent（要点）**

```
You are a senior C/C++ *defensive* security researcher.
... Respond with **JSON only** ...
"summary": ≤ 3-sentence plain-language overview
"checklist": array (≤ 8) of concise red-flag cues
- Focus exclusively on *detection* and *prevention* - do NOT produce exploitation steps.
- Do not invent symbols that are absent from the code or AST.
```

**Context Agent（要点）**

```
Given the target function and the context already collected, decide whether
additional external symbols are needed ...
Return JSON ONLY: {"need_more": bool, "new_symbols": [{name, kind}, ...]}
List at most 6 symbols and never repeat ones already provided.
```

**Detection Agent（要点）**

```
You are a C/C++ security analyst. Decide whether the given function contains
a vulnerability *defensively* ... list the minimal set of source statements
that directly cause the issue. Only flag as vulnerable if you are absolutely sure.
Return JSON ONLY: {"is_vulnerable": bool,
 "vuln_statements": [{"line": <0-based>, "statement": "...", "reason": "..."}]}
```

**Validation Agent（要点）**

```
You are a senior C/C++ security reviewer. ... decide whether you **agree**.
If you disagree, provide your own corrected list of vulnerable statements.
Return JSON ONLY: {"agree": bool, "is_vulnerable": bool, "vuln_statements": [...]}
```

完整提示词见 arXiv v1 Appendix D；仓库中的字符串与附录基本一致，但代码里的模板会把 AST/上下文标注为 “could be truncated”，Appendix D 未体现这一点。

### 3.3 截断预算（代码实测，影响公平性）

| 位置 | 参数 | 值 | 后果 |
|---|---|---:|---|
| Planning | `max_code_chars` | 11,264 字符 | 超长函数被截断 |
| Planning | `max_ast_chars` | 77,824 字符 | AST JSON 可占约 2 万 token（按 4 字符/token 估算） |
| Context | 源码预览 | 800 字符 | **只看到函数开头** |
| Context | 已收集符号预览 | 120 字符 | 只看到符号名列表开头 |
| Detection | `max_ast_chars` | 51,200 字符 | — |
| Detection | `max_ctx_chars` | 11,264 字符 | — |
| Validation | code/AST/ctx | 11,264 / 51,200 / 11,264 字符 | — |
| 本地 HF 模型 | tokenizer + pipeline | **6,144 token** | `truncation=True`，与 API 模型预算不等 |
| 所有模型 | `max_new_tokens` | 1,024 | 输出上限 |

> **这是复现实验最需要注意的一点**：开源模型在 `load_llm.py` 中被 `model_max_length=6144` + `truncation=True` 截断，而 GPT-4.1 / Claude 只受各 Agent 的字符上限约束。论文 Table 3/4 的跨模型比较因此**不是等输入预算的比较**。课程项目若混合本地模型与 API 模型，必须显式统一 token 预算，否则方法差异与模型差异会混淆。

### 3.4 正式版新增的 standalone 基线

正式版 §5（RQ1）用 **four-shot prompting**：

- 2 个来自漏洞函数的示例 + 2 个来自其对应修复版本的示例；
- 示例与输入函数**同 CWE 类型**；
- 输出为“漏洞语句 JSON 列表 + 简短理由”，无漏洞则空列表；
- 按模型输出行为**逐个微调指令**（论文原话 “We tweaked some instructions in the prompt based on each model’s output behavior”）；
- 语句与真实漏洞行匹配后，按与多智能体相同的 ①–④ 规则判 TP。

> 该基线不是 zero-shot，且 few-shot 示例按 CWE 选取，会抬高绝对值；与多智能体结果比较时要把“提示工程”与“智能体架构”两种因素分开讨论。

### 3.5 上下文检索实现（`agents/symbol_backend.py`）

- 对每个 `<repo, commit>`，用 `git grep -nP` 在源码扩展名（`.c/.h/.cpp/.cc/.cxx/.hpp/.hh/.hxx`）中找候选行；
- 用 `git rev-parse <commit>:<path>` 取 blob SHA，再用 `git cat-file -p` 读文件内容（不 checkout）；
- 用 tree-sitter 精确定位 function/typedef/struct/enum 节点；
- 结果写入 `symcache.sqlite`，以 `(repo, sha, kind, name)` 为主键；相同文件跨 commit 复用；
- **前置条件**：每个项目要在 `symbol_backend_projects/` 下有一份**完整历史**的 git clone（`project_links.json` 有 712 个仓库映射）。浅克隆不够，因为要按任意 commit 读 blob。
- 首次运行 Context Agent 很慢（论文 README 明确提示），之后靠 `symcache.sqlite` 加速。

---

## 4. 模型与运行配置

| 模型 | 类型 | 常用 HF/API 标识 | 备注 |
|---|---|---|---|
| DeepSeek-Coder-33B-Instruct | 开源 | `deepseek-ai/deepseek-coder-33b-instruct` | HF 权重 |
| Codestral-22B-v0.1 | 开源 | `mistralai/Codestral-22B-v0.1` | HF 权重 |
| Qwen2.5-Coder-32B-Instruct | 开源 | `Qwen/Qwen2.5-Coder-32B-Instruct` | HF 权重 |
| GPT-4.1 | 闭源 | `gpt-4.1` | OpenAI API |
| Claude-3.7-Sonnet | 闭源 | `claude-3-7-sonnet-20250219` | Anthropic API；notebook 默认值 |

> 论文只给模型名，未给 HF repo id；上表的 repo id 是按模型名对应的常用权重仓库，复现前应自行确认。

- 解码：`temperature = 0.1`，`pass@1`，`max_new_tokens = 1024`；
- 硬件：Intel Xeon Gold 6442Y + **4× NVIDIA L40S**，250 GiB RAM；
- 开源模型用 `transformers.pipeline`，`torch_dtype=bfloat16`，`device_map="auto"`；
- 每个模型只跑一个尺寸（作者在 Appendix A 明确承认未做同系列不同尺寸的比较）；
- 论文**没有报告 token 数、API 费用或美元成本**；只给了开源模型的单函数运行时间（见 §6.6）。课程报告若要做成本对比，必须自己计量，不能引用论文的成本数字。

---

## 5. 指标与评测协议

### 5.1 指标定义

- **函数级**：以“函数是否漏洞”为二分类，直接拿 Validation Agent 的 `is_vulnerable` 与数据集标签比对，自动计算 P/R/F1。
- **语句级**：正类 = 漏洞函数；TP 要求“定位到正确语句 **且** 理由正确”。
- 论文对语句级 TP 给了 4 条宽松规则（正式版 §6.3 / arXiv §5.1）：
  1. 输出完全正确的漏洞语句 + 正确理由；
  2. 同一漏洞在函数内多处修复时，至少命中一处；
  3. 命中漏洞语句 + 正确理由，且最多附带 2 条无关语句；
  4. 只输出 sink 语句，或同时输出 source 与 sink，且理由正确。
- 若模型正确判“函数有漏洞”但理由错误：函数级算 TP，语句级算 FN。

### 5.2 人工评测

- 从 **Top-25 CWE** 类型中随机抽 **300 条**（正式版 Table 4 的结果基于该子集）；
- 语句级结果**无法自动评**，作者人工逐条看输出；
- 函数级结果自动匹配；
- **没有报告标注者数量、双人标注或 inter-annotator agreement**；
- **没有公开这 300 条的人工标注或评测脚本**。

### 5.3 评测子集的真实构成（用官方 `random_subset.json` 核对）

| 项目 | 数值 |
|---|---:|
| CWE 分组 | 25 |
| 样本总数 | **301**（论文写 300；官方文件按各 CWE 配额四舍五入后累加为 301） |
| 漏洞函数 | **120** |
| 非漏洞函数 | **181** |
| 阳性率 | **39.9%** |

> Appendix C 说的 “120 true-positive functions (from our subset of 300 samples)” 与工件完全一致。这个 120/301 的构成是理解 Table 3/4 绝对值的关键：**评测集不是 43/57 的全表分布，而是 40/60**。

---

## 6. 主要结果

> 以下 Table 3/4/5 数字均在正式版 PDF（ACM DL）上逐格核对；Table 4（上下文识别）与 Table 6（runtime）取自 arXiv v1，因为正式版对应表格未逐格复核。

### 6.1 Standalone：four-shot 单模型（正式版 Table 3）

| 模型 | Precision (%) | Recall (%) | F1 (%) |
|---|---:|---:|---:|
| DeepSeek-Coder-33B | 0.28 | 0.24 | 0.26 |
| Codestral-22B | 1.12 | 0.67 | 0.84 |
| Qwen2.5-Coder-32B | 2.24 | **22.33** | **4.07** |
| GPT-4.1 | 1.98 | 5.23 | 2.87 |
| Claude-3.7-Sonnet | **3.75** | 2.95 | 3.30 |

**读法**：单模型几乎不能做语句级定位；Qwen 的 recall 22.33% 是靠大量误报换来的（precision 2.24%）。正式版 RQ1 的结论原话是 “the best performing Qwen2.5-Coder-32B model achieves only 4.07% F1-score”。

### 6.2 Agentic：五智能体（正式版 Table 4）

| 模型 | Func P | Func R | Func F1 | Stat P | Stat R | Stat F1 |
|---|---:|---:|---:|---:|---:|---:|
| Qwen2.5-Coder-32B | 35.48 | 34.92 | 35.20 | 12.10 | 15.46 | 13.57 |
| DeepSeek-Coder-33B | 45.16 | 46.28 | 45.71 | 5.65 | 9.72 | 7.14 |
| Codestral-22B | **47.41** | 45.83 | 46.61 | 12.93 | 18.75 | 15.31 |
| GPT-4.1 | 40.65 | 73.11 | 52.25 | 14.49 | 49.21 | 22.38 |
| Claude-3.7-Sonnet | 41.86 | **75.63** | **53.89** | **15.35** | **53.23** | **23.83** |

**读法**：

- 函数级：闭源模型 recall 很高（73–76%）但 precision 只有 40–42%，明显“宁可错杀”；开源模型 precision 为 35–47%（DeepSeek 45.16、Codestral 47.41、Qwen 35.48），但 recall 只有 35–46%。
- 语句级：所有模型 F1 都 ≤ 23.83%，precision 全部 ≤ 15.35%。**“找出函数有问题”与“指出哪条语句有问题并说对理由”是两个难度差一个数量级的任务。**
- 与 standalone 相比，agentic 的语句级 F1 从 4.07% 提到 23.83%，但这是“整套系统（AST + 规划 + 上下文 + 验证）”的联合效果，不是单一因素的消融。

### 6.3 Per-CWE（正式版 Table 5）

- 只统计 Top-10 高频 CWE：CWE-119、125、787、189、190、476、362、369、401、416。
- 性能随 CWE 波动很大：CWE-119/125/787 的 F1 多在 7–27 区间；CWE-401 在 Claude 与 Codestral 上达到 **80.0**，CWE-369 在 Claude 上也是 **80.0**；多个 CWE 对某些模型是 “–”（完全没命中）。
- 论文的定性结论：CWE-362（竞态）与 CWE-369（除零）**只有 Claude-3.7-Sonnet 与 GPT-4.1 识别到**；CWE-20 是第四高频但只有 GPT-4.1 识别到；CWE-120/415 等中等频率漏洞**没有任何模型检出**。
- **对课程项目的含义**：若只报告总体 F1，会被 Linux/Chrome 的高频 CWE 主导；应至少给出按 CWE 分组的表或混淆矩阵。

### 6.4 上下文识别（arXiv v1 Table 4；单位 %）

| 模型 | Function Argument | External Function | Type Definition | Globals |
|---|---:|---:|---:|---:|
| Qwen2.5-Coder-32B | 2.80 | 27.25 | 20.00 | 24.23 |
| DeepSeek-Coder-33B | 5.31 | 29.80 | 13.97 | 19.81 |
| Codestral-22B | 0.00 | 27.52 | 6.96 | 6.60 |
| GPT-4.1 | 3.51 | 27.52 | 20.00 | 18.87 |
| Claude-3.7-Sonnet | 0.00 | **37.00** | **41.33** | **34.53** |

- 五类中的 **Environment-level 没有任何模型识别出来**；论文解释是该类在数据中只占 1.5%，模型很难从函数内推断。
- Function Argument 普遍接近 0–5%，作者推测模型关注的是 struct 类型而不是参数变量本身。
- 这张表只出现在 arXiv v1；正式版结论仍说 Claude 在上下文识别上更好，但**分项数字引用时必须标注 arXiv v1**。

### 6.5 失败分析（正式版 §7；arXiv Appendix C）

**函数长度的影响**（检测到的 vs 漏掉的漏洞函数，LoC 中位数）：

| 模型 | Detected 中位数 | Missed 中位数 | Mann-Whitney p |
|---|---:|---:|---:|
| Claude-3.7-Sonnet | 33 | 71 | 0.0168 |
| GPT-4.1 | 31 | 71 | 0.0115 |
| Qwen2.5-Coder-32B | 18 | 65 | 0.000582 |
| DeepSeek-Coder-33B | 14 | 64 | 0.000197 |
| Codestral-22B | 25 | 67 | 0.000538 |

- 所有模型都显著更擅长短函数；漏掉的函数中位数 64–71 行，检出的 14–33 行。
- 正式版补充：数据集漏洞函数中位数 48 行，而被正确识别的漏洞语句所在函数中位数只有 **17 行**。
- 正式版补充：模型检出的漏洞语句中 **72.85%** 位于函数根层级（无嵌套），而全数据集中只有 **43.49%**；嵌套结构中的漏洞明显更难。
- 正式版补充：Claude 与 GPT-4.1 检出的漏洞中，76.12% / 89.74% 是单语句漏洞，而数据集中单语句漏洞只占 31.07%。

**过度告警**（300 条子集，真实漏洞函数 120 条）：

| 模型 | 判为漏洞的函数数 | 假阳性倾向 |
|---|---:|---|
| GPT-4.1 | 214 | 最激进 |
| Claude-3.7-Sonnet | 215 | 最激进 |
| Qwen2.5-Coder-32B | 121 | 保守 |
| DeepSeek-Coder-33B | 124 | 保守 |
| Codestral-22B | 116 | 保守 |

- 误报集中在 **CWE-476（空指针解引用）、CWE-416（use-after-free）、CWE-190（整数溢出）**；GPT-4.1 与 Claude 会把已有 null check 的指针解引用仍判成 CWE-476，也会把 `free()/kfree()` 之后的立即 return 误判成 UAF。
- 论文 Figure 5/6 给出了具体代码案例（`wlan_set_station_nickname`、`cdnsp_endpoint_init`），可直接用于课程报告的定性案例分析。

### 6.6 运行时间（arXiv v1 Table 6，开源模型，单函数）

| 模型 | Planning (s) | Context (s) | Detection+Validation (s) | 合计 (min) |
|---|---:|---:|---:|---:|
| Qwen2.5-Coder-32B | 52.33 | 96.19 | 213.26 | 6.03 |
| DeepSeek-Coder-33B | 59.49 | 137.16 | 283.01 | 7.99 |
| Codestral-22B | 36.25 | 59.54 | 202.17 | 4.97 |

- Normalization 与模型无关，只跑一次，约 1.2 ms/函数。
- 作者明确不比较 GPT-4.1 / Claude 的墙钟时间，因为受 rate limit 影响，不具可比性。
- **没有 token 数、没有美元成本**；课程项目要报告成本，只能自己从 API usage 里取。

---

## 7. 复现接口（官方工件）

### 7.1 仓库结构

| 路径 | 作用 | 备注 |
|---|---|---|
| `README.md` | 安装、环境变量、运行说明 | 见 §7.2 的缺口 |
| `orchestrator.ipynb` | 主入口，33 个 cell | 五阶段顺序执行 |
| `agents/normalization_agent.py` | tree-sitter 规范化 + 紧凑 AST | 无 LLM |
| `agents/planning_agent.py` | summary + checklist | 截断见 §3.3 |
| `agents/context_agent.py` | 请求外部符号 | 最多 3 轮，800 字符预览 |
| `agents/symbol_backend.py` | `git grep` + tree-sitter 取定义 | 需要完整 clone |
| `agents/detection_agent.py` | 判定 + 语句 + 理由 | JSON 解析失败重试 1 次 |
| `agents/validation_agent.py` | 复核/纠错 | 最多 3 轮 |
| `load_llm.py` | HF / OpenAI / Anthropic 客户端 | 硬编码 cache_dir；需 Python ≥3.12 |
| `random_subset.py` | 按 Top-25 CWE 分层抽 300 条 | 实际写 `random_subset_.json` |
| `random_subset.json` | 论文实验用的 301 条子集 | 120 漏洞 + 181 非漏洞 |
| `cwe_details.csv` | CWE-ID → 名称 | 约 2.9 MB |
| `symbol_backend_projects/project_links.json` | 712 个项目 → GitHub URL | clone 目录被 `.gitignore` 忽略 |

仓库最后一次 commit：`d937c2453939a53d5c72c09bf93a06c39d8156c9`，2025-05-22，共 5 个 commit，**无 release、无 tag、无 LICENSE 文件**。

### 7.2 环境与命令

README 给出的依赖：

```bash
pip install torch==2.5.1 transformers==4.47.0 accelerate==1.3.0 \
            openai anthropic tree-sitter tree-sitter-c==0.23.4 \
            tree-sitter-cpp==0.23.4 openpyxl
```

环境变量（或 `creds/*.json`）：

```bash
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export HF_TOKEN=...
```

运行：

```bash
jupyter notebook orchestrator.ipynb
```

在 notebook 中设置：

```python
args = argparse.Namespace(
    model_id="claude-3-7-sonnet-20250219",
    norm_file=None,
    run_norm=True,
    dataset="random_subset.json",
)
```

### 7.3 输出

```text
{model_id_basename}/
  norm_agent_otpt.jsonl
  plan_agent_otpt.jsonl
  cntxt_agent_otpt.jsonl
  val_agent_otpt.jsonl
  raw/{plan,cntxt,det,val}_agent_raw.jsonl
  {model_id_basename}_output.xlsx
symcache.sqlite
```

Excel 列：`commit_id, filepath, is_vulnerable, project, src_snippet, vuln_type, validate_is_vulnerable, validate_vuln_statements`。**没有 P/R/F1 列，也没有自动评分代码**。

### 7.4 复现坑清单（按严重度排序）

1. **Python 版本**：`load_llm.py` 与 notebook 使用 f-string 内嵌套双引号（`f"{model_id.split("/")[-1]}"`），只有 **Python ≥3.12** 能解析；3.10/3.11 直接 SyntaxError。
2. **硬编码路径**：`load_llm.py` 的 `cache_dir='/local/home/mbahmed/install_dir/.cache/huggingface/hub'` 必须改成自己的路径，否则下载/加载失败。
3. **输入预算不对等**：本地 HF 模型被截断到 6,144 token，API 模型按字符上限；跨模型比较前必须统一。
4. **Context Agent 只看 800 字符**：与论文“给定函数”的描述不符，复现时若要忠实论文语义，需要自己改成完整函数（并重跑）。
5. **JSONL append 模式**：重跑会在文件末尾追加，必须手动清空输出目录，否则重复样本进入统计。
6. **没有评测代码**：300 条子集的人工标注、评分脚本、inter-annotator 记录都未发布；只能自己重标。
7. **没有 LICENSE**：数据集是 MIT（HF 数据卡），但**代码仓库没有任何 license 文件**；课程报告引用代码时不要声称其 license。
8. **`random_subset.py` 写错文件名**：README 说覆盖 `random_subset.json`，代码实际写 `random_subset_.json`；且该脚本依赖 `datasets` 库，README 的 pip 列表没有它。
9. **静默跳过样本**：CWE 不在 `cwe_details.csv` 或扩展名不在 `c/.cpp/.cc/.cxx/.C` 的样本会被 `continue` 跳过，只打印提示；统计分母会变。
10. **`project` 字段丢失**：`norm_result` 只存 `repo_path/commit_id/filepath/is_vulnerable`，没有 `project`；Excel 的 `project` 列全是空。
11. **解析失败兜底偏向负类**：Detection 两次 JSON 解析失败即返回 `is_vulnerable=False`，会压低 recall；报告里应统计解析失败率。
12. **仓库克隆成本**：上下文检索要求 712 个项目各有一份完整历史 clone；Linux/Chrome 这类仓库非常大，磁盘与时间成本高。
13. **模型快照可能过期**：`claude-3-7-sonnet-20250219`、`gpt-4.1` 都是 2025 年的快照；2026 年复现需确认可用性，不能假设数字可复现。
14. **没有随机种子/重复运行**：论文只报 pass@1 单次结果，没有方差；课程实验若只跑一次，无法区分方法差异与噪声。

---

## 8. 局限

### 8.1 作者自述（正式版 §8；arXiv Appendix A）

- 上下文由 LLM 自动抽取，只在 100 条随机样本上人工验证（83.16 ± 6.93%）；“相关上下文”本身没有客观定义，存在标注者主观性。
- 数据集**不包含 repository-wide 上下文**（跨文件的传递效应、领域知识）。
- 人工分析 labor-intensive，规模受限；语句级评测只覆盖 300 条。
- 每个模型只测一个尺寸，结论不能外推到同系列小模型。

### 8.2 工件审计发现（本文新增）

- **无评测代码、无人工标注、无 license**：论文的核心指标无法从工件一键复现。
- **输入预算不一致**：本地模型 6,144 token vs API 模型字符上限，跨模型结论有 confound。
- **Context Agent 实现与论文描述不符**：800 字符预览 + 忽略 AST，可能低估上下文智能体的能力，也可能改变错误模式。
- **提示词按模型微调**：正式版明确说 standalone 的指令按模型输出行为调整；这使“模型间比较”混入了“提示适配”因素。
- **单次运行、无方差**：所有数字都是 pass@1 单次；23.83 vs 22.38 这种差距没有置信区间支撑。
- **数据卡小错**：字段数写 15（实际 16）；`fixed_func_id` 与列名 `fixed_func_idx` 不一致；称非漏洞行的 `fixed_func_id` 指向自身，但 Excel 中实际为 null。

### 8.3 基准设计层面的局限（影响课程实验解释）

1. **负样本 = 修复后版本**，不是自然良性代码。本项目的 40 条负样本 40/40 有 CVE ID、39/40 带修复新增行；任务本质是“修复前 vs 修复后”的近重复判别。模型可以利用“是否新增了边界检查/判空”这类浅层线索，函数级分数会偏乐观。
2. **标签由 patch 派生**：只覆盖“单 commit、改到函数、非 tangled”的修复；多 commit（43 个 CVE）、纯配置、重构类修复被排除。语句标签是“变更语句”，不一定是真正的 root cause；论文的 TP 规则允许 sink-only 和 ±2 条无关语句，标准偏宽松。
3. **source/sink 歧义**：模型输出 sink（崩溃点）而非 source（引入点）也算 TP；这会高估“定位根因”的能力。
4. **人工评测不可复现**：没有标注者数量、没有 IAA、没有公开标注；300 条只来自 Top-25 CWE，不能代表 145 种 CWE。
5. **类别与项目偏斜**：Linux + Chrome 占 41% 漏洞函数；评测子集按 Top-25 CWE 抽取，Top-10 CWE 的样本占很大比例。总体 F1 会被高频项目/CWE 主导。
6. **无时间/项目划分**：数据集用于评测可以，但不适合直接做“训练-测试”泛化结论；MD5 去重只解决完全重复，不解决同 CVE 的近重复。
7. **函数级标签是自动匹配**：`is_vulnerable` 来自数据构造，不是独立人工复核的“安全/不安全”判断。

### 8.4 对本文复核本身的限制

- ACM DL 有 Cloudflare，`curl` 无法直接取 PDF；正式版表格是通过浏览器逐页截图核对的，**只覆盖 Table 3/4/5、§7、§8、§9 和参考文献页**，未逐页核对第 2–5 页的正文。
- 因此 §6.4 的上下文识别分项数字、§6.6 的 runtime 数字标注为 arXiv v1；正式版是否保留该分项表，本文不作断言。
- 未复跑任何模型（无 API key、无 GPU），所有性能数字都是“论文报告值”，不是本项目实测值。

---

## 9. 对课程项目的可操作启示

### 9.1 三种方法族的定位（与论文的对应关系）

| 方案 | 做法 | 论文对应 | 调用数/函数 | 实现成本 | 证据 |
|---|---|---|---:|---|---|
| A. 单模型 few-shot | 函数 + 4 个同 CWE 示例 → JSON 语句列表 | 正式版 RQ1 / Table 3 | 1 | 低 | 最好 F1 4.07% |
| B. 上下文增强单模型 | tree-sitter 抽符号（参数/被调函数/类型/全局）→ 单模型判定 | 论文没有单独消融；是 Context + Detection 的子集 | 1–2 + 检索 | 中 | 论文未报告 |
| C. 多智能体 | Planning + Context + Detection + Validation | 正式版 RQ2 / Table 4 | 4–10 | 高 | 最好 F1 23.83% |

**研究缺口**：论文只比较了 A（four-shot 单模型）与 C（完整五智能体），**没有做 B（只加上下文、不加多智能体）的消融**。因此“提升来自上下文还是来自多智能体/验证”无法从论文回答。课程项目若选 A/B/C 三档，正好补上这个缺口；这比简单复现 C 更有报告价值。

### 9.2 可比性规则（必须写进报告）

1. **同一批样本**：三种方法跑完全相同的 200 条（或 200 对），固定顺序、固定输入字段。
2. **同一模型**：方法间比较时固定同一个 backbone（例如都用同一个 API 模型），否则方法效应与模型效应混淆；跨模型比较另设一张表。
3. **同一输入预算**：显式设定 token 上限（如 8k/16k），本地与 API 模型一致；报告实际截断率。
4. **报告阳性率**：本项目独立集 80% 阳性，论文子集 39.9%；在相同 TPR/FPR 下，80% 阳性会把 precision 抬高。示例（非实测）：TPR=0.5、FPR=0.3 时，39.9% 阳性下 P≈52.5%，80% 阳性下 P≈87.0%。所以**只报 P/R/F1 不够，必须同时报混淆矩阵或 TPR/FPR**。
5. **分开报函数级与语句级**：论文两者差距极大（53.89 vs 23.83）；混在一起会误导。
6. **语句级匹配要写清规则**：是否允许多行语句、是否允许 ±1 行、sink-only 是否算 TP；建议同时报“严格”和“宽松”两套。
7. **成对数据用成对分析**：`vulnerable_fixed_200_pairs.json` 可以做配对判别（同一函数修复前 vs 修复后），报 win rate / McNemar，比独立集更敏感。
8. **成本自测**：记录 input/output token、API 价格、墙钟时间、缓存命中；论文没有成本数字，不能引用。
9. **重复与置信区间**：随机方法跑 3 个种子（或 temperature>0 的多次采样），报均值±标准差；分类指标用 bootstrap 95% CI。
10. **人工复核**：抽 50–100 条做双人标注，报 Cohen's κ；至少给出 2–3 个定性案例（成功/失败各一）。

### 9.3 报告写作建议

- 引用正式版（AIware '26），不要把 arXiv v1 的 Table 3 当成正式版 Table 3。
- 说“论文报告 23.83%”时，注明这是 **Claude-3.7-Sonnet 在论文 300 条子集（官方文件实际 301 条，其中 120 条漏洞）上的语句级 F1，且经过人工判定**；不要说成“SOTA”或“通用性能”。
- 说“上下文有帮助”时，区分论文的两种证据：① 多智能体 vs standalone 的系统级差距；② 上下文识别准确率很低（0–41%），说明模型并不会用上下文。两者并不矛盾：系统级提升可能来自 Planning/Validation，而不是 Context。
- 定性案例可直接用论文 Figure 5/6（嵌套 buffer overflow 漏检、已有 null check 仍误报 CWE-476），但要自己重画/引用，不要复制受版权保护的图（CC BY 4.0 允许转载，需署名）。
- 不要声称复现了论文：除非真的跑了模型，否则写“我们采用论文的 X 设置，在本地 200 条上评测”。

### 9.4 最低可行实验骨架（供父任务参考）

```text
数据：independent_200.json（主表）+ vulnerable_fixed_200_pairs.json（配对分析）
方法：A 单模型 few-shot；B 上下文增强单模型；C 多智能体（可复用论文提示词）
模型：固定 1 个可用 API 模型（成本可控），可选 1 个本地模型做对照
指标：函数级 P/R/F1 + MCC；语句级严格/宽松 P/R/F1；配对 win rate
统计：bootstrap 95% CI；方法间 McNemar；按 CWE/长度分层
成本：token/样本、USD/样本、墙钟/样本
案例：2 成功 + 2 失败，附代码与模型理由
```

> 该骨架不预设最终模型；模型选择由父任务根据可用凭证与预算决定。当前环境未检测到 `DEEPSEEK_API_KEY` 等凭证，正式跑数前必须先解决凭证与预算问题。

---

## 10. 来源清单

| 用途 | URL | 访问日期 |
|---|---|---|
| 正式版 DOI | https://doi.org/10.1145/3805760.3814932 | 2026-11-11 |
| ACM DL 摘要页 | https://dl.acm.org/doi/abs/10.1145/3805760.3814932 | 2026-11-11 |
| ACM DL 开放获取 PDF | https://dl.acm.org/doi/pdf/10.1145/3805760.3814932 | 2026-11-11 |
| Crossref 元数据 | https://api.crossref.org/works/10.1145/3805760.3814932 | 2026-11-11 |
| Semantic Scholar 元数据 | https://api.semanticscholar.org/graph/v1/paper/DOI:10.1145/3805760.3814932 | 2026-11-11 |
| arXiv 摘要 | https://arxiv.org/abs/2505.19828 | 2026-11-11 |
| arXiv v1 全文 HTML | https://arxiv.org/html/2505.19828v1 | 2026-11-11 |
| AIware 2026 论文页 | https://2026.aiwareconf.org/details/aiware-2026-benchmark---dataset-track/11/SecVulEval-Context-Aware-Benchmarking-of-LLMs-for-Vulnerability-Detection | 2026-11-11 |
| GitHub 仓库 | https://github.com/basimbd/SecVulEval | 2026-11-11 |
| HF 数据集 | https://huggingface.co/datasets/arag0rn/SecVulEval | 2026-11-11 |
| HF 数据卡原文 | https://huggingface.co/datasets/arag0rn/SecVulEval/raw/main/README.md | 2026-11-11 |
| OpenReview 页面（未取到 PDF） | https://openreview.net/forum?id=lHa1bxq0eq | 2026-11-11 |

---

## 11. BibTeX 建议

### 11.1 正式版（推荐主引用）

```bibtex
@inproceedings{ahmed2026secvuleval,
  author    = {Md Basim Uddin Ahmed and Nima Shiri Harzevili and Jiho Shin
               and Hung Viet Pham and Song Wang},
  title     = {{SecVulEval}: Context-Aware Benchmarking of {LLMs}
               for Vulnerability Detection},
  booktitle = {Proceedings of the 3rd ACM International Conference
               on AI-Powered Software},
  series    = {AIware '26},
  year      = {2026},
  month     = jul,
  pages     = {388--396},
  publisher = {Association for Computing Machinery},
  address   = {New York, NY, USA},
  doi       = {10.1145/3805760.3814932},
  url       = {https://doi.org/10.1145/3805760.3814932},
  isbn      = {9798400726019}
}
```

> 与现有 `proposal/references.bib` 的 `ahmed2026secvuleval` 一致；新增了 `month` 与 `isbn`，可按需保留或删除。

### 11.2 arXiv 预印本（仅在引用预印本独有内容时使用）

```bibtex
@misc{ahmed2025secvuleval,
  author        = {Md Basim Uddin Ahmed and Nima Shiri Harzevili and Jiho Shin
                   and Hung Viet Pham and Song Wang},
  title         = {{SecVulEval}: Benchmarking {LLMs} for Real-World
                   {C/C++} Vulnerability Detection},
  year          = {2025},
  eprint        = {2505.19828},
  archivePrefix = {arXiv},
  primaryClass  = {cs.SE},
  doi           = {10.48550/arXiv.2505.19828},
  url           = {https://arxiv.org/abs/2505.19828}
}
```

### 11.3 数据集

```bibtex
@misc{secvulevaldata,
  author       = {{arag0rn}},
  title        = {{SecVulEval}: A Dataset of {C/C++} Vulnerabilities},
  howpublished = {Hugging Face Datasets},
  year         = {2025},
  note         = {MIT License; accessed Nov. 11, 2026},
  url          = {https://huggingface.co/datasets/arag0rn/SecVulEval}
}
```

### 11.4 代码工件

```bibtex
@misc{ahmed2025secvulevalcode,
  author       = {Md Basim Uddin Ahmed and Nima Shiri Harzevili and Jiho Shin
                  and Hung Viet Pham and Song Wang},
  title        = {{SecVulEval}: Code and Reproduction Artifacts},
  year         = {2025},
  howpublished = {GitHub},
  note         = {Commit d937c245; no license file; accessed Nov. 11, 2026},
  url          = {https://github.com/basimbd/SecVulEval}
}
```

> 若报告只允许一条 SecVulEval 引用，用 11.1；若正文引用了提示词、runtime 表或上下文识别分项数字，再加 11.2 并在句中注明 arXiv v1。

---

## 12. 核验记录

### 12.1 已核实

| 项 | 方法 | 结果 |
|---|---|---|
| 正式版题名/作者/单位/页码/DOI | ACM DL 页面 + Crossref JSON + PDF 首页 | 一致 |
| 会议时间/地点/论文集/ISBN | ACM DL “Published In” + PDF 页眉 | AIware '26，2026-07-06/07，Montreal，ISBN 9798400726019 |
| 出版/投稿/接收日期 | ACM DL + PDF 第 396 页脚注 | 2026-07-05 出版；2026-02-15 投稿；2026-03-28 接收 |
| 许可 | ACM DL + PDF 首页 | CC BY 4.0 |
| Table 3（standalone） | 正式版 PDF 第 6 页逐格 | 与本文 §6.1 一致 |
| Table 4（agentic） | 正式版 PDF 第 7 页逐格 | 与本文 §6.2 一致 |
| Table 5（per-CWE） | 正式版 PDF 第 8 页 | 存在，Top-10 CWE，含 “–” 单元格 |
| 失败分析数字 | 正式版 §7 + arXiv Appendix C | 一致（p 值、LoC 中位数） |
| 上下文准确率 | 正式版 §8 | 83.16 ± 6.93% |
| 数据集规模/标签计数 | 本地 `SecVulEval.xlsx` 元数据 + HF 数据卡 | 25,440 / 10,998 / 14,442 |
| 官方 300 条子集构成 | `random_subset.json` 统计 | 301 条，120 漏洞，181 非漏洞 |
| 代码行为 | `git clone` 后逐文件阅读 | 见 §3.3、§7.4 |
| 本地负样本性质 | 本地 JSON 统计 | 40/40 有 CVE，39/40 有修复新增行，context 全 null |
| 正式版新增 standalone | 正式版 Table 3 + §5 文字 | four-shot、同 CWE、按模型微调 |

### 12.2 未核实 / 无法核实

- **正式版第 2–5 页正文**未逐页阅读；仅核对了 Table 3/4/5、§7、§8、§9、参考文献页。
- **正式版是否保留上下文识别分项表**：未确认；本文 §6.4 明确标注为 arXiv v1。
- **正式版与 arXiv v1 的逐字差异**：只列了题名、单位、实验组织、表格编号、两个数字、措辞等可确认差异，未做全文 diff。
- **5,867 CVE / 707 项目 / 145 CWE**：来自论文与数据卡，未从 25,440 行原始表重新计算（本地 WSL 无 openpyxl，且不在本文范围内）。
- **代码 license**：仓库无 LICENSE 文件；未从其他渠道推断。
- **模型实测**：未运行任何模型（无 API key、无 GPU）；本文不含本项目实验结果。
- **成本**：论文未报告 token/美元成本；本文未估算具体金额，只给出调用次数与截断上限。

---

*本文只写入了 `research/secvuleval_review.md`，未修改项目中的其他文件。*

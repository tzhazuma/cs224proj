# 本地数据审计与透明参考基线

本目录只做两件事：

1. 审计 `datasets/independent_200.json` 与 `datasets/vulnerable_fixed_200_pairs.json` 的完整性、字段缺失、代码长度截断风险、CWE 分布和元数据泄漏风险；
2. 计算不需要任何模型或 API 的透明 reference baseline，作为后续 LLM 方法的对照下界。

**这些基线不是 LLM 检测器，也不是“手工漏洞规则”。** 它们只使用标签（多数类）、数据构造事实（配对顺序）或固定随机种子；没有任何 `if/else` 漏洞特征规则，不读取密钥，不联网，不调用模型。

## 运行

在 WSL 中执行，使用系统 Python 标准库：

```bash
wsl bash -lc "cd /mnt/c/Users/tzh03/Downloads/zy && mkdir -p baseline/results && python3 baseline/audit_and_baselines.py 2>&1 | tee baseline/results/run.log"
```

若不需要保存 `run.log`，可以去掉 `mkdir`/`tee`；脚本会自行创建输出目录。

已验证解释器为 WSL Python `3.14.8`。脚本只依赖标准库（`argparse`、`hashlib`、`json`、`math`、`platform`、`random`、`re`、`shlex`、`statistics`、`collections`、`datetime`、`pathlib`），不需要 `openai`、`pandas`、`openpyxl`。

可选参数：

```bash
# 改变配对随机基线的抽样种子（默认 42）
python3 baseline/audit_and_baselines.py --random-seed 43

# 写到其他目录（不会覆盖默认 results）
python3 baseline/audit_and_baselines.py --output-dir baseline/results_seed43
```

脚本会在输出目录创建：

| 文件 | 内容 |
| --- | --- |
| `results/audit.json` | 机器可读审计：哈希、完整性检查、字段完整性、context 审计、长度分布、源级截断、CWE/CVE 统计、警告 |
| `results/baselines.json` | 机器可读基线：混淆矩阵、accuracy/precision/recall/F1、specificity、配对双方均正确率 |
| `results/summary.md` | 简短中文报告，含表格和限制 |
| `results/manifest.json` | 输入/输出 SHA-256 与字节数 |
| `results/run.log` | 本次运行的命令和标准输出（由 `tee` 生成） |

`baselines.json` 的 `provenance.audit_json_sha256` 与 `manifest.json` 中 `audit.json` 的哈希一致，便于确认两份结果来自同一次运行。

## 输入与哈希

| 文件 | SHA-256 |
| --- | --- |
| `datasets/independent_200.json` | `055eccc29f640d47653f5289e6b7a9468fead248c05b137aec8779ba7461dc3d` |
| `datasets/vulnerable_fixed_200_pairs.json` | `7028b98d6f2c13b960bd08dd2e737e2ba61732b89dba03e3f173fe44c27214d5` |
| `SecVulEval.xlsx` | `3402fb572c1702491e121dbaa49f100ed0060ece06e18e2f6967766278a78a11` |

源工作簿哈希与两个 JSON 的 `metadata.source_sha256` 一致；两个 JSON 的抽样种子、源行数、排除项也一致。每次运行的脚本哈希和输出哈希见 `results/manifest.json`。

## 基线定义

### 独立集（200 条：160 漏洞 / 40 非漏洞）

- `always_vulnerable_majority`：所有样本判为有漏洞。因为正例占 160/200，这是多数类基线。
- `always_non_vulnerable`：所有样本判为无漏洞，用来暴露 accuracy/recall 的取舍；没有正类预测时 precision 和 F1 未定义（JSON 中为 `null`，Markdown 中为 `—`）。

### 配对集（200 对 / 400 条函数记录）

- `always_vulnerable_both`：每对两个成员都判为有漏洞。
- `always_non_vulnerable_both`：每对两个成员都判为无漏洞。
- `random_member_seeded`：每对随机指定恰好一个有漏洞；默认种子 42。这是配对场景的机会水平参照，单次抽样结果不应被挑选。
- `pair_slot_oracle_leakage`：按 JSON 槽位把 `vulnerable` 成员判为有漏洞、`fixed` 成员判为无漏洞。该文件顺序固定为 `(vulnerable, fixed)`，所以 100% 是**数据构造泄漏**，不是检测能力；它只用于验证评测脚本的标签映射是否正确，不能作为方法结果报告。

## 指标定义

正类固定为“有漏洞”（`is_vulnerable=true`），负类为“无漏洞”。

```text
accuracy     = (TP + TN) / N
precision    = TP / (TP + FP)       （无正类预测时为 null）
recall       = TP / (TP + FN)
F1           = 2 * precision * recall / (precision + recall)
specificity  = TN / (TN + FP)
balanced_acc = (recall + specificity) / 2
```

配对场景另报：

```text
pair_both_correct = 两个成员都判对的对数 / 200
pair_at_least_one_correct = 至少一个成员判对的对数 / 200
```

`pair_both_correct` 是配对实验的核心指标；每函数 accuracy 会把“每对一个对一个错”的常量基线算成 50%，掩盖它在配对层面完全失败的事实。

## 关键结果（详见 `results/summary.md`）

| 基线 | Accuracy | Precision | Recall | F1 | Specificity | 配对双方均正确 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 独立集：永远有漏洞（多数类） | 80.0% | 0.800 | 1.000 | 0.889 | 0.000 | — |
| 独立集：永远无漏洞 | 20.0% | — | 0.000 | — | 1.000 | — |
| 配对：两侧永远有漏洞 | 50.0% | 0.500 | 1.000 | 0.667 | 0.000 | 0/200（0.0%） |
| 配对：两侧永远无漏洞 | 50.0% | — | 0.000 | — | 1.000 | 0/200（0.0%） |
| 配对：随机指定一个有漏洞（seed 42） | 51.5% | 0.515 | 0.515 | 0.515 | 0.515 | 103/200（51.5%） |
| 配对：槽位 oracle（泄漏，不是检测器） | 100.0% | 1.000 | 1.000 | 1.000 | 1.000 | 200/200（100.0%） |

解释：

- 独立集多数类的 80% accuracy 只是 160/200 的标签比例，是没有区分能力的下界；不能把“超过 80%”直接解释为有效检测。
- 配对常量基线每函数 accuracy 都是 50%，但双方均正确率为 0%；报告配对实验时必须同时给出双方均正确率。
- 随机配对基线的双方均正确率约 50%，是配对场景真正的机会水平。默认种子 42 的单次结果是 103/200；不要为了得到 50.0% 而换种子。
- 槽位 oracle 的 100% 来自 JSON 成员顺序，必须与 LLM 方法分开报告。

## 冻结测试集基线

`split_baselines.py` 在 `splits/test_detection_160.json` 和 `splits/test_pairs_180.json` 上重算相同口径，输出 `results/test_split_baselines.json`。运行命令为 `python3 baseline/split_baselines.py`（WSL）。独立测试集多数类基线仍为 80.0% accuracy、0 specificity；配对常量基线的双方均正确率仍为 0%。配对内随机指定一个有漏洞时，固定 seed 42 得到 101/180（56.1%）双方均正确，这是单次随机实现，不应替代约 50% 的解析机会水平。

## 审计发现

完整性检查 23/23 通过：数量、标签、索引唯一性、配对方向、身份字段、函数正文差异、跨数据集隔离、源工作簿哈希均一致。16 个字段在 600 条记录中均存在。

需要特别说明的数据问题：

1. **源级截断（高）**：5 条函数正文恰好 32,767 字符，且全部在函数中间结束。32,767 是 Excel 单元格字符上限，说明截断发生在源工作簿，而不是模型侧。涉及 `independent` 的 idx 9991、8265、7018，以及配对 `8675:8676` 的两个成员。长度分布因此是截断后的下界。
2. **`context` 与标签完全相关（高）**：独立集 40/40 条非漏洞样本的 `context` 是同一个全 null 字符串；160/160 条漏洞样本的 `context` 含 `array(...)` 注释载荷。若把原始 `context` 放入 prompt，标签可由格式和是否存在注释直接判断。配对集内 `context` 200/200 相同，不能区分对内的漏洞/修复版本。
3. **`fixed_func_idx` 存在性泄漏（高）**：独立集 143/160 条正例非空，0/40 条负例非空。任何模型输入都应排除该字段。
4. **CWE/CVE 不是函数级标签特征（中）**：40/40 条独立集非漏洞样本也带非空 `cwe_list` 和 `cve_list`；配对集修复版本 200/200 复制漏洞版本的 CWE/CVE。CWE/CVE 是源 CVE 的溯源信息，不能当作“有 CWE 就是漏洞”，也不能把 200 对当成 400 条独立 CWE 观测。
5. **长度风险（中）**：独立集 73/200 条超过 2,000 字符，14/200 条超过 8,000 字符；配对漏洞版本 9 条、修复版本 11 条超过 8,000 字符。`chars/4` 只是粗略 token 提示，实际截断需用具体模型 tokenizer 复核。
6. **项目集中（中）**：独立集和配对集各有 80 个项目；linux + Chrome 分别占前两大项目的 41.5% 和 39.0%。项目级泛化结论需谨慎。
7. **字段空值（低）**：全部 600 条记录中，`commit_message` 为 null 1 条（独立集 idx 19871），`changed_lines` 为空 21 条，`changed_statements` 为空 39 条；`context.Explanation` 全部为 null。没有 schema 缺字段。

CWE 统计按 `CWE-\d+` 拆分连写标签（如 `CWE-125CWE-787`），在单个函数内去重，`NVD-CWE-*` 单独作为占位标记。独立集正例为 39 种数字 CWE、163 个数字标签归属、10 个占位标记归属、10 个多标签函数；配对漏洞版本为 39 种、198 个归属、15 个占位标记归属、11 个多标签函数。这些计数与只读的 `proposal/figures/cwe_counts.json` 一致；本目录没有修改 `proposal/`。

## 范围与限制

- 本目录不实现 LLM runner、不选择模型、不做 prompt 设计、不调用 API；这些属于其他实验模块。
- 没有读取或输出任何密钥；运行时不访问环境变量中的凭证。
- 没有修改 `datasets/`、`proposal/`、`runner/`、`research/`、`report/`；只在 `baseline/` 下创建文件。
- 200 条独立样本和 200 对配对样本是评估子集，不是训练/测试划分；配对的两个成员共享项目、提交、文件、上下文和 CWE/CVE，不是 400 个独立样本。
- 独立集只有 40 条负例；Wilson 区间是描述性的，不能替代方法之间的统计检验。
- 所有结果只来自标签、数据构造事实或固定种子，没有编造 LLM 输出。

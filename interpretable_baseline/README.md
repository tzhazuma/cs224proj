# 可解释非 LLM 基线（Tier A detection）

本目录只负责一件事：在冻结的 `secvul-split-v1` 检测划分上，用 **dev40 拟合/选择**、**test160 只评估一次** 的方式，回答一个被现有 LLM 结果跳过的问题——

> 只用函数长度、调用数、分配/释放计数、内存 API 等表面特征，能做到什么程度？如果它和 LLM 差不多甚至更高，差的是“检测能力”，还是 macro-F1 这个口径下的操作点？

本目录不调用模型、不联网、不读取环境变量或密钥，不修改 `splits/`、`runner/`、`benchmark/` 或任何旧结果。所有输出写在 `interpretable_baseline/results/<UTC 时间戳>/`；脚本拒绝覆盖非空目录。

## 1. 预注册（在 test 评估之前冻结）

### 1.1 数据与隔离

| 项 | 值 |
| --- | --- |
| dev | `splits/dev_detection_40.json`，40 条（32 V / 8 NV），40 个项目，每个项目 1 条 |
| test | `splits/test_detection_160.json`，160 条（128 V / 32 NV），40 个项目 |
| 标签 | `is_vulnerable`（bool），正类 = vulnerable |
| 隔离 | 脚本启动时检查 dev/test 的 idx、项目、函数体 MD5 交集必须为 0；不通过直接退出 |
| 近重复 | Tier A 的冻结协议只保证**项目级**隔离，不保证 5-gram 近重复隔离；本目录不新增/不放宽任何隔离，也不声称做了近重复控制 |

`dev40` 的 8 条负例全部来自单例小项目；test 的 40 个项目由 `linux`（52 条）、`Chrome`（31 条）、`tensorflow`（7 条）等主导。这个协变量偏移是已知限制，不能把 dev 的选择当成 test 分布的保证。

### 1.2 特征（只用 `func_body`）

先做保守的词法清洗（去掉 `//`、`/* */`、字符串和字符字面量；不处理 C++ raw string），再统计：

| 特征 | 定义 |
| --- | --- |
| `chars` | 原始函数体字符数（与项目已有的配对长度启发式同口径） |
| `lines` | 原始函数体行数 |
| `tokens` | 清洗后标识符个数 |
| `calls` | 第一个 `{` 之后的调用点个数；排除 `if/for/while/switch/return/sizeof` 等关键字 |
| `call_density` | `calls / lines` |
| `alloc` | `malloc/calloc/strdup/strndup/new` 出现次数（不含 `realloc`） |
| `realloc` | `realloc` 出现次数 |
| `free` | `free/delete` 出现次数 |
| `alloc_minus_free` | `alloc - free` |
| `mem_api` | `memcpy/memmove/memset/strcpy/strncpy/strcat/sprintf/snprintf/gets/scanf/sscanf/alloca` 出现次数 |
| `branches` | `if/for/while/switch/case` 出现次数 |
| `branch_density` | `branches / lines` |
| `ptr_arrow` | `->` 出现次数 |
| `nulls` | `NULL/nullptr` 出现次数 |
| `returns` | `return` 出现次数 |

不使用 `context`、`changed_lines`、`changed_statements`、`cve_list`、`cwe_list`、`fixed_func_idx`、项目名或文件名。`func_body` 中如果含注释掉的代码或 `#if 0`，会计入统计；这是词法基线的已知噪声。

### 1.3 规则族（方向与阈值在 test 之前固定）

阈值只由 dev 计算：`chars` 用 dev 中位数，`calls` 用 dev 中位数，`prior_positive` 用 dev 正例率是否 ≥ 0.5。

| 规则 | 预测 vulnerable 的条件 | 先验理由 |
| --- | --- | --- |
| `prior_majority` | 恒为 1 | dev 正例率 0.8 > 0.5；这是多数类参照 |
| `length_short` | `chars <= median_dev(chars)` | 项目已有配对长度启发式选择更短的一侧；dev 的 V 中位长度也短于 NV |
| `calls_high` | `calls >= median_dev(calls)` | 调用点多 = 攻击面/复杂度更高；注意 dev AUC 并不支持这个方向（见 §3） |
| `alloc_unbalanced` | `alloc > free` | 分配多于释放，是泄漏/生命周期问题的经典表面信号 |
| `mem_api_present` | `mem_api >= 1` | 出现内存/字符串 API，是经典静态启发式 |
| `alloc_or_mem` | 上面两条任一 | 放宽召回 |
| `short_and_alloc_or_mem` | `length_short` 且 `alloc_or_mem` | 收紧精确率 |

**dev 选择规则（唯一允许的选择）**：在 7 条规则中取 dev macro-F1 最高者；并列时取 dev MCC 更高者，再取复杂度更低者（`RULE_COMPLEXITY`），最后按名字排序。选中结果写入 `metrics.json.config.selected_rule_on_dev`，并在 test 上只报告一次。test 标签不参与阈值、方向、规则选择或早停。

### 1.4 小型逻辑回归（标准库 IRLS）

| 项 | 值 |
| --- | --- |
| 特征 | `log1p(chars)`、`calls`、`alloc_minus_free`、`mem_api`、`branch_density` |
| 标准化 | 用 dev 的均值和总体标准差（ddof=0） |
| 正则 | L2，`λ = 1.0`，只惩罚斜率，不惩罚截距 |
| 优化 | 牛顿/IRLS + 回溯线搜索，最多 100 次，收敛阈值 1e-9 |
| 阈值 | 固定 0.5，不在 test 上调 |
| 变体 | `lr_unweighted`（不加类权重）与 `lr_balanced`（正负类总权重相等） |
| dev 诊断 | 留一交叉验证（LOO）只用于报告，不用于选择 λ、特征或阈值 |

`lr_unweighted` 在 32 V / 8 NV 的 dev 上很可能退化为“几乎全判正”；这不是 bug，而是 dev 先验的直接后果。`lr_balanced` 是预先声明的敏感性变体。

### 1.5 评估与统计

- 指标定义与 `benchmark/PROTOCOL.md` §7.1 一致：macro-F1 是正类 F1 与负类 F1 的算术平均；MCC 分母为 0 时记 0.0 且标 `mcc_degenerate`。
- 所有基线在 test 上的 coverage 都是 1.0（规则/LR 不会产生 invalid）。
- 95% CI：按 **project** 聚类的 percentile bootstrap，10,000 次，seed 42；与 `benchmark/tools/bench_common.py` 的 cluster 单位一致。
- 与 LLM 的配对比较：common-valid 单元上的 exact McNemar；每个 LLM 参照 run 内做 Holm 校正。Δmacro-F1 的 CI 用同一套 cluster bootstrap。
- 脚本会重新计算 8 个已有 LLM detection run 的指标，并与各自 `metrics.json` 逐项比对（macro-F1、MCC、accuracy、valid、TP/FP/TN/FN，容差 1e-9）；不一致直接退出。这是指标实现的回归测试，不是新实验。

### 1.6 test-tuned 上界（明确不是方法）

为了回答“这些表面特征里到底还有多少可用信号”，脚本额外计算：

1. 每个单特征在 test 上扫所有唯一阈值、两个方向，取 macro-F1 最大者；
2. 7 条规则在 test 上的最好者；
3. LR 在 test 上**同数据拟合再评自己**（in-sample，乐观）；
4. LR 在 test 上做 5 折分层 CV（仍然用了 test 标签训练，只是不同折）；
5. 每个 LLM run 的 self-reported `confidence` 在 test 上扫阈值（同样是 test-tuned 上界）；它回答“即使允许在 test 上重新校准 LLM 的操作点，能否超过简单规则”。

这些数字只作为上界/敏感性，不能写进 leaderboard，也不能称为“方法结果”。

## 2. 运行

```bash
wsl bash -lc "cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
  python3 interpretable_baseline/run_baseline.py 2>&1 | tee interpretable_baseline/results_run.log"
```

可选：

```bash
# 快速冒烟（2,000 次 bootstrap，结果仍写入新目录）
python3 interpretable_baseline/run_baseline.py --resamples 2000

# 指定输出目录（必须不存在或为空）
python3 interpretable_baseline/run_baseline.py --out-dir interpretable_baseline/results/check
```

只依赖 Python 3 标准库。已在 WSL Python 3.14.8 下运行。

本次正式结果：`results/main_20261122c/`（10,000 次 bootstrap，seed 42），中文总结见 `REPORT.md`，文献与改进建议见 `LITERATURE.md`。

## 3. 产物

| 文件 | 内容 |
| --- | --- |
| `results/<ts>/metrics.json` | 配置、dev 规则表、test 指标、bootstrap、LLM 指标与校验、配对比较、test-tuned 上界 |
| `results/<ts>/features.jsonl` | dev/test 每条样本的 15 个特征 |
| `results/<ts>/predictions.jsonl` | 每个方法在 dev/test 上的逐条预测（LR 另带概率） |
| `results/<ts>/error_analysis.json` | 长度四分位、项目分层、LLM FN/FP 与规则的重叠、rationale 关键词率 |
| `results/<ts>/cases.json` | 按长度四分位抽取的 LLM FN/FP 案例（含代码片段与特征） |
| `results/<ts>/report.md` | 机器生成的英文表格报告 |
| `results/<ts>/manifest.json` | 输入/输出 SHA-256、脚本哈希、Python 版本 |
| `REPORT.md` | 中文总结、真实指标、解释与局限 |
| `LITERATURE.md` | 与本基线直接相关的已核验文献与改进建议 |
| `explore_features.py` | 探索性逐特征 dev/test AUC；**不参与方法选择**，仅作描述性附录 |

## 4. 已知限制（必须与结果一起读）

1. **dev 太小且不平衡**：40 条、8 条负例、40 个项目各 1 条。任何 dev 选择都不稳定；`lr_*` 的 LOO 区间会很宽。
2. **dev/test 协变量偏移**：dev 全是单例小项目；test 由 linux/Chrome/tensorflow 主导。长度、调用密度、代码风格都不同。
3. **标签语义**：`is_vulnerable` 表示“该函数是 CVE 修复前的漏洞版本”（false = 同一修复对的修复后版本），不是“函数文本中一定存在可静态识别的缺陷”。很多正例是普通业务代码，任何词法基线都没有信号。
4. **词法特征不是静态分析**：不去注释之外的预处理分支、不解析宏、不处理 raw string、不区分 `free` 是函数还是变量、不分析数据流。它只能回答“表面统计是否与标签相关”。
5. **test-tuned 上界不是可部署结果**：它使用了 test 标签；只能用于说明“还有多少信号”，不能用于主张方法优越。
6. **单次运行、无种子方差**：规则和 LR 都是确定性的；bootstrap 只给抽样不确定性，不给数据构造/标签噪声的不确定性。
7. **多重比较**：8 个 LLM run × 多个基线会产生很多 McNemar；本目录只在预先声明的 LLM 参照族内做 Holm，其他配对结果只作描述。
8. **长度截断**：test 中有函数体恰好 32,767 字符（Excel 单元格上限），长度特征是截断后的下界；这些样本会影响 `length_short` 和 LR。

## 5. 与项目其他部分的关系

- 本目录不是 `baseline/` 的替代：`baseline/` 只做标签/构造事实基线（多数类、随机配对），本目录做**函数内容**的可解释基线。
- 本目录不是 B9（Juliet label-only 泄漏审计）：B9 是 Tier B 的 sanitizer gate；本目录是 Tier A detection 的方法基线。
- 本目录不修改 `benchmark/results/LEADERBOARD.md`；是否把结果并入主表由 benchmark 所有者决定。

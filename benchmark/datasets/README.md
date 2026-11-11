# `benchmark/datasets/` — 冻结数据与数据卡

本目录只放**数据卡、单元清单和哈希**，不放原始大归档，也不重新抽样。原始数据保持在原位置：

| 层级 | 数据 | 位置 | 状态 |
| --- | --- | --- | --- |
| Tier A | SecVulEval `secvul-split-v1` | `splits/test_detection_160.json`、`splits/test_pairs_180.json` | 已冻结，直接引用 |
| Tier B | Juliet CWE-401 | `juliet/raw/`（归档）；`benchmark/datasets/juliet_cwe401_v1/dataset_manifest.json`（数据卡） | 已冻结（200 units / 100 groups / 42 families） |

## Tier A：SecVulEval（只读）

Tier A 不复制、不重新抽样、不修改 `splits/`。冻结信息以 `splits/FREEZE.txt` 为准：

| 文件 | SHA-256 | 单元 |
| --- | --- | --- |
| `splits/test_detection_160.json` | `bc83af63329963cb98c2e1f9b6d4f80e98e4dc16018d24b7308346d3abfa2bf8` | 160 函数（128 V / 32 NV） |
| `splits/test_pairs_180.json` | `21218fd8db79f75f4759cab66907796f68c73449c2a820c6e8c6a0e74ebbb47d` | 180 对 / 360 函数 |

开发/示例只用于提示和校准：`splits/dev_detection_40.json`、`splits/dev_pairs_20.json`、`splits/dev_examples_fewshot.json`。任何测试集样本都不得进入 few-shot 示例或阈值拟合。

数据卡的机器可读字段见 `../schemas/dataset_manifest.schema.json`。Tier A 的 `dataset_manifest` 可以只引用上述 split 文件、哈希和计数，不需要复制源码。

## Tier B：Juliet CWE-401（已冻结）

### 目录约定

```text
benchmark/datasets/juliet_cwe401_v1/
├── dataset_manifest.json        # 数据卡，schema=benchmark-dataset-v1
├── units.jsonl                  # 每个 case variant 一行，含 unit_id/case_id/cluster_id/label
├── splits/
│   ├── dev.json                 # family-disjoint dev
│   └── test.json                # family-disjoint test
├── build/
│   ├── compile_commands.dev.json
│   └── compile_commands.test.json
└── README.md                    # 获取方式、版本、哈希、许可
```

原始 Juliet 归档和编译产物不提交；`dataset_manifest.json` 记录归档 URL、版本、`archive_sha256`、许可和检索时间。当前数据卡固定 `juliet/subset_units.jsonl`（SHA-256 `4827d1…ac24`）与归档哈希；**200 units / 100 groups / 42 families**，dev 60 units/13 families，test 140 units/29 families。

**重要**：上游验证显示 200 个 unit 全部编译/宏/符号 gate 通过，但 22 个 bad unit 没有观察到 LSan leak；这些 unit 的 Juliet 标签仍是 bad，动态方法必须把 clean 视为 `inconclusive`，不能算 TN。详见数据卡 `oracle.consensus_policy` 与 `PROTOCOL.md` §12.7。

数据卡已冻结；**B9 是 partial**：sanitizer/prompt 审计 200/200 通过，但 label-only baseline 尚未跑。因此 LLM/混合结果可以报告，但必须带此 caveat；B4（DeepSeek Juliet LLM）和 B8（cascade）仍无结果。`juliet/scripts/build_subset.py` 的候选 ID 是 `juliet-cwe401-v1.3-subset-v1`，与数据卡一致。

### 单元定义

- `case_id`：Juliet 测试用例文件（去掉语言/路径后的稳定 ID）。
- `variant_id`：`bad` / `good`。
- `unit_id`：`juliet:<case_id>:<bad|good>`。
- `cluster_id`：`case_family`，即去掉 `_NN` / `_NNa` 变体后缀后的模板族。用于按族聚类 bootstrap；不能把同一族的多个变体当独立样本。
- `label`：Juliet 设计标签（bad=1, good=0）。动态工具是**方法**，不是标签来源；标签一致性另由 `oracle` 字段记录。

### Core set 与 extended set

**Core set（主分析）**必须同时满足：

1. 单文件变体，`bad()` 与 `good()` 在同一 translation unit；
2. 用预注册编译器/宏能编译（`-DOMITGOOD` 只留 bad，`-DOMITBAD` 只留 good）；
3. 目标函数入口可执行，动态 harness 能产生明确的 leak/no-leak 或 inconclusive；
4. 标签与至少一个动态 oracle 不矛盾；矛盾 case 记为 `oracle_mismatch`，从主分母排除并报告计数。

**Extended set（次要）**包含多文件 `_51`–`_54` 等变体。静态/动态可以跑，但 LLM function view 可能缺少 support code；不得和 core set 合并成一个 F1。Extended 结果只作稳健性/案例。

### Dev/test 切分

- 按 `case_family` 做**族级互斥**，不能按文件随机切；否则同模板变体会同时出现在 dev/test。
- 目标：test 至少覆盖 70% 的族，dev 至多 30%；若族数少于 10，改用 5-fold family cross-validation，并只报告 out-of-fold 预测，不声称单次冻结测试。
- 所有提示、阈值、融合规则、工具 severity 选择只在 dev 上定；test 只评估一次。
- 具体族数、case 数、dev/test 计数由 `dataset_manifest.json` 记录；本文件不预填。

### 标签与泄漏审计

Juliet 的**文件名、路径、注释、函数名**（`bad`/`good`）、宏（`OMITBAD`/`OMITGOOD`）和注释里的 `CWE401`/`memory leak` 都会泄露标签。冻结前必须：

1. 生成 `sanitizer_version` 和 sanitizer 的 SHA-256；
2. 对 LLM 输入删除/重命名上述标记；保留可编译语义；
3. 跑 label-only baseline（只看文件名/注释/标识符，不看代码逻辑）。若其准确率显著高于机会水平，**停止**，修好 sanitizer 再跑任何 LLM/混合实验；
4. 把审计结果写入 `dataset_manifest.sanitization.audit`，并在结果 run 的 `input.sanitized=true` 与 `sanitizer_version` 中引用。

### 构建与动态 harness

- 编译器/版本、flags、`compile_commands` 路径写入数据卡；不要用“本机默认”而不记录。
- 同一 case 的 bad/good 必须用**同一编译器、同一 flags、同一 harness**，只改 `OMITGOOD`/`OMITBAD`。
- 动态工具记录：sanitizer/Valgrind 版本、命令行、suppression 文件哈希、输入/种子、重复次数、超时。
- 覆盖率来源（gcov/llvm-cov/sanitizer instrumentation）和阈值写入数据卡；clean 结果低于阈值时标 `inconclusive`，不是 `good`。

### 获取与冻结检查清单

- [ ] 记录 Juliet release/commit、归档 URL、`archive_sha256`、许可；
- [ ] 枚举 CWE401 目录，生成 `units.jsonl` 与 SHA-256；
- [ ] 单文件 core set 编译通过率与失败清单；
- [ ] `-DOMITGOOD` / `-DOMITBAD` 两套构建均通过；
- [ ] LSan/Valgrind 至少一个 oracle 与设计标签一致；不一致 case 计数；
- [ ] sanitizer + label-only baseline 通过；
- [ ] family-disjoint dev/test 冻结；
- [ ] 写入 `dataset_manifest.json`，此后只读；改动必须新建 `juliet-cwe401-v2`。

截至 2026-11-12：`B9-LEAKAGE-AUDIT` 记为 **`partial`**——sanitizer/prompt 审计 200/200 通过（禁用 token/路径/CWE/标识符均未命中），但 label-only baseline 仍未跑。因此 `B5/B6/B7/B11/B12` 的真实结果可以报告，但必须带这个 caveat；`B4`（DeepSeek Juliet LLM）因 401/402 仍 `blocked_gate`，`B8` 级联仍 `planned`。B0 数据卡已冻结，但数据冻结不等于 gate 已完全通过。
